"""Exercise the pinned KEDA controller and Helm release on a DEC-099 host."""

import argparse
import hashlib
import json
import shlex
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

from inf054_cpu_helm import TAPE, HelmProofPorts, build_tape_input
from inf054_autoscaling import serving_values
from inf054_dcgm import LATER_WAIT_S, exporter, require_dcgm
from inf054_dec100 import Dec100Workload, configure_mock_dcgm, replica, write
from inf054_eks_workload import (
    OBSERVE_DOWNSCALE_S,
    PREPARATION_S,
    RESET_S,
    read_tape,
    workload_cycle,
    write_rows,
)
from inf060_eks_cpu_plan import require_helm_session
from inf063_chart import PINS, command as captured_command, download, install_helm
from inference_platform.kind_rollout import Campaign
from inference_platform.m5_descriptive import resources
from inference_platform.m5_descriptive_client import pushed_digest
from inference_platform.m5_descriptive_operator import file_inventory, phase_deadline
from prepare_inf060_cpu_eks_images import export_images
from rehearse_m5_descriptive import REGISTRY_HOSTS, REGISTRY_IMAGE, kind_config

CLUSTER = "inf054"
KIND_HELM_SESSION = "m5-desc-r447-helm"
REGISTRY = "m5-descriptive-registry"
KUBECTL_DELAY_S = 0.45
HEALTH_DELAY_S = 215


def delay_kubectl(campaign, work):
    count = work / "kubectl-calls"
    wrapper = work / "kubectl-delayed"
    wrapper.write_text(
        "#!/bin/sh\nprintf '1\\n' >> "
        + shlex.quote(str(count.resolve()))
        + f"\nsleep {KUBECTL_DELAY_S}\nexec "
        + shlex.quote(str(campaign.kubectl.resolve()))
        + ' "$@"\n',
        encoding="utf-8",
        newline="\n",
    )
    wrapper.chmod(0o755)
    campaign.kubectl = wrapper
    return count


def command(*argv, **kwargs):
    try:
        return captured_command(*argv, **kwargs)
    except subprocess.CalledProcessError as error:
        sys.stderr.write((error.stderr or "")[-4096:])
        raise


def publish_fixture_images(campaign):
    images = {}
    for role, image in (
        ("gateway", "mti-gateway:stage1"),
        ("client", "mti-fake:stage1"),
    ):
        repository = "localhost:5001/" + role
        tag = repository + ":source"
        command("docker", "tag", image, tag)
        command("docker", "push", tag)
        inspect = json.loads(command("docker", "image", "inspect", tag).stdout)
        images[role] = pushed_digest(inspect[0], repository)
    for node in command(
        campaign.kind, "get", "nodes", "--name", CLUSTER
    ).stdout.split():
        directory = "/etc/containerd/certs.d/localhost:5001"
        command("docker", "exec", node, "mkdir", "-p", directory)
        command(
            "docker",
            "exec",
            "-i",
            node,
            "tee",
            directory + "/hosts.toml",
            input=REGISTRY_HOSTS,
        )
        for image in images.values():
            command("docker", "exec", node, "crictl", "pull", image)
    return images


def stream_overlap(rows, ordinal_uid, termination_ns, origin_ns):
    def elapsed(instant):
        return (instant - origin_ns) / 1e9 if instant is not None else None

    probes = []
    for row in rows:
        first = row["first_content_ns"]
        ordinal_one = row["pod_uid"] == ordinal_uid
        overlaps = (
            ordinal_one
            and termination_ns is not None
            and first is not None
            and first < termination_ns < row["closed_ns"]
        )
        outcome = (
            "complete"
            if row["complete"]
            else "partial"
            if first is not None
            else "error"
        )
        probes.append(
            {
                "started_s": elapsed(row["started_ns"]),
                "first_content_s": elapsed(first),
                "closed_s": elapsed(row["closed_ns"]),
                "ordinal_one": ordinal_one,
                "http_status": row["status"],
                "overlaps_termination": overlaps,
                "outcome": outcome,
            }
        )
    return {
        "termination_s": elapsed(termination_ns),
        "termination_source": "statefulset_replicas_observed_2_to_1"
        if termination_ns is not None
        else None,
        "probes": probes,
        "overlap_outcomes": [
            probe["outcome"] for probe in probes if probe["overlaps_termination"]
        ],
    }


class KindHelmProofPorts(HelmProofPorts):
    """Substitute cluster provisioning, the VPC CNI and the laptop's SSM hop."""

    def provision(self):
        config = kind_config()
        for node in config["nodes"]:
            node["labels"]["m5-role"] = "cpu"
            if node["role"] == "worker":
                node["labels"]["inf054-dcgm"] = "true"
        cfg = write(self.output / "kind.json", config)
        command(
            self.campaign.kind,
            "create",
            "cluster",
            "--name",
            CLUSTER,
            "--image",
            self.campaign.pins["node_image"],
            "--config",
            cfg,
            "--kubeconfig",
            self.kubeconfig,
            "--wait",
            "180s",
            timeout=360,
        )
        command("docker", "network", "connect", "kind", REGISTRY)
        self.k(
            "taint",
            "nodes",
            CLUSTER + "-control-plane",
            "node-role.kubernetes.io/control-plane-",
        )
        images = publish_fixture_images(self.campaign)
        self.kind_images = {
            role: image.rpartition("@")[2] for role, image in images.items()
        }
        self.client_image = images["client"]
        return self.deploy(resources(self.namespace, images["gateway"]))

    def policy_agent(self):
        return {"enabled": True, "desired": 3, "ready": 3}

    def retrieve(self):
        # This is the SSM boundary. Keep the real export and compare the
        # downstream copy against the independent frozen-file inventory.
        facts = file_inventory(self.output / "frozen")
        received = super().retrieve()
        if received != facts:
            raise ValueError("inf054_kind_frozen_digest")
        return received


def kind_proof_ports(output, tape_hash, campaign):
    original_end = time.time() + 18000
    timing = {
        "cleanup_reserve_seconds": 1800,
        "retrieval_reserve_seconds": 4416,
        "gateway_rollout_seconds": 60,
        "vllm_rollout_seconds": 60,
        "rollout_action_seconds": 60,
        "minimum_workload_seconds": 1,
    }
    binding = {
        "session": require_helm_session(KIND_HELM_SESSION),
        "kubernetes_context": "kind-" + CLUSTER,
        "startup_seconds": 640,
        "timing": timing,
        "original_deadline_epoch": original_end,
        "inf054_cpu_helm": {"tape_sha256": tape_hash},
    }
    return KindHelmProofPorts(
        output,
        {
            "descriptive": binding,
            "deadline_epoch": phase_deadline(original_end, timing, "provision"),
        },
        campaign=campaign,
    )


def kind_inventory():
    return command(
        "docker",
        "ps",
        "-a",
        "--filter",
        "label=io.x-k8s.kind.cluster=" + CLUSTER,
        "--format",
        "{{.Names}}",
        timeout=20,
    ).stdout.split()


def cleanup_kind(campaign):
    attempts = []

    def attempt(*args, timeout):
        try:
            command(*args, timeout=timeout)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
            attempts.append(type(error).__name__)
        else:
            attempts.append("ok")

    def remaining():
        try:
            return kind_inventory()
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return None

    nodes = None
    for _ in range(2):
        attempt(campaign.kind, "delete", "cluster", "--name", CLUSTER, timeout=45)
        nodes = remaining()
        if nodes == []:
            break
    if nodes:
        for node in nodes:
            attempt("docker", "rm", "-f", node, timeout=25)
        nodes = remaining()
    return {
        "remaining": nodes,
        "kind_teardown_verified": nodes == [],
        "attempts": attempts,
        "requires_enclosing_zero": nodes != [],
    }


def dcgm_controls(backend, frozen, receipt):
    positive = json.loads(receipt.read_bytes())
    if not positive["ready"] or positive["wait_bound_s"] != LATER_WAIT_S:
        raise ValueError("inf054_kind_later_dcgm_gate")
    at_gate = positive["at_gate"]
    if not at_gate["node_proxy_allowed"] or not any(
        row.get("container_memory_max_usage_bytes") for row in at_gate["nodes"]
    ):
        raise ValueError("inf054_kind_dcgm_cadvisor_peak")
    configure_mock_dcgm(backend.cluster, time.monotonic() + 30, crash=True)
    end = time.monotonic() + 75
    while time.monotonic() < end:
        pods = (
            backend.get(
                min(end, time.monotonic() + 5), "pods", "-l", "app=dcgm-exporter"
            ).get("items")
            or []
        )
        if any((exporter(pod).get("restartCount") or 0) > 0 for pod in pods):
            break
        time.sleep(1)
    else:
        raise ValueError("inf054_kind_dcgm_no_restart")
    negative = frozen / "dcgm-not-ready.json"
    try:
        require_dcgm(backend, negative, node_role="cpu,inf054-dcgm=true", wait_s=15)
    except ValueError as error:
        if str(error) != "inf054_dcgm_not_ready":
            raise
    else:
        raise ValueError("inf054_kind_dcgm_control_did_not_refuse")
    refused = json.loads(negative.read_bytes())
    if refused["ready"] or not any(
        (node["restart_count"] or 0) > 0
        for poll in refused["polls"]
        for node in poll.get("nodes", [])
    ):
        raise ValueError("inf054_kind_dcgm_diagnostics")
    return {
        "negative": {key: value for key, value in refused.items() if key != "snapshot"},
        "positive": positive,
        "substitution": "CPU exporter stand-in with an exit after its first scrape",
    }


def delayed_readiness(ports, tape, digest, result):
    work = ports.output / "readiness-gate"
    work.mkdir()
    frozen = ports.output / "frozen"
    frozen.mkdir()
    stored = json.loads((ports.output / "inf054-images.secret").read_bytes())
    ports.gateway_image = stored["images"]["gateway"]
    ports.client_image = stored["images"]["client"]
    helm = install_helm(work)
    chart = download(PINS["keda"], work / "keda.tgz")
    # The delayed startup controls precede the full downscale allowance.
    # Leave an independent namespace/KEDA cleanup allocation after the watch.
    cleanup_end = time.monotonic() + 2900
    workload = Dec100Workload(
        ports,
        helm,
        tape,
        digest,
        work,
        cleanup_end=cleanup_end,
        cpu=True,
        split_readiness=True,
        mock_health_delay_s=HEALTH_DELAY_S,
        mock_gpu_diagnostics=True,
        rehearsal_burst_s=300,
    )
    result["mock_health_delay_s"] = HEALTH_DELAY_S
    result["delayed_readiness"] = {}
    try:
        with workload.helm.keda(
            chart, install_end=time.monotonic() + 180, cleanup_end=cleanup_end
        ) as installed:
            write(frozen / "keda-install.json", installed)
            workload.split_readiness = False
            try:
                with workload.release(
                    "fixed-1", 2, serving_values("fixed-1"), time.monotonic() + RESET_S
                ):
                    raise ValueError("inf054_delayed_control_ready")
            except TimeoutError as error:
                if str(error) != "inf054_ready_or_membership":
                    raise
                result["control"] = {"seconds": RESET_S, "reason": str(error)}

            workload.split_readiness = True
            for arm in ("fixed-1", "fixed-2", "keda"):
                with workload.release(
                    arm, 1, serving_values(arm), time.monotonic() + PREPARATION_S
                ) as backend:
                    trail = work / f"{ports.namespace}-readiness.jsonl"
                    events = [
                        json.loads(line) for line in trail.read_bytes().splitlines()
                    ]
                    ready = events[-1]
                    if ready["event"] != "ready":
                        raise ValueError("inf054_delayed_readiness_missing")
                    result["delayed_readiness"][arm] = {
                        "preparation_s": events[0]["elapsed_s"],
                        "bound_s": events[0]["readiness_bound_s"],
                        "ready": ready,
                    }
                    if arm == "fixed-2":
                        result["dcgm_controls"] = dcgm_controls(
                            backend, frozen, work / "dcgm-gate-fixed-2-1.json"
                        )
                        parallel = False
                        for event in events:
                            if event["event"] != "membership":
                                continue
                            replicas = event["replicas"]
                            if any(row["ready"] for row in replicas):
                                break
                            if sum(row["started"] for row in replicas) == 2:
                                parallel = True
                        result["fixed_two_started_in_parallel"] = parallel
                        if not parallel:
                            raise ValueError("inf054_delayed_fixed_two_serial")
                    if arm == "keda":
                        origin_epoch = time.time() - (time.monotonic() - backend.origin)
                        rows = [
                            row
                            for row in read_tape(tape, digest)
                            if row["offset_ns"] < 360 * 10**9
                        ]
                        report = workload_cycle(
                            backend,
                            rows,
                            work,
                            arm=arm,
                            cycle=1,
                            end=time.monotonic() + 540,
                            offer_end=360,
                        )
                        [pod] = [
                            pod
                            for pod in backend.engine_pods(time.monotonic() + 10)
                            if replica(pod) == 1
                        ]
                        [engine] = [
                            row
                            for row in pod["status"]["containerStatuses"]
                            if row["name"] == "vllm"
                        ]
                        start = datetime.fromisoformat(
                            engine["state"]["running"]["startedAt"]
                        ).timestamp()
                        at = next(
                            row["at_s"]
                            for row in backend.scale
                            if any(
                                p["ordinal"] == 1 and p["ready"]
                                for p in row["replicas"] or []
                            )
                        )
                        elapsed = origin_epoch + at - start
                        write_rows(frozen / "keda-scale.jsonl", backend.scale)
                        result["second_replica"] = {
                            "ready_at_s": at,
                            "container_start_to_ready_s": elapsed,
                            "first_completion_s": report["second_serving_s"],
                        }
                        if (
                            elapsed < HEALTH_DELAY_S - 1
                            or report["second_serving_s"] is None
                        ):
                            raise ValueError("inf054_delayed_second_replica")
                        downscale_end = time.monotonic() + OBSERVE_DOWNSCALE_S
                        if downscale_end > cleanup_end - 180:
                            raise TimeoutError("inf054_kind_downscale_reserve")
                        downscale = backend.downscale(downscale_end)
                        write(frozen / "long-downscale.json", downscale)
                        result["long_downscale"] = {
                            "output_cap": downscale["output_cap"],
                            "watch_bound_s": OBSERVE_DOWNSCALE_S,
                            "events_since_probe_s": downscale["events_since_probe_s"],
                            "overlap": downscale["overlap"],
                            "offers": len(downscale["probes"]),
                            "precontent_502": downscale["precontent_502"],
                        }
                        if (
                            not downscale["removal_observed"]
                            or not downscale["overlap"]["termination_started_estimate"]
                        ):
                            raise ValueError("inf054_kind_gpu_downscale_no_witness")
    finally:
        for trail in work.glob("*-readiness.jsonl"):
            shutil.copyfile(trail, frozen / trail.name)
        for receipt in work.glob("dcgm-gate-*.json"):
            shutil.copyfile(receipt, frozen / receipt.name)
        result["frozen"] = ports.retrieve()


def rehearse(work, cpu_inputs=None, *, readiness_gate=False):
    started = time.monotonic()
    work.mkdir(parents=True)
    inputs = cpu_inputs if cpu_inputs is not None else work / "inputs"
    inputs.mkdir()
    build_tape_input(inputs)
    output = work / "operator"
    campaign = Campaign(output)
    campaign.tools.mkdir(exist_ok=True)
    campaign.install_tools()
    campaign.build()
    tape = inputs / TAPE
    tape_hash = hashlib.sha256(tape.read_bytes()).hexdigest()
    ports = kind_proof_ports(output, tape_hash, campaign)
    count = delay_kubectl(campaign, work)
    ports.image_archive = inputs / "images.tar"
    burst_seconds = 300 if readiness_gate else 120
    result = {
        "complete": False,
        "substitutions": {
            "EKSClusterPorts.provision": "three CPU-labelled kind nodes and a local image registry",
            "StreamingClusterPorts.policy_agent": "VPC CNI is absent on kind; no VPC CNI claim",
            "ClusterPorts.retrieve": "local verified custody in place of operator-to-laptop SSM",
        },
        "baseline_seconds": 60,
        "burst_seconds": burst_seconds,
        "scale_down_stabilization_seconds": 900,
        "tape_sha256": tape_hash,
    }
    if cpu_inputs is not None:
        saved = export_images(cpu_inputs)
        result["sealed_image_inputs"] = saved["images"]
        result["sealed_image_archive"] = saved["archive"]
    try:
        command(
            "docker",
            "run",
            "-d",
            "--name",
            REGISTRY,
            "-p",
            "127.0.0.1:5001:5000",
            REGISTRY_IMAGE,
            timeout=180,
        )
        try:
            ports.provision()
            if readiness_gate:
                delayed_readiness(ports, tape, tape_hash, result)
            else:
                result["proof"] = ports.proof(rehearsal_burst_s=burst_seconds)
                if not result["proof"]["live_overlap"]:
                    raise ValueError("inf054_scale_down_no_live_overlap")
        finally:
            result["runtime_registry_digests"] = getattr(ports, "kind_images", {})
            if not readiness_gate:
                frozen = ports.export()
                result["frozen"] = ports.retrieve()
                if frozen != result["frozen"]:
                    raise ValueError("inf054_kind_frozen_digest")
            archived = ports.output / "retrieved"
            for name in (
                "proof.json",
                "chart-checks.json",
                "keda-install.json",
                "engine-render.json",
                "keda-1/summary.json",
            ):
                if (archived / name).is_file():
                    result[name] = json.loads((archived / name).read_bytes())
            gauges = archived / "keda-1/gauges.jsonl"
            if gauges.is_file():
                from collections import Counter

                counts = Counter()
                with gauges.open(encoding="utf-8") as stream:
                    for line in stream:
                        for name, reason in json.loads(line)["read_errors"].items():
                            counts[(name, reason)] += 1
                result["gauge_error_counts"] = [
                    {"read": name, "error_type": reason, "count": count}
                    for (name, reason), count in sorted(counts.items())
                ]
            if ports.kubeconfig.is_file():
                namespaces = (
                    json.loads(ports.k("get", "namespace", "-o", "json")).get("items")
                    or []
                )
                if any(
                    row["metadata"]["name"].startswith(ports.namespace)
                    for row in namespaces
                ):
                    raise ValueError("inf054_kind_namespace_uninstall")
                # Helm removes its release, while the created KEDA namespace
                # is an independent object owned by this disposable cluster.
                ports.k(
                    "delete",
                    "namespace",
                    "keda",
                    "--ignore-not-found",
                    "--wait=true",
                    deadline=time.monotonic() + 120,
                )
                result["namespace_uninstalled"] = True
        result["complete"] = True
    finally:
        result["kind_cleanup"] = cleanup_kind(campaign)
        try:
            command("docker", "rm", "-f", REGISTRY, timeout=25)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
            result["registry_cleanup_error"] = type(error).__name__
            result["kind_cleanup"]["requires_enclosing_zero"] = True
        result["kubectl_injection"] = {
            "delay_seconds": KUBECTL_DELAY_S,
            "calls": len(count.read_bytes().splitlines()) if count.is_file() else 0,
        }
        result["duration_seconds"] = time.monotonic() - started
        write(work / "receipt.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--cpu-inputs", type=Path)
    parser.add_argument("--readiness-gate", action="store_true")
    args = parser.parse_args()
    rehearse(args.work, args.cpu_inputs, readiness_gate=args.readiness_gate)


if __name__ == "__main__":
    main()
