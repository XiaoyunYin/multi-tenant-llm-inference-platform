"""DEC-099 proof of the CPU EKS port methods on three real kind worker nodes."""

import argparse
import base64
import hashlib
import json
import shutil
import time
from pathlib import Path
from urllib.request import Request, urlopen

from inf060_eks_cpu_plan import IMAGE_ARCHIVE, NODE_COUNT, SERVICE_IMAGES
from inf060_eks_cpu_remote import CpuClockPorts
from inf060_eks_operator import execute_streaming, verify_cpu_clock_results
from inference_platform.inf060_eks_receipts import schedule_digest, verify
from inference_platform.inf060_eks_schedule import SEED, TENANTS, WINDOW_SECONDS
from inference_platform.kind_rollout import Campaign
from inference_platform.m5_descriptive_operator import phase_deadline, session_timing
from rehearse_inf060_kind import (
    CALICO_SHA256,
    CALICO_VERSION,
    RehearsalTransport,
    command,
    write,
)
from rehearse_m5_descriptive import REGISTRY_IMAGE, kind_config, registry_configured

ROOT = Path(__file__).resolve().parents[1]
CLUSTER = "inf060-cpu-clock"
REGISTRY = CLUSTER + "-registry"
REGISTRY_PORT = 5001
REPOSITORY = f"localhost:{REGISTRY_PORT}/clock"
MEDIA_TYPES = (
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
)


class LocalRegistry:
    def get_authorization_token(self):
        # The HTTP registry is local and unauthenticated. Use the unchanged
        # Docker login/push/logout path with a fixture-only login value.
        token = base64.b64encode(b"kind:kind").decode()
        return {"authorizationData": [{"authorizationToken": token}]}

    def batch_get_image(self, *, repositoryName, imageIds, acceptedMediaTypes):
        [wanted] = imageIds
        digest = wanted["imageDigest"]
        if repositoryName != "clock" or tuple(acceptedMediaTypes) != MEDIA_TYPES:
            raise ValueError("cpu_clock:kind_registry_request")
        request = Request(
            f"http://127.0.0.1:{REGISTRY_PORT}/v2/{repositoryName}/manifests/{digest}",
            headers={"Accept": ", ".join(acceptedMediaTypes)},
        )
        with urlopen(request, timeout=15) as reply:
            raw = reply.read(1024**2 + 1)
            observed = reply.headers["Docker-Content-Digest"]
        if len(raw) > 1024**2 or not observed:
            raise ValueError("cpu_clock:kind_registry_readback")
        return {
            "images": [
                {"imageId": {"imageDigest": observed}, "imageManifest": raw.decode()}
            ]
        }


class KindCpuClockPorts(CpuClockPorts):
    def __init__(self, root, kubeconfig, producer, mode):
        self.root, self.original_kubeconfig, self.mode = root, kubeconfig, mode
        self.image_archive = producer / IMAGE_ARCHIVE
        metadata = json.loads((producer / "images.json").read_bytes())
        self.end = time.time() + 18000
        timing = session_timing(180, 0)
        self.manifest = {
            "account": "kind-fixture",
            "timing": timing,
            "forecast_basis": {"hourly_usd": 0, "fixed_other_usd": 0, "margin": 1},
            "deadline_epoch": phase_deadline(self.end, timing, "provision"),
            "descriptive": {
                "session": "m5-kind-clock-" + mode,
                "kubernetes_context": "kind-" + CLUSTER,
                "source_commit": metadata["source"],
                "startup_seconds": 180,
                "timing": timing,
                "original_deadline_epoch": self.end,
                "repository_url": REPOSITORY,
                "cpu_clock_rehearsal": {
                    "images": metadata["images"],
                    "service_images": SERVICE_IMAGES,
                },
                "streaming": {
                    "gpu_hourly_usd": 0,
                    "conditions": {
                        "source": metadata["source"],
                        "artifact_path": "r420-real-cpu-ports-kind",
                        "model": "cpu-sse-mock",
                        "revision": "fixture",
                        "engine_version": "cpu-mock",
                        "image_digest": metadata["images"]["client"]["manifest_digest"],
                        "engine_flags": ["epoch-frontend-abort-fixture"],
                        "gpu_type": None,
                        "gpu_count": 0,
                        "capacity_type": "routine-cpu",
                        "zone": None,
                        "policy": "round_robin",
                        "tenants": list(TENANTS),
                        "seed": SEED,
                        "run_count": 1,
                        "schedule_sha256": schedule_digest(),
                        "pins": {"calico": CALICO_SHA256, **SERVICE_IMAGES},
                        "limits": {
                            "window_seconds": WINDOW_SECONDS,
                            "window_labels": ["8"],
                        },
                    },
                },
            },
        }
        super().__init__(root / "descriptive-private", self.manifest)
        self.host = RehearsalTransport(root, self.manifest, self.end)

    def configure_kubeconfig(self):
        shutil.copyfile(self.original_kubeconfig, self.kubeconfig)

    def image_registry(self):
        return LocalRegistry()

    def client_job(self):
        resources = super().client_job()
        if self.mode == "placement":
            job = next(row for row in resources["items"] if row["kind"] == "Job")
            spec = job["spec"]["template"]["spec"]
            del spec["affinity"]
            # Force the bad placement once anti-affinity has been removed.
            # An unconstrained scheduler can place on the correct node by chance.
            engine = json.loads(self.k("get", "pod/vllm-0", "-o", "json"))
            spec["nodeName"] = engine["spec"]["nodeName"]
        return resources

    def remote(self, phase):
        if phase.startswith("stream-window-"):
            return self.stream_window(phase.removeprefix("stream-window-"))
        if phase.startswith("stream-snapshot-"):
            return self.stream_freeze(phase.removeprefix("stream-snapshot-"))
        if phase == "stream-partial":
            return self.stream_freeze("final")
        raise ValueError("cpu_clock:kind_phase")

    def teardown(self):
        self.k(
            "delete",
            "namespace",
            self.namespace,
            "--ignore-not-found=true",
            "--timeout=90s",
        )
        return {"complete": True}

    def inventory(self):
        spaces = json.loads(self.k("get", "namespaces", "-o", "json"))["items"]
        return {
            "complete": self.namespace
            not in {row["metadata"]["name"] for row in spaces}
        }


def kube(campaign, kubeconfig, *args, seconds=180):
    return command(campaign.kubectl, "--kubeconfig", kubeconfig, *args, seconds=seconds)


def configure(campaign, work, kubeconfig):
    campaign.install_tools()
    command(
        "docker",
        "run",
        "-d",
        "--rm",
        "--name",
        REGISTRY,
        "-p",
        f"127.0.0.1:{REGISTRY_PORT}:5000",
        REGISTRY_IMAGE,
    )
    config = kind_config()
    config["nodes"] = [{"role": "control-plane"}] + [
        {"role": "worker", "labels": {"m5-role": "cpu"}} for _ in range(NODE_COUNT)
    ]
    config["networking"] = {"disableDefaultCNI": True, "podSubnet": "192.168.0.0/16"}
    config_file = work / "kind.json"
    write(config_file, config)
    command(
        campaign.kind,
        "create",
        "cluster",
        "--name",
        CLUSTER,
        "--image",
        campaign.pins["node_image"],
        "--config",
        config_file,
        "--kubeconfig",
        kubeconfig,
        seconds=360,
    )
    command("docker", "network", "connect", "kind", REGISTRY)
    hosts = work / "hosts.toml"
    hosts.write_text(
        f'server = "http://{REGISTRY}:5000"\n'
        f'[host."http://{REGISTRY}:5000"]\n  capabilities = ["pull", "resolve"]\n',
        encoding="utf-8",
    )
    for node in (
        command(campaign.kind, "get", "nodes", "--name", CLUSTER).decode().splitlines()
    ):
        target = f"/etc/containerd/certs.d/localhost:{REGISTRY_PORT}"
        command("docker", "exec", node, "mkdir", "-p", target)
        command("docker", "cp", hosts, node + ":" + target + "/hosts.toml")
        effective = command("docker", "exec", node, "containerd", "config", "dump")
        if not registry_configured(effective.decode()):
            raise ValueError("cpu_clock:kind_registry_config")
    url = f"https://raw.githubusercontent.com/projectcalico/calico/{CALICO_VERSION}/manifests/calico.yaml"
    with urlopen(url, timeout=30) as response:
        manifest = response.read(1024**2)
    if hashlib.sha256(manifest).hexdigest() != CALICO_SHA256:
        raise ValueError("cpu_clock:kind_calico_binding")
    path = work / "calico.yaml"
    path.write_bytes(manifest)
    kube(campaign, kubeconfig, "create", "-f", path)
    kube(
        campaign,
        kubeconfig,
        "wait",
        "--for=condition=Ready",
        "nodes",
        "--all",
        "--timeout=240s",
        seconds=265,
    )


def deploy_agent(campaign, kubeconfig, work, *, enabled):
    labels = {"app": "r420-policy-agent"}
    path = work / "aws-node.json"
    write(
        path,
        {
            "apiVersion": "apps/v1",
            "kind": "DaemonSet",
            "metadata": {"name": "aws-node", "namespace": "kube-system"},
            "spec": {
                "selector": {"matchLabels": labels},
                "template": {
                    "metadata": {"labels": labels},
                    "spec": {
                        "nodeSelector": {"m5-role": "cpu"},
                        "containers": [
                            {
                                "name": "aws-eks-nodeagent",
                                "image": SERVICE_IMAGES["streaming-ingress"],
                                "command": [
                                    "/bin/sh",
                                    "-c",
                                    "exec sleep 3600",
                                    "policy-agent",
                                ],
                                "args": ["--enable-network-policy=true"]
                                if enabled
                                else [],
                            }
                        ],
                    },
                },
            },
        },
    )
    kube(campaign, kubeconfig, "apply", "-f", path)
    kube(
        campaign,
        kubeconfig,
        "-n",
        "kube-system",
        "rollout",
        "status",
        "daemonset/aws-node",
        "--timeout=180s",
        seconds=200,
    )


def docker_readback(output, producer):
    metadata = json.loads((producer / "images.json").read_bytes())
    imds = "http://169.254.169.254/latest"
    with urlopen(
        Request(
            imds + "/api/token",
            method="PUT",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"},
        ),
        timeout=5,
    ) as response:
        token = response.read(2048).decode()
    with urlopen(
        Request(
            imds + "/meta-data/ami-id", headers={"X-aws-ec2-metadata-token": token}
        ),
        timeout=5,
    ) as response:
        ami = response.read(128).decode().strip()
    if ami != metadata["operator_ami"]:
        raise ValueError("cpu_clock:operator_ami_readback")
    version = json.loads(command("docker", "version", "--format", "{{json .}}"))
    info = json.loads(command("docker", "info", "--format", "{{json .}}"))
    service = command(
        "systemctl", "show", "docker", "-p", "ExecStart", "--value"
    ).decode()
    if "path=/opt/dec077/tools/docker/dockerd" not in service:
        raise ValueError("cpu_clock:operator_dockerd")
    write(
        output / "docker.json",
        {
            "operator_ami": ami,
            "binary": "/opt/dec077/tools/docker/dockerd",
            "version": version,
            "driver": info["Driver"],
            "driver_status": info["DriverStatus"],
            "containerd": info.get("ContainerdCommit"),
        },
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--images", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output
    output.mkdir()
    runtime = json.loads(Path("/opt/dec077/runtime.json").read_bytes())
    if runtime["role"] != "routine_tests":
        raise ValueError("cpu_clock:routine_host_required")
    docker_readback(output, args.images)
    work = ROOT / ".cache/r420-kind"
    work.mkdir()
    campaign = Campaign(work)
    kubeconfig = work / "kubeconfig"
    report = {"mutations": {}}
    try:
        configure(campaign, work, kubeconfig)
        for mode, error_code in (
            ("agent", "stream_network_policy"),
            ("placement", "cpu_clock:cross_node_placement"),
        ):
            deploy_agent(campaign, kubeconfig, work, enabled=mode != "agent")
            ports = KindCpuClockPorts(work / mode, kubeconfig, args.images, mode)
            try:
                ports.provision()
            except ValueError as error:
                if str(error) != error_code or any(
                    record["phase"] == "cpu-clock-policy"
                    for record in ports.results.get("stream_diagnostics", [])
                ):
                    raise
                report["mutations"][mode] = {
                    "refusal": str(error),
                    "timing_started": False,
                }
                write(output / "kind-rehearsal.json", report)
            else:
                raise ValueError("cpu_clock:kind_mutation_accepted:" + mode)
            finally:
                try:
                    ports.teardown()
                    if not ports.inventory()["complete"]:
                        raise ValueError("cpu_clock:namespace_remaining")
                finally:
                    ports.host.close()
        ports = KindCpuClockPorts(work / "production", kubeconfig, args.images, "run")
        try:
            execute_streaming(ports, output / "production")
        finally:
            ports.host.close()
        final = output / "production/results-final"
        manifest = verify(final)
        verify_cpu_clock_results(final)
        report.update(
            {
                "verification": "PASS",
                "image_load": ports.results["cpu_clock_image_load"],
                "image_push": ports.results["cpu_clock_image_push"],
                "window_seconds": WINDOW_SECONDS,
                "expected_slots": 4800,
                "production_manifest_complete": manifest["complete"],
                "substitutions": [
                    "kind API and Calico instead of EKS control plane and AWS VPC CNI",
                    "real registry HTTP instead of ECR authentication and API",
                    "supplied kind kubeconfig instead of EKS describe and token",
                    "ready DaemonSet object stands in for aws-node; Calico enforces policy",
                    "real authenticated chunk receiver through a loopback host hop",
                ],
            }
        )
        write(output / "kind-rehearsal.json", report)
    finally:
        try:
            if getattr(campaign, "kind", None):
                command(
                    campaign.kind, "delete", "cluster", "--name", CLUSTER, seconds=240
                )
        finally:
            if command(
                "docker", "ps", "-aq", "--filter", "name=^/" + REGISTRY + "$"
            ).strip():
                command("docker", "rm", "-fv", REGISTRY)
        containers = command(
            "docker", "ps", "-aq", "--filter", "label=io.x-k8s.kind.cluster=" + CLUSTER
        )
        registry = command(
            "docker", "ps", "-aq", "--filter", "name=^/" + REGISTRY + "$"
        )
        write(
            output / "kind-cleanup.json",
            {
                "remaining_kind_containers": len(containers.splitlines()),
                "remaining_registry_containers": len(registry.splitlines()),
            },
        )
        if containers.strip() or registry.strip():
            raise ValueError("cpu_clock:kind_cleanup")


if __name__ == "__main__":
    main()
