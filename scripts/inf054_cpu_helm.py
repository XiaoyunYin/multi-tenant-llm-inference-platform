"""CPU-only INF-054 Helm/KEDA proof on the sealed DEC-100 operator."""

import json
import shutil
import time

from inf054_autoscaling import ARMS, CYCLES
from inf054_dec100 import Dec100Workload, write
from inf054_eks_workload import (
    RESET_S,
    SNAPSHOT_LIMIT,
    gpu_release_seconds,
    run,
    workload_reserve,
)
from inf060_eks_cpu_plan import HELM_TAPE as TAPE, HELM_TAPE_RECEIPT as PRODUCER
from inf060_eks_cpu_remote import CpuClockPorts
from inf063_chart import PINS, chart_checks, download, install_helm
from m5_descriptive_remote import EKSClusterPorts

from inference_platform.m5_descriptive_operator import file_inventory

KEDA_INSTALL_S = 180


def telemetry_evidence(cycle, scale):
    total = cycle["samples"]
    complete = cycle["complete_samples"]
    desired_two = any(row["desired"] == 2 for row in scale)
    ordinal_one_ready = any(
        replica["ordinal"] == 1 and replica["ready"] is True
        for row in scale
        for replica in row["replicas"] or []
    )
    reasons = []
    if total == 0 or 100 * complete < 95 * total:
        reasons.append("inf054_gauge_completeness")
    if not scale:
        reasons.append("inf054_scale_trace_empty")
    elif not (desired_two and ordinal_one_ready):
        reasons.append("inf054_scale_trace_witness")
    return {
        "complete": not reasons,
        "gauge_rows": total,
        "complete_gauge_rows": complete,
        "missing_gauge_rows": total - complete,
        "scale_rows": len(scale),
        "desired_two": desired_two,
        "ordinal_one_ready": ordinal_one_ready,
        "reasons": reasons,
    }


def record_proof(results, cycle, policy_agent, golden, sha256):
    trace = results / "keda-1/scale.jsonl"
    with trace.open(encoding="utf-8") as stream:
        telemetry = telemetry_evidence(cycle, [json.loads(line) for line in stream])
    status = {
        "complete": telemetry["complete"]
        and cycle["second_serving_s"] is not None
        and cycle["downscale"]["observed"],
        "telemetry": telemetry,
        "policy_agent": policy_agent,
        "external_metric_api": True,
        "live_scale_out": telemetry["complete"]
        and cycle["second_serving_s"] is not None,
        "downscale": telemetry["complete"] and cycle["downscale"]["observed"],
        "live_overlap": telemetry["complete"]
        and bool(cycle["downscale"]["probe_overlaps"]),
        "observed_scale_out": cycle["second_serving_s"] is not None,
        "observed_downscale": cycle["downscale"]["observed"],
        "observed_live_overlap": bool(cycle["downscale"]["probe_overlaps"]),
        "helm_uninstalled": True,
        "golden": golden,
        "tape_sha256": sha256,
    }
    write(results / "proof.json", status)
    if not telemetry["complete"]:
        raise ValueError(telemetry["reasons"][0])
    if not status["live_scale_out"] or not status["downscale"]:
        raise ValueError("inf054_cpu_scale_unobserved")
    return status


class ChatTemplateAdapter:
    """Expose the three chat-template flags used by the sealed tape renderer."""

    def __init__(self, tokenizer):
        self.tokenizer = tokenizer

    def apply_chat_template(
        self, messages, *, tokenize, add_generation_prompt, return_dict
    ):
        if (
            tokenize is not True
            or add_generation_prompt is not True
            or return_dict is not False
        ):
            raise ValueError("inf054_chat_template_flags")
        return self.tokenizer(messages)


class HelmProofPorts(CpuClockPorts):
    cpu_proof = True
    policy_nodes = 3
    helm_binding = "inf054_cpu_helm"
    client_job = EKSClusterPorts.client_job
    tenant_configuration = EKSClusterPorts.tenant_configuration
    client_credentials = EKSClusterPorts.client_credentials

    def provision(self):
        return EKSClusterPorts.provision(self)

    def deploy(self, source):
        end = min(self.deadline, time.monotonic() + 120)
        wanted = {
            "enabled": True,
            "desired": self.policy_nodes,
            "ready": self.policy_nodes,
        }
        self.wait(lambda: self.policy_agent() == wanted, deadline=end)
        gateway = next(
            row
            for row in source["items"]
            if row["kind"] == "StatefulSet" and row["metadata"]["name"] == "gateway"
        )
        images = {
            "gateway": gateway["spec"]["template"]["spec"]["containers"][0]["image"],
            "client": self.client_image,
        }
        data = {"images": images, "policy_agent": wanted}
        write(self.output / "inf054-images.secret", data)
        return {"policy_agent": wanted}

    def proof(self, *, rehearsal_burst_s=None):
        absolute_end = self.deadline
        # The SSM caller starts export/retrieval after this phase. Keep the
        # namespace and KEDA cleanup inside the same deadline as the proof.
        cycles = 1 if self.cpu_proof else len(ARMS) * CYCLES
        from inf054_dcgm import RESERVE_S

        install_cutoff = absolute_end - workload_reserve(
            cycles,
            observe_downscale=True,
            release_seconds=RESET_S if self.cpu_proof else gpu_release_seconds(),
            dcgm_seconds=0 if self.cpu_proof else RESERVE_S,
        )
        if time.monotonic() + KEDA_INSTALL_S > install_cutoff:
            raise TimeoutError("inf054_helm_phase_reserve")
        stored = json.loads((self.output / "inf054-images.secret").read_bytes())
        self.gateway_image = stored["images"]["gateway"]
        self.client_image = stored["images"]["client"]
        work = self.output / "inf054-helm"
        work.mkdir()
        helm = install_helm(work)
        chart = download(PINS["keda"], work / "keda.tgz")
        golden = chart_checks(helm)
        write(work / "chart-checks.json", golden)
        tape = self.image_archive.parent / TAPE
        sha256 = self.binding[self.helm_binding]["tape_sha256"]
        now = time.monotonic()
        if now + KEDA_INSTALL_S > install_cutoff:
            raise TimeoutError("inf054_helm_phase_reserve")
        ports = Dec100Workload(
            self,
            helm,
            tape,
            sha256,
            work,
            cleanup_end=absolute_end,
            cpu=self.cpu_proof,
            rehearsal_burst_s=rehearsal_burst_s,
            rendered_receipt=work / "engine-render.json",
        )
        results = self.output / "inf054-results"
        with ports.helm.keda(
            chart,
            install_end=now + KEDA_INSTALL_S,
            cleanup_end=absolute_end,
        ) as installed:
            write(work / "keda-install.json", installed)
            write(
                work / f"{self.namespace}-keda-1-readiness.jsonl",
                {"event": "pending"},
            )
            records = run(
                ports,
                tape,
                sha256,
                results,
                absolute_end=absolute_end,
                cpu_proof=self.cpu_proof,
                rehearsal_burst_s=rehearsal_burst_s,
            )
        if not self.cpu_proof:
            status = {
                "complete": len(records) == cycles
                and all(row["complete"] for row in records),
                "cycles": len(records),
                "dcgm_gates": [
                    f"dcgm-gate-{row['arm']}-{row['cycle']}.json" for row in records
                ],
                "policy_agent": stored["policy_agent"],
                "golden": golden,
                "helm_uninstalled": True,
                "tape_sha256": sha256,
            }
            write(results / "proof.json", status)
            return status
        [cycle] = records
        return record_proof(results, cycle, stored["policy_agent"], golden, sha256)

    def export(self):
        src = self.output / "inf054-results"
        frozen = self.output / "frozen"
        frozen.mkdir()
        helm = self.output / "inf054-helm"
        # These receipts are collected before the workload yields a backend;
        # preserve them even if the proof never creates a workload result.
        preflight = {
            "chart-checks.json": helm / "chart-checks.json",
            "keda-install.json": helm / "keda-install.json",
            "engine-render.json": helm / "engine-render.json",
            "keda-1/readiness.jsonl": (
                helm / f"{self.namespace}-keda-1-readiness.jsonl"
            ),
        }
        allowed = {
            "proof.json",
            "summary.json",
            "keda-1/summary.json",
            "keda-1/offers.jsonl",
            "keda-1/gauges.jsonl",
            "keda-1/scale.jsonl",
            "keda-1/tsdb.tar.gz",
            "keda-1/tsdb-receipt.json",
        }
        if not self.cpu_proof:
            cycle_files = {name.split("/", 1)[1] for name in allowed if "/" in name}
            allowed = {name for name in allowed if "/" not in name}
            for arm in ARMS:
                for index in range(1, CYCLES + 1):
                    cycle = f"{arm}-{index}"
                    name = f"dcgm-gate-{cycle}.json"
                    preflight[name] = helm / name
                    allowed.update(f"{cycle}/{item}" for item in cycle_files)
                    preflight[f"{cycle}/readiness.jsonl"] = (
                        helm / f"{self.namespace}-{cycle}-readiness.jsonl"
                    )
        files = {name: src / name for name in allowed} | preflight
        for name, source in sorted(files.items()):
            if source.is_file():
                if source.stat().st_size > SNAPSHOT_LIMIT:
                    raise ValueError("inf054_frozen_file_limit")
                dest = frozen / name
                dest.parent.mkdir(exist_ok=True)
                shutil.copyfile(source, dest)
        if not (frozen / "proof.json").exists():
            reason = "workload_interrupted" if src.is_dir() else "workload_not_started"
            if any(
                json.loads(gate.read_bytes()).get("ready") is False
                for gate in frozen.glob("dcgm-gate-*.json")
            ):
                reason = "inf054_dcgm_not_ready"
            write(
                frozen / "proof.json",
                {"complete": False, "reason": reason},
            )
        return file_inventory(frozen)


class GPUHelmPorts(HelmProofPorts):
    cpu_proof = False
    policy_nodes = 4
    helm_binding = "inf054_gpu_helm"
    prepare_images = EKSClusterPorts.prepare_images
    check_pushed_image = EKSClusterPorts.check_pushed_image
    stage_model = EKSClusterPorts.stage_model


def build_tape_input(folder):
    from inf054_eks_workload import build_tape, read_tape
    from inference_platform.stage_c_tokenizer import (
        FILE_HASHES,
        REVISION,
        pinned_tokenizer,
    )

    tape = folder / TAPE
    sha256 = build_tape(ChatTemplateAdapter(pinned_tokenizer(fetch=True)), tape)
    rows = read_tape(tape, sha256)
    write(
        folder / PRODUCER,
        {
            "sha256": sha256,
            "bytes": tape.stat().st_size,
            "rows": len(rows),
            "rendered_tokens": 1024,
            "tokenizer_revision": REVISION,
            "tokenizer_files": FILE_HASHES,
        },
    )


def verify_tape_input(folder, expected):
    from inf054_eks_workload import read_tape
    from inference_platform.stage_c_tokenizer import FILE_HASHES, REVISION

    tape = folder / TAPE
    producer = json.loads((folder / PRODUCER).read_bytes())
    data = {"bytes": tape.stat().st_size, "sha256": producer["sha256"]}
    if (
        data != expected
        or producer["bytes"] != data["bytes"]
        or producer["rows"] != 2760
        or producer["rendered_tokens"] != 1024
        or producer["tokenizer_files"] != FILE_HASHES
        or producer["tokenizer_revision"] != REVISION
        or len(read_tape(tape, data["sha256"])) != 2760
    ):
        raise ValueError("inf054_tape_producer_binding")
    return producer
