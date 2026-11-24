"""Production streaming ports on an isolated DEC-099 kind cluster."""

import argparse
import copy
import json
import shutil
import time
from pathlib import Path
from unittest.mock import patch

from inf060_eks_gpu_plan import verify_gpu_binding
from inf060_eks_operator import execute_streaming
from inf060_eks_remote import StreamingClusterPorts
from inference_platform.inf060_eks_packet import (
    ARCHIVE_BYTES,
    CLEANUP_SECONDS,
    CORPUS_NAME,
    PHASE_WAITS,
    bound,
    file_sha,
    require_window_budget,
    transfer_rate,
)
from inference_platform.inf060_eks_receipts import verify
from inference_platform.inf060_eks_schedule import LEVELS, WINDOW_SECONDS
from inference_platform.kind_rollout import Campaign
from inference_platform.m5_descriptive_operator import phase_deadline
from m5_descriptive_eks import EKSports
from rehearse_inf060_cpu_eks_kind import (
    CLUSTER,
    REGISTRY,
    REPOSITORY,
    KindCpuClockPorts,
    LocalRegistry,
    configure,
    deploy_agent,
)
from rehearse_inf060_kind import RehearsalTransport, command, write

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = Path("/opt/dec077/runtime.json")
STAGED = Path("/opt/dec077/gate-a-inputs")
INOTIFY_MINIMUMS = {
    "fs.inotify.max_user_instances": 512,
    "fs.inotify.max_user_watches": 524288,
}


def prepare_kind_host():
    # The five kind nodes share the disposable routine host's inotify limits.
    # Kube-proxy must initialize on every worker before CNI contacts the API.
    limits = {}
    for key, minimum in INOTIFY_MINIMUMS.items():
        observed = int(command("sysctl", "-n", key))
        if observed < minimum:
            command("sysctl", "-w", f"{key}={minimum}")
            observed = int(command("sysctl", "-n", key))
        if observed < minimum:
            raise ValueError("streaming_kind_inotify")
        limits[key] = observed
    return limits


def mutations(packet, manifest, work):
    records = {}
    code = manifest["descriptive"]["streaming"]
    calls = []

    def refuse(name, expected, call):
        try:
            call()
        except (ValueError, TimeoutError) as exc:
            if str(exc) != expected or calls:
                raise
            records[name] = {"refusal": str(exc), "apply_calls": 0}
        else:
            raise ValueError("streaming_mutation_accepted:" + name)

    def forbidden(*args, **kwargs):
        calls.append("apply")
        raise AssertionError("streaming_mutation_called_apply")

    with patch.object(EKSports, "tf", forbidden):
        for name, field, expected in (
            ("engine-image", "image_digest", "streaming_engine_digest"),
            ("model-revision", "revision", "streaming_model_revision"),
        ):
            changed = copy.deepcopy(manifest)
            changed["descriptive"]["streaming"]["conditions"][field] = "invalid"
            refuse(name, expected, lambda: verify_gpu_binding(packet, changed))
        altered = work / "mutation-packet"
        shutil.copytree(packet, altered)
        first = altered / manifest["alternatives"][0]["directory"] / "show.stdout"
        original = json.loads(first.read_bytes())
        for name, address, field, value, expected in (
            (
                "gpu-count",
                "module.eks.aws_eks_node_group.gpu[0]",
                "scaling_config",
                [{"max_size": 1, "min_size": 1, "desired_size": 1}],
                "streaming_node_count",
            ),
            (
                "policy-flag",
                'module.eks.aws_eks_addon.network["vpc-cni"]',
                "configuration_values",
                None,
                "streaming_vpc_cni_policy",
            ),
        ):
            changed = copy.deepcopy(original)
            target = next(
                r for r in changed["resource_changes"] if r["address"] == address
            )
            target["change"]["after"][field] = value
            write(first, changed)
            refuse(name, expected, lambda: verify_gpu_binding(altered, manifest))
        write(first, original)
        with (altered / CORPUS_NAME).open("ab") as stream:
            stream.write(b"mutation")
        refuse(
            "corpus",
            "streaming_corpus_digest",
            lambda: verify_gpu_binding(altered, manifest),
        )

        fake_ports = EKSports.__new__(EKSports)
        fake_ports.directory, fake_ports.sdk = work, None
        with patch(
            "m5_descriptive_eks.streaming_quota",
            return_value={
                "gpu": {"fits": False, "quota_vcpus": 8, "running_vcpus": 4},
                "standard": {"fits": True},
            },
        ):
            refuse(
                "busy-quota",
                "streaming_gpu_quota_busy",
                lambda: fake_ports.check_streaming_quota("init"),
            )
        rate = transfer_rate(code["laptop_transfer"])
        threshold = PHASE_WAITS["8"] + 2 * bound(ARCHIVE_BYTES, rate) + CLEANUP_SECONDS
        refuse(
            "window-8-guard",
            "streaming_window_guard:8",
            lambda: require_window_budget("8", threshold - 1, rate, rate),
        )
    return records


class KindGpuStreamPorts(StreamingClusterPorts):
    def __init__(self, work, kubeconfig, sealed):
        self.original_kubeconfig = kubeconfig
        self.corpus_path = STAGED / CORPUS_NAME
        self.end = time.time() + sealed["session_seconds"]
        manifest = copy.deepcopy(sealed)
        binding = manifest["descriptive"]
        binding.update(
            session="m5-kind-gpu-streaming",
            kubernetes_context="kind-" + CLUSTER,
            repository_url=REPOSITORY,
            original_deadline_epoch=self.end,
        )
        manifest["deadline_epoch"] = phase_deadline(
            self.end, manifest["timing"], "provision"
        )
        binding["streaming"]["conditions"]["artifact_path"] = (
            "inf060-gpu-path-kind-cpu-mock"
        )
        self.manifest = manifest
        super().__init__(work / "descriptive-private", manifest)
        self.host = RehearsalTransport(work, manifest, self.end)

    def configure_kubeconfig(self):
        shutil.copyfile(self.original_kubeconfig, self.kubeconfig)

    def image_registry(self):
        return LocalRegistry()

    def stage_model(self):
        return {"engine": "cpu-sse-mock", "weights_staged": False}

    def engine_generation(self, pod, alias):
        # This is the one engine identity substitution. Rendering still verifies
        # the production image/model before the mock is installed.
        return {"generation": alias, "engine": "cpu-sse-mock"}

    def render_manifest(self, source):
        result = super().render_manifest(source)
        result["items"] = [
            item for item in result["items"] if item["kind"] != "DaemonSet"
        ]
        mock = "inf060-kind-engine"
        result["items"].append(
            {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "immutable": True,
                "metadata": {"namespace": self.namespace, "name": mock},
                "data": {
                    "engine.py": (ROOT / "scripts/inf060_kind_engine.py").read_text()
                },
            }
        )
        engines = next(
            item
            for item in result["items"]
            if item["metadata"]["name"] == "vllm" and item["kind"] == "StatefulSet"
        )
        pod = engines["spec"]["template"]["spec"]
        vllm = pod["containers"][0]
        vllm.update(
            image=self.client_image,
            command=["python", "-u", "/mock/engine.py"],
            args=[],
            env=[],
            volumeMounts=[{"name": mock, "mountPath": "/mock", "readOnly": True}],
            resources={
                "requests": {"cpu": "100m", "memory": "64Mi"},
                "limits": {"cpu": "2", "memory": "256Mi"},
            },
        )
        pod["volumes"].append({"name": mock, "configMap": {"name": mock}})
        return result

    def remote(self, phase):
        if phase.startswith("stream-window-"):
            return self.stream_window(phase.removeprefix("stream-window-"))
        if phase.startswith("stream-snapshot-"):
            return self.stream_freeze(phase.removeprefix("stream-snapshot-"))
        if phase in {"stream-final", "stream-partial"}:
            return self.stream_freeze("final", complete=phase == "stream-final")
        if phase == "stream-transfer-probe":
            return self.stream_transfer_probe()
        raise ValueError("streaming_kind_phase")

    teardown = KindCpuClockPorts.teardown
    inventory = KindCpuClockPorts.inventory


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if json.loads(RUNTIME.read_bytes())["role"] != "routine_tests":
        raise ValueError("streaming_kind_routine_role")
    output = args.output
    output.mkdir()
    manifest = json.loads((STAGED / "manifest.json").read_bytes())
    source = command("git", "rev-parse", "HEAD").decode().strip()
    if source != manifest["source_commit"]:
        raise ValueError("streaming_kind_source")
    verify_gpu_binding(STAGED, manifest)
    work = ROOT / ".cache/r423-gpu-kind"
    work.mkdir()
    campaign = Campaign(work)
    kubeconfig = work / "kubeconfig"
    write(output / "mutations.json", mutations(STAGED, manifest, work))
    try:
        write(output / "kind-host-limits.json", prepare_kind_host())
        configure(campaign, work, kubeconfig, roles=["cpu", "cpu", "gpu", "gpu"])
        deploy_agent(campaign, kubeconfig, work, enabled=True, gpu_fixture=True)
        ports = KindGpuStreamPorts(work, kubeconfig, manifest)
        try:
            execute_streaming(ports, output / "production")
        finally:
            ports.host.close()
        final = verify(output / "production/results-final")
        if not final["complete"]:
            raise ValueError("streaming_kind_incomplete")
        write(
            output / "kind-rehearsal.json",
            {
                "complete": True,
                "source": source,
                "seal_manifest_sha256": file_sha(STAGED / "manifest.json"),
                "window_seconds": WINDOW_SECONDS,
                "windows": list(LEVELS),
                "substitutions": [
                    "kind control plane and Calico on four CPU worker containers",
                    "supplied kubeconfig instead of EKS describe and token",
                    "local registry HTTP instead of ECR",
                    "native aws-node readback represented by a DaemonSet; Calico enforces policy",
                    "CPU mock engine and staging in place of its GPU and weights",
                    "authenticated loopback archive read in place of the separate SSM hop",
                ],
            },
        )
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
        count = {
            "kind": len(
                command(
                    "docker",
                    "ps",
                    "-aq",
                    "--filter",
                    "label=io.x-k8s.kind.cluster=" + CLUSTER,
                ).splitlines()
            ),
            "registry": len(
                command(
                    "docker", "ps", "-aq", "--filter", "name=^/" + REGISTRY + "$"
                ).splitlines()
            ),
        }
        write(output / "kind-cleanup.json", count)
        if any(count.values()):
            raise ValueError("streaming_kind_cleanup")


if __name__ == "__main__":
    main()
