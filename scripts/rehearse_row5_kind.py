"""Run the retained row 5 control rehearsal in an owned, CPU-only kind cluster.

The mock vLLM requests the two manually advertised kind GPU slots. This is a
control-path rehearsal; it does not claim native GPU or engine fitness.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import http.client
import json
import os
import re
import shutil
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python" / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

import rehearse_eks_package_a as package_a  # noqa: E402
from inference_platform.eks_deployment import REDIS_IMAGE  # noqa: E402
from inference_platform.package_a_cloud import (  # noqa: E402
    ROW5_KIND_COMMAND_TIMEOUT_S,
    ROW5_KIND_CLUSTER_CREATE_TIMEOUT_S,
    ROW5_KIND_CLUSTER_PROBE_TIMEOUT_S,
    ROW5_KIND_CONFIGURATION_CAPTURE_TIMEOUT_S,
    ROW5_KIND_DIAGNOSTIC_BUILD_TIMEOUT_S,
    ROW5_KIND_DEPLOYMENT_ROLLOUT_TIMEOUT_S,
    ROW5_KIND_GPU_DELETE_TIMEOUT_S,
    ROW5_KIND_GPU_PENDING_TIMEOUT_S,
    ROW5_KIND_HOLD_END_TIMEOUT_S,
    ROW5_KIND_HOLD_POLL_INTERVAL_S,
    ROW5_KIND_IMAGE_INSPECT_TIMEOUT_S,
    ROW5_KIND_MEASUREMENT_PROBE_TIMEOUT_S,
    ROW5_KIND_NODE_READY_TIMEOUT_S,
    ROW5_KIND_OPERATOR_TIMEOUT_S,
    ROW5_KIND_REDIS_ROLLOUT_TIMEOUT_S,
    ROW5_KIND_REDIS_PULL_TIMEOUT_S,
    ROW5_KIND_SCALE_OBSERVE_TIMEOUT_S,
    ROW5_KIND_SCALE_READY_TIMEOUT_S,
    ROW5_KIND_STAGE_WINDOW_TIMEOUT_S,
    ROW5_KIND_PINNED_HOLD_MS,
    ROW5_KIND_PINNED_TTL_MS,
    ROW5_KIND_RESTORE_GRACE_AFTER_S,
    ROW5_KIND_RESTORE_GRACE_BEFORE_S,
)
from inference_platform.inf037b_archive import IntegrityError, encode, sha, strict_json  # noqa: E402
from inference_platform.inf037b_capture import CaptureOwner, DeadlineHTTP  # noqa: E402
from inference_platform.inf037b_durable_ports import DurableStore  # noqa: E402
from inference_platform.inf037b_live import RedisWire  # noqa: E402
from inference_platform.inf037b_row5 import (  # noqa: E402
    BoundedRBACHTTP,
    KubernetesRolePort,
    RoleControl,
    canonical_role,
)
from inference_platform.inf037b_row5_kind import (  # noqa: E402
    kind_row5_ports,
    retain_row5_role,
    retain_kind_row5_inputs_before_proofs,
    row5_runtime_sources,
    row5_timings,
    validate_retained_kind_row5,
)  # noqa: E402
from inference_platform.inf037b_sources import SourceJoin  # noqa: E402

NAMESPACE_PREFIX = "mti-m5-row5-"
ROW5_KIND_DIAGNOSTIC_COMMAND_TIMEOUT_S = 5
ROW5_KIND_DIAGNOSTIC_MAX_FILE_BYTES = 1_048_576
ROW5_KIND_DIAGNOSTIC_MAX_PODS = 12
ROW5_KIND_DIAGNOSTIC_MAX_CONTAINERS_PER_POD = 8
BASE_MANIFEST_OBJECTS = {
    ("ServiceAccount", "gateway"),
    ("Role", "endpoint-reader"),
    ("RoleBinding", "gateway-endpoints"),
    ("Service", "redis"),
    ("Service", "gateway"),
    ("Service", "gateway-peer"),
    ("Service", "vllm"),
    ("Deployment", "redis"),
    ("StatefulSet", "gateway"),
    ("StatefulSet", "vllm"),
    ("PodDisruptionBudget", "gateway"),
    ("PodDisruptionBudget", "vllm"),
}


class Refusal(RuntimeError):
    def __init__(self, name: str, detail: str = ""):
        self.name = name
        self.detail = detail
        super().__init__(name + (":" + detail if detail else ""))


def restoration_hold_start_label(state: dict, _redis_time_ms: int) -> str | None:
    if state.get("n") == 2:
        raise Refusal("kind_restore_hold_start_missed")
    if state.get("n") == 1 and state.get("candidate") == 2:
        return "hold_start"
    return None


def restore_window_s(config: dict) -> float:
    return (
        ROW5_KIND_RESTORE_GRACE_BEFORE_S
        + (config["ttl_ms"] + config["hold_ms"]) / 1000
        + ROW5_KIND_RESTORE_GRACE_AFTER_S
    )


def wait_for_restoration_hold_start(
    live_snapshot, timeout_s, *, monotonic=time.monotonic, sleep=time.sleep
):
    deadline = monotonic() + timeout_s
    while monotonic() < deadline:
        current = live_snapshot(label_if=restoration_hold_start_label)
        if current is not None:
            state = current.get("payload", {}).get("state", {})
            if state.get("n") == 1 and state.get("candidate") == 2:
                return current
        sleep(ROW5_KIND_HOLD_POLL_INTERVAL_S)
    return None


def require_hold_end_snapshot(live_snapshot):
    snapshot = live_snapshot("hold_end")
    if snapshot is None:
        raise Refusal("kind_restore_hold_end_snapshot_missing")
    return snapshot


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _tool(path: str | None, name: str, pins: dict) -> tuple[str, bool]:
    """Return a pinned default or an explicit command override for fake checks."""
    if path:
        found = shutil.which(path) if not Path(path).is_file() else path
        if not found:
            raise Refusal("kind_tool_missing", name)
        return str(Path(found).resolve()) if Path(found).is_file() else found, False
    binary = ROOT / ".tools" / (name + (".exe" if os.name == "nt" else ""))
    key = f"{name}_{'windows' if os.name == 'nt' else 'linux'}_amd64_sha256"
    if not binary.is_file():
        raise Refusal("kind_tool_missing", name)
    if digest(binary.read_bytes()) != pins[key]:
        raise Refusal("kind_tool_pin_mismatch", name)
    return str(binary), True


def _manifest_inputs(namespace: str) -> dict:
    model = {"config.json": {"bytes": 3, "sha256": digest(b"{}\n")}}
    model_bytes = json.dumps(model, sort_keys=True, separators=(",", ":")).encode()
    return {
        "crictl_host_path": "/usr/bin/crictl",
        "crictl_sha256": "c" * 64,
        "model_manifest_sha256": digest(model_bytes),
        "model_manifest": model,
        "operator_cidrs": ["192.0.2.1/32"],
        "namespace": namespace,
        "gateway_image": "example.invalid/gateway@sha256:" + "a" * 64,
        "config_sha256": "b" * 64,
        "tls_secret": "gateway-tls",
        "r": 4,
        "w": 1,
    }


def render_row5_manifest(namespace: str, gateway_image: str) -> tuple[dict, list[str]]:
    source = (ROOT / "deploy" / "eks" / "capture_runtime.py").read_text(
        encoding="utf-8"
    )
    include = {
        ("Namespace", namespace),
        *BASE_MANIFEST_OBJECTS,
    }
    manifest, used_images = package_a.render_kind_manifest(
        _manifest_inputs(namespace),
        source,
        gateway_image,
        {"redis": REDIS_IMAGE},
        (gateway_image, "mti-fake:stage1"),
        include=include,
    )
    namespace_item = next(o for o in manifest["items"] if o["kind"] == "Namespace")
    if namespace_item["metadata"]["name"] != namespace:
        raise Refusal("kind_manifest_namespace")
    for item in manifest["items"]:
        if item["kind"] == "StatefulSet" and item["metadata"]["name"] == "vllm":
            item["spec"]["replicas"] = 0
    mock = next(
        o
        for o in manifest["items"]
        if o["kind"] == "ConfigMap" and o["metadata"]["name"] == "mock-backend"
    )
    # Short retained SSE streams keep outage controls inside their 30 s bound.
    mock["data"]["entry.py"] = (
        "from inference_platform import kind_fake\n"
        "kind_fake.STREAM_CHUNKS=4\n"
        "kind_fake.STREAM_CHUNK_DELAY_MS=20\n"
        "raise SystemExit(kind_fake.main())\n"
    )
    secret_data = {
        "tenants.json": (ROOT / "deploy" / "local" / "tenants.json").read_bytes(),
        "cache-salt.secret": (
            ROOT / "deploy" / "local" / "cache-salt.secret.example"
        ).read_bytes(),
    }
    manifest["items"].append(
        {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": "gateway-config", "namespace": namespace},
            "type": "Opaque",
            "data": {
                k: base64.b64encode(v).decode("ascii") for k, v in secret_data.items()
            },
        }
    )
    return manifest, used_images


def check_row5_manifest_images(used_images: list[str], gateway_image: str) -> None:
    expected_images = {
        package_a.KIND_LOCAL_IMAGE_TAGS["redis"],
        gateway_image,
        "mti-fake:stage1",
    }
    if set(used_images) != expected_images:
        raise Refusal("kind_manifest_image_set", repr(sorted(used_images)))


def operator_rbac_manifest(namespace: str, endpoint_reader_role: dict) -> dict:
    role_name = "row5-operator-endpoint-reader"
    return {
        "apiVersion": "v1",
        "kind": "List",
        "items": [
            {
                "apiVersion": "v1",
                "kind": "ServiceAccount",
                "metadata": {"name": "row5-operator", "namespace": namespace},
            },
            {
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "Role",
                "metadata": {"name": role_name, "namespace": namespace},
                "rules": copy.deepcopy(endpoint_reader_role["rules"]),
            },
            {
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "RoleBinding",
                "metadata": {"name": role_name, "namespace": namespace},
                "roleRef": {
                    "apiGroup": "rbac.authorization.k8s.io",
                    "kind": "Role",
                    "name": role_name,
                },
                "subjects": [
                    {
                        "kind": "ServiceAccount",
                        "name": "row5-operator",
                        "namespace": namespace,
                    }
                ],
            },
            {
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "ClusterRole",
                "metadata": {"name": "row5-operator"},
                "rules": [
                    {
                        "apiGroups": ["rbac.authorization.k8s.io"],
                        "resources": ["roles"],
                        "resourceNames": ["endpoint-reader"],
                        "verbs": ["get", "update"],
                    },
                    {
                        "apiGroups": ["rbac.authorization.k8s.io"],
                        "resources": ["rolebindings"],
                        "resourceNames": ["gateway-endpoints"],
                        "verbs": ["get"],
                    },
                    {
                        "apiGroups": ["authorization.k8s.io"],
                        "resources": ["subjectaccessreviews"],
                        "verbs": ["create"],
                    },
                ],
            },
            {
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "ClusterRoleBinding",
                "metadata": {"name": "row5-operator"},
                "roleRef": {
                    "apiGroup": "rbac.authorization.k8s.io",
                    "kind": "ClusterRole",
                    "name": "row5-operator",
                },
                "subjects": [
                    {
                        "kind": "ServiceAccount",
                        "name": "row5-operator",
                        "namespace": namespace,
                    }
                ],
            },
        ],
    }


def kind_config() -> dict:
    return {
        "kind": "Cluster",
        "apiVersion": "kind.x-k8s.io/v1alpha4",
        "nodes": [
            {"role": "control-plane"},
            {"role": "worker"},
            {"role": "worker"},
        ],
    }


def _manifest_call(
    kubectl,
    kubeconfig,
    context,
    namespace,
    args,
    *,
    timeout=ROW5_KIND_DEPLOYMENT_ROLLOUT_TIMEOUT_S,
):
    command = [
        kubectl,
        "--kubeconfig",
        kubeconfig,
        "--context",
        context,
        "-n",
        namespace,
        *args,
    ]
    try:
        return package_a.run(command, timeout=timeout)
    except Exception as exc:
        raise Refusal("kind_manifest_step_failed", f"{args[0]}:{exc}") from exc


def apply_manifest_steps(
    kubectl,
    kubeconfig,
    context,
    namespace,
    manifest_path,
    *,
    timeout=ROW5_KIND_DEPLOYMENT_ROLLOUT_TIMEOUT_S,
):
    """Apply resources, verify both gateway containers start, and defer readiness."""
    _manifest_call(
        kubectl,
        kubeconfig,
        context,
        namespace,
        ["apply", "--validate=false", "-f", manifest_path],
        timeout=timeout,
    )
    statefulsets = strict_json(
        _manifest_call(
            kubectl,
            kubeconfig,
            context,
            namespace,
            ["get", "statefulsets", "-o", "json"],
            timeout=timeout,
        ).encode()
    )
    names = {
        item.get("metadata", {}).get("name")
        for item in statefulsets.get("items", [])
        if isinstance(item, dict)
    }
    if not {"gateway", "vllm"} <= names:
        raise Refusal("kind_manifest_statefulsets_missing")
    try:
        for ordinal in (0, 1):
            pod = f"pod/gateway-{ordinal}"
            try:
                _manifest_call(
                    kubectl,
                    kubeconfig,
                    context,
                    namespace,
                    ["wait", "--for=create", pod, f"--timeout={timeout}s"],
                    timeout=timeout + 5,
                )
            except Refusal as exc:
                raise Refusal(
                    "kind_first_readiness_wait",
                    f"step=gateway-{ordinal}-pod-create:{exc.detail}",
                ) from exc
            try:
                _manifest_call(
                    kubectl,
                    kubeconfig,
                    context,
                    namespace,
                    [
                        "wait",
                        "--for=jsonpath={.status.containerStatuses[0].started}=true",
                        pod,
                        f"--timeout={timeout}s",
                    ],
                    timeout=timeout + 5,
                )
            except Refusal as exc:
                raise Refusal(
                    "kind_first_readiness_wait",
                    f"step=gateway-{ordinal}-container-start:{exc.detail}",
                ) from exc
    except Refusal as exc:
        if exc.name == "kind_first_readiness_wait":
            raise
        raise Refusal("kind_first_readiness_wait", exc.detail) from exc
    return statefulsets


def complete_step(report, name, started_ns, *, ended_ns=None):
    ended_ns = time.monotonic_ns() if ended_ns is None else ended_ns
    report.setdefault("timings_ms", {})["step:" + name] = max(
        0, (ended_ns - started_ns) // 1_000_000
    )


def timed_step(report, name, action):
    started_ns = time.monotonic_ns()
    try:
        return action()
    finally:
        complete_step(report, name, started_ns)


def wait_for_step(
    predicate,
    timeout,
    *,
    step_name,
    budget,
    report,
    bound_subprocess=False,
):
    started_ns = time.monotonic_ns()
    try:
        deadline = time.monotonic() + min(timeout, budget.cap(timeout))
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise Refusal("kind_behavior_deadline", "step=" + step_name)
            ready = (
                predicate(min(ROW5_KIND_COMMAND_TIMEOUT_S, remaining))
                if bound_subprocess
                else predicate()
            )
            if ready:
                if time.monotonic() >= deadline:
                    raise Refusal("kind_behavior_deadline", "step=" + step_name)
                return
            time.sleep(min(0.25, max(0, deadline - time.monotonic())))
    finally:
        complete_step(report, "wait-" + step_name, started_ns)


def capture_refusal_diagnostics(
    kubectl, kubeconfig, context, namespace, output, *, run=None
):
    """Save bounded cluster state before deletion; each kubectl call is independent."""
    run = run or package_a.run
    directory = Path(output) / "diagnostics"
    directory.mkdir(parents=True, exist_ok=True)
    base = [
        str(kubectl),
        "--kubeconfig",
        str(kubeconfig),
        "--context",
        str(context),
        "-n",
        str(namespace),
    ]
    results = []

    def invoke(name, argv):
        target = directory / name
        row = {
            "file": str(target.relative_to(output)),
            "command": argv,
            "timeout_s": ROW5_KIND_DIAGNOSTIC_COMMAND_TIMEOUT_S,
        }
        try:
            code, stdout = run(
                argv,
                timeout=ROW5_KIND_DIAGNOSTIC_COMMAND_TIMEOUT_S,
                check=False,
                return_status=True,
            )
            raw = (
                stdout.encode("utf-8", errors="replace")
                if isinstance(stdout, str)
                else bytes(stdout)
            )
            limited = raw[:ROW5_KIND_DIAGNOSTIC_MAX_FILE_BYTES]
            target.write_bytes(limited)
            row.update(
                exit_code=code,
                bytes_written=len(limited),
                truncated=len(raw) > len(limited),
            )
            if code:
                row["error"] = "kubectl_exit:" + str(code)
        except Exception as exc:
            error_file = target.with_suffix(target.suffix + ".error.json")
            error = {"error": type(exc).__name__, "detail": str(exc)[:500]}
            error_file.write_text(
                json.dumps(error, sort_keys=True) + "\n", encoding="utf-8"
            )
            row.update(
                error=error["error"],
                detail=error["detail"],
                error_file=str(error_file.relative_to(output)),
            )
            raw = b""
        results.append(row)
        return raw, row.get("exit_code") == 0 and not row.get("truncated")

    resources, resources_ok = invoke(
        "resources.json",
        [*base, "get", "pods,statefulsets,deployments,endpointslices", "-o", "json"],
    )
    invoke("events.json", [*base, "get", "events", "-o", "json"])
    if resources_ok:
        try:
            parsed = strict_json(resources)
            items = parsed.get("items", []) if isinstance(parsed, dict) else []
            if not isinstance(items, list):
                raise ValueError("resource_items_not_list")
        except Exception as exc:
            items = []
            results.append({"error": "resource_json:" + type(exc).__name__})
        pods = []
        for item in items:
            if not isinstance(item, dict) or item.get("kind") != "Pod":
                continue
            metadata = item.get("metadata")
            if not isinstance(metadata, dict):
                continue
            labels = metadata.get("labels")
            if not isinstance(labels, dict) or labels.get("app") not in {
                "gateway",
                "vllm",
                "redis",
            }:
                continue
            pods.append(item)
            if len(pods) == ROW5_KIND_DIAGNOSTIC_MAX_PODS:
                break
        for pod in pods:
            metadata = pod["metadata"]
            name = metadata.get("name")
            if not isinstance(name, str) or not name:
                continue
            invoke(
                f"pod-{name}-current.log",
                [*base, "logs", "pod/" + name, "--all-containers=true", "--tail=500"],
            )
            status = pod.get("status")
            status = status if isinstance(status, dict) else {}
            statuses = status.get("containerStatuses", [])
            init_statuses = status.get("initContainerStatuses", [])
            statuses = [
                *(statuses if isinstance(statuses, list) else []),
                *(init_statuses if isinstance(init_statuses, list) else []),
            ][:ROW5_KIND_DIAGNOSTIC_MAX_CONTAINERS_PER_POD]
            for status in statuses:
                if not isinstance(status, dict):
                    continue
                container = status.get("name")
                if (
                    isinstance(container, str)
                    and container
                    and type(status.get("restartCount")) is int
                    and status["restartCount"] > 0
                ):
                    invoke(
                        f"pod-{name}-container-{container}-previous.log",
                        [
                            *base,
                            "logs",
                            "pod/" + name,
                            "--container=" + container,
                            "--previous",
                            "--tail=500",
                        ],
                    )
    summary = {"commands": results, "command_count": len(results)}
    (directory / "diagnostics.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return summary


def _fake_kubeconfig(server: str, destination: Path):
    if not server.startswith(("http://127.0.0.1:", "http://localhost:")):
        raise Refusal("kind_fake_api_loopback_required")
    destination.write_text(
        json.dumps(
            {
                "apiVersion": "v1",
                "kind": "Config",
                "clusters": [{"name": "row5-api", "cluster": {"server": server}}],
                "users": [{"name": "row5-api"}],
                "contexts": [
                    {
                        "name": "row5-api",
                        "context": {"cluster": "row5-api", "user": "row5-api"},
                    }
                ],
                "current-context": "row5-api",
            }
        ),
        encoding="utf-8",
    )


def _hashes(args, node_image, cluster_bytes, manifest_bytes, image_hashes):
    return {
        "cluster": {
            "name": args.cluster,
            "node_image": node_image,
            "kind_config_sha256": digest(cluster_bytes),
        },
        "images": image_hashes,
        "manifest_sha256": digest(manifest_bytes),
    }


def _owner_arguments(
    root: Path, name: str, binding: dict, sources: dict, boot_path: Path
):
    operation = {
        "operation": "capture",
        "key": name,
        "sequence": 0,
        "body": {
            "binding": binding,
            "capture": {
                "sources": sources,
                "attempt": "setup",
                "stages": [1, 2, 3, 4, 5],
                "boot_id": boot_path.read_text(encoding="utf-8").strip(),
            },
        },
    }
    label = sha(encode(["capture", name]))
    operation_store = DurableStore(
        root.parent / (root.name + "-operations"),
        {"operations": {label: operation}},
        initialize=True,
    )
    store = DurableStore(root.parent / (root.name + "-store"), {}, initialize=True)
    return {
        "store": store,
        "operation_store": operation_store,
        "operation": operation,
        "binding": binding,
        "root": root,
        "boot_path": boot_path,
    }


def _measurement_boot(port: int) -> str:
    connection = http.client.HTTPConnection(
        "127.0.0.1", port, timeout=ROW5_KIND_MEASUREMENT_PROBE_TIMEOUT_S
    )
    try:
        connection.request("GET", "/internal/measurement?offset=0")
        response = connection.getresponse()
        body = response.read(8_388_609)
        if response.status != 200 or len(body) > 8_388_608:
            raise Refusal("kind_gateway_measurement_probe")
        boot = response.getheader("X-Capture-Boot")
        next_offset = response.getheader("X-Capture-Next")
        if not boot or next_offset != str(len(body)) or not body.endswith(b"\n"):
            raise Refusal("kind_gateway_measurement_probe")
        return boot
    finally:
        connection.close()


def _run_live(
    args,
    budget,
    kubectl,
    kubeconfig,
    context,
    namespace,
    output,
    forwards,
    logs,
    capture_owners,
    cleanups,
    manifest,
    manifest_sha,
    report,
):
    def call(argv, *, timeout=ROW5_KIND_COMMAND_TIMEOUT_S, **kwargs):
        return package_a.run(argv, timeout=budget.cap(timeout), **kwargs)

    def k(*argv, timeout=ROW5_KIND_COMMAND_TIMEOUT_S, **kwargs):
        return call(
            [
                kubectl,
                "--kubeconfig",
                kubeconfig,
                "--context",
                context,
                "-n",
                namespace,
                *argv,
            ],
            timeout=timeout,
            **kwargs,
        )

    nodes = [
        args.cluster + suffix for suffix in ("-control-plane", "-worker", "-worker2")
    ]
    for node in nodes:
        call(
            [
                "docker",
                "update",
                "--cpus",
                "2" if node == nodes[0] else "1",
                "--memory",
                "2560m" if node == nodes[0] else "1024m",
                "--memory-swap",
                "2560m" if node == nodes[0] else "1024m",
                node,
            ]
        )
        k("label", "node", node, "m5-role=" + ("cpu" if node == nodes[0] else "gpu"))
    k("taint", "node", nodes[0], "node-role.kubernetes.io/control-plane-", check=False)
    for node in nodes[1:]:
        k("taint", "node", node, "nvidia.com/gpu=true:NoSchedule")
        k(
            "patch",
            "node",
            node,
            "--subresource=status",
            "--type=merge",
            "-p",
            json.dumps(
                {
                    "status": {
                        "capacity": {"nvidia.com/gpu": "1"},
                        "allocatable": {"nvidia.com/gpu": "1"},
                    }
                }
            ),
        )
    k(
        "wait",
        "--for=condition=Ready",
        "nodes",
        "--all",
        f"--timeout={ROW5_KIND_NODE_READY_TIMEOUT_S}s",
        timeout=ROW5_KIND_NODE_READY_TIMEOUT_S,
    )

    image_hashes = report["images"]
    local_images = (args.gateway_image, "mti-fake:stage1")
    with tempfile.TemporaryDirectory(prefix="row5-kind-images-") as image_tmp:
        archive = Path(image_tmp) / "redis-amd64.tar"
        status, _ = package_a.run(
            ["docker", "image", "inspect", REDIS_IMAGE],
            timeout=budget.cap(ROW5_KIND_IMAGE_INSPECT_TIMEOUT_S),
            check=False,
            return_status=True,
        )
        if status:
            call(
                ["docker", "pull", REDIS_IMAGE], timeout=ROW5_KIND_REDIS_PULL_TIMEOUT_S
            )
        image = package_a.load_kind_image_archive(
            shutil.which(args.kind_bin)
            if args.kind_bin and shutil.which(args.kind_bin)
            else ROOT / ".tools" / ("kind.exe" if os.name == "nt" else "kind"),
            REDIS_IMAGE,
            archive,
            args.cluster,
            package_a.KIND_LOCAL_IMAGE_TAGS["redis"],
            call,
        )
        image_hashes["redis"] = image.get("config_digest") or image.get("source_digest")
    for local in local_images:
        status, _ = package_a.run(
            ["docker", "image", "inspect", local],
            timeout=budget.cap(ROW5_KIND_IMAGE_INSPECT_TIMEOUT_S),
            check=False,
            return_status=True,
        )
        if status:
            raise Refusal("kind_local_image_missing", local)
        kind_command = args.kind_bin or str(
            ROOT / ".tools" / ("kind.exe" if os.name == "nt" else "kind")
        )
        image_hashes["gateway" if local == args.gateway_image else "mock_vllm"] = (
            package_a.load_kind_local_image(kind_command, local, args.cluster, call)
        )

    rendered, used_images = render_row5_manifest(namespace, args.gateway_image)
    check_row5_manifest_images(used_images, args.gateway_image)
    endpoint_reader_role = next(
        item
        for item in rendered["items"]
        if item["kind"] == "Role" and item["metadata"]["name"] == "endpoint-reader"
    )
    manifest_bytes = (
        json.dumps(rendered, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    )
    if digest(manifest_bytes) != manifest_sha:
        raise Refusal("kind_manifest_changed_after_create")
    manifest_path = output / "row5-resources.json"
    manifest_path.write_bytes(manifest_bytes)
    timed_step(
        report,
        "manifest-application-and-gateway-start",
        lambda: apply_manifest_steps(
            kubectl,
            kubeconfig,
            context,
            namespace,
            manifest_path,
            timeout=ROW5_KIND_DEPLOYMENT_ROLLOUT_TIMEOUT_S,
        ),
    )
    try:
        timed_step(
            report,
            "redis-rollout-ready",
            lambda: k(
                "rollout",
                "status",
                "deployment/redis",
                f"--timeout={ROW5_KIND_DEPLOYMENT_ROLLOUT_TIMEOUT_S}s",
                timeout=ROW5_KIND_REDIS_ROLLOUT_TIMEOUT_S,
            ),
        )
    except Exception as exc:
        raise Refusal("kind_redis_readiness", str(exc)) from exc

    # Create a short-lived, narrowly scoped operator identity for RoleControl.
    operator_manifest = operator_rbac_manifest(namespace, endpoint_reader_role)
    operator_path = output / "operator-rbac.json"
    operator_path.write_text(json.dumps(operator_manifest), encoding="utf-8")

    def create_operator_token():
        k(
            "apply",
            "--validate=false",
            "-f",
            operator_path,
            timeout=ROW5_KIND_OPERATOR_TIMEOUT_S,
        )
        return k(
            "create",
            "token",
            "row5-operator",
            "--duration=1h",
            timeout=ROW5_KIND_OPERATOR_TIMEOUT_S,
        ).strip()

    token = timed_step(report, "operator-identity-and-token", create_operator_token)
    if not token:
        raise Refusal("kind_operator_token_missing")

    api_info = timed_step(
        report,
        "operator-api-discovery",
        lambda: strict_json(
            k(
                "config",
                "view",
                "--raw",
                "-o",
                "json",
                timeout=ROW5_KIND_OPERATOR_TIMEOUT_S,
            ).encode()
        ),
    )
    current = api_info["current-context"]
    selected = next(c["context"] for c in api_info["contexts"] if c["name"] == current)
    cluster = next(
        c["cluster"] for c in api_info["clusters"] if c["name"] == selected["cluster"]
    )
    ca_data = cluster.get("certificate-authority-data")
    if not ca_data:
        raise Refusal("kind_api_ca_missing")
    ca_path = output / "kind-api-ca.crt"
    ca_path.write_bytes(base64.b64decode(ca_data))
    api_base = cluster["server"]

    def wait(
        predicate,
        timeout=ROW5_KIND_SCALE_OBSERVE_TIMEOUT_S,
        *,
        step_name,
        bound_subprocess=False,
    ):
        return wait_for_step(
            predicate,
            timeout,
            step_name=step_name,
            budget=budget,
            report=report,
            bound_subprocess=bound_subprocess,
        )

    def forward(resource, remote):
        return package_a.start_forward(
            kubectl,
            kubeconfig,
            context,
            namespace,
            output,
            resource,
            remote,
            forwards,
            logs,
            wait,
            step_name="port-forward-" + resource.replace("/", "-") + "-ready",
        )

    redis_port, gateway_ports = timed_step(
        report,
        "redis-and-gateway-port-forwards",
        lambda: (
            forward("service/redis", 6379),
            {
                g: forward(f"pod/gateway-{i}", 8080)
                for i, g in enumerate(("gateway0", "gateway1"))
            },
        ),
    )
    gateway_boots = timed_step(
        report,
        "gateway-measurement-endpoints",
        lambda: {g: _measurement_boot(port) for g, port in gateway_ports.items()},
    )
    boot_path = Path("/proc/sys/kernel/random/boot_id")
    collector_boot = boot_path.read_text(encoding="utf-8").strip()
    binding = {
        "session_id": "kind-row5-" + uuid.uuid4().hex,
        "pins": {"configuration": "0" * 64, "manifest": manifest_sha},
        "t0_ms": time.monotonic_ns() // 1_000_000,
    }
    configuration_sha = None
    config = {
        "redis_addr": "redis:6379",
        "namespace": namespace,
        "global_capacity": 64,
        "lease_ms": 90000,
        "tombstone_ms": 300000,
        "running": 4,
        "waiting": 1,
        "ttl_ms": ROW5_KIND_PINNED_TTL_MS,
        "hold_ms": ROW5_KIND_PINNED_HOLD_MS,
        "capture": True,
    }
    configuration_sha = sha(encode(config))
    binding["pins"]["configuration"] = configuration_sha
    sources = {g: [["gateway", g, gateway_boots[g]]] for g in gateway_boots}
    (output / "captures").mkdir(parents=True, exist_ok=True)
    start_args = _owner_arguments(
        output / "captures" / "configuration",
        "row5-configuration",
        binding,
        sources,
        boot_path,
    )
    configuration_owner = timed_step(
        report,
        "configuration-capture-owner",
        lambda: CaptureOwner(
            **start_args,
            sources=sources,
            attempt="setup",
            stages=[1, 2, 3, 4, 5],
        ),
    )
    capture_owners.append(configuration_owner)
    configuration_stop_ns = (
        time.monotonic_ns() + ROW5_KIND_CONFIGURATION_CAPTURE_TIMEOUT_S * 1_000_000_000
    )

    def capture_gateway_configurations():
        for gateway, port in gateway_ports.items():
            client = DeadlineHTTP(
                "http://127.0.0.1:" + str(port),
                stop_ns=configuration_stop_ns,
                retain=configuration_owner.retainer(gateway),
                local_test=True,
            )
            body, headers = client.get("/internal/measurement?offset=0")
            if headers.get("X-Capture-Boot") != gateway_boots[
                gateway
            ] or not body.endswith(b"\n"):
                raise Refusal("kind_gateway_configuration_capture", gateway)

    timed_step(report, "gateway-configuration-capture", capture_gateway_configurations)

    role_object = endpoint_reader_role
    binding_object = next(
        o
        for o in rendered["items"]
        if o["kind"] == "RoleBinding" and o["metadata"]["name"] == "gateway-endpoints"
    )
    owner_holder = {}

    def retain_role(*args, **kwargs):
        retain_row5_role(owner_holder, *args, **kwargs)

    role_http = BoundedRBACHTTP(
        api_base,
        token=lambda: token,
        deadline_ns=time.monotonic_ns()
        + ROW5_KIND_STAGE_WINDOW_TIMEOUT_S * 1_000_000_000,
        retain=retain_role,
        ca=ca_path,
    )
    role = RoleControl(
        KubernetesRolePort(role_http),
        namespace,
        role_object,
        binding_object,
        hashlib.sha256(canonical_role(role_object)).hexdigest(),
    )

    diagnostic_binary = output / "row5-diagnostic"
    call(
        ["go", "build", "-o", diagnostic_binary, "./cmd/row5-diagnostic"],
        timeout=ROW5_KIND_DIAGNOSTIC_BUILD_TIMEOUT_S,
    )
    runtime_sources = row5_runtime_sources(gateway_boots, collector_boot)
    runtime_args = _owner_arguments(
        output / "captures" / "runtime",
        "row5-runtime",
        binding,
        runtime_sources,
        boot_path,
    )
    stop_event = threading.Event()
    collector_errors = []
    collector_holder = {"ports": None, "thread": None, "started": False}

    def stop_collectors():
        stop_event.set()
        thread = collector_holder["thread"]
        try:
            if thread is not None and collector_holder["started"]:
                thread.join(timeout=5)
                if thread.is_alive():
                    raise IntegrityError("fitness:row5_collector_join")
        finally:
            ports = collector_holder["ports"]
            if ports is not None and (thread is None or not thread.is_alive()):
                report.update(ports.window_summary())
        if collector_errors:
            raise IntegrityError("fitness:row5_collector:" + str(collector_errors[0]))

    cleanups.append(stop_collectors)

    live_gateways = {
        g: {
            "boot": gateway_boots[g],
            "http": {
                "base": "http://127.0.0.1:" + str(gateway_ports[g]),
                "local_test": True,
            },
            "request": {
                "url": "http://127.0.0.1:"
                + str(gateway_ports[g])
                + "/v1/chat/completions",
                "payload": {
                    "model": "test-model",
                    "messages": [{"role": "user", "content": "row5 kind rehearsal"}],
                    "max_tokens": 8,
                    "stream": True,
                },
                "credential": "local-dev-token",
                "local_test": True,
            },
        }
        for g in gateway_boots
    }
    runtime_root = output / "captures" / "runtime"
    wire = RedisWire(
        "127.0.0.1",
        redis_port,
        tls=False,
        local_test=True,
        stop_ns=time.monotonic_ns() + ROW5_KIND_STAGE_WINDOW_TIMEOUT_S * 1_000_000_000,
    )

    def retain_step_timing(name, elapsed_ms):
        report.setdefault("timings_ms", {})["step:" + name] = elapsed_ms

    ports = kind_row5_ports(
        store=runtime_args["store"],
        operation_store=runtime_args["operation_store"],
        operation=runtime_args["operation"],
        binding=binding,
        root=runtime_root,
        gateways=live_gateways,
        gateway_configuration_owner=configuration_owner,
        dial_addr="127.0.0.1:" + str(redis_port),
        step_timing=retain_step_timing,
        redis_wire=wire,
        redis_gateway_ids={"gateway-0": "gateway0", "gateway-1": "gateway1"},
        slots={"vllm-0": 0, "vllm-1": 1},
        role=role,
        binary=diagnostic_binary,
        binary_sha256=digest(diagnostic_binary.read_bytes()),
        config=config,
        measured_tenants=["tenant-local"],
        configuration_sha256=configuration_sha,
        stop_ns=time.monotonic_ns() + ROW5_KIND_STAGE_WINDOW_TIMEOUT_S * 1_000_000_000,
        stop_collectors=stop_collectors,
    )
    owner_holder["owner"] = ports.owner
    runtime_owner = ports.owner
    capture_owners.append(runtime_owner)
    cleanups.append(wire.close)
    collector_holder["ports"] = ports

    ports.live.row5_control.retain_inputs = retain_kind_row5_inputs_before_proofs(
        output, ports
    )

    def collect():
        last = time.monotonic_ns()
        try:
            while not stop_event.wait(0.2):
                with ports.live.lock:
                    ports.live.poll()
                    ports.poll_clocks()
                    now = time.monotonic_ns()
                    runtime_owner.group_tick_intervals_ms.append((now - last) / 1e6)
                    runtime_owner.group_barrier()
                    last = now
        except Exception as exc:
            collector_errors.append(exc)
            stop_event.set()

    collector_thread = threading.Thread(
        target=collect, name="row5-kind-collectors", daemon=True
    )
    collector_holder["thread"] = collector_thread
    ports.start_window()
    collector_thread.start()
    collector_holder["started"] = True

    overall_stop_ns = (
        time.monotonic_ns() + ROW5_KIND_STAGE_WINDOW_TIMEOUT_S * 1_000_000_000
    )

    def check_collectors():
        if collector_errors:
            raise IntegrityError("fitness:row5_collector:" + str(collector_errors[0]))

    def statefulset(timeout=ROW5_KIND_COMMAND_TIMEOUT_S):
        return strict_json(
            k("get", "statefulset", "vllm", "-o", "json", timeout=timeout).encode()
        )

    def pods(timeout=ROW5_KIND_COMMAND_TIMEOUT_S):
        return strict_json(
            k("get", "pods", "-l", "app=vllm", "-o", "json", timeout=timeout).encode()
        ).get("items", [])

    def ready_count(timeout=ROW5_KIND_COMMAND_TIMEOUT_S):
        return sum(
            any(
                c.get("type") == "Ready" and c.get("status") == "True"
                for c in p.get("status", {}).get("conditions", [])
            )
            for p in pods(timeout=timeout)
        )

    def scale(n):
        k("scale", "statefulset/vllm", f"--replicas={n}")
        wait(
            lambda timeout: statefulset(timeout).get("spec", {}).get("replicas") == n,
            ROW5_KIND_SCALE_OBSERVE_TIMEOUT_S,
            step_name=f"known{n}-replicas-observed",
            bound_subprocess=True,
        )
        wait(
            lambda timeout: ready_count(timeout) == n,
            ROW5_KIND_SCALE_READY_TIMEOUT_S,
            step_name=f"known{n}-pods-ready",
            bound_subprocess=True,
        )
        check_collectors()

    stage_requests = []
    for name, replicas in (("known0", 0), ("known1", 1), ("known2", 2)):
        timed_step(report, name + "-scale", lambda replicas=replicas: scale(replicas))
        stage_requests.extend(
            timed_step(
                report,
                name + "-proofs",
                lambda name=name: ports.live.row5_stage(name, overall_stop_ns),
            )
        )
        check_collectors()

    before_pods = timed_step(
        report,
        "gpu-release-initial-pods",
        lambda: {p["metadata"]["name"]: p for p in pods()},
    )
    old = before_pods.get("vllm-1")
    if not old or not old.get("spec", {}).get("nodeName"):
        raise Refusal("kind_gpu_release_target_missing")
    target_node = old["spec"]["nodeName"]
    old_uid = old["metadata"]["uid"]
    timed_step(report, "gpu-release-cordon", lambda: k("cordon", target_node))
    timed_step(
        report,
        "gpu-release-delete-old-pod",
        lambda: k(
            "delete",
            "pod",
            "vllm-1",
            "--wait=true",
            f"--timeout={ROW5_KIND_GPU_PENDING_TIMEOUT_S}s",
            timeout=ROW5_KIND_GPU_DELETE_TIMEOUT_S,
        ),
    )

    def replacement_pending(timeout):
        current = {p["metadata"]["name"]: p for p in pods(timeout=timeout)}
        replacement = current.get("vllm-1")
        return (
            replacement
            if replacement
            and replacement.get("metadata", {}).get("uid") != old_uid
            and replacement.get("status", {}).get("phase") == "Pending"
            else None
        )

    pending = None
    pending_started_ns = time.monotonic_ns()
    try:
        deadline = time.monotonic() + budget.cap(ROW5_KIND_GPU_PENDING_TIMEOUT_S)
        while pending is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            pending = replacement_pending(
                min(ROW5_KIND_GPU_PENDING_TIMEOUT_S, remaining)
            )
            if pending is None:
                time.sleep(min(0.25, max(0, deadline - time.monotonic())))
    finally:
        complete_step(report, "gpu-release-replacement-pending", pending_started_ns)
    if pending is None:
        raise Refusal("kind_gpu_release_replacement_not_pending")
    ready_started_ns = time.monotonic_ns()
    try:
        ready_slots = ready_count()
    finally:
        complete_step(report, "gpu-release-ready-slot-count", ready_started_ns)
    if ready_slots != 1:
        raise Refusal("kind_gpu_release_ready_slot_count")
    node_json = timed_step(
        report,
        "gpu-release-node-readback",
        lambda: strict_json(k("get", "node", target_node, "-o", "json").encode()),
    )
    target_gpu_pods = timed_step(
        report,
        "gpu-release-assigned-pod-readback",
        lambda: [
            p["metadata"]["name"]
            for p in strict_json(k("get", "pods", "-A", "-o", "json").encode()).get(
                "items", []
            )
            if p.get("spec", {}).get("nodeName") == target_node
            and any(
                "nvidia.com/gpu" in c.get("resources", {}).get("requests", {})
                for c in p.get("spec", {}).get("containers", [])
            )
        ],
    )
    if (
        node_json.get("status", {}).get("allocatable", {}).get("nvidia.com/gpu") != "1"
        or target_gpu_pods
    ):
        raise Refusal("kind_gpu_release_proof_failed")
    gpu_release_proof = {
        "old_pod_uid": old_uid,
        "replacement_pod_uid": pending["metadata"]["uid"],
        "replacement_phase": "Pending",
        "replacement_node": pending.get("spec", {}).get("nodeName"),
        "released_node": target_node,
        "advertised_gpu": node_json["status"]["allocatable"]["nvidia.com/gpu"],
        "assigned_gpu_pods": target_gpu_pods,
    }
    stage_requests.extend(
        timed_step(
            report,
            "cached-stop-known1-proofs",
            lambda: ports.live.row5_stage("cached_stop_known1", overall_stop_ns),
        )
    )
    check_collectors()
    cached_stop = ports.live.stage_snapshots.get("cached_stop_known1")
    if cached_stop is None:
        raise Refusal("kind_restore_cached_stop_snapshot_missing")
    cached_stop_time_ms = cached_stop["payload"]["redis_time_ms"]
    uncordon_started = time.monotonic()
    timed_step(
        report,
        "gpu-release-uncordon",
        lambda: k("uncordon", target_node, timeout=ROW5_KIND_COMMAND_TIMEOUT_S),
    )

    def live_snapshot(name=None, *, label_if=None):
        with ports.live.lock:
            ports.live.poll()
            return ports.live.redis.snapshot(snapshot_id=name, label_if=label_if)

    hold_start_started_ns = time.monotonic_ns()
    try:
        hold_start = wait_for_restoration_hold_start(
            live_snapshot,
            budget.cap(restore_window_s(config)),
        )
    finally:
        complete_step(report, "restoration-hold-start", hold_start_started_ns)
    uncordon_to_hold_start_ms = round((time.monotonic() - uncordon_started) * 1000)
    if hold_start is None:
        raise Refusal("kind_restore_hold_candidate_missing")
    start_state = hold_start.get("payload", {}).get("state", {})
    since_ms = start_state.get("since_ms")
    hold_start_time_ms = hold_start["payload"]["redis_time_ms"]
    hold_ms = config["hold_ms"]
    if (
        type(since_ms) is not int
        or since_ms > hold_start_time_ms
        or since_ms <= cached_stop_time_ms
    ):
        raise Refusal("kind_restore_hold_start_since_invalid")
    transition_deadline_ms = since_ms + hold_ms
    hold_end_started_ns = time.monotonic_ns()
    hold_end = None
    try:
        hold_deadline = time.monotonic() + ROW5_KIND_HOLD_END_TIMEOUT_S
        while time.monotonic() < hold_deadline:
            time.sleep(ROW5_KIND_HOLD_POLL_INTERVAL_S)
            current = live_snapshot()
            if current is None:
                continue
            reports = current.get("payload", {}).get("reports", {})
            state = current.get("payload", {}).get("state", {})
            now_ms = current.get("payload", {}).get("redis_time_ms", 0)
            reports_fresh_known2 = set(reports) == {"gateway0", "gateway1"} and all(
                r.get("n") == 2
                and r.get("unknown") is False
                and type(r.get("expires_ms")) is int
                and r["expires_ms"] > now_ms
                for r in reports.values()
            )
            if (
                state.get("n") == 2
                and reports_fresh_known2
                and now_ms >= transition_deadline_ms
            ):
                hold_end = require_hold_end_snapshot(live_snapshot)
                end_state = hold_end.get("payload", {}).get("state", {})
                end_payload = hold_end.get("payload", {})
                end_reports = end_payload.get("reports", {})
                if (
                    end_state.get("n") != 2
                    or end_payload.get("redis_time_ms", 0) - since_ms < hold_ms
                    or set(end_reports) != {"gateway0", "gateway1"}
                    or any(
                        r.get("n") != 2
                        or r.get("unknown") is not False
                        or type(r.get("expires_ms")) is not int
                        or r["expires_ms"] <= end_payload.get("redis_time_ms", 0)
                        for r in end_reports.values()
                    )
                ):
                    hold_end = None
                else:
                    break
        if hold_end is None:
            raise Refusal("kind_restore_hold_proof_failed")
    finally:
        complete_step(report, "restoration-hold-end", hold_end_started_ns)
    hold_proof = {
        "start_redis_time_ms": hold_start_time_ms,
        "since_ms": since_ms,
        "end_redis_time_ms": hold_end["payload"]["redis_time_ms"],
        "effective_n": hold_end["payload"]["state"].get("n"),
        "transition_deadline_ms": transition_deadline_ms,
        "uncordon_to_hold_start_ms": uncordon_to_hold_start_ms,
        "report_gateways": sorted(hold_end["payload"]["reports"]),
    }
    stage_requests.extend(
        timed_step(
            report,
            "cached-restore-known2-proofs",
            lambda: ports.live.row5_stage("cached_restore_known2", overall_stop_ns),
        )
    )
    prepared = {
        "fitness_raw": encode(
            {
                "schema": "inf037b-setup-v1",
                "session_id": binding["session_id"],
                "pins": binding["pins"],
                "t0_ms": binding["t0_ms"],
                "raw": [],
            }
        )
    }
    control_result = timed_step(
        report,
        "rbac-outage-restore-recovery-controls",
        lambda: ports.live.row5_control(overall_stop_ns, prepared),
    )
    check_collectors()
    control_result.update(ports.window_summary())
    report.update(ports.window_summary())
    all_requests = [*stage_requests, *control_result["row5_control_requests"]]
    validator = timed_step(
        report,
        "validate-kind-row5",
        lambda: validate_retained_kind_row5(
            output,
            control_result,
            all_requests,
            configuration_sha256=configuration_sha,
            binding=binding,
        ),
    )
    raw = strict_json(control_result["fitness_raw"])["raw"]
    join = SourceJoin(raw)
    if join.errors:
        raise IntegrityError("setup:source_join")
    timings = timed_step(
        report,
        "row5-control-timings",
        lambda: row5_timings(join.rows, control_result["row5_evidence"]),
    )
    if set(timings) != {"gateway0", "gateway1"}:
        raise Refusal("kind_timing_gateway_inventory")
    return {
        "validator": validator,
        "timings_ms": timings,
        "gpu_release_proof": gpu_release_proof,
        "hold_proof": hold_proof,
        "known_stage_requests": len(stage_requests),
        "outage_requests": len(control_result["row5_control_requests"]),
        "control_requests": len(all_requests),
        "image_hashes": image_hashes,
        **ports.window_summary(),
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--gateway-image", required=True)
    parser.add_argument("--cluster", default="row5-" + uuid.uuid4().hex[:10])
    parser.add_argument("--kind-bin")
    parser.add_argument("--kubectl-bin")
    parser.add_argument(
        "--api-server", help="loopback fake API mode; applies and waits only"
    )
    parser.add_argument("--readiness-timeout", type=int, default=60)
    parser.add_argument(
        "--runner-timeout", type=int, default=package_a.KIND_RUNNER_TIMEOUT_S
    )
    args = parser.parse_args(argv)
    if args.readiness_timeout <= 0:
        parser.error("--readiness-timeout must be positive")
    if args.runner_timeout <= 0:
        parser.error("--runner-timeout must be positive")
    report = {
        "schema": "inf037b-row5-kind-rehearsal-v1",
        "status": "refused",
        "exit_status": 1,
        "refusal": None,
        "validator": None,
        "timings_ms": {},
        "cluster": {"name": args.cluster},
        "images": {},
        "manifest_sha256": None,
    }
    budget = package_a.WorkBudget(args.runner_timeout)
    forwards, logs = [], []
    capture_owners, cleanups = [], []
    kind = kubeconfig = None
    owns_cluster = False
    output_created = False
    cleanup_errors = []
    try:
        if os.name != "posix" and not (args.api_server or args.kind_bin):
            raise Refusal("row5_requires_linux_capture_host")
        if args.output.exists():
            raise Refusal("kind_output_must_be_new")
        if not re.fullmatch(r"row5-[a-z0-9-]{1,35}", args.cluster):
            raise Refusal("kind_cluster_name_must_be_owned")
        args.output.mkdir(parents=True)
        output_created = True
        pins = json.loads(
            (ROOT / "deploy" / "k8s" / "pins.json").read_text(encoding="utf-8")
        )
        kind = None if args.api_server else _tool(args.kind_bin, "kind", pins)[0]
        kubectl, _ = _tool(args.kubectl_bin, "kubectl", pins)
        cluster_data = (
            json.dumps(kind_config(), sort_keys=True, separators=(",", ":")).encode()
            + b"\n"
        )
        (args.output / "kind.json").write_bytes(cluster_data)
        namespace = NAMESPACE_PREFIX + args.cluster.removeprefix("row5-")
        rendered, _ = render_row5_manifest(namespace, args.gateway_image)
        manifest_data = (
            json.dumps(rendered, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        )
        manifest_hash = digest(manifest_data)
        report.update(
            _hashes(
                args,
                pins["node_image"],
                cluster_data,
                manifest_data,
                {"redis": None, "gateway": None, "mock_vllm": None},
            )
        )
        report["manifest_sha256"] = manifest_hash
        manifest_path = args.output / "row5-resources.json"
        manifest_path.write_bytes(manifest_data)

        if args.api_server:
            _fake_kubeconfig(args.api_server, args.output / "kubeconfig")
            try:
                apply_manifest_steps(
                    kubectl,
                    str(args.output / "kubeconfig"),
                    "row5-api",
                    namespace,
                    manifest_path,
                    timeout=args.readiness_timeout,
                )
            except Refusal as exc:
                raise Refusal(exc.name, exc.detail) from exc
            report.update(status="api_steps_complete", exit_status=0)
            return 0

        config_path = args.output / "kind.json"
        kubeconfig = args.output / "kubeconfig"
        context = "kind-" + args.cluster

        def call(argv, *, timeout=180, **kwargs):
            try:
                return package_a.run(argv, timeout=budget.cap(timeout), **kwargs)
            except Exception as exc:
                raise Refusal("kind_command_failed", f"{argv[0]}:{exc}") from exc

        existing = call(
            [kind, "get", "clusters"], timeout=ROW5_KIND_CLUSTER_PROBE_TIMEOUT_S
        ).splitlines()
        if args.cluster in existing:
            raise Refusal("kind_owned_name_already_exists")
        owns_cluster = True
        try:
            package_a.create_kind_cluster(
                kind,
                args.cluster,
                pins["node_image"],
                config_path,
                kubeconfig,
                call,
                timeout=ROW5_KIND_CLUSTER_CREATE_TIMEOUT_S,
            )
        except Exception as exc:
            raise Refusal("kind_create_failed", str(exc)) from exc
        if not kubeconfig.exists():
            raise Refusal("kind_kubeconfig_missing")
        values = _run_live(
            args,
            budget,
            kubectl,
            str(kubeconfig),
            context,
            namespace,
            args.output,
            forwards,
            logs,
            capture_owners,
            cleanups,
            rendered,
            manifest_hash,
            report,
        )
        report.update(
            status="accepted",
            exit_status=0,
            refusal=None,
            validator=values["validator"],
            timings_ms={**report.get("timings_ms", {}), **values["timings_ms"]},
            evidence={
                k: values[k]
                for k in (
                    "gpu_release_proof",
                    "hold_proof",
                    "known_stage_requests",
                    "outage_requests",
                    "control_requests",
                    "row5_window_start",
                    "row5_prewindow_skipped_counts",
                )
            },
            images=values["image_hashes"],
        )
    except BaseException as exc:
        name = (
            exc.name
            if isinstance(exc, Refusal)
            else str(exc)
            if isinstance(exc, IntegrityError)
            else "kind_unexpected_" + type(exc).__name__
        )
        report.update(status="refused", exit_status=1, refusal=name)
        refusal_line = "row5_kind_refusal:" + name
        if isinstance(exc, Refusal) and exc.detail:
            detail = exc.detail[:500]
            report["refusal_detail"] = detail
            refusal_line += ":" + detail
        print(refusal_line, file=sys.stderr, flush=True)
    finally:
        budget.cleanup = True
        for cleanup in cleanups:
            try:
                cleanup()
            except Exception as exc:
                cleanup_errors.append(
                    "row5_cleanup:" + type(exc).__name__ + ":" + str(exc)
                )
        for owner in reversed(capture_owners):
            try:
                if not owner.closed:
                    owner.close()
            except Exception as exc:
                cleanup_errors.append(
                    "capture_close:" + type(exc).__name__ + ":" + str(exc)
                )
        for process in forwards:
            try:
                process.terminate()
                process.wait(timeout=10)
            except Exception as exc:
                cleanup_errors.append("port_forward_cleanup:" + type(exc).__name__)
        for stream in logs:
            try:
                stream.close()
            except Exception as exc:
                cleanup_errors.append("port_forward_log_cleanup:" + type(exc).__name__)
        if owns_cluster and kind and kubeconfig and report.get("refusal"):
            try:
                report["diagnostics"] = capture_refusal_diagnostics(
                    kubectl,
                    kubeconfig,
                    context,
                    namespace,
                    args.output,
                )
            except Exception as exc:
                report["diagnostics_error"] = {
                    "error": type(exc).__name__,
                    "detail": str(exc)[:500],
                }
        if owns_cluster and kind and kubeconfig:
            try:
                package_a.delete_kind_cluster(
                    kind, args.cluster, kubeconfig, package_a.run, timeout=180
                )
            except Exception as exc:
                cleanup_errors.append("kind_delete_failed:" + type(exc).__name__)
                if report.get("refusal") is None:
                    report.update(
                        status="refused", exit_status=1, refusal="kind_delete_failed"
                    )
                    print(
                        "row5_kind_refusal:kind_delete_failed",
                        file=sys.stderr,
                        flush=True,
                    )
        if cleanup_errors:
            report["cleanup_errors"] = cleanup_errors
            if report.get("refusal") is None:
                report.update(
                    status="refused", exit_status=1, refusal="kind_cleanup_failed"
                )
                print(
                    "row5_kind_refusal:kind_cleanup_failed", file=sys.stderr, flush=True
                )
        if output_created:
            _write_report(args.output, report)
    return int(report.get("exit_status", 1))


def _write_report(output: Path, report: dict) -> int:
    output.mkdir(parents=True, exist_ok=True)
    target = output / "result.json"
    target.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, sort_keys=True), flush=True)
    return int(report.get("exit_status", 1))


if __name__ == "__main__":
    raise SystemExit(main())
