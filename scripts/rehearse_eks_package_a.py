"""Isolated kind rehearsal of rendered EKS resources with explicit CPU mocks.

Never uses the current kube context, AWS, a GPU, or a public registry push.
"""

import argparse
import copy
import hashlib
import http.client
import json
import math
import os
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from inference_platform.eks_deployment import resources
from inference_platform.inf037b_requests import SSEDecoder
from inference_platform.inf037b_live import HTTP, LiveRows, NodeCacheAdapter
from inference_platform.inf037b_sources import ClockMapper, SourceJoin
from inference_platform.eks_deployment import (
    NGINX_IMAGE,
    PROMETHEUS_IMAGE,
    PYTHON_IMAGE,
    REDIS_IMAGE,
)
from inference_platform.package_a_images import (
    KIND_ARCHIVE_LOAD_TIMEOUT_S,
    KIND_LOCAL_IMAGE_TAGS,
    KIND_LOCAL_IMAGE_INSPECT_TIMEOUT_S,
    KIND_LOCAL_IMAGE_LOAD_TIMEOUT_S,
    crictl_image_resolution_matches,
    rewrite_kind_workload_images,
    save_amd64_archive,
)
from inference_platform.package_a_workload import write_kind_secret, test_tls_command
from inference_platform.package_a_cloud import (
    KIND_RUNNER_TIMEOUT_S,
    ROW5_KIND_CLEANUP_RESERVE_S,
    ROW5_KIND_PORT_FORWARD_CONNECT_TIMEOUT_S,
    ROW5_KIND_PORT_FORWARD_READY_TIMEOUT_S,
    ROW5_KIND_RECEIPT_RESERVE_S,
)

ROOT = Path(__file__).resolve().parents[1]
DIAGNOSTIC_COMMAND_TIMEOUT_S = 15
DIAGNOSTIC_CAPTURE_BUDGET_S = 60
DIAGNOSTIC_FILE_LIMIT_BYTES = 256 * 1024
KIND_CLEANUP_RESERVE_S = ROW5_KIND_CLEANUP_RESERVE_S
KIND_RECEIPT_RESERVE_S = ROW5_KIND_RECEIPT_RESERVE_S
ADMISSION_READER_TIMEOUT_S = 5


def admission_settings(manifest):
    container = next(
        obj
        for obj in manifest["items"]
        if obj["kind"] == "StatefulSet" and obj["metadata"]["name"] == "gateway"
    )["spec"]["template"]["spec"]["containers"][0]
    return {entry["name"]: entry.get("value") for entry in container["env"]}


def admission_timing(env):
    """Derive the wait from rendered policy, Go timing and the reader timeout.

    Lua retains a lower report for TTL + hold; the candidate then needs another
    full hold. Include freshness, two report periods and one reader timeout.
    """

    def duration(value):
        match = re.fullmatch(r"([0-9.]+)(ms|s)", value)
        if not match:
            raise ValueError("unsupported_admission_duration:" + value)
        return float(match[1]) / (1000 if match[2] == "ms" else 1)

    backend = (ROOT / "internal/gateway/backend.go").read_text(encoding="utf-8")
    main = (ROOT / "cmd/gateway/main.go").read_text(encoding="utf-8")

    def constant(name):
        match = re.search(
            r"const " + name + r" = (?:(\d+) \* )?time\.(Second|Millisecond)", backend
        )
        if not match:
            raise ValueError("health_timing_source_changed:" + name)
        return int(match[1] or 1) / (1000 if match[2] == "Millisecond" else 1)

    constructor = (
        "NewDiscoveryRegistry"
        if env.get("BACKEND_DISCOVERY") == "endpointslices"
        else "NewRegistry"
    )
    match = re.search(constructor + r"\([^\n]*?([0-9]+)\*time.Millisecond\)", main)
    if not match:
        raise ValueError("registry_period_source_changed")
    period = int(match[1]) / 1000
    freshness = (
        period
        + constant("HealthCheckTimeout")
        + 2 * constant("CapacityReportTimeout")
        + constant("HealthFreshnessMargin")
    )
    terms = {
        "report_ttl_s": duration(env["ADMISSION_REPORT_TTL"]),
        "hold_down_s": duration(env["ADMISSION_HOLD_DOWN"]),
        "health_freshness_s": freshness,
        "report_period_s": period,
        "reader_timeout_s": ADMISSION_READER_TIMEOUT_S,
    }
    terms["deadline_s"] = (
        math.ceil(
            terms["report_ttl_s"] + 2 * terms["hold_down_s"] + freshness + 2 * period
        )
        + terms["reader_timeout_s"]
    )
    if terms["deadline_s"] >= KIND_RUNNER_TIMEOUT_S - KIND_CLEANUP_RESERVE_S:
        raise ValueError("admission_deadline_exceeds_work_budget")
    return terms


def wait_admission_capacity(reader, env, expected_n, records, *, timeout=None):
    """Observe effective Redis N without offering requests or bypassing hold-down."""
    timing = admission_timing(env)
    started = time.monotonic()
    allowed = (
        timing["deadline_s"] if timeout is None else min(timeout, timing["deadline_s"])
    )
    record = {
        **timing,
        "namespace": env["ADMISSION_NAMESPACE"],
        "expected_n": expected_n,
        "allowed_wait_s": allowed,
        "values": [],
        "complete": False,
    }
    records.append(record)
    last = None
    try:
        while time.monotonic() - started < allowed:
            raw = reader(allowed - (time.monotonic() - started))
            last = int(raw) if raw is not None and str(raw).strip() else None
            record["values"].append(last)
            if last == expected_n:
                record["complete"] = True
                return record
            time.sleep(min(0.1, max(0, allowed - (time.monotonic() - started))))
        raise TimeoutError(
            f"admission_capacity_not_restored:last_n={last}:expected_n={expected_n}"
        )
    finally:
        record["wait_s"] = time.monotonic() - started


class WorkBudget:
    """Reserve outer-runner time for diagnostics, owned cleanup and the receipt."""

    def __init__(self, timeout_s=KIND_RUNNER_TIMEOUT_S):
        if timeout_s <= KIND_CLEANUP_RESERVE_S + KIND_RECEIPT_RESERVE_S:
            raise ValueError("kind_runner_timeout_must_exceed_reserved_time")
        self.started = time.monotonic()
        self.end = self.started + timeout_s
        self.work_end = self.end - KIND_CLEANUP_RESERVE_S
        self.cleanup_end = self.end - KIND_RECEIPT_RESERVE_S
        self.cleanup = False

    def cap(self, requested):
        deadline = self.cleanup_end if self.cleanup else self.work_end
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            phase = "cleanup" if self.cleanup else "work"
            raise TimeoutError("kind_internal_deadline:" + phase)
        return min(float(requested), remaining)


def run(argv, *, timeout=180, check=True, return_status=False, return_details=False):
    result = subprocess.run(
        [str(v) for v in argv], capture_output=True, text=True, timeout=timeout
    )
    if check and result.returncode:
        command = [str(value) for value in argv]
        if "--context" in command:
            command = command[command.index("--context") + 2 :]
        raise RuntimeError(
            f"command_failed:{command}: {result.stdout[-2000:]} {result.stderr[-2000:]}"
        )
    if return_details:
        return {
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    return (result.returncode, result.stdout) if return_status else result.stdout


def create_kind_cluster(
    kind, cluster, image, config, kubeconfig, call=run, *, timeout=240
):
    """Create a uniquely owned kind cluster with Package A's pinned CLI shape."""
    return call(
        [
            kind,
            "create",
            "cluster",
            "--name",
            cluster,
            "--image",
            image,
            "--config",
            config,
            "--kubeconfig",
            kubeconfig,
        ],
        timeout=timeout,
    )


def delete_kind_cluster(kind, cluster, kubeconfig, call=run, *, timeout=180):
    """Delete only the caller's named kind cluster."""
    return call(
        [kind, "delete", "cluster", "--name", cluster, "--kubeconfig", kubeconfig],
        timeout=timeout,
    )


def load_kind_image_archive(kind, image, archive, cluster, local_tag, call=run):
    """Use the package's amd64 archive conversion and load it into kind."""
    receipt = save_amd64_archive(image, archive, call, local_tag=local_tag)
    call(
        [kind, "load", "image-archive", archive, "--name", cluster],
        timeout=KIND_ARCHIVE_LOAD_TIMEOUT_S,
    )
    return receipt


def load_kind_local_image(kind, image, cluster, call=run):
    """Verify a locally built image and load it without an implicit pull."""
    digest = call(
        ["docker", "image", "inspect", "--format", "{{.Id}}", image],
        timeout=KIND_LOCAL_IMAGE_INSPECT_TIMEOUT_S,
    ).strip()
    if not digest.startswith("sha256:"):
        raise ValueError("local_kind_image_config_digest_missing:" + image)
    call(
        [kind, "load", "docker-image", image, "--name", cluster],
        timeout=KIND_LOCAL_IMAGE_LOAD_TIMEOUT_S,
    )
    return digest


def render_kind_manifest(
    inputs, source, gateway_image, pulled_images, local_images, *, include=None
):
    """Render EKS resources and apply the shared CPU-only kind mock mutation."""
    manifest = resources(inputs, source)
    if include is not None:
        wanted = set(include)
        manifest["items"] = [
            item
            for item in manifest["items"]
            if (item["kind"], item["metadata"]["name"]) in wanted
        ]
        found = {(item["kind"], item["metadata"]["name"]) for item in manifest["items"]}
        if found != wanted:
            raise ValueError("kind_manifest_subset_incomplete")
    used_images = mutate_kind_manifest(
        manifest, gateway_image, pulled_images, local_images
    )
    return manifest, used_images


def _diagnostic_bytes(value):
    if value is None:
        return b""
    return value if isinstance(value, bytes) else str(value).encode("utf-8", "replace")


def capture_kind_diagnostics(
    output, kubectl, kubeconfig, context, namespace, nodes, *, admission_namespace=None
):
    """Best-effort, bounded diagnostics for an owned cluster before deletion."""
    started = time.monotonic()
    deadline = started + DIAGNOSTIC_CAPTURE_BUDGET_S
    directory = Path(output) / "diagnostics"
    result = {
        "complete": False,
        "budget_seconds": DIAGNOSTIC_CAPTURE_BUDGET_S,
        "command_timeout_seconds": DIAGNOSTIC_COMMAND_TIMEOUT_S,
        "file_limit_bytes": DIAGNOSTIC_FILE_LIMIT_BYTES,
        "files": [],
        "commands": [],
        "failures": [],
        "warnings": [],
    }
    index = 0
    stopped = False

    def capture(label, argv, *, missing_previous_allowed=False):
        nonlocal index, stopped
        if stopped:
            return None
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            result["failures"].append(
                {"stage": label, "error": "diagnostic_capture_budget_exhausted"}
            )
            stopped = True
            return None
        timeout = min(DIAGNOSTIC_COMMAND_TIMEOUT_S, remaining)
        safe_label = "".join(
            char if char.isalnum() or char in "-_." else "_" for char in label
        )[:80]
        relative = Path("diagnostics") / f"{index:03d}-{safe_label}.log"
        path = Path(output) / relative
        index += 1
        command = [str(value) for value in argv]
        record = {"stage": label, "command": command, "file": relative.as_posix()}
        stdout = b""
        stderr = b""
        try:
            observed = run(
                argv,
                timeout=timeout,
                check=False,
                return_details=True,
            )
            if not isinstance(observed, dict):
                raise TypeError("diagnostic_run_result_not_mapping")
            code = observed.get("returncode")
            stdout = _diagnostic_bytes(observed.get("stdout"))
            stderr = _diagnostic_bytes(observed.get("stderr"))
            record["exit_code"] = code
            if code != 0:
                combined_output = (stdout + b"\n" + stderr).lower()
                missing_previous = (
                    b"previous terminated container" in combined_output
                    and b"not found" in combined_output
                )
                if missing_previous_allowed and missing_previous:
                    record["missing_previous_log_allowed"] = True
                    result["warnings"].append(
                        {
                            "stage": label,
                            "exit_code": code,
                            "reason": "previous_log_unavailable",
                        }
                    )
                else:
                    record["error"] = f"command_exit:{code}"
                    result["failures"].append(
                        {"stage": label, "error": record["error"]}
                    )
        except Exception as exc:
            stdout = _diagnostic_bytes(
                getattr(exc, "stdout", None) or getattr(exc, "output", None)
            )
            stderr = _diagnostic_bytes(getattr(exc, "stderr", None))
            record["error"] = f"{type(exc).__name__}:{exc}"
            result["failures"].append({"stage": label, "error": record["error"]})

        payload = stdout
        if stderr:
            payload += b"\n--- stderr ---\n" + stderr
        if record.get("error"):
            payload += ("\n--- capture error ---\n" + record["error"] + "\n").encode(
                "utf-8", "replace"
            )
        truncated = len(payload) > DIAGNOSTIC_FILE_LIMIT_BYTES
        payload = payload[:DIAGNOSTIC_FILE_LIMIT_BYTES]
        try:
            directory.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            file_record = {
                "path": relative.as_posix(),
                "bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
            if truncated:
                file_record["truncated"] = True
            result["files"].append(file_record)
            record["truncated"] = truncated
        except Exception as exc:
            record["file_error"] = f"{type(exc).__name__}:{exc}"
            result["failures"].append({"stage": label, "error": record["file_error"]})
        result["commands"].append(record)
        return (
            stdout.decode("utf-8", "replace") if record.get("exit_code") == 0 else None
        )

    try:
        try:
            prefix = [
                str(kubectl),
                "--kubeconfig",
                str(kubeconfig),
                "--context",
                context,
                "-n",
                namespace,
            ]
            for label, args in (
                (
                    "resources",
                    ["get", "pods,deploy,sts,ds,svc,endpointslices", "-o", "wide"],
                ),
                ("events", ["get", "events", "--sort-by=.lastTimestamp"]),
                ("describe-pods", ["describe", "pods"]),
            ):
                capture(label, [*prefix, *args])
            for suffix in ("state", "reports"):
                capture(
                    "capacity-" + suffix,
                    [
                        *prefix,
                        "exec",
                        "deploy/redis",
                        "--",
                        "redis-cli",
                        "HGETALL",
                        (admission_namespace or namespace)
                        + ":{admission}:capacity:"
                        + suffix,
                    ],
                )
            pods_text = capture("pods-json", [*prefix, "get", "pods", "-o", "json"])
            if pods_text is not None:
                try:
                    pods = json.loads(pods_text).get("items", [])
                    for pod in pods:
                        pod_name = pod.get("metadata", {}).get("name")
                        spec = pod.get("spec", {})
                        containers = [
                            container
                            for key in (
                                "initContainers",
                                "containers",
                                "ephemeralContainers",
                            )
                            for container in spec.get(key, [])
                        ]
                        for container in containers:
                            container_name = container.get("name")
                            if not pod_name or not container_name:
                                result["failures"].append(
                                    {
                                        "stage": "pods-json",
                                        "error": "pod_or_container_name_missing",
                                    }
                                )
                                continue
                            identity = f"logs-{pod_name}-{container_name}"
                            capture(
                                identity,
                                [
                                    *prefix,
                                    "logs",
                                    "--tail=200",
                                    pod_name,
                                    "-c",
                                    container_name,
                                ],
                            )
                            capture(
                                identity + "-previous",
                                [
                                    *prefix,
                                    "logs",
                                    "--previous",
                                    "--tail=200",
                                    pod_name,
                                    "-c",
                                    container_name,
                                ],
                                missing_previous_allowed=True,
                            )
                except Exception as exc:
                    result["failures"].append(
                        {"stage": "pods-json", "error": f"{type(exc).__name__}:{exc}"}
                    )
            for node in nodes:
                capture(
                    f"crictl-{node}", ["docker", "exec", node, "crictl", "ps", "-a"]
                )
        except Exception as exc:
            result["failures"].append(
                {"stage": "diagnostic-capture", "error": f"{type(exc).__name__}:{exc}"}
            )
    except BaseException as exc:
        # Diagnostics must never mask the workload exception or block cleanup.
        result["failures"].append(
            {"stage": "diagnostic-capture", "error": f"{type(exc).__name__}:{exc}"}
        )
    result["elapsed_seconds"] = max(0.0, time.monotonic() - started)
    result["complete"] = not result["failures"] and not stopped
    return result


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def start_forward(
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
    *,
    step_name=None,
):
    port = free_port()
    log = (output / f"forward-{port}.log").open("wb")
    logs.append(log)
    process = subprocess.Popen(
        [
            str(kubectl),
            "--kubeconfig",
            str(kubeconfig),
            "--context",
            context,
            "-n",
            namespace,
            "port-forward",
            resource,
            f"{port}:{remote}",
            "--address",
            "127.0.0.1",
        ],
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    forwards.append(process)

    def up():
        try:
            with socket.create_connection(
                ("127.0.0.1", port), timeout=ROW5_KIND_PORT_FORWARD_CONNECT_TIMEOUT_S
            ):
                return True
        except OSError:
            return False

    if step_name is None:
        wait(up, ROW5_KIND_PORT_FORWARD_READY_TIMEOUT_S)
    else:
        wait(up, ROW5_KIND_PORT_FORWARD_READY_TIMEOUT_S, step_name=step_name)
    return port


def read_stream(port, *, tls=False, cafile, timeout=35):
    connection = (
        http.client.HTTPSConnection(
            "localhost",
            port,
            context=ssl.create_default_context(cafile=str(cafile)),
            timeout=timeout,
        )
        if tls
        else http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    )
    begin, first, decoder = time.monotonic(), None, SSEDecoder()
    try:
        connection.request(
            "POST",
            "/v1/chat/completions",
            json.dumps(
                {
                    "model": "test-model",
                    "messages": [{"role": "user", "content": "kind engineering drain"}],
                    "max_tokens": 32,
                    "stream": True,
                }
            ),
            {
                "Authorization": "Bearer local-dev-token",
                "Content-Type": "application/json",
            },
        )
        response = connection.getresponse()
        assert response.status == 200, (response.status, response.read())
        while chunk := response.read1(65536):
            now = time.monotonic()
            if first is None:
                first = now
            decoder.feed(chunk, [int(now * 1000)] * 2)
        assert decoder.report()["complete"], decoder.report()
        elapsed = time.monotonic() - begin
        assert first is not None and first - begin < elapsed / 2, (
            first - begin,
            elapsed,
        )
        return {
            "complete": True,
            "first_chunk_seconds": first - begin,
            "elapsed_seconds": elapsed,
        }
    finally:
        connection.close()


def mutate_kind_manifest(manifest, gateway_image, pulled_images, local_images):
    """Apply the rehearsal CPU mocks and exact loaded-image policy to real resources."""
    namespace = next(
        o["metadata"]["name"] for o in manifest["items"] if o["kind"] == "Namespace"
    )
    objects = []
    for obj in manifest["items"]:
        if (
            obj["kind"] == "DaemonSet"
            and obj["metadata"]["name"] == "nvidia-device-plugin"
        ):
            continue  # manually advertised mock GPU resources, never real plugin fitness
        if obj["kind"] in ("Deployment", "StatefulSet"):
            pod = obj["spec"]["template"]["spec"]
            for container in pod["containers"]:
                container["imagePullPolicy"] = "IfNotPresent"
            if obj["metadata"]["name"] == "gateway":
                pod["containers"][0]["image"] = gateway_image
                pod["containers"][0]["imagePullPolicy"] = "Never"
            if obj["metadata"]["name"] == "vllm":
                container = pod["containers"][0]
                container.update(
                    image="mti-fake:stage1",
                    imagePullPolicy="Never",
                    command=["python", "/mock/entry.py"],
                    args=[],
                    volumeMounts=[
                        {"name": "mock", "mountPath": "/mock", "readOnly": True}
                    ],
                    resources={
                        "requests": {
                            "cpu": "100m",
                            "memory": "64Mi",
                            "nvidia.com/gpu": "1",
                        },
                        "limits": {
                            "cpu": "1",
                            "memory": "256Mi",
                            "nvidia.com/gpu": "1",
                        },
                    },
                )
                pod["volumes"] = [
                    {"name": "mock", "configMap": {"name": "mock-backend"}}
                ]
        if obj["kind"] == "Service" and obj["spec"]["type"] == "LoadBalancer":
            obj["spec"]["type"] = "ClusterIP"
            obj["spec"].pop("loadBalancerClass", None)
            obj["spec"].pop("loadBalancerSourceRanges", None)
            obj["metadata"].pop("annotations", None)
        objects.append(obj)
    objects.append(
        {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "mock-backend", "namespace": namespace},
            "data": {
                "entry.py": "from inference_platform import kind_fake\nkind_fake.STREAM_CHUNKS=20\nkind_fake.STREAM_CHUNK_DELAY_MS=500\nraise SystemExit(kind_fake.main())\n"
            },
        }
    )
    manifest["items"] = objects
    image_replacements = {
        image: KIND_LOCAL_IMAGE_TAGS[name] for name, image in pulled_images.items()
    }
    allowed_workload_images = set(KIND_LOCAL_IMAGE_TAGS.values()) | set(local_images)
    used_images = rewrite_kind_workload_images(
        manifest,
        replacements=image_replacements,
        allowed_images=allowed_workload_images,
    )
    return used_images


def main():
    budget = WorkBudget()

    def call(argv, *, timeout=180, **kwargs):
        return run(argv, timeout=budget.cap(timeout), **kwargs)

    def phase(name):
        started_s = round(time.monotonic() - budget.started, 6)
        receipts["phase_started_s"].append(
            {"phase": name, "phase_started_s": started_s}
        )
        print(f"kind_phase:{name} phase_started_s={started_s:.6f}", flush=True)

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--gateway-image", required=True)
    parser.add_argument("--cluster", default="m5-package-a")
    args = parser.parse_args()
    if not args.cluster.startswith("m5-package-a") or args.output.exists():
        raise ValueError("unique_owned_cluster_and_new_output_required")
    kind = ROOT / ".tools" / ("kind.exe" if os.name == "nt" else "kind")
    kubectl = ROOT / ".tools" / ("kubectl.exe" if os.name == "nt" else "kubectl")
    pins = json.loads((ROOT / "deploy/k8s/pins.json").read_text())
    if pins["redis_image"] != REDIS_IMAGE:
        raise ValueError("redis_image_pin_mismatch")
    for name, path in (("kind", kind), ("kubectl", kubectl)):
        key = f"{name}_{'windows' if os.name == 'nt' else 'linux'}_amd64_sha256"
        if hashlib.sha256(path.read_bytes()).hexdigest() != pins[key]:
            raise ValueError("tool_pin_mismatch:" + name)
    if args.cluster in call([kind, "get", "clusters"]).splitlines():
        raise ValueError("refuse_existing_cluster")
    args.output.mkdir(parents=True)
    kubeconfig = args.output / "kubeconfig"
    namespace = "mti-m5-package-a"
    context = "kind-" + args.cluster

    def k(*argv, **kwargs):
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
            **kwargs,
        )

    def wait(predicate, timeout=90):
        deadline = time.monotonic() + budget.cap(timeout)
        while not predicate():
            if time.monotonic() >= deadline:
                raise TimeoutError("kind_behavior_deadline")
            time.sleep(budget.cap(0.25))

    nodes = [
        args.cluster + suffix for suffix in ("-control-plane", "-worker", "-worker2")
    ]
    forwards, logs, receipts, owned = [], [], {}, False
    receipts["phase_started_s"] = []
    receipts["timeout_budget"] = {
        "outer_seconds": KIND_RUNNER_TIMEOUT_S,
        "work_seconds": KIND_RUNNER_TIMEOUT_S - KIND_CLEANUP_RESERVE_S,
        "cleanup_reserve_seconds": KIND_CLEANUP_RESERVE_S,
        "receipt_reserve_seconds": KIND_RECEIPT_RESERVE_S,
        "reserve_plan": "60 s diagnostics + 6 x 10 s forward/control waits + 180 s cluster deletion + 10 s receipt write",
    }
    cluster_created = False
    env_values = {}
    started = budget.started
    try:
        phase("create")
        config = {
            "kind": "Cluster",
            "apiVersion": "kind.x-k8s.io/v1alpha4",
            "nodes": [
                {"role": "control-plane"},
                {"role": "worker"},
                {"role": "worker"},
            ],
        }
        (args.output / "kind.json").write_text(json.dumps(config))
        owned = True
        create_kind_cluster(
            kind,
            args.cluster,
            pins["node_image"],
            args.output / "kind.json",
            kubeconfig,
            call,
            timeout=240,
        )
        cluster_created = True
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
            k(
                "label",
                "node",
                node,
                "m5-role=" + ("cpu" if node == nodes[0] else "gpu"),
            )
        k(
            "taint",
            "node",
            nodes[0],
            "node-role.kubernetes.io/control-plane-",
            check=False,
        )
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
        pulled_images = {
            "redis": REDIS_IMAGE,
            "nginx": NGINX_IMAGE,
            "prometheus": PROMETHEUS_IMAGE,
            "python": PYTHON_IMAGE,
        }
        pulled_image_names = {image: name for name, image in pulled_images.items()}
        local_images = (args.gateway_image, "mti-fake:stage1")
        local_image_digests = {}
        image_archives = []
        phase("image-load")
        cache_root = ROOT / ".cache"
        cache_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="package-a-kind-images-", dir=cache_root
        ) as archive_temp:
            archive_dir = Path(archive_temp)
            for image in (*local_images, *pulled_images.values()):
                if (
                    call(["docker", "image", "inspect", image], check=False).strip()
                    == "[]"
                ):
                    if image in local_images:
                        raise ValueError("locally_built_image_missing:" + image)
                    call(["docker", "pull", image], timeout=180)
                if image in pulled_image_names:
                    image_name = pulled_image_names[image]
                    archive_path = archive_dir / f"image-{len(image_archives)}.tar"
                    archived = save_amd64_archive(
                        image,
                        archive_path,
                        call,
                        local_tag=KIND_LOCAL_IMAGE_TAGS[image_name],
                    )
                    image_archives.append(
                        {
                            **archived,
                            "archive_path": archive_path.name,
                            "removed_after_load": True,
                        }
                    )
                    call(
                        [
                            kind,
                            "load",
                            "image-archive",
                            archive_dir / f"image-{len(image_archives) - 1}.tar",
                            "--name",
                            args.cluster,
                        ],
                        timeout=180,
                    )
        for image in local_images:
            local_image_digests[image] = load_kind_local_image(
                kind, image, args.cluster, call
            )
        large_output_files = [
            path.relative_to(args.output).as_posix()
            for path in args.output.rglob("*")
            if path.is_file() and path.stat().st_size > 1024**2
        ]
        receipts["post_archive_large_files"] = large_output_files
        if large_output_files:
            raise ValueError("kind_output_archive_file_over_1_mib")
        receipts["image_archives"] = image_archives
        source = (ROOT / "deploy/eks/capture_runtime.py").read_text()
        crictl_path = call(
            ["docker", "exec", nodes[1], "sh", "-c", "command -v crictl"]
        ).strip()
        crictl_hash = call(
            ["docker", "exec", nodes[1], "sha256sum", crictl_path]
        ).split()[0]
        assert (
            call(["docker", "exec", nodes[2], "sha256sum", crictl_path]).split()[0]
            == crictl_hash
        )
        model_manifest = json.dumps(
            {
                "config.json": {
                    "bytes": 3,
                    "sha256": hashlib.sha256(b"{}\n").hexdigest(),
                }
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        (args.output / "model-manifest.json").write_bytes(model_manifest)
        inputs = {
            "crictl_host_path": crictl_path,
            "crictl_sha256": crictl_hash,
            "model_manifest_sha256": hashlib.sha256(model_manifest).hexdigest(),
            "model_manifest": json.loads(model_manifest),
            "operator_cidrs": ["192.0.2.1/32"],
            "namespace": namespace,
            "gateway_image": "example.invalid/gateway@sha256:" + "a" * 64,
            "config_sha256": "b" * 64,
            "tls_secret": "gateway-tls",
            "r": 4,
            "w": 1,
        }
        manifest, used_images = render_kind_manifest(
            inputs, source, args.gateway_image, pulled_images, local_images
        )
        env_values = admission_settings(manifest)
        expected_config_digests = {
            item["local_tag"]: item["config_digest"] for item in image_archives
        }
        expected_loaded_images = set(expected_config_digests) | set(local_image_digests)
        if set(used_images) != expected_loaded_images:
            raise ValueError("kind_manifest_loaded_image_set_mismatch")
        image_labels = {
            KIND_LOCAL_IMAGE_TAGS[name]: name for name in KIND_LOCAL_IMAGE_TAGS
        }
        image_labels.update({args.gateway_image: "gateway", "mti-fake:stage1": "fake"})
        (args.output / "mock-resources.json").write_text(json.dumps(manifest))
        resolution = {
            "complete": False,
            "nodes": nodes,
            "images": {
                image: {
                    "name": image_labels[image],
                    "expected_config_digest": expected_config_digests.get(image),
                    "source_image_config_digest": local_image_digests.get(image),
                    "nodes": {},
                }
                for image in used_images
            },
        }
        receipts["loaded_image_resolution"] = resolution
        for node in nodes:
            for image in used_images:
                code, text = call(
                    ["docker", "exec", node, "crictl", "inspecti", image],
                    timeout=30,
                    check=False,
                    return_status=True,
                )
                try:
                    status = json.loads(text)["status"]
                    observed_id = status["id"]
                except (json.JSONDecodeError, KeyError, TypeError):
                    status, observed_id = {}, None
                node_result = {
                    "exit_code": code,
                    "resolved_image_id": observed_id,
                    "repo_tags": status.get("repoTags", []),
                }
                resolution["images"][image]["nodes"][node] = node_result
                if not crictl_image_resolution_matches(
                    image,
                    code,
                    status,
                    expected_config_digest=expected_config_digests.get(image),
                ):
                    raise RuntimeError(
                        "loaded_image_not_resolvable:" + image_labels[image]
                    )
        resolution["complete"] = True
        k("create", "namespace", namespace)
        k(
            "create",
            "configmap",
            "model-cache-manifest",
            "--from-file=manifest.json=" + str(args.output / "model-manifest.json"),
        )
        secret = args.output / "cache-salt.secret"
        write_kind_secret(secret)
        k(
            "create",
            "secret",
            "generic",
            "gateway-config",
            "--from-file=tenants.json=" + str(ROOT / "deploy/local/tenants.json"),
            "--from-file=cache-salt.secret=" + str(secret),
        )
        call(test_tls_command(args.output))
        k(
            "create",
            "secret",
            "tls",
            "gateway-tls",
            "--cert=" + str(args.output / "tls.crt"),
            "--key=" + str(args.output / "tls.key"),
        )

        def forward(resource, remote):
            return start_forward(
                kubectl,
                kubeconfig,
                context,
                namespace,
                args.output,
                resource,
                remote,
                forwards,
                logs,
                wait,
            )

        bootstrap = {
            "apiVersion": "v1",
            "kind": "List",
            "items": [o for o in manifest["items"] if o["kind"] != "StatefulSet"],
        }
        (args.output / "bootstrap.json").write_text(json.dumps(bootstrap))
        phase("bootstrap")
        k("apply", "-f", args.output / "bootstrap.json")
        k("rollout", "status", "daemonset/node-observer", "--timeout=120s", timeout=140)
        observer_pods = json.loads(
            k("get", "pods", "-l", "app=node-observer", "-o", "json")
        )["items"]
        assert len(observer_pods) == 2
        capture_rows = []
        source_rows = LiveRows(
            "kind-package-a", "kind-collector", sink=capture_rows.append
        )
        cache_sources = {}
        for pod in observer_pods:
            node = pod["spec"]["nodeName"]
            port = forward("pod/" + pod["metadata"]["name"], 9102)
            adapter = NodeCacheAdapter(
                source_rows, HTTP(f"http://127.0.0.1:{port}", local_test=True), node
            )
            adapter.clock()
            witness = adapter.capture()
            assert (
                witness["image_cache_state"] == "cold"
                and witness["model_cache_state"] == "cold"
            ), witness
            time.sleep(budget.cap(0.01))
            adapter.clock()
            cache_sources[node] = adapter
        clock_maps = ClockMapper(
            [r for r in capture_rows if r["source_kind"] == "clocks"]
        )
        time.sleep(budget.cap(0.15))
        creation_start = time.monotonic_ns() // 1_000_000
        k("apply", "-f", args.output / "mock-resources.json")
        creation_end = time.monotonic_ns() // 1_000_000
        phase("readiness")
        for name in ("vllm", "gateway"):
            k(
                "wait",
                "--for=jsonpath={.status.readyReplicas}=2",
                "statefulset/" + name,
                "--timeout=180s",
                timeout=200,
            )
        k(
            "rollout",
            "status",
            "deployment/streaming-ingress",
            "--timeout=180s",
            timeout=200,
        )

        phase("cache-and-discovery")

        def pods():
            return {
                p["metadata"]["name"]: p
                for p in json.loads(k("get", "pods", "-o", "json"))["items"]
            }

        initial = pods()
        for slot in (0, 1):
            pod = initial[f"vllm-{slot}"]
            result = cache_sources[pod["spec"]["nodeName"]].for_pod(
                pod["metadata"]["uid"],
                slot,
                creation_bounds=[creation_start, creation_end],
                clocks=clock_maps,
            )
            assert result["error"] is None, result
        assert not SourceJoin(capture_rows).errors
        receipts["node_observer_cri_cache_and_clocks"] = {
            "nodes": 2,
            "normalized_cache_rows": 2,
            "model_cache": "cold",
            "real_vllm_image_cache": "cold",
            "crictl_sha256": crictl_hash,
        }
        backend_nodes = {initial["vllm-" + str(i)]["spec"]["nodeName"] for i in (0, 1)}
        assert backend_nodes == set(nodes[1:]), backend_nodes
        assert (
            k(
                "auth",
                "can-i",
                "list",
                "endpointslices",
                "--as",
                f"system:serviceaccount:{namespace}:gateway",
            ).strip()
            == "yes"
        )
        receipts["distinct_gpu_nodes_and_discovery_rbac"] = True

        ports = [forward("pod/gateway-" + str(i), 8080) for i in (0, 1)]
        tls_port = forward("service/streaming-ingress", 443)

        def stream(port, *, tls=False):
            return read_stream(
                port,
                tls=tls,
                cafile=args.output / "tls.crt",
                timeout=budget.cap(35),
            )

        receipts["admission_capacity"] = []

        def capacity_wait():
            timing = admission_timing(env_values)
            return wait_admission_capacity(
                lambda remaining: k(
                    "exec",
                    "deploy/redis",
                    "--",
                    "redis-cli",
                    "HGET",
                    env_values["ADMISSION_NAMESPACE"] + ":{admission}:capacity:state",
                    "n",
                    timeout=min(ADMISSION_READER_TIMEOUT_S, remaining),
                ).strip(),
                env_values,
                2,
                receipts["admission_capacity"],
                timeout=budget.cap(timing["deadline_s"]),
            )

        phase("admission-capacity")
        capacity_wait()
        phase("streams")
        receipts["gateway_streams"] = [stream(port) for port in ports]
        receipts["tls_incremental_stream"] = stream(tls_port, tls=True)
        connection = http.client.HTTPSConnection(
            "localhost",
            tls_port,
            context=ssl.create_default_context(cafile=str(args.output / "tls.crt")),
            timeout=budget.cap(35),
        )
        connection.request("GET", "/internal/measurement?offset=0")
        assert connection.getresponse().status == 404
        connection.close()
        receipts["public_admin_404"] = True
        phase("ondelete-and-capacity")
        # OnDelete template changes cannot roll either slot by themselves.
        old_uids = {
            name: initial[name]["metadata"]["uid"] for name in ("vllm-0", "vllm-1")
        }
        next_manifest = copy.deepcopy(manifest)
        next_backend = next(
            o
            for o in next_manifest["items"]
            if o["kind"] == "StatefulSet" and o["metadata"]["name"] == "vllm"
        )
        next_backend["spec"]["template"]["metadata"]["annotations"] = {
            "package-a-revision": "next"
        }
        (args.output / "next-resources.json").write_text(json.dumps(next_manifest))
        k("apply", "-f", args.output / "next-resources.json")
        time.sleep(budget.cap(1))
        assert all(
            pods()[name]["metadata"]["uid"] == uid for name, uid in old_uids.items()
        )
        # Both nodes are occupied: a third backend must remain unscheduled.
        overflow = copy.deepcopy(
            next(
                o
                for o in manifest["items"]
                if o["kind"] == "StatefulSet" and o["metadata"]["name"] == "vllm"
            )["spec"]["template"]
        )
        overflow.update(apiVersion="v1", kind="Pod")
        overflow["metadata"].update(name="gpu-overflow", namespace=namespace)
        (args.output / "overflow.json").write_text(json.dumps(overflow))
        k("apply", "-f", args.output / "overflow.json")
        time.sleep(budget.cap(2))
        assert not pods()["gpu-overflow"]["spec"].get("nodeName"), (
            "third backend scheduled"
        )
        k("delete", "pod", "gpu-overflow", "--wait=true")
        receipts["ondelete_and_no_third_gpu_pod"] = True
        drain_log = (args.output / "old-vllm-0.log").open("wb")
        logs.append(drain_log)
        following = subprocess.Popen(
            [
                str(kubectl),
                "--kubeconfig",
                str(kubeconfig),
                "--context",
                context,
                "-n",
                namespace,
                "logs",
                "--follow",
                "vllm-0",
            ],
            stdout=drain_log,
            stderr=subprocess.STDOUT,
        )
        forwards.append(following)
        # Two streams per independent round-robin gateway cover both backends
        # regardless of which backend served the earlier direct/TLS requests.
        assert env_values["GATEWAY_ROUTING_POLICY"] == "round_robin"
        assert env_values["ADMISSION_CAPACITY_MODE"] == "dynamic"
        # B=N*(R+W); R>=4 permits all four even at reduced N=1, without
        # depending on waiting slots. The tenant must also permit all four.
        assert int(env_values["ADMISSION_RUNNING"]) >= 4
        tenants = json.loads((ROOT / "deploy/local/tenants.json").read_bytes())
        tenant = next(t for t in tenants["tenants"] if t["tenant_id"] == "tenant-local")
        assert tenant["max_concurrent"] >= 4
        draining, drain_errors = [], []

        def in_flight(port):
            try:
                draining.append(stream(port))
            except Exception as exc:
                drain_errors.append(str(exc))

        clients = [
            threading.Thread(target=in_flight, args=(port,))
            for port in ports
            for _ in range(2)
        ]
        # No backend has been deleted yet. Refresh N before all four offers;
        # a report freshness gap can otherwise reduce N to zero even here.
        capacity_wait()
        for client in clients:
            client.start()
        phase("drain")
        time.sleep(budget.cap(2))
        phase("replacement")
        k("delete", "pod", "vllm-0", "--wait=true", timeout=90)
        k("wait", "--for=create", "pod/vllm-0", "--timeout=90s", timeout=100)
        assert pods()["vllm-0"]["metadata"]["uid"] != old_uids["vllm-0"]
        k("wait", "--for=condition=Ready", "pod/vllm-0", "--timeout=90s", timeout=100)
        for client in clients:
            client.join(timeout=budget.cap(35))
            assert not client.is_alive(), "drain client still active"
        assert not drain_errors and len(draining) == 4, drain_errors
        try:
            following.wait(timeout=budget.cap(10))
        except subprocess.TimeoutExpired:
            following.terminate()
            following.wait(timeout=budget.cap(10))
        native_log = []
        for line in (args.output / "old-vllm-0.log").read_text().splitlines():
            try:
                native_log.append(json.loads(line))
            except ValueError:
                continue
        signals = [row for row in native_log if row.get("msg") == "SIGTERM received"]
        assert len(signals) == 1 and signals[0]["active"] > 0, native_log
        assert any(
            row.get("msg") == "last stream drained" and row["active"] == 0
            for row in native_log
        ), native_log
        receipts["sigterm_nonzero_live_and_both_streams_complete"] = {
            "active_at_signal": signals[0]["active"],
            "streams": draining,
        }
        replaced = pods()
        assert replaced["vllm-0"]["metadata"]["uid"] != old_uids["vllm-0"]
        assert replaced["vllm-1"]["metadata"]["uid"] == old_uids["vllm-1"]
        new_uid = replaced["vllm-0"]["metadata"]["uid"]
        # Roll back exact saved bytes, then only the changed slot.
        k("apply", "-f", args.output / "mock-resources.json")
        phase("rollback-replacement")
        k("delete", "pod", "vllm-0", "--wait=true", timeout=90)
        k("wait", "--for=create", "pod/vllm-0", "--timeout=90s", timeout=100)
        assert pods()["vllm-0"]["metadata"]["uid"] not in (old_uids["vllm-0"], new_uid)
        k("wait", "--for=condition=Ready", "pod/vllm-0", "--timeout=90s", timeout=100)
        rolled_back = pods()
        assert rolled_back["vllm-0"]["metadata"]["uid"] not in (
            old_uids["vllm-0"],
            new_uid,
        )
        assert rolled_back["vllm-1"]["metadata"]["uid"] == old_uids["vllm-1"]
        assert "package-a-revision" not in rolled_back["vllm-0"]["metadata"].get(
            "annotations", {}
        )
        receipts["replacement_and_prior_template_rollback"] = True
        # Slot 1 stays ready, but stale/retained reports can still leave N=0.
        # Observe full restoration after rollback before new stream offers.
        capacity_wait()
        for port in ports:
            stream(port)
        receipts["source_manifest_sha256"] = hashlib.sha256(
            (args.output / "mock-resources.json").read_bytes()
        ).hexdigest()
        receipts["scope"] = (
            "local kind, manually advertised mock GPU capacity, mock vLLM; no real GPU/plugin/NLB/AWS fitness"
        )
        receipts["engineering_workload"] = (
            "20 chunks,500ms spacing,max_tokens32 for incremental SSE; not registration-v3 measurement data"
        )
        phase("success")
        receipts["elapsed_seconds"] = time.monotonic() - started
    except Exception as exc:
        receipts["error"] = f"{type(exc).__name__}:{exc}"
        if cluster_created:
            phase("diagnostics")
            receipts["diagnostics"] = capture_kind_diagnostics(
                args.output,
                kubectl,
                kubeconfig,
                context,
                namespace,
                nodes,
                admission_namespace=env_values.get("ADMISSION_NAMESPACE", namespace),
            )
        raise
    finally:
        budget.cleanup = True
        phase("cleanup")
        active_exception = sys.exc_info()[1]
        cleanup_errors = []
        for process in forwards:
            try:
                process.terminate()
            except Exception as exc:
                cleanup_errors.append(f"forward_terminate:{type(exc).__name__}:{exc}")
            try:
                process.wait(timeout=budget.cap(10))
            except Exception as exc:
                cleanup_errors.append(f"forward_wait:{type(exc).__name__}:{exc}")
        for log in logs:
            try:
                log.close()
            except Exception as exc:
                cleanup_errors.append(f"log_close:{type(exc).__name__}:{exc}")
        if owned:
            try:
                delete_kind_cluster(kind, args.cluster, kubeconfig, call, timeout=180)
                remaining = call(
                    [
                        "docker",
                        "ps",
                        "-aq",
                        "--filter",
                        "label=io.x-k8s.kind.cluster=" + args.cluster,
                    ]
                ).strip()
                receipts["owned_cluster_cleanup_verified"] = not remaining
                receipts["owned_cluster_cleanup_elapsed_seconds"] = (
                    time.monotonic() - started
                )
                if remaining:
                    cleanup_errors.append("owned kind containers remain")
            except Exception as exc:
                cleanup_errors.append(f"cluster_cleanup:{type(exc).__name__}:{exc}")
        if cleanup_errors:
            receipts["cleanup_errors"] = cleanup_errors
            if "error" not in receipts:
                receipts["error"] = cleanup_errors[0]
        (args.output / "receipt.json").write_text(
            json.dumps(receipts, indent=2, sort_keys=True) + "\n"
        )
        if cleanup_errors and active_exception is None:
            raise RuntimeError("; ".join(cleanup_errors))
    print(json.dumps(receipts, sort_keys=True))


if __name__ == "__main__":
    main()
