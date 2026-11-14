"""DEC-100 serving manifests and descriptive client accounting, without INF-037b custody."""

import http.client
import json
import math
import re
import time
import urllib.error
import urllib.request
from collections import Counter

from .eks_deployment import (
    DEVICE_IMAGE,
    MODEL,
    NGINX,
    NGINX_IMAGE,
    PROMETHEUS_IMAGE,
    REDIS_IMAGE,
    REVISION,
    VLLM_IMAGE,
    image_pin,
)
from .inf037b_requests import SSEDecoder
from .r1_spec import engine_argv, parse_engine_argv
from .time_budget import deadline_urlopen


def resources(namespace, gateway_image, tls_secret="gateway-tls"):
    """Only runtime inputs; credentials and certificates are separate Secrets.

    Load clients reach the private TLS ClusterIP from a CPU-node Job.
    No load-balancer controller, public backend/admin Service or autoscaler.
    """
    if not re.fullmatch(r"mti-m5-[a-z0-9-]{1,40}", namespace):
        raise ValueError("descriptive:namespace")
    image_pin(gateway_image)
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,62}", tls_secret):
        raise ValueError("descriptive:tls_secret")
    engine_args = engine_argv()
    running = parse_engine_argv(engine_args).get("--max-num-seqs")
    if not isinstance(running, str) or not running.isdecimal() or int(running) <= 0:
        raise ValueError("descriptive:engine_admission_capacity")
    objects = []

    def add(kind, name, spec=None, api="v1", **extra):
        obj = {
            "apiVersion": api,
            "kind": kind,
            "metadata": {"name": name, "namespace": namespace, "labels": {"m5-session": namespace}},
            **extra,
        }
        if spec is not None:
            obj["spec"] = spec
        objects.append(obj)
        return obj

    add("Namespace", namespace)["metadata"].pop("namespace")
    add("ServiceAccount", "gateway")
    add(
        "Role",
        "endpoint-reader",
        api="rbac.authorization.k8s.io/v1",
        rules=[
            {"apiGroups": ["discovery.k8s.io"], "resources": ["endpointslices"], "verbs": ["list"]}
        ],
    )
    add(
        "RoleBinding",
        "gateway-endpoints",
        api="rbac.authorization.k8s.io/v1",
        subjects=[{"kind": "ServiceAccount", "name": "gateway", "namespace": namespace}],
        roleRef={
            "kind": "Role",
            "name": "endpoint-reader",
            "apiGroup": "rbac.authorization.k8s.io",
        },
    )
    add("ConfigMap", "streaming-ingress", data={"nginx.conf": NGINX})
    for name, port, headless in (
        ("gateway", 8080, False),
        ("gateway-peer", 8080, True),
        ("vllm", 8000, True),
        ("redis", 6379, False),
        ("streaming-ingress", 8443, False),
        ("telemetry", 9090, False),
    ):
        service = add(
            "Service",
            name,
            {
                "type": "ClusterIP",
                "selector": {"app": "gateway" if name == "gateway-peer" else name},
                "ports": [{"name": "http", "port": port, "targetPort": port}],
            },
        )
        if headless:
            service["spec"]["clusterIP"] = "None"

    def workload(kind, name, replicas, container, **pod):
        spec = {
            "replicas": replicas,
            "selector": {"matchLabels": {"app": name}},
            "template": {
                "metadata": {"labels": {"app": name, "m5-session": namespace}},
                "spec": {
                    "automountServiceAccountToken": False,
                    "terminationGracePeriodSeconds": 45,
                    "nodeSelector": {"m5-role": "cpu"},
                    "containers": [container],
                    **pod,
                },
            },
        }
        if kind == "StatefulSet":
            spec.update(
                serviceName="gateway-peer" if name == "gateway" else name,
                podManagementPolicy="Parallel",
                updateStrategy={"type": "OnDelete"},
            )
        else:
            spec["strategy"] = {"type": "Recreate"}
        return add(kind, name, spec, api="apps/v1")

    security = {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}}
    workload(
        "Deployment",
        "redis",
        1,
        {
            "name": "redis",
            "image": REDIS_IMAGE,
            "args": [
                "redis-server",
                "--save",
                "",
                "--appendonly",
                "no",
                "--maxmemory",
                "256mb",
                "--maxmemory-policy",
                "noeviction",
            ],
            "readinessProbe": {"exec": {"command": ["redis-cli", "ping"]}, "periodSeconds": 1},
            "resources": {
                "requests": {"cpu": "100m", "memory": "128Mi"},
                "limits": {"cpu": "1", "memory": "384Mi"},
            },
            "securityContext": security,
        },
    )
    env = {
        "BACKEND_DISCOVERY": "endpointslices",
        "BACKEND_DISCOVERY_NAMESPACE": namespace,
        "BACKEND_DISCOVERY_SERVICE": "vllm",
        "BACKEND_DISCOVERY_INTERVAL": "250ms",
        "TENANT_CONFIG_PATH": "/config/tenants.json",
        "CACHE_SALT_SECRET_FILE": "/config/cache-salt.secret",
        "REDIS_ADDR": "redis:6379",
        "ADMISSION_NAMESPACE": namespace,
        "GATEWAY_TOTAL_TIMEOUT": "30s",
        "GATEWAY_SHUTDOWN_GRACE": "35s",
        "GATEWAY_SHUTDOWN_HARD_STOP": "10s",
        "ADMISSION_LEASE": "90s",
        "ADMISSION_CAPACITY_MODE": "dynamic",
        "ADMISSION_RUNNING": str(int(running)),
        "ADMISSION_WAITING": "4",
        "ADMISSION_REPORT_TTL": "8s",
        "ADMISSION_HOLD_DOWN": "2s",
        "ADMISSION_GATEWAY_ID": "$(POD_NAME)",
        "GATEWAY_ROUTING_POLICY": "round_robin",
        "OTEL_SDK_DISABLED": "true",
    }
    workload(
        "StatefulSet",
        "gateway",
        2,
        {
            "name": "gateway",
            "image": gateway_image,
            "ports": [{"containerPort": 8080}],
            "env": [
                {"name": "POD_NAME", "valueFrom": {"fieldRef": {"fieldPath": "metadata.name"}}},
                *[{"name": k, "value": v} for k, v in env.items()],
            ],
            "volumeMounts": [{"name": "config", "mountPath": "/config", "readOnly": True}],
            "startupProbe": {
                "httpGet": {"path": "/healthz", "port": 8080},
                "periodSeconds": 1,
                "failureThreshold": 60,
            },
            "readinessProbe": {
                "httpGet": {"path": "/readyz", "port": 8080},
                "periodSeconds": 1,
                "failureThreshold": 1,
            },
            "lifecycle": {"preStop": {"sleep": {"seconds": 3}}},
            "securityContext": {**security, "readOnlyRootFilesystem": True},
            "resources": {
                "requests": {"cpu": "250m", "memory": "256Mi"},
                "limits": {"cpu": "1", "memory": "512Mi"},
            },
        },
        serviceAccountName="gateway",
        automountServiceAccountToken=True,
        securityContext={"runAsUser": 65532, "runAsNonRoot": True, "fsGroup": 65532},
        volumes=[{"name": "config", "secret": {"secretName": "gateway-config"}}],
    )
    workload(
        "StatefulSet",
        "vllm",
        2,
        {
            "name": "vllm",
            "image": VLLM_IMAGE,
            "command": ["vllm", "serve"],
            "args": [
                MODEL,
                "--revision",
                REVISION,
                "--host",
                "0.0.0.0",
                "--port",
                "8000",
                *engine_args,
                "--shutdown-timeout",
                "35",
            ],
            "ports": [{"name": "http", "containerPort": 8000}],
            "env": [{"name": "VLLM_WORKER_MULTIPROC_METHOD", "value": "spawn"}],
            "startupProbe": {
                "httpGet": {"path": "/health", "port": 8000},
                "periodSeconds": 1,
                "failureThreshold": 1800,
            },
            "readinessProbe": {
                "httpGet": {"path": "/health", "port": 8000},
                "periodSeconds": 1,
                "failureThreshold": 1,
            },
            "volumeMounts": [
                {"name": "model", "mountPath": "/root/.cache/huggingface"},
                {"name": "shm", "mountPath": "/dev/shm"},
            ],
            "securityContext": security,
            "resources": {
                "requests": {"nvidia.com/gpu": "1", "cpu": "2", "memory": "8Gi"},
                "limits": {"nvidia.com/gpu": "1", "cpu": "4", "memory": "12Gi"},
            },
        },
        nodeSelector={"m5-role": "gpu"},
        tolerations=[
            {"key": "nvidia.com/gpu", "operator": "Equal", "value": "true", "effect": "NoSchedule"}
        ],
        affinity={
            "podAntiAffinity": {
                "requiredDuringSchedulingIgnoredDuringExecution": [
                    {
                        "labelSelector": {"matchLabels": {"app": "vllm"}},
                        "topologyKey": "kubernetes.io/hostname",
                    }
                ]
            }
        },
        volumes=[
            {
                "name": "model",
                "hostPath": {"path": "/var/cache/mti-m5/models", "type": "DirectoryOrCreate"},
            },
            {"name": "shm", "emptyDir": {"medium": "Memory", "sizeLimit": "1Gi"}},
        ],
    )
    workload(
        "Deployment",
        "streaming-ingress",
        1,
        {
            "name": "nginx",
            "image": NGINX_IMAGE,
            "command": ["nginx", "-g", "daemon off;"],
            "ports": [{"containerPort": 8443}],
            "volumeMounts": [
                {
                    "name": "config",
                    "mountPath": "/etc/nginx/nginx.conf",
                    "subPath": "nginx.conf",
                    "readOnly": True,
                },
                {"name": "tls", "mountPath": "/tls", "readOnly": True},
                {"name": "tmp", "mountPath": "/tmp"},
            ],
            "securityContext": {**security, "readOnlyRootFilesystem": True},
            "readinessProbe": {"tcpSocket": {"port": 8443}, "periodSeconds": 1},
            "resources": {
                "requests": {"cpu": "100m", "memory": "32Mi"},
                "limits": {"cpu": "1", "memory": "128Mi"},
            },
        },
        securityContext={"runAsUser": 101, "runAsNonRoot": True, "fsGroup": 101},
        volumes=[
            {"name": "config", "configMap": {"name": "streaming-ingress"}},
            {"name": "tls", "secret": {"secretName": tls_secret}},
            {"name": "tmp", "emptyDir": {}},
        ],
    )
    add(
        "ConfigMap",
        "telemetry",
        data={
            "prometheus.yml": json.dumps(
                {
                    "global": {"scrape_interval": "5s"},
                    "scrape_configs": [
                        {"job_name": name, "static_configs": [{"targets": targets}]}
                        for name, targets in (
                            ("gateway", [f"gateway-{i}.gateway-peer:8080" for i in range(2)]),
                            ("vllm", [f"vllm-{i}.vllm:8000" for i in range(2)]),
                        )
                    ],
                }
            )
        },
    )
    workload(
        "Deployment",
        "telemetry",
        1,
        {
            "name": "prometheus",
            "image": PROMETHEUS_IMAGE,
            "args": [
                "--config.file=/etc/prometheus/prometheus.yml",
                "--storage.tsdb.path=/data",
                "--storage.tsdb.retention.time=4h",
                "--storage.tsdb.retention.size=512MB",
            ],
            "ports": [{"containerPort": 9090}],
            "volumeMounts": [
                {"name": "config", "mountPath": "/etc/prometheus", "readOnly": True},
                {"name": "data", "mountPath": "/data"},
            ],
            "resources": {
                "requests": {"cpu": "100m", "memory": "128Mi"},
                "limits": {"cpu": "500m", "memory": "512Mi"},
            },
            "securityContext": security,
        },
        securityContext={"runAsUser": 65534, "runAsNonRoot": True, "fsGroup": 65534},
        volumes=[
            {"name": "config", "configMap": {"name": "telemetry"}},
            {"name": "data", "emptyDir": {"sizeLimit": "1Gi"}},
        ],
    )
    add(
        "DaemonSet",
        "nvidia-device-plugin",
        {
            "selector": {"matchLabels": {"app": "nvidia-device-plugin"}},
            "template": {
                "metadata": {"labels": {"app": "nvidia-device-plugin"}},
                "spec": {
                    "automountServiceAccountToken": False,
                    "nodeSelector": {"m5-role": "gpu"},
                    "tolerations": [
                        {"key": "nvidia.com/gpu", "operator": "Exists", "effect": "NoSchedule"}
                    ],
                    "containers": [
                        {
                            "name": "plugin",
                            "image": DEVICE_IMAGE,
                            "env": [{"name": "FAIL_ON_INIT_ERROR", "value": "true"}],
                            "volumeMounts": [
                                {"name": "plugins", "mountPath": "/var/lib/kubelet/device-plugins"}
                            ],
                            "securityContext": security,
                        }
                    ],
                    "volumes": [
                        {
                            "name": "plugins",
                            "hostPath": {
                                "path": "/var/lib/kubelet/device-plugins",
                                "type": "Directory",
                            },
                        }
                    ],
                },
            },
        },
        api="apps/v1",
    )
    return {"apiVersion": "v1", "kind": "List", "items": objects}


def stream(config, configuration_digest, start_ns, prompt, deadline=None, *, tls_context=None):
    """Existing calibration scheduling, strict existing gateway SSE decoder."""
    from .stage_c_prompts import prompt_messages

    dispatched = time.perf_counter_ns()
    end = min(deadline or float("inf"), dispatched / 1e9 + config.timeout_seconds)
    decoder, status, error, backend = SSEDecoder(), None, None, None
    content = []
    req = urllib.request.Request(
        config.url.rstrip("/") + "/v1/chat/completions",
        data=json.dumps(
            {
                "model": config.model,
                "messages": prompt_messages(prompt),
                "stream": True,
                "max_tokens": config.max_tokens,
                "temperature": 0,
            }
        ).encode(),
        headers={"Authorization": "Bearer " + config.token, "Content-Type": "application/json"},
    )
    try:
        with deadline_urlopen(
            req, timeout=config.timeout_seconds, deadline=end, context=tls_context
        ) as response:
            status = response.status
            backend = response.headers.get("X-Inference-Backend")
            received = 0
            # Match the existing decoder's 1 MiB ceiling before retaining bytes;
            # An unbounded line iterator could allocate an arbitrarily long line.
            for line in iter(lambda: response.read1(64 * 1024), b""):
                received += len(line)
                if received > 1_048_576:
                    decoder.errors.append("oversize_sse")
                    break
                now = time.perf_counter_ns()
                previous = len(decoder.content)
                decoder.feed(line, [now // 1_000_000, (now + 999_999) // 1_000_000])
                content.extend([now] * (len(decoder.content) - previous))
    except urllib.error.HTTPError as exc:
        status, error = exc.code, "http_rejection"
        exc.close()
    except (OSError, ValueError, http.client.HTTPException) as exc:
        error = type(exc).__name__
    ended = time.perf_counter_ns()
    report = decoder.report()
    completed = status == 200 and report["complete"] and error is None
    return {
        "configuration_digest": configuration_digest,
        "backend_id": backend,
        "dispatch_offset_ns": dispatched - start_ns,
        "first_content_offset_ns": content[0] - start_ns if content else None,
        "completion_offset_ns": ended - start_ns,
        "outcome": "completed"
        if completed
        else "partial_stream"
        if content
        else "rejected"
        if status == 429
        else "failed_before_content",
        "http_status": status,
        "dispatched": True,
        "admitted": True if status == 200 else False if status == 429 else None,
        "error_code": error or (None if completed else "invalid_or_incomplete_sse"),
        "itl_ns": [right - left for left, right in zip(content, content[1:], strict=False)],
        "strict_terminal": report,
        "dispatch_monotonic_ns": dispatched,
    }


def summarize(rows, elapsed_s):
    if not math.isfinite(elapsed_s) or elapsed_s <= 0:
        raise ValueError("descriptive:measurement_interval")
    rows = list(rows)
    outcomes = Counter(row["outcome"] for row in rows)
    if set(outcomes) - {
        "completed",
        "partial_stream",
        "rejected",
        "failed_before_content",
        "cancelled",
        "not_dispatched",
    }:
        raise ValueError("descriptive:unknown_outcome")

    def percentiles(values):
        values = sorted(values)
        return {
            "n": len(values),
            **{
                f"p{p}": values[math.ceil(len(values) * p / 100) - 1] / 1e6
                if len(values) * (100 - p) >= 2000
                else None
                for p in (50, 95)
            },
        }

    failed_admitted = sum(
        row["outcome"] == "failed_before_content"
        and row.get("dispatched", row.get("dispatch_offset_ns") is not None)
        and row.get("admitted", row["http_status"] == 200) is True
        for row in rows
    )
    return {
        "run": len(rows),
        "outcomes": dict(outcomes),
        "completed": outcomes["completed"],
        "partial": outcomes["partial_stream"],
        "failed_no_content": failed_admitted,
        "failed_admission_unknown": outcomes["failed_before_content"] - failed_admitted,
        "rejected": outcomes["rejected"],
        "not_dispatched": outcomes["not_dispatched"],
        "cancelled": outcomes["cancelled"],
        "http_statuses": dict(Counter(str(row["http_status"]) for row in rows)),
        "elapsed_s": elapsed_s,
        "completed_per_s": sum(
            row["outcome"] == "completed" and row["completion_offset_ns"] <= elapsed_s * 1e9
            for row in rows
        )
        / elapsed_s,
        "completed_in_window": sum(
            row["outcome"] == "completed" and row["completion_offset_ns"] <= elapsed_s * 1e9
            for row in rows
        ),
        "completed_during_drain": sum(
            row["outcome"] == "completed" and row["completion_offset_ns"] > elapsed_s * 1e9
            for row in rows
        ),
        "ttft_ms": percentiles(
            row["first_content_offset_ns"] - row["dispatch_offset_ns"]
            for row in rows
            if row["first_content_offset_ns"] is not None
        ),
        "itl_ms": percentiles(gap for row in rows for gap in row.get("itl_ns", [])),
    }
