"""Versioned EKS resources. Rendering is offline; this module never applies them."""

import hashlib
import ipaddress
import json
import re
from pathlib import Path, PurePosixPath

from .r1_spec import engine_argv

VLLM_IMAGE = "docker.io/vllm/vllm-openai@sha256:082ca6f035279109041ffd3fe0695cb568b29bc580b35c4f297a66a08b216c1b"
MODEL = "Qwen/Qwen2.5-7B-Instruct"
REVISION = "a09a35458c702b33eeacc393d103063234e8bc28"
NGINX_IMAGE = (
    "nginx:1.30.6-alpine@sha256:970364228b1e4f932abc22d321932816782cca8a20b85a77552a7cfe9acfb3b5"
)
PROMETHEUS_IMAGE = "prom/prometheus:v3.13.0@sha256:c6b27ea434f8389bfe233fbc7be381cf50587c286e871bc842008f5a1b1908a7"
PYTHON_IMAGE = "python:3.12.7-slim-bookworm@sha256:60d9996b6a8a3689d36db740b49f4327be3be09a21122bd02fb8895abb38b50d"
DEVICE_IMAGE = "nvcr.io/nvidia/k8s-device-plugin:v0.17.1@sha256:af31e2b7c7f89834c4e5219860def7ac2e49a207b3d4e8610d5a26772b7738e5"
REDIS_IMAGE = (
    "redis:8.2.9-alpine@sha256:30abb90e62f14b737010746def3ba99cc79fe19dcdb3d37b41f21fc62e7da19d"
)

NGINX = """pid /tmp/nginx.pid;
events { worker_connections 4096; }
http {
  access_log /dev/stdout;
  error_log /dev/stderr;
  client_body_temp_path /tmp/client;
  proxy_temp_path /tmp/proxy;
  fastcgi_temp_path /tmp/fastcgi;
  uwsgi_temp_path /tmp/uwsgi;
  scgi_temp_path /tmp/scgi;
  upstream gateways { server gateway:8080; keepalive 32; }
  server {
    listen 8443 ssl;
    ssl_certificate /tls/tls.crt;
    ssl_certificate_key /tls/tls.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    keepalive_timeout 65s;
    client_header_timeout 10s;
    client_body_timeout 10s;
    send_timeout 45s;
    location = /v1/chat/completions {
      limit_except POST { deny all; }
      proxy_pass http://gateways;
      proxy_http_version 1.1;
      proxy_set_header Connection "";
      proxy_buffering off;
      proxy_request_buffering off;
      proxy_cache off;
      gzip off;
      proxy_connect_timeout 2s;
      proxy_read_timeout 45s;
      proxy_send_timeout 45s;
      proxy_next_upstream off;
      add_header X-Accel-Buffering no always;
    }
    location / { return 404; }
  }
}
"""


def image_pin(value):
    if not isinstance(value, str) or not re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", value):
        raise ValueError("image_digest_required")
    return value


def resource_agent_command(*, python, spec_path, host, port):
    """Independent resource process entry; placement/spec/capacity are explicit.

    Do not run this inside capture_runtime's measured vLLM child/cgroup. The
    launcher validates source, boot, target and guaranteed-capacity evidence.
    """
    if not all(isinstance(s, str) and s for s in (python, str(spec_path), host)):
        raise ValueError("resource_agent_launch_inputs")
    if type(port) is not int or not 0 <= port <= 65535:
        raise ValueError("resource_agent_port")
    return [
        python,
        "-m",
        "inference_platform.inf037b_resource_agent",
        "--spec",
        str(spec_path),
        "--host",
        host,
        "--port",
        str(port),
    ]


def setup_signal_pod(inputs, slot, node_name, runtime_source):
    """Non-serving supervisor on the target node, created before the fixed probe."""
    if type(slot) is not int or slot not in (0, 1) or not node_name:
        raise ValueError("setup_signal:binding")
    namespace = inputs["namespace"]
    runtime_hash = hashlib.sha256(runtime_source.encode()).hexdigest()
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "namespace": namespace,
            "name": "setup-signal-" + str(slot),
            "labels": {
                "m5-session": namespace,
                "inf037b-role": "setup_signal",
                "inf037b-slot": str(slot),
            },
        },
        "spec": {
            "nodeName": node_name,
            "restartPolicy": "Never",
            "automountServiceAccountToken": False,
            "terminationGracePeriodSeconds": 45,
            "tolerations": [
                {"key": "nvidia.com/gpu", "operator": "Exists", "effect": "NoSchedule"}
            ],
            "containers": [
                {
                    "name": "signal",
                    "image": VLLM_IMAGE,
                    "command": ["python3", "/capture-code/capture_runtime.py"],
                    "args": ["--setup-signal"],
                    "env": [
                        {"name": "NVIDIA_VISIBLE_DEVICES", "value": "void"},
                        {
                            "name": "POD_UID",
                            "valueFrom": {"fieldRef": {"fieldPath": "metadata.uid"}},
                        },
                        {
                            "name": "NODE_NAME",
                            "valueFrom": {"fieldRef": {"fieldPath": "spec.nodeName"}},
                        },
                        {"name": "BACKEND_SLOT", "value": str(slot)},
                        {"name": "CAPTURE_ROOT", "value": "/capture-data/$(POD_UID)"},
                    ],
                    "readinessProbe": {
                        "httpGet": {"path": "/ready", "port": 9101},
                        "periodSeconds": 1,
                        "timeoutSeconds": 1,
                    },
                    "resources": {
                        "requests": {"cpu": "250m", "memory": "512Mi"},
                        "limits": {"cpu": "1", "memory": "2Gi"},
                    },
                    "volumeMounts": [
                        {"name": "runtime", "mountPath": "/capture-code", "readOnly": True},
                        {"name": "capture", "mountPath": "/capture-data"},
                    ],
                }
            ],
            "volumes": [
                {"name": "runtime", "configMap": {"name": "runtime-capture-" + runtime_hash[:12]}},
                {
                    "name": "capture",
                    "hostPath": {
                        "path": "/var/lib/mti-m5/" + namespace,
                        "type": "DirectoryOrCreate",
                    },
                },
            ],
        },
    }


def device_witness_resources(inputs):
    """Read-only node sources; actual driver/release evidence remains explicit.

    The independent Pod UID and Node UID are filled from discovery, never engine
    Pod identities. The controller publishes clock-joined receipts separately.
    """
    config = inputs.get("device_witness")
    if config is None:
        return []
    namespace = inputs["namespace"]
    source = (Path(__file__).parent / "inf037b_device.py").read_text()
    source_sha = hashlib.sha256(source.encode()).hexdigest()
    required = (
        "spec_configmap",
        "token_secret",
        "tls_secret",
        "helper_host_path",
        "nvidia_smi_host_path",
        "driver_lib_host_path",
        "crictl_host_path",
        "nvidia_runtime_class",
        "report_names",
    )
    if not all(config.get(k) for k in required):
        raise ValueError("device:unresolved:node_source_deployment")
    paths = (config[k] for k in required if k.endswith("_host_path"))
    if not all(
        PurePosixPath(path).is_absolute() and ".." not in PurePosixPath(path).parts
        for path in paths
    ):
        raise ValueError("device:host_path")
    if (
        type(config["report_names"]) is not list
        or len(set(config["report_names"])) != 2
        or not all(re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", n) for n in config["report_names"])
    ):
        raise ValueError("device:report_names")
    volumes = [
        {"name": "code", "configMap": {"name": "device-code-" + source_sha[:12]}},
        {"name": "spec", "configMap": {"name": config["spec_configmap"]}},
        {"name": "token", "secret": {"secretName": config["token_secret"]}},
        {"name": "tls", "secret": {"secretName": config["tls_secret"]}},
        *[
            {"name": name, "hostPath": {"path": path, "type": kind}}
            for name, path, kind in (
                ("podresources", "/var/lib/kubelet/pod-resources", "Directory"),
                ("helper", config["helper_host_path"], "File"),
                ("smi", config["nvidia_smi_host_path"], "File"),
                ("driver-libs", config["driver_lib_host_path"], "Directory"),
                ("crictl", config["crictl_host_path"], "File"),
                ("cri", "/run/containerd/containerd.sock", "Socket"),
                ("host-proc", "/proc", "Directory"),
            )
        ],
    ]
    mounts = [
        {"name": name, "mountPath": path, "readOnly": True}
        for name, path in (
            ("code", "/code"),
            ("spec", "/spec"),
            ("token", "/token"),
            ("tls", "/tls"),
            ("podresources", "/var/lib/kubelet/pod-resources"),
            ("helper", "/tools/podresources"),
            ("smi", "/tools/nvidia-smi"),
            ("driver-libs", "/node-libs"),
            ("crictl", "/tools/crictl"),
            ("cri", "/run/containerd/containerd.sock"),
            ("host-proc", "/host-proc"),
        )
    ]
    objects = [
        {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"namespace": namespace, "name": "device-code-" + source_sha[:12]},
            "immutable": True,
            "data": {"device.py": source},
        },
        {
            "apiVersion": "apps/v1",
            "kind": "DaemonSet",
            "metadata": {"namespace": namespace, "name": "device-witness"},
            "spec": {
                "updateStrategy": {
                    "type": "RollingUpdate",
                    "rollingUpdate": {"maxSurge": 0, "maxUnavailable": 1},
                },
                "selector": {"matchLabels": {"app": "device-witness"}},
                "template": {
                    "metadata": {"labels": {"app": "device-witness", "m5-session": namespace}},
                    "spec": {
                        "hostPID": True,
                        "runtimeClassName": config["nvidia_runtime_class"],
                        "automountServiceAccountToken": False,
                        "nodeSelector": {"m5-role": "gpu"},
                        "tolerations": [
                            {"key": "nvidia.com/gpu", "operator": "Exists", "effect": "NoSchedule"}
                        ],
                        "containers": [
                            {
                                "name": "witness",
                                "image": PYTHON_IMAGE,
                                "command": [
                                    "python",
                                    "/code/device.py",
                                    "--spec",
                                    "/spec/$(NODE_NAME).json",
                                ],
                                "ports": [{"containerPort": 9103}],
                                "env": [
                                    {
                                        "name": "POD_UID",
                                        "valueFrom": {"fieldRef": {"fieldPath": "metadata.uid"}},
                                    },
                                    {
                                        "name": "NODE_NAME",
                                        "valueFrom": {"fieldRef": {"fieldPath": "spec.nodeName"}},
                                    },
                                    {"name": "PYTHONDONTWRITEBYTECODE", "value": "1"},
                                    {"name": "LD_LIBRARY_PATH", "value": "/node-libs"},
                                    {"name": "NVIDIA_VISIBLE_DEVICES", "value": "all"},
                                    {"name": "NVIDIA_DRIVER_CAPABILITIES", "value": "utility"},
                                ],
                                "securityContext": {
                                    "runAsUser": 0,
                                    "readOnlyRootFilesystem": True,
                                    "allowPrivilegeEscalation": False,
                                    "capabilities": {"drop": ["ALL"], "add": ["SYS_PTRACE"]},
                                },
                                "resources": {
                                    "requests": {"cpu": "100m", "memory": "128Mi"},
                                    "limits": {"cpu": "500m", "memory": "256Mi"},
                                },
                                "volumeMounts": mounts,
                            }
                        ],
                        "volumes": volumes,
                    },
                },
            },
        },
    ]

    for name in config["report_names"]:
        objects.append(
            {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {"namespace": namespace, "name": name},
                "data": {},
            }
        )
    objects.extend(
        [
            {
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "Role",
                "metadata": {"namespace": namespace, "name": "device-report-writer"},
                "rules": [
                    {
                        "apiGroups": [""],
                        "resources": ["configmaps"],
                        "resourceNames": config["report_names"],
                        "verbs": ["get", "update"],
                    }
                ],
            },
            {
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "RoleBinding",
                "metadata": {"namespace": namespace, "name": "device-report-writer"},
                "subjects": [{"kind": "ServiceAccount", "name": "capture", "namespace": namespace}],
                "roleRef": {
                    "apiGroup": "rbac.authorization.k8s.io",
                    "kind": "Role",
                    "name": "device-report-writer",
                },
            },
        ]
    )
    return objects


def resources(inputs, runtime_source):
    """No defaults for paid inputs, credentials, TLS or dynamic capacity R/W."""
    namespace = inputs["namespace"]
    if not re.fullmatch(r"mti-m5-[a-z0-9-]{1,40}", namespace):
        raise ValueError("session_namespace_required")
    gateway_image = image_pin(inputs["gateway_image"])
    for key in ("crictl_sha256", "model_manifest_sha256"):
        if not isinstance(inputs[key], str) or not re.fullmatch(r"[0-9a-f]{64}", inputs[key]):
            raise ValueError("node_observer_pin_required:" + key)
    model_manifest = inputs.get("model_manifest")
    if not isinstance(model_manifest, dict) or not model_manifest:
        raise ValueError("complete_model_manifest_required")
    for name, expected in model_manifest.items():
        relative = PurePosixPath(name) if isinstance(name, str) else PurePosixPath("/")
        if (
            not isinstance(name, str)
            or relative.is_absolute()
            or not relative.parts
            or relative.as_posix() != name
            or ".." in relative.parts
            or "\\" in name
            or not isinstance(expected, dict)
            or set(expected) != {"sha256", "bytes"}
            or not isinstance(expected.get("sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", expected["sha256"])
            or type(expected.get("bytes")) is not int
            or expected["bytes"] < 0
        ):
            raise ValueError("invalid_model_manifest")
    model_manifest_bytes = json.dumps(
        model_manifest, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()
    if len(model_manifest_bytes) > 900_000:
        raise ValueError("model_manifest_configmap_oversize")
    if hashlib.sha256(model_manifest_bytes).hexdigest() != inputs["model_manifest_sha256"]:
        raise ValueError("model_manifest_pin_mismatch")
    if inputs["crictl_host_path"] not in ("/usr/bin/crictl", "/usr/local/bin/crictl"):
        raise ValueError("reviewed_crictl_host_path_required")
    source_ranges = inputs["operator_cidrs"]
    if (
        not isinstance(source_ranges, list)
        or not source_ranges
        or any(
            ipaddress.ip_network(cidr).version != 4 or ipaddress.ip_network(cidr).prefixlen < 24
            for cidr in source_ranges
        )
    ):
        raise ValueError("restricted_operator_ipv4_ranges_required")
    if (
        type(inputs["r"]) is not int
        or type(inputs["w"]) is not int
        or (inputs["r"], inputs["w"]) != (4, 1)
    ):
        raise ValueError("registration_v3_requires_R4_W1")
    if not re.fullmatch(r"[a-zA-Z0-9.-]+", inputs["tls_secret"]) or not inputs["tls_secret"]:
        raise ValueError("tls_secret_required")
    if not re.fullmatch(r"[0-9a-f]{64}", inputs["config_sha256"]):
        raise ValueError("config_sha256_required")
    output = []

    def add(kind, name, spec=None, api="v1", **extra):
        obj = {
            "apiVersion": api,
            "kind": kind,
            "metadata": {"name": name, "namespace": namespace, "labels": {"m5-session": namespace}},
            **extra,
        }
        if spec is not None:
            obj["spec"] = spec
        output.append(obj)
        return obj

    output.append(
        {
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {"name": namespace, "labels": {"m5-session": namespace}},
        }
    )
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
    add("ServiceAccount", "capture")
    add(
        "Role",
        "capture-reader",
        api="rbac.authorization.k8s.io/v1",
        rules=[
            {
                "apiGroups": [""],
                "resources": ["pods", "pods/log", "events"],
                "verbs": ["get", "list", "watch"],
            },
            {
                "apiGroups": ["discovery.k8s.io"],
                "resources": ["endpointslices"],
                "verbs": ["get", "list", "watch"],
            },
        ],
    )
    add(
        "RoleBinding",
        "capture-reader",
        api="rbac.authorization.k8s.io/v1",
        subjects=[{"kind": "ServiceAccount", "name": "capture", "namespace": namespace}],
        roleRef={"kind": "Role", "name": "capture-reader", "apiGroup": "rbac.authorization.k8s.io"},
    )
    runtime_hash = hashlib.sha256(runtime_source.encode()).hexdigest()
    add(
        "ConfigMap",
        "runtime-capture-" + runtime_hash[:12],
        immutable=True,
        data={"capture_runtime.py": runtime_source},
    )
    add("ConfigMap", "streaming-ingress", immutable=True, data={"nginx.conf": NGINX})
    observer_source = (
        Path(__file__).resolve().parents[3] / "deploy/eks/node_observer.py"
    ).read_text()
    native_source = (Path(__file__).parent / "inf037b_native.py").read_text()
    observer_hash = hashlib.sha256((observer_source + native_source).encode()).hexdigest()
    add(
        "ConfigMap",
        "node-observer-" + observer_hash[:12],
        immutable=True,
        data={"node_observer.py": observer_source, "native_source.py": native_source},
    )
    add(
        "ConfigMap",
        "model-cache-manifest",
        immutable=True,
        data={"manifest.json": model_manifest_bytes.decode()},
    )
    add(
        "ConfigMap",
        "telemetry",
        immutable=True,
        data={
            "prometheus.yml": json.dumps(
                {
                    "global": {"scrape_interval": "500ms", "scrape_timeout": "400ms"},
                    "scrape_configs": [
                        {
                            "job_name": "serving-pods",
                            "kubernetes_sd_configs": [
                                {"role": "pod", "namespaces": {"names": [namespace]}}
                            ],
                            "relabel_configs": [
                                {
                                    "source_labels": ["__meta_kubernetes_pod_label_app"],
                                    "regex": "gateway|vllm",
                                    "action": "keep",
                                },
                                {
                                    "source_labels": [
                                        "__meta_kubernetes_pod_container_port_number"
                                    ],
                                    "regex": "8000|8080",
                                    "action": "keep",
                                },
                                {
                                    "source_labels": ["__meta_kubernetes_pod_uid"],
                                    "target_label": "pod_uid",
                                },
                                {
                                    "source_labels": ["__meta_kubernetes_pod_name"],
                                    "target_label": "pod_name",
                                },
                                {
                                    "source_labels": ["__meta_kubernetes_pod_label_app"],
                                    "target_label": "app",
                                },
                            ],
                        },
                    ],
                }
            )
        },
    )

    def service(name, app, port, *, headless=False):
        spec = {
            "type": "ClusterIP",
            "selector": {"app": app},
            "ports": [
                {"name": "http" if port != 6379 else "redis", "port": port, "targetPort": port}
            ],
        }
        if headless:
            spec["clusterIP"] = "None"
        return add("Service", name, spec)

    service("vllm", "vllm", 8000, headless=True)
    service("redis", "redis", 6379)
    service("gateway", "gateway", 8080)
    service("gateway-peer", "gateway", 8080, headless=True)
    base_security = {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}}

    def workload(kind, name, replicas, containers, pod, strategy=None):
        spec = {
            "replicas": replicas,
            "selector": {"matchLabels": {"app": name}},
            "template": {
                "metadata": {"labels": {"app": name, "m5-session": namespace}},
                "spec": {
                    "automountServiceAccountToken": False,
                    "terminationGracePeriodSeconds": 60,
                    "nodeSelector": {"m5-role": "cpu"},
                    "containers": containers,
                    **pod,
                },
            },
        }
        if kind == "StatefulSet":
            spec.update(
                serviceName=name,
                podManagementPolicy="OrderedReady",
                updateStrategy={"type": "OnDelete"},
            )
        elif strategy:
            spec["strategy"] = strategy
        return add(kind, name, spec, api="apps/v1")

    workload(
        "Deployment",
        "redis",
        1,
        [
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
                "ports": [{"containerPort": 6379}],
                "securityContext": base_security,
                "readinessProbe": {"exec": {"command": ["redis-cli", "ping"]}, "periodSeconds": 1},
                "resources": {
                    "requests": {"cpu": "100m", "memory": "128Mi"},
                    "limits": {"cpu": "1", "memory": "384Mi"},
                },
            }
        ],
        {},
        {"type": "Recreate"},
    )

    downward = [
        {"name": name, "valueFrom": {"fieldRef": {"fieldPath": field}}}
        for name, field in (("POD_UID", "metadata.uid"), ("POD_NAME", "metadata.name"))
    ]
    gateway_env = {
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
        "ADMISSION_RUNNING": str(inputs["r"]),
        "ADMISSION_WAITING": str(inputs["w"]),
        "ADMISSION_REPORT_TTL": "8s",
        "ADMISSION_HOLD_DOWN": "2s",
        "GATEWAY_MEASUREMENT_PATH": "/capture-data/gateway.jsonl",
        "GATEWAY_ROUTING_POLICY": "round_robin",
        "OTEL_SDK_DISABLED": "true",
    }
    # StatefulSet identities make the two registered gateway sources stable;
    # POD_UID remains the independent source boot/generation.
    gateway_env["ADMISSION_GATEWAY_ID"] = "$(POD_NAME)"
    gateway_set = workload(
        "StatefulSet",
        "gateway",
        2,
        [
            {
                "name": "gateway",
                "image": gateway_image,
                "ports": [{"containerPort": 8080}],
                "env": downward + [{"name": k, "value": v} for k, v in gateway_env.items()],
                "volumeMounts": [
                    {"name": "config", "mountPath": "/config", "readOnly": True},
                    {"name": "capture", "mountPath": "/capture-data"},
                ],
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
                "securityContext": {**base_security, "readOnlyRootFilesystem": True},
                "resources": {
                    "requests": {"cpu": "250m", "memory": "256Mi"},
                    "limits": {"cpu": "1", "memory": "512Mi"},
                },
            }
        ],
        {
            "serviceAccountName": "gateway",
            "automountServiceAccountToken": True,
            "securityContext": {"runAsUser": 65532, "runAsNonRoot": True, "fsGroup": 65532},
            "volumes": [
                {"name": "config", "secret": {"secretName": "gateway-config"}},
                {"name": "capture", "emptyDir": {"sizeLimit": "1Gi"}},
            ],
        },
    )
    gateway_set["spec"]["serviceName"] = "gateway-peer"
    gateway_set["spec"]["podManagementPolicy"] = "Parallel"

    workload(
        "StatefulSet",
        "vllm",
        2,
        [
            {
                "name": "vllm",
                "image": VLLM_IMAGE,
                "command": ["python3", "/capture-code/capture_runtime.py"],
                "args": [
                    "--model",
                    MODEL,
                    "--revision",
                    REVISION,
                    "--host",
                    "0.0.0.0",
                    "--port",
                    "8000",
                    *engine_argv(),
                    "--shutdown-timeout",
                    "35",
                ],
                "env": downward + [{"name": "VLLM_WORKER_MULTIPROC_METHOD", "value": "spawn"}],
                "ports": [
                    {"name": "http", "containerPort": 8000},
                    {"name": "capture", "containerPort": 9101},
                ],
                "startupProbe": {
                    "httpGet": {"path": "/health", "port": 8000},
                    "periodSeconds": 1,
                    "timeoutSeconds": 1,
                    "failureThreshold": 1800,
                },
                "readinessProbe": {
                    "httpGet": {"path": "/health", "port": 8000},
                    "periodSeconds": 1,
                    "timeoutSeconds": 1,
                    "failureThreshold": 1,
                },
                "volumeMounts": [
                    {"name": "runtime", "mountPath": "/capture-code", "readOnly": True},
                    {"name": "capture", "mountPath": "/capture-data"},
                    {"name": "shm", "mountPath": "/dev/shm"},
                    {"name": "model", "mountPath": "/root/.cache/huggingface"},
                ],
                "securityContext": base_security,
                "resources": {
                    "requests": {"nvidia.com/gpu": "1", "cpu": "2", "memory": "8Gi"},
                    "limits": {"nvidia.com/gpu": "1", "cpu": "4", "memory": "12Gi"},
                },
            }
        ],
        {
            "terminationGracePeriodSeconds": 45,
            "nodeSelector": {"m5-role": "gpu"},
            "tolerations": [
                {
                    "key": "nvidia.com/gpu",
                    "operator": "Equal",
                    "value": "true",
                    "effect": "NoSchedule",
                }
            ],
            "affinity": {
                "podAntiAffinity": {
                    "requiredDuringSchedulingIgnoredDuringExecution": [
                        {
                            "labelSelector": {"matchLabels": {"app": "vllm"}},
                            "topologyKey": "kubernetes.io/hostname",
                        }
                    ]
                }
            },
            "volumes": [
                {"name": "runtime", "configMap": {"name": "runtime-capture-" + runtime_hash[:12]}},
                {
                    "name": "capture",
                    "hostPath": {
                        "path": "/var/lib/mti-m5/" + namespace,
                        "type": "DirectoryOrCreate",
                    },
                },
                {"name": "shm", "emptyDir": {"medium": "Memory", "sizeLimit": "1Gi"}},
                {
                    "name": "model",
                    "hostPath": {"path": "/var/cache/mti-m5/models", "type": "DirectoryOrCreate"},
                },
            ],
        },
    )
    # Each UID needs its own directory on the node across restarts and replacements.
    vllm = output[-1]["spec"]["template"]["spec"]["containers"][0]
    vllm["env"].append({"name": "CAPTURE_ROOT", "value": "/capture-data/$(POD_UID)"})
    vllm["env"].extend(
        [
            {
                "name": "BACKEND_SLOT",
                "valueFrom": {
                    "fieldRef": {"fieldPath": "metadata.labels['apps.kubernetes.io/pod-index']"}
                },
            },
            {"name": "NODE_NAME", "valueFrom": {"fieldRef": {"fieldPath": "spec.nodeName"}}},
        ]
    )
    overlay = inputs.get("native_overlay")
    if overlay is not None:
        from .inf037b_native import BASE_FILES

        manifest = overlay["manifest"]
        if (
            manifest.get("base") != BASE_FILES
            or manifest.get("version") != "0.29.0"
            or set(manifest.get("files", {})) != set(BASE_FILES)
            or hashlib.sha256(
                (Path(__file__).parent / "inf037b_native.py").read_bytes()
            ).hexdigest()
            != manifest.get("helper_sha256")
        ):
            raise ValueError("native:overlay_deployment_pin")
        for key in ("host_path", "runtime_site"):
            path = PurePosixPath(overlay[key])
            if not path.is_absolute() or ".." in path.parts:
                raise ValueError("native:overlay_deployment_path")
        pod_spec = output[-1]["spec"]["template"]["spec"]
        pod_spec["volumes"].append(
            {
                "name": "native-overlay",
                "hostPath": {"path": overlay["host_path"], "type": "Directory"},
            }
        )
        vllm["volumeMounts"].append(
            {"name": "native-overlay", "mountPath": "/native-overlay", "readOnly": True}
        )
        vllm["volumeMounts"].extend(
            {
                "name": "native-overlay",
                "subPath": name,
                "mountPath": str(PurePosixPath(overlay["runtime_site"]) / name),
                "readOnly": True,
            }
            for name in BASE_FILES
        )
        vllm["env"].extend(
            [
                {"name": "INF037B_NATIVE_ROOT", "value": "$(CAPTURE_ROOT)/native"},
                {
                    "name": "INF037B_NATIVE_MANIFEST",
                    "value": "/native-overlay/native-manifest.json",
                },
                {"name": "PYTHONPATH", "value": "/native-overlay"},
                {"name": "MODEL_SHA256", "value": overlay["model_sha256"]},
                {"name": "RUNTIME_SHA256", "value": VLLM_IMAGE.rsplit("sha256:", 1)[1]},
            ]
        )

    for app in ("gateway", "vllm"):
        add(
            "PodDisruptionBudget",
            app,
            {"minAvailable": 1, "selector": {"matchLabels": {"app": app}}},
            api="policy/v1",
        )
    add(
        "DaemonSet",
        "node-observer",
        {
            "selector": {"matchLabels": {"app": "node-observer"}},
            "updateStrategy": {
                "type": "RollingUpdate",
                "rollingUpdate": {"maxSurge": 0, "maxUnavailable": 1},
            },
            "template": {
                "metadata": {"labels": {"app": "node-observer", "m5-session": namespace}},
                "spec": {
                    "automountServiceAccountToken": False,
                    "nodeSelector": {"m5-role": "gpu"},
                    "tolerations": [
                        {
                            "key": "nvidia.com/gpu",
                            "operator": "Equal",
                            "value": "true",
                            "effect": "NoSchedule",
                        }
                    ],
                    "containers": [
                        {
                            "name": "observer",
                            "image": PYTHON_IMAGE,
                            "command": ["python", "/code/node_observer.py"],
                            "ports": [{"containerPort": 9102}],
                            "env": [
                                {
                                    "name": "NODE_NAME",
                                    "valueFrom": {"fieldRef": {"fieldPath": "spec.nodeName"}},
                                },
                                {"name": "PYTHONDONTWRITEBYTECODE", "value": "1"},
                                {"name": "EXPECTED_IMAGE", "value": VLLM_IMAGE},
                                {
                                    "name": "MODEL_MANIFEST_SHA256",
                                    "value": inputs["model_manifest_sha256"],
                                },
                                {"name": "CRICTL_SHA256", "value": inputs["crictl_sha256"]},
                            ],
                            "securityContext": {
                                **base_security,
                                "readOnlyRootFilesystem": True,
                                "runAsUser": 0,
                            },
                            "readinessProbe": {
                                "httpGet": {"path": "/clock", "port": 9102},
                                "periodSeconds": 1,
                            },
                            "resources": {
                                "requests": {"cpu": "100m", "memory": "64Mi"},
                                "limits": {"cpu": "500m", "memory": "128Mi"},
                            },
                            "volumeMounts": [
                                {"name": "code", "mountPath": "/code", "readOnly": True},
                                {
                                    "name": "manifest",
                                    "mountPath": "/model-manifest",
                                    "readOnly": True,
                                },
                                {"name": "models", "mountPath": "/models", "readOnly": True},
                                {"name": "crictl", "mountPath": "/tools/crictl", "readOnly": True},
                                {
                                    "name": "cri",
                                    "mountPath": "/run/containerd/containerd.sock",
                                    "readOnly": True,
                                },
                                {"name": "boot", "mountPath": "/node-boot-id", "readOnly": True},
                                {"name": "lifecycle", "mountPath": "/lifecycle", "readOnly": True},
                            ],
                        }
                    ],
                    "volumes": [
                        {
                            "name": "code",
                            "configMap": {"name": "node-observer-" + observer_hash[:12]},
                        },
                        {"name": "manifest", "configMap": {"name": "model-cache-manifest"}},
                        {
                            "name": "models",
                            "hostPath": {
                                "path": "/var/cache/mti-m5/models",
                                "type": "DirectoryOrCreate",
                            },
                        },
                        {
                            "name": "crictl",
                            "hostPath": {"path": inputs["crictl_host_path"], "type": "File"},
                        },
                        {
                            "name": "cri",
                            "hostPath": {
                                "path": "/run/containerd/containerd.sock",
                                "type": "Socket",
                            },
                        },
                        {
                            "name": "boot",
                            "hostPath": {"path": "/proc/sys/kernel/random/boot_id", "type": "File"},
                        },
                        {
                            "name": "lifecycle",
                            "hostPath": {
                                "path": "/var/lib/mti-m5/" + namespace,
                                "type": "DirectoryOrCreate",
                            },
                        },
                    ],
                },
            },
        },
        api="apps/v1",
    )
    add(
        "DaemonSet",
        "nvidia-device-plugin",
        {
            "selector": {"matchLabels": {"app": "nvidia-device-plugin"}},
            "updateStrategy": {
                "type": "RollingUpdate",
                "rollingUpdate": {"maxSurge": 0, "maxUnavailable": 1},
            },
            "template": {
                "metadata": {"labels": {"app": "nvidia-device-plugin", "m5-session": namespace}},
                "spec": {
                    "automountServiceAccountToken": False,
                    "nodeSelector": {"m5-role": "gpu"},
                    "tolerations": [
                        {
                            "key": "nvidia.com/gpu",
                            "operator": "Equal",
                            "value": "true",
                            "effect": "NoSchedule",
                        }
                    ],
                    "containers": [
                        {
                            "name": "plugin",
                            "image": DEVICE_IMAGE,
                            "env": [{"name": "FAIL_ON_INIT_ERROR", "value": "true"}],
                            "securityContext": base_security,
                            "volumeMounts": [
                                {"name": "plugins", "mountPath": "/var/lib/kubelet/device-plugins"}
                            ],
                            "resources": {
                                "requests": {"cpu": "50m", "memory": "32Mi"},
                                "limits": {"cpu": "100m", "memory": "128Mi"},
                            },
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
    workload(
        "Deployment",
        "streaming-ingress",
        1,
        [
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
                "readinessProbe": {"tcpSocket": {"port": 8443}, "periodSeconds": 1},
                "securityContext": {**base_security, "readOnlyRootFilesystem": True},
                "resources": {
                    "requests": {"cpu": "100m", "memory": "32Mi"},
                    "limits": {"cpu": "1", "memory": "128Mi"},
                },
            }
        ],
        {
            "securityContext": {"runAsUser": 101, "runAsNonRoot": True, "fsGroup": 101},
            "volumes": [
                {"name": "config", "configMap": {"name": "streaming-ingress"}},
                {"name": "tls", "secret": {"secretName": inputs["tls_secret"]}},
                {"name": "tmp", "emptyDir": {}},
            ],
        },
    )
    ingress = service("streaming-ingress", "streaming-ingress", 8443)
    ingress["spec"]["ports"][0].update(port=443, targetPort=8443)
    # Only this Service can create public access. Idle lifetime exceeds the
    # gateway's 30s absolute request bound; TLS is terminated in the pinned proxy.
    ingress["spec"]["type"] = "LoadBalancer"
    ingress["spec"]["loadBalancerClass"] = "service.k8s.aws/nlb"
    ingress["spec"]["loadBalancerSourceRanges"] = source_ranges
    ingress["metadata"]["annotations"] = {
        "service.beta.kubernetes.io/aws-load-balancer-type": "external",
        "service.beta.kubernetes.io/aws-load-balancer-scheme": "internet-facing",
        "service.beta.kubernetes.io/aws-load-balancer-nlb-target-type": "instance",
        "service.beta.kubernetes.io/aws-load-balancer-target-node-labels": "m5-role=cpu",
        "service.beta.kubernetes.io/aws-load-balancer-listener-attributes.TCP-443": "tcp.idle_timeout.seconds=120",
        "service.beta.kubernetes.io/aws-load-balancer-attributes": "deletion_protection.enabled=false",
        "service.beta.kubernetes.io/aws-load-balancer-additional-resource-tags": "m5-session="
        + namespace,
    }
    service("telemetry", "telemetry", 9090)
    workload(
        "Deployment",
        "telemetry",
        1,
        [
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
                "securityContext": base_security,
                "volumeMounts": [
                    {"name": "config", "mountPath": "/etc/prometheus", "readOnly": True},
                    {"name": "data", "mountPath": "/data"},
                ],
                "resources": {
                    "requests": {"cpu": "100m", "memory": "128Mi"},
                    "limits": {"cpu": "500m", "memory": "512Mi"},
                },
            }
        ],
        {
            "serviceAccountName": "capture",
            "automountServiceAccountToken": True,
            "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "fsGroup": 65534},
            "volumes": [
                {"name": "config", "configMap": {"name": "telemetry"}},
                {"name": "data", "emptyDir": {"sizeLimit": "1Gi"}},
            ],
        },
    )
    output.extend(device_witness_resources(inputs))
    return {"apiVersion": "v1", "kind": "List", "items": output}


TEARDOWN_SCOPES = (
    "eks_clusters",
    "nodegroups",
    "instances",
    "volumes",
    "interfaces",
    "security_groups",
    "load_balancers",
    "target_groups",
    "public_ips",
    "log_groups",
    "ecr_repositories",
    "state_buckets",
    "bucket_versions",
    "lockfiles",
    "capacity_reservations",
    "capacity_groups",
    "vpc_endpoints",
    "nat_gateways",
    "vpcs",
)


def verify_teardown(receipt, *, session_id, after_ms):
    """Validate complete controller inventories; no live AWS calls here."""
    if (
        receipt.get("schema") != "m5-teardown-inventory-v1"
        or receipt.get("session_id") != session_id
    ):
        raise ValueError("teardown_identity_mismatch")
    if receipt.get("region") != "us-east-1" or receipt.get("destroy_status") != "succeeded":
        raise ValueError("teardown_destroy_or_region_unverified")
    inventories = receipt.get("inventories", {})
    if set(inventories) != set(TEARDOWN_SCOPES):
        raise ValueError("teardown_incomplete_inventory")
    for scope, inventory in inventories.items():
        if (
            inventory.get("complete") is not True
            or not inventory.get("command")
            or inventory.get("error") is not None
        ):
            raise ValueError("teardown_query_incomplete:" + scope)
        if type(inventory.get("observed_ms")) is not int or inventory["observed_ms"] < after_ms:
            raise ValueError("teardown_inventory_predates_destroy:" + scope)
        if inventory.get("resources") != []:
            # Terminated historical instances belong in a separate historical
            # record. No active inventory entry or retained storage is accepted.
            raise ValueError("teardown_resources_remain:" + scope)
    return {
        "verified": True,
        "session_id": session_id,
        "inventory_count": len(inventories),
        "aws_calls": 0,
        "basis": "supplied complete controller inventories; not an independently refreshed AWS account query",
    }


def render(inputs_path, output_path, runtime_path):
    config = json.loads(Path(inputs_path).read_text())
    result = resources(config, Path(runtime_path).read_text())
    Path(output_path).write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )
    return result


def smoke_snapshot(snapshot, inputs):
    """Read-only steady-state deployment checks; serving fitness is separate."""
    namespace = inputs["namespace"]
    items = snapshot["items"]
    pods = [o for o in items if o["kind"] == "Pod" and o["metadata"].get("namespace") == namespace]
    nodes = {o["metadata"]["name"]: o for o in items if o["kind"] == "Node"}
    if (
        len(
            [
                n
                for n in nodes.values()
                if n.get("status", {}).get("allocatable", {}).get("nvidia.com/gpu")
                not in (None, "0")
            ]
        )
        != 2
    ):
        raise ValueError("smoke_requires_exactly_two_gpu_nodes")
    backends = [p for p in pods if p["metadata"].get("labels", {}).get("app") == "vllm"]
    gateways = [p for p in pods if p["metadata"].get("labels", {}).get("app") == "gateway"]
    if len(backends) != 2 or len(gateways) != 2:
        raise ValueError("smoke_requires_two_backends_and_two_gateways")
    used_nodes = set()
    for pod in backends + gateways:
        if pod["metadata"].get("deletionTimestamp") or not pod["metadata"].get("uid"):
            raise ValueError("smoke_missing_or_terminating_uid")
        if not any(
            c.get("type") == "Ready" and c.get("status") == "True"
            for c in pod.get("status", {}).get("conditions", [])
        ):
            raise ValueError("smoke_pod_not_ready")
        if pod["spec"].get("hostNetwork"):
            raise ValueError("smoke_host_network_exposes_admin")
    for pod in backends:
        node_name = pod["spec"]["nodeName"]
        node = nodes[node_name]
        if node_name in used_nodes or node["metadata"]["labels"].get("m5-role") != "gpu":
            raise ValueError("smoke_gpu_placement")
        used_nodes.add(node_name)
        if node["status"]["allocatable"].get("nvidia.com/gpu") != "1" or not any(
            t.get("key") == "nvidia.com/gpu"
            and t.get("value") == "true"
            and t.get("effect") == "NoSchedule"
            for t in node["spec"].get("taints", [])
        ):
            raise ValueError("smoke_gpu_capacity_or_taint")
        container = next(c for c in pod["spec"]["containers"] if c["name"] == "vllm")
        if container["image"] != VLLM_IMAGE or any(
            container["resources"][mode].get("nvidia.com/gpu") != "1"
            for mode in ("requests", "limits")
        ):
            raise ValueError("smoke_runtime_pin_or_device_request")
        for argument in (MODEL, REVISION):
            if argument not in container["args"]:
                raise ValueError("smoke_model_pin")
        actual = next(
            c["imageID"] for c in pod["status"]["containerStatuses"] if c["name"] == "vllm"
        )
        accepted = {VLLM_IMAGE.split("@", 1)[1]}
        if inputs.get("vllm_platform_digest"):
            if not re.fullmatch(r"[0-9a-f]{64}", inputs["vllm_platform_digest"]):
                raise ValueError("smoke_invalid_platform_digest")
            accepted.add("sha256:" + inputs["vllm_platform_digest"])
        if not any(actual.endswith(digest) for digest in accepted):
            raise ValueError("smoke_unbound_runtime_image_id")
    services = [
        o for o in items if o["kind"] == "Service" and o["metadata"].get("namespace") == namespace
    ]
    external = []
    for service in services:
        spec = service["spec"]
        if spec.get("externalIPs"):
            raise ValueError("smoke_unexpected_external_ip")
        if spec.get("type", "ClusterIP") != "ClusterIP":
            external.append(service)
    if len(external) != 1 or external[0]["metadata"]["name"] != "streaming-ingress":
        raise ValueError("smoke_public_interface_boundary")
    public = external[0]
    if (
        public["spec"].get("loadBalancerClass") != "service.k8s.aws/nlb"
        or public["spec"].get("loadBalancerSourceRanges") != inputs["operator_cidrs"]
    ):
        raise ValueError("smoke_ingress_controller_or_ranges")
    if (
        public["metadata"]
        .get("annotations", {})
        .get("service.beta.kubernetes.io/aws-load-balancer-listener-attributes.TCP-443")
        != "tcp.idle_timeout.seconds=120"
    ):
        raise ValueError("smoke_ingress_idle_setting")
    return {
        "manifest_smoke_passed": True,
        "backend_count": 2,
        "gateway_count": 2,
        "distinct_gpu_nodes": 2,
        "serving_fitness": False,
        "aws_calls": 0,
        "remaining_live_checks": [
            "TLS incremental SSE and admin404",
            "both-gateway UID/direct route and cancellation",
            "discovery failure/recovery",
            "actual NLB attributes",
            "startup cold/node-cached clock/cache fitness",
        ],
    }
