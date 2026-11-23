"""Streaming-only Kubernetes changes layered over the DEC-100 manifests."""

import json
from copy import deepcopy

from .inf060_eks_clock import PORT

CLIENT_LABELS = {"app": "load-client", "inf060-role": "streaming-client"}


def serving_resources(source, client_image, logging_config):
    resources = deepcopy(source)
    engine = next(
        item
        for item in resources["items"]
        if item["kind"] == "StatefulSet" and item["metadata"]["name"] == "vllm"
    )
    namespace = engine["metadata"]["namespace"]
    gateway = next(
        item
        for item in resources["items"]
        if item["kind"] == "StatefulSet" and item["metadata"]["name"] == "gateway"
    )
    gateway["spec"]["template"]["spec"]["containers"][0]["env"].append(
        {"name": "GATEWAY_INF060_OBSERVATIONS", "value": "true"}
    )
    metadata = {"name": "inf060-clock", "namespace": namespace}
    pod = engine["spec"]["template"]["spec"]
    vllm = pod["containers"][0]
    vllm["args"] += ["--enable-log-requests", "--max-log-len", "0"]
    vllm["env"] += [
        {"name": "VLLM_LOGGING_CONFIG_PATH", "value": "/logging/config.json"},
        {"name": "VLLM_LOGGING_LEVEL", "value": "INFO"},
        {"name": "VLLM_LOGGING_COLOR", "value": "0"},
        {"name": "NO_COLOR", "value": "1"},
        {"name": "TZ", "value": "UTC"},
    ]
    vllm["volumeMounts"].append({"name": "logging", "mountPath": "/logging", "readOnly": True})
    pod["volumes"].append({"name": "logging", "configMap": {"name": metadata["name"]}})
    pod["containers"].append(
        {
            "name": "clock-server",
            "image": client_image,
            "command": ["python", "-m", "inference_platform.inf060_eks_clock"],
            "env": [{"name": "POD_UID", "valueFrom": {"fieldRef": {"fieldPath": "metadata.uid"}}}],
            "ports": [{"name": "inf060-clock", "containerPort": PORT}],
            "readinessProbe": {
                "exec": {
                    "command": [
                        "python",
                        "-c",
                        f"import socket; socket.create_connection(('127.0.0.1', {PORT}), timeout=0.5).close()",
                    ],
                },
                "periodSeconds": 2,
            },
            "resources": {
                "requests": {"cpu": "25m", "memory": "32Mi"},
                "limits": {"cpu": "200m", "memory": "64Mi"},
            },
            "securityContext": {
                "runAsNonRoot": True,
                "runAsUser": 65532,
                "readOnlyRootFilesystem": True,
                "allowPrivilegeEscalation": False,
                "capabilities": {"drop": ["ALL"]},
            },
        }
    )
    resources["items"] += [
        {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": metadata,
            "immutable": True,
            "data": {"config.json": logging_config},
        },
        {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": metadata,
            "spec": {
                "podSelector": {"matchLabels": {"app": "vllm"}},
                "policyTypes": ["Ingress"],
                "ingress": [
                    {"ports": [{"protocol": "TCP", "port": 8000}]},
                    {
                        "ports": [{"protocol": "TCP", "port": PORT}],
                        "from": [{"podSelector": {"matchLabels": CLIENT_LABELS}}],
                    },
                ],
            },
        },
    ]
    return resources


def client_job(source, settings):
    result = deepcopy(source)
    template = next(item for item in result["items"] if item["kind"] == "Job")["spec"]["template"]
    template["metadata"]["labels"].update(CLIENT_LABELS)
    pod = template["spec"]
    client = pod["containers"][0]
    client["command"] = ["python", "-u", "-m", "inference_platform.inf060_eks_client", "serve"]
    client["env"].append({"name": "INF060_SETTINGS", "value": json.dumps(settings, sort_keys=True)})
    # Keep the journal readable after the client container exits. This
    # container sees only the results volume, without the client credentials.
    pod["containers"].append(
        {
            "name": "result-reader",
            "image": client["image"],
            "command": ["python", "-c", "import time; time.sleep(86400)"],
            "resources": {
                "requests": {"cpu": "10m", "memory": "16Mi"},
                "limits": {"cpu": "100m", "memory": "64Mi"},
            },
            "securityContext": client["securityContext"],
            "volumeMounts": [{"name": "results", "mountPath": "/results", "readOnly": True}],
        }
    )
    return result
