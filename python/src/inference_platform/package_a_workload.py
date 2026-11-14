"""Offline inputs and receipt validation for the Package A workload preflight."""

import hashlib
import json
import shutil
from pathlib import Path

from inference_platform.eks_deployment import NGINX_IMAGE, resources

ROOT = Path(__file__).resolve().parents[3]


def write_kind_secret(path):
    path.write_bytes((ROOT / "deploy/local/cache-salt.secret.example").read_bytes())


def test_tls_command(directory):
    """Use explicit local config; Windows OpenSSL may have no installed default."""
    config = directory / "openssl.cnf"
    config.write_text("[req]\ndistinguished_name=dn\n[dn]\n")
    openssl = shutil.which("openssl") or "C:/Program Files/Git/usr/bin/openssl.exe"
    return [
        openssl,
        "req",
        "-config",
        config,
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        directory / "tls.key",
        "-out",
        directory / "tls.crt",
        "-subj",
        "/CN=localhost",
        "-days",
        "1",
    ]


def preflight_manifest():
    model = {"config.json": {"bytes": 3, "sha256": hashlib.sha256(b"{}\n").hexdigest()}}
    inputs = {
        "crictl_host_path": "/usr/bin/crictl",
        "crictl_sha256": "c" * 64,
        "model_manifest_sha256": hashlib.sha256(
            json.dumps(model, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "model_manifest": model,
        "operator_cidrs": ["192.0.2.1/32"],
        "namespace": "mti-m5-package-a",
        "gateway_image": "example.invalid/gateway@sha256:" + "a" * 64,
        "config_sha256": "b" * 64,
        "tls_secret": "gateway-tls",
        "r": 4,
        "w": 1,
    }
    return resources(inputs, (ROOT / "deploy/eks/capture_runtime.py").read_text())


def workload_objects(manifest):
    return {(o["kind"], o["metadata"]["name"]): o for o in manifest["items"]}


def validate_workload_preflight(receipt):
    gateway = receipt.get("gateway_config", {})
    nginx = receipt.get("nginx_start", {})
    name = nginx.get("container_name")
    command = nginx.get("start", {}).get("command", [])
    if (
        gateway.get("exit_code") != 0
        or gateway.get("complete") is not True
        or gateway.get("command", [None])[-1] != "--check-config"
        or nginx.get("complete") is not True
        or nginx.get("running") is not True
        or nginx.get("https_status") != 404
        or nginx.get("container_removed") is not True
        or not isinstance(name, str)
        or not name.startswith("dec077-nginx-")
        or nginx.get("cleanup", {}).get("command") != ["docker", "rm", "-f", name]
        or nginx.get("cleanup", {}).get("exit_code") != 0
        or nginx.get("start", {}).get("exit_code") != 0
        or command[:3] != ["docker", "run", "--detach"]
        or "--read-only" not in command
        or "--user" not in command
        or command[command.index("--user") + 1] != "101:101"
        or "--tmpfs" not in command
        or command[command.index("--tmpfs") + 1] != "/tmp:rw,noexec,nosuid,size=64m,uid=101,gid=101"
        or command.count("--tmpfs") != 1
        or command.count("--mount") != 2
        or any(
            not command[i + 1].endswith(",readonly")
            for i, v in enumerate(command)
            if v == "--mount"
        )
        or command[-4:] != [NGINX_IMAGE, "nginx", "-g", "daemon off;"]
    ):
        raise ValueError("workload_preflight_incomplete")
    return gateway, nginx
