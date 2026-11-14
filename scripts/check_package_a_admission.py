"""$0 R325 real two-gateway/Redis hold-down check, without a kind cluster."""

import argparse
import contextlib
import http.client
import json
import os
import subprocess
import time
import uuid
from dataclasses import replace
from pathlib import Path

from inference_platform.eks_deployment import REDIS_IMAGE
from inference_platform.fake_backend import FakeBackend, FakeBackendConfig
from inference_platform.inf037b_archive import IntegrityError
from inference_platform.inf037b_live import REDIS_SNAPSHOT, RedisWire
from inference_platform.package_a_cloud import save, sha, utc
from inference_platform.package_a_workload import preflight_manifest, write_kind_secret
from package_a_local_preflight import unused_port
from rehearse_eks_package_a import (
    admission_settings,
    admission_timing,
    read_stream,
    wait_admission_capacity,
)

ROOT = Path(__file__).resolve().parents[1]


def read_capacity_state(wire, namespace):
    """Pinned read-only snapshot; retain the existing flat HGETALL receipt shape."""
    prefix = namespace + ":{admission}:"
    snapshot = json.loads(
        wire.command(
            "EVAL",
            REDIS_SNAPSHOT,
            5,
            prefix + "capacity:reports",
            prefix + "capacity:lows",
            prefix + "capacity:state",
            prefix + "global:active",
            prefix + "global:active:capture:sequence",
        )
    )
    value = snapshot["state"]
    return value if isinstance(value, list) else []


def command(*args):
    return subprocess.check_output([str(arg) for arg in args], cwd=ROOT, timeout=120)


def check(output):
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    binary = output / ("gateway.exe" if os.name == "nt" else "gateway")
    command("go", "build", "-o", binary, "./cmd/gateway")
    manifest = preflight_manifest()
    rendered = admission_settings(manifest)
    name = "dec080-admission-" + uuid.uuid4().hex[:12]
    redis_port = unused_port()
    receipt = {
        "schema": "package-a-real-admission-v1",
        "started_at_utc": utc(),
        "complete": False,
        "billable_actions": 0,
        "kind_cluster_created": False,
        "source_base_commit": command("git", "rev-parse", "HEAD").decode().strip(),
        "rendered_admission_env": {
            k: v for k, v in rendered.items() if k.startswith("ADMISSION_")
        },
        "gateway_binary_sha256": sha(binary),
        "redis_image": REDIS_IMAGE,
        "no_wait_control": [],
        "admission_capacity": [],
        "waited_streams": [],
        "flap_env": rendered,
        "flap_timing": admission_timing(rendered),
        "flap_cycles": [],
        "source_sha256": {
            name: sha(ROOT / name)
            for name in (
                "scripts/check_package_a_admission.py",
                "scripts/rehearse_eks_package_a.py",
                "python/src/inference_platform/eks_deployment.py",
                "cmd/gateway/main.go",
                "internal/gateway/backend.go",
                "internal/admission/scripts/admit.lua",
            )
        },
        "scope": "Native real gateways and two in-process FakeBackends, isolated real Redis; no Kubernetes timing claim. Only discovery transport/address, local paths and gateway identities overridden; admission policy is rendered unchanged. Static registry reports every 500 ms (kind discovery registry 250 ms).",
    }
    processes = []
    try:
        command(
            "docker",
            "run",
            "-d",
            "--name",
            name,
            "--memory",
            "256m",
            "--memory-swap",
            "256m",
            "-p",
            f"127.0.0.1:{redis_port}:6379",
            REDIS_IMAGE,
        )
        with contextlib.ExitStack() as stack:
            wire = None
            end = time.monotonic() + 10
            while wire is None:
                try:
                    wire = RedisWire(
                        "127.0.0.1", redis_port, tls=False, local_test=True
                    )
                    assert len(wire.command("TIME")) == 2
                except (OSError, IntegrityError):
                    if wire is not None:
                        wire.close()
                        wire = None
                    if time.monotonic() >= end:
                        raise
                    time.sleep(0.02)
            stack.callback(wire.close)
            backends = [
                stack.enter_context(
                    FakeBackend(
                        FakeBackendConfig(
                            backend_id=f"vllm-{i}",
                            chunks=("a", "b", "c", "d"),
                            completion_tokens=4,
                            first_item_delay_ms=20,
                            chunk_delay_ms=50,
                        )
                    )
                )
                for i in (0, 1)
            ]
            write_kind_secret(output / "salt")
            env = {
                **{k: v for k, v in rendered.items() if v is not None},
                "REDIS_ADDR": f"127.0.0.1:{redis_port}",
                "TENANT_CONFIG_PATH": str(ROOT / "deploy/local/tenants.json"),
                "CACHE_SALT_SECRET_FILE": str(output / "salt"),
                "OTEL_SDK_DISABLED": "true",
                "BACKENDS": ",".join(
                    f"vllm-{i}={backend.base_url}" for i, backend in enumerate(backends)
                ),
            }
            for key in list(env):
                if key.startswith("BACKEND_DISCOVERY"):
                    del env[key]
            ports = []

            def stop():
                for process in processes:
                    if process.poll() is None:
                        process.terminate()
                    process.wait(timeout=15)

            stack.callback(stop)
            # Start both before waiting for either, minimizing the readyz/control gap.
            for i in (0, 1):
                port = unused_port()
                ports.append(port)
                log = stack.enter_context((output / f"gateway-{i}.log").open("wb"))
                process_env = {
                    **os.environ,
                    **env,
                    "GATEWAY_HTTP_ADDR": f"127.0.0.1:{port}",
                    "POD_UID": f"gateway-{i}-boot",
                    "ADMISSION_GATEWAY_ID": f"gateway-{i}",
                    "GATEWAY_MEASUREMENT_PATH": str(output / f"gateway-{i}.jsonl"),
                }
                processes.append(
                    subprocess.Popen(
                        [str(binary)],
                        cwd=ROOT,
                        env=process_env,
                        stdout=log,
                        stderr=subprocess.STDOUT,
                    )
                )

            for port in ports:
                end = time.monotonic() + 10
                while True:
                    connection = http.client.HTTPConnection(
                        "127.0.0.1", port, timeout=1
                    )
                    try:
                        connection.request("GET", "/readyz")
                        if connection.getresponse().status == 200:
                            break
                    except OSError:
                        pass
                    finally:
                        connection.close()
                    if time.monotonic() >= end or any(
                        p.poll() is not None for p in processes
                    ):
                        raise RuntimeError("gateway_not_ready")
                    time.sleep(0.01)
                # Exactly the harness request; no wait must demonstrate the real refusal.
                try:
                    read_stream(port, cafile=None)
                except AssertionError as exc:
                    status, body = exc.args[0]
                    code = json.loads(body)["error"]["code"]
                    assert status == 429 and code == "system_capacity", (status, body)
                    receipt["no_wait_control"].append(
                        {"gateway": ports.index(port), "status": status, "code": code}
                    )
                else:
                    raise AssertionError("no_wait_control_did_not_refuse")

            def capacity_state():
                fields = read_capacity_state(wire, env["ADMISSION_NAMESPACE"])
                return dict(zip(fields[::2], fields[1::2], strict=True))

            wait_admission_capacity(
                lambda remaining: capacity_state().get("n"),
                env,
                2,
                receipt["admission_capacity"],
            )
            for port in ports:
                receipt["waited_streams"].append(
                    {
                        "gateway": ports.index(port),
                        "status": 200,
                        **read_stream(port, cafile=None),
                    }
                )
            receipt["capacity_state"] = [
                item for pair in capacity_state().items() for item in pair
            ]
            for cycle in range(1, 6):
                record = {"cycle": cycle, "complete": False}
                receipt["flap_cycles"].append(record)
                backends[0]._server.config = replace(backends[0].config, healthy=False)
                record["unhealthy_at_utc"] = utc()
                record["lower_capacity"] = []
                wait_admission_capacity(
                    lambda remaining: capacity_state().get("n"),
                    rendered,
                    1,
                    record["lower_capacity"],
                )
                low_started = time.monotonic()
                time.sleep(3)
                record["low_hold_s"] = time.monotonic() - low_started
                record["healthy_at_utc"] = utc()
                restored = time.monotonic()
                backends[0]._server.config = replace(backends[0].config, healthy=True)
                record["restored_capacity"] = []
                wait_admission_capacity(
                    lambda remaining: capacity_state().get("n"),
                    rendered,
                    2,
                    record["restored_capacity"],
                )
                record["restoration_s"] = time.monotonic() - restored
                record["restored_at_utc"] = utc()
                record["complete"] = True
        receipt["gateway_cleanup_verified"] = all(
            p.poll() is not None for p in processes
        )
        receipt["complete"] = True
    finally:
        command("docker", "rm", "-f", name)
        receipt["redis_cleanup_verified"] = not command(
            "docker", "ps", "-aq", "--filter", "name=^/" + name + "$"
        ).strip()
        receipt["finished_at_utc"] = utc()
        save(output / "receipt.json", receipt)
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    print(json.dumps(check(parser.parse_args().output), sort_keys=True))
