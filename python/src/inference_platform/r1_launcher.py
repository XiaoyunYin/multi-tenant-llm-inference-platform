"""Exact local launch plans; no cloud API, image pull or launch on import."""

import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path

from .r1_manifest import tenant_salt
from .r1_spec import GATEWAY_FIXED, IMAGE, MODEL, REVISION, encoded, engine_argv


def backend_command(cache_path, port=8000):
    if not Path(cache_path).is_absolute() or port != 8000:
        raise ValueError("pre-staged absolute weight cache and fixed backend port required")
    return [
        "docker",
        "run",
        "--rm",
        "--name",
        "r1-vllm",
        "--gpus",
        "all",
        "--ipc=host",
        "--publish",
        "8000:8000",
        "--publish",
        "5557:5557",
        "--volume",
        f"{cache_path}:/root/.cache/huggingface",
        "--env",
        "VLLM_SERVER_DEV_MODE=1",
        IMAGE,
        "--model",
        MODEL,
        "--revision",
        REVISION,
        *engine_argv()[:-2],
        "--kv-events-config",
        '{"enable_kv_cache_events":true,"publisher":"zmq","endpoint":"tcp://*:5557","topic":"kv-events"}',
        *engine_argv()[-2:],
        "--host",
        "0.0.0.0",
        "--port",
        "8000",
    ]


def gateway_environment(
    directory, inventory, redis_address, namespace, credential, secret, policy, r, w, b, seed, index
):
    if len(inventory) != 2 or index not in (0, 1) or policy not in {"hash", "ll", "rr"}:
        raise ValueError("R1 requires exactly two backends/gateways and a registered policy")
    if r not in (1, 2, 4, 8, 12, 16, 24, 32) or w not in (1, 2, 4) or b != 2 * (r + w):
        raise ValueError("incompatible calibrated admission inputs")
    if seed not in (4242, 4243, 4244) or len(secret) != 32 or not credential:
        raise ValueError("invalid seed/tenant credential/cache secret")
    import base64

    directory = Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    secret_path = directory / "cache-salt.secret"
    secret_path.write_text(base64.urlsafe_b64encode(secret).decode().rstrip("=") + "\n")
    tenant = {
        "tenant_id": "r1-synthetic",
        "credential_sha256": hashlib.sha256(credential.encode()).hexdigest(),
        "models": [MODEL],
        "max_request_bytes": 1048576,
        "max_output_tokens": 1,
        "request_rate_limit": 1000000,
        "request_rate_window_ms": 1000,
        "max_concurrent": b,
    }
    tenant_path = directory / "tenants.json"
    tenant_path.write_bytes(encoded({"tenants": [tenant]}) + b"\n")
    return {
        **GATEWAY_FIXED,
        "BACKENDS": ",".join(
            f"{item['id']}@{item['generation']}={item['url']}" for item in inventory
        ),
        "GATEWAY_HTTP_ADDR": f":{8080 + index}",
        "REDIS_ADDR": redis_address,
        "ADMISSION_NAMESPACE": namespace,
        "ADMISSION_GLOBAL_CAPACITY": str(b),
        "GATEWAY_MAX_CONCURRENT": str(b),
        "TENANT_CONFIG_PATH": str(tenant_path),
        "CACHE_SALT_SECRET_FILE": str(secret_path),
        "GATEWAY_ROUTING_SEED": str(seed),
        "GATEWAY_ROUTING_POLICY": {
            "hash": "hash_affinity",
            "ll": "least_loaded",
            "rr": "round_robin",
        }[policy],
    }


def launch_gateways(
    binary,
    directory,
    inventory,
    redis_address,
    namespace,
    credential,
    secret,
    policy,
    r,
    w,
    b,
    seed,
    deadline,
):
    import time

    processes, receipts = [], []
    try:
        for index in range(2):
            environment = gateway_environment(
                directory,
                inventory,
                redis_address,
                namespace,
                credential,
                secret,
                policy,
                r,
                w,
                b,
                seed,
                index,
            )
            # Do not inherit unrelated gateway/admission/hash overrides from the shell.
            clean = {
                key: value
                for key, value in os.environ.items()
                if not key.startswith(("GATEWAY_", "BACKEND_", "ADMISSION_", "REDIS_", "OTEL_"))
            }
            environment = {**clean, **environment}
            subprocess.run(
                [str(binary), "--check-config"],
                env=environment,
                check=True,
                capture_output=True,
                timeout=max(0.001, deadline - time.perf_counter()),
            )
            log_path = Path(directory) / f"gateway-{index}.jsonl"
            with log_path.open("ab") as log:
                log_start_offset = log.tell()
                process = subprocess.Popen(
                    [str(binary)], env=environment, stdout=log, stderr=subprocess.STDOUT
                )
            processes.append(process)
            receipts.append(
                {
                    "pid": process.pid,
                    "binary_sha256": hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
                    "environment": {
                        key: environment[key]
                        for key in (
                            *GATEWAY_FIXED,
                            "BACKENDS",
                            "GATEWAY_HTTP_ADDR",
                            "ADMISSION_NAMESPACE",
                            "ADMISSION_GLOBAL_CAPACITY",
                            "GATEWAY_MAX_CONCURRENT",
                            "GATEWAY_ROUTING_SEED",
                            "GATEWAY_ROUTING_POLICY",
                        )
                    },
                    "tenant_config_sha256": hashlib.sha256(
                        (Path(directory) / "tenants.json").read_bytes()
                    ).hexdigest(),
                    "cache_salt": tenant_salt(secret),
                    "log": str(log_path),
                    "log_start_offset": log_start_offset,
                }
            )
        return processes, receipts
    except BaseException:
        for process in processes:
            process.terminate()
        raise


def main():
    parser = argparse.ArgumentParser(
        description="Print exact R1 backend launch argv; never launch it."
    )
    parser.add_argument("--weight-cache", required=True)
    args = parser.parse_args()
    print(json.dumps(backend_command(args.weight_cache)))


if __name__ == "__main__":
    main()
