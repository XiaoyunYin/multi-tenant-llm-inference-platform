"""Launch the same-host gateway with the reviewed R0 environment, without a shell."""

import argparse
import json
import os
import subprocess
from pathlib import Path


def launch_gateway(binary: str, environment_json: Path, log):
    """Validate using the real binary, then return the directly owned gateway child."""
    environment = json.loads(environment_json.read_text(encoding="utf-8"))
    if not isinstance(environment, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in environment.items()
    ):
        raise ValueError("launcher environment must contain string keys and values")
    if environment.get("GATEWAY_FIRST_ITEM_TIMEOUT") != "120s":
        raise ValueError("r0-v2 requires the reviewed 120s first-item timeout")
    effective = {**os.environ, **environment}
    subprocess.run(
        [binary, "--check-config"],
        env=effective,
        check=True,
        timeout=10,
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    return subprocess.Popen([binary], env=effective, stdout=log, stderr=subprocess.STDOUT)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--environment-json", type=Path, required=True)
    parser.add_argument("--gateway-binary", required=True)
    args = parser.parse_args()
    environment = json.loads(args.environment_json.read_text(encoding="utf-8"))
    if not isinstance(environment, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in environment.items()
    ):
        parser.error("launcher environment must contain string keys and values")
    if environment.get("GATEWAY_FIRST_ITEM_TIMEOUT") != "120s":
        parser.error("r0-v2 requires the reviewed 120s first-item timeout")
    effective = {**os.environ, **environment}
    subprocess.run([args.gateway_binary, "--check-config"], env=effective, check=True, timeout=10)
    os.execve(args.gateway_binary, [args.gateway_binary], effective)


if __name__ == "__main__":
    main()
