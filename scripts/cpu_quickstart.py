"""Run and clean up a loopback-only CPU streaming demo."""

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from contextlib import ExitStack
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
LOCAL = ROOT / "deploy/local"


def command(*args, **options):
    return subprocess.run(args, cwd=ROOT, check=True, timeout=300, **options)


def cleanup(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def wait(process, check, name):
    end = time.monotonic() + 25
    while time.monotonic() < end:
        if process is not None and process.poll() is not None:
            raise RuntimeError(f"{name} exited with status {process.returncode}")
        if check():
            return
        time.sleep(0.2)
    raise TimeoutError(f"{name} readiness deadline")


def healthy(url):
    try:
        with urllib.request.urlopen(url, timeout=0.5) as response:
            return response.status == 200
    except (OSError, urllib.error.URLError):
        return False


def main():
    redis_image = yaml.safe_load((LOCAL / "compose.yaml").read_bytes())["services"][
        "redis"
    ]["image"]
    with (
        tempfile.TemporaryDirectory(prefix="mti-quickstart-") as name,
        ExitStack() as stop,
    ):
        work = Path(name)
        gateway = work / ("gateway.exe" if os.name == "nt" else "gateway")
        command("go", "build", "-p", "2", "-o", str(gateway), "./cmd/gateway")
        redis = "mti-quickstart-" + uuid.uuid4().hex[:12]
        # Register cleanup before starting the container, including a failed start.
        stop.callback(
            subprocess.run,
            ["docker", "rm", "-f", redis],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=20,
        )
        command(
            "docker",
            "run",
            "-d",
            "--name",
            redis,
            "-p",
            "127.0.0.1::6379",
            redis_image,
            "redis-server",
            "--save",
            "",
            "--appendonly",
            "no",
            stdout=subprocess.DEVNULL,
        )
        endpoint = command(
            "docker", "port", redis, "6379/tcp", capture_output=True, text=True
        ).stdout.strip()
        if not endpoint.startswith("127.0.0.1:") or not endpoint[10:].isdigit():
            raise ValueError("unexpected Redis port binding")
        wait(
            None,
            lambda: (
                subprocess.run(
                    ["docker", "exec", redis, "redis-cli", "--raw", "ping"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                ).stdout.strip()
                == "PONG"
            ),
            "Redis",
        )
        ready = work / "fake-ready.json"
        fake = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "inference_platform.fake_backend",
                "--config",
                str(LOCAL / "fake-backend-a.json"),
                "--host",
                "127.0.0.1",
                "--ready-file",
                str(ready),
            ],
            cwd=ROOT,
        )
        stop.callback(cleanup, fake)
        wait(fake, ready.is_file, "CPU backend")
        backend = json.loads(ready.read_bytes())
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            gateway_addr = f"127.0.0.1:{listener.getsockname()[1]}"
        salt = work / "cache-salt.secret"
        shutil.copyfile(LOCAL / "cache-salt.secret.example", salt)
        env = {
            **os.environ,
            "ADMISSION_MODE": "redis",
            "ADMISSION_NAMESPACE": redis,
            "BACKENDS": f"{backend['backend_id']}={backend['url']}",
            "CACHE_SALT_SECRET_FILE": str(salt),
            "GATEWAY_HTTP_ADDR": gateway_addr,
            "GATEWAY_ROUTING_POLICY": "round_robin",
            "REDIS_ADDR": endpoint,
            "TENANT_CONFIG_PATH": str(LOCAL / "tenants.json"),
        }
        service = subprocess.Popen([gateway], cwd=ROOT, env=env)
        stop.callback(cleanup, service)
        url = "http://" + gateway_addr
        wait(service, lambda: healthy(url + "/readyz"), "Go gateway")
        curl = "curl.exe" if os.name == "nt" else "curl"
        result = command(
            curl,
            "--fail-with-body",
            "--silent",
            "--show-error",
            "--no-buffer",
            "--max-time",
            "15",
            "-H",
            "Authorization: Bearer local-dev-token",
            "-H",
            "Content-Type: application/json",
            "--data-binary",
            "@-",
            url + "/v1/chat/completions",
            input=json.dumps(
                {
                    "model": "test-model",
                    "messages": [{"role": "user", "content": "Say hello."}],
                    "stream": True,
                    "max_tokens": 8,
                }
            ),
            capture_output=True,
            text=True,
        )
        if not result.stdout.rstrip().endswith("data: [DONE]"):
            raise ValueError("stream did not end with [DONE]")
        print(result.stdout.rstrip())


if __name__ == "__main__":
    main()
