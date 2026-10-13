"""Run the production SSM sh lists on Ubuntu 24.04, using real nohup and a dash-leading token."""

import argparse
import json
import subprocess
from pathlib import Path

SETUP = r"""set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update >/tmp/setup.log 2>&1
apt-get install -y python3 iproute2 procps >>/tmp/setup.log 2>&1
mkdir -p /test-bin /opt/r1 /etc/r1 /etc/systemd/system
touch /opt/r1/user-data.done
printf '9999999999\n' >/etc/r1/deadline_epoch
printf '#!/bin/sh\necho "{}"; exit 0\n' >/test-bin/cloud-init
printf '#!/bin/sh\necho "fixture SSM journal --token -fixture-secret"\n' >/test-bin/journalctl
cat >/test-bin/systemctl <<'SH'
#!/bin/sh
case "$1" in
 status|is-active|show) echo 'fixture: no r1-bootstrap unit'; exit 3;;
 *) exit 0;;
esac
SH
chmod +x /test-bin/*
export PATH=/test-bin:$PATH PYTHONPATH=/source/python/src
python3 /source/scripts/r1_ssm_rehearsal.py --inside
python3 -m unittest discover -s /source/python/tests -p test_r1_operator_shell.py -v
"""


def inside():
    import hashlib
    import http.client
    import time

    from inference_platform.r1_cloud_operator import (
        bootstrap_commands,
        host_diagnostic_commands,
    )

    source = Path("/source/scripts/r1-host-bootstrap.py").read_bytes()
    commands = bootstrap_commands(
        source, "-fixture-secret", "a" * 64, time.time() + 180
    )

    def shell(commands):
        result = subprocess.run(
            ["sh", "-c", "\n".join(commands)], capture_output=True, timeout=55
        )
        print(result.stdout.decode(), end="", flush=True)
        print(result.stderr.decode(), end="", flush=True)
        if result.returncode:
            raise RuntimeError("SSM sh command failed: " + str(result.returncode))
        return result.stdout

    def rpc(path, data=None):
        connection = http.client.HTTPConnection("127.0.0.1", 22280, timeout=5)
        headers = {"Authorization": "Bearer -fixture-secret"}
        if data:
            headers["X-Chunk-SHA256"] = hashlib.sha256(data).hexdigest()
        connection.request("GET" if data is None else "POST", path, data, headers)
        response = connection.getresponse()
        value = json.loads(response.read())
        connection.close()
        assert response.status == 200, value
        return value

    def stop():
        import os
        import signal

        result = subprocess.run(
            ["pgrep", "-f", r"^(/[^ ]*/)?python3 -B /opt/r1/bootstrap.py( |$)"],
            capture_output=True,
            timeout=3,
        )
        for value in result.stdout.split():
            pid = int(value)
            os.kill(pid, signal.SIGTERM)
            for _ in range(100):
                try:
                    if Path(f"/proc/{pid}/stat").read_text().split()[2] == "Z":
                        break
                except FileNotFoundError:
                    break
                time.sleep(0.02)
            else:
                raise RuntimeError("nohup process did not stop")

    try:
        shell(commands)
        assert rpc("/status")["bundle_sha256"] == "a" * 64
        chunk = b"R" * 1024**2
        assert rpc("/bundle/0", chunk)["offset"] == len(chunk)
        output = shell(host_diagnostic_commands())
        assert b"R1_BOOTSTRAP_HEALTH=running-listening" in output
        assert b"-fixture-secret" not in output
        pid = (
            subprocess.check_output(
                ["pgrep", "-f", r"^(/[^ ]*/)?python3 -B /opt/r1/bootstrap.py( |$)"]
            )
            .decode()
            .strip()
        )
        assert ("/proc/" + pid + "/cgroup").encode() in output
        # Restart the real nohup process with its existing /control.
        stop()
        shell(commands)
        assert rpc("/bundle")["offset"] == len(chunk)
        stop()
        output = shell(host_diagnostic_commands())
        assert output.startswith(b"R1_BOOTSTRAP_HEALTH=not-running")
        print(
            json.dumps(
                {
                    "sh_lists": "PASS",
                    "real_socket": True,
                    "chunk_bytes": len(chunk),
                    "restart_preserved_offset": True,
                    "token_redacted": True,
                    "launch": "real nohup; no r1-bootstrap unit",
                    "dash_leading_token": True,
                }
            )
        )
    finally:
        stop()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--inside", action="store_true")
    args = parser.parse_args()
    if args.inside:
        inside()
        return 0
    if not args.output:
        parser.error("--output required")
    args.output.mkdir(parents=True, exist_ok=False)
    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            str(Path.cwd()) + ":/source:ro",
            "ubuntu:24.04",
            "sh",
            "-c",
            SETUP,
        ],
        capture_output=True,
        timeout=300,
    )
    (args.output / "stdout.log").write_bytes(result.stdout)
    (args.output / "stderr.log").write_bytes(result.stderr)
    receipt = {
        "image": "ubuntu:24.04",
        "shell": "sh",
        "exit": result.returncode,
        "stubs": ["cloud-init", "systemctl (bootstrap unit absent)", "SSM journal"],
        "real": [
            "nohup launch",
            "Python bootstrap argparse with dash-leading token",
            "ss/iproute2",
            "ps/procps",
            "/proc cgroups",
            "loopback HTTP",
            "1 MiB chunk",
            "restart with existing /control",
        ],
    }
    (args.output / "receipt.json").write_bytes(
        (json.dumps(receipt, indent=2) + "\n").encode()
    )
    print(json.dumps(receipt))
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
