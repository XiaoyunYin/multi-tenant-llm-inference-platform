#!/usr/bin/python3
"""Only the explicitly enumerated scratch-host/GPU substitutions. No AWS access."""

import json
import os
import select
import socket
import socketserver
import subprocess
import sys
import threading
import time
from pathlib import Path

from_name = Path(sys.argv[0]).name
args = sys.argv[1:]


def proxy():
    class Forward(socketserver.BaseRequestHandler):
        def handle(self):
            with socket.create_connection(("127.0.0.1", 22280)) as remote:
                peers = [self.request, remote]
                while True:
                    readable, _, _ = select.select(peers, [], [], 5)
                    for source in readable:
                        data = source.recv(1024**2)
                        if not data:
                            return
                        (remote if source is self.request else self.request).sendall(
                            data
                        )

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    Server(("0.0.0.0", 22281), Forward).serve_forever()


if from_name == "systemctl":
    # Systemd/cloud-init and the independent EC2 termination timer do not exist
    # in this disposable container; these answers are never native evidence.
    raise SystemExit(0)
elif from_name == "nvidia-smi":
    print(
        "name, uuid, memory.total, driver_version\nL4 REHEARSAL, FAKE, 23034 MiB, FAKE"
    )
elif from_name == "docker":
    # Every non-vLLM command, including Redis/nginx pulls and lifecycle, goes
    # unchanged to a real nested Docker daemon.
    sys.path.insert(0, "/opt/dec077/repo/python/src")
    from inference_platform.l4_compat import PINS

    if PINS["vllm"] in args:
        if args[0] in ("pull", "image"):
            if args[0] == "image":
                print(
                    json.dumps(
                        {
                            "substitution": "GPU image is not installed",
                            "pin": PINS["vllm"],
                        }
                    )
                )
            raise SystemExit(0)
        if args[0] != "run":
            raise RuntimeError("unexpected_gpu_command")
        index = args.index(PINS["vllm"])
        mode = args[-1]
        if mode not in ("stage", "serve"):
            raise RuntimeError("unexpected_gpu_mode")
        options = args[:index]
        for flag in ("--gpus", "--pid", "--ipc", "--entrypoint"):
            if flag in options:
                at = options.index(flag)
                del options[at : at + 2]
        args = [
            *options,
            "--entrypoint",
            "/packet/.tools/python/bin/python3.12",
            "ubuntu:24.04",
            "/packet/scripts/l4_compat_fake_engine.py",
            mode,
        ]
    os.execv("/usr/bin/docker-real", ["docker-real", *args])
elif args == ["init"]:
    # Run real cloud-init against a local-only NoCloud seed. No EC2 datasource
    # or metadata discovery is enabled in this $0 host.
    Path("/etc/cloud/cloud.cfg").write_text(
        "datasource_list: [NoCloud]\nnetwork: {config: disabled}\n"
        "cloud_init_modules: []\ncloud_config_modules: []\ncloud_final_modules: []\n"
    )
    seed = Path("/var/lib/cloud/seed/nocloud")
    seed.mkdir(parents=True)
    (seed / "meta-data").write_text("instance-id: l4-rehearsal-local\n")
    (seed / "user-data").write_text("#cloud-config\n{}\n")
    for command in (
        ["cloud-init", "init", "--local"],
        ["cloud-init", "init"],
        ["cloud-init", "modules", "--mode=config"],
        ["cloud-init", "modules", "--mode=final"],
    ):
        subprocess.run(command, check=True, timeout=30)
    Path("/opt/dec077").mkdir(parents=True)
    Path("/etc/dec077").mkdir(parents=True)
    Path("/opt/dec077/user-data.done").touch()
    Path("/etc/dec077/deadline").write_text(str(int(time.time()) + 3600))
    daemon = subprocess.Popen(
        ["dockerd", "--storage-driver=vfs", "--iptables=false", "--bridge=none"],
        stdout=open("/dockerd.log", "wb"),
        stderr=subprocess.STDOUT,
    )
    for _ in range(150):
        if subprocess.run(["docker-real", "info"], capture_output=True).returncode == 0:
            break
        if daemon.poll() is not None:
            raise RuntimeError(Path("/dockerd.log").read_text())
        time.sleep(0.2)
    else:
        raise TimeoutError("nested_docker")
    threading.Thread(target=proxy, daemon=True).start()
    daemon.wait()
else:
    raise RuntimeError("unexpected_rehearsal_host_command")
