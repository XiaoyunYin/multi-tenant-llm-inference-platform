"""No-AWS clean Linux rehearsal of the production bootstrap and both control paths."""

import argparse
import hashlib
import json
import os
import selectors
import shutil
import signal
import socket
import socketserver
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path
from unittest.mock import patch

MINIMAL = {
    "PATH": "/opt/round58-venv/bin:/usr/local/bin:/usr/bin:/bin",
    "HOME": "/tmp",
    "LANG": "C.UTF-8",
}
STEPS = (
    "before_bootstrap",
    "server_started",
    "payload_put",
    "fake_readiness",
    "capture_started",
    "forward_status",
    "command_status",
    "server_killed",
    "command_restart",
    "restarted_forward_status",
    "restarted_command_status",
    "worker_finished",
)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def shell(command):
    return subprocess.run(
        ["env", "-i", *[f"{k}={v}" for k, v in MINIMAL.items()], "sh", "-c", command],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )


def inside():
    assert "PYTHONDONTWRITEBYTECODE" not in os.environ
    payload, output = Path("/input"), Path("/output")
    manifest = json.loads((payload / "staging-manifest.json").read_text())
    # The driver imports a separate scratch copy, never the installed staged tree.
    shutil.copytree(payload / "sources/python/src", "/scratch")
    sys.path.insert(0, "/scratch")
    from inference_platform.stage_c_session import (
        bootstrap_commands,
        disk_snapshot,
        host_status,
        load_identity,
        sidecar,
        verify_sources,
        write_json,
    )
    from inference_platform.stage_c_transport import (
        CommandChannel,
        ReconnectingTransport,
        command_batches,
        monitor_and_export,
    )

    destination = Path("/opt/inf011/reviewed")
    destination.parent.mkdir(parents=True)
    # Local pre-pull baseline, before worker measurement; no operator probe loop.
    write_json(
        destination.parent / "disk-before-pull.json", disk_snapshot(refresh=True)
    )
    Path("/etc/inf011").mkdir(parents=True)
    termination = int(time.time() + 300)
    Path("/etc/inf011/deadline_epoch").write_text(str(termination))
    nonce, port = "local-clean-remote-fixture", 22280
    source = (payload / "sources" / manifest["entrypoint"]["path"]).read_bytes()
    commands = bootstrap_commands(
        source,
        sha(payload / "staging-manifest.json"),
        manifest,
        str(destination),
        nonce,
        port,
        rehearse=True,
    )
    checkpoints = []

    def check(step):
        verify_sources(payload / "sources", manifest)
        tree = destination / "sources" if destination.exists() else payload / "sources"
        verify_sources(tree, manifest)
        actual = {
            p.relative_to(tree).as_posix(): sha(p)
            for p in tree.rglob("*")
            if p.is_file()
        }
        assert actual == {row["path"]: row["sha256"] for row in manifest["files"]}
        checkpoints.append(
            {
                "step": step,
                "tree": "staged" if destination.exists() else "bundle",
                "files_sha256": actual,
            }
        )

    def http(path, data=None, forward_port=port):
        request = urllib.request.Request(
            f"http://127.0.0.1:{forward_port}{path}",
            data=data,
            method="PUT" if data is not None else "GET",
            headers={"Authorization": nonce},
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            return json.load(response)

    def wait_status():
        limit = time.perf_counter() + 15
        while time.perf_counter() < limit:
            try:
                return http("/status")
            except OSError:
                time.sleep(0.05)
        raise TimeoutError("server unavailable")

    class Forward(socketserver.BaseRequestHandler):
        def handle(self):
            with socket.create_connection(("127.0.0.1", port), timeout=5) as upstream:
                with selectors.DefaultSelector() as selector:
                    selector.register(self.request, selectors.EVENT_READ, upstream)
                    selector.register(upstream, selectors.EVENT_READ, self.request)
                    while True:
                        ready = selector.select(5)
                        if not ready:
                            return
                        for key, _ in ready:
                            data = key.fileobj.recv(65536)
                            if not data:
                                return
                            key.data.sendall(data)

    # Substitute only the SSM delivery adapter. Execute the real generated shell
    # command, staged command module, status/diagnostics and restart on Linux.
    channel_commands = []

    def local_ssm(_aws, _instance, command_list, _deadline, _session, _attempts):
        channel_commands.extend(command_list)
        return {
            "StandardOutputContent": shell("set -eu\n" + "\n".join(command_list)).stdout
        }

    outcome = {"ssm_command_attempts": []}
    channel = CommandChannel(
        None, "local-no-aws", str(destination), port, output, outcome
    )
    proxy = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Forward)
    proxy.daemon_threads = True
    threading.Thread(target=proxy.serve_forever, daemon=True).start()

    class LocalForward:
        def poll(self):
            return None

    transport = ReconnectingTransport(
        LocalForward,
        f"http://127.0.0.1:{proxy.server_address[1]}",
        nonce,
        time.perf_counter() + 180,
        [],
        stop=lambda _: None,
    )
    try:
        check("before_bootstrap")
        for batch in command_batches(commands):
            shell("set -eu\n" + "\n".join(batch))
        assert wait_status()["started"] is False
        check("server_started")
        assert (
            http("/payload", (payload / "payload.tar.gz").read_bytes())["status"]
            == "started"
        )
        check("payload_put")
        identity = load_identity(destination / "controller-pid.json")
        limit = time.perf_counter() + 120
        readiness = destination / "session/readiness-wait.json"
        while not readiness.exists() and time.perf_counter() < limit:
            if host_status(destination, termination)["finished"]:
                raise AssertionError((destination / "controller.log").read_text())
            time.sleep(0.1)
        assert json.loads(readiness.read_text())["status"] == "ready"
        assert (
            json.loads((destination / "session/staging-verification.json").read_text())[
                "status"
            ]
            == "verified"
        )
        check("fake_readiness")
        capture_file = destination / "capture-private/session/kv-event-capture.json"
        capture_limit = time.perf_counter() + 30
        config_file = destination / "session/runtime-config-sanitized.json"
        while time.perf_counter() < capture_limit:
            if config_file.exists():
                config = json.loads(config_file.read_text())
                capture_file = Path(config["kv_capture_output_path"])
                decisions = Path(config["decision_export_output_path"])
                if (
                    decisions.exists()
                    and (destination / "session/fake-events.jsonl").exists()
                ):
                    break
            time.sleep(0.1)
        assert decisions.exists()
        assert decisions.parent == capture_file.parent
        assert "capture-private" in capture_file.parts
        assert (destination / "session/fake-events.jsonl").exists()
        check("capture_started")
        forward = json.loads(transport.get("/status"))
        assert forward["started"] and transport.last_channel == "forward"
        check("forward_status")
        with patch("inference_platform.stage_c_transport.ssm_commands", local_ssm):
            snapshot = json.loads(
                channel.request(
                    "/status", time.perf_counter() + 30, transport=transport
                )
            )
            assert snapshot["started"]
            check("command_status")
            server_identity = load_identity(sidecar(destination, ".server-pid.json"))
            os.kill(server_identity["pid"], signal.SIGKILL)
            time.sleep(0.1)
            check("server_killed")
            result = channel.call("restart", time.perf_counter() + 30)
            assert result["host_controller_restarted"] is False
            assert wait_status()["started"]
            assert load_identity(destination / "controller-pid.json") == identity
            check("command_restart")
            assert json.loads(transport.get("/status"))["started"]
            check("restarted_forward_status")
            assert json.loads(
                channel.request(
                    "/status", time.perf_counter() + 30, transport=transport
                )
            )["started"]
            check("restarted_command_status")
        while (
            not host_status(destination, termination)["finished"]
            and time.perf_counter() < limit
        ):
            time.sleep(0.1)
        assert host_status(destination, termination)["finished"]
        assert (
            json.loads((destination / "session/controller-exit.json").read_text())[
                "returncode"
            ]
            == 0
        )
        check("worker_finished")
        operator = output / "controller-export"
        operator.mkdir()
        # Local fixture allowance; the real controller uses persisted termination.
        transport.deadline = time.perf_counter() + 900
        monitor_and_export(transport, operator, outcome)
        final_status = json.loads(transport.get("/status"))
        disk_records = final_status["disk_records"]
        assert len(disk_records) == 6
        assert final_status["sampled_root_minimum_free_bytes"] > 0
        assert len(list((operator / "sealed-runs").glob("run-[1-4].tar.gz"))) == 4
        assert outcome["export_verified"] and not outcome.get("unfetched_full_runs")
        for name, record in disk_records.items():
            assert json.loads((operator / name).read_text()) == record
        check("controller_archives_and_disk_export")
        return {
            "status": "passed",
            "initial_environment": MINIMAL,
            "inherited_bytecode_variable": False,
            "bootstrap_commands_sha256": hashlib.sha256(
                json.dumps(commands).encode()
            ).hexdigest(),
            "bootstrap_launch_command": commands[-1],
            "bootstrap_command_count": len(commands),
            "command_channel_commands": channel_commands,
            "checkpoints": checkpoints,
            "same_worker_identity_after_restart": True,
            "fake_readiness": "ready",
            "shared_capture_started": True,
            "worker_returncode": 0,
            "controller_disk_records_via_status": len(disk_records),
            "sampled_root_minimum_free_bytes": final_status[
                "sampled_root_minimum_free_bytes"
            ],
            "archive_export_window": outcome["archive_export_window"],
            "operator_send_commands_during_measurement": 0,
            "operator_probe_scripts": 0,
            "aws_calls_made": False,
            "basis": "Fresh network-disabled Linux container; actual TCP relay and local shell delivery of command-channel commands; no SSM service or GPU",
        }
    finally:
        proxy.shutdown()
        proxy.server_close()
        for name in (
            sidecar(destination, ".server-pid.json"),
            destination / "controller-pid.json",
        ):
            identity = load_identity(name)
            if identity:
                try:
                    os.kill(identity["pid"], signal.SIGTERM)
                except ProcessLookupError:
                    pass
        for name in (
            "stage-c-artifact.json",
            "readiness-wait.json",
            "controller-exit.json",
            "staging-verification.json",
        ):
            path = destination / "session" / name
            if path.exists():
                shutil.copyfile(path, output / name)
        if (destination / "controller.log").exists():
            shutil.copyfile(destination / "controller.log", output / "controller.log")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inside", action="store_true")
    parser.add_argument("--payload", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--image", default="inf-round58-cpu:b85f48c")
    args = parser.parse_args()
    if args.inside:
        Path("/output/proof.json").write_text(json.dumps(inside(), indent=2) + "\n")
        return
    args.payload = args.payload.resolve()
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--cpus",
            "2",
            "--memory",
            "6g",
            "--workdir",
            "/workspace",
            "--mount",
            f"type=bind,source={Path(__file__).resolve().parents[1] / '.cache/pinned-tokenizer'},target=/workspace/.cache/pinned-tokenizer,readonly",
            "--mount",
            f"type=bind,source={args.payload.resolve()},target=/input,readonly",
            "--mount",
            f"type=bind,source={args.output.resolve()},target=/output",
            "--mount",
            f"type=bind,source={Path(__file__).resolve()},target=/driver.py,readonly",
            args.image,
            "env",
            "-i",
            *[f"{k}={v}" for k, v in MINIMAL.items()],
            "python3",
            "-B",
            "/driver.py",
            "--inside",
        ],
        capture_output=True,
        timeout=240,
    )
    (args.output / "docker.log").write_bytes(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(
            f"clean remote rehearsal failed: {result.stderr.decode(errors='replace')}"
        )
    proof = json.loads((args.output / "proof.json").read_text())
    shutil.copyfile(
        args.payload / "staging-manifest.json", args.output / "staging-manifest.json"
    )
    manifest = json.loads((args.payload / "staging-manifest.json").read_text())
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root / "python/src"))
    from inference_platform.remote_source_fitness import remote_fingerprint

    from inference_platform.stage_c_capture_rehearsal import rehearse

    capture = rehearse(args.payload / "sources", args.output / "real-capture")
    proof["real_capture"] = capture
    (args.output / "proof.json").write_text(
        json.dumps(proof, indent=2) + "\n", encoding="utf-8"
    )
    receipt = {
        "schema": "inf011-clean-remote-rehearsal.v1",
        "status": "passed",
        "source_files_sha256": remote_fingerprint(root),
        "source_commit": manifest["source_commit"],
        "manifest_sha256": sha(args.payload / "staging-manifest.json"),
        "manifest_path": (args.output / "staging-manifest.json")
        .relative_to(root)
        .as_posix(),
        "bundle_sha256": sha(args.payload / "payload.tar.gz"),
        "proof_path": (args.output / "proof.json").relative_to(root).as_posix(),
        "proof_sha256": sha(args.output / "proof.json"),
        "image": args.image,
        "image_id": subprocess.check_output(
            ["docker", "image", "inspect", args.image, "--format", "{{.Id}}"], text=True
        ).strip(),
        "steps": [row["step"] for row in proof["checkpoints"]],
        "aws_calls_made": False,
    }
    (args.output / "receipt.json").write_text(
        json.dumps(receipt, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({"status": receipt["status"], "steps": receipt["steps"]}))


if __name__ == "__main__":
    main()
