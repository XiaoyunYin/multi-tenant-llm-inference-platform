"""No-cost Docker rehearsal of the controller staging and real ZMQ capture branch."""

import argparse
import json
import subprocess
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

from .stage_c_capture import start_live_capture
from .stage_c_container import (
    CONTAINER,
    PACKAGE_ROOT,
    capture_argv,
    publisher_probe_argv,
    stage_capture_package,
)


def publisher():
    import msgspec
    import zmq

    context = zmq.Context()
    pub = context.socket(zmq.PUB)
    pub.bind("tcp://*:5557")
    sequence = 0

    class Warmup(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):  # noqa: N802
            nonlocal sequence
            self.rfile.read(int(self.headers["Content-Length"]))
            sequence += 1
            batch = {
                "ts": time.time(),
                "events": [
                    {
                        "type": "BlockStored",
                        "block_size": 16,
                        "block_hashes": [sequence],
                        "token_ids": list(range(16)),
                    }
                ],
            }
            pub.send_multipart(
                [b"kv-events", sequence.to_bytes(8, "big"), msgspec.msgpack.encode(batch)]
            )
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

    with HTTPServer(("127.0.0.1", 8000), Warmup) as server:
        try:
            server.serve_forever()
        finally:
            pub.close(linger=0)
            context.term()


def rehearse(sources: Path, output: Path, image="python:3.12-slim-bookworm"):
    def run(argv, **kwargs):
        return subprocess.run(argv, capture_output=True, text=True, **kwargs)

    if run(["docker", "inspect", CONTAINER], check=False).returncode == 0:
        raise RuntimeError("local inf011-vllm already exists; use an isolated Docker context")
    output.mkdir(parents=True, exist_ok=False)
    run(
        ["docker", "run", "--detach", "--name", CONTAINER, image, "sleep", "600"],
        check=True,
        timeout=120,
    )
    process = None
    try:
        install = run(
            [
                "docker",
                "exec",
                CONTAINER,
                "python3",
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "pyzmq==27.1.0",
                "msgspec==0.19.0",
            ],
            check=True,
            timeout=120,
        )
        (output / "dependencies.log").write_text(
            install.stdout + install.stderr, encoding="utf-8", newline="\n"
        )
        private = PurePosixPath("/tmp/inf011-capture-rehearsal")
        stage_capture_package(sources, private, run=run)
        fixture = capture_argv()
        fixture[-1] = "inference_platform.stage_c_capture_rehearsal"
        fixture += ["--publisher"]
        run(["docker", "exec", "--detach", *fixture[2:]], check=True, timeout=10)
        limit = time.perf_counter() + 10
        while True:
            check = run(
                [
                    "docker",
                    "exec",
                    CONTAINER,
                    "python3",
                    "-c",
                    "import socket; socket.create_connection(('127.0.0.1',8000),1).close()",
                ],
                check=False,
                timeout=2,
            )
            if check.returncode == 0:
                break
            if time.perf_counter() >= limit:
                raise RuntimeError("local PUB fixture did not start")
            time.sleep(0.1)
        command = publisher_probe_argv("tcp://127.0.0.1:5557", "kv-events", "test", 10)
        probe = run(command, check=False, timeout=15)
        receipt = {
            "probe_argv": command,
            "package_root": PACKAGE_ROOT,
            "returncode": probe.returncode,
            "stderr": probe.stderr,
            "probe": json.loads(probe.stdout),
            "publisher_bind": "tcp://*:5557",
            "basis": "LOCAL Docker/real pyzmq PUB/msgspec BlockStored; no GPU/AWS",
        }
        if probe.returncode or receipt["probe"].get("decoded_block_stored_count", 0) <= 0:
            raise RuntimeError(str(receipt))
        config = SimpleNamespace(
            kv_capture_output_path=str(private / "capture.json"),
            kv_capture_stop_file=str(private / "stop"),
            decision_export_output_path=str(private / "decisions.jsonl"),
            kv_event_endpoint="tcp://127.0.0.1:5557",
            kv_event_topic="kv-events",
            evidence_export_margin_seconds=600,
        )
        process = start_live_capture(config, time.perf_counter() + 30)
        run(
            ["docker", "exec", CONTAINER, "touch", config.decision_export_output_path],
            check=True,
            timeout=10,
        )
        # Subscribe via the actual live branch, then emit another warm-up store.
        trigger = run(command, check=True, timeout=15)
        run(
            ["docker", "exec", CONTAINER, "touch", config.kv_capture_stop_file],
            check=True,
            timeout=10,
        )
        process.wait(timeout=15)
        if process.returncode:
            raise RuntimeError(f"continuous capture exited ({process.returncode})")
        run(
            [
                "docker",
                "cp",
                f"{CONTAINER}:{config.kv_capture_output_path}",
                str(output / "capture.json"),
            ],
            check=True,
            timeout=10,
        )
        artifact = json.loads((output / "capture.json").read_text(encoding="utf-8"))
        count = sum(row["event_type"] == "BlockStored" for row in artifact["event_observations"])
        if count <= 0:
            raise RuntimeError("continuous capture decoded no BlockStored")
        receipt.update(
            continuous_decoded_block_stored_count=count,
            second_probe=json.loads(trigger.stdout),
            status="passed",
        )
        receipt["image_id"] = run(
            ["docker", "inspect", "--format", "{{.Image}}", CONTAINER], check=True
        ).stdout.strip()
        (output / "receipt.json").write_text(
            json.dumps(receipt, indent=2) + "\n", encoding="utf-8", newline="\n"
        )
        return receipt
    finally:
        run(["docker", "rm", "--force", CONTAINER], check=False, timeout=30)
        if process:
            process.wait(timeout=10)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--publisher", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.publisher:
        publisher()
    elif args.sources and args.output:
        print(json.dumps(rehearse(args.sources, args.output)))
    else:
        parser.error("--sources and --output are required")


if __name__ == "__main__":
    main()
