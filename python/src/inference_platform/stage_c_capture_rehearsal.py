"""No-cost Docker rehearsal of the controller staging and real ZMQ capture branch."""

import argparse
import json
import subprocess
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

from .disk_records import jsonl_rows
from .stage_c_capture import CAPTURE_ROOT, prepare_paths, start_live_capture
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


def checkpoint_fixture(megabytes):
    """Exercise the session callback against real bind-mounted, prompt-sized rows."""
    import hashlib
    from types import SimpleNamespace

    from .stage_c_checkpoint import checkpoint_run, file_sha

    session = Path(CAPTURE_ROOT) / "checkpoint-session"
    session.mkdir(mode=0o700)
    (session / "gateway.log").write_text("")
    observations = Path(CAPTURE_ROOT) / "capture.observations.jsonl"
    row = next(jsonl_rows(observations))
    row.update(token_count=6144, token_block_size=16)
    started = time.perf_counter()
    count = 0
    with observations.open("w", encoding="utf-8", newline="\n") as stream:
        while stream.tell() < megabytes * 1024 * 1024:
            count += 1
            row["sequence"] = count
            row["block_hash_digests"] = [
                hashlib.sha256(f"block-{count}-{i}".encode()).hexdigest() for i in range(384)
            ]
            row["token_block_digests"] = [
                hashlib.sha256(f"token-{count}-{i}".encode()).hexdigest() for i in range(384)
            ]
            stream.write(json.dumps(row) + "\n")
    config = SimpleNamespace(
        kv_capture_output_path=str(CAPTURE_ROOT / "capture.json"),
        decision_prompt_export_path="/absent-checkpoint-prompts",
    )
    receipts = []
    for number in range(1, 5):
        start = time.perf_counter()
        receipt = checkpoint_run(session, number, {"status": "completed", "levels": []}, config)
        if receipt is None or receipt["measurement_digest"]["event_lag_status"] == "unavailable":
            raise RuntimeError("real-size checkpoint failed to seal")
        receipt["elapsed_seconds"] = time.perf_counter() - start
        receipts.append(receipt)
    return {
        "status": "passed",
        "observations_bytes": observations.stat().st_size,
        "observations_sha256": file_sha(observations),
        "observation_rows": count,
        "blocks_per_row": 384,
        "elapsed_seconds": time.perf_counter() - started,
        "checkpoints": receipts,
        "basis": "Actual session checkpoint_run and seal_run, actual host bind mount, real capture-shaped high-entropy observations; no GPU/AWS or copy",
    }


def rehearse(
    sources: Path, output: Path, image="python:3.12-slim-bookworm", checkpoint_megabytes=0
):
    def run(argv, **kwargs):
        return subprocess.run(argv, capture_output=True, text=True, **kwargs)

    if run(["docker", "inspect", CONTAINER], check=False, timeout=10).returncode == 0:
        raise RuntimeError("local inf011-vllm already exists; use an isolated Docker context")
    output.mkdir(parents=True, exist_ok=False)
    run(
        [
            "docker",
            "run",
            "--detach",
            "--name",
            CONTAINER,
            "--volume",
            f"{output.resolve()}:{CAPTURE_ROOT}",
            image,
            "sleep",
            "1800",
        ],
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
        private = PurePosixPath(str(CAPTURE_ROOT))
        staging_start = time.perf_counter()
        stage_capture_package(sources, private, run=run)
        staging_elapsed = time.perf_counter() - staging_start
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
        # Host paths address the same files through the real bind mount.
        host_config = SimpleNamespace(
            decision_prompt_export_path=str(output / "restricted-prompts.jsonl"),
            decision_export_output_path=str(output / "decisions.jsonl"),
        )
        prepare_paths(host_config)
        if not (output / "decisions.jsonl").exists():
            raise RuntimeError("host decisions file was not prepared")
        process = start_live_capture(config, time.perf_counter() + 30)
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
        # The real host bind mount supplies metadata and streams without docker cp.
        count = sum(
            row["event_type"] == "BlockStored"
            for row in jsonl_rows(output / "capture.observations.jsonl")
        )
        if count <= 0:
            raise RuntimeError("continuous capture decoded no BlockStored")
        receipt.update(
            host_prepare_paths_before_capture=True,
            shared_decisions_visible_at_start=True,
            continuous_decoded_block_stored_count=count,
            second_probe=json.loads(trigger.stdout),
            status="passed",
            package_staging_seconds=staging_elapsed,
            package_source_bytes=sum(
                p.stat().st_size
                for p in (sources / "python/src/inference_platform").rglob("*")
                if p.is_file()
            ),
        )
        if checkpoint_megabytes:
            checkpoint_command = capture_argv()
            checkpoint_command[-1] = "inference_platform.stage_c_capture_rehearsal"
            checkpoint_command += ["--checkpoint-fixture", str(checkpoint_megabytes)]
            fixture = run(checkpoint_command, check=True, timeout=900)
            receipt["real_branch_checkpoints"] = json.loads(fixture.stdout)
        receipt["image_id"] = run(
            ["docker", "inspect", "--format", "{{.Image}}", CONTAINER], check=True, timeout=10
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
    parser.add_argument("--checkpoint-megabytes", type=int, default=0)
    parser.add_argument("--checkpoint-fixture", type=int, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.publisher:
        publisher()
    elif args.checkpoint_fixture:
        print(json.dumps(checkpoint_fixture(args.checkpoint_fixture)))
    elif args.sources and args.output:
        print(
            json.dumps(
                rehearse(args.sources, args.output, checkpoint_megabytes=args.checkpoint_megabytes)
            )
        )
    else:
        parser.error("--sources and --output are required")


if __name__ == "__main__":
    main()
