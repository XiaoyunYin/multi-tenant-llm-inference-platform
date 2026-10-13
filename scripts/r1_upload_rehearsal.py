"""Zero-AWS, real-size upload through the committed Operator and bootstrap server."""

import argparse
import hashlib
import importlib.util
import json
import math
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

from inference_platform.r1_cloud_operator import Operator, file_sha
from inference_platform.r1_spec import encoded
from inference_platform.session_stop import stop_forward

ROOT = Path(__file__).resolve().parents[1]
RATE = 500_000
BIND_DELAY = 5.0


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def relay(port, upstream, folder, number):
    time.sleep(BIND_DELAY)
    log_lock = threading.Lock()

    def connection(client):
        started = time.monotonic()
        body_bytes, path, disconnected = 0, "unknown", False
        try:
            with (
                client,
                socket.create_connection(("127.0.0.1", upstream), timeout=30) as server,
            ):
                header = b""
                while b"\r\n\r\n" not in header:
                    piece = client.recv(8192)
                    if not piece:
                        return
                    header += piece
                    if len(header) > 16384:
                        raise ValueError("fixture header size")
                head, pending = header.split(b"\r\n\r\n", 1)
                path = head.split(b" ")[1].decode("ascii")
                length = re.search(rb"(?im)^Content-Length:\s*(\d+)", head)
                length = int(length[1]) if length else 0
                match = re.fullmatch(r"/bundle/(\d+)", path)
                fault = (
                    match
                    and int(match[1]) >= 2 * 1024**2
                    and not (folder / "fault.json").exists()
                )
                server.sendall(head + b"\r\n\r\n")

                def response():
                    try:
                        while data := server.recv(8192):
                            client.sendall(data)
                    except OSError:
                        pass

                receiver = threading.Thread(target=response, daemon=True)
                receiver.start()
                while body_bytes < length:
                    data = pending or client.recv(min(8192, length - body_bytes))
                    pending = b""
                    if not data:
                        break
                    if fault:
                        data = data[: min(len(data), length // 2 - body_bytes)]
                    if data:
                        time.sleep(len(data) / RATE)
                        server.sendall(data)
                        body_bytes += len(data)
                    if fault and body_bytes == length // 2:
                        disconnected = True
                        (folder / "fault.json").write_bytes(
                            encoded(
                                {
                                    "offset": int(match[1]),
                                    "partial_chunk_bytes": body_bytes,
                                    "helper": number,
                                    "disconnects": 1,
                                }
                            )
                        )
                        server.shutdown(socket.SHUT_RDWR)
                        client.shutdown(socket.SHUT_RDWR)
                        break
                if not disconnected:
                    server.shutdown(socket.SHUT_WR)
                receiver.join(timeout=30)
        except OSError:
            pass
        finally:
            with log_lock, (folder / f"relay-{number}.jsonl").open("ab") as out:
                out.write(
                    encoded(
                        {
                            "path": path,
                            "body_bytes": body_bytes,
                            "elapsed_s": time.monotonic() - started,
                            "injected_disconnect": disconnected,
                        }
                    )
                    + b"\n"
                )

    with socket.socket() as listener:
        listener.bind(("127.0.0.1", port))
        listener.listen()
        while True:
            client, _ = listener.accept()
            threading.Thread(target=connection, args=(client,), daemon=True).start()


def run(source, output):
    source = source.resolve()
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    original_sha = file_sha(source)
    scratch = output / "scratch-bundle.tar.gz"
    shutil.copyfile(source, scratch)
    assert file_sha(scratch) == original_sha
    assert scratch.stat().st_size == 37_512_307, "use the real reviewed 37.5 MB bundle"
    paths = [
        "scripts/r1_upload_rehearsal.py",
        "scripts/r1-host-bootstrap.py",
        "python/src/inference_platform/r1_cloud_operator.py",
        "python/src/inference_platform/session_stop.py",
    ]
    sources = {p: file_sha(ROOT / p) for p in paths}
    for p, digest in sources.items():
        assert (
            hashlib.sha256(
                subprocess.check_output(["git", "show", "HEAD:" + p], cwd=ROOT)
            ).hexdigest()
            == digest
        )
    upstream, host_directory, helpers = free_port(), output / "host", []
    with (output / "bootstrap.log").open("wb") as log:
        host = subprocess.Popen(
            [
                sys.executable,
                str(ROOT / "scripts/r1-host-bootstrap.py"),
                "--token",
                "fixture-control",
                "--bundle-sha256",
                original_sha,
                "--deadline-unix-s",
                str(time.time() + 300),
                "--port",
                str(upstream),
                "--directory",
                str(host_directory),
            ],
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    operator = Operator(
        ROOT,
        {"bundle_path": str(scratch), "bundle_sha256": original_sha},
        output / "operator",
        time.time() + 240,
    )

    def tunnel(_):
        port, number = free_port(), len(helpers)
        with (output / f"relay-{number}.log").open("wb") as log:
            child = subprocess.Popen(
                [
                    sys.executable,
                    __file__,
                    "--relay",
                    str(port),
                    "--upstream",
                    str(upstream),
                    "--output",
                    str(output),
                    "--number",
                    str(number),
                ],
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        helpers.append(child)
        return port, child

    operator.tunnel = (
        tunnel  # Substitute only SSM start; RPC, upload and retries remain real.
    )
    original_rpc, followup = operator.rpc, [False]

    def rpc(port, path, token, data=None, headers=None):
        if path == "/run":
            followup[0] = True
            return b'{"started":"ready"}', {}
        if followup[0] and path == "/status":
            return encoded({"actions": {"ready": 0}}), {}
        return original_rpc(port, path, token, data, headers)

    operator.rpc = rpc  # Stub only /run's hardware-dependent follow-up.
    binding = {
        "hosts": {"generator": {"id": "fixture-host"}},
        "control_token": "fixture-control",
    }
    started = time.monotonic()
    try:
        operator.with_host("generator", "ready", binding)
        elapsed = time.monotonic() - started
        spec = importlib.util.spec_from_file_location(
            "verify_bootstrap", ROOT / "scripts/r1-host-bootstrap.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.verify_payload(host_directory / "payload")
        manifest = json.loads((host_directory / "payload/payload.json").read_bytes())
        channels = [
            json.loads(line)
            for line in (output / "operator/generator-ready-channel.jsonl")
            .read_bytes()
            .splitlines()
        ]
        upload = next(e for e in channels if e["event"] == "bundle_uploaded")
        fault = json.loads((output / "fault.json").read_bytes())
        assert upload["resume_offsets"] == [fault["offset"]] and fault["offset"] > 0
        assert (
            upload["reconnects"] == 1
            and upload["chunks"] == math.ceil(scratch.stat().st_size / 1024**2) + 1
        )
        assert len(helpers) == 2 and followup[0] and 75 < elapsed < 180
        requests = [
            json.loads(line)
            for p in sorted(output.glob("relay-*.jsonl"))
            for line in p.read_bytes().splitlines()
        ]
        chunks = [r for r in requests if re.fullmatch(r"/bundle/\d+", r["path"])]
        durations = sorted(
            r["elapsed_s"] for r in chunks if not r["injected_disconnect"]
        )
        assert (
            len(chunks) == upload["chunks"]
            and max(r["body_bytes"] for r in chunks) <= 1024**2
        )
        receipt = {
            "fixture": True,
            "real_aws_calls": 0,
            "committed_sources": True,
            "source_head": subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=ROOT
            )
            .decode()
            .strip(),
            "source_sha256": sources,
            "entrypoint": 'Operator.with_host(role, "ready", context)',
            "real_bootstrap": True,
            "bundle_bytes": scratch.stat().st_size,
            "bundle_sha256": original_sha,
            "pinned_path_written": False,
            "bind_delay_s_each": BIND_DELAY,
            "rate_limit_bytes_per_second": RATE,
            "elapsed_s": elapsed,
            "upload_event": upload,
            "fault": fault,
            "request_timings": chunks,
            "successful_chunk_elapsed_s": {
                "min": durations[0],
                "p50": durations[len(durations) // 2],
                "p95": durations[math.ceil(len(durations) * 0.95) - 1],
                "max": durations[-1],
            },
            "wire_upload_body_bytes": sum(r["body_bytes"] for r in chunks),
            "staged_payload_verified": True,
            "staged_file_count": len(manifest["files"]),
            "payload_manifest_sha256": file_sha(
                host_directory / "payload/payload.json"
            ),
        }
        (output / "receipt.json").write_bytes(encoded(receipt) + b"\n")
        print(
            json.dumps(
                {
                    k: receipt[k]
                    for k in (
                        "elapsed_s",
                        "bundle_bytes",
                        "upload_event",
                        "successful_chunk_elapsed_s",
                        "staged_file_count",
                    )
                },
                indent=2,
            )
        )
    finally:
        for child in helpers:
            stop_forward(child)
        stop_forward(host)
        assert file_sha(source) == original_sha, "pinned input changed"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--relay", type=int)
    parser.add_argument("--upstream", type=int)
    parser.add_argument("--number", type=int)
    args = parser.parse_args()
    if args.relay:
        relay(args.relay, args.upstream, args.output, args.number)
    else:
        run(args.bundle, args.output)


if __name__ == "__main__":
    main()
