"""No-AWS real-volume test/rehearsal through a throttled TCP forward.

Runs production monitor, durable Range fetch and HTTP range server. Synthetic
status transitions model measurement; a separate entrypoint rehearsal covers
actual fake inference. No model/performance inference follows from these bytes.
"""

import argparse
import gzip
import hashlib
import json
import random
import socket
import socketserver
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from inference_platform.archive_transfer import export_window
from inference_platform.stage_c_checkpoint import file_sha
from inference_platform.stage_c_session import reply_archive_file
from inference_platform.stage_c_digest import seal_digest
from inference_platform.stage_c_transport import (
    ReconnectingTransport,
    monitor_and_export,
)


def rehearse(work, output, rate, total_bytes, runs):
    root = Path(__file__).resolve().parents[1]
    sources = {
        name: hashlib.sha256(
            (root / name).read_bytes().replace(b"\r\n", b"\n")
        ).hexdigest()
        for name in (
            "scripts/rehearse_stage_c_export.py",
            "python/src/inference_platform/archive_transfer.py",
            "python/src/inference_platform/stage_c_transport.py",
            "python/src/inference_platform/stage_c_digest.py",
            "python/src/inference_platform/stage_c_session.py",
        )
    }
    work.mkdir(parents=True, exist_ok=False)
    host, operator = work / "host", work / "operator"
    host.mkdir()
    operator.mkdir()
    rng = random.Random(106)
    block = rng.randbytes(256 * 1024)
    receipts = []
    for number in range(1, runs + 1):
        path = host / f"run-{number}.tar.gz"
        # A real gzip stream at native volume, with incompressible synthetic input.
        with gzip.open(path, "wb", compresslevel=1) as stream:
            remaining = total_bytes // runs
            while remaining:
                data = block[: min(len(block), remaining)]
                stream.write(data)
                remaining -= len(data)
        digest = host / f"run-{number}.digest.json.gz"
        value = {
            "run": {
                "levels": [
                    {
                        "concurrency": 8,
                        "records": [
                            {
                                "request_id": f"synthetic-{i}",
                                "outcome": "completed"
                                if i % 5
                                else "failed_before_content",
                                "failure_class": "completed"
                                if i % 5
                                else "vllm_pre_content_rejection",
                                "dispatch_offset_ns": i * 10**9,
                                "first_content_offset_ns": i * 10**9 + i + 10
                                if i % 5
                                else None,
                                "completion_offset_ns": i * 10**9 + i + 1000,
                                "prompt_tokens": 6144,
                                "completion_tokens": i % 64,
                            }
                            for i in range(7000)
                        ],
                    }
                ]
            },
            "event_lag": {
                "status": "unestablished",
                "reason": "synthetic transport fixture",
            },
        }
        receipts.append(
            {
                "run_number": number,
                "bytes": path.stat().st_size,
                "sha256": file_sha(path),
                "measurement_digest": seal_digest(digest, value),
            }
        )
    payload = b"synthetic final metadata; no GPU measurement\n"
    final_receipt = {
        "bytes": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }
    stats = {
        "archive_bytes_during_measurement": 0,
        "archive_requests": [],
        "status_polls": 0,
        "disconnects": 0,
        "wire_bytes": 0,
    }
    state = {"finished": False}

    def status_bytes():
        stats["status_polls"] += 1
        state["finished"] = stats["status_polls"] >= 3
        disk = {
            "status": "available",
            "free_bytes": 80 * 1024**3,
            "directory_breakdown": {"status": "synthetic", "largest_directories": []},
        }
        return json.dumps(
            {
                "started": True,
                "finished": state["finished"],
                "completed_runs": receipts,
                "disk_records": {
                    name: disk
                    for name in (
                        "disk-before-pull.json",
                        "disk-readiness.json",
                        *(f"disk-checkpoint-{n}.json" for n in range(1, 5)),
                    )
                },
                "sampled_root_minimum_free_bytes": 79 * 1024**3,
            }
        ).encode()

    class CommandStub:
        def __init__(self):
            self.calls = []

        def request(self, path, deadline, *, transport):
            self.calls.append(path)
            time.sleep(min(2, max(0, deadline - time.perf_counter())))
            if path == "/status":
                return status_bytes()
            if path.startswith("/digest/"):
                return (host / f"run-{path[-1]}.digest.json.gz").read_bytes()
            raise ValueError("command stub supports only status and digests")

        def unavailable(self, error):
            raise AssertionError(f"unexpected command failure: {error}")

        def record_snapshot(self, status):
            pass

    class Host(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):  # noqa: N802
            if self.path == "/status":
                data = status_bytes()
            elif self.path.startswith("/digest/"):
                data = (host / f"run-{self.path[-1]}.digest.json.gz").read_bytes()
            elif self.path.startswith("/run/"):
                stats["archive_requests"].append(
                    {"range": self.headers.get("Range"), "finished": state["finished"]}
                )
                if not state["finished"]:
                    stats["archive_bytes_during_measurement"] += 1
                try:
                    reply_archive_file(self, host / f"run-{self.path[-1]}.tar.gz")
                except (ConnectionError, OSError):
                    pass
                return
            elif self.path == "/receipt":
                data = json.dumps(final_receipt).encode()
            elif self.path == "/export":
                data = payload
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Host)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    created = []
    transfer_start = time.perf_counter()

    class Relay(socketserver.BaseRequestHandler):
        def handle(self):
            with socket.create_connection(server.server_address) as upstream:
                request = b""
                while b"\r\n\r\n" not in request:
                    piece = self.request.recv(4096)
                    if not piece:
                        return
                    request += piece
                upstream.sendall(request)
                sent = 0
                begin = time.perf_counter()
                try:
                    while piece := upstream.recv(16384):
                        # Sleep BEFORE send so even the first chunk is rate-limited.
                        sent += len(piece)
                        time.sleep(max(0, sent / rate - (time.perf_counter() - begin)))
                        self.request.sendall(piece)
                        stats["wire_bytes"] += len(piece)
                        if (
                            stats["wire_bytes"] >= total_bytes // 2
                            and stats["disconnects"] == 0
                        ):
                            stats["disconnects"] += 1
                            return  # close mid-range; complete chunks remain durable
                except (ConnectionError, OSError):
                    pass

    class Forward:
        def __init__(self):
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                self.address = reservation.getsockname()
            self.server = socketserver.ThreadingTCPServer(
                self.address, Relay, bind_and_activate=False
            )
            self.server.daemon_threads = True
            self.cancel = threading.Event()
            self.bind_lock = threading.Lock()
            self.returncode = None
            self.bind_seconds = None
            self.thread = threading.Thread(target=self.listen, daemon=True)
            self.thread.start()

        def listen(self):
            launched = time.perf_counter()
            if self.cancel.wait(5):
                return
            with self.bind_lock:
                if self.cancel.is_set():
                    return
                self.server.server_bind()
                self.server.server_activate()
                self.bind_seconds = time.perf_counter() - launched
            self.server.serve_forever()

        def poll(self):
            return self.returncode

        def close(self):
            with self.bind_lock:
                self.cancel.set()
            if self.bind_seconds is not None:
                self.server.shutdown()
            self.server.server_close()
            self.thread.join()
            self.returncode = 0

    def start_forward():
        forward = Forward()
        created.append(forward)
        transport.base = f"http://127.0.0.1:{forward.address[1]}"
        return forward

    total = sum(r["bytes"] for r in receipts)
    interruptions, outcome = [], {}
    command = CommandStub()
    transport = ReconnectingTransport(
        start_forward,
        "unset",
        "synthetic",
        time.perf_counter() + export_window(total) + 120,
        interruptions,
        stop=lambda child: child.close(),
        command_channel=command,
    )
    try:
        monitor_and_export(transport, operator, outcome)
        if outcome.get("unfetched_full_runs"):
            raise ValueError(outcome["unfetched_full_runs"])
        transfers = []
        for receipt in receipts:
            number = receipt["run_number"]
            assert (
                file_sha(operator / f"sealed-runs/run-{number}.tar.gz")
                == receipt["sha256"]
            )
            transfers.append(
                json.loads(
                    (operator / f"sealed-runs/run-{number}.transfer.json").read_text()
                )
            )
        assert stats["archive_bytes_during_measurement"] == 0
        assert stats["disconnects"] == 1
        assert all(row["finished"] for row in stats["archive_requests"])
        assert len(list(operator.glob("disk-*.json"))) == 6
        assert (
            json.loads((operator / "sampled-root-minimum.json").read_text())[
                "free_bytes"
            ]
            == 79 * 1024**3
        )
        assert all(row["sha256_verified"] for row in transfers)
        assert len(created) == 2
        assert all(child.bind_seconds >= 5 for child in created)
        assert command.calls and all(
            path == "/status" or path.startswith("/digest/") for path in command.calls
        )
        assert sum(row["forwards_started"] for row in transfers) == 1
        elapsed = time.perf_counter() - transfer_start
        assert stats["wire_bytes"] / elapsed <= rate
        report = {
            "status": "passed",
            "source_files_lf_sha256": sources,
            "schema": "inf011-bandwidth-export.v2",
            "bytes_per_second_limit": rate,
            "source_archive_bytes": total,
            "wire_bytes": stats["wire_bytes"],
            "elapsed_seconds": elapsed,
            "measured_wire_bytes_per_second": stats["wire_bytes"] / elapsed,
            "disconnects": stats["disconnects"],
            "forwards_created": len(created),
            "forwards_started": transport.forwards_started,
            "forward_bind_seconds": [child.bind_seconds for child in created],
            "command_channel_calls": len(command.calls),
            "command_channel_paths": command.calls,
            "archive_bytes_during_measurement": 0,
            "all_archives_sha256_verified": True,
            "disk_records_via_status": 6,
            "operator_send_commands": 0,
            "digest_per_request_counts": [
                r["measurement_digest"]["per_request_count"] for r in receipts
            ],
            "digest_bytes": [r["measurement_digest"]["bytes"] for r in receipts],
            "archive_export_window": outcome["archive_export_window"],
            "transfers": transfers,
            "interruptions": interruptions,
            "aws_calls_made": False,
            "basis": "Actual production monitor/Range client/server over throttled reconnecting TCP forward; synthetic measurement status/records, no inference or GPU measurement",
        }
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n"
        )
        print(
            json.dumps(
                {
                    k: v
                    for k, v in report.items()
                    if k not in ("transfers", "interruptions")
                }
            ),
            flush=True,
        )
    finally:
        transport.close()
        server.shutdown()
        server.server_close()
        thread.join()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--rate", type=int, default=500_000)
    parser.add_argument("--bytes", type=int, default=300_000_000)
    parser.add_argument("--runs", type=int, choices=(1, 4), default=4)
    args = parser.parse_args()
    if not 0 < args.rate <= 1_000_000 or args.bytes < 300_000_000:
        parser.error("requires >=300 MB and rate <=1 MB/s")
    rehearse(args.work, args.output, args.rate, args.bytes, args.runs)
