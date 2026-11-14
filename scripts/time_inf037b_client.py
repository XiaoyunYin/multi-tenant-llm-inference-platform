"""Local 120 s client/cadence receipt; real TLS sockets, no serving/model claim."""

import argparse
import json
import math
import os
import platform
import ssl
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from inference_platform.inf037b_archive import sha
from inference_platform.inf037b_capture import wire_records
from inference_platform.inf037b_live import ClientSSEAdapter
from inference_platform.package_a_workload import test_tls_command
from time_inf037b_wire import inputs, owner


def quantiles(values):
    values = sorted(values)
    return {
        name: values[math.ceil(len(values) * p) - 1]
        for name, p in (("p50_ms", 0.5), ("p95_ms", 0.95), ("max_ms", 1))
    }


def measure(root, url, context, *, retain, duration=120):
    cadences = {
        "clock": 1000,
        "g0": 250,
        "g1": 250,
        "redis": 250,
        "kube": 250,
        "v0": 500,
        "v1": 500,
    }
    sources = {name: [["controller", name, "wire-receipt-boot"]] for name in cadences}
    sources["traffic"] = [
        ["client", "client:gateway" + str(i), "wire-receipt-boot"] for i in (0, 1)
    ]
    capture = owner(root, sources=sources)
    clients = [
        ClientSSEAdapter(
            capture.rows("traffic"),
            "gateway" + str(i),
            "a" * 64,
            retain=capture.retainer("traffic") if retain else None,
        )
        for i in (0, 1)
    ]
    slots, times, outcomes, dispatch_lateness = (
        {name: 0 for name in cadences},
        [],
        [],
        [],
    )
    periodic = []
    for name, cadence in cadences.items():
        rows = capture.rows(name)

        def collect(name=name, rows=rows):
            rows.row(
                "controller",
                name,
                "wire-receipt-boot",
                "precondition",
                {"name": "cadence", "value": slots[name]},
            )
            slots[name] += 1

        periodic.append((name, cadence, collect))

    def traffic():
        start = time.monotonic_ns()
        with ThreadPoolExecutor(max_workers=32) as pool:
            futures = []
            for index in range(math.ceil(10.92 * duration)):
                scheduled = start + index * 100_000_000_000 // 1092
                delay = (scheduled - time.monotonic_ns()) / 1e9
                if delay > 0:
                    time.sleep(delay)
                offer = {
                    "request_id": f"receipt-{index}",
                    "prefix_id": "p000",
                    "offer_index": index,
                    "scheduled_ms": scheduled // 1_000_000,
                }

                def request(index=index, offer=offer, scheduled=scheduled):
                    before = time.monotonic_ns()
                    output = clients[index % 2].request(
                        url,
                        {
                            "model": "Qwen/Qwen2.5-7B-Instruct",
                            "messages": [{"role": "user", "content": "x"}],
                            "stream": True,
                            "max_tokens": 1,
                        },
                        offer,
                        credential="receipt-only",
                        context=context,
                    )
                    times.append((time.monotonic_ns() - before) / 1e6)
                    dispatch_lateness.append((before - scheduled) / 1e6)
                    outcomes.append(output[-1]["payload"]["outcome"])

                futures.append(pool.submit(request))
            remaining = (start + duration * 1_000_000_000 - time.monotonic_ns()) / 1e9
            if remaining > 0:
                time.sleep(remaining)
            for future in futures:
                future.result()

    fsyncs = [0]
    fsync = os.fsync

    def counted(fd):
        assert not capture.lock._is_owned(), "fsync holds owner lock"
        fsyncs[0] += 1
        return fsync(fd)

    start = time.monotonic_ns()
    os.fsync = counted
    try:
        result = capture.run(
            periodic=periodic,
            watches={},
            actions={"traffic": traffic},
            stop_ns=start + (duration + 1) * 1_000_000_000,
        )
    finally:
        os.fsync = fsync
    records = list(wire_records(capture.root / "wire"))
    client_files = [
        v for p, v in result["files"].items() if p.startswith("wire/" + sha(b"traffic"))
    ]
    summary = {
        "retainer": retain,
        "offered_rate_per_s": 10.92,
        "duration_s": duration,
        "offers": len(times),
        "complete": outcomes.count("complete"),
        "missed_slots": sum(bool(r["metadata"].get("missed_slot")) for r, _ in records),
        "transport_clean": result["transport_clean"],
        "group_tick_max_interval_ms": max(capture.group_tick_intervals_ms),
        "slots": slots,
        "request": quantiles(times),
        "dispatch_lateness": quantiles(dispatch_lateness),
        "client_wire_bytes": sum(v["bytes"] for v in client_files),
        "client_wire_files": len(client_files),
        "client_wire_fsyncs": capture.wire["traffic"]["barriers"] * 2,
        "client_wire_fsyncs_per_s": capture.wire["traffic"]["barriers"] * 2 / duration,
        "spool_bytes": result["spool_bytes"],
        "spool_files": result["spool_files"],
        "spool_fsyncs": result["spool_fsyncs"],
        "spool_fsyncs_per_s": result["spool_fsyncs"] / duration,
        "all_fsyncs_including_archive_and_close": fsyncs[0],
        "all_fsyncs_per_s": fsyncs[0] / duration,
        "close_s": (time.monotonic_ns() - result["close_start_ns"]) / 1e9,
        "archive_bytes": sum(
            v["bytes"] for p, v in result["files"].items() if p.startswith("archive/")
        ),
        "archive_files": sum(p.startswith("archive/") for p in result["files"]),
        "client_normalized_bytes": result["files"]["archive/raw/client.jsonl"]["bytes"],
    }
    assert summary["offers"] == math.ceil(10.92 * duration) == summary["complete"]
    assert summary["missed_slots"] == 0 and summary["transport_clean"]
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    before = {
        **inputs(),
        "scripts/time_inf037b_client.py": sha(
            Path(__file__).read_bytes().replace(b"\r\n", b"\n")
        ),
    }
    args.work.mkdir(parents=True)
    subprocess.run(
        [str(p) for p in test_tls_command(args.work)], check=True, capture_output=True
    )
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(args.work / "tls.crt", args.work / "tls.key")
    context = ssl.create_default_context(cafile=str(args.work / "tls.crt"))

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def do_POST(self):
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            assert payload["max_tokens"] == 1
            self.send_response(200)
            self.send_header("X-Request-ID", self.headers["X-Request-ID"])
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for chunk in (
                b'data: {"choices":[{"index":0,"delta":{"role":"assistant"},"finish_reason":null}]}\n\n',
                b'data: {"choices":[{"index":0,"delta":{"content":"x"},"finish_reason":"length"}]}\n\n',
                b'data: {"choices":[],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2,"count_source":"runtime_usage"}}\n\ndata: [DONE]\n\n',
            ):
                self.wfile.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
                self.wfile.flush()
                time.sleep(0.001)
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    server.socket = server_context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        url = f"https://localhost:{server.server_port}/v1/chat/completions"
        summary = {
            "schema": "inf037b-client-cost-v1",
            "platform": platform.platform(),
            "python": platform.python_version(),
            "cost_usd": 0,
            "inputs_lf_sha256": before,
            "native_runtime": "NOT_RUN",
            "host": "WSL2 Docker ext4; 2 CPUs/4 GiB memory=swap/256 PIDs; warm caches",
        }
        for retain, name in ((False, "baseline"), (True, "retained")):
            print(name + " 120 s", flush=True)
            summary[name] = measure(args.work / name, url, context, retain=retain)
            args.output.write_text(
                json.dumps(summary, indent=2, allow_nan=False) + "\n"
            )
        summary["request_quantile_difference_ms"] = {
            key: summary["retained"]["request"][key]
            - summary["baseline"]["request"][key]
            for key in summary["baseline"]["request"]
        }
        summary["inputs_unchanged"] = before == {
            **inputs(),
            "scripts/time_inf037b_client.py": sha(
                Path(__file__).read_bytes().replace(b"\r\n", b"\n")
            ),
        }
        args.output.write_text(json.dumps(summary, indent=2, allow_nan=False) + "\n")
        print(
            json.dumps(
                {
                    key: value
                    for key, value in summary.items()
                    if key != "inputs_lf_sha256"
                }
            ),
            flush=True,
        )
        assert summary["inputs_unchanged"]
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
