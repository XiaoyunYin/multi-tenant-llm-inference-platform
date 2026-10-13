"""Committed Linux loopback rehearsal. Simulated GPU metrics are not GPU evidence.

Run in a disposable namespace with the pinned Redis on 127.0.0.1:6379.
The only session invocation is r1_session --http-config; its spec bytes stay fixed.
"""

import argparse
import base64
import hashlib
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from .r1_export_probe import measure
from .r1_fixture_target import MINIMUM_WALL_RATE
from .r1_launcher import backend_command
from .r1_manifest import build, load, tenant_salt
from .r1_metrics import NAMES, percentile
from .r1_spec import IMAGE, MODEL, SPEC_COMMIT, digest, encoded


class Replica:
    def __init__(self, index, banks, refusal):
        self.index, self.refusal = index, refusal
        self.lock = threading.Lock()
        self.tokens = {
            digest(item["request"]["messages"]): item["tokens"]
            for bank in banks.values()
            for item in bank
        }
        self.sentinel = digest(banks["sentinel.jsonl"][0]["request"]["messages"])
        self.cache, self.counts = set(), dict.fromkeys(NAMES, 0)
        self.phase, self.pending, self.posts, self.visible_until = {}, None, 0, 0
        self.refusals = []

    def metrics(self):
        with self.lock:
            values = dict(self.counts)
            if self.pending is not None:
                values["running"] = int(time.perf_counter() < self.visible_until)
                values["waiting"] = 0
            else:
                name, level = self.phase.get("name", ""), self.phase.get("level")
                values["running"] = min(level or 8, 8)
                values["waiting"] = max(0, (level or 0) - 8) if name.startswith("staircase") else 1
        labels = f'model_name="{MODEL}",engine="0"'
        lines = []
        for key, name in NAMES.items():
            if key == "completions":
                for reason in ("length", "stop", "abort"):
                    lines.append(
                        f'{name}{{{labels},finished_reason="{reason}"}} {values[key] if reason == "length" else 0}'
                    )
            else:
                lines.append(f"{name}{{{labels}}} {values[key]}")
        lines.append(f"vllm:kv_cache_usage_perc{{{labels}}} 0.5")
        return ("\n".join(lines) + "\n").encode()

    def handler(self):
        replica = self

        class Handler(BaseHTTPRequestHandler):
            def reply(self, body, content_type="application/json"):
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                self.reply(
                    replica.metrics() if self.path == "/metrics" else b"{}",
                    "text/plain" if self.path == "/metrics" else "application/json",
                )

            def do_POST(self):
                value = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if self.path == "/tokenize":
                    self.reply(
                        encoded(
                            {"tokens": replica.tokens[digest(value["messages"])], "count": 1024}
                        )
                    )
                elif self.path == "/fixture/preparation":
                    replica.pending, replica.posts = value["pending"], 0
                    self.reply(b"{}")
                elif self.path == "/fixture/phase":
                    replica.phase, replica.pending = value, None
                    self.reply(b"{}")
                elif self.path == "/reset_prefix_cache":
                    with replica.lock:
                        replica.posts += 1
                        refuse = (
                            replica.index == 0 and replica.posts == 1 and replica.pending in (1, 2)
                        )
                        if refuse:
                            replica.visible_until = time.perf_counter() + (
                                0.8 if replica.refusal == "visible" else 0
                            )
                            replica.refusals.append(
                                {
                                    "pending": replica.pending,
                                    "success": False,
                                    "status": 200,
                                    "observable_work": replica.refusal == "visible",
                                }
                            )
                        else:
                            replica.cache.clear()
                    self.reply(encoded({"success": not refuse}))
                elif self.path == "/v1/chat/completions":
                    key = digest(value["messages"])
                    with replica.lock:
                        if key == replica.sentinel:
                            hits = 1008 if key in replica.cache else 0
                        elif "-warm-" in replica.phase.get("name", ""):
                            window = int(replica.phase["name"].rsplit("-", 1)[1]) // 30
                            hits = 800 if window % 2 else 304
                        else:
                            hits = 512
                        replica.cache.add(key)
                        replica.counts["running"] += 1
                    delay = 0.080
                    if replica.phase.get("name") == "run4-measure":
                        delay = 0.120
                    time.sleep(delay)
                    with replica.lock:
                        replica.counts["queries"] += 1024
                        replica.counts["hits"] += hits
                        replica.counts["completions"] += 1
                        replica.counts["running"] -= 1
                    body = (
                        b"".join(
                            b"data: "
                            + encoded(
                                {
                                    "id": "chatcmpl-fixture",
                                    "object": "chat.completion.chunk",
                                    "created": 0,
                                    "model": MODEL,
                                    **chunk,
                                }
                            )
                            + b"\n\n"
                            for chunk in (
                                {
                                    "choices": [
                                        {
                                            "index": 0,
                                            "delta": {"role": "assistant", "content": ""},
                                            "finish_reason": None,
                                        }
                                    ]
                                },
                                {
                                    "choices": [
                                        {
                                            "index": 0,
                                            "delta": {"content": "x"},
                                            "finish_reason": None,
                                        }
                                    ]
                                },
                                {"choices": [{"index": 0, "delta": {}, "finish_reason": "length"}]},
                                {
                                    "choices": [],
                                    "usage": {
                                        "prompt_tokens": 1024,
                                        "completion_tokens": 1,
                                        "total_tokens": 1025,
                                    },
                                },
                            )
                        )
                        + b"data: [DONE]\n\n"
                    )
                    self.reply(body, "text/event-stream")
                else:
                    self.send_error(404)

            def log_message(self, format, *args):
                pass

        return Handler


def distribution(values):
    return {
        "n": len(values),
        "p50": percentile(values, 0.5),
        "p95": percentile(values, 0.95),
        "p99": percentile(values, 0.99),
        "max": max(values, default=None),
    }


def wait_listener(url, process, seconds=30):
    """Bound fixture startup before measuring the already-listening chunk path."""
    address = urlsplit(url)
    deadline = time.perf_counter() + seconds
    while time.perf_counter() < deadline:
        if process.poll() is not None:
            raise RuntimeError("fixture service agent exited during startup")
        try:
            with socket.create_connection((address.hostname, address.port), timeout=0.1):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError("fixture service agent startup exceeded bounded wait")


def inspect_records(output, require_full=True):
    result = json.loads((output / "result.json").read_bytes())
    records = []
    for path in output.glob("*.json"):
        value = json.loads(path.read_bytes())
        if "collector_ticks" not in value:
            continue
        records.append(
            {
                "name": value["name"],
                "seconds": value["seconds"],
                "wall_seconds": value["wall_seconds"],
                "loopback_compression": value["loopback_compression"],
                "wall_delivered_rate": value["delivered_rate"] * value["loopback_compression"],
                "q": value["q"],
                "offered": value["offered"],
                "completed": value["completed"],
                "delivered_rate": value["delivered_rate"],
                "missed": value["missed"],
                "missed_reasons": value["missed_reasons"],
                "lateness": distribution([offer["lateness_s"] for offer in value["offers"]]),
                "collector_tick_gap": distribution(
                    [tick["gap_s"] for tick in value["collector_ticks"]][1:]
                ),
                "collector_tick_duration": distribution(
                    [tick["duration_s"] for tick in value["collector_ticks"]]
                ),
                "resources_valid": value["resources_valid"],
                "generator_rss_bytes": distribution(
                    [
                        sample["rss_bytes"]
                        for sample in value["generator_process"]
                        if "rss_bytes" in sample
                    ]
                ),
                "generator_lifetime_peak_rss_bytes": max(
                    (sample.get("peak_rss_bytes", 0) for sample in value["generator_process"]),
                    default=0,
                ),
                "generator_gc_automatic_samples": sum(
                    sample["gc_automatic"] for sample in value["generator_process"]
                ),
                "service_process_rss_bytes": distribution(
                    [
                        sum(
                            process.get("rss_bytes", 0) for process in pair[0]["processes"].values()
                        )
                        for pair in value["resources"]
                    ]
                ),
            }
        )
    records.sort(key=lambda value: value["name"])
    configs = (
        json.loads((output / "configurations.json").read_bytes())
        if (output / "configurations.json").exists()
        else []
    )
    export = json.loads((output / "export-receipt.json").read_bytes())
    data = (output / "service-export.json").read_bytes()
    assert len(data) == export["bytes"] and hashlib.sha256(data).hexdigest() == export["sha256"]
    assert export["complete"] and export["elapsed_s"] <= export["allowance_s"]
    for config in configs:
        assert config["agent_duration_s"] <= 4.5 and config["client_duration_s"] <= 4.5, config
    if require_full:
        assert result["error"] is None, result["error"]
        assert len(result["runs"]) >= 6
        assert all(run["warm_s"] == 600 for run in result["runs"])
        for record in records:
            if record["q"] is not None:
                assert record["wall_delivered_rate"] >= MINIMUM_WALL_RATE, record
                assert abs(record["delivered_rate"] / record["q"] - 1) <= 0.02, record
                assert record["lateness"]["p95"] <= 0.020, record
                assert record["lateness"]["n"] == record["offered"]
            assert record["collector_tick_gap"]["max"] <= 2, record
        assert not any(run["summary"]["invalid_reasons"] for run in result["runs"])
    return {
        "head": result["head"],
        "spec_commit": result["spec_commit"],
        "frozen": result["frozen"],
        "error": result["error"],
        "slots": result["slots"],
        "windows": records,
        "first_comparison": next((row for row in records if row["name"] == "run1-measure"), None),
        "last_comparison": next(
            (row for row in reversed(records) if row["name"].endswith("-measure")), None
        ),
        "configure_client_duration": distribution([row["client_duration_s"] for row in configs]),
        "configure_agent_duration": distribution([row["agent_duration_s"] for row in configs]),
        "export": export,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--compression", type=float, default=4)
    parser.add_argument("--refusal", choices=("visible", "idle"), default="visible")
    args = parser.parse_args()
    if os.name != "posix":
        raise ValueError("Linux /proc agent fixture required")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    root = Path.cwd()
    subprocess.run(
        ["git", "diff", "--exit-code", "HEAD", "--", "python/src/inference_platform"], check=True
    )
    binary = output / "gateway"
    subprocess.run(["go", "build", "-o", str(binary), "./cmd/gateway"], check=True)
    manifest_dir = output / "manifests"
    build(manifest_dir, tenant_salt(b"0" * 32))
    manifest, banks = load(manifest_dir)
    shim_dir = output / "shims"
    shim_dir.mkdir()
    for name in ("docker", "chronyc"):
        path = shim_dir / name
        path.write_text(
            f"#!{sys.executable}\nfrom inference_platform.r1_shim import main\nmain()\n"
        )
        path.chmod(0o755)
    state = {"calls": str(output / "shim-calls.jsonl"), "weight_cache": str(output / "weights")}
    command = backend_command(state["weight_cache"])
    state["image"], state["command"] = IMAGE, command[command.index(IMAGE) + 1 :]
    (output / "shim-state.json").write_bytes(encoded(state))
    environment = {
        **os.environ,
        "PATH": str(shim_dir) + ":" + os.environ["PATH"],
        "R1_SHIM_STATE": str(output / "shim-state.json"),
        "PYTHONPATH": str(root / "python/src"),
        "NO_PROXY": "127.0.0.1,127.0.0.2,127.0.0.3,127.0.0.4,127.0.0.5",
    }
    agents = [f"http://127.0.0.2:9100/gpu-{i}" for i in range(2)]
    backends = [f"http://127.0.0.{i + 2}:8000" for i in range(2)]
    token, credential = "fixture-agent", "fixture-tenant"
    configs = [
        {
            "token": token,
            "replicas": {
                f"/gpu-{i}": {
                    "role": "backend",
                    "directory": str(output / f"gpu-{i}"),
                    "weight_cache": state["weight_cache"],
                    "container": f"r1-vllm-{i}",
                }
                for i in range(2)
            },
        },
        {
            "role": "service",
            "directory": str(output / "service"),
            "token": token,
            "binary": str(binary),
            "redis": "127.0.0.1:6379",
            "namespace": "round85-loopback",
            "secret": base64.urlsafe_b64encode(b"0" * 32).decode().rstrip("="),
            "credential": credential,
            "backends": backends,
            "backend_agents": agents,
            "export_minimum_bytes_per_second": 8388608,
            "export_link_rate_source": (
                "fixture conservative 8 MiB/s; prior idle chunk export "
                "23271814 bytes in 0.522500311 s; not host NIC evidence"
            ),
        },
        {"role": "generator", "directory": str(output / "generator"), "token": token},
    ]
    for config in configs[1:]:
        config.update(
            {
                "cpu_budget": max(8, os.cpu_count()),
                "nic": "lo",
                "nic_limit_bps": 10_000_000_000,
                "nic_limit_source": "loopback fixture 10 Gbit/s; not instance evidence",
                "fixture_memory_bytes": 16 * 1024**3,
            }
        )
    http_config = {
        "backends": backends,
        "backend_agents": agents,
        "gateways": ["http://127.0.0.4:8080", "http://127.0.0.4:8081"],
        "service_agent": "http://127.0.0.4:9100",
        "generator_agent": "http://127.0.0.5:9100",
        "agent_token": token,
        "credential": credential,
        "manifest_sha256": manifest["manifest_sha256"],
        "clock_evidence": {
            "source": "single Linux monotonic clock / fixture chronyc",
            "captured_at": time.time(),
            "usable": True,
        },
    }
    (output / "http-config.json").write_bytes(encoded(http_config))
    processes, servers, replicas = [], [], []
    try:
        for index in range(2):
            replica = Replica(index, banks, args.refusal)
            replicas.append(replica)
            server = ThreadingHTTPServer((f"127.0.0.{index + 2}", 8000), replica.handler())
            server.daemon_threads = True
            threading.Thread(target=server.serve_forever, daemon=True).start()
            servers.append(server)
        for index, config in enumerate(configs):
            path = output / f"agent-{index}.json"
            path.write_bytes(encoded(config))
            log = (output / f"agent-{index}.log").open("wb")
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "inference_platform.r1_agent",
                    "--config",
                    str(path),
                    "--bind",
                    f"127.0.0.{(2, 4, 5)[index]}:9100",
                ],
                env=environment,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            log.close()
            processes.append(process)
        wait_listener(http_config["service_agent"], processes[1])
        # Measure from the driver's namespace before gateways are configured.
        # Restart only the idle service agent to load the measured config.
        link = measure(http_config["service_agent"], token)
        (output / "export-link-probe.json").write_bytes(encoded(link) + b"\n")
        configs[1].update(link["agent_config"])
        processes[1].terminate()
        processes[1].wait(timeout=5)
        path = output / "agent-1.json"
        path.write_bytes(encoded(configs[1]))
        with (output / "agent-1.log").open("ab") as log:
            processes[1] = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "inference_platform.r1_agent",
                    "--config",
                    str(path),
                    "--bind",
                    "127.0.0.4:9100",
                ],
                env=environment,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        wait_listener(http_config["service_agent"], processes[1])
        command = [
            sys.executable,
            "-m",
            "inference_platform.r1_session",
            "--spec-commit",
            SPEC_COMMIT,
            "--manifest",
            str(manifest_dir),
            "--http-config",
            str(output / "http-config.json"),
            "--http-rehearsal-compression",
            str(args.compression),
            "--output",
            str(output / "session"),
        ]
        with (output / "entrypoint.log").open("wb") as log:
            exit_code = subprocess.run(
                command, env=environment, stdout=log, stderr=subprocess.STDOUT, timeout=7200
            ).returncode
        report = inspect_records(output / "session", args.refusal == "visible")
        report.update(
            {
                "entrypoint": command,
                "exit_code": exit_code,
                "agent_process_count": 3,
                "compression": args.compression,
                "GPU_evidence": False,
                "export_link_probe": link,
                "refusals": [row for replica in replicas for row in replica.refusals],
            }
        )
        if args.refusal == "idle":
            assert "without observable work" in report["error"]
            assert not any(slot["consumed"] for slot in report["slots"])
        (output / "receipt.json").write_bytes(encoded(report) + b"\n")
        print(
            json.dumps(
                {
                    key: report[key]
                    for key in (
                        "head",
                        "frozen",
                        "first_comparison",
                        "last_comparison",
                        "configure_client_duration",
                    )
                }
            )
        )
    finally:
        for process in processes:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
        for server in servers:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
