"""INF-036 local native-Go/Redis benchmark. No cloud or paid actions."""

from __future__ import annotations

import argparse
import ctypes
import gzip
import hashlib
import json
import math
import os
import platform
import statistics
import subprocess
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
REDIS = "redis:8.2.9-alpine@sha256:30abb90e62f14b737010746def3ba99cc79fe19dcdb3d37b41f21fc62e7da19d"
NAMESPACE = "mti:inf036:v1"
PORTS = [28700, 28701, 28800, 28801, 28900, 28901, 26379]


def write_json(path, value):
    path.write_text(
        json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def command(*args, **kwargs):
    return subprocess.check_output([str(a) for a in args], cwd=ROOT, **kwargs).decode().strip()


def get(url):
    with urllib.request.urlopen(url, timeout=30) as response:
        return response.read()


def preflight(url):
    payload = {
        "model": "test-model",
        "messages": [{"role": "user", "content": "cpu-probe"}],
        "stream": True,
        "max_tokens": 2,
    }
    request = urllib.request.Request(
        url + "/v1/chat/completions",
        json.dumps(payload).encode(),
        {"Authorization": "Bearer local-dev-token", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        events = [
            line[6:] for line in response.read().decode().splitlines() if line.startswith("data: ")
        ]
        assert response.status == 200 and events[-1] == "[DONE]"
    content, finishes, usage = "", 0, 0
    for data in events[:-1]:
        event = json.loads(data)
        assert "error" not in event and event["object"] == "chat.completion.chunk"
        for choice in event.get("choices", []):
            content += choice.get("delta", {}).get("content", "")
            finishes += choice.get("finish_reason") == "stop"
        if "usage" in event:
            assert event["usage"]["completion_tokens"] == 2
            usage += 1
    assert content == "hello world" and finishes == usage == 1
    return {"status": "PASS", "events": len(events), "exact_content_and_usage": True}


def native_process(pid):
    """Native cumulative CPU and resident/private bytes; no psutil dependency."""
    if os.name == "nt":
        from ctypes import wintypes

        class Memory(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("faults", wintypes.DWORD)] + [
                (name, ctypes.c_size_t)
                for name in (
                    "peak_rss",
                    "rss",
                    "peak_paged",
                    "paged",
                    "peak_nonpaged",
                    "nonpaged",
                    "pagefile",
                    "peak_pagefile",
                    "private",
                )
            ]

        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [
            ctypes.POINTER(wintypes.FILETIME)
        ] * 4
        handle = kernel.OpenProcess(0x0410, False, pid)
        if not handle:
            return None
        try:
            creation, end, system, user = [wintypes.FILETIME() for _ in range(4)]
            if not kernel.GetProcessTimes(
                handle,
                ctypes.byref(creation),
                ctypes.byref(end),
                ctypes.byref(system),
                ctypes.byref(user),
            ):
                return None
            memory = Memory()
            memory.cb = ctypes.sizeof(memory)
            psapi = ctypes.WinDLL("psapi", use_last_error=True)
            psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD]
            if not psapi.GetProcessMemoryInfo(handle, ctypes.byref(memory), memory.cb):
                return None
            cpu = sum((v.dwHighDateTime << 32) | v.dwLowDateTime for v in (system, user)) / 1e7
            return {"cpu_seconds": cpu, "rss_bytes": memory.rss, "private_bytes": memory.private}
        finally:
            kernel.CloseHandle(handle)
    try:
        stat = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        cpu = (int(stat[11]) + int(stat[12])) / os.sysconf("SC_CLK_TCK")
        rss = int(stat[21]) * os.sysconf("SC_PAGE_SIZE")
        return {"cpu_seconds": cpu, "rss_bytes": rss, "private_bytes": None}
    except (OSError, ValueError, IndexError):
        return None


def percentile(values, p):
    if len(values) < math.ceil(20 / (1 - p) - 1e-9):
        return None
    return sorted(values)[math.ceil(p * len(values)) - 1]


def audit_run(path, result):
    counts = {"completed": 0, "failed": 0, "partial": 0, "not_dispatched": 0}
    latency, arrival, lag, longest = [], [], [], []
    warm = dict.fromkeys(counts, 0)
    with gzip.open(path, "rt", encoding="utf-8") as stream:
        for line in stream:
            row = json.loads(line)
            if row["phase"] == "warmup":
                warm[row["outcome"]] += 1
                continue
            counts[row["outcome"]] += 1
            if row["outcome"] == "not_dispatched":
                continue
            assert row["end_ns"] >= row["dispatch_ns"] >= row["planned_ns"]
            lag.append((row["dispatch_ns"] - row["planned_ns"]) / 1e6)
            if row["outcome"] == "completed":
                assert row["status"] == 200 and row["first_content_ns"] > 0
                value = (row["end_ns"] - row["dispatch_ns"]) / 1e6
                latency.append(value)
                arrival.append((row["end_ns"] - row["planned_ns"]) / 1e6)
                longest.append({**row, "execution_ms": value})
                longest = sorted(longest, key=lambda r: r["execution_ms"], reverse=True)[:5]
    assert counts == result["measurement"]["counts"]
    assert warm == result["warmup"]["counts"]
    for key, values in (
        ("execution_ms", latency),
        ("arrival_ms", arrival),
        ("dispatch_lag_ms", lag),
    ):
        for name, p in (("p50", 0.5), ("p99", 0.99)):
            expected = percentile(values, p)
            observed = result["measurement"][key][name]
            # Cross-language float serialization may differ by an ULP. The
            # tolerance is far below the source integer clock's 1ns increment.
            assert (expected is None and observed is None) or (
                expected is not None
                and observed is not None
                and math.isclose(expected, observed, rel_tol=1e-12, abs_tol=1e-9)
            ), (key, name, expected, observed)
    return {
        "counts": counts,
        "warmup_counts": warm,
        "five_longest": longest,
        "execution_ms": {
            "n": len(latency),
            "p50": percentile(latency, 0.5),
            "p99": percentile(latency, 0.99),
            "max": max(latency, default=None),
        },
        "dispatch_lag_p99_ms": percentile(lag, 0.99),
    }


def resources(samples, timing):
    selected = [
        s for s in samples if timing["start_unix_ns"] <= s["unix_ns"] <= timing["end_unix_ns"]
    ]
    result = {}
    for role in ("gateway0", "gateway1", "fake", "load"):
        rows = [(s["unix_ns"], s["processes"][role]) for s in selected if role in s["processes"]]
        if len(rows) < 2:
            result[role] = {"samples": len(rows)}
            continue
        duration = (rows[-1][0] - rows[0][0]) / 1e9
        cores = [
            (b[1]["cpu_seconds"] - a[1]["cpu_seconds"]) / ((b[0] - a[0]) / 1e9)
            for a, b in zip(rows, rows[1:], strict=False)
        ]
        result[role] = {
            "samples": len(rows),
            "sampled_seconds": duration,
            "mean_cpu_cores": (rows[-1][1]["cpu_seconds"] - rows[0][1]["cpu_seconds"]) / duration,
            "peak_interval_cpu_cores": max(cores),
            "min_rss_bytes": min(r[1]["rss_bytes"] for r in rows),
            "max_rss_bytes": max(r[1]["rss_bytes"] for r in rows),
            "max_private_bytes": max((r[1]["private_bytes"] or 0) for r in rows),
        }
    return result


def comparison(runs):
    paired, rates = [], sorted({r["rate"] for r in runs if r["kind"] == "rate"})
    for rate in rates:
        for block in sorted({r["block"] for r in runs if r["kind"] == "rate"}):
            pair = {
                r["mode"]: r
                for r in runs
                if r["kind"] == "rate" and r["rate"] == rate and r["block"] == block
            }
            if len(pair) != 2:
                continue
            direct, gateway = pair["direct"], pair["gateway"]
            entry = {
                "rate": rate,
                "block": block,
                "direct_run": direct["id"],
                "gateway_run": gateway["id"],
            }
            entry["attribution_qualified"] = all(
                not sum(
                    v for k, v in run["result"]["measurement"]["counts"].items() if k != "completed"
                )
                and run["result"]["measurement"]["dispatch_lag_ms"]["p99"] is not None
                and run["result"]["measurement"]["dispatch_lag_ms"]["p99"] <= 5
                for run in (direct, gateway)
            )
            for name in ("p50", "p99"):
                d = direct["result"]["measurement"]["execution_ms"][name]
                g = gateway["result"]["measurement"]["execution_ms"][name]
                entry[f"added_{name}_ms"] = None if d is None or g is None else g - d
            paired.append(entry)
    low = [
        r["result"]["measurement"]["execution_ms"]["p99"]
        for r in runs
        if r["kind"] == "rate" and r["mode"] == "gateway" and r["rate"] == min(rates)
    ]
    baseline = (
        statistics.median(v for v in low if v is not None)
        if any(v is not None for v in low)
        else None
    )
    cells = []
    for rate in rates:
        rows = [
            r for r in runs if r["kind"] == "rate" and r["rate"] == rate and r["mode"] == "gateway"
        ]
        flags = []
        for r in rows:
            m = r["result"]["measurement"]
            p99, lag = m["execution_ms"]["p99"], m["dispatch_lag_ms"]["p99"]
            knee = (
                baseline is not None
                and p99 is not None
                and p99 > 2 * baseline
                and p99 - baseline >= 5
            )
            errors = sum(v for k, v in m["counts"].items() if k != "completed")
            duration = (
                r["result"]["timing"]["end_unix_ns"] - r["result"]["timing"]["start_unix_ns"]
            ) / 1e9
            flags.append(
                {
                    "run": r["id"],
                    "errors": errors,
                    "knee": knee,
                    "generator_qualified": lag is not None and lag <= 5,
                    "achieved_rps_with_drain": m["counts"]["completed"] / duration,
                    "sustainable": not errors
                    and not knee
                    and lag is not None
                    and lag <= 5
                    and m["counts"]["completed"] / duration >= 0.99 * rate,
                }
            )
        cells.append(
            {
                "rate": rate,
                "runs": flags,
                "all_sustainable": bool(flags) and all(f["sustainable"] for f in flags),
            }
        )
    return {
        "paired_quantile_differences": paired,
        "low_rate_p99_baseline_ms": baseline,
        "gateway_rate_cells": cells,
        "interpretation": "per-run differences, not a pooled percentile or confidence bound",
    }


def completion_accounting(delta, result):
    """A successful server write is not a client receipt acknowledgement."""
    server = sum(v.get("inference_gateway_completed_total", 0) for v in delta.values())
    client = sum(result[p]["counts"]["completed"] for p in ("warmup", "measurement"))
    uncertain = sum(
        result[p]["counts"][k] for p in ("warmup", "measurement") for k in ("failed", "partial")
    )
    # Not-dispatched work cannot account for any server completion. With no
    # client failures this still requires exact equality. Never promote a
    # failure to complete merely because the server successfully wrote DONE.
    if not client <= server <= client + uncertain:
        raise AssertionError(("completion observers", server, client, uncertain))
    return {
        "server_completed_including_warmup": server,
        "client_completed_including_warmup": client,
        "server_excess_indeterminate": server - client,
        "basis": "aggregate bounds only; excess is not identity-joined or credited to client completion",
    }


class Campaign:
    def __init__(self, args):
        self.args, self.output = args, args.output.resolve()
        self.container = f"mti-inf036-{os.getpid()}"
        self.work = ROOT / ".cache" / self.container
        self.processes, self.handles, self.pids = [], [], {}
        self.samples, self.stop = [], threading.Event()
        self.runs = []
        suffix = ".exe" if os.name == "nt" else ""
        self.gateway, self.bench = self.work / f"gateway{suffix}", self.work / f"cpu-bench{suffix}"
        inherited = {
            k: v
            for k, v in os.environ.items()
            if not k.startswith(
                ("GATEWAY_", "BACKEND", "ADMISSION_", "REDIS_", "TENANT_", "CACHE_SALT_", "OTEL_")
            )
        }
        self.env = {
            **inherited,
            "GOTOOLCHAIN": "local",
            "GOWORK": "off",
            "GOFLAGS": "",
            "GOCACHE": str(ROOT / ".cache/go-build"),
            "GOMODCACHE": str(ROOT / ".cache/go-mod"),
        }

    def redis(self, *args):
        return command("docker", "exec", self.container, "redis-cli", "--raw", *args)

    def info(self):
        result = {
            k: v
            for line in self.redis("INFO").splitlines()
            if ":" in line
            for k, v in [line.split(":", 1)]
            if k
            in {
                "used_memory",
                "used_memory_rss",
                "used_cpu_sys",
                "used_cpu_user",
                "connected_clients",
                "total_commands_processed",
            }
        }
        result["errorstats"] = self.redis("INFO", "errorstats")
        return result

    def reservations(self):
        prefix = NAMESPACE + ":{admission}:"
        return {
            "global": int(self.redis("ZCARD", prefix + "global:active")),
            "tenant": int(self.redis("ZCARD", prefix + "tenant:tenant-local:active")),
        }

    def metrics(self):
        result = {}
        for i in range(2):
            text = get(f"http://127.0.0.1:{28800 + i}/metrics").decode()
            result[f"gateway{i}"] = {
                line.split()[0]: int(line.split()[1])
                for line in text.splitlines()
                if line.split()
                and line.split()[0]
                in {
                    "inference_gateway_completed_total",
                    "inference_gateway_failed_total",
                    "inference_gateway_partial_total",
                    "inference_gateway_release_failures_total",
                    "inference_gateway_admission_unavailable_total",
                    "inference_gateway_rejected_total",
                }
            }
        return result

    def spawn(self, role, argv, env):
        handle = (self.work / f"{role}.log").open("wb")
        self.handles.append(handle)
        child = subprocess.Popen(
            [str(x) for x in argv], cwd=ROOT, env=env, stdout=handle, stderr=subprocess.STDOUT
        )
        self.processes.append(child)
        self.pids[role] = child.pid
        return child

    def wait_ready(self, url):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if any(p.poll() is not None for p in self.processes):
                raise RuntimeError("owned process exited before readiness; inspect local logs")
            try:
                get(url)
                return
            except OSError:
                time.sleep(0.05)
        raise TimeoutError(url)

    def sample(self):
        while not self.stop.is_set():
            row = {"unix_ns": time.time_ns(), "processes": {}}
            for role, pid in self.pids.copy().items():
                if value := native_process(pid):
                    row["processes"][role] = value
            self.samples.append(row)
            self.stop.wait(0.25)

    def profile(self, run_id, i):
        base = f"http://127.0.0.1:{28900 + i}/debug/pprof/"
        cpu = self.output / f"{run_id}-gateway{i}-cpu.pprof"
        cpu.write_bytes(get(base + "profile?seconds=15"))
        heap = self.output / f"{run_id}-gateway{i}-heap.pprof"
        heap.write_bytes(get(base + "heap?gc=1"))
        for path, index in ((cpu, "cpu"), (heap, "inuse_space"), (heap, "alloc_space")):
            text = command(
                "go",
                "tool",
                "pprof",
                "-top",
                "-nodecount=25",
                f"-sample_index={index}",
                self.gateway,
                path,
                env=self.env,
            )
            (self.output / f"{run_id}-gateway{i}-{index}-top.txt").write_text(
                text + "\n", encoding="utf-8", newline="\n"
            )

    def run(self, mode, rate, block, concurrency=0):
        kind = "profile" if concurrency else "rate"
        run_id = (
            f"{kind}-{'c' + str(concurrency) if concurrency else 'r' + str(rate)}-b{block}-{mode}"
        )
        before_reservations = self.reservations()
        assert before_reservations == {"global": 0, "tenant": 0}
        # Owned isolated Redis only: remove prior tombstone state between cells.
        assert self.redis("FLUSHDB") == "OK"
        before, redis_before = self.metrics(), self.info()
        targets = [f"http://127.0.0.1:{p}" for p in (PORTS[:2] if mode == "direct" else PORTS[2:4])]
        duration = 20 if concurrency else max(self.args.min_seconds, self.args.samples / rate)
        raw = self.output / f"{run_id}.jsonl.gz"
        argv = [
            self.bench,
            "-mode",
            "load",
            "-addresses",
            ",".join(targets),
            "-rate",
            str(rate),
            "-seconds",
            str(duration),
            "-output",
            raw,
        ]
        if concurrency:
            argv += ["-concurrency", str(concurrency)]
        if self.args.precise_dispatch:
            argv += ["-precise-dispatch"]
        process = subprocess.Popen(
            [str(x) for x in argv],
            cwd=ROOT,
            env={**self.env, "GOMAXPROCS": "4"},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.processes.append(process)
        self.pids["load"] = process.pid
        print(f"running {run_id}: {duration:.3f}s", flush=True)
        if concurrency:
            with ThreadPoolExecutor(max_workers=2) as executor:
                time.sleep(3)
                futures = [executor.submit(self.profile, run_id, i) for i in range(2)]
                stdout, stderr = process.communicate(timeout=duration + 40)
                for future in futures:
                    future.result()
        else:
            stdout, stderr = process.communicate(timeout=duration + 40)
        self.pids.pop("load", None)
        if process.returncode:
            raise RuntimeError(
                f"generator exited {process.returncode}: {stderr.decode(errors='replace')[:300]}"
            )
        result = json.loads(stdout)
        time.sleep(0.05)  # allow terminal accounting/release to finish, never TTL expiry
        after, reservations = self.metrics(), self.reservations()
        assert reservations == {"global": 0, "tenant": 0}
        delta = {
            role: {k: after[role][k] - before[role][k] for k in before[role]} for role in before
        }
        entry = {
            "id": run_id,
            "kind": kind,
            "mode": mode,
            "rate": rate,
            "block": block,
            "concurrency": concurrency,
            "result": result,
            "gateway_counter_delta": delta,
            "reservations_after": reservations,
            "redis_before": redis_before,
            "redis_after": self.info(),
            "resources": resources(self.samples, result["timing"]),
        }
        # Preserve source summaries even if the independent audit refuses them.
        write_json(self.output / f"{run_id}.json", {**entry, "audit_status": "pending"})
        if mode == "gateway":
            entry["completion_accounting"] = completion_accounting(delta, result)
        assert all(
            v.get("inference_gateway_release_failures_total", 0) == 0 for v in delta.values()
        )
        entry["independent_raw_audit"] = audit_run(raw, result)
        write_json(self.output / f"{run_id}.json", entry)
        self.runs.append(entry)
        write_json(self.output / "runs.json", self.runs)
        if kind == "rate":
            write_json(self.output / "comparison.json", comparison(self.runs))
        print(
            json.dumps(
                {
                    "run": run_id,
                    "counts": result["measurement"]["counts"],
                    "latency_ms": result["measurement"]["execution_ms"],
                }
            ),
            flush=True,
        )

    def execute(self):
        self.output.mkdir(parents=True, exist_ok=False)
        self.work.mkdir(parents=True, exist_ok=False)
        import socket

        for port in PORTS:
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", port))
        for target, package in ((self.gateway, "./cmd/gateway"), (self.bench, "./cmd/cpu-bench")):
            subprocess.run(
                ["go", "build", "-trimpath", "-o", str(target), package],
                cwd=ROOT,
                env=self.env,
                check=True,
            )
        tenant = json.loads((ROOT / "deploy/local/tenants.json").read_text(encoding="utf-8"))
        tenant["tenants"][0].update(request_rate_limit=100000, max_concurrent=1024)
        tenant_path = self.work / "tenants.json"
        write_json(tenant_path, tenant)
        owned_redis = False
        sampler = None
        try:
            if command("docker", "ps", "-aq", "--filter", f"name=^/{self.container}$"):
                raise RuntimeError("refusing preexisting Redis container")
            owned_redis = True  # also remove a partially started owned container
            command(
                "docker",
                "run",
                "-d",
                "--name",
                self.container,
                "--cpus",
                "2",
                "-p",
                "127.0.0.1:26379:6379",
                REDIS,
                "redis-server",
                "--save",
                "",
                "--appendonly",
                "no",
            )
            deadline = time.monotonic() + 20
            while self.redis("PING") != "PONG":
                if time.monotonic() > deadline:
                    raise TimeoutError("Redis")
                time.sleep(0.1)
            self.spawn(
                "fake",
                [self.bench, "-mode", "fakes", "-addresses", "127.0.0.1:28700,127.0.0.1:28701"],
                {**self.env, "GOMAXPROCS": "4"},
            )
            for i in range(2):
                self.wait_ready(f"http://127.0.0.1:{28700 + i}/health")
                env = {
                    **self.env,
                    "GOMAXPROCS": "2",
                    "GATEWAY_HTTP_ADDR": f"127.0.0.1:{28800 + i}",
                    "GATEWAY_PPROF_ADDR": f"127.0.0.1:{28900 + i}",
                    "BACKEND_DISCOVERY": "",
                    "BACKENDS": "fake-0=http://127.0.0.1:28700,fake-1=http://127.0.0.1:28701",
                    "TENANT_CONFIG_PATH": str(tenant_path),
                    "CACHE_SALT_SECRET_FILE": str(ROOT / "deploy/local/cache-salt.secret.example"),
                    "ADMISSION_MODE": "redis",
                    "REDIS_ADDR": "127.0.0.1:26379",
                    "ADMISSION_NAMESPACE": NAMESPACE,
                    "ADMISSION_GLOBAL_CAPACITY": "1024",
                    "GATEWAY_MAX_CONCURRENT": "512",
                    "OTEL_SDK_DISABLED": "true",
                }
                self.spawn(f"gateway{i}", [self.gateway], env)
                self.wait_ready(f"http://127.0.0.1:{28800 + i}/readyz")
            paths = command("git", "ls-files").splitlines()
            probes = {
                f"endpoint{i}": preflight(f"http://127.0.0.1:{port}")
                for i, port in enumerate(PORTS[:4])
            }
            write_json(self.output / "preflight.json", probes)
            sources = [
                p
                for p in paths
                if p.startswith(("cmd/", "internal/"))
                or p
                in {
                    "go.mod",
                    "go.sum",
                    ".tool-versions",
                    "python/src/inference_platform/cpu_benchmark.py",
                    "scripts/inf036.ps1",
                }
            ]
            write_json(
                self.output / "environment.json",
                {
                    "scope": "local CPU/mock engineering probe",
                    "source_commit": command("git", "rev-parse", "HEAD"),
                    "source_hashes": {
                        p: hashlib.sha256(
                            (ROOT / p).read_bytes().replace(b"\r\n", b"\n")
                        ).hexdigest()
                        for p in sources
                    },
                    "binary_sha256": {
                        p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                        for p in (self.gateway, self.bench)
                    },
                    "go": command("go", "version"),
                    "python": platform.python_version(),
                    "uv": command("uv", "--version"),
                    "os": platform.platform(),
                    "logical_cpus": os.cpu_count(),
                    "redis_image": REDIS,
                    "redis_cpus": 2,
                    "gomaxprocs": {"gateway_each": 2, "fake": 4, "generator": 4},
                    "protocol": {
                        "dispatch_mode": "busy_wait" if self.args.precise_dispatch else "sleep",
                        "blocks": self.args.blocks,
                        "rates": self.args.rates,
                        "minimum_seconds": self.args.min_seconds,
                        "minimum_samples": self.args.samples,
                        "delay_ms": 5,
                        "warmup_seconds": 2,
                        "profile_concurrency": [1, 16, 64] if self.args.profiles else [],
                        "connections": "HTTP/1.1 keep-alive; alternating two front ends",
                        "admission": {
                            "global": 1024,
                            "tenant": 1024,
                            "gateway_each": 512,
                            "tenant_requests_per_second": 100000,
                        },
                        "logging": "default info JSON to local disk; not disabled",
                    },
                    "preexisting_container_count": len(command("docker", "ps", "-q").splitlines())
                    - 1,
                    "clock_basis": "Go monotonic nanoseconds for request intervals; wall-clock labels only align native process samples",
                },
            )
            sampler = threading.Thread(target=self.sample)
            sampler.start()
            for rate in self.args.rates:
                for block in range(1, self.args.blocks + 1):
                    for mode in ["direct", "gateway"] if block % 2 else ["gateway", "direct"]:
                        self.run(mode, rate, block)
            if self.args.profiles:
                for concurrency in (1, 16, 64):
                    self.run("gateway", 100, 1, concurrency)
        except Exception as error:
            write_json(
                self.output / "failure.json",
                {"type": type(error).__name__, "reason": str(error)[:500], "accepted": False},
            )
            raise
        finally:
            self.stop.set()
            if sampler:
                sampler.join(timeout=5)
            write_json(self.output / "resource-samples.json", self.samples)
            for child in reversed(self.processes):
                if child.poll() is None:
                    child.terminate()
                    try:
                        child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait(timeout=5)
            for handle in self.handles:
                handle.close()
            if owned_redis:
                command("docker", "rm", "-f", self.container)
            remaining = command("docker", "ps", "-aq", "--filter", f"name=^/{self.container}$")
            write_json(
                self.output / "teardown.json",
                {
                    "owned_processes_exited": all(c.poll() is not None for c in self.processes),
                    "owned_redis_absent": not remaining,
                    "unrelated_containers": "preserved",
                },
            )
            files = sorted(
                p for p in self.output.iterdir() if p.is_file() and p.name != "SHA256SUMS.txt"
            )
            (self.output / "SHA256SUMS.txt").write_text(
                "".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n" for p in files),
                encoding="utf-8",
                newline="\n",
            )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--rates", type=int, nargs="+", default=[100, 200, 400, 800, 1600, 3200, 6400]
    )
    parser.add_argument("--blocks", type=int, default=3)
    parser.add_argument("--min-seconds", type=float, default=12)
    parser.add_argument("--samples", type=int, default=2400)
    parser.add_argument("--no-profiles", dest="profiles", action="store_false")
    parser.add_argument("--precise-dispatch", action="store_true")
    args = parser.parse_args()
    if (
        args.blocks < 1
        or args.samples < 1
        or args.min_seconds <= 0
        or any(r <= 0 for r in args.rates)
    ):
        parser.error("positive run conditions required")
    Campaign(args).execute()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
