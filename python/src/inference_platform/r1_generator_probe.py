"""Real dispatcher/tokenizer/journal sizing with explicitly stubbed service work.

Run on the generator shape or a documented local proxy. No network or AWS calls.
"""

import argparse
import concurrent.futures
import gc
import hashlib
import json
import os
import platform
import subprocess
import threading
import time
from pathlib import Path

from . import r1_transport
from .r1_fake import Fake
from .r1_loopback import distribution
from .r1_manifest import load
from .r1_records import Journal
from .r1_session import RealClock
from .r1_spec import encoded
from .stage_c_tokenizer import pinned_tokenizer

LEVELS = (1, 2, 4, 8, 12, 16, 24, 32)


def generator(directory, manifest, banks):
    io = r1_transport.HTTP.__new__(r1_transport.HTTP)
    io.clock, io.compression = RealClock(), 1
    io.output, io.preparing = directory, False
    io.config = {
        "backends": ["http://127.0.0.1:1", "http://127.0.0.2:1"],
        "gateways": ["http://127.0.0.1:1", "http://127.0.0.2:1"],
    }
    io.manifest, io.tokenizer = manifest, pinned_tokenizer()
    io.workload = {row["id"]: row for row in banks["workload.jsonl"]}
    io.cal_first = {tuple(row["tokens"][:16]) for bank in banks.values() for row in bank}
    io.phase_number, io.corpus_sequence, io.archive_error = 0, 0, None
    io.inflight_condition, io.inflight = threading.Condition(), 0
    io.journal = Journal(directory)
    io.executor = concurrent.futures.ThreadPoolExecutor(max_workers=128)
    io.futures = []
    native = Fake("success")
    io.snapshots = lambda deadline: native.snapshots(5)
    io.resources = lambda deadline: [
        {
            "cpu_budget": 8,
            "memory_bytes": 16 * 1024**3,
            "nic_limit_bps": 1e9,
            "nic_limit_source": "stub (not NIC evidence)",
            "nic_fraction": 0,
            "clock_usable": True,
            "cpu_fraction": 0,
        }
        for _ in range(2)
    ]
    io.record_native_completion = lambda backend, result: None
    return io


def run_phase(output, manifest, banks, name, seconds, latency, level=None, q=None):
    output.mkdir(parents=True, exist_ok=False)
    io = generator(output, manifest, banks)
    costs = []
    original_row = r1_transport.row

    def timed_row(*args):
        started = time.perf_counter()
        value = original_row(*args)
        costs.append(time.perf_counter() - started)
        return value

    def stream(url, value, deadline, gateway):
        time.sleep(latency)
        return {
            "completed": True,
            "censored": False,
            "status": 200,
            "backend_id": "gpu-0",
            "ended_s": io.clock.now(),
            "ttft_s": latency,
            "latency_s": latency,
        }

    io.stream = stream
    enabled, started = gc.isenabled(), io.clock.now()
    journal_closed = False
    r1_transport.row = timed_row
    try:
        result = io.phase(
            name, seconds, latency + 2, level=level, q=q, deadline=started + seconds + latency + 10
        )
        io.executor.shutdown(wait=True)
        io.journal.close(io.clock.now() + 5)
        journal_closed = True
        assert io.archive_error is None and io.inflight == 0
        result["gc_before_phase_s"] = result.get("gc_before_phase_s", 0)
        (output / (name + ".json")).write_bytes(encoded(result) + b"\n")
        provenance = {
            "head": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
            "gc_restored": gc.isenabled() == enabled,
            "actual_wall_elapsed_s": io.clock.now() - started,
            "service_resources_and_stream_are_fixtures": True,
            "stream_latency_s": latency,
        }
        (output / "provenance.json").write_bytes(encoded(provenance) + b"\n")
        offers = result["offers"]
        first, steady, seen = [], [], set()
        for offer in offers:
            target = steady if offer["worker"] in seen else first
            target.append(offer["lateness_s"])
            seen.add(offer["worker"])
        return {
            **provenance,
            "name": name,
            "level": level,
            "seconds": seconds,
            "q": q,
            "offered": result["offered"],
            "completed": result["completed"],
            "missed": result["missed"],
            "delivered_wall_rate": result["delivered_rate"],
            "lateness_s": distribution([offer["lateness_s"] for offer in offers]),
            "first_offer_lateness_s": distribution(first),
            "steady_lateness_s": distribution(steady),
            "initial_offer_count": len(first) if level is not None else None,
            "reissue_count": len(steady) if level is not None else None,
            "reissue_rate_per_wall_s": len(steady) / seconds if level is not None else None,
            "row_construction_s": distribution(costs),
            "process_cpu_s_per_offer": (
                result["generator_process"][-1]["cpu_seconds"]
                - result["generator_process"][0]["cpu_seconds"]
            )
            / len(offers),
            "qualified_20ms": result["lateness_p95_s"] <= 0.020
            and not result["fatal"]
            and result["failed"] == 0,
            "generator_rss_bytes": distribution(
                [row["rss_bytes"] for row in result["generator_process"]]
            ),
            "record_hashes": {
                path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in output.iterdir()
                if path.is_file()
            },
        }
    finally:
        r1_transport.row = original_row
        io.executor.shutdown(wait=True)
        if not journal_closed and io.journal.error is None:
            io.journal.close(io.clock.now() + 5)


def summarize_sweep(cases):
    """Keep nonmonotone failures; distinguish repeat offers from worker startup."""
    sweep = [case for case in cases if "nominal_stub_rate" in case]
    qualified = [case for case in sweep if case["qualified_20ms"]]
    best = max(qualified, key=lambda case: case["reissue_rate_per_wall_s"], default=None)
    failed = [case for case in sweep if not case["qualified_20ms"]]
    higher_failed = [
        case
        for case in failed
        if best is not None and case["nominal_stub_rate"] > best["nominal_stub_rate"]
    ]
    return {
        "highest_qualified_tested_reissue_rate": best["reissue_rate_per_wall_s"] if best else None,
        "highest_qualified_case_nominal_rate": best["nominal_stub_rate"] if best else None,
        "first_failed_nominal_rate": min(
            (case["nominal_stub_rate"] for case in failed), default=None
        ),
        "first_higher_failed_nominal_rate": min(
            (case["nominal_stub_rate"] for case in higher_failed), default=None
        ),
        "failed_nominal_rates": [case["nominal_stub_rate"] for case in failed],
        "exact_maximum_established": False,
        "all_lower_loads_certified": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mode", choices=("window", "staircase"), required=True)
    parser.add_argument("--host-description", required=True)
    args = parser.parse_args()
    subprocess.run(
        ["git", "diff", "--exit-code", "HEAD", "--", "python/src/inference_platform"], check=True
    )
    args.output.mkdir(parents=True, exist_ok=False)
    manifest, banks = load(args.manifest)
    cases = []
    if args.mode == "window":
        cases.append(
            run_phase(args.output / "window", manifest, banks, "generator-600s", 600, 0.08, q=40)
        )
    else:
        # Every level uses a 90 s wall window. At the loose TWO-L4 envelope
        # 20 req/s the 64-worker startup burst is < 3.6% of offers at level32.
        for level in LEVELS:
            cases.append(
                run_phase(
                    args.output / f"level-{level}",
                    manifest,
                    banks,
                    f"staircase-{level}",
                    90,
                    2 * level / 20,
                    level=level,
                )
            )
            print(json.dumps(cases[-1]), flush=True)
        # Keep 32 workers per backend; change only stub request latency to find
        # a tested reissue knee. These are local sizing probes, not R1 windows.
        for rate in (40, 80, 120, 160, 200, 240, 320, 400, 640, 800, 1200, 1600):
            cases.append(
                run_phase(
                    args.output / f"rate-{rate}",
                    manifest,
                    banks,
                    "staircase-32",
                    60,
                    64 / rate,
                    level=32,
                )
            )
            cases[-1]["nominal_stub_rate"] = rate
            print(json.dumps(cases[-1]), flush=True)
            if rate >= 400 and not cases[-1]["qualified_20ms"]:
                break
    report = {
        "head": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        "host_description": args.host_description,
        "platform": platform.platform(),
        "python": platform.python_version(),
        "logical_cpus_visible": os.cpu_count(),
        "cpu_affinity": sorted(os.sched_getaffinity(0))
        if hasattr(os, "sched_getaffinity")
        else None,
        "cgroup_cpu_max": Path("/sys/fs/cgroup/cpu.max").read_text().strip()
        if Path("/sys/fs/cgroup/cpu.max").exists()
        else None,
        "cgroup_memory_max": Path("/sys/fs/cgroup/memory.max").read_text().strip()
        if Path("/sys/fs/cgroup/memory.max").exists()
        else None,
        "manifest_sha256": manifest["manifest_sha256"],
        "cases": cases,
    }
    if any("nominal_stub_rate" in case for case in cases):
        report.update(summarize_sweep(cases))
    (args.output / "receipt.json").write_bytes(encoded(report) + b"\n")


if __name__ == "__main__":
    main()
