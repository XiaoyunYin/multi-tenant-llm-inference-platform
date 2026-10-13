"""Fixture-only transport target; never an R1 hardware admission criterion."""

import argparse
import hashlib
import json
import math
from pathlib import Path

from .r1_metrics import percentile
from .r1_spec import encoded

# Dense BF16 L4 peak / (2 * 6.53B non-embedding parameters * 1024 tokens)
# is about 9.05 UNCACHED prefill requests/s per GPU, rounded to 20 combined.
# 40 is a fixture floor, not a bound on warmed comparison q: prefix reuse can
# increase q by 1/(1-h). Report frozen hardware q against demonstrated HTTP
# wall rate and the generator window separately; this is not a session stop rule.
PLAUSIBLE_HARDWARE_RATE = 20
WALL_RATE_MULTIPLE = 2
MINIMUM_WALL_RATE = PLAUSIBLE_HARDWARE_RATE * WALL_RATE_MULTIPLE


def coverage_report(frozen_hardware_q, demonstrated_http_wall_rate, generator_window_q):
    """Readiness evidence comparison only; never changes session admission or q."""
    values = (frozen_hardware_q, demonstrated_http_wall_rate, generator_window_q)
    if any(isinstance(x, bool) or not math.isfinite(x) or x <= 0 for x in values):
        raise ValueError("coverage rates must be finite positive numbers")
    return {
        "frozen_hardware_q": frozen_hardware_q,
        "demonstrated_http_wall_rate": demonstrated_http_wall_rate,
        "generator_window_q": generator_window_q,
        "within_http_demonstration": frozen_hardware_q <= demonstrated_http_wall_rate,
        "within_generator_window": frozen_hardware_q <= generator_window_q,
        "advisory_only": True,
        "in_session_stop_rule": False,
    }


def window_q(receipt):
    """Accept a persisted phase or the compact readiness packet's one-case receipt."""
    if "cases" in receipt:
        if len(receipt["cases"]) != 1:
            raise ValueError("coverage requires one generator window")
        receipt = receipt["cases"][0]
    if receipt["seconds"] != 600:
        raise ValueError("coverage generator window must last 600 seconds")
    return receipt["q"]


def verify_generator_window(directory, head):
    if directory is None:
        raise ValueError("strict fixture verification requires a fresh 600 s q40 window")
    directory = Path(directory)
    phase = json.loads((directory / "generator-600s.json").read_bytes())
    provenance = json.loads((directory / "provenance.json").read_bytes())
    assert provenance["head"] == head
    assert phase["seconds"] == 600 and phase["q"] == 40
    assert phase["loopback_compression"] == 1
    assert math.isclose(phase["wall_seconds"], 600, abs_tol=1e-6)
    rows = [
        json.loads(line) for line in (directory / "offered-trace.jsonl").read_bytes().splitlines()
    ]
    assert len(rows) == phase["offered"] == 24000
    assert [row["index"] for row in rows] == list(range(24000))
    for row in rows:
        observed = row.get("observed_s", row.get("dispatch_s"))
        assert math.isclose(row["scheduled_s"], phase["start_s"] + row["index"] / 40, abs_tol=1e-7)
        assert math.isclose(row["lateness_s"], max(0, observed - row["scheduled_s"]), abs_tol=1e-9)
    p95 = percentile([row["lateness_s"] for row in rows], 0.95)
    assert p95 == phase["lateness_p95_s"] and p95 <= 0.020
    missed = sum(bool(row.get("not_dispatched")) for row in rows)
    assert missed == phase["missed"] and missed / 24000 <= 0.02
    assert abs(phase["delivered_rate"] / 40 - 1) <= 0.02
    outcomes = [
        json.loads(line)
        for line in (directory / "request-outcomes.jsonl").read_bytes().splitlines()
    ]
    dispatched = {row["index"] for row in rows if not row.get("not_dispatched")}
    assert len(outcomes) == len(dispatched)
    assert {row["index"] for row in outcomes} == dispatched
    assert sum(row["completed"] for row in outcomes) == phase["completed"] == len(dispatched)
    assert phase["resources_valid"] and not phase["fatal"]
    assert phase["generator_process"] and all(
        not item["gc_automatic"] for item in phase["generator_process"]
    )
    assert provenance["gc_restored"]
    return {
        "version": "fixture-wall-rate-v2",
        "plausible_two_L4_planning_rate": PLAUSIBLE_HARDWARE_RATE,
        "minimum_wall_rate": MINIMUM_WALL_RATE,
        "multiple": WALL_RATE_MULTIPLE,
        "generator_p95_s": p95,
        "generator_missed": missed,
        "generator_record_hashes": {
            name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
            for name in (
                "generator-600s.json",
                "offered-trace.jsonl",
                "request-outcomes.jsonl",
                "provenance.json",
            )
        },
    }


def main():
    parser = argparse.ArgumentParser(description="Advisory post-freeze readiness coverage")
    parser.add_argument("--hardware-result", type=Path, required=True)
    parser.add_argument("--http-strict", type=Path, required=True)
    parser.add_argument("--generator-window", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    hardware = json.loads(args.hardware_result.read_bytes())
    if hardware.get("fake") or hardware.get("scenario") is not None:
        raise ValueError("hardware coverage requires a real hardware result")
    http = json.loads(args.http_strict.read_bytes())
    window = json.loads(args.generator_window.read_bytes())
    scheduled = [row for row in http["windows"] if row["name"].startswith("run")]
    report = coverage_report(
        hardware["frozen"]["q"],
        min(row["wall_delivered_rate"] for row in scheduled),
        window_q(window),
    )
    report["source_sha256"] = {
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in (
            ("hardware", args.hardware_result),
            ("http", args.http_strict),
            ("generator", args.generator_window),
        )
    }
    args.output.write_bytes(encoded(report) + b"\n")


if __name__ == "__main__":
    main()
