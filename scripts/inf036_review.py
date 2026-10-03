"""Recount retained INF-036 populations and prepare tables for human inspection."""

import argparse
import collections
import gzip
import hashlib
import json
import math
from pathlib import Path


def quantile(values, p):
    if len(values) < math.ceil(20 / (1 - p) - 1e-9):
        return None
    return sorted(values)[math.ceil(p * len(values)) - 1]


def summarize(path):
    for line in (path / "SHA256SUMS.txt").read_text().splitlines():
        digest, name = line.split("  ", 1)
        if (
            Path(name).name != name
            or hashlib.sha256((path / name).read_bytes()).hexdigest() != digest
        ):
            raise ValueError(f"checksum mismatch: {name}")
    runs = json.loads((path / "runs.json").read_text())
    comparison = json.loads((path / "comparison.json").read_text())
    inspected = []
    for run in runs:
        rows = [
            json.loads(line)
            for line in gzip.open(path / (run["id"] + ".jsonl.gz"), "rt")
        ]
        rr = [r for r in rows if r["phase"] == "measurement"]
        counts = collections.Counter(r["outcome"] for r in rr)
        assert all(
            counts[k] == v for k, v in run["result"]["measurement"]["counts"].items()
        )
        latencies = [
            (r["end_ns"] - r["dispatch_ns"]) / 1e6
            for r in rr
            if r["outcome"] == "completed"
        ]
        for p in (0.5, 0.99):
            value = quantile(latencies, p)
            expected = run["result"]["measurement"]["execution_ms"][
                "p50" if p == 0.5 else "p99"
            ]
            assert (value is None and expected is None) or (
                value is not None and abs(value - expected) < 1e-6
            )
        limits = [5, 10, 20, 50, 100, 250, 500, 1000]
        histogram = collections.Counter(
            next((str(bound) for bound in limits if value <= bound), ">1000")
            for value in latencies
        )
        longest = sorted(
            (r for r in rr if r["outcome"] == "completed"),
            key=lambda r: r["end_ns"] - r["dispatch_ns"],
            reverse=True,
        )[:5]
        for row in longest:
            row["execution_ms"] = (row["end_ns"] - row["dispatch_ns"]) / 1e6
            row["first_content_ms"] = (
                row["first_content_ns"] - row["dispatch_ns"]
            ) / 1e6
            row["after_first_content_ms"] = (
                row["end_ns"] - row["first_content_ns"]
            ) / 1e6
            row["dispatch_lag_ms"] = (row["dispatch_ns"] - row["planned_ns"]) / 1e6
        failures = [r for r in rr if r["outcome"] != "completed"]
        inspected.append(
            {
                "run": run["id"],
                "counts": dict(counts),
                "completed_execution_histogram_ms": dict(histogram),
                "five_longest_completed": longest,
                "failure_codes": dict(
                    collections.Counter(r.get("error", "unknown") for r in failures)
                ),
                "failure_planned_seconds_range": [
                    min(r["planned_ns"] for r in failures) / 1e9,
                    max(r["planned_ns"] for r in failures) / 1e9,
                ]
                if failures
                else None,
            }
        )
    boundary = next(
        (
            cell["rate"]
            for cell in comparison["gateway_rate_cells"]
            if any(r["errors"] or r["knee"] for r in cell["runs"])
        ),
        None,
    )
    qualified = [
        cell["rate"]
        for cell in comparison["gateway_rate_cells"]
        if cell["all_sustainable"] and (boundary is None or cell["rate"] < boundary)
    ]
    pairs = [
        row
        for row in comparison["paired_quantile_differences"]
        if row["attribution_qualified"] and row["rate"] in qualified
    ]
    cells = []
    for cell in comparison["gateway_rate_cells"]:
        modes = {}
        for mode in ("direct", "gateway"):
            rr = [
                r
                for r in runs
                if r["kind"] == "rate"
                and r["mode"] == mode
                and r["rate"] == cell["rate"]
            ]
            modes[mode] = {
                "counts": {
                    key: sum(r["result"]["measurement"]["counts"][key] for r in rr)
                    for key in ("completed", "failed", "partial", "not_dispatched")
                },
                "per_run_p50_ms": [
                    r["result"]["measurement"]["execution_ms"]["p50"] for r in rr
                ],
                "per_run_p99_ms": [
                    r["result"]["measurement"]["execution_ms"]["p99"] for r in rr
                ],
                "per_run_dispatch_lag_p99_ms": [
                    r["result"]["measurement"]["dispatch_lag_ms"]["p99"] for r in rr
                ],
            }
        cells.append({**cell, **modes})
    return {
        "directory": path.as_posix(),
        "source_commit": json.loads((path / "environment.json").read_text())[
            "source_commit"
        ],
        "run_count": len(runs),
        "rate_cases": sum(r["kind"] == "rate" for r in runs),
        "profile_cases": sum(r["kind"] == "profile" for r in runs),
        "gateway_capacity": {
            "highest_qualified_tested_rps": max(qualified) if qualified else None,
            "first_error_or_knee_rps": boundary,
            "qualified_tested_rates": qualified,
        },
        "qualified_paired_delta_observed_max_ms": {
            p: max(row["added_" + p + "_ms"] for row in pairs) if pairs else None
            for p in ("p50", "p99")
        },
        "eligible_pairs": pairs,
        "rate_cells": cells,
        "profile_runs": [r for r in runs if r["kind"] == "profile"],
        "distribution_inspection": inspected,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--before", type=Path)
    p.add_argument("--after", type=Path)
    p.add_argument("--capture", type=Path)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    if args.capture:
        if args.before or args.after:
            p.error("use --capture alone or a --before/--after pair")
        report = {"capture": summarize(args.capture)}
        args.output.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        d = report["capture"]
        print(d["gateway_capacity"], d["qualified_paired_delta_observed_max_ms"])
        return
    if not args.before or not args.after:
        p.error("a --capture or a --before/--after pair is required")
    before_env = json.loads((args.before / "environment.json").read_text())
    after_env = json.loads((args.after / "environment.json").read_text())
    for key in (
        "protocol",
        "gomaxprocs",
        "redis_image",
        "redis_cpus",
        "go",
        "python",
        "logical_cpus",
        "os",
    ):
        assert before_env[key] == after_env[key], ("conditions changed", key)
    for key in (
        "cmd/cpu-bench/main.go",
        "python/src/inference_platform/cpu_benchmark.py",
        "scripts/inf036.ps1",
    ):
        assert before_env["source_hashes"][key] == after_env["source_hashes"][key], (
            "harness changed",
            key,
        )
    report = {
        "basis": "observed run-level bounds only; completed populations exclude separately counted failures; all distributions and five longest per run require human interpretation",
        "before": summarize(args.before),
        "after": summarize(args.after),
    }
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    for phase in ("before", "after"):
        d = report[phase]
        print(phase, d["gateway_capacity"], d["qualified_paired_delta_observed_max_ms"])
        for row in d["rate_cells"]:
            print(
                row["rate"],
                row["all_sustainable"],
                row["gateway"]["counts"],
                row["gateway"]["per_run_p50_ms"],
                row["gateway"]["per_run_p99_ms"],
                row["gateway"]["per_run_dispatch_lag_p99_ms"],
            )


if __name__ == "__main__":
    main()
