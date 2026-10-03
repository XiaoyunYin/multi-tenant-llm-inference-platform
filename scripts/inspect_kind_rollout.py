"""Recount sanitized kind evidence and enforce per-pod SIGTERM coverage offline."""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import statistics


def inspect(directory):
    logs = json.loads((directory / "logs.json").read_text(encoding="utf-8"))
    routes = {r["request_id"]: r for r in logs if r["msg"] == "request routed"}
    terminal = {r["request_id"]: r for r in logs if r["msg"] == "request terminal"}
    result = {
        "basis": "Codex offline recount of raw rows/logs; reviewer acceptance pending",
        "events": {},
        "analysis_script_sha256": hashlib.sha256(
            Path(__file__).read_bytes()
        ).hexdigest(),
    }
    for event in ("gateway-rollout", "backend-rollout"):
        summary = json.loads((directory / f"{event}.json").read_text(encoding="utf-8"))
        expected_victims = 2 if event == "gateway-rollout" else 1
        if (
            len(summary["stages"]) != expected_victims
            or not summary["sigterm_coverage_passed"]
        ):
            raise ValueError("rollout lacks required victim coverage")
        rows = [
            json.loads(line)
            for line in (directory / f"{event}-streams.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
        ]
        counts = dict(Counter(r["outcome"] for r in rows))
        counts.update({k: counts.get(k, 0) for k in ("completed", "failed", "partial")})
        if counts != summary["counts"] or any(summary["reservations_after"].values()):
            raise ValueError("counts or reservation reconciliation mismatch")
        for row in rows:
            if row["false_complete"] or (row["outcome"] == "completed") != (
                terminal.get(row["request_id"], {}).get("cause") == "completed"
            ):
                raise ValueError("false client/server completion")
        stages = []
        for stage in summary["stages"]:
            gen = stage["generation"]
            pairs = []
            for row in rows:
                route = routes.get(row["request_id"], {})
                matches = (
                    route.get("pod_generation") == gen
                    if event == "gateway-rollout"
                    else route.get("backend_generation") == gen
                )
                if matches:
                    pairs.append(
                        (
                            row["request_id"],
                            route["router_decision_unix_ns"],
                            terminal[row["request_id"]]["time_unix_ns"],
                        )
                    )
            deletion = stage["deletion_observed_unix_ns"]
            signal = stage["sigterm_unix_ns"]
            deleted_live = [rid for rid, start, end in pairs if start <= deletion < end]
            signal_live = [rid for rid, start, end in pairs if start <= signal < end]
            durations = {
                rid: (end - signal) / 1e6 for rid, _, end in pairs if rid in signal_live
            }
            if not signal_live:
                raise ValueError(f"zero streams at SIGTERM: {stage['pod']}")
            if (
                len(deleted_live) != stage["streams_inflight_at_deletion"]
                or len(signal_live) != stage["streams_inflight_at_sigterm"]
            ):
                raise ValueError("per-pod coverage mismatch")
            if durations != {
                r["request_id"]: r["ran_after_sigterm_ms"]
                for r in stage["streams_after_sigterm"]
            }:
                raise ValueError("post-SIGTERM duration mismatch")
            if event == "backend-rollout" and stage["backend_active_at_sigterm"] <= 0:
                raise ValueError("backend native SIGTERM counter is zero")
            stages.append(
                {
                    "pod": stage["pod"],
                    "generation": gen,
                    "inflight_at_deletion": len(deleted_live),
                    "inflight_at_sigterm": len(signal_live),
                    "post_sigterm_ms": durations,
                    "drain_ack_after_sigterm_ms": stage["drain_after_sigterm_ms"],
                    "backend_active_at_sigterm": stage.get("backend_active_at_sigterm"),
                }
            )
        values = [r["duration_ms"] for r in rows]
        buckets = {
            f"[{bound - 1000},{bound})": sum(bound - 1000 <= v < bound for v in values)
            for bound in range(29000, 37000, 1000)
        }
        buckets["outside_28s_36s"] = sum(v < 28000 or v >= 36000 for v in values)
        result["events"][event] = {
            "counts": counts,
            "zero_reservations": True,
            "false_completions": 0,
            "stages": stages,
            "duration_ms": {
                "n": len(values),
                "min": min(values),
                "empirical_median": statistics.median(values),
                "max": max(values),
            },
            "duration_histogram_ms": buckets,
            "longest_rows": sorted(rows, key=lambda r: r["duration_ms"], reverse=True)[
                :5
            ],
            "worker_sequence_counts": dict(Counter(str(r["sequence"]) for r in rows)),
            "percentile_claim": "none; small samples, empirical median only",
        }
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    data = inspect(args.run)
    output = args.output or args.run / "analysis.json"
    output.write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(json.dumps(data, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
