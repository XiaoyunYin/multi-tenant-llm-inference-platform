"""Recount a frozen INF-054 CPU proof with the registered scheduled-offer denominator."""

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from statistics import median

from inf054_autoscaling import BURST_SECONDS, SLO_DONE_S, SLO_TTFT_S
from inf054_eks_workload import BASELINE_S


def read(path):
    return json.loads(path.read_bytes()) if path.is_file() else None


def jsonl(path):
    if not path.is_file():
        return None
    with path.open(encoding="utf-8") as stream:
        return [json.loads(line) for line in stream]


def tally(rows):
    outcomes = Counter(row["outcome"] for row in rows)
    http = Counter(str(row.get("http_status")) for row in rows)
    rejected = Counter(
        row.get("gateway_code", "other")
        for row in rows
        if row.get("http_status") == 429
    )
    met = sum(
        row["outcome"] == "completed"
        and row["ttft_s"] <= SLO_TTFT_S
        and row["completed_s"] <= SLO_DONE_S
        for row in rows
    )
    samples = sorted(row["ttft_s"] for row in rows if row.get("ttft_s") is not None)
    return {
        "offered": len(rows),
        "outcomes": dict(outcomes),
        "http_status": dict(http),
        "http_429_by_code": dict(rejected),
        "slo_completed": met,
        "slo_attainment": met / len(rows) if rows else None,
        "ttft_s": {
            "n": len(samples),
            **{
                f"p{p}": samples[(p * len(samples) + 99) // 100 - 1]
                if samples
                else None
                for p in (50, 95)
            },
        },
    }


def offers_readback(rows, reported):
    second = min(
        (
            r["dispatch_s"] + r["completed_s"]
            for r in rows
            if r.get("replica_ordinal") == 1 and r["outcome"] == "completed"
        ),
        default=None,
    )
    horizon = BASELINE_S + BURST_SECONDS
    bounds = {"baseline": (0, BASELINE_S), "burst": (BASELINE_S, horizon)}
    if second is not None and BASELINE_S < second < horizon:
        bounds.update(pre_usable=(BASELINE_S, second), post_usable=(second, horizon))
    windows = {}
    for name, (start, end) in bounds.items():
        values = tally([r for r in rows if start <= r["scheduled_s"] < end])
        values.update(
            seconds=end - start,
            slo_goodput_per_s=values["slo_completed"] / (end - start),
        )
        windows[name] = values
    if reported and "windows" in reported:
        assert reported["offered"] == len(rows)
        assert reported["second_serving_s"] == second
        assert {
            k: {key: value for key, value in row.items() if key != "http_status"}
            for k, row in windows.items()
        } == reported["windows"]
    by_ordinal = defaultdict(list)
    for row in rows:
        ordinal = row.get("replica_ordinal")
        by_ordinal[str(ordinal) if ordinal is not None else "unassigned"].append(row)
    return {
        "all": tally(rows),
        "by_ordinal": {name: tally(group) for name, group in by_ordinal.items()},
        "first_ordinal_one_completion_s": second,
        "windows": windows,
    }


def downscale_readback(value):
    if not value or "probes" not in value:
        return value
    stop = value["probe_stop_s"]
    probes = value["probes"]
    overlapping = [
        row
        for row in probes
        if stop is not None
        and row["replica_ordinal"] == 1
        and row.get("ttft_s") is not None
        and row["dispatch_s"] + row["ttft_s"]
        < stop
        < row["dispatch_s"] + row["closed_s"]
    ]
    statuses = [row["outcome"] for row in overlapping]
    precontent = sum(row.get("http_status") == 502 for row in probes)
    assert value["probe_overlaps"] == statuses and value["precontent_502"] == precontent
    return {
        "observed": value["observed"],
        "probe_stop_s": stop,
        "probe_count": len(probes),
        "precontent_502": precontent,
        "overlap_by_outcome": dict(Counter(statuses)),
        "partial_close": [
            {
                "dispatch_s": r["dispatch_s"],
                "close_s": r["dispatch_s"] + r["closed_s"],
                "replica_ordinal": r["replica_ordinal"],
                "overlapped_scale_down": r in overlapping,
                "close_after_scale_down_s": (
                    r["dispatch_s"] + r["closed_s"] - stop if stop is not None else None
                ),
            }
            for r in probes
            if r["outcome"] == "partial"
        ],
    }


def telemetry_readback(gauges, scale, summary, proof):
    if gauges is None:
        return None
    starts = [row["at_s"] for row in gauges]
    spacing = [second - first for first, second in zip(starts, starts[1:])]
    assert all(delta > 0 for delta in spacing)
    missed = [row for row in gauges if row["missing"]]
    reasons = Counter(
        (read, error)
        for row in missed
        for read, error in row.get("read_errors", {}).items()
    )
    complete = len(gauges) - len(missed)
    if summary and "complete_samples" in summary:
        assert summary["complete_samples"] == complete
    recorded = (proof or {}).get("telemetry")
    if recorded is not None:
        assert recorded["gauge_rows"] == len(gauges)
        assert recorded["complete_gauge_rows"] == complete
        assert recorded["missing_gauge_rows"] == len(missed)
        assert recorded["scale_rows"] == len(scale or [])
    return {
        "scale_rows": len(scale) if scale is not None else None,
        "partial_scale_rows": sum(bool(row.get("read_errors")) for row in scale or [])
        if scale is not None
        else None,
        "gauge_rows": len(gauges),
        "complete_gauge_rows": complete,
        "missing_gauge_rows": len(missed),
        "missing_reasons": [
            {"read": read, "error_type": error, "rows": count}
            for (read, error), count in sorted(reasons.items())
        ],
        "sample_start_spacing_s": {
            "n": len(spacing),
            "min": min(spacing, default=None),
            "median": median(spacing) if spacing else None,
            "max": max(spacing, default=None),
            "above_cadence_n": sum(delta > 1.01 for delta in spacing),
        },
    }


def recount(directory):
    frozen = directory / "frozen"
    cycle = frozen / "keda-1"
    summary = read(cycle / "summary.json")
    readiness = jsonl(cycle / "readiness.jsonl")
    scale = jsonl(cycle / "scale.jsonl")
    gauges = jsonl(cycle / "gauges.jsonl")
    rows = jsonl(cycle / "offers.jsonl")
    first_two = None
    first_state = {}
    for sample in scale or []:
        if sample["desired"] == 2 and first_two is None:
            first_two = sample["at_s"]
        for replica in sample["replicas"] or []:
            if replica["ordinal"] == 1:
                for key in ("scheduled", "started", "ready", "terminating"):
                    if replica[key]:
                        first_state.setdefault(key, sample["at_s"])
    missing_gauges = sum(row["missing"] for row in gauges or [])
    replica_minutes = sum(
        first["ready"] * (second["at_s"] - first["at_s"]) / 60
        for first, second in zip(gauges or [], (gauges or [])[1:])
        if first["ready"] is not None
    )
    if summary and gauges is not None and "samples" in summary:
        assert summary["samples"] == len(gauges)
        reported_minutes = summary["ready_replica_minutes"]
        if reported_minutes is None:
            assert all(row["ready"] is None for row in gauges)
        else:
            assert reported_minutes == replica_minutes
    tsdb = read(cycle / "tsdb-receipt.json")
    if tsdb:
        path = cycle / "tsdb.tar.gz"
        with path.open("rb") as archive:
            assert hashlib.file_digest(archive, "sha256").hexdigest() == tsdb["sha256"]
        assert path.stat().st_size == tsdb["bytes"]
    proof = read(frozen / "proof.json")
    telemetry = (
        telemetry_readback(gauges, scale, summary, proof)
        if any("read_errors" in row for row in gauges or [])
        else None
    )
    return {
        **({"telemetry": telemetry} if telemetry is not None else {}),
        "readiness": next((r for r in readiness or [] if r["event"] == "ready"), None),
        "null_endpoint_slices": max(
            (r.get("null_endpoint_slices", 0) for r in readiness), default=0
        )
        if readiness is not None
        else None,
        "absent_endpoint_slices": max(
            (r.get("absent_endpoint_slices", 0) for r in readiness), default=0
        )
        if readiness is not None
        else None,
        "engine_render": read(frozen / "engine-render.json"),
        "chart_checks": read(frozen / "chart-checks.json"),
        "keda_install": read(frozen / "keda-install.json"),
        "scale_samples": len(scale) if scale is not None else None,
        "gauge_samples": len(gauges) if gauges is not None else None,
        "missing_gauge_samples": missing_gauges if gauges is not None else None,
        "ready_replica_minutes": (
            replica_minutes if gauges and missing_gauges < len(gauges) else None
        ),
        "desired_two_first_s": first_two,
        "ordinal_one_state_s": first_state or None,
        "offers": offers_readback(rows, summary) if rows is not None else None,
        "downscale": downscale_readback((summary or {}).get("downscale")),
        "tsdb": tsdb,
        "proof": proof,
        "session": read(directory / "session.json"),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("evidence", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    data = recount(args.evidence)
    args.output.write_bytes(
        (json.dumps(data, sort_keys=True, indent=2) + "\n").encode()
    )


if __name__ == "__main__":
    main()
