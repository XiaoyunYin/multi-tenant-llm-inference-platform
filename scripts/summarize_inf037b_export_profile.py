"""Summarize the R366 receipt with descriptive affine scaling, not a live gate."""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


def phases(sample, metric="seconds"):
    calls = sample["calls"]
    result = {}
    for call in calls:
        if (
            call["parent"] in ("capture_export", "sanitized_campaign")
            or call["phase"] == "capture_export"
        ):
            phase = call["phase"]
            for prefix, label in (
                ("capture_inventory_raw-", "capture_inventory_source"),
                ("capture_inventory_safe-", "capture_inventory_sanitized"),
                ("capture_inventory_destination-", "capture_inventory_destination"),
            ):
                if phase.startswith(prefix):
                    phase = label
            result[phase] = result.get(phase, 0) + call[metric]
    # Includes the safe reports, semantic comparison, and spec/diagnostic mapping.
    # It is the exact campaign residual after the other disjoint direct calls.
    excluded = sum(
        value
        for key, value in result.items()
        if key.startswith(("raw_reproduce_", "raw_report_", "sanitized_reproduce_"))
        or key in ("sanitized_sources", "materialize_bundle")
    )
    result["report_comparison_and_mapping"] = result["sanitized_campaign"] - excluded
    for key in list(result):
        if key.startswith("sanitized_report_"):
            del result[key]
    result["optimistic_required_subset"] = (
        result["capture_export"]
        - result["sanitized_campaign"]
        + result.get("sanitized_sources", 0)
        + result.get("materialize_bundle", 0)
    )
    return result


def fit(xs, ys):
    mx, my = sum(xs) / len(xs), sum(ys) / len(ys)
    slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys, strict=True)) / sum(
        (x - mx) ** 2 for x in xs
    )
    intercept = my - slope * mx
    errors = [y - (intercept + slope * x) for x, y in zip(xs, ys, strict=True)]
    total = sum((y - my) ** 2 for y in ys)
    return {
        "seconds_per_row": slope,
        "intercept_seconds": intercept,
        "r_squared": 1 - sum(e * e for e in errors) / total if total else 1,
        "maximum_absolute_residual_seconds": max(map(abs, errors)),
        "maximum_relative_residual": max(
            abs(e) / y for e, y in zip(errors, ys, strict=True)
        ),
    }


def summarize(receipt):
    xs = [s["raw_rows"] for s in receipt["samples"]]
    values = [phases(s) for s in receipt["samples"]]
    cpu_values = (
        [phases(s, "cpu_seconds") for s in receipt["samples"]]
        if all("cpu_seconds" in c for s in receipt["samples"] for c in s["calls"])
        else None
    )
    result = {
        "schema": "inf037b-r366-scaling-v1",
        "full_rows": receipt["full_rows"],
        "sample_rows": xs,
        "phases": {},
    }
    for phase in values[0]:
        ys = [v[phase] for v in values]
        model = fit(xs, ys)
        result["phases"][phase] = {
            "sample_seconds": ys,
            **model,
            "affine_full_seconds": model["intercept_seconds"]
            + model["seconds_per_row"] * receipt["full_rows"],
            "maximum_proportional_full_seconds": max(
                y / x * receipt["full_rows"] for x, y in zip(xs, ys, strict=True)
            ),
        }
        pair_predictions = []
        for left in range(len(xs)):
            for right in range(left + 1, len(xs)):
                pair = fit([xs[left], xs[right]], [ys[left], ys[right]])
                pair_predictions.append(
                    pair["intercept_seconds"]
                    + pair["seconds_per_row"] * receipt["full_rows"]
                )
        result["phases"][phase]["pairwise_full_estimates_seconds"] = pair_predictions
        result["phases"][phase]["maximum_pairwise_full_seconds"] = max(pair_predictions)
        if cpu_values is not None:
            cpus = [v[phase] for v in cpu_values]
            cpu_model = fit(xs, cpus)
            result["phases"][phase]["sample_cpu_seconds"] = cpus
            result["phases"][phase]["affine_full_cpu_seconds"] = (
                cpu_model["intercept_seconds"]
                + cpu_model["seconds_per_row"] * receipt["full_rows"]
            )
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("receipt", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--check-sources", action="store_true")
    parser.add_argument("--revision", default="HEAD")
    args = parser.parse_args()
    receipt = json.loads(args.receipt.read_text())
    if args.check_sources:
        root = Path(__file__).resolve().parents[1]
        crlf_sources = []
        for name, expected in receipt["source_sha256"].items():
            content = subprocess.check_output(
                ["git", "-C", str(root), "show", f"{args.revision}:{name}"]
            )
            if hashlib.sha256(content).hexdigest() != expected:
                # Preserve the measured raw digest. Reconstruct uniform CRLF
                # checkout bytes from an LF blob, without ignoring any content.
                if (
                    b"\r" not in content
                    and hashlib.sha256(content.replace(b"\n", b"\r\n")).hexdigest()
                    == expected
                ):
                    crlf_sources.append(name)
                else:
                    raise RuntimeError("source Git-blob mismatch: " + name)
        print(
            f"Source Git-blob joins passed: {len(receipt['source_sha256'])} at {args.revision}; "
            f"exact raw CRLF reconstruction: {crlf_sources}"
        )
    args.output.write_text(
        json.dumps(summarize(receipt), indent=2) + "\n", encoding="utf-8", newline="\n"
    )
