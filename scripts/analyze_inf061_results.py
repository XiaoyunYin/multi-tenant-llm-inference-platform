"""Recount INF-061 cells and scored items from the retained native receipts."""

import argparse
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCORES = ("exact", "wrong", "truncated", "invalid", "failed", "unreached")
QUALITY_PAIRS = {"bf16-repeat": "bf16-first", "fp8": "bf16-first", "awq": "bf16-repeat"}


def read(path):
    return json.loads(path.read_bytes()) if path.is_file() else None


def percentiles(samples):
    ordered = sorted(samples)
    return {
        "n": len(ordered),
        **{
            f"p{percentile}": ordered[(len(ordered) * percentile + 99) // 100 - 1]
            if ordered
            else None
            for percentile in (50, 95)
        },
    }


def count_window(rows, seconds, *, slo=None):
    completed = [row for row in rows if row["outcome"] == "completed"]
    tokens = sum(row["completion_tokens"] for row in completed)
    outcomes = Counter(row["outcome"] for row in rows)
    recounted = {
        "scheduled": len(rows),
        "outcomes": dict(outcomes),
        "completed_per_s": len(completed) / seconds,
        "output_tokens_per_s": tokens / seconds,
        "completed_output_tokens": tokens,
        "ttft_s": percentiles(row["ttft_s"] for row in rows if "ttft_s" in row),
        "tpot_s": percentiles(row["tpot_s"] for row in completed if "tpot_s" in row),
        "rejections": dict(
            Counter(row["gateway_code"] for row in rows if "gateway_code" in row)
        ),
        "pre_content_rejection_rate": outcomes["rejected"] / len(rows),
        "http_429": sum(row.get("http_status") == 429 for row in rows),
    }
    if slo is not None:
        met = sum(
            row["ttft_s"] <= slo[0] and row["completed_s"] <= slo[1]
            for row in completed
        )
        recounted.update(
            slo_met=met,
            slo_met_per_offer=met / len(rows),
            slo_goodput_per_s=met / seconds,
        )
    return recounted


def count_pairs(reference, candidate):
    pairs = Counter(
        (a == "exact", b == "exact") for a, b in zip(reference, candidate, strict=True)
    )
    return {
        "wins": pairs[False, True],
        "losses": pairs[True, False],
        "discordant": pairs[False, True] + pairs[True, False],
        "both_exact": pairs[True, True],
        "both_other": pairs[False, False],
    }


def verified_count(rows, seconds, runtime, *, slo=None):
    result = count_window(rows, seconds, slo=slo)
    if {
        key: value for key, value in result.items() if key != "slo_goodput_per_s"
    } != runtime:
        raise ValueError("inf061_runtime_reducer_disagrees")
    return result


def timed_cell(path, config, expected):
    cell = read(path)
    if cell is None:
        return None
    if (
        len(cell["rows"]) != expected
        or cell["window_s"] != config["window_s"]
        or cell["drain_s"] != config["drain_s"]
    ):
        raise ValueError("inf061_cell_schedule")
    seconds = cell["window_s"] + cell["drain_s"]
    return {
        "seconds": seconds,
        "metrics": verified_count(cell["rows"], seconds, cell["summary"]),
        "retained_gauges": cell["gauges"],
    }


def noisy_cell(path, config):
    cell = read(path)
    if cell is None:
        return None
    if len(cell["b_rows"]) != config["b_window_s"] * config["b_rate"]:
        raise ValueError("inf061_victim_schedule")
    seconds = config["b_window_s"] + config["drain_s"]
    b = verified_count(
        cell["b_rows"],
        seconds,
        cell["b"],
        slo=(config["b_slo_first_content_s"], config["b_slo_completed_s"]),
    )
    a = (
        verified_count(cell["a_rows"], seconds + config["a_lead_s"], cell["a"])
        if cell["a_rows"]
        else None
    )
    return {
        "seconds": seconds,
        "a": a,
        "b": b,
        "retained_gauges": cell["gauges"],
    }


def gateway_sanity(directory, plan):
    labels = [arm["name"] + "-gateway" for arm in plan["starts"]]
    labels += [f"stage-c-{i}" for i in range(len(plan["stage_c"]["arms"]))]
    result = {}
    for label in labels:
        row = read(directory / f"gateway-sanity-{label}.json")
        if row is None:
            result[label] = None
            continue
        if set(row) - {"a", "b", "q"}:
            raise ValueError("inf061_sanity_tenant")
        timed_cap = plan["stage_a"]["output_cap"]
        passed = (
            set(row) == {"a", "b", "q"}
            and row["q"]["http_status"] == 200
            and all(
                row[tenant]["http_status"] == 200
                and row[tenant]["outcome"] == "completed"
                and row[tenant]["completion_tokens"]
                == row[tenant]["max_tokens"]
                == timed_cap
                for tenant in ("a", "b")
            )
        )
        result[label] = {"status": "pass" if passed else "refused", "tenants": row}
    return result


def recount(directory, plan, session):
    benchmark = read(directory / "benchmark.json") or {}
    starts = {}
    quality = {}
    scores = {}
    for arm in plan["starts"]:
        name = arm["name"]
        facts = benchmark.get("arms", {}).get(name)
        cells = {"A": {}, "B": {}, "C": {}}
        if "A" in arm["stages"]:
            config = plan["stage_a"]
            for rate in config["rates"]:
                cells["A"][str(rate)] = timed_cell(
                    directory / f"{name}-a-{rate}.json",
                    config,
                    rate * config["window_s"],
                )
        if "B" in arm["stages"]:
            config = plan["stage_b"]
            for concurrency in config["concurrencies"]:
                cells["B"][str(concurrency)] = timed_cell(
                    directory / f"{name}-b-{concurrency}.json",
                    config,
                    config["requests_by_concurrency"][str(concurrency)],
                )
            if facts and "kv_bound_pass" in facts:
                predicted_slots = facts["kv_blocks"] // config["blocks_per_prompt"]
                if facts["kv_bound_pass"] != (64 > predicted_slots):
                    raise ValueError("inf061_kv_bound_recount")
                if not facts["kv_bound_pass"] and cells["B"]["64"] is not None:
                    raise ValueError("inf061_kv_bound_refused_cell")
        if "C" in arm["stages"]:
            for pressure in plan["stage_c"]["arms"]:
                cells["C"][pressure] = noisy_cell(
                    directory / f"{name}-c-{pressure}.json", plan["stage_c"]
                )
        starts[name] = {"readback": facts, "cells": cells}
        for stage in arm["stages"]:
            if not stage.startswith("quality-"):
                continue
            label = stage.removeprefix("quality-")
            row = read(directory / f"quality-{label}.json")
            if row is None:
                quality[label] = None
                continue
            values = row["scores"]
            counts = Counter(values)
            if (
                len(values) != 1319
                or set(counts) - set(SCORES)
                or counts != row["counts"]
            ):
                raise ValueError("inf061_quality_recount")
            scores[label] = values
            quality[label] = {
                "scheduled": len(values),
                **{key: counts[key] for key in SCORES},
            }
    paired = {}
    for label, base in QUALITY_PAIRS.items():
        paired[label] = (
            count_pairs(scores[base], scores[label])
            if base in scores and label in scores
            else None
        )
        expected = benchmark.get("paired", {}).get(label)
        if paired[label] != expected:
            raise ValueError("inf061_paired_recount")
    rates = attach_costs(starts, session)
    result = {"starts": starts, "quality": quality, "paired": paired, "cost": rates}
    if session.get("attempt") == 2:
        result["gateway_sanity"] = gateway_sanity(directory, plan)
    return result


def attach_costs(starts, session):
    # A and B have one tape. In C, A and B overlap; count wall time once and
    # include validated output from both tenants.
    gpu_rate = session["gpu_node_hourly_usd"]
    full_estimate = session.get("full_estimate_usd")
    cost_rows = {}
    for name, arm in starts.items():
        cells = arm["cells"]
        timed = [
            cell
            for stage in ("A", "B")
            for cell in cells[stage].values()
            if cell is not None
        ]
        seconds = sum(cell["seconds"] for cell in timed)
        tokens = sum(cell["metrics"]["completed_output_tokens"] for cell in timed)
        for cell in cells["C"].values():
            if cell is not None:
                seconds += cell["seconds"] + session["c_lead_s"]
                tokens += cell["b"]["completed_output_tokens"]
                if cell["a"] is not None:
                    tokens += cell["a"]["completed_output_tokens"]
        cost_rows[name] = {
            "timed_seconds": seconds,
            "completed_timed_output_tokens": tokens,
            "gpu_node_usd_per_million": gpu_rate * seconds / 3600 * 1e6 / tokens
            if tokens
            else None,
        }
    total_seconds = sum(row["timed_seconds"] for row in cost_rows.values())
    for row in cost_rows.values():
        tokens = row["completed_timed_output_tokens"]
        row["allocated_session_usd_per_million"] = (
            full_estimate * row["timed_seconds"] / total_seconds * 1e6 / tokens
            if full_estimate is not None and total_seconds and tokens
            else None
        )
    return {
        "full_estimate_usd": full_estimate,
        "gpu_node_hourly_usd": gpu_rate,
        "allocated_timed_seconds": total_seconds,
        "arms": cost_rows,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=Path)
    parser.add_argument(
        "--plan", type=Path, default=ROOT / "docs/INF061_FINAL_PLAN.json"
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = recount(
        args.results / "results", read(args.plan), read(args.results / "session.json")
    )
    args.output.write_bytes(
        (json.dumps(result, sort_keys=True, indent=2) + "\n").encode()
    )


if __name__ == "__main__":
    main()
