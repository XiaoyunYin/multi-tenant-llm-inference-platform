"""Registered calibration, warm-up, measurement and fragile repeat analysis."""

from .r1_metrics import delta, percentile


def resources_valid(result):
    return (
        result["resources_valid"]
        and result["collector_gap_max_s"] <= 2
        and result["lateness_p95_s"] <= 0.020
        and not result["fatal"]
    )


def eligible(result, level):
    return resources_valid(result) and all(
        replica["completed"] >= 100
        and replica["preemptions"] == 0
        and percentile(replica["waiting"], 0.95) == 0
        and percentile(replica["running"], 0.95) >= level / 2
        for replica in result["replicas"]
    )


def candidate(result, w, q):
    return (
        resources_valid(result)
        and abs(result["delivered_rate"] / q - 1) <= 0.02
        and result["admitted"] > 0
        and result["completed"] / result["admitted"] >= 0.99
        and all(
            sum(value > 0 for value in replica["waiting"]) >= 3
            and percentile(replica["waiting"], 0.95) <= w
            and replica["preemptions"] == 0
            for replica in result["replicas"]
        )
    )


def convergence(previous, current, consecutive):
    rates = []
    for before, after in zip(previous, current, strict=True):
        change = delta(before, after)
        rates.append(change["hits"] / change["queries"] if change["queries"] >= 20480 else None)
    return rates, consecutive


def distribution(values, requests=False):
    return {
        "n": len(values),
        "p50": percentile(values, 0.5, requests),
        "p95": percentile(values, 0.95, requests),
        "p99": percentile(values, 0.99, requests),
        "max": max(values, default=None),
    }


def warm_rates(result):
    valid = resources_valid(result) and abs(result["delivered_rate"] / result["q"] - 1) <= 0.02
    rates = []
    for before, after in zip(result["before"], result["after"], strict=True):
        change = delta(before, after)
        rates.append(
            change["hits"] / change["queries"] if valid and change["queries"] >= 20480 else None
        )
    return rates, valid


def summarize(result, w):
    output = {
        "throughput": result["completed"] / 600,
        "TTFT_p50": percentile(result["ttft_s"], 0.5, True),
        "TTFT_p95": percentile(result["ttft_s"], 0.95, True),
        "offered": result["offered"],
        "admitted": result["admitted"],
        "completed": result["completed"],
        "failed": result["failed"],
        "rejected": result["rejected"],
        "censored": result["censored"],
        "ttft": distribution(result["ttft_s"], True),
        "latency": distribution(result["latency_s"], True),
        "TTFT_missing": result["offered"] - len(result["ttft_s"]),
        "invalid_reasons": [],
        "replicas": [],
    }
    if not resources_valid(result):
        output["invalid_reasons"].append("resource/clock/collector/fatal validity")
    if abs(result["delivered_rate"] / result["q"] - 1) > 0.02:
        output["invalid_reasons"].append("delivered offered rate deviation >2%")
    concentrations, loads = [], []
    for left, right in zip(*[x["waiting"] for x in result["replicas"]], strict=True):
        if left + right > 0:
            concentrations.append(max(left, right) / (left + right))
    for left, right in zip(*[x["load"] for x in result["replicas"]], strict=True):
        if left + right > 0:
            loads.append(max(left, right) / (left + right))
    output["queue_concentration"] = distribution(concentrations)
    output["positive_joint_wait_fraction"] = len(concentrations) / max(
        1, len(result["replicas"][0]["waiting"])
    )
    output["load_concentration"] = distribution(loads)
    for replica in result["replicas"]:
        waits = replica["waiting"]
        output["replicas"].append(
            {
                "running": distribution(replica["running"]),
                "waiting": distribution(waits),
                "running_plus_waiting": distribution(replica["load"]),
                "positive_wait_fraction": sum(x > 0 for x in waits) / len(waits) if waits else None,
                "zero_wait_fraction": sum(x == 0 for x in waits) / len(waits) if waits else None,
                "time_above_W_s": sum(
                    interval
                    for wait, interval in zip(waits, replica["interval_s"], strict=True)
                    if wait > w
                ),
                "max_wait_minus_W": max(waits, default=0) - w,
                "completed": replica["completed"],
                "native_deltas": replica["deltas"],
            }
        )
    return output


METRICS = ("throughput", "TTFT_p50", "TTFT_p95")
POLICY_TIES = ("rr", "ll", "hash")


def noise(runs):
    spreads, offending = {}, []
    for mi, metric in enumerate(METRICS):
        ranges = {}
        for policy in POLICY_TIES:
            values = [run["summary"][metric] for run in runs if run["policy"] == policy]
            valid = (
                len(values) >= 2
                and all(value is not None and value > 0 for value in values)
                and not any(
                    run["summary"]["invalid_reasons"] for run in runs if run["policy"] == policy
                )
            )
            spread = (max(values) - min(values)) / (sum(values) / len(values)) if valid else None
            ranges[policy] = spread
        spread = max(ranges.values()) if all(v is not None for v in ranges.values()) else None
        tolerance = max(2 * spread, 0.05) if spread is not None else None
        if tolerance is not None and tolerance > 0.15:
            policy = next(policy for policy in POLICY_TIES if ranges[policy] == spread)
            offending.append((-spread, mi, POLICY_TIES.index(policy), policy))
        spreads[metric] = {
            "policy_ranges": ranges,
            "spread": spread,
            "tolerance": tolerance,
            "validated": tolerance is not None and tolerance <= 0.15,
        }
    paired = {}
    for policy in ("hash", "ll"):
        paired[policy] = {}
        for metric in METRICS:
            differences = []
            validity = []
            for block in ("b1", "b2"):
                selected = {run["policy"]: run["summary"] for run in runs if run["block"] == block}
                left_summary, rr_summary = selected.get(policy), selected.get("rr")
                reasons = (
                    None
                    if left_summary is None or rr_summary is None
                    else left_summary["invalid_reasons"] + rr_summary["invalid_reasons"]
                )
                left = None if left_summary is None else left_summary[metric]
                rr = None if rr_summary is None else rr_summary[metric]
                valid = reasons == [] and left is not None and rr is not None and rr > 0
                validity.append(
                    {
                        "block": block,
                        "valid": valid,
                        "invalid_reasons": reasons,
                        "metric_available": left is not None and rr is not None,
                    }
                )
                differences.append(
                    None if not valid else (left - rr) / rr if metric == "throughput" else rr - left
                )
            paired[policy][metric] = {
                "per_block": differences,
                "per_block_validity": validity,
                "mean": sum(differences) / 2 if all(x is not None for x in differences) else None,
            }
    return {
        "metrics": spreads,
        "conditional_policy": min(offending)[3] if offending else None,
        "paired_differences": paired,
        "basis": "pilot; no confirmatory interval",
    }
