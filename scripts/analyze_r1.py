"""Offline, hash-bound Round117 R1 pilot tables; no cloud or archive writes.

Run from the repository root with uv run --project python --locked python -B
scripts/analyze_r1.py [--check]. Only the thirteen registered inputs and the
supplementally bound warm-up snapshots are read from the private archive. Both
input manifests and the analysis implementation are committed.
"""

import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

from inference_platform.r1_analysis import (
    METRICS,
    POLICY_TIES,
    noise,
    resources_valid,
    summarize,
)
from inference_platform.r1_metrics import percentile

ROOT = Path(__file__).resolve().parents[1]
INDEX = (
    ROOT / "docs/evidence/round117-r1-multizone-session/private-raw-output-hashes.json"
)
INDEX_SHA256 = "0909c3566e9444e1432e162b85ab6fdc0d63d3e6a878a514d8c7cc060829714d"
WARMUP_INDEX = ROOT / "docs/evidence/r1-analysis/warm-up-input-sha256.json"
WARMUP_INDEX_SHA256 = "764dba47ffcd2dee1c3e6ab6814214ab709ed883340b458201ce362e086c3918"
ARCHIVE = ROOT / ".cache/round117/r1-runtime-session"
SOURCE = "972a9275dc1d6ef95264a400e0049e104d4b0777"
SPEC = "3d3c36a1cab1f0901049aeaa96d65782ce1028fb"
NAMES = {
    "result.json",
    "events.jsonl",
    "request-outcomes.jsonl",
    "offered-trace.jsonl",
    "configurations.json",
    "service-export.json",
    "export-receipt.json",
    *(f"run{i}-measure.json" for i in range(1, 7)),
}
COUNTS = ("offered", "admitted", "rejected", "missed", "failed", "censored")
WARMUP_SECONDS = tuple(range(0, 600, 30))
WARMUP_INPUT_COUNT = 6 * len(WARMUP_SECONDS)
MEASUREMENT_MAPPING = (
    (
        "vLLM running/waiting gauges",
        "native",
        "Bound pinned-capture series `vllm:num_requests_running` and "
        "`vllm:num_requests_waiting`.",
    ),
    (
        "Prefix-cache query/hit, preemption, and request-success counter deltas",
        "native",
        "Bound pinned-capture series `vllm:prefix_cache_queries_total`, "
        "`vllm:prefix_cache_hits_total`, `vllm:num_preemptions_total`, and "
        "`vllm:request_success_total`.",
    ),
    (
        "Per-replica/system running+waiting, wait fractions, time above W, "
        "max wait-W, queue/load concentration",
        "derived",
        "Per-sample sums and registered calculations from the native running/waiting "
        "series and frozen W.",
    ),
    (
        "Aggregate token-hit fractions and 30 s warm-up trajectories",
        "derived",
        "Hit-token/query-token ratios and window deltas from the native prefix-cache counters.",
    ),
    (
        "Offered/admitted/completed/429/missed/failed/censored counts; throughput, "
        "TTFT and end-to-end latency",
        "derived",
        "Bound offer/outcome records and their recorded request timestamps; throughput "
        "uses validated completions over the fixed 600 s window.",
    ),
    (
        "Effective-policy/fallback/escape counts",
        "derived",
        "Counts grouped from bound service-export route-decision records joined to "
        "measured request IDs.",
    ),
    (
        "Gateway RSS; service/generator CPU and NIC sample series",
        "native",
        "Bound process and host resource exports.",
    ),
    (
        "Gateway CPU-core equivalents and service/generator CPU/NIC fractions",
        "derived",
        "Adjacent process CPU-second deltas and exported host samples normalized by "
        "the recorded CPU budgets and NIC limits.",
    ),
    (
        "Policy means/repeat ranges, validity labels, and order/drift diagnostics",
        "derived",
        "Bound run records summarized under the registered pairing, validation, and "
        "order rules.",
    ),
    (
        "Eviction events and diagnostic KV-cache usage",
        "unsupported",
        "Not exported by the pinned capture; NA / INF-047 instrumentation remainder. "
        "Preemption delta 0 is the only observed churn signal.",
    ),
    (
        "Per-gateway Go heap/GC and exact active/shared/free/residency/event-lag measures",
        "unsupported",
        "Not exported in these bound inputs; NA / INF-047 instrumentation remainder.",
    ),
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def strict_json(blob):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result

    def constant(_):
        raise ValueError("non-finite JSON number")

    return json.loads(blob, object_pairs_hook=pairs, parse_constant=constant)


def load_inputs():
    index_bytes = INDEX.read_bytes()
    require(
        hashlib.sha256(index_bytes).hexdigest() == INDEX_SHA256,
        "input index hash mismatch",
    )
    records = strict_json(index_bytes)["analysis_input_sha256"]
    require(len(records) == 13, "expected exactly thirteen input hashes")
    blobs, hashes = {}, {}
    # Verify every byte stream before parsing ANY archive input or writing output.
    for row in records:
        path = (ROOT / ".cache/round117" / row["file"]).resolve()
        require(
            path.parent == (ARCHIVE / "generator/session").resolve(),
            "input outside session",
        )
        require(
            path.name in NAMES and path.name not in blobs, "unexpected/duplicate input"
        )
        blob = path.read_bytes()
        digest = hashlib.sha256(blob).hexdigest()
        require(digest == row["sha256"], f"input hash mismatch: {path.name}")
        blobs[path.name], hashes[path.name] = blob, digest
    require(set(blobs) == NAMES, "incomplete input set")

    warm_index_bytes = WARMUP_INDEX.read_bytes()
    warm_index_sha256 = hashlib.sha256(warm_index_bytes).hexdigest()
    require(
        warm_index_sha256 == WARMUP_INDEX_SHA256, "warm-up input index hash mismatch"
    )
    warm_records = strict_json(warm_index_bytes)
    require(
        warm_records.get("schema") == "r1-analysis-warmup-inputs-v1",
        "warm-up index schema",
    )
    rows = warm_records.get("inputs", [])
    require(len(rows) == WARMUP_INPUT_COUNT, "expected 120 warm-up input hashes")
    warm_blobs = {}
    for row in rows:
        path = (ROOT / ".cache/round117" / row["file"]).resolve()
        require(
            path.parent == (ARCHIVE / "generator/session").resolve(),
            "warm-up input outside session",
        )
        match = re.fullmatch(r"run([1-6])-warm-(0|[1-9][0-9]*)\.json", path.name)
        require(match is not None, "unexpected warm-up input name")
        run_id, elapsed_s = map(int, match.groups())
        require(elapsed_s in WARMUP_SECONDS, "unexpected warm-up input window")
        key = f"run{run_id}-warm-{elapsed_s}.json"
        require(key not in warm_blobs, "duplicate warm-up input")
        blob = path.read_bytes()
        digest = hashlib.sha256(blob).hexdigest()
        require(digest == row["sha256"], f"warm-up input hash mismatch: {path.name}")
        warm_blobs[key] = blob
        hashes[f"warmup/{key}"] = digest
    expected_warm_names = {
        f"run{run_id}-warm-{elapsed_s}.json"
        for run_id in range(1, 7)
        for elapsed_s in WARMUP_SECONDS
    }
    require(set(warm_blobs) == expected_warm_names, "incomplete warm-up input set")

    data = {
        name: [strict_json(line) for line in blob.splitlines()]
        if name.endswith(".jsonl")
        else strict_json(blob)
        for name, blob in blobs.items()
    }
    warmups = {name: strict_json(blob) for name, blob in warm_blobs.items()}
    return data, hashes, warmups, warm_index_sha256


def descriptive_distribution(values):
    return {
        "n": len(values),
        "p50": percentile(values, 0.5),
        "p95": percentile(values, 0.95),
        "max": max(values) if values else None,
    }


def system_occupancy_distribution(raw, expected_replicas):
    replicas, samples = raw["replicas"], raw["samples"]
    require(
        len(replicas) == expected_replicas and bool(samples),
        "system occupancy needs every registered replica and at least one sample",
    )
    require(
        all(
            len(replica[series]) == len(samples)
            for replica in replicas
            for series in ("running", "waiting")
        ),
        "per-replica occupancy length differs from the joint sample series",
    )
    values = []
    for sample_index, joint_sample in enumerate(samples):
        require(
            len(joint_sample) == expected_replicas,
            "joint sample is missing a registered replica",
        )
        total = 0
        for replica_id, sample in enumerate(joint_sample):
            replica = replicas[replica_id]
            require(
                sample["running"] == replica["running"][sample_index]
                and sample["waiting"] == replica["waiting"][sample_index],
                "joint sample differs from its bound per-replica occupancy series",
            )
            total += sample["running"] + sample["waiting"]
        values.append(total)
    return {
        "n": len(values),
        "p50": percentile(values, 0.5),
        "p95": percentile(values, 0.95),
        "p99": percentile(values, 0.99),
        "max": max(values),
    }


def routing_records(data):
    expected = {}
    for run_id in range(1, 7):
        raw = data[f"run{run_id}-measure.json"]
        for outcome in raw["outcomes"]:
            request_id = outcome.get("request_id")
            if request_id:
                require(
                    request_id not in expected,
                    "duplicate request id across measured runs",
                )
                expected[request_id] = run_id

    decisions = {}
    for blob in data["service-export.json"]["gateway_logs"].values():
        for line in blob.splitlines():
            event = strict_json(line.encode("utf-8"))
            request_id = event.get("request_id")
            if event.get("msg") != "request terminal" or request_id not in expected:
                continue
            require(
                request_id not in decisions,
                "duplicate request terminal in bound gateway logs",
            )
            decisions[request_id] = {
                "run_id": expected[request_id],
                "policy": event.get("router_policy"),
                "fallback_reason": event.get("router_fallback_reason"),
            }
    require(
        set(decisions) == set(expected),
        "measurement routing decision missing from gateway logs",
    )
    require(
        all(
            row["policy"] and row["fallback_reason"] is not None
            for row in decisions.values()
        ),
        "bound gateway log omits routing decision fields",
    )
    return decisions


def warm_trajectory(warmups, run_id):
    trajectory = []
    for elapsed_s in WARMUP_SECONDS:
        name = f"run{run_id}-warm-{elapsed_s}"
        raw = warmups[f"{name}.json"]
        require(
            raw["name"] == name and raw["seconds"] == 30,
            f"wrong warm-up window: {name}",
        )
        require(len(raw["replicas"]) == 2, f"warm-up replica count: {name}")
        replica_rows = []
        for replica_id, replica in enumerate(raw["replicas"]):
            before, after = raw["before"][replica_id], raw["after"][replica_id]
            deltas = replica["deltas"]
            counters = ("queries", "hits", "preemptions", "completions")
            same_identity = all(
                before[key] == after[key]
                for key in ("generation", "engine", "model_name")
            )
            monotonic = all(after[key] >= before[key] for key in counters)
            deltas_match = monotonic and all(
                deltas[key] == after[key] - before[key] for key in counters
            )
            queries, hits = deltas["queries"], deltas["hits"]
            counters_valid = same_identity and deltas_match and hits <= queries
            replica_rows.append(
                {
                    "replica": replica_id,
                    "hits_tokens": hits,
                    "query_tokens": queries,
                    "token_hit_fraction": hits / queries
                    if counters_valid and queries > 0
                    else None,
                    "same_generation": same_identity,
                    "counters_valid": counters_valid,
                    "query_threshold_met": queries >= 20480,
                    "eligible": counters_valid and queries >= 20480,
                }
            )
        trajectory.append(
            {
                "start_s": elapsed_s,
                "end_s": elapsed_s + 30,
                "replicas": replica_rows,
            }
        )
    return trajectory


def resource_summary(raw, service_export, configuration):
    resources = raw["resources"]
    require(len(resources) > 1, "resource sample set is empty")
    service_samples, generator_samples = [], []
    for sample in resources:
        require(len(sample) == 2, "unexpected resource role count")
        by_role = {row["role"]: row for row in sample}
        require(set(by_role) == {"service", "generator"}, "unexpected resource roles")
        service_samples.append(by_role["service"])
        generator_samples.append(by_role["generator"])

    config_rows = [
        row
        for row in service_export["configurations"]
        if row["configuration"] == configuration
    ]
    complete = []
    for row in config_rows:
        gateways = row["gateways"]
        pids = [str(gateway["pid"]) for gateway in gateways]
        coverage = sum(
            all(pid in sample["processes"] for pid in pids)
            for sample in service_samples
        )
        if len(pids) == 2 and coverage == len(service_samples):
            complete.append(pids)
    require(
        len(complete) == 1,
        "cannot uniquely bind both gateway processes to resource samples",
    )

    gateways = []
    pids = complete[0]
    for gateway_id, pid in enumerate(pids):
        rss_bytes = [
            sample["processes"][pid]["rss_bytes"] for sample in service_samples
        ]
        cpu_cores = []
        for before, after in zip(service_samples, service_samples[1:]):
            before_process = before["processes"][pid]
            after_process = after["processes"][pid]
            elapsed_s = after["monotonic_s"] - before["monotonic_s"]
            delta_cpu = after_process["cpu_seconds"] - before_process["cpu_seconds"]
            if elapsed_s > 0 and delta_cpu >= 0:
                cpu_cores.append(delta_cpu / elapsed_s)
        gateways.append(
            {
                "gateway": gateway_id,
                "cpu_cores": descriptive_distribution(cpu_cores),
                "rss_bytes": descriptive_distribution(rss_bytes),
            }
        )

    roles = {}
    for role, samples in (
        ("service", service_samples),
        ("generator", generator_samples),
    ):
        roles[role] = {
            "samples_n": len(samples),
            "cpu_budget": samples[0]["cpu_budget"],
            "cpu_fraction": descriptive_distribution(
                [sample["cpu_fraction"] for sample in samples]
            ),
            "nic_limit_bps": samples[0]["nic_limit_bps"],
            "nic_limit_source": samples[0]["nic_limit_source"],
            "nic_fraction": descriptive_distribution(
                [sample["nic_fraction"] for sample in samples]
            ),
        }
    return {"gateways": gateways, "roles": roles}


def analyze(data, hashes, warmups, warm_index_sha256):
    result = data["result.json"]
    require(
        result["head"] == SOURCE and result["spec_commit"] == SPEC,
        "source/spec mismatch",
    )
    require(
        result["error"] is None and not result["fake"], "incomplete or fake session"
    )
    require(len(result["runs"]) == 6, "expected six comparison windows")
    require(result["events_sha256"] == hashes["events.jsonl"], "event binding mismatch")
    frozen = result["frozen"]
    offers, outcomes = defaultdict(list), defaultdict(list)
    for row in data["offered-trace.jsonl"]:
        offers[row["phase"]].append({k: v for k, v in row.items() if k != "phase"})
    for row in data["request-outcomes.jsonl"]:
        outcomes[row["phase"]].append({k: v for k, v in row.items() if k != "phase"})
    warm_events = {
        e["id"]: e for e in data["events.jsonl"] if e["event"] == "warmup_complete"
    }
    started = {
        e["id"]: e for e in data["events.jsonl"] if e["event"] == "comparison_started"
    }
    configurations = [entry["configuration"] for entry in data["configurations.json"]]
    service_export = data["service-export.json"]
    route_events = routing_records(data)
    runs, repeat_inputs = [], []
    for position, original in enumerate(result["runs"], 1):
        require(original["id"] == position, "unexpected run order")
        raw = data[f"run{position}-measure.json"]
        phase = raw["name"]
        require(
            phase == f"run{position}-measure" and raw["seconds"] == 600, "wrong window"
        )
        require(raw["q"] == frozen["q"], "rate changed")
        config = started[position]["configuration"]
        require(config in configurations, "configuration missing from export")
        require(
            all(config[k] == frozen[k] for k in ("N", "R", "W", "B")), "limits changed"
        )
        require(config["policy"] == original["policy"], "policy mismatch")
        require(raw["offers"] == offers[phase], "offered trace mismatch")
        require(
            len({x["index"] for x in raw["outcomes"]}) == len(raw["outcomes"]),
            "duplicate outcome index",
        )
        require(
            sorted(raw["outcomes"], key=lambda x: x["index"])
            == sorted(outcomes[phase], key=lambda x: x["index"]),
            "outcome trace mismatch",
        )
        require(len(raw["offers"]) == raw["offered"], "offered denominator mismatch")
        require(
            len(raw["outcomes"]) + raw["missed"] == raw["offered"], "missed mismatch"
        )
        require(
            sum(x["status"] == 429 for x in raw["outcomes"]) == raw["rejected"],
            "429 mismatch",
        )
        completed = [x for x in raw["outcomes"] if x["completed"]]
        require(len(completed) == raw["completed"], "completion mismatch")
        require(
            sorted(x["ttft_s"] for x in completed) == sorted(raw["ttft_s"]),
            "TTFT mismatch",
        )
        require(
            raw["offered"] == sum(raw[k] for k in ("admitted", "rejected", "missed")),
            "admission denominator mismatch",
        )
        summary = summarize(raw, frozen["W"])
        require(
            summary == original["summary"],
            "recomputed summary differs from recorded summary",
        )
        require(
            warm_events[position]["seconds"] == original["warm_s"],
            "warm duration mismatch",
        )
        trajectory = warm_trajectory(warmups, position)
        require(
            all(
                replica["eligible"] for row in trajectory for replica in row["replicas"]
            ),
            "invalid warm-up trajectory window",
        )

        request_ids = [
            outcome["request_id"]
            for outcome in raw["outcomes"]
            if outcome.get("request_id")
        ]
        selected_route_events = [route_events[request_id] for request_id in request_ids]
        require(
            len(selected_route_events) == raw["admitted"],
            "route-decision denominator differs from admitted",
        )
        routing = {
            "decision_n": len(selected_route_events),
            "effective_policy_counts": dict(
                sorted(
                    Counter(event["policy"] for event in selected_route_events).items()
                )
            ),
            "fallback_reason_counts": dict(
                sorted(
                    Counter(
                        event["fallback_reason"] for event in selected_route_events
                    ).items()
                )
            ),
            "fallback_n": sum(
                event["fallback_reason"] != "none" for event in selected_route_events
            ),
            "escape_n": sum(
                event["fallback_reason"] == "backend_load_escape"
                for event in selected_route_events
            ),
        }
        sample_counts = {
            "joint_n": len(raw["samples"]),
            "replicas": [
                {
                    "positive_wait_n": sum(wait > 0 for wait in replica["waiting"]),
                    "zero_wait_n": sum(wait == 0 for wait in replica["waiting"]),
                    "above_W_n": sum(wait > frozen["W"] for wait in replica["waiting"]),
                }
                for replica in raw["replicas"]
            ],
        }
        system_running_plus_waiting = system_occupancy_distribution(raw, frozen["N"])
        require(
            system_running_plus_waiting["n"] == sample_counts["joint_n"],
            "system occupancy denominator differs from joint samples",
        )
        replica_throughput = [
            {
                "replica": replica_id,
                "completed": replica["completed"],
                "seconds": raw["seconds"],
                "requests_per_second": replica["completed"] / raw["seconds"],
            }
            for replica_id, replica in enumerate(summary["replicas"])
        ]
        require(
            sum(row["completed"] for row in replica_throughput) == raw["completed"],
            "per-replica completions do not reconcile to run total",
        )
        native_hit_fractions = []
        for replica_id, replica in enumerate(summary["replicas"]):
            deltas = replica["native_deltas"]
            native_hit_fractions.append(
                {
                    "replica": replica_id,
                    "hits_tokens": deltas["hits"],
                    "query_tokens": deltas["queries"],
                    "fraction": deltas["hits"] / deltas["queries"]
                    if deltas["queries"]
                    else None,
                    "label": "aggregate native token-counter fraction; not per-request hit probability",
                }
            )
        resources = resource_summary(raw, service_export, config)
        runs.append(
            {
                "id": position,
                "block": original["block"],
                "policy": original["policy"],
                "warm_s": original["warm_s"],
                "warm_label": warm_events[position]["label"],
                "counts": {k: raw[k] for k in COUNTS},
                "completed": raw["completed"],
                "ttft_n": len(raw["ttft_s"]),
                "TTFT_missing": summary["TTFT_missing"],
                "metrics": {k: summary[k] for k in METRICS},
                "summary": summary,
                "sample_counts": sample_counts,
                "system_running_plus_waiting": system_running_plus_waiting,
                "replica_throughput": replica_throughput,
                "native_hit_fractions": native_hit_fractions,
                "warm_trajectory": trajectory,
                "routing": routing,
                "resources": resources,
                "validity": {
                    "resources_valid": raw["resources_valid"],
                    "combined_resources_valid": resources_valid(raw),
                    "collector_gap_max_s": raw["collector_gap_max_s"],
                    "lateness_p95_s": raw["lateness_p95_s"],
                    "fatal": raw["fatal"],
                    "delivered_rate": raw["delivered_rate"],
                    "delivery_relative_deviation": abs(
                        raw["delivered_rate"] / raw["q"] - 1
                    ),
                    "invalid_reasons": summary["invalid_reasons"],
                },
            }
        )
        repeat_inputs.append({**original, "summary": summary})
    repeat = noise(repeat_inputs)
    require(repeat == result["noise"], "recomputed noise/paired differences mismatch")
    policies = {}
    for policy in POLICY_TIES:
        selected = [r for r in runs if r["policy"] == policy]
        policies[policy] = {
            metric: {
                "mean": sum(r["metrics"][metric] for r in selected) / len(selected),
                "relative_range": repeat["metrics"][metric]["policy_ranges"][policy],
            }
            for metric in METRICS
        }
    comparisons = []
    for policy in ("hash", "ll"):
        for metric in METRICS:
            paired = repeat["paired_differences"][policy][metric]
            baselines = [r["metrics"][metric] for r in runs if r["policy"] == "rr"]
            tolerance = repeat["metrics"][metric]["tolerance"]
            relative = (
                paired["per_block"]
                if metric == "throughput"
                else [
                    d / rr for d, rr in zip(paired["per_block"], baselines, strict=True)
                ]
            )
            mean_relative = (
                paired["mean"]
                if metric == "throughput"
                else (paired["mean"] / (sum(baselines) / len(baselines)))
            )
            comparisons.append(
                {
                    "policy": policy,
                    "metric": metric,
                    "differences": paired["per_block"],
                    "mean": paired["mean"],
                    "relative_differences": relative,
                    "mean_relative": mean_relative,
                    "tolerance": tolerance,
                    "exceeds": [abs(d) > tolerance for d in relative],
                    "mean_exceeds": abs(mean_relative) > tolerance,
                }
            )
    order_by_block = {}
    for block in ("b1", "b2"):
        ordered = sorted(
            (run for run in runs if run["block"] == block), key=lambda run: run["id"]
        )
        order_by_block[block] = {
            run["policy"]: position for position, run in enumerate(ordered, 1)
        }
    order_drift = []
    throughput_tolerance = repeat["metrics"]["throughput"]["tolerance"]
    for policy in POLICY_TIES:
        b1 = next(
            run for run in runs if run["policy"] == policy and run["block"] == "b1"
        )
        b2 = next(
            run for run in runs if run["policy"] == policy and run["block"] == "b2"
        )
        rr_by_block = {
            block: next(
                run for run in runs if run["policy"] == "rr" and run["block"] == block
            )
            for block in ("b1", "b2")
        }
        relative = [
            (b1["metrics"]["throughput"] - rr_by_block["b1"]["metrics"]["throughput"])
            / rr_by_block["b1"]["metrics"]["throughput"],
            (b2["metrics"]["throughput"] - rr_by_block["b2"]["metrics"]["throughput"])
            / rr_by_block["b2"]["metrics"]["throughput"],
        ]
        order_drift.append(
            {
                "policy": policy,
                "b1_position": order_by_block["b1"][policy],
                "b1_run_id": b1["id"],
                "b2_position": order_by_block["b2"][policy],
                "b2_run_id": b2["id"],
                "position_change": order_by_block["b2"][policy]
                - order_by_block["b1"][policy],
                "throughput_b1": b1["metrics"]["throughput"],
                "throughput_b2": b2["metrics"]["throughput"],
                "throughput_change": b2["metrics"]["throughput"]
                - b1["metrics"]["throughput"],
                "TTFT_p50_change": b2["metrics"]["TTFT_p50"]
                - b1["metrics"]["TTFT_p50"],
                "TTFT_p95_change": b2["metrics"]["TTFT_p95"]
                - b1["metrics"]["TTFT_p95"],
                "throughput_vs_rr_relative": relative,
                "throughput_tolerance": throughput_tolerance,
                "throughput_magnitude_exceeds_tolerance": [
                    abs(value) > throughput_tolerance for value in relative
                ],
            }
        )
    return {
        "schema": "r1-offline-analysis-v1",
        "source_commit": SOURCE,
        "spec_commit": SPEC,
        "spec_sha256": result["spec_sha256"],
        "manifest_sha256": result["manifest_sha256"],
        "index_sha256": INDEX_SHA256,
        "warmup_index_sha256": warm_index_sha256,
        "input_sha256": hashes,
        "frozen": frozen,
        "runs": runs,
        "policies": policies,
        "noise": repeat,
        "comparisons": comparisons,
        "order_drift": order_drift,
        "measurement_mapping": [
            {
                "quantity": quantity,
                "classification": classification,
                "basis": basis,
            }
            for quantity, classification, basis in MEASUREMENT_MAPPING
        ],
    }


def number(value):
    return "NA" if value is None else f"{value:.6f}"


def percent(value):
    return "NA" if value is None else f"{100 * value:.4f}%"


def cohort(run):
    return "/".join(str(run["counts"][k]) for k in COUNTS)


def distribution_cell(
    distribution, fields=("p50", "p95", "p99", "max"), denominator=None
):
    n = distribution["n"]
    sample_text = f"n={n}/{denominator}" if denominator is not None else f"n={n}"
    return (
        " / ".join(number(distribution[field]) for field in fields)
        + f" ({sample_text})"
    )


def resource_cell(distribution, unit="number"):
    values = (distribution["p50"], distribution["p95"], distribution["max"])
    if unit == "percent":
        formatted = [percent(value) for value in values]
    elif unit == "mib":
        formatted = [number(value / (1024 * 1024)) for value in values]
    else:
        formatted = [number(value) for value in values]
    return " / ".join(formatted) + f" (n={distribution['n']})"


def table(lines, headers, rows):
    lines.extend(
        [
            "",
            "| " + " | ".join(headers) + " |",
            "| " + " | ".join("---" for _ in headers) + " |",
        ]
    )
    lines.extend("| " + " | ".join(map(str, row)) + " |" for row in rows)
    lines.append("")


def render(receipt):
    runs, policies, repeated = receipt["runs"], receipt["policies"], receipt["noise"]
    f = receipt["frozen"]
    lines = [
        "# R1 Round117 offline pilot analysis for Xiaoyun's interpretation OK",
        "",
        "Status: **Analysis READY_FOR_REVIEW; DEC-041 item 5 interpretation OK GIVEN by Xiaoyun (Round121 addendum).** "
        "R151/R152 are VERIFIED in Claude Round118, whose Round117 evidence verdict is "
        "NO_BLOCKING_FINDINGS. R153 is VERIFIED in Claude Round120 (NO_BLOCKING_FINDINGS). "
        "R154 is VERIFIED in Claude Round121; analysis verdict is NO_BLOCKING_FINDINGS. "
        "INF-040/INF-047 remain IN_PROGRESS for their other acceptance gates. "
        "The Round116 condition-8 halt was CLEARED by Xiaoyun (DEC-064); caps are unchanged.",
        "",
        "## Evidence and numerical conditions",
        "",
        "All measured numbers inherit these conditions and their table run/cohort. This is "
        "pilot evidence, as required by PLAN section 6. The thirteen original hash-bound "
        "inputs in [the Round117 index](evidence/round117-r1-multizone-session/"
        "private-raw-output-hashes.json) and 120 supplemental warm-up snapshots in "
        "[the warm-up input manifest](evidence/r1-analysis/warm-up-input-sha256.json) "
        "are read from `.cache/round117/r1-runtime-session/`. Both manifests and every "
        "input hash are verified before any archive input is parsed or output written. "
        "The archive is read-only to this reproducer. Configuration literals below are "
        "the frozen registration and historical deployment conditions, not new observations.",
    ]
    table(
        lines,
        ["Condition", "Value / provenance"],
        [
            ["Executable commit", f"`{SOURCE}` (`972a927`), result.json head"],
            [
                "Frozen registration",
                f"`{SPEC}` (`3d3c36a`), result.json spec_commit; "
                "[R1_PRE_REGISTRATION.md](R1_PRE_REGISTRATION.md) sections 5/6",
            ],
            [
                "Hardware / purchase / zone",
                "2 x g6.xlarge, one NVIDIA L4 each; On-Demand with "
                "capacity reservation; us-east-1c (historical task conditions)",
            ],
            [
                "Model / runtime",
                "Qwen/Qwen2.5-7B-Instruct; vLLM v0.29.0 (result.json fitness)",
            ],
            [
                "Frozen admission / arrival rate",
                f"N={f['N']}, R={f['R']}, W={f['W']}, B={f['B']}; "
                f"q={number(f['q'])} offers/s (result.json frozen and per-run configurations)",
            ],
            [
                "Registered workload",
                "One synthetic tenant/salt domain; 384 independent 1,024-token "
                "prefixes; 96 hot receive 80% of potential references; maximum 1 output token, "
                "temperature 0. Mid-band candidate/proxy, not measured exact pressure (section 1).",
            ],
            [
                "Run design",
                "6 runs, 2 matched trace blocks; hash/ll/rr in b1, rr/ll/hash in b2; "
                "own-policy warm 600 s then measured 600 s per run; drain outcomes remain in their cohort",
            ],
            [
                "Denominators",
                "Each run: offered 6,553; dispatched 6,552; missed 1. Throughput = "
                "validated cohort completions / 600 s; TTFT n = admitted completed requests with first "
                "content. Policy means average 2 per-run values; no request pooling.",
            ],
        ],
    )
    lines += [
        "[receipt.json](evidence/r1-analysis/receipt.json) retains full precision and input hashes. "
        "[analyze_r1.py](../scripts/analyze_r1.py) imports the existing `r1_analysis.summarize/noise` "
        "and `r1_metrics.percentile` functions. It reconciles the measurement files with the "
        "offered/outcome JSONL, configuration exports, warm events and recorded summaries. "
        "These tables publish the registered per-replica, queue, latency, routing, resource, "
        "warm-up and order/drift fields from those bound inputs.",
        "",
        "Reproduce offline from the repository root (omit `--check` to regenerate both files):",
        "",
        "```powershell",
        "uv run --project python --locked python -B scripts/analyze_r1.py --check",
        "```",
        "",
        "## Per-run admitted-request results (section 5)",
        "",
        "**TTFT and throughput describe admitted requests only; rejection rates differ by policy.** "
        "Throughput counts validated completions from the scheduled cohort, including completion "
        "during drain, divided by the fixed measurement window. Rejected and missed offers never "
        "receive synthetic TTFT. All admitted requests here completed; none failed or were censored. "
        "Counts in every results table use **O/A/J/M/F/C = offered/admitted/rejected (HTTP 429)/"
        "missed/failed/censored**. The rejection-rate denominator is offered, including missed offers.",
    ]
    table(
        lines,
        [
            "Run / block / policy",
            "O/A/J/M/F/C",
            "Completed / TTFT n",
            "429 / offered",
            "Throughput (req/s)",
            "TTFT p50 (s)",
            "TTFT p95 (s)",
            "Missing TTFT / offered",
        ],
        [
            [
                f"{r['id']} / {r['block']} / {r['policy']}",
                cohort(r),
                f"{r['completed']} / {r['ttft_n']}",
                percent(r["counts"]["rejected"] / r["counts"]["offered"]),
                *(number(r["metrics"][m]) for m in METRICS),
                f"{r['TTFT_missing']} / {r['counts']['offered']}",
            ]
            for r in runs
        ],
    )
    lines += [
        "Nearest-rank percentiles require n x (1-p) >= 20. Both reported percentiles are available "
        "for every run. Missing TTFT equals rejected plus missed here; admitted TTFT missing, "
        "TTFT failure and censoring counts are zero. No admitted-request exclusions are added.",
        "",
        "## Per-policy means and relative repeat ranges (sections 5/6)",
        "",
        "Each raw pair is b1 / b2. The relative range is |x1−x2| / mean(x1,x2). "
        "Cohort pairs and TTFT sample sizes remain separate; means are not pooled percentiles.",
    ]
    rows = []
    for policy in POLICY_TIES:
        selected = [r for r in runs if r["policy"] == policy]
        for metric in METRICS:
            rows.append(
                [
                    policy,
                    metric,
                    "; ".join(cohort(r) for r in selected),
                    " / ".join(str(r["ttft_n"]) for r in selected),
                    " / ".join(number(r["metrics"][metric]) for r in selected),
                    number(policies[policy][metric]["mean"]),
                    percent(policies[policy][metric]["relative_range"]),
                ]
            )
    table(
        lines,
        [
            "Policy",
            "Metric (req/s or s)",
            "O/A/J/M/F/C b1; b2",
            "TTFT n b1 / b2",
            "Raw b1 / b2",
            "Mean",
            "Relative range",
        ],
        rows,
    )
    lines += [
        "## DEC-017 noise floor and paired differences (sections 5/6)",
        "",
        "For each metric, spread is the largest policy relative repeat range above. "
        "Tolerance = max(2 x spread, 0.05), with a hard maximum of 0.15; no clamping. "
        "These tolerances are emulator calibration tolerances, not significance thresholds. "
        "All requested metrics are retained.",
    ]
    table(
        lines,
        ["Metric", "Maximum spread", "Tolerance", "≤15%", "Largest-range policy"],
        [
            [
                m,
                percent(repeated["metrics"][m]["spread"]),
                percent(repeated["metrics"][m]["tolerance"]),
                str(repeated["metrics"][m]["validated"]),
                max(
                    POLICY_TIES,
                    key=lambda p: repeated["metrics"][m]["policy_ranges"][p],
                ),
            ]
            for m in METRICS
        ],
    )
    lines += [
        "No metric triggers the conditional repeat; the conditional slot was not started. "
        "The tolerance calculation alone does not establish emulator accuracy or complete validation.",
        "",
        "Baseline is registered **rr**. Throughput improvement = (policy - rr) / rr; latency "
        "improvement = rr - policy in seconds. Positive means improvement. Quantile differences "
        "are differences of per-run quantiles, not per-request difference quantiles. To compare "
        "a latency difference with a relative tolerance, divide by that block's rr quantile; "
        "for the mean divide the mean seconds difference by the mean rr quantile. "
        "Exceeds compares absolute magnitude with tolerance, so a deterioration can exceed it too. "
        "This is a descriptive comparison, not an added inferential test.",
    ]
    rows = []
    for c in receipt["comparisons"]:
        for j, block in enumerate(("b1", "b2")):
            pair = [
                next(r for r in runs if r["policy"] == p and r["block"] == block)
                for p in (c["policy"], "rr")
            ]
            diff = (
                percent(c["differences"][j])
                if c["metric"] == "throughput"
                else number(c["differences"][j])
            )
            rows.append(
                [
                    c["policy"],
                    c["metric"],
                    block,
                    "; ".join(cohort(r) for r in pair),
                    diff,
                    percent(c["relative_differences"][j]),
                    percent(c["tolerance"]),
                    str(c["exceeds"][j]),
                ]
            )
        context = "; ".join(
            f"{r['id']}:{cohort(r)}" for r in runs if r["policy"] in (c["policy"], "rr")
        )
        diff = percent(c["mean"]) if c["metric"] == "throughput" else number(c["mean"])
        rows.append(
            [
                c["policy"],
                c["metric"],
                "mean",
                context,
                diff,
                percent(c["mean_relative"]),
                percent(c["tolerance"]),
                str(c["mean_exceeds"]),
            ]
        )
    table(
        lines,
        [
            "Policy vs rr",
            "Metric",
            "Block",
            "O/A/J/M/F/C policy; rr (mean: run:counts)",
            "Improvement (fraction % or s)",
            "Relative improvement",
            "Tolerance",
            "Magnitude exceeds",
        ],
        rows,
    )
    lines += [
        "## Registered validity and warm-up checks",
        "",
        "These are retained harness validity outcomes: resources_valid, maximum collector gap "
        "≤2 s, dispatch lateness p95 ≤0.020 s, delivered-rate deviation ≤2%, fatal=false, "
        "and missed offers. resources_valid is the recorded resource/clock check, not a new "
        "independent audit of every raw host sample. No invalidity reason was recorded.",
    ]
    table(
        lines,
        [
            "Run",
            "resources_valid / combined",
            "Gap max (s)",
            "Lateness p95 (s)",
            "Delivered req/s / deviation",
            "Missed / offered",
            "Warm s / label",
        ],
        [
            [
                r["id"],
                f"{r['validity']['resources_valid']} / {r['validity']['combined_resources_valid']}",
                number(r["validity"]["collector_gap_max_s"]),
                number(r["validity"]["lateness_p95_s"]),
                f"{number(r['validity']['delivered_rate'])} / {percent(r['validity']['delivery_relative_deviation'])}",
                f"{r['counts']['missed']} / {r['counts']['offered']}",
                f"{r['warm_s']} / {r['warm_label']}",
            ]
            for r in runs
        ],
    )
    lines += [
        "All runs reached the maximum warm-up and remain valid-unstable under the registered "
        "per-replica convergence rule. They are retained; no steady-state claim follows.",
        "",
        "## Per-run, per-replica queue and native-counter summaries",
        "",
        "These values are taken from each recorded `result.json` run summary; the reproducer "
        "recomputes and requires exact equality before rendering. Occupancy distributions use "
        "the displayed sample denominator. Time above W sums the recorded sample intervals; "
        "the last column is the maximum observed waiting count minus frozen W.",
    ]
    rows = []
    for r in runs:
        for replica_id, replica in enumerate(r["summary"]["replicas"]):
            counts = r["sample_counts"]["replicas"][replica_id]
            sample_n = r["sample_counts"]["joint_n"]
            rows.append(
                [
                    f"{r['id']} / {r['block']} / {r['policy']} / {replica_id}",
                    distribution_cell(replica["running"]),
                    distribution_cell(replica["waiting"]),
                    distribution_cell(replica["running_plus_waiting"]),
                    f"{counts['positive_wait_n']}/{sample_n} ({percent(replica['positive_wait_fraction'])}) / "
                    f"{counts['zero_wait_n']}/{sample_n} ({percent(replica['zero_wait_fraction'])})",
                    f"{number(replica['time_above_W_s'])} / 600 s; "
                    f"{counts['above_W_n']}/{sample_n} samples",
                    replica["max_wait_minus_W"],
                    f"{replica['completed']} / "
                    f"{r['replica_throughput'][replica_id]['requests_per_second']:.6f} req/s",
                ]
            )
    table(
        lines,
        [
            "Run / block / policy / replica",
            "Running p50/p95/p99/max (n)",
            "Waiting p50/p95/p99/max (n)",
            "Running+waiting p50/p95/p99/max (n)",
            "Positive / zero wait (n/denominator; fraction)",
            "Time above W (s/600; sample n)",
            "Max wait-W",
            "Completed requests / validated throughput (req/s; 600 s)",
        ],
        rows,
    )
    rows = []
    for r in runs:
        for native in r["native_hit_fractions"]:
            rows.append(
                [
                    f"{r['id']} / {r['policy']} / {native['replica']}",
                    native["query_tokens"],
                    native["hits_tokens"],
                    f"{number(native['fraction'])} ({native['hits_tokens']} / "
                    f"{native['query_tokens']} query tokens)",
                    r["summary"]["replicas"][native["replica"]]["native_deltas"][
                        "preemptions"
                    ],
                ]
            )
    table(
        lines,
        [
            "Run / policy / replica",
            "Native query-token delta",
            "Native hit-token delta",
            "Token-hit fraction (aggregate counters)",
            "Native preemption delta",
        ],
        rows,
    )
    lines += [
        "Token-hit fraction is native hit-token delta divided by native query-token delta. "
        "It is an aggregate token-counter fraction, not a per-request hit probability.",
        "The pinned capture exported only the vLLM series `vllm:num_requests_running`, "
        "`vllm:num_requests_waiting`, `vllm:prefix_cache_queries_total`, "
        "`vllm:prefix_cache_hits_total`, `vllm:num_preemptions_total`, and "
        "`vllm:request_success_total`. Eviction events and diagnostic KV-cache usage were "
        "not exported; they are NA and remain in the INF-047 instrumentation remainder. "
        "All native preemption deltas are 0, the only observed churn signal.",
        "",
        "## Per-run joint queue, concentration and end-to-end latency",
        "",
        "Queue concentration is defined only for joint samples with positive total waiting; "
        "load concentration is defined only for samples with positive total running+waiting. "
        "The system running+waiting sum adds every replica's native running and waiting "
        "values within each joint sample. A distribution with n=0 is NA, never zero or "
        "balanced. Concentration n is shown against the joint-sample denominator; "
        "end-to-end latency n counts completed requests.",
    ]
    table(
        lines,
        [
            "Run / block / policy",
            "Positive joint wait (n / samples; fraction)",
            "Queue concentration p50/p95/p99/max (n / joint samples)",
            "Load concentration p50/p95/p99/max (n / joint samples)",
            "System running+waiting p50/p95/p99/max (n joint samples)",
            "End-to-end latency p50/p95/p99 (s; n)",
        ],
        [
            [
                f"{r['id']} / {r['block']} / {r['policy']}",
                f"{r['summary']['queue_concentration']['n']}/{r['sample_counts']['joint_n']} "
                f"({percent(r['summary']['positive_joint_wait_fraction'])})",
                distribution_cell(
                    r["summary"]["queue_concentration"],
                    denominator=r["sample_counts"]["joint_n"],
                ),
                distribution_cell(
                    r["summary"]["load_concentration"],
                    denominator=r["sample_counts"]["joint_n"],
                ),
                distribution_cell(r["system_running_plus_waiting"]),
                distribution_cell(r["summary"]["latency"], ("p50", "p95", "p99")),
            ]
            for r in runs
        ],
    )
    lines += [
        "## Effective routing, fallback and escape counts",
        "",
        "Counts below come from bound service-export request-terminal records joined to the "
        "measured outcome request IDs. Route-decision n equals admitted requests; HTTP 429 "
        "rejections have no route decision and remain in the offered/admitted/rejected counts above. "
        "`none` means no fallback. `backend_load_escape` is the registered hash load-escape reason; "
        "escape n is included in fallback n.",
    ]
    table(
        lines,
        [
            "Run / block / configured policy",
            "Route decisions n",
            "Effective policy counts",
            "Fallback reason counts",
            "Fallback n",
            "Escape n",
        ],
        [
            [
                f"{r['id']} / {r['block']} / {r['policy']}",
                r["routing"]["decision_n"],
                "; ".join(
                    f"{key}={value}"
                    for key, value in r["routing"]["effective_policy_counts"].items()
                ),
                "; ".join(
                    f"{key}={value}"
                    for key, value in r["routing"]["fallback_reason_counts"].items()
                ),
                r["routing"]["fallback_n"],
                r["routing"]["escape_n"],
            ]
            for r in runs
        ],
    )
    lines += [
        "## Gateway, service-host, generator and NIC utilization",
        "",
        "Gateway CPU is process CPU-core equivalents derived from adjacent cumulative CPU-second "
        "samples joined to the two gateway PIDs in the bound configuration export. Gateway memory "
        "is resident process memory (RSS), not Go heap. Values show p50 / p95 / max with n. "
        "Service and generator CPU fractions are host-role utilization divided by each exported "
        "role CPU budget; NIC fractions use the exported documented link limit.",
    ]
    rows = []
    for r in runs:
        for gateway in r["resources"]["gateways"]:
            rows.append(
                [
                    f"{r['id']} / {r['block']} / {r['policy']} / gateway-{gateway['gateway']}",
                    resource_cell(gateway["cpu_cores"]),
                    resource_cell(gateway["rss_bytes"], "mib"),
                ]
            )
    table(
        lines,
        [
            "Run / block / policy / gateway",
            "CPU cores p50/p95/max (n intervals)",
            "RSS MiB p50/p95/max (n samples)",
        ],
        rows,
    )
    table(
        lines,
        [
            "Run / block / policy",
            "Service CPU / budget (p50/p95/max; n)",
            "Service NIC / rated limit (p50/p95/max; n)",
            "Generator CPU / budget (p50/p95/max; n)",
            "Generator NIC / rated limit (p50/p95/max; n)",
        ],
        [
            [
                f"{r['id']} / {r['block']} / {r['policy']}",
                resource_cell(
                    r["resources"]["roles"]["service"]["cpu_fraction"], "percent"
                )
                + f"; budget={r['resources']['roles']['service']['cpu_budget']} vCPU",
                resource_cell(
                    r["resources"]["roles"]["service"]["nic_fraction"], "percent"
                )
                + f"; limit={r['resources']['roles']['service']['nic_limit_bps']} bps",
                resource_cell(
                    r["resources"]["roles"]["generator"]["cpu_fraction"], "percent"
                )
                + f"; budget={r['resources']['roles']['generator']['cpu_budget']} vCPU",
                resource_cell(
                    r["resources"]["roles"]["generator"]["nic_fraction"], "percent"
                )
                + f"; limit={r['resources']['roles']['generator']['nic_limit_bps']} bps",
            ]
            for r in runs
        ],
    )
    lines += [
        "The bound exports include process CPU seconds/RSS and service/generator role CPU/NIC "
        "samples. Per-gateway Go heap/GC metrics were not exported; those are NA and remain in "
        "the INF-047 instrumentation remainder.",
        "",
        "## Registered 30 s warm-up token-hit trajectories",
        "",
        "Each row is one bound 30 s snapshot window from elapsed seconds 0-600; each replica's "
        "token-hit fraction is native hit-token delta / query-token delta. The pre-registered "
        "window minimum is 20,480 query tokens per replica; validity requires stable generation "
        "and matching nonnegative counter deltas. All shown windows pass those checks. Fractions "
        "are token-counter ratios, not per-request hit probabilities.",
    ]
    table(
        lines,
        [
            "Run / block / policy",
            "Window (elapsed s)",
            "Replica 0 hit/query tokens (fraction)",
            "Replica 1 hit/query tokens (fraction)",
        ],
        [
            [
                f"{r['id']} / {r['block']} / {r['policy']}",
                f"{row['start_s']}-{row['end_s']}",
                *[
                    f"{replica['hits_tokens']}/{replica['query_tokens']} "
                    f"({percent(replica['token_hit_fraction'])}; {'eligible' if replica['eligible'] else 'invalid'})"
                    for replica in row["replicas"]
                ],
            ]
            for r in runs
            for row in r["warm_trajectory"]
        ],
    )
    lines += [
        "## Policy order and b1-to-b2 drift diagnostics",
        "",
        "Position is within each three-run trace block. The two-block order does not fully "
        "counterbalance three policies. `ll` is always in position 2. Hash's throughput "
        "magnitude exceedance over rr appears only in b1, where hash ran first; no order effect "
        "is inferred from these two blocks.",
    ]
    rows = []
    for order in receipt["order_drift"]:
        rows.append(
            [
                order["policy"],
                f"{order['b1_position']} (run {order['b1_run_id']})",
                f"{order['b2_position']} (run {order['b2_run_id']})",
                f"{order['position_change']:+d}",
                f"{number(order['throughput_b1'])} -> {number(order['throughput_b2'])}; "
                f"change {number(order['throughput_change'])} req/s",
                f"{number(order['TTFT_p50_change'])} s",
                f"{number(order['TTFT_p95_change'])} s",
                " / ".join(
                    percent(value) for value in order["throughput_vs_rr_relative"]
                ),
                " / ".join(
                    str(value)
                    for value in order["throughput_magnitude_exceeds_tolerance"]
                ),
            ]
        )
    table(
        lines,
        [
            "Policy",
            "b1 position",
            "b2 position",
            "Position change",
            "Throughput b1 -> b2",
            "TTFT p50 change",
            "TTFT p95 change",
            "Throughput vs rr b1 / b2",
            "Magnitude > tolerance b1 / b2",
        ],
        rows,
    )
    lines += [
        "## §2.5 measurement mapping",
        "",
        "Each published measurement is labeled native, derived, or unsupported. "
        "Unsupported quantities are NA; no proxy is substituted.",
    ]
    table(
        lines,
        ["Published quantity", "Classification", "Source or handling"],
        [
            [row["quantity"], row["classification"], row["basis"]]
            for row in receipt["measurement_mapping"]
        ],
    )
    lines += [
        "",
        "## Limitations and what this result does not show",
        "",
        "This is one session in one zone with n=2 paired blocks. Two blocks do not fully "
        "counterbalance three policies and cannot support DEC-017's confirmatory interval "
        "(at least three blocks required). There is no confirmatory 90% t-interval or "
        "bounded-no-benefit verdict. The synthetic single-tenant, short-output workload, frozen "
        "admission limits and valid-unstable warm-ups bound every comparison. Differing rejections "
        "mean the admitted TTFT populations differ by policy; these tables do not isolate a "
        "policy effect at matched admissions or establish latency for all offered requests.",
        "",
        "The operator lost SSM endpoint connectivity during run 2 (ll, b1), from "
        "14:59:07Z to 15:01:27Z. The reviewed Round117 evidence records restored contiguous "
        "segments with **no data loss**. This historical context comes from the already reviewed "
        "[session packet](evidence/round117-r1-multizone-session/README.md); no additional raw "
        "outage files are used as analysis inputs and run 2 is retained. The failed termination "
        "receipts triggered the Round117 condition-8 halt; Xiaoyun later cleared it after "
        "Round118 verified complete data, no data loss, and teardown.",
        "",
        "The result does not show general routing superiority, stable production capacity, "
        "multi-tenant isolation, an SLO/goodput result, cost efficiency, EKS performance, "
        "emulator predictive accuracy, exact realized cache pressure, or completed INF-022/INF-047 "
        "instrumentation. No public or career claim is proposed.",
        "",
        "## Interpretation draft for Xiaoyun's OK (DEC-041)",
        "",
        "Hash's throughput was 7.0709% above rr in b1 and 4.8479% above rr in b2; only b1 "
        "exceeded the 5% descriptive tolerance. In the order table, hash ran first in b1 and "
        "third in b2, while ll was always second. The throughput and position pattern coincide "
        "in these two blocks; this does not establish an order effect or a causal policy effect. "
        "With fixed open-loop offers, one missed offer per run and zero failures/censoring, the "
        "throughput-rate difference is the 429-count difference divided by the fixed 600 s "
        "window: hash completed 428 more requests per window than rr in b1 and 298 more in b2, "
        "matching 428 and 298 fewer 429s.",
        "",
        "The native counter table shows hash token-hit fractions of 0.540 / 0.551 in b1 and "
        "0.532 / 0.549 in b2 across replicas; the joint queue table shows ll positive-wait "
        "fractions of 0.423 in b1 and 0.386 in b2. The warm-up trajectory, native hit and queue "
        "tables provide descriptive context only; they do not support a causal claim. All runs "
        "reached the maximum warm-up and remained valid-unstable. Two blocks from one session "
        "support only this limited pilot comparison.",
        "",
    ]
    return "\n".join(lines).encode("utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check", action="store_true", help="compare outputs byte for byte"
    )
    parser.add_argument(
        "--output-dir", type=Path, help="write/check flat outputs in another directory"
    )
    args = parser.parse_args()
    data, hashes, warmups, warm_index_sha256 = load_inputs()
    receipt = analyze(data, hashes, warmups, warm_index_sha256)
    document = render(receipt)
    receipt["analysis_sha256"] = hashlib.sha256(document).hexdigest()
    receipt["reproducer_sha256"] = hashlib.sha256(
        Path(__file__).read_bytes()
    ).hexdigest()
    encoded = (
        json.dumps(receipt, indent=2, sort_keys=True, allow_nan=False) + "\n"
    ).encode("utf-8")
    outputs = {
        (
            args.output_dir / "R1_ANALYSIS.md"
            if args.output_dir
            else ROOT / "docs/R1_ANALYSIS.md"
        ): document,
        (
            args.output_dir / "receipt.json"
            if args.output_dir
            else ROOT / "docs/evidence/r1-analysis/receipt.json"
        ): encoded,
    }
    for path in outputs:
        require(
            not path.resolve().is_relative_to(ARCHIVE.resolve()),
            "output inside archive refused",
        )
    for path, blob in outputs.items():
        if args.check:
            require(path.read_bytes() == blob, f"output differs: {path.name}")
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(blob)
    print(
        "13 original and 120 warm-up hashes verified; six registered windows reconciled; outputs "
        + ("byte-identical." if args.check else "written.")
    )


if __name__ == "__main__":
    main()
