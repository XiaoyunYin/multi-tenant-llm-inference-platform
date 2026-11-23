"""Closed streaming export, per-level reduction and laptop readback checks."""

import hashlib
import json
import math
import re
from collections import Counter
from pathlib import Path

from .inf060_eks_clock import ClockRefusal, bracket, interval
from .inf060_eks_schedule import LEVELS, SETUP_PHASES, TENANTS, WINDOW_SECONDS, schedule
from .inf060_streaming_probe import summarize_same_read_by_level

ARCHIVE_LIMIT = 64 * 1024**2
EXPANDED_LIMIT = 256 * 1024**2
DIAGNOSTIC_LIMIT = 48 * 1024
FILES = {
    "requests.jsonl",
    "levels.json",
    "cancels.jsonl",
    "clocks.json",
    "gauges.jsonl",
    "observers.json",
    "diagnostics.json",
    "retrieval.json",
    "teardown.json",
    "cost.json",
}

CONDITIONS = {
    "source",
    "artifact_path",
    "model",
    "revision",
    "engine_version",
    "image_digest",
    "engine_flags",
    "gpu_type",
    "gpu_count",
    "capacity_type",
    "zone",
    "policy",
    "tenants",
    "seed",
    "run_count",
    "schedule_sha256",
    "pins",
    "limits",
}
REQUEST = {
    "alias",
    "level",
    "tenant",
    "input_tokens",
    "output_cap",
    "cancel_assigned",
    "slot_ns",
    "shared_prefix",
    "planned_ns",
    "dispatch_ns",
    "deadline_ns",
    "terminal_ns",
    "outcome",
    "http_status",
    "generation",
    "transport_error",
    "client_close_reason",
    "queue_status",
    "gateway_predispatch_ns",
    "cancel_status",
    "cancel_close_monotonic_ns",
    "complete",
    "content_event_count",
    "first_content_monotonic_ns",
    "completion_tokens",
    "token_itl_eligible",
    "token_itl_ns",
    "transport_content_gaps_ns",
    "same_read_content_pairs",
    "coalesced_read_excluded_gaps",
    "content_events",
    "finish_reason",
    "validated_done",
}
CANCEL = {
    "request_alias",
    "backend_generation",
    "cancel_close_monotonic_ns",
    "abort_status",
    "abort_log_stamp",
    "timing_status",
    "timing_interval_ns",
    "upper_ns",
    "width_ns",
}
FORBIDDEN = re.compile(
    rb"INF060CANARY[0-9a-f]{20}|req_[0-9a-f]{32}|"
    rb'"(?:private_request_id|podIP|containerID|token_ids|prompt_text|credential|tokens|Authorization)"\s*:'
)
OUTCOMES = {
    "completed",
    "cancelled",
    "failed",
    "rejected",
    "partial",
    "missed",
    "unresolved",
    "unreached",
}


def payload(value):
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode() + b"\n"
    )


def safe_request(row):
    return {name: value for name, value in row.items() if name in REQUEST}


def schedule_digest():
    return hashlib.sha256(
        payload([row for level in (*SETUP_PHASES, *LEVELS) for row in schedule(level)])
    ).hexdigest()


def percentile(series):
    items = sorted(series)
    n = len(items)
    return {
        "n": n,
        **{
            f"p{p}": items[math.ceil(n * p / 100) - 1] if n * (100 - p) >= 2000 else None
            for p in (50, 95, 99)
        },
    }


def rate_reason(rows, drain_ns):
    if any(row["outcome"] in {"unresolved", "unreached"} for row in rows):
        return "incomplete_window"
    if drain_ns is None:
        return "missing_drain"
    return None


def report_level(
    level, rows, drain_ns, join_rows, orphan_counts, manifest_sha, *, legacy=False, unavailable=None
):
    outcomes = Counter(row["outcome"] for row in rows)
    completed = [row for row in rows if row["outcome"] == "completed"]
    content = [row for row in rows if row.get("first_content_monotonic_ns") is not None]
    ttft = [row["first_content_monotonic_ns"] - row["dispatch_ns"] for row in content]
    completion = [row["terminal_ns"] - row["dispatch_ns"] for row in completed]
    tpot = [
        (row["terminal_ns"] - row["first_content_monotonic_ns"]) / (row["completion_tokens"] - 1)
        for row in completed
        if row.get("completion_tokens", 0) >= 2
    ]
    good = [
        row
        for row in completed
        if row["first_content_monotonic_ns"] - row["dispatch_ns"] <= 10**9
        and row["terminal_ns"] - row["dispatch_ns"] <= 15 * 10**9
    ]
    ordinary = [row for row in rows if not row["cancel_assigned"]]
    unavailable = None if legacy else unavailable or rate_reason(rows, drain_ns)
    elapsed = (
        WINDOW_SECONDS + drain_ns / 10**9 if drain_ns is not None and not unavailable else None
    )
    output_tokens = sum(row["completion_tokens"] for row in completed)
    return {
        "manifest_conditions_sha256": manifest_sha,
        "scheduled": len(rows),
        "outcomes": dict(outcomes),
        "content_requests": len(content),
        "elapsed_s": elapsed,
        **({} if legacy else {"rate_unavailable_reason": unavailable}),
        "drain_ns": drain_ns,
        "output_tokens": output_tokens,
        "input_tokens_dispatched": sum(r["input_tokens"] for r in rows if "dispatch_ns" in r),
        "output_tokens_per_s": output_tokens / elapsed if elapsed else None,
        "completed_per_s": len(completed) / elapsed if elapsed else None,
        "goodput": {
            "G": len(good),
            "per_s": len(good) / elapsed if elapsed else None,
            "all_scheduled": len(rows),
            "scheduled_attainment": len(good) / len(rows) if rows else None,
            "ordinary_good": sum(not r["cancel_assigned"] for r in good),
            "ordinary_scheduled": len(ordinary),
        },
        "latency_ns": {
            "ttft": percentile(ttft),
            "completion": percentile(completion),
            "tpot": percentile(tpot),
            "token_itl": percentile(g for row in rows for g in row.get("token_itl_ns", [])),
            "transport_gap": percentile(
                g for row in rows for g in row.get("transport_content_gaps_ns", [])
            ),
            "dispatch_lag": percentile(
                r["dispatch_ns"] - r["planned_ns"] for r in rows if "dispatch_ns" in r
            ),
            "planned_to_content": percentile(
                r["first_content_monotonic_ns"] - r["planned_ns"] for r in content
            ),
            "planned_to_completion": percentile(
                r["terminal_ns"] - r["planned_ns"] for r in completed
            ),
        },
        "exclusions": {
            "no_content": len(rows) - len(content),
            "completed_below_two_tokens": len(completed) - len(tpot),
            "itl_contributing_requests": sum(bool(row.get("token_itl_ns")) for row in rows),
        },
        **summarize_same_read_by_level(
            {
                level: [
                    {
                        "same_read_content_pairs": row.get("same_read_content_pairs", 0),
                        "coalesced_read_excluded_gaps": row.get("coalesced_read_excluded_gaps", 0),
                    }
                    for row in rows
                ]
            }
        )[level],
        "output_lengths": dict(Counter(row["completion_tokens"] for row in completed)),
        "outcomes_by_cap": {
            str(cap): dict(Counter(row["outcome"] for row in rows if row["output_cap"] == cap))
            for cap in (32, 64, 128)
        },
        "finish_reasons": dict(Counter(row["finish_reason"] for row in completed)),
        "cancel_assigned": sum(row["cancel_assigned"] for row in rows),
        "cancel_sent": sum(row.get("cancel_status") == "sent" for row in rows),
        "abort_status": dict(Counter(r["abort_status"] for r in join_rows)),
        "timing_status": dict(Counter(r["timing_status"] for r in join_rows)),
        "orphans_by_generation": orphan_counts,
        "queue": {
            "engine_per_request_status": "unavailable",
            "engine_aggregate_samples": "gauges.jsonl",
            "gateway_predispatch_ns": percentile(
                row["gateway_predispatch_ns"] for row in rows if "gateway_predispatch_ns" in row
            ),
        },
    }


def cohort_reports(level, rows, drain, joins, conditions_sha, *, legacy=False):
    unavailable = rate_reason(rows, drain)

    def group(field, value):
        selected = [row for row in rows if row[field] == value]
        aliases = {row["alias"] for row in selected}
        return report_level(
            level,
            selected,
            drain,
            [row for row in joins if row["request_alias"] in aliases],
            {},
            conditions_sha,
            legacy=legacy,
            unavailable=unavailable,
        )

    return {
        "by_tenant": {tenant: group("tenant", tenant) for tenant in TENANTS},
        "by_cancel_cohort": {
            name: group("cancel_assigned", assigned)
            for name, assigned in (("assigned", True), ("ordinary", False))
        },
    }


def recount_unexpected(rows, observations):
    scheduled = {row["alias"]: row for row in rows}
    counts = Counter()
    for observation in observations:
        if (
            not isinstance(observation, dict)
            or set(observation) != {"request_alias", "generation"}
            or type(observation["request_alias"]) is not int
            or type(observation["generation"]) is not int
            or observation["generation"] <= 0
        ):
            raise ValueError("streaming_unexpected_abort_observation")
        request = scheduled.get(observation["request_alias"])
        if request is None or (
            request.get("generation") == observation["generation"]
            and (request.get("cancel_status") == "sent" or request.get("client_close_reason"))
        ):
            raise ValueError("streaming_unexpected_abort_observation")
        counts[str(observation["generation"])] += 1
    return dict(counts)


def verify_cancel_timing(clocks, sent):
    bounds = {}
    for clock in clocks:
        generation = clock["generation"]
        if generation in bounds:
            raise ValueError("streaming_clock_generation")
        bounds[generation] = None
        try:
            computed = bracket(
                clock["before"],
                clock["after"],
                clock["mapping"],
                same_generation=clock.get("same_generation") is True,
            )
        except (ClockRefusal, KeyError, TypeError, ValueError):
            if clock["status"] == "bounded" or "bounds" in clock:
                raise ValueError("streaming_clock_bracket") from None
        else:
            if clock["status"] == "bounded":
                if computed != clock.get("bounds"):
                    raise ValueError("streaming_clock_bracket")
                bounds[generation] = computed
            elif "bounds" in clock:
                raise ValueError("streaming_clock_bracket")

    for row in sent:
        expected = {
            "timing_status": "unresolved",
            "timing_interval_ns": None,
            "upper_ns": None,
            "width_ns": None,
        }
        stamp = row.get("abort_log_stamp")
        bound = bounds.get(row["backend_generation"])
        if row["abort_status"] == "joined" and stamp and bound:
            lo, hi = interval(stamp, row["cancel_close_monotonic_ns"], bound)
            expected.update(upper_ns=hi, width_ns=hi - lo)
            if lo >= 0:
                expected.update(timing_status="bounded", timing_interval_ns=[lo, hi])
        if any(row.get(key) != value for key, value in expected.items()):
            raise ValueError("streaming_cancel_interval_mismatch")


def build(directory, conditions, windows, diagnostics, *, complete=False):
    directory = Path(directory)
    directory.mkdir()
    condition_hash = hashlib.sha256(payload(conditions)).hexdigest()
    requests, cancels, gauges, clocks, observers, levels = [], [], [], {}, {}, {}
    for level in LEVELS:
        window = windows.get(level, {})
        observed = {row["alias"]: safe_request(row) for row in window.get("requests", [])}
        rows = [
            {
                **row,
                **observed.get(
                    row["alias"],
                    {
                        "outcome": "unresolved" if level in windows else "unreached",
                    },
                ),
            }
            for row in schedule(level)
        ]
        requests.extend(rows)
        joined = {row["request_alias"]: row for row in window.get("cancels", [])}
        for row in rows:
            if row["cancel_assigned"]:
                alias = row["alias"]
                cancels.append(
                    {
                        "level": level,
                        "assigned": True,
                        "request_alias": alias,
                        "cancel_status": row.get("cancel_status", "unobserved"),
                        **{k: v for k, v in joined.get(alias, {}).items() if k in CANCEL},
                    }
                )
        gauges.extend({"level": level, **row} for row in window.get("gauges", []))
        clocks[level] = window.get("clocks", [])
        unexpected = window.get("unexpected_abort_observations", [])
        observers[level] = {
            **window.get("observers", {"status": "unavailable"}),
            "unexpected_abort_observations": unexpected,
        }
        args = (
            level,
            rows,
            window.get("drain_ns"),
            list(joined.values()),
            window.get("orphans", {}),
            condition_hash,
        )
        levels[level] = report_level(*args)
        levels[level].update(cohort_reports(level, rows, args[2], args[3], condition_hash))
        levels[level]["non_cancel_aborts"] = window.get(
            "non_cancel_aborts", {"expected": 0, "matched": 0}
        )
        levels[level]["unexpected_scheduled_aborts"] = recount_unexpected(rows, unexpected)
    values = {
        "requests.jsonl": requests,
        "cancels.jsonl": cancels,
        "gauges.jsonl": gauges,
        "levels.json": levels,
        "clocks.json": clocks,
        "observers.json": observers,
        "diagnostics.json": diagnostics,
        "retrieval.json": {"status": "awaiting_laptop_verification"},
        "teardown.json": {"status": "awaiting_cleanup"},
        "cost.json": {"status": "awaiting_final_elapsed"},
    }
    files = {}
    for name, value in values.items():
        data = b"".join(map(payload, value)) if name.endswith(".jsonl") else payload(value)
        (directory / name).write_bytes(data)
        files[name] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    (directory / "manifest.json").write_bytes(
        payload(
            {
                "schema": "inf060-eks-v2",
                "complete": complete,
                "files": files,
                "conditions": conditions,
                "conditions_sha256": condition_hash,
            }
        )
    )
    verify(directory)
    return files


def verify(directory, *, witness=None):
    directory = Path(directory)
    paths = list(directory.iterdir())
    if {p.name for p in paths} != FILES | {"manifest.json"} or any(
        p.is_symlink() or not p.is_file() for p in paths
    ):
        raise ValueError("streaming_output_files")
    if sum(p.stat().st_size for p in paths) > EXPANDED_LIMIT:
        raise ValueError("streaming_expanded_limit")
    if (directory / "diagnostics.json").stat().st_size > DIAGNOSTIC_LIMIT:
        raise ValueError("streaming_diagnostic_limit")
    raw = (directory / "manifest.json").read_bytes()
    if witness is not None and hashlib.sha256(raw).hexdigest() != witness:
        raise ValueError("streaming_manifest_hash")
    manifest = json.loads(raw)
    legacy = manifest["schema"] == "inf060-eks-v1"
    if (
        manifest["schema"] not in {"inf060-eks-v1", "inf060-eks-v2"}
        or set(manifest["files"]) != FILES
    ):
        raise ValueError("streaming_manifest_schema")
    if (
        set(manifest["conditions"]) != CONDITIONS
        or manifest["conditions_sha256"]
        != hashlib.sha256(payload(manifest["conditions"])).hexdigest()
    ):
        raise ValueError("streaming_conditions")
    if manifest["conditions"]["schedule_sha256"] != schedule_digest():
        raise ValueError("streaming_schedule_hash")
    values = {}
    for name, facts in manifest["files"].items():
        raw = (directory / name).read_bytes()
        if facts != {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}:
            raise ValueError("streaming_member_hash")
        if FORBIDDEN.search(raw):
            raise ValueError("streaming_private_field")
        values[name] = (
            [json.loads(line) for line in raw.splitlines()]
            if name.endswith(".jsonl")
            else json.loads(raw)
        )
    rows = values["requests.jsonl"]
    expected = [row for level in LEVELS for row in schedule(level)]
    for scheduled, row in zip(expected, rows, strict=True):
        if set(row) - REQUEST or any(row.get(k) != v for k, v in scheduled.items()):
            raise ValueError("streaming_schedule")
        if row["outcome"] not in OUTCOMES:
            raise ValueError("streaming_outcome")
        if manifest["complete"] and row["outcome"] in {"unreached", "unresolved"}:
            raise ValueError("streaming_missing_observation")
        if row["outcome"] == "completed" and (
            not {
                "dispatch_ns",
                "terminal_ns",
                "first_content_monotonic_ns",
                "completion_tokens",
                "validated_done",
                "finish_reason",
                "content_events",
            }
            <= row.keys()
            or row["validated_done"] is not True
            or row["completion_tokens"] is None
        ):
            raise ValueError("streaming_required_observation")
    cancels = values["cancels.jsonl"]
    if [(row["level"], row["request_alias"]) for row in cancels] != [
        (r["level"], r["alias"]) for r in expected if r["cancel_assigned"]
    ]:
        raise ValueError("streaming_cancel_population")
    for name in ("levels.json", "clocks.json", "observers.json"):
        if set(values[name]) != set(LEVELS):
            raise ValueError("streaming_level_files")
    for level in LEVELS:
        summary = values["levels.json"][level]
        level_rows = [row for row in rows if row["level"] == level]
        sent = [row for row in cancels if row["level"] == level and row["cancel_status"] == "sent"]
        reported = report_level(
            level,
            level_rows,
            summary["drain_ns"],
            sent,
            summary["orphans_by_generation"],
            manifest["conditions_sha256"],
            legacy=legacy,
        )
        if any(
            key not in summary or summary[key] != value
            for key, value in json.loads(payload(reported)).items()
        ):
            raise ValueError("streaming_summary_mismatch")
        grouped = cohort_reports(
            level,
            level_rows,
            summary["drain_ns"],
            sent,
            manifest["conditions_sha256"],
            legacy=legacy,
        )
        for key, value in json.loads(payload(grouped)).items():
            if summary.get(key) != value:
                raise ValueError("streaming_" + key + "_mismatch")
        if not legacy:
            observations = values["observers.json"][level].get("unexpected_abort_observations")
            if not isinstance(observations, list) or summary.get(
                "unexpected_scheduled_aborts"
            ) != recount_unexpected(level_rows, observations):
                raise ValueError("streaming_unexpected_abort_recount")
        non_cancel = summary["non_cancel_aborts"]
        expected_reasons = Counter(
            row["client_close_reason"] for row in level_rows if row.get("client_close_reason")
        )
        expected_closes = sum(expected_reasons.values())
        if (
            non_cancel["expected"] != expected_closes
            or not 0 <= non_cancel["matched"] <= expected_closes
        ):
            raise ValueError("streaming_non_cancel_population")
        by_reason = non_cancel.get("matched_by_reason")
        if by_reason is not None and (
            any(
                type(count) is not int or not 0 < count <= expected_reasons[reason]
                for reason, count in by_reason.items()
            )
            or sum(by_reason.values()) != non_cancel["matched"]
        ):
            raise ValueError("streaming_non_cancel_population")
        by_alias = {row["alias"]: row for row in level_rows}
        for row in sent:
            request = by_alias[row["request_alias"]]
            if (
                request.get("cancel_status") != "sent"
                or row["cancel_close_monotonic_ns"] != request.get("cancel_close_monotonic_ns")
                or row["backend_generation"] != request.get("generation", 0)
            ):
                raise ValueError("streaming_cancel_population")
        if len(sent) != reported["cancel_sent"]:
            raise ValueError("streaming_cancel_population")
        verify_cancel_timing(values["clocks.json"][level], sent)
    if manifest["complete"]:
        if any(
            not values["clocks.json"][level]
            or values["observers.json"][level].get("suppression") != "PASS"
            or values["levels.json"][level]["elapsed_s"] is None
            for level in LEVELS
        ):
            raise ValueError("streaming_required_capture")
    return manifest
