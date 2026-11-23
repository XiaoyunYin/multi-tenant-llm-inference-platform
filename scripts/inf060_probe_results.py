"""Closed-schema, size-bounded export from the controller's frozen archive."""

import hashlib
import json
import math
import re
import tarfile
from collections import Counter

import inf060_diagnostics as diagnostics
import inf060_probe_spec as spec

MAX_BYTES = 1024**2
# Reserve the final newline within the 24,000-character SSM stdout limit.
CHUNK_BYTES = 17_997
TRANSFER_S = 480
TRANSFER_RESERVE_S = 60
CHUNK_TIMEOUT_S = 7
ARMS = ("control", "logged")
OUTCOMES = ("complete", "cancelled", "failed", "rejected", "missed_offer")
LATENCY = ("completed_ttft_ns", "completed_elapsed_ns", "eligible_token_itl_ns")
GAUGES = ("vllm:num_requests_running", "vllm:kv_cache_usage_perc")
JOIN_STATUS = (
    "joined",
    "missing_gateway_request_id",
    "missing_abort",
    "duplicate_abort",
)
OPERATIONS = (
    "pull-nginx",
    "pull-redis",
    "pull-vllm",
    "model-stage-start",
    "model-stage-wait",
    *(
        f"{arm}-{step}"
        for arm in ARMS
        for step in ("engine-launch", "engine-health", "startup-log")
    ),
)


def integer(value):
    spec.check(type(value) is int and -(2**63) < value < 2**63, "results_integer")
    return value


def finite(value):
    spec.check(type(value) in (int, float) and math.isfinite(value), "results_number")
    return value


def choice(value, allowed):
    spec.check(value in allowed, "results_enum")
    return value


def integers(row, keys):
    return {key: integer(row[key]) for key in keys}


def timing(row):
    data = {key: finite(row[key]) for key in ("start_epoch", "end_epoch", "elapsed_s")}
    spec.check(data["elapsed_s"] >= 0, "results_elapsed")
    return {
        **data,
        "exit_code": integer(row["exit_code"])
        if row["exit_code"] is not None
        else None,
    }


def observation(row):
    spec.check(type(row["cancel_assigned"]) is bool, "results_assignment")
    return {
        "alias": integer(row["alias"]),
        "outcome": choice(row["outcome"], OUTCOMES),
        "cancel_assigned": row["cancel_assigned"],
        "cancel_status": choice(
            row.get("cancel_status"),
            (
                None,
                "not_assigned",
                "sent",
                "finished_before_cancel",
                "not_sent_unfinished",
            ),
        ),
        **{
            key: integer(row[key]) if row.get(key) is not None else None
            for key in (
                "ttft_ns",
                "elapsed_ns",
                "completion_tokens",
                "content_event_count",
            )
        },
    }


def joined_row(row):
    stamp = row["abort_log_stamp"]
    spec.check(
        stamp is None
        or (isinstance(stamp, str) and re.fullmatch(r"[0-9]{1,12}\.[0-9]{6}", stamp)),
        "results_stamp",
    )
    interval = row.get("timing_interval_ns")
    status = choice(row.get("timing_status"), ("bounded", "ordering_unresolved", None))
    spec.check((interval is not None) == (status == "bounded"), "results_interval")
    if interval is not None:
        spec.check(
            isinstance(interval, list) and len(interval) == 2, "results_interval"
        )
        interval = [integer(x) for x in interval]
        spec.check(0 <= interval[0] <= interval[1], "results_interval")
    return {
        **integers(
            row, ("request_alias", "backend_generation", "cancel_close_monotonic_ns")
        ),
        "abort_status": choice(row["abort_status"], JOIN_STATUS),
        "abort_log_stamp": stamp,
        "timing_status": status,
        "timing_interval_ns": interval,
        "timing_interval_width_ns": interval[1] - interval[0]
        if interval is not None
        else None,
    }


def clocks(row):
    clock = integers(
        row,
        (
            "offset_lo_ns",
            "offset_hi_ns",
            "sampled_offset_variation_ns",
            "stamp_resolution_ns",
            "minimum_interval_width_ns",
        ),
    )
    for end in ("before", "after"):
        spec.check(len(row[end]) == 10, "results_clock_count")
        clock[end] = [
            integers(exchange, ("c1", "c4", "e2", "e3", "lo", "hi", "width"))
            for exchange in row[end]
        ]
    return clock


def scans(row):
    spec.check(type(row["no_payload"]) is bool, "results_suppression")
    return {
        **integers(
            row,
            (
                "bytes",
                "lines",
                "canary_lines",
                "prompt_field_lines",
                "token_field_lines",
                "stock_timestamp_lines",
            ),
        ),
        "no_payload": row["no_payload"],
        "status": choice(row["status"], ("PASS", "REFUSED")),
    }


def project_arm(row, arm):
    observations = [observation(item) for item in row["observations"]]
    expected = {
        slot["alias"]: slot["cancel"]
        for slot in spec.request_manifest()["slots"]
        if slot["cohort"] == "measured"
    }
    spec.check(
        len(observations) == row["scheduled"] == len(expected)
        and {item["alias"]: item["cancel_assigned"] for item in observations}
        == expected,
        "results_slots",
    )
    spec.check(row["assigned_cancels"] == sum(expected.values()), "results_assignments")
    outcomes = dict(Counter(item["outcome"] for item in observations))
    spec.check(outcomes == row["outcomes"], "results_outcomes")
    joins = row["abort_join"]
    rows = [joined_row(item) for item in joins["rows"]]
    sent = [item["alias"] for item in observations if item["cancel_status"] == "sent"]
    spec.check(
        sorted(item["request_alias"] for item in rows) == sorted(sent)
        and all(item["backend_generation"] == ARMS.index(arm) for item in rows),
        "results_cancel_join",
    )
    totals = integers(
        joins,
        (
            "orphan_abort_count",
            "sent",
            "identity_joins",
            "timing_joins",
            "frontend_abort_lines",
            "stock_abort_matches",
        ),
    )
    spec.check(
        totals["sent"] == len(rows)
        and totals["identity_joins"]
        == sum(item["abort_status"] == "joined" for item in rows)
        and totals["timing_joins"]
        == sum(item["timing_status"] == "bounded" for item in rows),
        "results_join_totals",
    )
    latency = {
        name: {
            "n": integer(row["latency"][name]["n"]),
            **{
                p: value
                if (value := row["latency"][name][p]) == "insufficient"
                else integer(value)
                for p in ("p50", "p95", "p99")
            },
        }
        for name in LATENCY
    }
    gauges = [
        {
            **integers(sample, ("mono_ns", "wall_ns", "sample_width_ns")),
            "values": {
                metric: finite(sample["values"][metric])
                for metric in GAUGES
                if metric in sample["values"]
            },
        }
        for sample in row["coarse_gauges"]
    ]
    return {
        **integers(
            row, ("scheduled", "assigned_cancels", "engine_cpu_usec", "client_cpu_ns")
        ),
        "outcomes": outcomes,
        "observations": observations,
        "latency_summary": latency,
        "abort_join": {**totals, "rows": rows},
        "clock": clocks(row["clock"]),
        "coarse_gauges": gauges,
    }


def collect(archive, *, complete, mock):
    data = {
        "archive_status": "available" if archive.is_file() else "missing",
        "arms": {},
        "phases": {},
        "operations": {},
    }
    if archive.is_file():
        with tarfile.open(archive) as tar:
            members = {item.name: item for item in tar.getmembers() if item.isfile()}

            def load(name):
                item = members.get("results/" + name + ".json")
                if item is not None:
                    spec.check(item.size <= MAX_BYTES, "results_member_size")
                    return json.load(tar.extractfile(item))
                return None

            for arm in ARMS:
                row, log, startup = (
                    load(arm + suffix)
                    for suffix in ("", "-suppression", "-startup-suppression")
                )
                if row is not None or log is not None or startup is not None:
                    result = data["arms"].setdefault(arm, {})
                    if row is not None:
                        result.update(project_arm(row, arm))
                    if log is not None:
                        result["log_scan"] = scans(log)
                    if startup is not None:
                        result["startup_log_scan"] = scans(startup)
            for phase in spec.PHASES:
                if (row := load("phase-" + phase)) is not None:
                    spec.check(
                        row["phase"] == phase and row["env_i"] is True, "results_phase"
                    )
                    data["phases"][phase] = {
                        **timing(row),
                        "env_i": True,
                        "deadline_epoch": finite(row["deadline_epoch"]),
                    }
            for operation in OPERATIONS:
                if (row := load("operation-" + operation)) is not None:
                    data["operations"][operation] = timing(row)
    if complete:
        spec.check(
            set(data["arms"]) == set(ARMS) and set(data["phases"]) == set(spec.PHASES),
            "results_missing_phase_or_arm",
        )
        spec.check(
            all(
                arm.keys() >= {"observations", "log_scan", "startup_log_scan"}
                for arm in data["arms"].values()
            ),
            "results_missing_arm_fields",
        )
        needed = set(OPERATIONS) - (
            {"pull-vllm", "model-stage-start", "model-stage-wait"} if mock else set()
        )
        spec.check(data["operations"].keys() >= needed, "results_missing_operation")
    return data


def publish(path, archive, *, complete, mock):
    raw = diagnostics.encoded(collect(archive, complete=complete, mock=mock))
    spec.check(len(raw) <= MAX_BYTES, "results_size_cap")
    path.write_bytes(raw)
    return {
        "status": "available",
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
