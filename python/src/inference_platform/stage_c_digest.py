"""Bounded measurement projections, with explicit aggregate degradation."""

import gzip
import json
import os
import time
from pathlib import Path

from .disk_records import DiskList, jsonl_rows

DIGEST_LIMIT = 1024 * 1024
REQUEST_COLUMNS = [
    "index",
    "level",
    "failure_class",
    "ttft_ns",
    "completion_ns",
    "prompt_tokens",
    "completion_tokens",
    "event_lag_status",
    "event_lag_ns",
]
FINAL_LIMIT = 32000
FORWARD_WORST_BYTES_PER_SECOND = 100
RECEIPT = "docs/evidence/round60-fixes/constrained-rehearsal.json"


def compact(value, *, measurements=True):
    """Keep computations and numeric samples, excluding redundant raw representations."""
    if isinstance(value, dict):
        result = {}
        for key, child in value.items():
            if key in (
                "body",
                "sources",
                "processes",
                "event_observations",
                "capture",
                "routing_to_event_observation",
                "configuration",
                "tokenizations",
            ) or (
                not measurements and key in ("records", "metrics", "signals", "reference_capacity")
            ):
                continue
            if key == "metrics":
                result[key] = [
                    {
                        "offset_ns": row["offset_ns"],
                        "values": {
                            name: number
                            for name, number in row.get("values", {}).items()
                            if "vllm:" in name
                        },
                    }
                    for row in child
                ]
            elif key == "records":
                result[key] = DiskList(
                    {
                        name: number
                        for name, number in row.items()
                        if name
                        in (
                            "request_id",
                            "gateway_request_id",
                            "outcome",
                            "http_status",
                            "error_code",
                            "error_body_code",
                            "error_body_type",
                            "prompt_tokens",
                            "completion_tokens",
                            "token_count_source",
                            "failure_class",
                            "gateway_terminal_code",
                            "upstream_error_body_code",
                        )
                        or name.endswith("offset_ns")
                    }
                    for row in child
                )
            else:
                result[key] = compact(child, measurements=measurements)
        return result
    if isinstance(value, list):
        return [compact(row, measurements=measurements) for row in value]
    return value


def measurement_digest(session, run, directory, config=None):
    from .decision_export import export_decisions
    from .failure_taxonomy import classification
    from .kv_event_capture import (
        correlate_routing_events,
        load_routing_decisions,
        summarize_routing_correlations,
    )

    projected = compact(run)
    index = DiskList()
    index.db.execute("create table ids(id text primary key)")
    terminals = (
        DiskList(
            row
            for row in jsonl_rows(directory / "gateway.log")
            if row.get("msg") == "request terminal"
        )
        if (directory / "gateway.log").exists()
        else DiskList()
    )
    index.db.execute("create table terminals(id text primary key, value text)")
    index.db.executemany(
        "insert into terminals values (?,?)",
        ((row["request_id"], json.dumps(row)) for row in terminals),
    )

    def visit(value):
        if isinstance(value, dict):
            if "records" in value:
                replaced = DiskList()
                for row in value["records"]:
                    request_id = row.get("gateway_request_id") or row["request_id"]
                    index.db.execute("insert into ids values (?)", (request_id,))
                    match = index.db.execute(
                        "select value from terminals where id=?", (request_id,)
                    ).fetchone()
                    terminal = json.loads(match[0]) if match else None
                    row.update(
                        failure_class=classification(row, terminal),
                        gateway_terminal_code=terminal.get("code") if terminal else None,
                        upstream_error_body_code=terminal.get("upstream_error_code")
                        if terminal
                        else None,
                    )
                    replaced.append(row)
                value["records"] = replaced
            for key, child in value.items():
                if key not in ("records", "metrics"):
                    visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(projected)
    lag = {"status": "unestablished", "reason": "capture or restricted decision inputs unavailable"}
    prompt_path = Path(config.decision_prompt_export_path) if config else None
    events = next(
        (
            directory / name
            for name in ("fake-events.jsonl", "kv-event-capture.observations.jsonl")
            if (directory / name).exists()
        ),
        None,
    )
    if prompt_path and prompt_path.exists() and events:

        def selected(rows):
            return (
                row
                for row in rows
                if index.db.execute("select 1 from ids where id=?", (row["request_id"],)).fetchone()
            )

        prompts = DiskList(selected(jsonl_rows(prompt_path)))
        scoped = DiskList(selected(terminals))
        raw = session / "private" / "checkpoint-decisions.jsonl"
        decisions = None
        correlations = None
        observations = None
        try:
            exported = export_decisions(
                scoped,
                prompts,
                config.tokenize_url,
                deadline=min(run["effective_deadline_monotonic_s"], time.perf_counter() + 120),
            )
            with raw.open("w", encoding="utf-8", newline="\n") as stream:
                for row in exported:
                    stream.write(json.dumps(row) + "\n")
            offset = time.time_ns() - time.perf_counter_ns()
            decisions = load_routing_decisions(raw, wall_to_monotonic_offset_ns=offset)
            observations = DiskList(jsonl_rows(events))
            correlations = correlate_routing_events(decisions, observations)
            index.db.execute("create table lags(id text primary key, value text)")
            index.db.executemany(
                "insert into lags values (?,?)",
                ((row["request_id"], json.dumps(row)) for row in correlations),
            )
            # Detailed redacted joins stay in the forward-only full run archive;
            # the bounded command digest carries only their summary/histogram.
            with (directory / "event-lag-correlations.jsonl").open(
                "w", encoding="utf-8", newline="\n"
            ) as stream:
                for row in correlations:
                    stream.write(json.dumps(row, separators=(",", ":"), allow_nan=False) + "\n")
            bounds = [
                1_000_000,
                10_000_000,
                100_000_000,
                1_000_000_000,
                10_000_000_000,
                100_000_000_000,
            ]
            counts = [0] * (len(bounds) + 1)
            observed_lags = DiskList()
            for row in correlations:
                if row["status"] == "observed":
                    lag_ns = row["routing_to_event_observation_ns"]
                    observed_lags.append(lag_ns)
                    bucket = next(
                        (i for i, bound in enumerate(bounds) if lag_ns <= bound), len(bounds)
                    )
                    counts[bucket] += 1
            sequences = observations.db.execute(
                "select distinct json_extract(value,'$.sequence') as s from rows "
                "where s is not null order by s"
            )
            previous = None
            gaps = 0
            for (sequence,) in sequences:
                if previous is not None:
                    gaps += max(0, sequence - previous - 1)
                previous = sequence
            lag = {
                "status": "established",
                **summarize_routing_correlations(correlations),
                "observed_lags_ns": observed_lags,
                "snapshot_publisher_sequence_gap_count": gaps,
                "wall_to_monotonic_offset_ns": offset,
                "histogram": {
                    "upper_bounds_ns": bounds + [None],
                    "counts": counts,
                    "cumulative": False,
                },
                "snapshot_basis": "sealed before next run; no future stores included; final session join remains separate",
            }
        except (OSError, ValueError, RuntimeError) as error:
            lag = {"status": "unestablished", "reason": str(error)}
        finally:
            raw.unlink(missing_ok=True)
            prompts.close()
            scoped.close()
            if decisions is not None:
                decisions.close()
            if correlations is not None:
                correlations.close()
            if observations is not None:
                observations.close()
    if run.get("checkpoint", {}).get("event_lag_status") == "unavailable":
        lag = {"status": "unavailable", "reason": "checkpoint failure; event snapshot not trusted"}

    def lookup(row):
        if lag["status"] != "established":
            return {"status": lag["status"]}
        match = index.db.execute(
            "select value from lags where id=?",
            (row.get("gateway_request_id") or row["request_id"],),
        ).fetchone()
        return json.loads(match[0]) if match else {"status": "not_correlated"}

    table = request_table(projected, lookup)
    index.close()
    terminals.close()
    return {
        "schema": "inf011-measurement-digest.v2",
        "per_request": table,
        "run": projected,
        "event_lag": lag,
        "raw_prompt_token_inputs_included": False,
    }


def request_table(run, lookup=None):
    """Exact integer durations and explicit missing values; stable traversal indexes.

    Level is an index into paths so repeated concurrency levels remain distinct.
    The archive keeps request IDs; the essential digest never needs random IDs.
    """
    rows, levels = [], []

    def visit(value, path):
        if isinstance(value, dict):
            if "records" in value:
                level = len(levels)
                levels.append({"path": path, "concurrency": value.get("concurrency")})
                for row in value["records"]:
                    dispatch = row.get("dispatch_offset_ns")

                    def duration(name, row=row, dispatch=dispatch):
                        end = row.get(name)
                        return end - dispatch if end is not None and dispatch is not None else None

                    event = lookup(row) if lookup else {"status": "unestablished"}
                    rows.append(
                        [
                            len(rows),
                            level,
                            row.get("failure_class", row.get("outcome")),
                            duration("first_content_offset_ns"),
                            duration("completion_offset_ns"),
                            row.get("prompt_tokens"),
                            row.get("completion_tokens"),
                            event["status"],
                            event.get("routing_to_event_observation_ns"),
                        ]
                    )
            for key, child in value.items():
                if key not in ("records", "metrics", "signals"):
                    visit(child, path + [key])
        elif isinstance(value, list):
            for i, child in enumerate(value):
                visit(child, path + [i])

    visit(run, [])
    return {
        "columns": REQUEST_COLUMNS,
        "levels": levels,
        "rows": rows,
        "time_basis": "exact ns since dispatch; null means unavailable",
    }


def seal_digest(path, value):
    from .stage_c_checkpoint import file_sha

    if not isinstance(value.get("run"), dict) or not isinstance(value.get("event_lag"), dict):
        raise ValueError("measurement digest requires run and event_lag objects")
    if "per_request" not in value:
        value = {"per_request": request_table(value["run"]), **value}
    pending = path.with_suffix(".pending")

    def encode():
        with pending.open("wb") as output:
            with gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0) as stream:
                for text in json.JSONEncoder(separators=(",", ":"), allow_nan=False).iterencode(
                    value
                ):
                    stream.write(text.encode())
            output.flush()
            os.fsync(output.fileno())
        return pending.stat().st_size

    def drop_request_detail(child):
        from collections import Counter

        if isinstance(child, dict):
            result = {}
            for key, item in child.items():
                if key == "records":
                    counts = Counter()
                    for row in item:
                        counts[
                            (row.get("outcome"), row.get("failure_class"), row.get("http_status"))
                        ] += 1
                    result["request_outcome_aggregates"] = [
                        {
                            "outcome": outcome,
                            "failure_class": failure,
                            "http_status": status,
                            "count": count,
                        }
                        for (outcome, failure, status), count in counts.items()
                    ]
                    result["request_detail_count"] = sum(counts.values())
                elif key == "observed_lags_ns":
                    # Summary quantiles/counts/histogram remain; exact lag inputs are detail.
                    result["observed_lag_detail_count"] = len(item)
                else:
                    result[key] = drop_request_detail(item)
            return result
        if isinstance(child, list):
            return [drop_request_detail(item) for item in child]
        return child

    def drop_sample_detail(child):
        def aggregate(values):
            count = 0
            total = 0
            low = high = None
            for number in values:
                count += 1
                total += number
                low = number if low is None else min(low, number)
                high = number if high is None else max(high, number)
            return {
                "count": count,
                "min": low,
                "max": high,
                "mean": total / count if count else None,
            }

        if isinstance(child, dict):
            result = {}
            for key, item in child.items():
                if key == "metrics":
                    names = {name for row in item for name in row["values"]}
                    result["native_metric_aggregates"] = {
                        name: aggregate(
                            row["values"][name] for row in item if name in row["values"]
                        )
                        for name in sorted(names)
                    }
                elif key == "signals":
                    result["native_signal_aggregates"] = {
                        name: aggregate(rows) for name, rows in item.items()
                    }
                else:
                    result[key] = drop_sample_detail(item)
            return result
        if isinstance(child, list):
            return [drop_sample_detail(item) for item in child]
        return child

    try:
        size = encode()
        degraded = size > DIGEST_LIMIT
        original_size = size
        if degraded:
            value["run"] = drop_sample_detail(value["run"])
            value["detail_degradation"] = {
                "per_request_detail_dropped": False,
                "native_sample_detail_dropped": True,
                "reason": "compressed digest exceeded bound",
                "original_compressed_bytes": original_size,
                "full_archive_retains_detail": True,
            }
            size = encode()
        if size > DIGEST_LIMIT:
            # Remove redundant verbose rows only; the essential table always survives.
            value["run"] = drop_request_detail(value["run"])
            value["event_lag"] = drop_request_detail(value["event_lag"])
            value["detail_degradation"]["verbose_request_detail_dropped"] = True
            size = encode()
        if size > DIGEST_LIMIT:
            raise ValueError("essential request digest exceeds transport bound")
        pending.replace(path)
        return {
            "sha256": file_sha(path),
            "bytes": size,
            "limit_bytes": DIGEST_LIMIT,
            "path": path.name,
            "event_lag_status": value["event_lag"]["status"],
            "per_request_detail_dropped": False,
            "per_request_count": len(value["per_request"]["rows"]),
        }
    finally:
        pending.unlink(missing_ok=True)


def digest_fitness(root, receipt_path=None):
    from .host_headroom import source_fingerprint
    from .stage_c_checkpoint import file_sha

    path = Path(receipt_path) if receipt_path else root / RECEIPT
    try:
        row = json.loads(path.read_text(encoding="utf-8"))
        if row["status"] != "passed" or row["source_files_sha256"] != source_fingerprint(root):
            raise ValueError("digest rehearsal missing or stale executable source")
        digests = row["measurement_digests"]
        if len(digests) != 4 or {r["run_number"] for r in digests} != {1, 2, 3, 4}:
            raise ValueError("four full-volume measured digests required")
        for receipt in digests:
            target = (root / receipt["path"]).resolve()
            if (
                not target.is_relative_to(root.resolve())
                or not 0 < receipt["bytes"] <= DIGEST_LIMIT
            ):
                raise ValueError("digest exceeds compressed bound")
            if target.stat().st_size != receipt["bytes"] or file_sha(target) != receipt["sha256"]:
                raise ValueError("digest evidence checksum/size mismatch")
        if not 0 < row["final_export_bytes"] <= FINAL_LIMIT:
            raise ValueError("final export exceeds worst-case reserve bound")
        return True, (
            f"{path}: four digests <=1 MiB; final <={FINAL_LIMIT} bytes / 100 B/s <=320 s; "
            "last digest <=208.8 s at 2.4 s/command, leaving >=71.2 s in 600 s"
        )
    except (OSError, KeyError, TypeError, ValueError) as error:
        return False, f"{path}: {error}"
