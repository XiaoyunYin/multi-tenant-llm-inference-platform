"""Verify retained local archives and every bounded digest against its full run."""

import argparse
import gzip
import hashlib
import json
import tarfile
from collections import Counter
from pathlib import Path

from inference_platform.failure_taxonomy import classification
from inference_platform.kv_event_capture import summarize_routing_correlations
from inference_platform.stage_c_digest import DIGEST_LIMIT, FINAL_LIMIT


def distribution(values):
    values = sorted(value for value in values if value is not None)
    result = {
        "count": len(values),
        "min": values[0] if values else None,
        "max": values[-1] if values else None,
    }
    for label, probability in (("median", 0.5), ("p95", 0.95), ("p99", 0.99)):
        # Use the PLAN tail-support rule for diagnostic percentiles as well.
        if values and len(values) * (1 - probability) >= 20:
            result[label] = values[round((len(values) - 1) * probability)]
    return result


def audit_table(original, digest, terminals, correlations):
    """Reconstruct essential rows independently from retained request/event files."""
    table = digest["per_request"]
    if table["columns"] != [
        "index",
        "level",
        "failure_class",
        "ttft_ns",
        "completion_ns",
        "prompt_tokens",
        "completion_tokens",
        "event_lag_status",
        "event_lag_ns",
    ]:
        raise ValueError("essential table columns changed")
    levels_by_path = dict(levels(original))
    paths = [tuple(row["path"]) for row in table["levels"]]
    if len(paths) != len(set(paths)) or set(paths) != set(levels_by_path):
        raise ValueError("essential table lost level identity")
    # JSON persistence sorts object keys. The declared path mapping, not the
    # serialized object's key order, defines stable level indexes in the table.
    levels_in = [(path, levels_by_path[path]) for path in paths]
    if any(
        row.get("concurrency") != value.get("concurrency")
        for row, (_, value) in zip(table["levels"], levels_in, strict=True)
    ):
        raise ValueError("essential table changed level concurrency")
    joined = {row["request_id"]: row for row in correlations}
    index = 0
    reports = []
    for level_index, (path, value) in enumerate(levels_in):
        observed = []
        for record in value["records"]:
            request_id = record.get("gateway_request_id") or record["request_id"]
            terminal = terminals.get(request_id)
            failure = classification(record, terminal)
            dispatch = record.get("dispatch_offset_ns")
            first = record.get("first_content_offset_ns")
            completion = record.get("completion_offset_ns")
            event = (
                joined.get(request_id, {"status": "not_correlated"})
                if digest["event_lag"]["status"] == "established"
                else {"status": digest["event_lag"]["status"]}
            )
            expected = [
                index,
                level_index,
                failure,
                first - dispatch
                if first is not None and dispatch is not None
                else None,
                completion - dispatch
                if completion is not None and dispatch is not None
                else None,
                record.get("prompt_tokens"),
                record.get("completion_tokens"),
                event["status"],
                event.get("routing_to_event_observation_ns"),
            ]
            if index >= len(table["rows"]) or table["rows"][index] != expected:
                raise ValueError(
                    f"essential table row {index} differs from request/terminal/event join"
                )
            observed.append(expected)
            index += 1
        reports.append(
            {
                "path": list(path),
                "concurrency": value.get("concurrency"),
                "requests": len(observed),
                "failure_classes": dict(Counter(row[2] for row in observed)),
                "ttft_ns_by_failure_class": {
                    kind: distribution(row[3] for row in observed if row[2] == kind)
                    for kind in sorted({row[2] for row in observed})
                },
                "completion_ns": distribution(row[4] for row in observed),
                "prompt_tokens": distribution(row[5] for row in observed),
                "completion_tokens": distribution(row[6] for row in observed),
                "event_lag_statuses": dict(Counter(row[7] for row in observed)),
                "observed_event_lag_ns": distribution(
                    row[8] for row in observed if row[7] == "observed"
                ),
            }
        )
    if index != len(table["rows"]):
        raise ValueError("extra essential request rows")
    if digest.get("detail_degradation", {}).get("per_request_detail_dropped"):
        raise ValueError("essential table falsely marked dropped")
    return index, reports


def levels(value, path=()):
    if isinstance(value, dict):
        if "records" in value:
            yield path, value
        for key, child in value.items():
            if key not in ("records", "metrics"):
                yield from levels(child, path + (key,))
    elif isinstance(value, list):
        for index, row in enumerate(value):
            yield from levels(row, path + (index,))


def audit_archive(path):
    counts = Counter()
    with tarfile.open(path) as handle:
        members = handle.getmembers()
        if any(not m.isfile() or Path(m.name).name != m.name for m in members):
            raise ValueError("unsafe archive member")
        expected = dict(
            line.split("  ", 1)[::-1]
            for line in handle.extractfile("SHA256SUMS.txt")
            .read()
            .decode()
            .splitlines()
        )
        if set(expected) != {m.name for m in members if m.name != "SHA256SUMS.txt"}:
            raise ValueError("archive checksum member set mismatch")
        for member in members:
            if member.name in expected:
                with handle.extractfile(member) as stream:
                    if (
                        hashlib.file_digest(stream, "sha256").hexdigest()
                        != expected[member.name]
                    ):
                        raise ValueError("archive checksum mismatch")
            with handle.extractfile(member) as stream:
                for raw in stream:
                    text = raw.decode("utf-8", errors="strict")
                    if "\r" in text or text.startswith("\ufeff"):
                        raise ValueError("BOM/CR in exported evidence")
                    import re

                    if re.search(
                        r'"(?:token_ids|input_ids|expected_token_ids|prompt_text|password|api_key|authorization|bearer_token|cache_salt_master)"\s*:',
                        text,
                    ):
                        raise ValueError(
                            "raw prompt/token/credential field in evidence"
                        )
                    if re.search(
                        r"\barn:[a-z0-9-]+:[a-z0-9-]*:[a-z0-9-]*:\d{12}:", text
                    ):
                        raise ValueError("account ARN in evidence")
            counts["members"] += 1
    return counts


def audit(session):
    counts = Counter()
    distributions = []
    final = session / "evidence.tar.gz"
    if final.stat().st_size > FINAL_LIMIT:
        raise ValueError("final metadata export over bound")
    with tarfile.open(final) as handle:
        if any(
            name.endswith(".tar.gz")
            or name
            in ("gateway.log", "fake-events.jsonl", "host-process-samples.jsonl")
            for name in handle.getnames()
        ):
            raise ValueError("duplicate full stream/archive in final export")
    counts.update(audit_archive(final))
    receipts = []
    for n in range(1, 5):
        base = session / f"sealed-runs/run-{n}"
        seal = json.loads(base.with_suffix(".receipt.json").read_text())
        path = session / "sealed-runs" / seal["measurement_digest"]["path"]
        if not 0 < path.stat().st_size <= DIGEST_LIMIT:
            raise ValueError("digest bound exceeded")
        with gzip.open(path, "rt", encoding="utf-8") as stream:
            digest = json.load(stream)
        original = json.loads((base / "run-artifact.json").read_text())["run"]
        terminals = {
            row["request_id"]: row
            for row in (json.loads(line) for line in (base / "gateway.log").open())
            if row.get("msg") == "request terminal"
        }
        correlations = [
            json.loads(line) for line in (base / "event-lag-correlations.jsonl").open()
        ]
        if "per_request" in digest:
            number, per_level = audit_table(original, digest, terminals, correlations)
            distributions.append({"run_number": n, "levels": per_level})
            counts["essential_request_rows"] += number
        old, new = dict(levels(original)), dict(levels(digest["run"]))
        if old.keys() != new.keys() and "per_request" not in digest:
            raise ValueError("digest lost a level")
        for level_path, a in old.items():
            b = digest["run"]
            for key in level_path:
                b = b[key]
            degraded = digest.get("detail_degradation", {})
            if degraded.get("native_sample_detail_dropped") and a.get("metrics"):
                names = {
                    name
                    for row in a["metrics"]
                    for name in row["values"]
                    if "vllm:" in name
                }
                expected = {}
                for name in names:
                    values = [
                        row["values"][name]
                        for row in a["metrics"]
                        if name in row["values"]
                    ]
                    expected[name] = {
                        "count": len(values),
                        "min": min(values),
                        "max": max(values),
                        "mean": sum(values) / len(values),
                    }
                if b.get("native_metric_aggregates") != expected:
                    raise ValueError("degraded native sample aggregates changed")
            if not degraded.get("native_sample_detail_dropped") and a.get(
                "runtime_regime"
            ) != b.get("runtime_regime"):
                raise ValueError("digest changed native regime signals")
            if "records" not in b:
                if b.get("request_detail_count") != len(a["records"]):
                    raise ValueError("optional rows dropped without correct count")
                counts["outcomes"] += len(a["records"])
                continue  # Essential rows independently checked above.
            if len(a["records"]) != len(b["records"]):
                raise ValueError("digest lost outcomes")
            for record, row in zip(a["records"], b["records"], strict=True):
                for key, value in row.items():
                    if (
                        key
                        not in (
                            "failure_class",
                            "gateway_terminal_code",
                            "upstream_error_body_code",
                        )
                        and record.get(key) != value
                    ):
                        raise ValueError("outcome changed in digest")
                terminal = terminals.get(
                    record.get("gateway_request_id") or record["request_id"]
                )
                if row["failure_class"] != classification(record, terminal):
                    raise ValueError(
                        "digest failure class differs from exact terminal join"
                    )
                counts["outcomes"] += 1
            if not degraded.get("native_sample_detail_dropped") and len(
                a.get("metrics", [])
            ) != len(b.get("metrics", [])):
                raise ValueError("digest lost native samples")
            for source, sample in zip(
                a.get("metrics", [])
                if not degraded.get("native_sample_detail_dropped")
                else [],
                b.get("metrics", []),
                strict=True,
            ):
                if sample != {
                    "offset_ns": source["offset_ns"],
                    "values": {
                        key: value
                        for key, value in source["values"].items()
                        if "vllm:" in key
                    },
                }:
                    raise ValueError("native metric changed")
                counts["native_samples"] += 1
        lag = digest["event_lag"]
        if lag["status"] != "established":
            raise ValueError("synthetic publisher lag was not established")
        rows = correlations
        summary = summarize_routing_correlations(rows)
        if any(lag[key] != value for key, value in summary.items()):
            raise ValueError("digest lag summary differs from retained joins")
        histogram = [0] * len(lag["histogram"]["counts"])
        for row in rows:
            if row["status"] == "observed":
                index = next(
                    i
                    for i, bound in enumerate(lag["histogram"]["upper_bounds_ns"])
                    if bound is None or row["routing_to_event_observation_ns"] <= bound
                )
                histogram[index] += 1
        if histogram != lag["histogram"]["counts"]:
            raise ValueError("lag histogram mismatch")
        if "observed_lags_ns" in lag and lag["observed_lags_ns"] != [
            row["routing_to_event_observation_ns"]
            for row in rows
            if row["status"] == "observed"
        ]:
            raise ValueError("digest lost exact percentile inputs")
        sequences = sorted(
            {
                json.loads(line)["sequence"]
                for line in (base / "fake-events.jsonl").open()
            }
        )
        gaps = sum(max(0, b - a - 1) for a, b in zip(sequences, sequences[1:]))
        if lag["snapshot_publisher_sequence_gap_count"] != gaps:
            raise ValueError("publisher sequence-gap count mismatch")
        counts["event_joins"] += len(rows)
        counts.update(audit_archive(base.with_suffix(".tar.gz")))
        receipts.append({"run_number": n, **seal["measurement_digest"]})
    return {
        "schema": "inf011-measurement-audit.v1",
        "status": "passed",
        "counts": dict(counts),
        "digests": receipts,
        "final_export_bytes": final.stat().st_size,
        "per_level_distributions": distributions,
        "basis": "Exact outcomes/native samples vs full run; terminal-ID taxonomy; lag summary/histogram independently recounted; member checksums and raw-field/privacy checks; CPU synthetic only",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--session", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.write_text(
        json.dumps(audit(args.session), indent=2) + "\n", encoding="utf-8", newline="\n"
    )
