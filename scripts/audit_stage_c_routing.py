"""Audit a no-cost Stage C archive, optionally reclassifying legacy candidates.

Legacy exports removed complete prompt tokens and event streams. Re-evaluate
their retained first-store candidates without inventing any additional matches.
The fresh full rehearsal separately exercises the complete bounded search.
"""

import argparse
import hashlib
import json
import tarfile
from pathlib import Path

from inference_platform.decision_export import gateway_terminal_unix_ns
from inference_platform.kv_event_capture import (
    PUBLISHER_FLUSH_ALLOWANCE_NS,
    correlate_routing_events,
    summarize_routing_correlations,
)


def audit(archive_path: Path, *, legacy: bool = False) -> dict:
    with tarfile.open(archive_path) as archive:
        members = {
            member.name: archive.extractfile(member).read()
            for member in archive.getmembers()
            if member.isfile()
        }
    for line in members["SHA256SUMS.txt"].decode().splitlines():
        digest, name = line.split("  ", 1)
        assert hashlib.sha256(members[name]).hexdigest() == digest, name
    for name, raw in members.items():
        if name.endswith((".json", ".jsonl")):
            assert not raw.startswith(b"\xef\xbb\xbf") and b"\r" not in raw, name
            for text in (
                [raw.decode()] if name.endswith(".json") else raw.decode().splitlines()
            ):
                json.loads(text)
    artifact = json.loads(members["stage-c-artifact.json"])
    assert artifact["status"] == "completed"
    assert all(run["status"] == "completed" for run in artifact["timed_runs"])
    terminals = {
        row["request_id"]: row
        for line in members["gateway.log"].decode().splitlines()
        if (row := json.loads(line)).get("msg") == "request terminal"
    }
    outcomes = {}

    def visit(value):
        if isinstance(value, dict):
            if "request_id" in value and "outcome" in value:
                outcomes[value["request_id"]] = value
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(artifact["timed_runs"])
    original = artifact["decision_event_export"]["routing_to_event_observation"]
    rows, changed, old_violations = [], [], []
    for row in original:
        terminal = terminals[row["request_id"]]
        outcome = outcomes[row["request_id"]]
        offset = (
            terminal["router_decision_unix_ns"] - row["routing_decision_monotonic_ns"]
        )
        terminal_ns = gateway_terminal_unix_ns(terminal) - offset
        failed = (
            terminal["committed"] is False and terminal["cause"] != "completed"
        ) or (
            outcome["outcome"] in {"failed_before_content", "cancelled"}
            and outcome["first_content_offset_ns"] is None
        )
        if row["status"] == "observed" and row["event_observed_monotonic_ns"] > (
            terminal_ns + PUBLISHER_FLUSH_ALLOWANCE_NS
        ):
            old_violations.append(row["request_id"])
        if legacy:
            decision = {
                "request_id": row["request_id"],
                "routing_decision_monotonic_ns": row["routing_decision_monotonic_ns"],
                "gateway_terminal_monotonic_ns": terminal_ns,
                "expected_token_block_digests": row["matched_token_block_digests"]
                or ["legacy_unobserved_no_candidate"],
                "no_new_block": row["status"] == "no_new_block",
                "no_store_expected_request_failed": failed,
            }
            events = (
                [
                    {
                        "event_type": "BlockStored",
                        "sequence": row["event_sequence"],
                        "observed_monotonic_ns": row["event_observed_monotonic_ns"],
                        "token_block_digests": row["matched_token_block_digests"],
                    }
                ]
                if row["status"] == "observed"
                else []
            )
            current = correlate_routing_events([decision], events)[0]
            if current["status"] != row["status"]:
                changed.append(
                    {
                        "request_id": row["request_id"],
                        "old_status": row["status"],
                        "new_status": current["status"],
                        "http_status": outcome["http_status"],
                        "outcome": outcome["outcome"],
                        "old_lag_ns": row["routing_to_event_observation_ns"],
                    }
                )
        else:
            current = row
            assert current["gateway_terminal_monotonic_ns"] == terminal_ns
            if current["status"] == "observed_after_request_window":
                assert current["event_observed_monotonic_ns"] > (
                    terminal_ns + PUBLISHER_FLUSH_ALLOWANCE_NS
                )
                next_decision = current["next_same_identity_decision_monotonic_ns"]
                assert (
                    next_decision is None
                    or current["event_observed_monotonic_ns"] < next_decision
                )
            if failed:
                assert current["status"] == "no_store_expected_request_failed", current[
                    "request_id"
                ]
        rows.append(current)
    summary = summarize_routing_correlations(rows)
    assert summary["request_lifetime_bound_violation_count"] == 0
    if legacy:
        formerly_observed = [
            row
            for row in changed
            if row["old_status"] == "observed"
            and row["new_status"] == "no_store_expected_request_failed"
        ]
        assert len(formerly_observed) == 202
        assert all(
            row["new_status"] == "no_store_expected_request_failed"
            and row["outcome"] == "failed_before_content"
            and row["http_status"] == 502
            for row in formerly_observed
        )
    finalization = json.loads(members["session-finalization.json"])
    assert not finalization["errors"]
    assert all(child["reaped"] for child in finalization["children"])
    return {
        "schema": "inf011-stage-c-routing-bound-audit.v1",
        "status": "PASS",
        "archive": archive_path.as_posix(),
        "archive_sha256": hashlib.sha256(archive_path.read_bytes()).hexdigest(),
        "mode": "legacy_retained_candidate_reclassification"
        if legacy
        else "fresh_full_rehearsal",
        "legacy_limit": "Only retained first-store candidates re-evaluated; no additional match search"
        if legacy
        else None,
        "joined_decision_count": len(rows),
        **summary,
        "original_observed_count": sum(row["status"] == "observed" for row in original),
        "original_out_of_window_observed_count": len(old_violations),
        "formerly_observed_now_failed_count": sum(
            row["old_status"] == "observed"
            and row["new_status"] == "no_store_expected_request_failed"
            for row in changed
        ),
        "changed_rows": changed,
        "run_statuses": [run["status"] for run in artifact["timed_runs"]],
        "inner_checksums_and_strict_utf8_lf": "PASS",
        "children_reaped": True,
        "aws_calls_made": artifact["aws_calls_made"],
        "paid_plan_generated": artifact["paid_plan_generated"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--legacy", action="store_true")
    args = parser.parse_args()
    result = audit(args.archive, legacy=args.legacy)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(
        json.dumps(
            {key: value for key, value in result.items() if key != "changed_rows"}
        )
    )


if __name__ == "__main__":
    main()
