"""Inspect complete persisted HTTP records, including service-log coverage."""

import argparse
import collections
import hashlib
import json
import math
from pathlib import Path

from .r1_fixture_target import verify_generator_window
from .r1_loopback import distribution, inspect_records
from .r1_spec import SPEC_COMMIT, encoded


def verify(directory, full=True, generator_window=None):
    directory = Path(directory)
    report = inspect_records(directory, full)
    assert report["spec_commit"] == SPEC_COMMIT
    offers = collections.Counter()
    windows = {}
    for line in (directory / "offered-trace.jsonl").read_bytes().splitlines():
        row = json.loads(line)
        observed = row.get("observed_s", row.get("dispatch_s"))
        assert math.isclose(
            row["lateness_s"], max(0, observed - row["scheduled_s"]), abs_tol=1e-9
        ), row
        offers[row["phase"]] += 1
        windows.setdefault(row["phase"], []).append(row)
    for summary in report["windows"]:
        phase = json.loads((directory / (summary["name"] + ".json")).read_bytes())
        assert offers[phase["name"]] == phase["offered"]
        rows = windows[phase["name"]]
        assert sum(bool(row.get("not_dispatched")) for row in rows) == phase["missed"]
        assert distribution([row["lateness_s"] for row in rows])["p95"] == phase["lateness_p95_s"]
        if phase["q"] is not None:
            indices = [row["index"] for row in rows]
            assert len(set(indices)) == len(indices)
            assert indices == list(range(min(indices), max(indices) + 1))
        summary["gc_before_phase_s"] = phase["gc_before_phase_s"]
    gateway_outcomes = collections.Counter()
    validated_ids = set()
    outcomes_count = 0
    terminal_times = {}
    for line in (directory / "request-outcomes.jsonl").read_bytes().splitlines():
        row = json.loads(line)
        outcomes_count += 1
        terminal_times[(row["phase"], row["index"])] = row["ended_s"]
        if row["gateway"] is not None:
            gateway_outcomes[row["gateway"]] += 1
            if row["completed"]:
                assert row["request_id"] not in validated_ids
                validated_ids.add(row["request_id"])
    for summary in report["windows"]:
        if summary["q"] is not None:
            continue
        phase = json.loads((directory / (summary["name"] + ".json")).read_bytes())
        previous = {}
        for row in windows[summary["name"]]:
            worker = row["worker"]
            assert row["scheduled_s"] == previous.get(worker, phase["start_s"]), row
            previous[worker] = terminal_times[(summary["name"], row["index"])]
        assert summary["lateness"]["p95"] > 0, summary
        assert summary["generator_gc_automatic_samples"] == 0, summary
        assert summary["generator_rss_bytes"]["n"] > 0, summary
    service = json.loads((directory / "service-export.json").read_bytes())
    counts, ids = {}, set()
    for index in range(2):
        rows = [
            json.loads(line)
            for line in service["gateway_logs"][f"gateway-{index}.jsonl"].splitlines()
        ]
        starts = [row for row in rows if row.get("msg") == "gateway started"]
        terminals = [row for row in rows if row.get("msg") == "request terminal"]
        assert len(starts) == len(service["configurations"])
        assert len(terminals) == gateway_outcomes[index], (
            index,
            len(terminals),
            gateway_outcomes[index],
        )
        for row in terminals:
            assert row["request_id"] not in ids
            ids.add(row["request_id"])
        counts[index] = {"lines": len(rows), "startups": len(starts), "terminals": len(terminals)}
    assert validated_ids <= ids
    identities = [
        json.loads(line) for line in (directory / "identity-checks.jsonl").read_bytes().splitlines()
    ]
    samples = sum(row["collector_tick_duration"]["n"] * 2 for row in report["windows"])
    assert len(identities) < samples
    report.update(
        {
            "outcome_count": outcomes_count,
            "gateway_outcome_count": sum(gateway_outcomes.values()),
            "export_log_coverage": counts,
            "validated_request_ids_covered": len(validated_ids),
            "identity_checks": len(identities),
            "counter_scrapes_in_phases": samples,
            "identity_duration": distribution([row["duration_s"] for row in identities]),
            "collection_before_window": distribution(
                [row["gc_before_phase_s"] for row in report["windows"]]
            ),
            "all_offer_lateness_recomputed": True,
            "closed_loop_schedules_match_previous_terminal": True,
        }
    )
    if full:
        q = report["frozen"]["q"]
        runs = sum(slot["consumed"] for slot in report["slots"])
        logical_offers = sum(
            row["offered"] for row in report["windows"] if row["name"].startswith("run")
        )
        assert logical_offers == runs * math.ceil(600 * q) * 2, (logical_offers, runs, q)
        report["full_session_logical_offers"] = logical_offers
        report["fixture_target"] = verify_generator_window(generator_window, report["head"])
    report["record_hashes"] = {
        name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
        for name in (
            "result.json",
            "service-export.json",
            "export-receipt.json",
            "offered-trace.jsonl",
            "request-outcomes.jsonl",
            "events.jsonl",
        )
    }
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--session", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--idle-refusal", action="store_true")
    parser.add_argument("--generator-window", type=Path)
    args = parser.parse_args()
    report = verify(args.session, not args.idle_refusal, args.generator_window)
    args.output.write_bytes(encoded(report) + b"\n")
    print(
        json.dumps(
            {
                "head": report["head"],
                "outcomes": report["outcome_count"],
                "log_coverage": report["export_log_coverage"],
            }
        )
    )


if __name__ == "__main__":
    main()
