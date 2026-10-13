"""Run the same committed session entrypoint; inspect persisted output records."""

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

from .r1_fake import SCENARIOS
from .r1_spec import SPEC_COMMIT, digest, encoded

FAILED = {
    "exhaust_before_run1",
    "exhaust_between_runs",
    "positive_control_failure",
    "zero_hit_failure",
    "idle_refusal",
    "three_refusals",
    "session_cutoff",
}


def verify(directory, scenario):
    if not __debug__:
        raise RuntimeError("rehearsal assertions require Python without -O")
    directory = Path(directory)
    result = json.loads((directory / "result.json").read_bytes())
    event_bytes = (directory / "events.jsonl").read_bytes()
    assert hashlib.sha256(event_bytes).hexdigest() == result["events_sha256"]
    events = [json.loads(line) for line in event_bytes.splitlines()]
    assert (
        result["scenario"] == scenario and result["fake"] and result["spec_commit"] == SPEC_COMMIT
    )
    assert bool(result["error"]) == (scenario in FAILED), (scenario, result["error"])
    starts = [event for event in events if event["event"] == "comparison_started"]
    expected = (
        [1]
        if scenario == "exhaust_between_runs"
        else []
        if scenario in FAILED
        else list(range(1, 7))
    )
    if scenario == "noise_repeat":
        expected = list(range(1, 8))
    assert [event["id"] for event in starts] == expected
    assert [slot["id"] for slot in result["slots"] if slot["consumed"]] == expected
    assert all(slot["state"] == "completed" for slot in result["slots"] if slot["consumed"])
    assert all(slot["state"] == "not_started" for slot in result["slots"] if not slot["consumed"])
    preparations = [event for event in events if event["event"] == "reset_preparation_started"]
    assert all(
        event["slot_state"] == "pending" and not event["slot_consumed"] for event in preparations
    )
    failures = [event for event in events if event["event"] == "reset_preparation_failed"]
    assert all(
        event["slot_state"] == "not_started" and not event["slot_consumed"] for event in failures
    )
    assert all(
        not any(start["id"] == failure["pending"] for start in starts) for failure in failures
    )
    generations = {
        replica["generation"]
        for event in events
        for replica in event.get("replicas", []) + event.get("final_baselines", [])
    }
    assert generations == {"fake-generation-0", "fake-generation-1"}
    assert all(replica["age_s"] <= 1 for event in events for replica in event.get("replicas", []))
    waits = [event for event in events if event["event"] == "reset_overrun_wait"]
    if scenario in {
        "delayed_success",
        "exhaust_before_run1",
        "exhaust_between_runs",
        "session_cutoff",
    }:
        assert len(waits) == 1 and waits[0]["elapsed_s"] == 60
        terminal = next(
            event
            for event in events
            if event.get("pending") == waits[0]["pending"]
            and event["event"] in {"reset_preparation_succeeded", "reset_preparation_failed"}
        )
        assert terminal["wait_elapsed_s"] == terminal["elapsed_s"] - 60
        assert 60 < terminal["elapsed_s"] <= 120
        if scenario.startswith("exhaust"):
            assert terminal["elapsed_s"] == 120 and terminal["wait_elapsed_s"] == 60
        elif scenario == "session_cutoff":
            assert terminal["elapsed_s"] == 75 and terminal["wait_elapsed_s"] == 15
        else:
            assert [event["id"] for event in starts].count(terminal["pending"]) == 1
    else:
        assert not waits
    replies = [event for event in events if event["event"] == "reset_reply"]
    for pending in {event["pending"] for event in replies}:
        for backend in range(2):
            for stage in ("clear", "cleanup"):
                attempts = [
                    event
                    for event in replies
                    if event["pending"] == pending
                    and event["backend"] == backend
                    and event["stage"] == stage
                ]
                assert len(attempts) <= 3
                assert all(
                    b["attempt_started_elapsed_s"] - a["attempt_started_elapsed_s"] >= 1
                    for a, b in zip(attempts, attempts[1:], strict=False)
                )
    probes = [event for event in events if event["event"] == "sentinel"]
    assert all(
        change["queries"] == 1024 and change["completions"] == 1 and 0 <= change["hits"] <= 1008
        for event in probes
        for change in event["deltas"]
    )
    for start in starts:
        end = next(
            event
            for event in events
            if event["event"] == "reset_preparation_succeeded" and event["pending"] == start["id"]
        )
        assert end["final_baselines"] == start["baselines"]
        cleanups = [
            event
            for event in replies
            if event["pending"] == start["id"] and event["stage"] == "cleanup"
        ]
        assert len(cleanups) == 2 and all(event["response"]["success"] for event in cleanups)
        assert all(
            event["fixture_cache_state"] == {"fixture": True, "before": True, "after": False}
            for event in cleanups
        )
        assert start["session_elapsed_s"] >= end["session_elapsed_s"]
    refusals = [event for event in events if event["event"] == "reset_refusal"]
    if scenario == "idle_refusal":
        assert len([event for event in replies if event["pending"] == 1]) == 1
        assert (
            next(event for event in refusals if event["pending"] == 1)["observable_work"] is False
        )
    if scenario in {"in_flight_refusal", "http200_false"}:
        assert next(event for event in refusals if event["pending"] == 1)["observable_work"] is True
        assert any(
            event["pending"] == 1 and event["response"] == {"status": 200, "success": False}
            for event in replies
        )
    if scenario == "positive_control_failure":
        assert "positive-control" in result["error"]
        assert any(
            e["pending"] == 1
            and e["label"] == "positive_control"
            and all(d["hits"] == 0 for d in e["deltas"])
            for e in probes
        )
    if scenario == "zero_hit_failure":
        assert "nonzero" in result["error"]
        assert any(
            e["pending"] == 1
            and e["label"] == "zero_hit"
            and all(d["hits"] > 0 for d in e["deltas"])
            for e in probes
        )
    if scenario == "warm_unstable":
        warm = [e for e in events if e["event"] == "warmup_complete"]
        assert len(warm) == 6 and all(
            e["seconds"] == 600 and e["label"] == "valid-unstable" for e in warm
        )
    if scenario == "noise_repeat":
        assert result["runs"][-1]["policy"] == "rr" and result["runs"][-1]["block"] == "b3"
        assert result["noise"]["repeat_remaining"] == 0
        assert not result["noise"]["metrics"]["TTFT_p50"]["validated"]
    assert result["finish"]["dispatch_while_closed"] == 0
    return {
        "case": scenario,
        "head": result["head"],
        "result_sha256": digest(result),
        "events_sha256": result["events_sha256"],
        "slots": result["slots"],
        "starts": starts,
        "waits": waits,
        "failures": failures,
        "preparation_terminal_records": [
            event
            for event in events
            if event["event"] in {"reset_preparation_succeeded", "reset_preparation_failed"}
        ],
        "refusals": refusals,
        "reset_replies": replies,
        "probe_records": probes,
        "verified": True,
        "fake": True,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--tokenizer-cache", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    for path in (root / "python/src/inference_platform").glob("r1_*.py"):
        committed = subprocess.check_output(
            ["git", "show", f"{head}:{path.relative_to(root).as_posix()}"], cwd=root
        )
        if path.read_bytes().replace(b"\r\n", b"\n") != committed:
            raise ValueError("rehearsal requires committed entrypoint and dependencies")
    args.output.mkdir(parents=True, exist_ok=True)
    cases = []
    for scenario in SCENARIOS:
        directory = args.output / scenario
        if directory.exists():
            raise ValueError("output already exists; preserve prior records")
        command = [
            sys.executable,
            "-m",
            "inference_platform.r1_session",
            "--spec-commit",
            SPEC_COMMIT,
            "--manifest",
            str(args.manifest),
            "--fake-scenario",
            scenario,
            "--output",
            str(directory),
        ]
        if args.tokenizer_cache:
            command += ["--tokenizer-cache", str(args.tokenizer_cache)]
        subprocess.run(command, check=True, cwd=root, timeout=120)
        cases.append(verify(directory, scenario))
        print(f"verified persisted records: {scenario}", flush=True)
    receipt = {
        "head": head,
        "entrypoint": "inference_platform.r1_session",
        "spec_commit": SPEC_COMMIT,
        "cases": cases,
        "count": len(cases),
        "fake_only": True,
    }
    (args.output / "rehearsal.json").write_bytes(encoded(receipt) + b"\n")


if __name__ == "__main__":
    main()
