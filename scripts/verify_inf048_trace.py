"""Compare recorded execution with INF-048's immutable registration, offline."""

import argparse
import hashlib
import json
from pathlib import Path

from inf048_kv_source_pins import SOURCE_PINS


def compare(data):
    env = data["environment"]
    assert data["registration_commit"] == "208cd03f619d9b63a34da30027c5a323b449a9f7"
    assert env["vllm"] == "0.29.0+cpu"
    assert env["cuda_available"] is False and env["torch_cuda"] is None
    for name, digest in SOURCE_PINS.items():
        assert env["executed_sources"][name] == digest, name
    cases = data["cases"]
    comparisons = {}
    for length, expected in [(6144, 10), (6272, 9)]:
        direct = cases[f"allocator_{length}"]
        events = direct["trace"]
        admitted = sum(e["success"] for e in events)
        boundary = len(events) == expected + 1 and not events[-1]["success"]
        footprint = (length + 15) // 16
        allocations_match = all(
            e["resident_after"] == footprint
            and e["free_before"] - e["free_after"] == footprint
            for e in events
            if e["success"]
        )
        sched = cases[f"scheduler_{length}"]
        running = len(sched["initial"]["running"])
        waiting = len(sched["initial"]["waiting"])
        comparisons[f"cold_{length}"] = {
            "expected_admitted": expected,
            "allocator_admitted": admitted,
            "scheduler_running": running,
            "scheduler_waiting": waiting,
            "free": sched["initial"]["free"],
            "match": admitted == expected
            and boundary
            and allocations_match
            and running == expected
            and waiting == 16 - expected
            and sched["initial"]["free"] == 3890 - expected * footprint,
        }
    growth = cases["growth_ten"]
    events = growth["trace"]
    preemptions = [i for i, e in enumerate(events) if e["event"] == "preempt_end"]
    transitions = []
    for i in preemptions:
        end, freed, begin, failed = (
            events[i],
            events[i - 1],
            events[i - 2],
            events[i - 3],
        )
        before, after = begin["before"], end["after"]
        rid = end["request"]
        ordered = (
            failed["event"] == "allocation"
            and not failed["success"]
            and begin["event"] == "preempt_begin"
            and freed["event"] == "free"
            and freed["request"] == rid
            and begin["request"] == rid
            and failed["step"] == begin["step"] == freed["step"] == end["step"]
            and end["status"] == "PREEMPTED"
            and end["preemptions"] == 1
            and after["computed"][rid] == 0
            and after["resident"][rid] == 0
            and after["waiting"][0] == rid
            and freed["free_after"] - freed["free_before"] == before["resident"][rid]
        )
        transitions.append(
            {
                "step": end["step"],
                "victim": rid,
                "failed_request": failed["request"],
                "failure_free_blocks": failed["free_before"],
                "victim_computed_before": before["computed"][rid],
                "victim_generated_before": before["generated"][rid],
                "freed_blocks": freed["blocks_before"],
                "ordered": ordered,
            }
        )
    comparisons["growth_ten"] = {
        "initial_running": len(growth["initial"]["running"]),
        "transitions": transitions,
        "match": len(growth["initial"]["running"]) == 10
        and bool(transitions)
        and all(t["ordered"] for t in transitions),
    }
    control = cases["growth_eight"]
    steps = [e for e in control["trace"] if e["event"] == "step"]
    failures = sum(
        e["event"] == "allocation" and not e["success"] for e in control["trace"]
    )
    preemptions = sum(e["event"] == "preempt_end" for e in control["trace"])
    final = control["final"]
    comparisons["growth_eight"] = {
        "steps": len(steps),
        "allocation_failures": failures,
        "preemptions": preemptions,
        "final_computed": final["computed"],
        "final_generated": final["generated"],
        "final_free": final["free"],
        "match": len(steps) == 129
        and failures == preemptions == 0
        and len(final["running"]) == 8
        and not final["waiting"]
        and all(n == 6272 for n in final["computed"].values())
        and all(n == 392 for n in final["resident"].values())
        and final["free"] == 3890 - 8 * 392,
    }
    # Every recorded full state must conserve the real pool, including null.
    states = []
    for case in cases.values():
        states.extend([case["final"]])
        if "initial" in case:
            states.append(case["initial"])
        for e in case["trace"]:
            states.extend(e[key] for key in ["state", "before", "after"] if key in e)
    assert all(s["free"] + sum(s["resident"].values()) + 1 == 3891 for s in states)
    return {
        "comparison": comparisons,
        "conservation_states": len(states),
        "all_predictions_match": all(c["match"] for c in comparisons.values()),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("trace", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    raw = args.trace.read_bytes()
    result = compare(json.loads(raw))
    result["trace_sha256"] = hashlib.sha256(raw).hexdigest()
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    if not result["all_predictions_match"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
