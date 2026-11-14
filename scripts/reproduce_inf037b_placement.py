"""Write offline v4 placement fixture inputs and success/refusal receipts."""

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python/tests"))
from test_inf037b_placement import (  # noqa: E402
    change,
    fixture,
    node_memory,
    refresh_control,
    resources,
)

from inference_platform.inf037b_placement import Observation, check_placement  # noqa: E402
from inference_platform.inf037b_resolver import SessionDeadline  # noqa: E402


def examples():
    cases = {}
    cases["exactly_fitting_12_gib"] = fixture()
    under = fixture()
    node_memory(under, "12884901887")
    cases["under_12_gib_allocatable"] = under
    residual = fixture()
    change(
        residual,
        "requests",
        lambda obj: obj.update(
            pods=[
                {"uid": "other", "node_name": "export-node", "memory_requests": ["1"]}
            ]
        ),
    )
    cases["insufficient_residual"] = residual
    unequal = fixture()
    resources(unequal, "12Gi", "11Gi")
    cases["unequal_or_smaller_request_limit"] = unequal
    missing = fixture()
    change(missing, "node", lambda obj: obj["status"].pop("allocatable"))
    cases["missing_allocatable_proof"] = missing
    changed = fixture()
    change(
        changed,
        "node",
        lambda obj: obj["metadata"].update(uid="new-node-uid"),
        "pre_export",
    )
    cases["changed_node"] = changed
    physical = fixture()
    node_memory(physical, "11Gi")
    change(
        physical, "node", lambda obj: obj["status"]["capacity"].update(memory="12Gi")
    )
    cases["physical_12_gib_smaller_allocatable"] = physical
    late = fixture()
    late["now_ms"] = 12_600_001
    cases["cleanup_reserve_one_ms_short"] = late
    bound = fixture()
    change(
        bound,
        "pod",
        lambda obj: obj["spec"].update(nodeName="export-node"),
        "pre_schedule",
    )
    cases["bound_pre_schedule"] = bound
    early_residual = fixture()
    change(
        early_residual,
        "requests",
        lambda obj: obj.update(
            pods=[
                {"uid": "other", "node_name": "export-node", "memory_requests": ["1"]}
            ]
        ),
        "pre_schedule",
    )
    cases["pre_schedule_residual_one_byte_short"] = early_residual
    reused = fixture()
    reused["pre_export"]["node"] = reused["pre_schedule"]["node"]
    cases["reused_observation"] = reused
    before = fixture()
    before["deadline"] = SessionDeadline(1000, 18_001_000, 150)
    before["verified"] = Observation(before["verified"].raw, 150)
    cases["observation_before_origin"] = before
    equal = fixture()
    equal["pre_schedule"]["node"] = Observation(equal["pre_schedule"]["node"].raw, 200)
    cases["pre_export_equal_latest_pre_schedule"] = equal
    older = fixture()
    older["now_ms"] = 60_176
    older["pre_export"]["node"] = Observation(older["pre_export"]["node"].raw, 175)
    refresh_control(older)
    cases["registered_age_one_ms_excess"] = older
    for name, source, raw in (
        (
            "duplicate_json_member",
            "node",
            fixture()["pre_export"]["node"].raw.replace(
                b'"memory": "12Gi"', b'"memory": "8Gi", "memory": "12Gi"'
            ),
        ),
        ("nonfinite_json", "requests", b'{"extra": NaN}'),
        ("deep_json", "placement", b"[" * 200_000),
    ):
        case = fixture()
        case["pre_export"][source] = Observation(raw, 200)
        cases[name] = case
    oversized = fixture()
    node_memory(oversized, "9" * 5000)
    cases["oversized_allocatable"] = oversized
    contradictory = fixture()
    change(
        contradictory,
        "requests",
        lambda obj: obj.update(
            pods=[
                {
                    "uid": "pod-uid",
                    "node_name": "export-node",
                    "memory_requests": ["12Gi"],
                }
            ]
        ),
        "pre_schedule",
    )
    cases["pre_schedule_census_assigns_unbound_export_pod"] = contradictory
    empty = fixture()
    empty["pre_export"] = {}
    cases["empty_pre_export"] = empty
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    rows = []
    for name, inputs in examples().items():
        observations = {"verified": inputs["verified"]}
        for phase in ("pre_schedule", "pre_export"):
            observations.update(
                {phase + "/" + key: value for key, value in inputs[phase].items()}
            )
        rows.append(
            {
                "fixture": name,
                "raw_observations": {
                    key: {
                        "raw_utf8": value.raw.decode("utf-8"),
                        "observed_ms": value.observed_ms,
                    }
                    for key, value in observations.items()
                },
                "deadline": asdict(inputs["deadline"]),
                "now_ms": inputs["now_ms"],
                "receipt": check_placement(**inputs),
            }
        )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(
            {"scope": "offline synthetic fixtures only", "fixtures": rows}, indent=2
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(
        f"Wrote {len(rows)} fixture receipts: "
        + ", ".join(row["fixture"] + "=" + row["receipt"]["decision"] for row in rows)
    )


if __name__ == "__main__":
    main()
