"""Sixteen no-AWS cases through the production lifecycle entrypoint and durable gate."""

import argparse
import concurrent.futures
import json
import multiprocessing
import tempfile
from pathlib import Path

from .r1_lifecycle import ROLES, ConsumeGate, execute, sha
from .r1_spec import SPEC_COMMIT, encoded

SCENARIOS = (
    "success",
    "partial_provision",
    "readiness_failure",
    "measurement_failure",
    "export_failure",
    "session_cutoff",
    "teardown_failure",
    "quota_denial_before",
    "quota_denial_after",
    "wrong_hash",
    "stale_source",
    "uncommitted_review",
    "missing_approval",
    "budget_exceeded",
    "duplicate_apply",
    "concurrent_apply",
)


class Virtual:
    fixture, aws_calls = True, 0

    def __init__(self, scenario):
        self.scenario, self.elapsed, self.inventory = scenario, 0, []

    def now(self):
        return self.elapsed

    def preflight(self, plan, inputs):
        assert json.loads(plan)["schema"] == "OFFLINE-FIXTURE-NOT-TERRAFORM"

    def reserve_capacity(self, deadline):
        return {
            "result": "success",
            "error_code": None,
            "zone": "us-east-1b",
            "capacity_reservation_id": "fixture-capacity-reservation",
            "state": "active",
            "cleanup_verified": True,
        }

    def cancel_capacity(self, reservation_id, deadline):
        return {"verified": True, "state": "cancelled", "cancel_requested": True}

    def apply(self, plan, deadline, record):
        for role in ROLES:
            self.inventory.append(role)
            self.elapsed += 10
            record("host_created", role=role)
            if self.scenario == "partial_provision" and role == "gpu-1":
                raise RuntimeError("partial fixture provisioning failed")

    def ready(self, deadline, record):
        self.elapsed = 2400
        if self.scenario == "readiness_failure":
            raise RuntimeError("native/clock/host fitness failed; no calibration")

    def measure(self, deadline, record):
        if self.scenario == "session_cutoff":
            self.elapsed = deadline
            raise TimeoutError("session cutoff; partial export")
        self.elapsed += 2700
        record("calibration_complete")
        if self.scenario == "measurement_failure":
            raise RuntimeError("measurement failed; no automatic retry")
        for slot in range(1, 8):
            self.elapsed += 1440
            if self.elapsed > deadline:
                raise TimeoutError("measurement would invade export reserve")
            record("comparison_complete", slot=slot)

    def quota_denied_after(self):
        return self.scenario == "quota_denial_after"

    def close_admissions(self, deadline):
        pass

    def export(self, deadline):
        self.elapsed += 600
        assert self.elapsed <= deadline
        return self.scenario != "export_failure"

    def readiness_diagnostics(self, deadline):
        self.elapsed += 60
        assert self.elapsed <= deadline
        return [{"role": role, "Status": "Success"} for role in self.inventory]

    def destroy(self, deadline, record):
        for role in reversed(self.inventory.copy()):
            self.elapsed += 10
            record("destroy_attempted", role=role)
            if self.scenario != "teardown_failure" or role != "gpu-0":
                self.inventory.remove(role)
        assert self.elapsed <= deadline

    def verify_teardown(self, deadline):
        return self.inventory.copy()


def fixture_inputs(scenario):
    plan = encoded(
        {
            "schema": "OFFLINE-FIXTURE-NOT-TERRAFORM",
            "spec": SPEC_COMMIT,
            "roles": ROLES,
            "gpu_root_gib": 200,
            "cpu_root_gib": 40,
        }
    )
    inputs = {
        "plan_sha256": "0" * 64 if scenario == "wrong_hash" else sha(plan),
        "spec_commit": SPEC_COMMIT,
        "roles": list(ROLES),
        "region": "us-east-1",
        "gpu_type": "g6.xlarge",
        "cpu_type": "c6i.2xlarge",
        "m4_estimate_usd": 86.55 if scenario == "budget_exceeded" else 85.92,
        "session_estimate_usd": 31.12,
        "quota_denied": scenario == "quota_denial_before",
        "commands": {"ready": ["fixture", "--inputs", "docs/R1_SESSION_INPUTS.json"]},
    }
    return plan, inputs


def fixture_approval(scenario):
    def validate(inputs):
        if scenario in {"stale_source", "uncommitted_review", "missing_approval"}:
            raise ValueError(scenario + ": fixture admission closed")

    return validate


def worker(root, index, scenario):
    plan, inputs = fixture_inputs(scenario)
    return execute(
        Virtual(scenario),
        plan,
        inputs,
        ConsumeGate(Path(root) / "consume.sqlite3"),
        fixture_approval(scenario),
        Path(root) / f"worker-{index}.json",
    )


def rehearse(scenario):
    if scenario not in SCENARIOS:
        raise ValueError("unknown lifecycle fixture")
    with tempfile.TemporaryDirectory() as root:
        if scenario in {"duplicate_apply", "concurrent_apply"}:
            if scenario == "concurrent_apply":
                with concurrent.futures.ProcessPoolExecutor(
                    max_workers=8, mp_context=multiprocessing.get_context("spawn")
                ) as pool:
                    results = list(pool.map(worker, [root] * 8, range(8), ["success"] * 8))
            else:
                results = [worker(root, i, "success") for i in range(2)]
            winners = sum(x["apply_count"] for x in results)
            assert winners == 1
            return {
                "scenario": scenario,
                "fixture": True,
                "aws_calls": 0,
                "apply_winners": winners,
                "duplicate_rejections": [x["error"] for x in results if not x["apply_count"]],
                "cross_process": scenario == "concurrent_apply",
                "results": results,
                "entrypoint": "inference_platform.r1_lifecycle.execute",
            }
        return worker(root, 0, scenario)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    receipts = [rehearse(scenario) for scenario in SCENARIOS]
    for receipt in receipts:
        (args.output / (receipt["scenario"] + ".json")).write_bytes(encoded(receipt) + b"\n")
    print(
        json.dumps(
            {
                "offline_fixture_cases": len(receipts),
                "aws_calls": 0,
                "paid_adapter_implemented": True,
                "entrypoint": "inference_platform.r1_lifecycle.execute",
            }
        )
    )


if __name__ == "__main__":
    main()
