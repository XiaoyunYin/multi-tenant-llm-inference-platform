"""Run Linux port/controller/placement suites and retain raw offline wire receipts."""

import argparse
import copy
import hashlib
import io
import json
import os
import platform
import stat
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python/tests"))

from inference_platform import inf037b_durable_ports as durable  # noqa: E402

FIXTURES = [
    "test_DEC_069_billing_origin_and_effective_deadline",
    "test_Two_reviewed_AZ_plans_with_two_distinct_plan_hash_markers",
    "test_Every_reviewed_AZ_alternative_refuses",
    "test_An_alternative_whose_literal_C_or_D_session_differs",
    "test_A_reservation_is_partly_acquired_then_fails_verification",
    "test_Independent_backstop_arming_is_not_confirmed",
    "test_The_full_remaining_work_check_fails_immediately_before_consume",
]
FILES = [
    "python/src/inference_platform/inf037b_controller.py",
    "python/src/inference_platform/inf037b_durable_ports.py",
    "python/src/inference_platform/inf037b_authority.py",
    "python/src/inference_platform/inf037b_ports.py",
    "python/tests/inf037b_ports_support.py",
    "python/tests/test_inf037b_ports.py",
    "python/tests/test_inf037b_ports_git.py",
    "python/tests/fixtures/inf037b_ports_authority.json",
    "scripts/check_inf037b_ports.py",
    "scripts/check_inf037b_ports_mutations.py",
]


def hashes():
    return {
        path: hashlib.sha256(
            (ROOT / path).read_bytes().replace(b"\r\n", b"\n")
        ).hexdigest()
        for path in FILES
    }


class Result(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.passed = []

    def addSuccess(self, test):
        self.passed.append(test.id())
        super().addSuccess(test)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if os.name != "posix":
        parser.error(
            "positive filesystem validation requires Linux; use the pinned offline container"
        )
    import inf037b_ports_support as support
    import test_inf037b_controller as controller_tests
    import test_inf037b_placement as placement_tests
    import test_inf037b_ports as port_tests

    source_hashes = hashes()
    suite = unittest.TestSuite(
        unittest.defaultTestLoader.loadTestsFromModule(module)
        for module in (controller_tests, port_tests, placement_tests)
    )
    result = unittest.TextTestRunner(verbosity=2, resultclass=Result).run(suite)
    recovery_cases = copy.deepcopy(support.RECOVERY_CASES)
    fixtures = []
    for reverse in (False, True):
        for line, name in enumerate(FIXTURES, 84):
            rigs = []

            def factory(reverse=reverse):
                rig = support.Rig()
                if reverse:
                    rig.plans.reverse()
                    rig.ports()
                rigs.append(rig)
                return rig

            stream = io.StringIO()
            with patch.object(controller_tests, "Rig", factory):
                replay = unittest.TextTestRunner(stream=stream).run(
                    controller_tests.ControllerTests(name)
                )
            row = {
                "v4_line": line,
                "test": name,
                "az_order": "ba" if reverse else "ab",
                "passed": replay.wasSuccessful(),
                "skips": len(replay.skipped),
                "scenarios": [],
            }
            for rig in rigs:
                row["scenarios"].append(
                    {
                        "journal": copy.deepcopy(rig.journal.rows),
                        "consumptions": rig.gate.consumptions,
                        "requests": rig.responses.requests,
                        "raw_request_response_records": rig.responses.records,
                        "authority_ledgers": {
                            name: service.store.read()
                            for name, service in rig.responses.services.items()
                        },
                        "effects": rig.world.trace,
                    }
                )
                rig.close()
            fixtures.append(row)
    audit = []
    rig = support.Rig()
    real_sync = os.fsync

    def synced(fd):
        target = Path(os.readlink(f"/proc/self/fd/{fd}")).relative_to(rig.root)
        audit.append(
            {
                "ordinal": len(audit) + 1,
                "kind": "directory" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file",
                "relative_parent": str(
                    target if stat.S_ISDIR(os.fstat(fd).st_mode) else target.parent
                ),
            }
        )
        return real_sync(fd)

    with patch.object(durable.os, "fsync", side_effect=synced):
        rig.run()
    rig.close()
    if hashes() != source_hashes:
        raise RuntimeError("source changed during validation")
    receipt = {
        "scope": "offline recorded transports and real temporary Linux filesystem only",
        "platform": platform.system(),
        "python": platform.python_version(),
        "source_lf_sha256": source_hashes,
        "tests_run": result.testsRun,
        "skips": len(result.skipped),
        "passed_tests": result.passed,
        "failures": [str(t) for t, _ in result.failures + result.errors],
        "fixtures": fixtures,
        "effect_delivery_recovery_cases": recovery_cases,
        "cancel_verification_cases": support.CANCEL_CASES,
        "delayed_original_apply_cases": support.DELAYED_APPLY_CASES,
        "real_fsync_audit": audit,
        "file_fsync_calls": sum(a["kind"] == "file" for a in audit),
        "directory_fsync_calls": sum(a["kind"] == "directory" for a in audit),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(receipt, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    print(
        f"{result.testsRun} tests; {len(result.skipped)} skips; {len(fixtures)} fixture/order replays; file fsync={receipt['file_fsync_calls']}, directory fsync={receipt['directory_fsync_calls']}"
    )
    return (
        not result.wasSuccessful()
        or bool(result.skipped)
        or any(not f["passed"] or f["skips"] for f in fixtures)
    )


if __name__ == "__main__":
    sys.exit(main())
