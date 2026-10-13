"""Run portable snapshot tests; report cases requiring omitted private records.

The private all suite still runs every case through run_python_tests.py.
"""

import json
import sys
import unittest
from pathlib import Path

PRIVATE_MODULES = {
    "test_remote_source_fitness",
    "test_stage_c_fitness",
    "test_stage_c_preflight",
    "test_stage_c_protocol",
    "test_stage_c_session",
    "test_stage_c_sizing",
}
PRIVATE_CASES = {
    "test_r1.ManifestTests": "setUpClass requires private 3d3c36a preregistration history",
    "test_r1_cloud.CloudTests.test_host_spec_artifact_checks_identical_registered_bytes_without_git": "reads private 3d3c36a preregistration blob",
    "test_r1_fixture_target.FixtureTargetTests.test_committed_packet_window_schema_and_demonstrated_wall_rate": "reads omitted private Round87 measurement receipts",
}


def cases(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from cases(item)
        else:
            yield item


def select(suite):
    selected, omitted = [], []
    for case in cases(suite):
        identity = case.id()
        reason = next(
            (
                reason
                for key, reason in PRIVATE_CASES.items()
                if identity == key or identity.startswith(key + ".")
            ),
            None,
        )
        if reason:
            omitted.append({"case": identity, "reason": reason})
        else:
            selected.append(case)
    return unittest.TestSuite(selected), omitted


def main():
    directory = Path(__file__).resolve().parents[1] / "python/tests"
    sys.path.insert(0, str(directory))
    modules = sorted(
        p.stem for p in directory.glob("test_*.py") if p.stem not in PRIVATE_MODULES
    )
    suite = unittest.TestSuite(
        unittest.defaultTestLoader.loadTestsFromName(name) for name in modules
    )
    suite, omitted = select(suite)
    print(
        json.dumps(
            {
                "private_record_modules_excluded": sorted(PRIVATE_MODULES),
                "private_record_cases_excluded": omitted,
                "public_cases": suite.countTestCases(),
            }
        ),
        flush=True,
    )
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return int(not result.wasSuccessful())


if __name__ == "__main__":
    raise SystemExit(main())
