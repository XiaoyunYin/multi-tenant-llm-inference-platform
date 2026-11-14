"""Shared Go test output summary for DEC-077 preflight and host checks."""

import re

REAL_REDIS_EXPECTED_TESTS = (
    "TestRedisDynamicCapacityPhases",
    "TestRedisDynamicMutationSelfCheck",
    "TestRedisCoordinatorWithheldMarkerBlocksRestoration",
)


class GoTestSummaryError(ValueError):
    def __init__(self, message, summary):
        super().__init__(message)
        self.summary = summary


def go_test_summary(log: str, *, expected_tests=REAL_REDIS_EXPECTED_TESTS) -> dict:
    """Count verbose Go test results and refuse missing, empty, or skipped runs."""
    passed = re.findall(r"(?m)^\s*--- PASS:", log)
    skipped = re.findall(r"(?m)^\s*--- SKIP:", log)
    missing = [name for name in expected_tests if name not in log]
    summary = {
        "passed_tests": len(passed),
        "skipped_tests": len(skipped),
        "missing_expected_tests": missing,
    }
    if skipped:
        raise GoTestSummaryError("go_test_skipped_tests:" + str(len(skipped)), summary)
    if missing:
        raise GoTestSummaryError("go_test_missing_expected_tests:" + ",".join(missing), summary)
    if not passed:
        raise GoTestSummaryError("go_test_no_test_results", summary)
    return summary
