import unittest

from inference_platform.r1_lifecycle_rehearsal import SCENARIOS, rehearse


class LifecycleTests(unittest.TestCase):
    def test_guarded_offline_lifecycle_and_recovery(self):
        for scenario in SCENARIOS:
            with self.subTest(scenario=scenario):
                result = rehearse(scenario)
                self.assertTrue(result["fixture"])
                self.assertEqual(result["aws_calls"], 0)
                if "apply_winners" in result:
                    self.assertEqual(result["apply_winners"], 1)
                    continue
                self.assertLessEqual(result["apply_count"], 1)
                self.assertLessEqual(result["elapsed_s"], 16080)
                created = [
                    event["role"]
                    for event in result["events"]
                    if event["event"] == "fixture_host_created"
                ]
                destroyed = [
                    event["role"]
                    for event in result["events"]
                    if event["event"] == "fixture_destroy_attempted"
                ]
                self.assertEqual(destroyed, created[::-1])
                if scenario == "teardown_failure":
                    self.assertEqual(result["remaining_inventory"], ["gpu-0"])
                    self.assertIn("paid work halted", result["error"])
                else:
                    self.assertEqual(result["remaining_inventory"], [])
                if created and scenario not in {"partial_provision", "readiness_failure"}:
                    export = next(
                        event
                        for event in result["events"]
                        if event["event"] == "fixture_export_attempted"
                    )
                    self.assertLessEqual(export["elapsed_s"] + 600, 15780)
                if scenario in {
                    "success",
                    "quota_denial_after",
                    "export_failure",
                    "teardown_failure",
                }:
                    self.assertEqual(
                        [
                            event["slot"]
                            for event in result["events"]
                            if event["event"] == "fixture_comparison_complete"
                        ],
                        list(range(1, 8)),
                    )
                else:
                    self.assertFalse(
                        any(
                            event["event"] == "fixture_comparison_complete"
                            for event in result["events"]
                        )
                    )
                if scenario not in {"success", "quota_denial_after"}:
                    self.assertIsNotNone(result["error"])
                if scenario == "quota_denial_after":
                    self.assertTrue(
                        next(
                            event
                            for event in result["events"]
                            if event["event"] == "quota_denial_reported"
                        )["current_bounded_lifecycle_continues"]
                    )
                if scenario in {
                    "wrong_hash",
                    "stale_source",
                    "uncommitted_review",
                    "missing_approval",
                    "budget_exceeded",
                    "quota_denial_before",
                }:
                    self.assertEqual(result["apply_count"], 0)
                    self.assertEqual(created, [])
