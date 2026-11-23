"""CPU tests for the sealed schedule and the pre-billable and privacy gates."""

import unittest

import inf060_probe_spec as spec
from inf060_probe_client import bracket, suppress
from inference_platform.routine_aws_tests import selection


class ProbeContractTests(unittest.TestCase):
    def test_schedule_and_budget_match_registered_arms(self):
        schedule = spec.request_manifest()
        measured = [row for row in schedule["slots"] if row["cohort"] == "measured"]
        self.assertEqual(
            [row["slot"] for row in measured if row["cancel"]], list(range(2, 120, 5))
        )
        self.assertEqual(len(schedule["slots"]), 150)
        self.assertEqual(schedule["prompt_tokens"], 1024)
        self.assertEqual(schedule["max_tokens"], 32)
        timing = spec.budget(
            262144,
            500000,
            15_242_788_168,
            69_000_000,
            {
                "compute_usd_per_h": 0.8048,
                "gp3_usd_per_gib_month": 0.08,
                "ipv4_usd_per_h": 0.005,
            },
        )
        self.assertEqual(timing["deadline_seconds"], 4800)
        self.assertEqual(timing["host_timer_seconds"], 4200)
        self.assertEqual(timing["export_seconds"], 196)
        self.assertEqual(timing["hard_cap_usd"], 5.37)

    def test_approval_needs_one_exact_line_in_latest_round(self):
        packet = {
            "source_commit": "3" * 40,
            "sealed_plans": {"create_sha256": "2" * 64},
        }
        digest = "1" * 64
        marker = f"{spec.PREFIX} manifest={digest} plan={'2' * 64} source={'3' * 40}"
        review = f"## Claude Round 1\r\n- Verdict: NO_BLOCKING_FINDINGS\r\n{marker}\r\n"
        spec.approval(review, packet, digest)
        with self.assertRaisesRegex(ValueError, "approval_marker"):
            spec.approval(
                review + "## Codex response\n" + marker + "\n", packet, digest
            )
        with self.assertRaisesRegex(ValueError, "approval_marker"):
            spec.approval(
                review + "## Claude Round 2\n- Verdict: NO_BLOCKING_FINDINGS\n",
                packet,
                digest,
            )

    def test_routine_rehearsal_selector_has_no_arbitrary_path(self):
        self.assertIn(
            "inf060_probe_rehearsal",
            selection({"inf060_probe_rehearsal": "inf060-native-r405-abc"}),
        )
        with self.assertRaisesRegex(ValueError, "routine:inf060_probe_rehearsal"):
            selection({"inf060_probe_rehearsal": "../inf060-native-r405-abc"})

    def test_privacy_gate_refuses_canary_and_token_fields(self):
        canary = "fixture-a"
        for value in (b"rendered fixture-a text\n", b"prompt_token_ids=[4,5]\n"):
            rows, receipt = suppress(value, [canary])
            self.assertIsNone(rows)
            self.assertEqual(receipt["status"], "REFUSED")
        for value in (
            b"input: prompt=None, prompt_token_ids=[]\n",
            b"INFO 11-19 00:00:00 stock\n",
        ):
            self.assertEqual(suppress(value, [canary])[1]["status"], "PASS")

    def test_bracket_checks_discontinuity_and_counts_stamp_width(self):
        start = [{"width": 10, "lo": 100, "hi": 110}]
        end = [{"width": 10, "lo": 102, "hi": 112}]
        sampling = [
            {"wall_ns": 105, "mono_ns": 0, "sample_width_ns": 4},
            {"wall_ns": 112, "mono_ns": 5, "sample_width_ns": 2},
        ]
        out = bracket(start, end, sampling)
        self.assertEqual(out["minimum_interval_width_ns"], 1024)
        sampling[0]["wall_ns"] += 60_000_000
        with self.assertRaisesRegex(ValueError, "clock_discontinuity"):
            bracket(start, end, sampling)
