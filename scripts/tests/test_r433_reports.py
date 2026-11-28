import json
import tempfile
import unittest
from pathlib import Path

from analyze_inf061_results import (
    count_pairs,
    count_window,
    gateway_sanity,
    recount,
    verified_count,
)
from rehearse_inf054_kind import stream_overlap
from inf054_autoscaling import (
    ARMS,
    BURST_SECONDS,
    CYCLES,
    forecast,
    keda_image_refs,
    serving_values,
    tally,
    tape,
    tape_sha256,
)


class AutoscalingPlanTests(unittest.TestCase):
    def test_all_nine_cycles_have_identical_offers(self):
        expected = "2959160ccc4d3b245ecf534656033950c8e0a115362da7d1372883a711073056"
        self.assertEqual(tape_sha256(), expected)
        offers = tape()
        self.assertEqual(len(offers), 2760)
        self.assertEqual(len({row["seed"] for row in offers}), 2760)
        self.assertEqual(offers[60]["offset_ns"], 60_000_000_000)
        self.assertLess(offers[-1]["offset_ns"], 960_000_000_000)
        self.assertEqual(len(ARMS) * CYCLES, 9)

    def test_replica_ownership_and_digest_pins(self):
        fixed, scaled, warm = map(serving_values, ARMS)
        self.assertEqual((fixed["engineReplicas"], warm["engineReplicas"]), (1, 2))
        self.assertFalse(fixed["autoscaling"]["enabled"])
        self.assertTrue(scaled["autoscaling"]["enabled"])
        self.assertEqual(scaled["autoscaling"]["threshold"], "2")
        self.assertEqual(scaled["autoscaling"]["stabilizationSeconds"], BURST_SECONDS)
        self.assertEqual(len(keda_image_refs()), 3)
        for image in keda_image_refs():
            self.assertRegex(image, r"@sha256:[0-9a-f]{64}$")

    def test_missed_and_rejected_offers_stay_in_denominator(self):
        rows = [
            {"outcome": "completed", "ttft_s": 1, "completed_s": 15},
            {"outcome": "completed", "ttft_s": 1.1, "completed_s": 15},
            {
                "outcome": "rejected",
                "http_status": 429,
                "gateway_code": "system_capacity",
            },
            {"outcome": "missed_offer"},
        ]
        result = tally(rows)
        self.assertEqual(result["slo_attainment"], 0.25)
        self.assertEqual(result["http_429_by_code"], {"system_capacity": 1})
        self.assertEqual(result["ttft_s"], {"n": 2, "p50": 1, "p95": 1.1})

    def test_scale_down_accepts_complete_and_partial_streams_open_at_transition(self):
        example = {
            "started_ns": 10,
            "first_content_ns": 20,
            "closed_ns": 40,
            "pod_uid": "fixture-ordinal",
            "status": 200,
            "complete": True,
        }
        rows = [
            example,
            {**example, "complete": False},
            {**example, "closed_ns": 29},
            {**example, "first_content_ns": 31},
            {**example, "pod_uid": "other"},
            {**example, "first_content_ns": None, "status": None, "complete": False},
        ]
        outcome = stream_overlap(rows, "fixture-ordinal", 30, 10)
        self.assertEqual(outcome["overlap_outcomes"], ["complete", "partial"])
        self.assertEqual(outcome["probes"][-1]["outcome"], "error")
        self.assertNotIn("fixture-ordinal", str(outcome))
        missing = stream_overlap(rows, "fixture-ordinal", None, 10)
        self.assertEqual(missing["overlap_outcomes"], [])
        self.assertEqual(len(missing["probes"]), len(rows))

    def test_forecast_covers_two_attempts(self):
        result = forecast(2.8630444444444443)
        self.assertEqual(result["deadline_seconds"], 17820)
        self.assertAlmostEqual(result["estimated_with_retry_usd"], 42.930175)
        self.assertLess(
            result["estimated_with_retry_usd"], result["cap_including_retry_usd"]
        )


class NativeRecountTests(unittest.TestCase):
    def test_attempt_two_sanity_recount_preserves_refusal_and_missing(self):
        with tempfile.TemporaryDirectory() as work:
            folder = Path(work)
            plan = {
                "starts": [{"name": "bf16-16"}, {"name": "bf16-32"}],
                "stage_a": {"output_cap": 128},
                "stage_c": {"arms": ["b_alone"]},
            }
            cap = {
                "http_status": 200,
                "outcome": "completed",
                "completion_tokens": 128,
                "max_tokens": 128,
            }
            q = {**cap, "completion_tokens": 2, "max_tokens": 8}
            (folder / "gateway-sanity-bf16-16-gateway.json").write_text(
                json.dumps({"a": cap, "b": cap, "q": q}), encoding="utf-8"
            )
            bad = {
                **cap,
                "http_status": 400,
                "outcome": "rejected",
                "completion_tokens": None,
            }
            (folder / "gateway-sanity-stage-c-0.json").write_text(
                json.dumps({"a": bad}), encoding="utf-8"
            )
            rows = gateway_sanity(folder, plan)
            self.assertEqual(rows["bf16-16-gateway"]["status"], "pass")
            self.assertEqual(
                rows["stage-c-0"], {"status": "refused", "tenants": {"a": bad}}
            )
            self.assertIsNone(rows["bf16-32-gateway"])

    def test_counts_only_validated_output_and_keeps_partial_ttft(self):
        rows = [
            {
                "outcome": "completed",
                "ttft_s": 0.9,
                "completed_s": 12,
                "tpot_s": 0.2,
                "completion_tokens": 10,
            },
            {"outcome": "partial", "ttft_s": 0.1, "completion_tokens": 5},
            {
                "outcome": "rejected",
                "http_status": 429,
                "gateway_code": "system_capacity",
            },
            {"outcome": "missed_offer"},
        ]
        result = count_window(rows, 20, slo=(1, 15))
        self.assertEqual(result["slo_met_per_offer"], 0.25)
        self.assertEqual(result["completed_output_tokens"], 10)
        self.assertEqual(result["ttft_s"], {"n": 2, "p50": 0.1, "p95": 0.9})
        self.assertEqual(result["output_tokens_per_s"], 0.5)
        self.assertEqual(result["http_429"], 1)
        with self.assertRaisesRegex(ValueError, "inf061_runtime_reducer_disagrees"):
            verified_count(rows, 20, {**result, "scheduled": 3}, slo=(1, 15))

    def test_quality_pairs_include_nonexact_and_unreached_items(self):
        result = count_pairs(
            ["wrong", "exact", "exact", "unreached"],
            ["exact", "failed", "exact", "invalid"],
        )
        self.assertEqual(
            result,
            {"wins": 1, "losses": 1, "discordant": 2, "both_exact": 1, "both_other": 1},
        )

    def test_absent_archive_rows_are_null(self):
        plan = {
            "starts": [{"name": "bf16-16", "stages": ["A", "C", "quality-bf16-first"]}],
            "stage_a": {"rates": [1], "window_s": 1},
            "stage_c": {"arms": ["b_alone"]},
        }
        session = {
            "gpu_node_hourly_usd": 0.8048,
            "full_estimate_usd": 1,
            "c_lead_s": 30,
        }
        with tempfile.TemporaryDirectory() as folder:
            result = recount(Path(folder), plan, session)
        self.assertIsNone(result["starts"]["bf16-16"]["readback"])
        self.assertIsNone(result["starts"]["bf16-16"]["cells"]["A"]["1"])
        self.assertIsNone(result["starts"]["bf16-16"]["cells"]["C"]["b_alone"])
        self.assertIsNone(result["quality"]["bf16-first"])
        self.assertIsNone(result["cost"]["arms"]["bf16-16"]["gpu_node_usd_per_million"])
