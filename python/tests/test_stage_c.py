import json
import time
import unittest
import urllib.request
from unittest.mock import patch

from inference_platform.calibration import CalibrationConfig, run_calibration
from inference_platform.fake_backend import FakeBackend, FakeBackendConfig
from inference_platform.kv_event_capture import (
    correlate_routing_events,
    read_http_sse_event_stream,
    token_block_digests,
)
from inference_platform.stage_c import StageCConfig, run_stage_c
from inference_platform.stage_c_prompts import prompt_footprint
from inference_platform.stage_c_tokenizer import pinned_tokenizer


class StageCRehearsalTest(unittest.TestCase):
    def test_final_fake_capture_timeout_preserves_completed_core_results(self):
        ready = time.time()
        config = StageCConfig(
            url="http://127.0.0.1:1",
            token="test",
            tenant_id="tenant-test",
            model="test",
            run_id="timeout",
            reset_url="http://127.0.0.1:1",
            tokenize_url="http://127.0.0.1:1",
            instance_boot_unix_s=ready - 2015,
            instance_termination_unix_s=ready - 2015 + 14400,
            observed_readiness_unix_s=ready,
            fake_event_url="http://127.0.0.1:1/kv-events",
        )
        gate = {"status": "passed", "checks": {"kv_publisher": {"status": "ok"}}}
        with (
            patch("inference_platform.stage_c._runtime_readiness", return_value=gate),
            patch("inference_platform.stage_c._run_saturation"),
            patch("inference_platform.stage_c._run_reference_capacity"),
            patch("inference_platform.stage_c._run_rewarm"),
            patch(
                "inference_platform.stage_c.read_http_sse_event_stream",
                side_effect=TimeoutError("timed out"),
            ),
        ):
            result = run_stage_c(config)
        self.assertEqual(result["status"], "completed")
        self.assertEqual([run["status"] for run in result["timed_runs"]], ["completed"] * 4)
        self.assertEqual(result["event_dependent_outputs"]["event_lag"], "unestablished")
        self.assertEqual(result["fake_kv_event_rehearsal"]["reason"], "timed out")

    def test_four_runs_use_fake_tokenizer_backends_metrics_and_kv_events(self) -> None:
        tokenizer = pinned_tokenizer()
        capacity = prompt_footprint(
            [
                tokenizer((f"reference-corpus-prefix-{index:08d} " * 31).strip())
                for index in range(2)
            ]
        )["prompt_blocks"]
        fake_config = FakeBackendConfig(
            backend_id="stage-c-fake",
            first_item_delay_ms=30,
            chunk_delay_ms=5,
            running_capacity=1,
            reject_above_active=4,
            kv_cache_capacity_blocks=capacity,
            kv_blocks_per_unique_prompt=2,
        )
        with FakeBackend(fake_config) as backend:
            ready = time.time()
            result = run_stage_c(
                StageCConfig(
                    url=backend.base_url,
                    token="stage-c-test-token",
                    tenant_id="tenant-stage-c",
                    model="test-model",
                    run_id="stage-c-offline",
                    reset_url=backend.base_url,
                    tokenize_url=backend.base_url,
                    instance_boot_unix_s=ready - 2015,
                    instance_termination_unix_s=ready - 2015 + 14400,
                    observed_readiness_unix_s=ready,
                    gateway_mode=False,
                    saturation_levels=(1, 2, 4, 8),
                    reference_prefix_counts=(2, 4),
                    reference_concurrency=2,
                    rewarm_repeats=2,
                    rewarm_samples=3,
                    saturation_prompt_repetitions=4,
                    max_tokens=2,
                    sample_interval_ms=5,
                    timeout_seconds=10,
                    metrics_endpoints=(("vllm0", backend.base_url),),
                    fake_event_url=f"{backend.base_url}/kv-events",
                )
            )

        self.assertFalse(result["paid_plan_generated"])
        self.assertFalse(result["aws_calls_made"])
        self.assertEqual(len(result["configuration_digest"]), 64)
        self.assertNotIn("token", result["configuration"])
        self.assertEqual(result["tokenization_preflight"]["status"], "ok")
        self.assertEqual(len(result["timed_runs"]), 4)
        self.assertEqual(result["timed_runs"][3]["run_kind"], "stability_repeat_runs_1_and_2")
        saturation = result["timed_runs"][0]
        self.assertTrue(all(level["sampler_started_before_load"] for level in saturation["levels"]))
        saturation_outcomes = [
            record for level in saturation["levels"] for record in level["records"]
        ]
        self.assertIn("rejected", {record["outcome"] for record in saturation_outcomes})
        self.assertTrue(
            any(
                sample["values"].get("vllm:num_requests_waiting", 0) > 0
                for level in saturation["levels"]
                for sample in level["metrics"]
            )
        )
        reference = result["timed_runs"][1]
        self.assertEqual(
            [candidate["distinct_prefix_count"] for candidate in reference["candidates"]],
            [2, 4],
        )
        self.assertEqual(
            [candidate["all_replay_prefixes_hit"] for candidate in reference["candidates"]],
            [True, False],
        )
        self.assertEqual(len(result["timed_runs"][2]["repeats"]), 2)
        self.assertGreater(result["fake_kv_event_rehearsal"]["observed_event_count"], 0)
        self.assertIn("BlockStored", result["fake_kv_event_rehearsal"]["event_types"])
        self.assertIn("BlockRemoved", result["fake_kv_event_rehearsal"]["event_types"])
        self.assertGreater(
            result["fake_kv_event_rehearsal"]["inventory"]["block_stores_observed"], 0
        )

    def test_event_capture_measures_dispatch_to_matching_fake_kv_event(self) -> None:
        prompt = "capture this exact prefix " * 20
        messages = [{"role": "user", "content": prompt}]
        with FakeBackend(
            FakeBackendConfig(backend_id="event-fake", first_item_delay_ms=20)
        ) as backend:
            tokenize_request = urllib.request.Request(
                f"{backend.base_url}/tokenize",
                data=json.dumps(
                    {"model": "test-model", "messages": messages, "add_generation_prompt": True}
                ).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(tokenize_request, timeout=2) as response:
                token_ids = json.load(response)["tokens"]
            run = run_calibration(
                CalibrationConfig(
                    url=backend.base_url,
                    token="test-token",
                    tenant_id="tenant-event",
                    model="test-model",
                    run_id="kv-correlation",
                    gateway_mode=False,
                    prompt_text=prompt,
                    sample_interval_ms=5,
                    timeout_seconds=5,
                ),
                (1,),
            )
            record = run["levels"][0]["records"][0]
            observations = read_http_sse_event_stream(f"{backend.base_url}/kv-events")

        correlated = correlate_routing_events(
            [
                {
                    "request_id": record["request_id"],
                    "routing_decision_monotonic_ns": record["dispatch_monotonic_ns"],
                    "gateway_terminal_monotonic_ns": record["dispatch_monotonic_ns"]
                    + record["completion_offset_ns"]
                    - record["dispatch_offset_ns"],
                    "expected_token_block_digests": token_block_digests(token_ids),
                }
            ],
            observations,
        )
        self.assertEqual(correlated[0]["status"], "observed")
        self.assertEqual(correlated[0]["match_basis"], "identity_specific_16_token_block_digest")
        self.assertGreaterEqual(correlated[0]["routing_to_event_observation_ns"], 0)


if __name__ == "__main__":
    unittest.main()
