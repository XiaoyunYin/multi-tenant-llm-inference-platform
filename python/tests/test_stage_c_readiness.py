import time
import unittest
from contextlib import ExitStack
from dataclasses import replace
from unittest.mock import patch

from inference_platform.fake_backend import FakeBackend, FakeBackendConfig
from inference_platform.stage_c import StageCConfig, run_stage_c


class OutputReadinessTest(unittest.TestCase):
    def test_core_failure_before_probe_is_not_a_publisher_failure(self):
        config = replace(
            self.config("http://unused"),
            gateway_mode=True,
            protocol_version="r0-v2",
            decision_prompt_export_path="unused-prompts",
            decision_export_output_path="unused-decisions",
            kv_capture_output_path="unused-capture",
            kv_capture_stop_file="unused-stop",
        )
        with (
            patch(
                "inference_platform.stage_c._health_preflight",
                side_effect=RuntimeError("prompt gate failed"),
            ),
            patch("inference_platform.stage_c._publisher_preflight") as probe,
        ):
            result = run_stage_c(config)
        probe.assert_not_called()
        self.assertEqual(
            result["event_dependent_outputs"]["reason"], "not_attempted_readiness_failed"
        )
        self.assertEqual(
            result["decision_event_export"]["reason"], "not_attempted_readiness_failed"
        )

    def config(self, url):
        now = time.time()
        return StageCConfig(
            url=url,
            token="test",
            tenant_id="tenant-stage-c",
            model="test",
            run_id="gate",
            reset_url=url,
            tokenize_url=url,
            gateway_mode=False,
            instance_boot_unix_s=now - 2015,
            instance_termination_unix_s=now - 2015 + 14400,
            observed_readiness_unix_s=now,
        )

    def test_missing_or_unhealthy_publisher_skips_only_event_outputs(self):
        with FakeBackend(FakeBackendConfig()) as backend:
            for probe in (
                {"status": "unavailable", "reason": "missing publisher"},
                {"status": "unavailable", "reason": "no decoded event"},
                {"status": "ok", "decoded_block_stored_count": 1},
            ):
                with self.subTest(probe=probe), ExitStack() as stack:
                    stack.enter_context(
                        patch("inference_platform.stage_c._publisher_preflight", return_value=probe)
                    )
                    runners = [
                        stack.enter_context(patch(f"inference_platform.stage_c.{name}"))
                        for name in ("_run_saturation", "_run_reference_capacity", "_run_rewarm")
                    ]
                    result = run_stage_c(self.config(backend.base_url))
                    self.assertEqual(result["status"], "completed")
                    self.assertTrue(
                        all(run["status"] == "completed" for run in result["timed_runs"])
                    )
                    self.assertEqual([runner.call_count for runner in runners], [2, 2, 1])
                    self.assertEqual(
                        result["event_dependent_outputs"]["event_lag"],
                        "eligible" if probe["status"] == "ok" else "unestablished",
                    )

    def test_core_failures_stop_every_run_and_preserve_readiness_artifact(self):
        with FakeBackend(FakeBackendConfig()) as backend:
            for name in (
                "measurement_clocks",
                "_health_preflight",
                "_tokenize_preflight",
                "_reset_prefix_cache",
                "_admission_preflight",
            ):
                with (
                    self.subTest(name=name),
                    patch(f"inference_platform.stage_c.{name}", side_effect=RuntimeError(name)),
                    patch("inference_platform.stage_c._run_saturation") as runner,
                ):
                    result = run_stage_c(self.config(backend.base_url))
                    runner.assert_not_called()
                    self.assertEqual(result["status"], "readiness_failed")
                    self.assertIn(name, result["readiness"]["gate"]["reason"])
                    self.assertTrue(
                        all(
                            run["status"] == "skipped_readiness_failure"
                            for run in result["timed_runs"]
                        )
                    )

    def test_actual_unhealthy_backend_stops_session(self):
        with (
            FakeBackend(FakeBackendConfig(healthy=False)) as backend,
            patch("inference_platform.stage_c._run_saturation") as runner,
        ):
            result = run_stage_c(self.config(backend.base_url))
        runner.assert_not_called()
        self.assertEqual(result["status"], "readiness_failed")

    def test_cache_reset_failure_during_run_retains_partial_and_stops_later_runs(self):
        with FakeBackend(FakeBackendConfig()) as backend:

            def failed_run(config, suffix, deadline, result):
                result["levels"] = [{"records": ["retained-before-reset-failure"]}]
                raise RuntimeError("prefix cache reset did not return success=true")

            with (
                patch("inference_platform.stage_c._run_saturation", side_effect=failed_run),
                patch("inference_platform.stage_c._run_reference_capacity") as later,
            ):
                result = run_stage_c(self.config(backend.base_url))
        later.assert_not_called()
        self.assertEqual(
            result["timed_runs"][0]["levels"][0]["records"], ["retained-before-reset-failure"]
        )
        self.assertEqual(result["timed_runs"][0]["status"], "readiness_failure")
        self.assertEqual(result["timed_runs"][1]["status"], "skipped_readiness_failure")
