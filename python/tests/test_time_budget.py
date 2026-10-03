import json
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from inference_platform.calibration import CalibrationConfig, run_calibration
from inference_platform.fake_backend import FakeBackend, FakeBackendConfig
from inference_platform.stage_c import StageCConfig, _config_from_json, main, run_stage_c


class TimeBudgetTest(unittest.TestCase):
    def config(self, url):
        ready = time.time()
        return StageCConfig(
            url=url,
            token="test-token",
            tenant_id="tenant-test",
            model="test-model",
            run_id="budget",
            reset_url=url,
            tokenize_url=url,
            instance_boot_unix_s=ready - 2015,
            instance_termination_unix_s=ready - 2015 + 14400,
            observed_readiness_unix_s=ready,
            minimum_useful_run_seconds=(0.01, 0.01, 0.01, 0.01),
            gateway_mode=False,
            saturation_levels=(1, 2, 4),
            reference_prefix_counts=(2,),
            reference_concurrency=2,
            rewarm_repeats=2,
            rewarm_samples=3,
            saturation_prompt_repetitions=8,
            sample_interval_ms=5,
            timeout_seconds=30,
            run_time_budgets_seconds=(0.2, 0.3, 0.2, 0.3),
        )

    def test_config_leaves_reserve_and_rejects_overallocation(self):
        config = replace(
            self.config("http://localhost"), run_time_budgets_seconds=(3000, 2700, 1800, 3600)
        )
        config.validate()
        self.assertEqual(sum(config.run_time_budgets_seconds), 11100)
        self.assertEqual(14400 - 2015 - sum(config.run_time_budgets_seconds), 1285)
        for budgets in (
            (3000, 3000, 3000, 3385),
            (1, 2, 3),
            (float("nan"), 1, 1, 1),
            (True, 1, 1, 1),
            (0, 1, 1, 1),
        ):
            with self.subTest(budgets=budgets), self.assertRaises(ValueError):
                replace(config, run_time_budgets_seconds=budgets).validate()
        with self.assertRaises(ValueError):
            replace(config, cold_readiness_planning_seconds=2000).validate()
        with self.assertRaises(ValueError):
            replace(config, session_window_seconds=20000).validate()

    def test_all_four_expire_cleanly_and_cli_writes_partial_nested_results(self):
        with FakeBackend(FakeBackendConfig(first_item_delay_ms=1000)) as backend:
            config = self.config(backend.base_url)
            started = time.perf_counter()
            result = run_stage_c(config)
            self.assertLess(time.perf_counter() - started, 2.5)
            self.assertEqual(result["status"], "partial")
            for run in result["timed_runs"]:
                self.assertEqual(run["status"], "budget_exhausted")
                self.assertTrue(run["partial"])
                self.assertLess(run["elapsed_seconds"], run["time_budget_seconds"] + 0.5)
            self.assertEqual(result["timed_runs"][0]["planned_level_count"], 3)
            self.assertEqual(len(result["timed_runs"][0]["levels"]), 1)
            self.assertIn("population", result["timed_runs"][1]["candidates"][0])
            self.assertNotIn("replay", result["timed_runs"][1]["candidates"][0])
            self.assertEqual(len(result["timed_runs"][2]["repeats"]), 1)
            self.assertIn("levels", result["timed_runs"][3]["saturation"])
            records = result["timed_runs"][0]["levels"][0]["records"]
            self.assertEqual(records[0]["error_code"], "client_cancelled")
            self.assertEqual(records[0]["stop_reason"], "run_time_budget_exhausted")
            self.assertEqual(records[0]["outcome"], "cancelled")
            self.assertFalse(any(t.name == "calibration-metrics" for t in threading.enumerate()))
        with tempfile.TemporaryDirectory() as directory:
            config_file = Path(directory) / "config.json"
            output = Path(directory) / "partial.json"
            # Actual parser preserves the four run budgets; CLI serializes the partial artifact.
            raw = {
                "url": "http://localhost",
                "token": "test-token",
                "tenant_id": "tenant-test",
                "model": "test-model",
                "run_id": "budget",
                "reset_url": "http://localhost",
                "tokenize_url": "http://localhost",
                "run_time_budgets_seconds": [0.2, 0.3, 0.2, 0.3],
                "minimum_useful_run_seconds": [0.01, 0.01, 0.01, 0.01],
                "instance_boot_unix_s": config.instance_boot_unix_s,
                "instance_termination_unix_s": config.instance_termination_unix_s,
                "observed_readiness_unix_s": config.observed_readiness_unix_s,
            }
            config_file.write_text(json.dumps(raw), encoding="utf-8")
            self.assertEqual(
                _config_from_json(config_file).run_time_budgets_seconds, (0.2, 0.3, 0.2, 0.3)
            )
            with (
                patch(
                    "sys.argv", ["stage_c", "--config", str(config_file), "--output", str(output)]
                ),
                patch("inference_platform.stage_c.run_stage_c", return_value=result),
            ):
                self.assertEqual(main(), 0)
            self.assertFalse(output.read_bytes().startswith(b"\xef\xbb\xbf"))
            self.assertNotIn(b"\r", output.read_bytes())
            self.assertEqual(json.loads(output.read_text())["status"], "partial")

    def test_slow_readiness_caps_or_skips_runs_without_using_export_margin(self):
        from inference_platform.time_budget import BudgetExhausted

        clock = [1000.0]
        config = replace(
            self.config("http://localhost"),
            instance_boot_unix_s=0,
            instance_termination_unix_s=14400,
            observed_readiness_unix_s=13800,
            evidence_export_margin_seconds=120,
            run_time_budgets_seconds=(3000, 2700, 1800, 3600),
            minimum_useful_run_seconds=(60, 300, 60, 150),
        )
        seen = []

        def saturation(config, suffix, deadline, result):
            seen.append((suffix, deadline))
            clock[0] += 200
            result["levels"] = [{"records": ["completed-before-cap"]}]

        def rewarm(config, suffix, deadline, result):
            seen.append((suffix, deadline))
            result["repeats"] = [{"run": {"records": ["retained-partial"]}}]
            clock[0] = deadline
            raise BudgetExhausted()

        with (
            patch(
                "inference_platform.stage_c._runtime_readiness",
                return_value={"status": "ok", "checks": {}},
            ),
            patch("inference_platform.stage_c._run_saturation", side_effect=saturation),
            patch("inference_platform.stage_c._run_reference_capacity") as reference,
            patch("inference_platform.stage_c._run_rewarm", side_effect=rewarm),
        ):
            result = run_stage_c(
                config, monotonic_clock=lambda: clock[0], wall_clock=lambda: 13800 + clock[0] - 1000
            )
        self.assertEqual(result["clock_info"]["deadline_clock"], "perf_counter")
        self.assertIn("implementation", result["clock_info"]["clocks"]["time"])
        self.assertEqual(result["readiness"]["observed_readiness_seconds"], 13800)
        self.assertEqual(result["readiness"]["session_deadline_unix_s"], 14280)
        self.assertEqual(result["readiness"]["session_deadline_monotonic_s"], 1480)
        self.assertLessEqual(clock[0], 1480)
        self.assertEqual(
            [run["status"] for run in result["timed_runs"]],
            [
                "completed",
                "skipped_session_deadline",
                "budget_exhausted",
                "skipped_session_deadline",
            ],
        )
        self.assertTrue(all(deadline == 1480 for _, deadline in seen))
        reference.assert_not_called()
        self.assertEqual(result["timed_runs"][2]["stop_reason"], "session_deadline_exhausted")
        self.assertEqual(
            result["timed_runs"][2]["repeats"][0]["run"]["records"], ["retained-partial"]
        )
        self.assertEqual(result["status"], "partial")

    def test_expired_session_skips_preflight_and_all_runs(self):
        config = replace(
            self.config("http://localhost"),
            instance_boot_unix_s=0,
            instance_termination_unix_s=14400,
            observed_readiness_unix_s=14000,
        )
        with (
            patch("inference_platform.stage_c._tokenize_preflight") as preflight,
            patch("inference_platform.stage_c._run_saturation") as saturation,
        ):
            result = run_stage_c(config, monotonic_clock=lambda: 200, wall_clock=lambda: 14000)
        preflight.assert_not_called()
        saturation.assert_not_called()
        self.assertTrue(
            all(run["status"] == "skipped_session_deadline" for run in result["timed_runs"])
        )
        for change in (
            {"instance_boot_unix_s": None},
            {"evidence_export_margin_seconds": 0},
            {"instance_termination_unix_s": 14500},
            {"minimum_useful_run_seconds": (0, 1, 1, 1)},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                replace(config, **change).validate()

    def test_run4_subruns_share_one_deadline(self):
        config = replace(self.config("http://localhost"), run_time_budgets_seconds=(1, 1, 1, 0.08))
        deadlines = []
        clock = [1000.0]

        def saturation(config, suffix, deadline, result):
            if suffix == "run4-stability":
                deadlines.append(deadline)
                clock[0] += 0.04
            result["levels"] = [{"records": ["retained-saturation"]}]

        def reference(config, suffix, deadline, result):
            if suffix == "run4-stability":
                deadlines.append(deadline)
                self.assertAlmostEqual(deadline - clock[0], 0.04)
                result["candidates"] = [{"status": "in_progress"}]
                clock[0] += 0.05
                from inference_platform.time_budget import remaining_seconds

                remaining_seconds(deadline, 1)

        with (
            patch(
                "inference_platform.stage_c._runtime_readiness",
                return_value={"status": "ok", "checks": {}},
            ),
            patch("inference_platform.stage_c._run_saturation", side_effect=saturation),
            patch("inference_platform.stage_c._run_reference_capacity", side_effect=reference),
            patch("inference_platform.stage_c._run_rewarm"),
            patch("inference_platform.time_budget.time.perf_counter", side_effect=lambda: clock[0]),
        ):
            result = run_stage_c(config, monotonic_clock=lambda: clock[0])
        self.assertEqual(deadlines[0], deadlines[1])
        run4 = result["timed_runs"][3]
        self.assertEqual(run4["status"], "budget_exhausted")
        self.assertEqual(run4["saturation"]["levels"][0]["records"], ["retained-saturation"])
        self.assertIn("candidates", run4["reference_capacity"])

    def test_deadline_interrupts_trickling_stream_and_skips_later_bursts(self):
        with FakeBackend(
            FakeBackendConfig(first_item_delay_ms=10, chunk_delay_ms=40, chunks=("chunk",) * 100)
        ) as backend:
            started = time.perf_counter()
            run = run_calibration(
                CalibrationConfig(
                    url=backend.base_url,
                    token="test-token",
                    tenant_id="tenant-test",
                    model="test-model",
                    run_id="trickle",
                    gateway_mode=False,
                    sample_interval_ms=5,
                    timeout_seconds=30,
                ),
                (2, 4),
                deadline=started + 0.25,
            )
            self.assertLess(time.perf_counter() - started, 0.8)
            self.assertEqual(run["status"], "budget_exhausted")
            self.assertEqual(len(run["levels"]), 1)
            self.assertEqual(len(run["levels"][0]["records"]), 2)
            for record in run["levels"][0]["records"]:
                self.assertEqual(record["outcome"], "partial_stream")
                self.assertEqual(record["error_code"], "run_time_budget_exhausted")
            self.assertFalse(any(t.name == "calibration-metrics" for t in threading.enumerate()))


if __name__ == "__main__":
    unittest.main()
