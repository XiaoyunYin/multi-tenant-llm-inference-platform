import json
import os
import tempfile
import unittest
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from inference_platform.calibration import CalibrationConfig, run_calibration
from inference_platform.fake_backend import FakeBackend, FakeBackendConfig


class CalibrationRecorderTest(unittest.TestCase):
    def test_stepped_run_records_outcomes_and_inflight_metrics(self) -> None:
        with FakeBackend(
            FakeBackendConfig(chunks=("one", "two"), first_item_delay_ms=80, chunk_delay_ms=40)
        ) as backend:
            result = run_calibration(
                CalibrationConfig(
                    url=backend.base_url,
                    token="test-token",
                    tenant_id="tenant-calibration",
                    model="test-model",
                    run_id="calibration-test",
                    gateway_mode=False,
                    sample_interval_ms=10,
                    timeout_seconds=5,
                    process_pids=(os.getpid(),),
                ),
                (1, 2),
            )

        self.assertEqual(result["clock_info"]["interval_clock"], "perf_counter")
        info = result["clock_info"]["clocks"]["perf_counter"]
        self.assertIn("implementation", info)
        self.assertLessEqual(info["resolution"], 0.001)
        self.assertEqual([level["concurrency"] for level in result["levels"]], [1, 2])
        records = [record for level in result["levels"] for record in level["records"]]
        self.assertEqual(len(records), 3)
        self.assertTrue(all(record["outcome"] == "completed" for record in records))
        self.assertTrue(all(record["http_status"] == 200 for record in records))
        self.assertTrue(all(record["backend_id"] == "fake-backend-a" for record in records))
        self.assertTrue(
            any(
                sample.get("values", {}).get("vllm:num_requests_running", 0) > 0
                for level in result["levels"]
                for sample in level["metrics"]
            )
        )
        for sample in (sample for level in result["levels"] for sample in level["metrics"]):
            self.assertIn("body", sample)
            self.assertEqual(
                sample["raw_sha256"], sha256(sample["body"].encode("utf-8")).hexdigest()
            )
            process = sample["processes"][str(os.getpid())]
            self.assertGreater(process["rss_bytes"], 0)
            self.assertGreaterEqual(process["cpu_seconds"], 0)

    def test_coarse_clock_refuses_before_any_request(self):
        coarse = SimpleNamespace(
            implementation="injected coarse clock",
            resolution=0.015625,
            monotonic=True,
            adjustable=False,
        )
        with (
            patch("inference_platform.clocks.time.get_clock_info", return_value=coarse),
            patch("inference_platform.calibration._metrics") as metrics,
            self.assertRaisesRegex(RuntimeError, "coarser than 1 ms"),
        ):
            run_calibration(
                CalibrationConfig("http://localhost", "token", "tenant", "model", "coarse"),
                (1,),
            )
        metrics.assert_not_called()

    def test_coarse_wall_clock_is_labeled_without_degrading_interval_clock(self):
        from inference_platform.clocks import measurement_clocks

        fine = SimpleNamespace(
            implementation="fine interval",
            resolution=1e-7,
            monotonic=True,
            adjustable=False,
        )
        coarse = SimpleNamespace(
            implementation="coarse wall",
            resolution=0.015625,
            monotonic=False,
            adjustable=True,
        )
        with patch("inference_platform.clocks.time.get_clock_info", side_effect=[fine, coarse]):
            info = measurement_clocks(wall_clock=True)
        self.assertEqual(info["clocks"]["time"]["resolution"], 0.015625)
        self.assertIn("COARSE_WALL_CLOCK", info["measurement_warnings"][0])

    def test_cli_evidence_is_bom_free_utf8_with_lf(self):
        from inference_platform.calibration import main

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            token = root / "token"
            token.write_text("test-token", encoding="utf-8")
            output = root / "run.json"
            with (
                patch(
                    "sys.argv",
                    [
                        "calibration",
                        "--url",
                        "http://localhost",
                        "--token-file",
                        str(token),
                        "--model",
                        "model",
                        "--output",
                        str(output),
                    ],
                ),
                patch(
                    "inference_platform.calibration.run_calibration", return_value={"status": "ok"}
                ),
            ):
                self.assertEqual(main(), 0)
            data = output.read_bytes()
            self.assertFalse(data.startswith(b"\xef\xbb\xbf"))
            self.assertNotIn(b"\r", data)
            self.assertEqual(json.loads(data.decode("utf-8")), {"status": "ok"})


if __name__ == "__main__":
    unittest.main()
