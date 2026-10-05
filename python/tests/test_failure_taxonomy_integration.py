"""Real gateway/recorder rehearsal of every failure class; synthetic, no AWS."""

import json
import os
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path

from inference_platform.calibration import CalibrationConfig, run_calibration
from inference_platform.disk_records import write_json
from inference_platform.failure_taxonomy import add_failure_splits
from inference_platform.fake_backend import FailureMode, FakeBackend, FakeBackendConfig

try:
    from test_gateway_integration import GatewayIntegrationTest
except ImportError:
    from python.tests.test_gateway_integration import GatewayIntegrationTest


class FailureShapeIntegrationTest(unittest.TestCase):
    setUpClass = classmethod(GatewayIntegrationTest.setUpClass.__func__)
    tearDownClass = classmethod(GatewayIntegrationTest.tearDownClass.__func__)
    setUp = GatewayIntegrationTest.setUp
    tearDown = GatewayIntegrationTest.tearDown
    running_gateway = GatewayIntegrationTest.running_gateway

    def test_all_classes_are_joined_by_request_id_under_sustained_deadlines(self):
        cases = (
            (FailureMode.VLLM_HTTP_REJECTION, "vllm_pre_content_rejection", 502),
            (FailureMode.VLLM_SSE_ERROR_BEFORE_CONTENT, "vllm_in_stream_error", 502),
            (FailureMode.VLLM_SSE_ERROR_AFTER_CONTENT, "vllm_in_stream_error", 200),
            (FailureMode.MALFORMED_FIRST_ITEM, "gateway_protocol_rejection", 502),
            (FailureMode.NONE, "gateway_no_healthy_backend", 503),
        )
        evidence = []
        for mode, expected, status in cases:
            with (
                self.subTest(mode=mode, expected=expected),
                tempfile.TemporaryDirectory() as directory,
                FakeBackend(FakeBackendConfig(failure_mode=mode)) as backend,
            ):
                terminal = Path(directory) / "gateway.jsonl"
                with self.running_gateway([backend], terminal_log=terminal) as url:
                    if expected == "gateway_no_healthy_backend":
                        backend._server.config = replace(backend.config, healthy=False)
                        time.sleep(0.6)
                    run = run_calibration(
                        CalibrationConfig(
                            url,
                            "local-dev-token",
                            "tenant-a",
                            "test-model",
                            "failure-shapes",
                            max_tokens=2,
                            sample_interval_ms=20,
                            timeout_seconds=3,
                        ),
                        (1,),
                        level_duration_seconds=0.12,
                        minimum_cycle_seconds=0.02,
                        deadline=time.perf_counter() + 5,
                    )
                add_failure_splits(run, terminal)
                level = run["levels"][0]
                self.assertEqual(level["unmatched_dispatched_request_count"], 0)
                self.assertGreater(len(level["records"]), 0)
                self.assertTrue(
                    all(
                        row["class"] == expected and row["http_status"] == status
                        for row in level["failure_split"]
                    ),
                    level["failure_split"],
                )
                if expected == "gateway_no_healthy_backend":
                    self.assertTrue(
                        all(row["error_code"] == "no_healthy_backend" for row in level["records"])
                    )
                health = [
                    json.loads(line)
                    for line in terminal.read_text().splitlines()
                    if json.loads(line).get("msg") == "backend health poll"
                ]
                self.assertTrue(health)
                self.assertTrue(all(row["latency_ms"] >= 0 for row in health))
                evidence.append(
                    {
                        "fixture": mode.value,
                        "expected_class": expected,
                        "run": run,
                        "terminal_evidence": [
                            {
                                key: row[key]
                                for key in (
                                    "request_id",
                                    "code",
                                    "cause",
                                    "upstream_http_status",
                                    "upstream_error_code",
                                    "upstream_error_type",
                                    "upstream_error_shape",
                                )
                                if key in row
                            }
                            for row in map(json.loads, terminal.read_text().splitlines())
                            if row.get("msg") == "request terminal"
                        ],
                        "health_poll_count": len(health),
                        "health_transitions": [
                            {
                                "healthy_before": row["healthy_before"],
                                "healthy_after": row["healthy_after"],
                                "latency_ms": row["latency_ms"],
                                "error_class": row["error_class"],
                            }
                            for row in health
                            if row["healthy_before"] != row["healthy_after"]
                        ],
                    }
                )
        destination = os.environ.get("INF011_FAILURE_REHEARSAL_DIR")
        if destination:
            root = Path(destination)
            root.mkdir(parents=True, exist_ok=True)
            write_json(
                root / "failure-shapes.json",
                {
                    "schema": "inf011-failure-shape-rehearsal.v1",
                    "basis": "Real gateway and sustained recorder; source-shaped synthetic backend; no GPU/AWS or paid protocol change",
                    "cases": evidence,
                    "aws_calls_made": False,
                },
            )


del GatewayIntegrationTest

if __name__ == "__main__":
    unittest.main()
