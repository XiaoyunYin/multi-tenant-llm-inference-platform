import json
import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from inference_platform.stage_c import StageCConfig, _admission_preflight


class AdmissionReadinessTest(unittest.TestCase):
    def test_effective_configuration_must_match_and_exceed_top_sweep(self):
        expected = {
            "mode": "memory-test",
            "allow_unsafe_test_admission": True,
            "global_capacity": 128,
            "gateway_max_concurrent": 128,
            "tenants": {
                "tenant-stage-c": {
                    "max_concurrent": 128,
                    "request_rate_limit": 4096,
                    "request_rate_window_ms": 1000,
                }
            },
        }
        with (
            tempfile.TemporaryDirectory() as directory,
            patch("inference_platform.stage_c._check_gateway_pid") as alive,
        ):
            log = Path(directory) / "gateway.log"
            config = StageCConfig(
                url="http://localhost",
                token="test",
                tenant_id="tenant-stage-c",
                model="test",
                run_id="test",
                reset_url="http://localhost",
                tokenize_url="http://localhost",
                gateway_config_log=str(log),
                expected_admission_configuration=expected,
            )

            def write(value, timeout=120):
                log.write_text(
                    json.dumps(
                        {
                            "msg": "gateway started",
                            "pid": os.getpid(),
                            "admission_configuration": value,
                            "first_item_timeout_seconds": timeout,
                        }
                    )
                    + "\n",
                    encoding="utf-8",
                )

            write(expected)
            self.assertEqual(_admission_preflight(config)["effective_configuration"], expected)
            alive.assert_called_once_with(os.getpid())
            approved = replace(config, protocol_version="r0-v2")
            self.assertEqual(_admission_preflight(approved)["first_item_timeout_seconds"], 120)
            write(expected, timeout=5)
            with self.assertRaisesRegex(RuntimeError, "require effective 120s"):
                _admission_preflight(approved)
            wrong = dict(expected, mode="redis")
            write(wrong)
            with self.assertRaisesRegex(RuntimeError, "mismatch"):
                _admission_preflight(config)
            wrong = dict(expected, global_capacity=64)
            write(wrong)
            with self.assertRaisesRegex(RuntimeError, "exceed"):
                _admission_preflight(replace(config, expected_admission_configuration=wrong))
            log.write_text("", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "snapshot missing"):
                _admission_preflight(config)
