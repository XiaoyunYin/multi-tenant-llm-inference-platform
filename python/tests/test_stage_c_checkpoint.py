import gzip
import json
import random
import sqlite3
import subprocess
import tarfile
import tempfile
import time
import unittest
from functools import partial
from pathlib import Path
from unittest.mock import patch

from inference_platform.stage_c import StageCConfig, run_stage_c
from inference_platform.stage_c_capture import require_capture_mount
from inference_platform.stage_c_checkpoint import checkpoint_run, snapshot_jsonl
from inference_platform.stage_c_digest import DIGEST_LIMIT, seal_digest


class CheckpointRecoveryTest(unittest.TestCase):
    def config(self):
        ready = time.time()
        return StageCConfig(
            url="http://unused",
            token="test",
            tenant_id="test",
            model="test",
            run_id="test",
            reset_url="http://unused",
            tokenize_url="http://unused",
            instance_boot_unix_s=ready - 2015,
            instance_termination_unix_s=ready - 2015 + 14400,
            observed_readiness_unix_s=ready,
        )

    def run_four(self, session, saturation=None):
        with (
            patch(
                "inference_platform.stage_c._runtime_readiness",
                return_value={"status": "passed", "checks": {}},
            ),
            patch("inference_platform.stage_c._run_saturation", side_effect=saturation),
            patch("inference_platform.stage_c._run_reference_capacity"),
            patch("inference_platform.stage_c._run_rewarm"),
        ):
            result = run_stage_c(self.config(), on_run_complete=partial(checkpoint_run, session))
        self.assertEqual(result["status"], "completed")
        self.assertEqual([r["status"] for r in result["timed_runs"]], ["completed"] * 4)
        for n in range(1, 5):
            receipt = json.loads((session / f"sealed-runs/run-{n}.receipt.json").read_text())
            self.assertTrue(receipt["sealed_before_next_run"])
            self.assertTrue((session / f"sealed-runs/run-{n}.tar.gz").exists())
            self.assertLessEqual(receipt["measurement_digest"]["bytes"], DIGEST_LIMIT)
        return result

    def test_forced_legacy_copy_timeout_salvages_run_and_later_runs_seal(self):
        with tempfile.TemporaryDirectory() as directory:
            session = Path(directory)
            (session / "gateway.log").write_text("")
            calls = [0]

            def failed_copy(*args):
                calls[0] += 1
                if calls[0] == 1:
                    raise subprocess.TimeoutExpired(["docker", "cp"], 10)
                return snapshot_jsonl(*args)

            with patch(
                "inference_platform.stage_c_checkpoint.snapshot_jsonl", side_effect=failed_copy
            ):
                result = self.run_four(session)
            self.assertEqual(
                result["timed_runs"][0]["checkpoint"]["failure_type"], "TimeoutExpired"
            )
            failure = json.loads((session / "checkpoint-1.failure.json").read_text())
            self.assertEqual(failure["event_lag_status"], "unavailable")
            digest = json.loads(
                gzip.decompress((session / "sealed-runs/run-1.digest.json.gz").read_bytes())
            )
            self.assertEqual(digest["event_lag"]["status"], "unavailable")
            self.assertNotIn("checkpoint", result["timed_runs"][1])

    def test_oversize_digest_keeps_aggregates_and_later_runs_seal(self):
        rng = random.Random(101)
        records = [
            {
                "request_id": rng.randbytes(24).hex(),
                "dispatch_offset_ns": rng.randrange(10**15),
                "completion_offset_ns": rng.randrange(10**15),
                "http_status": 200,
                "outcome": "completed",
            }
            for _ in range(40000)
        ]
        calls = [0]

        def saturation(_config, _label, _deadline, run):
            calls[0] += 1
            if calls[0] == 1:
                run.update(
                    records=records, completed_requests=len(records), aggregate_mean_seconds=0.123
                )

        with tempfile.TemporaryDirectory() as directory:
            session = Path(directory)
            (session / "gateway.log").write_text("")
            self.run_four(session, saturation)
            digest = json.loads(
                gzip.decompress((session / "sealed-runs/run-1.digest.json.gz").read_bytes())
            )
            flag = digest["detail_degradation"]
            self.assertFalse(flag["per_request_detail_dropped"])
            self.assertEqual(len(digest["per_request"]["rows"]), 40000)
            self.assertGreater(flag["original_compressed_bytes"], DIGEST_LIMIT)
            self.assertNotIn("records", digest["run"])
            self.assertEqual(digest["run"]["request_detail_count"], 40000)
            self.assertEqual(digest["run"]["request_outcome_aggregates"][0]["count"], 40000)
            self.assertEqual(digest["run"]["aggregate_mean_seconds"], 0.123)
            self.assertEqual(digest["run"]["completed_requests"], 40000)
            full = json.loads((session / "sealed-runs/run-1/run-artifact.json").read_text())
            self.assertEqual(len(full["run"]["records"]), 40000)

    def test_missing_private_bind_mount_fails_before_capture_start(self):
        from types import SimpleNamespace

        config = SimpleNamespace(
            kv_capture_output_path="/opt/inf011/capture-private/test/capture.json",
            kv_capture_stop_file="/opt/inf011/capture-private/test/stop",
            decision_export_output_path="/opt/inf011/capture-private/test/decisions.jsonl",
        )
        with patch(
            "inference_platform.stage_c_capture.docker", return_value=SimpleNamespace(stdout="[]")
        ):
            with self.assertRaisesRegex(RuntimeError, "bind mount unavailable"):
                require_capture_mount(config, time.perf_counter() + 10)

    def test_native_sample_oversize_keeps_reference_and_metric_aggregates(self):
        rng = random.Random(102)
        samples = [
            {
                "offset_ns": rng.randrange(10**15),
                "values": {
                    "vllm:kv_cache_usage_perc": rng.random(),
                    "vllm:num_requests_running": n % 16,
                },
            }
            for n in range(80000)
        ]
        value = {
            "run": {
                "status": "completed",
                "metrics": samples,
                "reference_capacity": {"status": "established", "bracket": [3112, 3500]},
                "runtime_regime": {
                    "classification": "warm_shared",
                    "signals": {"vllm:num_requests_running": [1, 4, 8, 16]},
                },
            },
            "event_lag": {"status": "established", "histogram": {"counts": [4, 8]}, "p50_ns": 123},
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "digest.gz"
            receipt = seal_digest(path, value)
            self.assertLessEqual(receipt["bytes"], DIGEST_LIMIT)
            result = json.loads(gzip.decompress(path.read_bytes()))
        self.assertTrue(result["detail_degradation"]["native_sample_detail_dropped"])
        self.assertEqual(result["run"]["reference_capacity"], value["run"]["reference_capacity"])
        aggregate = result["run"]["native_metric_aggregates"]["vllm:kv_cache_usage_perc"]
        self.assertEqual(aggregate["count"], 80000)
        self.assertEqual(
            aggregate["min"], min(row["values"]["vllm:kv_cache_usage_perc"] for row in samples)
        )
        self.assertEqual(result["event_lag"], value["event_lag"])
        self.assertEqual(
            result["run"]["runtime_regime"]["native_signal_aggregates"][
                "vllm:num_requests_running"
            ],
            {"count": 4, "min": 1, "max": 16, "mean": 7.25},
        )

    def test_callback_failure_itself_never_aborts_later_runs(self):
        count = [0]

        def callback(*_):
            count[0] += 1
            if count[0] == 1:
                raise subprocess.TimeoutExpired("legacy-copy", 10)

        with (
            patch(
                "inference_platform.stage_c._runtime_readiness",
                return_value={"status": "passed", "checks": {}},
            ),
            patch("inference_platform.stage_c._run_saturation"),
            patch("inference_platform.stage_c._run_reference_capacity"),
            patch("inference_platform.stage_c._run_rewarm"),
        ):
            result = run_stage_c(self.config(), on_run_complete=callback)
        self.assertEqual(count[0], 4)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["timed_runs"][0]["checkpoint"]["event_lag_status"], "unavailable")

    def test_optional_database_archive_and_serialization_faults_salvage_later_runs(self):
        for error_type in (sqlite3.DatabaseError, tarfile.TarError, KeyError, TypeError):
            with (
                self.subTest(error_type=error_type.__name__),
                tempfile.TemporaryDirectory() as directory,
            ):
                session = Path(directory)
                (session / "gateway.log").write_text("")
                calls = [0]

                def failed_snapshot(*args, calls=calls, error_type=error_type):
                    calls[0] += 1
                    if calls[0] == 1:
                        raise error_type("private input must not appear in sanitized failure")
                    return snapshot_jsonl(*args)

                with patch(
                    "inference_platform.stage_c_checkpoint.snapshot_jsonl",
                    side_effect=failed_snapshot,
                ):
                    result = self.run_four(session)
                self.assertEqual(
                    result["timed_runs"][0]["checkpoint"]["failure_type"], error_type.__name__
                )
                failure = (session / "checkpoint-1.failure.json").read_text()
                self.assertNotIn("private input", failure)
                digest = json.loads(
                    gzip.decompress((session / "sealed-runs/run-1.digest.json.gz").read_bytes())
                )
                self.assertEqual(digest["event_lag"]["status"], "unavailable")
                self.assertNotIn("checkpoint", result["timed_runs"][1])

    def test_scheduler_isolates_unexpected_optional_callback_exception(self):
        count = [0]

        def callback(*_):
            count[0] += 1
            if count[0] == 1:
                raise KeyError("optional serializer failure")

        with (
            patch(
                "inference_platform.stage_c._runtime_readiness",
                return_value={"status": "passed", "checks": {}},
            ),
            patch("inference_platform.stage_c._run_saturation"),
            patch("inference_platform.stage_c._run_reference_capacity"),
            patch("inference_platform.stage_c._run_rewarm"),
        ):
            result = run_stage_c(self.config(), on_run_complete=callback)
        self.assertEqual(count[0], 4)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["timed_runs"][0]["checkpoint"]["failure_type"], "KeyError")
        self.assertEqual(result["timed_runs"][0]["checkpoint"]["event_lag_status"], "unavailable")
