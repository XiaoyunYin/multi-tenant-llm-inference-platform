import gzip
import hashlib
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

from remainder_fixtures import fixture

from inference_platform.stage_c import StageCConfig, run_stage_c
from inference_platform.stage_c_capture import require_capture_mount
from inference_platform.stage_c_checkpoint import checkpoint_run, seal_run, snapshot_jsonl
from inference_platform.stage_c_digest import DIGEST_LIMIT, seal_digest
from inference_platform.stage_c_registered import final_metadata_projection
from inference_platform.stage_c_session import export as export_session


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

    def assert_run4_raw_schema_refusal(self, mutate, expected_type):
        with tempfile.TemporaryDirectory() as directory:
            session = Path(directory)
            (session / "gateway.log").write_text("", encoding="utf-8")
            run = fixture(4)
            mutate(run)
            with (
                patch("inference_platform.stage_c_session.disk_snapshot", return_value={}),
                patch(
                    "inference_platform.stage_c_checkpoint.seal_run",
                    wraps=seal_run,
                ) as seal_spy,
            ):
                receipt = checkpoint_run(session, 4, run)
            self.assertEqual(seal_spy.call_count, 1)
            digest = receipt["measurement_digest"]
            self.assertEqual(digest["status"], "refused")
            self.assertEqual(digest["flag"], "retention_schema_overflow")
            self.assertEqual(digest["table"], "registered_source")
            failure_path = session / "sealed-runs" / "run-4.digest.json.gz.failure.json"
            failure = json.loads(failure_path.read_text(encoding="utf-8"))
            self.assertEqual(failure["failure_type"], expected_type)
            self.assertEqual(failure["table"], "registered_source")
            expected_count = len(run["requests"]) if isinstance(run.get("requests"), list) else None
            self.assertEqual(failure["observed_count"], expected_count)
            self.assertEqual(
                digest["failure_receipt_sha256"],
                hashlib.sha256(failure_path.read_bytes()).hexdigest(),
            )
            archive_path = session / "sealed-runs" / "run-4.tar.gz"
            archive_receipt_path = session / "sealed-runs" / "run-4.receipt.json"
            self.assertTrue(archive_path.exists())
            self.assertTrue(archive_receipt_path.exists())
            archive_receipt = json.loads(archive_receipt_path.read_text(encoding="utf-8"))
            self.assertEqual(archive_receipt["measurement_digest"], digest)
            projected = final_metadata_projection(session)
            run4 = next(row for row in projected["runs"] if row["run_number"] == 4)
            self.assertEqual(run4["status"], "refused")
            self.assertEqual(run4["archive_receipt"], archive_receipt)

    def test_run4_checkpoint_raw_keyerror_keeps_archive_and_final_projection(self):
        self.assert_run4_raw_schema_refusal(
            lambda run: run.pop("gateway_cpu_ticks_per_second"),
            "KeyError",
        )

    def test_run4_checkpoint_raw_typeerror_keeps_archive_and_final_projection(self):
        self.assert_run4_raw_schema_refusal(
            lambda run: run.__setitem__("source_binding", None),
            "TypeError",
        )

    def test_run4_checkpoint_null_requests_keeps_archive_and_final_projection(self):
        self.assert_run4_raw_schema_refusal(
            lambda run: run.__setitem__("requests", None),
            "TypeError",
        )

    def test_run4_retention_refusal_through_checkpoint_keeps_archive_and_final_projection(self):
        with tempfile.TemporaryDirectory() as directory:
            session = Path(directory)
            (session / "gateway.log").write_text("", encoding="utf-8")
            run = fixture(4)
            run["failure_tuples"] = [
                (200, "completed", "completed", index % 9, 0)
                for index in range(len(run["requests"]))
            ]
            with (
                patch("inference_platform.stage_c_session.disk_snapshot", return_value={}),
                patch("inference_platform.stage_c_checkpoint.seal_run", wraps=seal_run) as seal_spy,
            ):
                receipt = checkpoint_run(session, 4, run)
            self.assertEqual(seal_spy.call_count, 1)
            self.assertEqual(receipt["measurement_digest"]["status"], "refused")
            failure_path = session / "sealed-runs" / "run-4.digest.json.gz.failure.json"
            failure = json.loads(failure_path.read_text(encoding="utf-8"))
            self.assertEqual(failure["flag"], "failure_code_overflow")
            self.assertEqual(failure["table"], "failure_split_codebook.v1")
            self.assertEqual(
                receipt["measurement_digest"]["failure_receipt_sha256"],
                hashlib.sha256(failure_path.read_bytes()).hexdigest(),
            )
            self.assertFalse((session / "sealed-runs" / "run-4.digest.json.gz").exists())
            archive_path = session / "sealed-runs" / "run-4.tar.gz"
            archive_receipt_path = session / "sealed-runs" / "run-4.receipt.json"
            self.assertTrue(archive_path.exists())
            archive_receipt = json.loads(archive_receipt_path.read_text(encoding="utf-8"))
            self.assertEqual(archive_receipt["measurement_digest"], receipt["measurement_digest"])
            self.assertFalse((session / "checkpoint-4.failure.json").exists())
            projected = final_metadata_projection(session)
            run4 = next(row for row in projected["runs"] if row["run_number"] == 4)
            self.assertEqual(run4["status"], "refused")
            self.assertEqual(run4["archive_receipt"], archive_receipt)

    def test_run3_exhaustion_through_checkpoint_keeps_protected_digest_and_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            session = Path(directory)
            (session / "gateway.log").write_text("", encoding="utf-8")
            run = fixture(3)
            run["requests"] *= 13
            run["lags"] *= 13
            with patch("inference_platform.stage_c_session.disk_snapshot", return_value={}):
                receipt = checkpoint_run(session, 3, run)
            digest = receipt["measurement_digest"]
            self.assertTrue(digest["per_request_detail_dropped"])
            self.assertEqual(digest["event_lag_status"], "unavailable")
            self.assertTrue((session / "sealed-runs" / "run-3.tar.gz").exists())
            self.assertTrue((session / "sealed-runs" / "run-3.receipt.json").exists())
            self.assertTrue(
                (session / "sealed-runs" / "run-3.digest.json.gz.failure.json").exists()
            )
            projected = final_metadata_projection(session)
            run3 = next(row for row in projected["runs"] if row["run_number"] == 3)
            self.assertEqual(run3["status"], "protected_only")

    def assert_run3_fallback_refusal(self, mutate, *, export_both=False):
        with tempfile.TemporaryDirectory() as directory:
            session = Path(directory)
            (session / "gateway.log").write_text("", encoding="utf-8")
            run = fixture(3)
            mutate(run)
            with (
                patch("inference_platform.stage_c_session.disk_snapshot", return_value={}),
                patch("inference_platform.stage_c_checkpoint.seal_run", wraps=seal_run) as seal_spy,
            ):
                receipt = checkpoint_run(session, 3, run)

            self.assertEqual(seal_spy.call_count, 1)
            digest = receipt["measurement_digest"]
            self.assertEqual(digest["status"], "refused")
            failure_path = session / "sealed-runs" / "run-3.digest.json.gz.failure.json"
            failure = json.loads(failure_path.read_text(encoding="utf-8"))
            self.assertEqual(digest["flag"], failure["flag"])
            self.assertEqual(digest["table"], failure["table"])
            self.assertEqual(
                digest["failure_receipt_sha256"],
                hashlib.sha256(failure_path.read_bytes()).hexdigest(),
            )
            archive_path = session / "sealed-runs" / "run-3.tar.gz"
            archive_receipt_path = session / "sealed-runs" / "run-3.receipt.json"
            self.assertTrue(archive_path.exists())
            self.assertTrue(archive_receipt_path.exists())
            saved_receipt = json.loads(archive_receipt_path.read_text(encoding="utf-8"))
            self.assertEqual(saved_receipt["measurement_digest"], digest)
            projected = final_metadata_projection(session)
            run3 = next(row for row in projected["runs"] if row["run_number"] == 3)
            self.assertEqual(run3["status"], "refused")
            self.assertEqual(run3["archive_receipt"], saved_receipt)

            if export_both:
                manifest = session / "staging-manifest.json"
                manifest.write_text("{}\n", encoding="utf-8")
                for recovery in (False, True):
                    export_session(session, manifest, recovery=recovery)
                    artifact = session / "export" / "stage-c-artifact.json"
                    self.assertTrue(artifact.exists())
                    exported_run3 = next(
                        row
                        for row in json.loads(artifact.read_text(encoding="utf-8"))["runs"]
                        if row["run_number"] == 3
                    )
                    self.assertEqual(exported_run3["status"], "refused")

    def test_run3_null_rewarm_fallback_refuses_and_keeps_archive(self):
        self.assert_run3_fallback_refusal(
            lambda run: run.__setitem__("rewarm_convergence_compact", None)
        )

    def test_run3_null_source_binding_fallback_refuses_and_keeps_archive(self):
        self.assert_run3_fallback_refusal(lambda run: run.__setitem__("source_binding", None))

    def test_run3_invalid_protected_schema_export_recovers_in_both_modes(self):
        self.assert_run3_fallback_refusal(
            lambda run: run["rewarm_convergence_compact"].__setitem__("schema", "x"),
            export_both=True,
        )

    def test_run3_invalid_binding_hash_export_recovers_in_both_modes(self):
        self.assert_run3_fallback_refusal(
            lambda run: run["source_binding"].__setitem__("run_sha256", "ZZ"),
            export_both=True,
        )

    def test_run3_raw_keyerror_still_projects_protected_only(self):
        with tempfile.TemporaryDirectory() as directory:
            session = Path(directory)
            (session / "gateway.log").write_text("", encoding="utf-8")
            run = fixture(3)
            run.pop("gateway_cpu_ticks_per_second")
            with patch("inference_platform.stage_c_session.disk_snapshot", return_value={}):
                receipt = checkpoint_run(session, 3, run)
            self.assertEqual(receipt["measurement_digest"]["event_lag_status"], "unavailable")
            self.assertTrue((session / "sealed-runs" / "run-3.tar.gz").exists())
            self.assertTrue((session / "sealed-runs" / "run-3.receipt.json").exists())
            projected = final_metadata_projection(session)
            run3 = next(row for row in projected["runs"] if row["run_number"] == 3)
            self.assertEqual(run3["status"], "protected_only")

    def test_run3_checkpoint_null_requests_keeps_protected_only_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            session = Path(directory)
            (session / "gateway.log").write_text("", encoding="utf-8")
            run = fixture(3)
            run["requests"] = None
            with patch("inference_platform.stage_c_session.disk_snapshot", return_value={}):
                receipt = checkpoint_run(session, 3, run)

            digest = receipt["measurement_digest"]
            self.assertTrue(digest["per_request_detail_dropped"])
            self.assertEqual(digest["event_lag_status"], "unavailable")
            self.assertFalse(digest["full_measured_session_acceptance"])
            failure_path = session / "sealed-runs" / "run-3.digest.json.gz.failure.json"
            failure = json.loads(failure_path.read_text(encoding="utf-8"))
            archive_receipt_path = session / "sealed-runs" / "run-3.receipt.json"
            archive_receipt = json.loads(archive_receipt_path.read_text(encoding="utf-8"))
            self.assertIsNone(failure["observed_count"])
            self.assertEqual(failure["table"], "registered_source")
            self.assertTrue((session / "sealed-runs" / "run-3.tar.gz").exists())
            self.assertEqual(archive_receipt["measurement_digest"], digest)
            projected = final_metadata_projection(session)
            run3 = next(row for row in projected["runs"] if row["run_number"] == 3)
            self.assertEqual(run3["status"], "protected_only")

    def test_registered_success_digest_stays_byte_identical_after_refusal_handling(self):
        with tempfile.TemporaryDirectory() as directory:
            session = Path(directory)
            run = fixture(4)
            receipt = seal_run(session, 4, run, core_only=True)
        self.assertEqual(
            receipt["measurement_digest"]["sha256"],
            "67d73d5cb3725b19c006f0c3b4912473a19e213e52a94758a93375a728736bb1",
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
