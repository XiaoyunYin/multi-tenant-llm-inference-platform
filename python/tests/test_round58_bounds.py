import io
import json
import tempfile
import time
import tracemalloc
import unittest
from pathlib import Path
from unittest.mock import patch

from inference_platform.calibration import CalibrationConfig, _stream_request
from inference_platform.disk_records import DiskList, write_json
from inference_platform.failure_taxonomy import classification
from inference_platform.fake_backend import FailureMode, FakeBackend, FakeBackendConfig
from inference_platform.host_diagnostics import diagnostic_bundle, host_snapshot
from inference_platform.host_headroom import headroom_fitness
from inference_platform.stage_c_checkpoint import seal_run


class Round58BoundsTest(unittest.TestCase):
    def test_disk_volume_dump_and_reversal_have_bounded_python_memory(self):
        with tempfile.TemporaryDirectory() as directory:
            tracemalloc.start()
            rows = DiskList({"n": n, "value": "x" * 8192} for n in range(7000))
            write_json(Path(directory) / "rows.json", {"rows": rows})
            peak = tracemalloc.get_traced_memory()[1]
            tracemalloc.stop()
            self.assertLess(peak, 8 * 1024**2)
            self.assertEqual(next(reversed(rows))["n"], 6999)
            self.assertEqual(len(rows + [{"n": 7000}]), 7001)
            rows.close()

    def test_sustained_deadline_keeps_http_code_and_sse_error_is_never_completed(self):
        for mode in (
            FailureMode.VLLM_HTTP_REJECTION,
            FailureMode.VLLM_SSE_ERROR_BEFORE_CONTENT,
            FailureMode.VLLM_SSE_ERROR_AFTER_CONTENT,
        ):
            with (
                self.subTest(mode=mode),
                FakeBackend(FakeBackendConfig(failure_mode=mode)) as backend,
            ):
                row = _stream_request(
                    CalibrationConfig(
                        backend.base_url,
                        "unit-token",
                        "tenant",
                        "test-model",
                        "native-error",
                        gateway_mode=False,
                    ),
                    "0" * 64,
                    time.perf_counter_ns(),
                    "hello",
                    time.perf_counter() + 3,
                )
                self.assertEqual(row["error_body_code"], 503)
                self.assertEqual(row["error_body_type"], "Service Unavailable")
                self.assertNotEqual(row["outcome"], "completed")
                self.assertEqual(
                    row["http_status"], 503 if mode is FailureMode.VLLM_HTTP_REJECTION else 200
                )

    def test_health_failure_body_with_deadline_and_taxonomy_priority(self):
        import urllib.error
        from email.message import Message

        error = urllib.error.HTTPError(
            "local", 503, "test", Message(), io.BytesIO(b'{"error":{"code":"no_healthy_backend"}}')
        )
        with patch("inference_platform.calibration.deadline_urlopen", side_effect=error):
            row = _stream_request(
                CalibrationConfig("http://local", "unit-token", "tenant", "test-model", "health"),
                "0" * 64,
                time.perf_counter_ns(),
                "hello",
                time.perf_counter() + 3,
            )
        self.assertEqual(row["error_code"], "no_healthy_backend")
        self.assertEqual(row["error_body_code"], "no_healthy_backend")
        self.assertEqual(
            classification(row, {"code": "no_healthy_backend"}), "gateway_no_healthy_backend"
        )
        self.assertEqual(
            classification(row, {"code": "upstream_protocol_error"}), "gateway_protocol_rejection"
        )
        self.assertEqual(
            classification(
                row,
                {
                    "code": "upstream_protocol_error",
                    "upstream_error_code": 503,
                    "upstream_error_shape": "sse_error",
                },
            ),
            "vllm_in_stream_error",
        )

    def test_diagnostic_projection_drops_kernel_names_addresses_and_secrets(self):
        import subprocess

        text = b"[123.4] Out of memory: Killed process 777 (secret-host) total-vm:12000kB anon-rss:1000kB credential=super-secret 123456789012\n"
        with patch(
            "inference_platform.host_diagnostics.subprocess.run",
            return_value=subprocess.CompletedProcess([], 0, text, b""),
        ):
            bundle = diagnostic_bundle()
        encoded = json.dumps(bundle["dmesg_oom_kill_tail"])
        for value in ("secret-host", "super-secret", "123456789012", "777"):
            self.assertNotIn(value, encoded)
        self.assertIn("oom_kill", encoded)
        self.assertIn("anon-rss", encoded)
        self.assertIn("load_average", bundle["host"]) if bundle["host"][
            "status"
        ] == "available" else None
        self.assertIn("cgroup", host_snapshot())

    def test_headroom_gate_rejects_missing_stale_tampered_and_over_budget(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipt = root / "receipt.json"
            proof = root / "proof.json"
            proof.write_text("{}")
            import hashlib

            base = {
                "schema": "inf011-constrained-rehearsal.v1",
                "status": "passed",
                "source_files_sha256": {"source": "hash"},
                "memory_budget_bytes": 6 * 1024**3,
                "cpu_limit": 2,
                "measured_request_count": 7000,
                "completed_run_count": 4,
                "peak_memory_bytes": 200000000,
                "oom_kill_delta": 0,
                "host_series_sample_count": 1,
                "process_peaks": {
                    role: {"peak_rss_bytes": 100, "peak_cpu_percent": 1}
                    for role in ("host_controller", "capture", "gateway", "sampler")
                },
                "evidence_sha256": {"proof.json": hashlib.sha256(proof.read_bytes()).hexdigest()},
            }
            with patch(
                "inference_platform.host_headroom.source_fingerprint",
                return_value={"source": "hash"},
            ):
                self.assertFalse(headroom_fitness(root, receipt)[0])
                write_json(receipt, base)
                self.assertTrue(headroom_fitness(root, receipt)[0])
                for change in (
                    {"source_files_sha256": {}},
                    {"peak_memory_bytes": 4 * 1024**3},
                    {"measured_request_count": 6936},
                    {"cpu_limit": 4},
                    {"oom_kill_delta": 1},
                    {"process_peaks": {}},
                    {"evidence_sha256": {}},
                    {"evidence_sha256": {"proof.json": "0" * 64}},
                ):
                    write_json(receipt, {**base, **change})
                    self.assertFalse(headroom_fitness(root, receipt)[0], change)

    def test_sealed_run_is_complete_before_receipt_and_excludes_raw_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "gateway.log").write_text("")
            (root / "restricted-decisions.jsonl").write_text("raw-token-fixture")
            (root / "host-process-samples.jsonl").write_bytes(b'{}\n{"incomplete"')
            receipt = seal_run(root, 1, {"status": "completed", "levels": []})
            self.assertTrue(receipt["sealed_before_next_run"])
            import tarfile

            with tarfile.open(root / "sealed-runs/run-1.tar.gz") as archive:
                self.assertNotIn("restricted-decisions.jsonl", archive.getnames())
                self.assertEqual(archive.extractfile("host-process-samples.jsonl").read(), b"{}\n")


if __name__ == "__main__":
    unittest.main()
