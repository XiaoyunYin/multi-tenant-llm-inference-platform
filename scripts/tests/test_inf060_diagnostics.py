"""Failure evidence is bounded, closed-schema and transferred by hash."""

import base64
import hashlib
import json
import shlex
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

import inf060_diagnostics as diag
from audit_inf060_timing import verify_model_readback
from inf060_aws_operator import retrieve_diagnostics
from inf060_probe_spec import REVISION
from inf060_remote_service import save_witness


class DiagnosticTests(unittest.TestCase):
    def test_model_readback_matches_exact_runtime_file_facts(self):
        facts = {"bytes": 9, "sha256": "a" * 64}
        model = {
            "revision": REVISION,
            "files": {"config.json": {**facts, "git_blob": "b" * 40}},
        }
        readback = {
            "revision": REVISION,
            "files": {"config.json": facts},
            "tokens": 1024,
        }
        verify_model_readback(readback, model)
        readback["files"] = {"config.json": {**facts, "sha256": "c" * 64}}
        with self.assertRaisesRegex(ValueError, "timing_model_digest"):
            verify_model_readback(readback, model)

    def test_scrub_token_prompt_identifiers_and_host(self):
        sensitive = (
            "Authorization: Bearer the-actual-transfer-token",
            "rendered fixture-secret-canary one one one",
            "i-0123456789abcdef0 vpc-0123456789abcdef0 vol-0123456789abcdef0",
            "10.77.1.20 ip-10-77-1-20.internal hostname.example.net",
            "123456789012 ssm-session-test",
        )
        raw = "\n".join((*sensitive, "inf060:epoch_logging_readback")).encode()
        result = diag.tail(raw)
        self.assertEqual(
            result["lines"],
            ["[redacted]"] * len(sensitive) + ["inf060:epoch_logging_readback"],
        )
        self.assertEqual(
            diag.exception_record(ValueError(sensitive[0]))["message"], "[redacted]"
        )

    def test_large_logs_retain_bounded_tail(self):
        raw = (b"arbitrary log line with content\n" * 2500) + b"inf060:model_stage\n"
        result = diag.tail(raw)
        self.assertTrue(result["truncated"])
        self.assertEqual(result["source_bytes"], len(raw))
        self.assertEqual(len(result["lines"]), diag.TAIL_LINES)
        self.assertEqual(result["lines"][-1], "inf060:model_stage")

    def test_native_failures_keep_only_safe_fields(self):
        hidden = "Bearer hidden-token fixture-prompt 10.77.1.20 i-0123456789abcdef0 123456789012"
        rows = {
            "(EngineCore_DP0 pid=181) 1792002121.102031 ERROR [core.py:792] ": "ERROR [core.py:792]",
            "1792002121.102031 WARNING [stage.py:8] ": "WARNING [stage.py:8]",
            "1792002121.102031 CRITICAL [worker.py:71] ": "CRITICAL [worker.py:71]",
            "vllm: error: unrecognized arguments: ": "unrecognized arguments",
            "engine core initialization failed; ": "engine core initialization failed",
            "no available memory for the cache blocks; ": "no available memory for the cache blocks",
            "ModuleNotFoundError: ": "ModuleNotFoundError",
            "ImportError: ": "ImportError",
            "torch.cuda.DeviceError: ": "torch.cuda.DeviceError",
            "no CUDA GPUs are available. ": "no CUDA GPUs are available",
            "CUDA driver version is insufficient. ": "CUDA driver version is insufficient",
            "address already in use. ": "address already in use",
            "permission denied. ": "permission denied",
            "Killed ": "Killed",
        }
        record = diag.tail("\n".join(prefix + hidden for prefix in rows).encode())
        self.assertEqual(record["lines"], list(rows.values()))

    def test_traceback_keeps_packet_frames_without_locals_or_paths(self):
        namespace = {}
        exec(
            compile(
                "def stage():\n    raise KeyError('fixture-prompt')\n",
                str(diag.SCRIPTS / "synthetic_probe.py"),
                "exec",
            ),
            namespace,
        )
        with tempfile.TemporaryDirectory() as directory:
            exec(
                compile(
                    "def relay(callback):\n    callback()\n",
                    str(Path(directory) / "external.py"),
                    "exec",
                ),
                namespace,
            )
            try:
                namespace["relay"](namespace["stage"])
            except KeyError as error:
                record = diag.exception_record(error)
        caller = record["frames"][0]
        self.assertTrue(caller.startswith("test_inf060_diagnostics.py:"))
        self.assertTrue(caller.endswith(":" + self._testMethodName))
        self.assertEqual(
            record,
            {
                "type": "KeyError",
                "message": "[redacted]",
                "frames": [caller, "synthetic_probe.py:2:stage"],
            },
        )
        self.assertEqual(diag.safe_error(record), record)

    def test_missing_archive_keeps_controller_diagnostics(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            diag.write(
                path / "controller-error.json",
                diag.exception_record(RuntimeError("runner_failed:1")),
            )
            record = diag.collect(path)
            self.assertEqual(record["gpu_archive"]["status"], "missing")
            self.assertEqual(
                record["controller_error"],
                {"type": "RuntimeError", "message": "runner_failed:1", "frames": []},
            )

    def test_paid_fault_switch_is_inert(self):
        for fault in diag.FAILURES:
            self.assertIsNone(diag.injected_failure(None, fault))
            self.assertEqual(diag.injected_failure("mock", fault), fault)

    def test_witness_uses_preview_for_oversized_record(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            diag_row = {
                "preview": {"controller_error": "runner_failed:1"},
                "inline": {"log": "X" * diag.SSM_STDOUT_BYTES},
            }
            save_witness(path, "result.json", {"diagnostics": diag_row})
            self.assertEqual(
                json.loads((path / "result.json").read_bytes()),
                {"diagnostics": {"preview": diag_row["preview"]}},
            )

    def test_chunked_read_checks_full_file_hash(self):
        raw = diag.encoded({"log": ["inf060:model_stage"] * 600})
        sizes = []

        def ssm(_host, argv, **_kwargs):
            offset, size = map(int, shlex.split(argv[0])[-2:])
            sizes.append(size)
            return {
                "StandardOutputContent": base64.b64encode(
                    raw[offset : offset + size]
                ).decode()
            }

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stack = SimpleNamespace(run=root, ports=SimpleNamespace(ssm=ssm))
            submission = {"host": "test", "end": time.time() + 60}
            binding = {
                "status": "available",
                "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
            result = {
                "supervisor_complete": False,
                "supervisor_exit": 1,
                "diagnostics": binding,
            }
            receipt = retrieve_diagnostics(stack, submission, result)
            self.assertEqual(receipt["status"], "verified")
            self.assertGreater(len(sizes), 1)
            self.assertEqual(sum(sizes), len(raw))
            self.assertEqual((root / "failure-diagnostics.json").read_bytes(), raw)
            binding["sha256"] = "0" * 64
            self.assertEqual(
                retrieve_diagnostics(stack, submission, result)["status"],
                "diagnostics_unavailable",
            )
