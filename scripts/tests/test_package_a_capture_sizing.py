"""Compact adapter controls; maximum sizing runs only on the reviewed host."""

import contextlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from inference_platform import inf037b_archive as archive
from inference_platform import inf037b_campaign as campaign
from inference_platform import package_a_capture as capture
from inference_platform.package_a_cloud import sha

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
SCRIPT = Path(
    os.environ.get(
        "DEC086_SIZING_SCRIPT", ROOT / "scripts/size_inf037b_sanitized_export.py"
    )
)
SPEC = importlib.util.spec_from_file_location("dec086_sizing", SCRIPT)
SIZING = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SIZING)


class SizingCaptureTests(unittest.TestCase):
    def test_implicit_windows_sizing_workspace_uses_repository_cache(self):
        self.assertEqual(
            SIZING.default_work_path(Path("D:/checkout"), platform="win32"),
            Path("D:/checkout") / ".cache",
        )

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.args = SimpleNamespace(
            output=self.root / "native.json",
            capture_receipt=self.root / "capture.json",
            work=self.root,
        )
        self.provenance = {
            "source_commit": "a" * 40,
            "manifest_sha256": "b" * 64,
            "modules": {},
            "file_sha256": {},
            "host_binding": {"porcelain_sha256": "c" * 64},
        }

    def exercise(self, *, status="PASS", changed_head=False, failure=False):
        import time_inf037b_three_attempts as builder

        def build(root, **kw):
            self.assertEqual(kw, {"reset_ms": 300000, "include_reset_capture": True})
            (root / "raw").mkdir(parents=True)
            (root / "raw/a.jsonl").write_bytes(b"{}\n{}\n")
            return [{"expected_offers": []}] * 3, 2

        def sanitize(source, destination, specs, **kw):
            destination.mkdir()
            (destination / "data").write_bytes(b"safe")
            self.assertEqual(kw["key"], b"step5-sizing-key-only" * 2)
            return {"specs": specs, "source_manifest_sha256": "d" * 64}

        def compute(**kw):
            started = time.monotonic_ns()
            provenance = kw["verify_source"]()
            if failure:
                raise TimeoutError("injected capture deadline")
            kw["sanitize"](kw["source"], kw["sanitized"])
            return {
                "status": status,
                "source": provenance,
                "staging": kw["staging"],
                "monotonic_start_ns": started,
                "monotonic_end_ns": time.monotonic_ns(),
            }

        with (
            patch.object(builder, "build", side_effect=build),
            patch.object(campaign, "materialize_bundle"),
            patch.object(campaign, "sanitized_campaign", side_effect=sanitize),
            patch.object(
                archive,
                "verify_archive",
                return_value={"segments": {"raw/a": {"row_count": 2}}},
            ),
            patch.object(capture, "compute_capture", side_effect=compute),
            patch.object(
                SIZING,
                "source_manifest",
                return_value={**self.provenance, "source_commit": "b" * 40}
                if changed_head
                else self.provenance,
            ),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            SIZING.execute_sizing(
                ROOT, self.args, self.provenance, container_mode=False
            )

    def test_capture_writes_independent_native_scope_and_hashed_receipt(self):
        self.exercise()
        native = json.loads(self.args.output.read_bytes())
        early = json.loads(self.args.capture_receipt.read_bytes())
        self.assertEqual(early["native_receipt_sha256"], sha(self.args.output))
        self.assertEqual(
            native["elapsed_seconds"],
            (native["monotonic_end_ns"] - native["monotonic_start_ns"]) / 1e9,
        )
        self.assertLessEqual(early["monotonic_start_ns"], native["monotonic_start_ns"])
        self.assertLessEqual(native["monotonic_end_ns"], early["monotonic_end_ns"])
        self.assertIn("whole bounded compute capture", native["memory_method"])
        self.assertEqual(early["staging"]["raw_rows"], 2)
        self.assertTrue(early["staging"]["verified"])

    def test_source_change_refuses_inside_capture_and_retains_staging(self):
        with self.assertRaisesRegex(
            SIZING.SourceBindingError, "capture source changed"
        ):
            self.exercise(changed_head=True)
        self.assertEqual(
            json.loads(self.args.capture_receipt.read_bytes())["status"], "FAILED"
        )

    def test_compute_timeout_preserves_failed_staging_receipt(self):
        with self.assertRaisesRegex(TimeoutError, "deadline"):
            self.exercise(failure=True)
        receipt = json.loads(self.args.capture_receipt.read_bytes())
        self.assertEqual(receipt["status"], "FAILED")
        self.assertTrue(receipt["staging"]["verified"])

    def test_returned_overrun_refuses_even_if_capture_returns_normally(self):
        with self.assertRaisesRegex(
            RuntimeError, "capture_compute_exceeds_1650s_DEC041_item2"
        ):
            self.exercise(status="FAILED")
        self.assertEqual(
            json.loads(self.args.capture_receipt.read_bytes())["status"], "FAILED"
        )

    def test_capture_cli_refuses_non_native_modes(self):
        for mode in (
            ["--container-mode"],
            ["--write-source-manifest", "x"],
            ["--finalize-container-receipt", "x"],
            ["--preflight-only"],
        ):
            error = io.StringIO()
            with (
                self.subTest(mode=mode),
                contextlib.redirect_stderr(error),
                self.assertRaises(SystemExit) as result,
            ):
                SIZING.main(["--capture-receipt", "x", *mode])
            self.assertEqual(result.exception.code, 2)
            self.assertIn(
                "--capture-receipt requires a native sizing run", error.getvalue()
            )
