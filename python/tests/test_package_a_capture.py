import copy
import json
import signal
import sys
import tempfile
import time
import unittest
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import patch

from test_package_a_cloud import historical_timing_worksheet

from inference_platform import package_a_capture as capture
from inference_platform import package_a_cloud as cloud
from inference_platform import package_a_operator as operator
from inference_platform.package_a_operator import validate_host_refresh

ROOT = Path(__file__).resolve().parents[2]


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        (self.source / "raw").mkdir(parents=True)
        (self.source / "raw/a.jsonl").write_bytes(b'{"a":1}\n{"a":2}\n')
        self.specs = [{"attempt_index": 1}]
        self.staged = self.root / "staged"
        self.staging = capture.stage_fixture(self.source, self.staged, self.specs, 2)

    def compute(self, staging=None, verifier=None):
        return capture.compute_capture(
            staging=self.staging if staging is None else staging,
            source=self.staged,
            sanitized=self.root / "safe",
            destination=self.root / "readback",
            verify_source=verifier or (lambda: {"source_commit": "a" * 40}),
            sanitize=lambda *_: None,
        )

    def test_staging_records_hashes_rows_bytes_and_detects_bad_copy(self):
        self.assertTrue(self.staging["verified"])
        self.assertEqual(self.staging["raw_rows"], 2)
        self.assertEqual(self.staging["bytes"], 16)
        self.assertEqual(self.staging["manifest_sha256"], capture.digest(self.staging["manifest"]))
        for key in ("copy_s", "hash_check_s"):
            self.assertGreaterEqual(self.staging[key], 0)

        def bad_copy(*_):
            (self.root / "bad/raw").mkdir(parents=True)
            (self.root / "bad/raw/a.jsonl").write_bytes(b'{"a":3}\n{"a":4}\n')

        with patch.object(capture.shutil, "copytree", side_effect=bad_copy):
            bad = capture.stage_fixture(self.source, self.root / "bad", self.specs, 2)
        self.assertFalse(bad["verified"])
        wrong_rows = capture.stage_fixture(self.source, self.root / "wrong", self.specs, 3)
        self.assertFalse(wrong_rows["verified"])

    def test_staging_unverified_refuses_before_any_source_work(self):
        self.staging["verified"] = False
        with patch.object(capture, "capture_export") as work:
            with self.assertRaisesRegex(ValueError, "capture_staging_unverified"):
                self.compute()
            work.assert_not_called()

    def test_changed_staged_fixture_refuses(self):
        (self.staged / "raw/a.jsonl").write_bytes(b"changed\n")
        with self.assertRaisesRegex(ValueError, "capture_staged_fixture_changed"):
            self.compute()

    def test_one_source_bound_bracket_and_boundary(self):
        for seconds, status in ((1650, "PASS"), (1650.000000001, "FAILED")):
            events = []

            def verify(events=events):
                events.append("verify_source")
                return {"source_commit": "a" * 40, "file_sha256": {"sanitizer": "pinned"}}

            def export(events=events, **kw):
                events.append("export")
                kw["sanitize"](kw["source"], kw["sanitized"])
                return json.dumps({"sanitized": {"x": 1}, "destination": {"x": 1}}).encode(), {}

            with (
                patch.object(capture.time, "monotonic_ns", side_effect=(0, round(seconds * 1e9))),
                patch.object(capture, "capture_export", side_effect=export),
            ):
                result = self.compute(verifier=verify)
            self.assertEqual(events, ["verify_source", "export"])
            self.assertEqual(result["status"], status)
            self.assertEqual(result["compute_s"], seconds)
            self.assertEqual(result["source"]["file_sha256"]["sanitizer"], "pinned")

    def test_readback_mismatch_refuses(self):
        with patch.object(
            capture,
            "capture_export",
            return_value=(b'{"sanitized":{"x":1},"destination":{"x":2}}', {}),
        ):
            with self.assertRaisesRegex(ValueError, "capture_readback_mismatch"):
                self.compute()

    def test_compute_deadline_interrupts_work_and_restores_alarm(self):
        previous = signal.getsignal(signal.SIGALRM)
        with (
            patch.object(capture, "CAPTURE_LIMIT_S", 0.01),
            patch.object(
                capture, "capture_export", return_value=(b'{"sanitized":{},"destination":{}}', {})
            ),
        ):
            with self.assertRaisesRegex(TimeoutError, "DEC041_item2"):
                self.compute(verifier=lambda: time.sleep(1))
        self.assertEqual(signal.getsignal(signal.SIGALRM), previous)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))

    @staticmethod
    def receipts():
        native = {
            "source_commit": "a" * 40,
            "elapsed_seconds": 1.0,
            "monotonic_start_ns": 10,
            "monotonic_end_ns": 1000000010,
            "capture_reuse_scope": "sanitized_campaign only; excludes staging, source checks, transfer and readback",
        }
        early = {
            "status": "PASS",
            "compute_s": 2.0,
            "source": {"source_commit": "a" * 40},
            "staging": {"verified": True},
            "native_receipt_sha256": "bound",
            "monotonic_start_ns": 0,
            "monotonic_end_ns": 2000000000,
        }
        return early, native

    def test_native_reuse_rejects_each_unbound_receipt_field(self):
        early, native = self.receipts()
        capture.validate_native_reuse(early, native, "a" * 40, "bound")
        for owner, field, value in (
            ("capture", "status", "FAILED"),
            ("capture", "compute_s", 1650.001),
            ("capture", "compute_s", -1),
            ("capture", "source", {"source_commit": "b" * 40}),
            ("capture", "staging", {"verified": False}),
            ("capture", "native_receipt_sha256", "changed"),
            ("native", "source_commit", "b" * 40),
            ("native", "capture_reuse_scope", "unbounded"),
            ("native", "monotonic_start_ns", -1),
            ("native", "monotonic_end_ns", 2000000001),
            ("native", "monotonic_end_ns", 0),
            ("native", "elapsed_seconds", 9),
        ):
            with self.subTest(owner=owner, field=field, value=value):
                left, right = copy.deepcopy(early), copy.deepcopy(native)
                (left if owner == "capture" else right)[field] = value
                if owner == "native" and field in {"monotonic_start_ns", "monotonic_end_ns"}:
                    right["elapsed_seconds"] = (
                        right["monotonic_end_ns"] - right["monotonic_start_ns"]
                    ) / 1e9
                with self.assertRaisesRegex(ValueError, "capture_native_reuse_unbound"):
                    capture.validate_native_reuse(left, right, "a" * 40, "bound")

    def runner(self, execute=None, available=32 * cloud.GIB):
        memory = {"MemTotal": 32 * cloud.GIB, "MemAvailable": available}
        from test_package_a_cloud import Runner

        runner = Runner(
            ROOT,
            self.root / "runner",
            {
                "checks": ["capture", "native", "constrained"],
                "source_commit": "a" * 40,
                "python_sha256": {},
                "python_executable": sys.executable,
                "pins": {"python_image": "pin"},
                "instance_type": cloud.INSTANCE_TYPE,
                "ami": "image",
                "on_demand_usd_per_hour": 0.34,
                "deadline_epoch": time.time() + cloud.DEADLINE_S,
            },
            sample=lambda: {"host": memory, "vm": memory.copy(), "raw_proc_meminfo": "raw sample"},
            **({"execute": execute} if execute else {}),
        )
        return runner

    def test_capture_failure_halts_later_checks_and_image_preparation(self):
        runner = self.runner()
        called = []

        def fail(name):
            called.append(name)
            raise TimeoutError("capture overrun")

        runner.check = fail
        runner.prepare_images = lambda: self.fail("images after failed capture")
        with (
            patch.object(cloud, "verified_source", return_value={}),
            patch.object(cloud.Path, "read_text", return_value="cpu memory"),
        ):
            self.assertFalse(runner.run())
        self.assertEqual(called, ["capture"])
        self.assertEqual(
            [r["status"] for r in runner.receipt["checks"]],
            ["FAILED", "SKIPPED_CAPTURE_HALT", "SKIPPED_CAPTURE_HALT"],
        )
        self.assertTrue(
            all(r["sample"]["raw_proc_meminfo"] == "raw sample" for r in runner.receipt["checks"])
        )

    def test_runner_rejects_overrun_receipt_even_if_command_exits_zero(self):
        def execute(argv, **kw):
            if "--capture-receipt" in argv:
                early, native = self.receipts()
                early["compute_s"] = 1650.001
                path = self.root / "runner/sizing-native.json"
                cloud.save(path, native)
                early["native_receipt_sha256"] = cloud.sha(path)
                cloud.save(self.root / "runner/capture.json", early)
            return {}

        runner = self.runner(execute)
        runner.receipt["host"] = {"instance_type": cloud.INSTANCE_TYPE}
        with self.assertRaisesRegex(ValueError, "capture_native_reuse_unbound"):
            runner.check("capture")

    def test_capture_gate_skip_halts_without_preparing_images(self):
        runner = self.runner(available=0)
        runner.check = lambda _: self.fail("gate skipped work ran")
        runner.prepare_images = lambda: self.fail("gate skipped capture started images")
        with (
            patch.object(cloud, "verified_source", return_value={}),
            patch.object(cloud.Path, "read_text", return_value="cpu memory"),
        ):
            self.assertFalse(runner.run())
        self.assertEqual(
            [r["status"] for r in runner.receipt["checks"]],
            ["SKIPPED_GATE", "SKIPPED_CAPTURE_HALT", "SKIPPED_CAPTURE_HALT"],
        )

    def test_success_order_prepares_images_only_after_capture_and_native(self):
        runner = self.runner()
        events = []
        runner.check = lambda name: events.append(name)
        runner.prepare_images = lambda: events.append("prepare_images")
        with (
            patch.object(cloud, "verified_source", return_value={}),
            patch.object(cloud.Path, "read_text", return_value="cpu memory"),
        ):
            self.assertTrue(runner.run())
        self.assertEqual(events, ["capture", "native", "prepare_images", "constrained"])

    def test_native_reuse_admitted_by_its_own_short_budget(self):
        runner = self.runner()
        clock = [1000]
        runner.manifest["deadline_epoch"] = 1000 + cloud.BUDGETS["capture"] + 1
        events = []

        def check(name):
            events.append(name)
            clock[0] = runner.manifest["deadline_epoch"] - 31

        runner.check = check
        runner.prepare_images = lambda: self.fail("late image preparation")
        with (
            patch.object(cloud, "verified_source", return_value={}),
            patch.object(cloud.Path, "read_text", return_value="cpu memory"),
            patch.object(cloud.time, "time", side_effect=lambda: clock[0]),
        ):
            self.assertFalse(runner.run())
        self.assertEqual(events, ["capture", "native"])

    def test_native_reuse_executes_no_second_sanitizer_and_constrained_gate_stays(self):
        calls = []
        runner = self.runner(lambda argv, **_: calls.append(argv))
        early, native = self.receipts()
        cloud.save(runner.output / "sizing-native.json", native)
        early["native_receipt_sha256"] = cloud.sha(runner.output / "sizing-native.json")
        cloud.save(runner.output / "capture.json", early)
        runner.check("native")
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], "sh")
        required = 14336 * cloud.MIB
        for available, expected in ((required - 1, False), (required, True)):
            sample = {"MemAvailable": available, "MemTotal": 16 * cloud.GIB}
            self.assertEqual(
                cloud.gate({"host": sample, "vm": sample.copy()}, 14336, 12288), expected
            )

    def test_runner_native_refuses_changed_receipt_hash(self):
        runner = self.runner(lambda *_args, **_kw: None)
        early, native = self.receipts()
        cloud.save(runner.output / "sizing-native.json", native)
        cloud.save(runner.output / "capture.json", early)
        with self.assertRaisesRegex(ValueError, "capture_native_reuse_unbound"):
            runner.check("native")

    def test_refreshed_c6i_shape_and_timing_cost_policy(self):
        good = {"instance_type": cloud.INSTANCE_TYPE, "memory_mib": 16384, "vcpus": 8}
        validate_host_refresh(good)
        for key, value in (("instance_type", "m6i.2xlarge"), ("memory_mib", 32768), ("vcpus", 4)):
            with self.assertRaisesRegex(ValueError, "host_shape_refresh"):
                validate_host_refresh({**good, key: value})
        worksheet = historical_timing_worksheet(
            140000000, checks=("capture", "native", "constrained")
        )
        self.assertEqual(worksheet["checks"], ["capture", "native", "constrained"])
        self.assertEqual(worksheet["call_timeouts_s"]["native"], (30,))
        self.assertEqual(
            worksheet["work_seconds"], cloud.BUDGETS["capture"] + 30 + cloud.BUDGETS["constrained"]
        )
        self.assertEqual(cloud.DEADLINE_S, 21600)
        # Round 345's DEC-087 cap must cover recorded prior spend and this
        # unchanged historical worksheet, including the cleanup reserve.
        self.assertLessEqual(cloud.PRIOR_SPEND_USD, cloud.CAP_USD)
        self.assertGreater(worksheet["cost_guard_margin_s"], 0)
        self.assertGreaterEqual(worksheet["cost_guard_hours"] * 3600, worksheet["forecast_wall_s"])

    def test_prior_spend_ledger_matches_prior_spend_and_cap(self):
        ledger = json.loads((ROOT / "docs/evidence/m5-package-a/spend-ledger.json").read_bytes())
        paid_rows = [row for row in ledger["entries"] if row["classification"] == "dec077_paid"]
        self.assertAlmostEqual(
            sum(row["task_cost_usd"] for row in paid_rows), cloud.PRIOR_SPEND_USD, delta=1e-9
        )
        self.assertEqual(ledger["prior_spend_usd"], cloud.PRIOR_SPEND_USD)
        self.assertGreater(cloud.CAP_USD, ledger["prior_spend_usd"])

    def test_prepare_refuses_unclassified_consumed_packets(self):
        with tempfile.TemporaryDirectory() as directory:
            temp_root = Path(directory)
            unknown = temp_root / ".cache/unclassified-packet"
            unknown.mkdir(parents=True)
            (unknown / "consumed.json").write_text("{}\n", encoding="utf-8")
            packet = temp_root / "packet"
            with patch.object(operator, "ROOT", temp_root):
                with self.assertRaisesRegex(
                    ValueError, r"prior_spend_ledger_incomplete:\.cache/unclassified-packet"
                ):
                    operator.prepare(packet, temp_root / "unused-refresh.json", commit="c" * 40)
            self.assertFalse(packet.exists())

        committed_ledger = json.loads(operator.SPEND_LEDGER_PATH.read_bytes())
        missing_dirs = {
            ".cache/dec086-seventh-packet-ae0f538",
            ".cache/r407/packet-4c78fa8",
            ".cache/r412/packet-b36c74e",
        }
        ledger = copy.deepcopy(committed_ledger)
        ledger["entries"] = [
            row
            for row in ledger["entries"]
            if row.get("packet_dir") not in missing_dirs
            and not missing_dirs.intersection(row.get("packet_dirs", []))
        ]
        with tempfile.TemporaryDirectory() as directory:
            temp_root = Path(directory)
            scratch_ledger = temp_root / "spend-ledger.json"
            scratch_ledger.write_text(json.dumps(ledger), encoding="utf-8")
            for entry in committed_ledger["entries"]:
                packet_dirs = entry.get("packet_dirs") or [entry.get("packet_dir")]
                for packet_dir in packet_dirs:
                    consumed = temp_root / packet_dir / "consumed.json"
                    consumed.parent.mkdir(parents=True, exist_ok=True)
                    consumed.write_text("{}\n", encoding="utf-8")
            packet = temp_root / "packet"
            with (
                patch.object(operator, "ROOT", temp_root),
                patch.object(operator, "SPEND_LEDGER_PATH", scratch_ledger),
            ):
                with self.assertRaises(ValueError) as raised:
                    operator.prepare(packet, temp_root / "unused-refresh.json", commit="c" * 40)
            message = str(raised.exception)
            self.assertEqual(
                message,
                "prior_spend_ledger_incomplete:.cache/dec086-seventh-packet-ae0f538,.cache/r407/packet-4c78fa8,.cache/r412/packet-b36c74e",
            )
            self.assertFalse(packet.exists())

        with tempfile.TemporaryDirectory() as directory:
            with (
                patch.object(operator, "ROOT", Path(directory)),
                patch.object(cloud, "PRIOR_SPEND_USD", 10.097056430225757),
            ):
                with self.assertRaisesRegex(ValueError, "prior_spend_ledger_total_mismatch"):
                    operator.validate_prior_spend_ledger()

    def test_real_compact_archive_sanitizer_transfer_resume_readback(self):
        from types import SimpleNamespace

        from test_inf037b_collectors import CampaignTests

        from inference_platform import inf037b_export_runtime as export_runtime
        from inference_platform.inf037b_archive import verify_archive
        from inference_platform.inf037b_campaign import materialize_bundle, sanitized_campaign

        raw = self.root / "real"
        base, _ = CampaignTests.campaign(SimpleNamespace(root=self.root), name="real")
        rows = sum(
            sum(1 for _ in p.read_bytes().splitlines()) for p in (raw / "raw").glob("*.jsonl")
        )
        specs = [base.spec]
        sync_context = (
            patch.object(export_runtime, "synchronize")
            if sys.platform == "win32"
            else nullcontext()
        )
        with sync_context:
            materialize_bundle(raw, specs)
            staged = self.root / "real-staged"
            staging = capture.stage_fixture(raw, staged, specs, rows)
            result = capture.compute_capture(
                staging=staging,
                source=staged,
                sanitized=self.root / "real-safe",
                destination=self.root / "real-readback",
                verify_source=lambda: {"source_commit": "a" * 40},
                sanitize=lambda source, destination: sanitized_campaign(
                    source, destination, specs, key=b"test-capture-key-only" * 2
                ),
            )
        self.assertEqual(result["status"], "PASS")
        self.assertFalse(result["export"]["interrupted"]["complete"])
        self.assertTrue(result["export"]["resumed"]["complete"])
        self.assertEqual(result["export"]["sanitized"], result["export"]["destination"])
        verify_archive(self.root / "real-readback")
