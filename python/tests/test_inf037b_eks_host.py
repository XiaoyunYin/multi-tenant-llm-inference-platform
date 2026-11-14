"""Portable host-bound files over real TCP; POSIX copy/fsync stays opt-in."""

import os
import shutil
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from inf037b_eks_supervisor_worker import FileJournal

from inference_platform.inf037b_archive import encode, sha
from inference_platform.inf037b_authority import FencedAuthority
from inference_platform.inf037b_eks_execution import ExecutionRuntime, join_execution
from inference_platform.inf037b_eks_fixture import fixture_inventory
from inference_platform.inf037b_eks_host import HostFixtureExecutor
from inference_platform.inf037b_eks_provider import ScopedAuthority
from inference_platform.inf037b_eks_supervisor import AuthorityHTTP, supervisor_handler
from inference_platform.inf037b_ports import Authority
from inference_platform.inf037b_preparation import stage_fixture


class HostTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.binding = {"session_id": "unit", "t0_ms": 0, "pins": {"test": "a" * 64}}
        self.destination = {
            "node_uid": "export-node",
            "volume_id": "recovery-volume",
            "mount_path": str(self.root / "mounted-fixture"),
        }
        self.source = self.root / "pre-delivered"
        self.source.mkdir()
        (self.source / "real.bin").write_bytes(b"small real source bytes")
        self.sample = lambda: {"clock_id": "measurement", "boot_id": "test-boot", "ms": [100, 100]}
        self.count, self.drop, self.cut = 0, False, False
        self.executor = self.open()
        with patch("inference_platform.inf037b_authority.DurableStore", FileJournal):
            self.fenced = FencedAuthority(
                self.root / "fenced",
                "export-host",
                "eks_host",
                effect=self.executor.effect,
                read=self.executor.read,
                reconcile=self.executor.reconcile,
                initialize=True,
            )

        def serve(raw, timeout):
            result = self.fenced(raw, timeout)
            if self.drop:
                self.drop = False
                raise OSError("lost host reply")
            return result

        self.server = ThreadingHTTPServer(
            ("127.0.0.1", 0), supervisor_handler(serve, lambda: "test-token")
        )
        thread = threading.Thread(target=self.server.serve_forever)
        thread.start()
        self.addCleanup(thread.join, 2)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        authority = Authority(
            "export-host",
            "eks_host",
            AuthorityHTTP(
                f"http://127.0.0.1:{self.server.server_port}/authority",
                token=lambda: "test-token",
                local_test=True,
            ),
        )
        self.remote = ScopedAuthority(
            self.root / "client",
            authority,
            store=FileJournal(
                self.root / "client",
                {"sequence": 0, "operations": {}, "values": {}},
                initialize=True,
            ),
        )
        self.request = {
            "binding": self.binding,
            "destination": self.destination,
            "source": "controller-path-that-must-never-be-opened",
            "expected_inventory": fixture_inventory(self.source),
            "stop_ms": 1000,
        }

    def portable_copy(self, *, source, destination, expected_inventory, binding, sample):
        self.count += 1
        shutil.copytree(source, destination)
        if self.cut:
            raise OSError("crash after data copy, before receipt")
        return {
            "binding": binding,
            "pins": binding["pins"],
            "copy": {"start": sample(), "end": sample()},
            "hash": {"start": sample(), "end": sample()},
            "actual_inventory": fixture_inventory(destination),
            "expected_inventory": expected_inventory,
            "verified": True,
        }

    def open(self):
        return HostFixtureExecutor(
            binding=self.binding,
            destination=self.destination,
            local_source=self.source,
            local_mount=self.destination["mount_path"],
            journal=FileJournal(self.root / "host", {}, initialize=True),
            sample=self.sample,
            stage=self.portable_copy,
        )

    def restart(self):
        self.executor = self.open()
        self.fenced.effect, self.fenced.read, self.fenced.reconcile = (
            self.executor.effect,
            self.executor.read,
            self.executor.reconcile,
        )

    def test_host_uses_local_predelivered_source_then_hashes_actual_mount(self):
        result = self.remote.call("eks.host.stage", "stage", 0, self.request)
        self.assertEqual(result["actual_inventory"], self.request["expected_inventory"])
        self.assertEqual(self.count, 1)
        self.assertTrue(self.remote.call("eks.host.reverify", "read", 0, self.request)["verified"])

    def test_lost_stage_reply_restart_settles_without_copy_repeat(self):
        self.drop = True
        with self.assertRaises(OSError):
            self.remote.call("eks.host.stage", "stage", 0, self.request)
        self.restart()
        self.assertTrue(self.remote.call("eks.host.stage", "stage", 0, self.request)["verified"])
        self.assertEqual(self.count, 1)

    def test_partial_copy_restart_is_unknown_and_never_repeats(self):
        self.cut = True
        with self.assertRaises(OSError):
            self.remote.call("eks.host.stage", "stage", 0, self.request)
        self.restart()
        with self.assertRaises(OSError):
            self.remote.call("eks.host.stage", "stage", 0, self.request)
        self.assertEqual(self.count, 1)

    def test_different_destination_refuses_before_copy(self):
        request = {**self.request, "destination": {**self.destination, "node_uid": "foreign"}}
        with self.assertRaisesRegex(ValueError, "eks_host:destination"):
            self.executor.effect("eks.host.stage", "bad", request)
        self.assertEqual(self.count, 0)

    def test_source_mismatch_refuses(self):
        (self.source / "real.bin").write_bytes(b"wrong")
        with self.assertRaisesRegex(ValueError, "source_inventory"):
            self.executor.effect("eks.host.stage", "bad", self.request)

    def test_reverify_reads_files_and_refuses_corruption(self):
        self.remote.call("eks.host.stage", "stage", 0, self.request)
        (Path(self.destination["mount_path"]) / "real.bin").write_bytes(b"wrong")
        with self.assertRaisesRegex(ValueError, "reverify_inventory"):
            self.executor.read("eks.host.reverify", "read", self.request)

    def test_lost_reverify_reply_is_safe_read_on_restart(self):
        self.remote.call("eks.host.stage", "stage", 0, self.request)
        self.drop = True
        with self.assertRaises(OSError):
            self.remote.call("eks.host.reverify", "read", 0, self.request)
        self.restart()
        self.assertTrue(self.remote.call("eks.host.reverify", "read", 0, self.request)["verified"])
        self.assertEqual(self.count, 1)

    def test_replay_export_requires_final_host_pipeline_instead_of_local_copy(self):
        with self.assertRaisesRegex(ValueError, "unfinished:4e_replay_export_pipeline"):
            self.executor.effect("eks.host.replay_export", "export", self.request)

    def runtime(self):
        binding = {k: self.binding[k] for k in ("session_id", "t0_ms")}
        inputs = {
            "binding": binding,
            "pins": self.binding["pins"],
            "export_host": {"authority_id": "export-host", "destination": self.destination},
        }
        path = self.root / "execution.json"
        path.write_bytes(encode(inputs))
        runtime = ExecutionRuntime(
            binding=binding,
            pins=self.binding["pins"],
            source={"path": str(path), "sha256": sha(path.read_bytes())},
            journal=FileJournal(self.root / "execution", {}, initialize=True),
            clock=lambda: 100,
            components={"export_host": self.remote},
        )
        factory = SimpleNamespace(
            binding=binding,
            config={"pins": self.binding["pins"], "execution_runtime": runtime},
            port=SimpleNamespace(deadline=lambda *a, **kw: None),
        )
        return runtime, factory

    def test_runtime_proxy_joins_actual_stage_and_reverify_receipts(self):
        runtime, factory = self.runtime()
        result = runtime.dependency("export_host_stage_fixture", factory)(self.request)
        join_execution(result, factory, "export_host_stage_fixture")
        result = runtime.dependency("export_host_reverify_fixture", factory)(self.request)
        join_execution(result, factory, "export_host_reverify_fixture")
        self.assertEqual(result["actual_inventory"], self.request["expected_inventory"])

    def test_runtime_proxy_refuses_different_destination_before_sending(self):
        runtime, factory = self.runtime()
        request = {**self.request, "destination": {**self.destination, "node_uid": "foreign"}}
        with self.assertRaisesRegex(ValueError, "host_destination"):
            runtime.dependency("export_host_stage_fixture", factory)(request)
        self.assertEqual(self.count, 0)

    @unittest.skipUnless(
        os.name == "posix" and os.environ.get("INF037B_EKS_HOST_TEST") == "1",
        "real POSIX fixture staging runs on the AWS CPU host",
    )
    def test_real_posix_stage_and_independent_hash_readback(self):
        self.executor.stage = stage_fixture
        result = self.executor.effect("eks.host.stage", "posix", self.request)
        self.assertTrue(result["verified"])
        self.assertEqual(
            fixture_inventory(self.destination["mount_path"]), self.request["expected_inventory"]
        )


@unittest.skipUnless(
    os.name == "posix" and os.environ.get("INF037B_EKS_HOST_TEST") == "1",
    "real two-store/resume/readback runs on the AWS CPU host",
)
class RealStoreHostTests(unittest.TestCase):
    def test_real_socket_resume_and_both_store_readbacks(self):
        from test_inf037b_transfer import S3_URL, TransferIntegrationTests

        self.assertTrue(S3_URL, "host readiness must bind the real secured S3-compatible endpoint")
        suite = unittest.TestSuite(
            [TransferIntegrationTests("test_capture_tcp_resume_both_stores_retrieve_and_reopen")]
        )
        result = unittest.TestResult()
        suite.run(result)
        self.assertEqual(result.testsRun, 1)
        self.assertFalse(result.skipped)
        self.assertFalse(result.errors, result.errors)
        self.assertFalse(result.failures, result.failures)
