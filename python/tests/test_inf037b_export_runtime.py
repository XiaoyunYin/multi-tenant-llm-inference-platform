"""Production export cache refusals and operation-return durability barriers."""

import copy
import os
import shutil
import signal
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import test_inf037b_collectors as fixtures

from inference_platform import inf037b_archive as archive
from inference_platform import inf037b_campaign as campaign
from inference_platform import inf037b_export_runtime as runtime
from inference_platform import inf037b_packet as packet


@unittest.skipUnless(sys.platform == "linux", "requires real Linux directory fsync and procfs")
class ExportRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def fixture(self, name="raw"):
        fixture, _ = fixtures.CampaignTests.campaign(SimpleNamespace(root=self.root), name=name)
        return fixture.root, [fixture.spec]

    def test_unbatched_write_is_immediately_synced(self):
        with patch.object(os, "fsync", wraps=os.fsync) as calls:
            archive.durable_write(self.root / "ordinary-write", b"durable")
        self.assertEqual(calls.call_count, 1)
        self.assertIsNone(runtime._batch.get())

    def test_report_fresh_bytes_spec_and_mutable_result(self):
        raw, specs = self.fixture()

        @runtime.export_memoization
        def exercise():
            instance = campaign.OfflineCampaign(raw, specs[0])
            with patch.object(instance, "_report", wraps=instance._report) as calls:
                original = copy.deepcopy(instance.report())
                instance.report()["validity_reasons"].append("poison")
                self.assertEqual(instance.report(), original)
                self.assertEqual(calls.call_count, 1)
                # Reports read top-level raw JSONL, not derived receipts. Archive
                # verification separately covers *all* files and directories.
                (raw / "raw/unused.receipt.json").write_bytes(b"derived")
                self.assertEqual(instance.report(), original)
                self.assertEqual(calls.call_count, 1)
                instance.spec = {**specs[0], "target_uid": "changed"}
                self.assertEqual(instance.report()["target_uid"], "changed")
                self.assertEqual(calls.call_count, 2)
                campaign.OfflineCampaign(raw, specs[0]).start_attempt(
                    0, absolute_deadline_ms=6_000_000, export_cleanup_ms=0
                )
                instance.report()
                self.assertEqual(calls.call_count, 3)
                self.assertTrue(instance.journal.events)
                path = raw / "raw/client.jsonl"
                before = path.stat()
                data = path.read_bytes()
                # Same length and mtime must not reuse a report.
                path.write_bytes(data.replace(b'"schema_version":1', b'"schema_version":9', 1))
                os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
                with self.assertRaises(archive.IntegrityError):
                    instance.report()

        exercise()
        self.assertIsNone(runtime._memo.get())

    def test_verify_fresh_hash_inventory_and_known_files(self):
        raw, specs = self.fixture()
        campaign.materialize_bundle(raw, specs)

        @runtime.export_memoization
        def exercise():
            with patch.object(archive, "_verify_archive", wraps=archive._verify_archive) as calls:
                saved = copy.deepcopy(archive.verify_archive(raw))
                archive.verify_archive(raw)["segments"].clear()
                self.assertEqual(archive.verify_archive(raw), saved)
                self.assertEqual(calls.call_count, 1)
                with self.assertRaisesRegex(archive.IntegrityError, "archive_inventory_mismatch"):
                    archive.verify_archive(raw, known_files={})
                empty = raw / "events/empty"
                empty.mkdir()
                archive.verify_archive(raw)
                self.assertEqual(calls.call_count, 2)
                empty.rmdir()
                extra = raw / "extra"
                extra.write_bytes(b"extra")
                with self.assertRaisesRegex(archive.IntegrityError, "archive_inventory_mismatch"):
                    archive.verify_archive(raw)
                extra.unlink()
                path = raw / "registration.json"
                before = path.stat()
                path.write_bytes(path.read_bytes().replace(b"inf037b-v4-r315", b"inf037b-v9-r315"))
                os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
                with self.assertRaisesRegex(archive.IntegrityError, "hash_mismatch"):
                    archive.verify_archive(raw)

        exercise()

    def test_input_change_during_computation_refuses_and_is_not_saved(self):
        @runtime.export_memoization
        def exercise():
            for namespace in ("report", "verify"):
                values = iter(({"hash": 1}, {"hash": 2}))
                with self.assertRaisesRegex(archive.IntegrityError, "memoization_input_changed"):
                    runtime.fresh_result(
                        (namespace,), lambda values=values: next(values), lambda: {}
                    )
                self.assertNotIn((namespace,), runtime._memo.get())

        exercise()

    def test_cache_scope_exception_bound_and_symlink_refusal(self):
        @runtime.export_memoization
        def exercise():
            for i in range(20):
                runtime.fresh_result((i,), lambda: {}, lambda: {})
            self.assertEqual(len(runtime._memo.get()), 8)
            path = self.root / "link"
            path.symlink_to(self.root, target_is_directory=True)
            with self.assertRaisesRegex(archive.IntegrityError, "memoization_symlink_input"):
                runtime.inventory(self.root)
            raise RuntimeError("scope failure")

        with self.assertRaisesRegex(RuntimeError, "scope failure"):
            exercise()
        self.assertIsNone(runtime._memo.get())

    def operation(self, kind, source, target, specs):
        if kind == "sanitize":
            return packet.sanitized_sources(source, target, key=b"production-test-key" * 2)
        return campaign.materialize_bundle(target, specs)

    def test_operations_sync_every_file_and_directory_once_before_return(self):
        raw, specs = self.fixture()
        campaign.materialize_bundle(raw, specs)
        real_sync = os.fsync
        for kind in ("sanitize", "materialize"):
            target = self.root / "nested" / kind if kind == "sanitize" else self.root / kind
            if kind == "materialize":
                unsealed, _ = self.fixture("unsealed")
                shutil.copytree(unsealed, target)
            seen = []
            before_files = {p: archive.file_facts(p) for p in target.rglob("*") if p.is_file()}

            def sync(fd, seen=seen):
                seen.append(Path(os.readlink(f"/proc/self/fd/{fd}")))
                real_sync(fd)

            with patch.object(os, "fsync", sync):
                self.operation(kind, raw, target, specs)
            expected_files = {
                p
                for p in target.rglob("*")
                if p.is_file() and before_files.get(p) != archive.file_facts(p)
            }
            self.assertTrue(expected_files <= set(seen))
            duplicates = {path for path in seen if seen.count(path) > 1}
            self.assertEqual(duplicates, {target} if kind == "materialize" else set())
            if kind == "materialize":
                self.assertEqual(seen.count(target), 2)
            directories = {p.parent for p in expected_files}
            if kind == "sanitize":
                directories.update({target.parent.parent, target.parent, target / "events"})
            self.assertTrue(directories <= set(seen))
            self.assertIsNone(runtime._batch.get())

    def test_seal_syncs_archived_files_and_folders_before_manifest(self):
        real_sync = os.fsync
        seen = []

        def sync(fd):
            seen.append(Path(os.readlink(f"/proc/self/fd/{fd}")))
            real_sync(fd)

        with patch.object(os, "fsync", sync):
            unsealed, specs = self.fixture("seal-order")
            manifest = unsealed / "SHA256SUMS"
            real_verify = archive.verify_archive

            def verify_with_immediate_seal(root, **kwargs):
                if root == unsealed:
                    self.assertIn(manifest, seen)
                return real_verify(root, **kwargs)

            with patch.object(archive, "verify_archive", side_effect=verify_with_immediate_seal):
                campaign.materialize_bundle(unsealed, specs)

        manifest_index = seen.index(manifest)
        sealed_files = {
            unsealed / line.split("  ", 1)[1] for line in manifest.read_text().splitlines()
        }
        sealed_folders = {path for path in unsealed.rglob("*") if path.is_dir()}
        before_manifest = set(seen[:manifest_index])
        self.assertTrue(sealed_files <= before_manifest)
        self.assertTrue(sealed_folders <= before_manifest)
        self.assertEqual(seen.count(manifest), 1)
        self.assertEqual(seen[-1], unsealed)

    def test_operations_propagate_file_and_directory_durability_failure(self):
        raw, specs = self.fixture()
        campaign.materialize_bundle(raw, specs)
        real_sync = os.fsync
        for kind in ("sanitize", "materialize"):
            for directory in (False, True):
                target = self.root / f"{kind}-{directory}"
                if kind == "materialize":
                    unsealed, _ = self.fixture(f"source-{directory}")
                    shutil.copytree(unsealed, target)

                def sync(fd, directory=directory):
                    if stat.S_ISDIR(os.fstat(fd).st_mode) == directory:
                        raise OSError("injected durability failure")
                    real_sync(fd)

                with patch.object(os, "fsync", sync):
                    with self.assertRaisesRegex(OSError, "injected durability failure"):
                        self.operation(kind, raw, target, specs)
                self.assertIsNone(runtime._batch.get())

    def test_batch_exception_and_nested_operations_flush_their_own_writes(self):
        path = self.root / "partial"

        @runtime.batched_durability
        def inner():
            archive.durable_write(path, b"first")

        @runtime.batched_durability
        def outer():
            inner()
            archive.durable_write(path, b"second", "ab")
            raise ValueError("body refused")

        with patch.object(runtime, "synchronize", wraps=runtime.synchronize) as calls:
            with self.assertRaisesRegex(ValueError, "body refused"):
                outer()
        self.assertEqual(calls.call_count, 2)
        self.assertIsNone(runtime._batch.get())

    def test_sigkill_at_each_operation_barrier_never_acknowledges_return(self):
        # Parent cuts the child *before* each real file/directory syscall. The
        # uncut trace must include every output and parent; a missing final sync
        # is caught by the independent inventory assertion above.
        raw, specs = self.fixture()
        unsealed = self.root / "unsealed"
        shutil.copytree(raw, unsealed)
        campaign.materialize_bundle(raw, specs)
        for kind in ("sanitize", "materialize"):
            barriers = None
            cut = 0
            while barriers is None or cut <= barriers:
                target = self.root / f"cut-{kind}-{cut}"
                if kind == "materialize":
                    shutil.copytree(unsealed, target)
                from multiprocessing import Pipe

                parent, child = Pipe()
                pid = os.fork()
                if pid == 0:
                    parent.close()
                    real_sync = os.fsync

                    def sync(fd, child=child, real_sync=real_sync):
                        child.send("barrier")
                        child.recv()
                        real_sync(fd)

                    try:
                        with patch.object(os, "fsync", sync):
                            self.operation(kind, raw, target, specs)
                        child.send("returned")
                        os._exit(0)
                    except BaseException:
                        os._exit(3)
                child.close()
                count = 0
                returned = False
                killed = False
                try:
                    while True:
                        self.assertTrue(parent.poll(15), "child barrier timed out")
                        message = parent.recv()
                        if message == "returned":
                            returned = True
                            break
                        count += 1
                        if cut and count == cut:
                            os.kill(pid, signal.SIGKILL)
                            killed = True
                            break
                        parent.send("continue")
                finally:
                    if not returned and not killed:
                        os.kill(pid, signal.SIGKILL)
                    _, status = os.waitpid(pid, 0)
                    parent.close()
                if cut == 0:
                    self.assertTrue(returned)
                    self.assertEqual(status, 0)
                    barriers = count
                    self.assertGreater(barriers, 0)
                else:
                    self.assertFalse(returned)
                    self.assertEqual(os.WTERMSIG(status), signal.SIGKILL)
                cut += 1


class WindowsPacketSyncCompatibilityTests(unittest.TestCase):
    def test_windows_local_sync_uses_writable_file_handles_and_skips_directory_fsync(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            child = root / "child"
            child.mkdir()
            source = child / "fixture.bin"
            source.write_bytes(b"packet-input")
            with (
                patch.object(os, "fsync", wraps=os.fsync) as sync_file,
                patch.object(os, "open", side_effect=AssertionError("directory fsync")),
            ):
                runtime.synchronize({source}, {child, root}, platform_name="nt")
            self.assertEqual(sync_file.call_count, 1)
            self.assertEqual(source.read_bytes(), b"packet-input")
