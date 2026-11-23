"""R581 freeze progress, deadlines and wire compatibility."""

import hashlib
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from inference_platform.package_a_cloud import EXPORT_MAX_BYTES, transfer_seconds
from inference_platform.package_a_operator import Ports
from inference_platform.r1_cloud_operator import Operator
from package_a_host import Host, server


class FrozenArchiveTests(unittest.TestCase):
    def retrieve(self, root, *, synchronous=False, limit_seconds=3000):
        ports = Ports.__new__(Ports)
        ports.runtime = root
        ports.status_answered = True
        ports.host = "fixture"
        ports.manifest = {"role": "routine_tests"}
        now, ready = 1000, 1211
        deadlines = []
        payload = b"frozen fixture"
        digest = hashlib.sha256(payload).hexdigest()

        def sleep(seconds):
            nonlocal now
            now += seconds

        def request(path, data=None, *, end):
            deadlines.append((path, end))
            if path == "/freeze":
                if synchronous and end < ready:
                    sleep(end - now)
                    raise TimeoutError("legacy synchronous archive")
                reply = (
                    {"state": "archiving", "bytes_written": 3}
                    if now < ready
                    else {
                        "state": "ready",
                        "bytes": len(payload),
                        "sha256": digest,
                        "freeze_elapsed_s": 211,
                    }
                )
                return json.dumps(reply).encode(), {}
            self.assertEqual(path, "/archive/0")
            return payload, {"X-Chunk-SHA256": digest}

        ports.request = request
        absolute_end = now + limit_seconds
        with (
            patch("inference_platform.package_a_operator.time.time", lambda: now),
            patch("inference_platform.package_a_operator.time.sleep", sleep),
        ):
            value = ports.retrieve(absolute_end)
        self.assertTrue(all(end <= absolute_end for _, end in deadlines))
        self.assertEqual(json.loads((root / "retrieval.json").read_bytes()), value)
        return value, deadlines

    def test_archive_ready_after_211_seconds_uses_actual_transfer_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            result, deadlines = self.retrieve(Path(tmp))
            self.assertTrue(result["complete"])
            self.assertEqual(result["freeze_elapsed_s"], 211)
            self.assertEqual(result["archive_bytes"], 14)
            self.assertEqual(
                (Path(tmp) / "receipts.tar.gz").read_bytes(), b"frozen fixture"
            )
            self.assertEqual(
                deadlines[0], ("/freeze", 1000 + transfer_seconds(EXPORT_MAX_BYTES))
            )
            self.assertEqual(
                deadlines[1], ("/freeze", 1000 + transfer_seconds(512 * 1024**2))
            )
            self.assertEqual(deadlines[-1], ("/archive/0", 1211 + transfer_seconds(14)))

    def test_mutation_synchronous_freeze_refuses_at_196_seconds(self):
        with tempfile.TemporaryDirectory() as tmp:
            result, deadlines = self.retrieve(Path(tmp), synchronous=True)
            self.assertFalse(result["complete"])
            self.assertEqual(result["reason"], "freeze_unanswered")
            self.assertEqual(result["freeze_elapsed_s"], 196)
            self.assertEqual(len(deadlines), 1)

    def test_pending_archive_never_borrows_cleanup_time(self):
        with tempfile.TemporaryDirectory() as tmp:
            result, deadlines = self.retrieve(Path(tmp), limit_seconds=200)
            self.assertEqual(result["reason"], "archive_write_deadline")
            self.assertEqual(result["freeze_elapsed_s"], 200)
            self.assertTrue(all(path == "/freeze" for path, _ in deadlines))

    def test_http_progress_bypasses_host_lock_and_starts_only_one_build(self):
        with tempfile.TemporaryDirectory() as tmp:
            host = Host(tmp, "fixture-control", "unused", time.time() + 60)
            host.manifest = {"role": "routine_tests"}
            building = threading.Event()
            release = threading.Event()
            builds = []
            real_write = host._write_archive

            def write(path, entries, **kwargs):
                builds.append(1)
                path.write_bytes(b"progress")
                building.set()
                if not release.wait(5):
                    raise TimeoutError("fixture_release")
                return real_write(path, entries, **kwargs)

            with patch.object(host, "_write_archive", side_effect=write):
                http = server(host, port=0)
                worker = threading.Thread(target=http.serve_forever, daemon=True)
                worker.start()
                ports = Ports.__new__(Ports)
                ports.deadline = time.time() + 10

                def rpc(path):
                    return json.loads(
                        Operator.rpc(ports, http.server_address[1], path, host.token)[0]
                    )

                try:
                    self.assertEqual(rpc("/freeze")["state"], "archiving")
                    self.assertTrue(building.wait(2))
                    with host.lock:
                        self.assertEqual(rpc("/status")["freeze"]["bytes_written"], 8)
                        self.assertEqual(rpc("/freeze")["state"], "archiving")
                    release.set()
                    end = time.monotonic() + 2
                    meta = rpc("/freeze")
                    while meta["state"] == "archiving" and time.monotonic() < end:
                        time.sleep(0.01)
                        meta = rpc("/freeze")
                    self.assertEqual(meta["state"], "ready")
                    self.assertEqual(rpc("/status")["freeze"], meta)
                    self.assertEqual(builds, [1])
                finally:
                    release.set()
                    http.shutdown()
                    http.server_close()
                    worker.join()

    def test_build_failure_is_a_stable_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            host = Host(tmp, "fixture-control", "unused", time.time() + 60)
            host.manifest = {"role": "routine_tests"}
            with patch.object(host, "_build_archive", side_effect=OSError) as build:
                meta = host.start_freeze()
                end = time.monotonic() + 2
                while meta["state"] == "archiving" and time.monotonic() < end:
                    time.sleep(0.01)
                    meta = host.start_freeze()
                self.assertEqual(meta["state"], "failed")
                self.assertEqual(meta["reason"], "archive_build_failed")
                self.assertEqual(host.status()["freeze"], meta)
                build.assert_called_once()
