import gzip
import hashlib
import json
import socket
import tempfile
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Event, Lock, Thread
from types import SimpleNamespace
from unittest.mock import patch

from inference_platform.archive_transfer import CHUNK_BYTES, export_window
from inference_platform.stage_c_session import reply_archive_file
from inference_platform.stage_c_transport import (
    ReconnectingTransport,
    fetch_run,
    monitor_and_export,
)


class ArchiveTransferTest(unittest.TestCase):
    def test_delayed_forward_with_command_channel_resumes_and_starts_from_none(self):
        for initially_up in (True, False):
            with self.subTest(initially_up=initially_up):
                self._assert_delayed_forward(initially_up)

    def _assert_delayed_forward(self, initially_up):
        data = b"x" * (3 * CHUNK_BYTES + 123)
        receipt = {"run_number": 1, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "source"
            archive.write_bytes(data)
            ranges, forwards, channel_calls = [], [], []
            disconnected = [False]

            class Handler(BaseHTTPRequestHandler):
                def log_message(self, *_):
                    pass

                def do_GET(self):  # noqa: N802
                    if self.path == "/status":
                        self.send_response(200)
                        self.send_header("Content-Length", "2")
                        self.end_headers()
                        self.wfile.write(b"{}")
                        return
                    start = int(self.headers["Range"].split("=")[1].split("-")[0])
                    ranges.append(start)
                    if initially_up and start == CHUNK_BYTES and not disconnected[0]:
                        disconnected[0] = True
                        self.send_response(206)
                        end = start + CHUNK_BYTES - 1
                        self.send_header("Content-Range", f"bytes {start}-{end}/{len(data)}")
                        self.send_header("Content-Length", str(CHUNK_BYTES))
                        self.end_headers()
                        self.wfile.write(data[start : start + 1024])
                        self.close_connection = True
                        return
                    reply_archive_file(self, archive)

            class Forward:
                returncode = None

                def __init__(self, delay):
                    with socket.socket() as reservation:
                        reservation.bind(("127.0.0.1", 0))
                        self.address = reservation.getsockname()
                    self.server = ThreadingHTTPServer(
                        self.address, Handler, bind_and_activate=False
                    )
                    self.cancel, self.ready = Event(), Event()
                    self.bind_lock = Lock()
                    self.bind_seconds = None

                    def listen():
                        started = time.perf_counter()
                        if self.cancel.wait(delay):
                            return
                        with self.bind_lock:
                            if self.cancel.is_set():
                                return
                            self.server.server_bind()
                            self.server.server_activate()
                            self.bind_seconds = time.perf_counter() - started
                            self.ready.set()
                        self.server.serve_forever()

                    self.thread = Thread(target=listen, daemon=True)
                    self.thread.start()

                def poll(self):
                    return self.returncode

                def close(self):
                    with self.bind_lock:
                        self.cancel.set()
                    if self.ready.is_set():
                        self.server.shutdown()
                    self.thread.join(timeout=6)
                    self.server.server_close()
                    self.returncode = 0

            def start_forward():
                child = Forward(0 if initially_up and not forwards else 5)
                forwards.append(child)
                obj.base = f"http://127.0.0.1:{child.address[1]}"
                return child

            def channel_request(path, deadline, *, transport):
                channel_calls.append(path)
                time.sleep(2)
                return b"{}"

            obj = ReconnectingTransport(
                start_forward,
                "unused",
                "test",
                time.perf_counter() + 645,
                [],
                stop=lambda child: child.close(),
                command_channel=SimpleNamespace(request=channel_request),
                # Archive recovery must work after the measurement cutoff too.
                live_deadline=time.perf_counter() - 1,
            )
            try:
                if initially_up:
                    obj.launch_forward()
                    self.assertTrue(obj.forward.ready.wait(2))
                    obj.forward_ready = True
                fetch_run(obj, Path(directory), receipt)
                target = Path(directory) / "sealed-runs/run-1.tar.gz"
                self.assertEqual(hashlib.sha256(target.read_bytes()).hexdigest(), receipt["sha256"])
                transfer = json.loads(target.with_name("run-1.transfer.json").read_text())
                self.assertTrue(transfer["sha256_verified"])
                self.assertEqual(transfer["forwards_started"], 1)
                self.assertEqual(len(forwards), 2 if initially_up else 1)
                self.assertGreaterEqual(forwards[-1].bind_seconds, 5)
                self.assertEqual(channel_calls, [])
                if initially_up:
                    self.assertTrue(disconnected[0])
                    self.assertEqual(
                        ranges, [0, CHUNK_BYTES, CHUNK_BYTES, 2 * CHUNK_BYTES, 3 * CHUNK_BYTES]
                    )
            finally:
                obj.close()

    def test_command_status_preserves_forward_during_startup_grace(self):
        tick, stopped, calls = [0.0], [], []
        child = SimpleNamespace(poll=lambda: None)

        def request(*args):
            if tick[0] < 5:
                raise OSError("listener still starting")
            return b"{}"

        def command(path, deadline, *, transport):
            calls.append(path)
            tick[0] += 2
            return b"{}"

        obj = ReconnectingTransport(
            lambda: child,
            "unused",
            "test",
            90,
            [],
            clock=lambda: tick[0],
            request=request,
            stop=stopped.append,
            command_channel=SimpleNamespace(request=command),
        )
        self.assertEqual(obj.get("/status"), b"{}")
        self.assertIs(obj.forward, child)
        tick[0] = 5
        self.assertEqual(obj.get("/status"), b"{}")
        self.assertTrue(obj.forward_ready)
        self.assertEqual(obj.forwards_started, 1)
        self.assertEqual(stopped, [])
        self.assertEqual(calls, ["/status"])

    def test_failed_archive_restarts_back_off_without_command_calls(self):
        tick, pauses, channel_calls = [0.0], [], []

        def sleep(seconds):
            pauses.append(seconds)
            tick[0] += seconds

        def request(path, timeout, **kwargs):
            if path == "/status":
                return b"{}"
            raise OSError("disconnected")

        obj = ReconnectingTransport(
            lambda: SimpleNamespace(poll=lambda: None),
            "unused",
            "test",
            620,
            [],
            clock=lambda: tick[0],
            sleep=sleep,
            request=request,
            stop=lambda child: None,
            command_channel=SimpleNamespace(request=lambda *a, **k: channel_calls.append(a)),
        )
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(OSError, "resumable offset"):
                fetch_run(obj, Path(directory), {"run_number": 1, "bytes": 3, "sha256": "unused"})
        self.assertEqual(pauses, [1, 2, 4, 8, 5])
        self.assertEqual(obj.forwards_started, 5)
        self.assertEqual(channel_calls, [])

    def test_real_range_server_validates_ranges_and_exact_response(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "archive"
            path.write_bytes(b"0123456789")

            class Handler(BaseHTTPRequestHandler):
                def log_message(self, *_):
                    pass

                def do_GET(self):  # noqa: N802
                    reply_archive_file(self, path)

            server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            thread = Thread(target=server.serve_forever)
            thread.start()
            transport = ReconnectingTransport(
                None, f"http://127.0.0.1:{server.server_port}", "test", time.perf_counter() + 20, []
            )
            try:
                self.assertEqual(
                    transport.http_request("/run/1", 5, headers={"Range": "bytes=2-5"}), b"2345"
                )
                for header in ("bytes=2-99", "bytes=4-2", "bytes=1-2,4-5", "bytes=-2"):
                    with self.assertRaises(OSError):
                        transport.http_request("/run/1", 5, headers={"Range": header})
            finally:
                server.shutdown()
                server.server_close()
                thread.join()

    def test_persisted_offset_survives_deadline_and_new_controller(self):
        data = b"x" * (CHUNK_BYTES * 2 + 500)
        receipt = {"run_number": 1, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        with tempfile.TemporaryDirectory() as directory:
            tick, ranges = [0.0], []

            def request(path, timeout, *, headers=None):
                start, end = map(int, headers["Range"].removeprefix("bytes=").split("-"))
                ranges.append(start)
                tick[0] += 2
                return data[start : end + 1]

            def transport(deadline):
                obj = ReconnectingTransport(
                    lambda: SimpleNamespace(poll=lambda: None),
                    "unused",
                    "test",
                    deadline,
                    [],
                    clock=lambda: tick[0],
                    sleep=lambda seconds: tick.__setitem__(0, tick[0] + seconds),
                    request=request,
                )
                obj.forward = SimpleNamespace(poll=lambda: None)
                obj.forward_ready = True
                return obj

            with self.assertRaisesRegex(OSError, "resumable offset"):
                fetch_run(transport(602), Path(directory), receipt)
            progress = json.loads((Path(directory) / "sealed-runs/run-1.progress.json").read_text())
            self.assertEqual(progress["offset"], CHUNK_BYTES)
            # Emulate a crash between writing and acknowledging the next chunk.
            with (Path(directory) / "sealed-runs/run-1.tar.pending").open("ab") as stream:
                stream.write(b"unacknowledged")
            fetch_run(transport(900), Path(directory), receipt)
            self.assertEqual(ranges, [0, CHUNK_BYTES, 2 * CHUNK_BYTES])
            self.assertEqual((Path(directory) / "sealed-runs/run-1.tar.gz").read_bytes(), data)
            self.assertFalse((Path(directory) / "sealed-runs/run-1.progress.json").exists())

    def test_final_sha_rejects_same_size_corruption(self):
        with tempfile.TemporaryDirectory() as directory:
            obj = ReconnectingTransport(
                None,
                "unused",
                "test",
                time.perf_counter() + 900,
                [],
                request=lambda *args, **kwargs: b"bad",
            )
            obj.forward, obj.forward_ready = SimpleNamespace(poll=lambda: None), True
            with self.assertRaisesRegex(ValueError, "checksum"):
                fetch_run(
                    obj,
                    Path(directory),
                    {"run_number": 1, "bytes": 3, "sha256": hashlib.sha256(b"yes").hexdigest()},
                )
            self.assertFalse((Path(directory) / "sealed-runs/run-1.tar.gz").exists())

    def test_no_archive_request_until_finished_and_disk_records_use_status(self):
        data = b"archive"
        digest = gzip.compress(b"{}")
        final = b"metadata"
        receipt = {
            "run_number": 1,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "measurement_digest": {
                "bytes": len(digest),
                "sha256": hashlib.sha256(digest).hexdigest(),
            },
        }
        polls, calls, tick = [0], [], [0.0]

        def request(path, timeout, *, headers=None):
            calls.append((path, polls[0]))
            if path == "/status":
                polls[0] += 1
                return json.dumps(
                    {
                        "started": True,
                        "finished": polls[0] >= 3,
                        "completed_runs": [receipt],
                        "disk_records": {"disk-readiness.json": {"status": "available"}},
                        "sampled_root_minimum_free_bytes": 123,
                    }
                ).encode()
            if path == "/digest/1":
                return digest
            if path == "/run/1":
                self.assertGreaterEqual(polls[0], 3)
                return data
            if path == "/receipt":
                return json.dumps({"sha256": hashlib.sha256(final).hexdigest()}).encode()
            if path == "/export":
                return final
            self.fail(path)

        obj = ReconnectingTransport(
            lambda: SimpleNamespace(poll=lambda: None),
            "unused",
            "test",
            900,
            [],
            request=request,
            clock=lambda: tick[0],
            sleep=lambda s: tick.__setitem__(0, tick[0] + s),
        )
        with tempfile.TemporaryDirectory() as directory:
            outcome = {}
            monitor_and_export(obj, Path(directory), outcome)
            self.assertEqual(
                outcome["archive_export_window"]["archive_bytes_during_measurement"], 0
            )
            self.assertLess(
                [c[0] for c in calls].index("/run/1"), [c[0] for c in calls].index("/export")
            )
            self.assertEqual(
                json.loads((Path(directory) / "sampled-root-minimum.json").read_text())[
                    "free_bytes"
                ],
                123,
            )

    def test_size_derived_export_reserve_shortens_later_measurement_cutoff(self):
        self.assertEqual(export_window(300_000_000), 1800)
        for invalid in (-1, True, 1.5):
            with self.assertRaises(ValueError):
                export_window(invalid)
        # Actual scheduling integration: no fixture changes to the run budgets.
        from inference_platform.stage_c import StageCConfig, run_stage_c

        ready = time.time() - 1
        config = StageCConfig(
            url="http://unused",
            token="test",
            tenant_id="test",
            model="test",
            run_id="reserve",
            reset_url="http://unused",
            tokenize_url="http://unused",
            instance_boot_unix_s=ready - 2015,
            instance_termination_unix_s=ready - 2015 + 14400,
            observed_readiness_unix_s=ready,
        )
        with (
            patch(
                "inference_platform.stage_c._runtime_readiness",
                return_value={"status": "passed", "checks": {}},
            ),
            patch("inference_platform.stage_c._run_saturation"),
            patch("inference_platform.stage_c._run_reference_capacity"),
            patch("inference_platform.stage_c._run_rewarm"),
        ):
            result = run_stage_c(
                config,
                on_run_complete=lambda n, run: {
                    "archive_export_window": {"forecast_seconds": 10000}
                },
            )
        second = result["timed_runs"][1]
        self.assertTrue(second["deadline_capped_by_session"])
        self.assertLess(second["available_session_seconds_at_start"], 2000)
        self.assertEqual(
            result["configuration"]["run_time_budgets_seconds"], [3000, 2700, 1800, 3600]
        )
