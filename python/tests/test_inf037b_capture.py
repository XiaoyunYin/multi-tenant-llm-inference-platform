"""Actual loopback sockets and durable collector ownership; no cloud claims."""

import copy
import os
import socket
import subprocess
import sys
import threading
import time
import unittest
from http.client import IncompleteRead
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from inference_platform.inf037b_archive import (
    IntegrityError,
    encode,
    sha,
    strict_json,
    verify_archive,
)
from inference_platform.inf037b_capture import CaptureOwner, DeadlineHTTP, wire_records
from inference_platform.inf037b_durable_ports import DurableStore
from inference_platform.inf037b_lifecycle import ProcessCalls
from inference_platform.inf037b_live import (
    ClientSSEAdapter,
    ClockAdapter,
    KubernetesAdapter,
    LifecycleReceiptProducer,
    RedisWire,
    WatchCutoff,
)
from inference_platform.inf037b_producer_limits import CLIENT_DENIAL_BYTES, ProducerLimit


@unittest.skipUnless(os.name == "posix", "durable Linux capture")
class CaptureTests(unittest.TestCase):
    def test_durable_protocol_units_preserve_interleaved_raw_bytes_and_readback(self):
        from inference_platform.inf037b_wire_units import UnitRecorder

        with TemporaryDirectory() as directory:
            owner = self.owner(Path(directory))
            retain = owner.retainer("clock")
            first, second = UnitRecorder(retain, kind="body"), UnitRecorder(retain, kind="body")
            first.feed(0, 1, b"a")
            second.feed(1, 2, b"x")
            first.feed(2, 3, b"b")
            second.finish()
            first.finish()
            owner.barrier("clock")
            records = list(wire_records(owner.root / "wire"))
            self.assertEqual([b for _, b in records], [b"ab", b"x"])
            self.assertEqual(Path(owner.wire["clock"]["data"].name).read_bytes(), b"axb")
            self.assertEqual([r["read_count"] for r, _ in records], [2, 1])
            self.assertTrue(owner.close()["transport_clean"])
        with TemporaryDirectory() as directory:
            owner = self.owner(Path(directory))
            unit = UnitRecorder(owner.retainer("clock"), kind="body")
            unit.feed(4, 5, b"unfinished")
            result = owner.close()
            self.assertFalse(result["transport_clean"])
            self.assertIn("capture:uncompleted_protocol_unit:clock", result["losses"])
            records = list(wire_records(owner.root / "wire"))
            self.assertEqual(
                [(r["metadata"]["unit"], b) for r, b in records], [("refusal", b"unfinished")]
            )

    def test_real_http_producer_refusal_keeps_rejected_tail_through_durable_close(self):
        body = b"x" * (CLIENT_DENIAL_BYTES + 1)

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                self.send_response(429)
                self.send_header("X-Request-ID", "gateway-request")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        with TemporaryDirectory() as directory:
            owner = self.owner(
                Path(directory),
                sources={"client": [["client", "client:gateway0", "kernel-boot"]]},
                budgets={"client": {"raw_bytes": 20000, "index_bytes": 20000, "records": 100}},
            )
            client = ClientSSEAdapter(
                owner.rows("client"), "gateway0", "a" * 64, retain=owner.retainer("client")
            )
            offer = {"request_id": "offer", "offer_index": 0, "prefix_id": "p", "scheduled_ms": 0}
            reason = "capture:producer:client_denial_bytes"
            with self.assertRaisesRegex(ProducerLimit, reason):
                client.request(
                    f"http://127.0.0.1:{server.server_port}/",
                    {},
                    offer,
                    credential="fixture",
                    local_test=True,
                )
            result = owner.close()
            self.assertFalse(result["transport_clean"])
            self.assertTrue(any(reason in loss for loss in result["losses"]))
            records = self.wire(owner)
            self.assertEqual(b"".join(r["body"] for r in records), body)
            self.assertTrue(any(r["metadata"].get("error") == reason for r in records))

    def test_group_barrier_watermarks_do_not_hold_owner_lock_or_lose_appends(self):
        with TemporaryDirectory() as directory:
            owner = self.owner(Path(directory))
            owner.retain("clock", 0, 1, b"before", {})
            owner.local_clock(owner.rows("clock"))
            owner.client_complete("clock", 0, 1, b"", {"client_request_end": True})
            entered, release = threading.Event(), threading.Event()
            errors = []
            fsync = os.fsync

            def blocked(fd):
                self.assertFalse(owner.lock._is_owned(), "fsync holds owner lock")
                if not entered.is_set():
                    entered.set()
                    self.assertTrue(release.wait(2))
                return fsync(fd)

            def barrier():
                try:
                    owner.group_barrier()
                except Exception as exc:
                    errors.append(exc)

            with patch("os.fsync", side_effect=blocked):
                worker = threading.Thread(target=barrier)
                worker.start()
                self.assertTrue(entered.wait(2))
                appended = threading.Event()

                def concurrent_append():
                    owner.retain("clock", 1, 2, b"during", {})
                    owner.local_clock(owner.rows("clock"))
                    owner.client_complete("clock", 1, 2, b"", {"client_request_end": True})
                    appended.set()

                writer = threading.Thread(target=concurrent_append)
                writer.start()
                try:
                    self.assertTrue(appended.wait(1), "append blocked behind fsync")
                finally:
                    release.set()
                    writer.join(2)
                    worker.join(2)
            self.assertEqual(errors, [])
            self.assertTrue(owner.archive_pending)
            self.assertEqual(len(owner.client_completions), 1)
            owner.group_barrier()
            self.assertEqual(owner.client_completions, [])
            self.assertFalse(owner.archive_pending)
            self.assertFalse(owner.wire["clock"]["pending"])
            with patch("os.fsync", side_effect=blocked):
                self.assertTrue(owner.close()["transport_clean"])
            records = self.wire(owner)
            self.assertEqual(b"".join(r["body"] for r in records), b"beforeduring")
            self.assertEqual(
                sum(r["metadata"].get("client_request_end", False) for r in records), 2
            )

    def test_owner_tick_settles_client_without_per_request_barrier(self):
        with TemporaryDirectory() as directory:
            owner = self.owner(Path(directory))
            settle_by = time.monotonic() + 5

            def client():
                owner.retain("kube", 0, 1, b"client", {})
                owner.client_complete("kube", 0, 1, b"", {"client_request_end": True})
                while time.monotonic() < settle_by:
                    # Wait for the barrier to finish, including the completion it drained.
                    if owner.io_lock.acquire(blocking=False):
                        try:
                            with owner.lock:
                                wire = owner.wire["kube"]
                                if (
                                    not owner.client_completions
                                    and not wire["pending"]
                                    and wire["barriers"]
                                ):
                                    return
                        finally:
                            owner.io_lock.release()
                    time.sleep(0.02)
                self.fail("owner did not settle the client completion before the deadline")

            with (
                patch("inference_platform.inf037b_capture.require_group_leader"),
                patch("os._exit", side_effect=IntegrityError("test_fenced")) as exit_process,
            ):
                descriptor = owner.run(
                    periodic=[],
                    watches={},
                    actions={"kube": client, "clock": lambda: None},
                    stop_ns=time.monotonic_ns() + 6_000_000_000,
                )
            exit_process.assert_not_called()
            self.assertTrue(descriptor["transport_clean"])
            self.assertTrue(owner.group_tick_intervals_ms)
            self.assertEqual(
                descriptor["client_group_ticks"]["count"], len(owner.group_tick_intervals_ms)
            )

    def test_owner_records_client_group_tick_gap_without_refusal(self):
        with TemporaryDirectory() as directory:
            owner = self.owner(Path(directory))
            group_barrier = owner.group_barrier
            first = [True]

            def stalled():
                if first[0]:
                    first[0] = False
                    time.sleep(0.35)
                group_barrier()

            with (
                patch("inference_platform.inf037b_capture.require_group_leader"),
                patch.object(owner, "group_barrier", side_effect=stalled),
            ):
                # No periodic slot is due: only the durability tick is stalled.
                with patch("os._exit", side_effect=IntegrityError("test_fenced")):
                    descriptor = owner.run(
                        periodic=[],
                        watches={},
                        actions={name: lambda: time.sleep(0.9) for name in owner.sources},
                        stop_ns=time.monotonic_ns() + 2_000_000_000,
                    )
            self.assertTrue(descriptor["transport_clean"])
            ticks = descriptor["client_group_ticks"]
            self.assertGreaterEqual(ticks["max_ms"], 300)
            self.assertGreaterEqual(ticks["p99_ms"], 300)
            self.assertGreaterEqual(ticks["over_250_ms"], 1)
            self.assertEqual(ticks["count"], len(owner.group_tick_intervals_ms))
            self.assertEqual(owner.store.read()["capture"]["client_group_ticks"], ticks)

    def test_group_tick_io_error_still_refuses(self):
        with TemporaryDirectory() as directory:
            owner = self.owner(Path(directory))
            barrier = owner.group_barrier
            first = [True]

            def broken():
                if first[0]:
                    first[0] = False
                    raise OSError("forced_barrier_io")
                barrier()

            with (
                patch("inference_platform.inf037b_capture.require_group_leader"),
                patch.object(owner, "group_barrier", side_effect=broken),
                patch("os._exit", side_effect=IntegrityError("test_fenced")),
            ):
                with self.assertRaisesRegex(
                    (OSError, IntegrityError), "forced_barrier_io|test_fenced"
                ):
                    owner.run(
                        periodic=[],
                        watches={},
                        actions={name: lambda: time.sleep(0.5) for name in owner.sources},
                        stop_ns=time.monotonic_ns() + 2_000_000_000,
                    )
            self.assertTrue(
                any("forced_barrier_io" in v for v in owner.store.read()["capture"]["losses"])
            )
            self.assertFalse(owner.close()["transport_clean"])

    def test_watch_read_cause_rule_covers_headers_and_body_without_masking_early_errors(self):
        http = DeadlineHTTP("https://example.invalid", stop_ns=10, retain=lambda *args: None)

        def fail(exc):
            raise exc

        for exc in (
            TimeoutError("deadline"),
            IncompleteRead(b""),
            ValueError("framing"),
        ):
            with self.subTest(exception=type(exc).__name__):
                with patch("inference_platform.inf037b_capture.time.monotonic_ns", return_value=9):
                    with self.assertRaises(type(exc)):
                        http.read(lambda exc=exc: fail(exc), watch=True)
                with patch("inference_platform.inf037b_capture.time.monotonic_ns", return_value=10):
                    if isinstance(exc, TimeoutError):
                        with self.assertRaisesRegex(WatchCutoff, "deadline"):
                            http.read(lambda exc=exc: fail(exc), watch=True)
                    else:
                        with self.assertRaises(type(exc)):
                            http.read(lambda exc=exc: fail(exc), watch=True)
                http.cutoff_event.set()
                with self.assertRaises(WatchCutoff) as caught:
                    http.read(lambda exc=exc: fail(exc), watch=True)
                self.assertEqual(str(caught.exception), str(exc))
                with self.assertRaises(type(exc)):
                    http.read(lambda exc=exc: fail(exc), watch=False)
                http.cutoff_event.clear()

    def owner(self, root, sources=None, attempt=1, budgets=None):
        boot_path = root / "boot"
        boot_path.write_text("kernel-boot")
        binding = {"session_id": "capture-session", "pins": {"source": "a" * 64}}
        if budgets is not None:
            binding["capture_budgets"] = budgets
        operation = {
            "operation": "capture",
            "key": "original-operation",
            "sequence": 7,
            "body": {"binding": binding},
        }
        sources = sources or {
            "clock": [["clocks", "clock:measurement", "kernel-boot"]],
            "kube": [["kubernetes", "kubernetes", "kernel-boot"]],
        }
        operation["body"]["capture"] = {
            "sources": sources,
            "attempt": attempt,
            "stages": [1, 2, 3, 4, 5],
            "boot_id": "kernel-boot",
        }
        operations = DurableStore(
            root / "operations",
            {"operations": {sha(encode([operation["operation"], operation["key"]])): operation}},
            initialize=True,
        )
        store = DurableStore(root / "capture-store", {}, initialize=True)
        owner = CaptureOwner(
            store=store,
            operation_store=operations,
            operation=operation,
            binding=binding,
            root=root / "retained",
            sources=sources,
            attempt=attempt,
            stages=[1, 2, 3, 4, 5],
            boot_path=boot_path,
        )
        # Test cases intentionally leave interrupted owners unsealed. Release
        # their descriptors without manufacturing a successful close record.
        for segment in owner.wire.values():
            for key in ("data", "index"):
                self.addCleanup(segment[key].close)
        return owner

    def server(self, respond):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                try:
                    respond(self)
                except (OSError, BrokenPipeError):
                    pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return "http://127.0.0.1:" + str(server.server_port)

    def wire(self, owner):
        records = []
        for source in owner.sources:
            if not owner.closed:
                owner.barrier(source)
        for path in (owner.root / "wire").glob("*.jsonl"):
            data = path.with_suffix(".bin").read_bytes()
            for line in path.read_bytes().splitlines():
                record = strict_json(line)
                body = data[record["offset"] : record["offset"] + record["length"]]
                self.assertEqual(sha(body), record["sha256"])
                record["body"] = body
                records.append(record)
        return sorted(records, key=lambda r: r["sequence"])

    def test_real_watch_retains_original_bytes_and_eof_loss_in_operation_store(self):
        raw = encode({"type": "BOOKMARK", "object": {"metadata": {"resourceVersion": "27"}}})
        paths = []

        def respond(handler):
            paths.append(handler.path)
            handler.send_response(200)
            handler.send_header("Content-Length", str(len(raw)))
            handler.end_headers()
            handler.wfile.write(raw)

        base = self.server(respond)
        with TemporaryDirectory() as directory:
            owner = self.owner(Path(directory))
            rows = owner.rows("kube")
            producer = LifecycleReceiptProducer()
            http = DeadlineHTTP(
                base,
                stop_ns=time.monotonic_ns() + 2_000_000_000,
                local_test=True,
                retain=owner.retainer("kube"),
            )
            adapter = KubernetesAdapter(rows, http, "fixture", slot_names={}, lifecycle=producer)
            owner.watch("kube", adapter, "26")
            self.assertIn("resourceVersion=26", paths[0])
            self.assertTrue(producer.lost)
            records = self.wire(owner)
            self.assertEqual(
                b"".join(r["body"] for r in records if not r["metadata"].get("normalized")),
                raw,
            )
            result = owner.close()
            self.assertFalse(result["transport_clean"])
            self.assertIn("kube:watch_disconnected", result["losses"])
            self.assertEqual(result["operation"], owner.operation)
            archived = verify_archive(owner.archive.root)
            self.assertEqual(archived["segments"]["raw/kubernetes.jsonl"]["row_count"], 1)
            for path, facts in result["files"].items():
                self.assertEqual(sha((owner.root / path).read_bytes()), facts["sha256"])

    def test_clock_continuity_boot_change_and_rejected_lineage_are_retained(self):
        with TemporaryDirectory() as directory:
            owner = self.owner(Path(directory))
            rows = owner.rows("clock")
            self.assertIs(rows, owner.rows("clock"))
            owner.local_clock(rows)
            self.assertEqual(owner.clock_rows[0]["source_generation"], "kernel-boot")
            with self.assertRaisesRegex(IntegrityError, "capture:lineage"):
                ClockAdapter(rows).mapping("measurement", "other-boot", 1, 1, 1, wall_ms=1)
            self.assertTrue(any(b"other-boot" in r["body"] for r in self.wire(owner)))
            owner.boot_path.write_text("reboot")
            with self.assertRaisesRegex(IntegrityError, "capture:boot_changed"):
                owner.local_clock(rows)
            self.assertFalse(owner.close()["transport_clean"])

    def test_operation_change_refuses_without_discarding_original_row(self):
        with TemporaryDirectory() as directory:
            owner = self.owner(Path(directory))
            with owner.operation_store.lock():
                state = owner.operation_store.read()
                state["operations"][owner.label]["sequence"] += 1
                owner.operation_store.write(state)
            with self.assertRaisesRegex(IntegrityError, "capture:operation_store"):
                owner.local_clock(owner.rows("clock"))
            with self.assertRaisesRegex(IntegrityError, "capture:operation_store"):
                owner.local_clock(owner.rows("clock"))
            self.assertTrue(self.wire(owner))
            self.assertEqual(len(self.wire(owner)), 2)
            self.assertTrue(owner.store.read()["capture"]["losses"])

    def test_interrupted_capture_is_not_retried_or_rebound(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            owner = self.owner(root)
            original = owner.store.read()
            with self.assertRaisesRegex(IntegrityError, "capture:interrupted_no_retry"):
                CaptureOwner(
                    store=owner.store,
                    operation_store=owner.operation_store,
                    operation=owner.operation,
                    binding=owner.binding,
                    root=root / "new",
                    sources=owner.sources,
                    attempt=1,
                    stages=owner.stages,
                    boot_path=owner.boot_path,
                )
            self.assertFalse((root / "new").exists())
            self.assertEqual(owner.store.read(), original)

    def test_operation_scope_binding_and_source_inventory_refuse_before_files(self):
        for case, reason in (
            ("scope", "capture:operation_scope"),
            ("binding", "capture:binding"),
            ("duplicate", "capture:source_inventory"),
            ("boolean_attempt", "capture:scope"),
        ):
            with self.subTest(case=case), TemporaryDirectory() as directory:
                root = Path(directory)
                owner = self.owner(root)
                sources = copy.deepcopy(owner.sources)
                binding = copy.deepcopy(owner.binding)
                attempt = 1
                if case == "scope":
                    attempt = 2
                elif case == "binding":
                    binding["session_id"] = "another-session"
                elif case == "boolean_attempt":
                    attempt = True
                else:
                    sources["duplicate"] = sources["clock"]
                with self.assertRaisesRegex(IntegrityError, reason):
                    CaptureOwner(
                        store=DurableStore(root / "new-store", {}, initialize=True),
                        operation_store=owner.operation_store,
                        operation=owner.operation,
                        binding=binding,
                        root=root / "new",
                        sources=sources,
                        attempt=attempt,
                        stages=owner.stages,
                        boot_path=owner.boot_path,
                    )
                self.assertFalse((root / "new").exists())

    def test_schedule_records_missed_slot_and_never_backfills(self):
        with TemporaryDirectory() as directory:
            owner = self.owner(Path(directory))
            calls = []

            def slow():
                calls.append(True)
                time.sleep(0.04)

            with self.assertRaisesRegex(IntegrityError, "capture:missed_slot"):
                owner.periodic(
                    "clock",
                    slow,
                    period_ms=10,
                    stop_ns=time.monotonic_ns() + 1_000_000_000,
                    stop_event=threading.Event(),
                )
            self.assertEqual(len(calls), 1)
            records = self.wire(owner)
            self.assertTrue(records[-1]["metadata"].get("missed_slot"))
            # Refuse the overlong completed slot immediately, before advancing
            # the schedule and noticing a different missed start next time.
            self.assertEqual(
                records[-1]["metadata"]["scheduled_ns"], records[0]["metadata"]["scheduled_ns"]
            )
            self.assertFalse(owner.close()["transport_clean"])

    def test_late_scheduled_start_does_not_issue_a_backfilled_poll(self):
        with TemporaryDirectory() as directory:
            owner = self.owner(Path(directory))
            calls = []
            ticks = iter((0, 0, 20_000_001, 20_000_002, 20_000_003))
            with patch(
                "inference_platform.inf037b_capture.time.monotonic_ns",
                side_effect=lambda: next(ticks, 20_000_004),
            ):
                with self.assertRaisesRegex(IntegrityError, "capture:missed_slot"):
                    owner.periodic(
                        "clock",
                        lambda: calls.append(True),
                        period_ms=10,
                        stop_ns=1_000_000_000,
                        stop_event=threading.Event(),
                    )
            self.assertEqual(calls, [])
            self.assertFalse(owner.close()["transport_clean"])

    def test_concurrent_row_sinks_keep_sequence_and_archive_bytes(self):
        with TemporaryDirectory() as directory:
            owner = self.owner(Path(directory))
            rows = owner.rows("clock")
            self.assertEqual(owner.root.stat().st_mode & 0o777, 0o700)
            self.assertEqual((owner.root / "wire").stat().st_mode & 0o777, 0o700)
            threads = [threading.Thread(target=lambda: owner.local_clock(rows)) for _ in range(8)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            result = owner.close()
            self.assertTrue(result["transport_clean"])
            self.assertEqual([row["source_seq"] for row in owner.clock_rows], list(range(8)))
            self.assertEqual(result["archive"]["segments"]["raw/clocks.jsonl"]["row_count"], 8)
            self.assertEqual(self.wire(owner), [])  # Accepted rows have no spool duplicate.

    def test_concurrent_cached_joins_serialize_the_operation_store_lease(self):
        with TemporaryDirectory() as directory:
            owner = self.owner(Path(directory))
            begin, errors = threading.Barrier(8), []
            generation = owner.generation

            def slow_generation():
                time.sleep(0.01)  # Hold the real nonblocking file lease across overlap.
                return generation()

            def join():
                try:
                    begin.wait(2)
                    owner.join_current()
                except Exception as exc:
                    errors.append(str(exc))

            with patch.object(owner, "generation", side_effect=slow_generation):
                threads = [threading.Thread(target=join) for _ in range(8)]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join(2)
                self.assertTrue(all(not thread.is_alive() for thread in threads))
            self.assertEqual(errors, [])
            self.assertTrue(owner.close()["transport_clean"])

    def test_batched_raw_segments_barrier_precedes_normalization_and_cached_join(self):
        raw = b"one\x00two\xff" * 20000

        def respond(handler):
            handler.send_response(200)
            handler.send_header("Content-Length", str(len(raw)))
            handler.end_headers()
            handler.wfile.write(raw)

        base = self.server(respond)
        with TemporaryDirectory() as directory:
            owner = self.owner(Path(directory))
            http = DeadlineHTTP(
                base,
                stop_ns=time.monotonic_ns() + 5_000_000_000,
                retain=owner.retainer("clock"),
                local_test=True,
            )
            with patch.object(owner, "join", wraps=owner.join) as joins:
                body, _ = http.get("/bytes")
                self.assertEqual(body, raw)
                self.assertEqual(owner.fsync_count, 2)
                for _ in range(30):
                    owner.local_clock(owner.rows("clock"))
                self.assertEqual(joins.call_count, 0)
            self.assertEqual(len(list((owner.root / "wire").iterdir())), 4)
            records = self.wire(owner)
            self.assertEqual(b"".join(r["body"] for r in records), raw)
            self.assertFalse(any(r["metadata"].get("normalized") for r in records))
            owner.close()
            self.assertEqual(b"".join(body for _, body in wire_records(owner.root / "wire")), raw)
            index = next(p for p in (owner.root / "wire").glob("*.jsonl") if p.stat().st_size)
            original = index.read_bytes()
            index.write_bytes(original[:-1])
            with self.assertRaisesRegex(IntegrityError, "capture:torn_wire_index"):
                list(wire_records(owner.root / "wire"))
            index.write_bytes(original)
            data = index.with_suffix(".bin")
            data.write_bytes(b"!" + data.read_bytes()[1:])
            with self.assertRaisesRegex(IntegrityError, "capture:wire_hash"):
                list(wire_records(owner.root / "wire"))

    def test_real_runner_watch_cutoff_eof_and_unsettled_grace(self):
        for mode in (
            "watch-cutoff",
            "watch-eof",
            "watch-cutoff-chunked",
            "watch-eof-chunked",
            "watch-eof-abrupt-chunked",
            "watch-shutdown-chunked",
            "unsettled",
        ):
            with self.subTest(mode=mode), TemporaryDirectory() as directory:
                root = Path(directory)
                calls = ProcessCalls(
                    {
                        "preparation": [
                            sys.executable,
                            "-c",
                            "from test_inf037b_capture import runner_child; import sys; "
                            "runner_child(sys.argv[1], sys.argv[2])",
                            directory,
                            mode,
                        ]
                    },
                    lambda: int(time.monotonic() * 1000),
                )
                identities = []
                start = time.monotonic()
                if mode.startswith("watch-cutoff") or mode == "watch-shutdown-chunked":
                    result = calls(
                        "preparation",
                        int(time.monotonic() * 1000) + 10_000,
                        {},
                        spawned=identities.append,
                    )
                    self.assertTrue(result["transport_clean"])
                    self.assertTrue(result["closed"])
                    self.assertTrue((root / "retained/archive/SHA256SUMS").is_file())
                    records = []
                    for path in (root / "retained/wire").glob("*.jsonl"):
                        records.extend(strict_json(line) for line in path.read_bytes().splitlines())
                    cutoff = next(r for r in records if r["metadata"].get("end") == "cutoff")
                    self.assertEqual(cutoff["metadata"]["last_resource_version"], "27")
                    self.assertGreater(cutoff["metadata"]["bytes"], 0)
                    self.assertGreaterEqual(cutoff["end_ns"], cutoff["metadata"]["stop_ns"])
                    self.assertGreater(time.monotonic() - start, 2)
                    self.assertTrue((root / "transport-closed").exists())
                    self.assertNotIn("losses", result)
                    if mode == "watch-shutdown-chunked":
                        self.assertIn("IncompleteRead", cutoff["metadata"]["cutoff_exception"])
                else:
                    with self.assertRaisesRegex(IntegrityError, "lifecycle:process_exit"):
                        calls(
                            "preparation",
                            int(time.monotonic() * 1000) + 10_000,
                            {},
                            spawned=identities.append,
                        )
                    state = DurableStore(root / "capture-store", {}).read()["capture"]
                    self.assertNotIn("closed", state)
                    self.assertEqual((root / "exit-code").read_text(), "76")
                    self.assertIn("capture:workers_failed_or_unsettled", state["losses"])
                    if mode.startswith("watch-eof"):
                        self.assertTrue(any(loss.startswith("kube:") for loss in state["losses"]))
                    self.assertLess(time.monotonic() - start, 4)
                from inference_platform.inf037b_lifecycle import group_members

                self.assertEqual(group_members(identities[0]["group"]), [])

    def test_archive_slot_and_rejected_row_barriers_precede_completion_and_loss(self):
        with TemporaryDirectory() as directory:
            owner = self.owner(Path(directory))
            events = []
            fsync, retain, write = os.fsync, owner.retain, owner.store.write

            def synced(fd):
                events.append(("sync", os.readlink(f"/proc/self/fd/{fd}")))
                return fsync(fd)

            def retained(source, start, end, body, metadata):
                if (
                    "scheduled_ns" in metadata
                    or metadata.get("watch_batch")
                    or metadata.get("client_request_end")
                ):
                    events.append(("completion", metadata))
                return retain(source, start, end, body, metadata)

            def stored(state):
                if state["capture"].get("losses"):
                    events.append(("loss", state["capture"]["losses"][-1]))
                return write(state)

            def collect():
                owner.retain("clock", 0, 1, b"raw", {})
                owner.barrier("clock")
                events.append(("raw_durable", None))
                owner.local_clock(owner.rows("clock"))
                owner.local_clock(owner.rows("clock"))
                events.append(("appended", None))

            archive_path = str(owner.archive.root / "raw/clocks.jsonl")
            with (
                patch("os.fsync", side_effect=synced),
                patch.object(owner, "retain", side_effect=retained),
                patch.object(owner.store, "write", side_effect=stored),
            ):
                start = time.monotonic_ns()
                owner.periodic(
                    "clock",
                    collect,
                    period_ms=1000,
                    start_ns=start,
                    stop_ns=start + 1_000_000_000,
                    stop_event=threading.Event(),
                )
                appended = next(i for i, event in enumerate(events) if event[0] == "appended")
                completed = next(i for i, event in enumerate(events) if event[0] == "completion")
                segment_syncs = [
                    i for i, event in enumerate(events) if event == ("sync", archive_path)
                ]
                self.assertEqual(len(segment_syncs), 1)  # Two rows, one slot barrier.
                self.assertLess(appended, segment_syncs[0])
                self.assertLess(segment_syncs[0], completed)
                self.assertTrue(
                    any(
                        event[0] == "sync" and "/wire/" in event[1]
                        for event in events[completed + 1 :]
                    )
                )

                # A watch read batch uses the same explicit owner barrier.
                events.clear()
                owner.local_clock(owner.rows("clock"))
                owner.retainer("clock").complete(0, 1, b"", {"watch_batch": True})
                self.assertLess(
                    events.index(("sync", archive_path)),
                    next(i for i, event in enumerate(events) if event[0] == "completion"),
                )

                events.clear()
                owner.local_clock(owner.rows("clock"))
                owner.retainer("clock").client_complete(0, 1, b"", {"client_request_end": True})
                self.assertFalse(any(event[0] == "completion" for event in events))
                owner.group_barrier()
                self.assertLess(
                    events.index(("sync", archive_path)),
                    next(i for i, event in enumerate(events) if event[0] == "completion"),
                )

                # A rejected row must settle prior accepted rows and its own
                # original bytes before the durable loss snapshot.
                events.clear()
                row = owner.local_clock(owner.rows("clock"))
                events.append(("appended", None))
                row["source_identity"] = "unregistered"
                with self.assertRaisesRegex(IntegrityError, "capture:lineage"):
                    owner.rows("clock").sink(row)
                lost = next(i for i, event in enumerate(events) if event[0] == "loss")
                self.assertIn(("sync", archive_path), events[:lost])
                self.assertLess(events.index(("sync", archive_path)), lost)
                self.assertTrue(
                    any(event[0] == "sync" and "/wire/" in event[1] for event in events[:lost])
                )
            self.assertFalse(owner.close()["transport_clean"])

    def test_capture_archive_barrier_is_independent_of_export_batch(self):
        from inference_platform.inf037b_export_runtime import _batch

        with TemporaryDirectory() as directory:
            owner = self.owner(Path(directory))
            files, directories = set(), set()
            token = _batch.set((files, directories))
            try:
                owner.local_clock(owner.rows("clock"))
                self.assertEqual(files, set())
                self.assertEqual(directories, set())
                owner.archive_barrier()
                self.assertEqual(files, set())
                with self.assertRaisesRegex(IntegrityError, "capture:export_context_at_close"):
                    owner.close()
                new = Path(directory) / "nested"
                new.mkdir()
                with self.assertRaisesRegex(IntegrityError, "capture:export_context_at_open"):
                    self.owner(new)
                self.assertFalse((new / "retained").exists())
                self.assertNotIn("capture", DurableStore(new / "capture-store", {}).read())
            finally:
                _batch.reset(token)
            self.assertTrue(owner.close()["transport_clean"])

    def test_archive_seal_directories_are_durable_before_closed_descriptor(self):
        from inference_platform.inf037b_durable_ports import sync_directory

        with TemporaryDirectory() as directory:
            owner = self.owner(Path(directory))
            owner.local_clock(owner.rows("clock"))
            events = []
            seal, write = owner.archive.seal, owner.store.write

            def sealed():
                result = seal()
                events.append(("sealed", None))
                return result

            def synced(path):
                sync_directory(path)
                events.append(("directory", path))

            def stored(state):
                if state["capture"].get("closed"):
                    events.append(("closed", None))
                return write(state)

            with (
                patch.object(owner.archive, "seal", side_effect=sealed),
                patch("inference_platform.inf037b_capture.sync_directory", side_effect=synced),
                patch.object(owner.store, "write", side_effect=stored),
            ):
                self.assertTrue(owner.close()["transport_clean"])
            start, end = events.index(("sealed", None)), events.index(("closed", None))
            for path in (
                owner.archive.root,
                owner.archive.root / "raw",
                owner.archive.root / "cohorts",
                owner.archive.root / "events",
            ):
                self.assertIn(("directory", path), events[start + 1 : end])

    def test_real_runner_partial_final_slot_closes_and_period_overrun_refuses(self):
        for mode in ("periodic-300", "periodic-50", "periodic-overrun"):
            with self.subTest(mode=mode), TemporaryDirectory() as directory:
                root = Path(directory)
                calls = ProcessCalls(
                    {
                        "preparation": [
                            sys.executable,
                            "-c",
                            "from test_inf037b_capture import runner_child; import sys; "
                            "runner_child(sys.argv[1], sys.argv[2])",
                            directory,
                            mode,
                        ]
                    },
                    lambda: int(time.monotonic() * 1000),
                )
                if mode == "periodic-overrun":
                    with self.assertRaisesRegex(IntegrityError, "lifecycle:process_exit"):
                        calls("preparation", int(time.monotonic() * 1000) + 10_000, {})
                    state = DurableStore(root / "capture-store", {}).read()["capture"]
                    self.assertNotIn("closed", state)
                    self.assertTrue(any("capture:missed_slot" in loss for loss in state["losses"]))
                else:
                    result = calls("preparation", int(time.monotonic() * 1000) + 10_000, {})
                    self.assertTrue(result["closed"] and result["transport_clean"])
                    stop_ns = int((root / "periodic-stop").read_text())
                    slots = [
                        record
                        for record, _ in wire_records(root / "retained/wire")
                        if "period_ms" in record["metadata"]
                    ]
                    self.assertEqual(len(slots), 4)  # Two complete slots per source.
                    self.assertTrue(all(record["end_ns"] <= stop_ns for record in slots))
                    self.assertTrue(
                        all(
                            record["metadata"]["scheduled_ns"] + 1_000_000_000 <= stop_ns
                            for record in slots
                        )
                    )

    def test_real_runner_actions_share_capture_fence_and_absolute_cutoff(self):
        for mode in ("action-clean", "action-fail", "action-late"):
            with self.subTest(mode=mode), TemporaryDirectory() as directory:
                root = Path(directory)
                calls = ProcessCalls(
                    {
                        "preparation": [
                            sys.executable,
                            "-c",
                            "from test_inf037b_capture import runner_child; import sys; "
                            "runner_child(sys.argv[1], sys.argv[2])",
                            directory,
                            mode,
                        ]
                    },
                    lambda: int(time.monotonic() * 1000),
                )
                identities = []
                if mode == "action-clean":
                    result = calls(
                        "preparation",
                        int(time.monotonic() * 1000) + 10_000,
                        {},
                        spawned=identities.append,
                    )
                    self.assertTrue(result["closed"] and result["transport_clean"])
                    records = [record for record, _ in wire_records(root / "retained/wire")]
                    self.assertEqual(
                        sum(
                            record["metadata"].get("action_completed", False) for record in records
                        ),
                        1,
                    )
                else:
                    with self.assertRaisesRegex(IntegrityError, "lifecycle:process_exit"):
                        calls(
                            "preparation",
                            int(time.monotonic() * 1000) + 10_000,
                            {},
                            spawned=identities.append,
                        )
                    state = DurableStore(root / "capture-store", {}).read()["capture"]
                    self.assertNotIn("closed", state)
                    reason = (
                        "forced-action-loss"
                        if mode == "action-fail"
                        else "capture:action_failed_or_late"
                    )
                    self.assertTrue(any(reason in loss for loss in state["losses"]))
                from inference_platform.inf037b_lifecycle import group_members

                self.assertEqual(group_members(identities[0]["group"]), [])

    def test_http_cutoff_truncation_redirect_and_torn_line_retain_bytes(self):
        for case, reason in (
            ("slow", "capture:deadline"),
            ("truncated", "capture:truncated_response"),
            ("redirect", "capture:http_status"),
            ("watch_redirect", "capture:http_status"),
            ("torn", "capture:torn_line"),
            ("oversize", "capture:line_limit"),
            ("long_line", "capture:line_limit"),
        ):

            def respond(handler, case=case):
                handler.send_response(302 if case in {"redirect", "watch_redirect"} else 200)
                if case == "truncated":
                    handler.send_header("Content-Length", "100")
                handler.end_headers()
                for _ in range(10 if case == "slow" else 1):
                    handler.wfile.write(b"partial\n" if case == "long_line" else b"partial")
                    handler.wfile.flush()
                    if case == "slow":
                        time.sleep(0.015)

            base, retained = self.server(respond), []
            http = DeadlineHTTP(
                base,
                stop_ns=time.monotonic_ns() + (60_000_000 if case == "slow" else 2_000_000_000),
                retain=lambda *args, retained=retained: retained.append(args),
                local_test=True,
            )
            with (
                self.subTest(case=case),
                self.assertRaisesRegex((IntegrityError, TimeoutError), reason + "|timed out"),
            ):
                if case in ("torn", "oversize", "long_line", "watch_redirect"):
                    list(http.lines("/watch", max_line=3 if case != "torn" else 100))
                else:
                    http.get("/source")
            self.assertTrue(any(r[3].get("error") for r in retained))
            if case not in {"redirect", "watch_redirect"}:
                self.assertTrue(any(r[2] for r in retained))

    def test_redis_real_resp_bytes_and_partial_failure_remain_secured(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        retained = []
        barriers = []

        def respond():
            with listener.accept()[0] as connection:
                connection.recv(4096)
                connection.sendall(b"*2\r\n$3\r\n123\r\n$3\r\n456\r\n")
                connection.recv(4096)
                connection.sendall(b"$10\r\nshort")

        thread = threading.Thread(target=respond)
        thread.start()
        self.addCleanup(listener.close)
        wire = RedisWire(
            "127.0.0.1",
            listener.getsockname()[1],
            tls=False,
            local_test=True,
            stop_ns=time.monotonic_ns() + 2_000_000_000,
            retain=lambda *args: retained.append(args),
            barrier=lambda: barriers.append(b"".join(r[2] for r in retained)),
        )
        self.addCleanup(wire.close)
        self.assertEqual(wire.command("TIME"), ["123", "456"])
        self.assertEqual(barriers, [b"*2\r\n$3\r\n123\r\n$3\r\n456\r\n"])
        with self.assertRaisesRegex(IntegrityError, "redis_capture_truncated"):
            wire.command("TIME")
        self.assertEqual(len(barriers), 2)
        self.assertTrue(barriers[-1].endswith(b"short"))
        thread.join(1)
        self.assertFalse(thread.is_alive())
        self.assertEqual(
            b"".join(r[2] for r in retained), b"*2\r\n$3\r\n123\r\n$3\r\n456\r\n$10\r\nshort"
        )

    def test_tls_and_group_owner_refuse_before_network_or_workers(self):
        with self.assertRaisesRegex(IntegrityError, "capture:tls"):
            DeadlineHTTP("http://example.invalid", stop_ns=1, retain=None)
        for url, reason in (
            ("https://user:secret@example.invalid", "capture:endpoint"),
            ("https://example.invalid/path", "capture:endpoint_path"),
        ):
            with self.assertRaisesRegex(IntegrityError, reason):
                DeadlineHTTP(url, stop_ns=1, retain=None)
        http = DeadlineHTTP("https://example.invalid", stop_ns=1, retain=lambda *args: None)
        with self.assertRaisesRegex(IntegrityError, "capture:deadline"):
            http.remaining()
        with self.assertRaisesRegex(IntegrityError, "capture:request_path"):
            http.get("//another-host/path")
        with TemporaryDirectory() as directory:
            owner = self.owner(Path(directory))
            with patch("inference_platform.inf037b_command.os.getpgrp", return_value=-1):
                with self.assertRaisesRegex(IntegrityError, "command:group_leader"):
                    owner.run(periodic=[], watches={}, stop_ns=time.monotonic_ns() + 1)

    def test_real_runner_success_seals_actual_clock_rows_and_original_operation(self):
        with TemporaryDirectory() as directory:
            calls = ProcessCalls(
                {
                    "preparation": [
                        sys.executable,
                        "-c",
                        "from test_inf037b_capture import runner_child; "
                        "import sys; runner_child(sys.argv[1], 'clean')",
                        directory,
                    ]
                },
                lambda: int(time.monotonic() * 1000),
            )
            result = calls("preparation", int(time.monotonic() * 1000) + 10_000, {})
            self.assertTrue(result["transport_clean"])
            self.assertTrue(result["closed"])
            self.assertEqual(result["operation"]["sequence"], 7)
            self.assertEqual(result["archive"]["segments"]["raw/clocks.jsonl"]["row_count"], 1)
            self.assertTrue(any(p.startswith("wire/") for p in result["files"]))

    def test_real_runner_failure_is_durable_before_prompt_group_fence(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            calls = ProcessCalls(
                {
                    "preparation": [
                        sys.executable,
                        "-c",
                        "from test_inf037b_capture import runner_child; "
                        "import sys; runner_child(sys.argv[1])",
                        str(root),
                    ]
                },
                lambda: int(time.monotonic() * 1000),
            )
            identities = []
            start = time.monotonic()
            with self.assertRaisesRegex(IntegrityError, "lifecycle:process_exit"):
                calls(
                    "preparation",
                    int(time.monotonic() * 1000) + 15_000,
                    {},
                    spawned=identities.append,
                )
            self.assertLess(time.monotonic() - start, 3)
            state = DurableStore(root / "capture-store", {}).read()["capture"]
            self.assertIn("clock:forced-collector-loss", state["losses"])
            self.assertIn("capture:workers_failed_or_unsettled", state["losses"])
            self.assertNotIn("closed", state)
            from inference_platform.inf037b_lifecycle import group_members

            self.assertEqual(group_members(identities[0]["group"]), [])


def runner_child(directory, mode="fail"):
    root = Path(directory)
    fixture = CaptureTests()
    owner = fixture.owner(root)
    real_exit = os._exit

    def exit_recorded(code):
        (root / "exit-code").write_text(str(code))
        real_exit(code)

    os._exit = exit_recorded
    if mode.startswith("action-"):
        started = threading.Event()

        def clock():
            started.set()
            if mode == "action-fail":
                time.sleep(30)
            else:
                owner.local_clock(owner.rows("clock"))

        def action():
            started.wait(2)
            if mode == "action-fail":
                raise ValueError("forced-action-loss")
            if mode == "action-late":
                time.sleep(1.2)

        result = owner.run(
            periodic=[("clock", 1000, clock)],
            watches={},
            actions={"kube": action},
            stop_ns=time.monotonic_ns() + 1_100_000_000,
        )
        sys.stdout.buffer.write(encode(result))
        return
    if mode == "unsettled":
        owner.run(
            periodic=[
                ("clock", 1000, lambda: owner.local_clock(owner.rows("clock"))),
                ("kube", 1000, lambda: time.sleep(30)),
            ],
            watches={},
            stop_ns=time.monotonic_ns() + 1_100_000_000,
        )
        return
    if mode.startswith("watch-"):
        raw = encode({"type": "BOOKMARK", "object": {"metadata": {"resourceVersion": "27"}}})

        def respond(handler):
            chunked = mode.endswith("chunked")
            if chunked:
                handler.protocol_version = "HTTP/1.1"
            handler.send_response(200)
            if chunked:
                handler.send_header("Transfer-Encoding", "chunked")
            elif mode == "watch-eof":
                handler.send_header("Content-Length", str(len(raw)))
            handler.end_headers()
            handler.wfile.write(f"{len(raw):x}\r\n".encode() + raw + b"\r\n" if chunked else raw)
            if mode == "watch-eof-chunked":
                handler.wfile.write(b"0\r\n\r\n")
            if mode == "watch-eof-abrupt-chunked":
                handler.close_connection = True
            handler.wfile.flush()
            if mode.startswith("watch-cutoff") or mode == "watch-shutdown-chunked":
                handler.connection.recv(1)  # Open, silent until the client closes.
                (root / "transport-closed").write_text("closed")

        base = fixture.server(respond)
        stop_ns = time.monotonic_ns() + 2_700_000_000
        http = DeadlineHTTP(base, stop_ns=stop_ns, retain=owner.retainer("kube"), local_test=True)
        if mode == "watch-shutdown-chunked":
            remaining = http.remaining

            def delayed_timeout(**kwargs):
                value = remaining(**kwargs)
                return value + 5 if kwargs.get("watch") else value

            http.remaining = delayed_timeout  # Deterministically let owned shutdown win.
        adapter = KubernetesAdapter(
            owner.rows("kube"), http, "fixture", slot_names={}, lifecycle=LifecycleReceiptProducer()
        )
        original_watch = owner.watch

        def settle(*args):
            original_watch(*args)
            time.sleep(0.12)  # Bounded end-record/transport settlement latency.

        owner.watch = settle
        result = owner.run(
            periodic=[("clock", 1000, lambda: owner.local_clock(owner.rows("clock")))],
            watches={"kube": (adapter, "26")},
            stop_ns=stop_ns,
        )
        if mode.startswith("watch-cutoff") or mode == "watch-shutdown-chunked":
            assert not adapter.lifecycle.lost, "orderly cutoff poisoned lifecycle continuity"
        sys.stdout.buffer.write(encode(result))
        return
    if mode.startswith("periodic-"):
        delay, duration, period = {
            "periodic-300": (0.3, 2.2, 1000),
            "periodic-50": (0.05, 2.02, 1000),
            "periodic-overrun": (0.15, 1.1, 100),
        }[mode]
        stop_ns = time.monotonic_ns() + int(duration * 1e9)
        (root / "periodic-stop").write_text(str(stop_ns))
        result = owner.run(
            periodic=[
                ("clock", 1000, lambda: owner.local_clock(owner.rows("clock"))),
                ("kube", period, lambda: time.sleep(delay)),
            ],
            watches={},
            stop_ns=stop_ns,
        )
        sys.stdout.buffer.write(encode(result))
        return
    if mode == "clean":
        result = owner.run(
            periodic=[
                ("clock", 1000, lambda: owner.local_clock(owner.rows("clock"))),
                ("kube", 1000, lambda: None),
            ],
            watches={},
            stop_ns=time.monotonic_ns() + 1_100_000_000,
        )
        sys.stdout.buffer.write(encode(result))
        return
    descendant = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    (root / "descendant").write_text(str(descendant.pid))
    started = threading.Event()

    def blocked():
        started.set()
        time.sleep(30)

    def fail():
        started.wait(2)
        raise ValueError("forced-collector-loss")

    owner.run(
        periodic=[("clock", 1000, fail), ("kube", 1000, blocked)],
        watches={},
        stop_ns=time.monotonic_ns() + 15_000_000_000,
    )


if __name__ == "__main__":
    unittest.main()
