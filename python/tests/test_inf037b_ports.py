"""Linux real-filesystem port controls; all external I/O is recorded byte transport."""

import io
import json
import os
import stat
import threading
import unittest
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import patch

import test_inf037b_controller as legacy
from inf037b_ports_support import Rig, review_bytes

from inference_platform import inf037b_durable_ports as durable
from inference_platform.inf037b_archive import IntegrityError, encode
from inference_platform.inf037b_ports import (
    Authority,
    AuthorityUnavailable,
    BackstopPort,
    FileGate,
    GitReviewSource,
    committed_marker,
)


class PortsTests(unittest.TestCase):
    def setUp(self):
        self.rig = Rig()
        self.addCleanup(self.rig.close)

    def journal(self, name="direct-journal"):
        result = durable.FileJournal(self.rig.root / name, self.rig.world.clock, initialize=True)
        self.addCleanup(result.close)
        return result

    def prepared(self):
        controller = self.rig.open()
        controller.mark()
        controller.acquire()
        return controller

    def test_real_file_and_directory_fsync_and_readback(self):
        journal = self.journal()
        calls = []
        order = []
        actual = os.fsync
        actual_open, actual_replace = durable.Path.open, os.replace

        class Traced:
            def __init__(self, stream):
                self.stream = stream

            def __enter__(self):
                return self

            def __exit__(self, *args):
                order.append("close")
                return self.stream.__exit__(*args)

            def write(self, data):
                order.append("write")
                return self.stream.write(data)

            def flush(self):
                order.append("flush")
                return self.stream.flush()

            def fileno(self):
                return self.stream.fileno()

        def opened(path, *args, **kwargs):
            result = actual_open(path, *args, **kwargs)
            return Traced(result) if path.name.startswith("pending-") else result

        def renamed(source, target):
            order.append("replace")
            return actual_replace(source, target)

        def sync(fd):
            calls.append("directory" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file")
            order.append(calls[-1])
            return actual(fd)

        row = {"seq": 1, "event": "bound", "index": -1, "data": []}
        with (
            patch.object(durable.os, "fsync", side_effect=sync),
            patch.object(durable.Path, "open", opened),
            patch.object(durable.os, "replace", side_effect=renamed),
        ):
            self.assertIs(journal.append_fsync(row), True)
        self.assertEqual(calls, ["file", "directory"])
        self.assertEqual(order, ["write", "flush", "file", "close", "replace", "directory"])
        self.assertEqual(journal.read(), [row])
        journal.close()
        reopened = durable.FileJournal(journal.store.path, self.rig.world.clock)
        self.addCleanup(reopened.close)
        self.assertEqual(reopened.read(), [row])

    def test_file_and_directory_fsync_failures_never_acknowledge(self):
        for failing in ("file", "directory"):
            journal = self.journal("fail-" + failing)
            actual = os.fsync

            def sync(fd, failing=failing, actual=actual):
                kind = "directory" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file"
                if kind == failing:
                    raise OSError("injected_" + failing + "_fsync")
                return actual(fd)

            row = {"seq": 1, "event": "bound", "index": -1, "data": []}
            with patch.object(durable.os, "fsync", side_effect=sync):
                with self.assertRaisesRegex(OSError, "injected_"):
                    journal.append_fsync(row)
            with self.assertRaisesRegex(IntegrityError, "store_poisoned"):
                journal.read()
            with self.assertRaisesRegex(IntegrityError, "store_poisoned"):
                journal.store.write({})
            with self.assertRaisesRegex(IntegrityError, "store_poisoned"), journal.store.lock():
                self.fail("poisoned authority acquired a lock")
            journal.close()
            reopened = durable.FileJournal(journal.store.path, self.rig.world.clock)
            self.addCleanup(reopened.close)
            self.assertEqual(reopened.read(), [] if failing == "file" else [row])

    def test_torn_truncated_corrupt_or_missing_store_refuses_reopen(self):
        for fault in (
            "truncated",
            "hash",
            "duplicate",
            "missing",
            "schema",
            "extra",
            "lost-directory",
        ):
            journal = self.journal(fault)
            journal.append_fsync({"seq": 1, "event": "bound", "index": -1, "data": []})
            journal.close()
            path = journal.store.path / "state.json"
            raw = path.read_bytes()
            if fault == "missing":
                path.unlink()
            elif fault == "lost-directory":
                for child in journal.store.path.iterdir():
                    child.unlink()
                journal.store.path.rmdir()
            elif fault == "truncated":
                path.write_bytes(raw[: len(raw) // 2])
            elif fault == "hash":
                obj = json.loads(raw)
                obj["payload"]["rows"] = []
                path.write_bytes(encode(obj))
            elif fault == "duplicate":
                path.write_bytes(raw.replace(b'"schema":', b'"schema":"wrong","schema":'))
            else:
                obj = json.loads(raw)
                if fault == "schema":
                    obj["schema"] = "other"
                else:
                    obj["extra"] = 1
                path.write_bytes(encode(obj))
            if fault == "lost-directory":
                with self.assertRaisesRegex(IntegrityError, "initialization_required"):
                    durable.FileJournal(journal.store.path, self.rig.world.clock)
                self.assertFalse(journal.store.path.exists())
            else:
                with self.subTest(fault=fault), self.assertRaises((IntegrityError, OSError)):
                    durable.FileJournal(journal.store.path, self.rig.world.clock)

    def test_torn_temporary_write_and_replace_failure_preserve_prefix(self):
        journal = self.journal()
        row = {"seq": 1, "event": "bound", "index": -1, "data": []}
        with patch.object(durable.os, "replace", side_effect=OSError("rename_failed")):
            with self.assertRaises(OSError):
                journal.append_fsync(row)
        for path in journal.store.path.glob("pending-*"):
            path.write_bytes(b'{"torn":')
        journal.close()
        reopened = durable.FileJournal(journal.store.path, self.rig.world.clock)
        self.addCleanup(reopened.close)
        self.assertEqual(reopened.read(), [])

    def test_one_writer_stale_owner_and_fence_mismatch_refuse(self):
        journal = self.journal()
        with self.assertRaises(BlockingIOError):
            durable.FileJournal(journal.store.path, self.rig.world.clock)
        state = journal.store.read()
        state["epoch"] += 1
        journal.store.write(state)
        with self.assertRaisesRegex(IntegrityError, "stale_fence"):
            journal.append_fsync({"seq": 1, "event": "bound"})
        journal.close()
        with self.assertRaisesRegex(IntegrityError, "stale_writer"):
            journal.append_fsync({"seq": 1, "event": "bound"})

    def test_origin_samples_completed_barrier_and_unsealed_anchor_refuses(self):
        journal = self.journal()
        actual = durable.sync_directory

        def slow(path):
            actual(path)
            self.rig.world.now += 10

        row = {"seq": 1, "event": "billing_origin", "index": -1, "data": {"session_id": "fixture"}}
        with patch.object(durable, "sync_directory", side_effect=slow):
            receipt = journal.append_origin_fsync(row)
        self.assertEqual(receipt["row"]["data"]["t0_ms"], legacy.BASE + 10)
        self.assertEqual(self.rig.world.now, legacy.BASE + 20)
        with self.assertRaisesRegex(IntegrityError, "origin_once"):
            journal.append_origin_fsync(dict(row, seq=2))
        other = self.journal("unsealed")
        with patch.object(other, "clock", side_effect=legacy.Crash("before_seal")):
            with self.assertRaises(legacy.Crash):
                other.append_origin_fsync(row)
        with self.assertRaisesRegex(IntegrityError, "unsealed_origin"):
            other.read()
        other.close()
        with self.assertRaisesRegex(IntegrityError, "unsealed_origin"):
            durable.FileJournal(other.store.path, self.rig.world.clock)

    def test_journal_sequence_and_origin_entrypoint_refuse_before_append(self):
        journal = self.journal()
        with self.assertRaisesRegex(IntegrityError, "journal_sequence"):
            journal.append_fsync({"seq": 2, "event": "bound"})
        with self.assertRaisesRegex(IntegrityError, "origin_requires_anchor"):
            journal.append_fsync({"seq": 1, "event": "billing_origin"})
        with self.assertRaisesRegex(IntegrityError, "origin_event"):
            journal.append_origin_fsync({"seq": 1, "event": "bound"})
        with self.assertRaisesRegex(IntegrityError, "origin_sequence"):
            journal.append_origin_fsync({"seq": 2, "event": "billing_origin"})
        self.assertEqual(journal.read(), [])

    def test_invalid_origin_clock_and_fence_epoch_fail_closed(self):
        for value in (True, -1):
            journal = self.journal("bad-clock-" + str(value))
            with patch.object(journal, "clock", return_value=value):
                with self.assertRaisesRegex(IntegrityError, "origin_clock"):
                    journal.append_origin_fsync({"seq": 1, "event": "billing_origin", "data": {}})
        other = self.journal("bad-epoch")
        state = other.store.read()
        state["epoch"] = True
        other.store.write(state)
        other.close()
        with self.assertRaisesRegex(IntegrityError, "fence_epoch"):
            durable.FileJournal(other.store.path, self.rig.world.clock)

    def test_request_response_binding_and_unknown_stale_reads(self):
        self.rig.run()
        authority = self.rig.gate.authority
        changes = {
            "request": lambda a: a.update(request_sha256="0" * 64),
            "identity": lambda a: a.update(authority_id="other"),
            "namespace": lambda a: a.update(namespace="other"),
            "unknown": lambda a: a.update(status="unavailable"),
            "ambiguous": lambda a: a.update(status="ambiguous"),
            "complete": lambda a: a.update(complete=False),
            "lag": lambda a: a.update(settled_sequence=0),
            "proof": lambda a: a.update(proof_id=""),
        }
        for name, change in changes.items():
            self.rig.responses.change = lambda request, answer, change=change: change(answer)
            with self.subTest(fault=name), self.assertRaises(AuthorityUnavailable):
                authority.call("application.lookup", "fixture", 1, None)
        self.rig.responses.change = None
        self.assertIsNone(authority.call("application.lookup", "fixture", 1, None))
        with patch.object(authority, "transport", side_effect=OSError("offline_connection_lost")):
            with self.assertRaises(OSError):
                authority.call("application.lookup", "fixture", 1, None)

    def test_authority_configuration_and_invalid_bytes_fail_closed(self):
        for identity, transport, timeout in (
            ("", lambda *_: b"", 1),
            ("x", None, 1),
            ("x", lambda *_: b"", 0),
            ("x", lambda *_: b"", True),
            ("x", lambda *_: b"", 10001),
        ):
            with self.assertRaises(IntegrityError):
                Authority(identity, "test", transport, timeout)
        authority = Authority("fixture", "test", lambda *_: b'{"bad":NaN}')
        with self.assertRaises(AuthorityUnavailable):
            authority.call("application.lookup", "fixture", 0, None)

    def test_markers_bind_binary_json_payload_source_pins_and_latest_commit(self):
        item = self.rig.items[0]
        data = review_bytes(self.rig.items)
        self.assertEqual(committed_marker(item, lambda *_: data)["binding"], item.plan.descriptor())
        pins = json.loads(item.pins)
        for bad, reason in (
            (
                replace(
                    item,
                    plan=replace(item.plan, capacity=legacy.Binding(legacy.GROUP, "us-east-1b")),
                ),
                "show_binding",
            ),
            (replace(item, source_commit="b" * 40), "source_pin"),
            (replace(item, pins=encode(dict(pins, payload_sha256="0" * 64))), "artifact_pins"),
        ):
            with self.assertRaisesRegex(IntegrityError, reason):
                bad.hashes()
        for bad in (
            replace(item, payload=b"altered"),
            replace(item, show_json=b"{}"),
            replace(item, pins=b"{}"),
            replace(item, source_commit="b" * 40),
            replace(item, review_commit="not-a-commit"),
            replace(item, plan=replace(item.plan, saved_plan=b"altered")),
        ):
            with self.subTest(bad=bad), self.assertRaises((ValueError, KeyError)):
                committed_marker(bad, lambda *_: data)
        for bad in (
            b"missing review sections",
            b"fixture\n## Claude review rounds\n## Findings\n",
            data.replace(b"COMMITTED", b"PROVISIONAL"),
            data.replace(b"NO_BLOCKING_FINDINGS", b"BLOCKING_FINDINGS"),
            data.replace(b"review_round=1", b"review_round=2"),
            data.replace(b"\n## Findings", b"\n### Round 2\n\n## Findings"),
        ):
            with self.assertRaises(IntegrityError):
                committed_marker(item, lambda *_, bad=bad: bad)
        line = next(line for line in data.splitlines() if item.plan.plan_hash.encode() in line)
        for bad in (data.replace(line, line + b"\n" + line), line + b"\n" + data):
            with self.assertRaises(IntegrityError):
                committed_marker(item, lambda *_, bad=bad: bad)

    def test_git_source_reads_committed_blob_not_worktree(self):
        source = GitReviewSource("/offline-repository")
        with patch(
            "inference_platform.inf037b_ports.subprocess.check_output",
            side_effect=[b"commit\n", b"", b"committed fixture\n"],
        ) as git:
            self.assertEqual(source("c" * 40, "a" * 40), b"committed fixture\n")
        self.assertEqual(
            [call.args[0][3:] for call in git.call_args_list],
            [
                ["cat-file", "-t", "c" * 40],
                ["merge-base", "--is-ancestor", "a" * 40, "c" * 40],
                ["show", "c" * 40 + ":REVIEW.md"],
            ],
        )
        with patch(
            "inference_platform.inf037b_ports.subprocess.check_output", return_value=b"blob\n"
        ):
            with self.assertRaisesRegex(IntegrityError, "review_commit"):
                source("c" * 40, "a" * 40)

    def test_duplicate_and_concurrent_consume_is_one_durable_session(self):
        controller = self.prepared()
        binding = controller.bindings[0]
        gate = self.rig.gate
        entered, release = threading.Event(), threading.Event()
        results = []

        def admit():
            entered.set()
            self.assertTrue(release.wait(5))
            return self.rig.world.now

        def consume():
            results.append(gate.consume(binding, admit))

        worker = threading.Thread(target=consume)
        worker.start()
        self.assertTrue(entered.wait(5))
        other = FileGate.__new__(FileGate)
        other.__dict__.update(gate.__dict__)
        try:
            with self.assertRaises(BlockingIOError):
                other.consume(binding, lambda: self.fail("loser admission ran"))
        finally:
            release.set()
            worker.join(10)
        self.assertFalse(worker.is_alive())
        self.assertEqual(
            gate.consume(binding, lambda: self.fail("duplicate admission ran")), results[0]
        )
        with self.assertRaisesRegex(IntegrityError, "one_consume"):
            gate.consume(controller.bindings[1], lambda: self.rig.world.now)
        self.rig.ports()
        self.assertEqual(self.rig.gate.consumption(binding["session_id"]), results[0])

    def test_application_lost_reply_reconciles_without_second_apply(self):
        self.rig.world.crash_operation = "apply"
        with self.assertRaises(legacy.Crash):
            self.rig.run()
        self.rig.journal.close()
        self.rig.ports()
        state = self.rig.open().recover()
        self.assertEqual(state["sessions"], 1)
        self.assertEqual(sum(name == "apply" for name, _ in self.rig.world.trace), 1)
        self.assertEqual(
            sum(q["operation"] == "application.apply" for q in self.rig.responses.requests), 1
        )
        self.assertEqual(self.rig.open()._get("applied", 0), True)

    def test_application_absence_unavailable_contradictory_and_disappeared(self):
        controller = self.prepared()
        binding = controller.bindings[0]
        self.rig.gate.consume(binding, lambda: self.rig.world.now)
        self.assertIsNone(self.rig.gate.application(binding["session_id"]))
        for result in (
            {"session_id": "wrong", "plan_hash": binding["plan_hash"]},
            {"session_id": binding["session_id"], "plan_hash": "0" * 64},
        ):
            self.rig.responses.change = lambda q, a, result=result: (
                a.update(result=result) if q["operation"] == "application.lookup" else None
            )
            with self.assertRaisesRegex(IntegrityError, "application_binding"):
                self.rig.gate.application(binding["session_id"])
        self.rig.responses.change = None
        self.rig.gate.apply_once(binding)
        self.rig.responses.change = lambda q, a: (
            a.update(result=None) if q["operation"] == "application.lookup" else None
        )
        with self.assertRaisesRegex(IntegrityError, "application_disappeared"):
            self.rig.gate.application(binding["session_id"])
        self.rig.responses.change = lambda q, a: (
            a.update(status="unavailable") if q["operation"] == "application.lookup" else None
        )
        with self.assertRaises(AuthorityUnavailable):
            self.rig.gate.application(binding["session_id"])

    def test_cancel_twice_survives_reopen_with_expected_ids_and_same_time(self):
        controller = self.prepared()
        token = controller._token(0)
        first = self.rig.capacity.cancel(token, legacy.GROUP)
        self.rig.world.now += 1000
        self.rig.ports()
        second = self.rig.capacity.cancel(token, legacy.GROUP)
        self.assertEqual(first, second)
        self.assertEqual(first["reservation_ids"], [self.rig.responses.capacity.ids[token]])
        self.assertEqual(sum(name == "cancel" for name, _ in self.rig.world.trace), 1)
        ledger = self.rig.capacity.ledger(token, legacy.BASE)
        self.assertEqual(ledger["stop_ms"], first["stop_ms"])
        self.assertGreater(ledger["cost_micros"], 0)

    def test_lagging_absent_and_contradictory_token_reads_never_advance(self):
        controller = self.prepared()
        token = controller._token(0)
        for mutate in (
            lambda a: a.update(result=None),
            lambda a: a.update(settled_sequence=-1),
            lambda a: a["result"].update(reservation_id="cr-other"),
        ):
            self.rig.responses.change = lambda q, a, mutate=mutate: (
                mutate(a) if q["operation"] == "odcr.lookup" else None
            )
            with self.assertRaises((AuthorityUnavailable, IntegrityError)):
                self.rig.capacity.lookup(token)
        self.rig.responses.change = None
        self.rig.capacity.cancel(token, legacy.GROUP)
        self.rig.responses.change = lambda q, a: (
            a["result"].update(state="active") if q["operation"] == "odcr.lookup" else None
        )
        with self.assertRaisesRegex(IntegrityError, "cancel_regression"):
            self.rig.capacity.lookup(token)

    def test_cancel_missing_ids_wrong_states_or_time_never_acknowledges(self):
        for mutate in (
            lambda a: a["result"].update(reservation_ids=[], states={}),
            lambda a: a["result"].update(verified=False),
            lambda a: a["result"].update(complete=False),
            lambda a: a["result"].update(stop_ms=True),
            lambda a: a["result"].update(stop_ms=-1),
            lambda a: a["result"].update(reservation_ids=dict(a["result"]["states"])),
            lambda a: a["result"]["reservation_ids"].extend(a["result"]["reservation_ids"]),
            lambda a: a["result"]["states"].update({a["result"]["reservation_ids"][0]: "active"}),
        ):
            rig = Rig()
            self.addCleanup(rig.close)
            controller = rig.open()
            controller.mark()
            controller.acquire()
            rig.responses.change = lambda q, a, mutate=mutate: (
                mutate(a) if q["operation"] == "odcr.cancel" else None
            )
            with self.assertRaises(IntegrityError):
                rig.capacity.cancel(controller._token(0), legacy.GROUP)
            self.assertIsNone(rig.capacity.cancellation(controller._token(0)))

    def test_gate_requires_markers_current_bindings_and_valid_admission(self):
        binding = self.rig.plans[0].descriptor()
        with self.assertRaisesRegex(IntegrityError, "marker_required"):
            self.rig.gate.consume(binding, self.rig.world.clock)
        with self.assertRaisesRegex(IntegrityError, "apply_without_consume"):
            self.rig.gate.apply_once(binding)
        self.rig.gate.marker(binding)
        changed = dict(binding, C="2026-10-19T00:00:00Z")
        with self.assertRaisesRegex(IntegrityError, "marker_descriptor"):
            self.rig.gate.marker(changed)
        for clock in (True, -1):
            with self.assertRaisesRegex(IntegrityError, "consume_clock"):
                self.rig.gate.consume(binding, lambda clock=clock: clock)
            self.assertIsNone(self.rig.gate.consumption(binding["session_id"]))
        self.rig.gate.consume(binding, self.rig.world.clock)
        with self.assertRaisesRegex(IntegrityError, "apply_hash"):
            self.rig.gate.apply_once(self.rig.plans[1].descriptor())

    def test_entire_ordered_artifact_set_and_review_marker_count(self):
        binding = self.rig.plans[0].descriptor()
        text = review_bytes(self.rig.items)
        line = next(
            line for line in text.splitlines() if self.rig.plans[1].plan_hash.encode() in line
        )
        for bad in (text.replace(line, b""), text.replace(line, line + b"\n" + line)):
            self.rig.gate.read_review = lambda *_, bad=bad: bad
            with self.assertRaisesRegex(IntegrityError, "marker_count"):
                self.rig.gate.marker(binding)
            self.assertEqual(self.rig.gate.markers, {})
        self.rig.gate.read_review = lambda *_: text
        saved = self.rig.gate.artifacts.copy()
        self.rig.gate.artifacts = dict(reversed(list(saved.items())))
        with self.assertRaisesRegex(IntegrityError, "ordered_artifacts"):
            self.rig.gate.marker(binding)
        self.rig.gate.artifacts = saved
        other = self.rig.items[1]
        self.rig.gate.artifacts[other.plan.plan_hash] = replace(other, review_commit="d" * 40)
        with self.assertRaisesRegex(IntegrityError, "shared_artifacts"):
            self.rig.gate.marker(binding)
        with self.assertRaisesRegex(IntegrityError, "artifacts_required"):
            FileGate(
                self.rig.root / "empty-artifacts", self.rig.gate.authority, [], lambda *_: text
            )
        with self.assertRaisesRegex(IntegrityError, "distinct_artifacts"):
            FileGate(
                self.rig.root / "duplicate-artifacts",
                self.rig.gate.authority,
                [other, other],
                lambda *_: text,
            )

    def test_changed_marker_application_pins_and_stored_receipt_refuse(self):
        binding = self.rig.plans[0].descriptor()
        self.rig.gate.marker(binding)
        state = self.rig.gate.store.read()
        state["values"]["marker/" + binding["plan_hash"]]["review_commit"] = "d" * 40
        self.rig.gate.store.write(state)
        with self.assertRaisesRegex(IntegrityError, "immutable_marker"):
            self.rig.gate.marker(binding)
        self.rig.gate.store.write(dict(state, values={}))
        self.rig.gate.marker(binding)
        self.rig.gate.consume(binding, self.rig.world.clock)
        state = self.rig.gate.store.read()
        original = state["values"]["marker/" + binding["plan_hash"]]
        state["values"]["marker/" + binding["plan_hash"]] = {}
        self.rig.gate.store.write(state)
        with self.assertRaisesRegex(IntegrityError, "apply_marker"):
            self.rig.gate.apply_once(binding)
        state["values"]["marker/" + binding["plan_hash"]] = original
        self.rig.gate.store.write(state)
        self.rig.responses.change = lambda q, a: (
            a["result"]["artifacts"].update(payload_sha256="0" * 64)
            if q["operation"] == "application.apply"
            else None
        )
        with self.assertRaisesRegex(IntegrityError, "application_artifacts"):
            self.rig.gate.apply_once(binding)
        self.rig.responses.change = None
        self.rig.gate.application(binding["session_id"])
        state = self.rig.gate.store.read()
        state["values"]["applied/" + binding["session_id"]]["plan_hash"] = "0" * 64
        self.rig.gate.store.write(state)
        with self.assertRaisesRegex(IntegrityError, "applied_binding"):
            self.rig.gate.apply_once(binding)

    def test_unavailable_application_holds_consumed_capacity_until_recovery(self):
        controller = self.prepared()
        self.rig.responses.change = lambda q, a: (
            a.update(status="ambiguous") if q["operation"] == "application.lookup" else None
        )
        with self.assertRaises(AuthorityUnavailable):
            controller.consume()
        self.assertEqual(
            self.rig.gate.consumption(controller.session_id)["plan_hash"],
            self.rig.plans[0].plan_hash,
        )
        self.assertFalse(self.rig.responses.capacity.cancelled)
        self.rig.responses.change = None
        self.rig.world.now = legacy.utc_ms(legacy.C) + 1
        state = self.rig.open().recover()
        self.assertEqual(state["sessions"], 1)
        self.assertIs(state["stopped"]["applied"], False)
        self.assertEqual(self.rig.capacity.group, [])

    def test_consume_directory_ack_loss_recovers_committed_session(self):
        controller = self.prepared()
        actual = durable.sync_directory

        def fail(path):
            if path == self.rig.gate.store.path:
                raise OSError("consume_directory_ack_lost")
            return actual(path)

        with patch.object(durable, "sync_directory", side_effect=fail):
            with self.assertRaises((OSError, IntegrityError)):
                controller.consume()
        self.rig.journal.close()
        self.rig.ports()
        state = self.rig.open().recover()
        self.assertEqual(state["sessions"], 1)
        self.assertIs(self.rig.open()._get("applied", 0), True)
        self.assertEqual(sum(n == "apply" for n, _ in self.rig.world.trace), 1)

    def test_operation_rebinding_member_shapes_and_cost_boundaries(self):
        from inference_platform.inf037b_ports import CapacityPort, Port

        for value in (0, False, -1):
            with self.assertRaisesRegex(IntegrityError, "cost_rate"):
                CapacityPort(
                    self.rig.root / ("bad-rate-" + str(value)), self.rig.capacity.authority, value
                )
        separate = Port(
            self.rig.root / "intent-control", self.rig.capacity.authority, initialize=True
        )
        with separate.store.lock():
            state = separate.store.read()
            separate.intent(state, "fixture", "key", {"x": 1})
            with self.assertRaisesRegex(IntegrityError, "operation_binding"):
                separate.intent(state, "fixture", "key", {"x": 2})
        for value in (None, ["id", "id"], [7]):
            self.rig.responses.change = lambda q, a, value=value: (
                a.update(result=value) if q["operation"] == "odcr.members" else None
            )
            with self.assertRaises(IntegrityError):
                self.rig.capacity.members(legacy.GROUP)
        self.rig.responses.change = None
        controller = self.prepared()
        token = controller._token(0)
        self.rig.capacity.cancel(token, legacy.GROUP)
        for t0 in (True, -1, self.rig.world.now + 1):
            with self.assertRaisesRegex(IntegrityError, "ledger_time"):
                self.rig.capacity.ledger(token, t0)

    def test_writer_process_exit_releases_fence_without_losing_rows(self):
        import subprocess
        import sys

        journal = self.journal()
        script = """
import os,sys
from inference_platform.inf037b_durable_ports import FileJournal
try:
    journal=FileJournal(sys.argv[1],lambda:0)
except BlockingIOError:
    print('fenced')
    raise SystemExit(0)
if sys.argv[2]=='blocked':
    raise SystemExit(1)
journal.append_fsync(dict(seq=1,event='bound',index=-1,data=[]))
os._exit(0)
"""
        result = subprocess.run(
            [sys.executable, "-c", script, str(journal.store.path), "blocked"],
            capture_output=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), b"fenced")
        journal.close()
        subprocess.run(
            [sys.executable, "-c", script, str(journal.store.path), "write"], check=True, timeout=10
        )
        reopened = durable.FileJournal(journal.store.path, self.rig.world.clock)
        self.addCleanup(reopened.close)
        self.assertEqual(reopened.read(), [{"seq": 1, "event": "bound", "index": -1, "data": []}])

    def test_short_write_and_corrupt_readback_never_acknowledge(self):
        journal = self.journal()
        actual = durable.Path.open

        class Short:
            def __init__(self, stream):
                self.stream = stream

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return self.stream.__exit__(*args)

            def write(self, data):
                return self.stream.write(data[:-1])

            def __getattr__(self, name):
                return getattr(self.stream, name)

        def opened(path, *args, **kwargs):
            result = actual(path, *args, **kwargs)
            return Short(result) if path.name.startswith("pending-") else result

        with patch.object(durable.Path, "open", opened):
            with self.assertRaisesRegex(IntegrityError, "short_write"):
                journal.append_fsync({"seq": 1, "event": "bound", "index": -1, "data": []})
        journal.close()
        reopened = durable.FileJournal(journal.store.path, self.rig.world.clock)
        self.addCleanup(reopened.close)
        self.assertEqual(reopened.read(), [])
        with patch.object(durable.Path, "read_bytes", return_value=b"corrupt_readback"):
            with self.assertRaisesRegex(IntegrityError, "write_readback"):
                reopened.store.write({"fixture": True})

    def test_malformed_reservation_acquisition_and_group_ack_refuse(self):
        controller = self.prepared()
        token = controller._token(0)
        for value in ({}, {"reservation_id": 7}):
            self.rig.responses.change = lambda q, a, value=value: (
                a.update(result=value)
                if q["operation"] in {"odcr.lookup", "odcr.acquire"}
                else None
            )
            with self.assertRaisesRegex(IntegrityError, "reservation_shape"):
                self.rig.capacity.lookup(token)
            with self.assertRaisesRegex(IntegrityError, "acquire_shape"):
                self.rig.capacity.acquire(token, self.rig.plans[0].capacity)
        self.rig.responses.change = lambda q, a: (
            a.update(result={}) if q["operation"] == "odcr.add" else None
        )
        with self.assertRaisesRegex(IntegrityError, "add_receipt"):
            self.rig.capacity.add(legacy.GROUP, "fixture-id")

    def test_backstop_absence_death_lost_reply_and_no_later_rearm(self):
        self.rig.world.crash_operation = "arm"
        with self.assertRaises(legacy.Crash):
            self.rig.run()
        self.rig.journal.close()
        self.rig.ports()
        self.rig.run()
        deadline = legacy.BASE + 18_000_000
        self.assertEqual(sum(name == "arm" for name, _ in self.rig.world.trace), 1)
        self.assertTrue(self.rig.backstop.arm("m5-offline", deadline))
        with self.assertRaisesRegex(IntegrityError, "immutable_backstop"):
            self.rig.backstop.arm("m5-offline", deadline + 1)
        self.rig.responses.backstop.confirm_ok = False
        self.assertFalse(self.rig.backstop.confirmed("m5-offline", deadline))
        self.assertFalse(self.rig.backstop.arm("m5-offline", deadline))
        self.rig.responses.backstop.armed.clear()
        self.assertFalse(self.rig.backstop.arm("m5-offline", deadline))
        self.assertEqual(sum(name == "arm" for name, _ in self.rig.world.trace), 1)
        self.assertEqual(
            sum(q["operation"] == "backstop.arm" for q in self.rig.responses.requests), 1
        )

    def test_backstop_binding_independence_and_expiration(self):
        with self.assertRaisesRegex(IntegrityError, "backstop_not_armed"):
            self.rig.backstop.confirmed("unarmed", self.rig.world.now + 100)
        with self.assertRaisesRegex(IntegrityError, "independent_backstop"):
            BackstopPort(
                self.rig.root / "same-owner",
                Authority("operator", "backstop", self.rig.responses),
                self.rig.world.clock,
                "operator",
            )
        with self.assertRaisesRegex(IntegrityError, "backstop_expired"):
            self.rig.backstop.arm("fixture", self.rig.world.now)
        deadline = self.rig.world.now + 10
        self.assertTrue(self.rig.backstop.arm("fixture", deadline))
        for key, value in (
            ("session_id", "wrong"),
            ("deadline_ms", deadline + 1),
            ("durable", False),
            ("arm_id", ""),
        ):
            self.rig.responses.change = lambda q, a, key=key, value=value: (
                a["result"].update({key: value}) if q["operation"] == "backstop.lookup" else None
            )
            with self.assertRaises(IntegrityError):
                self.rig.backstop.confirmed("fixture", deadline)
        self.rig.responses.change = None
        self.rig.world.now = deadline
        self.assertFalse(self.rig.backstop.confirmed("fixture", deadline))

    def test_real_backstop_peer_death_and_restart_cannot_rearm(self):
        import select
        import subprocess
        import sys

        script = """
import sys
from inference_platform.inf037b_authority import FencedAuthority
armed=None
def effect(operation,key,body):
    global armed
    armed=body
    return body
def read(operation,key,body):
    return None if armed is None else dict(armed,armed=True,alive=True,durable=True,arm_id='peer-arm')
def reconcile(operation,key,body):
    return dict(known=armed==body,executed=armed==body,result=body if armed==body else None)
service=FencedAuthority(sys.argv[1],'peer','backstop',effect=effect,read=read,reconcile=reconcile,initialize=sys.argv[2]=='new')
for raw in sys.stdin.buffer:
    sys.stdout.buffer.write(service(raw,2000))
    sys.stdout.buffer.flush()
"""
        peers = []

        def start():
            peer = subprocess.Popen(
                [
                    sys.executable,
                    "-u",
                    "-c",
                    script,
                    str(self.rig.root / "peer-authority"),
                    "new" if not peers else "open",
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            peers.append(peer)
            return peer

        def cleanup():
            for peer in peers:
                if peer.poll() is None:
                    peer.terminate()
                    peer.wait(timeout=5)
                for stream in (peer.stdin, peer.stdout, peer.stderr):
                    stream.close()

        self.addCleanup(cleanup)
        peer = start()
        operations = []

        def transport(raw, timeout):
            operations.append(json.loads(raw)["operation"])
            if peer.poll() is not None:
                raise OSError("independent_peer_dead")
            peer.stdin.write(raw)
            peer.stdin.flush()
            if not select.select([peer.stdout], [], [], timeout / 1000)[0]:
                raise TimeoutError("peer_reply_timeout")
            response = peer.stdout.readline()
            if not response:
                raise OSError("peer_closed")
            return response

        authority = Authority("peer", "backstop", transport)
        port = BackstopPort(
            self.rig.root / "peer-client",
            authority,
            self.rig.world.clock,
            "operator",
            initialize=True,
        )
        deadline = self.rig.world.now + 10_000
        self.assertTrue(port.arm("peer-session", deadline))
        port = BackstopPort(
            self.rig.root / "peer-client", authority, self.rig.world.clock, "operator"
        )
        self.assertTrue(port.arm("peer-session", deadline))
        peer.terminate()
        peer.wait(timeout=5)
        with self.assertRaisesRegex(OSError, "independent_peer_dead"):
            port.confirmed("peer-session", deadline)
        peer = start()
        self.assertFalse(port.arm("peer-session", deadline))
        self.assertEqual(operations.count("backstop.arm"), 1)

    def test_application_without_consumption_and_wrong_arm_ack_refuse(self):
        binding = self.rig.plans[0].descriptor()
        self.rig.responses.gate.applies[binding["session_id"]] = binding["plan_hash"]
        with self.assertRaisesRegex(IntegrityError, "application_without_consume"):
            self.rig.gate.application(binding["session_id"])
        self.rig.responses.change = lambda q, a: (
            a.update(result={}) if q["operation"] == "backstop.arm" else None
        )
        with self.assertRaisesRegex(IntegrityError, "arm_receipt"):
            self.rig.backstop.arm("wrong-ack", self.rig.world.now + 100)

    def wire(self, namespace, operation, key="fixture-token", sequence=0, body=None):
        service = self.rig.responses.services[namespace]
        return {
            "schema": "inf037b-authority-v1",
            "authority_id": service.identity,
            "namespace": namespace,
            "operation": operation,
            "key": key,
            "minimum_sequence": sequence,
            "nonce": "0" * 32,
            "body": body,
        }

    def test_authority_never_certifies_an_unseen_or_unsettled_fence(self):
        service = self.rig.responses.services["capacity"]
        request = self.wire("capacity", "odcr.lookup", sequence=1)
        with patch.object(service, "read", side_effect=AssertionError("unseen fence cannot read")):
            result = json.loads(service(encode(request), 100))
        self.assertEqual(
            (result["status"], result["complete"], result["settled_sequence"]),
            ("ambiguous", False, 0),
        )
        with patch.object(service, "effect", side_effect=OSError("before_effect_unknown")):
            with self.assertRaises(OSError):
                self.rig.capacity.acquire("fixture-token", self.rig.plans[0].capacity)
        self.rig.responses.attach(self.rig.root)
        self.assertIsNone(self.rig.capacity.lookup("fixture-token"))
        self.assertFalse(any(n == "odcr" for n, _ in self.rig.world.trace))

    def test_authority_reconciles_lost_effect_without_executing_it_again(self):
        self.rig.world.crash_operation = "odcr"
        with self.assertRaises(legacy.Crash):
            self.rig.capacity.acquire("fixture-token", self.rig.plans[0].capacity)
        self.rig.responses.attach(self.rig.root)
        self.rig.ports()
        first = self.rig.capacity.lookup("fixture-token")
        self.assertIsInstance(first, dict)
        second = self.rig.capacity.acquire("fixture-token", self.rig.plans[0].capacity)
        self.assertEqual(first, second)
        self.assertEqual(sum(n == "odcr" for n, _ in self.rig.world.trace), 1)
        state = self.rig.responses.services["capacity"].store.read()
        self.assertEqual(state["watermark"], 1)
        self.assertIsNone(state["pending"])

    def test_authority_application_ledger_overrules_a_lagging_downstream_read(self):
        self.rig.run()
        service = self.rig.responses.services["gate"]
        self.rig.responses.gate.applies.clear()
        with patch.object(service, "read", side_effect=AssertionError("lagging SDK view used")):
            result = self.rig.gate.application("m5-offline")
        self.assertEqual(
            result, {"session_id": "m5-offline", "plan_hash": self.rig.plans[0].plan_hash}
        )

    def test_authority_token_fence_rejects_lag_without_client_cached_receipt(self):
        service = self.rig.responses.services["capacity"]
        # Lose the acquisition acknowledgement before the client saves its ID.
        self.rig.world.crash_operation = "odcr"
        with self.assertRaises(legacy.Crash):
            self.rig.capacity.acquire("fixture-token", self.rig.plans[0].capacity)
        self.rig.responses.attach(self.rig.root)
        service = self.rig.responses.services["capacity"]
        self.rig.ports()
        self.assertEqual(self.rig.capacity.store.read()["values"], {})
        with patch.object(service, "read", return_value=None):
            with self.assertRaises(AuthorityUnavailable):
                self.rig.capacity.lookup("fixture-token")
        first = self.rig.capacity.lookup("fixture-token")
        with patch.object(service, "read", return_value=dict(first, reservation_id="other")):
            with self.assertRaises(AuthorityUnavailable):
                self.rig.capacity.authority.call("odcr.lookup", "fixture-token", 1, None)
        self.rig.capacity.cancel("fixture-token", legacy.GROUP)
        with patch.object(service, "read", return_value=first):
            with self.assertRaises(AuthorityUnavailable):
                self.rig.capacity.authority.call("odcr.lookup", "fixture-token", 2, None)
        self.rig.responses.capacity.outcomes = ["refused"]
        self.assertIsNone(self.rig.capacity.acquire("refused-token", self.rig.plans[0].capacity))
        with patch.object(service, "read", return_value=first):
            with self.assertRaises(AuthorityUnavailable):
                self.rig.capacity.lookup("refused-token")

    def test_authority_request_identity_schema_nonce_and_bounds(self):
        service = self.rig.responses.services["capacity"]
        request = self.wire("capacity", "odcr.lookup")
        before = service.store.read()
        for field, value, reason in (
            ("schema", "wrong", "schema"),
            ("authority_id", "other", "identity"),
            ("namespace", "other", "binding"),
            ("operation", "unknown", "operation"),
            ("key", "", "key"),
            ("nonce", "invalid", "nonce"),
            ("minimum_sequence", True, "sequence"),
            ("minimum_sequence", -1, "sequence"),
        ):
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(IntegrityError, "authority:" + reason),
            ):
                service(encode(dict(request, **{field: value})), 100)
        with self.assertRaisesRegex(IntegrityError, "request_keys"):
            service(encode(dict(request, extra=1)), 100)
        for timeout in (0, 10001):
            with self.assertRaisesRegex(IntegrityError, "authority:timeout"):
                service(encode(request), timeout)
        self.assertEqual(service.store.read(), before)
        from inference_platform.inf037b_authority import FencedAuthority

        with self.assertRaisesRegex(IntegrityError, "authority:namespace"):
            FencedAuthority(
                self.rig.root / "invalid-server",
                "fixture",
                "unknown",
                effect=None,
                read=None,
                reconcile=None,
            )

    def test_authority_reconciliation_needs_an_explicit_known_receipt(self):
        service = self.rig.responses.services["capacity"]
        with patch.object(service, "effect", side_effect=OSError("effect_unknown")):
            with self.assertRaises(OSError):
                self.rig.capacity.acquire("fixture-token", self.rig.plans[0].capacity)
        query = self.wire("capacity", "odcr.lookup", sequence=1)
        for known in (False, 1):
            with patch.object(
                service,
                "reconcile",
                return_value={"known": known, "executed": False, "result": None},
            ):
                answer = json.loads(service(encode(query), 100))
            self.assertEqual(answer["status"], "ambiguous")
            self.assertEqual(answer["settled_sequence"], 0)
        with patch.object(service, "reconcile", return_value={"known": False}):
            with self.assertRaisesRegex(IntegrityError, "reconciliation_shape"):
                service(encode(query), 100)
        with patch.object(
            service, "reconcile", return_value={"known": True, "executed": False, "result": None}
        ):
            answer = json.loads(service(encode(query), 100))
        self.assertEqual(
            (answer["status"], answer["settled_sequence"], answer["result"]), ("confirmed", 1, None)
        )

    def test_authority_effect_sequences_and_duplicate_body_binding(self):
        service = self.rig.responses.services["capacity"]
        request = self.wire("capacity", "odcr.acquire", body=vars(self.rig.plans[0].capacity))
        for sequence in (0, 2):
            with self.assertRaisesRegex(IntegrityError, "next_sequence"):
                service(encode(dict(request, minimum_sequence=sequence)), 100)
        request["minimum_sequence"] = 1
        first = json.loads(service(encode(request), 100))["result"]
        self.assertEqual(json.loads(service(encode(request), 100))["result"], first)
        with self.assertRaisesRegex(IntegrityError, "idempotent_sequence"):
            service(encode(dict(request, minimum_sequence=2)), 100)
        with self.assertRaisesRegex(IntegrityError, "idempotent_binding"):
            service(encode(dict(request, body=vars(self.rig.plans[1].capacity))), 100)
        self.assertEqual(sum(n == "odcr" for n, _ in self.rig.world.trace), 1)

    def test_authority_lost_directory_ack_recovers_without_reexecuting(self):
        service = self.rig.responses.services["capacity"]
        actual_write, actual_sync = service.store.write, durable.sync_directory

        def directory(path):
            if path == service.store.path:
                raise OSError("authority_directory_ack_lost")
            return actual_sync(path)

        def write(state):
            if state["pending"] is None and state["completed"]:
                with patch.object(durable, "sync_directory", side_effect=directory):
                    return actual_write(state)
            return actual_write(state)

        with patch.object(service.store, "write", side_effect=write):
            with self.assertRaisesRegex(OSError, "authority_directory_ack_lost"):
                self.rig.capacity.acquire("fixture-token", self.rig.plans[0].capacity)
        self.rig.responses.attach(self.rig.root)
        result = self.rig.capacity.lookup("fixture-token")
        self.assertIsInstance(result, dict)
        self.assertEqual(sum(n == "odcr" for n, _ in self.rig.world.trace), 1)

    def lost_case(self, operation, mode="drop", *, expire=False, outcome="ok", cut=None):
        rig = Rig()
        self.addCleanup(rig.close)
        rig.responses.capacity.outcomes = [outcome, "ok"]
        controller = rig.open()
        controller.mark()
        if operation in {"odcr.cancel", "application.apply"}:
            controller.acquire()
        rig.responses.cut_operation = operation
        rig.responses.cut_mode = mode
        with self.assertRaises(legacy.Crash):
            if operation == "odcr.cancel":
                controller.refuse("operator_stop")
            elif operation == "application.apply":
                controller.consume()
            else:
                controller.acquire()
        original = rig.responses.lost_request
        self.assertIsNotNone(original)
        rig.journal.close()
        rig.responses.attach(rig.root)
        rig.ports()
        if expire:
            rig.world.now = legacy.utc_ms(legacy.D) + 1
        recovery_start = len(rig.journal.rows)
        if cut is not None:
            rig.journal.cut = len(rig.journal.rows) + cut
            try:
                rig.open().recover()
            except legacy.Crash:
                pass
            rig.journal.cut = None
            rig.journal.close()
            rig.responses.attach(rig.root)
            rig.ports()
        rig.open().recover()
        rig.recovery_row_count = len(rig.journal.rows) - recovery_start
        current = rig.open()
        if operation == "backstop.arm":
            self.assertFalse(rig.responses.capacity.results)
            self.assertFalse(rig.responses.gate.applies)
        else:
            events = [row["event"] for row in rig.journal.rows]
            positions = [events.index(name) for name in ("cancelled", "ledger", "advanced")]
            self.assertEqual(positions, sorted(positions))
            self.assertIsNotNone(current._get("advanced", 0))
            for reservation in rig.responses.capacity.results.values():
                if reservation is not None:
                    self.assertEqual(reservation["state"], "cancelled")
            ledger = current._get("ledger", 0)
            self.assertEqual(
                ledger["stop_ms"], rig.capacity.cancellation(current._token(0))["stop_ms"]
            )
            if outcome == "partial" and operation == "odcr.add":
                self.assertGreater(ledger["cost_micros"], 0)
        if operation == "application.apply":
            self.assertEqual(current.status()["sessions"], 1)
            self.assertFalse(current.status()["stopped"]["applied"])
            self.assertFalse(rig.responses.gate.applies)
        effects = [n for n, _ in rig.world.trace if n in {"odcr", "add", "cancel", "apply", "arm"}]
        for effect in set(effects):
            self.assertLessEqual(effects.count(effect), 1, (operation, mode, rig.world.trace))
        before = list(rig.world.trace)
        rig.responses(original, 2000)
        self.assertEqual(rig.world.trace, before, "late original executed after settlement")
        from inf037b_ports_support import RECOVERY_CASES

        RECOVERY_CASES.append(
            {
                "operation": operation,
                "cut_mode": mode,
                "recovery_row_cut": cut,
                "expired": expire,
                "outcome": outcome,
                "journal": rig.journal.rows,
                "provider_effects": rig.world.trace,
                "authority_ledgers": {
                    name: a.store.read() for name, a in rig.responses.services.items()
                },
                "original_request_utf8": original.decode(),
                "late_original_no_effect": True,
                "raw_request_response_records": rig.responses.records,
            }
        )
        return rig

    def cancel_verification_case(self, *, die=False):
        rig = self.rig
        provider = rig.responses.capacity
        provider.outcomes = ["partial", "ok"]
        provider.cancel_ok = False
        c = rig.open()
        c.mark()
        if die:
            rig.responses.cut_operation = "odcr.cancel"
            rig.responses.cut_mode = "authority_death_after_effect"
            with self.assertRaises(legacy.Crash):
                c.acquire()
            original = rig.responses.lost_request
        else:
            with self.assertRaises((AuthorityUnavailable, IntegrityError)):
                c.acquire()
            original = next(
                r["request_utf8"].encode()
                for r in rig.responses.records
                if json.loads(r["request_utf8"])["operation"] == "odcr.cancel"
            )
        token = c._token(0)
        stop = provider.cancelled[token]["stop_ms"]
        service = rig.responses.services["capacity"]
        pending = service.store.read()["pending"]
        self.assertIsNotNone(pending, "unverified cancel must remain pending")
        self.assertEqual(pending["operation"], "odcr.cancel")
        self.assertNotIn(pending["operation_key"], service.store.read()["completed"])
        self.assertEqual(service.store.read()["watermark"], pending["sequence"] - 1)
        rig.journal.close()
        rig.responses.attach(rig.root)
        rig.ports()
        service = rig.responses.services["capacity"]
        before = list(rig.world.trace)
        reply = json.loads(rig.responses(original, 2000))
        self.assertEqual((reply["status"], reply["complete"]), ("ambiguous", False))
        self.assertEqual(service.store.read()["pending"], pending)
        self.assertEqual(rig.world.trace, before)
        with self.assertRaises((AuthorityUnavailable, IntegrityError)):
            rig.open().recover()
        self.assertIsNone(rig.capacity.cancellation(token))
        self.assertFalse(
            any(r["event"] in {"cancelled", "ledger", "advanced"} for r in rig.journal.rows)
        )
        self.assertEqual(sum(n == "odcr" for n, _ in rig.world.trace), 1)
        rig.world.now += 2000
        provider.cancelled[token]["verified"] = True
        recovered = rig.open()
        recovered.recover()
        events = [r["event"] for r in rig.journal.rows]
        self.assertLess(events.index("cancelled"), events.index("ledger"))
        self.assertLess(events.index("ledger"), events.index("advanced"))
        ledger = recovered._get("ledger", 0)
        self.assertEqual(ledger["stop_ms"], stop)
        self.assertEqual(rig.capacity.cancellation(token)["stop_ms"], stop)
        self.assertGreater(ledger["cost_micros"], 0)
        self.assertIsNone(service.store.read()["pending"])
        completed = service.store.read()["completed"][pending["operation_key"]]
        self.assertEqual({k: completed[k] for k in pending}, pending)
        self.assertEqual(completed["result"]["stop_ms"], stop)
        before = list(rig.world.trace)
        late = json.loads(rig.responses(original, 2000))
        self.assertEqual(late["status"], "confirmed")
        self.assertEqual(rig.world.trace, before, "late original cancel ran an effect")
        self.assertEqual(rig.capacity.lookup("unrelated-token"), None)
        from inf037b_ports_support import CANCEL_CASES

        CANCEL_CASES.append(
            {
                "authority_death_after_unverified_effect": die,
                "pending": pending,
                "unverified_reply": reply,
                "provider_stop_ms": stop,
                "cancel_receipt": rig.capacity.cancellation(token),
                "ledger": ledger,
                "journal": rig.journal.rows,
                "authority_ledger": service.store.read(),
                "provider_effects": rig.world.trace,
                "late_original_no_effect": True,
                "raw_request_response_records": rig.responses.records,
            }
        )
        recovered.acquire()
        self.assertEqual(recovered.consume()["sessions"], 1)

    def test_cancel_verification_blocks_advance_and_recovery_records_cost(self):
        self.cancel_verification_case()

    def test_unverified_cancel_authority_death_recovers_original_stop_and_cost(self):
        self.cancel_verification_case(die=True)

    def test_invalid_cancel_results_remain_pending_on_effect_and_reconcile(self):
        service = self.rig.responses.services["capacity"]
        original_effect = service.effect
        faults = [
            None,
            [],
            {},
            {"verified": False},
            {"verified": 1},
            {"complete": False},
            {"complete": 1},
            {"reservation_ids": [], "states": {}},
            {"reservation_ids": ["", "cr-expected"]},
            {"reservation_ids": ["cr-expected", "cr-expected"]},
            {"reservation_ids": "cr-expected"},
            {"reservation_ids": {"cr-expected": "cancelled"}},
            {"states": {"cr-expected": "active"}},
            {"stop_ms": -1},
            {"stop_ms": True},
            {"stop_ms": "10"},
        ]
        for mode in ("fresh", "reconcile", "identical_retry"):
            for index, fault in enumerate(faults):
                with self.subTest(mode=mode, fault=fault):
                    valid = {
                        "verified": True,
                        "complete": True,
                        "reservation_ids": ["cr-expected"],
                        "states": {"cr-expected": "cancelled"},
                        "stop_ms": 10,
                    }
                    invalid = dict(valid, **fault) if isinstance(fault, dict) and fault else fault
                    key = f"cancel-{mode}-{index}"
                    before = service.store.read()
                    request = self.wire(
                        "capacity",
                        "odcr.cancel",
                        key=key,
                        sequence=before["watermark"] + 1,
                        body={"group": legacy.GROUP, "expected_ids": ["cr-expected"]},
                    )
                    raw = encode(request)
                    if mode != "fresh":
                        with patch.object(
                            service, "effect", side_effect=OSError("effect reply lost")
                        ):
                            with self.assertRaises(OSError):
                                service(raw, 100)
                    if mode == "reconcile":
                        reconciliation = {"known": True, "executed": True, "result": invalid}
                    else:
                        reconciliation = {"known": True, "executed": False, "result": None}
                    with (
                        patch.object(service, "effect", return_value=invalid) as effect,
                        patch.object(service, "reconcile", return_value=reconciliation),
                    ):
                        answer = json.loads(service(raw, 100))
                    self.assertEqual(
                        (answer["status"], answer["complete"], answer["result"]),
                        ("ambiguous", False, None),
                    )
                    state = service.store.read()
                    self.assertEqual(state["watermark"], before["watermark"])
                    self.assertEqual(state["completed"], before["completed"])
                    self.assertEqual(state["pending"]["body"], request["body"])
                    self.assertEqual(state["pending"]["sequence"], request["minimum_sequence"])
                    if mode == "reconcile":
                        effect.assert_not_called()
                    else:
                        effect.assert_called_once_with("odcr.cancel", key, request["body"])
                    with patch.object(
                        service,
                        "reconcile",
                        return_value={"known": True, "executed": True, "result": valid},
                    ):
                        accepted = json.loads(service(raw, 100))
                    self.assertEqual(accepted["status"], "confirmed")
                    self.assertEqual(accepted["result"], valid)
                    self.assertIsNone(service.store.read()["pending"])
        self.assertEqual(service.effect, original_effect)

    def test_delayed_original_apply_before_settle_is_fenced_after_authority_restart(self):
        rig = self.rig
        c = self.prepared()
        rig.responses.cut_operation = "application.apply"
        rig.responses.cut_mode = "authority_death"
        with self.assertRaises(legacy.Crash):
            c.consume()
        original = rig.responses.lost_request
        rig.journal.close()
        rig.responses.attach(rig.root)
        rig.ports()
        service = rig.responses.services["gate"]
        pending = service.store.read()["pending"]
        self.assertEqual(pending["operation"], "application.apply")
        # Deliver the original while still pending, before any intent.settle.
        before_requests = len(rig.responses.requests)
        answer = json.loads(rig.responses(original, 2000))
        self.assertFalse(
            any(q["operation"] == "intent.settle" for q in rig.responses.requests[before_requests:])
        )
        self.assertEqual(
            (answer["status"], answer["executed"], answer["result"]), ("confirmed", False, None)
        )
        self.assertFalse(rig.responses.gate.applies)
        self.assertIsNone(service.store.read()["pending"])
        self.assertFalse(service.store.read()["completed"][pending["operation_key"]]["executed"])
        recovered = rig.open()
        recovered.recover()
        stopped = recovered.status()["stopped"]
        self.assertTrue(stopped["session_consumed"])
        self.assertFalse(stopped["applied"])
        events = [r["event"] for r in rig.journal.rows]
        self.assertLess(events.index("cancelled"), events.index("ledger"))
        self.assertLess(events.index("ledger"), events.index("advanced"))
        self.assertEqual(rig.responses.capacity.results[c._token(0)]["state"], "cancelled")
        self.assertFalse(any(n == "apply" for n, _ in rig.world.trace))
        from inf037b_ports_support import DELAYED_APPLY_CASES

        DELAYED_APPLY_CASES.append(
            {
                "pending_before_original": pending,
                "original_request_utf8": original.decode(),
                "answer_before_settle": answer,
                "journal": rig.journal.rows,
                "authority_ledgers": {
                    name: a.store.read() for name, a in rig.responses.services.items()
                },
                "provider_effects": rig.world.trace,
                "raw_request_response_records": rig.responses.records,
            }
        )

    def test_lost_acquire_request_is_fenced_and_cleanup_advances(self):
        self.lost_case("odcr.acquire")

    def test_lost_add_request_is_fenced_and_cleanup_advances(self):
        self.lost_case("odcr.add")

    def test_lost_cancel_request_retries_identically_and_advances(self):
        rig = self.lost_case("odcr.cancel")
        original = json.loads(rig.responses.lost_request)
        retries = [
            q
            for q in rig.responses.requests
            if q["operation"] == "intent.settle" and q["body"]["operation"] == "odcr.cancel"
        ]
        self.assertTrue(retries)
        self.assertTrue(
            all(
                q["key"] == original["key"]
                and q["minimum_sequence"] == original["minimum_sequence"]
                and q["body"]["body"] == original["body"]
                for q in retries
            )
        )

    def test_lost_apply_request_is_fenced_consumed_stop_and_cleanup(self):
        for expire in (False, True):
            with self.subTest(expire=expire):
                self.lost_case("application.apply", expire=expire)

    def test_lost_arm_request_refuses_before_odcr_without_rearm(self):
        rig = self.lost_case("backstop.arm")
        completed = list(rig.responses.services["backstop"].store.read()["completed"].values())
        self.assertEqual(len(completed), 1)
        self.assertIs(completed[0]["executed"], False)

    def test_effect_delivery_and_authority_death_recovery_cut_matrix(self):
        for operation in (
            "odcr.acquire",
            "odcr.add",
            "odcr.cancel",
            "application.apply",
            "backstop.arm",
        ):
            for mode in ("drop", "authority_death"):
                with self.subTest(operation=operation, mode=mode, recovery_row_cut=None):
                    baseline = self.lost_case(operation, mode)
                for cut in range(1, baseline.recovery_row_count + 1):
                    with self.subTest(operation=operation, mode=mode, recovery_row_cut=cut):
                        self.lost_case(operation, mode, cut=cut)

    def test_lost_add_after_partial_acquire_preserves_positive_ledger(self):
        # Partial acquisition normally rejects before add; crash the pending
        # acquire after its billable partial effect, then recover and reject.
        rig = self.rig
        rig.responses.capacity.outcomes = ["partial", "ok"]
        c = rig.open()
        c.mark()
        rig.world.crash_operation = "odcr"
        with self.assertRaises(legacy.Crash):
            c.acquire()
        rig.responses.attach(rig.root)
        rig.ports()
        rig.open().recover()
        c = rig.open()
        self.assertEqual(rig.responses.capacity.lookup(c._token(0))["state"], "cancelled")
        self.assertGreater(c._get("ledger", 0)["cost_micros"], 0)
        # Also exercise a billed, rejected acquisition whose add is undelivered.
        self.lost_case("odcr.add")

    def test_omitted_after_cancel_uses_durable_stop_and_advances(self):
        c = self.prepared()
        service = self.rig.responses.services["capacity"]
        read = service.read

        def omitted(operation, key, body):
            value = read(operation, key, body)
            if operation == "odcr.lookup" and value is not None and value["state"] == "cancelled":
                return None
            return value

        with patch.object(service, "read", side_effect=omitted):
            c.refuse("operator_stop")
            self.rig.open().recover()
        c = self.rig.open()
        receipt = self.rig.capacity.cancellation(c._token(0))
        self.assertEqual(c._get("ledger", 0)["stop_ms"], receipt["stop_ms"])
        self.assertIsNotNone(c._get("advanced", 0))
        # The client itself permits confirmed None only with its durable receipt.
        self.rig.responses.change = lambda q, a: (
            a.update(result=None) if q["operation"] == "odcr.lookup" else None
        )
        self.assertIsNone(self.rig.capacity.lookup(c._token(0)))
        state = self.rig.capacity.store.read()
        del state["values"]["cancel/" + c._token(0)]
        self.rig.capacity.store.write(state)
        # Isolate the lookup guard from settlement, which can restore the receipt.
        with patch.object(self.rig.capacity, "settle", return_value=None):
            state["operations"] = {}
            self.rig.capacity.store.write(state)
            with self.assertRaisesRegex(IntegrityError, "reservation_disappeared"):
                self.rig.capacity.lookup(c._token(0))

    def test_settlement_binding_namespace_and_retry_policy(self):
        service = self.rig.responses.services["capacity"]
        body = {
            "operation": "odcr.acquire",
            "body": vars(self.rig.plans[0].capacity),
            "retry": False,
        }
        request = self.wire("capacity", "intent.settle", sequence=1, body=body)
        answer = json.loads(service(encode(request), 100))
        self.assertEqual(
            (answer["status"], answer["result"], answer["executed"]), ("confirmed", None, False)
        )
        for change, reason in (
            ({"retry": True}, "cancel_only"),
            ({"retry": 1}, "settlement_retry"),
            ({"operation": "application.apply"}, "settlement_effect"),
            ({"extra": 1}, "settlement_shape"),
        ):
            with self.subTest(change=change), self.assertRaisesRegex(IntegrityError, reason):
                service(encode(dict(request, body=dict(body, **change))), 100)
        cancel = dict(
            body, operation="odcr.cancel", body={"expected_ids": [], "group": legacy.GROUP}
        )
        with self.assertRaisesRegex(IntegrityError, "settlement_cancel_retry"):
            service(encode(dict(request, body=cancel)), 100)
        for change, reason in (
            ({"minimum_sequence": 2}, "idempotent_sequence"),
            ({"body": dict(body, body={})}, "idempotent_binding"),
        ):
            with self.assertRaisesRegex(IntegrityError, reason):
                service(encode(dict(request, **change)), 100)

    def test_known_not_executed_requires_boolean_and_empty_result(self):
        service = self.rig.responses.services["capacity"]
        with patch.object(service, "effect", side_effect=OSError("before_effect")):
            with self.assertRaises(OSError):
                self.rig.capacity.acquire("fixture-token", self.rig.plans[0].capacity)
        query = self.wire("capacity", "odcr.lookup", sequence=1)
        for executed, result, reason in (
            (0, None, "reconciliation_execution"),
            (False, {}, "not_executed_result"),
        ):
            with patch.object(
                service,
                "reconcile",
                return_value={"known": True, "executed": executed, "result": result},
            ):
                with self.assertRaisesRegex(IntegrityError, reason):
                    service(encode(query), 100)
        with patch.object(
            service, "reconcile", return_value={"known": True, "executed": False, "result": None}
        ):
            answer = json.loads(service(encode(query), 100))
        self.assertEqual(answer["status"], "confirmed")
        self.assertIsNone(self.rig.capacity.acquire("fixture-token", self.rig.plans[0].capacity))
        self.assertFalse(any(n == "odcr" for n, _ in self.rig.world.trace))

    def test_fenced_apply_requires_explicit_execution_proof(self):
        for execution in (None, False):
            rig = Rig()
            self.addCleanup(rig.close)
            c = rig.open()
            c.mark()
            c.acquire()

            def changed(q, a, execution=execution):
                if q["operation"] == "application.apply":
                    a["executed"] = execution

            rig.responses.change = changed
            with self.subTest(execution=execution), self.assertRaises(AuthorityUnavailable):
                c.consume()
            self.assertFalse(rig.responses.capacity.cancelled)
            rig.responses.change = None
            rig.open().recover()
            self.assertTrue(rig.gate.applies)

    def replay(self, name):
        with patch.object(legacy, "Rig", Rig):
            stream = io.StringIO()
            case = legacy.ControllerTests(name)
            result = unittest.TextTestRunner(stream=stream).run(case)
            self.assertEqual(result.skipped, [], stream.getvalue())
            self.assertTrue(result.wasSuccessful(), stream.getvalue())

    def test_accepted_row_cut_and_every_public_call_matrix(self):
        self.replay("test_crash_cut_at_every_row_and_every_public_call_after_reopen")

    def test_accepted_external_effect_cut_matrix(self):
        self.replay("test_external_effect_crash_before_ack_recovers_once")

    def test_accepted_recover_alone_row_cut_matrix(self):
        self.replay("test_recover_alone_from_every_journal_cut_resumes_only_pending_operation")

    def test_accepted_consumed_stop_cleanup_row_cut_matrix(self):
        self.replay("test_post_consume_stop_recovers_alone_after_every_cleanup_row")

    def test_accepted_no_origin_cleanup_row_cut_matrix(self):
        self.replay("test_no_origin_stop_recovers_alone_through_advance")

    def test_v4_84_to_90_in_both_saved_az_orders(self):
        cases = [
            "test_DEC_069_billing_origin_and_effective_deadline",
            "test_Two_reviewed_AZ_plans_with_two_distinct_plan_hash_markers",
            "test_Every_reviewed_AZ_alternative_refuses",
            "test_An_alternative_whose_literal_C_or_D_session_differs",
            "test_A_reservation_is_partly_acquired_then_fails_verification",
            "test_Independent_backstop_arming_is_not_confirmed",
            "test_The_full_remaining_work_check_fails_immediately_before_consume",
        ]
        for reverse in (False, True):

            def factory(reverse=reverse):
                rig = Rig()
                if reverse:
                    rig.plans.reverse()
                    rig.ports()
                return rig

            for name in cases:
                with self.subTest(order="ba" if reverse else "ab", fixture=name):
                    with patch.object(legacy, "Rig", factory):
                        stream = io.StringIO()
                        result = unittest.TextTestRunner(stream=stream).run(
                            legacy.ControllerTests(name)
                        )
                        self.assertEqual(result.skipped, [], stream.getvalue())
                        self.assertTrue(result.wasSuccessful(), stream.getvalue())


class PlatformTests(unittest.TestCase):
    def test_unsupported_platform_refuses_before_any_filesystem_effect(self):
        with (
            patch.object(durable, "os", SimpleNamespace(name="nt")),
            patch.object(durable.Path, "mkdir") as mkdir,
        ):
            with self.assertRaisesRegex(OSError, "posix_directory_durability_required"):
                durable.DurableStore("unused-offline-path", {})
            mkdir.assert_not_called()


def load_tests(loader, tests, pattern):
    suite = loader.loadTestsFromTestCase(PlatformTests)
    if os.name == "posix":
        suite.addTests(loader.loadTestsFromTestCase(PortsTests))
    return suite


if __name__ == "__main__":
    unittest.main()
