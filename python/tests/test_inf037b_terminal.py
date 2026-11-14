"""Terminal adapter fakes, adversarial replay and nonmutating snapshot rehearsal."""

import copy
import os
import time
import unittest
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory

from inference_platform.inf037b_archive import IntegrityError, encode, sha
from inference_platform.inf037b_terminal import (
    INVENTORIES,
    CleanupScope,
    SnapshotBackend,
    SnapshotCapacity,
    SnapshotProducer,
    TerminalAdapters,
    rehearse,
)

CASES = []


class Cut(BaseException):
    pass


class MemoryStore:
    def __init__(self):
        self.state = {"binding": None}
        self.writes, self.cut = 0, None
        self.locked = False

    @contextmanager
    def lock(self):
        assert not self.locked
        self.locked = True
        try:
            yield
        finally:
            self.locked = False

    def read(self):
        return copy.deepcopy(self.state)

    def write(self, state):
        self.state = copy.deepcopy(state)
        self.writes += 1
        if self.writes == self.cut:
            self.cut = None
            raise Cut("durable write cut")


class Backend:
    def __init__(self, scope):
        self.scope = scope.descriptor()
        self.resources = {c: [{"id": c + "-fixture"}] for c in INVENTORIES}
        self.resources["instances"] = [{"id": i, "state": "running"} for i in scope.instance_ids]
        self.resources["reservations"] = [{"id": "cr-fixture", "state": "active"}]
        self.requests, self.executions, self.visits = {}, [], []
        self.fail, self.lost, self.cut_after = None, None, None
        self.shutting_down, self.omit_instance = False, False
        self.bad_inventory, self.bad_export = None, None
        self.member_checks = []
        self.now = 100

    def effect(self, label, key, body, stop):
        request = {"label": label, "body": body, "stop": stop}
        if key in self.requests:
            assert self.requests[key][0] == request
            return copy.deepcopy(self.requests[key][1])
        if self.fail == label:
            raise OSError("offline effect failure:" + label)
        if label == "delete_capacity_group":
            assert self.member_checks and self.member_checks[-1] == []
        self.executions.append(label)
        if label == "delete_nodes":
            for row in self.resources["instances"]:
                row["state"] = "shutting-down" if self.shutting_down else "terminated"
            if self.omit_instance:
                self.resources["instances"].pop()
        elif label.startswith("delete_"):
            category = label.removeprefix("delete_")
            self.resources[category] = []
            if category == "nlb":
                self.resources["target_groups"] = []
        result = {"accepted": True, "request_key": key, "body_sha256": sha(encode(body))}
        if label in {"export", "preserve_state"}:
            result.update(
                verified=True,
                manifest_sha256=sha(encode(self.resources)),
                destination=self.scope["state_destination"],
            )
            if self.bad_export:
                result[self.bad_export[0]] = self.bad_export[1]
        self.requests[key] = (copy.deepcopy(request), copy.deepcopy(result))
        if self.cut_after == label:
            self.cut_after = None
            raise Cut("effect cut")
        if self.lost == label:
            self.lost = None
            raise OSError("lost accepted reply")
        return result

    def inventory(self, category, scope, stop):
        self.visits.append(category)
        if self.bad_inventory == category:
            raise OSError("inventory unavailable")
        return {
            "complete": True,
            "scope_sha256": sha(encode(scope)),
            "resources": copy.deepcopy(self.resources[category]),
        }


class Capacity:
    def __init__(self, backend):
        self.backend = backend
        self.receipts, self.calls = {}, []
        self.cancel_invocations = []
        self.unknown, self.extra = False, False

    def cancel(self, token, group):
        self.cancel_invocations.append((token, group))
        if self.unknown:
            raise OSError("authority unknown")
        if token not in self.receipts:
            self.calls.append((token, group))
            self.backend.resources["reservations"][0]["state"] = "cancelled"
            self.receipts[token] = {
                "verified": True,
                "complete": True,
                "reservation_ids": ["cr-fixture"],
                "states": {"cr-fixture": "cancelled"},
                "stop_ms": self.backend.now,
            }
        return copy.deepcopy(self.receipts[token])

    def cancellation(self, token):
        return copy.deepcopy(self.receipts.get(token))

    def ledger(self, token, t0):
        stop = self.receipts[token]["stop_ms"]
        return {
            "t0_ms": t0,
            "stop_ms": stop,
            "billed_ms": stop - t0,
            "cost_micros": 2 * (stop - t0),
        }

    def members(self, group):
        result = ["cr-intruder"] if self.extra else []
        self.backend.member_checks.append(result)
        return result


class TerminalTests(unittest.TestCase):
    def snapshot_port(self):
        backend = Backend(self.scope)
        original = copy.deepcopy(backend.resources)

        class ReadOnly:
            def inventory(inner, category, scope, stop):
                return backend.inventory(category, scope, stop)

            def capacity_inventory(inner, scope, stop):
                return {
                    "complete": True,
                    "scope_sha256": sha(encode(scope)),
                    "tokens": {self.scope.tokens[0]: ["cr-fixture"]},
                    "members": ["cr-fixture"],
                }

            def effect(inner, *args):
                raise AssertionError("snapshot producer attempted a write")

        return ReadOnly(), backend, original

    def test_module_snapshot_rehearsal_deletes_only_model_and_preserves_original_bytes(self):
        port, live, original = self.snapshot_port()
        snapshot = SnapshotProducer(port, lambda: live.now).produce(self.scope, 10000)
        before = bytes(snapshot)
        model = SnapshotBackend(snapshot)
        capacity = SnapshotCapacity(model)
        result = rehearse(snapshot, backend=model, capacity=capacity)
        self.assertEqual(snapshot, before)
        self.assertEqual(live.resources, original)
        self.assertEqual(live.executions, [])
        self.assertEqual(live.visits, list(INVENTORIES))
        self.assertTrue(result["snapshot_unchanged"])
        self.assertEqual(result["report"]["errors"], [])
        self.assertEqual(set(result["report"]["inventories"]), set(INVENTORIES))
        actions = result["actions"]
        self.assertLess(actions.index("delete_nodes"), actions.index("cancel:original-token"))
        self.assertLess(actions.index("cancel:original-token"), actions.index("delete_cluster"))
        self.assertEqual(actions[-1], "delete_bootstrap")
        self.assertEqual(capacity.members(self.scope.group), [])
        self.assertGreaterEqual(result["wall_ms"], 0)
        self.assertEqual(rehearse(snapshot)["report"], result["report"])
        CASES.append({"case": "module_snapshot_rehearsal", "result": result})

    def test_module_rehearsal_refuses_live_types_and_model_subclasses_before_calls(self):
        from inference_platform.inf037b_ports import CapacityPort

        port, live, original = self.snapshot_port()
        snapshot = SnapshotProducer(port, lambda: live.now).produce(self.scope, 10000)

        class DerivedBackend(SnapshotBackend):
            pass

        class DerivedCapacity(SnapshotCapacity):
            pass

        for backend in (live, DerivedBackend(snapshot)):
            with (
                self.subTest(backend=type(backend).__name__),
                self.assertRaisesRegex(IntegrityError, "model_backend"),
            ):
                rehearse(snapshot, backend=backend)
        model = SnapshotBackend(snapshot)
        for capacity in (
            Capacity(live),
            CapacityPort.__new__(CapacityPort),
            DerivedCapacity(model),
        ):
            with (
                self.subTest(capacity=type(capacity).__name__),
                self.assertRaisesRegex(IntegrityError, "model_capacity"),
            ):
                rehearse(snapshot, backend=model, capacity=capacity)
        with self.assertRaisesRegex(IntegrityError, "capacity_model_binding"):
            rehearse(snapshot, backend=model, capacity=SnapshotCapacity(SnapshotBackend(snapshot)))
        with self.assertRaisesRegex(IntegrityError, "snapshot_bytes"):
            rehearse(bytearray(snapshot))
        self.assertEqual(live.resources, original)
        self.assertEqual(live.executions, [])

    def test_snapshot_producer_refuses_incomplete_unknown_unbound_and_late_reads(self):
        port, live, original = self.snapshot_port()
        for category in INVENTORIES:
            live.bad_inventory = category
            with self.subTest(category=category), self.assertRaises(OSError):
                SnapshotProducer(port, lambda: live.now).produce(self.scope, 10000)
        live.bad_inventory = None
        from unittest.mock import patch

        inventory = port.inventory
        for field, bad in (("complete", False), ("scope_sha256", "f" * 64)):

            def changed(category, scope, stop, field=field, bad=bad):
                return {**inventory(category, scope, stop), field: bad}

            with (
                patch.object(port, "inventory", side_effect=changed),
                self.assertRaises(IntegrityError),
            ):
                SnapshotProducer(port, lambda: live.now).produce(self.scope, 10000)
        with (
            patch.object(
                port,
                "capacity_inventory",
                return_value={
                    "complete": False,
                    "scope_sha256": sha(encode(self.scope.descriptor())),
                    "tokens": {"original-token": ["cr-fixture"]},
                    "members": ["cr-fixture"],
                },
            ),
            self.assertRaisesRegex(IntegrityError, "capacity_complete"),
        ):
            SnapshotProducer(port, lambda: live.now).produce(self.scope, 10000)
        ticks = iter((100, 10000))
        with self.assertRaisesRegex(IntegrityError, "read_end"):
            SnapshotProducer(port, lambda: next(ticks)).produce(self.scope, 10000)
        self.assertEqual(live.executions, [])
        self.assertEqual(live.resources, original)

    def setUp(self):
        self.scope = CleanupScope(
            "offline-session",
            "offline-group",
            ("original-token",),
            ("i-fixture-1", "i-fixture-2"),
            17,
            "offline-state-source",
            "offline-independent-export",
        )
        self.backend = Backend(self.scope)
        self.capacity = Capacity(self.backend)
        self.store = MemoryStore()
        self.adapter = self.open()

    def open(self):
        return TerminalAdapters(
            store=self.store,
            scope=self.scope,
            backend=self.backend,
            capacity=self.capacity,
            clock=lambda: self.backend.now,
        )

    def request(self, operation="cleanup", stop=10000):
        return {
            "input": None,
            "operation_key": "original-session-key:" + operation,
            "operation_label": operation,
            "measurement_deadline_ms": stop,
            "kill_cutoff_ms": stop - 1000,
        }

    def run_cleanup(self):
        return self.adapter("cleanup", 10000, self.request())

    def assert_all_inventories(self):
        self.assertEqual(self.backend.visits[-len(INVENTORIES) :], list(INVENTORIES))

    def test_dependency_order_termination_capacity_state_and_identical_replay(self):
        self.assertTrue(self.run_cleanup())
        actions = self.backend.executions[:]
        for before, after in (
            ("delete_ingress", "delete_nlb"),
            ("delete_nlb", "delete_controllers"),
            ("delete_controllers", "delete_cluster"),
            ("delete_nodes", "delete_cluster"),
            ("delete_cluster", "delete_identity"),
            ("preserve_state", "delete_state_versions"),
            ("delete_state_storage", "delete_bootstrap"),
        ):
            self.assertLess(actions.index(before), actions.index(after))
        self.assertEqual(self.capacity.calls, [("original-token", "offline-group")])
        self.assert_all_inventories()
        self.adapter = self.open()
        self.assertTrue(self.run_cleanup())
        self.assertEqual(self.backend.executions, actions)
        self.assertEqual(len(self.capacity.calls), 1)
        self.assert_all_inventories()
        CASES.append(
            {
                "case": "ordered_cleanup_replay",
                "actions": actions,
                "report": self.adapter.last_report,
            }
        )

    def test_shutting_down_missing_or_extra_live_instance_blocks_cluster_capacity(self):
        for failure in ("shutting_down", "missing", "extra"):
            with self.subTest(failure=failure):
                self.setUp()
                if failure == "shutting_down":
                    self.backend.shutting_down = True
                if failure == "missing":
                    self.backend.omit_instance = True
                if failure == "extra":
                    original = self.backend.inventory

                    def inventory(category, scope, stop, original=original):
                        result = original(category, scope, stop)
                        if category == "instances":
                            result["resources"].append({"id": "i-extra", "state": "running"})
                        return result

                    self.backend.inventory = inventory
                with self.assertRaises(IntegrityError):
                    self.run_cleanup()
                self.assertNotIn("delete_cluster", self.backend.executions)
                self.assertNotIn("delete_capacity_group", self.backend.executions)
                self.assertEqual(self.capacity.calls, [])
                self.assertEqual(self.capacity.cancel_invocations, [])
                self.assert_all_inventories()

    def test_every_deletion_failure_still_visits_all_inventories_and_stops_dependencies(self):
        self.run_cleanup()
        actions = self.backend.executions[:]
        for label in actions:
            with self.subTest(action=label):
                self.setUp()
                self.backend.fail = label
                with self.assertRaises(IntegrityError):
                    self.run_cleanup()
                self.assert_all_inventories()
                self.assertEqual(self.backend.executions, actions[: actions.index(label)])
                if label in {"delete_ingress", "delete_nlb", "delete_controllers", "delete_nodes"}:
                    self.assertEqual(self.capacity.calls, [])
                    self.assertEqual(self.capacity.cancel_invocations, [])
                if label in {"delete_cluster", "delete_identity"}:
                    self.assertEqual(self.capacity.calls, [("original-token", "offline-group")])
                    self.assertEqual(
                        self.capacity.cancel_invocations, [("original-token", "offline-group")]
                    )
                    self.assertEqual(
                        self.backend.resources["reservations"][0]["state"], "cancelled"
                    )
                    self.assertIn("delete_capacity_group", self.backend.executions)
                    self.assertEqual(self.backend.member_checks, [[]])

    def test_report_is_durable_after_success_failure_and_report_write_cut(self):
        for failure in (None, "delete_cluster", "inventory"):
            with self.subTest(failure=failure):
                self.setUp()
                if failure == "inventory":
                    self.backend.bad_inventory = "nlb"
                else:
                    self.backend.fail = failure
                if failure:
                    with self.assertRaises(IntegrityError):
                        self.run_cleanup()
                else:
                    self.run_cleanup()
                report = copy.deepcopy(self.adapter.last_report)
                self.assertEqual(set(report["inventories"]), set(INVENTORIES))
                self.assertEqual(set(report["read_ms"]), set(INVENTORIES))
                self.assertEqual(self.open().last_report, report)
                writes = self.store.writes
                # Cut after the final report is durable but before acknowledgement.
                self.setUp()
                self.backend.fail = None if failure == "inventory" else failure
                self.backend.bad_inventory = "nlb" if failure == "inventory" else None
                self.store.cut = writes
                with self.assertRaises(Cut):
                    self.run_cleanup()
                reopened = self.open()
                self.assertEqual(reopened.last_report, report)
                if failure:
                    with self.assertRaises(IntegrityError):
                        reopened("cleanup", 10000, self.request())
                else:
                    self.assertTrue(reopened("cleanup", 10000, self.request()))
                self.assertEqual(reopened.last_report, report)

    def test_export_failure_in_lifecycle_still_cleans_and_verifies_every_inventory(self):
        from test_inf037b_lifecycle import DriverTests

        fixture = DriverTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        original = fixture.execute
        self.backend.fail = "export"

        def execute(op, stop, context):
            if op in {"export", "cleanup"}:
                return self.adapter(op, stop, context)
            return original(op, stop, context)

        fixture.driver.execute = execute
        result = fixture.driver.run()
        self.assertIn("offline effect failure:export", " ".join(result["refusals"]))
        self.assertTrue(any(c["operation"] == "cleanup" for c in result["calls"]))
        self.assert_all_inventories()
        self.assertEqual(self.adapter.last_report["errors"], [])
        CASES.append(
            {
                "case": "export_failure_lifecycle",
                "request": self.request(),
                "report": self.adapter.last_report,
            }
        )

    def test_original_request_context_key_scope_or_deadline_cannot_change(self):
        self.run_cleanup()
        original_effects = self.backend.executions[:]
        for field, value in (
            ("operation_key", "different:cleanup"),
            ("input", {"changed": True}),
            ("kill_cutoff_ms", 8999),
        ):
            with self.subTest(field=field):
                request = self.request()
                request[field] = value
                with self.assertRaises(IntegrityError):
                    self.adapter("cleanup", 10000, request)
        with self.assertRaises(IntegrityError):
            self.adapter("cleanup", 10001, self.request(stop=10001))
        other = TerminalAdapters(
            store=self.store,
            scope=replace(self.scope, group="different"),
            backend=self.backend,
            capacity=self.capacity,
            clock=lambda: 100,
        )
        with self.assertRaises(IntegrityError):
            other("cleanup", 10000, self.request())
        self.assertEqual(self.backend.executions, original_effects)
        with self.assertRaisesRegex(IntegrityError, "independent_destination"):
            replace(self.scope, state_destination=self.scope.state_storage_id).descriptor()

    def test_lost_backend_replies_retry_identical_keys_without_second_effect(self):
        for label in ("delete_ingress", "delete_cluster", "preserve_state", "delete_bootstrap"):
            with self.subTest(label=label):
                self.setUp()
                self.backend.lost = label
                with self.assertRaises(IntegrityError):
                    self.run_cleanup()
                self.assert_all_inventories()
                self.adapter = self.open()
                self.assertTrue(self.run_cleanup())
                self.assertEqual(self.backend.executions.count(label), 1)
                self.assert_all_inventories()

    def test_every_durable_and_external_cut_recovers_same_intents(self):
        self.run_cleanup()
        writes = self.store.writes
        labels = self.backend.executions[:]
        for cut in range(1, writes + 1):
            with self.subTest(write_cut=cut):
                self.setUp()
                self.store.cut = cut
                with self.assertRaises(Cut):
                    self.run_cleanup()
                self.adapter = self.open()
                self.assertTrue(self.run_cleanup())
                self.assertEqual(len(self.backend.executions), len(set(self.backend.executions)))
        for label in labels:
            with self.subTest(effect_cut=label):
                self.setUp()
                self.backend.cut_after = label
                with self.assertRaises(Cut):
                    self.run_cleanup()
                self.adapter = self.open()
                self.assertTrue(self.run_cleanup())
                self.assertEqual(self.backend.executions.count(label), 1)
        CASES.append(
            {"case": "terminal_cut_matrix", "durable_cuts": writes, "effect_cuts": len(labels)}
        )

    def test_unknown_cancel_or_group_member_blocks_group_and_state_deletion(self):
        for kind in ("unknown", "extra"):
            with self.subTest(kind=kind):
                self.setUp()
                setattr(self.capacity, kind, True)
                with self.assertRaises(IntegrityError):
                    self.run_cleanup()
                self.assertNotIn("delete_capacity_group", self.backend.executions)
                self.assertNotIn("preserve_state", self.backend.executions)
                self.assert_all_inventories()

    def test_inventory_failure_or_scope_gap_never_becomes_success(self):
        for category in INVENTORIES:
            with self.subTest(category=category):
                self.setUp()
                self.backend.bad_inventory = category
                with self.assertRaises(IntegrityError):
                    self.run_cleanup()
                self.assert_all_inventories()
                if category in {"ingress", "nlb", "target_groups", "controllers", "instances"}:
                    self.assertEqual(self.capacity.cancel_invocations, [])
        for field, value in (("complete", False), ("scope_sha256", "unbound"), ("resources", None)):
            with self.subTest(field=field):
                self.setUp()
                original = self.backend.inventory

                def inventory(category, scope, stop, field=field, value=value, original=original):
                    row = original(category, scope, stop)
                    row[field] = value
                    return row

                self.backend.inventory = inventory
                with self.assertRaises((IntegrityError, TypeError)):
                    self.run_cleanup()
                self.assert_all_inventories()

    def test_state_preservation_failure_keeps_versions_locks_and_bootstrap(self):
        self.backend.fail = "preserve_state"
        with self.assertRaises(IntegrityError):
            self.run_cleanup()
        for category in ("state_versions", "lockfiles", "state_storage", "bootstrap"):
            self.assertTrue(self.backend.resources[category])
        self.assert_all_inventories()

    def test_export_requires_bound_verified_manifest_and_replays_identically(self):
        for field, value in (
            ("verified", False),
            ("manifest_sha256", "bad"),
            ("destination", "wrong"),
            ("request_key", "wrong"),
            ("body_sha256", "wrong"),
        ):
            with self.subTest(field=field):
                self.setUp()
                self.backend.bad_export = (field, value)
                with self.assertRaises(IntegrityError):
                    self.adapter("export", 10000, self.request("export"))
        self.setUp()
        self.assertTrue(self.adapter("export", 10000, self.request("export")))
        self.adapter = self.open()
        self.assertTrue(self.adapter("export", 10000, self.request("export")))
        self.assertEqual(self.backend.executions, ["export"])
        self.setUp()
        self.backend.lost = "export"
        with self.assertRaises(OSError):
            self.adapter("export", 10000, self.request("export"))
        self.adapter = self.open()
        self.assertTrue(self.adapter("export", 10000, self.request("export")))
        self.assertEqual(self.backend.executions, ["export"])

    def test_deadline_refusal_still_visits_each_inventory_without_effect(self):
        for invalid_now in (16, 10000):
            with self.subTest(invalid_now=invalid_now):
                self.setUp()
                self.backend.now = invalid_now
                with self.assertRaises(IntegrityError):
                    self.run_cleanup()
                self.assertEqual(self.backend.executions, [])
                self.assert_all_inventories()
        for completion in (10000, 10001):
            with self.subTest(completion=completion):
                self.setUp()
                original = self.backend.effect

                def effect(label, key, body, stop, original=original, completion=completion):
                    value = original(label, key, body, stop)
                    self.backend.now = completion
                    return value

                self.backend.effect = effect
                if completion == 10000:
                    self.assertTrue(self.adapter("export", 10000, self.request("export")))
                else:
                    with self.assertRaisesRegex(IntegrityError, "terminal:deadline"):
                        self.adapter("export", 10000, self.request("export"))

    def test_nonmutating_rehearsal_runs_same_adapter_on_an_isolated_snapshot(self):
        before = encode(self.backend.resources)
        snapshot = copy.deepcopy(self.backend.resources)
        model = Backend(self.scope)
        model.resources = snapshot
        adapter = TerminalAdapters(
            store=MemoryStore(),
            scope=self.scope,
            backend=model,
            capacity=Capacity(model),
            clock=lambda: model.now,
        )
        started = time.monotonic_ns()
        self.assertTrue(adapter("cleanup", 10000, self.request()))
        elapsed = (time.monotonic_ns() - started) / 1_000_000
        self.assertEqual(encode(self.backend.resources), before)
        self.assertEqual(self.backend.executions, [])
        self.assertEqual(self.capacity.calls, [])
        CASES.append(
            {
                "case": "nonmutating_cleanup_rehearsal",
                "snapshot_sha256": sha(before),
                "wall_ms": elapsed,
                "actions": model.executions,
                "report": adapter.last_report,
                "scope": "offline snapshot; no live O_i or worst-case timing claim",
            }
        )

    def test_linux_durable_store_and_accepted_4a_authority_cancel_group_and_ledger(self):
        from inf037b_ports_support import Rig

        from inference_platform.inf037b_durable_ports import DurableStore

        rig = Rig()
        self.addCleanup(rig.close)
        controller = rig.run()
        scope = CleanupScope(
            controller.session_id,
            controller.group,
            (controller._token(0),),
            self.scope.instance_ids,
            controller._get("billing_origin")["t0_ms"],
            self.scope.state_storage_id,
            self.scope.state_destination,
        )
        backend = Backend(scope)
        members = rig.capacity.members

        def checked_members(group):
            result = members(group)
            backend.member_checks.append(result)
            return result

        rig.capacity.members = checked_members
        original = backend.inventory

        def inventory(category, scope, stop):
            row = original(category, scope, stop)
            if category == "reservations":
                row["resources"] = [
                    {"id": r["reservation_id"], "state": r["state"]}
                    for r in rig.responses.capacity.results.values()
                    if r
                ]
            return row

        backend.inventory = inventory
        with TemporaryDirectory() as temporary:
            directory = Path(temporary) / "terminal"
            store = DurableStore(directory, {"binding": None}, initialize=True)
            adapter = TerminalAdapters(
                store=store,
                scope=scope,
                backend=backend,
                capacity=rig.capacity,
                clock=rig.world.clock,
            )
            context = self.request(stop=rig.world.now + 10000)
            stop = context["measurement_deadline_ms"]
            self.assertTrue(adapter("cleanup", stop, context))
            self.assertEqual(
                TerminalAdapters(
                    store=DurableStore(directory, {}),
                    scope=scope,
                    backend=backend,
                    capacity=rig.capacity,
                    clock=rig.world.clock,
                ).last_report,
                adapter.last_report,
            )
            self.assertEqual(rig.capacity.members(scope.group), [])
            self.assertEqual(rig.capacity.cancellation(scope.tokens[0])["verified"], True)
            count = sum(r[0] == "cancel" for r in rig.world.trace)
            reopened = TerminalAdapters(
                store=DurableStore(directory, {}),
                scope=scope,
                backend=backend,
                capacity=rig.capacity,
                clock=rig.world.clock,
            )
            self.assertTrue(reopened("cleanup", stop, context))
            self.assertEqual(sum(r[0] == "cancel" for r in rig.world.trace), count)
            CASES.append(
                {
                    "case": "accepted_4a_terminal_cleanup",
                    "ledger": rig.capacity.ledger(scope.tokens[0], scope.t0_ms),
                    "authority_requests": [
                        r["request_utf8"]
                        for r in rig.responses.records
                        if "odcr.cancel" in r["request_utf8"]
                    ],
                }
            )


def load_tests(loader, tests, pattern):
    return unittest.TestSuite(
        TerminalTests(name)
        for name in loader.getTestCaseNames(TerminalTests)
        if os.name == "posix" or not name.startswith("test_linux_")
    )
