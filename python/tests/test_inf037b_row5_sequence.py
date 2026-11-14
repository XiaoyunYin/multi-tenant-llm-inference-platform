"""Fake-clock sequencing; real RoleControl, expiry and agreement decisions."""

import copy
import importlib
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import test_inf037b_row5 as role_fixtures

from inference_platform.inf037b_archive import IntegrityError, encode
from inference_platform.inf037b_row5 import canonical_role


class Clock:
    def __init__(self):
        self.ns = 20_000_000_000

    def __call__(self):
        return self.ns

    def sleep(self, seconds):
        self.ns += round(seconds * 1e9)


class SequenceTests(unittest.TestCase):
    def setUp(self):
        # Import per test so the scratch-baseline run reports every test's
        # missing implementation, rather than a single loader failure.
        self.sequence = importlib.import_module("inference_platform.inf037b_row5_sequence")
        self.clock = Clock()
        fixture = role_fixtures.RoleControlTests()
        fixture.setUp()
        self.role, self.role_port = fixture.control, fixture.port
        self.role.clock, self.role.sleep = self.clock, self.clock.sleep
        self.original = canonical_role(self.role_port.role)
        self.n, self.stores, self.events = 0, [20_000, 20_000], []
        self.active, self.expired_at_end, self.bad_report = False, False, False
        self.requests, self.diagnostics, self.restores = [], [], []
        receipt_hashes = {}
        original_restore = self.role.restore

        def restore(**kwargs):
            self.restores.append(kwargs["envelope_deadline_ns"])
            return original_restore(**kwargs)

        self.role.restore = restore

        def snapshot(*, snapshot_id=None):
            start = self.clock()
            self.clock.sleep(0.01)
            now = self.clock() // 1_000_000
            if snapshot_id == "expired" and self.expired_at_end:
                self.clock.ns = (min(self.stores) + 10_000) * 1_000_000
                now = self.clock() // 1_000_000
            unknown = not bool(self.role_port.role["rules"])
            reports = {
                g: {
                    "n": self.n,
                    "unknown": unknown,
                    "stored_ms": self.stores[i] if unknown else now,
                    "expires_ms": (self.stores[i] if unknown else now) + 8000,
                }
                for i, g in enumerate(("gateway0", "gateway1"))
            }
            if self.bad_report:
                reports.pop("gateway1")
            row = {
                "payload": {
                    "event": "snapshot",
                    "snapshot_id": snapshot_id,
                    "redis_time_ms": now,
                    "reports": reports,
                    "state": {"n": self.n},
                    "active_reservations": ["active"] if self.active else [],
                    "occupied": int(self.active),
                },
                "capture_start_mono_ns": start,
                "capture_end_mono_ns": self.clock(),
            }
            self.events.append(("snapshot", snapshot_id, now))
            return row

        def request(**kwargs):
            self.assertGreater(kwargs["deadline_ns"], self.clock())
            self.requests.append(copy.deepcopy(kwargs))
            self.events.append(("request", kwargs["offer"]["snapshot_id"]))
            self.clock.sleep(0.005)
            return []

        def diagnostic(**kwargs):
            self.assertGreater(kwargs["deadline_ns"], self.clock())
            self.diagnostics.append(copy.deepcopy(kwargs))
            receipt_hashes[kwargs["reservation_id"]] = "b" * 64
            self.events.append(("diagnostic",))
            self.clock.sleep(0.01)
            return {"reservation_id": kwargs["reservation_id"], "decision": "allowed"}

        self.stage = self.sequence.KnownStage(
            redis=SimpleNamespace(snapshot=snapshot),
            clients={g: SimpleNamespace(request=request) for g in ("gateway0", "gateway1")},
            diagnostic=SimpleNamespace(run_from_captures=diagnostic, receipt_hashes=receipt_hashes),
            request_arguments=lambda g: {
                "url": "https://fixture.invalid",
                "payload": {},
                "credential": "test",
            },
            diagnostic_arguments=lambda: {"config": {"running": 4, "waiting": 1}},
            proof_inputs=lambda *args: (
                {"gateway_request_id": "req_" + "1" * 32, "raw_gateway_prefix": b"captured"}
                if args[1]
                else {}
            ),
            configuration_sha256="a" * 64,
            clock=self.clock,
            sleep=self.clock.sleep,
        )
        # These source-join helpers have their own whole-module tests. Here
        # their seams record scheduling; no fixture claims live capture fitness.
        self.known = self.enterContext(
            patch.object(
                self.sequence,
                "known_gateway_control",
                side_effect=lambda **k: {
                    "reservation_id": "rsv_" + "1" * 32,
                    "decision": "allowed" if k["expected_n"] else "system_capacity",
                    "effective_n": k["expected_n"],
                    "effective_b": k["expected_n"] * 5,
                },
            )
        )
        self.refusal = self.enterContext(
            patch.object(
                self.sequence,
                "captured_refusal_control",
                return_value={"gateway": {}, "client": {}, "redis": {}},
            )
        )
        self.diag = self.enterContext(
            patch.object(
                self.sequence,
                "diagnostic_snapshot_control",
                side_effect=lambda **k: {
                    "reservation_id": k["receipt"]["reservation_id"],
                    "decision": "allowed",
                    "effective_n": self.n,
                    "effective_b": self.n * 5,
                },
            )
        )
        self.late_403, self.recovery_calls = False, 0

        def recovery(deadline):
            self.recovery_calls += 1
            self.clock.sleep(0.5)
            denied = self.late_403 and self.recovery_calls == 4
            self.events.append(("recovery", denied, self.clock() // 1_000_000))
            return {
                "source_complete": True,
                "evidence_sha256": "b" * 64,
                "observations": [
                    {
                        "time_ms": self.clock() // 1_000_000,
                        "known": not denied,
                        "reason": "403" if denied else None,
                        "n": 2,
                        "effective_b": 10,
                    }
                ],
            }

        self.outage = self.sequence.OutageSequence(
            stage=self.stage,
            role=self.role,
            recovery=recovery,
            capture=lambda prepared: {
                "fitness_raw": encode({"schema": "inf037b-setup-v1", "raw": []}),
                "row5_evidence": {},
                "artifacts": {},
            },
        )

    def bring_up(self):
        records = []
        for name, n in (
            ("known0", 0),
            ("known1", 1),
            ("known2", 2),
            ("cached_stop_known1", 1),
            ("cached_restore_known2", 2),
        ):
            self.n = n
            records.extend(self.stage(name, self.clock() + 10_000_000_000))
        return records

    def test_stage_order_and_repetition(self):
        self.stage("known0", self.clock() + 1_000_000_000)
        for name in ("known2", "known0"):
            with self.assertRaisesRegex(IntegrityError, "fitness:row5_stage_order"):
                self.stage(name, self.clock() + 1_000_000_000)
        self.n = 1
        self.stage("known1", self.clock() + 1_000_000_000)
        self.n = 2
        self.stage("known2", self.clock() + 1_000_000_000)

    def test_all_five_stages_and_fresh_request_deadlines(self):
        records = self.bring_up()
        self.assertEqual(len(records), 10)
        self.assertEqual(len({r["request_id"] for r in records}), 10)
        self.assertTrue(all(not r["request_id"].startswith("rsv_d1a6") for r in records))
        self.assertEqual(len(self.diagnostics), 5)
        self.assertEqual(len({r["reservation_id"] for r in self.diagnostics}), 5)
        self.assertTrue(all(r["reservation_id"].startswith("rsv_d1a6") for r in self.diagnostics))
        self.assertEqual(self.known.call_count, 10)
        self.assertEqual(self.diag.call_count, 5)

    def test_incomplete_reports_wait_until_deadline(self):
        self.bad_report = True
        stop = self.clock() + 150_000_000
        with self.assertRaisesRegex(IntegrityError, "fitness:row5_stage_deadline"):
            self.stage("known0", stop)
        self.assertEqual(self.clock(), stop)
        self.assertEqual(self.requests, [])

    def test_release_failure_prevents_later_stage(self):
        self.active = True
        with self.assertRaisesRegex(IntegrityError, "fitness:row5_release"):
            self.stage("known0", self.clock() + 1_000_000_000)
        with self.assertRaisesRegex(IntegrityError, "fitness:row5_stage_order"):
            self.stage("known0", self.clock() + 1_000_000_000)

    def test_snapshot_predicate_refuses_stale_unknown_or_unequal_state(self):
        row = self.stage.snapshot(self.clock() + 1_000_000_000)
        self.assertTrue(self.stage.matches(row, 0))
        for field, value in (("unknown", True), ("n", 1), ("expires_ms", 0)):
            changed = copy.deepcopy(row)
            changed["payload"]["reports"]["gateway1"][field] = value
            self.assertFalse(self.stage.matches(changed, 0))
        row["payload"]["state"]["n"] = 1
        self.assertFalse(self.stage.matches(row, 0))

    def test_spread_refuses_and_restores_original_role(self):
        self.bring_up()
        self.stores = [18_000, 20_100]
        with self.assertRaisesRegex(IntegrityError, "fitness:expired_snapshot_window"):
            self.outage(self.clock() + 30_000_000_000, {})
        self.assertEqual(len(self.restores), 1)
        self.assertEqual(canonical_role(self.role_port.read_role("test")), self.original)
        self.assertTrue(self.outage.restore_outcome["success"])

    def test_late_403_restarts_agreement_then_passes(self):
        self.bring_up()
        self.late_403 = True
        result = self.outage(self.clock() + 30_000_000_000, {})
        observations = result["row5_evidence"]["recovery"]["observations"]
        denied = [r for r in observations if not r["known"]]
        self.assertEqual(len(denied), 1)
        self.assertEqual(denied[0]["reason"], "403")
        first_good = next(r for r in observations if r["time_ms"] > denied[0]["time_ms"])
        self.assertGreaterEqual(observations[-1]["time_ms"] - first_good["time_ms"], 2000)
        self.assertEqual(len(self.restores), 1)
        self.assertEqual(canonical_role(self.role_port.role), self.original)

    def test_revoke_readback_failure_still_restores(self):
        self.bring_up()
        original_read = self.role_port.read_role
        failed = False

        def read(namespace):
            nonlocal failed
            if not self.role_port.role["rules"] and not failed:
                failed = True
                raise IntegrityError("fitness:rbac_revoke_readback")
            return original_read(namespace)

        self.role_port.read_role = read
        with self.assertRaisesRegex(IntegrityError, "fitness:rbac_revoke_readback"):
            self.outage(self.clock() + 30_000_000_000, {})
        self.assertEqual(len(self.restores), 1)
        self.assertEqual(canonical_role(original_read("test")), self.original)

    def test_refusal_records_timing_for_active_outage_step(self):
        self.bring_up()
        timings = []
        self.outage.step_timing = lambda name, elapsed: timings.append((name, elapsed))

        def refuse_wait(*_args, **_kwargs):
            raise IntegrityError("fitness:row5_stage_deadline")

        self.stage.wait = refuse_wait
        with self.assertRaisesRegex(IntegrityError, "fitness:row5_stage_deadline"):
            self.outage(self.clock() + 30_000_000_000, {})

        self.assertEqual([name for name, _elapsed in timings], ["rbac-revoke-and-unknown-window"])
        self.assertGreaterEqual(timings[0][1], 0)
        self.assertEqual(len(self.restores), 1)
        self.assertEqual(canonical_role(self.role_port.role), self.original)

    def test_envelope_expiry_attempts_restore_without_extending_deadline(self):
        self.bring_up()
        stop = self.clock() + 200_000_000
        with self.assertRaisesRegex(IntegrityError, "fitness:row5_stage_deadline"):
            self.outage(stop, {})
        self.assertEqual(self.restores, [stop])
        self.assertFalse(self.outage.restore_outcome["success"])
        self.assertEqual(self.outage.restore_outcome["deadline_ns"], stop)
        self.assertEqual(self.clock(), stop)

    def test_failed_restore_records_outcome_and_preserves_original_refusal(self):
        self.bring_up()
        self.stores = [18_000, 20_100]
        replace = self.role_port.replace_role

        def fail_restore(namespace, role):
            if role["rules"]:
                raise IntegrityError("restore_failed")
            return replace(namespace, role)

        self.role_port.replace_role = fail_restore
        with self.assertRaisesRegex(IntegrityError, "fitness:expired_snapshot_window"):
            self.outage(self.clock() + 30_000_000_000, {})
        self.assertEqual(len(self.restores), 1)
        self.assertFalse(self.outage.restore_outcome["success"])
        self.assertEqual(self.outage.restore_outcome["error_class"], "IntegrityError")

    def test_failure_before_replace_has_no_restore_effect(self):
        self.bring_up()
        self.role_port.binding["subjects"] = []
        with self.assertRaisesRegex(IntegrityError, "fitness:rbac_binding"):
            self.outage(self.clock() + 30_000_000_000, {})
        self.assertEqual(self.restores, [])
        self.assertEqual(canonical_role(self.role_port.role), self.original)

    def test_source_gap_after_restore_refuses_without_another_restore(self):
        self.bring_up()
        self.outage.recovery = lambda stop: {"source_complete": False}
        with self.assertRaisesRegex(IntegrityError, "fitness:recovery_source_incomplete"):
            self.outage(self.clock() + 30_000_000_000, {})
        self.assertEqual(len(self.restores), 1)
        self.assertEqual(canonical_role(self.role_port.role), self.original)

    def test_late_403_after_control_refuses_final_agreement(self):
        self.bring_up()
        recovery = self.outage.recovery

        def tail(deadline):
            batch = recovery(deadline)
            if self.recovery_calls == 6:
                batch["observations"][0].update(known=False, reason="403")
            return batch

        self.outage.recovery = tail
        with self.assertRaisesRegex(IntegrityError, "fitness:recovery_agreement"):
            self.outage(self.clock() + 30_000_000_000, {})
        self.assertEqual(len(self.restores), 1)
        self.assertEqual(canonical_role(self.role_port.role), self.original)

    def test_empty_continuous_tail_preserves_agreement(self):
        self.bring_up()
        recovery = self.outage.recovery

        def tail(deadline):
            batch = recovery(deadline)
            if self.recovery_calls == 6:
                batch["observations"] = []
            return batch

        self.outage.recovery = tail
        self.assertEqual(
            len(self.outage(self.clock() + 30_000_000_000, {})["row5_control_requests"]), 6
        )

    def test_expired_snapshot_at_window_end_refuses_and_restores(self):
        self.bring_up()
        self.expired_at_end = True
        with self.assertRaisesRegex(IntegrityError, "fitness:expired_snapshot_window"):
            self.outage(self.clock() + 30_000_000_000, {})
        self.assertEqual(len(self.restores), 1)
        self.assertEqual(canonical_role(self.role_port.role), self.original)

    def test_expired_snapshot_is_inside_and_outage_returns_only_six(self):
        known = self.bring_up()
        result = self.outage(self.clock() + 30_000_000_000, {})
        first, end = result["row5_evidence"]["expired_window_ms"]
        self.assertEqual(result["row5_evidence"]["expired_snapshot_latency_ms"], 10)
        at = next(row[2] for row in self.events if row[:2] == ("snapshot", "expired"))
        self.assertLess(first, at)
        self.assertLess(at, end)
        controls = result["row5_control_requests"]
        self.assertEqual(len(controls), 6)
        self.assertEqual(
            {r["snapshot_id"] for r in controls}, {"unknown", "expired", "post_outage_known2"}
        )
        self.assertEqual(len({r["request_id"] for r in known + controls}), 16)
        snapshots = [e for e in self.events if e[0] == "snapshot"]
        self.assertEqual(snapshots[-1][:2], ("snapshot", "post_outage_agreement"))

    def test_outage_known_instance_refuses_at_port_boundary(self):
        from contextlib import nullcontext

        from test_inf037b_preparation import BINDING, point
        from test_inf037b_preparation_adapter import known_requests, row5_stage_stub, row5_stub

        from inference_platform.inf037b_preparation import ConcurrentPreparation

        saved = {"binding": BINDING, "creation": {"result": True, "data": {"ready": point(10)}}}
        store = SimpleNamespace(
            lock=nullcontext, read=lambda: copy.deepcopy(saved), write=lambda v: saved.update(v)
        )
        control = row5_stub()
        # Keep the union of 16 intact, but swap ownership between the two legs.
        known = known_requests()
        known[0], control["row5_control_requests"][0] = (
            control["row5_control_requests"][0],
            known[0],
        )
        adapter = ConcurrentPreparation(
            store=store,
            binding=BINDING,
            sample=lambda: point(30),
            capture=None,
            creation=None,
            gpu=lambda stop, stage: {"fitness_raw": b"raw", "row5_known_requests": known},
            row5_stage=row5_stage_stub,
            row5_control=lambda stop, prepared: control,
        )
        with patch(
            "inference_platform.inf037b_preparation.PreparationFork.run",
            lambda fork, stop: fork.branches["gpu"](stop),
        ):
            with self.assertRaisesRegex(IntegrityError, "preparation:row5_request_partition"):
                adapter("preparation", 1000)
