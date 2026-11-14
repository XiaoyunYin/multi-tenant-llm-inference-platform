"""Offline durable-port fixtures. No AWS, host gates, Docker or live sessions."""

import copy
import hashlib
import itertools
import unittest
from dataclasses import replace
from datetime import UTC, datetime
from unittest.mock import patch

from inference_platform.inf037b_archive import IntegrityError
from inference_platform.inf037b_controller import Controller, ReviewedPlan, utc_ms
from inference_platform.m5_infra_safety import Binding

BASE = int(datetime(2026, 10, 19, tzinfo=UTC).timestamp()) * 1000
C = "2026-10-19T01:00:00Z"
D = "2026-10-19T06:00:00Z"
GROUP = "arn:aws:resource-groups:us-east-1:000000000000:group/m5-offline-capacity"


class Crash(BaseException):
    pass


class World:
    def __init__(self):
        self.now = BASE
        self.trace = []
        self.crash_operation = None

    def clock(self):
        return self.now

    def op(self, name, value=None):
        self.trace.append((name, copy.deepcopy(value)))
        if self.crash_operation == name:
            self.crash_operation = None
            raise Crash(name)


class FakeJournal:
    def __init__(self, world):
        self.world, self.rows = world, []
        self.cut = None
        self.ack = True
        self.bad_readback = False
        self.origin_delay = 0

    def read(self):
        rows = copy.deepcopy(self.rows)
        if self.bad_readback and rows:
            rows[-1]["data"] = "corrupt"
        return rows

    def append_fsync(self, row):
        self.rows.append(copy.deepcopy(row))
        self.world.op("fsync", row)
        if len(self.rows) == self.cut:
            self.cut = None
            raise Crash("journal_cut")
        return self.ack

    def append_origin_fsync(self, row):
        self.world.now += self.origin_delay
        row["data"]["t0_ms"] = self.world.now
        ack = self.append_fsync(row)
        return {"fsync": ack, "row": copy.deepcopy(row)}


class FakeGate:
    def __init__(self, world):
        self.world = world
        self.markers, self.consumptions, self.applies = {}, {}, {}
        self.marker_override = {}
        self.consume_delay = 0

    def marker(self, binding):
        key = binding["plan_hash"]
        marker = {"binding": binding, "committed": True, "review_commit": "c" * 40}
        marker.update(copy.deepcopy(self.marker_override))
        if key in self.markers:
            if self.markers[key] != marker:
                raise IntegrityError("marker_changed")
        else:
            self.markers[key] = copy.deepcopy(marker)
            self.world.op("marker", marker)
        return copy.deepcopy(marker)

    def consumption(self, session_id):
        return copy.deepcopy(self.consumptions.get(session_id))

    def consume(self, binding, admission_check):
        session, key = binding["session_id"], binding["plan_hash"]
        if session in self.consumptions:
            if self.consumptions[session]["plan_hash"] != key:
                raise IntegrityError("session_already_consumed")
            return self.consumption(session)
        self.world.now += self.consume_delay
        now = admission_check()
        row = {"session_id": session, "plan_hash": key, "consumed_ms": now}
        self.consumptions[session] = row
        self.world.op("consume", row)
        return copy.deepcopy(row)

    def apply_once(self, binding):
        session = binding["session_id"]
        if session not in self.applies:
            self.applies[session] = binding["plan_hash"]
            self.world.op("apply", binding)

    def application(self, session_id):
        if session_id in self.applies:
            return {"session_id": session_id, "plan_hash": self.applies[session_id]}
        return None


class FakeBackstop:
    def __init__(self, world):
        self.world, self.armed = world, {}
        self.arm_ok, self.confirm_ok = True, True

    def arm(self, session_id, deadline_ms):
        if self.arm_ok:
            self.armed[session_id] = deadline_ms
        self.world.op("arm", deadline_ms)
        return self.arm_ok

    def confirmed(self, session_id, deadline_ms):
        self.world.op("confirm", deadline_ms)
        return self.confirm_ok and self.armed.get(session_id) == deadline_ms


class FakeCapacity:
    def __init__(self, world):
        self.world = world
        self.results, self.group, self.cancelled, self.ids = {}, [], {}, {}
        self.outcomes = ["ok", "ok"]
        self.overrides = {}
        self.extra_member = False
        self.cancel_ok = True
        self.cancel_advance = 10
        self.acquire_advance = 0
        self.ledger_override = {}

    def lookup(self, token):
        return copy.deepcopy(self.results.get(token))

    def acquire(self, token, binding):
        if token not in self.results:
            outcome = self.outcomes.pop(0)
            result = None
            if outcome != "refused":
                result = {
                    "reservation_id": "cr-" + token[:12],
                    "zone": binding.zone,
                    "instance_type": binding.instance_type,
                    "platform": binding.platform,
                    "tenancy": binding.tenancy,
                    "total": 2,
                    "available": 2,
                    "state": "active",
                    "match_criteria": "targeted",
                }
                self.ids[token] = result["reservation_id"]
                if outcome == "partial":
                    result.update(total=1, available=1)
                result.update(copy.deepcopy(self.overrides))
            self.results[token] = result
            self.world.now += self.acquire_advance
            self.world.op("odcr", {"token": token, "binding": vars(binding)})
            if outcome == "lost_reply":
                raise OSError("ambiguous_acquisition_reply")
        return self.lookup(token)

    def add(self, group, reservation_id):
        if reservation_id not in self.group:
            self.group.append(reservation_id)
        if self.extra_member and "cr-intruder" not in self.group:
            self.group.append("cr-intruder")
        self.world.op("add", reservation_id)

    def members(self, group):
        return self.group.copy()

    def cancel(self, token, group):
        if token not in self.cancelled:
            self.world.now += self.cancel_advance
            result = self.results.get(token)
            if result is not None:
                result["state"] = "cancelled"
                if self.ids[token] in self.group:
                    self.group.remove(self.ids[token])
            self.cancelled[token] = {
                "verified": self.cancel_ok,
                "complete": True,
                "stop_ms": self.world.now,
                "reservation_ids": [] if result is None else [self.ids[token]],
                "states": {} if result is None else {self.ids[token]: "cancelled"},
            }
            self.world.op("cancel", token)

    def cancellation(self, token):
        return copy.deepcopy(self.cancelled.get(token))

    def ledger(self, token, t0):
        stop = self.cancelled[token]["stop_ms"]
        row = {
            "t0_ms": t0,
            "stop_ms": stop,
            "billed_ms": stop - t0,
            "cost_micros": 0 if self.results.get(token) is None else (stop - t0) * 2,
        }
        row.update(self.ledger_override)
        return row


def plans():
    result = []
    for zone in ("us-east-1a", "us-east-1b"):
        data = ("saved-offline-plan-" + zone).encode()
        result.append(
            ReviewedPlan(
                data, hashlib.sha256(data).hexdigest(), "m5-offline", Binding(GROUP, zone), C, D
            )
        )
    return result


class Rig:
    def __init__(self):
        self.world = World()
        self.journal = FakeJournal(self.world)
        self.gate = FakeGate(self.world)
        self.capacity = FakeCapacity(self.world)
        self.backstop = FakeBackstop(self.world)
        self.plans = plans()

    def open(self):
        return Controller(
            self.plans,
            journal=self.journal,
            gate=self.gate,
            capacity=self.capacity,
            backstop=self.backstop,
            clock=self.world.clock,
        )

    def run(self, *, consume=True):
        controller = self.open()
        controller.recover()
        if not self.gate.consumptions and controller.status()["stopped"] is None:
            controller.mark()
            for _ in self.plans:
                if controller._index() == len(self.plans):
                    break
                index = controller._index()
                controller.acquire()
                if (
                    controller._get("verified", index)
                    and controller._get("rejected", index) is None
                ):
                    if consume:
                        controller.consume()
                    else:
                        controller.refuse("operator_stop")
                    break
        return controller


PUBLIC_CALLS = ("mark", "acquire", "consume", "recover", "refuse", "status")


class ControllerTests(unittest.TestCase):
    def test_fallback_acquire_C_cutoff_independent_of_readiness_cutoff(self):
        for outcome in ("refused", "partial"):
            with self.subTest(outcome=outcome):
                rig = Rig()
                rig.capacity.outcomes = [outcome, "ok"]
                rig.world.now = utc_ms(C) - 1000
                controller = rig.open()
                controller.mark()
                controller.acquire()
                t0 = controller._get("billing_origin")["t0_ms"]
                rig.world.now = utc_ms(C) + 1
                self.assertLess(rig.world.now - t0, 1_800_000)
                state = rig.open().acquire()
                self.assertEqual(sum(name == "odcr" for name, _ in rig.world.trace), 1)
                self.assertIn(controller._token(1), rig.capacity.cancelled)
                self.assertEqual(len(state["ledger"]), 2)
                self.assertEqual(state["sessions"], 0)

    def test_fallback_acquire_readiness_cutoff_cancels_without_create(self):
        for outcome in ("refused", "partial"):
            for elapsed in (1_799_999, 1_800_000, 1_800_001):
                with self.subTest(outcome=outcome, elapsed=elapsed):
                    rig = Rig()
                    rig.capacity.outcomes = [outcome, "ok"]
                    controller = rig.open()
                    controller.mark()
                    controller.acquire()
                    self.assertEqual(controller._index(), 1)
                    rig.world.now = BASE + elapsed
                    controller = rig.open()
                    before = sum(name == "odcr" for name, _ in rig.world.trace)
                    state = controller.acquire()
                    created = sum(name == "odcr" for name, _ in rig.world.trace) - before
                    if elapsed == 1_799_999:
                        self.assertEqual(created, 1)
                        self.assertIs(controller._get("verified", 1), True)
                        self.assertEqual(controller.consume()["sessions"], 1)
                        self.assertEqual(len(rig.gate.applies), 1)
                    else:
                        self.assertEqual(created, 0, "late acquisition must not create ODCR")
                        self.assertIn("readiness_cutoff", controller._get("rejected", 1)["reason"])
                        self.assertIn(controller._token(1), rig.capacity.cancelled)
                        self.assertEqual(len(state["ledger"]), 2)
                        self.assertEqual(state["ledger"][-1]["t0_ms"], BASE)
                        self.assertEqual(state["sessions"], 0)
                        self.assertFalse(rig.gate.applies)
                        self.assertFalse(rig.capacity.group)

    def test_lost_acquisition_reply_retried_past_cutoff_cancels_existing(self):
        rig = Rig()
        controller = rig.open()
        controller.mark()
        # The provider created capacity, then the caller died before its reply.
        rig.world.crash_operation = "odcr"
        with self.assertRaises(Crash):
            controller.acquire()
        token = controller._token(0)
        self.assertEqual(rig.capacity.lookup(token)["state"], "active")
        rig.world.now = BASE + 1_800_001
        state = rig.open().acquire()
        self.assertEqual(sum(name == "odcr" for name, _ in rig.world.trace), 1)
        self.assertEqual(rig.capacity.lookup(token)["state"], "cancelled")
        self.assertEqual(len(state["ledger"]), 1)
        self.assertGreater(state["ledger"][0]["cost_micros"], 0)
        self.assertEqual(state["sessions"], 0)
        self.assertFalse(rig.gate.applies)

    def test_readiness_cutoff_refuses_before_consumption_and_apply(self):
        for elapsed in (1_799_999, 1_800_000, 1_800_001):
            with self.subTest(elapsed=elapsed):
                rig = Rig()
                controller = rig.open()
                controller.mark()
                controller.acquire()
                rig.world.now = BASE + elapsed
                state = controller.consume()
                if elapsed == 1_799_999:
                    self.assertEqual(state["sessions"], 1)
                    self.assertEqual(len(rig.gate.applies), 1)
                    self.assertEqual(state["ledger"], [])
                else:
                    self.assertEqual(state["sessions"], 0)
                    self.assertFalse(rig.gate.applies)
                    self.assertEqual(
                        rig.capacity.lookup(controller._token(0))["state"], "cancelled"
                    )
                    self.assertEqual(len(state["ledger"]), 1)
                    self.assertEqual(state["ledger"][0]["t0_ms"], BASE)

    def test_consume_intent_reopen_after_readiness_cutoff_never_applies(self):
        rig = Rig()
        controller = rig.open()
        controller.mark()
        controller.acquire()
        rig.journal.cut = len(rig.journal.rows) + 1
        with self.assertRaises(Crash):
            controller.consume()
        self.assertIs(controller.journal.rows[-1]["data"], True)
        self.assertEqual(controller.journal.rows[-1]["event"], "consume_intent")
        rig.world.now = BASE + 1_800_001
        state = rig.open().recover()
        self.assertEqual(state["sessions"], 0)
        self.assertFalse(rig.gate.applies)
        self.assertEqual(rig.capacity.lookup(controller._token(0))["state"], "cancelled")
        self.assertEqual(len(state["ledger"]), 1)

    def test_consumed_receipt_crossing_readiness_cutoff_refuses_before_apply(self):
        rig = Rig()
        controller = rig.open()
        controller.mark()
        controller.acquire()
        rig.world.now = BASE + 1_799_999
        append = rig.journal.append_fsync

        def cross_cutoff(row):
            ack = append(row)
            if row["event"] == "consumed":
                rig.world.now = BASE + 1_800_000
            return ack

        rig.journal.append_fsync = cross_cutoff
        state = controller.consume()
        self.assertEqual(state["sessions"], 1)
        self.assertFalse(rig.gate.applies)
        self.assertIn("readiness_cutoff", state["stopped"]["reason"])
        self.assertEqual(len(state["ledger"]), 1)
        self.assertIsNone(controller._get("applied", 0))

    def ambiguous_consume(self, *, committed, late=False):
        rig = Rig()
        controller = rig.open()
        controller.mark()
        controller.acquire()
        consume = rig.gate.consume

        def reply(binding, admission):
            if committed:
                consume(binding, admission)
            if late:
                rig.world.now = BASE + 3_600_001
            raise OSError("ambiguous_consume_reply")

        rig.gate.consume = reply
        return rig, controller, controller.consume()

    def test_oserror_after_consume_commit_applies_and_journals_without_cancel(self):
        rig, controller, state = self.ambiguous_consume(committed=True)
        self.assertEqual(state["sessions"], 1)
        self.assertEqual(sum(name == "apply" for name, _ in rig.world.trace), 1)
        self.assertEqual(controller._get("consumed", 0), state["consumed"])
        self.assertIs(controller._get("applied", 0), True)
        self.assertIsNone(controller._get("rejected", 0))
        self.assertFalse(rig.capacity.cancelled)

    def test_oserror_after_consume_commit_late_stops_cancels_and_ledgers(self):
        rig, controller, state = self.ambiguous_consume(committed=True, late=True)
        self.assertEqual(state["sessions"], 1)
        self.assertIs(state["stopped"]["session_consumed"], True)
        self.assertIs(state["stopped"]["measurement_started"], False)
        self.assertIs(state["stopped"]["applied"], False)
        self.assertEqual(controller._get("consumed", 0), state["consumed"])
        self.assertFalse(rig.gate.applies)
        self.assertEqual(len(state["ledger"]), 1)
        self.assertEqual(rig.capacity.group, [])

    def test_oserror_before_consume_commit_queries_before_zero_session_refusal(self):
        rig = Rig()
        controller = rig.open()
        controller.mark()
        controller.acquire()
        seen = []
        query = rig.gate.consumption

        def consumption(session):
            seen.append(session)
            return query(session)

        def consume(binding, admission):
            seen.clear()
            raise OSError("before_commit")

        reject = controller._reject

        def rejected(index, reason):
            self.assertEqual(seen, [controller.session_id])
            reject(index, reason)

        rig.gate.consumption = consumption
        rig.gate.consume = consume
        controller._reject = rejected
        state = controller.consume()
        self.assertEqual(state["sessions"], 0)
        self.assertFalse(rig.gate.applies)
        self.assertIsNone(controller._get("consumed", 0))
        self.assertEqual(len(state["ledger"]), 1)

    def failed_cancel_for_refuse(self):
        rig = Rig()
        rig.capacity.outcomes = ["partial"]
        controller = rig.open()
        controller.mark()
        with patch.object(rig.capacity, "cancel", side_effect=OSError("cancel_unavailable")):
            with self.assertRaisesRegex(OSError, "cancel_unavailable"):
                controller.acquire()
        return rig, controller

    def test_refuse_after_failed_cancel_returns_status_without_rewriting_rejection(self):
        rig, controller = self.failed_cancel_for_refuse()
        rejected = copy.deepcopy(controller._get("rejected", 0))
        state = controller.refuse("operator_stop")
        self.assertEqual(state["stopped"], {"reason": "operator_stop"})
        self.assertEqual(state["refused"], [0])
        self.assertEqual(controller._get("rejected", 0), rejected)
        self.assertEqual(len(state["ledger"]), 1)
        self.assertFalse(rig.gate.applies)

    def test_refuse_completes_cancel_once_backend_recovers(self):
        rig, controller = self.failed_cancel_for_refuse()
        controller.refuse("operator_stop")
        for _ in range(3):
            state = rig.open().recover()
        self.assertEqual(state["refused"], [0])
        self.assertEqual(len(state["ledger"]), 1)
        self.assertEqual(sum(name == "cancel" for name, _ in rig.world.trace), 1)
        self.assertEqual(rig.capacity.group, [])
        self.assertEqual(len(rig.capacity.cancelled), 1)

    def call(self, controller, name):
        return (
            getattr(controller, name)("explicit_stop")
            if name == "refuse"
            else getattr(controller, name)()
        )

    def invariant(self, rig):
        rows = rig.journal.rows
        origins = [r for r in rows if r["event"] == "billing_origin"]
        self.assertLessEqual(len(origins), 1)
        self.assertLessEqual(len(rig.gate.consumptions), 1)
        self.assertLessEqual(sum(r["event"] == "consumed" for r in rows), 1)
        self.assertEqual(len(rig.gate.markers), len(set(rig.gate.markers)))
        for name, _value in rig.world.trace:
            if name == "odcr":
                self.assertEqual(len(origins), 1)
        if rig.gate.consumptions:
            self.assertTrue(any(r["event"] == "verified" for r in rows))

    def test_DEC_069_billing_origin_and_effective_deadline(self):
        """DEC-069 billing origin and effective deadline."""
        rig = Rig()
        controller = rig.open()
        controller.mark()
        self.assertIsNone(controller.status()["billing_origin"])
        controller.acquire()
        origin = controller.status()["billing_origin"]
        self.assertEqual(origin, {"session_id": "m5-offline", "t0_ms": BASE})
        self.assertEqual(controller._deadline().effective_ms, BASE + 18_000_000)
        self.assertLess(controller._deadline().effective_ms, utc_ms(D))
        trace = rig.world.trace
        origin_at = next(
            i
            for i, (name, value) in enumerate(trace)
            if name == "fsync" and value["event"] == "billing_origin"
        )
        arm_at = next(i for i, (name, _) in enumerate(trace) if name == "arm")
        confirm_at = next(i for i, (name, _) in enumerate(trace) if name == "confirm")
        odcr_at = next(i for i, (name, _) in enumerate(trace) if name == "odcr")
        self.assertLess(origin_at, arm_at)
        self.assertLess(arm_at, confirm_at)
        self.assertLess(confirm_at, odcr_at)
        self.assertEqual(rig.backstop.armed["m5-offline"], BASE + 18_000_000)
        controller.consume()
        self.assertEqual(controller.status()["sessions"], 1)
        self.assertEqual([n for n, _ in trace if n in ("consume", "apply")], ["consume", "apply"])
        for now in (utc_ms(C) + 1,):
            late = Rig()
            late.world.now = now
            late.run()
            self.assertFalse(late.gate.consumptions)
            self.assertFalse(any(n == "odcr" for n, _ in late.world.trace))
            self.assertEqual(sum(r["event"] == "billing_origin" for r in late.journal.rows), 1)

    def test_Two_reviewed_AZ_plans_with_two_distinct_plan_hash_markers(self):
        """Two reviewed AZ plans with two distinct plan-hash markers."""
        rig = Rig()
        rig.capacity.outcomes = ["refused", "ok"]
        controller = rig.run()
        state = controller.status()
        self.assertEqual(len(rig.gate.markers), 2)
        self.assertEqual(state["sessions"], 1)
        self.assertEqual(state["consumed"]["plan_hash"], rig.plans[1].plan_hash)
        self.assertEqual(state["unused"], [rig.plans[0].plan_hash])
        self.assertEqual(state["billing_origin"]["t0_ms"], BASE)
        self.assertEqual(sum(r["event"] == "billing_origin" for r in rig.journal.rows), 1)
        names = [n for n, _ in rig.world.trace]
        self.assertLess(names.index("cancel"), len(names) - 1 - names[::-1].index("odcr"))
        self.assertEqual(sum(n == "consume" for n in names), 1)

    def test_Every_reviewed_AZ_alternative_refuses(self):
        """Every reviewed AZ alternative refuses."""
        rig = Rig()
        rig.capacity.outcomes = ["refused", "refused"]
        state = rig.run().status()
        self.assertEqual(state["sessions"], 0)
        self.assertEqual(len(state["unused"]), 2)
        self.assertEqual(state["refused"], [0, 1])
        self.assertEqual(sum(r["event"] == "billing_origin" for r in rig.journal.rows), 1)
        self.assertFalse(any(r["event"] == "consumed" for r in rig.journal.rows))
        self.assertEqual(sum(n == "cancel" for n, _ in rig.world.trace), 2)

    def test_An_alternative_whose_literal_C_or_D_session_differs(self):
        """An alternative whose literal C or D_session differs."""
        for field, value in (
            ("C", "2026-10-19T01:00:01Z"),
            ("D_session", "2026-10-19T06:00:01Z"),
            ("session_id", "other"),
            ("capacity", Binding(GROUP + "other", "us-east-1b")),
        ):
            with self.subTest(field=field):
                rig = Rig()
                rig.plans[1] = replace(rig.plans[1], **{field: value})
                with self.assertRaises(IntegrityError):
                    rig.open().mark()
                self.assertEqual(rig.journal.rows, [])
                self.assertEqual(rig.world.trace, [])

    def test_A_reservation_is_partly_acquired_then_fails_verification(self):
        """A reservation is partly acquired, then fails verification and is cancelled."""
        rig = Rig()
        rig.capacity.outcomes = ["partial", "refused"]
        rig.capacity.acquire_advance = 20
        state = rig.run().status()
        self.assertEqual(state["sessions"], 0)
        self.assertEqual(
            state["ledger"][0],
            {"t0_ms": BASE, "stop_ms": BASE + 30, "billed_ms": 30, "cost_micros": 60},
        )
        self.assertEqual(rig.capacity.group, [])
        self.assertTrue(all(r["verified"] for r in rig.capacity.cancelled.values()))
        self.assertFalse(any(r["event"] == "consumed" for r in rig.journal.rows))

    def test_Independent_backstop_arming_is_not_confirmed(self):
        """Independent backstop arming is not confirmed after the durable billing-origin record."""
        for field in ("arm_ok", "confirm_ok"):
            rig = Rig()
            setattr(rig.backstop, field, False)
            rig.run()
            self.assertFalse(any(n == "odcr" for n, _ in rig.world.trace))
            self.assertFalse(rig.gate.consumptions)
            self.assertEqual(sum(r["event"] == "billing_origin" for r in rig.journal.rows), 1)

    def test_The_full_remaining_work_check_fails_immediately_before_consume(self):
        """The full remaining-work check fails immediately before consume after ODCR acquisition."""
        for extra in (0, 1):
            rig = Rig()
            rig.plans = [
                replace(p, C="2026-10-19T03:00:00Z", D_session="2026-10-19T08:00:00Z")
                for p in rig.plans
            ]
            controller = rig.open()
            controller.mark()
            controller.acquire()
            rig.world.now = BASE + 1_700_000
            # The old time boundary is now shadowed by the stricter readiness
            # refusal. Keep the remaining-work wiring observable below it by
            # making the synthetic setup allowance exactly fit / one ms short.
            from inference_platform.inf037b_controller import BOUNDS_MS

            with patch.dict(BOUNDS_MS, preparation=BOUNDS_MS["preparation"] + extra):
                state = controller.consume()
            self.assertEqual(state["sessions"], 0 if extra else 1)
            if extra:
                self.assertEqual(state["unused"], [p.plan_hash for p in rig.plans])
                self.assertGreater(state["ledger"][0]["cost_micros"], 0)
                self.assertFalse(any(n == "apply" for n, _ in rig.world.trace))

    def test_Insufficient_immutable_deadline_for_all_remaining_attempts(self):
        """Insufficient immutable deadline for all remaining attempts: late consume and extension."""
        rig = Rig()
        controller = rig.open()
        controller.mark()
        controller.acquire()
        rig.world.now = utc_ms(C) + 1
        self.assertEqual(controller.consume()["sessions"], 0)
        rig.plans = [
            replace(p, C="2026-10-19T02:00:00Z", D_session="2026-10-19T07:00:00Z")
            for p in rig.plans
        ]
        with self.assertRaisesRegex(IntegrityError, "reopened_binding"):
            rig.open()

    def test_reservation_attributes_and_exclusivity_are_rechecked(self):
        adverse = {
            "zone": "us-east-1f",
            "instance_type": "g5.xlarge",
            "platform": "Windows",
            "tenancy": "dedicated",
            "total": 1,
            "available": 1,
            "state": "pending",
            "match_criteria": "open",
            "reservation_id": "",
        }
        for field, value in adverse.items():
            for phase in ("acquire", "consume"):
                with self.subTest(field=field, phase=phase):
                    rig = Rig()
                    controller = rig.open()
                    controller.mark()
                    if phase == "acquire":
                        rig.capacity.overrides[field] = value
                    controller.acquire()
                    if phase == "consume":
                        rig.capacity.results[controller._token(0)][field] = value
                        controller.consume()
                    self.assertFalse(rig.gate.consumptions)
                    self.assertTrue(rig.capacity.cancelled)
        rig = Rig()
        controller = rig.open()
        controller.mark()
        controller.acquire()
        rig.capacity.group.append("cr-intruder")
        with self.assertRaisesRegex(IntegrityError, "cancelled_group_empty"):
            controller.consume()
        self.assertFalse(rig.gate.consumptions)

    def test_marker_tamper_and_saved_plan_hash_refuse(self):
        for override in (
            {"committed": False},
            {"committed": 1},
            {"binding": {}},
            {"review_commit": "no"},
        ):
            rig = Rig()
            rig.gate.marker_override = override
            with self.assertRaises(IntegrityError):
                rig.open().mark()
            self.assertFalse(rig.capacity.results)
        rig = Rig()
        rig.plans[0] = replace(rig.plans[0], saved_plan=b"tamper")
        with self.assertRaisesRegex(IntegrityError, "plan_hash"):
            rig.open()

    def test_cancel_verification_blocks_advance_and_recovery_records_cost(self):
        rig = Rig()
        rig.capacity.outcomes = ["partial", "ok"]
        rig.capacity.cancel_ok = False
        controller = rig.open()
        controller.mark()
        with self.assertRaisesRegex(IntegrityError, "cancellation_verified"):
            controller.acquire()
        self.assertEqual(sum(n == "odcr" for n, _ in rig.world.trace), 1)
        with self.assertRaises(IntegrityError):
            rig.open().acquire()
        self.assertEqual(sum(n == "odcr" for n, _ in rig.world.trace), 1)
        for receipt in rig.capacity.cancelled.values():
            receipt["verified"] = True
        recovered = rig.open()
        recovered.recover()
        recovered.acquire()
        self.assertEqual(recovered.consume()["sessions"], 1)

    def test_lost_reply_cancels_by_durable_token(self):
        rig = Rig()
        rig.capacity.outcomes = ["lost_reply", "ok"]
        state = rig.run().status()
        self.assertEqual(state["sessions"], 1)
        self.assertGreater(state["ledger"][0]["cost_micros"], 0)
        self.assertEqual(len(rig.capacity.cancelled), 1)

    def test_fsync_ack_and_readback_are_required_before_effects(self):
        for failure in ("ack", "bad_readback"):
            rig = Rig()
            setattr(rig.journal, failure, False if failure == "ack" else True)
            with self.assertRaises(IntegrityError):
                rig.open()
            self.assertFalse(rig.gate.markers)
            self.assertFalse(rig.capacity.results)

    def test_origin_is_the_durable_write_time_and_never_recomputed(self):
        rig = Rig()
        rig.journal.origin_delay = 123
        controller = rig.open()
        controller.mark()
        controller.acquire()
        self.assertEqual(controller.status()["billing_origin"]["t0_ms"], BASE + 123)
        rig.world.now += 300
        rig.journal.origin_delay = 900
        controller = rig.open()
        controller.recover()
        self.assertEqual(controller.status()["billing_origin"]["t0_ms"], BASE + 123)
        self.assertEqual(rig.backstop.armed["m5-offline"], BASE + 123 + 18_000_000)
        controller.consume()
        self.assertEqual(sum(r["event"] == "billing_origin" for r in rig.journal.rows), 1)

    def test_origin_ack_and_readback_failure_prevent_odcr(self):
        for failure in ("ack", "bad_readback"):
            rig = Rig()
            controller = rig.open()
            controller.mark()
            setattr(rig.journal, failure, False if failure == "ack" else True)
            # Isolate failure at the origin, after the acquisition intent fsync.
            original = rig.journal.append_origin_fsync
            setattr(rig.journal, failure, True if failure == "ack" else False)

            def broken(row, *, original=original, failure=failure, rig=rig):
                setattr(rig.journal, failure, False if failure == "ack" else True)
                return original(row)

            rig.journal.append_origin_fsync = broken
            with self.assertRaises(IntegrityError):
                controller.acquire()
            self.assertFalse(any(n == "odcr" for n, _ in rig.world.trace))
            self.assertFalse(rig.gate.consumptions)

    def test_deadline_and_remaining_checks_are_called_at_consume(self):
        for check in ("SessionDeadline.check_consume", "remaining_work"):
            rig = Rig()
            controller = rig.open()
            controller.mark()
            controller.acquire()
            with patch(
                "inference_platform.inf037b_controller." + check,
                side_effect=IntegrityError("sentinel_check"),
            ) as guard:
                self.assertEqual(controller.consume()["sessions"], 0)
                guard.assert_called()
                if check == "remaining_work":
                    self.assertIs(guard.call_args.kwargs["before_attempt1"], True)
                    self.assertEqual(
                        (guard.call_args.kwargs["attempts"], guard.call_args.kwargs["resets"]),
                        (3, 2),
                    )
            self.assertFalse(rig.gate.applies)

    def test_initial_group_empty_and_marker_order_are_required(self):
        rig = Rig()
        controller = rig.open()
        with self.assertRaisesRegex(IntegrityError, "markers_required"):
            controller.acquire()
        self.assertIsNone(controller.status()["billing_origin"])
        controller.mark()
        rig.capacity.group = ["cr-existing"]
        with self.assertRaisesRegex(IntegrityError, "initial_group_empty"):
            controller.acquire()
        self.assertIsNone(controller.status()["billing_origin"])
        self.assertFalse(rig.capacity.results)

    def test_invalid_inputs_fail_before_marker(self):
        for field, value in (
            ("saved_plan", bytearray(b"x")),
            ("session_id", ""),
            ("session_id", 1),
            ("capacity", None),
            ("C", "2026-10-19T01:00:00+00:00"),
            ("C", "2026-02-30T01:00:00Z"),
            ("C", "1969-12-31T23:59:59Z"),
        ):
            rig = Rig()
            rig.plans[0] = replace(rig.plans[0], **{field: value})
            with self.subTest(field=field, value=value), self.assertRaises(IntegrityError):
                rig.open()
            self.assertFalse(rig.gate.markers)
        for items in ([], {}, [None], [plans()[0], plans()[0]]):
            rig = Rig()
            rig.plans = items
            with self.assertRaises(IntegrityError):
                rig.open()

    def test_corrupt_journal_shape_sequence_and_predecessors_refuse(self):
        rig = Rig()
        rig.run()
        for index in range(len(rig.journal.rows)):
            for field, value in (
                ("seq", -1),
                ("seq", True),
                ("event", "unknown"),
                ("index", -2),
                ("index", 2),
                ("index", True),
            ):
                branch = copy.deepcopy(rig)
                branch.journal.rows[index][field] = value
                with (
                    self.subTest(index=index, field=field, value=value),
                    self.assertRaises(IntegrityError),
                ):
                    branch.open()
        for event in (
            "marker",
            "acquired",
            "verified",
            "rejected",
            "cancelled",
            "ledger",
            "advanced",
            "consume_intent",
            "consumed",
            "applied",
        ):
            branch = Rig()
            branch.open()
            branch.journal.rows.append({"seq": 2, "event": event, "index": 0, "data": True})
            with (
                self.subTest(event=event),
                self.assertRaisesRegex(IntegrityError, "journal_predecessor"),
            ):
                branch.open()
        branch = Rig()
        branch.journal.rows = [None]
        with self.assertRaisesRegex(IntegrityError, "journal_shape"):
            branch.open()

    def test_clock_and_ledger_negative_one_tick_controls(self):
        for bad_clock in (-1, True):
            rig = Rig()
            controller = rig.open()
            rig.world.now = bad_clock
            with self.assertRaisesRegex(IntegrityError, "clock"):
                controller._now()
        for field, value in (
            ("stop_ms", BASE - 1),
            ("billed_ms", 9),
            ("cost_micros", -1),
            ("t0_ms", BASE + 1),
        ):
            rig = Rig()
            rig.capacity.outcomes = ["partial", "ok"]
            rig.capacity.ledger_override[field] = value
            controller = rig.open()
            controller.mark()
            with self.subTest(field=field), self.assertRaises(IntegrityError):
                controller.acquire()
            self.assertEqual(controller._index(), 0)
            self.assertFalse(rig.gate.consumptions)

    def test_consume_after_explicit_refusal_cannot_resume_consumption(self):
        rig = Rig()
        controller = rig.open()
        controller.mark()
        controller.acquire()
        controller.refuse("explicit_stop")
        with self.assertRaisesRegex(IntegrityError, "stopped"):
            rig.open().consume()
        rig.open().recover()
        self.assertFalse(rig.gate.consumptions)

    def test_duplicate_and_changed_durable_facts_refuse(self):
        rig = Rig()
        controller = rig.open()
        controller.mark()
        with self.assertRaisesRegex(IntegrityError, "immutable_row"):
            controller._write("marker_intent", {}, 0)
        row = copy.deepcopy(rig.journal.rows[-1])
        row["seq"] = len(rig.journal.rows) + 1
        rig.journal.rows.append(row)
        with self.assertRaisesRegex(IntegrityError, "journal_duplicate"):
            rig.open()

    def test_literal_and_saved_input_checks_independently(self):
        for literal, reason in (
            ("2026-1-1T00:00:00Z", "utc_literal"),
            ("1969-12-31T23:59:59Z", "utc_nonnegative"),
        ):
            with self.subTest(literal=literal), self.assertRaisesRegex(IntegrityError, reason):
                utc_ms(literal)
        for field, value in (
            ("saved_plan", bytearray(plans()[0].saved_plan)),
            ("session_id", ""),
            ("session_id", 1),
            ("D_session", "2026-10-19T06:00:01Z"),
        ):
            rig = Rig()
            rig.plans = [replace(rig.plans[0], **{field: value})]
            with self.subTest(field=field, value=value), self.assertRaises(IntegrityError):
                rig.open().mark()
            self.assertFalse(rig.gate.markers)
        rig = Rig()
        rig.plans = [
            replace(p, C="2026-10-19T01:00:01Z", D_session="2026-10-19T06:00:01Z") if i else p
            for i, p in enumerate(rig.plans)
        ]
        with self.assertRaisesRegex(IntegrityError, "shared_literals"):
            rig.open()

    def test_replay_global_indices_acquisition_order_origin_and_ledger(self):
        for index, reason in (
            (-2, "journal_index"),
            (2, "journal_index"),
            (-1, "journal_event_index"),
        ):
            rig = Rig()
            rig.open()
            rig.journal.rows.append(
                {"seq": 2, "event": "marker_intent", "index": index, "data": {}}
            )
            with self.subTest(index=index), self.assertRaisesRegex(IntegrityError, reason):
                rig.open()
        rig = Rig()
        rig.open()
        rig.journal.rows.append({"seq": 2, "event": "acquire_intent", "index": 0, "data": {}})
        with self.assertRaisesRegex(IntegrityError, "journal_acquire_order"):
            rig.open()
        rig = Rig()
        controller = rig.open()
        controller.mark()
        controller._write("acquire_intent", {"token": controller._token(0)}, 0)
        rig.journal.rows.append(
            {"seq": len(rig.journal.rows) + 1, "event": "acquired", "index": 0, "data": {}}
        )
        with self.assertRaisesRegex(IntegrityError, "journal_origin"):
            rig.open()
        rig = Rig()
        rig.capacity.outcomes = ["partial", "refused"]
        rig.run()
        prefix = rig.journal.rows[
            : next(i for i, row in enumerate(rig.journal.rows) if row["event"] == "rejected") + 1
        ]
        branch = copy.deepcopy(rig)
        branch.journal.rows = prefix + [
            {"seq": len(prefix) + 1, "event": "verified", "index": 0, "data": True}
        ]
        with self.assertRaisesRegex(IntegrityError, "journal_not_rejected"):
            branch.open()
        branch = copy.deepcopy(rig)
        branch.journal.rows = [
            row
            for row in branch.journal.rows
            if not (row["event"] == "ledger" and row["index"] == 0)
        ]
        for seq, row in enumerate(branch.journal.rows, 1):
            row["seq"] = seq
        with self.assertRaisesRegex(IntegrityError, "journal_ledger"):
            branch.open()

    def test_origin_backend_receipt_checks(self):
        for field, value, reason in (
            ("fsync", False, "origin_fsync_ack"),
            ("seq", 999, "origin_envelope"),
            ("session_id", "other", "origin_key"),
            ("t0_ms", -1, "origin_time"),
        ):
            rig = Rig()
            controller = rig.open()
            controller.mark()
            original = rig.journal.append_origin_fsync

            def corrupt(row, *, original=original, field=field, value=value):
                ack = original(row)
                if field == "fsync":
                    ack[field] = value
                elif field == "seq":
                    ack["row"][field] = value
                else:
                    ack["row"]["data"][field] = value
                return ack

            rig.journal.append_origin_fsync = corrupt
            with self.subTest(field=field), self.assertRaisesRegex(IntegrityError, reason):
                controller._origin()
            self.assertFalse(rig.capacity.results)

    def test_journal_container_marker_and_ledger_receipt_shapes(self):
        for rows in (None, (), {}):
            rig = Rig()
            rig.journal.read = lambda rows=rows: rows
            with self.assertRaisesRegex(IntegrityError, "journal_rows"):
                rig.open()
        rig = Rig()
        rig.gate.marker = lambda binding: None
        with self.assertRaisesRegex(IntegrityError, "marker_shape"):
            rig.open().mark()
        rig = Rig()
        rig.capacity.outcomes = ["partial", "refused"]
        rig.capacity.ledger = lambda token, t0: None
        controller = rig.open()
        controller.mark()
        with self.assertRaisesRegex(IntegrityError, "ledger_receipt"):
            controller.acquire()

    def test_ledger_one_tick_before_origin_is_rejected(self):
        rig = Rig()
        rig.capacity.outcomes = ["partial", "refused"]
        rig.capacity.ledger_override.update(stop_ms=BASE - 1, billed_ms=-1, cost_micros=0)
        rig.capacity.cancel_advance = -1
        controller = rig.open()
        controller.mark()
        with self.assertRaisesRegex(IntegrityError, "ledger_stop"):
            controller.acquire()

    def test_atomic_consume_boundary_rechecks_time(self):
        rig = Rig()
        controller = rig.open()
        controller.mark()
        controller.acquire()
        rig.world.now = utc_ms(C)
        rig.gate.consume_delay = 1
        self.assertEqual(controller.consume()["sessions"], 0)
        self.assertFalse(rig.gate.applies)

    def test_lost_consume_receipt_hash_and_session_are_bound(self):
        for field in ("plan_hash", "session_id"):
            rig = Rig()
            rig.world.crash_operation = "consume"
            with self.assertRaises(Crash):
                rig.run()
            rig.gate.consumptions["m5-offline"][field] = "other"
            with self.assertRaisesRegex(
                IntegrityError, "consumed_" + ("hash" if field == "plan_hash" else "session")
            ):
                rig.open().recover()
            self.assertFalse(rig.gate.applies)

    def test_each_partial_reservation_requires_complete_verified_cancellation(self):
        for broken in ("complete", "states", "reservation_ids"):
            rig = Rig()
            rig.capacity.outcomes = ["partial", "ok"]
            original = rig.capacity.cancellation

            def receipt(token, *, original=original, broken=broken):
                result = original(token)
                if broken == "complete":
                    result["complete"] = False
                elif broken == "states":
                    result["reservation_ids"].append("cr-partial-2")
                    result["states"]["cr-partial-2"] = "active"
                else:
                    result["reservation_ids"] *= 2
                return result

            rig.capacity.cancellation = receipt
            controller = rig.open()
            controller.mark()
            with self.subTest(broken=broken), self.assertRaises(IntegrityError):
                controller.acquire()
            self.assertEqual(controller._index(), 0)
            self.assertEqual(sum(n == "odcr" for n, _ in rig.world.trace), 1)
            self.assertFalse(rig.gate.consumptions)

    def test_partial_acquisition_cannot_have_zero_cost_or_shorten_billing(self):
        for override in ({"cost_micros": 0}, {"stop_ms": BASE, "billed_ms": 0}):
            rig = Rig()
            rig.capacity.outcomes = ["partial", "ok"]
            rig.capacity.ledger_override = override
            controller = rig.open()
            controller.mark()
            with self.subTest(override=override), self.assertRaises(IntegrityError):
                controller.acquire()
            self.assertEqual(controller._index(), 0)

    def test_stop_during_interrupted_consume_intent_is_recovered_as_refusal(self):
        rig = Rig()
        controller = rig.open()
        controller.mark()
        controller.acquire()
        rig.journal.cut = len(rig.journal.rows) + 1
        with self.assertRaises(Crash):
            controller.consume()
        rig.journal.cut = len(rig.journal.rows) + 1
        with self.assertRaises(Crash):
            rig.open().refuse("stop_before_consume")
        rig.open().recover()
        self.assertFalse(rig.gate.consumptions)
        self.assertFalse(rig.gate.applies)
        self.assertEqual(rig.capacity.group, [])

    def test_consumed_state_refuses_all_mutating_public_calls(self):
        rig = Rig()
        rig.run()
        for name in ("mark", "acquire", "consume", "refuse"):
            branch = copy.deepcopy(rig)
            before = copy.deepcopy(branch.journal.rows)
            with (
                self.subTest(name=name),
                self.assertRaisesRegex(IntegrityError, "already_consumed"),
            ):
                self.call(branch.open(), name)
            self.assertEqual(branch.journal.rows, before)
            self.assertFalse(branch.capacity.cancelled)
            self.assertEqual(len(branch.capacity.group), 1)

    def test_alternative_reuses_t0_but_refuses_if_C_has_passed(self):
        rig = Rig()
        rig.capacity.outcomes = ["refused", "ok"]
        controller = rig.open()
        controller.mark()
        controller.acquire()
        rig.world.now = utc_ms(C) + 1
        state = rig.open().acquire()
        self.assertEqual(state["sessions"], 0)
        self.assertEqual(sum(n == "odcr" for n, _ in rig.world.trace), 1)
        self.assertEqual(state["billing_origin"]["t0_ms"], BASE)

    def test_missing_or_foreign_billing_origin_refuses(self):
        rig = Rig()
        controller = rig.open()
        with self.assertRaisesRegex(IntegrityError, "billing_origin_required"):
            controller._deadline()
        controller.mark()
        controller.acquire()
        for row in rig.journal.rows:
            if row["event"] == "billing_origin":
                row["data"]["session_id"] = "foreign"
        reopened = rig.open()
        reopened.consume()
        self.assertFalse(rig.gate.consumptions)

    def test_arm_error_even_with_previously_confirmed_backstop_refuses_consume(self):
        rig = Rig()
        controller = rig.open()
        controller.mark()
        controller.acquire()
        rig.backstop.arm_ok = False
        self.assertEqual(controller.consume()["sessions"], 0)
        self.assertFalse(rig.gate.applies)

    def test_cancellation_receipt_shape_and_unbilled_capacity_refuse(self):
        rig = Rig()
        rig.capacity.outcomes = ["partial", "refused"]
        rig.capacity.cancellation = lambda token: None
        controller = rig.open()
        controller.mark()
        with self.assertRaisesRegex(IntegrityError, "cancellation_receipt"):
            controller.acquire()
        rig = Rig()
        controller = rig.open()
        controller.mark()
        controller._write("acquire_intent", {"token": controller._token(0)}, 0)
        rig.capacity.results[controller._token(0)] = {
            "reservation_id": "cr-orphan",
            "state": "active",
        }
        rig.capacity.ids[controller._token(0)] = "cr-orphan"
        with self.assertRaisesRegex(IntegrityError, "no_unbilled_acquisition"):
            controller.refuse("unbilled_capacity")
        self.assertEqual(controller._index(), 0)

    def test_ledger_origin_and_negative_cost_are_independent_checks(self):
        rig = Rig()
        rig.capacity.outcomes = ["partial", "refused"]
        rig.capacity.ledger_override.update(t0_ms=BASE + 1, billed_ms=9)
        controller = rig.open()
        controller.mark()
        with self.assertRaisesRegex(IntegrityError, "ledger_origin"):
            controller.acquire()
        for value in (-1, False):
            rig = Rig()
            rig.capacity.outcomes = ["refused", "refused"]
            rig.capacity.ledger_override["cost_micros"] = value
            controller = rig.open()
            controller.mark()
            with self.subTest(value=value), self.assertRaisesRegex(IntegrityError, "ledger_cost"):
                controller.acquire()

    def test_clock_one_tick_before_origin_refuses_acquire_and_consume(self):
        for operation in ("acquire", "consume"):
            rig = Rig()
            controller = rig.open()
            controller.mark()
            if operation == "consume":
                controller.acquire()
            else:
                controller._origin()
            rig.world.now = BASE - 1
            self.assertEqual(getattr(controller, operation)()["sessions"], 0)
            if operation == "acquire":
                self.assertFalse(any(n == "odcr" for n, _ in rig.world.trace))

    def test_consume_requires_current_index_and_verified_state_before_writes(self):
        rig = Rig()
        controller = rig.open()
        before = copy.deepcopy(rig.journal.rows)
        with self.assertRaisesRegex(IntegrityError, "verified_required"):
            controller.consume()
        self.assertEqual(rig.journal.rows, before)
        rig.capacity.outcomes = ["refused", "refused"]
        controller = rig.run()
        before = copy.deepcopy(rig.journal.rows)
        with self.assertRaisesRegex(IntegrityError, "consume_index"):
            controller.consume()
        self.assertEqual(rig.journal.rows, before)

    def test_rejected_verified_reservation_cannot_reenter_consume(self):
        rig = Rig()
        controller = rig.open()
        controller.mark()
        controller.acquire()
        rig.capacity.cancel_ok = False
        rig.world.now = utc_ms(C) + 1
        with self.assertRaisesRegex(IntegrityError, "cancellation_verified"):
            controller.consume()
        with self.assertRaisesRegex(IntegrityError, "rejected_not_consumable"):
            rig.open().consume()

    def test_refusal_requires_nonempty_exact_reason(self):
        for reason in ("", None, False, 1):
            rig = Rig()
            controller = rig.open()
            before = copy.deepcopy(rig.journal.rows)
            with (
                self.subTest(reason=reason),
                self.assertRaisesRegex(IntegrityError, "refusal_reason"),
            ):
                controller.refuse(reason)
            self.assertEqual(rig.journal.rows, before)

    def test_crash_cut_at_every_row_and_every_public_call_after_reopen(self):
        for outcomes, consume in (
            (["refused", "ok"], True),
            (["partial", "refused"], True),
            (["ok", "ok"], False),
        ):
            baseline = Rig()
            baseline.capacity.outcomes = outcomes.copy()
            expected = baseline.run(consume=consume).status()
            for cut in range(1, len(baseline.journal.rows) + 1):
                with self.subTest(outcomes=outcomes, consume=consume, cut=cut):
                    rig = Rig()
                    rig.capacity.outcomes = outcomes.copy()
                    rig.journal.cut = cut
                    with self.assertRaises(Crash):
                        rig.run(consume=consume)
                    for name in PUBLIC_CALLS:
                        branch = copy.deepcopy(rig)
                        reopened = branch.open()
                        try:
                            self.call(reopened, name)
                        except IntegrityError:
                            pass
                        self.invariant(branch)
                    actual = rig.run(consume=consume).status()
                    self.assertEqual(actual, expected)
                    self.invariant(rig)

    def test_external_effect_crash_before_ack_recovers_once(self):
        for operation in ("marker", "odcr", "add", "consume", "apply", "cancel"):
            rig = Rig()
            rig.capacity.outcomes = ["partial", "ok"] if operation == "cancel" else ["ok", "ok"]
            rig.world.crash_operation = operation
            with self.assertRaises(Crash):
                rig.run()
            self.assertEqual(rig.run().status()["sessions"], 1)
            self.assertEqual(sum(n == "consume" for n, _ in rig.world.trace), 1)
            self.assertEqual(sum(n == "apply" for n, _ in rig.world.trace), 1)
            self.invariant(rig)

    def test_every_public_call_order_into_consumed_and_refused_states(self):
        for terminal in ("consumed", "refused"):
            rig = Rig()
            if terminal == "refused":
                rig.capacity.outcomes = ["refused", "refused"]
            rig.run()
            for sequence in itertools.product(PUBLIC_CALLS, repeat=3):
                with self.subTest(terminal=terminal, sequence=sequence):
                    branch = copy.deepcopy(rig)
                    for name in sequence:
                        controller = branch.open()
                        try:
                            self.call(controller, name)
                        except IntegrityError:
                            pass
                    self.invariant(branch)
                    self.assertEqual(
                        len(branch.gate.consumptions), 1 if terminal == "consumed" else 0
                    )
            for sequence in itertools.permutations(PUBLIC_CALLS):
                branch = Rig()
                branch.capacity.outcomes = (
                    ["refused", "refused"] if terminal == "refused" else ["ok", "ok"]
                )
                for name in sequence:
                    try:
                        self.call(branch.open(), name)
                    except IntegrityError:
                        pass
                self.invariant(branch)

    def test_omitted_acquired_id_blocks_partial_mismatch_and_lost_reply(self):
        for outcome in ("partial", "mismatch", "lost_reply"):
            rig = Rig()
            rig.capacity.outcomes = ["ok" if outcome == "mismatch" else outcome, "ok"]
            if outcome == "mismatch":
                rig.capacity.overrides["platform"] = "Windows"
            original = rig.capacity.cancellation

            def omit(token, *, original=original):
                row = original(token)
                row.update(reservation_ids=[], states={})
                return row

            rig.capacity.cancellation = omit
            rig.capacity.ledger_override["cost_micros"] = 0
            controller = rig.open()
            controller.mark()
            with (
                self.subTest(outcome=outcome),
                self.assertRaisesRegex(IntegrityError, "acquired_ids_cancelled"),
            ):
                controller.acquire()
            self.assertEqual(controller._index(), 0)
            with self.assertRaisesRegex(IntegrityError, "acquired_ids_cancelled"):
                rig.open().acquire()
            self.assertEqual(sum(name == "odcr" for name, _ in rig.world.trace), 1)
            self.assertFalse(rig.gate.consumptions)

    def test_cancellation_ids_include_both_durable_and_lookup_identities(self):
        for source in ("durable", "lookup"):
            rig = Rig()
            rig.capacity.outcomes = ["partial", "ok"]
            controller = rig.open()
            controller.mark()
            lookup = rig.capacity.lookup
            receipt = rig.capacity.cancellation

            def observed(token, *, lookup=lookup, controller=controller, source=source):
                row = lookup(token)
                if controller._get("rejected", 0) is not None:
                    if source == "durable":
                        return None
                    if row is not None:
                        row["reservation_id"] = "cr-observed-alternative"
                return row

            def cancelled(token, *, receipt=receipt, source=source):
                row = receipt(token)
                if source == "durable":
                    row.update(reservation_ids=[], states={})
                return row

            rig.capacity.lookup = observed
            rig.capacity.cancellation = cancelled
            with (
                self.subTest(source=source),
                self.assertRaisesRegex(IntegrityError, "acquired_ids_cancelled"),
            ):
                controller.acquire()
            self.assertEqual(controller._index(), 0)

    def test_post_cancel_lookup_must_be_cancelled_with_and_without_origin(self):
        for origin in (True, False):
            rig = Rig()
            controller = rig.open()
            controller.mark()
            token = controller._token(0)
            if not origin:
                rig.journal.cut = len(rig.journal.rows) + 1
                with self.assertRaises(Crash):
                    controller.acquire()
                controller = rig.open()
                rig.capacity.results[token] = {"reservation_id": "cr-orphan", "state": "active"}
                rig.capacity.ids[token] = "cr-orphan"
            else:
                rig.capacity.outcomes = ["partial", "ok"]
            cancel = rig.capacity.cancel

            def leave_active(token, group, *, cancel=cancel, rig=rig):
                before = copy.deepcopy(rig.capacity.results.get(token))
                cancel(token, group)
                rig.capacity.results[token] = before

            rig.capacity.cancel = leave_active
            with (
                self.subTest(origin=origin),
                self.assertRaisesRegex(IntegrityError, "cancelled_lookup"),
            ):
                if origin:
                    controller.acquire()
                else:
                    controller.refuse("orphan_stop")
            self.assertEqual(controller._index(), 0)
            self.assertIsNone(controller._get("advanced", 0))

    def test_partial_cost_does_not_depend_on_receipt_id_list(self):
        rig = Rig()
        rig.capacity.overrides["reservation_id"] = ""
        rig.capacity.ledger_override["cost_micros"] = 0
        receipt = rig.capacity.cancellation

        def no_ids(token):
            row = receipt(token)
            row.update(reservation_ids=[], states={})
            return row

        rig.capacity.cancellation = no_ids
        controller = rig.open()
        controller.mark()
        with self.assertRaisesRegex(IntegrityError, "partial_cost"):
            controller.acquire()
        self.assertEqual(controller._index(), 0)

    def test_cancel_intent_retains_lost_reply_acquisition_after_lookup_disappears(self):
        rig = Rig()
        rig.capacity.outcomes = ["lost_reply", "ok"]
        cancel = rig.capacity.cancel

        def remove_lookup(token, group):
            cancel(token, group)
            rig.capacity.results.pop(token, None)

        rig.capacity.cancel = remove_lookup
        controller = rig.open()
        controller.mark()
        rig.journal.cut = len(rig.journal.rows) + 5
        with self.assertRaises(Crash):
            controller.acquire()
        reopened = rig.open()
        self.assertIsNone(reopened._get("acquired", 0))
        self.assertIsNone(rig.capacity.lookup(reopened._token(0)))
        self.assertIs(reopened._get("cancel_intent", 0)["acquisition_existed"], True)
        rig.capacity.ledger_override["cost_micros"] = 0
        with self.assertRaisesRegex(IntegrityError, "partial_cost"):
            reopened.recover()
        self.assertEqual(reopened._index(), 0)
        rig.capacity.ledger_override["cost_micros"] = 20
        self.assertEqual(rig.open().recover()["refused"], [0])

    def test_cancel_intent_retains_expected_id_after_lost_cancel_reply(self):
        rig = Rig()
        rig.capacity.outcomes = ["lost_reply", "ok"]
        rig.world.crash_operation = "cancel"
        with self.assertRaises(Crash):
            rig.run()
        controller = rig.open()
        token = controller._token(0)
        self.assertIsNone(controller._get("acquired", 0))
        rig.capacity.results.pop(token)
        rig.capacity.cancelled[token].update(reservation_ids=[], states={})
        rig.capacity.ledger_override["cost_micros"] = 20
        with self.assertRaisesRegex(IntegrityError, "acquired_ids_cancelled"):
            controller.recover()
        self.assertEqual(controller._index(), 0)

    def lost_consume(self, *, later_C=False):
        rig = Rig()
        if later_C:
            rig.plans = [
                replace(p, C="2026-10-19T06:00:00Z", D_session="2026-10-19T11:00:00Z")
                for p in rig.plans
            ]
        rig.world.crash_operation = "consume"
        with self.assertRaises(Crash):
            rig.run()
        return rig

    def test_lost_consume_recovery_rechecks_C_remaining_boundary_and_D_eff(self):
        cases = (
            ("C+1", False, 3_600_001, False),
            ("readiness-1", True, 1_799_999, True),
            ("readiness", True, 1_800_000, False),
            ("readiness+1", True, 1_800_001, False),
            ("old-remaining-boundary", True, 3_600_000, False),
            ("D_eff+1", True, 18_000_001, False),
        )
        for name, later_C, elapsed, admissible in cases:
            rig = self.lost_consume(later_C=later_C)
            rig.world.now = BASE + elapsed
            with self.subTest(case=name):
                state = rig.open().recover()
                self.assertEqual(state["sessions"], 1)
                self.assertEqual(bool(rig.gate.applies), admissible)
                if not admissible:
                    self.assertIs(state["stopped"]["session_consumed"], True)
                    self.assertIs(state["stopped"]["measurement_started"], False)
                    self.assertIs(state["stopped"]["applied"], False)
                    self.assertEqual(rig.capacity.group, [])
                    self.assertEqual(len(state["ledger"]), 1)
                    self.assertEqual(state["ledger"][0]["t0_ms"], BASE)
                    self.assertGreater(state["ledger"][0]["cost_micros"], 0)
                    self.assertFalse(rig.gate.applies)

    def test_post_consume_journal_delay_rechecks_time_before_apply(self):
        rig = Rig()
        controller = rig.open()
        controller.mark()
        controller.acquire()
        append = rig.journal.append_fsync

        def delay(row):
            ack = append(row)
            if row["event"] == "consumed":
                rig.world.now = BASE + 3_600_001
            return ack

        rig.journal.append_fsync = delay
        state = controller.consume()
        self.assertEqual(state["sessions"], 1)
        self.assertFalse(rig.gate.applies)
        self.assertIs(state["stopped"]["measurement_started"], False)
        self.assertEqual(len(state["ledger"]), 1)

    def test_completed_recover_uses_applied_row_without_apply_or_arm(self):
        rig = Rig()
        controller = rig.run()
        self.assertIs(controller._get("applied", 0), True)
        with (
            patch.object(rig.gate, "apply_once") as apply,
            patch.object(rig.backstop, "arm") as arm,
            patch.object(
                rig.gate,
                "application",
                side_effect=AssertionError("durable applied row is sufficient"),
            ),
        ):
            for _ in range(3):
                rig.world.now += 21_600_000
                self.assertEqual(rig.open().recover()["sessions"], 1)
            apply.assert_not_called()
            arm.assert_not_called()

    def test_lost_apply_reply_reconciles_without_reapply_or_cancellation(self):
        rig = Rig()
        rig.world.crash_operation = "apply"
        with self.assertRaises(Crash):
            rig.run()
        rig.world.now = BASE + 20_000_000
        with (
            patch.object(rig.gate, "apply_once") as apply,
            patch.object(rig.backstop, "arm") as arm,
        ):
            recovered = rig.open()
            recovered.recover()
            self.assertIs(recovered._get("applied", 0), True)
            apply.assert_not_called()
            arm.assert_not_called()
        self.assertFalse(rig.capacity.cancelled)

    def test_unknown_apply_oserror_holds_capacity_until_reconciliation(self):
        for executed in (False, True):
            with self.subTest(executed=executed):
                rig = Rig()
                controller = rig.open()
                controller.mark()
                controller.acquire()
                apply = rig.gate.apply_once

                def unknown(binding, *, executed=executed, apply=apply):
                    if executed:
                        apply(binding)
                    raise OSError("unknown Apply outcome")

                with patch.object(rig.gate, "apply_once", side_effect=unknown):
                    with self.assertRaisesRegex(OSError, "unknown Apply outcome"):
                        controller.consume()
                self.assertEqual(controller.status()["sessions"], 1)
                self.assertIsNone(controller._get("applied", 0))
                self.assertIsNone(controller._get("rejected", 0))
                self.assertEqual(controller.status()["ledger"], [])
                self.assertFalse(rig.capacity.cancelled)
                rig.world.now = BASE + 1_800_001
                with patch.object(rig.gate, "apply_once") as retry:
                    reopened = rig.open()
                    state = reopened.recover()
                retry.assert_not_called()
                if executed:
                    self.assertIs(reopened._get("applied", 0), True)
                    self.assertFalse(rig.capacity.cancelled)
                else:
                    self.assertEqual(len(state["ledger"]), 1)
                    self.assertIsNone(reopened._get("applied", 0))

    def test_application_receipt_is_bound_before_reconciling_applied(self):
        rig = Rig()
        rig.world.crash_operation = "apply"
        with self.assertRaises(Crash):
            rig.run()
        rig.gate.application = lambda session: {"session_id": session, "plan_hash": "wrong"}
        with self.assertRaisesRegex(IntegrityError, "application_receipt"):
            rig.open().recover()

    def test_expired_recovery_does_not_arm_backstop(self):
        rig = self.lost_consume(later_C=True)
        rig.world.now = BASE + 18_000_001
        with patch.object(rig.backstop, "arm", wraps=rig.backstop.arm) as arm:
            rig.open().recover()
            arm.assert_not_called()
        self.assertFalse(rig.gate.applies)

    def test_admission_samples_clock_after_backstop_io(self):
        for phase in ("consume", "apply"):
            rig = Rig()
            rig.plans = [
                replace(p, C="2026-10-19T00:00:01Z", D_session="2026-10-19T05:00:01Z")
                for p in rig.plans
            ]
            controller = rig.open()
            controller.mark()
            controller.acquire()
            rig.world.now = BASE + 1000
            original = rig.backstop.arm

            def delayed(session, deadline, *, original=original, rig=rig, phase=phase):
                result = original(session, deadline)
                if (phase == "apply") == bool(rig.gate.consumptions):
                    rig.world.now += 1
                return result

            rig.backstop.arm = delayed
            with self.subTest(phase=phase):
                state = controller.consume()
                self.assertEqual(state["sessions"], 0 if phase == "consume" else 1)
                self.assertFalse(rig.gate.applies)

    def test_post_consume_stop_recovers_alone_after_every_cleanup_row(self):
        initial = self.lost_consume()
        initial.world.now = BASE + 3_600_001
        baseline = copy.deepcopy(initial)
        expected = baseline.open().recover()
        for cut in range(len(initial.journal.rows) + 1, len(baseline.journal.rows) + 1):
            rig = copy.deepcopy(initial)
            rig.journal.cut = cut
            with self.subTest(cut=cut):
                with self.assertRaises(Crash):
                    rig.open().recover()
                self.assertEqual(rig.open().recover(), expected)
                self.assertFalse(rig.gate.applies)
                with (
                    patch.object(rig.gate, "apply_once") as apply,
                    patch.object(rig.backstop, "arm") as arm,
                    patch.object(rig.capacity, "cancel") as cancel,
                ):
                    rig.open().recover()
                    apply.assert_not_called()
                    arm.assert_not_called()
                    cancel.assert_not_called()

    def test_consumed_stop_remains_final_when_backstop_recovers(self):
        rig = self.lost_consume()
        append = rig.journal.append_fsync

        def cut_after_stop(row):
            ack = append(row)
            if row["event"] == "stopped":
                raise Crash("durable stop before cleanup")
            return ack

        rig.journal.append_fsync = cut_after_stop
        with patch.object(rig.backstop, "arm", return_value=False):
            with self.assertRaises(Crash):
                rig.open().recover()
        rig.journal.append_fsync = append
        with patch.object(rig.backstop, "arm", wraps=rig.backstop.arm) as arm:
            state = rig.open().recover()
            arm.assert_not_called()
        self.assertEqual(state["sessions"], 1)
        self.assertIs(state["stopped"]["measurement_started"], False)
        self.assertFalse(rig.gate.applies)
        self.assertEqual(len(state["ledger"]), 1)
        self.assertEqual(rig.capacity.group, [])

    def test_recover_alone_from_every_journal_cut_resumes_only_pending_operation(self):
        for outcomes, consume in (
            (["refused", "ok"], True),
            (["partial", "refused"], True),
            (["ok", "ok"], False),
        ):
            baseline = Rig()
            baseline.capacity.outcomes = outcomes.copy()
            baseline.run(consume=consume)
            for cut in range(1, len(baseline.journal.rows) + 1):
                rig = Rig()
                rig.capacity.outcomes = outcomes.copy()
                rig.journal.cut = cut
                with self.assertRaises(Crash):
                    rig.run(consume=consume)
                controller = rig.open()
                index = controller._index()
                prefix = copy.deepcopy(rig.journal.rows)
                stopped = controller._get("stopped")
                pending_acquire = (
                    index < len(rig.plans) and controller._get("acquire_intent", index) is not None
                )
                pending_consume = (
                    index < len(rig.plans) and controller._get("consume_intent", index) is not None
                )
                pending_marker = any(
                    controller._get("marker_intent", i) for i in range(len(rig.plans))
                ) and not all(controller._get("marker", i) for i in range(len(rig.plans)))
                with self.subTest(outcomes=outcomes, consume=consume, cut=cut):
                    result = controller.recover()
                    if pending_consume:
                        self.assertEqual(result["sessions"], 1)
                        self.assertIs(controller._get("applied", index), True)
                    elif stopped is not None and pending_acquire:
                        self.assertIs(controller._get("advanced", index), True)
                    elif pending_acquire:
                        self.assertTrue(
                            controller._get("verified", index) is True
                            or controller._get("advanced", index) is True
                        )
                    elif pending_marker:
                        self.assertTrue(
                            all(controller._get("marker", i) for i in range(len(rig.plans)))
                        )
                    else:
                        self.assertEqual(rig.journal.rows, prefix)
                    self.invariant(rig)

    def test_recover_fresh_journal_does_not_start_marking(self):
        rig = Rig()
        controller = rig.open()
        prefix = copy.deepcopy(rig.journal.rows)
        self.assertEqual(controller.recover(), controller.status())
        self.assertEqual(rig.journal.rows, prefix)
        self.assertFalse(rig.gate.markers)

    def test_rejected_acquire_retries_cancel_without_reverification(self):
        rig = Rig()
        controller = rig.open()
        controller.mark()
        add = rig.capacity.add
        rig.capacity.add = lambda group, rid: (_ for _ in ()).throw(OSError("add_failed"))
        cancel = rig.capacity.cancel

        def unchanged(token, group):
            old = copy.deepcopy(rig.capacity.results.get(token))
            cancel(token, group)
            rig.capacity.results[token] = old

        rig.capacity.cancel = unchanged
        with self.assertRaisesRegex(IntegrityError, "cancelled_lookup"):
            controller.acquire()
        rig.capacity.add = add
        with (
            patch.object(
                controller,
                "_verify",
                side_effect=AssertionError("rejected index must only retry cancel"),
            ),
            patch.object(rig.backstop, "arm", side_effect=AssertionError("no acquisition retry")),
        ):
            with self.assertRaisesRegex(IntegrityError, "cancelled_lookup"):
                controller.acquire()
        self.assertEqual(controller._index(), 0)
        self.assertEqual(sum(name == "odcr" for name, _ in rig.world.trace), 1)
        rig.capacity.cancel = cancel
        rig.capacity.cancelled.clear()
        state = controller.acquire()
        self.assertEqual(state["refused"], [0])
        self.assertEqual(controller._index(), 1)

    def test_no_origin_stop_recovers_alone_through_advance(self):
        initial = Rig()
        controller = initial.open()
        controller.mark()
        initial.journal.cut = len(initial.journal.rows) + 1
        with self.assertRaises(Crash):
            controller.acquire()
        baseline = copy.deepcopy(initial)
        expected = baseline.open().refuse("before_origin")
        for cut in range(len(initial.journal.rows) + 1, len(baseline.journal.rows) + 1):
            rig = copy.deepcopy(initial)
            rig.journal.cut = cut
            with self.assertRaises(Crash):
                rig.open().refuse("before_origin")
            self.assertEqual(rig.open().recover(), expected)
            self.assertEqual(rig.open()._index(), 1)
            self.assertIsNone(expected["billing_origin"])
            self.assertFalse(rig.capacity.results)

    def test_write_and_origin_validate_candidate_before_append(self):
        rig = Rig()
        controller = rig.open()
        before = copy.deepcopy(rig.journal.rows)
        facts = copy.deepcopy(controller.facts)
        with self.assertRaisesRegex(IntegrityError, "journal_predecessor"):
            controller._write("acquired", {}, 0)
        self.assertEqual(rig.journal.rows, before)
        self.assertEqual(controller.facts, facts)
        controller._write("billing_origin", None)
        before = copy.deepcopy(rig.journal.rows)
        facts = copy.deepcopy(controller.facts)
        with self.assertRaisesRegex(IntegrityError, "journal_duplicate"):
            controller._origin()
        self.assertEqual(rig.journal.rows, before)
        self.assertEqual(controller.facts, facts)

    def test_public_calls_return_observable_status(self):
        rig = Rig()
        controller = rig.open()
        for name in ("mark", "acquire", "consume", "recover", "status"):
            self.assertEqual(self.call(controller, name), controller.status())
        rig = Rig()
        controller = rig.open()
        self.assertEqual(controller.refuse("stop"), controller.status())

    def test_consumption_receipt_retains_admission_time(self):
        rig = Rig()
        self.assertEqual(rig.run().status()["consumed"]["consumed_ms"], BASE)

    def test_journal_cannot_place_first_bound_after_another_event(self):
        rig = Rig()
        bound = copy.deepcopy(rig.open().rows[0])
        bound["seq"] = 2
        rig.journal.rows = [
            {"seq": 1, "event": "marker_intent", "index": 0, "data": {}},
            bound,
        ]
        with self.assertRaises(IntegrityError):
            rig.open()


if __name__ == "__main__":
    unittest.main()
