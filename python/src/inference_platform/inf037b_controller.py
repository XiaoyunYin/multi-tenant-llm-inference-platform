"""Offline v4 marker/billing/consume state machine, with injected durable ports.

Slice 4a supplies durable filesystem/transport ports; no marker authoring CLI,
configured AWS client or paid entry point exists.
One fenced writer owns a journal. Ports must durably deduplicate operation keys;
in particular recovery queries an ambiguous acquisition/consume before retrying.
The journal's append_fsync acknowledges persistence, not a queued write.
"""

import copy
import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime

from .inf037b_archive import IntegrityError, encode
from .inf037b_resolver import BOUNDS_MS, SessionDeadline, exact, integer, remaining_work, require
from .m5_infra_safety import Binding


class ApplyNotExecuted(OSError):
    """The gate durably fenced this Apply; no delayed request can execute it."""


def refusal(reason):
    raise IntegrityError("v4:controller:" + reason)


def utc_ms(literal):
    require(
        type(literal) is str
        and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", literal) is not None,
        "controller:utc_literal",
    )
    try:
        value = datetime.strptime(literal, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise IntegrityError("v4:controller:utc_calendar") from exc
    result = int(value.timestamp()) * 1000
    require(result >= 0, "controller:utc_nonnegative")
    return result


@dataclass(frozen=True)
class ReviewedPlan:
    """Already verified saved-plan binding; parsing raw Terraform is a later port."""

    saved_plan: bytes
    plan_hash: str
    session_id: str
    capacity: Binding
    C: str
    D_session: str

    def descriptor(self):
        require(type(self.saved_plan) is bytes, "controller:saved_plan_bytes")
        exact(hashlib.sha256(self.saved_plan).hexdigest(), self.plan_hash, "controller:plan_hash")
        require(type(self.session_id) is str and bool(self.session_id), "controller:session_id")
        require(type(self.capacity) is Binding, "controller:capacity_binding")
        SessionDeadline(utc_ms(self.C), utc_ms(self.D_session), 0)
        return {
            "plan_hash": self.plan_hash,
            "session_id": self.session_id,
            "capacity": vars(self.capacity).copy(),
            "C": self.C,
            "D_session": self.D_session,
        }


class Controller:
    """mark -> acquire (one AZ per call) -> consume/Apply; recover every prefix.

    Journal: read(), append_fsync(row)->True; append_origin_fsync(row) atomically
    stamps the durable-write time and returns {fsync: True, row: persisted_row}.
    Gate: marker(descriptor),
    consumption(session_id), consume(descriptor, admission_check),
    application(session_id), apply_once(descriptor).
    consume runs admission_check at its atomic commit boundary and records its time.
    Capacity: lookup(token), acquire(token, binding), add(group, reservation_id),
    members(group), cancel(token, group), cancellation(token), ledger(token, t0).
    Backstop: arm(session_id, deadline_ms)->True; confirmed(session_id, deadline_ms).
    Slice 4a implements these interfaces with durable injected ports; this
    state-machine suite also retains the accepted offline doubles.
    """

    def __init__(self, plans, *, journal, gate, capacity, backstop, clock):
        require(type(plans) in (list, tuple) and bool(plans), "controller:ordered_plans")
        require(all(type(p) is ReviewedPlan for p in plans), "controller:plan_types")
        self.plans = tuple(plans)
        self.bindings = [p.descriptor() for p in plans]
        first = self.bindings[0]
        for binding in self.bindings:
            exact(
                [binding[k] for k in ("session_id", "C", "D_session")]
                + [binding["capacity"]["group_arn"]],
                [first[k] for k in ("session_id", "C", "D_session")]
                + [first["capacity"]["group_arn"]],
                "controller:shared_literals",
            )
        require(len({p.plan_hash for p in plans}) == len(plans), "controller:distinct_plan_hashes")
        self.journal, self.gate, self.capacity = journal, gate, capacity
        self.backstop, self.clock = backstop, clock
        self.session_id = first["session_id"]
        self.group = first["capacity"]["group_arn"]
        self.rows = copy.deepcopy(journal.read())
        require(type(self.rows) is list, "controller:journal_rows")
        self.facts = {}
        for row in self.rows:
            self._replay(row)
        if self.rows:
            exact(self._get("bound"), self.bindings, "controller:reopened_binding")
        else:
            self._write("bound", self.bindings)

    def _replay(self, row):
        require(
            type(row) is dict and set(row) == {"seq", "event", "index", "data"},
            "controller:journal_shape",
        )
        require(
            integer(row["seq"]) and row["seq"] == len(self.facts) + 1,
            "controller:journal_sequence",
        )
        require(
            type(row["event"]) is str
            and row["event"]
            in {
                "bound",
                "marker_intent",
                "marker",
                "acquire_intent",
                "billing_origin",
                "acquired",
                "verified",
                "rejected",
                "cancel_intent",
                "cancelled",
                "ledger",
                "advanced",
                "consume_intent",
                "consumed",
                "applied",
                "stopped",
            },
            "controller:journal_event",
        )
        require(
            integer(row["index"]) and -1 <= row["index"] < len(self.plans),
            "controller:journal_index",
        )
        key = (row["event"], row["index"])
        require(key not in self.facts, "controller:journal_duplicate")
        event, index = key
        global_event = event in {"bound", "billing_origin", "stopped"}
        require((index == -1) == global_event, "controller:journal_event_index")
        if event == "bound":
            require(not self.facts, "controller:bound_first")
        else:
            require(self._get("bound") is not None, "controller:journal_bound")
        prerequisites = {
            "marker": "marker_intent",
            "acquired": "acquire_intent",
            "verified": "acquired",
            "rejected": "acquire_intent",
            "cancel_intent": "rejected",
            "cancelled": "cancel_intent",
            "ledger": "cancelled",
            "advanced": "cancelled",
            "consume_intent": "verified",
            "consumed": "consume_intent",
            "applied": "consumed",
        }
        if event in prerequisites:
            require(
                self._get(prerequisites[event], index) is not None,
                "controller:journal_predecessor",
            )
        if event == "acquire_intent":
            require(
                all(self._get("marker", i) is not None for i in range(len(self.plans)))
                and all(self._get("advanced", i) is not None for i in range(index)),
                "controller:journal_acquire_order",
            )
        if event in {"verified", "consume_intent", "consumed"}:
            require(self._get("rejected", index) is None, "controller:journal_not_rejected")
        if event in {"acquired", "ledger"}:
            require(self._get("billing_origin") is not None, "controller:journal_origin")
        if event == "advanced" and self._get("billing_origin") is not None:
            require(self._get("ledger", index) is not None, "controller:journal_ledger")
        self.facts[key] = copy.deepcopy(row["data"])

    def _get(self, event, index=-1):
        return self.facts.get((event, index))

    def _validate_candidate(self, row):
        replay = copy.copy(self)
        replay.facts = copy.deepcopy(self.facts)
        replay._replay(copy.deepcopy(row))

    def _write(self, event, data, index=-1):
        if (event, index) in self.facts:
            exact(self._get(event, index), data, "controller:immutable_row")
            return
        row = {"seq": len(self.facts) + 1, "event": event, "index": index, "data": data}
        self._validate_candidate(row)
        ack = self.journal.append_fsync(copy.deepcopy(row))
        require(ack is True, "controller:fsync_ack")
        exact(self.journal.read(), self.rows + [row], "controller:journal_readback")
        self._replay(row)
        self.rows.append(copy.deepcopy(row))

    def _now(self):
        now = self.clock()
        require(integer(now) and now >= 0, "controller:clock")
        return now

    def _deadline(self):
        origin = self._get("billing_origin")
        require(type(origin) is dict, "controller:billing_origin_required")
        exact(origin["session_id"], self.session_id, "controller:origin_session")
        return SessionDeadline(
            utc_ms(self.plans[0].C), utc_ms(self.plans[0].D_session), origin["t0_ms"]
        )

    def _arm(self):
        deadline = self._deadline()
        armed = self.backstop.arm(self.session_id, deadline.effective_ms)
        require(armed is True, "controller:backstop_arm")
        require(
            self.backstop.confirmed(self.session_id, deadline.effective_ms) is True,
            "controller:backstop_confirmation",
        )

    def _origin(self):
        if self._get("billing_origin") is None:
            row = {
                "seq": len(self.facts) + 1,
                "event": "billing_origin",
                "index": -1,
                "data": {"session_id": self.session_id},
            }
            self._validate_candidate(row)
            ack = self.journal.append_origin_fsync(copy.deepcopy(row))
            require(type(ack) is dict and ack.get("fsync") is True, "controller:origin_fsync_ack")
            persisted = ack["row"]
            exact(
                {k: persisted.get(k) for k in ("seq", "event", "index")},
                {k: row[k] for k in ("seq", "event", "index")},
                "controller:origin_envelope",
            )
            exact(persisted["data"].get("session_id"), self.session_id, "controller:origin_key")
            require(
                integer(persisted["data"].get("t0_ms")) and persisted["data"]["t0_ms"] >= 0,
                "controller:origin_time",
            )
            exact(self.journal.read(), self.rows + [persisted], "controller:origin_readback")
            self._replay(persisted)
            self.rows.append(copy.deepcopy(persisted))

    def _index(self):
        return next(
            (i for i in range(len(self.plans)) if self._get("advanced", i) is None),
            len(self.plans),
        )

    def _open(self):
        if self._get("stopped") is not None:
            refusal("stopped")
        if self.gate.consumption(self.session_id) is not None:
            refusal("already_consumed")

    def mark(self):
        self._open()
        for index, binding in enumerate(self.bindings):
            self._write("marker_intent", binding, index)
            marker = self.gate.marker(copy.deepcopy(binding))
            require(type(marker) is dict, "controller:marker_shape")
            exact(marker.get("binding"), binding, "controller:marker_binding")
            exact(marker.get("committed"), True, "controller:marker_committed")
            require(
                type(marker.get("review_commit")) is str
                and re.fullmatch(r"[0-9a-f]{40}", marker["review_commit"]) is not None,
                "controller:marker_review_commit",
            )
            self._write("marker", marker, index)
        return self.status()

    def _token(self, index):
        return hashlib.sha256(encode([self.session_id, self.plans[index].plan_hash])).hexdigest()

    def _verify(self, index, *, add=False):
        token = self._token(index)
        reservation = self.capacity.lookup(token)
        require(type(reservation) is dict, "controller:reservation_required")
        binding = self.bindings[index]["capacity"]
        expected = {k: binding[k] for k in ("zone", "instance_type", "platform", "tenancy")}
        expected.update(total=2, available=2, state="active", match_criteria="targeted")
        exact(
            {k: reservation.get(k) for k in expected},
            expected,
            "controller:reservation_attributes",
        )
        require(
            type(reservation.get("reservation_id")) is str and bool(reservation["reservation_id"]),
            "controller:reservation_id",
        )
        if add:
            self.capacity.add(self.group, reservation["reservation_id"])
        exact(
            self.capacity.members(self.group),
            [reservation["reservation_id"]],
            "controller:exclusive_membership",
        )

    def _reject(self, index, reason):
        self._write("rejected", {"reason": reason}, index)
        self._cancel(index)

    def _cancel(self, index):
        token = self._token(index)
        acquired = self._get("acquired", index)
        durable = acquired.get("reservation") if acquired is not None else None
        observed = self.capacity.lookup(token)
        expected = {
            reservation["reservation_id"]
            for reservation in (durable, observed)
            if type(reservation) is dict
            and type(reservation.get("reservation_id")) is str
            and reservation["reservation_id"]
        }
        existed = durable is not None or observed is not None
        if self._get("cancel_intent", index) is None:
            self._write(
                "cancel_intent",
                {
                    "expected_ids": sorted(expected),
                    "acquisition_existed": existed,
                },
                index,
            )
        intent = self._get("cancel_intent", index)
        expected.update(intent["expected_ids"])
        existed = existed or intent["acquisition_existed"]
        self.capacity.cancel(token, self.group)
        cancellation = self.capacity.cancellation(token)
        require(type(cancellation) is dict, "controller:cancellation_receipt")
        exact(cancellation.get("verified"), True, "controller:cancellation_verified")
        exact(cancellation.get("complete"), True, "controller:cancellation_complete")
        ids = cancellation.get("reservation_ids")
        require(
            type(ids) is list
            and all(type(rid) is str and bool(rid) for rid in ids)
            and len(ids) == len(set(ids)),
            "controller:cancellation_ids",
        )
        exact(
            cancellation.get("states"),
            dict.fromkeys(ids, "cancelled"),
            "controller:each_reservation_cancelled",
        )
        require(expected <= set(ids), "controller:acquired_ids_cancelled")
        after = self.capacity.lookup(token)
        require(
            after is None or (type(after) is dict and after.get("state") == "cancelled"),
            "controller:cancelled_lookup",
        )
        exact(self.capacity.members(self.group), [], "controller:cancelled_group_empty")
        self._write("cancelled", cancellation, index)
        if self._get("billing_origin") is None:
            exact(existed, False, "controller:no_unbilled_acquisition")
            self._write("advanced", True, index)
            return
        t0 = self._get("billing_origin")["t0_ms"]
        ledger = self.capacity.ledger(token, t0)
        require(type(ledger) is dict, "controller:ledger_receipt")
        exact(ledger.get("t0_ms"), t0, "controller:ledger_origin")
        exact(
            ledger.get("stop_ms"),
            cancellation.get("stop_ms"),
            "controller:ledger_cancellation_time",
        )
        require(
            integer(ledger.get("stop_ms")) and ledger["stop_ms"] >= ledger["t0_ms"],
            "controller:ledger_stop",
        )
        exact(
            ledger.get("billed_ms"),
            ledger["stop_ms"] - ledger["t0_ms"],
            "controller:ledger_duration",
        )
        require(
            integer(ledger.get("cost_micros")) and ledger["cost_micros"] >= 0,
            "controller:ledger_cost",
        )
        require(
            not existed or ledger["billed_ms"] == 0 or ledger["cost_micros"] > 0,
            "controller:partial_cost",
        )
        self._write("ledger", ledger, index)
        self._write("advanced", True, index)

    def acquire(self):
        self._open()
        require(
            all(self._get("marker", i) is not None for i in range(len(self.plans))),
            "controller:markers_required",
        )
        index = self._index()
        if index == len(self.plans):
            refusal("all_az_refused")
        if self._get("rejected", index) is not None:
            self._cancel(index)
            return self.status()
        if self._get("acquire_intent", index) is None:
            exact(self.capacity.members(self.group), [], "controller:initial_group_empty")
            self._write("acquire_intent", {"token": self._token(index)}, index)
        self._origin()
        try:
            self._arm()
            require(
                self._now() >= self._deadline().billing_origin_ms,
                "controller:acquire_before_origin",
            )
            self._deadline().check_consume(self._now())
            require(
                self._now() - self._deadline().billing_origin_ms < 1_800_000,
                "controller:readiness_cutoff",
            )
            token = self._token(index)
            result = self.capacity.lookup(token)
            if result is None and self._get("acquired", index) is None:
                result = self.capacity.acquire(token, self.plans[index].capacity)
            self._write("acquired", {"reservation": result}, index)
            self._verify(index, add=self._get("verified", index) is None)
            self._write("verified", True, index)
        except (IntegrityError, OSError) as exc:
            self._reject(index, str(exc))
        return self.status()

    def _admit(self, index):
        deadline = self._deadline()
        deadline.check_consume(self._now())
        self._arm()
        self._verify(index)
        now = self._now()
        deadline.check_consume(now)
        elapsed = now - deadline.billing_origin_ms
        require(elapsed >= 0, "controller:clock_before_origin")
        require(elapsed < 1_800_000, "controller:readiness_cutoff")
        unspent = (
            max(0, BOUNDS_MS["creation"] - elapsed)
            + BOUNDS_MS["preparation"]
            + BOUNDS_MS["resolution"]
        )
        remaining_work(
            now_upper_ms=now,
            deadline=deadline,
            allowances=BOUNDS_MS,
            attempts=3,
            resets=2,
            unspent_setup_ms=unspent,
            before_attempt1=True,
        )
        return now

    def _complete_consume(self, index):
        if self._get("applied", index) is True:
            return
        consumption = self.gate.consumption(self.session_id)
        if consumption is None:
            try:
                consumption = self.gate.consume(
                    copy.deepcopy(self.bindings[index]), lambda: self._admit(index)
                )
            except (IntegrityError, OSError) as exc:
                consumption = self.gate.consumption(self.session_id)
                if consumption is None:
                    self._reject(index, str(exc))
                    return
        exact(consumption["plan_hash"], self.plans[index].plan_hash, "controller:consumed_hash")
        exact(consumption["session_id"], self.session_id, "controller:consumed_session")
        self._write("consumed", consumption, index)
        application = self.gate.application(self.session_id)
        if application is not None:
            exact(
                application,
                {
                    "session_id": self.session_id,
                    "plan_hash": self.plans[index].plan_hash,
                },
                "controller:application_receipt",
            )
            self._write("applied", True, index)
            return
        admitted = False
        try:
            self._admit(index)
            admitted = True
            self.gate.apply_once(copy.deepcopy(self.bindings[index]))
        except (IntegrityError, OSError) as exc:
            if admitted and not isinstance(exc, ApplyNotExecuted):
                # An unknown Apply still holds capacity for reconciliation.
                raise
            self._write(
                "stopped",
                {
                    "reason": str(exc),
                    "session_consumed": True,
                    "measurement_started": False,
                    "applied": False,
                    "index": index,
                },
            )
            self._reject(index, str(exc))
            return
        self._write("applied", True, index)

    def consume(self):
        self._open()
        index = self._index()
        require(index < len(self.plans), "controller:consume_index")
        require(self._get("verified", index) is True, "controller:verified_required")
        require(self._get("rejected", index) is None, "controller:rejected_not_consumable")
        self._write("consume_intent", True, index)
        self._complete_consume(index)
        return self.status()

    def refuse(self, reason):
        self._open()
        require(type(reason) is str and bool(reason), "controller:refusal_reason")
        self._write("stopped", {"reason": reason})
        index = self._index()
        if index < len(self.plans) and self._get("acquire_intent", index) is not None:
            if self._get("rejected", index) is not None:
                self._cancel(index)
            else:
                self._reject(index, reason)
        return self.status()

    def recover(self):
        stopped = self._get("stopped")
        if stopped is not None and stopped.get("session_consumed") is True:
            index = stopped["index"]
            if self._get("advanced", index) is None:
                self._reject(index, stopped["reason"])
        else:
            index = self._index()
            if index < len(self.plans):
                if self._get("rejected", index) is not None:
                    self._cancel(index)
                elif (
                    self._get("stopped") is not None
                    and self.gate.consumption(self.session_id) is None
                ):
                    if self._get("acquire_intent", index) is not None:
                        self._reject(index, self._get("stopped")["reason"])
                elif self._get("consume_intent", index) is not None:
                    self._complete_consume(index)
                elif self._get("acquire_intent", index) is not None:
                    self.acquire()
                elif any(self._get("marker_intent", i) for i in range(len(self.plans))) and not all(
                    self._get("marker", i) is not None for i in range(len(self.plans))
                ):
                    self.mark()
        return self.status()

    def status(self):
        consumption = self.gate.consumption(self.session_id)
        return copy.deepcopy(
            {
                "sessions": int(consumption is not None),
                "consumed": consumption,
                "billing_origin": self._get("billing_origin"),
                "unused": [
                    p.plan_hash
                    for p in self.plans
                    if consumption is None or p.plan_hash != consumption["plan_hash"]
                ],
                "refused": [i for i in range(len(self.plans)) if self._get("advanced", i)],
                "ledger": [
                    self._get("ledger", i)
                    for i in range(len(self.plans))
                    if self._get("ledger", i) is not None
                ],
                "stopped": self._get("stopped"),
            }
        )
