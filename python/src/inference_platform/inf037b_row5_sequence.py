"""Row 5 scheduling over the existing capture, client, diagnostic and RBAC ports.

The deployment supplies request/diagnostic arguments and source-bound checker
inputs. ``capture`` returns the existing preparation capture shape, with only
new raw rows. No state/report writer or capture serializer lives here.
``recovery`` drains continuous post-restore observations (including every 403),
not just successful samples; incomplete capture is a terminal refusal.
"""

import copy
import time
import uuid

from .inf037b_archive import IntegrityError, encode, sha
from .inf037b_row5 import ROW5_KNOWN_CONTROLS, RecoveryAgreement, expired_window
from .inf037b_row5_capture import (
    captured_refusal_control,
    diagnostic_snapshot_control,
    known_gateway_control,
)

STAGES = ("known0", "known1", "known2", "cached_stop_known1", "cached_restore_known2")
GATEWAYS = ("gateway0", "gateway1")
OUTAGE_SEQUENCE_TIMEOUT_S = 30


class KnownStage:
    def __init__(
        self,
        *,
        redis,
        clients,
        diagnostic,
        request_arguments,
        diagnostic_arguments,
        proof_inputs,
        configuration_sha256,
        clock=time.monotonic_ns,
        sleep=time.sleep,
        defer_proofs=False,
    ):
        self.redis, self.clients, self.diagnostic = redis, clients, diagnostic
        self.request_arguments, self.diagnostic_arguments = request_arguments, diagnostic_arguments
        self.proof_inputs, self.configuration_sha256 = proof_inputs, configuration_sha256
        self.clock, self.sleep = clock, sleep
        self.defer_proofs = defer_proofs
        self.next_stage, self.failed = 0, False
        self.controls, self.requests = {}, []

    def deadline(self, stop_ns, reason="fitness:row5_stage_deadline"):
        if self.clock() >= stop_ns:
            raise IntegrityError(reason)

    def pause(self, stop_ns):
        self.deadline(stop_ns)
        self.sleep(min(0.05, (stop_ns - self.clock()) / 1e9))

    def snapshot(self, stop_ns, name=None):
        self.deadline(stop_ns)
        row = self.redis.snapshot(**({"snapshot_id": name} if name else {}))
        self.deadline(stop_ns)
        if not isinstance(row, dict) or row.get("error") is not None:
            raise IntegrityError("fitness:row5_snapshot_capture")
        return row

    @staticmethod
    def matches(row, n, *, unknown=False, expired=False):
        p = row.get("payload", {})
        now, reports, state = p.get("redis_time_ms"), p.get("reports"), p.get("state", {})
        # Redis stores n, not B. The frozen R=4/W=1 configuration derives B=5n;
        # the existing admit/diagnostic checkers verify the actual effective B.
        return (
            type(now) is int
            and type(state.get("n")) is int
            and state["n"] == n
            and isinstance(reports, dict)
            and set(reports) == set(GATEWAYS)
            and all(
                isinstance(r, dict)
                and type(r.get("n")) is int
                and r["n"] == n
                and r.get("unknown") is unknown
                and type(r.get("expires_ms")) is int
                and (now >= r["expires_ms"]) is expired
                for r in reports.values()
            )
        )

    def wait(self, stop_ns, n, *, unknown=False):
        while True:
            row = self.snapshot(stop_ns)
            if self.matches(row, n, unknown=unknown):
                return row
            self.pause(stop_ns)

    def __call__(self, name, stop_ns):
        self.stop_domain(stop_ns)
        if self.failed or self.next_stage >= len(STAGES) or name != STAGES[self.next_stage]:
            raise IntegrityError("fitness:row5_stage_order")
        # An interrupted control is never replayed with fresh requests.
        self.failed = True
        n = ROW5_KNOWN_CONTROLS[name][0]
        self.wait(stop_ns, n)
        snapshot = self.snapshot(stop_ns, name)
        if not self.matches(snapshot, n):
            raise IntegrityError("fitness:row5_snapshot_state")
        requests = self.control(name, stop_ns, snapshot)
        self.next_stage += 1
        self.failed = False
        return requests

    def control(self, name, stop_ns, snapshot):
        requests = []
        for gateway in GATEWAYS:
            self.deadline(stop_ns)
            offer = {
                "request_id": "row5-" + uuid.uuid4().hex,
                "gateway_uid": gateway,
                "snapshot_id": name,
                "offer_index": len(self.requests),
                "prefix_id": "row5",
                "phase": "pre",
                "config_sha256": self.configuration_sha256,
                "scheduled_ms": self.clock() // 1_000_000,
            }
            self.clients[gateway].request(
                **self.request_arguments(gateway), offer=offer, deadline_ns=stop_ns
            )
            self.deadline(stop_ns)
            requests.append(offer)
            self.requests.append(offer)
        receipt = self.diagnostic.run_from_captures(
            **self.diagnostic_arguments(),
            reservation_id="rsv_d1a6" + uuid.uuid4().hex[:28],
            deadline_ns=stop_ns,
        )
        after = self.snapshot(stop_ns)
        if (
            after["payload"].get("active_reservations") != []
            or after["payload"].get("occupied") != 0
        ):
            raise IntegrityError("fitness:row5_release")
        self.controls[name] = (snapshot, after, requests, receipt)
        if not self.defer_proofs:
            self.proofs(name)
        self.deadline(stop_ns)
        return copy.deepcopy(requests)

    def stop_domain(self, stop_ns):
        if type(stop_ns) is not int or stop_ns > self.clock() + 1_800_000_000_000:
            raise IntegrityError("fitness:row5_stop_domain")

    def proofs(self, name):
        """Rejoin retained captures, also after close when prefix hashes are final."""
        snapshot, after, requests, receipt = self.controls[name]
        gateways = {}
        for offer in requests:
            gateway = offer["gateway_uid"]
            args = self.proof_inputs(name, gateway, offer, snapshot, after, receipt)
            if name in ROW5_KNOWN_CONTROLS:
                n = ROW5_KNOWN_CONTROLS[name][0]
                gateway_row = args.pop("gateway", gateway)
                result = known_gateway_control(
                    **args,
                    snapshot=snapshot,
                    after=after,
                    gateway=gateway_row,
                    expected_n=n,
                    expected_snapshot_id=name,
                )
                gateways[gateway] = {
                    **result,
                    "request_id": offer["request_id"],
                    "gateway_request_id": args["gateway_request_id"],
                    "terminal": "released" if n else "system_capacity",
                    "released": n != 0,
                    "capture_sha256": sha(args["raw_gateway_prefix"]),
                }
            else:
                result = captured_refusal_control(**args, redis_before=snapshot, redis_after=after)
                proof = {key: result[key] for key in ("gateway", "client", "redis")}
                gateways[gateway] = {
                    "request_id": offer["request_id"],
                    **proof,
                    "evidence_sha256": sha(encode(proof)),
                }
        args = self.proof_inputs(name, None, None, snapshot, after, receipt)
        diagnostic = diagnostic_snapshot_control(
            **args, snapshot=snapshot, after=after, receipt=receipt, control_name=name
        )
        return gateways, {
            **diagnostic,
            "receipt_sha256": self.diagnostic.receipt_hashes[receipt["reservation_id"]],
            "configuration_sha256": sha(encode(self.diagnostic_arguments()["config"])),
        }


class OutageSequence:
    def __init__(self, *, stage, role, recovery, capture, step_timing=None):
        self.stage, self.role, self.recovery, self.capture = stage, role, recovery, capture
        self.step_timing = step_timing
        self.restore_outcome = None
        self.started = False
        self.retain_inputs = None

    def _step_start(self):
        return self.stage.clock()

    def _step_done(self, name, started_ns):
        if self.step_timing is not None:
            self.step_timing(name, max(0, (self.stage.clock() - started_ns) // 1_000_000))

    def restore(self, stop_ns):
        self.restore_outcome = {"start_ns": self.stage.clock(), "deadline_ns": stop_ns}
        source_error = None
        try:
            # The live reader takes every gateway cursor before the actuation.
            if hasattr(self.recovery, "start"):
                try:
                    self.recovery.start(stop_ns)
                except Exception as exc:
                    source_error = exc
                    self.restore_outcome["capture_error_class"] = type(exc).__name__
            self.role.restore(envelope_deadline_ns=stop_ns)
        except BaseException as exc:
            self.restore_outcome.update(success=False, error_class=type(exc).__name__)
            raise
        else:
            self.restore_outcome["success"] = True
        finally:
            self.restore_outcome["end_ns"] = self.stage.clock()
        if source_error is not None:
            raise source_error

    def __call__(self, stop_ns, prepared):
        s = self.stage
        s.stop_domain(stop_ns)
        if self.started or s.failed or s.next_stage != len(STAGES):
            raise IntegrityError("fitness:row5_stage_order")
        self.started = True
        start = s.clock()
        deadline = min(stop_ns, start + OUTAGE_SEQUENCE_TIMEOUT_S * 1_000_000_000)
        restored = False
        active_step = None

        def begin_step(name):
            nonlocal active_step
            active_step = (name, self._step_start())

        def finish_step():
            nonlocal active_step
            if active_step is not None:
                name, started_ns = active_step
                active_step = None
                self._step_done(name, started_ns)

        try:
            begin_step("rbac-revoke-and-unknown-window")
            self.role.revoke(envelope_deadline_ns=deadline)
            s.wait(deadline, 2, unknown=True)
            unknown = s.snapshot(deadline, "unknown")
            if not s.matches(unknown, 2, unknown=True):
                raise IntegrityError("fitness:row5_snapshot_state")
            requests = s.control("unknown", deadline, unknown)
            finish_step()

            begin_step("expired-window-controls")
            stores = {g: unknown["payload"]["reports"][g]["stored_ms"] for g in GATEWAYS}
            # Measured capture duration, rounded outwards, never a guessed bound.
            latency = (
                unknown["capture_end_mono_ns"] - unknown["capture_start_mono_ns"] + 999_999
            ) // 1_000_000
            first, end = expired_window(stores.values(), 8000, 2000, latency)
            while True:
                current = s.snapshot(deadline)
                at = current["payload"]["redis_time_ms"]
                if at >= end:
                    raise IntegrityError("fitness:expired_snapshot_window")
                if first < at and at + latency < end:
                    break
                s.pause(deadline)
            expired = s.snapshot(deadline, "expired")
            actual_latency = (
                expired["capture_end_mono_ns"] - expired["capture_start_mono_ns"] + 999_999
            ) // 1_000_000
            latency = max(latency, actual_latency)
            first, end = expired_window(stores.values(), 8000, 2000, latency)
            if not first < expired["payload"]["redis_time_ms"] < end:
                raise IntegrityError("fitness:expired_snapshot_window")
            if not s.matches(expired, 2, unknown=True, expired=True):
                raise IntegrityError("fitness:row5_snapshot_state")
            requests.extend(s.control("expired", deadline, expired))
            finish_step()

            begin_step("rbac-restore")
            self.restore(deadline)
            restored = True
            finish_step()

            begin_step("recovery-and-post-outage-controls")
            agreement = RecoveryAgreement(deadline // 1_000_000)
            observations, batches = [], []

            def observe(batch, current):
                if batch.get("source_complete") is not True:
                    raise IntegrityError("fitness:recovery_source_incomplete")
                batches.append(batch)
                complete = (
                    agreement.start_ms is not None
                    and agreement.last_ms - agreement.start_ms >= agreement.duration_ms
                )
                for observation in batch["observations"]:
                    if (
                        type(observation.get("time_ms")) is not int
                        or type(observation.get("known")) is not bool
                        or (
                            "source_event_ns" in observation
                            and (
                                observation.get("time_clock") != "collector_monotonic"
                                or type(observation.get("read_mono_ns")) is not int
                                or observation["time_ms"]
                                != observation["read_mono_ns"] // 1_000_000
                            )
                        )
                        or not self.restore_outcome["start_ns"] // 1_000_000
                        <= observation["time_ms"]
                        <= s.clock() // 1_000_000
                    ):
                        raise IntegrityError("fitness:recovery_source_incomplete")
                    known = (
                        observation["known"] is True
                        and observation["n"] == 2
                        and observation["effective_b"] == 10
                        and s.matches(current, 2)
                    )
                    sample = {
                        **observation,
                        "known": known,
                        "reason": None if known else observation["reason"] or "unknown",
                    }
                    observations.append(sample)
                    complete = agreement.observe(
                        sample["time_ms"], known=known, reason=sample["reason"]
                    )
                return complete

            complete = False
            while not complete:
                s.deadline(deadline)
                batch = self.recovery(deadline)
                complete = observe(batch, s.snapshot(deadline))
                if not complete:
                    s.pause(deadline)
            post = s.snapshot(deadline, "post_outage_known2")
            if not s.matches(post, 2):
                raise IntegrityError("fitness:row5_snapshot_state")
            requests.extend(s.control("post_outage_known2", deadline, post))
            finish_step()

            begin_step("capture-join-and-final-agreement")
            final = s.snapshot(deadline, "post_outage_agreement")
            if not s.matches(final, 2) or final["payload"].get("active_reservations") != []:
                raise IntegrityError("fitness:recovery_agreement")
            # Drain through the final snapshot too: a late 403 during the
            # post-recovery requests must not hide behind the earlier agreement.
            if hasattr(self.recovery, "finish"):
                self.recovery.finish(deadline)
            if not observe(self.recovery(deadline), final):
                raise IntegrityError("fitness:recovery_agreement")
            result = self.capture(prepared)
            evidence = result["row5_evidence"]
            evidence.update(
                schema="inf037b-row5-evidence-v1",
                configuration_sha256=s.configuration_sha256,
                known={},
                refusals={},
                diagnostics={},
                last_known_stores_ms=stores,
                expired_snapshot_latency_ms=latency,
                expired_window_ms=[first, end],
                rbac={
                    "reviewed_sha256": sha(self.role.original_projection),
                    "actions": copy.deepcopy(self.role.actuations),
                    "reviews": copy.deepcopy(self.role.reviews),
                    "envelope_start_ns": start,
                    "envelope_deadline_ns": deadline,
                },
                recovery={
                    "observations": observations,
                    "source_complete": True,
                    "evidence_sha256": sha(encode(batches)),
                },
            )
            evidence["restore_outcome"] = copy.deepcopy(self.restore_outcome)
            result["row5_recovery_batches"] = copy.deepcopy(batches)
            result["row5_control_requests"] = copy.deepcopy(requests)
            if self.retain_inputs is not None:
                self.retain_inputs(result, requests)
            for name in s.controls:
                gateways, diagnostic = s.proofs(name)
                evidence["known" if name in ROW5_KNOWN_CONTROLS else "refusals"][name] = gateways
                evidence["diagnostics"][name] = diagnostic
            s.deadline(deadline)
            finish_step()
            return result
        except BaseException:
            finish_step()
            if self.role.revoke_replaced and not restored and not self.role.restore_replaced:
                try:
                    self.restore(deadline)
                except BaseException:
                    pass  # Outcome retained; preserve the original refusal.
            raise
