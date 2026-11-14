"""Durable offline attempt accounting, not a cluster operator (:73-74, :89-100).

The journal is the archive's attempts.jsonl. Reopening replays durable transitions;
setup is a separate call, so its attempt-start has already been fsynced. One writer
owns a journal. Torn writes fail closed; they are preserved for archive diagnostics.
"""

from pathlib import Path

from .inf037b_archive import durable_write, encode, envelope, inspect_segment
from .inf037b_contract import (
    ATTEMPT_MS,
    CAMPAIGN_MS,
    MAX_ATTEMPTS,
    MAX_RESETS,
    RESET_MS,
    TARGET_ORDER,
    nonnegative,
)


class Refused(ValueError):
    pass


class AttemptController:
    def __init__(self, journal: Path):
        self.journal = journal
        if not journal.exists():
            durable_write(journal, b"")
        _, self.rows = inspect_segment(journal)
        self.events = [r["payload"] for r in self.rows]
        self._recover_interrupted_stops()

    def _recover_interrupted_stops(self) -> None:
        """Finish durable multi-row transitions that were interrupted by a crash."""
        while self.events:
            stop_at = self.events[-1]["now_ms"]

            current = self._open_attempt()
            reset = self._open_reset()
            if current and reset:
                setup = next(
                    (
                        event
                        for event in reversed(self._of("setup_complete"))
                        if event["attempt"] == current["attempt"] and event["preconditions"]
                    ),
                    None,
                )
                traffic = any(
                    event["attempt"] == current["attempt"] for event in self._of("traffic_start")
                )
                if setup and not traffic:
                    # Successful setup is durable, but traffic has not started. Close
                    # the reset only; recovery must never manufacture traffic_start.
                    self._write("reset_complete", setup["now_ms"], deadline_ms=reset["deadline_ms"])
                    continue

            reset_failures = self._of("reset_failed")
            if reset_failures and not self._stop_reason():
                failure = reset_failures[-1]
                reason = failure["reason"]
                current = self._open_attempt()
                if current:
                    self.end_attempt(
                        stop_at,
                        measurement_valid=False,
                        reasons=[reason],
                        operational_outcomes=["deletion_not_issued"],
                        replacement_usable_by_deadline=None,
                    )
                self.stop(stop_at, reason)
                continue

            current = self._open_attempt()
            if current:
                failed_setup = [
                    event
                    for event in self._of("setup_failed")
                    if event["attempt"] == current["attempt"]
                ]
                if failed_setup:
                    failure = failed_setup[-1]
                    self.end_attempt(
                        failure["now_ms"],
                        measurement_valid=False,
                        reasons=failure["reasons"],
                        operational_outcomes=["deletion_not_issued"],
                        replacement_usable_by_deadline=None,
                    )
                    continue

            reset = self._open_reset()
            ends = self._of("attempt_end")
            if reset and ends:
                end = ends[-1]
                traffic = [
                    event
                    for event in self._of("traffic_start")
                    if event["attempt"] == end["attempt"]
                ]
                reset_index = max(
                    i for i, event in enumerate(self.events) if event["event"] == "reset_start"
                )
                if not traffic and any(
                    event["event"] == "attempt_start" and event["attempt"] == end["attempt"]
                    for event in self.events[reset_index + 1 :]
                ):
                    self.fail_reset(end["now_ms"], "reset_setup_failure")
                    continue

            ends = self._of("attempt_end")
            if ends and not self._stop_reason():
                end = ends[-1]
                if end["replacement_usable_by_deadline"] is False:
                    self.stop(end["now_ms"], "previous_replacement_never_usable")
                    continue
            break

    def _write(self, event: str, now_ms: int, **fields) -> None:
        nonnegative(now_ms, "now_ms")
        if self.events and now_ms < self.events[-1]["now_ms"]:
            raise Refused("monotonic_clock_regressed")
        if (
            self.journal.with_suffix(".receipt.json").exists()
            or (self.journal.parent / "SHA256SUMS").exists()
        ):
            raise Refused("journal_finalized")
        payload = {"event": event, "now_ms": now_ms, **fields}
        row = envelope(payload, seq=len(self.rows), attempt=fields.get("attempt", "setup"))
        durable_write(self.journal, encode(row), "ab")
        self.rows.append(row)
        self.events.append(payload)

    def _of(self, event: str) -> list[dict]:
        return [e for e in self.events if e["event"] == event]

    def _stop_reason(self) -> str | None:
        stops = self._of("campaign_stop")
        return stops[-1]["reason"] if stops else None

    def _open_attempt(self) -> dict | None:
        starts, ends = self._of("attempt_start"), self._of("attempt_end")
        return starts[-1] if len(starts) > len(ends) else None

    def _open_reset(self) -> dict | None:
        starts = self._of("reset_start")
        ends = self._of("reset_complete") + self._of("reset_failed")
        return starts[-1] if len(starts) > len(ends) else None

    def stop(self, now_ms: int, reason: str) -> None:
        if not reason or self._open_attempt():
            raise Refused("end_attempt_before_stopping")
        if self._stop_reason():
            if self._stop_reason() != reason:
                raise Refused("campaign_stop_reason_is_durable")
            return
        self._write("campaign_stop", now_ms, reason=reason)
        for slot in self.report()["slots"]:
            if slot.get("state") == "not_attempted":
                self._write("not_attempted", now_ms, **slot)

    def begin_reset(self, now_ms: int, *, remaining_ms: int, export_cleanup_ms: int) -> None:
        nonnegative(remaining_ms, "remaining_ms")
        nonnegative(export_cleanup_ms, "export_cleanup_ms")
        if self._stop_reason() or self._open_attempt() or self._open_reset():
            raise Refused("campaign_stopped_or_transition_open")
        ends = self._of("attempt_end")
        if not ends or len(self._of("attempt_start")) >= MAX_ATTEMPTS:
            raise Refused("no_next_attempt")
        if len(self._of("reset_start")) >= MAX_RESETS:
            raise Refused("reset_cap")
        previous_end = ends[-1]["now_ms"]
        if now_ms < previous_end:
            raise Refused("monotonic_clock_regressed")
        if now_ms > previous_end + RESET_MS:
            self.stop(now_ms, "reset_expired")
            raise Refused("reset_expired")
        if remaining_ms < RESET_MS + ATTEMPT_MS + export_cleanup_ms:
            self.stop(now_ms, "insufficient_remaining_absolute_time")
            raise Refused("insufficient_remaining_absolute_time")
        self._write("reset_start", now_ms, deadline_ms=previous_end + RESET_MS)

    def allocate(
        self, now_ms: int, *, remaining_ms: int, export_cleanup_ms: int, replacement: bool = False
    ) -> int:
        nonnegative(remaining_ms, "remaining_ms")
        nonnegative(export_cleanup_ms, "export_cleanup_ms")
        if replacement:
            raise Refused("replacement_attempt_forbidden")
        starts = self._of("attempt_start")
        if len(starts) >= MAX_ATTEMPTS:
            raise Refused("three_total_attempt_cap")
        if self._stop_reason() or self._open_attempt():
            raise Refused("campaign_stopped_or_attempt_open")
        if starts:
            reset = self._open_reset()
            if not reset:
                raise Refused("reset_required_before_next_setup")
            if now_ms > reset["deadline_ms"]:
                self.fail_reset(now_ms, "reset_expired")
                raise Refused("reset_expired")
            reset_index = max(
                i for i, event in enumerate(self.events) if event["event"] == "reset_start"
            )
            if any(e["event"] == "attempt_start" for e in self.events[reset_index + 1 :]):
                raise Refused("reset_attempt_already_allocated")
        if remaining_ms < ATTEMPT_MS + export_cleanup_ms:
            if self._open_reset():
                self.fail_reset(now_ms, "insufficient_remaining_absolute_time")
            else:
                self.stop(now_ms, "insufficient_remaining_absolute_time")
            raise Refused("insufficient_remaining_absolute_time")
        attempt = len(starts) + 1
        self._write("attempt_start", now_ms, attempt=attempt, target_slot=TARGET_ORDER[attempt - 1])
        return attempt

    def setup_complete(self, now_ms: int, *, preconditions: bool, reasons: list[str]) -> None:
        current = self._open_attempt()
        if not current:
            raise Refused("durable_attempt_start_required")
        if any(e["attempt"] == current["attempt"] for e in self._of("setup_complete")):
            raise Refused("setup_already_completed")
        reset = self._open_reset()
        if reset and now_ms > reset["deadline_ms"]:
            self.fail_reset(now_ms, "reset_expired")
            raise Refused("reset_expired")
        if not preconditions:
            if not reasons:
                raise ValueError("failed_precondition_requires_reason")
            self._write(
                "setup_failed",
                now_ms,
                attempt=current["attempt"],
                preconditions=False,
                reasons=reasons,
            )
            self.end_attempt(
                now_ms,
                measurement_valid=False,
                reasons=reasons,
                operational_outcomes=["deletion_not_issued"],
                replacement_usable_by_deadline=None,
            )
            return
        self._write("setup_complete", now_ms, attempt=current["attempt"], preconditions=True)
        if reset:
            self._write("reset_complete", now_ms, deadline_ms=reset["deadline_ms"])
        self._write(
            "traffic_start", now_ms, attempt=current["attempt"], deadline_ms=now_ms + ATTEMPT_MS
        )

    def end_attempt(
        self,
        now_ms: int,
        *,
        measurement_valid: bool,
        reasons: list[str],
        operational_outcomes: list[str],
        replacement_usable_by_deadline: bool | None,
    ) -> None:
        current = self._open_attempt()
        if not current:
            raise Refused("no_open_attempt")
        traffic = [e for e in self._of("traffic_start") if e["attempt"] == current["attempt"]]
        if measurement_valid and not traffic:
            raise Refused("setup_failure_cannot_be_valid_event")
        if not measurement_valid and not reasons:
            raise ValueError("inadequate_attempt_requires_reason")
        if traffic and now_ms > traffic[-1]["deadline_ms"]:
            raise Refused("attempt_deadline_exceeded_close_at_deadline")
        self._write(
            "attempt_end",
            now_ms,
            attempt=current["attempt"],
            measurement_valid=measurement_valid,
            reasons=reasons,
            operational_outcomes=operational_outcomes,
            replacement_usable_by_deadline=replacement_usable_by_deadline,
        )
        if not traffic and self._open_reset():
            self.fail_reset(now_ms, "reset_setup_failure")
        elif replacement_usable_by_deadline is False:
            self.stop(now_ms, "previous_replacement_never_usable")

    def fail_reset(self, now_ms: int, reason: str) -> None:
        if not reason or not self._open_reset():
            raise Refused("no_open_reset_or_reason")
        # Close the reset before closing setup, so end_attempt cannot reclassify
        # an explicit reset failure/expiry as reset_setup_failure.
        self._write("reset_failed", now_ms, reason=reason)
        if self._open_attempt():
            self.end_attempt(
                now_ms,
                measurement_valid=False,
                reasons=[reason],
                operational_outcomes=["deletion_not_issued"],
                replacement_usable_by_deadline=None,
            )
        self.stop(now_ms, reason)

    def record_one_event_decision(self, now_ms: int, *, authority: str, decision_ref: str) -> None:
        # A reference records the owner's existing §6.4 decision; never creates one.
        if authority != "Xiaoyun" or not decision_ref:
            raise Refused("recorded_owner_section_6_4_decision_required")
        self._write("section_6_4_decision", now_ms, authority=authority, decision_ref=decision_ref)

    def report(self) -> dict:
        starts = {e["attempt"]: e for e in self._of("attempt_start")}
        ends = {e["attempt"]: e for e in self._of("attempt_end")}
        slots = []
        for index, target in enumerate(TARGET_ORDER, 1):
            if index in ends:
                slots.append({"attempt": index, "target_slot": target, **ends[index]})
            elif index in starts:
                slots.append({"attempt": index, "target_slot": target, "state": "in_progress"})
            else:
                slots.append(
                    {
                        "attempt": index,
                        "target_slot": target,
                        "state": "not_attempted",
                        "reason": self._stop_reason() or "not_started",
                    }
                )
        valid = sum(e["measurement_valid"] for e in ends.values())
        inadequate = any(not e["measurement_valid"] for e in ends.values())
        return {
            "slots": slots,
            "full_acceptance_reachable": valid == MAX_ATTEMPTS
            or (not inadequate and not self._stop_reason()),
            "three_valid_events": valid == MAX_ATTEMPTS,
            "one_event_decision_recorded": bool(self._of("section_6_4_decision")),
            "one_event_label_eligible": valid >= 1 and bool(self._of("section_6_4_decision")),
            "reset_receipts": [e for e in self.events if e["event"].startswith("reset_")],
            "campaign_max_ms": CAMPAIGN_MS,
        }

    def close_slots(self, now_ms: int, reason: str) -> dict:
        self.stop(now_ms, reason)
        return self.report()
