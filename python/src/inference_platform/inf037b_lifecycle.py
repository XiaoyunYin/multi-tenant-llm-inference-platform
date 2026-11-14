"""Offline 4b lifecycle, durable recovery and bounded child execution.

No configured provider, paid launcher, setup materializer or packet producer.
The runner and pre-start packet barrier are required injected ports. An offline
barrier double is not evidence of the two-store contract owned by 4c.
"""

import copy
import os
import signal
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path

from .inf037b_archive import durable_write, encode, envelope, inspect_segment, sha, strict_json
from .inf037b_attempts import AttemptController
from .inf037b_contract import EXPORT_CLEANUP_MS
from .inf037b_resolver import BOUNDS_MS, SessionDeadline, exact, integer, remaining_work, require

EXIT_RESERVE_MS = 1000


@dataclass(frozen=True)
class AttemptExit:
    value: object
    observed_ms: int


class LifecycleJournal:
    """Serialized, append-only lifecycle receipts; POSIX file/directory barriers.

    The path entry to LifecycleDriver opens AttemptController under this lease.
    A preopened controller is retained for single-writer fixture callers only.
    Windows supports portable fixture execution, not the POSIX recovery proof.
    """

    def __init__(self, path):
        self.path, self.rows = Path(path), []
        self.opened = False
        self.failed = False

    @contextmanager
    def lease(self):
        with self.path.with_suffix(".lock").open("a+b") as stream:
            if os.name == "posix":
                import fcntl

                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            else:
                import msvcrt

                if stream.tell() == 0:
                    stream.write(b"0")
                    stream.flush()
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            try:
                yield
            finally:
                if os.name == "posix":
                    fcntl.flock(stream, fcntl.LOCK_UN)
                else:
                    stream.seek(0)
                    msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)

    def open(self, binding, attempt_path):
        if self.path.exists():
            _, rows = inspect_segment(self.path)
            require(bool(rows), "lifecycle:unsealed_journal")
            previous = None
            for index, row in enumerate(rows):
                exact(row["source_seq"], index, "lifecycle:journal_sequence")
                exact(row["payload"]["previous_sha256"], previous, "lifecycle:journal_chain")
                previous = sha(encode(row))
            self.rows = [r["payload"] for r in rows]
            exact(self.rows[0]["event"], "binding", "lifecycle:journal_origin")
            exact(self.rows[0]["binding"], binding, "lifecycle:original_binding")
            # A prior writer may have lost the fsync acknowledgement after a
            # complete append. Re-barrier those bytes before exposing receipts.
            try:
                with self.path.open("r+b") as stream:
                    os.fsync(stream.fileno())
                if os.name == "posix":
                    from .inf037b_durable_ports import sync_directory

                    sync_directory(self.path.parent)
            except BaseException:
                self.failed = True
                raise
        else:
            require(
                not attempt_path.exists() or attempt_path.stat().st_size == 0,
                "lifecycle:missing_original_journal",
            )
            self.opened = True
            self.append("binding", binding["deadline"]["billing_origin_ms"], binding=binding)
        self.opened = True

    def append(self, event, now_ms, **fields):
        require(self.opened and not self.failed, "lifecycle:journal_open_or_poisoned")
        require(integer(now_ms) and now_ms >= 0, "lifecycle:journal_time")
        if self.rows:
            require(now_ms >= self.rows[-1]["now_ms"], "lifecycle:journal_monotonic")
        previous = (
            sha(encode(envelope(self.rows[-1], seq=len(self.rows) - 1))) if self.rows else None
        )
        payload = dict(event=event, now_ms=now_ms, previous_sha256=previous, **fields)
        row = envelope(payload, seq=len(self.rows))
        data = encode(row)
        try:
            durable_write(self.path, data, "ab" if self.rows else "xb")
            if os.name == "posix":
                from .inf037b_durable_ports import sync_directory

                sync_directory(self.path.parent)
            expected = b"".join(encode(envelope(r, seq=i)) for i, r in enumerate(self.rows)) + data
            exact(self.path.read_bytes(), expected, "lifecycle:journal_readback")
        except BaseException:
            self.failed = True
            raise
        self.rows.append(payload)

    def find(self, event, key):
        matches = [r for r in self.rows if r["event"] == event and r.get("key") == key]
        require(len(matches) <= 1, "lifecycle:duplicate_receipt")
        return matches[0] if matches else None


def valid_outcome(value):
    """The child boundary is exact typed, including bool/int separation."""
    keys = {
        "measurement_valid",
        "reasons",
        "operational_outcomes",
        "replacement_usable_by_deadline",
        "measurement_end_ms",
    }
    return (
        type(value) is dict
        and set(value) == keys
        and type(value["measurement_valid"]) is bool
        and all(
            type(value[k]) is list and all(type(s) is str and bool(s) for s in value[k])
            for k in ("reasons", "operational_outcomes")
        )
        and (
            value["replacement_usable_by_deadline"] is True
            or value["replacement_usable_by_deadline"] is False
            or value["replacement_usable_by_deadline"] is None
        )
        and integer(value["measurement_end_ms"])
        and value["measurement_end_ms"] >= 0
    )


def cancel_reconcile(operation, key, body, observation):
    """Classify a serialized, request-bound provider observation, never absence.

    The reader must prove accepted requests under the authority's exclusive
    credentials; this is deliberately not an EC2 Describe adapter. Missing,
    stale, malformed or unbound observations remain unknown. Repeated real
    cancellation must be idempotent, or raise on an unmapped provider error.
    """
    unknown = {"known": False, "executed": False, "result": None}
    exact(operation, "odcr.cancel", "lifecycle:cancel_operation")
    ids = body["expected_ids"]
    require(
        type(ids) is list and all(type(i) is str and i for i in ids) and len(ids) == len(set(ids)),
        "lifecycle:cancel_ids",
    )
    if not isinstance(observation, dict):
        return unknown
    if (
        observation.get("authoritative") is not True
        or observation.get("key") != key
        or observation.get("body_sha256") != sha(encode(body))
    ):
        return unknown
    states = observation.get("reservations")
    if not isinstance(states, dict):
        return unknown
    rows = [states.get(i) for i in ids]
    if all(isinstance(r, dict) and r.get("cancel_accepted") is True for r in rows):
        return {"known": True, "executed": True, "result": copy.deepcopy(observation.get("result"))}
    if any(
        isinstance(r, dict) and r.get("state") == "active" and r.get("cancel_accepted") is False
        for r in rows
    ):
        return {"known": True, "executed": False, "result": None}
    return unknown


def kernel_process(pid):
    """Read Linux stat without confusing spaces/parentheses in comm."""
    try:
        raw = Path(f"/proc/{pid}/stat").read_text()
    except (FileNotFoundError, ProcessLookupError):
        return None
    fields = raw[raw.rindex(")") + 2 :].split()
    return {"state": fields[0], "group": int(fields[2]), "start_ticks": int(fields[19])}


def child_identity(pid):
    record = kernel_process(pid)
    require(record is not None and record["group"] == pid, "lifecycle:child_session")
    return {
        "pid": pid,
        "group": record["group"],
        "start_ticks": record["start_ticks"],
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
    }


def group_members(group):
    # Z/X tasks are already dead: they cannot execute, create descendants or
    # write data. Their /proc entries can persist until an unrelated init reaps.
    members = []
    for path in Path("/proc").iterdir():
        if path.name.isdecimal():
            record = kernel_process(int(path.name))
            if record and record["group"] == group and record["state"] not in {"Z", "X"}:
                members.append(int(path.name))
    return members


def fence_child(identity, *, owned=False, timeout=1.0):
    """Fence only the original kernel identity; uncertainty blocks termination work."""
    exact(set(identity), {"pid", "group", "start_ticks", "boot_id"}, "lifecycle:child_identity")
    for key in ("pid", "group", "start_ticks"):
        require(integer(identity[key]) and identity[key] > 0, "lifecycle:child_identity")
    exact(identity["group"], identity["pid"], "lifecycle:child_group")
    exact(
        Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        identity["boot_id"],
        "lifecycle:child_boot",
    )
    record = kernel_process(identity["pid"])
    if (record is None and not owned) or (
        record is not None
        and (
            record["start_ticks"] != identity["start_ticks"] or record["group"] != identity["group"]
        )
    ):
        # A reused PID is never a licence to signal it or its group. Even a
        # missing leader cannot prove that its old descendants have stopped.
        require(not group_members(identity["group"]), "lifecycle:child_identity_unconfirmed")
        return
    try:
        os.killpg(identity["group"], signal.SIGKILL)
    except ProcessLookupError:
        pass
    until = time.monotonic() + timeout
    while group_members(identity["group"]):
        require(time.monotonic() < until, "lifecycle:child_group_unconfirmed")
        time.sleep(0.01)


# The trusted bootstrap cannot run the supplied command until it receives the
# release byte. EOF after parent death exits without acting. The JSON context
# remains file-backed, so neither argv limits nor a large pipe write can stall.
CHILD_BARRIER = """import os,sys
if sys.stdin.buffer.read(1) != b'1':
    raise SystemExit(125)
os.dup2(int(sys.argv[1]), 0)
os.execvp(sys.argv[2], sys.argv[2:])
"""


class ProcessCalls:
    """Offline Linux child watchdog; kill the entire process group on every exit.

    Commands are explicitly supplied by the harness. Attempts measure through
    stop_ms, with EXIT_RESERVE_MS afterward for exit. All other phases retain
    their internal 1 s reserve. No detached retries survive a timeout.
    A live remote transport still needs its own effect fence and recovery proof;
    killing a local client does not establish that a remote effect did not run.
    """

    def __init__(self, commands, clock):
        require(os.name == "posix", "lifecycle:process_platform")
        self.commands, self.clock = commands, clock

    def __call__(self, operation, stop_ms, context, *, spawned=None, fenced=None):
        kill_ms = stop_ms + EXIT_RESERVE_MS if operation == "attempt" else stop_ms - 1000
        remaining = kill_ms - self.clock()
        require(remaining > 0, "lifecycle:process_reserve")
        with (
            tempfile.TemporaryFile() as inputs,
            tempfile.TemporaryFile() as output,
            tempfile.TemporaryFile() as errors,
        ):
            inputs.write(encode(context))
            inputs.seek(0)
            proc = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    CHILD_BARRIER,
                    str(inputs.fileno()),
                    *self.commands[operation],
                ],
                pass_fds=(inputs.fileno(),),
                stdin=subprocess.PIPE,
                stdout=output,
                stderr=errors,
                start_new_session=True,
            )
            try:
                identity = child_identity(proc.pid)
            except BaseException:
                # No release has been sent: only our inert bootstrap exists.
                proc.stdin.close()
                proc.kill()
                proc.wait(timeout=1)
                raise
            try:
                if spawned is not None:
                    spawned(identity)
                proc.stdin.write(b"1")
                proc.stdin.close()
                proc.wait(timeout=max(0, kill_ms - self.clock()) / 1000)
                observed_ms = self.clock()
                require(proc.returncode == 0, "lifecycle:process_exit")
            finally:
                try:
                    fence_child(identity, owned=True)
                finally:
                    proc.stdin.close()
                    proc.wait(timeout=1)
                if fenced is not None:
                    fenced(identity)
            require(
                observed_ms <= (kill_ms if operation == "attempt" else stop_ms),
                "lifecycle:process_cutoff",
            )
            output.seek(0)
            data = output.read(1_000_001)
            require(len(data) <= 1_000_000, "lifecycle:process_output")
            value = strict_json(data)
            return AttemptExit(value, observed_ms) if operation == "attempt" else value


class LifecycleDriver:
    """Durable offline lifecycle; no provider/paid entry point is configured.

    Call receipts are independent of attempt accounting. An interrupted effect
    is never guessed successful. Only export/cleanup replay their original
    request, and require an idempotent/fenced executor under that same key.
    Host loss, escaped descendants, damaged storage and fsync stalls still need
    the independent emergency supervisor. Local reopen fences are not that host.
    """

    def __init__(self, *, deadline, clock, execute, attempts):
        require(type(deadline) is SessionDeadline, "lifecycle:deadline")
        self.deadline, self.clock, self.execute = deadline, clock, execute
        self.attempt_path = (
            attempts.journal if isinstance(attempts, AttemptController) else Path(attempts)
        )
        self.attempts = attempts if isinstance(attempts, AttemptController) else None
        self.journal = LifecycleJournal(self.attempt_path.with_name("lifecycle.jsonl"))
        self.allowances = BOUNDS_MS.copy()
        self.previous = deadline.billing_origin_ms
        self.calls, self.refusals = [], []
        self.campaign_origin = None
        self.used, self.abort_deadline = False, False
        self.last_exit_ms = None
        self.abort_checked_ms = None

    def now(self):
        now = self.clock()
        require(integer(now) and now >= self.previous, "lifecycle:clock")
        self.previous = now
        return now

    def remaining(self, attempts, resets, setup=0, *, first=False):
        now = self.now()

        def check(unspent):
            return remaining_work(
                now_upper_ms=now,
                deadline=self.deadline,
                allowances=self.allowances,
                attempts=attempts,
                resets=resets,
                unspent_setup_ms=unspent,
                before_attempt1=first,
            )

        if setup is None:
            elapsed = now - self.deadline.billing_origin_ms
            # Retain the original fixed-envelope gate. Charging R against all
            # 7,320 s of offline setup ceilings would always reject 18,000 s.
            check(max(0, 3_600_000 - elapsed) + 3_720_000)
            # The additional exit-reserve gate uses the already accepted live
            # creation/preparation limits, plus the full resolution allowance.
            setup = max(0, 1_800_000 - elapsed) + 1_920_000
        result = check(setup)
        extra = attempts * EXIT_RESERVE_MS
        require(
            result["latest_finish_ms"] + extra <= self.deadline.effective_ms,
            "lifecycle:remaining_exit_reserve",
        )
        return {
            "remaining_ms": result["remaining_ms"] + extra,
            "latest_finish_ms": result["latest_finish_ms"] + extra,
        }

    def _key(self, operation, context):
        return operation + (
            ":" + str(context["attempt"]) if type(context) is dict and "attempt" in context else ""
        )

    def _done(self, operation, context=None):
        return self.journal.find("call_end", self._key(operation, context))

    def _window(self, key, stop):
        row = self.journal.find("window", key)
        if row is None:
            self.journal.append("window", self.now(), key=key, stop_ms=stop)
            row = self.journal.find("window", key)
        return row["stop_ms"]

    def _completion(self, start, completed):
        checked_ms = completed["now_ms"]
        observed_ms = completed["observed_exit_ms"]
        require(
            integer(observed_ms) and start["start_ms"] <= observed_ms <= checked_ms,
            "lifecycle:observed_exit",
        )
        require(checked_ms <= start["kill_ms"], "lifecycle:call_overrun")
        self.last_exit_ms = observed_ms
        return copy.deepcopy(completed["value"]), checked_ms

    def call(self, operation, stop_ms, context=None):
        key = self._key(operation, context)
        start = self.journal.find("call_start", key)
        completed = self.journal.find("call_end", key)
        failed = self.journal.find("call_error", key)
        if start:
            # On reopen the persisted request wins, including its original
            # cutoff and context. Nothing is rebased on restart time.
            exact(start["stop_ms"], stop_ms, "lifecycle:original_cutoff")
            if completed:
                return self._completion(start, completed)
            if failed:
                raise RuntimeError(failed["reason"])
            require(operation in {"export", "cleanup"}, "lifecycle:interrupted_call")
        now = self.now()
        require(
            integer(stop_ms) and now < stop_ms <= self.deadline.effective_ms,
            "lifecycle:call_cutoff",
        )
        kill_ms = stop_ms + EXIT_RESERVE_MS if operation == "attempt" else stop_ms
        if operation == "attempt":
            require(
                kill_ms <= self.deadline.effective_ms - EXPORT_CLEANUP_MS,
                "lifecycle:attempt_kill_reserve",
            )
        if start is None:
            wire = {
                "input": copy.deepcopy(context),
                "operation_key": self.session_key + ":" + key,
                "operation_label": key,
                "measurement_deadline_ms": stop_ms,
                "kill_cutoff_ms": kill_ms if operation == "attempt" else stop_ms - 1000,
            }
            self.journal.append(
                "call_start",
                now,
                key=key,
                operation=operation,
                start_ms=now,
                stop_ms=stop_ms,
                kill_ms=kill_ms,
                context=wire,
            )
            start = self.journal.find("call_start", key)
            self.calls.append(
                {k: start[k] for k in ("operation", "start_ms", "stop_ms", "kill_ms")}
            )
        try:

            def spawned(identity):
                self.journal.append("spawned", self.now(), key=key, identity=identity)

            def fenced(identity):
                self.journal.append("child_fenced", self.now(), key=key, identity=identity)

            if isinstance(self.execute, ProcessCalls):
                value = self.execute(
                    operation,
                    stop_ms,
                    copy.deepcopy(start["context"]),
                    spawned=spawned,
                    fenced=fenced,
                )
            else:
                value = self.execute(operation, stop_ms, copy.deepcopy(start["context"]))
            checked_ms = self.now()
            observed_ms = value.observed_ms if isinstance(value, AttemptExit) else checked_ms
            value = value.value if isinstance(value, AttemptExit) else value
            self.journal.append(
                "call_end", checked_ms, key=key, value=value, observed_exit_ms=observed_ms
            )
        except Exception as error:
            self.journal.append(
                "call_error", self.now(), key=key, reason=type(error).__name__ + ":" + str(error)
            )
            raise
        return self._completion(start, self.journal.find("call_end", key))

    def _refusal(self, reason):
        if reason not in self.refusals:
            self.refusals.append(reason)
            self.journal.append("refusal", self.now(), key=reason, reason=reason)

    def _close(self, reason):
        intent = self.journal.find("stop_intent", "campaign")
        if intent is None:
            self.journal.append(
                "stop_intent",
                self.now(),
                key="campaign",
                reason=reason,
                at_deadline=self.abort_deadline,
                checked_ms=self.abort_checked_ms,
            )
            intent = self.journal.find("stop_intent", "campaign")
        reason = intent["reason"]
        now = self.now()
        current = self.attempts._open_attempt()
        if current:
            traffic = [
                e for e in self.attempts._of("traffic_start") if e["attempt"] == current["attempt"]
            ]
            end = intent.get("checked_ms") if intent.get("checked_ms") is not None else now
            if traffic:
                deadline = min(traffic[-1]["deadline_ms"], self.campaign_origin + 5_280_000)
                end = deadline if intent["at_deadline"] else min(end, deadline)
            self.attempts.end_attempt(
                end,
                measurement_valid=False,
                reasons=[reason],
                operational_outcomes=["aborted"],
                replacement_usable_by_deadline=None,
            )
        # A refused reported endpoint is censored at the deadline even if the
        # parent caught it earlier. Keep logical journal order without changing
        # the real clock used for export, cleanup and every admission check.
        logical_now = max(now, self.attempts.events[-1]["now_ms"] if self.attempts.events else now)
        if self.attempts._open_reset():
            self.attempts.fail_reset(logical_now, reason)
        elif not self.attempts._stop_reason():
            self.attempts.close_slots(logical_now, reason)

    def _prepare(self):
        if not self._done("creation"):
            self.remaining(3, 2, None, first=True)
            value, _ = self.call("creation", self.deadline.billing_origin_ms + 1_800_000)
            exact(value, True, "lifecycle:creation_ack")
        else:
            value, _ = self.call("creation", self.deadline.billing_origin_ms + 1_800_000)
            exact(value, True, "lifecycle:creation_ack")
        if not self._done("preparation"):
            self.remaining(3, 2, 3_720_000, first=True)
            stop = self._window(
                "preparation",
                min(
                    self.now() + 1_800_000,
                    self.deadline.billing_origin_ms + 3_600_000,
                    self.deadline.effective_ms - 8_880_000,
                ),
            )
            value, _ = self.call("preparation", stop)
            exact(value, True, "lifecycle:preparation_ack")
        else:
            value, _ = self.call(
                "preparation", self.journal.find("window", "preparation")["stop_ms"]
            )
            exact(value, True, "lifecycle:preparation_ack")
        preparation_stop = self.journal.find("window", "preparation")["stop_ms"]
        if not self._done("packet_barrier"):
            self.remaining(3, 2, 120_000, first=True)
            stop = self._window(
                "resolution", min(self.now() + 60_000, self.deadline.effective_ms - 8_880_000)
            )
            decision, _ = self.call("resolution", stop)
            value, _ = self.call("packet_barrier", stop, decision)
            exact(value, True, "lifecycle:packet_barrier")
        else:
            value, _ = self.call(
                "packet_barrier", self.journal.find("window", "resolution")["stop_ms"]
            )
            exact(value, True, "lifecycle:packet_barrier")
        return preparation_stop

    def _campaign(self, preparation_stop):
        while not self.attempts._stop_reason():
            allocated_here = False
            starts = self.attempts._of("attempt_start")
            current = self.attempts._open_attempt()
            if current is None:
                index = len(starts)
                if index == 3:
                    break
                if index and not self.attempts._open_reset():
                    self.remaining(3 - index, 3 - index)
                    now = self.now()
                    self.attempts.begin_reset(
                        now,
                        remaining_ms=self.deadline.effective_ms - now,
                        export_cleanup_ms=EXPORT_CLEANUP_MS,
                    )
                reset = self.attempts._open_reset()
                stop = (
                    preparation_stop
                    if not index
                    else min(
                        reset["deadline_ms"],
                        self.campaign_origin + 5_280_000,
                        self.deadline.effective_ms - EXPORT_CLEANUP_MS,
                    )
                )
                stop = self._window("setup:" + str(index + 1), stop)
                self.remaining(
                    3 - index,
                    2 - index,
                    max(0, preparation_stop - self.now()) if index == 0 else 0,
                    first=index == 0,
                )
                now = self.now()
                require(now < stop, "lifecycle:setup_start_budget")
                self.attempts.allocate(
                    now,
                    remaining_ms=self.deadline.effective_ms - now,
                    export_cleanup_ms=EXPORT_CLEANUP_MS,
                )
                allocated_here = True
                current = self.attempts._open_attempt()
            attempt = current["attempt"]
            context = {"attempt": attempt}
            traffic = [e for e in self.attempts._of("traffic_start") if e["attempt"] == attempt]
            if not traffic:
                require(not self.reopening or allocated_here, "lifecycle:interrupted_setup")
                require(
                    not any(e["attempt"] == attempt for e in self.attempts._of("setup_complete")),
                    "lifecycle:interrupted_traffic_start",
                )
                stop = self.journal.find("window", "setup:" + str(attempt))["stop_ms"]
                ready, checked_ms = self.call("attempt_setup", stop, context)
                exact(ready, True, "lifecycle:attempt_ready")
                self.remaining(4 - attempt, 3 - attempt)
                self.attempts.setup_complete(checked_ms, preconditions=True, reasons=[])
                traffic = [self.attempts._of("traffic_start")[-1]]
            if self.campaign_origin is None:
                self.campaign_origin = self.attempts._of("traffic_start")[0]["now_ms"]
            require(
                self.campaign_origin <= self.deadline.billing_origin_ms + 3_600_000,
                "lifecycle:first_traffic_anchor",
            )
            stop = min(traffic[-1]["deadline_ms"], self.campaign_origin + 5_280_000)
            # A traffic row without its call receipt after process death cannot
            # invent the missing continuous capture. Consume, close, export.
            require(
                not self.reopening
                or allocated_here
                or self.journal.find("call_start", "attempt:" + str(attempt)),
                "lifecycle:interrupted_measurement",
            )
            self.abort_deadline = True
            outcome, checked_ms = self.call("attempt", stop, context)
            self.abort_deadline = False
            self.abort_checked_ms = checked_ms
            require(valid_outcome(outcome), "lifecycle:outcome_shape")
            self.abort_checked_ms = None
            end_ms = outcome["measurement_end_ms"]
            self.abort_deadline = True
            require(
                traffic[-1]["now_ms"] <= end_ms <= stop and end_ms <= self.last_exit_ms,
                "lifecycle:measurement_end",
            )
            self.attempts.end_attempt(
                end_ms, **{k: v for k, v in outcome.items() if k != "measurement_end_ms"}
            )
            self.abort_deadline = False
            self.reopening = False
        self._close(self.attempts._stop_reason() or "campaign_complete")

    def _fence_pending(self):
        for row in self.journal.rows:
            if row["event"] == "spawned" and not any(
                r["event"] == "child_fenced"
                and r.get("key") == row["key"]
                and r["identity"] == row["identity"]
                for r in self.journal.rows
            ):
                fence_child(row["identity"])
                self.journal.append(
                    "child_fenced", self.now(), key=row["key"], identity=row["identity"]
                )

    def _finish(self):
        for operation, reserve in (("export", 1_800_000), ("cleanup", 0)):
            if not self._safe_fence():
                return
            try:
                if not self.journal.find("terminal_visit", operation):
                    self.journal.append("terminal_visit", self.now(), key=operation)
                start = self.journal.find("call_start", operation)
                stop = (
                    start["stop_ms"]
                    if start
                    else self._window(
                        operation,
                        min(
                            self.now() + BOUNDS_MS[operation], self.deadline.effective_ms - reserve
                        ),
                    )
                )
                value, _ = self.call(operation, stop)
                exact(value, True, "lifecycle:" + operation + "_ack")
            except Exception as error:
                self._refusal(operation + ":" + str(error))
        self.journal.append("complete", self.now(), key="session")

    def _safe_fence(self):
        try:
            self._fence_pending()
            return True
        except Exception as error:
            self._refusal("reopen_fence:" + str(error))
            return False

    def _report(self):
        return {
            "measurement_started": bool(self.attempts._of("attempt_start")),
            "attempts": self.attempts.report(),
            "calls": self.calls,
            "refusals": self.refusals,
            "raw_outcomes": [
                {"key": r["key"], "value": copy.deepcopy(r["value"])}
                for r in self.journal.rows
                if r["event"] == "call_end" and r["key"].startswith("attempt:")
            ],
            "D_eff_ms": self.deadline.effective_ms,
            "campaign_origin_ms": self.campaign_origin,
            "paid_ready": False,
        }

    def run(self):
        require(not self.used, "lifecycle:single_run")
        self.used = True
        with self.journal.lease():
            self.reopening = self.journal.path.exists()
            binding = {
                "deadline": asdict(self.deadline),
                "attempt_path": str(self.attempt_path.resolve()),
                "exit_reserve_ms": EXIT_RESERVE_MS,
                "child_fence_protocol": "linux-bootstrap-v1",
            }
            self.session_key = sha(encode(binding))
            self.journal.open(binding, self.attempt_path)
            if self.attempts is None:
                self.attempts = AttemptController(self.attempt_path)
            else:
                # The path entry avoids opening/recovering the accepted attempt
                # controller until the exclusive driver lease has been acquired.
                _, self.attempts.rows = inspect_segment(self.attempt_path)
                self.attempts.events = [r["payload"] for r in self.attempts.rows]
                self.attempts._recover_interrupted_stops()
            self.previous = max(self.previous, self.journal.rows[-1]["now_ms"])
            self.calls = [
                {k: r[k] for k in ("operation", "start_ms", "stop_ms", "kill_ms")}
                for r in self.journal.rows
                if r["event"] == "call_start"
            ]
            self.refusals = [r["reason"] for r in self.journal.rows if r["event"] == "refusal"]
            traffic = self.attempts._of("traffic_start")
            self.campaign_origin = traffic[0]["now_ms"] if traffic else None
            if self.journal.find("complete", "session"):
                return self._report()
            # No campaign close, export or cleanup may race an old local child.
            # This also applies when the new executor is a synthetic callback.
            if not self._safe_fence():
                return self._report()
            try:
                intent = self.journal.find("stop_intent", "campaign")
                if intent:
                    self._close(intent["reason"])
                elif self.attempts._stop_reason():
                    self._close(self.attempts._stop_reason())
                else:
                    self._campaign(self._prepare())
            except (Exception, KeyboardInterrupt) as error:
                self._refusal(type(error).__name__ + ":" + str(error))
                if not self._safe_fence():
                    return self._report()
                self._close(self.refusals[-1])
            self._finish()
            return self._report()
