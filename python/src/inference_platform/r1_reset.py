"""One bounded preparation state machine, shared by HTTP and virtual rehearsals."""

from .r1_metrics import COUNTERS, delta


class PreparationFailed(Exception):
    pass


class Reset:
    def __init__(self, io, emit, pending, session_deadline):
        self.io, self.emit, self.pending = io, emit, pending
        self.start = io.clock.now()
        self.deadline = min(self.start + 120, session_deadline)
        self.overrun = False
        self.attempts = {}
        self.generations = None

    def event(self, kind, **fields):
        self.emit(
            {
                "event": kind,
                "pending": self.pending,
                "elapsed_s": self.io.clock.now() - self.start,
                "deadline_s": self.deadline,
                "remaining_s": max(0, self.deadline - self.io.clock.now()),
                "attempts": dict(self.attempts),
                **fields,
            }
        )

    def check(self):
        elapsed = self.io.clock.now() - self.start
        if elapsed >= 60 and not self.overrun:
            self.overrun = True
            self.event(
                "reset_overrun_wait",
                reason="preparation exceeded nominal 60 s",
                wait_start_elapsed_s=60,
                wait_limit_elapsed_s=self.deadline - self.start,
            )
        if self.io.clock.now() >= self.deadline:
            raise PreparationFailed("absolute reset/session deadline exhausted")

    def sleep(self, seconds):
        self.check()
        # Split at 60 s so the bounded-wait record starts at the actual threshold.
        boundary = self.start + 60 if not self.overrun else self.deadline
        amount = min(seconds, self.deadline - self.io.clock.now(), boundary - self.io.clock.now())
        self.io.clock.sleep(amount)
        self.check()
        if amount < seconds:
            self.sleep(seconds - amount)

    def call(self, method, *args, timeout=5):
        self.check()
        result = method(*args, deadline=min(self.deadline, self.io.clock.now() + timeout))
        self.check()
        return result

    def snapshots(self):
        values = self.call(self.io.snapshots)
        identities = [(s["generation"], s["engine"], s["model_name"]) for s in values]
        if len(values) != 2 or any(s["age_s"] > 1 for s in values):
            raise PreparationFailed("missing/stale replica sample")
        if self.generations is None:
            self.generations = identities
        if identities != self.generations:
            raise PreparationFailed("backend generation/identity changed")
        self.event("native_snapshot", replicas=values)
        return values

    def visible_work(self, values):
        state = self.call(self.io.admission_state)
        return any(s["running"] or s["waiting"] for s in values) or any(state.values())

    def drain(self):
        consecutive = 0
        while consecutive < 3:
            values = self.snapshots()
            consecutive = 0 if self.visible_work(values) else consecutive + 1
            if consecutive < 3:
                self.sleep(0.5)
        self.event("drained", replicas=values)
        return values

    def settle(self, before=None, expected_queries=None, expected_completions=None):
        end = min(self.deadline, self.io.clock.now() + 15)
        previous, consecutive = None, 0
        while self.io.clock.now() < end:
            values = self.snapshots()
            expected = True
            if before is None:
                floors = self.io.counter_floors()
                expected = all(
                    value["queries"] >= floor["queries"]
                    and value["completions"] >= floor["completions"]
                    for value, floor in zip(values, floors, strict=True)
                )
            if before is not None:
                changes = [delta(a, b) for a, b in zip(before, values, strict=True)]
                expected = all(
                    change["queries"] == expected_queries
                    and change["completions"] == expected_completions
                    for change in changes
                )
                if any(
                    change["queries"] > expected_queries
                    or change["completions"] > expected_completions
                    for change in changes
                ):
                    raise PreparationFailed("unexpected unrelated probe counter update")
            current = [[s[key] for key in COUNTERS] for s in values]
            consecutive = consecutive + 1 if expected and current == previous else int(expected)
            previous = current
            if consecutive == 3:
                self.event("counters_settled", replicas=values)
                return values
            self.sleep(min(0.5, end - self.io.clock.now()))
        raise PreparationFailed("native counters failed to settle in 15 s")

    def probe(self, label, before):
        result = self.call(self.io.probe, label, timeout=10)
        if len(result) != 2 or not all(
            item["completed"] and item["prompt_tokens"] == 1024 and item["completion_tokens"] <= 1
            for item in result
        ):
            raise PreparationFailed("sentinel completion validation failed")
        after = self.settle(before, 1024, 1)
        changes = [delta(a, b) for a, b in zip(before, after, strict=True)]
        if any(change["hits"] > 1008 or change["preemptions"] for change in changes):
            raise PreparationFailed("sentinel metric fitness failed")
        self.event("sentinel", label=label, deltas=changes, completion=result)
        return after, changes

    def post(self, stage):
        for backend in range(2):
            key = f"{stage}:{backend}"
            last_attempt = None
            for attempt in range(1, 4):
                if last_attempt is not None:
                    self.sleep(max(0, 1 - (self.io.clock.now() - last_attempt)))
                self.drain()
                self.attempts[key] = attempt
                last_attempt = self.io.clock.now()
                try:
                    response = self.call(self.io.reset, backend, stage)
                except TimeoutError:
                    response = {"status": None, "success": None, "uncertain": True}
                self.event(
                    "reset_reply",
                    backend=backend,
                    stage=stage,
                    response=response,
                    fixture_cache_state=getattr(self.io, "reset_cache_state", None),
                    attempt_started_elapsed_s=last_attempt - self.start,
                )
                if response.get("status") == 200 and response.get("success") is True:
                    break
                if response.get("uncertain") is True:
                    self.event(
                        "reset_retry_reason", reason="timeout; outcome uncertain", backend=backend
                    )
                    continue
                if response.get("status") == 200 and response.get("success") is False:
                    work = self.visible_work(self.snapshots())
                    self.event("reset_refusal", backend=backend, observable_work=work)
                    if work:
                        continue
                    raise PreparationFailed("reset refusal without observable work")
                raise PreparationFailed("invalid reset HTTP/body response")
            else:
                raise PreparationFailed("three reset POST attempts exhausted")

    def run(self, configure=None):
        self.event("reset_preparation_started", slot_state="pending", slot_consumed=False)
        try:
            self.call(self.io.close_admissions)
            self.drain()
            baseline = self.settle()
            baseline, _ = self.probe("prime", baseline)
            baseline, changes = self.probe("positive_control", baseline)
            if any(change["hits"] <= 0 for change in changes):
                raise PreparationFailed("positive-control replay had no native hits")
            self.post("clear")
            baseline = self.settle()
            baseline, changes = self.probe("zero_hit", baseline)
            if any(change["hits"] != 0 for change in changes):
                raise PreparationFailed("post-reset sentinel hit delta was nonzero")
            self.post("cleanup")
            baseline = self.settle()
            self.drain()
            if configure is not None:
                self.call(configure)
                baseline = self.settle()
            self.io.preparation_complete()
            self.event(
                "reset_preparation_succeeded",
                final_baselines=baseline,
                wait_elapsed_s=max(0, self.io.clock.now() - self.start - 60),
                slot_state="pending",
                slot_consumed=False,
            )
            return baseline
        except (PreparationFailed, ValueError, TimeoutError, OSError) as exc:
            self.event(
                "reset_preparation_failed",
                reason=str(exc),
                slot_state="not_started",
                slot_consumed=False,
                wait_elapsed_s=max(0, self.io.clock.now() - self.start - 60),
            )
            raise PreparationFailed(str(exc)) from exc
