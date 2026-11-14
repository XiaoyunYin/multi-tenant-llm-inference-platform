"""Start each native sampler from its retained, same-UID startup edge.

The capture's lifecycle loop is the sole owner of ``NodeLifecycleAdapter.poll``.
``startup_rows[uid]`` is a read-only iterable over that UID's retained row sink;
the sampler never polls a transport. ``RetainedStartupRows`` reads the existing
archive through its row API under the capture's append lock, without a second
store or a Kubernetes client.
"""

import threading
import time
from collections.abc import Iterable
from pathlib import Path

from .inf037b_archive import IntegrityError, iter_segment_rows

CADENCE_NS = 500_000_000


class MonotonicScheduler:
    def now_ns(self):
        return time.monotonic_ns()

    def wait_until(self, target_ns, stop):
        stop.wait(max(0, target_ns - self.now_ns()) / 1_000_000_000)


class RetainedStartupRows:
    """Read a UID's startup rows from the capture's original raw archive.

    Pass ``owner.archive.root / "raw"`` and ``owner.lock``. The same lock guards
    append and read, so the existing row iterator cannot observe a partial append.
    Each iteration returns newly decoded rows, never writable references to the sink.
    """

    def __init__(self, raw, uid, lock):
        self.raw, self.uid, self.lock = Path(raw), uid, lock

    def __iter__(self):
        with self.lock:
            rows = tuple(
                row
                for path in sorted(self.raw.glob("kubernetes*.jsonl"))
                for _, _, row in iter_segment_rows(path)
                if row["payload"].get("pod_uid") == self.uid
                and row["payload"].get("event") == "startup"
            )
        return iter(rows)


class SamplerComposition:
    """Own one worker per fixed Pod UID and join all workers before flushing.

    Sources and HTTP adapters must have bounded reads (the existing live HTTP
    transport does). Stop interrupts scheduler waits; an in-flight bounded read
    finishes before the worker is joined. ``flush`` drains the caller's retained
    row sink only after every worker has stopped using it.
    """

    def __init__(self, adapters, startup_rows, *, flush, scheduler=None):
        if (
            not adapters
            or set(adapters) != set(startup_rows)
            or any(uid != adapter.uid for uid, adapter in adapters.items())
            or any(
                callable(rows) or not isinstance(rows, Iterable) for rows in startup_rows.values()
            )
        ):
            raise IntegrityError("fitness:sampler_uid_inventory")
        self.adapters, self.startup_rows = dict(adapters), dict(startup_rows)
        self.flush = flush
        self.scheduler = scheduler or MonotonicScheduler()
        self.threads, self.samples = [], dict.fromkeys(adapters, 0)
        self.used = False
        self.polling, self.poll_due = False, {}

    def _wait(self, target_ns, stop):
        while not stop.is_set() and self.scheduler.now_ns() < target_ns:
            self.scheduler.wait_until(target_ns, stop)

    def _observed_startup(self, uid):
        return any(
            row.get("source_kind") == "kubernetes"
            and row.get("payload", {}).get("event") == "startup"
            and row["payload"].get("pod_uid") == uid
            and row.get("error") is None
            and row.get("missing_reason") is None
            for row in tuple(self.startup_rows[uid])
        )

    def poll(self, uid, *, deadline_ns):
        """One bounded step for CaptureOwner's existing 500 ms periodic loop.

        No worker or new lifetime is created. The owner settles/flushes these
        rows, and its original cutoff/cadence/failure rules remain authoritative.
        The threaded run() mode and cooperative poll() mode cannot be mixed.
        """
        if uid not in self.adapters or (self.used and not self.polling):
            raise IntegrityError("fitness:sampler_already_run")
        self.used, self.polling = True, True
        now = self.scheduler.now_ns()
        if now >= deadline_ns:
            raise IntegrityError("fitness:sampler_startup_deadline:" + uid)
        if uid not in self.poll_due:
            if not self._observed_startup(uid):
                return False
            if self.scheduler.now_ns() >= deadline_ns:
                raise IntegrityError("fitness:sampler_startup_deadline:" + uid)
            self.adapters[uid].engine_config()
            self.poll_due[uid] = self.scheduler.now_ns() + CADENCE_NS
            return False
        if now < self.poll_due[uid]:
            return False
        self.adapters[uid].sample()
        self.samples[uid] += 1
        tick = self.poll_due[uid] + CADENCE_NS
        now = self.scheduler.now_ns()
        if tick <= now:
            tick += ((now - tick) // CADENCE_NS + 1) * CADENCE_NS
        self.poll_due[uid] = tick
        return True

    def _startup(self, uid, deadline_ns, stop):
        while not stop.is_set():
            if self.scheduler.now_ns() >= deadline_ns:
                raise IntegrityError("fitness:sampler_startup_deadline:" + uid)
            observed = self._observed_startup(uid)
            if self.scheduler.now_ns() >= deadline_ns:
                raise IntegrityError("fitness:sampler_startup_deadline:" + uid)
            if stop.is_set():
                return False
            if observed:
                return True
            self._wait(min(self.scheduler.now_ns() + CADENCE_NS, deadline_ns), stop)
        return False

    def _sample(self, uid, deadline_ns, stop):
        adapter = self.adapters[uid]
        if not self._startup(uid, deadline_ns, stop):
            return
        adapter.engine_config()
        tick = self.scheduler.now_ns() + CADENCE_NS
        while not stop.is_set():
            self._wait(min(tick, deadline_ns), stop)
            now = self.scheduler.now_ns()
            if stop.is_set() or now >= deadline_ns:
                return
            adapter.sample()
            self.samples[uid] += 1
            tick += CADENCE_NS
            # Keep the original grid without bursting samples after a slow read.
            now = self.scheduler.now_ns()
            if tick <= now:
                tick += ((now - tick) // CADENCE_NS + 1) * CADENCE_NS

    def run(self, *, deadline_ns, stop=None):
        if self.used:
            raise IntegrityError("fitness:sampler_already_run")
        self.used = True
        stop = stop if stop is not None else threading.Event()
        failures, lock = [], threading.Lock()

        def worker(uid):
            try:
                self._sample(uid, deadline_ns, stop)
            except Exception as exc:
                with lock:
                    failures.append((uid, exc))
                stop.set()

        try:
            for uid in self.adapters:
                thread = threading.Thread(target=worker, args=(uid,), name="inf037b-sampler-" + uid)
                thread.start()
                self.threads.append(thread)
            for thread in self.threads:
                thread.join()
        finally:
            stop.set()
            for thread in self.threads:
                thread.join()
            self.flush()
        if failures:
            raise sorted(failures, key=lambda pair: pair[0])[0][1]
        return dict(self.samples)
