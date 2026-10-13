"""Bounded deterministic calibration look-ahead; never journals undispatched rows."""

import threading
import time
from collections import deque


class CalibrationRows:
    # Two rows per worker, plus at most one row being constructed. No phase bank.
    DEPTH = 2

    def __init__(self, level, salt, tokenizer, build, first_blocks, deadline):
        self.level, self.salt, self.tokenizer, self.build = level, salt, tokenizer, build
        self.deadline = deadline
        self.queues = [deque() for _ in range(2 * level)]
        self.cycles = [0] * len(self.queues)
        self.seen = set(first_blocks)
        self.condition = threading.Condition()
        self.stopped, self.error, self.high_water = False, None, 0
        self.thread = threading.Thread(target=self._produce, name="r1-calibration-lookahead")
        self.thread.start()
        try:
            with self.condition:
                while not all(self.queues):
                    self._wait()
        except BaseException:
            self.close()
            raise

    def _wait(self):
        if self.error:
            raise self.error
        remaining = self.deadline - time.perf_counter()
        if remaining <= 0:
            raise TimeoutError("calibration look-ahead deadline")
        self.condition.wait(min(remaining, 0.1))

    def _produce(self):
        try:
            worker = 0
            while True:
                with self.condition:
                    if self.stopped:
                        return
                    candidates = [
                        (worker + offset) % len(self.queues) for offset in range(len(self.queues))
                    ]
                    selected = next(
                        (i for i in candidates if len(self.queues[i]) < self.DEPTH), None
                    )
                    if selected is None:
                        self.condition.wait(0.1)
                        continue
                    cycle = self.cycles[selected]
                identity = f"cal-{selected // self.level}-{self.level}-{selected}-cycle-{cycle}"
                value = self.build(identity, self.salt, self.tokenizer)
                first = tuple(value["tokens"][:16])
                if first in self.seen:
                    raise ValueError("dynamic calibration first-block collision")
                self.seen.add(first)
                with self.condition:
                    self.queues[selected].append(value)
                    self.cycles[selected] += 1
                    self.high_water = max(self.high_water, sum(map(len, self.queues)))
                    self.condition.notify_all()
                worker = (selected + 1) % len(self.queues)
        except BaseException as exc:
            with self.condition:
                self.error = exc
                self.condition.notify_all()

    def take(self, worker):
        with self.condition:
            while not self.queues[worker]:
                self._wait()
            if self.error:
                raise self.error
            value = self.queues[worker].popleft()
            self.condition.notify_all()
            return value

    def close(self):
        with self.condition:
            self.stopped = True
            self.condition.notify_all()
        self.thread.join(timeout=max(0.1, self.deadline - time.perf_counter()))
        if self.thread.is_alive():
            raise TimeoutError("calibration row producer did not stop")
