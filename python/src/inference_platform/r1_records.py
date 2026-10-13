"""Bounded asynchronous JSONL journal; dispatch never opens, encodes or writes files."""

import queue
import threading
import time
from pathlib import Path

from .r1_spec import encoded


class Journal:
    def __init__(self, directory, capacity=8192):
        self.directory = Path(directory)
        self.queue = queue.Queue(capacity)
        self.error = None
        self.thread = threading.Thread(target=self._write, name="r1-record-writer", daemon=True)
        self.thread.start()

    def record(self, name, value):
        if self.error:
            raise OSError("R1 journal failed") from self.error
        try:
            self.queue.put_nowait((name, value))
        except queue.Full as exc:
            raise OSError("R1 journal backpressure; records cannot be dropped") from exc

    def _write(self):
        files = {}
        try:
            while True:
                item = self.queue.get()
                if item is None:
                    break
                name, value = item
                if isinstance(value, threading.Event):
                    for file in files.values():
                        file.flush()
                    value.set()
                else:
                    if name not in files:
                        files[name] = (self.directory / name).open("ab", buffering=1048576)
                    files[name].write(encoded(value) + b"\n")
        except BaseException as exc:
            self.error = exc
        finally:
            for file in files.values():
                file.close()

    def flush(self, deadline):
        event = threading.Event()
        self.queue.put((None, event), timeout=max(0.001, deadline - time.perf_counter()))
        while not event.wait(min(0.1, max(0, deadline - time.perf_counter()))):
            if self.error:
                raise OSError("R1 journal failed") from self.error
            if time.perf_counter() >= deadline:
                raise TimeoutError("R1 journal flush deadline")

    def close(self, deadline):
        self.flush(deadline)
        self.queue.put(None, timeout=max(0.001, deadline - time.perf_counter()))
        self.thread.join(timeout=max(0, deadline - time.perf_counter()))
        if self.thread.is_alive():
            raise TimeoutError("R1 journal close deadline")
