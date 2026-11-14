"""Small real-process witness; file fsync does not claim POSIX directory fencing."""

import copy
import json
import os
import sys
import threading
import time
from contextlib import contextmanager
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from inference_platform.inf037b_archive import encode
from inference_platform.inf037b_eks_supervisor import (
    AuthorityHTTP,
    SupervisorTimer,
    fenced_supervisor,
    supervisor_handler,
)
from inference_platform.inf037b_ports import Authority, BackstopPort


class FileJournal:
    """Explicit single-writer portable test seam, never a live DurableStore."""

    def __init__(self, directory, initial, *, initialize=False):
        Path(directory).mkdir(parents=True, exist_ok=True)
        self.path = Path(directory) / "journal.jsonl"
        self.mutex = threading.RLock()
        if not self.path.exists():
            assert initialize
            self.write(initial)

    @contextmanager
    def lock(self):
        with self.mutex:
            yield

    def read(self):
        return json.loads(self.path.read_bytes().splitlines()[-1])

    def write(self, state):
        with self.path.open("ab") as stream:
            stream.write(encode(copy.deepcopy(state)))
            stream.flush()
            os.fsync(stream.fileno())


def main():
    mode, root = sys.argv[1], Path(sys.argv[2])
    if mode == "service":

        def terminate(body):
            (root / "fired.json").write_bytes(encode(body))
            return body

        def reconcile(body):
            path = root / "fired.json"
            return {
                "known": path.exists(),
                "executed": path.exists(),
                "result": json.loads(path.read_bytes()) if path.exists() else None,
            }

        timer = SupervisorTimer(
            root / "timer",
            terminate=terminate,
            reconcile=reconcile,
            clock=lambda: time.time_ns() // 1_000_000,
            store=FileJournal(root / "timer", {"arms": {}}, initialize=True),
        ).start()

        def in_flight():
            (root / "in-flight").write_text("armed", encoding="utf-8")
            time.sleep(0.4)

        with patch("inference_platform.inf037b_authority.DurableStore", FileJournal):
            authority = fenced_supervisor(
                root / "authority", "supervisor", timer, effect_hook=in_flight
            )
        server = ThreadingHTTPServer(
            ("127.0.0.1", 0), supervisor_handler(authority, lambda: "local-token")
        )
        (root / "ready.json").write_bytes(encode({"port": server.server_port, "pid": os.getpid()}))
        try:
            server.serve_forever()
        finally:
            server.server_close()
            timer.close()
    else:
        port, deadline, timeout = map(int, sys.argv[3:6])
        authority = Authority(
            "supervisor",
            "backstop",
            AuthorityHTTP(
                f"http://127.0.0.1:{port}/authority", token=lambda: "local-token", local_test=True
            ),
            timeout_ms=timeout,
        )
        with patch("inference_platform.inf037b_ports.DurableStore", FileJournal):
            client = BackstopPort(
                root / "client",
                authority,
                lambda: time.time_ns() // 1_000_000,
                "operator",
                initialize=True,
            )
        try:
            result = (
                client.arm("session", deadline)
                if mode == "arm"
                else client.confirmed("session", deadline)
            )
            print(json.dumps({"confirmed": result, "pid": os.getpid(), "deadline_ms": deadline}))
        except Exception as exc:
            print(json.dumps({"error": type(exc).__name__ + ":" + str(exc), "pid": os.getpid()}))
            raise SystemExit(2) from None


if __name__ == "__main__":
    main()
