"""CPU-only rollout wrapper for the existing fake vLLM protocol backend."""

import dataclasses
import json
import os
import signal
import threading
import time

from .fake_backend import FakeBackend, FakeBackendConfig

STREAM_CHUNKS = 24
STREAM_CHUNK_DELAY_MS = 1250  # 30 s: beyond preStop plus a serial gateway rollout step.


def main():
    stop = threading.Event()

    def record(message, **fields):
        print(json.dumps({"time_unix_ns": time.time_ns(), "msg": message, **fields}), flush=True)

    def terminate(signum, _frame):
        record(
            "SIGTERM received", signal=signum, active=backend._server.observations.active_count()
        )
        stop.set()

    config = FakeBackendConfig(
        backend_id=os.environ["POD_NAME"],
        chunks=tuple(f"token-{i} " for i in range(STREAM_CHUNKS)),
        chunk_delay_ms=STREAM_CHUNK_DELAY_MS,
        health_ready_delay_ms=1000,
        completion_tokens=STREAM_CHUNKS,
    )
    backend = FakeBackend(config, host="0.0.0.0", port=8000).start()
    signal.signal(signal.SIGTERM, terminate)
    record("fake started", backend_id=config.backend_id, generation=os.environ["POD_UID"])
    stop.wait()
    # Stop health admission while allowing already accepted streams to finish.
    backend._server.config = dataclasses.replace(config, healthy=False)
    deadline = time.monotonic() + 130
    while backend._server.observations.active_count() and time.monotonic() < deadline:
        time.sleep(0.02)
    active = backend._server.observations.active_count()
    record("last stream drained", active=active)
    backend.close()
    return int(active != 0)


if __name__ == "__main__":
    raise SystemExit(main())
