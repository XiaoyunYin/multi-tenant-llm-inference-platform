"""Continuous redacted fake publisher capture in a separately sampled worker."""

import argparse
import json
import time

from .kv_event_capture import event_observations
from .time_budget import deadline_urlopen


def capture(endpoint, output, stop):
    after = 0
    with output.open("w", encoding="utf-8", newline="\n") as stream:
        while not stop.exists():
            with deadline_urlopen(f"{endpoint}?after={after}&duration=0.5", timeout=3) as response:
                for raw in response:
                    if not raw.startswith(b"data: "):
                        continue
                    batch = json.loads(raw[6:])
                    after = max(after, batch["sequence"] + 1)
                    rows = event_observations(
                        batch["sequence"],
                        batch["events"],
                        observed_monotonic_ns=batch.get(
                            "emitted_monotonic_ns", time.perf_counter_ns()
                        ),
                        batch_timestamp_s=batch.get("batch_timestamp_s"),
                    )
                    for row in rows:
                        stream.write(json.dumps(row) + "\n")
                    stream.flush()


def main():
    from pathlib import Path

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--stop", type=Path, required=True)
    args = parser.parse_args()
    capture(args.endpoint, args.output, args.stop)


if __name__ == "__main__":
    main()
