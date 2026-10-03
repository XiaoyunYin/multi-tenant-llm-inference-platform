"""Repeat the complete transport test class with reproducibly varied wall epochs."""

import argparse
import hashlib
import io
import json
import platform
import random
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import patch


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=200)
    parser.add_argument("--seed", type=int, default=48)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.iterations < 1:
        parser.error("--iterations must be positive")
    if args.output.exists():
        parser.error("--output must be a new file")

    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root / "python/tests"))
    from test_stage_c_transport import RemoteTransportTest

    rng = random.Random(args.seed)
    started = time.perf_counter()
    rows = []
    for iteration in range(1, args.iterations + 1):
        # The simulated monotonic bases are fixed. Vary the remaining wall base,
        # including its fractional second; real process polling keeps its clock.
        wall = rng.uniform(1_000_000_000.0, 2_000_000_000.0)
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(RemoteTransportTest)
        diagnostics = io.StringIO()
        with patch("time.time", return_value=wall):
            result = unittest.TextTestRunner(stream=diagnostics, verbosity=0).run(suite)
        rows.append(
            {
                "iteration": iteration,
                "wall_base_unix_s": wall,
                "tests": result.testsRun,
                "failures": len(result.failures),
                "errors": len(result.errors),
                "skips": len(result.skipped),
            }
        )
        if not result.wasSuccessful() or result.skipped:
            print(diagnostics.getvalue(), file=sys.stderr)
            break
        if iteration % 25 == 0:
            print(
                f"Transport class repetitions: {iteration}/{args.iterations}",
                flush=True,
            )

    report = {
        "schema_version": 1,
        "class": "test_stage_c_transport.RemoteTransportTest",
        "python": platform.python_version(),
        "platform": platform.system(),
        "seed": args.seed,
        "requested_iterations": args.iterations,
        "completed_iterations": len(rows),
        "tests": sum(row["tests"] for row in rows),
        "failures": sum(row["failures"] for row in rows),
        "errors": sum(row["errors"] for row in rows),
        "skips": sum(row["skips"] for row in rows),
        "elapsed_seconds": round(time.perf_counter() - started, 3),
        "simulated_monotonic_base_s": 1_000_000.0,
        "remaining_base_variation": "seeded uniform wall epochs [1e9, 2e9], fractional seconds",
        "real_process_polling": "unmodified live perf_counter; each repetition reaps its children",
        "normalized_test_source_sha256": hashlib.sha256(
            (root / "python/tests/test_stage_c_transport.py")
            .read_bytes()
            .replace(b"\r\n", b"\n")
        ).hexdigest(),
        "iterations": rows,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    passed = len(rows) == args.iterations and not any(
        report[key] for key in ("failures", "errors", "skips")
    )
    print(
        json.dumps({key: value for key, value in report.items() if key != "iterations"})
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
