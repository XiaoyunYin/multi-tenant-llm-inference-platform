"""Pinned offline export/cleanup and snapshot-rehearsal receipts; no live adapter."""

import argparse
import contextlib
import hashlib
import io
import json
import platform
import sys
import time
import unittest
from pathlib import Path

from check_inf037b_lifecycle import FILES as LIFECYCLE_FILES

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python/tests"))

FILES = LIFECYCLE_FILES + [
    "python/src/inference_platform/inf037b_terminal.py",
    "python/tests/test_inf037b_terminal.py",
    "scripts/check_inf037b_terminal.py",
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    import test_inf037b_terminal as tests

    stream = io.StringIO()
    started = time.monotonic_ns()
    with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
        result = unittest.TextTestRunner(stream=stream, verbosity=2).run(
            unittest.defaultTestLoader.loadTestsFromModule(tests)
        )
    receipt = {
        "inputs": {
            p: hashlib.sha256(
                (ROOT / p).read_bytes().replace(b"\r\n", b"\n")
            ).hexdigest()
            for p in FILES
        },
        "python": platform.python_version(),
        "platform": platform.system(),
        "tests": result.testsRun,
        "skips": len(result.skipped),
        "failures": [t.id() for t, _ in result.failures + result.errors],
        "elapsed_ms": (time.monotonic_ns() - started) / 1_000_000,
        "output": stream.getvalue(),
        "cases": tests.CASES,
        "paid_ready": False,
        "basis": "offline backend; accepted 4a capacity port uses fake authority transport; real durable-store integration on Linux; isolated-snapshot cleanup rehearsal",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(stream.getvalue())
    return not result.wasSuccessful() or bool(result.skipped)


if __name__ == "__main__":
    raise SystemExit(main())
