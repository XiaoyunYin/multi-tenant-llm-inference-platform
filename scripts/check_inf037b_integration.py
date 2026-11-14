"""Receipt for offline accepted-4a/durable-lifecycle composition; no live I/O."""

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

from check_inf037b_terminal import FILES as TERMINAL_FILES

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python/tests"))
FILES = TERMINAL_FILES + [
    "python/src/inference_platform/inf037b_integration.py",
    "python/tests/test_inf037b_integration.py",
    "python/tests/inf037b_integration_worker.py",
    "scripts/check_inf037b_integration.py",
    "python/tests/test_inf037b_controller.py",
    "scripts/check_inf037b_controller_mutations.py",
    "scripts/check_inf037b_placement_mutations.py",
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    import test_inf037b_integration as tests

    stream = io.StringIO()
    start = time.monotonic_ns()
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
        "elapsed_ms": (time.monotonic_ns() - start) / 1_000_000,
        "output": stream.getvalue(),
        "cases": tests.CASES,
        "paid_ready": False,
        "basis": "real accepted 4a filesystem ports/authority and durable LifecycleDriver; fake persistent provider, creation, phases and terminal transports; real SIGKILL at every durable start",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(stream.getvalue())
    return (
        not result.wasSuccessful()
        or bool(result.skipped)
        or platform.system() != "Linux"
    )


if __name__ == "__main__":
    raise SystemExit(main())
