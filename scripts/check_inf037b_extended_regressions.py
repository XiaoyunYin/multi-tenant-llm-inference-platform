"""Run the full collectors and sanitization regression modules with a receipt."""

import argparse
import hashlib
import importlib
import io
import json
import platform
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python/tests"))

MODULES = (
    "test_inf037b_collectors",
    "test_inf037b_sanitization_regressions",
    "test_evidence_sanitize",
)


def digest(path):
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    input_paths = {
        path.relative_to(ROOT).as_posix(): path
        for path in [
            *sorted((ROOT / "python/src/inference_platform").glob("*.py")),
            *(ROOT / "python/tests" / f"{name}.py" for name in MODULES),
            Path(__file__),
        ]
    }
    rows = []
    start_all = time.monotonic_ns()
    for name in MODULES:
        module = importlib.import_module(name)
        stream = io.StringIO()
        start = time.monotonic_ns()
        result = unittest.TextTestRunner(stream=stream, verbosity=2).run(
            unittest.defaultTestLoader.loadTestsFromModule(module)
        )
        rows.append(
            {
                "module": name,
                "tests": result.testsRun,
                "skips": len(result.skipped),
                "failures": [test.id() for test, _ in result.failures + result.errors],
                "elapsed_ms": (time.monotonic_ns() - start) / 1_000_000,
                "output": stream.getvalue(),
            }
        )
    receipt = {
        "python": platform.python_version(),
        "platform": platform.system(),
        "modules": rows,
        "total_tests": sum(row["tests"] for row in rows),
        "total_skips": sum(row["skips"] for row in rows),
        "total_failures": sum(len(row["failures"]) for row in rows),
        "elapsed_ms": (time.monotonic_ns() - start_all) / 1_000_000,
        "inputs": {name: digest(path) for name, path in sorted(input_paths.items())},
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(receipt, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    for row in rows:
        print(
            f"{row['module']}: {row['tests']} tests, {row['skips']} skips, "
            f"{len(row['failures'])} failures"
        )
        if row["output"]:
            print(row["output"], end="")
    print(
        f"total: {receipt['total_tests']} tests, {receipt['total_skips']} skips, "
        f"{receipt['total_failures']} failures"
    )
    return bool(receipt["total_skips"] or receipt["total_failures"])


if __name__ == "__main__":
    raise SystemExit(main())
