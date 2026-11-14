"""Pinned offline setup producer/collector/ProcessCalls receipts; no live I/O."""

import argparse
import contextlib
import hashlib
import importlib
import io
import json
import platform
import sys
import time
import unittest
from pathlib import Path

from check_inf037b_integration import FILES as INTEGRATION_FILES

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python/tests"))
FILES = sorted(
    set(
        INTEGRATION_FILES
        + [
            str(p.relative_to(ROOT)).replace("\\", "/")
            for pattern in ("python/src/inference_platform/inf037b_*.py",)
            for p in ROOT.glob(pattern)
        ]
        + [
            "python/tests/inf037b_setup_fixture.py",
            "python/tests/inf037b_setup_worker.py",
            "python/tests/inf037b_fitness_fixture.py",
            "python/tests/test_inf037b_fitness.py",
            "python/tests/test_inf037b_observations.py",
            "python/tests/inf037b_observations_fixture.py",
            "python/tests/test_inf037b_setup.py",
            "python/tests/test_inf037b_collectors.py",
            "python/tests/test_inf037b_live.py",
            "python/tests/test_inf037b_startup.py",
            "python/tests/test_inf037b_core.py",
            "scripts/check_inf037b_setup.py",
            "docs/INF037B_RESOLVER_V4.md",
            "docs/INF037B_SETUP_V4.md",
            "docs/INF037B_FITNESS_V4.md",
            "docs/INF037B_OBSERVATIONS_V4.md",
            "docs/INF037B_REGISTRATION_V4_R315.md",
            "python/tests/fixtures/inf037b_gateway_sse.json",
        ]
    )
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--suite", choices=("setup", "collectors", "fitness-core"), default="setup"
    )
    args = parser.parse_args()
    names = (
        ["test_inf037b_setup", "test_inf037b_fitness", "test_inf037b_observations"]
        if args.suite == "setup"
        else ["test_inf037b_core", "test_inf037b_live", "test_inf037b_startup"]
    )
    modules = [importlib.import_module(name) for name in names]
    if args.suite == "fitness-core":
        suite = unittest.defaultTestLoader.loadTestsFromNames(
            [
                "test_inf037b_core.ArchiveTests.test_registration_v4_binding_and_v3_preservation",
                "test_inf037b_collectors.SourceTests",
                "test_inf037b_collectors.ClockTests",
                "test_inf037b_collectors.RequestTests",
                "test_inf037b_collectors.AdmissionTests",
                "test_inf037b_startup",
            ]
        )
    elif args.suite == "collectors":
        # The actual gateway/Redis E2E has its own Package A runner and needs
        # its built binary/isolated Redis. Select the offline adapter class,
        # preserving every accepted test rather than invoking its skip gate.
        suite = unittest.TestSuite(
            [
                unittest.defaultTestLoader.loadTestsFromModule(modules[0]),
                unittest.defaultTestLoader.loadTestsFromTestCase(
                    modules[1].AdapterTests
                ),
                unittest.defaultTestLoader.loadTestsFromModule(modules[2]),
            ]
        )
    else:
        suite = unittest.TestSuite(
            unittest.defaultTestLoader.loadTestsFromModule(m) for m in modules
        )
    stream = io.StringIO()
    start = time.monotonic_ns()
    with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
        result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
    receipt = {
        "inputs": {
            p: hashlib.sha256(
                (ROOT / p).read_bytes().replace(b"\r\n", b"\n")
            ).hexdigest()
            for p in FILES
        },
        "python": platform.python_version(),
        "platform": platform.system(),
        "suite": args.suite,
        "excluded_external_suite": "test_inf037b_live.GatewayRedisEndToEnd: requires built gateway and isolated Redis; separate Package A check"
        if args.suite == "collectors"
        else None,
        "tests": result.testsRun,
        "skips": len(result.skipped),
        "failures": [t.id() for t, _ in result.failures + result.errors],
        "elapsed_ms": (time.monotonic_ns() - start) / 1_000_000,
        "output": stream.getvalue(),
        "cases": sum((getattr(m, "CASES", []) for m in modules), [])
        if args.suite == "setup"
        else [],
        "paid_ready": False,
        "basis": "synthetic immutable raw setup streams through accepted collectors, resolver and real ProcessCalls/LifecycleDriver; actual file/directory durable store on Linux; fake creation and terminal transports; no live O_i claim",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(receipt, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    print(stream.getvalue())
    return not result.wasSuccessful() or bool(result.skipped)


if __name__ == "__main__":
    raise SystemExit(main())
