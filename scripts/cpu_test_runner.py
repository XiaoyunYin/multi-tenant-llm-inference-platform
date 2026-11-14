"""Unittest module timing and immediate failure diagnostics for bounded stages."""

import faulthandler
import json
import time
import traceback
import unittest
from pathlib import Path


def open_descriptor_count():
    """Linux process descriptors; unsupported platforms are explicit nulls."""
    directory = Path("/proc/self/fd")
    return len(list(directory.iterdir())) if directory.is_dir() else None


class ProgressResult(unittest.TextTestResult):
    def __init__(self, *args, **kw):
        super().__init__(*args, **kw)
        self.passed = []

    def addSuccess(self, test):
        self.passed.append(test.id())
        super().addSuccess(test)

    def immediate(self, test, err):
        self.stream.writeln("IMMEDIATE " + test.id())
        self.stream.writeln("".join(traceback.format_exception(*err)))
        self.stream.flush()

    def addError(self, test, err):
        super().addError(test, err)
        self.immediate(test, err)

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.immediate(test, err)

    def addSubTest(self, test, subtest, err):
        super().addSubTest(test, subtest, err)
        if err is not None:
            self.immediate(subtest, err)


class ModuleSuite(unittest.TestSuite):
    def __init__(self, name, suite):
        super().__init__([suite])
        self.name = name

    def run(self, result, debug=False):
        start = time.monotonic()
        counts = lambda: {  # noqa: E731
            "run": result.testsRun,
            "passed": len(getattr(result, "passed", [])),
            "skipped": len(result.skipped),
            "failures": len(result.failures),
            "errors": len(result.errors),
        }
        before = counts()
        print(json.dumps({"module_start": self.name, "monotonic_s": start}), flush=True)
        try:
            return super().run(result, debug)
        finally:
            print(
                json.dumps(
                    {
                        "module_finish": self.name,
                        "duration_s": time.monotonic() - start,
                        "open_descriptors": open_descriptor_count(),
                        "tests": {
                            key: value - before[key] for key, value in counts().items()
                        },
                    }
                ),
                flush=True,
            )


def run_modules(names, *, dump_after=None):
    suite = unittest.TestSuite(
        ModuleSuite(n, unittest.defaultTestLoader.loadTestsFromName(n)) for n in names
    )
    faulthandler.enable()
    if dump_after is not None:
        faulthandler.dump_traceback_later(dump_after)
    try:
        result = unittest.TextTestRunner(verbosity=2, resultclass=ProgressResult).run(
            suite
        )
    finally:
        if dump_after is not None:
            faulthandler.cancel_dump_traceback_later()
    from inference_platform.package_a_cpu_validation import result_record

    print(json.dumps({"cpu_result": result_record(result, result.passed)}), flush=True)
    return result
