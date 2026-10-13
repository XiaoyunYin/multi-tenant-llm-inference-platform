"""Run observer CPU fixtures in a read-only Linux checkout; no serving launch.

Use the cached tooling image and the documented 2-CPU/6-GiB Docker invocation.
This small fixture campaign is not the registered full-volume rehearsal.
"""

import errno
import json
import resource
import time
import unittest
import uuid
from pathlib import Path


def main():
    started = time.monotonic()
    root = Path(__file__).resolve().parents[1]
    probe = root / ".cache" / ("observer-write-probe-" + uuid.uuid4().hex)
    try:
        with probe.open("xb"):
            pass
    except OSError as exc:
        if exc.errno != errno.EROFS:
            raise
    else:
        probe.unlink()
        raise AssertionError("Expected a read-only filesystem denial")
    suite = unittest.defaultTestLoader.discover(
        str(root / "python/tests"), pattern="*observer*.py"
    )
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print(
        json.dumps(
            {
                "tests": result.testsRun,
                "skips": len(result.skipped),
                "successful": result.wasSuccessful(),
                "readonly_denied": True,
                "elapsed_s": time.monotonic() - started,
                "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
            }
        )
    )
    return int(not result.wasSuccessful())


if __name__ == "__main__":
    raise SystemExit(main())
