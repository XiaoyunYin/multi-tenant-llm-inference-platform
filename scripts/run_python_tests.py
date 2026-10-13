"""Run deterministic whole-module shards whose union is unittest discovery."""

import argparse
import json
import sys
import time
import unittest
from pathlib import Path


def modules(directory, index, count):
    if count <= 0 or not 0 <= index < count:
        raise ValueError("invalid shard")
    return sorted(Path(directory).glob("test*.py"))[index::count]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index", type=int, default=0)
    parser.add_argument("--count", type=int, default=1)
    args = parser.parse_args()
    directory = Path("python/tests").resolve()
    sys.path.insert(0, str(directory))
    selected = modules(directory, args.index, args.count)
    suite = unittest.TestSuite(
        unittest.defaultTestLoader.loadTestsFromName(path.stem) for path in selected
    )
    print(json.dumps({"shard": args.index, "count": args.count,
                      "modules": [p.name for p in selected], "cases": suite.countTestCases()}), flush=True)
    started = time.monotonic()
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print(json.dumps({"shard": args.index, "duration_s": time.monotonic() - started,
                      "run": result.testsRun, "skipped": len(result.skipped)}), flush=True)
    return int(not result.wasSuccessful())


if __name__ == "__main__":
    raise SystemExit(main())
