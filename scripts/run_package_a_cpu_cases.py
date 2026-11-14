"""Fixed host-case launcher; the manifest never supplies commands."""

import argparse
import sys
from pathlib import Path

from cpu_test_runner import run_modules
from inference_platform.package_a_cpu_validation import (
    CGROUP_CASE,
    READONLY_CASE,
    READONLY_RACE_CASE,
    HOST_MODULES,
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("before", "after", "cgroup"), required=True)
    args = parser.parse_args()
    sys.path.insert(0, str(Path("python/tests").resolve()))
    names = (
        HOST_MODULES
        if args.phase == "before"
        else (
            (CGROUP_CASE, READONLY_CASE, READONLY_RACE_CASE)
            if args.phase == "cgroup"
            else ("test_inf037b_transfer.MinioRestartReadTests",)
        )
    )
    result = run_modules(names, dump_after=1770 if args.phase == "before" else 270)
    return int(not result.wasSuccessful())


if __name__ == "__main__":
    raise SystemExit(main())
