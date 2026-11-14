"""Mandatory $0 kind-harness checks: pinned kubectl/fake API and scripted walk."""

import argparse
import json
from pathlib import Path

from inference_platform.package_a_cloud import save, sha
from package_a_kind_api import check_api
from package_a_kind_walk import coverage


def check(output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    api = check_api(output / "api")
    walk = coverage(output / "walk")
    result = {
        "schema": "package-a-kind-no-cluster-v1",
        "complete": api["complete"]
        and walk["coverage_percent"] == 100
        and walk["line_coverage_percent"] == 100,
        "billable_actions": 0,
        "skipped_tests": 0,
        "kubectl_sha256": api["kubectl_sha256"],
        "coverage_percent": walk["coverage_percent"],
        "line_coverage_percent": walk["line_coverage_percent"],
        "rehearsal_sha256": walk["source_sha256"],
        "files_sha256": {
            path.relative_to(output).as_posix(): sha(path)
            for path in sorted(output.rglob("*"))
            if path.is_file()
        },
    }
    save(output / "receipt.json", result)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = check(args.output)
    print(
        json.dumps(
            {
                "complete": result["complete"],
                "coverage_percent": result["coverage_percent"],
            }
        )
    )
