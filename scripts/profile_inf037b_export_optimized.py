"""Measure adopted production export on existing 5/10/25% baseline fixtures.

No candidate patches, fixture construction or full native/constrained sizing.
"""

import argparse
import hashlib
import json
from pathlib import Path

import profile_inf037b_export_candidate as driver


def run(raw_root, baseline, work, output):
    driver.run(raw_root, baseline, work, output, [5, 10, 25], optimize=False)
    receipt = json.loads(output.read_bytes())
    receipt["experiment"] = "adopted-production-batched-sync-fresh-hash"
    receipt["baseline_target"] = "300d76230c90a5b5f074e80144a5965cf55cda6d"
    repo = Path(__file__).resolve().parents[1]
    receipt["source_sha256"] = {
        p.relative_to(repo).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in (
            Path(__file__),
            repo / "scripts/profile_inf037b_export.py",
            repo / "scripts/profile_inf037b_export_candidate.py",
            repo / "scripts/time_inf037b_three_attempts.py",
            repo / "python/tests/test_inf037b_collectors.py",
            *sorted((repo / "python/src/inference_platform").glob("*.py")),
        )
    }
    receipt["proof_boundary"] = (
        "local sample scaling and exact baseline artifact comparison; excludes "
        "external durable-store persistence and real network/recovery; not live O_export"
    )
    output.write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("raw-root", "baseline", "work", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    run(args.raw_root, args.baseline, args.work, args.output)
