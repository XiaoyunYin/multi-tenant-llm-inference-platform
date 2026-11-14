"""Verify a complete public job matrix, selected-case union and real host times."""

import argparse
import hashlib
import json
from pathlib import Path


def verify(reports, jobs, checks):
    if not reports or sorted(r["shard"] for r in reports) != list(range(len(reports))):
        raise ValueError("public_shards:missing_shard")
    if any(r["count"] != len(reports) for r in reports):
        raise ValueError("public_shards:count")
    identities = [name for r in reports for name in r["selected_cases"]]
    digest = hashlib.sha256("\n".join(sorted(identities)).encode()).hexdigest()
    if len(identities) != len(set(identities)) or any(
        r["catalog_sha256"] != digest or r["public_cases"] != len(identities)
        for r in reports
    ):
        raise ValueError("public_shards:union")
    if sorted(j["shard"] for j in jobs) != list(range(len(reports))):
        raise ValueError("public_shards:missing_job")
    if any(j["exit_code"] or not 0 < j["elapsed_s"] < 900 for j in jobs):
        raise ValueError("public_shards:failed_or_15_minute_job")
    if checks["exit_code"] or not 0 < checks["elapsed_s"] < 900:
        raise ValueError("public_shards:failed_or_15_minute_checks_job")
    if any(r["result"]["failures"] or r["result"]["errors"] for r in reports):
        raise ValueError("public_shards:failed_case")
    return {
        "complete": True,
        "selected_cases": len(identities),
        "catalog_sha256": digest,
        "jobs": len(jobs),
        "maximum_job_s": max(j["elapsed_s"] for j in jobs),
        "checks_job_s": checks["elapsed_s"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--jobs", type=Path, required=True)
    parser.add_argument("--checks", type=Path, required=True)
    args = parser.parse_args()
    reports = [
        json.loads(p.read_bytes()) for p in sorted(args.directory.glob("shard-*.json"))
    ]
    result = verify(
        reports,
        json.loads(args.jobs.read_text(encoding="utf-8-sig")),
        json.loads(args.checks.read_text(encoding="utf-8-sig")),
    )
    print(json.dumps(result))


if __name__ == "__main__":
    main()
