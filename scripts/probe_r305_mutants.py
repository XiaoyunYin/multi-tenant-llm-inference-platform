"""Require the five Round 229 sanitizer mutants to fail default regressions."""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from inference_platform.package_a_cloud import save, utc

ROOT = Path(__file__).resolve().parents[1]
TEST = "test_inf037b_sanitization_regressions.py"
MUTANTS = {
    "nested_boundary_vocabulary": (
        "inf037b_sources.py",
        "EXTRA_PAYLOAD_KEYS = TOP_LEVEL_EXTRA_KEYS | BOUNDARY_KEYS",
        "EXTRA_PAYLOAD_KEYS = TOP_LEVEL_EXTRA_KEYS",
    ),
    "remaining_reservations": (
        "inf037b_campaign.py",
        '            "remaining_reservations",\n',
        "",
    ),
    "request_ids": (
        "inf037b_campaign.py",
        '            "request_ids",\n',
        "",
    ),
    "after_first_content": (
        "inf037b_campaign.py",
        '            "after_first_content",\n',
        "",
    ),
    "unscheduled_request": (
        "inf037b_campaign.py",
        '            "unscheduled_request",\n',
        "",
    ),
}


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def probe(output):
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    source_root = ROOT / "python/src/inference_platform"
    results = {}
    for name, (filename, before, after) in MUTANTS.items():
        target = output / name / "src/inference_platform"
        target.parent.mkdir(parents=True)
        shutil.copytree(source_root, target)
        module = target / filename
        original = module.read_text(encoding="utf-8")
        if original.count(before) != 1:
            raise ValueError("mutation_point_missing_or_ambiguous:" + name)
        mutated = original.replace(before, after, 1)
        module.write_text(mutated, encoding="utf-8", newline="\n")
        env = {
            **os.environ,
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": os.pathsep.join(
                (
                    str(target.parent),
                    str(ROOT / "python/tests"),
                    os.environ.get("PYTHONPATH", ""),
                )
            ),
        }
        log = output / f"{name}.log"
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "unittest",
                "discover",
                "-s",
                str(ROOT / "python/tests"),
                "-p",
                TEST,
                "-v",
            ],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=120,
        )
        log.write_bytes(result.stdout)
        text = result.stdout.decode("utf-8", errors="replace")
        if result.returncode == 0 or "FAILED" not in text:
            raise AssertionError("default_regression_did_not_kill_mutant:" + name)
        results[name] = {
            "mutated_file": filename,
            "mutated_source_sha256": sha(module),
            "default_test_file": TEST,
            "exit_code": result.returncode,
            "killed": True,
            "log_path": log.name,
            "log_sha256": sha(log),
            "failed_test": next(
                (
                    line.split(" (", 1)[0]
                    for line in text.splitlines()
                    if line.startswith("FAIL:") or line.startswith("ERROR:")
                ),
                None,
            ),
        }
    receipt = {
        "schema": "r305-default-mutant-probe-v1",
        "utc": utc(),
        "source_head": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
        "test_command": f"{sys.executable} -m unittest discover -s python/tests -p {TEST} -v",
        "default_test_skips": 0,
        "mutants": results,
        "all_killed": len(results) == len(MUTANTS)
        and all(v["killed"] for v in results.values()),
    }
    save(output / "receipt.json", receipt)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    receipt = probe(args.output)
    print(
        json.dumps(
            {"all_killed": receipt["all_killed"], "mutants": len(receipt["mutants"])}
        )
    )


if __name__ == "__main__":
    main()
