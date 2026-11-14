"""Validate and promote the Round 265/266 offline R361-R365 evidence packet."""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = "docs/evidence/m5-package-b4b-r361-r363"
NAMES = (
    "setup-linux.json",
    "fitness-core-linux.json",
    "regression-linux.json",
    "lifecycle-validation.json",
    "integration-linux.json",
    "terminal-linux.json",
    "extended-regressions-linux.json",
    "export-memory-linux.json",
    "setup-mutations-linux.json",
)
COUNTS = {
    "setup-linux.json": 62,
    "fitness-core-linux.json": 18,
    "regression-linux.json": 231,
    "lifecycle-validation.json": 60,
    "integration-linux.json": 11,
    "terminal-linux.json": 18,
}
MODULES = {
    "fitness": "python/src/inference_platform/inf037b_setup_fitness.py",
    "observations": "python/src/inference_platform/inf037b_setup_observations.py",
    "setup": "python/src/inference_platform/inf037b_setup.py",
}
TEST_MODULES = (
    "test_inf037b_fitness",
    "test_inf037b_observations",
    "test_inf037b_setup",
)


def normalized(data):
    return data.replace(b"\r\n", b"\n")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def blob(revision, path):
    spec = f":{path}" if revision == "index" else f"{revision}:{path}"
    return subprocess.check_output(["git", "show", spec], cwd=ROOT)


def inspect(directory, revision):
    source_inputs, summaries = {}, {}

    def check_inputs(name, inputs):
        for path, expected in inputs.items():
            assert path not in source_inputs or source_inputs[path] == expected, (
                "inconsistent receipt input",
                name,
                path,
            )
            assert digest(normalized(blob(revision, path))) == expected, (
                "Git blob mismatch",
                name,
                path,
            )
            source_inputs[path] = expected

    for name in NAMES:
        receipt = json.loads((directory / name).read_bytes())
        if name in COUNTS:
            assert receipt["tests"] == COUNTS[name], name
            assert receipt["skips"] == 0 and not receipt["failures"], name
            assert receipt["platform"] == "Linux" and receipt["python"] == "3.12.7", (
                name
            )
            check_inputs(name, receipt["inputs"])
            summaries[name] = {
                key: receipt[key]
                for key in ("tests", "skips", "failures", "elapsed_ms")
            }
        elif name == "extended-regressions-linux.json":
            assert receipt["platform"] == "Linux" and receipt["python"] == "3.12.7"
            assert receipt["total_tests"] == 92
            assert receipt["total_skips"] == 0 and receipt["total_failures"] == 0
            modules = {row["module"]: row for row in receipt["modules"]}
            expected_modules = {
                "test_inf037b_collectors": 84,
                "test_inf037b_sanitization_regressions": 6,
                "test_evidence_sanitize": 2,
            }
            assert set(modules) == set(expected_modules)
            for module, count in expected_modules.items():
                row = modules[module]
                assert row["tests"] == count and row["skips"] == 0
                assert not row["failures"]
            check_inputs(name, receipt["inputs"])
            summaries[name] = {
                "modules": {
                    module: {
                        "tests": row["tests"],
                        "skips": row["skips"],
                        "failures": row["failures"],
                        "elapsed_ms": row["elapsed_ms"],
                    }
                    for module, row in modules.items()
                },
                "total_tests": receipt["total_tests"],
                "total_skips": receipt["total_skips"],
                "total_failures": receipt["total_failures"],
                "elapsed_ms": receipt["elapsed_ms"],
            }
        elif name == "export-memory-linux.json":
            assert receipt["platform"] == "Linux" and receipt["python"] == "3.12.7"
            assert receipt["passed"] is True
            small, large = receipt["measurements"]
            assert (small["payload_target_mb"], large["payload_target_mb"]) == (10, 100)
            assert 2400 <= small["average_jsonl_bytes_per_row"] <= 2600
            assert 2400 <= large["average_jsonl_bytes_per_row"] <= 2600
            assert receipt["whole_row_seen_mutant_rejected"] is True
            assert receipt["peak_rss_growth_10_to_100_mb_bytes"] < 64 * 1024 * 1024
            assert receipt["growth_bytes_per_added_row_10_to_100_mb"] < 1500
            assert receipt["state_file_growth_bytes"] <= 1024
            assert large["peak_rss_growth_bytes"] > small["peak_rss_growth_bytes"] > 0
            assert (
                large["state_file_bytes"] - small["state_file_bytes"]
                == receipt["state_file_growth_bytes"]
            )
            check_inputs(name, receipt["inputs"])
            summaries[name] = {
                "measurements": receipt["measurements"],
                "peak_rss_growth_10_to_100_mb_bytes": receipt[
                    "peak_rss_growth_10_to_100_mb_bytes"
                ],
                "growth_bytes_per_added_row_10_to_100_mb": receipt[
                    "growth_bytes_per_added_row_10_to_100_mb"
                ],
                "growth_bytes_per_added_archive_byte_10_to_100_mb": receipt[
                    "growth_bytes_per_added_archive_byte_10_to_100_mb"
                ],
                "whole_row_seen_mutant_rejected": True,
                "state_file_growth_bytes": receipt["state_file_growth_bytes"],
                "passed": receipt["passed"],
            }
        else:
            assert name == "setup-mutations-linux.json"
            assert receipt["complete"] is True
            assert receipt["baseline"]["tests"] >= 3
            assert receipt["baseline"]["skips"] == 0
            assert not receipt["baseline"]["failures"]
            assert receipt["runner_asserted_imported_mutant_identity"] is True
            assert (
                receipt["mutation"]
                == "each require/exact call statement replaced individually with pass"
            )
            mutants = receipt["mutants"]
            assert len(mutants) == 313
            assert mutants and len({row["site_id"] for row in mutants}) == len(mutants)
            for row in mutants:
                assert row["registered_candidates"], row["site_id"]
                if row["killed"]:
                    killer_id = row["killer_test"].split(" (", 1)[0]
                    assert killer_id in row["registered_candidates"]
                    assert killer_id in row["attempted"]
                elif row["equivalent_reason"] is None:
                    assert row in receipt["unexplained_survivors"], row["site_id"]
            assert receipt["survivors"] == [] and receipt["unexplained_survivors"] == []
            assert len(receipt["equivalent"]) == receipt["equivalent_count"]
            assert all(
                row["equivalent_reason"].strip() for row in receipt["equivalent"]
            )
            overlaps = [row["site_id"] for row in receipt["equivalent"] if row["killed"]]
            assert receipt["equivalent_killed_overlaps"] == overlaps
            assert overlaps == ["setup:__call__:setup:readiness_deadline#1"]
            assert receipt["killed"] + receipt["equivalent_count"] == len(mutants)
            for label, path in MODULES.items():
                expected = receipt["source_lf_sha256"][label]
                check_inputs(name, {path: expected})
            for test_name in TEST_MODULES:
                path = f"python/tests/{test_name}.py"
                check_inputs(name, {path: receipt["test_lf_sha256"][test_name]})
            check_inputs(
                name,
                {
                    "scripts/check_inf037b_setup_mutations.py": receipt[
                        "harness_lf_sha256"
                    ]
                },
            )
            summaries[name] = {
                "baseline": receipt["baseline"],
                "sites": len(mutants),
                "killed": receipt["killed"],
                "equivalent": receipt["equivalent_count"],
                "equivalent_killed_overlaps": overlaps,
                "unexplained_survivors": len(receipt["unexplained_survivors"]),
                "runner_asserted_imported_mutant_identity": True,
            }

    check_inputs(
        "packet tooling",
        {
            "scripts/check_inf037b_r361_r363_receipts.py": digest(
                normalized(
                    blob(revision, "scripts/check_inf037b_r361_r363_receipts.py")
                )
            )
        },
    )
    return {
        "revision": revision,
        "inputs": source_inputs,
        "summaries": summaries,
        "Git_blob_inputs_verified": True,
        "paid_ready": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=ROOT / PACKET)
    parser.add_argument(
        "--revision",
        default="index",
        help="Use index before commit or HEAD after commit",
    )
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    revision = args.revision
    result = inspect(args.directory, revision)
    if args.write:
        (args.directory / "receipt-inspection.json").write_text(
            json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n"
        )
        names = (*NAMES, "receipt-inspection.json")
        (args.directory / "SHA256SUMS").write_text(
            "".join(
                digest((args.directory / name).read_bytes()) + "  " + name + "\n"
                for name in sorted(names)
            ),
            encoding="utf-8",
            newline="\n",
        )
    else:
        for line in (args.directory / "SHA256SUMS").read_text().splitlines():
            expected, name = line.split("  ")
            assert digest(blob(revision, f"{PACKET}/{name}")) == expected, name
    print(
        json.dumps(
            {
                "source_inputs": len(result["inputs"]),
                "receipts": len(NAMES) + 1,
                "summaries": result["summaries"],
            }
        )
    )


if __name__ == "__main__":
    main()
