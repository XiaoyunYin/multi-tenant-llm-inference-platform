"""Named mutation controls for changed production refusal/durability code only."""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = "inf037b_export_runtime"
SYNC = "test_operations_sync_every_file_and_directory_once_before_return"
FAIL = "test_operations_propagate_file_and_directory_durability_failure"
REPORT = "test_report_fresh_bytes_spec_and_mutable_result"
VERIFY = "test_verify_fresh_hash_inventory_and_known_files"
MUTANTS = {
    "ordinary_write_barrier": (
        "inf037b_archive",
        "if not deferred:",
        "if False:",
        "test_unbatched_write_is_immediately_synced",
    ),
    "file_barrier": (RUNTIME, "os.fsync(handle.fileno())", "None", FAIL),
    "directory_barrier": (RUNTIME, "os.fsync(fd)", "None", FAIL),
    "operation_barrier": (
        RUNTIME,
        "            synchronize(files, directories)",
        "            None",
        FAIL,
    ),
    "file_tracking": (RUNTIME, "batch[0].add(path)", "None", FAIL),
    "parent_tracking": (RUNTIME, "batch[1].add(path.parent)", "None", FAIL),
    "created_directory_tracking": (
        RUNTIME,
        "batch[1].update((path, path.parent))",
        "None",
        SYNC,
    ),
    "cache_fresh_inventory": (RUNTIME, "saved[0] == before", "True", REPORT),
    "cache_verify_inventory": (RUNTIME, "saved[0] == before", "True", VERIFY),
    "cache_post_hash_refusal": (
        RUNTIME,
        "if before != observe():",
        "if False:",
        "test_input_change_during_computation_refuses_and_is_not_saved",
    ),
    "symlink_refusal": (
        RUNTIME,
        "if path.is_symlink():",
        "if False:",
        "test_cache_scope_exception_bound_and_symlink_refusal",
    ),
    "known_inventory_refusal": (
        "inf037b_archive",
        "if known_files != current:",
        "if False:",
        VERIFY,
    ),
    "report_spec_key": (
        "inf037b_campaign",
        "sha(encode(self.spec))",
        '"constant"',
        REPORT,
    ),
    "report_journal_refresh": (
        "inf037b_campaign",
        '            self.journal = AttemptController(self.root / "attempts.jsonl")',
        "            pass",
        REPORT,
    ),
    "report_jsonl_inventory": (
        RUNTIME,
        '*sorted((root / "raw").glob("*.jsonl"))',
        '*sorted((root / "raw").glob("*.receipt.json"))',
        REPORT,
    ),
    "sanitize_durability_scope": (
        "inf037b_packet",
        "@batched_durability\ndef sanitized_sources",
        "def sanitized_sources",
        SYNC,
    ),
    "materialize_durability_scope": (
        "inf037b_campaign",
        "@batched_durability\ndef materialize_bundle",
        "def materialize_bundle",
        SYNC,
    ),
    "archive_seal_barrier": (
        "inf037b_archive",
        "        barrier()\n",
        "        pass\n",
        "test_seal_syncs_archived_files_and_folders_before_manifest",
    ),
}


def check(package_root, module, killer):
    code = """
import importlib, io, json, pathlib, sys, unittest
module = importlib.import_module("inference_platform." + sys.argv[1])
assert pathlib.Path(module.__file__).resolve().is_relative_to(pathlib.Path(sys.argv[2]).resolve())
tests = importlib.import_module("test_inf037b_export_runtime")
suite = unittest.TestSuite([tests.ExportRuntimeTests(sys.argv[3])])
result = unittest.TextTestRunner(stream=io.StringIO()).run(suite)
print(json.dumps(dict(tests=result.testsRun, failures=len(result.failures),
 errors=len(result.errors), skips=len(result.skipped), module_identity_confirmed=True)))
"""
    environment = {
        **os.environ,
        "PYTHONPATH": os.pathsep.join((str(package_root), str(ROOT / "python/tests"))),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    result = subprocess.run(
        [sys.executable, "-c", code, module, str(package_root), killer],
        capture_output=True,
        text=True,
        env=environment,
        check=True,
        timeout=60,
    )
    return json.loads(result.stdout)


def run():
    results = []
    with tempfile.TemporaryDirectory() as directory:
        package_root = Path(directory)
        shutil.copytree(
            ROOT / "python/src/inference_platform", package_root / "inference_platform"
        )
        for name, (module, before, after, killer) in MUTANTS.items():
            path = package_root / "inference_platform" / (module + ".py")
            original = path.read_text()
            if original.count(before) != 1:
                raise RuntimeError("nonunique mutation site: " + name)
            baseline = check(package_root, module, killer)
            if baseline["failures"] or baseline["errors"] or baseline["skips"]:
                raise RuntimeError("unmodified killer failed: " + name)
            try:
                path.write_text(original.replace(before, after, 1))
                mutant = check(package_root, module, killer)
            finally:
                path.write_text(original)
            if mutant["failures"] != 1 or mutant["errors"] or mutant["skips"]:
                raise RuntimeError(
                    "not killed by assertion: " + name + " " + str(mutant)
                )
            results.append(
                {"site": name, "killer": killer, "baseline": baseline, "mutant": mutant}
            )
    return {
        "schema": "inf037b-production-export-mutations-v1",
        "sites": len(results),
        "killed": len(results),
        "survivors": 0,
        "results": results,
        "source_sha256": {
            p.relative_to(ROOT).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in (
                Path(__file__),
                ROOT / "python/tests/test_inf037b_export_runtime.py",
                *(
                    ROOT / "python/src/inference_platform" / (name + ".py")
                    for name in sorted({value[0] for value in MUTANTS.values()})
                ),
            )
        },
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    receipt = run()
    args.output.write_text(json.dumps(receipt, indent=2) + "\n")
    print(
        f"{receipt['killed']}/{receipt['sites']} killed; every unmodified killer passes"
    )
