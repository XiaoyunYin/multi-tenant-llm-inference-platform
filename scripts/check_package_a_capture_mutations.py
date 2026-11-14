"""DEC-086 changed refusal controls only; isolated copies, named assertion killers."""

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
CAPTURE = "python/src/inference_platform/package_a_capture.py"
CLOUD = "python/src/inference_platform/package_a_cloud.py"
OPERATOR = "python/src/inference_platform/package_a_operator.py"
SIZING = "scripts/size_inf037b_sanitized_export.py"
PREFLIGHT = "scripts/package_a_local_preflight.py"
TEST = "test_package_a_capture.CaptureTests."
SIZING_TEST = "test_package_a_capture_sizing.SizingCaptureTests."
REUSE = TEST + "test_native_reuse_rejects_each_unbound_receipt_field"
MUTANTS = {
    "linux_e2e_runtime": (
        OPERATOR,
        'e2e.get("runtime") != "linux-container"',
        "False",
        "test_package_a_linux_e2e.LinuxE2ETests.test_runtime_refuses_each_missing_or_wrong_binding",
    ),
    "linux_e2e_log_bytes": (
        OPERATOR,
        'root not in path.parents\n            or not path.is_file()\n            or sha(path) != evidence.get("log_sha256")',
        "False",
        "test_package_a_linux_e2e.LinuxE2ETests.test_changed_log_refuses",
    ),
    "linux_e2e_binary_bytes": (
        OPERATOR,
        'root not in binary.parents\n        or not binary.is_file()\n        or sha(binary) != e2e["build"]["binary_sha256"]',
        "False",
        "test_package_a_linux_e2e.LinuxE2ETests.test_changed_binary_refuses",
    ),
    "linux_e2e_cleanup": (
        PREFLIGHT,
        'if not evidence["container_removed"]:',
        "if False:",
        "test_package_a_linux_e2e.LinuxE2ETests.test_cleanup_remaining_container_refuses",
    ),
    "runner_native_receipt": (
        CLOUD,
        'if name == "native" and "capture" in self.manifest["checks"]:\n                native_path',
        "if False:\n                native_path",
        TEST + "test_runner_native_refuses_changed_receipt_hash",
    ),
    "runner_capture_image_readiness": (
        CLOUD,
        'elif name not in {"native", "capture"} and not images_ready:',
        'elif name != "native" and not images_ready:',
        TEST + "test_success_order_prepares_images_only_after_capture_and_native",
    ),
    "stage_copy_hash": (
        CAPTURE,
        "staged == files and rows == expected_rows",
        "rows == expected_rows",
        TEST + "test_staging_records_hashes_rows_bytes_and_detects_bad_copy",
    ),
    "stage_row_count": (
        CAPTURE,
        "staged == files and rows == expected_rows",
        "staged == files",
        TEST + "test_staging_records_hashes_rows_bytes_and_detects_bad_copy",
    ),
    "stage_refusal": (
        CAPTURE,
        'if staging.get("verified") is not True:',
        "if False:",
        TEST + "test_staging_unverified_refuses_before_any_source_work",
    ),
    "stage_recheck": (
        CAPTURE,
        'if inventory(source) != staging["manifest"]["files"]:',
        "if False:",
        TEST + "test_changed_staged_fixture_refuses",
    ),
    "readback": (
        CAPTURE,
        'if evidence["sanitized"] != evidence["destination"]:',
        "if False:",
        TEST + "test_readback_mismatch_refuses",
    ),
    "compute_bound": (
        CAPTURE,
        '"PASS" if seconds <= CAPTURE_LIMIT_S else "FAILED"',
        '"PASS"',
        TEST + "test_one_source_bound_bracket_and_boundary",
    ),
    "compute_alarm": (
        CAPTURE,
        "signal.setitimer(signal.ITIMER_REAL, CAPTURE_LIMIT_S)",
        "None",
        TEST + "test_compute_deadline_interrupts_work_and_restores_alarm",
    ),
    "source_verification": (
        CAPTURE,
        "provenance = verify_source()",
        "provenance = {}",
        TEST + "test_one_source_bound_bracket_and_boundary",
    ),
    "reuse_status": (CAPTURE, 'capture.get("status") != "PASS"', "False", REUSE),
    "reuse_compute": (
        CAPTURE,
        'not 0 <= capture.get("compute_s", float("inf")) <= CAPTURE_LIMIT_S',
        "False",
        REUSE,
    ),
    "reuse_source": (
        CAPTURE,
        'capture.get("source", {}).get("source_commit") != source_commit',
        "False",
        REUSE,
    ),
    "reuse_native_source": (
        CAPTURE,
        'native.get("source_commit") != source_commit',
        "False",
        REUSE,
    ),
    "reuse_hash": (
        CAPTURE,
        'capture.get("native_receipt_sha256") != native_hash',
        "False",
        REUSE,
    ),
    "reuse_staging": (
        CAPTURE,
        'not capture.get("staging", {}).get("verified")',
        "False",
        REUSE,
    ),
    "reuse_scope": (
        CAPTURE,
        'native.get("capture_reuse_scope")\n        != "sanitized_campaign only; excludes staging, source checks, transfer and readback"',
        "False",
        REUSE,
    ),
    "reuse_bracket": (
        CAPTURE,
        'not capture["monotonic_start_ns"]\n        <= native.get("monotonic_start_ns", -1)\n        <= native.get("monotonic_end_ns", -1)\n        <= capture["monotonic_end_ns"]',
        "False",
        REUSE,
    ),
    "reuse_elapsed": (
        CAPTURE,
        'native.get("elapsed_seconds")\n        != (native["monotonic_end_ns"] - native["monotonic_start_ns"]) / 1e9',
        "False",
        REUSE,
    ),
    "runner_capture_receipt": (
        CLOUD,
        'if name == "capture":\n                    native_path',
        "if False:\n                    native_path",
        TEST + "test_runner_rejects_overrun_receipt_even_if_command_exits_zero",
    ),
    "runner_halt_flag": (
        CLOUD,
        "capture_halted = True",
        "capture_halted = False",
        TEST + "test_capture_failure_halts_later_checks_and_image_preparation",
    ),
    "runner_halt_admission": (
        CLOUD,
        "if capture_halted:",
        "if False:",
        TEST + "test_capture_failure_halts_later_checks_and_image_preparation",
    ),
    "runner_capture_no_images": (
        CLOUD,
        'name not in {"native", "capture"}\n                    and not images_attempted',
        'name != "native"\n                    and not images_attempted',
        TEST + "test_success_order_prepares_images_only_after_capture_and_native",
    ),
    "runner_native_budget": (
        CLOUD,
        "budget = METADATA_S",
        "budget = SIZING_S",
        TEST + "test_native_reuse_admitted_by_its_own_short_budget",
    ),
    "refresh_shape": (
        OPERATOR,
        'refresh["instance_type"] != INSTANCE_TYPE',
        "False",
        TEST + "test_refreshed_c6i_shape_and_timing_cost_policy",
    ),
    "refresh_memory": (
        OPERATOR,
        'refresh["memory_mib"] != 16384',
        "False",
        TEST + "test_refreshed_c6i_shape_and_timing_cost_policy",
    ),
    "refresh_vcpu": (
        OPERATOR,
        'refresh["vcpus"] != 8',
        "False",
        TEST + "test_refreshed_c6i_shape_and_timing_cost_policy",
    ),
    "sizing_source": (
        SIZING,
        'if observed["source_commit"] != provenance["source_commit"]:',
        "if False:",
        SIZING_TEST + "test_source_change_refuses_inside_capture_and_retains_staging",
    ),
    "sizing_overrun": (
        SIZING,
        'if capture["status"] != "PASS":',
        "if False:",
        SIZING_TEST + "test_returned_overrun_refuses_even_if_capture_returns_normally",
    ),
    "sizing_cli": (
        SIZING,
        "if args.capture_receipt is not None and (",
        "if False and (",
        SIZING_TEST + "test_capture_cli_refuses_non_native_modes",
    ),
}


def check(root, path, killer):
    environment = {
        **os.environ,
        "PYTHONDONTWRITEBYTECODE": "1",
        "DEC086_SIZING_SCRIPT": str(root / SIZING),
        "PYTHONPATH": os.pathsep.join(
            (
                str(root / "python/src"),
                str(root / "scripts"),
                str(ROOT / "python/tests"),
                str(ROOT / "scripts/tests"),
                str(ROOT / "scripts"),
            )
        ),
    }
    code = """
import importlib, io, json, pathlib, sys, unittest
module = importlib.import_module("inference_platform." + pathlib.Path(sys.argv[1]).stem) if sys.argv[1].startswith("python/") else None
if module: assert pathlib.Path(module.__file__).resolve().is_relative_to(pathlib.Path(sys.argv[2]).resolve())
suite = unittest.defaultTestLoader.loadTestsFromName(sys.argv[3])
if sys.argv[1].startswith("scripts/"):
    module = importlib.import_module("test_package_a_capture_sizing").SIZING if "size_inf037b" in sys.argv[1] else importlib.import_module("package_a_local_preflight")
    assert pathlib.Path(module.__file__).resolve().is_relative_to(pathlib.Path(sys.argv[2]).resolve())
result = unittest.TextTestRunner(stream=io.StringIO()).run(suite)
print(json.dumps(dict(tests=result.testsRun,failures=len(result.failures),errors=len(result.errors),skips=len(result.skipped),module_identity_confirmed=True)))
"""
    result = subprocess.run(
        [sys.executable, "-c", code, path, str(root), killer],
        capture_output=True,
        text=True,
        env=environment,
        timeout=30,
        check=True,
    )
    return json.loads(result.stdout)


def run():
    results = []
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        shutil.copytree(
            ROOT / "python/src/inference_platform",
            root / "python/src/inference_platform",
        )
        (root / "scripts").mkdir()
        shutil.copyfile(ROOT / SIZING, root / SIZING)
        shutil.copyfile(ROOT / PREFLIGHT, root / PREFLIGHT)
        for name, (path, before, after, killer) in MUTANTS.items():
            target = root / path
            original = target.read_text()
            if original.count(before) != 1:
                raise RuntimeError("nonunique mutation site: " + name)
            baseline = check(root, path, killer)
            if (
                baseline["tests"] != 1
                or baseline["failures"]
                or baseline["errors"]
                or baseline["skips"]
            ):
                raise RuntimeError(
                    "unmodified killer failed: " + name + " " + str(baseline)
                )
            try:
                target.write_text(original.replace(before, after, 1))
                mutant = check(root, path, killer)
            finally:
                target.write_text(original)
            if mutant["failures"] < 1 or mutant["errors"] or mutant["skips"]:
                raise RuntimeError("not assertion-killed: " + name + " " + str(mutant))
            results.append(
                {
                    "site": name,
                    "path": path,
                    "killer": killer,
                    "baseline": baseline,
                    "mutant": mutant,
                }
            )
    return {
        "schema": "dec086-refusal-mutations-v1",
        "sites": len(results),
        "killed": len(results),
        "survivors": 0,
        "results": results,
        "source_sha256": {
            name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
            for name in sorted(
                {
                    CAPTURE,
                    CLOUD,
                    OPERATOR,
                    PREFLIGHT,
                    SIZING,
                    "python/tests/test_package_a_capture.py",
                    "scripts/tests/test_package_a_capture_sizing.py",
                    "scripts/tests/test_package_a_linux_e2e.py",
                    "scripts/check_package_a_capture_mutations.py",
                }
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
        f"{receipt['killed']}/{receipt['sites']} assertion-killed; unmodified killers pass"
    )
