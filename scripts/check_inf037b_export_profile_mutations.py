"""Named negative controls for the new offline R366 experiment, not old modules."""

import hashlib
import importlib
import io
import json
import sys
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "scripts"), str(ROOT / "scripts/tests")]
import test_profile_inf037b_export as tests  # noqa: E402

TARGET = ROOT / "scripts/profile_inf037b_export_candidate.py"
MODULE = "profile_inf037b_export_candidate"
CACHE_KILLER = (
    "test_candidate_preserves_bytes_and_invalidates_both_caches_on_changed_input"
)
SYNC_KILLER = "test_candidate_batch_propagates_file_and_directory_sync_failure"
MUTANTS = {
    "verify_cache_fresh_byte_key": (
        "key = (root.resolve(), archive.sha(archive.encode(observed)))",
        "key = (root.resolve(), 'mutant')",
        CACHE_KILLER,
    ),
    "report_cache_fresh_byte_key": (
        "            archive.sha(archive.encode(observed)),",
        "            'mutant',",
        CACHE_KILLER,
    ),
    "final_file_sync": ("original_sync(handle.fileno())", "None", SYNC_KILLER),
    "final_directory_sync": ("original_sync(fd)", "None", SYNC_KILLER),
}


def check(source, label, killer):
    module = types.ModuleType(MODULE)
    module.__file__ = str(TARGET)
    module._R366_MUTANT_LABEL = label
    exec(compile(source, str(TARGET), "exec"), module.__dict__)
    sys.modules[MODULE] = module
    assert importlib.import_module(MODULE) is module
    assert importlib.import_module(MODULE)._R366_MUTANT_LABEL == label
    output = io.StringIO()
    suite = unittest.TestSuite([tests.ExportProfileTests(killer)])
    result = unittest.TextTestRunner(stream=output).run(suite)
    return {
        "label": label,
        "killer": "ExportProfileTests." + killer,
        "tests": result.testsRun,
        "skips": len(result.skipped),
        "failures": len(result.failures),
        "errors": len(result.errors),
        "module_identity_confirmed": True,
    }


def run():
    source = TARGET.read_text()
    records = []
    for label, (before, after, killer) in MUTANTS.items():
        if source.count(before) != 1:
            raise RuntimeError("mutation site is not unique: " + label)
        baseline = check(source, "baseline:" + label, killer)
        if baseline["failures"] or baseline["errors"] or baseline["skips"]:
            raise RuntimeError("unmodified killer failed: " + label)
        mutant = check(source.replace(before, after, 1), label, killer)
        if mutant["failures"] != 1 or mutant["errors"] or mutant["skips"]:
            raise RuntimeError("mutant not killed by its named assertion: " + label)
        records.append(
            {"site": label, "baseline": baseline, "mutant": mutant, "outcome": "killed"}
        )
    return {
        "schema": "inf037b-r366-mutation-controls-v1",
        "sites": len(records),
        "killed": len(records),
        "survivors": 0,
        "source_sha256": {
            str(p.relative_to(ROOT)).replace("\\", "/"): hashlib.sha256(
                p.read_bytes()
            ).hexdigest()
            for p in (
                TARGET,
                Path(__file__),
                ROOT / "scripts/tests/test_profile_inf037b_export.py",
            )
        },
        "results": records,
    }


if __name__ == "__main__":
    destination = Path(sys.argv[1])
    destination.write_text(json.dumps(run(), indent=2) + "\n")
    print(
        "R366 experiment: four named mutants killed; all four unmodified controls pass"
    )
