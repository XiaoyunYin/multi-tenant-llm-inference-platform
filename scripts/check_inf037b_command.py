"""Only row 2 / R371 changed refusals and requested endpoint value mutants.

Each overlay is inherited by ProcessCalls children. Historical preparation
mutants are not rerun. Summary JSON retains exact replacements and log hashes.
"""

import argparse
import ast
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "python/src/inference_platform"
PATHS = [
    "test_inf037b_preparation_adapter.AdapterTests.test_joined_manifest_stat_guards_and_raw_references"
]
ENDPOINTS = ["test_inf037b_preparation_adapter.EvidenceTests"]
LEADERSHIP = ["test_inf037b_command.LeadershipTests"]
COMPLETION = ["test_inf037b_command.CompletionTests"]
LATE = [
    "test_inf037b_command.CommandTests.test_final_durable_write_is_charged_and_reopen_cannot_admit_late_result"
]
HAPPY = [
    "test_inf037b_command.CommandTests.test_real_commands_reconstruct_setup_attempt_and_lazy_terminal"
]
BAD_ARCHIVE = [
    "test_inf037b_command.CommandTests.test_export_archive_semantics_are_checked_before_branch_ack"
]
MAXIMUM = ["test_inf037b_maximum"]


def mutants():
    guards = {
        "inf037b_setup.py": {
            "setup:maximum_artifact": MAXIMUM,
            "setup:maximum_at_P": MAXIMUM,
            "setup:original_maximum": MAXIMUM,
            "setup:raw_reference_hash": PATHS,
            **dict.fromkeys(
                (
                    "setup:archive_branch_verified",
                    "setup:archive_branch_manifest",
                    "setup:archive_objects",
                    "setup:archive_under_objects",
                    "setup:archive_object_file",
                    "setup:archive_object_symlink",
                    "setup:archive_object_resolved",
                    "setup:archive_object_size",
                ),
                PATHS,
            ),
            "setup:durable_command_completion": COMPLETION,
        },
        "inf037b_command.py": dict.fromkeys(
            (
                "command:posix",
                "command:group_leader",
                "command:operation",
                "command:ports",
                "command:factory",
            ),
            LEADERSHIP,
        ),
        "inf037b_maximum.py": dict.fromkeys(
            (
                "maximum:artifact_hash",
                "maximum:canonical",
                "maximum:subject",
                "maximum:pins",
                "maximum:schedule",
                "maximum:current_sources",
                "maximum:inventory",
                "maximum:archive_inventory",
                "maximum:path",
                "maximum:bytes",
                "maximum:hash",
                "maximum:inventory_hash",
            ),
            MAXIMUM,
        ),
    }
    for filename, reasons in guards.items():
        text = (SOURCE / filename).read_text()
        found = set()
        for node in ast.walk(ast.parse(text)):
            if (
                isinstance(node, ast.Expr)
                and isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Name)
                and node.value.func.id in {"exact", "require"}
                and isinstance(node.value.args[-1], ast.Constant)
                and node.value.args[-1].value in reasons
            ):
                reason = node.value.args[-1].value
                found.add(reason)
                original = "\n".join(
                    text.splitlines()[node.lineno - 1 : node.end_lineno]
                )
                yield (
                    filename,
                    "remove " + reason,
                    original,
                    " " * node.col_offset + "pass",
                    reasons[reason],
                )
        assert found == reasons.keys(), (filename, reasons.keys() - found)
    values = [
        (
            "inf037b_preparation.py",
            "falsely verify refused raw candidate",
            '"archive_verified": False',
            '"archive_verified": True',
            BAD_ARCHIVE,
        ),
        (
            "inf037b_preparation.py",
            "discard refused raw candidate",
            '            persist("export", {"sha256": sha(raw), "archive_verified": False}, branch_stop)',
            "            pass",
            BAD_ARCHIVE,
        ),
        (
            "inf037b_command.py",
            "omit maximum admission",
            'load_maximum(config["maximum_fixture"], config["pins"])',
            "None",
            [
                "test_inf037b_command.CommandTests.test_maximum_refuses_before_factory_and_missing_proof_does_not_block_cleanup"
            ],
        ),
        (
            "inf037b_maximum.py",
            "trust claimed source bindings",
            'proof["source_lf_sha256"], current_sources(),',
            'proof["source_lf_sha256"], proof["source_lf_sha256"],',
            MAXIMUM,
        ),
        (
            "inf037b_maximum.py",
            "trust proof own pins",
            'proof["pins"], pins,',
            'proof["pins"], proof["pins"],',
            MAXIMUM,
        ),
        (
            "inf037b_maximum.py",
            "canonical self equality",
            "exact(raw, encode(proof),",
            "exact(raw, raw,",
            MAXIMUM,
        ),
        (
            "inf037b_maximum.py",
            "inventory hash self equality",
            'sha(encode(inventory)), proof["source_inventory_sha256"],',
            "sha(encode(inventory)), sha(encode(inventory)),",
            MAXIMUM,
        ),
        (
            "inf037b_command.py",
            "drop dispatcher leader check",
            "    require_group_leader()\n    require(operation in OPERATIONS",
            "    require(operation in OPERATIONS",
            LEADERSHIP,
        ),
        (
            "inf037b_command.py",
            "drop CLI leader check",
            "    require_group_leader()\n    config = strict_json",
            "    config = strict_json",
            LEADERSHIP,
        ),
        (
            "inf037b_preparation.py",
            "evidence lower to upper",
            '<= lo, "preparation:"',
            '<= hi, "preparation:"',
            ENDPOINTS,
        ),
        (
            "inf037b_preparation.py",
            "evidence upper to lower",
            'require(ehi <= branch["end"]',
            'require(elo <= branch["end"]',
            ENDPOINTS,
        ),
        (
            "inf037b_preparation.py",
            "signal upper to lower",
            "_, signal_hi = interval(signal,",
            "signal_hi, _ = interval(signal,",
            ENDPOINTS,
        ),
        (
            "inf037b_preparation.py",
            "capture lower to upper",
            'signal_hi <= export["start"]["ms"][0]',
            'signal_hi <= export["start"]["ms"][1]',
            ENDPOINTS,
        ),
        (
            "inf037b_setup.py",
            "manifest self equality",
            'exact(artifacts, branch["artifacts"],',
            "exact(artifacts, artifacts,",
            PATHS,
        ),
        (
            "inf037b_setup.py",
            "wrong branch manifest",
            'branch = state["preparation_fork"]["export"]',
            'branch = state["preparation_fork"]["gpu"]',
            HAPPY,
        ),
        (
            "inf037b_setup.py",
            "wrong stat length value",
            'exact(path.stat().st_size, facts["bytes"],',
            'exact(path.stat().st_size + 1, facts["bytes"],',
            PATHS,
        ),
        (
            "inf037b_setup.py",
            "wrong object folder",
            'self.store.path.name + ".objects"',
            'self.store.path.name + ".other"',
            PATHS,
        ),
        (
            "inf037b_setup.py",
            "hash reference self equality",
            'record.get("sha256", record.get("raw_sha256")),',
            "sha(raw),",
            PATHS,
        ),
        (
            "inf037b_setup.py",
            "duplicate raw in reference",
            'capture["raw_reference"] = list(reference)',
            'capture["raw_reference"] = list(reference)\n                capture["raw_hex"] = raw.hex()',
            PATHS,
        ),
        (
            "inf037b_setup.py",
            "rehash after join",
            "return self._joined_export_artifacts(artifacts)",
            'return persist_archive_artifacts(self.store, {k: v["path"] for k, v in artifacts.items()})',
            PATHS,
        ),
        (
            "inf037b_setup.py",
            "drop joined readback reuse",
            "readback=self._concurrent(),",
            "readback=False,",
            HAPPY,
        ),
        (
            "inf037b_preparation.py",
            "drop branch semantic validation",
            "validate_export_archives(strict_json(raw), manifest)",
            "pass",
            BAD_ARCHIVE,
        ),
        (
            "inf037b_setup.py",
            "substitute join for completion",
            'ready=creation["ready"], completed=completed',
            'ready=creation["ready"], completed=data["fork_receipt"]["join"]',
            LATE,
        ),
        (
            "inf037b_setup.py",
            "omit final completion check",
            'data, prior["creation"]["data"], completed',
            'data, prior["creation"]["data"], data["fork_receipt"]["join"]',
            LATE,
        ),
        (
            "inf037b_setup.py",
            "durable lower to upper",
            'now <= completed["ms"][0] <= completed["ms"][1] <= stop',
            'now <= completed["ms"][1] <= completed["ms"][1] <= stop',
            COMPLETION,
        ),
        (
            "inf037b_setup.py",
            "durable upper to lower",
            'now <= completed["ms"][0] <= completed["ms"][1] <= stop',
            'now <= completed["ms"][0] <= completed["ms"][0] <= stop',
            COMPLETION,
        ),
        (
            "inf037b_command.py",
            "group check own pid",
            "os.getpgrp() == os.getpid()",
            "os.getpgrp() == os.getpgrp()",
            LEADERSHIP,
        ),
        (
            "inf037b_command.py",
            "reverse group check",
            "os.getpgrp() == os.getpid()",
            "os.getpgrp() != os.getpid()",
            LEADERSHIP,
        ),
        (
            "inf037b_command.py",
            "wrong factory separator",
            'exact(separator, ":",',
            'exact(separator, "",',
            LEADERSHIP,
        ),
    ]
    yield from values


def run(overlay, tests):
    env = {
        **os.environ,
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": os.pathsep.join(
            map(str, (overlay, ROOT / "python/src", ROOT / "python/tests"))
        ),
    }
    result = subprocess.run(
        [sys.executable, "-m", "unittest", *tests, "-v"],
        env=env,
        cwd=ROOT,
        capture_output=True,
        timeout=180,
    )
    output = result.stdout + result.stderr
    return {
        "exit_code": result.returncode,
        "output_sha256": hashlib.sha256(output).hexdigest(),
        "output": output.decode(errors="replace"),
        "tests": tests,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    inputs = [
        *(
            SOURCE / f
            for f in (
                "inf037b_preparation.py",
                "inf037b_setup.py",
                "inf037b_setup_observations.py",
                "inf037b_command.py",
                "inf037b_maximum.py",
            )
        ),
        *(
            ROOT / "python/tests" / f
            for f in (
                "test_inf037b_command.py",
                "inf037b_command_fixture.py",
                "test_inf037b_preparation_adapter.py",
                "test_inf037b_maximum.py",
            )
        ),
        Path(__file__),
    ]

    def hashes():
        return {
            p.relative_to(ROOT).as_posix(): hashlib.sha256(
                p.read_bytes().replace(b"\r\n", b"\n")
            ).hexdigest()
            for p in inputs
        }

    summary = {
        "schema": "inf037b-command-mutations-v1",
        "inputs_lf_sha256": hashes(),
        "mutants": [],
    }
    with tempfile.TemporaryDirectory() as directory:
        overlay = Path(directory)
        package = overlay / "inference_platform"
        package.mkdir()
        (package / "__init__.py").write_text(f"__path__.append({str(SOURCE)!r})\n")
        summary["baseline"] = run(
            overlay,
            [
                "test_inf037b_command",
                "test_inf037b_preparation_adapter",
                "test_inf037b_maximum",
            ],
        )
        assert summary["baseline"]["exit_code"] == 0, summary["baseline"]["output"]
        for filename, label, original, replacement, tests in mutants():
            source = (SOURCE / filename).read_text()
            assert source.count(original) == 1, (label, source.count(original))
            changed = source.replace(original, replacement)
            compile(changed, filename, "exec")
            path = package / filename
            path.write_text(changed)
            try:
                result = run(overlay, tests)
            finally:
                path.unlink()
            # Store concise first-failure evidence, not every repeated traceback.
            failures = [
                line
                for line in result["output"].splitlines()
                if line.startswith(("FAIL:", "ERROR:", "Ran ", "FAILED"))
            ]
            result.pop("output")
            summary["mutants"].append(
                {
                    "file": filename,
                    "label": label,
                    "original": original,
                    "replacement": replacement,
                    "mutated_lf_sha256": hashlib.sha256(changed.encode()).hexdigest(),
                    "killed": result["exit_code"] != 0,
                    "failure_summary": failures,
                    **result,
                }
            )
            print(label, "KILLED" if result["exit_code"] else "SURVIVED", flush=True)
    summary["baseline"].pop("output")
    summary["killed"] = sum(m["killed"] for m in summary["mutants"])
    summary["survivors"] = len(summary["mutants"]) - summary["killed"]
    summary["inputs_unchanged"] = hashes() == summary["inputs_lf_sha256"]
    args.output.write_text(json.dumps(summary, indent=2, allow_nan=False) + "\n")
    assert summary["inputs_unchanged"] and summary["survivors"] == 0, summary


if __name__ == "__main__":
    main()
