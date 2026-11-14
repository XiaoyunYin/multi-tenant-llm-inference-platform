"""Scoped preparation mutations, including argument values and child-process code.

Use the pinned Linux runtime. Every mutant is an isolated import overlay, so
ProcessCalls children see the same changed bytes as the test process. The
repository, accepted contracts and historical evidence are never overwritten.
"""

import argparse
import ast
import hashlib
import json
import os
import platform
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "python/src/inference_platform"
PREPARATION = "inf037b_preparation.py"
SETUP = "inf037b_setup.py"
TESTS = ["test_inf037b_preparation", "test_inf037b_preparation_adapter"]


def run(overlay):
    environment = {
        **os.environ,
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": os.pathsep.join(
            map(str, (overlay, ROOT / "python/src", ROOT / "python/tests"))
        ),
    }
    started = time.monotonic()
    result = subprocess.run(
        [sys.executable, "-m", "unittest", *TESTS, "-v"],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        timeout=45,
    )
    output = result.stdout + result.stderr
    return {
        "exit_code": result.returncode,
        "elapsed_s": time.monotonic() - started,
        "output_sha256": hashlib.sha256(output).hexdigest(),
        "output": output.decode(errors="replace"),
    }


def mutations():
    # These replacements target the new executable sites and arguments. Each
    # source fragment must be unique; stale coverage refuses rather than skips.
    yield (
        SETUP,
        "remove admitted-evidence join",
        """        admit_branch_evidence(
            collected, binding=self.binding, receipt=collected["preparation_receipt"]
        )""",
        "        pass",
    )
    yield (
        SETUP,
        "remove paired-port guard",
        """            require(callable(capture) and callable(gpu), "setup:both_preparation_ports")""",
        "            pass",
    )
    yield (
        PREPARATION,
        "remove raw hash join (both branches)",
        """        exact(branch["sha256"], sha(collected[raw_name]), "preparation:" + name + "_raw_hash")""",
        "        pass",
    )
    yield (
        PREPARATION,
        "canonicalize admitted hash argument",
        "sha(collected[raw_name])",
        "sha(encode(strict_json(collected[raw_name])))",
    )
    yield (
        PREPARATION,
        "canonicalize fork hash argument",
        '"sha256": sha(value)',
        '"sha256": sha(encode(strict_json(value)))',
    )
    yield (
        PREPARATION,
        "remove evidence start check",
        """        require(branch["start"]["ms"][0] <= lo, "preparation:" + name + "_evidence_start")""",
        "        pass",
    )
    yield (
        PREPARATION,
        "remove evidence end check",
        """        require(ehi <= branch["end"]["ms"][1], "preparation:" + name + "_evidence_end")""",
        "        pass",
    )
    yield (
        PREPARATION,
        "use evidence's own clock in start argument",
        """interval(evidence["start"], binding, clock, binding["t0_ms"])""",
        """interval(evidence["start"], binding, (evidence["start"]["clock_id"], evidence["start"]["boot_id"]), binding["t0_ms"])""",
    )
    yield (
        PREPARATION,
        "use evidence's own clock in end argument",
        """interval(evidence["end"], binding, clock, hi)""",
        """interval(evidence["end"], binding, (evidence["end"]["clock_id"], evidence["end"]["boot_id"]), hi)""",
    )
    yield (
        PREPARATION,
        "remove evidence endpoint order argument",
        """interval(evidence["end"], binding, clock, hi)""",
        """interval(evidence["end"], binding, clock, binding["t0_ms"])""",
    )
    yield (
        PREPARATION,
        "fake fitness boot argument from branch",
        '"boot_id": fitness.rows[0]["collector_boot_id"]',
        '"boot_id": receipt["branches"]["gpu"]["start"]["boot_id"]',
    )
    yield (
        PREPARATION,
        "omit collection start bracket",
        """times[0] = min(times[0], min(r["capture_start_mono_ns"] // 1_000_000 for r in fitness.rows))""",
        "times[0] = times[0]",
    )
    yield (
        PREPARATION,
        "round collection end inward",
        '(r["capture_end_mono_ns"] + 999_999) // 1_000_000',
        'r["capture_end_mono_ns"] // 1_000_000',
    )
    yield (
        PREPARATION,
        "remove received signal order",
        """        require(signal_hi <= export["start"]["ms"][0], "preparation:capture_after_signal")""",
        "        pass",
    )
    yield (
        PREPARATION,
        "fake signal clock argument",
        """interval(signal, binding, clock, binding["t0_ms"])""",
        """interval(signal, binding, (signal["clock_id"], signal["boot_id"]), binding["t0_ms"])""",
    )
    yield (
        PREPARATION,
        "wait for all instead of FIRST_EXCEPTION",
        "return_when=FIRST_EXCEPTION",
        'return_when="ALL_COMPLETED"',
    )
    yield (
        PREPARATION,
        "wait for first success instead of both",
        "return_when=FIRST_EXCEPTION",
        'return_when="FIRST_COMPLETED"',
    )
    yield (
        PREPARATION,
        "ignore absolute wait timeout argument",
        'timeout=max(0, cutoff - self.sample()["ms"][1]) / 1000',
        "timeout=1800",
    )
    yield (
        PREPARATION,
        "rebase preparation cutoff from original P",
        'self.ready["ms"][0] + 1_800_000',
        'self.sample()["ms"][0] + 1_800_000',
    )
    yield (
        PREPARATION,
        "loosen branch stop argument",
        'start["ms"][0] + PREPARATION_BRANCH_MS',
        'start["ms"][0] + PREPARATION_BRANCH_MS + 1',
    )
    yield (
        PREPARATION,
        "pass global instead of branch persist cutoff",
        "self.persist(name, item, branch_stop)",
        "self.persist(name, item, cutoff)",
    )
    yield (
        PREPARATION,
        "remove immediate command exit",
        "self.exit_command(1)",
        "(lambda code: None)(1)",
    )
    yield (
        PREPARATION,
        "return successful process exit value",
        "self.exit_command(1)",
        "self.exit_command(0)",
    )
    yield (
        PREPARATION,
        "omit durable failure record call",
        'self.persist("failure", failure, cutoff)',
        "True",
    )
    yield (
        PREPARATION,
        "lose failed branch name argument",
        '"branch": name',
        '"branch": "unknown"',
    )
    yield (
        PREPARATION,
        "lose failure reason argument",
        '"reason": type(error).__name__ + ":" + str(error)',
        '"reason": "unknown"',
    )
    yield (
        PREPARATION,
        "remove adapter immutable binding",
        """            exact(state["binding"], self.binding, "preparation:collect_binding")""",
        "            pass",
    )
    yield (
        PREPARATION,
        "remove interrupted fork retry refusal",
        """            require("preparation_fork" not in state, "preparation:interrupted_no_retry")""",
        "            pass",
    )
    yield (
        PREPARATION,
        "drop fork intent persistence",
        """            self.store.write(state)
        outputs = {}""",
        """            pass
        outputs = {}""",
    )
    yield (
        PREPARATION,
        "drop durable receipt persistence",
        """                self.store.write(state)
            require(self.sample()["ms"][1] <= cutoff, "preparation:persist_cutoff")""",
        """                pass
            require(self.sample()["ms"][1] <= cutoff, "preparation:persist_cutoff")""",
    )
    yield (
        PREPARATION,
        "bypass branch archive persistence",
        "manifest = persist_archive_artifacts(self.store, artifacts)",
        "manifest = {}",
    )
    yield (
        PREPARATION,
        "change absolute stop argument to fork",
        ").run(stop)",
        ").run(stop + 1)",
    )
    yield (
        SETUP,
        "change creation phase argument",
        'collect("creation", stop)',
        'collect("preparation", stop)',
    )
    yield (
        SETUP,
        "change creation absolute stop argument",
        'collect("creation", stop)',
        'collect("creation", stop + 1)',
    )
    yield SETUP, "swap capture port argument", "capture=capture,", "capture=gpu,"
    yield SETUP, "swap GPU port argument", "gpu=gpu,", "gpu=capture,"
    yield (
        PREPARATION,
        "serialize concurrent branch workers",
        "max_workers=2",
        "max_workers=1",
    )
    yield (
        PREPARATION,
        "use extended deadline for failure persist argument",
        'self.persist("failure", failure, cutoff)',
        'self.persist("failure", failure, stop_ms)',
    )
    yield (
        PREPARATION,
        "ignore normalized fitness source endpoints",
        'times = fitness.row(binding["pins"])["observation_ms"]',
        'times = [min(r["capture_start_mono_ns"] // 1_000_000 for r in fitness.rows), max((r["capture_end_mono_ns"] + 999_999) // 1_000_000 for r in fitness.rows)]',
    )
    source = (SOURCE / PREPARATION).read_text(encoding="utf-8")
    guards = {
        "preparation:port_bytes",
        "preparation:capture_bytes",
        "preparation:gpu_bytes",
        "preparation:branch_ownership",
        "preparation:creation_required",
        "preparation:collect_operation",
    }
    found = set()
    for node in ast.walk(ast.parse(source)):
        if (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Name)
            and node.value.func.id in ("require", "exact")
            and isinstance(node.value.args[-1], ast.Constant)
            and node.value.args[-1].value in guards
        ):
            reason = node.value.args[-1].value
            found.add(reason)
            lines = source.splitlines()[node.lineno - 1 : node.end_lineno]
            yield (
                PREPARATION,
                "remove " + reason,
                "\n".join(lines),
                " " * node.col_offset + "pass",
            )
    assert found == guards, ("missing changed-site guard", guards - found)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    inputs = [
        SOURCE / PREPARATION,
        SOURCE / SETUP,
        ROOT / "python/tests/test_inf037b_preparation.py",
        ROOT / "python/tests/test_inf037b_preparation_adapter.py",
        ROOT / "python/tests/inf037b_setup_worker.py",
        Path(__file__),
    ]
    summary = {
        "schema": "inf037b-preparation-mutations-v1",
        "python": platform.python_version(),
        "system": platform.system(),
        "command": [sys.executable, "-m", "unittest", *TESTS, "-v"],
        "inputs_lf_sha256": {
            p.relative_to(ROOT).as_posix(): hashlib.sha256(
                p.read_bytes().replace(b"\r\n", b"\n")
            ).hexdigest()
            for p in inputs
        },
        "mutants": [],
    }
    with tempfile.TemporaryDirectory(
        prefix="inf037b-preparation-mutants-"
    ) as directory:
        overlay = Path(directory)
        package = overlay / "inference_platform"
        package.mkdir()
        (package / "__init__.py").write_text(f"__path__.append({str(SOURCE)!r})\n")
        summary["baseline"] = run(overlay)
        if (
            summary["baseline"]["exit_code"] != 0
            or "skipped=" in summary["baseline"]["output"]
        ):
            raise AssertionError(summary["baseline"]["output"])
        for filename, label, original, replacement in mutations():
            source = (SOURCE / filename).read_text(encoding="utf-8")
            assert source.count(original) == 1, (label, source.count(original))
            changed = source.replace(original, replacement)
            compile(changed, filename, "exec")
            target = package / filename
            target.write_text(changed)
            try:
                result = run(overlay)
            finally:
                target.unlink()
            summary["mutants"].append(
                {
                    "file": filename,
                    "label": label,
                    "original": original,
                    "replacement": replacement,
                    "mutated_lf_sha256": hashlib.sha256(changed.encode()).hexdigest(),
                    "killed": result["exit_code"] != 0,
                    **result,
                }
            )
            print(label, "KILLED" if result["exit_code"] else "SURVIVED", flush=True)
    summary["killed"] = sum(row["killed"] for row in summary["mutants"])
    summary["survivors"] = len(summary["mutants"]) - summary["killed"]
    summary["inputs_unchanged"] = summary["inputs_lf_sha256"] == {
        p.relative_to(ROOT).as_posix(): hashlib.sha256(
            p.read_bytes().replace(b"\r\n", b"\n")
        ).hexdigest()
        for p in inputs
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(summary, indent=2, allow_nan=False) + "\n", encoding="utf-8"
    )
    assert summary["survivors"] == 0, "mutation survivors"
    assert summary["inputs_unchanged"], "inputs changed during mutation sweep"
    print(f"{summary['killed']}/{len(summary['mutants'])} killed; zero survivors")


if __name__ == "__main__":
    main()
