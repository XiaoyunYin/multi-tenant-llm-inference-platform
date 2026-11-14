"""Source/doc binding receipts and changed-site refusal mutations for DEC-084/085.

Run inside pinned Linux Python 3.12.7. Historical packets are not rewritten.
Mutations are in-memory statement deletions plus one-ms numeric loosenings.
"""

import argparse
import ast
import contextlib
import copy
import difflib
import hashlib
import importlib
import io
import json
import platform
import subprocess
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python/tests"))
BASE = "4d2ab1e4824a66221d2c31a8a7b082b220d605fb"
MODULES = {
    "preparation": ["test_inf037b_preparation"],
    "placement": ["test_inf037b_placement"],
    "lifecycle": ["test_inf037b_lifecycle"],
    "setup": ["test_inf037b_preparation"],
    "resolver": ["test_inf037b_resolver"],
}


def git(*args):
    return subprocess.check_output(
        [
            "git",
            "-c",
            "core.autocrlf=true",
            "-c",
            "core.safecrlf=false",
            "-C",
            str(ROOT),
            *args,
        ]
    )


def digest(path):
    return hashlib.sha256(
        (ROOT / path).read_bytes().replace(b"\r\n", b"\n")
    ).hexdigest()


def bindings():
    from inference_platform.inf037b_contract import (
        REGISTRATION_COMMIT,
        REGISTRATION_GIT_BLOB_SHA256,
        REGISTRATION_PATH,
    )

    pinned = git("show", f"{REGISTRATION_COMMIT}:{REGISTRATION_PATH}")
    assert hashlib.sha256(pinned).hexdigest() == REGISTRATION_GIT_BLOB_SHA256
    assert pinned == (ROOT / REGISTRATION_PATH).read_bytes().replace(b"\r\n", b"\n")
    prior_v4 = "docs/INF037B_REGISTRATION_V4.md"
    prior_v4_sha256 = "02ba808f529622242b86ec0df0f464786608569f957123c97a8754e177d4d0ca"
    assert digest(prior_v4) == prior_v4_sha256
    v3 = "docs/INF037B_PRE_REGISTRATION.md"
    assert (
        digest(v3) == "05812e4560ec869a2d87171f93d064ed61a3ba0d3a0240def1e946219d958a34"
    )
    changed = git("diff", "--name-only", BASE).decode().splitlines()
    docs = [
        p
        for p in changed
        if p.endswith(".md") and p.startswith("docs/") and p != "docs/BUILD_LOG.md"
    ]
    inputs = {
        str(p.relative_to(ROOT)).replace("\\", "/"): digest(p.relative_to(ROOT))
        for pattern in (
            "python/src/inference_platform/inf037b_*.py",
            "python/tests/*inf037b*.py",
        )
        for p in ROOT.glob(pattern)
    }
    inputs.update({p: digest(p) for p in docs})
    inputs["scripts/check_inf037b_amendment.py"] = digest(
        "scripts/check_inf037b_amendment.py"
    )
    inputs["scripts/reproduce_inf037b_placement.py"] = digest(
        "scripts/reproduce_inf037b_placement.py"
    )
    return {
        "registration_commit": REGISTRATION_COMMIT,
        "registration_sha256": REGISTRATION_GIT_BLOB_SHA256,
        "prior_v4_preserved": {"path": prior_v4, "sha256": prior_v4_sha256},
        "v3_preserved": True,
        "inputs": inputs,
        "changed_documents": docs,
    }


def suite(names):
    # Only the mutation pass omits the 7,290,007-call property. The complete
    # accepted module is run separately by normal discovery for the final suite.
    tests = []

    def flatten(value):
        for item in value:
            if isinstance(item, unittest.TestSuite):
                flatten(item)
            elif (
                "test_every_admissible_integer_observation_has_L_equal_B"
                not in item.id()
            ):
                tests.append(item)

    for name in names:
        module = importlib.import_module(name)
        importlib.reload(module)
        flatten(unittest.defaultTestLoader.loadTestsFromModule(module))
    if "test_inf037b_lifecycle" in names:
        flatten(
            unittest.defaultTestLoader.loadTestsFromName(
                "test_inf037b_lifecycle_recovery.RecoveryTests.test_attempt_kill_cutoff_cannot_enter_export_cleanup_reserve"
            )
        )
    return unittest.TestSuite(tests)


def run(names):
    stream = io.StringIO()
    with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
        result = unittest.TextTestRunner(stream=stream, verbosity=0).run(suite(names))
    return result, stream.getvalue()


class Delete(ast.NodeTransformer):
    def __init__(self, line, mode):
        self.line, self.mode = line, mode

    def visit_Expr(self, node):
        if node.lineno == self.line:
            if self.mode == "delete":
                return ast.copy_location(ast.Pass(), node)
            # One-ms loosening of a comparison's upper bound.
            comparisons = [
                n
                for n in ast.walk(node.value.args[0])
                if isinstance(n, ast.Compare)
                and len(n.ops) == 1
                and isinstance(n.ops[0], (ast.LtE, ast.Lt))
            ]
            for n in comparisons:
                n.comparators[0] = ast.BinOp(
                    n.comparators[0], ast.Add(), ast.Constant(1)
                )
        return node

    def visit_Assign(self, node):
        if node.lineno == self.line and self.mode == "delete":
            return ast.copy_location(ast.Pass(), node)
        return node


def mutations():
    records = []
    for label, names in MODULES.items():
        module = importlib.import_module("inference_platform.inf037b_" + label)
        path = Path(module.__file__)
        relative = path.relative_to(ROOT).as_posix()
        source = path.read_text(encoding="utf-8")
        try:
            if label == "preparation":
                raise FileNotFoundError
            old = git("show", f"{BASE}:{relative}").decode()
        except (subprocess.CalledProcessError, FileNotFoundError):
            old = ""
        changed = set()
        for tag, a, b, c, d in difflib.SequenceMatcher(
            None, old.splitlines(), source.splitlines()
        ).get_opcodes():
            if tag != "equal":
                changed.update(range(c + 1, d + 1))
        tree = ast.parse(source)
        sites = [
            n
            for n in ast.walk(tree)
            if isinstance(n, ast.Expr)
            and isinstance(n.value, ast.Call)
            and isinstance(n.value.func, ast.Name)
            and n.value.func.id in ("require", "exact", "allowance")
            and changed.intersection(range(n.lineno, n.end_lineno + 1))
        ]
        # Removing the admission call itself must also fail the real lifecycle
        # control, not just tests that invoke the validator directly.
        sites.extend(
            n
            for n in ast.walk(tree)
            if isinstance(n, ast.Assign)
            and isinstance(n.value, ast.Call)
            and isinstance(n.value.func, ast.Attribute)
            and ast.unparse(n.value.func) == "self.validate_staging"
            and changed.intersection(range(n.lineno, n.end_lineno + 1))
        )
        baseline, output = run(names)
        assert baseline.wasSuccessful() and not baseline.skipped, output
        original = compile(source, str(path), "exec")
        try:
            for node in sites:
                modes = ["delete"]
                if getattr(node.value.func, "id", None) == "require" and any(
                    isinstance(n, ast.Compare)
                    and len(n.ops) == 1
                    and isinstance(n.ops[0], ast.LtE)
                    for n in ast.walk(node.value.args[0])
                ):
                    modes.append("loosen_1ms")
                for mode in modes:
                    mutant = Delete(node.lineno, mode).visit(copy.deepcopy(tree))
                    exec(
                        compile(ast.fix_missing_locations(mutant), str(path), "exec"),
                        module.__dict__,
                    )
                    result, output = run(names)
                    records.append(
                        {
                            "module": label,
                            "line": node.lineno,
                            "guard": ast.unparse(node.value),
                            "mutation": mode,
                            "killed": not result.wasSuccessful(),
                            "failures": [t.id() for t, _ in result.failures],
                            "errors": [t.id() for t, _ in result.errors],
                            "skips": len(result.skipped),
                            "diagnostic": output if result.wasSuccessful() else None,
                        }
                    )
                    exec(original, module.__dict__)
        finally:
            exec(original, module.__dict__)
    return {
        "baseline": "PASS",
        "mutants": records,
        "survivors": [r for r in records if not r["killed"]],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--mutate", action="store_true")
    parser.add_argument("--validate", action="store_true")
    args = parser.parse_args()
    result = {
        "binding": bindings(),
        "python": platform.python_version(),
        "platform": platform.system(),
        "paid_ready": False,
    }
    if args.mutate:
        result.update(mutations())
    if args.validate:
        stream = io.StringIO()
        start = time.monotonic()
        tests = unittest.defaultTestLoader.discover(
            str(ROOT / "python/tests"), pattern="test_inf037b*.py"
        )
        with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
            outcome = unittest.TextTestRunner(stream=stream, verbosity=1).run(tests)
        result["validation"] = {
            "scope": "whole modules: every test_inf037b*.py; real gateway/Redis supplied by environment",
            "tests": outcome.testsRun,
            "skips": outcome.skipped,
            "failures": [t.id() for t, _ in outcome.failures],
            "errors": [t.id() for t, _ in outcome.errors],
            "elapsed_s": time.monotonic() - start,
            "success": outcome.wasSuccessful() and not outcome.skipped,
        }
        if not result["validation"]["success"]:
            print(stream.getvalue())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "binding": "PASS",
                "mutants": len(result.get("mutants", [])),
                "survivors": [
                    {k: r[k] for k in ("module", "line", "guard", "mutation")}
                    for r in result.get("survivors", [])
                ],
            }
        )
    )
    return bool(result.get("survivors")) or (
        args.validate and not result["validation"]["success"]
    )


if __name__ == "__main__":
    sys.exit(main())
