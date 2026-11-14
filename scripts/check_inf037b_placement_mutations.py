"""Offline placement mutation receipt using the slice (2) operator set.

Each mutant starts with a clean module namespace and reloads the test module.
No source file is modified. Only reasoned equivalents may survive.
"""

import argparse
import ast
import contextlib
import hashlib
import importlib
import io
import json
import sys
import unittest
from pathlib import Path

from check_inf037b_controller_mutations import (
    ControllerMutate,
    StatementMutate,
    controller_sites,
    statement_sites,
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python/tests"))
from inference_platform import inf037b_placement as placement  # noqa: E402

EQUIVALENT = {
    ("check_placement: text(identity['name'])", "statement_delete"): (
        "Both phase joins validate a nonempty string node name with text(), then "
        "exact(node_name, identity['name']) checks both type and value. An invalid "
        "verified name cannot pass those checks; this early duplicate has no effect "
        "on the export decision or retained memory evidence."
    ),
}


class ParserMutate(ast.NodeTransformer):
    """Exercise parser/error-handler changes outside the statement operators."""

    def __init__(self, mode):
        self.mode = mode

    def visit_Call(self, node):
        if (
            self.mode == "plain_json"
            and isinstance(node.func, ast.Name)
            and node.func.id == "strict_json"
        ):
            node.func = ast.Attribute(
                value=ast.Call(
                    func=ast.Name(id="__import__", ctx=ast.Load()),
                    args=[ast.Constant("json")],
                    keywords=[],
                ),
                attr="loads",
                ctx=ast.Load(),
            )
        return self.generic_visit(node)

    def visit_ExceptHandler(self, node):
        if (
            self.mode == "uncaught_recursion"
            and isinstance(node.type, ast.Name)
            and node.type.id == "RecursionError"
        ):
            node.type = ast.Name(id="OSError", ctx=ast.Load())
        if self.mode == "uncaught_quantity_valueerror" and isinstance(
            node.type, ast.Tuple
        ):
            node.type.elts = [
                ast.Name(id="IntegrityError", ctx=ast.Load())
                if isinstance(item, ast.Name) and item.id == "ValueError"
                else item
                for item in node.type.elts
            ]
            # Only change inspect_phase's inner quantity loop, not its callers.
            return node
        return self.generic_visit(node)


def run(only=None):
    import test_inf037b_placement as tests

    importlib.reload(tests)
    stream = io.StringIO()
    with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
        result = unittest.TextTestRunner(stream=stream, failfast=only is None).run(
            unittest.TestSuite(tests.PlacementTests(name) for name in only)
            if only
            else unittest.defaultTestLoader.loadTestsFromTestCase(tests.PlacementTests)
        )
    return result.wasSuccessful(), sorted(
        {str(test) for test, _ in result.failures + result.errors}
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    path = Path(placement.__file__)
    source = path.read_text(encoding="utf-8")
    original = compile(source, str(path), "exec")
    metadata = {
        key: placement.__dict__[key]
        for key in ("__name__", "__package__", "__file__", "__spec__")
    }

    def install(code):
        placement.__dict__.clear()
        placement.__dict__.update(metadata)
        exec(code, placement.__dict__)
        placement.mutant_noop = lambda *args, **kwargs: None

    passed, failures = run()
    if not passed:
        raise SystemExit("baseline failed: " + repr(failures))
    passes = [
        (site, mode, "checks")
        for site in controller_sites(ast.parse(source))
        for mode in (("delete", "loosen") if site[4] else ("delete",))
    ] + [
        (
            site,
            "if_negate" if site[2] == "negate_if" else "statement_delete",
            "statements",
        )
        for site in statement_sites(ast.parse(source))
    ]
    records = []
    try:
        for site, mode, operator_pass in passes:
            tree = (
                ControllerMutate(site, mode)
                if operator_pass == "checks"
                else StatementMutate(site)
            ).visit(ast.parse(source))
            install(compile(ast.fix_missing_locations(tree), str(path), "exec"))
            passed, kills = run()
            row = {
                "operator_pass": operator_pass,
                "line": site[0],
                "kind": site[2],
                "check": site[3],
                "mutation": mode,
                "killed": not passed,
                "expected_test": kills[0] if kills else None,
                "tests": kills,
            }
            if passed:
                row["survivor_reason"] = EQUIVALENT.get((site[3], mode))
            records.append(row)
            print(json.dumps(row), flush=True)
        for mode in (
            "plain_json",
            "uncaught_recursion",
            "uncaught_quantity_valueerror",
        ):
            tree = ast.parse(source)
            target = next(
                node
                for node in tree.body
                if isinstance(node, ast.FunctionDef)
                and node.name
                == (
                    "inspect_phase"
                    if mode == "uncaught_quantity_valueerror"
                    else "decode"
                )
            )
            ParserMutate(mode).visit(target)
            install(compile(ast.fix_missing_locations(tree), str(path), "exec"))
            passed, kills = run(
                ["test_duplicate_json_member_refuses", "test_nonfinite_json_refuses"]
                if mode == "plain_json"
                else None
            )
            row = {
                "operator_pass": "parser_handlers",
                "line": target.lineno,
                "kind": "parser_handler",
                "check": mode,
                "mutation": mode,
                "killed": not passed,
                "expected_test": kills[0] if kills else None,
                "tests": kills,
            }
            records.append(row)
            print(json.dumps(row), flush=True)
    finally:
        install(original)
    survivors = [row for row in records if not row["killed"]]
    receipt = {
        "placement_lf_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "tests_lf_sha256": hashlib.sha256(
            (ROOT / "python/tests/test_inf037b_placement.py")
            .read_text(encoding="utf-8")
            .encode()
        ).hexdigest(),
        "baseline": "PASS",
        "operators": "all",
        "per_mutant_test_reload": True,
        "clean_module_namespace": True,
        "failfast": True,
        "parser_plain_json_runs_both_strictness_tests": True,
        "statement_exclusions": [
            "imports",
            "function/class definitions",
            "docstrings",
            "pass (no behavior)",
        ],
        "mutants": records,
        "survivors": survivors,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(receipt, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    print(f"{len(records) - len(survivors)}/{len(records)} mutants killed")
    print("Survivors: " + json.dumps(survivors))
    return any(not row.get("survivor_reason") for row in survivors)


if __name__ == "__main__":
    sys.exit(main())
