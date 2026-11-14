"""Offline single-site v4 range mutations; never edits repository source.

Compile each mutant into the module, reload the tests to bind its functions, and
record the tests that kill it. Each mutation gets its own fresh test suite.
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

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python/tests"))
from inference_platform import inf037b_resolver as resolver  # noqa: E402


def sites(tree):
    result = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            continue
        if node.func.id in ("within", "minimum"):
            result.append(
                (
                    node.lineno,
                    node.col_offset,
                    node.func.id,
                    ast.unparse(node.args[-1]),
                    True,
                )
            )
        elif node.func.id == "require" and len(node.args) == 2:
            reason = ast.unparse(node.args[1])
            numeric = any(
                isinstance(child, ast.Compare)
                and any(
                    isinstance(op, (ast.Lt, ast.LtE, ast.Gt, ast.GtE))
                    for op in child.ops
                )
                for child in ast.walk(node.args[0])
            )
            result.append((node.lineno, node.col_offset, "require", reason, numeric))
        elif node.func.id == "exact" and len(node.args) == 3:
            result.append(
                (
                    node.lineno,
                    node.col_offset,
                    "exact",
                    ast.unparse(node.args[2]),
                    False,
                )
            )
        elif node.func.id in ("proof", "provenance"):
            label = ast.unparse(node.args[-1]) if node.args else node.func.id
            result.append((node.lineno, node.col_offset, node.func.id, label, False))
    return sorted(result)


class Mutate(ast.NodeTransformer):
    def __init__(self, site, mode):
        self.site, self.mode = site, mode

    def visit_Call(self, node):
        self.generic_visit(node)
        if (node.lineno, node.col_offset) != self.site[:2]:
            return node
        if node.func.id in ("within", "minimum"):
            interval_check = node.func.id
            if self.mode == "delete":
                node.func.id = "span"
                node.args = [node.args[0], node.args[-1]]
            else:
                node.args[1] = ast.BinOp(node.args[1], ast.Sub(), ast.Constant(1))
                if interval_check == "within":
                    node.args[2] = ast.BinOp(node.args[2], ast.Add(), ast.Constant(1))
        elif self.mode == "delete":
            node.func.id = "mutant_noop"
        else:
            # Loosen every strict/inclusive numeric comparison by one tick.
            class Loosen(ast.NodeTransformer):
                def visit_Compare(self, comparison):
                    self.generic_visit(comparison)
                    if len(comparison.ops) == 1:
                        op = comparison.ops[0]
                        if isinstance(op, (ast.Lt, ast.LtE)):
                            comparison.comparators[0] = ast.BinOp(
                                comparison.comparators[0], ast.Add(), ast.Constant(1)
                            )
                        elif isinstance(op, (ast.Gt, ast.GtE)):
                            comparison.comparators[0] = ast.BinOp(
                                comparison.comparators[0], ast.Sub(), ast.Constant(1)
                            )
                    elif all(
                        isinstance(op, (ast.Lt, ast.LtE)) for op in comparison.ops
                    ):
                        comparison.left = ast.BinOp(
                            comparison.left, ast.Sub(), ast.Constant(1)
                        )
                        comparison.comparators[-1] = ast.BinOp(
                            comparison.comparators[-1], ast.Add(), ast.Constant(1)
                        )
                    return comparison

            node.args[0] = Loosen().visit(node.args[0])
        return node


def run():
    import test_inf037b_resolver as tests

    importlib.reload(tests)
    stream = io.StringIO()
    suite = unittest.TestSuite(
        tests.ResolverTests(name)
        for name in unittest.defaultTestLoader.getTestCaseNames(tests.ResolverTests)
        if name != "test_every_admissible_integer_observation_has_L_equal_B"
    )
    # The exhaustive 6,390,007-call property runs in the normal suite; targeted
    # boundary and independent-gate tests run once for every single-site mutant.
    with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
        result = unittest.TextTestRunner(stream=stream).run(suite)
    killed = sorted({str(test) for test, _ in result.failures + result.errors})
    return result.wasSuccessful(), killed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    path = Path(resolver.__file__)
    source = path.read_text(encoding="utf-8")
    original = compile(source, str(path), "exec")
    records = []
    try:
        exec(original, resolver.__dict__)
        passed, failures = run()
        if not passed:
            raise SystemExit("baseline failed: " + repr(failures))
        resolver.mutant_noop = lambda *args, **kwargs: None
        for site in sites(ast.parse(source)):
            modes = ("delete", "loosen") if site[4] else ("delete",)
            for mode in modes:
                tree = Mutate(site, mode).visit(ast.parse(source))
                exec(
                    compile(ast.fix_missing_locations(tree), str(path), "exec"),
                    resolver.__dict__,
                )
                passed, killed = run()
                record = {
                    "line": site[0],
                    "kind": site[2],
                    "check": site[3],
                    "mutation": mode,
                    "killed": not passed,
                    "tests": killed,
                }
                records.append(record)
                print(json.dumps(record), flush=True)
                exec(original, resolver.__dict__)
    finally:
        exec(original, resolver.__dict__)
    survivors = [r for r in records if not r["killed"]]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(
            {
                "resolver_lf_sha256": hashlib.sha256(source.encode()).hexdigest(),
                "tests_lf_sha256": hashlib.sha256(
                    (ROOT / "python/tests/test_inf037b_resolver.py")
                    .read_text(encoding="utf-8")
                    .encode()
                ).hexdigest(),
                "baseline": "PASS",
                "mutants": records,
                "survivors": survivors,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print("Survivors: " + json.dumps(survivors, sort_keys=True))
    print(f"{len(records) - len(survivors)}/{len(records)} mutants killed")
    return bool(survivors)


if __name__ == "__main__":
    sys.exit(main())
