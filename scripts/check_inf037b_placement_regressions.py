"""Run every newly added placement test against exact pre-fix module bytes.

The child imports a scratch copy of python/, never the editable installation.
The receipt confirms __file__, source hashes and each individual baseline failure.
"""

import argparse
import ast
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = "3550022d3afda4048348406eb74e85b423505fb7"
MODULE = "python/src/inference_platform/inf037b_placement.py"
TESTS = "python/tests/test_inf037b_placement.py"
CHILD = """
import contextlib, hashlib, io, json, sys, unittest
from pathlib import Path
scratch = Path(sys.argv[1]).resolve()
sys.path[:0] = [str(scratch / 'src'), str(scratch / 'tests')]
import inference_platform.inf037b_placement as placement
import test_inf037b_placement as tests
expected = scratch / 'src/inference_platform/inf037b_placement.py'
assert Path(placement.__file__).resolve() == expected
print('__file__ confirmed: ' + placement.__file__, file=sys.stderr)
rows = []
for name in json.loads(sys.argv[2]):
    stream = io.StringIO()
    with contextlib.redirect_stderr(stream), contextlib.redirect_stdout(stream):
        result = unittest.TextTestRunner(stream=stream).run(tests.PlacementTests(name))
    rows.append(dict(test=name, failed_at_baseline=not result.wasSuccessful(),
                     failures=len(result.failures), errors=len(result.errors),
                     skips=len(result.skipped)))
print(json.dumps(dict(module_file_relative_to_scratch=str(expected.relative_to(scratch)).replace('\\\\', '/'),
    module_file_confirmed=True, placement_sha256=hashlib.sha256(expected.read_bytes()).hexdigest(),
    tests=rows)))
"""


def git_bytes(base, path):
    return subprocess.check_output(["git", "show", f"{base}:{path}"], cwd=ROOT)


def names(source):
    return {
        node.name
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default=BASE)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    baseline = git_bytes(args.base, MODULE)
    current_tests = (ROOT / TESTS).read_bytes()
    added = sorted(names(current_tests) - names(git_bytes(args.base, TESTS)))
    if not added:
        raise SystemExit("no new tests found")
    with tempfile.TemporaryDirectory(prefix="inf037b-placement-") as directory:
        scratch = Path(directory) / "python"
        shutil.copytree(
            ROOT / "python",
            scratch,
            ignore=shutil.ignore_patterns(
                ".venv", "__pycache__", "*.egg-info", ".ruff_cache"
            ),
        )
        (scratch / "src/inference_platform/inf037b_placement.py").write_bytes(baseline)
        result = subprocess.run(
            [sys.executable, "-c", CHILD, str(scratch), json.dumps(added)],
            check=True,
            capture_output=True,
            text=True,
            cwd=directory,
        )
        print(result.stderr, end="")
        receipt = json.loads(result.stdout)
    assert receipt["placement_sha256"] == hashlib.sha256(baseline).hexdigest()
    receipt.update(
        baseline_commit=args.base,
        tests_lf_sha256=hashlib.sha256(
            current_tests.replace(b"\r\n", b"\n")
        ).hexdigest(),
        command=f"uv run --project python --locked python scripts/check_inf037b_placement_regressions.py --base {args.base} --output {args.output.as_posix()}",
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(receipt, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    for row in receipt["tests"]:
        print(json.dumps(row))
    return any(
        not row["failed_at_baseline"] or row["skips"] for row in receipt["tests"]
    )


if __name__ == "__main__":
    sys.exit(main())
