"""Three source mutants for R389; input mutants c/e/f live in test_inf037b_engine."""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEST = "test_l4_round281.LaunchParity.test_eks_argv_and_environment"


def run(output):
    results = []
    for name, module in (
        ("a-delete-max-num-seqs", "eks_deployment"),
        ("b-delete-generation-config", "eks_deployment"),
        ("d-shared-max-num-seqs-256", "r1_spec"),
    ):
        source = (ROOT / f"python/src/inference_platform/{module}.py").read_text(
            encoding="utf-8"
        )
        if module == "eks_deployment":
            flag = "--max-num-seqs" if name.startswith("a-") else "--generation-config"
            source += f"""\n_original_engine_argv = engine_argv
def engine_argv():
    args = _original_engine_argv()
    index = args.index({flag!r})
    del args[index:index + 2]
    return args
"""
        else:
            assert source.count('"max_num_seqs": 16,') == 1
            source = source.replace('"max_num_seqs": 16,', '"max_num_seqs": 256,')
        with tempfile.TemporaryDirectory(prefix="r389-mutant-") as temp:
            package_root = Path(temp) / "python/src"
            package = package_root / "inference_platform"
            package.mkdir(parents=True)
            observer = Path(temp) / "deploy/eks/node_observer.py"
            observer.parent.mkdir(parents=True)
            shutil.copyfile(ROOT / "deploy/eks/node_observer.py", observer)
            (package / "__init__.py").write_text(
                "__path__.append("
                + repr(str(ROOT / "python/src/inference_platform"))
                + ")\n",
                encoding="utf-8",
            )
            target = package / (module + ".py")
            target.write_text(source, encoding="utf-8")
            env = {
                **os.environ,
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONPATH": os.pathsep.join(
                    map(
                        str,
                        (
                            package_root,
                            ROOT / "python/tests",
                            ROOT / "scripts",
                            ROOT / "scripts/tests",
                        ),
                    )
                ),
            }
            code = f"""import importlib, pathlib, unittest
m = importlib.import_module("inference_platform.{module}")
assert pathlib.Path(m.__file__).resolve() == pathlib.Path({str(target)!r}).resolve()
suite = unittest.defaultTestLoader.loadTestsFromName({TEST!r})
result = unittest.TextTestRunner(verbosity=0).run(suite)
assert result.testsRun == 1 and not result.errors and len(result.failures) == 1
"""
            completed = subprocess.run(
                [sys.executable, "-B", "-c", code],
                env=env,
                cwd=ROOT,
                capture_output=True,
                timeout=60,
            )
            if completed.returncode:
                raise RuntimeError(
                    name + ": " + completed.stderr.decode(errors="replace")
                )
            results.append(
                {
                    "mutant": name,
                    "killed": True,
                    "killer": TEST,
                    "import_identity_asserted": True,
                    "assertion_failures": 1,
                }
            )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps({"source_mutants": results, "provider_calls": 0}, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"R389 source mutants: {len(results)}/{len(results)} killed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    run(parser.parse_args().output)
