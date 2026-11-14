import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "runner", Path(__file__).resolve().parents[1] / "run_python_tests.py"
)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class ShardTests(unittest.TestCase):
    def test_weighted_union_is_disjoint_collectors_isolated_and_ceilings_have_margin(
        self,
    ):
        from inference_platform.package_a_cpu_validation import SHARD_TEST_CEILINGS_S

        root = Path(__file__).resolve().parents[2] / "python/tests"
        shards = [runner.modules(root, i, 3, weighted=True) for i in range(3)]
        flattened = sum(shards, [])
        self.assertEqual(sorted(flattened), sorted(root.glob("test*.py")))
        self.assertEqual(len(flattened), len(set(flattened)))
        self.assertEqual([p.name for p in shards[0]], ["test_inf037b_collectors.py"])
        for paths, ceiling in zip(shards, SHARD_TEST_CEILINGS_S):
            weight = sum(runner.WEIGHTS_S[p.name] for p in paths)
            self.assertGreaterEqual(
                ceiling, runner.WEIGHT_DATA["ceiling_margin"] * weight
            )
        self.assertEqual(runner.WEIGHTS_S["test_inf037b_collectors.py"], 2436)
        self.assertEqual(SHARD_TEST_CEILINGS_S[0], 3660)

    def test_every_discovered_module_has_a_measured_weight_and_missing_is_an_error(
        self,
    ):
        root = Path(__file__).resolve().parents[2] / "python/tests"
        self.assertEqual(set(runner.WEIGHTS_S), {p.name for p in root.glob("test*.py")})
        for row in runner.WEIGHT_DATA["modules"].values():
            self.assertGreater(row["weight_s"], 0)
            self.assertIn("source", row)
            if "measured_tests" in row:
                self.assertEqual(row["measured_tests"]["failures"], 0)
                self.assertEqual(row["measured_tests"]["errors"], 0)
        with self.assertRaisesRegex(
            ValueError, "cpu_weights:missing:test_unmeasured.py"
        ):
            runner.weighted_shards([Path("test_unmeasured.py")], 3)

    def test_timeout_retains_immediate_errors_module_times_and_live_stack(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "quick.py").write_text(
                "import unittest\nclass Tests(unittest.TestCase):\n"
                " def test_error(self): raise RuntimeError('EARLY_ERROR')\n"
                " def test_failure(self): self.fail('EARLY_FAILURE')\n"
            )
            (root / "slow.py").write_text(
                "import unittest,time\nclass Tests(unittest.TestCase):\n"
                " def test_slow(self): time.sleep(30)\n"
            )
            code = "from cpu_test_runner import run_modules; run_modules(['quick','slow'], dump_after=0.2)"
            env = dict(
                os.environ,
                PYTHONPATH=os.pathsep.join(
                    [
                        str(root),
                        str(Path(__file__).resolve().parents[1]),
                        str(Path(__file__).resolve().parents[2] / "python/src"),
                    ]
                ),
            )
            with self.assertRaises(subprocess.TimeoutExpired) as caught:
                subprocess.run(
                    [sys.executable, "-c", code],
                    capture_output=True,
                    env=env,
                    timeout=2,
                )
            out = caught.exception.stdout.decode()
            err = caught.exception.stderr.decode()
            self.assertIn('"module_start": "quick"', out)
            self.assertIn('"module_finish": "quick"', out)
            self.assertIn('"open_descriptors":', out)
            self.assertIn('"module_start": "slow"', out)
            self.assertIn("EARLY_ERROR", err)
            self.assertIn("EARLY_FAILURE", err)
            self.assertIn("IMMEDIATE", err)
            self.assertIn("test_slow", err)

    def test_union_equals_discovery_without_duplicates_or_missing_modules(self):
        with tempfile.TemporaryDirectory() as root:
            for i in range(17):
                (Path(root) / f"test_{i:02}.py").touch()
            (Path(root) / "helper.py").touch()
            complete = runner.modules(root, 0, 1)
            shards = [runner.modules(root, i, 3) for i in range(3)]
            flattened = sum(shards, [])
            self.assertEqual(sorted(flattened), complete)
            self.assertEqual(len(flattened), len(set(flattened)))
            self.assertLessEqual(max(map(len, shards)) - min(map(len, shards)), 1)
        with self.assertRaises(ValueError):
            runner.modules(root, 3, 3)
