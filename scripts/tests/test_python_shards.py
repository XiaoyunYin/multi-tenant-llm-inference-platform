import importlib.util
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "runner", Path(__file__).resolve().parents[1] / "run_python_tests.py"
)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class ShardTests(unittest.TestCase):
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
