import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from inf060_operator_memory import COMMIT_MIN, PHYSICAL_MIN, record_launch_gate


class LaptopGateTests(unittest.TestCase):
    def test_exact_threshold_allows_requested_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "memory.json"
            result = record_launch_gate(
                path, requested="laptop", read=lambda: (PHYSICAL_MIN, COMMIT_MIN)
            )
            self.assertEqual(json.loads(path.read_bytes()), result)
            self.assertEqual(result["selected"], "laptop")

    def test_either_shortfall_refuses_laptop_and_preserves_aws_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "memory.json"
            for physical, commit in [
                (PHYSICAL_MIN - 1, COMMIT_MIN),
                (PHYSICAL_MIN, COMMIT_MIN - 1),
            ]:
                with self.subTest(physical=physical, commit=commit):

                    def read():
                        return physical, commit

                    with self.assertRaisesRegex(ValueError, "use_aws_operator"):
                        record_launch_gate(path, requested="laptop", read=read)
                    result = json.loads(path.read_bytes())
                    self.assertEqual(result["selected"], "aws")
                    self.assertEqual(result["free_physical_bytes"], physical)
                    self.assertEqual(result["available_commit_bytes"], commit)
                    self.assertEqual(
                        record_launch_gate(path, requested="aws", read=read)[
                            "selected"
                        ],
                        "aws",
                    )
