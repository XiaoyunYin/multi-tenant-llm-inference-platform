import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from summarize_test_logs import negative_control, summarize, summarize_directory


class TestSummaryTest(unittest.TestCase):
    def test_summary_overrides_misleading_verbose_labels(self):
        text = "test_class ... skipped 'redirect'\n" * 58
        text += "\nRan 2239 tests in 1.234s\n\nOK (skipped=55)\n"
        self.assertEqual(
            summarize(text),
            {
                "framework": "unittest",
                "run": 2239,
                "pass": 2184,
                "skip": 55,
                "fail": 0,
            },
        )

    def test_multiple_summaries_and_failed_partition(self):
        result = summarize(
            "Ran 5 tests in 1s\n\nFAILED (failures=1, errors=1, skipped=1)\nRan 2 tests in 1s\n\nOK\n"
        )
        self.assertEqual(
            [result[k] for k in ("run", "pass", "skip", "fail")], [7, 4, 1, 2]
        )

    def test_go_terminal_summary_events_only(self):
        rows = [
            {"Action": "run", "Package": "p", "Test": "T"},
            {"Action": "output", "Package": "p", "Test": "T", "Output": "--- PASS"},
            {"Action": "pass", "Package": "p", "Test": "T"},
            {"Action": "skip", "Package": "p", "Test": "S"},
            {"Action": "fail", "Package": "p", "Test": "F"},
            {"Action": "pass", "Package": "p"},
        ]
        result = summarize("\n".join(map(json.dumps, rows)))
        self.assertEqual(
            [result[k] for k in ("run", "pass", "skip", "fail")], [3, 1, 1, 1]
        )
        with self.assertRaisesRegex(ValueError, "duplicate_go_terminal"):
            summarize("\n".join(map(json.dumps, rows + [rows[2]])))

    def test_missing_or_impossible_summary_refuses(self):
        for text in ("passed!", "Ran 1 test in 1s\n\nOK (skipped=2)"):
            with self.assertRaises(ValueError):
                summarize(text)

    def test_directory_separates_command_logs_and_refuses_invalid_partition(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "native.log").write_text("Ran 3 tests in 1s\n\nOK (skipped=1)\n")
            (root / "pull.log").write_text("Pulled pinned image\n")
            result = summarize_directory(root)
            self.assertTrue(result["partitions_valid"])
            self.assertEqual(result["framework_logs"]["native.log"]["pass"], 2)
            self.assertEqual(result["non_test_logs"], ["pull.log"])
            (root / "native.log").write_text("Ran 1 test in 1s\n\nOK (skipped=2)\n")
            with self.assertRaisesRegex(ValueError, "invalid_partition"):
                summarize_directory(root)

    def test_verified_killed_subtest_control_is_separate_from_suite_counts(self):
        data = b"Ran 6 tests in 1.631s\n\nFAILED (failures=5, errors=3)\n"
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "native.log").write_text("Ran 3 tests in 1s\n\nOK\n")
            (root / "mutant.log").write_bytes(data)
            receipt = {
                "schema": "r305-default-mutant-probe-v1",
                "all_killed": True,
                "mutants": {
                    "nested_boundary_vocabulary": {
                        "log_path": "mutant.log",
                        "exit_code": 1,
                        "killed": True,
                        "log_sha256": hashlib.sha256(data).hexdigest(),
                    }
                },
            }
            (root / "receipt.json").write_text(json.dumps(receipt))
            result = summarize_directory(root)
            self.assertEqual(set(result["framework_logs"]), {"native.log"})
            self.assertEqual(result["framework_logs"]["native.log"]["pass"], 3)
            self.assertFalse(
                result["negative_control_logs"]["mutant.log"]["counted_as_test"]
            )
            self.assertTrue(result["partitions_valid"])
            (root / "receipt.json").unlink()
            with self.assertRaisesRegex(ValueError, "invalid_partition"):
                summarize_directory(root)

    def test_negative_control_requires_exact_hash_nonzero_exit_and_killed_receipt(self):
        data = b"Ran 6 tests in 1s\n\nFAILED (failures=5, errors=3)\n"
        original = {
            "log_path": "mutant.log",
            "exit_code": 1,
            "killed": True,
            "log_sha256": hashlib.sha256(data).hexdigest(),
        }
        for patch in ({"log_sha256": "0" * 64}, {"exit_code": 0}, {"killed": False}):
            with self.subTest(patch=patch):
                receipt = {
                    "schema": "r305-default-mutant-probe-v1",
                    "all_killed": True,
                    "mutants": {"nested": dict(original, **patch)},
                }
                with self.assertRaisesRegex(ValueError, "negative_control_receipt"):
                    negative_control("mutant.log", data, receipt)
        receipt = {
            "schema": "r305-default-mutant-probe-v1",
            "all_killed": False,
            "mutants": {"nested": original},
        }
        with self.assertRaisesRegex(ValueError, "negative_control_receipt"):
            negative_control("mutant.log", data, receipt)
        self.assertIsNone(negative_control("unrelated.log", data, receipt))
