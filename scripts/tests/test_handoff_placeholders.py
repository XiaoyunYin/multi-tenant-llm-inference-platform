import subprocess
import tempfile
import unittest
from pathlib import Path

from check_handoff_placeholders import check, placeholders


class HandoffTests(unittest.TestCase):
    def test_only_unfilled_standalone_lines_refuse(self):
        self.assertEqual(
            placeholders("FINAL_CI_RESULT\n- `BASE_SHA`\n"),
            ["FINAL_CI_RESULT", "- `BASE_SHA`"],
        )
        self.assertEqual(
            placeholders("Status: READY_FOR_REVIEW\nBASE_SHA is recorded below.\n"), []
        )

    def test_historical_placeholders_are_preserved_new_ones_refuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            def git(*args):
                return subprocess.check_output(["git", "-C", str(root), *args])

            git("init", "-q")
            git("config", "user.name", "fixture")
            git("config", "user.email", "fixture@example.invalid")
            path = root / "REVIEW.md"
            path.write_text("OLD_TEMPLATE\n")
            git("add", ".")
            git("commit", "-qm", "fixture")
            path.write_text("OLD_TEMPLATE\nActual result recorded.\n")
            git("add", ".")
            self.assertEqual(check(root), [])
            path.write_text(path.read_text() + "FINAL_TEST_COUNTS\n")
            git("add", ".")
            self.assertEqual(check(root), ["FINAL_TEST_COUNTS"])
