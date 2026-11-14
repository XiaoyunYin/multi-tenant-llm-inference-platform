"""Real local Git integration for the port proof reader (no remote calls)."""

import subprocess
import tempfile
import unittest
from pathlib import Path

from inference_platform.inf037b_ports import GitReviewSource


class GitSourceTests(unittest.TestCase):
    def test_real_git_uses_committed_blob_and_rejects_unknown_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", str(root)], check=True)

            def git(*args):
                return subprocess.check_output(["git", "-C", str(root), *args]).decode().strip()

            (root / "REVIEW.md").write_bytes(b"committed fixture\n")
            git("add", "REVIEW.md")
            git(
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "commit",
                "-qm",
                "fixture",
            )
            head = git("rev-parse", "HEAD")
            (root / "REVIEW.md").write_bytes(b"uncommitted change\n")
            source = GitReviewSource(root)
            self.assertEqual(source(head, head), b"committed fixture\n")
            with self.assertRaises(subprocess.CalledProcessError):
                source("0" * 40, head)


if __name__ == "__main__":
    unittest.main()
