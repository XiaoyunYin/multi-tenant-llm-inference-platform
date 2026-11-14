import hashlib
import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "guard", Path(__file__).parents[1] / "evidence_binary_guard.py"
)
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class BinaryEvidenceTest(unittest.TestCase):
    def test_committed_new_binary_rejected_history_retained_and_allowlist_exact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def run(*args):
                return subprocess.check_output(["git", "-C", str(root), *args])

            run("init", "-q")
            run("config", "user.name", "Evidence Test")
            run("config", "user.email", "test@example.invalid")
            (root / "experiments").mkdir()
            (root / "experiments/old.bin").write_bytes(b"\0" * (guard.LIMIT + 1))
            run("add", ".")
            run("commit", "-qm", "baseline", "--no-gpg-sign")
            base = run("rev-parse", "HEAD").decode().strip()
            data = b"\0" * guard.LIMIT + b"\1"
            (root / "experiments/new.bin").write_bytes(data)
            run("add", ".")
            tree = run("write-tree").decode().strip()
            with self.assertRaisesRegex(ValueError, "new.bin"):
                guard.check(root, base, tree)
            allowed = {
                "experiments/new.bin": {
                    "bytes": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
            }
            self.assertEqual(
                guard.check(root, base, tree, allowed)["large_binary_allowlisted"], 1
            )
            allowed["experiments/new.bin"]["sha256"] = "0" * 64
            with self.assertRaises(ValueError):
                guard.check(root, base, tree, allowed)
            run("commit", "-qm", "large binary", "--no-gpg-sign")
            run("rm", "experiments/new.bin")
            run("commit", "-qm", "delete large binary", "--no-gpg-sign")
            with patch.object(
                guard.subprocess, "run", wraps=subprocess.run
            ) as commands:
                with self.assertRaisesRegex(ValueError, "new.bin"):
                    guard.check(root, base, "HEAD")
            batch = [
                call
                for call in commands.call_args_list
                if any(str(arg).startswith("--batch-check=") for arg in call.args[0])
            ]
            self.assertEqual(len(batch), 1)
            self.assertGreater(len(batch[0].kwargs["input"].splitlines()), 1)
            self.assertFalse(
                any("-s" in call.args[0] for call in commands.call_args_list)
            )
            (root / "experiments/new.bin").write_bytes(b"\0" * guard.LIMIT)
            run("add", ".")
            self.assertEqual(
                guard.check(root, base, run("write-tree").decode().strip())[
                    "large_binary_allowlisted"
                ],
                0,
            )
