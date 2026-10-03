import hashlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


CHECK = Path(__file__).resolve().parents[1] / "check_experiment_evidence.py"


class CommittedEvidenceTest(unittest.TestCase):
    def test_committed_copies_reject_bom_and_stale_checksum(self):
        for case in ("valid", "legacy-captures", "bom", "stale", "invalid-jsonl"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                subprocess.run(["git", "init", "-q", str(root)], check=True)
                (root / ".gitattributes").write_bytes(b"* -text\n")
                evidence = root / "experiments/inf011/session-copy"
                if case == "legacy-captures":
                    evidence /= "captures"
                evidence.mkdir(parents=True)
                data = b'{"result":"abort"}\n'
                if case == "bom":
                    data = b"\xef\xbb\xbf" + data
                digest = hashlib.sha256(data).hexdigest()
                if case == "stale":
                    digest = "0" * 64
                (evidence / "data.json").write_bytes(data)
                relative = (
                    "captures/data.json" if case == "legacy-captures" else "data.json"
                )
                (evidence / "SHA256SUMS.txt").write_bytes(
                    f"{digest}  {relative}\n".encode()
                )
                if case == "invalid-jsonl":
                    (evidence / "events.jsonl").write_bytes(b'{"x":NaN}\n')
                subprocess.run(["git", "-C", str(root), "add", "."], check=True)
                subprocess.run(
                    [
                        "git",
                        "-C",
                        str(root),
                        "-c",
                        "user.name=Evidence Test",
                        "-c",
                        "user.email=evidence@example.invalid",
                        "-c",
                        "commit.gpgsign=false",
                        "commit",
                        "-qm",
                        "copy fixture",
                    ],
                    check=True,
                )
                # A clean working file cannot conceal a bad committed blob.
                (evidence / "data.json").write_bytes(b'{"worktree":"different"}\n')
                result = subprocess.run(
                    [sys.executable, str(CHECK), "--root", str(root)],
                    capture_output=True,
                    text=True,
                )
                if case in ("valid", "legacy-captures"):
                    self.assertEqual(result.returncode, 0, result.stderr)
                else:
                    self.assertNotEqual(result.returncode, 0)
                    expected = {
                        "bom": "UTF-8 BOM",
                        "stale": "stale checksum",
                        "invalid-jsonl": "non-JSON constant",
                    }[case]
                    self.assertIn(expected, result.stderr)
                    print(
                        f"PASS: committed copy {case} rejected: {result.stderr.strip()}"
                    )


if __name__ == "__main__":
    unittest.main()
