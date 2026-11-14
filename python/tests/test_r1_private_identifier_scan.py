import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from inference_platform.private_identifier_scan import (
    check_staged_repo,
    find_identifier_violations,
)


class PrivateIdentifierScanTests(unittest.TestCase):
    def test_matches_only_the_account_id_bound_by_hash(self):
        account = b"123456789012"
        digest = hashlib.sha256(account).hexdigest()
        findings = find_identifier_violations(
            {
                "docs/evidence/old.json": b'{"account":"123456789012"}',
                "docs/evidence/other.json": b'{"request":"109876543210"}',
            },
            digest,
        )
        self.assertEqual(
            findings,
            ["docs/evidence/old.json:1: token matches bound AWS account hash"],
        )
        self.assertNotIn(account.decode(), "\n".join(findings))

    def test_rejects_iam_account_arns_only_under_evidence(self):
        findings = find_identifier_violations(
            {
                "docs/evidence/status.json": b'{"arn":"arn:aws:iam::123456789012:user/test"}',
                "docs/notes.md": b"arn:aws:iam::123456789012:user/test",
            },
            "0" * 64,
        )
        self.assertEqual(
            findings,
            ["docs/evidence/status.json:1: IAM account ARN in evidence"],
        )

    def test_staged_tree_refuses_fake_iam_arn_before_commit(self):
        hook = Path(__file__).resolve().parents[2] / ".githooks/pre-commit"
        self.assertIn('check_private_identifiers.py" --staged', hook.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "docs/evidence").mkdir(parents=True)
            (root / "docs/R1_SESSION_INPUTS.json").write_text(
                json.dumps({"account_id_sha256": "0" * 64}), encoding="utf-8"
            )

            def git(*args):
                return subprocess.check_output(["git", "-C", str(root), *args])

            git("init", "--quiet")
            git("config", "user.name", "Private scan test")
            git("config", "user.email", "private-scan-test@example.invalid")
            git("add", "docs/R1_SESSION_INPUTS.json")
            git("commit", "--quiet", "-m", "safe scanner input")

            candidate = root / "docs/evidence/fake.json"
            candidate.write_text(
                '{"arn":"arn:aws:iam::123456789012:role/fake"}\n', encoding="utf-8"
            )
            git("add", "docs/evidence/fake.json")
            tracked, findings = check_staged_repo(root)
            self.assertEqual(tracked, 2)
            self.assertEqual(
                findings,
                ["docs/evidence/fake.json:1: IAM account ARN in evidence"],
            )
            with patch.object(
                sys,
                "argv",
                ["check_private_identifiers.py", "--root", str(root), "--staged"],
            ):
                from scripts.check_private_identifiers import main

                with self.assertRaises(SystemExit) as stopped:
                    main()

        self.assertEqual(stopped.exception.code, 1)


if __name__ == "__main__":
    unittest.main()
