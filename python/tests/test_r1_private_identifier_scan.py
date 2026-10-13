import hashlib
import unittest

from inference_platform.private_identifier_scan import find_identifier_violations


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


if __name__ == "__main__":
    unittest.main()
