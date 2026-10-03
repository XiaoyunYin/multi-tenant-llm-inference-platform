import json
import unittest

from inference_platform.evidence_sanitize import sanitize_accounts


class EvidenceSanitizerTest(unittest.TestCase):
    def test_digest_numeric_runs_survive_structural_account_redaction(self):
        digest = "sha256:082ca6f035279109041ffd3fe0695cb568b29bc580b35c4f297a66a08b216c1b"
        arn = "arn:aws:iam::123456789012:role/pilot"
        text = f'{digest}\n{arn}\n{{"Account": "123456789012"}}\n--account=123456789012\n'
        result = sanitize_accounts(text)
        self.assertIn(digest, result)
        self.assertIn("arn:aws:iam::[account-redacted]:role/pilot", result)
        self.assertIn('"Account": "[account-redacted]"', result)
        self.assertIn("--account=[account-redacted]", result)
        self.assertEqual(
            sanitize_accounts("f123456789012abcd\n123456789012"), "f123456789012abcd\n123456789012"
        )
        self.assertEqual(sanitize_accounts(result), result)

    def test_cloudtrail_account_fields_and_numeric_json_remain_valid(self):
        document = {
            "userIdentity": {"accountId": "123456789012"},
            "recipientAccountId": "123456789012",
            "Account": 123456789012,
            "digest": "f123456789012abcd",
        }
        result = json.loads(sanitize_accounts(json.dumps(document)))
        self.assertEqual(result["userIdentity"]["accountId"], "[account-redacted]")
        self.assertEqual(result["recipientAccountId"], "[account-redacted]")
        self.assertEqual(result["Account"], "[account-redacted]")
        self.assertEqual(result["digest"], document["digest"])
