import io
import json
import unittest
from unittest.mock import patch

from inference_platform.decision_export import export_decisions, gateway_terminal_unix_ns


class DecisionExportTest(unittest.TestCase):
    def test_terminal_timestamp_preserves_nanoseconds_and_timezone(self):
        for stamp in ("1970-01-01T00:00:10.123456789Z", "1970-01-01T01:00:10.123456789+01:00"):
            self.assertEqual(gateway_terminal_unix_ns({"time": stamp}), 10_123_456_789)
        with self.assertRaisesRegex(ValueError, "terminal timestamp"):
            gateway_terminal_unix_ns({})

    def test_export_carries_terminal_and_excludes_no_content_failures(self):
        for cause, committed, outcome, content, excluded in (
            ("upstream_failure", False, "failed_before_content", False, True),
            ("timeout", False, "failed_before_content", False, True),
            ("client_cancelled", False, "cancelled", False, True),
            ("client_cancelled", True, "cancelled", False, True),
            ("client_cancelled", True, "partial_stream", True, False),
            ("completed", True, "completed", True, False),
        ):
            with self.subTest(cause=cause, committed=committed, outcome=outcome):
                terminal = {
                    "msg": "request terminal",
                    "request_id": "request",
                    "router_decision_unix_ns": 10_000_000_000,
                    "time": "1970-01-01T00:00:11.123456789Z",
                    "cause": cause,
                    "committed": committed,
                }
                prompt = {
                    "request_id": "request",
                    "model": "model",
                    "messages": [],
                    "outcome": outcome,
                    "first_content_received": content,
                }
                with patch(
                    "inference_platform.decision_export.deadline_urlopen",
                    return_value=io.BytesIO(json.dumps({"tokens": list(range(32))}).encode()),
                ):
                    row = export_decisions([terminal], [prompt], "http://unused")[0]
                self.assertEqual(row["gateway_terminal_unix_ns"], 11_123_456_789)
                self.assertEqual(row["no_store_expected_request_failed"], excluded)


if __name__ == "__main__":
    unittest.main()
