import copy
import importlib.util
import unittest
from pathlib import Path

from inference_platform.stage_c_digest import request_table

spec = importlib.util.spec_from_file_location(
    "digest_audit", Path(__file__).parents[1] / "audit_measurement_digests.py"
)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class MeasurementAuditTest(unittest.TestCase):
    def fixture(self):
        original = {
            "levels": [
                {
                    "concurrency": 2,
                    "records": [
                        {
                            "request_id": "a",
                            "outcome": "completed",
                            "http_status": 200,
                            "dispatch_offset_ns": 10,
                            "first_content_offset_ns": 30,
                            "completion_offset_ns": 100,
                            "prompt_tokens": 4,
                            "completion_tokens": 1,
                            "failure_class": "completed",
                        },
                        {
                            "request_id": "b",
                            "outcome": "rejected",
                            "http_status": 429,
                            "dispatch_offset_ns": None,
                            "first_content_offset_ns": None,
                            "completion_offset_ns": None,
                            "prompt_tokens": None,
                            "completion_tokens": None,
                            "failure_class": "not_dispatched",
                        },
                    ],
                }
            ]
        }
        # Derive classification from source, independently of the stored table labels.
        for record in original["levels"][0]["records"]:
            record["failure_class"] = audit.classification(record, None)
        events = [
            {
                "request_id": "a",
                "status": "observed",
                "routing_to_event_observation_ns": 25,
            }
        ]
        table = request_table(
            original,
            lambda row: (
                events[0] if row["request_id"] == "a" else {"status": "not_correlated"}
            ),
        )
        return (
            original,
            {"per_request": table, "event_lag": {"status": "established"}},
            events,
        )

    def test_missing_rows_and_changed_duration_class_count_or_lag_are_rejected(self):
        original, digest, events = self.fixture()
        count, report = audit.audit_table(original, digest, {}, events)
        self.assertEqual(count, 2)
        self.assertEqual(report[0]["requests"], 2)
        self.assertEqual(
            report[0]["event_lag_statuses"], {"observed": 1, "not_correlated": 1}
        )
        for field in (0, 1, 2, 3, 4, 5, 6, 7, 8):
            changed = copy.deepcopy(digest)
            changed["per_request"]["rows"][0][field] = "corrupted"
            with self.subTest(field=field), self.assertRaises(ValueError):
                audit.audit_table(original, changed, {}, events)
        for rows in ([], digest["per_request"]["rows"] * 2):
            changed = copy.deepcopy(digest)
            changed["per_request"]["rows"] = rows
            with self.assertRaises(ValueError):
                audit.audit_table(original, changed, {}, events)

    def test_percentiles_require_tail_support(self):
        self.assertNotIn("p99", audit.distribution(range(100)))
        self.assertIn("p99", audit.distribution(range(2001)))
        self.assertEqual(audit.distribution([None, 2, 10])["count"], 2)

    def test_explicit_level_paths_survive_json_sorted_object_keys(self):
        import json

        original, _, events = self.fixture()
        reference = copy.deepcopy(original["levels"][0]["records"][0])
        reference["request_id"] = "c"
        composite = {
            "saturation": original,
            "reference_capacity": {"records": [reference]},
        }
        table = request_table(
            composite,
            lambda row: (
                events[0] if row["request_id"] == "a" else {"status": "not_correlated"}
            ),
        )
        digest = {"per_request": table, "event_lag": {"status": "established"}}
        persisted = json.loads(json.dumps(composite, sort_keys=True))
        count, _ = audit.audit_table(persisted, digest, {}, events)
        self.assertEqual(count, 3)
        corrupted = copy.deepcopy(digest)
        corrupted["per_request"]["levels"][1] = corrupted["per_request"]["levels"][0]
        with self.assertRaises(ValueError):
            audit.audit_table(persisted, corrupted, {}, events)


if __name__ == "__main__":
    unittest.main()
