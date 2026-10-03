import json
import unittest
from pathlib import Path

from inference_platform.records import Outcome, OutcomeRecord
from inference_platform.workload import (
    WorkloadRequest,
    generate_workload,
    load_config,
    trace_digest,
    trace_jsonl,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = REPOSITORY_ROOT / "experiments" / "examples"
SCHEMAS = REPOSITORY_ROOT / "experiments" / "schema"


class CheckedInSchemaExampleTest(unittest.TestCase):
    def test_checked_in_trace_is_the_canonical_generated_trace(self) -> None:
        config = load_config(EXAMPLES / "workload-config.json")
        records = generate_workload(config)
        checked_in = (EXAMPLES / "workload-trace.synthetic.jsonl").read_text(encoding="utf-8")

        self.assertEqual(
            config.digest(), "ccd0f2d54714a5bccd64e2ead0b50421ba68f6412f6c0661a14c482b670c48a6"
        )
        self.assertEqual(
            trace_digest(records),
            "53ea74b2c96fceade3ec0a7a076bfe6e5d7c7552f3219674e6f004acd7f1e386",
        )
        self.assertEqual(checked_in, trace_jsonl(records))

    def test_synthetic_outcomes_are_strict_and_cover_every_outcome(self) -> None:
        lines = (
            (EXAMPLES / "request-outcomes.synthetic.jsonl").read_text(encoding="utf-8").splitlines()
        )
        records = [OutcomeRecord.from_dict(json.loads(line)) for line in lines]

        self.assertEqual({record.outcome for record in records}, set(Outcome))
        self.assertTrue(
            any(
                record.outcome is Outcome.PARTIAL_STREAM and record.first_content_offset_ns is None
                for record in records
            )
        )
        self.assertTrue(
            any(
                record.outcome is Outcome.COMPLETED and record.first_content_offset_ns is None
                for record in records
            )
        )

    def test_json_schema_keys_match_runtime_record_keys(self) -> None:
        config = load_config(EXAMPLES / "workload-config.json")
        request = generate_workload(config)[0]
        outcome_line = (
            (EXAMPLES / "request-outcomes.synthetic.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()[0]
        )
        outcome = OutcomeRecord.from_dict(json.loads(outcome_line))

        cases = (
            ("workload-config.v0.schema.json", set(config.to_dict())),
            ("workload-request.v0.schema.json", set(request.to_dict())),
            ("request-outcome.v0.schema.json", set(outcome.to_dict())),
        )
        for schema_name, runtime_keys in cases:
            with self.subTest(schema=schema_name):
                schema = json.loads((SCHEMAS / schema_name).read_text(encoding="utf-8"))
                self.assertFalse(schema["additionalProperties"])
                self.assertEqual(set(schema["properties"]), runtime_keys)
                self.assertEqual(set(schema["required"]), runtime_keys)

    def test_checked_in_trace_records_parse_strictly(self) -> None:
        lines = (
            (EXAMPLES / "workload-trace.synthetic.jsonl").read_text(encoding="utf-8").splitlines()
        )
        records = [WorkloadRequest.from_dict(json.loads(line)) for line in lines]

        self.assertEqual(len(records), 7)
        self.assertEqual([record.ordinal for record in records], list(range(7)))


if __name__ == "__main__":
    unittest.main()
