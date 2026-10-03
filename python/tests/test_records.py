import unittest

from inference_platform.records import Outcome, OutcomeRecord, TokenCountSource, content_digest


class OutcomeRecordTest(unittest.TestCase):
    def setUp(self) -> None:
        self.digest = content_digest({"seed": 1729})
        self.base = {
            "run_id": "unit-run",
            "request_id": "unit-run-000000",
            "tenant_id": "tenant-a",
            "model": "test-model",
            "policy": "round-robin",
            "planned_arrival_offset_ns": 0,
            "dispatch_offset_ns": 10,
            "first_content_offset_ns": 20,
            "completion_offset_ns": 30,
            "outcome": Outcome.COMPLETED,
            "http_status": 200,
            "error_code": None,
            "prompt_tokens": 10,
            "completion_tokens": 5,
            "token_count_source": TokenCountSource.RUNTIME_USAGE,
            "backend_id": "backend-a",
            "configuration_digest": self.digest,
        }

    def test_all_outcome_classes_have_valid_representations(self) -> None:
        records = [
            OutcomeRecord(**self.base),
            OutcomeRecord(
                **{
                    **self.base,
                    "outcome": Outcome.REJECTED,
                    "http_status": 429,
                    "error_code": "system_capacity",
                    "first_content_offset_ns": None,
                    "prompt_tokens": None,
                    "completion_tokens": None,
                    "token_count_source": None,
                    "backend_id": None,
                }
            ),
            OutcomeRecord(
                **{
                    **self.base,
                    "outcome": Outcome.CANCELLED,
                    "http_status": None,
                    "error_code": "client_cancelled",
                    "first_content_offset_ns": None,
                    "prompt_tokens": None,
                    "completion_tokens": None,
                    "token_count_source": None,
                    "backend_id": None,
                }
            ),
            OutcomeRecord(
                **{
                    **self.base,
                    "outcome": Outcome.FAILED_BEFORE_CONTENT,
                    "http_status": 503,
                    "error_code": "no_healthy_backend",
                    "first_content_offset_ns": None,
                    "prompt_tokens": None,
                    "completion_tokens": None,
                    "token_count_source": None,
                    "backend_id": None,
                }
            ),
            OutcomeRecord(
                **{
                    **self.base,
                    "outcome": Outcome.PARTIAL_STREAM,
                    "error_code": "stream_interrupted",
                    "completion_tokens": None,
                }
            ),
            OutcomeRecord(
                **{
                    **self.base,
                    "outcome": Outcome.NOT_DISPATCHED,
                    "dispatch_offset_ns": None,
                    "first_content_offset_ns": None,
                    "completion_offset_ns": None,
                    "http_status": None,
                    "error_code": "load_generator_drop",
                    "prompt_tokens": None,
                    "completion_tokens": None,
                    "token_count_source": None,
                    "backend_id": None,
                }
            ),
        ]

        self.assertEqual({record.outcome for record in records}, set(Outcome))
        for record in records:
            self.assertEqual(OutcomeRecord.from_dict(record.to_dict()), record)

    def test_monotonic_offsets_are_enforced(self) -> None:
        with self.assertRaisesRegex(ValueError, "planned arrival"):
            OutcomeRecord(
                **{
                    **self.base,
                    "planned_arrival_offset_ns": 10,
                    "dispatch_offset_ns": 5,
                }
            )
        with self.assertRaisesRegex(ValueError, "first content"):
            OutcomeRecord(**{**self.base, "completion_offset_ns": 15})

    def test_committed_streams_without_text_have_explicit_representations(self) -> None:
        empty_completion = OutcomeRecord(**{**self.base, "first_content_offset_ns": None})
        interrupted_before_text = OutcomeRecord(
            **{
                **self.base,
                "outcome": Outcome.PARTIAL_STREAM,
                "first_content_offset_ns": None,
                "error_code": "stream_interrupted",
                "prompt_tokens": None,
                "completion_tokens": None,
                "token_count_source": None,
            }
        )

        self.assertIsNone(empty_completion.ttft_ns())
        self.assertIsNone(interrupted_before_text.ttft_ns())
        self.assertEqual(OutcomeRecord.from_dict(empty_completion.to_dict()), empty_completion)
        self.assertEqual(
            OutcomeRecord.from_dict(interrupted_before_text.to_dict()),
            interrupted_before_text,
        )

    def test_rejection_and_failure_shapes_are_distinct(self) -> None:
        with self.assertRaisesRegex(ValueError, "4xx"):
            OutcomeRecord(
                **{
                    **self.base,
                    "outcome": Outcome.REJECTED,
                    "http_status": 503,
                    "error_code": "upstream_failure",
                    "first_content_offset_ns": None,
                    "prompt_tokens": None,
                    "completion_tokens": None,
                    "token_count_source": None,
                    "backend_id": None,
                }
            )
        with self.assertRaisesRegex(ValueError, "5xx"):
            OutcomeRecord(
                **{
                    **self.base,
                    "outcome": Outcome.FAILED_BEFORE_CONTENT,
                    "http_status": 429,
                    "error_code": "system_capacity",
                    "first_content_offset_ns": None,
                    "prompt_tokens": None,
                    "completion_tokens": None,
                    "token_count_source": None,
                }
            )

    def test_null_required_offsets_raise_value_error(self) -> None:
        for field in ("planned_arrival_offset_ns", "dispatch_offset_ns", "completion_offset_ns"):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "offset"):
                OutcomeRecord(**{**self.base, field: None})

    def test_completed_token_counts_require_provenance(self) -> None:
        with self.assertRaisesRegex(ValueError, "token_count_source"):
            OutcomeRecord(**{**self.base, "token_count_source": None})
        with self.assertRaisesRegex(ValueError, "TokenCountSource"):
            OutcomeRecord(**{**self.base, "token_count_source": "runtime_usage"})

    def test_unknown_fields_and_digest_format_are_rejected(self) -> None:
        record = OutcomeRecord(**self.base).to_dict()
        with self.assertRaisesRegex(ValueError, "unknown"):
            OutcomeRecord.from_dict({**record, "latency_ms": 1})
        with self.assertRaisesRegex(ValueError, "64 lowercase"):
            OutcomeRecord(**{**self.base, "configuration_digest": "not-a-digest"})
        with self.assertRaisesRegex(ValueError, "Outcome value"):
            OutcomeRecord(**{**self.base, "outcome": "completed"})


if __name__ == "__main__":
    unittest.main()
