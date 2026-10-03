import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from inference_platform.workload import (
    WorkloadConfig,
    WorkloadRequest,
    generate_workload,
    load_config,
    main,
    trace_digest,
    trace_jsonl,
)


class WorkloadGenerationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.config = WorkloadConfig(
            run_id="unit-run",
            seed=1729,
            request_count=8,
            arrival_rate_rps=4.0,
            tenant_ids=("tenant-a", "tenant-b"),
            model="test-model",
            prefixes=("shared prefix alpha", "shared prefix beta"),
            max_tokens=32,
        )

    def test_same_seed_and_config_produce_byte_identical_trace(self) -> None:
        first = generate_workload(self.config)
        second = generate_workload(self.config)

        self.assertEqual(trace_jsonl(first), trace_jsonl(second))
        self.assertEqual(trace_digest(first), trace_digest(second))

    def test_changed_seed_changes_trace(self) -> None:
        changed = WorkloadConfig.from_dict({**self.config.to_dict(), "seed": 1730})

        self.assertNotEqual(
            trace_digest(generate_workload(self.config)),
            trace_digest(generate_workload(changed)),
        )

    def test_model_identifiers_allow_registry_paths(self) -> None:
        config = WorkloadConfig.from_dict(
            {**self.config.to_dict(), "model": "meta-llama/Llama-3.1:instruct"}
        )

        self.assertEqual(generate_workload(config)[0].model, config.model)

    def test_planned_offsets_are_monotonic_and_records_round_trip(self) -> None:
        records = generate_workload(self.config)
        offsets = [record.planned_arrival_offset_ns for record in records]

        self.assertEqual(offsets, sorted(offsets))
        self.assertEqual(offsets[0], 0)
        for record in records:
            self.assertEqual(WorkloadRequest.from_dict(record.to_dict()), record)
            self.assertEqual(record.configuration_digest, self.config.digest())

    def test_config_rejects_unknown_fields_and_invalid_values(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown"):
            WorkloadConfig.from_dict({**self.config.to_dict(), "tenant": "forged"})
        with self.assertRaisesRegex(ValueError, "arrival_rate_rps"):
            WorkloadConfig.from_dict({**self.config.to_dict(), "arrival_rate_rps": 0})
        with self.assertRaisesRegex(ValueError, "unique"):
            WorkloadConfig.from_dict(
                {**self.config.to_dict(), "tenant_ids": ["tenant-a", "tenant-a"]}
            )
        with self.assertRaisesRegex(ValueError, "prefixes must be unique"):
            WorkloadConfig.from_dict(
                {**self.config.to_dict(), "prefixes": ["duplicate", "duplicate"]}
            )

    def test_run_id_bound_preserves_generated_request_id_validity(self) -> None:
        accepted = WorkloadConfig.from_dict({**self.config.to_dict(), "run_id": "r" * 184})

        self.assertEqual(len(generate_workload(accepted)[0].request_id), 191)
        with self.assertRaisesRegex(ValueError, "run_id"):
            WorkloadConfig.from_dict({**self.config.to_dict(), "run_id": "r" * 185})

    def test_prefix_identity_is_content_derived_across_configurations(self) -> None:
        first = generate_workload(self.config)
        reordered = WorkloadConfig.from_dict(
            {**self.config.to_dict(), "prefixes": list(reversed(self.config.prefixes))}
        )
        second = generate_workload(reordered)
        first_ids = {
            record.messages[0]["content"].split("\n", maxsplit=1)[0]: record.prefix_id
            for record in first
        }
        second_ids = {
            record.messages[0]["content"].split("\n", maxsplit=1)[0]: record.prefix_id
            for record in second
        }

        self.assertEqual(first_ids.keys(), second_ids.keys())
        self.assertEqual(first_ids, second_ids)

    def test_cli_writes_exact_trace_and_validate_only_writes_no_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            config_path = root / "config.json"
            trace_path = root / "trace.jsonl"
            untouched_path = root / "untouched.jsonl"
            config_path.write_text(json.dumps(self.config.to_dict()), encoding="utf-8")

            self.assertEqual(main(["--config", str(config_path), "--output", str(trace_path)]), 0)
            self.assertEqual(
                trace_path.read_text(encoding="utf-8"), trace_jsonl(generate_workload(self.config))
            )

            with redirect_stdout(io.StringIO()):
                self.assertEqual(
                    main(
                        [
                            "--config",
                            str(config_path),
                            "--output",
                            str(untouched_path),
                            "--validate-only",
                        ]
                    ),
                    0,
                )
            self.assertFalse(untouched_path.exists())

    def test_load_config_rejects_non_object_json(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "config.json"
            path.write_text("[]", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "JSON object"):
                load_config(path)

    def test_load_config_rejects_duplicate_members(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "config.json"
            path.write_text('{"seed": 1, "seed": 2}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate JSON member"):
                load_config(path)


if __name__ == "__main__":
    unittest.main()
