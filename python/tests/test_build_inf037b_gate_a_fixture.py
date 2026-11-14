from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import build_inf037b_gate_a_fixture as producer

from inference_platform.inf037b_gate_a import gate_a_binding


class GateAFixtureProducerTests(unittest.TestCase):
    def build_with_binding(self, source, binding):
        root = source.parent
        source_hashes = {"inf037b_gate_a.py": "a" * 64}
        proof_document = {"subject": "lifecycle:maximum_export_fixture"}
        observation = {
            "binding": binding,
            "maximum_fixture_proof": {"path": "maximum.json"},
            "artifacts": {"maximum.json": json.dumps(proof_document)},
        }

        def build_maximum(source, *, reset_ms, include_reset_capture):
            self.assertFalse(source.exists())
            self.assertGreater(reset_ms, 0)
            self.assertTrue(include_reset_capture)
            raw = source / "raw/client.jsonl"
            raw.parent.mkdir(parents=True)
            raw.write_bytes(b"\n" * 701_418)
            return {"spec": "fixture"}, 701_418

        with (
            patch.object(producer, "build_maximum", side_effect=build_maximum),
            patch.object(producer, "materialize_bundle"),
            patch.object(producer, "setup_fixture", return_value=object()),
            patch.object(producer, "attach", side_effect=lambda value: value),
            patch.object(producer, "observations", return_value=observation),
            patch.object(producer, "current_sources", return_value=source_hashes),
            patch.object(
                producer,
                "load_maximum",
                return_value={"source_lf_sha256": source_hashes},
            ),
            patch.object(
                producer,
                "produce_export_sizing_proof",
                return_value={"raw_bytes": 701_418, "reconnect_bound_ms": 15_000},
            ),
        ):
            return producer.build(
                source,
                root / "proof.json",
                root / "sizing.json",
                root / "specs.json",
            )

    def test_archive_builder_owns_creation_of_the_fixture_directory(self):
        with tempfile.TemporaryDirectory(prefix="gate-a-fixture-producer-") as temporary:
            root = Path(temporary)
            source = root / "fixture"
            result = self.build_with_binding(source, gate_a_binding())

            self.assertEqual(result["fixture_rows"], 701_418)
            self.assertTrue(source.is_dir())
            self.assertTrue((root / "proof.json").is_file())
            self.assertTrue((root / "sizing.json").is_file())
            self.assertTrue((root / "specs.json").is_file())

    def test_archive_builder_refuses_a_different_synthetic_binding(self):
        binding = gate_a_binding()
        binding["pins"]["configuration"] = "0" * 64
        with tempfile.TemporaryDirectory(prefix="gate-a-fixture-producer-refuse-") as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(ValueError, "gate_a_fixture:synthetic_binding"):
                self.build_with_binding(root / "fixture", binding)


if __name__ == "__main__":
    unittest.main()
