"""Sanitized receipts must describe coordinates, never matched values."""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import diagnose_snapshot_spans as diagnostic


class SpanDiagnosticTests(unittest.TestCase):
    def test_synthetic_rows_discard_original_digit_labels(self):
        left, right = b"744574457445", b"122312231223"
        self.assertEqual(
            left.translate(diagnostic.synthetic_translation(left)),
            right.translate(diagnostic.synthetic_translation(right)),
        )
        for value in (left, right, b"000000000000", b"012345678901"):
            self.assertNotEqual(
                value.translate(diagnostic.synthetic_translation(value)), value
            )

    def test_real_shape_masks_values_and_records_all_candidate_offsets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            name = "experiments/inf037a/kind-2026-10-02-r090/observations.json"
            value = "123456789012"
            data = ('{"time_unix_ns":' + value + "34}\n").encode()
            hit = {
                "File": "/source/" + name,
                "RuleID": "aws-account-id",
                "StartLine": 1,
                "EndLine": 1,
                "StartColumn": 1,
                "EndColumn": 12,
                "Match": value,
            }
            raw = root / ".cache/snapshot-scan-test/snapshot-tree.raw.json"
            raw.parent.mkdir(parents=True)
            raw.write_text(json.dumps([hit]))
            report = root / "report.json"
            report.write_text(
                json.dumps(
                    {
                        "scanner": {
                            "raw_sha256": hashlib.sha256(raw.read_bytes()).hexdigest()
                        },
                        "source_commit": "test",
                    }
                )
            )
            with (
                patch.object(diagnostic.builder, "blob", return_value=b"{}"),
                patch.object(
                    diagnostic.builder,
                    "source_files",
                    return_value={name: {"data": data}},
                ),
            ):
                diagnostic.diagnose(root, report, root / "output")
            receipt = json.loads(
                (root / "output/refused-row-coordinates.json").read_bytes()
            )
            self.assertEqual(receipt["rows"][0]["candidate_count"], 0)
            self.assertEqual(receipt["rows"][0]["line_occurrence_count"], 1)
            self.assertEqual(receipt["rows"][0]["nearest_line_occurrence_deltas"], [16])
            for path in (root / "output").iterdir():
                self.assertNotIn(value, path.read_text())
                self.assertNotIn("matched_sha256", path.read_text())

    def test_raw_file_must_match_the_real_scan_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "report.json"
            report.write_text(json.dumps({"scanner": {"raw_sha256": "wrong"}}))
            with self.assertRaisesRegex(ValueError, "raw_receipt_binding"):
                diagnostic.diagnose(root, report, root / "output")
