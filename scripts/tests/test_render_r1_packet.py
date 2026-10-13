"""R1 provenance, public fallback and corrupted-input regression checks."""

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "r1_packet", Path(__file__).resolve().parents[1] / "render_r1_packet.py"
)
PACKET = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PACKET)


class R1PacketTest(unittest.TestCase):
    def test_projection_counts_and_paired_order(self):
        data = PACKET.read_data()
        self.assertEqual(
            [r["policy"] for r in data["rows"]],
            ["hash", "ll", "rr", "rr", "ll", "hash"],
        )
        self.assertEqual(
            [r["completed"] for r in data["rows"]], [6481, 5925, 6053, 6147, 5981, 6445]
        )
        compare = next(r for r in data["comparisons"] if r["policy"] == "hash")
        self.assertEqual(compare["exceeds"], [True, False])
        for key in ("TTFT", "resources", "input_sha256"):
            self.assertNotIn(key, json.dumps(data))

    def test_public_fallback_and_tamper_rejection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            dest = root / "experiments/r1/chart-data.json"
            dest.parent.mkdir(parents=True)
            dest.write_bytes(
                (PACKET.ROOT / "experiments/r1/chart-data.json").read_bytes()
            )
            with (
                patch.object(PACKET, "ROOT", root),
                patch.object(PACKET.subprocess, "run") as run,
            ):
                run.return_value.returncode = 1
                self.assertEqual(len(PACKET.read_data()["rows"]), 6)
                dest.write_bytes(dest.read_bytes() + b" ")
                with self.assertRaisesRegex(ValueError, "projection hash mismatch"):
                    PACKET.read_data()

    def test_present_history_cannot_fall_back_when_blob_read_fails(self):
        with (
            patch.object(PACKET.subprocess, "run") as run,
            patch.object(
                PACKET.subprocess,
                "check_output",
                side_effect=subprocess.CalledProcessError(128, "git"),
            ),
        ):
            run.return_value.returncode = 0
            with self.assertRaises(subprocess.CalledProcessError):
                PACKET.read_data()

    def test_changed_historical_blob_is_rejected(self):
        with (
            patch.object(PACKET.subprocess, "run") as run,
            patch.object(PACKET.subprocess, "check_output", return_value=b"{}"),
        ):
            run.return_value.returncode = 0
            with self.assertRaisesRegex(ValueError, "analysis hash mismatch"):
                PACKET.read_data()


if __name__ == "__main__":
    unittest.main()
