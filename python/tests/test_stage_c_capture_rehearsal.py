import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from inference_platform.stage_c_capture_rehearsal import rehearse


class CaptureRehearsalTest(unittest.TestCase):
    def run_rehearsal(self, root, events):
        def run(argv, **kwargs):
            stdout = ""
            code = 0
            if argv[:2] == ["docker", "inspect"]:
                if "--format" in argv:
                    stdout = "sha256:local-fixture\n"
                else:
                    code = 1
            elif argv[:2] == ["docker", "run"]:
                destination = root / "output"
                (destination / "capture.json").write_text(
                    json.dumps({"stream_files": {"observations": "capture.observations.jsonl"}})
                )
                (destination / "capture.observations.jsonl").write_text(
                    "".join(json.dumps({"event_type": e}) + "\n" for e in events)
                )
                (destination / "capture.correlations.jsonl").write_text("")
            elif "--readiness-probe" in argv:
                stdout = json.dumps({"decoded_block_stored_count": 1})
            return SimpleNamespace(returncode=code, stdout=stdout, stderr="")

        process = Mock(returncode=0)
        with (
            patch("inference_platform.stage_c_capture_rehearsal.subprocess.run", side_effect=run),
            patch("inference_platform.stage_c_capture_rehearsal.stage_capture_package"),
            patch(
                "inference_platform.stage_c_capture_rehearsal.start_live_capture",
                return_value=process,
            ),
        ):
            return rehearse(root / "sources", root / "output")

    def test_streamed_capture_without_inline_observations_is_verified(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            receipt = self.run_rehearsal(root, ["BlockStored", "BlockRemoved", "BlockStored"])
            self.assertEqual(receipt["continuous_decoded_block_stored_count"], 2)
            self.assertEqual(receipt["status"], "passed")
            self.assertTrue((root / "output/capture.correlations.jsonl").exists())

    def test_empty_stored_event_stream_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(RuntimeError, "decoded no BlockStored"):
                self.run_rehearsal(Path(temporary), ["BlockRemoved"])
