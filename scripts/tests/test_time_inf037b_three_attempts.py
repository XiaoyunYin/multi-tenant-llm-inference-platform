"""Small producer-shape controls; never run registration-scale sizing."""

import importlib.util
import tempfile
import unittest
from pathlib import Path

from inference_platform.inf037b_archive import encode, inspect_segment
from inference_platform.inf037b_live import LiveRows
from inference_platform.inf037b_packet import Sanitizer
from inference_platform.inf037b_sources import validate_payload

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "three_attempts_shapes", ROOT / "scripts/time_inf037b_three_attempts.py"
)
TIMING = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TIMING)


class SizingLiveShapeTests(unittest.TestCase):
    def test_sizing_archive_contains_live_boundaries_and_generation_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "raw").mkdir()
            builder = LiveRows("synthetic", "boot", clock=lambda: 10_000_000)
            rows = [
                builder.row(
                    "kubernetes", "kube", "boot", "snapshot", {"resource_version": "1"}
                ),
                builder.row(
                    "kubernetes",
                    "kube",
                    "boot",
                    "pod_created",
                    {"pod_uid": "new", "slot": 0},
                ),
                builder.row(
                    "vllm",
                    "native",
                    "boot",
                    "sample",
                    {"process_generation": "first", "reset_generation": "first"},
                ),
            ]
            for row in rows:
                path = root / "raw" / (row["source_kind"] + ".jsonl")
                with path.open("ab") as stream:
                    stream.write(encode(row))
            self.assertEqual(TIMING.add_live_shapes(root), 1)
            output = [
                row
                for path in sorted((root / "raw").glob("*.jsonl"))
                for row in inspect_segment(path)[1]
            ]
            self.assertEqual(len(output), 4)
            self.assertEqual({row["source_generation"] for row in output}, {"0"})
            snapshot = next(r for r in output if r["payload"]["event"] == "snapshot")
            self.assertEqual(
                set(snapshot["payload"]["boundaries"]),
                {"pods_resource_version", "endpointslices_resource_version"},
            )
            cache = next(
                r
                for r in output
                if r["payload"].get("container_state") == "cache_observation"
            )
            self.assertEqual(
                cache["payload"]["boundaries"],
                {"cache_witness_ms_bounds": [8, 9], "creation_ms_bounds": [10, 10]},
            )
            native = next(r for r in output if r["source_kind"] == "vllm")
            self.assertEqual(native["payload"]["process_generation"], "0")
            self.assertEqual(native["payload"]["reset_generation"], "0")
            for row in output:
                validate_payload(row)
                validate_payload(
                    Sanitizer(b"synthetic-shape-validation-key-32").row(row)
                )


if __name__ == "__main__":
    unittest.main()
