"""INF-060 GPU-specific packet budgets and guarded operator sequence."""

import json
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from inf060_eks_gpu_plan import require_streaming_quota, write_gpu_streaming_module
from inf060_eks_operator import execute_streaming
from inference_platform.inf060_eks_packet import (
    ARCHIVE_BYTES,
    CLEANUP_SECONDS,
    PHASE_WAITS,
    bound,
    load_corpus,
    require_window_budget,
    seal_timing,
)
from inference_platform.m5_descriptive_operator import session_timing


def probe(rate):
    return {
        "passes": {
            label: {
                "bytes": ARCHIVE_BYTES,
                "resume_offset": ARCHIVE_BYTES // 2 if label == "resumed" else 0,
                "elapsed_s": ARCHIVE_BYTES / (rate + 0.5),
                "rate_bytes_per_s": rate,
            }
            for label in ("cold", "resumed")
        },
        "worst_rate_bytes_per_s": rate,
    }


class GpuStreamingTests(unittest.TestCase):
    def test_component_sum_and_window_guard(self):
        timing = seal_timing(session_timing(640, 220), laptop_rate=150_000)
        self.assertEqual(sum(PHASE_WAITS.values()), 3600)
        self.assertEqual(sum(timing["streaming_components"].values()), 18000)
        self.assertEqual(timing["retrieval_reserve_seconds"], 1912)
        threshold = PHASE_WAITS["8"] + 1912 + CLEANUP_SECONDS
        require_window_budget("8", threshold, 150_000, 150_000)
        with self.assertRaisesRegex(TimeoutError, "streaming_window_guard:8"):
            require_window_budget("8", threshold - 1, 150_000, 150_000)
        with self.assertRaisesRegex(ValueError, "streaming_final_transfer_reserve"):
            seal_timing(session_timing(640, 220), laptop_rate=1000)

    def test_module_transform_and_corrupted_corpus(self):
        with tempfile.TemporaryDirectory() as tmp:
            copied = Path(tmp) / "main.tf"
            copied.write_bytes(b'each.key == "vpc-cni" && var.cpu_clock_rehearsal ?')
            write_gpu_streaming_module(copied)
            self.assertEqual(copied.read_bytes(), b'each.key == "vpc-cni" ?')
            with self.assertRaisesRegex(ValueError, "streaming_vpc_cni_source_binding"):
                write_gpu_streaming_module(copied)
            with self.assertRaisesRegex(ValueError, "streaming_corpus_digest"):
                load_corpus(copied, "0" * 64, ("smoke",))

    def test_busy_gpu_refuses_even_if_limit_were_increased(self):
        readback = {
            "gpu": {"fits": True, "running_vcpus": 4},
            "standard": {"fits": True},
        }
        with self.assertRaisesRegex(ValueError, "streaming_gpu_quota_busy"):
            require_streaming_quota(readback)

    def test_operator_preserves_checkpoints_when_window_eight_refuses(self):
        rate = 150_000
        original_end = time.time() + 18000
        manifest = {
            "account": "fixture",
            "timing": seal_timing(session_timing(640, 220), laptop_rate=rate),
            "descriptive": {
                "gpu_streaming": True,
                "streaming": {"laptop_transfer": probe(rate), "gpu_hourly_usd": 0},
            },
            "forecast_basis": {"hourly_usd": 0, "fixed_other_usd": 0, "margin": 1},
        }
        trace = []

        def remote(phase):
            trace.append(phase)
            if phase == "stream-transfer-probe":
                return probe(rate)
            if phase == "stream-snapshot-3":
                # Make the clock reach the point where level 8 no longer fits.
                ports.end = (
                    time.time()
                    + PHASE_WAITS["8"]
                    + 2 * bound(ARCHIVE_BYTES, rate)
                    + CLEANUP_SECONDS
                    - 1
                )
            return {"bytes": 4096}

        def retrieve(_host, label, expected, dest, _deadline, _account_hash, on_bytes):
            dest.mkdir()
            (dest / "manifest.json").write_text("{}")
            on_bytes(expected["bytes"])
            return {"status": "verified", **expected}, {"complete": label == "final"}

        def lifecycle(label):
            trace.append(label)
            return {"complete": True}

        ports = SimpleNamespace(
            manifest=manifest,
            end=original_end,
            host=None,
            remote=remote,
            provision=lambda: lifecycle("provision"),
            teardown=lambda: lifecycle("teardown"),
            inventory=lambda: lifecycle("inventory"),
        )
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch("inf060_eks_operator.retrieve", side_effect=retrieve),
            patch("inf060_eks_operator.attach_local"),
        ):
            output = Path(tmp) / "execution"
            with self.assertRaisesRegex(TimeoutError, "streaming_window_guard:8"):
                execute_streaming(ports, output)
            self.assertFalse("stream-window-8" in trace)
            self.assertEqual(trace[-3:], ["stream-partial", "teardown", "inventory"])
            for label in ("0.25", "1", "3"):
                self.assertTrue(
                    (output / ("results-" + label) / "manifest.json").is_file()
                )
            totals = json.loads((output / "retrieval.json").read_bytes())["totals"]
            self.assertEqual(totals["laptop_operator_archive_bytes"], 4 * 4096)
