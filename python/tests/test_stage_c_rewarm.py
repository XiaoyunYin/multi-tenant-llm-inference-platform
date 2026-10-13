import gzip
import json
import random
import tarfile
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from inference_platform.calibration import derive_runtime_regime
from inference_platform.disk_records import write_json
from inference_platform.stage_c import StageCConfig, _run_rewarm
from inference_platform.stage_c_digest import DIGEST_LIMIT, FINAL_LIMIT, compact, seal_digest
from inference_platform.stage_c_session import export

QUERIES = 'native:vllm:prefix_cache_queries_total{model_name="test",engine="0"}'
HITS = 'native:vllm:prefix_cache_hits_total{model_name="test",engine="0"}'


class RewarmCounterTest(unittest.TestCase):
    def rewarm(self, *, post_scrape_error=False):
        state = {"repeat": 0, "sample": 0, "queries": 0, "hits": 0}

        def reset(*_):
            state.update(repeat=state["repeat"] + 1, sample=0, queries=100, hits=50)

        def metrics(*_):
            if post_scrape_error and threading.current_thread().name != "calibration-metrics":
                return {"error": "BudgetExhausted"}
            return {"values": {QUERIES: state["queries"], HITS: state["hits"]}}

        def request(_config, _digest, start_ns, *_args):
            state["queries"] += 160
            state["hits"] += 144 if state["sample"] else 0
            state["sample"] += 1
            return {
                "dispatch_offset_ns": time.perf_counter_ns() - start_ns,
                "first_content_offset_ns": 1,
                "http_status": 200,
                "outcome": "completed",
            }

        result = {}
        config = StageCConfig(
            "http://unused",
            "token",
            "tenant",
            "test",
            "rewarm",
            "http://unused",
            "http://unused",
            sample_interval_ms=10000,
        )
        with (
            patch("inference_platform.stage_c._reset_prefix_cache", side_effect=reset),
            patch("inference_platform.calibration._metrics", side_effect=metrics),
            patch("inference_platform.calibration._stream_request", side_effect=request),
        ):
            _run_rewarm(config, "run3", time.perf_counter() + 30, result)
        self.assertEqual(state["repeat"], 3)
        return result

    def test_each_request_has_bracketed_counters_even_with_no_inflight_scrape(self):
        result = self.rewarm()
        for repeat in result["repeats"]:
            self.assertEqual(len(repeat["run"]["levels"]), 8)
            for index, level in enumerate(repeat["run"]["levels"]):
                counters = level["runtime_regime"]["prefix_cache_counters"]
                self.assertEqual(
                    counters["queries"],
                    {
                        "before": 100 + index * 160,
                        "after": 260 + index * 160,
                        "delta": 160,
                        "status": "observed",
                    },
                )
                self.assertEqual(
                    counters["hits"],
                    {
                        "before": 50 + max(0, index - 1) * 144,
                        "after": 50 + index * 144,
                        "delta": 144 if index else 0,
                        "status": "observed",
                    },
                )
                self.assertLess(counters["before_offset_ns"], counters["after_offset_ns"])
                self.assertEqual(len(level["metrics"]), 2)

    def test_failed_post_scrape_preserves_levels_with_unavailable_counters(self):
        result = self.rewarm(post_scrape_error=True)
        for repeat in result["repeats"]:
            self.assertEqual(len(repeat["run"]["levels"]), 8)
            for level in repeat["run"]["levels"]:
                for name in ("queries", "hits"):
                    counter = level["runtime_regime"]["prefix_cache_counters"][name]
                    self.assertIsNotNone(counter["before"])
                    self.assertIsNone(counter["after"])
                    self.assertIsNone(counter["delta"])
                    self.assertEqual(counter["status"], "unavailable")

    def test_missing_invalid_reset_and_changed_series_have_no_delta(self):
        def sample(values):
            return {"offset_ns": 0, "values": values}

        for rows, status in (
            ([], "unavailable"),
            ([{QUERIES: 10, HITS: 5}], "unavailable"),
            ([{QUERIES: 10}, {QUERIES: 20}], "unavailable"),
            ([{HITS: 5}, {}], "unavailable"),
            ([{HITS: -1}, {HITS: 5}], "unavailable"),
            ([{HITS: float("nan")}, {HITS: 5}], "unavailable"),
            ([{HITS: 5}, {HITS: 0}, {HITS: 10}], "counter_reset"),
            ([{HITS: 5}, {HITS.replace('engine="0"', 'engine="1"'): 10}], "unavailable"),
            # Summed counters rise even though one labelled engine resets.
            (
                [
                    {HITS: 5, HITS.replace('engine="0"', 'engine="1"'): 10},
                    {HITS: 0, HITS.replace('engine="0"', 'engine="1"'): 20},
                ],
                "counter_reset",
            ),
        ):
            with self.subTest(rows=rows):
                regime = derive_runtime_regime(
                    [sample(row) for row in rows], include_prefix_cache_counters=True
                )
                self.assertEqual(regime["prefix_cache_counters"]["hits"]["status"], status)
                self.assertIsNone(regime["prefix_cache_counters"]["hits"]["delta"])

    def test_counter_summary_survives_digest_degradation_and_final_export(self):
        result = self.rewarm()
        expected = compact(result, measurements=False)
        rng = random.Random(129)
        result["metrics"] = [
            {"offset_ns": i, "values": {f"vllm:fixture_{j}": rng.random() for j in range(8)}}
            for i in range(20000)
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            digest = root / "run-3.digest.json.gz"
            receipt = seal_digest(
                digest, {"run": compact(result), "event_lag": {"status": "unavailable"}}
            )
            retained = json.loads(gzip.decompress(digest.read_bytes()))
            self.assertGreater(
                retained["detail_degradation"]["original_compressed_bytes"], DIGEST_LIMIT
            )
            self.assertTrue(retained["detail_degradation"]["native_sample_detail_dropped"])
            self.assertLessEqual(receipt["bytes"], DIGEST_LIMIT)
            for actual_repeat, expected_repeat in zip(
                retained["run"]["repeats"], expected["repeats"], strict=True
            ):
                for actual, wanted in zip(
                    actual_repeat["run"]["levels"], expected_repeat["run"]["levels"], strict=True
                ):
                    self.assertEqual(
                        actual["runtime_regime"]["prefix_cache_counters"],
                        wanted["runtime_regime"]["prefix_cache_counters"],
                    )
            write_json(root / "stage-c-summary.json", expected)
            write_json(root / "manifest.json", {})
            self.assertLessEqual(export(root, root / "manifest.json")["bytes"], FINAL_LIMIT)
            with tarfile.open(root / "evidence.tar.gz") as archive:
                summary = json.load(archive.extractfile("stage-c-artifact.json"))
            self.assertEqual(summary, expected)
            self.assertIn(
                "prefix_cache_counters", summary["repeats"][0]["run"]["levels"][0]["runtime_regime"]
            )
