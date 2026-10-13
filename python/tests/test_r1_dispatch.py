import concurrent.futures
import gc
import json
import tempfile
import threading
import time
import unittest
import weakref
from pathlib import Path
from unittest.mock import Mock, patch

from inference_platform.r1_fake import Fake
from inference_platform.r1_records import Journal
from inference_platform.r1_session import RealClock
from inference_platform.r1_transport import HTTP


class DispatchTests(unittest.TestCase):
    def test_gc_state_restored_when_phase_raises(self):
        io = HTTP.__new__(HTTP)
        io.clock = RealClock()
        io._phase = Mock(side_effect=RuntimeError("phase exception"))
        original = gc.isenabled()
        try:
            gc.enable()
            with self.assertRaises(RuntimeError):
                io.phase()
            self.assertTrue(gc.isenabled())
            gc.disable()
            with self.assertRaises(RuntimeError):
                io.phase()
            self.assertFalse(gc.isenabled())
        finally:
            if original:
                gc.enable()
            else:
                gc.disable()

    def test_twenty_seconds_with_quarter_million_completed_history(self):
        with tempfile.TemporaryDirectory() as directory:
            io = HTTP.__new__(HTTP)
            io.clock, io.compression = RealClock(), 1
            io.output, io.preparing = Path(directory), False
            io.config = {"gateways": ["http://127.0.0.1:1", "http://127.0.0.2:1"]}
            io.workload = {
                f"p{i:03}": {"id": f"p{i:03}", "request_sha256": "fixture"} for i in range(384)
            }
            io.phase_number, io.corpus_sequence, io.archive_error = 0, 0, None
            io.lock, io.inflight_condition = threading.Lock(), threading.Condition()
            io.inflight = 0
            io.journal = Journal(directory)
            io.executor = concurrent.futures.ThreadPoolExecutor(max_workers=128)
            io.futures = []
            for _ in range(250000):
                future = concurrent.futures.Future()
                future.set_result(None)
                io.futures.append(future)
            native = Fake("success")
            io.snapshots = lambda deadline: native.snapshots(5)
            io.resources = lambda deadline: [
                {
                    "cpu_budget": 8,
                    "memory_bytes": 16 * 1024**3,
                    "nic_limit_bps": 1e9,
                    "nic_limit_source": "test",
                    "nic_fraction": 0,
                    "clock_usable": True,
                    "cpu_fraction": 0,
                }
                for _ in range(2)
            ]
            io.record_native_completion = lambda backend, result: None

            def stream(url, value, deadline, gateway):
                time.sleep(0.005)
                return {
                    "completed": True,
                    "censored": False,
                    "status": 200,
                    "backend_id": "gpu-0",
                    "ended_s": time.perf_counter(),
                    "ttft_s": 0.005,
                    "latency_s": 0.005,
                }

            io.stream = stream
            try:
                result = io.phase("run1-measure", 20, 1, q=40, deadline=time.perf_counter() + 30)
                closed = io.phase(
                    "calibration-corpus-warm", 0.2, 1, level=2, deadline=time.perf_counter() + 5
                )
                self.assertGreater(closed["offered"], 0)
                self.assertGreater(closed["lateness_p95_s"], 0)
                with io.inflight_condition:
                    io.inflight = 128
                missed = io.phase("run2-bound", 1, 0, q=40, deadline=time.perf_counter() + 5)
                with io.inflight_condition:
                    io.inflight = 0
                self.assertEqual(missed["offered"], 40)
                self.assertEqual(missed["missed"], 40)
                self.assertEqual(missed["lateness_count"], 40)
                self.assertEqual(missed["missed_reasons"]["inflight_bound"], 40)
                for offer in missed["offers"]:
                    self.assertEqual(
                        offer["lateness_s"], max(0, offer["observed_s"] - offer["scheduled_s"])
                    )
                io.journal.close(time.perf_counter() + 5)
            finally:
                io.executor.shutdown(wait=True)
            records = [
                json.loads(line)
                for line in (Path(directory) / "offered-trace.jsonl").read_bytes().splitlines()
            ]
            self.assertEqual(result["offered"], 800)
            records = [record for record in records if record["phase"] == "run1-measure"]
            self.assertEqual(len(records), 800)
            self.assertEqual(result["lateness_count"], 800)
            self.assertLessEqual(abs(result["delivered_rate"] / 40 - 1), 0.02)
            self.assertLessEqual(result["lateness_p95_s"], 0.020)
            self.assertEqual(
                result["missed"], sum(bool(row.get("not_dispatched")) for row in records)
            )
            ordered = sorted(row["lateness_s"] for row in records)
            self.assertEqual(result["lateness_p95_s"], ordered[759])
            terminal_history = [
                item for item in io.futures if isinstance(item, weakref.ReferenceType)
            ]
            self.assertGreaterEqual(sum(item() is None for item in terminal_history), 780)
            print(
                json.dumps(
                    {
                        "regression": "R122",
                        "history": 250000,
                        "seconds": 20,
                        "offers": len(records),
                        "delivered_rate": result["delivered_rate"],
                        "lateness_p95_s": result["lateness_p95_s"],
                        "missed": result["missed"],
                        "reasons": result["missed_reasons"],
                    }
                )
            )

    def test_closed_loop_readiness_includes_dispatch_work_with_rows_built_off_thread(self):
        with tempfile.TemporaryDirectory() as directory:
            io = HTTP.__new__(HTTP)
            io.clock, io.compression = RealClock(), 1
            io.output, io.preparing = Path(directory), False
            io.config = {"backends": ["http://127.0.0.1:1", "http://127.0.0.2:1"]}
            io.manifest, io.tokenizer = {"cache_salt": "fixture"}, None
            io.phase_number, io.corpus_sequence, io.archive_error = 0, 0, None
            io.cal_first, io.futures = set(), []
            io.inflight_condition, io.inflight = threading.Condition(), 0
            io.journal = Journal(directory)
            io.executor = concurrent.futures.ThreadPoolExecutor(max_workers=2)
            native = Fake("success")
            io.snapshots = lambda deadline: native.snapshots(5)
            io.resources = lambda deadline: [
                {
                    "cpu_budget": 8,
                    "memory_bytes": 16 * 1024**3,
                    "nic_limit_bps": 1e9,
                    "nic_limit_source": "test",
                    "nic_fraction": 0,
                    "clock_usable": True,
                    "cpu_fraction": 0,
                }
                for _ in range(2)
            ]
            io.record_native_completion = lambda backend, result: None
            rows = []
            builder_threads = []
            dispatch_thread = threading.get_ident()

            def slow_row(identity, salt, tokenizer):
                time.sleep(0.030)
                rows.append(identity)
                builder_threads.append(threading.get_ident())
                return {"id": identity, "tokens": [len(rows)] * 16, "request_sha256": "fixture"}

            def stream(url, value, deadline, gateway):
                time.sleep(0.005)
                return {
                    "completed": True,
                    "censored": False,
                    "status": 200,
                    "ended_s": io.clock.now(),
                    "ttft_s": 0,
                    "latency_s": 0,
                }

            io.stream = stream
            original_record = io.journal.record

            def slow_dispatch_record(name, value):
                if name == "calibration-requests.jsonl":
                    time.sleep(0.030)
                original_record(name, value)

            io.journal.record = slow_dispatch_record
            original_callback = concurrent.futures.Future.add_done_callback

            def delayed_callback(future, callback):
                def delayed(completed):
                    # Future.done() is visible before worker readiness is published.
                    time.sleep(0.050)
                    callback(completed)

                return original_callback(future, delayed)

            try:
                with (
                    patch("inference_platform.r1_transport.row", side_effect=slow_row),
                    patch("concurrent.futures.Future.add_done_callback", delayed_callback),
                ):
                    result = io.phase("staircase-1", 0.22, 1, level=1, deadline=io.clock.now() + 5)
                io.journal.close(io.clock.now() + 5)
            finally:
                io.executor.shutdown(wait=True)
            previous = {}
            by_index = {outcome["index"]: outcome for outcome in result["outcomes"]}
            self.assertGreater(len(result["offers"]), 2)
            self.assertTrue(all(identity != dispatch_thread for identity in builder_threads))
            self.assertLessEqual(len(rows) - len(result["offers"]), 5)
            calibration = [
                json.loads(line)
                for line in (Path(directory) / "calibration-requests.jsonl")
                .read_bytes()
                .splitlines()
            ]
            self.assertEqual(
                [row["id"] for row in calibration], [x["prefix"] for x in result["offers"]]
            )
            for offer in result["offers"]:
                outcome = by_index[offer["index"]]
                worker = offer["worker"]
                self.assertEqual(offer["scheduled_s"], previous.get(worker, result["start_s"]))
                self.assertGreaterEqual(offer["lateness_s"], 0.030)
                previous[worker] = outcome["ended_s"]
            self.assertGreater(result["lateness_p95_s"], 0.020)
            from inference_platform.r1_analysis import resources_valid

            self.assertFalse(resources_valid(result))
            self.assertTrue(result["resources_valid"])
            self.assertTrue(
                all(not sample["gc_automatic"] for sample in result["generator_process"])
            )
            self.assertTrue(all(sample["rss_bytes"] > 0 for sample in result["generator_process"]))
