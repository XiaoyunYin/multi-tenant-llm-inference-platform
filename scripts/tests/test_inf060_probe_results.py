"""Exercise archive-to-laptop export and the persistent clock protocol."""

import base64
import io
import shlex
import sys
import tarfile
import tempfile
import time
import unittest
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

import inf060_probe_results as results
import inf060_probe_spec as spec
from inf060_aws_operator import retrieve_results
from inf060_probe_client import bracket, clock_exchange, latency_summary
from inf060_probe_engine import clock_server


def produce_archive(path, *, dropped_field=False):
    timing = {
        "start_epoch": 1700000001,
        "end_epoch": 1700000002,
        "elapsed_s": 1.0,
        "exit_code": 0,
    }
    rows = {
        "phase-" + name: {
            **timing,
            "phase": name,
            "env_i": True,
            "deadline_epoch": 1700004200,
        }
        for name in spec.PHASES
    }
    rows.update({"operation-" + name: timing for name in results.OPERATIONS})
    specs = [
        row for row in spec.request_manifest()["slots"] if row["cohort"] == "measured"
    ]
    for generation, arm in enumerate(results.ARMS):
        observations = [
            {
                "alias": row["alias"],
                "cancel_assigned": row["cancel"],
                "cancel_status": "sent" if row["cancel"] else "not_assigned",
                "outcome": "cancelled" if row["cancel"] else "complete",
                "ttft_ns": 10_000,
                "elapsed_ns": 20_000,
                "token_itl_ns": [1000, 1000],
                "fixture_private": "discard-this-prompt",
            }
            for row in specs
        ]
        joins = [
            {
                "request_alias": row["alias"],
                "backend_generation": generation,
                "cancel_close_monotonic_ns": 20000,
                "abort_status": "joined" if generation else "missing_abort",
                "abort_log_stamp": "1700000001.000001" if generation else None,
                "timing_status": "bounded" if generation else None,
                "timing_interval_ns": [1000, 1200] if generation else None,
            }
            for row in specs
            if row["cancel"]
        ]
        exchange = {"c1": 1, "c4": 2, "e2": 7, "e3": 7, "lo": 5, "hi": 6, "width": 1}
        gauges = [
            {
                "mono_ns": 10000,
                "wall_ns": 10006,
                "sample_width_ns": 5,
                "values": {
                    "vllm:num_requests_running": 1,
                    "vllm:kv_cache_usage_perc": 0.01,
                },
            }
        ] * 200
        rows[arm] = {
            "scheduled": 120,
            "assigned_cancels": 24,
            "outcomes": dict(Counter(item["outcome"] for item in observations)),
            "observations": observations,
            "latency": latency_summary(observations),
            "engine_cpu_usec": 100,
            "client_cpu_ns": 500,
            "coarse_gauges": gauges,
            "clock": bracket([exchange] * 10, [exchange] * 10, gauges),
            "abort_join": {
                "rows": joins,
                "orphan_abort_count": generation,
                "stock_abort_matches": 0,
                "sent": len(joins),
                "identity_joins": generation * len(joins),
                "timing_joins": generation * len(joins),
                "frontend_abort_lines": generation * len(joins),
            },
        }
        scan = {
            "bytes": 1024,
            "lines": 3,
            "canary_lines": 0,
            "prompt_field_lines": 0,
            "token_field_lines": 0,
            "stock_timestamp_lines": 0,
            "status": "PASS",
            "no_payload": True,
        }
        rows[arm + "-suppression"] = scan
        rows[arm + "-startup-suppression"] = scan
    if dropped_field:
        del rows["logged"]["coarse_gauges"]
    with tarfile.open(path, "w:gz") as archive:
        for name, row in rows.items():
            data = spec.data(row)
            member = tarfile.TarInfo(f"results/{name}.json")
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))


class ProbeResultsTests(unittest.TestCase):
    def test_success_retains_every_plan_output_after_chunk_retrieval(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive, export = (
                root / name for name in ("receipts.tar.gz", "export.json")
            )
            produce_archive(archive)
            binding = results.publish(export, archive, complete=True, mock=False)
            raw = export.read_bytes()

            def ssm(_host, argv, **_kwargs):
                offset, size = map(int, shlex.split(argv[0])[-2:])
                return {
                    "StandardOutputContent": base64.b64encode(
                        raw[offset : offset + size]
                    ).decode()
                }

            stack = SimpleNamespace(run=root, ports=SimpleNamespace(ssm=ssm))
            status = retrieve_results(
                stack, {"end": time.time() + 60, "host": "mock"}, {"results": binding}
            )
            path = root / "probe-results.json"
            self.assertEqual(status["status"], "verified")
            self.assertGreater(len(status["round_trips"]), 1)
            self.assertEqual(path.read_bytes(), raw)
            self.assertLessEqual(len(raw), results.MAX_BYTES)
            self.assertNotIn(b"discard-this-prompt", raw)
            report = spec.load(path)
            self.assertEqual(set(report["phases"]), set(spec.PHASES))
            self.assertEqual(set(report["operations"]), set(results.OPERATIONS))
            for name, arm in report["arms"].items():
                self.assertEqual(arm["outcomes"], {"complete": 96, "cancelled": 24})
                self.assertEqual(len(arm["observations"]), 120)
                self.assertEqual(arm["observations"][0]["ttft_ns"], 10_000)
                self.assertEqual(arm["observations"][0]["elapsed_ns"], 20_000)
                self.assertEqual(arm["abort_join"]["sent"], 24)
                self.assertEqual(
                    arm["abort_join"]["rows"][0]["timing_interval_width_ns"],
                    200 if name == "logged" else None,
                )
                self.assertEqual(len(arm["clock"]["before"]), 10)
                self.assertEqual(len(arm["clock"]["after"]), 10)
                self.assertEqual(
                    arm["latency_summary"]["completed_elapsed_ns"]["p50"], 20_000
                )
                self.assertEqual(len(arm["coarse_gauges"]), 200)
                self.assertEqual(arm["log_scan"]["bytes"], 1024)
                self.assertEqual(arm["log_scan"]["lines"], 3)
                self.assertTrue(arm["log_scan"]["no_payload"])
                self.assertEqual(arm["startup_log_scan"]["token_field_lines"], 0)
                self.assertEqual(arm["engine_cpu_usec"], 100)
                self.assertEqual(arm["client_cpu_ns"], 500)

    def test_dropped_gauge_field_refuses_publish(self):
        with tempfile.TemporaryDirectory() as temp:
            archive, output = (
                Path(temp) / name for name in ("receipts.tar.gz", "export.json")
            )
            produce_archive(archive, dropped_field=True)
            with self.assertRaisesRegex(KeyError, "coarse_gauges"):
                results.publish(output, archive, complete=True, mock=False)
            self.assertFalse(output.exists())

    def test_failed_run_without_archive_keeps_absence(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output = root / "export.json"
            results.publish(output, root / "missing.tar.gz", complete=False, mock=False)
            self.assertEqual(
                spec.load(output),
                {
                    "archive_status": "missing",
                    "arms": {},
                    "phases": {},
                    "operations": {},
                },
            )

    def test_persistent_clock_serves_ten_exchanges_and_rejects_bad_input(self):
        output = io.BytesIO()
        self.assertEqual(clock_server(io.BytesIO(b"bad\n"), output), 1)
        self.assertEqual(output.getvalue(), b"ready\n")
        engine = Path(__file__).resolve().parents[1] / "inf060_probe_engine.py"
        rows = clock_exchange(
            [sys.executable, "-I", str(engine), "clock-server"], time.time() + 15
        )
        self.assertEqual(len(rows), 10)
        for row in rows:
            self.assertEqual(row["e2"], row["e3"])
            self.assertEqual(row["width"], row["c4"] - row["c1"])
