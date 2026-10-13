import json
import tempfile
import unittest
from pathlib import Path

from inference_platform.r1_fixture_target import coverage_report, verify_generator_window, window_q
from inference_platform.r1_spec import encoded


class FixtureTargetTests(unittest.TestCase):
    def test_committed_packet_window_schema_and_demonstrated_wall_rate(self):
        root = Path(__file__).resolve().parents[2] / "docs/evidence/round87-r1-readiness"
        receipt = json.loads((root / "generator-600s.json").read_bytes())
        self.assertEqual(window_q(receipt), 40)
        http = json.loads((root / "http-strict.json").read_bytes())
        rate = min(x["wall_delivered_rate"] for x in http["windows"] if x["name"].startswith("run"))
        self.assertAlmostEqual(rate, 200.1333333333)
        with self.assertRaises(ValueError):
            window_q({"cases": [receipt["cases"][0]] * 2})

    def test_cached_hardware_q_outside_fixture_is_reported_without_a_stop_rule(self):
        report = coverage_report(80, 200.1333333333, 40)
        self.assertTrue(report["within_http_demonstration"])
        self.assertFalse(report["within_generator_window"])
        self.assertTrue(report["advisory_only"])
        self.assertFalse(report["in_session_stop_rule"])
        self.assertFalse(coverage_report(220, 200.1333333333, 40)["within_http_demonstration"])
        self.assertTrue(coverage_report(40, 200.1333333333, 40)["within_generator_window"])
        for invalid in (0, -1, float("nan"), float("inf"), True):
            with self.assertRaises(ValueError):
                coverage_report(invalid, 200, 40)

    def test_strict_window_recomputes_records_and_rejects_missing_or_changed_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            rows = [
                {
                    "index": index,
                    "scheduled_s": index / 40,
                    "dispatch_s": index / 40 + 0.001,
                    "lateness_s": 0.001,
                }
                for index in range(24000)
            ]
            # A synthetic unit fixture, not a measured 600-second receipt.
            for row in rows:
                row["lateness_s"] = row["dispatch_s"] - row["scheduled_s"]
            phase = {
                "seconds": 600,
                "wall_seconds": 600,
                "q": 40,
                "loopback_compression": 1,
                "start_s": 0,
                "offered": 24000,
                "missed": 0,
                "delivered_rate": 40,
                "completed": 24000,
                "resources_valid": True,
                "fatal": False,
                "lateness_p95_s": sorted(row["lateness_s"] for row in rows)[22799],
                "generator_process": [{"gc_automatic": False}],
            }
            (output / "generator-600s.json").write_bytes(encoded(phase))
            (output / "provenance.json").write_bytes(
                encoded({"head": "unit-fixture", "gc_restored": True})
            )
            (output / "offered-trace.jsonl").write_bytes(b"\n".join(encoded(row) for row in rows))
            (output / "request-outcomes.jsonl").write_bytes(
                b"\n".join(encoded({"index": row["index"], "completed": True}) for row in rows)
            )
            self.assertEqual(
                verify_generator_window(output, "unit-fixture")["minimum_wall_rate"], 40
            )
            with self.assertRaises(ValueError):
                verify_generator_window(None, "unit-fixture")
            with self.assertRaises(AssertionError):
                verify_generator_window(output, "wrong-head")
            phase["loopback_compression"] = 4
            (output / "generator-600s.json").write_bytes(encoded(phase))
            with self.assertRaises(AssertionError):
                verify_generator_window(output, "unit-fixture")
            phase["loopback_compression"] = 1
            (output / "generator-600s.json").write_bytes(encoded(phase))
            rows[100]["scheduled_s"] += 0.03
            (output / "offered-trace.jsonl").write_text("\n".join(json.dumps(row) for row in rows))
            with self.assertRaises(AssertionError):
                verify_generator_window(output, "unit-fixture")
