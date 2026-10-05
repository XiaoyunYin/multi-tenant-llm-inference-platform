import base64
import gzip
import hashlib
import json
import os
import random
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from inference_platform.stage_c_digest import DIGEST_LIMIT, digest_fitness, seal_digest
from inference_platform.stage_c_transport import CommandChannel, fetch_digest


class DigestTest(unittest.TestCase):
    def test_7000_exact_essential_rows_survive_native_and_verbose_degradation(self):
        from inference_platform.stage_c_digest import request_table

        rng = random.Random(106)
        records = [
            {
                "request_id": rng.randbytes(32).hex(),
                "failure_class": "completed" if i % 3 else "vllm_pre_content_rejection",
                "dispatch_offset_ns": i * 10**9,
                "first_content_offset_ns": i * 10**9 + rng.randrange(10**9) if i % 3 else None,
                "completion_offset_ns": i * 10**9 + rng.randrange(10**9, 10**10),
                "prompt_tokens": 6144,
                "completion_tokens": i % 64,
            }
            for i in range(7000)
        ]
        run = {
            "levels": [
                {
                    "concurrency": 8,
                    "records": records,
                    "metrics": [
                        {"offset_ns": i, "values": {"vllm:cache": rng.random()}}
                        for i in range(100000)
                    ],
                }
            ]
        }
        table = request_table(
            run,
            lambda row: {
                "status": "observed" if row["first_content_offset_ns"] else "not_correlated",
                "routing_to_event_observation_ns": 987654321
                if row["first_content_offset_ns"]
                else None,
            },
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "digest.gz"
            receipt = seal_digest(
                path, {"per_request": table, "run": run, "event_lag": {"status": "established"}}
            )
            value = json.loads(gzip.decompress(path.read_bytes()))
        self.assertLessEqual(receipt["bytes"], DIGEST_LIMIT)
        self.assertFalse(receipt["per_request_detail_dropped"])
        self.assertEqual(value["per_request"], table)
        self.assertEqual(len(table["rows"]), 7000)
        self.assertTrue(value["detail_degradation"]["native_sample_detail_dropped"])
        for i, row in enumerate(table["rows"]):
            original = records[i]
            self.assertEqual(row[0:3], [i, 0, original["failure_class"]])
            self.assertEqual(
                row[3],
                original["first_content_offset_ns"] - original["dispatch_offset_ns"]
                if i % 3
                else None,
            )
            self.assertEqual(
                row[4], original["completion_offset_ns"] - original["dispatch_offset_ns"]
            )
            self.assertEqual(row[5:7], [6144, i % 64])
            self.assertEqual(
                row[7:9], ["observed", 987654321] if i % 3 else ["not_correlated", None]
            )

    def test_full_volume_signal_projection_exports_inside_combined_reserve(self):
        from inference_platform.disk_records import write_json
        from inference_platform.stage_c_digest import FINAL_LIMIT, compact
        from inference_platform.stage_c_session import export

        rng = random.Random(100)
        levels = [
            {
                "concurrency": 2**n,
                "runtime_regime": {
                    "classification": "warm_shared",
                    "signals": {
                        "vllm:num_requests_running": [
                            [rng.randrange(10**12), rng.random()] for _ in range(540)
                        ]
                    },
                },
            }
            for n in range(20)
        ]
        original = {"status": "completed", "timed_runs": [{"levels": levels}]}
        self.assertGreater(len(gzip.compress(json.dumps(original).encode())), FINAL_LIMIT)
        projected = compact(original, measurements=False)
        self.assertEqual(
            projected["timed_runs"][0]["levels"][0]["runtime_regime"]["classification"],
            "warm_shared",
        )
        self.assertEqual(
            len(
                compact(original)["timed_runs"][0]["levels"][0]["runtime_regime"]["signals"][
                    "vllm:num_requests_running"
                ]
            ),
            540,
        )
        with tempfile.TemporaryDirectory() as directory:
            session = Path(directory)
            write_json(session / "stage-c-summary.json", projected)
            manifest = session / "manifest.json"
            write_json(manifest, {})
            self.assertLess(export(session, manifest)["bytes"], FINAL_LIMIT)

    def test_actual_seals_status_and_operator_fetch_digest_before_each_full_archive(self):
        from inference_platform.stage_c_checkpoint import seal_run
        from inference_platform.stage_c_control import host_status
        from inference_platform.stage_c_session import export
        from inference_platform.stage_c_transport import ReconnectingTransport, monitor_and_export

        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "host"
            session = destination / "session"
            session.mkdir(parents=True)
            (session / "gateway.log").write_text("")
            for n in range(1, 5):
                seal_run(session, n, {"status": "completed", "levels": []})
            status = host_status(destination, 10000000000)
            self.assertEqual([row["run_number"] for row in status["completed_runs"]], [1, 2, 3, 4])
            status["finished"] = True
            manifest = destination / "staging-manifest.json"
            manifest.write_text("{}")
            receipt = export(session, manifest)
            calls = []

            def request(path, timeout, data=None, *, headers=None):
                calls.append(path)
                if path == "/status":
                    return json.dumps(status).encode()
                if path == "/receipt":
                    return json.dumps(receipt).encode()
                if path == "/export":
                    return (session / "evidence.tar.gz").read_bytes()
                kind, number = path.strip("/").split("/")
                suffix = ".digest.json.gz" if kind == "digest" else ".tar.gz"
                data = (session / "sealed-runs" / f"run-{number}{suffix}").read_bytes()
                if headers:
                    start, end = map(int, headers["Range"].removeprefix("bytes=").split("-"))
                    return data[start : end + 1]
                return data

            operator = Path(directory) / "operator"
            operator.mkdir()
            transport = ReconnectingTransport(
                lambda: SimpleNamespace(poll=lambda: None),
                "local",
                "unit",
                __import__("time").perf_counter() + 900,
                [],
                request=request,
            )
            outcome = {}
            monitor_and_export(transport, operator, outcome)
            self.assertTrue(outcome["export_verified"])
            self.assertEqual(outcome["export_transfer"]["transport"], "forward")
            for n in range(1, 5):
                self.assertLess(calls.index(f"/digest/{n}"), calls.index(f"/run/{n}"))
                self.assertLess(calls.index(f"/digest/{n}"), calls.index("/export"))
                self.assertLess(calls.index(f"/run/{n}"), calls.index("/export"))
                self.assertTrue((operator / f"sealed-runs/run-{n}.tar.gz").exists())

    def test_realistic_digest_over_24_second_commands_fits_reserve_and_no_full_run(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            rng = random.Random(99)
            value = {
                "run": {
                    "records": [
                        {
                            "request_id": "req_" + rng.randbytes(16).hex(),
                            "dispatch_offset_ns": rng.randrange(10**12),
                            "first_content_offset_ns": rng.randrange(10**12),
                            "completion_offset_ns": rng.randrange(10**12),
                            "http_status": 200 if n % 3 else 502,
                            "outcome": "completed" if n % 3 else "failed_before_content",
                            "failure_class": "completed" if n % 3 else "vllm_pre_content_rejection",
                        }
                        for n in range(18000)
                    ],
                    "metrics": [
                        {
                            "offset_ns": rng.randrange(10**12),
                            "values": {
                                "vllm:kv_cache_usage_perc": rng.random(),
                                "vllm:num_preemptions_total": n,
                                "vllm:num_requests_waiting": n % 32,
                            },
                        }
                        for n in range(1800)
                    ],
                },
                "event_lag": {"status": "established", "histogram": {"counts": [3000, 7000]}},
            }
            sealed = root / "fixture.json.gz"
            receipt = seal_digest(sealed, value)
            kept = json.loads(gzip.decompress(sealed.read_bytes()))
            self.assertEqual(len(kept["per_request"]["rows"]), 18000)
            self.assertFalse(receipt["per_request_detail_dropped"])
            self.assertGreater(receipt["bytes"], 12288)  # exercise multiple command chunks
            data = sealed.read_bytes()
            tick = [0.0]
            calls = []
            channel = CommandChannel(None, None, None, None, root, {})

            def call(action, deadline, *, archive="session", offset=0, size=12288):
                tick[0] += 2.4
                self.assertLess(tick[0], deadline)
                calls.append((action, archive))
                if action == "receipt":
                    return receipt
                chunk = data[offset : offset + size]
                return {
                    "offset": offset,
                    "bytes": len(chunk),
                    "base64": base64.b64encode(chunk).decode(),
                }

            channel.call = call
            transport = SimpleNamespace(clock=lambda: tick[0], deadline=600)
            transport.get = lambda path: channel.request(path, 600, transport=transport)
            fetch_digest(transport, root, {"run_number": 1, "measurement_digest": receipt})
            self.assertLess(tick[0], 240)
            # Include the maximum final archive at the conservative forward rate
            # and 60 seconds of receipt/packing/status overhead in one reserve.
            from inference_platform.stage_c_digest import FINAL_LIMIT

            self.assertLess(tick[0] + FINAL_LIMIT / 100 + 60, 600)
            from inference_platform.stage_c_transport import ReconnectingTransport, fetch_export

            final_data = b"x" * FINAL_LIMIT

            def forward(path, timeout, data=None):
                if path == "/receipt":
                    return json.dumps({"sha256": hashlib.sha256(final_data).hexdigest()}).encode()
                self.assertEqual(path, "/export")
                self.assertGreaterEqual(timeout, FINAL_LIMIT / 100)
                tick[0] += len(final_data) / 100
                return final_data

            final_transport = ReconnectingTransport(
                lambda: SimpleNamespace(poll=lambda: None),
                "local",
                "unit",
                600,
                [],
                request=forward,
                clock=lambda: tick[0],
            )
            digest_elapsed = tick[0]
            fetch_export(final_transport, root, {})
            self.assertLess(tick[0] + 60, 600)
            self.assertEqual((root / "sealed-runs/run-1.digest.json.gz").read_bytes(), data)
            self.assertEqual(json.loads(gzip.decompress(data))["per_request"], kept["per_request"])
            self.assertTrue(all(archive == "run-1.digest" for _, archive in calls))
            evidence = os.environ.get("INF011_DIGEST_REHEARSAL_DIR")
            if evidence:
                from inference_platform.disk_records import write_json

                output = Path(evidence)
                output.mkdir(parents=True, exist_ok=True)
                write_json(
                    output / "command-latency-receipt.json",
                    {
                        "schema": "inf011-digest-command-rehearsal.v1",
                        "status": "passed",
                        "compressed_bytes": len(data),
                        "sha256": receipt["sha256"],
                        "request_outcomes": 18000,
                        "native_metric_samples": 1800,
                        "command_count": len(calls),
                        "command_latency_seconds": 2.4,
                        "elapsed_seconds": digest_elapsed,
                        "combined_digest_and_final_seconds": tick[0],
                        "reserve_seconds": 600,
                        "worst_case_last_digest_seconds": 208.8,
                        "worst_case_final_export_seconds": FINAL_LIMIT / 100,
                        "remaining_combined_reserve_seconds": 600 - 208.8 - FINAL_LIMIT / 100,
                        "basis": "Realistic actual gzip measurement data over real chunk/receipt/checksum implementation; simulated SSM latency, no AWS or GPU",
                    },
                )
            with self.assertRaisesRegex(ValueError, "require the forward"):
                channel.request("/run/1", 600, transport=transport)

    def test_bound_fitness_rejects_oversize_stale_tampered_and_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = root / "digest.gz"
            data.write_bytes(gzip.compress(b"{}"))
            row = {
                "status": "passed",
                "source_files_sha256": {"source": "pin"},
                "final_export_bytes": 31000,
                "measurement_digests": [
                    {
                        "run_number": n,
                        "bytes": data.stat().st_size,
                        "path": data.name,
                        "sha256": hashlib.sha256(data.read_bytes()).hexdigest(),
                    }
                    for n in range(1, 5)
                ],
            }
            receipt = root / "receipt.json"
            with patch(
                "inference_platform.host_headroom.source_fingerprint",
                return_value={"source": "pin"},
            ):
                self.assertFalse(digest_fitness(root, receipt)[0])
                receipt.write_text(json.dumps(row))
                self.assertTrue(digest_fitness(root, receipt)[0])
                for change in ("oversize", "stale", "tampered", "final"):
                    broken = json.loads(json.dumps(row))
                    if change == "oversize":
                        broken["measurement_digests"][0]["bytes"] = DIGEST_LIMIT + 1
                    elif change == "stale":
                        broken["source_files_sha256"] = {}
                    elif change == "tampered":
                        broken["measurement_digests"][0]["sha256"] = "0" * 64
                    else:
                        broken["final_export_bytes"] = 48001
                    receipt.write_text(json.dumps(broken))
                    self.assertFalse(digest_fitness(root, receipt)[0], change)

    def test_seal_rejects_invalid_nonmeasurement_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "digest.gz"
            with self.assertRaisesRegex(ValueError, "requires run and event_lag"):
                seal_digest(
                    path,
                    {
                        "event_lag": {"status": "unestablished"},
                        "data": random.Random(1).randbytes(2 * DIGEST_LIMIT).hex(),
                    },
                )
            self.assertFalse(path.exists())
            self.assertFalse(path.with_suffix(".pending").exists())
