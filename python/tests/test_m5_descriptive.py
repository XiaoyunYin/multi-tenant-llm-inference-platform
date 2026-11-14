"""DEC-100 manifests and real socket terminal/outcome accounting."""

import json
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from inference_platform.calibration import CalibrationConfig, run_calibration
from inference_platform.m5_descriptive import resources, stream, summarize
from inference_platform.r1_spec import engine_argv


class ManifestTests(unittest.TestCase):
    def test_admission_running_is_bound_to_engine_max_sequences(self):
        for limit in (8, 16):
            args = engine_argv()
            args[args.index("--max-num-seqs") + 1] = str(limit)
            with patch("inference_platform.m5_descriptive.engine_argv", return_value=args):
                items = resources("mti-m5-test", "example.invalid/gateway@sha256:" + "a" * 64)[
                    "items"
                ]
            gateway = next(
                o
                for o in items
                if o["kind"] == "StatefulSet" and o["metadata"]["name"] == "gateway"
            )
            env = {
                r["name"]: r.get("value")
                for r in gateway["spec"]["template"]["spec"]["containers"][0]["env"]
            }
            self.assertEqual(env["ADMISSION_RUNNING"], str(limit))
            self.assertEqual(env["ADMISSION_WAITING"], "4")
            self.assertEqual(env["ADMISSION_CAPACITY_MODE"], "dynamic")
            vllm = next(
                o for o in items if o["kind"] == "StatefulSet" and o["metadata"]["name"] == "vllm"
            )
            actual = vllm["spec"]["template"]["spec"]["containers"][0]["args"]
            self.assertEqual(actual[actual.index("--max-num-seqs") + 1], str(limit))
        with patch(
            "inference_platform.m5_descriptive.engine_argv", return_value=["--max-num-seqs", "0"]
        ):
            with self.assertRaisesRegex(ValueError, "engine_admission_capacity"):
                resources("mti-m5-test", "example.invalid/gateway@sha256:" + "a" * 64)

    def test_offline_cli_renders_descriptive_resources_and_refuses_mutable_image(self):
        root = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "resources.json"
            argv = [
                sys.executable,
                str(root / "scripts/m5_eks.py"),
                "render-descriptive",
                "--namespace",
                "mti-m5-test",
                "--gateway-image",
                "example.invalid/gateway@sha256:" + "a" * 64,
                "--output",
                str(output),
            ]
            completed = subprocess.run(argv, cwd=root, capture_output=True, check=True)
            self.assertFalse(json.loads(completed.stdout)["applied"])
            self.assertEqual(
                json.loads(output.read_bytes()),
                resources("mti-m5-test", "example.invalid/gateway@sha256:" + "a" * 64),
            )
            output.unlink()
            argv[argv.index("--gateway-image") + 1] = "mutable:latest"
            self.assertNotEqual(subprocess.run(argv, cwd=root, capture_output=True).returncode, 0)
            self.assertFalse(output.exists())

    def test_two_fixed_replicas_private_discovery_and_no_capture(self):
        manifest = resources("mti-m5-test", "example.invalid/gateway@sha256:" + "a" * 64)
        objects = {
            obj["metadata"]["name"]: obj
            for obj in manifest["items"]
            if obj["kind"] == "StatefulSet"
        }
        self.assertEqual(set(objects), {"gateway", "vllm"})
        for obj in objects.values():
            self.assertEqual(obj["spec"]["replicas"], 2)
            self.assertEqual(obj["spec"]["updateStrategy"], {"type": "OnDelete"})
        serialized = json.dumps(manifest)
        for forbidden in (
            "capture_runtime",
            "capture-data",
            "host-observer",
            "HorizontalPodAutoscaler",
            "LoadBalancer",
        ):
            self.assertNotIn(forbidden, serialized)
        services = [obj for obj in manifest["items"] if obj["kind"] == "Service"]
        self.assertTrue(all(obj["spec"]["type"] == "ClusterIP" for obj in services))
        self.assertEqual(
            next(obj for obj in services if obj["metadata"]["name"] == "vllm")["spec"]["clusterIP"],
            "None",
        )
        gpu = objects["vllm"]["spec"]["template"]["spec"]
        self.assertEqual(gpu["containers"][0]["resources"]["limits"]["nvidia.com/gpu"], "1")
        self.assertIn("--enable-prefix-caching", gpu["containers"][0]["args"])
        self.assertNotIn("--enable-kv-cache-events", gpu["containers"][0]["args"])

    def test_bad_namespace_image_and_tls_refuse(self):
        for args in (
            ("default", "bad"),
            ("mti-m5-test", "mutable:latest"),
            ("mti-m5-test", "example.invalid/gateway@sha256:" + "a" * 64, "bad/name"),
        ):
            with self.subTest(args=args), self.assertRaises(ValueError):
                resources(*args)


class SocketTests(unittest.TestCase):
    def serve(self, mode):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"test_metric 1\n")

            def do_POST(self):
                payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if mode == "rejected":
                    self.send_response(429)
                    self.end_headers()
                    return
                self.send_response(200)
                if mode.startswith("chunk_abort"):
                    self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                if mode.startswith("chunk_abort"):
                    content = (
                        b'data: {"choices":[{"index":0,"delta":{"content":"a"},"finish_reason":null}]}\n\n'
                        if mode == "chunk_abort"
                        else b""
                    )
                    wire = (
                        (f"{len(content):x}\r\n".encode() + content + b"\r\n") if content else b""
                    )
                    self.wfile.write(wire + b"not-a-chunk-size\r\n")
                    self.wfile.flush()
                    return
                if mode == "oversize":
                    self.wfile.write(b"x" * (1_048_576 + 64))
                    self.wfile.flush()
                    return
                rows = [
                    {"choices": [{"index": 0, "delta": {"content": "a"}, "finish_reason": None}]}
                ]
                if mode != "partial":
                    rows += [
                        {"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]},
                        {
                            "choices": [],
                            "usage": {
                                "prompt_tokens": 4,
                                "completion_tokens": 1,
                                "total_tokens": 5,
                                "count_source": "runtime_usage",
                            },
                        },
                    ]
                for row in rows:
                    self.wfile.write(b"data: " + json.dumps(row).encode() + b"\n\n")
                if mode != "partial":
                    self.wfile.write(b"data: [DONE]\n\n")
                if mode == "trailing":
                    self.wfile.write(b"unexpected\n")
                self.wfile.flush()
                self.server.seen_payload = payload

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        self.addCleanup(lambda: (server.shutdown(), thread.join(), server.server_close()))
        return server, CalibrationConfig(
            url=f"http://127.0.0.1:{server.server_port}",
            token="synthetic-development",
            tenant_id="synthetic",
            model="test-model",
            run_id="test",
            max_tokens=1,
            sample_interval_ms=20,
            timeout_seconds=2,
        )

    def test_real_complete_partial_trailing_and_admission(self):
        for mode, outcome in (
            ("complete", "completed"),
            ("partial", "partial_stream"),
            ("trailing", "partial_stream"),
            ("rejected", "rejected"),
            ("chunk_abort", "partial_stream"),
            ("chunk_abort_empty", "failed_before_content"),
        ):
            _, config = self.serve(mode)
            with self.subTest(mode=mode):
                row = stream(config, "a" * 64, time.perf_counter_ns(), "test")
                self.assertEqual(row["outcome"], outcome)
                self.assertEqual(row["itl_ns"], [])
                self.assertEqual(row["strict_terminal"]["complete"], mode == "complete")
                if mode.startswith("chunk_abort"):
                    self.assertEqual(row["error_code"], "IncompleteRead")

    def test_real_unterminated_oversize_line_is_bounded_before_retaining(self):
        import contextlib
        from unittest.mock import patch

        from inference_platform import m5_descriptive as descriptive

        _, config = self.serve("oversize")
        original = descriptive.deadline_urlopen
        read_sizes = []

        @contextlib.contextmanager
        def observed(*args, **kwargs):
            with original(*args, **kwargs) as response:

                class BoundedResponse:
                    status, headers = response.status, response.headers

                    def read1(inner, size=-1):
                        self.assertGreater(size, 0, "unbounded pre-retain read")
                        self.assertLessEqual(size, 64 * 1024)
                        read_sizes.append(size)
                        return response.read1(size)

                # No unbounded iterator: the actual HTTP socket still supplies
                # every byte; this observer enforces the read contract.
                yield BoundedResponse()

        with patch.object(descriptive, "deadline_urlopen", side_effect=observed):
            row = stream(config, "a" * 64, time.perf_counter_ns(), "test")
        self.assertGreater(len(read_sizes), 1)
        self.assertEqual(row["outcome"], "failed_before_content")
        self.assertIn("oversize_sse", row["strict_terminal"]["errors"])
        self.assertLessEqual(row["strict_terminal"]["pending_bytes"], 1_048_576)

    def test_existing_generator_uses_strict_request_callback(self):
        server, config = self.serve("complete")
        result = run_calibration(
            config, (1,), level_duration_seconds=0.1, drain_seconds=2, request_function=stream
        )
        self.assertEqual(result["status"], "completed")
        records = result["levels"][0]["records"]
        self.assertTrue(all(row["outcome"] == "completed" for row in records))
        self.assertEqual(server.seen_payload["max_tokens"], 1)
        summary = summarize(records, result["levels"][0]["duration_ns"] / 1e9)
        self.assertGreater(summary["completed"], 0)
        self.assertIsNone(summary["itl_ms"]["p95"])


class SummaryTests(unittest.TestCase):
    def test_disjoint_outcomes_and_observed_percentiles(self):
        rows = [
            {
                "outcome": value,
                "http_status": status,
                "dispatch_offset_ns": 0,
                "completion_offset_ns": 30_000_000,
                "first_content_offset_ns": first,
                "itl_ns": [],
            }
            for value, status, first in (
                ("completed", 200, 10_000_000),
                ("partial_stream", 200, 20_000_000),
                ("rejected", 429, None),
                ("failed_before_content", 200, None),
                ("failed_before_content", None, None),
                ("not_dispatched", None, None),
                ("cancelled", None, None),
            )
        ]
        result = summarize(rows, 2)
        for name in (
            "completed",
            "partial",
            "failed_no_content",
            "failed_admission_unknown",
            "rejected",
            "not_dispatched",
            "cancelled",
        ):
            self.assertEqual(result[name], 1, name)
        self.assertEqual(
            sum(
                result[name]
                for name in (
                    "completed",
                    "partial",
                    "failed_no_content",
                    "failed_admission_unknown",
                    "rejected",
                    "not_dispatched",
                    "cancelled",
                )
            ),
            len(rows),
        )
        self.assertEqual(result["completed_per_s"], 0.5)
        self.assertEqual(result["ttft_ms"], {"n": 2, "p50": None, "p95": None})
        enough = summarize(rows * 200, 2)
        self.assertEqual(enough["ttft_ms"], {"n": 400, "p50": 10, "p95": 20})
        self.assertIsNone(result["itl_ms"]["p50"])
        for invalid in (0, -1, float("nan")):
            with self.assertRaises(ValueError):
                summarize(rows, invalid)
