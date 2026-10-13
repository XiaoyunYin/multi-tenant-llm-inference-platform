import base64
import hashlib
import json
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import Mock, patch

from inference_platform.r1_agent import Host
from inference_platform.r1_export_probe import measure
from inference_platform.r1_launcher import backend_command
from inference_platform.r1_spec import IMAGE, encoded
from inference_platform.r1_transport import request


class ExportTests(unittest.TestCase):
    def test_export_probe_measures_chunk_path_and_rejects_corruption(self):
        with tempfile.TemporaryDirectory() as directory:
            host = Host({"role": "service", "directory": directory})

            def probe(url, deadline, value, token, max_seconds):
                self.assertEqual(token, "fixture")
                return 200, encoded(host.handle("/export/probe", value, deadline))

            with (
                patch("inference_platform.r1_export_probe.request", side_effect=probe),
                patch("socket.gethostname", return_value="ip-10-23-45-67.ec2.internal") as hostname,
            ):
                result = measure("http://127.0.0.1:9100", "fixture", samples=4)
            hostname.assert_not_called()
            self.assertEqual(result["generator_hostname"], "redacted-at-source")
            self.assertNotIn("ip-10-23-45-67", encoded(result).decode())
            measurement = {
                key: value
                for key, value in result.items()
                if key not in {"measurement_sha256", "agent_config"}
            }
            self.assertEqual(
                hashlib.sha256(encoded(measurement)).hexdigest(), result["measurement_sha256"]
            )
            self.assertEqual(len(result["samples"]), 4)
            self.assertGreater(result["agent_config"]["export_minimum_bytes_per_second"], 0)
            self.assertLessEqual(
                result["minimum_bytes_per_second"],
                min(row["raw_bytes_per_second"] for row in result["samples"]) / 2,
            )
            self.assertIn(
                result["measurement_sha256"], result["agent_config"]["export_link_rate_source"]
            )
            self.assertFalse(host.closing)
            self.assertEqual(host.processes, [])
            for length in (0, 1048577, True):
                with self.assertRaises(ValueError):
                    host.handle("/export/probe", {"length": length}, time.perf_counter() + 5)

            corrupt = host.handle("/export/probe", {"length": 1048576}, time.perf_counter() + 5)
            corrupt["sha256"] = "0" * 64
            with patch(
                "inference_platform.r1_export_probe.request", return_value=(200, encoded(corrupt))
            ):
                with self.assertRaisesRegex(ValueError, "integrity"):
                    measure("http://127.0.0.1:9100", "fixture", samples=4)

    def test_export_probe_real_http_auth_and_json_path(self):
        with tempfile.TemporaryDirectory() as directory:
            host = Host({"role": "service", "directory": directory})

            class Handler(BaseHTTPRequestHandler):
                def do_POST(self):
                    if self.headers.get("Authorization") != "Bearer fixture":
                        self.send_error(401)
                        return
                    value = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                    result = host.handle(self.path, value, time.perf_counter() + 5)
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(encoded(result))

                def log_message(self, format, *args):
                    pass

            server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            try:
                result = measure(f"http://127.0.0.1:{server.server_port}", "fixture", samples=4)
                self.assertEqual(len(result["samples"]), 4)
                self.assertTrue(
                    all(row["wire_bytes"] > row["raw_bytes"] for row in result["samples"])
                )
            finally:
                server.shutdown()
                server.server_close()
                thread.join()

    def test_chunked_export_freezes_stopped_logs_and_checks_offsets(self):
        with tempfile.TemporaryDirectory() as directory:
            host = Host(
                {
                    "role": "service",
                    "directory": directory,
                    "export_minimum_bytes_per_second": 1048576,
                    "export_link_rate_source": "test",
                }
            )
            host.processes = [Mock()]
            content = b'{"msg":"fixture"}\n' * 150000
            (Path(directory) / "gateway-0.jsonl").write_bytes(content)
            with self.assertRaises(ValueError):
                host.handle("/logs/manifest", None, time.perf_counter() + 5)
            host.close()
            manifest = host.handle("/logs/manifest", None, time.perf_counter() + 5)
            self.assertEqual(manifest["files"]["gateway-0.jsonl"], len(content))
            restored = bytearray()
            while len(restored) < len(content):
                chunk = host.handle(
                    "/logs/chunk",
                    {
                        "name": "gateway-0.jsonl",
                        "offset": len(restored),
                        "length": min(1048576, len(content) - len(restored)),
                    },
                    time.perf_counter() + 5,
                )
                data = base64.b64decode(chunk["base64"], validate=True)
                self.assertEqual(chunk["offset"], len(restored))
                self.assertEqual(chunk["size"], len(content))
                self.assertEqual(chunk["sha256"], hashlib.sha256(data).hexdigest())
                restored.extend(data)
            self.assertEqual(restored, content)
            with self.assertRaises(ValueError):
                host.handle(
                    "/logs/chunk",
                    {"name": "../outside", "offset": 0, "length": 1},
                    time.perf_counter() + 5,
                )

    def test_export_request_can_exceed_control_five_second_cap(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                time.sleep(5.2)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"complete")

            def log_message(self, format, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            started = time.perf_counter()
            status, body = request(
                f"http://127.0.0.1:{server.server_port}", started + 8, max_seconds=8
            )
            self.assertEqual((status, body), (200, b"complete"))
            self.assertGreater(time.perf_counter() - started, 5)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_image_inspect_is_cached_but_container_identity_stays_fresh(self):
        with tempfile.TemporaryDirectory() as directory:
            command = backend_command(str(Path(directory).resolve()))
            item = {
                "Id": "fixture",
                "Image": "sha256:image",
                "State": {"Running": True, "StartedAt": "utc"},
                "Config": {
                    "Image": IMAGE,
                    "Cmd": command[command.index(IMAGE) + 1 :],
                    "Env": ["VLLM_SERVER_DEV_MODE=1"],
                },
            }
            image = {"Id": "sha256:image", "Config": {"Env": []}}
            host = Host(
                {
                    "role": "backend",
                    "directory": directory,
                    "weight_cache": str(Path(directory).resolve()),
                }
            )
            with patch(
                "inference_platform.r1_agent.subprocess.check_output",
                side_effect=[encoded([item]), encoded([image]), encoded([item])],
            ) as inspect:
                first, second = (
                    host.identity(time.perf_counter() + 5),
                    host.identity(time.perf_counter() + 5),
                )
            self.assertEqual(inspect.call_count, 3)
            self.assertFalse(first["image_inspect_cached"])
            self.assertTrue(second["image_inspect_cached"])
            self.assertEqual(first["generation"], second["generation"])
            self.assertGreaterEqual(second["duration_s"], 0)
            json.dumps(second)
