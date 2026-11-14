"""Functional capture-summary guards using real HTTP and owner raw/index files."""

import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from capture_inf037b_producer_sizes import summarize_wire
from inf037b_purpose_kube import periodic_objects
from time_inf037b_wire import owner

from inference_platform.inf037b_capture import DeadlineHTTP


class ProducerSizesTest(unittest.TestCase):
    def test_periodic_object_fixture_preserves_registered_engine_template(self):
        controller, pods = periodic_objects()
        self.assertEqual(controller["spec"]["replicas"], 2)
        self.assertEqual([p["metadata"]["name"] for p in pods], ["vllm-0", "vllm-1"])
        for pod in pods:
            self.assertEqual(pod["metadata"]["labels"]["app"], "vllm")
            self.assertEqual(
                pod["spec"]["containers"],
                controller["spec"]["template"]["spec"]["containers"],
            )
            volumes = {v["name"] for v in pod["spec"].get("volumes", [])}
            self.assertTrue(
                all(
                    m["name"] in volumes
                    for c in pod["spec"]["containers"]
                    for m in c.get("volumeMounts", [])
                )
            )

    def test_real_http_and_retained_index_summary_then_corruption_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = owner(
                Path(directory) / "owner",
                sources={"gateway0": [["gateway", "g", "wire-receipt-boot"]]},
            )
            body = b'{"source":"actual socket response"}'

            class Handler(BaseHTTPRequestHandler):
                def log_message(self, *args):
                    pass

                def do_GET(self):
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

            server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            try:
                client = DeadlineHTTP(
                    f"http://127.0.0.1:{server.server_port}",
                    stop_ns=time.monotonic_ns() + 10000000000,
                    retain=capture.retainer("gateway0"),
                    local_test=True,
                )
                self.assertEqual(client.get("/data")[0], body)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(2)
            capture.close()
            summary = summarize_wire(capture.root)
            self.assertTrue(summary["groups"])
            self.assertGreaterEqual(
                sum(r["total_raw_bytes"] for r in summary["groups"].values()), len(body)
            )
            target = next((capture.root / "wire").glob("*.bin"))
            raw = target.read_bytes()
            target.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
            with self.assertRaisesRegex(ValueError, "wire_hash"):
                summarize_wire(capture.root)
