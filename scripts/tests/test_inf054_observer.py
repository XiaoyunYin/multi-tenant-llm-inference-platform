"""Reproduce EKS command latency through the real kubectl wrapper."""

import json
import subprocess
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from inf054_cpu_helm import record_proof
from inf054_dec100 import ClusterWindow
from inf054_eks_workload import workload_cycle, write_rows

from inference_platform.m5_descriptive_cluster import ClusterPorts


class PrometheusFixture(BaseHTTPRequestHandler):
    def do_GET(self):
        body = {
            "status": "success",
            "data": {
                "result": [
                    {"metric": {"instance": "vllm-1.vllm:8000"}, "value": [0, "1"]}
                ]
            },
        }
        self.send_response(200)
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())

    def log_message(self, *args):
        pass


class ObserverLatencyTests(unittest.TestCase):
    def exercise(self, *, unreadable=False):
        calls = []
        with (
            tempfile.TemporaryDirectory() as name,
            ThreadingHTTPServer(("127.0.0.1", 0), PrometheusFixture) as server,
        ):
            worker = threading.Thread(target=server.serve_forever)
            worker.start()
            dest = Path(name)
            cycle = dest / "keda-1"
            cycle.mkdir()
            cluster = ClusterPorts()
            cluster.campaign = SimpleNamespace(kubectl="kubectl")
            cluster.kubeconfig = "fixture"
            cluster.context = "fixture"
            cluster.namespace = "mti-fixture"
            cluster.output = dest
            cluster.commands = []
            window = ClusterWindow(
                cluster,
                {"metadata": {"name": "load-client"}, "spec": {"nodeName": "client"}},
                server.server_port,
                "fixture",
                "keda",
            )

            def pipe(argv, *, timeout, **kwargs):
                operation, resource = argv[7:9]
                if operation == "exec":
                    time.sleep(4.2)
                    body = {"rows": []}
                else:
                    calls.append(resource)
                    delay = 0.45
                    time.sleep(min(timeout, delay))
                    if timeout < delay or (unreadable and resource == "pods"):
                        raise subprocess.TimeoutExpired(argv, timeout)
                    if resource == "pods":
                        body = {
                            "items": [
                                {
                                    "metadata": {
                                        "name": "vllm-1",
                                        "uid": "fixture-one",
                                    },
                                    "spec": {"nodeName": "engine"},
                                    "status": {"phase": "Running"},
                                }
                            ],
                        }
                    elif resource == "endpointslices":
                        body = {
                            "items": [
                                {
                                    "endpoints": [
                                        {
                                            "conditions": {"ready": True},
                                            "targetRef": {"uid": "fixture-one"},
                                        }
                                    ]
                                }
                            ]
                        }
                    else:
                        self.assertIn("hpa/keda-hpa-vllm", argv)
                        body = {
                            "items": [
                                {"kind": "StatefulSet", "spec": {"replicas": 2}},
                                {
                                    "kind": "HorizontalPodAutoscaler",
                                    "status": {"desiredReplicas": 2},
                                },
                            ]
                        }
                return SimpleNamespace(
                    returncode=0, stdout=json.dumps(body).encode(), stderr=b""
                )

            try:
                with patch("subprocess.run", side_effect=pipe):
                    summary = workload_cycle(
                        window,
                        [],
                        cycle,
                        arm="keda",
                        cycle=1,
                        end=time.monotonic() + 130,
                        offer_end=1,
                    )
                samples = [
                    json.loads(row)
                    for row in (cycle / "gauges.jsonl").read_bytes().splitlines()
                ]
                write_rows(cycle / "scale.jsonl", window.scale)
                summary.update(
                    second_serving_s=15,
                    downscale={"observed": True, "probe_overlaps": ["partial"]},
                )
                self.assertGreaterEqual(len(samples), 3)
                self.assertEqual(len(samples), len(window.scale))
                self.assertEqual(len(calls), 3 * len(samples))
                self.assertTrue(
                    all(
                        a["at_s"] + 1 <= b["at_s"] for a, b in zip(samples, samples[1:])
                    )
                )
                if unreadable:
                    with self.assertRaisesRegex(
                        ValueError, "^inf054_gauge_completeness$"
                    ):
                        record_proof(dest, summary, {}, {}, "fixture")
                    self.assertTrue(all(row["missing"] for row in samples))
                    self.assertTrue(
                        all(
                            row["read_errors"]["pods"] == "TimeoutExpired"
                            for row in samples
                        )
                    )
                    self.assertTrue(
                        all(
                            row["desired"] == 2 and row["replicas"] is None
                            for row in window.scale
                        )
                    )
                    proof = json.loads((dest / "proof.json").read_bytes())
                    self.assertFalse(proof["complete"])
                    self.assertFalse(proof["live_scale_out"])
                    self.assertTrue(proof["observed_scale_out"])
                else:
                    proof = record_proof(dest, summary, {}, {}, "fixture")
                    self.assertGreaterEqual(
                        summary["complete_samples"] / len(samples), 0.95
                    )
                    self.assertTrue(proof["telemetry"]["ordinal_one_ready"])
                    self.assertTrue(proof["live_scale_out"])
            finally:
                server.shutdown()
                worker.join()

    def test_observer_covers_real_kubectl_wrapper_with_450ms_latency(self):
        self.exercise()

    def test_failed_samples_keep_partial_scale_and_refuse_proof(self):
        self.exercise(unreadable=True)
