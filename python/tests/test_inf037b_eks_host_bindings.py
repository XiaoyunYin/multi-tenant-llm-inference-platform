"""Real SDK/HTTP identity joins, with explicit account-protocol fixtures."""

import copy
import json
import tempfile
import threading
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import test_inf037b_eks_provider_client as provider_fixture

from inference_platform.inf037b_eks_host_bindings import IndependentHosts, local_host_identity


class LocalHostIdentityTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.boot = self.root / "boot"
        self.boot.write_text("fixture-boot", encoding="ascii")
        self.calls = []
        self.document = {"accountId": "000000000000", "region": "us-east-1", "instanceId": "i-a"}
        self.now = 100
        case = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_PUT(self):
                case.calls.append(("PUT", self.path))
                case.assertEqual(self.headers["X-aws-ec2-metadata-token-ttl-seconds"], "60")
                self.reply(b"fixture-token")

            def do_GET(self):
                case.calls.append(("GET", self.path))
                case.assertEqual(self.headers["X-aws-ec2-metadata-token"], "fixture-token")
                self.reply(json.dumps(case.document).encode())

            def reply(self, data):
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=self.server.serve_forever)
        thread.start()
        self.addCleanup(thread.join, 2)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.kwargs = {
            "binding": {"session_id": "s", "C_ms": 10000, "D_session_ms": 18010000, "t0_ms": 17},
            "pins": {"source": "a" * 64},
            "account": "000000000000",
            "region": "us-east-1",
            "clock": lambda: self.now,
            "stop": 10000,
            "boot_path": self.boot,
            "metadata_base": f"http://127.0.0.1:{self.server.server_port}",
            "local_test": True,
        }

    def test_real_imdsv2_socket_and_boot_file_producer(self):
        result = local_host_identity(**self.kwargs)
        self.assertEqual(result["instance_id"], "i-a")
        self.assertEqual(result["boot_id"], "fixture-boot")
        self.assertEqual(
            self.calls,
            [("PUT", "/latest/api/token"), ("GET", "/latest/dynamic/instance-identity/document")],
        )
        self.assertNotIn(self.kwargs["account"], json.dumps(result))
        self.assertNotIn("fixture-token", json.dumps(result))

    def test_scope_drift_and_expired_original_deadline_refuse(self):
        self.document["accountId"] = "111111111111"
        with self.assertRaisesRegex(ValueError, "local_account"):
            local_host_identity(**self.kwargs)
        self.calls.clear()
        self.now = 10000
        with self.assertRaisesRegex(ValueError, "identity_deadline"):
            local_host_identity(**self.kwargs)
        self.assertEqual(self.calls, [])
        with self.assertRaisesRegex(ValueError, "metadata_endpoint"):
            local_host_identity(
                **{**self.kwargs, "metadata_base": "http://public.example", "local_test": False}
            )


class HostBindingsTest(unittest.TestCase):
    def setUp(self):
        self.peer = provider_fixture.ProviderClientTest(methodName="runTest")
        self.peer.setUp()
        self.addCleanup(self.peer.doCleanups)
        self.binding = {
            "session_id": self.peer.session_id,
            "C_ms": 10000,
            "D_session_ms": 18010000,
            "t0_ms": 17,
        }
        self.pins = {"source": "a" * 64}
        self.peer.pins = self.pins
        self.hosts = {
            r: {"instance_id": i, "boot_id": self.peer.boots[i]}
            for r, i in (("controller", "i-a"), ("export", "i-a"), ("supervisor", "i-b"))
        }
        self.redirect = False

    def witness(self, identity, stop):
        if self.redirect:
            identity = "i-a"
        with urllib.request.urlopen(
            f"http://127.0.0.1:{self.peer.server.server_port}/identity/{identity}", timeout=5
        ) as response:
            return json.load(response)

    def reader(self):
        return IndependentHosts(
            binding=self.binding,
            pins=self.pins,
            hosts=self.hosts,
            account_reader=self.peer.client,
            witness_read=self.witness,
        )

    def test_fresh_account_instance_boot_and_original_deadline_join(self):
        reader = self.reader()
        first, second = reader.observe(10000), reader.observe(10000)
        self.assertEqual(first, second)
        self.assertEqual(first["D_eff_ms"], 18000017)
        self.assertEqual(first["hosts"]["supervisor"]["instance_id"], "i-b")
        self.assertEqual(
            len([r for r in self.peer.requests if r["Action"] == ["GetCallerIdentity"]]), 2
        )

    def test_actual_reboot_misrouted_endpoint_and_pin_drift_refuse(self):
        reader = self.reader()
        self.peer.boots["i-b"] = "new-boot"
        with self.assertRaisesRegex(ValueError, "host_binding:boot"):
            reader.observe(10000)
        self.peer.boots["i-b"] = "boot-b"
        self.redirect = True
        with self.assertRaisesRegex(ValueError, "host_binding:instance"):
            reader.observe(10000)
        self.redirect = False
        self.peer.pins = {"source": "b" * 64}
        with self.assertRaisesRegex(ValueError, "host_binding:pins"):
            reader.observe(10000)

    def test_same_instance_and_same_boot_cannot_prove_independence(self):
        self.hosts["supervisor"] = copy.deepcopy(self.hosts["controller"])
        with self.assertRaisesRegex(ValueError, "physical_independence"):
            self.reader()
        self.hosts["supervisor"]["instance_id"] = "i-b"
        self.peer.boots["i-b"] = "boot-a"
        with self.assertRaisesRegex(ValueError, "boot_independence"):
            self.reader().observe(10000)

    def test_original_deadline_never_rebased_or_extended(self):
        reader = self.reader()
        with self.assertRaisesRegex(ValueError, "original_deadline"):
            reader.observe(18000018)
        self.assertEqual(self.peer.requests, [])
