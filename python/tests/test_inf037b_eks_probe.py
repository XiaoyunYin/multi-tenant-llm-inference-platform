"""Factory TLS/SSE plus compact scheduling and owner-local lineage controls.

Native sources in scheduling tests are explicit witnesses, never real-engine
abort/UID provenance or gateway/Redis integration evidence.
"""

import copy
import hashlib
import json
import ssl
import subprocess
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

import test_inf037b_capture_inventory as owner_tests
from test_inf037b_eks_commands import shell

from inference_platform import inf037b_native as native
from inference_platform.inf037b_archive import Archive, IntegrityError, encode, sha
from inference_platform.inf037b_contract import REGISTRATION_ID
from inference_platform.inf037b_live import ClientSSEAdapter
from inference_platform.inf037b_stream import StreamingArchiveWriter
from inference_platform.package_a_workload import test_tls_command


def component_owner(case):
    fixture = owner_tests.InventoryTests(methodName="runTest")
    case.addCleanup(fixture.doCleanups)
    owner = fixture.worker_owner()
    owner.attempt = "setup"
    owner.binding.update(pins={"configuration": "a" * 64}, session_id="s")
    owner.binding["capture_budgets"] = {
        source: {"raw_bytes": 2000000, "index_bytes": 2000000, "records": 10000}
        for source in owner.sources
    }
    owner.sources["kubernetes"] = [["kubernetes", "kubernetes", "boot"]]
    owner.sources["diagnostic"] = [["controller", "probe", "boot"]]
    owner.archive = Archive.create(owner.root / "archive", {"registration_id": REGISTRATION_ID})
    owner.writer = StreamingArchiveWriter(owner.archive.root, append_write=owner.archive_write)

    # Portable component witness only: real append/file reads, no claim about
    # Linux read-descriptor fsync or directory durability on this laptop.
    def archive_readback():
        for path in owner.archive_pending:
            Path(path).read_bytes()
        owner.archive_pending.clear()
        owner.archive_directories.clear()

    owner.archive_barrier = archive_readback
    owner.operation_store.write({"operations": {owner.label: owner.operation}})
    return owner


class EKSProbeTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory(prefix="r337-probe-")))
        self.owner = component_owner(self)
        self.factory = shell(self.root, "http://localhost:1")
        self.factory.config["pins"] = copy.deepcopy(self.owner.binding["pins"])

    def observe(self, uid, slot=0):
        return self.owner.rows("kubernetes").row(
            "kubernetes",
            "kubernetes",
            "boot",
            "pod_created",
            {"pod_uid": uid, "slot": slot, "node_pseudonym": "node" + str(slot)},
        )

    def sample(self, uid, source="metrics:slot0", process="process"):
        self.owner.retainer(source, uid=uid, process_generation=process)(1, 2, b"raw", {})
        return self.owner.rows(source).row(
            "vllm",
            "vllm:" + uid,
            process,
            "sample",
            {"pod_uid": uid, "slot": int(source[-1]), "process_generation": process},
            start_ns=1,
            end_ns=2,
        )

    def test_unadmitted_and_replacement_uid_refuse_until_own_kubernetes_observation(self):
        with self.assertRaisesRegex(IntegrityError, "uid_unadmitted"):
            self.sample("old")
        self.observe("old")
        self.sample("old")
        with self.assertRaisesRegex(IntegrityError, "uid_unadmitted"):
            self.sample("replacement")
        self.observe("replacement")
        self.sample("replacement")
        admissions = self.owner.store.read()["capture"]["lineage_admissions"]
        self.assertEqual(
            [(a["uid"], a["slot"]) for a in admissions], [("old", 0), ("replacement", 0)]
        )
        self.assertTrue(self.owner.failed, "admission must never clear the earlier capture loss")

    def test_other_owner_and_slot_observation_do_not_admit_uid(self):
        foreign = component_owner(self)
        foreign.rows("kubernetes").row(
            "kubernetes", "kubernetes", "boot", "pod_created", {"pod_uid": "foreign", "slot": 0}
        )
        with self.assertRaisesRegex(IntegrityError, "uid_unadmitted"):
            self.sample("foreign")
        self.observe("slot1", 1)
        with self.assertRaisesRegex(IntegrityError, "uid_unadmitted"):
            self.sample("slot1")

    def test_native_metrics_and_lifecycle_share_uid_sequence_without_new_files(self):
        self.observe("uid")
        before = set((self.owner.root / "wire").iterdir())
        a = self.sample("uid")
        b = self.sample("uid", "native:slot0")
        self.owner.retainer("lifecycle:slot0", uid="uid", process_generation="process")(
            1, 2, b"end", {}
        )
        c = self.owner.rows("kubernetes").row(
            "vllm",
            "vllm:uid",
            "process",
            "process_end",
            {"pod_uid": "uid", "slot": 0, "process_generation": "process"},
            start_ns=1,
            end_ns=2,
        )
        self.assertEqual([r["source_seq"] for r in (a, b, c)], [0, 1, 2])
        self.assertEqual(set((self.owner.root / "wire").iterdir()), before)
        self.assertEqual(len(self.owner.store.read()["capture"]["lineage_admissions"]), 1)

    def test_admitted_uid_still_refuses_unbound_generation(self):
        self.observe("uid")
        self.owner.retainer("metrics:slot0", uid="uid", process_generation="real")(1, 2, b"raw", {})
        with self.assertRaisesRegex(IntegrityError, "generation_unbound"):
            self.owner.rows("metrics:slot0").row(
                "vllm",
                "vllm:uid",
                "other",
                "sample",
                {"pod_uid": "uid", "slot": 0, "process_generation": "other"},
            )

    def runtime(self, endpoint, context, peer, *, clock=time.monotonic_ns, sleep=time.sleep):
        now = clock()
        # Labelled scheduling-only signal ports. Real process and source proof
        # are exercised by SetupSignalTests, not inferred from these fixtures.
        owner = self.owner

        class Signal:
            def __init__(self, slot):
                self.owner, self.slot = owner, slot

            def ready(self, before):
                pass

            def trigger(self, start, stop):
                return {"fixture_signal_slot": self.slot}

        manifest = {
            "schema": "inf037b-native-overlay-v1",
            "version": "0.29.0",
            "base": dict(native.BASE_FILES),
            "files": dict(native.BASE_FILES),
            "helper_sha256": sha(Path(native.__file__).read_bytes()),
        }
        payloads = {f"p{i:03}": {"max_tokens": 1, "stream": True} for i in range(384)}
        self.factory.config.update(
            native_manifest_sha256=sha(encode(manifest)),
            probe_payloads_sha256=sha(encode(payloads)),
        )
        return {
            "gateways": {
                g: {
                    "http": {
                        "base": endpoint.rsplit("/v1/", 1)[0],
                        "ca": str(self.root / "tls.crt"),
                    },
                    "endpoint": endpoint,
                    "credential": lambda: "measured",
                    "context": context,
                    "tls": {"version": "TLSv1.3", "verified": True, "peer_sha256": peer},
                }
                for g in ("gateway0", "gateway1")
            },
            "slots": {
                slot: {
                    "origin": {
                        "pod_uid": "uid" + str(slot),
                        "slot": slot,
                        "boot_id": "p" + str(slot),
                        "node": "node" + str(slot),
                        "node_boot_id": "n" + str(slot),
                        "helper_sha256": manifest["helper_sha256"],
                        "manifest_sha256": sha(encode(manifest)),
                    },
                    "manifest": manifest,
                    "http": {
                        "base": endpoint.rsplit("/v1/", 1)[0],
                        "ca": str(self.root / "tls.crt"),
                    },
                }
                for slot in (0, 1)
            },
            "slot_names": {"backend0": 0, "backend1": 1},
            "reservations": {},
            "controller_source": "diagnostic",
            "payloads": payloads,
            "control_credentials": {
                slot: lambda slot=slot: "control-" + str(slot) for slot in (0, 1)
            },
            "signals": [Signal(0), Signal(1)],
            "booking": {
                "branch_start_ns": now,
                "ready_ns": now,
                "branch_stop_ns": now + 1_740_000_000_000,
                "remaining_gpu_seconds": 1000,
            },
            "clock": clock,
            "sleep": sleep,
        }

    def tls_server(self):
        result = subprocess.run([str(v) for v in test_tls_command(self.root)], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.minimum_version = server_context.maximum_version = ssl.TLSVersion.TLSv1_3
        server_context.load_cert_chain(self.root / "tls.crt", self.root / "tls.key")
        state = {"refuse": False, "calls": []}
        content = (
            b'data: {"choices":[{"index":0,"delta":{"content":"one"},"finish_reason":null}]}\n\n'
            b'data: {"choices":[{"index":0,"delta":{},"finish_reason":"length"}]}\n\n'
            b'data: {"choices":[],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2,"count_source":"runtime_usage"}}\n\n'
            b"data: [DONE]\n\n"
        )

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                data = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                state["calls"].append((data, self.headers.get("Authorization")))
                body = b"{}" if state["refuse"] else content
                self.send_response(503 if state["refuse"] else 200)
                self.send_header(
                    "Content-Type", "application/json" if state["refuse"] else "text/event-stream"
                )
                self.send_header("X-Request-ID", "g-" + str(len(state["calls"])))
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.socket = server_context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        context = ssl.create_default_context(cafile=str(self.root / "tls.crt"))
        cert = ssl.PEM_cert_to_DER_cert((self.root / "tls.crt").read_text())
        runtime = self.runtime(
            f"https://localhost:{server.server_port}/v1/chat/completions",
            context,
            hashlib.sha256(cert).hexdigest(),
        )
        self.observe("uid0", 0)
        self.observe("uid1", 1)
        return runtime, state

    def test_factory_real_tls_sse_serving_and_refusing_controls(self):
        runtime, state = self.tls_server()
        probe = self.factory.setup_probe(self.owner, runtime)
        for gateway in ("gateway0", "gateway1"):
            offer = {
                "request_id": "ingress-" + gateway + "-0",
                "offer_index": 0,
                "prefix_id": "p000",
                "scheduled_ms": time.monotonic_ns() // 1000000,
            }
            rows = probe.request(gateway, offer, control=True, tls_record=True)
            self.assertTrue(
                any(r["payload"]["event"] == "terminal" and not r["error"] for r in rows)
            )
        state["refuse"] = True
        offer = {
            "request_id": "ingress-gateway0-1",
            "offer_index": 1,
            "prefix_id": "p000",
            "scheduled_ms": time.monotonic_ns() // 1000000,
        }
        rows = probe.request("gateway0", offer, control=True)
        self.assertFalse(
            any(
                r["payload"]["event"] == "terminal"
                and r["payload"].get("terminal_reason") == "length"
                for r in rows
            )
        )
        self.assertTrue(any(r["payload"].get("http_status") == 503 for r in rows))
        self.assertEqual(
            [h for _, h in state["calls"]],
            ["Bearer control-0", "Bearer control-0", "Bearer control-1"],
        )

    def test_missing_campaign_resource_window_port_refuses_before_probe(self):
        with self.assertRaisesRegex(IntegrityError, "unfinished:campaign_resource_bindings"):
            self.factory.run_setup_probe(self.owner, {}, 1767225601000)
        self.assertNotIn("single_probe", self.owner.store.read())

    def test_factory_refuses_empty_setup_signal_sources_before_traffic(self):
        from inference_platform.inf037b_eks_probe import compose_probe

        runtime = self.runtime("https://example.invalid/v1/chat/completions", None, None)
        runtime["signals"] = []
        with self.assertRaisesRegex(ValueError, "transport:unresolved:setup_signal_launcher"):
            compose_probe(self.factory, self.owner, runtime)

    def test_probe_booking_uses_original_gpu_branch_cutoff(self):
        self.factory.resource_windows = lambda *args, **kwargs: SimpleNamespace(close=lambda: None)
        with self.assertRaisesRegex(IntegrityError, "probe_original_cutoff"):
            self.factory.run_setup_probe(
                self.owner, {"booking": {"branch_stop_ns": 1767225601000000001}}, 1767225601000
            )
        self.assertNotIn("single_probe", self.owner.store.read())

    def test_failed_resource_collector_cannot_be_masked_by_a_successful_probe(self):
        def failed_close():
            raise IntegrityError("resource:collector_failed")

        self.factory.resource_windows = lambda *args, **kwargs: SimpleNamespace(close=failed_close)
        with (
            patch.object(
                self.factory,
                "setup_probe",
                return_value=SimpleNamespace(
                    run=lambda: True, store=SimpleNamespace(read=lambda: {"single_probe": True})
                ),
            ),
            patch(
                "inference_platform.inf037b_eks_probe.compose_probe_collectors",
                side_effect=lambda *a, **k: k["actions"]["diagnostic"](),
            ),
        ):
            with self.assertRaisesRegex(IntegrityError, "resource:collector_failed"):
                self.factory.run_setup_probe(
                    self.owner, {"booking": {"branch_stop_ns": 1767225601000000000}}, 1767225601000
                )

    def test_factory_runs_existing_1311_offers_and_six_controls_once(self):
        runtime, _ = self.tls_server()
        now = [0]
        calls = []
        lock = threading.Lock()

        def clock():
            with lock:
                return now[0]

        def sleep(seconds):
            with lock:
                now[0] += round(seconds * 1e9)
            time.sleep(0)

        runtime["clock"], runtime["sleep"] = clock, sleep
        runtime["booking"].update(branch_start_ns=0, ready_ns=0, branch_stop_ns=1_740_000_000_000)
        native_endpoints = SimpleNamespace(accepted=set(), ended=set(), pending=[])

        class Source:
            pending = []
            lost = False
            accepted, ended = native_endpoints.accepted, native_endpoints.ended

            def ready(self):
                return None

            def poll(self):
                return []

        class Client(ClientSSEAdapter):
            def request(self, url, payload, offer, **kwargs):
                with lock:
                    calls.append((self.gateway, copy.deepcopy(offer), kwargs["credential"]))
                    native_endpoints.accepted.add(offer["request_id"])
                    native_endpoints.ended.add(offer["request_id"])
                return [
                    {
                        "error": None,
                        "payload": {
                            "event": "cancel" if kwargs.get("cancel_after_content") else "terminal"
                        },
                    }
                ]

        with (
            patch("inference_platform.inf037b_eks_probe.ClientSSEAdapter", Client),
            patch(
                "inference_platform.inf037b_eks_probe.NativeRequestAdapter",
                side_effect=lambda *a, **k: Source(),
            ),
            patch(
                "inference_platform.inf037b_eks_probe.GatewayAdapter",
                side_effect=lambda *a, **k: Source(),
            ),
        ):
            probe = self.factory.setup_probe(self.owner, runtime)
        with patch("inference_platform.inf037b_probe.require_group_leader"):
            result = probe.run()
            probe.start_ns = now[0] + 90_000_000_000
            probe.stop_ns = now[0] + 240_000_000_000
            with self.assertRaisesRegex(IntegrityError, "already_allocated"):
                probe.run()
        self.assertEqual((result["scheduled"], len(calls), result["replacements"]), (1311, 1317, 0))
        self.assertEqual(
            len([c for c in calls if c[1]["request_id"].startswith(("ingress-", "cancel-"))]), 6
        )
        self.assertTrue(self.owner.store.read()["single_probe"]["traffic_complete"])


if __name__ == "__main__":
    unittest.main()
