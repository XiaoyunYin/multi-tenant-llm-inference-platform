"""Real transports -> accepted collectors, with explicit small-capture inadequacy."""

import base64
import hashlib
import importlib.util
import json
import os
import socket
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from redis_capture_test_support import AdminRedisWire as RedisWire

from inference_platform.fake_backend import FakeBackend, FakeBackendConfig
from inference_platform.inf037b_archive import Archive, IntegrityError, encode
from inference_platform.inf037b_campaign import (
    OfflineCampaign,
    materialize_bundle,
    registered_offers,
    reproduce,
    sanitized_campaign,
)
from inference_platform.inf037b_contract import REGISTRATION_GIT_BLOB_SHA256, REGISTRATION_ID
from inference_platform.inf037b_live import (
    HTTP,
    METRICS,
    ClientSSEAdapter,
    ClockAdapter,
    GatewayAdapter,
    KubernetesAdapter,
    LifecycleReceiptProducer,
    LiveRows,
    NodeLifecycleAdapter,
    RedisAdapter,
    VLLMAdapter,
)
from inference_platform.inf037b_packet import REQUIRED_PINS
from inference_platform.inf037b_sources import ClockMapper, SourceJoin
from inference_platform.inf037b_stream import StreamingArchiveWriter

ROOT = Path(__file__).resolve().parents[2]
HASH = "a" * 64


def serve(handler):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_port}"


class AdapterTests(unittest.TestCase):
    def test_gateway_capture_refuses_a_registered_diagnostic_reservation(self):
        from unittest.mock import Mock

        rid = "rsv_d1a6" + "a" * 28
        entries = [
            {
                "schema": "gateway-measurement-v1",
                "sequence": 0,
                "boot_id": "boot",
                "mono_ns": 1,
                "event": "capture_start",
                "data": {},
            },
            {
                "schema": "gateway-measurement-v1",
                "sequence": 1,
                "boot_id": "boot",
                "mono_ns": 2,
                "event": "admit",
                "data": {"request_id": "request", "reservation_id": rid},
            },
        ]
        body = b"".join(encode(item) for item in entries)
        http = Mock()
        http.get.return_value = (body, {"X-Capture-Boot": "boot", "X-Capture-Next": str(len(body))})
        adapter = GatewayAdapter(
            LiveRows("gateway", "collector"), http, "gateway0", slot_names={}, config_sha256=HASH
        )
        adapter.reservations[rid] = None
        with self.assertRaisesRegex(IntegrityError, "fitness:diagnostic_id_in_gateway"):
            adapter.poll()
        self.assertTrue(adapter.lost)

        other = GatewayAdapter(
            LiveRows("gateway", "collector"),
            http,
            "gateway0",
            slot_names={},
            config_sha256=HASH,
            reservations={rid: "different-request"},
        )
        with self.assertRaisesRegex(IntegrityError, "fitness:gateway_reservation_reused"):
            other.poll()

    def test_shared_gateway_and_diagnostic_registry_cannot_overwrite_each_other(self):
        from unittest.mock import Mock

        rid = "rsv_d1a6" + "a" * 28
        raw = b"".join(
            encode(r)
            for r in (
                {
                    "schema": "gateway-measurement-v1",
                    "sequence": 0,
                    "boot_id": "boot",
                    "mono_ns": 0,
                    "event": "capture_start",
                    "data": {},
                },
                {
                    "schema": "gateway-measurement-v1",
                    "sequence": 1,
                    "boot_id": "boot",
                    "mono_ns": 1,
                    "event": "admit",
                    "data": {"request_id": "request", "reservation_id": rid},
                },
            )
        )
        for _ in range(20):
            mapping = {}
            http = Mock()
            http.get.return_value = raw, {"X-Capture-Boot": "boot", "X-Capture-Next": str(len(raw))}
            gateway = GatewayAdapter(
                LiveRows("race", "collector"),
                http,
                "gateway0",
                slot_names={},
                config_sha256=HASH,
                reservations=mapping,
            )
            redis = RedisAdapter(
                LiveRows("race", "collector"), Mock(), "ns", HASH, reservations=mapping
            )
            barrier, outcomes = threading.Barrier(2), []

            def run(function, barrier=barrier, outcomes=outcomes):
                barrier.wait()
                try:
                    function()
                    outcomes.append("ok")
                except IntegrityError as exc:
                    outcomes.append(str(exc))

            threads = [
                threading.Thread(target=run, args=(gateway.poll,)),
                threading.Thread(
                    target=run,
                    args=(
                        lambda redis=redis, rid=rid: redis.register_diagnostic(
                            {"reservation_id": rid}
                        ),
                    ),
                ),
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertCountEqual(outcomes, ["ok", "fitness:diagnostic_id_in_gateway"])
            self.assertIn(mapping[rid], (None, "request"))

    def test_diagnostic_receipt_joins_redis_without_gateway_request_identity(self):
        from unittest.mock import Mock

        rid = "rsv_d1a6" + "a" * 28
        wire = Mock()
        adapter = RedisAdapter(LiveRows("diagnostic", "collector"), wire, "test", HASH)
        receipt = {"reservation_id": rid}
        adapter.register_diagnostic(receipt)
        raw = {
            "event": "admit",
            "redis_time_ms": "100",
            "capture_seq": "1",
            "decision": "allowed",
            "idempotent": "0",
            "occupied": "1",
            "reservation_id": rid,
            "effective_b": "10",
        }
        wire.command.return_value = [[["1-0", sum(([k, v] for k, v in raw.items()), [])]], "1"]
        row = adapter.operations()[0]
        self.assertIsNone(row["error"])
        self.assertEqual(row["payload"]["reservation_id"], rid)
        self.assertNotIn("request_id", row["payload"])
        with self.assertRaisesRegex(IntegrityError, "fitness:diagnostic_receipt_duplicate"):
            adapter.register_diagnostic(receipt)
        other = RedisAdapter(
            LiveRows("collision", "collector"),
            wire,
            "test",
            HASH,
            reservations={rid: "gateway-request"},
        )
        with self.assertRaisesRegex(IntegrityError, "fitness:diagnostic_id_in_gateway"):
            other.register_diagnostic(receipt)
        with self.assertRaisesRegex(IntegrityError, "fitness:gateway_id_in_diagnostic"):
            other.register_diagnostic({"reservation_id": "rsv_" + "1" * 32})

    def test_redis_snapshot_requires_atomic_capture_sequence(self):
        from unittest.mock import Mock

        rows = LiveRows("snapshot", "collector")
        wire = Mock()
        adapter = RedisAdapter(rows, wire, "test", HASH)
        raw = {
            "redis_time_ms": 1,
            "reports": [],
            "lows": [],
            "state": [],
            "active": [],
            "capture_order": "7",
        }
        wire.command.return_value = json.dumps(raw)
        result = adapter.snapshot()
        self.assertIsNone(result["error"])
        self.assertEqual(result["payload"]["store_order"], 7)
        self.assertEqual(wire.command.call_args.args[2], 5)
        self.assertEqual(
            wire.command.call_args.args[-1], "test:{admission}:global:active:capture:sequence"
        )
        for value in (None, "-1", "01", 3):
            bad = dict(raw, capture_order=value)
            wire.command.return_value = json.dumps(bad)
            self.assertEqual(adapter.snapshot()["payload"]["event"], "read_error")
        del raw["capture_order"]
        wire.command.return_value = json.dumps(raw)
        self.assertEqual(adapter.snapshot()["payload"]["event"], "read_error")

    def test_redis_snapshot_identity_survives_deferred_reservation_join(self):
        from unittest.mock import Mock

        wire = Mock()
        reservation = "rsv_" + "1" * 32
        raw = {
            "redis_time_ms": 1,
            "reports": [],
            "lows": [],
            "state": [],
            "active": ["tenant:" + reservation, "1000"],
            "capture_order": "3",
        }
        wire.command.return_value = json.dumps(raw)
        reservations = {}
        adapter = RedisAdapter(
            LiveRows("snapshot", "collector"),
            wire,
            "test",
            HASH,
            reservations=reservations,
            report_ttl_ms=8000,
        )
        self.assertIsNone(adapter.snapshot(snapshot_id="cached_stop_known1"))
        reservations[reservation] = "request-one"
        row = adapter.flush_snapshots()[0]
        self.assertEqual(row["payload"]["snapshot_id"], "cached_stop_known1")
        self.assertEqual(row["payload"]["store_order"], 3)
        self.assertEqual(row["payload"]["active_reservations"][0]["request_id"], "request-one")
        with self.assertRaisesRegex(IntegrityError, "redis_snapshot_ttl_unbound"):
            RedisAdapter(LiveRows("other", "collector"), wire, "test", HASH).snapshot(
                snapshot_id="known1"
            )
        with self.assertRaisesRegex(IntegrityError, "redis_snapshot_unknown_id"):
            adapter.snapshot(snapshot_id="invented")
        with self.assertRaisesRegex(IntegrityError, "redis_snapshot_unknown_id"):
            adapter.snapshot(snapshot_id=[])
        with self.assertRaisesRegex(IntegrityError, "redis_snapshot_pending_label_override"):
            adapter.snapshot(captured=(raw, 0, "known1"), snapshot_id="known2")

    def test_labeled_snapshot_derives_store_time_from_bound_ttl(self):
        from unittest.mock import Mock

        wire = Mock()
        raw = {
            "redis_time_ms": 10000,
            "reports": ["gateway-0", json.dumps({"n": 2, "expires": 17000, "unknown": True})],
            "lows": [],
            "state": [],
            "active": [],
            "capture_order": "3",
        }
        wire.command.return_value = json.dumps(raw)
        adapter = RedisAdapter(LiveRows("ttl", "collector"), wire, "test", HASH, report_ttl_ms=8000)
        row = adapter.snapshot(snapshot_id="unknown")
        self.assertEqual(row["payload"]["reports"]["gateway0"]["stored_ms"], 9000)
        raw["reports"][1] = json.dumps({"n": 2, "expires": 7999, "unknown": True})
        wire.command.return_value = json.dumps(raw)
        self.assertEqual(adapter.snapshot(snapshot_id="unknown")["payload"]["event"], "read_error")

    def test_redis_snapshot_sequence_is_read_from_real_redis_atomically(self):
        address = os.environ.get("REDIS_TEST_ADDR")
        if not address:
            self.skipTest("requires isolated real Redis")
        import uuid

        host, port = address.rsplit(":", 1)
        wire = RedisWire(host, int(port), tls=False, local_test=True)
        self.addCleanup(wire.close)
        namespace = "snapshot-" + uuid.uuid4().hex
        sequence_key = namespace + ":{admission}:global:active:capture:sequence"
        self.addCleanup(lambda: wire.command("DEL", sequence_key))
        rows = LiveRows("snapshot-live", "collector")
        adapter = RedisAdapter(rows, wire, namespace, HASH)
        self.assertEqual(wire.command("INCR", sequence_key), 1)
        snapshot = adapter.snapshot()
        self.assertIsNone(snapshot["error"])
        self.assertEqual(snapshot["payload"]["store_order"], 1)
        self.assertEqual(wire.command("INCR", sequence_key), 2)
        self.assertEqual(adapter.snapshot()["payload"]["store_order"], 2)

    def test_any_normalized_sink_exception_permanently_inhibits_receipts(self):
        producer = LifecycleReceiptProducer()
        producer.created("pod", 0)
        producer.ingest(
            {
                "pod_uid": "pod",
                "sequence": 0,
                "boot_id": "boot",
                "mono_ns": 0,
                "event": "supervisor_start",
            }
        )

        def failed_sink(_row):
            raise RuntimeError("writer_failed")

        rows = LiveRows("test", "collector", clock=lambda: 0, sink=failed_sink)
        rows.on_loss = producer.loss
        with self.assertRaisesRegex(RuntimeError, "writer_failed"):
            rows.row("kubernetes", "kubernetes", "collector", "watch", {})
        self.assertTrue(producer.lost)
        with self.assertRaisesRegex(IntegrityError, "receipt_refused"):
            producer.receipt(rows, "pod", 0, time_bounds=[0, 0])

    def test_absolute_client_timeout_does_not_count_trickled_content_as_complete(self):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                self.send_response(200)
                self.send_header("X-Request-ID", "gateway-owned-id")
                self.end_headers()
                try:
                    for _ in range(20):
                        self.wfile.write(b": keepalive\n\n")
                        self.wfile.flush()
                        time.sleep(0.04)
                except OSError:
                    pass

        server, url = serve(Handler)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        rows = LiveRows("test", "collector")
        adapter = ClientSSEAdapter(rows, "gateway0", HASH)
        now = time.monotonic_ns() // 1_000_000
        offer = {
            "request_id": "offer",
            "offer_index": 0,
            "prefix_id": "prefix",
            "scheduled_ms": now,
        }
        start = time.monotonic()
        with patch("inference_platform.inf037b_live.REQUEST_TIMEOUT_SECONDS", 0.15):
            captured = adapter.request(
                url + "/v1/chat/completions", {}, offer, credential="test", local_test=True
            )
        self.assertLess(time.monotonic() - start, 0.6)
        self.assertEqual(captured[-1]["payload"]["event"], "timeout")
        self.assertEqual(captured[-1]["payload"]["outcome"], "right_censored")

        start = time.monotonic()
        adapter = ClientSSEAdapter(LiveRows("test-deadline", "collector"), "gateway0", HASH)
        captured = adapter.request(
            url + "/v1/chat/completions",
            {},
            offer,
            credential="test",
            local_test=True,
            deadline_ns=time.monotonic_ns() + 150_000_000,
        )
        self.assertLess(time.monotonic() - start, 0.6)
        self.assertEqual(captured[-1]["payload"]["event"], "timeout")
        self.assertEqual(captured[-1]["payload"]["outcome"], "right_censored")
        emitted = []
        adapter = ClientSSEAdapter(
            LiveRows("expired", "collector", sink=emitted.append), "gateway0", HASH
        )
        with self.assertRaisesRegex(IntegrityError, "client:request_deadline"):
            adapter.request(
                url + "/v1/chat/completions",
                {},
                offer,
                credential="test",
                local_test=True,
                deadline_ns=time.monotonic_ns() - 1,
            )
        self.assertEqual(emitted, [])

    def test_receipt_permanently_refuses_loss_restarts_and_process_end(self):
        for mode in (
            "gap",
            "reboot",
            "capture_loss",
            "restart",
            "process_end",
            "sample",
            "startup",
            "ready",
            "metrics_pending",
        ):
            with self.subTest(mode=mode):
                producer = LifecycleReceiptProducer()
                producer.created("pod", 0)
                raw = {
                    "pod_uid": "pod",
                    "sequence": 0,
                    "boot_id": "boot",
                    "mono_ns": 0,
                    "event": "supervisor_start",
                }
                producer.ingest(raw)
                rows = LiveRows("test", "collector", clock=lambda: 0)
                self.assertEqual(
                    producer.receipt(rows, "pod", 0, time_bounds=[0, 0])["payload"][
                        "container_state"
                    ],
                    "metrics_not_started",
                )
                if mode in ("gap", "reboot", "capture_loss", "restart"):
                    bad = {**raw, "sequence": 1, "mono_ns": 250_000_000, "event": "heartbeat"}
                    bad.update(
                        {
                            "gap": {"sequence": 2},
                            "reboot": {"boot_id": "other"},
                            "capture_loss": {"capture_lost": True},
                            "restart": {"restart_count": 1},
                        }[mode]
                    )
                    with self.assertRaises(IntegrityError):
                        producer.ingest(bad)
                else:
                    producer.contradiction("pod", mode)
                with self.assertRaisesRegex(IntegrityError, "receipt_refused"):
                    producer.receipt(rows, "pod", 0)

    def test_live_process_end_before_loading_receipt_is_a_contradiction(self):
        spec = importlib.util.spec_from_file_location(
            "capture_runtime_early_end", ROOT / "deploy/eks/capture_runtime.py"
        )
        runtime = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runtime)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        supervisor = runtime.Supervisor(Path(tmp.name), "pod")
        self.addCleanup(supervisor.file.close)
        supervisor.record("process_end", pid=7, returncode=1)
        server, url = serve(supervisor.handler())
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        rows, producer = LiveRows("test", "collector"), LifecycleReceiptProducer()
        rows.on_loss = producer.loss
        producer.created("pod", 0)
        node = NodeLifecycleAdapter(rows, HTTP(url, local_test=True), "pod", 0, producer)
        first = node.clock()
        ended = node.poll()
        time.sleep(0.01)
        second = node.clock()
        node.clocks = ClockMapper([first, second])
        self.assertEqual(ended[0]["payload"]["event"], "process_end")
        self.assertTrue(producer.pods["pod"]["blocked"])
        with self.assertRaisesRegex(IntegrityError, "receipt_refused"):
            node.loading_receipt()

    def test_live_supervisor_output_and_watch_to_real_collector(self):
        spec = importlib.util.spec_from_file_location(
            "capture_runtime", ROOT / "deploy/eks/capture_runtime.py"
        )
        runtime = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runtime)
        tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(tmpdir.cleanup)
        tmp = tmpdir.name
        if tmp:
            supervisor = runtime.Supervisor(Path(tmp), "pod")
            self.addCleanup(supervisor.file.close)
            server, url = serve(supervisor.handler())
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
            rows, producer = LiveRows("test", "collector"), LifecycleReceiptProducer()
            kube = KubernetesAdapter(
                rows,
                HTTP(url, local_test=True),
                "test",
                slot_names={"vllm-0": 0},
                lifecycle=producer,
            )
            watch = kube.watch(
                iter(
                    [
                        encode(
                            {
                                "type": "ADDED",
                                "object": {
                                    "kind": "Pod",
                                    "metadata": {
                                        "uid": "pod",
                                        "name": "vllm-0",
                                        "resourceVersion": "1",
                                    },
                                    "status": {
                                        "conditions": [{"type": "Ready", "status": "False"}]
                                    },
                                },
                            }
                        )
                    ]
                )
            )
            created = next(watch)
            watch_row = next(watch)
            self.assertEqual(watch_row["payload"]["conditions"], {"Ready": "False"})
            self.assertFalse(SourceJoin([created, watch_row]).errors)
            node = NodeLifecycleAdapter(rows, HTTP(url, local_test=True), "pod", 0, producer)
            first_clock = node.clock()
            supervisor.record("heartbeat")
            self.assertEqual(node.poll(), [])
            time.sleep(0.01)
            second_clock = node.clock()
            node.clocks = ClockMapper([first_clock, second_clock])
            receipt = node.loading_receipt()
            joined = SourceJoin([created, watch_row, first_clock, second_clock, receipt])
            self.assertFalse(joined.errors, joined.errors)
            self.assertEqual(
                next(r for r in joined.rows if r["payload"]["event"] == "container_state")[
                    "payload"
                ]["reason"],
                "continuous_lifecycle_since_pod_creation",
            )
            self.assertEqual(
                {
                    (r["source_identity"], r["source_generation"])
                    for r in joined.rows
                    if r["source_kind"] == "kubernetes"
                },
                {("kubernetes", "collector")},
            )

            class NativeHTTP:
                def get(self, path):
                    if path == "/health":
                        return b"{}", {}
                    return b"\n".join(
                        f'{metric}{{model_name="test"}} 1'.encode() for metric in METRICS.values()
                    ), {}

            native = VLLMAdapter(
                rows,
                NativeHTTP(),
                pod_uid="pod",
                slot=0,
                process_generation=supervisor.boot,
                model_sha256=HASH,
                runtime_sha256=HASH,
                semantics_sha256=HASH,
                lifecycle=producer,
            )
            sampled = native.sample()
            self.assertIsNone(sampled["error"], sampled)
            supervisor.record("process_end", pid=123, returncode=0)
            ended = node.poll()
            self.assertEqual(ended[0]["payload"]["event"], "process_end")
            self.assertEqual(ended[0]["payload"]["process_generation"], supervisor.boot)
            self.assertFalse(
                SourceJoin(
                    [created, watch_row, first_clock, second_clock, receipt, sampled, *ended]
                ).errors
            )
            with self.assertRaises(IntegrityError):
                producer.receipt(rows, "pod", time.monotonic_ns())
            watch.close()
            self.assertTrue(producer.lost)
            with self.assertRaises(FileExistsError):
                runtime.Supervisor(Path(tmp), "pod")

    def test_metrics_real_http_missing_duplicate_reset_and_health(self):
        state = {"duplicate": False, "missing": False, "value": 5, "status": 200}

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                self.send_response(state["status"])
                self.end_headers()
                if self.path != "/metrics":
                    return
                for key, metric in METRICS.items():
                    if state["missing"] and key == "waiting":
                        continue
                    self.wfile.write(f'{metric}{{model_name="test"}} {state["value"]}\n'.encode())
                    if state["duplicate"] and key == "waiting":
                        self.wfile.write(f'{metric}{{model_name="other"}} 1\n'.encode())

        server, url = serve(Handler)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        rows = LiveRows("test", "collector")
        adapter = VLLMAdapter(
            rows,
            HTTP(url, local_test=True),
            pod_uid="pod",
            slot=0,
            process_generation="proc",
            model_sha256=HASH,
            runtime_sha256=HASH,
            semantics_sha256=HASH,
        )
        positive = adapter.sample()
        self.assertIsNone(positive["error"])
        self.assertFalse(SourceJoin([positive]).errors)
        state["value"] = 1
        self.assertEqual(adapter.sample()["payload"]["reset_generation"], "1")
        for key in ("duplicate", "missing"):
            state[key] = True
            failed = adapter.sample()
            self.assertIsNone(failed["error"])
            self.assertIn("observation_error", failed["payload"])
            self.assertIsNone(failed["payload"]["running"])
            state[key] = False

    def test_kubernetes_real_http_error_never_authorizes_receipt(self):
        state = {"status": 200}

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                self.send_response(state["status"])
                self.end_headers()
                version = "2" if "endpointslices" in self.path else "3"
                data = {"metadata": {"resourceVersion": version}, "items": []}
                self.wfile.write(encode(data))

        server, url = serve(Handler)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        rows, producer = LiveRows("test", "collector"), LifecycleReceiptProducer()
        kube = KubernetesAdapter(
            rows, HTTP(url, local_test=True), "test", slot_names={}, lifecycle=producer
        )
        positive = kube.snapshot()
        self.assertFalse(SourceJoin(positive).errors)
        self.assertEqual(kube.pod_resource_version, "3")
        self.assertEqual(kube.endpoint_resource_version, "2")
        state["status"] = 410
        self.assertIsNotNone(kube.snapshot()[0]["error"])
        self.assertTrue(producer.lost)
        state["status"] = 200
        kube.snapshot()
        self.assertTrue(producer.lost)

    def test_kubernetes_live_bookmark_stream_and_eof_latch(self):
        requested = []
        retained = []

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                requested.append(self.path)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(
                    encode(
                        {
                            "type": "BOOKMARK",
                            "object": {"metadata": {"resourceVersion": "17"}},
                        }
                    )
                )

        server, url = serve(Handler)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        rows, producer = LiveRows("test", "collector"), LifecycleReceiptProducer()
        http = HTTP(url, local_test=True, retain=lambda *args: retained.append(args))
        kube = KubernetesAdapter(rows, http, "test", slot_names={}, lifecycle=producer)
        output = list(kube.watch_pods("16"))
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(requested[0]).query)
        self.assertEqual(query["resourceVersion"], ["16"])
        self.assertEqual(query["allowWatchBookmarks"], ["true"])
        self.assertEqual(query["timeoutSeconds"], ["7200"])
        self.assertEqual(output[0]["payload"]["reason"], "BOOKMARK")
        self.assertEqual(output[0]["payload"]["resource_version"], "17")
        self.assertEqual(len(retained), 1)
        self.assertTrue(producer.lost)


class GatewayRedisEndToEnd(unittest.TestCase):
    def test_real_gateway_redis_sse_archive_sanitize_and_reproduce(self):
        binary = os.environ.get("M5_PACKAGE_A_BIN")
        address = os.environ.get("REDIS_TEST_ADDR")
        if not binary or not address:
            self.skipTest(
                "requires built gateway and isolated real Redis: M5_PACKAGE_A_BIN, REDIS_TEST_ADDR"
            )
        tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(tmpdir.cleanup)
        with FakeBackend(
            FakeBackendConfig(
                backend_id="vllm-0", chunks=("a",), completion_tokens=1, chunk_delay_ms=30
            )
        ) as backend:
            root = Path(tmpdir.name)
            credential = "package-a-test-credential"
            tenants = json.loads((ROOT / "deploy/local/tenants.json").read_bytes())
            tenants["tenants"][0]["credential_sha256"] = hashlib.sha256(
                credential.encode()
            ).hexdigest()
            (root / "tenants.json").write_text(json.dumps(tenants))
            (root / "salt").write_bytes(
                base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=") + b"\n"
            )
            sock = socket.socket()
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
            sock.close()
            namespace = "package-a-" + root.name.replace("_", "-")
            env = {
                **os.environ,
                "GATEWAY_HTTP_ADDR": f"127.0.0.1:{port}",
                "BACKENDS": f"vllm-0={backend.base_url}",
                "TENANT_CONFIG_PATH": str(root / "tenants.json"),
                "CACHE_SALT_SECRET_FILE": str(root / "salt"),
                "REDIS_ADDR": address,
                "ADMISSION_NAMESPACE": namespace,
                "POD_UID": "gateway-boot",
                "GATEWAY_MEASUREMENT_PATH": str(root / "gateway.jsonl"),
                "ADMISSION_CAPACITY_MODE": "dynamic",
                "ADMISSION_GATEWAY_ID": "gateway0",
                "ADMISSION_RUNNING": "4",
                "ADMISSION_WAITING": "1",
                "ADMISSION_REPORT_TTL": "8s",
                "ADMISSION_HOLD_DOWN": "2s",
                "OTEL_SDK_DISABLED": "true",
            }
            log = (root / "gateway.log").open("wb")
            process = subprocess.Popen([binary], env=env, stdout=log, stderr=subprocess.STDOUT)
            self.addCleanup(log.close)

            def cleanup():
                if process.poll() is None:
                    process.terminate()
                process.wait(timeout=15)

            self.addCleanup(cleanup)
            http = HTTP(f"http://127.0.0.1:{port}", local_test=True)
            deadline = time.monotonic() + 10
            while True:
                try:
                    http.get("/readyz")
                    break
                except OSError:
                    if process.poll() is not None or time.monotonic() > deadline:
                        self.fail((root / "gateway.log").read_text())
                    time.sleep(0.02)
            all_rows = []
            rows = LiveRows("adapter-e2e", "collector", sink=all_rows.append)
            wire = RedisWire(
                *[int(p) if i else p for i, p in enumerate(address.split(":"))],
                tls=False,
                local_test=True,
            )
            self.addCleanup(wire.close)
            # The registry reports every 500 ms; readiness alone does not end
            # the dynamic-capacity hold-down. Observe B=N*(R+W), without offers.
            deadline = time.monotonic() + 2 + 0.5 + 5
            while True:
                n = wire.command("HGET", namespace + ":{admission}:capacity:state", "n")
                if n is not None and int(n) * (4 + 1) > 0:
                    break
                if process.poll() is not None or time.monotonic() >= deadline:
                    self.fail("capacity B did not become positive before hold-down/report deadline")
                time.sleep(0.02)
            clocks = ClockAdapter(rows)
            clock_before = clocks.gateway(http, "gateway0")
            clocks.redis(wire)
            start_ms = time.monotonic_ns() // 1_000_000
            offers = registered_offers(1, start_ms, start_ms + 1000, HASH)
            client = ClientSSEAdapter(rows, "gateway0", HASH)
            client_rows = client.request(
                http.base + "/v1/chat/completions",
                {
                    "model": "test-model",
                    "messages": [{"role": "user", "content": "test"}],
                    "stream": True,
                    "max_tokens": 1,
                },
                offers[0],
                credential=credential,
                local_test=True,
            )
            self.assertEqual(client_rows[-1]["payload"]["outcome"], "complete", client_rows)
            time.sleep(0.55)
            clocks.gateway(http, "gateway0")
            clocks.redis(wire)
            mapper = ClockMapper([r for r in all_rows if r["source_kind"] == "clocks"])
            gateway = GatewayAdapter(
                rows,
                http,
                "gateway0",
                slot_names={"vllm-0": 0},
                config_sha256=HASH,
                clocks=mapper,
                request_ids=client.request_ids,
                capture_start_remote_ms=clock_before["payload"]["remote_ms"],
            )
            normalized = gateway.poll()
            self.assertTrue(
                any(r["payload"]["event"] == "upstream_open" for r in normalized), normalized
            )
            self.assertFalse(any(r["error"] for r in normalized), normalized)
            redis = RedisAdapter(
                rows, wire, namespace, HASH, reservations=gateway.reservations, report_ttl_ms=8000
            )
            operations = redis.operations()
            self.assertEqual(
                [
                    r["payload"]["event"]
                    for r in operations
                    if r["payload"]["event"] in ("admit", "release")
                ],
                ["admit", "release"],
            )
            snapshot = redis.snapshot(snapshot_id="known1")
            self.assertIsNone(snapshot["error"])
            self.assertEqual(snapshot["payload"]["snapshot_id"], "known1")
            report = snapshot["payload"]["reports"]["gateway0"]
            self.assertEqual(report["stored_ms"], report["expires_ms"] - 8000)
            self.assertGreaterEqual(
                snapshot["payload"]["store_order"],
                max(row["payload"]["store_order"] for row in operations),
            )
            native = VLLMAdapter(
                rows,
                HTTP(backend.base_url, local_test=True),
                pod_uid="0",
                slot=0,
                process_generation="mock-runtime",
                model_sha256=HASH,
                runtime_sha256=HASH,
                semantics_sha256=HASH,
            )
            self.assertIsNone(native.sample()["error"])

            class KubeHTTP(BaseHTTPRequestHandler):
                def log_message(self, *args):
                    pass

                def do_GET(self):
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(encode({"metadata": {"resourceVersion": "1"}, "items": []}))

            kube_server, kube_url = serve(KubeHTTP)
            self.addCleanup(kube_server.server_close)
            self.addCleanup(kube_server.shutdown)
            producer = LifecycleReceiptProducer()
            rows.on_loss = producer.loss
            kube = KubernetesAdapter(
                rows,
                HTTP(kube_url, local_test=True),
                "test",
                slot_names={"vllm-0": 0},
                lifecycle=producer,
            )
            kube.snapshot()
            watch = kube.watch(
                iter(
                    [
                        encode(
                            {
                                "type": "ADDED",
                                "object": {
                                    "kind": "Pod",
                                    "metadata": {
                                        "uid": "new",
                                        "name": "vllm-0",
                                        "resourceVersion": "2",
                                    },
                                },
                            }
                        )
                    ]
                )
            )
            next(watch)
            self.addCleanup(watch.close)
            runtime_spec = importlib.util.spec_from_file_location(
                "runtime_e2e", ROOT / "deploy/eks/capture_runtime.py"
            )
            runtime = importlib.util.module_from_spec(runtime_spec)
            runtime_spec.loader.exec_module(runtime)
            supervisor = runtime.Supervisor(root / "node-spool", "new")
            self.addCleanup(supervisor.file.close)
            node_server, node_url = serve(supervisor.handler())
            self.addCleanup(node_server.server_close)
            self.addCleanup(node_server.shutdown)
            node = NodeLifecycleAdapter(rows, HTTP(node_url, local_test=True), "new", 0, producer)
            node.clock()
            time.sleep(0.01)
            supervisor.record("heartbeat")
            node.poll()
            time.sleep(0.01)
            node.clock()
            node.clocks = ClockMapper([r for r in all_rows if r["source_kind"] == "clocks"])
            node.loading_receipt()
            end_ms = time.monotonic_ns() // 1_000_000
            spec = {
                "attempt_index": 1,
                "target_slot": 0,
                "target_uid": "0",
                "replacement_uid": "new",
                "expected_offers": registered_offers(1, start_ms, end_ms, HASH),
                "config_sha256": HASH,
                "traffic_start_ms": start_ms,
                "pre_end_ms": start_ms + 600000,
                "capture_start_ms": start_ms,
                "capture_end_ms": end_ms,
            }
            archive = Archive.create(
                root / "archive",
                {
                    "registration_id": REGISTRATION_ID,
                    "sources_sha256": {
                        **dict.fromkeys(REQUIRED_PINS, HASH),
                        "registration": REGISTRATION_GIT_BLOB_SHA256,
                    },
                },
            )
            writer = StreamingArchiveWriter(archive.root)
            for row in all_rows:
                writer.append("raw/" + row["source_kind"] + ".jsonl", row)
            campaign = OfflineCampaign(archive.root, spec)
            campaign.start_attempt(
                start_ms, absolute_deadline_ms=start_ms + 10_000_000, export_cleanup_ms=0
            )
            campaign.journal.setup_complete(start_ms, preconditions=True, reasons=[])
            campaign.record_capture_window(start_ms, end_ms)
            report = campaign.report()
            self.assertEqual(report["requests"]["cohorts"][0]["outcome"], "complete")
            self.assertFalse(
                report["measurement_valid"], "a small transport test must never establish a rollout"
            )
            materialize_bundle(archive.root, [spec])
            self.assertTrue(reproduce(archive.root, spec)["reproduced"])
            safe = sanitized_campaign(
                archive.root, root / "safe", [spec], key=b"adapter-sanitization-key-only" * 2
            )
            self.assertTrue(reproduce(root / "safe", safe["specs"][0])["reproduced"])
            counts = {}
            for path in sorted((root / "safe" / "raw").glob("*.jsonl")):
                exported = [json.loads(line) for line in path.read_bytes().splitlines()]
                counts[path.stem] = len(exported)
                for row in exported:
                    self.assertFalse(any(k.startswith("id-") for k in row["payload"]))
                    for name in ("boundaries", "field_reasons"):
                        self.assertFalse(
                            any(k.startswith("id-") for k in row["payload"].get(name, {}))
                        )
            print("sanitized_rows_per_source=" + json.dumps(counts, sort_keys=True), flush=True)
            print("sanitized_structural_keys_pseudonymized=0", flush=True)
            if output := os.environ.get("INF037B_E2E_OUTPUT"):
                import shutil

                shutil.copytree(root / "safe", Path(output))
            # Deleting even the latest atomic receipt must poison future captures.
            key = namespace + ":{admission}:global:active:capture"
            latest = wire.command("XREVRANGE", key, "+", "-", "COUNT", 1)[0][0]
            wire.command("XDEL", key, latest)
            lost = RedisAdapter(rows, wire, namespace, HASH, reservations=gateway.reservations)
            self.assertEqual(lost.operations()[-1]["payload"]["event"], "read_error")
            self.assertTrue(lost.lost)
