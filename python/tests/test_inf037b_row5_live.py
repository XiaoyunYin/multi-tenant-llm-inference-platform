"""Linux $0 live-port contracts, clock domains and continuous recovery."""

import copy
import importlib
import json
import ssl
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import Mock, patch

from inference_platform.inf037b_archive import IntegrityError, encode, sha
from inference_platform.inf037b_capture import wire_records
from inference_platform.inf037b_live import GatewayAdapter, LiveRows, RedisAdapter
from inference_platform.inf037b_row5 import canonical_role


class LiveTests(unittest.TestCase):
    def setUp(self):
        # Each new test must fail individually on the fdf098b scratch baseline.
        self.live = importlib.import_module("inference_platform.inf037b_row5_live")

    def sequence(self):
        from test_inf037b_row5_sequence import SequenceTests

        fixture = SequenceTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        return fixture

    def reader(self, fixture, *, gap=False, forbidden=False):
        gateways = {}
        self.polls = {g: 0 for g in ("gateway0", "gateway1")}
        self.raw_seq = {g: 0 for g in self.polls}
        self.source_event_ns = 1_750_000_000_000_000_000

        def http(gateway):
            offset = 0

            def get(path):
                nonlocal offset
                fixture.clock.sleep(0.25)
                self.polls[gateway] += 1
                poll = self.polls[gateway]
                denied = forbidden and gateway == "gateway0" and poll == 4
                data = {
                    "poll_seq": poll + (1 if gap and gateway == "gateway0" and poll >= 2 else 0),
                    "error_class": "EndpointSlice list: Forbidden" if denied else "",
                    "membership_known": not denied,
                    "members": [
                        {
                            "uid": f"uid{i}",
                            "name": f"slot{i}",
                            "ready": True,
                            "sampled": True,
                            "healthy": True,
                        }
                        for i in range(2)
                    ],
                }
                events = []
                if poll == 1:
                    events.append(("capture_start", {}))
                events.append(("install", data))
                body = b""
                for event, fields in events:
                    body += encode(
                        {
                            "schema": "gateway-measurement-v1",
                            "boot_id": gateway,
                            "sequence": self.raw_seq[gateway],
                            "mono_ns": self.source_event_ns,
                            "event": event,
                            "data": fields,
                        }
                    )
                    self.raw_seq[gateway] += 1
                offset += len(body)
                return body, {"X-Capture-Boot": gateway, "X-Capture-Next": str(offset)}

            return SimpleNamespace(get=get)

        for g in self.polls:
            gateways[g] = GatewayAdapter(
                LiveRows("recovery", "collector", clock=fixture.clock),
                http(g),
                g,
                slot_names={"slot0": 0, "slot1": 1},
                config_sha256="a" * 64,
            )
        return self.live.InstallRecovery(
            gateways, clock=fixture.clock, capture=SimpleNamespace(failed=False)
        )

    def test_relative_sample_refuses_before_snapshot(self):
        f = self.sequence()
        f.clock.ns = 5_000_000_000_000
        relative_sample_ms = 10
        with self.assertRaisesRegex(IntegrityError, "fitness:row5_stage_deadline"):
            f.stage("known0", (relative_sample_ms + 1000) * 1_000_000)
        self.assertEqual(f.events, [])

    def test_epoch_sample_refuses_stop_domain_before_snapshot(self):
        f = self.sequence()
        with self.assertRaisesRegex(IntegrityError, "fitness:row5_stop_domain"):
            f.stage("known0", 1_750_000_000_000 * 1_000_000)
        self.assertEqual(f.events, [])
        self.assertFalse(f.stage.failed)

    def test_outage_stop_domain_refuses_before_revoke(self):
        f = self.sequence()
        f.bring_up()
        with self.assertRaisesRegex(IntegrityError, "fitness:row5_stop_domain"):
            f.outage(f.clock() + 1_800_000_000_001, {})
        self.assertFalse(f.role.revoke_replaced)
        self.assertFalse(f.outage.started)

    def test_stop_domain_boundary_accepts_exact_1800_seconds(self):
        f = self.sequence()
        f.stage("known0", f.clock() + 1_800_000_000_000)
        self.assertEqual(len(f.requests), 2)

    def test_skipped_install_poll_refuses_and_role_is_restored(self):
        f = self.sequence()
        f.bring_up()
        f.outage.recovery = self.reader(f, gap=True)
        with self.assertRaisesRegex(IntegrityError, "fitness:recovery_source_incomplete"):
            f.outage(f.clock() + 30_000_000_000, {})
        self.assertEqual(canonical_role(f.role_port.role), f.original)
        self.assertTrue(f.outage.restore_outcome["success"])
        self.assertEqual(len(f.restores), 1)

    def test_install_stream_late_forbidden_restarts_then_passes(self):
        f = self.sequence()
        f.bring_up()
        recovery = self.reader(f, forbidden=True)
        f.outage.recovery = recovery
        restore = f.role.restore

        def checked_restore(**kwargs):
            self.assertIsNotNone(recovery.cursor)
            return restore(**kwargs)

        f.role.restore = checked_restore
        result = f.outage(f.clock() + 30_000_000_000, {})
        rows = result["row5_evidence"]["recovery"]["observations"]
        denied = [r for r in rows if r["reason"] == "403"]
        self.assertEqual(len(denied), 1)
        first_good = next(r for r in rows if r["known"] and r["time_ms"] > denied[0]["time_ms"])
        self.assertGreaterEqual(rows[-1]["time_ms"] - first_good["time_ms"], 2000)
        self.assertEqual(canonical_role(f.role_port.role), f.original)
        self.assertTrue(all(r["source_event_ns"] == self.source_event_ns for r in rows))

    def test_reader_stamps_collector_time_preserving_event_clock(self):
        f = self.sequence()
        recovery = self.reader(f)
        recovery.start(f.clock() + 10_000_000_000)
        batch = recovery(f.clock() + 10_000_000_000)
        self.assertTrue(batch["source_complete"])
        self.assertEqual(batch["cursors"], {"gateway0": 1, "gateway1": 1})
        for row in batch["observations"]:
            self.assertEqual(row["time_ms"], row["read_mono_ns"] // 1_000_000)
            self.assertNotEqual(row["time_ms"], row["source_event_ns"] // 1_000_000)

    def test_gateway_event_timestamp_in_observation_is_refused(self):
        f = self.sequence()
        f.bring_up()
        recovery = self.reader(f)
        recovery.start(f.clock() + 30_000_000_000)

        def corrupted(deadline):
            batch = recovery(deadline)
            for row in batch["observations"]:
                # Even a gateway clock numerically inside the collector range
                # is not a read timestamp; read_mono_ns must bind time_ms.
                row["source_event_ns"] = row["read_mono_ns"] - 1_000_000
                row["time_ms"] = row["source_event_ns"] // 1_000_000
            return batch

        f.outage.recovery = corrupted
        with self.assertRaisesRegex(IntegrityError, "fitness:recovery_source_incomplete"):
            f.outage(f.clock() + 30_000_000_000, {})
        self.assertEqual(canonical_role(f.role_port.role), f.original)

    def test_other_error_and_unknown_membership_map_unknown_and_loss_is_sticky(self):
        f = self.sequence()
        recovery = self.reader(f)
        recovery.start(f.clock() + 10_000_000_000)
        for error, known, reason in (
            ("403 Forbidden", True, "403"),
            ("timeout", True, "unknown"),
            ("", False, "unknown"),
        ):
            raw = {
                "mono_ns": 99,
                "data": {
                    "poll_seq": recovery.last["gateway0"] + 1,
                    "error_class": error,
                    "membership_known": known,
                    "members": [],
                },
            }
            recovery.install("gateway0", raw)
            self.assertEqual(recovery.pending[-1]["reason"], reason)
        recovery.capture.failed = True
        self.assertFalse(recovery(f.clock() + 10_000_000_000)["source_complete"])
        recovery.capture.failed = False
        recovery.gateways["gateway0"].lost = True
        self.assertFalse(recovery(f.clock() + 10_000_000_000)["source_complete"])

    def test_existing_redis_reader_supplies_every_sequencer_field(self):
        from test_inf037b_row5_sequence import Clock

        clock = Clock()
        wire = Mock()
        raw = {
            "redis_time_ms": 20000,
            "capture_order": "0",
            "lows": [],
            "active": [],
            "state": ["n", "2"],
            "reports": [],
        }
        for g in ("gateway-0", "gateway-1"):
            raw["reports"].extend([g, json.dumps({"n": 2, "unknown": False, "expires": 28000})])
        wire.command.return_value = json.dumps(raw)
        adapter = RedisAdapter(
            LiveRows("reader", "collector", clock=clock), wire, "test", "a" * 64, report_ttl_ms=8000
        )
        for row in (
            adapter.snapshot(snapshot_id="known2"),
            adapter.snapshot(captured=(copy.deepcopy(raw), clock(), "known2")),
        ):
            self.assertIsNone(row["error"])
            p = row["payload"]
            self.assertEqual(p["redis_time_ms"], 20000)
            self.assertEqual(p["state"]["n"], 2)
            self.assertEqual(p["active_reservations"], [])
            self.assertEqual(p["occupied"], 0)
            for report in p["reports"].values():
                self.assertEqual(
                    report, {"n": 2, "unknown": False, "expires_ms": 28000, "stored_ms": 20000}
                )
            self.assertLessEqual(row["capture_start_mono_ns"], row["capture_end_mono_ns"])
            self.assertTrue(self.live.KnownStage.matches(row, 2))

    def test_live_clients_are_gateway_keyed_and_retain_real_http_in_owner(self):
        from test_inf037b_capture import CaptureTests

        from inference_platform import inf037b_row5_capture as capture
        from inference_platform.inf037b_sources import ClockMapper

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                body = b'{"error":{"code":"discovery_unknown"}}'
                self.send_response(503)
                self.send_header("X-Request-ID", "req_" + "1" * 32)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        with TemporaryDirectory() as directory:
            helper = CaptureTests()
            self.addCleanup(helper.doCleanups)
            sources = {
                "client:" + g: [["client", "client:" + g, "kernel-boot"]]
                for g in ("gateway0", "gateway1")
            }
            sources.update({g: [["gateway", g, g]] for g in ("gateway0", "gateway1")})
            sources.update(
                redis=[["redis", "redis", "redis"]],
                diagnostic=[["controller", "operator", "kernel-boot"]],
            )
            owner = helper.owner(Path(directory), sources=sources, attempt="setup")
            context = ssl.create_default_context()
            live = self.live.LiveRow5(
                owner=owner,
                redis_wire=Mock(),
                redis_source="redis",
                redis_gateway_ids={g: g for g in ("gateway0", "gateway1")},
                gateways={
                    g: {
                        "source": g,
                        "boot": g,
                        "http": {"base": "https://localhost"},
                        "client_source": "client:" + g,
                        "request": {"context": context},
                    }
                    for g in ("gateway0", "gateway1")
                },
                slots={},
                role=Mock(),
                binary=Path(__file__),
                binary_sha256=sha(Path(__file__).read_bytes()),
                diagnostic_source="diagnostic",
                dial_addr="127.0.0.1:6379",
                config={"namespace": "row5-test"},
                gateway_config_captures={},
                measured_tenants=["measured"],
                configuration_sha256="a" * 64,
                stop_ns=10**18,
                stop_collectors=lambda: None,
            )
            clients = live.clients
            self.assertIsInstance(live.redis, RedisAdapter)
            self.assertIsInstance(live.row5_control, self.live.OutageSequence)
            self.assertTrue(live.row5_stage.defer_proofs)
            self.assertIs(live.row5_stage.request_arguments("gateway0")["context"], context)
            for g, client in clients.items():
                client.request(
                    url=f"http://127.0.0.1:{server.server_port}/v1/chat/completions",
                    payload={},
                    credential="fixture",
                    local_test=True,
                    offer={
                        "request_id": g,
                        "offer_index": 0,
                        "prefix_id": "row5",
                        "scheduled_ms": 0,
                    },
                )
            descriptor = owner.close()
            self.assertGreater(len(list(wire_records(owner.root / "wire"))), 0)
            live.descriptor = descriptor
            live.descriptor_sha256 = sha(encode(descriptor))
            live.rows = [
                {
                    "record_id": "redis:before",
                    "source_kind": "redis",
                    "payload": {"event": "snapshot", "store_order": 1},
                },
                {
                    "record_id": "redis:after",
                    "source_kind": "redis",
                    "payload": {"event": "snapshot", "store_order": 2},
                },
            ]
            live.receipts = []
            live.reservations = {}
            live.clocks = ClockMapper([])
            for g, client in clients.items():
                request = client.requests[g]
                terminals = [
                    record
                    for record, _ in wire_records(owner.root / "wire")
                    if record["source"] == "client:" + g
                    and record["start_ns"] == request["start_ns"]
                    and record["metadata"].get("client_request_end") is True
                ]
                self.assertEqual(len(terminals), 1)
                self.assertGreater(terminals[0]["end_ns"], request["end_ns"])

            gateway = "gateway0"
            request = clients[gateway].requests[gateway]
            args = live.proof_inputs(
                "unknown",
                gateway,
                {"request_id": gateway},
                live.rows[0],
                live.rows[1],
                {},
            )
            with (
                patch.object(capture, "gateway_prefix_from_capture", return_value=b"prefix"),
                patch.object(capture, "refusal_control", return_value={"accepted": True}),
                patch.object(ClockMapper, "inverse", return_value=[0, 1]),
            ):
                proof = capture.captured_refusal_control(
                    **args,
                    redis_before={"source_generation": "redis"},
                    redis_after={"source_generation": "redis"},
                )
            self.assertTrue(proof["accepted"])
            self.assertEqual(proof["client"]["client_code"], "discovery_unknown")
            self.assertEqual(proof["client"]["end_ns"], args["request_end_ns"])

    def test_proof_inputs_refuses_wire_terminal_before_client_row_end(self):
        live = self.live.LiveRow5.__new__(self.live.LiveRow5)
        snapshot = {
            "record_id": "redis:before",
            "source_kind": "redis",
            "payload": {"event": "snapshot", "store_order": 1},
        }
        after = {
            "record_id": "redis:after",
            "source_kind": "redis",
            "payload": {"event": "snapshot", "store_order": 2},
        }
        live.rows = [snapshot, after]
        live.owner = SimpleNamespace(root=Path("."))
        live.reservations = {}
        live.receipts = []
        live.clients = {
            "gateway0": SimpleNamespace(
                requests={
                    "offer": {
                        "gateway_request_id": "req_" + "1" * 32,
                        "start_ns": 100,
                        "end_ns": 151,
                    }
                }
            )
        }
        live.spec = {"gateway0": {"client_source": "client:gateway0"}}
        records = [
            (
                {
                    "source": "client:gateway0",
                    "start_ns": 100,
                    "end_ns": 101,
                    "metadata": {"headers": [["X-Request-ID", "req_" + "1" * 32]]},
                },
                b"",
            ),
            (
                {
                    "source": "client:gateway0",
                    "start_ns": 100,
                    "end_ns": 150,
                    "metadata": {"client_request_end": True},
                },
                b"",
            ),
        ]
        with patch.object(self.live, "wire_records", return_value=records):
            with self.assertRaisesRegex(IntegrityError, "fitness:row5_client_end_order"):
                live.proof_inputs(
                    "unknown", "gateway0", {"request_id": "offer"}, snapshot, after, {}
                )

    def test_proof_inputs_forward_retained_known_gateway_to_unchanged_checker(self):
        from test_inf037b_capture import CaptureTests
        from test_inf037b_row5_capture import KnownGatewayControlTests

        from inference_platform.inf037b_row5_capture import known_gateway_control
        from inference_platform.inf037b_sources import ClockMapper

        case = KnownGatewayControlTests().fixture(2)
        with TemporaryDirectory() as directory:
            helper = CaptureTests()
            self.addCleanup(helper.doCleanups)
            sources = {
                "gw": [["gateway", "gateway0", "boot"]],
                "client": [["client", "client:gateway0", "kernel-boot"]],
                "redis": [["redis", "redis", "redis"]],
            }
            owner = helper.owner(Path(directory), sources=sources, attempt="setup")
            live = self.live.LiveRow5.__new__(self.live.LiveRow5)
            live.owner = owner
            live.rows = []
            for label in ("snapshot", "after", "gateway"):
                old = case[label]
                source = "gw" if label == "gateway" else "redis"
                row = owner.rows(source).row(
                    old["source_kind"],
                    old["source_identity"],
                    "boot" if label == "gateway" else "redis",
                    old["payload"]["event"],
                    old["payload"],
                )
                case[label] = row
                live.rows.append(row)
            for operation in case["redis_operations"]:
                live.rows.append(
                    owner.rows("redis").row(
                        "redis",
                        "redis",
                        "redis",
                        operation["payload"]["event"],
                        operation["payload"],
                    )
                )
            case["snapshot"]["capture_start_mono_ns"] = 100
            case["snapshot"]["capture_end_mono_ns"] = 110
            case["after"]["capture_start_mono_ns"] = 200
            case["after"]["capture_end_mono_ns"] = 210
            case["snapshot"]["collector_boot_id"] = owner.boot
            case["after"]["collector_boot_id"] = owner.boot
            raw = case["raw_gateway_prefix"]
            path = "/internal/measurement?offset=0"
            owner.retain(
                "gw",
                1,
                2,
                b"",
                {
                    "path": path,
                    "status": 200,
                    "headers": [["X-Capture-Boot", "boot"], ["X-Capture-Next", str(len(raw))]],
                },
            )
            owner.retain("gw", 1, 2, raw, {"path": path})
            owner.retain(
                "client",
                case["request_start_ns"],
                case["request_start_ns"] + 1,
                b"",
                {"status": 200, "headers": [["X-Request-ID", case["gateway_request_id"]]]},
            )
            wire_end = case["request_end_ns"] + 2_000_000
            case["after"]["capture_start_mono_ns"] = wire_end + 1
            case["after"]["capture_end_mono_ns"] = wire_end + 10
            owner.retain(
                "client",
                case["request_start_ns"],
                wire_end,
                b"",
                {"client_request_end": True},
            )
            live.descriptor = owner.close()
            live.descriptor_sha256 = sha(encode(live.descriptor))
            live.reservations = {rid: "offer" for rid in case["gateway_reservations"]}
            live.receipts = case["diagnostic_receipts"]
            live.spec = {"gateway0": {"source": "gw", "boot": "boot", "client_source": "client"}}
            request = {
                "gateway_request_id": case["gateway_request_id"],
                "start_ns": case["request_start_ns"],
                "end_ns": case["request_end_ns"],
            }
            live.clients = {"gateway0": SimpleNamespace(requests={"offer": request})}
            self.assertGreater(wire_end, request["end_ns"])
            live.clocks = ClockMapper([])
            inverse_calls = []

            def recording_inverse(clock_id, boot_id, lower, upper):
                inverse_calls.append((clock_id, boot_id, lower, upper))
                return case["gateway_redis_bounds"]

            live.clocks.inverse = recording_inverse
            args = live.proof_inputs(
                "known2", "gateway0", {"request_id": "offer"}, case["snapshot"], case["after"], {}
            )
            self.assertEqual(args["request_end_ns"], wire_end)
            self.assertEqual(
                args["gateway_redis_bounds"],
                live.bounds(case["request_start_ns"], wire_end),
            )
            expected_inverse_call = (
                "redis",
                "redis",
                case["request_start_ns"] // 1_000_000,
                (wire_end + 999_999) // 1_000_000,
            )
            self.assertEqual(inverse_calls, [expected_inverse_call, expected_inverse_call])
            self.assertEqual(
                known_gateway_control(
                    **args,
                    snapshot=case["snapshot"],
                    after=case["after"],
                    expected_n=2,
                    expected_snapshot_id="known2",
                )["effective_b"],
                10,
            )
            changed = copy.deepcopy(case["snapshot"])
            changed["payload"]["occupied"] = 1
            with self.assertRaisesRegex(IntegrityError, "fitness:row5_snapshot_capture"):
                live.proof_inputs(
                    "known2", "gateway0", {"request_id": "offer"}, changed, case["after"], {}
                )

    def test_recovery_cursor_failure_still_restores_role(self):
        f = self.sequence()
        f.bring_up()
        f.outage.recovery = Mock()
        f.outage.recovery.start.side_effect = IntegrityError("fitness:recovery_source_incomplete")
        with self.assertRaisesRegex(IntegrityError, "fitness:recovery_source_incomplete"):
            f.outage(f.clock() + 30_000_000_000, {})
        self.assertEqual(canonical_role(f.role_port.role), f.original)
        self.assertTrue(f.outage.restore_outcome["success"])

    def test_proof_inputs_connect_retained_refusal_to_unchanged_checker(self):
        from test_inf037b_capture import CaptureTests
        from test_inf037b_row5_capture import GatewayRefusalPrefixTests, RedisControlEvidenceTests

        from inference_platform.inf037b_row5_capture import captured_refusal_control
        from inference_platform.inf037b_sources import ClockMapper

        raw_fixture, redis_fixture = GatewayRefusalPrefixTests(), RedisControlEvidenceTests()
        raw_fixture.setUp()
        redis_fixture.setUp()
        with TemporaryDirectory() as directory:
            helper = CaptureTests()
            self.addCleanup(helper.doCleanups)
            owner = helper.owner(
                Path(directory),
                sources={
                    "gw": [["gateway", "gateway0", raw_fixture.boot]],
                    "client": [["client", "client:gateway0", "kernel-boot"]],
                    "redis": [["redis", "redis", "redis"]],
                },
                attempt="setup",
            )
            rows = []
            for original in [redis_fixture.before, redis_fixture.after, *redis_fixture.events]:
                rows.append(
                    owner.rows("redis").row(
                        "redis", "redis", "redis", original["payload"]["event"], original["payload"]
                    )
                )
            raw = raw_fixture.raw()
            path = "/internal/measurement?offset=0"
            owner.retain(
                "gw",
                1,
                2,
                b"",
                {
                    "path": path,
                    "status": 200,
                    "headers": [
                        ["X-Capture-Boot", raw_fixture.boot],
                        ["X-Capture-Next", str(len(raw))],
                    ],
                },
            )
            owner.retain("gw", 1, 2, raw, {"path": path})
            start, end = 111, 150
            rows[0]["capture_start_mono_ns"] = 100
            rows[0]["capture_end_mono_ns"] = 110
            rows[1]["capture_start_mono_ns"] = 200
            rows[1]["capture_end_mono_ns"] = 210
            rows[0]["collector_boot_id"] = owner.boot
            rows[1]["collector_boot_id"] = owner.boot
            body = encode({"error": {"code": "discovery_unknown"}})
            owner.retain(
                "client",
                start,
                start + 1,
                b"",
                {"status": 503, "headers": [["X-Request-ID", raw_fixture.request]]},
            )
            owner.retain("client", start, start + 2, body, {"status": 503})
            owner.retain("client", start, end, b"", {"client_request_end": True})
            live = self.live.LiveRow5.__new__(self.live.LiveRow5)
            live.owner, live.rows, live.receipts, live.reservations = owner, rows, [], {}
            live.descriptor = owner.close()
            live.descriptor_sha256 = sha(encode(live.descriptor))
            live.spec = {
                "gateway0": {"source": "gw", "boot": raw_fixture.boot, "client_source": "client"}
            }
            live.clients = {
                "gateway0": SimpleNamespace(
                    requests={
                        "offer": {
                            "gateway_request_id": raw_fixture.request,
                            "start_ns": start,
                            "end_ns": end,
                        }
                    }
                )
            }
            live.clocks = ClockMapper(
                [
                    {
                        "payload": {
                            "event": "mapping",
                            "clock_id": "redis",
                            "boot_id": "redis",
                            "remote_ms": at,
                            "send_ms": at,
                            "receive_ms": at,
                            "local_mono_ms": at,
                            "local_wall_ms": at,
                        }
                    }
                    for at in (0, 1000)
                ]
            )
            args = live.proof_inputs(
                "unknown", "gateway0", {"request_id": "offer"}, rows[0], rows[1], {}
            )
            proof = captured_refusal_control(**args, redis_before=rows[0], redis_after=rows[1])
            self.assertEqual(proof["client"]["client_code"], "discovery_unknown")
            self.assertEqual(proof["gateway"]["reservation_id"], raw_fixture.reservation)
            self.assertEqual(proof["redis"]["reservation_id"], raw_fixture.reservation)

    def test_proof_inputs_connect_diagnostic_interval_to_unchanged_checker(self):
        from test_inf037b_row5_capture import DiagnosticSnapshotControlTests

        from inference_platform.inf037b_row5_capture import diagnostic_snapshot_control

        case = DiagnosticSnapshotControlTests().fixture("unknown")
        for index, row in enumerate([case["snapshot"], case["after"], *case["redis_operations"]]):
            row["record_id"] = str(index)
        live = self.live.LiveRow5.__new__(self.live.LiveRow5)
        live.owner = SimpleNamespace(boot="operator-boot")
        live.rows = [case["snapshot"], case["after"], *case["redis_operations"]]
        live.reservations = {rid: "request" for rid in case["gateway_ids"]}
        live.receipts = [
            {
                **case["receipt"],
                "process_start_ns": case["process_start_ns"],
                "process_end_ns": case["process_end_ns"],
            }
        ]
        live.bounds = lambda start, end: case["diagnostic_redis_bounds"]
        args = live.proof_inputs(
            "unknown", None, None, case["snapshot"], case["after"], case["receipt"]
        )
        self.assertEqual(
            diagnostic_snapshot_control(
                **args,
                snapshot=case["snapshot"],
                after=case["after"],
                receipt=case["receipt"],
                control_name="unknown",
            )["decision"],
            "allowed",
        )

    def test_final_settlement_retains_late_error_instead_of_hiding_it(self):
        f = self.sequence()
        f.bring_up()
        recovery = self.reader(f)
        f.outage.recovery = recovery

        def settle():
            recovery.install(
                "gateway0",
                {
                    "mono_ns": self.source_event_ns,
                    "data": {
                        "poll_seq": recovery.last["gateway0"] + 1,
                        "members": [],
                        "error_class": "403",
                        "membership_known": False,
                    },
                },
            )

        recovery.settle = settle
        with self.assertRaisesRegex(IntegrityError, "fitness:recovery_agreement"):
            f.outage(f.clock() + 30_000_000_000, {})
        self.assertEqual(canonical_role(f.role_port.role), f.original)

    def test_rendered_eks_and_kind_both_enable_measurement_recorder(self):
        from test_eks_package_a import INPUTS

        from inference_platform.eks_deployment import resources

        with patch.object(
            sys, "path", [str(Path(__file__).resolve().parents[2] / "scripts"), *sys.path]
        ):
            rehearsal = importlib.import_module("rehearse_eks_package_a")
        eks = resources(INPUTS, "runtime-source")
        kind = copy.deepcopy(eks)
        # Image inventory validation is independent of the gateway environment.
        with patch.object(rehearsal, "rewrite_kind_workload_images", return_value=set()):
            rehearsal.mutate_kind_manifest(kind, "fixture-gateway:local", {}, [])
        for manifest in (eks, kind):
            gateway = next(
                o
                for o in manifest["items"]
                if o["kind"] == "StatefulSet" and o["metadata"]["name"] == "gateway"
            )
            env = {
                e["name"]: e.get("value")
                for e in gateway["spec"]["template"]["spec"]["containers"][0]["env"]
            }
            self.assertEqual(env["GATEWAY_MEASUREMENT_PATH"], "/capture-data/gateway.jsonl")
