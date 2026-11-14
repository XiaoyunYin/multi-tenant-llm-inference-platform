import copy
import unittest

from inference_platform.inf037b_archive import IntegrityError, encode, sha
from inference_platform.inf037b_row5_capture import (
    ROW5_SNAPSHOT_IDS,
    captured_refusal_control,
    client_refusal_from_capture,
    diagnostic_snapshot_control,
    gateway_admit_join,
    gateway_prefix_from_capture,
    gateway_prefix_from_wire,
    gateway_resolved_config_from_capture,
    known_gateway_control,
    local_refusal_prefix,
    redis_refusal_interval,
    refusal_control,
    select_row5_snapshots,
)


class GatewayRefusalPrefixTests(unittest.TestCase):
    def setUp(self):
        self.request = "req_" + "1" * 32
        self.reservation = "rsv_" + "2" * 32
        self.boot = "gateway-boot"
        self.events = [
            ("capture_start", {}),
            ("poll_start", {"poll_seq": 1}),
            ("install", {"poll_seq": 1, "membership_known": False}),
            (
                "deny",
                {
                    "request_id": self.request,
                    "http_status": 503,
                    "denial_code": "discovery_unknown",
                },
            ),
            (
                "terminal",
                {
                    "request_id": self.request,
                    "reservation_id": self.reservation,
                    "outcome": "rejected",
                    "code": "discovery_unknown",
                },
            ),
        ]

    def raw(self, events=None):
        return b"".join(
            encode(
                {
                    "schema": "gateway-measurement-v1",
                    "sequence": i,
                    "boot_id": self.boot,
                    "mono_ns": i,
                    "event": event,
                    "data": data,
                }
            )
            for i, (event, data) in enumerate(events if events is not None else self.events)
        )

    def prove(self, raw, diagnostic_receipts=()):
        return local_refusal_prefix(
            raw,
            expected_sha256=sha(raw),
            gateway_boot=self.boot,
            gateway_request_id=self.request,
            diagnostic_receipts=diagnostic_receipts,
        )

    def test_valid_contiguous_refusal_returns_original_reservation(self):
        result = self.prove(self.raw())
        self.assertEqual(result["reservation_id"], self.reservation)
        self.assertEqual((result["deny_seq"], result["terminal_seq"]), (3, 4))

    def test_binding_and_capture_gaps_refuse(self):
        raw = self.raw()
        with self.assertRaisesRegex(IntegrityError, "fitness:refusal_capture_binding"):
            local_refusal_prefix(
                raw,
                expected_sha256="0" * 64,
                gateway_boot=self.boot,
                gateway_request_id=self.request,
                diagnostic_receipts=[],
            )
        with self.assertRaisesRegex(IntegrityError, "fitness:refusal_capture_binding"):
            self.prove(raw[:-1])
        lines = raw.splitlines(keepends=True)
        with self.assertRaisesRegex(IntegrityError, "fitness:refusal_capture_gap"):
            self.prove(b"".join(lines[:2] + lines[3:]))
        with self.assertRaisesRegex(IntegrityError, "fitness:refusal_capture_start"):
            self.prove(self.raw(self.events[1:]))

    def test_after_admit_and_unproven_absence_refuse(self):
        admitted = copy.deepcopy(self.events)
        admitted.insert(
            3, ("admit", {"request_id": self.request, "reservation_id": self.reservation})
        )
        with self.assertRaisesRegex(IntegrityError, "fitness:refusal_after_admit"):
            self.prove(self.raw(admitted))
        with self.assertRaisesRegex(IntegrityError, "fitness:refusal_absence_unproven"):
            self.prove(self.raw(self.events[:-1]))
        closed = copy.deepcopy(self.events)
        closed.insert(3, ("capture_end", {}))
        with self.assertRaisesRegex(IntegrityError, "fitness:refusal_capture_closed"):
            self.prove(self.raw(closed))
        wrong = copy.deepcopy(self.events)
        wrong[-2][1]["denial_code"] = "discovery_unknown_after_admit"
        with self.assertRaisesRegex(IntegrityError, "fitness:refusal_terminal"):
            self.prove(self.raw(wrong))

    def test_non_string_gateway_reservation_is_refused(self):
        events = copy.deepcopy(self.events)
        events.insert(3, ("terminal", {"request_id": "req_" + "9" * 32, "reservation_id": 42}))
        with self.assertRaisesRegex(IntegrityError, "fitness:gateway_reservation_invalid"):
            self.prove(self.raw(events))
        events[3][1]["reservation_id"] = {"malformed": True}
        with self.assertRaisesRegex(IntegrityError, "fitness:gateway_reservation_invalid"):
            self.prove(self.raw(events))

    def test_unrelated_prefixed_probe_passes_but_actual_receipt_overlap_refuses(self):
        chance_id = "rsv_d1a6" + "a" * 28
        other = copy.deepcopy(self.events)
        other.insert(
            3,
            (
                "terminal",
                {
                    "request_id": "req_" + "9" * 32,
                    "reservation_id": chance_id,
                    "outcome": "completed",
                    "code": "completed",
                },
            ),
        )
        raw = self.raw(other)
        self.assertEqual(self.prove(raw)["reservation_id"], self.reservation)
        with self.assertRaisesRegex(IntegrityError, "fitness:diagnostic_id_in_gateway"):
            self.prove(raw, diagnostic_receipts=[{"reservation_id": chance_id}])

    def test_gateway_diagnostic_id_and_discovery_ambiguity_refuse(self):
        diagnostic = copy.deepcopy(self.events)
        diagnostic[-1][1]["reservation_id"] = "rsv_d1a6" + "0" * 28
        with self.assertRaisesRegex(IntegrityError, "fitness:diagnostic_id_in_gateway"):
            self.prove(self.raw(diagnostic))
        known = copy.deepcopy(self.events)
        known[2][1]["membership_known"] = True
        with self.assertRaisesRegex(IntegrityError, "fitness:refusal_discovery_unknown"):
            self.prove(self.raw(known))
        in_flight = copy.deepcopy(self.events)
        in_flight.insert(3, ("poll_start", {"poll_seq": 2}))
        with self.assertRaisesRegex(IntegrityError, "fitness:refusal_discovery_ambiguous"):
            self.prove(self.raw(in_flight))


class GatewayWireEvidenceTests(unittest.TestCase):
    def setUp(self):
        fixture = GatewayRefusalPrefixTests(
            methodName="test_valid_contiguous_refusal_returns_original_reservation"
        )
        fixture.setUp()
        self.raw, self.boot, self.request = fixture.raw(), fixture.boot, fixture.request
        self.operation = "a" * 64

    def entries(self, parts):
        offset = 0
        records = []
        for seq, (metadata, body) in enumerate(parts):
            records.append(
                (
                    {
                        "source": "gateway-wire",
                        "operation_sha256": self.operation,
                        "sequence": seq,
                        "offset": offset,
                        "length": len(body),
                        "sha256": sha(body),
                        "metadata": metadata,
                    },
                    body,
                )
            )
            offset += len(body)
        return records

    def header(self, offset, next_offset, *, boot=None):
        path = f"/internal/measurement?offset={offset}"
        return {
            "path": path,
            "status": 200,
            "headers": [
                ["X-Capture-Boot", boot or self.boot],
                ["X-Capture-Next", str(next_offset)],
            ],
        }

    def prefix(self, entries):
        return gateway_prefix_from_wire(
            entries, source="gateway-wire", operation_sha256=self.operation, gateway_boot=self.boot
        )

    def test_reconstructs_multiple_exact_responses_and_checks_raw_prefix(self):
        split = self.raw.index(b"\n") + 1
        first, second = self.raw[:split], self.raw[split:]
        p0, p1 = "/internal/measurement?offset=0", f"/internal/measurement?offset={split}"
        records = self.entries(
            [
                (self.header(0, split), b""),
                ({"path": p0}, first),
                ({"path": "/internal/measurement?clock=1", "status": 200, "headers": []}, b""),
                ({"path": "/internal/measurement?clock=1"}, b'{"clock":1}'),
                (self.header(split, len(self.raw)), b""),
                ({"path": p1}, second),
            ]
        )
        prefix = self.prefix(records)
        self.assertEqual(prefix, self.raw)
        result = local_refusal_prefix(
            prefix,
            expected_sha256=sha(prefix),
            gateway_boot=self.boot,
            gateway_request_id=self.request,
            diagnostic_receipts=[],
        )
        self.assertEqual(result["gateway_request_id"], self.request)

    def test_binding_and_wire_integrity_fail_closed(self):
        records = self.entries(
            [
                (self.header(0, len(self.raw)), b""),
                ({"path": "/internal/measurement?offset=0"}, self.raw),
            ]
        )
        with self.assertRaisesRegex(IntegrityError, "fitness:gateway_wire_binding"):
            gateway_prefix_from_wire(
                records, source="", operation_sha256=self.operation, gateway_boot=self.boot
            )
        bad = copy.deepcopy(records)
        bad[1][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(IntegrityError, "fitness:gateway_wire_integrity"):
            self.prefix(bad)
        with self.assertRaisesRegex(IntegrityError, "fitness:gateway_wire_incomplete"):
            self.prefix([])
        short = self.entries(
            [
                (self.header(0, len(self.raw)), b""),
                ({"path": "/internal/measurement?offset=0"}, self.raw[:-1]),
            ]
        )
        with self.assertRaisesRegex(IntegrityError, "fitness:gateway_wire_incomplete"):
            self.prefix(short)

    def test_wire_size_and_overrun_are_refused_before_later_corruption(self):
        path = "/internal/measurement?offset=0"
        huge = b"x" * 8_388_609
        with self.assertRaisesRegex(IntegrityError, "fitness:gateway_wire_incomplete"):
            self.prefix(self.entries([(self.header(0, len(huge)), b""), ({"path": path}, huge)]))
        records = self.entries(
            [
                (self.header(0, 1), b""),
                ({"path": path}, b"too long"),
                ({"path": "/unrelated"}, b"x"),
            ]
        )
        records[-1][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(IntegrityError, "fitness:gateway_wire_incomplete"):
            self.prefix(records)

    def test_response_identity_headers_and_offsets_fail_closed(self):
        body = ({"path": "/internal/measurement?offset=0"}, self.raw)
        headers = [
            {"path": "/internal/measurement?clock=1", "status": 403, "headers": []},
            {"path": "/internal/measurement?clock=1", "status": 200.0, "headers": []},
            {"status": 200, "headers": []},
            {**self.header(0, len(self.raw)), "status": 403},
            {
                "path": "/internal/measurement?offset=0",
                "status": 200,
                "headers": [
                    ["X-Capture-Boot", self.boot, "extra"],
                    ["X-Capture-Next", str(len(self.raw))],
                ],
            },
            {
                "path": "/internal/measurement?offset=0",
                "status": 200,
                "headers": [
                    ["X-Capture-Boot", self.boot],
                    ["X-Capture-Boot", self.boot],
                    ["X-Capture-Next", str(len(self.raw))],
                ],
            },
            self.header(0, len(self.raw), boot="wrong-boot"),
        ]
        for header in headers:
            with self.subTest(header=header):
                with self.assertRaisesRegex(IntegrityError, "fitness:gateway_wire_response"):
                    self.prefix(self.entries([(header, b""), body]))


class RedisControlEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.rid = "rsv_" + "1" * 32
        self.config = "a" * 64
        self.gateway = {
            "source_kind": "gateway",
            "source_identity": "gateway0",
            "error": None,
            "payload": {
                "event": "admit",
                "gateway_uid": "gateway0",
                "request_id": "control",
                "reservation_id": self.rid,
                "decision": "allowed",
                "effective_b": 10,
                "admit_called": True,
            },
        }
        self.operation = {
            "source_kind": "redis",
            "source_identity": "redis",
            "error": None,
            "payload": {
                "event": "admit",
                "reservation_id": self.rid,
                "decision": "allowed",
                "effective_b": 10,
                "idempotent": False,
                "store_order": 11,
                "redis_time_ms": 120,
                "config_sha256": self.config,
            },
        }
        self.before = {
            "source_kind": "redis",
            "source_identity": "redis",
            "collector_boot_id": "operator-boot",
            "capture_start_mono_ns": 90,
            "capture_end_mono_ns": 110,
            "error": None,
            "payload": {
                "event": "snapshot",
                "store_order": 10,
                "redis_time_ms": 100,
                "config_sha256": self.config,
            },
        }
        self.after = {
            "source_kind": "redis",
            "source_identity": "redis",
            "collector_boot_id": "operator-boot",
            "capture_start_mono_ns": 160,
            "capture_end_mono_ns": 180,
            "error": None,
            "payload": {
                "event": "snapshot",
                "store_order": 12,
                "redis_time_ms": 200,
                "config_sha256": self.config,
            },
        }
        self.events = [
            {
                "source_kind": "redis",
                "source_identity": "redis",
                "error": None,
                "payload": {
                    "event": "unknown",
                    "store_order": 11,
                    "redis_time_ms": 120,
                    "config_sha256": self.config,
                },
            },
            {
                "source_kind": "redis",
                "source_identity": "redis",
                "error": None,
                "payload": {
                    "event": "report_store",
                    "store_order": 12,
                    "redis_time_ms": 150,
                    "config_sha256": self.config,
                },
            },
        ]

    def test_gateway_join_uses_reservation_and_rejects_diagnostic_ack(self):
        self.assertEqual(
            gateway_admit_join(self.gateway, self.operation, diagnostic_receipts=[]), self.rid
        )
        with self.assertRaisesRegex(IntegrityError, "fitness:control_gateway_ack"):
            gateway_admit_join(self.operation, self.operation, diagnostic_receipts=[])
        diagnostic = copy.deepcopy(self.gateway)
        diagnostic["payload"]["reservation_id"] = "rsv_d1a6" + "0" * 28
        with self.assertRaisesRegex(IntegrityError, "fitness:diagnostic_id_in_gateway"):
            gateway_admit_join(diagnostic, self.operation, diagnostic_receipts=[])
        wrong = copy.deepcopy(self.operation)
        wrong["payload"]["reservation_id"] = "rsv_" + "2" * 32
        with self.assertRaisesRegex(IntegrityError, "fitness:control_admit_join"):
            gateway_admit_join(self.gateway, wrong, diagnostic_receipts=[])
        wrong = copy.deepcopy(self.operation)
        wrong["payload"]["idempotent"] = True
        with self.assertRaisesRegex(IntegrityError, "fitness:control_admit_join"):
            gateway_admit_join(self.gateway, wrong, diagnostic_receipts=[])

    def test_refusal_control_requires_both_gateway_and_redis_evidence(self):
        fixture = GatewayRefusalPrefixTests(
            methodName="test_valid_contiguous_refusal_returns_original_reservation"
        )
        fixture.setUp()
        raw = fixture.raw()
        arguments = {
            "expected_sha256": sha(raw),
            "gateway_boot": fixture.boot,
            "gateway_request_id": fixture.request,
            "client_status": 503,
            "client_code": "discovery_unknown",
            "redis_before": self.before,
            "redis_after": self.after,
            "redis_operations": self.events,
            "request_start_ns": 111,
            "request_end_ns": 150,
            "collector_boot_id": "operator-boot",
            "diagnostic_receipts": [],
        }
        result = refusal_control(raw, **arguments)
        self.assertEqual(result["gateway"]["reservation_id"], fixture.reservation)
        self.assertEqual(result["redis"]["reservation_id"], fixture.reservation)
        bad = dict(arguments, client_status=200)
        with self.assertRaisesRegex(IntegrityError, "fitness:refusal_client_response"):
            refusal_control(raw, **bad)
        bad = dict(arguments, redis_operations=self.events[:1])
        with self.assertRaisesRegex(IntegrityError, "fitness:refusal_redis_gap"):
            refusal_control(raw, **bad)
        admitted = copy.deepcopy(self.events)
        admitted[0]["payload"].update(event="admit", reservation_id=fixture.reservation)
        bad = dict(arguments, redis_operations=admitted)
        with self.assertRaisesRegex(IntegrityError, "fitness:refusal_after_admit"):
            refusal_control(raw, **bad)

    def test_redis_interval_refuses_unproven_absence_and_after_admit(self):
        kwargs = {
            "request_start_ns": 111,
            "request_end_ns": 150,
            "collector_boot_id": "operator-boot",
            "diagnostic_receipts": [],
        }
        result = redis_refusal_interval(self.before, self.after, self.events, self.rid, **kwargs)
        self.assertEqual((result["first_order"], result["last_order"]), (10, 12))
        invalid_before = copy.deepcopy(self.before)
        invalid_before["source_kind"] = "gateway"
        with self.assertRaisesRegex(IntegrityError, "fitness:refusal_redis_interval"):
            redis_refusal_interval(invalid_before, self.after, self.events, self.rid, **kwargs)
        invalid_source = copy.deepcopy(self.events)
        invalid_source[0]["source_kind"] = "gateway"
        with self.assertRaisesRegex(IntegrityError, "fitness:refusal_redis_gap"):
            redis_refusal_interval(self.before, self.after, invalid_source, self.rid, **kwargs)
        with self.assertRaisesRegex(IntegrityError, "fitness:refusal_redis_gap"):
            redis_refusal_interval(self.before, self.after, self.events[:1], self.rid, **kwargs)
        wrong = copy.deepcopy(self.events)
        wrong[0]["payload"]["store_order"] = 12
        with self.assertRaisesRegex(IntegrityError, "fitness:refusal_redis_gap"):
            redis_refusal_interval(self.before, self.after, wrong, self.rid, **kwargs)
        admitted = copy.deepcopy(self.events)
        admitted[0]["payload"].update(event="admit", reservation_id=self.rid)
        with self.assertRaisesRegex(IntegrityError, "fitness:refusal_after_admit"):
            redis_refusal_interval(self.before, self.after, admitted, self.rid, **kwargs)
        with self.assertRaisesRegex(IntegrityError, "fitness:refusal_redis_interval"):
            redis_refusal_interval(
                self.before,
                self.after,
                self.events,
                self.rid,
                **{**kwargs, "request_start_ns": 109},
            )

    def test_refusal_interval_uses_ordered_same_boot_capture_brackets(self):
        kwargs = {
            "request_start_ns": 111,
            "request_end_ns": 150,
            "collector_boot_id": "operator-boot",
            "diagnostic_receipts": [],
        }
        result = redis_refusal_interval(self.before, self.after, self.events, self.rid, **kwargs)
        self.assertEqual(result["reservation_id"], self.rid)
        for mutation in ("before", "after", "boot", "request_start", "request_end"):
            before, after = copy.deepcopy(self.before), copy.deepcopy(self.after)
            bad = dict(kwargs)
            if mutation == "before":
                before["capture_end_mono_ns"] = 112
            elif mutation == "after":
                after["capture_start_mono_ns"] = 149
            elif mutation == "boot":
                after["collector_boot_id"] = "other-boot"
            elif mutation == "request_start":
                bad["request_start_ns"] = 109
            else:
                bad["request_end_ns"] = 161
            with (
                self.subTest(mutation=mutation),
                self.assertRaisesRegex(IntegrityError, "fitness:refusal_redis_interval"),
            ):
                redis_refusal_interval(before, after, self.events, self.rid, **bad)


class SnapshotIdentityTests(unittest.TestCase):
    def rows(self):
        return [
            {
                "source_kind": "redis",
                "source_identity": "redis",
                "error": None,
                "payload": {
                    "event": "snapshot",
                    "snapshot_id": name,
                    "redis_time_ms": 1000 + i,
                    "store_order": i,
                },
            }
            for i, name in enumerate(ROW5_SNAPSHOT_IDS)
        ]

    def test_duplicate_known_counts_select_designated_instances(self):
        rows = self.rows()
        gateway_row = {
            "source_kind": "gateway",
            "source_identity": "gateway0",
            "error": None,
            "payload": {"event": "admit", "snapshot_id": "known1"},
        }
        selected = select_row5_snapshots(rows + [gateway_row])
        self.assertIs(selected["known1"], rows[1])
        self.assertIs(selected["cached_stop_known1"], rows[3])
        self.assertIs(selected["known2"], rows[2])
        self.assertIs(selected["cached_restore_known2"], rows[4])
        self.assertIs(selected["post_outage_known2"], rows[7])
        with self.assertRaisesRegex(IntegrityError, "fitness:row5_snapshot_duplicate_or_invalid"):
            select_row5_snapshots(rows + [copy.deepcopy(rows[1])])
        with self.assertRaisesRegex(IntegrityError, "fitness:row5_snapshot_duplicate_or_invalid"):
            select_row5_snapshots(rows + [copy.deepcopy(rows[2])])
        with self.assertRaisesRegex(IntegrityError, "fitness:row5_snapshot_inventory"):
            select_row5_snapshots(rows[:-1])
        with self.assertRaisesRegex(IntegrityError, "fitness:row5_snapshot_inventory"):
            select_row5_snapshots(None)
        with self.assertRaisesRegex(IntegrityError, "fitness:row5_snapshot_inventory"):
            select_row5_snapshots([None])


class GatewayConfigCaptureTests(unittest.TestCase):
    def test_raw_config_requires_unique_boot_bound_exact_duration(self):
        from unittest.mock import patch

        fields = {
            "redis_addr": "redis:6379",
            "namespace": "ns",
            "global_capacity": 64,
            "lease_ms": 90000,
            "tombstone_ms": 300000,
            "running": 4,
            "waiting": 1,
            "ttl_ms": 8000,
            "hold_ms": 2000,
            "capture": True,
            "gateway_id": "gateway-0",
            "lease_ns": 90000000000,
            "tombstone_ns": 300000000000,
            "ttl_ns": 8000000000,
            "hold_ns": 2000000000,
        }
        records = [
            {
                "schema": "gateway-measurement-v1",
                "sequence": 0,
                "boot_id": "boot",
                "event": "capture_start",
                "data": {},
            },
            {
                "schema": "gateway-measurement-v1",
                "sequence": 1,
                "boot_id": "boot",
                "event": "admission_config",
                "data": fields,
            },
        ]
        args = dict(
            expected_binding={},
            expected_operation={},
            expected_descriptor_sha256="a" * 64,
            source="wire",
            gateway_uid="gateway0",
            gateway_boot="boot",
        )
        with patch(
            "inference_platform.inf037b_row5_capture.gateway_prefix_from_capture",
            return_value=b"".join(encode(r) for r in records),
        ):
            result = gateway_resolved_config_from_capture("unused", {}, **args)
            self.assertEqual(result["lease_ms"], 90000)
        for variant in ("precision", "identity", "duplicate", "boot"):
            bad = copy.deepcopy(records)
            if variant == "precision":
                bad[1]["data"]["ttl_ns"] += 1
            elif variant == "identity":
                bad[1]["data"]["gateway_id"] = "gateway-1"
            elif variant == "duplicate":
                extra = copy.deepcopy(bad[1])
                extra["sequence"] = 2
                bad.append(extra)
            else:
                bad[1]["boot_id"] = "other"
            with (
                self.subTest(variant=variant),
                patch(
                    "inference_platform.inf037b_row5_capture.gateway_prefix_from_capture",
                    return_value=b"".join(encode(r) for r in bad),
                ),
                self.assertRaisesRegex(IntegrityError, "fitness:gateway_config_capture"),
            ):
                gateway_resolved_config_from_capture("unused", {}, **args)


class ClientRefusalCaptureTests(unittest.TestCase):
    def test_bound_503_response_requires_request_identity_and_complete_wire(self):
        from unittest.mock import patch

        binding = {"session": "test"}
        sources = {"client-wire": [["client", "client:gateway0", "client-boot"]]}
        operation = {
            "body": {
                "binding": binding,
                "capture": {"sources": sources, "attempt": "setup", "boot_id": "collector"},
            }
        }
        descriptor = {
            "binding": binding,
            "operation": operation,
            "sources": sources,
            "attempt": "setup",
            "boot_id": "collector",
            "closed": True,
            "transport_clean": True,
        }
        request = "req_" + "a" * 32
        body = encode({"error": {"code": "discovery_unknown"}})

        def record(seq, data, meta, offset):
            return (
                {
                    "source": "client-wire",
                    "operation_sha256": sha(encode(operation)),
                    "sequence": seq,
                    "start_ns": 100,
                    "end_ns": 110 + seq,
                    "offset": offset,
                    "length": len(data),
                    "sha256": sha(data),
                    "metadata": meta,
                },
                data,
            )

        records = [
            record(0, b"", {"status": 503, "headers": [["X-Request-ID", request]]}, 0),
            record(1, body, {"status": 503}, 0),
            record(2, b"", {"client_request_end": True}, len(body)),
        ]
        args = dict(
            expected_binding=binding,
            expected_operation=operation,
            expected_descriptor_sha256=sha(encode(descriptor)),
            source="client-wire",
            client_identity="client:gateway0",
            client_boot="client-boot",
            gateway_request_id=request,
            request_start_ns=100,
        )

        def check(rows, **changes):
            with (
                patch("inference_platform.inf037b_probe.capture_rows", return_value=iter(())),
                patch("inference_platform.inf037b_capture.wire_records", return_value=iter(rows)),
            ):
                return client_refusal_from_capture("unused", descriptor, **(args | changes))

        proof = check(records)
        self.assertEqual((proof["client_status"], proof["client_code"]), (503, "discovery_unknown"))
        with self.assertRaisesRegex(IntegrityError, "fitness:client_refusal_response"):
            check(records, gateway_request_id="req_" + "b" * 32)
        with self.assertRaisesRegex(IntegrityError, "fitness:client_refusal_response"):
            check(records[:-1])
        with self.assertRaisesRegex(IntegrityError, "fitness:client_refusal_capture"):
            check(records, expected_descriptor_sha256="0" * 64)


class KnownGatewayControlTests(unittest.TestCase):
    def fixture(self, n):
        rid = "rsv_" + "1" * 32
        req = "req_" + "2" * 32
        decision = "system_capacity" if n == 0 else "allowed"
        reports = {
            g: {"n": n, "unknown": False, "stored_ms": 100, "expires_ms": 8100}
            for g in ("gateway0", "gateway1")
        }

        def snapshot(order, time_ms):
            return {
                "source_kind": "redis",
                "source_identity": "redis",
                "collector_boot_id": "operator-boot",
                "capture_start_mono_ns": time_ms,
                "capture_end_mono_ns": time_ms + 10,
                "error": None,
                "payload": {
                    "event": "snapshot",
                    "store_order": order,
                    "redis_time_ms": time_ms,
                    "config_sha256": "a" * 64,
                    "reports": copy.deepcopy(reports),
                    "state": {"n": n},
                    "active_reservations": [],
                    "occupied": 0,
                },
            }

        gateway = {
            "source_kind": "gateway",
            "source_identity": "gateway0",
            "source_generation": "boot",
            "error": None,
            "payload": {
                "event": "admit",
                "gateway_uid": "gateway0",
                "request_id": "offer",
                "reservation_id": rid,
                "decision": decision,
                "effective_b": 5 * n,
                "admit_called": True,
            },
        }

        def redis(event, order, time_ms, **fields):
            return {
                "source_kind": "redis",
                "source_identity": "redis",
                "error": None,
                "payload": {
                    "event": event,
                    "store_order": order,
                    "redis_time_ms": time_ms,
                    "config_sha256": "a" * 64,
                    "reservation_id": rid,
                    **fields,
                },
            }

        ops = [
            redis(
                "admit",
                11,
                120,
                decision=decision,
                effective_n=n,
                effective_b=n * 5,
                idempotent=False,
            )
        ]
        if n:
            ops.append(redis("release", 12, 130, decision="released", idempotent=False, occupied=0))
        events = [
            ("capture_start", {}),
            (
                "admit",
                {
                    "request_id": req,
                    "reservation_id": rid,
                    "decision": decision,
                    "effective_b": n * 5,
                },
            ),
        ]
        if n:
            events.append(
                ("release", {"request_id": req, "reservation_id": rid, "result": "released"})
            )
        events.append(
            (
                "terminal",
                {
                    "request_id": req,
                    "reservation_id": rid,
                    "code": "completed" if n else "system_capacity",
                },
            )
        )
        raw = b"".join(
            encode(
                {
                    "schema": "gateway-measurement-v1",
                    "sequence": i,
                    "boot_id": "boot",
                    "mono_ns": i,
                    "event": event,
                    "data": data,
                }
            )
            for i, (event, data) in enumerate(events)
        )
        return dict(
            snapshot={
                **snapshot(10, 100),
                "payload": {**snapshot(10, 100)["payload"], "snapshot_id": f"known{n}"},
            },
            after=snapshot(10 + len(ops), 200),
            gateway=gateway,
            redis_operations=ops,
            raw_gateway_prefix=raw,
            gateway_boot="boot",
            gateway_request_id=req,
            request_start_ns=111,
            request_end_ns=150,
            collector_boot_id="operator-boot",
            diagnostic_receipts=[],
            gateway_reservations=[rid],
            expected_n=n,
            expected_snapshot_id=f"known{n}",
            gateway_redis_bounds=[110, 150],
        )

    @staticmethod
    def add_two_refreshes_per_gateway(case, expected_n):
        original = case["redis_operations"]
        config = case["snapshot"]["payload"]["config_sha256"]
        refreshes = []
        last_store = {}
        for index, gateway in enumerate(("gateway0", "gateway1", "gateway0", "gateway1")):
            order = 11 + index
            at = 110 + index * 2
            last_store[gateway] = at
            refreshes.append(
                {
                    "source_kind": "redis",
                    "source_identity": "redis",
                    "error": None,
                    "payload": {
                        "event": "report_store",
                        "gateway_uid": gateway,
                        "n": expected_n,
                        "effective_n": expected_n,
                        "unknown": False,
                        "report_known": True,
                        "report_complete": True,
                        "report_success": True,
                        "config_sha256": config,
                        "expires_ms": at + 8000,
                        "store_order": order,
                        "redis_time_ms": at,
                    },
                }
            )
        for index, operation in enumerate(original, start=len(refreshes) + 11):
            operation["payload"]["store_order"] = index
        case["redis_operations"] = refreshes + original
        case["after"]["payload"]["store_order"] = 10 + len(case["redis_operations"])
        for gateway, stored_ms in last_store.items():
            case["after"]["payload"]["reports"][gateway].update(
                stored_ms=stored_ms, expires_ms=stored_ms + 8000
            )
        return case

    def test_known_controls_join_individual_request_and_release(self):
        for n in (0, 1, 2):
            with self.subTest(n=n):
                result = known_gateway_control(**self.fixture(n))
                self.assertEqual((result["effective_n"], result["effective_b"]), (n, n * 5))

    def test_known1_allows_two_fresh_same_n_report_refreshes_per_gateway(self):
        case = self.add_two_refreshes_per_gateway(self.fixture(1), 1)
        case["gateway_redis_bounds"] = [90, 150]
        self.assertEqual(known_gateway_control(**case)["effective_n"], 1)
        for field, value in (
            ("n", 2),
            ("unknown", True),
            ("report_known", False),
            ("report_complete", False),
            ("report_success", False),
            ("config_sha256", "b" * 64),
            ("expires_ms", 9000),
        ):
            bad = copy.deepcopy(case)
            bad["redis_operations"][0]["payload"][field] = value
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(IntegrityError, "fitness:known_control_gap"),
            ):
                known_gateway_control(**bad)

    def test_known_control_checks_after_snapshot_report_freshness(self):
        for field, value in (("stored_ms", 99), ("expires_ms", 8099), ("expires_ms", 200)):
            case = self.fixture(1)
            case["after"]["payload"]["reports"]["gateway0"][field] = value
            with (
                self.subTest(field=field, value=value),
                self.assertRaisesRegex(IntegrityError, "fitness:known_control_reports"),
            ):
                known_gateway_control(**case)

    def test_known_control_uses_same_clock_request_brackets(self):
        case = self.fixture(1)
        # The local request starts 1 ms after the reply, while the mapped
        # interval starts 7 ms before the Redis TIME snapshot.
        case["gateway_redis_bounds"] = [104, 150]
        self.assertEqual(known_gateway_control(**case)["effective_n"], 1)
        before_snapshot = copy.deepcopy(case)
        before_snapshot["request_start_ns"] = 109
        with self.assertRaisesRegex(IntegrityError, "fitness:known_control_interval"):
            known_gateway_control(**before_snapshot)

    def test_known_control_interval_can_contain_the_other_gateway_and_diagnostic(self):
        case = self.fixture(2)
        gateway1 = "rsv_" + "2" * 32
        diagnostic = "rsv_d1a6" + "c" * 28
        extra = copy.deepcopy(case["redis_operations"])
        for row in extra:
            payload = row["payload"]
            payload["reservation_id"] = gateway1
            payload["store_order"] += 2
            payload["redis_time_ms"] += 20
        diagnostic_ops = copy.deepcopy(case["redis_operations"])
        for index, row in enumerate(diagnostic_ops, start=15):
            row["payload"].update(
                reservation_id=diagnostic,
                store_order=index,
                redis_time_ms=160 + index,
                decision="allowed" if row["payload"]["event"] == "admit" else "released",
            )
        case["redis_operations"].extend(extra + diagnostic_ops)
        case["gateway_reservations"] = [case["gateway"]["payload"]["reservation_id"], gateway1]
        case["diagnostic_receipts"] = [{"reservation_id": diagnostic}]
        case["after"]["payload"]["store_order"] = 16
        case["gateway_redis_bounds"] = [110, 190]
        result = known_gateway_control(**case)
        self.assertEqual(result["decision"], "allowed")

    def test_known_control_interval_rejects_an_unowned_reservation(self):
        case = self.fixture(2)
        case["redis_operations"][0]["payload"]["reservation_id"] = "rsv_" + "9" * 32
        case["gateway_reservations"] = [case["gateway"]["payload"]["reservation_id"]]
        with self.assertRaisesRegex(IntegrityError, "fitness:unexplained_reservations"):
            known_gateway_control(**case)

    def test_refuses_gap_changed_report_wrong_count_unexplained_and_missing_release(self):
        for mutation, reason in (
            ("gap", "known_control_interval"),
            ("report", "known_control_interval"),
            ("count", "known_control_decision"),
            ("unexplained", "unexplained_reservations"),
            ("release", "known_terminal"),
            ("time", "known_control_decision"),
        ):
            case = self.fixture(2)
            if mutation == "gap":
                case["redis_operations"].pop()
            elif mutation == "report":
                case["after"]["payload"]["reports"]["gateway0"]["unknown"] = True
            elif mutation == "count":
                case["redis_operations"][0]["payload"]["effective_n"] = 1
            elif mutation == "unexplained":
                case["redis_operations"][1]["payload"]["reservation_id"] = "rsv_" + "3" * 32
            elif mutation == "release":
                case["redis_operations"][1]["payload"]["idempotent"] = True
            else:
                case["gateway_redis_bounds"] = [130, 150]
            with self.subTest(mutation=mutation), self.assertRaisesRegex(IntegrityError, reason):
                known_gateway_control(**case)

    def test_known_control_rejects_invalid_state_sequence_and_absent_ack(self):
        for mutation, reason in (
            ("invalid_n", "known_control_n"),
            ("state", "known_control_reports"),
            ("sequence", "known_control_gap"),
            ("missing_admit", "control_admit_join"),
            ("missing_terminal", "known_terminal"),
            ("gateway_boot", "control_gateway_ack"),
            ("ttl", "known_control_reports"),
        ):
            case = self.fixture(2)
            if mutation == "invalid_n":
                case["expected_n"] = True
            elif mutation == "state":
                case["snapshot"]["payload"]["state"]["n"] = 1
                case["after"]["payload"]["state"]["n"] = 1
            elif mutation == "sequence":
                case["redis_operations"][0]["payload"]["store_order"] += 1
            elif mutation == "missing_admit":
                case["redis_operations"][0]["payload"]["event"] = "release"
            elif mutation == "missing_terminal":
                case["raw_gateway_prefix"] = (
                    b"\n".join(case["raw_gateway_prefix"].splitlines()[:-1]) + b"\n"
                )
            elif mutation == "gateway_boot":
                case["gateway"]["source_generation"] = "other"
            else:
                for snap in (case["snapshot"], case["after"]):
                    snap["payload"]["reports"]["gateway0"]["stored_ms"] -= 1
            with self.subTest(mutation=mutation), self.assertRaisesRegex(IntegrityError, reason):
                known_gateway_control(**case)

    def test_known_control_distinguishes_repeated_snapshot_instances(self):
        case = self.fixture(2)
        case["expected_snapshot_id"] = "cached_restore_known2"
        with self.assertRaisesRegex(IntegrityError, "fitness:known_control_interval"):
            known_gateway_control(**case)
        case["snapshot"]["payload"]["snapshot_id"] = "cached_restore_known2"
        self.assertEqual(known_gateway_control(**case)["effective_n"], 2)
        case["expected_snapshot_id"] = "known1"
        with self.assertRaisesRegex(IntegrityError, "fitness:known_control_snapshot"):
            known_gateway_control(**case)


class DiagnosticSnapshotControlTests(unittest.TestCase):
    def fixture(self, name):
        n = {"known0": 0, "known1": 1, "known2": 2, "unknown": 2, "expired": 2}[name]
        case = KnownGatewayControlTests().fixture(n)
        rid = "rsv_d1a6" + "a" * 28
        expected = (
            "capacity_reports_expired"
            if name == "expired"
            else ("system_capacity" if n == 0 else "allowed")
        )
        case["snapshot"]["payload"]["snapshot_id"] = name
        for snap in (case["snapshot"], case["after"]):
            for report in snap["payload"]["reports"].values():
                report["unknown"] = name in ("unknown", "expired")
                if name == "expired":
                    report.update(expires_ms=10000, stored_ms=2000)
        if name == "expired":
            case["redis_operations"] = case["redis_operations"][:1]
            case["after"]["payload"]["store_order"] = 11
            case["snapshot"]["payload"]["redis_time_ms"] = 10000
            case["after"]["payload"]["redis_time_ms"] = 10100
            case["redis_operations"][0]["payload"]["redis_time_ms"] = 10020
        for operation in case["redis_operations"]:
            operation["payload"]["reservation_id"] = rid
        case["redis_operations"][0]["payload"]["decision"] = expected
        return {
            "snapshot": case["snapshot"],
            "after": case["after"],
            "redis_operations": case["redis_operations"],
            "receipt": {
                "reservation_id": rid,
                "decision": expected,
                "capacity": n * 5,
                "released": expected == "allowed",
            },
            "gateway_ids": ["rsv_" + "1" * 32],
            "diagnostic_redis_bounds": [10010, 10050] if name == "expired" else [110, 150],
            "process_start_ns": 111,
            "process_end_ns": 150,
            "collector_boot_id": "operator-boot",
            "control_name": name,
        }

    def test_five_diagnostic_results_preserve_real_unknown_semantics(self):
        for name in ("known0", "known1", "known2", "unknown", "expired"):
            with self.subTest(name=name):
                result = diagnostic_snapshot_control(**self.fixture(name))
                expected = (
                    "capacity_reports_expired"
                    if name == "expired"
                    else ("system_capacity" if name == "known0" else "allowed")
                )
                self.assertEqual(result["decision"], expected)

    def test_diagnostic_known1_allows_two_fresh_same_n_refreshes_per_gateway(self):
        case = KnownGatewayControlTests.add_two_refreshes_per_gateway(self.fixture("known1"), 1)
        case["diagnostic_redis_bounds"] = [90, 150]
        self.assertEqual(diagnostic_snapshot_control(**case)["effective_n"], 1)
        for field, value in (
            ("n", 2),
            ("unknown", True),
            ("report_known", False),
            ("report_complete", False),
            ("report_success", False),
            ("config_sha256", "b" * 64),
            ("expires_ms", 9000),
        ):
            bad = copy.deepcopy(case)
            bad["redis_operations"][0]["payload"][field] = value
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(IntegrityError, "fitness:diagnostic_gap"),
            ):
                diagnostic_snapshot_control(**bad)

    def test_diagnostic_checks_after_snapshot_report_freshness(self):
        for field, value in (("stored_ms", 99), ("expires_ms", 8099), ("expires_ms", 200)):
            case = self.fixture("known1")
            case["after"]["payload"]["reports"]["gateway0"][field] = value
            with (
                self.subTest(field=field, value=value),
                self.assertRaisesRegex(IntegrityError, "fitness:diagnostic_snapshot"),
            ):
                diagnostic_snapshot_control(**case)

    @staticmethod
    def add_unknown_marker(case, at):
        operations = case["redis_operations"]
        config = case["snapshot"]["payload"]["config_sha256"]
        first_order = case["snapshot"]["payload"]["store_order"] + 1
        marker = {
            "source_kind": "redis",
            "source_identity": "redis",
            "error": None,
            "payload": {
                "event": "unknown",
                "gateway_uid": "gateway0",
                "unknown": True,
                "report_known": False,
                "config_sha256": config,
                "store_order": first_order,
                "redis_time_ms": at,
            },
        }
        for order, operation in enumerate(operations, start=first_order + 1):
            operation["payload"]["store_order"] = order
        case["redis_operations"] = [marker, *operations]
        case["after"]["payload"]["store_order"] = case["snapshot"]["payload"]["store_order"] + len(
            case["redis_operations"]
        )
        return case

    def test_unknown_markers_are_limited_to_unknown_and_expired_intervals(self):
        unknown = self.add_unknown_marker(self.fixture("unknown"), 110)
        self.assertEqual(diagnostic_snapshot_control(**unknown)["decision"], "allowed")
        expired = self.add_unknown_marker(self.fixture("expired"), 10010)
        self.assertEqual(
            diagnostic_snapshot_control(**expired)["decision"], "capacity_reports_expired"
        )
        known = self.add_unknown_marker(self.fixture("known2"), 110)
        with self.assertRaisesRegex(IntegrityError, "fitness:diagnostic_gap"):
            diagnostic_snapshot_control(**known)
        for field, value in (
            ("gateway_uid", "gateway2"),
            ("unknown", False),
            ("report_known", True),
            ("config_sha256", "b" * 64),
        ):
            bad = copy.deepcopy(unknown)
            bad["redis_operations"][0]["payload"][field] = value
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(IntegrityError, "fitness:diagnostic_gap"),
            ):
                diagnostic_snapshot_control(**bad)

    def test_diagnostic_interval_uses_same_clock_process_brackets(self):
        case = self.fixture("known1")
        case["diagnostic_redis_bounds"] = [90, 150]
        self.assertEqual(diagnostic_snapshot_control(**case)["effective_n"], 1)
        before_snapshot = copy.deepcopy(case)
        before_snapshot["process_start_ns"] = 109
        with self.assertRaisesRegex(IntegrityError, "fitness:diagnostic_interval"):
            diagnostic_snapshot_control(**before_snapshot)

    def test_diagnostic_join_uses_reservation_id_when_gateway_uid_is_empty(self):
        case = self.fixture("known2")
        gateway_id = "rsv_" + "7" * 32
        gateway_ops = copy.deepcopy(case["redis_operations"])
        for index, row in enumerate(gateway_ops, start=11):
            row["payload"]["reservation_id"] = gateway_id
            row["payload"]["store_order"] = index
            row["payload"].pop("gateway_uid", None)
        diagnostic_ops = copy.deepcopy(case["redis_operations"])
        for index, row in enumerate(diagnostic_ops, start=13):
            row["payload"].update(store_order=index, redis_time_ms=120 + (index - 11) * 10)
        case["redis_operations"] = gateway_ops + diagnostic_ops
        case["gateway_ids"] = [gateway_id]
        case["after"]["payload"]["store_order"] = 14
        result = diagnostic_snapshot_control(**case)
        self.assertEqual(result["reservation_id"], case["receipt"]["reservation_id"])

    def test_snapshot_identity_and_interval_are_required(self):
        case = self.fixture("known2")
        case["snapshot"]["payload"]["snapshot_id"] = "post_outage_known2"
        with self.assertRaisesRegex(IntegrityError, "fitness:diagnostic_interval"):
            diagnostic_snapshot_control(**case)
        case = self.fixture("known2")
        case["after"]["payload"]["occupied"] = 1
        with self.assertRaisesRegex(IntegrityError, "fitness:diagnostic_interval"):
            diagnostic_snapshot_control(**case)

    def test_refuses_mismatched_result_snapshot_gap_overlap_and_release(self):
        for mutation, reason in (
            ("decision", "diagnostic_decision"),
            ("snapshot", "diagnostic_snapshot"),
            ("gap", "diagnostic_gap"),
            ("missing_diagnostic_reservation", "diagnostic_decision"),
            ("overlap", "diagnostic_id_in_gateway"),
            ("release", "diagnostic_release"),
            ("name", "diagnostic_control_name"),
            ("ttl", "diagnostic_snapshot"),
        ):
            case = self.fixture("unknown")
            if mutation == "decision":
                case["receipt"]["decision"] = "capacity_reports_expired"
            elif mutation == "snapshot":
                for snap in (case["snapshot"], case["after"]):
                    snap["payload"]["reports"]["gateway0"]["unknown"] = False
            elif mutation == "gap":
                case["redis_operations"][0]["payload"]["store_order"] += 1
            elif mutation == "missing_diagnostic_reservation":
                for operation in case["redis_operations"]:
                    operation["payload"]["reservation_id"] = case["gateway_ids"][0]
            elif mutation == "overlap":
                case["gateway_ids"].append(case["receipt"]["reservation_id"])
            elif mutation == "release":
                case["redis_operations"][1]["payload"]["idempotent"] = True
            elif mutation == "name":
                case["control_name"] = "invented"
            else:
                for snap in (case["snapshot"], case["after"]):
                    snap["payload"]["reports"]["gateway0"]["stored_ms"] -= 1
            with self.subTest(mutation=mutation), self.assertRaisesRegex(IntegrityError, reason):
                diagnostic_snapshot_control(**case)


class RealGatewayRefusalTests(unittest.TestCase):
    def test_real_gateway_403_produces_provable_local_refusal(self):
        import base64
        import hashlib
        import json
        import os
        import socket
        import ssl
        import subprocess
        import tempfile
        import threading
        import time
        import urllib.error
        import urllib.request
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from pathlib import Path

        from inference_platform.inf037b_capture import CaptureOwner, DeadlineHTTP, wire_records
        from inference_platform.inf037b_durable_ports import DurableStore
        from inference_platform.inf037b_live import (
            ClientSSEAdapter,
            ClockAdapter,
            LiveRows,
            RedisAdapter,
        )
        from inference_platform.inf037b_sources import ClockMapper

        binary, address = os.environ.get("M5_PACKAGE_A_BIN"), os.environ.get("REDIS_TEST_ADDR")
        if not binary or not address:
            self.skipTest("requires isolated real Redis and Linux gateway")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cert, key = root / "ca.crt", root / "key.pem"
            subprocess.run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-keyout",
                    str(key),
                    "-out",
                    str(cert),
                    "-days",
                    "1",
                    "-subj",
                    "/CN=localhost",
                    "-addext",
                    "subjectAltName=IP:127.0.0.1",
                ],
                check=True,
                capture_output=True,
            )
            account = Path("/var/run/secrets/kubernetes.io/serviceaccount")
            account.mkdir(parents=True, exist_ok=True)
            (account / "ca.crt").write_bytes(cert.read_bytes())
            (account / "token").write_text("fixture")

            class API(BaseHTTPRequestHandler):
                def log_message(self, *args):
                    pass

                def do_GET(self):
                    self.send_response(403)
                    self.send_header("Content-Length", "0")
                    self.end_headers()

            server = ThreadingHTTPServer(("127.0.0.1", 0), API)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
            credential = "row5-test-credential"
            tenants = json.loads(
                (Path(__file__).resolve().parents[2] / "deploy/local/tenants.json").read_bytes()
            )
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
            capture = root / "gateway.jsonl"
            namespace = "row5-prefix-" + root.name.replace("_", "-")
            env = {
                **os.environ,
                "GATEWAY_HTTP_ADDR": f"127.0.0.1:{port}",
                "TENANT_CONFIG_PATH": str(root / "tenants.json"),
                "CACHE_SALT_SECRET_FILE": str(root / "salt"),
                "REDIS_ADDR": address,
                "ADMISSION_NAMESPACE": namespace,
                "POD_UID": "gateway-boot",
                "GATEWAY_MEASUREMENT_PATH": str(capture),
                "ADMISSION_CAPACITY_MODE": "dynamic",
                "ADMISSION_GATEWAY_ID": "gateway-0",
                "ADMISSION_RUNNING": "4",
                "ADMISSION_WAITING": "1",
                "ADMISSION_REPORT_TTL": "8s",
                "ADMISSION_HOLD_DOWN": "2s",
                "BACKEND_DISCOVERY": "endpointslices",
                "BACKEND_DISCOVERY_NAMESPACE": "test",
                "BACKEND_DISCOVERY_SERVICE": "fake",
                "BACKEND_DISCOVERY_INTERVAL": "5s",
                "KUBERNETES_SERVICE_HOST": "127.0.0.1",
                "KUBERNETES_SERVICE_PORT_HTTPS": str(server.server_port),
                "OTEL_SDK_DISABLED": "true",
            }
            log = (root / "gateway.log").open("wb")
            process = subprocess.Popen([binary], env=env, stdout=log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 15
                while True:
                    if process.poll() is not None or time.monotonic() >= deadline:
                        self.fail((root / "gateway.log").read_text())
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                            break
                    except OSError:
                        time.sleep(0.02)
                host, redis_port = address.rsplit(":", 1)
                from redis_capture_test_support import AdminRedisWire

                wire = AdminRedisWire(host, int(redis_port), tls=False, local_test=True)
                self.addCleanup(wire.close)
                adapter = RedisAdapter(
                    LiveRows("row5-integration", "collector"), wire, namespace, "a" * 64
                )
                before = adapter.snapshot()
                self.assertIsNone(before["error"])
                payload = json.dumps(
                    {
                        "model": "test-model",
                        "messages": [{"role": "user", "content": "test"}],
                        "stream": True,
                        "max_tokens": 1,
                    }
                ).encode()
                request = urllib.request.Request(
                    f"http://127.0.0.1:{port}/v1/chat/completions",
                    data=payload,
                    headers={
                        "Authorization": "Bearer " + credential,
                        "Content-Type": "application/json",
                    },
                )
                try:
                    urllib.request.urlopen(request, timeout=5)
                    self.fail("gateway did not refuse discovery")
                except urllib.error.HTTPError as error:
                    self.assertEqual(error.code, 503)
                    gateway_request = error.headers["X-Request-ID"]
                    self.assertEqual(json.loads(error.read())["error"]["code"], "discovery_unknown")
                deadline = time.monotonic() + 5
                while True:
                    raw = capture.read_bytes()
                    complete = raw[: raw.rfind(b"\n") + 1]
                    if any(
                        json.loads(line).get("event") == "terminal"
                        and json.loads(line).get("data", {}).get("request_id") == gateway_request
                        for line in complete.splitlines()
                    ):
                        break
                    if time.monotonic() >= deadline:
                        self.fail("gateway terminal was not captured")
                    time.sleep(0.02)
                proof = local_refusal_prefix(
                    complete,
                    expected_sha256=sha(complete),
                    gateway_boot="gateway-boot",
                    gateway_request_id=gateway_request,
                    diagnostic_receipts=[],
                )
                collector_boot = root / "collector-boot"
                collector_boot.write_text("collector-boot")
                binding = {"session_id": "row5-test", "pins": {"source": "a" * 64}}
                sources = {
                    "gateway-wire": [["gateway", "gateway0", "gateway-boot"]],
                    "client-wire": [["client", "client:gateway0", "client-boot"]],
                }
                operation = {
                    "operation": "capture",
                    "key": "row5-test",
                    "sequence": 1,
                    "body": {
                        "binding": binding,
                        "capture": {
                            "sources": sources,
                            "attempt": "setup",
                            "stages": [1, 2, 3, 4, 5],
                            "boot_id": "collector-boot",
                        },
                    },
                }
                operations_store = DurableStore(
                    root / "operations",
                    {"operations": {sha(encode(["capture", "row5-test"])): operation}},
                    initialize=True,
                )
                capture_store = DurableStore(root / "capture-store", {}, initialize=True)
                owner = CaptureOwner(
                    store=capture_store,
                    operation_store=operations_store,
                    operation=operation,
                    binding=binding,
                    root=root / "retained",
                    sources=sources,
                    attempt="setup",
                    stages=[1, 2, 3, 4, 5],
                    boot_path=collector_boot,
                )
                http = DeadlineHTTP(
                    f"http://127.0.0.1:{port}",
                    stop_ns=time.monotonic_ns() + 5_000_000_000,
                    retain=owner.retainer("gateway-wire"),
                    local_test=True,
                )
                fetched, _ = http.get("/internal/measurement?offset=0")
                client = ClientSSEAdapter(
                    LiveRows("row5-test", "client-boot"),
                    "gateway0",
                    "a" * 64,
                    retain=owner.retainer("client-wire"),
                )
                offer = {
                    "request_id": "control",
                    "offer_index": 0,
                    "prefix_id": "prefix",
                    "scheduled_ms": time.monotonic_ns() // 1_000_000,
                }
                clock_adapter = ClockAdapter(LiveRows("row5-clock", "collector-boot"))
                mapping_before = clock_adapter.redis(wire)
                time.sleep(0.01)
                result = client.request(
                    f"http://127.0.0.1:{port}/v1/chat/completions",
                    json.loads(payload),
                    offer,
                    credential=credential,
                    local_test=True,
                    deadline_ns=time.monotonic_ns() + 5_000_000_000,
                )
                self.assertEqual(result[-2]["payload"]["denial_code"], "discovery_unknown")
                time.sleep(0.01)
                mapping_after = clock_adapter.redis(wire)
                new_gateway_id = next(iter(client.request_ids))
                deadline = time.monotonic() + 2
                while not any(
                    json.loads(line).get("event") == "terminal"
                    and json.loads(line).get("data", {}).get("request_id") == new_gateway_id
                    for line in capture.read_bytes().splitlines()
                ):
                    if time.monotonic() >= deadline:
                        self.fail("second gateway terminal was not captured")
                    time.sleep(0.01)
                tail, _ = http.get(f"/internal/measurement?offset={len(fetched)}")
                fetched += tail
                descriptor = owner.close()
                self.assertTrue(descriptor["transport_clean"])
                client_records = [
                    (r, b)
                    for r, b in wire_records(owner.root / "wire")
                    if r["source"] == "client-wire"
                ]
                starts = {r["start_ns"] for r, _ in client_records}
                self.assertEqual(len(starts), 1)
                gateway_id = new_gateway_id
                request_start_ns = starts.pop()
                client_proof = client_refusal_from_capture(
                    owner.root,
                    descriptor,
                    expected_binding=binding,
                    expected_operation=operation,
                    expected_descriptor_sha256=sha(encode(descriptor)),
                    source="client-wire",
                    client_identity="client:gateway0",
                    client_boot="client-boot",
                    gateway_request_id=gateway_id,
                    request_start_ns=request_start_ns,
                )
                request_end_ns = client_proof["end_ns"]
                self.assertEqual(client_proof["client_code"], "discovery_unknown")
                retained = gateway_prefix_from_capture(
                    owner.root,
                    descriptor,
                    expected_binding=binding,
                    expected_operation=operation,
                    expected_descriptor_sha256=sha(encode(descriptor)),
                    source="gateway-wire",
                    gateway_uid="gateway0",
                    gateway_boot="gateway-boot",
                )
                self.assertEqual(retained, fetched)
                after_control = adapter.snapshot()
                ops_control = [
                    row
                    for row in adapter.operations()
                    if before["payload"]["store_order"]
                    < row["payload"].get("store_order", -1)
                    <= after_control["payload"]["store_order"]
                ]
                common = {
                    "root": owner.root,
                    "descriptor": descriptor,
                    "expected_binding": binding,
                    "expected_operation": operation,
                    "expected_descriptor_sha256": sha(encode(descriptor)),
                }
                combined_source = captured_refusal_control(
                    gateway_capture={
                        **common,
                        "source": "gateway-wire",
                        "gateway_uid": "gateway0",
                        "gateway_boot": "gateway-boot",
                    },
                    client_capture={
                        **common,
                        "source": "client-wire",
                        "client_identity": "client:gateway0",
                        "client_boot": "client-boot",
                    },
                    gateway_request_id=gateway_id,
                    request_start_ns=request_start_ns,
                    request_end_ns=request_end_ns,
                    collector_boot_id=before["collector_boot_id"],
                    clocks=ClockMapper([mapping_before, mapping_after]),
                    redis_boot="redis",
                    redis_before=before,
                    redis_after=after_control,
                    redis_operations=ops_control,
                    diagnostic_receipts=[],
                )
                self.assertEqual(combined_source["client"]["client_code"], "discovery_unknown")
                wrong_boot = copy.deepcopy(after_control)
                wrong_boot["source_generation"] = "redis-restarted"
                with self.assertRaisesRegex(IntegrityError, "fitness:refusal_capture_binding"):
                    captured_refusal_control(
                        gateway_capture={
                            **common,
                            "source": "gateway-wire",
                            "gateway_uid": "gateway0",
                            "gateway_boot": "gateway-boot",
                        },
                        client_capture={
                            **common,
                            "source": "client-wire",
                            "client_identity": "client:gateway0",
                            "client_boot": "client-boot",
                        },
                        gateway_request_id=gateway_id,
                        request_start_ns=request_start_ns,
                        request_end_ns=request_end_ns,
                        collector_boot_id=before["collector_boot_id"],
                        clocks=ClockMapper([mapping_before, mapping_after]),
                        redis_boot="redis",
                        redis_before=before,
                        redis_after=wrong_boot,
                        redis_operations=ops_control,
                        diagnostic_receipts=[],
                    )
                with self.assertRaisesRegex(IntegrityError, "fitness:refusal_clock"):
                    captured_refusal_control(
                        gateway_capture={
                            **common,
                            "source": "gateway-wire",
                            "gateway_uid": "gateway0",
                            "gateway_boot": "gateway-boot",
                        },
                        client_capture={
                            **common,
                            "source": "client-wire",
                            "client_identity": "client:gateway0",
                            "client_boot": "client-boot",
                        },
                        gateway_request_id=gateway_id,
                        request_start_ns=request_start_ns,
                        request_end_ns=request_end_ns,
                        collector_boot_id=before["collector_boot_id"],
                        clocks=ClockMapper([]),
                        redis_boot="redis",
                        redis_before=before,
                        redis_after=after_control,
                        redis_operations=ops_control,
                        diagnostic_receipts=[],
                    )
                config_args = {
                    "expected_binding": binding,
                    "expected_operation": operation,
                    "expected_descriptor_sha256": sha(encode(descriptor)),
                    "source": "gateway-wire",
                    "gateway_uid": "gateway0",
                    "gateway_boot": "gateway-boot",
                }
                config = gateway_resolved_config_from_capture(owner.root, descriptor, **config_args)
                self.assertEqual(
                    config,
                    {
                        "redis_addr": address,
                        "namespace": namespace,
                        "global_capacity": 64,
                        "lease_ms": 180000,
                        "tombstone_ms": 300000,
                        "running": 4,
                        "waiting": 1,
                        "ttl_ms": 8000,
                        "hold_ms": 2000,
                        "capture": True,
                    },
                )
                with self.assertRaisesRegex(IntegrityError, "fitness:gateway_capture_descriptor"):
                    gateway_resolved_config_from_capture(
                        owner.root, descriptor, **dict(config_args, gateway_uid="gateway1")
                    )
                with self.assertRaisesRegex(IntegrityError, "fitness:gateway_capture_descriptor"):
                    gateway_prefix_from_capture(
                        owner.root,
                        descriptor,
                        expected_binding=binding,
                        expected_operation=operation,
                        expected_descriptor_sha256="0" * 64,
                        source="gateway-wire",
                        gateway_uid="gateway0",
                        gateway_boot="gateway-boot",
                    )
                with self.assertRaisesRegex(IntegrityError, "fitness:gateway_capture_descriptor"):
                    gateway_prefix_from_capture(
                        owner.root,
                        descriptor,
                        expected_binding={"wrong": True},
                        expected_operation=operation,
                        expected_descriptor_sha256=sha(encode(descriptor)),
                        source="gateway-wire",
                        gateway_uid="gateway0",
                        gateway_boot="gateway-boot",
                    )
                wire_file = next((owner.root / "wire").glob("*.bin"))
                wire_file.write_bytes(wire_file.read_bytes() + b"tampered")
                with self.assertRaisesRegex(IntegrityError, "probe:capture_inventory"):
                    gateway_prefix_from_capture(
                        owner.root,
                        descriptor,
                        expected_binding=binding,
                        expected_operation=operation,
                        expected_descriptor_sha256=sha(encode(descriptor)),
                        source="gateway-wire",
                        gateway_uid="gateway0",
                        gateway_boot="gateway-boot",
                    )
                complete = retained
                process.terminate()
                process.wait(timeout=10)
                try:
                    after = adapter.snapshot()
                    self.assertIsNone(after["error"])
                    operations = ops_control + [
                        row
                        for row in adapter.operations()
                        if before["payload"]["store_order"]
                        < row["payload"].get("store_order", -1)
                        <= after["payload"]["store_order"]
                    ]
                    combined = refusal_control(
                        complete,
                        expected_sha256=sha(complete),
                        gateway_boot="gateway-boot",
                        gateway_request_id=gateway_request,
                        client_status=503,
                        client_code="discovery_unknown",
                        redis_before=before,
                        redis_after=after,
                        redis_operations=operations,
                        diagnostic_receipts=[],
                        request_start_ns=before["capture_end_mono_ns"],
                        request_end_ns=after["capture_start_mono_ns"],
                        collector_boot_id=before["collector_boot_id"],
                    )
                    self.assertEqual(combined["gateway"]["reservation_id"], proof["reservation_id"])
                    rows = wire.command(
                        "XRANGE", namespace + ":{admission}:global:active:capture", "-", "+"
                    )
                    records = [
                        dict(zip(fields[::2], fields[1::2], strict=True)) for _, fields in rows
                    ]
                    self.assertTrue(records)
                    self.assertEqual(
                        int(
                            wire.command(
                                "GET", namespace + ":{admission}:global:active:capture:sequence"
                            )
                        ),
                        len(records),
                    )
                    self.assertFalse(
                        any(
                            row.get("event") == "admit"
                            and row.get("reservation_id") == proof["reservation_id"]
                            for row in records
                        )
                    )
                    self.assertEqual(
                        [int(row["capture_seq"]) for row in records],
                        list(range(1, len(records) + 1)),
                    )
                finally:
                    wire.close()
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=10)
                log.close()


if __name__ == "__main__":
    unittest.main()
