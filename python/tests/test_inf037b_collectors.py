"""Offline v3 adverse fixtures: every capture includes report and archived state.

INF037B_SLICE4B_OUTPUT writes inspectable actual decisions, never measurements.
"""

import copy
import json
import os
import random
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from inference_platform.inf037b_archive import (
    Archive,
    IntegrityError,
    archive_receipts,
    encode,
    envelope,
    inspect_segment,
    sha,
    verify_archive,
)
from inference_platform.inf037b_attempts import AttemptController, Refused
from inference_platform.inf037b_campaign import (
    OfflineCampaign,
    materialize_bundle,
    reproduce,
    sanitized_campaign,
    sanitized_report_facts,
)
from inference_platform.inf037b_contract import (
    REGISTRATION_GIT_BLOB_SHA256,
    REGISTRATION_ID,
    REGISTRATION_PATH,
)
from inference_platform.inf037b_packet import (
    REQUIRED_PINS,
    PacketReadiness,
    Sanitizer,
    sanitized_sources,
    sizing,
    source_manifest,
    verify_sources,
    workload_trace,
)
from inference_platform.inf037b_recovery import RecoveryJoin, percentiles
from inference_platform.inf037b_requests import RequestJoin, SSEDecoder
from inference_platform.inf037b_sources import FIELDS, ClockMapper, SourceJoin
from inference_platform.inf037b_stages import StageJoin
from inference_platform.inf037b_stream import StreamingArchiveWriter

OUTPUTS = {}
HASH = "a" * 64
# Verbatim client responses captured by TestGatewaySlice4bClientFixtures.
GATEWAY_STREAMS = json.loads(
    (Path(__file__).parent / "fixtures/inf037b_gateway_sse.json").read_bytes()
)
_FRAMES = [frame + b"\n\n" for frame in GATEWAY_STREAMS["complete"].encode().split(b"\n\n")[:-1]]
CONTENT = b"".join(_FRAMES[:2])  # assistant role then content
FINISH, USAGE, DONE = _FRAMES[2:]


def tearDownModule():
    if output := os.environ.get("INF037B_SLICE4B_OUTPUT"):
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(OUTPUTS, indent=2, sort_keys=True, allow_nan=False) + "\n",
            encoding="utf-8",
            newline="\n",
        )


class Records:
    def __init__(self):
        self.seq = {}

    def row(self, kind, event, time=0, *, identity=None, generation="boot0", **fields):
        identity = identity or kind + "-fixture"
        key = (kind, identity, generation)
        seq = self.seq.get(key, 0)
        self.seq[key] = seq + 1
        p = {name: None for name in FIELDS[kind].split()}
        p.update(event=event, **fields)
        if kind == "client" and event == "offer" and "dispatch_ms" not in fields:
            p["dispatch_ms"] = time
        if kind == "kubernetes" and event == "signal" and "signal_receipt_time" not in fields:
            p["signal_receipt_time"] = time
        p["field_reasons"] = {
            name: "not_applicable_to_event" for name, value in p.items() if value is None
        }
        row = envelope(p, seq=seq, attempt=1)
        row.update(
            source_kind=kind,
            source_identity=identity,
            source_generation=generation,
            record_id=f"{identity}-{generation}-{seq}",
            observed_mono_ns=time * 1_000_000,
            capture_start_mono_ns=time * 1_000_000,
            capture_end_mono_ns=time * 1_000_000,
            source_time={"clock_id": "measurement", "unit": "ms", "value": time},
            missing_reason=None,
        )
        return row

    def request(
        self,
        request="r0",
        gateway="gateway0",
        *,
        offered=0,
        opened=10,
        first=20,
        terminal=100,
        data=CONTENT + FINISH + USAGE + DONE,
        outcome="terminal",
        uid="old0",
        slot=0,
        phase="pre",
    ):
        fields = {
            "request_id": request,
            "gateway_uid": gateway,
            "offer_index": int(request.lstrip("r") or 0) if request.lstrip("r").isdigit() else 0,
            "prefix_id": "prefix0",
            "config_sha256": HASH,
            "policy": "round-robin",
            "retry_count": 0,
        }
        rows = [
            self.row("client", "offer", offered, **fields, lateness_ms=0),
            self.row(
                "client",
                "receive",
                opened,
                **fields,
                http_status=200,
                backend_uid=uid,
                backend_slot=slot,
            ),
            self.row(
                "gateway",
                "admit",
                opened,
                request_id=request,
                gateway_uid=gateway,
                effective_n=2,
                effective_b=10,
                admit_called=True,
                decision="allowed",
            ),
            self.row(
                "gateway",
                "select",
                opened,
                request_id=request,
                gateway_uid=gateway,
                backend_uid=uid,
                backend_slot=slot,
            ),
            self.row(
                "gateway",
                "revalidate",
                opened,
                request_id=request,
                gateway_uid=gateway,
                backend_uid=uid,
                backend_slot=slot,
            ),
            self.row(
                "gateway",
                "upstream_open",
                opened,
                request_id=request,
                gateway_uid=gateway,
                backend_uid=uid,
                backend_slot=slot,
                reservation_id="reservation-" + request,
            ),
            self.row("client", "sse", first, **fields, chunk_hex=data.hex()),
            self.row(
                "client",
                outcome,
                terminal,
                **fields,
                http_status=200,
                backend_uid=uid,
                backend_slot=slot,
            ),
        ]
        expected = {
            "request_id": request,
            "offer_index": fields["offer_index"],
            "prefix_id": "prefix0",
            "gateway_uid": gateway,
            "phase": phase,
            "config_sha256": HASH,
            "scheduled_ms": offered,
        }
        return rows, expected


def redis_clock(records, time, offset=0):
    return records.row(
        "clocks",
        "mapping",
        time,
        clock_id="redis",
        boot_id="boot0",
        local_mono_ms=time,
        local_wall_ms=time,
        remote_ms=time + offset,
        send_ms=time,
        receive_ms=time,
    )


class FixtureCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def capture(self, name, rows, report, *, journal=None, cohorts=None):
        root = self.root / name
        archive = Archive.create(root, {"registration_id": REGISTRATION_ID})
        writer = StreamingArchiveWriter(root)
        for row in rows:
            writer.append("raw/" + row["source_kind"] + ".jsonl", row)
        for index, cohort in enumerate(cohorts or []):
            row = envelope(cohort, seq=index, attempt=1)
            row.update(source_identity="fixture-cohort", record_id=f"fixture-cohort-{index}")
            writer.append("cohorts/requests.jsonl", row)
        if journal:
            (root / "attempts.jsonl").write_bytes(journal.read_bytes())
        state = archive.seal()
        value = {"report": report, "archive_state": state}
        if journal:
            value["journal"] = [r["payload"] for r in inspect_segment(journal)[1]]
        OUTPUTS[name] = copy.deepcopy(value)
        self.assertTrue(verify_archive(root)["verified"])
        return value

    def joined(self, rows):
        # Scripted per-request/per-gateway blocks are fixture construction order.
        # Give their shared source streams coherent chronological sequences.
        # Deliberate reorder/gap fixtures call SourceJoin directly, unmodified.
        rows.sort(key=lambda row: row["observed_mono_ns"])
        sequences = {}
        for row in rows:
            key = (row["source_kind"], row["source_identity"], row["source_generation"])
            row["source_seq"] = sequences.get(key, 0)
            sequences[key] = row["source_seq"] + 1
        return SourceJoin(rows).rows


class StreamTests(FixtureCase):
    def test_incremental_receipts_reopen_duplicates_conflicts_rotation(self):
        archive = Archive.create(self.root / "stream", {"registration_id": REGISTRATION_ID})
        rows = Records()
        a = rows.row("client", "offer", request_id="private-request")
        writer = StreamingArchiveWriter(archive.root)
        with (
            patch(
                "inference_platform.inf037b_archive.Archive.append",
                side_effect=AssertionError("offline append forbidden"),
            ),
            patch(
                "inference_platform.inf037b_stream.inspect_segment",
                side_effect=AssertionError("append reparsed"),
            ),
        ):
            for _ in range(30):
                writer.append("raw/client.jsonl", a)
        self.assertEqual(writer.report()["segments"]["raw/client.jsonl"]["duplicate_count"], 29)
        writer.finalize("raw/client.jsonl")
        reopened = StreamingArchiveWriter(archive.root)
        rotated = reopened.rotate("client", 1)
        b = copy.deepcopy(a)
        b["payload"]["request_id"] = "conflicting-private-request"
        reopened.append(rotated, b)
        report = copy.deepcopy(reopened.report())
        verified = reopened.seal()
        self.assertEqual(len(verified["segments"]["raw/client.jsonl"]["integrity_errors"]), 30)
        self.assertEqual(report["segments"], verified["segments"])
        OUTPUTS["stream_incremental_reopened_conflict"] = {
            "report": report,
            "archive_state": verified,
        }
        with self.assertRaisesRegex(IntegrityError, "closed"):
            reopened.append(rotated, a)

    def test_local_duplicates_when_global_first_is_another_segment(self):
        archive = Archive.create(self.root / "duplicates", {"registration_id": REGISTRATION_ID})
        writer = StreamingArchiveWriter(archive.root)
        row = Records().row("client", "offer")
        writer.append("raw/client.jsonl", row)
        name = writer.rotate("client", 1)
        writer.append(name, row)
        writer = StreamingArchiveWriter(archive.root)
        writer.append(name, row)
        self.assertEqual(writer.receipts[name]["duplicate_count"], 1)
        OUTPUTS["stream_local_duplicate_reopen"] = {
            "report": copy.deepcopy(writer.report()),
            "archive_state": writer.seal(),
        }

    def test_torn_open_rotate_and_same_size_mutation(self):
        archive = Archive.create(self.root / "torn", {"registration_id": REGISTRATION_ID})
        row = Records().row("client", "offer")
        (archive.root / "raw/client.jsonl").write_bytes(encode(row) + b'{"private-tail":')
        writer = StreamingArchiveWriter(archive.root)
        with self.assertRaisesRegex(IntegrityError, "torn"):
            writer.append("raw/client.jsonl", row)
        name = writer.rotate("client", 1)
        writer.append(name, row)
        OUTPUTS["stream_torn_rotation"] = {
            "report": copy.deepcopy(writer.report()),
            "archive_state": writer.seal(),
        }
        archive = Archive.create(self.root / "mutation", {"registration_id": REGISTRATION_ID})
        writer = StreamingArchiveWriter(archive.root)
        writer.append("raw/client.jsonl", row)
        p = archive.root / "raw/client.jsonl"
        p.write_bytes(p.read_bytes().replace(b"client-fixture", b"client-mutated"))
        with self.assertRaisesRegex(IntegrityError, "byte_mismatch"):
            writer.seal()
        OUTPUTS["stream_same_size_mutation"] = {
            "report": writer.report(),
            "archive_state": inspect_segment(p, source_errors=True)[0],
            "refusal": "stream_seal_byte_mismatch",
        }


class SourceTests(FixtureCase):
    def test_payload_validation_errors_preserve_raw(self):
        for name, mutate in (
            ("missing", lambda r: r["payload"].pop("retry_count")),
            ("null_without_reason", lambda r: r["payload"]["field_reasons"].clear()),
            ("boolean_as_count", lambda r: r["payload"].update(offer_index=True)),
            ("retry", lambda r: r["payload"].update(retry_count=1)),
            ("unknown_field", lambda r: r["payload"].update(prompt="secret")),
        ):
            with self.subTest(name=name):
                row = Records().row("client", "offer")
                mutate(row)
                join = SourceJoin([row])
                self.assertEqual(join.report()["validity_reasons"][0]["reason"], "schema_violation")
                self.capture("schema_" + name, [row], join.report())

    def test_duplicate_conflict_order_and_gaps(self):
        records = Records()
        a, b, c = [records.row("vllm", "sample", time=t) for t in (0, 500, 1000)]
        b["observed_mono_ns"] = 2000 * 1_000_000
        join = SourceJoin([a, c, b, b])
        self.assertEqual(join.duplicates, 1)
        self.assertFalse(join.errors)
        self.assertEqual([r["source_seq"] for r in join.rows], [0, 1, 2])
        self.capture("source_reorder_within_2s", [a, c, b, b], join.report())
        b["observed_mono_ns"] = 3001 * 1_000_000
        join = SourceJoin([a, c, b])
        self.assertIn("late_reorder_ambiguous", [e["reason"] for e in join.errors])
        self.capture("source_reorder_after_2s", [a, c, b], join.report())
        conflicting = copy.deepcopy(c)
        conflicting["payload"]["running"] = 10
        join = SourceJoin([a, c, conflicting])
        self.assertIn("conflicting_duplicate", [e["reason"] for e in join.errors])
        self.assertIn("source_sequence_gap", [e["reason"] for e in join.errors])
        self.capture("source_conflict_sequence_gap", [a, c, conflicting], join.report())

    def test_missed_slots_reconnect_and_lifecycle_downtime(self):
        records = Records()
        rows = [records.row("vllm", "sample", time=t) for t in (0, 500, 3501)]
        join = SourceJoin(rows)
        cadence = join.cadence("vllm", "vllm-fixture", "boot0", 0, 4000, 500)
        self.assertTrue(cadence["gaps_ms"])
        self.capture("source_reconnect_gap", rows, {"join": join.report(), "cadence": cadence})
        join = SourceJoin(rows)
        cadence = join.cadence(
            "vllm", "vllm-fixture", "boot0", 0, 4000, 500, absent_intervals=[(500, 3501)]
        )
        self.assertFalse(cadence["gaps_ms"])
        self.capture(
            "source_proven_target_downtime", rows, {"join": join.report(), "cadence": cadence}
        )


class ClockTests(FixtureCase):
    def test_inverse_mapping_preserves_nonzero_clock_offset(self):
        rows = self.mappings(width=0)
        for row in rows:
            row["payload"]["remote_ms"] += 100000
        mapper = ClockMapper(rows)
        inverse = mapper.inverse("remote", "boot0", 600, 600)
        self.assertEqual(inverse, [100500, 100500])
        self.capture(
            "clock_inverse_nonzero_offset", rows, {"inverse_ms_bounds": inverse, **mapper.report()}
        )

    def mappings(self, *, width=100, drift=0, wall_jump=0, gap=1000, boot="boot0"):
        records = Records()
        return [
            records.row(
                "clocks",
                "mapping",
                time=t,
                clock_id="remote",
                boot_id=boot,
                remote_ms=t,
                send_ms=t + 100 + (drift if t else 0),
                receive_ms=t + 100 + width + (drift if t else 0),
                local_mono_ms=t,
                local_wall_ms=t + (wall_jump if t else 0),
            )
            for t in (0, gap)
        ]

    def test_bracket_boundary_drift_steps_reboot_and_missing(self):
        cases = [
            ("exact_100", dict(width=100), "boot0", [600, 700]),
            ("asymmetric_rtt", dict(width=80), "boot0", [600, 680]),
            ("excess_101", dict(width=101), "boot0", None),
            ("drift_hull", dict(width=80, drift=20), "boot0", [600, 700]),
            ("drift_excess", dict(width=80, drift=21), "boot0", None),
            ("wall_jump", dict(width=0, wall_jump=101), "boot0", None),
            ("reconnect_gap", dict(width=0, gap=2001), "boot0", None),
            ("new_boot", dict(width=0), "boot1", None),
            ("missing_boot", dict(width=0, boot=None), "boot0", None),
        ]
        for name, kwargs, boot, expected in cases:
            with self.subTest(name=name):
                rows = self.mappings(**kwargs)
                mapper = ClockMapper(rows)
                mapped = mapper.map("remote", boot, 500, 500)
                self.assertEqual(mapped, expected)
                self.capture("clock_" + name, rows, {"mapped_ms_bounds": mapped, **mapper.report()})
        rows = self.mappings(width=10)
        mapper = ClockMapper(rows)
        self.assertIsNone(mapper.map("remote", "boot0", 1001, 1001))
        self.capture("clock_missing_after_last_mapping", rows, mapper.report())


class RequestTests(FixtureCase):
    def test_false_completion_claim_and_trailing_done_bytes_are_retained(self):
        for name, data in (
            ("false_completion_claim", CONTENT),
            ("trailing_done_bytes", CONTENT + FINISH + USAGE + DONE + b"unterminated-data"),
        ):
            records = Records()
            rows, offer = records.request(data=data)
            rows[-1]["payload"]["outcome"] = "complete"
            report = RequestJoin(self.joined(rows), [offer], 1000).report()
            self.assertEqual(report["cohorts"][0]["outcome"], "failed")
            self.assertEqual(report["stage1_scope"]["false_completion_after_content"]["count"], 1)
            self.assertTrue(report["stage1_scope"]["raw_refs"])
            self.capture("request_" + name, rows, report)

    def test_incremental_delayed_sse_drain_and_adverse_outcomes(self):
        for name, data, event, outcome, partial in (
            ("live_drain", CONTENT + FINISH + USAGE + DONE, "terminal", "complete", False),
            ("content_without_done", CONTENT + FINISH, "terminal", "failed", True),
            (
                "malformed_terminal",
                CONTENT + b'data: {"choices":[]}\n\n' + DONE,
                "terminal",
                "failed",
                True,
            ),
            ("partial_eof", CONTENT, "terminal", "failed", True),
            ("cancel", CONTENT, "cancel", "failed", True),
            ("timeout", CONTENT, "timeout", "right_censored", True),
        ):
            with self.subTest(name=name):
                records = Records()
                rows, offer = records.request(data=data, outcome=event)
                sse = rows[-2]
                split = 13
                sse["payload"]["chunk_hex"] = data[:split].hex()
                delayed = copy.deepcopy(sse)
                delayed["source_seq"] += 1
                delayed["record_id"] += "-delayed"
                delayed["source_time"]["value"] = 50
                delayed["observed_mono_ns"] = 50_000_000
                delayed["payload"]["chunk_hex"] = data[split:].hex()
                rows[-1]["source_seq"] += 1
                rows.insert(-1, delayed)
                join = RequestJoin(self.joined(rows), [offer], 1000)
                report = join.report()
                self.assertEqual(report["cohorts"][0]["outcome"], outcome)
                self.assertEqual(report["cohorts"][0]["partial"], partial)
                self.assertEqual(report["denominators"][outcome], 1)
                self.assertEqual(report["cohorts"][0]["first_content_ms_bounds"], [50, 50])
                self.capture("request_" + name, rows, report)

    def test_rejection_miss_conflict_lost_identity_and_route_race(self):
        records = Records()
        fields = {
            "request_id": "r0",
            "gateway_uid": "gateway0",
            "config_sha256": HASH,
            "retry_count": 0,
        }
        rows = [
            records.row("client", "offer", **fields),
            records.row(
                "gateway",
                "deny",
                10,
                request_id="r0",
                gateway_uid="gateway0",
                http_status=503,
                denial_code="capacity_reports_expired",
                admit_called=True,
            ),
        ]
        offer = {"request_id": "r0", "gateway_uid": "gateway0", "phase": "pre"}
        report = RequestJoin(self.joined(rows), [offer], 100).report()
        self.assertEqual(report["denominators"]["rejected"], 1)
        self.assertIsNone(report["cohorts"][0]["retry_after_ms"])
        self.capture("request_precontent_rejection", rows, report)
        missed = records.row("client", "missed", 20, request_id="r1", gateway_uid="gateway1")
        offers = [offer, {"request_id": "r1", "gateway_uid": "gateway1", "phase": "pre"}]
        report = RequestJoin(self.joined([*rows, missed]), offers, 100).report()
        self.assertEqual(report["denominators"]["scheduled"], 2)
        self.assertEqual(report["denominators"]["missed_offer"], 1)
        self.capture("request_missed_offer", [*rows, missed], report)
        records = Records()
        rows, offer = records.request()
        rows[3]["payload"]["backend_uid"] = "reused-old-address-new-uid"
        report = RequestJoin(self.joined(rows), [offer], 1000).report()
        self.assertEqual(
            report["operational_outcomes"][0]["reason"], "route_changed_between_admit_and_dispatch"
        )
        self.capture("request_route_changed_after_admit", rows, report)
        for row in rows:
            if "gateway_uid" in row["payload"]:
                row["payload"]["gateway_uid"] = None
                row["payload"]["field_reasons"]["gateway_uid"] = "identity_lost"
        report = RequestJoin(self.joined(rows), [offer], 1000).report()
        self.assertIn("lost_gateway_identity:r0", report["validity_reasons"])
        self.capture("request_lost_gateway_identity", rows, report)

    def test_definite_possible_zero_and_separate_deletion_signal_coverage(self):
        records = Records()
        a, offer0 = records.request("r0", "gateway0", opened=10, first=20, terminal=100)
        b, offer1 = records.request("r1", "gateway1", opened=10, first=20, terminal=100)
        join = RequestJoin(self.joined(a + b), [offer0, offer1], 1000)
        for name, boundary, valid in (
            ("definite", [50, 50], True),
            ("ambiguous", [5, 15], False),
            ("zero", [101, 101], False),
            ("missing_signal", None, False),
        ):
            report = join.coverage(boundary, "old0")
            self.assertEqual(not report["validity_reasons"], valid)
            self.capture("coverage_" + name, a + b, report)
        scope = join.report()["stage1_scope"]
        for key in (
            "mid_decode_interruption",
            "partial_after_content",
            "false_completion_after_content",
        ):
            self.assertEqual(scope[key], {"count": 0, "coverage": "not_exercised_max_tokens_1"})

    def test_status_policy_identity_and_choice_schema(self):
        for name in ("http_error", "wrong_policy", "wrong_uid", "bool_choice"):
            records = Records()
            rows, offer = records.request()
            for row in rows:
                p = row["payload"]
                if name == "http_error" and p.get("http_status") is not None:
                    p["http_status"] = 500
                if name == "wrong_policy" and p.get("policy"):
                    p["policy"] = "unexpected-policy"
                if name == "wrong_uid" and row["source_kind"] == "client" and p.get("backend_uid"):
                    p["backend_uid"] = "wrong-generation"
                if name == "bool_choice" and p["event"] == "sse":
                    p["chunk_hex"] = (
                        CONTENT.replace(b'"index":0', b'"index":false') + FINISH + USAGE + DONE
                    ).hex()
            report = RequestJoin(self.joined(rows), [offer], 1000).report()
            cohort = report["cohorts"][0]
            if name in ("http_error", "bool_choice"):
                self.assertEqual(cohort["outcome"], "failed")
            if name == "wrong_policy":
                self.assertEqual(cohort["policy"], "unexpected-policy")
                self.assertIn("missing_or_mismatched_policy:r0", report["validity_reasons"])
            if name == "wrong_uid":
                self.assertFalse(cohort["identity_join_valid"])
                self.assertIn("backend_identity_join_mismatch:r0", report["validity_reasons"])
            self.capture("request_" + name, rows, report)
        records = Records()
        rows = [
            records.row(
                "client", "offer", request_id="r0", gateway_uid="gateway0", policy="round-robin"
            ),
            records.row(
                "client", "receive", 10, request_id="r0", gateway_uid="gateway0", http_status=503
            ),
            records.row(
                "gateway",
                "deny",
                10,
                request_id="r0",
                gateway_uid="gateway0",
                http_status=503,
                denial_code="capacity_reports_expired",
                admit_called=True,
            ),
        ]
        report = RequestJoin(
            self.joined(rows),
            [{"request_id": "r0", "gateway_uid": "gateway0", "phase": "pre"}],
            100,
        ).report()
        self.assertEqual(report["cohorts"][0]["outcome"], "rejected")
        self.assertFalse(report["cohorts"][0]["admitted"])
        self.assertEqual(report["cohorts"][0]["admit_ms_bounds"], [10, 10])
        self.capture("request_refusal_after_http_receive", rows, report)


def stage_fixture(*, install=True, replacement=True, first_content_before_signal=False):
    records = Records()
    rows, offers = [], []
    for i, gateway in enumerate(("gateway0", "gateway1")):
        first = 500 if first_content_before_signal else 700
        request, offer = records.request(f"r{i}", gateway, first=first, terminal=1000)
        rows.extend(request)
        offers.append(offer)
        members = [
            {"slot": 0, "uid": "old0", "ready": True, "sampled": True, "healthy": True},
            {"slot": 1, "uid": "old1", "ready": True, "sampled": True, "healthy": True},
        ]
        rows.append(
            records.row(
                "gateway", "install", 0, gateway_uid=gateway, membership_known=True, members=members
            )
        )
        rows.append(
            records.row(
                "gateway",
                "install",
                1000 + i * 200,
                gateway_uid=gateway,
                membership_known=True,
                members=members[1:],
            )
        )
        rows.append(
            records.row(
                "redis",
                "report_store",
                2000,
                gateway_uid=gateway,
                redis_time_ms=2000,
                report_success=True,
                report_known=True,
                report_complete=True,
                store_order=0,
            )
        )
        if install:
            rows.append(
                records.row(
                    "gateway",
                    "install",
                    3200,
                    gateway_uid=gateway,
                    membership_known=True,
                    members=[{**members[0], "uid": "new0"}, members[1]],
                    replacement_uid="new0",
                    install_redis_ms_bounds=[3200, 3200],
                    store_order=2,
                )
            )
            rows.append(
                records.row(
                    "redis",
                    "report_store",
                    3300,
                    gateway_uid=gateway,
                    redis_time_ms=3300,
                    computed_ms=1000,
                    report_success=True,
                    report_known=True,
                    report_complete=True,
                    store_order=3,
                )
            )
        if replacement:
            request, offer = records.request(
                f"r{i + 2}",
                gateway,
                offered=3400,
                opened=3450,
                first=3900,
                terminal=4000 + i,
                uid="new0",
                phase="event",
            )
            rows.extend(request)
            offers.append(offer)
            rows.append(
                records.row(
                    "gateway",
                    "health",
                    3400,
                    gateway_uid=gateway,
                    members=[{"uid": "new0", "sampled": True, "healthy": True}],
                )
            )
    rows.extend(
        [
            records.row("kubernetes", "deletion", 500, pod_uid="old0", slot=0),
            records.row("kubernetes", "signal", 600, pod_uid="old0", slot=0, signal="SIGTERM"),
        ]
    )
    if replacement:
        for event, time in (
            ("gpu_free", 1800),
            ("pod_created", 2000),
            ("scheduled", 2300),
            ("startup", 2500),
            ("ready", 3000),
        ):
            rows.append(
                records.row(
                    "kubernetes",
                    event,
                    time,
                    pod_uid="new0",
                    slot=0,
                    image_cache_state="cold",
                    model_cache_state="cold",
                )
            )
    rows.append(
        records.row(
            "redis",
            "snapshot",
            3000,
            redis_time_ms=3000,
            reports={
                "gateway0": {"n": 1, "expires_ms": 8000, "unknown": False},
                "gateway1": {"n": 1, "expires_ms": 8000, "unknown": False},
            },
            lows=[],
            state={"n": 1, "candidate": None, "since_ms": None, "until_ms": None},
            active_reservations=[],
            occupied=0,
            config_sha256=HASH,
        )
    )
    for offer in offers:
        request_id = offer["request_id"]
        opened = 10 if request_id in ("r0", "r1") else 3450
        ended = 1000 if request_id in ("r0", "r1") else 4000 + int(request_id[-1]) - 2
        effective_n = 2 if request_id in ("r0", "r1") else 1
        for row in rows:
            if (
                row["source_kind"] == "gateway"
                and row["payload"]["event"] == "admit"
                and row["payload"].get("request_id") == request_id
            ):
                row["payload"].update(effective_n=effective_n, effective_b=5 * effective_n)
        rows.append(
            records.row(
                "redis",
                "admit",
                opened,
                redis_time_ms=opened,
                request_id=request_id,
                gateway_uid=offer["gateway_uid"],
                decision="allowed",
                effective_n=effective_n,
                effective_b=5 * effective_n,
                idempotent=False,
            )
        )
        rows.append(
            records.row(
                "redis",
                "release",
                ended,
                redis_time_ms=ended,
                request_id=request_id,
                gateway_uid=offer["gateway_uid"],
                decision="released",
                idempotent=False,
            )
        )
    if replacement:
        rows.append(
            records.row(
                "vllm",
                "sample",
                3400,
                pod_uid="new0",
                slot=0,
                process_generation="new-process",
                reset_generation="new-reset",
                model_sha256=HASH,
                runtime_sha256=HASH,
                metric_semantics_sha256=HASH,
                sample_time=3400,
                running=0,
                waiting=0,
                prefix_query_tokens_total=0,
                prefix_hit_tokens_total=0,
                preemptions_total=0,
                health_ready=True,
            )
        )
    rows.append(redis_clock(records, 10000))
    return records, rows, offers


class StageTests(FixtureCase):
    def test_later_valid_completion_after_missing_initial_fitness(self):
        records, rows, offers = stage_fixture()
        rows = [
            r
            for r in rows
            if not (r["source_kind"] == "gateway" and r["payload"]["event"] == "health")
        ]
        for i, gateway in enumerate(("gateway0", "gateway1")):
            request, offer = records.request(
                f"r{i + 4}",
                gateway,
                offered=4950,
                opened=5000,
                first=5100,
                terminal=5500 + i,
                uid="new0",
                phase="event",
            )
            rows.extend(request)
            offers.append(offer)
            rows.append(
                records.row(
                    "gateway",
                    "health",
                    4900,
                    gateway_uid=gateway,
                    members=[{"uid": "new0", "sampled": True, "healthy": True}],
                )
            )
        rows.append(
            records.row(
                "vllm",
                "sample",
                4900,
                pod_uid="new0",
                slot=0,
                process_generation="new-process",
                reset_generation="new-reset",
                model_sha256=HASH,
                runtime_sha256=HASH,
                metric_semantics_sha256=HASH,
                sample_time=4900,
                running=0,
                waiting=0,
                prefix_query_tokens_total=0,
                prefix_hit_tokens_total=0,
                preemptions_total=0,
                health_ready=True,
            )
        )
        report = self.report(rows, offers)
        self.assertEqual(report["stage4"]["usable_ms_bounds"], [5501, 5501])
        self.assertEqual(
            report["stage4"]["per_gateway_first_completion_ms_bounds"]["gateway0"], [4000, 4000]
        )
        self.capture("stages_later_qualified_usable_completion", rows, report)

    def report(self, rows, offers, *, end=10000, complete=True):
        joined = self.joined(rows)
        requests = RequestJoin(joined, offers, end)
        return StageJoin(
            joined, requests, target_uid="old0", replacement_uid="new0", capture_end_ms=end
        ).report(capture_complete=complete)

    def test_asymmetric_exclusion_lifecycle_and_usable_completion(self):
        records, rows, offers = stage_fixture()
        report = self.report(rows, offers)
        self.assertTrue(report["measurement_valid"], report["validity_reasons"])
        self.assertTrue(report["stage4"]["replacement_usable_by_deadline"])
        self.assertEqual(report["stage4"]["usable_ms_bounds"], [4001, 4001])
        self.assertEqual(report["stage2"]["gateway0"]["first_excluded_ms_bounds"], [1000, 1000])
        self.assertEqual(report["stage2"]["gateway1"]["first_excluded_ms_bounds"], [1200, 1200])
        self.capture("stages_asymmetric_usable", rows, report)
        rows.append(
            records.row(
                "gateway",
                "upstream_open",
                1500,
                request_id="r0",
                gateway_uid="gateway0",
                backend_uid="old0",
                backend_slot=0,
            )
        )
        report = self.report(rows, offers)
        self.assertIn(
            "old_uid_dispatch_after_exclusion",
            [o["reason"] for o in report["operational_outcomes"]],
        )
        self.capture("stages_late_old_dispatch", rows, report)

    def test_unknown_known_empty_relist_and_address_reuse(self):
        for name, known, members, error in (
            ("watch_disconnect", False, [], "expired_resource_version"),
            ("api_auth", False, [], "auth"),
            ("api_timeout", False, [], "timeout"),
            ("malformed_snapshot", False, [], "malformed"),
            ("known_empty", True, [], None),
            (
                "terminating_ready",
                True,
                [
                    {
                        "slot": 0,
                        "uid": "old0",
                        "ready": True,
                        "sampled": True,
                        "healthy": True,
                        "terminating": True,
                    }
                ],
                None,
            ),
            (
                "ip_reused_fresh_uid",
                True,
                [
                    {
                        "slot": 0,
                        "uid": "rollback-fresh-uid",
                        "address": "old-address",
                        "ready": True,
                        "sampled": False,
                        "healthy": False,
                    }
                ],
                None,
            ),
        ):
            records, rows, offers = stage_fixture()
            row = next(
                r
                for r in rows
                if r["source_kind"] == "gateway"
                and r["payload"]["event"] == "install"
                and r["payload"].get("gateway_uid") == "gateway0"
                and r["source_time"]["value"] == 1000
            )
            row["payload"].update(membership_known=known, members=members, error_class=error)
            rows.append(
                records.row(
                    "kubernetes",
                    "relist",
                    1100,
                    pod_uid="old0",
                    slot=0,
                    resource_version="new-rv",
                    list_valid=True,
                    endpoints=[],
                )
            )
            report = self.report(rows, offers)
            self.assertEqual(report["stage2"]["gateway0"]["first_excluded_ms_bounds"], [1000, 1000])
            self.capture("stages_" + name, rows, report)

    def test_missing_ambiguous_signal_unknown_cache_ready_without_completion(self):
        for name in (
            "missing_signal",
            "overlap_signal",
            "unknown_cache",
            "ready_only",
            "missing_health",
            "missing_native_metrics",
            "missing_signal_receipt",
        ):
            _, rows, offers = stage_fixture()
            if name == "missing_signal":
                rows = [
                    r
                    for r in rows
                    if not (r["source_kind"] == "kubernetes" and r["payload"]["event"] == "signal")
                ]
            elif name == "overlap_signal":
                row = next(
                    r
                    for r in rows
                    if r["source_kind"] == "kubernetes" and r["payload"]["event"] == "signal"
                )
                row["uncertainty_ns"] = 100_000_000
            elif name == "missing_signal_receipt":
                row = next(
                    r
                    for r in rows
                    if r["source_kind"] == "kubernetes" and r["payload"]["event"] == "signal"
                )
                row["payload"]["signal_receipt_time"] = None
                row["payload"]["field_reasons"]["signal_receipt_time"] = "actual_receipt_missing"
            elif name == "unknown_cache":
                for r in rows:
                    if r["source_kind"] == "kubernetes" and r["payload"]["event"] == "startup":
                        r["payload"]["model_cache_state"] = "unknown"
            elif name == "missing_health":
                rows = [
                    r
                    for r in rows
                    if not (r["source_kind"] == "gateway" and r["payload"]["event"] == "health")
                ]
            elif name == "missing_native_metrics":
                rows = [r for r in rows if r["source_kind"] != "vllm"]
            else:
                for r in rows:
                    if (
                        r["source_kind"] == "client"
                        and r["payload"].get("request_id") in ("r2", "r3")
                        and r["payload"]["event"] == "sse"
                    ):
                        r["payload"]["chunk_hex"] = CONTENT.hex()
            report = self.report(rows, offers)
            if name in ("ready_only", "missing_health", "missing_native_metrics"):
                self.assertIs(report["stage4"]["replacement_usable_by_deadline"], None)
                if name != "ready_only":
                    self.assertFalse(report["measurement_valid"])
            else:
                self.assertFalse(report["measurement_valid"])
            self.capture("stages_" + name, rows, report)

    def test_complete_never_usable_no_installations_is_valid_adverse(self):
        _, rows, offers = stage_fixture(install=False, replacement=False)
        # Complete capture proves cold cache even though startup/completion never arrives.
        rows.append(
            Records().row(
                "kubernetes",
                "container_state",
                2000,
                identity="cache-observer",
                pod_uid="new0",
                slot=0,
                image_cache_state="cold",
                model_cache_state="cold",
            )
        )
        rows.append(
            Records().row(
                "kubernetes",
                "pod_created",
                1900,
                identity="pending-replacement-observer",
                pod_uid="new0",
                slot=0,
            )
        )
        report = self.report(rows, offers, end=300500)
        self.assertTrue(report["measurement_valid"], report["validity_reasons"])
        self.assertIs(report["stage4"]["replacement_usable_by_deadline"], False)
        for gateway in report["addition_budgets"]:
            self.assertEqual(gateway["age_budget_status"], "not_applicable")
            self.assertEqual(gateway["renewal_budget_status"], "not_applicable")
        self.capture("stages_valid_never_usable_no_install", rows, report)


class AdmissionTests(FixtureCase):
    def test_read_timeout_and_missing_atomic_snapshot_do_not_become_zero(self):
        row = Records().row("redis", "read_error", 100, redis_time_ms=100, error="read_timeout")
        stage = StageJoin(
            self.joined([row]),
            RequestJoin([], [], 100),
            target_uid="old0",
            replacement_uid="new0",
            capture_end_ms=100,
        )
        report = {
            "admission": stage.admission(),
            "validity_reasons": stage.errors,
            "operational_outcomes": stage.outcomes,
        }
        self.assertIn("redis_read_evidence_missing", report["validity_reasons"])
        self.assertEqual(report["admission"]["timeline"], [])
        self.capture("admission_read_timeout_not_zero", [row], report)

    def budget_case(
        self,
        name,
        *,
        age=3000,
        renewal=3100,
        installation=True,
        other_install=True,
        open_renewal=False,
        bracket_width=0,
        missing_prior=False,
        tie=False,
        clock_offset_ms=0,
        clock_capture=True,
    ):
        records = Records()
        rows = []
        for gateway in ("gateway0", "gateway1"):
            if not installation or (gateway == "gateway1" and not other_install):
                continue
            actual_age = age if gateway == "gateway0" else 1
            if not missing_prior:
                rows.append(
                    records.row(
                        "redis",
                        "report_store",
                        10000 - actual_age,
                        gateway_uid=gateway,
                        redis_time_ms=10000 - actual_age,
                        report_success=True,
                        report_known=True,
                        report_complete=True,
                        store_order=None if tie else 1,
                    )
                )
            rows.append(
                records.row(
                    "gateway",
                    "install",
                    10000,
                    gateway_uid=gateway,
                    membership_known=True,
                    members=[],
                    replacement_uid="new0",
                    install_redis_ms_bounds=[10000, 10000 + bracket_width],
                    store_order=2,
                )
            )
            if not open_renewal:
                rows.append(
                    records.row(
                        "redis",
                        "report_store",
                        10000 + renewal,
                        gateway_uid=gateway,
                        redis_time_ms=10000 + renewal,
                        computed_ms=0,
                        report_success=True,
                        report_known=True,
                        report_complete=True,
                        store_order=3,
                    )
                )
        for row in rows:
            if row["source_kind"] == "redis":
                row["payload"]["redis_time_ms"] += clock_offset_ms
            if row["source_kind"] == "gateway":
                row["payload"]["install_redis_ms_bounds"] = [
                    v + clock_offset_ms for v in row["payload"]["install_redis_ms_bounds"]
                ]
        if clock_capture:
            rows.append(redis_clock(records, 10000 + renewal, clock_offset_ms))
        stage = StageJoin(
            self.joined(rows),
            RequestJoin([], [], 10000 + renewal),
            target_uid="old0",
            replacement_uid="new0",
            capture_end_ms=10000 + renewal,
        )
        report = {
            "budgets": stage.additions(True),
            "validity_reasons": stage.errors,
            "operational_outcomes": stage.outcomes,
        }
        self.capture(name, rows, report)
        return report

    def test_preceding_store_and_every_budget_boundary(self):
        offset = self.budget_case(
            "budget_nonzero_redis_clock_offset",
            age=3001,
            renewal=3101,
            open_renewal=True,
            clock_offset_ms=100000,
        )
        self.assertEqual(offset["budgets"][0]["age_budget_status"], "exceeded")
        self.assertEqual(offset["budgets"][0]["renewal_budget_status"], "exceeded")
        self.assertEqual(offset["budgets"][0]["renewal_elapsed_lower_bound_ms"], 3101)
        self.assertEqual(offset["budgets"][0]["capture_end_ms_bounds"], [113101, 113101])
        missing_clock = self.budget_case(
            "budget_missing_capture_end_redis_clock", clock_capture=False
        )
        self.assertIn("missing_required_clock_evidence", missing_clock["validity_reasons"])
        self.assertIsNone(missing_clock["budgets"][0]["capture_end_ms_bounds"])
        for age in (2999, 3000, 3001):
            report = self.budget_case("age_" + str(age), age=age)
            self.assertEqual(
                report["budgets"][0]["age_budget_status"], "exceeded" if age > 3000 else "within"
            )
            self.assertEqual(report["budgets"][1]["age_budget_status"], "within")
        for renewal in (3099, 3100, 3101):
            report = self.budget_case("renewal_" + str(renewal), renewal=renewal)
            self.assertEqual(
                report["budgets"][0]["renewal_budget_status"],
                "exceeded" if renewal > 3100 else "within",
            )
        report = self.budget_case("budget_straddling_age", age=3000, bracket_width=1, renewal=3200)
        self.assertEqual(report["budgets"][0]["age_budget_status"], "indeterminate")
        report = self.budget_case(
            "budget_straddling_renewal", age=2999, bracket_width=2, renewal=3101
        )
        self.assertEqual(report["budgets"][0]["renewal_budget_status"], "indeterminate")
        for elapsed in (2000, 3100, 3101):
            report = self.budget_case(
                "renewal_open_" + str(elapsed), renewal=elapsed, open_renewal=True
            )
            self.assertEqual(
                report["budgets"][0]["renewal_budget_status"],
                "exceeded" if elapsed > 3100 else "right_censored",
            )
            self.assertEqual(report["budgets"][0]["renewal_elapsed_lower_bound_ms"], elapsed)
        report = self.budget_case("budget_no_installs", installation=False)
        self.assertTrue(all(g["age_budget_status"] == "not_applicable" for g in report["budgets"]))
        report = self.budget_case("budget_only_one_gateway", other_install=False)
        self.assertEqual(report["budgets"][1]["age_budget_status"], "not_applicable")
        report = self.budget_case("budget_missing_preceding_store", missing_prior=True)
        self.assertIn("missing_preceding_report_store_join", report["validity_reasons"])
        report = self.budget_case("budget_ambiguous_tied_store", age=0, tie=True)
        self.assertIn("missing_preceding_report_store_join", report["validity_reasons"])

    def test_atomic_ttl_low_unknown_occupancy_and_duplicate_operations(self):
        records = Records()
        rows = []
        scenarios = [
            (
                0,
                2,
                {
                    "g0": {"n": 2, "expires_ms": 8000, "unknown": False},
                    "g1": {"n": 2, "expires_ms": 8000, "unknown": False},
                },
                [],
            ),
            (
                100,
                1,
                {
                    "g0": {"n": 1, "expires_ms": 8100, "unknown": False},
                    "g1": {"n": 2, "expires_ms": 8000, "unknown": False},
                },
                [{"n": 1, "until_ms": 10100}],
            ),
            (
                8000,
                1,
                {
                    "g0": {"n": 2, "expires_ms": 16000, "unknown": True},
                    "g1": {"n": 2, "expires_ms": 8000, "unknown": False},
                },
                [{"n": 1, "until_ms": 10100}],
            ),
            (16000, 1, {"g0": {"n": 2, "expires_ms": 16000, "unknown": True}}, []),
            (17000, 0, {"g0": {"n": 0, "expires_ms": 25000, "unknown": False}}, []),
        ]
        for time, n, reports, lows in scenarios:
            rows.append(
                records.row(
                    "redis",
                    "snapshot",
                    time,
                    redis_time_ms=time,
                    reports=reports,
                    lows=lows,
                    state={"n": n, "candidate": None, "since_ms": None, "until_ms": None},
                    active_reservations=[
                        {"request_id": f"active{i}", "expiry_ms": 30000} for i in range(10)
                    ],
                    occupied=10,
                    config_sha256=HASH,
                )
            )
        for event, idempotent, time in (
            ("admit", True, 10),
            ("admit", True, 11),
            ("release", False, 18000),
            ("release", True, 18001),
        ):
            rows.append(
                records.row(
                    "redis",
                    event,
                    time,
                    redis_time_ms=time,
                    request_id="active0",
                    decision="allowed",
                    effective_n=2 if event == "admit" else None,
                    effective_b=10 if event == "admit" else None,
                    idempotent=idempotent,
                )
            )
        stage = StageJoin(
            self.joined(rows),
            RequestJoin([], [], 19000),
            target_uid="old0",
            replacement_uid="new0",
            capture_end_ms=19000,
        )
        report = {
            "admission": stage.admission(),
            "validity_reasons": stage.errors,
            "operational_outcomes": stage.outcomes,
        }
        self.assertFalse(stage.errors)
        self.assertFalse(stage.outcomes)
        self.assertEqual(
            report["admission"]["remaining_reservations"], [f"active{i}" for i in range(1, 10)]
        )
        self.assertTrue(report["admission"]["timeline"][2]["all_expired"])
        self.assertTrue(report["admission"]["timeline"][1]["occupied_at_or_above_b"])
        self.capture("admission_ttl_unknown_retained_low_no_revocation", rows, report)
        bad = copy.deepcopy(rows)
        next(
            r
            for r in bad
            if r["payload"]["event"] == "snapshot" and r["payload"]["redis_time_ms"] == 100
        )["payload"]["occupied"] = 11
        next(
            r
            for r in bad
            if r["payload"]["event"] == "snapshot" and r["payload"]["redis_time_ms"] == 8000
        )["payload"]["state"]["candidate"] = 2
        stage = StageJoin(
            self.joined(bad),
            RequestJoin([], [], 19000),
            target_uid="old0",
            replacement_uid="new0",
            capture_end_ms=19000,
        )
        report = {
            "admission": stage.admission(),
            "validity_reasons": stage.errors,
            "operational_outcomes": stage.outcomes,
        }
        self.assertIn("atomic_snapshot_inconsistent", stage.errors)
        self.assertIn(
            "unknown_did_not_interrupt_restoration", [o["reason"] for o in stage.outcomes]
        )
        self.capture("admission_atomic_inconsistent_unknown_candidate", bad, report)
        drained = copy.deepcopy(rows)
        drained.extend(
            records.row(
                "redis",
                "release",
                18001 + i,
                redis_time_ms=18001 + i,
                request_id=f"active{i}",
                idempotent=False,
            )
            for i in range(1, 10)
        )
        for name, raw in (("drained", drained), ("missing_capacity", copy.deepcopy(rows))):
            if name == "missing_capacity":
                p = next(r["payload"] for r in raw if r["payload"]["event"] == "admit")
                p["effective_b"] = None
                p["field_reasons"]["effective_b"] = "capture_missing"
            stage = StageJoin(
                self.joined(raw),
                RequestJoin([], [], 19000),
                target_uid="old0",
                replacement_uid="new0",
                capture_end_ms=19000,
            )
            result = {
                "admission": stage.admission(),
                "validity_reasons": stage.errors,
                "operational_outcomes": stage.outcomes,
            }
            if name == "drained":
                self.assertEqual(result["admission"]["remaining_reservations"], [])
                self.assertFalse(stage.errors)
                self.assertFalse(stage.outcomes)
            else:
                self.assertIn("missing_operation_capacity:active0", stage.errors)
            self.capture("admission_" + name, raw, result)


def recovery_fixture(*, count=40, windows=10, latency=100, hits=100):
    records = Records()
    rows, cohorts = [], []
    for slot in (0, 1):
        for time in range(0, windows * 30000 + 1, 500):
            rows.append(
                records.row(
                    "vllm",
                    "sample",
                    time,
                    identity=f"vllm-slot{slot}",
                    pod_uid="new0" if slot == 0 and time >= 150000 else f"old{slot}",
                    slot=slot,
                    process_generation="process0",
                    reset_generation="reset0",
                    model_sha256=HASH,
                    runtime_sha256=HASH,
                    metric_semantics_sha256=HASH,
                    sample_time=time,
                    running=0,
                    waiting=0,
                    prefix_query_tokens_total=(
                        time - 150000 if slot == 0 and time >= 150000 else time
                    )
                    // 500
                    * 10,
                    prefix_hit_tokens_total=(
                        time - 150000 if slot == 0 and time >= 150000 else time
                    )
                    // 500
                    * hits
                    // 100
                    * 10,
                    preemptions_total=0,
                    health_ready=True,
                )
            )
    for window in range(windows):
        for gateway_index, gateway in enumerate(("gateway0", "gateway1")):
            for i in range(count):
                time = window * 30000 + 1000 + i
                cohorts.append(
                    {
                        "request_id": f"w{window}-g{gateway_index}-{i}",
                        "gateway_uid": gateway,
                        "backend_slot": gateway_index,
                        "backend_uid": "new0"
                        if window >= 5 and gateway_index == 0
                        else f"old{gateway_index}",
                        "outcome": "complete",
                        "offer_ms_bounds": [time, time],
                        "first_content_ms_bounds": [time + latency, time + latency],
                        "terminal_ms_bounds": [time + 2 * latency, time + 2 * latency],
                        "ttft_ms_bounds": [latency, latency],
                        "e2e_ms_bounds": [2 * latency, 2 * latency],
                    }
                )
    return rows, cohorts


class RecoveryTests(FixtureCase):
    def test_observed_generation_reset_censors_window_and_retains_valid_adverse(self):
        rows, cohorts = recovery_fixture(windows=10)
        for row in rows:
            p, time = row["payload"], row["source_time"]["value"]
            if p["slot"] == 0 and time >= 195000:
                p.update(
                    process_generation="restarted-process",
                    reset_generation="observed-reset",
                    prefix_query_tokens_total=(time - 195000) // 500 * 10,
                    prefix_hit_tokens_total=(time - 195000) // 500 * 10,
                )
        report = self.recovery(rows, cohorts).report()
        self.assertFalse(report["validity_reasons"])
        self.assertEqual(report["recovery"]["bracket_ms"], [210000, 300000])
        self.assertIn("observed_counter_generation_change", report["operational_outcomes"])
        self.capture(
            "recovery_observed_generation_reset_valid_adverse", rows, report, cohorts=cohorts
        )

    def recovery(self, rows, cohorts, end=300000):
        return RecoveryJoin(
            self.joined(rows),
            cohorts,
            pre_end_ms=120000,
            usable_ms=150000,
            capture_end_ms=end,
            replacement_uid="new0",
        )

    def test_sample_and_percentile_boundaries(self):
        rows, cohorts = recovery_fixture(windows=1)
        for n in (39, 40, 399, 400, 1999, 2000):
            stats = percentiles(list(range(n)))
            self.assertEqual(stats["p50_eligible"], n >= 40)
            self.assertEqual(stats["p95_eligible"], n >= 400)
            self.assertEqual(stats["p99_eligible"], n >= 2000)
            self.capture(
                "percentiles_n" + str(n),
                rows,
                stats,
                cohorts=[{"latency_ms": value} for value in range(n)],
            )
        rows, cohorts = recovery_fixture(count=39, windows=1)
        report = self.recovery(rows, cohorts).window(0, 30000)
        self.assertFalse(report["eligible"])
        self.capture("recovery_n39", rows, report, cohorts=cohorts)
        rows, cohorts = recovery_fixture(count=40, windows=1)
        report = self.recovery(rows, cohorts).window(0, 30000)
        self.assertTrue(report["eligible"], report["validity_reasons"])
        self.capture("recovery_n40", rows, report, cohorts=cohorts)

    def test_three_windows_recover_and_failed_window_breaks_streak(self):
        rows, cohorts = recovery_fixture(windows=10)
        report = self.recovery(rows, cohorts).report()
        self.assertEqual(
            report["recovery"], {"bracket_ms": [150000, 240000], "confirmation_ms": 240000}
        )
        self.assertFalse(report["validity_reasons"])
        self.capture("recovery_three_eligible", rows, report, cohorts=cohorts)
        for row in cohorts:
            if row["offer_ms_bounds"][0] // 30000 == 6:
                row["ttft_ms_bounds"] = [121, 121]
        report = self.recovery(rows, cohorts).report()
        self.assertEqual(report["recovery"]["bracket_ms"], [210000, 300000])
        self.assertEqual([w["streak"] for w in report["recovery_windows"][:3]], [1, 0, 1])
        self.capture("recovery_one_failed_window_breaks_streak", rows, report, cohorts=cohorts)

    def test_counter_and_coverage_adverse_cases(self):
        for name in (
            "missing_slot",
            "missing_gateway",
            "completion_uid_mismatch",
            "counter_reset",
            "uid_reset",
            "process_reset",
            "impossible_hits",
            "zero_queries",
            "late_settlement",
            "stale",
            "gap",
            "missing_clock",
        ):
            rows, cohorts = recovery_fixture(windows=1)
            if name == "missing_slot":
                rows = [r for r in rows if r["payload"]["slot"] == 0]
            elif name == "missing_gateway":
                cohorts = [r for r in cohorts if r["gateway_uid"] == "gateway0"]
            elif name == "completion_uid_mismatch":
                cohorts[0]["backend_uid"] = "another-pod-same-slot"
            elif name in ("counter_reset", "uid_reset", "process_reset"):
                for row in rows:
                    if row["payload"]["slot"] == 0 and row["source_time"]["value"] >= 15000:
                        field = {
                            "counter_reset": "prefix_query_tokens_total",
                            "uid_reset": "pod_uid",
                            "process_reset": "process_generation",
                        }[name]
                        row["payload"][field] = 0 if name == "counter_reset" else "new-generation"
            elif name in ("impossible_hits", "zero_queries", "late_settlement"):
                for row in rows:
                    if row["payload"]["slot"] == 0:
                        if name == "zero_queries":
                            row["payload"]["prefix_query_tokens_total"] = 0
                        else:
                            row["payload"]["prefix_hit_tokens_total"] += (
                                1000 if row["source_time"]["value"] >= 15000 else 0
                            )
            elif name == "stale":
                rows = [r for r in rows if r["source_time"]["value"] >= 1000]
            elif name == "gap":
                rows = [r for r in rows if not 10000 <= r["source_time"]["value"] <= 12500]
            elif name == "missing_clock":
                for row in rows:
                    row["source_time"]["clock_id"] = "unmapped-remote"
            report = self.recovery(rows, cohorts).window(0, 30000)
            self.assertFalse(report["eligible"], name)
            self.capture("recovery_" + name, rows, report, cohorts=cohorts)

    def test_unstable_baseline_no_recovery_and_zero_reference(self):
        rows, cohorts = recovery_fixture(windows=25)
        for row in cohorts:
            window = row["offer_ms_bounds"][0] // 30000
            if window == 0 or window >= 4:
                row["ttft_ms_bounds"] = [1000, 1000]
        report = self.recovery(rows, cohorts, end=750000).report()
        self.assertEqual(report["baseline_unstable_windows"], [0])
        self.assertIsNone(report["recovery"])
        self.assertEqual(report["censor_reason"], "recovery_deadline")
        self.assertFalse(report["validity_reasons"])
        self.capture("recovery_unstable_baseline_no_recovery", rows, report, cohorts=cohorts)
        self.assertTrue(RecoveryJoin.within_latency(0, 0))
        self.assertFalse(RecoveryJoin.within_latency(1, 0))
        rows, cohorts = recovery_fixture(latency=0, hits=0, windows=8)
        report = self.recovery(rows, cohorts, end=240000).report()
        self.assertIsNotNone(report["recovery"])
        self.capture("recovery_zero_references", rows, report, cohorts=cohorts)


class PacketTests(FixtureCase):
    def test_unknown_secret_keys_and_hex_strings_are_pseudonymized(self):
        secret = "f" * 64
        row = Records().row(
            "client",
            "offer",
            request_id="private-request",
            private_payload={"private-dynamic-key": "private-value"},
            authorization=secret,
        )
        archive = Archive.create(self.root / "secret-raw", {"registration_id": REGISTRATION_ID})
        writer = StreamingArchiveWriter(archive.root)
        writer.append("raw/client.jsonl", row)
        writer.seal()
        safe, _ = sanitized_sources(
            archive.root, self.root / "secret-safe", key=b"fixture-sanitization-key-32-bytes-long"
        )
        safe.seal()
        rows = inspect_segment(safe.root / "raw/client.jsonl")[1]
        report = SourceJoin(rows).report()
        self.assertEqual(report["validity_reasons"][0]["reason"], "schema_violation")
        for path in safe.root.rglob("*"):
            if path.is_file():
                for private in (
                    secret.encode(),
                    b"private-dynamic-key",
                    b"private-value",
                    b"private-request",
                ):
                    self.assertNotIn(private, path.read_bytes())
        OUTPUTS["sanitized_unknown_secret_fields_remain_invalid"] = {
            "report": report,
            "archive_state": verify_archive(safe.root),
        }

    def artifacts(self):
        repo = Path(__file__).resolve().parents[2]
        artifacts = {name: ("synthetic-" + name).encode() for name in REQUIRED_PINS}
        artifacts["registration"] = (repo / REGISTRATION_PATH).read_bytes().replace(b"\r\n", b"\n")
        return artifacts

    def sizing_inputs(self):
        return {
            "maximum_record_bytes": {
                name: 4096
                for name in (
                    "vllm",
                    "gateway",
                    "kubernetes",
                    "redis",
                    "clocks",
                    "controller",
                    "metadata",
                )
            },
            "request_record_bytes": 4096,
            "request_events": 20,
            "transfer_bytes_per_second": 10000000,
            "reconnect_ms": 60000,
            "lifecycle": {
                phase: {"observed_ms": 120001, "offline_bound_ms": 200000, "source_sha256": HASH}
                for phase in ("creation_readiness", "preparation", "cleanup")
            },
            "prices": [
                {
                    "resource": "synthetic-full-lifetime-all-resources",
                    "usd_per_hour": 1.0,
                    "count": 1,
                    "lifetime_ms": 10000000,
                    "source_sha256": HASH,
                }
            ],
            "already_spent_usd": 50.0,
            "full_project_remaining_usd": 100.0,
        }

    def test_hash_bound_manifest_missing_inputs_and_trace(self):
        artifacts = self.artifacts()
        manifest = source_manifest(artifacts)
        verify_sources(manifest, artifacts)
        report = PacketReadiness(manifest, {}).report()
        self.assertFalse(report["ready"])
        self.assertIn("signal_capture", report["missing_live_inputs"])
        self.capture("packet_missing_live_sources", [], report)
        altered = copy.deepcopy(artifacts)
        altered["model"] += b"changed"
        with self.assertRaisesRegex(IntegrityError, "mismatch"):
            verify_sources(manifest, altered)
        self.capture(
            "packet_source_hash_mismatch",
            [],
            {
                "refused": "packet_source_mismatch",
                "expected_manifest": manifest,
                "actual_manifest": source_manifest(altered),
            },
        )
        del altered["scheduler"]
        with self.assertRaisesRegex(IntegrityError, "missing"):
            source_manifest(altered)
        self.capture(
            "packet_missing_scheduler_resolution",
            [],
            {"refused": "missing_packet_sources:scheduler", "readiness": report},
        )
        trace = workload_trace("pre", 1, 600000)
        self.assertEqual(len(trace), 6552)
        self.assertEqual(
            [r["gateway_uid"] for r in trace[:4]], ["gateway0", "gateway1", "gateway0", "gateway1"]
        )
        self.assertEqual(len({r["prefix_id"] for r in trace[:1440]}), 384)
        self.assertEqual(sum(int(r["prefix_id"][1:]) < 96 for r in trace[:1440]), 1152)
        self.assertEqual(trace, workload_trace("pre", 1, 600000))
        self.assertNotEqual(trace, workload_trace("pre", 2, 600000))
        self.capture(
            "packet_frozen_weighted_trace",
            [],
            {
                "offers": len(trace),
                "epoch_rows": 1440,
                "trace_sha256": sha(encode({"trace": trace})),
                "first_four": trace[:4],
            },
            cohorts=trace,
        )

    def test_maximum_campaign_sizing_cost_caps_and_missing_sources(self):
        inputs = self.sizing_inputs()
        report = sizing(**inputs)
        self.assertEqual(report["campaign_ms"], 5280000)
        self.assertEqual(report["periodic_rows"]["vllm"], 21122)
        self.assertEqual(
            report["maximum_archive_bytes"], 2 * report["raw_byte_bound_before_margin"]
        )
        self.assertEqual(report["lifecycle_allowances_ms"]["cleanup"], 300000)
        self.assertTrue(report["within_300_total"])
        self.assertFalse(report["paid_ready"])
        self.capture(
            "packet_maximum_three_attempt_two_reset_sizing",
            [],
            {"inputs": inputs, "result": report},
        )
        inputs["already_spent_usd"] = 149
        inputs["full_project_remaining_usd"] = 150
        report = sizing(**inputs)
        self.assertFalse(report["within_150_checkpoint"])
        self.assertFalse(report["within_300_total"])
        self.capture("packet_forecast_exceeds_both_caps", [], {"inputs": inputs, "result": report})
        for name in ("size", "lifecycle", "price", "lifetime"):
            inputs = self.sizing_inputs()
            if name == "size":
                del inputs["maximum_record_bytes"]["clocks"]
            elif name == "lifecycle":
                inputs["lifecycle"]["cleanup"].pop("source_sha256")
            elif name == "price":
                inputs["prices"] = []
            else:
                inputs["prices"][0]["lifetime_ms"] = 1
            with self.assertRaises(IntegrityError) as exc:
                sizing(**inputs)
            self.capture(
                "packet_refused_missing_" + name,
                [],
                {"inputs": inputs, "reason": str(exc.exception)},
            )

    def test_sanitization_stream_fragments_and_join_identity(self):
        records = Records()
        rows, offer = records.request(request="private-request")
        raw = Archive.create(self.root / "private-archive", {"registration_id": REGISTRATION_ID})
        writer = StreamingArchiveWriter(raw.root)
        for row in rows:
            writer.append("raw/" + row["source_kind"] + ".jsonl", row)
        writer.seal()
        sanitized, provenance = sanitized_sources(
            raw.root, self.root / "sanitized", key=b"fixture-key-is-synthetic-not-secret" * 2
        )
        verified = sanitized.seal()
        sanitized_rows = []
        for path in (sanitized.root / "raw").glob("*.jsonl"):
            sanitized_rows.extend(inspect_segment(path)[1])
        sanitizer = Sanitizer(b"fixture-key-is-synthetic-not-secret" * 2)
        safe_offer = sanitizer.value(offer)
        safe_offer["gateway_uid"] = offer["gateway_uid"]
        before = RequestJoin(self.joined(rows), [offer], 1000).report()
        after = RequestJoin(self.joined(sanitized_rows), [safe_offer], 1000).report()
        self.assertEqual(before["denominators"], after["denominators"])
        self.assertEqual(
            before["cohorts"][0]["ttft_ms_bounds"], after["cohorts"][0]["ttft_ms_bounds"]
        )
        for path in sanitized.root.rglob("*"):
            if path.is_file():
                data = path.read_bytes()
                self.assertNotIn(b"private-request", data)
                self.assertNotIn(b"private text", data)
                self.assertNotIn(b"private text".hex().encode(), data)
        self.assertEqual(verify_archive(raw.root)["segments"]["raw/client.jsonl"]["row_count"], 4)
        from inference_platform.inf037b_archive import export_archive

        destination = self.root / "exported"
        interrupted = export_archive(sanitized.root, destination, byte_budget=11)
        resumed = export_archive(sanitized.root, destination)
        self.assertFalse(interrupted["complete"])
        self.assertTrue(resumed["complete"])
        OUTPUTS["sanitized_source_join_export_resume"] = {
            "report": after,
            "archive_state": verified,
            "provenance": provenance,
            "interrupted_export": interrupted,
            "resumed_export": resumed,
        }


class CampaignTests(FixtureCase):
    def test_streaming_raw_receipts_precede_controller_and_summary_finalization(self):
        campaign, _ = self.campaign()
        writer = StreamingArchiveWriter(campaign.root)
        closed = copy.deepcopy(writer.close_raw())
        self.assertTrue(closed["closed"])
        self.assertTrue(all(name.startswith("raw/") for name in closed["segments"]))
        self.assertFalse((campaign.root / "attempts.receipt.json").exists())
        self.assertFalse((campaign.root / "cohorts/requests.receipt.json").exists())
        campaign.start_attempt(0, absolute_deadline_ms=6000000, export_cleanup_ms=1000)
        campaign.journal.setup_complete(0, preconditions=True, reasons=[])
        controller = campaign.finish_attempt(
            10000, absolute_deadline_ms=6000000, export_cleanup_ms=1000
        )
        result = campaign.materialize()
        self.assertTrue(writer.seal()["verified"])
        self.assertTrue(reproduce(campaign.root, campaign.spec)["reproduced"])
        for name, receipt in closed["segments"].items():
            self.assertEqual(receipt, result["archive"]["segments"][name])
        OUTPUTS["stream_raw_close_controller_summary_lifecycle"] = {
            "report": {"writer": closed, "controller": controller},
            "archive_state": result["archive"],
            "summary_sha256": result["summary_sha256"],
        }

    def campaign(
        self,
        *,
        install=True,
        replacement=True,
        name="campaign",
        extra_rows=(),
        persistent_reservations=(),
        first_content_before_signal=False,
    ):
        _, rows, offers = stage_fixture(
            install=install,
            replacement=replacement,
            first_content_before_signal=first_content_before_signal,
        )
        rows.extend(extra_rows)
        for row in rows:
            if (
                row["source_kind"] == "redis"
                and row["payload"]["event"] == "snapshot"
                and row["payload"]["redis_time_ms"] >= 1000
            ):
                active = row["payload"]["active_reservations"]
                active.extend(
                    {"request_id": request_id, "expiry_ms": 10001}
                    for request_id in persistent_reservations
                )
                row["payload"]["occupied"] = len(active)
        archive = Archive.create(
            self.root / name,
            {"registration_id": REGISTRATION_ID, "sources_sha256": {"collector": HASH}},
        )
        writer = StreamingArchiveWriter(archive.root)
        for row in rows:
            writer.append("raw/" + row["source_kind"] + ".jsonl", row)
        spec = {
            "attempt_index": 1,
            "target_slot": 0,
            "target_uid": "old0",
            "replacement_uid": "new0",
            "expected_offers": offers,
            "config_sha256": HASH,
            "pre_end_ms": 600000,
            "capture_end_ms": 10000,
            "required_streams": [
                {
                    "kind": "gateway",
                    "identity": "gateway-fixture",
                    "generation": "boot0",
                    "start_ms": 0,
                    "end_ms": 10000,
                    "cadence_ms": 250,
                }
            ],
        }
        return OfflineCampaign(archive.root, spec), rows

    def test_partial_stage_capture_report_and_immutable_reproduction(self):
        campaign, _ = self.campaign()
        before = campaign.report()
        self.assertFalse(before["measurement_valid"])
        self.assertIn("inadequate_stage5_baseline", before["validity_reasons"])
        self.assertIn("missing_or_duplicate_durable_attempt_start", before["validity_reasons"])
        self.assertIn("missing_durable_traffic_start", before["validity_reasons"])
        self.assertIn("missing_role_resource_fitness", before["validity_reasons"])
        receipt = campaign.materialize()
        self.assertTrue(receipt["archive"]["verified"])
        verified = reproduce(campaign.root, campaign.spec)
        self.assertEqual(before["requests"]["denominators"], verified["denominators"])
        OUTPUTS["campaign_partial_stage_capture_reproduced"] = {
            "report": before,
            "archive_state": receipt["archive"],
            "summary_sha256": receipt["summary_sha256"],
            "reproduction": verified,
        }
        summary = campaign.root / "events/attempt-01.json"
        summary.write_bytes(summary.read_bytes() + b" ")
        with self.assertRaisesRegex(IntegrityError, "hash_mismatch"):
            reproduce(campaign.root, campaign.spec)
        OUTPUTS["campaign_summary_mutation_refused"] = {
            "report": before["controller"],
            "archive_state": receipt["archive"],
            "refusal": "hash_mismatch:events/attempt-01.json",
        }

    def test_unknown_usability_stops_remaining_slots_and_reopen(self):
        campaign, rows = self.campaign(install=False, replacement=False)
        campaign.start_attempt(0, absolute_deadline_ms=6000000, export_cleanup_ms=1000)
        campaign.journal.setup_complete(0, preconditions=True, reasons=[])
        report = campaign.finish_attempt(
            10000, absolute_deadline_ms=6000000, export_cleanup_ms=1000
        )
        self.assertEqual(report["slots"][1]["state"], "not_attempted")
        self.assertEqual(report["slots"][1]["reason"], "replacement_usability_not_established")
        self.assertFalse(report["full_acceptance_reachable"])
        reopened = AttemptController(campaign.root / "attempts.jsonl")
        self.assertEqual(reopened.report(), report)
        with self.assertRaises(Refused):
            campaign.start_attempt(11000, absolute_deadline_ms=6000000, export_cleanup_ms=1000)
        self.capture(
            "campaign_unknown_usability_sticky_stop",
            rows,
            {"event": campaign.report(), "controller": report, "reopened": reopened.report()},
            journal=campaign.root / "attempts.jsonl",
        )

    def test_absolute_deadline_and_failed_preconditions_are_durable(self):
        for name in ("insufficient_remaining", "absolute_deadline", "failed_precondition"):
            campaign, rows = self.campaign(name=name)
            if name == "insufficient_remaining":
                with self.assertRaisesRegex(Refused, "insufficient"):
                    campaign.start_attempt(0, absolute_deadline_ms=1559999, export_cleanup_ms=0)
            else:
                campaign.start_attempt(0, absolute_deadline_ms=6000000, export_cleanup_ms=1000)
                if name == "failed_precondition":
                    campaign.journal.setup_complete(
                        0, preconditions=False, reasons=["missing_source_clock"]
                    )
                else:
                    campaign.journal.setup_complete(0, preconditions=True, reasons=[])
                    with self.assertRaisesRegex(Refused, "absolute_session"):
                        campaign.finish_attempt(
                            10000, absolute_deadline_ms=10000, export_cleanup_ms=1
                        )
            report = campaign.journal.report()
            self.assertEqual(AttemptController(campaign.root / "attempts.jsonl").report(), report)
            self.capture("campaign_" + name, rows, report, journal=campaign.root / "attempts.jsonl")

    def test_sanitized_cohorts_and_summaries_reproduce_without_private_content(self):
        campaign, _ = self.campaign()
        original = campaign.report()
        campaign.materialize()
        result = sanitized_campaign(
            campaign.root,
            self.root / "safe-campaign",
            [campaign.spec],
            key=b"fixture-sanitization-key-32-bytes-long",
        )
        safe_root = self.root / "safe-campaign"
        safe_report = OfflineCampaign(safe_root, result["specs"][0]).report()
        self.assertEqual(
            original["requests"]["denominators"], safe_report["requests"]["denominators"]
        )
        self.assertEqual(
            original["stages"]["stage4"]["replacement_usable_by_deadline"],
            safe_report["stages"]["stage4"]["replacement_usable_by_deadline"],
        )
        self.assertEqual(
            [g["age_budget_status"] for g in original["stages"]["addition_budgets"]],
            [g["age_budget_status"] for g in safe_report["stages"]["addition_budgets"]],
        )
        for path in safe_root.rglob("*"):
            if path.is_file():
                data = path.read_bytes()
                for private in (
                    b'"old0"',
                    b'"new0"',
                    b'"r0"',
                    b'"reservation-r0"',
                    b"private text",
                    b"private text".hex().encode(),
                ):
                    self.assertNotIn(private, data)
        OUTPUTS["campaign_sanitized_cohorts_and_summary_reproduced"] = {
            "report": safe_report,
            "archive_state": result["archive"],
            "summaries": result["summaries"],
            "source_manifest_sha256": result["source_manifest_sha256"],
        }

    def test_all_three_attempt_summaries_no_pooling_and_omission_refused(self):
        campaign, rows = self.campaign()
        specs = [campaign.spec]
        for index in (2, 3):
            specs.append(
                {**campaign.spec, "attempt_index": index, "target_slot": (0, 1, 0)[index - 1]}
            )
            for original in rows:
                row = copy.deepcopy(original)
                row.update(
                    attempt_id=index,
                    record_id=original["record_id"] + f"-attempt{index}",
                    source_identity=original["source_identity"] + f"-attempt{index}",
                )
                with (campaign.root / "raw" / (row["source_kind"] + ".jsonl")).open("ab") as stream:
                    stream.write(encode(row))
        with self.assertRaisesRegex(IntegrityError, "every_attempted_slot"):
            campaign.materialize()
        result = materialize_bundle(campaign.root, specs)
        self.assertEqual(len(result["summaries"]), 3)
        reports = []
        for spec in specs:
            self.assertTrue(reproduce(campaign.root, spec)["reproduced"])
            report = OfflineCampaign(campaign.root, spec).report()
            self.assertEqual(report["requests"]["denominators"]["scheduled"], 4)
            reports.append(report)
        OUTPUTS["campaign_all_three_summaries_no_pooling"] = {
            "report": reports,
            "archive_state": result["archive"],
            "summaries": result["summaries"],
            "omission_refusal": "summaries_must_cover_every_attempted_slot",
        }


def complete_campaign_fixture(
    root,
    *,
    registration_scale=False,
    drop=None,
    end=1560000,
    recover=False,
    metrics_loading=False,
    extra_rows=(),
    persistent_reservations=(),
):
    """Complete registered schedule; explicit refusals bound correctness-fixture size.

    Baseline, signal and usable completions are captured. Unless recover=True,
    sample shortfall gives fully observed adverse nonrecovery. Timing mode
    completes every offer. These are synthetic software controls, not measurements.
    """
    records, rows, offers = Records(), [], []
    deletion, old_end, startup, ready = 600500, 601000, 650000, 660000
    installs = {"gateway0": 660250, "gateway1": 660500}
    if metrics_loading:
        startup = ready = None
        installs = dict.fromkeys(installs, end + 1)
    members = [
        {"uid": "old0", "slot": 0, "ready": True, "sampled": True, "healthy": True},
        {"uid": "old1", "slot": 1, "ready": True, "sampled": True, "healthy": True},
    ]

    def view(time, gateway):
        return [m.copy() for m in members if m["slot"] == 1 or time < deletion + 250] + (
            [{**members[0], "uid": "new0"}] if time >= installs[gateway] else []
        )

    # Every registered offer is captured. Most are explicit pre-admission refusals
    # in correctness mode; baseline, signal and usable requests complete normally.
    schedule = [
        {**o, "scheduled_ms": base + o["scheduled_ms_numerator"] // o["scheduled_ms_denominator"]}
        for phase, base, duration in (("pre", 0, 600000), ("event", 600000, end - 600000))
        for o in workload_trace(phase, 1, duration)
    ]
    request_intervals = []
    for o in schedule:
        time, gateway, phase = o["scheduled_ms"], o["gateway_uid"], o["phase"]
        baseline = 480000 <= time < 600000 and (time - 480000) % 30000 < 8000
        signal = 600000 <= time < 600300
        completion = (
            registration_scale
            or baseline
            or signal
            or 661000 <= time < 661500
            or 915000 <= time < 915500
            or (recover and 661000 <= time < 790000)
        )
        terminal = min(end, time + (1000 if signal else 100))
        uid = "old0" if time < deletion else "new0" if time >= installs[gateway] else "old1"
        if metrics_loading and time >= deletion:
            uid = "old1"
        if o["offer_index"] % 4 >= 2 and not signal:
            uid = "old1"
        slot = 1 if uid == "old1" else 0
        fields = {k: o[k] for k in ("request_id", "offer_index", "prefix_id", "gateway_uid")}
        fields.update(config_sha256=HASH, policy="round-robin", retry_count=0)
        if completion:
            request, _ = records.request(
                o["request_id"],
                gateway,
                offered=time,
                opened=time + 10,
                first=time + 20,
                terminal=terminal,
                uid=uid,
                slot=slot,
                phase=phase,
            )
            for row in request:
                if row["source_kind"] == "client":
                    row["payload"].update({k: fields[k] for k in ("offer_index", "prefix_id")})
                if row["source_kind"] == "gateway":
                    row["source_identity"] = gateway
            request_intervals.append((time + 10, terminal, o["request_id"]))
            for event, at in (("admit", time + 10), ("release", terminal)):
                rows.append(
                    records.row(
                        "redis",
                        event,
                        at,
                        request_id=o["request_id"],
                        gateway_uid=gateway,
                        redis_time_ms=at,
                        decision="allowed" if event == "admit" else "released",
                        effective_n=2,
                        effective_b=10,
                        idempotent=False,
                    )
                )
        else:
            request = [
                records.row("client", "offer", time, **fields, lateness_ms=0),
                records.row(
                    "client",
                    "deny",
                    time + 1,
                    **fields,
                    http_status=503,
                    denial_code="tenant_request_rate",
                    decision="refused",
                    admit_called=False,
                    effective_n=2,
                    effective_b=10,
                ),
                records.row("client", "terminal", terminal, **fields, http_status=503),
            ]
        rows.extend(request)
        offers.append(
            {
                **{
                    k: o[k]
                    for k in ("request_id", "offer_index", "prefix_id", "gateway_uid", "phase")
                },
                "config_sha256": HASH,
                "scheduled_ms": time,
            }
        )
    for time in range(0, end + 1, 250):
        for gateway in ("gateway0", "gateway1"):
            extra = (
                {"replacement_uid": "new0", "install_redis_ms_bounds": [time, time]}
                if time == installs[gateway]
                else {}
            )
            rows.append(
                records.row(
                    "gateway",
                    "install",
                    time,
                    identity=gateway,
                    gateway_uid=gateway,
                    membership_known=True,
                    members=view(time, gateway),
                    poll_seq=time // 250,
                    resource_version=str(time),
                    healthy_count=len(view(time, gateway)),
                    **extra,
                )
            )
            rows.append(
                records.row(
                    "gateway",
                    "health",
                    time,
                    identity=gateway,
                    gateway_uid=gateway,
                    members=view(time, gateway),
                    poll_seq=time // 250,
                    healthy_count=len(view(time, gateway)),
                )
            )
            rows.append(
                records.row(
                    "redis",
                    "report_store",
                    time + 1,
                    gateway_uid=gateway,
                    redis_time_ms=time + 1,
                    n=2,
                    report_success=True,
                    report_known=True,
                    report_complete=True,
                )
            )
        active = [
            {"request_id": rid, "expiry_ms": begin + 30000}
            for begin, finish, rid in request_intervals
            if begin <= time < finish
        ]
        if time >= 250:
            active.extend(
                {"request_id": request_id, "expiry_ms": end + 1000}
                for request_id in persistent_reservations
            )
        rows.append(
            records.row(
                "redis",
                "snapshot",
                time,
                redis_time_ms=time,
                reports={
                    g: {"n": 2, "expires_ms": time + 8000, "unknown": False}
                    for g in ("gateway0", "gateway1")
                },
                lows=[],
                state={"n": 2, "candidate": None, "since_ms": None, "until_ms": None},
                active_reservations=active,
                occupied=len(active),
                config_sha256=HASH,
            )
        )
        endpoints = [{"uid": "old1", "serving": True}]
        if time <= old_end:
            endpoints.append({"uid": "old0", "serving": time < deletion})
        if ready is not None and time >= ready:
            endpoints.append({"uid": "new0", "serving": True})
        rows.append(
            records.row(
                "kubernetes",
                "snapshot",
                time,
                resource_version=str(time),
                endpoints=endpoints,
                list_valid=True,
            )
        )
    for event, time, uid in (
        ("deletion", deletion, "old0"),
        ("signal", 600600, "old0"),
        ("pod_created", 602000, "new0"),
        ("gpu_free", 601500, "new0"),
        ("scheduled", 603000, "new0"),
        ("startup", startup, "new0"),
        ("ready", ready, "new0"),
    ):
        if time is None:
            continue
        rows.append(
            records.row(
                "kubernetes",
                event,
                time,
                pod_uid=uid,
                slot=0,
                signal="SIGTERM" if event == "signal" else None,
                image_cache_state="cold",
                model_cache_state="cold",
            )
        )
    if metrics_loading:
        for time, state, reason in (
            (603000, "running", "container_started"),
            (end, "metrics_not_started", "continuous_lifecycle_since_pod_creation"),
        ):
            rows.append(
                records.row(
                    "kubernetes",
                    "container_state",
                    time,
                    pod_uid="new0",
                    slot=0,
                    container_state=state,
                    reason=reason,
                    image_cache_state="cold",
                    model_cache_state="cold",
                )
            )
    for uid, slot, begin, finish in (
        ("old0", 0, 0, old_end),
        ("old1", 1, 0, end),
        ("new0", 0, startup, end),
    ):
        if begin is None:
            continue
        for time in range(begin, finish + 1, 500):
            rows.append(
                records.row(
                    "vllm",
                    "sample",
                    time,
                    identity=uid,
                    generation=uid + "-process",
                    pod_uid=uid,
                    slot=slot,
                    process_generation=uid + "-process",
                    reset_generation="reset0",
                    model_sha256=HASH,
                    runtime_sha256=HASH,
                    metric_semantics_sha256=HASH,
                    sample_time=time,
                    running=0,
                    waiting=0,
                    prefix_query_tokens_total=(time - begin) * 2,
                    prefix_hit_tokens_total=time - begin,
                    preemptions_total=0,
                    health_ready=True,
                )
            )
        if uid == "old0":
            rows.append(
                records.row(
                    "vllm",
                    "process_end",
                    finish,
                    identity=uid,
                    generation=uid + "-process",
                    pod_uid=uid,
                    slot=slot,
                )
            )
    for time in range(0, end + 1, 1000):
        rows.append(
            records.row(
                "clocks",
                "mapping",
                time,
                clock_id="redis",
                boot_id="redis-boot",
                remote_ms=time,
                local_mono_ms=time,
                local_wall_ms=time,
                send_ms=time,
                receive_ms=time,
            )
        )
    for role in ("gateway0", "gateway1", "generator"):
        rows.append(
            records.row(
                "controller",
                "resource",
                0,
                role=role,
                cpu_fraction=0.5,
                nic_fraction=0.5,
                limit_known=True,
            )
        )
    rows.extend(extra_rows)
    if drop:
        rows = [row for row in rows if not drop(row)]
    rows.sort(key=lambda row: (row["observed_mono_ns"], row["payload"]["event"] == "process_end"))
    sequences = {}
    segments = {}
    for row in rows:
        key = (row["source_kind"], row["source_identity"], row["source_generation"])
        row["source_seq"] = sequences.get(key, 0)
        sequences[key] = row["source_seq"] + 1
        row["record_id"] = ":".join(map(str, (*key, row["source_seq"])))
        segments.setdefault(row["source_kind"], bytearray()).extend(encode(row))
    Archive.create(
        root,
        {
            "registration_id": REGISTRATION_ID,
            "sources_sha256": {
                **dict.fromkeys(REQUIRED_PINS, HASH),
                "registration": REGISTRATION_GIT_BLOB_SHA256,
            },
        },
    )
    for kind, data in segments.items():
        (root / "raw" / (kind + ".jsonl")).write_bytes(data)
    spec = {
        "attempt_index": 1,
        "target_slot": 0,
        "target_uid": "old0",
        "replacement_uid": "new0",
        "expected_offers": offers,
        "config_sha256": HASH,
        "traffic_start_ms": 0,
        "pre_end_ms": 600000,
        "capture_start_ms": 0,
        "capture_end_ms": end,
    }
    campaign = OfflineCampaign(root, spec)
    campaign.start_attempt(0, absolute_deadline_ms=10000000, export_cleanup_ms=0)
    campaign.journal.setup_complete(0, preconditions=True, reasons=[])
    campaign.record_capture_window(0, end)
    return campaign, len(rows)


class Round193Tests(FixtureCase):
    def test_terminal_loss_cannot_prove_never_usable(self):
        _, rows, offers = stage_fixture(install=False, replacement=False)
        rows = [
            r
            for r in rows
            if not (r["source_kind"] == "client" and r["payload"]["event"] == "terminal")
        ]
        joined = self.joined(rows)
        stage = StageJoin(
            joined,
            RequestJoin(joined, offers, 300500),
            target_uid="old0",
            replacement_uid="new0",
            capture_end_ms=300500,
        )
        report = stage.report(capture_complete=True)
        self.assertIs(report["stage4"]["replacement_usable_by_deadline"], None)
        self.assertIn("incomplete_client_terminal_capture", report["validity_reasons"])
        self.capture("r193_missing_client_terminals", rows, report)

    def test_unattributed_archive_errors_and_external_sequences(self):
        campaign, _ = CampaignTests.campaign(self, name="archive-errors")
        with (campaign.root / "raw/client.jsonl").open("ab") as stream:
            stream.write(b'{"torn":')
        report = campaign.report()
        self.assertIn("truncated_jsonl", report["validity_reasons"])
        self.assertEqual(report["archive_level_errors"][0]["affects_attempts"], "all")
        self.retain("r193_archive_torn_tail", campaign, report)
        records = Records()
        a, omitted, b = [records.row("redis", "snapshot", t) for t in (0, 250, 500)]
        join = SourceJoin(
            [a, b],
            external_sequences={("redis", "redis-fixture", "boot0"): {omitted["source_seq"]}},
        )
        self.assertNotIn("source_sequence_gap", [e["reason"] for e in join.errors])
        self.capture("r193_other_attempt_sequence_is_not_missing", [a, omitted, b], join.report())

    def retain(self, name, campaign, report, **extra):
        # Full arrays are deterministic source indexes, not distinct decisions.
        # Hash the complete report and retain every validity/stage/coverage result.
        decision = {
            k: report[k]
            for k in (
                "measurement_valid",
                "validity_reasons",
                "coverage_contract",
                "archive_level_errors",
                "stages",
                "controller",
            )
        }
        OUTPUTS[name] = {
            "report": decision,
            "full_report_sha256": sha(encode(report)),
            "archive_state": Archive(campaign.root).seal(),
            **extra,
        }

    def test_complete_campaign_and_periodic_outages(self):
        cases = (
            ("complete", None),
            (
                "health_250s",
                lambda r: (
                    r["source_kind"] == "gateway"
                    and r["payload"].get("gateway_uid") == "gateway1"
                    and r["payload"]["event"] == "health"
                    and 660000 <= r["observed_mono_ns"] // 1000000 < 910000
                ),
            ),
            (
                "install_health_5s",
                lambda r: (
                    r["source_kind"] == "gateway"
                    and r["payload"].get("gateway_uid") == "gateway1"
                    and r["payload"]["event"] in ("install", "health")
                    and 700000 <= r["observed_mono_ns"] // 1000000 < 705000
                ),
            ),
        )
        for name, drop in cases:
            with self.subTest(name=name):
                campaign, _ = complete_campaign_fixture(self.root / name, drop=drop)
                report = campaign.report()
                self.assertEqual(
                    report["measurement_valid"], drop is None, report["validity_reasons"]
                )
                if drop:
                    if name == "health_250s":
                        self.assertIs(
                            report["stages"]["stage4"]["replacement_usable_by_deadline"], None
                        )
                    self.assertIn("required_source_gap", report["validity_reasons"])
                else:
                    self.assertIs(
                        report["stages"]["stage4"]["replacement_usable_by_deadline"], True
                    )
                    self.assertTrue(
                        any(c["lifecycle_proofs"] for c in report["coverage_contract"]["contracts"])
                    )
                self.retain("r193_" + name, campaign, report)

    def test_archived_spec_and_durable_controller_facts(self):
        campaign, _ = complete_campaign_fixture(
            self.root / "spec",
            drop=lambda r: (
                r["source_kind"] == "kubernetes"
                and r["payload"]["event"] == "snapshot"
                and 700000 <= r["observed_mono_ns"] // 1000000 < 705000
            ),
        )
        report = campaign.report()
        self.assertFalse(report["measurement_valid"])
        self.assertIn("required_source_gap", report["validity_reasons"])
        # Caller-controlled stream windows have no influence on registered coverage.
        campaign.spec["required_streams"] = [{"kind": "kubernetes", "end_ms": 690000}]
        self.assertFalse(campaign.report()["measurement_valid"])
        for field, value in (
            ("traffic_start_ms", 1),
            ("pre_end_ms", 1),
            ("capture_start_ms", 1),
            ("capture_end_ms", 690000),
            ("target_slot", 1),
        ):
            changed = {**campaign.spec, field: value}
            with self.assertRaisesRegex(IntegrityError, "durable_spec_mismatch:" + field):
                OfflineCampaign(campaign.root, changed).report()
        report = campaign.report()
        receipt = campaign.materialize()
        archived = json.loads((campaign.root / "events/attempt-01.spec.json").read_bytes())
        self.assertEqual(archived, campaign.spec)
        summary = json.loads((campaign.root / "events/attempt-01.json").read_bytes())
        self.assertEqual(summary["spec_sha256"], sha(encode(archived)))
        self.assertIn("events/attempt-01.spec.json", (campaign.root / "SHA256SUMS").read_text())
        self.assertTrue(reproduce(campaign.root, attempt_index=1)["reproduced"])
        narrowed = {**campaign.spec, "capture_end_ms": 690000}
        with self.assertRaisesRegex(IntegrityError, "caller_spec_differs_from_archived_spec"):
            reproduce(campaign.root, narrowed)
        with self.assertRaisesRegex(IntegrityError, "caller_spec_differs_from_archived_spec"):
            reproduce(campaign.root, {**campaign.spec, "required_streams": []})
        OUTPUTS["r193_archived_spec_gap"] = {
            "report": {
                "measurement_valid": report["measurement_valid"],
                "validity_reasons": report["validity_reasons"],
                "spec": archived,
            },
            "archive_state": receipt["archive"],
            "refusal": "caller_spec_differs_from_archived_spec",
        }

    def test_later_attempt_errors_setup_and_journal_validity(self):
        campaign, _ = complete_campaign_fixture(self.root / "attribution")
        initial = campaign.report()
        self.assertTrue(initial["measurement_valid"], initial["validity_reasons"])
        campaign.finish_attempt(1560000, absolute_deadline_ms=10000000, export_cleanup_ms=0)
        records = Records()
        bad = records.row("client", "offer", 1600000, identity="later-schema")
        bad["attempt_id"] = 2
        bad["payload"]["unregistered"] = "bad"
        a, b, c = [
            records.row("vllm", "sample", t, identity="later-reorder")
            for t in (1600000, 1600500, 1601000)
        ]
        b["observed_mono_ns"] = 1604001 * 1000000
        for row in (a, b, c):
            row["attempt_id"] = 2
        conflict = copy.deepcopy(c)
        conflict["payload"]["running"] = 1
        later = [bad, a, c, b, conflict]
        (campaign.root / "raw/later.jsonl").write_bytes(b"".join(encode(row) for row in later))
        report = campaign.report()
        self.assertTrue(report["measurement_valid"], report["validity_reasons"])
        # Cross-attempt conflict between 2 and 3 has no single owning row.
        cross = copy.deepcopy(c)
        cross["attempt_id"] = 3
        with (campaign.root / "raw/later.jsonl").open("ab") as stream:
            stream.write(encode(cross))
        report = campaign.report()
        self.assertTrue(report["measurement_valid"], report["validity_reasons"])
        self.assertEqual(report["archive_level_errors"][0]["affects_attempts"], [2, 3])
        later_join = SourceJoin(later)
        self.assertTrue(
            {"schema_violation", "late_reorder_ambiguous", "conflicting_duplicate"}
            <= {e["reason"] for e in later_join.errors}
        )
        specs = [
            campaign.spec,
            {**campaign.spec, "attempt_index": 2, "target_slot": 1},
            {**campaign.spec, "attempt_index": 3},
        ]
        sealed = materialize_bundle(campaign.root, specs)
        saved = json.loads((campaign.root / "events/attempt-01.json").read_bytes())
        self.assertEqual(
            campaign.journal.report()["slots"][0]["measurement_valid"], saved["measurement_valid"]
        )
        self.assertTrue(reproduce(campaign.root, campaign.spec)["measurement_valid"])
        OUTPUTS["r193_later_attempt_errors"] = {
            "report": {
                "measurement_valid": saved["measurement_valid"],
                "archive_level_errors": saved["archive_level_errors"],
                "journal_slot": campaign.journal.report()["slots"][0],
                "later_errors": later_join.errors,
            },
            "archive_state": sealed["archive"],
        }
        setup, _ = complete_campaign_fixture(self.root / "setup-error")
        bad["attempt_id"] = "setup"
        (setup.root / "raw/setup-error.jsonl").write_bytes(encode(bad))
        report = setup.report()
        self.assertFalse(report["measurement_valid"])
        self.assertIn("schema_violation", report["validity_reasons"])
        self.retain("r193_setup_error", setup, report)


class Round194Tests(FixtureCase):
    retain = Round193Tests.retain

    def rewrite(self, campaign, transform):
        for path in (campaign.root / "raw").glob("*.jsonl"):
            rows = [transform(row) for row in inspect_segment(path, source_errors=True)[1]]
            path.write_bytes(b"".join(encode(row) for row in rows if row is not None))

    def test_error_rows_do_not_fill_observation_slots(self):
        for kind, event, identity, field in (
            ("gateway", "health", "gateway1", "members"),
            ("gateway", "install", "gateway1", "members"),
            ("kubernetes", "snapshot", None, "endpoints"),
            ("vllm", "sample", "new0", "running"),
        ):
            with self.subTest(kind=kind, event=event):
                campaign, _ = complete_campaign_fixture(self.root / (kind + event))
                affected = []

                def mutate(
                    row, kind=kind, event=event, identity=identity, field=field, affected=affected
                ):
                    p = row["payload"]
                    if (
                        row["source_kind"] == kind
                        and p["event"] == event
                        and (identity is None or row["source_identity"] == identity)
                        and 660000 <= row["source_time"]["value"] < 910000
                    ):
                        row["error"] = "poll_timeout"
                        p[field] = None
                        p["field_reasons"][field] = "poll_timeout"
                        if event == "snapshot":
                            p["list_valid"] = False
                        if event == "install":
                            p["membership_known"] = False
                        affected.append(row["record_id"])
                    return row

                self.rewrite(campaign, mutate)
                report = campaign.report()
                self.assertFalse(report["measurement_valid"])
                self.assertIn("required_source_gap", report["validity_reasons"])
                self.assertIs(report["stages"]["stage4"]["replacement_usable_by_deadline"], None)
                contract = next(
                    r
                    for r in report["collector_cadence"]
                    if r["source_kind"] == kind
                    and r.get("event") == event
                    and (identity is None or r["identity"] == identity)
                )
                self.assertIn(700000, contract["missed_slots_ms"])
                self.assertEqual(
                    len([t for t in contract["missed_slots_ms"] if 660000 <= t < 910000]),
                    len(affected),
                )
                self.assertTrue(any(a < 660000 and b >= 910000 for a, b in contract["gaps_ms"]))
                campaign.finish_attempt(1560000, absolute_deadline_ms=10000000, export_cleanup_ms=0)
                stops = [
                    e["reason"] for e in campaign.journal.events if e["event"] == "campaign_stop"
                ]
                self.assertNotIn("previous_replacement_never_usable", stops)
                self.assertIn("replacement_usability_not_established", stops)
                self.retain(
                    "r194_error_" + kind + "_" + event,
                    campaign,
                    report,
                    error_row_count=len(affected),
                    finished_journal=campaign.journal.report(),
                )

    def test_boundary_gaps_and_sealed_journal_supersession(self):
        for setup in (False, True):
            campaign, _ = complete_campaign_fixture(self.root / ("tail-setup" if setup else "tail"))
            path = campaign.root / "raw/gateway.jsonl"
            raw = inspect_segment(path, source_errors=True)[1]
            stream = [r for r in raw if r["source_identity"] == "gateway1"]
            if setup:
                for row in stream[:4]:
                    row["attempt_id"] = "setup"
                path.write_bytes(b"".join(encode(r) for r in raw))
            initial = campaign.report()
            self.assertTrue(initial["measurement_valid"], initial["validity_reasons"])
            campaign.finish_attempt(1560000, absolute_deadline_ms=10000000, export_cleanup_ms=0)
            last = max(r["source_seq"] for r in stream)
            raw = [
                r
                for r in raw
                if not (r["source_identity"] == "gateway1" and r["source_seq"] > last - 3)
            ]
            for i in range(20):
                row = copy.deepcopy(stream[-1])
                row.update(
                    attempt_id=2,
                    source_seq=last + 1 + i,
                    record_id=f"later-{i}",
                    observed_mono_ns=(1600000 + i * 250) * 1000000,
                    source_time={
                        "clock_id": "measurement",
                        "unit": "ms",
                        "value": 1600000 + i * 250,
                    },
                )
                raw.append(row)
            path.write_bytes(b"".join(encode(r) for r in raw))
            report = campaign.report()
            self.assertFalse(report["measurement_valid"])
            self.assertIn("source_sequence_gap", report["validity_reasons"])
            gap = next(
                e for e in report["archive_level_errors"] if e["reason"] == "source_sequence_gap"
            )
            self.assertEqual(gap["affects_attempts"], [1, 2])
            self.assertEqual(gap["missing_sequence_range"], [last - 2, last])
            self.assertIs(
                report["journal_validity_superseded_by_sealed_summary"][
                    "journal_measurement_valid"
                ],
                True,
            )
            second = {**campaign.spec, "attempt_index": 2, "target_slot": 1, "expected_offers": []}
            second_report = OfflineCampaign(campaign.root, second).report()
            self.assertIn("source_sequence_gap", second_report["validity_reasons"])
            sealed = materialize_bundle(campaign.root, [campaign.spec, second])
            saved = json.loads((campaign.root / "events/attempt-01.json").read_bytes())
            self.assertEqual(
                saved["journal_validity_superseded_by_sealed_summary"],
                report["journal_validity_superseded_by_sealed_summary"],
            )
            self.assertFalse(reproduce(campaign.root, attempt_index=1)["measurement_valid"])
            OUTPUTS["r194_tail_setup" if setup else "r194_tail"] = {
                "report": {
                    "measurement_valid": report["measurement_valid"],
                    "validity_reasons": report["validity_reasons"],
                    "archive_level_errors": report["archive_level_errors"],
                    "journal_validity_superseded_by_sealed_summary": report[
                        "journal_validity_superseded_by_sealed_summary"
                    ],
                    "attempt2_validity_reasons": second_report["validity_reasons"],
                },
                "archive_state": sealed["archive"],
            }

    def test_mid_and_setup_neighbour_gap_attribution(self):
        for owners, expected in (
            ((1, 1), [1]),
            (("setup", 2), "all"),
            ((2, "setup"), "all"),
            ((2, 2), [2]),
        ):
            records = Records()
            rows = [
                records.row("gateway", "health", time, gateway_uid="gateway1", members=[])
                for time in (0, 250, 500, 750, 1000)
            ]
            rows = [rows[0], rows[-1]]
            for row, owner in zip(rows, owners, strict=True):
                row["attempt_id"] = owner
            errors = OfflineCampaign._archive_errors(rows, {})
            self.assertEqual(len(errors), 1)
            self.assertEqual(errors[0]["affects_attempts"], expected)
            self.assertIn("attribution_rule", errors[0])
            self.capture("r194_gap_" + "_".join(map(str, owners)), rows, errors)

    def test_short_capture_and_confirmation_plus_drain(self):
        for name, end, recover, valid in (
            ("short_720s", 720000, False, False),
            ("confirmed_with_drain", 900000, True, True),
            ("deadline_without_drain", 1280000, False, False),
        ):
            campaign, _ = complete_campaign_fixture(self.root / name, end=end, recover=recover)
            report = campaign.report()
            self.assertEqual(report["measurement_valid"], valid, report["validity_reasons"])
            if name == "short_720s":
                self.assertIn("recovery_deadline_not_fully_captured", report["validity_reasons"])
                self.assertIn(
                    "capture_deadline_plus_drain_not_fully_captured", report["validity_reasons"]
                )
                self.assertNotIn("no_recovery", report["operational_outcomes"])
                self.assertEqual(report["recovery"]["censor_reason"], "capture_end")
            elif valid:
                self.assertIsNotNone(report["recovery"]["recovery"])
                self.assertLessEqual(report["capture_requirement"]["required_capture_end_ms"], end)
                self.assertIsNone(report["recovery"]["censor_reason"])
            else:
                self.assertIn(
                    "capture_deadline_plus_drain_not_fully_captured", report["validity_reasons"]
                )
                self.assertLess(report["recovery"]["deadline_ms"], end)
                self.assertIn("no_recovery", report["operational_outcomes"])
                self.assertNotIn("recovery_deadline_not_fully_captured", report["validity_reasons"])
            self.retain(
                "r194_" + name,
                campaign,
                report,
                recovery=report["recovery"],
                capture_requirement=report["capture_requirement"],
            )

    def test_offers_cannot_differ_from_durable_trace(self):
        campaign, _ = complete_campaign_fixture(self.root / "offer-list")
        # Refusals happen before raw joining, including for a vanished request.
        for field, value in (
            ("request_id", "changed"),
            ("scheduled_ms", 1),
            ("prefix_id", "changed"),
            ("gateway_uid", "gateway1"),
        ):
            spec = copy.deepcopy(campaign.spec)
            spec["expected_offers"][0][field] = value
            with self.assertRaisesRegex(
                IntegrityError, "expected_offers_differ_from_registered_trace"
            ):
                OfflineCampaign(campaign.root, spec).report()
        spec = {**campaign.spec, "expected_offers": campaign.spec["expected_offers"][1:]}
        with self.assertRaisesRegex(IntegrityError, "expected_offers_differ_from_registered_trace"):
            OfflineCampaign(campaign.root, spec).report()
        OUTPUTS["r194_registered_offer_list_refusal"] = {
            "report": {"refusal": "expected_offers_differ_from_registered_trace"},
            "refusal": "expected_offers_differ_from_registered_trace",
            "archive_state": Archive(campaign.root).seal(),
        }

    def test_observation_error_null_and_unknown_flags_are_independent(self):
        for name, changes in (
            ("envelope_error", {"error": "timeout"}),
            ("null_members", {"members": None}),
            ("unknown_membership", {"membership_known": False}),
        ):
            records = Records()
            rows = []
            for time in range(0, 5001, 250):
                row = records.row(
                    "gateway",
                    "install",
                    time,
                    gateway_uid="gateway1",
                    members=[],
                    membership_known=True,
                    poll_seq=time // 250,
                    resource_version=str(time),
                    healthy_count=0,
                )
                if 250 <= time < 4000:
                    for field, value in changes.items():
                        if field == "error":
                            row[field] = value
                        else:
                            row["payload"][field] = value
                            if value is None:
                                row["payload"]["field_reasons"][field] = "poll_timeout"
                rows.append(row)
            joined = SourceJoin(rows)
            result = joined.cadence(
                "gateway", "gateway-fixture", "boot0", 0, 5000, 250, event="install"
            )
            self.assertEqual(result["gaps_ms"], [[0, 4000]])
            self.assertIn(1000, result["missed_slots_ms"])
            self.capture("r194_observation_" + name, rows, result)

    def test_registered_trace_labels_survive_sanitization(self):
        sanitizer = Sanitizer(b"synthetic-round194-key-32-bytes-long")
        for field, value in (("request_id", "a1-pre-123"), ("prefix_id", "p003")):
            self.assertEqual(sanitizer.value(value, field), value)
        for field, value in (("request_id", "private-request"), ("prefix_id", "private-prefix")):
            self.assertNotEqual(sanitizer.value(value, field), value)

    def test_sequence_collisions_preserve_previous_invalidity(self):
        for owners, expected in (
            ((1, 1), [1]),
            ((1, 2), [1, 2]),
            (("setup", 2), "all"),
            ((2, "setup"), "all"),
        ):
            records = Records()
            rows = [
                records.row("gateway", "health", t, gateway_uid="gateway1", members=[])
                for t in (0, 250)
            ]
            for row, owner in zip(rows, owners, strict=True):
                row.update(source_seq=0, attempt_id=owner)
            # Preserve the old invalid result, while attributing the shared error.
            self.assertIn("source_sequence_gap", [e["reason"] for e in SourceJoin(rows).errors])
            errors = OfflineCampaign._archive_errors(rows, {})
            self.assertEqual(len(errors), 1)
            self.assertEqual(errors[0]["reason"], "source_sequence_collision")
            self.assertEqual(errors[0]["affects_attempts"], expected)
            name = "r194_sequence_collision_" + "_".join(map(str, owners))
            self.capture(name, rows, errors)
            # An exact retransmission is still a duplicate, not a collision.
            self.assertEqual(
                OfflineCampaign._archive_errors([rows[0], copy.deepcopy(rows[0])], {}), []
            )
        campaign, count = complete_campaign_fixture(self.root / "collision-positive-control")
        raw, receipts = campaign._raw()
        self.assertEqual(len(raw), count)
        self.assertEqual(OfflineCampaign._archive_errors(raw, receipts), [])
        OUTPUTS["r194_sequence_collision_1_1"]["positive_control"] = {
            "input_fixture": "complete_campaign_fixture",
            "raw_rows": count,
            "archive_level_errors": [],
        }


class Round195Tests(FixtureCase):
    rewrite = Round194Tests.rewrite
    retain = Round193Tests.retain

    def test_clock_registered_gap_and_jitter(self):
        for gap in (1001, 1500, 2000, 2001):
            rows = ClockTests.mappings(self, width=0, gap=gap)
            mapper = ClockMapper(rows)
            mapped = mapper.map("remote", "boot0", 500, 500)
            self.assertEqual(mapped, [600, 600] if gap <= 2000 else None)
            self.capture(f"r195_clock_{gap}", rows, {"mapped": mapped, **mapper.report()})
        records = Records()
        rows = [redis_clock(records, 1000 * i + (i % 4)) for i in range(600)]
        mapper = ClockMapper(rows)
        points = [mapper.map("redis", "boot0", t, t) for t in range(250, 599000, 250)]
        self.assertTrue(
            all(p == [t, t] for p, t in zip(points, range(250, 599000, 250), strict=True))
        )
        self.capture("r195_clock_jitter", rows, {"points": points, **mapper.report()})

    def test_writer_rotation_conflict_fuzz(self):
        import random

        for reopen in (False, True):
            for seed in range(300):
                rng = random.Random(seed)
                archive = Archive.create(
                    self.root / f"fuzz-{reopen}-{seed}", {"registration_id": REGISTRATION_ID}
                )
                writer = StreamingArchiveWriter(archive.root)
                names = ["raw/client.jsonl"]
                originals = [Records().row("client", "offer", request_id=f"r{i}") for i in range(3)]
                for i, row in enumerate(originals):
                    row["record_id"] = f"k{i}"
                    row["source_seq"] = i
                for step in range(16):
                    if step in (0, 4, 9):
                        names.append(writer.rotate("client", step))
                    row = copy.deepcopy(rng.choice(originals))
                    row["payload"]["request_id"] = f"v{rng.randrange(4)}"
                    writer.append(rng.choice(names), row)
                    self.assertEqual(
                        writer.report()["segments"],
                        archive_receipts(archive.root),
                        (reopen, seed, step),
                    )
                    if reopen and step % 3 == 0:
                        writer = StreamingArchiveWriter(archive.root)
                        self.assertEqual(
                            writer.report()["segments"], archive_receipts(archive.root)
                        )
                report = copy.deepcopy(writer.close_raw())
                state = archive.seal()
                self.assertEqual(
                    report["segments"],
                    {k: v for k, v in state["segments"].items() if k.startswith("raw/")},
                )
                if seed == 0:
                    OUTPUTS[f"r195_writer_fuzz_reopen_{reopen}"] = {
                        "report": report,
                        "archive_state": state,
                    }

    def test_non2xx_after_admission_or_open_is_failed(self):
        for status in (502, 503):
            for admission, opened in ((True, True), (True, False), (False, True), (False, False)):
                rows, offer = Records().request()
                rows = [
                    r
                    for r in rows
                    if r["payload"]["event"] != "sse"
                    and (admission or r["payload"]["event"] != "admit")
                    and (opened or r["payload"]["event"] != "upstream_open")
                ]
                for row in rows:
                    if row["payload"].get("http_status") is not None:
                        row["payload"]["http_status"] = status
                report = RequestJoin(self.joined(rows), [offer], 1000).report()
                self.assertEqual(
                    report["cohorts"][0]["outcome"], "failed" if admission or opened else "rejected"
                )
                self.assertIs(report["cohorts"][0]["partial"], False)
                self.capture(f"r195_status_{status}_{admission}_{opened}", rows, report)

    def test_sanitized_damage_retains_raw_outcomes(self):
        for mode in (
            "same_tail",
            "done_whitespace",
            "tail_then_whitespace",
            "later_tail",
            "invalid_hex",
            "null",
            "integer",
            "oversize",
            "unfinished",
            "fragmented",
        ):
            records = Records()
            rows, offer = records.request()
            sse = next(r for r in rows if r["payload"]["event"] == "sse")
            if mode == "done_whitespace":
                sse["payload"]["chunk_hex"] += b" \n".hex()
            elif mode == "tail_then_whitespace":
                sse["payload"]["chunk_hex"] += b"unterminated".hex()
                rows.append(
                    records.row("client", "sse", 50, request_id="r0", chunk_hex=b" \n".hex())
                )
            elif mode == "same_tail":
                sse["payload"]["chunk_hex"] += b"unterminated".hex()
            elif mode == "later_tail":
                rows.append(
                    records.row(
                        "client", "sse", 50, request_id="r0", chunk_hex=b'data: {"partial'.hex()
                    )
                )
            elif mode in ("invalid_hex", "null", "integer"):
                sse["payload"]["chunk_hex"] = {"invalid_hex": "zz", "null": None, "integer": 42}[
                    mode
                ]
                if mode == "null":
                    sse["payload"]["field_reasons"]["chunk_hex"] = "decode_unavailable"
            elif mode == "oversize":
                sse["payload"]["chunk_hex"] = (b"x" * 1_048_577).hex()
            elif mode == "unfinished":
                sse["payload"]["chunk_hex"] = (CONTENT + b'data: {"partial').hex()
            elif mode == "fragmented":
                sse["payload"]["chunk_hex"] = CONTENT[:17].hex()
                rows.append(
                    records.row(
                        "client",
                        "sse",
                        50,
                        request_id="r0",
                        chunk_hex=(CONTENT[17:] + FINISH + USAGE + DONE).hex(),
                    )
                )
            before = RequestJoin(self.joined(rows), [offer], 1000).report()
            raw = Archive.create(self.root / ("raw-" + mode), {"registration_id": REGISTRATION_ID})
            writer = StreamingArchiveWriter(raw.root)
            for row in rows:
                writer.append("raw/" + row["source_kind"] + ".jsonl", row)
            writer.close_raw()
            raw.seal()
            safe, _ = sanitized_sources(
                raw.root, self.root / ("safe-" + mode), key=b"round195-synthetic-sanitizer-key!!"
            )
            safe_rows = [
                r for p in (safe.root / "raw").glob("*.jsonl") for r in inspect_segment(p)[1]
            ]
            sanitized_offer = Sanitizer(b"round195-synthetic-sanitizer-key!!").value(offer)
            sanitized_offer["gateway_uid"] = offer["gateway_uid"]
            after = RequestJoin(self.joined(safe_rows), [sanitized_offer], 1000).report()
            self.assertEqual(before["denominators"], after["denominators"])
            self.assertEqual(
                before["cohorts"][0]["stream"]["errors"], after["cohorts"][0]["stream"]["errors"]
            )
            self.assertEqual(
                before["cohorts"][0]["outcome"],
                "complete" if mode in ("fragmented", "done_whitespace") else "failed",
            )
            OUTPUTS["r195_sse_" + mode] = {
                "report": {"raw": before, "sanitized": after},
                "archive_state": safe.seal(),
            }

    def test_deadline_stop_precedes_report(self):
        campaign, _ = CampaignTests.campaign(self, name="broken-report")
        campaign.start_attempt(0, absolute_deadline_ms=6000000, export_cleanup_ms=1)
        campaign.journal.setup_complete(0, preconditions=True, reasons=[])
        with (
            patch.object(campaign, "report", side_effect=AssertionError("deadline must not join")),
            self.assertRaisesRegex(Refused, "absolute_session_deadline"),
        ):
            campaign.finish_attempt(10000, absolute_deadline_ms=10000, export_cleanup_ms=1)
        self.assertEqual(
            campaign.journal.report()["slots"][0]["reasons"], ["absolute_session_deadline"]
        )
        self.capture(
            "r195_deadline_before_report",
            [],
            campaign.journal.report(),
            journal=campaign.root / "attempts.jsonl",
        )

    def test_starting_topology_uses_successful_observations(self):
        for mode in (
            "last_pre",
            "stale_pre",
            "real_bad",
            "failed_surge",
            "real_surge",
            "missed_offer",
        ):
            campaign, _ = complete_campaign_fixture(self.root / mode, end=901000, recover=True)
            missing_id = campaign.spec["expected_offers"][10]["request_id"]

            def transform(row, mode=mode, missing_id=missing_id):
                p, time = row["payload"], row["observed_mono_ns"] // 1000000
                if mode == "missed_offer" and p.get("request_id") == missing_id:
                    if row["source_kind"] != "client" or p["event"] != "offer":
                        return None
                    p.update(event="missed", policy=None)
                    p["field_reasons"]["policy"] = "no_gateway_dispatch"
                if (
                    row["source_kind"] == "gateway"
                    and p["event"] == "install"
                    and p["gateway_uid"] == "gateway1"
                    and time == 600000
                ):
                    if mode in ("last_pre", "stale_pre"):
                        row["error"] = "poll_timeout"
                        if mode == "last_pre":
                            p.update(members=None, membership_known=False)
                            p["field_reasons"]["members"] = "poll_timeout"
                        else:
                            p["members"] = p["members"][:1]  # cached invalid topology cannot win
                    elif mode == "real_bad":
                        p["members"] = p["members"][:1]
                if (
                    mode in ("failed_surge", "real_surge")
                    and row["source_kind"] == "kubernetes"
                    and p["event"] == "snapshot"
                    and time == 600000
                ):
                    p["endpoints"].append({"uid": "cached-extra", "slot": 2, "serving": True})
                    if mode == "failed_surge":
                        row["error"] = "poll_timeout"
                return row

            self.rewrite(campaign, transform)
            if mode == "missed_offer":
                for path in (campaign.root / "raw").glob("*.jsonl"):
                    counters = {}
                    rows = inspect_segment(path)[1]
                    for row in rows:
                        stream = (row["source_identity"], row["source_generation"])
                        row["source_seq"] = counters.get(stream, 0)
                        counters[stream] = row["source_seq"] + 1
                    path.write_bytes(b"".join(encode(row) for row in rows))
            report = campaign.report()
            self.assertEqual(
                report["measurement_valid"],
                mode not in ("real_bad", "real_surge"),
                report["validity_reasons"],
            )
            self.retain("r195_topology_" + mode, campaign, report)

    def test_sealed_reasons_keep_deadline_and_precondition(self):
        campaign, _ = complete_campaign_fixture(self.root / "deadline", end=901000, recover=True)
        with self.assertRaisesRegex(Refused, "absolute_session_deadline"):
            campaign.finish_attempt(901000, absolute_deadline_ms=901000, export_cleanup_ms=1)
        campaign.materialize()
        summary = json.loads((campaign.root / "events/attempt-01.json").read_bytes())
        self.assertIs(summary["measurement_valid"], False)
        self.assertIn("absolute_session_deadline", summary["validity_reasons"])
        self.assertTrue(reproduce(campaign.root, campaign.spec)["reproduced"])
        OUTPUTS["r195_sealed_absolute_deadline"] = {
            "report": summary,
            "archive_state": verify_archive(campaign.root),
        }
        campaign, _ = CampaignTests.campaign(self, name="setup-failed")
        campaign.start_attempt(0, absolute_deadline_ms=6000000, export_cleanup_ms=1)
        campaign.journal.setup_complete(0, preconditions=False, reasons=["missing_source_clock"])
        campaign.materialize()
        summary = json.loads((campaign.root / "events/attempt-01.json").read_bytes())
        self.assertIn("missing_source_clock", summary["validity_reasons"])
        self.assertIs(summary["measurement_valid"], False)
        OUTPUTS["r195_sealed_setup_failure"] = {
            "report": summary,
            "archive_state": verify_archive(campaign.root),
        }

    def test_complete_ready_only_and_missing_health_are_distinct(self):
        for mode in ("ready_only", "missing_health"):
            _, rows, offers = stage_fixture()
            if mode == "ready_only":
                for row in rows:
                    if (
                        row["source_kind"] == "client"
                        and row["payload"]["event"] == "sse"
                        and row["payload"]["request_id"] in ("r2", "r3")
                    ):
                        row["payload"]["chunk_hex"] = CONTENT.hex()
            else:
                rows = [
                    r
                    for r in rows
                    if not (r["source_kind"] == "gateway" and r["payload"]["event"] == "health")
                ]
            endpoint_clock = redis_clock(Records(), 300500)
            endpoint_clock["record_id"] = "deadline-clock-end"
            rows.append(endpoint_clock)
            report = StageTests.report(self, rows, offers, end=300500)
            self.assertIs(
                report["stage4"]["replacement_usable_by_deadline"],
                False if mode == "ready_only" else None,
            )
            self.assertIs(report["measurement_valid"], mode == "ready_only")
            self.capture("r195_complete_" + mode, rows, report)

    def test_sanitized_campaign_compares_results_and_refuses_divergence(self):
        campaign, _ = CampaignTests.campaign(self, name="damaged-campaign")

        def damage(row):
            if row["source_kind"] == "client" and row["payload"]["event"] == "sse":
                row["payload"]["chunk_hex"] += b"unterminated".hex()
            return row

        self.rewrite(campaign, damage)
        campaign.materialize()
        safe = sanitized_campaign(
            campaign.root,
            self.root / "matching",
            [campaign.spec],
            key=b"round195-synthetic-sanitizer-key!!",
        )
        OUTPUTS["r195_sanitized_campaign_damaged"] = {
            "report": OfflineCampaign(self.root / "matching", safe["specs"][0]).report(),
            "archive_state": safe["archive"],
        }
        original = Sanitizer.row

        def drop_tail(sanitizer, row, **kwargs):
            safe_row = original(sanitizer, row, **kwargs)
            if safe_row["source_kind"] == "client" and safe_row["payload"]["event"] == "sse":
                data = bytes.fromhex(safe_row["payload"]["chunk_hex"])
                safe_row["payload"]["chunk_hex"] = data.replace(b"[redacted-pending]", b"").hex()
            return safe_row

        with (
            patch.object(Sanitizer, "row", drop_tail),
            self.assertRaisesRegex(IntegrityError, "^sanitized_sse_report_mismatch$"),
        ):
            sanitized_campaign(
                campaign.root,
                self.root / "divergent",
                [campaign.spec],
                key=b"round195-synthetic-sanitizer-key!!",
            )
        self.assertFalse((self.root / "divergent" / "SHA256SUMS").exists())

    def test_stage_eligibility_uses_own_failures(self):
        for kind in ("gateway", "redis"):
            campaign, _ = CampaignTests.campaign(self, name="eligibility-" + kind)
            self.rewrite(
                campaign, lambda row, kind=kind: None if row["source_kind"] == kind else row
            )
            report = campaign.report()
            self.assertIs(report["stage_eligibility"]["2" if kind == "gateway" else "3"], False)
            self.retain("r195_stage_eligibility_" + kind, campaign, report)

    def test_closed_journal_sanitization_preserves_codes_and_private_reasons(self):
        for mode in ("source", "deadline", "setup", "private_id"):
            campaign, _ = CampaignTests.campaign(self, name="closed-" + mode)
            if mode == "private_id":

                def private_id(row):
                    if row["payload"].get("request_id") == "r0":
                        row["payload"]["request_id"] = "private:request:195"
                        if "policy" in row["payload"]:
                            row["payload"]["policy"] = None
                            row["payload"].setdefault("field_reasons", {})["policy"] = (
                                "policy_missing"
                            )
                    return row

                self.rewrite(campaign, private_id)
                campaign.spec["expected_offers"][0]["request_id"] = "private:request:195"
            campaign.start_attempt(0, absolute_deadline_ms=6000000, export_cleanup_ms=1000)
            campaign.journal.setup_complete(
                0,
                preconditions=mode != "setup",
                reasons=["private_setup_marker_195"] if mode == "setup" else [],
            )
            if mode == "deadline":
                with self.assertRaisesRegex(Refused, "absolute_session_deadline"):
                    campaign.finish_attempt(10000, absolute_deadline_ms=10000, export_cleanup_ms=1)
            elif mode in ("source", "private_id"):
                campaign.finish_attempt(10000, absolute_deadline_ms=6000000, export_cleanup_ms=1000)
            campaign.materialize()
            safe_root = self.root / ("safe-closed-" + mode)
            safe = sanitized_campaign(
                campaign.root, safe_root, [campaign.spec], key=b"round195-synthetic-sanitizer-key!!"
            )
            report = OfflineCampaign(safe_root, safe["specs"][0]).report()
            self.assertIs(report["measurement_valid"], False)
            self.assertTrue(reproduce(safe_root, safe["specs"][0])["reproduced"])
            if mode == "deadline":
                self.assertIn("absolute_session_deadline", report["validity_reasons"])
            if mode in ("setup", "private_id"):
                self.assertNotIn("private_setup_marker_195", report["validity_reasons"])
                for path in safe_root.rglob("*"):
                    if path.is_file():
                        self.assertNotIn(b"private_setup_marker_195", path.read_bytes())
                        self.assertNotIn(b"private:request:195", path.read_bytes())
            OUTPUTS["r195_closed_sanitized_" + mode] = {
                "report": report,
                "archive_state": safe["archive"],
            }


class Round196Tests(FixtureCase):
    rewrite = Round194Tests.rewrite
    retain = Round193Tests.retain

    def test_gateway_client_usage_contract(self):
        usage = json.loads(USAGE.split(b"data: ", 1)[1])

        def changed_usage(**updates):
            chunk = copy.deepcopy(usage)
            chunk["usage"].update(updates)
            return b"data: " + json.dumps(chunk).encode() + b"\n\n"

        for name, data, error in (
            ("valid", CONTENT + FINISH + USAGE + DONE, None),
            ("missing", CONTENT + FINISH + DONE, "done_without_valid_usage"),
            ("early", CONTENT + USAGE + FINISH + DONE, "invalid_sse_usage_order"),
            ("duplicate", CONTENT + FINISH + USAGE + USAGE + DONE, "invalid_sse_usage_order"),
            ("late", CONTENT + FINISH + DONE + USAGE, "invalid_sse_chunk"),
            ("no_finish", CONTENT + USAGE + DONE, "invalid_sse_usage_order"),
            (
                "source",
                CONTENT + FINISH + changed_usage(count_source="estimated") + DONE,
                "invalid_sse_usage",
            ),
            (
                "total",
                CONTENT + FINISH + changed_usage(total_tokens=999) + DONE,
                "invalid_sse_usage",
            ),
            (
                "negative",
                CONTENT + FINISH + changed_usage(prompt_tokens=-1, total_tokens=0) + DONE,
                "invalid_sse_usage",
            ),
            (
                "boolean",
                CONTENT + FINISH + changed_usage(completion_tokens=True) + DONE,
                "invalid_sse_usage",
            ),
            (
                "float",
                CONTENT + FINISH + changed_usage(prompt_tokens=4.0) + DONE,
                "invalid_sse_usage",
            ),
            (
                "null_count",
                CONTENT + FINISH + changed_usage(prompt_tokens=None) + DONE,
                "invalid_sse_usage",
            ),
            (
                "null_usage",
                CONTENT + FINISH + b'data: {"choices":[],"usage":null}\n\n' + DONE,
                "invalid_sse_usage",
            ),
            ("empty", CONTENT + FINISH + b'data: {"choices":[]}\n\n' + DONE, "invalid_sse_choices"),
            (
                "multi",
                CONTENT + FINISH + b'data: {"choices":[{},{}]}\n\n' + DONE,
                "invalid_sse_choices",
            ),
            (
                "mixed_usage",
                CONTENT + FINISH + b'data: {"choices":[{}],"usage":{}}\n\n' + DONE,
                "invalid_sse_usage_order",
            ),
            ("interrupted", GATEWAY_STREAMS["interrupted"].encode(), "invalid_sse_chunk"),
        ):
            with self.subTest(name=name):
                rows, offer = Records().request(data=data)
                report = RequestJoin(self.joined(rows), [offer], 1000).report()
                stream = report["cohorts"][0]["stream"]
                self.assertEqual(
                    report["cohorts"][0]["outcome"], "complete" if error is None else "failed"
                )
                if error:
                    self.assertIn(error, stream["errors"])
                else:
                    self.assertEqual(stream["errors"], [])
                raw = Archive.create(
                    self.root / ("usage-raw-" + name), {"registration_id": REGISTRATION_ID}
                )
                writer = StreamingArchiveWriter(raw.root)
                for row in rows:
                    writer.append("raw/" + row["source_kind"] + ".jsonl", row)
                writer.close_raw()
                raw.seal()
                key = b"round196-usage-sanitizer-key-32!!"
                safe, _ = sanitized_sources(raw.root, self.root / ("usage-safe-" + name), key=key)
                safe_rows = [
                    row
                    for path in (safe.root / "raw").glob("*.jsonl")
                    for row in inspect_segment(path)[1]
                ]
                safe_offer = Sanitizer(key).value(offer)
                safe_offer["gateway_uid"] = offer["gateway_uid"]
                after = RequestJoin(self.joined(safe_rows), [safe_offer], 1000).report()
                self.assertEqual(report["denominators"], after["denominators"])
                self.assertEqual(stream["errors"], after["cohorts"][0]["stream"]["errors"])
                OUTPUTS["r196_usage_" + name] = {
                    "report": {"raw": report, "sanitized": after},
                    "archive_state": raw.seal(),
                    "sanitized_archive": safe.seal(),
                }

    def test_campaign_sanitized_gateway_and_five_regressions(self):
        for mode in (
            "usage",
            "stream_interrupted",
            "malformed_json",
            "duplicate_done",
            "duplicate_fragment",
            "rotation",
        ):
            with self.subTest(mode=mode):
                campaign, _ = CampaignTests.campaign(self, name=mode)
                path = campaign.root / "raw/client.jsonl"
                rows = inspect_segment(path)[1]
                position = next(i for i, row in enumerate(rows) if row["payload"]["event"] == "sse")
                original = rows[position]
                if mode == "stream_interrupted":
                    original["payload"]["chunk_hex"] = GATEWAY_STREAMS["interrupted"].encode().hex()
                elif mode == "malformed_json":
                    original["payload"]["chunk_hex"] = (
                        CONTENT
                        + b'data: {"private_json_marker":BROKEN}\n\n'
                        + FINISH
                        + USAGE
                        + DONE
                    ).hex()
                elif mode == "duplicate_done":
                    rows.insert(position + 1, copy.deepcopy(original))
                elif mode in ("duplicate_fragment", "rotation"):
                    data = bytes.fromhex(original["payload"]["chunk_hex"])
                    original["payload"]["chunk_hex"] = data[:17].hex()
                    tail = copy.deepcopy(original)
                    tail["record_id"] += "-tail"
                    tail["payload"]["chunk_hex"] = data[17:].hex()
                    rows.insert(position + 1, tail)
                    # Reserve a new source sequence without changing arrival times.
                    for index, row in enumerate(rows):
                        row["source_seq"] = index
                    if mode == "duplicate_fragment":
                        rows.insert(position + 1, copy.deepcopy(original))
                if mode == "rotation":
                    # Filename order reverses the two fragments; also cover 2 vs 10.
                    path.write_bytes(b"".join(encode(row) for row in rows[: position + 1]))
                    (path.parent / "client-2.jsonl").write_bytes(encode(rows[position + 1]))
                    (path.parent / "client-10.jsonl").write_bytes(
                        b"".join(encode(row) for row in rows[position + 2 :])
                    )
                else:
                    path.write_bytes(b"".join(encode(row) for row in rows))
                before = campaign.report()
                campaign.materialize()
                exported = sanitized_campaign(
                    campaign.root,
                    self.root / ("safe-" + mode),
                    [campaign.spec],
                    key=b"round196-gateway-campaign-key-32!!",
                )
                safe_root = self.root / ("safe-" + mode)
                after = OfflineCampaign(safe_root, exported["specs"][0]).report()
                self.assertEqual(
                    before["requests"]["denominators"], after["requests"]["denominators"]
                )
                self.assertEqual(
                    [c["stream"]["errors"] for c in before["requests"]["cohorts"]],
                    [c["stream"]["errors"] for c in after["requests"]["cohorts"]],
                )
                self.assertEqual(before["stage_eligibility"], after["stage_eligibility"])
                self.assertTrue(reproduce(safe_root, attempt_index=1)["reproduced"])
                self.assertEqual(
                    before["requests"]["denominators"]["complete"],
                    3 if mode in ("stream_interrupted", "malformed_json") else 4,
                )
                if mode.startswith("duplicate"):
                    self.assertEqual(
                        before["source_join"]["identical_duplicates"],
                        after["source_join"]["identical_duplicates"],
                    )
                    self.assertFalse(after["archive_level_errors"])
                for item in safe_root.rglob("*"):
                    if item.is_file():
                        data = item.read_bytes()
                        self.assertNotIn(b"private_json_marker", data)
                        self.assertNotIn(b"hello".hex().encode(), data)
                        self.assertNotIn(
                            GATEWAY_STREAMS["complete_request_id"].encode().hex().encode(), data
                        )
                OUTPUTS["r196_campaign_" + mode] = {
                    "report": {"raw": before, "sanitized": after},
                    "archive_state": exported["archive"],
                    "summaries": exported["summaries"],
                }

    def test_stage4_eligibility_complete_never_usable_and_own_failures(self):
        for mode in ("complete_recovery", "never_usable", "missing_health", "cache_unknown"):
            campaign, _ = complete_campaign_fixture(
                self.root / mode,
                end=901000 if mode == "complete_recovery" else 931000,
                recover=True,
            )

            def transform(row, mode=mode):
                p = row["payload"]
                if (
                    mode == "never_usable"
                    and row["source_kind"] == "client"
                    and p["event"] == "sse"
                ):
                    if row["observed_mono_ns"] // 1000000 > 600500:
                        p["chunk_hex"] = GATEWAY_STREAMS["interrupted"].encode().hex()
                elif (
                    mode == "missing_health"
                    and row["source_kind"] == "gateway"
                    and p["event"] == "health"
                ):
                    row["error"] = "poll_timeout"
                elif (
                    mode == "cache_unknown"
                    and row["source_kind"] == "kubernetes"
                    and p["event"] == "startup"
                    and p["pod_uid"] == "new0"
                ):
                    p["model_cache_state"] = "unknown"
                return row

            self.rewrite(campaign, transform)
            report = campaign.report()
            self.assertIs(
                report["stage_eligibility"]["4"], mode in ("complete_recovery", "never_usable")
            )
            self.assertIs(
                report["stages"]["stage4"]["replacement_usable_by_deadline"],
                False if mode == "never_usable" else None if mode == "missing_health" else True,
            )
            self.assertIs(
                report["measurement_valid"], mode in ("complete_recovery", "never_usable")
            )
            if mode == "complete_recovery":
                self.assertEqual(report["requests"]["denominators"]["complete"], 1761)
                self.assertIsNotNone(report["recovery"]["recovery"])
            self.retain(
                "r196_stage4_" + mode,
                campaign,
                report,
                stage_eligibility=report["stage_eligibility"],
                denominators=report["requests"]["denominators"],
                recovery=report["recovery"],
            )


class Round197Tests(FixtureCase):
    KEY = b"round197-differential-sanitizer-key"

    @staticmethod
    def split(rows, position, cut, *, later_ms=None, uncertainty=0):
        head = rows[position]
        data = bytes.fromhex(head["payload"]["chunk_hex"])
        head["payload"]["chunk_hex"] = data[:cut].hex()
        tail = copy.deepcopy(head)
        tail["record_id"] += "-tail"
        tail["payload"]["chunk_hex"] = data[cut:].hex()
        tail["uncertainty_ns"] = uncertainty
        if later_ms is not None:
            tail["source_time"]["value"] = later_ms
            for field in ("observed_mono_ns", "capture_start_mono_ns", "capture_end_mono_ns"):
                tail[field] = later_ms * 1_000_000
        rows.insert(position + 1, tail)
        Round197Tests.sequence(rows)
        return tail

    @staticmethod
    def sequence(rows):
        sequences = {}
        for row in rows:
            key = (row["source_kind"], row["source_identity"], row["source_generation"])
            row["source_seq"] = sequences.get(key, 0)
            sequences[key] = row["source_seq"] + 1

    @staticmethod
    def request_facts(report):
        # Same byte-metadata exclusions as the campaign export contract.
        return {
            **report,
            "cohorts": [
                {
                    **cohort,
                    "stream": {k: v for k, v in cohort["stream"].items() if k != "pending_bytes"},
                }
                for cohort in report["cohorts"]
            ],
        }

    def parity(self, name, rows, offer, *, attempt=None):
        raw = Archive.create(self.root / ("raw-" + name), {"registration_id": REGISTRATION_ID})
        writer = StreamingArchiveWriter(raw.root)
        for row in rows:
            writer.append("raw/" + row["source_kind"] + ".jsonl", row)
        writer.close_raw()
        state = raw.seal()
        safe, _ = sanitized_sources(raw.root, self.root / ("safe-" + name), key=self.KEY)

        def read(root):
            return [
                row
                for path in sorted((root / "raw").glob("*.jsonl"))
                for row in inspect_segment(path, source_errors=True)[1]
            ]

        originals, redacted = read(raw.root), read(safe.root)

        def view(rows):
            return (
                rows
                if attempt is None
                else [r for r in rows if r["attempt_id"] in (attempt, "setup")]
            )

        before_join, after_join = SourceJoin(view(originals)), SourceJoin(view(redacted))
        sanitizer = Sanitizer(self.KEY)
        safe_offer = sanitizer.value(offer)
        safe_offer["gateway_uid"] = offer["gateway_uid"]
        before = RequestJoin(before_join.rows, [offer], 1000).report()
        after = RequestJoin(after_join.rows, [safe_offer], 1000).report()
        identities = {}
        for original, safe_row in zip(originals, redacted, strict=True):
            for field in ("source_identity", "source_generation", "record_id"):
                identities[original[field]] = safe_row[field]
            for field in (
                "request_id",
                "gateway_uid",
                "backend_uid",
                "reservation_id",
                "prefix_id",
            ):
                if original["payload"].get(field):
                    identities[original["payload"][field]] = safe_row["payload"][field]

        def mapped(value):
            if isinstance(value, dict):
                return {identities.get(k, k): mapped(v) for k, v in value.items()}
            if isinstance(value, list):
                return [mapped(v) for v in value]
            if isinstance(value, str):
                return identities.get(
                    value, ":".join(identities.get(p, p) for p in value.split(":"))
                )
            return value

        self.assertEqual(mapped(self.request_facts(before)), self.request_facts(after))
        self.assertEqual(
            sorted(e["reason"] for e in before_join.errors),
            sorted(e["reason"] for e in after_join.errors),
        )
        self.assertEqual(before_join.duplicates, after_join.duplicates)
        for original, safe_row in zip(originals, redacted, strict=True):
            if "chunk_hex" in original["payload"] and not isinstance(
                original["payload"]["chunk_hex"], str
            ):
                self.assertIs(
                    type(safe_row["payload"]["chunk_hex"]), type(original["payload"]["chunk_hex"])
                )
        return before, after, state, safe.seal()

    def test_request_source_order_with_varying_uncertainty(self):
        for name, cut, later_ms, uncertainty in (
            ("equal", 17, 20, 0),
            ("same_ms_1ns", 17, 20, 1),
            ("next_ms_2ms", 17, 21, 2_000_000),
            ("frame_boundary", len(CONTENT), 20, 1),
        ):
            with self.subTest(name=name):
                rows, offer = Records().request()
                position = next(i for i, r in enumerate(rows) if r["payload"]["event"] == "sse")
                self.split(rows, position, cut, later_ms=later_ms, uncertainty=uncertainty)
                before, after, state, safe_state = self.parity(name, rows, offer)
                self.assertEqual(before["cohorts"][0]["outcome"], "complete")
                self.assertEqual(before["cohorts"][0]["stream"]["errors"], [])
                self.assertEqual(
                    before["stage1_scope"]["false_completion_after_content"]["count"], 0
                )
                OUTPUTS["r197_request_" + name] = {
                    "report": {"raw": before, "sanitized": after},
                    "archive_state": state,
                    "sanitized_archive": safe_state,
                }

    def test_request_rejects_multiple_sse_sources(self):
        for field in ("source_identity", "source_generation"):
            with self.subTest(field=field):
                rows, offer = Records().request()
                position = next(i for i, r in enumerate(rows) if r["payload"]["event"] == "sse")
                tail = self.split(rows, position, len(CONTENT))
                tail[field] = "private-other-client"
                self.sequence(rows)
                before, after, state, safe_state = self.parity(field, rows, offer)
                self.assertEqual(before["cohorts"][0]["outcome"], "failed")
                self.assertEqual(before["cohorts"][0]["stream"]["errors"], ["multiple_sse_sources"])
                OUTPUTS["r197_multiple_" + field] = {
                    "report": {"raw": before, "sanitized": after},
                    "archive_state": state,
                    "sanitized_archive": safe_state,
                }

    def test_campaign_dropped_rows_and_uncertainty(self):
        for mode in (
            "uncertainty_swap",
            "null_hex",
            "schema_mid",
            "conflict_fragment",
            "null_hex_reason",
            "int_hex",
            "conflict_collapse",
        ):
            with self.subTest(mode=mode):
                campaign, _ = CampaignTests.campaign(self, name=mode)
                path = campaign.root / "raw/client.jsonl"
                rows = inspect_segment(path)[1]
                position = next(i for i, r in enumerate(rows) if r["payload"]["event"] == "sse")
                original = rows[position]
                if mode in ("uncertainty_swap", "schema_mid", "conflict_fragment"):
                    self.split(
                        rows, position, 17, uncertainty=1 if mode == "uncertainty_swap" else 0
                    )
                if mode == "schema_mid":
                    original["payload"]["private_unregistered_field"] = "private-schema-value"
                elif mode in ("null_hex", "null_hex_reason", "int_hex"):
                    dropped = copy.deepcopy(original)
                    dropped["record_id"] += "-bad"
                    dropped["payload"]["chunk_hex"] = 42 if mode == "int_hex" else None
                    if mode == "null_hex_reason":
                        dropped["payload"]["field_reasons"]["chunk_hex"] = "capture_unavailable"
                    rows.insert(position + 1, dropped)
                    self.sequence(rows)
                elif mode in ("conflict_fragment", "conflict_collapse"):
                    conflict = copy.deepcopy(original)
                    conflict["payload"]["chunk_hex"] = b"private-conflicting-fragment".hex()
                    rows.insert(position + 1, conflict)
                path.write_bytes(b"".join(encode(row) for row in rows))
                before = campaign.report()
                campaign.materialize()
                safe_root = self.root / ("safe-" + mode)
                exported = sanitized_campaign(
                    campaign.root, safe_root, [campaign.spec], key=self.KEY
                )
                after = OfflineCampaign(safe_root, exported["specs"][0]).report()
                # Export already compares all mapped semantic facts, not just counts.
                self.assertEqual(
                    sanitized_report_facts(before)["requests"]["denominators"],
                    sanitized_report_facts(after)["requests"]["denominators"],
                )
                self.assertTrue(reproduce(campaign.root, attempt_index=1)["reproduced"])
                self.assertTrue(reproduce(safe_root, attempt_index=1)["reproduced"])
                self.assertEqual(
                    before["requests"]["denominators"]["complete"],
                    3 if mode in ("null_hex_reason", "int_hex") else 4,
                )
                if mode in ("null_hex", "schema_mid"):
                    self.assertTrue(
                        any(
                            e["reason"] == "schema_violation"
                            for e in before["source_join"]["validity_reasons"]
                        )
                    )
                for item in safe_root.rglob("*"):
                    if item.is_file():
                        data = item.read_bytes()
                        self.assertNotIn(b"private-schema-value", data)
                        self.assertNotIn(b"private-conflicting-fragment".hex().encode(), data)
                OUTPUTS["r197_campaign_" + mode] = {
                    "report": {"raw": before, "sanitized": after},
                    "archive_state": exported["archive"],
                    "summaries": exported["summaries"],
                }

    def test_sanitizer_first_valid_copy_and_non_sse_key(self):
        for mode in ("invalid_first", "non_sse_first"):
            with self.subTest(mode=mode):
                rows, offer = Records().request()
                position = next(i for i, r in enumerate(rows) if r["payload"]["event"] == "sse")
                self.split(rows, position, 17)
                head = rows[position]
                if mode == "invalid_first":
                    invalid = copy.deepcopy(head)
                    invalid["payload"]["private_unknown_field"] = "private-value"
                    rows.insert(position, invalid)
                else:
                    # A non-SSE row owns this key. Its conflicting SSE copy must
                    # not enter redaction state even with an earlier source_seq.
                    owner = rows[0]
                    conflict = copy.deepcopy(head)
                    conflict.update(
                        source_identity=owner["source_identity"],
                        source_generation=owner["source_generation"],
                        record_id=owner["record_id"],
                        source_seq=0,
                    )
                    rows.insert(position + 1, conflict)
                before, after, state, safe_state = self.parity(mode, rows, offer)
                self.assertEqual(before["cohorts"][0]["outcome"], "complete")
                OUTPUTS["r197_first_copy_" + mode] = {
                    "report": {"raw": before, "sanitized": after},
                    "archive_state": state,
                    "sanitized_archive": safe_state,
                }

    def test_seeded_bounded_raw_sanitized_differential(self):
        seed, cases = 197253254, 192
        rng = random.Random(seed)
        results = []
        variants = (
            CONTENT + FINISH + USAGE + DONE,
            CONTENT + FINISH + DONE,
            GATEWAY_STREAMS["interrupted"].encode(),
            CONTENT + b"data: {private-invalid}\n\n" + FINISH + USAGE + DONE,
            CONTENT + FINISH + USAGE + DONE + DONE,
            CONTENT + FINISH + USAGE + DONE + b"private-tail",
            CONTENT + b'data: {"choices":[]}\n\n' + FINISH + USAGE + DONE,
            CONTENT + FINISH + b'data: {"choices":[],"usage":null}\n\n' + DONE,
            b": comment\n\n" + CONTENT + FINISH + USAGE + DONE,
            (CONTENT + FINISH + USAGE + DONE).replace(b"\n", b"\r\n"),
            CONTENT + b'data: {"choices":[{"index":true,"delta":{}}]}\n\n' + FINISH + USAGE + DONE,
            CONTENT + b"data: \xff\n\n" + FINISH + USAGE + DONE,
        )
        for index in range(cases):
            with self.subTest(seed=seed, case=index):
                data = variants[index % len(variants)]
                rows, offer = Records().request(data=data)
                position = next(i for i, r in enumerate(rows) if r["payload"]["event"] == "sse")
                template = rows.pop(position)
                cuts = sorted(rng.sample(range(1, len(data)), rng.randrange(6)))
                boundaries = [0, *cuts, len(data)]
                fragments = []
                for part, (start, end) in enumerate(zip(boundaries, boundaries[1:], strict=False)):
                    row = copy.deepcopy(template)
                    row["record_id"] += f"-{part}"
                    row["payload"]["chunk_hex"] = data[start:end].hex()
                    row["source_time"]["value"] = 20 + part
                    row["observed_mono_ns"] = (20 + part) * 1_000_000
                    row["uncertainty_ns"] = rng.choice((0, 1, 999_999, 2_000_000, 4_000_000))
                    fragments.append(row)
                rows[position:position] = fragments
                self.sequence(rows)
                # Include ignored rows, exact copies and conflicts at random positions.
                for mutation in range(rng.randrange(1, 4)):
                    original = rng.choice(fragments)
                    extra = copy.deepcopy(original)
                    kind = (index + mutation) % 8
                    if kind == 0:
                        pass  # exact retransmission
                    elif kind == 1:
                        extra["payload"]["chunk_hex"] = b"private-conflict".hex()
                    else:
                        extra["record_id"] += f"-dropped-{mutation}"
                        extra["source_seq"] += 100 + mutation
                        if kind == 2:
                            extra["payload"]["chunk_hex"] = None
                        elif kind == 3:
                            extra["payload"]["private_schema_field"] = "private-value"
                        else:
                            extra["payload"]["chunk_hex"] = {4: 42, 5: [], 6: {}, 7: None}[kind]
                            if kind == 7:
                                extra["payload"]["field_reasons"]["chunk_hex"] = "unavailable"
                    # A conflict must follow its first copy; archive arrival order is authoritative.
                    where = next(i for i, r in enumerate(rows) if r is original)
                    rows.insert(rng.randrange(where + 1, len(rows) + 1), extra)
                before, after, state, safe_state = self.parity(str(index), rows, offer)
                results.append(
                    {
                        "case": index,
                        "input_sha256": sha(b"".join(encode(r) for r in rows)),
                        "row_count": len(rows),
                        "splits": len(fragments),
                        "raw": self.request_facts(before),
                        "sanitized": self.request_facts(after),
                        "raw_verified": state["verified"],
                        "sanitized_verified": safe_state["verified"],
                    }
                )
        self.capture(
            "r197_seeded_differential", [], {"seed": seed, "cases": cases, "results": results}
        )
        Round198Tests.seeded_extension(self)


class Round198Tests(FixtureCase):
    KEY = Round197Tests.KEY
    split = staticmethod(Round197Tests.split)
    sequence = staticmethod(Round197Tests.sequence)
    request_facts = staticmethod(Round197Tests.request_facts)
    parity = Round197Tests.parity

    def pair(self, name, rows, offer, *, attempt=None):
        before, after, state, safe_state = self.parity(name, rows, offer, attempt=attempt)
        OUTPUTS["r198_" + name] = {
            "report": {"raw": before, "sanitized": after},
            "archive_state": state,
            "sanitized_archive": safe_state,
        }
        return before

    @staticmethod
    def fragments(parts):
        rows, offer = Records().request(data=b"")
        position = next(i for i, row in enumerate(rows) if row["payload"]["event"] == "sse")
        template = rows.pop(position)
        for part, data in reversed(list(enumerate(parts))):
            row = copy.deepcopy(template)
            row["record_id"] += f"-part{part}"
            row["payload"]["chunk_hex"] = data.hex()
            rows.insert(position, row)
        Round197Tests.sequence(rows)
        return rows, offer

    def test_empty_string_payloads_remain_dropped(self):
        self.assertEqual(Sanitizer(self.KEY).value(""), "")
        for field in ("request_id", "field_reason"):
            for shape in ("extra", "head"):
                with self.subTest(field=field, shape=shape):
                    rows, offer = Records().request()
                    position = next(i for i, r in enumerate(rows) if r["payload"]["event"] == "sse")
                    if shape == "head":
                        self.split(rows, position, 17)
                        bad = rows[position]
                    else:
                        bad = copy.deepcopy(rows[position])
                        bad["record_id"] += "-empty"
                        rows.insert(position + 1, bad)
                    if field == "request_id":
                        bad["payload"][field] = ""
                    else:
                        bad["payload"]["chunk_hex"] = None
                        bad["payload"]["field_reasons"]["chunk_hex"] = ""
                    self.sequence(rows)
                    self.pair("empty_" + field + "_" + shape, rows, offer)

    def test_payload_validation_drift_refuses_with_fixed_code(self):
        original = Sanitizer._finish_row
        for direction in ("valid_to_invalid", "invalid_to_valid"):
            rows, offer = Records().request()
            if direction == "invalid_to_valid":
                rows[0]["payload"]["request_id"] = ""

            def drift(sanitizer, row, direction=direction):
                row = original(sanitizer, row)
                if row["payload"]["event"] == "offer":
                    row["payload"]["request_id"] = (
                        "" if direction == "valid_to_invalid" else "id-fixed"
                    )
                return row

            with patch.object(Sanitizer, "_finish_row", drift):
                with self.assertRaisesRegex(
                    IntegrityError, "^sanitized_payload_validation_mismatch$"
                ):
                    self.parity("validation-" + direction, rows, offer)
            self.capture(
                "r198_validation_" + direction,
                rows,
                {"refusal": "sanitized_payload_validation_mismatch", "direction": direction},
            )

    def test_per_attempt_first_copy_and_stream_state(self):
        for mode in (
            "other_first",
            "other_after",
            "split",
            "boundary",
            "setup_split",
            "setup_complete",
        ):
            rows, offer = Records().request()
            position = next(i for i, r in enumerate(rows) if r["payload"]["event"] == "sse")
            if mode.startswith("other_"):
                other = copy.deepcopy(rows[position])
                other["attempt_id"] = 2
                rows.insert(position if mode == "other_first" else position + 1, other)
            elif mode == "setup_complete":
                for row in rows:
                    row["attempt_id"] = "setup"
            else:
                tail = self.split(rows, position, len(CONTENT) if mode == "boundary" else 17)
                tail["attempt_id"] = 2 if mode != "setup_split" else 1
                if mode == "setup_split":
                    rows[position]["attempt_id"] = "setup"
            for attempt in (1, 2, 3):
                name = f"attempt_{mode}_{attempt}"
                with self.subTest(mode=mode, attempt=attempt):
                    if mode == "setup_split":
                        with self.assertRaisesRegex(
                            IntegrityError, "^sanitized_setup_view_mismatch$"
                        ):
                            self.parity(name, rows, offer, attempt=attempt)
                        self.capture(
                            "r198_" + name, rows, {"refusal": "sanitized_setup_view_mismatch"}
                        )
                    else:
                        self.pair(name, rows, offer, attempt=attempt)

    def test_post_done_pending_tail_probes(self):
        valid = CONTENT + FINISH + USAGE + DONE
        probes = {
            "second_done_split": (
                [valid + b"data: [DONE]", b"\n\n"],
                "done_without_unique_valid_finish",
            ),
            "invalid_json_split": ([valid + b'data: {"choices":[]', b"\n\n"], "invalid_sse_json"),
            "json_vt": ([valid + b"data: 0", b"\x0b\n\n"], "invalid_sse_json"),
            "json_nonws_ws": ([valid + b'data: {"x":1}', b"zz", b"\n\n"], "invalid_sse_chunk"),
            "done_crlf": (
                [valid + b"data: [DONE]\r", b"\n\r\n"],
                "done_without_unique_valid_finish",
            ),
            "no_data": ([valid + b": private-tail\r", b"\n\r\n"], None),
            "json_multiline": ([valid + b"data: [\ndata: 1]\n", b"\n"], "invalid_sse_chunk"),
        }
        for name, (parts, error) in probes.items():
            with self.subTest(name=name):
                rows, offer = self.fragments(parts)
                before = self.pair("tail_" + name, rows, offer)
                stream = before["cohorts"][0]["stream"]
                self.assertEqual(stream["events"], 6 if error else 5)
                if error:
                    self.assertIn(error, stream["errors"])
                else:
                    self.assertEqual(stream["errors"], [])

    def test_campaign_remaining_reproductions_export_and_reproduce(self):
        for mode in (
            "empty_reason",
            "empty_request",
            "second_done_split",
            "other_first",
            "other_after",
            "split",
        ):
            with self.subTest(mode=mode):
                campaign, _ = CampaignTests.campaign(self, name=mode)
                path = campaign.root / "raw/client.jsonl"
                rows = inspect_segment(path)[1]
                position = next(i for i, r in enumerate(rows) if r["payload"]["event"] == "sse")
                specs = [campaign.spec]
                if mode in ("other_first", "other_after", "split"):
                    # Include a third independent attempt; a stamping defect in
                    # either earlier owner must not prevent its export.
                    for attempt in (2, 3):
                        specs.append(
                            {
                                **campaign.spec,
                                "attempt_index": attempt,
                                "target_slot": (0, 1, 0)[attempt - 1],
                            }
                        )
                        for source in (campaign.root / "raw").glob("*.jsonl"):
                            originals = inspect_segment(source)[1]
                            with source.open("ab") as stream:
                                for row in originals:
                                    if row["attempt_id"] != 1:
                                        continue
                                    other = copy.deepcopy(row)
                                    other.update(
                                        attempt_id=attempt,
                                        record_id=row["record_id"] + f"-a{attempt}",
                                        source_identity=row["source_identity"] + f"-a{attempt}",
                                    )
                                    stream.write(encode(other))
                    rows = inspect_segment(path)[1]
                original = rows[position]
                if mode in ("empty_reason", "empty_request"):
                    bad = copy.deepcopy(original)
                    bad["record_id"] += "-empty"
                    if mode == "empty_reason":
                        bad["payload"]["chunk_hex"] = None
                        bad["payload"]["field_reasons"]["chunk_hex"] = ""
                    else:
                        bad["payload"]["request_id"] = ""
                    rows.insert(position + 1, bad)
                    self.sequence(rows)
                elif mode == "second_done_split":
                    original["payload"]["chunk_hex"] = (
                        bytes.fromhex(original["payload"]["chunk_hex"]) + b"data: [DONE]"
                    ).hex()
                    ws = copy.deepcopy(original)
                    ws["record_id"] += "-ws"
                    ws["payload"]["chunk_hex"] = b"\n\n".hex()
                    rows.insert(position + 1, ws)
                    self.sequence(rows)
                elif mode == "split":
                    tail = self.split(rows, position, 17)
                    tail["attempt_id"] = 2
                else:
                    other = copy.deepcopy(original)
                    other["attempt_id"] = 2
                    rows.insert(position if mode == "other_first" else position + 1, other)
                path.write_bytes(b"".join(encode(row) for row in rows))
                before = [OfflineCampaign(campaign.root, spec).report() for spec in specs]
                materialize_bundle(campaign.root, specs)
                safe_root = self.root / ("export-" + mode)
                exported = sanitized_campaign(campaign.root, safe_root, specs, key=self.KEY)
                after = [OfflineCampaign(safe_root, spec).report() for spec in exported["specs"]]
                for raw_report, safe_report, spec in zip(before, after, specs, strict=True):
                    self.assertEqual(
                        raw_report["requests"]["denominators"],
                        safe_report["requests"]["denominators"],
                    )
                    self.assertTrue(
                        reproduce(campaign.root, attempt_index=spec["attempt_index"])["reproduced"]
                    )
                    self.assertTrue(
                        reproduce(safe_root, attempt_index=spec["attempt_index"])["reproduced"]
                    )
                if len(specs) == 3:
                    self.assertEqual(before[2]["requests"]["denominators"]["complete"], 4)
                OUTPUTS["r198_campaign_" + mode] = {
                    "report": {"raw": before, "sanitized": after},
                    "archive_state": exported["archive"],
                    "summaries": exported["summaries"],
                }

    def seeded_extension(self):
        seed, rng, results = 198254255, random.Random(198254255), []
        # Exercise all split offsets, not just frame-aligned or random cuts.
        tails = (
            b"data: [DONE]",
            b'data: {"private":1}',
            b'data: {"choices":[]',
            b"data: 0",
            b"data: [DONE]\r",
            b"data: 0\n",
            b": private\r",
            b"data: [\ndata: 1]\r",
            b"data: 0\n: private",
            b"data: \xff",
        )
        whites = (b" ", b"\t", b"\r", b"\n", b"\x0b", b"\x0c")
        valid = CONTENT + FINISH + USAGE + DONE
        for tail in tails:
            for offset in range(len(tail) + 1):
                whitespace = list(whites)
                rng.shuffle(whitespace)
                parts = [valid + tail[:offset], tail[offset:]] + whitespace + [b"\n\n"]
                rows, offer = Round198Tests.fragments(parts)
                name = f"extended-tail-{tails.index(tail)}-{offset}"
                with self.subTest(seed=seed, tail=tail, offset=offset):
                    before, after, state, safe = self.parity(name, rows, offer)
                    results.append(
                        {
                            "case": name,
                            "offset": offset,
                            "tail_hex": tail.hex(),
                            "input_sha256": sha(b"".join(encode(r) for r in rows)),
                            "raw": self.request_facts(before),
                            "sanitized": self.request_facts(after),
                            "raw_verified": state["verified"],
                            "sanitized_verified": safe["verified"],
                        }
                    )
        for index in range(48):
            rows, offer = Records().request()
            position = next(i for i, r in enumerate(rows) if r["payload"]["event"] == "sse")
            tail = self.split(
                rows,
                position,
                rng.randrange(1, len(bytes.fromhex(rows[position]["payload"]["chunk_hex"]))),
            )
            tail["attempt_id"] = 2
            head = rows[position]
            bad = copy.deepcopy(head)
            bad["record_id"] += "-bad"
            bad["attempt_id"] = rng.choice((1, 2))
            if index % 2:
                bad["payload"]["request_id"] = ""
            else:
                bad["payload"]["chunk_hex"] = None
                bad["payload"]["field_reasons"]["chunk_hex"] = ""
            rows.insert(rng.randrange(len(rows) + 1), bad)
            if index % 3 == 0:
                other = copy.deepcopy(head)
                other["attempt_id"] = 2
                rows.insert(rng.randrange(len(rows) + 1), other)
            for attempt in (1, 2):
                name = f"extended-view-{index}-{attempt}"
                with self.subTest(seed=seed, case=index, attempt=attempt):
                    before, after, state, safe = self.parity(name, rows, offer, attempt=attempt)
                    results.append(
                        {
                            "case": name,
                            "attempt": attempt,
                            "input_sha256": sha(b"".join(encode(r) for r in rows)),
                            "raw": self.request_facts(before),
                            "sanitized": self.request_facts(after),
                            "raw_verified": state["verified"],
                            "sanitized_verified": safe["verified"],
                        }
                    )
        self.capture(
            "r198_seeded_differential",
            [],
            {"seed": seed, "cases": len(results), "results": results},
        )


class Round199Tests(FixtureCase):
    KEY = Round197Tests.KEY
    parity = Round197Tests.parity
    request_facts = staticmethod(Round197Tests.request_facts)
    sequence = staticmethod(Round197Tests.sequence)
    fragments = staticmethod(Round198Tests.fragments)
    pair = Round198Tests.pair

    @staticmethod
    def stream_report(parts):
        decoder = SSEDecoder()
        for part in parts:
            decoder.feed(part, [0, 0])
        return {k: v for k, v in decoder.report().items() if k != "pending_bytes"}

    def tail_case(self, name, parts):
        rows, offer = self.fragments(parts)
        sanitizer = Sanitizer(self.KEY)
        safe_parts = [
            bytes.fromhex(sanitizer.row(row, final_sse=i == len(parts) - 1)["payload"]["chunk_hex"])
            for i, row in enumerate(r for r in rows if r["payload"]["event"] == "sse")
        ]
        before, after = self.stream_report(parts), self.stream_report(safe_parts)
        if before != after:
            # Encoding guesses and latent CR boundaries can change parser class
            # under future whitespace. Such a stand-in must refuse export.
            with self.assertRaisesRegex(IntegrityError, "^sanitized_sse_report_mismatch$"):
                self.parity(name, rows, offer)
            decision = "sanitized_sse_report_mismatch"
        else:
            self.parity(name, rows, offer)
            decision = "equal"
        return {
            "parts_hex": [p.hex() for p in parts],
            "raw": before,
            "emitted": after,
            "decision": decision,
        }

    def test_post_done_cr_runs_and_encoding(self):
        valid = CONTENT + FINISH + USAGE + DONE
        probes = {
            "latent": [valid + b'data: {"x":1}\n\r\r\ndata: 7'],
            "latent_ws": [valid + b'data: {"x":1}\n\r\r\ndata: 7', b" ", b"\n\n"],
            "done_cr2_lf": [valid + b"data: [DONE]\r\r\n", b"\n"],
            "done_cr2": [valid + b"data: [DONE]\r\r\n"],
            "bracket": [valid + b"]\n\r\r\n"],
            "done_cr4": [valid + b"data: [DONE]\r\r\r\r", b"\n", b"\n", b"\n", b"\n\n"],
            "nul_space": [valid + b"data: 1\x00", b" \n\n"],
            "nul_lf": [valid + b"data: 1\x00", b"\n\n"],
        }
        results = {}
        for name, parts in probes.items():
            with self.subTest(name=name):
                result = self.tail_case("r199-tail-" + name, parts)
                self.assertEqual(
                    result["decision"],
                    "sanitized_sse_report_mismatch"
                    if name in ("nul_space", "latent_ws")
                    else "equal",
                )
                results[name] = result
        self.capture("r199_tail_probes", [], results)

    def test_seeded_tail_differential(self):
        seed, rng, results = 199255, random.Random(199255), []
        tokens = [
            b"data:",
            b"data: ",
            b"[DONE]",
            b"0",
            b"{",
            b"}",
            b'"a"',
            b"\r",
            b"\n",
            b" ",
            b"x",
            b": private-comment",
            b"[",
            b"]",
            b"\x00",
            b"\r\r\n",
            b"\n\r\r\n",
        ]
        whites = (b" ", b"\t", b"\r", b"\n", b"\x0b", b"\x0c")
        valid = CONTENT + FINISH + USAGE + DONE
        # Directed offsets guarantee the normalized-CR and encoding regressions
        # are reached; randomized rows then vary later normalization passes.
        tails = (b"]\n\r\r\n", b"data: [DONE]\r\r\n", b"data: 1\x00", b": private\n\r\r\n")
        inputs = []
        for tail in tails:
            for cut in range(len(tail) + 1):
                inputs.append([valid + tail[:cut], tail[cut:], b" \n\n"])
        for _ in range(384):
            tail = b"".join(rng.choice(tokens) for _ in range(rng.randint(1, 8)))
            cut = rng.randint(0, len(tail))
            parts = [valid + tail[:cut]]
            if cut < len(tail):
                parts.append(tail[cut:])
            for _ in range(rng.randint(0, 4)):
                parts.append(b"".join(rng.choice(whites) for _ in range(rng.randint(1, 3))))
            inputs.append(parts)
        for index, parts in enumerate(inputs):
            with self.subTest(seed=seed, case=index):
                results.append(self.tail_case(f"r199-fuzz-{index}", parts))
        self.capture(
            "r199_tail_differential", [], {"seed": seed, "cases": len(inputs), "results": results}
        )

    def test_stream_safety_net_attempt_views(self):
        finish = Sanitizer._finish_row
        rows, offer = Records().request()
        next(r for r in rows if r["payload"]["event"] == "sse")["payload"].pop("chunk_hex")
        before, _, _, _ = self.parity("missing-chunk-hex", rows, offer)
        self.assertEqual(before["cohorts"][0]["stream"]["errors"], ["invalid_chunk_hex"])
        for attempt in (1, 2, 3, "setup"):
            rows, offer = Records().request()
            for row in rows:
                row["attempt_id"] = attempt

            def drift(sanitizer, row):
                row = finish(sanitizer, row)
                if row["payload"]["event"] == "sse":
                    row["payload"]["chunk_hex"] = b"data: 0\n\n".hex()
                return row

            with self.subTest(attempt=attempt), patch.object(Sanitizer, "_finish_row", drift):
                with self.assertRaisesRegex(IntegrityError, "^sanitized_sse_report_mismatch$"):
                    self.parity(f"stream-drift-{attempt}", rows, offer)
        rows, offer = self.fragments([CONTENT, FINISH + USAGE + DONE])
        first = next(r["source_seq"] for r in rows if r["payload"]["event"] == "sse")
        held = {}

        def move_content(sanitizer, row):
            row = finish(sanitizer, row)
            if row["payload"]["event"] == "sse":
                if row["source_seq"] == first:
                    held[sanitizer] = row["payload"]["chunk_hex"]
                    row["payload"]["chunk_hex"] = ""
                else:
                    row["payload"]["chunk_hex"] = held.pop(sanitizer) + row["payload"]["chunk_hex"]
            return row

        with patch.object(Sanitizer, "_finish_row", move_content):
            with self.assertRaisesRegex(IntegrityError, "^sanitized_sse_report_mismatch$"):
                self.parity("moved-content", rows, offer)
        # Keep independent coverage of the later whole-campaign comparison:
        # terminal status drift leaves every stream decoder report unchanged.
        campaign, _ = CampaignTests.campaign(self, name="report-drift")
        campaign.materialize()

        def terminal_drift(sanitizer, row):
            row = finish(sanitizer, row)
            if row["source_kind"] == "client" and row["payload"]["event"] == "terminal":
                row["payload"]["http_status"] = 500
            return row

        with patch.object(Sanitizer, "_finish_row", terminal_drift):
            with self.assertRaisesRegex(IntegrityError, "^raw_sanitized_report_mismatch$"):
                sanitized_campaign(
                    campaign.root, self.root / "report-drift-safe", [campaign.spec], key=self.KEY
                )
        self.assertFalse((self.root / "report-drift-safe/SHA256SUMS").exists())
        self.capture(
            "r199_stream_guard",
            [],
            {
                "attempts": [1, 2, 3, "setup"],
                "refusal": "sanitized_sse_report_mismatch",
                "campaign_refusal": "raw_sanitized_report_mismatch",
                "first_content_read_drift_refusal": "sanitized_sse_report_mismatch",
                "missing_chunk_hex_error": "invalid_chunk_hex",
            },
        )

    def test_duplicate_equality_guard(self):
        finish = Sanitizer._finish_row
        for attempt in (1, 2, 3, "setup"):
            for field in ("observed_wall_utc", "collector_id"):
                rows, offer = Records().request()
                for row in rows:
                    row["attempt_id"] = attempt
                other = copy.deepcopy(rows[0])
                other[field] += "-private-different"
                rows.insert(1, other)

                def collapse(sanitizer, row, field=field):
                    row = finish(sanitizer, row)
                    row[field] = "fixed"
                    return row

                with (
                    self.subTest(attempt=attempt, field=field),
                    patch.object(Sanitizer, "_finish_row", collapse),
                ):
                    with self.assertRaisesRegex(
                        IntegrityError, "^sanitized_duplicate_equality_mismatch$"
                    ):
                        self.parity(f"duplicate-drift-{attempt}-{field}", rows, offer)
        self.capture(
            "r199_duplicate_guard",
            [],
            {
                "attempts": [1, 2, 3, "setup"],
                "fields": ["observed_wall_utc", "collector_id"],
                "refusal": "sanitized_duplicate_equality_mismatch",
            },
        )

    def test_seeded_duplicate_perturb_differential(self):
        seed, rng, results = 199256, random.Random(199256), []
        for index in range(96):
            rows, offer = Records().request()
            # Cycle every row and perturbation before seeded choices, retaining
            # exact retransmissions as well as both conflict arrival orders.
            position = index % len(rows) if index < 48 else rng.randrange(len(rows))
            original = rows[position]
            other = copy.deepcopy(original)
            field = ("exact", "observed_wall_utc", "collector_id", "payload")[index % 4]
            if field == "payload":
                if other["source_kind"] == "client":
                    other["payload"]["config_sha256"] = "b" * 64
                else:
                    other["payload"]["effective_b"] = (other["payload"].get("effective_b") or 0) + 1
            elif field != "exact":
                other[field] += "-private-perturbed"
            rows.insert(position + rng.randrange(2), other)
            attempt = (1, 2, 3, "setup")[(index // 4) % 4]
            for row in rows:
                row["attempt_id"] = attempt
            with self.subTest(seed=seed, case=index, field=field):
                before, after, state, safe = self.parity(
                    f"r199-duplicate-{index}",
                    rows,
                    offer,
                    attempt=1 if attempt == "setup" else attempt,
                )
                errors = SourceJoin(rows).errors
                self.assertNotIn("schema_violation", [e["reason"] for e in errors])
                self.assertEqual(
                    any(e["reason"] == "conflicting_duplicate" for e in errors), field != "exact"
                )
                results.append(
                    {
                        "case": index,
                        "event": original["payload"]["event"],
                        "field": field,
                        "attempt": attempt,
                        "raw": Round197Tests.request_facts(before),
                        "sanitized": Round197Tests.request_facts(after),
                        "raw_verified": state["verified"],
                        "sanitized_verified": safe["verified"],
                    }
                )
        self.capture(
            "r199_duplicate_differential",
            [],
            {"seed": seed, "cases": len(results), "results": results},
        )

    def test_campaign_r199_export_reproduce(self):
        for mode in ("control", "crcrlf_tail", "wall_conflict_terminal", "wall_conflict_offer"):
            with self.subTest(mode=mode):
                campaign, _ = CampaignTests.campaign(self, name=mode)
                path = campaign.root / "raw/client.jsonl"
                rows = inspect_segment(path)[1]
                if mode == "crcrlf_tail":
                    row = next(r for r in rows if r["payload"]["event"] == "sse")
                    row["payload"]["chunk_hex"] = (
                        bytes.fromhex(row["payload"]["chunk_hex"]) + b'data: {"x":1}\n\r\r\ndata: 7'
                    ).hex()
                elif mode.startswith("wall_conflict_"):
                    event = mode.removeprefix("wall_conflict_")
                    position = next(i for i, r in enumerate(rows) if r["payload"]["event"] == event)
                    other = copy.deepcopy(rows[position])
                    other["observed_wall_utc"] += "-private-different"
                    rows.insert(position + 1, other)
                path.write_bytes(b"".join(encode(r) for r in rows))
                before = campaign.report()
                campaign.materialize()
                safe_root = self.root / ("export-" + mode)
                exported = sanitized_campaign(
                    campaign.root, safe_root, [campaign.spec], key=self.KEY
                )
                after = OfflineCampaign(safe_root, exported["specs"][0]).report()
                self.assertEqual(
                    before["requests"]["denominators"], after["requests"]["denominators"]
                )
                self.assertEqual(before["validity_reasons"], after["validity_reasons"])
                if mode.startswith("wall_conflict_"):
                    self.assertIn("conflicting_duplicate", before["validity_reasons"])
                self.assertEqual(
                    before["requests"]["denominators"]["complete"],
                    3 if mode == "crcrlf_tail" else 4,
                )
                self.assertTrue(reproduce(campaign.root, attempt_index=1)["reproduced"])
                self.assertTrue(reproduce(safe_root, attempt_index=1)["reproduced"])
                OUTPUTS["r199_campaign_" + mode] = {
                    "report": {"raw": before, "sanitized": after},
                    "archive_state": exported["archive"],
                    "summaries": exported["summaries"],
                }


class Round200Tests(FixtureCase):
    KEY = Round197Tests.KEY
    parity = Round197Tests.parity
    request_facts = staticmethod(Round197Tests.request_facts)
    fragments = staticmethod(Round198Tests.fragments)
    stream_report = staticmethod(Round199Tests.stream_report)
    # Literal contract so the regression also runs against fb30a45's modules.
    DEPTH_LIMIT = 64

    @staticmethod
    def nested(depth, shape="array"):
        opens = [
            b'{"x":' if shape == "object" or (shape == "mixed" and i % 2) else b"["
            for i in range(depth)
        ]
        return (
            b"".join(opens)
            + b"0"
            + b"".join(b"}" if opening.startswith(b"{") else b"]" for opening in reversed(opens))
        )

    def check_parts(self, name, parts):
        rows, offer = self.fragments(parts)
        sanitizer = Sanitizer(self.KEY)
        emitted = [
            bytes.fromhex(sanitizer.row(row, final_sse=i == len(parts) - 1)["payload"]["chunk_hex"])
            for i, row in enumerate(r for r in rows if r["payload"]["event"] == "sse")
        ]
        raw, safe = self.stream_report(parts), self.stream_report(emitted)
        self.assertEqual(raw, safe)
        before, after, state, safe_state = self.parity(name, rows, offer)
        OUTPUTS[name] = {
            "report": {
                "decoder_raw": raw,
                "decoder_sanitized": safe,
                "raw": before,
                "sanitized": after,
            },
            "archive_state": state,
            "sanitized_archive": safe_state,
            "parts_hex": [p.hex() for p in parts],
            "emitted_hex": [p.hex() for p in emitted],
        }
        return raw, emitted

    def test_nested_event_depth_boundary_and_fragment_parity(self):
        for shape in ("array", "object", "mixed"):
            for depth in (63, 64, 65, 5000):
                for fragmented in (False, True):
                    with self.subTest(shape=shape, depth=depth, fragmented=fragmented):
                        event = b"data: " + self.nested(depth, shape) + b"\n\n"
                        parts = (
                            [event[: len(event) // 2], event[len(event) // 2 :]]
                            if fragmented
                            else [event]
                        )
                        raw, emitted = self.check_parts(
                            f"r200_depth_{shape}_{depth}_{fragmented}", parts
                        )
                        self.assertEqual(raw["events"], 1)
                        if depth > self.DEPTH_LIMIT:
                            self.assertEqual(raw["errors"], ["invalid_sse_json"])
                            self.assertIn(b"[redacted-invalid]", b"".join(emitted))
                        else:
                            self.assertNotIn("invalid_sse_json", raw["errors"])
                            self.assertNotIn(b"[redacted-invalid]", b"".join(emitted))

    def test_nested_done_tail_boundary_and_parity(self):
        for depth in (63, 64, 65, 5000):
            with self.subTest(depth=depth):
                tail = b"data: " + self.nested(depth)
                replacement = Sanitizer._done_tail(tail)
                self.assertEqual(
                    replacement,
                    b"data: [redacted-invalid]" if depth > self.DEPTH_LIMIT else b"data: 0",
                )
                raw, _ = self.check_parts(
                    f"r200_done_tail_{depth}", [CONTENT + FINISH + USAGE + DONE + tail, b"\n\n"]
                )
                self.assertEqual(
                    raw["errors"],
                    ["invalid_sse_json"] if depth > self.DEPTH_LIMIT else ["invalid_sse_chunk"],
                )

    def test_strings_escapes_and_json_byte_encodings(self):
        # Brackets, escaped quotes and backslashes in strings never add depth.
        text = ('[{\\"private' * 100) + ("\\" * 4) + "]}"
        chunk = {"choices": [{"index": 0, "delta": {"content": text}, "finish_reason": None}]}
        value = json.dumps(chunk, ensure_ascii=False)
        for encoding in ("utf-8", "utf-16", "utf-16-le", "utf-16-be", "utf-32"):
            with self.subTest(encoding=encoding):
                raw, _ = self.check_parts(
                    "r200_encoding_" + encoding,
                    [b"data: " + value.encode(encoding) + b"\n\n", FINISH + USAGE + DONE],
                )
                self.assertTrue(raw["complete"])
                self.assertEqual(raw["errors"], [])
        for encoding in ("utf-16", "utf-32-be"):
            with self.subTest(over_limit_encoding=encoding):
                raw, _ = self.check_parts(
                    "r200_encoded_depth_" + encoding,
                    [b"data: " + self.nested(65).decode().encode(encoding) + b"\n\n"],
                )
                self.assertEqual(raw["errors"], ["invalid_sse_json"])

    def test_decoder_recursion_failure_maps_to_invalid_json(self):
        rows, _ = self.fragments([b"data: []\n\n"])
        row = next(r for r in rows if r["payload"]["event"] == "sse")
        with patch("json.loads", side_effect=RecursionError("private-parser-message")):
            raw = self.stream_report([b"data: []\n\n"])
            emitted = bytes.fromhex(Sanitizer(self.KEY).row(row)["payload"]["chunk_hex"])
            tail = Sanitizer._done_tail(b"data: []")
        self.assertEqual(raw["errors"], ["invalid_sse_json"])
        self.assertEqual(emitted, b"data: [redacted-invalid]\n\n")
        self.assertEqual(tail, b"data: [redacted-invalid]")
        self.capture(
            "r200_recursion_fallback",
            [],
            {"raw": raw, "emitted_hex": emitted.hex(), "tail_hex": tail.hex()},
        )

    def test_campaign_depth_boundary_export_and_reproduce(self):
        for depth in (63, 64, 65, 5000):
            with self.subTest(depth=depth):
                campaign, _ = CampaignTests.campaign(self, name=f"depth-{depth}")
                path = campaign.root / "raw/client.jsonl"
                rows = inspect_segment(path)[1]
                row = next(r for r in rows if r["payload"]["event"] == "sse")
                # An ignored extra field makes the valid/invalid boundary affect
                # completion, rather than only the code for an invalid chunk.
                event = (
                    b'data: {"choices":[{"index":0,"delta":{"content":"private"},'
                    b'"finish_reason":null}],"extra":' + self.nested(depth - 1) + b"}\n\n"
                )
                row["payload"]["chunk_hex"] = (event + FINISH + USAGE + DONE).hex()
                path.write_bytes(b"".join(encode(r) for r in rows))
                before = campaign.report()
                errors = [e for c in before["requests"]["cohorts"] for e in c["stream"]["errors"]]
                self.assertEqual("invalid_sse_json" in errors, depth > self.DEPTH_LIMIT)
                self.assertEqual(
                    before["requests"]["denominators"]["complete"],
                    3 if depth > self.DEPTH_LIMIT else 4,
                )
                campaign.materialize()
                safe_root = self.root / f"export-{depth}"
                exported = sanitized_campaign(
                    campaign.root, safe_root, [campaign.spec], key=self.KEY
                )
                after = OfflineCampaign(safe_root, exported["specs"][0]).report()
                # sanitized_campaign compares every mapped semantic fact.
                self.assertEqual(
                    before["requests"]["denominators"], after["requests"]["denominators"]
                )
                self.assertEqual(before["validity_reasons"], after["validity_reasons"])
                self.assertTrue(reproduce(campaign.root, attempt_index=1)["reproduced"])
                self.assertTrue(reproduce(safe_root, attempt_index=1)["reproduced"])
                OUTPUTS[f"r200_campaign_depth_{depth}"] = {
                    "report": {"raw": before, "sanitized": after},
                    "archive_state": exported["archive"],
                    "summaries": exported["summaries"],
                    "depth": depth,
                }
