"""Round161–163 regressions through the real producer and disk-backed host adapter."""

import json
import struct
import sys
import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import patch

import test_stage_c_observer as fixtures
from test_stage_c_observer import MS, pinned_request_id, scan

from inference_platform import stage_c_observer as observer
from inference_platform.stage_c_observer_adapter import SourceStore, attach_observations
from inference_platform.stage_c_registered import QUANTITIES, vector


class AdapterLossAndIdentityTest(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.OwnerCaptureIntegrationTest()
        self.value, self.pool, self.manager = self.fixture.make_observer()
        self.value.last_enqueued = 1
        self.rows = []
        self.events = [["AllBlocksCleared", [], None]]

    def drain(self):
        self.rows.extend(self.value.records.drain())
        while (item := self.value.transport.take()) is not None:
            index, (kind, source) = item
            if kind == "scan":
                self.rows.append({"kind": "scan", "scan": observer.scan_to_row(source)})
            self.value.transport.release(index)

    def capture(self, slot, kind="ordinary", drain=True):
        self.fixture.stamp = (100 * slot + 5) * MS
        result = self.value.capture(kind, slot + 1 if kind == "seed" else None)
        if drain:
            self.drain()
        return result

    def project(self, last_slot=2, receipt=True, slot_overrides=None, batches=None):
        self.drain()
        batch = {
            "kind": "batch",
            "token": 1,
            "sequence": 0,
            "error": False,
            "prefixes": [],
            "events": self.events,
        }
        batches = [batch] if batches is None else batches
        rows = [
            *batches,
            *(
                {"kind": "subscriber", "sequence": b["sequence"], "events": b["events"]}
                for b in batches
            ),
            *self.rows,
        ]
        rows.extend(
            {
                "kind": "slot",
                "slot": s,
                "observed_ns": (s * 100 + 20) * MS,
                "certificate": None,
                "scan_id": None,
                "queue": [(s * 100 + 18) * MS, (s * 100 + 19) * MS, (s * 100 + 20) * MS, 4],
                **(slot_overrides or {}).get(s, {}),
            }
            for s in range(last_slot + 1)
        )
        if receipt:
            rows.append(self.value.receipt())
        with tempfile.TemporaryDirectory() as directory:
            store = SourceStore(
                Path(directory) / "source.db",
                quota_bytes=16_000_000,
                frozen=self.value.domain.frozen,
            )
            try:
                store.ingest(json.dumps(row).encode() for row in rows)
                return list(
                    store.observations(
                        origin=0, first_slot=0, last_slot=last_slot, epoch=1, phase=0
                    )
                )
            finally:
                store.close()

    def assert_gap(self):
        rows = self.project()
        self.assertEqual([r["status"] for r in rows], [0, 1, 0])
        self.assertIsNone(rows[1]["values"]["cached"])
        self.assertEqual([rows[i]["values"]["cached"] for i in (0, 2)], [0, 0])
        self.assertEqual(self.value.loss, {})
        # Independent queue reads remain observed even in the owner gap.
        self.assertEqual(rows[1]["values"]["queue"], 4)

    def test_gap_without_queue_read_is_missing(self):
        self.capture(0)
        self.value.gap("snapshot_buffer", 105 * MS)
        self.capture(2)
        rows = self.project(slot_overrides={1: {"queue": None}})
        self.assertEqual([row["status"] for row in rows], [0, 2, 0])
        self.assertTrue(all(value is None for value in rows[1]["values"].values()))

    def test_identical_evidence_produces_identical_rows_with_or_without_gap(self):
        self.capture(0)
        self.capture(2)
        ungapped = self.project()
        self.assertEqual(self.value.receipt()["gaps"], [])
        self.value.gap("snapshot_buffer", 105 * MS)
        gapped = self.project()
        self.assertEqual(self.value.receipt()["gaps"], [[1, "snapshot_buffer", 1]])
        self.assertEqual(gapped, ungapped)

    def test_cross_slot_scan_leaves_only_start_slot_partial(self):
        self.capture(0)
        stamps = iter([198 * MS, 201 * MS])
        with patch.object(self.value, "clock", lambda: next(stamps)):
            self.assertIsNone(self.value.capture("ordinary"))
        self.assertEqual(self.value.gaps[1, "cross_slot_scan"], 1)
        self.capture(2)
        self.assert_gap()

    def test_snapshot_buffer_drop_leaves_only_one_slot_partial(self):
        self.capture(0)
        reserved = [self.value.transport.reserve(), self.value.transport.reserve()]
        self.assertIsNone(self.capture(1))
        for index in reserved:
            self.value.transport.discard(index)
        self.capture(2)
        self.assertEqual(self.value.gaps[1, "snapshot_buffer"], 1)
        self.assert_gap()

    def test_failed_publish_recovers_on_next_capture_and_adapter(self):
        self.capture(0)
        publish = self.value.transport.publish

        def contended(index, source):
            with self.value.transport.lock:
                return publish(index, source)

        with patch.object(self.value.transport, "publish", contended):
            self.assertIsNone(self.capture(1))
        self.assertIn("WRITING", self.value.transport.states)
        self.capture(2)
        self.assertEqual(self.value.transport.states, ["FREE", "FREE"])
        self.assertEqual(self.value.gaps[1, "snapshot_publication"], 1)
        self.assert_gap()

    def test_budget_gap_does_not_override_valid_same_slot_scan(self):
        self.capture(0)
        self.assertIsNone(self.capture(0))
        self.assertEqual(self.project(0)[0]["status"], 0)

    def test_lost_entry_record_does_not_refuse_fresh_neighbours(self):
        self.capture(0)
        self.fixture.stamp = 120 * MS
        seed = self.value.capture("seed", 1)
        with patch.object(self.value.records, "put", return_value=False):
            certificate = self.value.open_block("gpu", seed)
        self.fixture.stamp = 180 * MS
        self.value.after_wait(certificate)
        self.drain()
        self.fixture.stamp = 220 * MS
        self.value.resolved_tokens.add(1)
        future = self.value.before_idle(True)
        self.fixture.stamp = 290 * MS
        self.value.after_wait(future)
        rows = self.project(
            slot_overrides={
                2: {
                    "scan_id": future.scan.identity,
                    "certificate": future.identity,
                    "observed_ns": 240 * MS,
                }
            }
        )
        self.assertEqual(rows[0]["status"], 0)
        self.assertEqual(rows[2]["status"], 0)
        self.assertIsNone(rows[1]["values"]["cached"])
        self.assertEqual(self.value.certificate_losses, {certificate.identity: 120 * MS})
        self.assertEqual(self.value.integrity, {})

    def test_boundary_read_contention_is_one_gap_and_later_held_proof_recovers(self):
        self.capture(0)
        self.fixture.stamp = 120 * MS
        with self.value.boundary_lock:
            self.assertIsNone(self.value.before_idle(True))
        self.drain()
        self.fixture.stamp = 220 * MS
        self.value.resolved_tokens.add(1)
        certificate = self.value.before_idle(True)
        self.fixture.stamp = 290 * MS
        self.value.after_wait(certificate)
        rows = self.project(
            slot_overrides={
                2: {
                    "scan_id": certificate.scan.identity,
                    "certificate": certificate.identity,
                    "observed_ns": 240 * MS,
                }
            }
        )
        self.assertEqual([row["status"] for row in rows], [0, 1, 0])
        self.assertEqual(self.value.integrity, {})
        self.assertGreater(self.value.gaps[1, "boundary_lock"], 0)

    def test_unexplained_orphan_exit_still_refuses(self):
        self.rows.append({"kind": "exit", "id": 100, "exit": 180 * MS, "epoch": 1, "thread": 10})
        with self.assertRaisesRegex(observer.Refusal, "unknown_duplicate_exit"):
            self.project(0)

    def test_lost_provenance_invalidates_forward_dependents_only(self):
        self.capture(0)
        self.fixture.stamp = 120 * MS
        rid, _ = pinned_request_id()
        full = bytes.fromhex(fixtures.GeneratedDomainTest.full())
        with patch.object(self.value.records, "put", return_value=False):
            self.value.observe_cache(
                self.pool,
                SimpleNamespace(request_id=rid, num_prompt_tokens=17),
                1,
                self.pool.blocks[1],
                full,
            )
        # This lost insertion could collide with any future key. Its source
        # time scopes the uncertainty even if the adapter runs much later.
        self.capture(1)
        self.fixture.stamp = 150 * MS
        self.value.observe_cache(
            self.pool,
            SimpleNamespace(request_id=rid, num_prompt_tokens=17),
            1,
            self.pool.blocks[1],
            full,
        )  # alias of the lost insertion
        self.assertEqual(self.value.provenance[1][4], "alias")
        self.capture(2)
        rows = self.project()
        self.assertEqual([r["status"] for r in rows], [0, 0, 3])
        self.assertEqual(rows[2]["invalid_reason"], "integrity:domain")
        self.assertEqual(rows[2]["values"]["queue"], 4)
        self.assertEqual(self.value.integrity, {"domain": 120 * MS})

    def test_sideband_loss_invalidates_event_counts_only_from_loss_time(self):
        self.capture(0)
        self.value.fail("sideband_lock", "events", 120 * MS)
        self.capture(1)
        self.capture(2)
        rows = self.project()
        self.assertEqual([r["status"] for r in rows], [0, 0, 3])
        self.assertIsNone(rows[2]["values"]["cached"])
        self.assertEqual(rows[2]["values"]["shared"], 0)
        self.assertEqual(rows[2]["values"]["capacity"], 3891)

    def assert_phase_vectors(self, rows, expected):
        run = {
            "snapshot_count_sources": [],
            "exposures": [{"arm": 1, "start_ns": 0, "end_ns": 300 * MS, "samples": {}}],
        }
        attached = attach_observations(run, rows)
        # Snapshot bits mean presence, including values in invalid rows.
        for source, snapshot in zip(rows, attached["snapshot_count_sources"], strict=True):
            self.assertEqual(snapshot["status"], source["status"])
            self.assertEqual(
                snapshot["presence_bitmap"],
                sum(
                    1 << i
                    for i, quantity in enumerate(QUANTITIES)
                    if quantity != "lag" and source["values"].get(quantity) is not None
                ),
            )
        phase = attached["exposures"][0]
        for quantity, (valid_n, invalid_n, maximum, total, integral, exposure) in expected.items():
            with self.subTest(quantity=quantity):
                encoded, present = vector(phase["samples"][quantity], 0, 300 * MS)
                self.assertTrue(present)
                self.assertEqual(struct.unpack_from("<II", encoded, 32), (valid_n, invalid_n))
                self.assertEqual(struct.unpack_from("<Q", encoded, 8)[0], maximum)
                self.assertEqual(int.from_bytes(encoded[16:32], "little"), total)
                self.assertEqual(int.from_bytes(encoded[48:64], "little"), integral)
                self.assertEqual(struct.unpack_from("<Q", encoded, 64)[0], exposure)

    def test_event_integrity_row_excludes_shared_from_phase_vector(self):
        full = fixtures.GeneratedDomainTest.full()
        self.value.domain = observer.NativeDomain({full: {"in_W": True}})
        self.capture(0)
        self.capture(1)
        self.value.fail("sideband_lock", "events", 150 * MS)
        self.fixture.stamp = 180 * MS
        rid, external = pinned_request_id()
        self.value.manifest["requests"] = {external: {"per_request_index": 0, "prompt_tokens": 17}}
        request = self.own(rid, 1, full)
        self.pool.blocks[1].set_block_hash(bytes.fromhex(full), num_tokens=16)
        self.value.observe_cache(self.pool, request, 0, self.pool.blocks[1], bytes.fromhex(full))
        self.capture(2)
        rows = self.project()
        self.assertEqual(rows[2]["status"], 3)
        self.assertEqual(rows[2]["invalid_reason"], "integrity:events")
        self.assertEqual(rows[2]["values"]["shared"], 1)
        self.assert_phase_vectors(rows, {"shared": (2, 1, 0, 0, 0, 100 * MS)})

    def test_missing_receipt_and_worker_exception_refuse_whole_source(self):
        self.capture(0)
        with self.assertRaisesRegex(observer.Refusal, "incomplete_source"):
            self.project(0, receipt=False)
        with tempfile.TemporaryDirectory() as directory:
            self.value.manifest.update(
                output_path=str(Path(directory) / "source.jsonl"),
                writer_quota_bytes=1_000_000,
                manifest_sha256="00" * 32,
            )
            self.value.activation_receipt = []
            self.value.execution_receipt = {}
            with patch.object(self.value.records, "drain", side_effect=RuntimeError("worker")):
                self.value.run()
            self.assertTrue(Path(self.value.manifest["output_path"] + ".failure.json").exists())
        self.assertTrue(self.value.first_failure[1].startswith("worker:"))
        with self.assertRaisesRegex(observer.Refusal, "incomplete_source"):
            self.project(0)

    def own(self, rid, block_id, full, *, index=0, prompt=17):
        request = SimpleNamespace(
            request_id=rid, num_prompt_tokens=prompt, block_hashes=[bytes.fromhex(full)[:-4]]
        )
        self.value.engine.scheduler.requests[rid] = request
        block = self.pool.blocks[block_id]
        block.ref_cnt = 1
        self.manager.req_to_blocks[rid] = [block]
        free = [b for b in self.pool.blocks[1:] if not b.ref_cnt]
        tail = self.pool.free_block_queue.fake_free_list_tail
        self.pool.free_block_queue.fake_free_list_head.next_free_block = free[0]
        for left, right in zip(free, [*free[1:], tail], strict=True):
            left.next_free_block = right
        self.pool.free_block_queue.num_free_blocks = len(free)
        return request

    def test_pinned_real_ids_cache_and_owner_capture_both_endpoints(self):
        for endpoint in ("chatcmpl", "cmpl"):
            with self.subTest(endpoint=endpoint):
                self.setUp()
                rid, external = pinned_request_id(endpoint=endpoint)
                self.value.manifest["requests"] = {
                    external: {"per_request_index": 0, "prompt_tokens": 0}
                }
                full = fixtures.GeneratedDomainTest.full()
                request = self.own(rid, 1, full, prompt=0)
                self.pool.blocks[1].set_block_hash(bytes.fromhex(full), num_tokens=16)
                self.value.observe_cache(
                    self.pool, request, 0, self.pool.blocks[1], bytes.fromhex(full)
                )
                self.events.append(["BlockStored", [7], 0])
                self.capture(0)
                rows = self.project(0)
                self.assertEqual(rows[0]["status"], 0)
                self.assertEqual(rows[0]["values"]["non_shared"], 1)
                source = next(row["scan"] for row in self.rows if row["kind"] == "scan")
                self.assertEqual(source["owners"][0][:2], [external, 0])
                self.assertNotIn(rid, json.dumps([*self.rows, self.value.receipt()]))

    def test_unregistered_owner_preserves_registered_identity_and_other_quantities(self):
        known, external = pinned_request_id()
        unknown, _ = pinned_request_id("probe-unregistered")
        full = fixtures.GeneratedDomainTest.full()
        self.value.manifest["requests"] = {external: {"per_request_index": 0, "prompt_tokens": 17}}
        self.value.domain = observer.NativeDomain({full: {"in_W": True}})
        self.own(known, 1, full)
        self.own(unknown, 2, fixtures.GeneratedDomainTest.full(2, 8))
        self.capture(0)
        first = self.project(0)[0]
        self.assertEqual(first["invalid_reason"], "request_identity")
        self.assertEqual(first["values"]["cached"], 0)
        self.assertEqual(first["values"]["evictable"], 0)
        self.assertTrue(self.value.domain.key_valid(full, 10**12))
        self.assertIsNone(self.value.domain.invalid_since)
        del self.manager.req_to_blocks[unknown]
        del self.value.engine.scheduler.requests[unknown]
        self.pool.blocks[2].ref_cnt = 0
        self.own(known, 1, full)  # reconcile free queue after the unknown owner exits
        self.capture(1)
        rows = self.project(1)
        self.assertEqual(rows[1]["status"], 0)
        self.assertEqual(rows[1]["values"]["shared"], 1)

    def test_unregistered_cache_taints_only_its_key_even_after_eviction(self):
        known, external = pinned_request_id()
        unknown, _ = pinned_request_id("probe-unregistered")
        full, other = fixtures.GeneratedDomainTest.full(), fixtures.GeneratedDomainTest.full(2, 8)
        self.value.manifest["requests"] = {external: {"per_request_index": 0, "prompt_tokens": 0}}
        self.pool.blocks[2].set_block_hash(bytes.fromhex(other), num_tokens=16)
        self.value.observe_cache(
            self.pool,
            SimpleNamespace(request_id=unknown, num_prompt_tokens=0),
            0,
            self.pool.blocks[2],
            bytes.fromhex(other),
        )
        self.assertIsNone(self.value.domain.invalid_since)
        self.assertTrue(self.value.domain.key_valid(full, 10**12))
        self.assertFalse(self.value.domain.key_valid(other, 10**12))
        request = self.own(known, 1, full, prompt=0)
        self.pool.blocks[1].set_block_hash(bytes.fromhex(full), num_tokens=16)
        self.value.observe_cache(self.pool, request, 0, self.pool.blocks[1], bytes.fromhex(full))
        self.events.append(["BlockStored", [7], 0])
        self.events.append(["BlockStored", [8], 0])
        self.capture(0)
        first = self.project(0)[0]
        self.assertEqual(first["values"]["cached"], 2)
        self.assertEqual(first["values"]["evictable"], 1)
        self.assertEqual(first["counts"]["event_live"], 2)
        self.assertEqual(first["invalid_reason"], "request_identity")
        self.assertEqual(first["values"]["non_shared"], 1)
        self.assertEqual(first["values"]["queue"], 4)
        self.pool.blocks[2].reset_hash()
        self.events.append(["BlockRemoved", [8], 0])
        self.capture(1)
        self.assertEqual(self.project(1)[1]["status"], 0)
        self.assertFalse(self.value.domain.key_valid(other, 10**12))

    def test_valid_held_scan_beats_fresh_unknown_alias_with_exact_two_batch_join(self):
        self.fixture.stamp = 220 * MS
        self.value.resolved_tokens.add(1)
        certificate = self.value.before_idle(True)
        self.drain()
        self.fixture.stamp = 250 * MS
        self.value.after_wait(certificate)

        # The unknown alias arrives only after the held certificate closes.
        self.fixture.stamp = 260 * MS
        full = fixtures.GeneratedDomainTest.full(2, 8)
        unknown, _ = pinned_request_id("probe-unregistered")
        block = self.pool.blocks[2]
        block.set_block_hash(bytes.fromhex(full), num_tokens=16)
        self.value.observe_cache(
            self.pool,
            SimpleNamespace(request_id=unknown, num_prompt_tokens=0),
            0,
            block,
            bytes.fromhex(full),
        )
        self.value.last_enqueued = 2
        self.fixture.stamp = 280 * MS
        fresh = self.value.capture("ordinary")
        batches = [
            {
                "kind": "batch",
                "token": 1,
                "sequence": 0,
                "error": False,
                "prefixes": [],
                "events": self.events,
            },
            {
                "kind": "batch",
                "token": 2,
                "sequence": 1,
                "error": False,
                "prefixes": [],
                "events": [["BlockStored", [8], 0]],
            },
        ]
        fresh_only = self.project(batches=batches)[2]
        self.assertEqual(fresh_only["observed_ns"], fresh.end)
        self.assertEqual(fresh_only["status"], 3)
        self.assertEqual(fresh_only["invalid_reason"], "request_identity")
        self.assertEqual(fresh_only["values"]["cached"], 1)
        self.assertEqual(fresh_only["join_sequence"], 1)
        self.assertTrue(all(value is not None for value in fresh_only["values"].values()))
        held = self.project(
            batches=batches,
            slot_overrides={
                2: {
                    "scan_id": certificate.scan.identity,
                    "certificate": certificate.identity,
                    "observed_ns": 240 * MS,
                }
            },
        )[2]
        self.assertEqual(held["status"], 0)
        self.assertIsNone(held["invalid_reason"])
        self.assertEqual(held["observed_ns"], 240 * MS)
        self.assertEqual(held["sample_age_ns"], 20 * MS)
        self.assertEqual(held["values"]["cached"], 0)
        self.assertEqual(held["join_sequence"], 0)

    def test_fresh_only_unknown_alias_excludes_owner_phase_samples_but_keeps_queue(self):
        self.capture(0)
        self.capture(1)
        # R193 Evidence (a), fresh-only slot: insertion after the idle hold
        # would close, then an exact two-batch fresh join at 280 ms.
        self.fixture.stamp = 260 * MS
        full = fixtures.GeneratedDomainTest.full(2, 8)
        unknown, _ = pinned_request_id("probe-unregistered")
        block = self.pool.blocks[2]
        block.set_block_hash(bytes.fromhex(full), num_tokens=16)
        self.value.observe_cache(
            self.pool,
            SimpleNamespace(request_id=unknown, num_prompt_tokens=0),
            0,
            block,
            bytes.fromhex(full),
        )
        self.value.last_enqueued = 2
        self.fixture.stamp = 280 * MS
        fresh = self.value.capture("ordinary")
        batches = [
            {
                "kind": "batch",
                "token": token,
                "sequence": token - 1,
                "error": False,
                "prefixes": [],
                "events": events,
            }
            for token, events in ((1, self.events), (2, [["BlockStored", [8], 0]]))
        ]
        rows = self.project(batches=batches)
        self.assertEqual([row["status"] for row in rows], [0, 0, 3])
        self.assertEqual(rows[2]["invalid_reason"], "request_identity")
        self.assertEqual(rows[2]["observed_ns"], fresh.end)
        self.assertEqual(rows[2]["values"]["cached"], 1)
        self.assertEqual(rows[2]["join_sequence"], 1)
        self.assert_phase_vectors(
            rows,
            {
                "cached": (2, 1, 0, 0, 0, 100 * MS),
                "shared": (2, 1, 0, 0, 0, 100 * MS),
                "queue": (3, 0, 4, 12, 800 * MS, 200 * MS),
            },
        )

    def test_invalid_held_unknown_alias_does_not_replace_inexact_fresh_scan(self):
        self.fixture.stamp = 200 * MS
        full = fixtures.GeneratedDomainTest.full(2, 8)
        unknown, _ = pinned_request_id("probe-unregistered")
        block = self.pool.blocks[2]
        block.set_block_hash(bytes.fromhex(full), num_tokens=16)
        self.value.observe_cache(
            self.pool,
            SimpleNamespace(request_id=unknown, num_prompt_tokens=0),
            0,
            block,
            bytes.fromhex(full),
        )
        self.events.append(["BlockStored", [8], 0])
        self.fixture.stamp = 220 * MS
        self.value.resolved_tokens.add(1)
        certificate = self.value.before_idle(True)
        self.drain()
        self.fixture.stamp = 250 * MS
        self.value.after_wait(certificate)
        block.reset_hash()
        # Eviction precedes the fresh copy, but its following-batch prefix is
        # not exact. Only the independent owner partition and queue validate.
        self.pool.kv_event_queue.append(object())
        self.fixture.stamp = 280 * MS
        fresh = self.value.capture("ordinary")
        batches = [
            {
                "kind": "batch",
                "token": 1,
                "sequence": 0,
                "error": False,
                "prefixes": [],
                "events": self.events,
            },
            {
                "kind": "batch",
                "token": 2,
                "sequence": 1,
                "error": False,
                "prefixes": [[fresh.identity, 1, False]],
                "events": [["BlockRemoved", [8], 0]],
            },
        ]
        overrides = {
            2: {
                "scan_id": certificate.scan.identity,
                "certificate": certificate.identity,
                "observed_ns": 240 * MS,
            }
        }
        fresh_only = self.project(batches=batches)[2]
        selected = self.project(batches=batches, slot_overrides=overrides)[2]
        self.assertEqual(selected, fresh_only)
        self.assertEqual(selected["status"], 1)
        self.assertIsNone(selected["invalid_reason"])
        self.assertEqual(selected["observed_ns"], fresh.end)
        self.assertEqual(selected["sample_age_ns"], 0)
        self.assertIsNone(selected["values"]["cached"])
        self.assertEqual(selected["values"]["non_shared"], 0)
        self.assertEqual(selected["values"]["queue"], 4)
        # With no fresh scan, retain the existing invalid-held reporting rule.
        self.rows = [
            r for r in self.rows if r["kind"] != "scan" or r["scan"]["identity"] != fresh.identity
        ]
        held_only = self.project(batches=batches, slot_overrides=overrides)[2]
        self.assertEqual(held_only["status"], 3)
        self.assertEqual(held_only["invalid_reason"], "request_identity")
        self.assertEqual(held_only["values"]["cached"], 1)
        self.assertEqual(held_only["observed_ns"], 240 * MS)

    def test_unregistered_frozen_W_alias_preserves_later_registered_scan(self):
        full = fixtures.GeneratedDomainTest.full()
        self.value.domain = observer.NativeDomain({full: {"in_W": True}})
        unknown, _ = pinned_request_id("probe-unregistered")
        block = self.pool.blocks[1]
        block.set_block_hash(bytes.fromhex(full), num_tokens=16)
        self.value.observe_cache(
            self.pool,
            SimpleNamespace(request_id=unknown, num_prompt_tokens=17),
            0,
            block,
            bytes.fromhex(full),
        )
        insertion_ns = self.value.provenance[1][-1]
        self.assertEqual(self.value.domain.aliases, 1)
        self.assertEqual(self.value.domain.collisions, 0)
        self.assertTrue(self.value.domain.key_valid(full, insertion_ns))
        self.assertIs(self.value.domain.membership(full, 10**12), True)
        self.events.append(["BlockStored", [7], 0])
        rid, _ = pinned_request_id()
        self.own(rid, 1, full)
        self.capture(0)
        first = self.project(0)[0]  # host replays the unregistered alias too
        self.assertEqual(first["status"], 0)
        self.assertEqual(first["values"]["shared"], 1)
        self.assertEqual(first["values"]["cached"], 1)
        # A later registered re-cache of the same frozen block is valid too.
        self.value.observe_cache(
            self.pool, self.value.engine.scheduler.requests[rid], 0, block, bytes.fromhex(full)
        )
        self.capture(1)
        self.assertEqual(self.project(1)[1]["status"], 0)

    def test_unregistered_frozen_key_collision_keeps_forward_taint(self):
        full, collision = fixtures.GeneratedDomainTest.full(), fixtures.GeneratedDomainTest.full(2)
        self.value.domain = observer.NativeDomain({full: {"in_W": True}})
        unknown, _ = pinned_request_id("probe-unregistered")
        self.value.observe_cache(
            self.pool,
            SimpleNamespace(request_id=unknown, num_prompt_tokens=17),
            0,
            self.pool.blocks[1],
            bytes.fromhex(collision),
        )
        insertion_ns = self.value.provenance[1][-1]
        self.assertEqual(self.value.domain.collisions, 1)
        self.assertEqual(self.value.domain.aliases, 0)
        self.assertTrue(self.value.domain.key_valid(full, insertion_ns - 1))
        self.assertFalse(self.value.domain.key_valid(full, insertion_ns))
        self.assertIsNone(self.value.domain.membership(full, 10**12))
        # Returning to the correct frozen hash cannot repair a real collision.
        rid, _ = pinned_request_id()
        request = self.own(rid, 1, full)
        self.pool.blocks[1].set_block_hash(bytes.fromhex(full), num_tokens=16)
        self.value.observe_cache(self.pool, request, 0, self.pool.blocks[1], bytes.fromhex(full))
        self.events.append(["BlockStored", [7], 0])
        self.capture(0)
        first = self.project(0)[0]
        self.assertEqual(first["status"], 3)
        self.assertEqual(first["invalid_reason"], "native_identity")
        self.assertFalse(self.value.domain.key_valid(full, 10**12))

    def test_concurrent_binding_refuses_both_then_recovers_after_retirement(self):
        a, external = pinned_request_id()
        b, _ = pinned_request_id()
        self.assertNotEqual(a, b)
        self.value.engine.scheduler.requests = {a: object(), b: object()}
        self.assertIsNone(self.value.request_binding(a)[1])
        self.assertIsNone(self.value.request_binding(b)[1])
        del self.value.engine.scheduler.requests[a]
        self.assertEqual(self.value.request_binding(b)[0], external)
        self.assertIsNotNone(self.value.request_binding(b)[1])
        for malformed in (external, external + "-ABCDEF12", external + "-abcd1234-extra"):
            self.assertIsNone(self.value.request_binding(malformed)[1])
        long_id, long_external = pinned_request_id("r" * 129)
        self.value.manifest["requests"][long_external] = {
            "per_request_index": 1,
            "prompt_tokens": 17,
        }
        self.assertEqual(self.value.request_binding(long_id)[1]["per_request_index"], 1)

    def test_generated_frozen_alias_uses_W_membership_in_adapter(self):
        full = fixtures.GeneratedDomainTest.full()
        self.value.domain = observer.NativeDomain({full: {"in_W": True}})
        rid, external = pinned_request_id()
        self.value.manifest["requests"] = {external: {"per_request_index": 0, "prompt_tokens": 0}}
        request = self.own(rid, 1, full, prompt=0)
        self.pool.blocks[1].set_block_hash(bytes.fromhex(full), num_tokens=16)
        self.value.observe_cache(self.pool, request, 0, self.pool.blocks[1], bytes.fromhex(full))
        self.events.append(["BlockStored", [7], 0])
        self.capture(0)
        rows = self.project(0)
        self.assertEqual(rows[0]["status"], 0)
        self.assertEqual(rows[0]["values"]["shared"], 1)
        self.assertEqual(rows[0]["values"]["non_shared"], 0)
        self.assertEqual(self.value.domain.aliases, 1)


class TransportAndReadinessRegressionTest(unittest.TestCase):
    def test_long_contended_worker_loop_never_loses_capacity_permanently(self):
        transport = observer.TwoSlotTransport()
        stop = threading.Event()
        consumed, errors = [], []

        def worker():
            try:
                while not stop.is_set():
                    item = transport.take()
                    if item is None:
                        stop.wait(0.0001)
                    else:
                        index, row = item
                        consumed.append(row)
                        transport.release(index)
            except Exception as exc:
                errors.append(exc)

        thread = threading.Thread(target=worker)
        thread.start()
        try:
            for n in range(5000):
                index = transport.reserve()
                if index is None:
                    continue
                if n % 7 == 0:
                    with transport.lock:
                        self.assertFalse(transport.publish(index, n))
                else:
                    transport.publish(index, n)
        finally:
            stop.set()
            thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        while (item := transport.take()) is not None:
            transport.release(item[0])
        a, b = transport.reserve(), transport.reserve()
        self.assertEqual({a, b}, {0, 1})
        self.assertIsNone(transport.reserve())
        self.assertEqual(len(consumed), len(set(consumed)))
        self.assertGreater(transport.drops, 0)
        transport.discard(a)
        transport.discard(b)
        integration = AdapterLossAndIdentityTest()
        integration.setUp()
        integration.value.transport = transport
        integration.capture(0)
        self.assertEqual(integration.project(0)[0]["status"], 0)

    def test_pre_admission_readiness_and_concrete_wait_guard(self):
        fixture = fixtures.OwnerCaptureIntegrationTest()
        value, _pool, _manager = fixture.make_observer()
        module = ModuleType("vllm.v1.worker.gpu.model_runner")
        runner_cls = type("GPUModelRunner", (), {"__module__": module.__name__})
        output_cls = type("AsyncOutput", (), {"__module__": "vllm.v1.worker.gpu.async_utils"})
        module.AsyncOutput = output_cls
        value.engine.model_executor.driver_worker = SimpleNamespace(
            worker=SimpleNamespace(model_runner=runner_cls())
        )
        with patch.dict(sys.modules, {module.__name__: module}):
            expected = value.admit()
            self.assertEqual(len(expected), 5)
            self.assertEqual(value.receipt()["readiness"], expected)
            value.before_wait(SimpleNamespace(async_output=output_cls()))
            self.assertEqual(value.readiness_guard_checks, 1)
            with self.assertRaisesRegex(observer.Refusal, "readiness_shape"):
                value.before_wait(SimpleNamespace(async_output=object()))
            value.engine.vllm_config.use_v2_model_runner = False
            with self.assertRaisesRegex(observer.Refusal, "readiness_shape"):
                value.admit()
        value.engine.model_executor.driver_worker.worker.model_runner = object()
        with self.assertRaisesRegex(observer.Refusal, "readiness_runner"):
            value.admit()

    def test_start_refuses_before_worker_or_capture_when_readiness_mismatches(self):
        fixture = fixtures.OwnerCaptureIntegrationTest()
        value, _pool, _manager = fixture.make_observer()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_text("{}", encoding="utf-8")
            with (
                patch.dict("os.environ", {"STAGE_C_OBSERVER_MANIFEST": str(path)}),
                patch.object(observer, "StageCObserver", return_value=value),
                patch.object(value, "admit", side_effect=observer.Refusal("readiness_shape")),
                patch.object(observer.threading, "Thread") as worker,
                patch.object(observer, "_observer", None),
                patch.object(observer, "_registrations", []),
            ):
                with self.assertRaisesRegex(observer.Refusal, "readiness_shape"):
                    observer.start(value.engine, __file__)
                worker.assert_not_called()
                self.assertEqual(value.budget.used, {})

    def test_boundary_token_eviction_is_oldest_first_and_recent_reuse_survives(self):
        fixture = fixtures.OwnerCaptureIntegrationTest()
        value, _pool, _manager = fixture.make_observer()
        value.event_live = set()
        for token in range(observer.MAX_ASSOCIATIONS + 1):
            value.event_token = token
            value.resolve_boundary(replace(scan(), preceding_token=token))
        self.assertEqual(len(value.resolved_tokens), observer.MAX_ASSOCIATIONS)
        self.assertNotIn(0, value.resolved_tokens)
        self.assertTrue(value.boundary_ready(observer.MAX_ASSOCIATIONS - 1))
        self.assertTrue(value.boundary_ready(observer.MAX_ASSOCIATIONS))
        self.assertEqual(value.resolved_order[0], 1)
        value.resolve_boundary(replace(scan(), preceding_token=observer.MAX_ASSOCIATIONS))
        self.assertEqual(len(value.resolved_order), observer.MAX_ASSOCIATIONS)
        value.observe_reset()
        self.assertEqual(len(value.resolved_order), 0)
        self.assertEqual(value.resolved_tokens, set())


if __name__ == "__main__":
    unittest.main()
