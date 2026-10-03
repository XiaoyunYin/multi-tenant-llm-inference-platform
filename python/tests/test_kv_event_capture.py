import json
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

import msgspec

from inference_platform.fake_backend import _ObservationStore
from inference_platform.kv_event_capture import (
    PUBLISHER_FLUSH_ALLOWANCE_NS,
    correlate_routing_events,
    decode_vllm_msgpack_batch,
    derive_event_inventory,
    event_observations,
    load_routing_decisions,
    main,
    read_jsonl_event_stream,
    summarize_routing_correlations,
    token_block_digests,
)


# Serializer fixture extracted from pinned vLLM v0.29.0 distributed/kv_events.py.
# These are real msgspec structs with the runtime's batch/event encoding flags;
# no GPU runtime import or handwritten msgpack map is used.
class EventBatch(msgspec.Struct, array_like=True, omit_defaults=True, gc=False):
    ts: float
    events: list[Any]
    data_parallel_rank: int | None = None


class KVCacheEvent(msgspec.Struct, omit_defaults=True, gc=False, tag=True):
    pass


class BlockStored(KVCacheEvent):
    block_hashes: list[int]
    parent_block_hash: int | None
    token_ids: list[int]
    block_size: int
    lora_id: int | None
    medium: str | None
    lora_name: str | None
    extra_keys: list[tuple[Any, ...] | None] | None = None
    group_idx: int | None = None
    kv_cache_spec_kind: str | None = None
    kv_cache_spec_sliding_window: int | None = None
    locality: str | None = None
    ownership: str | None = None


class BlockRemoved(KVCacheEvent):
    block_hashes: list[int]
    medium: str | None
    group_idx: int | None = None
    locality: str | None = None
    ownership: str | None = None


class AllBlocksCleared(KVCacheEvent):
    pass


class KVEventBatch(EventBatch):
    events: list[BlockStored | BlockRemoved | AllBlocksCleared]


class BlockCorrelationTest(unittest.TestCase):
    def test_batched_fake_events_still_skip_cached_prefix_and_partial_tail(self):
        store = _ObservationStore()
        tokens = list(range(16 * 70 + 5))
        store.observe_prompt("prefix", "scope", tokens[:16], 3891, 2)
        before = len(store.kv_events_after(0))
        store.observe_prompt("full", "scope", tokens, 3891, 2, event_blocks=32)
        events = [batch["events"][0] for batch in store.kv_events_after(before)]
        self.assertEqual([len(event["block_hashes"]) for event in events], [32, 32, 5])
        self.assertEqual(
            [token for event in events for token in event["token_ids"]], tokens[16 : 16 * 70]
        )
        store.observe_prompt("repeat", "scope", tokens, 3891, 2, event_blocks=32)
        self.assertEqual(len(store.kv_events_after(before)), 3)

    def test_inventory_resets_live_set_and_keeps_epoch_counts_without_digests(self):
        events = [
            {"event_type": "BlockStored", "block_hash_digests": ["a", "b"], "sequence": 1},
            {"event_type": "AllBlocksCleared", "sequence": 2},
            {"event_type": "BlockStored", "block_hash_digests": ["c"], "sequence": 3},
            {"event_type": "BlockRemoved", "block_hash_digests": ["c"], "sequence": 4},
        ]
        inventory = derive_event_inventory(events)
        self.assertEqual(inventory["cached_live_block_count_at_end"], 0)
        self.assertEqual(inventory["cache_reset_count"], 1)
        self.assertEqual(inventory["maximum_epoch_live_blocks"], 2)
        self.assertEqual(
            inventory["epochs"],
            [
                {
                    "epoch": 0,
                    "block_stores": 2,
                    "block_removals": 0,
                    "peak_live_blocks": 2,
                    "end_live_blocks": 2,
                },
                {
                    "epoch": 1,
                    "block_stores": 1,
                    "block_removals": 1,
                    "peak_live_blocks": 1,
                    "end_live_blocks": 0,
                },
            ],
        )
        self.assertNotIn("digests", json.dumps(inventory))

    def test_msgspec_runtime_batch_roundtrip_through_capture_decoder(self):
        stored = BlockStored(
            block_hashes=[1234, 5678],
            parent_block_hash=None,
            token_ids=list(range(32)),
            block_size=16,
            lora_id=None,
            medium="GPU",
            lora_name=None,
            group_idx=0,
            locality="LOCAL",
        )
        batch = KVEventBatch(
            ts=123.5,
            events=[
                stored,
                BlockRemoved(block_hashes=[1234], medium="GPU", group_idx=0, locality="LOCAL"),
                AllBlocksCleared(),
            ],
            data_parallel_rank=0,
        )
        payload = msgspec.msgpack.encode(batch)
        wire = msgspec.msgpack.decode(payload)
        self.assertIsInstance(wire, list)
        self.assertTrue(all(isinstance(event, dict) for event in wire[1]))
        self.assertEqual(
            [event["type"] for event in wire[1]],
            ["BlockStored", "BlockRemoved", "AllBlocksCleared"],
        )
        observations = decode_vllm_msgpack_batch(payload, sequence=7, observed_monotonic_ns=456)
        self.assertEqual(
            [event["event_type"] for event in observations],
            ["BlockStored", "BlockRemoved", "AllBlocksCleared"],
        )
        self.assertTrue(
            all(
                event["sequence"] == 7
                and event["observed_monotonic_ns"] == 456
                and event["batch_timestamp_s"] == 123.5
                for event in observations
            )
        )
        self.assertEqual(
            observations[0]["token_block_digests"], token_block_digests(list(range(32)))
        )
        self.assertEqual(len(observations[0]["block_hash_digests"]), 2)
        self.assertIn(
            observations[1]["block_hash_digests"][0], observations[0]["block_hash_digests"]
        )
        redacted = json.dumps(observations)
        for raw_field in ('"token_ids"', '"block_hashes"', '"extra_keys"'):
            self.assertNotIn(raw_field, redacted)

    def test_capture_artifact_retains_same_host_clock_pairs_and_offset(self):
        with tempfile.TemporaryDirectory() as directory:
            events = Path(directory) / "events.jsonl"
            decisions = Path(directory) / "decisions.jsonl"
            output = Path(directory) / "capture.json"
            events.write_text("", encoding="utf-8")
            decisions.write_text(
                json.dumps(
                    {
                        "request_id": "request",
                        "router_decision_unix_ns": 200,
                        "gateway_terminal_unix_ns": 250,
                        "expected_token_ids": list(range(16)),
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            with (
                patch(
                    "sys.argv",
                    [
                        "capture",
                        "--source",
                        "jsonl",
                        "--events-jsonl",
                        str(events),
                        "--decisions",
                        str(decisions),
                        "--output",
                        str(output),
                    ],
                ),
                patch("inference_platform.kv_event_capture.time.time_ns", side_effect=[200, 250]),
                patch(
                    "inference_platform.kv_event_capture.time.perf_counter_ns",
                    side_effect=[100, 140],
                ),
            ):
                self.assertEqual(main(), 0)
            self.assertFalse(output.read_bytes().startswith(b"\xef\xbb\xbf"))
            self.assertNotIn(b"\r", output.read_bytes())
            artifact = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(artifact["clock_info"]["interval_clock"], "perf_counter")
            self.assertIn("time", artifact["clock_info"]["clocks"])
            self.assertEqual(artifact["clock_pairs"]["wall_to_monotonic_offset_ns"], 110)
            self.assertEqual(artifact["clock_pairs"]["offset_change_ns"], 10)
            self.assertEqual(
                artifact["routing_to_event_observation"][0]["routing_decision_monotonic_ns"], 90
            )
            self.assertEqual(
                artifact["routing_to_event_observation"][0]["gateway_terminal_monotonic_ns"], 140
            )
            self.assertIn("1 s", artifact["basis"])

    def decisions(self, tokens, *, cached=None, at=10, terminal=None, failed=False):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "decisions.jsonl"
            value = {
                "request_id": "request",
                "routing_decision_monotonic_ns": at,
                "gateway_terminal_monotonic_ns": at + 100 if terminal is None else terminal,
                "no_store_expected_request_failed": failed,
                "expected_token_ids": tokens,
            }
            if cached is not None:
                value["cached_prompt_tokens"] = cached
            path.write_text(json.dumps(value) + "\n", encoding="utf-8")
            return load_routing_decisions(path)

    def test_rejected_decision_cannot_match_later_repeat_of_same_identity(self):
        second = 1_000_000_000
        tokens = list(range(32))
        decisions = self.decisions(tokens, at=10 * second, terminal=11 * second, failed=True)
        decisions[0]["request_id"] = "run1-rejected"
        decisions += self.decisions(tokens, at=3600 * second, terminal=3601 * second)
        decisions[1]["request_id"] = "run4-ok"
        events = event_observations(
            1,
            [{"type": "BlockStored", "token_ids": tokens, "block_size": 16}],
            observed_monotonic_ns=3600 * second + 200_000_000,
        )
        rows = correlate_routing_events(decisions, events)
        self.assertEqual(rows[0]["status"], "no_store_expected_request_failed")
        self.assertIsNone(rows[0]["event_sequence"])
        self.assertEqual(rows[1]["status"], "observed")
        summary = summarize_routing_correlations(rows)
        self.assertEqual(summary["max_observed_lag_ns"], 200_000_000)
        self.assertEqual(summary["no_store_expected_request_failed_count"], 1)
        self.assertEqual(summary["request_lifetime_bound_violation_count"], 0)

    def test_late_store_without_an_intervening_identity_decision_retains_lag(self):
        second = 1_000_000_000
        decision = self.decisions(
            list(range(32)), at=10 * second, terminal=10 * second + 10_000_000
        )
        events = event_observations(
            1,
            [{"type": "BlockStored", "token_ids": list(range(32)), "block_size": 16}],
            observed_monotonic_ns=10 * second + 1_190_000_000,
        )
        rows = correlate_routing_events(decision, events)
        self.assertEqual(rows[0]["status"], "observed_after_request_window")
        self.assertEqual(rows[0]["routing_to_event_observation_ns"], 1_190_000_000)
        self.assertEqual(rows[0]["event_sequence"], 1)
        self.assertIsNone(rows[0]["next_same_identity_decision_monotonic_ns"])
        summary = summarize_routing_correlations(rows)
        self.assertEqual(summary["observed_after_request_window_count"], 1)
        self.assertEqual(summary["max_observed_after_request_window_lag_ns"], 1_190_000_000)
        self.assertEqual(summary["observed_correlation_count"], 0)
        self.assertIsNone(summary["max_observed_lag_ns"])
        self.assertEqual(summary["excluded_counts"]["observed_after_request_window"], 1)

    def test_cross_run_late_store_cannot_match_flagged_or_unflagged_earlier_decision(self):
        second = 1_000_000_000
        tokens = list(range(32))
        for failed, expected_status in (
            (True, "no_store_expected_request_failed"),
            (False, "no_post_decision_store_event"),
        ):
            with self.subTest(failed=failed):
                earlier = self.decisions(
                    tokens,
                    at=10 * second,
                    terminal=11 * second,
                    failed=failed,
                    cached=0 if not failed else None,
                )
                earlier[0]["request_id"] = "run1"
                later = self.decisions(tokens, at=3600 * second, terminal=3601 * second)
                later[0]["request_id"] = "run4"
                events = event_observations(
                    1,
                    [{"type": "BlockStored", "token_ids": tokens, "block_size": 16}],
                    observed_monotonic_ns=3600 * second + 200_000_000,
                )
                # Decision order cannot affect the identity timeline.
                rows = correlate_routing_events(later + earlier, events)
                self.assertEqual(rows[1]["status"], expected_status)
                self.assertIsNone(rows[1]["routing_to_event_observation_ns"])
                self.assertEqual(rows[1]["next_same_identity_decision_monotonic_ns"], 3600 * second)
                self.assertEqual(rows[0]["status"], "observed")
                self.assertEqual(
                    summarize_routing_correlations(rows)["observed_after_request_window_count"], 0
                )

    def test_late_store_must_precede_next_identity_decision(self):
        tokens = list(range(32))
        first = self.decisions(tokens, terminal=20, cached=0)
        next_time = 20 + PUBLISHER_FLUSH_ALLOWANCE_NS + 100
        repeat = self.decisions(tokens, at=next_time, terminal=next_time + 100, cached=0)
        repeat[0]["request_id"] = "repeat"
        unrelated = self.decisions(list(range(32, 64)), at=30, terminal=40)
        unrelated[0]["request_id"] = "unrelated"
        for at, status in (
            (next_time - 1, "observed_after_request_window"),
            (next_time, "no_post_decision_store_event"),
            (next_time + 1, "no_post_decision_store_event"),
        ):
            with self.subTest(at=at):
                events = event_observations(
                    1,
                    [{"type": "BlockStored", "token_ids": tokens, "block_size": 16}],
                    observed_monotonic_ns=at,
                )
                row = correlate_routing_events(first + repeat + unrelated, events)[0]
                self.assertEqual(row["status"], status)

    def test_window_boundary_separates_in_window_and_late_stores(self):
        tokens = list(range(32))
        decisions = self.decisions(tokens, terminal=20, cached=0)
        bound = 20 + PUBLISHER_FLUSH_ALLOWANCE_NS
        for at, status in (
            (10, "no_post_decision_store_event"),
            (bound, "observed"),
            (bound + 1, "observed_after_request_window"),
        ):
            with self.subTest(at=at):
                events = event_observations(
                    1,
                    [{"type": "BlockStored", "token_ids": tokens, "block_size": 16}],
                    observed_monotonic_ns=at,
                )
                self.assertEqual(correlate_routing_events(decisions, events)[0]["status"], status)
        # Failure exclusion wins even when a store is in the window and fully cached.
        failed = self.decisions(tokens, cached=32, failed=True)
        self.assertEqual(
            correlate_routing_events(failed, events)[0]["status"],
            "no_store_expected_request_failed",
        )

    def test_missing_or_reversed_terminal_time_fails_closed(self):
        decision = self.decisions(list(range(32)))[0]
        for terminal in (None, True, 9):
            with self.subTest(terminal=terminal), self.assertRaisesRegex(ValueError, "terminal"):
                correlate_routing_events(
                    [{**decision, "gateway_terminal_monotonic_ns": terminal}], []
                )
        with self.assertRaisesRegex(ValueError, "terminal"):
            self.decisions(list(range(32)), terminal=9)

    def test_long_partial_prompt_cached_prefix_and_split_fake_events(self):
        # 16k + 5, k=1024: cached first block, 1023 new full blocks,
        # and five trailing tokens which cannot be stored yet.
        tokens = list(range(16 * 1024 + 5))
        store = _ObservationStore()
        store.observe_prompt("warm", "model-salt", tokens[:16], 2048, 1)
        before = len(store.kv_events_after(0))
        at = 10
        store.observe_prompt("long", "model-salt", tokens, 2048, 1)
        batches = store.kv_events_after(before)
        self.assertEqual(len(batches), 1023)
        raw_tokens = [t for batch in batches for t in batch["events"][0]["token_ids"]]
        self.assertEqual(raw_tokens, tokens[16 : 16 * 1024])
        self.assertTrue(all(len(b["events"][0]["token_ids"]) == 16 for b in batches))
        # Freeze timestamps to avoid platform monotonic clock resolution ties.
        for index, batch in enumerate(batches):
            batch["emitted_monotonic_ns"] = at + index + 1
        observations = read_jsonl_event_stream(json.dumps(b) for b in batches)
        decisions = self.decisions(tokens, cached=16, at=at)
        matched = correlate_routing_events(decisions, list(reversed(observations)))[0]
        self.assertEqual(matched["status"], "observed")
        self.assertEqual(matched["event_sequence"], batches[0]["sequence"])
        self.assertEqual(matched["match_basis"], "identity_specific_16_token_block_digest")
        self.assertEqual(matched["matched_token_block_digests"], token_block_digests(tokens[16:32]))
        # Only block digests and counts survive capture and decision loading.
        encoded = json.dumps({"decisions": decisions, "events": observations, "match": matched})
        self.assertNotIn('"token_ids"', encoded)
        self.assertNotIn('"expected_token_ids"', encoded)
        self.assertNotIn('"block_hashes"', encoded)
        self.assertEqual(len(decisions[0]["expected_token_block_digests"]), 1024)

        before_repeat = len(store.kv_events_after(0))
        self.assertTrue(store.observe_prompt("repeat", "model-salt", tokens, 2048, 1))
        self.assertEqual(store.kv_events_after(before_repeat), [])
        repeat = self.decisions(tokens, cached=16 * 1024, at=at)
        # Even an overlapping later store must not turn a fully cached prompt into a match.
        excluded = correlate_routing_events(repeat, observations)[0]
        self.assertEqual(excluded["status"], "no_new_block")
        self.assertIsNone(excluded["routing_to_event_observation_ns"])
        store.reset_cache()
        reset_events = read_jsonl_event_stream(json.dumps(b) for b in store.kv_events_after(0))
        self.assertEqual(derive_event_inventory(reset_events)["cached_live_block_count_at_end"], 0)

    def test_first_later_shared_block_ignores_old_unrelated_and_decode_blocks(self):
        tokens = list(range(69))

        def event(sequence, at, values):
            return event_observations(
                sequence,
                [
                    {
                        "type": "BlockStored",
                        "token_ids": values,
                        "block_hashes": [sequence],
                        "block_size": 16,
                    }
                ],
                observed_monotonic_ns=at,
            )

        observations = (
            event(1, 9, tokens[:16])
            + event(2, 10, tokens[:16])
            + event(3, 11, list(range(100, 116)))
            + event(4, 20, tokens[16:48])
            + event(5, 30, tokens[48:64])
        )
        result = correlate_routing_events(self.decisions(tokens, cached=16), observations)[0]
        self.assertEqual(result["event_sequence"], 4)
        self.assertEqual(result["routing_to_event_observation_ns"], 10)
        self.assertEqual(
            result["matched_token_block_digests"], sorted(token_block_digests(tokens[16:48]))
        )

    def test_shared_block_restored_by_another_identity_is_excluded(self):
        shared = list(range(16))
        tokens_a = shared + list(range(16, 32))
        tokens_b = shared + list(range(32, 48))
        decisions = self.decisions(tokens_a, cached=0) + self.decisions(tokens_b, cached=0)
        decisions[0]["request_id"] = "a"
        decisions[1]["request_id"] = "b"
        # B re-stores the shared template block before A's own unique block arrives.
        observations = event_observations(
            1,
            [
                {
                    "type": "BlockStored",
                    "block_size": 16,
                    "token_ids": tokens_b,
                    "block_hashes": [1, 2],
                }
            ],
            observed_monotonic_ns=11,
        )
        results = correlate_routing_events(decisions, observations)
        self.assertEqual(results[0]["status"], "no_post_decision_store_event")
        self.assertEqual(results[1]["status"], "observed")
        self.assertEqual(results[0]["excluded_shared_digest_count"], 1)
        # Repeated dispatches of A remain one identity, so A's own block is eligible.
        decisions.append({**decisions[0], "request_id": "a-repeat"})
        observations += event_observations(
            2,
            [
                {
                    "type": "BlockStored",
                    "block_size": 16,
                    "token_ids": tokens_a[16:],
                    "block_hashes": [3],
                }
            ],
            observed_monotonic_ns=20,
        )
        results = correlate_routing_events(decisions, observations)
        self.assertEqual([row["event_sequence"] for row in results], [2, 1, 2])

    def test_unknown_cache_state_without_store_has_separate_status_and_count(self):
        decision = self.decisions(list(range(32)))
        row = correlate_routing_events(decision, [])[0]
        self.assertEqual(row["status"], "no_identity_specific_store_cache_state_unknown")
        self.assertEqual(
            row["match_basis"],
            "cache_state_unknown_no_identity_specific_store_before_next_identity_decision",
        )
        summary = summarize_routing_correlations([row])
        self.assertIn("no_identity_specific_store_cache_state_unknown", summary["basis"])
        self.assertIn(
            "no_post_decision_store_event requires a known cached-token count", summary["basis"]
        )
        self.assertEqual(summary["no_identity_specific_store_cache_state_unknown_count"], 1)
        self.assertEqual(summary["no_post_decision_store_event_count"], 0)

    def test_known_cached_tokens_below_full_prompt_without_store_remains_no_post(self):
        self.assertEqual(
            correlate_routing_events(self.decisions(list(range(32)), cached=16), [])[0]["status"],
            "no_post_decision_store_event",
        )
        summary = summarize_routing_correlations(
            correlate_routing_events(self.decisions(list(range(32)), cached=16), [])
        )
        self.assertEqual(summary["no_post_decision_store_event_count"], 1)
        self.assertEqual(summary["no_identity_specific_store_cache_state_unknown_count"], 0)
        self.assertEqual(
            correlate_routing_events(self.decisions([1, 2, 3]), [])[0]["status"], "no_new_block"
        )
        with self.assertRaisesRegex(ValueError, "cached_prompt_tokens"):
            self.decisions(list(range(32)), cached=33)
        with self.assertRaisesRegex(ValueError, "16-token"):
            event_observations(
                0,
                [{"type": "BlockStored", "token_ids": list(range(32)), "block_size": 32}],
                observed_monotonic_ns=1,
            )


if __name__ == "__main__":
    unittest.main()
