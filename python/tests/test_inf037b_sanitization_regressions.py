"""Live producer shapes and identity/structure collisions (R296/R297)."""

import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

import test_inf037b_collectors as fixtures

from inference_platform.inf037b_archive import encode, inspect_segment
from inference_platform.inf037b_campaign import sanitized_campaign
from inference_platform.inf037b_live import (
    ClientSSEAdapter,
    ClockAdapter,
    GatewayAdapter,
    KubernetesAdapter,
    LifecycleReceiptProducer,
    LiveRows,
    NodeCacheAdapter,
    NodeLifecycleAdapter,
    RedisAdapter,
    VLLMAdapter,
)
from inference_platform.inf037b_packet import Sanitizer
from inference_platform.inf037b_sources import EVENTS, ClockMapper, validate_payload

HASH = "a" * 64
KEY = b"r228-synthetic-sanitization-key-only"


def payload_valid(row):
    try:
        validate_payload(row)
        return True
    except (ValueError, TypeError, KeyError):
        return False


def dict_key_tree(value):
    if isinstance(value, dict):
        return {key: dict_key_tree(child) for key, child in value.items()}
    if isinstance(value, list):
        return [dict_key_tree(child) for child in value]
    return None


class LiveSanitizationRegressions(unittest.TestCase):
    def test_r296_every_live_adapter_event_preserves_payload_validity(self):
        rows = LiveRows("synthetic", "0", clock=lambda: 0)
        http, producer = Mock(), LifecycleReceiptProducer()
        adapters = [
            (ClientSSEAdapter(rows, "gateway0", HASH), "client"),
            (GatewayAdapter(rows, http, "gateway0", slot_names={}, config_sha256=HASH), "gateway"),
            (
                KubernetesAdapter(rows, http, "test", slot_names={}, lifecycle=producer),
                "kubernetes",
            ),
            (NodeLifecycleAdapter(rows, http, "pod", 0, producer), "kubernetes"),
            (NodeCacheAdapter(rows, http, "node"), "kubernetes"),
            (
                VLLMAdapter(
                    rows,
                    http,
                    pod_uid="pod",
                    slot=0,
                    process_generation="0",
                    model_sha256=HASH,
                    runtime_sha256=HASH,
                    semantics_sha256=HASH,
                ),
                "vllm",
            ),
            (RedisAdapter(rows, Mock(), "synthetic", HASH), "redis"),
            (ClockAdapter(rows), "clocks"),
        ]
        covered = []
        for adapter, kind in adapters:
            for event in EVENTS[kind].split():
                with self.subTest(adapter=type(adapter).__name__, event=event):
                    fields = {"retry_count": 0} if kind == "client" else {}
                    if kind == "kubernetes" and event == "snapshot":
                        fields["boundaries"] = {
                            "pods_resource_version": "1",
                            "endpointslices_resource_version": "2",
                        }
                    if isinstance(adapter, NodeCacheAdapter) and event == "container_state":
                        fields["boundaries"] = {
                            "cache_witness_ms_bounds": [0, 0],
                            "creation_ms_bounds": [1, 1],
                        }
                    row = adapter.rows.row(kind, kind, "0", event, fields)
                    safe = Sanitizer(KEY).row(row)
                    self.assertTrue(payload_valid(row))
                    self.assertEqual(payload_valid(safe), payload_valid(row))
                    self.assertEqual(dict_key_tree(safe), dict_key_tree(row))
                    covered.append((type(adapter).__name__, event))
        self.assertGreater(len(covered), 70)

        # Exercise the producer methods too, so changes to their actual nested
        # boundary names cannot silently escape the event-builder coverage.
        http.get.return_value = (encode({"metadata": {"resourceVersion": "1"}, "items": []}), {})
        kube = KubernetesAdapter(rows, http, "test", slot_names={}, lifecycle=producer)
        native_rows = list(kube.snapshot())
        node = NodeCacheAdapter(rows, http, "node")
        node.witness = {
            "boot_id": "0",
            "end_ns": 0,
            "image_cache_state": "cold",
            "model_cache_state": "cold",
        }
        clocks = Mock()
        clocks.map.return_value = [0, 0]
        native_rows.append(node.for_pod("pod", 0, creation_bounds=[1, 1], clocks=clocks))
        for row in native_rows:
            safe = Sanitizer(KEY).row(row)
            self.assertTrue(payload_valid(row))
            self.assertEqual(payload_valid(safe), payload_valid(row))
            self.assertEqual(dict_key_tree(safe), dict_key_tree(row))

    def test_r306_payload_allowlist_scopes_boundary_names_to_the_nested_object(self):
        row = LiveRows("synthetic", "0", clock=lambda: 0).row(
            "kubernetes",
            "kubernetes",
            "0",
            "snapshot",
            {
                "resource_version": "1",
                "endpoints": [],
                "list_valid": True,
                "boundaries": {"creation_ms_bounds": [1, 2]},
            },
        )
        validate_payload(row)
        bad_top_level = copy.deepcopy(row)
        bad_top_level["payload"]["creation_ms_bounds"] = [1, 2]
        with self.assertRaisesRegex(ValueError, "source_schema_unknown:creation_ms_bounds"):
            validate_payload(bad_top_level)
        bad_nested = copy.deepcopy(row)
        bad_nested["payload"]["boundaries"]["not_a_boundary"] = [1, 2]
        with self.assertRaisesRegex(ValueError, "source_schema_unknown_boundary:not_a_boundary"):
            validate_payload(bad_nested)

    def test_r307_unmapped_node_cache_error_rows_validate_and_sanitize(self):
        for case in ("no_mapping", "drift"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                self.root = Path(directory)
                cache_rows = LiveRows("fixture", "r307-" + case, clock=lambda: 10_000_000_000)
                node = NodeCacheAdapter(cache_rows, None, "node-r307-" + case)
                node.witness = {
                    "boot_id": "node-boot",
                    "end_ns": 10_000_000_000,
                    "image_cache_state": "cold",
                    "model_cache_state": "cold",
                }
                clock_rows = []
                clocks = ClockMapper([])
                if case == "drift":
                    clock_source = LiveRows("fixture", "r307-clock", clock=lambda: 500_000_000_000)
                    clock_adapter = ClockAdapter(clock_source)
                    clock_rows = [
                        clock_adapter.mapping(
                            "node:node-r307-drift",
                            "node-boot",
                            9_999,
                            500_000_000_000,
                            500_000_000_000,
                            wall_ms=1_700_000_000_000,
                        ),
                        clock_adapter.mapping(
                            "node:node-r307-drift",
                            "node-boot",
                            10_001,
                            500_103_000_000,
                            500_103_000_000,
                            wall_ms=1_700_000_000_103,
                        ),
                    ]
                    clocks = ClockMapper(clock_rows)

                row = node.for_pod(
                    "pod-r307-" + case,
                    0,
                    creation_bounds=[20_000, 20_000],
                    clocks=clocks,
                )
                self.assertEqual(row["error"], "node_cache_clock_or_creation_unmapped")
                self.assertEqual(row["payload"]["reason"], "cache_timing_not_established")
                self.assertIsNone(row["payload"]["boundaries"]["cache_witness_ms_bounds"])
                validate_payload(row)

                missing_error = copy.deepcopy(row)
                missing_error["error"] = None
                with self.assertRaisesRegex(
                    ValueError, "source_schema_bracket:cache_witness_ms_bounds"
                ):
                    validate_payload(missing_error)

                campaign, _ = fixtures.CampaignTests.campaign(
                    self,
                    name="r307-" + case,
                    extra_rows=[*clock_rows, row],
                )
                campaign.materialize()
                safe_root = self.root / ("safe-" + case)
                sanitized_campaign(campaign.root, safe_root, [campaign.spec], key=KEY)
                safe_kubernetes = inspect_segment(safe_root / "raw/kubernetes.jsonl")[1]
                safe_rows = [
                    item
                    for item in safe_kubernetes
                    if item["payload"].get("boundaries", {}).get("cache_witness_ms_bounds") is None
                    and isinstance(item.get("error"), str)
                    and item["error"]
                ]
                self.assertEqual(len(safe_rows), 1)
                validate_payload(safe_rows[0])
                self.assertIsNone(safe_rows[0]["payload"]["boundaries"]["cache_witness_ms_bounds"])

    def test_r305_unregistered_reservations_and_node_cache_witness_sanitize(self):
        from inference_platform.inf037b_live import NodeCacheAdapter

        held = "private-held-request"
        disappeared = "private-disappeared-request"
        records = fixtures.Records()
        extra_rows = [
            records.row(
                "redis",
                "snapshot",
                0,
                identity="redis-r305",
                redis_time_ms=0,
                reports={
                    "gateway0": {"n": 1, "expires_ms": 8000, "unknown": False},
                    "gateway1": {"n": 1, "expires_ms": 8000, "unknown": False},
                },
                lows=[],
                state={"n": 1, "candidate": None, "since_ms": None, "until_ms": None},
                active_reservations=[{"request_id": disappeared, "expiry_ms": 8000}],
                occupied=1,
                config_sha256=HASH,
            ),
            records.row(
                "client",
                "offer",
                1,
                identity="client-r305",
                request_id=held,
                offer_index=9001,
                prefix_id="private-prefix",
                gateway_uid="gateway0",
                config_sha256=HASH,
                policy="round-robin",
                retry_count=0,
                lateness_ms=0,
            ),
            records.row(
                "client",
                "offer",
                2,
                identity="client-r305",
                request_id=disappeared,
                offer_index=9002,
                prefix_id="private-prefix-2",
                gateway_uid="gateway0",
                config_sha256=HASH,
                policy="round-robin",
                retry_count=0,
                lateness_ms=0,
            ),
            records.row(
                "redis",
                "admit",
                3,
                identity="redis-r305",
                request_id=held,
                gateway_uid="gateway0",
                redis_time_ms=3,
                decision="allowed",
                effective_n=2,
                effective_b=10,
                idempotent=False,
            ),
            records.row(
                "redis",
                "admit",
                4,
                identity="redis-r305",
                request_id=disappeared,
                gateway_uid="gateway0",
                redis_time_ms=4,
                decision="allowed",
                effective_n=2,
                effective_b=10,
                idempotent=False,
            ),
        ]
        cache_rows = LiveRows("fixture", "r305-cache", clock=lambda: 10_000_000_000)
        node = NodeCacheAdapter(cache_rows, None, "node-r305")
        node.witness = {
            "boot_id": "node-boot",
            "end_ns": 10_000_000_000,
            "image_cache_state": "cold",
            "model_cache_state": "cold",
        }
        clocks = Mock()
        clocks.map.return_value = [10_000, 10_000]
        node_row = node.for_pod("new0", 0, creation_bounds=[10_001, 10_001], clocks=clocks)
        extra_rows.append(node_row)

        with tempfile.TemporaryDirectory() as directory:
            self.root = Path(directory)
            campaign, _ = fixtures.CampaignTests.campaign(
                self,
                name="raw",
                extra_rows=extra_rows,
                persistent_reservations=[held],
                first_content_before_signal=True,
            )
            campaign.materialize()
            raw = campaign.report()
            self.assertIn("unscheduled_request:" + held, raw["requests"]["validity_reasons"])
            self.assertIn("unscheduled_request:" + disappeared, raw["requests"]["validity_reasons"])
            self.assertIn(held, raw["stages"]["stage3"]["remaining_reservations"])
            operations = raw["stages"]["stage3"]["operations"]
            for request_id in (held, disappeared):
                self.assertIn(
                    "admit", [op["event"] for op in operations if op["request_id"] == request_id]
                )
                self.assertNotIn(
                    "release", [op["event"] for op in operations if op["request_id"] == request_id]
                )
            redis_snapshots = [
                row
                for row in inspect_segment(campaign.root / "raw/redis.jsonl")[1]
                if row["payload"]["event"] == "snapshot"
            ]
            prior_reservation = next(
                (
                    row
                    for row in redis_snapshots
                    if disappeared
                    in [item["request_id"] for item in row["payload"]["active_reservations"]]
                ),
                None,
            )
            self.assertIsNotNone(prior_reservation)
            later_snapshot = next(
                (
                    row
                    for row in redis_snapshots
                    if row["payload"]["redis_time_ms"]
                    > prior_reservation["payload"]["redis_time_ms"]
                ),
                None,
            )
            self.assertIsNotNone(later_snapshot)
            self.assertNotIn(
                disappeared,
                [item["request_id"] for item in later_snapshot["payload"]["active_reservations"]],
            )
            vanished = [
                outcome
                for outcome in raw["stages"]["operational_outcomes"]
                if outcome["reason"] == "reservation_disappeared_without_observed_release"
            ]
            self.assertTrue(any(disappeared in outcome["request_ids"] for outcome in vanished))
            self.assertTrue(
                raw["stages"]["stage1"]["sigterm_coverage"]["sets"]["target"]["after_first_content"]
            )
            cache_events = [
                row
                for row in inspect_segment(campaign.root / "raw/kubernetes.jsonl")[1]
                if row["payload"].get("node_pseudonym") == "node-r305"
            ]
            self.assertEqual(len(cache_events), 1)
            self.assertEqual(
                cache_events[0]["payload"]["boundaries"],
                {
                    "cache_witness_ms_bounds": [10_000, 10_000],
                    "creation_ms_bounds": [10_001, 10_001],
                },
            )
            exported = sanitized_campaign(
                campaign.root, Path(directory) / "safe", [campaign.spec], key=KEY
            )
            self.assertEqual(exported["summaries"][0]["summary_path"], "events/attempt-01.json")

    def test_r297_identity_collisions_leave_slots_and_reason_words_structural(self):
        with tempfile.TemporaryDirectory() as directory:
            self.root = Path(directory)
            campaign, _ = fixtures.CampaignTests.campaign(self)
            names = {"old0": "0", "old1": "missing_counter_bracket", "new0": "1"}
            names.update(
                {
                    offer["request_id"]: f"a1-pre-{i}"
                    for i, offer in enumerate(campaign.spec["expected_offers"])
                }
            )

            def replace(value, field=""):
                if isinstance(value, dict):
                    result = {k: replace(v, k) for k, v in value.items()}
                    if field == "reports" and result:
                        result["0"] = copy.deepcopy(next(iter(result.values())))
                    return result
                if isinstance(value, list):
                    return [replace(v, field) for v in value]
                if isinstance(value, str):
                    if value in names:
                        return names[value]
                    if field.endswith("_generation"):
                        return "0" if value == "boot0" else "1"
                return value

            campaign.spec = replace(copy.deepcopy(campaign.spec))
            for path in (campaign.root / "raw").glob("*.jsonl"):
                path.write_bytes(b"".join(encode(replace(row)) for row in inspect_segment(path)[1]))
            campaign.materialize()
            raw = campaign.report()
            self.assertIn("0", raw["requests"]["counts"]["generation"])
            self.assertIn("1", raw["requests"]["counts"]["generation"])
            self.assertIn("0", raw["recovery"]["baseline_windows"][0]["slots"])
            exported = sanitized_campaign(
                campaign.root, self.root / "safe", [campaign.spec], key=KEY
            )
            from inference_platform.inf037b_campaign import OfflineCampaign

            safe = OfflineCampaign(self.root / "safe", exported["specs"][0]).report()
            self.assertIn("0", safe["recovery"]["baseline_windows"][0]["slots"])
            self.assertEqual(
                raw["recovery"]["baseline_windows"][0]["validity_reasons"],
                safe["recovery"]["baseline_windows"][0]["validity_reasons"],
            )
            self.assertEqual(
                {
                    Sanitizer(KEY).value(v, "backend_uid")
                    for v in raw["requests"]["counts"]["generation"]
                },
                set(safe["requests"]["counts"]["generation"]),
            )

    def test_declared_diagnostic_identity_segment_preserves_words_and_event(self):
        from inference_platform.inf037b_campaign import _mapped_diagnostic, _mapped_report_facts

        sanitizer = Sanitizer(KEY)
        identity = "missing_counter_bracket:0"
        self.assertEqual(
            _mapped_diagnostic("multiple_request_boundaries:" + identity + ":content", sanitizer),
            "multiple_request_boundaries:" + sanitizer.value(identity, "request_id") + ":content",
        )
        self.assertEqual(
            _mapped_diagnostic("missing_counter_bracket:0", sanitizer), "missing_counter_bracket:0"
        )
        private_reason = "multiple_request_boundaries:private"
        mapped = sanitizer.value(private_reason, "reasons")
        self.assertEqual(
            _mapped_report_facts(
                {"reasons": [private_reason]}, sanitizer, {private_reason: mapped}
            ),
            {"reasons": [mapped]},
        )
