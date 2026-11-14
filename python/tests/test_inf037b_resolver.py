"""Synthetic v4 setup evidence; no live fitness, marker or session controller."""

import unittest
from collections import UserDict
from dataclasses import FrozenInstanceError
from unittest.mock import patch

from inference_platform.inf037b_archive import IntegrityError
from inference_platform.inf037b_resolver import (
    BOUNDS_MS,
    PIN_NAMES,
    ROWS,
    SessionDeadline,
    allowance,
    remaining_work,
    resolve,
)

HASH = "a" * 64
PINS = dict.fromkeys(PIN_NAMES, HASH)


def proof():
    return {
        "path": "setup/fixture.jsonl",
        "sha256": HASH,
        "pins": PINS.copy(),
        "bounded_failure_recovery": True,
    }


def fixture():
    rows = {
        name: {
            "phase": "bringup",
            "attempt_id": None,
            "probe_count": 1,
            "pins": PINS.copy(),
            "sources": [{"path": "setup/fixture.jsonl", "sha256": HASH, "sequence": [1, 100]}],
            "observation_ms": [0, 1_000_000],
            "clock_uncertainty_ms": [0, 100],
            "clock_id": "mapped-boot-fixture",
            "selected_ms": 1_000_000,
        }
        for name in ROWS
    }
    rows["sse"].update(
        {
            "duration_ms": 120_000,
            "offers_per_100s": 1092,
            "max_tokens": 1,
            "alternating_gateways": True,
            "pod_deletions": 0,
            "identity_complete": True,
            "supervisor_receipt_joined": True,
            "signal_clock_joined": True,
            "gateway_traffic": {"gateway0": 1, "gateway1": 1},
            "live_samples": [
                {
                    "slot": slot,
                    "at_ms": 90_000 + slot * 30_000,
                    "gateway0": [1, 2],
                    "gateway1": [1, 2],
                    "target": [1, 2],
                }
                for slot in (0, 1)
            ],
            "windows": [
                {
                    "start_ms": n * 30_000,
                    "duration_ms": 30_000,
                    "misses_ppm": [0, 20_000],
                    "p95_lateness_ms": [0, 20],
                    "cpu_ppm": [0, 700_000],
                    "nic_ppm": [0, 700_000],
                }
                for n in range(4)
            ],
        }
    )
    rows["equivalence"].update(
        {
            "block_size": 16,
            "length": 8192,
            "max_seqs": 16,
            "l4_per_node": 1,
            "R": 4,
            "W": 1,
            "ttl_ms": 8000,
            "hold_ms": 2000,
            "operation_store_joined": True,
            "unexplained_reservations": 0,
            "restoration_controls_pass": True,
            "effective_pins": PINS.copy(),
            "workload_config": {
                "prefixes": 384,
                "prefix_tokens": 1024,
                "hot_prefixes": 96,
                "hot_percent": 80,
                "max_tokens": 1,
                "temperature": 0,
                "tenants": 1,
                "policy": "round_robin",
                "affinity": False,
                "escape": False,
                "seed": "inf037b-v1",
                "target_order": [0, 1, 0],
            },
            "controls": {
                "known2": 10,
                "known1": 5,
                "known0": 0,
                "expired": "refuse",
                "unknown": "refuse",
            },
            "report_ages_ms": {"gateway0": [0, 1000], "gateway1": [0, 1000]},
        }
    )
    rows["publication"].update(
        {
            "ttl_ms": 8000,
            "discovery_ms": 250,
            "health_ms": 250,
            "publication_ms": 250,
            "discovery_timeout_ms": 1000,
            "health_timeout_ms": 1000,
            "fresh_health_ms": [0, 1850],
            "gateways": {
                gateway: {
                    "store_clock_joined": True,
                    "atomic_order": [1, 2, 3],
                    "preceding_store_ms": [0, 0],
                    "install_ms": [3000, 3000],
                    "next_store_ms": [6100, 6100],
                }
                for gateway in ("gateway0", "gateway1")
            },
        }
    )
    rows["clocks"].update(
        {
            "maximum_uncertainty_ms": [0, 100],
            "maximum_gap_ms": [0, 2000],
            "cadence_ms": 1000,
            **dict.fromkeys(
                (
                    "entire_setup",
                    "probe_and_both_startups",
                    "all_endpoint_sequences_joined",
                    "boot_ids_complete",
                    "drift_applied",
                ),
                True,
            ),
            **dict.fromkeys(
                ("cross_boot_interpolation", "clock_step_interpolation", "overlap_order_assertion"),
                False,
            ),
        }
    )
    rows["ingress"].update(
        {
            "request_timeout_ms": 30_000,
            "transport_drain_ms": 5000,
            "grace_ms": 45_000,
            "joins": {
                name: {
                    "identity_exact": True,
                    "valid_finish_done": True,
                    "tls": True,
                    "incremental": True,
                    "upstream_attempts": 1,
                    "false_completion": False,
                    "content_ms": [0, 1],
                    "terminal_ms": [2, 3],
                }
                for name in ("g0s0", "g0s1", "g1s0", "g1s1")
            },
            "cancellations": {
                name: {"count": 1, "upstream_closed": True, "release_elapsed_ms": [0, 35_000]}
                for name in ("gateway0", "gateway1")
            },
        }
    )
    rows["startup"].update(
        {
            "components_ms": {
                "grace": 45_000,
                "kill_release": 15_000,
                "controller_scheduler": 30_000,
            },
            "component_proofs": {
                name: proof() for name in ("grace", "kill_release", "controller_scheduler")
            },
            "release_elapsed_ms": [0, 15_000],
            "controller_elapsed_ms": [0, 30_000],
            **dict.fromkeys(
                (
                    "two_slots_restored",
                    "probe_traffic_empty",
                    "reservations_empty",
                    "cached_same_node",
                    "cached_files_verified",
                    "no_cache_population",
                    "setup_pod_exit_gpu_release",
                    "no_rollout",
                    "cold_model_cache_empty",
                ),
                True,
            ),
            "case_order": ["cold", "node_cached"],
            "cases": {
                name: {
                    "model_cache_verified": True,
                    "image_cache_known": True,
                    "lifecycle_lineage": True,
                    "clocks_joined": True,
                    "pod_creation_ms": [0, 0] if name == "cold" else [310_000, 310_000],
                    "gpu_free_ms": [90_000, 90_000] if name == "cold" else [310_000, 310_000],
                    "completions_ms": {
                        "gateway0": [300_000, 300_000] if name == "cold" else [520_000, 520_000],
                        "gateway1": [300_000, 300_000] if name == "cold" else [520_000, 520_000],
                    },
                }
                for name in ("cold", "node_cached")
            },
        }
    )
    rows["lifecycle"].update(
        {
            "phases": {
                name: {
                    "offline_proof": proof(),
                    "offline_bound_ms": bound,
                    "observations_ms": [[0, bound // 2]] * {"attempt": 3, "reset": 2}.get(name, 1),
                }
                for name, bound in BOUNDS_MS.items()
            },
            "creation_from_t0": True,
            "cleanup_nonmutating": True,
            "replay_nonmutating": True,
            "replay_virtual_schedule_ms": [1_560_000] * 3 + [300_000] * 2,
            "transfer": {
                "sizing_proof": {"path": "offline/sizing.json", "sha256": HASH},
                "attempts": 3,
                "reset_durations_ms": [300_000] * 2,
                "full_fixture_sanitized_and_verified": True,
                "uses_rollout_compression": False,
                "raw_bytes": 450_000,
                "maximum_archive_bytes": 900_000,
                "minimum_bytes_per_second": 1000,
                "reconnect_ms": 0,
            },
        }
    )
    return rows


def assign(rows, path, value):
    obj = rows
    for key in path[:-1]:
        obj = obj[key]
    obj[path[-1]] = value


def removable_paths(value, prefix=()):
    if isinstance(value, dict):
        for key, item in value.items():
            path = (*prefix, key)
            if key != "attempt_id":
                yield path
            yield from removable_paths(item, path)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield (*prefix, index)
            yield from removable_paths(item, (*prefix, index))


def container_paths(value, prefix=()):
    if isinstance(value, dict):
        # Pin maps are tested through pin validation and key removal separately.
        if prefix and prefix[-1] not in ("pins", "effective_pins"):
            yield prefix
        for key, item in value.items():
            yield from container_paths(item, (*prefix, key))
    elif isinstance(value, list):
        if prefix and prefix[-1] not in ("pins", "effective_pins"):
            yield prefix
        for index, item in enumerate(value):
            yield from container_paths(item, (*prefix, index))


def replace_pin_maps(value, pins):
    if isinstance(value, dict):
        for key, item in value.items():
            if key in ("pins", "effective_pins"):
                value[key] = pins.copy()
            else:
                replace_pin_maps(item, pins)
    elif isinstance(value, list):
        for item in value:
            replace_pin_maps(item, pins)


class ResolverTests(unittest.TestCase):
    def refused(self, rows, reason="v4:"):
        with self.assertRaisesRegex(IntegrityError, reason):
            resolve(rows, pins=PINS)

    def test_all_seven_rows_inclusive_limits_and_receipt(self):
        rows = fixture()
        result = resolve(rows, pins=PINS)
        self.assertFalse(result["paid_ready"])
        self.assertEqual(result["allowances_ms"], BOUNDS_MS)
        self.assertEqual(set(result["rows"]), set(ROWS))
        self.assertEqual(result["rows"]["startup"]["result"]["D_bind_ms"], 90_000)
        rows["sse"]["pins"]["gpu"] = "b" * 64
        self.assertEqual(result["rows"]["sse"]["evidence"]["pins"], PINS)

    def test_each_row_ranges_reject_lower_and_upper_excess(self):
        cases = [
            (("sse", "live_samples", 0, "target"), [0, 1]),
            (("sse", "windows", 0, "misses_ppm"), [0, 20_001]),
            (("sse", "windows", 0, "p95_lateness_ms"), [0, 21]),
            (("sse", "windows", 0, "cpu_ppm"), [0, 700_001]),
            (("sse", "windows", 0, "nic_ppm"), [-1, 0]),
            (("equivalence", "report_ages_ms", "gateway1"), [0, 1001]),
            (("publication", "fresh_health_ms"), [0, 1851]),
            (("publication", "gateways", "gateway0", "preceding_store_ms"), [-1, 0]),
            (("publication", "gateways", "gateway1", "next_store_ms"), [6101, 6101]),
            (("clocks", "maximum_uncertainty_ms"), [0, 101]),
            (("clocks", "maximum_gap_ms"), [-1, 0]),
            (("clocks", "maximum_gap_ms"), [0, 2001]),
            (("ingress", "joins", "g0s0", "terminal_ms"), [1, 2]),
            (("ingress", "cancellations", "gateway1", "release_elapsed_ms"), [0, 35_001]),
            (("startup", "release_elapsed_ms"), [0, 15_001]),
            (("startup", "controller_elapsed_ms"), [-1, 0]),
            (("startup", "controller_elapsed_ms"), [0, 30_001]),
            (("startup", "cases", "cold", "completions_ms", "gateway0"), [300_001, 300_001]),
            (("lifecycle", "transfer", "minimum_bytes_per_second"), 499),
        ]
        for path, value in cases:
            with self.subTest(path=path, value=value):
                rows = fixture()
                assign(rows, path, value)
                self.refused(rows)
        for name in BOUNDS_MS:
            rows = fixture()
            rows["lifecycle"]["phases"][name]["observations_ms"][0] = [0, BOUNDS_MS[name] // 2 + 1]
            self.refused(rows)

    def test_provenance_and_sse_numeric_boundaries(self):
        for path, value in [
            (("clocks", "sources", 0, "sequence"), [-1, 1]),
            (("clocks", "observation_ms"), [-1, 0]),
            (("clocks", "clock_uncertainty_ms"), [0, 101]),
            (("clocks", "clock_id"), True),
            (("clocks", "sources", 0, "path"), 1),
            (("sse", "gateway_traffic", "gateway1"), 0),
            (("sse", "live_samples", 0, "at_ms"), 89_999),
            (("sse", "live_samples", 1, "at_ms"), 120_001),
        ]:
            rows = fixture()
            assign(rows, path, value)
            self.refused(rows)
        rows = fixture()
        rows["clocks"]["sources"][0]["sequence"] = [2**100, 2**100]
        rows["clocks"]["observation_ms"] = [0, 2**100]
        rows["clocks"]["selected_ms"] = 2**100
        rows["sse"]["live_samples"][0]["target"] = [2**100, 2**100]
        self.assertTrue(resolve(rows, pins=PINS)["rows"]["sse"]["admissible"])

    def test_no_best_probe_clamping_missing_or_rollout_inputs(self):
        for name in ROWS:
            for key, value in (
                ("probe_count", 2),
                ("phase", "event"),
                ("attempt_id", 1),
                ("sources", []),
                ("pins", {}),
                ("clock_uncertainty_ms", None),
            ):
                with self.subTest(row=name, key=key):
                    rows = fixture()
                    rows[name][key] = value
                    self.refused(rows)
            rows = fixture()
            del rows[name]
            self.refused(rows)
        rows = fixture()
        rows["sse"]["live_samples"][0]["target"] = [0, 0]
        rows["sse"]["live_samples"].insert(
            1, {**rows["sse"]["live_samples"][0], "at_ms": 95_000, "target": [1, 1]}
        )
        self.refused(rows, "sse:live:range")
        for value in (None, float("nan"), float("inf"), True, -1, "0"):
            rows = fixture()
            rows["clocks"]["maximum_uncertainty_ms"] = [0, value]
            self.refused(rows)

    def test_missing_every_required_leaf_fails_closed(self):
        # Remove each evidence leaf independently, including booleans and real zeros.
        def paths(value, prefix=()):
            if isinstance(value, dict):
                for key, item in value.items():
                    if key != "pins" and key != "effective_pins":
                        yield from paths(item, (*prefix, key))
            elif isinstance(value, list):
                for key, item in enumerate(value):
                    yield from paths(item, (*prefix, key))
            else:
                yield prefix

        for path in paths(fixture()):
            rows = fixture()
            assign(rows, path, None)
            if path[-1] == "attempt_id":
                continue  # null is the required literal here, not missing evidence.
            with self.subTest(path=path):
                self.refused(rows)

    def test_fixed_constants_controls_and_proofs(self):
        cases = [
            ("equivalence", "ttl_ms"),
            ("equivalence", "R"),
            ("publication", "health_ms"),
            ("publication", "ttl_ms"),
            ("ingress", "grace_ms"),
        ]
        for row, key in cases:
            rows = fixture()
            rows[row][key] += 1
            self.refused(rows)
        for path, value in [
            (("equivalence", "effective_pins", "model"), "b" * 64),
            (("equivalence", "controls", "known2"), 11),
            (("equivalence", "workload_config", "escape"), True),
            (("publication", "gateways", "gateway0", "atomic_order"), [1, 1, 2]),
            (("publication", "gateways", "gateway1", "store_clock_joined"), False),
            (("clocks", "cross_boot_interpolation"), True),
            (("ingress", "joins", "g1s1", "upstream_attempts"), 2),
            (("startup", "components_ms", "grace"), 46_000),
            (("startup", "cached_same_node"), False),
            (("startup", "component_proofs", "kill_release", "bounded_failure_recovery"), False),
            (("lifecycle", "transfer", "maximum_archive_bytes"), 450_000),
            (("lifecycle", "transfer", "reset_durations_ms"), [0, 0]),
        ]:
            rows = fixture()
            assign(rows, path, value)
            self.refused(rows)

    def test_completeness_sse_slots(self):
        rows = fixture()
        rows["sse"]["live_samples"].pop()
        self.refused(rows, "v4:sse:slots")

    def test_completeness_sse_traffic_keys(self):
        rows = fixture()
        del rows["sse"]["gateway_traffic"]["gateway1"]
        self.refused(rows, "v4:sse:traffic_keys")

    def test_completeness_sse_windows(self):
        rows = fixture()
        rows["sse"]["windows"].pop()
        self.refused(rows, "v4:sse:windows")

    def test_completeness_equivalence_reports(self):
        rows = fixture()
        del rows["equivalence"]["report_ages_ms"]["gateway1"]
        self.refused(rows, "v4:equivalence:reports")

    def test_completeness_publication_gateways(self):
        rows = fixture()
        del rows["publication"]["gateways"]["gateway1"]
        self.refused(rows, "v4:publication:gateways")

    def test_completeness_ingress_joins(self):
        rows = fixture()
        del rows["ingress"]["joins"]["g1s1"]
        self.refused(rows, "v4:ingress:joins")

    def test_completeness_ingress_cancellations(self):
        rows = fixture()
        del rows["ingress"]["cancellations"]["gateway1"]
        self.refused(rows, "v4:ingress:cancellations")

    def test_completeness_startup_proofs(self):
        rows = fixture()
        del rows["startup"]["component_proofs"]["grace"]
        self.refused(rows, "v4:startup:proofs")

    def test_completeness_startup_proof_pins(self):
        rows = fixture()
        rows["startup"]["component_proofs"]["grace"]["pins"]["gpu"] = "b" * 64
        self.refused(rows, "v4:startup:proof_pins")

    def test_completeness_startup_cases(self):
        rows = fixture()
        del rows["startup"]["cases"]["node_cached"]
        self.refused(rows, "v4:startup:cases")

    def test_completeness_startup_gateways(self):
        rows = fixture()
        del rows["startup"]["cases"]["cold"]["completions_ms"]["gateway1"]
        self.refused(rows, "v4:startup:gateways")

    def test_completeness_startup_completion_order(self):
        rows = fixture()
        rows["startup"]["cases"]["cold"]["completions_ms"]["gateway0"] = [89_999, 89_999]
        self.refused(rows, "v4:startup:completion_order")

    def test_completeness_allowance_observations(self):
        rows = fixture()
        rows["lifecycle"]["phases"]["attempt"]["observations_ms"].pop()
        self.refused(rows, "v4:allowance:observations")

    def test_completeness_lifecycle_phases(self):
        rows = fixture()
        del rows["lifecycle"]["phases"]["cleanup"]
        self.refused(rows, "v4:lifecycle:phases")

    def test_completeness_lifecycle_proof_pins(self):
        rows = fixture()
        rows["lifecycle"]["phases"]["creation"]["offline_proof"]["pins"]["gpu"] = "b" * 64
        self.refused(rows, "v4:lifecycle:proof_pins")

    def test_every_fixture_key_and_list_item_is_required(self):
        paths = tuple(removable_paths(fixture()))
        self.assertGreater(len(paths), 0)
        for path in paths:
            rows = fixture()
            parent = rows
            for part in path[:-1]:
                parent = parent[part]
            del parent[path[-1]]
            with self.subTest(path=path):
                with self.assertRaises(IntegrityError):
                    resolve(rows, pins=PINS)

    def test_every_container_substitution_is_a_row_integrity_refusal(self):
        paths = tuple(container_paths(fixture()))
        self.assertEqual(len(paths), 168)
        cases = 0
        for path in paths:
            for replacement in ("x", 7, [], {}):
                rows = fixture()
                assign(rows, path, replacement)
                with self.subTest(path=path, replacement=type(replacement).__name__):
                    with self.assertRaises(IntegrityError) as raised:
                        resolve(rows, pins=PINS)
                    message = str(raised.exception)
                    row_prefixes = (
                        ("v4:lifecycle:", "v4:allowance:")
                        if path[0] == "lifecycle"
                        else (f"v4:{path[0]}:",)
                    )
                    self.assertTrue(message.startswith(row_prefixes), message)
                    self.assertNotEqual(message, f"v4:{path[0]}:malformed", message)
                cases += 1
        self.assertEqual(cases, 672)

    def test_resolve_converts_unexpected_row_exception(self):
        with patch("inference_platform.inf037b_resolver.sse", side_effect=ValueError("bad row")):
            with self.assertRaisesRegex(IntegrityError, r"^v4:sse:malformed$"):
                resolve(fixture(), pins=PINS)

    def test_resolve_rejects_nonhex_pins_shared_by_every_row(self):
        for name in PIN_NAMES:
            with self.subTest(pin=name):
                rows = fixture()
                pins = PINS.copy()
                pins[name] = "g" * 64
                replace_pin_maps(rows, pins)
                with self.assertRaisesRegex(IntegrityError, r"^v4:pins$"):
                    resolve(rows, pins=pins)

    def test_resolve_rejects_nonmapping_rows(self):
        with self.assertRaisesRegex(IntegrityError, r"^v4:rows$"):
            resolve(list(ROWS), pins=PINS)

    def test_resolve_requires_builtin_pin_mapping(self):
        with self.assertRaisesRegex(IntegrityError, r"^v4:pins$"):
            resolve(fixture(), pins=UserDict(PINS))

    def test_resolve_rejects_extra_row(self):
        rows = fixture()
        rows["extra"] = {}
        with self.assertRaisesRegex(IntegrityError, r"^v4:rows$"):
            resolve(rows, pins=PINS)

    def test_nested_false_is_not_integer_zero(self):
        rows = fixture()
        rows["equivalence"]["workload_config"]["temperature"] = False
        self.refused(rows, "v4:equivalence:workload:temperature:fixed")

    def test_nested_false_is_not_integer_zero_inside_list(self):
        rows = fixture()
        rows["equivalence"]["workload_config"]["target_order"][0] = False
        self.refused(rows, "v4:equivalence:workload:target_order:fixed")

    def test_deadline_rejects_negative_billing_origin(self):
        with self.assertRaisesRegex(IntegrityError, "deadline:values"):
            SessionDeadline(4_600_000, 22_600_000, -1)

    def test_consume_time_requires_nonnegative_integer(self):
        deadline = SessionDeadline(4_600_000, 22_600_000, 1_000_000)
        for value in (-1, True):
            with self.subTest(value=value):
                with self.assertRaisesRegex(IntegrityError, "deadline:consume_time"):
                    deadline.check_consume(value)

    def test_provenance_selection_cannot_precede_observation_upper(self):
        rows = fixture()
        rows["sse"]["selected_ms"] = 999_999
        self.refused(rows, "v4:sse:selection_time")

    def test_sse_slot_must_be_an_integer_zero_or_one(self):
        rows = fixture()
        rows["sse"]["live_samples"][1]["slot"] = True
        self.refused(rows, "v4:sse:slot")

    def test_publication_atomic_order_must_be_strict(self):
        rows = fixture()
        rows["publication"]["gateways"]["gateway0"]["atomic_order"] = [1, 2, 2]
        self.refused(rows, "v4:publication:order")

    def test_startup_component_constants_cannot_trade_off_with_same_sum(self):
        rows = fixture()
        rows["startup"]["components_ms"].update(grace=44_000, kill_release=16_000)
        self.refused(rows, "v4:startup:components:fixed")

    def test_allowance_rejects_unknown_phase(self):
        with self.assertRaisesRegex(IntegrityError, "allowance:phase"):
            allowance("unknown", [[0, 0]], 1)

    def test_allowance_bound_is_exact_not_rounded_up(self):
        with self.assertRaisesRegex(IntegrityError, "allowance:offline_bound"):
            allowance("creation", [[0, 0]], BOUNDS_MS["creation"] - 1)

    def test_lifecycle_transfer_values_are_positive_and_nonnegative(self):
        for key, value, archive_bytes in (
            ("raw_bytes", 0, 0),
            ("minimum_bytes_per_second", 0, 900_000),
            ("reconnect_ms", -1, 900_000),
        ):
            with self.subTest(key=key, value=value):
                rows = fixture()
                transfer = rows["lifecycle"]["transfer"]
                transfer[key] = value
                transfer["maximum_archive_bytes"] = archive_bytes
                self.refused(rows, "v4:lifecycle:transfer_values")

    def test_remaining_work_requires_all_allowance_keys(self):
        allowances = BOUNDS_MS.copy()
        del allowances["attempt"]
        with self.assertRaisesRegex(IntegrityError, "remaining:allowances"):
            remaining_work(
                now_upper_ms=1_000_000,
                deadline=SessionDeadline(4_600_000, 22_600_000, 1_000_000),
                allowances=allowances,
                attempts=3,
                resets=2,
                unspent_setup_ms=0,
                before_attempt1=False,
            )

    def test_remaining_work_rejects_deadline_lookalike(self):
        class DeadlineLookalike:
            effective_ms = 19_000_000

        with self.assertRaisesRegex(IntegrityError, "remaining:immutable_deadline"):
            remaining_work(
                now_upper_ms=1_000_000,
                deadline=DeadlineLookalike(),
                allowances=BOUNDS_MS,
                attempts=3,
                resets=2,
                unspent_setup_ms=0,
                before_attempt1=False,
            )

    def test_remaining_work_rejects_one_tick_short_allowance(self):
        allowances = BOUNDS_MS.copy()
        allowances["attempt"] -= 1
        with self.assertRaisesRegex(IntegrityError, "remaining:attempt:fixed"):
            remaining_work(
                now_upper_ms=1_000_000,
                deadline=SessionDeadline(4_600_000, 22_600_000, 1_000_000),
                allowances=allowances,
                attempts=3,
                resets=2,
                unspent_setup_ms=0,
                before_attempt1=False,
            )

    def test_remaining_work_rejects_negative_unspent_setup(self):
        with self.assertRaisesRegex(IntegrityError, "remaining:values"):
            remaining_work(
                now_upper_ms=1_000_000,
                deadline=SessionDeadline(4_600_000, 22_600_000, 1_000_000),
                allowances=BOUNDS_MS,
                attempts=3,
                resets=2,
                unspent_setup_ms=-1,
                before_attempt1=False,
            )

    def test_remaining_work_initial_counts_must_be_three_attempts_two_resets(self):
        with self.assertRaisesRegex(IntegrityError, "remaining:initial_counts"):
            remaining_work(
                now_upper_ms=1_000_000,
                deadline=SessionDeadline(4_600_000, 22_600_000, 1_000_000),
                allowances=BOUNDS_MS,
                attempts=2,
                resets=2,
                unspent_setup_ms=0,
                before_attempt1=True,
            )

    def test_remaining_work_accepts_only_reachable_attempt_reset_pairs(self):
        reachable = {(3, 2), (2, 2), (2, 1), (1, 1), (1, 0), (0, 0)}
        for attempts in range(4):
            for resets in range(3):
                with self.subTest(attempts=attempts, resets=resets):
                    kwargs = dict(
                        now_upper_ms=1_000_000,
                        deadline=SessionDeadline(4_600_000, 22_600_000, 1_000_000),
                        allowances=BOUNDS_MS,
                        attempts=attempts,
                        resets=resets,
                        unspent_setup_ms=0,
                        before_attempt1=False,
                    )
                    if (attempts, resets) in reachable:
                        remaining_work(**kwargs)
                    else:
                        with self.assertRaisesRegex(IntegrityError, "remaining:counts"):
                            remaining_work(**kwargs)

    def test_startup_refuses_cached_case_before_cold_completion(self):
        rows = fixture()
        cached = rows["startup"]["cases"]["node_cached"]
        cached["pod_creation_ms"] = [0, 0]
        cached["gpu_free_ms"] = [0, 0]
        cached["completions_ms"] = {
            "gateway0": [100_000, 100_000],
            "gateway1": [100_000, 100_000],
        }
        self.refused(rows, "v4:startup:case_order_times")

    def test_startup_refuses_cached_gpu_free_equal_to_cold_completion(self):
        rows = fixture()
        cached = rows["startup"]["cases"]["node_cached"]
        cached["pod_creation_ms"] = [300_000, 300_000]
        cached["gpu_free_ms"] = [300_000, 300_000]
        cached["completions_ms"] = {
            "gateway0": [510_000, 510_000],
            "gateway1": [510_000, 510_000],
        }
        self.refused(rows, "v4:startup:case_order_times")

    def test_pending_and_delayed_creation_keep_full_D_bind(self):
        rows = fixture()
        case = rows["startup"]["cases"]["node_cached"]
        case["pod_creation_ms"] = [320_000, 320_000]
        case["completions_ms"] = dict.fromkeys(("gateway0", "gateway1"), [530_000, 530_000])
        result = resolve(rows, pins=PINS)["rows"]["startup"]["result"]
        self.assertEqual(result["cases"]["node_cached"]["D_bind_plus_U_ms"], 300_000)
        self.assertEqual(result["D_bind_ms"], 90_000)

    def test_every_admissible_integer_observation_has_L_equal_B(self):
        # Exhaust the actual public function's integer-ms domain for every phase.
        for name, bound in BOUNDS_MS.items():
            count = {"attempt": 3, "reset": 2}.get(name, 1)
            for observed in range(bound // 2 + 1):
                if allowance(name, [[0, observed]] * count, bound) != bound:
                    self.fail(f"{name}: L != B at O={observed}")

    def test_allowance_inclusive_limits(self):
        for name, bound in BOUNDS_MS.items():
            for upper in (0, 1, bound // 2 - 1, bound // 2):
                self.assertEqual(
                    allowance(name, [[0, upper]] * {"attempt": 3, "reset": 2}.get(name, 1), bound),
                    bound,
                )

    def test_allowance_range_defence_even_when_rounding_faults_low(self):
        # Isolate the O gate from the independent L gate (otherwise redundant).
        with patch("inference_platform.inf037b_resolver.ceil_minute", return_value=0):
            for name, bound in BOUNDS_MS.items():
                with self.assertRaisesRegex(IntegrityError, "allowance:" + name + ":range"):
                    allowance(
                        name, [[0, bound // 2 + 1]] * {"attempt": 3, "reset": 2}.get(name, 1), bound
                    )

    def test_L_ceiling_after_rounding_fault(self):
        with patch("inference_platform.inf037b_resolver.ceil_minute", return_value=3_600_001):
            with self.assertRaisesRegex(IntegrityError, "allowance:L_ceiling"):
                allowance("creation", [[0, 0]], 3_600_000)

    def test_startup_independent_defences(self):
        # Inject arithmetic/range-helper faults to exercise otherwise redundant gates.
        with patch("inference_platform.inf037b_resolver.sum", return_value=90_001, create=True):
            self.refused(fixture(), "startup:D_bind:range")
        from inference_platform import inf037b_resolver as module

        original = module.within

        def bypass_u(value, lower, upper, name):
            return value if name == "startup:U" else original(value, lower, upper, name)

        rows = fixture()
        rows["startup"]["cases"]["cold"]["completions_ms"]["gateway0"] = [300_001, 300_001]
        with patch.object(module, "within", side_effect=bypass_u):
            self.refused(rows, "startup:D_bind_plus_U:range")
        with patch("inference_platform.inf037b_resolver.sum", return_value=0, create=True):
            self.refused(rows, "startup:U:range")

    def test_fixture83_full_remaining_allowance_equality_and_tick_short(self):
        kwargs = dict(
            now_upper_ms=8_320_000,
            deadline=SessionDeadline(4_600_000, 22_600_000, 1_000_000),
            allowances=BOUNDS_MS,
            attempts=3,
            resets=2,
            unspent_setup_ms=0,
            before_attempt1=True,
        )
        self.assertEqual(remaining_work(**kwargs)["remaining_ms"], 10_680_000)
        with self.assertRaises(IntegrityError):
            remaining_work(**{**kwargs, "now_upper_ms": 8_320_001})
        later = {
            **kwargs,
            "attempts": 1,
            "resets": 1,
            "before_attempt1": False,
            "now_upper_ms": 11_740_001,
        }
        with self.assertRaisesRegex(IntegrityError, "remaining:deadline:range"):
            remaining_work(**later)
        with self.assertRaises(IntegrityError):
            remaining_work(**{**kwargs, "unspent_setup_ms": 1})

    def test_fixture83_late_consume_and_proposed_extension_refuse(self):
        deadline = SessionDeadline(4_600_000, 22_600_000, 1_000_000)
        self.assertEqual(deadline.effective_ms, 19_000_000)
        self.assertLess(deadline.effective_ms, deadline.session_ceiling_ms)
        self.assertTrue(deadline.check_consume(4_600_000)["consume_time_admissible"])
        with self.assertRaisesRegex(IntegrityError, "deadline:late_consume:range"):
            deadline.check_consume(4_600_001)
        early = SessionDeadline(20_000_000, 38_000_000, 1_000_000)
        self.assertTrue(early.check_consume(19_000_000)["consume_time_admissible"])
        with self.assertRaisesRegex(IntegrityError, "deadline:consume_effective:range"):
            early.check_consume(19_000_001)
        deadline.require_unchanged(latest_consume_ms=4_600_000, session_ceiling_ms=22_600_000)
        for consume, ceiling in ((4_600_000, 22_600_001), (4_600_001, 22_600_001)):
            with self.assertRaisesRegex(IntegrityError, "deadline:immutable_literals"):
                deadline.require_unchanged(latest_consume_ms=consume, session_ceiling_ms=ceiling)
        with self.assertRaises(FrozenInstanceError):
            deadline.session_ceiling_ms += 1
        with self.assertRaisesRegex(IntegrityError, "deadline:t0:range"):
            SessionDeadline(4_600_000, 22_600_000, 4_600_001)
        self.assertEqual(SessionDeadline(4_600_000, 22_600_000, 4_600_000).effective_ms, 22_600_000)
        with self.assertRaisesRegex(IntegrityError, "deadline:literal_session_ceiling"):
            SessionDeadline(4_600_000, 22_600_001, 1_000_000)
        for value in (None, True, float("nan"), -1):
            with self.assertRaises(IntegrityError):
                SessionDeadline(value, 22_600_000, 1_000_000)

    def test_transfer_reconnect_margin_and_no_float_rounding(self):
        rows = fixture()
        rows["lifecycle"]["transfer"].update(
            raw_bytes=885_000, maximum_archive_bytes=1_770_000, reconnect_ms=60_000
        )
        self.assertEqual(resolve(rows, pins=PINS)["allowances_ms"]["export"], 3_600_000)
        rows["lifecycle"]["transfer"]["reconnect_ms"] += 1
        self.refused(rows, "lifecycle:export_ceiling:range")

    def test_independent_export_and_campaign_ceilings(self):
        from inference_platform import inf037b_resolver as module

        original = module.ceil_minute

        def corrupt_transfer(numerator, denominator=1):
            return 3_600_001 if denominator != 1 else original(numerator, denominator)

        with patch.object(module, "ceil_minute", side_effect=corrupt_transfer):
            self.refused(fixture(), "lifecycle:export_ceiling:range")
        # Simulate corrupted event/reset arithmetic while the independent fixed
        # campaign ceiling must still preserve the complete campaign reserve.
        with patch.dict(module.BOUNDS_MS, attempt=0, reset=0):
            with self.assertRaisesRegex(IntegrityError, "remaining:campaign:range"):
                remaining_work(
                    now_upper_ms=8_320_001,
                    deadline=SessionDeadline(4_600_000, 22_600_000, 1_000_000),
                    allowances=module.BOUNDS_MS,
                    attempts=3,
                    resets=2,
                    unspent_setup_ms=0,
                    before_attempt1=True,
                )


if __name__ == "__main__":
    unittest.main()
