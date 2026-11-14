"""Observable raw-source refusals and derived :36-:40 rows, no live transport."""

import copy
import os
import unittest
from unittest.mock import patch

import test_inf037b_setup as setup_tests
from inf037b_fitness_fixture import attach
from inf037b_setup_fixture import fixture

import inference_platform.inf037b_setup_fitness as fitness_module
from inference_platform.inf037b_archive import IntegrityError, encode, sha, strict_json
from inference_platform.inf037b_resolver import clocks, equivalence, ingress, publication, sse
from inference_platform.inf037b_setup import SetupCollector
from inference_platform.inf037b_setup_fitness import (
    FitnessProducer,
    check_restoration_hold,
    fitness_request_joins,
)

CASES = []


def mutation_case(function, reason, occurrence=1):
    site = os.environ.get("INF037B_MUTATION_SITE_ID")
    if site is None or site.endswith(f":{function}:{reason}#{occurrence}"):
        return True
    if function == "probe" and reason.startswith("fitness:scheduled_"):
        return site.endswith(":probe:'fitness:scheduled_' + key#1")
    if function == "probe" and reason.startswith("fitness:actual_offer_"):
        return site.endswith(":probe:'fitness:actual_offer_' + key#1")
    if function == "cover" and reason == "fitness:resource_cadence":
        return site.endswith(f":cover:reason#{occurrence}")
    return False


def reorder(raw):
    raw["raw"].sort(key=lambda r: r["source_time"]["value"])
    sequences = {}
    for row in raw["raw"]:
        key = row["source_kind"], row["source_identity"], row["source_generation"]
        row["source_seq"] = sequences.get(key, 0)
        row["record_id"] = str(key) + str(row["source_seq"])
        sequences[key] = row["source_seq"] + 1
        row["observed_mono_ns"] = row["source_time"]["value"] * 1000000


class FitnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.value = attach(fixture())

    def producer(self, value=None, raw=None):
        value = value or self.value
        return FitnessProducer(
            raw or value["fitness_raw"],
            binding=value["binding"],
            artifacts=value["artifacts"],
            setup=SetupCollector(encode(value["bundle"]), **value["binding"]),
            allow_offline_fixture=True,
        )

    def test_restoration_hold_accepts_since_before_hold_start_snapshot_time(self):
        from inference_platform.inf037b_row5_capture import select_row5_snapshots

        producer = self.producer()
        snapshots = select_row5_snapshots(producer.c.rows)
        start = snapshots["hold_start"]["payload"]
        self.assertLess(start["state"]["since_ms"], start["redis_time_ms"])
        self.assertIsNone(check_restoration_hold(snapshots, producer.c.rows, 2000))

    def test_restoration_hold_requires_n1_candidate2_at_hold_start(self):
        from inference_platform.inf037b_row5_capture import select_row5_snapshots

        producer = self.producer()
        snapshots = select_row5_snapshots(producer.c.rows)
        snapshots["hold_start"]["payload"]["state"]["n"] = 2
        with self.assertRaisesRegex(IntegrityError, "fitness:hold_original_n"):
            check_restoration_hold(snapshots, producer.c.rows, 2000)

    def test_restoration_hold_missing_candidate_has_named_refusal(self):
        from inference_platform.inf037b_row5_capture import select_row5_snapshots

        producer = self.producer()
        snapshots = select_row5_snapshots(producer.c.rows)
        del snapshots["hold_start"]["payload"]["state"]["candidate"]
        with self.assertRaisesRegex(IntegrityError, "fitness:hold_candidate"):
            check_restoration_hold(snapshots, producer.c.rows, 2000)

    def test_restoration_hold_missing_since_has_named_refusal(self):
        from inference_platform.inf037b_row5_capture import select_row5_snapshots

        producer = self.producer()
        snapshots = select_row5_snapshots(producer.c.rows)
        del snapshots["hold_start"]["payload"]["state"]["since_ms"]
        with self.assertRaisesRegex(IntegrityError, "fitness:hold_since"):
            check_restoration_hold(snapshots, producer.c.rows, 2000)

    def test_restoration_hold_duration_starts_at_redis_since_time(self):
        from inference_platform.inf037b_row5_capture import select_row5_snapshots

        producer = self.producer()
        snapshots = select_row5_snapshots(producer.c.rows)
        end = snapshots["hold_end"]
        end["payload"]["redis_time_ms"] = 191998
        end["source_time"]["value"] = 191998
        end["time_ms_bounds"] = [191998, 191998]
        with self.assertRaisesRegex(IntegrityError, "fitness:restoration_hold"):
            check_restoration_hold(snapshots, producer.c.rows, 2000)

    def test_row5_requests_are_separate_from_the_fixed_probe_cohort(self):
        from test_inf037b_collectors import Records

        from inference_platform.inf037b_sources import SourceJoin

        records, rows, control_offers = Records(), [], []
        probe_rows, probe = records.request(
            "probe", "gateway0", offered=100, opened=110, first=120, terminal=130
        )
        rows.extend(probe_rows)
        for name in (
            "known0",
            "known1",
            "known2",
            "cached_stop_known1",
            "cached_restore_known2",
            "unknown",
            "expired",
            "post_outage_known2",
        ):
            for gateway in ("gateway0", "gateway1"):
                at = 200 + len(control_offers) * 40
                traffic, offer = records.request(
                    name + "-" + gateway,
                    gateway,
                    offered=at,
                    opened=at + 10,
                    first=at + 20,
                    terminal=at + 30,
                )
                rows.extend(traffic)
                control_offers.append({**offer, "snapshot_id": name})
        joined = SourceJoin(rows)
        self.assertFalse(joined.errors, joined.errors)
        probe_join, control_join = fitness_request_joins(joined.rows, [probe], control_offers, 1000)
        self.assertFalse(probe_join.errors)
        self.assertEqual(len(probe_join.cohorts), 1)
        self.assertEqual(len(control_join.cohorts), 16)
        broken = copy.deepcopy(control_offers)
        broken[0]["request_id"] = probe["request_id"]
        with self.assertRaisesRegex(IntegrityError, "fitness:control_requests"):
            fitness_request_joins(joined.rows, [probe], broken, 1000)
        with self.assertRaisesRegex(IntegrityError, "fitness:control_requests"):
            fitness_request_joins(joined.rows, [probe], control_offers[:-1], 1000)
        broken = copy.deepcopy(control_offers)
        broken[0]["snapshot_id"] = "known1"
        with self.assertRaisesRegex(IntegrityError, "fitness:control_requests"):
            fitness_request_joins(joined.rows, [probe], broken, 1000)
        with self.assertRaisesRegex(IntegrityError, "fitness:control_request_join"):
            fitness_request_joins(
                [
                    r
                    for r in joined.rows
                    if r["payload"].get("request_id") != control_offers[-1]["request_id"]
                ],
                [probe],
                control_offers,
                1000,
            )

    def test_live_control_inventory_requires_source_bound_row5_evidence(self):
        producer = self.producer()
        producer.control_requests.expected.append({"request_id": "control"})
        with self.assertRaisesRegex(IntegrityError, "fitness:row5_evidence_binding"):
            producer.equivalence_row()

    def refusal(self, mutate, reason, method="produce"):
        raw = strict_json(self.value["fitness_raw"])
        mutate(raw)
        # These are fresh hypothetical source streams, not damaged journals.
        # Keep sequence/arrival order valid so the target semantic guard is hit.
        reorder(raw)
        with self.assertRaisesRegex(IntegrityError, reason) as caught:
            getattr(self.producer(raw=encode(raw)), method)()
        CASES.append(
            {"raw_sha256": sha(encode(raw)), "reason": str(caught.exception), "method": method}
        )

    def test_all_five_rows_derive_without_resolver_fixtures_and_leave_inputs_unchanged(self):
        value = copy.deepcopy(self.value)
        self.assertNotIn("other_rows", value)
        original = copy.deepcopy(value)
        rows = self.producer(value).produce()
        self.assertEqual(value, original)
        self.assertEqual(sse(rows["sse"])["feasible"], True)
        self.assertEqual(
            equivalence(rows["equivalence"])["B_by_known_N"], {"2": 10, "1": 5, "0": 0}
        )
        self.assertEqual(
            publication(rows["publication"])["gateway0"],
            {"A_ms": [3000, 3000], "renewal_ms": [100, 100]},
        )
        self.assertEqual(clocks(rows["clocks"])["maximum_gap_ms"], 1000)
        self.assertEqual(ingress(rows["ingress"])["identity_joins"], 4)
        CASES.append(
            {
                "raw_sha256": sha(value["fitness_raw"]),
                "configuration_sha256": value["binding"]["pins"]["configuration"],
                "rows": rows,
                "nonmutating": True,
                "paid_ready": False,
            }
        )

    def test_configuration_pin_effective_pins_and_setup_only_refuse(self):
        value = copy.deepcopy(self.value)
        value["artifacts"]["fitness/config.json"] += b" "
        with self.assertRaisesRegex(IntegrityError, "fitness:configuration_hash"):
            self.producer(value)
        with self.assertRaisesRegex(IntegrityError, "fitness:configuration_artifact"):
            FitnessProducer(
                self.value["fitness_raw"],
                binding=self.value["binding"],
                artifacts={},
                setup=SetupCollector(encode(self.value["bundle"]), **self.value["binding"]),
            )
        self.refusal(
            lambda raw: next(
                r["payload"]["value"]
                for r in raw["raw"]
                if r["source_kind"] == "controller"
                and r["payload"].get("name", "").startswith("configuration:")
            ).update(runtime="f" * 64),
            "fitness:effective_pins",
        )
        self.refusal(lambda raw: raw["raw"][0].update(attempt_id=1), "setup:no_rollout")
        self.refusal(
            lambda raw: next(r for r in raw["raw"] if r["source_kind"] == "gateway")[
                "source_time"
            ].update(clock_id="measurement"),
            "fitness:source_clock_identity",
        )

    def test_setup_fitness_rows_refuse_future_selected_source(self):
        command = setup_tests.SetupTests().prepare(copy.deepcopy(self.value))
        command.sample = lambda: {
            "clock_id": "measurement",
            "boot_id": "host",
            "ms": [0, 0],
        }
        setup = SetupCollector(encode(self.value["bundle"]), **self.value["binding"])
        with self.assertRaisesRegex(IntegrityError, "setup:fitness_future_source"):
            command.fitness_rows(self.value, setup)

    def test_missing_signal_boot_source_and_supervisor_loss_refuse(self):
        self.refusal(
            lambda raw: raw["signal_processes"]["0"]["events"][-1].update(event="heartbeat"),
            "fitness:actual_signal",
            "probe",
        )
        self.refusal(
            lambda raw: raw["signal_processes"]["0"].update(supervisor_sha256="f" * 64),
            "fitness:signal_source",
            "probe",
        )
        self.refusal(
            lambda raw: raw["signal_processes"]["0"]["events"][-1].update(node_boot_id="reboot"),
            "fitness:signal_node_boot",
            "probe",
        )
        self.refusal(
            lambda raw: raw["supervisors"]["probe-uid0"].pop(3), "lifecycle_capture_lost", "probe"
        )

    def test_first_zero_coverage_sample_cannot_be_repaired_by_later_good_sample(self):
        def mutate(raw):
            row = next(
                r
                for r in raw["raw"]
                if r["payload"]["event"] == "sample" and r["payload"]["slot"] == 0
            )
            raw["raw"].append(copy.deepcopy(row))  # Later good 92s sample stays present.
            # Keep the first sample at the start, where no upstream is live.
            row["source_time"]["value"] = 91000
            for r in raw["raw"]:
                if r["payload"]["event"] == "accept" and r["payload"]["slot"] == 0:
                    t = r["source_time"]["value"]
                    if 90000 < t < 91000:
                        r["source_time"]["value"] = 91000

        self.refusal(mutate, "sse:live", "probe")

    def test_rate_trace_resource_limit_lateness_and_native_identity_refuse(self):
        self.refusal(
            lambda raw: raw["requests"][0].update(scheduled_ms=1001),
            "fitness:scheduled_time",
            "probe",
        )
        self.refusal(
            lambda raw: next(r for r in raw["raw"] if r["payload"]["event"] == "resource")[
                "payload"
            ]["value"].update(cpu_ppm=700001),
            "sse:cpu_ppm",
            "probe",
        )
        self.refusal(
            lambda raw: next(r for r in raw["raw"] if r["payload"]["event"] == "resource")[
                "payload"
            ].update(limit_known=False),
            "fitness:resource_limit",
            "probe",
        )

        def late(raw):
            for r in raw["raw"]:
                if (
                    r["source_kind"] == "client"
                    and r["payload"]["event"] == "offer"
                    and r["payload"]["request_id"].startswith("a1-pre-")
                ):
                    r["payload"]["dispatch_ms"] += 21

        self.refusal(late, "sse:lateness", "probe")
        self.refusal(
            lambda raw: next(r for r in raw["raw"] if r["payload"]["event"] == "accept")[
                "payload"
            ].update(pod_uid="wrong"),
            "fitness:native_uid",
            "probe",
        )

    def test_continuous_clocks_cover_startups_and_refuse_gap_reboot_step_and_drift(self):
        for field in ("gap", "boot", "step", "uncertainty"):

            def mutate(raw, field=field):
                for r in raw["raw"]:
                    p = r["payload"]
                    if p["event"] == "mapping" and p["clock_id"] == "client":
                        if field == "gap" and 10000 < p["remote_ms"] < 14000:
                            p["event"] = "missed"
                        if field == "boot" and p["remote_ms"] > 10000:
                            p["boot_id"] = "reboot"
                        if field == "step" and p["remote_ms"] > 10000:
                            p["local_wall_ms"] += 101
                        if field == "uncertainty":
                            p["receive_ms"] += 101

            with self.subTest(field=field):
                self.refusal(
                    mutate,
                    "setup:source_join",
                    "clock_row",
                )
        self.refusal(
            lambda raw: raw["raw"].__setitem__(
                slice(None),
                [
                    r
                    for r in raw["raw"]
                    if not (
                        r["payload"]["event"] == "mapping" and r["payload"]["clock_id"] == "client"
                    )
                ],
            ),
            "setup:source_join",
            "clock_row",
        )

    def test_atomic_control_response_ttl_unknown_hold_and_report_age_refuse(self):
        def change(name, key, value):
            def mutate(raw):
                row = next(
                    r
                    for r in raw["raw"]
                    if r["source_kind"] == "redis"
                    and r["payload"]["event"] == "snapshot"
                    and r["payload"]["snapshot_id"] == name
                )
                if key == "unknown":
                    for report in row["payload"]["reports"].values():
                        report["unknown"] = value
                elif key == "ttl":
                    row["payload"]["reports"]["gateway0"]["expires_ms"] += 1
                else:
                    row["payload"][key] = value

            return mutate

        self.refusal(change("known2", "occupied", 1), "fitness:occupied", "equivalence_row")
        self.refusal(change("known2", "ttl", 1), "fitness:report_ttl", "equivalence_row")
        self.refusal(
            change("unknown", "unknown", False), "fitness:expired_unknown", "equivalence_row"
        )
        self.refusal(change("hold_start", "unknown", True), "fitness:hold_fresh", "equivalence_row")
        self.refusal(
            change(
                "hold_start",
                "state",
                {"n": 2, "candidate": 2, "since_ms": 190000, "until_ms": 210000},
            ),
            "fitness:hold_original_n",
            "equivalence_row",
        )
        self.refusal(
            lambda raw: next(
                r
                for r in raw["raw"]
                if r["source_kind"] == "gateway" and r["payload"].get("snapshot_id") == "known2"
            )["payload"].update(effective_b=9),
            "fitness:control_ack_b",
            "equivalence_row",
        )

        def age(raw):
            for r in raw["raw"]:
                if r["payload"].get("snapshot_id") == "hold_end":
                    for report in r["payload"]["reports"].values():
                        report["expires_ms"] -= 1

        self.refusal(age, "equivalence:report_age", "equivalence_row")

    def test_publication_adjacent_store_clock_order_health_and_A_refuse(self):
        self.refusal(
            lambda raw: next(
                r
                for r in raw["raw"]
                if r["source_kind"] == "gateway" and r["payload"]["event"] == "install"
            )["payload"].update(store_order=20),
            "fitness:store_order_distinct",
            "publication_row",
        )
        self.refusal(
            lambda raw: next(
                r
                for r in raw["raw"]
                if r["source_kind"] == "gateway" and r["payload"]["event"] == "install"
            )["payload"].update(install_redis_ms_bounds=[511101, 511101]),
            "fitness:install_clock_join",
            "publication_row",
        )
        self.refusal(
            lambda raw: next(
                r
                for r in raw["raw"]
                if r["source_kind"] == "gateway" and r["payload"]["event"] == "health"
            )["payload"]["members"][0].update(healthy=False),
            "fitness:addition_healthy",
            "publication_row",
        )

        def old_store(raw):
            for r in raw["raw"]:
                p = r["payload"]
                if p["event"] == "report_store" and p.get("snapshot_id") == "prior":
                    r["source_time"]["value"] = 508099
                    p["redis_time_ms"] = 508099

        self.refusal(old_store, "publication:A", "publication_row")

    def test_ingress_buffering_tls_cancellation_release_and_identity_refuse(self):
        def buffered(raw):
            for r in raw["raw"]:
                if (
                    r["payload"].get("request_id") == "ingress-gateway0-0"
                    and r["payload"]["event"] == "sse"
                ):
                    r["source_time"]["value"] = 130100

        self.refusal(buffered, "ingress:increment_order", "ingress_row")
        self.refusal(
            lambda raw: next(
                r for r in raw["raw"] if r["payload"].get("name") == "tls:ingress-gateway0-0"
            )["payload"]["value"].update(verified=False),
            "fitness:tls_peer",
            "ingress_row",
        )

        def slow(raw):
            for r in raw["raw"]:
                if r["source_kind"] == "redis" and r["payload"]["event"] == "release":
                    at = 131030 + 35001
                    r["source_time"]["value"] = at
                    r["payload"]["redis_time_ms"] = at

        self.refusal(slow, "ingress:release", "ingress_row")
        self.refusal(
            lambda raw: next(
                r
                for r in raw["raw"]
                if r["source_kind"] == "redis" and r["payload"]["event"] == "release"
            )["payload"].update(reservation_id="other"),
            "fitness:cancel_reservation",
            "ingress_row",
        )

    def test_actual_setup_commands_capture_derive_and_resolve_without_other_rows(self):
        command = setup_tests.SetupTests().prepare(copy.deepcopy(self.value))
        prepared = command.store.state["preparation"]["data"]
        capture = command.store.state["fitness"]["capture"]
        self.assertEqual(bytes.fromhex(capture["raw_hex"]), self.value["fitness_raw"])
        self.assertEqual(
            set(prepared["other_rows"]), {"sse", "equivalence", "publication", "clocks", "ingress"}
        )
        self.assertFalse(command.store.state["resolution"]["result"]["paid_ready"])
        self.assertEqual(
            command.store.state["resolution"]["result"]["registration_id"], "inf037b-v4-r315"
        )

    def test_restoration_age_boundaries_periodic_stream_and_store_selection(self):
        self.assertEqual(
            self.producer().equivalence_row()["report_ages_ms"],
            {g: [1000, 1000] for g in ("gateway0", "gateway1")},
        )

        def change_age(raw, age):
            end = next(r for r in raw["raw"] if r["payload"].get("snapshot_id") == "hold_end")
            for r in end["payload"]["reports"].values():
                r.update(expires_ms=192000 - age + 8000, stored_ms=192000 - age)

        for age in (1001, 2000, -1):
            self.refusal(
                lambda raw, age=age: change_age(raw, age),
                "equivalence:report_age:range",
                "equivalence_row",
            )
        zero = strict_json(self.value["fitness_raw"])
        change_age(zero, 0)
        for r in zero["raw"]:
            if r["payload"]["event"] == "report_store" and r["source_time"]["value"] == 191000:
                r["source_time"]["value"] = 192000
                r["payload"]["redis_time_ms"] = 192000
            if (
                r["payload"]["event"] == "report_result"
                and r["payload"]["last_success_redis_ms"] == 191000
            ):
                r["source_time"]["value"] = 192100
                r["payload"]["last_success_redis_ms"] = 192000
        reorder(zero)
        self.assertEqual(
            self.producer(raw=encode(zero)).equivalence_row()["report_ages_ms"],
            {g: [0, 0] for g in ("gateway0", "gateway1")},
        )

        def stores(raw, mode):
            rows = [
                r
                for r in raw["raw"]
                if r["payload"]["event"] == "report_store" and r["source_time"]["value"] == 191000
            ]
            if mode == "missing":
                for r in rows:
                    raw["raw"].remove(r)
            elif mode == "early":
                for r in rows:
                    r["source_time"]["value"] = 189000
                    r["payload"].update(redis_time_ms=189000, snapshot_id="fitness_report")
            elif mode == "duplicate":
                raw["raw"].append(copy.deepcopy(rows[0]))
            elif mode == "time_order":
                newer = copy.deepcopy(rows[0])
                newer["source_time"]["value"] = 191100
                newer["payload"].update(redis_time_ms=191100, store_order=10)
                raw["raw"].append(newer)
            elif mode == "bad_state":
                rows[0]["payload"]["report_known"] = False
            elif mode == "n":
                rows[0]["payload"]["n"] = 1
            elif mode == "ack":
                for r in raw["raw"]:
                    if r["payload"]["event"] == "report_result":
                        r["payload"]["last_success_redis_ms"] = 190000

        for mode, reason in (
            ("missing", "fitness:restored_store$"),
            ("early", "fitness:restored_store_time"),
            ("duplicate", "fitness:restored_store_order"),
            ("time_order", "fitness:restored_store_order"),
            ("bad_state", "fitness:restored_store_state"),
            ("n", "fitness:restored_report_n"),
            ("ack", "fitness:report_ack_store"),
        ):
            self.refusal(lambda raw, mode=mode: stores(raw, mode), reason, "equivalence_row")
        raw = strict_json(self.value["fitness_raw"])
        # Many stores and results, all untrusted labels; select by atomic order.
        for row in list(raw["raw"]):
            if row["payload"]["event"] == "report_store" and row["source_time"]["value"] == 191000:
                for index, at in enumerate(range(190000, 191000, 250)):
                    periodic = copy.deepcopy(row)
                    periodic["source_time"]["value"] = at
                    periodic["payload"].update(
                        redis_time_ms=at, store_order=index, snapshot_id="fitness_report"
                    )
                    raw["raw"].append(periodic)
            if row["payload"]["event"] == "report_result":
                for delta in (250, 500, 750):
                    periodic = copy.deepcopy(row)
                    periodic["source_time"]["value"] += delta
                    raw["raw"].append(periodic)
        reorder(raw)
        self.producer(raw=encode(raw)).produce()
        CASES.append({"case": "periodic_reports", "raw_sha256": sha(encode(raw)), "pass": True})

    def test_resource_phase_overlap_maximum_gap_and_invalid_interval(self):
        for shift in (-500, -3, 3, 500):
            raw = strict_json(self.value["fitness_raw"])
            for row in raw["raw"]:
                p = row["payload"]
                if p["event"] == "resource" and row["source_time"]["value"] > 1000:
                    row["source_time"]["value"] += shift
                    p["window_start_ms"] += shift
                    p["window_end_ms"] += shift
            reorder(raw)
            self.producer(raw=encode(raw)).probe()
            CASES.append(
                {
                    "case": "resource_phase",
                    "phase_ms": shift,
                    "raw_sha256": sha(encode(raw)),
                    "pass": True,
                }
            )

        def gap(raw):
            raw["raw"] = [
                r
                for r in raw["raw"]
                if not (
                    r["payload"]["event"] == "resource"
                    and r["payload"]["role"] == "measurement"
                    and 10000 < r["source_time"]["value"] <= 14000
                )
            ]

        self.refusal(gap, "fitness:resource_cadence", "probe")
        for edge in ("start", "end"):

            def missing_edge(raw, edge=edge):
                raw["raw"] = [
                    r
                    for r in raw["raw"]
                    if not (
                        r["payload"]["event"] == "resource"
                        and r["payload"]["role"] == "measurement"
                        and (
                            r["source_time"]["value"] <= 2000
                            if edge == "start"
                            else r["source_time"]["value"] >= 121000
                        )
                    )
                ]

            self.refusal(missing_edge, "fitness:resource_cadence", "probe")

        def straddle(raw):
            r = next(
                r
                for r in raw["raw"]
                if r["payload"]["event"] == "resource" and r["source_time"]["value"] == 31000
            )
            r["source_time"]["value"] += 3
            r["payload"].update(window_start_ms=30997, window_end_ms=31003)
            r["payload"]["value"]["cpu_ppm"] = 700001

        self.refusal(straddle, "sse:cpu_ppm:range", "probe")
        self.refusal(
            lambda raw: next(r for r in raw["raw"] if r["payload"]["event"] == "resource")[
                "payload"
            ].pop("window_start_ms"),
            "fitness:resource_interval",
            "probe",
        )

    def test_cancel_requires_native_abort_and_joined_ordered_upstream_close(self):
        # Natural completion 30s after cancellation is still inside the 35s
        # release budget, but must never be classified as propagation.
        def natural(raw):
            for r in raw["raw"]:
                if (
                    r["source_kind"] == "vllm"
                    and r["payload"].get("request_id", "").startswith("cancel-")
                    and r["payload"]["event"] == "terminal"
                ):
                    r["source_time"]["value"] = 161030
                    r["payload"]["terminal_reason"] = "length"

        self.refusal(natural, "fitness:cancel_native_abort", "ingress_row")
        self.refusal(
            lambda raw: raw.update(
                raw=[r for r in raw["raw"] if r["payload"]["event"] != "upstream_close"]
            ),
            "fitness:cancel_upstream_close",
            "ingress_row",
        )
        self.refusal(
            lambda raw: next(r for r in raw["raw"] if r["payload"]["event"] == "upstream_close")[
                "payload"
            ].update(backend_slot=1),
            "fitness:cancel_close_identity",
            "ingress_row",
        )
        self.refusal(
            lambda raw: next(r for r in raw["raw"] if r["payload"]["event"] == "upstream_close")[
                "source_time"
            ].update(value=131029),
            "fitness:cancel_close_order",
            "ingress_row",
        )
        self.refusal(
            lambda raw: next(
                r
                for r in raw["raw"]
                if r["source_kind"] == "vllm"
                and r["payload"]["event"] == "terminal"
                and r["payload"].get("request_id", "").startswith("cancel-")
            )["payload"].pop("terminal_reason"),
            "fitness:cancel_native_abort",
            "ingress_row",
        )
        self.assertTrue(
            all(
                c["upstream_closed"]
                for c in self.producer().ingress_row()["cancellations"].values()
            )
        )

    def test_production_command_refuses_missing_fitness_raw(self):
        from inference_platform.inf037b_setup import SetupCommands

        command = object.__new__(SetupCommands)
        with self.assertRaisesRegex(IntegrityError, "setup:fitness_raw_required"):
            command.fitness_rows({"other_rows": {}}, None)

    def test_probe_gateway_route_fallback_without_optional_native_requests(self):
        raw = strict_json(self.value["fitness_raw"])
        raw["raw"] = [
            r
            for r in raw["raw"]
            if not (
                r["source_kind"] == "vllm"
                and r["payload"]["event"] in ("accept", "terminal")
                and r["payload"].get("request_id", "").startswith("a1-pre-")
            )
        ]
        reorder(raw)
        row = self.producer(raw=encode(raw)).probe()
        self.assertTrue(sse(row)["feasible"])
        CASES.append(
            {
                "case": "gateway_route_liveness_fallback",
                "raw_sha256": sha(encode(raw)),
                "feasible": True,
            }
        )
        wrong = copy.deepcopy(raw)
        for r in wrong["raw"]:
            if r["payload"].get("request_id") == "a1-pre-0" and r["payload"].get("backend_uid"):
                r["payload"]["backend_uid"] = "wrong-but-consistent-route"
        with self.assertRaisesRegex(IntegrityError, "fitness:direct_uid"):
            self.producer(raw=encode(wrong)).probe()
        # A partial native pair cannot silently select the fallback.
        self.refusal(
            lambda r: r.update(
                raw=[
                    x
                    for x in r["raw"]
                    if not (
                        x["source_kind"] == "vllm"
                        and x["payload"]["event"] == "terminal"
                        and x["payload"].get("request_id") == "a1-pre-0"
                    )
                ]
            ),
            "fitness:native_endpoints",
            "probe",
        )

    def test_native_abort_reason_and_close_schema_survive_sanitization(self):
        from inference_platform.inf037b_packet import Sanitizer
        from inference_platform.inf037b_sources import validate_payload

        raw = strict_json(self.value["fitness_raw"])
        sanitizer = Sanitizer(b"schema-test-key" * 4)
        for r in raw["raw"]:
            if (
                r["payload"].get("terminal_reason") == "client_cancel_abort"
                or r["payload"]["event"] == "upstream_close"
            ):
                validate_payload(r)
                safe = sanitizer.row(r)
                validate_payload(safe)
                self.assertEqual(safe["payload"]["event"], r["payload"]["event"])
                if "terminal_reason" in r["payload"]:
                    self.assertEqual(safe["payload"]["terminal_reason"], "client_cancel_abort")

    def test_fitness_constructor_guards_refuse_by_named_reason(self):
        path = "fitness/config.json"

        def construct(
            reason,
            *,
            change_config=None,
            change_binding=None,
            rows=None,
            ack_value=None,
            ack_hash=None,
            ack_time=None,
            request_error=False,
        ):
            config = strict_json(self.value["artifacts"][path])
            binding = copy.deepcopy(self.value["binding"])
            if change_config:
                change_config(config)
            if change_binding:
                change_binding(binding)
            artifact = encode(config)
            binding["pins"]["configuration"] = sha(artifact)

            class FakeCollector:
                def __init__(self, raw, **kwargs):
                    self.bundle = {"fitness_configuration": path, "requests": []}
                    self.rows = copy.deepcopy(rows or [])

                def one(self, source_kind, event, **fields):
                    return {
                        "payload": {
                            "input_sha256": binding["pins"]["configuration"]
                            if ack_hash is None
                            else ack_hash,
                            "value": copy.deepcopy(binding["pins"])
                            if ack_value is None
                            else copy.deepcopy(ack_value),
                        },
                        "time_ms_bounds": [0, 0] if ack_time is None else list(ack_time),
                    }

                def row(self, pins):
                    return {"selected_ms": config["probe_end_ms"] + 1}

            class FakeRequestJoin:
                def __init__(self, rows, requests, selected_ms):
                    self.errors = ["synthetic-invalid"] if request_error else []
                    self.operational = []
                    self.cohorts = []

            with (
                patch.object(fitness_module, "SetupCollector", FakeCollector),
                patch.object(fitness_module, "RequestJoin", FakeRequestJoin),
            ):
                with self.assertRaisesRegex(IntegrityError, reason):
                    FitnessProducer(
                        b"synthetic",
                        binding=binding,
                        artifacts={path: artifact},
                        setup=None,
                    )

        expected_clocks = [
            {"clock_id": "redis", "boot_id": "redisboot"},
            {"clock_id": "node:node0", "boot_id": "nodeboot"},
            {"clock_id": "node:node1", "boot_id": "nodeboot1"},
            {"clock_id": "gateway0", "boot_id": "gboot0"},
            {"clock_id": "gateway1", "boot_id": "gboot1"},
            {"clock_id": "client", "boot_id": "clientboot"},
        ]
        construct(
            "fitness:configuration_schema",
            change_config=lambda config: config.update(schema="wrong"),
        )
        construct(
            "fitness:required_roles",
            change_config=lambda config: config.update(roles=config["roles"][:-1]),
        )
        construct(
            "fitness:required_clocks",
            change_config=lambda config: config.update(clocks=config["clocks"][:-1]),
        )
        construct(
            "fitness:single_clock_boot_inventory",
            change_config=lambda config: config["clocks"].append(copy.deepcopy(expected_clocks[0])),
        )
        construct(
            "fitness:single_probe_duration",
            change_config=lambda config: config.update(probe_end_ms=config["probe_end_ms"] + 1),
        )
        construct(
            "fitness:probe_origin",
            change_binding=lambda binding: binding.update(t0_ms=binding["t0_ms"] + 1),
        )
        construct(
            "fitness:slots",
            change_config=lambda config: config["slots"].pop("1"),
        )
        construct(
            "fitness:distinct_placements",
            change_config=lambda config: config["slots"]["1"].update(
                uid=config["slots"]["0"]["uid"], node=config["slots"]["0"]["node"]
            ),
        )
        construct(
            "fitness:gateway_source",
            rows=[{"source_kind": "gateway", "payload": {"gateway_uid": "foreign"}}],
        )
        construct(
            "fitness:native_source_slot",
            rows=[{"source_kind": "vllm", "payload": {"slot": 99}}],
        )
        construct(
            "fitness:source_clock_identity",
            rows=[
                {
                    "source_kind": "gateway",
                    "payload": {"gateway_uid": "gateway0"},
                    "source_time": {"clock_id": "wrong"},
                    "source_generation": "gboot0",
                }
            ],
        )
        construct(
            "fitness:source_clock_boot",
            rows=[
                {
                    "source_kind": "gateway",
                    "payload": {"gateway_uid": "gateway0"},
                    "source_time": {"clock_id": "gateway0"},
                    "source_generation": "wrong",
                }
            ],
        )
        construct(
            "fitness:effective_config",
            ack_hash="wrong",
        )
        construct(
            "fitness:effective_pins",
            change_config=lambda config: config.update(sse={**config["sse"], "duration_ms": 1}),
            ack_value={"wrong": "pins"},
        )
        construct(
            "fitness:config_before_probe",
            ack_time=[1001, 1001],
        )
        construct("fitness:request_join", request_error=True)
        duplicate_native = [
            {
                "source_kind": "vllm",
                "source_time": {"clock_id": "node:node0"},
                "source_generation": "nodeboot",
                "payload": {"event": "accept", "request_id": "r", "slot": 0},
            },
            {
                "source_kind": "vllm",
                "source_time": {"clock_id": "node:node0"},
                "source_generation": "nodeboot",
                "payload": {"event": "accept", "request_id": "r", "slot": 0},
            },
        ]
        construct("fitness:unique_native_request", rows=duplicate_native)

    def test_native_identity_and_order_guards_refuse_by_named_reason(self):
        def refuse(reason, *, request_change=None, event_change=None, omit=None):
            producer = object.__new__(FitnessProducer)
            producer.pins = self.value["binding"]["pins"]
            producer.config = strict_json(self.value["artifacts"]["fitness/config.json"])
            uid = producer.config["slots"]["0"]["uid"]
            process = producer.config["slots"]["0"]["process_generation"]
            request = {
                "backend_uid": uid,
                "backend_slot": 0,
                "request_id": "native-test",
                "upstream_open_ms_bounds": [10, 10],
            }
            if request_change:
                request_change(request)

            def native_row(at):
                return {
                    "payload": {
                        "pod_uid": uid,
                        "slot": 0,
                        "model_sha256": producer.pins["model"],
                        "runtime_sha256": producer.pins["runtime"],
                        "process_generation": process,
                    },
                    "time_ms_bounds": [at, at],
                }

            accepted, ended = native_row(20), native_row(30)
            if event_change:
                event_change(accepted, ended)
            producer.native_events = {}
            if omit != "accept":
                producer.native_events["accept", "native-test"] = accepted
            if omit != "terminal":
                producer.native_events["terminal", "native-test"] = ended
            with self.assertRaisesRegex(IntegrityError, reason):
                producer.native(request)

        refuse(
            "fitness:direct_uid", request_change=lambda request: request.update(backend_uid="wrong")
        )
        refuse("fitness:native_endpoints", omit="terminal")
        refuse(
            "fitness:native_uid",
            event_change=lambda accepted, ended: accepted["payload"].update(pod_uid="wrong"),
        )
        refuse(
            "fitness:native_slot",
            event_change=lambda accepted, ended: accepted["payload"].update(slot=1),
        )
        refuse(
            "fitness:native_model",
            event_change=lambda accepted, ended: accepted["payload"].update(model_sha256="wrong"),
        )
        refuse(
            "fitness:native_runtime",
            event_change=lambda accepted, ended: accepted["payload"].update(runtime_sha256="wrong"),
        )
        refuse(
            "fitness:native_process",
            event_change=lambda accepted, ended: accepted["payload"].update(
                process_generation="wrong"
            ),
        )
        refuse(
            "fitness:native_order",
            event_change=lambda accepted, ended: accepted.update(time_ms_bounds=[9, 9]),
        )

    def test_probe_guard_refusals_have_named_reasons(self):
        def reject(reason, change):
            if not mutation_case("probe", reason):
                return
            producer = self.producer()
            change(producer)
            with self.assertRaisesRegex(IntegrityError, reason):
                producer.probe()

        reject("fitness:signal_origin", lambda p: p.c.bundle["signal_processes"]["0"].pop("origin"))
        for field in ("role", "node", "slot", "supervisor_sha256"):
            reject(
                "fitness:signal_origin",
                lambda p, field=field: p.c.bundle["signal_processes"]["0"]["origin"].update(
                    {field: "wrong"}
                ),
            )
        reject(
            "fitness:signal_receipt",
            lambda p: next(
                e for e in p.c.bundle["signal_processes"]["0"]["events"] if e["event"] == "signal"
            )["signal_data"].clear(),
        )
        reject(
            "fitness:signal_clock_join",
            lambda p: next(
                e for e in p.c.bundle["signal_processes"]["0"]["events"] if e["event"] == "signal"
            )["signal_data"].update(receipt_ns=2000000000),
        )

        reject(
            "fitness:probe_offers",
            lambda p: p.requests.cohorts.pop(
                next(
                    i
                    for i, request in enumerate(p.requests.cohorts)
                    if request["request_id"] == "a1-pre-0"
                )
            ),
        )
        for key, reason in (
            ("offer_index", "fitness:scheduled_offer_index"),
            ("prefix_id", "fitness:scheduled_prefix_id"),
            ("gateway_uid", "fitness:scheduled_gateway_uid"),
        ):

            def change(p, key=key):
                next(
                    offer for offer in p.c.bundle["requests"] if offer["request_id"] == "a1-pre-0"
                )[key] = "wrong"

            reject(reason, change)
        reject(
            "fitness:single_offer",
            lambda p: p.request_events.pop(("client", "offer", "a1-pre-0")),
        )
        for key, reason in (
            ("offer_index", "fitness:actual_offer_offer_index"),
            ("prefix_id", "fitness:actual_offer_prefix_id"),
            ("gateway_uid", "fitness:actual_offer_gateway_uid"),
            ("config_sha256", "fitness:actual_offer_config_sha256"),
        ):

            def change(p, key=key):
                p.request_events[("client", "offer", "a1-pre-0")][0]["payload"][key] = "wrong"

            reject(reason, change)
        reject(
            "fitness:dispatch",
            lambda p: p.by_id["a1-pre-0"].update(dispatch_ms_bounds=None),
        )
        reject(
            "fitness:probe_completion",
            lambda p: p.by_id["a1-pre-0"].update(identity_join_valid=False),
        )
        reject(
            "fitness:no_probe_deletion",
            lambda p: setattr(
                p.c,
                "find",
                lambda source, event, **fields: (
                    [{}] if source == "kubernetes" and event == "deletion" else []
                ),
            ),
        )
        reject(
            "fitness:supervisor_source",
            lambda p: p.c.bundle.update(supervisors_source_sha256="f" * 64),
        )
        reject(
            "fitness:supervisor_uid",
            lambda p: p.c.bundle["supervisors"]["probe-uid0"][0].update(pod_uid="wrong"),
        )
        reject(
            "fitness:supervisor_node_boot",
            lambda p: p.c.bundle["supervisors"]["probe-uid0"][0].update(node_boot_id="wrong"),
        )
        reject(
            "fitness:supervisor_process",
            lambda p: p.c.bundle["supervisors"]["probe-uid0"][0].update(boot_id="wrong"),
        )

        def wrong_supervisor_window(p):
            p.c.join.clocks.map = lambda *args: [p.start + 1, p.end]

        reject("fitness:supervisor_window", wrong_supervisor_window)
        reject(
            "fitness:separate_signal_process",
            lambda p: p.c.bundle["signal_processes"]["0"].update(uid="probe-uid0"),
        )
        reject(
            "fitness:signal_source",
            lambda p: p.c.bundle["signal_processes"]["0"].update(supervisor_sha256="f" * 64),
        )
        reject(
            "fitness:signal_uid",
            lambda p: p.c.bundle["signal_processes"]["0"]["events"][0].update(pod_uid="wrong"),
        )
        reject(
            "fitness:signal_node_boot",
            lambda p: p.c.bundle["signal_processes"]["0"]["events"][0].update(node_boot_id="wrong"),
        )

        def wrong_signal_clock(p):
            original = p.c.join.clocks.map

            def mapped(clock, boot, lo, hi):
                return [p.start - 1, p.start - 1] if lo == hi else original(clock, boot, lo, hi)

            p.c.join.clocks.map = mapped

        reject("fitness:signal_clock_join", wrong_signal_clock)

        def wrong_sample_uid(p):
            sample = next(
                r for r in p.c.find("vllm", "sample") if p.start + 90000 <= r["time_ms_bounds"][0]
            )
            sample["payload"]["pod_uid"] = "wrong"

        reject("fitness:sample_uid", wrong_sample_uid)
        reject(
            "fitness:resource_values",
            lambda p: p.c.find("controller", "resource")[0]["payload"]["value"].update(cpu_ppm=-1),
        )

        def no_dispatch_lateness(p):
            for request in p.requests.cohorts:
                if request["request_id"].startswith("a1-pre-"):
                    request["outcome"] = "missed_offer"
                    request["dispatch_ms_bounds"] = None
                    offer = next(
                        o
                        for o in p.c.bundle["requests"]
                        if o["request_id"] == request["request_id"]
                    )
                    p.request_events[("client", "missed", request["request_id"])] = [
                        {
                            "payload": {
                                key: offer[key]
                                for key in (
                                    "offer_index",
                                    "prefix_id",
                                    "gateway_uid",
                                    "config_sha256",
                                )
                            }
                        }
                    ]

        reject("fitness:dispatch_window", no_dispatch_lateness)

        def wrong_scheduled_time(p):
            offer = next(o for o in p.c.bundle["requests"] if o["request_id"] == "a1-pre-0")
            offer["scheduled_ms"] += 1

        reject("fitness:scheduled_time", wrong_scheduled_time)

    def test_clock_publication_ingress_and_cancel_guards_refuse_by_named_reason(self):
        def reject(function, reason, change):
            if not mutation_case(function, reason):
                return
            producer = self.producer()
            change(producer)
            with self.assertRaisesRegex(IntegrityError, reason):
                getattr(producer, function)()

        def clock_inventory(p):
            p.c.join.clocks.maps.pop(next(iter(p.c.join.clocks.maps)))

        reject("clock_row", "fitness:clock_inventory", clock_inventory)

        def entire_setup(p):
            maps = next(iter(p.c.join.clocks.maps.values()))
            maps[0]["send_ms"] = 10**15

        reject("clock_row", "fitness:entire_setup_clock", entire_setup)

        def clock_continuity(p):
            p.c.join.clocks.map = lambda *args: None

        reject("clock_row", "fitness:clock_continuity", clock_continuity)

        def startup_inventory(p):
            next(r for r in p.setup.rows if r["source_kind"] == "clocks")["payload"]["clock_id"] = (
                "foreign-clock"
            )

        reject("clock_row", "fitness:startup_clock_inventory", startup_inventory)

        def startup_clock_join(p):
            p.setup.join.clocks.map = lambda *args: [0, 0]

        reject("clock_row", "fitness:startup_clock_join", startup_clock_join)

        def clock_endpoints(p):
            for key, maps in p.c.join.clocks.maps.items():
                item = copy.deepcopy(maps[0])
                item["send_ms"] = 0
                item["receive_ms"] = 10**15
                p.c.join.clocks.maps[key] = [item]
            p.c.join.clocks.map = lambda *args: [0, 0]
            p.setup.join.clocks.map = lambda *args: [0, 0]

        reject("clock_row", "fitness:clock_endpoints", clock_endpoints)

        def publication_install(p):
            p.c.rows[:] = [
                r
                for r in p.c.rows
                if not (r["source_kind"] == "gateway" and r["payload"]["event"] == "install")
            ]

        reject("publication_row", "fitness:publication_install", publication_install)

        def startup_addition_uid(p):
            p.config["addition_uid"] = "other-uid"
            for row in p.c.rows:
                if row["source_kind"] == "gateway" and row["payload"]["event"] == "install":
                    row["payload"]["replacement_uid"] = "other-uid"

        reject("publication_row", "fitness:startup_addition_uid", startup_addition_uid)

        def addition_after_ready(p):
            p.setup.at = lambda *args, **kwargs: [10**15, 10**15]

        reject("publication_row", "fitness:addition_after_ready", addition_after_ready)

        def publication_report(p):
            next(
                r
                for r in p.c.rows
                if r["source_kind"] == "redis" and r["payload"]["event"] == "report_store"
            )["payload"]["report_success"] = False

        reject("publication_row", "fitness:publication_report", publication_report)

        def store_time_order(p):
            p.redis_time = lambda row: row["time_ms_bounds"]
            stores = [
                r
                for r in p.c.rows
                if r["source_kind"] == "redis"
                and r["payload"]["event"] == "report_store"
                and r["payload"]["gateway_uid"] == "gateway0"
            ]
            stores.sort(key=lambda r: r["payload"]["store_order"])
            stores[0]["time_ms_bounds"] = [100, 200]
            stores[1]["time_ms_bounds"] = [150, 250]

        reject("publication_row", "fitness:store_time_order", store_time_order)

        def publication_adjacent_stores(p):
            for row in p.c.rows:
                if row["source_kind"] == "gateway" and row["payload"]["event"] == "install":
                    row["payload"]["store_order"] = 10**6

        reject(
            "publication_row", "fitness:publication_adjacent_stores", publication_adjacent_stores
        )

        def publication_health(p):
            p.c.rows[:] = [
                r
                for r in p.c.rows
                if not (r["source_kind"] == "gateway" and r["payload"]["event"] == "health")
            ]

        reject("publication_row", "fitness:publication_health", publication_health)

        reject(
            "ingress_row",
            "fitness:ingress_gateway",
            lambda p: p.by_id["ingress-gateway0-0"].update(gateway_uid="gateway1"),
        )
        reject(
            "ingress_row",
            "fitness:ingress_slot",
            lambda p: p.by_id["ingress-gateway0-0"].update(backend_slot=1),
        )
        reject(
            "ingress_row",
            "fitness:ingress_completion",
            lambda p: p.by_id["ingress-gateway0-0"].update(identity_join_valid=False),
        )
        reject(
            "ingress_row",
            "fitness:tls_verified",
            lambda p: p.config["tls"]["gateway0"].update(verified=False),
        )
        reject(
            "ingress_row",
            "fitness:tls_version",
            lambda p: p.config["tls"]["gateway0"].update(version="TLSv1.1"),
        )

        def tls_before_open(p):
            next(
                r
                for r in p.c.rows
                if r["source_kind"] == "controller"
                and r["payload"].get("name") == "tls:ingress-gateway0-0"
            )["time_ms_bounds"] = [10**15, 10**15]

        reject("ingress_row", "fitness:tls_before_open", tls_before_open)
        reject(
            "ingress_row",
            "fitness:ingress_sse",
            lambda p: p.by_id["ingress-gateway0-0"]["stream"].update(errors=["bad"]),
        )
        reject(
            "ingress_row",
            "fitness:cancel_gateway",
            lambda p: p.by_id["cancel-gateway0"].update(gateway_uid="gateway1"),
        )
        reject(
            "ingress_row",
            "fitness:cancel_false_completion",
            lambda p: p.by_id["cancel-gateway0"].update(outcome="complete"),
        )

        def cancel_release(p):
            next(
                r
                for r in p.c.rows
                if r["source_kind"] == "redis"
                and r["payload"]["event"] == "release"
                and r["payload"]["request_id"] == "cancel-gateway0"
            )["payload"]["result"] = "held"

        reject("ingress_row", "fitness:cancel_release", cancel_release)

        def cancel_order(p):
            next(
                r
                for r in p.c.rows
                if r["source_kind"] == "client"
                and r["payload"]["event"] == "cancel"
                and r["payload"]["request_id"] == "cancel-gateway0"
            )["time_ms_bounds"] = [10**15, 10**15]

        reject("ingress_row", "fitness:cancel_order", cancel_order)

        def extra_probe_request(p):
            p.by_id["unexpected"] = {}

        reject("produce", "fitness:single_probe_request_inventory", extra_probe_request)

        def clock_errors(p):
            p.c.join.clocks.errors.append({"reason": "test"})

        reject("produce", "fitness:clock_errors", clock_errors)

    def test_resource_cover_rejects_each_missing_boundary_or_gap_by_reason(self):
        cover = FitnessProducer.cover
        cases = (
            ([], 0, 10000, "fitness:resource_cadence"),
            ([{"time_ms_bounds": [1, 5000]}], 0, 10000, "fitness:resource_cadence"),
            (
                [{"time_ms_bounds": [0, 1000]}, {"time_ms_bounds": [4001, 10000]}],
                0,
                10000,
                "fitness:resource_cadence",
            ),
            ([{"time_ms_bounds": [0, 9999]}], 0, 10000, "fitness:resource_cadence"),
        )
        for occurrence, (rows, start, end, reason) in enumerate(cases, 1):
            if not mutation_case("cover", reason, occurrence):
                continue
            with self.subTest(reason=reason, rows=len(rows)):
                with self.assertRaisesRegex(IntegrityError, reason):
                    cover(rows, start, end, reason)

    def test_equivalence_guards_refuse_restoration_and_report_corruption(self):
        def reject_one(reason, source_kind, event, fields, change):
            if not mutation_case("equivalence_row", reason):
                return
            producer = self.producer()
            if source_kind == "redis" and event == "snapshot":
                matches = [
                    row
                    for row in producer.c.rows
                    if row["source_kind"] == source_kind
                    and row["payload"].get("event") == event
                    and all(row["payload"].get(key) == value for key, value in fields.items())
                ]
                self.assertEqual(len(matches), 1)
                change(matches[0])
                with self.assertRaisesRegex(IntegrityError, reason):
                    producer.equivalence_row()
                return
            original = producer.c.one

            def one(source, event_name, **query):
                row = original(source, event_name, **query)
                if (
                    source == source_kind
                    and event_name == event
                    and all(query.get(key) == value for key, value in fields.items())
                ):
                    change(row)
                return row

            producer.c.one = one
            with self.assertRaisesRegex(IntegrityError, reason):
                producer.equivalence_row()

        def snapshot_change(name, reason, change):
            reject_one(reason, "redis", "snapshot", {"snapshot_id": name}, change)

        def mutate_payload(change):
            return lambda row: change(row["payload"])

        if mutation_case("redis_time", "fitness:redis_clock"):
            producer = self.producer()
            original_map = producer.c.join.clocks.map
            producer.c.join.clocks.map = lambda clock, *args: (
                None if clock == "redis" else original_map(clock, *args)
            )
            with self.assertRaisesRegex(IntegrityError, "fitness:redis_clock"):
                producer.equivalence_row()

        if mutation_case("redis_time", "fitness:redis_store_clock_join"):
            producer = self.producer()
            original_map = producer.c.join.clocks.map
            producer.c.join.clocks.map = lambda clock, *args: (
                [0, 0] if clock == "redis" else original_map(clock, *args)
            )
            with self.assertRaisesRegex(IntegrityError, "fitness:redis_store_clock_join"):
                producer.equivalence_row()

        snapshot_change(
            "known2",
            "fitness:unexplained_reservations",
            mutate_payload(lambda payload: payload.update(active_reservations=["ghost"])),
        )
        snapshot_change(
            "known2",
            "fitness:occupied",
            mutate_payload(lambda payload: payload.update(occupied=1)),
        )
        snapshot_change(
            "known2",
            "fitness:redis_configuration",
            mutate_payload(lambda payload: payload.update(config_sha256="wrong")),
        )
        snapshot_change(
            "known2",
            "fitness:report_inventory",
            mutate_payload(lambda payload: payload["reports"].pop("gateway1")),
        )

        def future_report(payload):
            report = payload["reports"]["gateway0"]
            delta = payload["redis_time_ms"] + 1 - report["stored_ms"]
            report["stored_ms"] += delta
            report["expires_ms"] += delta

        snapshot_change("known2", "fitness:report_future", mutate_payload(future_report))
        snapshot_change(
            "known2",
            "fitness:known_reports",
            mutate_payload(lambda payload: payload["reports"]["gateway0"].update(n=9)),
        )
        snapshot_change(
            "known2",
            "fitness:effective_n",
            mutate_payload(lambda payload: payload["state"].update(n=1)),
        )
        snapshot_change(
            "unknown",
            "fitness:expired_unknown",
            mutate_payload(
                lambda payload: [
                    report.update(unknown=False) for report in payload["reports"].values()
                ]
            ),
        )

        def operation_change(reason, change):
            if not mutation_case("equivalence_row", reason):
                return
            reject_one(reason, "redis", "admit", {"snapshot_id": "known2"}, mutate_payload(change))

        operation_change(
            "fitness:operation_store_order", lambda payload: payload.update(store_order=0)
        )
        operation_change("fitness:control_result", lambda payload: payload.update(result="refuse"))
        reject_one(
            "fitness:control_ack_order",
            "gateway",
            "admit",
            {"snapshot_id": "known2", "gateway_uid": "gateway0"},
            mutate_payload(lambda payload: payload.update(store_order=-1)),
        )
        reject_one(
            "fitness:control_ack",
            "gateway",
            "admit",
            {"snapshot_id": "known2", "gateway_uid": "gateway0"},
            mutate_payload(lambda payload: payload.update(decision="refused")),
        )
        reject_one(
            "fitness:control_ack_n",
            "gateway",
            "admit",
            {"snapshot_id": "known2", "gateway_uid": "gateway0"},
            mutate_payload(lambda payload: payload.update(effective_n=99)),
        )
        reject_one(
            "fitness:control_ack_b",
            "gateway",
            "admit",
            {"snapshot_id": "known2", "gateway_uid": "gateway0"},
            mutate_payload(lambda payload: payload.update(effective_b=-1)),
        )

        def change_hold(reason, change, *, returned_copy=False):
            if not mutation_case("equivalence_row", reason):
                return
            producer = self.producer()
            matches = [
                row
                for row in producer.c.rows
                if row["source_kind"] == "redis"
                and row["payload"].get("event") == "snapshot"
                and row["payload"].get("snapshot_id") in {"hold_start", "hold_end"}
            ]
            if returned_copy:
                matches = copy.deepcopy(matches)
            for row in matches:
                if row["payload"].get("snapshot_id") in {"hold_start", "hold_end"}:
                    change(row)
            if returned_copy:
                # A changed copy must not affect the producer's selected source.
                self.assertNotEqual(matches[0], producer.c.rows[-1])
            with self.assertRaisesRegex(IntegrityError, reason):
                producer.equivalence_row()

        change_hold(
            "fitness:restoration_hold",
            lambda row: (
                (
                    row["payload"].update(redis_time_ms=191998),
                    row["source_time"].update(value=191998),
                    row.update(time_ms_bounds=[191998, 191998]),
                )
                if row["payload"]["snapshot_id"] == "hold_end"
                else None
            ),
        )
        change_hold(
            "fitness:hold_original_n",
            lambda row: row["payload"]["state"].update(n=2),
        )
        change_hold(
            "fitness:hold_candidate",
            lambda row: row["payload"]["state"].update(candidate=3),
        )
        change_hold(
            "fitness:hold_since",
            lambda row: row["payload"]["state"].update(since_ms=1),
        )
        change_hold(
            "fitness:hold_expiry",
            lambda row: row["payload"]["state"].update(until_ms=1),
        )
        change_hold(
            "fitness:restored_n",
            lambda row: (
                row["payload"]["state"].update(n=1)
                if row["payload"]["snapshot_id"] == "hold_end"
                else None
            ),
        )

        def mutate_snapshot_find(reason, mutate):
            producer = self.producer()
            hold_start = next(
                row
                for row in producer.c.rows
                if row["source_kind"] == "redis"
                and row["payload"].get("event") == "snapshot"
                and row["payload"].get("snapshot_id") == "hold_start"
            )
            mutate(hold_start)
            with self.assertRaisesRegex(IntegrityError, reason):
                producer.equivalence_row()

        mutate_snapshot_find(
            "fitness:hold_reports",
            lambda row: row["payload"]["reports"].pop("gateway1"),
        )
        mutate_snapshot_find(
            "fitness:hold_fresh",
            lambda row: row["payload"]["reports"]["gateway0"].update(unknown=True),
        )
        mutate_snapshot_find(
            "fitness:hold_reservations",
            lambda row: row["payload"].update(active_reservations=["ghost"]),
        )

        producer = self.producer()
        hold_end = next(
            row
            for row in producer.c.rows
            if row["source_kind"] == "redis" and row["payload"].get("snapshot_id") == "hold_end"
        )
        report = hold_end["payload"]["reports"]["gateway0"]
        report["expires_ms"] = hold_end["payload"]["redis_time_ms"] + 8000 - 1001
        with self.assertRaisesRegex(IntegrityError, "equivalence:report_age:range"):
            producer.equivalence_row()

        def mutate_stores(reason, mutate):
            producer = self.producer()
            original_find = producer.c.find
            added = {"value": False}

            def find(source, event_name, **query):
                rows = original_find(source, event_name, **query)
                if (
                    source == "redis"
                    and event_name == "report_store"
                    and query.get("gateway_uid") == "gateway0"
                ):
                    if not added["value"]:
                        clone = copy.deepcopy(rows[0])
                        clone["payload"]["store_order"] = 12
                        clone["payload"]["redis_time_ms"] = 191500
                        clone["source_time"]["value"] = 191500
                        clone["time_ms_bounds"] = [191500, 191500]
                        producer.c.rows.append(clone)
                        added["value"] = True
                        rows.append(clone)
                    hold_end = original_find("redis", "snapshot", snapshot_id="hold_end")[0][
                        "payload"
                    ]["redis_time_ms"]
                    eligible = sorted(
                        [r for r in rows if r["payload"]["redis_time_ms"] <= hold_end],
                        key=lambda row: row["payload"]["store_order"],
                    )
                    mutate(eligible, producer)
                return rows

            producer.c.find = find
            with self.assertRaisesRegex(IntegrityError, reason):
                producer.equivalence_row()

        mutate_stores(
            "fitness:restored_store_order",
            lambda rows, p: rows[1]["payload"].update(
                store_order=rows[0]["payload"]["store_order"]
            ),
        )
        mutate_stores(
            "fitness:restored_store_order",
            lambda rows, p: rows[0]["payload"].update(
                redis_time_ms=rows[1]["payload"]["redis_time_ms"] + 1
            ),
        )

        change_hold(
            "fitness:restored_store",
            lambda row: (
                row["payload"].update(store_order=0)
                if row["payload"]["snapshot_id"] == "hold_end"
                else None
            ),
        )

        def mutate_selected_store(reason, mutation, *, bypass_join=False):
            producer = self.producer()
            hold_end = producer.c.one("redis", "snapshot", snapshot_id="hold_end")
            bound = hold_end["payload"]["store_order"]
            selected = max(
                (
                    row
                    for row in producer.c.find("redis", "report_store", gateway_uid="gateway0")
                    if row["payload"]["store_order"] < bound
                ),
                key=lambda row: row["payload"]["store_order"],
            )
            mutation(selected, hold_end)
            if bypass_join:
                producer.redis_time = lambda row: row["time_ms_bounds"]
            with self.assertRaisesRegex(IntegrityError, reason):
                producer.equivalence_row()

        mutate_selected_store(
            "fitness:restored_store_time",
            lambda store, hold: store["payload"].update(
                redis_time_ms=store["payload"]["redis_time_ms"] + 1
            ),
            bypass_join=True,
        )
        mutate_selected_store(
            "fitness:restored_report_n",
            lambda store, hold: store["payload"].update(n=1),
        )
        mutate_selected_store(
            "fitness:restored_store_state",
            lambda store, hold: store["payload"].update(report_success=False),
        )

        producer = self.producer()
        original_find = producer.c.find
        producer.c.find = lambda source, event_name, **query: (
            []
            if source == "gateway"
            and event_name == "report_result"
            and query.get("gateway_uid") == "gateway0"
            else original_find(source, event_name, **query)
        )
        with self.assertRaisesRegex(IntegrityError, "fitness:report_ack_store"):
            producer.equivalence_row()
