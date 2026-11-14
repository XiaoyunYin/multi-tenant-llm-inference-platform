"""Raw setup sources through collectors/resolver and ProcessCalls only commands."""

import copy
import json
import os
import platform
import sys
import unittest
import weakref
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from inf037b_setup_fixture import creation_raw, fixture, inventory, scope
from test_inf037b_terminal import Cut, MemoryStore

from inference_platform.inf037b_archive import IntegrityError, encode, sha, strict_json
from inference_platform.inf037b_lifecycle import LifecycleDriver, ProcessCalls
from inference_platform.inf037b_resolver import SessionDeadline, startup
from inference_platform.inf037b_setup import (
    SetupCollector,
    SetupCommands,
    cleanup_observation,
    creation_observation,
    offline_proof,
    persist_archive_artifacts,
    startup_row,
)

CASES = []


def mutation_case(function, reason, occurrence=1):
    site = os.environ.get("INF037B_MUTATION_SITE_ID")
    if site is None or site.endswith(f":{function}:{reason}#{occurrence}"):
        return True
    if function == "one" and reason.startswith("setup:unique:"):
        return site.endswith(":one:'setup:unique:' + event#1")
    if function == "creation_observation" and reason.startswith("setup:creation_ready:"):
        return site.endswith(":creation_observation:'setup:creation_ready:' + name#1")
    return False


def produce(value):
    c = SetupCollector(encode(value["bundle"]), **value["binding"])
    return startup_row(c, pins=value["binding"]["pins"], artifacts=value["artifacts"])


class FixtureSetupCommands(SetupCommands):
    """Legacy resolved-fixture seam; production has no such fallback."""

    def validate_staging(self, creation):
        return {"test_seam": True}

    def validate_preparation(self, collected, creation):
        return {"test_seam": True}

    def completion_observation(self, data, creation, completed):
        return {"test_seam": True, "elapsed_ms": completed["ms"][1] - creation["ready_ms"]}

    def fitness_rows(self, collected, setup):
        if collected.get("fitness_raw") is None:
            return copy.deepcopy(collected["other_rows"])
        # This fixture deliberately has no row 5 process captures. Keep it on
        # the explicit offline seam; production SetupCommands is live-required.
        from inference_platform.inf037b_setup_fitness import FitnessProducer

        producer = FitnessProducer(
            collected["fitness_raw"],
            binding=self.binding,
            artifacts=collected["artifacts"],
            setup=setup,
            allow_offline_fixture=True,
        )
        if producer.c.row(self.binding["pins"])["selected_ms"] > self.sample()["ms"][1]:
            raise IntegrityError("setup:fitness_future_source")
        return producer.produce()

    def lifecycle_input(self, collected):
        if collected.get("replay_raw") is None:
            return copy.deepcopy(collected["lifecycle"])
        return super().lifecycle_input(collected)

    def _persist_export_artifacts(self, artifacts):
        store = self.store
        if not hasattr(store, "path"):
            temporary = getattr(self, "_archive_objects_temp", None)
            if temporary is None:
                temporary = TemporaryDirectory(prefix="inf037b-test-archive-objects-")
                self._archive_objects_temp = temporary
                weakref.finalize(self, temporary.cleanup)
            store = SimpleNamespace(path=Path(temporary.name) / "setup-state")
        return persist_archive_artifacts(store, artifacts)


class SetupTests(unittest.TestCase):
    def test_slot1_ready_between_cold_startup_and_cached_stop(self):
        value = fixture()
        c = SetupCollector(encode(value["bundle"]), **value["binding"])
        cold = c.at("kubernetes", "ready", pod_uid="cold-uid")
        other = c.at("kubernetes", "ready", pod_uid="other-slot")
        stop = c.at("kubernetes", "signal", pod_uid="cold-uid")
        self.assertLess(cold[1], other[0])
        self.assertLess(other[1], stop[0])
        self.assertTrue(produce(value))

    def prepare(self, value):
        port, _ = inventory(scope())
        command = FixtureSetupCommands(
            store=MemoryStore(),
            binding=value["binding"],
            collect=lambda op, stop: (
                creation_raw(value["binding"], 1000)
                if op == "creation"
                else {**value, "raw": encode(value["bundle"])}
            ),
            inventory=port,
            scope=scope(),
            sample=lambda: {"clock_id": "measurement", "boot_id": "host", "ms": [513000, 513000]},
        )
        for operation in ("creation", "preparation", "resolution"):
            command(operation, 1801000, {"measurement_deadline_ms": 1801000})
        return command

    def test_proof_subject_path_missing_and_sizing_refusals(self):
        # Same-bound swaps remain distinguishable even without path reuse.
        for left, right in (("export", "cleanup"), ("creation", "preparation")):
            value = fixture()
            phases = value["lifecycle"]["phases"]
            a, b = phases[left]["offline_proof"], phases[right]["offline_proof"]
            a["path"], b["path"] = b["path"], a["path"]
            with (
                self.subTest(swap=(left, right)),
                self.assertRaisesRegex(IntegrityError, "setup:proof_subject:fixed"),
            ):
                self.prepare(value)
        value = fixture()
        value["lifecycle"]["phases"]["cleanup"]["offline_proof"]["path"] = "proof/export.json"
        with self.assertRaisesRegex(IntegrityError, "setup:distinct_proof_paths"):
            self.prepare(value)
        value = fixture()
        del value["artifacts"]["proof/cleanup.json"]
        with self.assertRaisesRegex(IntegrityError, "setup:proof_artifact"):
            self.prepare(value)
        value = fixture()
        sizing = strict_json(value["artifacts"]["proof/sizing.json"])
        sizing["raw_bytes"] = 450001
        value["artifacts"]["proof/sizing.json"] = encode(sizing)
        value["lifecycle"]["transfer"]["sizing_proof"]["sha256"] = sha(encode(sizing))
        with self.assertRaisesRegex(IntegrityError, "setup:sizing_raw_bytes:fixed"):
            self.prepare(value)
        self.prepare(fixture())
        # Components also exact-check subjects and cannot alias a phase proof.
        value = fixture()
        with self.assertRaisesRegex(IntegrityError, "setup:proof_subject:fixed"):
            offline_proof(
                value["artifacts"],
                "proof/kill_release.json",
                value["binding"]["pins"],
                15000,
                "startup:controller_scheduler",
            )

    def test_offline_proof_fields_refuse_by_named_reason(self):
        value = fixture()
        path = "proof/kill_release.json"
        original = strict_json(value["artifacts"][path])

        def reject(reason, artifacts):
            if not mutation_case("offline_proof", reason):
                return
            with self.assertRaisesRegex(IntegrityError, reason):
                offline_proof(
                    artifacts,
                    path,
                    value["binding"]["pins"],
                    15000,
                    "startup:kill_release",
                )

        reject("setup:proof_bytes", {path: "not-bytes"})
        for reason, field, changed in (
            ("setup:proof_pins", "pins", {}),
            ("setup:proof_subject", "subject", "wrong"),
            ("setup:proof_bound", "bound_ms", 15001),
            ("setup:bounded_failure_recovery", "bounded_failure_recovery", False),
            ("setup:proof_components", "timeout_recovery_ms", [15001]),
        ):
            proof = copy.deepcopy(original)
            proof[field] = changed
            reject(reason, {path: encode(proof)})

    def test_setup_collector_guards_refuse_by_named_reason(self):
        from inference_platform import inf037b_setup as setup_module

        class IdentityJoin:
            def __init__(self, rows):
                self.errors = []
                self.rows = []
                for original in rows:
                    row = copy.deepcopy(original)
                    value = row.get("source_time")
                    at = value["value"] if isinstance(value, dict) else 0
                    row["time_ms_bounds"] = [at, at]
                    self.rows.append(row)

        def reject(reason, mutate=None, *, data_as_text=False, joined=False, t0=None):
            if not mutation_case("__init__", reason):
                return
            value = fixture()
            bundle = copy.deepcopy(value["bundle"])
            binding = copy.deepcopy(value["binding"])
            if mutate is not None:
                mutate(bundle)
            if t0 is not None:
                bundle["t0_ms"] = t0
                binding["t0_ms"] = t0
            data = encode(bundle)
            if data_as_text:
                data = data.decode()
            with self.assertRaisesRegex(IntegrityError, reason):
                if joined:
                    with patch.object(setup_module, "SourceJoin", IdentityJoin):
                        SetupCollector(data, **binding)
                else:
                    SetupCollector(data, **binding)

        reject("setup:raw_bytes", data_as_text=True)
        reject("setup:schema", lambda b: b.update(schema="wrong"))
        reject("setup:session", lambda b: b.update(session_id="wrong"))
        reject("setup:pins", lambda b: b.update(pins={}))
        reject("setup:original_t0", lambda b: b.update(t0_ms=1001))
        reject("setup:raw_rows", lambda b: b.update(raw=[]))
        reject("setup:row_session", lambda b: b["raw"][0].update(session_id="wrong"))
        reject("setup:no_rollout", lambda b: b["raw"][0].update(attempt_id=1))
        reject("setup:no_event_stages", lambda b: b["raw"][0].update(stage=[1]))
        reject("setup:capture_loss", lambda b: b["raw"][0].update(error="lost"))
        reject("setup:before_t0", joined=True, t0=2_000_000)
        reject("setup:collector_boot", lambda b: b["raw"][0].update(collector_boot_id="new"))

        if mutation_case("__init__", "setup:source_join"):
            value = fixture()
            bundle = copy.deepcopy(value["bundle"])
            streams = {}
            for row in bundle["raw"]:
                key = (row["source_kind"], row["source_identity"], row["source_generation"])
                streams.setdefault(key, []).append(row)
            stream = next(rows for rows in streams.values() if len(rows) >= 2)
            stream.sort(key=lambda row: row["source_seq"])
            stream[1]["source_seq"] += 100
            with self.assertRaisesRegex(IntegrityError, "setup:source_join"):
                SetupCollector(encode(bundle), **value["binding"])

        def changed_source_generation(bundle):
            changed = next(
                row
                for row in bundle["raw"]
                if sum(
                    other["source_kind"] == row["source_kind"]
                    and other["source_identity"] == row["source_identity"]
                    for other in bundle["raw"]
                )
                > 1
            )
            changed["source_generation"] = "new-generation"

        reject("setup:source_boot", changed_source_generation, joined=True)

    def test_setup_collector_one_and_creation_observation_guards_have_named_killers(self):
        value = fixture()
        if mutation_case("one", "setup:unique:precondition"):
            collector = SetupCollector(encode(value["bundle"]), **value["binding"])
            row = collector.find("controller", "precondition", name="restored")[0]
            collector.rows.append(copy.deepcopy(row))
            with self.assertRaisesRegex(IntegrityError, "setup:unique:precondition"):
                collector.one("controller", "precondition", name="restored")

        for name in ("capacity", "bootstrap", "control_plane", "nodes"):
            reason = f"setup:creation_ready:{name}"
            if not mutation_case("creation_observation", reason):
                continue
            raw = strict_json(creation_raw(value["binding"], 1000))
            row = next(
                item
                for item in raw["raw"]
                if item["source_kind"] == "controller" and item["payload"].get("name") == name
            )
            row["payload"]["value"] = False
            with self.assertRaisesRegex(IntegrityError, reason):
                creation_observation(encode(raw), value["binding"])

    def test_startup_serving_guards_refuse_by_named_reason(self):
        def reject(reason, change_bundle=None, ready_change=None, change_collector=None):
            if not mutation_case("startup_row", reason):
                return
            value = fixture()
            collector = SetupCollector(encode(value["bundle"]), **value["binding"])
            if change_bundle is not None:
                change_bundle(collector.bundle, collector.rows)
            if change_collector is not None:
                change_collector(collector)
            if ready_change is not None:
                original = collector.one
                seen = {"cached_ready": 0}

                def one(kind, event, **fields):
                    row = original(kind, event, **fields)
                    if (
                        kind == "kubernetes"
                        and event == "ready"
                        and fields.get("pod_uid") == "node_cached-uid"
                    ):
                        seen["cached_ready"] += 1
                        if seen["cached_ready"] == 3:
                            ready_change(row)
                    return row

                collector.one = one
            with self.assertRaisesRegex(IntegrityError, reason):
                startup_row(collector, pins=value["binding"]["pins"], artifacts=value["artifacts"])

        reject(
            "setup:serving_ready_before_restore",
            ready_change=lambda row: row.update(time_ms_bounds=[10**15, 10**15]),
        )
        reject(
            "setup:serving_placement",
            ready_change=lambda row: row["payload"].update(slot="0"),
        )
        reject(
            "setup:cached_serving_slot",
            ready_change=lambda row: row["payload"].update(slot=1),
        )

        def missing_cached(bundle, rows):
            bundle["serving_uids"] = ["cold-uid", "other-slot"]

        def final_membership_only(collector):
            original = collector.find
            seen = {"gateway0": 0, "gateway1": 0}

            def find(kind, event, **fields):
                rows = original(kind, event, **fields)
                gateway = fields.get("gateway_uid")
                if kind == "gateway" and event == "install" and gateway in seen:
                    seen[gateway] += 1
                    if seen[gateway] == 3:
                        rows = copy.deepcopy(rows)
                        for row in rows:
                            row["payload"]["members"] = [
                                {"uid": uid, "ready": True, "healthy": True, "sampled": True}
                                for uid in collector.bundle["serving_uids"]
                            ]
                return rows

            collector.find = find

        reject(
            "setup:cached_serving_uid",
            change_bundle=missing_cached,
            change_collector=final_membership_only,
        )

    def test_startup_row_guards_refuse_by_named_reason(self):
        def reject(reason, change, *, function="startup_row", pins_change=None):
            if not mutation_case(function, reason):
                return
            value = fixture()
            collector = SetupCollector(encode(value["bundle"]), **value["binding"])
            change(collector, value)
            pins = copy.deepcopy(value["binding"]["pins"])
            if pins_change is not None:
                pins_change(pins)
            with self.assertRaisesRegex(IntegrityError, reason):
                startup_row(collector, pins=pins, artifacts=value["artifacts"])

        def raw_row(collector, kind, event, **fields):
            return next(
                row
                for row in collector.rows
                if row["source_kind"] == kind
                and row["payload"].get("event") == event
                and all(row["payload"].get(key) == value for key, value in fields.items())
            )

        reject(
            "setup:case_order",
            lambda c, v: c.bundle["cases"].reverse(),
        )
        reject(
            "setup:fresh_cached_uid",
            lambda c, v: c.bundle["cases"][1].update(uid=c.bundle["cases"][0]["uid"]),
        )
        reject(
            "setup:same_node",
            lambda c, v: c.bundle["cases"][1].update(node="other-node"),
        )
        reject(
            "setup:same_gpu_slot",
            lambda c, v: c.bundle["cases"][1].update(slot=1),
        )
        reject("setup:model_manifest", lambda c, v: c.bundle.update(model_manifest=[]))

        if mutation_case("startup_row", "setup:model_manifest"):
            value = fixture()
            pins = copy.deepcopy(value["binding"]["pins"])
            empty_manifest_hash = sha(encode([]))
            pins["model"] = empty_manifest_hash
            binding = copy.deepcopy(value["binding"])
            binding["pins"] = pins
            bundle = copy.deepcopy(value["bundle"])
            bundle["pins"] = pins
            bundle["model_manifest"] = []
            bundle["model_manifest_sha256"] = empty_manifest_hash
            artifacts = {}
            for path, raw in value["artifacts"].items():
                proof = strict_json(raw)
                proof["pins"] = pins
                artifacts[path] = encode(proof)
            collector = SetupCollector(encode(bundle), **binding)
            with self.assertRaises(IntegrityError) as refused:
                startup_row(collector, pins=pins, artifacts=artifacts)
            self.assertEqual(str(refused.exception), "v4:setup:model_manifest")
        reject(
            "setup:model_paths",
            lambda c, v: c.bundle["model_manifest"].append(
                copy.deepcopy(c.bundle["model_manifest"][0])
            ),
        )
        reject(
            "setup:model_file",
            lambda c, v: c.bundle["model_manifest"][0].update(bytes=0),
        )
        reject(
            "setup:model_manifest_hash",
            lambda c, v: c.bundle.update(model_manifest_sha256="f" * 64),
        )
        reject(
            "setup:pinned_model_manifest",
            lambda c, v: None,
            pins_change=lambda pins: pins.update(model="f" * 64),
        )
        reject(
            "setup:distinct_proof_paths",
            lambda c, v: c.bundle["component_proofs"].update(
                controller_scheduler=c.bundle["component_proofs"]["grace"]
            ),
        )
        reject(
            "setup:node_lineage",
            lambda c, v: raw_row(c, "kubernetes", "pod_created", pod_uid="cold-uid")[
                "payload"
            ].update(node_pseudonym="wrong-node"),
        )
        reject(
            "setup:slot_lineage",
            lambda c, v: raw_row(c, "kubernetes", "pod_created", pod_uid="cold-uid")[
                "payload"
            ].update(slot=1),
        )
        reject(
            "setup:startup_order",
            lambda c, v: raw_row(c, "kubernetes", "pod_created", pod_uid="cold-uid").update(
                time_ms_bounds=[10**15, 10**15]
            ),
        )

        for reason, change in (
            ("setup:cache_node", lambda w, s: w.update(node="wrong-node")),
            ("setup:cache_complete", lambda w, s: w.update(complete=False)),
            ("setup:cache_state", lambda w, s: w.update(model_cache_state="wrong")),
            ("setup:image_cache", lambda w, s: w.update(image_cache_state="unknown")),
            ("setup:cache_clock_join", lambda w, s: w.update(boot_id="wrong-boot")),
            ("setup:cache_files", lambda w, s: w.update(files=[{"path": "unexpected"}])),
        ):
            reject(
                reason,
                lambda c, v, change=change: change(
                    c.bundle["cases"][0]["cache"], c.bundle["cases"][0]
                ),
            )

        def cache_after_creation(c, value):
            spec = c.bundle["cases"][1]
            witness = spec["cache"]
            created = raw_row(c, "kubernetes", "pod_created", pod_uid=spec["uid"])
            source_ms = created["source_time"]["value"]
            witness["begin_ns"] = source_ms * 1_000_000
            witness["end_ns"] = source_ms * 1_000_000
            witness["observation_ms"] = list(created["time_ms_bounds"])

        reject("setup:cache_before_creation", cache_after_creation)

        reject(
            "setup:cache_activity_complete",
            lambda c, v: c.bundle["cases"][1]["cache"]["activity"].update(complete=False),
        )
        reject(
            "setup:cache_activity_window",
            lambda c, v: c.bundle["cases"][1]["cache"]["activity"].update(interval_ms=[1, 2]),
        )
        reject(
            "setup:cache_activity_clock_join",
            lambda c, v: c.bundle["cases"][1]["cache"]["activity"].update(begin_ns=1),
        )
        reject(
            "setup:no_cache_population",
            lambda c, v: c.bundle["cases"][1]["cache"]["activity"].update(mutations=["download"]),
        )

        reject("setup:lineage", lambda c, v: c.bundle["cases"][0].update(lineage=[]))
        reject(
            "setup:lineage_uid",
            lambda c, v: c.bundle["cases"][0]["lineage"][0].update(pod_uid="wrong"),
        )
        reject(
            "setup:node_boot",
            lambda c, v: c.bundle["cases"][0]["lineage"][0].update(node_boot_id="wrong"),
        )

        def future_lineage(c, value):
            for event in c.bundle["cases"][0]["lineage"]:
                event["mono_ns"] += 100_000 * 1_000_000

        reject("setup:lineage_origin", future_lineage)

        def bad_supervisor_start(c, value):
            event = next(
                event for event in c.bundle["cases"][0]["lineage"] if event["event"] == "startup"
            )
            event["mono_ns"] += 10_000_000

        reject("setup:supervisor_startup_join", bad_supervisor_start)

        def bad_lineage_tail(c, value):
            c.bundle["cases"][0]["lineage"][-1]["mono_ns"] = 211099 * 1_000_000

        reject("setup:lineage_through_completion", bad_lineage_tail)

        def break_exit_process(c, value):
            raw_row(c, "vllm", "process_end", pod_uid="cold-uid")["payload"][
                "process_generation"
            ] = "wrong-process"

        reject("setup:exit_process", break_exit_process)

        def late_gpu_release(c, value):
            original = c.at

            def at(kind, event, **fields):
                result = original(kind, event, **fields)
                if (
                    kind == "kubernetes"
                    and event == "gpu_free"
                    and fields.get("pod_uid") == "node_cached-uid"
                ):
                    return [10**15, 10**15]
                return result

            c.at = at

        reject("setup:cached_after_gpu_release", late_gpu_release)

        reject(
            "setup:exit_release_order",
            lambda c, v: raw_row(c, "kubernetes", "signal", pod_uid="cold-uid").update(
                time_ms_bounds=[10**15, 10**15]
            ),
        )
        reject(
            "setup:configured_grace",
            lambda c, v: raw_row(c, "kubernetes", "signal", pod_uid="cold-uid")["payload"].update(
                grace_ms=1
            ),
        )
        reject(
            "setup:creation_request_order",
            lambda c, v: raw_row(c, "controller", "action", name="cached_create_request").update(
                time_ms_bounds=[10**15, 10**15]
            ),
        )
        reject(
            "setup:restoration_ack",
            lambda c, v: raw_row(c, "controller", "precondition", name="restored")[
                "payload"
            ].update(value=False),
        )
        reject(
            "setup:restore_after_startups",
            lambda c, v: raw_row(c, "controller", "precondition", name="restored").update(
                time_ms_bounds=[1000, 1000]
            ),
        )

        def reject_request_join(reason, mutate):
            if not mutation_case("startup_row", reason):
                return
            from inference_platform import inf037b_setup as setup_module

            value = fixture()
            collector = SetupCollector(encode(value["bundle"]), **value["binding"])
            original = setup_module.RequestJoin

            class AlteredRequestJoin:
                def __init__(self, *args):
                    baseline = original(*args)
                    self.errors = list(baseline.errors)
                    self.cohorts = copy.deepcopy(baseline.cohorts)
                    mutate(self)

            with (
                patch.object(setup_module, "RequestJoin", AlteredRequestJoin),
                self.assertRaisesRegex(IntegrityError, reason),
            ):
                startup_row(
                    collector,
                    pins=value["binding"]["pins"],
                    artifacts=value["artifacts"],
                )

        reject_request_join("setup:request_join", lambda requests: requests.errors.append("bad"))
        reject_request_join("setup:four_startup_requests", lambda requests: requests.cohorts.pop())
        reject_request_join(
            "setup:single_startup_request",
            lambda requests: requests.cohorts.__setitem__(1, copy.deepcopy(requests.cohorts[0])),
        )
        reject_request_join(
            "setup:completion",
            lambda requests: requests.cohorts[0].update(outcome="refused"),
        )
        reject_request_join(
            "setup:ready_before_request",
            lambda requests: requests.cohorts[0].update(upstream_open_ms_bounds=[0, 0]),
        )

        reject(
            "setup:installed_route",
            lambda c, v: c.rows.__setitem__(
                slice(None),
                [
                    row
                    for row in c.rows
                    if not (
                        row["source_kind"] == "gateway" and row["payload"].get("event") == "install"
                    )
                ],
            ),
        )

        def ineligible_route(c, value):
            for row in c.rows:
                if row["source_kind"] == "gateway" and row["payload"].get("event") == "install":
                    row["payload"]["membership_known"] = False

        reject("setup:eligible_route", ineligible_route)

        def no_fresh_health(c, value):
            c.rows[:] = [
                row
                for row in c.rows
                if not (
                    row["source_kind"] == "gateway"
                    and row["payload"].get("event") == "health"
                    and row["payload"].get("gateway_uid") == "gateway0"
                )
            ]

        reject("setup:fresh_health", no_fresh_health)

        def no_native_metrics(c, value):
            c.rows[:] = [
                row
                for row in c.rows
                if not (
                    row["source_kind"] == "vllm"
                    and row["payload"].get("event") == "sample"
                    and row["payload"].get("pod_uid") == "cold-uid"
                )
            ]

        reject("setup:native_metrics", no_native_metrics)
        reject(
            "setup:native_model",
            lambda c, v: raw_row(c, "vllm", "sample", pod_uid="cold-uid")["payload"].update(
                model_sha256="wrong"
            ),
        )
        reject(
            "setup:native_runtime",
            lambda c, v: raw_row(c, "vllm", "sample", pod_uid="cold-uid")["payload"].update(
                runtime_sha256="wrong"
            ),
        )
        reject(
            "setup:process_lineage",
            lambda c, v: raw_row(c, "vllm", "sample", pod_uid="cold-uid")["payload"].update(
                process_generation="wrong"
            ),
        )
        reject(
            "setup:native_ready",
            lambda c, v: raw_row(c, "vllm", "sample", pod_uid="cold-uid")["payload"].update(
                health_ready=False
            ),
        )
        reject(
            "setup:native_fields",
            lambda c, v: raw_row(c, "vllm", "sample", pod_uid="cold-uid")["payload"].pop(
                "prefix_query_tokens_total"
            ),
        )

        def final_find_change(reason, change):
            if not mutation_case("startup_row", reason):
                return
            value = fixture()
            collector = SetupCollector(encode(value["bundle"]), **value["binding"])
            original = collector.find
            calls = {"gateway0": 0, "gateway1": 0}

            def find(kind, event, **fields):
                rows = original(kind, event, **fields)
                gateway = fields.get("gateway_uid")
                if kind == "gateway" and event == "install" and gateway in calls:
                    calls[gateway] += 1
                    if calls[gateway] == 3:
                        rows = copy.deepcopy(rows)
                        for row in rows:
                            change(row)
                return rows

            collector.find = find
            with self.assertRaisesRegex(IntegrityError, reason):
                startup_row(
                    collector,
                    pins=value["binding"]["pins"],
                    artifacts=value["artifacts"],
                )

        final_find_change(
            "setup:restore_known",
            lambda row: row["payload"].update(membership_known=False),
        )
        final_find_change(
            "setup:restored_uids",
            lambda row: row["payload"]["members"].__setitem__(
                0, {**row["payload"]["members"][0], "uid": "unknown-serving-uid"}
            ),
        )
        final_find_change(
            "setup:two_serving_slots",
            lambda row: row["payload"]["members"][0].update(healthy=False),
        )

        def dirty_live_set(c, value):
            raw_row(c, "client", "live_set", gateway_uid="gateway0")["payload"]["request_ids"] = [
                "still-active"
            ]

        reject("setup:drained_traffic", dirty_live_set)

        def stale_redis(c, value):
            row = raw_row(c, "redis", "snapshot")
            row["time_ms_bounds"] = [10**15, 10**15]

        reject("setup:drain_freshness", stale_redis)
        reject(
            "setup:drained_reservations",
            lambda c, v: raw_row(c, "redis", "snapshot")["payload"].update(
                active_reservations=["ghost"]
            ),
        )
        reject(
            "setup:drained_occupied",
            lambda c, v: raw_row(c, "redis", "snapshot")["payload"].update(occupied=1),
        )

    def test_latest_restore_observation_requires_freshness(self):
        if not mutation_case("latest", "setup:restore_freshness"):
            return
        value = fixture()
        collector = SetupCollector(encode(value["bundle"]), **value["binding"])
        original = collector.find
        calls = {"gateway0": 0, "gateway1": 0}

        def find(kind, event, **fields):
            rows = original(kind, event, **fields)
            gateway = fields.get("gateway_uid")
            if kind == "gateway" and event == "install" and gateway in calls:
                calls[gateway] += 1
                if calls[gateway] == 3:
                    rows = copy.deepcopy(rows)
                    for row in rows:
                        row["time_ms_bounds"] = [500000, 500000]
            return rows

        collector.find = find
        with self.assertRaisesRegex(IntegrityError, "setup:restore_freshness"):
            startup_row(collector, pins=value["binding"]["pins"], artifacts=value["artifacts"])

    def test_setup_future_source_refuses_before_cleanup(self):
        if not mutation_case("__call__", "setup:future_source"):
            return
        value = fixture()
        port, _ = inventory(scope())
        count = {"value": 0}

        def sample():
            count["value"] += 1
            # Creation now also samples after its durable result write.
            at = 0 if count["value"] == 5 else 513000
            return {"clock_id": "measurement", "boot_id": "host", "ms": [at, at]}

        command = FixtureSetupCommands(
            store=MemoryStore(),
            binding=value["binding"],
            collect=lambda operation, stop: (
                creation_raw(value["binding"], 1000)
                if operation == "creation"
                else {**value, "raw": encode(value["bundle"])}
            ),
            inventory=port,
            scope=scope(),
            sample=sample,
        )
        command("creation", 1801000, {"measurement_deadline_ms": 1801000})
        with self.assertRaisesRegex(IntegrityError, "setup:future_source"):
            command("preparation", 1801000, {"measurement_deadline_ms": 1801000})

    def test_setup_command_scope_and_capture_type_guards_refuse_by_named_reason(self):
        from types import SimpleNamespace

        value = fixture()
        valid_scope = scope()
        for reason, changed_scope in (
            ("setup:scope_session", SimpleNamespace(session_id="wrong", t0_ms=valid_scope.t0_ms)),
            (
                "setup:scope_t0",
                SimpleNamespace(session_id=valid_scope.session_id, t0_ms=valid_scope.t0_ms + 1),
            ),
        ):
            if not mutation_case("__init__", reason):
                continue
            with self.assertRaisesRegex(IntegrityError, reason):
                SetupCommands(
                    store=MemoryStore(),
                    binding=value["binding"],
                    collect=lambda *args: {},
                    inventory=lambda *args: {},
                    scope=changed_scope,
                    sample=lambda: {},
                )

        if mutation_case("_capture", "setup:capture_bytes"):
            command = object.__new__(SetupCommands)
            command.store = MemoryStore()
            with self.assertRaisesRegex(IntegrityError, "setup:capture_bytes"):
                command._capture("invalid", "not-bytes")

    @unittest.skipUnless(os.name == "posix", "archive directory fsync is Linux-only")
    def test_archive_persistence_guards_refuse_by_named_reason(self):
        from types import SimpleNamespace

        from inference_platform import inf037b_setup as setup_module
        from inference_platform.inf037b_setup_observations import file_facts

        key = "source/raw/payload.bin"

        def reject(reason, occurrence, prepare):
            if not mutation_case("persist_archive_artifacts", reason, occurrence):
                return
            with TemporaryDirectory() as directory:
                work = Path(directory)
                store = SimpleNamespace(path=work / "durable-state")
                source = work / "payload.bin"
                source.write_bytes(b"archive bytes")
                artifacts = {key: source}
                try:
                    prepare(work, store, source, artifacts)
                    with self.assertRaisesRegex(IntegrityError, reason):
                        persist_archive_artifacts(store, artifacts)
                finally:
                    patch.stopall()

        reject(
            "setup:archive_object_directory",
            1,
            lambda work, store, source, artifacts: (work / "durable-state.objects").symlink_to(
                work, target_is_directory=True
            ),
        )

        def nested_symlink(work, store, source, artifacts):
            facts = {key: file_facts(source)}
            root = work / "durable-state.objects" / sha(encode(facts))
            root.mkdir(parents=True)
            target = work / "outside"
            target.mkdir()
            for directory in ("raw", "cohorts", "events"):
                (target / directory).mkdir()
            (root / "source").symlink_to(target, target_is_directory=True)

        if mutation_case("persist_archive_artifacts", "setup:archive_object_directory", 2):
            from inference_platform import inf037b_setup as setup_module

            with TemporaryDirectory() as directory:
                work = Path(directory)
                store = SimpleNamespace(path=work / "durable-state")
                source = work / "payload.bin"
                source.write_bytes(b"archive bytes")
                artifacts = {key: source}
                nested_symlink(work, store, source, artifacts)
                with (
                    patch.object(
                        setup_module, "safe_file", side_effect=lambda root, name: Path(root) / name
                    ),
                    self.assertRaisesRegex(IntegrityError, "setup:archive_object_directory"),
                ):
                    persist_archive_artifacts(store, artifacts)

        reject(
            "setup:archive_path",
            1,
            lambda work, store, source, artifacts: artifacts.update({"invalid": source}),
        )
        reject(
            "setup:archive_source_file",
            1,
            lambda work, store, source, artifacts: artifacts.update({key: work / "missing"}),
        )

        def root_symlink(work, store, source, artifacts):
            address = sha(encode({key: file_facts(source)}))
            base = work / "durable-state.objects"
            base.mkdir()
            (work / "elsewhere").mkdir()
            (base / address).symlink_to(work / "elsewhere", target_is_directory=True)

        reject("setup:archive_object_root", 1, root_symlink)

        def source_changes_during_hash(work, store, source, artifacts):
            import inference_platform.inf037b_setup_observations as observations_module

            original = observations_module.file_facts
            changed = {"done": False}

            def facts(path):
                result = original(path)
                if Path(path) == source and not changed["done"]:
                    changed["done"] = True
                    source.write_bytes(b"changed after source hash")
                return result

            patcher = patch.object(observations_module, "file_facts", side_effect=facts)
            patcher.start()

        reject("setup:archive_copy_integrity", 1, source_changes_during_hash)

        def target_changes_after_replace(work, store, source, artifacts):
            original_replace = setup_module.os.replace

            def replace(src, dst):
                original_replace(src, dst)
                Path(dst).write_bytes(b"changed after replace")

            patch.object(setup_module.os, "replace", side_effect=replace).start()

        reject("setup:archive_object_integrity", 1, target_changes_after_replace)

        def unexpected_file(work, store, source, artifacts):
            original = setup_module.safe_file
            injected = {"done": False}

            def safe_file(root, name):
                path = original(root, name)
                if name == key and not injected["done"]:
                    injected["done"] = True
                    (Path(root) / "unexpected.bin").write_bytes(b"unexpected")
                return path

            patch.object(setup_module, "safe_file", side_effect=safe_file).start()

        reject("setup:archive_object_inventory", 1, unexpected_file)

    def test_archive_persistence_requires_a_durable_store_path(self):
        with TemporaryDirectory() as directory:
            source = Path(directory) / "payload.bin"
            source.write_bytes(b"archive bytes")
            with self.assertRaisesRegex(IntegrityError, "setup:archive_store_path"):
                persist_archive_artifacts(MemoryStore(), {"source/raw/payload.bin": source})

    def test_restoration_distinct_uids_slots_nodes_and_cached_binding(self):
        for change, reason in (
            ("members", "two_distinct_member_uids"),
            ("serving", "two_distinct_serving_uids"),
            ("slot", "distinct_serving_slots"),
            ("node", "distinct_serving_nodes"),
        ):
            value = fixture()
            if change == "serving":
                value["bundle"]["serving_uids"] = ["node_cached-uid"]
            for row in value["bundle"]["raw"]:
                p = row["payload"]
                if change == "members" and p["event"] == "install" and len(p["members"]) == 2:
                    p["members"][1] = copy.deepcopy(p["members"][0])
                if p["event"] == "ready" and p.get("pod_uid") == "other-slot":
                    if change == "slot":
                        p["slot"] = 0
                    if change == "node":
                        p["node_pseudonym"] = "node0"
            with (
                self.subTest(change=change),
                self.assertRaisesRegex(IntegrityError, "setup:" + reason),
            ):
                produce(value)

    def test_raw_startups_equality_pending_delayed_creation_and_provenance(self):
        value = fixture()
        raw = encode(value["bundle"])
        row = produce(value)
        result = startup(row)
        self.assertEqual(result["D_bind_ms"], 90000)
        self.assertEqual([c["U_ms"] for c in result["cases"].values()], [210000, 210000])
        self.assertEqual(result["cases"]["node_cached"]["t_start_ms"], [301200, 301200])
        self.assertEqual(result["cases"]["cold"]["t_start_ms"], [1100, 1100])
        self.assertLess(
            row["cases"]["cold"]["pod_creation_ms"][1], row["cases"]["cold"]["gpu_free_ms"][0]
        )
        self.assertEqual(row["release_elapsed_ms"], [0, 15000])
        self.assertEqual(row["controller_elapsed_ms"], [0, 30000])
        self.assertEqual(encode(value["bundle"]), raw)
        CASES.append({"case": "raw_startup_equality", "row": row, "verdict": result})
        # Preparation's upper elapsed bound must subtract readiness's LOWER
        # endpoint, retaining uncertainty rather than silently losing five ms.
        store = MemoryStore()
        store.state = {
            "creation": {
                "result": True,
                "data": {
                    "ready_ms": 1005,
                    "components": dict.fromkeys(
                        ("capacity", "bootstrap", "control_plane", "nodes"), [1000, 1005]
                    ),
                    "observation_ms": [0, 5],
                },
            }
        }
        port, _ = inventory(scope())
        command = FixtureSetupCommands(
            store=store,
            binding=value["binding"],
            collect=lambda op, stop: {**value, "raw": raw},
            inventory=port,
            scope=scope(),
            sample=lambda: {"clock_id": "measurement", "boot_id": "host", "ms": [512000, 512000]},
        )
        command(
            "preparation", 1801000, {"measurement_deadline_ms": 1801000, "operation_key": "prep"}
        )
        self.assertEqual(
            store.state["preparation"]["data"]["lifecycle"]["phases"]["preparation"][
                "observations_ms"
            ],
            [[511000, 511000]],
        )

    def test_raw_missing_cache_lineage_release_restoration_and_wrong_pins_refuse(self):
        changes = {
            "cache_hash": lambda v: v["bundle"]["cases"][1]["cache"]["files"][0].update(
                sha256="f" * 64
            ),
            "cold_not_empty": lambda v: v["bundle"]["cases"][0]["cache"].update(files=[{}]),
            "unknown_image": lambda v: v["bundle"]["cases"][0]["cache"].update(
                image_cache_state=None
            ),
            "other_node": lambda v: v["bundle"]["cases"][1].update(node="other"),
            "cache_population": lambda v: v["bundle"]["cases"][1]["cache"]["activity"].update(
                mutations=["download"]
            ),
            "lineage_gap": lambda v: v["bundle"]["cases"][0]["lineage"].pop(3),
            "lineage_boot": lambda v: v["bundle"]["cases"][0]["lineage"][3].update(boot_id="new"),
            "source_loss": lambda v: v["bundle"]["raw"][0].update(error="lost"),
            "rollout": lambda v: v["bundle"]["raw"][0].update(attempt_id=1),
            "proof_pin": lambda v: v["artifacts"].update(
                {"proof/grace.json": encode({"pins": {}, "bound_ms": 45000})}
            ),
        }
        for name, change in changes.items():
            with self.subTest(name=name):
                value = fixture()
                change(value)
                with self.assertRaises((IntegrityError, KeyError)):
                    produce(value)
        for event, kind, extra in (
            ("gpu_free", "kubernetes", {"pod_uid": "node_cached-uid"}),
            ("process_end", "vllm", {}),
            ("live_set", "client", {}),
            ("snapshot", "redis", {}),
            ("health", "gateway", {}),
        ):
            value = fixture()
            value["bundle"]["raw"] = [
                r
                for r in value["bundle"]["raw"]
                if not (
                    r["source_kind"] == kind
                    and r["payload"]["event"] == event
                    and all(r["payload"].get(k) == v for k, v in extra.items())
                )
            ]
            seqs = {}
            for row in value["bundle"]["raw"]:
                key = row["source_kind"], row["source_identity"], row["source_generation"]
                row["source_seq"] = seqs.get(key, 0)
                seqs[key] = row["source_seq"] + 1
            with self.subTest(event=event), self.assertRaises(IntegrityError):
                produce(value)

    def test_node_clock_offset_is_mapped_and_boot_gap_cannot_supply_lineage(self):
        value = fixture()
        for spec in value["bundle"]["cases"]:
            for holder in (spec["cache"], spec["cache"]["activity"]):
                holder["begin_ns"] += 10000 * 1000000
                holder["end_ns"] += 10000 * 1000000
            for event in spec["lineage"]:
                event["mono_ns"] += 10000 * 1000000
        for row in value["bundle"]["raw"]:
            if row["source_kind"] == "clocks":
                row["payload"]["remote_ms"] += 10000
        self.assertEqual(startup(produce(value))["D_bind_ms"], 90000)
        for row in value["bundle"]["raw"]:
            if row["source_kind"] == "clocks" and row["payload"]["remote_ms"] > 20000:
                row["payload"]["boot_id"] = "reboot"
        with self.assertRaises(IntegrityError):
            produce(value)

    def test_component_and_U_plus_one_cannot_hide_in_pending_or_creation(self):
        for field in ("release", "exit_release", "controller", "U"):
            value = fixture()
            # Change an endpoint without changing ordering/source sequence.
            for row in value["bundle"]["raw"]:
                p = row["payload"]
                match = (
                    field == "release"
                    and p["event"] == "signal"
                    or field == "exit_release"
                    and p["event"] == "process_end"
                    or field == "controller"
                    and p.get("name") == "cached_create_request"
                    or field == "U"
                    and p["event"] == "gpu_free"
                    and p.get("pod_uid") == "cold-uid"
                )
                if match:
                    row["source_time"]["value"] -= 1
            reason = {
                "release": "startup:release",
                "exit_release": "startup:release",
                "controller": "startup:controller",
                "U": "startup:U",
            }[field]
            with self.subTest(field=field), self.assertRaisesRegex(IntegrityError, reason):
                produce(value)

    def test_cleanup_O_includes_inventory_and_replay_with_upper_bound_and_no_effect(self):
        now = [500000]
        port, backend = inventory(scope(), lambda: now.__setitem__(0, now[0] + 2))
        original = copy.deepcopy(backend.resources)

        def sample():
            return {"clock_id": "measurement", "boot_id": "host", "ms": [now[0], now[0] + 3]}

        from inference_platform.inf037b_setup import rehearse as real_rehearse

        def timed(snapshot):
            result = real_rehearse(snapshot)
            now[0] += 100
            return result

        with patch("inference_platform.inf037b_setup.rehearse", side_effect=timed):
            result = cleanup_observation(inventory=port, scope=scope(), stop=1500000, sample=sample)
        self.assertEqual(result["observation_ms"], [143, 149])
        self.assertEqual(backend.resources, original)
        self.assertFalse(backend.executions)
        self.assertEqual(result["rehearsal"]["report"]["errors"], [])
        CASES.append({"case": "cleanup_O_inclusive_read_and_model", "receipt": result})

    def test_cleanup_O_range_deadline_boot_and_regression_refuse(self):
        for elapsed in (900000, 900001):
            now = [1000]
            port, _ = inventory(scope())

            def sample(now=now):
                return {"clock_id": "measurement", "boot_id": "host", "ms": [now[0]] * 2}

            from inference_platform.inf037b_setup import rehearse as real

            def timed(snapshot, now=now, elapsed=elapsed):
                value = real(snapshot)
                now[0] += elapsed
                return value

            with patch("inference_platform.inf037b_setup.rehearse", side_effect=timed):
                if elapsed == 900000:
                    self.assertEqual(
                        cleanup_observation(
                            inventory=port, scope=scope(), stop=2000000, sample=sample
                        )["observation_ms"],
                        [elapsed] * 2,
                    )
                else:
                    with self.assertRaisesRegex(IntegrityError, "allowance:cleanup"):
                        cleanup_observation(
                            inventory=port, scope=scope(), stop=2000000, sample=sample
                        )
        for mode in ("boot", "regression", "deadline"):
            count = [0]

            def bad_sample(count=count, mode=mode):
                count[0] += 1
                at = 1000 if count[0] == 1 else (999 if mode == "regression" else 1001)
                return {
                    "clock_id": "measurement",
                    "boot_id": "changed" if mode == "boot" and count[0] > 1 else "host",
                    "ms": [at] * 2,
                }

            with self.subTest(mode=mode), self.assertRaises(IntegrityError):
                cleanup_observation(
                    inventory=port,
                    scope=scope(),
                    stop=1001 if mode == "deadline" else 2000000,
                    sample=bad_sample,
                )

    def test_cleanup_start_and_clock_guards_refuse_by_named_reason(self):
        from inference_platform import inf037b_setup as setup_module

        def run(reason, samples):
            if not mutation_case("cleanup_observation", reason) and not mutation_case(
                "checked", reason
            ):
                return
            values = iter(samples)
            port, _ = inventory(scope())

            def sample():
                return next(values)

            class Snapshot:
                def __init__(self, inventory_port, clock):
                    self.clock = clock

                def produce(self, cleanup_scope, stop):
                    self.clock()
                    return encode({"synthetic": True})

            with (
                patch.object(setup_module, "SnapshotProducer", Snapshot),
                patch.object(setup_module, "rehearse", return_value={"report": {"errors": []}}),
                self.assertRaisesRegex(IntegrityError, reason),
            ):
                cleanup_observation(inventory=port, scope=scope(), stop=2000, sample=sample)

        run(
            "setup:cleanup_start",
            [
                {"clock_id": "measurement", "boot_id": "host", "ms": [900, 900]},
                {"clock_id": "measurement", "boot_id": "host", "ms": [1000, 1000]},
                {"clock_id": "measurement", "boot_id": "host", "ms": [1001, 1001]},
            ],
        )
        run(
            "setup:cleanup_clock",
            [
                {"clock_id": "measurement", "boot_id": "host", "ms": [1000, 1000]},
                {"clock_id": "measurement", "boot_id": "host", "ms": [999, 999]},
                {"clock_id": "measurement", "boot_id": "host", "ms": [1001, 1001]},
            ],
        )

    def test_setup_command_guards_refuse_by_named_reason(self):
        value = fixture()

        def command(
            *,
            collect=lambda *args: creation_raw(value["binding"], 1000),
            sample=lambda: {"ms": [1000, 1000]},
            store=None,
        ):
            return FixtureSetupCommands(
                store=store or MemoryStore(),
                binding=value["binding"],
                collect=collect,
                inventory=None,
                scope=scope(),
                sample=sample,
            )

        if mutation_case("__call__", "setup:operation"):
            prepared = self.prepare(value)
            with self.assertRaisesRegex(IntegrityError, "setup:operation"):
                prepared("unknown", 1801000, {"measurement_deadline_ms": 1801000})
        if mutation_case("__call__", "setup:command_deadline"):
            with self.assertRaisesRegex(IntegrityError, "setup:command_deadline"):
                command()("creation", 1801000, {"measurement_deadline_ms": 1800999})
        if mutation_case("__call__", "setup:command_start"):
            with self.assertRaisesRegex(IntegrityError, "setup:command_start"):
                command(
                    collect=lambda *args: self.fail("collection ran before command start"),
                    sample=lambda: {"ms": [1801000, 1801000]},
                )("creation", 1801000, {"measurement_deadline_ms": 1801000})

        def create(raw=None, *, samples=(1000, 1000)):
            times = iter(samples)

            def create_sample():
                at = next(times)
                return {"ms": [at, at]}

            return command(
                collect=lambda *args: raw or creation_raw(value["binding"], 1000),
                sample=create_sample,
            )

        if mutation_case("__call__", "setup:readiness_deadline"):
            with self.assertRaisesRegex(IntegrityError, "setup:readiness_deadline"):
                create(creation_raw(value["binding"], 1011))(
                    "creation", 1010, {"measurement_deadline_ms": 1010}
                )
        if mutation_case("__call__", "setup:creation_components"):
            from inference_platform import inf037b_setup as setup_module

            invalid = {"ready_ms": 1000, "components": {}}
            with patch.object(setup_module, "creation_observation", return_value=invalid):
                with self.assertRaisesRegex(IntegrityError, "setup:creation_components"):
                    create()("creation", 1801000, {"measurement_deadline_ms": 1801000})
        if mutation_case("__call__", "setup:creation_component_range"):
            from inference_platform import inf037b_setup as setup_module

            invalid = {
                "ready_ms": 1000,
                "components": {
                    name: [1001, 1001]
                    for name in ("capacity", "bootstrap", "control_plane", "nodes")
                },
            }
            with patch.object(setup_module, "creation_observation", return_value=invalid):
                with self.assertRaisesRegex(IntegrityError, "setup:creation_component_range"):
                    create()("creation", 1801000, {"measurement_deadline_ms": 1801000})
        if mutation_case("__call__", "setup:creation_required"):
            port, _ = inventory(scope())
            prep = command(
                collect=lambda operation, stop: {**value, "raw": encode(value["bundle"])},
                sample=lambda: {
                    "clock_id": "measurement",
                    "boot_id": "host",
                    "ms": [513000, 513000],
                },
            )
            prep.inventory, prep.scope = port, scope()
            with self.assertRaisesRegex(IntegrityError, "setup:creation_required"):
                prep("preparation", 1801000, {"measurement_deadline_ms": 1801000})
        if mutation_case("__call__", "setup:preparation_required"):
            with self.assertRaisesRegex(IntegrityError, "setup:preparation_required"):
                command()("resolution", 1801000, {"measurement_deadline_ms": 1801000})
        if mutation_case("__call__", "setup:command_completion"):
            times = iter((1000, 1801001))

            def late_sample():
                at = next(times)
                return {"ms": [at, at]}

            with self.assertRaisesRegex(IntegrityError, "setup:command_completion"):
                command(sample=late_sample)(
                    "creation", 1801000, {"measurement_deadline_ms": 1801000}
                )
        if mutation_case("__call__", "setup:creation_future_source"):
            times = iter((1000, 1200))

            def future_sample():
                at = next(times)
                return {"ms": [at, at]}

            with self.assertRaisesRegex(IntegrityError, "setup:creation_future_source"):
                command(
                    collect=lambda *args: creation_raw(value["binding"], 1300),
                    sample=future_sample,
                )("creation", 1801000, {"measurement_deadline_ms": 1801000})

    def test_setup_reopen_never_reprobes_an_interrupted_collection(self):
        value = fixture()
        store = MemoryStore()
        store.state = {}
        calls = []

        def collect(operation, stop):
            calls.append(operation)
            raise OSError("lost setup")

        command = FixtureSetupCommands(
            store=store,
            binding=value["binding"],
            collect=collect,
            inventory=None,
            scope=scope(),
            sample=lambda: {"ms": [1000, 1000]},
        )
        context = {"measurement_deadline_ms": 1801000, "operation_key": "one"}
        with self.assertRaises(OSError):
            command("creation", 1801000, context)
        with self.assertRaisesRegex(IntegrityError, "interrupted_no_reprobe"):
            command("creation", 1801000, context)
        self.assertEqual(calls, ["creation"])

    def test_creation_result_lost_ack_replays_once_and_binding_context_changes_refuse(self):
        value = fixture()
        for cut in (1, 2, 3, 4):
            store = MemoryStore()
            store.state, store.cut = {}, cut
            calls = []

            def collect(operation, stop, calls=calls):
                calls.append(operation)
                return creation_raw(value["binding"], 1050)

            def command(binding=value["binding"], store=store, collect=collect):
                return SetupCommands(
                    store=store,
                    binding=binding,
                    collect=collect,
                    inventory=None,
                    scope=scope(),
                    sample=lambda: {"ms": [1050, 1050]},
                )

            context = {"measurement_deadline_ms": 1801000, "operation_key": "one"}
            with self.subTest(cut=cut), self.assertRaises(Cut):
                command()("creation", 1801000, context)
            if cut in (2, 3):
                with self.assertRaisesRegex(IntegrityError, "interrupted_no_reprobe"):
                    command()("creation", 1801000, context)
                self.assertEqual(calls, [] if cut == 2 else ["creation"])
            else:
                self.assertTrue(command()("creation", 1801000, context))
                self.assertTrue(command()("creation", 1801000, context))
                self.assertEqual(calls, ["creation"])
            with self.assertRaisesRegex(IntegrityError, "original_command"):
                command()("creation", 1801000, {**context, "operation_key": "two"})
            changed = copy.deepcopy(value["binding"])
            changed["pins"]["runtime"] = "f" * 64
            with self.assertRaisesRegex(IntegrityError, "immutable_binding"):
                command(changed)("creation", 1801000, context)


if platform.system() == "Linux":

    class ProcessSetupTests(unittest.TestCase):
        def test_raw_setup_commands_feed_actual_resolver_driver_and_preserve_refusals(self):
            for failure in (
                "none",
                "cache",
                "restoration",
                "release",
                "creation",
                "proof",
                "reconnect",
                "fitness_signal",
                "fitness_control",
            ):
                with self.subTest(failure=failure), TemporaryDirectory() as directory:
                    root = Path(directory)
                    commands = {
                        operation: [
                            sys.executable,
                            str(Path(__file__).with_name("inf037b_setup_worker.py")),
                            str(root),
                            operation,
                            failure,
                        ]
                        for operation in (
                            "creation",
                            "preparation",
                            "resolution",
                            "packet_barrier",
                            "attempt_setup",
                            "attempt",
                            "reset",
                            "export",
                            "cleanup",
                        )
                    }

                    def clock(root=root):
                        return (
                            json.loads((root / "clock.json").read_text())["now"]
                            if (root / "clock.json").exists()
                            else 1000
                        )

                    driver = LifecycleDriver(
                        deadline=SessionDeadline(3601000, 21601000, 1000),
                        clock=clock,
                        execute=ProcessCalls(commands, clock),
                        attempts=root / "attempts.jsonl",
                    )
                    result = driver.run()
                    state = strict_json((root / "setup" / "state.json").read_bytes())
                    # DurableStore wraps the JSON state with its checksum envelope.
                    state = state["payload"]
                    if failure == "none":
                        self.assertTrue(result["attempts"]["three_valid_events"], result)
                        self.assertFalse(state["resolution"]["result"]["paid_ready"])
                        self.assertEqual(
                            state["preparation"]["data"]["other_rows"]["sse"]["sources"][0][
                                "sha256"
                            ],
                            state["fitness"]["capture"]["raw_sha256"],
                        )
                        cleanup_O = state["preparation"]["data"]["cleanup"]["observation_ms"]
                        self.assertEqual(
                            state["preparation"]["data"]["lifecycle"]["phases"]["cleanup"][
                                "observations_ms"
                            ],
                            [cleanup_O],
                        )
                    else:
                        self.assertFalse(result["measurement_started"], result)
                        self.assertEqual(len(result["attempts"]["slots"]), 3)
                        self.assertTrue(
                            all(a["state"] == "not_attempted" for a in result["attempts"]["slots"])
                        )
                    if failure in ("cache", "restoration", "release", "proof"):
                        capture = state["preparation"]["capture"]
                        from inference_platform.inf037b_archive import sha

                        self.assertEqual(
                            sha(bytes.fromhex(capture["raw_hex"])), capture["raw_sha256"]
                        )
                    if failure.startswith("fitness_"):
                        capture = state["fitness"]["capture"]
                        from inference_platform.inf037b_archive import sha

                        self.assertEqual(
                            sha(bytes.fromhex(capture["raw_hex"])), capture["raw_sha256"]
                        )
                    events = [r["event"] for r in driver.journal.rows]
                    self.assertEqual(events.count("spawned"), events.count("child_fenced"))
                    effects = json.loads((root / "terminal.json").read_text())
                    self.assertEqual(effects, ["export", "cleanup"])
                    CASES.append(
                        {
                            "case": "process_setup_" + failure,
                            "result": result,
                            "producer_state": {
                                key: {
                                    k: v for k, v in entry.items() if k not in ("data", "capture")
                                }
                                for key, entry in state.items()
                                if key != "binding"
                            },
                            "observations": {
                                k: state.get("preparation", {}).get("data", {}).get(k)
                                for k in ("raw_sha256", "startup", "cleanup", "lifecycle")
                            },
                            "terminal": effects,
                        }
                    )
