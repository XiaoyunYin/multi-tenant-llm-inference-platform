"""Compact adverse three-slot semantics through the factory's Part 3 path.

The maximum proof/cardinality is a test witness, never a real maximum build.
Host execution, transfer and stores are explicit unit ports; real archive,
sanitizer, reproduction and virtual replay code run unchanged on tiny inputs.
"""

import copy
import unittest
from pathlib import Path
from unittest.mock import patch

import test_inf037b_eks_fixture as fixture_tests
from inf037b_eks_store_fixture import portable_persist, store_binding
from test_inf037b_collectors import Records

from inference_platform import inf037b_campaign as campaign
from inference_platform import inf037b_eks_observations as observation
from inference_platform.inf037b_archive import (
    Archive,
    IntegrityError,
    encode,
    export_archive,
    sha,
    strict_json,
)
from inference_platform.inf037b_contract import REGISTRATION_ID
from inference_platform.inf037b_eks_fixture import fixture_inventory
from inference_platform.inf037b_resolver import BOUNDS_MS

KEY = b"r336-unit-sanitizer-key-only-32-bytes"


class ObservationScopeTests(unittest.TestCase):
    def setUp(self):
        self.case = fixture_tests.FixtureTests(methodName="runTest")
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.root, self.factory = self.case.root, self.case.factory
        source = self.root / "semantic-source"
        archive = Archive.create(
            source, {"registration_id": REGISTRATION_ID, "sources_sha256": {"collector": "a" * 64}}
        )
        records, specs = Records(), []
        for attempt, slot in enumerate((0, 1, 0), 1):
            row = records.row("controller", "resolution", attempt, name="fixture", value=attempt)
            row["attempt_id"] = attempt
            archive.append("raw/controller.jsonl", row)
            specs.append(
                {
                    "attempt_index": attempt,
                    "target_slot": slot,
                    "target_uid": "old" + str(slot),
                    "replacement_uid": "new" + str(slot),
                    "expected_offers": [],
                    "config_sha256": "a" * 64,
                    "pre_end_ms": 600000,
                    "capture_end_ms": 10000,
                    "required_streams": [],
                }
            )
        campaign.materialize_bundle(source, specs)
        self.case.source, self.case.specs = source, specs
        self.case.proof["fixture_inventory"] = fixture_inventory(source)
        self.case.proof["source_inventory_sha256"] = sha(
            encode(self.case.proof["fixture_inventory"])
        )
        self.case.write_inputs()
        self.factory.config["maximum_fixture_source"] = str(source)
        self.wait_refs = {}
        for phase in ("attempt", "reset"):
            path = self.root / (phase + "-real-wait.json")
            path.write_bytes(
                encode(
                    {
                        "pins": self.factory.config["pins"],
                        "subject": "lifecycle:" + phase,
                        "bound_ms": BOUNDS_MS[phase],
                        "bounded_failure_recovery": True,
                        "timeout_recovery_ms": [BOUNDS_MS[phase]],
                    }
                )
            )
            self.wait_refs[phase] = {"path": str(path), "sha256": sha(path.read_bytes())}
        sizing = self.root / "sizing.json"
        sizing.write_bytes(
            encode(
                {
                    "subject": "lifecycle:export_sizing",
                    "pins": self.factory.config["pins"],
                    "raw_bytes": sum(
                        f["bytes"] for f in self.case.proof["fixture_inventory"].values()
                    ),
                    "reconnect_bound_ms": 1000,
                }
            )
        )
        self.factory.config.update(
            real_wait_proofs=self.wait_refs,
            sanitizer_key_sha256=sha(KEY),
            export_sizing_proof={"path": str(sizing), "sha256": sha(sizing.read_bytes())},
        )
        self.case.create()
        self.stores = store_binding(self.root, self.factory.binding, self.factory.config["pins"])
        self.factory.implementations.update(
            {
                "4c_export_stores": lambda request: self.stores,
                "export_host_replay_export": self.host_run,
                "4c_export_artifact_access": lambda result, stop: {
                    "export_artifacts": result["export_artifacts"],
                    "store_readbacks": {
                        name: result["store_receipt"][name]["readback"]
                        for name in ("recovery", "s3")
                    },
                },
            }
        )
        self.persist = self.enterContext(
            patch.object(observation, "persist_to_both", side_effect=self.store_witness)
        )
        self.incomplete_resume = False
        self.tamper_return = False

    def transfer(self, *, sanitized, sanitized_inventory, destination, transfer_start):
        interrupted = export_archive(
            sanitized,
            destination,
            byte_budget=max(1, sum(v["bytes"] for v in sanitized_inventory.values()) // 2),
        )
        resumed = export_archive(sanitized, destination)
        if self.incomplete_resume:
            resumed["complete"] = False
        return {
            "interrupted": interrupted,
            "resumed": resumed,
            "destination_inventory": observation.inventory(destination),
            "destination_artifacts": {
                name: destination / name for name in observation.inventory(destination)
            },
            "transfer_start": transfer_start,
            "transfer_end": self.case.point(),
            "reconnect_elapsed_ms": 0,
        }

    def store_witness(self, *, artifacts, **kwargs):
        return portable_persist(artifacts, self.stores, self.root)

    def host_run(self, request):
        context = {
            "destination": copy.deepcopy(self.case.export_destination),
            "fixture_root": self.case.remote_volume / "fixture",
            "work": self.case.remote_volume / "observation",
            **{
                name: self.factory.config[name]
                for name in (
                    "maximum_fixture",
                    "maximum_fixture_specs",
                    "export_sizing_proof",
                    "real_wait_proofs",
                )
            },
        }
        result = observation.execute_on_export_host(
            request,
            context=context,
            sample=self.case.point,
            sanitizer_key=KEY,
            network_transfer=self.transfer,
            store_ports={},
        )
        if self.tamper_return:
            raw = strict_json(result["export_raw"])
            raw["resumed"]["complete"] = False
            result["export_raw"] = encode(raw)
        return result

    def run_scope(self):
        return self.factory(self.factory.config).capture(1767225601000)

    def test_factory_uses_real_sanitizer_materializer_reproduction_and_separate_waits(self):
        before = {phase: Path(ref["path"]).read_bytes() for phase, ref in self.wait_refs.items()}
        with (
            patch.object(
                campaign, "materialize_bundle", wraps=campaign.materialize_bundle
            ) as materialize,
            patch.object(campaign, "reproduce", wraps=campaign.reproduce) as reproduce,
        ):
            raw, artifacts = self.run_scope()
        self.assertTrue(materialize.called)
        self.assertGreaterEqual(reproduce.call_count, 6)
        self.assertTrue(self.persist.called)
        self.assertTrue(
            set(artifacts)
            >= {"source/SHA256SUMS", "sanitized/SHA256SUMS", "destination/SHA256SUMS"}
        )
        evidence = observation.SetupObservationScope(self.factory).evidence()
        self.assertEqual(evidence["replay"]["virtual_schedule_ms"], [1560000] * 3 + [300000] * 2)
        self.assertTrue(
            all(
                v[1] < BOUNDS_MS[phase]
                for phase, spans in evidence["replay"]["observations_ms"].items()
                for v in spans
            )
        )
        self.assertEqual(
            before, {phase: Path(ref["path"]).read_bytes() for phase, ref in self.wait_refs.items()}
        )
        self.assertFalse(evidence["paid_ready"])
        self.assertEqual(evidence["destination"], self.case.export_destination)
        self.assertEqual(strict_json(raw)["schema"], "inf037b-export-capture-v1")

    def test_factory_rechecks_export_guards_on_returned_capture(self):
        self.tamper_return = True
        with self.assertRaisesRegex(IntegrityError, "observations:resumed"):
            self.run_scope()

    def test_existing_incomplete_resume_guard_runs_through_factory(self):
        self.incomplete_resume = True
        with self.assertRaisesRegex(IntegrityError, "observations:transfer_resume"):
            self.run_scope()
        self.persist.assert_not_called()

    def test_changed_host_fixture_refuses_before_observation(self):
        (self.case.remote_volume / "fixture/raw/controller.jsonl").write_bytes(b"changed")
        with self.assertRaisesRegex(IntegrityError, "fixture_staged_inventory"):
            self.run_scope()
        self.assertFalse((self.case.remote_volume / "observation").exists())

    def test_missing_host_fixture_refuses_before_observation(self):
        (self.case.remote_volume / "fixture/raw/controller.jsonl").unlink()
        with self.assertRaisesRegex(IntegrityError, "fixture_staged_inventory"):
            self.run_scope()

    def test_missing_4c_stores_refuses_without_local_fallback(self):
        del self.factory.implementations["4c_export_stores"]
        with self.assertRaisesRegex(IntegrityError, "unfinished:4c_export_stores"):
            self.run_scope()
        self.assertFalse((self.case.remote_volume / "observation").exists())

    def test_missing_host_runner_refuses_without_local_fallback(self):
        del self.factory.implementations["export_host_replay_export"]
        with self.assertRaisesRegex(IntegrityError, "unfinished:export_host_replay_export"):
            self.run_scope()
        self.assertFalse((self.case.remote_volume / "observation").exists())

    def test_missing_4c_artifact_access_refuses_without_path_assumption(self):
        del self.factory.implementations["4c_export_artifact_access"]
        with self.assertRaisesRegex(IntegrityError, "unfinished:4c_export_artifact_access"):
            self.run_scope()

    def test_host_real_wait_proofs_must_match_controller(self):
        original = self.factory.implementations["export_host_replay_export"]

        def changed(request):
            result = original(request)
            result["real_wait_proofs"] = copy.deepcopy(result["real_wait_proofs"])
            result["real_wait_proofs"]["attempt"]["sha256"] = "b" * 64
            return result

        self.factory.implementations["export_host_replay_export"] = changed
        with self.assertRaisesRegex(IntegrityError, "part3:real_wait_join"):
            self.run_scope()

    def test_controller_recomputes_accessed_manifest_instead_of_accepting_host_digest(self):
        original = self.factory.implementations["export_host_replay_export"]

        def changed(request):
            result = original(request)
            result["store_receipt"]["source_manifest_sha256"] = "b" * 64
            return result

        self.factory.implementations["export_host_replay_export"] = changed
        with self.assertRaisesRegex(IntegrityError, "part3:store_manifest_join"):
            self.run_scope()

    def test_missing_real_wait_proofs_cannot_be_derived_from_virtual_replay(self):
        del self.factory.config["real_wait_proofs"]
        with self.assertRaisesRegex(IntegrityError, "part3:real_wait_proofs_required"):
            self.run_scope()
        self.assertFalse((self.case.remote_volume / "observation").exists())

    def test_missing_second_store_receipt_refuses(self):
        self.persist.side_effect = lambda **_: {"source_manifest_sha256": "a" * 64, "recovery": {}}
        with self.assertRaisesRegex(IntegrityError, "part3:both_store_receipts"):
            self.run_scope()

    def test_replay_recipe_tampering_is_refused_through_factory(self):
        original = self.factory.implementations["export_host_replay_export"]

        def changed(request):
            result = original(request)
            replay = strict_json(result["replay_raw"])
            replay["recipe"][0]["waits_ms"][0] -= 1
            result["replay_raw"] = encode(replay)
            return result

        self.factory.implementations["export_host_replay_export"] = changed
        with self.assertRaisesRegex(IntegrityError, "observations:maximum_schedule"):
            self.run_scope()


if __name__ == "__main__":
    unittest.main()
