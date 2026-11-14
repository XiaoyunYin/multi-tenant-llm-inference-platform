"""Small adverse archives, unchanged parent ledger, and admission before I/O."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import Mock, patch

from test_inf037b_collectors import Records
from test_inf037b_eks_commands import shell
from test_inf037b_eks_probe import component_owner

from inference_platform.inf037b_archive import Archive, IntegrityError, encode, sha, strict_json
from inference_platform.inf037b_attempts import Refused
from inference_platform.inf037b_contract import ATTEMPT_MS, REGISTRATION_ID
from inference_platform.inf037b_eks_campaign import (
    ParentCampaign,
    bind_replacement,
    retained_report,
)


class CampaignTests(unittest.TestCase):
    def test_lifecycle_next_setup_binds_reset_without_a_reset_owner(self):
        from test_inf037b_lifecycle import DriverTests
        from test_inf037b_terminal import MemoryStore

        from inference_platform.inf037b_eks_commands import EKSCommandFactory
        from inference_platform.inf037b_ports import Port

        fixture = DriverTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        store = MemoryStore()
        store.state = {"sequence": 0, "operations": {}, "values": {}}
        port = SimpleNamespace(store=store, validate_context=Mock(), invoke=Mock(return_value=True))
        port.intent = lambda *a: Port.intent(port, *a)
        opened, bound = [], []
        binding = {"session_id": "s"}

        def sealed(operation, stop, context):
            value = {"binding": binding, "sequence_checkpoint": []}
            attempt = context["input"]["attempt"]
            if attempt > 1:
                row = next(
                    r
                    for r in reversed(fixture.driver.attempts.rows)
                    if r["payload"]["event"] == "reset_start"
                )
                value["reset"] = {
                    "index": attempt - 1,
                    "begin_reset": row,
                    "begin_reset_sha256": sha(encode(row)),
                }
            return value

        def runtime(operation, stop, context, *, reset, sequence_checkpoint):
            attempt = context["input"]["attempt"]
            name = "attempt_setup_" + str(attempt)
            opened.append(name)
            bound.append(reset)
            owner = SimpleNamespace(
                binding=binding,
                sources={},
                attempt=attempt,
                stages=[1, 2, 3, 4, 5],
                root=fixture.root / name,
                closed=True,
                normalized_sequence={},
                run=lambda **k: {"close_start_ns": stop * 1000000},
            )
            return {
                "owner": owner,
                "capture_start_ns": (stop - 300000) * 1000000,
                "collector_bundle": {},
                "periodic": [],
                "watches": [],
            }

        dependencies = {
            "4c_attempt_start": lambda *a: True,
            "4c_campaign_capture": sealed,
            "4d_cluster_authority": lambda *a: True,
            "campaign_capture_runtime": runtime,
            "4d_campaign_actions": lambda *a, **k: {},
            "4c_campaign_materialize": lambda *a: {"root": "unused"},
        }
        factory = SimpleNamespace(
            binding=binding,
            port=port,
            config={"pins": {"configuration": "a" * 64}},
            dependency=lambda name: dependencies[name],
            capture_spec=lambda name: {"binding": binding, "sources": {}},
            resource_windows=lambda *a, **k: SimpleNamespace(adapters={}),
        )
        original = fixture.execute

        def execute(operation, stop, context):
            if operation == "attempt_setup":
                return EKSCommandFactory.phases(factory, operation, stop, context)
            return original(operation, stop, context)

        fixture.driver.execute = execute
        # This test isolates lifecycle ordering; concrete proof joins are tested
        # against the TCP API in test_inf037b_eks_cluster.
        with (
            patch(
                "inference_platform.inf037b_eks_campaign.join_cluster",
                return_value={"extra": {"entry_sequence_checkpoint": []}},
            ),
            patch("inference_platform.inf037b_eks_campaign.compose") as collectors,
        ):
            collectors.return_value.periodic = []
            result = fixture.driver.run()
        self.assertFalse(result["refusals"], result)
        self.assertEqual(opened, ["attempt_setup_1", "attempt_setup_2", "attempt_setup_3"])
        self.assertIsNone(bound[0])
        self.assertIsNotNone(bound[1])
        self.assertEqual(bound[1]["index"], 1)
        self.assertEqual(bound[1]["begin_reset"]["payload"]["event"], "reset_start")
        self.assertEqual(len(fixture.driver.attempts._of("reset_complete")), 2)
        self.assertEqual(port.invoke.call_args_list[1].args[3]["reset"], bound[1])

    def archive(self):
        root = Path(self.enterContext(TemporaryDirectory(prefix="r338-campaign-"))) / "archive"
        archive = Archive.create(root, {"registration_id": REGISTRATION_ID, "sources_sha256": {}})
        spec = {
            "attempt_index": 1,
            "target_slot": 0,
            "target_uid": "old0",
            "replacement_uid": "new0",
            "traffic_start_ms": 0,
            "pre_end_ms": 600000,
            "capture_start_ms": 0,
            "capture_end_ms": 0,
            "expected_offers": [],
            "config_sha256": "a" * 64,
            "required_streams": [],
        }
        row = Records().row("controller", "resolution", 0, name="adverse", value=True)
        archive.append("raw/controller.jsonl", row)
        return archive, ParentCampaign(root, spec), spec

    def test_inadequate_capture_and_unused_slots_survive_materialization(self):
        archive, parent, spec = self.archive()
        self.assertEqual(parent.allocate(0, deadline=ATTEMPT_MS + 1, reserve=0), 1)
        parent.campaign.journal.setup_complete(0, preconditions=True, reasons=[])
        parent.campaign.record_capture_window(0, 0)
        result = parent.finish(0, deadline=ATTEMPT_MS + 1, reserve=0)
        self.assertFalse(result["slots"][0]["measurement_valid"])
        closed = parent.close(0, "unused_must_not_replace", [spec])
        self.assertEqual(
            [r.get("state") for r in closed["slots"]["slots"]],
            [None, "not_attempted", "not_attempted"],
        )
        summary = strict_json((archive.root / "events/attempt-01.json").read_bytes())
        self.assertFalse(summary["measurement_valid"])
        self.assertEqual(len(summary["controller"]["slots"]), 3)
        self.assertFalse(closed["paid_ready"])
        path = archive.root / "events/attempt-01.json"
        before = (archive.root / "attempts.jsonl").read_bytes()
        with patch(
            "inference_platform.inf037b_eks_campaign.OfflineCampaign",
            side_effect=AssertionError("child writer"),
        ):
            self.assertEqual(retained_report(archive.root, 1, sha(path.read_bytes())), summary)
        self.assertEqual((archive.root / "attempts.jsonl").read_bytes(), before)
        with self.assertRaisesRegex(IntegrityError, "sealed_report"):
            retained_report(archive.root, 1, "0" * 64)

    def test_aborted_inadequate_slots_and_two_resets_keep_target_order(self):
        _, parent, _ = self.archive()
        j = parent.campaign.journal
        for i in range(3):
            if i:
                j.begin_reset(i * 10, remaining_ms=10000000, export_cleanup_ms=0)
            self.assertEqual(j.allocate(i * 10, remaining_ms=10000000, export_cleanup_ms=0), i + 1)
            j.setup_complete(i * 10, preconditions=True, reasons=[])
            j.end_attempt(
                i * 10 + 1,
                measurement_valid=False,
                reasons=["aborted" if i == 0 else "inadequate"],
                operational_outcomes=["stop"],
                replacement_usable_by_deadline=True,
            )
        result = j.close_slots(22, "campaign_complete")
        self.assertEqual([s["target_slot"] for s in result["slots"]], [0, 1, 0])
        self.assertEqual(
            [s["reasons"] for s in result["slots"]], [["aborted"], ["inadequate"], ["inadequate"]]
        )
        self.assertEqual(len(j._of("reset_complete")), 2)

    def test_allocation_reserve_deadline_inclusive_and_one_ms_short(self):
        _, parent, _ = self.archive()
        self.assertEqual(parent.allocate(10, deadline=ATTEMPT_MS + 110, reserve=100), 1)
        _, other, _ = self.archive()
        with self.assertRaisesRegex(Refused, "insufficient_remaining"):
            other.allocate(11, deadline=ATTEMPT_MS + 110, reserve=100)
        self.assertEqual(other.campaign.journal.report()["slots"][0]["state"], "not_attempted")

    def test_no_adapter_is_constructed_before_replacement_admission(self):
        owner = component_owner(self)
        spec = {
            "uid": "new",
            "origin": {"pod_uid": "new", "slot": 0},
            "process_generation": "p",
            "node": "node0",
            "node_boot_id": "n",
            "manifest": {},
            "metrics_http": {},
            "native_http": {},
            "lifecycle_http": {},
        }
        with (
            patch("inference_platform.inf037b_eks_campaign.DeadlineHTTP") as http,
            patch("inference_platform.inf037b_eks_campaign.VLLMAdapter") as metrics,
            patch("inference_platform.inf037b_eks_campaign.NativeRequestAdapter") as native,
            patch("inference_platform.inf037b_eks_campaign.NodeLifecycleAdapter") as lifecycle,
        ):
            with self.assertRaisesRegex(IntegrityError, "replacement_uid_not_observed"):
                bind_replacement(
                    owner,
                    0,
                    spec,
                    stop_ns=1,
                    pins={"model": "m", "runtime": "r", "metric_semantics": "s"},
                    request_ids={},
                    lifecycle=object(),
                )
            self.assertEqual(
                (http.call_count, metrics.call_count, native.call_count, lifecycle.call_count),
                (0, 0, 0, 0),
            )
            owner.rows("kubernetes").row(
                "kubernetes", "kubernetes", "boot", "pod_created", {"pod_uid": "new", "slot": 0}
            )
            result = bind_replacement(
                owner,
                0,
                spec,
                stop_ns=1,
                pins={"model": "m", "runtime": "r", "metric_semantics": "s"},
                request_ids={},
                lifecycle=object(),
            )
            self.assertEqual(set(result), {"metrics", "native", "lifecycle"})
            self.assertEqual(http.call_count, 3)
        with self.assertRaisesRegex(IntegrityError, "uid_unadmitted"):
            owner.retainer("metrics:slot0", uid="other", process_generation="p")(1, 2, b"raw", {})
            owner.rows("metrics:slot0").row(
                "vllm",
                "vllm:other",
                "p",
                "sample",
                {"pod_uid": "other", "slot": 0, "process_generation": "p"},
            )

    def test_missing_4c_sealed_inputs_refuses_without_child_ledger_write(self):
        with TemporaryDirectory(prefix="r338-missing-campaign-") as directory:
            f = shell(Path(directory), "http://localhost:1")
            f.implementations["4c_attempt_start"] = lambda *a: None
            context = {
                "operation_label": "attempt:1",
                "operation_key": f.port.driver_key + ":attempt:1",
                "measurement_deadline_ms": 1767225601000,
                "input": {"attempt": 1},
            }
            with self.assertRaisesRegex(IntegrityError, "unfinished:4c_campaign_capture"):
                f.phases("attempt", 1767225601000, context)
            self.assertFalse(Path(f.config["attempts"]).exists())

    def reset_proof(self):
        return {
            "reset": {
                "index": 1,
                "begin_reset": {
                    "payload": {"event": "reset_start", "now_ms": 100, "deadline_ms": 300100}
                },
            }
        }

    def test_wrong_reset_hash_refuses(self):
        from inference_platform.inf037b_eks_campaign import setup_reset

        proof = self.reset_proof()
        proof["reset"]["begin_reset_sha256"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "campaign:reset_record"):
            setup_reset("attempt_setup", 2, proof, 101)

    def test_setup_stop_past_reset_deadline_refuses(self):
        from inference_platform.inf037b_eks_campaign import setup_reset

        proof = self.reset_proof()
        proof["reset"]["begin_reset_sha256"] = sha(encode(proof["reset"]["begin_reset"]))
        with self.assertRaisesRegex(ValueError, "campaign:reset_cutoff"):
            setup_reset("attempt_setup", 2, proof, 300101)


if __name__ == "__main__":
    unittest.main()
