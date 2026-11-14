"""Small canonical inputs; real HTTP/files/process cut, no maximum build."""

import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import test_inf037b_eks_stores as store_tests
from inf037b_eks_supervisor_worker import FileJournal
from test_inf037b_collectors import Records
from test_inf037b_resolver import PINS, fixture

from inference_platform.inf037b_archive import (
    Archive,
    encode,
    envelope,
    file_facts,
    sha,
    strict_json,
)
from inference_platform.inf037b_attempts import AttemptController
from inference_platform.inf037b_contract import REGISTRATION_ID, REGISTRATION_PATH
from inference_platform.inf037b_eks_commands import EKSCommandFactory
from inference_platform.inf037b_eks_packet import CanonicalPacket, references
from inference_platform.inf037b_maximum import current_sources
from inference_platform.inf037b_packet import REQUIRED_PINS
from inference_platform.inf037b_resolver import resolve
from inference_platform.inf037b_setup_observations import inventory


class PacketTests(unittest.TestCase):
    def setUp(self):
        case = self.case = store_tests.StoreTests(methodName="runTest")
        case.setUp()
        self.addCleanup(case.doCleanups)
        self.root, self.now = case.root, 1000001
        plan = self.root / "unit-plan-input"
        plan.write_bytes(b"synthetic test bytes, not a Terraform plan")
        self.binding = {**case.controller, "plan_hash": sha(plan.read_bytes())}
        pin_bytes = b"synthetic pinned definition bytes"
        pin_hash = sha(pin_bytes)
        self.pins = dict.fromkeys(PINS, pin_hash)
        case.binding["controller"], case.binding["pins"] = self.binding, self.pins
        case.journal = FileJournal(self.root / "packet-journal", {}, initialize=True)
        case.repository = case.open()
        case.repository.clock = case.access.clock = lambda: self.now
        self.repository = case.repository
        sources = {}
        repository_root = Path(__file__).resolve().parents[2]
        for name in sorted(set(REQUIRED_PINS) | self.pins.keys()):
            path = self.root / ("source-" + name)
            path.write_bytes(
                (repository_root / REGISTRATION_PATH).read_bytes().replace(b"\r\n", b"\n")
                if name == "registration"
                else pin_bytes
            )
            sources[name] = path
        observation = self.root / "observation.jsonl"
        observation.write_bytes(encode(envelope({"test_observation": True}, seq=0)))

        def pinned(value):
            if isinstance(value, dict):
                return {key: pinned(child) for key, child in value.items()}
            if isinstance(value, list):
                return [pinned(child) for child in value]
            return pin_hash if value == "a" * 64 else value

        rows = pinned(fixture())
        for row in rows.values():
            row["observation_ms"][0] = self.binding["t0_ms"]
        for ref in references(rows):
            ref["sha256"] = sha(observation.read_bytes())
        self.decision = resolve(rows, pins=self.pins)
        marker = {
            "committed": True,
            "review_commit": "b" * 40,
            "binding": {
                "session_id": "s",
                "plan_hash": self.binding["plan_hash"],
                "C": "1970-01-01T00:00:10Z",
                "D_session": "1970-01-01T05:00:10Z",
            },
        }
        # A current, tiny proof witness follows load_maximum's real byte/pin
        # checks; no 701,418-row maximum is built or claimed by this fixture.
        proof_inventory = {}
        for name in (
            "registration.json",
            "attempts.jsonl",
            "SHA256SUMS",
            "raw/controller.jsonl",
        ):
            path = self.root / "compact-proof-fixture" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"compact unit fixture only\n")
            proof_inventory[name] = file_facts(path)
        rows["lifecycle"]["transfer"]["raw_bytes"] = sum(
            value["bytes"] for value in proof_inventory.values()
        )
        rows["lifecycle"]["transfer"]["maximum_archive_bytes"] = (
            2 * rows["lifecycle"]["transfer"]["raw_bytes"]
        )
        self.decision = resolve(rows, pins=self.pins)
        maximum = {
            "subject": "lifecycle:maximum_export_fixture",
            "pins": self.pins,
            "schedule_ms": [1560000] * 3 + [300000] * 2,
            "source_lf_sha256": current_sources(),
            "fixture_inventory": proof_inventory,
            "source_inventory_sha256": sha(encode(proof_inventory)),
        }
        proof = self.root / "unit-maximum-proof"
        proof.write_bytes(encode(maximum))
        self.inputs = {
            "resolution_started_ms": 1000000,
            "source_artifacts": sources,
            "observation_artifacts": {ref["path"]: observation for ref in references(rows)},
            "saved_plan": plan,
            "review_marker": marker,
            "admission_rows": [{"event": "marker", "data": marker}],
            "maximum_fixture": {"path": str(proof), "sha256": sha(proof.read_bytes())},
        }
        self.packet = self.open()
        self.stop = 1120000

    def open(self, hook=None, repository=None):
        return CanonicalPacket(
            repository=repository or self.repository,
            root=self.root / "unit-recovery/canonical",
            binding=self.binding,
            pins=self.pins,
            clock=lambda: self.now,
            hook=hook,
        )

    def seal(self):
        return self.packet.seal(self.inputs, self.decision, self.stop)

    def parent(self, ready=True):
        path = self.root / "parent-attempts.jsonl"
        journal = AttemptController(path)
        journal.allocate(1000010, remaining_ms=15000000, export_cleanup_ms=0)
        if ready:
            journal.setup_complete(1000010, preconditions=True, reasons=[])
        self.now = 1000011
        return path, journal

    def assert_invalid(self):
        state = self.packet.state()
        self.assertTrue(state["invalidated"])
        self.assertEqual(len(state["refusals"][-1]["invalidated_outcomes"]), 3)
        self.assertTrue(
            all(
                not row["measurement_valid"]
                for row in state["refusals"][-1]["invalidated_outcomes"]
            )
        )

    def test_canonical_exact_bytes_two_store_barrier_and_restart(self):
        self.assertTrue(self.seal())
        sealed = self.packet.state()["sealed"]
        for key in ("registration.json", "setup-manifest.json", "decision.json", "admission.json"):
            path = Path(sealed["artifacts"]["packet/" + key])
            self.assertEqual(path.read_bytes(), encode(strict_json(path.read_bytes())))
        registration = strict_json(
            Path(sealed["artifacts"]["packet/registration.json"]).read_bytes()
        )
        self.assertEqual(registration["D_eff_ms"], self.packet.deadline.effective_ms)
        self.assertFalse(registration["paid_ready"])
        before = self.case.persist_count
        self.assertTrue(self.open().seal(self.inputs, self.decision, self.stop))
        self.assertEqual(self.case.persist_count, before)
        self.assertEqual(len(sealed["store_receipt"]["acknowledgements"]), 2)

    def test_missing_observation_refuses_and_persists_all_invalidated_outcomes(self):
        self.inputs["observation_artifacts"] = {}
        with self.assertRaisesRegex(ValueError, "4c:observation_missing"):
            self.seal()
        self.assert_invalid()

    def test_stale_input_hash_refuses(self):
        self.inputs["observation_artifacts"]["setup/fixture.jsonl"].write_bytes(b"stale")
        with self.assertRaisesRegex(ValueError, "4c:observation_hash"):
            self.seal()
        self.assert_invalid()

    def test_definition_bytes_must_match_the_effective_pin(self):
        self.inputs["source_artifacts"]["model"].write_bytes(b"different definition")
        with self.assertRaisesRegex(ValueError, "4c:source_pin_join"):
            self.seal()
        self.assert_invalid()

    def test_maximum_inventory_bytes_must_match_resolved_transfer_size(self):
        proof = self.inputs["maximum_fixture"]
        path = Path(proof["path"])
        data = strict_json(path.read_bytes())
        data["fixture_inventory"]["raw/controller.jsonl"]["bytes"] += 1
        data["source_inventory_sha256"] = sha(encode(data["fixture_inventory"]))
        path.write_bytes(encode(data))
        proof["sha256"] = sha(path.read_bytes())
        with self.assertRaisesRegex(ValueError, "4c:maximum_size_join"):
            self.seal()
        self.assert_invalid()

    def test_lost_final_ack_refuses_even_when_both_stores_completed(self):
        publish = self.repository.publish

        def lost(*args, **kwargs):
            publish(*args, **kwargs)
            raise TimeoutError("lost final acknowledgement")

        self.repository.publish = lost
        with self.assertRaisesRegex(TimeoutError, "lost final acknowledgement"):
            self.seal()
        self.assert_invalid()
        self.assertIn(
            "receipt",
            self.repository.journal.read()["4c_stores"]["publications"]["canonical-packet"],
        )
        self.assertNotIn("sealed", self.packet.state())

    def test_durability_timeout_does_not_rebase_resolution(self):
        persist = self.repository.persist

        def delayed(**kwargs):
            result = persist(**kwargs)
            self.now += 60001
            return result

        self.repository.persist = delayed
        with self.assertRaisesRegex(ValueError, "4c:durability_window"):
            self.seal()
        self.assert_invalid()
        self.assertEqual(self.packet.state()["intent"]["inputs"]["resolution_started_ms"], 1000000)

    def test_exact_sixty_second_durability_boundary_passes(self):
        persist = self.repository.persist

        def delayed(**kwargs):
            result = persist(**kwargs)
            self.now += 60000
            return result

        self.repository.persist = delayed
        self.assertTrue(self.seal())
        sealed = self.packet.state()["sealed"]
        self.assertEqual(sealed["completed_ms"] - sealed["durability_started_ms"], 60000)

    def test_altered_allowance_is_not_reused_as_a_decision(self):
        self.decision["allowances_ms"]["attempt"] -= 1
        with self.assertRaisesRegex(ValueError, "4c:decision_reproduction"):
            self.seal()
        self.assert_invalid()

    def test_real_process_cut_after_barrier_intent_refuses_on_reopen(self):
        config = {"stores": self.case.binding, "binding": self.binding, "pins": self.pins}
        (self.root / "cut-config.json").write_bytes(encode(config))
        worker = Path(__file__).with_name("inf037b_eks_packet_worker.py")
        result = subprocess.run(
            [sys.executable, str(worker), str(self.root)], capture_output=True, timeout=10
        )
        self.assertEqual(result.returncode, 73, result.stderr)
        from inference_platform.inf037b_eks_stores import RecoveryRepository

        recovered = RecoveryRepository(
            binding=self.case.binding,
            journal=FileJournal(self.root / "cut-journal", {}),
            store_ports={},
            access=self.case.access,
            clock=lambda: self.now,
            metadata_root=self.root / "unit-recovery/meta",
            persist=self.case.persist,
        )
        packet = self.open(repository=recovered)
        with self.assertRaisesRegex(ValueError, "4c:interrupted_barrier"):
            packet.seal(self.inputs, self.decision, self.stop)
        self.assertTrue(packet.state()["invalidated"])
        self.assertEqual(len(packet.state()["refusals"][-1]["invalidated_outcomes"]), 3)

    def test_post_seal_mutation_refuses_before_start_and_keeps_parent_outcomes(self):
        self.seal()
        parent, _ = self.parent()
        Path(self.packet.state()["sealed"]["artifacts"]["packet/decision.json"]).write_bytes(
            b"changed"
        )
        with self.assertRaisesRegex(ValueError, "4c:post_seal_mutation"):
            self.packet.start("attempt_setup", 1, parent, self.stop)
        self.assert_invalid()
        self.assertEqual(
            self.packet.state()["refusals"][-1]["invalidated_outcomes"][0]["state"], "in_progress"
        )
        self.assertFalse(self.packet.state()["starts"])

    def test_partial_second_store_refuses_before_start(self):
        self.seal()
        parent, _ = self.parent()
        receipt = self.packet.state()["sealed"]["store_receipt"]
        key = next(iter(receipt["manifest"]))
        path = self.root / "unit-s3/objects" / receipt["source_manifest_sha256"] / key
        path.write_bytes(b"x")
        with self.assertRaisesRegex(ValueError, "4c:access_length"):
            self.packet.start("attempt_setup", 1, parent, self.stop)
        self.assert_invalid()

    def test_start_intent_cut_refuses_without_another_start(self):
        self.seal()
        parent, _ = self.parent()

        def cut(phase):
            if phase == "before_start":
                raise SystemExit("cut")

        packet = self.open(hook=cut)
        with self.assertRaises(SystemExit):
            packet.start("attempt_setup", 1, parent, self.stop)
        with self.assertRaisesRegex(ValueError, "4c:interrupted_start"):
            self.open().start("attempt_setup", 1, parent, self.stop)
        self.assert_invalid()

    def owner(self, sequence=0):
        root = self.root / ("owner-" + str(sequence))
        archive = Archive.create(root / "archive", {"registration_id": REGISTRATION_ID})
        records = Records()
        row = records.row("controller", "resolution", 0, name="fixture", value=True)
        row["source_seq"] = sequence
        archive.append("raw/controller.jsonl", row)
        archive.seal()
        descriptor = {
            "closed": True,
            "transport_clean": True,
            "files": inventory(root),
            "close_start_ns": 1000010 * 1000000,
        }
        return root, descriptor

    def archive_inputs(self):
        key = self.root / "sanitizer-key"
        key.write_bytes(b"r339-sanitizer-test-key-32-bytes-only")
        return {
            "aggregate_parent": str(self.root / "unit-recovery/aggregates"),
            "registration": {"registration_id": REGISTRATION_ID},
            "specs": [
                {
                    "attempt_index": 1,
                    "target_slot": 0,
                    "target_uid": "old0",
                    "replacement_uid": "new0",
                    "traffic_start_ms": 1000010,
                    "pre_end_ms": 1600010,
                    "capture_start_ms": 1000010,
                    "capture_end_ms": 1000010,
                    "expected_offers": [],
                    "config_sha256": self.pins["configuration"],
                    "required_streams": [],
                }
            ],
            "sanitizer_key": str(key),
        }

    def context(self, operation="attempt", attempt=1):
        return {
            "operation_key": "driver:" + operation + ":" + str(attempt),
            "operation_label": operation + ":" + str(attempt),
            "input": {"attempt": attempt},
            "measurement_deadline_ms": self.stop,
        }

    def test_capture_materializes_immutable_parent_report_checkpoint_and_shared_reset(self):
        self.seal()
        parent, controller = self.parent()
        context = self.context()
        self.packet.capture("attempt", self.stop, context, parent)
        root, descriptor = self.owner()
        before = parent.read_bytes()
        result = self.packet.materialize(
            "attempt", descriptor, root, self.stop, context, parent, self.archive_inputs()
        )
        self.assertEqual(parent.read_bytes(), before)
        self.assertEqual(
            file_facts(Path(result["root"]) / "events/attempt-01.json")["sha256"],
            result["attempt_report_sha256"],
        )
        self.assertEqual(self.packet.state()["sequence_checkpoint"][0]["next"], 1)
        self.assertEqual(
            [s.get("state") for s in result["controller_outcomes"]["slots"]],
            ["in_progress", "not_attempted", "not_attempted"],
        )
        controller.end_attempt(
            1000011,
            measurement_valid=False,
            reasons=["unit adverse"],
            operational_outcomes=["aborted"],
            replacement_usable_by_deadline=True,
        )
        controller.begin_reset(1000011, remaining_ms=15000000, export_cleanup_ms=0)
        controller.allocate(1000011, remaining_ms=15000000, export_cleanup_ms=0)
        shared = self.packet.capture(
            "attempt_setup", self.stop, self.context("attempt_setup", 2), parent
        )
        self.assertEqual(shared["reset"]["index"], 1)
        self.assertEqual(shared["reset"]["begin_reset"]["payload"]["event"], "reset_start")
        self.assertEqual(shared["sequence_checkpoint"][0]["next"], 1)

    def test_noncontinuous_owner_sequence_refuses_and_preserves_invalidated_slots(self):
        self.seal()
        parent, _ = self.parent()
        context = self.context()
        self.packet.capture("attempt", self.stop, context, parent)
        root, descriptor = self.owner(sequence=1)
        with self.assertRaisesRegex(ValueError, "4c:continuous_sequence"):
            self.packet.materialize(
                "attempt", descriptor, root, self.stop, context, parent, self.archive_inputs()
            )
        self.assert_invalid()

    def test_post_session_review_preserves_all_outcomes_and_invalidates_on_mutation(self):
        self.seal()
        parent, controller = self.parent()
        controller.end_attempt(
            1000011,
            measurement_valid=False,
            reasons=["unit adverse"],
            operational_outcomes=["aborted"],
            replacement_usable_by_deadline=True,
        )
        controller.close_slots(1000011, "unit closed")
        self.now = 19000000  # Review can run after the original paid deadline.
        self.assertTrue(self.packet.post_session(parent, self.now + 10000)["packet_valid"])
        sealed_path = Path(self.packet.state()["sealed"]["artifacts"]["packet/decision.json"])
        sealed_path.write_bytes(b"changed")
        review = self.packet.post_session(parent, self.now + 10000)
        self.assertFalse(review["packet_valid"])
        self.assertEqual(len(review["invalidated_outcomes"]), 3)
        self.assertEqual(review["invalidated_outcomes"][0]["operational_outcomes"], ["aborted"])
        self.assertTrue(all(row["packet_invalidated"] for row in review["invalidated_outcomes"]))

    def test_all_five_factory_ports_and_terminal_sanitized_inputs(self, omit_campaign=False):
        parent = self.root / "parent-attempts.jsonl"
        archive_inputs = self.archive_inputs()
        factory = SimpleNamespace(
            binding=self.binding,
            clock=lambda: self.now,
            admission_rows=self.inputs["admission_rows"],
            config={
                "pins": self.pins,
                "attempts": str(parent),
                "resolved_packet": str(self.packet.root),
                "maximum_fixture": self.inputs["maximum_fixture"],
                "recovery_store_binding": self.case.binding,
                "sanitizer_key_sha256": sha(Path(archive_inputs["sanitizer_key"]).read_bytes()),
            },
            implementations={
                "4d_recovery_store_runtime": lambda stop: {"repository": self.repository},
                "4e_packet_inputs": lambda stop: self.inputs,
                "4d_campaign_archive_inputs": lambda stop: archive_inputs,
                "4d_terminal_capture_inventory": lambda stop: {
                    "binding": self.binding,
                    "complete": True,
                    "owners": [
                        dict(entry, owner_id=entry["operation"] + "_" + str(entry["attempt"]))
                        for entry in self.packet.state()["owners"]
                    ],
                },
            },
            port=SimpleNamespace(deadline=Mock(), validate_context=Mock()),
        )
        factory.dependency = lambda name: EKSCommandFactory.dependency(factory, name)
        self.assertTrue(
            factory.dependency("4c_packet_barrier")(self.stop, {"input": self.decision})
        )
        parent, controller = self.parent()
        self.assertIn(
            "packet_sha256", factory.dependency("4c_attempt_start")(self.stop, self.context())
        )
        factory.dependency("4c_campaign_capture")("attempt", self.stop, self.context())
        root, descriptor = self.owner()
        result = factory.dependency("4c_campaign_materialize")(
            "attempt", descriptor, root, self.stop, self.context()
        )
        self.assertTrue(result["attempt_report_sha256"])
        controller.end_attempt(
            1000011,
            measurement_valid=False,
            reasons=["unit adverse"],
            operational_outcomes=["aborted"],
            replacement_usable_by_deadline=True,
        )
        controller.close_slots(1000011, "unit closed")
        if omit_campaign:
            factory.implementations["4d_terminal_capture_inventory"] = lambda stop: {
                "binding": self.binding,
                "complete": True,
                "owners": [],
            }
            with self.assertRaisesRegex(ValueError, "4c:terminal_campaign_coverage"):
                factory.dependency("4c_terminal_export_inputs")(self.stop)
            return
        terminal = factory.dependency("4c_terminal_export_inputs")(self.stop)
        self.assertEqual(terminal["binding"], self.binding)
        self.assertEqual(inventory(terminal["sanitized"]), terminal["inventory"])
        self.assertTrue(
            any(key.startswith("retained-owners/") for key in terminal["retained_artifacts"])
        )
        self.assertTrue(
            any(key.startswith("resolved-packet/") for key in terminal["retained_artifacts"])
        )
        self.assertTrue(
            strict_json((terminal["sanitized"] / "registration.json").read_bytes())["sanitized"]
        )

    def test_catalog_omitting_campaign_owner_refuses(self):
        self.test_all_five_factory_ports_and_terminal_sanitized_inputs(omit_campaign=True)

    def test_start_after_attempt_end_refuses(self):
        self.seal()
        parent, controller = self.parent()
        self.packet.start("attempt_setup", 1, parent, self.stop)
        controller.end_attempt(
            1000011,
            measurement_valid=False,
            reasons=["adverse"],
            operational_outcomes=["aborted"],
            replacement_usable_by_deadline=True,
        )
        with self.assertRaisesRegex(ValueError, "4c:attempt_already_ended"):
            self.packet.start("attempt_setup", 1, parent, self.stop)

    def test_missing_reset_start_refuses(self):
        self.seal()
        parent, controller = self.parent()
        for attempt in (1, 2):
            self.packet.start("attempt_setup", attempt, parent, self.stop)
            if attempt == 2:
                controller.setup_complete(1000011, preconditions=True, reasons=[])
            controller.end_attempt(
                1000011,
                measurement_valid=False,
                reasons=["adverse"],
                operational_outcomes=["aborted"],
                replacement_usable_by_deadline=True,
            )
            controller.begin_reset(1000011, remaining_ms=15000000, export_cleanup_ms=0)
            controller.allocate(1000011, remaining_ms=15000000, export_cleanup_ms=0)
        rows = [strict_json(line) for line in parent.read_bytes().splitlines()]
        missing = next(i for i, r in enumerate(rows) if r["payload"]["event"] == "reset_start")
        rows.pop(missing)
        parent.write_bytes(
            b"".join(encode(envelope(row["payload"], seq=i)) for i, row in enumerate(rows))
        )
        with self.assertRaisesRegex(ValueError, "4c:reset_index"):
            self.packet.capture(
                "attempt_setup", self.stop, self.context("attempt_setup", 3), parent
            )

    def test_rewritten_parent_prefix_refuses_materialization(self):
        self.seal()
        parent, _ = self.parent()
        context = self.context()
        self.packet.capture("attempt", self.stop, context, parent)
        rows = [strict_json(line) for line in parent.read_bytes().splitlines()]
        rows[0]["payload"]["now_ms"] += 1
        parent.write_bytes(
            b"".join(encode(envelope(row["payload"], seq=i)) for i, row in enumerate(rows))
        )
        root, descriptor = self.owner()
        with self.assertRaisesRegex(ValueError, "4c:parent_rewritten"):
            self.packet.materialize(
                "attempt", descriptor, root, self.stop, context, parent, self.archive_inputs()
            )

    def test_real_lifecycle_order_setup_attempt_reset_next_setup_materializes(self):
        self.seal()
        parent, controller = self.parent(ready=False)

        def step(operation, attempt, sequence, inputs):
            context = self.context(operation, attempt)
            request = self.packet.capture(operation, self.stop, context, parent)
            root, descriptor = self.owner(sequence)
            self.packet.materialize(operation, descriptor, root, self.stop, context, parent, inputs)
            return request

        inputs = self.archive_inputs()
        step("attempt_setup", 1, 0, inputs)
        controller.setup_complete(1000010, preconditions=True, reasons=[])
        step("attempt", 1, 1, inputs)
        controller.end_attempt(
            1000011,
            measurement_valid=False,
            reasons=["adverse"],
            operational_outcomes=["aborted"],
            replacement_usable_by_deadline=True,
        )
        controller.begin_reset(1000011, remaining_ms=15000000, export_cleanup_ms=0)
        controller.allocate(1000011, remaining_ms=15000000, export_cleanup_ms=0)
        inputs["specs"].append(
            dict(
                inputs["specs"][0],
                attempt_index=2,
                target_slot=1,
                target_uid="old1",
                replacement_uid="new1",
            )
        )
        request = step("attempt_setup", 2, 2, inputs)
        self.assertEqual(request["reset"]["index"], 1)
        self.assertEqual(self.packet.state()["sequence_checkpoint"][0]["next"], 3)
        self.assertFalse(self.packet.state().get("invalidated"))
