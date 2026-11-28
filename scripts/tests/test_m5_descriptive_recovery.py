"""Recovery fixtures use the real dispatch and lifecycle gates with fake I/O."""

import hashlib
import json
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from inf060_eks_cpu_plan import HELM_PHASE
from m5_descriptive_eks import EKSports, recover_execution


class RecoveryTests(unittest.TestCase):
    def setup_ports(self, root, state, *, bad_retrieval=False):
        ports = EKSports.__new__(EKSports)
        ports.directory = root
        ports.started = time.time() - 7000
        ports.end = ports.started + 18000
        ports.manifest = {
            "timing": {"cleanup_reserve_seconds": 1800, "one_retrieval_seconds": 2208}
        }
        ports.host = SimpleNamespace(token="fixture")
        ports.recovered_phases = {}
        ports.aws = Mock(return_value={"Status": state})
        execution = root / "execution"
        dispatch = execution / "remote-dispatch"
        dispatch.mkdir(parents=True)
        (dispatch / "1.json").write_text(
            json.dumps({"phase": HELM_PHASE, "host": "operator", "command": "command"}),
            encoding="utf-8",
        )
        original = execution / "receipt.json"
        original.write_bytes(b'{"deadline_monotonic":1}')
        events = []
        frozen = {"proof.json": {"sha256": "fixture", "bytes": 42}}

        def action(name, result):
            events.append(name)
            return result

        ports.export = lambda: action("export", frozen)
        ports.retrieve = lambda: action("retrieve", {} if bad_retrieval else frozen)
        ports.teardown = lambda: action("teardown", {"complete": True})
        ports.inventory = lambda: action("inventory", {"complete": True})
        return ports, events, original

    def test_finished_work_recovers_evidence_then_destroys(self):
        with tempfile.TemporaryDirectory() as name:
            ports, events, original = self.setup_ports(Path(name), "Success")
            receipt = recover_execution(ports)
            self.assertEqual(events, ["export", "retrieve", "teardown", "inventory"])
            self.assertTrue(receipt["complete"])
            self.assertEqual(receipt["original_deadline_epoch"], ports.started + 18000)
            self.assertTrue(receipt["original_receipt_unchanged"])
            self.assertEqual(
                receipt["original_receipt_sha256"],
                hashlib.sha256(original.read_bytes()).hexdigest(),
            )
            self.assertEqual(original.read_bytes(), b'{"deadline_monotonic":1}')
            self.assertEqual(ports.host.deadline, ports.end)
            self.assertEqual(ports.host.host, "operator")
            self.assertEqual(
                ports.aws.call_args.args[:2], ("ssm", "get-command-invocation")
            )

    def test_active_work_is_preserved_unless_cleanup_explicit(self):
        with tempfile.TemporaryDirectory() as name:
            ports, events, original = self.setup_ports(Path(name), "InProgress")
            with self.assertRaisesRegex(
                ValueError, "descriptive:recovery_remote_unfinished"
            ):
                recover_execution(ports)
            self.assertEqual(events, [])
            self.assertFalse(original.with_name("recovery-receipt.json").exists())
            receipt = recover_execution(ports, allow_cleanup=True)
            self.assertFalse(receipt["complete"])
            self.assertEqual(events, ["teardown", "inventory"])

    def test_hash_failure_still_destroys_and_inventories(self):
        with tempfile.TemporaryDirectory() as name:
            ports, events, original = self.setup_ports(
                Path(name), "Failed", bad_retrieval=True
            )
            with self.assertRaisesRegex(
                ValueError, "descriptive:retrieval_hash_mismatch"
            ):
                recover_execution(ports)
            self.assertEqual(events, ["export", "retrieve", "teardown", "inventory"])
            receipt = json.loads(
                original.with_name("recovery-receipt.json").read_bytes()
            )
            self.assertFalse(receipt["complete"])
            self.assertEqual(
                [row["status"] for row in receipt["phases"]],
                ["PASS", "FAILED", "PASS", "PASS"],
            )
            self.assertEqual(original.read_bytes(), b'{"deadline_monotonic":1}')
