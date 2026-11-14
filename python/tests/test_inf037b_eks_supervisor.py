"""Local HTTP/process evidence only; no host/cloud fencing claim."""

import json
import subprocess
import sys
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import Mock

from inf037b_eks_supervisor_worker import FileJournal

from inference_platform.inf037b_eks_supervisor import RecoveryBinding, SupervisorTimer
from inference_platform.inf037b_resolver import SessionDeadline


class SupervisorTests(unittest.TestCase):
    def timer_case(self, terminate, reconcile):
        root = Path(self.enterContext(TemporaryDirectory()))
        timer = SupervisorTimer(
            root,
            terminate=terminate,
            reconcile=reconcile,
            clock=lambda: 0,
            store=FileJournal(root, {"arms": {}}, initialize=True),
        )
        timer.arm({"session_id": "s", "deadline_ms": 1})
        timer.clock = lambda: 1
        return timer, root

    def test_transient_termination_reconciles_then_finishes_and_retains_attempts(self):
        effect = Mock(side_effect=[TimeoutError("provider"), {"terminated": True}])
        reconcile = Mock(return_value={"known": True, "executed": False, "result": None})
        timer, _ = self.timer_case(effect, reconcile)
        timer.tick()
        self.assertTrue(timer.lookup("s")["termination_pending"])
        self.assertTrue(timer.lookup("s")["armed"])
        timer.clock = lambda: 51
        timer.tick()
        timer.tick()
        self.assertEqual(effect.call_count, 2)
        self.assertEqual(reconcile.call_count, 1)
        arm = timer.store.read()["arms"]["s"]
        self.assertEqual(len(arm["termination_attempts"]), 2)
        self.assertIn("TimeoutError:provider", arm["termination_attempts"][0]["error"])
        self.assertEqual(len(arm["reconciliations"]), 1)
        self.assertFalse(timer.lookup("s")["termination_pending"])

    def crashed_timer(self, receipt):
        timer, root = self.timer_case(Mock(side_effect=SystemExit("cut")), Mock())
        with self.assertRaises(SystemExit):
            timer.tick()
        return SupervisorTimer(
            root,
            terminate=Mock(return_value={"terminated": True}),
            reconcile=Mock(return_value=receipt),
            clock=lambda: 51,
            store=FileJournal(root, {}),
        )

    def test_crash_known_not_executed_finishes_once(self):
        timer = self.crashed_timer({"known": True, "executed": False, "result": None})
        for _ in range(3):
            timer.tick()
        self.assertEqual(timer.terminate.call_count, 1)
        self.assertEqual(timer.reconcile.call_count, 1)
        self.assertEqual(len(timer.store.read()["arms"]["s"]["termination_attempts"]), 2)

    def test_crash_known_executed_records_without_repeat(self):
        timer = self.crashed_timer(
            {"known": True, "executed": True, "result": {"terminated": True}}
        )
        timer.tick()
        timer.tick()
        timer.terminate.assert_not_called()
        self.assertEqual(timer.store.read()["arms"]["s"]["result"], {"terminated": True})

    def test_crash_unknown_coalesces_reconciliations_without_firing(self):
        timer = self.crashed_timer({"known": False, "executed": False, "result": None})
        for now in (51, 151, 351):
            timer.clock = lambda now=now: now
            timer.tick()
        timer.terminate.assert_not_called()
        self.assertTrue(timer.lookup("s")["termination_pending"])
        self.assertEqual(timer.store.read()["arms"]["s"]["reconciliations"][0]["count"], 3)

    def test_two_process_settlement_without_repeat_and_supervisor_loss(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            worker = str(Path(__file__).with_name("inf037b_eks_supervisor_worker.py"))
            service = subprocess.Popen(
                [sys.executable, worker, "service", str(root)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                until = time.monotonic() + 10
                while not (root / "ready.json").exists():
                    self.assertIsNone(service.poll())
                    self.assertLess(time.monotonic(), until)
                    time.sleep(0.02)
                ready = json.loads((root / "ready.json").read_bytes())
                deadline = time.time_ns() // 1_000_000 + 2500

                def client(mode, timeout):
                    result = subprocess.run(
                        [
                            sys.executable,
                            worker,
                            mode,
                            str(root),
                            str(ready["port"]),
                            str(deadline),
                            str(timeout),
                        ],
                        capture_output=True,
                        text=True,
                        timeout=8,
                    )
                    return result.returncode, json.loads(result.stdout)

                code, lost = client("arm", 100)
                self.assertEqual(code, 2)
                self.assertIn("AuthorityUnavailable", lost["error"])
                self.assertTrue((root / "in-flight").exists())
                code, settled = client("confirm", 2000)
                self.assertEqual(code, 0, settled)
                self.assertTrue(settled["confirmed"])
                self.assertNotEqual(settled["pid"], ready["pid"])
                state = FileJournal(root / "timer", {}).read()
                self.assertEqual(state["arms"]["session"]["arm_effects"], 1)
                self.assertEqual(settled["deadline_ms"], deadline)
                # Both controller clients have exited; the independent service fires.
                until = time.monotonic() + 5
                while not (root / "fired.json").exists():
                    self.assertLess(time.monotonic(), until)
                    time.sleep(0.02)
                self.assertEqual(
                    json.loads((root / "fired.json").read_bytes())["deadline_ms"], deadline
                )
                service.kill()
                service.wait(timeout=5)
                code, absent = client("confirm", 200)
                self.assertEqual(code, 2)
                self.assertIn("AuthorityUnavailable", absent["error"])
            finally:
                if service.poll() is None:
                    service.kill()
                service.wait(timeout=5)

    def test_reopened_timer_keeps_original_deadline(self):
        with TemporaryDirectory() as temporary:

            def timer():
                return SupervisorTimer(
                    temporary,
                    terminate=Mock(),
                    reconcile=Mock(),
                    clock=lambda: 0,
                    store=FileJournal(temporary, {"arms": {}}, initialize=True),
                )

            timer().arm({"session_id": "s", "deadline_ms": 100})
            reopened = timer()
            self.assertEqual(
                reopened.arm({"session_id": "s", "deadline_ms": 100})["deadline_ms"], 100
            )
            with self.assertRaisesRegex(ValueError, "supervisor:immutable_deadline"):
                reopened.arm({"session_id": "s", "deadline_ms": 101})

    def test_binding_refuses_missing_independence_and_fences_before_settlement(self):
        binding = {"session_id": "s", "C_ms": 10000, "D_session_ms": 18010000, "t0_ms": 1}
        deadline = SessionDeadline(binding["C_ms"], binding["D_session_ms"], binding["t0_ms"])
        from test_inf037b_terminal import MemoryStore

        order = []
        port = SimpleNamespace(
            deadline=Mock(),
            store=MemoryStore(),
            settle=lambda *a, **k: order.append("settle") or {"known": True},
        )
        proof = {"binding": binding, "D_eff_ms": deadline.effective_ms}
        proofs = {
            "4c_recovery_supervisor": lambda stop: proof,
            "4d_independent_recovery": lambda stop: dict(
                proof, controller_host="a", supervisor_host="b"
            ),
        }
        factory = SimpleNamespace(
            binding=binding,
            port=port,
            controller=SimpleNamespace(backstop=SimpleNamespace(confirmed=lambda *a: True)),
            dependency=lambda name: proofs[name],
        )
        recovery = RecoveryBinding(factory)
        driver = SimpleNamespace(deadline=deadline, _fence_pending=lambda: order.append("fence"))
        self.assertEqual(recovery.settle(driver, "operation", "key", 100)["known"], True)
        self.assertEqual(order, ["fence", "settle"])
        proofs["4d_independent_recovery"] = lambda stop: dict(
            proof, controller_host="a", supervisor_host="a"
        )
        with self.assertRaisesRegex(ValueError, "eks:recovery_independence"):
            recovery.confirm(100)

    def test_unknown_many_ticks_has_one_receipt_with_count_and_last_seen(self):
        timer = self.crashed_timer({"known": False})
        for now in range(51, 240051, 50):
            timer.clock = lambda now=now: now
            timer.tick()
        arm = timer.store.read()["arms"]["s"]
        self.assertEqual(len(arm["reconciliations"]), 1)
        row = arm["reconciliations"][0]
        self.assertEqual(row["count"], timer.reconcile.call_count)
        self.assertLess(row["count"], 90)
        self.assertGreater(row["last_seen_ms"], row["at_ms"])
        timer.terminate.assert_not_called()

    def test_termination_attempts_are_paced_and_changed_receipts_retained(self):
        effect = Mock(side_effect=[TimeoutError("one"), TimeoutError("two"), True])
        timer, _ = self.timer_case(
            effect, Mock(return_value={"known": True, "executed": False, "result": None})
        )
        for now in range(1, 152):
            timer.clock = lambda now=now: now
            timer.tick()
        arm = timer.store.read()["arms"]["s"]
        self.assertEqual([a["begin_ms"] for a in arm["termination_attempts"]], [1, 51, 151])
        self.assertEqual(arm["reconciliations"][0]["count"], 2)
