import tempfile
import unittest
from unittest.mock import Mock

from inference_platform.r1_fake import Fake
from inference_platform.r1_reset import PreparationFailed
from inference_platform.r1_session import CALIBRATION_IDLE_TIMEOUT_S, Session


class CalibrationIdleTests(unittest.TestCase):
    def session(self, io):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        session = Session(io, {"manifest_sha256": "fixture"}, directory.name, head="fixture")
        self.addCleanup(session.event_file.close)
        return session

    def test_closed_loop_tail_is_serial_per_replica_and_configure_refuses(self):
        io = Fake("success")
        phase = io.phase("calibration-corpus-warm", 600, 0, level=8)
        self.assertEqual(phase["censored"], 8)
        self.assertEqual(io.admission_state(615)["coordinator_inflight"], 8)
        self.assertEqual([(s["running"], s["waiting"]) for s in io.snapshots(615)], [(1, 3)] * 2)
        with self.assertRaisesRegex(ValueError, "configuration refused while work remains"):
            io.configure("rr", 4, 1, 10, 4242, 615)
        self.assertEqual(io.configurations, [])
        io.clock.sleep(0.27 + 1e-9)
        self.assertEqual(io.admission_state(615)["coordinator_inflight"], 6)
        io.clock.sleep(3 * 0.27)
        self.assertEqual(io.admission_state(615)["coordinator_inflight"], 0)
        io.configure("rr", 4, 1, 10, 4242, 615)
        self.assertEqual(len(io.configurations), 1)

    def test_wait_then_configure_without_closing_admissions(self):
        io = Fake("success")
        io.phase("calibration-corpus-warm", 600, 0, level=8)
        io.configure = Mock(wraps=io.configure)
        io.close_admissions = Mock(side_effect=AssertionError("must finish naturally"))
        session = self.session(io)
        session.wait_for_calibration_idle("candidate-W1-f1.05")
        io.configure("rr", 4, 1, 10, 4242, session.active_deadline)
        io.configure.assert_called_once()
        io.close_admissions.assert_not_called()
        event = session.events[-1]
        self.assertTrue(event["success"])
        self.assertEqual(event["consecutive_zero_polls"], 3)
        self.assertEqual(event["elapsed_s"], 2.5)  # 1.08 tail, round up to 1.5 + 1 s stability.

    def test_never_idle_names_all_counts_and_never_configures(self):
        io = Fake("success")
        io.work_until = 1000
        io.configure = Mock(wraps=io.configure)
        session = self.session(io)
        with self.assertRaisesRegex(
            PreparationFailed, "admission=.*gateway_reservations.*2.*replicas=.*running.*1.*waiting"
        ):
            session.wait_for_calibration_idle("candidate-W1-f1.05")
            io.configure("rr", 4, 1, 10, 4242, session.active_deadline)
        self.assertEqual(io.clock.now(), CALIBRATION_IDLE_TIMEOUT_S)
        io.configure.assert_not_called()
        self.assertFalse(session.events[-1]["success"])

    def test_every_candidate_waits_and_earlier_zero_polls_do_not_count(self):
        io = Fake("success")
        session = self.session(io)
        # Admission-only and native waiting-only work must each reset the streak.
        states = [0, 0, 1, 0, 0, 0, 0, 0]
        native = [0, 0, 0, 0, 1, 0, 0, 0]
        original = io.snapshots
        io.admission_state = Mock(
            side_effect=lambda deadline: {"coordinator_inflight": states.pop(0)}
        )

        def snapshots(deadline):
            values = original(deadline)
            values[1]["waiting"] = native.pop(0)
            return values

        io.snapshots = snapshots
        session.wait_for_calibration_idle("fixture")
        self.assertEqual(session.events[-1]["polls"], 8)
        self.assertEqual(io.clock.now(), 3.5)

    def test_parent_cutoff_and_slow_poll_do_not_escape_bound(self):
        for slow in (False, True):
            with self.subTest(slow=slow):
                io = Fake("success")
                io.work_until = 1000
                session = self.session(io)
                session.active_deadline = 2
                if slow:

                    def admission(deadline, io=io):
                        io.clock.sleep(deadline - io.clock.now())
                        raise TimeoutError("state poll timed out")

                    io.admission_state = admission
                with self.assertRaisesRegex(PreparationFailed, "admission=.*replicas="):
                    session.wait_for_calibration_idle("fixture")
                self.assertEqual(io.clock.now(), 2)
                self.assertEqual(session.events[-1]["elapsed_s"], 2)

    def test_calibrate_waits_before_candidate_and_timeout_has_no_candidate_configure(self):
        for stuck in (False, True):
            with self.subTest(stuck=stuck):
                io = Fake("success")
                phase = io.phase

                def run_phase(*args, phase=phase, stuck=stuck, io=io, **kwargs):
                    value = phase(*args, **kwargs)
                    if stuck and args[0] == "calibration-corpus-warm":
                        io.work_until = io.clock.now() + 1000
                    return value

                io.phase = run_phase
                io.configure = Mock(wraps=io.configure)
                io.close_admissions = Mock(wraps=io.close_admissions)
                session = self.session(io)
                if stuck:
                    with self.assertRaisesRegex(PreparationFailed, "idle deadline exhausted"):
                        session.calibrate()
                    self.assertEqual(io.configure.call_count, 1)  # Initial setup only.
                else:
                    self.assertEqual(session.calibrate()["W"], 1)
                    self.assertEqual(io.configure.call_count, 2)
                self.assertEqual(io.close_admissions.call_count, 1)  # Setup reset only.
                self.assertEqual(session.events[-1]["success"] if stuck else True, not stuck)

    def test_missing_stale_or_changed_replica_fails_closed(self):
        for problem in ("missing", "stale", "generation"):
            with self.subTest(problem=problem):
                io = Fake("success")
                original = io.snapshots
                calls = 0

                def snapshots(deadline, original=original, problem=problem):
                    nonlocal calls
                    calls += 1
                    values = original(deadline)
                    if problem == "missing":
                        return values[:1]
                    if problem == "stale":
                        values[0]["age_s"] = 2
                    if problem == "generation" and calls == 2:
                        values[0]["generation"] = "changed"
                    return values

                io.snapshots = snapshots
                with self.assertRaises(PreparationFailed):
                    self.session(io).wait_for_calibration_idle("fixture")


if __name__ == "__main__":
    unittest.main()
