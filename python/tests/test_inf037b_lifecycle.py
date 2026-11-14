"""Offline driver proofs; all real filesystem/process cases run on pinned Linux."""

import copy
import importlib
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from inference_platform.inf037b_archive import IntegrityError, encode, sha
from inference_platform.inf037b_attempts import AttemptController
from inference_platform.inf037b_resolver import SessionDeadline

try:
    lifecycle = importlib.import_module("inference_platform.inf037b_lifecycle")
except ModuleNotFoundError:
    lifecycle = None

CASES = []


class Round369ExistingDeadlineTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "POSIX process-group watchdog")
    def test_existing_watchdog_times_out_and_fences_child(self):
        def clock():
            return int(time.monotonic() * 1000)

        runner = lifecycle.ProcessCalls(
            {"cleanup": [sys.executable, "-c", "import time;time.sleep(60)"]}, clock
        )
        with self.assertRaises(lifecycle.subprocess.TimeoutExpired):
            runner("cleanup", clock() + 1100, {})

    def test_scope_windows_reuse_the_existing_driver_limits(self):
        import ast

        from inference_platform.inf037b_capture_inventory import _method
        from inference_platform.inf037b_eks_collectors import SCOPE_WINDOWS_MS

        preparation = [
            n
            for n in ast.walk(_method("inf037b_lifecycle.py", "LifecycleDriver._prepare"))
            if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Attribute)
            and n.func.attr == "_window"
            and isinstance(n.args[0], ast.Constant)
            and n.args[0].value == "preparation"
        ]
        self.assertEqual(len(preparation), 1)
        bound = preparation[0].args[1].args[0].right.value
        self.assertEqual(SCOPE_WINDOWS_MS["attempt_setup:1"], bound)
        self.assertEqual(SCOPE_WINDOWS_MS["export"], lifecycle.BOUNDS_MS["export"])
        self.assertEqual(SCOPE_WINDOWS_MS["cleanup"], lifecycle.BOUNDS_MS["cleanup"])

    @unittest.skipUnless(os.name == "posix", "POSIX process-group watchdog")
    def test_existing_watchdog_refuses_late_completion_observation(self):
        now = [0]
        original = lifecycle.subprocess.Popen.wait

        def late_wait(process, *args, **kwargs):
            result = original(process, *args, **kwargs)
            now[0] = 10001
            return result

        runner = lifecycle.ProcessCalls(
            {"cleanup": [sys.executable, "-c", "print('true')"]}, lambda: now[0]
        )
        with patch.object(lifecycle.subprocess.Popen, "wait", late_wait):
            with self.assertRaisesRegex(ValueError, "lifecycle:process_cutoff"):
                runner("cleanup", 10000, {})
        self.assertEqual(now[0], 10001)


class DriverTests(unittest.TestCase):
    def test_terminal_attempt_kill_reserve_equality_and_one_ms_excess(self):
        cutoff = 18_000_000 - 5_400_000 - 1_000
        self.driver.session_key = "fixture"

        def admitted(*args, **kwargs):
            raise IntegrityError("after_admission")

        self.driver.journal.append = admitted
        with self.assertRaisesRegex(IntegrityError, "after_admission"):
            self.driver.call("attempt", cutoff, {"attempt": 1})
        with self.assertRaisesRegex(IntegrityError, "attempt_kill_reserve"):
            self.driver.call("attempt", cutoff + 1, {"attempt": 1})
        self.assertEqual(self.trace, [])

    def setUp(self):
        self.assertIsNotNone(lifecycle, "4b lifecycle driver is absent at a033f5e")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.time = 0
        self.durations = {}
        self.failed_operations = set()
        self.trace = []
        self.barrier = lambda decision, stop: True
        self.outcome = dict(
            measurement_valid=True,
            reasons=[],
            operational_outcomes=[],
            replacement_usable_by_deadline=True,
        )
        self.journal = AttemptController(self.root / "attempts.jsonl")
        self.driver = lifecycle.LifecycleDriver(
            deadline=SessionDeadline(0, 18_000_000, 0),
            clock=lambda: self.time,
            execute=self.execute,
            attempts=self.journal,
        )

    def execute(self, operation, stop, context):
        self.trace.append((operation, stop, copy.deepcopy(context)))
        value = self.durations.get(operation, 0)
        self.time += value.pop(0) if isinstance(value, list) else value
        if operation in self.failed_operations:
            raise OSError(operation + " fixture failure")
        if operation == "attempt":
            value = copy.deepcopy(self.outcome)
            if hasattr(lifecycle, "valid_outcome"):
                value.setdefault("measurement_end_ms", self.time)
            return value
        if operation == "packet_barrier":
            return self.barrier(context, stop)
        return True

    def test_maximum_attempt_reset_schedule_and_full_cleanup(self):
        self.durations.update(
            creation=1_800_000,
            preparation=600_000,
            resolution=59_000,
            packet_barrier=1000,
            attempt_setup=[60_000, 300_000, 300_000],
            attempt=1_560_000,
            export=3_600_000,
            cleanup=1_800_000,
        )
        result = self.driver.run()
        self.assertEqual(result["refusals"], [])
        self.assertTrue(result["attempts"]["three_valid_events"])
        self.assertEqual(len(self.journal._of("attempt_start")), 3)
        self.assertEqual(len(self.journal._of("reset_start")), 2)
        self.assertEqual([e["target_slot"] for e in self.journal._of("attempt_start")], [0, 1, 0])
        self.assertEqual(self.time - 5_400_000 - self.driver.campaign_origin, 5_280_000)
        self.assertEqual([n for n, _, _ in self.trace][-2:], ["export", "cleanup"])
        self.assertLessEqual(self.time, 18_000_000)
        CASES.append({"case": "maximum_schedule", "result": result, "events": self.journal.events})

    def test_every_prestart_failure_closes_three_unattempted_slots(self):
        for phase in ("creation", "preparation", "resolution", "packet"):
            with self.subTest(phase=phase):
                self.setUp()
                if phase == "packet":
                    self.barrier = lambda *args: False
                else:
                    self.failed_operations.add(phase)
                result = self.driver.run()
                self.assertFalse(result["measurement_started"])
                self.assertEqual(
                    [s["state"] for s in result["attempts"]["slots"]], ["not_attempted"] * 3
                )
                self.assertEqual(len(self.journal._of("not_attempted")), 3)
                self.assertEqual([n for n, _, _ in self.trace][-2:], ["export", "cleanup"])

    def test_nonacknowledged_phase_never_counts_as_success(self):
        for phase in ("creation", "preparation", "export", "cleanup"):
            with self.subTest(phase=phase):
                self.setUp()
                original = self.execute

                def execute(operation, *args, phase=phase, original=original):
                    result = original(operation, *args)
                    return False if operation == phase else result

                self.driver.execute = execute
                result = self.driver.run()
                self.assertTrue(any(phase + "_ack" in r for r in result["refusals"]))
                if phase in {"creation", "preparation"}:
                    self.assertFalse(result["measurement_started"])
                self.assertEqual(self.trace[-1][0], "cleanup")

    def test_creation_uses_original_t0_after_acquisition_delay(self):
        self.time = 500_000
        result = self.driver.run()
        self.assertEqual(result["refusals"], [])
        self.assertEqual(self.trace[0][:2], ("creation", 1_800_000))

    def test_creation_readiness_equality_and_one_tick_late(self):
        for value, started in ((1_800_000, True), (1_800_001, False)):
            with self.subTest(value=value):
                self.setUp()
                self.durations["creation"] = value
                result = self.driver.run()
                self.assertEqual(result["measurement_started"], started)

    def test_expired_first_setup_budget_refuses_before_durable_attempt_start(self):
        for after_ack_tick in (0, 1):
            with self.subTest(after_ack_tick=after_ack_tick):
                self.setUp()
                self.durations.update(preparation=1_740_000, resolution=59_000, packet_barrier=1000)
                state = {"ack": False, "reads": 0}
                original = self.execute

                def execute(operation, *args, original=original, state=state):
                    result = original(operation, *args)
                    if operation == "packet_barrier":
                        state["ack"] = True
                    return result

                def clock(state=state, tick=after_ack_tick):
                    if state["ack"]:
                        state["reads"] += 1
                        if state["reads"] == 2:
                            self.time += tick
                    return self.time

                self.driver.execute, self.driver.clock = execute, clock
                result = self.driver.run()
                CASES.append(
                    {
                        "case": "first_setup_admission",
                        "after_ack_tick": after_ack_tick,
                        "result": result,
                        "events": self.journal.events,
                    }
                )
                self.assertFalse(result["measurement_started"])
                self.assertEqual(self.journal._of("attempt_start"), [])
                self.assertEqual(
                    [s["state"] for s in result["attempts"]["slots"]], ["not_attempted"] * 3
                )
                self.assertEqual(self.trace[-1][0], "cleanup")

    def test_phase_cutoffs_are_absolute_and_overrun_is_not_success(self):
        for phase, value in (
            ("preparation", 1_800_001),
            ("resolution", 60_001),
            ("attempt", 1_561_001),
            ("export", 3_600_001),
            ("cleanup", 1_800_001),
        ):
            with self.subTest(phase=phase):
                self.setUp()
                self.durations[phase] = value
                result = self.driver.run()
                self.assertTrue(any("call_overrun" in r for r in result["refusals"]))
                self.assertEqual(self.trace[-1][0], "cleanup")

    def test_remaining_equality_one_tick_and_later_reset_full_reserve(self):
        for attempts, resets in ((3, 2), (2, 2), (2, 1), (1, 1), (1, 0), (0, 0)):
            with self.subTest(counts=(attempts, resets)):
                self.setUp()
                required = attempts * 1_561_000 + resets * 300_000 + 5_400_000
                self.time = 18_000_000 - required
                self.assertEqual(
                    self.driver.remaining(attempts, resets)["latest_finish_ms"], 18_000_000
                )
                self.time += 1
                with self.assertRaisesRegex(IntegrityError, "remaining.*(range|reserve)"):
                    self.driver.remaining(attempts, resets)

    def test_clock_rejects_regression_noninteger_and_boolean(self):
        self.driver.now()
        for bad in (-1, True, 1.5):
            self.time = bad
            with self.assertRaisesRegex(IntegrityError, "lifecycle:clock"):
                self.driver.now()
        self.time = 1
        self.driver.now()
        self.time = 0
        with self.assertRaisesRegex(IntegrityError, "lifecycle:clock"):
            self.driver.now()

    def test_deadline_object_is_required(self):
        with self.assertRaisesRegex(IntegrityError, "lifecycle:deadline"):
            lifecycle.LifecycleDriver(deadline=None, clock=lambda: 0, execute=None, attempts=None)

    def test_call_rejects_expired_and_extended_cutoff(self):
        for stop in (0, -1, True, 1.5, 18_000_001):
            with self.subTest(stop=stop):
                with self.assertRaisesRegex(IntegrityError, "lifecycle:call_cutoff"):
                    self.driver.call("creation", stop)
        self.assertEqual(self.trace, [])

    def test_packet_barrier_cannot_spend_resolution_or_extend_deadline(self):
        def late(*args):
            self.time += 60_001
            return True

        self.barrier = late
        result = self.driver.run()
        self.assertFalse(result["measurement_started"])
        self.assertTrue(any("call_overrun" in r for r in result["refusals"]))
        with self.assertRaisesRegex(IntegrityError, "immutable_literals"):
            self.driver.deadline.require_unchanged(
                latest_consume_ms=1, session_ceiling_ms=18_000_001
            )

    def test_single_instance_refuses_and_completed_journal_reopens(self):
        self.driver.run()
        with self.assertRaisesRegex(IntegrityError, "single_run"):
            self.driver.run()
        before = (self.root / "lifecycle.jsonl").read_bytes()
        resumed = lifecycle.LifecycleDriver(
            deadline=self.driver.deadline,
            clock=lambda: self.time,
            execute=self.execute,
            attempts=self.journal,
        )
        result = resumed.run()
        self.assertTrue(result["attempts"]["three_valid_events"])
        self.assertEqual((self.root / "lifecycle.jsonl").read_bytes(), before)

    def test_never_usable_preserves_adverse_attempt_without_replacement(self):
        self.outcome["replacement_usable_by_deadline"] = False
        result = self.driver.run()
        self.assertEqual(len(self.journal._of("attempt_start")), 1)
        self.assertTrue(result["attempts"]["slots"][0]["measurement_valid"])
        self.assertEqual(
            [s["state"] for s in result["attempts"]["slots"][1:]], ["not_attempted"] * 2
        )

    def test_failed_reset_setup_consumes_next_attempt_then_closes_unused_slot(self):
        self.durations["attempt_setup"] = [0, 300_001]
        result = self.driver.run()
        self.assertEqual(len(self.journal._of("attempt_start")), 2)
        self.assertFalse(result["attempts"]["slots"][1]["measurement_valid"])
        self.assertEqual(result["attempts"]["slots"][2]["state"], "not_attempted")
        self.assertEqual(len(self.journal._of("reset_failed")), 1)

    def test_failed_attempt_setup_is_allocated_and_cannot_start_traffic(self):
        original = self.execute
        self.driver.execute = lambda op, *args: (
            False if op == "attempt_setup" else original(op, *args)
        )
        result = self.driver.run()
        self.assertEqual(len(self.journal._of("attempt_start")), 1)
        self.assertEqual(self.journal._of("traffic_start"), [])
        self.assertFalse(result["attempts"]["slots"][0]["measurement_valid"])

    def test_export_failure_still_runs_cleanup_with_full_reserve(self):
        self.failed_operations.add("export")
        result = self.driver.run()
        self.assertEqual(self.trace[-1][0], "cleanup")
        self.assertEqual(
            result["calls"][-1]["stop_ms"] - result["calls"][-1]["start_ms"], 1_800_000
        )
        self.assertTrue(any(r.startswith("export:") for r in result["refusals"]))

    def test_all_remaining_work_is_checked_before_reset_row(self):
        original = self.journal.end_attempt

        def end(*args, **kwargs):
            original(*args, **kwargs)
            self.time = 10_200_000

        self.journal.end_attempt = end
        result = self.driver.run()
        self.assertEqual(self.journal._of("reset_start"), [])
        self.assertEqual(len(self.journal._of("attempt_start")), 1)
        self.assertTrue(result["refusals"])

    def test_all_remaining_work_is_checked_before_later_start(self):
        original = self.journal.begin_reset

        def begin(*args, **kwargs):
            original(*args, **kwargs)
            self.time = 10_200_000

        self.journal.begin_reset = begin
        self.driver.run()
        self.assertEqual(len(self.journal._of("attempt_start")), 1)

    def test_all_remaining_work_is_checked_after_setup_before_traffic_execution(self):
        original = self.driver.remaining
        checks = []

        def checked(*args, **kwargs):
            checks.append(args)
            if len(checks) == 8:
                raise IntegrityError("all remaining work no longer fits after setup")
            return original(*args, **kwargs)

        self.driver.remaining = checked
        self.driver.run()
        self.assertEqual(len(self.journal._of("attempt_start")), 2)
        self.assertEqual(sum(n == "attempt" for n, _, _ in self.trace), 1)
        self.assertEqual(len(self.journal._of("traffic_start")), 1)

    def test_first_setup_stays_in_preparation_budget_and_traffic_has_full_attempt(self):
        self.durations.update(
            preparation=1_700_000,
            resolution=59_000,
            packet_barrier=1000,
            attempt_setup=[40_000, 0, 0],
        )
        result = self.driver.run()
        self.assertEqual(result["refusals"], [])
        first = next(c for c in result["calls"] if c["operation"] == "attempt")
        self.assertEqual(first["stop_ms"] - first["start_ms"], 1_560_000)
        self.setUp()
        self.durations.update(
            preparation=1_700_000, resolution=59_000, packet_barrier=1000, attempt_setup=40_001
        )
        result = self.driver.run()
        self.assertEqual(self.journal._of("traffic_start"), [])
        self.assertTrue(any("call_overrun" in r for r in result["refusals"]))

    def test_process_late_completion_is_rejected_after_reap(self):
        values = iter((0, 0, 4001))
        runner = lifecycle.ProcessCalls(
            {"op": [sys.executable, "-c", "print('true')"]}, lambda: next(values)
        )
        with self.assertRaisesRegex(IntegrityError, "process_cutoff"):
            runner("op", 4000, {})

    def test_cancel_three_answers_include_partial_acceptance_and_unknown(self):
        body = {"expected_ids": ["cr-a", "cr-b"], "group": "group"}
        obs = {
            "authoritative": True,
            "key": "key",
            "body_sha256": sha(encode(body)),
            "reservations": {
                i: {"state": "active", "cancel_accepted": True} for i in body["expected_ids"]
            },
            "result": {"verified": False},
        }

        def classify():
            return lifecycle.cancel_reconcile("odcr.cancel", "key", body, obs)

        self.assertEqual(
            classify(), {"known": True, "executed": True, "result": {"verified": False}}
        )
        obs["reservations"]["cr-b"]["cancel_accepted"] = False
        self.assertEqual(classify(), {"known": True, "executed": False, "result": None})
        obs["reservations"]["cr-b"]["state"] = "cancelled"
        self.assertFalse(classify()["known"])
        del obs["reservations"]["cr-b"]
        self.assertFalse(classify()["known"])
        CASES.append({"case": "cancel_classification", "observation": obs, "answer": classify()})

    def test_cancel_missing_stale_unbound_and_malformed_stay_unknown(self):
        body = {"expected_ids": ["cr-a"]}
        good = {
            "authoritative": True,
            "key": "key",
            "body_sha256": sha(encode(body)),
            "reservations": {"cr-a": {"state": "active", "cancel_accepted": True}},
        }
        mutations = [
            ("authoritative", False),
            ("key", "other"),
            ("body_sha256", "wrong"),
            ("reservations", []),
            ("reservations", {"cr-a": None}),
            ("reservations", {"cr-a": {"state": "active", "cancel_accepted": None}}),
            ("reservations", {"cr-a": {"state": "active", "cancel_accepted": 0}}),
        ]
        for key, value in mutations:
            with self.subTest(key=key, value=value):
                obs = dict(good, **{key: value})
                self.assertFalse(
                    lifecycle.cancel_reconcile("odcr.cancel", "key", body, obs)["known"]
                )
        self.assertFalse(lifecycle.cancel_reconcile("odcr.cancel", "key", body, None)["known"])

    def test_cancel_operation_and_expected_id_contract(self):
        with self.assertRaisesRegex(IntegrityError, "cancel_operation"):
            lifecycle.cancel_reconcile("odcr.acquire", "k", {"expected_ids": []}, None)
        for ids in (["a", "a"], [""], [1], None, ("a",)):
            with self.subTest(ids=ids):
                with self.assertRaisesRegex(IntegrityError, "cancel_ids"):
                    lifecycle.cancel_reconcile("odcr.cancel", "k", {"expected_ids": ids}, None)

    def test_cancel_that_never_took_effect_reruns_identical_request_before_backstop(self):
        from inf037b_ports_support import Rig

        rig = Rig()
        self.addCleanup(rig.close)
        provider = rig.responses.capacity
        provider.outcomes = ["partial", "ok"]
        controller = rig.open()
        controller.mark()
        service = rig.responses.services["capacity"]
        effect = service.effect

        def drop_cancel(operation, key, body):
            if operation == "odcr.cancel":
                raise OSError("cancel never reached provider")
            return effect(operation, key, body)

        service.effect = drop_cancel
        with self.assertRaises(OSError):
            controller.acquire()
        pending = service.store.read()["pending"]
        self.assertEqual(pending["operation"], "odcr.cancel")
        token = controller._token(0)
        self.assertNotIn(token, provider.cancelled)

        def reconcile(operation, key, body):
            observation = {
                "authoritative": True,
                "key": key,
                "body_sha256": sha(encode(body)),
                "reservations": {
                    i: {"state": "active", "cancel_accepted": False} for i in body["expected_ids"]
                },
            }
            return lifecycle.cancel_reconcile(operation, key, body, observation)

        service.reconcile = reconcile
        seen = []

        def retry(operation, key, body):
            seen.append((operation, key, body))
            return effect(operation, key, body)

        service.effect = retry
        recovered = rig.open()
        recovered.recover()
        self.assertEqual(seen, [(pending["operation"], pending["key"], pending["body"])])
        events = [r["event"] for r in rig.journal.rows]
        self.assertLess(events.index("cancelled"), events.index("ledger"))
        self.assertLess(events.index("ledger"), events.index("advanced"))
        self.assertLess(rig.world.now, next(iter(rig.responses.backstop.armed.values())))
        self.assertGreater(recovered._get("ledger", 0)["cost_micros"], 0)
        completion = service.store.read()["completed"][pending["operation_key"]]
        self.assertEqual({k: completion[k] for k in pending}, pending)
        CASES.append(
            {
                "case": "never_effective_cancel",
                "pending": pending,
                "completion": completion,
                "events": rig.journal.rows,
                "wire": rig.responses.records,
                "before_backstop": True,
            }
        )

    def test_process_platform_guard(self):
        with patch.object(lifecycle.os, "name", "nt"):
            with self.assertRaisesRegex(IntegrityError, "process_platform"):
                lifecycle.ProcessCalls({}, lambda: 0)

    def test_real_watchdog_executes_every_driver_phase(self):
        def clock():
            return time.monotonic_ns() // 1_000_000

        commands = dict.fromkeys(
            (
                "creation",
                "preparation",
                "resolution",
                "packet_barrier",
                "attempt_setup",
                "export",
                "cleanup",
            ),
            [sys.executable, "-c", "print('true')"],
        )
        commands["attempt"] = [
            sys.executable,
            "-c",
            "import json,sys,time;c=json.load(sys.stdin);v="
            + repr(self.outcome)
            + ";v['measurement_end_ms']=time.monotonic_ns()//1000000;print(json.dumps(v))",
        ]
        origin = clock()
        driver = lifecycle.LifecycleDriver(
            deadline=SessionDeadline(origin, origin + 18_000_000, origin),
            clock=clock,
            execute=lifecycle.ProcessCalls(commands, clock),
            attempts=self.journal,
        )
        result = driver.run()
        self.assertEqual(result["refusals"], [])
        self.assertEqual(len(result["calls"]), 12)
        self.assertTrue(result["attempts"]["three_valid_events"])
        CASES.append({"case": "real_watchdog_all_phases", "result": result})

    def test_initial_envelope_samples_clock_once(self):
        ticks = iter(range(100))
        self.driver.clock = lambda: next(ticks)
        result = self.driver.remaining(3, 2, None, first=True)
        self.assertEqual(result["latest_finish_ms"], 14_403_000)

    def test_reset_cutoff_comes_from_previous_attempt_end(self):
        original = self.journal.end_attempt

        def end(*args, **kwargs):
            original(*args, **kwargs)
            self.time += 50_000

        self.journal.end_attempt = end
        result = self.driver.run()
        self.assertEqual(result["refusals"], [])
        setups = [c for c in result["calls"] if c["operation"] == "attempt_setup"]
        for setup in setups[1:]:
            self.assertEqual(setup["stop_ms"] - setup["start_ms"], 250_000)

    def test_process_success_error_output_and_reserve(self):
        def clock():
            return time.monotonic_ns() // 1_000_000

        for code, reason in (
            ("print('true')", None),
            ("raise SystemExit(3)", "process_exit"),
            ("import json;print(json.dumps('x'*999998))", "process_output"),
        ):
            with self.subTest(code=code):
                runner = lifecycle.ProcessCalls({"op": [sys.executable, "-c", code]}, clock)
                if reason:
                    with self.assertRaisesRegex(IntegrityError, reason):
                        runner("op", clock() + 4000, {})
                else:
                    self.assertIs(runner("op", clock() + 4000, {}), True)
        runner = lifecycle.ProcessCalls({}, clock)
        with self.assertRaisesRegex(IntegrityError, "process_reserve"):
            runner("op", clock() + 1000, {})

    def test_cancel_accepted_and_unknown_reads_never_rerun_pending_effect(self):
        from inf037b_ports_support import Rig

        for accepted in (True, None):
            with self.subTest(accepted=accepted):
                rig = Rig()
                self.addCleanup(rig.close)
                provider = rig.responses.capacity
                provider.outcomes = ["partial", "ok"]
                provider.cancel_ok = False
                controller = rig.open()
                controller.mark()
                with self.assertRaises((OSError, IntegrityError)):
                    controller.acquire()
                service = rig.responses.services["capacity"]
                pending = service.store.read()["pending"]

                def reconcile(operation, key, body, accepted=accepted, provider=provider):
                    return lifecycle.cancel_reconcile(
                        operation,
                        key,
                        body,
                        {
                            "authoritative": True,
                            "key": key,
                            "body_sha256": sha(encode(body)),
                            "reservations": {
                                i: {"state": "cancelled", "cancel_accepted": accepted}
                                for i in body["expected_ids"]
                            },
                            "result": provider.cancellation(key),
                        },
                    )

                with (
                    patch.object(service, "reconcile", reconcile),
                    patch.object(service, "effect") as effect,
                ):
                    with self.assertRaises((OSError, IntegrityError)):
                        rig.open().recover()
                    effect.assert_not_called()
                self.assertEqual(service.store.read()["pending"], pending)
                self.assertFalse(
                    any(r["event"] in {"cancelled", "ledger", "advanced"} for r in rig.journal.rows)
                )

    def test_process_watchdog_kills_hung_child_within_cutoff(self):
        def clock():
            return time.monotonic_ns() // 1_000_000

        runner = lifecycle.ProcessCalls(
            {"op": [sys.executable, "-c", "import time; time.sleep(30)"]}, clock
        )
        start = clock()
        with self.assertRaises(lifecycle.subprocess.TimeoutExpired):
            runner("op", start + 1200, {})
        elapsed = clock() - start
        self.assertLess(elapsed, 1200)
        CASES.append({"case": "real_child_timeout", "elapsed_ms": elapsed, "cutoff_ms": 1200})

    def test_process_kills_descendants_even_after_parent_exits(self):
        def clock():
            return time.monotonic_ns() // 1_000_000

        sentinel = self.root / "escaped"
        child = (
            "import time,pathlib;time.sleep(.5);pathlib.Path(" + repr(str(sentinel)) + ").touch()"
        )
        code = (
            "import subprocess,sys;subprocess.Popen([sys.executable,'-c',"
            + repr(child)
            + "]);print('true')"
        )
        runner = lifecycle.ProcessCalls({"op": [sys.executable, "-c", code]}, clock)
        self.assertTrue(runner("op", clock() + 4000, {}))
        time.sleep(0.65)
        self.assertFalse(sentinel.exists(), "descendant escaped watchdog process group")


def load_tests(loader, tests, pattern):
    # Follow the accepted ports suite: positive POSIX cases belong to Linux,
    # while native Windows runs portable behavior and explicit platform refusal.
    linux_only = {
        "test_cancel_that_never_took_effect_reruns_identical_request_before_backstop",
        "test_cancel_accepted_and_unknown_reads_never_rerun_pending_effect",
        "test_process_success_error_output_and_reserve",
        "test_process_watchdog_kills_hung_child_within_cutoff",
        "test_process_kills_descendants_even_after_parent_exits",
        "test_process_late_completion_is_rejected_after_reap",
        "test_real_watchdog_executes_every_driver_phase",
    }
    return unittest.TestSuite(
        DriverTests(name)
        for name in loader.getTestCaseNames(DriverTests)
        if os.name == "posix" or name not in linux_only
    )


if __name__ == "__main__":
    unittest.main()
