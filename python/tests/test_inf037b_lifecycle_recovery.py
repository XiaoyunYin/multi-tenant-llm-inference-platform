"""Second 4b part: typed/time boundaries and actual SIGKILL/reopen cuts."""

import copy
import json
import os
import signal
import subprocess
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from test_inf037b_lifecycle import DriverTests, lifecycle

from inference_platform.inf037b_archive import (
    IntegrityError,
    encode,
    envelope,
    inspect_segment,
    sha,
)
from inference_platform.inf037b_resolver import SessionDeadline

CASES = []


class RecoveryTests(DriverTests):
    def _worker_command(self, root, cut=None, hold=False, scenario="normal", delay=0):
        args = [
            sys.executable,
            str(Path(__file__).with_name("inf037b_lifecycle_worker.py")),
            "--root",
            str(root),
            "--scenario",
            scenario,
        ]
        args += ["--restart-delay", str(delay)]
        if cut:
            args += ["--cut", str(cut)]
        if hold:
            args += ["--hold"]
        if hasattr(lifecycle, "__mutant_source__"):
            source = self.root / "mutant.py"
            source.write_text(lifecycle.__mutant_source__)
            args += ["--source", str(source)]
        return args

    def _worker(self, root, cut=None, scenario="normal", delay=0):
        return subprocess.run(
            self._worker_command(root, cut, scenario=scenario, delay=delay),
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )

    def test_checked_completion_survives_ticking_clock_for_attempt_and_reset(self):
        for boundary in ("attempt", "reset"):
            with self.subTest(boundary=boundary):
                self.setUp()
                original = self.execute
                ticking = [False]
                checked = []

                def execute(
                    operation,
                    stop,
                    context,
                    boundary=boundary,
                    checked=checked,
                    ticking=ticking,
                    original=original,
                ):
                    inner = context.get("input", context) if type(context) is dict else context
                    hit = operation == "attempt" and boundary == "attempt" and not checked
                    hit |= (
                        operation == "attempt_setup"
                        and boundary == "reset"
                        and inner["attempt"] == 2
                    )
                    if hit:
                        self.time = stop
                        ticking[0] = True
                        checked.append(stop)
                    return original(operation, stop, context)

                def clock(ticking=ticking):
                    value = self.time
                    if ticking[0]:
                        self.time += 1
                    return value

                self.driver.execute, self.driver.clock = execute, clock
                result = self.driver.run()
                self.assertEqual(result["refusals"], [])
                self.assertTrue(result["attempts"]["three_valid_events"])
                rows = self.journal._of(
                    "attempt_end" if boundary == "attempt" else "setup_complete"
                )
                self.assertEqual(rows[0 if boundary == "attempt" else 1]["now_ms"], checked[0])
                CASES.append(
                    {
                        "case": "ticking_completion",
                        "boundary": boundary,
                        "checked_ms": checked[0],
                        "rows": rows,
                    }
                )

    def test_maximum_path_keeps_measurement_deadline_with_post_exit_reserve(self):
        original = self.execute
        self.durations.update(
            creation=1_800_000,
            preparation=600_000,
            resolution=59_000,
            packet_barrier=1000,
            attempt_setup=[60_000, 299_900, 299_900],
        )

        def execute(operation, stop, context):
            if operation == "attempt":
                self.time = stop + 100
                return {**self.outcome, "measurement_end_ms": stop}
            return original(operation, stop, context)

        self.driver.execute = execute
        result = self.driver.run()
        self.assertEqual(result["refusals"], [])
        self.assertTrue(result["attempts"]["three_valid_events"])
        for end, traffic in zip(
            self.journal._of("attempt_end"), self.journal._of("traffic_start"), strict=True
        ):
            self.assertEqual(end["now_ms"], traffic["deadline_ms"])
        for call in result["calls"]:
            if call["operation"] == "attempt":
                self.assertEqual(call["kill_ms"], call["stop_ms"] + 1000)
                self.assertLessEqual(call["kill_ms"], result["D_eff_ms"] - 5_400_000)
        CASES.append(
            {"case": "maximum_with_flush", "result": result, "events": self.journal.events}
        )

    def test_invalid_reported_end_after_deadline_or_exit_aborts_at_deadline(self):
        for bad in ("after_deadline", "after_exit", "before_traffic", "after_observed_exit"):
            with self.subTest(bad=bad):
                self.setUp()
                original = self.execute

                def execute(operation, stop, context, original=original, bad=bad):
                    if operation != "attempt":
                        return original(operation, stop, context)
                    traffic = self.journal._of("traffic_start")[-1]
                    self.time += 10
                    end = {
                        "after_deadline": stop + 1,
                        "after_exit": self.time + 1,
                        "before_traffic": traffic["now_ms"] - 1,
                        "after_observed_exit": self.time - 1,
                    }[bad]
                    # Keep the negative-end case in the typed integer range.
                    value = {**self.outcome, "measurement_end_ms": end}
                    if bad == "after_observed_exit":
                        return lifecycle.AttemptExit(value, self.time - 5)
                    return value

                self.durations["attempt_setup"] = 20
                self.driver.execute = execute
                result = self.driver.run()
                self.assertEqual(len(self.journal._of("attempt_start")), 1)
                end = self.journal._of("attempt_end")[0]
                self.assertEqual(end["now_ms"], self.journal._of("traffic_start")[0]["deadline_ms"])
                self.assertIs(end["measurement_valid"], False)
                self.assertEqual(end["operational_outcomes"], ["aborted"])
                self.assertIn("measurement_end", " ".join(result["refusals"]))
                self.assertEqual([n for n, _, _ in self.trace][-2:], ["export", "cleanup"])

    def test_exact_outcome_types_extra_and_missing_keep_raw_and_close_slots(self):
        good = {**self.outcome, "measurement_end_ms": 0}
        wrong = [("replacement_usable_by_deadline", v) for v in (0, "false", [], {})]
        wrong += [("measurement_valid", v) for v in (1, "true", None)]
        wrong += [
            (k, v) for k in ("reasons", "operational_outcomes") for v in ("", {}, [""], [1], [None])
        ]
        wrong += [("measurement_end_ms", v) for v in (True, "0", None, 0.0, -1)]
        values = [{**good, k: v} for k, v in wrong]
        values += [{**good, "extra": True}] + [
            {k: v for k, v in good.items() if k != missing} for missing in good
        ]
        values += [None, [], "outcome", 1]
        for index, value in enumerate(values):
            with self.subTest(index=index, raw=value):
                self.setUp()
                original = self.execute
                self.driver.execute = lambda op, stop, ctx, value=value, original=original: (
                    copy.deepcopy(value) if op == "attempt" else original(op, stop, ctx)
                )
                result = self.driver.run()
                self.assertEqual(len(self.journal._of("attempt_start")), 1)
                self.assertIs(self.journal._of("attempt_end")[0]["measurement_valid"], False)
                self.assertEqual(
                    self.journal._of("attempt_end")[0]["operational_outcomes"], ["aborted"]
                )
                self.assertIn("outcome_shape", " ".join(result["refusals"]))
                self.assertEqual(result["raw_outcomes"][0]["value"], value)
                self.assertEqual(encode(result["raw_outcomes"][0]["value"]), encode(value))
                self.assertEqual(
                    [s["state"] for s in result["attempts"]["slots"][1:]], ["not_attempted"] * 2
                )
                self.assertEqual([n for n, _, _ in self.trace][-2:], ["export", "cleanup"])
        CASES.append({"case": "outcome_shape_matrix", "cases": len(values)})
        self.setUp()
        self.outcome["replacement_usable_by_deadline"] = None
        result = self.driver.run()
        self.assertTrue(result["attempts"]["three_valid_events"])
        self.assertTrue(
            all(
                r["replacement_usable_by_deadline"] is None for r in self.journal._of("attempt_end")
            )
        )

    def test_malformed_shape_uses_checked_completion_despite_close_clock_ticks(self):
        original = self.execute
        ticking = [False]
        completion = []

        def execute(operation, stop, context):
            value = original(operation, stop, context)
            if operation == "attempt":
                completion.append(self.time)
                ticking[0] = True
                return {"malformed": True}
            return value

        def clock():
            value = self.time
            if ticking[0]:
                self.time += 1
            return value

        self.driver.execute, self.driver.clock = execute, clock
        result = self.driver.run()
        self.assertIn("outcome_shape", " ".join(result["refusals"]))
        self.assertEqual(self.journal._of("attempt_end")[0]["now_ms"], completion[0])

    def _killed_process_fixture(self, root, phase, cut):
        command = self._worker_command(root) + ["--process-phase", phase, "--spawn-cut", cut]
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            until = time.monotonic() + 8
            while (
                not (root / "ready").exists() and proc.poll() is None and time.monotonic() < until
            ):
                time.sleep(0.01)
            self.assertTrue((root / "ready").exists(), "driver never reached process cut")
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.communicate(timeout=3)
        self.assertEqual(proc.returncode, -signal.SIGKILL)
        return root

    def _remove_fixture_children(self, root):
        path = root / "children.json"
        if path.exists():
            try:
                os.killpg(json.loads(path.read_text())[0], signal.SIGKILL)
            except ProcessLookupError:
                pass

    def test_real_sigkill_spawned_matrix_fences_setup_attempt_and_grandchildren(self):
        observations = []
        for phase in ("creation", "attempt"):
            for cut in ("before", "after", "acting"):
                with self.subTest(phase=phase, cut=cut):
                    root = self.root / f"{phase}-{cut}"
                    self.addCleanup(self._remove_fixture_children, root)
                    self._killed_process_fixture(root, phase, cut)
                    time.sleep(0.15)
                    _, rows = inspect_segment(root / "lifecycle.jsonl")
                    life = [r["payload"] for r in rows]
                    spawned = [
                        r
                        for r in life
                        if r["event"] == "spawned" and r["key"].split(":")[0] == phase
                    ]
                    if cut == "before":
                        self.assertFalse(spawned)
                    else:
                        self.assertEqual(len(spawned), 1)
                        self.assertEqual(
                            set(spawned[0]["identity"]), {"pid", "group", "start_ticks", "boot_id"}
                        )
                    if cut != "acting":
                        self.assertFalse(
                            (root / "acted").exists(), "child acted before durable release"
                        )
                    resumed = self._worker(root, delay=10_000)
                    self.assertEqual(resumed.returncode, 0, resumed.stderr)
                    data = json.loads(resumed.stdout)
                    self.assertFalse(
                        (root / "terminal-saw-live").exists(), "terminal executor raced old group"
                    )
                    self.assertIn("interrupted_call", " ".join(data["result"]["refusals"]))
                    self.assertEqual(data["effect_order"][-2:], ["export", "cleanup"])
                    if phase == "attempt":
                        self.assertEqual(
                            len(
                                [
                                    r
                                    for r in data["attempts"]
                                    if r["payload"]["event"] == "attempt_start"
                                ]
                            ),
                            1,
                        )
                        self.assertIs(
                            [
                                r["payload"]
                                for r in data["attempts"]
                                if r["payload"]["event"] == "attempt_end"
                            ][0]["measurement_valid"],
                            False,
                        )
                    time.sleep(1.05)
                    self.assertFalse((root / "escaped").exists())
                    observations.append({"phase": phase, "cut": cut, "spawned": spawned})
        CASES.append({"case": "real_spawned_sigkill_matrix", "cuts": observations})

    def test_process_reused_identity_kills_nothing_and_unconfirmed_fence_blocks_close(self):
        identity = (
            lifecycle.child_identity(os.getpid())
            if os.getpgrp() == os.getpid()
            else {
                "pid": os.getpid(),
                "group": os.getpid(),
                "start_ticks": 1,
                "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            }
        )
        identity["start_ticks"] += 1
        with (
            patch.object(lifecycle.os, "killpg") as kill,
            patch.object(lifecycle, "group_members", return_value=[123]),
        ):
            for owned in (False, True):
                with self.assertRaisesRegex(IntegrityError, "child_identity_unconfirmed"):
                    lifecycle.fence_child(identity, owned=owned)
            kill.assert_not_called()
        # A pending real-child row must block every subsequent effect, including
        # the campaign close, even when the replacement executor is synthetic.
        root = self.root / "uncertain"
        self.addCleanup(self._remove_fixture_children, root)
        self._killed_process_fixture(root, "attempt", "acting")
        _, rows = inspect_segment(root / "lifecycle.jsonl")
        before = (root / "attempts.jsonl").read_bytes()
        clock = max(r["payload"]["now_ms"] for r in rows) + 10_000
        driver = lifecycle.LifecycleDriver(
            deadline=SessionDeadline(50, 18_000_050, 17),
            clock=lambda: clock,
            execute=lambda *a: self.fail("effect after uncertain fence"),
            attempts=root / "attempts.jsonl",
        )
        with patch.object(lifecycle, "fence_child", side_effect=OSError("unconfirmed group")):
            result = driver.run()
        self.assertIn("reopen_fence", " ".join(result["refusals"]))
        self.assertEqual((root / "attempts.jsonl").read_bytes(), before)
        _, final = inspect_segment(root / "lifecycle.jsonl")
        self.assertFalse(
            any(
                r["payload"]["event"] in {"stop_intent", "terminal_visit", "complete"}
                for r in final
            )
        )

        # Kernel-identity mismatch persisted in an otherwise valid journal.
        previous = None
        rebuilt = []
        for index, row in enumerate(final):
            payload = row["payload"]
            if payload["event"] == "spawned" and payload["key"] == "attempt:1":
                payload["identity"]["start_ticks"] += 1
            payload["previous_sha256"] = previous
            entry = envelope(payload, seq=index)
            rebuilt.append(encode(entry))
            previous = sha(encode(entry))
        (root / "lifecycle.jsonl").write_bytes(b"".join(rebuilt))
        driver = lifecycle.LifecycleDriver(
            deadline=SessionDeadline(50, 18_000_050, 17),
            clock=lambda: clock,
            execute=lambda *a: self.fail("effect on PID reuse"),
            attempts=root / "attempts.jsonl",
        )
        with patch.object(lifecycle.os, "killpg", wraps=os.killpg) as kill:
            result = driver.run()
            kill.assert_not_called()
        self.assertIn("child_identity_unconfirmed", " ".join(result["refusals"]))
        self.assertEqual((root / "attempts.jsonl").read_bytes(), before)

        with (
            patch.object(
                lifecycle,
                "kernel_process",
                return_value={"group": identity["group"], "start_ticks": identity["start_ticks"]},
            ),
            patch.object(lifecycle, "group_members", return_value=[identity["pid"]]),
            patch.object(lifecycle.os, "killpg") as kill,
        ):
            with self.assertRaisesRegex(IntegrityError, "child_group_unconfirmed"):
                lifecycle.fence_child(identity, timeout=0.01)
            kill.assert_called_once_with(identity["group"], signal.SIGKILL)

    def test_real_missing_leader_with_live_grandchild_refuses_reopen_fence(self):
        root = self.root / "orphan"
        self.addCleanup(self._remove_fixture_children, root)
        self._killed_process_fixture(root, "creation", "orphan")
        ids = json.loads((root / "children.json").read_text())
        self.assertIsNone(lifecycle.kernel_process(ids[0]))
        self.assertIn(ids[1], lifecycle.group_members(ids[0]))
        resumed = self._worker(root)
        self.assertEqual(resumed.returncode, 0, resumed.stderr)
        data = json.loads(resumed.stdout)
        self.assertIn("reopen_fence", " ".join(data["result"]["refusals"]))
        self.assertEqual(data["effect_order"], [])
        self.assertFalse(any(r["payload"]["event"] == "child_fenced" for r in data["lifecycle"]))

    def _uncertain_process_executor(self, phase):
        original = self.execute
        calls = []

        class Executor(lifecycle.ProcessCalls):
            def __call__(self, operation, stop, context, **kwargs):
                calls.append(operation)
                if operation == phase:
                    return super().__call__(operation, stop, context, **kwargs)
                return original(operation, stop, context)

        self.driver.execute = Executor(
            {phase: [sys.executable, "-c", "print('true')"]}, lambda: self.time
        )
        return calls

    def test_process_export_unconfirmed_fence_blocks_cleanup(self):
        calls = self._uncertain_process_executor("export")
        with patch.object(
            lifecycle, "fence_child", side_effect=OSError("unconfirmed export fence")
        ):
            result = self.driver.run()
        self.assertIn("export", calls)
        self.assertNotIn("cleanup", calls)
        self.assertIn("reopen_fence", " ".join(result["refusals"]))

    def test_process_attempt_unconfirmed_fence_writes_no_stop_or_attempt_end(self):
        self._uncertain_process_executor("attempt")
        with patch.object(
            lifecycle, "fence_child", side_effect=OSError("unconfirmed attempt fence")
        ):
            result = self.driver.run()
        self.assertIn("reopen_fence", " ".join(result["refusals"]))
        self.assertEqual(self.journal._of("attempt_end"), [])
        self.assertFalse(any(r["event"] == "stop_intent" for r in self.driver.journal.rows))

    def test_process_spawned_different_boot_refuses_without_signal(self):
        root = self.root / "different-boot"
        self.addCleanup(self._remove_fixture_children, root)
        self._killed_process_fixture(root, "creation", "acting")
        _, rows = inspect_segment(root / "lifecycle.jsonl")
        previous, rebuilt = None, []
        for index, row in enumerate(rows):
            payload = row["payload"]
            if payload["event"] == "spawned":
                payload["identity"]["boot_id"] = "different-boot-fixture"
            payload["previous_sha256"] = previous
            entry = envelope(payload, seq=index)
            rebuilt.append(encode(entry))
            previous = sha(encode(entry))
        (root / "lifecycle.jsonl").write_bytes(b"".join(rebuilt))
        driver = lifecycle.LifecycleDriver(
            deadline=SessionDeadline(50, 18_000_050, 17),
            clock=lambda: 100,
            execute=lambda *a: self.fail("terminal executor on another boot"),
            attempts=root / "attempts.jsonl",
        )
        with patch.object(lifecycle.os, "killpg", wraps=os.killpg) as kill:
            result = driver.run()
        kill.assert_not_called()
        self.assertIn("child_boot", " ".join(result["refusals"]))

    def test_wrong_legacy_field_types_never_allocate_later_attempts(self):
        # Match the old four-key wire contract in the isolated eed6531 control,
        # so these cases demonstrate its unsafe type acceptance directly.
        for field, value in (
            ("replacement_usable_by_deadline", 0),
            ("replacement_usable_by_deadline", "false"),
            ("measurement_valid", 1),
        ):
            with self.subTest(field=field, value=value):
                self.setUp()
                self.outcome[field] = value
                result = self.driver.run()
                self.assertEqual(len(self.journal._of("attempt_start")), 1)
                self.assertIs(self.journal._of("attempt_end")[0]["measurement_valid"], False)
                self.assertIn("outcome_shape", " ".join(result["refusals"]))

    def test_remaining_checks_charge_one_reserve_per_remaining_attempt(self):
        for attempts, resets in ((3, 2), (2, 2), (2, 1), (1, 1), (1, 0)):
            with self.subTest(attempts=attempts, resets=resets):
                self.setUp()
                required = attempts * 1_561_000 + resets * 300_000 + 5_400_000
                self.time = 18_000_000 - required
                self.assertEqual(
                    self.driver.remaining(attempts, resets)["latest_finish_ms"], 18_000_000
                )
                self.time += 1
                with self.assertRaises(IntegrityError):
                    self.driver.remaining(attempts, resets)

    def test_attempt_kill_cutoff_cannot_enter_export_cleanup_reserve(self):
        with self.assertRaisesRegex(IntegrityError, "attempt_kill_reserve"):
            self.driver.call("attempt", 18_000_000 - 5_400_000, {"attempt": 1})
        self.assertEqual(self.trace, [])

    def test_reopen_rejects_changed_session_binding_and_missing_original_journal(self):
        self.driver.run()
        before = (self.root / "lifecycle.jsonl").read_bytes()
        resumed = lifecycle.LifecycleDriver(
            deadline=SessionDeadline(1, 18_000_001, 1),
            clock=lambda: self.time,
            execute=self.execute,
            attempts=self.journal,
        )
        with self.assertRaisesRegex(IntegrityError, "original_binding"):
            resumed.run()
        self.assertEqual((self.root / "lifecycle.jsonl").read_bytes(), before)
        _, legacy_rows = inspect_segment(self.root / "lifecycle.jsonl")
        legacy_rows[0]["payload"]["binding"].pop("child_fence_protocol", None)
        previous, rebuilt = None, []
        for index, row in enumerate(legacy_rows):
            row["payload"]["previous_sha256"] = previous
            entry = envelope(row["payload"], seq=index)
            rebuilt.append(encode(entry))
            previous = sha(encode(entry))
        (self.root / "lifecycle.jsonl").write_bytes(b"".join(rebuilt))
        legacy = lifecycle.LifecycleDriver(
            deadline=self.driver.deadline,
            clock=lambda: self.time,
            execute=lambda *a: self.fail("legacy child provenance"),
            attempts=self.journal,
        )
        with self.assertRaisesRegex(IntegrityError, "original_binding"):
            legacy.run()
        (self.root / "lifecycle.jsonl").unlink()
        resumed = lifecycle.LifecycleDriver(
            deadline=self.driver.deadline,
            clock=lambda: self.time,
            execute=self.execute,
            attempts=self.journal,
        )
        with self.assertRaisesRegex(IntegrityError, "missing_original_journal"):
            resumed.run()

    def test_torn_or_rechained_journal_refuses_without_external_calls(self):
        self.driver.run()
        path = self.root / "lifecycle.jsonl"
        original = path.read_bytes()
        for damage in (
            original + b'{"torn":',
            original.replace(b'"exit_reserve_ms":1000', b'"exit_reserve_ms":1001', 1),
            original.replace(b'"operation":"creation"', b'"operation":"changed"', 1),
        ):
            with self.subTest(damage=damage[-20:]):
                path.write_bytes(damage)
                before = len(self.trace)
                driver = lifecycle.LifecycleDriver(
                    deadline=self.driver.deadline,
                    clock=lambda: self.time,
                    execute=self.execute,
                    attempts=self.journal,
                )
                with self.assertRaises(IntegrityError):
                    driver.run()
                self.assertEqual(len(self.trace), before)
        path.write_bytes(original)
        before = len(self.trace)
        driver = lifecycle.LifecycleDriver(
            deadline=self.driver.deadline,
            clock=lambda: self.time,
            execute=self.execute,
            attempts=self.journal,
        )
        with patch.object(lifecycle.os, "fsync", side_effect=OSError("lost recovery barrier")):
            with self.assertRaisesRegex(OSError, "recovery barrier"):
                driver.run()
        self.assertEqual(len(self.trace), before)
        self.assertEqual(path.read_bytes(), original)

    def test_uncertain_journal_write_poison_stops_effects_and_preserves_raw_bytes(self):
        original = lifecycle.durable_write

        def partial_write(path, data, mode="xb"):
            if path.name == "lifecycle.jsonl" and b'"event":"call_start"' in data:
                with path.open(mode) as stream:
                    stream.write(b'{"torn":')
                    stream.flush()
                raise OSError("injected uncertain write")
            return original(path, data, mode)

        with patch.object(lifecycle, "durable_write", partial_write):
            with self.assertRaises((OSError, IntegrityError)):
                self.driver.run()
        self.assertTrue(self.driver.journal.failed)
        self.assertEqual(self.trace, [])
        path = self.root / "lifecycle.jsonl"
        damaged = path.read_bytes()
        self.assertTrue(damaged.endswith(b'{"torn":'))
        with self.assertRaisesRegex(IntegrityError, "poisoned"):
            self.driver.journal.append("unsafe_retry", self.time)
        self.assertEqual(path.read_bytes(), damaged)
        reopened = lifecycle.LifecycleDriver(
            deadline=self.driver.deadline,
            clock=lambda: self.time,
            execute=self.execute,
            attempts=self.journal,
        )
        with self.assertRaisesRegex(IntegrityError, "truncated_jsonl"):
            reopened.run()
        self.assertEqual(self.trace, [])

    def test_sigkill_writer_lease_releases_only_on_process_death(self):
        root = self.root / "exclusive"
        proc = subprocess.Popen(
            self._worker_command(root, 1, hold=True),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            deadline = time.monotonic() + 5
            while (
                not (root / "ready").exists()
                and proc.poll() is None
                and time.monotonic() < deadline
            ):
                time.sleep(0.01)
            self.assertTrue((root / "ready").exists())
            before = (root / "lifecycle.jsonl").read_bytes()
            contender = self._worker(root)
            self.assertNotEqual(contender.returncode, 0)
            self.assertEqual((root / "lifecycle.jsonl").read_bytes(), before)
            self.assertFalse((root / "executor.json").exists())
        finally:
            proc.kill()
            proc.communicate(timeout=5)
        self.assertEqual(proc.returncode, -signal.SIGKILL)
        resumed = self._worker(root)
        self.assertEqual(resumed.returncode, 0, resumed.stderr)
        self.assertTrue(json.loads(resumed.stdout)["result"]["attempts"]["three_valid_events"])

    def test_sigkill_reopen_late_reset_does_not_extend_or_allocate(self):
        normal = self._worker(self.root / "reference")
        self.assertEqual(normal.returncode, 0, normal.stderr)
        cuts = json.loads(normal.stdout)["cuts"]
        cut = next(
            i
            for i, r in enumerate(cuts, 1)
            if r["kind"] == "attempt" and r["event"] == "reset_start"
        )
        root = self.root / "late-reset"
        self.assertEqual(self._worker(root, cut).returncode, -signal.SIGKILL)
        _, rows = inspect_segment(root / "attempts.jsonl")
        reset = rows[-1]["payload"]
        state = json.loads((root / "executor.json").read_bytes())
        state["clock_ms"] = reset["deadline_ms"] + 1
        (root / "executor.json").write_bytes(encode(state))
        resumed = self._worker(root)
        self.assertEqual(resumed.returncode, 0, resumed.stderr)
        data = json.loads(resumed.stdout)
        events = [r["payload"] for r in data["attempts"]]
        self.assertEqual(len([r for r in events if r["event"] == "attempt_start"]), 1)
        self.assertEqual([r for r in events if r["event"] == "reset_start"], [reset])
        self.assertTrue(any(r["event"] == "reset_failed" for r in events))
        self.assertEqual(data["effect_order"][-2:], ["export", "cleanup"])

    def test_sigkill_completed_attempt_receipt_keeps_checked_end_after_restart_delay(self):
        normal = self._worker(self.root / "reference")
        self.assertEqual(normal.returncode, 0, normal.stderr)
        cuts = json.loads(normal.stdout)["cuts"]
        cut = next(
            i
            for i, r in enumerate(cuts, 1)
            if r["kind"] == "lifecycle" and r["event"] == "call_end" and r["key"] == "attempt:1"
        )
        for delay in (0, 10_000):
            with self.subTest(restart_delay_ms=delay):
                root = self.root / ("receipt-" + str(delay))
                self.assertEqual(self._worker(root, cut).returncode, -signal.SIGKILL)
                state = json.loads((root / "executor.json").read_bytes())
                checked_end = state["effects"]["attempt:1"]["value"]["measurement_end_ms"]
                state["clock_ms"] += delay
                (root / "executor.json").write_bytes(encode(state))
                resumed = self._worker(root)
                self.assertEqual(resumed.returncode, 0, resumed.stderr)
                data = json.loads(resumed.stdout)
                ends = [
                    r["payload"] for r in data["attempts"] if r["payload"]["event"] == "attempt_end"
                ]
                self.assertEqual(ends[0]["now_ms"], checked_end)
                self.assertIs(ends[0]["measurement_valid"], True)
                self.assertTrue(data["result"]["attempts"]["three_valid_events"])
                first_traffic = next(
                    r["payload"]
                    for r in data["attempts"]
                    if r["payload"]["event"] == "traffic_start"
                )
                self.assertEqual(data["result"]["campaign_origin_ms"], first_traffic["now_ms"])

    def test_sigkill_late_completed_receipt_does_not_become_a_timely_ack(self):
        normal = self._worker(self.root / "reference", scenario="creation_overrun")
        self.assertEqual(normal.returncode, 0, normal.stderr)
        cuts = json.loads(normal.stdout)["cuts"]
        cut = next(
            i
            for i, r in enumerate(cuts, 1)
            if r["kind"] == "lifecycle" and r["event"] == "call_end" and r["key"] == "creation"
        )
        root = self.root / "late-receipt"
        self.assertEqual(
            self._worker(root, cut, scenario="creation_overrun").returncode, -signal.SIGKILL
        )
        resumed = self._worker(root, scenario="creation_overrun")
        self.assertEqual(resumed.returncode, 0, resumed.stderr)
        data = json.loads(resumed.stdout)
        self.assertFalse(data["result"]["measurement_started"])
        self.assertIn("call_overrun", " ".join(data["result"]["refusals"]))
        self.assertEqual(data["effect_order"][-2:], ["export", "cleanup"])

        # Downtime before preparation's first window must not move t0+3,600 s.
        reference = self._worker(self.root / "delayed-reference", scenario="delayed_preparation")
        self.assertEqual(reference.returncode, 0, reference.stderr)
        cuts = json.loads(reference.stdout)["cuts"]
        cut = next(
            i
            for i, row in enumerate(cuts, 1)
            if row["kind"] == "lifecycle"
            and row["event"] == "call_end"
            and row["key"] == "creation"
        )
        root = self.root / "delayed-preparation"
        self.assertEqual(
            self._worker(root, cut, scenario="delayed_preparation").returncode, -signal.SIGKILL
        )
        state = json.loads((root / "executor.json").read_bytes())
        state["clock_ms"] = 17 + 3_000_000
        (root / "executor.json").write_bytes(encode(state))
        resumed = self._worker(root, scenario="delayed_preparation")
        self.assertEqual(resumed.returncode, 0, resumed.stderr)
        data = json.loads(resumed.stdout)
        preparation = next(
            row["payload"]
            for row in data["lifecycle"]
            if row["payload"]["event"] == "window" and row["payload"]["key"] == "preparation"
        )
        self.assertEqual(preparation["stop_ms"], 17 + 3_600_000)
        self.assertTrue(data["result"]["attempts"]["three_valid_events"])
        self.assertLessEqual(data["result"]["campaign_origin_ms"], 17 + 3_600_000)

    def test_process_context_over_128k_uses_file_backed_stdin(self):
        def clock():
            return time.monotonic_ns() // 1_000_000

        code = "import json,sys;c=json.load(sys.stdin);print(json.dumps([len(c['blob']),len(sys.argv)]))"
        runner = lifecycle.ProcessCalls({"op": [sys.executable, "-c", code]}, clock)
        self.assertEqual(runner("op", clock() + 4000, {"blob": "x" * 200_000}), [200_000, 1])
        CASES.append(
            {
                "case": "stdin_context",
                "json_bytes": len(encode({"blob": "x" * 200_000})),
                "argv_items": 1,
            }
        )

    def test_real_process_separate_measurement_and_kill_cutoffs(self):
        def clock():
            return time.monotonic_ns() // 1_000_000

        deadline = clock() + 400
        code = (
            "import json,sys,time;c=json.load(sys.stdin);d=c['measurement_deadline_ms'];"
            "time.sleep(max(0,d/1000-time.monotonic()));time.sleep(.05);"
            "print(json.dumps({'measurement_end_ms':d}))"
        )
        runner = lifecycle.ProcessCalls({"attempt": [sys.executable, "-c", code]}, clock)
        result = runner(
            "attempt",
            deadline,
            {"measurement_deadline_ms": deadline, "kill_cutoff_ms": deadline + 1000},
        )
        self.assertEqual(result.value, {"measurement_end_ms": deadline})
        self.assertGreaterEqual(result.observed_ms, deadline)
        self.assertLessEqual(result.observed_ms, deadline + 1000)
        CASES.append(
            {
                "case": "real_post_deadline_exit",
                "measurement_deadline_ms": deadline,
                "kill_cutoff_ms": deadline + 1000,
                "parent_observed_exit_ms": result.observed_ms,
                "flush_exit_ms": result.observed_ms - deadline,
            }
        )

    def test_real_child_after_deadline_plus_reserve_is_killed_and_driver_aborted(self):
        def clock():
            return time.monotonic_ns() // 1_000_000

        sentinel = self.root / "late_child_escaped"
        code = "import time,pathlib;time.sleep(3);pathlib.Path(" + repr(str(sentinel)) + ").touch()"
        runner = lifecycle.ProcessCalls({"attempt": [sys.executable, "-c", code]}, clock)
        original = self.execute
        observed = []

        def execute(operation, stop, context):
            if operation == "attempt":
                start = clock()
                try:
                    # Short local watchdog probe; the driver's registered
                    # deadline remains full length and is never scaled.
                    runner("attempt", start + 100, {"measurement_deadline_ms": start + 100})
                finally:
                    observed.append(clock() - start)
            return original(operation, stop, context)

        self.driver.execute = execute
        result = self.driver.run()
        end = self.journal._of("attempt_end")[0]
        self.assertIs(end["measurement_valid"], False)
        self.assertEqual(end["now_ms"], self.journal._of("traffic_start")[0]["deadline_ms"])
        self.assertEqual(len(self.journal._of("attempt_start")), 1)
        self.assertIn("TimeoutExpired", " ".join(result["refusals"]))
        self.assertLess(observed[0], 2000)
        time.sleep(0.05)
        self.assertFalse(sentinel.exists())
        CASES.append(
            {"case": "real_late_child_aborted", "elapsed_ms": observed[0], "attempt_end": end}
        )

    def test_sigkill_every_durable_row_reopens_without_reallocation_or_rebased_anchors(self):
        self._check_all_cuts("normal")

    def test_sigkill_adverse_rows_preserve_stop_and_terminal_order(self):
        for scenario in ("reset_failure", "never_usable", "export_failure", "bad_end"):
            with self.subTest(scenario=scenario):
                self.setUp()
                self._check_all_cuts(scenario)

    def _check_all_cuts(self, scenario):
        normal = self._worker(self.root / "normal", scenario=scenario)
        self.assertEqual(normal.returncode, 0, normal.stderr)
        reference = json.loads(normal.stdout)
        if scenario in {"normal", "export_failure"}:
            self.assertTrue(reference["result"]["attempts"]["three_valid_events"])
        else:
            self.assertFalse(reference["result"]["attempts"]["three_valid_events"])
        self.assertGreater(len(reference["cuts"]), 20)
        cases = []
        for cut, label in enumerate(reference["cuts"], 1):
            with self.subTest(cut=cut, label=label):
                root = self.root / ("cut-" + str(cut))
                killed = self._worker(root, cut, scenario=scenario)
                self.assertEqual(killed.returncode, -signal.SIGKILL, killed.stderr)
                paths = [
                    p for p in (root / "attempts.jsonl", root / "lifecycle.jsonl") if p.exists()
                ]
                prefixes = {p: p.read_bytes() for p in paths}
                initial_events = []
                if (root / "attempts.jsonl").exists():
                    _, initial_rows = inspect_segment(root / "attempts.jsonl")
                    initial_events = [r["payload"] for r in initial_rows]
                initial_life = []
                if (root / "lifecycle.jsonl").exists():
                    _, initial_rows = inspect_segment(root / "lifecycle.jsonl")
                    initial_life = [r["payload"] for r in initial_rows]
                completed_keys = {
                    r["key"] for r in initial_life if r["event"] in {"call_end", "call_error"}
                }
                pending = [
                    r
                    for r in initial_life
                    if r["event"] == "call_start"
                    and r["key"] not in completed_keys
                    and r["operation"] not in {"export", "cleanup"}
                ]
                initial_effects = (
                    json.loads((root / "executor.json").read_bytes())["effects"]
                    if (root / "executor.json").exists()
                    else {}
                )
                resumed = self._worker(root, scenario=scenario, delay=10_000)
                self.assertEqual(resumed.returncode, 0, resumed.stderr)
                data = json.loads(resumed.stdout)
                for path, prefix in prefixes.items():
                    self.assertTrue(path.read_bytes().startswith(prefix), str(path))
                events = [r["payload"] for r in data["attempts"]]
                starts = [r for r in events if r["event"] == "attempt_start"]
                # Position-based, independent of which refusal happened to fire.
                for allocated in (r for r in initial_events if r["event"] == "attempt_start"):
                    attempt = allocated["attempt"]
                    if not any(
                        r["event"] == "call_start" and r.get("key") == f"attempt:{attempt}"
                        for r in initial_life
                    ):
                        ends = [
                            r
                            for r in events
                            if r["event"] == "attempt_end" and r["attempt"] == attempt
                        ]
                        self.assertEqual(len(ends), 1)
                        self.assertIs(ends[0]["measurement_valid"], False)
                        self.assertEqual(len(starts), attempt)
                        old_traffic = [
                            r
                            for r in initial_events
                            if r["event"] == "traffic_start" and r["attempt"] == attempt
                        ]
                        new_traffic = [
                            r
                            for r in events
                            if r["event"] == "traffic_start" and r["attempt"] == attempt
                        ]
                        self.assertEqual(new_traffic, old_traffic, "recovery manufactured traffic")
                self.assertEqual([r["attempt"] for r in starts], list(range(1, len(starts) + 1)))
                self.assertLessEqual(len(starts), 3)
                if pending:
                    self.assertEqual(
                        len(starts), sum(r["event"] == "attempt_start" for r in initial_events)
                    )
                    for row in pending:
                        self.assertEqual(
                            row["key"] in data["effects"], row["key"] in initial_effects
                        )
                self.assertFalse(
                    any(
                        s.get("state") == "in_progress" for s in data["result"]["attempts"]["slots"]
                    )
                )
                previous_end = None
                for row in events:
                    if row["event"] == "attempt_end":
                        previous_end = row["now_ms"]
                    elif row["event"] == "reset_start":
                        self.assertEqual(row["deadline_ms"], previous_end + 300_000)
                    elif row["event"] == "traffic_start":
                        self.assertEqual(row["deadline_ms"], row["now_ms"] + 1_560_000)
                life = [r["payload"] for r in data["lifecycle"]]
                binding = life[0]["binding"]["deadline"]
                self.assertEqual(
                    binding,
                    {
                        "latest_consume_ms": 50,
                        "session_ceiling_ms": 18_000_050,
                        "billing_origin_ms": 17,
                    },
                )
                self.assertEqual(data["result"]["D_eff_ms"], 18_000_017)
                traffic = [r for r in events if r["event"] == "traffic_start"]
                self.assertEqual(
                    data["result"]["campaign_origin_ms"], traffic[0]["now_ms"] if traffic else None
                )
                visits = [r["key"] for r in life if r["event"] == "terminal_visit"]
                self.assertEqual(visits, ["export", "cleanup"])
                effects = data["effect_order"]
                self.assertEqual(effects[-1], "cleanup")
                if scenario != "export_failure":
                    self.assertEqual(effects[-2:], ["export", "cleanup"])
                else:
                    self.assertNotIn("export", effects)
                    self.assertIn(
                        "export", [r["operation"] for r in life if r["event"] == "call_start"]
                    )
                before = {p: p.read_bytes() for p in paths}
                again = self._worker(root, scenario=scenario)
                self.assertEqual(again.returncode, 0, again.stderr)
                self.assertEqual(json.loads(again.stdout)["effects"], data["effects"])
                for path, prefix in before.items():
                    self.assertEqual(path.read_bytes(), prefix)
                cases.append(
                    {
                        "cut": cut,
                        **label,
                        "starts": len(starts),
                        "stop_reason": next(
                            (r["reason"] for r in events if r["event"] == "campaign_stop"), None
                        ),
                        "prefix_sha256": {p.name: sha(b) for p, b in prefixes.items()},
                    }
                )
        CASES.append(
            {
                "case": "sigkill_all_durable_rows",
                "scenario": scenario,
                "cuts": cases,
                "reference_cuts": reference["cuts"],
            }
        )


LINUX_ONLY = {
    name
    for name in RecoveryTests.__dict__
    if name.startswith("test_process_")
    or name.startswith("test_real_")
    or name.startswith("test_sigkill_")
}
ROUND259_TESTS = [
    "test_malformed_shape_uses_checked_completion_despite_close_clock_ticks",
    "test_real_sigkill_spawned_matrix_fences_setup_attempt_and_grandchildren",
    "test_process_reused_identity_kills_nothing_and_unconfirmed_fence_blocks_close",
]
NEW_TESTS = sorted(name for name in RecoveryTests.__dict__ if name.startswith("test_"))


def load_tests(loader, tests, pattern):
    return unittest.TestSuite(
        RecoveryTests(name) for name in NEW_TESTS if os.name == "posix" or name not in LINUX_ONLY
    )


if __name__ == "__main__":
    unittest.main()
