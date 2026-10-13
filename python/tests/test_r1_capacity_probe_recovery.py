import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from inference_platform.r1_lifecycle import (
    ConsumeGate,
    Production,
    execute,
    sha,
)
from inference_platform.r1_lifecycle import (
    main as lifecycle_main,
)
from inference_platform.r1_lifecycle_rehearsal import fixture_inputs

RESERVATION_ID = "cr-r144-probe"


def reservation(state):
    return {
        "CapacityReservationId": RESERVATION_ID,
        "State": state,
        "AvailabilityZone": "us-east-1b",
        "InstanceType": "g6.xlarge",
        "InstancePlatform": "Linux/UNIX",
        "Tenancy": "default",
        "InstanceMatchCriteria": "open",
        "TotalInstanceCount": 2,
        "AvailableInstanceCount": 2,
    }


class CapacityProbeRecoveryTests(unittest.TestCase):
    def run_case(
        self,
        scenario,
        *,
        cleanup_succeeds=True,
        probe_timeout=180,
        pending_timeout=3,
        settle_timeout=3,
        poll_seconds=1,
        margin_seconds=20,
        fail_internal_late_cancel=False,
    ):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        repo = Path(temporary.name)
        output = repo / "output"
        output.mkdir()
        plan, inputs = fixture_inputs("success")
        inputs.update(
            {
                "terraform": "terraform.exe",
                "session_id": "r144-session",
                "aws_profile": "fake",
                "availability_zone": "us-east-1b",
            }
        )
        terraform = repo / inputs["terraform"]
        terraform.write_bytes(b"local test terraform")
        adapter = Production(repo, inputs, output)
        gate = ConsumeGate(repo / "consume.sqlite3")
        clock = [100.0]
        state = {"reservation": "pending", "cancel_calls": 0}
        calls = []
        poll_counts = {
            "capacity-reservation-pending-probe": 0,
            "capacity-reservation-pending-settle": 0,
        }

        def fake_aws(_service, operation, args, deadline, name):
            calls.append((operation, name, list(args), deadline))
            if operation == "create-capacity-reservation":
                if scenario == "deadline-binds-second-window":
                    clock[0] += 110
                return {"CapacityReservation": reservation("pending")}
            if operation == "describe-capacity-reservations":
                if name in poll_counts:
                    poll_counts[name] += 1
                    index = poll_counts[name]
                    if (
                        scenario == "describe-error"
                        and name.endswith("pending-probe")
                        and index == 1
                    ):
                        raise RuntimeError("InvalidCapacityReservationId.NotFound")
                    if scenario == "not-found-then-active" and name.endswith("pending-probe"):
                        if index == 1:
                            raise RuntimeError("InvalidCapacityReservationId.NotFound")
                        state["reservation"] = "active"
                        return {"CapacityReservations": [reservation("active")]}
                    if (
                        scenario in {"late-active", "late-active-cancel-raises"}
                        and name.endswith("pending-settle")
                        and index >= 2
                    ):
                        state["reservation"] = "active"
                        return {"CapacityReservations": [reservation("active")]}
                    return {"CapacityReservations": [reservation("pending")]}
                if name == "capacity-reservation-before-cancel":
                    if state["reservation"] == "pending":
                        state["reservation"] = "active"
                    return {"CapacityReservations": [reservation(state["reservation"])]}
                if name == "capacity-reservation-after-cancel":
                    current = "cancelled" if cleanup_succeeds else "active"
                    state["reservation"] = current
                    return {"CapacityReservations": [reservation(current)]}
                if name == "capacity-reservation-session-inventory":
                    if state["reservation"] in {"cancelled", "expired", "failed"}:
                        return {"CapacityReservations": []}
                    return {"CapacityReservations": [reservation(state["reservation"])]}
                raise AssertionError(f"unexpected reservation describe: {name}")
            if operation == "cancel-capacity-reservation":
                state["cancel_calls"] += 1
                if cleanup_succeeds:
                    state["reservation"] = "cancelled"
                return {}
            raise AssertionError(f"unexpected AWS operation: {operation}")

        def apply(_plan, _deadline, record):
            record("apply_stubbed")

        original_cancel = adapter.cancel_capacity
        cancel_method_calls = [0]

        def cancel_with_optional_error(reservation_id, deadline):
            cancel_method_calls[0] += 1
            if fail_internal_late_cancel and cancel_method_calls[0] == 1:
                raise RuntimeError("internal cancellation state unknown")
            return original_cancel(reservation_id, deadline)

        with (
            patch.object(adapter, "now", side_effect=lambda: clock[0]),
            patch(
                "inference_platform.r1_lifecycle.time.sleep",
                side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds),
            ),
            patch.object(adapter, "aws", side_effect=fake_aws),
            patch.object(adapter, "cancel_capacity", side_effect=cancel_with_optional_error),
            patch.object(adapter, "preflight", return_value=None),
            patch.object(adapter, "apply", side_effect=apply),
            patch.object(adapter, "ready", return_value=None),
            patch.object(adapter, "measure", return_value=None),
            patch.object(adapter, "wait_until", return_value=None),
            patch.object(adapter, "close_admissions", return_value=None),
            patch.object(adapter, "export", return_value=True),
            patch.object(adapter, "destroy", return_value=None),
            patch.object(adapter, "verify_teardown", return_value=[]),
            patch("inference_platform.r1_lifecycle.CAPACITY_PROBE_TIMEOUT_SECONDS", probe_timeout),
            patch(
                "inference_platform.r1_lifecycle.CAPACITY_RESERVATION_PENDING_TIMEOUT_SECONDS",
                pending_timeout,
            ),
            patch(
                "inference_platform.r1_lifecycle.CAPACITY_RESERVATION_SETTLE_TIMEOUT_SECONDS",
                settle_timeout,
            ),
            patch(
                "inference_platform.r1_lifecycle.CAPACITY_RESERVATION_POLL_SECONDS", poll_seconds
            ),
            patch(
                "inference_platform.r1_lifecycle.CAPACITY_RESERVATION_WINDOW_MARGIN_SECONDS",
                margin_seconds,
            ),
        ):
            result = execute(
                adapter,
                plan,
                inputs,
                gate,
                lambda _inputs: None,
                output / "receipt.json",
            )

        with gate.connect() as db:
            halt_count = db.execute("SELECT COUNT(*) FROM halt").fetchone()[0]
        return result, calls, poll_counts, state, halt_count, cancel_method_calls[0]

    def test_pending_describe_error_keeps_polling_and_cleanup_controls_exit_and_halt(self):
        clean, calls, _poll_counts, state, halt_count, _cancel_calls = self.run_case(
            "describe-error"
        )
        probe = next(event for event in clean["events"] if event["event"] == "capacity_probe")
        names = [event["event"] for event in clean["events"]]
        self.assertEqual(probe["capacity_reservation_id"], RESERVATION_ID)
        self.assertEqual(clean["exit_code"], 2)
        self.assertIn("capacity_reservation_cancelled", names)
        self.assertEqual(state["cancel_calls"], 1)
        self.assertEqual(halt_count, 0)
        self.assertFalse(any(name == "plan_consumed" for name in names))

        unverified, failed_calls, _poll_counts, _state, halt_count, _cancel_calls = self.run_case(
            "describe-error", cleanup_succeeds=False
        )
        probe = next(event for event in unverified["events"] if event["event"] == "capacity_probe")
        self.assertEqual(probe["capacity_reservation_id"], RESERVATION_ID)
        self.assertTrue(
            any(name == "capacity-reservation-session-inventory" for _, name, _, _ in failed_calls)
        )
        self.assertEqual(unverified["exit_code"], 2)
        self.assertEqual(halt_count, 1)

    def test_probe_deadline_leaves_second_window_time_for_cleanup(self):
        result, calls, poll_counts, state, halt_count, _cancel_calls = self.run_case(
            "deadline-binds-second-window",
            probe_timeout=180,
            pending_timeout=60,
            settle_timeout=60,
            poll_seconds=2,
            margin_seconds=20,
        )
        probe = next(event for event in result["events"] if event["event"] == "capacity_probe")
        self.assertEqual(probe["capacity_reservation_id"], RESERVATION_ID)
        self.assertEqual(result["exit_code"], 2)
        self.assertEqual(poll_counts["capacity-reservation-pending-settle"], 0)
        self.assertEqual(state["cancel_calls"], 1)
        self.assertTrue(
            any(name == "capacity-reservation-session-inventory" for _, name, _, _ in calls)
        )
        self.assertEqual(halt_count, 0)

    def test_not_found_then_active_is_a_successful_preconsume_probe(self):
        result, calls, poll_counts, _state, halt_count, _cancel_calls = self.run_case(
            "not-found-then-active"
        )
        events = result["events"]
        names = [event["event"] for event in events]
        probe = next(event for event in events if event["event"] == "capacity_probe")
        self.assertEqual(probe["result"], "success")
        self.assertEqual(poll_counts["capacity-reservation-pending-probe"], 2)
        self.assertLess(names.index("capacity_probe"), names.index("plan_consumed"))
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["gate_plan_status"], "verified")
        self.assertEqual(halt_count, 0)
        self.assertEqual(sum(op == "cancel-capacity-reservation" for op, _, _, _ in calls), 1)

    def test_late_active_in_second_window_is_cancelled_once_then_refused(self):
        result, calls, poll_counts, state, halt_count, _cancel_calls = self.run_case(
            "late-active", pending_timeout=2, settle_timeout=4, poll_seconds=1
        )
        events = result["events"]
        probe = next(event for event in events if event["event"] == "capacity_probe")
        self.assertEqual(poll_counts["capacity-reservation-pending-probe"], 2)
        self.assertEqual(poll_counts["capacity-reservation-pending-settle"], 2)
        self.assertEqual(probe["state"], "active")
        self.assertTrue(probe["cleanup_verified"])
        self.assertEqual(result["exit_code"], 2)
        self.assertEqual(result["apply_count"], 0)
        self.assertIsNone(result["gate_plan_status"])
        self.assertEqual(state["cancel_calls"], 1)
        self.assertEqual(halt_count, 0)

    def test_late_cancel_exception_returns_unknown_and_execute_retries_cleanup(self):
        result, calls, _poll_counts, state, halt_count, cancel_method_calls = self.run_case(
            "late-active-cancel-raises",
            pending_timeout=2,
            settle_timeout=4,
            poll_seconds=1,
            fail_internal_late_cancel=True,
        )
        probe = next(event for event in result["events"] if event["event"] == "capacity_probe")
        self.assertEqual(probe["result"], "partial")
        self.assertEqual(probe["error_code"], "ReservationStateUnknown")
        self.assertEqual(probe["capacity_reservation_id"], RESERVATION_ID)
        self.assertEqual(probe["state"], "active")
        self.assertNotIn("cleanup_attempted", probe)
        self.assertEqual(cancel_method_calls, 2)
        self.assertEqual(state["cancel_calls"], 1)
        self.assertEqual(result["exit_code"], 2)
        self.assertEqual(halt_count, 0)
        names = [event["event"] for event in result["events"]]
        self.assertLess(
            names.index("capacity_probe"), names.index("capacity_reservation_cancelled")
        )

    def test_adapter_exception_is_recorded_and_tag_sweep_controls_halt(self):
        for clean in (True, False):
            with self.subTest(clean=clean), tempfile.TemporaryDirectory() as temporary:
                repo = Path(temporary)
                output = repo / "output"
                output.mkdir()
                plan, inputs = fixture_inputs("success")
                inputs.update(
                    {
                        "terraform": "terraform.exe",
                        "session_id": "r144-exception",
                        "aws_profile": "fake",
                        "availability_zone": "us-east-1b",
                    }
                )
                (repo / inputs["terraform"]).write_bytes(b"local test terraform")
                adapter = Production(repo, inputs, output)
                gate = ConsumeGate(repo / "consume.sqlite3")
                calls = []

                def aws(_service, operation, _args, _deadline, name, calls=calls):
                    calls.append((operation, name))
                    if operation == "describe-capacity-reservations":
                        return {"CapacityReservations": []}
                    raise AssertionError(f"unexpected AWS operation: {operation}")

                with (
                    patch.object(adapter, "preflight", return_value=None),
                    patch.object(
                        adapter, "reserve_capacity", side_effect=RuntimeError("probe failed")
                    ),
                    patch.object(adapter, "aws", side_effect=aws),
                    patch.object(
                        adapter,
                        "cancel_session_capacity_reservations",
                        return_value=clean,
                    ) as sweep,
                ):
                    result = execute(
                        adapter,
                        plan,
                        inputs,
                        gate,
                        lambda _inputs: None,
                        output / "receipt.json",
                    )

                probe = next(
                    event for event in result["events"] if event["event"] == "capacity_probe"
                )
                self.assertEqual(probe["error_code"], "RuntimeError")
                self.assertEqual(probe["error"], "probe failed")
                self.assertEqual(result["exit_code"], 2)
                self.assertEqual(result["apply_count"], 0)
                self.assertEqual(result["gate_plan_status"], None)
                self.assertEqual(calls, [])
                sweep.assert_called_once()
                with gate.connect() as db:
                    halt_count = db.execute("SELECT COUNT(*) FROM halt").fetchone()[0]
                self.assertEqual(halt_count, 0 if clean else 1)

    def test_recover_uncancellable_tagged_reservation_exits_one_and_marks_uncertain(self):
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            (repo / ".git").mkdir()
            inputs = {
                "plan_sha256": sha(b"recover-plan"),
                "commands": {"ready": ["fixture", "--inputs", "inputs.json"]},
                "terraform": "artifacts/terraform.exe",
                "region": "us-east-1",
                "aws_profile": "fake",
                "session_id": "r144-recovery",
                "runtime_directory": ".cache/runtime",
                "bundle_path": "artifacts/bundle.tar.gz",
                "session_manager_plugin_path": "artifacts/session-manager-plugin.exe",
            }
            terraform = repo / inputs["terraform"]
            terraform.parent.mkdir(parents=True)
            terraform.write_bytes(b"local test terraform")
            input_path = repo / "inputs.json"
            input_path.write_text(json.dumps(inputs), encoding="utf-8")
            saved_plan = repo / "plans/plan.tfplan"
            saved_plan.parent.mkdir()
            saved_plan.write_bytes(b"recover-plan")
            output = repo / "recover-output"
            gate = ConsumeGate(repo / ".git/r1-paid-consumption.sqlite3")
            gate.consume(
                inputs["plan_sha256"],
                {**inputs, "_capacity_reservation_id": RESERVATION_ID},
            )

            def aws(_self, _service, operation, _args, _deadline, _name):
                if operation == "describe-capacity-reservations":
                    return {"CapacityReservations": [reservation("active")]}
                if operation == "describe-instances":
                    return {"Reservations": []}
                if operation == "list-roles":
                    return {"Roles": []}
                if operation == "list-instance-profiles":
                    return {"InstanceProfiles": []}
                return {"Items": []}

            argv = [
                "r1_lifecycle",
                "--repo",
                str(repo),
                "--inputs",
                str(input_path),
                "--saved-plan",
                str(saved_plan),
                "--output",
                str(output),
                "--recover",
            ]
            with (
                patch.object(sys, "argv", argv),
                patch(
                    "inference_platform.r1_lifecycle.subprocess.check_output", return_value=".git"
                ),
                patch.object(
                    Production,
                    "cancel_capacity",
                    return_value={"verified": False, "state": "active", "cancel_requested": False},
                ),
                patch.object(Production, "destroy", return_value=None),
                patch.object(Production, "aws", new=aws),
                patch.object(Production, "tf", return_value=b"{}"),
            ):
                exit_code = lifecycle_main()

            recovery = json.loads((output / "recovery.json").read_text(encoding="utf-8"))
            self.assertEqual(exit_code, 1)
            self.assertIn("capacity-reservations", recovery["remaining"])
            self.assertFalse(recovery["verified"])
            self.assertEqual(gate.plan_status(inputs["plan_sha256"]), "uncertain")


if __name__ == "__main__":
    unittest.main()
