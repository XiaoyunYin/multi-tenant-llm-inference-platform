import http.client
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from inference_platform.r1_cloud_operator import Forward, Operator, host_diagnostic_commands


class BootstrapHealthTests(unittest.TestCase):
    def run_forward(self, listening):
        with tempfile.TemporaryDirectory() as root:
            op = Operator(Path(root), {}, Path(root), time.time() + 100)
            child = MagicMock()
            child.poll.return_value = None
            faults = [http.client.RemoteDisconnected()] * (12 if listening else 6)
            state = "running-listening" if listening else "not-running"
            invocation = {
                "Status": "Success",
                "StandardOutputContent": f"R1_BOOTSTRAP_HEALTH={state}\n"
                "systemctl status: unit r1-bootstrap not found\n--token secret-token\n",
            }
            with (
                patch.object(op, "tunnel", return_value=(1, child)),
                patch.object(op, "rpc", side_effect=[*faults, (b"ok", {})]) as rpc,
                patch.object(op, "ssm", return_value=invocation) as ssm,
                patch("inference_platform.r1_cloud_operator.time.sleep"),
                patch("inference_platform.r1_cloud_operator.stop_forward"),
                patch(
                    "inference_platform.r1_cloud_operator.terminate_forward_session",
                    return_value={},
                ),
            ):
                channel = Forward(op, "host", "secret-token", "service", "ready")
                if listening:
                    self.assertEqual(channel.request("/status")[0], b"ok")
                    self.assertEqual(rpc.call_count, 13)
                else:
                    with self.assertRaisesRegex(RuntimeError, "bootstrap not running/listening"):
                        channel.request("/status")
                    self.assertEqual(rpc.call_count, 6)
                ssm.assert_called_once_with("host", host_diagnostic_commands(), timeout_s=45)
                evidence = (Path(root) / "bootstrap-health.jsonl").read_text()
                self.assertNotIn("secret-token", evidence)
                self.assertEqual(json.loads(evidence)["running_listening"], listening)
                self.assertEqual(channel.status_failures, 0 if listening else 6)

    def test_six_failures_dead_nohup_host_fails_fast_with_one_check(self):
        self.run_forward(False)

    def test_healthy_nohup_host_without_unit_keeps_bounded_reconnects_without_second_check(self):
        self.run_forward(True)

    def test_success_resets_consecutive_failure_count(self):
        with tempfile.TemporaryDirectory() as root:
            op = Operator(Path(root), {}, Path(root), time.time() + 100)
            child = MagicMock()
            child.poll.return_value = None
            with (
                patch.object(op, "tunnel", return_value=(1, child)),
                patch.object(
                    op,
                    "rpc",
                    side_effect=[
                        *([http.client.RemoteDisconnected()] * 5),
                        (b"ok", {}),
                        *([http.client.RemoteDisconnected()] * 5),
                        (b"ok", {}),
                    ],
                ),
                patch.object(op, "bootstrap_health") as health,
                patch("inference_platform.r1_cloud_operator.time.sleep"),
                patch("inference_platform.r1_cloud_operator.stop_forward"),
                patch(
                    "inference_platform.r1_cloud_operator.terminate_forward_session",
                    return_value={},
                ),
            ):
                channel = Forward(op, "host", "token", "service", "ready")
                channel.request("/status")
                channel.request("/status")
                health.assert_not_called()

    def test_ssm_health_failure_is_recorded_and_fails_closed(self):
        with tempfile.TemporaryDirectory() as root:
            op = Operator(Path(root), {}, Path(root), time.time() + 100)
            with patch.object(op, "ssm", side_effect=TimeoutError("bounded health timeout")):
                self.assertFalse(op.bootstrap_health("host", "service"))
            self.assertIn(
                "bounded health timeout", (Path(root) / "bootstrap-health.jsonl").read_text()
            )

    def test_health_ssm_pending_has_45_second_local_bound_without_changing_ready_deadline(self):
        with tempfile.TemporaryDirectory() as root:
            clock = [100.0]
            op = Operator(Path(root), {}, Path(root), 2500)

            def aws(service, operation, args, *, deadline):
                self.assertEqual(deadline, 145)
                if operation == "send-command":
                    parameter = args[args.index("--parameters") + 1]
                    self.assertTrue(parameter.startswith("file://"))
                    params = json.loads(Path(parameter.removeprefix("file://")).read_bytes())
                    self.assertEqual(params["executionTimeout"], ["45"])
                    return {"Command": {"CommandId": "cmd"}}
                return {"Status": "Pending"}

            def sleep(seconds):
                clock[0] += seconds

            with (
                patch(
                    "inference_platform.r1_cloud_operator.time.time", side_effect=lambda: clock[0]
                ),
                patch("inference_platform.r1_cloud_operator.time.sleep", side_effect=sleep),
                patch.object(op, "aws", side_effect=aws),
            ):
                with self.assertRaisesRegex(TimeoutError, "SSM command deadline"):
                    op.ssm("host", host_diagnostic_commands(), timeout_s=45)
            self.assertEqual(clock[0], 145)
            self.assertEqual(op.deadline, 2500)
