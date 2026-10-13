import hashlib
import http.client
import json
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from inference_platform.r1_cloud_operator import (
    ChannelError,
    Forward,
    Operator,
    cloud_init_commands,
)
from inference_platform.r1_evidence import Spool, restore
from inference_platform.r1_lifecycle import ConsumeGate, execute
from inference_platform.r1_lifecycle_rehearsal import Virtual, fixture_inputs
from inference_platform.r1_spec import encoded


class RecoveryTests(unittest.TestCase):
    def test_terminal_ssm_failures_retain_bounded_diagnostics_without_parameters(self):
        for status in ("Failed", "Cancelled", "TimedOut", "Cancelling", "UnknownTerminal"):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as root:
                folder = Path(root)
                op = Operator(folder, {}, folder, time.time() + 30)
                op.context_path.write_bytes(encoded({"hosts": {"gpu-0": {"id": "host"}}}))
                result = {
                    "Status": status,
                    "ResponseCode": 1,
                    "StandardOutputContent": "discard" + "o" * 4096,
                    "StandardErrorContent": "discard" + "e" * 4090 + "stderr",
                    "Parameters": {"commands": ["CONTROL_TOKEN"]},
                }
                with patch.object(
                    op, "aws", side_effect=[{"Command": {"CommandId": "cmd"}}, result]
                ):
                    with self.assertRaisesRegex(RuntimeError, "gpu-0.*host.*cmd.*code=1.*stderr"):
                        op.ssm("host", ["CONTROL_TOKEN"])
                raw = (folder / "ssm-failures.jsonl").read_bytes()
                failure = json.loads(raw)
                self.assertEqual(failure["CommandId"], "cmd")
                self.assertEqual(failure["Status"], status)
                self.assertEqual(failure["ResponseCode"], 1)
                self.assertEqual(failure["StandardOutputContent"], "o" * 4096)
                self.assertEqual(len(failure["StandardErrorContent"].encode()), 4096)
                self.assertNotIn(b"CONTROL_TOKEN", raw)
                self.assertNotIn(b"Parameters", raw)

    def test_gateway_logs_ship_once_and_rebuild_original_export_hash(self):
        with tempfile.TemporaryDirectory() as root:
            folder = Path(root)
            op = Operator(folder, {}, folder, time.time() + 30)
            session = folder / "generator/session"
            service = folder / "service/logs"
            session.mkdir(parents=True)
            service.mkdir(parents=True)
            configs = [{"policy": "rr", "R": 8}]
            logs = {"gateway-0.jsonl": '{"id":1}\n', "gateway-1.jsonl": '{"id":2}\n'}
            original = encoded({"configurations": configs, "gateway_logs": logs}) + b"\n"
            for name, data in logs.items():
                (service / name).write_bytes(data.encode())
            (session / "service-export-metadata.json").write_bytes(
                encoded({"configurations": configs})
            )
            (session / "export-receipt.json").write_bytes(
                encoded({"sha256": hashlib.sha256(original).hexdigest()})
            )
            op.reconstruct_gateway_export()
            self.assertEqual((session / "service-export.json").read_bytes(), original)
            (service / "gateway-0.jsonl").write_bytes(b"missing bytes")
            with self.assertRaisesRegex(ValueError, "differs from host receipt"):
                op.reconstruct_gateway_export()

    def test_delayed_bind_keeps_fresh_helper_and_does_not_count_reconnect(self):
        with tempfile.TemporaryDirectory() as root:
            folder = Path(root)
            op = Operator(folder, {}, folder, time.time() + 30)
            child = MagicMock()
            child.poll.return_value = None
            with (
                patch.object(op, "tunnel", return_value=(1, child)) as tunnels,
                patch.object(
                    op,
                    "rpc",
                    side_effect=[ConnectionRefusedError(), ConnectionRefusedError(), (b"ok", {})],
                ),
                patch("inference_platform.r1_cloud_operator.time.sleep"),
            ):
                channel = Forward(op, "host", "token", "generator", "measure")
                self.assertEqual(channel.request("/status")[0], b"ok")
                self.assertEqual(channel.reconnects, 0)
                tunnels.assert_called_once()

    def test_live_helper_http_disconnect_5xx_and_oserror_reopen_immediately(self):
        for failure in (
            http.client.RemoteDisconnected(),
            ChannelError("HTTP 503"),
            OSError("reset"),
        ):
            with tempfile.TemporaryDirectory() as root:
                folder = Path(root)
                op = Operator(folder, {}, folder, time.time() + 30)
                child = MagicMock()
                child.poll.return_value = None
                with (
                    patch.object(op, "tunnel", return_value=(1, child)) as tunnels,
                    patch.object(op, "rpc", side_effect=[failure, (b"ok", {})]),
                    patch("inference_platform.r1_cloud_operator.time.sleep"),
                    patch("inference_platform.r1_cloud_operator.stop_forward"),
                ):
                    channel = Forward(op, "host", "token", "generator", "measure")
                    self.assertEqual(channel.request("/status")[0], b"ok")
                    self.assertEqual(channel.reconnects, 1)
                    self.assertEqual(tunnels.call_count, 2)

    def test_fresh_ssm_confirmation_recovers_errors_and_monitors_running_host(self):
        with tempfile.TemporaryDirectory() as root:
            folder = Path(root)
            op = Operator(folder, {}, folder, time.time() + 30)
            op.context_path.write_bytes(encoded({"hosts": {"generator": {"id": "host"}}}))
            with (
                patch.object(
                    op,
                    "ssm",
                    side_effect=[
                        OSError("lost send-command"),
                        {"StandardOutputContent": '{"running":true}'},
                        {"StandardOutputContent": '{"running":false}'},
                    ],
                ) as calls,
                patch("inference_platform.r1_cloud_operator.time.sleep"),
            ):
                self.assertFalse(op.monitor_measure())
                self.assertEqual(calls.call_count, 3)

    def test_close_refused_when_fresh_status_reports_running_measure(self):
        with tempfile.TemporaryDirectory() as root:
            folder = Path(root)
            op = Operator(folder, {"bundle_sha256": "a"}, folder, time.time() + 30)
            op.context_path.write_bytes(
                encoded({"hosts": {"generator": {"id": "host"}}, "control_token": "t"})
            )
            state = encoded({"bundle_sha256": "a", "actions": {"measure": None}})
            with patch.object(Forward, "request", return_value=(state, {})) as calls:
                op.with_host("generator", "close")
                calls.assert_called_once_with("/status")

    def test_cloud_init_exit_2_needs_completion_marker(self):
        commands = cloud_init_commands()
        # Execute the actual generated shell conditions with only cloud-init/path
        # supplied by a fixture. This runs under hosted Linux; Windows uses Docker.
        with tempfile.TemporaryDirectory() as root:
            folder = Path(root)
            for code, marker, expected in ((0, True, 0), (2, True, 0), (2, False, 1), (1, True, 1)):
                script = "set -eu\ncloud-init() { echo '{}'; return " + str(code) + "; }\n"
                marker_path = folder / "user-data.done"
                marker_path.unlink(missing_ok=True)
                if marker:
                    marker_path.touch()
                script += "\n".join(commands).replace("/opt/r1", folder.as_posix())
                if __import__("os").name == "nt":
                    # Git Bash has the same set -eu and case semantics; no Docker startup cost.
                    shell = r"C:\Program Files\Git\bin\bash.exe"
                else:
                    shell = "bash"
                result = subprocess.run([shell, "-c", script], capture_output=True)
                self.assertEqual(result.returncode, expected, result.stderr)
                self.assertEqual(json.loads((folder / "cloud-init-status.json").read_bytes()), {})

    def test_transport_reconnects_but_host_exit_is_failure(self):
        with tempfile.TemporaryDirectory() as root:
            op = Operator(Path(root), {"bundle_sha256": "a"}, Path(root), time.time() + 60)
            children = [MagicMock(), MagicMock()]
            children[0].poll.return_value = 1
            children[1].poll.return_value = None
            with (
                patch.object(op, "tunnel", side_effect=[(1, children[0]), (2, children[1])]),
                patch.object(op, "rpc", return_value=(b"ok", {})),
                patch("inference_platform.r1_cloud_operator.stop_forward"),
                patch("inference_platform.r1_cloud_operator.time.sleep"),
            ):
                channel = Forward(op, "host", "token", "generator", "measure")
                self.assertEqual(channel.request("/status")[0], b"ok")
                self.assertEqual(channel.reconnects, 1)
                channel.close()
            binding = {"hosts": {"generator": {"id": "host"}}, "control_token": "token"}
            op.context_path.write_bytes(encoded(binding))
            state = encoded({"bundle_sha256": "a", "actions": {"measure": 7}})
            with (
                patch.object(Forward, "request", return_value=(state, {})),
                patch.object(Forward, "close"),
            ):
                with self.assertRaisesRegex(RuntimeError, "exit 7"):
                    op.with_host("generator", "measure")

    def test_resume_and_reject_archive_size_change(self):
        with tempfile.TemporaryDirectory() as root:
            folder = Path(root)
            op = Operator(folder, {}, folder, time.time() + 10)
            channel = MagicMock()
            channel.reconnects = 2
            destination = folder / "archive.gz"
            destination.write_bytes(b"abc")
            destination.with_suffix(".gz.transfer.json").write_bytes(encoded({"bytes": 6}))
            channel.request.return_value = (
                b"def",
                {"X-Archive-Size": "6", "X-Chunk-SHA256": hashlib.sha256(b"def").hexdigest()},
            )
            receipt = op.retrieve(channel, "/archive", destination)
            channel.request.assert_called_once_with("/archive/3")
            self.assertEqual(destination.read_bytes(), b"abcdef")
            self.assertTrue(receipt["complete"])
            destination.write_bytes(b"abc")
            channel.request.return_value = (b"defg", {"X-Archive-Size": "7"})
            with self.assertRaisesRegex(ValueError, "archive changed"):
                op.retrieve(channel, "/archive", destination)

    def test_incremental_prefixes_final_tails_and_replay(self):
        with tempfile.TemporaryDirectory() as root:
            folder = Path(root)
            source, output = folder / "source", folder / "output"
            (source / "session").mkdir(parents=True)
            stream = source / "session/offers.jsonl"
            stream.write_bytes(b'{"id":1}\n{"id":')
            phase = source / "session/run1-measure.json"
            phase.write_bytes(b'{"sealed":true}')
            (source / "session/service-export.json").write_bytes(b"duplicate gateway bytes")
            spool = Spool(source)
            spool.capture()
            self.assertEqual(spool.offsets["session/offers.jsonl"], 9)
            stream.write_bytes(b'{"id":1}\n{"id":2}\n')
            spool.capture(final=True)
            for item in spool.inventory:
                restore(spool.segments / item["name"], output)
                restore(spool.segments / item["name"], output)
            self.assertEqual((output / "session/offers.jsonl").read_bytes(), stream.read_bytes())
            self.assertEqual(
                (output / "session/run1-measure.json").read_bytes(), phase.read_bytes()
            )
            self.assertFalse((output / "session/service-export.json").exists())

    def test_lifecycle_monitor_error_never_closes_running_session(self):
        class Running(Virtual):
            def measure(self, deadline, record):
                raise http.client.RemoteDisconnected("operator channel lost")

            def recover_measure(self, deadline, record):
                self.elapsed = deadline
                record("measure_state_confirmed", running=True, close_sent=False)
                return False

            def close_admissions(self, deadline):
                raise AssertionError("close sent while Session runs")

        with tempfile.TemporaryDirectory() as root:
            plan, inputs = fixture_inputs("success")
            result = execute(
                Running("success"),
                plan,
                inputs,
                ConsumeGate(Path(root) / "gate"),
                lambda _: None,
                Path(root) / "receipt.json",
            )
            self.assertFalse(
                any(x["event"].endswith("admissions_closed") for x in result["events"])
            )
            self.assertTrue(result["export_complete"])


if __name__ == "__main__":
    unittest.main()
