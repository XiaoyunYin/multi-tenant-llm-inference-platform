import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from inference_platform.session_stop import pid_is_running, stop_forward
from inference_platform.stage_c_readiness import readiness_window, wait_startup
from inference_platform.stage_c_session import ENTRYPOINT, remote_session, sha
from inference_platform.stage_c_transport import (
    ReconnectingTransport,
    command_batches,
    wait_ssm_online,
)


class Forward:
    def __init__(self, drop=False):
        self.returncode = None
        self.polls = 0
        self.drop = drop

    def poll(self):
        self.polls += 1
        if self.drop and self.polls >= 4:
            self.returncode = 1
        return self.returncode


class RemoteTransportTest(unittest.TestCase):
    def test_forward_stop_reaps_parent_and_stops_plugin_descendant(self):
        with tempfile.TemporaryDirectory() as directory:
            pid_file = Path(directory) / "plugin.pid"
            script = (
                "import subprocess,sys,time; from pathlib import Path; "
                "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); "
                f"Path({str(pid_file)!r}).write_text(str(child.pid)); time.sleep(30)"
            )
            parent = subprocess.Popen(
                [sys.executable, "-c", script], start_new_session=os.name != "nt"
            )
            try:
                deadline = time.perf_counter() + 5
                while not pid_file.exists() and time.perf_counter() < deadline:
                    time.sleep(0.01)
                plugin_pid = int(pid_file.read_text())
                self.assertTrue(pid_is_running(plugin_pid))
                receipt = stop_forward(parent)
                self.assertTrue(receipt["reaped"])
                while pid_is_running(plugin_pid) and time.perf_counter() < deadline:
                    time.sleep(0.01)
                self.assertFalse(pid_is_running(plugin_pid))
            finally:
                stop_forward(parent)

    def exercise(self, failure):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = root / "payload"
            source = payload / "sources" / ENTRYPOINT
            source.parent.mkdir(parents=True)
            source.write_text("# test committed entrypoint\n", encoding="utf-8")
            (payload / "gateway").write_bytes(b"gateway")
            manifest = {
                "files": [{"path": ENTRYPOINT}],
                "gateway_artifact": {"goos": "linux", "path": "gateway"},
                "entrypoint": {"sha256": sha(source)},
            }
            manifest_path = payload / "staging-manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
                for name in ("staging-manifest.json", "gateway", "sources/" + ENTRYPOINT):
                    archive.add(payload / name, arcname=name, recursive=False)
            pinned_bundle = buffer.getvalue()
            args = SimpleNamespace(
                repo=root,
                payload=payload,
                session=root / "session",
                plan_sha256="0" * 64,
                manifest_sha256=sha(manifest_path),
                remote_instance="i-test",
            )
            inputs = {
                "staging": {"manifest_sha256": args.manifest_sha256},
                "region": "us-east-1",
                "aws_profile": "admin-learning",
                "availability_zone": "us-east-1b",
                "maximum_duration_hours": 4,
                "minimum_useful_run_seconds": [1200, 1200, 300, 2400],
                "evidence_export_margin_seconds": 600,
            }
            # Keep simulated elapsed-time arithmetic independent of host uptime.
            # This base and the simulated waits are exactly representable.
            tick, wall = [1_000_000.0], time.time()
            started, finished, bad_export = [False], [False], [False]
            statuses, commands, forwards, order = [], [], [], []
            startup_attempts = [0]
            data = b"exported evidence"
            termination = int(wall + 14400)

            def aws(argv, **kwargs):
                service, operation = argv[1:3]
                if (service, operation) == ("ec2", "describe-instances"):
                    result = {
                        "Reservations": [
                            {
                                "Instances": [
                                    {
                                        "InstanceType": "g6.xlarge",
                                        "State": {"Name": "running"},
                                        "Placement": {"AvailabilityZone": "us-east-1b"},
                                        "Tags": [{"Key": "Task", "Value": "INF-011"}],
                                        "LaunchTime": datetime.fromtimestamp(wall, UTC).isoformat(),
                                    }
                                ]
                            }
                        ]
                    }
                elif operation == "describe-instance-information":
                    result = {
                        "InstanceInformationList": [
                            {
                                "InstanceId": "i-test",
                                "PingStatus": "Offline" if failure == "ssm_expired" else "Online",
                            }
                        ]
                    }
                elif operation == "send-command":
                    parameters = Path(
                        argv[argv.index("--parameters") + 1].removeprefix("file://")
                    ).read_bytes()
                    self.assertLessEqual(len(parameters), 24000)
                    commands.append(parameters)
                    result = {"Command": {"CommandId": "c-test"}}
                elif operation == "get-command-invocation":
                    result = {"Status": "Success", "StandardOutputContent": str(termination)}
                else:
                    self.fail(f"unexpected real AWS command: {argv}")
                return json.dumps(result)

            def run(argv, **kwargs):
                if argv[0] == "session-manager-plugin":
                    return subprocess.CompletedProcess(argv, 0, "1.test", "")
                action = argv[argv.index("-Action") + 1]
                order.append((action, tick[0]))
                self.assertIn(action, ("Destroy", "VerifyTeardown"))
                return subprocess.CompletedProcess(argv, 0)

            def start(*_, **kwargs):
                port = json.loads(_[0][_[0].index("--parameters") + 1])["localPortNumber"][0]
                self.assertTrue(port)
                child = Forward(drop=failure == "forward_drop" and not forwards)
                forwards.append(child)
                return child

            def request(path, timeout, body=None):
                self.assertGreater(timeout, 0)
                if failure == "startup_delay" and not started[0]:
                    startup_attempts[0] += 1
                    if startup_attempts[0] <= 2:
                        raise OSError("new forward listener is still starting")
                if path == "/payload":
                    self.assertEqual(body, pinned_bundle)
                    started[0] = True
                    if failure == "lost_put":
                        raise OSError("lost successful PUT response")
                    return b"{}"
                if started[0] and failure in ("outage", "recover_finished") and not finished[0]:
                    if tick[0] - first_tick >= 300 and failure == "recover_finished":
                        finished[0] = True
                    else:
                        raise OSError("sustained SSM outage")
                if path == "/status":
                    if started[0]:
                        statuses.append(1)
                        if failure == "status_drop" and len(statuses) == 1:
                            raise OSError("connection reset once")
                        finished[0] = len(statuses) > 1 or finished[0]
                    return json.dumps(
                        {
                            "started": started[0],
                            "finished": finished[0],
                            "instance_termination_unix_s": termination,
                        }
                    ).encode()
                if path == "/receipt":
                    order.append(("receipt", tick[0]))
                    return json.dumps({"sha256": hashlib.sha256(data).hexdigest()}).encode()
                if path == "/export":
                    if failure == "export_drop" and not bad_export[0]:
                        bad_export[0] = True
                        raise OSError("first export fetch failed")
                    order.append(("export", tick[0]))
                    return data
                self.fail(path)

            first_tick = tick[0]
            timing = dict(
                clock=lambda: tick[0],
                wall_clock=lambda: wall + (tick[0] - first_tick),
                sleep=lambda seconds: tick.__setitem__(0, tick[0] + seconds),
            )

            def factory(*args, **kwargs):
                kwargs.pop("stop", None)
                return ReconnectingTransport(
                    *args,
                    **kwargs,
                    **timing,
                    request=request,
                    stop=lambda _: {"reaped": True},
                )

            def ssm_wait(*args, **kwargs):
                return wait_ssm_online(
                    *args,
                    **kwargs,
                    **timing,
                )

            with (
                # Every mocked readiness/bootstrap deadline must share the same
                # simulated clock; real process polling in the other test does not.
                patch("inference_platform.stage_c_session.time.perf_counter", timing["clock"]),
                patch("inference_platform.stage_c_session.time.time", timing["wall_clock"]),
                patch(
                    "inference_platform.stage_c_readiness.readiness_window",
                    side_effect=partial(
                        readiness_window, clock=timing["clock"], wall_clock=timing["wall_clock"]
                    ),
                ),
                patch(
                    "inference_platform.stage_c_readiness.wait_startup",
                    side_effect=partial(wait_startup, **timing),
                ),
                patch("inference_platform.stage_c_session.require_approval", return_value=inputs),
                # Integrity is exercised separately by the real preflight/Git
                # tests; this fixture supplies already verified pinned bytes.
                patch(
                    "inference_platform.stage_c_session.verify_pinned_payload",
                    return_value=pinned_bundle,
                ),
                patch(
                    "inference_platform.stage_c_session.shutil.which", return_value="mock-plugin"
                ),
                patch(
                    "inference_platform.stage_c_session.subprocess.check_output", side_effect=aws
                ),
                patch("inference_platform.stage_c_session.subprocess.run", side_effect=run),
                patch("inference_platform.stage_c_session.subprocess.Popen", side_effect=start),
                patch("inference_platform.stage_c_transport.wait_ssm_online", side_effect=ssm_wait),
                patch(
                    "inference_platform.stage_c_transport.ReconnectingTransport",
                    side_effect=factory,
                ),
            ):
                code = remote_session(args)
            outcome = json.loads(
                (args.session / "controller-outcome.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                [x[0] for x in order if x[0] in ("Destroy", "VerifyTeardown")],
                ["Destroy", "VerifyTeardown"],
            )
            self.assertFalse(outcome["apply_called"])
            if failure == "ssm_expired":
                self.assertFalse(commands)
                self.assertEqual(code, 1)
                self.assertEqual(outcome["reason"], "skipped_readiness_deadline")
                self.assertAlmostEqual(tick[0] - first_tick, 8700, places=5)
                self.assertEqual(len(outcome["timed_runs"]), 4)
                self.assertEqual(forwards, [])
                return
            self.assertTrue(commands)
            self.assertFalse((args.session / "ssm-stage-request.json").exists())
            if failure == "outage":
                self.assertEqual(code, 1)
                self.assertEqual(outcome["reason"], "sustained_transport_outage")
                self.assertGreaterEqual(order[-2][1] - first_tick, 300)
                self.assertLessEqual(order[-2][1] - first_tick, 360)
                self.assertTrue(outcome["export_recovery_attempted"])
            else:
                self.assertEqual(code, 0, outcome)
                self.assertTrue(outcome["export_verified"])
                self.assertLess(
                    [x[0] for x in order].index("export"), [x[0] for x in order].index("Destroy")
                )
                self.assertEqual((args.session / "evidence.tar.gz").read_bytes(), data)
            if failure != "none":
                self.assertTrue(outcome["transport_interruptions"])
                if failure == "startup_delay":
                    self.assertEqual(len(forwards), 1)
                else:
                    self.assertGreater(len(forwards), 1)

    def test_mocked_aws_status_drop_forward_exit_and_export_retry_keep_session(self):
        for failure in ("status_drop", "forward_drop", "export_drop", "lost_put"):
            with self.subTest(failure=failure):
                self.exercise(failure)

    def test_mocked_aws_new_forward_has_time_to_bind_before_replacement(self):
        self.exercise("startup_delay")

    def test_mocked_aws_sustained_outage_waits_before_single_teardown(self):
        self.exercise("outage")

    def test_mocked_aws_loss_recovers_finished_export_before_teardown(self):
        self.exercise("recover_finished")

    def test_ssm_deadline_expiry_never_sends_or_tears_down_before_wait_bound(self):
        self.exercise("ssm_expired")

    def test_control_deadline_truncates_outage_window(self):
        tick, interruptions = [0.0], []
        transport = ReconnectingTransport(
            lambda: Forward(),
            "local",
            "nonce",
            10,
            interruptions,
            clock=lambda: tick[0],
            wall_clock=lambda: tick[0],
            sleep=lambda seconds: tick.__setitem__(0, tick[0] + seconds),
            request=lambda *_: (_ for _ in ()).throw(OSError("offline")),
            stop=lambda _: {},
        )
        with self.assertRaisesRegex(RuntimeError, "control_deadline"):
            transport.get("/status")
        self.assertEqual(tick[0], 10)
        self.assertTrue(interruptions)

    def test_bootstrap_is_split_by_serialized_size_preserving_command_order(self):
        commands = ["printf %s " + "a" * 3000 for _ in range(40)]
        batches = command_batches(commands)
        self.assertGreater(len(batches), 1)
        self.assertEqual([c for b in batches for c in b], commands)
        self.assertTrue(
            all(
                len(json.dumps({"commands": ["set -eu\n" + "\n".join(b)]}).encode()) <= 24000
                for b in batches
            )
        )
