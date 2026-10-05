import base64
import hashlib
import io
import json
import os
import re
import shutil
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
    def test_trickling_archive_cannot_extend_absolute_attempt_deadline(self):
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):  # noqa: N802
                self.send_response(200)
                self.send_header("Content-Length", "1000000")
                self.end_headers()
                try:
                    while True:
                        self.wfile.write(b"x")
                        self.wfile.flush()
                        time.sleep(0.02)
                except OSError:
                    pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        started = time.perf_counter()
        transport = ReconnectingTransport(
            lambda: None, f"http://127.0.0.1:{server.server_port}", "unit", started + 0.15, []
        )
        try:
            with self.assertRaises(OSError):
                transport.http_request("/export", 30)
            self.assertLess(time.perf_counter() - started, 1)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=1)

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
            fixture_buffer = io.BytesIO()
            fixture_content = (
                b'{"status":"completed","basis":"mocked SSM fixture; no measured GPU data"}\n'
            )
            with tarfile.open(fileobj=fixture_buffer, mode="w:gz") as fixture_archive:
                info = tarfile.TarInfo("completed-run.json")
                info.size = len(fixture_content)
                fixture_archive.addfile(info, io.BytesIO(fixture_content))
            data = fixture_buffer.getvalue()
            termination = int(wall + 14400)
            restart_count = [0]
            faults = ("control_server_killed", "forward_650", "both_channels", "host_died")
            run_receipt = {
                "run_number": 1,
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
            run_receipt["measurement_digest"] = {
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
            diagnostic = {
                "schema": "inf011-host-diagnostics.v1",
                "host": {
                    "uptime_seconds": 10,
                    "load_average": [1, 1, 1],
                    "memory_available_bytes": 4000000000,
                    "oom_kill": 0,
                    "pressure": {
                        "cpu": "some avg10=0",
                        "memory": "some avg10=0",
                        "io": "some avg10=0",
                    },
                },
                "free_m": {"status": "captured", "text": "Mem: 16384 8192 8192"},
                "dmesg_oom_kill_tail": {"status": "captured", "text": []},
                "top_processes_by_rss": [{"role": "python", "rss_bytes": 200000000}],
                "control_port_listening": False,
                "host_controller": {"alive": True, "state": "R"},
            }

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
                    if (
                        failure == "both_channels"
                        and tick[0] - first_tick >= 10
                        and b"--action" in parameters
                    ):
                        raise OSError("mock command channel disconnected")
                    result = {"Command": {"CommandId": "c-test"}}
                elif operation == "get-command-invocation":
                    action = re.search(rb"--action ([a-z]+)", commands[-1])
                    value = termination
                    if action:
                        name = action[1].decode()
                        elapsed = tick[0] - first_tick
                        if name == "snapshot":
                            done = failure == "host_died" or elapsed >= 650
                            host_alive = not done
                            value = {
                                "status": {
                                    "started": True,
                                    "finished": done,
                                    "host_controller_alive": host_alive,
                                    "instance_termination_unix_s": termination,
                                    "completed_runs": [run_receipt],
                                },
                                "diagnostics": {
                                    **diagnostic,
                                    "host_controller": {
                                        "alive": host_alive,
                                        "state": "R" if host_alive else None,
                                    },
                                },
                            }
                        elif name == "restart":
                            restart_count[0] += 1
                            value = {
                                "status": "control_server_restart_requested",
                                "host_controller_restarted": False,
                            }
                        elif name == "recover":
                            order.append(("command_recover", tick[0]))
                            value = {"status": "exported"}
                        elif name == "receipt":
                            value = {**run_receipt}
                        elif name == "read":
                            offset = int(re.search(rb"--offset ([0-9]+)", commands[-1])[1])
                            order.append(("export", tick[0]))
                            chunk = data[offset : offset + 12288]
                            value = {
                                "offset": offset,
                                "bytes": len(chunk),
                                "base64": base64.b64encode(chunk).decode(),
                            }
                    result = {"Status": "Success", "StandardOutputContent": json.dumps(value)}
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

            def request(path, timeout, body=None, *, headers=None):
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
                elapsed = tick[0] - first_tick
                if started[0] and failure in faults and elapsed >= 5:
                    if failure != "control_server_killed" or restart_count[0] == 0:
                        if failure != "forward_650" or elapsed < 650:
                            raise OSError("mock killed server or blocked forward")
                if path in ("/run/1", "/digest/1"):
                    if headers:
                        self.assertTrue(finished[0] or elapsed >= 650 or failure == "host_died")
                        start, end = map(int, headers["Range"].removeprefix("bytes=").split("-"))
                        return data[start : end + 1]
                    return data
                if path == "/status":
                    if started[0]:
                        statuses.append(1)
                        if failure == "status_drop" and len(statuses) == 1:
                            raise OSError("connection reset once")
                        finished[0] = (
                            (len(statuses) > 1 or finished[0])
                            if failure not in faults
                            else elapsed >= 650
                            or (failure == "control_server_killed" and restart_count[0] > 0)
                        )
                    return json.dumps(
                        {
                            "started": started[0],
                            "finished": finished[0],
                            "instance_termination_unix_s": termination,
                            "host_controller_alive": started[0] and not finished[0],
                            "completed_runs": [run_receipt]
                            if started[0] and failure in faults
                            else [],
                            "host": diagnostic["host"],
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
            if failure in faults:
                self.assertTrue((args.session / "sealed-runs/run-1.digest.json.gz").exists())
                diagnostics = [
                    json.loads(line)
                    for line in (args.session / "host-diagnostics.jsonl").read_text().splitlines()
                ]
                self.assertTrue(
                    any(row.get("schema") == "inf011-host-diagnostics.v1" for row in diagnostics)
                )
                self.assertLess(order[-1][1] - first_tick, 14400)
                if failure == "both_channels":
                    self.assertEqual(code, 1)
                    self.assertTrue(
                        any(row["status"] == "UNAVAILABLE_COMMAND_CHANNEL" for row in diagnostics)
                    )
                    self.assertGreaterEqual(order[-2][1] - first_tick, 13799)
                else:
                    self.assertEqual(code, 0, outcome)
                    self.assertTrue(outcome["export_verified"])
                    if failure == "forward_650":
                        self.assertGreaterEqual(order[-2][1] - first_tick, 650)
                    if failure == "control_server_killed":
                        self.assertGreater(restart_count[0], 0)
                    if failure == "host_died":
                        self.assertIn("command_recover", [row[0] for row in order])
                evidence_root = os.environ.get("INF011_FAULT_REHEARSAL_DIR")
                if evidence_root:
                    destination = Path(evidence_root) / failure
                    destination.mkdir(parents=True, exist_ok=True)
                    for name in (
                        "controller-outcome.json",
                        "host-diagnostics.jsonl",
                        "operator-host-snapshots.jsonl",
                        "export-receipt.json",
                        "evidence.tar.gz",
                    ):
                        path = args.session / name
                        if path.exists():
                            shutil.copyfile(path, destination / name)
                    shutil.copytree(
                        args.session / "sealed-runs",
                        destination / "sealed-runs",
                        dirs_exist_ok=True,
                    )
                    (destination / "basis.json").write_text(
                        json.dumps(
                            {
                                "basis": "Real committed remote controller with mocked AWS/SSM/forward and simulated clock; server loss is injected; separate Linux test kills actual process",
                                "simulated_elapsed_to_destroy_seconds": order[-2][1] - first_tick,
                                "simulated_termination_seconds": 14400,
                                "aws_calls_made": False,
                                "gpu_measurements": False,
                            }
                        )
                        + "\n",
                        encoding="utf-8",
                        newline="\n",
                    )
                return
            if failure == "ssm_expired":
                self.assertFalse(commands)
                self.assertEqual(code, 1)
                self.assertEqual(outcome["reason"], "skipped_readiness_deadline")
                self.assertAlmostEqual(tick[0] - first_tick, 8100, places=5)
                self.assertEqual(len(outcome["timed_runs"]), 4)
                self.assertEqual(forwards, [])
                return
            self.assertTrue(commands)
            self.assertFalse((args.session / "ssm-stage-request.json").exists())
            if failure == "outage":
                self.assertEqual(code, 1)
                self.assertEqual(outcome["reason"], "control_deadline")
                self.assertGreaterEqual(order[-2][1] - first_tick, 13799)
                self.assertLessEqual(order[-2][1] - first_tick, 13800)
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
                elif failure != "export_drop":
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

    def test_real_controller_command_channel_faults(self):
        for fault in ("control_server_killed", "forward_650", "both_channels", "host_died"):
            with self.subTest(fault=fault):
                self.exercise(fault)

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
