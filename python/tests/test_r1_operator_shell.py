"""Execute the production SSM command lists with sh and isolated host paths."""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from inference_platform.r1_cloud_operator import Operator
from inference_platform.r1_spec import encoded

ROOT = Path(__file__).resolve().parents[2]


def user_data_timer(deadline):
    source = (ROOT / "infra/terraform/r1/user-data.sh").read_text(encoding="utf-8")
    marker = "cat > /etc/systemd/system/r1-terminate.timer <<UNIT\n"
    timer = source.split(marker, 1)[1].split("\nUNIT\n", 1)[0] + "\n"
    return timer.replace("OnCalendar=@$deadline", f"OnCalendar=@{deadline}").encode()


@unittest.skipUnless(sys.platform.startswith("linux"), "production shell execution requires Linux")
class OperatorShellTests(unittest.TestCase):
    def shell(self, folder, commands, code=0, *, process=True, listening=True):
        stubs = folder / "bin"
        stubs.mkdir(exist_ok=True)
        for name, body in {
            "cloud-init": f"echo '{{}}'; exit {code}\n",
            "systemctl": 'printf "%s\\n" "$*" >> "$CALLS"\n',
            "nohup": 'printf "%s\\n" "$*" >> "$CALLS"\n',
            "pgrep": "echo 123\n" if process else "exit 1\n",
            "ss": "echo 'LISTEN 0 128 127.0.0.1:22280 0.0.0.0:*'\n" if listening else "exit 0\n",
        }.items():
            path = stubs / name
            path.write_text("#!/bin/sh\n" + body)
            path.chmod(0o755)
        # AWS returns after launching nohup. Reap the test's short-lived launch
        # stub before inspecting its receipt or deleting the temporary host root.
        script = "\n".join(commands) + "\nwait\n"
        for path in ("/etc/r1", "/etc/systemd/system", "/opt/r1"):
            script = script.replace(path, (folder / path.lstrip("/")).as_posix())
        return subprocess.run(
            ["sh", "-c", script],
            capture_output=True,
            timeout=10,
            env={
                **os.environ,
                "PATH": str(stubs) + os.pathsep + os.environ["PATH"],
                "CALLS": str(folder / "calls"),
            },
        )

    def capture_ready(self, folder):
        secret = folder / "secret"
        secret.write_bytes(b"test secret")
        inputs = {
            "terraform": sys.executable,
            "cache_secret_path": str(secret),
            "cache_secret_sha256": hashlib.sha256(secret.read_bytes()).hexdigest(),
            "session_id": "shell-test",
            "source_head": "test",
            "bundle_sha256": "a" * 64,
            "cpu_memory_bytes": 17179869184,
            "cpu_memory_source": "fixture",
        }
        op = Operator(ROOT, inputs, folder, time.time() + 60)
        hosts = {r: {"id": r} for r in ("gpu-0", "gpu-1", "service", "generator")}
        captured = {}
        with (
            patch(
                "inference_platform.r1_cloud_operator.subprocess.check_output",
                return_value=encoded(hosts),
            ),
            patch.object(
                op, "aws", return_value={"InstanceInformationList": [{"PingStatus": "Online"}]}
            ),
            patch.object(
                op, "ssm", side_effect=lambda host, commands: captured.update({host: commands})
            ),
            patch.object(op, "with_host"),
        ):
            op.ready()
        self.assertEqual(set(captured), set(hosts))
        self.assertTrue(all(commands == captured["generator"] for commands in captured.values()))
        context = json.loads(op.context_path.read_bytes())
        for name in ("control_token", "agent_token", "credential"):
            self.assertRegex(context[name], r"^[0-9a-f]{64}$")
        return captured["generator"], int(op.deadline + 13680)

    def test_ready_tightens_preserves_bootstrap_and_does_not_extend_deadline(self):
        for offset in (45, -45):
            with self.subTest(offset=offset), tempfile.TemporaryDirectory() as root:
                folder = Path(root)
                commands, deadline = self.capture_ready(folder)
                for path in ("etc/r1", "etc/systemd/system", "opt/r1"):
                    (folder / path).mkdir(parents=True)
                (folder / "opt/r1/user-data.done").touch()
                epoch = folder / "etc/r1/deadline_epoch"
                epoch.write_text(str(deadline + offset) + "\n")
                timer = folder / "etc/systemd/system/r1-terminate.timer"
                original = f"[Timer]\nOnCalendar=@{deadline + offset}\nPersistent=true\nAccuracySec=1s\nUnit=r1-terminate.service\n[Install]\nWantedBy=timers.target\n"
                timer.write_text(original)
                result = self.shell(folder, commands)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(
                    (folder / "opt/r1/bootstrap.py").read_bytes(),
                    (ROOT / "scripts/r1-host-bootstrap.py").read_bytes(),
                )
                calls = (folder / "calls").read_text()
                self.assertIn("bootstrap.py", calls)
                self.assertIn("--token=", calls)
                self.assertNotIn("systemd-run", "\n".join(commands))
                if offset > 0:
                    self.assertEqual(int(epoch.read_text()), deadline)
                    self.assertEqual(timer.read_bytes(), user_data_timer(deadline))
                    self.assertIn("daemon-reload\nrestart r1-terminate.timer\n", calls)
                else:
                    self.assertEqual(epoch.read_text(), str(deadline + offset) + "\n")
                    self.assertEqual(timer.read_bytes(), user_data_timer(deadline + offset))
                    self.assertNotIn("daemon-reload", calls)

    def test_ready_cloud_init_exit_one_fails_before_timer_or_bootstrap(self):
        with tempfile.TemporaryDirectory() as root:
            folder = Path(root)
            commands, _ = self.capture_ready(folder)
            (folder / "opt/r1").mkdir(parents=True)
            (folder / "opt/r1/user-data.done").touch()
            result = self.shell(folder, commands, code=1)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((folder / "opt/r1/bootstrap.py").exists())
            self.assertFalse((folder / "calls").exists())

    def test_launch_wait_requires_both_process_and_socket_and_expires(self):
        for process, listening in ((False, True), (True, False)):
            with self.subTest(process=process), tempfile.TemporaryDirectory() as root:
                folder = Path(root)
                commands, _ = self.capture_ready(folder)
                for path in ("etc/r1", "etc/systemd/system", "opt/r1"):
                    (folder / path).mkdir(parents=True)
                (folder / "opt/r1/user-data.done").touch()
                (folder / "etc/r1/deadline_epoch").write_text("0\n")
                # Keep the production loop, shorten only its test deadline.
                commands = [command.replace("+ 30", "+ 1") for command in commands]
                result = self.shell(folder, commands, process=process, listening=listening)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b"bootstrap not running/listening", result.stdout)

    def test_monitor_heredoc_absent_running_and_terminal(self):
        with tempfile.TemporaryDirectory() as root:
            folder = Path(root)
            op = Operator(ROOT, {}, folder, time.time() + 60)
            op.context_path.write_bytes(encoded({"hosts": {"generator": {"id": "host"}}}))
            control = folder / "opt/r1/control"
            control.mkdir(parents=True)
            observed = []

            def run_shell(host, commands):
                result = self.shell(folder, commands)
                self.assertEqual(result.returncode, 0, result.stderr)
                observed.append(json.loads(result.stdout)["running"])
                if observed[-1]:
                    (control / "measure-terminal.json").touch()
                return {"StandardOutputContent": result.stdout.decode()}

            with (
                patch.object(op, "ssm", side_effect=run_shell),
                patch("inference_platform.r1_cloud_operator.time.sleep"),
            ):
                self.assertFalse(op.monitor_measure())
                (control / "measure-started.json").touch()
                self.assertFalse(op.monitor_measure())
            self.assertEqual(observed, [False, True, False])
