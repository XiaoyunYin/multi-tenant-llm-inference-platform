"""Real Linux server kill: its independent host child survives and sealed disk data remains."""

import hashlib
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path
from unittest.mock import patch

from inference_platform.disk_records import write_json
from inference_platform.host_diagnostics import diagnostic_bundle, identity_alive, process_identity
from inference_platform.session_stop import stop_child
from inference_platform.stage_c_control import host_status, load_identity, restart_server, sidecar
from inference_platform.stage_c_session import free_port


@unittest.skipUnless(
    sys.platform.startswith("linux"),
    "Linux proc identity / real server recovery; run explicitly in local Docker",
)
class ServerRecoveryTest(unittest.TestCase):
    def test_killed_server_preserves_host_controller_and_restart_reattaches(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / "reviewed"
            destination.mkdir()
            (destination / "session/sealed-runs").mkdir(parents=True)
            write_json(
                destination / "session/sealed-runs/run-1.receipt.json",
                {
                    "run_number": 1,
                    "sha256": hashlib.sha256(b"completed run").hexdigest(),
                    "bytes": 13,
                },
            )
            (destination / "session/sealed-runs/run-1.tar.gz").write_bytes(b"completed run")
            epoch = root / "epoch"
            epoch.write_text(str(int(time.time() + 60)))
            module = Path(__file__).parents[1] / "src/inference_platform/stage_c_session.py"
            bootstrap = sidecar(destination, "-entrypoint.py")
            bootstrap.write_bytes(module.read_bytes())
            write_json(
                destination / "staging-manifest.json",
                {"entrypoint": {"sha256": hashlib.sha256(bootstrap.read_bytes()).hexdigest()}},
            )
            child = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(60)"], start_new_session=True
            )
            write_json(destination / "controller-pid.json", process_identity(child.pid))
            port = free_port()
            nonce = "local-recovery-fixture"
            server = subprocess.Popen(
                [
                    sys.executable,
                    str(bootstrap),
                    "--serve-transport",
                    str(destination),
                    "--manifest-sha256",
                    "0" * 64,
                    "--nonce",
                    nonce,
                    "--port",
                    str(port),
                    "--epoch-file",
                    str(epoch),
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )

            def status():
                request = urllib.request.Request(
                    f"http://127.0.0.1:{port}/status", headers={"Authorization": nonce}
                )
                with urllib.request.urlopen(request, timeout=1) as response:
                    return json.load(response)

            def wait_status():
                limit = time.perf_counter() + 5
                while time.perf_counter() < limit:
                    try:
                        return status()
                    except OSError:
                        time.sleep(0.05)
                self.fail("real recovery server unavailable")

            try:
                self.assertTrue(wait_status()["host_controller_alive"])
                os.kill(server.pid, signal.SIGKILL)
                server.wait(timeout=3)
                diag = diagnostic_bundle(process_identity(child.pid), port)
                self.assertTrue(diag["host_controller"]["alive"])
                self.assertFalse(diag["control_port_listening"])
                self.assertEqual(
                    len(host_status(destination, int(epoch.read_text()))["completed_runs"]), 1
                )
                owned = []
                spawn = subprocess.Popen

                def retain(*args, **kwargs):
                    process = spawn(*args, **kwargs)
                    owned.append(process)
                    return process

                with patch(
                    "inference_platform.stage_c_control.subprocess.Popen", side_effect=retain
                ):
                    result = restart_server(destination, port)
                self.assertFalse(result["host_controller_restarted"])
                self.assertTrue(wait_status()["host_controller_alive"])
                self.assertEqual(
                    load_identity(destination / "controller-pid.json")["pid"], child.pid
                )
                request = urllib.request.Request(
                    f"http://127.0.0.1:{port}/run/1", headers={"Authorization": nonce}
                )
                with self.assertRaises(urllib.error.HTTPError) as blocked:
                    urllib.request.urlopen(request, timeout=1)
                self.assertEqual(blocked.exception.code, 409)
                blocked.exception.close()
                # The worker survives server replacement. Archives become available
                # only when that worker exits, never while measurement is active.
                stop_child(child)
                self.assertTrue(wait_status()["finished"])
                with urllib.request.urlopen(request, timeout=1) as response:
                    self.assertEqual(response.read(), b"completed run")
                ranged = urllib.request.Request(
                    f"http://127.0.0.1:{port}/run/1",
                    headers={"Authorization": nonce, "Range": "bytes=2-5"},
                )
                with urllib.request.urlopen(ranged, timeout=1) as response:
                    self.assertEqual(response.status, 206)
                    self.assertEqual(response.read(), b"mple")
                receipt = os.environ.get("INF011_FAULT_REHEARSAL_DIR")
                if receipt:
                    write_json(
                        Path(receipt) / "real-linux-server-kill.json",
                        {
                            "schema": "inf011-real-server-kill.v1",
                            "status": "passed",
                            "diagnostics": diag,
                            "host_controller_survived_server_sigkill": True,
                            "same_host_controller_identity_after_restart": True,
                            "completed_archive_fetch": "checksum-matched",
                            "aws_calls_made": False,
                            "basis": "Actual local Linux server SIGKILL and replacement; independent real host worker; no GPU; mocked remote-controller tests are separate",
                        },
                    )
            finally:
                identity = load_identity(sidecar(destination, ".server-pid.json"))
                if identity_alive(identity):
                    os.kill(identity["pid"], signal.SIGTERM)
                for process in locals().get("owned", []):
                    stop_child(process)
                stop_child(server)
                stop_child(child)
                if server.stderr:
                    server.stderr.close()


if __name__ == "__main__":
    unittest.main()
