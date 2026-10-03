import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from inference_platform.fake_backend import FakeBackend, FakeBackendConfig
from inference_platform.session_stop import stop_child
from inference_platform.stage_c_readiness import (
    check_processes,
    inspect_container,
    wait_readiness,
    wait_startup,
)
from inference_platform.stage_c_transport import wait_ssm_online


class ReadinessWaitTest(unittest.TestCase):
    def timing(self):
        tick = [100.0]
        return tick, dict(
            clock=lambda: tick[0],
            wall_clock=lambda: tick[0],
            sleep=lambda seconds: tick.__setitem__(0, tick[0] + seconds),
        )

    def test_container_missing_then_created_then_running_is_bounded_and_recorded(self):
        tick, timing = self.timing()
        results = [subprocess.CompletedProcess([], 1, "", "No such container") for _ in range(2)]
        results += [
            subprocess.CompletedProcess([], 0, '{"Running":false,"Pid":0}', ""),
            subprocess.CompletedProcess([], 0, '{"Running":true,"Pid":321}', ""),
        ]
        with patch(
            "inference_platform.stage_c_readiness.subprocess.run", side_effect=results
        ) as run:
            receipt = wait_startup(
                {"instance_termination_unix_s": 200}, (10,) * 4, 10, inspect_container, **timing
            )
        self.assertEqual(receipt["status"], "ready")
        self.assertEqual(len(receipt["attempts"]), 4)
        self.assertIn("No such container", receipt["attempts"][0]["stderr"])
        self.assertEqual(receipt["attempts"][-1]["state"]["Pid"], 321)
        self.assertTrue(all(call.kwargs["timeout"] <= 10 for call in run.call_args_list))
        self.assertLess(tick[0], receipt["readiness_deadline_unix_s"])

    def test_ssm_offline_then_online_and_both_startup_deadline_expiries(self):
        for kind in ("online", "ssm_expired", "container_expired"):
            tick, timing = self.timing()
            calls = []

            def aws(*argv, calls=calls, kind=kind, **kwargs):
                calls.append(argv)
                return {
                    "InstanceInformationList": [
                        {
                            "InstanceId": "i-test",
                            "PingStatus": "Online"
                            if kind == "online" and len(calls) >= 3
                            else "Offline",
                        }
                    ]
                }

            epoch = {"instance_termination_unix_s": 152}
            if kind == "container_expired":
                with patch(
                    "inference_platform.stage_c_readiness.subprocess.run",
                    return_value=subprocess.CompletedProcess([], 1, "", "No such container"),
                ):
                    receipt = wait_startup(epoch, (10,) * 4, 10, inspect_container, **timing)
            else:
                receipt = wait_ssm_online(aws, "i-test", epoch, (10,) * 4, 10, **timing)
            if kind == "online":
                self.assertEqual(receipt["status"], "ready")
                self.assertEqual(
                    [a["PingStatus"] for a in receipt["attempts"]], ["Offline", "Offline", "Online"]
                )
            else:
                self.assertEqual(receipt["reason"], "skipped_readiness_deadline")
                self.assertEqual(tick[0], 102)
                self.assertEqual(len(receipt["timed_runs"]), 4)
            self.assertTrue(all(c[:2] == ("ssm", "describe-instance-information") for c in calls))

    def test_delayed_backend_is_polled_until_ready(self):
        with FakeBackend(FakeBackendConfig()) as backend:
            attempts = []
            import urllib.request

            def delayed_probe(url, timeout):
                attempts.append(url)
                if len(attempts) < 3:
                    return False
                with urllib.request.urlopen(url, timeout=timeout) as response:
                    return response.status == 200

            now = time.time()
            receipt = wait_readiness(
                {"instance_boot_unix_s": now, "instance_termination_unix_s": now + 20},
                (1, 1, 1, 1),
                2,
                (backend.base_url + "/health",),
                lambda: None,
                probe=delayed_probe,
            )
            self.assertEqual(receipt["status"], "ready")
            self.assertEqual(len(receipt["attempts"]), 3)
            self.assertGreaterEqual(receipt["observed_readiness_unix_s"], now)

    def test_gateway_startup_exit_reports_last_error_without_waiting(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "gateway.log"
            with log.open("w", encoding="utf-8") as output:
                child = subprocess.Popen(
                    [sys.executable, "-c", "print('invalid BACKENDS'); raise SystemExit(2)"],
                    stdout=output,
                )
                child.wait(timeout=5)
            start = time.perf_counter()
            now = time.time()
            receipt = wait_readiness(
                {"instance_boot_unix_s": now, "instance_termination_unix_s": now + 100},
                (1, 1, 1, 1),
                2,
                ("http://127.0.0.1:1/healthz",),
                lambda: check_processes(child, lambda: True, log),
            )
            stop_child(child)
            self.assertEqual(receipt["status"], "process_exited")
            self.assertIn("invalid BACKENDS", receipt["reason"])
            self.assertLess(time.perf_counter() - start, 1)
            self.assertEqual(receipt["attempts"], [])

    def test_deadline_uses_persisted_epoch_and_reserves_all_minimum_runs(self):
        tick = [50.0]

        def sleep(seconds):
            tick[0] += seconds

        receipt = wait_readiness(
            {"instance_boot_unix_s": 0, "instance_termination_unix_s": 120},
            (2, 2, 2, 2),
            10,
            ("backend", "gateway"),
            lambda: None,
            clock=lambda: tick[0],
            wall_clock=lambda: tick[0] + 50,
            sleep=sleep,
            probe=lambda *_: False,
        )
        self.assertEqual(receipt["readiness_deadline_unix_s"], 102)
        self.assertEqual(receipt["status"], "deadline_expired")
        self.assertEqual(tick[0], 52)
        self.assertTrue(receipt["attempts"])
        self.assertTrue(
            all(r["reason"] == "skipped_readiness_deadline" for r in receipt["timed_runs"])
        )
