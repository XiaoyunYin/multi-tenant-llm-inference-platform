import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from inference_platform.kv_event_capture import capture_zmq_event_stream
from inference_platform.session_stop import pid_is_running, stop_child, stop_pid_file
from inference_platform.stage_c import _counter, main


class StageCFinalizeTest(unittest.TestCase):
    def test_finalizer_reaps_live_and_already_exited_real_children(self):
        for code in ("import time; time.sleep(60)", "pass"):
            with self.subTest(code=code):
                child = subprocess.Popen([sys.executable, "-c", code])
                if code != "pass":
                    self.assertTrue(pid_is_running(child.pid))
                if code == "pass":
                    time.sleep(0.2)  # Deliberately leave the exited child unreaped on POSIX.
                receipt = stop_child(child)
                self.assertTrue(receipt["reaped"])
                self.assertEqual(receipt["status"], "stopped")
                self.assertIsNotNone(child.returncode)
                self.assertFalse(pid_is_running(child.pid))

    def test_labelled_native_counters_sum_series_without_confusing_other_names(self):
        with patch(
            "inference_platform.stage_c._metrics",
            return_value={
                "values": {
                    'backend:a:vllm:prefix_cache_hits_total{model_name="m",engine="0"}': 16,
                    'backend:b:vllm:prefix_cache_hits_total{model_name="m",engine="1"}': 32,
                    'vllm:prefix_cache_queries_total{model_name="m"}': 100,
                }
            },
        ):
            self.assertEqual(_counter(None, "vllm:prefix_cache_hits_total"), 48)
            self.assertIsNone(_counter(None, "vllm:unknown_total"))

    def test_pid_file_stops_real_sampler_with_spaces_in_path(self):
        with tempfile.TemporaryDirectory(prefix="stage c ") as directory:
            path = Path(directory) / "sampler pid.txt"
            samples = Path(directory) / "sampler samples.jsonl"
            # On the EC2 host the sampler's SIGTERM handler flushes its writer.
            # Windows terminates this disposable child; neither uses a shell string.
            with subprocess.Popen(
                [
                    # Windows venv python.exe redirects to a child interpreter.
                    # Exercise the recorded PID itself, not the redirector PID.
                    getattr(sys, "_base_executable", sys.executable),
                    "-c",
                    "import json,signal,sys,time; "
                    "signal.signal(signal.SIGTERM,lambda *_:sys.exit(0)); "
                    "f=open(sys.argv[1],'w',encoding='utf-8'); "
                    "f.write(json.dumps({'sample':1})+'\\n'); f.flush(); time.sleep(60)",
                    str(samples),
                ]
            ) as child:
                try:
                    deadline = time.perf_counter() + 5
                    while not samples.exists() or not samples.stat().st_size:
                        if time.perf_counter() > deadline:
                            self.fail("sampler failed to write")
                        time.sleep(0.01)
                    path.write_text(str(child.pid), encoding="utf-8")
                    self.assertEqual(stop_pid_file(path), child.pid)
                    child.wait(timeout=5)
                finally:
                    if child.poll() is None:
                        child.kill()
                        child.wait(timeout=5)
            self.assertEqual(json.loads(samples.read_text(encoding="utf-8")), {"sample": 1})
            path.write_text("1; echo unsafe", encoding="utf-8")
            with self.assertRaises(ValueError):
                stop_pid_file(path)

    def test_real_capture_cooperative_stop_returns_before_duration_ceiling(self):
        with tempfile.TemporaryDirectory() as directory:
            stop = Path(directory) / "capture.stop"
            started = time.perf_counter()
            observations = capture_zmq_event_stream(
                "tcp://127.0.0.1:1",
                duration_seconds=60,
                stop_file=stop,
                on_subscribed=lambda: stop.touch(),
            )
            self.assertEqual(observations, [])
            self.assertLess(time.perf_counter() - started, 5)

    def test_cli_finalizes_immediately_after_artifact_without_waiting_for_cutoff(self):
        with tempfile.TemporaryDirectory(prefix="stage c ") as directory:
            output = Path(directory) / "artifact.json"
            marker = Path(directory) / "export and teardown.txt"
            result = {
                "status": "completed",
                "finalization": {
                    "start": "immediately_after_last_run",
                    "export_cutoff_is_ceiling_only": True,
                },
            }
            argv = [
                "stage-c",
                "--config",
                "unused.json",
                "--output",
                str(output),
                "--finalize-argv",
                sys.executable,
                "-c",
                "import pathlib,sys; assert pathlib.Path(sys.argv[1]).exists(); "
                "pathlib.Path(sys.argv[2]).write_text('export verified; teardown')",
                str(output),
                str(marker),
            ]
            started = time.perf_counter()
            with (
                patch.object(sys, "argv", argv),
                patch(
                    "inference_platform.stage_c._config_from_json",
                    return_value=SimpleNamespace(
                        instance_termination_unix_s=time.time() + 3600,
                        protocol_version="r0-v2",
                        local_rehearsal=True,
                    ),
                ),
                patch("inference_platform.stage_c.run_stage_c", return_value=result),
            ):
                self.assertEqual(main(), 0)
            self.assertLess(time.perf_counter() - started, 5)
            self.assertTrue(marker.exists())
            self.assertEqual(
                json.loads(output.read_text())["finalization"]["controller_exit_code"], 0
            )

    def test_expired_finalizer_preserves_artifact_and_returns_nonzero(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "artifact.json"
            result = {"status": "partial", "finalization": {}}
            argv = [
                "stage-c",
                "--config",
                "unused",
                "--output",
                str(output),
                "--finalize-argv",
                sys.executable,
                "-c",
                "import time; time.sleep(60)",
            ]
            with (
                patch.object(sys, "argv", argv),
                patch(
                    "inference_platform.stage_c._config_from_json",
                    return_value=SimpleNamespace(
                        instance_termination_unix_s=time.time() + 0.1,
                        protocol_version="r0-v2",
                        local_rehearsal=True,
                    ),
                ),
                patch("inference_platform.stage_c.run_stage_c", return_value=result),
            ):
                self.assertEqual(main(), 1)
            saved = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(saved["status"], "partial")
            self.assertIn("error", saved["finalization"])
