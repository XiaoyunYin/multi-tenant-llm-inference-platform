import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from inference_platform.host_disk import COMPONENTS, GIB, disk_fitness, require_disk_headroom
from inference_platform.stage_c import StageCConfig, _runtime_readiness
from inference_platform.stage_c_session import (
    DISK_DIRECTORIES,
    disk_snapshot,
    host_snapshot,
    host_status,
    sampler,
)


class HostDiskTest(unittest.TestCase):
    def test_sampler_minimum_and_status_do_not_rescan_growing_host_file(self):
        import json

        with tempfile.TemporaryDirectory() as directory:
            session = Path(directory) / "session"
            session.mkdir()
            output = session / "host-process-samples.jsonl"
            handlers, count = {}, [0]

            def pause(_):
                count[0] += 1
                if count[0] == 3:
                    handlers[__import__("signal").SIGTERM]()

            with (
                patch(
                    "inference_platform.stage_c_session.signal.signal",
                    side_effect=lambda sig, handler: handlers.__setitem__(sig, handler),
                ),
                patch("inference_platform.stage_c_session.time.sleep", side_effect=pause),
                patch("inference_platform.host_diagnostics.session_processes", return_value={}),
                patch(
                    "inference_platform.host_diagnostics.host_snapshot",
                    side_effect=[
                        {"root_disk": {"free_bytes": free}, "cgroup": {}} for free in (100, 40, 80)
                    ],
                ),
            ):
                sampler(output, [])
            # A broken large historical stream must not affect the constant-size status path.
            output.write_text("invalid historical row\n" * 100000)
            for name in (
                "disk-before-pull.json",
                "disk-readiness.json",
                *(f"disk-checkpoint-{n}.json" for n in range(1, 5)),
            ):
                (session / name).write_text(json.dumps({"status": "available", "free_bytes": 40}))
            status = host_status(Path(directory), 10000)
            self.assertEqual(status["sampled_root_minimum_free_bytes"], 40)
            self.assertEqual(len(status["disk_records"]), 6)

    def test_free_gate_boundary_and_unavailable(self):
        for status, free, passes in (
            ("available", 60 * GIB, True),
            ("available", 60 * GIB - 1, False),
            ("unavailable", 90 * GIB, False),
        ):
            with (
                self.subTest(status=status, free=free),
                patch(
                    "inference_platform.host_disk.disk_snapshot",
                    return_value={"status": status, "free_bytes": free},
                ),
            ):
                if passes:
                    self.assertEqual(require_disk_headroom()["status"], "ok")
                else:
                    with self.assertRaises(RuntimeError):
                        require_disk_headroom()

    def test_low_disk_stops_before_health_tokenize_or_workload(self):
        now = time.time()
        config = StageCConfig(
            url="http://unused",
            token="test",
            tenant_id="test",
            model="test",
            run_id="disk",
            reset_url="http://unused",
            tokenize_url="http://unused",
            gateway_mode=False,
            protocol_version="r0-v2",
            instance_boot_unix_s=now - 2015,
            instance_termination_unix_s=now - 2015 + 14400,
            observed_readiness_unix_s=now,
        )
        with (
            patch(
                "inference_platform.host_disk.disk_snapshot",
                return_value={"status": "available", "free_bytes": 5_906_432},
            ),
            patch("inference_platform.stage_c._health_preflight") as health,
            patch("inference_platform.stage_c._tokenize_preflight") as tokenize,
        ):
            gate = _runtime_readiness(config, 100)
        self.assertEqual(gate["status"], "failed")
        health.assert_not_called()
        tokenize.assert_not_called()

    def test_budget_rotation_and_missing_component(self):
        inputs = {
            "disk_budget": {
                "components_bytes": dict(COMPONENTS),
                "root_volume_gib": 200,
                "minimum_free_after_model_bytes": 60 * GIB,
            }
        }
        launcher = (
            "--log-driver json-file --log-opt max-size=20m --log-opt max-file=3 SystemMaxUse=256M"
        )
        self.assertTrue(disk_fitness(inputs, launcher)[0])
        self.assertFalse(disk_fitness(inputs, launcher.replace("max-file=3", "max-file=0"))[0])
        inputs["disk_budget"]["root_volume_gib"] = 100
        self.assertFalse(disk_fitness(inputs, launcher)[0])
        inputs["disk_budget"]["root_volume_gib"] = 200
        del inputs["disk_budget"]["components_bytes"]["ami_used_upper_bound"]
        self.assertFalse(disk_fitness(inputs, launcher)[0])

    def test_root_series_and_bounded_fixed_directory_breakdown(self):
        with (
            patch(
                "inference_platform.stage_c_session.shutil.disk_usage",
                return_value=SimpleNamespace(total=200 * GIB, used=100 * GIB, free=100 * GIB),
            ),
            patch("inference_platform.stage_c_session.sys.platform", "linux"),
            patch("inference_platform.stage_c_session.Path.stat"),
            patch(
                "inference_platform.stage_c_session.subprocess.run",
                return_value=SimpleNamespace(
                    returncode=1,
                    stdout="500\t/var/lib/docker\n100\t/var/log\n999\t/untrusted-host-name\n",
                ),
            ) as du,
        ):
            snapshot = disk_snapshot(refresh=True)
            self.assertEqual(snapshot["free_bytes"], 100 * GIB)
            self.assertEqual(snapshot["directory_breakdown"]["status"], "partial")
            self.assertEqual(
                snapshot["directory_breakdown"]["largest_directories"],
                [{"label": "docker", "bytes": 500}, {"label": "system_logs", "bytes": 100}],
            )
            self.assertEqual(du.call_args.kwargs["timeout"], 3)
            host = host_snapshot()
            self.assertIn("root_disk", host)
            self.assertEqual(du.call_count, len(DISK_DIRECTORIES))
            self.assertTrue(all(len(call.args[0]) == 5 for call in du.call_args_list))

    def test_per_path_timeout_keeps_previous_and_partial_stdout_and_continues(self):
        def du(argv, **kwargs):
            path = argv[-1]
            if path.endswith("hf-cache"):
                raise subprocess.TimeoutExpired(argv, 3, output=f"50\t{path}\n".encode())
            return SimpleNamespace(returncode=0, stdout=f"100\t{path}\n")

        with (
            patch("inference_platform.stage_c_session.sys.platform", "linux"),
            patch("inference_platform.stage_c_session.Path.stat"),
            patch("inference_platform.stage_c_session.subprocess.run", side_effect=du) as calls,
        ):
            result = disk_snapshot(refresh=True)["directory_breakdown"]
        self.assertEqual(result["path_status"]["model_cache"], "timeout")
        self.assertEqual(len(result["largest_directories"]), len(DISK_DIRECTORIES))
        self.assertEqual(calls.call_count, len(DISK_DIRECTORIES))
        self.assertEqual(result["path_status"]["system_opt"], "available")

    def test_sampler_snapshot_never_runs_directory_scan(self):
        with patch("inference_platform.stage_c_session.subprocess.run") as du:
            result = host_snapshot()
        self.assertIn("free_bytes", result["root_disk"])
        self.assertNotIn("directory_breakdown", result["root_disk"])
        du.assert_not_called()

    def test_nonexistent_path_is_absent_without_du(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch("inference_platform.stage_c_session.sys.platform", "linux"),
            patch(
                "inference_platform.stage_c_session.DISK_DIRECTORIES",
                {"missing": str(Path(directory) / "absent")},
            ),
            patch("inference_platform.stage_c_session.subprocess.run") as du,
        ):
            result = disk_snapshot(refresh=True)["directory_breakdown"]
        self.assertEqual(result["path_status"], {"missing": "absent"})
        self.assertEqual(result["status"], "available")
        du.assert_not_called()

    @unittest.skipUnless(sys.platform == "linux", "real GNU du requires Linux")
    def test_real_du_nested_directories_all_labels_are_present(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = {
                "parent": str(root),
                "model_cache": str(root / "cache"),
                "capture_data": str(root / "capture"),
                "nested": str(root / "cache/sub"),
            }
            for path in paths.values():
                Path(path).mkdir(parents=True, exist_ok=True)
                (Path(path) / "sample").write_bytes(b"x" * 8192)
            with patch("inference_platform.stage_c_session.DISK_DIRECTORIES", paths):
                result = disk_snapshot(refresh=True)["directory_breakdown"]
            self.assertEqual(result["status"], "available")
            self.assertEqual({r["label"] for r in result["largest_directories"]}, set(paths))
            self.assertTrue(all(r["bytes"] >= 8192 for r in result["largest_directories"]))
