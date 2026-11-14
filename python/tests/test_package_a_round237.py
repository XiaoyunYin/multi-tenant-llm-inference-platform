"""Round 237 regressions; all I/O is local fixture data, no cluster or AWS."""

import importlib.util
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from test_package_a_cloud import Runner, historical_timing_worksheet

from inference_platform import package_a_cloud as cloud
from inference_platform.package_a_cloud import GIB, save

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from package_a_kind_walk import coverage  # noqa: E402


class Round237Tests(unittest.TestCase):
    def manifest(self, checks):
        return {
            "checks": checks,
            "python_executable": sys.executable,
            "pins": {"python_image": "fixture"},
            "source_commit": "f" * 40,
            "python_sha256": {},
            "instance_type": "fixture",
            "ami": "fixture",
            "on_demand_usd_per_hour": 0,
            "deadline_epoch": time.time() + 20000,
        }

    def test_r319_real_producer_walk_covers_all_statements(self):
        with tempfile.TemporaryDirectory() as directory:
            result = coverage(Path(directory) / "walk")
            self.assertEqual(result["coverage_percent"], 100)
            receipt = json.loads((Path(directory) / "walk/success/receipt.json").read_bytes())
            for archive in receipt["image_archives"]:
                self.assertTrue(archive["complete"])
                self.assertEqual(archive["export_prefetch"], "buildx_from_pinned_base")
                self.assertEqual(archive["missing_files"], [])

    def test_r320_failed_constrained_keeps_external_oom_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            data = {"MemAvailable": 32 * GIB, "MemTotal": 32 * GIB}
            runner = Runner(
                ROOT,
                Path(directory) / "out",
                self.manifest(["constrained"]),
                sample=lambda: {"host": data, "vm": data.copy()},
            )
            retained = [False]
            calls = []
            peak = {
                "anon_peak_bytes": 123456789,
                "sample_count": 201,
                "sampled_at_utc": "2026-10-21T00:00:10Z",
            }

            def execute(argv, *, output, expected, **kwargs):
                argv = [str(arg) for arg in argv]
                calls.append(argv)
                log = Path(output)
                body = b""
                if argv[:2] == ["docker", "run"]:
                    self.assertNotIn("--rm", argv)
                    self.assertEqual(argv[argv.index("--memory") + 1], "12g")
                    self.assertEqual(argv[argv.index("--memory-swap") + 1], "12g")
                    self.assertEqual(argv[argv.index("--name") + 1], runner.container_name)
                    retained[0] = True
                    save(runner.output / "anon-progress.json", peak)
                    log.write_bytes(b"fixture SIGKILL\n")
                    raise RuntimeError("check_exit:constrained.log:137")
                if argv[:2] == ["docker", "inspect"]:
                    self.assertTrue(retained[0])
                    body = b'{"OOMKilled":true,"ExitCode":137}'
                elif argv[0] == "journalctl":
                    self.assertIn("--since", argv)
                    self.assertIn("--until", argv)
                    self.assertIn("--grep", argv)
                    body = b"fixture kernel oom killed measured process\n" * 3000
                elif argv[:2] == ["docker", "rm"]:
                    retained[0] = False
                elif argv[:2] == ["docker", "ps"]:
                    body = b"leftover" if retained[0] else b""
                log.write_bytes(body)
                return {"log": log.name, "exit": 0}

            runner.execute = execute
            runner.prepare_images = lambda: None
            with (
                patch.object(cloud, "verified_source", return_value={}),
                patch.object(Path, "read_text", return_value="cpu memory"),
            ):
                self.assertFalse(runner.run())
            row = json.loads((runner.output / "runner.json").read_bytes())["checks"][0]
            self.assertEqual(row["status"], "FAILED")
            self.assertIn("137", row["error"])
            evidence = row["failure_evidence"]
            self.assertEqual(evidence["inspect_state"], {"OOMKilled": True, "ExitCode": 137})
            self.assertIn("oom killed", evidence["kernel_oom"]["text"])
            self.assertLessEqual(len(evidence["kernel_oom"]["text"].encode()), 65536)
            self.assertEqual(evidence["last_progress_peak"], peak)
            self.assertTrue(evidence["container_gone"])
            self.assertLess(
                calls.index(next(c for c in calls if c[:2] == ["docker", "inspect"])),
                calls.index(next(c for c in calls if c[:2] == ["docker", "rm"])),
            )

    def test_r320_scoped_runner_refuses_unlisted_check_and_forecast_uses_list(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = Runner(ROOT, Path(directory) / "out", self.manifest(["kind", "constrained"]))
            runner.call = lambda *_args, **_kwargs: self.fail("unlisted check executed I/O")
            with self.assertRaisesRegex(ValueError, "check_not_in_manifest:smoke"):
                runner.check("smoke")
        worksheet = historical_timing_worksheet(
            139300866, checks=("kind",), hourly_all_resources_usd=0.4
        )
        self.assertEqual(worksheet["checks"], ["kind"])
        self.assertEqual(worksheet["work_seconds"], cloud.BUDGETS["kind"])
        self.assertEqual(set(worksheet["admission_budgets_s"]), {"kind", "prepare_images"})
        self.assertEqual(worksheet["deadline_seconds"], 21600)
        from inference_platform.package_a_operator import Ports

        ports = Ports.__new__(Ports)
        ports.manifest = {"prior_spend_usd": 6.33528005, "hourly_all_resources_usd": 0.4}
        self.assertAlmostEqual(ports.task_cost(0, 3600), 1.4)
        self.assertAlmostEqual(ports.cumulative_cost(0, 3600), 7.73528005)

    def test_r320_sampler_persists_peak_every_ten_seconds(self):
        spec = importlib.util.spec_from_file_location(
            "sizing_r320", ROOT / "scripts/size_inf037b_sanitized_export.py"
        )
        sizing = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(sizing)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            progress = root / "results/anon-progress.json"
            (root / "memory.stat").write_bytes(b"anon 123\n")
            sampler = sizing.CgroupAnonSampler(root, True, progress_path=progress)
            with patch.object(sizing.time, "monotonic", side_effect=[0, 9.99, 10]):
                sampler.sample()
                first = progress.read_bytes()
                (root / "memory.stat").write_bytes(b"anon 456\n")
                sampler.sample()
                self.assertEqual(progress.read_bytes(), first)
                sampler.sample()
            result = json.loads(progress.read_bytes())
            self.assertEqual(result["anon_peak_bytes"], 456)
            self.assertEqual(result["sample_count"], 3)
            self.assertEqual(result["monotonic_s"], 10)
            self.assertIn("sampled_at_utc", result)


if __name__ == "__main__":
    unittest.main()
