import json
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from inference_platform.stage_c import StageCConfig, _publisher_preflight
from inference_platform.stage_c_container import PACKAGE_ROOT, capture_argv, stage_capture_package
from inference_platform.stage_c_fitness import capture_layout_fitness


class ContainerLayoutTest(unittest.TestCase):
    def test_staging_probe_and_capture_share_importable_package_root(self):
        root = Path(__file__).resolve().parents[2]
        provided, reason = capture_layout_fitness(root)
        self.assertTrue(provided, reason)
        commands = []
        stage_capture_package(
            root, Path("/tmp/private"), run=lambda argv, **_: commands.append(argv)
        )
        self.assertIn(PACKAGE_ROOT, commands[0])
        self.assertEqual(commands[1][-1], f"inf011-vllm:{PACKAGE_ROOT}/")
        self.assertIn(f"PYTHONPATH={PACKAGE_ROOT}", capture_argv())

    def test_semantic_fitness_rejects_successful_copy_to_wrong_package_root(self):
        root = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            package = target / "python/src/inference_platform"
            shutil.copytree(
                root / "python/src/inference_platform",
                package,
                ignore=shutil.ignore_patterns("__pycache__"),
            )
            source = package / "stage_c_container.py"
            source.write_text(
                source.read_text(encoding="utf-8").replace(
                    'f"{container}:{PACKAGE_ROOT}/"', 'f"{container}:/opt/inf011/python/"'
                ),
                encoding="utf-8",
            )
            provided, reason = capture_layout_fitness(target)
            self.assertFalse(provided)
            self.assertIn("staged import failed", reason)

    def test_empty_and_invalid_probe_stdout_report_stderr_and_returncode(self):
        for stdout in ("", "not JSON", "[]"):
            result = subprocess.CompletedProcess(
                [], 1, stdout, "ModuleNotFoundError: inference_platform"
            )
            config = StageCConfig(
                url="http://127.0.0.1:8080",
                model="test",
                gateway_mode=True,
                token="local",
                tenant_id="test",
                run_id="test",
                reset_url="local",
                tokenize_url="local",
            )
            with (
                self.subTest(stdout=stdout),
                patch("inference_platform.stage_c.subprocess.run", return_value=result),
            ):
                receipt = _publisher_preflight(config, time.perf_counter() + 30)
            self.assertEqual(receipt["status"], "unavailable")
            self.assertEqual(receipt["returncode"], 1)
            self.assertIn("ModuleNotFoundError", receipt["stderr"])
            json.dumps(receipt)
