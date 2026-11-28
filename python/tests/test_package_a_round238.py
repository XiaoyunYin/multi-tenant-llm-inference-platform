"""Round 238 regressions for rehearsal fixtures and DEC-077 cost accounting."""

import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import time
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from test_package_a_cloud import Runner, historical_timing_worksheet

from inference_platform import package_a_cloud as cloud
from inference_platform import package_a_operator as operator
from inference_platform.package_a_cloud import GIB, save

ROOT = Path(__file__).resolve().parents[2]
REHEARSAL_SCRIPT = (
    Path(os.environ.get("R238_SCRIPT_ROOT", ROOT / "scripts")) / "package_a_linux_rehearsal.py"
)
BUNDLE_BYTES = 139_300_866
HOURLY_USD = 0.384 + 0.005 + (64 * 0.08 / 720)


def rehearsal_module():
    scripts = str(ROOT / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    spec = importlib.util.spec_from_file_location(
        "package_a_linux_rehearsal_r238", REHEARSAL_SCRIPT
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Round238Tests(unittest.TestCase):
    def test_r321_host_gate_status_comes_from_the_sample(self):
        module = rehearsal_module()
        required = 2304 * 1024**2
        sample = {
            "sampled_at_utc": "2026-10-21T12:00:00+00:00",
            "host": {"MemAvailable": required - 1, "MemTotal": 8 * GIB},
            "vm": {"MemTotal": 8 * GIB},
        }
        record = module.constrained_host_record(sample)
        self.assertEqual(record["memory_limit_bytes"], 256 * 1024**2)
        self.assertEqual(record["memory_swap_total_bytes"], 256 * 1024**2)
        self.assertEqual(record["host_gate_required_bytes"], required)
        self.assertEqual(record["available_before_run_bytes"], required - 1)
        self.assertEqual(record["host_gate_status"], "host_gate_failed")
        sample["host"]["MemAvailable"] = required
        self.assertEqual(module.constrained_host_record(sample)["host_gate_status"], "passed")
        audit = json.loads(
            (ROOT / "docs/evidence/m5-package-a/round237-source-audit.json").read_bytes()
        )["round238_claude_determination"]
        self.assertEqual(audit["native_inventory_stop"], "resolved")
        self.assertEqual(audit["collector_modules_unchanged"], 17)
        self.assertEqual(
            {
                row["path"]: row["resolution"]
                for row in audit["r321_rehearsal_fixture_classifications"]
            },
            {
                "scripts/check_package_a_cloud.py": "unrelated",
                "scripts/package_a_linux_rehearsal.py": "unrelated",
            },
        )

    def cloud_runner(self, output, execute):
        data = {"MemAvailable": 32 * GIB, "MemTotal": 32 * GIB}
        runner = Runner(
            ROOT,
            output,
            {
                "checks": ["constrained"],
                "python_executable": sys.executable,
                "pins": {"python_image": "fixture"},
                "source_commit": "f" * 40,
                "python_sha256": {},
                "instance_type": "fixture",
                "ami": "fixture",
                "on_demand_usd_per_hour": 0,
                "deadline_epoch": time.time() + 20000,
            },
            sample=lambda: {"host": data, "vm": data.copy()},
        )
        runner.execute = execute
        runner.prepare_images = lambda: None
        return runner

    def test_r322_kernel_excerpt_artifact_is_bounded_to_64_kib(self):
        worksheet = historical_timing_worksheet(BUNDLE_BYTES, ["kind", "constrained"])
        self.assertIn("cost_guard_hours", worksheet)
        self.assertIn("cost_guard_margin_s", worksheet)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "out"
            long_kernel_log = b"fixture oom line\n" * 6000

            def execute(argv, *, output, expected, **kwargs):
                argv = [str(arg) for arg in argv]
                path = Path(output)
                if argv[:2] == ["docker", "run"]:
                    path.write_bytes(b"fixture SIGKILL\n")
                    raise RuntimeError("check_exit:constrained.log:137")
                if argv[:2] == ["docker", "inspect"]:
                    path.write_bytes(b'{"OOMKilled":true,"ExitCode":137}')
                elif argv[0] == "journalctl":
                    path.write_bytes(long_kernel_log)
                elif argv[:2] == ["docker", "ps"]:
                    path.write_bytes(b"")
                else:
                    path.write_bytes(b"")
                return {"log": path.name, "exit": 0}

            runner = self.cloud_runner(output, execute)
            with (
                patch.object(cloud, "verified_source", return_value={}),
                patch.object(Path, "read_text", return_value="cpu memory"),
            ):
                self.assertFalse(runner.run())
            artifact = output / "constrained-kernel_oom.log"
            self.assertLessEqual(artifact.stat().st_size, 65536)
            row = json.loads((output / "runner.json").read_bytes())["checks"][0]
            self.assertTrue(row["failure_evidence"]["kernel_oom"]["truncated"])
            self.assertLessEqual(len(row["failure_evidence"]["kernel_oom"]["text"].encode()), 65536)

    def test_r322_unverified_container_cleanup_raises_after_a_successful_run(self):
        worksheet = historical_timing_worksheet(BUNDLE_BYTES, ["kind", "constrained"])
        self.assertIn("cost_guard_hours", worksheet)
        self.assertIn("cost_guard_margin_s", worksheet)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "out"

            def execute(argv, *, output, expected, **kwargs):
                argv = [str(arg) for arg in argv]
                path = Path(output)
                if argv[:2] == ["docker", "inspect"]:
                    path.write_bytes(b'{"OOMKilled":false,"ExitCode":0}')
                elif argv[:2] == ["docker", "ps"]:
                    path.write_bytes(b"leftover-container-id\n")
                else:
                    path.write_bytes(b"")
                return {"log": path.name, "exit": 0}

            runner = self.cloud_runner(output, execute)
            with (
                patch.object(cloud, "verified_source", return_value={}),
                patch.object(Path, "read_text", return_value="cpu memory"),
            ):
                self.assertFalse(runner.run())
            receipt = json.loads((output / "runner.json").read_bytes())
            row = receipt["checks"][0]
            self.assertEqual(row["status"], "FAILED")
            self.assertIn("constrained_container_cleanup_unverified", row["error"])
            self.assertFalse(row["failure_evidence"]["container_gone"])

    @staticmethod
    def fake_preflight(root, commit):
        receipt_root = root / "preflight"
        receipt_root.mkdir()

        def evidence(name):
            path = receipt_root / name
            path.write_bytes(b"fixture evidence\n")
            return {"log": name, "log_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}

        sections = {
            name: evidence(name + ".log")
            for name in (
                "go_real_redis",
                "go_real_redis_race",
                "gateway_build",
                "gateway_config",
            )
        }
        from inference_platform.package_a_images import LINUX_E2E_IMAGE

        binary = receipt_root / "gateway-linux"
        binary.write_bytes(b"fixture linux binary")
        sections["gateway_redis_e2e"] = {
            **evidence("gateway_redis_e2e.log"),
            "runtime": "linux-container",
            "python_image": LINUX_E2E_IMAGE,
            "container_removed": True,
            "build": {
                **evidence("gateway-e2e-build.log"),
                "exit_code": 0,
                "GOOS": "linux",
                "GOARCH": "amd64",
                "CGO_ENABLED": "0",
                "binary_path": binary.name,
                "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            },
            "cleanup": evidence("gateway-e2e-cleanup.log"),
            "verify_removed": evidence("gateway-e2e-verify-removed.log"),
        }
        control_archive = receipt_root / "control.tar"
        control_archive.write_bytes(b"fixture archive")
        control = {
            "import": evidence("control-import.log"),
            "inspect": evidence("control-inspect.log"),
            "export_commands": [],
            "archive_path": control_archive.name,
            "archive_sha256": hashlib.sha256(control_archive.read_bytes()).hexdigest(),
        }
        containerd = {
            "start": evidence("containerd-start.log"),
            "ready": evidence("containerd-ready.log"),
            "cleanup": evidence("containerd-cleanup.log"),
            "images": {},
            "control": control,
        }
        receipt = {
            "source_head": commit,
            **sections,
            "images": {},
            "containerd_image_resolution": containerd,
            "gateway_config": sections["gateway_config"],
            "nginx_start": {},
            "kind_no_cluster": {},
            "workload_files_sha256": {},
        }
        path = receipt_root / "receipt.json"
        path.write_text(json.dumps(receipt), encoding="utf-8")
        return path

    @staticmethod
    def fake_refresh(root):
        refresh = {
            "instance_type": "c6i.2xlarge",
            "memory_mib": 16384,
            "vcpus": 8,
            "availability_zones": ["us-east-1a"],
            "standard_vcpu_quota": 8,
            "active_instance_count": 0,
            "image_bytes": {"node": 1024, "python": 1024, "redis": 1024},
            "observed_export_bytes": 1,
            "on_demand_usd_per_hour": 0.384,
            "ipv4_usd_per_hour": 0.005,
            "gp3_usd_per_gib_month": 0.08,
            "ami": "ami-fixture",
            "account_id_sha256": "a" * 64,
        }
        path = root / "refresh.json"
        path.write_text(json.dumps(refresh), encoding="utf-8")
        return path

    def prepare_packet(self, root, prior_spend):
        (root / "deploy/package-a").mkdir(parents=True)
        (root / "deploy/package-a/pins.json").write_text("{}", encoding="utf-8")
        for path in (
            root / ".tools/terraform/1.16.2/terraform.exe",
            root / ".cache/session-manager-plugin/bin/bin/session-manager-plugin.exe",
            root / "aws.exe",
        ):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"fixture executable")
        commit = "c" * 40
        preflight = self.fake_preflight(root, commit)
        refresh = self.fake_refresh(root)
        packet = root / "packet"

        def fake_git(*args, **kwargs):
            if args[0] == "clone":
                Path(args[-1]).mkdir()
            elif args[:2] == ("rev-parse", "HEAD"):
                return commit.encode()
            elif args[:2] == ("bundle", "create"):
                with Path(args[2]).open("wb") as stream:
                    stream.truncate(BUNDLE_BYTES)
            elif args[0] == "ls-tree":
                return b"100644 blob " + b"a" * 40 + b" 1 fixture-file\n"
            return b""

        def fake_run(argv, *, cwd, output, timeout, env=None, expected=0):
            path = Path(output)
            if str(argv[0]).endswith("terraform.exe"):
                path.write_bytes(b'{"terraform_version":"1.16.2"}')
            else:
                path.write_bytes(b"fixture version\n")
            return {"log_sha256": operator.sha(path)}

        def fake_seal(directory):
            variables = json.loads((directory / "input.tfvars.json").read_bytes())
            save(
                directory / "sealed-plans.json",
                {"create_sha256": "1" * 64, "destroy_sha256": "2" * 64, "variables": variables},
            )

        with ExitStack() as stack:
            stack.enter_context(patch.object(operator, "ROOT", root))
            stack.enter_context(patch.object(operator, "PRIOR_RUN_COST_USD", prior_spend))
            stack.enter_context(patch.object(operator, "git", side_effect=fake_git))
            stack.enter_context(patch.object(operator, "python_hashes", return_value={}))
            stack.enter_context(patch.object(operator, "run_exe", side_effect=fake_run))
            stack.enter_context(patch.object(operator, "sealed_plans", side_effect=fake_seal))
            stack.enter_context(
                patch.object(operator.shutil, "which", return_value=str(root / "aws.exe"))
            )
            stack.enter_context(
                patch.object(operator, "validate_real_dependency_preflight_receipt")
            )
            stack.enter_context(patch.object(operator, "bind_workload_preflight"))
            return operator.prepare(packet, refresh, commit=commit, preflight=preflight)

    def test_r322_prepare_records_task_and_cumulative_forecasts(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = self.prepare_packet(Path(directory), cloud.PRIOR_RUN_COST_USD)
        expected_task = 6 * manifest["hourly_all_resources_usd"] + 1.0
        self.assertAlmostEqual(manifest["task_cost_usd"], expected_task)
        self.assertAlmostEqual(
            manifest["cumulative_cost_usd"], cloud.PRIOR_RUN_COST_USD + expected_task
        )
        self.assertIn("cost_guard_hours", manifest)
        self.assertIn("cost_guard_margin_s", manifest)
        self.assertGreater(manifest["cost_guard_margin_s"], 0)
        self.assertEqual(manifest["hard_cap_usd"], cloud.CAP_USD)
        self.assertLess(
            manifest["cumulative_cost_usd"] + manifest["cleanup_cost_reserve_usd"],
            cloud.CAP_USD,
        )
        self.assertNotIn("forecast_usd_including_failed_work", manifest)

    def test_r322_prepare_refuses_budget_sum_past_cost_guard_time(self):
        # Fixture-scale prior spend puts the guard below the selected work sum.
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "cost_guard_budget_exceeds_guard_time"):
                self.prepare_packet(Path(directory), cloud.CAP_USD - 2.1)


if __name__ == "__main__":
    unittest.main()
