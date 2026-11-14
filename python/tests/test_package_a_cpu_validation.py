"""Docker-free route/Runner contracts; fake command results are explicit."""

import contextlib
import copy
import io
import json
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.request import Request, urlopen

import environment_requirements as requirements
import package_a_cpu_stage as stagecopy
import run_resource_cgroup_case as cgroup_stage
from package_a_cpu_stage import run_stage

from inference_platform import package_a_cloud as cloud
from inference_platform import package_a_cpu_validation as cpu
from inference_platform import package_a_operator as operator
from inference_platform.package_a_cpu_fixture import produce
from inference_platform.package_a_operator import host_check_preflight_binding

ROOT = Path(__file__).resolve().parents[2]


class RouteTests(unittest.TestCase):
    def test_cgroup_helper_cleans_after_emitter_failure_without_a_second_run(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        (root / "123").mkdir()
        (root / "123/cgroup").write_text("0::/target")
        for failed in (False, True):
            calls = []

            def execute(argv, calls=calls, failed=failed, **kw):
                calls.append(argv)
                output = b"123" if "inspect" in argv else b""
                code = int(failed and "--cgroupns=host" in argv)
                return subprocess.CompletedProcess(argv, code, output, b"")

            with contextlib.redirect_stdout(io.StringIO()):
                if failed:
                    with self.assertRaises(subprocess.CalledProcessError):
                        cgroup_stage.run(
                            "image",
                            ROOT,
                            "unit-cgroup",
                            state_root=root,
                            execute=execute,
                            proc=root,
                        )
                else:
                    self.assertTrue(
                        cgroup_stage.run(
                            "image",
                            ROOT,
                            "unit-cgroup",
                            state_root=root,
                            execute=execute,
                            proc=root,
                        )["complete"]
                    )
            self.assertEqual(sum("--cgroupns=host" in c for c in calls), 1)
            self.assertEqual(calls[-2][:3], ["docker", "rm", "-f"])
            self.assertEqual(calls[-1][:3], ["docker", "ps", "-aq"])

    def test_dedicated_cgroup_stage_has_separate_exact_target_emitter_argv(self):
        target, emitter = cgroup_stage.commands(
            "pinned@sha256:unit", ROOT, "unit-cgroup", "/target-leaf", ROOT / "fixture-spool"
        )
        self.assertEqual(target[target.index("--cpus") + 1], "1")
        self.assertNotEqual(
            target[target.index("--name") + 1], emitter[emitter.index("--name") + 1]
        )
        self.assertIn("--cgroupns=host", emitter)
        self.assertTrue(any("target=/native-spools,readonly" in a for a in emitter))
        self.assertTrue(any("target=/native-spools" in a and "readonly" not in a for a in target))
        self.assertNotIn("--privileged", emitter)
        self.assertTrue(any("target=/repo,readonly" in arg for arg in emitter))
        self.assertIn("INF037B_RESOURCE_TARGET_CGROUP=/target-leaf", emitter)
        self.assertEqual(
            emitter[-4:], ["python", "scripts/run_package_a_cpu_cases.py", "--phase", "cgroup"]
        )
        required = json.loads((ROOT / cpu.CASE_MANIFEST).read_bytes())
        self.assertEqual(
            required["cgroup"], [cpu.CGROUP_CASE, cpu.READONLY_CASE, cpu.READONLY_RACE_CASE]
        )
        self.assertEqual(sum(phase.count(cpu.CGROUP_CASE) for phase in required.values()), 1)
        self.assertEqual(cpu.CGROUP_STAGE_TIMEOUT_S, 120)

    def test_receipts_glued_to_unittest_output_are_not_lost(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        log = root / "log"
        records = [
            {"module_finish": "one", "duration_s": 3},
            {"shard": 2, "modules": ["one"]},
            {"cpu_stage_integrity": {"complete": True}},
            {"cpu_result": {"errors": 0, "failures": 0, "run": 1}},
        ]
        log.write_text("\n".join("test ... ok" + json.dumps(row) for row in records))
        result = cpu.summary(log)
        self.assertEqual(result["module_durations_s"], records[:1])
        self.assertEqual(result["assignment"], records[1:2])
        self.assertEqual(list(cpu.json_receipts(log.read_text())), records)

    def test_prepare_routes_none_preflight_through_the_selected_tuple(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        for index, checks in enumerate((cloud.TASK_CHECKS, cloud.CPU_VALIDATION_CHECKS)):
            with (
                patch.object(operator, "validate_prior_spend_ledger"),
                patch.object(
                    operator, "host_check_preflight_binding", wraps=host_check_preflight_binding
                ) as binding,
            ):
                with self.assertRaises(FileNotFoundError):
                    operator.prepare(
                        root / str(index),
                        root / "missing-refresh",
                        commit="a" * 40,
                        checks=checks,
                        preflight=None,
                    )
                binding.assert_called_once_with(checks)

    def test_bound_command_lines_and_parameter_guards(self):
        directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        source = (ROOT / "scripts/package_a_host.py").read_bytes()
        manifest = {"source_commit": "HEAD", "region": "us-east-1"}
        with patch.object(operator, "git", return_value=source):
            rows = operator.cpu_command_line_records(directory, manifest)
            self.assertEqual([r["step"] for r in rows], ["readiness", "bootstrap"])
            self.assertTrue(
                all(r["argv_length"] < 30000 and r["parameter_bytes"] < 60000 for r in rows)
            )
            with patch.object(operator, "windows_command_line_length", return_value=30000):
                with self.assertRaisesRegex(ValueError, "windows_command_line:readiness"):
                    operator.cpu_command_line_records(directory, manifest)
            with patch.object(operator, "bootstrap_shell", return_value=["x" * 60000]):
                with self.assertRaisesRegex(ValueError, "ssm_parameter_bytes:bootstrap"):
                    operator.cpu_command_line_records(directory, manifest)
        with patch.object(operator, "git", return_value=b"changed"):
            with self.assertRaisesRegex(ValueError, "host_source_changed"):
                operator.cpu_command_line_records(directory, manifest)

    def test_cli_preflight_refuses_a_parse_error(self):
        directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        with patch.object(
            operator, "operator_aws_cli_pairs", return_value=(("s3api", "list-buckets"),)
        ):
            with patch.object(operator, "run_exe", return_value={"exit": 0}):
                self.assertEqual(operator.cpu_cli_preflight("aws", directory)[0]["exit"], 0)
            with patch.object(operator, "run_exe", return_value={"exit": 252}):
                with self.assertRaisesRegex(ValueError, "aws_cli_parse:s3api:list-buckets"):
                    operator.cpu_cli_preflight("aws", directory)

    def test_only_the_two_exact_tuples_are_accepted(self):
        for checks in (cloud.TASK_CHECKS, cloud.CPU_VALIDATION_CHECKS):
            self.assertEqual([r[0] for r in cloud.selected_checks(checks)], list(checks))
            binding = host_check_preflight_binding(checks)
            self.assertEqual(binding["host_checks"], list(checks))
            self.assertEqual(binding["status"], "REPLACED_BY_HOST_CHECKS")
        self.assertIn(
            "Round 344", host_check_preflight_binding(cloud.CPU_VALIDATION_CHECKS)["authority"]
        )
        for checks in (
            ("race",),
            ("cpu_validation", "race", "e2e"),
            ("race", "e2e", "kind"),
            (),
            "race",
        ):
            with (
                self.subTest(checks=checks),
                self.assertRaisesRegex(ValueError, "invalid_task_checks"),
            ):
                cloud.selected_checks(checks)
        with self.assertRaisesRegex(ValueError, "real_dependency_preflight_required"):
            host_check_preflight_binding(("race", "e2e", "kind"))

    def test_default_binding_is_byte_for_byte_unchanged(self):
        self.assertEqual(
            host_check_preflight_binding(cloud.TASK_CHECKS),
            {
                "status": "REPLACED_BY_HOST_CHECKS",
                "host_checks": ["race", "e2e", "row5"],
                "authority": "Claude Round 290 (DEC-041/DEC-087; DEC-093 note)",
            },
        )

    def test_r351_linux_measured_collector_budget_fits_deadline_and_host_timer(self):
        self.assertEqual(cloud.DEADLINE_S, 21600)
        self.assertEqual(cloud.HOST_TIMER_S, 21000)
        # Round 370 adds four measured modules; keep the collector budget.
        self.assertEqual(cpu.SHARD_TEST_CEILINGS_S, (3660, 3000, 3000))
        worksheet = cloud.timing_worksheet(
            146567703,
            cloud.CPU_VALIDATION_CHECKS,
            cap_usd=40,
            prior_spend_usd=cloud.PRIOR_SPEND_USD,
        )
        self.assertEqual(worksheet["forecast_wall_s"], 21574)
        self.assertEqual(cpu.CPU_STAGE_TIMEOUTS[10:13], (4020, 3360, 3360))
        self.assertEqual(worksheet["call_timeouts_s"]["cpu_validation"][10:13], (4020, 3360, 3360))
        host_envelope = (
            worksheet["forecast_wall_s"]
            - worksheet["cleanup_seconds"]
            - worksheet["retrieval_timeout_s"]
        )
        self.assertEqual(host_envelope, 20778)
        self.assertEqual(cloud.DEADLINE_S - worksheet["forecast_wall_s"], 26)
        self.assertEqual(cloud.HOST_TIMER_S - host_envelope, 222)

    def test_required_case_discovery_is_committed_and_complete(self):
        required = json.loads((ROOT / cpu.CASE_MANIFEST).read_bytes())
        self.assertEqual(required, cpu.required_from_source(ROOT))
        self.assertGreater(len(required["before"]), 60)
        self.assertTrue(any("HostPlacementTests" in case for case in required["before"]))
        self.assertTrue(any("HostClusterTests" in case for case in required["before"]))

    def test_02a_linux_resource_and_clock_cases_are_required(self):
        required = json.loads((ROOT / cpu.CASE_MANIFEST).read_bytes())
        for identifier in (
            "test_inf037b_resources.ResourceAgentTests.test_real_linux_boot_cgroup_and_interface_counters",
            "test_inf037b_eks_execution.ExecutionTests.test_real_linux_measurement_clock_is_continuous",
        ):
            self.assertIn(
                identifier,
                required["cgroup"] if identifier == cpu.CGROUP_CASE else required["before"],
            )

    def test_missing_skipped_and_failed_summaries_refuse(self):
        for passed in ([], ["another.test"]):
            with self.assertRaisesRegex(ValueError, "required_host_case_missing_or_skipped"):
                cpu.validate_required({"passed": passed}, ["required.test"])
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        log = root / "log"
        for text, reason in (
            ("not a summary", "missing_summary"),
            (json.dumps({"cpu_result": {"errors": 1, "failures": 0, "run": 1}}), "failed_cases"),
            (json.dumps({"cpu_result": {"errors": 0, "failures": 0, "run": 0}}), "failed_cases"),
        ):
            log.write_text(text)
            with self.assertRaisesRegex(ValueError, reason):
                cpu.summary(log)


class RunnerTests(unittest.TestCase):
    def execute_branch(self, fault=None):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        manifest = {
            "checks": list(cloud.CPU_VALIDATION_CHECKS),
            "python_executable": sys.executable,
            "pins": json.loads((ROOT / "deploy/package-a/pins.json").read_bytes()),
            "source_commit": "a" * 40,
            "python_sha256": {},
            "instance_type": "c6i.2xlarge",
            "ami": "fixture",
            "on_demand_usd_per_hour": 0.34,
            "deadline_epoch": time.time() + 21000,
        }
        commands, environments = [], {}
        required = json.loads((ROOT / cpu.CASE_MANIFEST).read_bytes())

        def execute(argv, **kw):
            argv = list(map(str, argv))
            path = Path(kw["output"])
            commands.append((path.stem, argv, kw["timeout"]))
            if "--env-file" in argv:
                for index, item in enumerate(argv):
                    if item == "--env-file":
                        environments[path.stem] = Path(argv[index + 1]).read_text()
            text = ""
            if path.stem == "cpu-locked-site":
                text = json.dumps({"site": str(root.resolve())})
                if fault == "site":
                    text = json.dumps({"site": "relative"})
            elif path.stem.startswith("cpu-shard-") or path.stem in (
                "cpu-host-before",
                "cpu-host-after",
                "cpu-resource-cgroup",
            ):
                phase = (
                    "cgroup"
                    if path.stem == "cpu-resource-cgroup"
                    else ("after" if path.stem.endswith("after") else "before")
                )
                passed = (
                    required[phase] if "host" in path.stem or phase == "cgroup" else ["shard.test"]
                )
                if fault == "skip" and path.stem == "cpu-host-before":
                    passed = []
                text = json.dumps(
                    {
                        "cpu_result": {
                            "run": len(passed) or 1,
                            "passed": passed,
                            "errors": 0,
                            "failures": 0,
                            "skips": [],
                        }
                    }
                )
                if fault in ("shard", "summary", "missing") and path.stem == "cpu-shard-0":
                    if fault == "missing":
                        text = "command ended without a summary"
                    else:
                        parsed = json.loads(text)
                        parsed["cpu_result"]["failures"] = 1
                        text = json.dumps(parsed)
                if fault == "before" and path.stem == "cpu-host-before":
                    parsed = json.loads(text)
                    parsed["cpu_result"]["errors"] = 1
                    text = json.dumps(parsed)
            elif path.stem == "race":
                text = "\n".join(
                    "--- PASS: " + name + " (0.00s)"
                    for name in (
                        "TestRedisDynamicCapacityPhases",
                        "TestRedisDynamicMutationSelfCheck",
                        "TestRedisCoordinatorWithheldMarkerBlocksRestoration",
                    )
                )
            elif path.stem == "e2e":
                text = "Ran 1 test in 0.1s\n\nOK\n"
            if fault == "remaining" and path.stem == "cpu-remaining":
                text = "owned-container"
            if path.stem.startswith("cpu-shard-") or path.stem in (
                "cpu-host-before",
                "cpu-host-after",
                "cpu-resource-cgroup",
            ):
                text += "\n" + json.dumps(
                    {
                        "cpu_stage_integrity": {
                            "complete": not (fault == "integrity" and path.stem == "cpu-shard-0"),
                            "go_network": "disabled",
                        }
                    }
                )
            path.write_text(text, encoding="utf-8")
            failing_stage = {
                "shard": "cpu-shard-0",
                "fixtures": "cpu-fixtures",
                "before": "cpu-host-before",
                "cleanup": "cpu-minio-remove",
                "prerequisite": "cpu-diagnostic-build",
            }.get(fault)
            code = int(path.stem == failing_stage)
            if code and kw["expected"] == 0:
                raise RuntimeError("check_exit:" + path.name + ":1")
            return {"log": path.name, "log_sha256": cloud.sha(path), "exit": code}

        def sample():
            return {
                "host": {"MemTotal": 16384 * 1024**2, "MemAvailable": 14000 * 1024**2},
                "vm": {"MemTotal": 16384 * 1024**2, "MemAvailable": 14000 * 1024**2},
            }

        runner = cloud.Runner(ROOT, root / "output", manifest, execute=execute, sample=sample)
        # Existing image preparation and source verification have their own tests.
        with (
            patch.object(cloud, "verified_source", return_value={}),
            patch.object(cloud.Runner, "prepare_images"),
            patch.object(Path, "read_text", autospec=True, side_effect=self.read_text),
        ):
            self.original_read_text = self.read_original
            success = runner.run()
        return success, runner, commands, environments

    read_original = staticmethod(Path.read_text)

    def read_text(self, path, *args, **kw):
        if path.as_posix() == "/sys/fs/cgroup/cgroup.controllers":
            return "memory cpu"
        return self.read_original(path, *args, **kw)

    def test_fixed_branch_via_runner_entrypoint_phase_order_environment_and_receipts(self):
        success, runner, calls, env = self.execute_branch()
        self.assertTrue(success, runner.receipt)
        self.assertEqual([row["status"] for row in runner.receipt["checks"]], ["PASS"] * 3)
        names = [row[0] for row in calls]
        self.assertLess(names.index("cpu-host-before"), names.index("cpu-minio-restart"))
        self.assertLess(names.index("cpu-minio-restart"), names.index("cpu-host-after"))
        for index in range(3):
            argv = next(argv for name, argv, _ in calls if name == f"cpu-shard-{index}")
            self.assertIn("--weighted", argv)
            self.assertEqual(argv[-1], str(cpu.SHARD_TEST_CEILINGS_S[index]))
            self.assertIn(f"type=bind,source={ROOT},target=/source,readonly", argv)
            writable = [a for a in argv if a.startswith("type=bind,") and "target=/repo" in a]
            self.assertEqual(len(writable), 1)
            self.assertNotIn("readonly", writable[0])
            self.assertIn("type=bind,source=/root/go/pkg/mod,target=/go-mod,readonly", argv)
            self.assertIn("/source/scripts/package_a_cpu_stage.py", argv)
        hostenv = env["cpu-host-before"]
        self.assertIn("INF037B_PLACEMENT_HOST_CONFIG=", hostenv)
        self.assertIn("INF037B_CLUSTER_HOST_CONFIG=", hostenv)
        self.assertIn("INF037B_EKS_HOST_TEST=1", hostenv)
        self.assertIn("S3_ENDPOINT_URL=http://127.0.0.1:9000", hostenv)
        self.assertEqual(runner.receipt["cpu_validation"]["remaining"], "")
        self.assertFalse((runner.output / "cpu-validation/host.env").exists())
        self.assertFalse((runner.output / "cpu-validation/minio-data").exists())
        self.assertLessEqual(
            sum(t for n, _, t in calls if n.startswith("cpu-")), sum(cpu.CPU_STAGE_TIMEOUTS)
        )

    def test_required_host_skip_fails_and_still_cleans(self):
        success, runner, calls, _ = self.execute_branch("skip")
        self.assertFalse(success)
        self.assertIn(
            "required_host_case_missing_or_skipped", runner.receipt["cpu_validation"]["error"]
        )
        self.assertIn("cpu-kind-remove", [row[0] for row in calls])

    def test_dirty_tracked_file_receipt_fails_stage_and_continues(self):
        self.assert_all_test_stages_recorded("integrity", "shard-0", "tracked_file_integrity")

    def assert_all_test_stages_recorded(self, fault, failed_stage, reason):
        success, runner, calls, _ = self.execute_branch(fault)
        self.assertFalse(success)
        receipt = runner.receipt["cpu_validation"]
        stages = {row["name"]: row for row in receipt["stages"]}
        for name in ("shard-0", "shard-1", "shard-2", "host-before", "host-after"):
            self.assertIn(name, stages)
            if name != failed_stage or fault != "missing":
                self.assertIn("tests", stages[name])
        self.assertEqual(stages[failed_stage]["status"], "FAILED")
        self.assertIn(reason, stages[failed_stage]["error"])
        self.assertEqual(stages["host-after"]["status"], "PASS")
        self.assertEqual(receipt["status"], "FAILED")
        self.assertEqual(receipt["remaining"], "")
        self.assertEqual(runner.receipt["checks"][-1]["status"], "FAILED")
        self.assertIn("failed_or_cleanup_unverified", runner.receipt["checks"][-1]["error"])
        self.assertIn("cpu-kind-remove", [row[0] for row in calls])
        self.assertFalse((runner.output / "cpu-validation/host.env").exists())
        frozen = json.loads((runner.output / "runner.json").read_bytes())
        self.assertEqual(frozen["cpu_validation"], receipt)
        self.assertLessEqual(
            sum(t for n, _, t in calls if n.startswith("cpu-")), sum(cpu.CPU_STAGE_TIMEOUTS)
        )
        return stages

    def test_failed_shard_records_counts_and_runs_remaining_shards_and_phases(self):
        rows = self.assert_all_test_stages_recorded("shard", "shard-0", "failed_cases")
        self.assertEqual(rows["shard-0"]["exit"], 1)
        self.assertEqual(rows["shard-0"]["tests"]["failures"], 1)

    def test_failed_fixture_still_runs_and_records_all_test_stages(self):
        rows = self.assert_all_test_stages_recorded("fixtures", "fixtures", "stage_exit:1")
        self.assertEqual(rows["fixtures"]["exit"], 1)

    def test_missing_summary_is_recorded_and_remaining_test_stages_run(self):
        self.assert_all_test_stages_recorded("missing", "shard-0", "missing_summary")

    def test_failed_summary_even_with_zero_exit_retains_counts_and_continues(self):
        rows = self.assert_all_test_stages_recorded("summary", "shard-0", "failed_cases")
        self.assertEqual(rows["shard-0"]["exit"], 0)
        self.assertEqual(rows["shard-0"]["tests"]["failures"], 1)

    def test_failed_before_still_runs_and_records_after(self):
        rows = self.assert_all_test_stages_recorded("before", "host-before", "failed_cases")
        self.assertEqual(rows["host-before"]["tests"]["errors"], 1)

    def test_shared_prerequisite_failure_stays_fail_fast(self):
        success, runner, calls, _ = self.execute_branch("prerequisite")
        self.assertFalse(success)
        names = [row[0] for row in calls]
        self.assertNotIn("cpu-shard-0", names)
        self.assertIn("cpu-kind-remove", names)
        self.assertEqual(runner.receipt["cpu_validation"]["status"], "FAILED")

    def test_cleanup_failure_and_remaining_resource_refuse(self):
        for fault in ("cleanup", "remaining", "site"):
            success, runner, _, _ = self.execute_branch(fault)
            self.assertFalse(success, (fault, runner.receipt))


class WritableStageTests(unittest.TestCase):
    def test_stage_bootstraps_pins_without_site_packages_or_pythonpath(self):
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                "-B",
                str(ROOT / "scripts/package_a_cpu_stage.py"),
                "--help",
            ],
            cwd=self.enterContext(tempfile.TemporaryDirectory()),
            capture_output=True,
            text=True,
            timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("--module-cache", result.stdout)

    def fixture(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        source, cache = root / "source", root / "modules"
        source.mkdir()
        cache.mkdir()
        (source / "tracked.txt").write_text("original")
        (cache / "module.txt").write_text("preloaded")
        (source / ".tools").mkdir()
        (source / ".tools/kind").write_text("pinned-kind")
        (source / ".tools/kubectl").write_text("pinned-kubectl")
        (source / ".cache/kind-build").mkdir(parents=True)
        (source / ".cache/kind-build/gateway").write_bytes(b"gateway")
        tokenizer = source / ".cache/pinned-tokenizer" / stagecopy.REVISION
        tokenizer.mkdir(parents=True)
        hashes = {}
        for name in stagecopy.FILE_HASHES:
            data = ("pinned-" + name).encode()
            (tokenizer / name).write_bytes(data)
            hashes[name] = __import__("hashlib").sha256(data).hexdigest()
        self.enterContext(patch.object(stagecopy, "FILE_HASHES", hashes))
        (source / "scripts").mkdir()
        (source / "scripts/check_private_identifiers.py").write_bytes(
            (ROOT / "scripts/check_private_identifiers.py").read_bytes()
        )
        package = source / "python/src/inference_platform"
        package.mkdir(parents=True)
        for name in ("__init__.py", "private_identifier_scan.py"):
            (package / name).write_bytes(
                (ROOT / "python/src/inference_platform" / name).read_bytes()
            )
        subprocess.run(["git", "init", str(source)], check=True, capture_output=True)
        return root, source, cache, tokenizer

    def test_real_copy_seeds_cache_and_refuses_changed_tracked_file(self):
        root, source, cache, tokenizer = self.fixture()
        for dirty in (False, True):
            code = "import os; from pathlib import Path; assert os.environ['GOPROXY']=='off'; assert Path('.cache/go-mod/module.txt').read_text()=='preloaded'"
            if dirty:
                code += "; Path('tracked.txt').write_text('changed')"
            code += "; assert Path('.tools/kind').read_text()=='pinned-kind'"
            code += "; from scripts.check_private_identifiers import main; assert callable(main)"
            code += "; assert str(Path.cwd()) in os.environ['PYTHONPATH'].split(os.pathsep)"
            code += "; assert str(Path.cwd()/'python/src') in os.environ['PYTHONPATH'].split(os.pathsep)"
            code += "; import inference_platform.private_identifier_scan as scan; assert Path(scan.__file__).is_relative_to(Path.cwd())"
            for name in stagecopy.FILE_HASHES:
                code += f"; assert Path('.cache/pinned-tokenizer/{stagecopy.REVISION}/{name}').read_bytes()=={(tokenizer / name).read_bytes()!r}"
            (source / "scripts/probe.py").write_text(code)
            subprocess.run(
                ["git", "-C", str(source), "add", "tracked.txt", "scripts", "python/src"],
                check=True,
            )
            stream = io.StringIO()
            with contextlib.redirect_stdout(stream):
                result = run_stage(
                    source, root / str(dirty), cache, [sys.executable, "scripts/probe.py"]
                )
            self.assertEqual(result, int(dirty))
            record = json.loads(stream.getvalue().splitlines()[-1])["cpu_stage_integrity"]
            self.assertEqual(record["complete"], not dirty)
            self.assertEqual(record["changed_tracked_files"], ["tracked.txt"] if dirty else [])
            self.assertEqual((source / "tracked.txt").read_text(), "original")
            copied = json.loads(stream.getvalue().splitlines()[0])["cpu_stage_copy"]
            self.assertEqual(
                {r["name"] for r in copied["ignored_inputs"]},
                {"module_cache", "tools", "gateway", "tokenizer"},
            )
            self.assertEqual(
                copied["ignored_inputs"][-1]["files"], stagecopy.input_facts(tokenizer)["files"]
            )
            self.assertIn("soft", copied["descriptor_limits"])

    def test_missing_or_corrupt_declared_input_refuses_before_child(self):
        for name in ("module_cache", "tools", "gateway", "tokenizer"):
            root, source, cache, tokenizer = self.fixture()
            path = {
                "module_cache": cache / "module.txt",
                "tools": source / ".tools/kind",
                "gateway": source / ".cache/kind-build/gateway",
                "tokenizer": tokenizer / "tokenizer.json",
            }[name]
            path.unlink()
            with self.assertRaisesRegex(ValueError, "cpu_stage:input_missing:" + name):
                run_stage(
                    source,
                    root / "work",
                    cache,
                    [sys.executable, "-c", "raise AssertionError('child ran')"],
                )
            self.assertFalse((root / "work").exists())
        root, source, cache, tokenizer = self.fixture()
        (tokenizer / "tokenizer.json").write_bytes(b"wrong")
        with self.assertRaisesRegex(ValueError, "cpu_stage:input_hash:tokenizer:tokenizer.json"):
            run_stage(source, root / "work", cache, [])


class EnvironmentTests(unittest.TestCase):
    def test_only_absent_object_in_real_shallow_repository_skips(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        full, shallow, outside = root / "full", root / "shallow", root / "outside"
        outside.mkdir()

        def git(*args):
            return (
                subprocess.check_output(["git", *map(str, args)], stderr=subprocess.DEVNULL)
                .decode()
                .strip()
            )

        git("init", full)
        git(
            "-C",
            full,
            "-c",
            "user.name=fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "--allow-empty",
            "-m",
            "first",
        )
        first = git("-C", full, "rev-parse", "HEAD")
        git(
            "-C",
            full,
            "-c",
            "user.name=fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "--allow-empty",
            "-m",
            "second",
        )
        git("clone", "--depth", "1", full.as_uri(), shallow)
        requirements.require_history(full, first)
        with self.assertRaisesRegex(
            unittest.SkipTest, "shallow_source_bundle_lacks_pinned_history"
        ):
            requirements.require_history(shallow, first)
        for path in (full, outside):
            try:
                requirements.require_history(path, "a" * 40)
            except unittest.SkipTest:
                self.fail("only an absent object in a shallow repository may skip")
            except subprocess.CalledProcessError:
                pass
            else:
                self.fail("broken/full repository failure was accepted")
        self.assertEqual(
            cpu.skip_classification("history", "shallow_source_bundle_lacks_pinned_history: pin"),
            "shallow_source_bundle_lacks_pinned_history",
        )

    def test_missing_powershell_skips_only_off_windows(self):
        with patch.object(requirements.shutil, "which", return_value=None):
            with patch.object(requirements.os, "name", "posix"):
                with self.assertRaisesRegex(
                    unittest.SkipTest, "non_windows_powershell_wrapper_unavailable"
                ):
                    requirements.require_powershell()
            with patch.object(requirements.os, "name", "nt"):
                with self.assertRaisesRegex(RuntimeError, "PowerShell is required"):
                    requirements.require_powershell()
        self.assertEqual(
            cpu.skip_classification("wrapper", "non_windows_powershell_wrapper_unavailable"),
            "non_windows_powershell_wrapper_unavailable",
        )

    def test_venv_control_runs_even_from_a_standalone_interpreter(self):
        from test_package_a_cloud import PackageACloudTests

        with (
            patch.object(cloud.sys, "prefix", "standalone"),
            patch.object(cloud.sys, "base_prefix", "standalone"),
        ):
            PackageACloudTests(
                "test_gate_a_roles_reexec_to_locked_venv_and_refuse_standalone"
            ).test_gate_a_roles_reexec_to_locked_venv_and_refuse_standalone()


class APIFixtureTests(unittest.TestCase):
    def make(self, capacity=16 * 1024**3, held=True, uid=True, workers=2, pod_exists=True):
        requests, objects = [], {}

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def handle_request(self):
                body = json.loads(
                    self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"null"
                )
                requests.append((self.command, self.path, body))
                if self.path == "/api/v1/nodes":
                    result = {
                        "items": [
                            {
                                "metadata": {
                                    "name": "node" + str(i),
                                    "uid": "uid" + str(i),
                                    "labels": {},
                                },
                                "status": {"allocatable": {"memory": str(capacity)}},
                            }
                            for i in range(workers)
                        ]
                    }
                elif self.command == "GET":
                    if "labelSelector" in self.path:
                        name = self.path.split("%3D")[-1]
                        spec = copy.deepcopy(objects[name]["spec"]["template"]["spec"])
                        if not held:
                            spec["nodeName"] = "already-bound"
                        result = {
                            "items": [{"metadata": {"name": name + "-pod"}, "spec": spec}]
                            if pod_exists
                            else []
                        }
                    else:
                        result = {
                            "items": [
                                {
                                    "metadata": {"name": "system", "namespace": "kube-system"},
                                    "spec": {
                                        "containers": [
                                            {"resources": {"requests": {"memory": "128Mi"}}}
                                        ]
                                    },
                                }
                            ]
                        }
                else:
                    result = copy.deepcopy(body)
                    if uid:
                        result["metadata"]["uid"] = "real-API-uid"
                    if body.get("kind") == "Job":
                        objects[body["metadata"]["name"]] = result
                data = json.dumps(result).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = do_PUT = handle_request

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)

        class API:
            def request(self, method, path, body=None):
                data = None if body is None else json.dumps(body).encode()
                with urlopen(
                    Request(
                        f"http://127.0.0.1:{server.server_port}" + path, data=data, method=method
                    ),
                    timeout=3,
                ) as reply:
                    return json.load(reply)

        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        result = produce(
            API(),
            root,
            api_binding={"base": "https://actual", "token_file": "token", "ca": "ca"},
            boot_id="boot",
            image="pinned",
        )
        return root, result, requests

    def test_real_socket_api_producer_exact_fit_and_one_byte_short(self):
        root, (placement, cluster), requests = self.make()
        fillers = json.loads((root / "capacity.json").read_bytes())["fillers"]
        self.assertEqual([r["residual_bytes"] for r in fillers], [12 * 1024**3, 12 * 1024**3 - 1])
        for row in fillers:
            self.assertEqual(
                row["allocatable_bytes"] - row["existing_requests_bytes"] - row["filler_bytes"],
                row["residual_bytes"],
            )
        self.assertEqual(placement["cases"]["short"]["node"]["uid"], "uid1")
        self.assertEqual(len(cluster["nodes"]), 2)
        self.assertTrue(any(body and body.get("kind") == "Job" for _, _, body in requests))

    def test_insufficient_allocatable_bound_pod_and_missing_uid_refuse(self):
        for kw, reason in (
            ({"capacity": 1024**3}, "allocatable_below"),
            ({"held": False}, "pod_not_held"),
            ({"uid": False}, "configmap_uid"),
            ({"workers": 1}, "two_workers_required"),
        ):
            with self.subTest(kw=kw), self.assertRaisesRegex(ValueError, reason):
                self.make(**kw)

    def test_missing_job_pod_has_a_bounded_deadline(self):
        with patch("inference_platform.package_a_cpu_fixture.time.monotonic", side_effect=[0, 61]):
            with self.assertRaisesRegex(ValueError, "pod_deadline"):
                self.make(pod_exists=False)
