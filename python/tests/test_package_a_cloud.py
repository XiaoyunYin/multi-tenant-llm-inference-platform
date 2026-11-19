import hashlib
import importlib.util
import inspect
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import traceback
import unittest
from http.client import HTTPConnection
from pathlib import Path
from unittest.mock import MagicMock, patch

from inference_platform import package_a_cloud as cloud
from inference_platform.package_a_cloud import (
    BUDGETS,
    CALL_S,
    CALL_TIMEOUTS,
    CHECKS,
    CLEANUP_S,
    DEADLINE_S,
    EXPORT_MAX_BYTES,
    GIB,
    METADATA_S,
    ROW5_DIAGNOSTIC_INTEGRATION_TIMEOUT_S,
    ROW5_KIND_CRITICAL_PATH_S,
    ROW5_KIND_DIAGNOSTIC_BUILD_TIMEOUT_S,
    ROW5_KIND_TIME_BOUNDS_S,
    ROW5_KIND_TIMEOUT_S,
    ROW5_NATIVE_SUITE_TIMEOUT_S,
    ROW5_READINESS_TIMEOUT_S,
    ROW5_SUITE_TIMEOUT_S,
    Lifecycle,
    gate,
    memory_sample,
    run_exe,
    save,
    sha,
    transfer_seconds,
    verified_source,
)
from inference_platform.package_a_cloud import (
    Runner as ProductionRunner,
)
from inference_platform.package_a_images import LINUX_E2E_IMAGE, inspect_docker_archive
from inference_platform.package_a_operator import (
    Ports,
    bootstrap_shell,
    recover,
    render_user_data,
    require_marker,
    ssm_registration_window_s,
    validate_review_marker,
)
from inference_platform.package_a_secrets import control_token
from inference_platform.package_a_timings import build_timings_receipt

ROOT = Path(__file__).resolve().parents[2]


def sample(available):
    data = {"MemAvailable": available, "MemTotal": 32 * GIB}
    return {"host": data, "vm": data.copy(), "sampled_at_utc": "2026-10-19T00:00:00+00:00"}


def run_real_unittest_module(root, name, source, *, expected=0):
    package = root / name
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "test_cases.py").write_text(source, encoding="utf-8")
    log = root / (name + ".log")
    env = {
        **os.environ,
        "PYTHONPATH": str(root),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    result = run_exe(
        [sys.executable, "-m", "unittest", "-v", name + ".test_cases"],
        cwd=root,
        output=log,
        timeout=30,
        env=env,
        expected=expected,
    )
    return log, result


def historical_timing_worksheet(*args, **kwargs):
    """Keep historical pure timing arithmetic controls out of packet admission."""
    with patch.object(
        cloud,
        "selected_checks",
        side_effect=lambda names: [row for name in names for row in CHECKS if row[0] == name],
    ):
        return cloud.timing_worksheet(*args, **kwargs)


def Runner(*args, **kwargs):
    """Exercise historical individual branches without admitting legacy packets.

    Production selected_checks now admits only the two reviewed tuples. These
    old tests deliberately cover all historical branch bodies and failure order.
    """
    with patch.object(
        cloud,
        "selected_checks",
        side_effect=lambda names: [row for name in names for row in CHECKS if row[0] == name],
    ):
        return ProductionRunner(*args, **kwargs)


class Clock:
    def __init__(self):
        self.now = 1000

    def __call__(self):
        return self.now


class FaultPorts:
    def __init__(self, clock, fault):
        self.clock, self.fault, self.calls = clock, fault, []
        self.active = False
        self.cap_seen = False
        self.partial = []

    def task_cost(self, start, now):
        return 1 + (now - start) * 0.0001

    def cumulative_cost(self, start, now):
        self.cap_seen = self.cap_seen or (self.fault == "cap" and self.active)
        return cloud.CAP_USD + 0.1 if self.cap_seen else 5 + self.task_cost(start, now)

    def apply(self, end):
        self.calls.append("apply")
        self.active = True
        if self.fault == "lost_apply":
            raise ConnectionError("ambiguous successful create, reply lost")

    def bootstrap(self, end):
        self.calls.append("bootstrap")
        if self.fault == "deadline":
            self.clock.now += DEADLINE_S - CLEANUP_S + 1

    def upload(self, end):
        self.calls.append("upload")

    def run_checks(self, end):
        self.calls.append("run_checks")
        for name, *_ in CHECKS:
            self.partial.append(name)
            if name == "smoke" and self.fault in {"check", "lost_ssm"}:
                raise ConnectionError(self.fault)
        if self.fault == "gate":
            self.partial[1] = "smoke:SKIPPED_GATE"
            raise RuntimeError("runner nonzero: recorded gate skip")

    def retrieve(self, end):
        self.calls.append("retrieve")
        if self.fault == "retrieve":
            raise ConnectionError("lost retrieval session")
        return {"complete": True, "existing": self.partial.copy()}

    def teardown(self, end):
        self.calls.append("teardown")
        self.active = False
        if self.fault == "teardown":
            raise RuntimeError("destroy reply lost")
        return {"destroy_completed": True}

    def inventory(self, end):
        self.calls.append("inventory")
        return {"empty": not self.active}


class PackageACloudTests(unittest.TestCase):
    def test_linux_standin_hashes_bundle_without_whole_file_allocation(self):
        spec = importlib.util.spec_from_file_location(
            "linux_standin_hash", ROOT / "scripts/package_a_linux_rehearsal.py"
        )
        module = importlib.util.module_from_spec(spec)
        with patch.object(sys, "path", [str(ROOT / "scripts"), *sys.path]):
            spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "source.bundle"
            expected = hashlib.sha256()
            with path.open("wb") as handle:
                for _ in range(80):
                    block = b"real-bundle-data" * 4096
                    handle.write(block)
                    expected.update(block)
            with patch.object(
                Path, "read_bytes", side_effect=AssertionError("unbounded bundle read")
            ):
                self.assertEqual(
                    module.bundle_facts(path),
                    {"bundle_bytes": 80 * len(block), "bundle_sha256": expected.hexdigest()},
                )

    def test_transport_rehearsal_lifecycle_contains_monotonic_phase_ranges(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "transport"
            environment = {
                **os.environ,
                "PYTHONPATH": str(ROOT / "python/src"),
                "PYTHONDONTWRITEBYTECODE": "1",
            }
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts/package_a_transport_rehearsal.py"),
                    "--output",
                    str(output),
                ],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            receipt = json.loads((output / "transport.json").read_bytes())
            self.assertEqual(len(receipt["scenarios"]), 7)
            for scenario in receipt["scenarios"]:
                with self.subTest(fault=scenario["fault"]):
                    phases = scenario["lifecycle"]["phases"]
                    self.assertEqual(
                        set(phases),
                        {
                            "apply",
                            "bootstrap",
                            "readiness",
                            "upload",
                            "staging",
                            "run_checks",
                            "retrieve",
                            "teardown",
                            "inventory",
                        },
                    )
                    for name, phase in phases.items():
                        start = phase["monotonic_start_ns"]
                        end = phase["monotonic_end_ns"]
                        if phase["status"] == "NOT_RUN":
                            self.assertIsNone(start)
                            self.assertIsNone(end)
                        else:
                            self.assertIsInstance(start, int, name)
                            self.assertIsInstance(end, int, name)
                            self.assertGreaterEqual(end, start, name)
                    timings = build_timings_receipt(scenario["lifecycle"], "")
                    self.assertEqual(set(timings["lifecycle_phase_seconds"]), set(phases))
                    self.assertIn(
                        "SSM registration", timings["lifecycle_phase_meanings"]["bootstrap"]
                    )
                    self.assertIn(
                        "host bootstrap script", timings["lifecycle_phase_meanings"]["run_checks"]
                    )

    def test_timings_receipt_builds_host_bootstrap_interval_from_log_fixture(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            lifecycle = {
                "phases": {
                    "bootstrap": {
                        "status": "PASS",
                        "monotonic_start_ns": 0,
                        "monotonic_end_ns": 14_672_000_000,
                    },
                    "run_checks": {
                        "status": "PASS",
                        "monotonic_start_ns": 15_000_000_000,
                        "monotonic_end_ns": 115_000_000_000,
                    },
                }
            }
            bootstrap = (
                "start_utc=2026-11-06T00:00:00Z unrelated log line\n"
                "step=apt_update attempt=1 cap_s=300 start_utc=2026-11-06T01:06:28Z\n"
                "step=apt_update attempt=1 end_utc=2026-11-06T01:06:37Z exit_code=0\n"
                "step=tool_download:uv attempt=1 cap_s=52 start_utc=2026-11-06T01:06:50+00:00\n"
                "step=tool_download:uv attempt=1 elapsed_ms=316 end_utc=2026-11-06T01:06:51+00:00 exit_code=0\n"
                "step=gateway_build attempt=1 end_utc=2026-11-06T01:07:57Z exit_code=0\n"
                "end_utc=2026-11-06T02:00:00Z unrelated log line\n"
            )
            (root / "lifecycle.json").write_text(json.dumps(lifecycle), encoding="utf-8")
            (root / "bootstrap.log").write_text(bootstrap, encoding="utf-8")
            (root / "base.json").write_text(
                json.dumps({"operator_command_seconds": {"apply": 37.844}}), encoding="utf-8"
            )
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts/build_package_a_timings.py"),
                    "--lifecycle",
                    str(root / "lifecycle.json"),
                    "--bootstrap-log",
                    str(root / "bootstrap.log"),
                    "--base",
                    str(root / "base.json"),
                    "--output",
                    str(root / "timings.json"),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
                env={**os.environ, "PYTHONPATH": str(ROOT / "python/src")},
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            receipt = json.loads((root / "timings.json").read_bytes())
            self.assertEqual(receipt["bootstrap_script"]["duration_s"], 89)
            self.assertEqual(receipt["bootstrap_script"]["start_utc"], "2026-11-06T01:06:28Z")
            self.assertEqual(receipt["bootstrap_script"]["end_utc"], "2026-11-06T01:07:57Z")
            self.assertEqual(receipt["bootstrap_script"]["containing_phase"], "run_checks")
            self.assertIsNone(receipt["bootstrap_script_reason"])
            self.assertEqual(receipt["lifecycle_phase_seconds"]["bootstrap"]["duration_s"], 14.672)
            self.assertEqual(receipt["lifecycle_phase_total_s"], 114.672)
            self.assertEqual(receipt["operator_command_seconds"], {"apply": 37.844})
            self.assertEqual(lifecycle["phases"]["bootstrap"]["monotonic_start_ns"], 0)

    def test_timings_receipt_without_step_lines_has_null_interval_and_named_reason(self):
        receipt = build_timings_receipt({"phases": {}}, "bootstrap failed before its first step\n")
        self.assertIsNone(receipt["bootstrap_script"])
        self.assertEqual(receipt["bootstrap_script_reason"], "bootstrap_script:no_step_lines")

    def test_timings_receipt_reads_host_log_from_frozen_archive(self):
        from inference_platform.package_a_timings import main as build_timings

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "lifecycle.json").write_text('{"phases": {}}', encoding="utf-8")
            log = (
                b"step=apt start_utc=2026-11-06T01:00:00Z\n"
                b"step=build end_utc=2026-11-06T01:00:03Z exit_code=0\n"
            )
            with tarfile.open(root / "receipts.tar.gz", "w:gz") as archive:
                member = tarfile.TarInfo("bootstrap.log")
                member.size = len(log)
                archive.addfile(member, io.BytesIO(log))
            with patch("sys.stdout", new=io.StringIO()):
                build_timings(
                    [
                        "--lifecycle",
                        str(root / "lifecycle.json"),
                        "--receipts",
                        str(root / "receipts.tar.gz"),
                        "--output",
                        str(root / "timings.json"),
                    ]
                )
            receipt = json.loads((root / "timings.json").read_bytes())
            self.assertEqual(receipt["bootstrap_script"]["duration_s"], 3)
            self.assertFalse((root / "bootstrap.log").exists())

    def test_timings_receipt_incomplete_or_invalid_step_interval_is_explicit(self):
        for log, reason in (
            ("step=apt start_utc=2026-11-06T01:06:28Z\n", "incomplete_step_interval"),
            ("step=apt start_utc=invalid\nstep=apt end_utc=invalid\n", "invalid_step_timestamp"),
            (
                "step=apt start_utc=2026-11-06T01:07:57Z\nstep=apt end_utc=2026-11-06T01:06:28Z\n",
                "reversed_step_interval",
            ),
        ):
            with self.subTest(reason=reason):
                receipt = build_timings_receipt({"phases": {}}, log)
                self.assertIsNone(receipt["bootstrap_script"])
                self.assertEqual(receipt["bootstrap_script_reason"], "bootstrap_script:" + reason)

    def test_gate_a_ssm_registration_window_is_600_seconds_and_other_workloads_stay_180(self):
        self.assertEqual(ssm_registration_window_s({"workload": "r366-gate-a"}), 600)
        self.assertEqual(ssm_registration_window_s({"workload": "package-a"}), 180)
        self.assertEqual(ssm_registration_window_s({}), 180)

    def test_spend_ledger_ignores_copied_evidence_but_counts_consumed_packets(self):
        from inference_platform import package_a_operator as operator

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ledger = root / "spend-ledger.json"
            ledger.write_text(json.dumps({"entries": [], "prior_spend_usd": 0}), encoding="utf-8")
            evidence = root / ".cache" / "archive" / "docs/evidence/session"
            evidence.mkdir(parents=True)
            (root / ".cache" / "archive" / "PLAN.md").write_text("plan", encoding="utf-8")
            (root / ".cache" / "archive" / "REVIEW.md").write_text("review", encoding="utf-8")
            (evidence / "consumed.json").write_text("{}", encoding="utf-8")
            with patch.object(operator.package_a_cloud_module, "PRIOR_SPEND_USD", 0):
                self.assertEqual(
                    operator.validate_prior_spend_ledger(root, ledger),
                    {
                        "entries": [],
                        "prior_spend_usd": 0,
                    },
                )
                packet = root / ".cache" / "packet"
                packet.mkdir()
                (packet / "consumed.json").write_text("{}", encoding="utf-8")
                with self.assertRaisesRegex(
                    ValueError, r"prior_spend_ledger_incomplete:\.cache/packet"
                ):
                    operator.validate_prior_spend_ledger(root, ledger)

    def test_gate_a_registration_halts_with_last_ping_when_five_seconds_remain(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory) / "runtime"
            ports = Ports.__new__(Ports)
            ports.runtime = runtime
            runtime.mkdir()
            ports.registration_path = runtime / "ssm-registration.json"
            ports.status_answered = False
            ports.host = "i-fixture"
            ports.started = 0
            ports.manifest = {"cleanup_cost_reserve_usd": 1, "workload": "r366-gate-a"}
            ports.manifest_hash = "f" * 64
            ports.token = "fixture"
            ports.cumulative_cost = lambda *args: 0
            ports.aws = lambda *args: {
                "InstanceInformationList": [{"PingStatus": "ConnectionLost"}]
            }
            now = [1_000.0]
            with (
                patch(
                    "inference_platform.package_a_operator.time.time", side_effect=lambda: now[0]
                ),
                patch(
                    "inference_platform.package_a_operator.time.sleep",
                    side_effect=lambda seconds: now.__setitem__(0, now[0] + 596),
                ),
                self.assertRaisesRegex(
                    TimeoutError,
                    r"ssm_registration_deadline elapsed_s=\d+\.\d{3} "
                    r"last_ping_status=ConnectionLost",
                ) as raised,
            ):
                ports.bootstrap(5_000)
            self.assertEqual(ports.deadline, 1_600.0)
            self.assertFalse(ports.ssm_online)
            self.assertIn("last_ping_status=ConnectionLost", str(raised.exception))

    def test_gate_a_roles_reexec_to_locked_venv_and_refuse_standalone(self):
        target = os.path.abspath(sys.executable)
        with (
            patch.object(cloud.sys, "prefix", target + "-venv"),
            patch.object(cloud.sys, "base_prefix", target),
        ):
            self.assertEqual(
                cloud.gate_a_role_reexec_target(
                    {"role": "gate_a_receiver", "python_executable": target}
                ),
                None,
            )
        self.assertEqual(
            cloud.gate_a_role_reexec_target(
                {"role": "host_checks", "python_executable": "/unused/python"}
            ),
            None,
        )
        with (
            patch.object(cloud.sys, "prefix", target),
            patch.object(cloud.sys, "base_prefix", target),
        ):
            with self.assertRaisesRegex(RuntimeError, "gate_a:role_requires_locked_venv"):
                cloud.gate_a_role_reexec_target(
                    {"role": "gate_a_sender", "python_executable": target}
                )
        other = str(Path(target).with_name("locked-venv-python"))
        self.assertEqual(
            cloud.gate_a_role_reexec_target(
                {"role": "gate_a_receiver", "python_executable": other}
            ),
            other,
        )

    def test_gate_a_receiver_runner_serializes_path_values_from_role_receipt(self):
        from pathlib import Path

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = Runner(
                ROOT,
                root / "runner-output",
                {
                    "role": "gate_a_receiver",
                    "python_executable": sys.executable,
                    "pins": {"python_image": "pinned"},
                    "gate_a_receiver": {
                        "service": True,
                        "run_readiness": False,
                        "private_address": "127.0.0.1",
                    },
                },
            )
            service = MagicMock()
            service.start.return_value = ("0.0.0.0", 38473)
            service.wait.return_value = {"complete": True, "retrieval_path": root / "retrieved"}
            with patch(
                "inference_platform.inf037b_gate_a.GateAReceiverSupervisor",
                return_value=service,
            ):
                self.assertTrue(runner.run_gate_a_receiver())
            receipt = json.loads((runner.output / "runner.json").read_bytes())
            self.assertEqual(receipt["status"], "PASS")
            self.assertEqual(receipt["gate_a_receiver"]["retrieval_path"], str(root / "retrieved"))

    def test_lifecycle_then_recovery_preserves_distinct_command_receipts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = {
                "session_manager_plugin_path": "fixture",
                "operator_tools": {"terraform": {"path": "terraform"}},
                "hourly_all_resources_usd": 0,
                "prior_spend_usd": 0,
                "cleanup_cost_reserve_usd": 1,
            }
            save(root / "manifest.json", manifest)
            save(root / "operator.lock", {"pid": 1})

            def ports_factory(*args, **kwargs):
                ports = Ports(*args, **kwargs)
                for name in ("apply", "bootstrap", "upload", "run_checks"):
                    setattr(ports, name, lambda end: None)
                ports.retrieve = lambda end: {"complete": True}
                ports.instance_ids = lambda: ["fixture-id"]
                ports.aws = lambda *args, **kwargs: {}

                def inventory(end):
                    result = {"empty": True}
                    save(ports.runtime / "teardown-inventory.json", result)
                    return result

                ports.inventory = inventory
                return ports

            def execute(argv, *, output, **kwargs):
                output.write_bytes(
                    b"No changes. 0 destroyed\n"
                    if output.parent.name.startswith("recovery-")
                    else b"Destroy complete. 5 destroyed\n"
                )
                result = {"log_sha256": sha(output), "exit": 0}
                save(output.with_suffix(".command.json"), result)
                return result

            with patch("inference_platform.package_a_operator.run_exe", side_effect=execute):
                original = ports_factory(root, manifest)
                result = Lifecycle(original, manifest, root / "final").run()
                self.assertTrue(result["complete"], result)
                before = {p: p.read_bytes() for p in original.runtime.iterdir() if p.is_file()}
                with (
                    patch("inference_platform.package_a_operator.Ports", side_effect=ports_factory),
                    patch("inference_platform.package_a_operator.executing_binding"),
                    patch(
                        "inference_platform.package_a_operator.pid_is_running", return_value=False
                    ),
                ):
                    for _ in range(2):
                        recovered = recover(root, "fixture")
                        self.assertTrue(recovered["inventory"]["empty"], recovered)
                        self.assertTrue(recovered["teardown"]["destroy_completed"], recovered)
            for path, data in before.items():
                self.assertEqual(path.read_bytes(), data)
            logs = sorted((root / "operator").glob("recovery-*/destroy.log"))
            self.assertEqual(len(logs), 2)
            self.assertNotEqual(sha(logs[0]), sha(root / "operator/destroy.log"))
            for path in logs:
                self.assertEqual(path.read_bytes(), b"No changes. 0 destroyed\n")
                self.assertTrue((path.parent / "wait-terminated.command.json").is_file())
                self.assertTrue((path.parent / "teardown-inventory.json").is_file())
                self.assertTrue((path.parent / "recovery.json").is_file())

    def test_command_refuses_existing_log_or_receipt_before_execution(self):
        for suffix in (".log", ".command.json"):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                manifest = {"session_manager_plugin_path": "fixture", "operator_tools": {}}
                save(root / "manifest.json", manifest)
                ports = Ports(root, manifest)
                path = ports.runtime / ("destroy" + suffix)
                path.write_bytes(b"original receipt")
                with patch("inference_platform.package_a_operator.run_exe") as execute:
                    with self.assertRaises(FileExistsError):
                        ports.command(["fixture"], time.time() + 30, "destroy")
                    execute.assert_not_called()
                self.assertEqual(path.read_bytes(), b"original receipt")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = {"session_manager_plugin_path": "fixture", "operator_tools": {}}
            save(root / "manifest.json", manifest)
            ports = Ports(root, manifest)
            barrier = threading.Barrier(2)
            outcomes = []

            def invoke():
                barrier.wait(timeout=5)
                try:
                    ports.command(["fixture"], time.time() + 30, "destroy")
                    outcomes.append("executed")
                except FileExistsError:
                    outcomes.append("refused")

            with patch("inference_platform.package_a_operator.run_exe") as execute:
                threads = [threading.Thread(target=invoke) for _ in range(2)]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join(timeout=10)
                    self.assertFalse(thread.is_alive())
                self.assertEqual(sorted(outcomes), ["executed", "refused"])
                self.assertEqual(execute.call_count, 1)

    @staticmethod
    def valid_real_dependency_preflight_receipt():
        from inference_platform.package_a_images import KIND_LOCAL_IMAGE_TAGS

        images = {}
        resolved = {}
        export_commands = [
            {"log": f"export-{index}.log", "log_sha256": "e" * 64} for index in range(3)
        ]
        container_name = "dec077-containerd-fixture"
        node_image = json.loads((ROOT / "deploy/k8s/pins.json").read_bytes())["node_image"]
        import_command = [
            "docker",
            "exec",
            "-i",
            container_name,
            "ctr",
            "--namespace=k8s.io",
            "images",
            "import",
            "--all-platforms",
            "--digests",
            "--snapshotter=overlayfs",
            "-",
        ]
        for index, (name, local_tag) in enumerate(KIND_LOCAL_IMAGE_TAGS.items(), start=1):
            pinned = f"registry.example/{name}@sha256:{str(index) * 64}"
            config_digest = "sha256:" + str(index + 4) * 64
            images[name] = {
                "complete": True,
                "platform": "linux/amd64",
                "local_tag": local_tag,
                "pinned_reference": pinned,
                "config_digest": config_digest,
                "sha256": "a" * 64,
                "commands": export_commands,
            }
            resolved[name] = {
                "local_tag": local_tag,
                "pinned_reference": pinned,
                "config_digest": config_digest,
                "archive_sha256": "a" * 64,
                "export_commands": export_commands,
                "import": {"exit_code": 0, "command": import_command},
                "inspect": {
                    "exit_code": 0,
                    "command": ["docker", "exec", container_name, "crictl", "inspecti", local_tag],
                    "resolved_image_id": config_digest,
                },
            }
        start_command = [
            "docker",
            "run",
            "--detach",
            "--rm",
            "--privileged",
            "--memory",
            "512m",
            "-v",
            "/var/lib/containerd",
            "--name",
            container_name,
            "--entrypoint",
            "containerd",
            node_image,
        ]
        control_reference = "registry.example/redis@sha256:" + "1" * 64
        return {
            "schema": "dec077-real-dependency-preflight-v1",
            "complete": True,
            "billable_actions": 0,
            "source_head": "c" * 40,
            "kind_no_cluster": {
                "schema": "package-a-kind-no-cluster-v1",
                "complete": True,
                "billable_actions": 0,
                "skipped_tests": 0,
                "coverage_percent": 100,
                "line_coverage_percent": 100,
                "kubectl_sha256": json.loads(
                    (Path(__file__).resolve().parents[2] / "deploy/k8s/pins.json").read_bytes()
                )[
                    "kubectl_windows_amd64_sha256"
                    if os.name == "nt"
                    else "kubectl_linux_amd64_sha256"
                ],
                "rehearsal_sha256": sha(
                    Path(__file__).resolve().parents[2] / "scripts/rehearse_eks_package_a.py"
                ),
                "files_sha256": {
                    name: "a" * 64
                    for name in (
                        "api/transcript.json",
                        "walk/coverage.json",
                        "walk/success/receipt.json",
                    )
                },
            },
            "zero_skips": True,
            "go_real_redis": {"complete": True, "passed_tests": 1, "skipped_tests": 0},
            "go_real_redis_race": {
                "complete": True,
                "exit_code": 0,
                "passed_tests": 1,
                "skipped_tests": 0,
            },
            "gateway_redis_e2e": {
                "passed_tests": 1,
                "skipped_tests": 0,
                "runtime": "linux-container",
                "python_image": LINUX_E2E_IMAGE,
                "container_removed": True,
                "build": {
                    "exit_code": 0,
                    "GOOS": "linux",
                    "GOARCH": "amd64",
                    "CGO_ENABLED": "0",
                    "binary_sha256": "a" * 64,
                },
            },
            "gateway_config": {
                "exit_code": 0,
                "complete": True,
                "command": ["gateway", "--check-config"],
            },
            "nginx_start": {
                "complete": True,
                "running": True,
                "https_status": 404,
                "container_removed": True,
                "container_name": "dec077-nginx-fixture",
                "start": {
                    "exit_code": 0,
                    "command": [
                        "docker",
                        "run",
                        "--detach",
                        "--name",
                        "dec077-nginx-fixture",
                        "--read-only",
                        "--user",
                        "101:101",
                        "--tmpfs",
                        "/tmp:rw,noexec,nosuid,size=64m,uid=101,gid=101",
                        "--mount",
                        "type=bind,source=config,target=/etc/nginx/nginx.conf,readonly",
                        "--mount",
                        "type=bind,source=tls,target=/tls,readonly",
                        __import__(
                            "inference_platform.eks_deployment", fromlist=["NGINX_IMAGE"]
                        ).NGINX_IMAGE,
                        "nginx",
                        "-g",
                        "daemon off;",
                    ],
                },
                "inspect": {"exit_code": 0},
                "logs": {"exit_code": 0},
                "cleanup": {
                    "exit_code": 0,
                    "command": ["docker", "rm", "-f", "dec077-nginx-fixture"],
                },
                "verify_removed": {"exit_code": 1},
            },
            "images": images,
            "redis_cleanup": {"container_removed": True},
            "containerd_image_resolution": {
                "schema": "dec077-containerd-image-resolution-v1",
                "complete": True,
                "container_removed": True,
                "container_name": container_name,
                "node_image": node_image,
                "start": {"exit_code": 0, "command": start_command},
                "ready": {
                    "exit_code": 0,
                    "command": ["docker", "exec", container_name, "ctr", "version"],
                },
                "cleanup": {
                    "exit_code": 0,
                    "command": ["docker", "rm", "-f", container_name],
                },
                "images": resolved,
                "control": {
                    "expected_failure": True,
                    "pinned_reference": control_reference,
                    "archive_path": "images/redis-digest-control.tar",
                    "archive_sha256": "b" * 64,
                    "export_commands": export_commands,
                    "import": {"exit_code": 0, "command": import_command},
                    "inspect": {
                        "exit_code": 1,
                        "command": [
                            "docker",
                            "exec",
                            container_name,
                            "crictl",
                            "inspecti",
                            control_reference,
                        ],
                    },
                },
            },
        }

    def test_kind_amd64_archive_requires_every_manifest_descriptor(self):
        with tempfile.TemporaryDirectory() as directory:
            archive_path = Path(directory) / "image.tar"
            manifest = json.dumps(
                [{"Config": "config.json", "RepoTags": ["fixture:tag"], "Layers": ["layer.tar"]}]
            ).encode()
            with tarfile.open(archive_path, "w") as archive:
                for name, data in (
                    ("manifest.json", manifest),
                    ("config.json", b'{"os":"linux","architecture":"amd64"}'),
                    ("layer.tar", b"layer"),
                ):
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
            result = inspect_docker_archive(archive_path)
            self.assertTrue(result["complete"])
            self.assertEqual(result["platform"], "linux/amd64")
            self.assertEqual(result["descriptor_count"], 2)
            self.assertEqual(result["missing_files"], [])

            incomplete = Path(directory) / "incomplete.tar"
            with tarfile.open(incomplete, "w") as archive:
                for name, data in (
                    ("manifest.json", manifest),
                    ("config.json", b'{"os":"linux","architecture":"amd64"}'),
                ):
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
            with self.assertRaisesRegex(ValueError, "docker_archive_descriptor_missing:layer.tar"):
                inspect_docker_archive(incomplete)

            wrong_platform = Path(directory) / "wrong-platform.tar"
            with tarfile.open(wrong_platform, "w") as archive:
                for name, data in (
                    ("manifest.json", manifest),
                    ("config.json", b'{"os":"linux","architecture":"arm64"}'),
                    ("layer.tar", b"layer"),
                ):
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
            with self.assertRaisesRegex(ValueError, "docker_archive_platform_mismatch:linux/arm64"):
                inspect_docker_archive(wrong_platform)

    def test_r300_local_tag_archives_and_all_kind_controller_images(self):
        from inference_platform.eks_deployment import (
            NGINX_IMAGE,
            PROMETHEUS_IMAGE,
            PYTHON_IMAGE,
            REDIS_IMAGE,
            VLLM_IMAGE,
        )
        from inference_platform.package_a_images import (
            KIND_LOCAL_IMAGE_TAGS,
            crictl_image_resolution_matches,
            rewrite_kind_workload_images,
        )

        self.assertTrue(
            crictl_image_resolution_matches(
                "mti-fake:stage1",
                0,
                {
                    "id": "sha256:" + "b" * 64,
                    "repoTags": ["docker.io/library/mti-fake:stage1"],
                },
            )
        )
        self.assertFalse(
            crictl_image_resolution_matches(
                "mti-fake:stage1",
                0,
                {
                    "id": "sha256:" + "b" * 64,
                    "repoTags": ["docker.io/library/other:stage1"],
                },
            )
        )
        self.assertTrue(
            crictl_image_resolution_matches(
                "dec077-kind/redis:amd64",
                0,
                {
                    "id": "sha256:" + "a" * 64,
                    "repoTags": ["docker.io/dec077-kind/redis:amd64"],
                },
                expected_config_digest="sha256:" + "a" * 64,
            )
        )
        self.assertFalse(
            crictl_image_resolution_matches(
                "dec077-kind/redis:amd64",
                0,
                {
                    "id": "sha256:" + "b" * 64,
                    "repoTags": ["docker.io/dec077-kind/redis:amd64"],
                },
                expected_config_digest="sha256:" + "a" * 64,
            )
        )

        gateway_source = "example.invalid/gateway@sha256:" + "a" * 64
        local_gateway, local_fake = "mti-gateway:stage1", "mti-fake:stage1"
        replacements = {
            REDIS_IMAGE: KIND_LOCAL_IMAGE_TAGS["redis"],
            NGINX_IMAGE: KIND_LOCAL_IMAGE_TAGS["nginx"],
            PROMETHEUS_IMAGE: KIND_LOCAL_IMAGE_TAGS["prometheus"],
            PYTHON_IMAGE: KIND_LOCAL_IMAGE_TAGS["python"],
            gateway_source: local_gateway,
            VLLM_IMAGE: local_fake,
        }
        allowed = set(KIND_LOCAL_IMAGE_TAGS.values()) | {local_gateway, local_fake}
        manifest = {
            "items": [
                {
                    "kind": "Deployment",
                    "metadata": {"name": "gateway"},
                    "spec": {"template": {"spec": {"containers": [{"image": gateway_source}]}}},
                },
                {
                    "kind": "Deployment",
                    "metadata": {"name": "metrics"},
                    "spec": {
                        "template": {
                            "spec": {
                                "containers": [
                                    {"image": NGINX_IMAGE},
                                    {"image": PROMETHEUS_IMAGE},
                                ]
                            }
                        }
                    },
                },
                {
                    "kind": "StatefulSet",
                    "metadata": {"name": "redis-vllm"},
                    "spec": {
                        "template": {
                            "spec": {
                                "containers": [
                                    {"image": REDIS_IMAGE},
                                    {"image": VLLM_IMAGE},
                                ]
                            }
                        }
                    },
                },
                {
                    "kind": "DaemonSet",
                    "metadata": {"name": "node-observer"},
                    "spec": {"template": {"spec": {"containers": [{"image": PYTHON_IMAGE}]}}},
                },
            ]
        }
        used = rewrite_kind_workload_images(
            manifest, replacements=replacements, allowed_images=allowed
        )
        self.assertEqual(set(used), allowed)
        for resource in manifest["items"]:
            if resource["kind"] not in {"Deployment", "StatefulSet", "DaemonSet"}:
                continue
            for container in resource["spec"]["template"]["spec"]["containers"]:
                self.assertIn(container["image"], allowed)
                self.assertEqual(container["imagePullPolicy"], "Never")

        config = b'{"os":"linux","architecture":"amd64"}'
        local_tag = KIND_LOCAL_IMAGE_TAGS["redis"]
        with tempfile.TemporaryDirectory() as directory:
            archive_path = Path(directory) / "tagged.tar"
            archive_manifest = json.dumps(
                [{"Config": "config.json", "RepoTags": [local_tag], "Layers": ["layer.tar"]}]
            ).encode()
            with tarfile.open(archive_path, "w") as archive:
                for name, data in (
                    ("manifest.json", archive_manifest),
                    ("config.json", config),
                    ("layer.tar", b"layer"),
                ):
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
            observed = inspect_docker_archive(archive_path, expected_local_tag=local_tag)
            self.assertEqual(observed["repo_tags"], [local_tag])
            self.assertEqual(
                observed["config_digest"],
                "sha256:" + hashlib.sha256(config).hexdigest(),
            )

            commands = []

            def fake_docker(argv, *, timeout):
                command = [str(part) for part in argv]
                commands.append(command)
                if command[:3] == ["docker", "image", "save"]:
                    output = Path(command[command.index("--output") + 1])
                    output.write_bytes(archive_path.read_bytes())
                return {"exit_code": 0, "log": "fixture.log", "log_sha256": "d" * 64}

            from inference_platform.package_a_images import save_amd64_archive

            saved = save_amd64_archive(
                "registry.example/redis@sha256:" + "b" * 64,
                Path(directory) / "saved.tar",
                fake_docker,
                local_tag=local_tag,
            )
            build = next(
                command for command in commands if command[:3] == ["docker", "buildx", "build"]
            )
            save_command = next(
                command for command in commands if command[:3] == ["docker", "image", "save"]
            )
            self.assertEqual(build[build.index("--tag") + 1], local_tag)
            self.assertEqual(save_command[save_command.index("--platform") + 1], "linux/amd64")
            self.assertEqual(save_command[-1], local_tag)
            self.assertEqual(saved["pinned_reference"], "registry.example/redis@sha256:" + "b" * 64)
            self.assertEqual(saved["local_tag"], local_tag)

    def test_r300_prepare_requires_containerd_resolution_and_control(self):
        from inference_platform.package_a_operator import validate_real_dependency_preflight_receipt

        receipt = self.valid_real_dependency_preflight_receipt()
        validate_real_dependency_preflight_receipt(receipt, "c" * 40)
        del receipt["containerd_image_resolution"]
        with self.assertRaisesRegex(ValueError, "real_dependency_preflight_incomplete"):
            validate_real_dependency_preflight_receipt(receipt, "c" * 40)
        receipt = self.valid_real_dependency_preflight_receipt()
        receipt["containerd_image_resolution"]["start"]["command"].remove("--rm")
        with self.assertRaisesRegex(ValueError, "real_dependency_preflight_incomplete"):
            validate_real_dependency_preflight_receipt(receipt, "c" * 40)
        receipt = self.valid_real_dependency_preflight_receipt()
        receipt["containerd_image_resolution"]["images"]["redis"]["import"]["command"].remove(
            "--digests"
        )
        with self.assertRaisesRegex(ValueError, "containerd_image_resolution_mismatch:redis"):
            validate_real_dependency_preflight_receipt(receipt, "c" * 40)
        receipt = self.valid_real_dependency_preflight_receipt()
        receipt["containerd_image_resolution"]["cleanup"]["command"][-1] = "not-the-owned-container"
        with self.assertRaisesRegex(ValueError, "real_dependency_preflight_incomplete"):
            validate_real_dependency_preflight_receipt(receipt, "c" * 40)

    def test_r308_prepare_requires_a_complete_real_redis_race_receipt(self):
        from inference_platform.package_a_operator import validate_real_dependency_preflight_receipt

        receipt = self.valid_real_dependency_preflight_receipt()
        del receipt["go_real_redis_race"]
        with self.assertRaisesRegex(ValueError, "real_dependency_preflight_incomplete"):
            validate_real_dependency_preflight_receipt(receipt, "c" * 40)
        receipt = self.valid_real_dependency_preflight_receipt()
        receipt["go_real_redis_race"]["complete"] = False
        with self.assertRaisesRegex(ValueError, "real_dependency_preflight_incomplete"):
            validate_real_dependency_preflight_receipt(receipt, "c" * 40)

    def test_prepare_host_checks_replace_preflight_only_for_exact_task_route(self):
        from inference_platform.package_a_cloud import TASK_CHECKS
        from inference_platform.package_a_operator import (
            host_check_preflight_binding,
            prepare,
        )

        expected = {
            "status": "REPLACED_BY_HOST_CHECKS",
            "host_checks": ["race", "e2e", "row5"],
            "authority": "Claude Round 290 (DEC-041/DEC-087; DEC-093 note)",
        }
        self.assertEqual(TASK_CHECKS, ("race", "e2e", "row5"))
        self.assertEqual(host_check_preflight_binding(TASK_CHECKS), expected)
        for index, checks in enumerate((("row5",), ("race", "row5"), ("e2e", "race", "row5"))):
            with self.subTest(checks=checks), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                with patch("inference_platform.package_a_operator.TASK_CHECKS", checks):
                    with self.assertRaisesRegex(ValueError, "real_dependency_preflight_required"):
                        prepare(
                            root / f"packet-{index}",
                            root / "unused-refresh.json",
                            commit="c" * 40,
                            preflight=None,
                        )

    def test_prepare_records_exact_host_preflight_replacement(self):
        from inference_platform import package_a_operator as operator

        expected = {
            "status": "REPLACED_BY_HOST_CHECKS",
            "host_checks": ["race", "e2e", "row5"],
            "authority": "Claude Round 290 (DEC-041/DEC-087; DEC-093 note)",
        }
        refresh_value = {
            "instance_type": "c6i.2xlarge",
            "memory_mib": 16384,
            "vcpus": 8,
            "ami": "ami-0123456789abcdef0",
            "availability_zones": ["us-east-1a"],
            "standard_vcpu_quota": 8,
            "active_instance_count": 0,
            "image_bytes": {"node": 1, "python": 1},
            "observed_export_bytes": 1,
            "on_demand_usd_per_hour": 0.34,
            "ipv4_usd_per_hour": 0.005,
            "gp3_usd_per_gib_month": 0.08,
            "account_id_sha256": "a" * 64,
        }

        def fake_git(*argv, repo=operator.ROOT):
            if argv[:2] == ("bundle", "create"):
                Path(argv[2]).write_bytes(b"test-bundle")
            if argv[:2] == ("ls-tree", "-rl"):
                return b"100644 blob " + b"b" * 40 + b" 1024\tpython/example.py\n"
            if argv[:2] == ("rev-parse", "HEAD"):
                return b"c" * 40
            return b""

        def fake_run_exe(_argv, *, output, **_kwargs):
            output = Path(output)
            if output.name == "terraform-version.log":
                output.write_text('{"terraform_version":"1.16.2"}', encoding="utf-8")
            else:
                output.write_text("ok", encoding="utf-8")
            return {"log_sha256": "d" * 64}

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            refresh = root / "refresh.json"
            refresh.write_text(json.dumps(refresh_value), encoding="utf-8")

            def fake_seal(packet):
                operator.save(
                    Path(packet) / "sealed-plans.json",
                    {"create_sha256": "e" * 64, "destroy_sha256": "f" * 64},
                )

            with (
                patch.object(operator, "TASK_CHECKS", ("race", "e2e", "row5")),
                patch.object(operator, "git", side_effect=fake_git),
                patch.object(operator, "python_hashes", return_value={"python/a.py": "a" * 64}),
                patch.object(
                    operator,
                    "timing_worksheet",
                    return_value={"cost_hours": 0.1, "cost_guard_margin_s": 600},
                ),
                patch.object(operator, "validate_host_refresh"),
                patch.object(operator, "sealed_plans", side_effect=fake_seal),
                patch.object(operator, "run_exe", side_effect=fake_run_exe),
                patch.object(operator, "sha", return_value="c" * 64),
                patch.object(operator.shutil, "which", return_value="aws"),
                patch.object(Path, "is_file", return_value=True),
            ):
                manifest = operator.prepare(root / "packet", refresh, commit="c" * 40)

            self.assertEqual(manifest["local_real_dependency_preflight"], expected)
            self.assertEqual(manifest["hard_cap_usd"], cloud.CAP_USD)
            self.assertLess(manifest["cumulative_cost_usd"], cloud.CAP_USD)
            self.assertEqual(
                json.loads((root / "packet" / "manifest.json").read_bytes())[
                    "local_real_dependency_preflight"
                ],
                expected,
            )

    def test_prepare_supplied_preflight_still_validates_receipt(self):
        from inference_platform.package_a_operator import prepare

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipt = root / "preflight.json"
            receipt.write_text("{}", encoding="utf-8")
            with patch("inference_platform.package_a_operator.ROOT", root):
                with self.assertRaisesRegex(ValueError, "workload_preflight_incomplete"):
                    prepare(
                        root / "packet",
                        root / "unused-refresh.json",
                        commit="c" * 40,
                        preflight=receipt,
                    )

    def test_exact_gates_boundary_and_combined_limit_plus_reserve(self):
        self.assertEqual(
            [x[1] for x in CHECKS],
            [9123, 2304, 2560, 2560, 6656, 6656, 14336, 9123],
        )
        for name, minimum, combined, _ in CHECKS:
            with self.subTest(name=name):
                self.assertFalse(gate(sample(minimum * 1024**2 - 1), minimum, combined))
                self.assertTrue(gate(sample(minimum * 1024**2), minimum, combined))
        wrong = sample(32 * GIB)
        wrong["vm"]["MemAvailable"] = 7 * GIB
        self.assertFalse(gate(wrong, 14336, 12288))

    def test_meminfo_raw_timestamp_and_identical_linux_host_vm_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "meminfo"
            path.write_text("MemTotal: 33554432 kB\nMemAvailable: 12000000 kB\n")
            result = memory_sample(path)
            self.assertEqual(result["host"], result["vm"])
            self.assertEqual(result["host"]["MemAvailable"], 12000000 * 1024)
            self.assertEqual(result["raw_proc_meminfo"], path.read_text())
            self.assertIn("+00:00", result["sampled_at_utc"])
            path.write_text("MemTotal: 1 kB\n")
            with self.assertRaises(ValueError):
                memory_sample(path)

    def test_fault_matrix_always_retrieves_then_tears_down_and_inventories(self):
        receipts = {}
        for fault in (
            "none",
            "gate",
            "check",
            "lost_ssm",
            "deadline",
            "cap",
            "lost_apply",
            "retrieve",
            "teardown",
        ):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                clock = Clock()
                ports = FaultPorts(clock, fault)
                result = Lifecycle(
                    ports, {"cleanup_cost_reserve_usd": 1}, directory, clock=clock
                ).run()
                self.assertEqual(ports.calls[-3:], ["retrieve", "teardown", "inventory"])
                self.assertFalse(ports.active)
                self.assertEqual(result["deadline_epoch"], 1000 + DEADLINE_S)
                self.assertTrue(result["inventory"]["empty"])
                self.assertIn("task_cost_usd", result)
                self.assertIn("cumulative_cost_usd", result)
                self.assertNotIn("cost_usd_including_failed_work", result)
                if fault == "none":
                    self.assertTrue(result["complete"])
                    self.assertEqual(result["task_cost_usd"], 1)
                    self.assertEqual(result["cumulative_cost_usd"], 6)
                else:
                    self.assertFalse(result["complete"], fault)
                if fault in {"check", "lost_ssm"}:
                    self.assertEqual(result["retrieve"]["existing"], ["native", "smoke"])
                if fault in {"deadline", "cap", "lost_apply"}:
                    self.assertNotIn("run_checks", ports.calls)
                receipts[fault] = result
        evidence = os.environ.get("DEC077_FAULT_OUTPUT")
        if evidence:
            save(evidence, receipts)

    def test_r323_complete_allows_under_cap_after_42_hours_with_reserve_spent_in_cleanup(self):
        class CleanupElapsedPorts(FaultPorts):
            def __init__(self, clock):
                super().__init__(clock, "none")
                self.billing_origin = clock.now

            def task_cost(self, start, now):
                return 1 + (now - start) / 3600 * 0.39611111111111114

            def cumulative_cost(self, start, now):
                return cloud.CAP_USD - 3.66471995 + self.task_cost(start, now)

            def run_checks(self, end):
                self.calls.append("run_checks")
                self.clock.now = self.billing_origin + 4.1 * 3600

            def retrieve(self, end):
                self.calls.append("retrieve")
                self.clock.now = self.billing_origin + 4.3 * 3600
                return {"complete": True}

            def teardown(self, end):
                self.calls.append("teardown")
                self.clock.now = self.billing_origin + 4.4 * 3600
                self.active = False
                return {"destroy_completed": True}

            def inventory(self, end):
                self.calls.append("inventory")
                self.clock.now = self.billing_origin + 4.5 * 3600
                return {"empty": True}

        clock = Clock()
        origin = clock.now
        ports = CleanupElapsedPorts(clock)
        with tempfile.TemporaryDirectory() as directory:
            result = Lifecycle(ports, {"cleanup_cost_reserve_usd": 1}, directory, clock=clock).run()

        elapsed_s = clock.now - origin
        self.assertGreater(elapsed_s, 4.2 * 3600)
        self.assertLess(elapsed_s, 6 * 3600)
        self.assertLess(result["cumulative_cost_usd"], cloud.CAP_USD)
        self.assertGreaterEqual(result["cumulative_cost_usd"] + 1, cloud.CAP_USD)
        self.assertTrue(result["complete"])

    def test_r323_run_checks_stops_on_cumulative_guard_on_second_poll(self):
        from inference_platform import package_a_operator as operator

        ports = Ports.__new__(Ports)
        ports.started = 100
        ports.manifest = {"cleanup_cost_reserve_usd": 1}
        costs = iter((cloud.CAP_USD - 1.01, cloud.CAP_USD - 1.0))
        cost_polls = []

        def cumulative_cost(start, now):
            cost_polls.append((start, now))
            return next(costs)

        ports.cumulative_cost = cumulative_cost
        ports.task_cost = lambda start, now: 0.5
        status_polls = []

        def request(path, data=None, headers=None, *, end):
            if path == "/start":
                return b"{}", {}
            if path == "/status":
                status_polls.append(path)
                return b'{"runner_exit":null}', {}
            raise AssertionError(f"unexpected request path: {path}")

        ports.request = request
        time_values = iter((101.0, 101.5, 102.0, 102.5, 201.0))

        def fake_time():
            return next(time_values, 201.0)

        with (
            patch.object(operator.time, "time", side_effect=fake_time),
            patch.object(operator.time, "sleep"),
        ):
            with self.assertRaisesRegex(RuntimeError, "^cost_cap_during_run$"):
                ports.run_checks(200)

        self.assertEqual(len(cost_polls), 2)
        self.assertEqual(len(status_polls), 1)

    def test_r327_cleanup_crosses_cumulative_cap_and_complete_is_false(self):
        class CleanupOverCap(FaultPorts):
            def cumulative_cost(self, start, now):
                return cloud.CAP_USD - 1.01 + (now - start) / 200

            def retrieve(self, end):
                self.clock.now += 200
                return super().retrieve(end)

            def teardown(self, end):
                self.clock.now += 200
                return super().teardown(end)

        clock = Clock()
        ports = CleanupOverCap(clock, "none")
        with tempfile.TemporaryDirectory() as directory:
            result = Lifecycle(ports, {"cleanup_cost_reserve_usd": 1}, directory, clock=clock).run()
        self.assertNotIn("halt", result)
        self.assertEqual(ports.calls[-3:], ["retrieve", "teardown", "inventory"])
        self.assertTrue(result["retrieve"]["complete"])
        self.assertTrue(result["teardown"]["destroy_completed"])
        self.assertTrue(result["inventory"]["empty"])
        self.assertGreater(result["cumulative_cost_usd"], cloud.CAP_USD)
        self.assertFalse(result["complete"])

    def test_r327_ssm_registration_reserves_cleanup_at_threshold(self):
        from inference_platform import package_a_operator as operator

        for delta, expected_polls in ((0, 1), (-0.01, 2)):
            with self.subTest(delta=delta):
                ports = Ports.__new__(Ports)
                ports.host = "i-fixture"
                ports.started = 100
                ports.manifest = {"cleanup_cost_reserve_usd": 1}
                polls = []

                def aws(*args, polls=polls):
                    polls.append(args)
                    return {"InstanceInformationList": []}

                ports.aws = aws
                costs = iter((cloud.CAP_USD - 1 + delta, cloud.CAP_USD - 1))
                ports.cumulative_cost = lambda *args, costs=costs: next(costs)
                ports.task_cost = lambda *args: 0.1
                with (
                    patch.object(operator.time, "time", return_value=101),
                    patch.object(
                        operator.time,
                        "sleep",
                        side_effect=[None, AssertionError("guard missed threshold")],
                    ),
                    self.assertRaisesRegex(RuntimeError, "^cost_cap_during_ssm_registration$"),
                ):
                    ports.bootstrap(1000)
                self.assertEqual(len(polls), expected_polls)

    def test_transfer_timeout_uses_actual_bytes_and_one_retry(self):
        self.assertEqual(transfer_seconds(139225436), 618)
        self.assertEqual(transfer_seconds(EXPORT_MAX_BYTES), 196)
        with self.assertRaises(ValueError):
            transfer_seconds(-1)

    def test_real_child_exit_failure_and_timeout_are_captured(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_exe(
                [sys.executable, "-c", "print('actual executable')"],
                cwd=root,
                output=root / "ok.log",
                timeout=10,
            )
            self.assertIn("actual executable", (root / "ok.log").read_text())
            with self.assertRaises(RuntimeError):
                run_exe(
                    [sys.executable, "-c", "raise SystemExit(7)"],
                    cwd=root,
                    output=root / "bad.log",
                    timeout=10,
                )
            with self.assertRaises(subprocess.TimeoutExpired):
                run_exe(
                    [sys.executable, "-c", "import time; time.sleep(60)"],
                    cwd=root,
                    output=root / "timeout.log",
                    timeout=0.1,
                )

    def test_source_binding_checks_entire_python_inventory_and_head(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            (root / "python").mkdir()
            (root / "python/a.py").write_text("original\n")
            subprocess.run(["git", "-C", str(root), "add", "python"], check=True)
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(root),
                    "-c",
                    "user.name=fixture",
                    "-c",
                    "user.email=fixture@invalid",
                    "commit",
                    "-qm",
                    "fixture",
                ],
                check=True,
            )
            head = (
                subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"])
                .decode()
                .strip()
            )
            hashes = {"python/a.py": sha(root / "python/a.py")}
            self.assertEqual(verified_source(root, head, hashes)["python_files"], 1)
            (root / "python/a.py").write_text("changed\n")
            with self.assertRaisesRegex(ValueError, "bytes_mismatch"):
                verified_source(root, head, hashes)
            with self.assertRaisesRegex(ValueError, "head_mismatch"):
                verified_source(root, "0" * 40, hashes)

    def test_committed_marker_missing_duplicate_wrong_hash_and_consumed_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "terraform").mkdir()
            (root / "terraform/create.tfplan").write_bytes(b"fixture plan")
            (root / "manifest.json").write_bytes(b"fixture manifest")
            manifest = {
                "source_commit": "a" * 40,
                "sealed_plans": {"create_sha256": sha(root / "terraform/create.tfplan")},
            }
            prefix = "- DEC-077 " + "CPU PLAN APPROVED"
            marker = f"{prefix} {manifest['sealed_plans']['create_sha256']} {sha(root / 'manifest.json')} {'a' * 40}"
            committed = subprocess.check_output(
                ["git", "show", "HEAD:REVIEW.md"], cwd=ROOT
            ).decode()
            heading = "### Round 9999\n- Review basis: COMMITTED\n- Verdict: NO_BLOCKING_FINDINGS\n"

            def insert(block):
                return committed.replace("\n## Findings\n", "\n" + block + "\n## Findings\n", 1)

            review = insert(heading + marker + "\n")
            with patch("inference_platform.package_a_operator.git", return_value=review.encode()):
                require_marker(root, manifest)
            historical = re.findall(
                rf"(?m)^{re.escape(prefix)} ([0-9a-f]{{64}}) ([0-9a-f]{{64}}) ([0-9a-f]{{40}})$",
                committed,
            )
            self.assertTrue(historical, "the committed Round 227 marker is the history fixture")
            replay = insert(heading + f"{prefix} {' '.join(historical[0])}\n")
            with self.assertRaisesRegex(ValueError, "exact_plan_marker"):
                validate_review_marker(replay, historical[0])
            for bad in (
                review.replace(marker, ""),
                review.replace(marker, marker + "\n" + marker),
                insert(heading + marker + "\n" + marker + "\n"),
                insert(
                    "### Round 9998\n- Review basis: COMMITTED\n"
                    "- Verdict: NO_BLOCKING_FINDINGS\n" + marker + "\n" + heading + marker + "\n"
                ),
                committed + "\n## Codex handoff\nTask: fixture\n" + marker + "\n",
                review + "\n## Codex handoff\n" + marker + "\n",
                review.replace(marker, marker + "wrong"),
                review.replace("COMMITTED", "PROVISIONAL"),
                insert(
                    heading.replace("NO_BLOCKING_FINDINGS", "CHANGES_REQUESTED") + marker + "\n"
                ),
                insert(
                    heading
                    + marker
                    + "\n### Round 10000\n- Review basis: COMMITTED\n- Verdict: NO_BLOCKING_FINDINGS\n"
                ),
                committed
                + "\n## Codex handoff\n"
                + heading.replace("### Round 9999\n", "")
                + marker
                + "\n",
                committed
                + "\n#### Round 10000 — Codex response\n"
                + heading.replace("### Round 9999\n", "")
                + marker
                + "\n",
                insert(heading + "Quoted in prose: `" + marker + "`\n"),
            ):
                with (
                    self.subTest(bad=bad),
                    patch("inference_platform.package_a_operator.git", return_value=bad.encode()),
                ):
                    with self.assertRaises(ValueError):
                        require_marker(root, manifest)
            (root / "consumed.json").touch()
            with patch("inference_platform.package_a_operator.git", return_value=review.encode()):
                with self.assertRaisesRegex(ValueError, "already_consumed"):
                    require_marker(root, manifest)

    def assert_timing_policy(self, module):
        self.assertEqual(module.DEADLINE_S, 21600)
        self.assertEqual(module.HOST_TIMER_S, module.DEADLINE_S - 600)
        worksheet = module.timing_worksheet(139300866, hourly_all_resources_usd=0.4)
        self.assertEqual(worksheet["deadline_seconds"], module.DEADLINE_S)
        self.assertEqual(worksheet["host_timer_seconds"], module.HOST_TIMER_S)
        self.assertEqual(worksheet["cost_hours"], module.DEADLINE_S / 3600)
        self.assertGreaterEqual(worksheet["sizing_timeout_s"], 1.3 * 5533)
        self.assertLessEqual(worksheet["forecast_wall_s"], module.DEADLINE_S)

    def test_timing_single_origin_and_three_policy_mutants(self):
        self.assert_timing_policy(cloud)
        self.assertIn("+21000)", render_user_data())
        template = (ROOT / "infra/terraform/package_a/main.tf").read_text()
        self.assertIn("host_timer_seconds = var.host_timer_seconds", template)
        for before, after in (
            ("DEADLINE_S = 21_600", "DEADLINE_S = 14_400"),
            ("HOST_TIMER_S = DEADLINE_S - APPLY_S", "HOST_TIMER_S = 13800"),
            ('"cost_hours": DEADLINE_S / 3600', '"cost_hours": 4'),
        ):
            with self.subTest(mutant=after):
                source = inspect.getsource(cloud)
                self.assertIn(before, source)
                namespace = {
                    "__name__": "inference_platform.policy_mutant",
                    "__package__": "inference_platform",
                }
                exec(
                    compile(source.replace(before, after, 1), "policy_mutant.py", "exec"), namespace
                )
                from types import SimpleNamespace

                with self.assertRaises((AssertionError, ValueError)):
                    self.assert_timing_policy(SimpleNamespace(**namespace))

    def test_admission_budgets_equal_actual_call_timeout_sums(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = Runner(
                ROOT,
                Path(directory) / "out",
                {
                    "checks": [row[0] for row in CHECKS],
                    "python_executable": sys.executable,
                    "pins": {
                        "python_image": "pinned",
                        "redis_image": "redis",
                        "node_image": "node",
                    },
                },
            )
            for name in CALL_TIMEOUTS:
                runner.manifest["checks"] = [name]
                runner.manifest["source_commit"] = "a" * 40
                runner.receipt["host"] = {"instance_type": "fixture"}
                observed = []

                def execute(argv, observed=observed, **kwargs):
                    observed.append(kwargs["timeout"])
                    log = Path(kwargs["output"])
                    if log.stem == "capture":
                        native = {
                            "source_commit": "a" * 40,
                            "elapsed_seconds": 1.0,
                            "monotonic_start_ns": 0,
                            "monotonic_end_ns": 1000000000,
                            "capture_reuse_scope": "sanitized_campaign only; excludes staging, source checks, transfer and readback",
                        }
                        save(runner.output / "sizing-native.json", native)
                        save(
                            runner.output / "capture.json",
                            {
                                "status": "PASS",
                                "compute_s": 1.0,
                                "source": {"source_commit": "a" * 40},
                                "staging": {"verified": True},
                                "monotonic_start_ns": 0,
                                "monotonic_end_ns": 1000000000,
                                "native_receipt_sha256": sha(runner.output / "sizing-native.json"),
                            },
                        )
                    log.write_text(
                        "memory.max differs from manifest"
                        if "smoke-mismatch" in log.name
                        else "Ran 1 test in 0.001s\n\nOK\n"
                        if log.stem == "e2e"
                        else "Ran 1 test in 0.001s\n\nOK\n"
                        if log.stem == "row5-diagnostic-real-redis"
                        else "Ran 1 test in 0.001s\n\nOK\n"
                        if log.stem in {"row5-linux-suites", "row5-native-suites"}
                        else "\n".join(
                            f"--- PASS: {name} (0.00s)"
                            for name in (
                                "TestRedisDynamicCapacityPhases",
                                "TestRedisDynamicMutationSelfCheck",
                                "TestRedisCoordinatorWithheldMarkerBlocksRestoration",
                            )
                        )
                        if log.stem == "race"
                        else ""
                        if log.stem == "constrained-remaining"
                        else ""
                        if log.stem == "row5-linux-suites-remaining"
                        else '{"OOMKilled":false,"ExitCode":0}'
                        if log.stem == "constrained-inspect_state"
                        else '{"tokenizer_available":true,"probe_tokens":34,"uid":65532}'
                        if log.stem == "fake-tokenizer-self-test"
                        else "[]"
                    )
                    return {"log": log.name, "exit": 0}

                runner.execute = execute
                if name == "prepare_images":
                    runner.prepare_images()
                elif name == "row5":
                    with patch(
                        "inference_platform.package_a_cloud.shutil.which",
                        return_value="/usr/bin/git",
                    ):
                        runner.check(name)
                else:
                    runner.check(name)
                self.assertEqual(tuple(observed), CALL_TIMEOUTS[name], name)
                self.assertEqual(sum(observed), BUDGETS[name], name)

    def test_r308_go_summary_refuses_indented_subtest_skips(self):
        from inference_platform.package_a_go import GoTestSummaryError, go_test_summary

        log = (
            "--- PASS: TestRedisDynamicCapacityPhases (0.01s)\n"
            "    --- PASS: TestRedisDynamicCapacityPhases/healthy (0.00s)\n"
            "    --- SKIP: TestRedisDynamicCapacityPhases/no_redis (0.00s)\n"
            "--- PASS: TestRedisDynamicMutationSelfCheck (0.01s)\n"
            "--- PASS: TestRedisCoordinatorWithheldMarkerBlocksRestoration (0.01s)\n"
        )
        with self.assertRaisesRegex(GoTestSummaryError, "go_test_skipped_tests:1") as raised:
            go_test_summary(log)
        self.assertEqual(raised.exception.summary["passed_tests"], 4)
        self.assertEqual(raised.exception.summary["skipped_tests"], 1)

    def test_r308_host_race_uses_verbose_shared_summary_in_its_receipt(self):
        from inference_platform.package_a_go import REAL_REDIS_EXPECTED_TESTS

        with tempfile.TemporaryDirectory() as directory:
            runner = Runner(
                ROOT,
                Path(directory) / "out",
                {
                    "checks": [row[0] for row in CHECKS],
                    "python_executable": sys.executable,
                    "pins": {"python_image": "pinned", "redis_image": "redis"},
                },
            )
            observed = []

            def call(argv, name, **kwargs):
                observed.append((argv, name, kwargs))
                log = runner.output / (name + ".log")
                if name == "race":
                    self.assertIn("-v", argv)
                    log.write_text(
                        "".join(f"--- PASS: {test} (0.00s)\n" for test in REAL_REDIS_EXPECTED_TESTS)
                    )
                else:
                    log.write_text("ready\n")
                return {"log": log.name, "exit": 0, "log_sha256": sha(log)}

            runner.call = call
            runner.check("race")
            self.assertEqual(runner.receipt["go_real_redis_race"]["passed_tests"], 3)
            self.assertEqual(runner.receipt["go_real_redis_race"]["skipped_tests"], 0)
            self.assertTrue(runner.receipt["go_real_redis_race"]["complete"])
            self.assertEqual(
                [step[1] for step in observed],
                ["race-redis", "race-redis-ready", "race", "race-redis-remove"],
            )

    def test_prepare_images_has_memory_and_deadline_admission(self):
        for available, deadline, expected in (
            (32 * GIB, 0, "SKIPPED_DEADLINE"),
            (0, time.time() + 30000, "SKIPPED_GATE"),
        ):
            with tempfile.TemporaryDirectory() as directory:
                runner = Runner(
                    ROOT,
                    Path(directory) / "out",
                    {
                        "checks": [row[0] for row in CHECKS],
                        "python_executable": sys.executable,
                        "pins": {"python_image": "p"},
                        "source_commit": "fixture",
                        "python_sha256": {},
                        "instance_type": "fixture",
                        "ami": "fixture",
                        "on_demand_usd_per_hour": 0,
                        "deadline_epoch": deadline,
                    },
                    sample=lambda available=available: sample(available),
                )
                runner.prepare_images = lambda: self.fail("inadmissible preparation executed")
                runner.check = lambda name: None
                with (
                    patch("inference_platform.package_a_cloud.verified_source", return_value={}),
                    patch(
                        "inference_platform.package_a_cloud.Path.read_text",
                        return_value="cpu memory",
                    ),
                ):
                    runner.run()
                self.assertEqual(runner.receipt["prepare_images"]["status"], expected)

    def test_kind_failure_keeps_600_second_budget_and_runner_continues(self):
        from inference_platform.package_a_cloud import KIND_RUNNER_TIMEOUT_S

        with tempfile.TemporaryDirectory() as directory:
            runner = Runner(
                ROOT,
                Path(directory) / "out",
                {
                    "checks": [row[0] for row in CHECKS],
                    "python_executable": sys.executable,
                    "pins": {"python_image": "pinned"},
                    "source_commit": "c" * 40,
                    "python_sha256": {},
                    "instance_type": "fixture",
                    "ami": "fixture",
                    "on_demand_usd_per_hour": 0,
                    "deadline_epoch": 2**31,
                },
                sample=lambda: sample(32 * GIB),
            )
            completed = []

            def check(name):
                completed.append(name)
                if name == "kind":
                    raise RuntimeError("kind diagnostic failure")

            runner.prepare_images = lambda: None
            runner.check = check
            with (
                patch("inference_platform.package_a_cloud.verified_source", return_value={}),
                patch(
                    "inference_platform.package_a_cloud.Path.read_text", return_value="cpu memory"
                ),
            ):
                self.assertFalse(runner.run())
            self.assertEqual(completed, [name for name, *_ in CHECKS])
            self.assertEqual(runner.receipt["checks"][4]["status"], "FAILED")
            self.assertEqual(runner.receipt["checks"][5]["status"], "PASS")
            self.assertEqual(CALL_TIMEOUTS["kind"], (600,))
            self.assertEqual(BUDGETS["kind"], 600)
            self.assertEqual(KIND_RUNNER_TIMEOUT_S, CALL_TIMEOUTS["kind"][0])
            self.assertEqual(KIND_RUNNER_TIMEOUT_S, BUDGETS["kind"])

    def test_row5_runs_linux_native_and_kind_suites_in_order(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = Runner(
                ROOT,
                Path(directory) / "out",
                {
                    "checks": ["row5"],
                    "python_executable": sys.executable,
                    "pins": {"python_image": "pinned", "redis_image": "redis"},
                },
            )
            calls = []

            def execute(argv, *, cwd, output, env, timeout, expected):
                output = Path(output)
                name = output.stem
                calls.append((name, argv, cwd, env, timeout, expected))
                output.write_text(
                    "Ran 1 test in 0.001s\n\nOK\n"
                    if name == "row5-diagnostic-real-redis"
                    else "Ran 2 tests in 0.001s\n\nOK\n"
                    if name in {"row5-linux-suites", "row5-native-suites"}
                    else "",
                    encoding="utf-8",
                )
                return {"log": output.name, "exit": 0, "log_sha256": "a" * 64}

            runner.execute = execute
            with patch(
                "inference_platform.package_a_cloud.shutil.which", return_value="/usr/bin/git"
            ):
                runner.check("row5")

            self.assertEqual(
                [row[0] for row in calls],
                [
                    "row5-diagnostic-binary-build",
                    "row5-diagnostic-redis-start",
                    "row5-diagnostic-redis-ready",
                    "row5-diagnostic-real-redis",
                    "row5-diagnostic-redis-remove",
                    "row5-linux-suites",
                    "row5-linux-suites-remove",
                    "row5-linux-suites-remaining",
                    "row5-native-suites",
                    "row5-kind",
                ],
            )
            self.assertEqual(
                [row[4] for row in calls],
                [
                    ROW5_KIND_DIAGNOSTIC_BUILD_TIMEOUT_S,
                    CALL_S,
                    METADATA_S,
                    ROW5_DIAGNOSTIC_INTEGRATION_TIMEOUT_S,
                    METADATA_S,
                    ROW5_SUITE_TIMEOUT_S,
                    METADATA_S,
                    METADATA_S,
                    ROW5_NATIVE_SUITE_TIMEOUT_S,
                    ROW5_KIND_TIMEOUT_S,
                ],
            )
            self.assertEqual(
                CALL_TIMEOUTS["row5"],
                (
                    ROW5_KIND_DIAGNOSTIC_BUILD_TIMEOUT_S,
                    CALL_S,
                    METADATA_S,
                    ROW5_DIAGNOSTIC_INTEGRATION_TIMEOUT_S,
                    METADATA_S,
                    ROW5_SUITE_TIMEOUT_S,
                    METADATA_S,
                    METADATA_S,
                    ROW5_NATIVE_SUITE_TIMEOUT_S,
                    ROW5_KIND_TIMEOUT_S,
                ),
            )
            self.assertEqual(calls[4][5], "any")
            self.assertEqual(calls[6][5], "any")
            self.assertEqual(calls[7][5], 0)
            self.assertEqual(
                set(ROW5_KIND_TIME_BOUNDS_S),
                {
                    "cluster_creation",
                    "cluster_name_probe",
                    "image_loads",
                    "three_scale_waits",
                    "gpu_release",
                    "restore_window",
                    "node_setup_commands",
                    "node_ready_wait",
                    "manifest_application_and_gateway_readiness",
                    "redis_rollout",
                    "operator_identity_and_api_discovery",
                    "diagnostic_build",
                    "port_forward_startup",
                    "port_forward_probe_slack",
                    "gateway_boot_probes",
                    "configuration_capture_window",
                    "six_live_stage_window",
                    "known_stage_diagnostic_calls",
                    "outage_diagnostic_calls",
                    "uncordon",
                    "hold_end_window",
                    "hold_end_final_poll_slack",
                    "restore_start_final_poll_slack",
                    "outage_sequence_window",
                    "outage_rbac_review_windows",
                    "cleanup_reserve",
                    "receipt_reserve",
                },
            )
            self.assertEqual(ROW5_KIND_CRITICAL_PATH_S, 6275.1)
            self.assertEqual(
                ROW5_READINESS_TIMEOUT_S,
                cloud.math.ceil(2 * cloud.PACKAGE_A_HOST_READY_MEASURED_S / 60) * 60,
            )
            self.assertEqual(
                ROW5_SUITE_TIMEOUT_S,
                cloud.math.ceil(5 * cloud.PACKAGE_A_KIND_MEASURED_S / 60) * 60,
            )
            self.assertEqual(
                ROW5_KIND_TIMEOUT_S,
                cloud.math.ceil(
                    (
                        ROW5_KIND_CRITICAL_PATH_S
                        + ROW5_KIND_TIME_BOUNDS_S["cleanup_reserve"]
                        + ROW5_KIND_TIME_BOUNDS_S["receipt_reserve"]
                    )
                    / 60
                )
                * 60,
            )
            self.assertEqual(ROW5_KIND_TIMEOUT_S, 6600)
            self.assertEqual(
                ROW5_KIND_CRITICAL_PATH_S
                + ROW5_KIND_TIME_BOUNDS_S["cleanup_reserve"]
                + ROW5_KIND_TIME_BOUNDS_S["receipt_reserve"],
                6595.1,
            )
            self.assertEqual(
                BUDGETS["row5"],
                ROW5_KIND_DIAGNOSTIC_BUILD_TIMEOUT_S
                + CALL_S
                + 2 * METADATA_S
                + ROW5_DIAGNOSTIC_INTEGRATION_TIMEOUT_S
                + ROW5_SUITE_TIMEOUT_S
                + 2 * METADATA_S
                + ROW5_NATIVE_SUITE_TIMEOUT_S
                + ROW5_KIND_TIMEOUT_S,
            )
            diagnostic_argv = calls[3][1]
            self.assertIn("--network", diagnostic_argv)
            self.assertEqual(diagnostic_argv[diagnostic_argv.index("--network") + 1], "host")
            self.assertIn("REDIS_TEST_ADDR=127.0.0.1:26379", diagnostic_argv)
            self.assertIn("ROW5_DIAGNOSTIC_BIN=/diagnostic/row5-diagnostic", diagnostic_argv)
            self.assertIn(
                "test_inf037b_row5_diagnostic",
                diagnostic_argv,
            )
            suite_argv = calls[5][1]
            self.assertEqual(suite_argv[:3], ["docker", "run", "--rm"])
            suite_container_name = runner.container_name + "-row5-suites"
            self.assertEqual(suite_argv[suite_argv.index("--name") + 1], suite_container_name)
            self.assertEqual(calls[6][1], ["docker", "rm", "-f", suite_container_name])
            self.assertEqual(
                calls[7][1],
                [
                    "docker",
                    "ps",
                    "-aq",
                    "--filter",
                    "name=^/" + suite_container_name + "$",
                ],
            )
            self.assertIn("--network", suite_argv)
            self.assertIn("none", suite_argv)
            self.assertIn("6656m", suite_argv)
            self.assertIn("type=bind,source=" + str(ROOT) + ",target=/repo,readonly", suite_argv)
            self.assertIn(runner.image, suite_argv)
            self.assertIn(
                "test_inf037b_row5_capture.DiagnosticSnapshotControlTests.test_refuses_mismatched_result_snapshot_gap_overlap_and_release",
                suite_argv,
            )
            self.assertIn("test_inf037b_row5_kind", suite_argv)
            self.assertIn(
                "test_package_a_cloud.PackageACloudTests.test_row5_runs_linux_native_and_kind_suites_in_order",
                suite_argv,
            )
            self.assertIn("test_package_a_kind_readiness", suite_argv)
            self.assertIn("scripts.tests.test_rehearse_row5_kind", suite_argv)
            self.assertIn("test_rehearse_eks_package_a", suite_argv)
            native_argv = calls[8][1]
            self.assertEqual(
                native_argv,
                [
                    sys.executable,
                    "-m",
                    "unittest",
                    "-v",
                    "test_rehearse_eks_package_a",
                    "test_package_a_cloud",
                ],
            )
            self.assertEqual(calls[8][2], ROOT)
            self.assertEqual(
                calls[8][3],
                {
                    "PATH": "/usr/bin:/bin",
                    "HOME": str(runner.output / "row5-native-home"),
                    "LANG": "C.UTF-8",
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "PYTHONPATH": f"{ROOT / 'python/src'}:{ROOT / 'python/tests'}",
                },
            )
            self.assertEqual(list((runner.output / "row5-native-home").iterdir()), [])
            self.assertEqual(calls[9][5], 0)
            self.assertEqual(calls[9][1][0], sys.executable)
            self.assertIn("scripts/rehearse_row5_kind.py", calls[9][1])
            self.assertEqual(
                calls[9][1][calls[9][1].index("--readiness-timeout") + 1],
                str(ROW5_READINESS_TIMEOUT_S),
            )
            self.assertEqual(
                calls[9][1][calls[9][1].index("--runner-timeout") + 1],
                str(ROW5_KIND_TIMEOUT_S),
            )
            self.assertEqual(runner.receipt["row5"]["linux_suites"]["status"], "PASS")
            self.assertEqual(runner.receipt["row5"]["diagnostic_real_redis"]["status"], "PASS")
            self.assertEqual(runner.receipt["row5"]["linux_suites"]["tests_run"], 2)
            self.assertEqual(runner.receipt["row5"]["linux_suites"]["skipped"], 0)
            self.assertEqual(
                runner.receipt["row5"]["linux_suites"]["container_cleanup"],
                {"remove_exit": 0, "remaining": ""},
            )
            self.assertEqual(runner.receipt["row5"]["native_suites"]["status"], "PASS")
            self.assertEqual(runner.receipt["row5"]["native_suites"]["tests_run"], 2)
            self.assertEqual(runner.receipt["row5"]["native_suites"]["skipped"], 0)
            self.assertEqual(runner.receipt["row5"]["kind_rehearsal"]["status"], "PASS")

    def test_row5_suite_log_validator_uses_real_verbose_unittest_logs(self):
        from inference_platform.package_a_cloud import validate_row5_suite_log

        cases = (
            (
                "passing",
                "import unittest\n"
                "class Cases(unittest.TestCase):\n"
                "    def test_skipped_name_only(self): self.assertTrue(True)\n"
                "    def test_second(self): self.assertTrue(True)\n",
                0,
                None,
            ),
            (
                "skipped",
                "import unittest\n"
                "class Cases(unittest.TestCase):\n"
                "    @unittest.skip('fixture skip')\n"
                "    def test_one(self): self.fail('unreachable')\n",
                0,
                "row5_suite_log_skipped",
            ),
            (
                "failing",
                "import unittest\n"
                "class Cases(unittest.TestCase):\n"
                "    def test_one(self): self.fail('fixture failure')\n",
                "refuse",
                "row5_suite_log_not_final_ok",
            ),
            (
                "empty",
                "import unittest\nclass NoTests(unittest.TestCase): pass\n",
                "refuse",
                "row5_suite_log_zero_tests",
            ),
        )
        for name, source, expected_exit, refusal in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                log, result = run_real_unittest_module(
                    root, "case_" + name, source, expected=expected_exit
                )
                self.assertIn("-m", result["argv"])
                self.assertIn("unittest", result["argv"])
                self.assertIn("-v", result["argv"])
                text = log.read_text(encoding="utf-8")
                self.assertRegex(text, r"(?m)^Ran \d+ tests? in \d+(?:\.\d+)?s$")
                if refusal is None:
                    self.assertEqual(validate_row5_suite_log(log), {"tests_run": 2, "skipped": 0})
                    self.assertEqual(
                        validate_row5_suite_log(log, expected_tests=2),
                        {"tests_run": 2, "skipped": 0},
                    )
                    with self.assertRaisesRegex(ValueError, "row5_suite_log_unexpected_test_count"):
                        validate_row5_suite_log(log, expected_tests=1)
                    text_without_ran = "\n".join(
                        line for line in text.splitlines() if not line.startswith("Ran ")
                    )
                    malformed = root / "missing-ran.log"
                    malformed.write_text(text_without_ran, encoding="utf-8")
                    with self.assertRaisesRegex(ValueError, "row5_suite_log_missing_ran"):
                        validate_row5_suite_log(malformed)
                else:
                    if name == "skipped":
                        self.assertIn("OK (skipped=1)", text)
                    with self.assertRaisesRegex(ValueError, refusal):
                        validate_row5_suite_log(log)

                if name == "skipped":
                    summary_only = root / "summary-skipped.log"
                    summary_only.write_text(
                        "Ran 1 test in 0.001s\n\nOK (skipped=1)\n", encoding="utf-8"
                    )
                    with self.assertRaisesRegex(ValueError, "row5_suite_log_not_final_ok"):
                        validate_row5_suite_log(summary_only)

    def test_row5_diagnostic_accepts_passing_test_name_containing_skipped(self):
        from inference_platform.package_a_cloud import sha

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_log, _ = run_real_unittest_module(
                root,
                "diagnostic_fixture",
                "import unittest\n"
                "class Cases(unittest.TestCase):\n"
                "    def test_route_is_not_skipped_when_valid(self): self.assertTrue(True)\n",
            )
            runner = Runner(
                ROOT,
                root / "runner-output",
                {
                    "checks": ["row5"],
                    "python_executable": sys.executable,
                    "pins": {"python_image": "pinned", "redis_image": "redis"},
                },
            )

            def fake_call(_argv, name, **_kwargs):
                log = runner.output / (name + ".log")
                if name == "row5-diagnostic-real-redis":
                    log.write_bytes(source_log.read_bytes())
                else:
                    log.write_text("", encoding="utf-8")
                return {"log": log.name, "exit": 0, "log_sha256": sha(log)}

            runner.call = fake_call
            receipt = runner.row5_diagnostic_real_redis()

        self.assertEqual(receipt["status"], "PASS")
        self.assertEqual(receipt["tests"], 1)
        self.assertEqual(receipt["skipped"], 0)

    def test_e2e_accepts_passing_test_name_containing_skipped(self):
        from inference_platform.package_a_cloud import sha

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_log, _ = run_real_unittest_module(
                root,
                "e2e_fixture",
                "import unittest\n"
                "class Cases(unittest.TestCase):\n"
                "    def test_gateway_is_not_skipped_when_valid(self): self.assertTrue(True)\n",
            )
            runner = Runner(
                ROOT,
                root / "runner-output",
                {
                    "checks": ["e2e"],
                    "python_executable": sys.executable,
                    "pins": {"python_image": "pinned", "redis_image": "redis"},
                },
            )

            def fake_call(_argv, name, **_kwargs):
                log = runner.output / (name + ".log")
                if name == "e2e":
                    log.write_bytes(source_log.read_bytes())
                else:
                    log.write_text("", encoding="utf-8")
                return {"log": log.name, "exit": 0, "log_sha256": sha(log)}

            runner.call = fake_call
            runner.check("e2e")

    def test_row5_native_suite_refuses_when_host_git_is_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = Runner(
                ROOT,
                Path(directory) / "out",
                {
                    "checks": ["row5"],
                    "python_executable": sys.executable,
                    "pins": {"python_image": "pinned", "redis_image": "redis"},
                },
            )
            calls = []

            def call(_argv, name, **kwargs):
                calls.append(name)
                log = runner.output / (name + ".log")
                if name in {"row5-diagnostic-real-redis", "row5-linux-suites"}:
                    log.write_text("Ran 1 test in 0.001s\n\nOK\n", encoding="utf-8")
                else:
                    log.write_text("", encoding="utf-8")
                return {"log": log.name, "exit": 0, "log_sha256": "c" * 64}

            runner.call = call
            runner.execute = lambda *args, **kwargs: self.fail("native suite ran without host git")
            with patch("inference_platform.package_a_cloud.shutil.which", return_value=None):
                with self.assertRaisesRegex(ValueError, "row5_native_git_missing"):
                    runner.check("row5")

            self.assertEqual(
                calls,
                [
                    "row5-diagnostic-binary-build",
                    "row5-diagnostic-redis-start",
                    "row5-diagnostic-redis-ready",
                    "row5-diagnostic-real-redis",
                    "row5-diagnostic-redis-remove",
                    "row5-linux-suites",
                    "row5-linux-suites-remove",
                    "row5-linux-suites-remaining",
                    "row5-kind",
                ],
            )
            self.assertEqual(runner.receipt["row5"]["linux_suites"]["status"], "PASS")
            self.assertEqual(runner.receipt["row5"]["native_suites"]["status"], "FAILED")
            self.assertEqual(
                runner.receipt["row5"]["native_suites"]["refusal"], "row5_native_git_missing"
            )
            self.assertEqual(runner.receipt["row5"]["kind_rehearsal"]["status"], "PASS")

    def test_row5_linux_failure_still_records_native_suites_and_runs_kind(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = Runner(
                ROOT,
                Path(directory) / "out",
                {
                    "checks": ["row5"],
                    "python_executable": sys.executable,
                    "pins": {"python_image": "pinned", "redis_image": "redis"},
                },
            )
            calls = []

            def call(argv, name, **kwargs):
                calls.append(name)
                if name == "row5-diagnostic-real-redis":
                    log = runner.output / (name + ".log")
                    log.write_text("Ran 1 test in 0.001s\n\nOK\n", encoding="utf-8")
                    return {"log": log.name, "exit": 0, "log_sha256": "a" * 64}
                if name == "row5-linux-suites":
                    log = runner.output / "row5-linux-suites.log"
                    failed_tests = [
                        f"ERROR: test_inf037b_row5_kind.Case.test_failure_{index}"
                        for index in range(6)
                    ]
                    error_sections = []
                    for failed_test in failed_tests:
                        error_sections.extend(
                            [
                                "=" * 70,
                                failed_test,
                                "-" * 70,
                                "Traceback (most recent call last):",
                                '  File "test_inf037b_row5_kind.py", line 1, in test_failure',
                                "RuntimeError: fixture failure",
                                "",
                            ]
                        )
                    log.write_text(
                        "\n".join(
                            [
                                *error_sections,
                                "-" * 70,
                                "Ran 130 tests in 326.225s",
                                "",
                                "FAILED (errors=6)",
                            ]
                        )
                        + "\n",
                        encoding="utf-8",
                    )
                    save(
                        runner.output / "row5-linux-suites.command.json",
                        {"argv": argv, "exit": 1, "log": log.name},
                    )
                    raise RuntimeError("check_exit:row5-linux-suites.log:1")
                if name == "row5-linux-suites-remaining":
                    (runner.output / (name + ".log")).write_text("", encoding="utf-8")
                return {"log": name + ".log", "exit": 0, "log_sha256": "a" * 64}

            def execute(argv, *, output, **kwargs):
                calls.append(Path(output).stem)
                Path(output).write_text("Ran 1 test in 0.001s\n\nOK\n", encoding="utf-8")
                return {"log": Path(output).name, "exit": 0, "log_sha256": "b" * 64}

            runner.call = call
            runner.execute = execute
            with self.assertRaisesRegex(RuntimeError, "check_exit:row5-linux-suites"):
                with patch(
                    "inference_platform.package_a_cloud.shutil.which", return_value="/usr/bin/git"
                ):
                    runner.check("row5")

            self.assertEqual(
                calls,
                [
                    "row5-diagnostic-binary-build",
                    "row5-diagnostic-redis-start",
                    "row5-diagnostic-redis-ready",
                    "row5-diagnostic-real-redis",
                    "row5-diagnostic-redis-remove",
                    "row5-linux-suites",
                    "row5-linux-suites-remove",
                    "row5-linux-suites-remaining",
                    "row5-native-suites",
                    "row5-kind",
                ],
            )
            self.assertEqual(runner.receipt["row5"]["linux_suites"]["status"], "FAILED")
            self.assertEqual(
                runner.receipt["row5"]["linux_suites"]["summary"],
                {
                    "tests_run": 130,
                    "errors": 6,
                    "failures": 0,
                    "skipped": 0,
                    "failed_tests": [
                        f"test_inf037b_row5_kind.Case.test_failure_{index}" for index in range(6)
                    ],
                },
            )
            self.assertEqual(runner.receipt["row5"]["native_suites"]["status"], "PASS")
            self.assertEqual(runner.receipt["row5"]["native_suites"]["tests_run"], 1)
            self.assertEqual(runner.receipt["row5"]["kind_rehearsal"]["status"], "PASS")
            self.assertTrue((runner.output / "runner.json").is_file())

    def test_row5_timeout_still_removes_and_probes_suite_container(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = Runner(
                ROOT,
                Path(directory) / "out",
                {
                    "checks": ["row5"],
                    "python_executable": sys.executable,
                    "pins": {"python_image": "pinned", "redis_image": "redis"},
                },
            )
            calls = []

            def execute(argv, *, output, timeout, **kwargs):
                output = Path(output)
                name = output.stem
                calls.append((name, argv, timeout))
                if name == "row5-linux-suites":
                    output.write_text("partial suite output\n", encoding="utf-8")
                    raise subprocess.TimeoutExpired(argv, timeout)
                output.write_text(
                    "Ran 1 test in 0.001s\n\nOK\n"
                    if name in {"row5-diagnostic-real-redis", "row5-native-suites"}
                    else "",
                    encoding="utf-8",
                )
                return {"log": output.name, "exit": 0, "log_sha256": "d" * 64}

            runner.execute = execute
            with patch(
                "inference_platform.package_a_cloud.shutil.which", return_value="/usr/bin/git"
            ):
                with self.assertRaises(subprocess.TimeoutExpired):
                    runner.check("row5")

            self.assertEqual(
                [row[0] for row in calls],
                [
                    "row5-diagnostic-binary-build",
                    "row5-diagnostic-redis-start",
                    "row5-diagnostic-redis-ready",
                    "row5-diagnostic-real-redis",
                    "row5-diagnostic-redis-remove",
                    "row5-linux-suites",
                    "row5-linux-suites-remove",
                    "row5-linux-suites-remaining",
                    "row5-native-suites",
                    "row5-kind",
                ],
            )
            self.assertEqual(
                runner.receipt["row5"]["linux_suites"]["container_cleanup"],
                {"remove_exit": 0, "remaining": ""},
            )
            self.assertEqual(runner.receipt["row5"]["kind_rehearsal"]["status"], "PASS")

    def test_row5_remaining_suite_container_refuses_after_kind_runs(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = Runner(
                ROOT,
                Path(directory) / "out",
                {
                    "checks": ["row5"],
                    "python_executable": sys.executable,
                    "pins": {"python_image": "pinned", "redis_image": "redis"},
                },
            )
            calls = []

            def execute(argv, *, output, **kwargs):
                output = Path(output)
                name = output.stem
                calls.append(name)
                if name in {
                    "row5-diagnostic-real-redis",
                    "row5-linux-suites",
                    "row5-native-suites",
                }:
                    output.write_text("Ran 1 test in 0.001s\n\nOK\n", encoding="utf-8")
                elif name == "row5-linux-suites-remaining":
                    output.write_text("container-id\n", encoding="utf-8")
                else:
                    output.write_text("", encoding="utf-8")
                return {"log": output.name, "exit": 0, "log_sha256": "e" * 64}

            runner.execute = execute
            with patch(
                "inference_platform.package_a_cloud.shutil.which", return_value="/usr/bin/git"
            ):
                with self.assertRaisesRegex(ValueError, "row5_suite_container_remaining"):
                    runner.check("row5")

            self.assertEqual(
                calls,
                [
                    "row5-diagnostic-binary-build",
                    "row5-diagnostic-redis-start",
                    "row5-diagnostic-redis-ready",
                    "row5-diagnostic-real-redis",
                    "row5-diagnostic-redis-remove",
                    "row5-linux-suites",
                    "row5-linux-suites-remove",
                    "row5-linux-suites-remaining",
                    "row5-native-suites",
                    "row5-kind",
                ],
            )
            self.assertEqual(
                runner.receipt["row5"]["linux_suites"]["container_cleanup"],
                {"remove_exit": 0, "remaining": "container-id"},
            )
            self.assertEqual(runner.receipt["row5"]["kind_rehearsal"]["status"], "PASS")

    def test_token_is_persisted_private_and_recovery_never_mints_one(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(FileNotFoundError):
                control_token(root, create=False)
            token = control_token(root, create=True)
            self.assertEqual(control_token(root, create=False), token)
            self.assertEqual(control_token(root, create=True), token)
            if os.name != "nt":
                self.assertEqual((root / "control-token.secret").stat().st_mode & 0o777, 0o600)
                (root / "control-token.secret").chmod(0o644)
                with self.assertRaisesRegex(ValueError, "permissions"):
                    control_token(root, create=False)

    def test_aws_failures_and_ssm_tails_never_expose_control_token(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = {"session_manager_plugin_path": "fixture"}
            save(root / "manifest.json", manifest)
            ports = Ports(root, manifest)
            argv = ["aws", "--token", ports.token, "Bearer " + ports.token]
            for error in (
                subprocess.CalledProcessError(
                    254, argv, output=ports.token, stderr="Bearer secret"
                ),
                subprocess.TimeoutExpired(argv, 17, output=ports.token, stderr="Bearer secret"),
            ):
                with patch(
                    "inference_platform.r1_cloud_operator.subprocess.check_output",
                    side_effect=error,
                ):
                    with self.assertRaises(type(error)) as caught:
                        ports.aws("ssm", "send-command", ["--parameters", ports.token])
                sanitized = caught.exception
                self.assertEqual(sanitized.cmd, ["aws", "ssm", "send-command"])
                self.assertIsNone(sanitized.output)
                self.assertIsNone(sanitized.stderr)
                self.assertTrue(sanitized.__suppress_context__)
                self.assertEqual(
                    getattr(sanitized, "returncode", None), getattr(error, "returncode", None)
                )
                self.assertEqual(
                    getattr(sanitized, "timeout", None), getattr(error, "timeout", None)
                )
                rendered = "".join(traceback.format_exception(sanitized))
                self.assertNotIn(ports.token, rendered)
                self.assertNotIn("Bearer", rendered)
            self.assertNotIn(ports.token, ports.redact("unexpected echo: " + ports.token))

    def test_real_ports_ssm_retries_first_invocation_exit_254(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = {"session_manager_plugin_path": "fixture"}
            save(root / "manifest.json", manifest)
            ports = Ports(root, manifest)
            polls = []

            def cli(argv, **kwargs):
                if "send-command" in argv:
                    return b'{"Command":{"CommandId":"fixture"}}'
                polls.append(argv)
                if len(polls) == 1:
                    raise subprocess.CalledProcessError(
                        254, [*argv, "--token", ports.token], output="Bearer " + ports.token
                    )
                return b'{"Status":"Success"}'

            with (
                patch(
                    "inference_platform.r1_cloud_operator.subprocess.check_output", side_effect=cli
                ),
                patch("inference_platform.r1_cloud_operator.time.sleep"),
            ):
                self.assertEqual(
                    ports.ssm("i-fixture", ["--token " + ports.token])["Status"], "Success"
                )
            self.assertEqual(len(polls), 2)
            for path in root.rglob("*"):
                if path.is_file() and path.name != "control-token.secret":
                    self.assertNotIn(ports.token.encode(), path.read_bytes())
                    self.assertNotIn(b"Bearer", path.read_bytes())

    def test_retrieve_reachability_is_independent_of_six_hour_end(self):
        for answered in (False, True):
            with self.subTest(status_answered=answered), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                manifest = {"session_manager_plugin_path": "fixture"}
                save(root / "manifest.json", manifest)
                ports = Ports(root, manifest)
                ports.host = "i-fixture"
                if answered:
                    ports.remember_status()
                    self.assertTrue(Ports(root, manifest, recovering=True).status_answered)
                clock = Clock()
                ports.tunnel = lambda _: (_ for _ in ()).throw(ConnectionResetError("no agent"))
                with (
                    patch("inference_platform.package_a_operator.time.time", side_effect=clock),
                    patch(
                        "inference_platform.package_a_operator.time.sleep",
                        side_effect=lambda seconds, clock=clock: setattr(
                            clock, "now", clock.now + seconds
                        ),
                    ),
                ):
                    result = ports.retrieve(clock.now + DEADLINE_S - CLEANUP_S)
                self.assertEqual(result["status"], "unreachable")
                self.assertEqual(
                    result["reason"], "freeze_unanswered" if answered else "status_never_answered"
                )
                self.assertEqual(
                    result["elapsed_s"], transfer_seconds(EXPORT_MAX_BYTES) if answered else 0
                )
                self.assertEqual(
                    json.loads((ports.runtime / "retrieval.json").read_bytes()), result
                )

    def test_runner_check_commands_preserve_limits_and_mismatch_only_memory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = Runner(
                ROOT,
                root / "out",
                {
                    "checks": [row[0] for row in CHECKS],
                    "python_executable": sys.executable,
                    "pins": {"python_image": "pinned"},
                },
            )
            commands = []

            def call(argv, name, **kwargs):
                commands.append((argv, name, kwargs))
                if name == "smoke-mismatch":
                    (runner.output / "smoke-mismatch.log").write_text(
                        "memory.max differs from manifest"
                    )

            runner.call = call
            runner.check("smoke")
            good, bad = commands[1][0], commands[2][0]
            self.assertEqual(good[good.index("--memory") + 1], "256m")
            self.assertEqual(bad[bad.index("--memory") + 1], "192m")
            self.assertEqual(good[good.index("--memory-swap") + 1], "256m")
            self.assertIn("none", good)
            runner.constrained_run = lambda limit, manifest: runner.call(
                runner.docker(
                    limit, manifest, "--output", "/results/sizing-linux-raw.json", retain=True
                ),
                "constrained",
            )
            runner.check("constrained")
            constrained = commands[-2][0]
            for flag, value in (
                ("--memory", "12g"),
                ("--memory-swap", "12g"),
                ("--cpus", "2"),
                ("--pids-limit", "128"),
            ):
                self.assertEqual(constrained[constrained.index(flag) + 1], value)

    def test_host_hash_binding_partial_upload_cancel_and_frozen_retrieval(self):
        spec = importlib.util.spec_from_file_location(
            "dec077_host_fixture", ROOT / "scripts/package_a_host.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = b"fixture bundle"
            manifest = json.dumps(
                {
                    "bundle_bytes": len(payload),
                    "bundle_sha256": __import__("hashlib").sha256(payload).hexdigest(),
                }
            ).encode()
            host = module.Host(
                root, "token", __import__("hashlib").sha256(manifest).hexdigest(), time.time() + 20
            )
            with self.assertRaises(ValueError):
                host.dispatch("/manifest", b"altered", {})
            host.dispatch("/manifest", manifest, {})
            headers = {"X-Chunk-SHA256": __import__("hashlib").sha256(payload).hexdigest()}
            host.dispatch("/upload/0", payload, headers)
            with self.assertRaises(ValueError):
                host.dispatch("/upload/0", payload, headers)
            host.output.mkdir()
            (host.output / "partial.log").write_text("real partial data\n")
            kind_diagnostics = host.output / "runner/kind/diagnostics"
            kind_diagnostics.mkdir(parents=True)
            (kind_diagnostics / "001-events.log").write_text("captured events\n")
            host.deadline = 0
            self.assertEqual(host.dispatch("/cancel", b"", {})["offset"], len(payload))
            frozen = host.dispatch("/freeze", b"", {})
            block = host.dispatch("/archive/0", b"", {})
            self.assertEqual(__import__("hashlib").sha256(block).hexdigest(), frozen["sha256"])
            self.assertEqual(host.dispatch("/freeze", b"", {}), frozen)
            with tarfile.open(root / "receipts.tar.gz", "r:gz") as archive:
                self.assertIn("results/runner/kind/diagnostics/001-events.log", archive.getnames())

    def test_host_status_reads_the_bootstrap_runner_output_directory(self):
        spec = importlib.util.spec_from_file_location(
            "dec077_host_runner_status_fixture", ROOT / "scripts/package_a_host.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            host = module.Host(Path(directory), "token", "unused", time.time() + 20)
            runner_output = host.output / "runner"
            runner_output.mkdir(parents=True)
            (runner_output / "runner.json").write_text(
                json.dumps(
                    {
                        "role": "gate_a_receiver",
                        "status": "LISTENING",
                        "receiver_address": ["172.20.0.3", 38473],
                    }
                ),
                encoding="utf-8",
            )

            runner = host.status()["runner_status"]

            self.assertEqual(runner["role"], "gate_a_receiver")
            self.assertEqual(runner["status"], "LISTENING")
            self.assertEqual(runner["receiver_address"], ["172.20.0.3", 38473])

    def test_r316_freeze_cuts_40_mib_log_and_keeps_receipt_and_hash(self):
        spec = importlib.util.spec_from_file_location(
            "package_a_host_r316_single", ROOT / "scripts/package_a_host.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        def write_random(path, size):
            remaining = size
            digest = hashlib.sha256()
            with path.open("wb") as stream:
                while remaining:
                    data = os.urandom(min(1024**2, remaining))
                    stream.write(data)
                    digest.update(data)
                    remaining -= len(data)
            return digest.hexdigest()

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            host = module.Host(root, "fixture-host-token", "unused", time.time() + 60)
            log = host.output / "runner/kind/diagnostics/race.log"
            log.parent.mkdir(parents=True)
            original_bytes = 40 * 1024**2
            original_sha256 = write_random(log, original_bytes)
            receipt = host.output / "sizing/receipt.json"
            receipt.parent.mkdir(parents=True)
            receipt_bytes = b'{"complete":true,"sentinel":"keep-whole"}\n'
            receipt.write_bytes(receipt_bytes)

            frozen = host.dispatch("/freeze", b"", {})

            self.assertLessEqual(frozen["bytes"], EXPORT_MAX_BYTES)
            self.assertTrue(frozen["bounded"])
            self.assertEqual(len(frozen["truncated_files"]), 1)
            cut = frozen["truncated_files"][0]
            self.assertEqual(cut["path"], "results/runner/kind/diagnostics/race.log")
            self.assertEqual(cut["original_bytes"], original_bytes)
            self.assertEqual(cut["sha256"], original_sha256)
            self.assertFalse(cut["dropped"])
            with tarfile.open(root / "receipts.tar.gz", "r:gz") as archive:
                self.assertEqual(
                    archive.extractfile("results/sizing/receipt.json").read(), receipt_bytes
                )
                payload = archive.extractfile(cut["path"]).read()
                self.assertEqual(len(payload), 1024**2)
                with log.open("rb") as stream:
                    self.assertEqual(payload[: 512 * 1024], stream.read(512 * 1024))
                    stream.seek(-512 * 1024, os.SEEK_END)
                    self.assertEqual(payload[512 * 1024 :], stream.read(512 * 1024))
                listed = json.loads(archive.extractfile("truncated.json").read())
                self.assertEqual(listed, frozen["truncated_files"])

    def test_r316_drop_order_never_drops_receipts_or_json(self):
        spec = importlib.util.spec_from_file_location(
            "package_a_host_r316_many", ROOT / "scripts/package_a_host.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        def write_random(path, size):
            remaining = size
            with path.open("wb") as stream:
                while remaining:
                    data = os.urandom(min(1024**2, remaining))
                    stream.write(data)
                    remaining -= len(data)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            host = module.Host(root, "fixture-host-token", "unused", time.time() + 60)
            host.output.mkdir(parents=True)
            receipt = host.output / "receipt.json"
            receipt_bytes = b'{"complete":true,"must":"survive"}\n'
            receipt.write_bytes(receipt_bytes)
            config = host.output / "run.json"
            config_bytes = b'{"case":"json-must-survive"}\n'
            config.write_bytes(json.dumps({"data": os.urandom(3 * 1024**2).hex()}).encode())
            config_bytes = config.read_bytes()
            logs = []
            for index in range(35):
                log = host.output / "logs" / f"large-{index:02d}.log"
                log.parent.mkdir(parents=True, exist_ok=True)
                write_random(log, 2 * 1024**2)
                logs.append(f"results/logs/{log.name}")

            frozen = host.dispatch("/freeze", b"", {})

            self.assertLessEqual(frozen["bytes"], EXPORT_MAX_BYTES)
            truncated = frozen["truncated_files"]
            dropped = {item["path"] for item in truncated if item["dropped"]}
            self.assertTrue(dropped)
            self.assertTrue(dropped.issubset(set(logs)))
            self.assertEqual({item["path"] for item in truncated}, set(logs) | {"results/run.json"})
            self.assertNotIn("results/run.json", dropped)
            with tarfile.open(root / "receipts.tar.gz", "r:gz") as archive:
                names = set(archive.getnames())
                self.assertIn("results/receipt.json", names)
                self.assertIn("results/run.json", names)
                self.assertEqual(archive.extractfile("results/receipt.json").read(), receipt_bytes)
                cut_json = archive.extractfile("results/run.json").read()
                self.assertLessEqual(len(cut_json), 1024**2)
                self.assertEqual(cut_json[: 256 * 1024], config_bytes[: 256 * 1024])
                self.assertEqual(cut_json[-256 * 1024 :], config_bytes[-256 * 1024 :])
                self.assertEqual(
                    json.loads(archive.extractfile("truncated.json").read()), truncated
                )
                for path in logs:
                    self.assertEqual(path in names, path not in dropped)

    def test_r316_real_server_and_operator_rpc_report_freeze_prerequisite(self):
        from inference_platform.r1_cloud_operator import Operator

        spec = importlib.util.spec_from_file_location(
            "package_a_host_r316_server", ROOT / "scripts/package_a_host.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        token = "fixture-host-control-token"
        with tempfile.TemporaryDirectory() as directory:
            host = module.Host(Path(directory), token, "unused", time.time() + 60)
            http = module.server(host, port=0)
            worker = threading.Thread(target=http.serve_forever, daemon=True)
            worker.start()
            try:
                ports = Ports.__new__(Ports)
                ports.deadline = time.time() + 10
                with self.assertRaisesRegex(RuntimeError, "freeze_before_retrieve") as raised:
                    Operator.rpc(ports, http.server_address[1], "/archive/0", token)
                self.assertNotIn(token, str(raised.exception))

                for reason in (
                    "receipt_archive_exceeds_32_mib_after_cut_logs",
                    "source_python_hash_binding",
                ):

                    def long_reason(*_args, reason=reason):
                        raise ValueError(reason)

                    host.dispatch = long_reason
                    with self.assertRaisesRegex(RuntimeError, reason):
                        Operator.rpc(ports, http.server_address[1], "/freeze", token)

                def token_bearing_failure(*_args):
                    raise ValueError("synthetic detail " + token)

                host.dispatch = token_bearing_failure
                connection = HTTPConnection("127.0.0.1", http.server_address[1])
                try:
                    connection.request(
                        "GET",
                        "/forced-error",
                        headers={"Authorization": "Bearer " + token},
                    )
                    response = connection.getresponse()
                    body = response.read()
                    self.assertEqual(response.status, 409)
                    self.assertIn(b"[redacted]", body)
                    self.assertNotIn(token.encode(), body)
                finally:
                    connection.close()
            finally:
                http.shutdown()
                http.server_close()
                worker.join(timeout=5)
                self.assertFalse(worker.is_alive())

    def test_ssm_shell_has_no_crlf_shell_syntax_breakage(self):
        commands = bootstrap_shell(b"print('source bytes')\r\n", "safe-token", "f" * 64, 2000)
        self.assertTrue(all("\r" not in command for command in commands))
        self.assertIn("base64 -d", "\n".join(commands))

    def test_teardown_attempts_destroy_when_instance_inventory_or_wait_fails(self):
        for fault in ("lookup", "wait"):
            ports = Ports.__new__(Ports)
            ports.child = None
            ports.inputs = {"aws_profile": "fixture"}
            ports.manifest = {"operator_tools": {"terraform": {"path": "terraform-pinned"}}}
            calls = []

            def ids(fault=fault):
                if fault == "lookup":
                    raise ConnectionError("lost inventory reply")
                return ["i-fixture"]

            def command(argv, end, name, calls=calls):
                calls.append(name)
                if name == "wait-terminated":
                    raise TimeoutError("wait expired")

            ports.instance_ids = ids
            ports.aws = lambda *args, calls=calls, **kwargs: calls.append("terminate")
            ports.command = command
            result = ports.teardown(time.time() + 60)
            self.assertEqual(calls[-1], "destroy")
            self.assertFalse(result["destroy_completed"])

    def test_applied_consume_exclusive_file_blocks_duplicate_apply_effect(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "terraform").mkdir()
            plan = root / "terraform/create.tfplan"
            plan.write_bytes(b"fixture")
            ports = Ports.__new__(Ports)
            ports.directory = root
            ports.manifest = {"sealed_plans": {"create_sha256": sha(plan)}}
            calls = []
            ports.command = lambda *args: calls.append("apply")
            ports.instance_ids = lambda: ["i-fixture"]
            ports.apply(time.time() + 60)
            with self.assertRaises(FileExistsError):
                ports.apply(time.time() + 60)
            self.assertEqual(calls, ["apply"])

    def test_bootstrap_waits_for_online_ssm_and_refuses_expired_registration(self):
        def fixture(runtime):
            ports = Ports.__new__(Ports)
            ports.runtime = runtime
            ports.registration_path = runtime / "ssm-registration.json"
            runtime.mkdir(parents=True)
            ports.status_answered = False
            ports.host = "i-fixture"
            ports.started = 0
            ports.manifest = {"cleanup_cost_reserve_usd": 1}
            ports.manifest_hash = "f" * 64
            ports.token = "fixture"
            ports.cumulative_cost = lambda *args: 0
            return ports

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ports = fixture(root / "success-runtime")
            calls = []
            responses = iter(
                [
                    {"InstanceInformationList": []},
                    {"InstanceInformationList": [{"PingStatus": "Online"}]},
                ]
            )
            ports.aws = lambda *args: next(responses)
            ports.ssm = lambda *args, **kwargs: calls.append(args[1])
            with patch("inference_platform.package_a_operator.time.sleep"):
                ports.bootstrap(time.time() + 300)
            self.assertEqual(len(calls), 2)
            self.assertIn("cloud-init status --wait", calls[0])
            self.assertTrue(ports.status_answered)
            self.assertEqual(
                json.loads((ports.runtime / "host-reachable.json").read_bytes()),
                {"manifest_sha256": ports.manifest_hash},
            )
            self.assertEqual(
                json.loads((ports.registration_path).read_bytes()),
                {"ping_status": "Online"},
            )

            failed = fixture(root / "failed-runtime")
            failed.aws = lambda *args: {"InstanceInformationList": []}
            now = [0]
            with (
                patch(
                    "inference_platform.package_a_operator.time.time", side_effect=lambda: now[0]
                ),
                patch(
                    "inference_platform.package_a_operator.time.sleep",
                    side_effect=lambda _: now.__setitem__(0, 180),
                ),
            ):
                with self.assertRaisesRegex(
                    TimeoutError,
                    r"ssm_registration_deadline elapsed_s=\d+\.\d{3} "
                    r"last_ping_status=no_instance_information",
                ):
                    failed.bootstrap(1000)
            self.assertFalse(failed.status_answered)
            self.assertFalse((failed.runtime / "host-reachable.json").exists())


if __name__ == "__main__":
    unittest.main()
