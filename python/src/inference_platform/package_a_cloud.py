"""DEC-077 serial host runner and bounded, independently testable lifecycle.

No AWS action is performed by import or by the runner. The operator owns every
billable call, resource inventory, receipt retrieval and final teardown.
"""

import argparse
import hashlib
import json
import math
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

from .inf037b_live import REDIS_CAPTURE_SOCKET_TIMEOUT_S
from .inf037b_row5 import RBAC_REVIEW_TIMEOUT_S
from .inf037b_row5_diagnostic import DIAGNOSTIC_PROCESS_TIMEOUT_S
from .inf037b_row5_sequence import OUTAGE_SEQUENCE_TIMEOUT_S
from .package_a_capture import validate_native_reuse
from .package_a_cpu_validation import CPU_STAGE_TIMEOUTS
from .package_a_go import GoTestSummaryError, go_test_summary
from .package_a_images import (
    ARCHIVE_BUILD_TIMEOUT_S,
    ARCHIVE_EXPORT_TIMEOUT_S,
    ARCHIVE_PREFETCH_CLEANUP_TIMEOUT_S,
    KIND_ARCHIVE_LOAD_TIMEOUT_S,
    KIND_LOCAL_IMAGE_INSPECT_TIMEOUT_S,
    KIND_LOCAL_IMAGE_LOAD_TIMEOUT_S,
)
from .session_stop import stop_forward

MIB = 1024**2
GIB = 1024**3
GATE_A_MINIO_IMAGE = "ghcr.io/coollabsio/minio@sha256:69b55a1c1c5dc285ce04db96689f5b2102317fc77a50680a1874ca6efd1c87f9"
GATE_A_BOTO3_VERSION = "1.43.123"
GATE_A_READINESS_MODULES = (
    "test_inf037b_transfer",
    "test_inf037b_gate_a",
    "test_inf037b_gate_a_spool",
    "test_inf037b_maximum",
    "test_inf037b_gate_a_socket",
    "test_package_a_gate_a_host",
    "test_package_a_gate_a_operator",
    "test_package_a_sealed",
    "test_build_inf037b_gate_a_fixture",
)
CAP_USD = 40
INSTANCE_TYPE = "c6i.2xlarge"  # Seventh task only; historical packets retain m6i.
DEADLINE_S = 21_600  # DEC-077 / Xiaoyun's R287 amendment: one policy origin.
CLEANUP_S = 600
APPLY_S = CLEANUP_S
HOST_TIMER_S = DEADLINE_S - APPLY_S
SIZING_S = DEADLINE_S // 3
CALL_S = 60
METADATA_S = 30
KIND_RUNNER_TIMEOUT_S = 600
# Task 6 measured 56.204844 s to the first passing host sample and 180.079147 s
# for its full kind command. The new workload is unmeasured, so these fixed
# multipliers give it conservative ceilings, rounded up to whole minutes.
PACKAGE_A_HOST_READY_MEASURED_S = 56.204844
PACKAGE_A_KIND_MEASURED_S = 180.079147
ROW5_SUITE_TIMEOUT_S = math.ceil(5 * PACKAGE_A_KIND_MEASURED_S / 60) * 60
ROW5_DIAGNOSTIC_INTEGRATION_TIMEOUT_S = 120
ROW5_NATIVE_SUITE_TIMEOUT_S = 120
ROW5_KIND_COMMAND_TIMEOUT_S = 90
ROW5_KIND_CLUSTER_CREATE_TIMEOUT_S = 240
ROW5_KIND_CLUSTER_PROBE_TIMEOUT_S = 30
ROW5_KIND_DEPLOYMENT_ROLLOUT_TIMEOUT_S = 90
ROW5_KIND_READINESS_GRACE_S = 5
ROW5_KIND_NODE_READY_TIMEOUT_S = 90
ROW5_KIND_SCALE_OBSERVE_TIMEOUT_S = 30
ROW5_KIND_SCALE_READY_TIMEOUT_S = 90
ROW5_KIND_GPU_DELETE_TIMEOUT_S = 70
ROW5_KIND_GPU_PENDING_TIMEOUT_S = 60
ROW5_KIND_REDIS_ROLLOUT_TIMEOUT_S = 100
ROW5_KIND_OPERATOR_TIMEOUT_S = 90
ROW5_KIND_DIAGNOSTIC_BUILD_TIMEOUT_S = 90
ROW5_KIND_PORT_FORWARD_READY_TIMEOUT_S = 15
ROW5_KIND_MEASUREMENT_PROBE_TIMEOUT_S = 2
ROW5_KIND_CONFIGURATION_CAPTURE_TIMEOUT_S = 600
ROW5_KIND_STAGE_WINDOW_TIMEOUT_S = 600
ROW5_KIND_HOLD_END_TIMEOUT_S = 8
ROW5_KIND_HOLD_POLL_INTERVAL_S = 0.25
ROW5_KIND_PORT_FORWARD_CONNECT_TIMEOUT_S = 0.2
ROW5_KIND_RESTORE_GRACE_BEFORE_S = 90
ROW5_KIND_RESTORE_GRACE_AFTER_S = 10
ROW5_KIND_PINNED_TTL_MS = 8000
ROW5_KIND_PINNED_HOLD_MS = 2000
ROW5_KIND_CLEANUP_RESERVE_S = 310
ROW5_KIND_RECEIPT_RESERVE_S = 10
ROW5_KIND_IMAGE_INSPECT_TIMEOUT_S = 30
ROW5_KIND_REDIS_PULL_TIMEOUT_S = 180
ROW5_KIND_TIME_BOUNDS_S = {
    "cluster_creation": ROW5_KIND_CLUSTER_CREATE_TIMEOUT_S,
    "cluster_name_probe": ROW5_KIND_CLUSTER_PROBE_TIMEOUT_S,
    # Redis inspect/pull/buildx/save/temp removal/kind load, plus each local
    # image's presence probe, digest inspection and kind load.
    "image_loads": (
        ROW5_KIND_IMAGE_INSPECT_TIMEOUT_S
        + ROW5_KIND_REDIS_PULL_TIMEOUT_S
        + ARCHIVE_BUILD_TIMEOUT_S
        + ARCHIVE_EXPORT_TIMEOUT_S
        + ARCHIVE_PREFETCH_CLEANUP_TIMEOUT_S
        + KIND_ARCHIVE_LOAD_TIMEOUT_S
        + 2
        * (
            ROW5_KIND_IMAGE_INSPECT_TIMEOUT_S
            + KIND_LOCAL_IMAGE_INSPECT_TIMEOUT_S
            + KIND_LOCAL_IMAGE_LOAD_TIMEOUT_S
        )
    ),
    "three_scale_waits": 3
    * (
        ROW5_KIND_COMMAND_TIMEOUT_S
        + ROW5_KIND_SCALE_OBSERVE_TIMEOUT_S
        + ROW5_KIND_SCALE_READY_TIMEOUT_S
    ),
    "gpu_release": (
        ROW5_KIND_COMMAND_TIMEOUT_S
        + ROW5_KIND_GPU_DELETE_TIMEOUT_S
        + ROW5_KIND_GPU_PENDING_TIMEOUT_S
        + 3 * ROW5_KIND_COMMAND_TIMEOUT_S
    ),
    "restore_window": (
        ROW5_KIND_RESTORE_GRACE_BEFORE_S
        + (ROW5_KIND_PINNED_TTL_MS + ROW5_KIND_PINNED_HOLD_MS) / 1000
        + ROW5_KIND_RESTORE_GRACE_AFTER_S
    ),
    "node_setup_commands": 11 * ROW5_KIND_COMMAND_TIMEOUT_S,
    "node_ready_wait": ROW5_KIND_NODE_READY_TIMEOUT_S,
    "manifest_application_and_gateway_readiness": (
        ROW5_KIND_COMMAND_TIMEOUT_S
        + ROW5_KIND_COMMAND_TIMEOUT_S
        + ROW5_KIND_DEPLOYMENT_ROLLOUT_TIMEOUT_S
        + ROW5_KIND_READINESS_GRACE_S
    ),
    "redis_rollout": ROW5_KIND_REDIS_ROLLOUT_TIMEOUT_S,
    "operator_identity_and_api_discovery": 3 * ROW5_KIND_OPERATOR_TIMEOUT_S,
    "diagnostic_build": ROW5_KIND_DIAGNOSTIC_BUILD_TIMEOUT_S,
    "port_forward_startup": 3 * ROW5_KIND_PORT_FORWARD_READY_TIMEOUT_S,
    "port_forward_probe_slack": 3 * ROW5_KIND_PORT_FORWARD_CONNECT_TIMEOUT_S,
    "gateway_boot_probes": 2 * ROW5_KIND_MEASUREMENT_PROBE_TIMEOUT_S,
    "configuration_capture_window": ROW5_KIND_CONFIGURATION_CAPTURE_TIMEOUT_S,
    "six_live_stage_window": ROW5_KIND_STAGE_WINDOW_TIMEOUT_S,
    "known_stage_diagnostic_calls": 5 * DIAGNOSTIC_PROCESS_TIMEOUT_S,
    "outage_diagnostic_calls": 3 * DIAGNOSTIC_PROCESS_TIMEOUT_S,
    "uncordon": ROW5_KIND_COMMAND_TIMEOUT_S,
    "hold_end_window": ROW5_KIND_HOLD_END_TIMEOUT_S,
    "hold_end_final_poll_slack": (ROW5_KIND_HOLD_POLL_INTERVAL_S + REDIS_CAPTURE_SOCKET_TIMEOUT_S),
    "restore_start_final_poll_slack": (
        ROW5_KIND_HOLD_POLL_INTERVAL_S + REDIS_CAPTURE_SOCKET_TIMEOUT_S
    ),
    "outage_sequence_window": OUTAGE_SEQUENCE_TIMEOUT_S,
    "outage_rbac_review_windows": 2 * RBAC_REVIEW_TIMEOUT_S,
    "cleanup_reserve": ROW5_KIND_CLEANUP_RESERVE_S,
    "receipt_reserve": ROW5_KIND_RECEIPT_RESERVE_S,
}
ROW5_KIND_CRITICAL_PATH_S = sum(
    value
    for name, value in ROW5_KIND_TIME_BOUNDS_S.items()
    if name not in {"cleanup_reserve", "receipt_reserve"}
)
ROW5_KIND_TIMEOUT_S = (
    math.ceil(
        (
            ROW5_KIND_CRITICAL_PATH_S
            + ROW5_KIND_TIME_BOUNDS_S["cleanup_reserve"]
            + ROW5_KIND_TIME_BOUNDS_S["receipt_reserve"]
        )
        / 60
    )
    * 60
)
ROW5_READINESS_TIMEOUT_S = math.ceil(2 * PACKAGE_A_HOST_READY_MEASURED_S / 60) * 60
# Every tuple enumerates the sequential subprocess bounds, including finally.
CALL_TIMEOUTS = {
    "capture": (METADATA_S, SIZING_S),
    "native": (METADATA_S, SIZING_S),
    "prepare_images": (CALL_S, 300, 300, 300, 600, *([METADATA_S] * 5)),
    "smoke": (CALL_S, CALL_S, CALL_S),
    "race": (CALL_S, METADATA_S, 600, METADATA_S),
    "e2e": (CALL_S, METADATA_S, 180, METADATA_S),
    "kind": (KIND_RUNNER_TIMEOUT_S,),
    "row5": (
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
    "constrained": (CALL_S, SIZING_S, *([METADATA_S] * 4), CALL_S),
}
BUDGETS = {name: sum(calls) for name, calls in CALL_TIMEOUTS.items()}
CHECKS = (
    ("native", 9123, 0, BUDGETS["native"]),
    ("smoke", 2304, 256, BUDGETS["smoke"]),
    ("race", 2560, 512, BUDGETS["race"]),
    ("e2e", 2560, 512, BUDGETS["e2e"]),
    ("kind", 6656, 4608, BUDGETS["kind"]),
    ("row5", 6656, 4608, BUDGETS["row5"]),
    ("constrained", 14336, 12288, BUDGETS["constrained"]),
    ("capture", 9123, 0, BUDGETS["capture"]),
)
TASK_CHECKS = ("race", "e2e", "row5")
CPU_VALIDATION_CHECKS = ("race", "e2e", "cpu_validation")
PRIOR_RUN_COST_USD = 0.0  # Standalone fixture with no prior runs.
# Includes .cache/r407/packet-4c78fa8 (1.1087691236057768) and .cache/r412/packet-b36c74e (1.1084082576326528).
EXPORT_MAX_BYTES = 32 * MIB
TRANSFER_BPS = 500_000  # Same conservative floor as the R1 operator.
COST_FIXED_USD = 1.0
WORKSHEET_HOURLY_USD = 0.35211111111111115  # Refreshed DEC-086 64 GiB root.


def utc():
    return datetime.now(UTC).isoformat(timespec="microseconds")


def save(path, value):
    """BOM-free, atomic receipts, including partial/failure results."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("wb") as stream:
        stream.write((json.dumps(value, indent=2, sort_keys=True) + "\n").encode())
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for data in iter(lambda: stream.read(MIB), b""):
            digest.update(data)
    return digest.hexdigest()


def transfer_seconds(size):
    if type(size) is not int or size < 0:
        raise ValueError("invalid_transfer_size")
    # Two full byte passes plus setup; reconnects share this absolute budget.
    return 2 * math.ceil(size / TRANSFER_BPS) + 60


def validate_row5_suite_log(path, *, expected_tests=None):
    if expected_tests is not None and (type(expected_tests) is not int or expected_tests <= 0):
        raise ValueError("row5_suite_log_expected_tests_invalid")
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    matches = re.findall(r"(?m)^Ran (\d+) tests? in \d+(?:\.\d+)?s$", text)
    if len(matches) != 1:
        raise ValueError("row5_suite_log_missing_ran")
    tests_run = int(matches[0])
    if tests_run <= 0:
        raise ValueError("row5_suite_log_zero_tests")
    if expected_tests is not None and tests_run != expected_tests:
        raise ValueError("row5_suite_log_unexpected_test_count")
    if re.search(r"(?m) \.\.\. skipped ", text):
        raise ValueError("row5_suite_log_skipped")
    if not lines or lines[-1] != "OK":
        raise ValueError("row5_suite_log_not_final_ok")
    return {"tests_run": tests_run, "skipped": 0}


def summarize_failed_row5_suite_log(path):
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    ran = re.findall(r"(?m)^Ran (\d+) tests? in \d+(?:\.\d+)?s$", text)
    failed = re.findall(r"(?m)^FAILED \(([^)]*)\)$", text)
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(ran) != 1 or len(failed) != 1 or not lines or not lines[-1].startswith("FAILED ("):
        return None
    counts = {}
    for item in failed[0].split(","):
        match = re.fullmatch(r"\s*(errors|failures|skipped)=(\d+)\s*", item)
        if match is None:
            return None
        counts[match.group(1)] = int(match.group(2))
    if not counts:
        return None
    return {
        "tests_run": int(ran[0]),
        "errors": counts.get("errors", 0),
        "failures": counts.get("failures", 0),
        "skipped": counts.get("skipped", 0),
        "failed_tests": re.findall(r"(?m)^(?:ERROR|FAIL):\s+(.+?)\s*$", text)[:20],
    }


def selected_checks(names):
    if not isinstance(names, (list, tuple)) or tuple(names) not in (
        TASK_CHECKS,
        CPU_VALIDATION_CHECKS,
    ):
        raise ValueError("invalid_task_checks")
    rows = {row[0]: row for row in CHECKS}
    rows["cpu_validation"] = ("cpu_validation", 6656, 4608, sum(CPU_STAGE_TIMEOUTS))
    return [rows[name] for name in names]


def timing_worksheet(
    bundle_bytes,
    checks=TASK_CHECKS,
    *,
    hourly_all_resources_usd=WORKSHEET_HOURLY_USD,
    prior_spend_usd=PRIOR_RUN_COST_USD,
    cleanup_cost_reserve_usd=1.0,
    cap_usd=CAP_USD,
):
    if hourly_all_resources_usd <= 0:
        raise ValueError("invalid_hourly_cost")
    selected = selected_checks(checks)
    call_timeouts = {
        name: (CPU_STAGE_TIMEOUTS if name == "cpu_validation" else CALL_TIMEOUTS[name])
        for name in (*checks, "prepare_images")
    }
    if "capture" in checks and "native" in checks:
        # Native consumes the capture's separately bounded sanitizer receipt.
        call_timeouts["native"] = (METADATA_S,)
    budgets = {name: sum(calls) for name, calls in call_timeouts.items()}
    result = {
        "checks": list(checks),
        "deadline_seconds": DEADLINE_S,
        "host_timer_seconds": HOST_TIMER_S,
        "cost_hours": DEADLINE_S / 3600,
        "call_timeouts_s": call_timeouts,
        "admission_budgets_s": budgets,
        "sizing_timeout_s": SIZING_S,
        "work_seconds": sum(budgets[row[0]] for row in selected),
        "image_preparation_forecast_s": BUDGETS["prepare_images"],
        "apply_forecast_s": APPLY_S,
        # SSM registration/readiness/launch: 180+300+60; remaining 360 s is
        # forecast installation/dependency time, not a cloud speed measurement.
        "bootstrap_forecast_s": 900,
        "upload_timeout_s": transfer_seconds(bundle_bytes),
        "retrieval_timeout_s": transfer_seconds(EXPORT_MAX_BYTES),
        "cleanup_seconds": CLEANUP_S,
        "prior_measured_wall_s": 5533,
        "prior_measured_wall_source": (
            ".cache/m5-sizing-native-v2.log CreationTime 2026-10-18 02:12:17 "
            "to LastWriteTime 03:44:30, laptop local time; Claude Round 225 / R287"
        ),
        "prior_export_only_s": 4713.195,
        "prior_export_only_source": "docs/evidence/m5-package-a/sizing-native.json elapsed_seconds; construction/materialization/verification excluded",
    }
    result["forecast_wall_s"] = sum(
        result[key]
        for key in (
            "work_seconds",
            "image_preparation_forecast_s",
            "apply_forecast_s",
            "bootstrap_forecast_s",
            "upload_timeout_s",
            "retrieval_timeout_s",
            "cleanup_seconds",
        )
    )
    if result["forecast_wall_s"] > DEADLINE_S:
        raise ValueError("wall_forecast_exceeds_deadline")
    result["cost_guard_hours"] = (
        cap_usd - prior_spend_usd - COST_FIXED_USD - cleanup_cost_reserve_usd
    ) / hourly_all_resources_usd
    result["cost_guard_margin_s"] = result["cost_guard_hours"] * 3600 - result["forecast_wall_s"]
    return result


def memory_sample(path=Path("/proc/meminfo")):
    raw = path.read_text()
    values = {
        row.split(":")[0]: int(row.split()[1]) * 1024
        for row in raw.splitlines()
        if row.startswith(("MemAvailable:", "MemTotal:"))
    }
    if set(values) != {"MemAvailable", "MemTotal"}:
        raise ValueError("missing_meminfo")
    return {
        "sampled_at_utc": utc(),
        "raw_proc_meminfo": raw,
        "host": values,
        "vm": values.copy(),
        "vm_meaning": "Linux host: VM fields are the same host /proc/meminfo",
    }


def gate(sample, required_mib, combined_mib):
    host, vm = sample["host"], sample["vm"]
    return (
        host == vm
        and host["MemAvailable"] >= required_mib * MIB
        and (not combined_mib or host["MemAvailable"] >= (combined_mib + 2048) * MIB)
        and vm["MemAvailable"] >= combined_mib * MIB
        and vm["MemTotal"] >= combined_mib * MIB
    )


def verified_source(repo, commit, hashes):
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo).decode().strip()
    if actual != commit:
        raise ValueError("source_head_mismatch")
    # Include every tracked python/ file, not just imported collectors.
    names = subprocess.check_output(["git", "ls-files", "-z", "python"], cwd=repo)
    names = [name.decode() for name in names.split(b"\0") if name]
    observed = {name: sha(repo / name) for name in names}
    if observed != hashes:
        raise ValueError("python_inventory_or_bytes_mismatch")
    if subprocess.check_output(["git", "status", "--porcelain"], cwd=repo):
        raise ValueError("source_worktree_dirty")
    return {"commit": actual, "python_files": len(observed), "python_sha256": observed}


def run_exe(argv, *, cwd, output, timeout, env=None, expected=0):
    """Run real executables, capture raw bytes, kill the owned process group."""
    argv = [str(x) for x in argv]
    started = time.monotonic()
    log = Path(output)
    log.parent.mkdir(parents=True, exist_ok=True)
    child = None
    try:
        with log.open("wb") as stream:
            child = subprocess.Popen(
                argv,
                cwd=cwd,
                env=env,
                stdout=stream,
                stderr=subprocess.STDOUT,
                start_new_session=os.name != "nt",
            )
            try:
                code = child.wait(timeout=timeout)
            except BaseException as exc:
                # Windows venv launchers can own another Python executable.
                # Reap the owned tree, not only the launcher holding its PID.
                if os.name == "nt":
                    stop_forward(child)
                else:
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    child.wait(timeout=10)
                save(
                    log.with_suffix(".command.json"),
                    {
                        "argv": argv,
                        "exit": child.returncode,
                        "error": type(exc).__name__,
                        "elapsed_s": time.monotonic() - started,
                        "log": log.name,
                        "log_sha256": sha(log),
                    },
                )
                raise
        result = {
            "argv": argv,
            "exit": code,
            "elapsed_s": time.monotonic() - started,
            "log": log.name,
            "log_sha256": sha(log),
        }
        save(log.with_suffix(".command.json"), result)
        if (expected == 0 and code != 0) or (expected == "refuse" and code == 0):
            raise RuntimeError("check_exit:" + log.name + ":" + str(code))
        return result
    finally:
        if child is not None and child.poll() is None:
            stop_forward(child)


class Runner:
    def __init__(
        self,
        repo,
        output,
        manifest,
        *,
        sample=memory_sample,
        execute=run_exe,
        recovery_root=None,
    ):
        self.repo, self.output = Path(repo).resolve(), Path(output).resolve()
        self.manifest, self.sample, self.execute = manifest, sample, execute
        self.role = manifest.get("role", "host_checks")
        if self.role in {
            "gate_a_receiver",
            "gate_a_sender",
            "routine_tests",
            "descriptive_operator",
        }:
            self.checks = []
        elif self.role == "host_checks":
            self.checks = selected_checks(manifest["checks"])
        else:
            raise ValueError("invalid_package_a_runner_role")
        self.container_name = "dec077-sizing-" + uuid.uuid4().hex
        self.output.mkdir(parents=True, exist_ok=False)
        self.env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "GOTOOLCHAIN": "local"}
        self.env["PYTHONPATH"] = str(self.repo / "python/src")
        self.env["M5_PACKAGE_A_BIN"] = str(self.repo / ".cache/kind-build/gateway")
        self.env["REDIS_TEST_ADDR"] = "127.0.0.1:26379"
        self.python = manifest["python_executable"]
        self.image = manifest["pins"]["python_image"]
        self.sizing = [self.python, "scripts/size_inf037b_sanitized_export.py"]
        self.gate_a_recovery_root = Path(recovery_root or "/recovery")
        self.receipt = {"schema": "dec077-host-v1", "started_at_utc": utc(), "checks": []}

    def call(self, argv, name, *, timeout=CALL_S, expected=0):
        return self.execute(
            argv,
            cwd=self.repo,
            output=self.output / (name + ".log"),
            env=self.env,
            timeout=timeout,
            expected=expected,
        )

    def row5_diagnostic_real_redis(self):
        """Run the production diagnostic binary against isolated host Redis on Linux."""
        redis_name = self.container_name + "-row5-diagnostic-redis"
        errors = []
        test_receipt = None
        with tempfile.TemporaryDirectory(prefix="row5-diagnostic-bin-") as binary_directory:
            binary = Path(binary_directory) / "row5-diagnostic"
            try:
                self.call(
                    ["go", "build", "-o", binary, "./cmd/row5-diagnostic"],
                    "row5-diagnostic-binary-build",
                    timeout=ROW5_KIND_DIAGNOSTIC_BUILD_TIMEOUT_S,
                )
                self.call(
                    [
                        "docker",
                        "run",
                        "-d",
                        "--name",
                        redis_name,
                        "--memory",
                        "512m",
                        "--memory-swap",
                        "512m",
                        "--cpus",
                        "1",
                        "--pids-limit",
                        "64",
                        "-p",
                        "127.0.0.1:26379:6379",
                        self.manifest["pins"]["redis_image"],
                    ],
                    "row5-diagnostic-redis-start",
                )
                self.call(
                    [
                        "sh",
                        "-c",
                        "i=0; until docker exec "
                        + redis_name
                        + " redis-cli ping | grep -qx PONG; do "
                        "i=$((i+1)); test $i -lt 20 || exit 1; sleep 1; done",
                    ],
                    "row5-diagnostic-redis-ready",
                    timeout=METADATA_S,
                )
                result = self.call(
                    [
                        "docker",
                        "run",
                        "--rm",
                        "--name",
                        self.container_name + "-row5-diagnostic-test",
                        "--network",
                        "host",
                        "--memory",
                        "6656m",
                        "--memory-swap",
                        "6656m",
                        "--cpus",
                        "2",
                        "--pids-limit",
                        "128",
                        "--mount",
                        f"type=bind,source={self.repo},target=/repo,readonly",
                        "--mount",
                        f"type=bind,source={binary_directory},target=/diagnostic,readonly",
                        "-e",
                        "PYTHONPATH=/repo/python/src:/repo/python/tests",
                        "-e",
                        "PYTHONDONTWRITEBYTECODE=1",
                        "-e",
                        "REDIS_TEST_ADDR=127.0.0.1:26379",
                        "-e",
                        "ROW5_DIAGNOSTIC_BIN=/diagnostic/row5-diagnostic",
                        "-w",
                        "/repo",
                        self.image,
                        "python",
                        "-m",
                        "unittest",
                        "-v",
                        "test_inf037b_row5_diagnostic",
                    ],
                    "row5-diagnostic-real-redis",
                    timeout=ROW5_DIAGNOSTIC_INTEGRATION_TIMEOUT_S,
                )
                try:
                    summary = validate_row5_suite_log(self.output / result["log"])
                except ValueError as exc:
                    raise ValueError("row5_diagnostic_real_redis_test_incomplete") from exc
                test_receipt = {
                    "status": "PASS",
                    **result,
                    "tests": summary["tests_run"],
                    "skipped": summary["skipped"],
                }
            except Exception as exc:
                errors.append({"error": type(exc).__name__, "detail": str(exc)[:500]})
            finally:
                try:
                    cleanup = self.call(
                        ["docker", "rm", "-f", redis_name],
                        "row5-diagnostic-redis-remove",
                        timeout=METADATA_S,
                        expected="any",
                    )
                    if cleanup.get("exit") not in (0, 1):
                        errors.append({"error": "redis_cleanup_exit", "detail": str(cleanup)[:500]})
                except Exception as exc:
                    errors.append({"error": type(exc).__name__, "detail": str(exc)[:500]})
        if errors:
            return {"status": "FAILED", "test": test_receipt, "errors": errors}
        return test_receipt

    def docker(self, limit, *tail, retain=False):
        return [
            "docker",
            "run",
            *([] if retain else ["--rm"]),
            "--name",
            self.container_name,
            "--network",
            "none",
            "--memory",
            limit,
            "--memory-swap",
            limit,
            "--cpus",
            "2",
            "--pids-limit",
            "128",
            "--mount",
            f"type=bind,source={self.repo},target=/repo,readonly",
            "--mount",
            f"type=bind,source={self.output},target=/results",
            "-e",
            "PYTHONPATH=/repo/python/src",
            "-e",
            "PYTHONDONTWRITEBYTECODE=1",
            "-w",
            "/repo",
            self.image,
            "python",
            "scripts/size_inf037b_sanitized_export.py",
            "--container-mode",
            "--source-manifest",
            "/results/" + tail[0],
            *tail[1:],
        ]

    def prepare_images(self):
        # Native has finished. No container was started during host preparation.
        self.call(["systemctl", "start", "docker"], "start-docker")
        for key in ("python_image", "redis_image", "node_image"):
            self.call(["docker", "pull", self.manifest["pins"][key]], "pull-" + key, timeout=300)
        # Reuse the existing source-bound kind builder, not old local image tags.
        self.call(
            [
                self.python,
                "-c",
                "from inference_platform.kind_rollout import Campaign; "
                "from pathlib import Path; c=Campaign.__new__(Campaign); "
                "import json; c.pins=json.loads(Path('deploy/k8s/pins.json').read_bytes()); c.build()",
            ],
            "build-kind-images",
            timeout=600,
        )
        # Exercise the built image's real USER before kind can create a cluster.
        self.receipt["fake_tokenizer_self_test"] = {"complete": False}
        row = self.call(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                "--entrypoint",
                "python",
                "mti-fake:stage1",
                "-c",
                "import json,os; from inference_platform.stage_c_tokenizer import pinned_tokenizer; "
                "t=pinned_tokenizer(); n=len(t('stage-c tokenizer preflight')); "
                "assert n==34,n; print(json.dumps({'tokenizer_available':True,"
                "'probe_tokens':n,'uid':os.getuid()}))",
            ],
            "fake-tokenizer-self-test",
            timeout=METADATA_S,
        )
        result = json.loads((self.output / row["log"]).read_bytes())
        if result != {"tokenizer_available": True, "probe_tokens": 34, "uid": 65532}:
            raise RuntimeError("fake_tokenizer_self_test_invalid")
        self.receipt["fake_tokenizer_self_test"] = {"complete": True, "command": row, **result}
        self.receipt["images"] = {}
        for name in (self.image, "mti-gateway:stage1", "mti-fake:stage1", "mti-redis:stage1"):
            row = self.call(
                ["docker", "image", "inspect", name],
                "image-" + str(len(self.receipt["images"])),
                timeout=METADATA_S,
            )
            self.receipt["images"][name] = json.loads((self.output / row["log"]).read_bytes())

    def check(self, name):
        if name not in self.manifest["checks"]:
            raise ValueError("check_not_in_manifest:" + name)
        if name in {"native", "capture"}:
            # Even an unexpectedly preexisting container makes native inadmissible.
            self.call(
                ["sh", "-c", "! pgrep -x dockerd && ! pgrep -x containerd"],
                name + "-no-daemon",
                timeout=METADATA_S,
            )
            if name == "native" and "capture" in self.manifest["checks"]:
                native_path = self.output / "sizing-native.json"
                validate_native_reuse(
                    json.loads((self.output / "capture.json").read_bytes()),
                    json.loads(native_path.read_bytes()),
                    self.manifest["source_commit"],
                    sha(native_path),
                )
            else:
                self.call(
                    self.sizing
                    + ["--output", self.output / "sizing-native.json"]
                    + (
                        ["--capture-receipt", self.output / "capture.json"]
                        if name == "capture"
                        else []
                    ),
                    name,
                    timeout=SIZING_S,
                )
                if name == "capture":
                    native_path = self.output / "sizing-native.json"
                    capture_path = self.output / "capture.json"
                    capture = json.loads(capture_path.read_bytes())
                    validate_native_reuse(
                        capture,
                        json.loads(native_path.read_bytes()),
                        self.manifest["source_commit"],
                        sha(native_path),
                    )
                    capture["host_identity"] = self.receipt["host"]
                    save(capture_path, capture)
        elif name in {"smoke", "constrained"}:
            limit = "256m" if name == "smoke" else "12g"
            manifest = name + "-source.json"
            self.call(
                self.sizing
                + [
                    "--write-source-manifest",
                    self.output / manifest,
                    "--docker-memory",
                    limit,
                    "--docker-memory-swap",
                    limit,
                    "--docker-cpus",
                    "2",
                    "--docker-pids",
                    "128",
                ],
                name + "-manifest",
            )
            if name == "smoke":
                self.call(self.docker(limit, manifest, "--preflight-only"), "smoke-matching")
                mismatch = self.docker(limit, manifest, "--preflight-only")
                mismatch[mismatch.index("--memory") + 1] = "192m"
                self.call(mismatch, "smoke-mismatch", expected="refuse")
                text = (self.output / "smoke-mismatch.log").read_text()
                if "memory.max" not in text or "differs from manifest" not in text:
                    raise ValueError("mismatch_failed_for_wrong_reason")
            else:
                self.constrained_run(limit, manifest)
                self.call(
                    self.sizing
                    + [
                        "--finalize-container-receipt",
                        self.output / "sizing-linux-raw.json",
                        "--source-manifest",
                        self.output / manifest,
                        "--raw-receipt",
                        self.output / "sizing-linux-raw.json",
                        "--output",
                        self.output / "sizing-linux.json",
                    ],
                    "constrained-finalize",
                )
        elif name in {"race", "e2e"}:
            try:
                self.call(
                    [
                        "docker",
                        "run",
                        "-d",
                        "--name",
                        "dec077-redis",
                        "--memory",
                        "512m",
                        "--memory-swap",
                        "512m",
                        "--cpus",
                        "2",
                        "--pids-limit",
                        "128",
                        "-p",
                        "127.0.0.1:26379:6379",
                        self.manifest["pins"]["redis_image"],
                    ],
                    name + "-redis",
                )
                self.call(
                    [
                        "sh",
                        "-c",
                        "i=0; until docker exec dec077-redis redis-cli ping | grep -qx PONG; do "
                        "i=$((i+1)); test $i -lt 20 || exit 1; sleep 1; done",
                    ],
                    name + "-redis-ready",
                    timeout=METADATA_S,
                )
                if name == "race":
                    result = self.call(
                        [
                            "go",
                            "test",
                            "-race",
                            "-v",
                            "-count=1",
                            "-timeout",
                            "240s",
                            "./...",
                        ],
                        "race",
                        timeout=600,
                    )
                    log = (self.output / result["log"]).read_text(encoding="utf-8")
                    try:
                        summary = go_test_summary(log)
                    except GoTestSummaryError as exc:
                        self.receipt["go_real_redis_race"] = {
                            **result,
                            **exc.summary,
                            "complete": False,
                            "redis_addr": self.env["REDIS_TEST_ADDR"],
                        }
                        raise
                    self.receipt["go_real_redis_race"] = {
                        **result,
                        **summary,
                        "complete": True,
                        "redis_addr": self.env["REDIS_TEST_ADDR"],
                    }
                else:
                    result = self.call(
                        [
                            self.python,
                            "-m",
                            "unittest",
                            "test_inf037b_live.GatewayRedisEndToEnd",
                            "-v",
                        ],
                        "e2e",
                        timeout=180,
                    )
                    try:
                        validate_row5_suite_log(self.output / result["log"], expected_tests=1)
                    except ValueError as exc:
                        raise ValueError("e2e_skipped_or_missing") from exc
            finally:
                self.call(
                    ["docker", "rm", "-f", "dec077-redis"],
                    name + "-redis-remove",
                    timeout=METADATA_S,
                )
        elif name == "cpu_validation":
            from .package_a_cpu_validation import run

            run(self)
        elif name == "kind":
            self.call(
                [
                    self.python,
                    "scripts/rehearse_eks_package_a.py",
                    "--output",
                    self.output / "kind",
                    "--gateway-image",
                    "mti-gateway:stage1",
                    "--cluster",
                    "m5-package-a-dec077",
                ],
                "kind",
                timeout=KIND_RUNNER_TIMEOUT_S,
            )
        elif name == "row5":
            receipt = {
                "diagnostic_real_redis": None,
                "linux_suites": None,
                "native_suites": None,
                "kind_rehearsal": None,
            }
            failures = []
            diagnostic_result = self.row5_diagnostic_real_redis()
            receipt["diagnostic_real_redis"] = diagnostic_result
            if diagnostic_result.get("status") != "PASS":
                failures.append(ValueError("row5_diagnostic_real_redis_failed"))
            suite_container_name = self.container_name + "-row5-suites"
            try:
                suite = self.call(
                    [
                        "docker",
                        "run",
                        "--rm",
                        "--name",
                        suite_container_name,
                        "--network",
                        "none",
                        "--memory",
                        "6656m",
                        "--memory-swap",
                        "6656m",
                        "--cpus",
                        "2",
                        "--pids-limit",
                        "128",
                        "--mount",
                        f"type=bind,source={self.repo},target=/repo,readonly",
                        "-e",
                        "PYTHONPATH=/repo/python/src:/repo/python/tests",
                        "-w",
                        "/repo",
                        self.image,
                        "python",
                        "-m",
                        "unittest",
                        "-v",
                        "test_inf037b_row5_capture.DiagnosticSnapshotControlTests.test_refuses_mismatched_result_snapshot_gap_overlap_and_release",
                        "test_inf037b_row5_kind",
                        "test_inf037b_row5_replay",
                        "test_inf037b_row5_live",
                        "test_inf037b_row5_sequence",
                        "test_inf037b_row5",
                        "test_inf037b_fitness",
                        "test_inf037b_preparation_adapter",
                        "test_inf037b_command",
                        "test_package_a_cloud.PackageACloudTests.test_row5_runs_linux_native_and_kind_suites_in_order",
                        "test_package_a_kind_readiness",
                        "scripts.tests.test_rehearse_row5_kind",
                        "test_rehearse_eks_package_a",
                    ],
                    "row5-linux-suites",
                    timeout=ROW5_SUITE_TIMEOUT_S,
                )
                suite.update(validate_row5_suite_log(self.output / suite["log"]))
            except Exception as exc:
                command_path = self.output / "row5-linux-suites.command.json"
                command = json.loads(command_path.read_bytes()) if command_path.is_file() else None
                summary = None
                if (
                    isinstance(command, dict)
                    and isinstance(command.get("exit"), int)
                    and command["exit"] != 0
                    and command.get("log")
                ):
                    try:
                        summary = summarize_failed_row5_suite_log(self.output / command["log"])
                    except OSError:
                        summary = None
                receipt["linux_suites"] = {
                    "status": "FAILED",
                    "command": command,
                    "error": type(exc).__name__,
                    "refusal": str(exc),
                    "summary": summary,
                }
                failures.append(exc)
            else:
                receipt["linux_suites"] = {"status": "PASS", **suite}
            finally:
                cleanup = {"remove_exit": None, "remaining": None}
                try:
                    removed = self.call(
                        ["docker", "rm", "-f", suite_container_name],
                        "row5-linux-suites-remove",
                        timeout=METADATA_S,
                        expected="any",
                    )
                    cleanup["remove_exit"] = removed.get("exit")
                except Exception as exc:
                    failures.append(exc)
                try:
                    remaining_result = self.call(
                        [
                            "docker",
                            "ps",
                            "-aq",
                            "--filter",
                            "name=^/" + suite_container_name + "$",
                        ],
                        "row5-linux-suites-remaining",
                        timeout=METADATA_S,
                        expected=0,
                    )
                    remaining_path = self.output / remaining_result["log"]
                    remaining = remaining_path.read_text(encoding="utf-8", errors="replace").strip()
                    cleanup["remaining"] = remaining
                    if remaining:
                        failures.append(ValueError("row5_suite_container_remaining"))
                except Exception as exc:
                    failures.append(exc)
                receipt["linux_suites"]["container_cleanup"] = cleanup

            native_home = self.output / "row5-native-home"
            native_env = {
                "PATH": "/usr/bin:/bin",
                "HOME": str(native_home),
                "LANG": "C.UTF-8",
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONPATH": f"{self.repo / 'python/src'}:{self.repo / 'python/tests'}",
            }
            try:
                native_home.mkdir()
                if shutil.which("git", path="/usr/bin:/bin") is None:
                    raise ValueError("row5_native_git_missing")
                native = self.execute(
                    [
                        self.python,
                        "-m",
                        "unittest",
                        "-v",
                        "test_rehearse_eks_package_a",
                        "test_package_a_cloud",
                    ],
                    cwd=self.repo,
                    output=self.output / "row5-native-suites.log",
                    env=native_env,
                    timeout=ROW5_NATIVE_SUITE_TIMEOUT_S,
                    expected=0,
                )
                native.update(validate_row5_suite_log(self.output / native["log"]))
            except Exception as exc:
                command_path = self.output / "row5-native-suites.command.json"
                receipt["native_suites"] = {
                    "status": "FAILED",
                    "command": (
                        json.loads(command_path.read_bytes()) if command_path.is_file() else None
                    ),
                    "error": type(exc).__name__,
                    "refusal": str(exc),
                }
                failures.append(exc)
            else:
                receipt["native_suites"] = {"status": "PASS", **native}

            try:
                rehearsal = self.call(
                    [
                        self.python,
                        "scripts/rehearse_row5_kind.py",
                        "--output",
                        self.output / "row5-kind",
                        "--gateway-image",
                        "mti-gateway:stage1",
                        "--cluster",
                        "row5-package-a",
                        "--readiness-timeout",
                        str(ROW5_READINESS_TIMEOUT_S),
                        "--runner-timeout",
                        str(ROW5_KIND_TIMEOUT_S),
                    ],
                    "row5-kind",
                    timeout=ROW5_KIND_TIMEOUT_S,
                )
            except Exception as exc:
                command_path = self.output / "row5-kind.command.json"
                receipt["kind_rehearsal"] = {
                    "status": "FAILED",
                    "command": (
                        json.loads(command_path.read_bytes()) if command_path.is_file() else None
                    ),
                    "error": type(exc).__name__,
                    "refusal": str(exc),
                }
                failures.append(exc)
            else:
                receipt["kind_rehearsal"] = {"status": "PASS", **rehearsal}
            self.receipt["row5"] = receipt
            save(self.output / "runner.json", self.receipt)
            if failures:
                raise failures[0]

    def constrained_run(self, limit, manifest):
        started = utc()
        evidence = {"container_name": self.container_name, "started_at_utc": started}
        row = next(
            (r for r in reversed(self.receipt["checks"]) if r["name"] == "constrained"), None
        )
        if row is not None:
            row["failure_evidence"] = evidence
        try:
            self.call(
                self.docker(
                    limit, manifest, "--output", "/results/sizing-linux-raw.json", retain=True
                ),
                "constrained",
                timeout=SIZING_S,
            )
        finally:
            ended = utc()
            evidence["finished_at_utc"] = ended
            # Probe independently: one failed diagnostic must not prevent cleanup.
            probes = (
                (
                    "inspect_state",
                    ["docker", "inspect", "--format", "{{json .State}}", self.container_name],
                ),
                (
                    "kernel_oom",
                    [
                        "journalctl",
                        "-k",
                        "--since",
                        started,
                        "--until",
                        ended,
                        "--no-pager",
                        "--grep",
                        "(?i)oom",
                    ],
                ),
                ("remove", ["docker", "rm", "-f", self.container_name]),
                (
                    "remaining",
                    ["docker", "ps", "-aq", "--filter", "name=^/" + self.container_name + "$"],
                ),
            )
            for key, argv in probes:
                try:
                    result = self.call(
                        argv, "constrained-" + key, timeout=METADATA_S, expected="any"
                    )
                    path = self.output / result["log"]
                    # Bound retained kernel diagnostics even when journal output is large.
                    if key == "kernel_oom":
                        with path.open("rb") as stream:
                            data = stream.read(65537)
                        path.write_bytes(data[:65536])
                        result["log_sha256"] = sha(path)
                        save(path.with_suffix(".command.json"), result)
                        evidence[key] = {
                            "text": data[:65536].decode("utf-8", errors="replace"),
                            "truncated": len(data) > 65536,
                            "exit": result["exit"],
                        }
                    elif key == "inspect_state":
                        evidence[key] = json.loads(path.read_bytes())
                    elif key == "remaining":
                        evidence["container_gone"] = (
                            result["exit"] == 0 and not path.read_bytes().strip()
                        )
                    else:
                        evidence[key] = result
                except Exception as exc:
                    evidence[key + "_error"] = type(exc).__name__ + ":" + str(exc)
            progress = self.output / "anon-progress.json"
            try:
                evidence["last_progress_peak"] = (
                    json.loads(progress.read_bytes()) if progress.is_file() else None
                )
            except (OSError, ValueError) as exc:
                evidence["last_progress_peak"] = None
                evidence["progress_error"] = type(exc).__name__ + ":" + str(exc)
            save(self.output / "runner.json", self.receipt)
        if not evidence.get("container_gone"):
            raise RuntimeError("constrained_container_cleanup_unverified")

    def run(self):
        self.receipt["source"] = verified_source(
            self.repo, self.manifest["source_commit"], self.manifest["python_sha256"]
        )
        if self.role == "descriptive_operator":
            from .m5_payload_guard import install_read_guard

            install_read_guard(self.repo, self.manifest["source_payload"]["paths"])
            # Bootstrap installed the pinned tools/locked venv. The existing
            # SSM operator invokes bounded descriptive phases afterward.
            self.call(
                ["systemctl", "is-active", "--quiet", "dec077-terminate.timer"],
                "descriptive-os-backstop",
            )
            self.receipt.update(complete=True, role=self.role)
            save(self.output / "runner.json", self.receipt)
            return True
        if self.role == "routine_tests":
            try:
                self.call(
                    [
                        self.python,
                        "scripts/routine_aws_tests.py",
                        "host",
                        "--manifest",
                        "/opt/dec077/runtime.json",
                        "--directory",
                        str(self.output / "routine"),
                    ],
                    "routine-selection",
                    timeout=max(1, self.manifest["deadline_epoch"] - time.time() - 900),
                )
                self.receipt["complete"] = True
            except Exception as error:
                self.receipt.update(complete=False, error=type(error).__name__)
            save(self.output / "runner.json", self.receipt)
            return self.receipt["complete"]
        if self.role == "gate_a_receiver":
            return self.run_gate_a_receiver()
        if self.role == "gate_a_sender":
            return self.run_gate_a_sender()
        self.receipt["host"] = {
            "instance_type": self.manifest["instance_type"],
            "ami": self.manifest["ami"],
            "on_demand_usd_per_hour": self.manifest["on_demand_usd_per_hour"],
            "kernel": platform.release(),
            "platform": platform.platform(),
            "cgroup_controllers": Path("/sys/fs/cgroup/cgroup.controllers").read_text(),
        }
        self.env["PYTHONPATH"] += os.pathsep + str(self.repo / "python/tests")
        images_ready = False
        images_attempted = False
        capture_halted = False
        for name, minimum, combined, budget in self.checks:
            if name == "native" and "capture" in self.manifest["checks"]:
                budget = METADATA_S
            row = {"name": name, "gate_mib": minimum, "combined_mib": combined}
            self.receipt["checks"].append(row)
            try:
                row["sample"] = self.sample()
                # Preparation happens after native and before the next gate sample.
                if (
                    name not in {"native", "capture"}
                    and not images_attempted
                    and not capture_halted
                ):
                    images_attempted = True
                    preparation = {
                        "sample": self.sample(),
                        "budget_s": BUDGETS["prepare_images"],
                        "gate_mib": 6656,
                        "combined_mib": 4608,
                    }
                    self.receipt["prepare_images"] = preparation
                    if not gate(preparation["sample"], 6656, 4608):
                        preparation["status"] = "SKIPPED_GATE"
                    elif time.time() + BUDGETS["prepare_images"] >= self.manifest["deadline_epoch"]:
                        preparation["status"] = "SKIPPED_DEADLINE"
                    else:
                        try:
                            self.prepare_images()
                            images_ready = True
                            preparation["status"] = "PASS"
                        except Exception as exc:
                            preparation.update(status="FAILED", error=str(exc))
                row["sample"] = self.sample()
                row["gate_passed"] = gate(row["sample"], minimum, combined)
                save(self.output / "runner.json", self.receipt)
                if capture_halted:
                    row["status"] = "SKIPPED_CAPTURE_HALT"
                elif not row["gate_passed"]:
                    row["status"] = "SKIPPED_GATE"
                elif name not in {"native", "capture"} and not images_ready:
                    row["status"] = "SKIPPED_PREPARATION_FAILED"
                elif time.time() + budget >= self.manifest["deadline_epoch"]:
                    row["status"] = "SKIPPED_DEADLINE"
                else:
                    self.check(name)
                    row["status"] = "PASS"
            except Exception as exc:
                row["status"], row["error"] = "FAILED", str(exc)
            finally:
                if name == "capture" and row.get("status") != "PASS":
                    capture_halted = True
                    self.receipt["halt"] = "DEC-041 item 2: capture did not pass; no later checks"
                row["finished_at_utc"] = utc()
                save(self.output / "runner.json", self.receipt)
        self.receipt["finished_at_utc"] = utc()
        save(self.output / "runner.json", self.receipt)
        return all(x["status"] == "PASS" for x in self.receipt["checks"])

    def run_gate_a_receiver(self):
        from .inf037b_gate_a import GateAReceiverRole, GateAReceiverSupervisor, _json_safe

        config = dict(self.manifest["gate_a_receiver"])
        self.receipt.update(
            role="gate_a_receiver",
            status="STARTING",
        )
        save(self.output / "runner.json", self.receipt)
        try:
            if config.pop("service", False):
                if config.pop("run_readiness", False):
                    self.run_gate_a_readiness()
                service = GateAReceiverSupervisor(config)
                address = service.start()
                self.receipt["receiver_address"] = [
                    config["private_address"],
                    address[1],
                ]
                self.receipt["status"] = "LISTENING"
                save(self.output / "runner.json", self.receipt)
                self.receipt["gate_a_receiver"] = _json_safe(service.wait())
            else:
                config["receipt_path"] = self.output / "gate-a-receiver.json"
                receiver = GateAReceiverRole(**config)
                address = receiver.start()
                self.receipt["receiver_address"] = list(address)
                self.receipt["status"] = "LISTENING"
                save(self.output / "runner.json", self.receipt)
                self.receipt["gate_a_receiver"] = _json_safe(receiver.finish())
            self.receipt["status"] = "PASS"
        except Exception as exc:
            self.receipt["status"] = "FAILED"
            self.receipt["error"] = type(exc).__name__ + ":" + str(exc)
        self.receipt["finished_at_utc"] = utc()
        save(self.output / "runner.json", self.receipt)
        return self.receipt["status"] == "PASS"

    def run_gate_a_readiness(self):
        """Run the pinned, real-MinIO transfer suite on the receiver before P."""
        from .inf037b_durable_ports import sync_directory

        probe = subprocess.run(
            [
                self.python,
                "-c",
                "import boto3,json,pathlib; print(json.dumps({"
                "'site_packages': str(pathlib.Path(boto3.__file__).resolve().parent.parent), "
                "'version': boto3.__version__}))",
            ],
            cwd=self.repo,
            env=self.env,
            capture_output=True,
            check=True,
            text=True,
            timeout=30,
        )
        boto3_runtime = json.loads(probe.stdout.strip())
        boto3_site_packages = Path(boto3_runtime["site_packages"])
        boto3_version = boto3_runtime["version"]
        if boto3_version != GATE_A_BOTO3_VERSION:
            raise RuntimeError("gate_a:readiness_boto3_version")
        recovery = self.gate_a_recovery_root / "preflight"
        recovery.mkdir(parents=True, exist_ok=False)
        suffix = uuid.uuid4().hex[:12]
        minio_name = "gate-a-ready-minio-" + suffix
        test_name = "gate-a-ready-tests-" + suffix
        access_key = "gate-a-readiness-access"
        secret_key = "gate-a-readiness-secret-123456"
        test_bucket = "gate-a-ready-" + suffix
        minio_started = False
        test_result = None
        failures = []
        try:
            self.call(["systemctl", "start", "docker"], "gate-a-ready-docker")
            self.call(["docker", "pull", self.image], "gate-a-ready-python-image", timeout=600)
            self.call(
                ["docker", "pull", GATE_A_MINIO_IMAGE], "gate-a-ready-minio-image", timeout=600
            )
            self.call(
                [
                    "docker",
                    "run",
                    "--detach",
                    "--rm",
                    "--name",
                    minio_name,
                    "--publish",
                    "127.0.0.1:9000:9000",
                    "--env",
                    "MINIO_ROOT_USER=" + access_key,
                    "--env",
                    "MINIO_ROOT_PASSWORD=" + secret_key,
                    GATE_A_MINIO_IMAGE,
                    "server",
                    "/data",
                    "--console-address",
                    ":9001",
                ],
                "gate-a-ready-minio-start",
                timeout=120,
            )
            minio_started = True
            self.call(
                [
                    "sh",
                    "-c",
                    "i=0; until curl -fsS --max-time 2 "
                    "http://127.0.0.1:9000/minio/health/ready >/dev/null; do "
                    "i=$((i+1)); test $i -lt 60 || exit 1; sleep 1; done",
                ],
                "gate-a-ready-minio-health",
                timeout=METADATA_S,
            )
            argv = [
                "docker",
                "run",
                "--rm",
                "--name",
                test_name,
                "--network",
                "host",
                "--memory",
                "6144m",
                "--memory-swap",
                "6144m",
                "--cpus",
                "2",
                "--pids-limit",
                "128",
                "--mount",
                f"type=bind,source={self.repo},target=/repo,readonly",
                "--mount",
                f"type=bind,source={boto3_site_packages},target=/gate-a-host-site-packages,readonly",
                "--mount",
                f"type=bind,source={recovery},target=/recovery/preflight",
            ]
            for key, value in (
                (
                    "PYTHONPATH",
                    "/repo/scripts:/repo/python/src:/repo/python/tests:/gate-a-host-site-packages",
                ),
                ("PYTHONDONTWRITEBYTECODE", "1"),
                ("S3_ENDPOINT_URL", "http://127.0.0.1:9000"),
                ("MINIO_TEST_ENDPOINT", "http://127.0.0.1:9000"),
                ("MINIO_TEST_ACCESS_KEY", access_key),
                ("MINIO_TEST_SECRET_KEY", secret_key),
                ("S3_TEST_BUCKET", test_bucket),
                ("AWS_ACCESS_KEY_ID", access_key),
                ("AWS_SECRET_ACCESS_KEY", secret_key),
                ("AWS_DEFAULT_REGION", "us-east-1"),
                ("TRANSFER_RESTART_PHASE", "during"),
                ("RECOVERY_ROOT", "/recovery/preflight"),
            ):
                argv.extend(("-e", key + "=" + value))
            argv.extend(("-w", "/repo", self.image, "python", "-m", "unittest", "-v"))
            argv.extend(GATE_A_READINESS_MODULES)
            test_result = self.call(argv, "gate-a-readiness-suites", timeout=3600)
            output = (self.output / test_result["log"]).read_text(
                encoding="utf-8", errors="replace"
            )
            match = re.search(r"Ran (\d+) tests? in ([0-9.]+)s", output)
            if match is None or "OK" not in output:
                raise RuntimeError("gate_a:readiness_test_summary")
            skipped = re.search(r"OK \(skipped=(\d+)\)", output)
            self.receipt["gate_a_readiness"] = {
                "status": "PASS",
                "modules": list(GATE_A_READINESS_MODULES),
                "passed": int(match.group(1)) - (int(skipped.group(1)) if skipped else 0),
                "skipped": int(skipped.group(1)) if skipped else 0,
                "elapsed_seconds": float(match.group(2)),
                "python_image": self.image,
                "minio_image": GATE_A_MINIO_IMAGE,
                "boto3_dependency": {
                    "version": boto3_version,
                    "host_site_packages": str(boto3_site_packages),
                    "container_source": "/gate-a-host-site-packages/boto3/__init__.py",
                    "lock_source": "python/pyproject.toml boto3==1.43.123; python/uv.lock boto3 1.43.123",
                },
                "minio_removed": True,
                "recovery_test_root_removed": True,
                "source_mount_read_only": True,
            }
            save(self.output / "runner.json", self.receipt)
        except BaseException as exc:
            failures.append(type(exc).__name__ + ":" + str(exc))
        finally:
            try:
                cleanup = self.call(
                    ["docker", "rm", "--force", test_name],
                    "gate-a-ready-test-remove",
                    expected="any",
                )
                if cleanup["exit"] not in {0, 1}:
                    failures.append("test_container_cleanup:exit_" + str(cleanup["exit"]))
            except BaseException as exc:
                failures.append("test_container_cleanup:" + type(exc).__name__)
            if minio_started:
                try:
                    cleanup = self.call(
                        ["docker", "rm", "--force", minio_name],
                        "gate-a-ready-minio-remove",
                        expected="any",
                    )
                    if cleanup["exit"] not in {0, 1}:
                        failures.append("minio_cleanup:exit_" + str(cleanup["exit"]))
                except BaseException as exc:
                    failures.append("minio_cleanup:" + type(exc).__name__)
            try:
                shutil.rmtree(recovery)
                if os.name == "posix":
                    sync_directory(recovery.parent)
            except BaseException as exc:
                failures.append("recovery_cleanup:" + type(exc).__name__)
        if failures:
            self.receipt["gate_a_readiness"] = {
                "status": "FAILED",
                "errors": failures,
                "test": test_result,
                "minio_image": GATE_A_MINIO_IMAGE,
            }
            save(self.output / "runner.json", self.receipt)
            raise RuntimeError("gate_a:readiness_failed:" + ";".join(failures))

    def run_gate_a_sender(self):
        from .inf037b_gate_a import GateASenderRole

        self.receipt.update(role="gate_a_sender", status="RUNNING")
        save(self.output / "runner.json", self.receipt)
        try:
            self.receipt["gate_a_sender"] = GateASenderRole(
                self.manifest["gate_a_sender"], self.output
            ).run()
            self.receipt["status"] = self.receipt["gate_a_sender"]["status"]
        except Exception as exc:
            self.receipt["status"] = "FAILED"
            self.receipt["error"] = type(exc).__name__ + ":" + str(exc)
        self.receipt["finished_at_utc"] = utc()
        save(self.output / "runner.json", self.receipt)
        return self.receipt["status"] == "PASS"


class Halt(RuntimeError):
    pass


class Lifecycle:
    """All operations from the first possible billable effect share one finally.

    Ports' individual calls must be interruptible and bounded by the supplied
    absolute deadline. Cleanup has a separate original-deadline reserve.
    """

    def __init__(self, ports, manifest, output, *, clock=time.time):
        self.ports, self.manifest, self.output, self.clock = ports, manifest, Path(output), clock
        phase_names = (
            "apply",
            "bootstrap",
            "readiness",
            "upload",
            "staging",
            "run_checks",
            "retrieve",
            "teardown",
            "inventory",
        )
        self.receipt = {
            "schema": "dec077-final-v1",
            "events": [],
            "complete": False,
            "phases": {
                name: {
                    "status": "NOT_RUN",
                    "monotonic_start_ns": None,
                    "monotonic_end_ns": None,
                }
                for name in phase_names
            },
        }
        self.receipt["binding"] = {
            key: manifest.get(key)
            for key in (
                "source_commit",
                "instance_type",
                "ami",
                "on_demand_usd_per_hour",
                "sealed_plans",
            )
        }
        self.receipt["cost_method"] = (
            "Conservative duration-based task upper bound (min 60s compute plus storage, IPv4 and $1 fixed other cost); cumulative adds prior spend; cap checks add the separate cleanup reserve; bill reconciliation remains separate"
        )
        self.ports.phase_runner = self.measure_phase

    def measure_phase(self, name, operation):
        row = self.receipt["phases"][name]
        if row["status"] != "NOT_RUN":
            raise Halt("phase_already_recorded:" + name)
        row["status"] = "RUNNING"
        row["monotonic_start_ns"] = time.monotonic_ns()
        save(self.output / "lifecycle.json", self.receipt)
        try:
            result = operation()
        except BaseException:
            row["status"] = "FAILED"
            raise
        else:
            row["status"] = "PASS"
            return result
        finally:
            row["monotonic_end_ns"] = time.monotonic_ns()
            save(self.output / "lifecycle.json", self.receipt)

    def checkpoint(self):
        now = self.clock()
        if now >= self.end - CLEANUP_S - transfer_seconds(EXPORT_MAX_BYTES):
            raise Halt("deadline_reserve")
        task_cost = self.ports.task_cost(self.start, now)
        cumulative_cost = self.ports.cumulative_cost(self.start, now)
        self.receipt["task_cost_usd"] = task_cost
        self.receipt["cumulative_cost_usd"] = cumulative_cost
        if cumulative_cost + self.manifest["cleanup_cost_reserve_usd"] >= CAP_USD:
            raise Halt("cost_cap")

    def call(self, name):
        self.checkpoint()
        self.receipt["events"].append(name)
        save(self.output / "lifecycle.json", self.receipt)
        result = self.measure_phase(
            name,
            lambda: getattr(self.ports, name)(
                self.end - CLEANUP_S - transfer_seconds(EXPORT_MAX_BYTES)
            ),
        )
        self.checkpoint()
        return result

    def run(self):
        self.output.mkdir(parents=True, exist_ok=True)
        self.start = self.clock()  # Conservatively before Apply, never after creation.
        self.end = self.start + DEADLINE_S
        self.receipt.update(first_possible_billable_at_epoch=self.start, deadline_epoch=self.end)
        try:
            # Durable origin BEFORE the first possible billable call.
            save(self.output / "lifecycle.json", self.receipt)
            for name in ("apply", "bootstrap", "upload", "run_checks"):
                self.call(name)
        except BaseException as exc:
            self.receipt["halt"] = type(exc).__name__ + ":" + str(exc)
        finally:
            # Retrieval and cancellation are attempted independently. Neither a
            # broken tunnel nor a damaged receipt can bypass resource cleanup.
            for name, end in (
                ("retrieve", self.end - CLEANUP_S),
                ("teardown", self.end),
                ("inventory", self.end),
            ):
                try:
                    self.receipt["events"].append(name)
                    self.receipt[name] = self.measure_phase(
                        name, lambda name=name, end=end: getattr(self.ports, name)(end)
                    )
                except BaseException as exc:
                    self.receipt[name] = {"error": type(exc).__name__ + ":" + str(exc)}
            final_now = self.clock()
            self.receipt["task_cost_usd"] = self.ports.task_cost(self.start, final_now)
            self.receipt["cumulative_cost_usd"] = self.ports.cumulative_cost(self.start, final_now)
            self.receipt["counts_against_ceiling_usd"] = 300
            self.receipt["complete"] = (
                "halt" not in self.receipt
                and self.receipt.get("inventory", {}).get("empty") is True
                and self.receipt.get("teardown", {}).get("destroy_completed") is True
                and self.receipt.get("retrieve", {}).get("complete") is True
                and self.receipt["cumulative_cost_usd"] <= CAP_USD
                and self.clock() <= self.end
            )
            save(self.output / "lifecycle.json", self.receipt)
        return self.receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_bytes())
    role_interpreter = gate_a_role_reexec_target(manifest)
    if role_interpreter is not None:
        os.execvpe(
            role_interpreter,
            [
                role_interpreter,
                "-m",
                "inference_platform.package_a_cloud",
                *sys.argv[1:],
            ],
            os.environ.copy(),
        )
    raise SystemExit(0 if Runner(args.repo, args.output, manifest).run() else 1)


def gate_a_role_reexec_target(manifest):
    """Return the locked venv for Gate A roles, or require it is already active."""
    if manifest.get("role") not in {"gate_a_receiver", "gate_a_sender", "descriptive_operator"}:
        return None
    target = manifest.get("python_executable")
    if not isinstance(target, str) or not Path(target).is_absolute():
        raise ValueError("gate_a:locked_python_executable")
    target = os.path.abspath(target)
    current = os.path.abspath(sys.executable)
    if current != target:
        return target
    if sys.prefix == sys.base_prefix:
        raise RuntimeError("gate_a:role_requires_locked_venv")
    return None


if __name__ == "__main__":
    main()
