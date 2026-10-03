"""Bounded same-host readiness wait anchored to the persisted termination epoch."""

from __future__ import annotations

import json
import subprocess
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path

from .clocks import measurement_clocks
from .session_stop import pid_is_running


def last_log_line(path: Path) -> str:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        return lines[-1] if lines else "(empty gateway log)"
    except OSError:
        return "(gateway log unavailable)"


def check_processes(gateway, backend_alive: Callable[[], bool], gateway_log: Path) -> None:
    if gateway.poll() is not None:
        raise RuntimeError(f"gateway exited ({gateway.returncode}): {last_log_line(gateway_log)}")
    if not backend_alive():
        raise RuntimeError("vLLM process exited during readiness")


def health_probe(url: str, timeout: float) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return response.status == 200
    except (OSError, urllib.error.URLError):
        return False


def readiness_window(
    epoch,
    minimum_useful_run_seconds,
    export_margin_seconds,
    *,
    clock=time.perf_counter,
    wall_clock=time.time,
):
    wall, mono = wall_clock(), clock()
    deadline_epoch = (
        epoch["instance_termination_unix_s"]
        - export_margin_seconds
        - sum(minimum_useful_run_seconds)
    )
    return mono + deadline_epoch - wall, {
        "status": "waiting",
        "epoch": epoch,
        "measurement_clocks": measurement_clocks(wall_clock=True),
        "readiness_deadline_unix_s": deadline_epoch,
        "deadline_clock_pair": {"unix_s": wall, "perf_counter_s": mono},
        "minimum_useful_run_seconds": list(minimum_useful_run_seconds),
        "attempts": [],
    }


def wait_startup(
    epoch, minima, margin, probe, *, clock=time.perf_counter, wall_clock=time.time, sleep=time.sleep
):
    """Poll a startup prerequisite in the same absolute readiness window as health."""
    deadline, receipt = readiness_window(epoch, minima, margin, clock=clock, wall_clock=wall_clock)
    backoff = 0.25
    while clock() < deadline:
        attempt = {"unix_s": wall_clock(), "perf_counter_s": clock()}
        try:
            attempt.update(probe(min(10, deadline - clock())))
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            attempt.update(ready=False, error=str(error))
        receipt["attempts"].append(attempt)
        if attempt.get("ready") and clock() < deadline:
            receipt.update(status="ready", observed_readiness_unix_s=wall_clock())
            return receipt
        sleep(max(0, min(backoff, deadline - clock())))
        backoff = min(backoff * 2, 5)
    receipt.update(status="deadline_expired", reason="skipped_readiness_deadline")
    receipt["timed_runs"] = [
        {"run": i + 1, "status": "skipped_readiness_failure", "reason": receipt["reason"]}
        for i in range(4)
    ]
    return receipt


def inspect_container(timeout):
    result = subprocess.run(
        ["docker", "inspect", "--format", "{{json .State}}", "inf011-vllm"],
        capture_output=True,
        text=True,
        check=False,
        timeout=timeout,
    )
    state = json.loads(result.stdout) if result.returncode == 0 else {}
    return {
        "ready": bool(state.get("Running") and state.get("Pid", 0) > 0),
        "state": state,
        "returncode": result.returncode,
        "stderr": result.stderr,
    }


def wait_readiness(
    epoch: dict,
    minimum_useful_run_seconds: tuple[float, ...],
    export_margin_seconds: float,
    endpoints: tuple[str, ...],
    check_alive: Callable[[], None],
    *,
    clock: Callable[[], float] = time.perf_counter,
    wall_clock: Callable[[], float] = time.time,
    sleep: Callable[[float], None] = time.sleep,
    probe: Callable[[str, float], bool] = health_probe,
) -> dict:
    """No run starts after the latest instant that all minimum durations fit."""
    deadline, receipt = readiness_window(
        epoch,
        minimum_useful_run_seconds,
        export_margin_seconds,
        clock=clock,
        wall_clock=wall_clock,
    )
    backoff = 0.25
    while True:
        try:
            check_alive()
        except RuntimeError as error:
            receipt.update(status="process_exited", reason=str(error))
            break
        if clock() >= deadline:
            receipt.update(status="deadline_expired", reason="skipped_readiness_deadline")
            break
        attempt = {"unix_s": wall_clock(), "perf_counter_s": clock(), "endpoints": []}
        ready = True
        for endpoint in endpoints:
            check_alive_error = None
            try:
                check_alive()
            except RuntimeError as error:
                check_alive_error = str(error)
            if check_alive_error:
                receipt.update(status="process_exited", reason=check_alive_error)
                ready = False
                break
            remaining = deadline - clock()
            healthy = remaining > 0 and probe(endpoint, min(1.0, remaining))
            attempt["endpoints"].append({"url": endpoint, "healthy": healthy})
            ready &= healthy
        receipt["attempts"].append(attempt)
        if receipt["status"] == "process_exited":
            break
        try:
            check_alive()
        except RuntimeError as error:
            receipt.update(status="process_exited", reason=str(error))
            break
        if ready and clock() < deadline:
            receipt.update(status="ready", observed_readiness_unix_s=wall_clock())
            break
        sleep(max(0, min(backoff, deadline - clock())))
        backoff = min(backoff * 2, 5.0)
    if receipt["status"] != "ready":
        receipt["timed_runs"] = [
            {"run": index + 1, "status": "skipped_readiness_failure", "reason": receipt["reason"]}
            for index in range(4)
        ]
    return receipt


def linux_backend_alive(pid: int) -> bool:
    return pid_is_running(pid)


def read_epoch(path: Path) -> dict:
    epoch = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(epoch, int):
        epoch = {
            "instance_termination_unix_s": epoch,
            "instance_boot_unix_s": epoch - 14400,
            "basis": "persisted /etc/inf011/deadline_epoch minus approved max_session_hours=4",
        }
    boot, termination = epoch["instance_boot_unix_s"], epoch["instance_termination_unix_s"]
    if not 0 < termination - boot <= 14400:
        raise ValueError("persisted termination epoch exceeds four-hour session limit")
    return epoch
