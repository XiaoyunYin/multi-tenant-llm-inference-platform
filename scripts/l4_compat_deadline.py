"""Independent controller hard stop around a separately approved driver.

The child is the existing operator/SSM workflow with this packet's host command.
Arm BEFORE its first possible provider action. On exit or cutoff kill the whole
child group before the exact prepared cleanup argv, then inventory argv. These
are supplied as a reviewed JSON file, never shell text. This module is also
rehearsed with harmless local child/cleanup/inventory commands at $0.
"""

import argparse
import json
import os
import signal
import subprocess
import time
import uuid
from pathlib import Path

from inference_platform.package_a_cloud import save
from inference_platform.session_stop import stop_forward


def fenced_stop(process):
    if os.name == "nt":
        stop_forward(process)
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)


def supervise(
    commands, output, *, work_seconds=3600, cleanup_seconds=600, origin_epoch=None
):
    output.mkdir(parents=True, exist_ok=True)
    lock = output / "supervisor.lock"
    with lock.open("x") as stream:
        stream.write(str(os.getpid()))
        stream.flush()
        os.fsync(stream.fileno())
    packet_lock = None
    try:
        controller = commands["controller"]
        if "--directory" in controller:
            directory = Path(controller[controller.index("--directory") + 1])
            candidate = directory / "supervisor.lock"
            with candidate.open("x") as stream:
                stream.write(str(os.getpid()))
                stream.flush()
                os.fsync(stream.fileno())
            packet_lock = candidate
        return _supervise(
            commands,
            output / ("attempt-" + uuid.uuid4().hex),
            work_seconds=work_seconds,
            cleanup_seconds=cleanup_seconds,
            origin_epoch=origin_epoch,
        )
    finally:
        if packet_lock is not None:
            packet_lock.unlink()
        lock.unlink()


def _supervise(commands, output, *, work_seconds, cleanup_seconds, origin_epoch=None):
    if work_seconds <= 0 or cleanup_seconds <= 0:
        raise ValueError("l4:independent_supervisor")
    output.mkdir(parents=True, exist_ok=False)
    origin = time.time() if origin_epoch is None else origin_epoch
    age = time.time() - origin
    if not 0 <= age < work_seconds:
        raise ValueError("l4:independent_supervisor_origin")
    mono = time.monotonic() - age
    receipt = {
        "t0_epoch": origin,
        "deadline_epoch": origin + work_seconds + cleanup_seconds,
        "work_stop_epoch": origin + work_seconds,
        "complete": False,
        "attempt_directory": str(output.resolve()),
        "stages": {},
    }
    save(
        output / "deadline.json", receipt
    )  # durable before child can create resources.
    environment = {
        **os.environ,
        "L4_T0_EPOCH": str(origin),
        "L4_ATTEMPT_DIRECTORY": str(output.resolve()),
    }
    process = None
    try:
        with (output / "controller.log").open("wb") as log:
            stage_start = time.monotonic()
            process = subprocess.Popen(
                commands["controller"],
                env=environment,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=os.name != "nt",
            )
            receipt["controller_pid"] = process.pid
            try:
                receipt["controller_exit"] = process.wait(
                    timeout=max(0.001, mono + work_seconds - time.monotonic())
                )
            except subprocess.TimeoutExpired:
                receipt["cutoff"] = True
            finally:
                receipt["stages"]["controller"] = {
                    "exit_code": receipt.get("controller_exit"),
                    "elapsed_seconds": time.monotonic() - stage_start,
                }
    finally:
        if process is not None:
            fenced_stop(process)
        # Reserve inventory time even if destroy hangs. No cleanup extension.
        cleanup_end = min(
            mono + work_seconds + cleanup_seconds, time.monotonic() + cleanup_seconds
        )
        for name, reserve in (
            ("cleanup", min(60, cleanup_seconds / 2)),
            ("inventory", 0),
        ):
            left = cleanup_end - time.monotonic() - reserve
            stage_start = time.monotonic()
            try:
                with (output / (name + ".log")).open("wb") as log:
                    child = subprocess.Popen(
                        commands[name],
                        stdout=log,
                        stderr=subprocess.STDOUT,
                        env=environment,
                        start_new_session=os.name != "nt",
                    )
                    try:
                        receipt[name + "_exit"] = child.wait(timeout=max(0.001, left))
                    finally:
                        fenced_stop(child)
            except Exception as exc:
                receipt[name + "_error"] = str(exc)
            finally:
                receipt["stages"][name] = {
                    "exit_code": receipt.get(name + "_exit"),
                    "elapsed_seconds": time.monotonic() - stage_start,
                }
        receipt["elapsed_seconds"] = time.monotonic() - mono
        receipt["complete"] = (
            receipt.get("controller_exit") == 0
            and receipt.get("cleanup_exit") == 0
            and receipt.get("inventory_exit") == 0
        )
        save(output / "deadline.json", receipt)
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--commands", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    raise SystemExit(
        0
        if supervise(json.loads(args.commands.read_bytes()), args.output)["complete"]
        else 1
    )
