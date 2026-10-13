"""Wall-clock guard for the wrapper's child apply; never generates a plan."""

from __future__ import annotations

import argparse
import os
import queue
import re
import signal
import subprocess
import threading
import time
from pathlib import Path

from .session_stop import stop_forward
from .stage_c_session import write_json

CAPACITY = re.compile(
    r"InsufficientInstanceCapacity|InsufficientHostCapacity|insufficient capacity", re.I
)
CAPACITY_CODE = re.compile(r"(?:Server\.)?(Insufficient(?:Instance|Host)Capacity)", re.I)
ZONE = re.compile(r"\b(?:us|ap|eu|sa|ca|me|af)-[a-z]+-\d[a-z]\b", re.I)


def bounded_apply(
    argv: list[str],
    receipt: Path,
    seconds: float = 600,
    grace: float = 10,
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    stdout_path: Path | None = None,
    stderr_path: Path | None = None,
) -> int:
    """Tee both streams without blocking the deadline on a silent provider retry."""
    if not 0 < seconds <= 600 or not 0 < grace <= 10:
        raise ValueError("apply deadline must be <=600s, interrupt grace <=10s")
    receipt.unlink(missing_ok=True)
    started = time.monotonic()
    receipt.parent.mkdir(parents=True, exist_ok=True)
    for path in (stdout_path, stderr_path):
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
    stdout_log = stdout_path.open("wb") if stdout_path else None
    stderr_log = stderr_path.open("wb") if stderr_path else None
    try:
        child = subprocess.Popen(
            argv,
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
            start_new_session=os.name != "nt",
        )
    except BaseException:
        if stdout_log is not None:
            stdout_log.close()
        if stderr_log is not None:
            stderr_log.close()
        raise
    lines = queue.Queue()

    def drain(stream, output_log):
        for raw_line in stream:
            if output_log is not None:
                output_log.write(raw_line)
                output_log.flush()
            lines.put(raw_line)
        stream.close()

    readers = [
        threading.Thread(target=drain, args=(stream, output_log), daemon=True)
        for stream, output_log in ((child.stdout, stdout_log), (child.stderr, stderr_log))
    ]
    for reader in readers:
        reader.start()
    capacity = False
    capacity_error_count = 0
    capacity_codes = set()
    zones = set()
    deadline_hit = False
    interrupted_at = None
    forced = False

    def observe(raw_line):
        nonlocal capacity, capacity_error_count
        line = raw_line.decode("utf-8", errors="backslashreplace")
        matches = list(CAPACITY.finditer(line))
        if not matches:
            return
        capacity = True
        capacity_error_count += len(matches)
        for match in CAPACITY_CODE.finditer(line):
            token = match.group(1).lower()
            capacity_codes.add(
                "InsufficientInstanceCapacity"
                if "instance" in token
                else "InsufficientHostCapacity"
            )
        zones.update(match.group(0) for match in ZONE.finditer(line))

    try:
        while (
            child.poll() is None
            or any(reader.is_alive() for reader in readers)
            or not lines.empty()
        ):
            try:
                line = lines.get(timeout=0.05)
                observe(line)
                print(line.decode("utf-8", errors="backslashreplace").rstrip("\r\n"), flush=True)
            except queue.Empty:
                pass
            now = time.monotonic()
            if child.poll() is None and not deadline_hit and now - started >= seconds:
                deadline_hit = True
                interrupted_at = now
                print("apply wall-clock deadline reached; interrupting Terraform", flush=True)
                try:
                    if os.name == "nt":
                        child.send_signal(signal.CTRL_BREAK_EVENT)
                    else:
                        os.killpg(child.pid, signal.SIGINT)
                except (OSError, ProcessLookupError):
                    pass
            if deadline_hit and not forced and now - interrupted_at >= grace:
                forced = True
                stop_forward(child)
                for reader in readers:
                    reader.join(timeout=1)
                while not lines.empty():
                    line = lines.get_nowait()
                    observe(line)
                    print(
                        line.decode("utf-8", errors="backslashreplace").rstrip("\r\n"), flush=True
                    )
                break
        code = child.wait(timeout=grace)
    finally:
        if child.poll() is None:
            stop_forward(child)
        if stdout_log is not None:
            stdout_log.close()
        if stderr_log is not None:
            stderr_log.close()
    reason = (
        ("capacity" if capacity else "apply_deadline")
        if deadline_hit
        else ("capacity" if capacity and code != 0 else "terraform_error" if code else "completed")
    )
    result = {
        "schema": "inf011-terraform-apply-watchdog.v1",
        "abort_reason": reason,
        "deadline_exceeded": deadline_hit,
        "capacity_error_observed": capacity,
        "capacity_error_count": capacity_error_count,
        "capacity_error_codes": sorted(capacity_codes),
        "availability_zones": sorted(zones),
        "elapsed_seconds": time.monotonic() - started,
        "wall_clock_limit_seconds": seconds,
        "interrupt_grace_seconds": grace,
        "forced_process_tree_stop": forced,
        "child_exit_code": code,
        "destroy_requested": deadline_hit or code != 0,
        "verify_teardown_requested": deadline_hit or code != 0,
    }
    write_json(receipt, result)
    if deadline_hit:
        print(
            f"infrastructure abort: {reason}; run Destroy and VerifyTeardown; no retry", flush=True
        )
        return 124
    return code


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--seconds", type=float, default=600)
    parser.add_argument("--grace", type=float, default=10)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("child argv required")
    return bounded_apply(command, args.receipt, args.seconds, args.grace)


if __name__ == "__main__":
    raise SystemExit(main())
