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


def bounded_apply(argv: list[str], receipt: Path, seconds: float = 600, grace: float = 10) -> int:
    """Tee both streams without blocking the deadline on a silent provider retry."""
    if not 0 < seconds <= 600 or not 0 < grace <= 10:
        raise ValueError("apply deadline must be <=600s, interrupt grace <=10s")
    receipt.unlink(missing_ok=True)
    started = time.monotonic()
    child = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="backslashreplace",
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
        start_new_session=os.name != "nt",
    )
    lines = queue.Queue()

    def drain(stream):
        for line in stream:
            lines.put(line)
        stream.close()

    readers = [
        threading.Thread(target=drain, args=(stream,), daemon=True)
        for stream in (child.stdout, child.stderr)
    ]
    for reader in readers:
        reader.start()
    capacity = False
    deadline_hit = False
    interrupted_at = None
    forced = False
    try:
        while (
            child.poll() is None
            or any(reader.is_alive() for reader in readers)
            or not lines.empty()
        ):
            try:
                line = lines.get(timeout=0.05)
                capacity |= bool(CAPACITY.search(line))
                print(line.rstrip("\r\n"), flush=True)
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
                    capacity |= bool(CAPACITY.search(line))
                    print(line.rstrip("\r\n"), flush=True)
                break
        code = child.wait(timeout=grace)
    finally:
        if child.poll() is None:
            stop_forward(child)
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
