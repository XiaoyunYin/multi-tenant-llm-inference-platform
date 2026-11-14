"""Small real-emitter states for the dedicated read-only CPU-host case."""

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

RACE_SPOOLS = 48


def race(root):
    """One process, one emitter/event/clean close per independent spool."""
    from inference_platform.inf037b_native import NativeEmitter

    root.mkdir()
    emitters = []
    try:
        for index in range(RACE_SPOOLS):
            directory = root / str(index)
            directory.mkdir()
            origin = {
                "pod_uid": "race-" + str(index),
                "supervisor_pid": os.getpid(),
                "supervisor_start": Path("/proc/self/stat")
                .read_text()
                .rsplit(")", 1)[1]
                .split()[19],
            }
            emitter = NativeEmitter(directory, origin)
            emitter.observe("installed", "input", "a" * 64)
            if emitter.failed:
                raise ValueError("native_readonly:race_writer_failed")
            emitters.append(emitter)
        (root / "current").write_text("0")
        (root / "ready").write_text(str(RACE_SPOOLS))
        for index, emitter in enumerate(emitters):
            current = root / "current.next"
            current.write_text(str(index))
            os.replace(current, root / "current")
            # The reader loops this spool while its single close checkpoints.
            time.sleep(0.25)
            emitter.close()
        (root / "complete").write_text(str(RACE_SPOOLS))
    finally:
        for emitter in emitters:
            if not emitter.closed:
                emitter.close()


def write(root, state):
    from inference_platform.inf037b_native import NativeEmitter

    root.mkdir()
    origin = {
        "pod_uid": state,
        "supervisor_pid": os.getpid(),
        "supervisor_start": Path("/proc/self/stat")
        .read_text()
        .rsplit(")", 1)[1]
        .split()[19],
    }
    emitter = NativeEmitter(root, origin)
    emitter.observe("installed", "input", "a" * 64)
    if emitter.failed:
        raise ValueError("native_readonly:writer_failed")
    (root / "ready").write_text("committed")
    if state == "closed":
        emitter.close()
    else:
        time.sleep(150)


def prepare(root):
    children = []
    try:
        for state in ("open", "closed", "killed"):
            process = subprocess.Popen(
                [
                    sys.executable,
                    __file__,
                    "--write",
                    state,
                    "--root",
                    str(root / state),
                ],
                start_new_session=True,
            )
            children.append(process)
            deadline = time.monotonic() + 5
            while not (root / state / "ready").exists():
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise ValueError("native_readonly:writer_not_ready:" + state)
                time.sleep(0.01)
            if state == "closed":
                if process.wait(timeout=5) != 0:
                    raise ValueError("native_readonly:close_failed")
            elif state == "killed":
                os.kill(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
        process = subprocess.Popen(
            [sys.executable, __file__, "--race", "--root", str(root / "race")],
            start_new_session=True,
        )
        children.append(process)
        deadline = time.monotonic() + 5
        while not (root / "race/ready").exists():
            if process.poll() is not None or time.monotonic() >= deadline:
                raise ValueError("native_readonly:race_not_ready")
            time.sleep(0.01)
        print(
            json.dumps({"native_readonly_prepared": ["open", "closed", "killed"]}),
            flush=True,
        )
    except BaseException:
        for process in children:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
        raise
    # Writer processes belong to the target container, removed at stage cleanup.


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--write", choices=("open", "closed", "killed"))
    parser.add_argument("--race", action="store_true")
    args = parser.parse_args()
    if args.race:
        race(args.root)
    elif args.write:
        write(args.root, args.write)
    else:
        prepare(args.root)


if __name__ == "__main__":
    main()
