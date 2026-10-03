"""Stop one recorded helper PID, without shell interpolation or process-name matching."""

import argparse
import ctypes
import os
import signal
import subprocess
from pathlib import Path


def stop_child(child: subprocess.Popen, timeout: float = 5) -> dict:
    """Stop and reap an owned child, including an already exited zombie."""
    if child.poll() is None:
        child.terminate()
    try:
        return_code = child.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        child.kill()
        return_code = child.wait(timeout=timeout)
    return {"pid": child.pid, "status": "stopped", "reaped": True, "returncode": return_code}


def stop_forward(child: subprocess.Popen) -> dict:
    """The AWS CLI owns a plugin child; terminate the forward's process tree too."""
    if os.name == "nt":
        if child.poll() is None:
            subprocess.run(
                ["taskkill", "/PID", str(child.pid), "/T", "/F"],
                capture_output=True,
                check=False,
                timeout=5,
            )
    else:
        # Forward Popen creates a new session, so its group contains only its own
        # AWS/plugin descendants, even when the AWS CLI parent has already exited.
        try:
            os.killpg(child.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    return stop_child(child)


def pid_is_running(pid: int) -> bool:
    """Non-child Linux fallback: a zombie is stopped, although /proc still exists."""
    if os.name == "posix" and Path("/proc").exists():
        try:
            state = (Path("/proc") / str(pid) / "stat").read_text().rpartition(") ")[2].split()[0]
            return state not in ("Z", "X")
        except (OSError, IndexError):
            return False
    if os.name == "nt":
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.restype = ctypes.c_void_p
        kernel.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        handle = kernel.OpenProcess(0x1000, False, pid)
        if not handle:
            return False
        try:
            code = ctypes.c_ulong()
            if not kernel.GetExitCodeProcess(handle, ctypes.byref(code)):
                raise OSError(ctypes.get_last_error(), "GetExitCodeProcess")
            return code.value == 259  # STILL_ACTIVE, rather than mere handle existence.
        finally:
            kernel.CloseHandle(handle)
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def stop_pid_file(path: Path) -> int:
    text = path.read_text(encoding="utf-8").strip()
    if not text.isdecimal():
        raise ValueError("helper PID file must contain one decimal PID")
    pid = int(text)
    if pid <= 1 or pid == os.getpid():
        raise ValueError("refusing invalid or own helper PID")
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass  # Already stopped; idempotent cleanup.
    return pid


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid-file", type=Path, required=True)
    args = parser.parse_args()
    stop_pid_file(args.pid_file)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
