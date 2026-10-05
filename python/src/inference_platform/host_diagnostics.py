"""Bounded host observations. Never expose arguments, environments or host identity."""

import os
import re
import subprocess
from pathlib import Path

from .process_metrics import process_snapshot
from .stage_c_session import host_snapshot, identity_alive, process_identity


def diagnostic_bundle(controller=None, control_port=22280):
    result = {"schema": "inf011-host-diagnostics.v1", "host": host_snapshot()}
    result["host_controller"] = {
        "alive": identity_alive(controller),
        "state": (process_identity(controller["pid"]) or {}).get("state") if controller else None,
    }
    top = []
    for path in Path("/proc").glob("[0-9]*"):
        snapshot = process_snapshot(int(path.name))
        if "rss_bytes" in snapshot:
            # Role only: command lines and arbitrary process names can expose secrets.
            try:
                comm = (path / "comm").read_text().strip().lower()
            except OSError:
                comm = ""
            role = next(
                (
                    name
                    for name in ("python", "gateway", "vllm", "ssm-agent", "dockerd", "containerd")
                    if name in comm
                ),
                "other",
            )
            top.append({"role": role, **snapshot})
            top.sort(key=lambda row: row["rss_bytes"], reverse=True)
            del top[10:]
    result["top_processes_by_rss"] = top
    result["control_port_listening"] = False
    for name in ("tcp", "tcp6"):
        try:
            for line in (Path("/proc/net") / name).read_text().splitlines()[1:]:
                fields = line.split()
                if int(fields[1].split(":")[1], 16) == control_port and fields[3] == "0A":
                    result["control_port_listening"] = True
        except (OSError, ValueError, IndexError):
            pass
    for label, argv in (
        ("free_m", ["free", "-m"]),
        (
            "dmesg_oom_kill_tail",
            [
                "sh",
                "-c",
                "dmesg --color=never 2>/dev/null | tail -n 200 | grep -Ei 'oom|out of memory|kill' | tail -n 20",
            ],
        ),
    ):
        try:
            completed = subprocess.run(argv, capture_output=True, timeout=3, check=False)
            text = completed.stdout[:8192].decode("utf-8", errors="replace")
            if label == "dmesg_oom_kill_tail":
                # Arbitrary kernel text may contain process names, paths or secrets.
                # Export only the matching category, timestamp and numeric memory fields.
                rows = []
                for line in text.splitlines():
                    stamp = re.match(r"\[\s*([0-9.]+)\]", line)
                    category = "oom_kill" if re.search(r"(?i)oom|out of memory", line) else "kill"
                    memory = re.findall(
                        r"(?i)([a-z_-]*(?:rss|vm|mem)[a-z_-]*):([0-9]+)(kB|KB|MB)?", line
                    )
                    rows.append(
                        {
                            "uptime_seconds": float(stamp[1]) if stamp else None,
                            "category": category,
                            "memory_fields": memory,
                        }
                    )
                text = rows
            result[label] = {
                "status": "captured" if completed.returncode == 0 else "unavailable_or_no_matches",
                "text": text,
            }
        except (OSError, subprocess.SubprocessError):
            result[label] = {"status": "unavailable", "text": None}
    return result


def session_processes(roles):
    """Find only capture/control workers; never export their arguments."""
    found = dict(roles)
    for path in Path("/proc").glob("[0-9]*"):
        try:
            cmd = (path / "cmdline").read_bytes()[:8192]
        except OSError:
            continue
        if (
            b"inference_platform.kv_event_capture" in cmd
            or b"inference_platform.stage_c_fake_capture" in cmd
        ):
            found["capture"] = int(path.name)
        if b"--serve-transport" in cmd and b"--manifest-sha256" in cmd:
            found["control_server"] = int(path.name)
    found["sampler"] = os.getpid()
    return found
