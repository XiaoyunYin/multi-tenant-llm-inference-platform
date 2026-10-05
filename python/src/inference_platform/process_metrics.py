"""Dependency-free per-process resident-memory and CPU sampling."""

from __future__ import annotations

import ctypes
import os
import sys
from pathlib import Path
from typing import Any


def process_snapshot(pid: int) -> dict[str, Any]:
    """Return RSS bytes and cumulative CPU seconds, or a bounded error code."""

    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        return {"error": "invalid_pid"}
    try:
        if sys.platform.startswith("linux"):
            return _linux_snapshot(pid)
        if sys.platform == "win32":
            return _windows_snapshot(pid)
    except (OSError, ValueError, OverflowError):
        return {"error": "process_unavailable"}
    return {"error": "unsupported_platform"}


def _linux_snapshot(pid: int) -> dict[str, int | float]:
    stat = (Path("/proc") / str(pid) / "stat").read_text(encoding="ascii")
    _prefix, _separator, tail = stat.rpartition(") ")
    fields = tail.split()
    if len(fields) <= 12:
        raise ValueError("short proc stat record")
    user_ticks = int(fields[11])
    system_ticks = int(fields[12])
    resident_pages = int((Path("/proc") / str(pid) / "statm").read_text().split()[1])
    status = dict(
        line.split(":", 1)
        for line in (Path("/proc") / str(pid) / "status").read_text().splitlines()
        if ":" in line
    )
    return {
        "rss_bytes": resident_pages * os.sysconf("SC_PAGE_SIZE"),
        "peak_rss_bytes": int(status.get("VmHWM", "0 kB").split()[0]) * 1024,
        "cpu_seconds": (user_ticks + system_ticks) / os.sysconf("SC_CLK_TCK"),
    }


def _windows_snapshot(pid: int) -> dict[str, int | float]:
    from ctypes import wintypes

    class FileTime(ctypes.Structure):
        _fields_ = [("low", wintypes.DWORD), ("high", wintypes.DWORD)]

    class ProcessMemoryCountersEx(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("page_fault_count", wintypes.DWORD),
            ("peak_working_set_size", ctypes.c_size_t),
            ("working_set_size", ctypes.c_size_t),
            ("quota_peak_paged_pool_usage", ctypes.c_size_t),
            ("quota_paged_pool_usage", ctypes.c_size_t),
            ("quota_peak_non_paged_pool_usage", ctypes.c_size_t),
            ("quota_non_paged_pool_usage", ctypes.c_size_t),
            ("pagefile_usage", ctypes.c_size_t),
            ("peak_pagefile_usage", ctypes.c_size_t),
            ("private_usage", ctypes.c_size_t),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    handle_type = wintypes.HANDLE
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = handle_type
    kernel32.GetProcessTimes.argtypes = [
        handle_type,
        ctypes.POINTER(FileTime),
        ctypes.POINTER(FileTime),
        ctypes.POINTER(FileTime),
        ctypes.POINTER(FileTime),
    ]
    kernel32.GetProcessTimes.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [handle_type]
    kernel32.CloseHandle.restype = wintypes.BOOL
    psapi.GetProcessMemoryInfo.argtypes = [
        handle_type,
        ctypes.POINTER(ProcessMemoryCountersEx),
        wintypes.DWORD,
    ]
    psapi.GetProcessMemoryInfo.restype = wintypes.BOOL

    process_query_information = 0x0400
    process_vm_read = 0x0010
    handle = kernel32.OpenProcess(process_query_information | process_vm_read, False, pid)
    if not handle:
        raise OSError("OpenProcess failed")
    try:
        memory = ProcessMemoryCountersEx()
        memory.cb = ctypes.sizeof(memory)
        if not psapi.GetProcessMemoryInfo(handle, ctypes.byref(memory), memory.cb):
            raise OSError("GetProcessMemoryInfo failed")
        creation, exit_time, kernel, user = FileTime(), FileTime(), FileTime(), FileTime()
        if not kernel32.GetProcessTimes(
            handle,
            ctypes.byref(creation),
            ctypes.byref(exit_time),
            ctypes.byref(kernel),
            ctypes.byref(user),
        ):
            raise OSError("GetProcessTimes failed")
        kernel_ticks = (kernel.high << 32) | kernel.low
        user_ticks = (user.high << 32) | user.low
        return {
            "rss_bytes": int(memory.working_set_size),
            "peak_rss_bytes": int(memory.peak_working_set_size),
            "cpu_seconds": (kernel_ticks + user_ticks) / 10_000_000,
        }
    finally:
        kernel32.CloseHandle(handle)
