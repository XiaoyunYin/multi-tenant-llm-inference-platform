"""Record the Windows launch decision before any native probe provider call."""

import ctypes
from ctypes import wintypes
from datetime import UTC, datetime

from inf060_probe_spec import save

PHYSICAL_MIN = 3 * 1024**3 // 2
COMMIT_MIN = 2 * 1024**3


def windows_headroom():
    # GetPerformanceInfo reports system-wide values in pages. Unlike process
    # available page-file bytes, these counters also work in a job object.
    class PerformanceInfo(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            *[
                (field, ctypes.c_size_t)
                for field in (
                    "CommitTotal",
                    "CommitLimit",
                    "CommitPeak",
                    "PhysicalTotal",
                    "PhysicalAvailable",
                    "SystemCache",
                    "KernelTotal",
                    "KernelPaged",
                    "KernelNonpaged",
                    "PageSize",
                )
            ],
            ("HandleCount", wintypes.DWORD),
            ("ProcessCount", wintypes.DWORD),
            ("ThreadCount", wintypes.DWORD),
        ]

    info = PerformanceInfo()
    info.cb = ctypes.sizeof(info)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    read = psapi.GetPerformanceInfo
    read.argtypes = (ctypes.POINTER(PerformanceInfo), wintypes.DWORD)
    read.restype = wintypes.BOOL
    if not read(ctypes.byref(info), info.cb):
        raise ctypes.WinError(ctypes.get_last_error())
    return info.PhysicalAvailable * info.PageSize, (
        info.CommitLimit - info.CommitTotal
    ) * info.PageSize


def record_launch_gate(path, *, requested, read=windows_headroom):
    if requested not in {"laptop", "aws"}:
        raise ValueError("inf060:unknown_operator_path")
    physical, commit = read()
    enough = physical >= PHYSICAL_MIN and commit >= COMMIT_MIN
    receipt = {
        "utc": datetime.now(UTC).isoformat(),
        "free_physical_bytes": physical,
        "available_commit_bytes": commit,
        "minimum_free_physical_bytes": PHYSICAL_MIN,
        "minimum_available_commit_bytes": COMMIT_MIN,
        "requested": requested,
        "selected": requested if enough else "aws",
    }
    save(path, receipt)
    if requested == "laptop" and not enough:
        raise ValueError("inf060:laptop_memory_gate:use_aws_operator")
    return receipt
