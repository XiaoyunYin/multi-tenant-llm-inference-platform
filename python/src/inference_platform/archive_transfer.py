"""Bounded range export and size-derived reserve, independent of measured traffic."""

import math

ARCHIVE_BYTES_PER_SECOND = 500_000  # decimal MB/s, deliberately below observed SSM
CHUNK_BYTES = 2 * 1024 * 1024
CHUNK_TIMEOUT_SECONDS = 20
FINAL_EXPORT_RESERVE_SECONDS = 600


def export_window(total_bytes):
    if type(total_bytes) is not int or total_bytes < 0:
        raise ValueError("archive size must be a nonnegative integer")
    # Allow one retry per chunk plus the small metadata/control reserve.
    return math.ceil(total_bytes / ARCHIVE_BYTES_PER_SECOND) * 2 + FINAL_EXPORT_RESERVE_SECONDS
