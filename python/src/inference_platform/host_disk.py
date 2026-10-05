"""Conservative root-disk planning and post-model, pre-load admission."""

import math

from .stage_c_session import disk_snapshot

GIB = 1024**3
MINIMUM_FREE_BYTES = 60 * GIB
COMPONENTS = {
    "ami_used_upper_bound": 75 * GIB,
    "extracted_images_and_pull_workspace": 40 * GIB,
    "model_cache": 20 * GIB,
    "session_worst_case": 20 * GIB,
    "margin": 40 * GIB,
    "filesystem_overhead": 5 * GIB,
}


def require_disk_headroom(snapshot=None):
    if snapshot is None:
        snapshot = disk_snapshot(refresh=True)
    if snapshot.get("status") != "available":
        raise RuntimeError("root disk free space unavailable; no load admitted")
    if snapshot["free_bytes"] < MINIMUM_FREE_BYTES:
        raise RuntimeError("root disk below 60 GiB post-model free-space gate; no load admitted")
    return {**snapshot, "status": "ok", "minimum_free_bytes": MINIMUM_FREE_BYTES}


def rehearsal_disk_snapshot():
    """Explicit synthetic admission input, never a measurement of the host."""
    return {
        "status": "available",
        "free_bytes": MINIMUM_FREE_BYTES,
        "source": "rehearsal",
        "basis": "Synthetic headroom for an explicitly selected fake-runtime rehearsal",
    }


def disk_fitness(inputs, launcher):
    """A recorded, byte-explicit budget must cover every fixed conservative floor."""
    try:
        budget = inputs["disk_budget"]
        components = budget["components_bytes"]
        if any(
            type(components.get(k)) is not int or components[k] < v for k, v in COMPONENTS.items()
        ):
            raise ValueError("missing or undersized disk component")
        required = sum(components.values())
        volume = budget["root_volume_gib"]
        if (
            type(volume) is not int
            or not 200 <= volume <= 250
            or volume < math.ceil(required / GIB)
        ):
            raise ValueError("root volume does not cover disk budget")
        if budget["minimum_free_after_model_bytes"] != MINIMUM_FREE_BYTES:
            raise ValueError("post-model gate must reserve session worst case plus margin")
        if components["session_worst_case"] + components["margin"] > MINIMUM_FREE_BYTES:
            raise ValueError("post-model free-space gate does not cover session and margin")
        for flag in (
            "--log-driver json-file",
            "--log-opt max-size=20m",
            "--log-opt max-file=3",
            "SystemMaxUse=256M",
        ):
            if flag not in launcher:
                raise ValueError("bounded runtime and journal logs required")
        return True, f"{required} bytes budget on {volume} GiB root; 60 GiB post-model gate"
    except (KeyError, TypeError, ValueError) as error:
        return False, str(error)
