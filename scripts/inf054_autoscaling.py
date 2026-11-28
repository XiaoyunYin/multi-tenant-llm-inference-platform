"""Fixed INF-054 offer tape, KEDA pins, and scaled-arm reporting rules."""

import hashlib
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARMS = ("fixed-1", "keda", "fixed-2")
CYCLES = 3
BURST_SECONDS = 900
THRESHOLD = 2
SLO_TTFT_S = 1
SLO_DONE_S = 15
TIMING_S = {
    "provision_and_cache": 2400,
    "nine_cycles": 11340,
    "observed_scale_down": 1080,
    "transfer": 1200,
    "teardown": 1800,
}
KEDA_VERSION = "2.21.1"
KEDA_IMAGES = {
    "keda": (
        "keda",
        "d09d92c0a310e3057a3c54df387b99abf2bf31352218dbe1adcb00e807886488",
    ),
    "metricsApiServer": (
        "keda-metrics-apiserver",
        "747e376b3e80dc4f72bf4f7043f47cc4cdb56f34b1aed9531789f474996e1c84",
    ),
    "webhooks": (
        "keda-admission-webhooks",
        "5f4b0b0f7831b9f53738be85e99449a1747a5effa970305fe602455ab0f4fcd3",
    ),
}


def keda_values():
    return {
        "image": {
            role: {
                "registry": "ghcr.io",
                "repository": "kedacore/" + name,
                "tag": KEDA_VERSION + "@sha256:" + digest,
            }
            for role, (name, digest) in KEDA_IMAGES.items()
        }
    }


def keda_image_refs():
    return {
        f"ghcr.io/kedacore/{name}:{KEDA_VERSION}@sha256:{digest}"
        for name, digest in KEDA_IMAGES.values()
    }


def tape():
    """Return the same ordered prompt seeds and offsets for every arm and cycle."""
    baseline = 60
    return [
        {
            "slot": i,
            "offset_ns": (i * 1_000_000_000)
            if i < baseline
            else (baseline * 1_000_000_000) + (i - baseline) * 1_000_000_000 // 3,
            "seed": 433054 + i,
            "output_cap": 64,
        }
        for i in range(baseline + 3 * BURST_SECONDS)
    ]


def tape_sha256():
    return hashlib.sha256(
        json.dumps(tape(), sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def serving_values(arm):
    if arm not in ARMS:
        raise ValueError("inf054_unknown_arm")
    return {
        "engineReplicas": 2 if arm == "fixed-2" else 1,
        "firstItemTimeout": "60s",
        "autoscaling": {
            "enabled": arm == "keda",
            "threshold": str(THRESHOLD),
            "burstSeconds": BURST_SECONDS,
            "stabilizationSeconds": BURST_SECONDS,
        },
        "snapshotAdminAPI": True,
        "dcgm": {"enabled": True},
    }


def tally(rows):
    """Use all scheduled outcomes, including misses, as the attainment denominator."""
    outcomes = Counter(row["outcome"] for row in rows)
    codes = Counter(
        row.get("gateway_code", "other")
        for row in rows
        if row.get("http_status") == 429
    )
    samples = sorted(row["ttft_s"] for row in rows if row.get("ttft_s") is not None)
    passed = sum(
        row["outcome"] == "completed"
        and row["ttft_s"] <= SLO_TTFT_S
        and row["completed_s"] <= SLO_DONE_S
        for row in rows
    )
    return {
        "offered": len(rows),
        "outcomes": dict(outcomes),
        "slo_completed": passed,
        "slo_attainment": passed / len(rows) if rows else None,
        "http_429_by_code": dict(codes),
        "ttft_s": {
            "n": len(samples),
            **{
                f"p{p}": samples[(p * len(samples) + 99) // 100 - 1]
                if samples
                else None
                for p in (50, 95)
            },
        },
    }


def forecast(hourly_usd):
    seconds = sum(TIMING_S.values())
    per_attempt = 1.25 * (hourly_usd * seconds / 3600 + 3)
    return {
        "hourly_usd": hourly_usd,
        "fixed_allowance_usd_per_attempt": 3,
        "margin_multiplier": 1.25,
        "deadline_seconds": seconds,
        "estimated_single_attempt_usd": per_attempt,
        "estimated_with_retry_usd": 2 * per_attempt,
        "cap_including_retry_usd": 45,
    }
