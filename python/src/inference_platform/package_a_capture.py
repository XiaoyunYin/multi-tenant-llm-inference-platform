"""DEC-086 early compute capture; local disk readback, not a live O_export gate."""

import hashlib
import json
import shutil
import signal
import time

from .inf037b_setup_observations import capture_export, inventory

CAPTURE_LIMIT_S = 1650


def digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def stage_fixture(source, destination, specs, expected_rows):
    """Copy an already constructed maximum fixture; book copy and hashing apart."""
    first = time.monotonic()
    files = inventory(source)
    source_hash_s = time.monotonic() - first
    copy_start = time.monotonic()
    shutil.copytree(source, destination)
    copy_s = time.monotonic() - copy_start
    hash_start = time.monotonic()
    staged = inventory(destination)
    rows = 0
    for path in sorted((destination / "raw").glob("*.jsonl")):
        with path.open("rb") as stream:
            rows += sum(1 for _ in stream)
    verified = staged == files and rows == expected_rows
    result = {
        "verified": verified,
        "copy_s": copy_s,
        "hash_check_s": source_hash_s + time.monotonic() - hash_start,
        "manifest": {"files": files, "specs_sha256": digest(specs), "raw_rows": rows},
        "raw_rows": rows,
        "bytes": sum(item["bytes"] for item in files.values()),
    }
    result["manifest_sha256"] = digest(result["manifest"])
    return result


def compute_capture(*, staging, source, sanitized, destination, verify_source, sanitize):
    """One monotonic bracket includes source checks through resumed local readback."""
    if staging.get("verified") is not True:
        raise ValueError("capture_staging_unverified")
    started = time.monotonic_ns()

    def timeout(*_):
        raise TimeoutError("capture_compute_exceeds_1650s_DEC041_item2")

    previous = signal.signal(signal.SIGALRM, timeout)
    signal.setitimer(signal.ITIMER_REAL, CAPTURE_LIMIT_S)
    try:
        provenance = verify_source()
        if inventory(source) != staging["manifest"]["files"]:
            raise ValueError("capture_staged_fixture_changed")
        raw, _ = capture_export(
            binding={},
            source=source,
            sanitized=sanitized,
            destination=destination,
            sanitize=sanitize,
            sample=lambda: {"ms": [(time.monotonic_ns() - started) // 1_000_000] * 2},
            reconnect_ms=0,
        )
        evidence = json.loads(raw)
        if evidence["sanitized"] != evidence["destination"]:
            raise ValueError("capture_readback_mismatch")
        ended = time.monotonic_ns()
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
    seconds = (ended - started) / 1e9
    return {
        "schema": "dec086-early-compute-capture-v1",
        "status": "PASS" if seconds <= CAPTURE_LIMIT_S else "FAILED",
        "compute_s": seconds,
        "limit_s": CAPTURE_LIMIT_S,
        "monotonic_start_ns": started,
        "monotonic_end_ns": ended,
        "source": provenance,
        "staging": staging,
        "export": evidence,
        "scope": "source verification, sanitized_campaign, sanitized verification, interrupted local transfer, resume and local readback; fixture construction/staging excluded",
        "limits": "Early compute only; full planned-host stores/network/recovery/placement O_export remains required before an exact live plan.",
    }


def validate_native_reuse(capture, native, source_commit, native_hash):
    """A capture pass cannot stand in for an unbounded or differently bound sizing."""
    if (
        capture.get("status") != "PASS"
        or not 0 <= capture.get("compute_s", float("inf")) <= CAPTURE_LIMIT_S
        or capture.get("source", {}).get("source_commit") != source_commit
        or native.get("source_commit") != source_commit
        or capture.get("native_receipt_sha256") != native_hash
        or not capture.get("staging", {}).get("verified")
        or native.get("capture_reuse_scope")
        != "sanitized_campaign only; excludes staging, source checks, transfer and readback"
        or not capture["monotonic_start_ns"]
        <= native.get("monotonic_start_ns", -1)
        <= native.get("monotonic_end_ns", -1)
        <= capture["monotonic_end_ns"]
        or native.get("elapsed_seconds")
        != (native["monotonic_end_ns"] - native["monotonic_start_ns"]) / 1e9
    ):
        raise ValueError("capture_native_reuse_unbound")
