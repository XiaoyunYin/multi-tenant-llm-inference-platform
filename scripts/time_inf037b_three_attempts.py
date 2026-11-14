"""Reproducible offline report timing over a full three-attempt archive.

No paid allowance is inferred. Construction is outside the measured interval.
"""

import argparse
import copy
import json
import platform
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "python/tests"))
ROOT = Path(__file__).resolve().parents[1]
from test_inf037b_collectors import complete_campaign_fixture  # noqa: E402

from inference_platform.inf037b_archive import encode, inspect_segment  # noqa: E402
from inference_platform.inf037b_campaign import OfflineCampaign, registered_offers  # noqa: E402
from inference_platform.inf037b_live import LiveRows  # noqa: E402


def add_live_shapes(root):
    """Include producer boundary vocabulary and first-generation identities.

    This runs before attempt cloning, outside the measured export interval.
    Only fixture construction changes; no full sizing is implied by unit tests.
    """
    added = 0
    for path in sorted((root / "raw").glob("*.jsonl")):
        rows = inspect_segment(path)[1]
        for row in rows:
            row["source_generation"] = "0"
            payload = row["payload"]
            for field in ("process_generation", "reset_generation"):
                if payload.get(field) is not None:
                    payload[field] = "0"
            if row["source_kind"] == "kubernetes" and payload["event"] == "snapshot":
                payload["boundaries"] = {
                    "pods_resource_version": payload["resource_version"],
                    "endpointslices_resource_version": payload["resource_version"],
                }
        created = next(
            (
                r
                for r in rows
                if r["source_kind"] == "kubernetes"
                and r["payload"]["event"] == "pod_created"
            ),
            None,
        )
        if created:
            now = created["source_time"]["value"]
            p = created["payload"]
            builder = LiveRows(
                created["session_id"], "0", clock=lambda: now * 1_000_000
            )
            cache = builder.row(
                "kubernetes",
                created["source_identity"],
                "0",
                "container_state",
                {
                    "pod_uid": p["pod_uid"],
                    "slot": p["slot"],
                    "node_pseudonym": "synthetic-node",
                    "container_state": "cache_observation",
                    "image_cache_state": "cold",
                    "model_cache_state": "cold",
                    "reason": "cache_observed_before_creation",
                    "boundaries": {
                        "cache_witness_ms_bounds": [now - 2, now - 1],
                        "creation_ms_bounds": [now, now],
                    },
                },
            )
            cache["record_id"] = "synthetic-node-cache-witness"
            rows.append(cache)
            added += 1
        rows.sort(key=lambda r: (r["observed_mono_ns"], r["source_seq"]))
        sequences = {}
        for row in rows:
            key = (row["source_identity"], row["source_generation"])
            row["source_seq"] = sequences.get(key, 0)
            sequences[key] = row["source_seq"] + 1
        path.write_bytes(b"".join(encode(row) for row in rows))
    return added


def build(root, *, reset_ms=120_000, include_reset_capture=False):
    base, count = complete_campaign_fixture(root, registration_scale=True)
    count += add_live_shapes(root)
    specs = [base.spec]
    journal = base.journal
    for attempt in (2, 3):
        offset = (attempt - 1) * (1_560_000 + reset_ms)
        offers = registered_offers(
            attempt, offset, offset + 1_560_000, base.spec["config_sha256"]
        )
        ids = {
            old["request_id"]: new
            for old, new in zip(base.spec["expected_offers"], offers, strict=True)
        }
        names = {
            "old0": f"old0-a{attempt}",
            "old1": f"old1-a{attempt}",
            "new0": f"new0-a{attempt}",
        }
        absolute = {
            "redis_time_ms",
            "sample_time",
            "local_mono_ms",
            "local_wall_ms",
            "remote_ms",
            "send_ms",
            "receive_ms",
            "dispatch_ms",
            "signal_receipt_time",
            "expiry_ms",
            "expires_ms",
            "since_ms",
            "until_ms",
            "install_redis_ms_bounds",
            "cache_witness_ms_bounds",
            "creation_ms_bounds",
        }

        def shifted(value, field=""):
            if isinstance(value, dict):
                result = {k: shifted(v, k) for k, v in value.items()}
                if value.get("request_id") in ids:
                    offer = ids[value["request_id"]]
                    for k in ("request_id", "offer_index", "prefix_id"):
                        if k in result:
                            result[k] = offer[k]
                return result
            if isinstance(value, list):
                return [shifted(v, field) for v in value]
            if type(value) is int:
                if field in ("slot", "backend_slot") and attempt == 2:
                    return 1 - value
                if field in absolute:
                    return value + offset
            if isinstance(value, str):
                if value in names:
                    return names[value]
                if field in (
                    "source_identity",
                    "source_generation",
                    "record_id",
                    "process_generation",
                    "reset_generation",
                    "boot_id",
                ):
                    return value + f"-a{attempt}"
                if field == "request_id" and value in ids:
                    return ids[value]["request_id"]
                if field == "reservation_id" and value.startswith("reservation-"):
                    return (
                        "reservation-"
                        + ids[value.removeprefix("reservation-")]["request_id"]
                    )
            return value

        for path in sorted((root / "raw").glob("*.jsonl")):
            original = [r for r in inspect_segment(path)[1] if r["attempt_id"] == 1]
            with path.open("ab") as stream:
                for row in original:
                    new = shifted(row)
                    new["attempt_id"] = attempt
                    for field in (
                        "observed_mono_ns",
                        "capture_start_mono_ns",
                        "capture_end_mono_ns",
                    ):
                        new[field] += offset * 1_000_000
                    new["source_time"]["value"] += offset
                    stream.write(encode(new))
                    if (
                        include_reset_capture
                        and row["payload"]["event"]
                        in ("install", "health", "snapshot", "sample", "mapping")
                        and row["source_time"]["value"] < reset_ms
                    ):
                        reset = copy.deepcopy(new)

                        def earlier(value, field=""):
                            if isinstance(value, dict):
                                return {k: earlier(v, k) for k, v in value.items()}
                            if isinstance(value, list):
                                return [earlier(v, field) for v in value]
                            if type(value) is int and field in absolute:
                                return value - reset_ms
                            return value

                        reset["payload"] = earlier(reset["payload"])
                        for field in (
                            "observed_mono_ns",
                            "capture_start_mono_ns",
                            "capture_end_mono_ns",
                        ):
                            reset[field] -= reset_ms * 1_000_000
                        reset["source_time"]["value"] -= reset_ms
                        reset["record_id"] += "-reset"
                        stream.write(encode(reset))
        previous = (attempt - 2) * (1_560_000 + reset_ms) + 1_560_000
        journal.end_attempt(
            previous,
            measurement_valid=True,
            reasons=[],
            operational_outcomes=[],
            replacement_usable_by_deadline=True,
        )
        journal.begin_reset(previous, remaining_ms=10_000_000, export_cleanup_ms=0)
        journal.allocate(
            previous if include_reset_capture else offset,
            remaining_ms=10_000_000,
            export_cleanup_ms=0,
        )
        journal.setup_complete(offset, preconditions=True, reasons=[])
        spec = {
            **copy.deepcopy(base.spec),
            "attempt_index": attempt,
            "target_slot": 1 if attempt == 2 else 0,
            "target_uid": names["old0"],
            "replacement_uid": names["new0"],
            "expected_offers": offers,
            "traffic_start_ms": offset,
            "pre_end_ms": offset + 600_000,
            "capture_start_ms": offset,
            "capture_end_ms": offset + 1_560_000,
        }
        campaign = OfflineCampaign(root, spec)
        campaign.record_capture_window(offset, offset + 1_560_000)
        journal = campaign.journal
        specs.append(spec)
    if include_reset_capture:
        count = 0
        for path in sorted((root / "raw").glob("*.jsonl")):
            source = inspect_segment(path)[1]
            source.sort(key=lambda r: (r["observed_mono_ns"], r["source_seq"]))
            sequences = {}
            with path.open("wb") as stream:
                for row in source:
                    key = (row["source_identity"], row["source_generation"])
                    row["source_seq"] = sequences.get(key, 0)
                    sequences[key] = row["source_seq"] + 1
                    stream.write(encode(row))
                    count += 1
        return specs, count
    return specs, count * 3


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    cache_root = ROOT / ".cache"
    cache_root.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=cache_root) as directory:
        root = Path(directory) / "campaign"
        specs, rows = build(root)
        samples = []
        for spec in specs:
            campaign = OfflineCampaign(root, spec)
            tracemalloc.start()
            started = time.perf_counter()
            report = campaign.report()
            elapsed = time.perf_counter() - started
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            samples.append(
                {
                    "attempt": spec["attempt_index"],
                    "seconds": elapsed,
                    "peak_traced_python_bytes": peak,
                    "scheduled_offers": len(spec["expected_offers"]),
                    "measurement_valid": report["measurement_valid"],
                    "validity_reasons": report["validity_reasons"],
                }
            )
            del report
            print(json.dumps(samples[-1]), flush=True)
        receipt = {
            "scope": "three registered 1560s attempts, both 120s resets; each report sees the full archive",
            "rows": rows,
            "report_calls": 3,
            "samples": samples,
            "max_seconds": max(s["seconds"] for s in samples),
            "max_peak_traced_python_bytes": max(
                s["peak_traced_python_bytes"] for s in samples
            ),
            "python": platform.python_version(),
            "platform": platform.platform(),
            "memory_method": "tracemalloc peak per report, excludes fixture construction and RSS; tracing overhead included",
            "paid_reset_policy": "Full replay/materialization is offline after raw export; live scheduling must not call this offline replay bridge during either reset. Host-specific safety-path sizing is still required in the resolved packet.",
            "limits": "Observed synthetic CPU bounds on this host only; no measurement-host guarantee, paid allowance, rollout or inference-performance claim.",
        }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


if __name__ == "__main__":
    main()
