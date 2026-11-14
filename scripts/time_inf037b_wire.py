"""$0 R374 disk-volume and sustained-sink receipts; no planned-host claim.

Replay every byte of the registered maximum archive as synthetic response bytes
through the actual spool. This is an explicit wire-volume model, not authority
for a deployed API's response maxima. Separately sustain 150 accepted 7.3 KB
rows/s for 60 s, with raw retention, barriers and a real 16 MiB Port store.
"""

import argparse
import hashlib
import json
import math
import platform
import statistics
import threading
import time
from pathlib import Path

from inference_platform.inf037b_archive import encode, sha
from inference_platform.inf037b_capture import CaptureOwner, wire_records
from inference_platform.inf037b_contract import SOURCE_KINDS
from inference_platform.inf037b_durable_ports import DurableStore
from inference_platform.inf037b_live import LiveRows
from inference_platform.inf037b_ports import Port

ROOT = Path(__file__).resolve().parents[1]


def inputs():
    paths = [
        *(ROOT / "python/src/inference_platform").glob("inf037b*.py"),
        Path(__file__),
    ]
    return {
        p.relative_to(ROOT).as_posix(): sha(p.read_bytes().replace(b"\r\n", b"\n"))
        for p in sorted(paths)
    }


def owner(root, *, sources=None):
    root.mkdir(parents=True)
    boot = root / "boot"
    boot.write_text("wire-receipt-boot")
    binding = {"session_id": "wire-receipt", "pins": {"source": "a" * 64}}
    sources = sources or {
        kind: [[kind, kind, "wire-receipt-boot"]] for kind in sorted(SOURCE_KINDS)
    }
    port = Port(root / "port", None, initialize=True)
    with port.store.lock():
        state = port.store.read()
        # Actual Port.intent records, with settled raw-value storage shaped like
        # the setup ports. 128 intents and 16 MiB of response evidence. No fake
        # read() or memory store, and no provider authority/transport invoked.
        for i in range(128):
            key = f"prior-operation-{i}"
            port.intent(
                state,
                "receipt.fixture",
                key,
                {"binding": binding, "source": f"fixture-{i}", "raw_sha256": "b" * 64},
            )
            state["values"][key] = {"raw_hex": (b"r" * 65536).hex(), "accepted": True}
        key = "capture-wire"
        body = {
            "binding": binding,
            "capture": {
                "sources": sources,
                "attempt": 1,
                "stages": [1, 2, 3, 4, 5],
                "boot_id": boot.read_text(),
            },
        }
        port.intent(state, "capture", key, body)
        operation = state["operations"][sha(encode(["capture", key]))]
    result = CaptureOwner(
        store=DurableStore(root / "capture", {}, initialize=True),
        operation_store=port.store,
        operation=operation,
        binding=binding,
        root=root / "retained",
        sources=sources,
        attempt=1,
        stages=[1, 2, 3, 4, 5],
        boot_path=boot,
    )
    return result


def maximum(work, source):
    capture = owner(work)
    manifest, total, batches = {}, 0, 0
    start = time.monotonic_ns()
    for path in sorted(source.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(source).as_posix()
        kind = path.stem.split(".")[0]
        kind = kind if kind in capture.sources else "controller"
        count, digest, size = 0, hashlib.sha256(), 0
        with path.open("rb") as stream:
            while chunk := stream.read(65536):
                before = time.monotonic_ns()
                digest.update(chunk)
                size += len(chunk)
                capture.retain(
                    kind,
                    before,
                    time.monotonic_ns(),
                    chunk,
                    {"fixture_file": relative, "model": "maximum-archive-as-wire"},
                )
                count += 1
                if count % 16 == 0:
                    capture.barrier(kind)
                    batches += 1
        capture.barrier(kind)
        manifest[relative] = {"bytes": size, "sha256": digest.hexdigest()}
        total += size
    retained_ns = time.monotonic_ns()
    result = capture.close()
    closed_ns = time.monotonic_ns()
    # Actual retrieval verification reads every indexed byte; no compressed or
    # stat-only substitution. Network/store copying and durable ack remain R366.
    retrieved = sum(len(body) for _, body in wire_records(capture.root / "wire"))
    end_ns = time.monotonic_ns()
    assert retrieved == total
    assert total == 5_110_460_667 and len(manifest) == 80, (total, len(manifest))
    assert result["transport_clean"]
    return {
        "registered_archive_rows": 701418,
        "fixture_files": manifest,
        "fixture_bytes": total,
        "retrieved_wire_bytes": retrieved,
        "spool_bytes": result["spool_bytes"],
        "spool_files": result["spool_files"],
        "fsyncs": result["spool_fsyncs"],
        "barriers": result["spool_barriers"],
        "retention_s": (retained_ns - start) / 1e9,
        "close_seal_hash_descriptor_s": (closed_ns - retained_ns) / 1e9,
        "retrieval_verification_s": (end_ns - closed_ns) / 1e9,
        "retention_fsyncs_per_s": result["spool_fsyncs"]
        / ((retained_ns - start) / 1e9),
        "normalized_duplicate_spool_bytes": 0,
        "wire_model_is_deployed_upper_bound": False,
    }


def sustained(work, *, rows_per_s=150, duration_s=60):
    capture = owner(work)
    rows = capture.rows("controller")
    # Calibrate the actual accepted row shape to the registered mean, including
    # stage decoration. Sequence digit growth is reported, never hidden.
    fields = {"name": "wire-sink-volume", "value": ""}
    sample = LiveRows("wire-receipt", "wire-receipt-boot").row(
        "controller", "controller", "wire-receipt-boot", "precondition", fields
    )
    sample["stage"] = capture.stages
    fields["value"] = "x" * max(
        0, math.ceil(5_110_460_667 / 701418) - len(encode(sample))
    )
    costs, slots, actual_bytes = [], [], []
    raw = encode({"name": "wire-sink-volume", "value": fields["value"]})
    store_reads = [0]
    original_read = capture.operation_store.read

    def counted_read():
        store_reads[0] += 1
        return original_read()

    capture.operation_store.read = counted_read

    def collect():
        before = time.monotonic_ns()
        capture.join_current()  # Actual generation-cache path, against the real 16 MiB store.
        for _ in range(rows_per_s):
            capture.retain(
                "controller", before, time.monotonic_ns(), raw, {"slot": len(slots)}
            )
        capture.barrier("controller")  # Raw durable before the first row predicate.
        for _ in range(rows_per_s):
            row_start = time.monotonic_ns()
            row = rows.row(
                "controller", "controller", "wire-receipt-boot", "precondition", fields
            )
            costs.append((time.monotonic_ns() - row_start) / 1e6)
            actual_bytes.append(len(encode(row)))
        slots.append((time.monotonic_ns() - before) / 1e6)

    settled_slots = []
    complete = capture.complete

    def completed(source, start, end, body, metadata):
        complete(source, start, end, body, metadata)
        settled_slots.append((time.monotonic_ns() - start) / 1e6)

    capture.complete = completed
    start = time.monotonic_ns()
    error = None
    try:
        capture.periodic(
            "controller",
            collect,
            period_ms=1000,
            start_ns=start,
            stop_ns=start + duration_s * 1_000_000_000,
            stop_event=threading.Event(),
        )
    except Exception as exc:
        error = str(exc)
    # Remain present for the complete sustained observation window.
    remaining = (start + duration_s * 1_000_000_000 - time.monotonic_ns()) / 1e9
    if remaining > 0:
        time.sleep(remaining)
    close_start = time.monotonic_ns()
    result = capture.close()
    close_end = time.monotonic_ns()
    missed = sum(
        bool(record["metadata"].get("missed_slot"))
        for record, _ in wire_records(capture.root / "wire")
    )
    summary = {
        "rate_rows_per_s": rows_per_s,
        "duration_s": duration_s,
        "rows": len(costs),
        "collection_slots": len(slots),
        "missed_slots": missed,
        "error": error,
        "operation_store_bytes": (capture.operation_store.path / "state.json")
        .stat()
        .st_size,
        "full_store_reads_including_close": store_reads[0],
        "mean_row_bytes": statistics.mean(actual_bytes) if actual_bytes else None,
        "mean_sink_ms_per_row": statistics.mean(costs) if costs else None,
        "p99_sink_ms_per_row": sorted(costs)[math.ceil(len(costs) * 0.99) - 1]
        if costs
        else None,
        "mean_slot_ms": statistics.mean(slots) if slots else None,
        "max_slot_ms": max(slots, default=None),
        "max_settled_slot_ms": max(settled_slots, default=None),
        "p99_settled_slot_ms": sorted(settled_slots)[
            math.ceil(len(settled_slots) * 0.99) - 1
        ]
        if settled_slots
        else None,
        "p99_slot_ms": sorted(slots)[math.ceil(len(slots) * 0.99) - 1]
        if slots
        else None,
        "spool_bytes": result["spool_bytes"],
        "spool_files": result["spool_files"],
        "spool_fsyncs": result["spool_fsyncs"],
        "spool_fsyncs_per_s": result["spool_fsyncs"] / duration_s,
        "close_seal_hash_descriptor_s": (close_end - close_start) / 1e9,
        "transport_clean": result["transport_clean"],
    }
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--rate-only", action="store_true")
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    before = inputs()
    summary = {
        "schema": "inf037b-wire-cost-v1",
        "python": platform.python_version(),
        "platform": platform.platform(),
        "inputs_lf_sha256": before,
        "cost_usd": 0,
        "planned_host_gate": "NOT_RUN",
        "deployed_wire_maximum_authority": False,
    }
    if not args.rate_only:
        assert args.source is not None
        print("Maximum wire-volume model", flush=True)
        summary["maximum"] = maximum(args.work / "maximum", args.source)
    print("Sustain 150 rows/s for 60 s", flush=True)
    summary["sustained"] = sustained(args.work / "sustained")
    gate = summary["sustained"]
    if gate["rows"] == 9000 and gate["missed_slots"] == 0 and gate["transport_clean"]:
        print("Informational 300 rows/s step (10 s, not a gate)", flush=True)
        summary["informational_300"] = sustained(
            args.work / "headroom", rows_per_s=300, duration_s=10
        )
    summary["inputs_unchanged"] = inputs() == before
    args.output.write_text(json.dumps(summary, indent=2, allow_nan=False) + "\n")
    print(
        json.dumps(
            {
                "maximum": {
                    k: v
                    for k, v in summary.get("maximum", {}).items()
                    if k != "fixture_files"
                },
                "sustained": summary["sustained"],
            },
            indent=2,
        ),
        flush=True,
    )
    assert summary["inputs_unchanged"]
    assert (
        summary["sustained"]["rows"] == 9000
        and summary["sustained"]["missed_slots"] == 0
    )
    assert summary["sustained"]["transport_clean"]


if __name__ == "__main__":
    main()
