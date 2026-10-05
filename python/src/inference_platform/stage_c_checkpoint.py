"""Seal a completed run before starting the next; no private prompt/token inputs."""

import hashlib
import json
import os
import shutil
import tarfile
from pathlib import Path

from .disk_records import write_json


def file_sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def snapshot_jsonl(source, destination):
    """Copy complete rows present at snapshot time; never follow a growing tail."""
    if not source.exists():
        return
    remaining = source.stat().st_size
    with source.open("rb") as stream, destination.open("wb") as target:
        while remaining > 0:
            line = stream.readline(min(remaining, 4 * 1024 * 1024))
            remaining -= len(line)
            if not line.endswith(b"\n"):
                break
            json.loads(line)
            target.write(line)


def seal_run(session, number, run, config=None, *, core_only=False):
    from .failure_taxonomy import add_failure_splits

    disk = session / f"disk-checkpoint-{number}.json"

    if not core_only:
        add_failure_splits(run, session / "gateway.log")
    root = session / "sealed-runs"
    root.mkdir(exist_ok=True)
    directory = root / f"run-{number}"
    directory.mkdir(exist_ok=True)
    if disk.exists():
        shutil.copyfile(disk, directory / "disk-breakdown.json")
    write_json(
        directory / "run-artifact.json",
        {
            "schema": "inf011-sealed-run.v1",
            "run_number": number,
            "run": run,
            "event_correlation_status": "requires_final_session_join",
            "basis": "Core measurement records durable before the next run; no final-session acceptance implied",
        },
    )
    for name in (
        "gateway.log",
        "host-process-samples.jsonl",
        "fake-events.jsonl",
        "kv-event-capture.observations.jsonl",
    ):
        if core_only:
            (directory / name).unlink(missing_ok=True)
            continue
        source = session / name
        if name == "kv-event-capture.observations.jsonl" and config:
            source = Path(config.kv_capture_output_path).with_suffix(".observations.jsonl")
        if name.endswith(".jsonl"):
            snapshot_jsonl(source, directory / name)
        elif source.exists():
            shutil.copyfile(source, directory / name)
    from .stage_c_digest import measurement_digest, seal_digest

    digest = seal_digest(
        root / f"run-{number}.digest.json.gz",
        measurement_digest(session, run, directory, None if core_only else config),
    )
    write_json(root / f"run-{number}.digest.receipt.json", digest)
    sums = "".join(f"{file_sha(path)}  {path.name}\n" for path in sorted(directory.iterdir()))
    (directory / "SHA256SUMS.txt").write_text(sums, encoding="utf-8", newline="\n")
    pending = root / f"run-{number}.pending"
    archive = root / f"run-{number}.tar.gz"
    with tarfile.open(pending, "w:gz") as handle:
        for path in sorted(directory.iterdir()):
            handle.add(path, arcname=path.name, recursive=False)
    with pending.open("r+b") as stream:
        os.fsync(stream.fileno())
    pending.replace(archive)
    receipt = {
        "schema": "inf011-sealed-run-receipt.v1",
        "run_number": number,
        "run_status": run["status"],
        "sha256": file_sha(archive),
        "bytes": archive.stat().st_size,
        "measurement_digest": digest,
        "sealed_before_next_run": True,
        "raw_prompt_token_inputs_included": False,
    }
    from .archive_transfer import export_window

    sizes = [
        json.loads(path.read_text())["bytes"]
        for path in root.glob("run-[1-4].receipt.json")
        if path.name != f"run-{number}.receipt.json"
    ] + [receipt["bytes"]]
    total = sum(sizes)
    # Protect the remaining runs with the largest observed archive per run.
    # This forecast is conservative telemetry, not a changed run budget/cap.
    forecast = total + max(sizes) * (4 - len(sizes))
    receipt["archive_export_window"] = {
        "total_sealed_bytes": total,
        "forecast_total_bytes": forecast,
        "bytes_per_second": 500_000,
        "required_seconds": export_window(total),
        "forecast_seconds": export_window(forecast),
    }
    write_json(root / f"run-{number}.receipt.json", receipt)
    return receipt


def checkpoint_run(session, number, run, config=None):
    """Session's actual callback: salvage core data without stopping later measurements."""
    from .stage_c_session import disk_snapshot

    try:
        write_json(session / f"disk-checkpoint-{number}.json", disk_snapshot(refresh=True))
        return seal_run(session, number, run, config)
    except Exception as error:
        # Never include command output, paths or raw capture inputs in sanitized errors.
        run["checkpoint"] = {
            "status": "degraded",
            "failure_type": type(error).__name__,
            "event_lag_status": "unavailable",
            "reason": "checkpoint failed; core measurement salvage attempted",
        }
        write_json(session / f"checkpoint-{number}.failure.json", run["checkpoint"])
        directory = session / "sealed-runs" / f"run-{number}"
        if directory.exists():
            shutil.rmtree(directory)
        try:
            return seal_run(session, number, run, config, core_only=True)
        except Exception as fallback:
            run["checkpoint"]["core_seal_status"] = "unavailable"
            run["checkpoint"]["core_seal_failure_type"] = type(fallback).__name__
            write_json(session / f"checkpoint-{number}.failure.json", run["checkpoint"])
            return None
