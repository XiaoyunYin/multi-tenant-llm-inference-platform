"""INF-054 workload and receipt driver for an already provisioned EKS operator."""

import hashlib
import json
import math
import subprocess
import threading
import time

from inf054_autoscaling import ARMS, BURST_SECONDS, CYCLES, serving_values, tally, tape
from inf061_native_workload import render_exact, run_window


BASELINE_S = 60
DRAIN_S = 120
RESET_S = 180
PREPARATION_S = 180
READY_HOLD_S = 2
READY_PROBE_S = 30
OBSERVE_DOWNSCALE_S = 1080
TRANSFER_S = 1200
TEARDOWN_S = 1800
SAMPLE_CADENCE_S = 1
# Three kubectl reads at the measured EKS cost of about 0.29 s each.
# Leave the rest of the bound for API jitter and local Prometheus reads.
SAMPLE_TIMEOUT_S = 5
SAMPLE_ERRORS = (OSError, ValueError, KeyError, subprocess.SubprocessError)
TAPE_LIMIT = 32 * 1024**2
SNAPSHOT_LIMIT = 64 * 1024**2
OUTCOMES = {
    "completed",
    "partial",
    "failed",
    "transport_error",
    "rejected",
    "missed_offer",
}
GAUGES = (
    "ready",
    "desired",
    "running",
    "waiting",
    "kv_fraction",
    "gpu_memory_mib",
    "dcgm_gpu_util_pct",
)
GATEWAY_CODES = {
    "tenant_concurrency_limit",
    "tenant_rate_limit",
    "system_capacity",
    "global_concurrency",
}


def write_json(path, value):
    path.write_text(
        json.dumps(value, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def write_rows(path, rows):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        for row in rows:
            stream.write(json.dumps(row, sort_keys=True, allow_nan=False) + "\n")


def build_tape(tokenizer, destination):
    """Render the registered tape once with the caller's pinned tokenizer."""
    write_rows(
        destination,
        (
            {**row, "prompt": render_exact(tokenizer, row["seed"], 1024)}
            for row in tape()
        ),
    )
    if destination.stat().st_size > TAPE_LIMIT:
        raise ValueError("inf054_tape_size")
    return hashlib.sha256(destination.read_bytes()).hexdigest()


def read_tape(source, sha256):
    if not 0 < source.stat().st_size <= TAPE_LIMIT:
        raise ValueError("inf054_tape_size")
    raw = source.read_bytes()
    if hashlib.sha256(raw).hexdigest() != sha256:
        raise ValueError("inf054_tape_hash")
    rows = [json.loads(line) for line in raw.splitlines()]
    for row, expected in zip(rows, tape(), strict=True):
        if (
            not isinstance(row, dict)
            or set(row) != expected.keys() | {"prompt"}
            or any(row[key] != value for key, value in expected.items())
            or not isinstance(row["prompt"], str)
            or not 0 < len(row["prompt"].encode()) <= 8192
        ):
            raise ValueError("inf054_tape_slot")
    if len({item["prompt"] for item in rows}) != len(rows):
        raise ValueError("inf054_tape_prompt_reuse")
    return rows


def transfer_snapshot(read, expected, target, end):
    """Stream one sealed TSDB archive into local custody, with a byte cap."""
    size, checksum = expected["bytes"], expected["sha256"]
    if type(size) is not int or not 0 < size <= SNAPSHOT_LIMIT:
        raise ValueError("inf054_snapshot_size")
    started = time.monotonic()
    pending = target.with_suffix(".partial")
    digest = hashlib.sha256()
    received = 0
    if target.exists():
        raise FileExistsError(target)
    stream = pending.open("xb")
    try:
        with stream as sink:
            while received < size:
                if time.monotonic() >= end:
                    raise TimeoutError("inf054_snapshot_deadline")
                wanted = min(1024**2, size - received)
                chunk = read(received, wanted, end)
                if not chunk or len(chunk) > wanted:
                    raise ValueError("inf054_snapshot_chunk")
                sink.write(chunk)
                digest.update(chunk)
                received += len(chunk)
        if time.monotonic() >= end:
            raise TimeoutError("inf054_snapshot_deadline")
        if digest.hexdigest() != checksum:
            raise ValueError("inf054_snapshot_hash")
        pending.replace(target)
    except BaseException:
        pending.unlink(missing_ok=True)
        raise
    return {
        "bytes": received,
        "sha256": checksum,
        "elapsed_s": time.monotonic() - started,
    }


def summarize(rows, second_serving_s, *, offer_end=BASELINE_S + BURST_SECONDS):
    splits = [
        ("baseline", 0, BASELINE_S),
        ("burst", BASELINE_S, offer_end),
    ]
    if second_serving_s is not None and BASELINE_S < second_serving_s < offer_end:
        splits.extend(
            [
                ("pre_usable", BASELINE_S, second_serving_s),
                ("post_usable", second_serving_s, offer_end),
            ]
        )
    result = {}
    for name, low, high in splits:
        data = tally([row for row in rows if low <= row["scheduled_s"] < high])
        result[name] = {
            **data,
            "seconds": high - low,
            "slo_goodput_per_s": data["slo_completed"] / (high - low),
        }
    return result


def safe_number(value):
    return (
        value
        if type(value) in (int, float) and 0 <= value < 10**10 and math.isfinite(value)
        else None
    )


def workload_cycle(
    backend,
    rows,
    output,
    *,
    arm,
    cycle,
    end,
    scheduler=run_window,
    offer_end=BASELINE_S + BURST_SECONDS,
):
    """A production open-loop window with concurrent bounded observation."""
    start = time.monotonic()
    if start + offer_end + DRAIN_S > end:
        raise TimeoutError("inf054_cycle_work_budget")
    stopped = threading.Event()
    samples = []

    required = {"ready", "desired", "running", "waiting", "kv_fraction"}
    gpu_metrics = getattr(backend, "gpu_metrics", False)
    if gpu_metrics:
        required.update(("gpu_memory_mib", "dcgm_gpu_util_pct"))

    def sample():
        while not stopped.is_set() and time.monotonic() < end:
            now = time.monotonic()
            sampled_epoch = time.time() if gpu_metrics else None
            try:
                raw = backend.observe(min(end, now + SAMPLE_TIMEOUT_S))
            except SAMPLE_ERRORS as error:
                raw = {"read_errors": {"observer": type(error).__name__}}
            row = {key: safe_number(raw.get(key)) for key in GAUGES}
            errors = dict(raw.get("read_errors", {}))
            for key in sorted(required):
                if row[key] is None:
                    errors.setdefault(key, "MissingValue")
            scrape = raw.get("scrape")
            if not scrape or all(value is None for value in scrape.values()):
                errors.setdefault("scrape", "MissingValue")
            samples.append(
                {
                    "at_s": now - start,
                    **({"sample_epoch_s": sampled_epoch} if gpu_metrics else {}),
                    "missing": bool(errors),
                    "read_errors": errors,
                    "scrape": scrape,
                    **row,
                }
            )
            # Start at most one sample per cadence. Overruns skip time slots
            # rather than queuing samples or compressing their timestamps.
            stopped.wait(max(0, now + SAMPLE_CADENCE_S - time.monotonic()))

    def send(slot, stop):
        at = time.monotonic() - start
        data = backend.offer(slot["prompt"], slot["output_cap"], min(end, stop))
        return {**data, "dispatch_s": at}

    observer = threading.Thread(target=sample, daemon=True)
    observer.start()
    try:
        if hasattr(backend, "window"):
            seen = backend.window(end)
        else:
            seen = scheduler(
                send,
                [(r["offset_ns"] / 1e9, r) for r in rows],
                window_s=offer_end,
                drain_s=DRAIN_S,
                start=start,
            )
    finally:
        stopped.set()
        observer.join(
            timeout=min(SAMPLE_TIMEOUT_S + 1, max(0, end - time.monotonic()) + 1)
        )
        write_rows(output / "gauges.jsonl", samples)
    if observer.is_alive():
        raise TimeoutError("inf054_observer_stop")
    safe = []
    second = None
    for slot, data in zip(rows, seen, strict=True):
        outcome = data["outcome"]
        if outcome not in OUTCOMES:
            raise ValueError("inf054_offer_outcome")
        row = {
            "arm": arm,
            "cycle": cycle,
            "slot": slot["slot"],
            "scheduled_s": slot["offset_ns"] / 1e9,
            "outcome": outcome,
            **{
                key: safe_number(data.get(key))
                for key in (
                    "dispatch_s",
                    "http_status",
                    "ttft_s",
                    "completed_s",
                    "completion_tokens",
                    "replica_ordinal",
                )
            },
        }
        code = data.get("gateway_code")
        if row["http_status"] == 429:
            row["gateway_code"] = code if code in GATEWAY_CODES else "other"
        if outcome == "completed":
            if any(
                row[key] is None
                for key in ("dispatch_s", "ttft_s", "completed_s", "completion_tokens")
            ):
                raise ValueError("inf054_complete_fields")
            if row["replica_ordinal"] == 1:
                timestamp = row["dispatch_s"] + row["completed_s"]
                second = timestamp if second is None else min(second, timestamp)
        safe.append(row)
    write_rows(output / "offers.jsonl", safe)
    return {
        "offered": len(safe),
        "second_serving_s": second,
        "windows": summarize(safe, second, offer_end=offer_end),
        "samples": len(samples),
        "complete_samples": sum(not sample["missing"] for sample in samples),
        "ready_replica_minutes": sum(
            first["ready"] * (second["at_s"] - first["at_s"]) / 60
            for first, second in zip(samples, samples[1:])
            if first["ready"] is not None
        )
        if any(sample["ready"] is not None for sample in samples)
        else None,
    }


def engine_readiness_seconds(probe):
    period = probe["periodSeconds"]
    failures = probe["failureThreshold"]
    if any(type(value) is not int or value <= 0 for value in (period, failures)):
        raise ValueError("inf054_startup_probe_bound")
    return period * failures + READY_HOLD_S + READY_PROBE_S


def gpu_release_seconds():
    import yaml
    from inf054_dcgm import CADVISOR_S
    from inf063_chart import CHART

    values = yaml.safe_load((CHART / "values.yaml").read_bytes())
    return (
        PREPARATION_S
        + engine_readiness_seconds(values["engine"]["startupProbe"])
        + CADVISOR_S
    )


def run(
    ports,
    rendered,
    sha256,
    output,
    *,
    absolute_end,
    scheduler=run_window,
    cpu_proof=False,
    rehearsal_burst_s=None,
):
    """Run fixed-1, KEDA and fixed-2, with a fresh chart release per cycle.

    The reviewed cluster adapter owns the release context and supplies a
    backend with bounded offer, observe, downscale and TSDB snapshot calls.
    """
    from inf054_dcgm import DIAGNOSTICS_S, LATER_WAIT_S, WAIT_S

    rows = read_tape(rendered, sha256)
    offer_end = BASELINE_S + BURST_SECONDS
    if rehearsal_burst_s is not None:
        if not cpu_proof or not 0 < rehearsal_burst_s < BURST_SECONDS:
            raise ValueError("inf054_rehearsal_burst")
        offer_end = BASELINE_S + rehearsal_burst_s
        rows = [row for row in rows if row["offset_ns"] < offer_end * 10**9]
    output.mkdir(exist_ok=False)
    records = []
    transfer_left = TRANSFER_S
    cycles = (
        [("keda", 1)]
        if cpu_proof
        else [(arm, number) for arm in ARMS for number in range(1, CYCLES + 1)]
    )
    downscale = ("keda", 1 if cpu_proof else CYCLES)
    release_seconds = RESET_S if cpu_proof else gpu_release_seconds()
    for index, (arm, number) in enumerate(cycles):
        remaining = cycles[index:]
        needed = workload_reserve(
            len(remaining),
            observe_downscale=downscale in remaining,
            transfer=transfer_left,
            release_seconds=release_seconds,
            dcgm_seconds=(
                0
                if cpu_proof
                else DIAGNOSTICS_S
                + len(remaining) * LATER_WAIT_S
                + (WAIT_S - LATER_WAIT_S if index == 0 else 0)
            ),
        )
        if time.monotonic() + needed > absolute_end:
            raise TimeoutError("inf054_cycle_reserve")
        cycle = output / f"{arm}-{number}"
        cycle.mkdir()
        summary = {
            "arm": arm,
            "cycle": number,
            "tape_sha256": sha256,
            "complete": False,
        }
        try:
            with ports.release(
                arm,
                number,
                serving_values(arm),
                time.monotonic() + (RESET_S if cpu_proof else PREPARATION_S),
            ) as backend:
                try:
                    work_end = absolute_end - transfer_left - TEARDOWN_S
                    summary.update(
                        workload_cycle(
                            backend,
                            rows,
                            cycle,
                            arm=arm,
                            cycle=number,
                            end=work_end,
                            scheduler=scheduler,
                            offer_end=offer_end,
                        )
                    )
                    if (arm, number) == downscale:
                        summary["downscale"] = backend.downscale(
                            min(work_end, time.monotonic() + OBSERVE_DOWNSCALE_S)
                        )
                finally:
                    if hasattr(backend, "scale"):
                        write_rows(cycle / "scale.jsonl", backend.scale)
                    freeze_start = time.monotonic()
                    transfer_end = min(
                        freeze_start + transfer_left, absolute_end - TEARDOWN_S
                    )
                    binding, read = backend.freeze_tsdb(transfer_end)
                    stored = transfer_snapshot(
                        read, binding, cycle / "tsdb.tar.gz", transfer_end
                    )
                    spent = time.monotonic() - freeze_start
                    transfer_left -= spent
                    write_json(
                        cycle / "tsdb-receipt.json",
                        {**stored, "freeze_and_transfer_s": spent},
                    )
            summary["complete"] = True
        finally:
            write_json(cycle / "summary.json", summary)
            records.append(summary)
            write_json(output / "summary.json", records)
    return records


def workload_reserve(
    cycles,
    *,
    observe_downscale,
    transfer=TRANSFER_S,
    release_seconds=RESET_S,
    dcgm_seconds=0,
):
    return (
        cycles * (release_seconds + BASELINE_S + BURST_SECONDS + DRAIN_S)
        + (OBSERVE_DOWNSCALE_S if observe_downscale else 0)
        + dcgm_seconds
        + transfer
        + TEARDOWN_S
    )
