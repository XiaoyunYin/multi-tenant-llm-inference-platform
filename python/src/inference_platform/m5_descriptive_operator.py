"""Thin DEC-100 sequence; provider lifecycle remains the caller's sealed binding."""

import hashlib
import json
import math
import re
import time
from pathlib import Path

from .calibration import CalibrationConfig, run_calibration
from .m5_descriptive import stream, summarize
from .r1_manifest import epoch, row
from .stage_c_tokenizer import pinned_tokenizer

LEVELS = (1, 4, 16)
CLIENT_DRAIN_SECONDS = 120
SMOKE_STREAM_SECONDS = 30
CLIENT_HTTP_TIMEOUT_SECONDS = 5
SMOKE_BOUNDARIES = (("/", 404), ("/metrics", 404), ("/admin", 404), ("/v1/chat/completions", 401))
OBSERVER_STOP_SECONDS = 5
TASK_CONTROL_MARGIN_SECONDS = 30
ROLLOUT_ACTION_SECONDS = 120
PHASES = (
    "provision",
    "smoke",
    "load",
    "gateway_rollout",
    "replica_rollout",
    "export",
    "retrieve",
    "teardown",
    "inventory",
)


def task_work_seconds(task, startup_seconds, rollout_action_seconds):
    """Maximum submitted work; replacement readiness and measured load run concurrently."""
    if task["kind"] == "smoke":
        return SMOKE_STREAM_SECONDS + len(SMOKE_BOUNDARIES) * CLIENT_HTTP_TIMEOUT_SECONDS
    client = len(task["levels"]) * (task["duration"] + CLIENT_DRAIN_SECONDS)
    if "replacement" not in task:
        return client
    return (
        max(client, rollout_action_seconds + startup_seconds)
        + OBSERVER_STOP_SECONDS
        + CLIENT_HTTP_TIMEOUT_SECONDS
    )


def task_poll_budget(task, startup_seconds, rollout_action_seconds):
    return (
        task_work_seconds(task, startup_seconds, rollout_action_seconds)
        + TASK_CONTROL_MARGIN_SECONDS
    )


def workload_budget(
    warmup_seconds,
    level_seconds,
    gateway_seconds,
    vllm_seconds,
    *,
    startup_seconds,
    rollout_action_seconds,
):
    tasks = (
        {"kind": "smoke"},
        {"kind": "load", "levels": [1], "duration": warmup_seconds},
        {"kind": "load", "levels": LEVELS, "duration": level_seconds},
        {"kind": "load", "levels": [4], "duration": gateway_seconds, "replacement": {}},
        {"kind": "load", "levels": [4], "duration": vllm_seconds, "replacement": {}},
    )
    return sum(task_poll_budget(task, startup_seconds, rollout_action_seconds) for task in tasks)


def session_timing(startup_seconds, payload_upload_seconds=0):
    """Reserve both retrieval hops and cleanup inside the original five hours."""
    from .package_a_cloud import transfer_seconds

    if type(startup_seconds) is not int or startup_seconds <= 0:
        raise ValueError("descriptive:startup_bound")
    if type(payload_upload_seconds) is not int or payload_upload_seconds < 0:
        raise ValueError("descriptive:payload_upload_bound")
    if ROLLOUT_ACTION_SECONDS + startup_seconds + 60 > 900:
        raise ValueError("descriptive:startup_exceeds_replacement_window")
    one_hop = transfer_seconds(512 * 1024**2)
    # Warmup/drain, three measured levels/drains, two rollouts/drains, smoke.
    workload = workload_budget(
        120,
        600,
        600,
        900,
        startup_seconds=startup_seconds,
        rollout_action_seconds=ROLLOUT_ACTION_SECONDS,
    )
    available = 18000 - 2 * one_hop - 1800 - workload - 2 * startup_seconds - payload_upload_seconds
    # Round 379 R536: Round 376 provision was 1581.078 s before upload
    # finished. Reserve twice that observation plus 60 s for Apply/staging.
    # Upload and startup still have their own unchanged, conservative reserves.
    apply_staging = math.ceil(2 * 1581.078 + 60)
    wait = max(0, available - apply_staging)
    return {
        "session_seconds": 18000,
        "receipt_limit_bytes": 512 * 1024**2,
        "one_retrieval_seconds": one_hop,
        "retrieval_reserve_seconds": 2 * one_hop,
        "cleanup_reserve_seconds": 1800,
        "gateway_rollout_seconds": 600,
        "vllm_rollout_seconds": 900,
        "rollout_action_seconds": ROLLOUT_ACTION_SECONDS,
        "minimum_workload_seconds": workload,
        "initial_startup_budget_seconds": 2 * startup_seconds,
        "source_upload_budget_seconds": payload_upload_seconds,
        "infrastructure_before_capacity_wait_seconds": available,
        "apply_through_staging_reserve_seconds": apply_staging,
        "capacity_wait_budget_seconds": wait,
        "capacity_cycle_spacing_seconds": 60,
        "remaining_infrastructure_seconds": available - wait,
    }


def phase_deadline(original_end, timing, phase):
    stop = original_end - timing["cleanup_reserve_seconds"]
    if phase == "retrieve":
        return stop
    if phase == "export":
        return stop - timing["one_retrieval_seconds"]
    return stop - timing["retrieval_reserve_seconds"]


def execute(ports, output, *, deadline, rehearsal=False):
    """Same order and finally cleanup for CPU and later approved EKS adapters.

    The caller provides an original absolute monotonic deadline and independent
    backstop evidence. Nothing here creates an approval or a paid plan.
    """
    output = Path(output)
    if not math.isfinite(deadline):
        raise ValueError("descriptive:finite_original_deadline_required")
    output.mkdir(parents=True, exist_ok=False)
    receipt = {
        "schema": "m5-descriptive.v1",
        "complete": False,
        "rehearsal": rehearsal,
        "phases": [],
        "substitutions": ports.substitutions,
        "deadline_monotonic": deadline,
    }

    def phase(name, function):
        if name not in {"teardown", "inventory"} and time.monotonic() >= deadline - 300:
            raise TimeoutError("descriptive:session_deadline")
        item = {"name": name, "start_monotonic": time.monotonic(), "status": "RUNNING"}
        receipt["phases"].append(item)
        try:
            result = function()
            if name in {"teardown", "inventory"} and (
                not isinstance(result, dict) or result.get("complete") is not True
            ):
                raise ValueError("descriptive:" + name + "_incomplete")
            item.update(status="PASS", result=result)
            return result
        except Exception as error:
            item.update(status="FAILED", error=type(error).__name__ + ":" + str(error))
            raise
        finally:
            item["elapsed_s"] = time.monotonic() - item["start_monotonic"]
            (output / "receipt.json").write_text(
                json.dumps(receipt, indent=2, sort_keys=True) + "\n"
            )

    failed = None

    def retrieve_verified(expected):
        retrieved = ports.retrieve()
        if expected != retrieved:
            raise ValueError("descriptive:retrieval_hash_mismatch")
        return retrieved

    try:
        phase("provision", ports.provision)
        phase("smoke", ports.smoke)
        phase("load", lambda: ports.load(LEVELS))
        phase("gateway_rollout", lambda: ports.rollout("gateway"))
        phase("replica_rollout", lambda: ports.rollout("vllm"))
        frozen = phase("export", ports.export)

        phase("retrieve", lambda: retrieve_verified(frozen))
        if frozen.get("kind") == "repo-free-diagnostics":
            # Diagnostics can be retrieved successfully without establishing
            # that the workload's frozen evidence was exported completely.
            raise RuntimeError("descriptive:diagnostics_only_export")
    except Exception as error:
        failed = error
        receipt["halt"] = type(error).__name__ + ":" + str(error)
    finally:
        if failed is not None and not any(p["name"] == "export" for p in receipt["phases"]):
            # Preserve completed/failed client records after a work-phase error;
            # never rerun measurement or a partially attempted freeze.
            try:
                frozen_failure = phase("export", ports.export)
                phase("retrieve", lambda: retrieve_verified(frozen_failure))
            except Exception as error:
                receipt.setdefault("diagnostic_errors", []).append(
                    type(error).__name__ + ":" + str(error)
                )
        for name in ("teardown", "inventory"):
            try:
                phase(name, getattr(ports, name))
            except Exception as error:
                failed = failed or error
                receipt.setdefault("cleanup_errors", []).append(
                    type(error).__name__ + ":" + str(error)
                )
        receipt["complete"] = failed is None
        (output / "receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    if failed:
        raise failed
    return receipt


def build_corpus():
    tokenizer = pinned_tokenizer()
    return {
        f"p{i:03}": row(f"p{i:03}", "descriptive-not-exported", tokenizer)["request"]["messages"]
        for i in range(384)
    }


def load(ports, levels, *, duration, deadline, corpus=None, label="load"):
    """Reuse the existing calibration scheduler and R1 exact prompt producer."""
    if not re.fullmatch(r"[a-z][a-z0-9_]{0,40}", label):
        raise ValueError("descriptive:client_artifact_label")
    corpus = corpus or build_corpus()
    order = epoch("measure", "b1")
    summaries = []
    for level in levels:
        config = CalibrationConfig(
            url=ports.client_url,
            token=ports.credential,
            tenant_id=ports.tenant_id,
            model=ports.model,
            run_id=f"m5-level-{level}",
            max_tokens=1,
            timeout_seconds=30,
            sample_interval_ms=250,
            metrics_endpoints=ports.metrics_endpoints,
        )

        def request(config, digest, start_ns, prompt, request_deadline=None):
            value = stream(
                config,
                digest,
                start_ns,
                prompt,
                request_deadline,
                tls_context=getattr(ports, "tls_context", None),
            )
            completion = value.get("completion_offset_ns")
            value["completion_monotonic_ns"] = (
                start_ns + completion if completion is not None else None
            )
            return value

        result = run_calibration(
            config,
            (level,),
            cycle_prompt_factory=lambda _index, worker, cycle, level=level: corpus[
                order[(cycle * level + worker) % len(order)][0]
            ],
            deadline=deadline,
            level_duration_seconds=duration,
            drain_seconds=CLIENT_DRAIN_SECONDS,
            request_function=request,
        )
        if result["status"] != "completed" or len(result["levels"]) != 1:
            raise ValueError("descriptive:load_incomplete")
        block = result["levels"][0]
        directory = Path(ports.output) / "clients"
        directory.mkdir(exist_ok=True)
        path = directory / f"{label}-level-{level}.jsonl"
        # Client outcomes and timing only: no credential, prompt, URL, raw SSE
        # content or private backend address survives in the frozen export.
        with path.open("x", encoding="utf-8", newline="\n") as handle:
            for ordinal, record in enumerate(block["records"]):
                public = {
                    key: record.get(key)
                    for key in (
                        "configuration_digest",
                        "dispatch_offset_ns",
                        "first_content_offset_ns",
                        "completion_offset_ns",
                        "completion_monotonic_ns",
                        "outcome",
                        "http_status",
                        "dispatched",
                        "admitted",
                        "error_code",
                        "itl_ns",
                        "strict_terminal",
                    )
                }
                public["dispatched"] = record.get(
                    "dispatched", record.get("dispatch_offset_ns") is not None
                )
                public["admitted"] = record.get(
                    "admitted", True if record.get("http_status") == 200 else None
                )
                public.update(schema="m5-descriptive-client.v1", ordinal=ordinal)
                public["backend_slot"] = {"vllm-0": 0, "vllm-1": 1}.get(
                    record.get("backend_id"), "unmapped"
                )
                handle.write(json.dumps(public, sort_keys=True, separators=(",", ":")) + "\n")
        summaries.append(
            {
                "concurrency": level,
                "requested_seconds": duration,
                "summary": summarize(block["records"], min(duration, block["duration_ns"] / 1e9)),
                "load_and_drain_elapsed_s": block["duration_ns"] / 1e9,
                "client_records": {
                    "path": path.relative_to(ports.output).as_posix(),
                    "bytes": path.stat().st_size,
                    "sha256": file_digest(path),
                },
                "sampler_started_before_load": block["sampler_started_before_load"],
            }
        )
    return summaries


def file_inventory(directory):
    """Byte-addressed frozen export inventory, no credentials or implicit files."""
    return {
        path.relative_to(directory).as_posix(): {
            "bytes": path.stat().st_size,
            "sha256": file_digest(path),
        }
        for path in sorted(Path(directory).rglob("*"))
        if path.is_file()
    }


def file_digest(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while chunk := handle.read(1024**2):
            digest.update(chunk)
    return digest.hexdigest()
