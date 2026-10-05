"""No-cost INF-011 Stage C harness for controlled timed-run rehearsal."""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from .calibration import CalibrationConfig, _metrics, run_calibration
from .clocks import measurement_clocks
from .kv_event_capture import derive_event_inventory, read_http_sse_event_stream
from .records import content_digest
from .stage_c_capture import docker, finish_capture, prepare_paths, start_live_capture
from .stage_c_prompts import (
    exact_prompt,
    identity_messages,
    prompt_bank,
    prompt_footprint,
    saturation_identity,
)
from .stage_c_sizing import clustered_counts
from .time_budget import BudgetExhausted, deadline_urlopen, remaining_seconds


@dataclass(frozen=True, slots=True)
class StageCConfig:
    """One explicit Stage C protocol configuration."""

    url: str
    token: str
    tenant_id: str
    model: str
    run_id: str
    reset_url: str
    tokenize_url: str
    gateway_mode: bool = True
    saturation_levels: tuple[int, ...] = (1, 2, 4, 8, 12, 16, 24, 32, 48, 64)
    reference_prefix_counts: tuple[int, ...] = (4, 8, 16, 32)
    reference_concurrency: int = 4
    rewarm_repeats: int = 3
    rewarm_samples: int = 8
    saturation_prompt_repetitions: int = 1_500
    max_tokens: int = 128
    sample_interval_ms: int = 100
    timeout_seconds: float = 180.0
    metrics_endpoints: tuple[tuple[str, str], ...] = ()
    process_pids: tuple[int, ...] = ()
    fake_event_url: str | None = None
    decision_prompt_export_path: str | None = None
    gateway_config_log: str | None = None
    expected_admission_configuration: dict[str, Any] | None = None
    kv_event_endpoint: str = "tcp://127.0.0.1:5557"
    kv_event_topic: str = "kv-events"
    kv_probe_timeout_seconds: float = 30
    kv_capture_staging_error: str | None = None
    run_time_budgets_seconds: tuple[float, ...] = (3000, 2700, 1800, 3600)
    session_window_seconds: float = 14400
    cold_readiness_planning_seconds: float = 2015
    instance_boot_unix_s: float | None = None
    instance_termination_unix_s: float | None = None
    observed_readiness_unix_s: float | None = None
    evidence_export_margin_seconds: float = 600
    cleanup_margin_seconds: float = 600
    minimum_useful_run_seconds: tuple[float, ...] = (300, 300, 180, 600)
    protocol_version: str = "legacy-rehearsal"
    saturation_prompt_tokens: int = 6144
    reference_prompt_tokens: int = 1024
    reference_max_tokens: int = 1
    reference_target_capacity_ratios: tuple[float, ...] = (0.5, 0.8, 0.9, 1, 1.1, 1.25, 1.5)
    measured_capacity_blocks: int = 3891
    sustained_level_seconds: float = 90
    drain_seconds: float = 120
    minimum_cycle_seconds: float = 2
    expected_first_item_timeout_seconds: float = 120
    decision_export_output_path: str | None = None
    kv_capture_output_path: str | None = None
    kv_capture_stop_file: str | None = None
    local_rehearsal: bool = False

    def validate(self) -> None:
        for name, value in (
            ("url", self.url),
            ("tenant_id", self.tenant_id),
            ("model", self.model),
            ("run_id", self.run_id),
            ("reset_url", self.reset_url),
            ("tokenize_url", self.tokenize_url),
        ):
            if not isinstance(value, str) or not value:
                raise ValueError(f"{name} must be a non-empty string")
        for name, value in (
            ("session_window_seconds", self.session_window_seconds),
            ("cold_readiness_planning_seconds", self.cold_readiness_planning_seconds),
            ("evidence_export_margin_seconds", self.evidence_export_margin_seconds),
            ("instance_boot_unix_s", self.instance_boot_unix_s),
            ("instance_termination_unix_s", self.instance_termination_unix_s),
            ("observed_readiness_unix_s", self.observed_readiness_unix_s),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
            ):
                raise ValueError(f"{name} must be finite")
        if not 0 < self.session_window_seconds <= 14400:
            raise ValueError("session window must be within the four-hour maximum")
        if not 0 < self.evidence_export_margin_seconds < self.session_window_seconds:
            raise ValueError("evidence export margin must be positive and smaller than the window")
        if self.cleanup_margin_seconds < 600 or not math.isfinite(self.cleanup_margin_seconds):
            raise ValueError("cleanup requires at least 600 finite seconds")
        if not 0 <= self.instance_boot_unix_s <= self.observed_readiness_unix_s:
            raise ValueError("observed readiness must be at or after the instance boot anchor")
        if not math.isclose(
            self.instance_termination_unix_s - self.instance_boot_unix_s,
            self.session_window_seconds,
            abs_tol=1e-6,
            rel_tol=0,
        ):
            raise ValueError("termination time must equal boot anchor plus session window")
        if self.cold_readiness_planning_seconds < 2015:
            raise ValueError(
                "cold readiness planning must allow at least the measured 2015 seconds"
            )
        if len(self.run_time_budgets_seconds) != 4 or any(
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or value <= 0
            for value in self.run_time_budgets_seconds
        ):
            raise ValueError("four finite positive run time budgets are required")
        if len(self.minimum_useful_run_seconds) != 4 or any(
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or not 0 < value <= budget
            for value, budget in zip(
                self.minimum_useful_run_seconds, self.run_time_budgets_seconds, strict=True
            )
        ):
            raise ValueError("four positive minimum useful durations must fit their run budgets")
        if sum(self.run_time_budgets_seconds) >= (
            self.session_window_seconds
            - self.cold_readiness_planning_seconds
            - self.evidence_export_margin_seconds
            - self.cleanup_margin_seconds
        ):
            raise ValueError(
                "run time budgets must leave time after cold readiness within the session"
            )
        if not isinstance(self.gateway_mode, bool):
            raise ValueError("gateway_mode must be a boolean")
        if not self.saturation_levels or any(level <= 0 for level in self.saturation_levels):
            raise ValueError("saturation_levels must contain positive concurrency values")
        if self.reference_concurrency <= 0:
            raise ValueError("reference_concurrency must be positive")
        if not self.reference_prefix_counts or any(
            count <= 0 or count % self.reference_concurrency
            for count in self.reference_prefix_counts
        ):
            raise ValueError(
                "reference prefix counts must be positive multiples of reference_concurrency"
            )
        if self.rewarm_repeats <= 0 or self.rewarm_samples <= 0:
            raise ValueError("rewarm_repeats and rewarm_samples must be positive")
        if self.saturation_prompt_repetitions <= 0:
            raise ValueError("saturation_prompt_repetitions must be positive")
        if self.max_tokens <= 0 or self.sample_interval_ms <= 0 or self.timeout_seconds <= 0:
            raise ValueError("token, sample, and timeout values must be positive")
        if not math.isfinite(self.kv_probe_timeout_seconds) or self.kv_probe_timeout_seconds <= 2:
            raise ValueError("kv_probe_timeout_seconds must be finite and exceed setup reserve")
        if self.protocol_version == "r0-v2":
            if self.evidence_export_margin_seconds < 600:
                raise ValueError("r0-v2 requires at least 600s for join/export and cleanup")
            for name, value in (
                ("sustained_level_seconds", self.sustained_level_seconds),
                ("drain_seconds", self.drain_seconds),
                ("minimum_cycle_seconds", self.minimum_cycle_seconds),
            ):
                if not math.isfinite(value) or value <= 0:
                    raise ValueError(f"{name} must be finite and positive")
            if not self.gateway_mode:
                raise ValueError("r0-v2 requires the measured gateway request path")
            if self.reference_max_tokens != 1:
                raise ValueError("r0-v2 reference runs must be prefill-only")
            if not self.local_rehearsal and (
                self.sustained_level_seconds != 90
                or self.saturation_prompt_tokens != 6144
                or self.reference_prompt_tokens != 1024
                or self.max_tokens != 128
                or self.reference_concurrency != 4
                or self.measured_capacity_blocks != 3891
                or self.reference_target_capacity_ratios != (0.5, 0.8, 0.9, 1, 1.1, 1.25, 1.5)
                or self.fake_event_url is not None
            ):
                raise ValueError(
                    "paid r0-v2 prompt sizes and duration must match approved protocol"
                )
            if self.expected_first_item_timeout_seconds != 120:
                raise ValueError("r0-v2 first item timeout must be 120 seconds")
            if not all((self.decision_prompt_export_path, self.decision_export_output_path)):
                raise ValueError("r0-v2 decision export paths required")
            if not self.fake_event_url and not all(
                (self.kv_capture_output_path, self.kv_capture_stop_file)
            ):
                raise ValueError("live capture output and cooperative stop path required")


def _base_calibration(config: StageCConfig, suffix: str) -> CalibrationConfig:
    return CalibrationConfig(
        url=config.url,
        token=config.token,
        tenant_id=config.tenant_id,
        model=config.model,
        run_id=f"{config.run_id}-{suffix}",
        policy="stage_c_r0_v2" if config.protocol_version == "r0-v2" else "stage_c_rehearsal",
        gateway_mode=config.gateway_mode,
        max_tokens=config.max_tokens,
        sample_interval_ms=config.sample_interval_ms,
        timeout_seconds=config.timeout_seconds,
        metrics_endpoints=config.metrics_endpoints,
        process_pids=config.process_pids,
        decision_prompt_export_path=config.decision_prompt_export_path,
    )


def _reset_prefix_cache(config: StageCConfig, deadline: float | None = None) -> None:
    request = urllib.request.Request(
        config.reset_url.rstrip("/") + "/reset_prefix_cache",
        headers={"Authorization": f"Bearer {config.token}"},
        method="POST",
    )
    try:
        with deadline_urlopen(request, timeout=5, deadline=deadline) as response:
            body = json.loads(response.read(64 * 1024))
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as error:
        remaining_seconds(deadline, 1)
        raise RuntimeError(f"prefix cache reset failed: {type(error).__name__}") from error
    if not isinstance(body, dict) or body.get("success") is not True:
        raise RuntimeError("prefix cache reset did not return success=true")


def _tokenize_preflight(config: StageCConfig, deadline: float) -> dict[str, Any]:
    request_body = json.dumps(
        {
            "model": config.model,
            "messages": [{"role": "user", "content": "stage-c tokenizer preflight"}],
            "add_generation_prompt": True,
        },
        separators=(",", ":"),
    ).encode()
    request = urllib.request.Request(
        config.tokenize_url.rstrip("/") + "/tokenize",
        data=request_body,
        headers={"Authorization": f"Bearer {config.token}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with deadline_urlopen(request, timeout=5, deadline=deadline) as response:
            payload = json.loads(response.read(1 << 20))
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as error:
        remaining_seconds(deadline, 1)
        raise RuntimeError(f"tokenization preflight failed: {type(error).__name__}") from error
    tokens = payload.get("tokens") if isinstance(payload, dict) else None
    if not isinstance(tokens, list) or not tokens or payload.get("count") != len(tokens):
        raise RuntimeError("tokenization preflight returned an invalid token response")
    return {"status": "ok", "token_count": len(tokens), "endpoint": config.tokenize_url}


def _check_gateway_pid(pid: int) -> None:
    if os.name != "posix":
        raise RuntimeError("gateway readiness requires the reviewed EC2 Linux topology")
    os.kill(pid, 0)


def _admission_preflight(config: StageCConfig) -> dict[str, Any]:
    if not config.gateway_mode:
        return {"status": "not_applicable_direct_backend_rehearsal"}
    expected = config.expected_admission_configuration
    if not config.gateway_config_log or not expected:
        raise RuntimeError("gateway effective admission configuration and reviewed inputs required")
    snapshots = []
    with Path(config.gateway_config_log).open(encoding="utf-8") as source:
        for line in source:
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if value.get("msg") == "gateway started":
                snapshots.append(value)
    if not snapshots:
        raise RuntimeError("gateway startup configuration snapshot missing")
    snapshot = snapshots[-1]
    observed = snapshot.get("admission_configuration")
    if observed != expected:
        raise RuntimeError(f"gateway admission configuration mismatch: observed={observed!r}")
    if config.local_rehearsal and os.name != "posix":
        from .process_metrics import process_snapshot

        if "error" in process_snapshot(snapshot["pid"]):
            raise RuntimeError("local rehearsal gateway PID not running")
    else:
        _check_gateway_pid(snapshot["pid"])
    if (
        config.protocol_version == "r0-v2"
        and snapshot.get("first_item_timeout_seconds") != config.expected_first_item_timeout_seconds
    ):
        raise RuntimeError("gateway first item timeout mismatch; require effective 120s")
    tenant = expected["tenants"][config.tenant_id]
    top = max(config.saturation_levels)
    if (
        min(
            expected["global_capacity"],
            expected["gateway_max_concurrent"],
            tenant["max_concurrent"],
            tenant["request_rate_limit"],
        )
        <= top
    ):
        raise RuntimeError("reviewed admission limits must exceed the top sweep level")
    return {
        "status": "ok",
        "effective_configuration": observed,
        "gateway_pid": snapshot["pid"],
        "first_item_timeout_seconds": snapshot.get("first_item_timeout_seconds"),
    }


def _counter(config: CalibrationConfig, suffix: str, deadline: float | None = None) -> float | None:
    remaining_seconds(deadline, 1)
    snapshot = _metrics(config, deadline).get("values", {})
    remaining_seconds(deadline, 1)
    values = [value for name, value in snapshot.items() if name.split("{", 1)[0].endswith(suffix)]
    return sum(values) if values else None


def _health_preflight(config: StageCConfig, deadline: float) -> dict[str, Any]:
    endpoints = {config.tokenize_url.rstrip("/") + "/health"}
    endpoints.add(config.url.rstrip("/") + ("/readyz" if config.gateway_mode else "/health"))
    if config.gateway_mode:
        endpoints.add(config.url.rstrip("/") + "/healthz")
    for _, base in config.metrics_endpoints:
        endpoints.add(base.rstrip("/") + "/metrics")
    for endpoint in sorted(endpoints):
        with deadline_urlopen(endpoint, timeout=5, deadline=deadline) as response:
            if response.status != 200:
                raise RuntimeError(f"readiness endpoint unhealthy: {endpoint}")
            response.read(1024 * 1024)
    return {"status": "ok", "endpoints": sorted(endpoints)}


def _publisher_preflight(config: StageCConfig, deadline: float) -> dict[str, Any]:
    if config.kv_capture_staging_error:
        return {"status": "unavailable", "reason": config.kv_capture_staging_error}
    if config.fake_event_url:
        # The fake shares the HTTP host and emits normalized events for the probe request.
        request = urllib.request.Request(
            config.tokenize_url.rstrip("/") + "/v1/chat/completions",
            data=json.dumps(
                {
                    "model": config.model,
                    "messages": [
                        {"role": "user", "content": "stage c publisher untimed probe " * 32}
                    ],
                    "max_tokens": 1,
                    "stream": True,
                }
            ).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with deadline_urlopen(request, timeout=5, deadline=deadline) as response:
            response.read(64 * 1024)
        events = read_http_sse_event_stream(config.fake_event_url)
        stored = sum(event["event_type"] == "BlockStored" for event in events)
        return {
            "status": "ok" if stored else "unavailable",
            "basis": "fake contract rehearsal",
            "decoded_block_stored_count": stored,
        }
    if not config.gateway_mode:
        return {"status": "unavailable", "reason": "direct rehearsal has no configured publisher"}
    timeout = remaining_seconds(deadline, config.kv_probe_timeout_seconds)
    from .stage_c_container import publisher_probe_argv

    command = publisher_probe_argv(
        config.kv_event_endpoint, config.kv_event_topic, config.model, max(0.1, timeout - 2)
    )
    probe = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    try:
        payload = json.loads(probe.stdout)
        if not isinstance(payload, dict):
            raise ValueError("publisher probe returned a non-object JSON value")
    except ValueError as error:
        payload = {"status": "unavailable", "reason": f"invalid publisher probe stdout: {error}"}
    payload.update(returncode=probe.returncode, stderr=probe.stderr)
    if probe.returncode != 0 or payload.get("decoded_block_stored_count", 0) <= 0:
        payload["status"] = "unavailable"
    return payload


def _runtime_readiness(config: StageCConfig, deadline: float) -> dict[str, Any]:
    checks: dict[str, Any] = {}
    try:
        if sys.version_info[:2] != (3, 12):
            raise RuntimeError("Stage C requires Python 3.12")
        if config.protocol_version == "r0-v2":
            from .host_disk import require_disk_headroom

            if config.local_rehearsal:
                from .stage_c_session import record_disk_readiness

                checks["root_disk"] = record_disk_readiness(
                    Path(config.decision_prompt_export_path).parent, rehearse=True
                )
            else:
                checks["root_disk"] = require_disk_headroom()
        checks["health_and_metrics"] = _health_preflight(config, deadline)
        checks["gateway_admission"] = _admission_preflight(config)
        checks["tokenize"] = _tokenize_preflight(config, deadline)
        if config.protocol_version == "r0-v2":
            native = _metrics(_base_calibration(config, "sizing"), deadline)["values"]
            capacity = {
                (int(n.group(1)), int(b.group(1)))
                for name in native
                if "cache_config_info{" in name
                and (n := re.search(r'num_gpu_blocks="(\d+)"', name))
                and (b := re.search(r'block_size="(\d+)"', name))
            }
            if capacity != {(config.measured_capacity_blocks, 16)}:
                raise RuntimeError("native KV capacity/block size differs from reviewed sizing")
            saturation_tokens = []
            reference_tokens = []
            prompt_bank(
                config,
                "saturation",
                max(config.saturation_levels),
                config.saturation_prompt_tokens,
                deadline,
                tokenizations=saturation_tokens,
            )
            prompt_bank(
                config,
                "reference",
                max(config.reference_prefix_counts),
                config.reference_prompt_tokens,
                deadline,
                tokenizations=reference_tokens,
            )
            counts = clustered_counts(
                config.measured_capacity_blocks,
                config.reference_prompt_tokens // 16,
                config.reference_concurrency,
                list(config.reference_target_capacity_ratios),
            )
            if tuple(counts) != config.reference_prefix_counts:
                raise RuntimeError("reference corpus counts differ from runtime capacity sizing")
            checks["protocol_sizing"] = {
                "status": "ok",
                "native_capacity_blocks": config.measured_capacity_blocks,
                "saturation_prompt_tokens": config.saturation_prompt_tokens,
                "reference_prompt_tokens": config.reference_prompt_tokens,
                "reference_prefix_counts": counts,
                "saturation_prompt_footprint": prompt_footprint(saturation_tokens),
                "reference_corpus_footprints": [
                    {"count": count, **prompt_footprint(reference_tokens[:count])}
                    for count in counts
                ],
            }
            prepare_paths(config)
            checks["evidence_paths"] = {"status": "ok", "fresh_restricted_paths": True}
        _reset_prefix_cache(config, deadline)
        checks["cache_reset"] = {"status": "ok", "success": True}
    except BudgetExhausted:
        return {"status": "session_deadline_exhausted", "checks": checks}
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        return {"status": "failed", "reason": str(error), "checks": checks}
    try:
        checks["kv_publisher"] = _publisher_preflight(config, deadline)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        checks["kv_publisher"] = {"status": "unavailable", "reason": str(error)}
    # Publisher warm-up must not populate the first measured run's cache.
    try:
        _reset_prefix_cache(config, deadline)
    except BudgetExhausted:
        return {"status": "session_deadline_exhausted", "checks": checks}
    except (OSError, RuntimeError, ValueError) as error:
        return {"status": "failed", "reason": str(error), "checks": checks}
    return {"status": "ok", "checks": checks}


def _require_preload_sampling(run: dict[str, Any]) -> None:
    if not all(level.get("sampler_started_before_load") is True for level in run["levels"]):
        raise RuntimeError("a run level did not start the metrics sampler before load")


def _run_saturation(
    config: StageCConfig, suffix: str, deadline: float, result: dict[str, Any]
) -> None:
    calibration = _base_calibration(config, suffix)
    long_prefix = "stage-c long prompt token " * config.saturation_prompt_repetitions
    bank = (
        prompt_bank(
            config,
            "saturation",
            max(config.saturation_levels),
            config.saturation_prompt_tokens,
            deadline,
        )
        if config.protocol_version == "r0-v2"
        else None
    )

    def prompt(level_index: int, worker_index: int) -> str:
        return (
            bank[worker_index]
            if bank
            else f"{long_prefix}burst={level_index} request={worker_index}"
        )

    def cycle_prompt(level_index: int, worker_index: int, cycle: int) -> str:
        # Tokenizer work is outside the latency interval; it remains inside the
        # load/run deadline. A new first-block identity prevents warm-loop reuse.
        return exact_prompt(
            config.tokenize_url,
            config.model,
            saturation_identity(level_index, worker_index, cycle),
            config.saturation_prompt_tokens,
            deadline,
        )[0]

    _reset_prefix_cache(config, deadline)
    run = run_calibration(
        calibration,
        config.saturation_levels,
        prompt_factory=prompt,
        cycle_prompt_factory=cycle_prompt if bank else None,
        deadline=deadline,
        level_duration_seconds=config.sustained_level_seconds if bank else 0,
        drain_seconds=config.drain_seconds,
        minimum_cycle_seconds=config.minimum_cycle_seconds,
    )
    _require_preload_sampling(run)
    result.update(run)
    remaining_seconds(deadline, 1)


def _run_reference_capacity(
    config: StageCConfig, suffix: str, deadline: float, result: dict[str, Any]
) -> None:
    calibration = _base_calibration(config, suffix)
    if config.protocol_version == "r0-v2":
        calibration = replace(calibration, max_tokens=config.reference_max_tokens)
    tokenizations = []
    bank = (
        prompt_bank(
            config,
            "reference",
            max(config.reference_prefix_counts),
            config.reference_prompt_tokens,
            deadline,
            tokenizations=tokenizations,
        )
        if config.protocol_version == "r0-v2"
        else None
    )
    candidates: list[dict[str, Any]] = []
    result["candidates"] = candidates
    for prefix_count in config.reference_prefix_counts:
        _reset_prefix_cache(config, deadline)
        level_count = prefix_count // config.reference_concurrency

        def prompt(level_index: int, worker_index: int) -> str:
            prefix_index = level_index * config.reference_concurrency + worker_index
            return (
                bank[prefix_index]
                if bank
                else (f"reference-corpus-prefix-{prefix_index:08d} " * 31).strip()
            )

        levels = (config.reference_concurrency,) * level_count
        candidate: dict[str, Any] = {
            "distinct_prefix_count": prefix_count,
            "fixed_concurrency": config.reference_concurrency,
            "status": "in_progress",
        }
        candidates.append(candidate)
        before_queries = _counter(calibration, "vllm:prefix_cache_queries_total", deadline)
        before_hits = _counter(calibration, "vllm:prefix_cache_hits_total", deadline)
        populate = run_calibration(
            replace(calibration, run_id=f"{calibration.run_id}-populate-{prefix_count}"),
            levels,
            prompt_factory=prompt,
            deadline=deadline,
        )
        candidate["population"] = populate
        _require_preload_sampling(populate)
        remaining_seconds(deadline, 1)
        populated_queries = _counter(calibration, "vllm:prefix_cache_queries_total", deadline)
        populated_hits = _counter(calibration, "vllm:prefix_cache_hits_total", deadline)
        replay = run_calibration(
            replace(calibration, run_id=f"{calibration.run_id}-replay-{prefix_count}"),
            levels,
            prompt_factory=prompt,
            deadline=deadline,
        )
        candidate["replay"] = replay
        _require_preload_sampling(replay)
        remaining_seconds(deadline, 1)
        final_queries = _counter(calibration, "vllm:prefix_cache_queries_total", deadline)
        final_hits = _counter(calibration, "vllm:prefix_cache_hits_total", deadline)
        query_delta = None if final_queries is None else final_queries - (populated_queries or 0)
        hit_delta = None if final_hits is None else final_hits - (populated_hits or 0)
        candidate.update(
            {
                "distinct_prefix_count": prefix_count,
                "fixed_concurrency": config.reference_concurrency,
                "population": populate,
                "replay": replay,
                "prefix_query_delta_during_replay": query_delta,
                "prefix_hit_delta_during_replay": hit_delta,
                "all_replay_prefixes_hit": None if bank else hit_delta == prefix_count,
                "replay_token_hit_share": hit_delta / query_delta
                if query_delta and bank and hit_delta is not None
                else None,
                "max_tokens": calibration.max_tokens,
                "prompt_blocks": prompt_footprint(tokenizations[:prefix_count])["prompt_blocks"]
                if bank
                else None,
                "initial_counter_values": {"queries": before_queries, "hits": before_hits},
                "status": "completed",
            }
        )


def _run_rewarm(config: StageCConfig, suffix: str, deadline: float, result: dict[str, Any]) -> None:
    calibration = _base_calibration(config, suffix)
    repeats: list[dict[str, Any]] = []
    result["repeats"] = repeats
    for repeat in range(config.rewarm_repeats):
        _reset_prefix_cache(config, deadline)
        run = run_calibration(
            replace(calibration, run_id=f"{calibration.run_id}-reset-{repeat + 1}"),
            (1,) * config.rewarm_samples,
            prompt_factory=lambda _level, _worker: (
                identity_messages("rewarm", "repeated-reset-rewarm-prefix")
                if config.protocol_version == "r0-v2"
                else "repeated-reset-rewarm-prefix"
            ),
            deadline=deadline,
        )
        _require_preload_sampling(run)
        repeats.append({"repeat": repeat + 1, "run": run})
        remaining_seconds(deadline, 1)


def run_stage_c(
    config: StageCConfig,
    *,
    monotonic_clock: Callable[[], float] = time.perf_counter,
    wall_clock: Callable[[], float] = time.time,
    on_run_complete: Callable | None = None,
) -> dict[str, Any]:
    """Execute the four-run protocol against explicitly supplied endpoints."""

    config.validate()
    clock_error = None
    try:
        clocks = measurement_clocks(wall_clock=True)
    except RuntimeError as error:
        clocks = {"status": "failed", "reason": str(error)}
        clock_error = str(error)
    # Convert once from instance epoch timestamps into the recorder's monotonic domain.
    # Later wall-clock steps must not reset or extend the session allowance.
    measured_monotonic_s = monotonic_clock()
    measured_unix_s = wall_clock()
    if config.observed_readiness_unix_s > measured_unix_s:
        raise ValueError("observed readiness cannot be in the recorder's future")
    session_deadline_unix_s = (
        config.instance_termination_unix_s
        - config.evidence_export_margin_seconds
        - config.cleanup_margin_seconds
    )
    session_deadline = measured_monotonic_s + session_deadline_unix_s - measured_unix_s
    export_deadline = session_deadline + config.evidence_export_margin_seconds
    archive_windows = []
    readiness = {
        "instance_boot_unix_s": config.instance_boot_unix_s,
        "instance_termination_unix_s": config.instance_termination_unix_s,
        "observed_readiness_unix_s": config.observed_readiness_unix_s,
        "observed_readiness_seconds": config.observed_readiness_unix_s
        - config.instance_boot_unix_s,
        "evidence_export_margin_seconds": config.evidence_export_margin_seconds,
        "cleanup_margin_seconds": config.cleanup_margin_seconds,
        "session_deadline_unix_s": session_deadline_unix_s,
        "session_deadline_monotonic_s": session_deadline,
        "clock_pair": {"unix_s": measured_unix_s, "monotonic_s": measured_monotonic_s},
    }
    configuration = {
        "url": config.url.rstrip("/"),
        "token_configured": bool(config.token),
        "tenant_id": config.tenant_id,
        "model": config.model,
        "run_id": config.run_id,
        "reset_url": config.reset_url.rstrip("/"),
        "tokenize_url": config.tokenize_url.rstrip("/"),
        "gateway_mode": config.gateway_mode,
        "saturation_levels": list(config.saturation_levels),
        "reference_prefix_counts": list(config.reference_prefix_counts),
        "reference_concurrency": config.reference_concurrency,
        "rewarm_repeats": config.rewarm_repeats,
        "rewarm_samples": config.rewarm_samples,
        "saturation_prompt_repetitions": config.saturation_prompt_repetitions,
        "max_tokens": config.max_tokens,
        "sample_interval_ms": config.sample_interval_ms,
        "timeout_seconds": config.timeout_seconds,
        "metrics_endpoints": list(config.metrics_endpoints),
        "process_pids": list(config.process_pids),
        "fake_event_url": config.fake_event_url,
        "kv_event_endpoint": config.kv_event_endpoint,
        "kv_event_topic": config.kv_event_topic,
        "expected_admission_configuration": config.expected_admission_configuration,
        "run_time_budgets_seconds": list(config.run_time_budgets_seconds),
        "session_window_seconds": config.session_window_seconds,
        "cold_readiness_planning_seconds": config.cold_readiness_planning_seconds,
        "evidence_export_margin_seconds": config.evidence_export_margin_seconds,
        "cleanup_margin_seconds": config.cleanup_margin_seconds,
        "minimum_useful_run_seconds": list(config.minimum_useful_run_seconds),
        "cold_readiness_basis": "first us-west-2 session: launch to first response, 2015 seconds",
        "regional_readiness_warning": "us-east-1 cold readiness is unestablished; reserve is not a readiness guarantee",
        "remaining_time_reserve_seconds": (
            config.session_window_seconds
            - config.cold_readiness_planning_seconds
            - sum(config.run_time_budgets_seconds)
            - config.evidence_export_margin_seconds
            - config.cleanup_margin_seconds
        ),
    }
    for name in (
        "protocol_version",
        "saturation_prompt_tokens",
        "reference_prompt_tokens",
        "reference_max_tokens",
        "reference_target_capacity_ratios",
        "measured_capacity_blocks",
        "sustained_level_seconds",
        "drain_seconds",
        "minimum_cycle_seconds",
        "expected_first_item_timeout_seconds",
        "local_rehearsal",
    ):
        configuration[name] = getattr(config, name)
    if clock_error:
        gate = {"status": "failed", "reason": clock_error, "checks": {}}
    elif monotonic_clock() >= session_deadline:
        gate = {"status": "session_deadline_exhausted", "checks": {}}
    else:
        gate = _runtime_readiness(config, session_deadline)
    readiness["gate"] = gate
    gate_finished_unix_s = measured_unix_s + monotonic_clock() - measured_monotonic_s
    readiness["gate_finished_unix_s"] = gate_finished_unix_s
    readiness["gate_finished_seconds_since_boot"] = (
        gate_finished_unix_s - config.instance_boot_unix_s
    )
    preflight = gate["checks"].get("tokenize", {"status": gate["status"]})
    event_ready = gate["checks"].get("kv_publisher", {}).get("status") == "ok"
    core_failure = gate["status"] == "failed"
    capture_process = None
    if (
        config.protocol_version == "r0-v2"
        and event_ready
        and not config.fake_event_url
        and not core_failure
    ):
        try:
            capture_process = start_live_capture(config, session_deadline)
            gate["checks"]["capture_start"] = {"status": "ok", "same_container_subscriber": True}
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
            event_ready = False
            gate["checks"]["capture_start"] = {"status": "unavailable", "reason": str(error)}
    runs: list[dict[str, Any]] = []
    for index, kind in enumerate(
        (
            "long_prompt_saturation_sweep",
            "reference_capacity_calibration",
            "cache_reset_rewarm_curve",
            "stability_repeat_runs_1_and_2",
        )
    ):
        budget = config.run_time_budgets_seconds[index]
        started = monotonic_clock()
        available = max(0, session_deadline - started)
        minimum = config.minimum_useful_run_seconds[index]
        deadline = min(started + budget, session_deadline)
        run: dict[str, Any] = {
            "run_kind": kind,
            "status": "in_progress",
            "time_budget_seconds": budget,
            "minimum_useful_seconds": minimum,
            "available_session_seconds_at_start": available,
            "effective_deadline_monotonic_s": deadline,
            "deadline_capped_by_session": session_deadline < started + budget,
        }
        runs.append(run)
        if core_failure:
            run.update(
                status="skipped_readiness_failure",
                partial=True,
                elapsed_seconds=0,
                stop_reason=gate.get("reason", "required readiness failed"),
            )
            continue
        if available < minimum:
            run.update(
                status="skipped_session_deadline",
                partial=True,
                elapsed_seconds=0,
                stop_reason="minimum_useful_duration_does_not_fit",
            )
            continue
        try:
            if index == 0:
                _run_saturation(config, "run1", deadline, run)
            elif index == 1:
                _run_reference_capacity(config, "run2", deadline, run)
            elif index == 2:
                _run_rewarm(config, "run3", deadline, run)
            else:
                run["saturation"] = {}
                _run_saturation(config, "run4-stability", deadline, run["saturation"])
                run["reference_capacity"] = {}
                _run_reference_capacity(
                    config, "run4-stability", deadline, run["reference_capacity"]
                )
            run["status"] = "completed"
        except BudgetExhausted:
            run["status"] = "budget_exhausted"
            run["stop_reason"] = (
                "session_deadline_exhausted"
                if deadline == session_deadline
                else "run_time_budget_exhausted"
            )
        except (RuntimeError, OSError) as error:
            core_failure = True
            run.update(status="readiness_failure", stop_reason=str(error))
        run["elapsed_seconds"] = monotonic_clock() - started
        run["partial"] = run["status"] != "completed"
        if on_run_complete is not None:
            try:
                receipt = on_run_complete(index + 1, run)
                window = (receipt or {}).get("archive_export_window")
                if window:
                    archive_windows.append(window)
                    # Only shorten measurement; never extend the termination or cleanup bound.
                    session_deadline = min(
                        session_deadline, export_deadline - window["forecast_seconds"]
                    )
            except Exception as error:
                # Optional evidence must not abort core scheduling; control signals still propagate.
                run["checkpoint"] = {
                    "status": "failed",
                    "failure_type": type(error).__name__,
                    "event_lag_status": "unavailable",
                    "reason": "checkpoint callback failed; later measurements continue",
                }
    result: dict[str, Any] = {
        "schema": "inf011-stage-c-run.v3"
        if config.protocol_version == "r0-v2"
        else "inf011-stage-c-no-cost-rehearsal.v2",
        "measurement_basis": "scaled local fake rehearsal"
        if config.local_rehearsal
        else "declared same-host session endpoints; runtime evidence required",
        "clock_info": clocks,
        "paid_plan_generated": False,
        "aws_calls_made": False,
        "configuration": configuration,
        "configuration_digest": content_digest(configuration),
        "tokenization_preflight": preflight,
        "readiness": readiness,
        "timed_runs": runs,
        "archive_export_windows": archive_windows,
        "finalization": {
            "start": "immediately_after_last_run",
            "export_cutoff_is_ceiling_only": True,
            "action": "stop_capture_and_samplers_export_verify_then_teardown",
        },
        "status": "readiness_failed"
        if core_failure
        else ("partial" if any(run["partial"] for run in runs) else "completed"),
        "event_dependent_outputs": {
            "event_lag": "eligible" if event_ready else "unestablished",
            "event_derived_section_2_5": "eligible" if event_ready else "unestablished",
            "reason": "publisher probe passed; measurements still required"
            if event_ready
            else (
                "not_attempted_readiness_failed"
                if "kv_publisher" not in gate["checks"]
                else "KV publisher unavailable or unhealthy; skip event outputs only"
            ),
        },
    }
    events = None
    if event_ready and config.fake_event_url:
        try:
            events = read_http_sse_event_stream(
                config.fake_event_url, timeout_seconds=60, deadline=export_deadline
            )
            result["fake_kv_event_rehearsal"] = {
                "observed_event_count": len(events),
                "event_types": sorted({event["event_type"] for event in events}),
                "inventory": derive_event_inventory(events),
            }
        except (OSError, ValueError, RuntimeError) as error:
            event_ready = False
            result["fake_kv_event_rehearsal"] = {"status": "unestablished", "reason": str(error)}
            result["event_dependent_outputs"].update(
                event_lag="unestablished",
                event_derived_section_2_5="unestablished",
                reason="finite fake event replay failed: " + str(error),
            )
    if config.protocol_version == "r0-v2":

        def unobserved_id_count(value):
            if isinstance(value, dict):
                return int(
                    value.get("decision_prompt_export_status")
                    == "not_recorded_no_gateway_request_id"
                ) + sum(unobserved_id_count(v) for v in value.values())
            if isinstance(value, list):
                return sum(unobserved_id_count(v) for v in value)
            return 0

        result["decision_event_exclusions"] = {
            "unobserved_gateway_request_id_count": unobserved_id_count(runs),
            "basis": "gateway ID not observed; outcome retained; routing ownership unknown",
        }
        owned_paths = gate["checks"].get("evidence_paths", {}).get("status") == "ok"
        try:
            if event_ready and owned_paths:
                result["decision_event_export"] = finish_capture(config, events, export_deadline)
                matched = sum(
                    row["status"] == "observed"
                    for row in result["decision_event_export"]["routing_to_event_observation"]
                )
                result["decision_event_export"]["observed_correlation_count"] = matched
                if not matched:
                    result["event_dependent_outputs"]["event_lag"] = "unestablished"
            else:
                result["decision_event_export"] = {
                    "status": "unestablished",
                    "reason": "not_attempted_readiness_failed"
                    if "kv_publisher" not in gate["checks"]
                    else "event capture unavailable",
                }
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            result["decision_event_export"] = {"status": "unestablished", "reason": str(error)}
            result["event_dependent_outputs"]["event_lag"] = "unestablished"
        finally:
            if capture_process:
                try:
                    docker(
                        config,
                        ["exec", "inf011-vllm", "touch", config.kv_capture_stop_file],
                        export_deadline,
                        check=False,
                    )
                    capture_process.wait(timeout=remaining_seconds(export_deadline, 5))
                except (OSError, RuntimeError, subprocess.SubprocessError) as error:
                    result["finalization"]["capture_stop_error"] = str(error)
            if owned_paths:
                if capture_process:
                    try:
                        docker(
                            config,
                            [
                                "exec",
                                "--env",
                                "PYTHONDONTWRITEBYTECODE=1",
                                "inf011-vllm",
                                "python3",
                                "-B",
                                "-c",
                                "import os,sys; p=sys.argv[1]; os.unlink(p) if os.path.exists(p) else None",
                                config.decision_export_output_path,
                            ],
                            export_deadline,
                        )
                        result["finalization"]["container_raw_token_input_removed"] = True
                    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
                        result["finalization"]["container_raw_token_cleanup_error"] = str(error)
                for name in (
                    config.decision_prompt_export_path,
                    config.decision_export_output_path,
                ):
                    Path(name).unlink(missing_ok=True)
                result["finalization"]["raw_prompt_token_inputs_removed"] = True
    return result


def _config_from_json(path: Path) -> StageCConfig:
    raw = json.loads(path.read_text(encoding="utf-8"))
    for name in (
        "saturation_levels",
        "reference_prefix_counts",
        "metrics_endpoints",
        "process_pids",
        "run_time_budgets_seconds",
        "minimum_useful_run_seconds",
        "reference_target_capacity_ratios",
    ):
        if name in raw:
            raw[name] = tuple(tuple(item) if isinstance(item, list) else item for item in raw[name])
    return StageCConfig(**raw)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--finalize-argv",
        nargs=argparse.REMAINDER,
        help="Reviewed controller argv: stop helpers, export/hash verification, then teardown. "
        "Runs immediately after writing the artifact; never waits for the cutoff.",
    )
    args = parser.parse_args()
    config = _config_from_json(args.config)
    if config.protocol_version == "r0-v2" and not config.local_rehearsal:
        parser.error(
            "paid r0-v2 must use the reviewed inference_platform.stage_c_session entrypoint"
        )
    result = run_stage_c(config)
    from .disk_records import write_json

    write_json(args.output, result)
    if args.finalize_argv:
        # No shell string: argv survives spaces/quotes in staged paths.
        try:
            # Cleanup must also fit the persisted instance lifetime.
            timeout = max(0.1, config.instance_termination_unix_s - time.time())
            completed = subprocess.run(
                args.finalize_argv, shell=False, check=False, timeout=timeout
            )
            result["finalization"]["controller_exit_code"] = completed.returncode
        except (OSError, subprocess.TimeoutExpired) as error:
            result["finalization"].update(controller_exit_code=1, error=str(error))
        write_json(args.output, result)
        if result["finalization"]["controller_exit_code"]:
            return 1
    return int(result["status"] == "readiness_failed")


if __name__ == "__main__":
    raise SystemExit(main())
