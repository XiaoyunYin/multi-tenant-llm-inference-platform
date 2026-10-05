"""Bounded streaming calibration recorder for local rehearsal and INF-011 runs.

The recorder deliberately keeps the transport dependency-free.  It starts a
metrics sampler before each stepped burst, records one strict INF-004 outcome
per request, and writes a single JSON artifact containing the time-aligned
samples and request records.
"""

from __future__ import annotations

import argparse
import json
import threading
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

from .clocks import measurement_clocks
from .decision_export import append_prompt
from .disk_records import DiskList
from .process_metrics import process_snapshot
from .records import Outcome, OutcomeRecord, TokenCountSource, content_digest
from .stage_c_prompts import ChatPrompt, prompt_messages
from .time_budget import BudgetExhausted, deadline_urlopen, read_error_body, remaining_seconds


@dataclass(frozen=True, slots=True)
class CalibrationConfig:
    """Inputs that are hashed into every outcome record."""

    url: str
    token: str
    tenant_id: str
    model: str
    run_id: str
    policy: str = "calibration"
    gateway_mode: bool = True
    max_tokens: int = 512
    sample_interval_ms: int = 100
    timeout_seconds: float = 120.0
    prompt_text: str = "calibration"
    unique_prompt_per_request: bool = False
    metrics_endpoints: tuple[tuple[str, str], ...] = ()
    process_pids: tuple[int, ...] = ()
    decision_prompt_export_path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url.rstrip("/"),
            "tenant_id": self.tenant_id,
            "model": self.model,
            "run_id": self.run_id,
            "policy": self.policy,
            "gateway_mode": self.gateway_mode,
            "max_tokens": self.max_tokens,
            "sample_interval_ms": self.sample_interval_ms,
            "timeout_seconds": self.timeout_seconds,
            "prompt_sha256": sha256(self.prompt_text.encode("utf-8")).hexdigest(),
            "prompt_length_chars": len(self.prompt_text),
            "unique_prompt_per_request": self.unique_prompt_per_request,
            "metrics_endpoints": list(self.metrics_endpoints),
            "process_pids": list(self.process_pids),
        }


def _metrics_endpoint(url: str, token: str, deadline: float | None = None) -> dict[str, Any]:
    request = urllib.request.Request(
        f"{url.rstrip('/')}/metrics", headers={"Authorization": f"Bearer {token}"}
    )
    try:
        with deadline_urlopen(request, timeout=2, deadline=deadline) as response:
            body = response.read(1 << 20).decode("utf-8", errors="replace")
    except (OSError, urllib.error.URLError) as error:
        return {"error": type(error).__name__}
    values: dict[str, float] = {}
    for line in body.splitlines():
        if not line or line.startswith("#"):
            continue
        name, _, raw = line.partition(" ")
        try:
            values[name] = float(raw.strip())
        except ValueError:
            continue
    return {
        "values": values,
        "body": body,
        "raw_sha256": sha256(body.encode("utf-8")).hexdigest(),
    }


def _metrics(config: CalibrationConfig, deadline: float | None = None) -> dict[str, Any]:
    endpoints = config.metrics_endpoints or (("primary", config.url),)
    with ThreadPoolExecutor(max_workers=min(16, len(endpoints))) as executor:
        pending = {
            name: executor.submit(_metrics_endpoint, url, config.token, deadline)
            for name, url in endpoints
        }
        sources = {name: future.result() for name, future in pending.items()}
    if len(sources) == 1:
        name, sample = next(iter(sources.items()))
        result = {**sample, "source": name}
        if config.process_pids:
            result["processes"] = {str(pid): process_snapshot(pid) for pid in config.process_pids}
        return result
    values = {
        f"{source}:{metric}": value
        for source, sample in sources.items()
        for metric, value in sample.get("values", {}).items()
    }
    body = "".join(f"# source={name}\n{sample.get('body', '')}" for name, sample in sources.items())
    result = {
        "sources": sources,
        "values": values,
        "body": body,
        "raw_sha256": sha256(body.encode("utf-8")).hexdigest(),
    }
    if config.process_pids:
        result["processes"] = {str(pid): process_snapshot(pid) for pid in config.process_pids}
    return result


def _stream_request(
    config: CalibrationConfig,
    configuration_digest: str,
    level_start_ns: int,
    prompt_text: ChatPrompt,
    deadline: float | None = None,
) -> dict[str, Any]:
    request_id = f"cal_{uuid.uuid4().hex}"
    gateway_request_id: str | None = None
    payload: dict[str, Any] = {
        "model": config.model,
        "messages": prompt_messages(prompt_text),
        "stream": True,
        "max_tokens": config.max_tokens,
    }
    if not config.gateway_mode:
        payload["stream_options"] = {"include_usage": True}
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        f"{config.url.rstrip('/')}/v1/chat/completions",
        data=body,
        headers={
            "Authorization": f"Bearer {config.token}",
            "Content-Type": "application/json",
            "X-Request-ID": request_id,
        },
        method="POST",
    )
    if deadline is not None and time.perf_counter() >= deadline:
        return OutcomeRecord(
            run_id=config.run_id,
            request_id=request_id,
            tenant_id=config.tenant_id,
            model=config.model,
            policy=config.policy,
            planned_arrival_offset_ns=0,
            dispatch_offset_ns=None,
            first_content_offset_ns=None,
            completion_offset_ns=None,
            outcome=Outcome.NOT_DISPATCHED,
            http_status=None,
            error_code="run_time_budget_exhausted",
            prompt_tokens=None,
            completion_tokens=None,
            token_count_source=None,
            backend_id=None,
            configuration_digest=configuration_digest,
        ).to_dict()
    dispatch_monotonic_ns = time.perf_counter_ns()
    dispatch_ns = dispatch_monotonic_ns - level_start_ns
    first_content_ns: int | None = None
    completion_ns: int | None = None
    status: int | None = None
    backend_id: str | None = None
    error_code: str | None = None
    error_body_code = None
    error_body_type = None
    error_shape = None
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    saw_done = False
    try:
        with deadline_urlopen(
            request, timeout=config.timeout_seconds, deadline=deadline
        ) as response:
            status = response.status
            gateway_request_id = response.headers.get("X-Request-ID")
            backend_id = response.headers.get("X-Inference-Backend")
            for raw_line in response:
                line = raw_line.decode("utf-8", errors="replace").strip()
                if not line.startswith("data: "):
                    continue
                event_payload = line[6:]
                if event_payload == "[DONE]":
                    saw_done = True
                    completion_ns = time.perf_counter_ns() - level_start_ns
                    continue
                try:
                    event = json.loads(event_payload)
                except json.JSONDecodeError:
                    error_code = "invalid_stream_json"
                    continue
                if isinstance(event.get("error"), dict):
                    candidate = event["error"].get("code") or event["error"].get("type")
                    error_body_code = event["error"].get("code")
                    error_body_type = event["error"].get("type")
                    error_shape = "sse_error"
                    error_code = str(candidate) if candidate is not None else "stream_error"
                    continue
                for choice in event.get("choices", []):
                    content = choice.get("delta", {}).get("content")
                    if isinstance(content, str) and content and first_content_ns is None:
                        first_content_ns = time.perf_counter_ns() - level_start_ns
                usage = event.get("usage")
                if isinstance(usage, dict):
                    prompt_tokens = usage.get("prompt_tokens")
                    completion_tokens = usage.get("completion_tokens")
            if completion_ns is None:
                completion_ns = time.perf_counter_ns() - level_start_ns
    except urllib.error.HTTPError as error:
        status = error.code
        gateway_request_id = error.headers.get("X-Request-ID")
        backend_id = error.headers.get("X-Inference-Backend")
        try:
            error_body = json.loads(read_error_body(error, deadline=deadline).decode("utf-8"))
            error_body_code = error_body.get("code")
            candidate = error_body.get("code") or error_body.get("error")
            if isinstance(candidate, dict):
                error_body_code = candidate.get("code")
                error_body_type = candidate.get("type")
                candidate = candidate.get("code") or candidate.get("type")
            error_shape = "http_error"
            if type(candidate) is int:
                candidate = str(candidate)
            error_code = candidate if isinstance(candidate, str) and candidate else f"http_{status}"
        except (OSError, ValueError):
            error_code = f"http_{status}"
        error.close()
        completion_ns = time.perf_counter_ns() - level_start_ns
    except (OSError, urllib.error.URLError, TimeoutError):
        error_code = "transport_error"
        completion_ns = time.perf_counter_ns() - level_start_ns

    budget_exhausted = deadline is not None and time.perf_counter() >= deadline
    if budget_exhausted and not saw_done:
        outcome = Outcome.CANCELLED if first_content_ns is None else Outcome.PARTIAL_STREAM
        error_code = "client_cancelled" if first_content_ns is None else "run_time_budget_exhausted"
        source = None
    elif (
        status == 200
        and saw_done
        and error_code is None
        and backend_id
        and isinstance(prompt_tokens, int)
        and isinstance(completion_tokens, int)
    ):
        outcome = Outcome.COMPLETED
        error_code = None
        source = TokenCountSource.RUNTIME_USAGE
    elif status == 200 and backend_id:
        outcome = Outcome.PARTIAL_STREAM
        error_code = error_code or "stream_incomplete"
        source = None
    elif status is not None and 400 <= status < 500:
        outcome = Outcome.REJECTED
        error_code = error_code or f"http_{status}"
        source = None
        backend_id = None
    else:
        outcome = Outcome.FAILED_BEFORE_CONTENT
        error_code = error_code or "upstream_failure"
        source = None
        backend_id = None
    record = OutcomeRecord(
        run_id=config.run_id,
        request_id=gateway_request_id or request_id,
        tenant_id=config.tenant_id,
        model=config.model,
        policy=config.policy,
        planned_arrival_offset_ns=0,
        dispatch_offset_ns=dispatch_ns,
        first_content_offset_ns=first_content_ns,
        completion_offset_ns=completion_ns,
        outcome=outcome,
        http_status=status,
        error_code=error_code,
        prompt_tokens=prompt_tokens if outcome is Outcome.COMPLETED else None,
        completion_tokens=completion_tokens if outcome is Outcome.COMPLETED else None,
        token_count_source=source,
        backend_id=backend_id,
        configuration_digest=configuration_digest,
    )
    value = record.to_dict()
    value.update(
        error_body_code=error_body_code, error_body_type=error_body_type, error_shape=error_shape
    )
    if budget_exhausted and not saw_done:
        value["stop_reason"] = "run_time_budget_exhausted"
    value["dispatch_monotonic_ns"] = dispatch_monotonic_ns
    prompt_bytes = (
        prompt_text
        if isinstance(prompt_text, str)
        else json.dumps(prompt_text, sort_keys=True, separators=(",", ":"))
    ).encode("utf-8")
    value["prompt_sha256"] = sha256(prompt_bytes).hexdigest()
    if config.decision_prompt_export_path:
        # A client transport failure before response headers has no observed
        # gateway ID. Preserve its outcome, but do not invent a routing join.
        value["gateway_request_id_observed"] = bool(gateway_request_id)
        value["decision_prompt_export_status"] = (
            "recorded" if gateway_request_id else "not_recorded_no_gateway_request_id"
        )
        if gateway_request_id:
            append_prompt(
                config.decision_prompt_export_path,
                record.request_id,
                payload,
                outcome=outcome.value,
                first_content_received=first_content_ns is not None,
            )
    return value


def run_calibration(
    config: CalibrationConfig,
    levels: tuple[int, ...],
    *,
    prompt_factory: Callable[[int, int], ChatPrompt] | None = None,
    cycle_prompt_factory: Callable[[int, int, int], ChatPrompt] | None = None,
    deadline: float | None = None,
    level_duration_seconds: float = 0,
    drain_seconds: float = 120,
    minimum_cycle_seconds: float = 0.05,
) -> dict[str, Any]:
    """Run stepped concurrent streaming bursts and return a JSON-ready record."""

    if not levels or any(level <= 0 for level in levels):
        raise ValueError("levels must contain positive concurrency values")
    if level_duration_seconds < 0 or drain_seconds <= 0 or minimum_cycle_seconds <= 0:
        raise ValueError("level duration/cycle/drain configuration is invalid")
    clocks = measurement_clocks()
    configuration_digest = content_digest(config.to_dict())
    result: dict[str, Any] = {
        "schema": "inf004-calibration-run.v0",
        "clock_info": clocks,
        "run_id": config.run_id,
        "configuration": config.to_dict(),
        "configuration_digest": configuration_digest,
        "levels": [],
        "status": "completed",
    }
    for concurrency in levels:
        if deadline is not None and time.perf_counter() >= deadline:
            result["status"] = "budget_exhausted"
            break
        level_start_ns = time.perf_counter_ns()
        load_end = level_start_ns / 1e9 + level_duration_seconds
        level_deadline = (
            min(load_end + drain_seconds, deadline or float("inf"))
            if level_duration_seconds
            else deadline
        )
        stop_sampler = threading.Event()
        first_sample = threading.Event()
        samples = DiskList()
        records = DiskList()

        def sample(
            stop_event: threading.Event = stop_sampler,
            ready_event: threading.Event = first_sample,
            sample_values: list[dict[str, Any]] = samples,
            start_ns: int = level_start_ns,
            sample_deadline: float | None = level_deadline,
        ) -> None:
            while not stop_event.is_set():
                sample_values.append(
                    {
                        "offset_ns": time.perf_counter_ns() - start_ns,
                        **_metrics(config, sample_deadline),
                    }
                )
                ready_event.set()
                stop_event.wait(config.sample_interval_ms / 1000)

        sampler = threading.Thread(target=sample, name="calibration-metrics", daemon=True)
        sampler.start()
        try:
            try:
                sample_wait = remaining_seconds(deadline, 5)
            except BudgetExhausted:
                sample_wait = 0
            if not first_sample.wait(timeout=sample_wait):
                if deadline is not None and time.perf_counter() >= deadline:
                    result["status"] = "budget_exhausted"
                    result["partial_metrics"] = samples
                    break
                raise TimeoutError("metrics sampler did not capture a pre-burst sample")
            barrier = threading.Barrier(concurrency + 1, timeout=2)

            def worker(
                start_barrier: threading.Barrier = barrier,
                start_ns: int = level_start_ns,
                worker_index: int = 0,
                work_deadline: float | None = level_deadline,
                load_until: float = load_end,
                output: DiskList = records,
            ) -> list[dict[str, Any]]:
                start_barrier.wait()
                prompt_text = (
                    prompt_factory(len(result["levels"]), worker_index)
                    if prompt_factory is not None
                    else config.prompt_text
                )
                if config.unique_prompt_per_request and prompt_factory is None:
                    prompt_text = f"{prompt_text}\nrequest={worker_index}"
                cycle = 0
                while True:
                    cycle_started = time.perf_counter()
                    if cycle_prompt_factory is not None:
                        try:
                            prompt_text = cycle_prompt_factory(
                                len(result["levels"]), worker_index, cycle
                            )
                        except BudgetExhausted:
                            break
                        if time.perf_counter() >= min(load_until, deadline or float("inf")):
                            break
                    record = _stream_request(
                        config, configuration_digest, start_ns, prompt_text, work_deadline
                    )
                    output.append(record)
                    cycle += 1
                    if not level_duration_seconds:
                        break
                    now = time.perf_counter()
                    if now >= min(load_until, deadline or float("inf")):
                        break
                    time.sleep(
                        min(
                            max(0, minimum_cycle_seconds - (now - cycle_started)),
                            max(0, min(load_until, deadline or float("inf")) - now),
                        )
                    )
                    if time.perf_counter() >= min(load_until, deadline or float("inf")):
                        break
                return cycle

            with ThreadPoolExecutor(max_workers=concurrency) as executor:
                futures = [
                    executor.submit(worker, worker_index=index) for index in range(concurrency)
                ]
                barrier.wait()
                for future in futures:
                    future.result()
        finally:
            stop_sampler.set()
            sampler.join(timeout=3)
            if sampler.is_alive():
                raise RuntimeError("metrics sampler did not stop before level serialization")
        first_sample_offset = min((sample["offset_ns"] for sample in samples), default=None)
        first_dispatch_offset = min(
            (
                record["dispatch_offset_ns"]
                for record in records
                if record["dispatch_offset_ns"] is not None
            ),
            default=None,
        )
        sampler_preceded_load = (
            first_sample_offset is not None
            and first_dispatch_offset is not None
            and first_sample_offset <= first_dispatch_offset
        )
        if first_dispatch_offset is None and (
            (deadline is not None and time.perf_counter() >= deadline)
            or (level_duration_seconds and time.perf_counter() >= load_end)
        ):
            sampler_preceded_load = True  # no dispatch occurred; keep not-dispatched records
        if not sampler_preceded_load:
            raise RuntimeError("metrics sampler did not start before request load")
        result["levels"].append(
            {
                "concurrency": concurrency,
                "records": records,
                "metrics": samples,
                "sampler_started_before_load": sampler_preceded_load,
                "duration_ns": time.perf_counter_ns() - level_start_ns,
                "load_mode": "sustained_closed_loop" if level_duration_seconds else "single_burst",
                "planned_load_seconds": level_duration_seconds,
                "minimum_cycle_seconds": minimum_cycle_seconds,
                "censored_ttft_count": sum(
                    r["http_status"] == 504 and r["first_content_offset_ns"] is None
                    for r in records
                ),
                "runtime_regime": derive_runtime_regime(samples),
            }
        )
    if deadline is not None and time.perf_counter() >= deadline:
        result["status"] = "budget_exhausted"
    result["completed_level_count"] = len(result["levels"])
    result["planned_level_count"] = len(levels)
    return result


def derive_runtime_regime(samples: list[dict[str, Any]]) -> dict[str, Any]:
    def value(sample: dict[str, Any], suffix: str) -> float | None:
        series = [
            v for k, v in sample.get("values", {}).items() if k.split("{", 1)[0].endswith(suffix)
        ]
        return sum(series) if series else None

    signals = {
        name: [v for sample in samples if (v := value(sample, name)) is not None]
        for name in (
            "vllm:num_preemptions_total",
            "vllm:num_requests_running",
            "vllm:num_requests_waiting",
        )
    }
    preemptions = signals["vllm:num_preemptions_total"]
    reset = any(after < before for before, after in zip(preemptions, preemptions[1:], strict=False))
    delta = preemptions[-1] - preemptions[0] if len(preemptions) >= 2 and not reset else None
    running = signals["vllm:num_requests_running"]
    waiting = signals["vllm:num_requests_waiting"]
    labels = []
    if delta is not None and delta > 0:
        labels.append("kv_pressure_preemptions_observed")
    if waiting and max(waiting) > 0:
        labels.append("waiting_observed")
    if not all(signals.values()) or delta is None:
        labels.append("regime_unestablished_missing_native_signals")
    if not labels:
        labels.append("no_preemption_or_waiting_observed")
    return {
        "labels": labels,
        "preemptions_delta": delta,
        "running_peak": max(running) if running else None,
        "waiting_peak": max(waiting) if waiting else None,
        "signals": signals,
        "basis": "native counter/gauges, not latency inference",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--token-file", required=True, type=Path)
    parser.add_argument("--tenant-id", default="tenant-calibration")
    parser.add_argument("--model", required=True)
    parser.add_argument("--run-id", default="inf011-m3-followup")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--levels", default="1,2,4,8,12")
    parser.add_argument("--max-tokens", type=int, default=512)
    parser.add_argument("--sample-interval-ms", type=int, default=100)
    args = parser.parse_args()
    token = args.token_file.read_text(encoding="utf-8").strip()
    if not token:
        parser.error("token file is empty")
    levels = tuple(int(value) for value in args.levels.split(",") if value)
    config = CalibrationConfig(
        url=args.url,
        token=token,
        tenant_id=args.tenant_id,
        model=args.model,
        run_id=args.run_id,
        max_tokens=args.max_tokens,
        sample_interval_ms=args.sample_interval_ms,
    )
    result = run_calibration(config, levels)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
