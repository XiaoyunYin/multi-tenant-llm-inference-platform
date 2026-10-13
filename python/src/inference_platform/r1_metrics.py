"""Pinned v0.29.0 native counters; no cache occupancy inference."""

import json
import math
import re

from .r1_spec import MODEL

NAMES = {
    "queries": "vllm:prefix_cache_queries_total",
    "hits": "vllm:prefix_cache_hits_total",
    "preemptions": "vllm:num_preemptions_total",
    "completions": "vllm:request_success_total",
    "running": "vllm:num_requests_running",
    "waiting": "vllm:num_requests_waiting",
}
COUNTERS = ("queries", "hits", "preemptions", "completions")
FITNESS = {
    "version": "v0.29.0",
    "labels": ["model_name", "engine"],
    "completion_extra_label": "finished_reason",
    "engine": "0",
    "model_name": MODEL,
    "units": {
        "queries": "tokens",
        "hits": "tokens",
        "preemptions": "preemption events",
        "completions": "requests",
        "running": "requests",
        "waiting": "requests",
    },
    "names": NAMES,
    "sentinel_query_increment": 1024,
    "sentinel_max_replay_hits": 1008,
    "sentinel_max_reusable_blocks": 63,
    "source": {
        "query": "vllm/v1/core/kv_cache_manager.py:get_computed_blocks -> PrefixCacheStats.record",
        "hits": "vllm/v1/core/kv_cache_manager.py:get_computed_blocks; num_tokens-1; full-attention block alignment",
        "export": "vllm/v1/metrics/loggers.py:PrometheusStatLogger.record",
        "reset": "vllm/entrypoints/serve/dev/cache/api_router.py:reset_prefix_cache",
    },
}
SAMPLE = re.compile(r"([^ {]+)(?:\{(.*)\})?\s+([^ ]+)(?:\s+\d+)?$")
LABEL = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*")(?:,|$)')


def parse(text, generation, now, wall):
    values, raw = {}, []
    for line in text.splitlines():
        match = SAMPLE.fullmatch(line)
        if not match or match[1] not in NAMES.values():
            continue
        labels = {key: json.loads(value) for key, value in LABEL.findall(match[2] or "")}
        if labels.get("model_name") != MODEL or labels.get("engine") != "0":
            raise ValueError("unexpected model/engine in native metrics")
        key = next(key for key, name in NAMES.items() if name == match[1])
        expected = {"model_name", "engine"} | (
            {"finished_reason"} if key == "completions" else set()
        )
        if set(labels) != expected:
            raise ValueError("unexpected native counter labels")
        number = float(match[3])
        if not math.isfinite(number) or number < 0 or not number.is_integer():
            raise ValueError("invalid native count")
        if key in values and key != "completions":
            raise ValueError("duplicate native series")
        if any(item["name"] == match[1] and item["labels"] == labels for item in raw):
            raise ValueError("duplicate completion series")
        values[key] = values.get(key, 0) + int(number)
        raw.append({"name": match[1], "labels": labels, "value": int(number)})
    if set(values) != set(NAMES) or not generation:
        raise ValueError("missing native metric/identity")
    return {
        **values,
        "generation": generation,
        "engine": "0",
        "model_name": MODEL,
        "monotonic_s": now,
        "wall_s": wall,
        "age_s": 0,
        "raw": raw,
    }


def delta(before, after):
    if any(before[key] != after[key] for key in ("generation", "engine", "model_name")):
        raise ValueError("native identity/generation changed")
    if after["age_s"] > 1 or after["monotonic_s"] < before["monotonic_s"]:
        raise ValueError("stale/reversed native snapshot")
    result = {key: after[key] - before[key] for key in COUNTERS}
    if any(value < 0 for value in result.values()) or result["hits"] > result["queries"]:
        raise ValueError("native counter decrease or impossible hit delta")
    return result


def percentile(values, p, requests=False):
    values = sorted(values)
    if not values or (requests and len(values) * (1 - p) + 1e-9 < 20):
        return None
    return values[math.ceil(len(values) * p) - 1]
