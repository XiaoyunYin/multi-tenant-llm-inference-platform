"""Pinned v0.29.0 engine evidence. Missing observations never imply defaults."""

import json
import math
import re

from .inf037b_archive import IntegrityError

# Exact archived v0.29.0 set: chart-data.json / native_capacity_source.
CACHE_LABELS = frozenset(
    """
_block_size_resolved block_size cache_dtype enable_prefix_caching engine
gpu_memory_utilization is_attention_free kv_cache_dtype_skip_layers kv_cache_layout
kv_cache_max_concurrency kv_cache_memory_bytes kv_cache_size_tokens kv_offloading_backend
kv_offloading_size kv_sharing_fast_prefill mamba_block_size mamba_cache_dtype
mamba_cache_mode mamba_page_size_padded mamba_ssm_cache_dtype num_cpu_blocks
num_gpu_blocks num_gpu_blocks_override prefix_cache_retention_interval
prefix_caching_hash_algo prefix_match_unit replayssm_buffer_len skip_page_size_padded
sliding_window use_kda_recoverssm use_replayssm user_specified_block_size
user_specified_mamba_block_size
""".split()
)


def cache_config(body):
    series = [
        line for line in body.decode().splitlines() if line.startswith("vllm:cache_config_info")
    ]
    if len(series) != 1:
        raise IntegrityError("engine:cache_series_missing_or_duplicate")
    match = re.fullmatch(r"vllm:cache_config_info\{(.*)\}\s+1(?:\.0)?", series[0])
    if not match:
        raise IntegrityError("engine:cache_series_invalid")
    labels, offset = {}, 0
    for label in re.finditer(r'([a-zA-Z_][a-zA-Z_0-9]*)=("(?:[^"\\]|\\.)*")(?:,|$)', match[1]):
        if label.start() != offset or label[1] in labels:
            raise IntegrityError("engine:cache_labels_invalid")
        labels[label[1]] = json.loads(label[2])
        offset = label.end()
    if offset != len(match[1]) or set(labels) != CACHE_LABELS:
        raise IntegrityError("engine:cache_labels_missing_or_unknown")
    # Preserve all exact labels; validate the fields used by equivalence now.
    for key in ("block_size", "num_gpu_blocks"):
        if not labels[key].isdigit() or (key == "block_size" and int(labels[key]) <= 0):
            raise IntegrityError("engine:cache_value_invalid:" + key)
    memory = float(labels["gpu_memory_utilization"])
    if not math.isfinite(memory) or not 0 < memory <= 1:
        raise IntegrityError("engine:cache_value_invalid:gpu_memory_utilization")
    if labels["enable_prefix_caching"] not in ("True", "False") or labels["engine"] != "0":
        raise IntegrityError("engine:cache_value_invalid:engine_or_prefix")
    return labels
