"""Immutable R1 v2 inputs. Admission wording is not a harness input."""

import hashlib
import json
import subprocess
from pathlib import Path

SPEC_COMMIT = "3d3c36a1cab1f0901049aeaa96d65782ce1028fb"
SPEC_SHA256 = "d752cd6cce342f0fd256a6dd684a96289c472c5e251a276ddf2660edbabbdfb4"
MODEL = "Qwen/Qwen2.5-7B-Instruct"
REVISION = "a09a35458c702b33eeacc393d103063234e8bc28"
IMAGE = "docker.io/vllm/vllm-openai@sha256:082ca6f035279109041ffd3fe0695cb568b29bc580b35c4f297a66a08b216c1b"
POLICIES = ("hash", "ll", "rr", "rr", "ll", "hash")
FIXED = {
    "schema": "r1-v2.harness.1",
    "spec_commit": SPEC_COMMIT,
    "spec_sha256": SPEC_SHA256,
    "model": MODEL,
    "revision": REVISION,
    "image": IMAGE,
    "replicas": 2,
    "gateways": 2,
    "prefixes": 384,
    "hot_prefixes": 96,
    "share": 0.8,
    "hot_weight": 12,
    "tail_weight": 1,
    "input_tokens": 1024,
    "max_tokens": 1,
    "temperature": 0,
    "block_size": 16,
    "reusable_blocks": 63,
    "reset_nominal_s": 60,
    "reset_hard_s": 120,
    "control_timeout_s": 5,
    "probe_timeout_s": 10,
    "settle_timeout_s": 15,
    "poll_s": 0.5,
    "freshness_s": 1,
    "warm_min_s": 120,
    "warm_max_s": 600,
    "warm_window_s": 30,
    "warm_queries_min": 20480,
    "warm_adjacent_changes": 3,
    "warm_epsilon": 0.02,
    "measurement_s": 600,
    "drain_s": 120,
    "setup_s": 2700,
    "session_s": 18000,
    "export_s": 600,
    "teardown_s": 300,
    "seeds": [4242, 4243, 4244],
    "policies": list(POLICIES),
    "calibration_levels": [1, 2, 4, 8, 12, 16, 24, 32],
    "rate_factors": [1.05, 1.15, 1.25],
    "waiting_candidates": [1, 2, 4],
    "engine": {
        "dtype": "bfloat16",
        "max_model_len": 8192,
        "max_num_seqs": 16,
        "max_num_queued_reqs": 32,
        "gpu_memory_utilization": 0.90,
        "enable_prefix_caching": True,
        "generation_config": "vllm",
        "kv_events": {
            "enable_kv_cache_events": True,
            "publisher": "zmq",
            "endpoint": "tcp://*:5557",
            "topic": "kv-events",
        },
        "VLLM_SERVER_DEV_MODE": "1",
    },
}


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def verify_spec(commit, root=None, artifact=None):
    if commit != SPEC_COMMIT:
        raise ValueError("only the committed R1 v2 spec at 3d3c36a is supported")
    root = root or Path(__file__).resolve().parents[3]
    data = (
        Path(artifact).read_bytes()
        if artifact is not None
        else subprocess.check_output(
            ["git", "-C", str(root), "show", f"{SPEC_COMMIT}:docs/R1_PRE_REGISTRATION.md"]
        )
    )
    if hashlib.sha256(data).hexdigest() != SPEC_SHA256:
        raise ValueError("committed v2 specification bytes do not match")


def validate_fixed(value):
    if encoded(value) != encoded(FIXED):
        raise ValueError("incompatible R1 fixed inputs; no overrides or unknown fields")


GATEWAY_FIXED = {
    "GOMAXPROCS": "2",
    "ADMISSION_MODE": "redis",
    "BACKEND_DISCOVERY": "",
    "BACKEND_METRICS_INTERVAL": "500ms",
    "BACKEND_METRICS_MAX_AGE": "1s",
    "GATEWAY_FIRST_ITEM_TIMEOUT": "5s",
    "GATEWAY_TOTAL_TIMEOUT": "120s",
    "GATEWAY_ADMISSION_TIMEOUT": "250ms",
    "GATEWAY_RELEASE_TIMEOUT": "1s",
    "GATEWAY_ROUTING_TOKENIZE_TIMEOUT": "500ms",
    "GATEWAY_SHUTDOWN_GRACE": "120s",
    "GATEWAY_SHUTDOWN_HARD_STOP": "10s",
    "ADMISSION_LEASE": "180s",
    "ADMISSION_TOMBSTONE_TTL": "300s",
    "GATEWAY_HASH_AFFINITY_BLOCK_SIZE": "16",
    "GATEWAY_HASH_AFFINITY_MAX_BLOCKS": "16",
    "GATEWAY_HASH_AFFINITY_ESCAPE_MARGIN": "2",
    "ALLOW_UNSAFE_TEST_ADMISSION": "false",
    "OTEL_SDK_DISABLED": "true",
}
