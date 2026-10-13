"""Exact Qwen token/request/block manifests and frozen weighted R1 traces."""

import argparse
import base64
import hashlib
import hmac
import json
import math
from collections import Counter
from functools import lru_cache
from pathlib import Path

from .r1_spec import (
    FIXED,
    GATEWAY_FIXED,
    MODEL,
    SPEC_COMMIT,
    digest,
    encoded,
    validate_fixed,
    verify_spec,
)
from .stage_c_prompts import exact_prompt
from .stage_c_tokenizer import FILE_HASHES, REVISION, pinned_tokenizer, verified_files


def tenant_salt(secret, tenant="r1-synthetic"):
    message = b"multi-tenant-llm-inference-platform/cache-salt/v1\0" + tenant.encode()
    return base64.urlsafe_b64encode(hmac.digest(secret, message, "sha256")).decode().rstrip("=")


def row(identity, salt, tokenizer):
    messages, tokens = exact_prompt("offline", MODEL, identity, 1024, None, tokenize_fn=tokenizer)
    request = {
        "model": MODEL,
        "messages": messages,
        "max_tokens": 1,
        "temperature": 0,
        "stream": True,
        "stream_options": {"include_usage": True},
        "cache_salt": salt,
    }
    gateway_request = {
        key: value for key, value in request.items() if key not in {"cache_salt", "stream_options"}
    }
    parent = digest({"model": MODEL, "revision": REVISION, "salt": salt})
    blocks = []
    for start in range(0, 1008, 16):
        parent = digest([parent, tokens[start : start + 16]])
        blocks.append(parent)
    return {
        "id": identity,
        "request": request,
        "tokens": tokens,
        "token_sha256": digest(tokens),
        "request_sha256": digest(request),
        "gateway_request_sha256": digest(gateway_request),
        "first_block_sha256": digest(tokens[:16]),
        "reusable_block_sha256": blocks,
    }


def validate_row(value, tokenizer, first_blocks=None):
    request = value["request"]
    tokens = tokenizer(request["messages"])
    expected = row(value["id"], request["cache_salt"], tokenizer)
    if value != expected or len(tokens) != 1024 or tokens != value["tokens"]:
        raise ValueError("altered request/token/block manifest")
    if first_blocks is not None:
        block = tuple(tokens[:16])
        if block in first_blocks:
            raise ValueError("prefix/sentinel first reusable block collision")
        first_blocks.add(block)


@lru_cache(maxsize=128)
def epoch(phase, block, number=0):
    if phase not in {"warm", "measure"} or block not in {"b1", "b2", "b3"}:
        raise ValueError("unknown frozen trace")
    entries = [(f"p{i:03}", n) for i in range(384) for n in range(12 if i < 96 else 1)]
    if type(number) is not int or number < 0:
        raise ValueError("epoch number must be a nonnegative integer")
    return tuple(
        sorted(
            entries,
            key=lambda item: (
                hashlib.sha256(
                    f"r1-v1|{phase}|{block}|{number}|{item[0]}|{item[1]}".encode()
                ).digest(),
                item,
            ),
        )
    )


def trace(phase, block, q, seconds):
    if not math.isfinite(q) or q <= 0:
        raise ValueError("q must be positive and finite")
    # Epoch count/order is determined by the registered rate, never by hit outcomes.
    count = math.ceil(seconds * q)
    for number in range(math.ceil(count / 1440)):
        for offset, (prefix, occurrence) in enumerate(epoch(phase, block, number)):
            index = number * 1440 + offset
            if index >= count or index / q >= seconds:
                return
            yield {
                "index": index,
                "prefix": prefix,
                "epoch": number,
                "occurrence": occurrence,
                "arrival_s": index / q,
                "gateway": index % 2,
            }


def trace_profile(rows):
    rows = list(rows)
    counts = Counter(x["prefix"] for x in rows)
    last = {}
    request_distances, block_distances = [], []
    unseen = 0
    for index, entry in enumerate(rows):
        prefix = entry["prefix"]
        if prefix not in last:
            unseen += 1
        else:
            request_distances.append(index - last[prefix] - 1)
            block_distances.append(
                62 + 63 * sum(position > last[prefix] for position in last.values())
            )
        last[prefix] = index

    def stats(values):
        values = sorted(values)
        return {
            "n": len(values),
            "p50": values[math.ceil(len(values) * 0.5) - 1] if values else None,
            "p95": values[math.ceil(len(values) * 0.95) - 1] if values else None,
            "max": max(values, default=None),
        }

    return {
        "offers": len(rows),
        "counts": dict(sorted(counts.items())),
        "unseen": unseen,
        "hot_share": sum(n for p, n in counts.items() if int(p[1:]) < 96) / len(rows)
        if rows
        else None,
        "reuse_requests": stats(request_distances),
        "reuse_distinct_blocks": {**stats(block_distances), "n": 63 * len(block_distances)},
        "unseen_blocks": 63 * unseen,
        "block_distance_basis": "expanded 63-block potential-reference stream; includes 62 other blocks of same prefix",
        "trace_sha256": digest(rows),
    }


def build(directory, salt, cache=None):
    verify_spec(SPEC_COMMIT)
    tokenizer = pinned_tokenizer(cache=cache)
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    files = {}
    first = set()
    families = {
        "workload.jsonl": [f"p{i:03}" for i in range(384)],
        "calibration.jsonl": [
            f"cal-{backend}-{level}-{worker}"
            for backend in range(2)
            for level in FIXED["calibration_levels"]
            for worker in range(level)
        ],
        "sentinel.jsonl": ["r1-v2-reset-sentinel"],
    }
    for filename, identities in families.items():
        data = []
        for identity in identities:
            value = row(
                identity, salt if not identity.startswith("cal-") else salt + "-cal", tokenizer
            )
            validate_row(value, tokenizer, first)
            data.append(encoded(value) + b"\n")
        content = b"".join(data)
        (directory / filename).write_bytes(content)
        files[filename] = {
            "sha256": hashlib.sha256(content).hexdigest(),
            "bytes": len(content),
            "rows": len(identities),
        }
    traces = {
        f"{phase}-{block}": [list(x) for x in epoch(phase, block)]
        for phase in ("warm", "measure")
        for block in ("b1", "b2", "b3")
    }
    (directory / "epochs.json").write_bytes(encoded(traces) + b"\n")
    files["epochs.json"] = {
        "sha256": hashlib.sha256((directory / "epochs.json").read_bytes()).hexdigest()
    }
    native_template = json.loads(verified_files(cache)["tokenizer_config.json"])["chat_template"]
    manifest = {
        "fixed": FIXED,
        "implementation": {
            "gateway": GATEWAY_FIXED,
            "generator_max_workers": 128,
            "generator_max_active": 128,
        },
        "cache_salt": salt,
        "tokenizer_files": FILE_HASHES,
        "chat_template_sha256": hashlib.sha256(native_template.encode()).hexdigest(),
        "files": files,
        "pressure": {
            "corpus_reusable_blocks": 24192,
            "hot_reusable_blocks": 6048,
            "aligned_proxy_blocks": 4032,
            "minimal_s_cover_blocks": 6048,
            "per_hot_block_weight": 12,
            "per_tail_block_weight": 1,
            "ratio": 1.5,
            "basis": "mid-band candidate/proxy",
        },
        "sorted_reference_weights": [
            {"weight": 12, "blocks": 6048, "cumulative_weight": 72576, "cumulative_share": 0.8},
            {"weight": 1, "blocks": 18144, "cumulative_weight": 90720, "cumulative_share": 1.0},
        ],
        "block_hash_basis": "offline SHA256 contextual/salt fingerprints, not native vLLM hashes",
        "calibration_generation": "unique per backend/level/worker/cycle; materialize and verify before dispatch",
        "epoch_profiles": {
            key: trace_profile([{"prefix": x[0]} for x in entries])
            for key, entries in traces.items()
        },
    }
    manifest["manifest_sha256"] = digest(manifest)
    (directory / "manifest.json").write_bytes(encoded(manifest) + b"\n")
    return manifest


def load(directory, commit=SPEC_COMMIT, cache=None, spec_artifact=None):
    verify_spec(commit, artifact=spec_artifact)
    directory = Path(directory)
    value = json.loads((directory / "manifest.json").read_bytes())
    checksum = value.pop("manifest_sha256")
    if digest(value) != checksum:
        raise ValueError("manifest digest mismatch")
    value["manifest_sha256"] = checksum
    expected_keys = {
        "fixed",
        "cache_salt",
        "tokenizer_files",
        "chat_template_sha256",
        "files",
        "pressure",
        "block_hash_basis",
        "calibration_generation",
        "epoch_profiles",
        "implementation",
        "sorted_reference_weights",
        "manifest_sha256",
    }
    if set(value) != expected_keys:
        raise ValueError("unknown/missing manifest metadata")
    validate_fixed(value["fixed"])
    if value["implementation"] != {
        "gateway": GATEWAY_FIXED,
        "generator_max_workers": 128,
        "generator_max_active": 128,
    }:
        raise ValueError("implementation configuration differs")
    tokenizer = pinned_tokenizer(cache=cache)
    expected_files = {"workload.jsonl", "calibration.jsonl", "sentinel.jsonl", "epochs.json"}
    if set(value["files"]) != expected_files:
        raise ValueError("missing/unknown manifest files")
    native_template = json.loads(verified_files(cache)["tokenizer_config.json"])["chat_template"]
    if value["chat_template_sha256"] != hashlib.sha256(native_template.encode()).hexdigest():
        raise ValueError("chat template differs")
    if value["pressure"] != {
        "corpus_reusable_blocks": 24192,
        "hot_reusable_blocks": 6048,
        "aligned_proxy_blocks": 4032,
        "minimal_s_cover_blocks": 6048,
        "per_hot_block_weight": 12,
        "per_tail_block_weight": 1,
        "ratio": 1.5,
        "basis": "mid-band candidate/proxy",
    }:
        raise ValueError("pressure inputs differ")
    if value["sorted_reference_weights"] != [
        {"weight": 12, "blocks": 6048, "cumulative_weight": 72576, "cumulative_share": 0.8},
        {"weight": 1, "blocks": 18144, "cumulative_weight": 90720, "cumulative_share": 1.0},
    ]:
        raise ValueError("potential-reference weights differ")
    first = set()
    banks = {}
    for filename, details in value["files"].items():
        if filename not in {"workload.jsonl", "calibration.jsonl", "sentinel.jsonl", "epochs.json"}:
            raise ValueError("unknown manifest file")
        data = (directory / filename).read_bytes()
        if hashlib.sha256(data).hexdigest() != details["sha256"]:
            raise ValueError("manifest file digest mismatch")
        if filename.endswith("jsonl"):
            rows = [json.loads(line) for line in data.splitlines()]
            if details != {
                "sha256": hashlib.sha256(data).hexdigest(),
                "bytes": len(data),
                "rows": len(rows),
            }:
                raise ValueError("file length/count mismatch")
            for item in rows:
                expected_salt = value["cache_salt"] + (
                    "-cal" if filename == "calibration.jsonl" else ""
                )
                if item["request"]["cache_salt"] != expected_salt:
                    raise ValueError("cache salt differs from manifest")
                validate_row(item, tokenizer, first)
            banks[filename] = rows
        elif json.loads(data) != {
            f"{phase}-{block}": [list(x) for x in epoch(phase, block)]
            for phase in ("warm", "measure")
            for block in ("b1", "b2", "b3")
        }:
            raise ValueError("trace seed/order mismatch")
    if [x["id"] for x in banks["workload.jsonl"]] != [f"p{i:03}" for i in range(384)]:
        raise ValueError("corpus differs from v2")
    if [x["id"] for x in banks["sentinel.jsonl"]] != ["r1-v2-reset-sentinel"] or [
        x["id"] for x in banks["calibration.jsonl"]
    ] != [
        f"cal-{backend}-{level}-{worker}"
        for backend in range(2)
        for level in FIXED["calibration_levels"]
        for worker in range(level)
    ]:
        raise ValueError("calibration/sentinel bank differs")
    if value["tokenizer_files"] != FILE_HASHES:
        raise ValueError("tokenizer pins differ")
    profiles = {
        f"{phase}-{block}": trace_profile([{"prefix": x[0]} for x in epoch(phase, block)])
        for phase in ("warm", "measure")
        for block in ("b1", "b2", "b3")
    }
    if value["epoch_profiles"] != profiles:
        raise ValueError("offline trace profiles differ")
    return value, banks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--cache-salt", required=True)
    parser.add_argument("--tokenizer-cache", type=Path)
    args = parser.parse_args()
    print(json.dumps(build(args.output, args.cache_salt, args.tokenizer_cache)["files"]))


if __name__ == "__main__":
    main()
