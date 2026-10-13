"""Audit pinned primary source bytes for the R1 native metric contract."""

import argparse
import hashlib
import json
import urllib.request
from pathlib import Path

from .r1_metrics import FITNESS
from .r1_spec import encoded

SOURCES = {
    "vllm/v1/core/kv_cache_manager.py": "2213a68ea1a2f05b1d99de25a3f1daf4040d8d7fdd0e271d80b7ba9e1977a08d",
    "vllm/v1/core/single_type_kv_cache_manager.py": "3038a12b187453a5e1a3b2fd4f5cb4f5be08b23108f8352263032d9179472d55",
    "vllm/v1/metrics/stats.py": "e8c3cbcfb880e7a2a496a1e499d4e4efccf70ba1eef56f4a1a6ee44cc0bf49bc",
    "vllm/v1/metrics/loggers.py": "d5a91626cf79118f98ae6438c842cb30fc44ca14463c7e2af5871e3da8e51bcf",
    "vllm/entrypoints/serve/dev/cache/api_router.py": "ba0e9be90c4fe8f42526c163d073ee5889492e4cdd8231599901d0b3aab669ce",
    "vllm/v1/core/block_pool.py": "daf37f8c3e85d6debac02df2ac2356f5500555b613a369e8efdc66a0db94286b",
}


def audit(directory, fetch=False):
    receipts, texts = [], {}
    for path, expected in SOURCES.items():
        local = Path(directory) / path
        url = "https://raw.githubusercontent.com/vllm-project/vllm/v0.29.0/" + path
        if not local.exists() and fetch:
            with urllib.request.urlopen(url, timeout=15) as response:
                data = response.read()
            local.parent.mkdir(parents=True, exist_ok=True)
            local.write_bytes(data)
        data = local.read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError("pinned source hash mismatch: " + path)
        texts[path] = data.decode()
        receipts.append({"url": url, "path": path, "sha256": expected, "bytes": len(data)})
    manager = texts["vllm/v1/core/kv_cache_manager.py"]
    stats = texts["vllm/v1/metrics/stats.py"]
    logger = texts["vllm/v1/metrics/loggers.py"]
    if not all(
        fragment in manager
        for fragment in (
            "num_tokens=request.num_tokens",
            "max_cache_hit_length = request.num_tokens - 1",
        )
    ):
        raise ValueError("query/last-token source rule differs")
    if (
        "self.queries += num_tokens" not in stats
        or 'labelnames = ["model_name", "engine"]' not in logger
    ):
        raise ValueError("native units/labels differ")
    return {
        "fitness": FITNESS,
        "sources": receipts,
        "derivation": {
            "query_tokens": 1024,
            "last_token_limit": 1023,
            "full_blocks": 1023 // 16,
            "maximum_hit_tokens": (1023 // 16) * 16,
        },
        "basis": "primary-source semantics, not measured GPU counter fitness",
        "runtime_gate": "native token-ID checks and settled seeded sentinel deltas on both replicas",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--fetch", action="store_true")
    args = parser.parse_args()
    result = audit(args.cache, args.fetch)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(encoded(result) + b"\n")
    print(json.dumps(result["derivation"]))


if __name__ == "__main__":
    main()
