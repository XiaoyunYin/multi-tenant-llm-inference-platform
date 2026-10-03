"""No-cost pinned Qwen chat tokenizer and complete offline r0-v2 prompt fitness."""

import argparse
import hashlib
import json
import math
import os
import urllib.request
from functools import lru_cache
from pathlib import Path
from types import SimpleNamespace

from .stage_c_prompts import (
    exact_prompt,
    identity_messages,
    prompt_bank,
    prompt_footprint,
    prompt_messages,
    saturation_identity,
)

MODEL = "Qwen/Qwen2.5-7B-Instruct"
REVISION = "a09a35458c702b33eeacc393d103063234e8bc28"
FILE_HASHES = {
    "tokenizer.json": "c0382117ea329cdf097041132f6d735924b697924d6f6fc3945713e96ce87539",
    "tokenizer_config.json": "5b5d4f65d0acd3b2d56a35b56d374a36cbc1c8fa5cf3b3febbbfabf22f359583",
}


def cache_directory():
    return Path(os.environ.get("INF011_TOKENIZER_CACHE", ".cache/pinned-tokenizer")) / REVISION


def verified_files(cache=None, *, fetch=False):
    """Only fetch public tokenizer files; fail closed on missing or altered bytes."""
    cache = Path(cache) if cache is not None else cache_directory()
    files = {}
    for name, expected in FILE_HASHES.items():
        path = cache / name
        if not path.exists() and fetch:
            url = f"https://huggingface.co/{MODEL}/resolve/{REVISION}/{name}"
            with urllib.request.urlopen(url, timeout=60) as response:
                data = response.read(16 << 20)
            if hashlib.sha256(data).hexdigest() != expected:
                raise ValueError(f"pinned tokenizer hash mismatch: {name}")
            cache.mkdir(parents=True, exist_ok=True)
            # Publish complete bytes atomically, including concurrent cold-cache callers.
            import tempfile

            with tempfile.NamedTemporaryFile(dir=cache, delete=False) as stream:
                temporary = Path(stream.name)
                stream.write(data)
            try:
                os.replace(temporary, path)
            finally:
                temporary.unlink(missing_ok=True)
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != expected:
            raise ValueError(f"pinned tokenizer hash mismatch: {name}")
        files[name] = data
    return files


class PinnedChatTokenizer:
    def __init__(self, files):
        from jinja2.sandbox import ImmutableSandboxedEnvironment
        from tokenizers import Tokenizer

        config = json.loads(files["tokenizer_config.json"])
        self.template = ImmutableSandboxedEnvironment(
            trim_blocks=True, lstrip_blocks=True
        ).from_string(config["chat_template"])
        self.tokenizer = Tokenizer.from_str(files["tokenizer.json"].decode("utf-8"))

    def __call__(self, messages):
        messages = prompt_messages(messages)
        if not messages or any(
            not isinstance(m, dict)
            or m.get("role") not in {"system", "user", "assistant"}
            or not isinstance(m.get("content"), str)
            or m.get("tool_calls")
            for m in messages
        ):
            raise ValueError("offline tokenizer supports text system/user/assistant messages only")
        rendered = self.template.render(messages=messages, add_generation_prompt=True)
        return self.tokenizer.encode(rendered, add_special_tokens=False).ids


@lru_cache(maxsize=4)
def _loaded(cache):
    return PinnedChatTokenizer(verified_files(Path(cache)))


def pinned_tokenizer(*, cache=None, fetch=False):
    directory = Path(cache) if cache is not None else cache_directory()
    verified_files(directory, fetch=fetch)
    return _loaded(str(directory.resolve()))


@lru_cache(maxsize=4)
def _prompt_path(config_json, cache, builder_sha256):
    """Exercise the actual builders, including every possible sustained-cycle index."""
    config = SimpleNamespace(**{**json.loads(config_json), "tokenize_url": "offline"})
    tokenizer = pinned_tokenizer(cache=cache)
    probe_count = len(tokenizer("stage-c tokenizer preflight"))
    if probe_count != 34:
        raise ValueError(f"readiness probe must reproduce 34 tokens, got {probe_count}")
    if config.protocol_version != "r0-v2" or config.minimum_cycle_seconds <= 0:
        raise ValueError("complete prompt fitness requires bounded r0-v2 cycles")
    banks = {}
    rows = []
    first_blocks = {}
    for family, counts, target in (
        ("saturation", [2, max(config.saturation_levels)], config.saturation_prompt_tokens),
        ("reference", [2, *config.reference_prefix_counts], config.reference_prompt_tokens),
    ):
        for count in sorted(set(counts)):
            tokens = []
            prompt_bank(
                config, family, count, target, None, tokenize_fn=tokenizer, tokenizations=tokens
            )
            rows.append(
                {
                    "family": family,
                    "count": count,
                    "target_tokens": target,
                    **prompt_footprint(tokens),
                }
            )
            banks[family] = tokens
            for index, token_ids in enumerate(tokens):
                identity = f"{family}-{index}"
                block = tuple(token_ids[:16])
                if block in first_blocks and first_blocks[block] != identity:
                    raise ValueError("prompt families share a first block across identities")
                first_blocks[block] = identity
    # Run 4 repeats the same seeds/schedule. Min cycle time bounds the dispatch
    # domain even if requests complete instantly; tokenization consumes that time.
    cycles = math.ceil(config.sustained_level_seconds / config.minimum_cycle_seconds)
    cycle_count = 0
    for level, workers in enumerate(config.saturation_levels):
        for worker in range(workers):
            for cycle in range(cycles):
                identity = saturation_identity(level, worker, cycle)
                _, tokens = exact_prompt(
                    "offline",
                    config.model,
                    identity,
                    config.saturation_prompt_tokens,
                    None,
                    tokenize_fn=tokenizer,
                )
                block = tuple(tokens[:16])
                if block in first_blocks:
                    raise ValueError("sustained cycles share a first block across identities")
                first_blocks[block] = identity
                cycle_count += 1
    # The reset/rewarm run deliberately repeats this ordinary user prompt.
    rewarm_tokens = tokenizer(identity_messages("rewarm", "repeated-reset-rewarm-prefix"))
    if tuple(rewarm_tokens[:16]) in first_blocks:
        raise ValueError("rewarm shares a first block with another identity")
    return {
        "status": "pass",
        "model": MODEL,
        "model_revision": REVISION,
        "file_sha256": FILE_HASHES,
        "readiness_probe_tokens": probe_count,
        "prompt_builder_sha256": builder_sha256,
        "banks": rows,
        "sustained_cycle_count": cycle_count,
        "cycles_per_worker_bound": cycles,
        "repeat_schedule": "Run 4 repeats the same identities and corpora",
        "rewarm": {
            "tokens": len(rewarm_tokens),
            "samples": config.rewarm_samples,
            "repeats": config.rewarm_repeats,
        },
        "maximum_active_prompt_footprint": prompt_footprint(
            banks["saturation"][: config.max_num_seqs]
        ),
        "basis": "real pinned chat tokenizations; full KV prefix chains; no GPU measurement",
    }


def prompt_path_fitness(config, *, cache=None, fetch=False):
    defaults = {"max_num_seqs": 16, "rewarm_samples": 8, "rewarm_repeats": 3}
    # Only prompt-path inputs determine this proof. URLs/timestamps/secrets do not.
    fields = (
        "model",
        "protocol_version",
        "saturation_levels",
        "reference_prefix_counts",
        "saturation_prompt_tokens",
        "reference_prompt_tokens",
        "sustained_level_seconds",
        "minimum_cycle_seconds",
        *defaults,
    )
    config = {field: config.get(field, defaults.get(field)) for field in fields}
    directory = Path(cache) if cache is not None else cache_directory()
    verified_files(directory, fetch=fetch)
    source = Path(__file__).with_name("stage_c_prompts.py").read_bytes()
    return _prompt_path(
        json.dumps(config, sort_keys=True),
        str(directory.resolve()),
        hashlib.sha256(source).hexdigest(),
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--fetch", action="store_true")
    parser.add_argument("--fetch-only", action="store_true")
    args = parser.parse_args()
    if args.fetch_only:
        tokenizer = pinned_tokenizer(fetch=args.fetch)
        count = len(tokenizer("stage-c tokenizer preflight"))
        if count != 34:
            raise ValueError(f"readiness probe must reproduce 34, got {count}")
        print(json.dumps({"file_sha256": FILE_HASHES, "readiness_probe_tokens": count}))
        return 0
    if args.config is None:
        parser.error("--config is required unless --fetch-only")
    config = json.loads(args.config.read_text(encoding="utf-8"))
    config.setdefault("max_num_seqs", 16)
    result = prompt_path_fitness(config, fetch=args.fetch)
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
