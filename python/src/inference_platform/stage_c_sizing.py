"""Offline arithmetic guard for Stage C pressure and reference-capacity regimes."""

import argparse
import json
import math
import re
from pathlib import Path
from typing import Any


def decode_blocks(max_tokens: int, block_size: int) -> int:
    # Aligned prefill-only requests do not fill a decode block. Generated
    # requests reserve the conservative ceiling, including partial decode tails.
    return 0 if max_tokens == 1 else math.ceil(max_tokens / block_size)


def clustered_counts(
    capacity: int, blocks_per_prompt: int, concurrency: int, targets: list[float]
) -> list[int]:
    return [
        max(concurrency, round(target * capacity / blocks_per_prompt / concurrency) * concurrency)
        for target in targets
    ]


def check_sizing(
    config: dict[str, Any], *, launcher: str | None = None, tokenization: dict | None = None
) -> dict[str, Any]:
    required = (
        "capacity_blocks",
        "block_size",
        "max_num_seqs",
        "max_model_len",
        "saturation_prompt_tokens",
        "max_tokens",
        "reference_prompt_tokens",
    )
    for name in required:
        if type(config.get(name)) is not int or config[name] <= 0:
            raise ValueError(f"{name} must be a positive token/count integer")
    counts = config.get("reference_prefix_counts")
    if (
        not isinstance(counts, list)
        or not counts
        or any(type(n) is not int or n <= 0 for n in counts)
    ):
        raise ValueError("reference_prefix_counts must be positive integers")
    levels = config.get("saturation_levels")
    if (
        not isinstance(levels, list)
        or not levels
        or any(type(n) is not int or n <= 0 for n in levels)
    ):
        raise ValueError("saturation_levels must be positive integers")
    targets = config.get("reference_target_capacity_ratios")
    clustered = (
        isinstance(targets, list)
        and 6 <= len(targets) <= 8
        and all(type(t) in (int, float) and math.isfinite(t) and t > 0 for t in targets)
        and targets == sorted(set(targets))
        and len(counts) == len(targets)
        and 0.45 <= targets[0] <= 0.55
        and 1.4 <= targets[-1] <= 1.6
        and sum(0.8 <= t <= 1.25 for t in targets) >= 4
    )
    capacity = config["capacity_blocks"] * config["block_size"]
    active = min(config["max_num_seqs"], max(levels)) * config["saturation_prompt_tokens"]
    reference_max_tokens = config.get("reference_max_tokens", config["max_tokens"])
    concurrency = config.get("reference_concurrency", 4)
    if type(reference_max_tokens) is not int or reference_max_tokens <= 0:
        raise ValueError("reference_max_tokens must be positive")
    if type(concurrency) is not int or concurrency <= 0:
        raise ValueError("reference_concurrency must be positive")
    prompt_blocks = config["reference_prompt_tokens"] // config["block_size"]
    generated_blocks = decode_blocks(reference_max_tokens, config["block_size"])
    blocks_per_request = prompt_blocks + generated_blocks
    footprints = [n * blocks_per_request for n in counts]
    measured = {}
    if tokenization is not None:
        if any(
            row["target_tokens"] != config[f"{row['family']}_prompt_tokens"]
            for row in tokenization["banks"]
        ):
            raise ValueError("real tokenizer footprints differ from sizing prompt targets")
        measured = {
            row["count"]: row["prompt_blocks"]
            for row in tokenization["banks"]
            if row["family"] == "reference"
        }
        footprints = [measured[n] + n * generated_blocks for n in counts]
        active = (
            tokenization["maximum_active_prompt_footprint"]["prompt_blocks"] * config["block_size"]
        )
    failures = []
    if not clustered:
        failures.append("reference grid requires 6-8 corpora clustered around measured capacity")
    recomputed = (
        clustered_counts(config["capacity_blocks"], blocks_per_request, concurrency, targets)
        if clustered
        else []
    )
    if clustered and counts != recomputed:
        failures.append("reference counts differ from recomputed capacity-clustered grid")
    if config["reference_prompt_tokens"] % config["block_size"]:
        failures.append("reference prompts must be block-aligned for prefill-only footprints")
    waves = sum(math.ceil(n / concurrency) for n in counts) * 2
    duration = (
        waves * config.get("reference_prefill_seconds_per_wave_planning", 8) + len(counts) * 20
    )
    budget = config.get("reference_run_budget_seconds", 2400)
    if duration >= budget:
        failures.append("population/replay planning duration does not fit Run 2 budget")
    if active <= capacity:
        failures.append("KV pressure unreachable: max active prompt KV <= measured capacity")
    if config.get("distinct_from_first_block") is not True:
        failures.append("unique first blocks required; shared prompt KV invalidates active bound")
    if (
        max(
            config["saturation_prompt_tokens"] + config["max_tokens"],
            config["reference_prompt_tokens"] + reference_max_tokens,
        )
        > config["max_model_len"]
    ):
        failures.append("prompt plus decode exceeds max-model-len")
    if not min(footprints) < config["capacity_blocks"] < max(footprints):
        failures.append("reference capacity unreachable: corpora do not bracket capacity")
    for blocks, target in zip(footprints, targets, strict=False):
        if abs(blocks / config["capacity_blocks"] - target) > 0.1 * target:
            failures.append(f"reference target {target}x unreachable within 10% sizing tolerance")
    if max(levels) <= config["max_num_seqs"]:
        failures.append("waiting regime unreachable: sweep never exceeds max-num-seqs")
    if launcher is not None:
        for key, flag in (("max_num_seqs", "max-num-seqs"), ("max_model_len", "max-model-len")):
            match = re.search(rf"--{flag}\s+(\d+)", launcher)
            if not match or int(match[1]) != config[key]:
                failures.append(f"sizing inputs differ from rendered --{flag}")
    return {
        "status": "pass" if not failures else "fail",
        "failures": failures,
        "capacity_blocks": config["capacity_blocks"],
        "capacity_tokens": capacity,
        "maximum_active_prompt_kv_tokens": active,
        "maximum_active_kv_tokens_including_decode": active
        + min(config["max_num_seqs"], max(levels)) * config["max_tokens"],
        "reference_prompt_blocks_per_request": prompt_blocks,
        "reference_decode_blocks_per_request": generated_blocks,
        "reference_max_tokens": reference_max_tokens,
        "recomputed_reference_prefix_counts": recomputed,
        "reference_population_replay_planning_seconds": duration,
        "reference_run_budget_seconds": budget,
        "active_prompt_capacity_ratio": active / capacity,
        "reference_corpora": [
            {
                "prefixes": n,
                "prompt_blocks": measured.get(n, n * prompt_blocks),
                "decode_blocks_assumed": n * generated_blocks,
                "blocks": b,
                "capacity_ratio": b / config["capacity_blocks"],
            }
            for n, b in zip(counts, footprints, strict=True)
        ],
        "basis": "real pinned chat prefix-block footprints; no measured regime claim"
        if tokenization is not None
        else "arithmetic forecast only; complete real tokenizer fitness "
        "required before PlanPaid; no measured regime claim",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--rendered-json", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    inputs = json.loads(args.inputs.read_text(encoding="utf-8"))
    launcher = None
    if args.rendered_json:
        launcher = json.loads(json.loads(args.rendered_json.read_text(encoding="utf-8")))
    from .stage_c_tokenizer import prompt_path_fitness

    sizing = inputs.get("workload_sizing", inputs)
    example = json.loads(
        (
            Path(__file__).resolve().parents[3] / "experiments/examples/stage-c-config.json"
        ).read_text(encoding="utf-8")
    )
    tokenization = prompt_path_fitness(
        {
            **example,
            "max_num_seqs": sizing["max_num_seqs"],
            "saturation_levels": sizing["saturation_levels"],
            "reference_prefix_counts": sizing["reference_prefix_counts"],
            "saturation_prompt_tokens": sizing["saturation_prompt_tokens"],
            "reference_prompt_tokens": sizing["reference_prompt_tokens"],
            "rewarm_samples": example.get("rewarm_samples", 8),
            "rewarm_repeats": example.get("rewarm_repeats", 3),
        }
    )
    result = check_sizing(sizing, launcher=launcher, tokenization=tokenization)
    print(json.dumps(result, indent=2))
    if args.output:
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n")
    return int(result["status"] != "pass")


if __name__ == "__main__":
    raise SystemExit(main())
