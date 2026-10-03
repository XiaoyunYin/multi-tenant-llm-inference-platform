"""Build block-aligned prompts with counts verified by the runtime chat tokenizer."""

import hashlib
import json
import urllib.request

from .time_budget import deadline_urlopen

ChatPrompt = str | list[dict[str, str]]


def prompt_messages(prompt):
    """Keep ordinary calibration strings compatible with explicit chat prompts."""
    return [{"role": "user", "content": prompt}] if isinstance(prompt, str) else prompt


def identity_messages(identity, content):
    return [
        {"role": "system", "content": hashlib.sha256(identity.encode()).hexdigest()[:16]},
        {"role": "user", "content": content},
    ]


def saturation_identity(level, worker, cycle):
    return f"saturation-level-{level}-worker-{worker}-cycle-{cycle}"


def tokenize(url, model, prompt, deadline):
    request = urllib.request.Request(
        url.rstrip("/") + "/tokenize",
        data=json.dumps(
            {
                "model": model,
                "messages": prompt_messages(prompt),
                "add_generation_prompt": True,
            }
        ).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with deadline_urlopen(request, timeout=5, deadline=deadline) as response:
        value = json.loads(response.read(1 << 20))
    tokens = value.get("tokens")
    if (
        not isinstance(tokens, list)
        or value.get("count") != len(tokens)
        or any(type(t) is not int or t < 0 for t in tokens)
    ):
        raise RuntimeError("invalid runtime tokenizer response")
    return tokens


def exact_prompt(url, model, identity, target, deadline, *, tokenize_fn=None):
    # Identity occurs before repeated filler, so a tail nonce cannot hide KV sharing.
    repeats = max(0, target - 20)
    low, high = 0, target * 2
    for attempt in range(24):
        messages = identity_messages(identity, " x" * repeats)
        tokens = tokenize_fn(messages) if tokenize_fn else tokenize(url, model, messages, deadline)
        count = len(tokens)
        if count == target:
            return messages, tokens
        if count < target:
            low = max(low, repeats + 1)
        else:
            high = min(high, repeats - 1)
        if low > high:
            break
        estimate = repeats + target - count
        repeats = estimate if attempt < 3 and low <= estimate <= high else (low + high) // 2
    raise RuntimeError(f"cannot construct verified {target}-token prompt; no truncation fallback")


def prompt_bank(config, family, count, target, deadline, *, tokenize_fn=None, tokenizations=None):
    prompts = []
    first_blocks = set()
    for index in range(count):
        text, tokens = exact_prompt(
            config.tokenize_url,
            config.model,
            f"{family}-{index}",
            target,
            deadline,
            tokenize_fn=tokenize_fn,
        )
        block = tuple(tokens[:16])
        if len(block) != 16 or block in first_blocks:
            raise RuntimeError("prompts must have distinct first full blocks")
        first_blocks.add(block)
        prompts.append(text)
        if tokenizations is not None:
            tokenizations.append(tokens)
    return prompts


def prompt_footprint(tokenizations, block_size=16):
    """Count actual full KV prefix blocks, including each block's parent context."""
    blocks = set()
    total = 0
    for tokens in tokenizations:
        parent = ""
        for start in range(0, len(tokens) - block_size + 1, block_size):
            parent = hashlib.sha256(
                json.dumps([parent, tokens[start : start + block_size]]).encode()
            ).hexdigest()
            blocks.add(parent)
            total += 1
    return {
        "prompt_blocks": len(blocks),
        "total_full_blocks": total,
        "shared_prefix_blocks": total - len(blocks),
    }
