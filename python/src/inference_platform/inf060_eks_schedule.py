"""Frozen cohort assignment, exact prompts and a bounded open-loop scheduler."""

import hashlib
import random
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from fractions import Fraction

from .stage_c_prompts import identity_messages

LEVELS = ("0.25", "1", "3", "8")
TENANTS = ("inf060-a", "inf060-b")
WINDOW_SECONDS = 600
DRAIN_SECONDS = 120
WARMUP_SECONDS = 120
SMOKE_SECONDS = 2
REQUEST_CAP_SECONDS = 30
WINDOW_WAIT_SECONDS = 780
SETUP_PHASES = ("smoke", "warmup")
SLOTS = 512
SEED = 399060


def allocate(total, weights):
    exact = [Fraction(total * weight, sum(weights)) for weight in weights]
    counts = [int(n) for n in exact]
    order = sorted(range(len(counts)), key=lambda i: (counts[i] - exact[i], i))
    for index in order[: total - sum(counts)]:
        counts[index] += 1
    return counts


def schedule(level):
    if level not in (*LEVELS, *SETUP_PHASES):
        raise ValueError("streaming_level")
    setup = level in SETUP_PHASES
    duration = {"smoke": SMOKE_SECONDS, "warmup": WARMUP_SECONDS}.get(level, WINDOW_SECONDS)
    rate = Fraction(1 if setup else level)
    count = int(rate * duration)
    rng = random.Random(f"{SEED}:{level}")
    groups = []
    for tenant in TENANTS:
        strata = []
        for cap, size in zip((32, 64, 128), allocate(count // 2, (1, 2, 1)), strict=True):
            strata.append([{"tenant": tenant, "output_cap": cap} for _ in range(size)])
        groups.extend(strata)
    for rows, cancels in zip(
        groups, allocate(0 if setup else count // 10, list(map(len, groups))), strict=True
    ):
        for index, row in enumerate(rows):
            row["cancel_assigned"] = index < cancels
    by_tenant = []
    for tenant in TENANTS:
        rows = [row for strata in groups for row in strata if row["tenant"] == tenant]
        rng.shuffle(rows)
        for index, row in enumerate(rows):
            row["shared_prefix"] = index < len(rows) // 2
        by_tenant.append(rows)
    earlier = LEVELS if setup else LEVELS[: LEVELS.index(level)]
    start = sum(int(Fraction(prior) * WINDOW_SECONDS) for prior in earlier)
    if level == "warmup":
        start += SMOKE_SECONDS
    interleaved = [row for pair in zip(*by_tenant, strict=True) for row in pair]
    return [
        {
            **row,
            "alias": start + index,
            "level": level,
            "input_tokens": 1024,
            "slot_ns": int(Fraction(index * 10**9) / rate),
            "cancel_assigned": index == 0 if level == "smoke" else row["cancel_assigned"],
        }
        for index, row in enumerate(interleaved)
    ]


def prompt_label(row):
    return f"{row['level']}-{row['tenant']}-{row['alias']}"


def prompts(rows, tokenize):
    """Keep prompt text and token IDs entirely in the client pod."""
    cached_prefixes = {}
    shared_blocks, distinct = {}, set()
    for row in rows:
        label = prompt_label(row)
        marker = canary(label)

        def render(filler, marker=marker, unique_label=None if row["shared_prefix"] else label):
            content = filler + " " + marker + " Continue counting:"
            if unique_label is not None:
                # The default chat template's common system prologue can
                # mask a user-message identity in the first cache block.
                return identity_messages(unique_label, content)
            return [{"role": "user", "content": content}]

        if row["shared_prefix"]:
            tenant = row["tenant"]
            if tenant not in cached_prefixes:
                for size in range(470, 520):
                    base = f"Shared vocabulary for {tenant}." + " one" * size
                    a = tokenize([{"role": "user", "content": base + " apple"}])
                    b = tokenize([{"role": "user", "content": base + " banana"}])
                    if a[:512] == b[:512] and a[512] != b[512]:
                        cached_prefixes[tenant] = base
                        shared_blocks[tenant] = tuple(a[:512])
                        break
                else:
                    raise ValueError("streaming_shared_prefix")
            base = cached_prefixes[tenant]
        else:
            base = "Unique sequence."
        available = 1024 - len(tokenize(render(base)))
        for delta in (0, -1, 1, -2, 2, -3, 3, -4, 4):
            # Keep the shared-prefix divergence ahead of deterministic padding.
            text = render(base)
            text[-1]["content"] += " one" * max(0, available + delta)
            tokens = tokenize(text)
            if len(tokens) == 1024:
                break
        else:
            raise ValueError("streaming_prompt_length")
        if row["shared_prefix"]:
            if tuple(tokens[:512]) != shared_blocks[row["tenant"]]:
                raise ValueError("streaming_shared_prefix")
        else:
            block = tuple(tokens[:16])
            if block in distinct:
                raise ValueError("streaming_distinct_prefix")
            distinct.add(block)
        yield text


def canary(label):
    return "INF060CANARY" + hashlib.sha256(label.encode()).hexdigest()[:20]


def run_offers(
    rows,
    perform,
    record,
    *,
    end_ns,
    start_ns=None,
    slots=SLOTS,
    now=time.monotonic_ns,
    sleep=time.sleep,
):
    start = now() if start_ns is None else start_ns
    active = set()
    with ThreadPoolExecutor(max_workers=slots) as pool:

        def collect(done):
            for future in done:
                record(future.result())
            active.difference_update(done)

        for index, row in enumerate(rows):
            planned = start + row["slot_ns"]
            next_slot = start + rows[index + 1]["slot_ns"] if index + 1 < len(rows) else end_ns
            left = planned - now()
            if left > 0:
                sleep(left / 10**9)
            collect({future for future in active if future.done()})
            last = min(next_slot, end_ns)
            if len(active) == slots or now() >= last:
                record({**row, "planned_ns": planned, "outcome": "missed"})
                continue

            def dispatch(row=row, planned=planned, last=last):
                if now() >= last:
                    return {**row, "planned_ns": planned, "outcome": "missed"}
                return perform({**row, "planned_ns": planned})

            active.add(pool.submit(dispatch))
        while active:
            done, _ = wait(active, return_when=FIRST_COMPLETED)
            collect(done)
    return start
