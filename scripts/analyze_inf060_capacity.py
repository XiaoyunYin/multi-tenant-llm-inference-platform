"""Recount the four frozen INF-060 windows and render their measured curve."""

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

EVIDENCE = Path("docs/evidence/r424-inf060-gpu")
WINDOW_S = 600
GPU_COUNT = 2
# Committed price: docs/INF060_GPU_EKS_EXACT_PLAN.md, "Live prices and forecast".
GPU_HOURLY_USD = 0.8048
# The client recorded the end of each drain separately from its request rows.
# Exact values from frozen/levels.json, retained here so the only runtime
# inputs are requests.jsonl and the operator's cost record.
DRAIN_NS = {"0.25": 81196512, "1": 6037097146, "3": 6065074649, "8": 10139371687}


def recount(requests, cost):
    by_level = defaultdict(list)
    with requests.open(encoding="utf-8") as source:
        for line in source:
            row = json.loads(line)
            by_level[row["level"]].append(row)
    if set(by_level) != DRAIN_NS.keys():
        raise ValueError("expected all four frozen windows")
    if cost["invoice"] is not False or cost["task_cost_estimate_usd"] <= 0:
        raise ValueError("expected the operator estimate")
    total_elapsed = sum(WINDOW_S + drain / 1e9 for drain in DRAIN_NS.values())
    rows = []
    for level, drain in DRAIN_NS.items():
        offers = by_level[level]
        elapsed = WINDOW_S + drain / 1e9
        if len(offers) != float(level) * WINDOW_S:
            raise ValueError(f"scheduled count mismatch at {level}")
        outcomes = Counter(row["outcome"] for row in offers)
        completed = [row for row in offers if row["outcome"] == "completed"]
        if any(
            not row["validated_done"] or row["completion_tokens"] < 0
            for row in completed
        ):
            raise ValueError(f"invalid completed row at {level}")
        good = [
            row
            for row in completed
            if row["first_content_monotonic_ns"] - row["dispatch_ns"] <= 10**9
            and row["terminal_ns"] - row["dispatch_ns"] <= 15 * 10**9
        ]
        ordinary = sum(not row["cancel_assigned"] for row in offers)
        ordinary_good = sum(not row["cancel_assigned"] for row in good)
        tokens = sum(row["completion_tokens"] for row in completed)
        rejected = sum(row.get("http_status") == 429 for row in offers)
        gpu_cost = GPU_COUNT * GPU_HOURLY_USD * elapsed / 3600
        apportioned_cost = cost["task_cost_estimate_usd"] * elapsed / total_elapsed
        rows.append(
            {
                "offered_per_s": float(level),
                "elapsed_s": elapsed,
                "scheduled": len(offers),
                "outcomes": dict(outcomes),
                "ordinary_scheduled": ordinary,
                "good": len(good),
                "ordinary_good": ordinary_good,
                "completed_per_s": len(completed) / elapsed,
                "goodput_per_s": len(good) / elapsed,
                "http_429": rejected,
                "http_429_per_s": rejected / elapsed,
                "completed_output_tokens": tokens,
                "output_tokens_per_s": tokens / elapsed,
                "output_tokens_per_s_per_gpu": tokens / elapsed / GPU_COUNT,
                "gpu_only_usd_per_million_output": 1e6 * gpu_cost / tokens,
                "full_session_allocated_usd_per_million_output": 1e6
                * apportioned_cost
                / tokens,
            }
        )
    return rows


def render(rows):
    """Draw the observed points without interpolating untested rates."""
    svg = [
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 720 350" role="img"',
        ' aria-labelledby="title description">',
        '<title id="title">INF-060 goodput and HTTP 429 rates</title>',
        '<desc id="description">Four measured rates on two L4 GPUs, one run per rate.</desc>',
        '<rect width="720" height="350" fill="white"/>',
        '<g font-family="sans-serif" fill="#192434" font-size="13">',
        '<text x="76" y="30" font-size="19">INF-060 outcomes at tested rates</text>',
        '<text x="76" y="52">Two L4 GPUs · One 600 s window plus drain per rate</text>',
        '<text x="20" y="190" transform="rotate(-90 20 190)">Outcomes/s</text>',
        '<text x="376" y="322" text-anchor="middle">Scheduled offers/s</text>',
    ]
    for tick in range(5):
        y = 270 - 48 * tick
        svg.extend(
            (
                f'<path d="M 76 {y} H 676" stroke="#d1d9e2"/>',
                f'<text x="65" y="{y + 4}" text-anchor="end">{tick}</text>',
            )
        )
    for row in rows:
        rate = row["offered_per_s"]
        x = 76 + 75 * rate
        y_good = 270 - 48 * row["goodput_per_s"]
        y_rejected = 270 - 48 * row["http_429_per_s"]
        svg.extend(
            (
                f'<circle cx="{x:.2f}" cy="{y_good:.2f}" r="5" fill="#075d7b"/>',
                f'<rect x="{x - 4:.2f}" y="{y_rejected - 4:.2f}" width="8" height="8" fill="#b34b13"/>',
                f'<text x="{x:.2f}" y="294" text-anchor="middle">{rate:g}</text>',
            )
        )
    svg.extend(
        (
            '<circle cx="350" cy="87" r="5" fill="#075d7b"/>',
            '<text x="362" y="92">SLO-met completions</text>',
            '<rect x="532" y="83" width="8" height="8" fill="#b34b13"/>',
            '<text x="547" y="92">HTTP 429</text>',
            "</g></svg>",
        )
    )
    return "\n".join(svg) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chart", type=Path, required=True)
    args = parser.parse_args()
    cost = json.loads((EVIDENCE / "operator-cost.json").read_text(encoding="utf-8"))
    rows = recount(EVIDENCE / "frozen/requests.jsonl", cost)
    args.chart.write_text(render(rows), encoding="utf-8", newline="\n")
    print(json.dumps(rows, indent=2, ensure_ascii=False, allow_nan=False))


if __name__ == "__main__":
    main()
