# /// script
# requires-python = "==3.12.*"
# dependencies = ["matplotlib==3.10.7"]
# ///
"""Render pinned attempt-7 digests from Git or hash-checked snapshot paths.

uv run --locked --script scripts/render_r0_packet.py --output-dir <directory>
"""

import argparse
import gzip
import hashlib
import json
import platform
import re
import subprocess
from collections import Counter
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

EVIDENCE = "f2fe3c68a571b450c386915cb350854ea230c777"
ROOT = Path(__file__).resolve().parents[1]
PREFIX = "experiments/inf011/session-2026-10-04-dec044-attempt7/"
SNAPSHOT_PREFIX = "experiments/r0/attempt7/"
DIGEST_PINS = {
    1: "15f74651acf0264e405bbd91d7957da9c43d10053c247800f9f2afd86d6f1328",
    2: "0077ca1b61b786dc3f8aacf10f2ea8f0698e42315d7a664b552b6b3818edd354",
    4: "7958bb6072dc528100801748cb04bbd49289c8082f60c5e5184a2de121fa05c9",
}


def read_digest(number):
    path = PREFIX + f"run-{number}.digest.json.gz"
    present = (
        subprocess.run(
            ["git", "cat-file", "-e", f"{EVIDENCE}^{{commit}}"],
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode
        == 0
    )
    if present:
        # A present historical commit must succeed; never mask a broken Git read.
        raw = subprocess.check_output(["git", "show", f"{EVIDENCE}:{path}"], cwd=ROOT)
    else:
        raw = (ROOT / SNAPSHOT_PREFIX / f"run-{number}.digest.json.gz").read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != DIGEST_PINS[number]:
        raise ValueError(f"Changed digest {path}")
    data = json.loads(gzip.decompress(raw))
    assert data["run"]["status"] == "completed" and not data["run"]["partial"]
    return data, {"commit": EVIDENCE, "path": path, "sha256": digest, "bytes": len(raw)}


def saturation(data, number):
    base = "/run" if number == 1 else "/run/saturation"
    run = data["run"] if number == 1 else data["run"]["saturation"]
    rows = []
    for index, level in enumerate(run["levels"]):
        counts = Counter()
        for outcome in level["failure_split"]:
            counts[outcome["class"]] += outcome["count"]
        total = sum(counts.values())
        assert total == level["request_detail_count"] and total > 0
        assert level["unmatched_dispatched_request_count"] == 0
        assert level["sampler_started_before_load"]
        regime = level["runtime_regime"]
        peak = {}
        for name in ["running", "waiting"]:
            aggregate = regime["native_signal_aggregates"][f"vllm:num_requests_{name}"]
            value = regime[f"{name}_peak"]
            assert value == aggregate["max"] and value == int(value)
            peak[name] = int(value)
        rows.append(
            {
                "run": number,
                "concurrency": level["concurrency"],
                "completed": counts["completed"],
                "dispatched": total,
                "completed_fraction": counts["completed"] / total,
                "outcome_counts": dict(counts),
                "running_peak": peak["running"],
                "waiting_peak": peak["waiting"],
                "pre_content_rejected": counts["vllm_pre_content_rejection"],
                "preemptions_delta": regime["preemptions_delta"],
                "load_seconds": level["planned_load_seconds"],
                "minimum_cycle_seconds": level["minimum_cycle_seconds"],
                "sources": {
                    "level": f"{base}/levels/{index}",
                    "completed_and_dispatched": "failure_split/*/class,count (sum by class)",
                    "denominator_check": "request_detail_count",
                    "gauge_peaks": "runtime_regime/{running,waiting}_peak",
                    "gauge_check": "runtime_regime/native_signal_aggregates/*/max",
                },
            }
        )
    return rows


def reference(data, number):
    base = "/run" if number == 2 else "/run/reference_capacity"
    run = data["run"] if number == 2 else data["run"]["reference_capacity"]
    rows = []
    for index, candidate in enumerate(run["candidates"]):
        n = candidate["distinct_prefix_count"]
        queries = candidate["prefix_query_delta_during_replay"]
        hits = candidate["prefix_hit_delta_during_replay"]
        assert candidate["status"] == "completed" and queries > 0
        assert candidate["all_replay_prefixes_hit"] is None
        assert candidate["replay_token_hit_share"] == hits / queries
        rows.append(
            {
                "run": number,
                "prefixes_and_replay_requests": n,
                "prompt_span_blocks": candidate["prompt_blocks"],
                "query_tokens": int(queries),
                "hit_tokens": int(hits),
                "token_hit_share": hits / queries,
                "reference_prompt_tokens": int(queries / n),
                "max_generated_tokens": candidate["max_tokens"],
                "concurrency": candidate["fixed_concurrency"],
                "source": f"{base}/candidates/{index}",
                "share_denominator": "prefix_query_delta_during_replay (tokens, not requests)",
            }
        )
    return rows


def extract():
    digests, inputs = {}, {}
    for number in DIGEST_PINS:
        digests[number], inputs[str(number)] = read_digest(number)
    sweeps = {str(n): saturation(digests[n], n) for n in [1, 4]}
    refs = {str(n): reference(digests[n], n) for n in [2, 4]}
    levels = [r["concurrency"] for r in sweeps["1"]]
    assert levels == [r["concurrency"] for r in sweeps["4"]]
    assert [
        {k: v for k, v in r.items() if k not in ["run", "source"]} for r in refs["2"]
    ] == [{k: v for k, v in r.items() if k not in ["run", "source"]} for r in refs["4"]]
    metrics = digests[1]["run"]["levels"][0]["native_metric_aggregates"]
    cache_keys = [k for k in metrics if ":vllm:cache_config_info{" in k]
    assert len(cache_keys) == 1
    labels = dict(re.findall(r'(\w+)="([^"]*)"', cache_keys[0]))
    gpu_blocks = int(labels["num_gpu_blocks"])
    block_size = int(labels["block_size"])
    assert int(labels["kv_cache_size_tokens"]) == gpu_blocks * block_size
    success = [r for r in refs["2"] if r["hit_tokens"] > 0]
    lower = max(r["prompt_span_blocks"] for r in success)
    upper = min(r["prompt_span_blocks"] for r in refs["2"] if r["hit_tokens"] == 0)
    assert lower < gpu_blocks < upper
    first_rejections = {
        n: min(r["concurrency"] for r in rows if r["pre_content_rejected"] > 0)
        for n, rows in sweeps.items()
    }
    return {
        "schema": "inf047-r0-chart.v1",
        "evidence_commit": EVIDENCE,
        "input_blobs": inputs,
        "fixed_caption_conditions": {
            "basis": "Committed approved inputs; constants cited, not read as chart data",
            "commit": "1242b8107539f6ce5ee1ce804fa4584ad77997aa",
            "path": "docs/INF011_STAGE_C_SESSION_INPUTS.json",
            "sha256": "6190000ae8e38417f7f86adaf3cfaecc74ccd56d0f1d310fb223786ee4447ad1",
            "values_by_json_pointer": {
                "/instance_type": "g6.xlarge",
                "/gpu": "1 x NVIDIA L4",
                "/availability_zone": "us-east-1b",
                "/model": "Qwen/Qwen2.5-7B-Instruct",
                "/runtime_image": "docker.io/vllm/vllm-openai:v0.29.0",
                "/runtime_image_linux_amd64_digest": "sha256:082ca6f035279109041ffd3fe0695cb568b29bc580b35c4f297a66a08b216c1b",
                "/workload_sizing/saturation_prompt_tokens": 6144,
                "/workload_sizing/max_tokens": 128,
            },
            "runtime_and_on_demand_basis": "R0_ANALYSIS.md: Evidence and numerical conditions, approved at e630b47",
        },
        "saturation": sweeps,
        "reference": refs,
        "derived": {
            "reference_bracket_prompt_span_blocks": [lower, upper],
            "bracket_basis": "largest nonzero replay token-hit candidate to first zero-hit candidate",
            "native_gpu_blocks": gpu_blocks,
            "block_size_tokens": block_size,
            "native_capacity_source": "/run/levels/0/native_metric_aggregates/"
            + cache_keys[0],
            "first_pre_content_rejection_concurrency": first_rejections,
            "max_completed_run_difference": max(
                abs(a["completed"] - b["completed"])
                for a, b in zip(sweeps["1"], sweeps["4"], strict=True)
            ),
        },
        "semantics": {
            "counts": "Completed and dispatched at each run/level; completed includes drain, not throughput",
            "peaks": "Separate sampled maxima within each level; not simultaneous occupancy",
            "reference": "Aggregate replay hit tokens / query tokens, not per-request hit proof or exact capacity",
            "x_spacing": "S panels equally space tested concurrency levels; lines guide the eye",
            "conditions": "Hardware/model/workload pins in R0_ANALYSIS; chart data input is ONLY the three committed attempt7 digests",
        },
    }


def render(data, output):
    plt.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 10,
            "axes.spines.top": False,
            "axes.spines.right": False,
            "savefig.dpi": 130,
        }
    )
    figure, axes = plt.subplots(2, 2, figsize=(14, 10))
    blue, orange = "#2166ac", "#b35806"
    levels = [r["concurrency"] for r in data["saturation"]["1"]]
    x = list(range(len(levels)))
    for number, color, marker, style in [
        ("1", blue, "o", "-"),
        ("4", orange, "s", "--"),
    ]:
        rows = data["saturation"][number]
        # Dodge only display positions; the tested levels and data stay exact.
        run_x = [value + (-0.08 if number == "1" else 0.08) for value in x]
        a, b, c = axes[0, 0], axes[0, 1], axes[1, 0]
        a.plot(
            run_x,
            [r["completed"] for r in rows],
            color=color,
            marker=marker,
            linestyle=style,
            label=f"Run {number} completed",
        )
        a.plot(
            run_x,
            [r["dispatched"] for r in rows],
            color=color,
            linestyle=":",
            marker=marker,
            markerfacecolor="white",
            label=f"Run {number} dispatched",
        )
        b.plot(
            run_x,
            [r["completed_fraction"] for r in rows],
            color=color,
            marker=marker,
            linestyle=style,
            label=f"Run {number}",
        )
        for i, row in enumerate(rows):
            b.annotate(
                f"{row['completed']}/{row['dispatched']}",
                (run_x[i], row["completed_fraction"]),
                textcoords="offset points",
                xytext=(0, 12 if number == "1" else -18),
                ha="center",
                color=color,
                fontsize=7,
            )
        c.plot(
            run_x,
            [r["running_peak"] for r in rows],
            color=color,
            marker=marker,
            linestyle=style,
            markerfacecolor="white" if number == "4" else color,
            label=f"Run {number} running",
        )
        c.plot(
            run_x,
            [r["waiting_peak"] for r in rows],
            color=color,
            marker="^",
            linestyle=":" if number == "1" else "--",
            markerfacecolor="white",
            label=f"Run {number} waiting",
        )
    axes[0, 0].set(
        title="A. Completion and dispatch counts",
        ylabel="Requests per level (log scale)",
        yscale="log",
    )
    axes[0, 1].set(
        title="B. Completed / dispatched",
        ylabel="Fraction of dispatched requests",
        ylim=(-0.12, 1.15),
    )
    axes[1, 0].set(
        title="C. Sampled running and waiting peaks",
        ylabel="Requests (separate maxima)",
    )
    for axis in [axes[0, 0], axes[0, 1], axes[1, 0]]:
        axis.set_xticks(x, [str(n) for n in levels])
        axis.set_xlabel("Offered concurrency (tested levels, equally spaced)")
        axis.grid(alpha=0.15)
        axis.legend(fontsize=8, loc="best")
    ref = axes[1, 1]
    lower, upper = data["derived"]["reference_bracket_prompt_span_blocks"]
    ref.axvspan(
        lower,
        upper,
        color="#c7e9c0",
        alpha=0.5,
        label=f"Bracket {lower:,} to {upper:,} span blocks",
    )
    for number, color, marker, style in [
        ("2", blue, "o", "-"),
        ("4", orange, "x", "--"),
    ]:
        rows = data["reference"][number]
        ref.plot(
            [r["prompt_span_blocks"] for r in rows],
            [r["token_hit_share"] for r in rows],
            color=color,
            marker=marker,
            linestyle="none",
            markerfacecolor="white",
            label=f"Run {number} C replay",
        )
    blocks = data["derived"]["native_gpu_blocks"]
    ref.axvline(
        blocks, color="#444444", linestyle=":", label=f"Native GPU blocks {blocks:,}"
    )
    ref.set(
        title="D. Reference-capacity bracket (aggregate counters)",
        xlabel="Population prompt-span blocks",
        ylabel="Replay hit tokens / query tokens",
        ylim=(-0.08, 1.08),
    )
    ref.legend(fontsize=8, loc="center right")
    ref.grid(alpha=0.15)
    figure.suptitle(
        "R0 attempt 7 | aggregate evidence, not a safe-capacity certificate",
        fontsize=16,
    )
    figure.text(
        0.5,
        0.93,
        "g6.xlarge / L4 | On-Demand us-east-1b | Qwen2.5-7B-Instruct | vLLM 0.29.0",
        ha="center",
        fontsize=11,
    )
    seconds = data["saturation"]["1"][0]["load_seconds"]
    c = data["reference"]["2"][0]
    figure.text(
        0.5,
        0.035,
        f"S: 6,144-token prompt / max 128 output, {seconds}s closed-loop load + drain. "
        f"C: {c['reference_prompt_tokens']:,}-token prefix / max {c['max_generated_tokens']} output, "
        f"concurrency {c['concurrency']}. Block size {data['derived']['block_size_tokens']}.\n"
        "Completion is not throughput; peaks are not simultaneous; replay hits are token counters. "
        "A-C: run 1 left / run 4 right of each tested level.\n"
        "Source: f2fe3c6 attempt7 digests (paths/hashes and every plotted value in chart-data.json).",
        ha="center",
        fontsize=9,
    )
    figure.subplots_adjust(
        left=0.075, right=0.975, top=0.86, bottom=0.14, hspace=0.42, wspace=0.22
    )
    figure.savefig(output, metadata={"Software": "INF047 pinned Matplotlib 3.10.7"})
    plt.close(figure)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    data = extract()
    image = args.output_dir / "r0-saturation-reference.png"
    render(data, image)
    data["render"] = {
        "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "lock_sha256": hashlib.sha256(
            Path(__file__).with_suffix(".py.lock").read_bytes()
        ).hexdigest(),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "matplotlib": matplotlib.__version__,
        "image_sha256": hashlib.sha256(image.read_bytes()).hexdigest(),
        "image_bytes": image.stat().st_size,
        "style": "fixed DejaVu Sans, Agg backend, fixed size/DPI and PNG metadata",
        "workload_caption_note": "S prompt/output settings are fixed conditions cited from approved R0_ANALYSIS, not inferred from digest token counts",
    }
    (args.output_dir / "chart-data.json").write_text(
        json.dumps(data, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    print(
        json.dumps(
            {"image_bytes": image.stat().st_size, "derived": data["derived"]}, indent=2
        )
    )


if __name__ == "__main__":
    main()
