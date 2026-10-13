# /// script
# requires-python = "==3.12.*"
# dependencies = ["matplotlib==3.10.7"]
# ///
"""Render R1-C1 from committed analysis, or the hash-pinned public projection."""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ANALYSIS_COMMIT = "ec934b25403359842ed621fe17c44946c81b07dc"
ANALYSIS_PATH = "docs/evidence/r1-analysis/receipt.json"
ANALYSIS_SHA256 = "4774cd05abc77fb0c6b02399f704df3e0e215f1c0b0b7a917390064e197f2002"
PROJECTION_SHA256 = "7ef3a2e8cdc88db3e204e395a7f9f88ff789536045da15415872fdffa4dfa6de"


def encoded(data):
    return (json.dumps(data, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()


def project(receipt):
    rows = []
    for row in receipt["runs"]:
        rows.append(
            dict(
                run=row["id"],
                block=row["block"],
                position=(row["id"] - 1) % 3 + 1,
                policy=row["policy"],
                counts=row["counts"],
                completed=row["completed"],
                throughput=row["metrics"]["throughput"],
                native_hit_fractions=row["native_hit_fractions"],
                joint_samples=row["sample_counts"]["joint_n"],
                positive_joint_wait_fraction=row["summary"][
                    "positive_joint_wait_fraction"
                ],
                warm_label=row["warm_label"],
                warm_s=row["warm_s"],
            )
        )
    return dict(
        schema=1,
        source=dict(commit=ANALYSIS_COMMIT, path=ANALYSIS_PATH, sha256=ANALYSIS_SHA256),
        scope="pilot, one session, two blocks; admitted requests only; no causal claim or confirmatory interval",
        conditions="2 x g6.xlarge / one L4 each; Qwen2.5-7B-Instruct; vLLM v0.29.0; 10.92 offers/s; 6553 offers/run",
        definition="validated cohort completions / fixed 600 seconds including drain completions; 429 denominator is offered",
        measured_seconds=600,
        descriptive_tolerance=0.05,
        rows=rows,
        comparisons=[r for r in receipt["comparisons"] if r["metric"] == "throughput"],
    )


def read_data():
    present = (
        subprocess.run(
            ["git", "cat-file", "-e", f"{ANALYSIS_COMMIT}^{{commit}}"],
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode
        == 0
    )
    if present:
        raw = subprocess.check_output(
            ["git", "show", f"{ANALYSIS_COMMIT}:{ANALYSIS_PATH}"], cwd=ROOT
        )
        if hashlib.sha256(raw).hexdigest() != ANALYSIS_SHA256:
            raise ValueError("Committed R1 analysis hash mismatch")
        raw = encoded(project(json.loads(raw)))
    else:
        raw = (ROOT / "experiments/r1/chart-data.json").read_bytes()
    if hashlib.sha256(raw).hexdigest() != PROJECTION_SHA256:
        raise ValueError("R1 projection hash mismatch")
    data = json.loads(raw)
    for row in data["rows"]:
        c = row["counts"]
        if c["offered"] != sum(c[k] for k in ("admitted", "rejected", "missed")):
            raise ValueError("Offered denominator mismatch")
        if row["completed"] != c["admitted"] or c["failed"] or c["censored"]:
            raise ValueError("Unexpected admitted cohort outcomes")
        if row["throughput"] != row["completed"] / data["measured_seconds"]:
            raise ValueError("Throughput definition mismatch")
    return data


def render(data, output):
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, axes = plt.subplots(
        1, 2, figsize=(12, 5.8), gridspec_kw={"width_ratios": [1.3, 1]}
    )
    colors = {"hash": "#007e87", "ll": "#956531", "rr": "#556273"}
    for block, offset in (("b1", -0.18), ("b2", 0.18)):
        rows = [
            next(r for r in data["rows"] if r["block"] == block and r["policy"] == p)
            for p in ("rr", "ll", "hash")
        ]
        xs = [i + offset for i in range(3)]
        axes[0].bar(
            xs,
            [r["throughput"] for r in rows],
            width=0.32,
            color=[colors[r["policy"]] for r in rows],
            alpha=1 if block == "b1" else 0.6,
            label=block,
        )
        for x, row in zip(xs, rows, strict=True):
            axes[0].text(
                x,
                row["throughput"] + 0.12,
                f"{row['throughput']:.3f}\npos {row['position']}",
                ha="center",
                fontsize=9,
            )
    axes[0].set(
        xticks=range(3),
        xticklabels=["rr", "ll", "hash"],
        ylim=(0, 12.4),
        ylabel="Completions per second (validated cohort ÷ 600 s)",
    )
    axes[0].legend(
        title="Paired block (dark = b1, light = b2)",
        loc="upper left",
        bbox_to_anchor=(0, 1.22),
        ncol=2,
    )
    compare = next(r for r in data["comparisons"] if r["policy"] == "hash")
    values = [v * 100 for v in compare["relative_differences"]]
    axes[1].bar([0, 1], values, color=[colors["hash"]] * 2, alpha=0.85, width=0.5)
    axes[1].axhline(
        5, color="#9e3939", linestyle="--", label="5% descriptive tolerance"
    )
    for i, value in enumerate(values):
        axes[1].text(
            i,
            value + 0.35,
            f"{value:.4f}%\nhash position {1 if i == 0 else 3}",
            ha="center",
            fontsize=10,
        )
    axes[1].set(
        xticks=[0, 1],
        xticklabels=["b1", "b2"],
        ylim=(0, 9.7),
        ylabel="Hash throughput above paired rr (%)",
    )
    axes[1].legend(loc="upper right", fontsize=9)
    for ax in axes:
        ax.spines[["top", "right"]].set_visible(False)
        ax.grid(axis="y", alpha=0.15)
        ax.set_axisbelow(True)
    fig.suptitle("R1 pilot: one session, two blocks", fontsize=17, fontweight="bold")
    fig.text(
        0.5,
        0.89,
        "2 x L4 | Qwen2.5-7B-Instruct | vLLM v0.29.0 | fixed 10.92 offers/s",
        ha="center",
        fontsize=10,
    )
    fig.text(
        0.07,
        0.055,
        "Admitted requests only; 6,553 offers/run. Only b1 exceeds 5%; hash ran first there.\nOrder and throughput coincide; no order effect or causal policy effect established. No confirmatory interval.",
        fontsize=10,
    )
    fig.subplots_adjust(left=0.07, right=0.98, bottom=0.22, top=0.72, wspace=0.22)
    output.mkdir(parents=True, exist_ok=True)
    (output / "chart-data.json").write_bytes(encoded(data))
    fig.savefig(
        output / "r1-throughput.png",
        dpi=160,
        metadata={"Software": "matplotlib 3.10.7"},
    )
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    data = read_data()
    render(data, args.output_dir)
    print("R1 chart and hash-checked projection written; pilot only")


if __name__ == "__main__":
    main()
