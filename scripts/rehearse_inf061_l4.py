"""Rehearse the registered single-L4 sequence without cloud or GPU access."""

import argparse
import hashlib
import json
import math
import re
from collections import Counter
from decimal import Decimal
from pathlib import Path

from inference_platform.inf060_streaming_probe import observe_stream

ROOT = Path(__file__).resolve().parents[1]
FINAL_LINE = re.compile(r"FINAL: (-?[0-9]+(?:\.[0-9]+)?)")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def quality_cases(path, pin):
    data = path.read_bytes()
    if sha(data) != pin["source_sha256"]:
        raise ValueError("quality_source_digest")
    items = data.splitlines()[: pin["count"]]
    if (
        len(items) != pin["count"]
        or sha(b"\n".join(items) + b"\n") != pin["subset_sha256"]
    ):
        raise ValueError("quality_subset_digest")
    cases = [json.loads(item) for item in items]
    return [
        (
            case["question"],
            Decimal(case["answer"].rsplit("#### ", 1)[1].replace(",", "")),
        )
        for case in cases
    ]


def score(text, answer):
    lines = text.strip().splitlines()
    match = FINAL_LINE.fullmatch(lines[-1].strip()) if lines else None
    return bool(match and Decimal(match[1]) == answer)


def quantiles(samples):
    ordered = sorted(samples)
    return {
        "n": len(ordered),
        **{
            f"p{q}": ordered[math.ceil(len(ordered) * q / 100) - 1] if ordered else None
            for q in (50, 95)
        },
    }


def summarize(rows, elapsed):
    counts = Counter(row["outcome"] for row in rows)
    finished = [row for row in rows if row["outcome"] == "completed"]
    return {
        "scheduled": len(rows),
        "outcomes": dict(counts),
        "completed_per_s": len(finished) / elapsed,
        "completed_output_tokens_per_s": sum(
            row["completion_tokens"] for row in finished
        )
        / elapsed,
        "ttft_ms": quantiles(
            [row["ttft_ms"] for row in rows if row.get("ttft_ms") is not None]
        ),
        "tpot_ms": quantiles(
            [row["tpot_ms"] for row in finished if row["tpot_ms"] is not None]
        ),
        "http_429": sum(row.get("http_status") == 429 for row in rows),
        "pre_content_rejection_rate": counts["rejected"] / len(rows),
    }


class Refused(ValueError):
    """Closed refusal code from a session boundary."""


def require(condition, code):
    if not condition:
        raise Refused(code)


def verify(plan):
    for name, expected in plan["bindings"].items():
        require(sha((ROOT / name).read_bytes()) == expected, "input_hash")
    require(
        [(arm["precision"], arm["max_num_seqs"]) for arm in plan["arms"]]
        == [("bf16", 16), ("bf16", 32), ("bf16", 64), ("fp8", 32)],
        "arms",
    )
    require(plan["rates"] == [1, 3, 6, 12], "rates")
    per_attempt = sum(plan["gpu_deadlines_s"].values())
    require(per_attempt <= plan["gpu_attempt_limit_s"], "time_envelope")
    require(plan["forecast_usd_with_retry"] <= plan["cap_usd"] == 25, "cost_envelope")


def execute(plan, cases, backend):
    """Drive every registered boundary. Provisioning and engine work are ports."""
    verify(plan)
    order = []
    result = {"arms": [], "sequence": order}
    applied = False
    try:
        readback = backend.preflight()
        require(readback["offering"], "capacity_unavailable")
        require(
            readback["running_vcpus"] + 4 <= readback["quota_vcpus"], "busy_gpu_quota"
        )
        order.append("preflight")
        # Apply may fail after creating resources. Even a failed call owns cleanup.
        applied = True
        backend.apply_once()
        order.append("apply")
        require(backend.stage(plan["model"]), "model_pin")
        order.append("stage")
        for arm in plan["arms"]:
            try:
                started = backend.start(arm)
                require(0 < started <= plan["startup_limit_s"], "engine_start")
                order.append("start:" + arm["name"])
                backend.warm(arm)
                order.append("warm:" + arm["name"])
                value = {"name": arm["name"], "startup_s": started, "levels": []}
                result["arms"].append(value)
                for rate in plan["rates"]:
                    rows, elapsed, gauges = backend.window(arm, rate, plan["window_s"])
                    require(len(rows) == rate * plan["window_s"], "offer_accounting")
                    value["levels"].append(
                        {"rate": rate, **summarize(rows, elapsed), "gauges": gauges}
                    )
                    order.append(f"window:{arm['name']}:{rate}")
                if arm["quality"]:
                    answers = backend.quality(cases, arm)
                    require(len(answers) == len(cases), "quality_count")
                    scored = [
                        score(text, answer)
                        for text, (_, answer) in zip(answers, cases, strict=True)
                    ]
                    value["quality"] = {
                        "total": len(cases),
                        "exact": sum(scored),
                        "missing": sum(not text for text in answers),
                        "exact_by_item": scored,
                    }
                    order.append("quality:" + arm["name"])
            finally:
                backend.stop()
        result["complete"] = True
        bf16, fp8 = [
            arm["quality"]["exact_by_item"]
            for arm in result["arms"]
            if "quality" in arm
        ]
        paired = Counter(zip(bf16, fp8, strict=True))
        result["quality_pairs"] = {
            "both_exact": paired[True, True],
            "bf16_only": paired[True, False],
            "fp8_only": paired[False, True],
            "neither_exact": paired[False, False],
        }
    except Refused as exc:
        result.update(complete=False, refusal=str(exc))
    finally:
        if applied:
            try:
                result["retrieval_verified"] = backend.freeze(result)
                if not result["retrieval_verified"]:
                    result.update(complete=False, refusal="receipt_retrieval")
                order.append("freeze")
            finally:
                backend.destroy()
                order.append("destroy")
                result["inventory"] = backend.inventory()
                order.append("inventory")
                require(not any(result["inventory"].values()), "teardown_unverified")
    return result


def event(value):
    return b"data: " + json.dumps(value).encode() + b"\n\n"


def stream_fixture():
    content = event(
        {"choices": [{"index": 0, "delta": {"content": "one"}, "finish_reason": None}]}
    )
    finish = event({"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]})
    usage = event(
        {
            "choices": [],
            "usage": {
                "prompt_tokens": 1024,
                "completion_tokens": 2,
                "total_tokens": 1026,
                "count_source": "runtime_usage",
            },
        }
    )
    ticks = iter((200_000_000, 270_000_000, 275_000_000, 276_000_000, 277_000_000))
    row = observe_stream(
        [content, content, finish, usage, b"data: [DONE]\n\n"],
        cancel_assigned=False,
        close=lambda: None,
        clock_ns=lambda: next(ticks),
        details=True,
    )
    require(row["complete"] and row["completion_tokens"] == 2, "fixture_stream")
    return {
        "outcome": "completed",
        "http_status": 200,
        "completion_tokens": row["completion_tokens"],
        "ttft_ms": row["first_content_monotonic_ns"] / 1e6,
        "tpot_ms": (row["done_ns"] - row["first_content_monotonic_ns"])
        / 1e6
        / (row["completion_tokens"] - 1),
    }


class FakeBackend:
    """Closed synthetic responses. Times and scores are fixture values."""

    def __init__(self, fault=None):
        self.fault = fault
        self.applies = 0
        self.owns_stack = False
        self.active = False
        self.frozen_sha256 = None
        self.completed = stream_fixture()

    def preflight(self):
        return {
            "offering": self.fault != "capacity",
            "running_vcpus": 8 if self.fault == "quota" else 0,
            "quota_vcpus": 8,
        }

    def apply_once(self):
        require(self.applies == 0, "duplicate_apply")
        self.applies += 1
        self.owns_stack = True

    def stage(self, model):
        return self.owns_stack and len(model["files"]) == 11

    def start(self, arm):
        require(not self.active and self.owns_stack, "engine_overlap")
        self.active = True
        return 601 if self.fault == "startup" else 280

    def warm(self, arm):
        require(self.active, "engine_unavailable")

    def window(self, arm, rate, seconds):
        seats = arm["max_num_seqs"]
        offered = rate * seconds
        rejected = offered // 3 if rate == 12 else 0
        rows = [self.completed] * (offered - rejected) + [
            {"outcome": "rejected", "http_status": 429}
        ] * rejected
        return (
            rows,
            seconds + 2,
            {
                "peak_running": min(seats, 4 * rate),
                "peak_waiting": 4 if rejected else 0,
                "peak_kv_fraction": 0.6,
                "kv_blocks": 4000,
                "peak_memory_mib": 21000,
            },
        )

    def quality(self, cases, arm):
        # Exact, wrong, and missing final answers exercise the shared scorer.
        return [
            f"FINAL: {answer:f}"
            if index < 98
            else ("FINAL: invalid" if index == 98 else "")
            for index, (_, answer) in enumerate(cases)
        ]

    def stop(self):
        self.active = False

    def freeze(self, result):
        frozen = json.dumps(result, sort_keys=True).encode()
        self.frozen_sha256 = sha(frozen)
        return sha(bytes(frozen)) == self.frozen_sha256 and self.fault != "retrieve"

    def destroy(self):
        require(not self.active, "active_engine")
        self.owns_stack = False

    def inventory(self):
        return {"owned_stack": int(self.owns_stack)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--quality", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    raw = args.plan.read_bytes()
    plan = json.loads(raw)
    cases = quality_cases(args.quality, plan["quality"])
    observed = {}
    for scenario in ("success", "capacity", "quota", "startup", "retrieve"):
        backend = FakeBackend(None if scenario == "success" else scenario)
        result = execute(plan, cases, backend)
        observed[scenario] = {
            **result,
            "fake_apply_calls": backend.applies,
            "fake_frozen_sha256": backend.frozen_sha256,
        }
    arms = observed["success"]["arms"]
    require(
        len(arms) == 4 and all(len(arm["levels"]) == 4 for arm in arms),
        "fixture_matrix",
    )
    require(
        [arm["quality"]["exact"] for arm in arms if "quality" in arm] == [98, 98],
        "fixture_quality",
    )
    for scenario, reason in (
        ("capacity", "capacity_unavailable"),
        ("quota", "busy_gpu_quota"),
    ):
        require(
            observed[scenario]["refusal"] == reason
            and observed[scenario]["fake_apply_calls"] == 0,
            "fixture_preflight_refusal",
        )
    require(observed["startup"]["refusal"] == "engine_start", "fixture_start_refusal")
    require(not observed["retrieve"]["retrieval_verified"], "fixture_retrieve_refusal")
    require(
        all(
            observed[key]["inventory"] == {"owned_stack": 0}
            for key in ("success", "startup", "retrieve")
        ),
        "fixture_destroy",
    )
    args.output.write_text(
        json.dumps(
            {"plan_sha256": sha(raw), "backend": "synthetic", "scenarios": observed},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )


if __name__ == "__main__":
    main()
