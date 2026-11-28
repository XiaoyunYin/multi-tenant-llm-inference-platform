"""Deadline-bounded native SSE client for the INF-061 five-start experiment."""

import concurrent.futures as futures
import hashlib
import http.client
import json
import threading
import time
from collections import Counter
from pathlib import Path

from inference_platform.inf060_streaming_probe import (
    MAX_STREAM_BYTES,
    _validated_frames,
    observe_stream,
)

from rehearse_inf061_l4 import quality_cases, quantiles, score

MODEL = "Qwen/Qwen2.5-7B-Instruct"
DENIALS = {"tenant_concurrency_limit", "system_capacity", "tenant_rate_limit"}


def offer(
    origin, credential, prompt, cap, deadline, *, quality=False, request_id=False
):
    connection = http.client.HTTPConnection(
        "127.0.0.1", origin, timeout=max(0.001, deadline - time.monotonic())
    )
    start = time.perf_counter_ns()
    row = {"outcome": "transport_error"}
    chunks = []
    try:
        if deadline <= time.monotonic():
            return {"outcome": "missed_offer"}, None
        connection.request(
            "POST",
            "/v1/chat/completions",
            json.dumps(
                {
                    "model": MODEL,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": cap,
                    "temperature": 0,
                    "top_p": 1,
                    "stream": True,
                }
            ),
            {
                "Content-Type": "application/json",
                "Authorization": "Bearer " + credential,
            },
        )
        response = connection.getresponse()
        row["http_status"] = response.status
        if request_id:
            row["request_id"] = response.getheader("X-Request-ID")
        if response.status != 200:
            code = "other"
            if response.status == 429:
                try:
                    found = json.loads(response.read(8192))["error"]["code"]
                    if isinstance(found, str) and found in DENIALS:
                        code = found
                except (ValueError, KeyError, TypeError):
                    pass
            return {**row, "outcome": "rejected", "gateway_code": code}, None

        def reads():
            size = 0
            while True:
                left = deadline - time.monotonic()
                if left <= 0:
                    return
                if connection.sock is not None:
                    connection.sock.settimeout(left)
                data = response.read1(65536)
                if not data:
                    return
                size += len(data)
                if quality and size <= MAX_STREAM_BYTES:
                    chunks.append(data)
                yield data

        observed = observe_stream(
            reads(), cancel_assigned=False, close=connection.close, details=True
        )
        first, done = observed["first_content_monotonic_ns"], observed["done_ns"]
        if first is not None:
            row["ttft_s"] = (first - start) / 1e9
        if not observed["complete"]:
            return {
                **row,
                "outcome": "partial" if first is not None else "failed",
            }, None
        tokens = observed["completion_tokens"]
        row.update(
            outcome="completed",
            finish=observed["finish_reason"],
            completion_tokens=tokens,
            completed_s=(done - start) / 1e9,
        )
        if tokens > 1:
            row["tpot_s"] = (done - first) / (tokens - 1) / 1e9
        text = None
        if quality:
            frames = list(_validated_frames(b"".join(chunks)))
            text = "".join(
                event["choices"][0]["delta"].get("content") or ""
                for event in reversed(frames)
                if event["choices"]
            )
        return row, text
    except (OSError, http.client.HTTPException):
        return row, None
    finally:
        connection.close()


def labeled_prompt(seed, index):
    return hashlib.sha256(f"{seed}:{index}".encode()).hexdigest()[:24]


def render_exact(tokenizer, seed, count):
    prefix = "Synthetic trace " + labeled_prompt(seed, 0) + ". Continue counting:"

    def tokens(text):
        return len(
            tokenizer.apply_chat_template(
                [{"role": "user", "content": text}],
                tokenize=True,
                add_generation_prompt=True,
                return_dict=False,
            )
        )

    estimate = count - tokens(prefix)
    for offset in (0, -1, 1, -2, 2, -3, 3, -4, 4):
        text = prefix + " one" * (estimate + offset)
        if tokens(text) == count:
            return text
    raise ValueError("inf061:rendered_prompt_length")


def run_window(
    send, tasks, *, window_s, drain_s, concurrency=128, open_loop=True, start=None
):
    """One row per offered slot, including work that missed its dispatch bound."""
    start = time.monotonic() if start is None else start
    offer_end = start + window_s
    deadline = offer_end + drain_s
    results = [{"outcome": "missed_offer"} for _ in tasks]
    pending = {}

    def collect(done):
        for future in done:
            index = pending.pop(future)
            results[index] = future.result()

    with futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        for index, (offset, payload) in enumerate(tasks):
            if open_loop:
                time.sleep(max(0, start + offset - time.monotonic()))
                collect([future for future in pending if future.done()])
            elif len(pending) >= concurrency:
                done, _ = futures.wait(
                    pending,
                    timeout=max(0, offer_end - time.monotonic()),
                    return_when=futures.FIRST_COMPLETED,
                )
                collect(done)
            if (
                time.monotonic() >= offer_end
                or len(pending) >= concurrency
                or (open_loop and time.monotonic() - start - offset > 0.1)
            ):
                continue
            task = pool.submit(send, payload, deadline)
            pending[task] = index
        collect(futures.as_completed(list(pending)))
    return results


def tally(rows, seconds, *, slo=None):
    counts = Counter(row["outcome"] for row in rows)
    completed = [row for row in rows if row["outcome"] == "completed"]
    output = sum(row["completion_tokens"] for row in completed)
    result = {
        "scheduled": len(rows),
        "outcomes": dict(counts),
        "completed_per_s": len(completed) / seconds,
        "output_tokens_per_s": output / seconds,
        "completed_output_tokens": output,
        "ttft_s": quantiles([row["ttft_s"] for row in rows if "ttft_s" in row]),
        "tpot_s": quantiles([row["tpot_s"] for row in completed if "tpot_s" in row]),
        "rejections": dict(
            Counter(row["gateway_code"] for row in rows if "gateway_code" in row)
        ),
        "pre_content_rejection_rate": counts["rejected"] / len(rows),
        "http_429": sum(row.get("http_status") == 429 for row in rows),
    }
    if slo:
        met = sum(
            row["ttft_s"] <= slo[0] and row["completed_s"] <= slo[1]
            for row in completed
        )
        result.update(slo_met=met, slo_met_per_offer=met / len(rows))
    return result


def run_quality(send, cases, suffix, allowance, concurrency):
    def grade(payload, deadline):
        question, answer = payload
        row, text = send(question + suffix, deadline)
        if row["outcome"] == "completed":
            if row["finish"] == "length":
                row["score"] = "truncated"
            elif score(text, answer):
                row["score"] = "exact"
            else:
                from rehearse_inf061_l4 import FINAL_LINE

                last = text.strip().splitlines()
                row["score"] = (
                    "wrong" if last and FINAL_LINE.fullmatch(last[-1]) else "invalid"
                )
        else:
            row["score"] = "failed"
        return row

    rows = run_window(
        grade,
        [(0, case) for case in cases],
        window_s=allowance,
        drain_s=0,
        concurrency=concurrency,
        open_loop=False,
    )
    return [row.get("score", "unreached") for row in rows]


def quality_dataset(plan, root):
    path = Path(root) / "quality.jsonl"
    return quality_cases(path, plan["quality"])


class Samples:
    """Sample fixed gauges during a cell and preserve continuity evidence."""

    def __init__(self, scrape, interval=0.5):
        self.scrape, self.interval = scrape, interval
        self.stop = threading.Event()
        self.rows = []
        self.thread = threading.Thread(target=self.sample)

    def sample(self):
        while not self.stop.is_set():
            stamp = time.monotonic()
            self.rows.append(self.scrape())
            self.stop.wait(max(0, self.interval - (time.monotonic() - stamp)))

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.stop.set()
        self.thread.join()

    def summary(self):
        rows = [row for row in self.rows if row is not None]
        return {
            "samples": len(rows),
            "missed": len(self.rows) - len(rows),
            "max_running": max((r["running"] for r in rows), default=None),
            "max_waiting": max((r["waiting"] for r in rows), default=None),
            "max_kv": max((r["kv"] for r in rows), default=None),
            "max_gpu_memory_mib": max(
                (r["gpu_memory_mib"] for r in rows), default=None
            ),
            "preemptions_delta": rows[-1]["preemptions"] - rows[0]["preemptions"]
            if len(rows) > 1
            else None,
            "running_and_waiting": max(
                (r["running"] for r in rows if r["waiting"] > 0), default=0
            ),
        }
