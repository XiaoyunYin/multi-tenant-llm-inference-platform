"""Bounded INF-054 SSE client, running in the DEC-100 in-cluster Job."""

import argparse
import hashlib
import http.client
import json
import ssl
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from pathlib import Path

from .inf060_streaming_probe import observe_stream

LIMIT = 32 * 1024**2
OFFER_WINDOW_S = 960
DRAIN_S = 120
PER_REQUEST_S = 120
LONG_PROBE_CAP = 800
LONG_PROBE_STEP_S = 5
LONG_PROBE_STOP = Path("/results/downscale-stop")
LONG_PROBE_PROMPT = (
    "scale-down live stream: Write a numbered list of 500 integers starting at 1. "
    "Write every integer on a separate line with no omissions and keep going."
)
DENIALS = frozenset(("tenant_concurrency_limit", "tenant_rate_limit", "system_capacity"))


def offer(port, tls, token, model, prompt, cap, end):
    started = time.monotonic()
    end = min(end, started + PER_REQUEST_S)
    result = {"outcome": "transport_error", "dispatch": started}
    connection = http.client.HTTPSConnection(
        "streaming-ingress", port, context=tls, timeout=max(0.001, end - started)
    )
    try:
        connection.request(
            "POST",
            "/v1/chat/completions",
            json.dumps(
                {
                    "model": model,
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": True,
                    "max_tokens": cap,
                    "temperature": 0,
                }
            ),
            {"Authorization": "Bearer " + token, "Content-Type": "application/json"},
        )
        transport = connection.sock
        response = connection.getresponse()
        result["http_status"] = response.status
        result["uid"] = response.getheader("X-Inf060-Backend-Pod-Uid")
        if response.status != 200:
            result["outcome"] = "rejected"
            if response.status == 429:
                try:
                    code = json.loads(response.read(8192))["error"]["code"]
                    result["gateway_code"] = code if code in DENIALS else "other"
                except (ValueError, TypeError, KeyError):
                    result["gateway_code"] = "other"
            return result

        def chunks():
            observed = 0
            while (left := end - time.monotonic()) > 0 and observed < 2 * 1024**2:
                if transport is not None:
                    transport.settimeout(left)
                try:
                    chunk = response.read1(65536)
                except (OSError, http.client.HTTPException):
                    break
                if not chunk:
                    break
                observed += len(chunk)
                yield chunk

        stream = observe_stream(
            chunks(),
            cancel_assigned=False,
            close=connection.close,
            details=True,
            clock_ns=time.monotonic_ns,
        )
        first = stream["first_content_monotonic_ns"]
        if first is not None:
            result["ttft_s"] = first / 1e9 - started
        result["outcome"] = "partial" if first else "failed"
        if stream["complete"]:
            result.update(
                outcome="completed",
                completion_tokens=stream["completion_tokens"],
                completed_s=stream["done_ns"] / 1e9 - started,
            )
        return result
    except (OSError, http.client.HTTPException):
        return result
    finally:
        result["closed_s"] = time.monotonic() - started
        connection.close()


def schedule(rows, request, *, duration, drain, end_epoch, stop=None):
    """Replay the ordered monotonic offsets with bounded concurrency and misses."""
    start = time.monotonic()
    start_epoch = time.time()
    end = start + duration + drain
    if start_epoch + duration + drain > end_epoch:
        raise TimeoutError("inf054_client_window_budget")
    outputs = []
    pending = {}
    with ThreadPoolExecutor(max_workers=128) as pool:
        for index, row in enumerate(rows):
            when = start + row["offset_ns"] / 1e9
            time.sleep(max(0, when - time.monotonic()))
            if stop is not None and stop.exists():
                break
            outputs.append({"outcome": "missed_offer"})
            for done in [future for future in pending if future.done()]:
                outputs[pending.pop(done)] = done.result()
            if len(pending) < 128 and time.monotonic() - when <= 0.1:
                future = pool.submit(request, row, end)
                pending[future] = index
        while pending:
            done, _ = wait(pending, return_when=FIRST_COMPLETED)
            for future in done:
                outputs[pending.pop(future)] = future.result()
    for row in outputs:
        if "dispatch" in row:
            row["dispatch_s"] = row.pop("dispatch") - start
    return {"start_epoch": start_epoch, "rows": outputs}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tape", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--deadline", type=float, required=True)
    parser.add_argument(
        "--mode",
        choices=("readiness", "window", "downscale", "gpu-downscale"),
        default="window",
    )
    parser.add_argument("--rehearsal-burst-seconds", type=int)
    args = parser.parse_args()
    with args.tape.open("rb") as source:
        raw = source.read(LIMIT + 1)
    if len(raw) > LIMIT or hashlib.sha256(raw).hexdigest() != args.sha256:
        raise ValueError("inf054_client_tape_hash")
    rows = [json.loads(line) for line in raw.splitlines()]
    if len(rows) != 2760 or any(not 0 <= row["offset_ns"] < OFFER_WINDOW_S * 10**9 for row in rows):
        raise ValueError("inf054_client_tape_schedule")
    credentials = json.loads(Path("/credential/client.json").read_bytes())
    tls = ssl.create_default_context(cafile="/ca/tls.crt")

    def request(row, end):
        return offer(
            8443,
            tls,
            credentials["token"],
            credentials["model"],
            row["prompt"],
            row["output_cap"],
            end,
        )

    if args.mode == "readiness":
        left = args.deadline - time.time()
        if left <= 0:
            raise TimeoutError("inf054_readiness_deadline")
        result = {
            "rows": [
                request({"prompt": "Reply with one.", "output_cap": 1}, time.monotonic() + left)
            ]
        }
    else:
        duration = OFFER_WINDOW_S
        if args.rehearsal_burst_seconds is not None:
            if args.mode != "window" or not 0 < args.rehearsal_burst_seconds < 900:
                raise ValueError("inf054_rehearsal_burst")
            duration = 60 + args.rehearsal_burst_seconds
            rows = [row for row in rows if row["offset_ns"] < duration * 10**9]
        if args.mode == "downscale":
            rows = [
                {
                    "offset_ns": index * 5 * 10**9,
                    "output_cap": 64,
                    "prompt": f"scale-down live stream {index}",
                }
                for index in range(46)
            ]
            duration = 230
        stop = None
        if args.mode == "gpu-downscale":
            duration = int(args.deadline - time.time()) - DRAIN_S - 1
            if duration < LONG_PROBE_STEP_S:
                raise TimeoutError("inf054_gpu_downscale_budget")
            rows = [
                {
                    "offset_ns": offset * 10**9,
                    "output_cap": LONG_PROBE_CAP,
                    "prompt": LONG_PROBE_PROMPT,
                }
                for offset in range(0, duration, LONG_PROBE_STEP_S)
            ]
            stop = LONG_PROBE_STOP
        result = schedule(
            rows,
            request,
            duration=duration,
            drain=DRAIN_S,
            end_epoch=args.deadline,
            stop=stop,
        )
    print(json.dumps(result, separators=(",", ":"), allow_nan=False))


if __name__ == "__main__":
    main()
