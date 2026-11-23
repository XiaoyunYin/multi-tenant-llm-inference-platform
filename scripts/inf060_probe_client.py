"""Loopback TLS requests and privacy-filtered observations for INF-060."""

import http.client
import json
import math
import queue
import re
import socket
import ssl
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.request import urlopen

from inference_platform.inf060_streaming_probe import (
    ABORT_LINE,
    SentCancel,
    join_abort_rows,
    observe_stream,
)

from inf060_probe_spec import MODEL, check

LOG_BYTES = 4 * 1024**2
FORMAT = re.compile(r"(?:\(APIServer pid=\d+\) )?(\d{1,12}\.\d{6}) INFO \[")
PROMPT_FIELD = re.compile(
    r"""(?i)\b(?:prompt(?:_text)?|prompt_token_ids|token_ids)["']?\s*[:=]\s*"""
    r"""(?!(?:None|null|\[\]|""|'')(?=\s|,|}|$))\S"""
)
TOKEN_FIELD = re.compile(
    r"""(?i)\b(?:prompt_token_ids|token_ids)["']?\s*[:=]\s*"""
    r"""(?!(?:None|null|\[\]|""|'')(?=\s|,|}|$))\S"""
)
STOCK = re.compile(r"(?:\(APIServer pid=\d+\) )?INFO \d\d-\d\d \d\d:\d\d:\d\d ")


def suppress(raw, canaries):
    check(len(raw) <= LOG_BYTES, "bounded_engine_log")
    check(not raw or raw.endswith(b"\n"), "truncated_engine_log")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeError:
        raise ValueError("inf060:engine_log_encoding") from None
    counts = {
        "bytes": len(raw),
        "lines": len(lines),
        "canary_lines": sum(
            any(canary in line for canary in canaries) for line in lines
        ),
        "prompt_field_lines": sum(
            PROMPT_FIELD.search(line) is not None for line in lines
        ),
        "token_field_lines": sum(
            TOKEN_FIELD.search(line) is not None for line in lines
        ),
        "stock_timestamp_lines": sum(STOCK.match(line) is not None for line in lines),
    }
    no_payload = not (counts["canary_lines"] or counts["prompt_field_lines"])
    return (lines if no_payload else None), {
        **counts,
        "no_payload": no_payload,
        "status": "PASS" if no_payload else "REFUSED",
    }


def clock_exchange(argv, deadline, *, env=None):
    exchanges = []
    responses = queue.Queue()

    def seconds_left():
        left = min(10, deadline - time.time())
        check(left > 0, "clock_exchange")
        return left

    def read_lines(stream):
        for _ in range(12):
            line = stream.readline(128)
            responses.put((time.monotonic_ns(), line))
            if not line:
                return

    def receive_line():
        try:
            instant, line = responses.get(timeout=seconds_left())
        except queue.Empty:
            raise TimeoutError("inf060:clock_exchange") from None
        check(line.endswith(b"\n"), "clock_exchange")
        return instant, line

    seconds_left()
    with subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        bufsize=0,
        env=env,
    ) as child:
        reader = threading.Thread(target=read_lines, args=(child.stdout,), daemon=True)
        reader.start()
        try:
            check(receive_line()[1] == b"ready\n", "clock_exchange")
            for _ in range(10):
                seconds_left()
                send = time.monotonic_ns()
                child.stdin.write(b"?\n")
                receive, line = receive_line()
                e2, e3 = json.loads(line)
                lo, hi = e3 - receive, e2 - send
                check(
                    type(e2) is int and type(e3) is int and e2 == e3 and lo <= hi,
                    "clock_exchange",
                )
                exchanges.append(
                    {
                        "c1": send,
                        "c4": receive,
                        "e2": e2,
                        "e3": e3,
                        "lo": lo,
                        "hi": hi,
                        "width": hi - lo,
                    }
                )
            check(child.wait(timeout=seconds_left()) == 0, "clock_exchange")
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
            reader.join(timeout=1)
    return exchanges


def bracket(before, after, observations):
    first, last = (min(rows, key=lambda row: row["width"]) for rows in (before, after))
    offsets = [row["wall_ns"] - row["mono_ns"] for row in observations]
    variation = max(offsets) - min(offsets)
    check(variation <= 5_000_000, "clock_discontinuity")
    expansion = variation + max(row["sample_width_ns"] for row in observations)
    check(
        first["lo"] <= last["hi"] + expansion and last["lo"] <= first["hi"] + expansion,
        "clock_bracket_inconsistent",
    )
    lo = min(first["lo"], last["lo"]) - expansion
    hi = max(first["hi"], last["hi"]) + expansion
    return {
        "before": before,
        "after": after,
        "offset_lo_ns": lo,
        "offset_hi_ns": hi,
        "sampled_offset_variation_ns": variation,
        "stamp_resolution_ns": 1000,
        "minimum_interval_width_ns": hi - lo + 1000,
    }


def request(row, content, credential, context, deadline):
    start = time.monotonic_ns()
    verdict = {
        "alias": row["alias"],
        "cancel_assigned": row["cancel"],
        "outcome": "failed",
    }
    conn = http.client.HTTPSConnection("localhost", 8443, context=context, timeout=30)
    response = None
    try:
        payload = {
            "model": MODEL,
            "messages": [{"role": "user", "content": content}],
            "stream": True,
            "temperature": 0,
            "max_tokens": 32,
        }
        conn.request(
            "POST",
            "/v1/chat/completions",
            body=json.dumps(payload),
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer " + credential,
            },
        )
        transport = conn.sock
        response = conn.getresponse()
        verdict["status"] = response.status
        if response.status != 200:
            verdict["outcome"] = "rejected"
            return verdict, None
        check(
            response.getheader("Content-Type", "").startswith("text/event-stream"),
            "content_type",
        )
        identifier = response.getheader("X-Request-ID")

        def chunks():
            while True:
                remaining = deadline - time.time()
                if remaining <= 0:
                    raise TimeoutError
                if transport is not None and transport.fileno() >= 0:
                    transport.settimeout(remaining)
                chunk = response.read1(65536)
                if not chunk:
                    return
                yield chunk

        def close():
            if transport is not None and transport.fileno() >= 0:
                try:
                    transport.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            response.close()
            conn.close()

        observed = observe_stream(
            chunks(),
            cancel_assigned=row["cancel"],
            close=close,
            clock_ns=time.monotonic_ns,
        )
        close_at = observed["cancel_close_monotonic_ns"]
        first_content = observed.pop("first_content_monotonic_ns")
        verdict.update(observed)
        verdict.update(
            outcome="complete"
            if observed["complete"]
            else "cancelled"
            if close_at is not None
            else "failed",
            ttft_ns=None if first_content is None else first_content - start,
            elapsed_ns=time.monotonic_ns() - start,
        )
        return verdict, (identifier, close_at) if close_at is not None else None
    except (OSError, http.client.HTTPException, ValueError):
        verdict.update(
            failure="transport_or_schema", elapsed_ns=time.monotonic_ns() - start
        )
        return verdict, None
    finally:
        if response is not None:
            response.close()
        conn.close()


def gauges():
    a = time.monotonic_ns()
    wall = time.time_ns()
    b = time.monotonic_ns()
    values = {}
    try:
        with urlopen("http://127.0.0.1:8000/metrics", timeout=0.12) as response:
            raw = response.read(512 * 1024 + 1)
        check(len(raw) <= 512 * 1024, "metrics_bound")
        for line in raw.decode().splitlines():
            for name in ("vllm:num_requests_running", "vllm:kv_cache_usage_perc"):
                if line.startswith((name + " ", name + "{")):
                    value = float(line.split()[-1])
                    if math.isfinite(value) and value >= 0:
                        values[name] = values.get(name, 0) + value
    except (OSError, ValueError):
        values = {}
    return {
        "mono_ns": (a + b) // 2,
        "wall_ns": wall,
        "sample_width_ns": b - a,
        "values": values,
    }


def run_arm(manifest, prompts, credential, cert, deadline):
    ctx = ssl.create_default_context(cafile=cert)
    futures, missed, samples = {}, {}, []
    start_wall, start_mono = time.time(), time.monotonic()
    cpu = time.process_time_ns()
    check(start_wall + 179 < deadline, "arm_reserve")
    with ThreadPoolExecutor(max_workers=manifest["in_flight_max"]) as pool:
        for index, row in enumerate(manifest["slots"]):
            due = start_mono + index
            while time.monotonic() < due:
                samples.append(gauges())
                time.sleep(min(0.25, max(0, due - time.monotonic())))
            if (
                time.monotonic() - due > 0.25
                or sum(not f.done() for f in futures.values()) >= 64
            ):
                missed[row["alias"]] = (
                    {
                        "alias": row["alias"],
                        "outcome": "missed_offer",
                        "cancel_assigned": row["cancel"],
                    },
                    None,
                )
            else:
                futures[row["alias"]] = pool.submit(
                    request,
                    row,
                    prompts[row["alias"]],
                    credential,
                    ctx,
                    min(deadline, time.time() + 30),
                )
        cutoff = min(start_wall + 180, deadline)
        while any(not f.done() for f in futures.values()) and time.time() < cutoff:
            samples.append(gauges())
            time.sleep(0.25)
        check(all(f.done() for f in futures.values()), "unresolved_occupied_slots")
    return (
        {**missed, **{alias: f.result() for alias, f in futures.items()}},
        samples,
        time.process_time_ns() - cpu,
    )


def join(generation, events, raw_lines, clock):
    sent = [
        SentCancel(alias, generation, extra[0], extra[1])
        for alias, (_, extra) in sorted(events.items())
        if extra is not None
    ]
    joined, orphans = join_abort_rows(sent, {generation: raw_lines})
    lo, hi = clock["offset_lo_ns"], clock["offset_hi_ns"]
    for row in joined:
        stamp = row["abort_log_stamp"]
        if stamp is not None:
            sec, fraction = stamp.split(".")
            epoch_ns = int(sec) * 10**9 + int(fraction) * 1000
            close = row["cancel_close_monotonic_ns"]
            interval = [epoch_ns - 500 - hi - close, epoch_ns + 500 - lo - close]
            row["timing_interval_ns"] = interval if interval[0] >= 0 else None
            row["timing_status"] = (
                "bounded" if interval[0] >= 0 else "ordering_unresolved"
            )
    return {
        "rows": joined,
        "orphan_abort_count": orphans[generation],
        "sent": len(sent),
        "identity_joins": sum(row["abort_status"] == "joined" for row in joined),
        "timing_joins": sum(row.get("timing_status") == "bounded" for row in joined),
        "frontend_abort_lines": sum(
            ABORT_LINE.fullmatch(line) is not None for line in raw_lines
        ),
        "stock_abort_matches": sum(
            STOCK.match(line) is not None and ABORT_LINE.fullmatch(line) is not None
            for line in raw_lines
        ),
    }


def latency_summary(measured):
    complete = [row for row in measured if row["outcome"] == "complete"]
    series = {
        "completed_ttft_ns": [
            r["ttft_ns"] for r in complete if r["ttft_ns"] is not None
        ],
        "completed_elapsed_ns": [r["elapsed_ns"] for r in complete],
        "eligible_token_itl_ns": [
            value for row in complete for value in row["token_itl_ns"]
        ],
    }
    return {
        key: {
            "n": len(values),
            **{
                label: sorted(values)[math.ceil(len(values) * quantile) - 1]
                if len(values) >= sample_floor
                else "insufficient"
                for label, quantile, sample_floor in (
                    ("p50", 0.5, 40),
                    ("p95", 0.95, 400),
                    ("p99", 0.99, 2000),
                )
            },
        }
        for key, values in series.items()
    }
