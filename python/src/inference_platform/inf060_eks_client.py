"""In-cluster CPU Job for streaming load, pod clocks and resource observation."""

import argparse
import http.client
import json
import os
import resource
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.request import Request, urlopen

from .eks_deployment import MODEL
from .inf060_eks_clock import ClockRefusal, ClockStream, bracket, wall_mapping
from .inf060_eks_schedule import (
    DRAIN_SECONDS,
    REQUEST_CAP_SECONDS,
    SMOKE_SECONDS,
    WARMUP_SECONDS,
    WINDOW_SECONDS,
    prompts,
    run_offers,
    schedule,
)
from .inf060_streaming_probe import GATEWAY_REQUEST_ID, observe_stream
from .stage_c_tokenizer import pinned_tokenizer

ROOT = Path("/results")
JOURNAL_LIMIT = 48 * 1024**2
API = "https://kubernetes.default.svc"
IDENTITY = Path("/var/run/secrets/kubernetes.io/serviceaccount")
GAUGES = {
    "vllm:num_requests_running": "running",
    "vllm:kv_cache_usage_perc": "kv_fraction",
    "process_cpu_seconds_total": "frontend_cpu_s",
    "vllm:request_queue_time_seconds_count": "queue_count",
    "vllm:request_queue_time_seconds_sum": "queue_sum_s",
    "vllm:request_prefill_time_seconds_count": "prefill_count",
    "vllm:request_prefill_time_seconds_sum": "prefill_sum_s",
    "vllm:request_decode_time_seconds_count": "decode_count",
    "vllm:request_decode_time_seconds_sum": "decode_sum_s",
}


def generation(pod):
    statuses = {row["name"]: row for row in pod["status"]["containerStatuses"]}
    return [
        pod["metadata"]["uid"],
        *[
            [statuses[name]["containerID"], statuses[name]["restartCount"]]
            for name in ("vllm", "clock-server")
        ],
    ]


def pods(namespace):
    token = (IDENTITY / "token").read_text().strip()
    context = ssl.create_default_context(cafile=str(IDENTITY / "ca.crt"))
    query = Request(
        f"{API}/api/v1/namespaces/{namespace}/pods?labelSelector=app%3Dvllm",
        headers={"Authorization": "Bearer " + token},
    )
    with urlopen(query, context=context, timeout=3) as response:
        value = json.load(response)
    return {
        pod["metadata"]["name"]: {"ip": pod["status"]["podIP"], "identity": generation(pod)}
        for pod in value["items"]
    }


def scrape(ip, timeout):
    with urlopen(f"http://{ip}:8000/metrics", timeout=timeout) as response:
        raw = response.read(2 * 1024**2 + 1)
    if len(raw) > 2 * 1024**2:
        raise ValueError("streaming_metrics_limit")
    values = {}
    for line in raw.decode().splitlines():
        if line.startswith("#") or not line:
            continue
        key, value, *_ = line.split()
        metric = GAUGES.get(key.split("{", 1)[0])
        if metric:
            number = float(value)
            if not 0 <= number < float("inf"):
                raise ValueError("streaming_metrics_value")
            values[metric] = values.get(metric, 0) + number
    if not {"running", "kv_fraction"} <= values.keys() or values["kv_fraction"] > 1:
        raise ValueError("streaming_metrics_missing")
    return values


def observe_replica(replica, stop):
    rows = []
    target = time.monotonic()
    while not stop.is_set():
        row = {
            "monotonic_ns": time.monotonic_ns(),
            "status": "sample",
            "wall_mapping": wall_mapping(),
        }
        try:
            row.update(scrape(replica["ip"], 0.2))
        except (OSError, ValueError):
            row["status"] = "unavailable"
        rows.append(row)
        target = max(time.monotonic(), target + 0.25)
        stop.wait(max(0, target - time.monotonic()))
    return rows


def attempt(row, messages, secret, host, context, deadline_ns, backends):
    now = time.monotonic_ns
    dispatch = now()
    final_ns = min(deadline_ns, dispatch + REQUEST_CAP_SECONDS * 10**9)
    connection = http.client.HTTPSConnection(host, 8443, context=context)
    observation = {
        **row,
        "dispatch_ns": dispatch,
        "deadline_ns": final_ns,
        "outcome": "failed",
        "queue_status": "unavailable_per_request",
    }
    response = None

    def timeout():
        remaining = (final_ns - now()) / 10**9
        if remaining <= 0:
            raise TimeoutError("streaming_request_deadline")
        return remaining

    try:
        connection.timeout = timeout()
        connection.request(
            "POST",
            "/v1/chat/completions",
            json.dumps(
                {
                    "model": MODEL,
                    "messages": messages,
                    "stream": True,
                    "temperature": 0,
                    "max_tokens": row["output_cap"],
                }
            ),
            {
                "Authorization": "Bearer " + secret,
                "Content-Type": "application/json",
            },
        )
        transport = connection.sock
        transport.settimeout(timeout())
        response = connection.getresponse()
        observation["http_status"] = response.status
        if response.status != 200:
            observation["outcome"] = "rejected" if response.status == 429 else "failed"
            return observation
        backend = response.getheader("X-Inference-Backend")
        if (
            backend in backends
            and response.getheader("X-Inf060-Backend-Pod-Uid") == backends[backend]["identity"][0]
        ):
            observation["generation"] = backends[backend]["alias"]
        span = response.getheader("X-Inf060-Gateway-Predispatch-Ns", "")
        if span.isascii() and span.isdecimal() and len(span) <= 12:
            observation["gateway_predispatch_ns"] = int(span)
        request_id = response.getheader("X-Request-ID", "")
        if GATEWAY_REQUEST_ID.fullmatch(request_id):
            observation["private_request_id"] = request_id
        if not response.getheader("Content-Type", "").startswith("text/event-stream"):
            return observation

        def chunks():
            while True:
                transport.settimeout(timeout())
                content = response.read1(65536)
                if not content:
                    return
                yield content

        def close():
            try:
                transport.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
            response.close()

        def bounded_chunks():
            try:
                yield from chunks()
            except TimeoutError:
                observation["transport_error"] = True
                observation["client_close_reason"] = "deadline"
            except (OSError, http.client.HTTPException):
                observation["transport_error"] = True

        parsed = observe_stream(
            bounded_chunks(),
            cancel_assigned=row["cancel_assigned"],
            close=close,
            clock_ns=now,
            details=True,
        )
        observation.update(parsed)
        observation["outcome"] = (
            "cancelled"
            if parsed["cancel_status"] == "sent"
            else "completed"
            if parsed["complete"]
            else "partial"
            if parsed["content_event_count"]
            else "failed"
        )
    except TimeoutError:
        observation["transport_error"] = True
        if response is not None and response.status == 200:
            observation["client_close_reason"] = "deadline"
    except (OSError, http.client.HTTPException):
        observation["transport_error"] = True
    finally:
        if (
            response is not None
            and response.status == 200
            and observation["outcome"] in {"failed", "partial"}
        ):
            observation.setdefault(
                "client_close_reason",
                "transport_error" if observation.get("transport_error") else "partial",
            )
        # DONE is recorded on the read that delivered it, even if HTTP EOF arrives later.
        done = observation.pop("done_ns", None)
        observation["terminal_ns"] = done if done is not None else now()
        if response is not None:
            response.close()
        connection.close()
    return observation


def run_window(task, cfg, results):
    label = task["label"]
    duration = {"smoke": SMOKE_SECONDS, "warmup": WARMUP_SECONDS}.get(label, WINDOW_SECONDS)
    rows = schedule(label)
    context = ssl.create_default_context(cafile="/ca/tls.crt")
    corpus = dict(
        zip((row["alias"] for row in rows), prompts(rows, pinned_tokenizer()), strict=True)
    )
    end = time.monotonic() + task["deadline_epoch"] - time.time()
    if end - time.monotonic() < duration + DRAIN_SECONDS:
        raise TimeoutError("streaming_window_budget")
    backends = task["backends"]
    if {name: row["identity"] for name, row in pods(cfg["namespace"]).items()} != {
        name: row["identity"] for name, row in backends.items()
    }:
        raise ClockRefusal("streaming_generation")
    streams, clocks, errors = {}, {}, {}
    stop = threading.Event()
    cpu_started = resource.getrusage(resource.RUSAGE_SELF)
    gauge_pool = ThreadPoolExecutor(max_workers=len(backends))
    gauge_tasks = {
        row["alias"]: gauge_pool.submit(observe_replica, row, stop) for row in backends.values()
    }
    try:
        for replica in backends.values():
            alias = replica["alias"]
            try:
                connection = ClockStream(replica["ip"], replica["identity"][0], end)
                streams[alias] = connection
                clocks[alias] = {"before": connection.exchange(), "mapping": [wall_mapping()]}
            except (OSError, ClockRefusal) as exc:
                errors[alias] = str(exc) if isinstance(exc, ClockRefusal) else "clock_transport"
        cfg_path = results / (label + "-journal.jsonl")
        with cfg_path.open("xb") as journal:
            journal.write((json.dumps({"type": "window", "label": label}) + "\n").encode())
            journal.flush()

            def record(result):
                data = (json.dumps(result, separators=(",", ":")) + "\n").encode()
                if journal.tell() + len(data) > JOURNAL_LIMIT:
                    raise ValueError("streaming_journal_limit")
                journal.write(data)
                journal.flush()

            started_ns = time.monotonic_ns()
            window_end = started_ns + duration * 10**9
            run_offers(
                rows,
                lambda row: attempt(
                    row,
                    corpus[row["alias"]],
                    cfg["tokens"][row["tenant"]],
                    cfg["host"],
                    context,
                    window_end + DRAIN_SECONDS * 10**9,
                    backends,
                ),
                record,
                end_ns=window_end,
                start_ns=started_ns,
            )
            if time.monotonic_ns() < window_end:
                time.sleep((window_end - time.monotonic_ns()) / 10**9)
        drain_ns = time.monotonic_ns() - window_end
        release = []
        for replica in backends.values():
            try:
                metrics = scrape(replica["ip"], 0.2)
                release.append(
                    {
                        "generation": replica["alias"],
                        "monotonic_ns": time.monotonic_ns(),
                        "status": "sample",
                        **metrics,
                    }
                )
            except (OSError, ValueError):
                release.append(
                    {
                        "generation": replica["alias"],
                        "monotonic_ns": time.monotonic_ns(),
                        "status": "unavailable",
                    }
                )
        try:
            readback = pods(cfg["namespace"])
        except (OSError, ValueError, KeyError):
            readback = {}
        for name, replica in backends.items():
            alias = replica["alias"]
            if alias in errors:
                continue
            row = clocks[alias]
            try:
                row["same_generation"] = (
                    readback.get(name, {}).get("identity") == replica["identity"]
                )
                if not row["same_generation"]:
                    raise ClockRefusal("clock_generation")
                row["after"] = streams[alias].exchange()
                row["mapping"].append(wall_mapping())
                row["bounds"] = bracket(
                    row["before"],
                    row["after"],
                    row["mapping"],
                    same_generation=row["same_generation"],
                )
            except (OSError, ClockRefusal) as exc:
                errors[alias] = str(exc) if isinstance(exc, ClockRefusal) else "clock_transport"
    finally:
        try:
            for connection in streams.values():
                connection.close()
        finally:
            stop.set()
            gauge_pool.shutdown()
        cpu_end = resource.getrusage(resource.RUSAGE_SELF)
        details = {
            "clocks": [
                {"generation": key, **value, "status": errors.get(key, "bounded")}
                for key, value in clocks.items()
            ],
            "clock_refusals": [
                {"generation": key, "reason": reason} for key, reason in errors.items()
            ],
            "gauges": [],
            "client_cpu_s": cpu_end.ru_utime
            + cpu_end.ru_stime
            - cpu_started.ru_utime
            - cpu_started.ru_stime,
            "start_ns": locals().get("started_ns"),
            "drain_ns": locals().get("drain_ns"),
            "end_of_drain": locals().get("release", []),
        }
        for alias, future in gauge_tasks.items():
            for sample in future.result():
                details["gauges"].append({"generation": alias, **sample})
        for row in details["clocks"]:
            if row["status"] != "bounded":
                continue
            row["mapping"] = [
                row["mapping"][0],
                *(
                    sample["wall_mapping"]
                    for sample in details["gauges"]
                    if sample["generation"] == row["generation"]
                ),
                row["mapping"][-1],
            ]
            try:
                row["bounds"] = bracket(
                    row["before"], row["after"], row["mapping"], same_generation=True
                )
            except ClockRefusal as exc:
                row.pop("bounds", None)
                row["status"] = str(exc)
        (results / (label + "-details.json")).write_text(json.dumps(details), encoding="utf-8")
    return details


def serve(root):
    cfg = json.loads(os.environ["INF060_SETTINGS"])
    cfg["tokens"] = json.loads(Path("/credential/client.json").read_bytes())["tokens"]
    (root / "ready").touch()
    task = root / "stream-task.json"
    while time.time() < float(os.environ["M5_DEADLINE_EPOCH"]):
        if task.exists():
            work = json.loads(task.read_bytes())
            task.unlink()
            status = root / (work["label"] + "-status.json")
            try:
                run_window(work, cfg, root)
                result = {"status": "complete"}
            except Exception as exc:
                result = {"status": "failed", "type": type(exc).__name__}
            temporary = status.with_suffix(".tmp")
            temporary.write_text(json.dumps(result))
            temporary.replace(status)
        time.sleep(0.05)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("serve", "submit"))
    parser.add_argument("task", nargs="?")
    args = parser.parse_args()
    if args.mode == "serve":
        serve(ROOT)
    else:
        pending = ROOT / "stream-task.tmp"
        pending.write_text(args.task)
        pending.replace(ROOT / "stream-task.json")


if __name__ == "__main__":
    main()
