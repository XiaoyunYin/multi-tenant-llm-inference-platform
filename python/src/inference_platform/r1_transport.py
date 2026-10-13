"""Private HTTP adapter and bounded open/closed-loop load generation. Never calls AWS."""

import base64
import collections
import concurrent.futures
import gc
import hashlib
import ipaddress
import json
import math
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import weakref
from pathlib import Path

from .process_metrics import process_snapshot
from .r1_calibration_rows import CalibrationRows
from .r1_launcher import GATEWAY_FIXED
from .r1_manifest import epoch, row, trace
from .r1_metrics import delta, parse, percentile
from .r1_records import Journal
from .r1_session import RealClock
from .r1_spec import FIXED, MODEL, digest, encoded
from .stage_c_tokenizer import pinned_tokenizer
from .time_budget import deadline_urlopen


def private_url(value):
    url = urllib.parse.urlsplit(value)
    try:
        host = ipaddress.ip_address(url.hostname)
    except ValueError as exc:
        raise ValueError("literal private/loopback HTTP addresses required") from exc
    if (
        url.scheme != "http"
        or not host.is_private
        or host.is_multicast
        or url.username
        or url.password
    ):
        raise ValueError("public/ambiguous HTTP target refused")
    return value.rstrip("/")


def request(url, deadline, payload=None, token=None, max_seconds=5):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(
        url, data=None if payload is None else encoded(payload), headers=headers
    )
    deadline = min(deadline, time.perf_counter() + max_seconds)
    with deadline_urlopen(req, timeout=max_seconds, deadline=deadline) as response:
        return response.status, response.read()


class HTTP:
    def __init__(self, config, manifest, banks, output, cache=None, compression=1):
        expected = {
            "backends",
            "backend_agents",
            "gateways",
            "service_agent",
            "generator_agent",
            "agent_token",
            "credential",
            "manifest_sha256",
            "clock_evidence",
        }
        if set(config) != expected or config["manifest_sha256"] != manifest["manifest_sha256"]:
            raise ValueError("unknown/missing HTTP input or incompatible manifest")
        for key in ("backends", "backend_agents", "gateways"):
            if len(config[key]) != 2 or len(set(config[key])) != 2:
                raise ValueError("exactly two distinct hosts/processes required")
            config[key] = [private_url(url) for url in config[key]]
        for key in ("service_agent", "generator_agent"):
            config[key] = private_url(config[key])
        if (
            not math.isfinite(compression)
            or compression < 1
            or (
                compression != 1
                and not all(
                    ipaddress.ip_address(urllib.parse.urlsplit(url).hostname).is_loopback
                    for key in ("backends", "backend_agents", "gateways")
                    for url in config[key]
                )
            )
            or (
                compression != 1
                and not all(
                    ipaddress.ip_address(urllib.parse.urlsplit(config[key]).hostname).is_loopback
                    for key in ("service_agent", "generator_agent")
                )
            )
        ):
            raise ValueError("time compression is restricted to loopback rehearsals")
        self.compression = compression
        backend_hosts = {urllib.parse.urlsplit(url).hostname for url in config["backends"]}
        cpu_hosts = {
            urllib.parse.urlsplit(config[key]).hostname
            for key in ("service_agent", "generator_agent")
        }
        if len(backend_hosts) != 2 or len(cpu_hosts) != 2 or backend_hosts & cpu_hosts:
            raise ValueError("two GPU and two separate CPU roles required")
        evidence = config["clock_evidence"]
        if (
            not evidence.get("source")
            or not evidence.get("captured_at")
            or not evidence.get("usable")
        ):
            raise ValueError("clock provenance/readiness unresolved")
        self.config, self.manifest, self.banks = config, manifest, banks
        self.clock, self.closed, self.configured = RealClock(), True, None
        self.tokenizer = pinned_tokenizer(cache=cache)
        self.workload = {item["id"]: item for item in banks["workload.jsonl"]}
        self.output = Path(output)
        self.output.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=128)
        self.futures = []
        self.inflight = 0
        self.inflight_condition = threading.Condition()
        self.journal = Journal(self.output)
        self.archive_error = None
        self.identities = None
        self.identity_cache = [None, None]
        self.identity_times = [0, 0]
        self.identity_lock = threading.Lock()
        self.floors = None
        self.cal_first = {
            tuple(item["tokens"][:16]) for family in banks.values() for item in family
        }
        self.receipts = []
        self.phase_number = 0
        self.collector_stop = None
        self.collector_thread = None
        self.preparing = False
        self.corpus_sequence = 0
        self.outcome_lock = threading.Lock()
        self.gc_events = []
        self.gc_callback = None
        if compression != 1:
            started = [None]
            events = self.gc_events

            def gc_timing(phase, info):
                if phase == "start":
                    started[0] = time.perf_counter()
                elif started[0] is not None:
                    events.append(
                        {
                            "start_s": started[0],
                            "duration_s": time.perf_counter() - started[0],
                            "generation": info["generation"],
                        }
                    )
                    started[0] = None

            self.gc_callback = gc_timing
            gc.callbacks.append(gc_timing)

    def agent(self, url, path, deadline, payload=None):
        status, data = request(url + path, deadline, payload, self.config["agent_token"])
        if status != 200:
            raise ValueError("agent refused operation")
        return json.loads(data)

    def begin_preparation(self, pending):
        self.pending = pending
        self.preparing = True
        if self.compression != 1:
            for url in self.config["backends"]:
                request(url + "/fixture/preparation", self.clock.now() + 5, {"pending": pending})

    def preparation_complete(self):
        self.preparing = False

    def runtime_fitness(self, deadline):
        snapshots = self.snapshots(min(deadline, self.clock.now() + 5))
        receipts = []
        for backend, url in enumerate(self.config["backends"]):
            for family in self.banks.values():
                for value in family:
                    status, body = request(
                        url + "/tokenize",
                        min(deadline, self.clock.now() + 5),
                        {
                            "model": MODEL,
                            "messages": value["request"]["messages"],
                            "add_generation_prompt": True,
                        },
                    )
                    response = json.loads(body)
                    if (
                        status != 200
                        or response.get("tokens") != value["tokens"]
                        or response.get("count") != 1024
                    ):
                        raise ValueError("native token/block manifest mismatch")
                    receipts.append(
                        {
                            "backend": backend,
                            "id": value["id"],
                            "native_token_sha256": digest(response["tokens"]),
                        }
                    )
        result = {
            "native_tokens_match": True,
            "replicas": 2,
            "snapshots": snapshots,
            "rows": receipts,
            "clock_evidence": self.config["clock_evidence"],
        }
        (self.output / "runtime-fitness.json").write_bytes(encoded(result) + b"\n")
        return result

    def close_admissions(self, deadline):
        self.closed = True
        self.agent(self.config["service_agent"], "/close", deadline, {})

    def admission_state(self, deadline):
        result = self.agent(self.config["service_agent"], "/state", deadline)
        return {
            "gateway_reservations": result["gateway_reservations"],
            "coordinator_inflight": result["coordinator_inflight"],
            "gateway_processes_draining": result["gateway_processes_draining"],
        }

    def snapshots(self, deadline):
        values, identities = [], []
        for index, (url, agent) in enumerate(
            zip(self.config["backends"], self.config["backend_agents"], strict=True)
        ):
            with self.identity_lock:
                if (
                    self.identity_cache[index] is None
                    or self.clock.now() - self.identity_times[index] >= 5
                ):
                    started = self.clock.now()
                    self.identity_cache[index] = self.agent(agent, "/identity", deadline)
                    self.identity_times[index] = self.clock.now()
                    self.journal.record(
                        "identity-checks.jsonl",
                        {
                            "backend": index,
                            "start_s": started,
                            "duration_s": self.clock.now() - started,
                            "identity": self.identity_cache[index],
                        },
                    )
                identity = self.identity_cache[index]
            if identity["fixed"] != FIXED or identity["VLLM_SERVER_DEV_MODE"] != "1":
                raise ValueError("backend launcher/engine inputs differ")
            identities.append(identity["generation"])
            health_status, _ = request(url + "/health", deadline)
            if health_status != 200:
                raise ValueError("replica health dropped; N=2 comparison invalid")
            capture_start = self.clock.now()
            status, content = request(url + "/metrics", deadline)
            if status != 200:
                raise ValueError("native scrape failed")
            sample = parse(
                content.decode(), identity["generation"], self.clock.now(), self.clock.wall()
            )
            sample["age_s"] = self.clock.now() - capture_start
            sample["capture_start_s"] = capture_start
            if sample["age_s"] > 1:
                raise ValueError("native scrape exceeds freshness bound")
            values.append(sample)
        if self.identities is not None and identities != self.identities:
            raise ValueError("backend generation changed")
        self.identities = identities
        if self.floors is None:
            self.floors = [
                {key: value[key] for key in ("queries", "completions")} for value in values
            ]
        return values

    def counter_floors(self):
        with self.lock:
            return [dict(value) for value in self.floors]

    def record_native_completion(self, backend, result):
        if result["completed"]:
            with self.lock:
                self.floors[backend]["queries"] += 1024
                self.floors[backend]["completions"] += 1

    def stream(self, url, value, deadline, gateway=False):
        started, first = self.clock.now(), None
        payload = dict(value["request"])
        if gateway:
            payload.pop("cache_salt")
            payload.pop("stream_options")
        headers = {"Content-Type": "application/json"}
        if gateway:
            headers["Authorization"] = "Bearer " + self.config["credential"]
        req = urllib.request.Request(
            url + "/v1/chat/completions", data=encoded(payload), headers=headers
        )
        result = {
            "completed": False,
            "prompt_tokens": None,
            "completion_tokens": None,
            "ttft_s": None,
            "status": None,
            "empty_content": True,
            "censored": False,
        }
        done, finished, usage = False, False, None
        try:
            with deadline_urlopen(
                req, timeout=min(120, max(0.001, deadline - started)), deadline=deadline
            ) as response:
                result["status"] = response.status
                result["backend_id"] = response.headers.get("X-Inference-Backend")
                result["request_id"] = response.headers.get("X-Request-ID")
                result["trace_id"] = response.headers.get("X-Trace-ID")
                for line in response:
                    if len(line) > 1048576:
                        raise ValueError("oversize SSE event")
                    if not line.startswith(b"data: "):
                        continue
                    data = line[6:].strip()
                    if data == b"[DONE]":
                        done = True
                        break
                    chunk = json.loads(data)
                    if "error" in chunk:
                        raise ValueError("SSE error")
                    for choice in chunk.get("choices", []):
                        if choice.get("delta", {}).get("content"):
                            result["empty_content"] = False
                            if first is None:
                                first = self.clock.now() - started
                        if choice.get("finish_reason") in {"stop", "length"}:
                            finished = True
                    if chunk.get("usage") is not None:
                        if usage is not None:
                            raise ValueError("duplicate usage")
                        usage = chunk["usage"]
                if done and finished and usage is not None:
                    prompt, completion = usage.get("prompt_tokens"), usage.get("completion_tokens")
                    if (
                        type(prompt) is not int
                        or prompt != 1024
                        or type(completion) is not int
                        or not 0 <= completion <= 1
                    ):
                        raise ValueError("completion/token manifest mismatch")
                    if gateway and result["backend_id"] not in {"gpu-0", "gpu-1"}:
                        raise ValueError("incompatible completion backend identity")
                    result.update(
                        completed=True, prompt_tokens=prompt, completion_tokens=completion
                    )
        except urllib.error.HTTPError as exc:
            result.update(status=exc.code, error="HTTP rejection")
        except (OSError, TimeoutError, ValueError) as exc:
            result.update(error=str(exc), censored=self.clock.now() >= deadline)
        if not result["completed"]:
            result["censored"] |= self.clock.now() >= deadline
            result.setdefault("error", "incomplete SSE finish/usage/DONE sequence")
        result.update(ttft_s=first, latency_s=self.clock.now() - started, ended_s=self.clock.now())
        return result

    def probe(self, label, deadline):
        sentinel = self.banks["sentinel.jsonl"][0]
        futures = [
            self.executor.submit(self.stream, url, sentinel, deadline)
            for url in self.config["backends"]
        ]
        results = [
            future.result(timeout=max(0.001, deadline - self.clock.now())) for future in futures
        ]
        for backend, result in enumerate(results):
            self.record_native_completion(backend, result)
        return results

    def reset(self, backend, stage, deadline):
        try:
            status, body = request(
                self.config["backends"][backend] + "/reset_prefix_cache", deadline, {}
            )
            value = json.loads(body)
            if set(value) != {"success"} or type(value["success"]) is not bool:
                raise ValueError("invalid native reset reply")
            return {"status": status, "success": value["success"]}
        except urllib.error.HTTPError as exc:
            return {"status": exc.code, "success": None}
        except (TimeoutError, OSError) as exc:
            raise TimeoutError("uncertain reset response") from exc

    def configure(self, policy, r, w, b, seed, deadline):
        started = self.clock.now()
        result = self.agent(
            self.config["service_agent"],
            "/configure",
            deadline,
            {"policy": policy, "R": r, "W": w, "B": b, "seed": seed, "N": 2},
        )
        if len(result["gateways"]) != 2 or result["cache_salt"] != self.manifest["cache_salt"]:
            raise ValueError("gateway topology/salt mismatch")
        for receipt in result["gateways"]:
            if any(
                receipt["environment"].get(key) != value for key, value in GATEWAY_FIXED.items()
            ):
                raise ValueError("gateway fixed configuration differs")
        self.configured = result["configuration"]
        result["client_duration_s"] = self.clock.now() - started
        self.receipts.append(result)
        (self.output / "configurations.json").write_bytes(encoded(self.receipts) + b"\n")
        return self.configured

    def resources(self, deadline):
        return [
            self.agent(self.config[key], "/resources", deadline)
            for key in ("service_agent", "generator_agent")
        ]

    def phase(self, *args, **kwargs):
        # Refcounting still reclaims terminal work. Run cyclic collection before
        # the arrival window: a full collection holds the GIL and stops offers.
        enabled = gc.isenabled()
        started = self.clock.now()
        if enabled:
            gc.collect()
            gc.disable()
        collection_s = self.clock.now() - started
        self.calibration_rows = None
        try:
            result = self._phase(*args, **kwargs)
            result["gc_before_phase_s"] = collection_s
            result["gc_automatic_during_phase"] = False
            return result
        finally:
            try:
                if getattr(self, "collector_stop", None) is not None:
                    self.collector_stop.set()
                    self.collector_thread.join(timeout=5)
                if self.calibration_rows is not None:
                    self.calibration_rows.close()
            finally:
                if enabled:
                    gc.enable()

    def _phase(
        self,
        name,
        seconds,
        drain,
        q=None,
        level=None,
        block="b1",
        offset=0,
        deadline=None,
        request_deadline=None,
    ):
        if self.preparing:
            raise ValueError("generator dispatch forbidden during reset preparation")
        self.closed = False
        before = (
            self.warm_last
            if "-warm-" in name and not name.endswith("-0")
            else self.snapshots(min(deadline, self.clock.now() + 5))
        )
        if self.compression != 1:
            for url in self.config["backends"]:
                request(
                    url + "/fixture/phase",
                    self.clock.now() + 5,
                    {
                        "name": name,
                        "level": level,
                        "q": q,
                        "configuration": self.configured,
                        "compression": self.compression,
                    },
                )
        staircase = name.startswith("staircase")
        if staircase:
            # Initial rows are ready before phase start; reissues are built alongside
            # the phase. Waiting for an empty queue remains measured dispatch delay.
            self.calibration_rows = CalibrationRows(
                level,
                self.manifest["cache_salt"] + "-cal",
                self.tokenizer,
                row,
                self.cal_first,
                deadline,
            )
        start = self.clock.now()
        if start + seconds / self.compression > deadline:
            raise TimeoutError("phase does not fit original deadline after preparation/collection")
        stop = start + seconds / self.compression
        outcomes, offers, samples, resources, lateness, ticks = [], [], [], [], [], []
        closed_loop = q is None
        self.phase_number += 1
        workers = level * 2 if staircase else level if closed_loop else 128
        active = {0: [], 1: []}
        # None means the terminal callback has not published worker readiness yet.
        ready_at = [start] * max(1, workers)
        schedule = iter(
            trace("measure" if "measure" in name else "warm", block, q or 1, offset + seconds)
        )
        next_offer = next(schedule, None)
        while next_offer is not None and next_offer["arrival_s"] < offset:
            next_offer = next(schedule, None)
        index, max_gap, fatal = 0, 0, False
        collector_stop = threading.Event()
        self.collector_stop = collector_stop
        generator_process = []

        def sample_generator():
            generator_process.append(
                {
                    "monotonic_s": self.clock.now(),
                    "pid": os.getpid(),
                    "gc_automatic": gc.isenabled(),
                    **process_snapshot(os.getpid()),
                }
            )

        sample_generator()

        def collect():
            nonlocal max_gap, fatal
            target, last_sample, last_tick = start, start, start
            while not collector_stop.is_set() and self.clock.now() < stop:
                stamp = self.clock.now()
                max_gap = max(max_gap, stamp - last_sample)
                last_sample = stamp
                try:
                    snapshot = self.snapshots(min(deadline, stamp + 5))
                    samples.append(snapshot)
                    self.journal.record(
                        "native-samples.jsonl", {"phase": name, "replicas": snapshot}
                    )
                    resources.append(self.resources(min(deadline, self.clock.now() + 5)))
                    sample_generator()
                except Exception as exc:
                    self.archive_error = exc
                    fatal = True
                    return
                ticks.append(
                    {
                        "start_s": stamp,
                        "duration_s": self.clock.now() - stamp,
                        "gap_s": stamp - last_tick if ticks else 0,
                    }
                )
                last_tick = stamp
                target += 0.5
                collector_stop.wait(max(0, target - self.clock.now()))

        collector = threading.Thread(target=collect)
        self.collector_thread = collector
        collector.start()

        def dispatch(backend, entry, worker, offer_stamp=None):
            nonlocal index, fatal
            with self.inflight_condition:
                scheduled = (
                    ready_at[worker]
                    if closed_loop
                    else (start + (entry["arrival_s"] - offset) / self.compression)
                )
                if closed_loop:
                    ready_at[worker] = None
            if staircase:
                value = self.calibration_rows.take(worker)
                first_block = tuple(value["tokens"][:16])
                if first_block in self.cal_first:
                    raise ValueError("dynamic calibration first-block collision")
                self.cal_first.add(first_block)
                self.journal.record("calibration-requests.jsonl", value)
            else:
                value = self.workload[entry["prefix"]]
            gateway = not staircase
            url = self.config["gateways" if gateway else "backends"][backend]
            # Stamp at dispatch, after look-ahead retrieval and calibration journal.
            # The schedule still comes from phase start / the previous terminal.
            stamp = self.clock.now() if offer_stamp is None else offer_stamp
            offer = {
                "index": index if closed_loop else entry["index"],
                "worker": worker if closed_loop else None,
                "prefix": value["id"],
                "gateway": backend if gateway else None,
                "backend": backend if not gateway else None,
                "scheduled_s": scheduled,
                "dispatch_s": stamp,
                "lateness_s": max(0, stamp - scheduled),
                "request_sha256": value["request_sha256"],
            }
            offers.append(offer)
            self.journal.record("offered-trace.jsonl", {"phase": name, **offer})
            lateness.append(offer["lateness_s"])
            index += 1
            with self.inflight_condition:
                self.inflight += 1
            try:
                future = self.executor.submit(
                    self.stream,
                    url,
                    value,
                    min(request_deadline or deadline, self.clock.now() + 120),
                    gateway,
                )
            except BaseException:
                with self.inflight_condition:
                    self.inflight -= 1
                    self.inflight_condition.notify_all()
                raise
            active[backend].append((future, worker, offer))
            # History is for finish only. Executor/active cohort own pending futures;
            # weak references let terminal futures and their callbacks be reclaimed.
            self.futures.append(weakref.ref(future))

            def archive(completed):
                terminal_stamp = self.clock.now()
                try:
                    terminal = (
                        completed.result()
                        if not completed.cancelled()
                        else {
                            "completed": False,
                            "censored": True,
                            "error": "cancelled at session end",
                        }
                    )
                    if closed_loop:
                        with self.inflight_condition:
                            ready_at[worker] = terminal.get("ended_s", terminal_stamp)
                    outcome = {"phase": name, **offer, **terminal}
                    target = (
                        int(terminal["backend_id"].rsplit("-", 1)[1])
                        if gateway and terminal["completed"]
                        else backend
                    )
                    self.record_native_completion(target, terminal)
                    self.journal.record("request-outcomes.jsonl", outcome)
                except BaseException as exc:
                    self.archive_error = exc
                finally:
                    with self.inflight_condition:
                        self.inflight -= 1
                        self.inflight_condition.notify_all()

            future.add_done_callback(archive)

        while self.clock.now() < stop:
            for backend in range(2):
                remaining = []
                for future, worker, offer in active[backend]:
                    with self.inflight_condition:
                        terminal_ready = not closed_loop or ready_at[worker] is not None
                    if future.done() and terminal_ready:
                        outcomes.append({**offer, **future.result()})
                    else:
                        remaining.append((future, worker, offer))
                active[backend] = remaining
            if closed_loop:
                for backend in range(2):
                    desired = level if staircase else level // 2
                    used = {worker for _, worker, _ in active[backend]}
                    for local in range(desired):
                        worker = backend * desired + local
                        if worker not in used:
                            entries = epoch("warm", block, self.corpus_sequence // 1440)
                            entry = {"prefix": entries[self.corpus_sequence % 1440][0]}
                            self.corpus_sequence += 1
                            dispatch(backend, entry, worker)
            else:
                while (
                    next_offer is not None
                    and next_offer["arrival_s"] < offset + seconds
                    and start + (next_offer["arrival_s"] - offset) / self.compression
                    <= self.clock.now()
                ):
                    stamp = self.clock.now()
                    late = max(
                        0, stamp - (start + (next_offer["arrival_s"] - offset) / self.compression)
                    )
                    with self.inflight_condition:
                        at_bound = self.inflight >= workers
                    reasons = []
                    if late >= 1 / (q * self.compression):
                        reasons.append("missed_schedule_no_catch_up")
                    if late > 0.020:
                        reasons.append("lateness_over_20ms")
                    if at_bound:
                        reasons.append("inflight_bound")
                    if reasons:
                        missed = {
                            **next_offer,
                            "scheduled_s": start
                            + (next_offer["arrival_s"] - offset) / self.compression,
                            "not_dispatched": True,
                            "lateness_s": late,
                            "observed_s": stamp,
                            "reason": reasons[0],
                            "reasons": reasons,
                        }
                        offers.append(missed)
                        lateness.append(late)
                        self.journal.record("offered-trace.jsonl", {"phase": name, **missed})
                    else:
                        dispatch(next_offer["gateway"], next_offer, 0, stamp)
                    next_offer = next(schedule, None)
            wake = stop
            if not closed_loop and next_offer is not None:
                wake = min(wake, start + (next_offer["arrival_s"] - offset) / self.compression)
            self.clock.sleep(min(0.001, max(0, wake - self.clock.now())))
        if not closed_loop:
            while next_offer is not None and next_offer["arrival_s"] < offset + seconds:
                stamp = self.clock.now()
                late = max(
                    0, stamp - (start + (next_offer["arrival_s"] - offset) / self.compression)
                )
                missed = {
                    **next_offer,
                    "scheduled_s": start + (next_offer["arrival_s"] - offset) / self.compression,
                    "not_dispatched": True,
                    "observed_s": stamp,
                    "lateness_s": late,
                    "reason": "window_ended_no_catch_up",
                    "reasons": ["window_ended_no_catch_up"],
                }
                offers.append(missed)
                lateness.append(late)
                self.journal.record("offered-trace.jsonl", {"phase": name, **missed})
                next_offer = next(schedule, None)
        collector_stop.set()
        collector.join(timeout=max(0.001, deadline - self.clock.now()))
        if collector.is_alive():
            raise TimeoutError("collector exceeded phase deadline")
        self.closed = True
        # Cohort remains open for terminal outcomes through the registered drain.
        end = min(deadline, stop + drain)
        while self.clock.now() < end and any(active.values()):
            for backend in range(2):
                remaining = []
                for future, worker, offer in active[backend]:
                    if future.done():
                        outcomes.append({**offer, **future.result()})
                    else:
                        remaining.append((future, worker, offer))
                active[backend] = remaining
            self.clock.sleep(0.001)
        censored = sum(len(values) for values in active.values()) + sum(
            outcome["censored"] for outcome in outcomes
        )
        sample_generator()
        self.journal.flush(deadline)
        fatal |= self.archive_error is not None
        after = (
            self.snapshots(min(deadline, self.clock.now() + 5))
            if self.clock.now() < deadline
            else samples[-1]
        )
        if "-warm-" in name:
            self.warm_last = after
        replicas = []
        for backend in range(2):
            change = delta(before[backend], after[backend])
            replicas.append(
                {
                    "completed": sum(
                        outcome["completed"]
                        and (
                            outcome.get("backend") == backend
                            or outcome.get("backend_id") == f"gpu-{backend}"
                        )
                        for outcome in outcomes
                    ),
                    "preemptions": change["preemptions"],
                    "running": [sample[backend]["running"] for sample in samples],
                    "waiting": [sample[backend]["waiting"] for sample in samples],
                    "load": [
                        sample[backend]["running"] + sample[backend]["waiting"]
                        for sample in samples
                    ],
                    "deltas": change,
                    "interval_s": [
                        max(
                            0,
                            min(
                                samples[i + 1][backend]["monotonic_s"]
                                if i + 1 < len(samples)
                                else stop,
                                stop,
                            )
                            - sample[backend]["monotonic_s"],
                        )
                        for i, sample in enumerate(samples)
                    ],
                }
            )
        completed = sum(x["completed"] for x in outcomes)
        rejected = sum(x["status"] == 429 for x in outcomes)
        dispatched = sum(not x.get("not_dispatched") for x in offers)
        valid_resources = bool(resources) and all(
            item["cpu_budget"] >= 8
            and item["memory_bytes"] >= 16 * 1024**3
            and item["nic_limit_bps"] > 0
            and bool(item["nic_limit_source"])
            and item["nic_fraction"] <= 0.70
            and item["clock_usable"]
            for pair in resources
            for item in pair
        )
        if resources:
            valid_resources &= all(
                sum(pair[role]["cpu_fraction"] for pair in resources) / len(resources) <= 0.70
                for role in range(2)
            )
        last60 = [
            sum(
                outcome["completed"]
                and stop - 60 / self.compression <= outcome["ended_s"] <= stop
                and (
                    outcome.get("backend") == backend
                    or outcome.get("backend_id") == f"gpu-{backend}"
                )
                for outcome in outcomes
            )
            / 60
            for backend in range(2)
        ]
        return {
            "name": name,
            "q": q,
            "seconds": seconds,
            "wall_seconds": stop - start,
            "start_s": start,
            "stop_s": stop,
            "loopback_compression": self.compression,
            "before": before,
            "after": after,
            "samples": samples,
            "resources": resources,
            "generator_process": generator_process,
            "offers": offers,
            "outcomes": outcomes,
            "resources_valid": valid_resources,
            "collector_gap_max_s": max_gap,
            "collector_ticks": ticks,
            "lateness_count": len(lateness),
            "lateness_p95_s": percentile(lateness, 0.95) or 0,
            "missed": sum(bool(x.get("not_dispatched")) for x in offers),
            "missed_reasons": dict(
                collections.Counter(
                    reason for x in offers if x.get("not_dispatched") for reason in x["reasons"]
                )
            ),
            "fatal": fatal,
            "offered": len(offers),
            "admitted": dispatched - rejected,
            "completed": completed,
            "failed": dispatched - completed - rejected,
            "rejected": rejected,
            "censored": censored,
            "delivered_rate": dispatched / seconds,
            "ttft_s": [x["ttft_s"] for x in outcomes if x["ttft_s"] is not None],
            "latency_s": [x["latency_s"] for x in outcomes if x["completed"]],
            "replicas": replicas,
            "last_60_replica_rates": last60,
        }

    def finish(self, deadline):
        self.closed = True
        if self.gc_callback is not None:
            gc.callbacks.remove(self.gc_callback)
            self.gc_callback = None
            (self.output / "gc-events.json").write_bytes(encoded(self.gc_events) + b"\n")
        if self.collector_stop is not None:
            self.collector_stop.set()
            self.collector_thread.join(timeout=max(0, min(5, deadline - 300 - self.clock.now())))
        self.executor.shutdown(wait=False, cancel_futures=True)
        history = [
            item() if isinstance(item, weakref.ReferenceType) else item for item in self.futures
        ]
        _, unfinished = concurrent.futures.wait(
            [item for item in history if item is not None],
            timeout=max(0, min(600, deadline - 300 - self.clock.now())),
        )
        if unfinished:
            return {
                "exported": False,
                "error": "client outcomes incomplete at export cutoff",
                "teardown_required": True,
            }
        try:
            cutoff = min(deadline - 300, self.clock.now() + 600)
            with self.inflight_condition:
                while self.inflight:
                    remaining = cutoff - self.clock.now()
                    if remaining <= 0:
                        raise TimeoutError("terminal callback export cutoff")
                    self.inflight_condition.wait(min(0.1, remaining))
            self.journal.close(cutoff)
            if self.archive_error is not None:
                raise OSError("terminal record writer failed") from self.archive_error
            self.close_admissions(min(deadline, self.clock.now() + 5))
            manifest = self.agent(self.config["service_agent"], "/logs/manifest", cutoff)
            expected_receipts = [
                {key: value for key, value in item.items() if key != "client_duration_s"}
                for item in self.receipts
            ]
            if manifest["configurations"] != expected_receipts or (
                self.receipts and set(manifest["files"]) != {"gateway-0.jsonl", "gateway-1.jsonl"}
            ):
                raise ValueError("incomplete service configuration/log manifest")
            rate = manifest["minimum_bytes_per_second"]
            if rate <= 0 or not manifest["link_rate_source"]:
                raise ValueError("export link rate evidence missing")
            total = sum(manifest["files"].values())
            wire_estimate = (
                (total * 4 // 3) + len(encoded(manifest)) + 4096 * (total // 1048576 + 2)
            )
            allowance = 10 + 2 * wire_estimate / rate + (total // 1048576 + 2) * 0.1
            if self.clock.now() + allowance > cutoff:
                raise TimeoutError("byte-sized export does not fit registered export cutoff")
            started = self.clock.now()
            export_deadline = started + allowance
            logs = {"configurations": manifest["configurations"], "gateway_logs": {}}
            chunks = []
            for name, size in manifest["files"].items():
                content = bytearray()
                while len(content) < size:
                    offset, length = len(content), min(1048576, size - len(content))
                    status, data = request(
                        self.config["service_agent"] + "/logs/chunk",
                        export_deadline,
                        {"name": name, "offset": offset, "length": length},
                        self.config["agent_token"],
                        max_seconds=10 + 2 * (length * 4 / 3 + 4096) / rate,
                    )
                    chunk = json.loads(data)
                    part = base64.b64decode(chunk["base64"], validate=True)
                    if (
                        status != 200
                        or chunk["offset"] != offset
                        or chunk["size"] != size
                        or chunk["bytes"] != length
                        or len(part) != length
                        or hashlib.sha256(part).hexdigest() != chunk["sha256"]
                    ):
                        raise ValueError("incomplete or changed resumable export chunk")
                    content.extend(part)
                    chunks.append(
                        {"name": name, "offset": offset, "bytes": length, "sha256": chunk["sha256"]}
                    )
                logs["gateway_logs"][name] = content.decode()
            content = encoded(logs) + b"\n"
            (self.output / "service-export.json").write_bytes(content)
            receipt = {
                "complete": True,
                "bytes": len(content),
                "raw_log_bytes": total,
                "sha256": hashlib.sha256(content).hexdigest(),
                "chunks": chunks,
                "wire_estimate_bytes": wire_estimate,
                "minimum_bytes_per_second": rate,
                "link_rate_source": manifest["link_rate_source"],
                "allowance_s": allowance,
                "elapsed_s": self.clock.now() - started,
                "cutoff_s": cutoff,
                "deadline_s": export_deadline,
            }
            (self.output / "export-receipt.json").write_bytes(encoded(receipt) + b"\n")
        except (ValueError, OSError, TimeoutError) as exc:
            return {"exported": False, "error": str(exc), "teardown_required": True}
        return {
            "exported": True,
            "receipt": receipt,
            "teardown_required": True,
            "scope": "host teardown belongs to the later approved lifecycle wrapper",
        }
