"""Single registered setup probe and independent native endpoint transport.

This produces raw source evidence. FitnessProducer retains authority for first
joined observations, TLS/SSE, native cancellation, release and all fixed bounds.
No missing emitter is replaced by a gateway event or an inference outcome.
"""

import copy
import math
import threading
import time
from concurrent.futures import FIRST_EXCEPTION, ThreadPoolExecutor, wait
from pathlib import Path
from urllib.parse import urlsplit

from . import inf037b_native
from .inf037b_archive import encode, file_facts, sha, strict_json, verify_archive
from .inf037b_capture import CaptureOwner
from .inf037b_command import require_group_leader
from .inf037b_controls import (
    CONTROL_ALLOWANCE_SECONDS,
    CONTROL_PAYLOADS,
    CONTROL_PAYLOADS_SHA256,
    control_slot,
)
from .inf037b_live import REQUEST_TIMEOUT_SECONDS, ClientSSEAdapter
from .inf037b_packet import workload_trace
from .inf037b_resolver import exact, require
from .inf037b_sources import ClockMapper


def capture_rows(root, descriptor):
    root = Path(root)
    require(
        descriptor.get("closed") is True and descriptor.get("transport_clean") is True,
        "probe:closed_clean_capture_required",
    )
    report = verify_archive(root / "archive")
    exact(report, descriptor["archive"], "probe:sealed_capture")
    files = {
        p.relative_to(root).as_posix(): file_facts(p)
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }
    exact(files, descriptor["files"], "probe:capture_inventory")
    for path in sorted((root / "archive/raw").glob("*.jsonl")):
        for line in path.read_bytes().splitlines():
            yield strict_json(line)


class NativeRequestAdapter:
    def __init__(
        self, rows, http, *, origin, manifest, slot, request_ids, clock_rows, clock_id=None
    ):
        exact(manifest["schema"], "inf037b-native-overlay-v1", "probe:native_manifest_schema")
        exact(manifest["version"], "0.29.0", "probe:native_version")
        exact(manifest["base"], inf037b_native.BASE_FILES, "probe:native_base_sources")
        exact(set(manifest["files"]), set(inf037b_native.BASE_FILES), "probe:native_file_inventory")
        exact(
            manifest["helper_sha256"],
            sha(Path(inf037b_native.__file__).read_bytes()),
            "probe:native_helper_source",
        )
        exact(origin["helper_sha256"], manifest["helper_sha256"], "probe:native_helper_binding")
        exact(origin["manifest_sha256"], sha(encode(manifest)), "probe:native_manifest_binding")
        self.rows, self.http, self.origin, self.manifest = (
            rows,
            http,
            copy.deepcopy(origin),
            copy.deepcopy(manifest),
        )
        self.slot, self.request_ids = slot, request_ids
        self.clock_rows, self.clock_id = clock_rows, clock_id or "node:" + origin["node"]
        self.offset, self.lost, self.installed = -1, False, {}
        self.requests, self.pending, self.pids = {}, [], {}
        self.poll_lock, self.raw_requests = threading.RLock(), {}
        self.accepted, self.ended = set(), set()

    def poll(self):
        with self.poll_lock:
            return self._poll()

    def _poll(self):
        require(not self.lost, "probe:native_capture_lost")
        start = self.rows.clock()
        output = []
        try:
            more = True
            while more:
                body, _ = self.http.get(f"/native/events?after={self.offset}")
                bundle = strict_json(body)
                exact(bundle["schema"], "inf037b-native-events-v1", "probe:native_schema")
                exact(bundle["origin"], self.origin, "probe:native_lineage")
                for event in bundle["events"]:
                    exact(event["sequence"], self.offset + 1, "probe:native_sequence")
                    chain = event["ancestry"]
                    require(
                        bool(chain)
                        and chain[0] == {"pid": event["pid"], "start": event["process_start"]}
                        and chain[-1]
                        == {
                            "pid": self.origin["supervisor_pid"],
                            "start": self.origin["supervisor_start"],
                        },
                        "probe:native_process_lineage",
                    )
                    pid = event["pid"]
                    exact(
                        self.pids.setdefault(pid, event["process_start"]),
                        event["process_start"],
                        "probe:native_pid_reused",
                    )
                    self.offset += 1
                    kind = event["event"]
                    if kind == "installed":
                        name = {
                            "core": "vllm/v1/engine/core.py",
                            "input": "vllm/v1/engine/input_processor.py",
                            "api": "vllm/v1/engine/async_llm.py",
                            "scheduler": "vllm/v1/core/sched/scheduler.py",
                        }[event["kind"]]
                        exact(
                            event["source_sha256"],
                            self.manifest["files"][name],
                            "probe:native_source",
                        )
                        self.installed.setdefault(event["kind"], set()).add(
                            (pid, event["process_start"])
                        )
                    elif kind == "identity":
                        require(
                            event["internal"] not in self.requests, "probe:native_identity_reused"
                        )
                        self.requests[event["internal"]] = event["external"]
                        self.raw_requests[event["internal"]] = {}
                    elif kind in ("accept", "terminal"):
                        records = self.raw_requests[event["internal"]]
                        require(kind not in records, "probe:native_endpoint_duplicate")
                        if kind == "accept":
                            require(
                                (pid, event["process_start"])
                                in self.installed.get("scheduler", set()),
                                "probe:native_engine_process",
                            )
                        else:
                            exact(
                                event["terminal"],
                                {k: v for k, v in records["native_end"].items() if k != "sequence"},
                                "probe:native_end_reference",
                            )
                            status = event["terminal"]["status"]
                            if event["terminal_reason"] == "client_cancel_abort":
                                exact(status, "FINISHED_ABORTED", "probe:native_abort_status")
                                exact(
                                    event["terminal"]["abort_rpc"], True, "probe:native_abort_path"
                                )
                                require(
                                    "abort_intent" in records
                                    and "abort_ack" in records
                                    and records["abort_intent"]["mono_ns"]
                                    <= event["terminal"]["mono_ns"],
                                    "probe:native_abort_cause",
                                )
                            else:
                                exact(
                                    {
                                        "FINISHED_STOPPED": "stop",
                                        "FINISHED_LENGTH_CAPPED": "length",
                                    }.get(status),
                                    event["terminal_reason"],
                                    "probe:native_natural_status",
                                )
                        records[kind] = event
                        self.pending.append((event, start, self.rows.clock()))
                    elif kind in ("abort_intent", "abort_ack", "native_end"):
                        records = self.raw_requests[event["internal"]]
                        require(kind not in records, "probe:native_cause_duplicate")
                        role = "scheduler" if kind == "native_end" else "api"
                        require(
                            (pid, event["process_start"]) in self.installed.get(role, set()),
                            "probe:native_cause_process",
                        )
                        records[kind] = event
                    else:
                        require(False, "probe:native_event")
                exact(bundle["next"], self.offset, "probe:native_offset")
                more = bundle["more"]
                require(
                    type(more) is bool and (not more or bool(bundle["events"])),
                    "probe:native_progress",
                )
            # Bind the exact native external ID produced by the pinned OpenAI
            # route and InputProcessor. Never strip/guess an internal suffix.
            aliases = {}
            for bindings in self.request_ids.values():
                for native, offered in bindings.copy().items():
                    external = "chatcmpl-" + native
                    require(external not in aliases, "probe:ambiguous_native_request")
                    aliases[external] = offered
            remaining = []
            clocks = ClockMapper(list(self.clock_rows))
            for event, begin, end in self.pending:
                external = self.requests[event["internal"]]
                if external not in aliases:
                    remaining.append((event, begin, end))
                    continue
                terminal = event.get("terminal", event)
                bounds = clocks.map(
                    self.clock_id,
                    self.origin["node_boot_id"],
                    terminal["mono_ns"] // 1_000_000,
                    (terminal["mono_ns"] + 999_999) // 1_000_000,
                )
                if bounds is None:
                    remaining.append((event, begin, end))
                    continue  # Await the following booked mapping; never label process UUID as kernel boot.
                kind = event["event"]
                fields = {
                    "pod_uid": self.origin["pod_uid"],
                    "slot": self.slot,
                    "process_generation": self.origin["boot_id"],
                    "request_id": aliases[external],
                    "model_sha256": self.origin["model_sha256"],
                    "runtime_sha256": self.origin["runtime_sha256"],
                }
                if kind == "terminal":
                    require(
                        event["terminal_reason"] in ("stop", "length", "client_cancel_abort"),
                        "probe:native_terminal_reason",
                    )
                    fields["terminal_reason"] = event["terminal_reason"]
                    fields["terminal_ms"] = terminal["mono_ns"] // 1_000_000
                    require(
                        aliases[external] in self.accepted, "probe:native_terminal_without_accept"
                    )
                    self.ended.add(aliases[external])
                else:
                    fields["accept_ms"] = terminal["mono_ns"] // 1_000_000
                    self.accepted.add(aliases[external])
                output.append(
                    self.rows.row(
                        "vllm",
                        "vllm:" + self.origin["pod_uid"],
                        self.origin["boot_id"],
                        kind,
                        fields,
                        source_ms=terminal["mono_ns"] // 1_000_000,
                        clock_id="node:" + self.origin["node"],
                        start_ns=begin,
                        end_ns=end,
                        time_bounds=bounds,
                    )
                )
            self.pending = remaining
            return output
        except Exception:
            self.lost = True
            if self.rows.on_loss:
                self.rows.on_loss()
            raise

    def ready(self):
        self.poll()
        exact(
            set(self.installed),
            {"input", "api", "core", "scheduler"},
            "probe:native_emitter_missing",
        )
        return {
            "origin": self.origin,
            "installed": {kind: sorted(values) for kind, values in self.installed.items()},
            "last_sequence": self.offset,
        }


class SingleProbe:
    def __init__(
        self,
        *,
        owner,
        clients,
        endpoints,
        credentials,
        control_credentials,
        contexts,
        tls,
        controller_rows,
        payloads,
        payloads_sha256,
        start_ns,
        stop_ns,
        native,
        gateway_adapters,
        signals=(),
        clock=time.monotonic_ns,
        sleep=time.sleep,
    ):
        require(isinstance(owner, CaptureOwner) and owner.attempt == "setup", "probe:setup_owner")
        exact(set(clients), {"gateway0", "gateway1"}, "probe:gateways")
        require(
            all(client.rows in owner.builders.values() for client in clients.values())
            and controller_rows in owner.builders.values(),
            "probe:capture_row_owner",
        )
        for mapping in (endpoints, credentials, contexts, tls, gateway_adapters):
            exact(set(mapping), set(clients), "probe:gateway_inventory")
        for endpoint in endpoints.values():
            url = urlsplit(endpoint)
            require(
                url.scheme == "https"
                and bool(url.hostname)
                and url.path == "/v1/chat/completions"
                and not url.username
                and not url.password
                and not url.query
                and not url.fragment,
                "probe:tls_endpoint",
            )
        require(
            all(isinstance(client, ClientSSEAdapter) for client in clients.values()),
            "probe:client_transport",
        )
        exact(sha(encode(payloads)), payloads_sha256, "probe:payload_pin")
        exact(set(payloads), {f"p{i:03}" for i in range(384)}, "probe:prefix_inventory")
        require(
            all(
                type(value.get("max_tokens")) is int
                and value.get("max_tokens") == 1
                and value.get("stream") is True
                and type(value.get("n", 1)) is int
                and value.get("n", 1) == 1
                for value in payloads.values()
            ),
            "probe:registered_decode",
        )
        require(
            type(start_ns) is int
            and type(stop_ns) is int
            and start_ns + 120_000_000_000 <= stop_ns,
            "probe:window",
        )
        self.owner, self.store = owner, owner.store
        self.clients, self.endpoints, self.credentials = (
            clients,
            endpoints,
            credentials,
        )
        self.contexts, self.tls, self.controller_rows = (
            contexts,
            copy.deepcopy(tls),
            controller_rows,
        )
        exact(set(control_credentials), {0, 1}, "probe:control_credentials")
        self.control_credentials = control_credentials
        self.control_payloads = copy.deepcopy(CONTROL_PAYLOADS)
        exact(sha(encode(self.control_payloads)), CONTROL_PAYLOADS_SHA256, "probe:control_pin")
        self.payloads, self.start_ns, self.stop_ns = copy.deepcopy(payloads), start_ns, stop_ns
        self.native, self.gateways, self.clock, self.sleep = native, gateway_adapters, clock, sleep
        self.signals = tuple(signals)
        if self.signals:
            exact(sorted(s.slot for s in self.signals), [0, 1], "probe:signal_slots")
            require(all(s.owner is owner for s in self.signals), "probe:signal_owner")

    def request(self, gateway, offer, *, cancel=False, tls_record=False, control=False):
        def tls_observed(facts, start, end):
            exact(facts, self.tls[gateway], "probe:tls_peer")
            if tls_record:
                self.controller_rows.row(
                    "controller",
                    "probe",
                    self.controller_rows.boot,
                    "precondition",
                    {"name": "tls:" + offer["request_id"], "value": facts},
                    start_ns=start,
                    end_ns=end,
                )

        require(self.clock() < self.stop_ns, "probe:deadline")
        payload = (
            self.control_payloads[offer["request_id"]]
            if control
            else self.payloads[offer["prefix_id"]]
        )
        credential = (
            self.control_credentials[control_slot(offer["request_id"])]
            if control
            else self.credentials[gateway]
        )
        return self.clients[gateway].request(
            self.endpoints[gateway],
            payload,
            offer,
            credential=credential(),
            context=self.contexts[gateway],
            cancel_after_content=cancel,
            tls_observer=tls_observed,
        )

    def run(self):
        require_group_leader()
        controls_ready_ns = self.clock()
        require(
            controls_ready_ns + CONTROL_ALLOWANCE_SECONDS * 1_000_000_000 <= self.start_ns,
            "probe:control_allowance",
        )
        with self.owner.io_lock, self.store.lock():
            state = self.store.read()
            require("single_probe" not in state, "probe:already_allocated")
            state["single_probe"] = {
                "start_ns": self.start_ns,
                "end_ns": self.start_ns + 120_000_000_000,
                "stop_ns": self.stop_ns,
                "measurement_started": False,
                "controls_ready_ns": controls_ready_ns,
                "controls_allowance_seconds": CONTROL_ALLOWANCE_SECONDS,
            }
            self.store.write(state)  # Irrevocable intent before source/traffic effects.
        for source in self.signals:
            source.ready(self.start_ns)
        for source in self.native:
            source.ready()  # A missing/unreviewed emitter refuses before traffic.

        def controls(gateway):
            for index in range(3):
                rid = f"ingress-{gateway}-{index}" if index < 2 else "cancel-" + gateway
                offer = {
                    "request_id": rid,
                    "offer_index": index,
                    "prefix_id": "p000",
                    "scheduled_ms": self.clock() // 1_000_000,
                }
                result = self.request(
                    gateway, offer, cancel=index == 2, tls_record=index < 2, control=True
                )
                require(not any(row["error"] for row in result), "probe:control_transport")
                require(
                    any(
                        row["payload"]["event"] == ("cancel" if index == 2 else "terminal")
                        for row in result
                    ),
                    "probe:control_endpoint",
                )

        pool = ThreadPoolExecutor(max_workers=2)
        try:
            futures = [pool.submit(controls, gateway) for gateway in self.clients]
            done, pending = wait(
                futures,
                timeout=max(0, (self.start_ns - self.clock()) / 1e9),
                return_when=FIRST_EXCEPTION,
            )
            for future in done:
                future.result()
            require(not pending, "probe:unsettled_controls")
        finally:
            pool.shutdown(wait=False, cancel_futures=True)
        require(self.clock() <= self.start_ns, "probe:late_start")
        trace = workload_trace("pre", 1, 120000)
        # Fixed offered load and unchanged 30 s request timeout bound the number
        # of simultaneous requests. Saturation records misses, never queues a
        # late replacement. No executor admission blocks the scheduled offers.
        limit = math.ceil(10.92 * REQUEST_TIMEOUT_SECONDS)
        available, futures = threading.BoundedSemaphore(limit), []
        dispatched = set()
        pool = ThreadPoolExecutor(max_workers=limit + len(self.signals))
        try:
            signal_futures = {
                source.slot: pool.submit(source.trigger, self.start_ns, self.stop_ns)
                for source in self.signals
            }
            futures.extend(signal_futures.values())
            for planned in trace:
                scheduled = (
                    self.start_ns
                    + planned["scheduled_ms_numerator"]
                    * 1_000_000
                    // planned["scheduled_ms_denominator"]
                )
                delay = scheduled - self.clock()
                if delay > 0:
                    self.sleep(delay / 1e9)
                offer = {**planned, "scheduled_ms": scheduled // 1_000_000}
                gateway = planned["gateway_uid"]
                if self.clock() >= self.start_ns + 120_000_000_000 or not available.acquire(
                    blocking=False
                ):
                    self.clients[gateway].missed(offer)
                    continue

                def dispatch(gateway=gateway, offer=offer):
                    try:
                        return self.request(gateway, offer)
                    finally:
                        available.release()

                futures.append(pool.submit(dispatch))
                dispatched.add(offer["request_id"])
            remaining = (self.start_ns + 120_000_000_000 - self.clock()) / 1e9
            if remaining > 0:
                self.sleep(remaining)
            done, pending = wait(futures, timeout=max(0, (self.stop_ns - self.clock()) / 1e9))
            require(not pending, "probe:unsettled_requests")
            for future in done:
                future.result()
            expected = (
                dispatched
                | {f"ingress-{gateway}-{slot}" for gateway in self.clients for slot in (0, 1)}
                | {"cancel-" + gateway for gateway in self.clients}
            )
            while True:
                for source in self.native:
                    source.poll()
                for source in self.gateways.values():
                    source.poll()
                    require(not source.lost, "probe:gateway_capture_lost")
                settled = (
                    all(not source.pending for source in self.native)
                    and all(not source.pending for source in self.gateways.values())
                    and set().union(*(source.ended for source in self.native)) == expected
                )
                if settled or self.clock() >= self.stop_ns:
                    break
                self.sleep(min(0.05, (self.stop_ns - self.clock()) / 1e9))
            require(settled, "probe:native_unjoined")
            exact(
                set().union(*(source.accepted for source in self.native)),
                expected,
                "probe:native_accept_endpoints",
            )
            exact(
                set().union(*(source.ended for source in self.native)),
                expected,
                "probe:native_terminal_endpoints",
            )
            with self.owner.io_lock, self.store.lock():
                state = self.store.read()
                require(self.clock() <= self.stop_ns, "probe:deadline")
                state["single_probe"].update(
                    traffic_complete=True,
                    scheduled=len(trace),
                    replacements=0,
                    signal_processes={
                        str(slot): future.result() for slot, future in signal_futures.items()
                    },
                )
                self.store.write(state)
            return state["single_probe"]
        finally:
            pool.shutdown(wait=False, cancel_futures=True)
