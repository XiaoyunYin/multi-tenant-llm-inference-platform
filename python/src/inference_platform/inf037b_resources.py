"""Independent cgroup/NIC counters and budgeted HTTP resource windows (:10/:36).

CPU and NIC capacities are pinned role inputs, never inferred from throughput.
The host launcher/placement and those capacity proofs remain deployment inputs.
"""

import hmac
import os
import re
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler
from pathlib import Path

from .inf037b_archive import encode, sha, strict_json
from .inf037b_capture import DeadlineHTTP
from .inf037b_live import ClockAdapter
from .inf037b_resolver import exact, integer, require
from .inf037b_sources import ClockMapper

RESOURCE_ROLES = ("measurement", "generator", "gateway0", "gateway1", "node0", "node1")


def validate_resource_binding(role, spec):
    require(role in RESOURCE_ROLES, "resource:role")
    require(bool(spec.get("generation")) and bool(spec.get("boot_id")), "resource:identity")
    for key in ("source_sha256", "agent_sha256"):
        require(
            type(spec.get(key)) is str and re.fullmatch("[0-9a-f]{64}", spec[key]),
            "resource:identity:" + key,
        )
    budget = spec.get("budget", {})
    require(
        all(
            integer(budget.get(k)) and budget[k] > 0
            for k in ("cpu_millicores", "nic_bytes_per_second")
        ),
        "resource:capacity",
    )
    require(
        type(budget.get("capacity_ref")) is str
        and re.fullmatch("[0-9a-f]{64}", budget["capacity_ref"]),
        "resource:unresolved:capacity_authority",
    )
    require(type(spec.get("provenance")) is dict, "resource:provenance")
    for key in ("cgroup_identity", "interface_identity"):
        value = spec["provenance"].get(key)
        require(
            type(value) is list and len(value) == 2 and all(integer(v) and v >= 0 for v in value),
            "resource:provenance:" + key,
        )
    require(
        integer(spec["provenance"].get("ifindex")) and spec["provenance"]["ifindex"] > 0,
        "resource:provenance:ifindex",
    )
    exact(
        spec["provenance"]["capacity_sha256"], budget["capacity_ref"], "resource:capacity_binding"
    )
    exact(spec["provenance"]["agent_sha256"], spec["agent_sha256"], "resource:agent_binding")


class ProcCounters:
    """Run independently of the measured role, reading its cgroup and NIC.

    iface must identify that role's network namespace or a conservative whole
    host accounting interface. No link-speed/burst-rate guess is a NIC budget.
    """

    def __init__(self, cgroup, interface, *, cpu_millicores, nic_bytes_per_second, capacity_ref):
        require(
            all(integer(n) and n > 0 for n in (cpu_millicores, nic_bytes_per_second)),
            "resource:capacity",
        )
        require(type(capacity_ref) is str and len(capacity_ref) == 64, "resource:capacity_proof")
        self.cgroup, self.interface = Path(cgroup), Path(interface)
        self.budget = {
            "cpu_millicores": cpu_millicores,
            "nic_bytes_per_second": nic_bytes_per_second,
            "capacity_ref": capacity_ref,
        }

    def __call__(self):
        quota, period = (self.cgroup / "cpu.max").read_text().split()
        actual = os.cpu_count() * 1000 if quota == "max" else int(quota) * 1000 // int(period)
        exact(actual, self.budget["cpu_millicores"], "resource:cpu_capacity_changed")
        values = dict(line.split() for line in (self.cgroup / "cpu.stat").read_text().splitlines())
        return {
            "cpu_ns": int(values["usage_usec"]) * 1000,
            "rx_bytes": int((self.interface / "statistics/rx_bytes").read_text()),
            "tx_bytes": int((self.interface / "statistics/tx_bytes").read_text()),
        }


class ResourceProducer:
    def __init__(
        self, *, role, binding, generation, boot, counters, budget, clock=time.monotonic_ns
    ):
        require(role in RESOURCE_ROLES and generation and boot, "resource:identity")
        require(
            all(
                integer(budget[k]) and budget[k] > 0
                for k in ("cpu_millicores", "nic_bytes_per_second")
            ),
            "resource:capacity",
        )
        if isinstance(counters, ProcCounters):
            exact(budget, counters.budget, "resource:capacity_binding")
        self.role, self.binding, self.generation, self.boot = role, binding, generation, boot
        self.counters, self.budget, self.clock = counters, budget, clock
        self.provenance = None
        self.history, self.lock = deque(maxlen=4), threading.Lock()

    def read(self):
        with self.lock:
            begin = self.clock()
            counters = self.counters()
            end = self.clock()
            require(
                set(counters) == {"cpu_ns", "rx_bytes", "tx_bytes"}
                and all(integer(v) and v >= 0 for v in counters.values()),
                "resource:counters",
            )
            require(begin <= end, "resource:clock")
            self.history.append({"begin_ns": begin, "end_ns": end, **counters})
            # A sliding interval overlaps its neighbours. End it one poll before
            # the current mapping, so both endpoints have bracketing clock maps.
            window = [self.history[0], self.history[2]] if len(self.history) == 4 else None
            result = {
                "schema": "inf037b-resource-v1",
                "role": self.role,
                "binding": self.binding,
                "generation": self.generation,
                "boot_id": self.boot,
                "budget": self.budget,
                "source_sha256": sha(Path(__file__).read_bytes().replace(b"\r\n", b"\n")),
                "clock_ns": end,
                "window": window,
            }
            if self.provenance is not None:
                result["provenance"] = self.provenance
            return result


def resource_handler(producer, token):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            if self.path != "/resources" or not hmac.compare_digest(
                self.headers.get("Authorization", ""), "Bearer " + token()
            ):
                self.send_error(403)
                return
            try:
                body = encode(producer.read())
            except Exception:
                self.send_error(503)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return Handler


def ceil_div(n, d):
    require(d > 0, "resource:duration")
    return (n + d - 1) // d


class ResourceAdapter:
    def __init__(self, owner, role, spec, stop_ns):
        require(role in RESOURCE_ROLES, "resource:role")
        self.owner, self.role, self.spec = owner, role, spec
        self.source = "resource:" + role
        self.rows = owner.rows(self.source)
        self.http = DeadlineHTTP(
            **spec["http"], stop_ns=stop_ns, retain=owner.retainer(self.source)
        )
        self.emitted, self.last_window = False, None

    def poll(self):
        start = self.rows.clock()
        try:
            body, _ = self.http.get("/resources")
            end = self.rows.clock()
            raw = strict_json(body)
            exact(raw["schema"], "inf037b-resource-v1", "resource:schema")
            exact(
                raw["binding"],
                {
                    "session_id": self.owner.binding["session_id"],
                    "pins": self.owner.binding["pins"],
                },
                "resource:binding",
            )
            for key, value in (
                ("role", self.role),
                ("generation", self.spec["generation"]),
                ("boot_id", self.spec["boot_id"]),
                ("budget", self.spec["budget"]),
                ("source_sha256", self.spec["source_sha256"]),
            ):
                exact(raw[key], value, "resource:identity:" + key)
            if "provenance" in self.spec:
                exact(raw.get("provenance"), self.spec["provenance"], "resource:provenance")
            require(0 <= end - start <= 100_000_000, "resource:clock_uncertainty")
            ClockAdapter(self.rows).mapping(
                "resource:" + self.role, raw["boot_id"], raw["clock_ns"] // 1_000_000, start, end
            )
            if raw["window"] is None:
                require(not self.emitted, "resource:window_reset")
                return []
            left, right = raw["window"]
            require(left["end_ns"] < right["begin_ns"], "resource:window_order")
            mapper = ClockMapper(self.owner.clock_rows)
            clock_id = "resource:" + self.role
            a = mapper.map(
                clock_id,
                raw["boot_id"],
                left["begin_ns"] // 1_000_000,
                (left["end_ns"] + 999999) // 1_000_000,
            )
            b = mapper.map(
                clock_id,
                raw["boot_id"],
                right["begin_ns"] // 1_000_000,
                (right["end_ns"] + 999999) // 1_000_000,
            )
            if a is None or b is None:
                require(not self.emitted, "resource:clock")
                return []
            lo, hi = a[1], b[0]  # Guaranteed interior only; never optimistic coverage.
            require(lo < hi and hi - lo <= 2000, "resource:window_duration")
            require(
                self.last_window is None or lo > self.last_window[0], "resource:window_repeated"
            )
            elapsed_ns = right["begin_ns"] - left["end_ns"]
            deltas = {k: right[k] - left[k] for k in ("cpu_ns", "rx_bytes", "tx_bytes")}
            require(
                all(integer(v) and v >= 0 for v in deltas.values()), "resource:counter_regressed"
            )
            budget = raw["budget"]
            cpu = ceil_div(deltas["cpu_ns"] * 1_000_000_000, elapsed_ns * budget["cpu_millicores"])
            nic = ceil_div(
                (deltas["rx_bytes"] + deltas["tx_bytes"]) * 1_000_000_000_000_000,
                elapsed_ns * budget["nic_bytes_per_second"],
            )
            row = self.rows.row(
                "controller",
                self.source,
                raw["generation"],
                "resource",
                {
                    "role": self.spec.get("normalized_role", self.role),
                    "window_start_ms": lo,
                    "window_end_ms": hi,
                    "value": {"cpu_ppm": cpu, "nic_ppm": nic},
                    "cpu_fraction": cpu / 1_000_000,
                    "nic_fraction": nic / 1_000_000,
                    "limit_known": True,
                    "input_sha256": sha(body),
                },
                start_ns=start,
                end_ns=end,
            )
            self.emitted, self.last_window = True, (lo, hi)
            return [row]
        except Exception as exc:
            self.owner.loss(self.source + ":" + str(exc))
            raise


class ResourceWindows:
    """Use CaptureOwner.periodic and its budgets/failure semantics, not a probe."""

    def __init__(self, owner, bindings, stop_ns):
        self.owner, self.stop_ns = owner, stop_ns
        self.adapters = {
            role: ResourceAdapter(owner, role, spec, stop_ns) for role, spec in bindings.items()
        }
        self.stop, self.threads, self.errors = threading.Event(), [], []

    def start(self):
        for role, adapter in self.adapters.items():

            def run(adapter=adapter):
                try:
                    self.owner.periodic(
                        adapter.source,
                        adapter.poll,
                        period_ms=500,
                        stop_ns=self.stop_ns,
                        stop_event=self.stop,
                    )
                except Exception as exc:
                    self.errors.append(exc)
                    self.stop.set()

            thread = threading.Thread(target=run, name="resource-" + role)
            thread.start()
            self.threads.append(thread)
        return self

    def close(self):
        self.stop.set()
        for thread in self.threads:
            thread.join(timeout=0.5)
            if thread.is_alive():
                self.owner.loss("resource:unsettled")
                require(False, "resource:unsettled")
        if self.errors:
            raise self.errors[0]
