"""02-E composed collectors and their source-call contracts; no budget admission.

Scope windows are booked before work against the existing original cutoff.
Transport/census/source bindings remain explicit. No full-session polling proxy
or generic success callback supplies an otherwise missing collector.
"""

import ast
import math
import threading
from dataclasses import dataclass
from pathlib import Path

from .inf037b_contract import ATTEMPT_MS, RESET_MS
from .inf037b_resolver import BOUNDS_MS, exact, require

GATEWAY_POLL_MS = 250
KUBERNETES_POLL_MS = 250
REDIS_POLL_MS = 250
METRICS_POLL_MS = 500
NATIVE_POLL_MS = 500
LIFECYCLE_POLL_MS = 500
RESOURCE_POLL_MS = 500
CLOCK_POLL_MS = 1000
# Source: SingleProbe.run, the real native/gateway-only post-traffic settle.
PROBE_SETTLE_POLL_MS = 50
PROBE_SETTLE_MS = 30000
PROBE_MS = 120000
CONTROL_MS = 3 * 30000
PROBE_OWNER_MS = CONTROL_MS + PROBE_MS + PROBE_SETTLE_MS
STARTUP_MS = 300000
# Existing original phase cutoffs: LifecycleDriver._prepare/_campaign/_finish,
# its durable _window/call_start, and ProcessCalls' process-group watchdog.
# First setup shares the remaining original preparation window (<=1800 s).
# Only the missing smoke/rollback scope gets a new project window.
PROJECT_WINDOWS_MS = {"configuration_smoke_rollback": 120000}
SCOPE_WINDOWS_MS = {
    "attempt_setup:1": 1800000,
    "export": BOUNDS_MS["export"],
    "cleanup": BOUNDS_MS["cleanup"],
    **PROJECT_WINDOWS_MS,
}


@dataclass(frozen=True)
class ScopeWindow:
    scope: str
    start_ns: int
    stop_ns: int
    pin: str
    action_count: int = 0

    def __post_init__(self):
        require(
            type(self.start_ns) is int
            and type(self.stop_ns) is int
            and 0 <= self.start_ns <= self.stop_ns
            and bool(self.pin),
            "collectors:scope_window",
        )
        require(type(self.action_count) is int and self.action_count >= 0, "collectors:actions")
        if self.scope.startswith("attempt:"):
            maximum = ATTEMPT_MS
        elif self.scope in ("cold_startup", "cached_startup"):
            maximum = STARTUP_MS
        elif self.scope == "fitness_probe_and_signal":
            maximum = PROBE_OWNER_MS
        elif self.scope in ("attempt_setup:2", "attempt_setup:3"):
            maximum = RESET_MS
        else:
            maximum = SCOPE_WINDOWS_MS.get(self.scope)  # Never a session fallback.
        require(maximum is None or self.duration_ms <= maximum, "collectors:scope_deadline")

    @property
    def duration_ms(self):
        return (self.stop_ns - self.start_ns + 999999) // 1000000

    def slots(self, period_ms):
        # CaptureOwner.periodic executes only while next + period <= cutoff.
        return (self.stop_ns - self.start_ns) // (period_ms * 1000000)

    def traffic(self):
        if self.scope.startswith("attempt:"):
            pre = min(self.duration_ms, 600000)
            event = min(max(0, self.duration_ms - pre), 960000)
            return math.ceil(pre * 273 / 25000) + math.ceil(event * 273 / 25000)
        if self.scope == "fitness_probe_and_signal":
            return math.ceil(PROBE_MS * 273 / 25000)
        return 0

    def controls(self):
        return (
            6
            if self.scope == "fitness_probe_and_signal"
            else 10
            if self.scope == "row5_controls_and_restoration"
            else 0
        )


def producer_entries():
    # The publishers may run while no capture scope is active. Their lifetime
    # is the session bound, unlike the collectors' polling/traffic windows.
    offers = 3 * (math.ceil(600000 * 273 / 25000) + math.ceil(960000 * 273 / 25000))
    offers += math.ceil(PROBE_MS * 273 / 25000) + 6 + 10
    reports = 4 * (math.ceil(18000000 / 250) + 1 + 22)
    return 4 * offers + reports + 10


def redis_counts(window):
    boundaries = 2 * window.action_count + 1  # before/after fixed effects and initial read
    snapshots = window.slots(REDIS_POLL_MS) + boundaries
    clocks = window.slots(CLOCK_POLL_MS) + boundaries
    drains = math.ceil(producer_entries() / 1000)
    return {
        "AUTH": 1,
        "TIME": clocks,
        "snapshot": snapshots,
        "audit": 2 * snapshots + drains,
        "entries": producer_entries(),
    }


class ComposedCollectors:
    """Actual callbacks attached to the existing CaptureOwner scheduler."""

    def __init__(
        self,
        owner,
        window,
        *,
        redis,
        clocks,
        gateways=(),
        kubernetes=None,
        metrics=(),
        native=(),
        lifecycle=(),
        resources=(),
        replacements=None,
    ):
        self.owner, self.window, self.redis, self.clocks = owner, window, redis, clocks
        self.gateways = dict(gateways)
        self.kubernetes = kubernetes
        self.metrics, self.native = dict(metrics), dict(native)
        self.lifecycle, self.resources = dict(lifecycle), dict(resources)
        self.counts = redis_counts(window)
        self.calls = {}
        self.replacements = replacements
        self.boundaries = 0
        self.count_lock = threading.Lock()
        self.redis_lock = threading.RLock()
        self.redis.wire.bind_scope_contract(self.counts)
        self.redis.scope_contract = self.counts
        self.periodic = [
            ("redis", REDIS_POLL_MS, self.poll_redis),
            ("clocks", CLOCK_POLL_MS, self.poll_clocks),
        ]
        self.periodic += [
            (source, GATEWAY_POLL_MS, self._bounded(source, GATEWAY_POLL_MS, adapter.poll))
            for source, adapter in self.gateways.items()
        ]
        if kubernetes is not None:
            self.periodic.append(
                (
                    "kubernetes",
                    KUBERNETES_POLL_MS,
                    self._bounded("kubernetes", KUBERNETES_POLL_MS, kubernetes.snapshot),
                )
            )
        from .inf037b_composition import SamplerComposition

        for source, (sampler, uid) in self.metrics.items():
            require(isinstance(sampler, SamplerComposition), "collectors:startup_sampler")

            def sample(sampler=sampler, uid=uid, source=source):
                result = sampler.poll(uid, deadline_ns=self.window.stop_ns)
                if self.replacements is not None:
                    for other_uid, adapters in tuple(
                        self.replacements["replacement_adapters"].items()
                    ):
                        if source == "metrics:slot" + str(adapters["metrics"].slot):
                            other = self.replacements["replacement_samplers"][other_uid]
                            require(
                                isinstance(other, SamplerComposition), "collectors:startup_sampler"
                            )
                            other.poll(other_uid, deadline_ns=self.window.stop_ns)
                return result

            self.periodic.append(
                (source, METRICS_POLL_MS, self._bounded(source, METRICS_POLL_MS, sample))
            )
        for collection, period in (
            (self.native, NATIVE_POLL_MS),
            (self.lifecycle, LIFECYCLE_POLL_MS),
            (self.resources, RESOURCE_POLL_MS),
        ):
            for source, adapter in collection.items():

                def poll(source=source, adapter=adapter):
                    result = adapter.poll()
                    if self.replacements is not None and source.startswith(
                        ("native:slot", "lifecycle:slot")
                    ):
                        kind = source.split(":")[0]
                        for adapters in tuple(self.replacements["replacement_adapters"].values()):
                            if source == kind + ":slot" + str(adapters["metrics"].slot):
                                adapters[kind].poll()
                    return result

                self.periodic.append((source, period, self._bounded(source, period, poll)))
        for source, adapter in self.lifecycle.items():
            self.periodic.append(
                (source, CLOCK_POLL_MS, self._bounded(source, CLOCK_POLL_MS, adapter.clock))
            )

    def _bounded(self, source, period, callback):
        key = (source, period)

        def collect():
            with self.count_lock:
                self.calls[key] = self.calls.get(key, 0) + 1
                require(
                    self.calls[key] <= self.window.slots(period), "collectors:call_count:" + source
                )
            return callback()

        return collect

    def poll_redis(self):
        key = ("redis", REDIS_POLL_MS)
        self.calls[key] = self.calls.get(key, 0) + 1
        require(self.calls[key] <= self.window.slots(REDIS_POLL_MS), "collectors:call_count:redis")
        with self.redis_lock:
            self.redis.snapshot()
            self.redis.operations()

    def poll_clocks(self):
        key = ("clocks", CLOCK_POLL_MS)
        self.calls[key] = self.calls.get(key, 0) + 1
        require(self.calls[key] <= self.window.slots(CLOCK_POLL_MS), "collectors:call_count:clocks")
        self.owner.local_clock(self.clocks.rows)
        self.clocks.redis(self.redis.wire)
        for gateway, adapter in self.gateways.items():
            # Keep each gateway HTTP header/body exchange contiguous with its
            # measurement response; replay groups those responses by headers.
            with adapter.poll_lock:
                self.clocks.gateway(adapter.http, gateway)

    def boundary(self):
        with self.count_lock:
            self.boundaries += 1
        require(self.boundaries <= 2 * self.window.action_count + 1, "collectors:boundary_count")
        self.owner.local_clock(self.clocks.rows)
        with self.redis_lock:
            self.clocks.redis(self.redis.wire)
            self.redis.snapshot()
            self.redis.operations()

    def action(self, callback):
        def bounded_action():
            self.boundary()
            try:
                return callback()
            finally:
                self.boundary()

        return bounded_action

    def run(self, *, watches=None, actions=None):
        actions = dict(actions or {})
        exact(len(actions), self.window.action_count, "collectors:action_inventory")
        wrapped = {name: self.action(callback) for name, callback in actions.items()}
        self.boundary()  # One initial boundary, inside the original cutoff.
        return self.owner.run(
            periodic=self.periodic,
            watches=watches or {},
            actions=wrapped,
            stop_ns=self.window.stop_ns,
        )


def count_sources():
    return [
        *[
            {"count": kind, "path": path, "method": method, "call": call}
            for kind, path, method, call in (
                (
                    "measurement_clock",
                    "inf037b_eks_collectors.py",
                    "ComposedCollectors.poll_clocks",
                    "local_clock",
                ),
                ("gateway_GET", "inf037b_live.py", "GatewayAdapter._poll", "get"),
                ("kube_GET", "inf037b_live.py", "KubernetesAdapter.snapshot", "get"),
                ("native_GET", "inf037b_probe.py", "NativeRequestAdapter._poll", "get"),
                ("lifecycle_GET", "inf037b_live.py", "NodeLifecycleAdapter._poll", "get"),
                ("lifecycle_clock_GET", "inf037b_live.py", "NodeLifecycleAdapter.clock", "get"),
                ("resource_GET", "inf037b_resources.py", "ResourceAdapter.poll", "get"),
                ("engine_GET", "inf037b_live.py", "VLLMAdapter.engine_config", "get"),
                ("sample_GET", "inf037b_live.py", "VLLMAdapter.sample", "get"),
                ("sampler_gate", "inf037b_composition.py", "SamplerComposition.poll", "sample"),
                ("probe_settle_native_gateway_only", "inf037b_probe.py", "SingleProbe.run", "poll"),
                (
                    "row5_inline_snapshot",
                    "inf037b_row5_sequence.py",
                    "KnownStage.snapshot",
                    "snapshot",
                ),
                ("traffic_dispatch", "inf037b_eks_campaign.py", "traffic", "request"),
                ("probe_dispatch", "inf037b_probe.py", "SingleProbe.request", "request"),
                ("redis_connection", "inf037b_live.py", "RedisWire.__init__", "create_connection"),
                ("http_connection", "inf037b_capture.py", "DeadlineHTTP.chunks", "cls"),
            )
        ],
        {
            "count": "TIME",
            "path": "inf037b_eks_collectors.py",
            "method": "ComposedCollectors.poll_clocks",
            "call": "redis",
            "cadence_ms": CLOCK_POLL_MS,
        },
        {
            "count": "snapshot",
            "path": "inf037b_eks_collectors.py",
            "method": "ComposedCollectors.poll_redis",
            "call": "snapshot",
            "cadence_ms": REDIS_POLL_MS,
        },
        {
            "count": "audit",
            "path": "inf037b_eks_collectors.py",
            "method": "ComposedCollectors.poll_redis",
            "call": "operations",
            "cadence_ms": REDIS_POLL_MS,
        },
        {
            "count": "boundary_TIME",
            "path": "inf037b_eks_collectors.py",
            "method": "ComposedCollectors.boundary",
            "call": "redis",
        },
        {
            "count": "boundary_snapshot",
            "path": "inf037b_eks_collectors.py",
            "method": "ComposedCollectors.boundary",
            "call": "snapshot",
        },
        {
            "count": "boundary_audit",
            "path": "inf037b_eks_collectors.py",
            "method": "ComposedCollectors.boundary",
            "call": "operations",
        },
        {
            "count": "AUTH",
            "path": "inf037b_live.py",
            "method": "RedisWire.__init__",
            "call": "command",
            "literal": "AUTH",
        },
        {
            "count": "drain_audit",
            "path": "inf037b_live.py",
            "method": "RedisAdapter.snapshot",
            "call": "operations",
        },
    ]


def validate_count_sources(rows=None):
    base = Path(__file__).parent
    for row in count_sources() if rows is None else rows:
        tree = ast.parse((base / row["path"]).read_bytes())
        body = tree
        for name in row["method"].split("."):
            body = next(
                n
                for n in body.body
                if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name == name
            )
        matches = [
            n
            for n in ast.walk(body)
            if isinstance(n, ast.Call)
            and (
                (isinstance(n.func, ast.Attribute) and n.func.attr == row["call"])
                or (isinstance(n.func, ast.Name) and n.func.id == row["call"])
            )
        ]
        if "literal" in row:
            matches = [
                n
                for n in matches
                if n.args
                and isinstance(n.args[0], ast.Constant)
                and n.args[0].value == row["literal"]
            ]
        require(bool(matches), "collectors:unsourced_count:" + row["count"])
    return True


def compose(owner, window, bundle, *, resources=(), replacements=None):
    """A source-bound bundle supplies real adapters, never arbitrary periodic code."""
    require(type(bundle) is dict, "capture:unresolved:collector_bindings:" + window.scope)
    required = {"redis", "clocks", "gateways", "kubernetes", "metrics", "native", "lifecycle"}
    require(required <= bundle.keys(), "capture:unresolved:collector_bindings:" + window.scope)
    result = ComposedCollectors(
        owner,
        window,
        resources=resources,
        replacements=replacements,
        **{k: bundle[k] for k in required},
    )
    missing = {name for name, _, _ in result.periodic} - set(owner.sources)
    require(not missing, "collectors:source_inventory")
    return result
