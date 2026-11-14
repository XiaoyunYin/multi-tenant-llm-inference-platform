"""Importable kind row 5 ports and proofs; no deployment commands or engine claims."""

import copy
import time
from dataclasses import dataclass
from pathlib import Path

from .inf037b_archive import IntegrityError, encode, sha, strict_json
from .inf037b_capture import CaptureOwner, DeadlineHTTP
from .inf037b_live import ClockAdapter
from .inf037b_row5 import validate_control_evidence
from .inf037b_row5_capture import gateway_resolved_config_from_capture, select_row5_snapshots
from .inf037b_row5_diagnostic import parse_dial_addr
from .inf037b_row5_live import LiveRow5
from .inf037b_row5_sequence import GATEWAYS
from .inf037b_setup_fitness import check_restoration_hold, fitness_request_joins
from .inf037b_sources import ClockMapper, SourceJoin


@dataclass
class KindRow5Ports:
    owner: CaptureOwner
    live: LiveRow5
    clocks: ClockAdapter
    clock_http: dict
    window_start_attempted: bool = False
    window_start: dict | None = None

    def __post_init__(self):
        self.live.require_window_start = True

    @staticmethod
    def sample():
        return time.monotonic_ns() // 1_000_000

    def poll_clocks(self):
        # Clock queries do not read/advance the measurement event stream.
        rows = {"redis": self.clocks.redis(self.live.redis.wire)}
        rows.update(
            {
                gateway: self.clocks.gateway(http, gateway)
                for gateway, http in self.clock_http.items()
            }
        )
        return rows

    def start_window(self):
        if self.window_start_attempted:
            raise IntegrityError("fitness:row5_window_start_duplicate")
        self.window_start_attempted = True
        if self.live.first_poll_ns is not None:
            raise IntegrityError("fitness:row5_window_start_after_poll")
        sample_start_ns = self.live.clock()
        rows = self.poll_clocks()
        sample_end_ns = self.live.clock()
        if set(rows) != {"redis", *GATEWAYS}:
            raise IntegrityError("fitness:row5_window_start_inventory")
        mappings = {}
        for clock_id, row in rows.items():
            payload = row["payload"]
            if payload["event"] != "mapping":
                raise IntegrityError("fitness:row5_window_start_clock:" + clock_id)
            mappings[clock_id] = {
                key: payload[key]
                for key in (
                    "clock_id",
                    "boot_id",
                    "remote_ms",
                    "local_mono_ms",
                    "local_wall_ms",
                    "send_ms",
                    "receive_ms",
                )
            }
        self.live.redis.capture_start_remote_ms = mappings["redis"]["remote_ms"]
        for gateway in GATEWAYS:
            self.live.gateways[gateway].capture_start_remote_ms = mappings[gateway]["remote_ms"]
        self.window_start = {
            "sample_start_mono_ns": sample_start_ns,
            "sample_end_mono_ns": sample_end_ns,
            "mappings": mappings,
        }
        self.live.window_start_mono_ns = sample_end_ns
        return copy.deepcopy(self.window_start)

    def assert_window_before_known0(self, first_action_ns):
        if self.window_start is None:
            raise IntegrityError("fitness:row5_window_start_missing")
        if self.window_start["sample_end_mono_ns"] >= first_action_ns:
            raise IntegrityError("fitness:row5_window_start_after_known0")

    def window_summary(self):
        return {
            "row5_window_start": copy.deepcopy(self.window_start),
            "row5_prewindow_skipped_counts": {
                **{
                    gateway: dict(
                        sorted(self.live.gateways[gateway].prewindow_skipped_counts.items())
                    )
                    for gateway in GATEWAYS
                },
                "redis": dict(sorted(self.live.redis.prewindow_skipped_counts.items())),
            },
        }


class WindowStartStage:
    """Check the shared clock window before KnownStage's first action."""

    def __init__(self, stage, ports):
        self.stage, self.ports = stage, ports

    def __getattr__(self, name):
        return getattr(self.stage, name)

    def __call__(self, name, stop_ns):
        if name == "known0":
            self.ports.assert_window_before_known0(self.ports.live.clock())
        return self.stage(name, stop_ns)


def row5_runtime_sources(gateway_boots, boot):
    """One source inventory for the durable operation and runtime owner."""
    if set(gateway_boots) != set(GATEWAYS):
        raise IntegrityError("fitness:row5_gateway_inventory")
    return {
        **{g: [["gateway", g, gateway_boots[g]]] for g in GATEWAYS},
        **{"client:" + g: [["client", "client:" + g, boot]] for g in GATEWAYS},
        "redis": [["redis", "redis", "redis"]],
        "diagnostic": [["controller", "operator", boot]],
        "rbac": [["controller", "operator-rbac", boot]],
        "clocks": [["clocks", "clock:redis", "redis"]]
        + [["clocks", "clock:" + g, gateway_boots[g]] for g in GATEWAYS],
    }


def retain_row5_role(owner_holder, *args, **kwargs):
    """Bind RBAC wire retention after the shared runtime owner is constructed."""
    owner = owner_holder.get("owner")
    if owner is None:
        raise IntegrityError("fitness:row5_capture_owner_unbound")
    owner.retainer("rbac")(*args, **kwargs)


def retain_kind_row5_inputs(output, control_result, all_requests):
    """Persist the replay inputs before any validator can refuse.

    These are evidence, offers and cutoff provenance, never HTTP options or credentials.
    fitness_raw is already retained in the owner's closed row files.
    """
    keys = (
        "row5_evidence",
        "row5_control_requests",
        "row5_window_start",
        "row5_prewindow_skipped_counts",
        "row5_recovery_batches",
    )
    (Path(output) / "row5-control-result.json").write_bytes(
        encode({k: control_result[k] for k in keys})
    )
    (Path(output) / "row5-all-requests.json").write_bytes(encode(all_requests))


def validate_retained_kind_row5(output, control_result, all_requests, **arguments):
    retain_kind_row5_inputs(output, control_result, all_requests)
    return validate_kind_row5(control_result, all_requests, **arguments)


def retain_kind_row5_inputs_before_proofs(output, ports):
    """Retain the exact staged offer list and evidence before deferred proofs run."""

    def retain(control_result, _outage_requests):
        control_result.update(ports.window_summary())
        all_requests = list(ports.live.row5_stage.requests)
        retain_kind_row5_inputs(output, control_result, all_requests)

    return retain


class TimedRole:
    """Add collector invocation brackets to the existing RoleControl actions."""

    def __init__(self, role, clock):
        self.role, self.clock = role, clock

    def __getattr__(self, name):
        return getattr(self.role, name)

    def act(self, phase, **arguments):
        start, count = self.clock(), len(self.role.actuations)
        try:
            return getattr(self.role, phase)(**arguments)
        finally:
            end = self.clock()
            for action in self.role.actuations[count:]:
                action.update(start_ns=start, end_ns=end)

    def revoke(self, **arguments):
        return self.act("revoke", **arguments)

    def restore(self, **arguments):
        return self.act("restore", **arguments)


def kind_row5_ports(
    *,
    store,
    operation_store,
    operation,
    binding,
    root,
    gateways,
    gateway_configuration_owner,
    dial_addr,
    step_timing=None,
    boot_path=Path("/proc/sys/kernel/random/boot_id"),
    **live_arguments,
):
    """Seal the startup owner, then open one setup owner for all runtime ports.

    The caller pins this exact source inventory in its durable operation, drives
    poll_clocks at <=2 s spacing around all events, polls live continuously and
    supplies stop_collectors that joins those workers. Clock HTTP only requests
    ?clock=1; LiveRow5's adapters alone request ?offset=... .
    """
    if set(gateways) != set(GATEWAYS):
        raise IntegrityError("fitness:row5_gateway_inventory")
    dial_host, dial_port = parse_dial_addr(dial_addr)
    redis_wire = live_arguments.get("redis_wire")
    if (
        redis_wire is None
        or getattr(redis_wire, "host", None) != dial_host
        or type(getattr(redis_wire, "port", None)) is not int
        or redis_wire.port != dial_port
    ):
        raise IntegrityError("fitness:diagnostic_dial_addr_mismatch")
    boot = boot_path.read_text().strip()
    sources = row5_runtime_sources({g: gateways[g]["boot"] for g in GATEWAYS}, boot)
    descriptor = gateway_configuration_owner.close()
    captures = {}
    for g in GATEWAYS:
        captures[g] = {
            "root": str(gateway_configuration_owner.root),
            "descriptor": descriptor,
            "expected_binding": binding,
            "expected_operation": gateway_configuration_owner.operation,
            "expected_descriptor_sha256": sha(encode(descriptor)),
            "source": g,
            "gateway_uid": g,
            "gateway_boot": gateways[g]["boot"],
        }
        gateway_resolved_config_from_capture(**captures[g])
        # DiagnosticProcess keys gateways by the enclosing mapping.
        del captures[g]["gateway_uid"]
    owner = CaptureOwner(
        store=store,
        operation_store=operation_store,
        operation=operation,
        binding=binding,
        root=root,
        sources=sources,
        attempt="setup",
        stages=[1, 2, 3, 4, 5],
        boot_path=boot_path,
    )
    for g in GATEWAYS:
        owner.rows(g).row5_single_reader = True
    specs = {g: {**gateways[g], "source": g, "client_source": "client:" + g} for g in GATEWAYS}
    live_arguments = dict(live_arguments)
    live_arguments["step_timing"] = step_timing
    live_arguments["role"] = TimedRole(
        live_arguments["role"], live_arguments.get("clock", time.monotonic_ns)
    )
    live = LiveRow5(
        owner=owner,
        gateways=specs,
        redis_source="redis",
        diagnostic_source="diagnostic",
        dial_addr=dial_addr,
        gateway_config_captures=captures,
        **live_arguments,
    )
    clocks = ClockAdapter(owner.rows("clocks"))
    clock_http = {
        g: DeadlineHTTP(
            **gateways[g]["http"],
            stop_ns=live_arguments["stop_ns"],
            retain=owner.retainer("clocks"),
        )
        for g in GATEWAYS
    }
    ports = KindRow5Ports(owner, live, clocks, clock_http)
    live.row5_stage = WindowStartStage(live.row5_stage, ports)
    live.row5_control.stage = live.row5_stage
    live.final_clocks = ports.poll_clocks
    return ports


def validate_kind_row5(result, control_requests, *, configuration_sha256, binding):
    """Use precisely the row 5 branch, without native engines or a probe claim."""
    raw = strict_json(result["fitness_raw"])["raw"]
    join = SourceJoin(raw)
    if join.errors:
        raise IntegrityError("setup:source_join")
    rows = join.rows
    snapshots = select_row5_snapshots(rows)
    check_restoration_hold(snapshots, rows, 2000)
    _, control = fitness_request_joins(
        rows, [], control_requests, max(r["time_ms_bounds"][1] for r in rows)
    )
    return validate_control_evidence(
        result["row5_evidence"],
        control_requests,
        configuration_sha256=configuration_sha256,
        binding={k: binding[k] for k in ("session_id", "pins", "t0_ms")},
        snapshots=snapshots,
        rows=rows,
        control_cohorts=control.cohorts,
    )


def row5_timings(rows, evidence):
    """Outward ms intervals on the collector clock, never cross-clock subtraction.

    Revoke/restore use action start (before the mutation); restore_outcome start
    also includes the retained recovery cursor read. Instants with uncertainty
    overlapping the action cannot establish an after-action event and refuse.
    The spread is the absolute difference of the two mapped last-store times.
    """
    clocks = ClockMapper(rows)

    def mapped(clock, boot, lo, hi):
        value = clocks.map(clock, boot, lo, hi)
        if value is None or clocks.errors:
            raise IntegrityError("fitness:row5_timing_clock")
        return value

    def event_time(row):
        source = row["source_time"]
        return mapped(
            source["clock_id"], row["source_generation"], source["value"], source["value"]
        )

    def collector(ns):
        return [ns // 1_000_000, (ns + 999_999) // 1_000_000]

    def delta(end, start):
        return [end[0] - start[1], end[1] - start[0]]

    revoke = collector(evidence["rbac"]["actions"][0]["start_ns"])
    restore = collector(evidence["restore_outcome"]["start_ns"])
    stores = [mapped("redis", "redis", at, at) for at in evidence["last_known_stores_ms"].values()]
    diff = delta(stores[1], stores[0])
    spread = [max(0, diff[0], -diff[1]), max(abs(v) for v in diff)]
    result = {}
    for gateway in GATEWAYS:
        installs = sorted(
            (
                r
                for r in rows
                if r["source_kind"] == "gateway"
                and r["source_identity"] == gateway
                and r["payload"]["event"] == "install"
            ),
            key=lambda r: r["source_seq"],
        )

        def first(candidates, start):
            for row in candidates:
                at = event_time(row)
                if at[1] < start[0]:
                    continue
                if at[0] < start[1]:
                    raise IntegrityError("fitness:row5_timing_clock")
                return delta(at, start)
            raise IntegrityError("fitness:row5_timing_clock")

        forbidden = [
            r
            for r in installs
            if "403" in (r["payload"].get("error_class") or "")
            or "forbidden" in (r["payload"].get("error_class") or "").lower()
        ]
        success = [
            r
            for r in installs
            if r["payload"].get("error_class") == ""
            and r["payload"].get("membership_known") is True
        ]
        known2 = sorted(
            (
                r
                for r in rows
                if r["source_kind"] == "redis"
                and r["payload"].get("event") == "report_store"
                and r["payload"].get("gateway_uid") == gateway
                and r["payload"].get("report_known") is True
                and r["payload"].get("n") == 2
            ),
            key=lambda r: r["payload"]["store_order"],
        )
        result[gateway] = {
            "revoke_to_first_403_ms": first(forbidden, revoke),
            "last_known_store_spread_ms": spread[:],
            "restore_to_first_successful_install_ms": first(success, restore),
            "restore_to_first_known2_store_ms": first(known2, restore),
        }
    return result
