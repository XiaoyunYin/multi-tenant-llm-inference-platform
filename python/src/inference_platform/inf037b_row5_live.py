"""Deployment-neutral row 5 composition over real retained transports.

Both kind and EKS supply independently pinned gateway identities, endpoints,
the existing RoleControl and a CaptureOwner. The preparation sample port MUST
return absolute ``time.monotonic_ns() // 1_000_000`` on this collector host.
The relative-to-start clock in package_a_capture.py must not be reused. Stage
and outage deadlines are nanoseconds on KnownStage.clock, never epoch time.

Gateway configuration captures are sealed before this composition starts (the
diagnostic verifies them on every invocation). Runtime proofs are deferred
until stop_collectors has joined all workers and the runtime owner is sealed.
No checker accepts an open spool. Call poll continuously during GPU bring-up;
the outage also polls on every snapshot and recovery read. No state is written
to Redis by this module. Its wire must already be connected/authenticated.
"""

import copy
import threading
import time
from contextlib import ExitStack

from .inf037b_archive import IntegrityError, encode, sha, strict_json
from .inf037b_capture import DeadlineHTTP, wire_records
from .inf037b_live import ClientSSEAdapter, GatewayAdapter, RedisAdapter
from .inf037b_probe import capture_rows
from .inf037b_row5 import ROW5_KNOWN_CONTROLS
from .inf037b_row5_capture import gateway_prefix_from_capture
from .inf037b_row5_diagnostic import DiagnosticProcess, diagnostic_receipts_from_capture
from .inf037b_row5_sequence import GATEWAYS, KnownStage, OutageSequence
from .inf037b_sources import ClockMapper


class InstallRecovery:
    """Tap the retained measurement reader, before request-binding deferrals.

    The gateway adapter still owns byte-offset/boot/record-sequence validation.
    We independently require contiguous *install* poll_seq, even if all recorder
    sequence numbers are contiguous. Loss is sticky. No source event timestamp
    is compared with a collector timestamp. Locks serialize cursor installation
    with the same adapter polls used by CaptureOwner's collection workers.
    """

    def __init__(self, gateways, *, clock, capture, settle=None):
        self.gateways, self.clock, self.capture = gateways, clock, capture
        self.settle, self.finished = settle, False
        self.lock = threading.RLock()
        self.last = dict.fromkeys(GATEWAYS, 0)
        self.latest = dict.fromkeys(GATEWAYS)
        self.cursor, self.pending, self.complete = None, [], True
        for gateway, adapter in gateways.items():
            if adapter.offset or adapter.seq:
                raise IntegrityError("fitness:recovery_source_incomplete")
            adapter.http = self.Tap(adapter.http, self, gateway)

    class Tap:
        def __init__(self, http, recovery, gateway):
            self.http, self.recovery, self.gateway = http, recovery, gateway

        def get(self, path):
            body, headers = self.http.get(path)
            # The underlying DeadlineHTTP has already retained these bytes.
            for line in body.splitlines():
                raw = strict_json(line)
                if raw.get("event") == "install":
                    self.recovery.install(self.gateway, raw)
            return body, headers

    def install(self, gateway, raw):
        with self.lock:
            data = raw["data"]
            seq = data.get("poll_seq")
            if type(seq) is not int or seq != self.last[gateway] + 1:
                self.complete = False
            if type(seq) is int:
                self.last[gateway] = seq
            error = data.get("error_class")
            reason = (
                "403"
                if isinstance(error, str) and ("403" in error or "forbidden" in error.lower())
                else "unknown"
                if error or data.get("membership_known") is not True
                else None
            )
            members = data.get("members")
            if not isinstance(members, list) or any(
                not isinstance(m, dict)
                or any(type(m.get(k)) is not bool for k in ("ready", "sampled", "healthy"))
                for m in members
            ):
                self.complete = False
                members = []
            n = sum(m["ready"] and m["sampled"] and m["healthy"] for m in members)
            self.latest[gateway] = reason is None and n == 2
            if self.cursor is not None:
                read_ns = self.clock()
                self.pending.append(
                    {
                        "gateway_uid": gateway,
                        "poll_seq": seq,
                        "time_ms": read_ns // 1_000_000,
                        "read_mono_ns": read_ns,
                        "time_clock": "collector_monotonic",
                        "source_event_ns": raw["mono_ns"],
                        "known": all(self.latest.values()),
                        "reason": reason or (None if all(self.latest.values()) else "unknown"),
                        "n": n,
                        "effective_b": 5 * n,
                    }
                )

    def start(self, deadline):
        if self.cursor is not None:
            return
        with ExitStack() as stack:
            for adapter in self.gateways.values():
                stack.enter_context(adapter.poll_lock)
            for adapter in self.gateways.values():
                adapter.poll()
            with self.lock:
                self.cursor = copy.deepcopy(self.last)
                self.complete &= all(seq > 0 for seq in self.cursor.values())
                self.latest = dict.fromkeys(GATEWAYS)

    def __call__(self, deadline):
        if not self.finished:
            for adapter in self.gateways.values():
                if self.clock() >= deadline:
                    raise IntegrityError("fitness:row5_stage_deadline")
                adapter.poll()
        with self.lock:
            observations, self.pending = self.pending, []
            return {
                "source_complete": self.cursor is not None
                and self.complete
                and not self.capture.failed
                and not any(a.lost for a in self.gateways.values()),
                "cursors": copy.deepcopy(self.cursor),
                "last_poll_seq": copy.deepcopy(self.last),
                "observations": observations,
            }

    def finish(self, deadline):
        if self.settle is not None:
            self.settle()
            self.finished = True


class RetainedClient:
    def __init__(self, adapter):
        self.adapter, self.requests = adapter, {}

    def request(self, **arguments):
        rows = self.adapter.request(**arguments)
        offer = arguments["offer"]
        ids = [k for k, v in self.adapter.request_ids.items() if v == offer["request_id"]]
        if len(ids) != 1 or any(row.get("error") for row in rows):
            raise IntegrityError("fitness:row5_client_capture")
        self.requests[offer["request_id"]] = {
            "gateway_request_id": ids[0],
            "start_ns": rows[0]["capture_start_mono_ns"],
            "end_ns": rows[-1]["capture_end_mono_ns"],
        }
        return rows


class Row5RedisRows:
    """Normalize TTL-bound reports before the owner's immutable append.

    RedisAdapter labels control snapshots, but their unnamed after-snapshots
    need the identical stored-time representation for interval comparisons.
    """

    def __init__(self, rows):
        self.rows = rows

    def __getattr__(self, name):
        return getattr(self.rows, name)

    def row(self, kind, identity, generation, event, fields, **arguments):
        if event == "snapshot":
            fields = copy.deepcopy(fields)
            for report in fields["reports"].values():
                report["stored_ms"] = report["expires_ms"] - 8000
        return self.rows.row(kind, identity, generation, event, fields, **arguments)


class LiveRow5:
    """Construct row5_stage and outage-only row5_control for either deployment.

    gateways maps gateway_uid to {source, boot, http, client_source, request}.
    http contains DeadlineHTTP's base/CA/token/local_test options; request holds
    ClientSSEAdapter.request's url/payload/credential/TLS options. Source names
    and generations must already be in the owner's immutable source inventory.
    stop_collectors must join workers without closing owner; poll is serialized
    and may also be registered as an owner periodic action. Configuration
    captures have the exact DiagnosticProcess.run_from_captures argument shape.
    """

    def __init__(
        self,
        *,
        owner,
        redis_wire,
        redis_source,
        redis_gateway_ids,
        gateways,
        slots,
        role,
        binary,
        binary_sha256,
        diagnostic_source,
        dial_addr,
        config,
        gateway_config_captures,
        measured_tenants,
        configuration_sha256,
        stop_ns,
        stop_collectors,
        final_clocks=None,
        step_timing=None,
        clock=time.monotonic_ns,
        sleep=time.sleep,
    ):
        if set(gateways) != set(GATEWAYS):
            raise IntegrityError("fitness:row5_gateway_inventory")
        # TLS contexts and callbacks are transport ports; copy request data,
        # while preserving those resources' identity.
        self.owner, self.spec, self.stop_collectors = (
            owner,
            {
                g: {
                    **spec,
                    "http": dict(spec["http"]),
                    "request": {
                        key: value if key in {"context", "tls_observer"} else copy.deepcopy(value)
                        for key, value in spec["request"].items()
                    },
                }
                for g, spec in gateways.items()
            },
            stop_collectors,
        )
        self.lock, self.rows, self.descriptor = threading.RLock(), None, None
        self.clock = clock
        self.first_poll_ns = None
        self.require_window_start = False
        self.window_start_mono_ns = None
        self.settled = False
        self.final_clocks = final_clocks
        self.stage_snapshots = {}
        self.config_captures = copy.deepcopy(gateway_config_captures)
        self.config = copy.deepcopy(config)
        self.diagnostic_source = diagnostic_source
        self.diagnostic_generation = owner.sources[diagnostic_source][0][2]
        self.reservations = {}
        redis_wire.retain = owner.retainer(redis_source)
        redis_wire.barrier = redis_wire.retain.barrier
        self.redis = RedisAdapter(
            Row5RedisRows(owner.rows(redis_source)),
            redis_wire,
            config["namespace"],
            configuration_sha256,
            reservations=self.reservations,
            report_ttl_ms=8000,
        )
        self.redis.gateway_ids = dict(redis_gateway_ids)
        self.redis.ordered_snapshots = True
        self.clients, self.gateways = {}, {}
        for gateway, spec in gateways.items():
            client = ClientSSEAdapter(
                owner.rows(spec["client_source"]),
                gateway,
                configuration_sha256,
                retain=owner.retainer(spec["client_source"]),
            )
            self.clients[gateway] = RetainedClient(client)
            self.gateways[gateway] = GatewayAdapter(
                owner.rows(spec["source"]),
                DeadlineHTTP(
                    **spec["http"], stop_ns=stop_ns, retain=owner.retainer(spec["source"])
                ),
                gateway,
                slot_names=slots,
                config_sha256=configuration_sha256,
                request_ids=client.request_ids,
                reservations=self.reservations,
                defer_request_bindings=True,
            )
        self.diagnostic = DiagnosticProcess(
            binary=binary,
            binary_sha256=binary_sha256,
            capture=owner,
            source=diagnostic_source,
            redis=self.redis,
            dial_addr=dial_addr,
            clock=clock,
        )
        self.recovery = InstallRecovery(
            self.gateways, clock=clock, capture=owner, settle=self.settle
        )
        composition = self

        class Snapshots:
            def snapshot(self, **arguments):
                with composition.lock:
                    composition.poll()
                    row = composition.redis.snapshot(**arguments)
                    snapshot_id = arguments.get("snapshot_id")
                    if row is not None and snapshot_id is not None:
                        composition.stage_snapshots[snapshot_id] = row
                    return row

        self.row5_stage = KnownStage(
            redis=Snapshots(),
            clients=self.clients,
            diagnostic=self.diagnostic,
            request_arguments=lambda g: self.spec[g]["request"],
            diagnostic_arguments=lambda: {
                "config": self.config,
                "gateway_captures": self.config_captures,
                "measured_tenants": measured_tenants,
            },
            proof_inputs=self.proof_inputs,
            configuration_sha256=configuration_sha256,
            clock=clock,
            sleep=sleep,
            defer_proofs=True,
        )
        self.row5_control = OutageSequence(
            stage=self.row5_stage,
            role=role,
            recovery=self.recovery,
            capture=self.capture,
            step_timing=step_timing,
        )

    def poll(self):
        with self.lock:
            if self.first_poll_ns is None:
                self.first_poll_ns = self.clock()
            if self.require_window_start and self.window_start_mono_ns is None:
                raise IntegrityError("fitness:row5_window_start_missing")
            for gateway, adapter in self.gateways.items():
                adapter.poll()
                if adapter.boot not in (None, self.spec[gateway]["boot"]) or adapter.lost:
                    raise IntegrityError("fitness:row5_gateway_capture")
            self.redis.flush_snapshots()
            self.redis.operations()
            if self.redis.lost or self.owner.failed:
                raise IntegrityError("fitness:row5_capture")

    def binding(self, source, **identity):
        return {
            "root": str(self.owner.root),
            "descriptor": self.descriptor,
            "expected_binding": self.owner.binding,
            "expected_operation": self.owner.operation,
            "expected_descriptor_sha256": self.descriptor_sha256,
            "source": source,
            **identity,
        }

    def gateway_binding(self, gateway):
        spec = self.spec[gateway]
        return self.binding(spec["source"], gateway_uid=gateway, gateway_boot=spec["boot"])

    def bounds(self, start, end):
        bounds = self.clocks.inverse(
            "redis", "redis", start // 1_000_000, (end + 999_999) // 1_000_000
        )
        if bounds is None or self.clocks.errors:
            raise IntegrityError("fitness:refusal_clock")
        return bounds

    def proof_inputs(self, name, gateway, offer, snapshot, after, receipt):
        if self.rows is None:
            raise IntegrityError("fitness:row5_unsealed_capture")
        for row in (snapshot, after):
            bound = [r for r in self.rows if r["record_id"] == row["record_id"]]
            if len(bound) != 1 or any(bound[0].get(k) != v for k, v in row.items()):
                raise IntegrityError("fitness:row5_snapshot_capture")
        lo, hi = snapshot["payload"]["store_order"], after["payload"]["store_order"]
        operations = [
            r
            for r in self.rows
            if r["source_kind"] == "redis"
            and r["payload"]["event"] != "snapshot"
            and lo < r["payload"].get("store_order", -1) <= hi
        ]
        ids = [k for k, v in self.reservations.items() if v is not None]
        if gateway is None:
            matches = [r for r in self.receipts if r["reservation_id"] == receipt["reservation_id"]]
            if len(matches) != 1:
                raise IntegrityError("fitness:row5_diagnostic_receipt")
            captured = matches[0]
            return {
                "redis_operations": operations,
                "gateway_ids": ids,
                "diagnostic_redis_bounds": self.bounds(
                    captured["process_start_ns"], captured["process_end_ns"]
                ),
                "process_start_ns": captured["process_start_ns"],
                "process_end_ns": captured["process_end_ns"],
                "collector_boot_id": self.owner.boot,
            }
        client = self.clients[gateway].requests[offer["request_id"]]
        records = [
            (r, b)
            for r, b in wire_records(self.owner.root / "wire")
            if r["source"] == self.spec[gateway]["client_source"]
            and r["start_ns"] == client["start_ns"]
        ]
        headers = [r["metadata"]["headers"] for r, _ in records if "headers" in r["metadata"]]
        terminals = [r for r, _ in records if r["metadata"].get("client_request_end") is True]
        if (
            len(headers) != 1
            or len(terminals) != 1
            or [v for k, v in headers[0] if k.lower() == "x-request-id"]
            != [client["gateway_request_id"]]
            or any(r["metadata"].get("error") for r, _ in records)
        ):
            raise IntegrityError("fitness:row5_client_capture")
        request_end = terminals[0]["end_ns"]
        if request_end < client["end_ns"]:
            raise IntegrityError("fitness:row5_client_end_order")
        common = {"redis_operations": operations, "diagnostic_receipts": self.receipts}
        binding = self.gateway_binding(gateway)
        if name not in ROW5_KNOWN_CONTROLS:
            return {
                **common,
                "gateway_capture": binding,
                "client_capture": self.binding(
                    self.spec[gateway]["client_source"],
                    client_identity="client:" + gateway,
                    client_boot=self.owner.boot,
                ),
                "gateway_request_id": client["gateway_request_id"],
                "request_start_ns": client["start_ns"],
                "request_end_ns": request_end,
                "collector_boot_id": self.owner.boot,
                "clocks": self.clocks,
                "redis_boot": "redis",
            }
        admits = [
            r
            for r in self.rows
            if r["source_kind"] == "gateway"
            and r["payload"].get("event") == "admit"
            and r["payload"].get("gateway_uid") == gateway
            and r["payload"].get("request_id") == offer["request_id"]
        ]
        if len(admits) != 1:
            raise IntegrityError("fitness:control_admit_join")
        return {
            **common,
            "gateway": admits[0],
            "gateway_boot": self.spec[gateway]["boot"],
            "gateway_request_id": client["gateway_request_id"],
            "request_start_ns": client["start_ns"],
            "request_end_ns": request_end,
            "collector_boot_id": self.owner.boot,
            "raw_gateway_prefix": gateway_prefix_from_capture(**binding),
            "gateway_reservations": ids,
            "gateway_redis_bounds": self.bounds(client["start_ns"], request_end),
        }

    def settle(self):
        if not self.settled:
            self.stop_collectors()
            self.poll()
            if self.final_clocks is not None:
                self.final_clocks()
            self.settled = True

    def capture(self, prepared):
        self.settle()
        descriptor = self.owner.close()
        with self.owner.store.lock():
            trusted = self.owner.store.read()["capture"]
        if trusted != descriptor:
            raise IntegrityError("fitness:row5_capture_descriptor")
        self.descriptor, self.descriptor_sha256 = descriptor, sha(encode(trusted))
        self.rows = list(capture_rows(self.owner.root, descriptor))
        self.clocks = ClockMapper(self.rows)
        self.receipts = diagnostic_receipts_from_capture(
            **self.binding(self.diagnostic_source),
            source_generation=self.diagnostic_generation,
            binary_sha256=self.diagnostic.binary_sha256,
            gateway_configs={g: self.config for g in GATEWAYS},
        )
        base = strict_json(prepared["fitness_raw"])
        raw = {k: base[k] for k in ("schema", "session_id", "pins", "t0_ms")}
        raw["raw"] = self.rows
        return {
            "fitness_raw": encode(raw),
            "artifacts": {},
            "row5_evidence": {
                "gateway_config_captures": {g: self.gateway_binding(g) for g in GATEWAYS},
                "gateway_reservation_ids": [
                    k for k, v in self.reservations.items() if v is not None
                ],
            },
        }
