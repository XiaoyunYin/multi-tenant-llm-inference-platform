"""Live transports into the accepted v3 collectors; no AWS client or paid path.

Original responses must be kept in the secured spool. Normalization never
substitutes a failed observation with zero or reuses a previous healthy value.
"""

import copy
import hashlib
import http.client
import ipaddress
import json
import math
import re
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from functools import wraps

from .inf037b_archive import IntegrityError, encode, envelope, sha, strict_json
from .inf037b_contract import SESSION_ENVELOPE_MS
from .inf037b_engine import cache_config
from .inf037b_producer_contracts import (
    AUDIT_SCRIPT,
    SSEBudget,
    audit_reply_contract,
    check_audit,
    client_contract,
    client_error_text,
    guarded_response,
    redis_scope_contract,
)
from .inf037b_producer_limits import (
    CLIENT_DENIAL_BYTES,
    CLIENT_PENDING_BYTES,
    RESP_ARRAY_ELEMENTS,
    RESP_BULK_BYTES,
    RESP_LINE_BYTES,
    ProducerLimit,
    ReplyBudget,
    refuse,
    resp_contract,
)
from .inf037b_requests import SSEDecoder
from .inf037b_sources import FIELDS, validate_payload
from .inf037b_wire_units import UnitReads, UnitRecorder
from .r1_spec import parse_engine_argv

REQUEST_TIMEOUT_SECONDS = 30
REDIS_CAPTURE_SOCKET_TIMEOUT_S = 1
_RESERVATION_LOCK = threading.RLock()

_PREWINDOW_GATEWAY_EVENTS = frozenset(
    {
        "capture_start",
        "admission_config",
        "health",
        "install",
        "poll_start",
        "report_intent",
        "report_result",
    }
)
_PREWINDOW_REDIS_EVENTS = frozenset({"report_store", "unknown"})


def _count_prewindow(counts, event):
    counts[event] = counts.get(event, 0) + 1


class WatchCutoff(Exception):
    """Owned transport reached its absolute cutoff without an earlier loss."""


class LiveRows:
    """One collector boot, explicit source boots and independent raw provenance."""

    def __init__(
        self,
        session,
        collector_boot,
        *,
        attempt=1,
        clock=time.monotonic_ns,
        sink=None,
        on_loss=None,
    ):
        self.session, self.boot, self.attempt = session, collector_boot, attempt
        self.clock, self.sink = clock, sink
        self.sequence = {}
        self.lock, self.on_loss = threading.Lock(), on_loss

    def row(self, *args, **kwargs):
        if kwargs.get("error") is not None and self.on_loss:
            self.on_loss()
        try:
            with self.lock:
                return self._row(*args, **kwargs)
        except Exception:
            if self.on_loss:
                self.on_loss()
            raise

    def _row(
        self,
        kind,
        identity,
        generation,
        event,
        fields,
        *,
        source_ms=None,
        clock_id="measurement",
        start_ns=None,
        end_ns=None,
        error=None,
        time_bounds=None,
    ):
        start = self.clock() if start_ns is None else start_ns
        end = self.clock() if end_ns is None else end_ns
        if end < start:
            raise IntegrityError("reversed_live_capture")
        key = (kind, identity, generation)
        seq = self.sequence.get(key, 0)
        payload = dict.fromkeys(FIELDS[kind].split())
        payload.update(copy.deepcopy(fields), event=event)
        payload["field_reasons"] = {
            name: "not_observed_due_to_capture_error"
            if error
            else ("unavailable_from_source" if name in fields else "not_applicable_to_event")
            for name, value in payload.items()
            if value is None
        }
        row = envelope(payload, seq=seq, attempt=self.attempt)
        row.update(
            session_id=self.session,
            source_kind=kind,
            source_identity=identity,
            source_generation=generation,
            record_id=f"{identity}:{generation}:{seq}",
            collector_id="inf037b-live-v1",
            collector_boot_id=self.boot,
            observed_mono_ns=self.clock(),
            capture_start_mono_ns=start,
            capture_end_mono_ns=end,
            observed_wall_utc=datetime.now(UTC).isoformat(),
            uncertainty_ns=end - start,
            source_time={
                "clock_id": clock_id,
                "unit": "ms",
                "value": source_ms if source_ms is not None else end // 1_000_000,
            },
            missing_reason=None,
            error=error,
        )
        if time_bounds is not None:
            lower, upper = time_bounds
            if type(lower) is not int or type(upper) is not int or not 0 <= lower <= upper:
                raise IntegrityError("invalid_mapped_live_bounds")
            middle = (lower + upper) // 2
            row["source_time"] = {"clock_id": "measurement", "unit": "ms", "value": middle}
            row["uncertainty_ns"] = max(middle - lower, upper - middle) * 1_000_000
        validate_payload(row)
        if self.sink:
            self.sink(row)
        self.sequence[key] = seq + 1
        return row


class HTTP:
    """Bounded authenticated HTTPS; redirects are capture failures, never retried."""

    def __init__(
        self,
        base,
        *,
        token=None,
        ca=None,
        local_test=False,
        internal=False,
        timeout=1,
        watch_timeout=7200,
        retain=None,
    ):
        url = urllib.parse.urlsplit(base)
        allowed_internal = False
        if internal:
            try:
                allowed_internal = ipaddress.ip_address(url.hostname).is_private
            except ValueError:
                allowed_internal = url.hostname.endswith(".svc") or url.hostname.endswith(
                    ".svc.cluster.local"
                )
        if (
            url.scheme != "https"
            and not allowed_internal
            and not (
                local_test
                and url.scheme == "http"
                and url.hostname in ("localhost", "127.0.0.1", "::1")
            )
        ):
            raise ValueError("live_source_requires_tls")
        self.base, self.token, self.timeout, self.watch_timeout, self.retain = (
            base.rstrip("/"),
            token,
            timeout,
            watch_timeout,
            retain,
        )
        context = ssl.create_default_context(cafile=ca)

        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None

        self.opener = urllib.request.build_opener(
            NoRedirect(), urllib.request.HTTPSHandler(context=context)
        )

    def get(self, path):
        headers = {"Authorization": "Bearer " + self.token()} if self.token else {}
        request = urllib.request.Request(self.base + path, headers=headers)
        start = time.monotonic_ns()
        with self.opener.open(request, timeout=self.timeout) as response:
            body = response.read(8_388_609)
            if len(body) > 8_388_608:
                raise IntegrityError("source_response_oversize")
            if self.retain:
                self.retain(path, start, time.monotonic_ns(), body)
            return body, dict(response.headers)

    def watch(self, path):
        headers = {"Authorization": "Bearer " + self.token()} if self.token else {}
        return self.opener.open(
            urllib.request.Request(self.base + path, headers=headers), timeout=self.watch_timeout
        )

    def lines(self, path, *, max_line=1_048_576):
        """Yield bounded raw watch lines; EOF and read errors remain visible."""
        with self.watch(path) as response:
            pending = bytearray()
            while True:
                start = time.monotonic_ns()
                chunk = response.read1(min(max_line + 1, 65_536))
                end = time.monotonic_ns()
                if not chunk:
                    if pending:
                        raise IntegrityError("kubernetes_watch_truncated_line")
                    return
                if self.retain:
                    self.retain(path, start, end, chunk)
                pending.extend(chunk)
                while True:
                    newline = pending.find(b"\n")
                    if newline < 0:
                        if len(pending) > max_line:
                            raise IntegrityError("kubernetes_watch_line_oversize")
                        break
                    if newline + 1 > max_line:
                        raise IntegrityError("kubernetes_watch_line_oversize")
                    line = bytes(pending[: newline + 1])
                    del pending[: newline + 1]
                    yield line


class GatewayAdapter:
    def __init__(
        self,
        rows,
        http,
        gateway,
        *,
        slot_names,
        config_sha256,
        clocks=None,
        request_ids=None,
        replacement_uid=None,
        capture_start_remote_ms=0,
        defer_request_bindings=False,
        reservations=None,
    ):
        # A composition can reserve a source for its sole measurement reader.
        # Register even before that reservation so an existing reader is visible.
        with rows.lock:
            readers = getattr(rows, "gateway_readers", [])
            if getattr(rows, "row5_single_reader", False) and readers:
                raise IntegrityError("fitness:row5_second_stream_reader")
            rows.gateway_readers = [*readers, self]
        self.rows, self.http, self.gateway = rows, http, gateway
        self.slots, self.config, self.clocks = slot_names, config_sha256, clocks
        self.offset, self.seq, self.boot, self.lost = 0, 0, None, False
        self.reservations = reservations if reservations is not None else {}
        self.request_ids = request_ids if request_ids is not None else {}
        self.replacement_uid = replacement_uid
        self.capture_start_remote_ms = capture_start_remote_ms
        self.prewindow_skipped_counts = {}
        self.admit_requests = set()
        self.defer_request_bindings, self.pending = defer_request_bindings, []
        self.poll_lock = threading.RLock()

    def poll(self):
        with self.poll_lock:
            return self._poll()

    def _poll(self):
        start = self.rows.clock()
        try:
            if self.lost:
                raise IntegrityError("gateway_capture_previously_lost")
            body, headers = self.http.get(f"/internal/measurement?offset={self.offset}")
            boot = headers["X-Capture-Boot"]
            next_offset = int(headers["X-Capture-Next"])
            if self.boot not in (None, boot) or next_offset != self.offset + len(body):
                raise IntegrityError("gateway_capture_rotated_or_lost")
            self.boot = boot
            output = []
            end = self.rows.clock()
            for line in body.splitlines():
                raw = strict_json(line)
                if (
                    raw["schema"] != "gateway-measurement-v1"
                    or raw["sequence"] != self.seq
                    or raw["boot_id"] != boot
                ):
                    raise IntegrityError("gateway_capture_sequence_gap")
                self.seq += 1
                self.pending.append((raw, start, end))
            self.offset = next_offset
            if sum(len(json.dumps(raw)) for raw, _, _ in self.pending) > 8_388_608:
                raise IntegrityError("gateway_unjoined_buffer_limit")
            consumed = 0
            for raw, captured_start, captured_end in self.pending:
                event, data = raw["event"], raw["data"]
                if raw["mono_ns"] // 1_000_000 < self.capture_start_remote_ms:
                    if event not in _PREWINDOW_GATEWAY_EVENTS:
                        raise IntegrityError("fitness:row5_prewindow_evidence")
                    _count_prewindow(self.prewindow_skipped_counts, event)
                    consumed += 1
                    continue
                if (
                    self.defer_request_bindings
                    and event not in ("capture_start", "capture_end", "terminal")
                    and data.get("request_id")
                    and data["request_id"] not in self.request_ids
                ):
                    break  # Raw bytes are durable; wait for the actual response-ID bijection.
                consumed += 1
                event, data = raw["event"], raw["data"]
                if data.get("reservation_id") and data.get("request_id"):
                    reservation = data["reservation_id"]
                    request = self.request_ids.get(data["request_id"], data["request_id"])
                    with _RESERVATION_LOCK:
                        if (
                            reservation in self.reservations
                            and self.reservations[reservation] != request
                        ):
                            reason = (
                                "fitness:diagnostic_id_in_gateway"
                                if self.reservations[reservation] is None
                                else "fitness:gateway_reservation_reused"
                            )
                            raise IntegrityError(reason)
                        self.reservations[reservation] = request
                if event in ("capture_start", "capture_end", "terminal", "admission_config"):
                    continue
                fields = {"gateway_uid": self.gateway}
                for name in (
                    "poll_seq",
                    "resource_version",
                    "membership_known",
                    "report_known",
                    "report_success",
                    "request_id",
                    "reservation_id",
                    "decision",
                    "admit_called",
                    "effective_n",
                    "effective_b",
                    "http_status",
                    "denial_code",
                    "retry_after_ms",
                    "result",
                    "idempotent",
                    "error_class",
                ):
                    if name in data:
                        fields[name] = data[name]
                if "members" in data:
                    members = []
                    for member in data["members"]:
                        members.append(
                            {k: member[k] for k in ("uid", "ready", "sampled", "healthy")}
                            | {"slot": self.slots[member["name"]]}
                        )
                    fields["members"] = members
                    fields["healthy_count"] = sum(
                        m["sampled"] and m["healthy"] and m["ready"] for m in members
                    )
                    if event == "install" and self.replacement_uid in {m["uid"] for m in members}:
                        fields["replacement_uid"] = self.replacement_uid
                if data.get("backend_uid"):
                    fields.update(
                        backend_uid=data["backend_uid"],
                        backend_slot=self.slots[data["backend_name"]],
                    )
                if fields.get("request_id") in self.request_ids:
                    fields["request_id"] = self.request_ids[fields["request_id"]]
                if event == "admit":
                    self.admit_requests.add(fields["request_id"])
                elif event == "deny":
                    fields["admit_called"] = fields["request_id"] in self.admit_requests
                remote = raw["mono_ns"] // 1_000_000
                event_bounds = None
                if event == "install" and self.clocks:
                    mapped = self.clocks.map(
                        self.gateway,
                        boot,
                        data["event_start_ns"] // 1_000_000,
                        (data["event_end_ns"] + 999_999) // 1_000_000,
                    )
                    event_bounds = mapped
                    if mapped:
                        bounds = self.clocks.inverse("redis", "redis", *mapped)
                        if bounds:
                            fields["install_redis_ms_bounds"] = bounds
                output.append(
                    self.rows.row(
                        "gateway",
                        self.gateway,
                        boot,
                        event,
                        fields,
                        source_ms=remote,
                        clock_id=self.gateway,
                        start_ns=captured_start,
                        end_ns=captured_end,
                        error=data.get("error"),
                        time_bounds=event_bounds,
                    )
                )
            del self.pending[:consumed]
            return output
        except (OSError, ValueError, KeyError, TypeError) as exc:
            self.lost = True
            if isinstance(exc, IntegrityError) and str(exc) in (
                "fitness:diagnostic_id_in_gateway",
                "fitness:gateway_reservation_reused",
                "fitness:row5_prewindow_evidence",
            ):
                raise
            return [
                self.rows.row(
                    "gateway",
                    self.gateway,
                    self.boot or "unknown",
                    "poll_end",
                    {
                        "gateway_uid": self.gateway,
                        "membership_known": False,
                        "error_class": type(exc).__name__,
                    },
                    start_ns=start,
                    error="gateway_capture_lost",
                )
            ]


class RedisWire:
    """Minimal RESP2 capture connection. Production may supply a verified TLS socket."""

    def __init__(
        self,
        host,
        port,
        *,
        password=None,
        tls=True,
        ca=None,
        local_test=False,
        retain=None,
        barrier=None,
        stop_ns=None,
    ):
        if not tls and not (local_test and host in ("127.0.0.1", "localhost")):
            raise ValueError("redis_capture_requires_tls_or_explicit_local_test")
        self.host, self.port = host, port
        self.retain, self.stop_ns = retain, stop_ns
        self.barrier = barrier or getattr(retain, "barrier", lambda: None)
        sock = socket.create_connection((host, port), timeout=self.remaining())
        self.sock = (
            ssl.create_default_context(cafile=ca).wrap_socket(sock, server_hostname=host)
            if tls
            else sock
        )
        self.file = self.sock.makefile("rb")
        self.pending = bytearray()
        self.reply_budget, self.producer_failed = None, False
        state = getattr(retain, "producer_state", None)
        self.producer_state = state if type(state) is dict else {}
        self.producer_lock = self.producer_state.setdefault("producer_lock", threading.RLock())
        duration = (
            max(0, (stop_ns - time.monotonic_ns()) / 1e9)
            if stop_ns is not None
            else SESSION_ENVELOPE_MS / 1000
        )
        self.scope_contract = self.producer_state.setdefault(
            "redis_contract", redis_scope_contract(duration)
        )
        if password:
            self.command("AUTH", password)

    def bind_scope_contract(self, contract):
        with self.producer_lock:
            for kind, seen in self.producer_state.get("redis_calls", {}).items():
                if contract.get(kind) is not None and seen > contract[kind]:
                    self.producer_refusal(
                        "capture:producer:redis_calls:" + kind,
                        time.monotonic_ns(),
                        time.monotonic_ns(),
                    )
            self.scope_contract = dict(contract)
            self.producer_state["redis_contract"] = self.scope_contract

    def close(self):
        if getattr(self, "reply_unit", None) is not None:
            self.reply_unit.finish("close")
        self.file.close()
        self.sock.close()

    def remaining(self):
        if self.stop_ns is None:
            return 1
        remaining = (self.stop_ns - time.monotonic_ns()) / 1e9
        if remaining <= 0:
            raise IntegrityError("redis_capture_deadline")
        return min(REDIS_CAPTURE_SOCKET_TIMEOUT_S, remaining)

    def capture_read(self, length, *, line=False):
        while True:
            newline = self.pending.find(b"\n") if line else -1
            size = min(newline + 1, length) if newline >= 0 else length
            if len(self.pending) >= size and (not line or newline >= 0 or size == length):
                data = bytes(self.pending[:size])
                del self.pending[:size]
                return data
            self.sock.settimeout(self.remaining())
            start = time.monotonic_ns()
            allowance = (
                self.reply_budget.contract["bytes"] - self.reply_received + 1
                if self.reply_budget
                else length
            )
            chunk = self.file.read1(min(65536, length - len(self.pending), allowance))
            end = time.monotonic_ns()
            self.reply_received += len(chunk)
            self.reply_unit.feed(start, end, chunk)
            if self.reply_received > self.reply_budget.contract["bytes"]:
                self.producer_refusal("capture:producer:resp_bytes", start, end)
            if self.reply_budget and (reason := self.reply_budget.add(len(chunk))):
                self.producer_refusal(reason, start, end)
            if self.stop_ns is not None and end > self.stop_ns:
                raise IntegrityError("redis_capture_deadline")
            self.pending.extend(chunk)
            if not chunk:
                data = bytes(self.pending)
                self.pending.clear()
                return data

    def producer_refusal(self, reason, start, end):
        self.producer_failed = True
        if getattr(self, "reply_unit", None) is not None:
            self.reply_unit.finish("refusal")
        refuse(self.retain or (lambda *args: None), reason, start, end)

    def read(self, *, decode=True, _depth=0):
        if self.reply_budget is None:
            now = time.monotonic_ns()
            self.producer_refusal("capture:producer:resp_contract_missing", now, now)
        start = time.monotonic_ns()
        line = self.capture_read(RESP_LINE_BYTES + 1, line=True)
        if len(line) > RESP_LINE_BYTES:
            self.producer_refusal("capture:producer:resp_line", start, time.monotonic_ns())
        if self.reply_budget and (reason := self.reply_budget.node(_depth)):
            self.producer_refusal(reason, start, time.monotonic_ns())
        if not line.endswith(b"\r\n"):
            raise IntegrityError("redis_capture_truncated")
        prefix, value = line[:1], line[1:-2]
        if self.reply_budget.contract.get("audit") and prefix == b":":
            self.producer_refusal("capture:producer:resp_audit_shape", start, time.monotonic_ns())
        if prefix == b"-":
            raise IntegrityError("redis_capture_command_failed")
        if prefix == b"+":
            return value.decode() if decode else value
        if prefix == b":":
            return int(value)
        if prefix == b"$":
            length = int(value)
            if length == -1:
                return None
            if not 0 <= length <= self.reply_budget.contract.get("bulk", RESP_BULK_BYTES):
                self.producer_refusal("capture:producer:resp_bulk", start, time.monotonic_ns())
            data = self.capture_read(length + 2)
            if len(data) != length + 2 or not data.endswith(b"\r\n"):
                raise IntegrityError("redis_capture_truncated")
            return data[:-2].decode() if decode else data[:-2]
        if prefix == b"*":
            count = int(value)
            if count == -1:
                return None
            if not 0 <= count <= RESP_ARRAY_ELEMENTS:
                self.producer_refusal("capture:producer:resp_array", start, time.monotonic_ns())
            if self.reply_budget:
                contract = self.reply_budget.contract
                if _depth + 1 > contract["depth"]:
                    self.producer_refusal("capture:producer:resp_depth", start, time.monotonic_ns())
                if count > contract["elements"] - self.reply_budget.elements:
                    self.producer_refusal(
                        "capture:producer:resp_elements", start, time.monotonic_ns()
                    )
            return [self.read(decode=decode, _depth=_depth + 1) for _ in range(count)]
        raise IntegrityError("redis_capture_invalid_resp")

    def command(self, *args):
        # Snapshot, audit and clock callbacks share this one connection. A
        # whole command/reply, not only its counter increment, is serialized.
        with self.producer_lock:
            return self._command(*args)

    def _command(self, *args):
        if self.producer_failed:
            raise ProducerLimit("capture:producer:resp_poisoned")
        if self.pending:
            now = time.monotonic_ns()
            self.producer_refusal("capture:producer:resp_unsolicited", now, now)
        self.sock.settimeout(self.remaining())
        contract = (
            audit_reply_contract()
            if len(args) >= 2 and args[:2] == ("EVAL", AUDIT_SCRIPT)
            else resp_contract(args, REDIS_SNAPSHOT)
        )
        if contract is None:
            now = time.monotonic_ns()
            self.producer_refusal("capture:producer:resp_command", now, now)
        kind = (
            "audit"
            if len(args) >= 2 and args[:2] == ("EVAL", AUDIT_SCRIPT)
            else "snapshot"
            if args[0] == "EVAL"
            else args[0]
        )
        with self.producer_lock:
            calls = self.producer_state.setdefault("redis_calls", {})
            calls[kind] = calls.get(kind, 0) + 1
            if self.scope_contract[kind] is not None and calls[kind] > self.scope_contract[kind]:
                now = time.monotonic_ns()
                self.producer_refusal("capture:producer:redis_calls:" + kind, now, now)
        return self._exchange(args, contract)

    def _exchange(self, args, contract):
        """Parser seam; production dispatch above only supplies pinned contracts."""
        self.reply_budget = ReplyBudget(contract)
        self.reply_received = 0
        self.reply_unit = UnitRecorder(
            self.retain or (lambda *args: None), kind="resp_reply", metadata={"protocol": "RESP2"}
        )
        values = [str(arg).encode() for arg in args]
        self.sock.sendall(
            b"*%d\r\n" % len(values) + b"".join(b"$%d\r\n" % len(v) + v + b"\r\n" for v in values)
        )
        parsed = False
        try:
            result = self.read(decode=False)  # Framing only, no text/schema normalization.
            parsed = True
            self.reply_unit.emit(self.reply_received - len(self.pending))
        finally:
            # On a parse/refusal error, all received bytes still get one final
            # partial unit. A successful unsolicited suffix stays pending until
            # the next command refuses or the original connection closes.
            if not parsed or not self.pending or self.producer_failed:
                self.reply_unit.finish("refusal")
            try:
                self.barrier()
            finally:
                self.reply_budget = None

        if len(args) >= 2 and args[:2] == ("EVAL", AUDIT_SCRIPT):
            check_audit(
                result,
                lambda reason: self.producer_refusal(
                    reason, time.monotonic_ns(), time.monotonic_ns()
                ),
            )

        if contract.get("shape"):
            from .inf037b_redis_shapes import validate_reply

            validate_reply(
                result,
                contract["shape"],
                lambda reason: self.producer_refusal(
                    reason, time.monotonic_ns(), time.monotonic_ns()
                ),
            )

        def decoded(value):
            if isinstance(value, bytes):
                return value.decode()
            if isinstance(value, list):
                return [decoded(item) for item in value]
            return value

        return decoded(result)


REDIS_SNAPSHOT = """
local t=redis.call('TIME')
return cjson.encode({redis_time_ms=tonumber(t[1])*1000+math.floor(tonumber(t[2])/1000),
 reports=redis.call('HGETALL',KEYS[1]), lows=redis.call('ZRANGE',KEYS[2],0,-1,'WITHSCORES'),
 state=redis.call('HGETALL',KEYS[3]), active=redis.call('ZRANGE',KEYS[4],0,-1,'WITHSCORES'),
 capture_order=redis.call('GET',KEYS[5]) or '0'})
"""


class RedisAdapter:
    def __init__(
        self,
        rows,
        wire,
        namespace,
        config_sha256,
        *,
        reservations=None,
        report_ttl_ms=None,
        capture_start_remote_ms=0,
    ):
        self.rows, self.wire, self.namespace, self.config = rows, wire, namespace, config_sha256
        self.report_ttl_ms = report_ttl_ms
        self.cursor = "0-0"
        self.audit_seq, self.lost = 0, False
        self.capture_start_remote_ms = capture_start_remote_ms
        self.prewindow_skipped_counts = {}
        self.reservations = reservations if reservations is not None else {}
        self.gateway_ids = {"gateway-0": "gateway0", "gateway-1": "gateway1"}
        self.waiting_since = None
        self.pending_snapshots = []
        scope = getattr(wire, "scope_contract", None)
        self.scope_contract = scope if type(scope) is dict else None

    def register_diagnostic(self, receipt):
        """Register a captured process receipt before joining its Redis events.

        The caller must first bind the receipt to the diagnostic process and its
        configuration. A None mapping denotes the separately captured process,
        so no diagnostic Redis row acquires a gateway request identifier.
        """
        from .inf037b_row5 import check_reservation_partition

        check_reservation_partition([], [receipt])
        reservation = receipt["reservation_id"]
        with _RESERVATION_LOCK:
            if reservation in self.reservations:
                if self.reservations[reservation] is None:
                    raise IntegrityError("fitness:diagnostic_receipt_duplicate")
                raise IntegrityError("fitness:diagnostic_id_in_gateway")
            self.reservations[reservation] = None

    def snapshot(self, *, captured=None, snapshot_id=None, label_if=None):
        # Labels identify actual snapshots; they never supply or alter Redis state.
        if label_if is not None and (
            captured is not None or snapshot_id is not None or not callable(label_if)
        ):
            raise IntegrityError("redis_snapshot_labeler_invalid")
        if captured is not None:
            if snapshot_id is not None:
                raise IntegrityError("redis_snapshot_pending_label_override")
            snapshot_id = captured[2]
        if snapshot_id is not None and (
            not isinstance(snapshot_id, str)
            or snapshot_id
            not in {
                "known0",
                "known1",
                "known2",
                "cached_stop_known1",
                "cached_restore_known2",
                "post_outage_known2",
                "post_outage_agreement",
                "unknown",
                "expired",
                "hold_start",
                "hold_end",
            }
        ):
            raise IntegrityError("redis_snapshot_unknown_id")
        if snapshot_id is not None and (
            type(self.report_ttl_ms) is not int or self.report_ttl_ms <= 0
        ):
            raise IntegrityError("redis_snapshot_ttl_unbound")
        start = self.rows.clock() if captured is None else captured[1]
        prefix = self.namespace + ":{admission}:"
        try:
            raw = (
                captured[0]
                if captured is not None
                else json.loads(
                    self.wire.command(
                        "EVAL",
                        REDIS_SNAPSHOT,
                        5,
                        prefix + "capacity:reports",
                        prefix + "capacity:lows",
                        prefix + "capacity:state",
                        prefix + "global:active",
                        prefix + "global:active:capture:sequence",
                    )
                )
            )

            def pairs(values):
                if values == {}:
                    return {}
                return dict(zip(values[::2], values[1::2], strict=True))

            capture_order = raw["capture_order"]
            if not isinstance(capture_order, str) or not re.fullmatch(
                r"0|[1-9][0-9]*", capture_order
            ):
                raise IntegrityError("redis_snapshot_capture_order")
            if raw["redis_time_ms"] < self.capture_start_remote_ms:
                raise IntegrityError("fitness:row5_prewindow_evidence")
            state = {k: int(v) for k, v in pairs(raw["state"]).items()}
            state = {k + "_ms" if k in ("since", "until") else k: v for k, v in state.items()}
            if label_if is not None:
                snapshot_id = label_if(dict(state), raw["redis_time_ms"])
                if snapshot_id is not None and (
                    not isinstance(snapshot_id, str)
                    or snapshot_id
                    not in {
                        "known0",
                        "known1",
                        "known2",
                        "cached_stop_known1",
                        "cached_restore_known2",
                        "post_outage_known2",
                        "post_outage_agreement",
                        "unknown",
                        "expired",
                        "hold_start",
                        "hold_end",
                    }
                ):
                    raise IntegrityError("redis_snapshot_unknown_id")
                if snapshot_id is not None and (
                    type(self.report_ttl_ms) is not int or self.report_ttl_ms <= 0
                ):
                    raise IntegrityError("redis_snapshot_ttl_unbound")
            reports = {k: json.loads(v) for k, v in pairs(raw["reports"]).items()}
            reports = {self.gateway_ids.get(k, k): v for k, v in reports.items()}
            for report in reports.values():
                report["expires_ms"] = report.pop("expires")
                if snapshot_id is not None:
                    if (
                        type(report["expires_ms"]) is not int
                        or report["expires_ms"] < self.report_ttl_ms
                    ):
                        raise IntegrityError("redis_snapshot_expiry_invalid")
                    # Lua stores Redis TIME + the frozen report TTL; unknown does not renew it.
                    report["stored_ms"] = report["expires_ms"] - self.report_ttl_ms
            lows = [
                {
                    "gateway_uid": self.gateway_ids.get(k.rsplit("|", 1)[0], k.rsplit("|", 1)[0]),
                    "n": int(k.rsplit("|", 1)[1]),
                    "until_ms": int(float(v)),
                }
                for k, v in pairs(raw["lows"]).items()
            ]
            raw_active = {
                k: v
                for k, v in pairs(raw["active"]).items()
                if int(float(v)) > raw["redis_time_ms"]
            }
            if any(k.split(":", 1)[1] not in self.reservations for k in raw_active):
                if self.rows.clock() - start > 2_000_000_000:
                    raise IntegrityError("redis_snapshot_gateway_join_timeout")
                self.pending_snapshots.append((raw, start, snapshot_id))
                return None
            active = [
                {
                    **(
                        {"request_id": self.reservations[k.split(":", 1)[1]]}
                        if self.reservations[k.split(":", 1)[1]] is not None
                        else {}
                    ),
                    "reservation_id": k.split(":", 1)[1],
                    "expiry_ms": int(float(v)),
                }
                for k, v in raw_active.items()
            ]
            if getattr(self, "ordered_snapshots", False):
                # The atomic snapshot's high-water mark excludes operations
                # performed after it. Drain only through that mark, otherwise
                # the drain itself could put a newer operation before this row.
                target = int(capture_order)
                if self.audit_seq > target:
                    raise IntegrityError("redis_snapshot_operations_reordered")
                while self.audit_seq < target:
                    previous = self.audit_seq
                    self.operations(through_store_order=target)
                    if self.lost or self.audit_seq == previous:
                        raise IntegrityError("redis_snapshot_operations_incomplete")
            return self.rows.row(
                "redis",
                "redis",
                "redis",
                "snapshot",
                {
                    "redis_time_ms": raw["redis_time_ms"],
                    "store_order": int(capture_order),
                    "reports": reports,
                    "lows": lows,
                    "state": state,
                    "active_reservations": active,
                    "occupied": len(active),
                    "config_sha256": self.config,
                    **({"snapshot_id": snapshot_id} if snapshot_id is not None else {}),
                },
                source_ms=raw["redis_time_ms"],
                clock_id="redis",
                start_ns=start,
            )
        except (OSError, ValueError, TypeError, KeyError) as exc:
            if isinstance(exc, IntegrityError) and str(exc) == "fitness:row5_prewindow_evidence":
                self.lost = True
                raise
            return self.rows.row(
                "redis",
                "redis",
                "redis",
                "read_error",
                {"config_sha256": self.config},
                start_ns=start,
                error=str(exc) if isinstance(exc, ProducerLimit) else type(exc).__name__,
            )

    def flush_snapshots(self):
        pending, self.pending_snapshots = self.pending_snapshots, []
        return [
            row for captured in pending if (row := self.snapshot(captured=captured)) is not None
        ]

    def operations(self, *, through_store_order=None):
        """Atomic operation receipts and a sequence high-water mark detect XDEL/trim."""
        start = self.rows.clock()
        key = self.namespace + ":{admission}:global:active:capture"
        script = AUDIT_SCRIPT
        try:
            if self.lost:
                raise IntegrityError("redis_audit_previously_lost")
            batch, high = self.wire.command("EVAL", script, 1, key, self.cursor)
            if self.scope_contract is not None and int(high) > self.scope_contract["entries"]:
                self.wire.producer_refusal(
                    "capture:producer:redis_entries", start, self.rows.clock()
                )
            output = []
            waiting = False
            for entry_id, values in batch:
                raw = dict(zip(values[::2], values[1::2], strict=True))
                seq = int(raw["capture_seq"])
                if through_store_order is not None and seq > through_store_order:
                    waiting = True
                    break
                if seq != self.audit_seq + 1:
                    raise IntegrityError("redis_audit_sequence_gap")
                redis_time_ms = int(raw["redis_time_ms"])
                if redis_time_ms < self.capture_start_remote_ms:
                    if raw["event"] not in _PREWINDOW_REDIS_EVENTS:
                        raise IntegrityError("fitness:row5_prewindow_evidence")
                    _count_prewindow(self.prewindow_skipped_counts, raw["event"])
                    self.audit_seq, self.cursor = seq, entry_id
                    continue
                if raw.get("reservation_id") and raw["reservation_id"] not in self.reservations:
                    if self.waiting_since is None:
                        self.waiting_since = self.rows.clock()
                    if self.rows.clock() - self.waiting_since > 2_000_000_000:
                        raise IntegrityError("redis_operation_gateway_join_timeout")
                    waiting = True
                    break
                self.waiting_since = None
                fields = {
                    "redis_time_ms": int(raw["redis_time_ms"]),
                    "store_order": seq,
                    "config_sha256": self.config,
                    "decision": raw["decision"],
                    "idempotent": raw["idempotent"] == "1",
                    "occupied": int(raw["occupied"]),
                }
                for name in ("effective_n", "effective_b"):
                    if raw.get(name):
                        fields[name] = int(raw[name])
                if raw.get("reservation_id"):
                    fields["reservation_id"] = raw["reservation_id"]
                    request = self.reservations[raw["reservation_id"]]
                    if request is not None:
                        fields["request_id"] = request
                if raw.get("gateway_uid"):
                    fields["gateway_uid"] = self.gateway_ids.get(
                        raw["gateway_uid"], raw["gateway_uid"]
                    )
                if raw.get("report"):
                    report = strict_json(raw["report"].encode())
                    fields.update(
                        n=report["n"],
                        expires_ms=report["expires"],
                        unknown=report["unknown"],
                        report_known=not report["unknown"],
                        report_success=True,
                        report_complete=not report["unknown"],
                    )
                output.append(
                    self.rows.row(
                        "redis",
                        "redis",
                        "redis",
                        raw["event"],
                        fields,
                        source_ms=fields["redis_time_ms"],
                        clock_id="redis",
                        start_ns=start,
                    )
                )
                self.audit_seq, self.cursor = seq, entry_id
            if not waiting and len(batch) < 1000 and self.audit_seq != int(high):
                raise IntegrityError("redis_audit_missing_tail")
            return output
        except (OSError, ValueError, KeyError, TypeError) as exc:
            if isinstance(exc, IntegrityError) and str(exc) == "fitness:row5_prewindow_evidence":
                self.lost = True
                raise
            self.lost = True
            return [
                self.rows.row(
                    "redis",
                    "redis",
                    "redis",
                    "read_error",
                    {"config_sha256": self.config},
                    start_ns=start,
                    error=str(exc) if isinstance(exc, ProducerLimit) else type(exc).__name__,
                )
            ]


class ClockAdapter:
    def __init__(self, rows):
        self.rows = rows

    def mapping(self, clock_id, boot_id, remote_ms, send_ns, receive_ns, *, wall_ms=None):
        return self.rows.row(
            "clocks",
            "clock:" + clock_id,
            boot_id,
            "mapping",
            {
                "clock_id": clock_id,
                "boot_id": boot_id,
                "remote_ms": remote_ms,
                "local_mono_ms": receive_ns // 1_000_000,
                "local_wall_ms": int(time.time() * 1000) if wall_ms is None else wall_ms,
                "send_ms": send_ns // 1_000_000,
                "receive_ms": receive_ns // 1_000_000,
            },
            start_ns=send_ns,
            end_ns=receive_ns,
        )

    def gateway(self, http, gateway):
        start = self.rows.clock()
        try:
            body, _ = http.get("/internal/measurement?clock=1")
            end = self.rows.clock()
            data = strict_json(body)
            return self.mapping(gateway, data["boot_id"], data["mono_ns"] // 1_000_000, start, end)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            return self.missed(gateway, start, exc)

    def missed(self, clock_id, start, exc):
        return self.rows.row(
            "clocks",
            "clock:" + clock_id,
            "unknown",
            "missed",
            {"clock_id": clock_id, "boot_id": "unknown"},
            start_ns=start,
            error=type(exc).__name__,
        )

    def redis(self, wire):
        start = self.rows.clock()
        try:
            seconds, micros = wire.command("TIME")
            end = self.rows.clock()
            return self.mapping(
                "redis", "redis", int(seconds) * 1000 + int(micros) // 1000, start, end
            )
        except (OSError, ValueError, KeyError, TypeError) as exc:
            return self.missed("redis", start, exc)


METRICS = {
    "running": "vllm:num_requests_running",
    "waiting": "vllm:num_requests_waiting",
    "prefix_query_tokens_total": "vllm:prefix_cache_queries_total",
    "prefix_hit_tokens_total": "vllm:prefix_cache_hits_total",
    "preemptions_total": "vllm:num_preemptions_total",
}


class VLLMAdapter:
    def __init__(
        self,
        rows,
        http,
        *,
        pod_uid,
        slot,
        process_generation,
        model_sha256,
        runtime_sha256,
        semantics_sha256,
        lifecycle=None,
    ):
        self.rows, self.http, self.uid, self.slot = rows, http, pod_uid, slot
        self.process, self.model, self.runtime, self.semantics = (
            process_generation,
            model_sha256,
            runtime_sha256,
            semantics_sha256,
        )
        self.previous, self.reset, self.lifecycle = None, 0, lifecycle
        # A failed first observation is retained, but does not suppress the
        # first successful report when the process becomes ready. The setup
        # composition calls sample() on its cadence; each sample retries the
        # config observation until one is complete.
        self.engine_emitted = False

    def engine_config(self):
        """Retain failed reads and retry until one successful fixed-UID/process report."""
        if self.engine_emitted:
            return None
        start = self.rows.clock()
        fields = {
            "pod_uid": self.uid,
            "slot": self.slot,
            "process_generation": self.process,
            "model_sha256": self.model,
            "runtime_sha256": self.runtime,
        }
        error = None
        try:
            if not self.lifecycle or self.lifecycle.process_boot(self.uid) != self.process:
                raise IntegrityError("engine:generation_unjoined")
            body, _ = self.http.get("/metrics")
            labels = cache_config(body)
            body, _ = self.http.get("/v1/models")
            models = strict_json(body)["data"]
            if not isinstance(models, list) or len(models) != 1:
                raise IntegrityError("engine:models_missing_or_ambiguous")
            length = models[0]["max_model_len"]
            if type(length) is not int or length <= 0:
                raise IntegrityError("engine:model_length_invalid")
            if self.lifecycle.process_boot(self.uid) != self.process or self.lifecycle.lost:
                raise IntegrityError("engine:generation_unjoined")
            fields.update(cache_config_labels=labels, max_model_len=length)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            error = (
                str(exc)
                if isinstance(exc, IntegrityError)
                else "engine:capture:" + type(exc).__name__
            )
            fields["observation_error"] = error
        row = self.rows.row(
            "vllm",
            "vllm:" + self.uid,
            self.process,
            "engine_config",
            fields,
            start_ns=start,
        )
        self.engine_emitted = error is None
        return row

    def sample(self):
        self.engine_config()
        start = self.rows.clock()
        try:
            if self.lifecycle and self.lifecycle.process_boot(self.uid) != self.process:
                raise IntegrityError("vllm_supervisor_generation_mismatch")
            body, _ = self.http.get("/metrics")
            values = {}
            for line in body.decode().splitlines():
                if not line or line.startswith("#"):
                    continue
                match = re.fullmatch(r"([^ {]+)(?:\{(.*)\})?\s+([^ ]+)", line)
                if not match or match[1] not in METRICS.values():
                    continue
                if match[1] in values:
                    raise IntegrityError("ambiguous_metric_series")
                value = float(match[3])
                if not math.isfinite(value) or value < 0 or not value.is_integer():
                    raise IntegrityError("invalid_native_counter")
                values[match[1]] = int(value)
            counters = {name: values[metric] for name, metric in METRICS.items()}
            if self.previous and any(
                counters[k] < self.previous[k]
                for k in (
                    "prefix_query_tokens_total",
                    "prefix_hit_tokens_total",
                    "preemptions_total",
                )
            ):
                self.reset += 1
            self.previous = counters
            health_ready = True
            try:
                self.http.get("/health")
            except urllib.error.HTTPError as exc:
                if exc.code != 503:
                    raise
                health_ready = False
            if self.lifecycle:
                self.lifecycle.contradiction(self.uid, "sample")
            return self.rows.row(
                "vllm",
                "vllm:" + self.uid,
                self.process,
                "sample",
                {
                    **counters,
                    "pod_uid": self.uid,
                    "slot": self.slot,
                    "process_generation": self.process,
                    "model_sha256": self.model,
                    "runtime_sha256": self.runtime,
                    "sample_time": start // 1_000_000,
                    "health_ready": health_ready,
                    "reset_generation": str(self.reset),
                    "metric_semantics_sha256": self.semantics,
                },
                start_ns=start,
            )
        except (OSError, ValueError, KeyError, TypeError) as exc:
            return self.rows.row(
                "vllm",
                "vllm:" + self.uid,
                self.process,
                "sample",
                {
                    "pod_uid": self.uid,
                    "slot": self.slot,
                    "process_generation": self.process,
                    "observation_error": type(exc).__name__,
                },
                start_ns=start,
            )

    def process_end(self):
        if self.lifecycle:
            self.lifecycle.contradiction(self.uid, "process_end")
        return self.rows.row(
            "vllm",
            "vllm:" + self.uid,
            self.process,
            "process_end",
            {"pod_uid": self.uid, "slot": self.slot, "process_generation": self.process},
        )


def _producer_locked(method):
    @wraps(method)
    def locked(self, *args, **kwargs):
        with self.lock:
            return method(self, *args, **kwargs)

    return locked


class LifecycleReceiptProducer:
    """Sticky loss/contradiction latch, fed by the independent supervisor spool.

    A new HTTP connection, relist or restart cannot clear the latch. Pod creation
    and all process records retain independent provenance in the raw archive.
    """

    def __init__(self):
        self.pods, self.lost = {}, False
        self.lock = threading.RLock()

    @_producer_locked
    def loss(self):
        self.lost = True

    @_producer_locked
    def created(self, uid, slot):
        if uid in self.pods:
            self.loss()
            return
        self.pods[uid] = {
            "slot": slot,
            "seq": 0,
            "boot": None,
            "last_ns": None,
            "blocked": False,
            "begun": False,
        }

    @_producer_locked
    def contradiction(self, uid, event):
        if uid in self.pods and event in (
            "startup",
            "ready",
            "sample",
            "process_end",
            "metrics_pending",
        ):
            self.pods[uid]["blocked"] = True

    @_producer_locked
    def process_boot(self, uid):
        pod = self.pods.get(uid)
        return pod["boot"] if pod else None

    @_producer_locked
    def ingest(self, raw):
        try:
            if (
                type(raw.get("sequence")) is not int
                or raw["sequence"] < 0
                or type(raw.get("mono_ns")) is not int
                or raw["mono_ns"] < 0
                or not isinstance(raw.get("boot_id"), str)
                or not raw["boot_id"]
                or raw.get("event")
                not in (
                    "supervisor_start",
                    "process_start",
                    "heartbeat",
                    "metrics_pending",
                    "startup",
                    "signal",
                    "process_end",
                )
            ):
                raise IntegrityError("invalid_lifecycle_record")
            pod = self.pods[raw["pod_uid"]]
            if (
                self.lost
                or raw["sequence"] != pod["seq"]
                or pod["boot"] not in (None, raw["boot_id"])
            ):
                raise IntegrityError("lifecycle_sequence_or_boot_loss")
            now = raw["mono_ns"]
            if pod["last_ns"] is not None and not 0 <= now - pod["last_ns"] <= 2_000_000_000:
                raise IntegrityError("lifecycle_capture_gap")
            if raw.get("capture_lost") or raw.get("restart_count", 0) != 0:
                raise IntegrityError("lifecycle_capture_lost")
            if pod["seq"] == 0 and raw["event"] != "supervisor_start":
                raise IntegrityError("lifecycle_missing_origin")
            pod.update(seq=pod["seq"] + 1, boot=raw["boot_id"], last_ns=now, begun=True)
            self.contradiction(raw["pod_uid"], raw["event"])
            return pod
        except (ValueError, KeyError, TypeError):
            self.loss()
            raise IntegrityError("lifecycle_capture_lost") from None

    @_producer_locked
    def receipt(self, rows, uid, now_ns, *, time_bounds=None):
        pod = self.pods[uid]
        if (
            self.lost
            or pod["blocked"]
            or not pod["begun"]
            or not 0 <= now_ns - pod["last_ns"] <= 500_000_000
        ):
            raise IntegrityError("lifecycle_receipt_refused")
        if time_bounds is None:
            raise IntegrityError("lifecycle_receipt_unmapped_clock")
        return rows.row(
            "kubernetes",
            "kubernetes",
            rows.boot,
            "container_state",
            {
                "pod_uid": uid,
                "slot": pod["slot"],
                "container_state": "metrics_not_started",
                "reason": "continuous_lifecycle_since_pod_creation",
            },
            time_bounds=time_bounds,
        )


class KubernetesAdapter:
    def __init__(self, rows, http, namespace, *, slot_names, lifecycle):
        self.rows, self.http, self.namespace, self.slots, self.lifecycle = (
            rows,
            http,
            namespace,
            slot_names,
            lifecycle,
        )
        self.created = set()
        self.observed = set()
        self.pod_resource_version = None
        self.endpoint_resource_version = None

    def pod_observations(self, pod, *, start_ns=None):
        meta, status = pod["metadata"], pod.get("status", {})
        uid, slot = meta["uid"], self.slots[meta["name"]]
        output, events = [], []
        if meta.get("deletionTimestamp"):
            events.append("deletion")
        raw_conditions = status.get("conditions", [])
        conditions = {c["type"]: c["status"] for c in raw_conditions}
        if any(c["type"] == "PodScheduled" and c["status"] == "True" for c in raw_conditions):
            events.append("scheduled")
        if any(c["type"] == "Ready" and c["status"] == "True" for c in raw_conditions):
            self.lifecycle.contradiction(uid, "ready")
            events.append("ready")
        image, engine = None, None
        for container in status.get("containerStatuses", []):
            if container.get("name") != "vllm":
                continue
            if container.get("restartCount", 0):
                self.lifecycle.loss()
            if "running" in container.get("state", {}):
                events.append("container_state")
                if container.get("name") == "vllm":
                    engine = container
            match = re.search(r"sha256:([0-9a-f]{64})$", container.get("imageID", ""))
            if match:
                image = match[1]
        for event in events:
            if (uid, event) in self.observed:
                continue
            self.observed.add((uid, event))
            fields = {
                "pod_uid": uid,
                "slot": slot,
                "resource_version": meta["resourceVersion"],
                "conditions": conditions,
                "image_sha256": image,
                "reason": "first_observed_" + event,
                "node_pseudonym": pod.get("spec", {}).get("nodeName"),
            }
            if event == "deletion":
                fields["deletion_time"] = meta["deletionTimestamp"]
            elif event == "container_state":
                fields["container_state"] = "running"
                if engine is not None:
                    admitted = [c for c in pod["spec"]["containers"] if c["name"] == "vllm"]
                    if len(admitted) != 1:
                        raise IntegrityError("engine:missing_pod_container")
                    command, args = admitted[0]["command"], admitted[0]["args"]
                    if (
                        not isinstance(command, list)
                        or not command
                        or any(not isinstance(arg, str) for arg in command)
                    ):
                        raise IntegrityError("engine:invalid_command")
                    fields.update(
                        engine_command=command,
                        engine_args=args,
                        engine_argv_sha256=sha(encode({"command": command, "args": args})),
                        engine_flags=parse_engine_argv(args),
                        container_id=engine["containerID"],
                        restart_count=engine["restartCount"],
                        gpu_count=str(admitted[0]["resources"]["limits"]["nvidia.com/gpu"]),
                    )
            output.append(
                self.rows.row(
                    "kubernetes", "kubernetes", self.rows.boot, event, fields, start_ns=start_ns
                )
            )
        return output

    def snapshot(self):
        start = self.rows.clock()
        try:
            prefix = "/apis/discovery.k8s.io/v1/namespaces/" + self.namespace
            endpoints, _ = self.http.get(
                prefix + "/endpointslices?labelSelector=kubernetes.io%2Fservice-name%3Dvllm"
            )
            pods, _ = self.http.get(
                "/api/v1/namespaces/" + self.namespace + "/pods?labelSelector=app%3Dvllm"
            )
            slices, podlist = strict_json(endpoints), strict_json(pods)
            if slices["metadata"].get("continue") or podlist["metadata"].get("continue"):
                raise IntegrityError("incomplete_kubernetes_list")
            self.pod_resource_version = podlist["metadata"]["resourceVersion"]
            self.endpoint_resource_version = slices["metadata"]["resourceVersion"]
            output, members = [], []
            for item in slices["items"]:
                for endpoint in item["endpoints"]:
                    ref = endpoint["targetRef"]
                    if ref["kind"] != "Pod" or ref["namespace"] != self.namespace:
                        raise IntegrityError("kubernetes_endpoint_identity")
                    conditions = endpoint["conditions"]
                    members.append(
                        {"uid": ref["uid"], "slot": self.slots[ref["name"]], **conditions}
                    )
            for pod in podlist["items"]:
                output.extend(self.pod_observations(pod, start_ns=start))
                # A list can establish a creation observation but never continuous
                # history; only the supervisor's sequence-zero origin may attest it.
                # A list/relist never authorizes a cumulative receipt. Creation
                # must have arrived on the continuously owned watch before launch.
            output.append(
                self.rows.row(
                    "kubernetes",
                    "kubernetes",
                    self.rows.boot,
                    "snapshot",
                    {
                        "resource_version": self.pod_resource_version,
                        "endpoints": members,
                        "list_valid": True,
                        "boundaries": {
                            "pods_resource_version": self.pod_resource_version,
                            "endpointslices_resource_version": self.endpoint_resource_version,
                        },
                    },
                    start_ns=start,
                )
            )
            return output
        except (OSError, ValueError, KeyError, TypeError) as exc:
            self.lifecycle.loss()
            return [
                self.rows.row(
                    "kubernetes",
                    "kubernetes",
                    self.rows.boot,
                    "snapshot",
                    {"list_valid": False},
                    start_ns=start,
                    error=type(exc).__name__,
                )
            ]

    def watch(self, lines):
        """Consume raw Kubernetes Watch JSON lines; ERROR/410/EOF poisons proof."""
        cutoff = False
        try:
            for line in lines:
                event = strict_json(line)
                if event["type"] == "ERROR":
                    raise IntegrityError("kubernetes_watch_error")
                obj = event["object"]
                self.last_resource_version = obj["metadata"]["resourceVersion"]
                if event["type"] == "BOOKMARK":
                    meta = obj["metadata"]
                    yield self.rows.row(
                        "kubernetes",
                        "kubernetes",
                        self.rows.boot,
                        "watch",
                        {
                            "resource_version": meta["resourceVersion"],
                            "reason": "BOOKMARK",
                            "conditions": {},
                        },
                    )
                    continue
                if event["type"] not in ("ADDED", "MODIFIED", "DELETED"):
                    raise IntegrityError("unknown_kubernetes_watch_event")
                if obj.get("kind") != "Pod":
                    raise IntegrityError("kubernetes_watch_object_kind")
                meta = obj["metadata"]
                uid, slot = meta["uid"], self.slots[meta["name"]]
                if event["type"] == "ADDED" and uid not in self.created:
                    self.created.add(uid)
                    self.lifecycle.created(uid, slot)
                    yield self.rows.row(
                        "kubernetes",
                        "kubernetes",
                        self.rows.boot,
                        "pod_created",
                        {
                            "pod_uid": uid,
                            "slot": slot,
                            "resource_version": meta["resourceVersion"],
                            "reason": "continuous_watch_added",
                        },
                    )
                yield self.rows.row(
                    "kubernetes",
                    "kubernetes",
                    self.rows.boot,
                    "watch",
                    {
                        "pod_uid": meta["uid"],
                        "slot": self.slots[meta["name"]],
                        "resource_version": meta["resourceVersion"],
                        "reason": event["type"],
                        "conditions": {
                            c["type"]: c["status"]
                            for c in obj.get("status", {}).get("conditions", [])
                        },
                    },
                )
                yield from self.pod_observations(obj)
        except WatchCutoff:
            cutoff = True
            raise
        finally:
            if not cutoff:
                self.lifecycle.loss()

    def watch_pods(self, resource_version):
        if not resource_version:
            raise IntegrityError("kubernetes_pod_snapshot_required_before_watch")
        self.last_resource_version = resource_version
        query = urllib.parse.urlencode(
            {
                "watch": "true",
                "allowWatchBookmarks": "true",
                "timeoutSeconds": "7200",
                "resourceVersion": resource_version,
                "labelSelector": "app=vllm",
            }
        )
        path = f"/api/v1/namespaces/{self.namespace}/pods?{query}"
        yield from self.watch(self.http.lines(path))


class NodeLifecycleAdapter:
    """Normalize node evidence into the one Kubernetes capture stream.

    Campaigns use the stable physical-node clock observed before pod creation;
    a new UID must not invent a new periodic Kubernetes/clock source mid-event.
    """

    def __init__(
        self,
        rows,
        http,
        uid,
        slot,
        producer,
        *,
        clocks=None,
        clock_id=None,
        clock_boot=None,
        spool_http=None,
    ):
        self.rows, self.http, self.uid, self.slot = rows, http, uid, slot
        self.spool_http = spool_http
        self.producer, self.clocks, self.offset, self.boot = producer, clocks, 0, None
        self.clock_id, self.clock_boot = clock_id or "node:" + uid, clock_boot
        self.fixed_node_clock = clock_id is not None
        self.poll_lock = threading.RLock()

    def clock(self):
        start = self.rows.clock()
        try:
            body, _ = self.http.get("/clock")
            end = self.rows.clock()
            raw = strict_json(body)
            if self.boot not in (None, raw["boot_id"]):
                raise IntegrityError("node_supervisor_boot_changed")
            self.boot = raw["boot_id"]
            if self.fixed_node_clock and raw.get("node_boot_id") != self.clock_boot:
                raise IntegrityError("node_kernel_boot_mismatch")
            return ClockAdapter(self.rows).mapping(
                self.clock_id, self.clock_boot or self.boot, raw["mono_ns"] // 1_000_000, start, end
            )
        except (OSError, ValueError, KeyError, TypeError) as exc:
            self.producer.loss()
            return ClockAdapter(self.rows).missed(self.clock_id, start, exc)

    def bounds(self, begin_ns, end_ns):
        if not self.clocks:
            return None
        return self.clocks.map(
            self.clock_id,
            self.clock_boot or self.boot,
            begin_ns // 1_000_000,
            (end_ns + 999_999) // 1_000_000,
        )

    def loading_receipt(self):
        pod = self.producer.pods[self.uid]
        try:
            body, _ = self.http.get("/clock")
            native_now = strict_json(body)
            if native_now["boot_id"] != self.boot or (
                self.fixed_node_clock and native_now.get("node_boot_id") != self.clock_boot
            ):
                raise IntegrityError("node_supervisor_boot_changed")
        except (OSError, ValueError, KeyError, TypeError):
            self.producer.loss()
            raise
        return self.producer.receipt(
            self.rows,
            self.uid,
            native_now["mono_ns"],
            time_bounds=self.bounds(pod["last_ns"], pod["last_ns"]),
        )

    def poll(self):
        with self.poll_lock:
            return self._poll()

    def _poll(self):
        start = self.rows.clock()
        try:
            source = self.spool_http or self.http
            path = (
                f"/lifecycle/{urllib.parse.quote(self.uid, safe='')}/events?offset={self.offset}"
                if self.spool_http
                else f"/events?offset={self.offset}"
            )
            body, headers = source.get(path)
            if not body.endswith(b"\n") and body:
                raise IntegrityError("torn_node_capture")
            boot = headers["X-Capture-Boot"]
            next_offset = int(headers["X-Capture-Next"])
            if next_offset != self.offset + len(body):
                raise IntegrityError("node_capture_offset_mismatch")
            if self.boot not in (None, boot):
                raise IntegrityError("node_supervisor_boot_changed")
            self.boot = boot
            output = []
            for line in body.splitlines():
                raw = strict_json(line)
                if (
                    raw["schema"] != "vllm-supervisor-v1"
                    or raw["pod_uid"] != self.uid
                    or raw["boot_id"] != boot
                ):
                    raise IntegrityError("node_lifecycle_identity_mismatch")
                if self.fixed_node_clock and raw.get("node_boot_id") != self.clock_boot:
                    raise IntegrityError("node_kernel_boot_mismatch")
                self.producer.ingest(raw)
                event = raw["event"]
                if event in ("startup", "signal"):
                    fields = {
                        "pod_uid": self.uid,
                        "slot": self.slot,
                        "reason": "independent_supervisor",
                    }
                    data = raw.get("signal_data", {})
                    if event == "startup":
                        bounds = self.bounds(data["start_ns"], data["end_ns"])
                    else:
                        received = data.get("receipt_ns", raw["mono_ns"])
                        bounds = self.bounds(received, received)
                        fields.update(
                            signal=raw["signal"],
                            signal_receipt_time=(sum(bounds) // 2 if bounds else None),
                        )
                    output.append(
                        self.rows.row(
                            "kubernetes",
                            "kubernetes",
                            self.rows.boot,
                            event,
                            fields,
                            start_ns=start,
                            time_bounds=bounds,
                            error=None if bounds else "lifecycle_clock_unmapped",
                        )
                    )
                elif event == "process_end":
                    self.producer.contradiction(self.uid, "process_end")
                    bounds = self.bounds(raw["mono_ns"], raw["mono_ns"])
                    output.append(
                        self.rows.row(
                            "vllm",
                            "vllm:" + self.uid,
                            boot,
                            "process_end",
                            {"pod_uid": self.uid, "slot": self.slot, "process_generation": boot},
                            start_ns=start,
                            time_bounds=bounds,
                            error=None if bounds else "lifecycle_clock_unmapped",
                        )
                    )
            self.offset = next_offset
            return output
        except (OSError, ValueError, TypeError, KeyError) as exc:
            self.producer.loss()
            return [
                self.rows.row(
                    "kubernetes",
                    "kubernetes",
                    self.rows.boot,
                    "container_state",
                    {"pod_uid": self.uid, "slot": self.slot},
                    start_ns=start,
                    error=type(exc).__name__,
                )
            ]


class NodeCacheAdapter:
    """Stable node clock plus original CRI/model-file witnesses before creation."""

    def __init__(self, rows, http, node):
        self.rows, self.http, self.node = rows, http, node
        self.clock_id, self.witness = "node:" + node, None

    def clock(self):
        start = self.rows.clock()
        try:
            body, _ = self.http.get("/clock")
            end = self.rows.clock()
            raw = strict_json(body)
            return ClockAdapter(self.rows).mapping(
                self.clock_id, raw["boot_id"], raw["mono_ns"] // 1_000_000, start, end
            )
        except (OSError, ValueError, TypeError, KeyError) as exc:
            return ClockAdapter(self.rows).missed(self.clock_id, start, exc)

    def capture(self):
        try:
            body, _ = self.http.get("/snapshot")
            witness = strict_json(body)
            if (
                witness["schema"] != "m5-node-cache-v1"
                or witness["node"] != self.node
                or witness["complete"] is not True
            ):
                raise IntegrityError("incomplete_node_cache_witness")
            self.witness = witness
            return witness
        except (OSError, ValueError, KeyError, TypeError):
            if self.rows.on_loss:
                self.rows.on_loss()
            raise

    def for_pod(self, uid, slot, *, creation_bounds, clocks):
        witness = self.witness
        if witness is None:
            raise IntegrityError("missing_node_cache_witness")
        bounds = clocks.map(
            self.clock_id,
            witness["boot_id"],
            witness["end_ns"] // 1_000_000,
            (witness["end_ns"] + 999_999) // 1_000_000,
        )
        before_creation = bounds is not None and bounds[1] < creation_bounds[0]
        return self.rows.row(
            "kubernetes",
            "kubernetes",
            self.rows.boot,
            "container_state",
            {
                "pod_uid": uid,
                "slot": slot,
                "node_pseudonym": self.node,
                "container_state": "cache_observation",
                "image_cache_state": witness["image_cache_state"] if before_creation else None,
                "model_cache_state": witness["model_cache_state"] if before_creation else None,
                "reason": "cache_observed_before_creation"
                if before_creation
                else "cache_timing_not_established",
                "boundaries": {
                    "cache_witness_ms_bounds": bounds,
                    "creation_ms_bounds": creation_bounds,
                },
            },
            error=None if before_creation else "node_cache_clock_or_creation_unmapped",
        )


class ClientSSEAdapter:
    """Capture actual HTTP chunks; validated completion comes from SSEDecoder."""

    def __init__(self, rows, gateway_uid, config_sha256, *, retain=None):
        self.rows, self.gateway, self.config = rows, gateway_uid, config_sha256
        self.request_ids = {}
        self.binding_lock = threading.Lock()
        self.retain = retain or (lambda *args: None)
        self.complete = getattr(retain, "client_complete", lambda *args: None)

    def missed(self, offer):
        return self.rows.row(
            "client",
            "client:" + self.gateway,
            self.rows.boot,
            "missed",
            {
                "gateway_uid": self.gateway,
                "config_sha256": self.config,
                "policy": "round-robin",
                "retry_count": 0,
                **{k: offer[k] for k in ("request_id", "offer_index", "prefix_id", "scheduled_ms")},
                "dispatch_ms": None,
                "outcome": "missed_offer",
            },
        )

    def request(
        self,
        url,
        payload,
        offer,
        *,
        credential,
        context=None,
        local_test=False,
        cancel_after_content=False,
        tls_observer=None,
        deadline_ns=None,
    ):
        retain = UnitReads(self.retain, mode="sse_frame")
        if deadline_ns is not None:
            if type(deadline_ns) is not int:
                raise IntegrityError("client:request_deadline")
            timeout_seconds = min(
                REQUEST_TIMEOUT_SECONDS, (deadline_ns - time.monotonic_ns()) / 1e9
            )
            if timeout_seconds <= 0:
                raise IntegrityError("client:request_deadline")
        else:
            timeout_seconds = REQUEST_TIMEOUT_SECONDS
        target = urllib.parse.urlsplit(url)
        if target.scheme != "https" and not (
            local_test and target.hostname in ("localhost", "127.0.0.1")
        ):
            raise ValueError("client_requires_tls")
        if target.scheme == "https":
            context = context or ssl.create_default_context()
            if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
                raise ValueError("client_requires_verified_tls")
        fields = {
            "gateway_uid": self.gateway,
            "config_sha256": self.config,
            "policy": "round-robin",
            "retry_count": 0,
            **{k: offer[k] for k in ("request_id", "offer_index", "prefix_id")},
        }
        start = self.rows.clock()
        output = [
            self.rows.row(
                "client",
                "client:" + self.gateway,
                self.rows.boot,
                "offer",
                {
                    **fields,
                    "scheduled_ms": offer["scheduled_ms"],
                    "dispatch_ms": start // 1_000_000,
                    "lateness_ms": max(0, start // 1_000_000 - offer["scheduled_ms"]),
                },
                start_ns=start,
            )
        ]
        decoder = SSEDecoder()
        if deadline_ns is not None:
            timeout_seconds = min(timeout_seconds, (deadline_ns - time.monotonic_ns()) / 1e9)
            if timeout_seconds <= 0:
                raise IntegrityError("client:request_deadline")
        connection = (
            http.client.HTTPSConnection(
                target.hostname, target.port or 443, context=context, timeout=timeout_seconds
            )
            if target.scheme == "https"
            else http.client.HTTPConnection(
                target.hostname, target.port or 80, timeout=timeout_seconds
            )
        )
        try:
            contract = client_contract(payload.get("max_tokens", 1))
        except ValueError as exc:
            connection.close()
            refuse(retain, str(exc), start, self.rows.clock())
        connection.response_class = guarded_response(retain, self.rows.clock)
        sse_budget = SSEBudget(
            contract,
            lambda reason: refuse(retain, reason, start, self.rows.clock()),
        )
        expired, responses = threading.Event(), []

        def absolute_timeout():
            expired.set()
            sockets = [connection.sock]
            if responses and responses[0].fp:
                sockets.append(getattr(responses[0].fp.raw, "_sock", None))
            for sock in sockets:
                if sock is not None:
                    try:
                        sock.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
            connection.close()

        if deadline_ns is not None:
            timeout_seconds = min(timeout_seconds, (deadline_ns - time.monotonic_ns()) / 1e9)
            if timeout_seconds <= 0:
                connection.close()
                raise IntegrityError("client:request_deadline")
        timer = threading.Timer(timeout_seconds, absolute_timeout)
        timer.daemon = True
        timer.start()
        try:
            if deadline_ns is not None and time.monotonic_ns() >= deadline_ns:
                raise TimeoutError("client_absolute_timeout")
            connection.connect()
            if target.scheme == "https":
                tls = {
                    "verified": True,
                    "version": connection.sock.version(),
                    "peer_sha256": hashlib.sha256(connection.sock.getpeercert(True)).hexdigest(),
                }
                retain(start, self.rows.clock(), b"", {"tls": tls})
                if tls_observer:
                    tls_observer(tls, start, self.rows.clock())
            if deadline_ns is not None and time.monotonic_ns() >= deadline_ns:
                raise TimeoutError("client_absolute_timeout")
            connection.request(
                "POST",
                target.path,
                json.dumps(payload),
                {
                    "Authorization": "Bearer " + credential,
                    "Content-Type": "application/json",
                    "X-Request-ID": offer["request_id"],
                },
            )
            response = connection.getresponse()
            responses.append(response)
            retain(
                start,
                self.rows.clock(),
                b"",
                {
                    "status": response.status,
                    "headers": list(response.getheaders()),
                },
            )
            # Retain this bijection with the secured HTTP evidence. The offered
            # schedule ID and gateway-owned request ID have distinct ownership.
            gateway_request = response.getheader("X-Request-ID")
            with self.binding_lock:
                if not gateway_request or gateway_request in self.request_ids:
                    raise IntegrityError("client_gateway_request_id_missing_or_reused")
                self.request_ids[gateway_request] = offer["request_id"]
            status = response.status
            output.append(
                self.rows.row(
                    "client",
                    "client:" + self.gateway,
                    self.rows.boot,
                    "receive",
                    {**fields, "http_status": status},
                )
            )
            if status != 200:
                body = response.read(CLIENT_DENIAL_BYTES + 1)
                retain(start, self.rows.clock(), body, {"status": status})
                if len(body) > CLIENT_DENIAL_BYTES:
                    refuse(
                        retain,
                        "capture:producer:client_denial_bytes",
                        start,
                        self.rows.clock(),
                    )
                retain.finish("body")
                denied = strict_json(body)
                code = denied.get("error", {}).get("code")
                output.append(
                    self.rows.row(
                        "client",
                        "client:" + self.gateway,
                        self.rows.boot,
                        "deny",
                        {
                            **fields,
                            "http_status": status,
                            "denial_code": code,
                            "admit_called": None,
                        },
                        start_ns=start,
                    )
                )
            else:
                while True:
                    remaining = (
                        REQUEST_TIMEOUT_SECONDS - (self.rows.clock() - start) / 1_000_000_000
                    )
                    if deadline_ns is not None:
                        remaining = min(remaining, (deadline_ns - time.monotonic_ns()) / 1e9)
                    if remaining <= 0:
                        raise TimeoutError("client_absolute_timeout")
                    if connection.sock:
                        connection.sock.settimeout(remaining)
                    chunk = response.read1(65536)
                    retain(start, self.rows.clock(), chunk, {"status": status})
                    if not chunk:
                        break
                    if len((decoder.buffer + chunk).replace(b"\r\n", b"\n")) > CLIENT_PENDING_BYTES:
                        refuse(
                            retain,
                            "capture:producer:client_sse_pending",
                            start,
                            self.rows.clock(),
                        )
                    sse_budget.feed(chunk)
                    retain.units()
                    now = self.rows.clock()
                    decoder.feed(chunk, [now // 1_000_000] * 2)
                    output.append(
                        self.rows.row(
                            "client",
                            "client:" + self.gateway,
                            self.rows.boot,
                            "sse",
                            {**fields, "chunk_hex": chunk.hex()},
                            start_ns=now,
                        )
                    )
                    if cancel_after_content and decoder.content:
                        # One observed content token exhausts a one-token
                        # request even when the finish record is a later read.
                        # This refuses cancellation intent; native completion
                        # remains a separately required source observation.
                        if decoder.finish or payload.get("max_tokens") == 1:
                            raise IntegrityError("client_cancel_already_complete")
                        output.append(
                            self.rows.row(
                                "client",
                                "client:" + self.gateway,
                                self.rows.boot,
                                "cancel",
                                fields,
                            )
                        )
                        # The native abort endpoint must independently confirm
                        # this action; missing DONE/release never supplies it.
                        if connection.sock:
                            connection.sock.shutdown(socket.SHUT_RDWR)
                        connection.close()
                        output.append(
                            self.rows.row(
                                "client",
                                "client:" + self.gateway,
                                self.rows.boot,
                                "terminal",
                                {
                                    **fields,
                                    "http_status": status,
                                    "outcome": "right_censored",
                                    "transport_end": "client_cancel",
                                },
                            )
                        )
                        return output
            retain.finish("eof")
            report = decoder.report()
            if expired.is_set() or (deadline_ns is not None and time.monotonic_ns() >= deadline_ns):
                raise TimeoutError("client_absolute_timeout")
            output.append(
                self.rows.row(
                    "client",
                    "client:" + self.gateway,
                    self.rows.boot,
                    "terminal",
                    {
                        **fields,
                        "http_status": status,
                        "outcome": "complete" if report["complete"] else "failed",
                        "transport_end": "eof",
                    },
                )
            )
            return output
        except ProducerLimit:
            raise
        except (OSError, ValueError, http.client.HTTPException) as exc:
            message = client_error_text(exc, retain, start, self.rows.clock())
            retain(start, self.rows.clock(), getattr(exc, "partial", b""), {"error": message})
            deadline_reached = deadline_ns is not None and time.monotonic_ns() >= deadline_ns
            output.append(
                self.rows.row(
                    "client",
                    "client:" + self.gateway,
                    self.rows.boot,
                    "timeout"
                    if expired.is_set() or deadline_reached or isinstance(exc, TimeoutError)
                    else "terminal",
                    {
                        **fields,
                        "outcome": "right_censored"
                        if expired.is_set() or deadline_reached or isinstance(exc, TimeoutError)
                        else "failed",
                        "transport_end": "error",
                    },
                    error=type(exc).__name__,
                )
            )
            return output
        finally:
            retain.finish("close")
            timer.cancel()
            connection.close()
            self.complete(start, self.rows.clock(), b"", {"client_request_end": True})
