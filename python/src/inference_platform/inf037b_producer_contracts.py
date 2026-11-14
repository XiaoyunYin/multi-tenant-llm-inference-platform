"""Round 367 source-derived reading contracts, not registered workload changes.

Derivations and immutable source/line citations live in the slice plan. Limits
are checked by readers; no gateway or vLLM behaviour is changed.
"""

import http.client
import json
import math
import re
import threading
import time

from .inf037b_archive import strict_json
from .inf037b_producer_limits import RESP_LINE_BYTES, refuse
from .stage_c_tokenizer import MODEL

# Verified tokenizer.json at stage_c_tokenizer.FILE_HASHES, decoded vocabulary.
TOKEN_BYTES = 128
INT64_CHARS = 20
UID_BYTES, NAME_BYTES, LABEL_BYTES = 36, 253, 63
STREAM_ID_BYTES = 2 * INT64_CHARS + 1
# coordinator.go tenantPattern; Lua report has two numeric values and a bool.
GATEWAY_ID_BYTES = 191
REPORT_BYTES = len(b'{"n":,"expires":,"unknown":}') + 2 * INT64_CHARS + 5
AUDIT_COUNT = 1000
ADMIT_FIELDS = {
    "capture_seq": INT64_CHARS,
    "event": len("report_store"),
    "redis_time_ms": INT64_CHARS,
    "reservation_id": len("rsv_") + 32,
    "gateway_uid": GATEWAY_ID_BYTES,
    "decision": len("tenant_concurrency_limit"),
    "idempotent": 1,
    "effective_b": INT64_CHARS,
    "effective_n": INT64_CHARS,
    "occupied": INT64_CHARS,
    "report": REPORT_BYTES,
}
RELEASE_FIELDS = {
    k: ADMIT_FIELDS[k]
    for k in (
        "capture_seq",
        "event",
        "redis_time_ms",
        "reservation_id",
        "decision",
        "idempotent",
        "occupied",
    )
}
AUDIT_SCRIPT = "return {redis.call('XRANGE',KEYS[1],'('..ARGV[1],'+','COUNT',1000),redis.call('GET',KEYS[1]..':sequence') or '0'}"


def bulk_bytes(n):
    return n + len(str(n)) + 5


def audit_reply_contract():
    entry = (
        4
        + bulk_bytes(STREAM_ID_BYTES)
        + len(b"*22\r\n")
        + sum(bulk_bytes(len(k)) + bulk_bytes(v) for k, v in ADMIT_FIELDS.items())
    )
    raw = 4 + len(b"*1000\r\n") + AUDIT_COUNT * entry + bulk_bytes(INT64_CHARS)
    return {
        "bytes": max(RESP_LINE_BYTES, raw),  # preserve the existing error-line ceiling
        "elements": 3 + AUDIT_COUNT * (3 + 2 * len(ADMIT_FIELDS)),
        "depth": 4,
        "bulk": max(GATEWAY_ID_BYTES, REPORT_BYTES, STREAM_ID_BYTES),
        "valid_reply_bytes": raw,
        "entry_bytes": entry,
        "audit": True,
    }


def check_audit(value, reject):
    """Reject malformed/unbounded fields before any application normalization."""
    if not isinstance(value, list) or len(value) != 2 or not isinstance(value[0], list):
        reject("capture:producer:resp_audit_shape")
    batch, high = value
    if len(batch) > AUDIT_COUNT:
        reject("capture:producer:resp_audit_entries")
    if not isinstance(high, bytes) or len(high) > INT64_CHARS:
        reject("capture:producer:resp_audit_high_water")

    def integer(raw):
        return bool(re.fullmatch(rb"-?[0-9]+", raw)) and -(2**63) <= int(raw) < 2**63

    if not integer(high):
        reject("capture:producer:resp_audit_type")
    for item in batch:
        if not isinstance(item, list) or len(item) != 2:
            reject("capture:producer:resp_audit_shape")
        identity, fields = item
        if not isinstance(identity, bytes) or len(identity) > STREAM_ID_BYTES:
            reject("capture:producer:resp_audit_id")
        components = identity.split(b"-")
        if len(components) != 2 or any(not p.isdigit() or int(p) >= 2**64 for p in components):
            reject("capture:producer:resp_audit_type")
        if not isinstance(fields, list) or len(fields) % 2:
            reject("capture:producer:resp_audit_shape")
        mapping = {}
        for key, field in zip(fields[::2], fields[1::2], strict=True):
            if not isinstance(key, bytes) or not isinstance(field, bytes) or key in mapping:
                reject("capture:producer:resp_audit_shape")
            if not key.isascii() or not field.isascii():
                reject("capture:producer:resp_audit_non_ascii")
            mapping[key] = field
        names = {k.encode(): v for k, v in ADMIT_FIELDS.items()}
        release = {k.encode(): v for k, v in RELEASE_FIELDS.items()}
        limits = release if mapping.get(b"event") == b"release" else names
        if set(mapping) != set(limits):
            reject("capture:producer:resp_audit_fields")
        for key, field in mapping.items():
            if len(field) > limits[key]:
                reject("capture:producer:resp_audit_field:" + key.decode("ascii"))
        for key in (b"capture_seq", b"redis_time_ms", b"effective_b", b"effective_n", b"occupied"):
            if mapping.get(key) and not integer(mapping[key]):
                reject("capture:producer:resp_audit_type")
        if mapping[b"idempotent"] not in (b"0", b"1"):
            reject("capture:producer:resp_audit_type")
        if mapping.get(b"report"):
            try:
                report = strict_json(mapping[b"report"])
                valid = (
                    set(report) == {"n", "expires", "unknown"}
                    and type(report["n"]) is int
                    and 0 <= report["n"] <= 1000000
                    and type(report["expires"]) is int
                    and -(2**63) <= report["expires"] < 2**63
                    and type(report["unknown"]) is bool
                )
            except (TypeError, ValueError):
                valid = False
            if not valid:
                reject("capture:producer:resp_audit_type")


HEADER_NAMES = (
    "X-Request-ID",
    "X-Trace-ID",
    "Allow",
    "Retry-After",
    "Content-Type",
    "Cache-Control",
    "X-Inference-Backend",
    "Date",
    "Transfer-Encoding",
    "Content-Length",
    "Connection",
    "Server",
    "X-Accel-Buffering",
    "X-Content-Type-Options",
)
HEADER_COUNT = len(HEADER_NAMES)
HEADER_NAME_BYTES = max(map(len, HEADER_NAMES))
HEADER_VALUE_BYTES = NAME_BYTES
HEADER_LINE_BYTES = HEADER_NAME_BYTES + HEADER_VALUE_BYTES + 4
# Status line uses the pinned Python parser ceiling; final blank line is CRLF.
HEADER_BYTES = http.client._MAXLINE + HEADER_COUNT * HEADER_LINE_BYTES + 2
HEADER_REJECTED_BYTES = HEADER_BYTES + http.client._MAXLINE + 1
ERROR_TEXT_BYTES = 4 * http.client._MAXLINE + 2  # worst repr(Latin-1 status line)
ERROR_TEXT_CHUNK = (
    1024  # UTF-8 <=4 bytes/codepoint, same bounded string-chunk method as bounded_json
)


def client_error_text(error, retain, start, end):
    """Read error context in bounded UTF-8 chunks; refuse, never accept a prefix."""
    text, data = str(error), bytearray()
    for at in range(0, len(text), ERROR_TEXT_CHUNK):
        chunk = text[at : at + ERROR_TEXT_CHUNK].encode("utf-8")
        data.extend(chunk)
        if len(data) > ERROR_TEXT_BYTES:
            retain(start, end, bytes(data), {"client_rejected_error_text": True})
            refuse(retain, "capture:producer:client_error_bytes", start, end)
    return text


class HeaderReader:
    """Bound before http.client parses, keeping a rejected header's raw tail.

    Successful response wire format stays the existing parsed-header record.
    Only rejected/partial headers add a raw custody record. No Expect header is
    sent by the client, so this producer contract allows one final response.
    """

    def __init__(self, stream, retain, clock, *, client=True):
        self.stream, self.retain, self.clock = stream, retain, clock
        self.start = clock()
        self.data = bytearray()
        self.at_status, self.responses, self.headers = True, 0, 0
        self.kept = False
        self.client = client
        self.header_count = HEADER_COUNT if client else http.client._MAXHEADERS - 1
        self.header_line_bytes = HEADER_LINE_BYTES if client else http.client._MAXLINE
        self.header_bytes = (
            HEADER_BYTES if client else http.client._MAXHEADERS * http.client._MAXLINE + 2
        )
        self.prefix = "capture:producer:client_" if client else "capture:producer:http_"

    def __getattr__(self, name):
        return getattr(self.stream, name)

    def keep(self):
        if self.data and not self.kept:
            self.kept = True
            self.retain(self.start, self.clock(), bytes(self.data), {"rejected_headers": True})

    def reject(self, reason):
        self.keep()
        refuse(self.retain, reason, self.start, self.clock())

    def readline(self, limit=-1):
        cap = http.client._MAXLINE if self.at_status else self.header_line_bytes
        line = self.stream.readline(min(cap + 1, limit) if limit >= 0 else cap + 1)
        self.data.extend(line)
        if len(line) > cap:
            self.reject(self.prefix + "header_line")
        if len(self.data) > self.header_bytes:
            self.reject(self.prefix + "header_bytes")
        if self.at_status:
            self.responses += 1
            if self.responses > 1:
                self.reject(self.prefix + "header_responses")
            self.at_status = False
        elif line in (b"\r\n", b"\n", b""):
            self.at_status = True
        else:
            self.headers += 1
            if self.headers > self.header_count:
                self.reject(self.prefix + "header_count")
            key, sep, value = line.rstrip(b"\r\n").partition(b":")
            if self.client and (
                len(key) > HEADER_NAME_BYTES
                or (bool(sep) and len(value.lstrip(b" \t")) > HEADER_VALUE_BYTES)
            ):
                self.reject(self.prefix + "header_field")
        return line


def guarded_response(retain, clock, *, client=True):
    class Response(http.client.HTTPResponse):
        def begin(self):
            raw = self.fp
            guard = HeaderReader(raw, retain, clock, client=client)
            self.fp = guard
            try:
                return super().begin()
            except Exception:
                guard.keep()
                raise
            finally:
                if self.fp is guard:
                    self.fp = raw

    return Response


def client_contract(tokens=1):
    # Trace is one token; the separate frozen setup controls permit 64. This
    # ceiling cannot authorize another workload: callers retain their pins.
    from .inf037b_controls import CONTROL_TOKENS

    if type(tokens) is not int or not 1 <= tokens <= CONTROL_TOKENS:
        raise ValueError("capture:producer:client_request_tokens")

    def size(value):
        return len(json.dumps(value, separators=(",", ":")).encode())

    base = {"id": "", "object": "chat.completion.chunk", "created": -(2**63), "model": ""}
    content = {
        **base,
        "choices": [
            {"index": 0, "delta": {"role": "assistant", "content": ""}, "finish_reason": "length"}
        ],
    }
    usage = {
        **base,
        "choices": [],
        "usage": {
            "prompt_tokens": -(2**63),
            "completion_tokens": -(2**63),
            "total_tokens": -(2**63),
            "count_source": "runtime_usage",
        },
    }
    identity = len("chatcmpl_req_") + 32
    model = 6 * len(MODEL.encode())
    # Go encoding/json expands a content UTF-8 byte by at most six ASCII bytes.
    frame = max(size(content) + 6 * TOKEN_BYTES * tokens, size(usage)) + identity + model + 10
    frames = tokens + 5  # role + <=K content + finish + usage + DONE + one error
    return {"frames": frames, "frame_bytes": frame, "body_bytes": frames * frame}


class SSEBudget:
    def __init__(self, contract, reject):
        self.contract, self.reject = contract, reject
        self.pending = bytearray()
        self.frames = self.total = 0

    def feed(self, data):
        self.total += len(data)
        if self.total > self.contract["body_bytes"]:
            self.reject("capture:producer:client_body_bytes")
        self.pending.extend(data)
        while True:
            ends = [
                p + len(delimiter)
                for delimiter in (b"\n\n", b"\n\r\n")
                if (p := self.pending.find(delimiter)) >= 0
            ]
            if not ends:
                if len(self.pending) > self.contract["frame_bytes"]:
                    self.reject("capture:producer:client_frame_bytes")
                return
            end = min(ends)
            if end > self.contract["frame_bytes"]:
                self.reject("capture:producer:client_frame_bytes")
            self.frames += 1
            if self.frames > self.contract["frames"]:
                self.reject("capture:producer:client_frames")
            del self.pending[:end]


# One full serving-set lifecycle per fixed effect; allow every API phase and
# both bookmark/status refreshes, not an observed event count. Source table
# enumerates the effects and 32 transitions/pod. Retries remain zero in CaptureOwner.
POD_TRANSITIONS = 4 + 5 + 2 * 6 + 3 + 2 + 2 + 4
FIXED_POD_GENERATIONS = 2 * (5 + 3 * 5 + 2)  # slots * (setup + attempt stages + resets)
WATCH_EVENTS = POD_TRANSITIONS * FIXED_POD_GENERATIONS
WATCH_TIMEOUT_SECONDS = 7200


def watch_contract(duration_s):
    return {
        "events": WATCH_EVENTS,
        "connections": 1 + math.floor(duration_s / WATCH_TIMEOUT_SECONDS) + 5 + 3 * 5 + 2,
    }


def redis_scope_contract(duration_s=None):
    """Uncomposed transport has no invented polling/call envelope (R517)."""
    from .inf037b_eks_collectors import producer_entries

    return {
        "entries": producer_entries(),
        "AUTH": None,
        "TIME": None,
        "snapshot": None,
        "audit": None,
    }


def validate_kube_identities(value, reject):
    if isinstance(value, dict):
        metadata = value.get("metadata")
        if isinstance(metadata, dict):
            for key, cap in (
                ("uid", UID_BYTES),
                ("name", NAME_BYTES),
                ("namespace", NAME_BYTES),
                ("resourceVersion", INT64_CHARS),
            ):
                if key in metadata and (
                    not isinstance(metadata[key], str) or len(metadata[key].encode()) > cap
                ):
                    reject("capture:producer:kube_" + key)
            labels = metadata.get("labels", {})
            if isinstance(labels, dict):
                if any(
                    not isinstance(v, str) or len(v.encode()) > LABEL_BYTES for v in labels.values()
                ):
                    reject("capture:producer:kube_label_value")
                if any(len(k.encode()) > NAME_BYTES + 1 + LABEL_BYTES for k in labels):
                    reject("capture:producer:kube_label_key")
            annotations = metadata.get("annotations", {})
            if isinstance(annotations, dict) and any(
                not isinstance(v, str) for v in annotations.values()
            ):
                reject("capture:producer:kube_annotations")
            if (
                isinstance(annotations, dict)
                and sum(len(k.encode()) + len(str(v).encode()) for k, v in annotations.items())
                > 256 * 1024
            ):
                reject("capture:producer:kube_annotations")
        for item in value.values():
            validate_kube_identities(item, reject)
    elif isinstance(value, list):
        for item in value:
            validate_kube_identities(item, reject)


class WatchBudget:
    def __init__(self, *, stop_ns, reject, state=None):
        self.stop_ns, self.reject = stop_ns, reject
        self.state = state if type(state) is dict else {}
        self.lock = self.state.setdefault("producer_lock", threading.RLock())
        with self.lock:
            self.contract = self.state.setdefault(
                "watch_contract", watch_contract(max(0, (stop_ns - time.monotonic_ns()) / 1e9))
            )

    def connect(self):
        with self.lock:
            self.state["watch_connections"] = self.state.get("watch_connections", 0) + 1
            if self.state["watch_connections"] > self.contract["connections"]:
                self.reject("capture:producer:watch_connections")

    def event(self, value):
        validate_kube_identities(value, self.reject)
        with self.lock:
            self.state["watch_events"] = self.state.get("watch_events", 0) + 1
            if self.state["watch_events"] > self.contract["events"]:
                self.reject("capture:producer:watch_events")
            obj = value.get("object") if isinstance(value, dict) else None
            metadata = obj.get("metadata") if isinstance(obj, dict) else None
            uid = metadata.get("uid") if isinstance(metadata, dict) else None
            if uid:
                seen = self.state.setdefault("watch_uids", {})
                seen[uid] = seen.get(uid, 0) + 1
                if len(seen) > FIXED_POD_GENERATIONS:
                    self.reject("capture:producer:watch_generations")
                if seen[uid] > POD_TRANSITIONS:
                    self.reject("capture:producer:watch_pod_events")
