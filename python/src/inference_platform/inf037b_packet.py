"""Offline source-bound manifests, registered sizing formulas and sanitization.

No AWS adapter or pricing lookup. Supplied prices are evidence-bound inputs,
not current prices or permission to spend. Missing live inputs block readiness.
"""

import copy
import hashlib
import hmac
import json
import math
import re
from pathlib import Path

from .inf037b_archive import (
    Archive,
    IntegrityError,
    durable_write,
    encode,
    inspect_segment,
    record_key,
    sha,
    verify_archive,
)
from .inf037b_contract import (
    CAMPAIGN_MS,
    REGISTRATION_GIT_BLOB_SHA256,
    REGISTRATION_ID,
    SOURCE_KINDS,
)
from .inf037b_export_runtime import batched_durability
from .inf037b_requests import CODES, SSEDecoder
from .inf037b_sources import (
    EVENTS,
    EXTRA,
    EXTRA_PAYLOAD_KEYS,
    FIELDS,
    source_order,
    validate_payload,
)
from .inf037b_sse_json import sse_json_loads
from .inf037b_stream import StreamingArchiveWriter

REQUIRED_PINS = (
    "registration",
    "collector",
    "images",
    "model",
    "tokenizer",
    "template",
    "engine",
    "manifests",
    "workload",
    "trace",
    "salt_domain",
    "kubernetes",
    "controller",
    "scheduler",
    "metric_semantics",
    "topology",
    "clock_fitness",
)
LIVE_INPUTS = (
    "signal_capture",
    "atomic_redis_authorization",
    "incremental_ingress",
    "startup_cold",
    "startup_node_cached",
    "lifecycle",
    "transfer",
    "cost_forecast",
    "saved_plan",
)


def workload_trace(phase: str, attempt: int, duration_ms: int):
    """v3 :59: R1 weighted multiset, M5 seed, exact rational scheduled offsets."""
    if (
        phase not in ("pre", "event")
        or type(attempt) is not int
        or attempt not in (1, 2, 3)
        or type(duration_ms) is not int
        or duration_ms <= 0
    ):
        raise IntegrityError("invalid_trace_input")
    count = math.ceil(duration_ms * 1092 / 100_000)
    entries = [(f"p{i:03}", n) for i in range(384) for n in range(12 if i < 96 else 1)]
    result = []
    for epoch in range(math.ceil(count / len(entries))):
        ordered = sorted(
            entries,
            key=lambda item, epoch=epoch: (
                hashlib.sha256(
                    f"inf037b-v1|{phase}|{attempt}|{epoch}|{item[0]}|{item[1]}".encode()
                ).digest(),
                item,
            ),
        )
        for prefix, occurrence in ordered:
            index = len(result)
            if index >= count:
                break
            result.append(
                {
                    "request_id": f"a{attempt}-{phase}-{index}",
                    "offer_index": index,
                    "prefix_id": prefix,
                    "occurrence": occurrence,
                    "epoch": epoch,
                    "gateway_uid": f"gateway{index % 2}",
                    "phase": phase,
                    "scheduled_ms_numerator": index * 100_000,
                    "scheduled_ms_denominator": 1092,
                }
            )
    return result


def source_manifest(artifacts: dict[str, bytes]) -> dict:
    missing = set(REQUIRED_PINS) - artifacts.keys()
    if missing:
        raise IntegrityError("missing_packet_sources:" + ",".join(sorted(missing)))
    hashes = {name: sha(data) for name, data in artifacts.items()}
    if hashes["registration"] != REGISTRATION_GIT_BLOB_SHA256:
        raise IntegrityError("registration_bytes_mismatch")
    return {
        "registration_id": REGISTRATION_ID,
        "sources_sha256": hashes,
        "resolved": False,
        "basis": "offline_synthetic_until_live_inputs_bound",
    }


def verify_sources(manifest: dict, artifacts: dict[str, bytes]):
    if manifest != source_manifest(artifacts):
        raise IntegrityError("packet_source_mismatch")


def sizing(
    *,
    maximum_record_bytes: dict[str, int],
    request_record_bytes: int,
    request_events: int,
    transfer_bytes_per_second: int,
    reconnect_ms: int,
    lifecycle: dict[str, dict],
    prices: list[dict],
    already_spent_usd: float,
    full_project_remaining_usd: float,
) -> dict:
    """v3 :74; sizes cover 3 full attempts plus both full 300s resets, 2x margin.

    Includes all sources/identities, 1092/100 offers/sec, event-driven byte caps,
    manifests/receipts via explicit caller bound. No outcome-based compression.
    """
    required = {"vllm", "gateway", "kubernetes", "redis", "clocks", "controller", "metadata"}
    if set(maximum_record_bytes) != required or any(
        type(v) is not int or v <= 0 for v in maximum_record_bytes.values()
    ):
        raise IntegrityError("missing_or_invalid_size_bounds")
    if (
        any(
            type(v) is not int or v <= 0
            for v in (request_record_bytes, request_events, transfer_bytes_per_second)
        )
        or reconnect_ms < 0
    ):
        raise IntegrityError("invalid_export_bounds")
    # Identity counts are the two gateways/two slots plus Redis, Kube and host.
    periods = {
        "vllm": (500, 2),
        "gateway": (250, 2),
        "kubernetes": (250, 1),
        "redis": (250, 1),
        "clocks": (1000, 8),
        "controller": (250, 1),
    }
    rows = {
        kind: (math.ceil(CAMPAIGN_MS / cadence) + 1) * count
        for kind, (cadence, count) in periods.items()
    }
    offers = math.ceil(CAMPAIGN_MS * 1092 / 100_000)
    raw = (
        sum(rows[k] * maximum_record_bytes[k] for k in rows)
        + offers * request_events * request_record_bytes
        + maximum_record_bytes["metadata"]
    )
    maximum = 2 * raw
    export = (
        math.ceil((2 * maximum * 1000 / transfer_bytes_per_second + reconnect_ms) / 60_000) * 60_000
    )
    allowances = {}
    for phase in ("creation_readiness", "preparation", "cleanup"):
        item = lifecycle.get(phase, {})
        if not {
            "observed_ms",
            "offline_bound_ms",
            "source_sha256",
        } <= item.keys() or not re.fullmatch(r"[0-9a-f]{64}", item.get("source_sha256", "")):
            raise IntegrityError("missing_lifecycle_source:" + phase)
        if any(
            type(item[k]) is not int or item[k] < 0 for k in ("observed_ms", "offline_bound_ms")
        ):
            raise IntegrityError("invalid_lifecycle_bound")
        allowances[phase] = (
            math.ceil(max(2 * item["observed_ms"], item["offline_bound_ms"]) / 60_000) * 60_000
        )
    absolute = sum(allowances.values()) + CAMPAIGN_MS + export
    if not prices or any(
        not {"resource", "usd_per_hour", "count", "lifetime_ms", "source_sha256"} <= p.keys()
        for p in prices
    ):
        raise IntegrityError("missing_cost_inputs")
    cost = 0
    for item in prices:
        if not re.fullmatch(r"[0-9a-f]{64}", item["source_sha256"]) or any(
            type(item[k]) not in (int, float) or not math.isfinite(item[k]) or item[k] < 0
            for k in ("usd_per_hour", "count", "lifetime_ms")
        ):
            raise IntegrityError("invalid_cost_input")
        if item["lifetime_ms"] < absolute:
            raise IntegrityError("resource_lifetime_excludes_full_session")
        cost += item["usd_per_hour"] * item["count"] * item["lifetime_ms"] / 3_600_000
    if any(not math.isfinite(v) or v < 0 for v in (already_spent_usd, full_project_remaining_usd)):
        raise IntegrityError("invalid_project_forecast")
    total = already_spent_usd + cost + full_project_remaining_usd
    return {
        "campaign_ms": CAMPAIGN_MS,
        "periodic_rows": rows,
        "offer_upper_bound": offers,
        "raw_byte_bound_before_margin": raw,
        "maximum_archive_bytes": maximum,
        "export_allowance_ms": export,
        "lifecycle_allowances_ms": allowances,
        "absolute_session_ms": absolute,
        "supplied_price_estimate_usd": cost,
        "full_project_estimate_usd": total,
        "within_150_checkpoint": already_spent_usd + cost <= 150,
        "within_300_total": total <= 300,
        "paid_ready": False,
        "basis": "offline_supplied_bounds_and_prices_not_live_fitness",
    }


class PacketReadiness:
    def __init__(self, manifest, live_inputs):
        self.manifest, self.live_inputs = manifest, live_inputs

    def report(self):
        missing = [
            name
            for name in LIVE_INPUTS
            if not isinstance(self.live_inputs.get(name), dict)
            or not re.fullmatch(r"[0-9a-f]{64}", self.live_inputs[name].get("source_sha256", ""))
            or self.live_inputs[name].get("verified") is not True
        ]
        return {
            "ready": False,
            "missing_live_inputs": missing,
            "reason": "offline_checkpoint_requires_independent_resolved_packet_and_exact_plan_review",
            "sources_sha256": self.manifest["sources_sha256"],
        }


class Sanitizer:
    """HMAC pseudonyms join consistently across raw/cohort/summary provenance.

    All arbitrary text is pseudonymized. SSE data is reduced to schema/boolean
    content evidence, never text, preserving arrival time of each complete event.
    Unknown schema keys must be rejected by source normalization before export.
    """

    def __init__(self, key: bytes, *, diagnostics: dict | None = None):
        if len(key) < 32:
            raise IntegrityError("sanitizer_key_too_short")
        self.key, self.buffers, self.done = key, {}, set()
        self.diagnostics = diagnostics or {}
        self.keys = {
            "schema_version",
            "registration_id",
            "session_id",
            "attempt_id",
            "stage",
            "source_kind",
            "source_identity",
            "source_generation",
            "source_seq",
            "record_id",
            "collector_id",
            "collector_boot_id",
            "observed_mono_ns",
            "observed_wall_utc",
            "source_time",
            "capture_start_mono_ns",
            "capture_end_mono_ns",
            "uncertainty_ns",
            "payload",
            "missing_reason",
            "error",
            "clock_id",
            "unit",
            "value",
            "field_reasons",
            "uid",
            "slot",
            "address",
            "ready",
            "sampled",
            "healthy",
            "sample_time_ms",
            "terminating",
            "serving",
            "n",
            "expires_ms",
            "until_ms",
            "unknown",
            "candidate",
            "since_ms",
            "expiry_ms",
            "record_key",
            "locations",
            "segment",
            "line",
            "byte_offset",
            "reason",
            "bytes",
            "row_count",
            "first_sequence",
            "last_sequence",
            "sha256",
            "duplicate_count",
            "torn_tail_offset",
            "integrity_errors",
            "sources_sha256",
            "resolved",
            "basis",
            "sanitized",
            "source_manifest_sha256",
            "segments",
            "pending_sse_streams",
            "attempt_index",
            "target_slot",
            "target_uid",
            "replacement_uid",
            "expected_offers",
            "pre_end_ms",
            "capture_end_ms",
            "capture_start_ms",
            "traffic_start_ms",
            "required_streams",
            "kind",
            "identity",
            "generation",
            "start_ms",
            "end_ms",
            "cadence_ms",
            "absent_intervals",
            "scheduled_ms",
            "scheduled_ms_numerator",
            "scheduled_ms_denominator",
            "phase",
            "occurrence",
            "epoch",
            "event",
            "now_ms",
            "attempt",
            "state",
            "measurement_valid",
            "replacement_usable_by_deadline",
            "operational_outcomes",
            "remaining_ms",
            "export_cleanup_ms",
            "authority",
            "decision_ref",
            *REQUIRED_PINS,
            *EXTRA_PAYLOAD_KEYS,
            *(name for fields in (*FIELDS.values(), *EXTRA.values()) for name in fields.split()),
        }
        self.semantic = {
            *CODES,
            REGISTRATION_ID,
            "round-robin",
            "ms",
            "ns",
            "measurement",
            "setup",
            "cold",
            "node_cached",
            "metrics_not_started",
            "continuous_lifecycle_since_pod_creation",
            "unknown",
            "stop",
            "length",
            "allowed",
            "denied",
            "released",
            "client_cancel_abort",
            "refused",
            "tenant_request_rate",
            "complete",
            "failed",
            "rejected",
            "missed_offer",
            "right_censored",
            "within",
            "exceeded",
            "indeterminate",
            "not_applicable",
            "queued_or_prefill",
            "not_exercised_max_tokens_1",
            *SOURCE_KINDS,
            *(event for events in EVENTS.values() for event in events.split()),
            "pre",
            "event",
            "generator",
            "SIGTERM",
            "attempt_start",
            "attempt_end",
            "setup_complete",
            "setup_failed",
            "traffic_start",
            "capture_window",
            "reset_start",
            "reset_complete",
            "reset_failed",
            "campaign_stop",
            "not_attempted",
            "section_6_4_decision",
        }

    def pseudonym(self, value: str):
        return "id-" + hmac.new(self.key, value.encode(), hashlib.sha256).hexdigest()[:24]

    def value(self, value, field=""):
        if isinstance(value, dict):
            return {
                self.pseudonym(k)
                if field in ("reports",)
                or (
                    k not in self.keys
                    and not re.fullmatch(
                        r"raw/(client|gateway|kubernetes|vllm|redis|clocks|controller)(-\d+)?\.jsonl",
                        k,
                    )
                )
                else k: self.value(v, k)
                for k, v in value.items()
            }
        if isinstance(value, list):
            return [self.value(v, field) for v in value]
        if isinstance(value, str):
            if value == "":
                return ""
            if field == "observed_wall_utc":
                return self.pseudonym(value)
            if field in ("reason", "reasons", "operational_outcomes") and value in self.diagnostics:
                return self.diagnostics[value]
            if (
                value in self.semantic
                # These identifiers are fixed public trace labels, not source IDs.
                # Preserve them so sanitized specs can rederive the same schedule.
                or (field == "request_id" and re.fullmatch(r"a[123]-(pre|event)-\d+", value))
                or (field == "prefix_id" and re.fullmatch(r"p\d{3}", value))
                or re.fullmatch(
                    r"raw/(client|gateway|kubernetes|vllm|redis|clocks|controller)(-\d+)?\.jsonl",
                    value,
                )
                or (
                    re.fullmatch(r"[0-9a-f]{64}", value)
                    and (field.endswith("sha256") or field in REQUIRED_PINS)
                )
                or value in {f"raw/{k}.jsonl" for k in SOURCE_KINDS}
            ):
                return value
            return self.pseudonym(value)
        return value

    def row(self, original, *, final_sse=False, dropped_sse=False):
        row = self.value(copy.deepcopy(original))
        # Every arbitrary ID uses the same function, including standard gateway
        # IDs. Consumers receive the explicit transformed gateway aliases.
        if original["source_kind"] == "client" and original["payload"].get("event") == "sse":
            p = original["payload"]
            if dropped_sse:
                # Schema-invalid rows must remain invalid; conflicts must remain
                # distinct from the accepted copy, without touching stream state.
                if isinstance(p.get("chunk_hex"), str):
                    row["payload"]["chunk_hex"] = "redacted-dropped-" + self.pseudonym(
                        sha(encode(original))
                    )
                return self._finish_row(row)
            key = (original["source_identity"], original["source_generation"], p.get("request_id"))
            try:
                incoming = bytes.fromhex(p["chunk_hex"])
            except (ValueError, TypeError, KeyError):
                if isinstance(p.get("chunk_hex"), str):
                    row["payload"]["chunk_hex"] = "zz"
                return self._finish_row(row)
            if key in self.done:
                row["payload"]["chunk_hex"] = (
                    b"[redacted-post-done]" if incoming.strip() else incoming
                ).hex()
                return self._finish_row(row)
            data = self.buffers.get(key, b"") + incoming
            data = data.replace(b"\r\n", b"\n")
            if len(data) > 1_048_576:
                self.buffers[key] = b""
                row["payload"]["chunk_hex"] = (b"x" * 1_048_577).hex()
                return self._finish_row(row)
            out = []
            while b"\n\n" in data:
                event, data = data.split(b"\n\n", 1)
                fields = [
                    line[5:].lstrip(b" ")
                    for line in event.split(b"\n")
                    if line.startswith(b"data:")
                ]
                if not fields:
                    continue
                raw = b"\n".join(fields)
                if raw == b"[DONE]":
                    out.append(b"data: [DONE]\n\n")
                    self.done.add(key)
                    continue
                try:
                    chunk = sse_json_loads(raw)
                    if not isinstance(chunk, dict):
                        safe = None
                    elif "error" in chunk:
                        safe = {"error": "redacted"}
                    elif chunk.get("choices") == [] and "usage" in chunk:
                        usage = chunk["usage"]
                        safe = {"choices": [], "usage": None}
                        if isinstance(usage, dict):
                            safe["usage"] = {
                                k: v
                                if isinstance(v, (int, float, bool, type(None)))
                                else "redacted"
                                for k in ("prompt_tokens", "completion_tokens", "total_tokens")
                                for v in (usage.get(k),)
                            }
                            safe["usage"]["count_source"] = (
                                "runtime_usage"
                                if usage.get("count_source") == "runtime_usage"
                                else "invalid"
                            )
                    else:
                        choices = chunk.get("choices")
                        safe = {"choices": None}
                        if isinstance(choices, list):
                            safe["choices"] = [None] * len(choices)
                            if len(choices) == 1 and isinstance(choices[0], dict):
                                choice = choices[0]
                                delta = choice.get("delta")
                                text = delta.get("content") if isinstance(delta, dict) else None
                                safe["choices"] = [
                                    {
                                        "index": choice.get("index")
                                        if isinstance(choice.get("index"), (int, bool))
                                        else None,
                                        "delta": {"content": "x" if text else text}
                                        if isinstance(text, (str, type(None)))
                                        and isinstance(delta, dict)
                                        else {"content": 1}
                                        if isinstance(delta, dict)
                                        else None,
                                        "finish_reason": choice.get("finish_reason")
                                        if choice.get("finish_reason") in (None, "stop", "length")
                                        else "invalid",
                                    }
                                ]
                        if "usage" in chunk:
                            safe["usage"] = None
                    out.append(
                        (b"event: error\n" if isinstance(chunk, dict) and "error" in chunk else b"")
                        + b"data: "
                        + json.dumps(safe, separators=(",", ":")).encode()
                        + b"\n\n"
                    )
                except (ValueError, KeyError, TypeError, AttributeError):
                    out.append(b"data: [redacted-invalid]\n\n")
            self.buffers[key] = data
            if data and (key in self.done or final_sse):
                # Keep an unterminated nonempty tail without exporting its bytes.
                out.append(
                    self._done_tail(data)
                    if key in self.done
                    else b"[redacted-pending]"
                    if data.strip()
                    else data
                )
            row["payload"]["chunk_hex"] = b"".join(out).hex()
        return self._finish_row(row)

    @staticmethod
    def _done_tail(data):
        """Preserve the parser class and line boundaries under later whitespace."""
        lines = data.split(b"\n")
        # Later feeds can consume the whole CR run, one CRLF pass at a time.
        classify = data.rstrip(b"\r")
        fields = [
            line[5:].lstrip(b" ") for line in classify.split(b"\n") if line.startswith(b"data:")
        ]
        value = b"\n".join(fields)
        if value == b"[DONE]":
            replacement = b"[DONE]"
        else:
            try:
                sse_json_loads(value)
                replacement = b"0"
            except (ValueError, UnicodeError):
                replacement = b"[redacted-invalid]"
        output, first = [], True
        for line in lines:
            trailing_cr = line[len(line.rstrip(b"\r")) :]
            if line.startswith(b"data:"):
                line_value = line[5:].lstrip(b" ").rstrip(b"\r")
                stand_in = b"[DONE]" if line_value == b"[DONE]" else replacement if first else b""
                output.append(b"data: " + stand_in + trailing_cr)
                first = False
            else:
                output.append(line if not line.strip() else b"[redacted-pending]" + trailing_cr)
        # The input has already had this feed's CRLF normalization. Undo that
        # pass for the stand-in so its decoder reaches the same buffer state.
        return b"\n".join(output).replace(b"\r\n", b"\r\r\n")

    def _finish_row(self, row):
        # Preserve fixed alias vocabulary while raw dynamic identities pseudonymize.
        for g in ("gateway0", "gateway1"):
            row = _replace_value(row, self.pseudonym(g), g)
        return row


def _replace_value(obj, before, after):
    if isinstance(obj, dict):
        return {
            after if k == before else k: _replace_value(v, before, after) for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_replace_value(v, before, after) for v in obj]
    return after if obj == before else obj


@batched_durability
def sanitized_sources(
    raw: Path, destination: Path, *, key: bytes, diagnostics: dict | None = None
) -> tuple[Archive, dict]:
    verified = verify_archive(raw)
    sanitizer = Sanitizer(key, diagnostics=diagnostics)
    registration = json.loads((raw / "registration.json").read_bytes())
    archive = Archive.create(destination, sanitizer.value(registration), sanitized=True)
    writer = StreamingArchiveWriter(destination)
    source_errors = {}
    # Match OfflineCampaign._raw: each registered view includes its own rows
    # and setup. First-copy ownership and incremental state are view-local.
    views = {
        attempt: {
            "sanitizer": Sanitizer(key, diagnostics=diagnostics),
            "seen": set(),
            "sse": [],
            "last": {},
        }
        for attempt in (1, 2, 3)
    }
    sanitized_sse = {}

    def payload_valid(row):
        try:
            validate_payload(row)
            return True
        except (ValueError, TypeError, KeyError):
            return False

    for name in verified["segments"]:
        if not name.startswith("raw/"):
            continue
        for line, row in enumerate(inspect_segment(raw / name, source_errors=True)[1]):
            valid, record = payload_valid(row), record_key(row)
            for attempt, view in views.items():
                if row["attempt_id"] not in (attempt, "setup"):
                    continue
                accepted = valid and record not in view["seen"]
                if accepted:
                    view["seen"].add(record)
                if row["source_kind"] != "client" or row["payload"].get("event") != "sse":
                    continue
                stream = None
                if accepted:
                    stream = (
                        row["source_identity"],
                        row["source_generation"],
                        row["payload"].get("request_id"),
                    )
                    view["last"][stream] = max(view["last"].get(stream, -1), row["source_seq"])
                view["sse"].append((name, line, row, stream, (record, sha(encode(row)))))
    for view in views.values():
        copies = {}
        decoders = {}
        for name, line, row, stream, identity in sorted(
            view["sse"], key=lambda item: source_order(item[2])
        ):
            if identity not in copies:
                copies[identity] = view["sanitizer"].row(
                    row,
                    final_sse=stream is not None and view["last"][stream] == row["source_seq"],
                    dropped_sse=stream is None,
                )
            safe = copies[identity]
            position = (name, line)
            if position in sanitized_sse and sanitized_sse[position] != safe:
                raise IntegrityError("sanitized_setup_view_mismatch")
            sanitized_sse[position] = safe
            if stream is not None:
                pair = decoders.setdefault(stream, (SSEDecoder(), SSEDecoder()))
                for decoder, item in zip(pair, (row, safe), strict=True):
                    try:
                        # Stable read labels also detect content moving between
                        # rows, independently of overlapping clock intervals.
                        decoder.feed(
                            bytes.fromhex(item["payload"]["chunk_hex"]), [row["source_seq"]] * 2
                        )
                    except (ValueError, TypeError, KeyError):
                        decoder.errors.append("invalid_chunk_hex")
        for pair in decoders.values():
            reports = [{k: v for k, v in d.report().items() if k != "pending_bytes"} for d in pair]
            if reports[0] != reports[1]:
                raise IntegrityError("sanitized_sse_report_mismatch")
    # Release per-view row references before the writing pass.
    for view in views.values():
        view["sse"].clear()
        view["seen"].clear()
        view["raw_copies"], view["safe_copies"] = {}, {}
    for name, receipt in verified["segments"].items():
        # Derived artifacts must be rebuilt from sanitized immutable sources.
        if not name.startswith("raw/") and name != "attempts.jsonl":
            continue
        if name not in writer.receipts:
            kind = name.split("/")[-1].split("-")[0].split(".")[0]
            segment_id = int(name.rsplit("-", 1)[1].split(".")[0])
            writer.rotate(kind, segment_id)
        _, rows = inspect_segment(raw / name, source_errors=True, segment_name=name)
        for line, row in enumerate(rows):
            safe = sanitized_sse.get((name, line))
            if safe is None:
                safe = sanitizer.row(row, dropped_sse=True)
            if name.startswith("raw/") and payload_valid(row) != payload_valid(safe):
                raise IntegrityError("sanitized_payload_validation_mismatch")
            if name.startswith("raw/"):
                raw_hash, safe_hash = sha(encode(row)), sha(encode(safe))
                record = record_key(row)
                for attempt, view in views.items():
                    if row["attempt_id"] not in (attempt, "setup"):
                        continue
                    for copies, before, after in (
                        (view["raw_copies"], raw_hash, safe_hash),
                        (view["safe_copies"], safe_hash, raw_hash),
                    ):
                        previous = copies.setdefault((record, before), after)
                        if previous != after:
                            raise IntegrityError("sanitized_duplicate_equality_mismatch")
            writer.append(name, safe)
        if receipt["torn_tail_offset"] is not None:
            # Do not export unknown partial bytes; keep a nonempty invalid tail.
            durable_write(destination / name, b"[redacted-torn-tail", "ab")
        if receipt["integrity_errors"]:
            source_errors[name] = sanitizer.value(receipt)
    durable_write(
        destination / "source-integrity.receipt.json",
        encode(
            {
                "source_manifest_sha256": sha((raw / "SHA256SUMS").read_bytes()),
                "segments": source_errors,
                "pending_sse_streams": sum(
                    bool(buffer)
                    for view in views.values()
                    for buffer in view["sanitizer"].buffers.values()
                ),
            }
        ),
    )
    # Torn tails are preserved independently, so use disk audit on finalization.
    return archive, {
        "source_manifest_sha256": sha((raw / "SHA256SUMS").read_bytes()),
        "segments": source_errors,
    }
