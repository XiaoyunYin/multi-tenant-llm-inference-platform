"""Offline source normalization, arrival ordering, cadence and clocks (:23–39).

All times exposed by these joins are integer milliseconds; original envelope
nanoseconds and exact bytes remain in the archive. Unknown fields are refused.
"""

import copy
import re
from bisect import bisect_left, bisect_right
from collections import defaultdict

from .inf037b_archive import IntegrityError, record_key, validate_envelope
from .inf037b_contract import nonnegative

# Required normalized fields from v3 :35–39. Event-specific inapplicable fields
# may be null only with a field-level reason; absent fields are schema errors.
FIELDS = {
    "client": "event request_id offer_index prefix_id gateway_uid backend_slot backend_uid reservation_id policy config_sha256 http_status denial_code retry_after_ms admit_called decision effective_n effective_b content_seq content_valid finish_valid done_valid outcome partial bytes_received retry_count censor_reason",
    "gateway": "event gateway_uid poll_seq resource_version membership_known members healthy_count report_known report_success last_success_redis_ms error_class",
    "kubernetes": "event resource_version pod_uid slot node_pseudonym revision_sha256 deletion_time signal signal_receipt_time conditions container_state image_sha256 image_cache_state model_cache_state reason endpoints list_valid error",
    "vllm": "event pod_uid slot process_generation model_sha256 runtime_sha256 sample_time running waiting prefix_query_tokens_total prefix_hit_tokens_total preemptions_total health_ready reset_generation metric_semantics_sha256",
    "redis": "event redis_time_ms reports lows state active_reservations occupied config_sha256",
    "clocks": "event clock_id boot_id local_mono_ms local_wall_ms remote_ms send_ms receive_ms",
    "controller": "event attempt_index target_slot target_uid start_ms action_ms end_ms deadline_ms preconditions validity reasons safe_stop_reason archive_receipt export_status cleanup_status",
}
EXTRA = {
    "client": "scheduled_ms dispatch_ms lateness_ms chunk_hex transport_end request_open_ms request_terminal_ms",
    "gateway": "replacement_uid install_redis_ms_bounds store_order last_complete_report_redis_ms addition_report_age_ms_bounds renewal_elapsed_ms_bounds age_budget_status renewal_budget_status age_budget_reason renewal_budget_reason age_elapsed_lower_bound_ms renewal_elapsed_lower_bound_ms redis_ms computed_ms complete withheld report_store_ms request_id backend_uid backend_slot reservation_id decision effective_n effective_b http_status denial_code retry_after_ms admit_called operation idempotent occupied result error snapshot_id",
    "kubernetes": "gpu_free_ms pod_created_ms scheduled_ms startup_ms ready_ms kind controller_sha256 grace_ms signal_ms engine_command engine_args engine_argv_sha256 engine_flags container_id restart_count gpu_count",
    "vllm": "request_id accept_ms terminal_ms terminal_reason cache_config_labels max_model_len observation_error",
    "redis": "operation gateway_uid request_id reservation_id decision effective_b effective_n idempotent result error snapshot_id store_order report_known report_success report_complete n expires_ms until_ms unknown backend_uids computed_ms",
    "clocks": "uncertainty_ms offset_ms_bounds",
    "controller": "name value unit input_sha256 formula selected_ms cpu_fraction nic_fraction role window_start_ms window_end_ms limit_known",
}
INTS = set(
    "offer_index backend_slot http_status retry_after_ms effective_n effective_b content_seq bytes_received retry_count poll_seq healthy_count last_success_redis_ms running waiting prefix_query_tokens_total prefix_hit_tokens_total preemptions_total redis_time_ms occupied attempt_index target_slot".split()
)
BOOLS = set(
    "admit_called content_valid finish_valid done_valid partial membership_known report_known report_success health_ready list_valid idempotent complete withheld unknown report_complete validity limit_known".split()
)
EVENTS = {
    "client": "offer receive admit deny select revalidate upstream_open content terminal cancel timeout missed sse live_set",
    "gateway": "poll_start poll_end install health report_intent report_result addition_budget_summary select revalidate upstream_open upstream_close admit deny release live_set",
    "kubernetes": "snapshot watch signal container_state deletion pod_created gpu_free scheduled startup ready watch_disconnect relist",
    "vllm": "sample accept terminal process_end engine_config",
    "redis": "snapshot report_store unknown admit release read_error",
    "clocks": "mapping missed",
    "controller": "start action end deadline precondition resolution resource missed_slot",
}

# Top-level extras and boundary-object members have different schema roles.
TOP_LEVEL_EXTRA_KEYS = frozenset("field_reasons request_ids boundaries".split())
BOUNDARY_KEYS = frozenset(
    "pods_resource_version endpointslices_resource_version "
    "cache_witness_ms_bounds creation_ms_bounds".split()
)
# Both sets are sanitizer vocabulary. Only TOP_LEVEL_EXTRA_KEYS belong in the
# general payload allowlist.
EXTRA_PAYLOAD_KEYS = TOP_LEVEL_EXTRA_KEYS | BOUNDARY_KEYS


def validate_payload(row: dict) -> None:
    validate_envelope(row)
    kind, payload = row["source_kind"], row["payload"]
    required = set(FIELDS[kind].split())
    allowed = required | set(EXTRA[kind].split()) | TOP_LEVEL_EXTRA_KEYS
    if required - payload.keys():
        raise IntegrityError("source_schema_missing:" + ",".join(sorted(required - payload.keys())))
    if payload.keys() - allowed:
        raise IntegrityError("source_schema_unknown:" + ",".join(sorted(payload.keys() - allowed)))
    if payload["event"] not in EVENTS[kind].split():
        raise IntegrityError("source_schema_event")
    reasons = payload.get("field_reasons", {})
    if not isinstance(reasons, dict):
        raise IntegrityError("invalid_field_reasons")
    boundaries = payload.get("boundaries")
    if boundaries is not None:
        if not isinstance(boundaries, dict):
            raise IntegrityError("source_schema_object:boundaries")
        unknown_boundaries = boundaries.keys() - BOUNDARY_KEYS
        if unknown_boundaries:
            raise IntegrityError(
                "source_schema_unknown_boundary:" + ",".join(sorted(unknown_boundaries))
            )
        for name, value in boundaries.items():
            if name.endswith("_ms_bounds"):
                if value is None and isinstance(row.get("error"), str) and row["error"]:
                    continue
                if (
                    not isinstance(value, list)
                    or len(value) != 2
                    or any(type(part) is not int for part in value)
                    or value[0] > value[1]
                ):
                    raise IntegrityError("source_schema_bracket:" + name)
            elif not isinstance(value, str) or not value:
                raise IntegrityError("source_schema_boundary_identity:" + name)
    for name, value in payload.items():
        if value is None:
            if not isinstance(reasons.get(name), str) or not reasons[name]:
                raise IntegrityError("null_field_requires_reason:" + name)
        elif name in INTS or name.endswith("_ms"):
            nonnegative(value, name)
        elif name in BOOLS and type(value) is not bool:
            raise IntegrityError("source_schema_boolean:" + name)
        elif name.endswith("_ms_bounds"):
            if not isinstance(value, list) or len(value) != 2:
                raise IntegrityError("source_schema_bracket:" + name)
            if any(type(v) is not int for v in value) or value[0] > value[1]:
                raise IntegrityError("source_schema_bracket:" + name)
        elif name.endswith("_sha256") and (
            not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value)
        ):
            raise IntegrityError("source_schema_hash:" + name)
        elif name.endswith(("_uid", "_id", "_generation")) and (
            not isinstance(value, str) or not value
        ):
            raise IntegrityError("source_schema_identity:" + name)
    if row["source_kind"] == "client" and payload.get("retry_count") not in (None, 0):
        raise IntegrityError("registered_no_retries")
    for field in ("reports", "state", "conditions"):
        if field in payload and payload[field] is not None and not isinstance(payload[field], dict):
            raise IntegrityError("source_schema_object:" + field)
    for field in ("members", "endpoints", "active_reservations", "lows", "request_ids"):
        if field in payload and payload[field] is not None and not isinstance(payload[field], list):
            raise IntegrityError("source_schema_array:" + field)
    for member in payload.get("members") or []:
        if (
            not isinstance(member, dict)
            or not isinstance(member.get("uid"), str)
            or not member["uid"]
            or any(type(member.get(flag)) is not bool for flag in ("sampled", "healthy"))
        ):
            raise IntegrityError("source_schema_member")
    for ratio in ("cpu_fraction", "nic_fraction"):
        if payload.get(ratio) is not None and (
            type(payload[ratio]) not in (int, float) or not 0 <= payload[ratio] <= 1
        ):
            raise IntegrityError("source_schema_ratio")


class ClockMapper:
    """Use adjacent mappings' offset hull, including observed drift, never a midpoint.

    Mapping uncertainty is width of the resulting endpoint interval. Wall/mono
    disagreement over 100ms is a step; mappings across boots/gaps never join.
    """

    def __init__(self, rows: list[dict]):
        self.rows = rows
        self.errors = []
        self.maps = defaultdict(list)
        for row in rows:
            p = row.get("payload", {})
            if p.get("event") != "mapping":
                continue
            try:
                if any(not isinstance(p.get(k), str) or not p[k] for k in ("clock_id", "boot_id")):
                    raise ValueError("missing_clock_identity_or_boot")
                values = [
                    p[k]
                    for k in (
                        "remote_ms",
                        "send_ms",
                        "receive_ms",
                        "local_mono_ms",
                        "local_wall_ms",
                    )
                ]
                for value in values:
                    nonnegative(value, "clock")
                if p["send_ms"] > p["receive_ms"] or p["receive_ms"] - p["send_ms"] > 100:
                    raise ValueError("clock_uncertainty_exceeded")
                self.maps[(p["clock_id"], p["boot_id"])].append(p)
            except (ValueError, TypeError, KeyError):
                self.errors.append(
                    {"reason": "invalid_clock_mapping", "record_id": row["record_id"]}
                )
        for mappings in self.maps.values():
            mappings.sort(key=lambda p: p["remote_ms"])
        self.remote_times = {
            key: [p["remote_ms"] for p in mappings] for key, mappings in self.maps.items()
        }

    def map(self, clock_id: str, boot_id: str, lower: int, upper: int) -> list[int] | None:
        mappings = self.maps[(clock_id, boot_id)]
        times = self.remote_times.get((clock_id, boot_id), ())
        left, right = bisect_right(times, lower) - 1, bisect_left(times, upper)
        if left < 0 or right >= len(mappings):
            self.errors.append({"reason": "missing_clock_mapping", "clock_id": clock_id})
            return None
        a, b = mappings[left], mappings[right]
        span = mappings[bisect_left(times, a["remote_ms"]) : bisect_right(times, b["remote_ms"])]
        for first, last in zip(span, span[1:], strict=False):
            delta = last["local_mono_ms"] - first["local_mono_ms"]
            if (
                delta <= 0
                or delta > 2000
                or abs(last["local_wall_ms"] - first["local_wall_ms"] - delta) > 100
            ):
                self.errors.append({"reason": "clock_step_reboot_or_gap", "clock_id": clock_id})
                return None
        offsets = [(p["send_ms"] - p["remote_ms"], p["receive_ms"] - p["remote_ms"]) for p in span]
        low, high = min(v[0] for v in offsets), max(v[1] for v in offsets)
        if high - low > 100:
            self.errors.append({"reason": "clock_drift_uncertainty_exceeded", "clock_id": clock_id})
            return None
        return [lower + low, upper + high]

    def inverse(self, clock_id: str, boot_id: str, lower: int, upper: int) -> list[int] | None:
        """Map a measurement-host bracket to a remote clock without mixing epochs."""
        mappings = self.maps[(clock_id, boot_id)]
        left = [p for p in mappings if p["local_mono_ms"] <= lower]
        right = [p for p in mappings if p["local_mono_ms"] >= upper]
        if not left or not right:
            self.errors.append({"reason": "missing_inverse_clock_mapping", "clock_id": clock_id})
            return None
        a, b = left[-1], right[0]
        mapped = self.map(clock_id, boot_id, a["remote_ms"], b["remote_ms"])
        if mapped is None:
            return None
        offset_lower, offset_upper = mapped[0] - a["remote_ms"], mapped[1] - b["remote_ms"]
        return [lower - offset_upper, upper - offset_lower]

    def report(self):
        return {"mapping_count": sum(map(len, self.maps.values())), "validity_reasons": self.errors}


# Event-specific observation fields; other normalized fields can be inapplicable.
PERIODIC_FIELDS = {
    (
        "gateway",
        "install",
    ): "gateway_uid poll_seq resource_version membership_known members healthy_count",
    ("gateway", "health"): "gateway_uid poll_seq members healthy_count",
    ("kubernetes", "snapshot"): "resource_version endpoints list_valid",
    (
        "redis",
        "snapshot",
    ): "redis_time_ms reports lows state active_reservations occupied config_sha256",
    ("vllm", "sample"): FIELDS["vllm"],
    ("clocks", "mapping"): FIELDS["clocks"],
}


def carries_observation(row):
    """Failed periodic polls remain raw evidence, but cannot prove observation coverage."""
    p = row["payload"]
    key = (row["source_kind"], p["event"])
    fields = PERIODIC_FIELDS.get(key)
    if fields is None:
        return True
    return (
        row.get("error") is None
        and all(p.get(field) is not None for field in fields.split())
        and (key != ("kubernetes", "snapshot") or p.get("list_valid") is True)
        and (key != ("gateway", "install") or p.get("membership_known") is True)
    )


def source_order(row: dict) -> tuple[str, str, int]:
    """Byte order within a producer boot; clock bounds are never stream order."""
    return row["source_identity"], row["source_generation"], row["source_seq"]


class SourceJoin:
    """Deduplicate scoped IDs; preserve arrivals and source order with 2s watermark."""

    def __init__(
        self,
        rows: list[dict],
        *,
        measurement_clock: str = "measurement",
        external_sequences: dict | None = None,
        check_sequences: bool = True,
    ):
        self.rows, self.errors, self.duplicates = [], [], 0
        self.arrivals = []
        self.measurement_clock = measurement_clock
        external_sequences = external_sequences or {}
        self.clocks = ClockMapper([r for r in rows if r.get("source_kind") == "clocks"])
        seen, streams = {}, defaultdict(list)
        for arrival, original in enumerate(rows):
            # Normalization only adds top-level fields; payloads stay immutable.
            row = copy.copy(original)
            self.arrivals.append({"arrival": arrival, "record_key": list(record_key(row))})
            try:
                validate_payload(row)
            except (ValueError, TypeError, KeyError) as exc:
                self.errors.append(
                    {
                        "reason": "schema_violation",
                        "record_id": row.get("record_id"),
                        "detail": str(exc),
                    }
                )
                continue
            key = record_key(row)
            if key in seen:
                if seen[key] == row:
                    self.duplicates += 1
                else:
                    self.errors.append(
                        {"reason": "conflicting_duplicate", "record_id": row["record_id"]}
                    )
                continue
            seen[key] = original
            clock = row["source_time"]
            if clock and clock["unit"] == "ms" and clock["clock_id"] == measurement_clock:
                t = clock["value"]
                if type(t) is not int or t < 0:
                    self.errors.append(
                        {"reason": "invalid_source_clock", "record_id": row["record_id"]}
                    )
                    row["time_ms_bounds"] = None
                else:
                    u = (row["uncertainty_ns"] + 999_999) // 1_000_000
                    row["time_ms_bounds"] = [t - u, t + u] if u <= 100 else None
            elif clock and clock["unit"] == "ms":
                row["time_ms_bounds"] = self.clocks.map(
                    clock["clock_id"], row["source_generation"], clock["value"], clock["value"]
                )
            elif row["source_kind"] == "clocks":
                row["time_ms_bounds"] = [row["observed_mono_ns"] // 1_000_000] * 2
            else:
                row["time_ms_bounds"] = None
            if row["time_ms_bounds"] is None:
                self.errors.append(
                    {"reason": "missing_or_excess_clock", "record_id": row["record_id"]}
                )
            row["raw_ref"] = {
                "source_identity": row["source_identity"],
                "source_generation": row["source_generation"],
                "record_id": row["record_id"],
                "source_seq": row["source_seq"],
                "arrival": arrival,
            }
            streams[(row["source_kind"], row["source_identity"], row["source_generation"])].append(
                row
            )
        for stream in streams.values():
            high_seq, high_arrival = -1, 0
            for row in sorted(stream, key=lambda r: r["observed_mono_ns"]):
                arrival_ms = row["observed_mono_ns"] // 1_000_000
                if row["source_seq"] < high_seq and arrival_ms - high_arrival > 2000:
                    self.errors.append(
                        {"reason": "late_reorder_ambiguous", "record_id": row["record_id"]}
                    )
                if row["source_seq"] > high_seq:
                    high_seq, high_arrival = row["source_seq"], arrival_ms
            ordered = sorted(stream, key=source_order)
            stream_key = (
                ordered[0]["source_kind"],
                ordered[0]["source_identity"],
                ordered[0]["source_generation"],
            )
            external = sorted(external_sequences.get(stream_key, ()))
            for a, b in zip(ordered, ordered[1:], strict=False):
                omitted = bisect_left(external, b["source_seq"]) - bisect_left(
                    external, a["source_seq"] + 1
                )
                if check_sequences and b["source_seq"] != a["source_seq"] + 1 + omitted:
                    self.errors.append(
                        {"reason": "source_sequence_gap", "record_id": b["record_id"]}
                    )
                if (
                    a["time_ms_bounds"]
                    and b["time_ms_bounds"]
                    and b["time_ms_bounds"][1] < a["time_ms_bounds"][0]
                ):
                    self.errors.append(
                        {"reason": "source_time_reversed", "record_id": b["record_id"]}
                    )
            self.rows.extend(ordered)
        self.errors.extend(self.clocks.errors)
        self.streams = streams

    def cadence(
        self,
        kind: str,
        identity: str,
        generation: str,
        start_ms: int,
        end_ms: int,
        cadence_ms: int,
        *,
        absent_intervals: list[tuple[int, int]] = (),
        event: str | None = None,
        payload_match: dict | None = None,
    ) -> dict:
        """Lifecycle-proven downtime waives only that UID's samples, never other sources."""
        rows = [
            r
            for r in self.streams.get((kind, identity, generation), ())
            if r["time_ms_bounds"]
            and carries_observation(r)
            and (event is None or r["payload"]["event"] == event)
            and all(r["payload"].get(k) == v for k, v in (payload_match or {}).items())
        ]
        times = sorted(r["time_ms_bounds"][0] for r in rows)
        missing = []
        for scheduled in range(start_ms, end_ms + 1, cadence_ms):
            if any(a <= scheduled < b for a, b in absent_intervals):
                continue
            index = bisect_left(times, scheduled)
            # A poll at the next boundary belongs to that next slot, never both.
            if index == len(times) or times[index] >= scheduled + cadence_ms:
                missing.append(scheduled)
        # Split the observation window at proven absence, so downtime does not
        # hide a gap immediately before process end or after process start.
        active, cursor = [], start_ms
        for a, b in sorted(absent_intervals):
            a, b = max(start_ms, a), min(end_ms, b)
            if a > cursor:
                active.append((cursor, a))
            cursor = max(cursor, b)
        if cursor < end_ms:
            active.append((cursor, end_ms))
        gaps = []
        for lower, upper in active:
            points = [lower, *[t for t in times if lower <= t <= upper], upper]
            gaps.extend([a, b] for a, b in zip(points, points[1:], strict=False) if b - a > 2000)
        result = {
            "source_kind": kind,
            "identity": identity,
            "generation": generation,
            "missed_slots_ms": missing,
            "gaps_ms": gaps,
            "cadence_ms": cadence_ms,
        }
        if event is not None:
            result.update(
                event=event, payload_match=payload_match or {}, absent_intervals=absent_intervals
            )
        if gaps:
            self.errors.append({"reason": "required_source_gap", **result})
        return result

    def report(self):
        return {
            "rows": len(self.rows),
            "identical_duplicates": self.duplicates,
            "arrival_order": self.arrivals,
            "source_order": [r["raw_ref"] for r in self.rows],
            "validity_reasons": self.errors,
        }
