"""Raw gateway prefix evidence for a row 5 local refusal.

The caller must independently bind the captured bytes, boot ID, and request ID
 to the authenticated gateway and retained client response. This function does
not establish Redis stream completeness and is not a readiness decision.
"""

import re

from .inf037b_archive import IntegrityError, encode, sha, strict_json

_ROW5_GATEWAYS = {"gateway0", "gateway1"}


def _relevant_report_projection(reports):
    if not isinstance(reports, dict) or set(reports) != _ROW5_GATEWAYS:
        return None
    if any(not isinstance(report, dict) for report in reports.values()):
        return None
    return {
        gateway: (report.get("n"), report.get("unknown")) for gateway, report in reports.items()
    }


def _same_clock_brackets(before, after, *, start_ns, end_ns, collector_boot_id):
    before_start = before.get("capture_start_mono_ns") if isinstance(before, dict) else None
    before_end = before.get("capture_end_mono_ns") if isinstance(before, dict) else None
    after_start = after.get("capture_start_mono_ns") if isinstance(after, dict) else None
    after_end = after.get("capture_end_mono_ns") if isinstance(after, dict) else None
    values = (before_start, before_end, start_ns, end_ns, after_start, after_end)
    return (
        all(type(value) is int and value >= 0 for value in values)
        and before_start <= before_end <= start_ns <= end_ns <= after_start <= after_end
        and isinstance(collector_boot_id, str)
        and bool(collector_boot_id)
        and before.get("collector_boot_id") == collector_boot_id
        and after.get("collector_boot_id") == collector_boot_id
    )


def _valid_report_store(payload, *, expected_n, config_sha256):
    return (
        isinstance(payload, dict)
        and payload.get("gateway_uid") in _ROW5_GATEWAYS
        and type(payload.get("n")) is int
        and payload["n"] == expected_n
        and type(payload.get("effective_n")) is int
        and payload["effective_n"] == expected_n
        and payload.get("unknown") is False
        and payload.get("report_known") is True
        and payload.get("report_complete") is True
        and payload.get("report_success") is True
        and payload.get("config_sha256") == config_sha256
        and type(payload.get("expires_ms")) is int
        and type(payload.get("redis_time_ms")) is int
        and payload["expires_ms"] - payload["redis_time_ms"] == 8000
    )


def local_refusal_prefix(
    raw, *, expected_sha256, gateway_boot, gateway_request_id, diagnostic_receipts
):
    """Refuse unless a contiguous raw prefix proves the local gateway path."""
    if (
        type(raw) is not bytes
        or not raw
        or len(raw) > 8_388_608
        or not raw.endswith(b"\n")
        or sha(raw) != expected_sha256
        or not isinstance(gateway_boot, str)
        or not gateway_boot
        or not isinstance(gateway_request_id, str)
        or re.fullmatch(r"req_[0-9a-f]{32}", gateway_request_id) is None
    ):
        raise IntegrityError("fitness:refusal_capture_binding")
    records = [strict_json(line) for line in raw.splitlines()]
    previous_mono = -1
    gateway_reservations = set()
    for seq, record in enumerate(records):
        if (
            not isinstance(record, dict)
            or record.get("schema") != "gateway-measurement-v1"
            or type(record.get("sequence")) is not int
            or record["sequence"] != seq
            or record.get("boot_id") != gateway_boot
            or type(record.get("mono_ns")) is not int
            or record["mono_ns"] < previous_mono
            or not isinstance(record.get("event"), str)
            or not isinstance(record.get("data"), dict)
        ):
            raise IntegrityError("fitness:refusal_capture_gap")
        previous_mono = record["mono_ns"]
        reservation = record["data"].get("reservation_id")
        if reservation not in (None, ""):
            if not isinstance(reservation, str):
                raise IntegrityError("fitness:gateway_reservation_invalid")
            gateway_reservations.add(reservation)
    if records[0]["event"] != "capture_start":
        raise IntegrityError("fitness:refusal_capture_start")
    requests = [r for r in records if r["data"].get("request_id") == gateway_request_id]
    if any(r["event"] == "admit" for r in requests):
        raise IntegrityError("fitness:refusal_after_admit")
    denials = [r for r in requests if r["event"] == "deny"]
    terminals = [r for r in requests if r["event"] == "terminal"]
    if len(denials) != 1 or len(terminals) != 1:
        raise IntegrityError("fitness:refusal_absence_unproven")
    denial, terminal = denials[0], terminals[0]
    if any(
        r["event"] in ("capture_start", "capture_end")
        for r in records[1 : terminal["sequence"] + 1]
    ):
        raise IntegrityError("fitness:refusal_capture_closed")
    reservation = terminal["data"].get("reservation_id")
    if (
        denial["sequence"] >= terminal["sequence"]
        or denial["data"].get("http_status") != 503
        or denial["data"].get("denial_code") != "discovery_unknown"
        or terminal["data"].get("code") != "discovery_unknown"
        or terminal["data"].get("outcome") != "rejected"
        or not isinstance(reservation, str)
        or re.fullmatch(r"rsv_[0-9a-f]{32}", reservation) is None
    ):
        raise IntegrityError("fitness:refusal_terminal")
    from .inf037b_row5 import check_reservation_partition

    check_reservation_partition(
        gateway_reservations, diagnostic_receipts, control_ids=[reservation]
    )
    installs = [r for r in records[: denial["sequence"]] if r["event"] == "install"]
    if not installs or installs[-1]["data"].get("membership_known") is not False:
        raise IntegrityError("fitness:refusal_discovery_unknown")
    install = installs[-1]
    polls = [r for r in records[: install["sequence"]] if r["event"] == "poll_start"]
    if (
        not polls
        or type(install["data"].get("poll_seq")) is not int
        or polls[-1]["data"].get("poll_seq") != install["data"]["poll_seq"]
        or any(
            r["event"] == "poll_start"
            for r in records[install["sequence"] + 1 : terminal["sequence"] + 1]
        )
    ):
        raise IntegrityError("fitness:refusal_discovery_ambiguous")
    return {
        "gateway_request_id": gateway_request_id,
        "reservation_id": reservation,
        "deny_seq": denial["sequence"],
        "terminal_seq": terminal["sequence"],
        "capture_sha256": expected_sha256,
    }


def gateway_admit_join(gateway, operation, *, diagnostic_receipts):
    """Join an independently captured gateway admit to its Redis operation.

    The caller must validate source clocks, process identities, request/response
    binding, configuration and the snapshot interval before using this join.
    """
    from .inf037b_row5 import check_reservation_partition

    if (
        not isinstance(gateway, dict)
        or gateway.get("source_kind") != "gateway"
        or gateway.get("source_identity") not in ("gateway0", "gateway1")
        or gateway.get("error") is not None
        or gateway.get("payload", {}).get("event") != "admit"
        or gateway["payload"].get("gateway_uid") != gateway["source_identity"]
    ):
        raise IntegrityError("fitness:control_gateway_ack")
    gp = gateway["payload"]
    reservation = gp.get("reservation_id")
    check_reservation_partition([reservation], diagnostic_receipts, control_ids=[reservation])
    if (
        not isinstance(gp.get("request_id"), str)
        or not gp["request_id"]
        or gp.get("decision")
        not in (
            "allowed",
            "system_capacity",
            "tenant_rate_limit",
            "tenant_concurrency_limit",
            "capacity_reports_expired",
        )
        or type(gp.get("effective_b")) is not int
        or gp["effective_b"] < 0
        or not isinstance(operation, dict)
        or operation.get("source_kind") != "redis"
        or operation.get("source_identity") != "redis"
        or operation.get("error") is not None
        or operation.get("payload", {}).get("event") != "admit"
        or operation["payload"].get("reservation_id") != reservation
        or operation["payload"].get("decision") != gp.get("decision")
        or operation["payload"].get("effective_b") != gp.get("effective_b")
        or operation["payload"].get("idempotent") is not False
        or gp.get("admit_called") is not True
    ):
        raise IntegrityError("fitness:control_admit_join")
    return reservation


def redis_refusal_interval(
    before,
    after,
    operations,
    reservation_id,
    *,
    request_start_ns,
    request_end_ns,
    collector_boot_id,
    diagnostic_receipts,
):
    """Check a contiguous Redis capture interval for a gateway reservation.

    The caller must bind both atomic snapshots and the request brackets to
    their live sources and confirm capture-mode configuration independently.
    This validates an interval; it does not supply that external provenance.
    """
    from .inf037b_row5 import check_reservation_partition

    check_reservation_partition([reservation_id], diagnostic_receipts, control_ids=[reservation_id])
    if (
        not isinstance(before, dict)
        or not isinstance(after, dict)
        or before.get("source_kind") != "redis"
        or after.get("source_kind") != "redis"
        or before.get("source_identity") != "redis"
        or after.get("source_identity") != "redis"
        or before.get("error") is not None
        or after.get("error") is not None
        or not isinstance(operations, list)
    ):
        raise IntegrityError("fitness:refusal_redis_interval")
    first, last = before.get("payload", {}), after.get("payload", {})
    lo, hi = first.get("store_order"), last.get("store_order")
    start, end = first.get("redis_time_ms"), last.get("redis_time_ms")
    if (
        first.get("event") != "snapshot"
        or last.get("event") != "snapshot"
        or type(lo) is not int
        or type(hi) is not int
        or lo < 0
        or hi < lo
        or type(start) is not int
        or type(end) is not int
        or not (0 <= start <= end)
        or not _same_clock_brackets(
            before,
            after,
            start_ns=request_start_ns,
            end_ns=request_end_ns,
            collector_boot_id=collector_boot_id,
        )
        or not isinstance(first.get("config_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", first["config_sha256"]) is None
        or first.get("config_sha256") != last.get("config_sha256")
    ):
        raise IntegrityError("fitness:refusal_redis_interval")
    if len(operations) != hi - lo:
        raise IntegrityError("fitness:refusal_redis_gap")
    previous_time = start
    for expected_order, operation in enumerate(operations, start=lo + 1):
        if (
            not isinstance(operation, dict)
            or operation.get("source_kind") != "redis"
            or operation.get("source_identity") != "redis"
            or operation.get("error") is not None
            or not isinstance(operation.get("payload"), dict)
        ):
            raise IntegrityError("fitness:refusal_redis_gap")
        payload = operation["payload"]
        at = payload.get("redis_time_ms")
        if (
            payload.get("event") not in ("report_store", "unknown", "admit", "release")
            or (
                payload.get("event") in ("admit", "release")
                and (
                    not isinstance(payload.get("reservation_id"), str)
                    or re.fullmatch(r"rsv_[0-9a-f]{32}", payload["reservation_id"]) is None
                )
            )
            or type(payload.get("store_order")) is not int
            or payload["store_order"] != expected_order
            or payload.get("config_sha256") != first["config_sha256"]
            or type(at) is not int
            or not previous_time <= at <= end
        ):
            raise IntegrityError("fitness:refusal_redis_gap")
        if payload.get("event") == "admit" and payload.get("reservation_id") == reservation_id:
            raise IntegrityError("fitness:refusal_after_admit")
        previous_time = at
    return {"reservation_id": reservation_id, "first_order": lo, "last_order": hi}


def refusal_control(
    raw_gateway_prefix,
    *,
    expected_sha256,
    gateway_boot,
    gateway_request_id,
    client_status,
    client_code,
    redis_before,
    redis_after,
    redis_operations,
    request_start_ns,
    request_end_ns,
    collector_boot_id,
    diagnostic_receipts,
):
    """Join both sides of one refusal after the caller binds live sources.

    The caller must bind the client response to gateway_request_id, the prefix
    bytes/boot to that gateway, both Redis snapshots to capture-mode Redis, and
    the request and snapshots to one collector monotonic clock.
    """
    if type(client_status) is not int or client_status != 503 or client_code != "discovery_unknown":
        raise IntegrityError("fitness:refusal_client_response")
    gateway = local_refusal_prefix(
        raw_gateway_prefix,
        expected_sha256=expected_sha256,
        gateway_boot=gateway_boot,
        gateway_request_id=gateway_request_id,
        diagnostic_receipts=diagnostic_receipts,
    )
    redis_interval = redis_refusal_interval(
        redis_before,
        redis_after,
        redis_operations,
        gateway["reservation_id"],
        request_start_ns=request_start_ns,
        request_end_ns=request_end_ns,
        collector_boot_id=collector_boot_id,
        diagnostic_receipts=diagnostic_receipts,
    )
    return {"gateway": gateway, "redis": redis_interval}


def gateway_prefix_from_wire(entries, *, source, operation_sha256, gateway_boot):
    """Reconstruct gateway capture bytes from verified CaptureOwner wire records.

    The caller must independently bind the source and operation to the live
    gateway and verify the secured archive inventory. Entries are (index, body)
    pairs, as returned by wire_records. Offsets, hashes, HTTP status, response
    headers and contiguous gateway read offsets are checked again here.
    """
    import urllib.parse

    if (
        not isinstance(source, str)
        or not source
        or not isinstance(gateway_boot, str)
        or not gateway_boot
        or not isinstance(operation_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", operation_sha256) is None
    ):
        raise IntegrityError("fitness:gateway_wire_binding")
    prefix = bytearray()
    pending = None
    selected = 0
    wire_offset = 0
    last_sequence = -1

    def finish():
        nonlocal pending
        if pending is None:
            return
        if len(pending["body"]) != pending["next"] - pending["offset"]:
            raise IntegrityError("fitness:gateway_wire_incomplete")
        prefix.extend(pending["body"])
        if len(prefix) > 8_388_608:
            raise IntegrityError("fitness:gateway_wire_incomplete")
        pending = None

    for record, body in entries:
        if not isinstance(record, dict) or record.get("source") != source:
            continue
        selected += 1
        meta = record.get("metadata")
        seq = record.get("sequence")
        if (
            record.get("operation_sha256") != operation_sha256
            or not isinstance(meta, dict)
            or meta.get("error")
            or type(seq) is not int
            or seq <= last_sequence
            or type(record.get("offset")) is not int
            or record["offset"] != wire_offset
            or type(body) is not bytes
            or type(record.get("length")) is not int
            or record["length"] != len(body)
            or record.get("sha256") != sha(body)
        ):
            raise IntegrityError("fitness:gateway_wire_integrity")
        last_sequence, wire_offset = seq, wire_offset + len(body)
        path = meta.get("path")
        if "status" in meta:
            finish()
            if not isinstance(path, str):
                raise IntegrityError("fitness:gateway_wire_response")
            parsed = urllib.parse.urlsplit(path)
            if parsed.path != "/internal/measurement":
                continue
            query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            if query == {"clock": ["1"]}:
                if (
                    parsed.scheme
                    or parsed.netloc
                    or parsed.fragment
                    or type(meta["status"]) is not int
                    or meta["status"] != 200
                    or body
                ):
                    raise IntegrityError("fitness:gateway_wire_response")
                continue
            if (
                parsed.scheme
                or parsed.netloc
                or parsed.fragment
                or set(query) != {"offset"}
                or len(query["offset"]) != 1
                or re.fullmatch(r"0|[1-9][0-9]*", query["offset"][0]) is None
                or type(meta["status"]) is not int
                or meta["status"] != 200
                or not isinstance(meta.get("headers"), list)
                or body
            ):
                raise IntegrityError("fitness:gateway_wire_response")
            headers = {}
            for entry in meta["headers"]:
                if (
                    not isinstance(entry, (list, tuple))
                    or len(entry) != 2
                    or not all(isinstance(v, str) for v in entry)
                ):
                    raise IntegrityError("fitness:gateway_wire_response")
                name = entry[0].lower()
                if name in ("x-capture-boot", "x-capture-next"):
                    if name in headers:
                        raise IntegrityError("fitness:gateway_wire_response")
                    headers[name] = entry[1]
            offset = int(query["offset"][0])
            next_value = headers.get("x-capture-next", "")
            if (
                headers.get("x-capture-boot") != gateway_boot
                or re.fullmatch(r"0|[1-9][0-9]*", next_value) is None
                or offset != len(prefix)
                or int(next_value) < offset
            ):
                raise IntegrityError("fitness:gateway_wire_response")
            pending = {"path": path, "offset": offset, "next": int(next_value), "body": bytearray()}
        elif pending is not None and path == pending["path"]:
            pending["body"].extend(body)
            if len(pending["body"]) > pending["next"] - pending["offset"]:
                raise IntegrityError("fitness:gateway_wire_incomplete")
        elif path is not None or body:
            finish()
    finish()
    if not selected or not prefix:
        raise IntegrityError("fitness:gateway_wire_incomplete")
    return bytes(prefix)


ROW5_SNAPSHOT_IDS = (
    "known0",
    "known1",
    "known2",
    "cached_stop_known1",
    "cached_restore_known2",
    "unknown",
    "expired",
    "post_outage_known2",
    "post_outage_agreement",
    "hold_start",
    "hold_end",
)


def select_row5_snapshots(rows):
    """Resolve the designated instances without treating repeated counts as one.

    Source/configuration, state semantics, clocks and action joins remain the
    caller's responsibility; this selection alone never certifies a control.
    """
    if not isinstance(rows, list):
        raise IntegrityError("fitness:row5_snapshot_inventory")
    selected = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("payload"), dict):
            raise IntegrityError("fitness:row5_snapshot_inventory")
        p = row["payload"]
        if row.get("source_kind") != "redis" or p.get("event") != "snapshot":
            continue
        name = p.get("snapshot_id")
        if name not in ROW5_SNAPSHOT_IDS:
            continue
        if (
            name in selected
            or row.get("source_identity") != "redis"
            or row.get("error") is not None
            or type(p.get("redis_time_ms")) is not int
            or p["redis_time_ms"] < 0
            or type(p.get("store_order")) is not int
            or p["store_order"] < 0
        ):
            raise IntegrityError("fitness:row5_snapshot_duplicate_or_invalid")
        selected[name] = row
    if set(selected) != set(ROW5_SNAPSHOT_IDS):
        raise IntegrityError("fitness:row5_snapshot_inventory")
    return selected


def gateway_prefix_from_capture(
    root,
    descriptor,
    *,
    expected_binding,
    expected_operation,
    expected_descriptor_sha256,
    source,
    gateway_uid,
    gateway_boot,
):
    """Read a gateway prefix from a closed, inventory-verified CaptureOwner.

    The expected binding, operation and descriptor hash must come from the
    durable operation store and reviewed source inventory, not from the
    descriptor itself.
    """
    from pathlib import Path

    from .inf037b_capture import wire_records
    from .inf037b_probe import capture_rows

    if (
        not isinstance(descriptor, dict)
        or not isinstance(expected_binding, dict)
        or not expected_binding
        or not isinstance(expected_operation, dict)
        or not expected_operation
        or not isinstance(expected_descriptor_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", expected_descriptor_sha256) is None
        or sha(encode(descriptor)) != expected_descriptor_sha256
        or not isinstance(descriptor.get("sources"), dict)
        or descriptor.get("closed") is not True
        or descriptor.get("transport_clean") is not True
        or descriptor.get("binding") != expected_binding
        or descriptor.get("operation") != expected_operation
        or descriptor.get("attempt") != "setup"
        or gateway_uid not in ("gateway0", "gateway1")
        or not isinstance(source, str)
        or not source
        or not isinstance(gateway_boot, str)
        or not gateway_boot
        or descriptor["sources"].get(source) != [["gateway", gateway_uid, gateway_boot]]
        or not isinstance(expected_operation.get("body"), dict)
        or expected_operation["body"].get("binding") != expected_binding
        or not isinstance(expected_operation["body"].get("capture"), dict)
        or expected_operation["body"]["capture"].get("sources") != descriptor["sources"]
        or expected_operation["body"]["capture"].get("attempt") != "setup"
        or expected_operation["body"]["capture"].get("boot_id") != descriptor.get("boot_id")
    ):
        raise IntegrityError("fitness:gateway_capture_descriptor")
    # Exhaust the iterator: it verifies the sealed archive and the complete
    # inventory before yielding any normalized row, including every wire file.
    for _ in capture_rows(Path(root), descriptor):
        pass
    return gateway_prefix_from_wire(
        wire_records(Path(root) / "wire"),
        source=source,
        operation_sha256=sha(encode(expected_operation)),
        gateway_boot=gateway_boot,
    )


def gateway_resolved_config_from_capture(
    root,
    descriptor,
    *,
    expected_binding,
    expected_operation,
    expected_descriptor_sha256,
    source,
    gateway_uid,
    gateway_boot,
):
    """Read the gateway's actual startup config from its bound raw prefix."""
    raw = gateway_prefix_from_capture(
        root,
        descriptor,
        expected_binding=expected_binding,
        expected_operation=expected_operation,
        expected_descriptor_sha256=expected_descriptor_sha256,
        source=source,
        gateway_uid=gateway_uid,
        gateway_boot=gateway_boot,
    )
    if not raw.endswith(b"\n"):
        raise IntegrityError("fitness:gateway_config_capture")
    records = [strict_json(line) for line in raw.splitlines()]
    if len(records) < 2:
        raise IntegrityError("fitness:gateway_config_capture")
    for seq, record in enumerate(records):
        if (
            not isinstance(record, dict)
            or record.get("schema") != "gateway-measurement-v1"
            or type(record.get("sequence")) is not int
            or record["sequence"] != seq
            or record.get("boot_id") != gateway_boot
            or not isinstance(record.get("data"), dict)
        ):
            raise IntegrityError("fitness:gateway_config_capture")
    configs = [r for r in records if r.get("event") == "admission_config"]
    if (
        records[0].get("event") != "capture_start"
        or len(configs) != 1
        or configs[0]["sequence"] != 1
    ):
        raise IntegrityError("fitness:gateway_config_capture")
    data = configs[0]["data"]
    config_keys = {
        "redis_addr",
        "namespace",
        "global_capacity",
        "lease_ms",
        "tombstone_ms",
        "running",
        "waiting",
        "ttl_ms",
        "hold_ms",
        "capture",
    }
    if (
        set(data) != config_keys | {"gateway_id", "lease_ns", "tombstone_ns", "ttl_ns", "hold_ns"}
        or data["gateway_id"] != {"gateway0": "gateway-0", "gateway1": "gateway-1"}[gateway_uid]
        or any(
            type(data[k]) is not int
            for k in (
                "lease_ms",
                "tombstone_ms",
                "ttl_ms",
                "hold_ms",
                "lease_ns",
                "tombstone_ns",
                "ttl_ns",
                "hold_ns",
            )
        )
        or any(
            data[k + "_ns"] != data[k + "_ms"] * 1_000_000
            for k in ("lease", "tombstone", "ttl", "hold")
        )
    ):
        raise IntegrityError("fitness:gateway_config_capture")
    return {key: data[key] for key in config_keys}


def client_refusal_from_capture(
    root,
    descriptor,
    *,
    expected_binding,
    expected_operation,
    expected_descriptor_sha256,
    source,
    client_identity,
    client_boot,
    gateway_request_id,
    request_start_ns,
):
    """Bind one client's retained HTTP 503 to the gateway-owned request ID.

    The caller supplies trusted durable operation and descriptor pins and must
    join the returned interval to its scheduled control and clock mappings.
    """
    from pathlib import Path

    from .inf037b_capture import wire_records
    from .inf037b_probe import capture_rows

    if (
        not isinstance(descriptor, dict)
        or not isinstance(expected_binding, dict)
        or not expected_binding
        or not isinstance(expected_operation, dict)
        or not expected_operation
        or not isinstance(expected_descriptor_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", expected_descriptor_sha256) is None
        or sha(encode(descriptor)) != expected_descriptor_sha256
        or not isinstance(descriptor.get("sources"), dict)
        or descriptor.get("closed") is not True
        or descriptor.get("transport_clean") is not True
        or descriptor.get("binding") != expected_binding
        or descriptor.get("operation") != expected_operation
        or descriptor.get("attempt") != "setup"
        or not isinstance(source, str)
        or not source
        or client_identity not in ("client:gateway0", "client:gateway1")
        or not isinstance(client_boot, str)
        or not client_boot
        or descriptor["sources"].get(source) != [["client", client_identity, client_boot]]
        or not isinstance(expected_operation.get("body"), dict)
        or expected_operation["body"].get("binding") != expected_binding
        or not isinstance(expected_operation["body"].get("capture"), dict)
        or expected_operation["body"]["capture"].get("sources") != descriptor["sources"]
        or expected_operation["body"]["capture"].get("attempt") != "setup"
        or expected_operation["body"]["capture"].get("boot_id") != descriptor.get("boot_id")
        or not isinstance(gateway_request_id, str)
        or re.fullmatch(r"req_[0-9a-f]{32}", gateway_request_id) is None
        or type(request_start_ns) is not int
        or request_start_ns < 0
    ):
        raise IntegrityError("fitness:client_refusal_capture")
    for _ in capture_rows(Path(root), descriptor):
        pass
    records = []
    last_sequence, offset = -1, 0
    for record, body in wire_records(Path(root) / "wire"):
        if record.get("source") != source:
            continue
        if (
            record.get("operation_sha256") != sha(encode(expected_operation))
            or type(record.get("sequence")) is not int
            or record["sequence"] <= last_sequence
            or record.get("offset") != offset
            or record.get("length") != len(body)
            or record.get("sha256") != sha(body)
            or not isinstance(record.get("metadata"), dict)
            or type(record.get("start_ns")) is not int
            or type(record.get("end_ns")) is not int
            or not 0 <= record["start_ns"] <= record["end_ns"]
        ):
            raise IntegrityError("fitness:client_refusal_capture")
        last_sequence, offset = record["sequence"], offset + len(body)
        if record["start_ns"] == request_start_ns:
            records.append((record, body))
    responses = [(r, b) for r, b in records if "headers" in r["metadata"]]
    bodies = [(r, b) for r, b in records if r["metadata"].get("status") == 503 and b]
    terminals = [(r, b) for r, b in records if r["metadata"].get("client_request_end") is True]
    if (
        len(responses) != 1
        or len(bodies) != 1
        or len(terminals) != 1
        or responses[0][0]["metadata"].get("status") != 503
        or responses[0][1]
        or terminals[0][1]
        or len(bodies[0][1]) > 8192
        or not (
            responses[0][0]["sequence"] < bodies[0][0]["sequence"] < terminals[0][0]["sequence"]
        )
        or not (responses[0][0]["end_ns"] <= bodies[0][0]["end_ns"] <= terminals[0][0]["end_ns"])
        or any(r["metadata"].get("error") for r, _ in records)
    ):
        raise IntegrityError("fitness:client_refusal_response")
    headers = responses[0][0]["metadata"]["headers"]
    if not isinstance(headers, list) or any(
        not isinstance(h, (list, tuple)) or len(h) != 2 or not all(isinstance(v, str) for v in h)
        for h in headers
    ):
        raise IntegrityError("fitness:client_refusal_response")
    ids = [value for name, value in headers if name.lower() == "x-request-id"]
    payload = strict_json(bodies[0][1])
    if (
        ids != [gateway_request_id]
        or not isinstance(payload, dict)
        or not isinstance(payload.get("error"), dict)
        or payload["error"].get("code") != "discovery_unknown"
    ):
        raise IntegrityError("fitness:client_refusal_response")
    return {
        "gateway_request_id": gateway_request_id,
        "client_status": 503,
        "client_code": "discovery_unknown",
        "start_ns": request_start_ns,
        "end_ns": terminals[0][0]["end_ns"],
        "body_sha256": sha(bodies[0][1]),
    }


def captured_refusal_control(
    *,
    gateway_capture,
    client_capture,
    gateway_request_id,
    request_start_ns,
    request_end_ns,
    collector_boot_id,
    clocks,
    redis_boot,
    redis_before,
    redis_after,
    redis_operations,
    diagnostic_receipts,
):
    """Join independently bound HTTP, gateway prefix and continuous Redis evidence.

    The caller must use a source-validated ClockMapper and bind Redis rows and
    operation/descriptor pins to the durable collection. No absence is inferred
    from a missing normalized gateway admit or an incomplete Redis interval.
    """
    from .inf037b_sources import ClockMapper

    if (
        not isinstance(gateway_capture, dict)
        or not isinstance(client_capture, dict)
        or gateway_capture.get("expected_binding") != client_capture.get("expected_binding")
        or gateway_capture.get("expected_operation") != client_capture.get("expected_operation")
        or gateway_capture.get("gateway_uid") not in ("gateway0", "gateway1")
        or client_capture.get("client_identity") != "client:" + gateway_capture["gateway_uid"]
        or not isinstance(redis_boot, str)
        or not redis_boot
        or not isinstance(clocks, ClockMapper)
        or not isinstance(redis_before, dict)
        or not isinstance(redis_after, dict)
        or redis_before.get("source_generation") != redis_boot
        or redis_after.get("source_generation") != redis_boot
        or not isinstance(redis_operations, list)
        or any(
            not isinstance(row, dict) or row.get("source_generation") != redis_boot
            for row in redis_operations
        )
    ):
        raise IntegrityError("fitness:refusal_capture_binding")
    prefix = gateway_prefix_from_capture(**gateway_capture)
    client = client_refusal_from_capture(
        **client_capture, gateway_request_id=gateway_request_id, request_start_ns=request_start_ns
    )
    if client.get("end_ns") != request_end_ns:
        raise IntegrityError("fitness:row5_client_capture")
    if clocks.errors:
        raise IntegrityError("fitness:refusal_clock")
    bounds = clocks.inverse(
        "redis",
        redis_boot,
        client["start_ns"] // 1_000_000,
        (client["end_ns"] + 999_999) // 1_000_000,
    )
    if bounds is None or clocks.errors:
        raise IntegrityError("fitness:refusal_clock")
    result = refusal_control(
        prefix,
        expected_sha256=sha(prefix),
        gateway_boot=gateway_capture["gateway_boot"],
        gateway_request_id=gateway_request_id,
        client_status=client["client_status"],
        client_code=client["client_code"],
        redis_before=redis_before,
        redis_after=redis_after,
        redis_operations=redis_operations,
        request_start_ns=client["start_ns"],
        request_end_ns=client["end_ns"],
        collector_boot_id=collector_boot_id,
        diagnostic_receipts=diagnostic_receipts,
    )
    return {**result, "client": client, "redis_time_bounds": bounds}


def known_gateway_control(
    *,
    snapshot,
    after,
    gateway,
    redis_operations,
    raw_gateway_prefix,
    gateway_boot,
    gateway_request_id,
    request_start_ns,
    request_end_ns,
    collector_boot_id,
    diagnostic_receipts,
    expected_n,
    expected_snapshot_id,
    gateway_redis_bounds,
    gateway_reservations,
):
    """Check one known gateway admit against its own Redis operation and release.

    Source binding of all rows, raw prefix, client request/response and clock
    brackets is the caller's responsibility. The complete interval may contain
    owned same-n report refreshes and gateway/diagnostic operations;
    it cannot treat a different snapshot's count as the tested instance.
    """
    if expected_n not in (0, 1, 2) or type(expected_n) is not int:
        raise IntegrityError("fitness:known_control_n")
    instances = {
        "known0": 0,
        "known1": 1,
        "known2": 2,
        "cached_stop_known1": 1,
        "cached_restore_known2": 2,
        "post_outage_known2": 2,
    }
    if (
        not isinstance(expected_snapshot_id, str)
        or instances.get(expected_snapshot_id) != expected_n
    ):
        raise IntegrityError("fitness:known_control_snapshot")
    if (
        not isinstance(snapshot, dict)
        or not isinstance(after, dict)
        or snapshot.get("source_kind") != "redis"
        or after.get("source_kind") != "redis"
        or snapshot.get("source_identity") != "redis"
        or after.get("source_identity") != "redis"
        or snapshot.get("error") is not None
        or after.get("error") is not None
        or not isinstance(snapshot.get("payload"), dict)
        or not isinstance(after.get("payload"), dict)
        or not isinstance(redis_operations, list)
        or not isinstance(gateway_redis_bounds, list)
        or len(gateway_redis_bounds) != 2
        or any(type(v) is not int for v in gateway_redis_bounds)
    ):
        raise IntegrityError("fitness:known_control_interval")
    first, last = snapshot["payload"], after["payload"]
    lo, hi, start, end = (
        first.get("store_order"),
        last.get("store_order"),
        first.get("redis_time_ms"),
        last.get("redis_time_ms"),
    )
    if (
        first.get("event") != "snapshot"
        or last.get("event") != "snapshot"
        or first.get("snapshot_id") != expected_snapshot_id
        or any(type(v) is not int for v in (lo, hi, start, end))
        or not (0 <= lo <= hi and 0 <= start <= end)
        or not _same_clock_brackets(
            snapshot,
            after,
            start_ns=request_start_ns,
            end_ns=request_end_ns,
            collector_boot_id=collector_boot_id,
        )
        or len(redis_operations) != hi - lo
        or first.get("config_sha256") != last.get("config_sha256")
        or not isinstance(first.get("config_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", first["config_sha256"]) is None
        or _relevant_report_projection(first.get("reports"))
        != _relevant_report_projection(last.get("reports"))
        or first.get("state") != last.get("state")
        or first.get("active_reservations") != []
        or last.get("active_reservations") != []
        or type(first.get("occupied")) is not int
        or first["occupied"] != 0
        or type(last.get("occupied")) is not int
        or last["occupied"] != 0
    ):
        raise IntegrityError("fitness:known_control_interval")
    reports, state = first.get("reports"), first.get("state")
    if (
        not isinstance(reports, dict)
        or set(reports) != {"gateway0", "gateway1"}
        or not isinstance(state, dict)
        or type(state.get("n")) is not int
        or state["n"] != expected_n
        or any(
            not isinstance(r, dict)
            or type(r.get("n")) is not int
            or r["n"] != expected_n
            or r.get("unknown") is not False
            or type(r.get("stored_ms")) is not int
            or r["stored_ms"] < 0
            or r["stored_ms"] > start
            or type(r.get("expires_ms")) is not int
            or r["expires_ms"] - r["stored_ms"] != 8000
            or r["expires_ms"] <= end
            for r in reports.values()
        )
    ):
        raise IntegrityError("fitness:known_control_reports")
    after_reports = last.get("reports")
    if any(
        not isinstance(report, dict)
        or type(report.get("n")) is not int
        or report["n"] != expected_n
        or report.get("unknown") is not False
        or type(report.get("stored_ms")) is not int
        or report["stored_ms"] < reports[gateway]["stored_ms"]
        or report["stored_ms"] > end
        or type(report.get("expires_ms")) is not int
        or report["expires_ms"] - report["stored_ms"] != 8000
        or report["expires_ms"] <= end
        for gateway, report in after_reports.items()
    ):
        raise IntegrityError("fitness:known_control_reports")
    previous = start
    for order, operation in enumerate(redis_operations, lo + 1):
        if (
            not isinstance(operation, dict)
            or operation.get("source_kind") != "redis"
            or operation.get("source_identity") != "redis"
            or operation.get("error") is not None
            or not isinstance(operation.get("payload"), dict)
        ):
            raise IntegrityError("fitness:known_control_gap")
        p = operation["payload"]
        event = p.get("event")
        if (
            type(p.get("store_order")) is not int
            or p["store_order"] != order
            or type(p.get("redis_time_ms")) is not int
            or not previous <= p["redis_time_ms"] <= end
            or p.get("config_sha256") != first["config_sha256"]
            or (
                event not in ("admit", "release")
                and not (
                    event == "report_store"
                    and _valid_report_store(
                        p, expected_n=expected_n, config_sha256=first["config_sha256"]
                    )
                )
            )
        ):
            raise IntegrityError("fitness:known_control_gap")
        previous = p["redis_time_ms"]
    if (
        not isinstance(gateway, dict)
        or not isinstance(gateway.get("payload"), dict)
        or gateway.get("source_generation") != gateway_boot
    ):
        raise IntegrityError("fitness:control_gateway_ack")
    reservation = gateway["payload"].get("reservation_id")
    if not isinstance(gateway_reservations, (list, tuple, set)):
        raise IntegrityError("fitness:gateway_reservation_invalid")
    from .inf037b_row5 import check_reservation_partition

    check_reservation_partition(gateway_reservations, diagnostic_receipts)
    known_gateway_ids = set(gateway_reservations)
    diagnostic_ids = {receipt["reservation_id"] for receipt in diagnostic_receipts}
    if reservation not in known_gateway_ids:
        raise IntegrityError("fitness:unexplained_reservations")
    if any(
        operation["payload"].get("event") in ("admit", "release")
        and operation["payload"].get("reservation_id") not in known_gateway_ids | diagnostic_ids
        for operation in redis_operations
    ):
        raise IntegrityError("fitness:unexplained_reservations")
    matches = [
        o
        for o in redis_operations
        if o["payload"].get("event") == "admit"
        and o["payload"].get("reservation_id") == reservation
    ]
    if len(matches) != 1:
        raise IntegrityError("fitness:control_admit_join")
    gateway_admit_join(gateway, matches[0], diagnostic_receipts=diagnostic_receipts)
    admit = matches[0]["payload"]
    expected_decision = "system_capacity" if expected_n == 0 else "allowed"
    if (
        admit.get("decision") != expected_decision
        or type(admit.get("effective_n")) is not int
        or admit["effective_n"] != expected_n
        or admit.get("effective_b") != expected_n * 5
        or not gateway_redis_bounds[0] <= admit["redis_time_ms"] <= gateway_redis_bounds[1]
    ):
        raise IntegrityError("fitness:known_control_decision")
    if (
        type(raw_gateway_prefix) is not bytes
        or not raw_gateway_prefix.endswith(b"\n")
        or not isinstance(gateway_boot, str)
        or not gateway_boot
        or not isinstance(gateway_request_id, str)
        or re.fullmatch(r"req_[0-9a-f]{32}", gateway_request_id) is None
    ):
        raise IntegrityError("fitness:known_terminal")
    records = [strict_json(line) for line in raw_gateway_prefix.splitlines()]
    if (
        not records
        or not isinstance(records[0], dict)
        or records[0].get("event") != "capture_start"
        or any(
            not isinstance(r, dict)
            or type(r.get("sequence")) is not int
            or r["sequence"] != i
            or r.get("schema") != "gateway-measurement-v1"
            or r.get("boot_id") != gateway_boot
            or not isinstance(r.get("data"), dict)
            for i, r in enumerate(records)
        )
    ):
        raise IntegrityError("fitness:known_terminal")
    previous_mono = -1
    for record in records:
        at = record.get("mono_ns")
        if type(at) is not int or at < previous_mono:
            raise IntegrityError("fitness:known_terminal")
        previous_mono = at
    relevant = [r for r in records if r["data"].get("request_id") == gateway_request_id]
    admits = [r for r in relevant if r.get("event") == "admit"]
    terminals = [r for r in relevant if r.get("event") == "terminal"]
    releases = [r for r in relevant if r.get("event") == "release"]
    redis_releases = [
        o
        for o in redis_operations
        if o["payload"].get("event") == "release"
        and o["payload"].get("reservation_id") == reservation
    ]
    if (
        len(admits) != 1
        or len(terminals) != 1
        or admits[0]["data"].get("reservation_id") != reservation
        or terminals[0]["data"].get("reservation_id") != reservation
        or admits[0]["sequence"] >= terminals[0]["sequence"]
        or any(
            r.get("event") in ("capture_start", "capture_end")
            for r in records[1 : terminals[0]["sequence"] + 1]
        )
        or admits[0]["data"].get("decision") != expected_decision
        or admits[0]["data"].get("effective_b") != expected_n * 5
        or (
            expected_n == 0
            and (
                releases or redis_releases or terminals[0]["data"].get("code") != "system_capacity"
            )
        )
        or (
            expected_n != 0
            and (
                len(releases) != 1
                or len(redis_releases) != 1
                or releases[0]["data"].get("reservation_id") != reservation
                or releases[0]["data"].get("result") != "released"
                or not admits[0]["sequence"] < releases[0]["sequence"] < terminals[0]["sequence"]
                or redis_releases[0]["payload"].get("decision") != "released"
                or redis_releases[0]["payload"].get("idempotent") is not False
                or redis_releases[0]["payload"].get("occupied") != 0
                or redis_releases[0]["payload"].get("store_order") <= admit["store_order"]
            )
        )
    ):
        raise IntegrityError("fitness:known_terminal")
    return {
        "reservation_id": reservation,
        "decision": expected_decision,
        "effective_n": expected_n,
        "effective_b": expected_n * 5,
    }


def diagnostic_snapshot_control(
    *,
    snapshot,
    after,
    redis_operations,
    receipt,
    gateway_ids,
    diagnostic_redis_bounds,
    process_start_ns,
    process_end_ns,
    collector_boot_id,
    control_name,
):
    """Join one diagnostic process receipt to its Redis interval and state.

    Receipt, snapshots and clock mapping must already be source-bound. The
    interval may contain same-n report refreshes, outage unknown markers, and
    gateway operations, each checked by its own evidence. This result is never
    a gateway acknowledgement.
    """
    from .inf037b_row5 import check_reservation_partition

    expected = {
        "known0": (0, "system_capacity", 0),
        "known1": (1, "allowed", 5),
        "known2": (2, "allowed", 10),
        "unknown": (2, "allowed", 10),
        "expired": (2, "capacity_reports_expired", 10),
        "cached_stop_known1": (1, "allowed", 5),
        "cached_restore_known2": (2, "allowed", 10),
        "post_outage_known2": (2, "allowed", 10),
    }
    if not isinstance(control_name, str) or control_name not in expected:
        raise IntegrityError("fitness:diagnostic_control_name")
    check_reservation_partition(gateway_ids, [receipt])
    if (
        not isinstance(snapshot, dict)
        or not isinstance(after, dict)
        or snapshot.get("source_kind") != "redis"
        or after.get("source_kind") != "redis"
        or snapshot.get("source_identity") != "redis"
        or after.get("source_identity") != "redis"
        or snapshot.get("error") is not None
        or after.get("error") is not None
        or not isinstance(snapshot.get("payload"), dict)
        or not isinstance(after.get("payload"), dict)
        or not isinstance(redis_operations, list)
        or not isinstance(diagnostic_redis_bounds, list)
        or len(diagnostic_redis_bounds) != 2
        or any(type(v) is not int for v in diagnostic_redis_bounds)
    ):
        raise IntegrityError("fitness:diagnostic_interval")
    a, b = snapshot["payload"], after["payload"]
    lo, hi, start, end = (
        a.get("store_order"),
        b.get("store_order"),
        a.get("redis_time_ms"),
        b.get("redis_time_ms"),
    )
    if (
        a.get("event") != "snapshot"
        or b.get("event") != "snapshot"
        or a.get("snapshot_id") != control_name
        or any(type(v) is not int for v in (lo, hi, start, end))
        or not (0 <= lo <= hi and 0 <= start <= end)
        or not _same_clock_brackets(
            snapshot,
            after,
            start_ns=process_start_ns,
            end_ns=process_end_ns,
            collector_boot_id=collector_boot_id,
        )
        or len(redis_operations) != hi - lo
        or not isinstance(a.get("config_sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", a["config_sha256"]) is None
        or a.get("config_sha256") != b.get("config_sha256")
        or (
            a.get("reports") != b.get("reports")
            if control_name in ("unknown", "expired")
            else _relevant_report_projection(a.get("reports"))
            != _relevant_report_projection(b.get("reports"))
        )
        or a.get("state") != b.get("state")
        or a.get("active_reservations") != []
        or b.get("active_reservations") != []
        or type(a.get("occupied")) is not int
        or a["occupied"] != 0
        or type(b.get("occupied")) is not int
        or b["occupied"] != 0
    ):
        raise IntegrityError("fitness:diagnostic_interval")
    n, decision, capacity = expected[control_name]
    reports = a.get("reports")
    if (
        not isinstance(reports, dict)
        or set(reports) != {"gateway0", "gateway1"}
        or not isinstance(a.get("state"), dict)
        or not isinstance(b.get("state"), dict)
        or type(a["state"].get("n")) is not int
        or a["state"]["n"] != n
        or type(b["state"].get("n")) is not int
        or b["state"]["n"] != n
        or any(
            not isinstance(r, dict)
            or type(r.get("n")) is not int
            or r["n"] != n
            or type(r.get("stored_ms")) is not int
            or r["stored_ms"] < 0
            or r["stored_ms"] > start
            or type(r.get("expires_ms")) is not int
            or r["expires_ms"] - r["stored_ms"] != 8000
            or (r.get("unknown") is not (control_name in ("unknown", "expired")))
            or (r["expires_ms"] <= end if control_name != "expired" else r["expires_ms"] > start)
            for r in reports.values()
        )
    ):
        raise IntegrityError("fitness:diagnostic_snapshot")
    after_reports = b.get("reports")
    if any(
        not isinstance(report, dict)
        or type(report.get("n")) is not int
        or report["n"] != n
        or report.get("unknown") is not (control_name in ("unknown", "expired"))
        or type(report.get("stored_ms")) is not int
        or report["stored_ms"] < reports[gateway]["stored_ms"]
        or report["stored_ms"] > end
        or type(report.get("expires_ms")) is not int
        or report["expires_ms"] - report["stored_ms"] != 8000
        or (
            report["expires_ms"] > start
            if control_name == "expired"
            else report["expires_ms"] <= end
        )
        for gateway, report in after_reports.items()
    ):
        raise IntegrityError("fitness:diagnostic_snapshot")
    rid = receipt["reservation_id"]
    gateway_ids = set(gateway_ids)
    admits, releases, previous = [], [], start
    for order, row in enumerate(redis_operations, lo + 1):
        if (
            not isinstance(row, dict)
            or row.get("source_kind") != "redis"
            or row.get("source_identity") != "redis"
            or row.get("error") is not None
            or not isinstance(row.get("payload"), dict)
        ):
            raise IntegrityError("fitness:diagnostic_gap")
        p = row["payload"]
        event = p.get("event")
        if (
            type(p.get("store_order")) is not int
            or p["store_order"] != order
            or type(p.get("redis_time_ms")) is not int
            or not previous <= p["redis_time_ms"] <= end
            or p.get("config_sha256") != a["config_sha256"]
            or event not in ("admit", "release", "report_store", "unknown")
        ):
            raise IntegrityError("fitness:diagnostic_gap")
        if event == "report_store":
            if not _valid_report_store(p, expected_n=n, config_sha256=a["config_sha256"]):
                raise IntegrityError("fitness:diagnostic_gap")
        elif event == "unknown":
            if (
                control_name not in ("unknown", "expired")
                or p.get("gateway_uid") not in _ROW5_GATEWAYS
                or p.get("unknown") is not True
                or p.get("report_known") is not False
            ):
                raise IntegrityError("fitness:diagnostic_gap")
        else:
            operation_id = p.get("reservation_id")
            if not isinstance(operation_id, str):
                raise IntegrityError("fitness:diagnostic_gap")
            if operation_id == rid:
                (admits if event == "admit" else releases).append(p)
            elif operation_id not in gateway_ids:
                raise IntegrityError("fitness:diagnostic_gap")
        previous = p["redis_time_ms"]
    if (
        len(admits) != 1
        or admits[0].get("decision") != decision
        or type(admits[0].get("effective_n")) is not int
        or admits[0]["effective_n"] != n
        or type(admits[0].get("effective_b")) is not int
        or admits[0]["effective_b"] != capacity
        or admits[0].get("idempotent") is not False
        or not diagnostic_redis_bounds[0]
        <= admits[0]["redis_time_ms"]
        <= diagnostic_redis_bounds[1]
        or receipt.get("decision") != decision
        or type(receipt.get("capacity")) is not int
        or receipt["capacity"] != capacity
        or type(receipt.get("released")) is not bool
        or receipt["released"] is not (decision == "allowed")
    ):
        raise IntegrityError("fitness:diagnostic_decision")
    if decision == "allowed" and (
        len(releases) != 1
        or releases[0].get("decision") != "released"
        or releases[0].get("idempotent") is not False
        or releases[0].get("occupied") != 0
        or releases[0]["store_order"] <= admits[0]["store_order"]
    ):
        raise IntegrityError("fitness:diagnostic_release")
    if decision != "allowed" and releases:
        raise IntegrityError("fitness:diagnostic_release")
    return {"reservation_id": rid, "decision": decision, "effective_n": n, "effective_b": capacity}
