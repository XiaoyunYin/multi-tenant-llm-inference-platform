"""Replay row5 proofs from an already closed CaptureOwner receipt."""

from __future__ import annotations

import copy
from collections import defaultdict
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

from .inf037b_archive import IntegrityError, encode, sha, strict_json
from .inf037b_capture import wire_records
from .inf037b_probe import capture_rows
from .inf037b_row5 import expired_window
from .inf037b_row5_capture import gateway_prefix_from_capture, gateway_resolved_config_from_capture
from .inf037b_row5_diagnostic import diagnostic_receipts_from_capture
from .inf037b_row5_live import LiveRow5
from .inf037b_row5_sequence import GATEWAYS, OUTAGE_SEQUENCE_TIMEOUT_S, KnownStage
from .inf037b_sources import ClockMapper

CONTROL_ORDER = (
    "known0",
    "known1",
    "known2",
    "cached_stop_known1",
    "cached_restore_known2",
    "unknown",
    "expired",
    "post_outage_known2",
)


def _json(path):
    return strict_json(Path(path).read_bytes())


def _durable_payload(path):
    record = _json(path)
    if (
        not isinstance(record, dict)
        or record.get("schema") != "inf037b-durable-v1"
        or not isinstance(record.get("payload"), dict)
        or record.get("sha256") != sha(encode(record["payload"]))
    ):
        raise IntegrityError("row5_replay:durable_record")
    return record["payload"]


def _operation(path, key):
    payload = _durable_payload(path)
    operations = payload.get("operations")
    if not isinstance(operations, dict):
        raise IntegrityError("row5_replay:operation_store")
    matches = [item for item in operations.values() if item.get("key") == key]
    if len(matches) != 1:
        raise IntegrityError("row5_replay:operation_store")
    return matches[0]


def _capture(root, name):
    base = Path(root) / "captures" / name
    payload = _durable_payload(Path(root) / "captures" / f"{name}-store" / "state.json")
    descriptor = payload.get("capture")
    operation = _operation(
        Path(root) / "captures" / f"{name}-operations" / "state.json",
        "row5-" + name,
    )
    if not isinstance(descriptor, dict) or descriptor.get("operation") != operation:
        raise IntegrityError("row5_replay:capture_store")
    owner = SimpleNamespace(
        root=base,
        boot=descriptor.get("boot_id"),
        binding=descriptor.get("binding"),
        operation=operation,
        sources=descriptor.get("sources"),
    )
    return owner, descriptor


def _rbac_transaction_semantics(receipt_root, wire, binding):
    """Rebuild exact RoleControl action and review semantics from retained HTTP."""
    from .inf037b_row5 import canonical_role

    root = Path(receipt_root)
    resource_bytes = (root / "row5-resources.json").read_bytes()
    if sha(resource_bytes) != binding.get("pins", {}).get("manifest"):
        raise IntegrityError("row5_replay:row5_manifest")
    resources = strict_json(resource_bytes)
    items = resources.get("items") if isinstance(resources, dict) else None
    roles = [
        item
        for item in items or []
        if isinstance(item, dict)
        and item.get("kind") == "Role"
        and item.get("metadata", {}).get("name") == "endpoint-reader"
    ]
    if len(roles) != 1:
        raise IntegrityError("row5_replay:operator_role")
    reviewed_role = roles[0]
    operator_resources = _json(root / "operator-rbac.json")
    operator_items = (
        operator_resources.get("items") if isinstance(operator_resources, dict) else None
    )
    if not isinstance(operator_items, list) or not any(
        isinstance(item, dict)
        and item.get("kind") == "ServiceAccount"
        and item.get("metadata", {}).get("name") == "row5-operator"
        for item in operator_items
    ):
        raise IntegrityError("row5_replay:operator_rbac_manifest")
    original_projection = canonical_role(reviewed_role)
    reviewed_hash = sha(original_projection)

    transactions = []
    current = None

    def finish():
        nonlocal current
        if current is None:
            return
        headers = [
            row
            for row, _ in current["responses"]
            if row.get("metadata", {}).get("direction") == "response_headers"
        ]
        body = b"".join(
            chunk
            for row, chunk in current["responses"]
            if row.get("metadata", {}).get("direction") == "response"
        )
        errors = [
            row.get("metadata", {}).get("review_error_class")
            for row, _ in current["responses"]
            if row.get("metadata", {}).get("review_error_class")
        ]
        if len(headers) != 1 or errors or not body:
            raise IntegrityError("row5_replay:rbac_http_transaction")
        status = headers[0].get("metadata", {}).get("status")
        if type(status) is not int or not 200 <= status < 300:
            raise IntegrityError("row5_replay:rbac_http_transaction")
        current["response"] = strict_json(body)
        current["status"] = status
        current["response_end_ns"] = current["responses"][-1][0].get("end_ns")
        transactions.append(current)
        current = None

    for row, body in wire:
        if row.get("source") != "rbac":
            continue
        metadata = row.get("metadata", {})
        direction = metadata.get("direction")
        if direction == "request":
            finish()
            current = {
                "sequence": row.get("sequence"),
                "method": metadata.get("method"),
                "path": metadata.get("path"),
                "request": strict_json(body) if body else None,
                "request_start_ns": row.get("start_ns"),
                "responses": [],
            }
        else:
            if (
                current is None
                or metadata.get("method") != current["method"]
                or metadata.get("path") != current["path"]
            ):
                raise IntegrityError("row5_replay:rbac_http_transaction")
            current["responses"].append((row, body))
    finish()

    role_path = "/roles/endpoint-reader"
    role_reads = [
        item
        for item in transactions
        if item["path"].endswith(role_path) and item["method"] == "GET"
    ]
    role_writes = [
        item
        for item in transactions
        if item["path"].endswith(role_path) and item["method"] == "PUT"
    ]
    reviews = [
        item
        for item in transactions
        if item["path"] == "/apis/authorization.k8s.io/v1/subjectaccessreviews"
        and item["method"] == "POST"
    ]
    if len(role_reads) != 4 or len(role_writes) != 2 or not reviews:
        raise IntegrityError("row5_replay:rbac_inventory")
    if canonical_role(role_reads[0]["response"]) != original_projection:
        raise IntegrityError("row5_replay:rbac_reviewed_role")

    actions = []
    for index, write in enumerate(role_writes):
        phase = "revoke" if index == 0 else "restore"
        previous_reads = [item for item in role_reads if item["sequence"] < write["sequence"]]
        later_reads = [item for item in role_reads if item["sequence"] > write["sequence"]]
        if not previous_reads or not later_reads:
            raise IntegrityError("row5_replay:rbac_readback")
        before, after = previous_reads[-1], later_reads[0]
        request_role = write["request"]
        if not isinstance(request_role, dict):
            raise IntegrityError("row5_replay:rbac_role_write")
        before_meta = before["response"].get("metadata", {})
        after_meta = after["response"].get("metadata", {})
        request_meta = request_role.get("metadata", {})
        uid = role_reads[0]["response"].get("metadata", {}).get("uid")
        precondition = before_meta.get("resourceVersion")
        readback = after_meta.get("resourceVersion")
        if (
            not isinstance(uid, str)
            or before_meta.get("uid") != uid
            or after_meta.get("uid") != uid
        ):
            raise IntegrityError("row5_replay:rbac_uid")
        if (
            not isinstance(precondition, str)
            or request_meta.get("resourceVersion") != precondition
            or not isinstance(readback, str)
            or readback == precondition
        ):
            raise IntegrityError("row5_replay:rbac_resource_version")
        if canonical_role(after["response"]) != canonical_role(request_role):
            raise IntegrityError("row5_replay:rbac_readback")
        projection = canonical_role(request_role)
        action = {
            "phase": phase,
            "uid": uid,
            "precondition_resource_version": precondition,
            "readback_resource_version": readback,
            "canonical_projection_sha256": sha(projection),
        }
        if phase == "revoke":
            if request_role.get("rules") != []:
                raise IntegrityError("row5_replay:rbac_revoke_rules")
        else:
            if projection != original_projection:
                raise IntegrityError("row5_replay:rbac_restore_projection")
            action["restored_matches_reviewed_sha256"] = sha(projection) == reviewed_hash
        actions.append(action)

    first_write, second_write = role_writes
    review_semantics = []
    for review in reviews:
        request, response = review["request"], review["response"]
        spec = request.get("spec", {}) if isinstance(request, dict) else {}
        verb = spec.get("resourceAttributes", {}).get("verb")
        status = response.get("status", {}) if isinstance(response, dict) else {}
        allowed = status.get("allowed")
        if (
            request.get("kind") != "SubjectAccessReview"
            or verb not in ("list", "watch")
            or status.get("evaluationError")
            or type(allowed) is not bool
        ):
            raise IntegrityError("row5_replay:rbac_review")
        phase = (
            "initial"
            if review["sequence"] < first_write["sequence"]
            else "revoke"
            if review["sequence"] < second_write["sequence"]
            else "restore"
        )
        review_semantics.append({"phase": phase, "verb": verb, "allowed": allowed})

    expected_reviews = {
        ("initial", "list", True),
        ("initial", "watch", False),
        ("revoke", "list", False),
        ("revoke", "watch", False),
        ("restore", "list", True),
        ("restore", "watch", False),
    }
    actual_reviews = {(item["phase"], item["verb"], item["allowed"]) for item in review_semantics}
    if not expected_reviews <= actual_reviews:
        raise IntegrityError("row5_replay:rbac_review_inventory")
    return {
        "reviewed_sha256": reviewed_hash,
        "actions": actions,
        "reviews": review_semantics,
        "restore_success": actions[-1]["restored_matches_reviewed_sha256"]
        and ("restore", "list", True) in actual_reviews
        and ("restore", "watch", False) in actual_reviews,
        "transactions": transactions,
    }


def _gateway_measurement_polls(wire):
    """Group retained gateway measurement responses by their header records."""
    polls = {gateway: [] for gateway in GATEWAYS}
    current = {}

    def finish(gateway):
        poll = current.pop(gateway, None)
        if poll is None:
            return
        records = poll["records"]
        last = records[-1][0]
        poll["last_end_ns"] = last.get("end_ns")
        poll["body"] = b"".join(part for _, part in poll["records"])
        if type(poll["last_end_ns"]) is not int or poll["last_end_ns"] < poll["start_ns"]:
            raise IntegrityError("row5_replay:gateway_measurement_poll")
        poll["raw_records"] = [strict_json(line) for line in poll["body"].splitlines() if line]
        polls[gateway].append(poll)

    for record, body in wire:
        gateway = record.get("source")
        if gateway not in GATEWAYS:
            continue
        metadata = record.get("metadata", {})
        if metadata.get("error"):
            raise IntegrityError("row5_replay:gateway_measurement_poll")
        if "headers" in metadata:
            finish(gateway)
            path = metadata.get("path")
            if (
                not isinstance(path, str)
                or urlsplit(path).path != "/internal/measurement"
                or metadata.get("status") != 200
                or type(record.get("start_ns")) is not int
                or type(record.get("sequence")) is not int
            ):
                raise IntegrityError("row5_replay:gateway_measurement_poll")
            current[gateway] = {
                "gateway": gateway,
                "start_ns": record["start_ns"],
                "header_sequence": record["sequence"],
                "records": [(record, body)],
            }
        else:
            if gateway not in current:
                raise IntegrityError("row5_replay:gateway_measurement_poll")
            current[gateway]["records"].append((record, body))
    for gateway in GATEWAYS:
        finish(gateway)
    if any(not polls[gateway] for gateway in GATEWAYS):
        raise IntegrityError("row5_replay:gateway_measurement_poll")
    return polls


def _reconstruct_wrapper_times(rbac, transactions, gateway_polls):
    """Rebuild the permitted RoleControl and InstallRecovery wrapper clocks."""
    timed_rbac = copy.deepcopy(rbac)
    restore_success = timed_rbac.pop("restore_success", None) is True
    role_path = "/roles/endpoint-reader"
    role_writes = [
        item
        for item in transactions
        if item.get("method") == "PUT" and item.get("path", "").endswith(role_path)
    ]
    if len(role_writes) != 2 or len(timed_rbac.get("actions", [])) != 2:
        raise IntegrityError("row5_replay:rbac_call_split")
    second_write = role_writes[1]
    binding_reads = [
        item
        for item in transactions
        if item.get("method") == "GET"
        and item.get("path", "").endswith("/rolebindings/gateway-endpoints")
        and item.get("sequence", -1) < second_write.get("sequence", -1)
    ]
    if not binding_reads:
        raise IntegrityError("row5_replay:rbac_call_split")
    restore_start = binding_reads[-1]
    try:
        split = transactions.index(restore_start)
    except ValueError as exc:
        raise IntegrityError("row5_replay:rbac_call_split") from exc
    if split <= 0 or split >= len(transactions):
        raise IntegrityError("row5_replay:rbac_call_split")
    calls = (transactions[:split], transactions[split:])
    if any(not call for call in calls):
        raise IntegrityError("row5_replay:rbac_call_split")
    for index, call in enumerate(calls):
        start_ns = call[0].get("request_start_ns")
        end_ns = call[-1].get("response_end_ns")
        if type(start_ns) is not int or type(end_ns) is not int or end_ns < start_ns:
            raise IntegrityError("row5_replay:rbac_call_split")
        timed_rbac["actions"][index].update(start_ns=start_ns, end_ns=end_ns)

    review_transactions = [
        item
        for item in transactions
        if item.get("method") == "POST"
        and item.get("path") == "/apis/authorization.k8s.io/v1/subjectaccessreviews"
    ]
    try:
        paired_reviews = list(zip(timed_rbac.get("reviews", []), review_transactions, strict=True))
    except ValueError as exc:
        raise IntegrityError("row5_replay:rbac_review_zip") from exc
    for semantic, transaction in paired_reviews:
        request = transaction.get("request")
        response = transaction.get("response")
        verb = (
            request.get("spec", {}).get("resourceAttributes", {}).get("verb")
            if isinstance(request, dict)
            else None
        )
        allowed = response.get("status", {}).get("allowed") if isinstance(response, dict) else None
        phase = (
            "initial"
            if transaction["sequence"] < role_writes[0]["sequence"]
            else "revoke"
            if transaction["sequence"] < second_write["sequence"]
            else "restore"
        )
        if (semantic.get("phase"), semantic.get("verb"), semantic.get("allowed")) != (
            phase,
            verb,
            allowed,
        ):
            raise IntegrityError("row5_replay:rbac_review_zip")
        start_ns = transaction.get("request_start_ns")
        end_ns = transaction.get("response_end_ns")
        if type(start_ns) is not int or type(end_ns) is not int or end_ns < start_ns:
            raise IntegrityError("row5_replay:rbac_review_zip")
        semantic["start_ns"], semantic["end_ns"] = start_ns, end_ns

    envelope_start_ns = timed_rbac["actions"][0]["start_ns"]
    envelope_deadline_ns = envelope_start_ns + OUTAGE_SEQUENCE_TIMEOUT_S * 1_000_000_000
    timed_rbac["envelope_start_ns"] = envelope_start_ns
    timed_rbac["envelope_deadline_ns"] = envelope_deadline_ns
    restore_request_start_ns = restore_start.get("request_start_ns")
    if type(restore_request_start_ns) is not int:
        raise IntegrityError("row5_replay:restore_poll_selection")
    selected_polls = {}
    for gateway in GATEWAYS:
        before = [
            poll
            for poll in gateway_polls[gateway]
            if poll["last_end_ns"] < restore_request_start_ns
        ]
        if not before:
            raise IntegrityError("row5_replay:restore_poll_selection")
        selected_polls[gateway] = max(
            before, key=lambda poll: (poll["last_end_ns"], poll["header_sequence"])
        )
    cursor_ns = max(poll["last_end_ns"] for poll in selected_polls.values())
    restore_outcome = {
        "start_ns": min(poll["start_ns"] for poll in selected_polls.values()),
        "end_ns": timed_rbac["actions"][1]["end_ns"],
        "deadline_ns": envelope_deadline_ns,
        "success": restore_success,
    }
    if restore_outcome["end_ns"] < restore_outcome["start_ns"]:
        raise IntegrityError("row5_replay:restore_poll_selection")
    return timed_rbac, restore_outcome, cursor_ns


def _reconstruct_recovery_observations(gateway_polls, cursor_ns):
    """Replay InstallRecovery's merge and OutageSequence's sample rule."""
    latest = dict.fromkeys(GATEWAYS)
    last_seq = dict.fromkeys(GATEWAYS, 0)
    observations = []
    ordered_polls = sorted(
        (poll for gateway in GATEWAYS for poll in gateway_polls[gateway]),
        key=lambda poll: (poll["last_end_ns"], poll["header_sequence"]),
    )
    for poll in ordered_polls:
        gateway = poll["gateway"]
        after_cursor = poll["start_ns"] > cursor_ns
        for raw in poll["raw_records"]:
            if raw.get("event") != "install":
                continue
            data = raw.get("data")
            if not isinstance(data, dict):
                raise IntegrityError("row5_replay:recovery_source_incomplete")
            seq = data.get("poll_seq")
            if type(seq) is not int or seq != last_seq[gateway] + 1:
                raise IntegrityError("row5_replay:recovery_source_incomplete")
            last_seq[gateway] = seq
            if not after_cursor:
                continue
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
                not isinstance(member, dict)
                or any(type(member.get(key)) is not bool for key in ("ready", "sampled", "healthy"))
                for member in members
            ):
                raise IntegrityError("row5_replay:recovery_source_incomplete")
            n = sum(
                member["ready"] and member["sampled"] and member["healthy"] for member in members
            )
            latest[gateway] = reason is None and n == 2
            merged_known = all(latest.values())
            merged_reason = reason or (None if merged_known else "unknown")
            read_mono_ns = poll["last_end_ns"]
            known = merged_known is True and n == 2 and 5 * n == 10
            observations.append(
                {
                    "gateway_uid": gateway,
                    "poll_seq": seq,
                    "time_ms": read_mono_ns // 1_000_000,
                    "read_mono_ns": read_mono_ns,
                    "time_clock": "collector_monotonic",
                    "source_event_ns": raw.get("mono_ns"),
                    "known": known,
                    "reason": None if known else merged_reason or "unknown",
                    "n": n,
                    "effective_b": 5 * n,
                }
            )
            if type(observations[-1]["source_event_ns"]) is not int:
                raise IntegrityError("row5_replay:recovery_source_incomplete")
    if any(last_seq[gateway] == 0 for gateway in GATEWAYS):
        raise IntegrityError("row5_replay:recovery_source_incomplete")
    return observations


def _gateway_reservation_map(prefixes):
    reservations = {}
    for prefix in prefixes.values():
        for line in prefix.splitlines():
            record = strict_json(line)
            data = record.get("data")
            if not isinstance(data, dict):
                continue
            reservation = data.get("reservation_id")
            request_id = data.get("request_id")
            if reservation is None or request_id is None:
                continue
            if (
                not isinstance(reservation, str)
                or not reservation
                or not isinstance(request_id, str)
                or not request_id
            ):
                raise IntegrityError("row5_replay:gateway_reservation")
            if reservation in reservations and reservations[reservation] != request_id:
                raise IntegrityError("row5_replay:gateway_reservation")
            reservations[reservation] = request_id
    return reservations


def _reconstructed_offers(replayed):
    offers = [
        copy.deepcopy(offer)
        for name in CONTROL_ORDER
        for offer in replayed["grouped_offers"].get(name, [])
    ]
    if len(offers) != len(CONTROL_ORDER) * len(GATEWAYS):
        raise IntegrityError("row5_replay:offer_inventory")
    controls = [
        copy.deepcopy(offer)
        for name in ("unknown", "expired", "post_outage_known2")
        for offer in replayed["grouped_offers"].get(name, [])
    ]
    if len(controls) != 3 * len(GATEWAYS):
        raise IntegrityError("row5_replay:offer_inventory")
    return offers, controls


def _reconstruct_row5_evidence(replayed):
    gateway_polls = _gateway_measurement_polls(replayed["wire"])
    rbac, restore_outcome, cursor_ns = _reconstruct_wrapper_times(
        replayed["rbac"], replayed["rbac_transactions"], gateway_polls
    )
    observations = _reconstruct_recovery_observations(gateway_polls, cursor_ns)
    live = replayed["live"]
    evidence = {
        "schema": "inf037b-row5-evidence-v1",
        "configuration_sha256": replayed["configuration_sha256"],
        "gateway_config_captures": {gateway: live.gateway_binding(gateway) for gateway in GATEWAYS},
        "gateway_reservation_ids": sorted(live.reservations),
        "known": {},
        "refusals": {},
        "diagnostics": {},
        "last_known_stores_ms": copy.deepcopy(replayed["last_known_stores_ms"]),
        "expired_snapshot_latency_ms": replayed["expired_snapshot_latency_ms"],
        "expired_window_ms": list(replayed["expired_window_ms"]),
        "rbac": rbac,
        "restore_outcome": restore_outcome,
        "recovery": {
            "observations": observations,
            "source_complete": True,
            "evidence_sha256": sha(encode(observations)),
        },
    }
    from .inf037b_row5 import ROW5_KNOWN_CONTROLS

    for name in CONTROL_ORDER:
        proof = replayed["proofs_by_control"][name]
        section = "known" if name in ROW5_KNOWN_CONTROLS else "refusals"
        evidence[section][name] = copy.deepcopy(proof["gateways"])
        evidence["diagnostics"][name] = copy.deepcopy(proof["diagnostic"])
    return evidence


def _client_requests(rows, wire):
    groups = defaultdict(list)
    for record, body in wire:
        if record.get("source") in {"client:gateway0", "client:gateway1"}:
            groups[record["source"], record["start_ns"]].append((record, body))
    offers = sorted(
        (
            row
            for row in rows
            if row.get("source_kind") == "client" and row.get("payload", {}).get("event") == "offer"
        ),
        key=lambda row: row["payload"].get("offer_index", -1),
    )
    if len(offers) != len(CONTROL_ORDER) * len(GATEWAYS):
        raise IntegrityError("row5_replay:offer_inventory")
    request_records, request_times, grouped_offers = {}, {}, defaultdict(list)
    for index, row in enumerate(offers):
        payload = row["payload"]
        expected_index = index
        name = CONTROL_ORDER[index // len(GATEWAYS)]
        gateway = GATEWAYS[index % len(GATEWAYS)]
        if (
            payload.get("offer_index") != expected_index
            or payload.get("gateway_uid") != gateway
            or not isinstance(payload.get("request_id"), str)
            or row.get("capture_start_mono_ns") is None
        ):
            raise IntegrityError("row5_replay:offer_order")
        start_ns = row["capture_start_mono_ns"]
        records = groups.get(("client:" + gateway, start_ns), [])
        headers = [record for record, _ in records if "headers" in record.get("metadata", {})]
        terminals = [
            record
            for record, _ in records
            if record.get("metadata", {}).get("client_request_end") is True
        ]
        if len(headers) != 1 or len(terminals) != 1:
            raise IntegrityError("row5_replay:client_wire_join")
        header_values = [
            value
            for key, value in headers[0]["metadata"].get("headers", [])
            if key.lower() == "x-request-id"
        ]
        if len(header_values) != 1:
            raise IntegrityError("row5_replay:client_wire_join")
        client_rows = [
            candidate
            for candidate in rows
            if candidate.get("source_kind") == "client"
            and candidate.get("payload", {}).get("request_id") == payload["request_id"]
        ]
        if not client_rows:
            raise IntegrityError("row5_replay:client_wire_join")
        request_end = max(client_rows, key=lambda candidate: candidate["source_seq"])[
            "capture_end_mono_ns"
        ]
        offer = {
            "request_id": payload["request_id"],
            "gateway_uid": gateway,
            "snapshot_id": name,
            "offer_index": expected_index,
            "prefix_id": payload.get("prefix_id"),
            "phase": "pre",
            "config_sha256": payload.get("config_sha256"),
            "scheduled_ms": payload.get("scheduled_ms"),
        }
        request_records[offer["request_id"]] = {
            "start_ns": start_ns,
            "end_ns": request_end,
            "gateway_request_id": header_values[0],
        }
        request_times[offer["request_id"]] = (start_ns, terminals[0]["end_ns"])
        grouped_offers[name].append(offer)
    return grouped_offers, request_records, request_times


def replay_row5_proofs(receipt_root):
    """Run LiveRow5.proof_inputs and KnownStage.proofs over the sealed capture."""
    receipt_root = Path(receipt_root).resolve()
    runtime_owner, runtime_descriptor = _capture(receipt_root, "runtime")
    configuration_owner, configuration_descriptor = _capture(receipt_root, "configuration")
    binding = runtime_descriptor["binding"]
    if configuration_descriptor.get("binding") != binding:
        raise IntegrityError("row5_replay:configuration_binding")
    rows = list(capture_rows(runtime_owner.root, runtime_descriptor))
    wire = list(wire_records(runtime_owner.root / "wire"))
    rbac = _rbac_transaction_semantics(receipt_root, wire, runtime_descriptor["binding"])
    rbac_transactions = rbac.pop("transactions")
    recovery_install_rows = {
        gateway: [
            {
                "poll_seq": row["payload"].get("poll_seq"),
                "healthy_count": row["payload"].get("healthy_count"),
                "membership_known": row["payload"].get("membership_known"),
                "error_class": row["payload"].get("error_class"),
            }
            for row in rows
            if row.get("source_kind") == "gateway"
            and row.get("source_identity") == gateway
            and row.get("payload", {}).get("event") == "install"
        ]
        for gateway in GATEWAYS
    }
    grouped_offers, client_requests, request_times = _client_requests(rows, wire)

    config_captures = {}
    for gateway in GATEWAYS:
        source = gateway
        triples = configuration_descriptor["sources"].get(source)
        if not isinstance(triples, list) or len(triples) != 1:
            raise IntegrityError("row5_replay:configuration_source")
        gateway_boot = triples[0][2]
        config_captures[gateway] = {
            "root": str(configuration_owner.root),
            "descriptor": configuration_descriptor,
            "expected_binding": configuration_owner.binding,
            "expected_operation": configuration_owner.operation,
            "expected_descriptor_sha256": sha(encode(configuration_descriptor)),
            "source": source,
            "gateway_uid": gateway,
            "gateway_boot": gateway_boot,
        }
    configs = {
        gateway: gateway_resolved_config_from_capture(**config_captures[gateway])
        for gateway in GATEWAYS
    }
    if configs["gateway0"] != configs["gateway1"]:
        raise IntegrityError("row5_replay:gateway_configuration_mismatch")
    config = configs["gateway0"]
    configuration_sha256 = sha(encode(config))
    if binding.get("pins", {}).get("configuration") != configuration_sha256:
        raise IntegrityError("row5_replay:configuration_hash")

    diagnostic_source = "diagnostic"
    diagnostic_source_spec = runtime_descriptor["sources"].get(diagnostic_source)
    if not isinstance(diagnostic_source_spec, list) or len(diagnostic_source_spec) != 1:
        raise IntegrityError("row5_replay:diagnostic_source")
    diagnostic_generation = diagnostic_source_spec[0][2]
    diagnostic_binary = receipt_root / "row5-diagnostic"
    if not diagnostic_binary.is_file():
        raise IntegrityError("row5_replay:diagnostic_binary")
    receipts = diagnostic_receipts_from_capture(
        str(runtime_owner.root),
        runtime_descriptor,
        expected_binding=runtime_owner.binding,
        expected_operation=runtime_owner.operation,
        expected_descriptor_sha256=sha(encode(runtime_descriptor)),
        source=diagnostic_source,
        source_generation=diagnostic_generation,
        binary_sha256=sha(diagnostic_binary.read_bytes()),
        gateway_configs={gateway: config for gateway in GATEWAYS},
    )
    if len(receipts) != len(CONTROL_ORDER):
        raise IntegrityError("row5_replay:diagnostic_inventory")

    live = LiveRow5.__new__(LiveRow5)
    live.owner = runtime_owner
    live.spec = {
        gateway: {
            "source": gateway,
            "boot": runtime_descriptor["sources"][gateway][0][2],
            "client_source": "client:" + gateway,
        }
        for gateway in GATEWAYS
    }
    live.rows = rows
    live.descriptor = runtime_descriptor
    live.descriptor_sha256 = sha(encode(runtime_descriptor))
    live.clocks = ClockMapper(rows)
    live.config_captures = config_captures
    live.config = config
    live.diagnostic_source = diagnostic_source
    live.diagnostic_generation = diagnostic_generation
    live.receipts = receipts
    live.clients = {
        gateway: SimpleNamespace(
            requests={
                request_id: record
                for request_id, record in client_requests.items()
                if next(
                    o
                    for offers in grouped_offers.values()
                    for o in offers
                    if o["request_id"] == request_id
                )["gateway_uid"]
                == gateway
            }
        )
        for gateway in GATEWAYS
    }
    prefixes = {
        gateway: gateway_prefix_from_capture(**live.gateway_binding(gateway))
        for gateway in GATEWAYS
    }
    live.reservations = _gateway_reservation_map(prefixes)

    receipt_hashes = {item["reservation_id"]: item["receipt_sha256"] for item in receipts}
    live.diagnostic = SimpleNamespace(receipt_hashes=receipt_hashes)
    named_snapshots = {
        row["payload"].get("snapshot_id"): row
        for row in rows
        if row.get("source_kind") == "redis"
        and row.get("payload", {}).get("event") == "snapshot"
        and row.get("payload", {}).get("snapshot_id")
    }
    required_snapshots = set(CONTROL_ORDER) | {"post_outage_agreement", "hold_start", "hold_end"}
    if not required_snapshots <= set(named_snapshots):
        raise IntegrityError("row5_replay:snapshot_inventory")
    unknown = named_snapshots["unknown"]
    expired = named_snapshots["expired"]
    last_known_stores_ms = {
        gateway: unknown["payload"]["reports"][gateway]["stored_ms"] for gateway in GATEWAYS
    }
    expired_snapshot_latency_ms = max(
        (row["capture_end_mono_ns"] - row["capture_start_mono_ns"] + 999_999) // 1_000_000
        for row in (unknown, expired)
    )
    expired_window_ms = expired_window(
        last_known_stores_ms.values(), 8000, 2000, expired_snapshot_latency_ms
    )
    if not (
        expired_window_ms[0] < expired["payload"].get("redis_time_ms", -1) < expired_window_ms[1]
    ):
        raise IntegrityError("fitness:expired_snapshot_window")
    receipts_by_order = sorted(receipts, key=lambda item: item["process_start_ns"])
    stage = KnownStage(
        redis=None,
        clients=live.clients,
        diagnostic=live.diagnostic,
        request_arguments=lambda gateway: {},
        diagnostic_arguments=lambda: {"config": config},
        proof_inputs=live.proof_inputs,
        configuration_sha256=configuration_sha256,
        clock=lambda: 0,
        sleep=lambda _: None,
        defer_proofs=True,
    )
    all_snapshots = [
        row
        for row in rows
        if row.get("source_kind") == "redis" and row.get("payload", {}).get("event") == "snapshot"
    ]
    counts = {"controls": 0, "gateway_proofs": 0, "diagnostic_proofs": 0}
    controls_run = []
    proofs_by_control = {}
    for index, name in enumerate(CONTROL_ORDER):
        snapshot = named_snapshots.get(name)
        requests = grouped_offers.get(name, [])
        receipt = receipts_by_order[index]
        if snapshot is None or len(requests) != 2:
            raise IntegrityError("row5_replay:control_inventory")
        request_ends = [request_times[item["request_id"]][1] for item in requests]
        end_ns = max([*request_ends, receipt["process_end_ns"]])
        later = sorted(
            (
                row
                for row in all_snapshots
                if row["payload"]["store_order"] > snapshot["payload"]["store_order"]
                and row.get("capture_start_mono_ns", -1) >= end_ns
            ),
            key=lambda row: (row["capture_start_mono_ns"], row["payload"]["store_order"]),
        )
        if not later:
            raise IntegrityError("row5_replay:after_snapshot")
        after = later[0]
        stage.controls[name] = (snapshot, after, requests, receipt)
    for name in CONTROL_ORDER:
        gateways, diagnostic = stage.proofs(name)
        proofs_by_control[name] = {"gateways": gateways, "diagnostic": diagnostic}
        controls_run.append(name)
        counts["controls"] += 1
        counts["gateway_proofs"] += 2
        counts["diagnostic_proofs"] += 1
    return {
        "receipt_root": str(receipt_root),
        "source_rows": len(rows),
        "proofs": counts,
        "controls_run": controls_run,
        "runtime_descriptor_sha256": sha(encode(runtime_descriptor)),
        "configuration_descriptor_sha256": sha(encode(configuration_descriptor)),
        "configuration_sha256": configuration_sha256,
        "live": live,
        "stage": stage,
        "binding": binding,
        "configuration": config,
        "grouped_offers": grouped_offers,
        "named_snapshots": named_snapshots,
        "last_known_stores_ms": last_known_stores_ms,
        "expired_snapshot_latency_ms": expired_snapshot_latency_ms,
        "expired_window_ms": expired_window_ms,
        "rbac": rbac,
        "rbac_transactions": rbac_transactions,
        "wire": wire,
        "proofs_by_control": proofs_by_control,
        "recovery_install_rows": recovery_install_rows,
    }


_RECONSTRUCTION_SUBSTITUTIONS = [
    {
        "field": "row5_evidence.rbac.actions[0].start_ns",
        "rule": "start of the first retained RBAC request in the revoke call",
    },
    {
        "field": "row5_evidence.rbac.actions[0].end_ns",
        "rule": "end of the last retained RBAC response before the restore split",
    },
    {
        "field": "row5_evidence.rbac.actions[1].start_ns",
        "rule": "start of the last GET rolebindings/gateway-endpoints request before the second Role PUT",
    },
    {
        "field": "row5_evidence.rbac.actions[1].end_ns",
        "rule": "end of the last retained RBAC response after the restore split",
    },
    {
        "field": "row5_evidence.rbac.envelope_start_ns",
        "rule": "start_ns of the reconstructed revoke action",
    },
    {
        "field": "row5_evidence.rbac.envelope_deadline_ns",
        "rule": "envelope_start_ns plus OUTAGE_SEQUENCE_TIMEOUT_S seconds",
    },
    {
        "field": "row5_evidence.rbac.reviews[*].start_ns",
        "rule": "request start bracket, zipped in sequence order with rebuilt review semantics",
    },
    {
        "field": "row5_evidence.rbac.reviews[*].end_ns",
        "rule": "last response end bracket, zipped in sequence order with rebuilt review semantics",
    },
    {
        "field": "row5_evidence.restore_outcome.start_ns",
        "rule": "minimum start_ns of each gateway's last measurement poll ending before the restore split",
    },
    {
        "field": "row5_evidence.restore_outcome.end_ns",
        "rule": "end_ns of the reconstructed restore action",
    },
    {
        "field": "row5_evidence.restore_outcome.deadline_ns",
        "rule": "reconstructed RBAC envelope deadline",
    },
    {
        "field": "row5_evidence.restore_outcome.success",
        "rule": "restored Role readback hash plus successful restore list/watch reviews",
    },
    {
        "field": "row5_evidence.recovery.observations[*].read_mono_ns",
        "rule": "last retained record end_ns of the gateway measurement poll containing the install line",
    },
    {
        "field": "row5_evidence.recovery.observations[*].time_ms",
        "rule": "floor of read_mono_ns divided by 1,000,000",
    },
    {
        "field": "row5_evidence.recovery.observations[*].known",
        "rule": "InstallRecovery latest-per-gateway merge, then OutageSequence n=2/effective_b=10 sample rule",
    },
    {
        "field": "row5_evidence.recovery.observations[*].reason",
        "rule": "InstallRecovery 403/unknown rule and OutageSequence unknown fallback",
    },
    {
        "field": "row5_evidence.recovery.evidence_sha256",
        "rule": "SHA-256 of canonical encoding of the reconstructed observations list",
    },
    {
        "field": "row5_evidence.recovery.source_complete",
        "rule": "true only after retained install poll_seq values are contiguous for both gateways",
    },
]


def _proof_maps(replayed):
    from .inf037b_row5 import ROW5_KNOWN_CONTROLS

    known, refusals, diagnostics = {}, {}, {}
    for name in CONTROL_ORDER:
        proof = replayed["proofs_by_control"][name]
        (known if name in ROW5_KNOWN_CONTROLS else refusals)[name] = copy.deepcopy(
            proof["gateways"]
        )
        diagnostics[name] = copy.deepcopy(proof["diagnostic"])
    return known, refusals, diagnostics


def _prepare_saved_composition_inputs(replayed, receipt_root, controls, requests):
    """Validate retained offers, rebase capture roots, and merge replayed proofs."""
    if not isinstance(controls, dict) or not isinstance(controls.get("row5_evidence"), dict):
        raise IntegrityError("row5_replay:saved_control_result")
    if not isinstance(requests, list) or any(not isinstance(item, dict) for item in requests):
        raise IntegrityError("row5_replay:saved_offers")
    saved_controls = controls.get("row5_control_requests")
    if not isinstance(saved_controls, list) or any(
        not isinstance(item, dict) for item in saved_controls
    ):
        raise IntegrityError("row5_replay:saved_offers")
    all_offers, control_offers = _reconstructed_offers(replayed)
    expected_all_ids = [offer["request_id"] for offer in all_offers]
    expected_control_ids = [offer["request_id"] for offer in control_offers]
    request_ids = [item.get("request_id") for item in requests]
    control_ids = [item.get("request_id") for item in saved_controls]
    if any(
        not isinstance(request_id, str) or not request_id
        for request_id in (*request_ids, *control_ids)
    ):
        raise IntegrityError("row5_replay:saved_offers")
    if len(set(request_ids)) != len(request_ids) or len(set(control_ids)) != len(control_ids):
        raise IntegrityError("row5_replay:offer_duplicate")
    if request_ids != expected_all_ids or control_ids != expected_control_ids:
        raise IntegrityError("row5_replay:offer_ids")

    evidence = copy.deepcopy(controls["row5_evidence"])
    expected_descriptor_sha256 = replayed["runtime_descriptor_sha256"]
    gateway_configs = evidence.get("gateway_config_captures")
    if not isinstance(gateway_configs, dict) or set(gateway_configs) != set(GATEWAYS):
        raise IntegrityError("row5_replay:saved_gateway_config")
    runtime_root = str(Path(receipt_root).resolve() / "captures" / "runtime")
    for gateway in GATEWAYS:
        item = gateway_configs[gateway]
        if (
            not isinstance(item, dict)
            or item.get("expected_descriptor_sha256") != expected_descriptor_sha256
        ):
            raise IntegrityError("row5_replay:descriptor_hash")
        item["root"] = runtime_root

    known, refusals, diagnostics = _proof_maps(replayed)
    evidence["known"] = known
    evidence["refusals"] = refusals
    evidence["diagnostics"] = diagnostics
    return requests, evidence


def _compose_result(replayed, requests, evidence, *, status, substitutions=None):
    from .inf037b_row5_kind import row5_timings, validate_kind_row5
    from .inf037b_sources import SourceJoin

    raw = {
        "schema": "inf037b-setup-v1",
        **replayed["binding"],
        "raw": replayed["live"].rows,
    }
    result = {"fitness_raw": encode(raw), "row5_evidence": evidence}
    validator = validate_kind_row5(
        result,
        requests,
        configuration_sha256=replayed["configuration_sha256"],
        binding=replayed["binding"],
    )
    join = SourceJoin(raw["raw"])
    if join.errors:
        raise IntegrityError("row5_replay:source_join")
    timings = row5_timings(join.rows, evidence)
    output = {"status": status, "validator": validator, "timings_ms": timings}
    if substitutions is not None:
        output["substitutions"] = copy.deepcopy(substitutions)
    return output


def replay_saved_composition(replayed, receipt_root):
    """Run reconstructed mode when inputs are absent, or replay saved live inputs."""
    receipt_root = Path(receipt_root).resolve()
    saved = receipt_root / "row5-control-result.json"
    offers_path = receipt_root / "row5-all-requests.json"
    all_offers, control_offers = _reconstructed_offers(replayed)

    if not saved.is_file():
        evidence = _reconstruct_row5_evidence(replayed)
        return _compose_result(
            replayed,
            all_offers,
            evidence,
            status="passed_reconstructed",
            substitutions=_RECONSTRUCTION_SUBSTITUTIONS,
        )
    if not offers_path.is_file():
        raise IntegrityError("row5_replay:saved_offers_missing")

    controls = _json(saved)
    requests, evidence = _prepare_saved_composition_inputs(
        replayed, receipt_root, controls, _json(offers_path)
    )
    return _compose_result(replayed, requests, evidence, status="passed")


def replay(receipt_root):
    proofs = replay_row5_proofs(receipt_root)
    composition = replay_saved_composition(proofs, receipt_root)
    return {
        "status": composition["status"],
        "proofs": proofs["proofs"],
        "controls_run": proofs["controls_run"],
        "reconstructed_rbac": proofs["rbac"],
        "recovery_install_row_counts": {
            gateway: len(items) for gateway, items in proofs["recovery_install_rows"].items()
        },
        "composition": composition,
    }
