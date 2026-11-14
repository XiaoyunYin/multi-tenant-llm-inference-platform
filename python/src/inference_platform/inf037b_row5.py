"""Fail-closed timing and identity checks for the row 5 live controls.

These helpers do not start controls; callers must retain source receipts and enforce
an absolute envelope.  Redis times passed here must come from ordered captures.
"""

from .inf037b_archive import IntegrityError

DIAGNOSTIC_PREFIX = "rsv_d1a6"
RBAC_REVIEW_TIMEOUT_S = 5


def expired_window(last_stores, ttl_ms, hold_ms, snapshot_latency_ms):
    """Return [first, end) in Redis time, or refuse an unobservable interval."""
    values = list(last_stores)
    if (
        len(values) != 2
        or any(type(v) is not int or v < 0 for v in values)
        or any(type(v) is not int or v <= 0 for v in (ttl_ms, hold_ms))
        or type(snapshot_latency_ms) is not int
        or snapshot_latency_ms < 0
    ):
        raise IntegrityError("fitness:expired_snapshot_inputs")
    first = max(values) + ttl_ms
    end = min(values) + ttl_ms + hold_ms
    if first + snapshot_latency_ms >= end:
        raise IntegrityError("fitness:expired_snapshot_window")
    return first, end


def check_reservation_partition(gateway_ids, diagnostic_receipts, *, control_ids=()):
    """Compare actual diagnostic receipts with all gateway IDs and controls.

    Callers must independently bind the complete receipt inventory to the
    diagnostic process and bind gateway IDs to the complete gateway capture.
    The reserved prefix is prohibited for row 5 control IDs only.
    """
    import re

    def valid(value):
        return isinstance(value, str) and re.fullmatch(r"rsv_[0-9a-f]{32}", value) is not None

    if not isinstance(gateway_ids, (list, tuple, set)) or not isinstance(
        control_ids, (list, tuple, set)
    ):
        raise IntegrityError("fitness:gateway_reservation_invalid")
    if any(not valid(value) for value in gateway_ids) or any(
        not valid(value) for value in control_ids
    ):
        raise IntegrityError("fitness:gateway_reservation_invalid")
    gateways, controls = set(gateway_ids), set(control_ids)
    if not controls <= gateways:
        raise IntegrityError("fitness:gateway_reservation_invalid")
    if not isinstance(diagnostic_receipts, (list, tuple)):
        raise IntegrityError("fitness:gateway_id_in_diagnostic")
    diagnostics = []
    for receipt in diagnostic_receipts:
        if not isinstance(receipt, dict):
            raise IntegrityError("fitness:gateway_id_in_diagnostic")
        value = receipt.get("reservation_id")
        if not valid(value) or not value.startswith(DIAGNOSTIC_PREFIX):
            raise IntegrityError("fitness:gateway_id_in_diagnostic")
        diagnostics.append(value)
    if len(set(diagnostics)) != len(diagnostics):
        raise IntegrityError("fitness:diagnostic_receipt_duplicate")
    if gateways.intersection(diagnostics) or any(
        value.startswith(DIAGNOSTIC_PREFIX) for value in controls
    ):
        raise IntegrityError("fitness:diagnostic_id_in_gateway")


class RecoveryAgreement:
    """Track stability only after the caller proves source-complete continuity.

    Observations alone cannot prove there were no uncaptured gaps. Unknown or
    a 403 restarts convergence; callers must not substitute sparse polling.
    """

    def __init__(self, deadline_ms, duration_ms=2000):
        if type(deadline_ms) is not int or type(duration_ms) is not int or duration_ms <= 0:
            raise IntegrityError("fitness:agreement_inputs")
        self.deadline_ms = deadline_ms
        self.duration_ms = duration_ms
        self.start_ms = None
        self.last_ms = None
        self.restarts = []
        self.restart_reasons = []

    def observe(self, now_ms, *, known, reason=None):
        if (
            type(now_ms) is not int
            or type(known) is not bool
            or (known and reason is not None)
            or (not known and reason not in (None, "unknown", "403"))
            or (self.last_ms is not None and now_ms < self.last_ms)
        ):
            raise IntegrityError("fitness:agreement_order")
        if now_ms > self.deadline_ms:
            raise IntegrityError("fitness:agreement_deadline")
        self.last_ms = now_ms
        if not known:
            self.restarts.append(now_ms)
            self.restart_reasons.append(reason or "unknown")
            self.start_ms = None
            return False
        if self.start_ms is None:
            self.start_ms = now_ms
        return now_ms - self.start_ms >= self.duration_ms


ROW5_KNOWN_CONTROLS = {
    "known0": (0, "system_capacity", 0),
    "known1": (1, "allowed", 5),
    "known2": (2, "allowed", 10),
    "cached_stop_known1": (1, "allowed", 5),
    "cached_restore_known2": (2, "allowed", 10),
    "post_outage_known2": (2, "allowed", 10),
}
ROW5_ALL_CONTROLS = tuple(ROW5_KNOWN_CONTROLS) + ("unknown", "expired")


def validate_control_evidence(
    evidence,
    control_offers,
    *,
    configuration_sha256,
    binding,
    snapshots,
    rows,
    control_cohorts,
):
    """Validate the reviewed per-gateway and separate-diagnostic proof packet.

    Source-capture helpers must create each nested proof before this function
    is called: known entries are results of ``known_gateway_control``, refusal
    entries are results of ``captured_refusal_control``, and diagnostic entries
    are results of ``diagnostic_snapshot_control`` plus a closed process
    receipt. The raw captures remain in the setup archive; these checks bind
    their calculated outcomes to the scheduled requests, reservation partition,
    snapshot inventory, expiry interval, RBAC transition, and recovery window.
    """
    import hashlib
    import re

    from .inf037b_archive import encode, sha, strict_json

    def digest(value, reason):
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise IntegrityError(reason)

    def mapping(value, reason, keys):
        if not isinstance(value, dict) or set(value) != set(keys):
            raise IntegrityError(reason)
        return value

    if (
        not isinstance(evidence, dict)
        or evidence.get("schema") != "inf037b-row5-evidence-v1"
        or evidence.get("configuration_sha256") != configuration_sha256
        or not isinstance(control_offers, list)
        or not isinstance(snapshots, dict)
        or not set(ROW5_ALL_CONTROLS) <= set(snapshots)
        or not isinstance(rows, list)
        or not isinstance(control_cohorts, list)
    ):
        raise IntegrityError("fitness:row5_evidence_binding")
    digest(configuration_sha256, "fitness:row5_evidence_binding")
    from .inf037b_row5_capture import (
        gateway_prefix_from_capture,
        gateway_resolved_config_from_capture,
    )

    gateway_configs = mapping(
        evidence.get("gateway_config_captures"),
        "fitness:diagnostic_config_mismatch",
        ("gateway0", "gateway1"),
    )
    resolved_configs = {}
    gateway_prefixes = {}
    for gateway in ("gateway0", "gateway1"):
        item = mapping(
            gateway_configs[gateway],
            "fitness:diagnostic_config_mismatch",
            (
                "root",
                "descriptor",
                "expected_binding",
                "expected_operation",
                "expected_descriptor_sha256",
                "source",
                "gateway_uid",
                "gateway_boot",
            ),
        )
        if item["gateway_uid"] != gateway or item["expected_binding"] != binding:
            raise IntegrityError("fitness:diagnostic_config_mismatch")
        resolved_configs[gateway] = gateway_resolved_config_from_capture(**item)
        gateway_prefixes[gateway] = gateway_prefix_from_capture(**item)
    if (
        gateway_configs["gateway0"]["gateway_boot"] == gateway_configs["gateway1"]["gateway_boot"]
        or gateway_configs["gateway0"]["expected_operation"]
        != gateway_configs["gateway1"]["expected_operation"]
        or gateway_configs["gateway0"]["source"] == gateway_configs["gateway1"]["source"]
    ):
        raise IntegrityError("fitness:diagnostic_config_mismatch")
    if resolved_configs["gateway0"] != resolved_configs["gateway1"]:
        raise IntegrityError("fitness:diagnostic_config_mismatch")
    resolved_config = resolved_configs["gateway0"]
    required_config = {
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
        not isinstance(resolved_config, dict)
        or set(resolved_config) != required_config
        or (
            resolved_config.get("running"),
            resolved_config.get("waiting"),
            resolved_config.get("ttl_ms"),
            resolved_config.get("hold_ms"),
            resolved_config.get("capture"),
        )
        != (4, 1, 8000, 2000, True)
    ):
        raise IntegrityError("fitness:diagnostic_config_mismatch")
    resolved_config_sha256 = hashlib.sha256(encode(resolved_config)).hexdigest()
    offers = {}
    for item in control_offers:
        if (
            not isinstance(item, dict)
            or item.get("snapshot_id") not in ROW5_ALL_CONTROLS
            or item.get("gateway_uid") not in ("gateway0", "gateway1")
            or not isinstance(item.get("request_id"), str)
            or not item["request_id"]
            or item["request_id"].startswith(DIAGNOSTIC_PREFIX)
        ):
            raise IntegrityError("fitness:control_requests")
        key = item["snapshot_id"], item["gateway_uid"]
        if key in offers:
            raise IntegrityError("fitness:control_requests")
        offers[key] = item["request_id"]
    if set(offers) != {
        (name, gateway) for name in ROW5_ALL_CONTROLS for gateway in ("gateway0", "gateway1")
    }:
        raise IntegrityError("fitness:control_requests")

    snapshot_n = {name: n for name, (n, _, _) in ROW5_KNOWN_CONTROLS.items()}
    snapshot_n.update(unknown=2, expired=2)
    snapshot_n["post_outage_agreement"] = 2
    for name in (*ROW5_ALL_CONTROLS, "post_outage_agreement"):
        row = snapshots[name]
        payload = row.get("payload", {})
        now = payload.get("redis_time_ms")
        reports = payload.get("reports")
        if (
            row.get("source_kind") != "redis"
            or row.get("source_identity") != "redis"
            or row.get("error") is not None
            or payload.get("event") != "snapshot"
            or payload.get("snapshot_id") != name
            or type(now) is not int
            or payload.get("config_sha256") != configuration_sha256
            or payload.get("active_reservations") != []
            or payload.get("occupied") != 0
            or not isinstance(reports, dict)
            or set(reports) != {"gateway0", "gateway1"}
            or not isinstance(payload.get("state"), dict)
            or payload["state"].get("n") != snapshot_n[name]
        ):
            raise IntegrityError("fitness:row5_snapshot_state")
        expired_state = name == "expired"
        unknown_state = name in ("unknown", "expired")
        for report in reports.values():
            if (
                not isinstance(report, dict)
                or type(report.get("n")) is not int
                or report["n"] != snapshot_n[name]
                or report.get("unknown") is not unknown_state
                or type(report.get("stored_ms")) is not int
                or type(report.get("expires_ms")) is not int
                or report["stored_ms"] > now
                or report["expires_ms"] - report["stored_ms"] != 8000
                or (report["expires_ms"] <= now) is not expired_state
            ):
                raise IntegrityError("fitness:row5_snapshot_state")

    known = mapping(evidence.get("known"), "fitness:known_control_inventory", ROW5_KNOWN_CONTROLS)
    controls = {}
    control_reservation_ids = []
    all_gateway_ids = evidence.get("gateway_reservation_ids")
    if not isinstance(all_gateway_ids, list):
        raise IntegrityError("fitness:gateway_reservation_invalid")
    captured_gateway_ids = set()
    raw_gateway_records = {}
    for gateway, prefix in gateway_prefixes.items():
        records = [strict_json(line) for line in prefix.splitlines()]
        raw_gateway_records[gateway] = records
        captured_gateway_ids.update(
            record["data"]["reservation_id"]
            for record in records
            if isinstance(record.get("data"), dict)
            and isinstance(record["data"].get("reservation_id"), str)
        )
    if (
        any(not isinstance(value, str) for value in all_gateway_ids)
        or len(set(all_gateway_ids)) != len(all_gateway_ids)
        or sorted(captured_gateway_ids) != sorted(all_gateway_ids)
    ):
        raise IntegrityError("fitness:gateway_reservation_invalid")
    cohort_by_id = {}
    for cohort in control_cohorts:
        if not isinstance(cohort, dict) or cohort.get("request_id") in cohort_by_id:
            raise IntegrityError("fitness:control_request_join")
        cohort_by_id[cohort["request_id"]] = cohort
    for name, (n, decision, capacity) in ROW5_KNOWN_CONTROLS.items():
        gateways = mapping(known[name], "fitness:known_control_inventory", ("gateway0", "gateway1"))
        for gateway in ("gateway0", "gateway1"):
            proof = mapping(
                gateways[gateway],
                "fitness:known_control_proof",
                (
                    "request_id",
                    "gateway_request_id",
                    "reservation_id",
                    "decision",
                    "effective_n",
                    "effective_b",
                    "terminal",
                    "released",
                    "capture_sha256",
                ),
            )
            if (
                proof["request_id"] != offers[name, gateway]
                or not isinstance(proof["gateway_request_id"], str)
                or re.fullmatch(r"req_[0-9a-f]{32}", proof["gateway_request_id"]) is None
                or not isinstance(proof["reservation_id"], str)
                or re.fullmatch(r"rsv_[0-9a-f]{32}", proof["reservation_id"]) is None
                or proof["decision"] != decision
                or type(proof["effective_n"]) is not int
                or proof["effective_n"] != n
                or type(proof["effective_b"]) is not int
                or proof["effective_b"] != capacity
                or proof["terminal"] != ("system_capacity" if n == 0 else "released")
                or type(proof["released"]) is not bool
                or proof["released"] is not (n != 0)
            ):
                raise IntegrityError("fitness:known_control_proof")
            digest(proof["capture_sha256"], "fitness:known_control_proof")
            if proof["capture_sha256"] != sha(gateway_prefixes[gateway]):
                raise IntegrityError("fitness:known_control_proof")
            if proof["reservation_id"] not in all_gateway_ids:
                raise IntegrityError("fitness:unexplained_reservations")
            control_reservation_ids.append(proof["reservation_id"])
            raw_admits = [
                record
                for record in raw_gateway_records[gateway]
                if record.get("event") == "admit"
                and record.get("data", {}).get("request_id") == proof["gateway_request_id"]
                and record.get("data", {}).get("reservation_id") == proof["reservation_id"]
                and record.get("data", {}).get("decision") == decision
                and record.get("data", {}).get("effective_b") == capacity
            ]
            if len(raw_admits) != 1:
                raise IntegrityError("fitness:known_control_proof")
            terminals = [
                record
                for record in raw_gateway_records[gateway]
                if record.get("event") == "terminal"
                and record.get("data", {}).get("request_id") == proof["gateway_request_id"]
                and record.get("data", {}).get("reservation_id") == proof["reservation_id"]
            ]
            releases = [
                record
                for record in raw_gateway_records[gateway]
                if record.get("event") == "release"
                and record.get("data", {}).get("request_id") == proof["gateway_request_id"]
                and record.get("data", {}).get("reservation_id") == proof["reservation_id"]
            ]
            if (
                len(terminals) != 1
                or (n == 0 and (releases or terminals[0]["data"].get("code") != "system_capacity"))
                or (
                    n != 0
                    and (
                        len(releases) != 1
                        or not raw_admits[0]["sequence"]
                        < releases[0]["sequence"]
                        < terminals[0]["sequence"]
                    )
                )
            ):
                raise IntegrityError("fitness:known_control_proof")
            cohort = cohort_by_id.get(proof["request_id"])
            expected_outcome = "rejected" if n == 0 else "complete"
            if (
                not isinstance(cohort, dict)
                or cohort.get("gateway_uid") != gateway
                or cohort.get("outcome") != expected_outcome
                or cohort.get("denial_code") != ("system_capacity" if n == 0 else None)
                or cohort.get("http_status") != (429 if n == 0 else 200)
                or (n != 0 and cohort.get("reservation_id") != proof["reservation_id"])
                or (n != 0 and cohort.get("effective_b") != capacity)
                or (n != 0 and cohort.get("admitted") is not True)
            ):
                raise IntegrityError("fitness:control_request_join")
            redis_admits = [
                row
                for row in rows
                if row.get("source_kind") == "redis"
                and row.get("error") is None
                and row.get("payload", {}).get("event") == "admit"
                and row.get("payload", {}).get("reservation_id") == proof["reservation_id"]
            ]
            if (
                len(redis_admits) != 1
                or redis_admits[0]["payload"].get("request_id") != proof["request_id"]
                or redis_admits[0]["payload"].get("effective_n") != n
                or redis_admits[0]["payload"].get("effective_b") != capacity
                or redis_admits[0]["payload"].get("decision") != decision
            ):
                raise IntegrityError("fitness:control_request_join")
            normalized_admits = [
                row
                for row in rows
                if row.get("source_kind") == "gateway"
                and row.get("source_identity") == gateway
                and row.get("error") is None
                and row.get("payload", {}).get("event") == "admit"
                and row.get("payload", {}).get("request_id") == proof["request_id"]
            ]
            if (
                len(normalized_admits) != 1
                or normalized_admits[0]["payload"].get("reservation_id") != proof["reservation_id"]
                or normalized_admits[0]["payload"].get("decision") != decision
                or normalized_admits[0]["payload"].get("effective_b") != capacity
                or normalized_admits[0].get("source_generation")
                != gateway_configs[gateway]["gateway_boot"]
            ):
                raise IntegrityError("fitness:control_request_join")
            controls.setdefault(name, {})[gateway] = {
                "reservation_id": proof["reservation_id"],
                "decision": decision,
                "effective_n": n,
                "effective_b": capacity,
            }

    refusals = mapping(
        evidence.get("refusals"), "fitness:refusal_control_inventory", ("unknown", "expired")
    )
    for name in ("unknown", "expired"):
        gateways = mapping(
            refusals[name], "fitness:refusal_control_inventory", ("gateway0", "gateway1")
        )
        for gateway in ("gateway0", "gateway1"):
            proof = mapping(
                gateways[gateway],
                "fitness:refusal_control_proof",
                ("request_id", "gateway", "client", "redis", "evidence_sha256"),
            )
            gateway_proof = mapping(
                proof["gateway"],
                "fitness:refusal_absence_unproven",
                (
                    "gateway_request_id",
                    "reservation_id",
                    "deny_seq",
                    "terminal_seq",
                    "capture_sha256",
                ),
            )
            client_proof = mapping(
                proof["client"],
                "fitness:refusal_client_response",
                (
                    "gateway_request_id",
                    "client_status",
                    "client_code",
                    "start_ns",
                    "end_ns",
                    "body_sha256",
                ),
            )
            redis_proof = mapping(
                proof["redis"],
                "fitness:refusal_absence_unproven",
                ("reservation_id", "first_order", "last_order"),
            )
            if (
                proof["request_id"] != offers[name, gateway]
                or not isinstance(gateway_proof["gateway_request_id"], str)
                or gateway_proof["gateway_request_id"] != client_proof["gateway_request_id"]
                or not isinstance(gateway_proof["reservation_id"], str)
                or gateway_proof["reservation_id"] != redis_proof["reservation_id"]
                or proof["request_id"] != offers[name, gateway]
                or type(gateway_proof["deny_seq"]) is not int
                or type(gateway_proof["terminal_seq"]) is not int
                or gateway_proof["deny_seq"] >= gateway_proof["terminal_seq"]
                or type(redis_proof["first_order"]) is not int
                or type(redis_proof["last_order"]) is not int
                or redis_proof["first_order"] > redis_proof["last_order"]
                or client_proof["client_status"] != 503
                or client_proof["client_code"] != "discovery_unknown"
                or type(client_proof["start_ns"]) is not int
                or type(client_proof["end_ns"]) is not int
                or client_proof["start_ns"] > client_proof["end_ns"]
            ):
                raise IntegrityError("fitness:refusal_absence_unproven")
            digest(gateway_proof["capture_sha256"], "fitness:refusal_capture_binding")
            digest(client_proof["body_sha256"], "fitness:refusal_capture_binding")
            digest(proof["evidence_sha256"], "fitness:refusal_capture_binding")
            if gateway_proof["capture_sha256"] != sha(gateway_prefixes[gateway]):
                raise IntegrityError("fitness:refusal_capture_binding")
            if (
                proof["evidence_sha256"]
                != hashlib.sha256(
                    encode(
                        {
                            "gateway": proof["gateway"],
                            "client": proof["client"],
                            "redis": proof["redis"],
                        }
                    )
                ).hexdigest()
            ):
                raise IntegrityError("fitness:refusal_capture_binding")
            if gateway_proof["reservation_id"] not in all_gateway_ids:
                raise IntegrityError("fitness:unexplained_reservations")
            control_reservation_ids.append(gateway_proof["reservation_id"])
            actual_id = gateway_proof["gateway_request_id"]
            raw_records = raw_gateway_records[gateway]
            raw_admits = [
                record
                for record in raw_records
                if record.get("event") == "admit"
                and record.get("data", {}).get("request_id") == actual_id
            ]
            raw_denials = [
                record
                for record in raw_records
                if record.get("event") == "deny"
                and record.get("data", {}).get("request_id") == actual_id
                and record.get("data", {}).get("denial_code") == "discovery_unknown"
            ]
            if any(
                "reservation_id" in record.get("data", {})
                and record["data"].get("reservation_id") != gateway_proof["reservation_id"]
                for record in raw_denials
            ):
                raise IntegrityError("fitness:refusal_absence_unproven")
            raw_terminals = [
                record
                for record in raw_records
                if record.get("event") == "terminal"
                and record.get("data", {}).get("request_id") == actual_id
                and record.get("data", {}).get("reservation_id") == gateway_proof["reservation_id"]
                and record.get("data", {}).get("code") == "discovery_unknown"
                and record.get("data", {}).get("outcome") == "rejected"
            ]
            cohort = cohort_by_id.get(proof["request_id"])
            normalized_denials = [
                row
                for row in rows
                if row.get("source_kind") == "gateway"
                and row.get("source_identity") == gateway
                and row.get("error") is None
                and row.get("payload", {}).get("event") == "deny"
                and row.get("payload", {}).get("request_id") == proof["request_id"]
            ]
            normalized_admits = [
                row
                for row in rows
                if row.get("source_kind") == "gateway"
                and row.get("source_identity") == gateway
                and row.get("error") is None
                and row.get("payload", {}).get("event") == "admit"
                and row.get("payload", {}).get("request_id") == proof["request_id"]
            ]
            if (
                raw_admits
                or len(raw_denials) != 1
                or len(raw_terminals) != 1
                or raw_denials[0]["sequence"] >= raw_terminals[0]["sequence"]
                or not isinstance(cohort, dict)
                or cohort.get("gateway_uid") != gateway
                or cohort.get("outcome") != "rejected"
                or cohort.get("http_status") != 503
                or cohort.get("denial_code") != "discovery_unknown"
                or len(normalized_denials) != 1
                or normalized_denials[0]["payload"].get("denial_code") != "discovery_unknown"
                or normalized_denials[0]["payload"].get("admit_called") is not False
                or normalized_admits
            ):
                raise IntegrityError("fitness:refusal_absence_unproven")

    receipts = evidence.get("diagnostics")
    diagnostics = mapping(receipts, "fitness:diagnostic_control_inventory", ROW5_ALL_CONTROLS)
    diagnostic_ids = []
    expected_diagnostic = {
        **{
            name: (n, decision, capacity)
            for name, (n, decision, capacity) in ROW5_KNOWN_CONTROLS.items()
        },
        "unknown": (2, "allowed", 10),
        "expired": (2, "capacity_reports_expired", 10),
    }
    for name, (n, decision, capacity) in expected_diagnostic.items():
        proof = mapping(
            diagnostics[name],
            "fitness:diagnostic_control_proof",
            (
                "reservation_id",
                "decision",
                "effective_n",
                "effective_b",
                "receipt_sha256",
                "configuration_sha256",
            ),
        )
        if (
            not isinstance(proof["reservation_id"], str)
            or re.fullmatch(r"rsv_d1a6[0-9a-f]{28}", proof["reservation_id"]) is None
            or proof["decision"] != decision
            or type(proof["effective_n"]) is not int
            or proof["effective_n"] != n
            or type(proof["effective_b"]) is not int
            or proof["effective_b"] != capacity
            or proof["configuration_sha256"] != resolved_config_sha256
        ):
            raise IntegrityError("fitness:diagnostic_control_proof")
        digest(proof["receipt_sha256"], "fitness:diagnostic_control_proof")
        diagnostic_ids.append(proof["reservation_id"])
    if len(set(control_reservation_ids)) != len(control_reservation_ids):
        raise IntegrityError("fitness:control_reservation_reused")
    check_reservation_partition(
        all_gateway_ids,
        [{"reservation_id": rid} for rid in diagnostic_ids],
        control_ids=control_reservation_ids,
    )
    if any(rid in {item["request_id"] for item in control_offers} for rid in diagnostic_ids):
        raise IntegrityError("fitness:diagnostic_row_as_gateway_ack")

    last_stores = mapping(
        evidence.get("last_known_stores_ms"),
        "fitness:expired_snapshot_inputs",
        ("gateway0", "gateway1"),
    )
    if any(type(v) is not int or v < 0 for v in last_stores.values()):
        raise IntegrityError("fitness:expired_snapshot_inputs")
    latency = evidence.get("expired_snapshot_latency_ms")
    if type(latency) is not int or latency < 0:
        raise IntegrityError("fitness:expired_snapshot_inputs")
    unknown_reports = snapshots["unknown"]["payload"]["reports"]
    if any(
        unknown_reports[gateway]["stored_ms"] != last_stores[gateway]
        or unknown_reports[gateway]["expires_ms"] != last_stores[gateway] + 8000
        for gateway in ("gateway0", "gateway1")
    ):
        raise IntegrityError("fitness:expired_snapshot_inputs")
    expired_snapshot = snapshots["expired"]
    capture_duration_ms = (
        expired_snapshot["capture_end_mono_ns"]
        - expired_snapshot["capture_start_mono_ns"]
        + 999_999
    ) // 1_000_000
    if capture_duration_ms > latency:
        raise IntegrityError("fitness:expired_snapshot_window")
    start, end = expired_window(list(last_stores.values()), 8000, 2000, latency)
    expired_at = snapshots["expired"]["payload"].get("redis_time_ms")
    if type(expired_at) is not int or not start <= expired_at < end:
        raise IntegrityError("fitness:expired_snapshot_window")
    if evidence.get("expired_window_ms") != [start, end]:
        raise IntegrityError("fitness:expired_snapshot_window")

    role = mapping(
        evidence.get("rbac"),
        "fitness:rbac_evidence",
        ("reviewed_sha256", "actions", "reviews", "envelope_start_ns", "envelope_deadline_ns"),
    )
    digest(role["reviewed_sha256"], "fitness:rbac_evidence")
    if (
        type(role["envelope_start_ns"]) is not int
        or type(role["envelope_deadline_ns"]) is not int
        or not 0 < role["envelope_deadline_ns"] - role["envelope_start_ns"] <= 30_000_000_000
        or not isinstance(role["actions"], list)
        or [a.get("phase") for a in role["actions"] if isinstance(a, dict)] != ["revoke", "restore"]
        or not isinstance(role["reviews"], list)
    ):
        raise IntegrityError("fitness:rbac_evidence")
    revoke, restore = role["actions"]
    if (
        revoke.get("uid") != restore.get("uid")
        or revoke.get("precondition_resource_version") == revoke.get("readback_resource_version")
        or restore.get("precondition_resource_version") == restore.get("readback_resource_version")
        or not restore.get("restored_matches_reviewed_sha256")
        or restore.get("canonical_projection_sha256") != role["reviewed_sha256"]
    ):
        raise IntegrityError("fitness:rbac_readback_hash")
    for phase, expected_list in (("revoke", False), ("restore", True)):
        phase_reviews = [
            r for r in role["reviews"] if isinstance(r, dict) and r.get("phase") == phase
        ]
        # The reviewed endpoint-reader Role grants list only. The effective
        # watch permission must remain false during revoke and restoration.
        for verb, expected in (("list", expected_list), ("watch", False)):
            matching = [
                r for r in phase_reviews if r.get("verb") == verb and r.get("allowed") is expected
            ]
            if not matching:
                raise IntegrityError("fitness:rbac_" + phase + "_reviews")
        if (
            phase_reviews
            and max(r["end_ns"] for r in phase_reviews) - min(r["start_ns"] for r in phase_reviews)
            > 5_000_000_000
        ):
            raise IntegrityError("fitness:rbac_review_bound")
        if any(
            type(r.get("start_ns")) is not int
            or type(r.get("end_ns")) is not int
            or not role["envelope_start_ns"]
            <= r["start_ns"]
            <= r["end_ns"]
            <= role["envelope_deadline_ns"]
            for r in phase_reviews
        ):
            raise IntegrityError("fitness:rbac_evidence")
    initial_reviews = [
        r for r in role["reviews"] if isinstance(r, dict) and r.get("phase") == "initial"
    ]
    if not any(
        r.get("verb") == "list" and r.get("allowed") is True for r in initial_reviews
    ) or not any(r.get("verb") == "watch" and r.get("allowed") is False for r in initial_reviews):
        raise IntegrityError("fitness:rbac_initial_reviews")

    recovery = mapping(
        evidence.get("recovery"),
        "fitness:recovery_evidence",
        ("observations", "source_complete", "evidence_sha256"),
    )
    digest(recovery["evidence_sha256"], "fitness:recovery_evidence")
    if recovery["source_complete"] is not True or not isinstance(recovery["observations"], list):
        raise IntegrityError("fitness:recovery_source_incomplete")
    observer = RecoveryAgreement(role["envelope_deadline_ns"] // 1_000_000)
    completed = False
    for observation in recovery["observations"]:
        plain_keys = {"time_ms", "known", "reason", "n", "effective_b"}
        source_keys = plain_keys | {
            "gateway_uid",
            "poll_seq",
            "read_mono_ns",
            "time_clock",
            "source_event_ns",
        }
        if not isinstance(observation, dict):
            raise IntegrityError("fitness:recovery_source_incomplete")
        observation_keys = set(observation)
        if observation_keys == plain_keys:
            sample_keys = plain_keys
        elif observation_keys == source_keys:
            sample_keys = source_keys
        else:
            raise IntegrityError("fitness:recovery_source_incomplete")
        sample = mapping(
            observation,
            "fitness:recovery_source_incomplete",
            sample_keys,
        )
        if sample_keys == source_keys:
            from .inf037b_row5_sequence import GATEWAYS

            if (
                sample["time_clock"] != "collector_monotonic"
                or type(sample["read_mono_ns"]) is not int
                or type(sample["time_ms"]) is not int
                or sample["time_ms"] != sample["read_mono_ns"] // 1_000_000
                or sample["gateway_uid"] not in GATEWAYS
                or type(sample["poll_seq"]) is not int
                or type(sample["source_event_ns"]) is not int
            ):
                raise IntegrityError("fitness:recovery_source_incomplete")
        known = sample["known"] is True and sample["n"] == 2 and sample["effective_b"] == 10
        if sample["known"] not in (True, False):
            raise IntegrityError("fitness:recovery_source_incomplete")
        if not sample["known"] and sample["reason"] not in ("unknown", "403"):
            raise IntegrityError("fitness:recovery_source_incomplete")
        completed = observer.observe(
            sample["time_ms"], known=known, reason=None if known else sample["reason"]
        )
    if not completed or not observer.restarts == [
        r.get("time_ms") for r in recovery["observations"] if r.get("known") is False
    ]:
        raise IntegrityError("fitness:recovery_agreement")
    return {
        "controls": {
            "known2": 10,
            "known1": 5,
            "known0": 0,
            "expired": "refuse",
            "unknown": "refuse",
        },
        "gateway_controls": controls,
        "diagnostic_controls": {
            name: {
                key: diagnostics[name][key]
                for key in ("reservation_id", "decision", "effective_n", "effective_b")
            }
            for name in ROW5_ALL_CONTROLS
        },
        "expired_window_ms": [start, end],
        "recovery_restarts_ms": list(observer.restarts),
        "rbac_reviews": len(role["reviews"]),
    }


def _projected_annotations(metadata):
    """Keep reviewed annotations, excluding only kubectl's applied-object snapshot."""
    annotations = metadata.get("annotations", {})
    if not isinstance(annotations, dict):
        return annotations
    return {
        key: value
        for key, value in annotations.items()
        if key != "kubectl.kubernetes.io/last-applied-configuration"
    }


def canonical_role(role):
    """Project only explicitly reviewed RBAC fields, omitting server-owned metadata."""
    from .inf037b_archive import encode

    meta = role["metadata"]
    owner_references = meta.get("ownerReferences")
    finalizers = meta.get("finalizers")
    rules = role.get("rules")
    return encode(
        {
            "apiVersion": role["apiVersion"],
            "kind": role["kind"],
            "metadata": {
                "name": meta["name"],
                "namespace": meta["namespace"],
                "labels": meta.get("labels", {}),
                "annotations": _projected_annotations(meta),
                "ownerReferences": [] if owner_references is None else owner_references,
                "finalizers": [] if finalizers is None else finalizers,
            },
            "rules": [] if rules is None else rules,
        }
    )


def canonical_binding(binding):
    """Project reviewed binding fields independently of server-managed metadata."""
    from .inf037b_archive import encode

    meta = binding["metadata"]
    return encode(
        {
            "apiVersion": binding["apiVersion"],
            "kind": binding["kind"],
            "metadata": {
                "name": meta["name"],
                "namespace": meta["namespace"],
                "labels": meta.get("labels", {}),
                "annotations": _projected_annotations(meta),
                "ownerReferences": meta.get("ownerReferences", []),
                "finalizers": meta.get("finalizers", []),
            },
            "roleRef": binding["roleRef"],
            "subjects": binding["subjects"],
        }
    )


class RoleControl:
    """A source-bound RBAC control over an authenticated, bounded Kubernetes port.

    The port provides read_role, read_binding, replace_role and access_review.
    replace_role must send metadata.resourceVersion unchanged in a Kubernetes PUT;
    access_review must test the gateway service account, including other grants.
    The deployment's required row5_control callback builds this actuator from
    its authenticated RBAC port and runs it in the bounded GPU branch.
    """

    def __init__(
        self,
        port,
        namespace,
        reviewed_role,
        reviewed_binding,
        expected_sha256,
        *,
        clock=None,
        sleep=None,
    ):
        import copy
        import hashlib
        import time

        self.clock, self.sleep = clock or time.monotonic_ns, sleep or time.sleep
        self.reviews = []
        self.port, self.namespace = port, namespace
        self.original, self.binding = copy.deepcopy(reviewed_role), copy.deepcopy(reviewed_binding)
        projection = canonical_role(self.original)
        if hashlib.sha256(projection).hexdigest() != expected_sha256:
            raise IntegrityError("fitness:rbac_review_hash")
        if (
            self.original.get("apiVersion") != "rbac.authorization.k8s.io/v1"
            or self.original.get("kind") != "Role"
            or self.original["metadata"].get("name") != "endpoint-reader"
            or self.original["metadata"].get("namespace") != namespace
            or self.original.get("rules")
            != [
                {
                    "apiGroups": ["discovery.k8s.io"],
                    "resources": ["endpointslices"],
                    "verbs": ["list"],
                }
            ]
        ):
            raise IntegrityError("fitness:rbac_review_role")
        if (
            self.binding.get("apiVersion") != "rbac.authorization.k8s.io/v1"
            or self.binding.get("kind") != "RoleBinding"
            or self.binding.get("metadata", {}).get("name") != "gateway-endpoints"
            or self.binding.get("metadata", {}).get("namespace") != namespace
            or self.binding.get("roleRef")
            != {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "endpoint-reader"}
            or self.binding.get("subjects")
            != [{"kind": "ServiceAccount", "name": "gateway", "namespace": namespace}]
        ):
            raise IntegrityError("fitness:rbac_review_binding")
        self.binding_projection = canonical_binding(self.binding)
        self.binding_uid = None
        self.original_projection = projection
        self.revoked_projection = None
        self.uid = None
        self.original_watch = None
        self.actuations = []
        self.revoke_replaced = False
        self.restore_replaced = False

    def verify_binding(self):
        binding = self.port.read_binding(self.namespace)
        uid = binding.get("metadata", {}).get("uid")
        if (
            not uid
            or (self.binding_uid is not None and uid != self.binding_uid)
            or canonical_binding(binding) != self.binding_projection
        ):
            raise IntegrityError("fitness:rbac_binding")
        self.binding_uid = uid

    def access(self, verb, *, deadline_ns=None, phase="initial"):
        started = self.clock()
        try:
            if deadline_ns is None:
                value = self.port.access_review(self.namespace, "gateway", verb)
            else:
                value = self.port.access_review(
                    self.namespace, "gateway", verb, deadline_ns=deadline_ns
                )
            if type(value) is not bool:
                raise IntegrityError("fitness:rbac_access_indeterminate")
        except Exception as exc:
            self.reviews.append(
                {
                    "phase": phase,
                    "verb": verb,
                    "start_ns": started,
                    "end_ns": self.clock(),
                    "error_class": type(exc).__name__,
                }
            )
            raise
        self.reviews.append(
            {
                "phase": phase,
                "verb": verb,
                "start_ns": started,
                "end_ns": self.clock(),
                "allowed": value,
            }
        )
        return value

    def review_until(self, expected_list, expected_watch, *, deadline_ns, phase):
        """Poll both effective permissions within a fixed 5 s sub-bound."""
        reason = "fitness:rbac_" + phase + "_access"
        while self.clock() < deadline_ns:
            try:
                allowed_list = self.access("list", deadline_ns=deadline_ns, phase=phase)
                if self.clock() >= deadline_ns:
                    break
                allowed_watch = self.access("watch", deadline_ns=deadline_ns, phase=phase)
                if self.clock() > deadline_ns:
                    break
                if allowed_list == expected_list and allowed_watch == expected_watch:
                    return
            except IntegrityError as exc:
                # Capture failures are terminal: no successful result may hide lost evidence.
                if str(exc) not in (
                    "fitness:rbac_access_indeterminate",
                    "fitness:rbac_transport_deadline",
                ):
                    raise
            except (OSError, ValueError):
                # A transient or malformed review is retained, never a grant.
                pass
            remaining = deadline_ns - self.clock()
            if remaining > 0:
                self.sleep(min(0.1, remaining / 1_000_000_000))
        raise IntegrityError(reason)

    def subdeadline(self, envelope_deadline_ns):
        now = self.clock()
        if type(envelope_deadline_ns) is not int or envelope_deadline_ns <= now:
            raise IntegrityError("fitness:rbac_envelope_deadline")
        return min(envelope_deadline_ns, now + RBAC_REVIEW_TIMEOUT_S * 1_000_000_000)

    def revoke(self, *, envelope_deadline_ns):
        import copy

        self.subdeadline(envelope_deadline_ns)
        self.verify_binding()
        role = self.port.read_role(self.namespace)
        meta = role["metadata"]
        if (
            canonical_role(role) != self.original_projection
            or not meta.get("uid")
            or not meta.get("resourceVersion")
        ):
            raise IntegrityError("fitness:rbac_initial_readback")
        self.uid = meta["uid"]
        if not self.access("list", phase="initial"):
            raise IntegrityError("fitness:rbac_initial_access")
        self.original_watch = self.access("watch", phase="initial")
        if self.original_watch:
            # The reviewed Role grants list only. An additional grant that
            # makes watch effective means this is not the registered fixture.
            raise IntegrityError("fitness:rbac_initial_access")
        changed = copy.deepcopy(role)
        changed["rules"] = []
        self.revoked_projection = canonical_role(changed)
        precondition = meta["resourceVersion"]
        self.port.replace_role(self.namespace, changed)
        self.revoke_replaced = True
        review_deadline_ns = self.subdeadline(envelope_deadline_ns)
        observed = self.port.read_role(self.namespace)
        readback_version = observed.get("metadata", {}).get("resourceVersion")
        if (
            observed["metadata"].get("uid") != self.uid
            or canonical_role(observed) != self.revoked_projection
        ):
            raise IntegrityError("fitness:rbac_revoke_readback")
        if not isinstance(readback_version, str) or readback_version == precondition:
            raise IntegrityError("fitness:rbac_revoke_resource_version")
        import hashlib

        self.actuations.append(
            {
                "phase": "revoke",
                "uid": self.uid,
                "precondition_resource_version": precondition,
                "readback_resource_version": readback_version,
                "canonical_projection_sha256": hashlib.sha256(self.revoked_projection).hexdigest(),
            }
        )
        self.verify_binding()
        self.review_until(False, False, deadline_ns=review_deadline_ns, phase="revoke")

    def restore(self, *, envelope_deadline_ns):
        import copy

        if self.uid is None or self.revoked_projection is None:
            raise IntegrityError("fitness:rbac_no_revoke")
        self.subdeadline(envelope_deadline_ns)
        self.verify_binding()
        current = self.port.read_role(self.namespace)
        meta = current["metadata"]
        if (
            meta.get("uid") != self.uid
            or not meta.get("resourceVersion")
            or canonical_role(current) != self.revoked_projection
        ):
            raise IntegrityError("fitness:rbac_restore_precondition")
        replacement = copy.deepcopy(self.original)
        precondition = meta["resourceVersion"]
        replacement["metadata"]["resourceVersion"] = precondition
        self.port.replace_role(self.namespace, replacement)
        self.restore_replaced = True
        review_deadline_ns = self.subdeadline(envelope_deadline_ns)
        observed = self.port.read_role(self.namespace)
        readback_version = observed.get("metadata", {}).get("resourceVersion")
        if (
            observed["metadata"].get("uid") != self.uid
            or canonical_role(observed) != self.original_projection
        ):
            raise IntegrityError("fitness:rbac_restore_readback")
        if not isinstance(readback_version, str) or readback_version == precondition:
            raise IntegrityError("fitness:rbac_restore_resource_version")
        import hashlib

        restored_projection = canonical_role(observed)
        self.actuations.append(
            {
                "phase": "restore",
                "uid": self.uid,
                "precondition_resource_version": precondition,
                "readback_resource_version": readback_version,
                "canonical_projection_sha256": hashlib.sha256(restored_projection).hexdigest(),
                "restored_matches_reviewed_sha256": hashlib.sha256(restored_projection).hexdigest()
                == hashlib.sha256(self.original_projection).hexdigest(),
            }
        )
        self.verify_binding()
        self.review_until(
            True, self.original_watch, deadline_ns=review_deadline_ns, phase="restore"
        )


class KubernetesRolePort:
    """Kubernetes RBAC API operations over a bounded JSON transport."""

    def __init__(self, http):
        self.http = http

    @staticmethod
    def _prefix(namespace):
        import re

        if not isinstance(namespace, str) or not re.fullmatch(
            r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", namespace
        ):
            raise IntegrityError("fitness:rbac_namespace")
        return "/apis/rbac.authorization.k8s.io/v1/namespaces/" + namespace

    def read_role(self, namespace):
        return self.http.json_request("GET", self._prefix(namespace) + "/roles/endpoint-reader")

    def read_binding(self, namespace):
        return self.http.json_request(
            "GET", self._prefix(namespace) + "/rolebindings/gateway-endpoints"
        )

    def replace_role(self, namespace, role):
        return self.http.json_request(
            "PUT", self._prefix(namespace) + "/roles/endpoint-reader", role
        )

    def access_review(self, namespace, service_account, verb, *, deadline_ns=None):
        if service_account != "gateway" or verb not in ("list", "watch"):
            raise IntegrityError("fitness:rbac_review_request")
        self._prefix(namespace)
        kwargs = {"deadline_ns": deadline_ns} if deadline_ns is not None else {}
        result = self.http.json_request(
            "POST",
            "/apis/authorization.k8s.io/v1/subjectaccessreviews",
            {
                "apiVersion": "authorization.k8s.io/v1",
                "kind": "SubjectAccessReview",
                "spec": {
                    "user": f"system:serviceaccount:{namespace}:gateway",
                    "groups": [
                        "system:serviceaccounts",
                        f"system:serviceaccounts:{namespace}",
                        "system:authenticated",
                    ],
                    "resourceAttributes": {
                        "namespace": namespace,
                        "group": "discovery.k8s.io",
                        "resource": "endpointslices",
                        "verb": verb,
                    },
                },
            },
            **kwargs,
        )
        status = result.get("status", {})
        if status.get("evaluationError") or type(status.get("allowed")) is not bool:
            raise IntegrityError("fitness:rbac_access_indeterminate")
        return status["allowed"]


class BoundedRBACHTTP:
    """Bounded TLS JSON transport retaining the RBAC request and response bytes."""

    def __init__(self, base, *, token, deadline_ns, retain, ca=None, local_test=False):
        import ssl
        import urllib.parse

        url = urllib.parse.urlsplit(base)
        if (
            (
                url.scheme != "https"
                and not (
                    local_test
                    and url.scheme == "http"
                    and url.hostname in ("127.0.0.1", "localhost")
                )
            )
            or url.path not in ("", "/")
            or url.query
            or url.fragment
            or url.username
            or url.password
        ):
            raise IntegrityError("fitness:rbac_transport_endpoint")
        self.url, self.token, self.deadline_ns, self.retain = url, token, deadline_ns, retain
        self.context = ssl.create_default_context(cafile=ca)
        self.ca, self.local_test = ca, local_test
        self.barrier = getattr(retain, "barrier", lambda: None)

    def lines(self, path):
        # Reuse the existing bounded streaming reader; no second API client.
        from .inf037b_capture import DeadlineHTTP

        self.stream = DeadlineHTTP(
            self.url.geturl(),
            stop_ns=self.deadline_ns,
            retain=self.retain,
            token=self.token,
            ca=self.ca,
            local_test=self.local_test,
        )
        try:
            yield from self.stream.lines(path)
        finally:
            self.watch_bytes = getattr(self.stream, "watch_bytes", 0)

    def cutoff(self):
        self.stream.cutoff()

    def json_request(self, method, path, body=None, *, deadline_ns=None):
        import http.client
        import time

        from .inf037b_archive import strict_json
        from .inf037b_bounded import bounded_json

        if (
            method not in ("GET", "PUT", "POST", "DELETE")
            or not path.startswith("/")
            or path.startswith("//")
        ):
            raise IntegrityError("fitness:rbac_transport_request")
        if deadline_ns is not None and type(deadline_ns) is not int:
            raise IntegrityError("fitness:rbac_transport_deadline")
        stop_ns = self.deadline_ns if deadline_ns is None else min(self.deadline_ns, deadline_ns)
        remaining = (stop_ns - time.monotonic_ns()) / 1e9
        if remaining <= 0:
            raise IntegrityError("fitness:rbac_transport_deadline")
        payload = (
            bounded_json(
                body,
                limit=min(
                    8_388_608, getattr(self.retain, "remaining_raw_bytes", lambda: 8_388_608)()
                ),
                loss=getattr(self.retain, "loss", lambda reason: None),
            )
            if body is not None
            else None
        )
        connection_class = (
            http.client.HTTPSConnection
            if self.url.scheme == "https"
            else http.client.HTTPConnection
        )
        kwargs = {"context": self.context} if self.url.scheme == "https" else {}
        from .inf037b_producer_contracts import guarded_response

        connection = connection_class(
            self.url.hostname, self.url.port, timeout=min(1, remaining), **kwargs
        )
        connection.response_class = guarded_response(self.retain, time.monotonic_ns, client=False)
        from .inf037b_wire_units import UnitReads

        retain = UnitReads(self.retain, mode="body")
        start = time.monotonic_ns()
        try:
            headers = {
                "Authorization": "Bearer " + self.token(),
                "Content-Type": "application/json",
            }
            retain(
                start,
                start,
                payload or b"",
                {"method": method, "path": path, "direction": "request"},
            )
            connection.request(method, path, body=payload, headers=headers)
            sock = connection.sock
            response = connection.getresponse()
            headers_ns = time.monotonic_ns()
            retain(
                start,
                headers_ns,
                b"",
                {
                    "method": method,
                    "path": path,
                    "status": response.status,
                    "headers": list(response.getheaders()),
                    "direction": "response_headers",
                },
            )
            if headers_ns > stop_ns:
                raise IntegrityError("fitness:rbac_transport_deadline")
            chunks = []
            total = 0
            while True:
                if response.isclosed():
                    break
                remaining = (stop_ns - time.monotonic_ns()) / 1e9
                if remaining <= 0:
                    raise IntegrityError("fitness:rbac_transport_deadline")
                sock.settimeout(min(1, remaining))
                before = time.monotonic_ns()
                chunk = response.read1(min(65536, 8_388_609 - total))
                after = time.monotonic_ns()
                retain(
                    before,
                    after,
                    chunk,
                    {
                        "method": method,
                        "path": path,
                        "status": response.status,
                        "direction": "response",
                    },
                )
                total += len(chunk)
                if total > 8_388_608:
                    raise IntegrityError("fitness:rbac_transport_size")
                if after > stop_ns:
                    raise IntegrityError("fitness:rbac_transport_deadline")
                if not chunk:
                    break
                chunks.append(chunk)
            if response.status < 200 or response.status >= 300 or response.length not in (None, 0):
                raise IntegrityError("fitness:rbac_transport_response")
            retain.finish("body")
            self.barrier()
            value = strict_json(b"".join(chunks))
            from .inf037b_producer_contracts import validate_kube_identities
            from .inf037b_producer_limits import refuse

            validate_kube_identities(
                value,
                lambda reason: refuse(retain, reason, start, time.monotonic_ns()),
            )
            return value
        except Exception as exc:
            retain(
                start,
                time.monotonic_ns(),
                b"",
                {"method": method, "path": path, "review_error_class": type(exc).__name__},
            )
            raise
        finally:
            retain.finish("close")
            connection.close()
            self.barrier()
