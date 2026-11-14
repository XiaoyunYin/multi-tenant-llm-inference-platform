"""Offline replay-to-cohort/event producer and durable attempt bridge (v3).

report() never allocates attempts or changes the journal. The explicit finish
method persists source-derived validity/usable facts through the 4a controller.
"""

import json
import math
from pathlib import Path

from .inf037b_archive import (
    Archive,
    IntegrityError,
    durable_write,
    encode,
    envelope,
    inspect_segment,
    record_key,
    sha,
    verify_archive,
)
from .inf037b_attempts import AttemptController, Refused
from .inf037b_contract import (
    ATTEMPT_MS,
    GATEWAYS,
    REGISTRATION_GIT_BLOB_SHA256,
    REGISTRATION_ID,
    TARGET_ORDER,
    nonnegative,
)
from .inf037b_coverage import registered_coverage
from .inf037b_export_runtime import (
    batched_durability,
    export_memoization,
    fresh_result,
    inventory,
)
from .inf037b_packet import REQUIRED_PINS, PacketReadiness, workload_trace
from .inf037b_recovery import RecoveryJoin
from .inf037b_requests import RequestJoin
from .inf037b_sources import SourceJoin, carries_observation


def registered_offers(attempt, traffic_start_ms, capture_end_ms, config_sha256):
    """Exact registered trace projected onto durable traffic time, including drain."""
    offers = []
    for phase, base, maximum in (
        ("pre", traffic_start_ms, 600_000),
        ("event", traffic_start_ms + 600_000, 960_000),
    ):
        duration = min(maximum, capture_end_ms - base)
        if duration <= 0:
            continue
        for row in workload_trace(phase, attempt, duration):
            offers.append(
                {
                    **{
                        k: row[k]
                        for k in ("request_id", "offer_index", "prefix_id", "gateway_uid", "phase")
                    },
                    "config_sha256": config_sha256,
                    "scheduled_ms": base
                    + row["scheduled_ms_numerator"] // row["scheduled_ms_denominator"],
                }
            )
    return offers


class OfflineCampaign:
    def __init__(self, root: Path, spec: dict):
        self.root, self.spec = root, spec
        self.journal = AttemptController(root / "attempts.jsonl")

    def record_capture_window(self, start_ms: int, end_ms: int):
        """Persist actual capture bounds before reporting/sealing, after raw closure."""
        attempt = self.spec["attempt_index"]
        nonnegative(start_ms, "capture_start_ms")
        nonnegative(end_ms, "capture_end_ms")
        current = self.journal._open_attempt()
        if current is None or current["attempt"] != attempt:
            raise IntegrityError("capture_window_requires_open_attempt")
        if start_ms > end_ms or any(
            e["event"] == "capture_window" and e["attempt"] == attempt for e in self.journal.events
        ):
            raise IntegrityError("invalid_or_duplicate_capture_window")
        self.journal._write(
            "capture_window",
            end_ms,
            attempt=attempt,
            capture_start_ms=start_ms,
            capture_end_ms=end_ms,
        )

    def _durable_spec(self, errors):
        spec, attempt = self.spec, self.spec["attempt_index"]
        events = [e for e in self.journal.events if e.get("attempt") == attempt]
        facts = {}
        for event, fields in (
            ("attempt_start", {"target_slot": "target_slot"}),
            ("traffic_start", {"traffic_start_ms": "now_ms"}),
            (
                "capture_window",
                {"capture_start_ms": "capture_start_ms", "capture_end_ms": "capture_end_ms"},
            ),
        ):
            matches = [e for e in events if e["event"] == event]
            if len(matches) == 1:
                facts.update({name: matches[0][field] for name, field in fields.items()})
            elif event == "capture_window":
                errors.append("missing_or_duplicate_durable_capture_window")
        if "traffic_start_ms" in facts:
            facts["pre_end_ms"] = facts["traffic_start_ms"] + 600000
        for name, value in facts.items():
            if (
                spec.get(name, 0 if name in ("traffic_start_ms", "capture_start_ms") else None)
                != value
            ):
                raise IntegrityError("durable_spec_mismatch:" + name)
        return facts

    @staticmethod
    def _archive_errors(raw, receipts):
        """Tails affect all attempts; cross-attempt conflicts affect their owners.

        A setup owner affects all attempts. Same-attempt conflicts remain ordinary
        SourceJoin errors. Later-attempt local errors never contaminate an earlier one.
        """
        errors, seen = [], {}
        for name, receipt in receipts.items():
            for error in receipt["integrity_errors"]:
                if error["reason"] == "truncated_jsonl":
                    errors.append(
                        {
                            **error,
                            "segment": name,
                            "affects_attempts": "all",
                            "attribution_rule": "unattributed_torn_tail_affects_all_attempts",
                        }
                    )
        for row in raw:
            key = record_key(row)
            previous = seen.setdefault(key, row)
            if previous != row and previous["attempt_id"] != row["attempt_id"]:
                owners = {previous["attempt_id"], row["attempt_id"]}
                errors.append(
                    {
                        "reason": "cross_attempt_conflicting_duplicate",
                        "record_key": list(key),
                        "owners": sorted(owners, key=str),
                        "affects_attempts": "all" if "setup" in owners else sorted(owners),
                        "attribution_rule": "conflict_affects_owners_setup_affects_all",
                    }
                )
        streams = {}
        for row in raw:
            key = (row["source_kind"], row["source_identity"], row["source_generation"])
            streams.setdefault(key, {}).setdefault(row["source_seq"], []).append(row)
        for key, sequence in sorted(streams.items()):
            for number, occurrences in sorted(sequence.items()):
                keys = {record_key(row) for row in occurrences}
                if len(keys) <= 1:
                    continue
                # Exact retries share a key; distinct keys cannot share a sequence.
                # The old local sequence check rejected this case too.
                owners = {row["attempt_id"] for row in occurrences}
                errors.append(
                    {
                        "reason": "source_sequence_collision",
                        "stream": list(key),
                        "source_seq": number,
                        "record_keys": [list(record) for record in sorted(keys)],
                        "owners": sorted(owners, key=str),
                        "affects_attempts": "all" if "setup" in owners else sorted(owners),
                        "attribution_rule": "sequence_collision_affects_owners_setup_affects_all",
                    }
                )
            ordered = sorted(sequence)
            for a, b in zip(ordered, ordered[1:], strict=False):
                if b == a + 1:
                    continue
                owners = {r["attempt_id"] for seq in (a, b) for r in sequence[seq]}
                errors.append(
                    {
                        "reason": "source_sequence_gap",
                        "stream": list(key),
                        "sequence_bounds": [a, b],
                        "missing_sequence_range": [a + 1, b - 1],
                        "owners": sorted(owners, key=str),
                        "affects_attempts": "all" if "setup" in owners else sorted(owners),
                        "attribution_rule": "gap_affects_both_neighbour_owners_setup_affects_all",
                        "neighbours": [
                            {
                                "record_id": r["record_id"],
                                "source_seq": r["source_seq"],
                                "attempt_id": r["attempt_id"],
                            }
                            for seq in (a, b)
                            for r in sequence[seq]
                        ],
                    }
                )
        return errors

    def _raw(self, *, attempt=None):
        rows, receipts, integrity_rows = [], {}, []
        for path in sorted((self.root / "raw").glob("*.jsonl")):
            name = path.relative_to(self.root).as_posix()
            receipt, records = inspect_segment(path, source_errors=True, segment_name=name)
            receipts[name] = receipt
            if attempt is None:
                rows.extend(records)
            else:
                # Preserve archive-wide ownership/conflict checks without keeping
                # other attempts' payload trees in the join's working set.
                for row in records:
                    integrity_rows.append(
                        {
                            **{
                                k: row[k]
                                for k in (
                                    "source_kind",
                                    "source_identity",
                                    "source_generation",
                                    "record_id",
                                    "source_seq",
                                    "attempt_id",
                                )
                            },
                            "row_sha256": sha(encode(row)),
                        }
                    )
                    if row["attempt_id"] in (attempt, "setup"):
                        rows.append(row)
        return (rows, receipts) if attempt is None else (rows, receipts, integrity_rows)

    def report(self):
        def produce():
            # Reopen the journal too: an existing instance must not replay a
            # constructor-time journal after its freshly hashed bytes changed.
            self.journal = AttemptController(self.root / "attempts.jsonl")
            return self._report(), self.archive_derived_reasons

        value, reasons = fresh_result(
            ("report", self.root.resolve(), sha(encode(self.spec))),
            lambda: inventory(self.root, report=True),
            produce,
        )
        self.archive_derived_reasons = reasons
        return value

    def _report(self):
        spec = self.spec
        attempt = spec["attempt_index"]
        if attempt not in (1, 2, 3):
            raise IntegrityError("attempt_index_outside_registration")
        errors = []
        facts = self._durable_spec(errors)
        if "traffic_start_ms" in facts and "capture_end_ms" in facts:
            expected = registered_offers(
                attempt, facts["traffic_start_ms"], facts["capture_end_ms"], spec["config_sha256"]
            )
            if spec["expected_offers"] != expected:
                raise IntegrityError("expected_offers_differ_from_registered_trace")
        rows, receipts, integrity_rows = self._raw(attempt=attempt)
        sessions = {r["session_id"] for r in rows}
        # Sequence gaps are computed across the continuous archive, once per stream.
        # Local joins retain schema/order/clock/conflict attribution only.
        source = SourceJoin(rows, check_sequences=False)
        errors.extend(e["reason"] for e in source.errors)
        archive_errors = self._archive_errors(integrity_rows, receipts)
        del integrity_rows
        errors.extend(
            e["reason"]
            for e in archive_errors
            if e["affects_attempts"] == "all" or attempt in e["affects_attempts"]
        )
        starts = [
            e
            for e in self.journal.events
            if e["event"] == "attempt_start" and e["attempt"] == attempt
        ]
        traffic = [
            e
            for e in self.journal.events
            if e["event"] == "traffic_start" and e["attempt"] == attempt
        ]
        if len(starts) != 1:
            errors.append("missing_or_duplicate_durable_attempt_start")
        elif starts[0]["target_slot"] != spec["target_slot"]:
            errors.append("durable_attempt_target_mismatch")
        if not traffic:
            errors.append("missing_durable_traffic_start")
        manifest = json.loads((self.root / "registration.json").read_bytes())
        pins = manifest.get("sources_sha256", {})
        if (
            set(REQUIRED_PINS) - pins.keys()
            or pins.get("registration") != REGISTRATION_GIT_BLOB_SHA256
        ):
            errors.append("missing_or_mismatched_source_provenance")
        if len(sessions) != 1:
            errors.append("missing_or_mixed_session_identity")
        coverage = registered_coverage(
            source,
            facts.get("capture_start_ms", spec.get("capture_start_ms", 0)),
            facts.get("capture_end_ms", spec["capture_end_ms"]),
        )
        cadence = coverage["results"]
        errors.extend(e["reason"] for e in source.errors)
        source.rows = [
            r
            for r in source.rows
            if r["time_ms_bounds"] is None
            or spec.get("capture_start_ms", 0) <= r["time_ms_bounds"][0] <= spec["capture_end_ms"]
        ]
        requests = RequestJoin(source.rows, spec["expected_offers"], spec["capture_end_ms"])
        request_report = requests.report()
        errors.extend(request_report["validity_reasons"])
        from .inf037b_stages import StageJoin

        observations = [r for r in source.rows if carries_observation(r)]
        stage = StageJoin(
            observations,
            requests,
            target_uid=spec["target_uid"],
            replacement_uid=spec["replacement_uid"],
            capture_end_ms=spec["capture_end_ms"],
        )
        stages = stage.report(capture_complete=not errors, coverage_results=cadence)
        errors.extend(stages["validity_reasons"])
        deletion = stages["stage4"]["deletion_ms_bounds"]
        if deletion and (
            deletion[0] < spec["pre_end_ms"] or deletion[1] > spec["pre_end_ms"] + 30000
        ):
            errors.append("deletion_outside_registered_trigger_window")
        if spec["pre_end_ms"] - spec.get("traffic_start_ms", 0) != 600000:
            errors.append("pre_event_duration_not_600s")
        usable = stages["stage4"]["usable_ms_bounds"]
        recovery = RecoveryJoin(
            observations,
            requests.cohorts,
            pre_end_ms=spec["pre_end_ms"],
            usable_ms=usable[1]
            if usable and stages["stage4"]["replacement_usable_by_deadline"]
            else None,
            capture_end_ms=spec["capture_end_ms"],
            replacement_uid=spec["replacement_uid"],
        ).report()
        errors.extend(recovery["validity_reasons"])
        required_end = None
        if stages["stage4"]["replacement_usable_by_deadline"] is True:
            required_end = (
                recovery["recovery"]["confirmation_ms"]
                if recovery["recovery"]
                else recovery["deadline_ms"]
            )
        elif deletion:
            required_end = deletion[1] + 300_000
        if (
            "traffic_start_ms" in facts
            and facts.get("capture_start_ms", 0) > facts["traffic_start_ms"]
        ):
            errors.append("capture_starts_after_traffic_start")
        if (
            required_end is not None
            and facts.get("capture_end_ms", spec["capture_end_ms"]) < required_end + 30_000
        ):
            errors.append("capture_deadline_plus_drain_not_fully_captured")
        capture_requirement = {
            "applicable_endpoint_ms": required_end,
            "drain_ms": 30_000,
            "required_capture_end_ms": required_end + 30_000 if required_end is not None else None,
            "basis": "recovery_confirmation_or_deadline"
            if stages["stage4"]["replacement_usable_by_deadline"] is True
            else "stage4_deadline",
        }
        if spec["target_slot"] != TARGET_ORDER[attempt - 1]:
            errors.append("target_order_mismatch")
        # Validate the source configuration, never infer equivalence from tags.
        config = spec["config_sha256"]
        for row in source.rows:
            supplied = row["payload"].get("config_sha256")
            if supplied is not None and supplied != config:
                errors.append("configuration_hash_mismatch")
        baseline_installs = [
            r
            for r in observations
            if r["source_kind"] == "gateway"
            and r["payload"]["event"] == "install"
            and r["time_ms_bounds"]
            and r["time_ms_bounds"][1] <= spec["pre_end_ms"]
        ]
        starting = {
            r["payload"].get("gateway_uid"): r["payload"].get("members") for r in baseline_installs
        }
        if set(starting) != set(GATEWAYS) or any(
            not isinstance(members, list)
            or len(members) != 2
            or {m.get("slot") for m in members} != {0, 1}
            for members in starting.values()
        ):
            errors.append("starting_topology_not_two_by_two")
        for row in observations:
            p = row["payload"]
            if (
                row["source_kind"] == "kubernetes"
                and p["event"] in ("snapshot", "watch", "relist")
                and p.get("list_valid") is True
            ):
                endpoints = p.get("endpoints") or []
                if len([m for m in endpoints if m.get("serving") is True]) > 2:
                    errors.append("surge_or_topology_change")
        denominators = request_report["denominators"]
        if (
            denominators["scheduled"] == 0
            or abs(denominators["offered"] - denominators["scheduled"])
            > denominators["scheduled"] * 0.02
        ):
            errors.append("offered_schedule_outside_two_percent")
        lateness = [
            r["payload"].get("lateness_ms")
            for r in source.rows
            if r["source_kind"] == "client" and r["payload"]["event"] == "offer"
        ]
        if not lateness or any(type(v) is not int for v in lateness):
            errors.append("missing_dispatch_lateness")
        elif sorted(lateness)[math.ceil(len(lateness) * 0.95) - 1] > 20:
            errors.append("dispatch_lateness_above_20ms")
        resources = [
            r["payload"]
            for r in source.rows
            if r["source_kind"] == "controller" and r["payload"]["event"] == "resource"
        ]
        roles = {r.get("role") for r in resources}
        if roles != {*GATEWAYS, "generator"}:
            errors.append("missing_role_resource_fitness")
        for record in resources:
            if record.get("limit_known") is not True or any(
                type(record.get(k)) not in (float, int) or not 0 <= record[k] <= 0.70
                for k in ("cpu_fraction", "nic_fraction")
            ):
                errors.append("resource_limit_missing_or_above_70_percent")
        for gateway in GATEWAYS:
            for phase in ("pre", "event"):
                if not any(
                    r["gateway_uid"] == gateway
                    and r.get("phase") == phase
                    and r["outcome"] != "missed_offer"
                    for r in requests.cohorts
                ):
                    errors.append("missing_gateway_phase_traffic:" + gateway + ":" + phase)
        operational = [
            *request_report["operational_outcomes"],
            *stages["operational_outcomes"],
            *recovery["operational_outcomes"],
        ]
        ended = [
            e
            for e in self.journal.events
            if e["event"] == "attempt_end" and e["attempt"] == attempt
        ]
        # Private producer vocabulary for privacy-safe journal exports. This is
        # computed before reading any caller-supplied journal diagnostic text.
        self.archive_derived_reasons = sorted(set(errors))
        if ended:
            errors.extend(ended[-1]["reasons"])
        supersession = None
        if ended and (
            ended[-1]["measurement_valid"] != (not errors)
            or sorted(set(ended[-1]["reasons"])) != sorted(set(errors))
        ):
            supersession = {
                "journal_measurement_valid": ended[-1]["measurement_valid"],
                "journal_validity_reasons": ended[-1]["reasons"],
                "summary_measurement_valid": not errors,
                "summary_validity_reasons": sorted(set(errors)),
                "attribution_rule": "final_archive_summary_supersedes_attempt_end_journal",
            }
        return {
            "registration_id": REGISTRATION_ID,
            "attempt_index": attempt,
            "target_slot": spec["target_slot"],
            "target_uid": spec["target_uid"],
            "replacement_uid": spec["replacement_uid"],
            "sources_sha256": json.loads((self.root / "registration.json").read_bytes()).get(
                "sources_sha256", {}
            ),
            "source_join": source.report(),
            "collector_cadence": cadence,
            "coverage_contract": coverage,
            "archive_level_errors": archive_errors,
            "journal_validity_superseded_by_sealed_summary": supersession,
            "capture_requirement": capture_requirement,
            "source_error_attribution": "this_attempt_and_setup_only; archive_level_errors_use_affects_attempts",
            "requests": request_report,
            "stages": stages,
            "recovery": recovery,
            "measurement_valid": not errors,
            "validity_reasons": sorted(set(errors)),
            "operational_outcomes": operational,
            "stage_eligibility": {
                "1": not stages["stage1"]["sigterm_coverage"]["validity_reasons"],
                "2": not stage.stage_errors["2"]
                and not any(
                    c["gaps_ms"] for c in cadence if c["source_kind"] in ("gateway", "kubernetes")
                ),
                "3": not stage.stage_errors["3"]
                and not any(c["gaps_ms"] for c in cadence if c["source_kind"] == "redis"),
                "4": stages["stage4"]["replacement_usable_by_deadline"] is not None
                and not stage.stage_errors["4"]
                and not any(
                    c["gaps_ms"]
                    for c in cadence
                    if c["source_kind"] in ("gateway", "kubernetes", "vllm", "clocks")
                ),
                "5": not recovery["validity_reasons"],
            },
            "raw_segments": receipts,
            "controller": self.journal.report(),
            "paid_readiness": PacketReadiness(
                json.loads((self.root / "registration.json").read_bytes()), {}
            ).report(),
        }

    def finish_attempt(self, now_ms: int, *, absolute_deadline_ms: int, export_cleanup_ms: int):
        if now_ms + export_cleanup_ms > absolute_deadline_ms:
            self.journal.end_attempt(
                now_ms,
                measurement_valid=False,
                reasons=["absolute_session_deadline"],
                replacement_usable_by_deadline=None,
                operational_outcomes=["absolute_session_deadline"],
            )
            self.journal.stop(now_ms, "absolute_session_deadline")
            raise Refused("absolute_session_deadline")
        report = self.report()
        self.journal.end_attempt(
            now_ms,
            measurement_valid=report["measurement_valid"],
            reasons=report["validity_reasons"],
            replacement_usable_by_deadline=report["stages"]["stage4"][
                "replacement_usable_by_deadline"
            ],
            operational_outcomes=report["operational_outcomes"],
        )
        if report["stages"]["stage4"]["replacement_usable_by_deadline"] is None:
            self.journal.stop(now_ms, "replacement_usability_not_established")
        return self.journal.report()

    def start_attempt(self, now_ms: int, *, absolute_deadline_ms: int, export_cleanup_ms: int):
        remaining = absolute_deadline_ms - now_ms
        if remaining < ATTEMPT_MS + export_cleanup_ms:
            self.journal.stop(now_ms, "insufficient_remaining_absolute_time")
            raise Refused("insufficient_remaining_absolute_time")
        return self.journal.allocate(
            now_ms, remaining_ms=remaining, export_cleanup_ms=export_cleanup_ms
        )

    def materialize(self):
        bundle = materialize_bundle(self.root, [self.spec])
        return {**bundle["summaries"][0], "archive": bundle["archive"]}


@batched_durability
def materialize_bundle(root: Path, specs: list[dict]):
    """Produce every attempted slot together; one global cohort hash, no pooling."""
    if (root / "SHA256SUMS").exists():
        raise IntegrityError("cannot_materialize_sealed_archive")
    indices = [spec["attempt_index"] for spec in specs]
    if not specs or len(set(indices)) != len(indices) or any(i not in (1, 2, 3) for i in indices):
        raise IntegrityError("invalid_or_duplicate_summary_slots")
    journal = AttemptController(root / "attempts.jsonl")
    attempted = {e["attempt"] for e in journal.events if e["event"] == "attempt_start"}
    for path in (root / "raw").glob("*.jsonl"):
        attempted.update(
            r["attempt_id"]
            for r in inspect_segment(path, source_errors=True)[1]
            if type(r["attempt_id"]) is int
        )
    if attempted != set(indices):
        raise IntegrityError("summaries_must_cover_every_attempted_slot")
    path = root / "cohorts/requests.jsonl"
    if path.stat().st_size or any((root / "events").iterdir()):
        raise IntegrityError("derived_artifacts_already_materialized")
    reports = [
        OfflineCampaign(root, spec).report()
        for spec in sorted(specs, key=lambda spec: spec["attempt_index"])
    ]
    sequence = 0
    for report in reports:
        for cohort in report["requests"]["cohorts"]:
            row = envelope(cohort, seq=sequence, attempt=report["attempt_index"])
            row.update(
                record_id=f"cohort-{report['attempt_index']}-{sequence}",
                source_identity="offline-cohort-producer",
            )
            durable_write(path, encode(row), "ab")
            sequence += 1
    digest, summaries = sha(path.read_bytes()), []
    ordered_specs = sorted(specs, key=lambda spec: spec["attempt_index"])
    for report, spec in zip(reports, ordered_specs, strict=True):
        spec_name = f"events/attempt-{report['attempt_index']:02}.spec.json"
        durable_write(root / spec_name, encode(spec))
        report["spec_sha256"] = sha((root / spec_name).read_bytes())
        report["cohort_sha256"] = digest
        report["cohort_row_count"] = len(report["requests"]["cohorts"])
        name = f"events/attempt-{report['attempt_index']:02}.json"
        durable_write(root / name, encode(report))
        summaries.append(
            {
                "summary_path": name,
                "summary_sha256": sha((root / name).read_bytes()),
                "cohort_sha256": digest,
                "spec_path": spec_name,
                "spec_sha256": report["spec_sha256"],
            }
        )
    return {"summaries": summaries, "archive": Archive(root).seal()}


# Diagnostic grammar: prefix : opaque request_id [: event]. The opaque segment
# may itself contain colons. Slot suffixes and diagnostic names are never IDs.
DIAGNOSTIC_IDENTITIES = {
    **dict.fromkeys(
        (
            "unscheduled_request",
            "missed_offer_has_traffic",
            "unreconciled_offer",
            "missing_offer",
            "gateway_identity_join",
            "lost_gateway_identity",
            "backend_identity_join_mismatch",
            "missing_or_mismatched_policy",
            "lost_backend_generation",
            "missing_dispatch_timestamp",
            "request_clock_order_unknown",
            "missing_operation_capacity",
            "missing_request_admission_operation",
        ),
        ("request_id", 0),
    ),
    "multiple_request_boundaries": ("request_id", 1),
}


def _mapped_report_value(value, sanitizer, field):
    from .inf037b_packet import _replace_value

    value = sanitizer.value(value, field)
    # _finish_row is a row-only safety-net hook, also exercised by drift tests.
    # Projection of facts must not invoke that hook on scalar identities.
    for gateway in GATEWAYS:
        value = _replace_value(value, sanitizer.pseudonym(gateway), gateway)
    return value


def _mapped_diagnostic(reason, sanitizer):
    prefix, separator, suffix = reason.partition(":")
    if not separator or prefix not in DIAGNOSTIC_IDENTITIES:
        return reason
    field, tail_count = DIAGNOSTIC_IDENTITIES[prefix]
    parts = suffix.rsplit(":", tail_count) if tail_count else [suffix]
    if len(parts) != tail_count + 1:
        raise IntegrityError("invalid_diagnostic_identity_segments")
    parts[0] = _mapped_report_value(parts[0], sanitizer, field)
    return prefix + ":" + ":".join(parts)


def _mapped_report_facts(value, sanitizer, diagnostics, field=""):
    """Map only identity positions; report schema keys are public vocabulary."""
    if field == "quantity_reasons":
        return _mapped_report_value(value, sanitizer, "field_reasons")
    if field == "reports":
        return _mapped_report_value(value, sanitizer, field)
    if isinstance(value, dict):
        return {
            _mapped_report_value(k, sanitizer, "backend_uid")
            if field == "generation"
            else k: _mapped_report_facts(v, sanitizer, diagnostics, k)
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_mapped_report_facts(v, sanitizer, diagnostics, field) for v in value]
    if isinstance(value, str):
        if field in ("reason", "reasons", "validity_reasons", "operational_outcomes"):
            if value in diagnostics:
                return diagnostics[value]
            return _mapped_diagnostic(value, sanitizer)
        if field in (
            "request_ids",
            "remaining_reservations",
            "definitely_live",
            "possibly_live",
            "after_first_content",
        ):
            return _mapped_report_value(value, sanitizer, "request_id")
        if field.endswith(("_id", "_uid", "_identity", "_generation")) or field in (
            "uid",
            "identity",
            "generation",
        ):
            return _mapped_report_value(value, sanitizer, field)
    return value


@export_memoization
def sanitized_campaign(raw: Path, destination: Path, specs: list[dict], *, key: bytes):
    from .inf037b_packet import Sanitizer, _replace_value, sanitized_sources

    raw_reports, source_reasons = [], set()
    for spec in specs:
        reproduce(raw, spec)
        campaign = OfflineCampaign(raw, spec)
        raw_reports.append(campaign.report())
        source_reasons.update(campaign.archive_derived_reasons)
    sanitizer = Sanitizer(key)
    safe_specs = sanitizer.value(specs)
    for gateway in GATEWAYS:
        safe_specs = _replace_value(safe_specs, sanitizer.pseudonym(gateway), gateway)
    # Only producer-derived diagnostics are public vocabulary, with dynamic
    # identity suffixes mapped consistently. Arbitrary journal text still hashes.
    diagnostics = {reason: _mapped_diagnostic(reason, sanitizer) for reason in source_reasons}
    diagnostics["absolute_session_deadline"] = "absolute_session_deadline"
    sanitizer.diagnostics = diagnostics
    for row in inspect_segment(raw / "attempts.jsonl")[1]:
        for reason in row["payload"].get("reasons") or []:
            diagnostics.setdefault(reason, sanitizer.value(reason, "reasons"))
    sanitized_sources(raw, destination, key=key, diagnostics=diagnostics)

    for original, spec in zip(raw_reports, safe_specs, strict=True):
        safe_report = OfflineCampaign(destination, spec).report()
        if _canonical_facts(
            _mapped_report_facts(sanitized_report_facts(original), sanitizer, diagnostics)
        ) != _canonical_facts(sanitized_report_facts(safe_report)):
            raise IntegrityError("raw_sanitized_report_mismatch")
    result = materialize_bundle(destination, safe_specs)
    for spec in safe_specs:
        reproduce(destination, spec)
    return {
        **result,
        "specs": safe_specs,
        "source_manifest_sha256": sha((raw / "SHA256SUMS").read_bytes()),
    }


def _canonical_facts(value, field=""):
    if isinstance(value, dict):
        return {k: _canonical_facts(v, k) for k, v in value.items()}
    if isinstance(value, list):
        values = [_canonical_facts(v, field) for v in value]
        return (
            sorted(values)
            if field in ("validity_reasons", "remaining_reservations", "request_ids")
            else values
        )
    return value


def sanitized_report_facts(report):
    """Semantic export contract; byte lengths and source hashes are intentionally new."""
    return {
        **{
            k: report[k]
            for k in (
                "measurement_valid",
                "validity_reasons",
                "stages",
                "recovery",
                "operational_outcomes",
                "stage_eligibility",
                "capture_requirement",
            )
        },
        "requests": {
            **{
                k: report["requests"][k]
                for k in (
                    "denominators",
                    "counts",
                    "stage1_scope",
                    "validity_reasons",
                    "operational_outcomes",
                )
            },
            "cohorts": [
                {k: v for k, v in cohort.items() if k != "stream"}
                | {"stream": {k: v for k, v in cohort["stream"].items() if k != "pending_bytes"}}
                for cohort in report["requests"]["cohorts"]
            ],
        },
    }


def reproduce(root: Path, spec: dict | None = None, *, attempt_index: int | None = None):
    verify_archive(root)
    attempt = spec["attempt_index"] if spec is not None else attempt_index
    if attempt not in (1, 2, 3):
        raise IntegrityError("attempt_index_required")
    spec_bytes = (root / f"events/attempt-{attempt:02}.spec.json").read_bytes()
    archived_spec = json.loads(spec_bytes)
    if spec is not None and spec != archived_spec:
        raise IntegrityError("caller_spec_differs_from_archived_spec")
    report = OfflineCampaign(root, archived_spec).report()
    saved = json.loads((root / f"events/attempt-{attempt:02}.json").read_bytes())
    if saved.pop("spec_sha256") != sha(spec_bytes):
        raise IntegrityError("archived_spec_hash_mismatch")
    saved.pop("cohort_sha256")
    saved.pop("cohort_row_count")
    if saved != report:
        raise IntegrityError("summary_reproduction_mismatch")
    return {
        "reproduced": True,
        "measurement_valid": report["measurement_valid"],
        "denominators": report["requests"]["denominators"],
    }
