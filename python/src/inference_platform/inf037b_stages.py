"""Offline discovery, signal/lifecycle and atomic Redis joins (v3 stages1–4)."""

from .inf037b_budget import Bounds, both_gateways
from .inf037b_contract import GATEWAYS
from .inf037b_requests import CODES, elapsed
from .inf037b_sources import ClockMapper


class StageJoin:
    def __init__(self, rows, requests, *, target_uid, replacement_uid, capture_end_ms):
        self.rows, self.requests = rows, requests
        self.target, self.replacement = target_uid, replacement_uid
        self.end = capture_end_ms
        self.errors, self.outcomes = [], []
        self.kube = [r for r in rows if r["source_kind"] == "kubernetes"]
        self.gateways = [r for r in rows if r["source_kind"] == "gateway"]
        self.redis = [r for r in rows if r["source_kind"] == "redis"]

    def _endpoint(self, event, uid):
        found = [
            r
            for r in self.kube
            if r["payload"]["event"] == event
            and r["payload"].get("pod_uid") == uid
            and (
                event != "signal"
                or (
                    r["payload"].get("signal") == "SIGTERM"
                    and r["payload"].get("signal_receipt_time") is not None
                )
            )
            and r["time_ms_bounds"]
        ]
        return min((r["time_ms_bounds"] for r in found), default=None)

    def discovery(self):
        result = {}
        deletion = self._endpoint("deletion", self.target)
        for gateway in GATEWAYS:
            installs = [
                r
                for r in self.gateways
                if r["payload"]["event"] == "install" and r["payload"].get("gateway_uid") == gateway
            ]
            installs.sort(key=lambda r: (r["time_ms_bounds"] or [10**20])[0])
            last, excluded, unknown = None, None, []
            refs = []
            for row in installs:
                p, time = row["payload"], row["time_ms_bounds"]
                refs.append(row["raw_ref"])
                if p.get("membership_known") is False:
                    unknown.append(time)
                    eligible = False
                elif p.get("membership_known") is True and isinstance(p.get("members"), list):
                    # UID and readiness, never address reuse, determine membership.
                    eligible = any(
                        m.get("uid") == self.target
                        and m.get("ready") is True
                        and m.get("sampled") is True
                        and m.get("healthy") is True
                        and not m.get("terminating", False)
                        for m in p["members"]
                    )
                else:
                    self.errors.append("invalid_membership_install:" + gateway)
                    continue
                if eligible:
                    last = time
                elif deletion and time and time[0] >= deletion[1] and excluded is None:
                    excluded = time
            if not installs:
                self.errors.append("missing_gateway_installations:" + gateway)
            late = [
                r["raw_ref"]
                for r in self.gateways
                if r["payload"]["event"] == "upstream_open"
                and r["payload"].get("gateway_uid") == gateway
                and r["payload"].get("backend_uid") == self.target
                and excluded
                and r["time_ms_bounds"]
                and r["time_ms_bounds"][0] >= excluded[1]
            ]
            if late:
                self.outcomes.append(
                    {
                        "reason": "old_uid_dispatch_after_exclusion",
                        "gateway_uid": gateway,
                        "raw_refs": late,
                    }
                )
            if deletion and (excluded is None or excluded[1] - deletion[0] > 30_000):
                self.outcomes.append(
                    {"reason": "exclusion_deadline_missed", "gateway_uid": gateway}
                )
            result[gateway] = {
                "last_eligible_ms_bounds": last,
                "first_excluded_ms_bounds": excluded,
                "exclusion_observation_bracket_ms": [last[0], excluded[1]]
                if last and excluded
                else None,
                "deletion_to_excluded_ms_bounds": elapsed(deletion, excluded),
                "unknown_intervals": unknown,
                "late_old_dispatches": late,
                "raw_refs": refs,
            }
        return result

    def additions(self, capture_complete):
        inputs, refs = {}, {}
        clock_rows = [
            r
            for r in self.rows
            if r["source_kind"] == "clocks" and r["payload"].get("clock_id") == "redis"
        ]
        mapper = ClockMapper(clock_rows)
        ends = []
        for (clock, boot), mappings in list(mapper.maps.items()):
            if any(p["local_mono_ms"] <= self.end for p in mappings) and any(
                p["local_mono_ms"] >= self.end for p in mappings
            ):
                end = mapper.inverse(clock, boot, self.end, self.end)
                if end is not None and end[0] >= 0:
                    ends.append(end)
        redis_end = ends[0] if len(ends) == 1 else None
        for gateway in GATEWAYS:
            installs = [
                r
                for r in self.gateways
                if r["payload"]["event"] == "install"
                and r["payload"].get("gateway_uid") == gateway
                and r["payload"].get("replacement_uid") == self.replacement
            ]
            installs.sort(key=lambda r: (r["time_ms_bounds"] or [10**20])[0])
            install = installs[0] if installs else None
            p = install["payload"] if install else {}
            bracket = p.get("install_redis_ms_bounds")
            stores = [
                r
                for r in self.redis
                if r["payload"]["event"] == "report_store"
                and r["payload"].get("gateway_uid") == gateway
                and r["payload"].get("report_success") is True
                and r["payload"].get("report_complete") is True
                and r["payload"].get("report_known") is True
            ]
            stores.sort(
                key=lambda r: (r["payload"]["redis_time_ms"], r["payload"].get("store_order") or 0)
            )
            prior, renewal, order_ok = None, None, True
            if bracket:
                for store in stores:
                    s = store["payload"]
                    t, order = s["redis_time_ms"], s.get("store_order")
                    if t < bracket[0] or (
                        t == bracket[0] == bracket[1]
                        and type(order) is int
                        and type(p.get("store_order")) is int
                        and order < p["store_order"]
                    ):
                        prior = store
                    elif t > bracket[1] or (
                        t == bracket[0] == bracket[1]
                        and type(order) is int
                        and type(p.get("store_order")) is int
                        and order > p["store_order"]
                    ):
                        if renewal is None:
                            renewal = store
                    elif t <= bracket[1]:
                        # A possible newer preceding report means an older store cannot prove A.
                        order_ok = False
            if install and not bracket:
                self.errors.append("installation_missing_redis_clock:" + gateway)
            refs[gateway] = [r["raw_ref"] for r in (install, prior, renewal) if r]
            inputs[gateway] = {
                "capture_end": Bounds(*redis_end) if redis_end else Bounds(0, 0),
                "capture_complete": capture_complete,
                "installation": Bounds(*bracket) if bracket else None,
                "preceding_store_ms": prior["payload"]["redis_time_ms"] if prior else None,
                "renewal_store": Bounds(*([renewal["payload"]["redis_time_ms"]] * 2))
                if renewal
                else None,
                "clock_evidence": install is None
                or (
                    bracket is not None
                    and install["time_ms_bounds"] is not None
                    and redis_end is not None
                ),
                "store_order_evidenced": order_ok,
            }
        summaries = both_gateways(self.replacement, **inputs)
        for summary in summaries:
            if redis_end is None:
                summary["capture_end_ms_bounds"] = None
            summary["capture_end_clock_refs"] = [r["raw_ref"] for r in clock_rows]
            summary["raw_refs"] = refs[summary["gateway_uid"]]
            self.errors.extend(summary["validity_reasons"])
            for quantity in ("age", "renewal"):
                if summary[f"{quantity}_budget_status"] == "exceeded":
                    self.outcomes.append(
                        {
                            "reason": quantity + "_budget_exceeded",
                            "gateway_uid": summary["gateway_uid"],
                        }
                    )
        return summaries

    def admission(self):
        timeline, operations, reservations = [], [], set()
        expiries, seeded = {}, False
        last_time = -1
        for row in sorted(
            self.redis, key=lambda r: (r["payload"].get("redis_time_ms") or 0, r["source_seq"])
        ):
            p = row["payload"]
            if p["event"] == "read_error":
                self.errors.append("redis_read_evidence_missing")
                continue
            now = p.get("redis_time_ms")
            if type(now) is not int or now < last_time:
                self.errors.append("redis_time_reversed_or_missing")
                continue
            last_time = now
            expired = {request for request, expiry in expiries.items() if expiry <= now}
            reservations.difference_update(expired)
            for request in expired:
                expiries.pop(request, None)
            if p["event"] == "snapshot":
                try:
                    reports, lows, state = p["reports"], p["lows"], p["state"]
                    if (
                        not isinstance(reports, dict)
                        or not isinstance(lows, list)
                        or not isinstance(state, dict)
                    ):
                        raise ValueError("missing_atomic_state")
                    fresh = [
                        v["n"]
                        for v in reports.values()
                        if v["expires_ms"] > now and v["unknown"] is False
                    ]
                    fresh_unknown = any(
                        v["expires_ms"] > now and v["unknown"] is True for v in reports.values()
                    )
                    low_values = [v["n"] for v in lows if v["until_ms"] > now]
                    if any(
                        type(v) is not int or v < 0
                        for v in (*fresh, *low_values, state["n"], p["occupied"])
                    ):
                        raise ValueError("invalid_atomic_counts")
                    active = p["active_reservations"]
                    ids = [v["request_id"] for v in active if v["expiry_ms"] > now]
                    if seeded and reservations - set(ids):
                        self.outcomes.append(
                            {
                                "reason": "reservation_disappeared_without_observed_release",
                                "request_ids": sorted(reservations - set(ids)),
                                "raw_ref": row["raw_ref"],
                            }
                        )
                    reservations = set(ids)
                    expiries = {
                        v["request_id"]: v["expiry_ms"] for v in active if v["expiry_ms"] > now
                    }
                    seeded = True
                    if len(set(ids)) != len(ids) or p["occupied"] != len(ids):
                        self.errors.append("atomic_snapshot_inconsistent")
                    n = state["n"]
                    b = 5 * n
                    ceiling = min(fresh + low_values) if fresh + low_values else 0
                    violations = []
                    if fresh and n > ceiling:
                        violations.append("effective_n_above_fresh_min_or_retained_low")
                    if timeline and n > timeline[-1]["n"]:
                        previous = timeline[-1]
                        since = previous["state"].get("since_ms")
                        until = previous["state"].get("until_ms")
                        if (
                            previous["state"].get("candidate") != n
                            or since is None
                            or until is None
                            or now - since < 2000
                            or now >= until
                            or fresh_unknown
                            or not fresh
                        ):
                            violations.append("restoration_without_full_fresh_hold")
                    if fresh_unknown and state.get("candidate") is not None:
                        violations.append("unknown_did_not_interrupt_restoration")
                    if state.get("candidate") is not None and (
                        state.get("since_ms") is None or state.get("until_ms") is None
                    ):
                        self.errors.append("missing_restoration_endpoints")
                    timeline.append(
                        {
                            "redis_time_ms": now,
                            "n": n,
                            "b": b,
                            "occupied": p["occupied"],
                            "reports": reports,
                            "lows": lows,
                            "state": state,
                            "all_expired": not fresh,
                            "fresh_unknown": fresh_unknown,
                            "occupied_at_or_above_b": p["occupied"] >= b,
                            "violations": violations,
                            "raw_ref": row["raw_ref"],
                        }
                    )
                    self.outcomes.extend(
                        {"reason": v, "raw_ref": row["raw_ref"]} for v in violations
                    )
                except (KeyError, TypeError, ValueError):
                    self.errors.append("invalid_atomic_snapshot")
            if p["event"] in ("admit", "release"):
                request = p.get("request_id")
                if not request or p.get("idempotent") is None:
                    self.errors.append("missing_operation_identity")
                    continue
                if p["event"] == "admit":
                    if p.get("effective_b") is None:
                        self.errors.append("missing_operation_capacity:" + request)
                    elif (
                        p.get("effective_n") is not None
                        and p["effective_b"] != 5 * p["effective_n"]
                    ):
                        self.outcomes.append(
                            {
                                "reason": "operation_b_n_mismatch",
                                "request_id": request,
                                "raw_ref": row["raw_ref"],
                            }
                        )
                if p["event"] == "admit" and p.get("decision") == "allowed":
                    if request in reservations and not p["idempotent"]:
                        self.outcomes.append(
                            {"reason": "duplicate_nonidempotent_admission", "request_id": request}
                        )
                    reservations.add(request)
                elif p["event"] == "release":
                    if request not in reservations and not p["idempotent"]:
                        self.outcomes.append(
                            {"reason": "release_without_active_reservation", "request_id": request}
                        )
                    reservations.discard(request)
                    expiries.pop(request, None)
                operations.append(
                    {
                        "event": p["event"],
                        "request_id": request,
                        "decision": p.get("decision"),
                        "idempotent": p["idempotent"],
                        "redis_time_ms": now,
                        "effective_n": p.get("effective_n"),
                        "effective_b": p.get("effective_b"),
                        "occupied": p.get("occupied"),
                        "quantity_reasons": {
                            k: p.get("field_reasons", {}).get(k)
                            for k in ("effective_n", "effective_b", "occupied")
                            if p.get(k) is None
                        },
                        "raw_ref": row["raw_ref"],
                    }
                )
        if not timeline:
            self.errors.append("missing_atomic_redis_snapshots")
        admitted_ids = {op["request_id"] for op in operations if op["event"] == "admit"}
        for cohort in self.requests.cohorts:
            if cohort["admit_called"] is True and cohort["request_id"] not in admitted_ids:
                self.errors.append("missing_request_admission_operation:" + cohort["request_id"])
            if cohort["denial_code"] == "capacity_reports_expired" and (
                cohort["http_status"] != 503 or cohort["retry_after_ms"] is not None
            ):
                self.outcomes.append(
                    {
                        "reason": "expired_reports_response_contract",
                        "request_id": cohort["request_id"],
                    }
                )
        return {
            "timeline": timeline,
            "operations": operations,
            "remaining_reservations": sorted(reservations),
            "reservation_state_redis_ms": last_time if last_time >= 0 else None,
            "denial_codes": {
                code: sum(r["denial_code"] == code for r in self.requests.cohorts) for code in CODES
            },
        }

    def report(self, *, capture_complete: bool = True, coverage_results=()):
        self.errors, self.outcomes = [], []
        deletion, signal = (
            self._endpoint("deletion", self.target),
            self._endpoint("signal", self.target),
        )
        if deletion is None:
            self.errors.append("missing_deletion_observation")
        if signal is None:
            self.errors.append("missing_actual_sigterm")
        if deletion and signal and signal[0] <= deletion[1]:
            self.errors.append("deletion_signal_order_unknown")
        coverage = self.requests.coverage(signal, self.target)
        self.errors.extend(coverage["validity_reasons"])
        before = len(self.errors)
        discovery = self.discovery()
        discovery_errors = self.errors[before:]
        addition = self.additions(capture_complete)
        before = len(self.errors)
        admission = self.admission()
        admission_errors = self.errors[before:]
        self.stage_errors = {
            "2": discovery_errors + (["missing_deletion_observation"] if deletion is None else []),
            "3": admission_errors,
        }
        stage4_start = len(self.errors)
        ready = self._endpoint("ready", self.replacement)
        if ready:
            for gateway in GATEWAYS:
                if not any(
                    r["payload"]["event"] == "health"
                    and r["payload"].get("gateway_uid") == gateway
                    and r["time_ms_bounds"]
                    and r["time_ms_bounds"][0] >= ready[1]
                    for r in self.gateways
                ):
                    self.errors.append("missing_replacement_health_capture:" + gateway)
            if not any(
                r["source_kind"] == "vllm"
                and r["payload"].get("pod_uid") == self.replacement
                and r["payload"].get("health_ready") is not None
                for r in self.rows
            ):
                self.errors.append("missing_replacement_native_metrics")
        completions = [
            r
            for r in self.requests.cohorts
            if r["backend_uid"] == self.replacement
            and r["outcome"] == "complete"
            and r.get("identity_join_valid") is True
            and r["terminal_ms_bounds"]
            and ready
            and r["terminal_ms_bounds"][0] >= ready[1]
        ]
        raw_firsts = {
            g: min(
                (r["terminal_ms_bounds"] for r in completions if r["gateway_uid"] == g),
                default=None,
            )
            for g in GATEWAYS
        }
        firsts, fresh, installed, native_fresh = {}, {}, {}, {}
        for gateway in GATEWAYS:
            candidates = sorted(
                (r for r in completions if r["gateway_uid"] == gateway),
                key=lambda r: r["terminal_ms_bounds"][1],
            )
            firsts[gateway] = None
            fresh[gateway] = installed[gateway] = native_fresh[gateway] = False
            for candidate in candidates:
                opened = candidate["upstream_open_ms_bounds"]
                if not opened:
                    continue
                views = [
                    r
                    for r in self.gateways
                    if r["payload"]["event"] == "install"
                    and r["payload"].get("gateway_uid") == gateway
                    and r["time_ms_bounds"]
                    and r["time_ms_bounds"][1] <= opened[0]
                ]
                view = max(views, key=lambda r: r["time_ms_bounds"][1]) if views else None
                installed[gateway] = bool(
                    view
                    and view["payload"].get("membership_known") is True
                    and any(
                        m.get("uid") == self.replacement
                        and m.get("ready") is True
                        and m.get("healthy") is True
                        and m.get("sampled") is True
                        and not m.get("terminating", False)
                        for m in view["payload"].get("members", [])
                    )
                )
                fresh[gateway] = any(
                    r["payload"]["event"] == "health"
                    and r["payload"].get("gateway_uid") == gateway
                    and any(
                        m.get("uid") == self.replacement
                        and m.get("healthy") is True
                        and m.get("sampled") is True
                        for m in (r["payload"].get("members") or [])
                    )
                    and r["time_ms_bounds"]
                    and r["time_ms_bounds"][1] <= opened[0]
                    and opened[1] - r["time_ms_bounds"][0] <= 1000
                    for r in self.gateways
                )
                native_fresh[gateway] = any(
                    r["source_kind"] == "vllm"
                    and r["payload"].get("pod_uid") == self.replacement
                    and r["payload"].get("health_ready") is True
                    and all(
                        r["payload"].get(field) is not None
                        for field in (
                            "process_generation",
                            "reset_generation",
                            "model_sha256",
                            "runtime_sha256",
                            "metric_semantics_sha256",
                            "running",
                            "waiting",
                            "prefix_query_tokens_total",
                            "prefix_hit_tokens_total",
                            "preemptions_total",
                        )
                    )
                    and r["time_ms_bounds"]
                    and r["time_ms_bounds"][1] <= opened[0]
                    and opened[1] - r["time_ms_bounds"][0] <= 1000
                    for r in self.rows
                )
                if fresh[gateway] and installed[gateway] and native_fresh[gateway]:
                    firsts[gateway] = candidate["terminal_ms_bounds"]
                    break
        usable = max(firsts.values()) if all(firsts.values()) else None
        fits = bool(usable and deletion and usable[1] - deletion[0] <= 300_000)
        # A completion cannot establish usability across missing discovery/native
        # observations. Later gaps do not erase an already established endpoint.
        if (
            fits
            and ready
            and any(
                a < usable[1] and b > ready[0]
                for contract in coverage_results
                if contract["source_kind"] in ("gateway", "kubernetes", "vllm")
                for a, b in contract["gaps_ms"]
            )
        ):
            fits, usable = False, None
            self.errors.append("incomplete_usable_input_coverage")
        deadline = deletion[1] + 300_000 if deletion else None
        usability = True if fits else None
        terminals_complete = not any(
            r.get("censor_reason") == "capture_end"
            and r.get("offer_ms_bounds")
            and deadline is not None
            and r["offer_ms_bounds"][0] <= deadline
            for r in self.requests.cohorts
        )
        if not fits and not terminals_complete:
            self.errors.append("incomplete_client_terminal_capture")
        if (
            not fits
            and capture_complete
            and terminals_complete
            and deadline is not None
            and self.end >= deadline
            and not any(reason.startswith("missing_replacement_") for reason in self.errors)
        ):
            if usable is None or usable[0] - deletion[1] > 300_000:
                usability = False
        if not fits and deadline is not None and self.end < deadline:
            self.errors.append("usable_deadline_not_fully_captured")
        if not fits and not capture_complete:
            self.errors.append("incomplete_usable_input_coverage")
        if usability is False:
            self.outcomes.append({"reason": "replacement_never_usable_by_deadline"})
        elif usability is None:
            self.outcomes.append({"reason": "replacement_usability_not_established"})
        cache_rows = [
            r["payload"]
            for r in self.kube
            if r["payload"].get("pod_uid") == self.replacement
            and r["payload"]["event"] in ("container_state", "startup")
        ]
        cache = [
            {"image": p.get("image_cache_state"), "model": p.get("model_cache_state")}
            for p in cache_rows
        ]
        if not cache or any(
            c["image"] not in ("cold", "node_cached") or c["model"] not in ("cold", "node_cached")
            for c in cache
        ):
            self.errors.append("unknown_cache_state")
        lifecycle = {
            event: self._endpoint(event, self.replacement)
            for event in ("pod_created", "gpu_free", "scheduled", "startup", "ready")
        }
        self.stage_errors["4"] = self.errors[stage4_start:] + (
            ["missing_deletion_observation"] if deletion is None else []
        )
        return {
            "stage1": {
                "deletion_coverage": self.requests.coverage(deletion, self.target),
                "sigterm_coverage": coverage,
                **self.requests.report()["stage1_scope"],
            },
            "stage2": discovery,
            "stage3": admission,
            "addition_budgets": addition,
            "stage4": {
                "deletion_ms_bounds": deletion,
                "signal_ms_bounds": signal,
                **{k + "_ms_bounds": v for k, v in lifecycle.items()},
                "per_gateway_first_completion_ms_bounds": raw_firsts,
                "per_gateway_first_usable_completion_ms_bounds": firsts,
                "fresh_gateway_telemetry": fresh,
                "installed_eligible_route": installed,
                "fresh_native_metrics": native_fresh,
                "usable_ms_bounds": usable,
                "replacement_usable_by_deadline": usability,
                "usability_reason": "validated_usable_completion"
                if usability is True
                else "complete_capture_through_usable_deadline"
                if usability is False
                else "usability_not_established",
                "right_censored_at_ms": min(self.end, deadline) if deadline and not fits else None,
                "cache_states": cache,
            },
            "measurement_valid": not self.errors,
            "validity_reasons": sorted(set(self.errors)),
            "operational_outcomes": self.outcomes,
        }
