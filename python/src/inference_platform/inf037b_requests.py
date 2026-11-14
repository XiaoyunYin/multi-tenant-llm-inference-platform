"""Incremental SSE and offer/request reconciliation for offline v3 stages1–5."""

from collections import Counter

from .inf037b_budget import stage1_scope
from .inf037b_contract import GATEWAYS
from .inf037b_sources import source_order
from .inf037b_sse_json import sse_json_loads

CODES = (
    "discovery_unknown",
    "discovery_unknown_after_admit",
    "backend_membership_changed_after_admit",
    "capacity_reports_expired",
    "system_capacity",
)
OUTCOMES = ("complete", "failed", "rejected", "missed_offer", "right_censored")


class SSEError(ValueError):
    """Only fixed public codes enter reports, never parser exception text."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


class SSEDecoder:
    """Chunk boundaries/EOF do not prove a validated finish and DONE."""

    def __init__(self):
        self.buffer = b""
        self.content = []
        self.finish = False
        self.usage = False
        self.done = False
        self.errors = []
        self.events = 0

    def feed(self, data: bytes, time_ms_bounds: list[int]):
        if self.done and data.strip():
            self.errors.append("data_after_done")
            return
        self.buffer += data
        self.buffer = self.buffer.replace(b"\r\n", b"\n")
        if len(self.buffer) > 1_048_576:
            self.errors.append("oversize_sse")
            self.buffer = b""
            return
        while b"\n\n" in self.buffer:
            event, self.buffer = self.buffer.split(b"\n\n", 1)
            fields = [
                line[5:].lstrip(b" ") for line in event.split(b"\n") if line.startswith(b"data:")
            ]
            if not fields:
                continue
            value = b"\n".join(fields)
            self.events += 1
            if value == b"[DONE]":
                if self.done or not self.finish:
                    self.errors.append("done_without_unique_valid_finish")
                if not self.usage:
                    self.errors.append("done_without_valid_usage")
                self.done = True
                continue
            try:
                chunk = sse_json_loads(value)
            except (ValueError, UnicodeError):
                self.errors.append("invalid_sse_json")
                continue
            try:
                if not isinstance(chunk, dict) or "error" in chunk or self.done:
                    raise SSEError("invalid_sse_chunk")
                choices = chunk.get("choices")
                if choices == [] and "usage" in chunk:
                    usage = chunk["usage"]
                    if (
                        not isinstance(usage, dict)
                        or any(
                            type(usage.get(k)) is not int or usage[k] < 0
                            for k in ("prompt_tokens", "completion_tokens", "total_tokens")
                        )
                        or usage.get("count_source") != "runtime_usage"
                        or usage["total_tokens"]
                        != usage["prompt_tokens"] + usage["completion_tokens"]
                    ):
                        raise SSEError("invalid_sse_usage")
                    if not self.finish or self.usage:
                        raise SSEError("invalid_sse_usage_order")
                    self.usage = True
                    continue
                if "usage" in chunk or self.usage:
                    raise SSEError("invalid_sse_usage_order")
                if not isinstance(choices, list) or len(choices) != 1:
                    raise SSEError("invalid_sse_choices")
                choice = choices[0]
                if (
                    not isinstance(choice, dict)
                    or type(choice.get("index")) is not int
                    or choice["index"] != 0
                    or not isinstance(choice.get("delta"), dict)
                ):
                    raise SSEError("invalid_sse_schema")
                text = choice["delta"].get("content")
                if text is not None and not isinstance(text, str):
                    raise SSEError("invalid_sse_content")
                if text:
                    if self.finish:
                        raise SSEError("content_after_finish")
                    self.content.append(time_ms_bounds)
                reason = choice.get("finish_reason")
                if reason is not None:
                    if reason not in ("stop", "length") or self.finish:
                        raise SSEError("invalid_sse_finish")
                    self.finish = True
            except SSEError as exc:
                self.errors.append(exc.code)

    def report(self):
        errors = self.errors + (
            ["trailing_bytes_after_done"] if self.done and self.buffer.strip() else []
        )
        return {
            "content_valid": bool(self.content),
            "finish_valid": self.finish,
            "done_valid": self.done,
            "complete": bool(self.content) and self.finish and self.done and not errors,
            "partial": bool(self.content) and not (self.finish and self.done and not errors),
            "first_content_ms_bounds": self.content[0] if self.content else None,
            "events": self.events,
            "pending_bytes": len(self.buffer),
            "errors": errors,
        }


def elapsed(start, end):
    if start is None or end is None or end[0] < start[1]:
        return None
    return [end[0] - start[1], end[1] - start[0]]


class RequestJoin:
    def __init__(self, rows: list[dict], expected_offers: list[dict], capture_end_ms: int):
        self.rows = rows
        self.expected = expected_offers
        self.capture_end = capture_end_ms
        self.errors, self.operational, self.cohorts = [], [], []
        self._build()

    def _build(self):
        expected_ids = [offer["request_id"] for offer in self.expected]
        if len(set(expected_ids)) != len(expected_ids):
            raise ValueError("duplicate_scheduled_request")
        expected_ids = set(expected_ids)
        records = {}
        for row in self.rows:
            p = row["payload"]
            if p.get("request_id"):
                records.setdefault(p["request_id"], []).append(row)
                if p["request_id"] not in expected_ids:
                    self.errors.append("unscheduled_request:" + p["request_id"])
        for offer in self.expected:
            request = offer["request_id"]
            joined = records.get(request, [])
            joined.sort(key=lambda r: (r["time_ms_bounds"] or [10**20])[0])
            client = [r for r in joined if r["source_kind"] == "client"]
            by_event = {}
            for row in client:
                by_event.setdefault(row["payload"]["event"], []).append(row)
            for event in ("offer", "receive", "terminal", "missed", "cancel", "timeout"):
                if len(by_event.get(event, [])) > 1:
                    self.errors.append("multiple_request_boundaries:" + request + ":" + event)

            def first(event, by_event=by_event):
                return (by_event.get(event) or [None])[0]

            def at(event):
                return first(event)["time_ms_bounds"] if first(event) else None

            decoder = SSEDecoder()
            sse = sorted(by_event.get("sse", []), key=source_order)
            if len({source_order(row)[:2] for row in sse}) > 1:
                # There is no byte ordering across producers or boots. Do not
                # assemble an apparently valid stream from unrelated fragments.
                decoder.errors.append("multiple_sse_sources")
                sse = []
            for row in sse:
                try:
                    if row["time_ms_bounds"] is None:
                        raise ValueError("sse_clock_missing")
                    decoder.feed(bytes.fromhex(row["payload"]["chunk_hex"]), row["time_ms_bounds"])
                except (ValueError, TypeError, KeyError):
                    decoder.errors.append("invalid_chunk_hex")
            stream = decoder.report()
            denial = next((r for r in joined if r["payload"]["event"] == "deny"), None)
            opens = [r for r in joined if r["payload"]["event"] == "upstream_open"]
            admission_rows = [r for r in joined if r["payload"]["event"] == "admit"]
            status = next(
                (
                    r["payload"]["http_status"]
                    for r in reversed(client)
                    if r["payload"].get("http_status") is not None
                ),
                denial["payload"].get("http_status") if denial else None,
            )
            terminal = first("terminal") or first("timeout") or first("cancel")
            end = terminal["time_ms_bounds"] if terminal else [self.capture_end] * 2
            if first("missed"):
                outcome = "missed_offer"
                if len(client) != 1:
                    self.errors.append("missed_offer_has_traffic:" + request)
            elif denial and not opens:
                outcome = "rejected"
            elif status is not None and not 200 <= status < 300:
                outcome = (
                    "failed"
                    if opens
                    or any(r["payload"].get("decision") == "allowed" for r in admission_rows)
                    or stream["content_valid"]
                    else "rejected"
                )
            elif stream["complete"] and first("terminal"):
                outcome = "complete"
            elif first("timeout") or (not terminal and not denial):
                outcome = "right_censored"
            else:
                outcome = "failed"
            if not client:
                self.errors.append("unreconciled_offer:" + request)
            if outcome != "missed_offer" and not at("offer"):
                self.errors.append("missing_offer:" + request)
            gateway = offer.get("gateway_uid")
            identities = {
                r["payload"].get("gateway_uid") for r in joined if r["payload"].get("gateway_uid")
            }
            if gateway not in GATEWAYS or identities - {gateway}:
                self.errors.append("gateway_identity_join:" + request)
            if outcome not in ("missed_offer",) and not identities:
                self.errors.append("lost_gateway_identity:" + request)
            route = opens[-1]["payload"] if opens else {}
            client_uids = {
                r["payload"]["backend_uid"] for r in client if r["payload"].get("backend_uid")
            }
            identity_valid = not client_uids or client_uids == {route.get("backend_uid")}
            if not identity_valid:
                self.errors.append("backend_identity_join_mismatch:" + request)
            policies = {r["payload"]["policy"] for r in joined if r["payload"].get("policy")}
            policy = next(iter(policies)) if len(policies) == 1 else None
            if outcome != "missed_offer" and policies != {"round-robin"}:
                self.errors.append("missing_or_mismatched_policy:" + request)
            route_ids = [
                (r["payload"].get("backend_slot"), r["payload"].get("backend_uid"))
                for r in joined
                if r["payload"]["event"] in ("select", "revalidate", "upstream_open")
            ]
            if len(set(route_ids)) > 1:
                self.operational.append(
                    {
                        "reason": "route_changed_between_admit_and_dispatch",
                        "request_id": request,
                        "routes": [list(v) for v in route_ids],
                    }
                )
            if outcome == "complete" and (
                not route.get("backend_uid") or route.get("backend_slot") not in (0, 1)
            ):
                self.errors.append("lost_backend_generation:" + request)
            if at("offer") and end and end[0] - at("offer")[1] > 30_000:
                self.operational.append(
                    {"reason": "request_absolute_timeout_exceeded", "request_id": request}
                )
            payload = (
                denial["payload"]
                if denial
                else next((r["payload"] for r in joined if r["payload"]["event"] == "admit"), {})
            )
            row = {
                **offer,
                "outcome": outcome,
                "partial": stream["content_valid"] and outcome in ("failed", "right_censored"),
                "offer_ms_bounds": at("offer"),
                "receive_ms_bounds": at("receive"),
                "dispatch_ms_bounds": [first("offer")["payload"]["dispatch_ms"]] * 2
                if first("offer") and first("offer")["payload"].get("dispatch_ms") is not None
                else None,
                "admit_ms_bounds": admission_rows[0]["time_ms_bounds"]
                if admission_rows
                else denial["time_ms_bounds"]
                if denial and denial["payload"].get("admit_called") is True
                else None,
                "admit_endpoint_reason": "observed_admission_result"
                if admission_rows or (denial and denial["payload"].get("admit_called") is True)
                else "admission_not_observed_or_not_invoked",
                "identity_join_valid": identity_valid,
                "first_content_ms_bounds": stream["first_content_ms_bounds"],
                "terminal_ms_bounds": end,
                "upstream_open_ms_bounds": opens[-1]["time_ms_bounds"] if opens else None,
                "backend_uid": route.get("backend_uid"),
                "backend_slot": route.get("backend_slot"),
                "reservation_id": route.get("reservation_id"),
                "http_status": status,
                "denial_code": payload.get("denial_code"),
                "retry_after_ms": payload.get("retry_after_ms"),
                "admit_called": payload.get("admit_called"),
                "effective_n": payload.get("effective_n"),
                "effective_b": payload.get("effective_b"),
                "admitted": any(r["payload"].get("decision") == "allowed" for r in admission_rows),
                "retry_count": 0,
                "censor_reason": "request_timeout"
                if first("timeout")
                else "capture_end"
                if outcome == "right_censored"
                else None,
                "stream": stream,
                "terminal_claimed_complete": bool(
                    first("terminal") and first("terminal")["payload"].get("outcome") == "complete"
                ),
                "raw_refs": [r["raw_ref"] for r in joined],
                "config_sha256": offer.get("config_sha256"),
                "policy": policy,
            }
            row["dispatch_reason"] = (
                None
                if row["dispatch_ms_bounds"] is not None
                else "offer_missed"
                if outcome == "missed_offer"
                else "dispatch_timestamp_missing"
            )
            if outcome != "missed_offer" and row["dispatch_ms_bounds"] is None:
                self.errors.append("missing_dispatch_timestamp:" + request)
            row["ttft_ms_bounds"] = (
                elapsed(at("offer"), stream["first_content_ms_bounds"])
                if outcome == "complete"
                else None
            )
            row["e2e_ms_bounds"] = elapsed(at("offer"), end) if outcome == "complete" else None
            if outcome == "complete" and (
                row["ttft_ms_bounds"] is None or row["e2e_ms_bounds"] is None
            ):
                self.errors.append("request_clock_order_unknown:" + request)
            self.cohorts.append(row)

    def coverage(self, boundary: list[int] | None, target_uid: str) -> dict:
        result = {
            g: {"definitely_live": [], "possibly_live": [], "after_first_content": []}
            for g in (*GATEWAYS, "target")
        }
        if boundary is None:
            return {
                "boundary_ms_bounds": None,
                "sets": result,
                "validity_reasons": ["missing_actual_signal"],
            }
        for row in self.cohorts:
            opened = row["upstream_open_ms_bounds"]
            terminal = row["terminal_ms_bounds"]
            if not opened or not terminal:
                continue
            definite = opened[1] < boundary[0] and terminal[0] > boundary[1]
            possible = opened[0] <= boundary[1] and terminal[1] >= boundary[0]
            groups = [row["gateway_uid"]]
            if row["backend_uid"] == target_uid:
                groups.append("target")
            for group in groups:
                if group not in result:
                    continue
                if definite:
                    result[group]["definitely_live"].append(row["request_id"])
                if possible:
                    result[group]["possibly_live"].append(row["request_id"])
                first = row["first_content_ms_bounds"]
                if definite and first and first[1] < boundary[0]:
                    result[group]["after_first_content"].append(row["request_id"])
        errors = [
            "zero_or_ambiguous_sigterm_coverage:" + group
            for group, sets in result.items()
            if not sets["definitely_live"]
        ]
        return {"boundary_ms_bounds": boundary, "sets": result, "validity_reasons": errors}

    def report(self):
        counts = Counter(row["outcome"] for row in self.cohorts)
        denominators = {
            "scheduled": len(self.expected),
            "offered": sum(
                r["outcome"] != "missed_offer" and r["offer_ms_bounds"] is not None
                for r in self.cohorts
            ),
            "dispatched": sum(
                r["dispatch_ms_bounds"] is not None or r["receive_ms_bounds"] is not None
                for r in self.cohorts
            ),
            "admitted": sum(r["admitted"] for r in self.cohorts),
            **{k: counts[k] for k in OUTCOMES},
            "partial": sum(r["partial"] for r in self.cohorts),
        }
        generations = sorted({r["backend_uid"] for r in self.cohorts if r["backend_uid"]})
        groups = {}
        for name, field, values in (
            ("gateway", "gateway_uid", GATEWAYS),
            ("generation", "backend_uid", generations),
            ("code", "denial_code", CODES),
        ):
            groups[name] = {
                str(value): {
                    outcome: sum(
                        r[field] == value and r["outcome"] == outcome for r in self.cohorts
                    )
                    for outcome in OUTCOMES
                }
                for value in values
            }
        unexpected = {
            "partial_after_content": denominators["partial"],
            "false_completion_after_content": sum(
                r["stream"]["content_valid"]
                and r["outcome"] != "complete"
                and r["terminal_claimed_complete"]
                for r in self.cohorts
            ),
        }
        refs = [
            ref
            for r in self.cohorts
            if r["partial"] or (r["stream"]["content_valid"] and r["outcome"] != "complete")
            for ref in r["raw_refs"]
        ]
        return {
            "denominators": denominators,
            "counts": groups,
            "cohorts": self.cohorts,
            "stage1_scope": stage1_scope(unexpected, raw_refs=refs),
            "validity_reasons": sorted(set(self.errors)),
            "operational_outcomes": self.operational,
        }
