"""Per-gateway classifications (:64, :78-85, :106). Inputs are already joined.

Missing join/clock evidence is a validity reason and leaves the status null.
Slice 4b will produce these inputs from independently captured source records.
"""

from dataclasses import dataclass

from .inf037b_contract import (
    AGE_MS,
    GATEWAYS,
    MAX_TOKENS,
    RENEWAL_MS,
    STAGE1_CATEGORIES,
    UNEXERCISED,
    BudgetStatus,
    nonnegative,
)


@dataclass(frozen=True)
class Bounds:
    """A measured bracket, in ms on one mapped clock (:25, :31)."""

    lower: int
    upper: int

    def __post_init__(self) -> None:
        nonnegative(self.lower, "lower")
        nonnegative(self.upper, "upper")
        if self.lower > self.upper:
            raise ValueError("reversed bracket")

    def json(self) -> list[int]:
        return [self.lower, self.upper]


def classify(bounds: Bounds, limit_ms: int, *, open_interval: bool = False) -> dict:
    """An unfinished quantity cannot be classified within/indeterminate (:80-85)."""
    nonnegative(limit_ms, "limit_ms")
    if bounds.lower > limit_ms:
        status, reason = BudgetStatus.EXCEEDED, "lower_bound_above_limit"
    elif open_interval:
        status, reason = BudgetStatus.RIGHT_CENSORED, "attempt_end"
    elif bounds.upper <= limit_ms:
        status, reason = BudgetStatus.WITHIN, "upper_bound_at_or_below_limit"
    else:
        status, reason = BudgetStatus.INDETERMINATE, "measured_uncertainty_straddles_limit"
    return {
        "status": status.value,
        "reason": reason,
        "bounds_ms": bounds.json(),
        "elapsed_lower_bound_ms": bounds.lower if open_interval else None,
        "terminal_open": open_interval,
    }


def gateway_budget(
    gateway: str,
    replacement_uid: str,
    *,
    capture_end: Bounds,
    capture_complete: bool,
    installation: Bounds | None = None,
    preceding_store_ms: int | None = None,
    renewal_store: Bounds | None = None,
    clock_evidence: bool = True,
    store_order_evidenced: bool = True,
    noninstallation_reason: str = "replacement_not_installed_before_attempt_end",
) -> dict:
    if gateway not in GATEWAYS or not replacement_uid:
        raise ValueError("gateway/replacement identity required")
    result = {
        "gateway_uid": gateway,
        "replacement_uid": replacement_uid,
        "install_redis_ms_bounds": installation.json() if installation else None,
        "last_complete_report_redis_ms": preceding_store_ms,
        "capture_end_ms_bounds": capture_end.json(),
        "renewal_store_ms_bounds": renewal_store.json() if renewal_store else None,
        "age_budget_status": None,
        "renewal_budget_status": None,
        "age_budget_reason": None,
        "renewal_budget_reason": None,
        "addition_report_age_ms_bounds": None,
        "renewal_elapsed_ms_bounds": None,
        "age_elapsed_lower_bound_ms": None,
        "renewal_elapsed_lower_bound_ms": None,
        "validity_reasons": [],
    }
    reasons = result["validity_reasons"]
    if not capture_complete:
        reasons.append("incomplete_installation_capture")
    if not clock_evidence:
        reasons.append("missing_required_clock_evidence")
    if reasons:
        return result
    if installation is None:
        if preceding_store_ms is not None or renewal_store is not None:
            reasons.append("endpoint_without_installation")
            return result
        if not noninstallation_reason:
            raise ValueError("not_applicable requires reason")
        for kind in ("age", "renewal"):
            result[f"{kind}_budget_status"] = BudgetStatus.NOT_APPLICABLE.value
            result[f"{kind}_budget_reason"] = noninstallation_reason
        return result
    if installation.upper > capture_end.lower:
        reasons.append("installation_capture_end_order_unknown")
        return result
    if preceding_store_ms is None or not store_order_evidenced:
        reasons.append("missing_preceding_report_store_join")
    else:
        nonnegative(preceding_store_ms, "preceding_store_ms")
        if preceding_store_ms > installation.lower:
            reasons.append("report_not_proven_preceding_by_store_time")
        else:
            age = Bounds(
                installation.lower - preceding_store_ms, installation.upper - preceding_store_ms
            )
            classified = classify(age, AGE_MS)
            result["age_budget_status"] = classified["status"]
            result["age_budget_reason"] = classified["reason"]
            result["addition_report_age_ms_bounds"] = age.json()
    end = renewal_store or capture_end
    if renewal_store and renewal_store.upper > capture_end.upper:
        reasons.append("renewal_after_capture_end")
    elif end.lower < installation.upper:
        reasons.append("renewal_clock_order_unknown")
    else:
        elapsed = Bounds(end.lower - installation.upper, end.upper - installation.lower)
        classified = classify(elapsed, RENEWAL_MS, open_interval=renewal_store is None)
        result["renewal_budget_status"] = classified["status"]
        result["renewal_budget_reason"] = classified["reason"]
        result["renewal_elapsed_ms_bounds"] = elapsed.json()
        result["renewal_elapsed_lower_bound_ms"] = classified["elapsed_lower_bound_ms"]
    return result


def both_gateways(replacement_uid: str, **inputs: dict) -> list[dict]:
    if set(inputs) != set(GATEWAYS):
        raise ValueError("summaries required for both gateways")
    return [gateway_budget(g, replacement_uid, **inputs[g]) for g in GATEWAYS]


def stage1_scope(observed: dict[str, int] | None = None, *, raw_refs: list | None = None) -> dict:
    """Only claim-boundary objects, not stage/cohort reconciliation (:15, :106)."""
    observed = observed or {}
    if set(observed) - set(STAGE1_CATEGORIES):
        raise ValueError("unknown Stage 1 category")
    result = {"max_tokens": MAX_TOKENS, "sigterm_coverage_scope": "queued_or_prefill"}
    for category in STAGE1_CATEGORIES:
        count = nonnegative(observed.get(category, 0), category)
        if count and not raw_refs:
            raise ValueError("unexpected nonzero outcome requires raw references")
        result[category] = {"count": count, "coverage": UNEXERCISED}
    result["raw_refs"] = raw_refs or []
    return result
