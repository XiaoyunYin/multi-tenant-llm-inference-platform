"""Source-bound startup feasibility (:72); all fixtures are synthetic, not timing claims."""

from dataclasses import dataclass

from .inf037b_budget import Bounds
from .inf037b_contract import (
    CACHE_STATES,
    CLOCK_UNCERTAINTY_MS,
    DBIND_COMPONENTS,
    GATEWAYS,
    IMAGE_CACHE_STATES,
    MIN_GRACE_MS,
    USABLE_MS,
    nonnegative,
)


@dataclass(frozen=True)
class SourceBracket:
    """Observation interval and required clock-mapping uncertainty (:25)."""

    bounds: Bounds
    source: str
    pins: dict[str, str]
    clock_id: str
    evidence_ref: str
    mapping_uncertainty_ms: int | None


@dataclass(frozen=True)
class Component:
    name: str
    bound_ms: int | None
    source: str
    pins: dict[str, str]


@dataclass(frozen=True)
class StartupCase:
    model_cache: str
    image_cache: str
    pod_creation: SourceBracket | None
    gpu_free: SourceBracket | None
    usable_by_gateway: dict[str, SourceBracket]
    signal_evidence: str
    cache_evidence: str


def startup_fitness(
    *,
    components: list[Component],
    configured_grace_ms: int,
    cases: list[StartupCase],
    required_pins: dict[str, str],
) -> dict:
    """Each component, including additional allowances, needs its own source and pins.

    Controller kind/configuration, Kubernetes version and runtime/model/manifests
    are caller-resolved pins; empty EKS defaults cannot constitute fitness evidence.
    """
    nonnegative(configured_grace_ms, "configured_grace_ms")
    reasons = []
    expected = {"controller", "configuration_sha256", "kubernetes_version"}
    if not expected <= required_pins.keys() or not all(required_pins.values()):
        reasons.append("unresolved_controller_configuration_or_kubernetes_pin")
    names = [c.name for c in components]
    if len(set(names)) != len(names) or not set(DBIND_COMPONENTS) <= set(names):
        reasons.append("missing_or_duplicate_d_bind_component")
    total = 0
    for c in components:
        if c.bound_ms is None:
            reasons.append(f"unbounded_component:{c.name}")
        else:
            total += nonnegative(c.bound_ms, c.name)
        if not c.source:
            reasons.append(f"unsourced_component:{c.name}")
        if (
            not required_pins
            or not c.pins
            or any(not value or c.pins.get(key) != value for key, value in required_pins.items())
        ):
            reasons.append(f"unpinned_component:{c.name}")
        if c.name == "termination_grace" and c.bound_ms != configured_grace_ms:
            reasons.append("grace_does_not_match_configured_value")
    if configured_grace_ms < MIN_GRACE_MS:
        reasons.append("configured_grace_below_registered_minimum")
    if sorted(c.model_cache for c in cases) != sorted(CACHE_STATES):
        reasons.append("require_one_cold_and_one_node_cached_case")
    reports = []
    for case in cases:
        invalid = []
        if case.model_cache not in CACHE_STATES or case.image_cache not in IMAGE_CACHE_STATES:
            invalid.append("unknown_cache_state")
        if not case.signal_evidence:
            invalid.append("missing_signal_evidence")
        if not case.cache_evidence:
            invalid.append("missing_cache_evidence")
        if set(case.usable_by_gateway) != set(GATEWAYS):
            invalid.append("missing_gateway_usable_completion")
        brackets = [case.pod_creation, case.gpu_free, *case.usable_by_gateway.values()]
        if len({b.clock_id for b in brackets if b is not None}) > 1:
            invalid.append("unrelated_mapped_clock_timelines")
        for b in brackets:
            if b is None:
                invalid.append("missing_source_clock_bracket")
            elif (
                not b.source
                or not b.clock_id
                or not b.evidence_ref
                or not b.pins
                or any(not v or b.pins.get(k) != v for k, v in required_pins.items())
            ):
                invalid.append("unsourced_or_unpinned_clock_bracket")
            else:
                uncertainty = getattr(b, "mapping_uncertainty_ms", None)
                if uncertainty is None:
                    invalid.append("missing_clock_mapping")
                elif nonnegative(uncertainty, "mapping_uncertainty_ms") > CLOCK_UNCERTAINTY_MS:
                    invalid.append("clock_uncertainty_exceeds_registered_bound")
        report = {"model_cache": case.model_cache, "t_start_ms_bounds": None, "gateways": {}}
        if not invalid and case.pod_creation and case.gpu_free:
            pod_uncertainty = case.pod_creation.mapping_uncertainty_ms
            gpu_uncertainty = case.gpu_free.mapping_uncertainty_ms
            start_lower = max(
                case.pod_creation.bounds.lower - pod_uncertainty,
                case.gpu_free.bounds.lower - gpu_uncertainty,
            )
            start_upper = max(
                case.pod_creation.bounds.upper + pod_uncertainty,
                case.gpu_free.bounds.upper + gpu_uncertainty,
            )
            report["t_start_ms_bounds"] = [start_lower, start_upper]
            for gateway, usable in case.usable_by_gateway.items():
                usable_uncertainty = usable.mapping_uncertainty_ms
                usable_lower = usable.bounds.lower - usable_uncertainty
                usable_upper = usable.bounds.upper + usable_uncertainty
                if usable_lower < start_upper:
                    invalid.append(f"usable_start_order_unknown:{gateway}")
                    continue
                upper = usable_upper - start_lower
                combined = total + upper
                report["gateways"][gateway] = {
                    "measured_upper_ms": upper,
                    "d_bind_plus_upper_ms": combined,
                    "fits": combined <= USABLE_MS,
                }
                if combined > USABLE_MS:
                    invalid.append(f"startup_deadline_infeasible:{gateway}")
        report["reasons"] = invalid
        reports.append(report)
        reasons.extend(f"{case.model_cache}:{r}" for r in invalid)
    return {
        "fit": not reasons,
        "d_bind_ms": total if all(c.bound_ms is not None for c in components) else None,
        "components": [
            {"name": c.name, "bound_ms": c.bound_ms, "source": c.source, "pins": c.pins}
            for c in components
        ],
        "cases": reports,
        "reasons": reasons,
        "readiness_action": "continue_resolved_packet" if not reasons else "stop_readiness",
    }
