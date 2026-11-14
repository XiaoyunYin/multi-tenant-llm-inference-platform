"""Pure offline v4 resolution checks; no marker, AWS adapter or attempt start.

Inputs are already joined, conservatively mapped setup evidence. This module
checks its structure, provenance and predicates; source adapters must still prove
the joins against immutable raw records. A decision is not a durable packet.
All times are integer milliseconds, transfer sizes integer bytes.
"""

import copy
import re
from dataclasses import dataclass

from .inf037b_archive import IntegrityError
from .inf037b_contract import (
    EXPORT_BOUND_MS,
    REGISTRATION_GIT_BLOB_SHA256,
    REGISTRATION_ID,
    SESSION_ENVELOPE_MS,
)

ROWS = ("sse", "equivalence", "publication", "clocks", "ingress", "startup", "lifecycle")
FORMULAS = {
    "sse": "first joined final-30s sample per slot: lower live(g0,g1,target)>=1",
    "equivalence": "B=N*(R+W), N=2/1/0, R=4, W=1; exact pins and controls",
    "publication": "A=install-preceding_store; renewal=next_store-install; TTL=ceil_s(3.1+3+1)",
    "clocks": "max required cross-clock uncertainty<=100ms; max source gap<=2000ms",
    "ingress": "upper(content)<lower(terminal); cancellation release<=35000ms; exact identities",
    "startup": "D_bind=45000+15000+30000; U=max_g upper(completion_g-max(pod,GPU_free))",
    "lifecycle": "L=ceil_60000ms(max(2*O_upper,B)); export=max(L,ceil(2*max_bytes/rate+reconnect))",
}
BOUNDS_MS = {
    "creation": 3_600_000,
    "preparation": 3_600_000,
    "resolution": 120_000,
    "attempt": 1_560_000,
    "reset": 300_000,
    "export": EXPORT_BOUND_MS,
    "cleanup": 1_800_000,
}
PIN_NAMES = {
    "gpu",
    "model",
    "runtime",
    "tokenizer",
    "template",
    "engine",
    "workload",
    "configuration",
    "supervisor",
    "controller",
    "scheduler",
    "manifests",
    "resolver",
}


@dataclass(frozen=True)
class SessionDeadline:
    """Immutable literal UTC ceilings mapped onto the common ms timeline.

    The later controller must obtain t0 from its session_id-keyed durable record,
    not reconstruct it on retries. This value object performs no persistence.
    """

    latest_consume_ms: int
    session_ceiling_ms: int
    billing_origin_ms: int

    def __post_init__(self):
        require(
            all(
                integer(v) and v >= 0
                for v in (
                    self.latest_consume_ms,
                    self.session_ceiling_ms,
                    self.billing_origin_ms,
                )
            ),
            "deadline:values",
        )
        require(
            self.session_ceiling_ms == self.latest_consume_ms + SESSION_ENVELOPE_MS,
            "deadline:literal_session_ceiling",
        )
        require(self.billing_origin_ms <= self.latest_consume_ms, "deadline:t0:range")

    @property
    def effective_ms(self):
        return min(self.session_ceiling_ms, self.billing_origin_ms + SESSION_ENVELOPE_MS)

    def require_unchanged(self, *, latest_consume_ms, session_ceiling_ms):
        exact(
            (latest_consume_ms, session_ceiling_ms),
            (self.latest_consume_ms, self.session_ceiling_ms),
            "deadline:immutable_literals",
        )

    def check_consume(self, now_upper_ms):
        require(integer(now_upper_ms) and now_upper_ms >= 0, "deadline:consume_time")
        require(now_upper_ms <= self.latest_consume_ms, "deadline:late_consume:range")
        require(now_upper_ms <= self.effective_ms, "deadline:consume_effective:range")
        return {"consume_time_admissible": True, "D_eff_ms": self.effective_ms}


def require(condition, reason):
    if not condition:
        raise IntegrityError("v4:" + reason)


def integer(value):
    return type(value) is int


def object_map(value, name):
    require(type(value) is dict, name + ":object")
    return value


def span(value, name):
    require(
        type(value) is list
        and len(value) == 2
        and all(integer(v) for v in value)
        and value[0] <= value[1],
        name + ":interval",
    )
    return value


def within(value, lower, upper, name):
    lo, hi = span(value, name)
    require(lower <= lo and hi <= upper, name + ":range")
    return lo, hi


def minimum(value, lower, name):
    lo, hi = span(value, name)
    require(lo >= lower, name + ":range")
    return lo, hi


def exact(value, expected, name):
    require(type(value) is type(expected) and value == expected, name + ":fixed")
    if type(expected) is dict:
        for key in expected:
            exact(value[key], expected[key], name + ":" + str(key))
    elif type(expected) in (list, tuple):
        for actual, wanted in zip(value, expected, strict=True):
            exact(actual, wanted, name)


def proof(value, name):
    value = object_map(value, name + ":proof")
    require(isinstance(value.get("path"), str) and bool(value["path"].strip()), name + ":path")
    require(
        isinstance(value.get("sha256"), str)
        and re.fullmatch(r"[0-9a-f]{64}", value["sha256"]) is not None,
        name + ":sha256",
    )


def provenance(row, pins, name):
    row = object_map(row, name + ":missing_row")
    exact(row.get("phase"), "bringup", name + ":phase")
    require("attempt_id" in row and row["attempt_id"] is None, name + ":attempt")
    exact(row.get("probe_count"), 1, name + ":probe_count")
    exact(row.get("pins"), pins, name + ":pins")
    require(type(row.get("sources")) is list and bool(row["sources"]), name + ":sources")
    for source in row["sources"]:
        proof(source, name)
        minimum(source.get("sequence"), 0, name + ":sequence")
    observation = minimum(row.get("observation_ms"), 0, name + ":observation")
    within(row.get("clock_uncertainty_ms"), 0, 100, name + ":clock")
    require(
        isinstance(row.get("clock_id"), str) and bool(row["clock_id"].strip()), name + ":clock_id"
    )
    require(
        integer(row.get("selected_ms")) and row["selected_ms"] >= observation[1],
        name + ":selection_time",
    )


def sse(row):
    row = object_map(row, "sse:row")
    for key, value in {
        "duration_ms": 120_000,
        "offers_per_100s": 1092,
        "max_tokens": 1,
        "alternating_gateways": True,
        "pod_deletions": 0,
    }.items():
        exact(row.get(key), value, "sse:" + key)
    for key in ("identity_complete", "supervisor_receipt_joined", "signal_clock_joined"):
        exact(row.get(key), True, "sse:" + key)
    traffic = object_map(row.get("gateway_traffic"), "sse:traffic")
    exact(set(traffic), {"gateway0", "gateway1"}, "sse:traffic_keys")
    for count in traffic.values():
        require(integer(count) and count >= 1, "sse:traffic:range")
    samples = row.get("live_samples")
    require(type(samples) is list and bool(samples), "sse:samples")
    first = {}
    previous = -1
    for sample in samples:
        sample = object_map(sample, "sse:sample")
        at = sample.get("at_ms")
        require(integer(at) and 90_000 <= at <= 120_000 and at >= previous, "sse:window:range")
        previous = at
        slot = sample.get("slot")
        require(integer(slot) and slot in (0, 1), "sse:slot")
        first.setdefault(slot, sample)
    exact(set(first), {0, 1}, "sse:slots")
    # The first joined sample for each slot is authoritative, even if a later one passes.
    for sample in first.values():
        for identity in ("gateway0", "gateway1", "target"):
            minimum(sample.get(identity), 1, "sse:live")
    windows = row.get("windows")
    require(type(windows) is list and len(windows) == 4, "sse:windows")
    for index, window in enumerate(windows):
        window = object_map(window, "sse:window")
        exact(window.get("start_ms"), index * 30_000, "sse:window_start")
        exact(window.get("duration_ms"), 30_000, "sse:window_duration")
        within(window.get("misses_ppm"), 0, 20_000, "sse:misses")
        within(window.get("p95_lateness_ms"), 0, 20, "sse:lateness")
        for key in ("cpu_ppm", "nic_ppm"):
            within(window.get(key), 0, 700_000, "sse:" + key)
    return {"feasible": True, "first_samples": copy.deepcopy(first)}


def equivalence(row):
    row = object_map(row, "equivalence:row")
    for key, value in {
        "block_size": 16,
        "length": 8192,
        "max_seqs": 16,
        "l4_per_node": 1,
        "R": 4,
        "W": 1,
        "ttl_ms": 8000,
        "hold_ms": 2000,
        "operation_store_joined": True,
        "unexplained_reservations": 0,
        "restoration_controls_pass": True,
    }.items():
        exact(row.get(key), value, "equivalence:" + key)
    exact(row.get("effective_pins"), row["pins"], "equivalence:effective_pins")
    exact(
        row.get("workload_config"),
        {
            "prefixes": 384,
            "prefix_tokens": 1024,
            "hot_prefixes": 96,
            "hot_percent": 80,
            "max_tokens": 1,
            "temperature": 0,
            "tenants": 1,
            "policy": "round_robin",
            "affinity": False,
            "escape": False,
            "seed": "inf037b-v1",
            "target_order": [0, 1, 0],
        },
        "equivalence:workload",
    )
    exact(
        row.get("controls"),
        {"known2": 10, "known1": 5, "known0": 0, "expired": "refuse", "unknown": "refuse"},
        "equivalence:controls",
    )
    reports = object_map(row.get("report_ages_ms"), "equivalence:reports")
    exact(set(reports), {"gateway0", "gateway1"}, "equivalence:reports")
    for age in reports.values():
        within(age, 0, 1000, "equivalence:report_age")
    return {"B_by_known_N": {"2": 10, "1": 5, "0": 0}, "ttl_ms": 8000}


def publication(row):
    row = object_map(row, "publication:row")
    for key, value in {
        "ttl_ms": 8000,
        "discovery_ms": 250,
        "health_ms": 250,
        "publication_ms": 250,
        "discovery_timeout_ms": 1000,
        "health_timeout_ms": 1000,
    }.items():
        exact(row.get(key), value, "publication:" + key)
    within(row.get("fresh_health_ms"), 0, 1850, "publication:health")
    gateways = object_map(row.get("gateways"), "publication:gateways")
    exact(set(gateways), {"gateway0", "gateway1"}, "publication:gateways")
    result = {}
    for gateway, item in gateways.items():
        item = object_map(item, "publication:gateway")
        exact(item.get("store_clock_joined"), True, "publication:join")
        order = item.get("atomic_order")
        require(
            type(order) is list
            and len(order) == 3
            and all(integer(n) for n in order)
            and 0 <= order[0] < order[1] < order[2],
            "publication:order",
        )
        prev = span(item.get("preceding_store_ms"), "publication:previous")
        install = span(item.get("install_ms"), "publication:install")
        following = span(item.get("next_store_ms"), "publication:next")
        age = [install[0] - prev[1], install[1] - prev[0]]
        renewal = [following[0] - install[1], following[1] - install[0]]
        within(age, 0, 3000, "publication:A")
        within(renewal, 0, 3100, "publication:renewal")
        result[gateway] = {"A_ms": age, "renewal_ms": renewal}
    return result


def clocks(row):
    row = object_map(row, "clocks:row")
    within(row.get("maximum_uncertainty_ms"), 0, 100, "clocks:uncertainty")
    within(row.get("maximum_gap_ms"), 0, 2000, "clocks:gap")
    exact(row.get("cadence_ms"), 1000, "clocks:cadence")
    for key in (
        "entire_setup",
        "probe_and_both_startups",
        "all_endpoint_sequences_joined",
        "boot_ids_complete",
        "drift_applied",
    ):
        exact(row.get(key), True, "clocks:" + key)
    for key in ("cross_boot_interpolation", "clock_step_interpolation", "overlap_order_assertion"):
        exact(row.get(key), False, "clocks:" + key)
    return {
        "maximum_uncertainty_ms": row["maximum_uncertainty_ms"][1],
        "maximum_gap_ms": row["maximum_gap_ms"][1],
    }


def ingress(row):
    row = object_map(row, "ingress:row")
    for key in ("request_timeout_ms", "transport_drain_ms", "grace_ms"):
        exact(
            row.get(key),
            {"request_timeout_ms": 30_000, "transport_drain_ms": 5000, "grace_ms": 45_000}[key],
            "ingress:" + key,
        )
    joins = object_map(row.get("joins"), "ingress:joins")
    require(set(joins) == {"g0s0", "g0s1", "g1s0", "g1s1"}, "ingress:joins")
    for item in joins.values():
        item = object_map(item, "ingress:join")
        for key in ("identity_exact", "valid_finish_done", "tls", "incremental"):
            exact(item.get(key), True, "ingress:" + key)
        exact(item.get("upstream_attempts"), 1, "ingress:retry")
        exact(item.get("false_completion"), False, "ingress:false_completion")
        content = span(item.get("content_ms"), "ingress:content")
        terminal = span(item.get("terminal_ms"), "ingress:terminal")
        require(content[1] < terminal[0], "ingress:increment_order:range")
    cancellations = object_map(row.get("cancellations"), "ingress:cancellations")
    exact(set(cancellations), {"gateway0", "gateway1"}, "ingress:cancellations")
    for item in cancellations.values():
        item = object_map(item, "ingress:cancellation")
        exact(item.get("count"), 1, "ingress:cancel_count")
        exact(item.get("upstream_closed"), True, "ingress:closed")
        within(item.get("release_elapsed_ms"), 0, 35_000, "ingress:release")
    return {"identity_joins": 4, "cancellation_controls": 2, "incremental_sse": True}


def startup(row):
    row = object_map(row, "startup:row")
    components_ms = object_map(row.get("components_ms"), "startup:components")
    exact(
        components_ms,
        {"grace": 45_000, "kill_release": 15_000, "controller_scheduler": 30_000},
        "startup:components",
    )
    proofs = object_map(row.get("component_proofs"), "startup:proofs")
    require(set(proofs) == set(components_ms), "startup:proofs")
    for name, item in proofs.items():
        item = object_map(item, "startup:component_proof")
        proof(item, "startup:" + name)
        exact(item.get("pins"), row["pins"], "startup:proof_pins")
        exact(item.get("bounded_failure_recovery"), True, "startup:bounded")
    within(row.get("release_elapsed_ms"), 0, 15_000, "startup:release")
    within(row.get("controller_elapsed_ms"), 0, 30_000, "startup:controller")
    for key in (
        "two_slots_restored",
        "probe_traffic_empty",
        "reservations_empty",
        "cached_same_node",
        "cached_files_verified",
        "no_cache_population",
        "setup_pod_exit_gpu_release",
        "no_rollout",
        "cold_model_cache_empty",
    ):
        exact(row.get(key), True, "startup:" + key)
    exact(row.get("case_order"), ["cold", "node_cached"], "startup:case_order")
    cases = object_map(row.get("cases"), "startup:cases")
    require(set(cases) == {"cold", "node_cached"}, "startup:cases")
    result = {}
    d_bind = sum(components_ms.values())
    require(d_bind <= 90_000, "startup:D_bind:range")
    for name, case in cases.items():
        case = object_map(case, "startup:case")
        for key in (
            "model_cache_verified",
            "image_cache_known",
            "lifecycle_lineage",
            "clocks_joined",
        ):
            exact(case.get(key), True, "startup:" + key)
        creation = span(case.get("pod_creation_ms"), "startup:pod")
        free = span(case.get("gpu_free_ms"), "startup:gpu")
        start = [max(creation[0], free[0]), max(creation[1], free[1])]
        completions = object_map(case.get("completions_ms"), "startup:gateways")
        require(set(completions) == {"gateway0", "gateway1"}, "startup:gateways")
        upper = 0
        for completion in completions.values():
            lo, hi = span(completion, "startup:completion")
            require(lo >= start[1], "startup:completion_order")
            upper = max(upper, hi - start[0])
        within([0, upper], 0, 210_000, "startup:U")
        require(d_bind + upper <= 300_000, "startup:D_bind_plus_U:range")
        result[name] = {"t_start_ms": start, "U_ms": upper, "D_bind_plus_U_ms": d_bind + upper}
    cold_completion_upper = max(
        span(value, "startup:completion")[1] for value in cases["cold"]["completions_ms"].values()
    )
    cached_gpu_free_lower = span(cases["node_cached"]["gpu_free_ms"], "startup:gpu")[0]
    require(
        cold_completion_upper < cached_gpu_free_lower,
        "startup:case_order_times",
    )
    return {"D_bind_ms": d_bind, "cases": result}


def ceil_minute(numerator, denominator=1):
    return ((numerator + denominator * 60_000 - 1) // (denominator * 60_000)) * 60_000


def allowance(phase, observations, offline_bound_ms):
    """Separate O range and post-rounding L ceiling, both fail closed."""
    require(phase in BOUNDS_MS, "allowance:phase")
    bound = BOUNDS_MS[phase]
    exact(offline_bound_ms, bound, "allowance:offline_bound")
    count = {"attempt": 3, "reset": 2}.get(phase, 1)
    require(type(observations) is list and len(observations) == count, "allowance:observations")
    upper = max(within(o, 0, bound // 2, "allowance:" + phase)[1] for o in observations)
    resolved = ceil_minute(max(2 * upper, offline_bound_ms))
    require(resolved <= bound, "allowance:L_ceiling")
    return resolved


def lifecycle(row):
    row = object_map(row, "lifecycle:row")
    phases = object_map(row.get("phases"), "lifecycle:phases")
    require(set(phases) == set(BOUNDS_MS), "lifecycle:phases")
    resolved = {}
    for name, item in phases.items():
        item = object_map(item, "lifecycle:phase")
        proof(item.get("offline_proof"), "lifecycle:" + name)
        exact(item["offline_proof"].get("pins"), row["pins"], "lifecycle:proof_pins")
        exact(item["offline_proof"].get("bounded_failure_recovery"), True, "lifecycle:bounded")
        resolved[name] = allowance(name, item.get("observations_ms"), item.get("offline_bound_ms"))
    exact(row.get("creation_from_t0"), True, "lifecycle:t0")
    exact(row.get("cleanup_nonmutating"), True, "lifecycle:cleanup")
    exact(row.get("replay_nonmutating"), True, "lifecycle:replay")
    exact(
        row.get("replay_virtual_schedule_ms"), [1_560_000] * 3 + [300_000] * 2, "lifecycle:schedule"
    )
    export = object_map(row.get("transfer"), "lifecycle:transfer")
    proof(export.get("sizing_proof"), "lifecycle:sizing")
    exact(export.get("attempts"), 3, "lifecycle:attempts")
    exact(export.get("reset_durations_ms"), [300_000, 300_000], "lifecycle:resets")
    exact(export.get("full_fixture_sanitized_and_verified"), True, "lifecycle:verified_transfer")
    exact(export.get("uses_rollout_compression"), False, "lifecycle:compression")
    raw, rate, reconnect = (
        export.get(k) for k in ("raw_bytes", "minimum_bytes_per_second", "reconnect_ms")
    )
    require(
        integer(raw)
        and raw > 0
        and integer(rate)
        and rate > 0
        and integer(reconnect)
        and reconnect >= 0,
        "lifecycle:transfer_values",
    )
    maximum = 2 * raw
    exact(export.get("maximum_archive_bytes"), maximum, "lifecycle:raw_margin")
    # Keep both factors of two: archive record margin, then transfer safety margin.
    transfer = ceil_minute(2 * maximum * 1000 + reconnect * rate, rate)
    resolved["export"] = max(resolved["export"], transfer)
    require(resolved["export"] <= EXPORT_BOUND_MS, "lifecycle:export_ceiling:range")
    return resolved


def remaining_work(
    *,
    now_upper_ms,
    deadline,
    allowances,
    attempts,
    resets,
    unspent_setup_ms,
    before_attempt1=False,
):
    require(type(deadline) is SessionDeadline, "remaining:immutable_deadline")
    deadline_ms = deadline.effective_ms
    require(type(allowances) is dict and set(allowances) == set(BOUNDS_MS), "remaining:allowances")
    for name, bound in BOUNDS_MS.items():
        exact(allowances[name], bound, "remaining:" + name)
    require(
        all(
            integer(v) and v >= 0
            for v in (now_upper_ms, deadline_ms, attempts, resets, unspent_setup_ms)
        ),
        "remaining:values",
    )
    require(
        (attempts, resets) in {(3, 2), (2, 2), (2, 1), (1, 1), (1, 0), (0, 0)},
        "remaining:counts",
    )
    if before_attempt1:
        exact((attempts, resets), (3, 2), "remaining:initial_counts")
    total = (
        attempts * allowances["attempt"]
        + resets * allowances["reset"]
        + allowances["export"]
        + allowances["cleanup"]
        + unspent_setup_ms
    )
    if before_attempt1:
        require(
            now_upper_ms
            + 5_280_000
            + allowances["export"]
            + allowances["cleanup"]
            + unspent_setup_ms
            <= deadline_ms,
            "remaining:campaign:range",
        )
    require(now_upper_ms + total <= deadline_ms, "remaining:deadline:range")
    return {"remaining_ms": total, "latest_finish_ms": now_upper_ms + total}


def resolve(rows, *, pins):
    """Return an inspectable decision only after every v4 row passes."""
    if type(pins) is not dict:
        require(False, "pins")
    require(
        set(pins) == PIN_NAMES
        and all(isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v) for v in pins.values()),
        "pins",
    )
    if type(rows) is not dict:
        require(False, "rows")
    require(set(rows) == set(ROWS), "rows")
    validators = (sse, equivalence, publication, clocks, ingress, startup, lifecycle)
    decisions = {}
    for name, validator in zip(ROWS, validators, strict=True):
        try:
            provenance(rows[name], pins, name)
            decisions[name] = {
                "admissible": True,
                "result": validator(rows[name]),
                "formula": FORMULAS[name],
                "evidence": copy.deepcopy(rows[name]),
            }
        except IntegrityError:
            raise
        except Exception as error:
            raise IntegrityError(f"v4:{name}:malformed") from error
    return {
        "registration_id": REGISTRATION_ID,
        "registration_sha256": REGISTRATION_GIT_BLOB_SHA256,
        "rows": decisions,
        "allowances_ms": decisions["lifecycle"]["result"],
        "paid_ready": False,
        "basis": "offline_joined_setup_evidence_not_durable_packet",
    }
