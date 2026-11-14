"""Pure offline v4 export admission. Raw observations in; decision receipt out.

No command execution, network, scheduling or export is performed. Producers must
attest a complete node pod census and authoritative scheduler evidence; slice (4)
must implement and prove those adapters. Timestamps share SessionDeadline's ms axis.
"""

import copy
import hashlib
import re
from dataclasses import dataclass
from fractions import Fraction

from .inf037b_archive import IntegrityError, strict_json
from .inf037b_contract import MAX_PLACEMENT_OBSERVATION_AGE_MS
from .inf037b_resolver import BOUNDS_MS, SessionDeadline, exact, integer, require

MEMORY_BYTES = 12_884_901_888
SCALES = {
    "": 1,
    "n": Fraction(1, 10**9),
    "u": Fraction(1, 10**6),
    "m": Fraction(1, 1000),
    "k": 1000,
    "M": 1000**2,
    "G": 1000**3,
    "T": 1000**4,
    "P": 1000**5,
    "E": 1000**6,
    **{unit + "i": 1024**power for power, unit in enumerate("KMGTPE", 1)},
}
INPUTS = {"job", "pod", "node", "requests", "placement", "verified"}
ISOLATED_ROLES = ("gateway", "redis", "generator", "coordinator", "replay")
ISOLATION_POLICY = [
    {
        "labelSelector": {
            "matchExpressions": [
                {"key": "inf037b-role", "operator": "In", "values": list(ISOLATED_ROLES)}
            ]
        },
        "topologyKey": "kubernetes.io/hostname",
        "namespaceSelector": {},
    }
]


def quantity_bytes(raw):
    """Nonnegative decimal mantissa with explicit SI/binary suffix; no rounding.

    Exponent notation, signs, whitespace and all other grammars are refused.
    Kubernetes can round fractional bytes; this admission contract refuses them.
    """
    require(type(raw) is str, "placement:quantity_string")
    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)([a-zA-Z]*)", raw)
    require(match is not None, "placement:quantity_format")
    number, suffix = match.groups()
    require(suffix in SCALES, "placement:quantity_suffix")
    value = Fraction(number) * SCALES[suffix]
    require(value.denominator == 1, "placement:integer_bytes")
    return value.numerator


@dataclass(frozen=True)
class Observation:
    raw: bytes
    observed_ms: int


def decode(observation, now_ms, record):
    require(type(observation) is Observation, "placement:observation")
    require(type(observation.raw) is bytes, "placement:raw_bytes")
    record["sha256"] = hashlib.sha256(observation.raw).hexdigest()
    record["observed_ms"] = observation.observed_ms
    require(
        integer(observation.observed_ms) and 0 <= observation.observed_ms <= now_ms,
        "placement:observation_time",
    )
    try:
        return strict_json(observation.raw)
    except RecursionError:
        raise IntegrityError("placement:json_recursion") from None


def text(value):
    require(type(value) is str and bool(value), "placement:identity")
    return value


def inspect_phase(values, identity, receipt, phase):
    job, pod, node, census, placement = (
        values[key] for key in ("job", "pod", "node", "requests", "placement")
    )
    # Raw API hashes remain in the receipt. Only server default/gate mechanics
    # are normalized for this existing evaluator; resources and isolation are
    # compared from both objects without replacement.
    job, pod = copy.deepcopy(job), copy.deepcopy(pod)
    template = job["spec"]["template"]["spec"]
    template.pop("schedulingGates", None)
    pod["spec"].pop("schedulingGates", None)
    for key in (
        "serviceAccountName",
        "serviceAccount",
        "automountServiceAccountToken",
        "enableServiceLinks",
        "priority",
        "schedulerName",
        "securityContext",
        "dnsPolicy",
        "terminationGracePeriodSeconds",
        "preemptionPolicy",
        "imagePullSecrets",
        "tolerations",
    ):
        if key not in template and key in pod["spec"]:
            template[key] = copy.deepcopy(pod["spec"][key])
    # Admission's standard service-account projection does not change requests.
    defaults = [
        v
        for v in pod["spec"].get("volumes", [])
        if v["name"].startswith("kube-api-access-") and set(v) == {"name", "projected"}
    ]
    if "volumes" not in template and defaults:
        template["volumes"] = defaults
    if len(template["containers"]) == len(pod["spec"]["containers"]):
        for declared, actual in zip(template["containers"], pod["spec"]["containers"], strict=True):
            for key in ("imagePullPolicy", "terminationMessagePath", "terminationMessagePolicy"):
                if key not in declared and key in actual:
                    declared[key] = copy.deepcopy(actual[key])
            if "volumeMounts" not in declared:
                mounts = [
                    m
                    for m in actual.get("volumeMounts", [])
                    if m.get("name") in {v["name"] for v in defaults} and m.get("readOnly") is True
                ]
                if mounts:
                    declared["volumeMounts"] = mounts
    join = {
        "job_uid": job["metadata"]["uid"],
        "pod_uid": pod["metadata"]["uid"],
        "pod_node_name": pod["spec"].get("nodeName"),
        "node_name": node["metadata"]["name"],
        "node_uid": node["metadata"]["uid"],
    }
    receipt["join"] = join
    spec = job["spec"]["template"]["spec"]
    exact(values["verified"], identity, "placement:refreshed_identity")
    containers = spec["containers"]
    require(type(containers) is list and len(containers) == 1, "placement:single_container")
    resources = containers[0]["resources"]
    quantities = {}
    errors = []
    # Read all three independently so known sizes survive a missing proof.
    for field, owner, key in (
        ("allocatable_bytes", node["status"].get("allocatable", {}), "memory"),
        ("request_bytes", resources.get("requests", {}), "memory"),
        ("limit_bytes", resources.get("limits", {}), "memory"),
    ):
        try:
            quantities[field] = quantity_bytes(owner[key])
            receipt[field] = quantities[field]
        except (ValueError, KeyError, TypeError) as exc:
            errors.append(field + ":" + str(exc))
    require(not errors, "placement:memory_proof:" + repr(errors))
    allocatable, request, limit = (
        quantities[field] for field in ("allocatable_bytes", "request_bytes", "limit_bytes")
    )
    for key in ("job_uid", "pod_uid", "node_name", "node_uid"):
        text(join[key])
    exact(spec.get("nodeName", identity["name"]), identity["name"], "placement:job_node")
    if phase == "pre_schedule":
        require("nodeName" not in pod["spec"], "placement:pre_schedule_bound")
        exact(pod["spec"], spec, "placement:pod_spec")
        expected_placement = {
            "scheduled": False,
            "job_uid": join["job_uid"],
            "pod_uid": join["pod_uid"],
        }
    else:
        exact(pod["spec"], dict(spec, nodeName=join["pod_node_name"]), "placement:pod_spec")
        exact(join["pod_node_name"], identity["name"], "placement:pod_node")
        expected_placement = {
            "scheduled": True,
            "job_uid": join["job_uid"],
            "pod_uid": join["pod_uid"],
            "node_name": identity["name"],
            "node_uid": identity["uid"],
        }
    exact(join["node_name"], identity["name"], "placement:node_name")
    exact(join["node_uid"], identity["uid"], "placement:node_uid")
    exact(
        [{"uid": owner["uid"]} for owner in pod["metadata"]["ownerReferences"]],
        [{"uid": join["job_uid"]}],
        "placement:job_owner",
    )
    require(not spec.get("initContainers") and not spec.get("overhead"), "placement:extra_memory")
    exact(request, MEMORY_BYTES, "placement:request")
    exact(limit, MEMORY_BYTES, "placement:limit")
    # Every required term must pin the node; accepting one OR term is unsafe.
    if "nodeSelector" in spec:
        exact(
            spec["nodeSelector"], {"kubernetes.io/hostname": identity["name"]}, "placement:selector"
        )
        exact(
            node["metadata"]["labels"]["kubernetes.io/hostname"],
            identity["name"],
            "placement:hostname",
        )
    else:
        terms = spec["affinity"]["nodeAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"][
            "nodeSelectorTerms"
        ]
        exact(
            terms,
            [
                {
                    "matchFields": [
                        {"key": "metadata.name", "operator": "In", "values": [identity["name"]]}
                    ]
                }
            ],
            "placement:affinity",
        )
    exact(census["complete"], True, "placement:census_complete")
    exact(census["node"], identity, "placement:census_node")
    require(type(census["pods"]) is list, "placement:census_pods")
    seen = set()
    other, other_terminal = 0, 0
    terminal = []
    receipt["terminal_pods"] = terminal
    receipt["terminal_requests_bytes"] = 0
    for assigned in census["pods"]:
        uid = text(assigned["uid"])
        require(uid not in seen, "placement:duplicate_pod")
        seen.add(uid)
        exact(assigned["node_name"], identity["name"], "placement:assigned_node")
        requests = assigned["memory_requests"]
        require(type(requests) is list and bool(requests), "placement:assigned_requests")
        requested = sum(quantity_bytes(value) for value in requests)
        is_terminal = assigned.get("phase") in ("Succeeded", "Failed")
        if is_terminal:
            terminal.append({"uid": uid, "phase": assigned["phase"], "memory_bytes": requested})
            receipt["terminal_requests_bytes"] += requested
        if uid == join["pod_uid"]:
            require(phase != "pre_schedule", "placement:census_unbound_pod")
            exact(requested, request, "placement:own_request")
        else:
            other += requested
            if is_terminal:
                other_terminal += requested
    receipt["other_requests_bytes"] = other
    receipt["residual_bytes"] = allocatable - other
    require(allocatable >= MEMORY_BYTES, "placement:allocatable")
    require(
        allocatable - other >= MEMORY_BYTES,
        "placement:residual_terminal_counted" if other_terminal else "placement:residual",
    )
    exact(
        placement,
        expected_placement,
        "placement:scheduler_join",
    )
    exact(
        spec["affinity"]["podAntiAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"],
        ISOLATION_POLICY,
        "placement:isolation_policy",
    )
    roles = []
    for assigned in census["pods"]:
        role = assigned.get("role")
        require(role in (*ISOLATED_ROLES, "export", "system"), "placement:unknown_role")
        require(role not in ISOLATED_ROLES, "placement:isolated_node")
        roles.append({"uid": assigned["uid"], "role": role})
    receipt["isolation"] = {
        "verified": True,
        "excluded_roles": list(ISOLATED_ROLES),
        "assigned_roles": roles,
        "policy": ISOLATION_POLICY,
    }
    return {key: join[key] for key in ("job_uid", "pod_uid", "node_name", "node_uid")}


def check_placement(
    *, verified, pre_schedule, pre_export, deadline, now_ms, control=None, stage=None
):
    """Return a serializable receipt on success AND refusal, without side effects.

    Each phase is a map of the five INPUTS to Observation(raw JSON bytes, time).
    verified is a sixth raw observation with exactly the verified name and UID.
    Unknown receipt fields remain null on refusal; hashes survive malformed JSON.
    """
    receipt = {
        "schema": "inf037b-export-placement-v4",
        "decision": "REFUSE",
        "reason": None,
        "now_ms": now_ms,
        "pre_export_age_ms": None,
        "D_eff_ms": None,
        "cleanup_reserve_ms": BOUNDS_MS["cleanup"],
        "export_bound_ms": BOUNDS_MS["export"],
        "sources": {},
        "phases": {},
    }
    try:
        require(stage in (None, "pre_schedule"), "placement:stage")
        phases = (
            (("pre_schedule", pre_schedule),)
            if stage
            else (("pre_schedule", pre_schedule), ("pre_export", pre_export))
        )
        # Hash ALL supplied inputs before interpreting any; retain later sources
        # even if an earlier observation is malformed or fails a predicate.
        observations = {"verified": verified}
        errors = []
        for phase, inputs in phases:
            receipt["phases"][phase] = dict.fromkeys(
                (
                    "join",
                    "allocatable_bytes",
                    "request_bytes",
                    "limit_bytes",
                    "other_requests_bytes",
                    "residual_bytes",
                    "terminal_pods",
                    "terminal_requests_bytes",
                )
            )
            if type(inputs) is not dict:
                errors.append("placement:phase_inputs:" + phase)
                continue
            observations.update({phase + "/" + key: value for key, value in inputs.items()})
        decoded = {}
        for name, observation in observations.items():
            record = {}
            receipt["sources"][name] = record
            try:
                decoded[name] = decode(observation, now_ms, record)
            except (IntegrityError, ValueError, TypeError) as exc:
                errors.append(str(exc))
        require(integer(now_ms) and now_ms >= 0, "placement:now")
        require(type(deadline) is SessionDeadline, "placement:deadline")
        receipt["D_eff_ms"] = deadline.effective_ms
        require(not errors, "placement:source:" + repr(errors))
        if stage is None and set(pre_export) == INPUTS:
            receipt["pre_export_age_ms"] = now_ms - min(
                observation.observed_ms for observation in pre_export.values()
            )
        identity = decoded["verified"]
        exact(set(identity), {"name", "uid"}, "placement:verified_keys")
        text(identity["name"])
        text(identity["uid"])
        joins = []
        for phase, inputs in phases:
            try:
                exact(set(inputs), INPUTS, "placement:inputs")
                values = {key: decoded[phase + "/" + key] for key in INPUTS}
                joins.append(inspect_phase(values, identity, receipt["phases"][phase], phase))
            except (IntegrityError, KeyError, TypeError, ValueError, AttributeError) as exc:
                errors.append(phase + ":" + str(exc))
        require(not errors, "placement:proof:" + repr(errors))
        if stage is None:
            exact(joins[0], joins[1], "placement:identity_changed")
        require(now_ms >= deadline.billing_origin_ms, "placement:before_origin")
        for observation in observations.values():
            require(
                observation.observed_ms >= deadline.billing_origin_ms,
                "placement:observation_before_origin",
            )
        latest_pre_schedule = max(observation.observed_ms for observation in pre_schedule.values())
        for observation in (pre_export or {}).values():
            require(observation.observed_ms > latest_pre_schedule, "placement:time_order")
        require(
            now_ms + BOUNDS_MS["export"] + BOUNDS_MS["cleanup"] <= deadline.effective_ms,
            "placement:export_cleanup_fit",
        )
        require(type(control) is dict, "placement:control_required")
        exact(control[stage or "pre_export"]["signal_ms"], now_ms, "placement:signal_endpoint")
        overhead = 0
        for phase, inputs in phases:
            evidence = control[phase]
            require(
                all(
                    type(v) is str and bool(v) for v in (evidence["clock_id"], evidence["boot_id"])
                ),
                "placement:control_clock",
            )
            exact(
                (evidence["clock_id"], evidence["boot_id"]),
                (control["pre_schedule"]["clock_id"], control["pre_schedule"]["boot_id"]),
                "placement:control_boot",
            )
            exact(evidence["acknowledged"], True, "placement:durable_ack")
            exact(evidence["received_once"], True, "placement:received_signal")
            decision, ack, signal = (
                evidence[key] for key in ("decision_ms", "ack_ms", "signal_ms")
            )
            require(all(integer(v) for v in (decision, ack, signal)), "placement:control_times")
            require(0 <= decision <= ack <= signal <= now_ms, "placement:signal_order")
            exact(evidence["pod_uid"], joins[0]["pod_uid"], "placement:signal_uid")
            hashes = {key: receipt["sources"][phase + "/" + key]["sha256"] for key in INPUTS}
            exact(evidence["source_hashes"], hashes, "placement:signal_hashes")
            starts = []
            for key, observation in inputs.items():
                read = evidence["reads"][key]
                start, end = read["ms"]
                exact(
                    (read["clock_id"], read["boot_id"]),
                    (evidence["clock_id"], evidence["boot_id"]),
                    "placement:read_clock",
                )
                require(
                    integer(read["uncertainty_ms"]) and 0 <= read["uncertainty_ms"] <= 100,
                    "placement:read_uncertainty",
                )
                require(
                    integer(start)
                    and integer(end)
                    and deadline.billing_origin_ms
                    <= start
                    <= observation.observed_ms
                    <= end
                    <= decision,
                    "placement:read_bracket",
                )
                require(
                    signal - start <= MAX_PLACEMENT_OBSERVATION_AGE_MS, "placement:observation_age"
                )
                starts.append(start)
            overhead += signal - min(starts)
            receipt["phases"][phase]["control"] = evidence
        if stage is None:
            require(
                control["pre_schedule"]["signal_ms"]
                < min(read["ms"][0] for read in control["pre_export"]["reads"].values()),
                "placement:release_order",
            )
        require(overhead <= 60_000, "placement:shared_overhead")
        receipt["decision"] = "EXPORT"
        receipt["reason"] = "placement_verified"
    except (IntegrityError, KeyError, TypeError, ValueError, AttributeError) as exc:
        receipt["reason"] = str(exc)
    return receipt
