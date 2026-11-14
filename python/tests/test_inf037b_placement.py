"""Offline registration :93 fixtures; no Kubernetes client or AWS calls."""

import copy
import hashlib
import json
import unittest

from inference_platform.inf037b_archive import IntegrityError
from inference_platform.inf037b_placement import (
    ISOLATION_POLICY,
    Observation,
    check_placement,
    quantity_bytes,
)
from inference_platform.inf037b_resolver import BOUNDS_MS, SessionDeadline

MEMORY_BYTES = 12_884_901_888


def observed(value, at=100):
    return Observation(json.dumps(value, indent=2).encode(), at)


def fixture():
    identity = {"name": "export-node", "uid": "node-uid"}
    spec = {
        "nodeSelector": {"kubernetes.io/hostname": identity["name"]},
        "affinity": {
            "podAntiAffinity": {
                "requiredDuringSchedulingIgnoredDuringExecution": copy.deepcopy(ISOLATION_POLICY)
            }
        },
        "containers": [
            {
                "name": "export",
                "resources": {"requests": {"memory": "12Gi"}, "limits": {"memory": "12Gi"}},
            }
        ],
    }
    phase = {
        "verified": observed(identity),
        "job": observed({"metadata": {"uid": "job-uid"}, "spec": {"template": {"spec": spec}}}),
        "pod": observed(
            {
                "metadata": {"uid": "pod-uid", "ownerReferences": [{"uid": "job-uid"}]},
                "spec": dict(spec, nodeName=identity["name"]),
            }
        ),
        "node": observed(
            {
                "metadata": dict(identity, labels={"kubernetes.io/hostname": identity["name"]}),
                "status": {"allocatable": {"memory": "12Gi"}, "capacity": {"memory": "16Gi"}},
            }
        ),
        "requests": observed({"complete": True, "node": identity, "pods": []}),
        "placement": observed(
            {
                "scheduled": True,
                "job_uid": "job-uid",
                "pod_uid": "pod-uid",
                "node_name": identity["name"],
                "node_uid": identity["uid"],
            }
        ),
    }
    pre_schedule = copy.deepcopy(phase)
    pod = json.loads(pre_schedule["pod"].raw)
    pod["spec"].pop("nodeName")
    pre_schedule["pod"] = observed(pod)
    pre_schedule["placement"] = observed(
        {"scheduled": False, "job_uid": "job-uid", "pod_uid": "pod-uid"}
    )
    args = {
        "verified": observed(identity, 0),
        "pre_schedule": pre_schedule,
        "pre_export": {key: Observation(value.raw, 200) for key, value in phase.items()},
        "deadline": SessionDeadline(1000, 18_001_000, 0),
        "now_ms": 200,
    }
    refresh_control(args)
    return args


def refresh_control(args):
    args["control"] = {}
    for phase in ("pre_schedule", "pre_export"):
        inputs = args[phase]
        at = max(o.observed_ms for o in inputs.values())
        args["control"][phase] = {
            "clock_id": "common",
            "boot_id": "host",
            "decision_ms": at,
            "ack_ms": at,
            "signal_ms": args["now_ms"] if phase == "pre_export" else at,
            "acknowledged": True,
            "received_once": True,
            "pod_uid": "pod-uid",
            "source_hashes": {key: hashlib.sha256(o.raw).hexdigest() for key, o in inputs.items()},
            "reads": {
                key: {
                    "ms": [o.observed_ms, o.observed_ms],
                    "clock_id": "common",
                    "boot_id": "host",
                    "uncertainty_ms": 100,
                }
                for key, o in inputs.items()
            },
        }


def change(args, source, update, phase=None):
    for name in [phase] if phase else ["pre_schedule", "pre_export"]:
        obs = args[name][source]
        data = json.loads(obs.raw)
        update(data)
        args[name][source] = observed(data, obs.observed_ms)
    refresh_control(args)


def node_memory(args, value):
    change(args, "node", lambda obj: obj["status"]["allocatable"].update(memory=value))


def resources(args, request, limit):
    def update(spec):
        spec["containers"][0]["resources"] = {
            "requests": {"memory": request},
            "limits": {"memory": limit},
        }

    change(args, "job", lambda job: update(job["spec"]["template"]["spec"]))
    change(args, "pod", lambda pod: update(pod["spec"]))


class PlacementTests(unittest.TestCase):
    def test_own_terminal_uid_is_recorded_without_double_counting_job_request(self):
        args = fixture()
        change(
            args,
            "requests",
            lambda obj: obj.update(
                pods=[
                    {
                        "uid": "pod-uid",
                        "node_name": "export-node",
                        "role": "export",
                        "phase": "Succeeded",
                        "memory_requests": ["12Gi"],
                    }
                ]
            ),
            phase="pre_export",
        )
        receipt = check_placement(**args)
        self.assertEqual(receipt["decision"], "EXPORT", receipt)
        facts = receipt["phases"]["pre_export"]
        self.assertEqual(facts["other_requests_bytes"], 0)
        self.assertEqual(facts["request_bytes"], MEMORY_BYTES)
        self.assertEqual(
            facts["terminal_pods"],
            [{"uid": "pod-uid", "phase": "Succeeded", "memory_bytes": MEMORY_BYTES}],
        )
        self.assertEqual(facts["terminal_requests_bytes"], MEMORY_BYTES)

    def test_terminal_demand_counts_and_named_refusal_preserves_its_receipt(self):
        for phase in ("Succeeded", "Failed"):
            for capacity, expected in (("12Gi", "REFUSE"), ("13Gi", "EXPORT")):
                with self.subTest(phase=phase, capacity=capacity):
                    args = fixture()
                    node_memory(args, capacity)
                    change(
                        args,
                        "requests",
                        lambda obj, phase=phase: obj.update(
                            pods=[
                                {
                                    "uid": "terminal",
                                    "node_name": "export-node",
                                    "role": "system",
                                    "phase": phase,
                                    "memory_requests": ["1Gi"],
                                }
                            ]
                        ),
                    )
                    receipt = check_placement(**args)
                    self.assertEqual(receipt["decision"], expected, receipt)
                    for name in ("pre_schedule", "pre_export"):
                        facts = receipt["phases"][name]
                        self.assertEqual(
                            facts["terminal_pods"],
                            [{"uid": "terminal", "phase": phase, "memory_bytes": 1024**3}],
                        )
                        self.assertEqual(facts["terminal_requests_bytes"], 1024**3)
                        self.assertEqual(facts["other_requests_bytes"], 1024**3)
                    if expected == "REFUSE":
                        self.assertIn("placement:residual_terminal_counted", receipt["reason"])
                    else:
                        self.assertEqual(receipt["reason"], "placement_verified")

    def test_isolation_policy_census_and_refreshed_identity(self):
        for phase in ("pre_schedule", "pre_export"):
            for role in ("gateway", "redis", "generator", "coordinator", "replay", "unknown", None):
                args = fixture()
                change(args, "node", lambda obj: obj["status"]["allocatable"].update(memory="13Gi"))
                change(
                    args,
                    "requests",
                    lambda obj, role=role: obj.update(
                        pods=[
                            {
                                "uid": "other",
                                "node_name": "export-node",
                                "role": role,
                                "memory_requests": ["1Gi"],
                            }
                        ]
                    ),
                    phase,
                )
                with self.subTest(phase=phase, role=role):
                    self.refuse(
                        args, "unknown_role" if role in ("unknown", None) else "isolated_node"
                    )
            args = fixture()
            change(args, "verified", lambda obj: obj.update(uid="changed"), phase)
            self.refuse(args, "refreshed_identity")
            args = fixture()
            for source in ("job", "pod"):
                change(
                    args,
                    source,
                    lambda obj, source=source: (
                        obj["spec"]["template"]["spec"] if source == "job" else obj["spec"]
                    )["affinity"]["podAntiAffinity"].update(
                        requiredDuringSchedulingIgnoredDuringExecution=[]
                    ),
                    phase,
                )
            self.refuse(args, "isolation_policy")
        result = check_placement(**fixture())
        self.assertTrue(all(p["isolation"]["verified"] for p in result["phases"].values()))

    def test_each_source_age_equality_plus_one_and_aggregate_budget(self):
        for phase in ("pre_schedule", "pre_export"):
            for source in fixture()[phase]:
                for extra in (0, 1):
                    args = fixture()
                    # Separate phases with one source 60 s older than its peers.
                    for key, obs in args["pre_schedule"].items():
                        args["pre_schedule"][key] = Observation(obs.raw, 60_100)
                    for key, obs in args["pre_export"].items():
                        args["pre_export"][key] = Observation(obs.raw, 120_200)
                    args["now_ms"] = 120_200
                    obs = args[phase][source]
                    args[phase][source] = Observation(obs.raw, obs.observed_ms - 60_000 - extra)
                    # Pre-export must remain strictly after all earlier reads.
                    if phase == "pre_export":
                        for key, old in args["pre_schedule"].items():
                            args["pre_schedule"][key] = Observation(old.raw, 100)
                    refresh_control(args)
                    with self.subTest(phase=phase, source=source, extra=extra):
                        result = check_placement(**args)
                        if extra:
                            self.assertEqual(result["decision"], "REFUSE")
                            self.assertIn("observation_age", result["reason"])
                        else:
                            self.assertEqual(result["decision"], "EXPORT", result["reason"])
        args = fixture()
        args["now_ms"] = 60_200
        refresh_control(args)
        args["control"]["pre_schedule"]["signal_ms"] = 101
        self.refuse(args, "shared_overhead")

    def test_control_missing_late_lost_duplicate_hash_uid_boot_and_order_refuse(self):
        cases = (
            (lambda a: a.update(control=None), "control_required"),
            (lambda a: a["control"]["pre_export"].update(signal_ms=201), "signal_endpoint"),
            (lambda a: a["control"]["pre_export"].update(clock_id=""), "control_clock"),
            (lambda a: a["control"]["pre_export"].update(clock_id=True), "control_clock"),
            (lambda a: a["control"]["pre_export"].update(boot_id="other"), "control_boot"),
            (lambda a: a["control"]["pre_export"].update(ack_ms=True), "control_times"),
            (lambda a: a["control"]["pre_export"].update(decision_ms=201), "signal_order"),
            (lambda a: a["control"]["pre_export"].update(acknowledged=False), "durable_ack"),
            (lambda a: a["control"]["pre_export"].update(received_once=False), "received_signal"),
            (lambda a: a["control"]["pre_export"].update(pod_uid="wrong"), "signal_uid"),
            (lambda a: a["control"]["pre_export"].update(source_hashes={}), "signal_hashes"),
            (
                lambda a: a["control"]["pre_export"]["reads"]["requests"].update(ms=[199, 201]),
                "read_bracket",
            ),
            (
                lambda a: a["control"]["pre_export"]["reads"]["requests"].update(boot_id="other"),
                "read_clock",
            ),
            (
                lambda a: a["control"]["pre_export"]["reads"]["requests"].update(
                    uncertainty_ms=101
                ),
                "read_uncertainty",
            ),
            (lambda a: a["control"]["pre_schedule"].update(signal_ms=200), "release_order"),
        )
        for modify, reason in cases:
            args = fixture()
            modify(args)
            with self.subTest(reason=reason):
                self.refuse(args, reason)

    def refuse(self, args, reason):
        result = check_placement(**args)
        self.assertEqual(result["decision"], "REFUSE", result)
        self.assertIn(reason, result["reason"])
        self.assertEqual(result["cleanup_reserve_ms"], BOUNDS_MS["cleanup"])
        self.assertEqual(result["export_bound_ms"], BOUNDS_MS["export"])
        return result

    def test_exactly_fitting_12_gib(self):
        args = fixture()
        result = check_placement(**args)
        self.assertEqual(result["decision"], "EXPORT", result)
        self.assertEqual(result["schema"], "inf037b-export-placement-v4")
        self.assertEqual(result["reason"], "placement_verified")
        self.assertEqual(result["now_ms"], 200)
        self.assertEqual(result["D_eff_ms"], 18_000_000)
        for phase in ("pre_schedule", "pre_export"):
            self.assertEqual(
                {
                    k: v
                    for k, v in result["phases"][phase].items()
                    if k not in {"isolation", "control"}
                },
                {
                    "join": {
                        "job_uid": "job-uid",
                        "pod_uid": "pod-uid",
                        "pod_node_name": None if phase == "pre_schedule" else "export-node",
                        "node_name": "export-node",
                        "node_uid": "node-uid",
                    },
                    "allocatable_bytes": MEMORY_BYTES,
                    "request_bytes": MEMORY_BYTES,
                    "limit_bytes": MEMORY_BYTES,
                    "other_requests_bytes": 0,
                    "residual_bytes": MEMORY_BYTES,
                    "terminal_pods": [],
                    "terminal_requests_bytes": 0,
                },
            )
        self.assertEqual(len(result["sources"]), 13)

        for phase in ("pre_schedule", "pre_export"):
            for name, observation in args[phase].items():
                self.assertEqual(
                    result["sources"][phase + "/" + name],
                    {
                        "sha256": hashlib.sha256(observation.raw).hexdigest(),
                        "observed_ms": observation.observed_ms,
                    },
                )
        self.assertEqual(
            result["sources"]["verified"],
            {"sha256": hashlib.sha256(args["verified"].raw).hexdigest(), "observed_ms": 0},
        )

    def test_refusal_retains_known_sizes_and_both_phase_observations(self):
        args = fixture()
        change(args, "node", lambda obj: obj["metadata"].update(uid="changed"), "pre_schedule")
        result = self.refuse(args, "node_uid")
        for phase in ("pre_schedule", "pre_export"):
            for field in ("allocatable_bytes", "request_bytes", "limit_bytes"):
                self.assertEqual(result["phases"][phase][field], MEMORY_BYTES)
            self.assertEqual(result["phases"][phase]["join"]["pod_uid"], "pod-uid")
        args = fixture()
        change(args, "node", lambda obj: obj["status"].pop("allocatable"))
        result = self.refuse(args, "allocatable")
        for phase in ("pre_schedule", "pre_export"):
            self.assertIsNone(result["phases"][phase]["allocatable_bytes"])
            self.assertEqual(result["phases"][phase]["request_bytes"], MEMORY_BYTES)
            self.assertEqual(result["phases"][phase]["limit_bytes"], MEMORY_BYTES)

    def test_job_node_name_cannot_override_selector_pin(self):
        args = fixture()
        change(args, "job", lambda obj: obj["spec"]["template"]["spec"].update(nodeName="other"))
        self.refuse(args, "job_node")

    def test_under_12_gib_allocatable(self):
        for phase in ("pre_schedule", "pre_export"):
            args = fixture()
            change(
                args,
                "node",
                lambda obj: obj["status"]["allocatable"].update(memory=str(MEMORY_BYTES - 1)),
                phase,
            )
            with self.subTest(phase=phase):
                result = self.refuse(args, "allocatable")
                self.assertEqual(result["phases"][phase]["allocatable_bytes"], MEMORY_BYTES - 1)

    def test_insufficient_residual_and_one_byte_boundary(self):
        for other, allowed in ((1024**3, True), (1024**3 + 1, False)):
            args = fixture()
            node_memory(args, "13Gi")
            change(
                args,
                "requests",
                lambda obj, other=other: obj.update(
                    pods=[
                        {
                            "uid": "other-pod",
                            "node_name": "export-node",
                            "role": "system",
                            "memory_requests": [str(other)],
                        }
                    ]
                ),
            )
            with self.subTest(other=other):
                result = check_placement(**args)
                self.assertEqual(result["decision"], "EXPORT" if allowed else "REFUSE", result)
                self.assertEqual(result["phases"]["pre_schedule"]["other_requests_bytes"], other)
                self.assertEqual(
                    result["phases"]["pre_schedule"]["residual_bytes"], 13 * 1024**3 - other
                )
                if not allowed:
                    self.assertIn("residual", result["reason"])

    def test_unequal_or_smaller_request_limit(self):
        for request, limit in (
            ("11Gi", "12Gi"),
            ("12Gi", "11Gi"),
            ("11Gi", "11Gi"),
            ("13Gi", "12Gi"),
            ("12Gi", "13Gi"),
        ):
            args = fixture()
            resources(args, request, limit)
            with self.subTest(request=request, limit=limit):
                self.refuse(args, "placement:request" if request != "12Gi" else "placement:limit")

    def test_missing_allocatable_proof(self):
        args = fixture()
        change(args, "node", lambda obj: obj["status"].pop("allocatable"))
        result = self.refuse(args, "allocatable")
        self.assertIsNone(result["phases"]["pre_schedule"]["allocatable_bytes"])
        self.assertEqual(len(result["sources"]), 13)

    def test_changed_node_name_or_uid_at_both_observations(self):
        for phase in ("pre_schedule", "pre_export"):
            for key in ("name", "uid"):
                args = fixture()
                change(
                    args,
                    "node",
                    lambda obj, key=key: obj["metadata"].update({key: "changed"}),
                    phase,
                )
                with self.subTest(phase=phase, key=key):
                    self.refuse(args, "node_" + key)

    def test_physical_12_gib_with_smaller_allocatable(self):
        args = fixture()
        node_memory(args, "11Gi")
        change(args, "node", lambda obj: obj["status"]["capacity"].update(memory="12Gi"))
        self.refuse(args, "allocatable")

    def test_quantities_exact_binary_and_decimal_suffix_equivalents(self):
        for value in (
            "12Gi",
            "12288Mi",
            "12582912Ki",
            "12884901888",
            "12884901888.0",
            "12884901.888k",
            "12884.901888M",
            "12.884901888G",
            "0.012884901888T",
            "0.000012884901888P",
            "0.000000012884901888E",
            "12884901888000m",
            "12884901888000000u",
            "12884901888000000000n",
        ):
            with self.subTest(value=value):
                self.assertEqual(quantity_bytes(value), 12_884_901_888)
        for value, expected in (
            ("1Ti", 1024**4),
            ("1Pi", 1024**5),
            ("1Ei", 1024**6),
            ("0", 0),
            ("0.5Ki", 512),
        ):
            self.assertEqual(quantity_bytes(value), expected)
        args = fixture()
        node_memory(args, "12.884901888G")
        resources(args, "12884901.888k", "12884.901888M")
        self.assertEqual(check_placement(**args)["decision"], "EXPORT")

    def test_unsupported_and_noninteger_quantities_refuse(self):
        for value in (
            None,
            12,
            True,
            "",
            " 12Gi",
            "12Gi\n",
            "-1",
            "+12Gi",
            "1e3",
            "1E3",
            "12GB",
            "12K",
            "NaN",
            "1.1",
            "1m",
            "0.1Ki",
            ".5Ki",
            "1.",
        ):
            with self.subTest(value=value), self.assertRaises(IntegrityError):
                quantity_bytes(value)
        args = fixture()
        node_memory(args, "0.1Gi")
        self.refuse(args, "integer_bytes")

    def test_other_pods_sum_every_request_and_exclude_job_own_request(self):
        args = fixture()
        node_memory(args, "15Gi")
        change(
            args,
            "requests",
            lambda obj: obj.update(
                pods=[
                    {
                        "uid": "a",
                        "node_name": "export-node",
                        "role": "system",
                        "memory_requests": ["1Gi", "512Mi"],
                    },
                    {
                        "uid": "b",
                        "node_name": "export-node",
                        "role": "system",
                        "memory_requests": ["1536Mi"],
                    },
                ]
            ),
        )
        change(
            args,
            "requests",
            lambda obj: obj["pods"].append(
                {
                    "uid": "pod-uid",
                    "node_name": "export-node",
                    "role": "system",
                    "memory_requests": ["12Gi"],
                }
            ),
            "pre_export",
        )
        result = check_placement(**args)
        self.assertEqual(result["decision"], "EXPORT", result)
        self.assertEqual(result["phases"]["pre_export"]["other_requests_bytes"], 3 * 1024**3)
        self.assertEqual(result["phases"]["pre_export"]["residual_bytes"], MEMORY_BYTES)

    def test_unknown_or_mismatched_census_refuses(self):
        changes = [
            (lambda obj: obj.update(complete=False), "census_complete"),
            (lambda obj: obj.update(complete=1), "census_complete"),
            (lambda obj: obj.update(node={"name": "export-node", "uid": "wrong"}), "census_node"),
            (lambda obj: obj.update(pods=None), "census_pods"),
            (
                lambda obj: obj.update(
                    pods=[
                        {
                            "uid": "a",
                            "node_name": "elsewhere",
                            "role": "system",
                            "memory_requests": ["0"],
                        }
                    ]
                ),
                "assigned_node",
            ),
            (
                lambda obj: obj.update(
                    pods=[
                        {
                            "uid": "a",
                            "node_name": "export-node",
                            "role": "system",
                            "memory_requests": [],
                        }
                    ]
                ),
                "assigned_requests",
            ),
            (
                lambda obj: obj.update(
                    pods=[
                        {
                            "uid": "a",
                            "node_name": "export-node",
                            "role": "system",
                            "memory_requests": [None],
                        }
                    ]
                ),
                "quantity_string",
            ),
            (
                lambda obj: obj.update(
                    pods=[
                        {
                            "uid": "pod-uid",
                            "node_name": "export-node",
                            "role": "system",
                            "memory_requests": ["1Gi"],
                        }
                    ]
                ),
                "own_request",
            ),
            (
                lambda obj: obj.update(
                    pods=[
                        {
                            "uid": "a",
                            "node_name": "export-node",
                            "role": "system",
                            "memory_requests": ["0"],
                        }
                    ]
                    * 2
                ),
                "duplicate_pod",
            ),
        ]
        for phase in ("pre_schedule", "pre_export"):
            for update, reason in changes:
                args = fixture()
                change(args, "requests", update, phase)
                expected = (
                    "census_unbound_pod"
                    if phase == "pre_schedule" and reason == "own_request"
                    else reason
                )
                with self.subTest(phase=phase, reason=reason):
                    self.refuse(args, expected)

    def test_selector_affinity_and_pod_spec_pin_verified_node(self):
        args = fixture()
        change(args, "pod", lambda obj: obj["spec"].update(nodeName="other"), "pre_export")
        self.refuse(args, "pod_node")
        for phase in ("pre_schedule", "pre_export"):
            args = fixture()
            change(
                args, "pod", lambda obj: obj["spec"]["containers"][0].update(name="wrong"), phase
            )
            self.refuse(args, "pod_spec")
        args = fixture()
        change(args, "pod", lambda obj: obj["metadata"].update(ownerReferences=[{"uid": "other"}]))
        self.refuse(args, "job_owner")
        for bad in ("selector", "hostname", "affinity"):
            args = fixture()
            if bad == "hostname":
                change(
                    args,
                    "node",
                    lambda obj: obj["metadata"]["labels"].update(
                        {"kubernetes.io/hostname": "other"}
                    ),
                )
            else:

                def update(spec):
                    spec["nodeSelector"] = {"kubernetes.io/hostname": "other"}

                change(args, "job", lambda obj: update(obj["spec"]["template"]["spec"]))
                change(args, "pod", lambda obj: update(obj["spec"]))
            self.refuse(args, "hostname" if bad == "hostname" else "selector")

    def test_required_affinity_every_or_term_pins_node(self):
        def affinity(spec):
            spec.pop("nodeSelector")
            spec["affinity"].update(
                {
                    "nodeAffinity": {
                        "requiredDuringSchedulingIgnoredDuringExecution": {
                            "nodeSelectorTerms": [
                                {
                                    "matchFields": [
                                        {
                                            "key": "metadata.name",
                                            "operator": "In",
                                            "values": ["export-node"],
                                        }
                                    ]
                                }
                            ]
                        }
                    }
                }
            )

        args = fixture()
        change(args, "job", lambda obj: affinity(obj["spec"]["template"]["spec"]))
        change(args, "pod", lambda obj: affinity(obj["spec"]))
        self.assertEqual(check_placement(**args)["decision"], "EXPORT")

        def unpin(spec):
            spec["affinity"]["nodeAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"][
                "nodeSelectorTerms"
            ].append({})

        change(args, "job", lambda obj: unpin(obj["spec"]["template"]["spec"]))
        change(args, "pod", lambda obj: unpin(obj["spec"]))
        self.refuse(args, "affinity")

    def test_unmatched_placement_or_changed_pod_or_job_refuses(self):
        for phase in ("pre_schedule", "pre_export"):
            for key, value in (
                ("scheduled", phase == "pre_schedule"),
                ("scheduled", 1),
                ("job_uid", "other"),
                ("pod_uid", "other"),
                ("node_name", "other"),
                ("node_uid", "other"),
            ):
                args = fixture()
                change(
                    args,
                    "placement",
                    lambda obj, key=key, value=value: obj.update({key: value}),
                    phase,
                )
                with self.subTest(phase=phase, key=key):
                    self.refuse(args, "scheduler_join")
        for identity in ("pod", "job"):
            args = fixture()
            change(args, identity, lambda obj: obj["metadata"].update(uid="changed"), "pre_export")
            if identity == "pod":
                change(args, "placement", lambda obj: obj.update(pod_uid="changed"), "pre_export")
            else:
                change(
                    args,
                    "pod",
                    lambda obj: obj["metadata"].update(ownerReferences=[{"uid": "changed"}]),
                    "pre_export",
                )
                change(args, "placement", lambda obj: obj.update(job_uid="changed"), "pre_export")
            self.refuse(args, "identity_changed")

    def test_export_plus_cleanup_equality_and_one_ms_short_use_D_eff(self):
        for delta, allowed in ((0, True), (1, False)):
            args = fixture()
            args["now_ms"] = 18_000_000 - BOUNDS_MS["export"] - BOUNDS_MS["cleanup"] + delta
            for key, obs in args["pre_export"].items():
                args["pre_export"][key] = Observation(obs.raw, args["now_ms"])
            refresh_control(args)
            result = check_placement(**args)
            self.assertEqual(result["decision"], "EXPORT" if allowed else "REFUSE", result)
            self.assertEqual(result["cleanup_reserve_ms"], 1_800_000)
            self.assertEqual(result["export_bound_ms"], 3_600_000)
            self.assertEqual(result["D_eff_ms"], 18_000_000)
            if not allowed:
                self.assertIn("export_cleanup_fit", result["reason"])

    def test_raw_hashes_preserve_observed_bytes_on_success_and_refusal(self):
        args = fixture()
        original = args["pre_export"]["node"]
        args["pre_export"]["node"] = Observation(original.raw + b" \n", original.observed_ms)
        refresh_control(args)
        result = check_placement(**args)
        self.assertEqual(result["decision"], "EXPORT")
        self.assertNotEqual(
            result["sources"]["pre_schedule/node"]["sha256"],
            result["sources"]["pre_export/node"]["sha256"],
        )
        args["pre_schedule"]["job"] = Observation(b"bad JSON", 100)
        result = self.refuse(args, "source")
        self.assertEqual(len(result["sources"]), 13)
        self.assertEqual(
            result["sources"]["pre_schedule/job"]["sha256"], hashlib.sha256(b"bad JSON").hexdigest()
        )
        self.assertEqual(
            result["sources"]["pre_export/node"]["sha256"],
            hashlib.sha256(original.raw + b" \n").hexdigest(),
        )

    def test_missing_unknown_identity_inputs_and_times_refuse_with_receipt(self):
        for phase in ("pre_schedule", "pre_export"):
            for source in ("job", "pod", "node", "requests", "placement"):
                args = fixture()
                del args[phase][source]
                self.refuse(args, "inputs")
            args = fixture()
            args[phase]["extra"] = args[phase]["node"]
            self.refuse(args, "inputs")
        for source, update in (
            ("job", lambda obj: obj["metadata"].update(uid="")),
            ("pod", lambda obj: obj["metadata"].update(uid=None)),
            ("node", lambda obj: obj["metadata"].update(name=1)),
        ):
            args = fixture()
            change(args, source, update)
            self.refuse(args, "identity")
        for at in (-1, True, 201, None):
            args = fixture()
            args["pre_export"]["job"] = Observation(args["pre_export"]["job"].raw, at)
            self.refuse(args, "observation_time")
        args = fixture()
        args["pre_schedule"]["node"] = Observation(args["pre_schedule"]["node"].raw, 101)
        args["pre_export"]["node"] = Observation(args["pre_export"]["node"].raw, 100)
        self.refuse(args, "time_order")
        for now in (-1, True, None):
            args = fixture()
            args["now_ms"] = now
            result = self.refuse(args, "placement:now")
            self.assertEqual(len(result["sources"]), 13)
        args = fixture()
        args["deadline"] = None
        result = self.refuse(args, "placement:deadline")
        self.assertEqual(len(result["sources"]), 13)
        args = fixture()
        args["deadline"] = SessionDeadline(1000, 18_001_000, 201)
        result = self.refuse(args, "before_origin")
        self.assertEqual(result["reason"], "v4:placement:before_origin")
        args = fixture()
        args["verified"] = observed({"name": "export-node", "uid": "node-uid", "extra": 1}, 0)
        self.refuse(args, "verified_keys")
        args = fixture()
        args["verified"] = observed({"name": "export-node", "uid": ""}, 0)
        self.refuse(args, "identity")
        args = fixture()
        args["pre_export"]["job"] = None
        self.refuse(args, "observation")
        args = fixture()
        args["pre_export"]["job"] = Observation("text", 100)
        self.refuse(args, "raw_bytes")
        args = fixture()
        args["pre_export"] = None
        result = self.refuse(args, "phase_inputs")
        self.assertEqual(len(result["sources"]), 7)

    def test_pending_pre_schedule_passes(self):
        args = fixture()
        self.assertNotIn("nodeName", json.loads(args["pre_schedule"]["pod"].raw)["spec"])
        self.assertEqual(
            json.loads(args["pre_schedule"]["placement"].raw),
            {"scheduled": False, "job_uid": "job-uid", "pod_uid": "pod-uid"},
        )
        result = check_placement(**args)
        self.assertEqual(result["decision"], "EXPORT", result)

    def test_bound_pre_schedule_refuses(self):
        for node_name in ("export-node", "", None):
            args = fixture()
            change(
                args,
                "pod",
                lambda obj, node_name=node_name: obj["spec"].update(nodeName=node_name),
                "pre_schedule",
            )
            args["pre_schedule"]["placement"] = Observation(
                args["pre_export"]["placement"].raw, 100
            )
            self.refuse(args, "pre_schedule_bound")

    def test_pre_schedule_residual_one_byte_short_keeps_both_sizes(self):
        args = fixture()
        change(
            args,
            "requests",
            lambda obj: obj.update(
                pods=[
                    {
                        "uid": "other",
                        "node_name": "export-node",
                        "role": "system",
                        "memory_requests": ["1"],
                    }
                ]
            ),
            "pre_schedule",
        )
        result = self.refuse(args, "placement:residual")
        for phase in ("pre_schedule", "pre_export"):
            for field in ("allocatable_bytes", "request_bytes", "limit_bytes"):
                self.assertEqual(result["phases"][phase][field], MEMORY_BYTES)
        self.assertEqual(result["phases"]["pre_schedule"]["residual_bytes"], MEMORY_BYTES - 1)
        self.assertEqual(result["phases"]["pre_export"]["residual_bytes"], MEMORY_BYTES)

    def test_same_observation_in_both_phases_refuses(self):
        args = fixture()
        args["pre_export"]["node"] = args["pre_schedule"]["node"]
        self.refuse(args, "time_order")

    def test_every_observation_before_origin_refuses_equal_origin_passes(self):
        for name in (
            "verified",
            *(
                phase + "/" + key
                for phase in ("pre_schedule", "pre_export")
                for key in fixture()[phase]
            ),
        ):
            args = fixture()
            args["deadline"] = SessionDeadline(1000, 18_001_000, 50)
            original = args["verified"]
            args["verified"] = Observation(original.raw, 50)
            if name == "verified":
                owner, key = args, name
            else:
                phase, key = name.split("/")
                owner = args[phase]
            obs = owner[key]
            owner[key] = Observation(obs.raw, 49)
            with self.subTest(name=name):
                self.refuse(args, "observation_before_origin")
        args = fixture()
        args["deadline"] = SessionDeadline(1000, 18_001_000, 100)
        args["verified"] = Observation(args["verified"].raw, 100)
        self.assertEqual(check_placement(**args)["decision"], "EXPORT")

    def test_each_pre_export_strictly_after_latest_pre_schedule(self):
        for source in fixture()["pre_export"]:
            for at, allowed in ((150, False), (151, True)):
                args = fixture()
                obs = args["pre_schedule"]["node"]
                args["pre_schedule"]["node"] = Observation(obs.raw, 150)
                obs = args["pre_export"][source]
                args["pre_export"][source] = Observation(obs.raw, at)
                refresh_control(args)
                with self.subTest(source=source, at=at):
                    if allowed:
                        self.assertEqual(check_placement(**args)["decision"], "EXPORT")
                    else:
                        self.refuse(args, "time_order")

    def test_pre_export_age_uses_oldest_with_registered_threshold(self):
        args = fixture()
        args["pre_export"]["node"] = Observation(args["pre_export"]["node"].raw, 175)
        args["now_ms"] = 60_175
        refresh_control(args)
        result = check_placement(**args)
        self.assertEqual(result["decision"], "EXPORT", result)
        self.assertEqual(result["pre_export_age_ms"], 60_000)
        args["now_ms"] = 60_176
        refresh_control(args)
        result = self.refuse(args, "observation_age")
        self.assertEqual(result["pre_export_age_ms"], 60_001)

    def test_duplicate_json_member_refuses(self):
        args = fixture()
        obs = args["pre_export"]["node"]
        args["pre_export"]["node"] = Observation(
            obs.raw.replace(b'"memory": "12Gi"', b'"memory": "8Gi", "memory": "12Gi"'),
            obs.observed_ms,
        )
        self.refuse(args, "duplicate_json_member:memory")

    def test_nonfinite_json_refuses(self):
        args = fixture()
        obs = args["pre_export"]["requests"]
        args["pre_export"]["requests"] = Observation(
            obs.raw[:-1] + b', "extra": NaN}', obs.observed_ms
        )
        self.refuse(args, "nonfinite_json:NaN")

    def test_deep_json_returns_refusal_and_all_source_hashes(self):
        args = fixture()
        raw = b"[" * 200_000
        args["pre_export"]["placement"] = Observation(raw, 200)
        result = self.refuse(args, "placement:json_recursion")
        self.assertEqual(len(result["sources"]), 13)
        for name, source in result["sources"].items():
            if name == "verified":
                obs = args[name]
            else:
                phase, key = name.split("/")
                obs = args[phase][key]
            self.assertEqual(source["sha256"], hashlib.sha256(obs.raw).hexdigest())

    def test_oversized_allocatable_keeps_request_limit(self):
        args = fixture()
        node_memory(args, "9" * 5000)
        result = self.refuse(args, "placement:memory_proof")
        for phase in ("pre_schedule", "pre_export"):
            self.assertIsNone(result["phases"][phase]["allocatable_bytes"])
            self.assertEqual(result["phases"][phase]["request_bytes"], MEMORY_BYTES)
            self.assertEqual(result["phases"][phase]["limit_bytes"], MEMORY_BYTES)

    def test_extra_container_init_and_overhead_refuse(self):
        for field in ("containers", "initContainers", "overhead"):
            args = fixture()

            def update(spec, field=field):
                if field == "containers":
                    spec[field].append(copy.deepcopy(spec[field][0]))
                else:
                    spec[field] = ["unaccounted"]

            change(args, "job", lambda obj: update(obj["spec"]["template"]["spec"]))
            change(args, "pod", lambda obj: update(obj["spec"]))
            self.refuse(args, "single_container" if field == "containers" else "extra_memory")

    def test_pre_schedule_census_cannot_assign_unbound_export_pod(self):
        args = fixture()
        change(
            args,
            "requests",
            lambda obj: obj.update(
                pods=[
                    {
                        "uid": "pod-uid",
                        "node_name": "export-node",
                        "role": "system",
                        "memory_requests": ["12Gi"],
                    }
                ]
            ),
            "pre_schedule",
        )
        result = self.refuse(args, "v4:placement:census_unbound_pod")
        self.assertEqual(len(result["sources"]), 13)
        self.assertEqual(result["phases"]["pre_schedule"]["request_bytes"], MEMORY_BYTES)
        self.assertEqual(result["phases"]["pre_export"]["residual_bytes"], MEMORY_BYTES)

    def test_empty_pre_export_refuses_with_input_reason_and_unknown_age(self):
        args = fixture()
        args["pre_export"] = {}
        result = self.refuse(args, "v4:placement:inputs")
        self.assertIsNone(result["pre_export_age_ms"])
        self.assertEqual(len(result["sources"]), 7)
        self.assertEqual(result["phases"]["pre_schedule"]["request_bytes"], MEMORY_BYTES)
        self.assertEqual(result["phases"]["pre_schedule"]["allocatable_bytes"], MEMORY_BYTES)


if __name__ == "__main__":
    unittest.main()
