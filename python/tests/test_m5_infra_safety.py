import copy
import json
import unittest
from dataclasses import replace
from hashlib import sha256
from pathlib import Path

from inference_platform.m5_infra_safety import (
    Binding,
    Refused,
    Reservation,
    recreate_gpu,
    rehearse_lifecycle,
    verify_gpu_destroy_plan,
    verify_gpu_plan,
    verify_gpu_recreate_plan,
    verify_reservation,
    wait_terminated,
)

GROUP = "arn:aws:resource-groups:us-east-1:000000000000:group/m5-fixture-capacity"
BINDING = Binding(GROUP, "us-east-1a")
RESERVATION = Reservation("cr-fixture", "us-east-1a")
CONFIGURATION_FIXTURE = Path(__file__).parent / "fixtures/m5_plan_configuration.json"


def plan_fixture():
    # Constructed from HashiCorp's JSON plan/configuration/expression format:
    # https://developer.hashicorp.com/terraform/internals/json-format
    # Constructed fixture with the real provider's wholly unknown subnet set.
    # Sealed runner plans also exercise real show output; no production fallback.
    return {
        "format_version": "1.0",
        "configuration": json.loads(CONFIGURATION_FIXTURE.read_text()),
        "output_changes": {
            "capacity_binding": {
                "after": {
                    "group_arn": GROUP,
                    "zone": "us-east-1a",
                    "type": "g6.xlarge",
                    "platform": "Linux/UNIX",
                    "tenancy": "default",
                    "count": 2,
                }
            }
        },
        "resource_changes": [
            {
                "type": "aws_eks_node_group",
                "name": "gpu",
                "change": {
                    "actions": ["create"],
                    "after": {
                        "ami_type": "AL2023_x86_64_NVIDIA",
                        "capacity_type": "ON_DEMAND",
                        "scaling_config": [{"min_size": 2, "desired_size": 2, "max_size": 2}],
                        "node_repair_config": [{"enabled": False}],
                    },
                    "after_unknown": {"subnet_ids": True},
                },
            },
            {
                "type": "aws_launch_template",
                "name": "gpu",
                "change": {
                    "actions": ["create"],
                    "after": {
                        "placement": [{"tenancy": "default"}],
                        "instance_type": "g6.xlarge",
                        "capacity_reservation_specification": [
                            {
                                "capacity_reservation_preference": "capacity-reservations-only",
                                "capacity_reservation_target": [
                                    {"capacity_reservation_resource_group_arn": GROUP}
                                ],
                            }
                        ],
                    },
                },
            },
            {
                "address": 'aws_subnet.m5["0"]',
                "type": "aws_subnet",
                "name": "m5",
                "change": {
                    "actions": ["create"],
                    "after": {
                        "availability_zone": "us-east-1a",
                    },
                    "after_unknown": {"id": True},
                },
            },
            {
                "address": 'aws_subnet.m5["1"]',
                "type": "aws_subnet",
                "name": "m5",
                "change": {
                    "actions": ["create"],
                    "after": {"availability_zone": "us-east-1b"},
                    "after_unknown": {"id": True},
                },
            },
        ],
    }


SAVED_PLAN = json.dumps(plan_fixture()).encode()
HASH = sha256(SAVED_PLAN).hexdigest()


class FakePort:
    def __init__(self, fail=None, reservation=RESERVATION):
        self.events = []
        self.fail = fail
        self.reservation = reservation
        self.members = []
        self.applied = None
        self.consumed_hash = None

    def event(self, name):
        self.events.append(name)
        if self.fail == name:
            raise RuntimeError(name)

    def marker(self, plan_hash):
        self.event("marker")
        if plan_hash != HASH:
            raise Refused("marker hash mismatch")

    def group_members(self, group_arn):
        self.event("members")
        if group_arn != GROUP:
            raise Refused("wrong group")
        return self.members

    def acquire(self, token, binding):
        self.acquired_binding = binding
        self.token = token  # models a side effect even when the response is lost
        self.event("acquire")
        return self.reservation

    def add(self, group_arn, reservation):
        self.event("add")
        self.members = [reservation.reservation_id]

    def consume(self, plan_hash):
        self.event("consume")
        self.consumed_hash = plan_hash

    def apply(self, saved_plan):
        self.event("control-plane/apply")
        self.applied = saved_plan

    def destroy_and_wait(self):
        self.event("destroy/wait-terminated")

    def cancel_and_verify(self, token):
        self.event("cancel/verify")
        self.cancelled_token = token


class CapacityTests(unittest.TestCase):
    def test_wrong_type_zone_platform_tenancy_count_availability_or_state_unusable(self):
        for override in (
            {"instance_type": "g6.2xlarge"},
            {"zone": "us-east-1b"},
            {"platform": "Windows"},
            {"tenancy": "dedicated"},
            {"total": 3},
            {"available": 1},
            {"state": "pending"},
            {"match_criteria": "open"},
        ):
            with self.subTest(override=override), self.assertRaises(Refused):
                verify_reservation(BINDING, replace(RESERVATION, **override))
        verify_reservation(BINDING, RESERVATION)

    def test_marker_before_reserve_and_unchanged_plan_before_consume(self):
        port = FakePort()
        rehearse_lifecycle(port, lambda: SAVED_PLAN, HASH, BINDING)
        self.assertEqual(
            port.events,
            [
                "marker",
                "members",
                "acquire",
                "add",
                "members",
                "consume",
                "control-plane/apply",
                "destroy/wait-terminated",
                "cancel/verify",
            ],
        )
        self.assertEqual(port.consumed_hash, HASH)
        self.assertEqual(sha256(port.applied).hexdigest(), HASH)
        self.assertEqual(port.cancelled_token, HASH)
        self.assertEqual(port.acquired_binding, verify_gpu_plan(plan_fixture()))

    def test_plan_1a_packet_and_reservation_1b_refused_before_marker_or_acquire(self):
        port = FakePort(reservation=replace(RESERVATION, zone="us-east-1b"))
        with self.assertRaisesRegex(Refused, "disagree"):
            rehearse_lifecycle(port, lambda: SAVED_PLAN, HASH, replace(BINDING, zone="us-east-1b"))
        self.assertEqual(port.events, [])

    def test_wrong_plan_tenancy_or_platform_refused_before_marker_or_acquire(self):
        for resource, field, value in (
            (1, "placement", [{"tenancy": "dedicated"}]),
            (0, "ami_type", "WINDOWS_CORE_2022_x86_64"),
        ):
            plan = plan_fixture()
            plan["resource_changes"][resource]["change"]["after"][field] = value
            saved = json.dumps(plan).encode()
            port = FakePort()
            with self.subTest(field=field), self.assertRaises(Refused):
                rehearse_lifecycle(
                    port, lambda saved=saved: saved, sha256(saved).hexdigest(), BINDING
                )
            self.assertEqual(port.events, [])

    def test_invalid_json_or_missing_capacity_refused_before_marker(self):
        for saved in (b"opaque binary fixture", b"{}", b"null", b"[]"):
            port = FakePort()
            with self.subTest(saved=saved), self.assertRaises(Refused):
                rehearse_lifecycle(
                    port, lambda saved=saved: saved, sha256(saved).hexdigest(), BINDING
                )
            self.assertEqual(port.events, [])

    def test_hash_tamper_after_reserve_cancels_without_consume(self):
        port = FakePort()
        reads = iter([SAVED_PLAN, b"changed plan"])
        with self.assertRaisesRegex(Refused, "plan changed"):
            rehearse_lifecycle(port, lambda: next(reads), HASH, BINDING)
        self.assertNotIn("consume", port.events)
        self.assertEqual(port.events[-1], "cancel/verify")

    def test_pre_acquisition_rejections_create_nothing(self):
        for stage in ("marker", "members"):
            port = FakePort(fail=stage)
            with self.subTest(stage=stage), self.assertRaises(RuntimeError):
                rehearse_lifecycle(port, lambda: SAVED_PLAN, HASH, BINDING)
            self.assertNotIn("acquire", port.events)
        port = FakePort()
        port.members = ["cr-unrelated"]
        with self.assertRaises(Refused):
            rehearse_lifecycle(port, lambda: SAVED_PLAN, HASH, BINDING)
        self.assertNotIn("acquire", port.events)
        port = FakePort()
        with self.assertRaises(Refused):
            rehearse_lifecycle(port, lambda: b"tampered", HASH, BINDING)
        self.assertNotIn("acquire", port.events)

    def test_every_exit_after_acquisition_attempts_cancel_including_lost_reply(self):
        for stage in (
            "acquire",
            "add",
            "consume",
            "control-plane/apply",
            "destroy/wait-terminated",
            "cancel/verify",
        ):
            port = FakePort(fail=stage)
            with self.subTest(stage=stage), self.assertRaises(RuntimeError):
                rehearse_lifecycle(port, lambda: SAVED_PLAN, HASH, BINDING)
            self.assertEqual(port.events[-1], "cancel/verify")
            self.assertIn("destroy/wait-terminated", port.events)
            if stage in {"acquire", "add"}:
                self.assertNotIn("consume", port.events)
                self.assertNotIn("control-plane/apply", port.events)
            if stage == "acquire":
                self.assertEqual(port.cancelled_token, port.token)

    def test_mismatch_never_creates_control_plane(self):
        for field, value in (("zone", "us-east-1c"), ("platform", "Windows")):
            port = FakePort(reservation=replace(RESERVATION, **{field: value}))
            with self.subTest(field=field), self.assertRaises(Refused):
                rehearse_lifecycle(port, lambda: SAVED_PLAN, HASH, BINDING)
            self.assertNotIn("consume", port.events)
            self.assertNotIn("control-plane/apply", port.events)
            self.assertEqual(port.events[-1], "cancel/verify")

    def test_foreign_member_inserted_after_acquire_refuses(self):
        class ForeignMemberPort(FakePort):
            def add(self, group_arn, reservation):
                super().add(group_arn, reservation)
                self.members.append("cr-foreign")

        port = ForeignMemberPort()
        with self.assertRaisesRegex(Refused, "only this"):
            rehearse_lifecycle(port, lambda: SAVED_PLAN, HASH, BINDING)
        self.assertNotIn("consume", port.events)

    def test_operator_interruption_cancels(self):
        class InterruptedPort(FakePort):
            def add(self, group_arn, reservation):
                raise KeyboardInterrupt

        port = InterruptedPort()
        with self.assertRaises(KeyboardInterrupt):
            rehearse_lifecycle(port, lambda: SAVED_PLAN, HASH, BINDING)
        self.assertEqual(port.events[-1], "cancel/verify")


class ReplacementTests(unittest.TestCase):
    def test_shutting_down_counts_until_all_old_and_conflicting_instances_terminated(self):
        events = []
        snapshots = iter(
            [
                {"old-1": "terminated", "old-2": "shutting-down", "foreign": "running"},
                {"old-1": "terminated", "old-2": "terminated", "foreign": "shutting-down"},
                {"old-1": "terminated", "old-2": "terminated", "foreign": "terminated"},
            ]
        )

        def inventory():
            states = next(snapshots)
            events.append(states)
            return states

        recreate_gpu(
            "destroy-recreate",
            frozenset({"old-1", "old-2"}),
            lambda events=events: events.append("destroy"),
            inventory,
            lambda events=events: events.append("wait"),
            lambda events=events: events.append("create-two"),
        )
        self.assertEqual(events[0], "destroy")
        self.assertEqual(events[-1], "create-two")
        self.assertEqual(len([event for event in events if isinstance(event, dict)]), 3)

    def test_pending_stopped_stopping_shutting_down_unknown_and_missing_block_recreate(self):
        for state in ("pending", "running", "stopped", "stopping", "shutting-down", "unknown"):
            events = []
            with self.subTest(state=state), self.assertRaises(Refused):
                recreate_gpu(
                    "destroy-recreate",
                    frozenset({"old"}),
                    lambda events=events: events.append("destroy"),
                    lambda state=state: {"old": state},
                    lambda: None,
                    lambda events=events: events.append("create"),
                )
            self.assertEqual(events, ["destroy"])
        with self.assertRaises(Refused):
            wait_terminated(lambda: {}, lambda: None, 2, frozenset({"old"}))

    def test_disappearing_conflict_is_not_proof_of_termination(self):
        snapshots = iter([{"old": "terminated", "other": "running"}, {"old": "terminated"}])
        with self.assertRaises(Refused):
            wait_terminated(lambda: next(snapshots), lambda: None, 2, frozenset({"old"}))

    def test_updates_and_unrecorded_paths_refused_before_destroy(self):
        for path in ("MINIMAL", "DEFAULT", "update-version", "update-config", ""):
            events = []
            with self.subTest(path=path), self.assertRaises(Refused):
                recreate_gpu(
                    path,
                    frozenset({"old"}),
                    lambda events=events: events.append("destroy"),
                    lambda: {},
                    lambda: None,
                    lambda events=events: events.append("create"),
                )
            self.assertEqual(events, [])


def destroy_plan_fixture():
    # Constructed JSON fixture for the offline destroy model, not provider output.
    return {
        "resource_changes": [
            {
                "address": f"{kind}.gpu[0]",
                "type": kind,
                "name": "gpu",
                "mode": "managed",
                "change": {"actions": ["delete"], "after": None},
            }
            for kind in ("aws_eks_node_group", "aws_launch_template")
        ]
        + [
            {
                "address": 'aws_subnet.m5["0"]',
                "type": "aws_subnet",
                "name": "m5",
                "change": {"actions": ["no-op"], "after": {"id": "subnet-fixture"}},
            }
        ]
    }


class DestroyPlanTests(unittest.TestCase):
    def test_only_both_gpu_deletions_with_retained_no_ops_accepted(self):
        verify_gpu_destroy_plan(destroy_plan_fixture())

    def test_any_other_action_refused(self):
        for index in range(3):
            for actions in (
                [],
                ["create"],
                ["update"],
                ["delete", "create"],
                ["create", "delete"],
                ["read"],
                ["forget"],
                ["no-op"],
                ["delete"],
            ):
                if actions == (["delete"] if index < 2 else ["no-op"]):
                    continue
                with self.subTest(index=index, actions=actions), self.assertRaises(Refused):
                    plan = destroy_plan_fixture()
                    plan["resource_changes"][index]["change"]["actions"] = actions
                    verify_gpu_destroy_plan(plan)

    def test_missing_duplicate_misaddressed_and_malformed_refused(self):
        plans = [{}, {"resource_changes": None}, {"resource_changes": []}]
        for index in (0, 1):
            plan = destroy_plan_fixture()
            del plan["resource_changes"][index]
            plans.append(plan)
        for field, value in (
            ("address", "aws_eks_node_group.cpu[0]"),
            ("type", "aws_subnet"),
            ("name", "cpu"),
            ("mode", "data"),
        ):
            plan = destroy_plan_fixture()
            plan["resource_changes"][0][field] = value
            plans.append(plan)
        plan = destroy_plan_fixture()
        plan["resource_changes"].append(copy.deepcopy(plan["resource_changes"][0]))
        plans.append(plan)
        plan = destroy_plan_fixture()
        plan["resource_changes"][0]["change"]["after"] = {}
        plans.append(plan)
        plan = destroy_plan_fixture()
        del plan["resource_changes"][0]["change"]["actions"]
        plans.append(plan)
        for plan in plans:
            with self.subTest(plan=plan), self.assertRaises(Refused):
                verify_gpu_destroy_plan(plan)


def recreate_plan_fixture():
    plan = plan_fixture()
    for row in plan["resource_changes"]:
        row["mode"] = "managed"
        row.setdefault("address", f"{row['type']}.{row['name']}[0]")
        if row["name"] != "gpu":
            row["change"].update(actions=["no-op"], replace_paths=[])
    return plan


class RecreatePlanTests(unittest.TestCase):
    def test_two_gpu_creates_with_retained_no_ops_accepted(self):
        self.assertEqual(verify_gpu_recreate_plan(recreate_plan_fixture(), BINDING), BINDING)

    def test_retained_actions_and_replacement_paths_refused(self):
        for actions, paths in (
            (["update"], []),
            (["delete", "create"], [["cidr_block"]]),
            (["create", "delete"], [["cidr_block"]]),
            (["create"], []),
            (["delete"], []),
            (["no-op"], [["cidr_block"]]),
            (["no-op"], None),
        ):
            with self.subTest(actions=actions, paths=paths):
                plan = recreate_plan_fixture()
                plan["resource_changes"][3]["change"].update(actions=actions, replace_paths=paths)
                # General capacity verification accepts this retained-resource drift.
                self.assertEqual(verify_gpu_plan(plan, BINDING), BINDING)
                with self.assertRaises(Refused):
                    verify_gpu_recreate_plan(plan, BINDING)

    def test_missing_duplicate_misaddressed_and_nonmanaged_refused(self):
        plans = []
        for index in (0, 1):
            for field, value in (("address", "wrong"), ("mode", "data")):
                plan = recreate_plan_fixture()
                plan["resource_changes"][index][field] = value
                plans.append(plan)
            plan = recreate_plan_fixture()
            del plan["resource_changes"][index]["address"]
            plans.append(plan)
        plan = recreate_plan_fixture()
        plan["resource_changes"].append(copy.deepcopy(plan["resource_changes"][3]))
        plans.append(plan)
        plan = recreate_plan_fixture()
        plan["resource_changes"][3]["mode"] = "data"
        plans.append(plan)
        plan = recreate_plan_fixture()
        del plan["resource_changes"][3]["mode"]
        plans.append(plan)
        for plan in plans:
            with self.subTest(plan=plan), self.assertRaises(Refused):
                verify_gpu_recreate_plan(plan, BINDING)

    def test_capacity_and_packet_checks_still_required(self):
        with self.assertRaises(Refused):
            verify_gpu_recreate_plan(recreate_plan_fixture(), replace(BINDING, zone="us-east-1b"))


class PlanTests(unittest.TestCase):
    def setUp(self):
        # Small contract fixture; sealed runner plans use real configuration.
        self.plan = plan_fixture()

    def assert_refused_before_marker(self, plan):
        saved = json.dumps(plan).encode()
        port = FakePort()
        with self.assertRaises(Refused):
            rehearse_lifecycle(port, lambda: saved, sha256(saved).hexdigest(), BINDING)
        self.assertEqual(port.events, [])

    def test_moved_gpu_subnet_refuses_before_marker(self):
        gpu = self.plan["configuration"]["root_module"]["resources"][0]
        gpu["expressions"]["subnet_ids"]["references"] = [
            'aws_subnet.m5["1"].id',
            'aws_subnet.m5["1"]',
            "aws_subnet.m5",
        ]
        self.assert_refused_before_marker(self.plan)
        # The selected instance, rather than a hard-coded key, supplies the AZ.
        self.plan["output_changes"]["capacity_binding"]["after"]["zone"] = "us-east-1b"
        self.assertEqual(verify_gpu_plan(self.plan).zone, "us-east-1b")

    def test_missing_configuration_or_subnet_reference_refuses_before_marker(self):
        for path in (
            ("configuration",),
            ("configuration", "root_module"),
            ("configuration", "root_module", "resources"),
            ("configuration", "root_module", "resources", 0, "expressions", "subnet_ids"),
            (
                "configuration",
                "root_module",
                "resources",
                0,
                "expressions",
                "subnet_ids",
                "references",
            ),
        ):
            plan = copy.deepcopy(self.plan)
            parent = plan
            for key in path[:-1]:
                parent = parent[key]
            del parent[path[-1]]
            with self.subTest(path=path):
                self.assert_refused_before_marker(plan)

    def test_ambiguous_unindexed_or_foreign_subnet_references_refuse(self):
        for references in (
            [],
            None,
            "aws_subnet.m5",
            [None],
            ["aws_subnet.m5"],
            ["local.gpu_subnet"],
            ['aws_subnet.m5["2"]', "aws_subnet.m5"],
            ['aws_subnet.m5["0"]', 'aws_subnet.m5["1"]', "aws_subnet.m5"],
            ['aws_subnet.m5["0"]', "var.other_subnet"],
        ):
            plan = copy.deepcopy(self.plan)
            gpu = plan["configuration"]["root_module"]["resources"][0]
            gpu["expressions"]["subnet_ids"]["references"] = references
            with self.subTest(references=references):
                self.assert_refused_before_marker(plan)

    def test_missing_or_duplicate_gpu_configuration_refuses(self):
        for resources in ([], self.plan["configuration"]["root_module"]["resources"] * 2):
            plan = copy.deepcopy(self.plan)
            plan["configuration"]["root_module"]["resources"] = resources
            self.assert_refused_before_marker(plan)

    def test_group_binding_without_id(self):
        self.assertEqual(verify_gpu_plan(self.plan), BINDING)
        self.assertEqual(verify_gpu_plan(self.plan, BINDING), BINDING)

    def test_known_single_subnet_accepted(self):
        change = self.plan["resource_changes"][0]["change"]
        change["after"]["subnet_ids"] = ["subnet-fixture"]
        change["after_unknown"] = {"subnet_ids": [False]}
        self.assertEqual(verify_gpu_plan(self.plan), BINDING)

    def test_other_subnet_value_shapes_refuse_before_marker(self):
        # Mock-provider [null]/[true] is deliberately a labelled negative case.
        for after, unknown in (
            ({"subnet_ids": [None]}, {"subnet_ids": [True]}),
            ({"subnet_ids": []}, {}),
            ({"subnet_ids": ["subnet-a", "subnet-b"]}, {}),
            ({}, {}),
            ({}, {"subnet_ids": False}),
            ({}, {"subnet_ids": 1}),
            ({}, {"subnet_ids": [True]}),
            ({"subnet_ids": None}, {"subnet_ids": True}),
            ({"subnet_ids": "subnet-a"}, {}),
            ({"subnet_ids": [None]}, {}),
            ({"subnet_ids": [""]}, {}),
            ({"subnet_ids": [7]}, {}),
            ({"subnet_ids": ["subnet-a"]}, {"subnet_ids": True}),
            ({"subnet_ids": ["subnet-a"]}, {"subnet_ids": [True]}),
            ({"subnet_ids": ["subnet-a"]}, {"subnet_ids": [0]}),
            ({"subnet_ids": ["subnet-a"]}, {"subnet_ids": [False, False]}),
            ({"subnet_ids": ["subnet-a"]}, {"subnet_ids": []}),
            ({"subnet_ids": ["subnet-a"]}, {}),
            ({"subnet_ids": ["subnet-a"]}, {"subnet_ids": False}),
        ):
            plan = copy.deepcopy(self.plan)
            change = plan["resource_changes"][0]["change"]
            change["after"].update(after)
            change["after_unknown"] = unknown
            with self.subTest(after=after, unknown=unknown):
                self.assert_refused_before_marker(plan)
        del self.plan["resource_changes"][0]["change"]["after_unknown"]
        self.assert_refused_before_marker(self.plan)

    def test_output_zone_must_equal_gpu_subnet_az(self):
        for changed_zone in (None, "us-east-1b"):
            plan = copy.deepcopy(self.plan)
            plan["resource_changes"][2]["change"]["after"]["availability_zone"] = changed_zone
            with self.subTest(zone=changed_zone), self.assertRaises(Refused):
                verify_gpu_plan(plan)

    def test_output_tenancy_platform_type_count_and_group_must_agree(self):
        for field, value in (
            ("tenancy", "dedicated"),
            ("platform", "Windows"),
            ("type", "g6.2xlarge"),
            ("count", 1),
            ("group_arn", GROUP + "-other"),
        ):
            plan = copy.deepcopy(self.plan)
            plan["output_changes"]["capacity_binding"]["after"][field] = value
            with self.subTest(field=field), self.assertRaises(Refused):
                verify_gpu_plan(plan)

    def test_missing_or_unknown_capacity_values_refused(self):
        for field in ("group_arn", "zone", "type", "platform", "tenancy", "count"):
            for missing in (False, True):
                plan = copy.deepcopy(self.plan)
                output = plan["output_changes"]["capacity_binding"]["after"]
                if missing:
                    del output[field]
                else:
                    output[field] = None
                with self.subTest(field=field, missing=missing), self.assertRaises(Refused):
                    verify_gpu_plan(plan)

    def test_update_and_both_replacement_orders_refused(self):
        for actions in (["update"], ["delete", "create"], ["create", "delete"]):
            for resource in (0, 1):
                plan = copy.deepcopy(self.plan)
                plan["resource_changes"][resource]["change"]["actions"] = actions
                with self.subTest(actions=actions, resource=resource), self.assertRaises(Refused):
                    verify_gpu_plan(plan, BINDING)

    def test_surge_spot_repair_and_extra_groups_refused(self):
        for field, value in (
            ("capacity_type", "SPOT"),
            ("scaling_config", [{"min_size": 2, "desired_size": 2, "max_size": 3}]),
            ("node_repair_config", [{"enabled": True}]),
            ("warm_pool_config", [{"min_size": 1}]),
            ("update_config", [{"update_strategy": "MINIMAL"}]),
        ):
            plan = copy.deepcopy(self.plan)
            plan["resource_changes"][0]["change"]["after"][field] = value
            with self.subTest(field=field), self.assertRaises(Refused):
                verify_gpu_plan(plan, BINDING)
        plan = copy.deepcopy(self.plan)
        plan["resource_changes"].append(copy.deepcopy(plan["resource_changes"][0]))
        with self.assertRaises(Refused):
            verify_gpu_plan(plan, BINDING)

    def test_id_wrong_handle_or_open_fallback_refused(self):
        for field, value in (
            ("capacity_reservation_id", "cr-too-early"),
            ("capacity_reservation_resource_group_arn", GROUP + "-other"),
        ):
            plan = copy.deepcopy(self.plan)
            spec = plan["resource_changes"][1]["change"]["after"][
                "capacity_reservation_specification"
            ][0]
            spec["capacity_reservation_target"][0][field] = value
            with self.subTest(field=field), self.assertRaises(Refused):
                verify_gpu_plan(plan, BINDING)
        plan = copy.deepcopy(self.plan)
        plan["resource_changes"][1]["change"]["after"]["capacity_reservation_specification"][0][
            "capacity_reservation_preference"
        ] = "open"
        with self.assertRaises(Refused):
            verify_gpu_plan(plan, BINDING)

    def test_autoscaler_warm_pool_or_other_resources_refused(self):
        for resource_type in (
            "aws_autoscaling_group",
            "aws_autoscaling_policy",
            "aws_autoscaling_warm_pool",
            "aws_instance",
            "aws_ec2_capacity_reservation",
            "helm_release",
        ):
            plan = copy.deepcopy(self.plan)
            plan["resource_changes"].append({"type": resource_type})
            with self.subTest(resource_type=resource_type), self.assertRaises(Refused):
                verify_gpu_plan(plan, BINDING)

    def test_source_has_no_extra_session_resource_kinds(self):
        # Complements plan-value tests: capacity automation cannot hide in another
        # resource/module that is absent from the chosen test variables.
        import re

        from inference_platform.m5_infra_safety import SESSION_TYPES

        root = Path(__file__).resolve().parents[2] / "infra/terraform/eks"
        source = "\n".join(p.read_text() for p in root.glob("*.tf"))
        kinds = set(re.findall(r'resource\s+"([^"]+)"', source))
        self.assertEqual(kinds, SESSION_TYPES)
        self.assertNotRegex(source, r'(?m)^\s*module\s+"')
        self.assertNotIn(
            "create_before_destroy", source.replace("# Deliberately no create_before_destroy", "#")
        )


if __name__ == "__main__":
    unittest.main()
