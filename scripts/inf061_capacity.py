"""Operator-side single-slot ODCR hunt using the reviewed R1 and DEC-100 ports."""

import json
import math
import os
import time
from datetime import UTC, datetime
from pathlib import Path

import inf060_probe_spec as spec
from inference_platform.r1_lifecycle import Production
from m5_descriptive_capacity import EKS_ZONES, select_capacity

ZONES = EKS_ZONES
WAIT_S = 21600
SPACING_S = 120
GPU_SECONDS = 45120
OPERATOR_SECONDS = 47800 + WAIT_S
RESERVATION_EXTRA_S = 1800
KEY = "capacity_hunt"
PRIMARY_ZONE = "us-east-1b"
ROOTS = {
    zone: "terraform" if zone == PRIMARY_ZONE else f"gpu-plans/{zone}" for zone in ZONES
}
PLAN_SOURCE = "docs/INF061_HUNTER_PLAN.json"
STATE = "capacity-selected.json"


def options():
    return {
        "zones": list(ZONES),
        "wait_s": WAIT_S,
        "cycle_spacing_s": SPACING_S,
        "reservation_extra_s": RESERVATION_EXTRA_S,
    }


def active_reservations(invoke):
    # Read the region, including untagged rows. Never mutate outside the
    # session-tagged R1 selector.
    response = invoke(
        "ec2",
        "describe-capacity-reservations",
        [
            "--filters",
            "Name=state,Values=active,pending",
        ],
    )
    spec.check(not response.get("NextToken"), "open_capacity_reservations_incomplete")
    return response["CapacityReservations"]


class OpenCapacityReadbackPending(ValueError):
    """The expected newly launched instance has incomplete EC2 readback."""


def open_capacity_guard(invoke, session, selection, *, operator_id, launched_id=None):
    rows = active_reservations(invoke)
    spec.check(len(rows) == 1, "open_capacity_regional_reservation_count")
    slot = rows[0]
    available = slot["AvailableInstanceCount"]
    spec.check(
        slot["CapacityReservationId"] == selection["reservation_id"]
        and slot["AvailabilityZone"] == selection["zone"]
        and slot["State"] == "active"
        and slot["InstanceMatchCriteria"] == "open"
        and slot["TotalInstanceCount"] == 1
        and available in ((0, 1) if launched_id else (1,))
        and {"Key": "Session", "Value": session} in slot.get("Tags", []),
        "open_capacity_selected_reservation",
    )
    response = invoke(
        "ec2",
        "describe-instances",
        ["--filters", "Name=instance-state-name,Values=pending,running"],
    )
    spec.check(not response.get("NextToken"), "open_capacity_inventory_incomplete")
    instances = [
        row for group in response["Reservations"] for row in group["Instances"]
    ]
    expected = {
        identifier
        for identifier in (operator_id, launched_id)
        if identifier is not None
    }
    observed = {row["InstanceId"]: row for row in instances}
    spec.check(
        len(observed) == len(instances)
        and observed.keys() <= expected
        and (operator_id is None or operator_id in observed),
        "open_capacity_foreign_instance",
    )
    if launched_id is None:
        return
    launched = observed.get(launched_id)
    if launched is None:
        raise OpenCapacityReadbackPending("open_capacity_launched_instance_pending")
    binding = launched.get("CapacityReservationId")
    spec.check(
        binding in (None, selection["reservation_id"])
        and launched["Placement"]["AvailabilityZone"] == selection["zone"]
        and {"Key": "Session", "Value": session} in launched.get("Tags", []),
        "capacity_instance_readback",
    )
    if binding is None or available != 0:
        raise OpenCapacityReadbackPending("open_capacity_association_pending")


def verify_open_launch(
    invoke,
    session,
    selection,
    *,
    operator_id,
    launched_id,
    end,
    clock=time.time,
    sleep=time.sleep,
):
    spec.check(
        bool(launched_id) and launched_id != operator_id,
        "open_capacity_launched_identity",
    )
    attempts, delay = 0, 2
    while True:
        attempts += 1
        try:
            open_capacity_guard(
                invoke,
                session,
                selection,
                operator_id=operator_id,
                launched_id=launched_id,
            )
        except OpenCapacityReadbackPending as exc:
            left = end - clock()
            if left <= 0:
                raise TimeoutError("inf060:" + str(exc)) from exc
            sleep(min(delay, left))
            delay = min(delay * 2, 8)
        else:
            return attempts


def open_template_placement(zone):
    return {"AvailabilityZone": zone, "Tenancy": "default"}


OPEN_CAPACITY_PREFERENCE = "capacity-reservations-only"


def reservation_inventory(invoke, session):
    rows = active_reservations(invoke)
    templates = invoke(
        "ec2",
        "describe-launch-templates",
        [
            "--filters",
            "Name=tag:Session,Values=" + session,
        ],
    )["LaunchTemplates"]
    tags = [{v["Key"]: v["Value"] for v in row.get("Tags", [])} for row in rows]
    return {
        "launch_templates": len(templates),
        "session_reservations": sum(row.get("Session") == session for row in tags),
        "untagged_regional_reservations": sum(not row.get("Session") for row in tags),
        "foreign_regional_reservations": sum(
            bool(row.get("Session")) and row["Session"] != session for row in tags
        ),
    }


class ReservationPorts(Production):
    def __init__(self, directory, session, *, instance_type=spec.SHAPE):
        self.directory = Path(directory)
        self.repo = self.directory
        self.aws_calls = 0
        self.inputs = {
            "region": spec.REGION,
            "session_id": session,
            "availability_zone": None,
            "gpu_type": instance_type,
        }

    def child_environment(self):
        return {
            **os.environ,
            "AWS_REGION": spec.REGION,
            "AWS_DEFAULT_REGION": spec.REGION,
            "AWS_MAX_ATTEMPTS": "1",
        }

    def aws(self, service, operation, args, deadline, name):
        self.aws_calls += 1
        return json.loads(
            self.command(
                [
                    "aws",
                    "--region",
                    spec.REGION,
                    service,
                    operation,
                    *args,
                    "--output",
                    "json",
                    "--no-cli-pager",
                ],
                deadline,
                name,
            )
            or b"{}"
        )

    def reserve_capacity(self, deadline):
        regional = active_reservations(
            lambda s, o, a: self.aws(
                s, o, a, deadline, "capacity-regional-before-probe"
            )
        )
        spec.check(not regional, "capacity_regional_not_empty")
        history = self.describe_capacity_reservations(deadline, "capacity-prior-holds")
        # Immediate capacity refusals have no active slot. Allow for at most
        # two early 900-second holds, including a future selected reservation.
        cancelled = {
            row["CapacityReservationId"]
            for row in history
            if self._reservation_state(row) in {"cancelled", "expired"}
        }
        spec.check(len(cancelled) < 2, "capacity_hold_budget")
        return super().reserve_capacity(
            deadline, instance_count=1, match_criteria="open"
        )


class Hunter:
    def __init__(
        self,
        directory,
        manifest,
        *,
        clock=time.monotonic,
        epoch=time.time,
        instance_type=spec.SHAPE,
    ):
        self.directory = Path(directory)
        self.original = manifest
        self.clock = clock
        self.epoch = epoch
        self.capacity = ReservationPorts(
            self.directory, manifest["session"], instance_type=instance_type
        )
        self.deadline = clock() + WAIT_S
        self.manifest = {
            "timing": {
                "capacity_wait_budget_seconds": WAIT_S,
                "capacity_cycle_spacing_seconds": SPACING_S,
                "retrieval_reserve_seconds": 0,
                **dict.fromkeys(
                    (
                        "minimum_workload_seconds",
                        "initial_startup_budget_seconds",
                        "source_upload_budget_seconds",
                        "cleanup_reserve_seconds",
                        "remaining_infrastructure_seconds",
                    ),
                    0,
                ),
            },
            "alternatives": [{"zone": az, "directory": ROOTS[az]} for az in ZONES],
        }
        self.selection = None
        self.sleep = time.sleep

    def hold_open(self, identifier, *, deadline):
        zone = self.capacity.inputs["availability_zone"]
        selected_epoch = self.epoch()
        end = int(selected_epoch + self.original["deadline_seconds"])
        deadline = min(deadline, self.clock() + 60)
        command = [
            "--capacity-reservation-id",
            identifier,
            "--end-date-type",
            "limited",
            "--end-date",
            datetime.fromtimestamp(end, UTC).isoformat(),
        ]
        self.capacity.aws(
            "ec2", "modify-capacity-reservation", command, deadline, "capacity-hold"
        )
        while self.clock() < deadline:
            rows = self.capacity.describe_capacity_reservations(
                deadline, "capacity-hold-readback", identifier
            )
            spec.check(
                len(rows) == 1
                and self.capacity._reservation_matches_probe(
                    rows[0], identifier, instance_count=1, match_criteria="open"
                ),
                "capacity_selected_readback",
            )
            observed = datetime.fromisoformat(
                rows[0]["EndDate"].replace("Z", "+00:00")
            ).timestamp()
            spec.check(observed <= end, "capacity_hold_end")
            if observed == end:
                break
            self.sleep(min(1, max(0, deadline - self.clock())))
        else:
            raise TimeoutError("capacity_hold_readback")
        self.selection = {
            "zone": zone,
            "selected_epoch": selected_epoch,
            "reservation_id": identifier,
            "hold_end_epoch": end,
            "plan_sha256": self.original[KEY]["plans"][zone]["create_sha256"],
        }

    def select(self, *, sleep=time.sleep):
        # The existing cycle logic owns every non-selection's cancellation.
        self.sleep = sleep
        picked = select_capacity(
            self,
            clock=self.clock,
            sleep=sleep,
            epoch=self.epoch,
            prepare_choice=self.hold_open,
        )
        row = self.selection
        spec.check(
            row and picked == {"zone": row["zone"], "directory": ROOTS[row["zone"]]},
            "capacity_selected_plan",
        )
        with (self.directory / STATE).open("x", encoding="utf-8") as stream:
            json.dump(row, stream)
            stream.flush()
            os.fsync(stream.fileno())
        return row


def selected_plan(directory, manifest):
    row = spec.load(directory / STATE)
    zone = row["zone"]
    epoch = row["selected_epoch"]
    root = directory / ROOTS[zone]
    binding = manifest[KEY]["plans"][zone]
    spec.check(
        not root.is_symlink()
        and type(epoch) in (int, float)
        and math.isfinite(epoch)
        and row["hold_end_epoch"] == int(epoch + manifest["deadline_seconds"])
        and row["plan_sha256"] == binding["create_sha256"]
        and spec.facts(root / "create.tfplan")["sha256"] == row["plan_sha256"],
        "capacity_selected_plan",
    )
    return row, root


def close_reservation(directory, manifest, end):
    ports = ReservationPorts(directory, manifest["session"])
    deadline = time.monotonic() + max(0, end - time.time())
    spec.check(
        ports.cancel_session_capacity_reservations(deadline),
        "capacity_cancel_unverified",
    )
    row = reservation_inventory(
        lambda s, o, a: ports.aws(s, o, a, deadline, "capacity-final-inventory"),
        manifest["session"],
    )
    spec.check(not any(row.values()), "capacity_inventory_unverified")
    return row


def validate_binding(directory, manifest):
    from inf060_probe_spec import TERRAFORM_FILES, verify_plan

    capacity = manifest[KEY]
    if (
        set(capacity) != {"options", "plans"}
        or capacity["options"] != options()
        or set(capacity["plans"]) != set(ZONES)
    ):
        raise ValueError("inf061:capacity_scope")
    expected_paths = set()
    for zone, folder in ROOTS.items():
        root = directory / folder
        for name in (
            *TERRAFORM_FILES,
            "create.tfplan",
            "create.json",
            "input.tfvars.json",
        ):
            if zone != PRIMARY_ZONE:
                expected_paths.add(folder + "/" + name)
        values = spec.load(root / "input.tfvars.json")
        spec.check(
            values == spec.load(directory / "terraform/input.tfvars.json"),
            "capacity_zone_variables",
        )
        binary = spec.facts(root / "create.tfplan")["sha256"]
        plan_hex = spec.facts(root / "create.json")["sha256"]
        spec.check(
            capacity["plans"][zone]
            == {"create_sha256": binary, "json_sha256": plan_hex},
            "capacity_zone_digest",
        )
        view = spec.load(root / "create.json")
        verify_plan(
            view,
            values,
            (root / "user-data.sh").read_text(encoding="utf-8"),
            timer=manifest["host_timer_seconds"],
            zone=zone,
            open_capacity=True,
        )
    actual_paths = {
        name for name in manifest["artifacts"] if name.startswith("gpu-plans/")
    }
    spec.check(expected_paths == actual_paths, "capacity_plan_file_set")


def policy_cases(account, session):
    ec2 = f"arn:aws:ec2:{spec.REGION}:{account}:"
    reservation = ec2 + "capacity-reservation/cr-00000000000000000"
    instance = ec2 + "instance/i-00000000000000000"
    owned = {"ec2:ResourceTag/Session": session}
    requested = {"aws:RequestTag/Session": session}
    cases = [
        (
            "ec2:CreateCapacityReservation",
            zone,
            reservation,
            {
                **requested,
                "ec2:AvailabilityZone": zone,
                "ec2:InstanceType": spec.SHAPE,
                "ec2:InstancePlatform": "Linux/UNIX",
                "ec2:Tenancy": "default",
                "ec2:EndDateType": "limited",
                "ec2:InstanceMatchCriteria": "open",
                "ec2:InstanceCount": 1,
            },
        )
        for zone in ZONES
    ]
    cases.extend(
        (
            "ec2:RunInstances",
            zone,
            instance,
            {
                **requested,
                "ec2:AvailabilityZone": zone,
                "ec2:InstanceType": spec.SHAPE,
                "ec2:MetadataHttpTokens": "required",
            },
        )
        for zone in ZONES
    )
    cases.extend(
        [
            (
                "ec2:CreateTags",
                "create_reservation",
                reservation,
                {**requested, "ec2:CreateAction": "CreateCapacityReservation"},
            ),
            ("ec2:DescribeCapacityReservations", "regional", "*", {}),
            (
                "ec2:RunInstances",
                "owned_reservation",
                reservation,
                {"aws:ResourceTag/Session": session},
            ),
            *(
                (
                    "ec2:" + action,
                    "owned_reservation",
                    reservation,
                    {"aws:ResourceTag/Session": session},
                )
                for action in ("ModifyCapacityReservation", "CancelCapacityReservation")
            ),
        ]
    )
    template = ec2 + "launch-template/lt-00000000000000000"
    cases.extend(
        [
            ("ec2:CreateLaunchTemplate", "template", template, requested),
            (
                "ec2:CreateTags",
                "create_template",
                template,
                {**requested, "ec2:CreateAction": "CreateLaunchTemplate"},
            ),
            ("ec2:DeleteLaunchTemplate", "owned_template", template, owned),
            (
                "ec2:RunInstances",
                "owned_template",
                template,
                {"aws:ResourceTag/Session": session},
            ),
            ("ec2:DescribeLaunchTemplates", "regional", "*", {}),
            ("ec2:DescribeLaunchTemplateVersions", "regional", "*", {}),
        ]
    )
    return cases


def deny_policy_cases(account, session):
    action, _, resource, context = policy_cases(account, session)[0]
    return [
        (action, label, resource, {**context, key: value})
        for label, key, value in (
            ("targeted", "ec2:InstanceMatchCriteria", "targeted"),
            ("off_zone", "ec2:AvailabilityZone", "us-east-1e"),
            ("foreign_session", "aws:RequestTag/Session", "unowned"),
            ("two_slots", "ec2:InstanceCount", 2),
        )
    ]


def verify_capacity_policy(receipt, policy_sha256, account, session):
    from inf060_policy_gate import require_allowed

    def coverage(rows, cases):
        return sorted(
            (r["action"], r["resource"], tuple(r["context"])) for r in rows
        ) == sorted((a, b, tuple(sorted(ctx))) for a, b, _, ctx in cases)

    require_allowed(receipt["results"])
    spec.check(
        receipt["policy_sha256"] == policy_sha256
        and coverage(receipt["results"], policy_cases(account, session))
        and coverage(receipt["denied"], deny_policy_cases(account, session))
        and all(row["decision"] == "implicitDeny" for row in receipt["denied"]),
        "capacity_policy_simulation",
    )
