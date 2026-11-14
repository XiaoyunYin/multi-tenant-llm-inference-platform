"""Offline INF-019 contracts. No AWS client, CLI, marker parser or paid entry point.

The injected port is deliberately implemented only by test doubles in this slice.
It models the ordering a later reviewed paid controller must enforce, including
ambiguous acquisition and cleanup errors. It cannot authorize a real consume.
"""

import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from hashlib import sha256
from typing import Protocol


class Refused(ValueError):
    pass


@dataclass(frozen=True)
class Binding:
    group_arn: str
    zone: str
    instance_type: str = "g6.xlarge"
    platform: str = "Linux/UNIX"
    tenancy: str = "default"
    count: int = 2

    def __post_init__(self) -> None:
        if (
            not self.group_arn.startswith("arn:aws:resource-groups:us-east-1:")
            or ":group/m5-" not in self.group_arn
            or self.zone not in {f"us-east-1{suffix}" for suffix in "abcdef"}
            or (self.instance_type, self.platform, self.tenancy, self.count)
            != ("g6.xlarge", "Linux/UNIX", "default", 2)
        ):
            raise Refused("invalid capacity binding")


@dataclass(frozen=True)
class Reservation:
    reservation_id: str
    zone: str
    instance_type: str = "g6.xlarge"
    platform: str = "Linux/UNIX"
    tenancy: str = "default"
    total: int = 2
    available: int = 2
    state: str = "active"
    match_criteria: str = "targeted"


def verify_reservation(binding: Binding, reservation: Reservation) -> None:
    if (
        not reservation.reservation_id
        or (reservation.zone, reservation.instance_type, reservation.platform, reservation.tenancy)
        != (binding.zone, binding.instance_type, binding.platform, binding.tenancy)
        or (reservation.total, reservation.available) != (binding.count, binding.count)
        or reservation.state != "active"
        or reservation.match_criteria != "targeted"
    ):
        raise Refused("capacity mismatch or unavailable; no fallback")


def verify_group(reservation: Reservation, members: Sequence[str]) -> None:
    if list(members) != [reservation.reservation_id]:
        raise Refused("group must contain only this verified reservation")


def wait_terminated(
    inventory: Callable[[], Mapping[str, str]],
    wait: Callable[[], None],
    max_polls: int,
    old_ids: frozenset[str] = frozenset(),
) -> None:
    """Inventory must cover all GPU usage, not just tagged/current ASG members.

    Missing old IDs are unknown, never proof of termination. Retain observations
    of newly discovered IDs too, so a later incomplete inventory cannot clear it.
    Only EC2's literal `terminated` is safe, including for shutting-down hosts.
    """
    known = set(old_ids)
    for attempt in range(max_polls):
        states = inventory()
        known.update(states)
        if all(states.get(instance_id) == "terminated" for instance_id in known):
            return
        if attempt + 1 < max_polls:
            wait()
    raise Refused("GPU termination unverified; no recreate or reservation cancellation")


def recreate_gpu(
    path: str,
    old_ids: frozenset[str],
    destroy: Callable[[], None],
    inventory: Callable[[], Mapping[str, str]],
    wait: Callable[[], None],
    create: Callable[[], None],
    max_polls: int = 3,
) -> None:
    if path != "destroy-recreate" or not old_ids:
        raise Refused("GPU node-group updates refused; recorded destroy/recreate path required")
    destroy()
    wait_terminated(inventory, wait, max_polls, old_ids)
    create()


# No autoscaling policy, warm pool, mixed fleet, external module or reservation
# resource is allowed in a session plan. Capacity is acquired separately later.
SESSION_TYPES = frozenset(
    {
        "terraform_data",
        "aws_vpc",
        "aws_internet_gateway",
        "aws_subnet",
        "aws_route_table",
        "aws_route_table_association",
        "aws_iam_role",
        "aws_iam_role_policy_attachment",
        "aws_cloudwatch_log_group",
        "aws_eks_cluster",
        "aws_eks_addon",
        "aws_eks_access_entry",
        "aws_eks_access_policy_association",
        "aws_launch_template",
        "aws_eks_node_group",
        "aws_ecr_repository",
    }
)


def verify_gpu_plan(plan: Mapping, packet_binding: Binding | None = None) -> Binding:
    """Derive capacity from reviewed JSON and require agreement with the packet.

    Missing, unknown or malformed capacity fields refuse before any lifecycle
    operation. The packet is a cross-check, never the acquisition input.
    """
    try:
        return _verify_gpu_plan(plan, packet_binding)
    except (KeyError, TypeError, IndexError, AttributeError) as error:
        raise Refused("missing, unknown or malformed plan capacity values") from error


def verify_gpu_recreate_plan(plan: Mapping, packet_binding: Binding | None = None) -> Binding:
    """Require two GPU creates and retained no-ops after the termination barrier.

    A future wrapper must bind this JSON to the real saved recreate binary.
    Refusal is a DEC-041 halt, never permission to regenerate and retry.
    """
    binding = verify_gpu_plan(plan, packet_binding)
    expected = {
        "aws_launch_template.gpu[0]": ("aws_launch_template", "gpu"),
        "aws_eks_node_group.gpu[0]": ("aws_eks_node_group", "gpu"),
    }
    try:
        seen = set()
        created = set()
        for resource in plan["resource_changes"]:
            address = resource["address"]
            if address in seen or resource.get("mode") != "managed":
                raise Refused("duplicate or non-managed recreate resource")
            seen.add(address)
            change = resource["change"]
            if address in expected:
                if (resource["type"], resource["name"]) != expected[address] or change[
                    "actions"
                ] != ["create"]:
                    raise Refused("recreate must create both GPU resources only")
                created.add(address)
            elif change["actions"] != ["no-op"] or change.get("replace_paths", []) != []:
                raise Refused("retained recreate resource must be no-op without replacement paths")
        if created != set(expected):
            raise Refused("recreate requires both GPU creates at their exact addresses")
    except (KeyError, TypeError, IndexError, AttributeError) as error:
        raise Refused("missing or malformed GPU recreate plan") from error
    return binding


def verify_gpu_destroy_plan(plan: Mapping) -> None:
    """Offline model: exactly two GPU deletions; every other resource is no-op.

    This does not apply a plan or establish EC2 termination. A future wrapper
    must bind this JSON to the saved destroy binary and enforce the barrier.
    """
    expected = {
        "aws_eks_node_group.gpu[0]": ("aws_eks_node_group", "gpu"),
        "aws_launch_template.gpu[0]": ("aws_launch_template", "gpu"),
    }
    try:
        changes = plan["resource_changes"]
        if not isinstance(changes, list):
            raise Refused("missing destroy resource changes")
        seen = set()
        deleted = set()
        for resource in changes:
            address = resource["address"]
            if address in seen or resource.get("mode", "managed") != "managed":
                raise Refused("duplicate or non-managed destroy resource")
            seen.add(address)
            actions = resource["change"]["actions"]
            if address in expected:
                if (
                    (resource["type"], resource["name"]) != expected[address]
                    or actions != ["delete"]
                    or resource["change"]["after"] is not None
                ):
                    raise Refused("destroy must delete both GPU resources only")
                deleted.add(address)
            elif actions != ["no-op"] or resource["type"] not in SESSION_TYPES:
                raise Refused("non-GPU destroy action refused")
        if deleted != set(expected):
            raise Refused("destroy requires both GPU deletions")
    except (KeyError, TypeError, IndexError, AttributeError) as error:
        raise Refused("missing or malformed GPU destroy plan") from error


def _verify_gpu_plan(plan: Mapping, packet_binding: Binding | None) -> Binding:
    """Inspect Terraform JSON values and configuration references, never source text.

    The initial/recreate packet must create the GPU group/template separately
    from deleting the prior group. Even delete-before-create in one plan lacks
    an EC2 termination barrier. Never accept an in-place update as a rollout.
    """
    output = plan["output_changes"]["capacity_binding"]["after"]
    binding = Binding(
        group_arn=output["group_arn"],
        zone=output["zone"],
        instance_type=output["type"],
        platform=output["platform"],
        tenancy=output["tenancy"],
        count=output["count"],
    )
    changes = plan.get("resource_changes")
    if not isinstance(changes, list):
        raise Refused("missing resource changes")
    configurations = plan["configuration"]["root_module"]["resources"]
    if not isinstance(configurations, list):
        raise Refused("missing root resource configuration")
    configured_gpu = [
        resource for resource in configurations if resource["address"] == "aws_eks_node_group.gpu"
    ]
    if len(configured_gpu) != 1:
        raise Refused("exactly one GPU node-group configuration required")
    references = configured_gpu[0]["expressions"]["subnet_ids"]["references"]
    if not isinstance(references, list) or not all(isinstance(ref, str) for ref in references):
        raise Refused("missing or malformed GPU subnet references")
    # Terraform unwraps traversals into instance, attribute and collection
    # references. Compare opaque addresses by equality as documented, rather
    # than counting those repeated steps as multiple subnet instances.
    subnet_addresses = {
        resource["address"]
        for resource in changes
        if resource["type"] == "aws_subnet" and resource["name"] == "m5"
    }
    referenced_subnets = {
        address
        for address in subnet_addresses
        if address in references or f"{address}.id" in references
    }
    if len(referenced_subnets) != 1:
        raise Refused("GPU subnet_ids must reference exactly one planned aws_subnet.m5 instance")
    gpu_subnet_address = referenced_subnets.pop()
    allowed_references = {
        "local.gpu_subnet",
        "aws_subnet.m5",
        gpu_subnet_address,
        f"{gpu_subnet_address}.id",
    }
    if not set(references) <= allowed_references:
        raise Refused("unexpected or ambiguous GPU subnet reference")
    gpu = []
    gpu_unknown = []
    templates = []
    gpu_subnets = []
    cpu_count = 0
    for resource in changes:
        if resource.get("mode", "managed") != "managed" or resource["type"] not in SESSION_TYPES:
            raise Refused("unexpected resource or capacity automation")
        actions = resource["change"]["actions"]
        if resource.get("address") == gpu_subnet_address:
            gpu_subnets.append(resource["change"]["after"])
        if resource["type"] == "aws_launch_template":
            templates.append(resource["change"]["after"])
            if actions != ["create"]:
                raise Refused("GPU launch-template updates/replacements refused")
        if resource["type"] == "aws_eks_node_group" and resource["name"] == "gpu":
            gpu.append(resource["change"]["after"])
            gpu_unknown.append(resource["change"].get("after_unknown", {}))
            if actions != ["create"]:
                raise Refused("GPU node-group updates/replacements refused")
        elif resource["type"] == "aws_eks_node_group":
            cpu_count += 1
            cpu = resource["change"]["after"]
            if (
                resource["name"] != "cpu"
                or cpu_count > 1
                or cpu["instance_types"] != ["c6i.2xlarge"]
                or cpu["scaling_config"] != [{"desired_size": 2, "max_size": 2, "min_size": 2}]
            ):
                raise Refused("additional GPU group or unbounded CPU footprint")
    if len(gpu) != 1 or len(templates) != 1 or len(gpu_subnets) != 1:
        raise Refused("exactly one two-node GPU group, template and GPU subnet required")
    group, template = gpu[0], templates[0]
    # A real provider's set containing a new subnet ID is wholly unknown;
    # Terraform omits it from after. Configuration above proves one instance.
    # A known singleton has one literal false per element in after_unknown.
    if "subnet_ids" not in group:
        single_subnet = gpu_unknown[0].get("subnet_ids") is True
    else:
        subnets = group["subnet_ids"]
        unknown_subnets = gpu_unknown[0].get("subnet_ids")
        single_subnet = (
            isinstance(subnets, list)
            and len(subnets) == 1
            and isinstance(subnets[0], str)
            and bool(subnets[0])
            and isinstance(unknown_subnets, list)
            and len(unknown_subnets) == 1
            and unknown_subnets[0] is False
        )
    # Only the pinned NVIDIA Linux AMI is supported by this slice. Never assume
    # an unknown/custom/Windows AMI has the Linux/UNIX reservation platform.
    platform = {"AL2023_x86_64_NVIDIA": "Linux/UNIX"}.get(group["ami_type"])
    if (
        gpu_subnets[0]["availability_zone"] != binding.zone
        or len(template["placement"]) != 1
        or template["placement"][0]["tenancy"] != binding.tenancy
        or platform != binding.platform
        or (packet_binding is not None and packet_binding != binding)
    ):
        raise Refused("plan output, GPU subnet/template/AMI and packet capacity disagree")
    if (
        group["capacity_type"] != "ON_DEMAND"
        or group["scaling_config"] != [{"desired_size": 2, "max_size": 2, "min_size": 2}]
        or len(group["node_repair_config"]) != 1
        or group["node_repair_config"][0]["enabled"] is not False
        or not single_subnet
        or template["instance_type"] != binding.instance_type
        or group.get("warm_pool_config", [])
        or group.get("update_config", [])
        or group.get("force_update_version")
    ):
        raise Refused("GPU bound changed")
    specification = template["capacity_reservation_specification"]
    if len(specification) != 1:
        raise Refused("missing capacity specification")
    spec = specification[0]
    target = spec["capacity_reservation_target"]
    if (
        spec["capacity_reservation_preference"] != "capacity-reservations-only"
        or len(target) != 1
        or target[0].get("capacity_reservation_id") is not None
        or target[0].get("capacity_reservation_resource_group_arn") != binding.group_arn
    ):
        raise Refused("plan must target only the reviewed group; no ID or fallback")
    return binding


class MockLifecyclePort(Protocol):
    """Abstract operations for the offline model; no production adapter exists."""

    def marker(self, plan_hash: str) -> None: ...
    def group_members(self, group_arn: str) -> Sequence[str]: ...
    def acquire(self, token: str, binding: Binding) -> Reservation: ...
    def add(self, group_arn: str, reservation: Reservation) -> None: ...
    def consume(self, plan_hash: str) -> None: ...
    def apply(self, saved_plan: bytes) -> None: ...
    def destroy_and_wait(self) -> None: ...
    def cancel_and_verify(self, token: str) -> None: ...


def rehearse_lifecycle(
    port: MockLifecyclePort,
    read_plan: Callable[[], bytes],
    expected_hash: str,
    packet_binding: Binding,
) -> None:
    """Mock marker -> reserve -> group -> unchanged hash -> consume -> apply.

    The acquisition token must be durable in the future wrapper; cancellation by
    token covers an acquisition whose response is lost. Destroy/wait precedes
    cancellation. Attempt cancellation even if destruction fails; propagate
    cleanup errors and never advance to another AZ here. This is a single-exit
    ordering model, not crash/SIGKILL recovery or actual paid authorization.
    """
    plan = read_plan()
    if sha256(plan).hexdigest() != expected_hash:
        raise Refused("plan hash changed before reservation")
    try:
        parsed_plan = json.loads(plan)
    except (ValueError, UnicodeError) as error:
        raise Refused("invalid reviewed plan JSON") from error
    binding = verify_gpu_plan(parsed_plan, packet_binding)
    port.marker(expected_hash)
    if port.group_members(binding.group_arn):
        raise Refused("capacity group is not empty")
    token = expected_hash
    try:
        reservation = port.acquire(token, binding)
        verify_reservation(binding, reservation)
        port.add(binding.group_arn, reservation)
        verify_group(reservation, port.group_members(binding.group_arn))
        if read_plan() != plan:
            raise Refused("plan changed after reservation")
        port.consume(expected_hash)
        port.apply(plan)
    finally:
        try:
            port.destroy_and_wait()
        finally:
            port.cancel_and_verify(token)
