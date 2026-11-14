"""Service-specific descriptive teardown readbacks, joined to accepted validation."""

import time
import json
from pathlib import Path

from inference_platform.eks_deployment import TEARDOWN_SCOPES, verify_teardown
from m5_descriptive_cleanup import missing, owned_session, pages


def gpu_states(sdk, session, known_ids=()):
    """Retain IDs across MNG/ASG deletion; disappearance is not termination."""
    ec2 = sdk.client("ec2")
    reservations = []
    for tag in ("Session", "eks:cluster-name", "aws:eks:cluster-name"):
        reservations += pages(
            ec2,
            "describe_instances",
            "Reservations",
            Filters=[{"Name": "tag:" + tag, "Values": [session]}],
        )
    ids = set(known_ids)
    for group in pages(
        sdk.client("autoscaling"), "describe_auto_scaling_groups", "AutoScalingGroups"
    ):
        if group["AutoScalingGroupName"].startswith("eks-" + session + "-"):
            ids.update(i["InstanceId"] for i in group.get("Instances", []))
    if ids:
        reservations += pages(
            ec2, "describe_instances", "Reservations", InstanceIds=sorted(ids)
        )
    return {
        item["InstanceId"]: item["State"]["Name"]
        for reservation in reservations
        for item in reservation["Instances"]
        if item["InstanceType"] == "g6.xlarge"
    }


def inventory(sdk, *, session, bucket, after_ms, vpc_ids=(), output=None):
    session = owned_session(session)
    operator = "dec077-" + session
    values = {key: [] for key in TEARDOWN_SCOPES}
    commands = {key: [] for key in TEARDOWN_SCOPES}

    def query(scope, service, operation, key, **kwargs):
        commands[scope].append(f"{service}.{operation}")
        try:
            return pages(sdk.client(service), operation, key, **kwargs)
        except Exception as error:
            if missing(error):
                return []
            raise

    clusters = query("eks_clusters", "eks", "list_clusters", "clusters")
    values["eks_clusters"] = [name for name in clusters if name == session]
    values["nodegroups"] = query(
        "nodegroups", "eks", "list_nodegroups", "nodegroups", clusterName=session
    )
    ec2_scopes = {
        "volumes": ("describe_volumes", "Volumes"),
        "interfaces": ("describe_network_interfaces", "NetworkInterfaces"),
        "security_groups": ("describe_security_groups", "SecurityGroups"),
        "public_ips": ("describe_addresses", "Addresses"),
        "vpc_endpoints": ("describe_vpc_endpoints", "VpcEndpoints"),
        "nat_gateways": ("describe_nat_gateways", "NatGateways"),
        "vpcs": ("describe_vpcs", "Vpcs"),
        "capacity_reservations": (
            "describe_capacity_reservations",
            "CapacityReservations",
        ),
    }
    for scope, (operation, key) in ec2_scopes.items():
        rows = []
        for owner in (session, operator):
            rows += query(
                scope,
                "ec2",
                operation,
                key,
                Filters=[{"Name": "tag:Session", "Values": [owner]}],
            )
        if scope == "capacity_reservations":
            rows = [
                r for r in rows if r["State"] not in {"cancelled", "expired", "failed"}
            ]
        if scope == "nat_gateways":
            rows = [r for r in rows if r["State"] != "deleted"]
        values[scope] = rows
    known_vpcs = set(vpc_ids) | {r["VpcId"] for r in values["vpcs"]}
    if known_vpcs:
        for scope, operation, key in (
            ("interfaces", "describe_network_interfaces", "NetworkInterfaces"),
            ("security_groups", "describe_security_groups", "SecurityGroups"),
        ):
            values[scope] += query(
                scope,
                "ec2",
                operation,
                key,
                Filters=[{"Name": "vpc-id", "Values": sorted(known_vpcs)}],
            )
    for tag, owner in (
        ("Session", session),
        ("Session", operator),
        ("eks:cluster-name", session),
        ("aws:eks:cluster-name", session),
    ):
        reservations = query(
            "instances",
            "ec2",
            "describe_instances",
            "Reservations",
            Filters=[{"Name": "tag:" + tag, "Values": [owner]}],
        )
        values["instances"] += [
            i
            for r in reservations
            for i in r["Instances"]
            if i["State"]["Name"] != "terminated"
        ]
    for item in query(
        "load_balancers", "elbv2", "describe_load_balancers", "LoadBalancers"
    ):
        tags = sdk.client("elbv2").describe_tags(
            ResourceArns=[item["LoadBalancerArn"]]
        )["TagDescriptions"][0]["Tags"]
        if any(
            t["Key"] in {"Session", "elbv2.k8s.aws/cluster"} and t["Value"] == session
            for t in tags
        ):
            values["load_balancers"].append(item)
    for item in query(
        "target_groups", "elbv2", "describe_target_groups", "TargetGroups"
    ):
        tags = sdk.client("elbv2").describe_tags(ResourceArns=[item["TargetGroupArn"]])[
            "TagDescriptions"
        ][0]["Tags"]
        if item.get("VpcId") in known_vpcs or any(
            t["Key"] == "Session" and t["Value"] == session for t in tags
        ):
            values["target_groups"].append(item)
    values["log_groups"] = query(
        "log_groups",
        "logs",
        "describe_log_groups",
        "logGroups",
        logGroupNamePrefix="/aws/eks/" + session + "/",
    )
    values["ecr_repositories"] = query(
        "ecr_repositories",
        "ecr",
        "describe_repositories",
        "repositories",
        repositoryNames=[session],
    )
    buckets = query("state_buckets", "s3", "list_buckets", "Buckets")
    values["state_buckets"] = [b for b in buckets if b["Name"] == bucket]
    values["bucket_versions"] = query(
        "bucket_versions", "s3", "list_object_versions", "Versions", Bucket=bucket
    )
    values["bucket_versions"] += query(
        "bucket_versions", "s3", "list_object_versions", "DeleteMarkers", Bucket=bucket
    )
    values["lockfiles"] = [
        r for r in values["bucket_versions"] if r["Key"].endswith(".tflock")
    ]
    commands["lockfiles"] = list(commands["bucket_versions"])
    values["capacity_groups"] = [
        r
        for r in query(
            "capacity_groups", "resource-groups", "list_groups", "GroupIdentifiers"
        )
        if r["GroupName"] == session + "-capacity"
    ]
    # These are not among the legacy validator's scope names, so require them
    # separately. An empty Terraform state alone never establishes cleanup.
    extra = {}
    for key, operation, field, name in (
        ("roles", "list_roles", "Roles", "RoleName"),
        (
            "profiles",
            "list_instance_profiles",
            "InstanceProfiles",
            "InstanceProfileName",
        ),
    ):
        rows = pages(sdk.client("iam"), operation, field)
        extra[key] = [
            r[name]
            for r in rows
            if r[name].startswith((session + "-", operator + "-"))
            and not r[name].startswith(session + "-cleanup")
        ]
    extra["launch_templates"] = pages(
        sdk.client("ec2"),
        "describe_launch_templates",
        "LaunchTemplates",
        Filters=[{"Name": "tag:Session", "Values": [session]}],
    )
    extra["autoscaling_groups"] = [
        group["AutoScalingGroupName"]
        for group in pages(
            sdk.client("autoscaling"),
            "describe_auto_scaling_groups",
            "AutoScalingGroups",
        )
        if group["AutoScalingGroupName"].startswith("eks-" + session + "-")
    ]
    receipt = {
        "schema": "m5-teardown-inventory-v1",
        "session_id": session,
        "region": "us-east-1",
        "destroy_status": "succeeded",
        "inventories": {
            key: {
                "complete": True,
                "command": commands[key],
                "observed_ms": int(time.time() * 1000),
                "error": None,
                "resources": values[key],
            }
            for key in TEARDOWN_SCOPES
        },
        "extra": extra,
    }
    try:
        receipt["validation"] = verify_teardown(
            receipt, session_id=session, after_ms=after_ms
        )
        if any(extra.values()):
            raise ValueError("descriptive:extra_inventory_nonempty")
    except Exception as error:
        receipt["validation_error"] = type(error).__name__ + ":" + str(error)
        raise
    finally:
        if output is not None:
            Path(output).write_text(json.dumps(receipt, indent=2, default=str))
    return receipt
