"""Independent scheduled AWS cleanup for one reviewed descriptive session.

Stdlib + Lambda's boto3. No operator process, disk, Terraform, or credentials
file is needed. Each minute makes bounded, idempotent progress; API errors keep
the schedule armed. The normal operator still destroys Terraform and verifies
the full service inventories before removing this backstop.
"""

import json
import os
import re
import time


def owned_session(value):
    if not re.fullmatch(r"m5-[a-z0-9-]{1,17}", value):
        raise ValueError("descriptive:cleanup_session")
    return value


def pages(client, operation, key, **kwargs):
    if client.can_paginate(operation):
        return [
            item
            for page in client.get_paginator(operation).paginate(**kwargs)
            for item in page.get(key, [])
        ]
    return getattr(client, operation)(**kwargs).get(key, [])


def missing(error):
    return getattr(error, "response", {}).get("Error", {}).get("Code") in {
        "ResourceNotFoundException",
        "ResourceNotFoundFault",
        "NoSuchBucket",
        "NoSuchEntity",
        "ParameterNotFound",
        "RepositoryNotFoundException",
        "InvalidGroup.NotFound",
        "InvalidVpcID.NotFound",
        "NotFoundException",
    }


def deadline(ssm, parameter):
    try:
        record = json.loads(ssm.get_parameter(Name=parameter)["Parameter"]["Value"])
    except Exception:
        return 0  # Unreadable authority fails closed to cleanup, never extends.
    if (
        not isinstance(record, dict)
        or set(record) != {"session", "started_epoch", "deadline_epoch"}
        or not all(
            type(record[key]) in (int, float)
            for key in ("deadline_epoch", "started_epoch")
        )
        or record["deadline_epoch"] - record["started_epoch"] != 18000
    ):
        return 0
    if record["session"] != os.environ["SESSION"]:
        return 0
    return record["deadline_epoch"]


def clean(sdk, session, bucket):
    """Only exact cluster/repository/bucket names and owned EC2 VPCs are touched."""
    session = owned_session(session)
    operator = "dec077-" + session
    result = {"attempted": [], "errors": []}

    def read(client, operation, key, **kwargs):
        try:
            return pages(client, operation, key, **kwargs)
        except Exception as error:
            if not missing(error):
                result["errors"].append(
                    {
                        "step": "read:" + operation,
                        "type": type(error).__name__,
                        "code": getattr(error, "response", {})
                        .get("Error", {})
                        .get("Code"),
                    }
                )
            return []  # Unknown reads never authorize state deletion below.

    def attempt(label, function, **kwargs):
        try:
            function(**kwargs)
            result["attempted"].append(label)
        except Exception as error:
            if not missing(error):
                result["errors"].append(
                    {
                        "step": label,
                        "type": type(error).__name__,
                        "code": getattr(error, "response", {})
                        .get("Error", {})
                        .get("Code"),
                    }
                )

    eks, ec2 = sdk.client("eks"), sdk.client("ec2")
    groups = read(eks, "list_nodegroups", "nodegroups", clusterName=session)
    for group in groups:
        attempt(
            "nodegroup", eks.delete_nodegroup, clusterName=session, nodegroupName=group
        )
    autoscaling = sdk.client("autoscaling")
    asg_instances = []
    for group in read(autoscaling, "describe_auto_scaling_groups", "AutoScalingGroups"):
        if group["AutoScalingGroupName"].startswith("eks-" + session + "-"):
            asg_instances.extend(i["InstanceId"] for i in group.get("Instances", []))
            attempt(
                "autoscaling_group",
                autoscaling.delete_auto_scaling_group,
                AutoScalingGroupName=group["AutoScalingGroupName"],
                ForceDelete=True,
            )
    # Terminate leaked/stranded nodes too. Do not trust a tagging API snapshot.
    instances = {}
    for tag, value in (
        ("Session", session),
        ("Session", operator),
        ("eks:cluster-name", session),
        ("aws:eks:cluster-name", session),
    ):
        for reservation in read(
            ec2,
            "describe_instances",
            "Reservations",
            Filters=[{"Name": "tag:" + tag, "Values": [value]}],
        ):
            for instance in reservation["Instances"]:
                if instance["State"]["Name"] not in {"terminated", "shutting-down"}:
                    instances[instance["InstanceId"]] = instance
    identifiers = sorted(set(instances) | set(asg_instances))
    if identifiers:
        attempt("terminate", ec2.terminate_instances, InstanceIds=identifiers)
    if not groups:
        attempt("cluster", eks.delete_cluster, name=session)
    for reservation in read(
        ec2,
        "describe_capacity_reservations",
        "CapacityReservations",
        Filters=[{"Name": "tag:Session", "Values": [session]}],
    ):
        if reservation["State"] == "active":
            attempt(
                "reservation",
                ec2.cancel_capacity_reservation,
                CapacityReservationId=reservation["CapacityReservationId"],
            )
    attempt(
        "repository",
        sdk.client("ecr").delete_repository,
        repositoryName=session,
        force=True,
    )
    for scope in (session, operator):
        vpcs = read(
            ec2,
            "describe_vpcs",
            "Vpcs",
            Filters=[{"Name": "tag:Session", "Values": [scope]}],
        )
        for vpc in vpcs:
            filters = [{"Name": "vpc-id", "Values": [vpc["VpcId"]]}]
            for interface in read(
                ec2, "describe_network_interfaces", "NetworkInterfaces", Filters=filters
            ):
                if interface["Status"] == "available":
                    attempt(
                        "interface",
                        ec2.delete_network_interface,
                        NetworkInterfaceId=interface["NetworkInterfaceId"],
                    )
            for group in read(
                ec2, "describe_security_groups", "SecurityGroups", Filters=filters
            ):
                if group["GroupName"] != "default":
                    for direction, permission in (
                        ("ingress", "IpPermissions"),
                        ("egress", "IpPermissionsEgress"),
                    ):
                        if group.get(permission):
                            attempt(
                                "revoke_" + direction,
                                getattr(ec2, "revoke_security_group_" + direction),
                                GroupId=group["GroupId"],
                                IpPermissions=group[permission],
                            )
                    attempt(
                        "security_group",
                        ec2.delete_security_group,
                        GroupId=group["GroupId"],
                    )
            for table in read(
                ec2, "describe_route_tables", "RouteTables", Filters=filters
            ):
                if any(a.get("Main") for a in table.get("Associations", [])):
                    continue
                for association in table.get("Associations", []):
                    attempt(
                        "route_association",
                        ec2.disassociate_route_table,
                        AssociationId=association["RouteTableAssociationId"],
                    )
                attempt(
                    "route_table",
                    ec2.delete_route_table,
                    RouteTableId=table["RouteTableId"],
                )
            for subnet in read(ec2, "describe_subnets", "Subnets", Filters=filters):
                attempt("subnet", ec2.delete_subnet, SubnetId=subnet["SubnetId"])
            for gateway in read(
                ec2,
                "describe_internet_gateways",
                "InternetGateways",
                Filters=[{"Name": "attachment.vpc-id", "Values": [vpc["VpcId"]]}],
            ):
                attempt(
                    "detach_gateway",
                    ec2.detach_internet_gateway,
                    InternetGatewayId=gateway["InternetGatewayId"],
                    VpcId=vpc["VpcId"],
                )
                attempt(
                    "gateway",
                    ec2.delete_internet_gateway,
                    InternetGatewayId=gateway["InternetGatewayId"],
                )
            attempt("vpc", ec2.delete_vpc, VpcId=vpc["VpcId"])
        for address in read(
            ec2,
            "describe_addresses",
            "Addresses",
            Filters=[{"Name": "tag:Session", "Values": [scope]}],
        ):
            attempt(
                "address", ec2.release_address, AllocationId=address["AllocationId"]
            )
        for template in read(
            ec2,
            "describe_launch_templates",
            "LaunchTemplates",
            Filters=[{"Name": "tag:Session", "Values": [scope]}],
        ):
            attempt(
                "launch_template",
                ec2.delete_launch_template,
                LaunchTemplateId=template["LaunchTemplateId"],
            )
    iam = sdk.client("iam")
    for profile in read(iam, "list_instance_profiles", "InstanceProfiles"):
        if profile["InstanceProfileName"].startswith(operator + "-"):
            for role in profile.get("Roles", []):
                attempt(
                    "profile_role",
                    iam.remove_role_from_instance_profile,
                    InstanceProfileName=profile["InstanceProfileName"],
                    RoleName=role["RoleName"],
                )
            attempt(
                "profile",
                iam.delete_instance_profile,
                InstanceProfileName=profile["InstanceProfileName"],
            )
    for role in read(iam, "list_roles", "Roles"):
        name = role["RoleName"]
        if not name.startswith((session + "-", operator + "-")) or name.startswith(
            session + "-cleanup"
        ):
            continue
        for policy in read(
            iam, "list_attached_role_policies", "AttachedPolicies", RoleName=name
        ):
            attempt(
                "detach_policy",
                iam.detach_role_policy,
                RoleName=name,
                PolicyArn=policy["PolicyArn"],
            )
        for policy in read(iam, "list_role_policies", "PolicyNames", RoleName=name):
            attempt(
                "inline_policy",
                iam.delete_role_policy,
                RoleName=name,
                PolicyName=policy,
            )
        attempt("role", iam.delete_role, RoleName=name)
    # State/receipts stay available until compute cleanup has been requested.
    # Normal operator retrieval precedes this deadline; on operator loss there
    # is no successful measurement claim. The scheduled cleanup is fail-safe.
    remaining_instances = []
    for owner in (session, operator):
        remaining_instances.extend(
            i
            for r in read(
                ec2,
                "describe_instances",
                "Reservations",
                Filters=[{"Name": "tag:Session", "Values": [owner]}],
            )
            for i in r["Instances"]
            if i["State"]["Name"] != "terminated"
        )
    clusters = read(eks, "list_clusters", "clusters")
    remaining_vpcs = [
        v
        for owner in (session, operator)
        for v in read(
            ec2,
            "describe_vpcs",
            "Vpcs",
            Filters=[{"Name": "tag:Session", "Values": [owner]}],
        )
    ]
    if (
        not result["errors"]
        and bucket
        and bucket.startswith(session + "-")
        and not remaining_instances
        and session not in clusters
        and not remaining_vpcs
    ):
        s3 = sdk.client("s3")
        try:
            rows = read(s3, "list_object_versions", "Versions", Bucket=bucket)
            markers = read(s3, "list_object_versions", "DeleteMarkers", Bucket=bucket)
            objects = [
                {"Key": r["Key"], "VersionId": r["VersionId"]} for r in rows + markers
            ]
            for offset in range(0, len(objects), 1000):
                response = s3.delete_objects(
                    Bucket=bucket,
                    Delete={"Objects": objects[offset : offset + 1000], "Quiet": True},
                )
                if response.get("Errors"):
                    raise ValueError("descriptive:cleanup_s3_errors")
            attempt("state_bucket", s3.delete_bucket, Bucket=bucket)
        except Exception as error:
            if not missing(error):
                result["errors"].append(
                    {"step": "state_bucket", "type": type(error).__name__}
                )
    attempt(
        "capacity_group",
        sdk.client("resource-groups").delete_group,
        GroupName=session + "-capacity",
    )
    logs = sdk.client("logs")
    for prefix in ("/aws/eks/" + session + "/",):
        for group in read(
            logs, "describe_log_groups", "logGroups", logGroupNamePrefix=prefix
        ):
            attempt("logs", logs.delete_log_group, logGroupName=group["logGroupName"])
    return result


def handler(event, context):
    import boto3

    from botocore.config import Config
    from botocore.session import get_session

    base = get_session()
    base.set_default_client_config(
        Config(
            connect_timeout=3,
            read_timeout=5,
            retries={"mode": "standard", "total_max_attempts": 2},
        )
    )
    sdk = boto3.Session(botocore_session=base, region_name="us-east-1")
    stop = deadline(sdk.client("ssm"), os.environ["PARAMETER"])
    if time.time() < stop:
        return {"armed": True, "deadline_epoch": stop, "cleanup_started": False}
    return clean(sdk, os.environ["SESSION"], os.environ["STATE_BUCKET"])
