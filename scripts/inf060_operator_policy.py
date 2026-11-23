"""Produce the inline role policy for one INF-060 GPU session."""

import re


def operator_policy(account, session, ami, region="us-east-1"):
    if not (
        re.fullmatch(r"[0-9]{12}", account)
        and re.fullmatch(r"dec077-inf060-[a-z0-9-]{1,15}", session)
        and re.fullmatch(r"ami-[a-f0-9]{17}", ami)
        and region == "us-east-1"
    ):
        raise ValueError("inf060:policy_scope")
    ec2 = f"arn:aws:ec2:{region}:{account}:"
    iam = f"arn:aws:iam::{account}:"
    ssm = f"arn:aws:ssm:{region}:"
    role = iam + "role/" + session + "-gpu"
    profile = iam + "instance-profile/" + session + "-gpu"
    statements = []

    def allow(actions, resources, **equals):
        entry = {"Effect": "Allow", "Action": actions.split(), "Resource": resources}
        if equals:
            entry["Condition"] = {"StringEquals": equals}
        statements.append(entry)

    request = {"aws:RequestTag/Session": session}
    owned = {"ec2:ResourceTag/Session": session}
    creates = {
        "CreateVpc": "vpc",
        "CreateInternetGateway": "internet-gateway",
        "CreateSubnet": "subnet",
        "CreateSecurityGroup": "security-group",
        "CreateRouteTable": "route-table",
    }
    for action, resource in creates.items():
        allow("ec2:" + action, ec2 + resource + "/*", **request)
    allow(
        "ec2:CreateSubnet ec2:CreateRouteTable ec2:CreateSecurityGroup",
        ec2 + "vpc/*",
        **owned,
    )
    allow(
        "ec2:CreateTags",
        [ec2 + t + "/*" for t in (*creates.values(), "instance", "volume")],
        **{"ec2:CreateAction": [*creates, "RunInstances"], **request},
    )
    for actions, types in [
        ("DeleteVpc ModifyVpcAttribute", ["vpc"]),
        ("DeleteSubnet ModifySubnetAttribute", ["subnet"]),
        ("DeleteInternetGateway", ["internet-gateway"]),
        ("AttachInternetGateway DetachInternetGateway", ["vpc", "internet-gateway"]),
        ("AssociateRouteTable DisassociateRouteTable", ["subnet", "route-table"]),
        ("CreateRoute DeleteRoute DeleteRouteTable", ["route-table"]),
        (
            "DeleteSecurityGroup AuthorizeSecurityGroupEgress RevokeSecurityGroupEgress RevokeSecurityGroupIngress",
            ["security-group"],
        ),
        ("TerminateInstances ModifyInstanceAttribute", ["instance"]),
    ]:
        allow(
            " ".join("ec2:" + a for a in actions.split()),
            [ec2 + t + "/*" for t in types],
            **owned,
        )
    allow(
        "ec2:RunInstances",
        ec2 + "instance/*",
        **{
            **request,
            "ec2:InstanceType": "g6.xlarge",
            "ec2:MetadataHttpTokens": "required",
            "ec2:AvailabilityZone": region + "a",
        },
    )
    allow(
        "ec2:RunInstances",
        ec2 + "volume/*",
        **{**request, "ec2:VolumeType": "gp3"},
    )
    statements[-1]["Condition"]["Bool"] = {"ec2:Encrypted": "true"}
    allow("ec2:RunInstances", [ec2 + "subnet/*", ec2 + "security-group/*"], **owned)
    # EC2 creates the primary ENI as part of RunInstances. Require the owned
    # subnet and SG independently in the same multi-resource authorization.
    allow("ec2:RunInstances", ec2 + "network-interface/*", **{"ec2:Region": region})
    allow("ec2:RunInstances", f"arn:aws:ec2:{region}::image/{ami}")

    allow("iam:CreateRole iam:TagRole", role, **request)
    allow(
        "iam:GetRole iam:DeleteRole iam:ListRolePolicies iam:ListAttachedRolePolicies iam:ListInstanceProfilesForRole",
        role,
    )
    allow(
        "iam:AttachRolePolicy iam:DetachRolePolicy",
        role,
        **{"iam:PolicyARN": "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"},
    )
    allow("iam:CreateInstanceProfile iam:TagInstanceProfile", profile, **request)
    allow(
        "iam:GetInstanceProfile iam:DeleteInstanceProfile iam:AddRoleToInstanceProfile iam:RemoveRoleFromInstanceProfile",
        profile,
    )
    allow("iam:PassRole", role, **{"iam:PassedToService": "ec2.amazonaws.com"})
    allow(
        "ssm:SendCommand ssm:StartSession",
        ec2 + "instance/*",
        **{"ssm:resourceTag/Inf060Target": session},
    )
    allow("ssm:SendCommand", ssm + ":document/AWS-RunShellScript")
    allow("ssm:StartSession", ssm + ":document/AWS-StartPortForwardingSession")
    allow("ssm:TerminateSession", ssm + account + ":session/${aws:userid}-*")
    allow(
        "ec2:DescribeInstances ec2:DescribeInstanceAttribute ec2:DescribeInstanceCreditSpecifications "
        "ec2:DescribeInstanceTypes ec2:DescribeInstanceTypeOfferings ec2:DescribeImages ec2:DescribeAvailabilityZones "
        "ec2:DescribeVpcs ec2:DescribeVpcAttribute ec2:DescribeNetworkAcls ec2:DescribeSubnets ec2:DescribeRouteTables "
        "ec2:DescribeSecurityGroups ec2:DescribeSecurityGroupRules ec2:DescribeInternetGateways "
        "ec2:DescribeNetworkInterfaces ec2:DescribeAddresses ec2:DescribeVolumes "
        "ec2:DescribeInstanceStatus ec2:DescribeTags ec2:DescribeIamInstanceProfileAssociations "
        "ssm:DescribeInstanceInformation ssm:GetCommandInvocation iam:ListRoles iam:ListInstanceProfiles "
        "pricing:GetProducts servicequotas:GetServiceQuota sts:GetCallerIdentity",
        "*",
    )
    return {"Version": "2012-10-17", "Statement": statements}
