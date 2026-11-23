"""Simulate the traced provider and operator calls in their AWS resource contexts."""

import copy
import json
import os
import tempfile
from pathlib import Path

import inf060_probe_spec as spec

ACTION_RECORD = "deploy/inf060/operator-actions.json"
SSM_CORE = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
EC2_CREATED = {
    "CreateVpc": "vpc",
    "CreateInternetGateway": "internet-gateway",
    "CreateSubnet": "subnet",
    "CreateSecurityGroup": "security-group",
    "CreateRouteTable": "route-table",
}
EC2_OWNED = {
    "ModifyVpcAttribute": ("vpc",),
    "DeleteVpc": ("vpc",),
    "DeleteInternetGateway": ("internet-gateway",),
    "DeleteSubnet": ("subnet",),
    "ModifySubnetAttribute": ("subnet",),
    "DeleteRouteTable": ("route-table",),
    "DeleteSecurityGroup": ("security-group",),
    "AuthorizeSecurityGroupEgress": ("security-group",),
    "RevokeSecurityGroupEgress": ("security-group",),
    "RevokeSecurityGroupIngress": ("security-group",),
    "AttachInternetGateway": ("vpc", "internet-gateway"),
    "DetachInternetGateway": ("vpc", "internet-gateway"),
    "AssociateRouteTable": ("subnet", "route-table"),
    "DisassociateRouteTable": ("subnet", "route-table"),
    "CreateRoute": ("route-table",),
    "DeleteRoute": ("route-table",),
    "ModifyInstanceAttribute": ("instance",),
    "TerminateInstances": ("instance",),
}
ROLE_ACTIONS = {
    "CreateRole",
    "TagRole",
    "AttachRolePolicy",
    "DetachRolePolicy",
    "DeleteRole",
    "GetRole",
    "ListRolePolicies",
    "ListAttachedRolePolicies",
    "ListInstanceProfilesForRole",
    "ListRoleTags",
    "PassRole",
}
PROFILE_ACTIONS = {
    "CreateInstanceProfile",
    "TagInstanceProfile",
    "GetInstanceProfile",
    "AddRoleToInstanceProfile",
    "RemoveRoleFromInstanceProfile",
    "DeleteInstanceProfile",
    "ListInstanceProfileTags",
}


def action_names(record):
    known = {
        "ec2.amazonaws.com": "ec2",
        "iam.amazonaws.com": "iam",
        "sts.amazonaws.com": "sts",
        "ssm.amazonaws.com": "ssm",
        "servicequotas.amazonaws.com": "servicequotas",
        "pricing.amazonaws.com": "pricing",
    }
    names = {
        known[row["event_source"]] + ":" + row["event_name"]
        for row in record["provider"]["events"]
    }
    return sorted(
        names | set(record["operator_cli"]) | set(record["authorization_dependencies"])
    )


def action_cases(action, account, session, ami):
    service, name = action.split(":")
    region = spec.REGION
    ec2 = f"arn:aws:ec2:{region}:{account}:"
    ssm = f"arn:aws:ssm:{region}:"
    iam = f"arn:aws:iam::{account}:"
    owned = {"ec2:ResourceTag/Session": session}
    requested = {"aws:RequestTag/Session": session}

    # Representative ARNs have the same type, region, account and scope as the
    # real calls. No active resource IDs are needed to simulate an identity policy.
    def ec2_case(label, kind, context):
        return label, ec2 + kind + "/resource-under-review", context

    if service == "ec2":
        if name in EC2_CREATED:
            cases = [ec2_case("created", EC2_CREATED[name], requested)]
            if name in {"CreateSubnet", "CreateRouteTable", "CreateSecurityGroup"}:
                cases.append(ec2_case("parent_vpc", "vpc", owned))
            return cases
        if name in EC2_OWNED:
            return [ec2_case(kind, kind, owned) for kind in EC2_OWNED[name]]
        if name == "CreateTags":
            subjects = [
                *EC2_CREATED.items(),
                ("RunInstances", "instance"),
                ("RunInstances", "volume"),
            ]
            return [
                ec2_case(
                    origin + "/" + kind, kind, {**requested, "ec2:CreateAction": origin}
                )
                for origin, kind in subjects
            ]
        if name == "RunInstances":
            return [
                ("ami", f"arn:aws:ec2:{region}::image/{ami}", {}),
                ec2_case(
                    "instance",
                    "instance",
                    {
                        **requested,
                        "ec2:InstanceType": spec.SHAPE,
                        "ec2:AvailabilityZone": spec.ZONE,
                        "ec2:MetadataHttpTokens": "required",
                    },
                ),
                ec2_case(
                    "volume",
                    "volume",
                    {**requested, "ec2:VolumeType": "gp3", "ec2:Encrypted": True},
                ),
                ec2_case(
                    "network_interface", "network-interface", {"ec2:Region": region}
                ),
                ec2_case("subnet", "subnet", owned),
                ec2_case("security_group", "security-group", owned),
            ]
        if name == "DescribeInstanceAttribute":
            return [ec2_case("instance", "instance", owned)]
        if name.startswith("Describe"):
            return [("regional_read", "*", {})]
    if service == "iam":
        context = {}
        if name in {
            "CreateRole",
            "CreateInstanceProfile",
            "TagRole",
            "TagInstanceProfile",
        }:
            context = requested
        elif name in {"AttachRolePolicy", "DetachRolePolicy"}:
            context = {"iam:PolicyARN": SSM_CORE}
        elif name == "PassRole":
            context = {"iam:PassedToService": "ec2.amazonaws.com"}
        if name in ROLE_ACTIONS:
            return [("role", iam + "role/" + session + "-gpu", context)]
        if name in PROFILE_ACTIONS:
            return [("profile", iam + "instance-profile/" + session + "-gpu", context)]
        if name in {"ListRoles", "ListInstanceProfiles"}:
            return [("account_read", "*", {})]
    if action in {"ssm:SendCommand", "ssm:StartSession"}:
        document = {
            "ssm:SendCommand": "AWS-RunShellScript",
            "ssm:StartSession": "AWS-StartPortForwardingSession",
        }[action]
        return [
            ec2_case(
                "target_instance", "instance", {"ssm:resourceTag/Inf060Target": session}
            ),
            ("aws_document", ssm + ":document/" + document, {}),
        ]
    if action == "ssm:TerminateSession":
        return [
            (
                "sender_session",
                ssm + account + ":session/inf060-owner-probe",
                {"aws:userid": "inf060-owner"},
            )
        ]
    if action in {
        "ssm:DescribeInstanceInformation",
        "ssm:GetCommandInvocation",
        "sts:GetCallerIdentity",
        "pricing:GetProducts",
        "servicequotas:GetServiceQuota",
    }:
        return [("service_read", "*", {})]
    raise ValueError("inf060:unmodeled_action:" + action)


def context_entries(values):
    return [
        {
            "ContextKeyName": key,
            "ContextKeyValues": [
                str(value).lower() if isinstance(value, bool) else value
            ],
            "ContextKeyType": "boolean" if isinstance(value, bool) else "string",
        }
        for key, value in sorted(values.items())
    ]


def simulate(invoke, policy, actions, account, session, ami, *, role=None):
    expected = [
        (action, *case)
        for action in actions
        for case in action_cases(action, account, session, ami)
    ]
    groups = {}
    for name, label, resource, context in expected:
        key = (resource, json.dumps(context, sort_keys=True))
        groups.setdefault(key, []).append((name, label, context))
    results = []
    with tempfile.TemporaryDirectory(
        prefix="inf060-iam-", dir=os.environ.get("TMPDIR")
    ) as directory:
        request_file = Path(directory) / "request.json"
        for (resource, _), rows in groups.items():
            context = rows[0][2]
            request = {
                "ActionNames": sorted({name for name, _, _ in rows}),
                "ResourceArns": [resource],
                "ContextEntries": context_entries(context),
            }
            if role:
                request["PolicySourceArn"] = role
            else:
                request["PolicyInputList"] = [json.dumps(policy, separators=(",", ":"))]
            spec.save(request_file, request)
            response = invoke(
                "iam",
                "simulate-principal-policy" if role else "simulate-custom-policy",
                ["--cli-input-json", "file://" + request_file.as_posix()],
            )
            evaluated = response["EvaluationResults"]
            by_name = {row["EvalActionName"]: row for row in evaluated}
            spec.check(
                not response.get("IsTruncated")
                and len(evaluated) == len(by_name)
                and by_name.keys() == set(request["ActionNames"]),
                "simulation_coverage",
            )
            for name, label, _ in rows:
                outcome = by_name[name]
                results.append(
                    {
                        "action": name,
                        "resource": label,
                        "context": sorted(context),
                        "decision": outcome["EvalDecision"],
                        "missing_context": outcome.get("MissingContextValues", []),
                    }
                )
    return sorted(results, key=lambda row: (row["action"], row["resource"]))


def require_allowed(rows):
    denied = [
        row["action"] + "/" + row["resource"] + "=" + row["decision"]
        for row in rows
        if row["decision"] != "allowed"
    ]
    spec.check(
        bool(rows) and not denied, "policy_simulation_denied:" + ",".join(denied)
    )


def seal(invoke, policy_file, record_path, account, session, ami):
    policy = spec.load(policy_file)
    names = action_names(spec.load(record_path))
    rows = simulate(invoke, policy, names, account, session, ami)
    require_allowed(rows)
    removed = "ec2:ModifyInstanceAttribute"
    mutant = copy.deepcopy(policy)
    for statement in mutant["Statement"]:
        statement["Action"] = [name for name in statement["Action"] if name != removed]
    mutant["Statement"] = [
        statement for statement in mutant["Statement"] if statement["Action"]
    ]
    violation = simulate(invoke, mutant, [removed], account, session, ami)
    try:
        require_allowed(violation)
    except ValueError as exc:
        spec.check(
            all(row["decision"] == "implicitDeny" for row in violation),
            "policy_mutation_wrong_denial",
        )
        mutation = {
            "removed": removed,
            "decision": "implicitDeny",
            "gate_refusal": str(exc),
        }
    else:
        raise ValueError("inf060:policy_mutation_not_refused")
    return {
        "policy_sha256": spec.facts(policy_file)["sha256"],
        "actions_sha256": spec.facts(record_path)["sha256"],
        "action_count": len(names),
        "results": rows,
        "mutation": mutation,
    }
