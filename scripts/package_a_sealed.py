"""Real locked-provider create/destroy plans, inside --network none only."""

import argparse
import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, "/repo/python/src")
sys.path.insert(0, "/repo/scripts")
from check_m5_offline import synthetic_retained_state  # noqa: E402
from inference_platform.package_a_cloud import save, sha  # noqa: E402


def validate_gate_a_receiver_ingress(change, configuration, transfer_port):
    """Validate narrow sender-only ingress even when Terraform plans its SG ID as unknown."""
    after = change.get("after") or {}
    unknown = change.get("after_unknown") or {}
    ingress = after.get("ingress")
    unknown_ingress = unknown.get("ingress")
    references = set(
        configuration.get("expressions", {}).get("ingress", {}).get("references", [])
    )
    expected_references = {
        "var.transfer_port",
        "aws_security_group.hosts.id",
        "aws_security_group.hosts",
    }
    if not isinstance(ingress, list) or len(ingress) != 1:
        raise ValueError("unexpected_gate_a_receiver_ingress")
    rule = ingress[0]
    expected_unknown = [
        {
            "cidr_blocks": [],
            "ipv6_cidr_blocks": [],
            "prefix_list_ids": [],
            "security_groups": True,
        }
    ]
    if (
        rule.get("from_port") != transfer_port
        or rule.get("to_port") != transfer_port
        or rule.get("protocol") != "tcp"
        or rule.get("cidr_blocks") != []
        or rule.get("ipv6_cidr_blocks") != []
        or rule.get("prefix_list_ids") != []
        or rule.get("self") is not False
        or unknown_ingress != expected_unknown
        or references != expected_references
    ):
        raise ValueError("unexpected_gate_a_receiver_ingress")


def validate_gate_a_interface_endpoints(rows, configuration):
    expected = {
        "com.amazonaws.us-east-1.ssm",
        "com.amazonaws.us-east-1.ssmmessages",
        "com.amazonaws.us-east-1.ec2messages",
    }
    interfaces = [
        row
        for row in rows
        if row["type"] == "aws_vpc_endpoint"
        and (row["change"].get("after") or {}).get("vpc_endpoint_type") == "Interface"
    ]
    observed = [
        (row["change"].get("after") or {}).get("service_name") for row in interfaces
    ]
    endpoint_configuration = [
        resource
        for resource in configuration.get("root_module", {}).get("resources", [])
        if resource.get("address") == "aws_vpc_endpoint.ssm"
    ]
    subnet_references = (
        endpoint_configuration[0]
        .get("expressions", {})
        .get("subnet_ids", {})
        .get("references", [])
        if len(endpoint_configuration) == 1
        else []
    )
    expected_subnet_references = {"aws_subnet.gate_a.id", "aws_subnet.gate_a"}
    subnet_values_match = all(
        (
            (row["change"].get("after_unknown") or {}).get("subnet_ids") is True
            and "subnet_ids" not in (row["change"].get("after") or {})
        )
        or (
            len((row["change"].get("after") or {}).get("subnet_ids", [])) == 1
            and (row["change"].get("after_unknown") or {}).get("subnet_ids") is not True
        )
        for row in interfaces
    )
    if (
        len(interfaces) != 3
        or set(observed) != expected
        or len(observed) != len(set(observed))
        or set(subnet_references) != expected_subnet_references
        or len(subnet_references) != len(expected_subnet_references)
        or not subnet_values_match
    ):
        raise ValueError("unexpected_gate_a_interface_endpoints")


def validate_gate_a_instance_dependencies(configuration):
    expected = {
        "aws_iam_role_policy_attachment.ssm",
        "aws_vpc_endpoint.ssm",
        "aws_vpc_endpoint.s3",
        "aws_route_table_association.gate_a",
    }
    resources = configuration.get("root_module", {}).get("resources", [])
    instances = {
        resource.get("address"): resource
        for resource in resources
        if resource.get("type") == "aws_instance"
    }
    if set(instances) != {"aws_instance.sender", "aws_instance.receiver"} or any(
        not expected.issubset(set(resource.get("depends_on", [])))
        for resource in instances.values()
    ):
        raise ValueError("unexpected_gate_a_instance_dependencies")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=Path("/packet"))
    parser.add_argument(
        "--module", type=Path, default=Path("/repo/infra/terraform/package_a")
    )
    parser.add_argument("--expected-managed", type=int, default=10)
    parser.add_argument("--gate-a", action="store_true")
    args = parser.parse_args()
    packet = args.directory
    # Execute the provider on native Linux storage. Mmapping its executable
    # through a Windows bind mount can SIGBUS despite a correct archive pin.
    root = Path("/tmp/dec077-terraform")
    root.mkdir(exist_ok=False)
    exported = packet / "terraform"
    exported.mkdir(exist_ok=True)
    for source in args.module.iterdir():
        if source.is_file():
            shutil.copy2(source, root / source.name)
            shutil.copy2(source, exported / source.name)
    archive = Path("/terraform.zip")
    if (
        sha(archive)
        != "0d17011f0c4664539b164b044903d04e296c86c13cb9f28040076c65cfb3985a"
    ):
        raise ValueError("terraform_archive_pin")
    with zipfile.ZipFile(archive) as stream:
        stream.extract("terraform", "/tmp/dec077-bin")
    exe = Path("/tmp/dec077-bin/terraform")
    exe.chmod(0o755)
    Path("/tmp/dec077.rc").write_text(
        'provider_installation { filesystem_mirror { path = "/mirror" } }\n'
    )
    env = {
        **os.environ,
        "TF_CLI_CONFIG_FILE": "/tmp/dec077.rc",
        "AWS_ACCESS_KEY_ID": "fixture",
        "AWS_SECRET_ACCESS_KEY": "fixture",
        "AWS_EC2_METADATA_DISABLED": "true",
    }

    def tf(*argv, name):
        result = subprocess.run(
            [str(exe), f"-chdir={root}", *argv],
            env=env,
            capture_output=True,
            timeout=180,
        )
        (packet / (name + ".stdout")).write_bytes(result.stdout)
        (packet / (name + ".stderr")).write_bytes(result.stderr)
        result.check_returncode()
        return result.stdout

    tf("init", "-backend=false", "-input=false", "-lockfile=readonly", name="init")
    variables = json.loads((packet / "input.tfvars.json").read_bytes())
    save(root / "input.tfvars.json", variables)
    save(exported / "input.tfvars.json", variables)
    tf("validate", name="validate")
    tf(
        "plan",
        "-input=false",
        "-refresh=false",
        "-var-file=input.tfvars.json",
        "-out=create.tfplan",
        name="create",
    )
    plan = json.loads(tf("show", "-json", "create.tfplan", name="create-show"))
    rows = [x for x in plan["resource_changes"] if x["mode"] == "managed"]
    if len(rows) != args.expected_managed or any(
        x["change"]["actions"] != ["create"] for x in rows
    ):
        raise ValueError("unexpected_create_graph")
    if not args.gate_a:
        instance = next(
            x["change"]["after"] for x in rows if x["type"] == "aws_instance"
        )
        if instance["instance_type"] != variables["instance_type"] or instance.get(
            "instance_market_options"
        ):
            raise ValueError("unexpected_or_spot_host")
    if args.gate_a:
        validate_gate_a_interface_endpoints(rows, plan["configuration"])
        validate_gate_a_instance_dependencies(plan["configuration"])
        instances = [x["change"]["after"] for x in rows if x["type"] == "aws_instance"]
        if (
            len(instances) != 2
            or any(x["instance_type"] != "c6i.2xlarge" for x in instances)
            or any(x["associate_public_ip_address"] for x in instances)
            or not {x["type"] for x in rows}.issuperset(
                {
                    "aws_instance",
                    "aws_ebs_volume",
                    "aws_volume_attachment",
                    "aws_s3_bucket",
                }
            )
        ):
            raise ValueError("unexpected_gate_a_graph")
        receiver = next(
            x["change"] for x in rows if x["address"] == "aws_security_group.receiver"
        )
        receiver_configuration = next(
            resource
            for resource in plan["configuration"]["root_module"]["resources"]
            if resource.get("address") == "aws_security_group.receiver"
        )
        validate_gate_a_receiver_ingress(
            receiver, receiver_configuration, variables["transfer_port"]
        )
        recovery = next(
            x["change"]["after"] for x in rows if x["type"] == "aws_ebs_volume"
        )
        if not recovery["encrypted"] or recovery["type"] != "gp3":
            raise ValueError("unexpected_gate_a_recovery_volume")
    schema = json.loads(tf("providers", "schema", "-json", name="schema"))[
        "provider_schemas"
    ]["registry.terraform.io/hashicorp/aws"]["resource_schemas"]
    state = synthetic_retained_state(plan, schema)
    save(root / "synthetic.tfstate", state)
    tf(
        "plan",
        "-destroy",
        "-input=false",
        "-refresh=false",
        "-state=synthetic.tfstate",
        "-var-file=input.tfvars.json",
        "-out=destroy.tfplan",
        name="destroy",
    )
    destroy = json.loads(tf("show", "-json", "destroy.tfplan", name="destroy-show"))
    deleted = [x for x in destroy["resource_changes"] if x["mode"] == "managed"]
    if len(deleted) != args.expected_managed or any(
        x["change"]["actions"] != ["delete"] for x in deleted
    ):
        raise ValueError("unexpected_destroy_graph")
    for name in ("create.tfplan", "destroy.tfplan", "synthetic.tfstate"):
        shutil.copy2(root / name, exported / name)
    save(
        packet / "sealed-plans.json",
        {
            "schema": "dec077-sealed-plans-v1",
            "network": "none",
            "provider": "6.64.0",
            "terraform": "1.16.2",
            "create_sha256": sha(root / "create.tfplan"),
            "destroy_sha256": sha(root / "destroy.tfplan"),
            "create_json_sha256": sha(packet / "create-show.stdout"),
            "destroy_json_sha256": sha(packet / "destroy-show.stdout"),
            "create_actions": {x["address"]: x["change"]["actions"] for x in rows},
            "destroy_actions": {x["address"]: x["change"]["actions"] for x in deleted},
            "destroy_basis": "synthetic state; never a real teardown receipt",
            "variables": variables,
        },
    )
    print((packet / "sealed-plans.json").read_text())


if __name__ == "__main__":
    main()
