"""One saved, review-only R1 Terraform plan. Never consumes or applies a plan."""

import argparse
import datetime
import hashlib
import json
import subprocess
import sys
import zipfile
from decimal import Decimal
from pathlib import Path
from unittest.mock import patch

from inference_platform.r1_lifecycle import (
    M4_PHASE_CAP_USD,
    R1_SESSION_CAP_USD,
    Production,
    validate_inputs_commands,
)
from inference_platform.r1_bundle import validate_reviewed_bundle


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write(path, value):
    path.write_bytes((json.dumps(value, indent=2) + "\n").encode("utf-8"))


def validate_resource_changes(document):
    """Reject output-only and wrong-topology plans before reading other fields."""
    if not isinstance(document, dict):
        raise ValueError("plan JSON is not an object")
    changes = document.get("resource_changes")
    if not isinstance(changes, list):
        raise ValueError(
            "plan JSON has no resource_changes array; Terraform returned an "
            "output-only plan, not a reviewable R1 resource plan"
        )
    if len(changes) != 13:
        raise ValueError(f"expected exactly 13 resource changes, found {len(changes)}")

    action_counts = {"create": 0, "update": 0, "delete": 0}
    for change in changes:
        actions = change.get("change", {}).get("actions")
        if not isinstance(actions, list):
            raise ValueError("resource change is missing its actions list")
        for action in action_counts:
            action_counts[action] += int(action in actions)
    if action_counts != {"create": 13, "update": 0, "delete": 0}:
        raise ValueError(
            "expected 13 creates, 0 updates and 0 deletes; found "
            f"{action_counts['create']} creates, {action_counts['update']} updates "
            f"and {action_counts['delete']} deletes"
        )
    if any(change.get("change", {}).get("actions") != ["create"] for change in changes):
        raise ValueError("all 13 resource changes must be create-only actions")

    instance_types = []
    for resource in changes:
        if resource.get("type") == "aws_instance":
            after = resource.get("change", {}).get("after")
            instance_types.append(after.get("instance_type") if after else None)
    gpu_count = instance_types.count("g6.xlarge")
    cpu_count = instance_types.count("c6i.2xlarge")
    if len(instance_types) != 4 or gpu_count != 2 or cpu_count != 2:
        raise ValueError(
            "expected exactly 2 g6.xlarge GPU and 2 c6i.2xlarge CPU instances; "
            f"found {gpu_count} GPU, {cpu_count} CPU, and {len(instance_types)} total instances"
        )
    return changes


def offline_aws(identity, service, operation, *args):
    """Return explicit empty inventory for the structural-preflight callbacks."""
    if service == "sts" and operation == "get-caller-identity":
        return identity
    if service == "ec2":
        response_keys = {
            "describe-instances": "Reservations",
            "describe-volumes": "Volumes",
            "describe-addresses": "Addresses",
            "describe-network-interfaces": "NetworkInterfaces",
            "describe-security-groups": "SecurityGroups",
            "describe-subnets": "Subnets",
            "describe-route-tables": "RouteTables",
            "describe-internet-gateways": "InternetGateways",
            "describe-vpcs": "Vpcs",
            "describe-capacity-reservations": "CapacityReservations",
        }
        if operation in response_keys:
            key = response_keys[operation]
            return {key: []}
    if service == "iam" and operation == "list-roles":
        return {"Roles": []}
    if service == "iam" and operation == "list-instance-profiles":
        return {"InstanceProfiles": []}
    raise ValueError(f"unexpected offline AWS operation: {service} {operation}")


def build_plan_summary(
    document,
    inputs,
    *,
    prepared_at,
    preparation_commit,
    plan_sha256,
    saved_plan_path,
    plan_bytes,
    user_data_source_sha256,
    embedded_committed_config_sha256,
    terraform_sha256,
    production_structural_preflight,
    raw,
):
    """Validate planned R1 resources and return the curated packet summary."""
    changes = validate_resource_changes(document)
    configured_resources = (
        document.get("configuration", {}).get("root_module", {}).get("resources")
    )
    if not isinstance(configured_resources, list):
        raise ValueError("plan JSON is missing configured root resources")
    cpu_configuration = next(
        (
            resource
            for resource in configured_resources
            if resource.get("address") == "aws_instance.cpu"
        ),
        None,
    )
    if cpu_configuration is None:
        raise ValueError("plan JSON is missing configured aws_instance.cpu")
    cpu_dependencies = cpu_configuration.get("depends_on", [])
    if "aws_instance.gpu" not in cpu_dependencies:
        raise ValueError("CPU instances must depend on GPU instances")

    instances = {
        change["change"]["after"]["tags"]["Role"]: change["change"]["after"]
        for change in changes
        if change["type"] == "aws_instance"
    }
    if set(instances) != set(inputs["roles"]):
        raise ValueError("plan host roles differ from exact R1 inputs")
    for role, value in instances.items():
        gpu = role.startswith("gpu")
        if value["instance_type"] != inputs["gpu_type" if gpu else "cpu_type"]:
            raise ValueError(f"planned instance type differs for {role}")
        if value["ami"] != inputs["gpu_ami" if gpu else "cpu_ami"]:
            raise ValueError(f"planned AMI differs for {role}")
        if value["root_block_device"][0]["volume_size"] != (200 if gpu else 40):
            raise ValueError(f"planned root volume size differs for {role}")
        if value["metadata_options"][0]["http_tokens"] != "required":
            raise ValueError(f"planned metadata tokens are not required for {role}")
        if value["instance_initiated_shutdown_behavior"] != "terminate":
            raise ValueError(f"planned shutdown behavior differs for {role}")
        if gpu:
            reservation = value.get("capacity_reservation_specification") or []
            if (
                len(reservation) != 1
                or reservation[0].get("capacity_reservation_preference")
                != "capacity-reservations-only"
                or value.get("tenancy") != "default"
            ):
                raise ValueError(
                    f"GPU role {role} must require capacity-reservations-only and default tenancy"
                )

    user_data_hashes = {
        role: sha(str(value["user_data"]).encode("utf-8"))
        for role, value in instances.items()
        if value.get("user_data") is not None
    }
    if set(user_data_hashes) != set(inputs["roles"]):
        raise ValueError("planned user data is missing for one or more hosts")
    if len(set(user_data_hashes.values())) != 1:
        raise ValueError("planned user data differs across hosts")
    if (
        user_data_source_sha256
        != inputs["source_sha256"]["infra/terraform/r1/user-data.sh"]
    ):
        raise ValueError("user-data source hash differs from bound R1 inputs")
    if set(user_data_hashes.values()) != {user_data_source_sha256}:
        raise ValueError("planned user data differs from its committed source")

    subnet = next(
        (
            change["change"]["after"]
            for change in changes
            if change["type"] == "aws_subnet"
        ),
        None,
    )
    if subnet is None or subnet["availability_zone"] != inputs["availability_zone"]:
        raise ValueError(
            "planned subnet availability zone differs from exact R1 inputs"
        )

    hosts = {}
    for role, value in instances.items():
        host = {
            key: value[key]
            for key in (
                "instance_type",
                "ami",
                "root_block_device",
                "metadata_options",
                "instance_initiated_shutdown_behavior",
                "tags",
            )
        }
        if role.startswith("gpu"):
            host["capacity_reservation_specification"] = value[
                "capacity_reservation_specification"
            ]
            host["tenancy"] = value["tenancy"]
        else:
            host["capacity_reservation_specification"] = "not set (On-Demand default)"
            host["tenancy"] = "not set (On-Demand default)"
        hosts[role] = host

    return {
        "schema": "r1-saved-plan-review.v1",
        "prepared_at": prepared_at,
        "preparation_commit": preparation_commit,
        "source_head": inputs["source_head"],
        "plan_sha256": plan_sha256,
        "saved_plan_path": saved_plan_path,
        "plan_bytes": plan_bytes,
        "plan_exit": 0,
        "plan_count": 1,
        "plan_apply_count": 0,
        "actions": {"create": 13, "change": 0, "destroy": 0},
        "variables": document["variables"],
        "cpu_depends_on": cpu_dependencies,
        "planned_user_data_sha256_by_role": user_data_hashes,
        "planned_user_data_matches_source_sha256": True,
        "user_data_source_sha256": user_data_source_sha256,
        "hosts": hosts,
        "embedded_committed_config_sha256": embedded_committed_config_sha256,
        "source_hashes_match_git": True,
        "source_files_bound": len(inputs["source_sha256"]),
        "bundle_sha256": inputs["bundle_sha256"],
        "m4_cap_usd": str(M4_PHASE_CAP_USD),
        "session_ceiling_usd": str(R1_SESSION_CAP_USD),
        "m4_estimate_usd": str(inputs["m4_estimate_usd"]),
        "session_estimate_usd": str(inputs["session_estimate_usd"]),
        "production_structural_preflight": production_structural_preflight,
        "terraform_sha256": terraform_sha256,
        "state": "No state",
        "approval": "absent; exact-plan Claude review required",
        "raw": raw,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--refresh", type=Path, required=True)
    parser.add_argument(
        "--inputs", type=Path, default=Path("docs/R1_SESSION_INPUTS.json")
    )
    args = parser.parse_args()
    root = Path.cwd()
    inputs_path = (root / args.inputs).resolve()
    inputs = json.loads(inputs_path.read_bytes())
    validate_inputs_commands(root, inputs_path, inputs)
    validate_reviewed_bundle(root, inputs)
    current_head = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], text=True
    ).strip()
    if inputs.get("source_head") != current_head:
        raise ValueError(
            "R1 source_head must match the committed plan-preparation HEAD"
        )
    refresh_summary = json.loads((args.refresh / "summary.json").read_bytes())
    for key in (
        "session_estimate_usd",
        "session_cap_usd",
        "m4_estimate_usd",
        "m4_cap_usd",
    ):
        if str(refresh_summary[key]) != str(inputs[key]):
            raise ValueError(f"session inputs differ from read-only refresh: {key}")
    if refresh_summary["account_id_sha256"] != inputs["account_id_sha256"]:
        raise ValueError(
            "session inputs and read-only refresh are from different accounts"
        )
    if Decimal(str(inputs["m4_cap_usd"])) != M4_PHASE_CAP_USD:
        raise ValueError("session inputs do not record the DEC-058 M4 cap")
    if Decimal(str(inputs["session_cap_usd"])) != R1_SESSION_CAP_USD:
        raise ValueError("session inputs do not record the DEC-058 R1 cap")
    if Decimal(str(inputs["m4_estimate_usd"])) > M4_PHASE_CAP_USD:
        raise ValueError("refreshed M4 estimate exceeds DEC-058 cap")
    if Decimal(str(inputs["session_estimate_usd"])) > R1_SESSION_CAP_USD:
        raise ValueError("refreshed R1 estimate exceeds DEC-058 cap")
    for path, digest in inputs["source_sha256"].items():
        assert (
            sha(subprocess.check_output(["git", "show", "HEAD:" + path])) == digest
        ), path
        # Terraform embeds working-tree configuration. Refuse line-ending drift.
        if path.startswith("infra/terraform/r1/"):
            assert sha((root / path).read_bytes()) == digest, path
    tf = (root / inputs["terraform"]).resolve()
    plan = (root / inputs["saved_plan_path"]).resolve()
    folder = plan.parent
    if plan.exists():
        raise ValueError(
            "saved plan already exists; review helper never overwrites/replans"
        )
    variables = folder / "variables.tfvars.json"
    argv = [
        str(tf),
        "-chdir=" + str(root / "infra/terraform/r1"),
        "plan",
        "-input=false",
        "-no-color",
        "-out=" + str(plan),
        "-var-file=" + str(variables),
    ]
    write(folder / "plan.argv.json", argv)
    with (
        (folder / "plan.stdout").open("wb") as out,
        (folder / "plan.stderr").open("wb") as err,
    ):
        result = subprocess.run(argv, stdout=out, stderr=err, timeout=300)
    if result.returncode:
        raise RuntimeError("review-only plan failed; private stdout/stderr retained")
    raw = subprocess.check_output(
        [
            str(tf),
            "-chdir=" + str(root / "infra/terraform/r1"),
            "show",
            "-json",
            str(plan),
        ]
    )
    (folder / "plan.json").write_bytes(raw)
    document = json.loads(raw)
    try:
        validate_resource_changes(document)
    except ValueError as exc:
        print(f"Refusing exact-plan packet: {exc}", file=sys.stderr)
        return 2
    user_data_source_sha = sha((root / "infra/terraform/r1/user-data.sh").read_bytes())
    embedded = {}
    with zipfile.ZipFile(plan) as archive:
        for name in archive.namelist():
            relative = "infra/terraform/r1/" + name.removeprefix("tfconfig/m-/")
            if name == ".terraform.lock.hcl":
                relative = "infra/terraform/r1/.terraform.lock.hcl"
            if relative in inputs["source_sha256"]:
                assert sha(archive.read(name)) == inputs["source_sha256"][relative], (
                    relative
                )
                embedded[relative] = sha(archive.read(name))
    if len(embedded) < 4:
        raise ValueError("saved plan embeds fewer than four bound Terraform sources")
    inputs["plan_sha256"] = sha(plan.read_bytes())
    inputs["review_state"] = (
        "READY_FOR_REVIEW; exact regenerated review-only plan; Apply closed"
    )
    check = folder / "structural-preflight"
    check.mkdir(exist_ok=False)
    adapter = Production(root, inputs, check, str(tf))
    identity = json.loads((args.refresh / "identity.raw.json").read_bytes())

    with (
        patch.object(
            adapter,
            "aws",
            side_effect=lambda service, operation, *aws_args: offline_aws(
                identity, service, operation, *aws_args
            ),
        ),
        patch.object(adapter, "quota_denied_after", return_value=False),
        patch.object(adapter, "fresh_footprint"),
    ):
        adapter.preflight(plan.read_bytes(), inputs)
    if sha((check / "consumed.tfplan").read_bytes()) != inputs["plan_sha256"]:
        raise ValueError("structural preflight copied different saved-plan bytes")
    raw_metadata = {
        name: {
            "bytes": (folder / name).stat().st_size,
            "sha256": sha((folder / name).read_bytes()),
        }
        for name in [
            "plan.stdout",
            "plan.stderr",
            "plan.argv.json",
            "plan.json",
            "variables.tfvars.json",
        ]
    }
    try:
        summary = build_plan_summary(
            document,
            inputs,
            prepared_at=datetime.datetime.now(datetime.UTC).isoformat(),
            preparation_commit=subprocess.check_output(
                ["git", "rev-parse", "HEAD"], text=True
            ).strip(),
            plan_sha256=inputs["plan_sha256"],
            saved_plan_path=inputs["saved_plan_path"],
            plan_bytes=plan.stat().st_size,
            user_data_source_sha256=user_data_source_sha,
            embedded_committed_config_sha256=embedded,
            terraform_sha256=sha(tf.read_bytes()),
            production_structural_preflight=(
                "PASS actual saved binary parsed/copied/hashed; refreshed "
                "account/usage/inventory callbacks are offline; no consume/execute/Apply"
            ),
            raw=raw_metadata,
        )
    except ValueError as exc:
        print(f"Refusing exact-plan packet: {exc}", file=sys.stderr)
        return 2
    write(args.evidence / "exact-plan.json", summary)
    write(inputs_path, inputs)
    print(json.dumps({"plan_sha256": inputs["plan_sha256"], "creates": 13, "apply": 0}))


if __name__ == "__main__":
    raise SystemExit(main())
