"""Run mock/schema/controller checks and optional sealed real-provider plans.

Real plan/show runs require the network-disabled container, a local-backend
override and fixture variables/credentials. Never plan against AWS or apply.
"""

import argparse
import copy
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from hashlib import sha256
from pathlib import Path

from inference_platform.m5_infra_safety import (
    Binding,
    Refused,
    rehearse_lifecycle,
    verify_gpu_destroy_plan,
    verify_gpu_plan,
    verify_gpu_recreate_plan,
)

ROOT = Path(__file__).resolve().parents[1]


class NoLifecycleCalls:
    def __getattr__(self, name):
        raise AssertionError(f"mismatched plan reached lifecycle operation {name}")


def run(command, env):
    result = subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=False,
    )
    if result.returncode:
        sys.stderr.write(result.stdout + result.stderr)
        raise SystemExit(result.returncode)
    if "unittest" in command:
        print(result.stderr, end="")
    return result.stdout


def refuse_before_marker(plan, binding, verifier=None):
    saved = json.dumps(plan).encode()
    try:
        if verifier is not None:
            verifier(plan, binding)
            # Acceptance here must fail immediately: a later general-capacity
            # refusal (notably on destroy's null binding) cannot mask a bad check.
            NoLifecycleCalls().marker(sha256(saved).hexdigest())
        rehearse_lifecycle(
            NoLifecycleCalls(), lambda: saved, sha256(saved).hexdigest(), binding
        )
    except Refused:
        return
    raise AssertionError("unsafe plan accepted before marker")


def synthetic_retained_state(plan, schemas):
    """Fixture state for the resources retained by gpu_enabled=false, not AWS evidence.

    Start with real provider planned defaults, then supply fixture identities and
    dependency values. Never apply, refresh, import or read a real state/backend.
    """
    resources = []
    default_tags = {
        "Project": "multi-tenant-llm-inference-platform",
        "Milestone": "INF-019",
        "Session": "m5-fixture",
    }
    vpc_id = "vpc-00000000000000000"
    subnet_ids = [f"subnet-0000000000000000{i}" for i in range(2)]
    gateway_id = "igw-00000000000000000"
    route_table_id = "rtb-00000000000000000"
    subnet_ids_by_key = {}
    route_table_ids_by_key = {}
    for row in plan["resource_changes"]:
        key = (row.get("name"), row.get("index"))
        if row["type"] == "aws_subnet":
            subnet_ids_by_key[key] = f"subnet-{len(subnet_ids_by_key) + 1:017x}"
        elif row["type"] == "aws_route_table":
            route_table_ids_by_key[key] = f"rtb-{len(route_table_ids_by_key) + 1:017x}"
    for row in plan["resource_changes"]:
        if row["address"] in {
            "aws_launch_template.gpu[0]",
            "aws_eks_node_group.gpu[0]",
        }:
            continue
        kind = row["type"]
        values = copy.deepcopy(row["change"]["after"])
        values["id"] = f"fixture-{len(resources)}"
        if kind.startswith("aws_"):
            values["region"] = "us-east-1"
            if "tags" in values or "tags_all" in values:
                values["tags_all"] = default_tags | (values.get("tags") or {})
        if kind == "aws_vpc":
            values.update(id=vpc_id, ipv6_netmask_length=0)
        elif kind == "aws_subnet":
            values.update(
                id=subnet_ids_by_key[(row.get("name"), row.get("index"))],
                vpc_id=vpc_id,
                assign_ipv6_address_on_creation=False,
                enable_dns64=False,
                ipv6_native=False,
                enable_resource_name_dns_a_record_on_launch=False,
                enable_resource_name_dns_aaaa_record_on_launch=False,
            )
        elif kind == "aws_internet_gateway":
            values.update(id=gateway_id, vpc_id=vpc_id)
        elif kind == "aws_route_table":
            key = (row.get("name"), row.get("index"))
            values.update(id=route_table_ids_by_key[key], vpc_id=vpc_id)
            values["route"][0]["gateway_id"] = gateway_id
        elif kind == "aws_route_table_association":
            key = (row.get("name"), row.get("index"))
            if row.get("index") is None:
                values.update(
                    subnet_id=subnet_ids_by_key[key],
                    route_table_id=route_table_ids_by_key[key],
                )
            else:
                values.update(
                    subnet_id=subnet_ids[int(row["index"])],
                    route_table_id=route_table_id,
                )
        elif kind == "aws_iam_role":
            name = f"m5-fixture-{row.get('index', row['name'])}-fixture"
            values.update(
                id=name, name=name, arn=f"arn:aws:iam::000000000000:role/{name}"
            )
        elif kind == "aws_iam_role_policy_attachment":
            role_key = row.get("index", row["name"])
            role = (
                role_key
                if role_key in {"cluster", "node", "sender", "receiver"}
                else "node"
            )
            values["role"] = f"m5-fixture-{role}-fixture"
        elif kind == "aws_eks_cluster":
            values["role_arn"] = (
                "arn:aws:iam::000000000000:role/m5-fixture-cluster-fixture"
            )
            values["vpc_config"][0]["subnet_ids"] = subnet_ids
            values["vpc_config"][0]["security_group_ids"] = []
        elif kind == "aws_eks_node_group":
            values["node_role_arn"] = (
                "arn:aws:iam::000000000000:role/m5-fixture-node-fixture"
            )
            values["subnet_ids"] = subnet_ids
        # Empty computed collections must be represented as empty rather than
        # null, just as on a provider-populated state. No plan actions are edited.
        if kind != "terraform_data":
            block = schemas[kind]["block"]
            for key, attribute in block["attributes"].items():
                attribute_type = attribute["type"]
                if (
                    attribute.get("computed")
                    and values.get(key) is None
                    and isinstance(attribute_type, list)
                ):
                    values[key] = {} if attribute_type[0] == "map" else []
            for key, nested in block.get("block_types", {}).items():
                if values.get(key) is None and nested["nesting_mode"] in {
                    "list",
                    "set",
                }:
                    values[key] = []
        instance = {
            "schema_version": schemas[kind]["version"]
            if kind != "terraform_data"
            else 0,
            "attributes": values,
        }
        if "index" in row:
            instance["index_key"] = row["index"]
        resources.append(
            {
                "mode": "managed",
                "type": kind,
                "name": row["name"],
                "provider": (
                    'provider["terraform.io/builtin/terraform"]'
                    if kind == "terraform_data"
                    else 'provider["registry.terraform.io/hashicorp/aws"]'
                ),
                "instances": [instance],
            }
        )
    # for_each instances of the same resource share one state resource record.
    grouped = {}
    for resource in resources:
        key = (resource["type"], resource["name"])
        if key in grouped:
            grouped[key]["instances"].extend(resource["instances"])
        else:
            grouped[key] = resource
    return {
        "version": 4,
        "terraform_version": "1.16.2",
        "serial": 1,
        "lineage": "00000000-0000-0000-0000-000000000211",
        "outputs": {},
        "resources": list(grouped.values()),
    }


def add_synthetic_gpu_state(state, plan, schemas, include_group):
    """Add fixture GPU identities for surviving-template or full destroy state."""
    for row in plan["resource_changes"]:
        kind = row["type"]
        if row["name"] != "gpu" or kind not in {
            "aws_launch_template",
            "aws_eks_node_group",
        }:
            continue
        if kind == "aws_eks_node_group" and not include_group:
            continue
        attributes = copy.deepcopy(row["change"]["after"])
        if kind == "aws_launch_template":
            attributes.update(id="lt-00000000000000000", latest_version=1)
        else:
            attributes.update(
                id="m5-fixture:gpu",
                node_role_arn="arn:aws:iam::000000000000:role/m5-fixture-node-fixture",
                subnet_ids=["subnet-00000000000000000"],
            )
            attributes["launch_template"][0].update(
                id="lt-00000000000000000", version="1"
            )
        state["resources"].append(
            {
                "mode": "managed",
                "type": kind,
                "name": "gpu",
                "provider": 'provider["registry.terraform.io/hashicorp/aws"]',
                "instances": [
                    {
                        "index_key": 0,
                        "schema_version": schemas[kind]["version"],
                        "attributes": attributes,
                    }
                ],
            }
        )


def inspect_actions(plan, label):
    """Emit reviewable actions/replacement paths, beyond a suite PASS line."""
    for row in plan["resource_changes"]:
        print(
            f"{label} {row['address']}: actions={row['change']['actions']} "
            f"replace_paths={row['change'].get('replace_paths', [])}"
        )
        if row["change"]["actions"] == ["update"]:
            change = row["change"]
            before, after = change["before"], change["after"]
            print(
                {
                    key: (
                        before.get(key),
                        after.get(key),
                        change["after_unknown"].get(key),
                    )
                    for key in before.keys()
                    | after.keys()
                    | change["after_unknown"].keys()
                    if before.get(key) != after.get(key)
                    or change["after_unknown"].get(key) is True
                }
            )


def sealed_provider_plans(terraform, env):
    """Use real configuration from plan/show, only in the sealed Linux container."""
    # Refuse accidental native/host execution even when skip flags are enabled.
    assert Path("/work/src").resolve() == ROOT
    assert {path.name for path in Path("/sys/class/net").iterdir()} == {"lo"}
    original = ROOT / "infra/terraform/eks"
    schemas = json.loads(
        run(
            [
                terraform,
                "-chdir=infra/terraform/eks/bootstrap",
                "providers",
                "schema",
                "-json",
            ],
            env,
        )
    )["provider_schemas"]["registry.terraform.io/hashicorp/aws"]["resource_schemas"]
    tests = (original / "tests/offline.tftest.hcl").read_text()
    for name, zone in (
        ("reviewed_group_binding_and_fixed_nodes", "us-east-1a"),
        ("reviewed_alternative_zone", "us-east-1b"),
    ):
        # Copy the test's HCL assignments verbatim, including nested objects.
        # Configuration references below always come from show, never source regex.
        variables = tests.split(f'run "{name}" {{', 1)[1]
        variables = variables.split("  variables {\n", 1)[1].split("\n  }\n", 1)[0]
        happy_plan = None
        literal_subnet = "subnet-0fixture00000001"
        for variant in (
            "base",
            "moved",
            "known",
            "recreate",
            "surviving-template",
            "recreate-retained-replacement",
            "destroy",
            "destroy-retained-replacement",
        ):
            with tempfile.TemporaryDirectory(
                prefix="m5-sealed-", dir="/work"
            ) as directory:
                scratch = Path(directory)
                for path in original.glob("*.tf"):
                    shutil.copy2(path, scratch / path.name)
                shutil.copy2(original / ".terraform.lock.hcl", scratch)
                (scratch / "fixture.tfvars").write_text(variables)
                (scratch / "sealed_override.tf").write_text(
                    'terraform {\n  backend "local" {}\n}\n'
                    'provider "aws" {\n'
                    "  skip_credentials_validation = true\n"
                    "  skip_metadata_api_check = true\n"
                    "  skip_requesting_account_id = true\n}\n"
                )
                state_variant = variant in {
                    "recreate",
                    "surviving-template",
                    "recreate-retained-replacement",
                    "destroy",
                    "destroy-retained-replacement",
                }
                if state_variant:
                    assert happy_plan is not None
                    state = synthetic_retained_state(happy_plan, schemas)
                    if variant == "surviving-template" or variant.startswith("destroy"):
                        add_synthetic_gpu_state(
                            state,
                            happy_plan,
                            schemas,
                            include_group=variant.startswith("destroy"),
                        )
                    if variant.endswith("retained-replacement"):
                        subnet = next(
                            row
                            for row in state["resources"]
                            if row["type"] == "aws_subnet"
                        )
                        instance = next(
                            row
                            for row in subnet["instances"]
                            if row["index_key"] == "1"
                        )
                        instance["attributes"]["cidr_block"] = "10.45.9.0/24"
                    if variant.startswith("destroy"):
                        with (scratch / "fixture.tfvars").open("a") as stream:
                            stream.write("\ngpu_enabled = false\n")
                    (scratch / "terraform.tfstate").write_text(json.dumps(state))
                if variant in {"moved", "known"}:
                    source = (scratch / "main.tf").read_text()
                    start = source.index('resource "aws_eks_node_group" "gpu" {')
                    body, count = re.subn(
                        r"(?m)^(\s*subnet_ids\s*=).+$",
                        (
                            r'\1 [aws_subnet.m5["1"].id]'
                            if variant == "moved"
                            else rf'\1 ["{literal_subnet}"]'
                        ),
                        source[start:],
                        count=1,
                    )
                    assert count == 1
                    (scratch / "main.tf").write_text(source[:start] + body)
                scratch_env = dict(env, TF_DATA_DIR=str(scratch / ".terraform"))
                command = [terraform, f"-chdir={scratch}"]
                run(
                    command + ["init", "-input=false", "-lockfile=readonly"],
                    scratch_env,
                )
                run(
                    command
                    + [
                        "plan",
                        "-input=false",
                        "-refresh=false",
                        "-lock=false",
                        "-var-file=fixture.tfvars",
                        "-out=sealed.tfplan",
                    ],
                    scratch_env,
                )
                plan = json.loads(
                    run(command + ["show", "-json", "sealed.tfplan"], scratch_env)
                )
                output = (happy_plan if variant.startswith("destroy") else plan)[
                    "output_changes"
                ]["capacity_binding"]["after"]
                packet = Binding(output["group_arn"], zone)
                if state_variant:
                    inspect_actions(plan, f"Sealed {zone} {variant}")
                    by_address = {
                        row["address"]: row["change"]
                        for row in plan["resource_changes"]
                    }
                    if variant.endswith("retained-replacement"):
                        subnet = by_address['aws_subnet.m5["1"]']
                        assert subnet["actions"] == ["delete", "create"]
                        assert subnet["replace_paths"] == [["cidr_block"]]
                        if variant.startswith("destroy"):
                            refuse_before_marker(
                                plan,
                                packet,
                                lambda plan, _: verify_gpu_destroy_plan(plan),
                            )
                        else:
                            assert verify_gpu_plan(plan, packet) == packet
                            refuse_before_marker(plan, packet, verify_gpu_recreate_plan)
                        print(
                            f"Sealed real-provider {zone}: {variant} refused before marker PASS"
                        )
                        continue
                    for address, change in by_address.items():
                        if address not in {
                            "aws_launch_template.gpu[0]",
                            "aws_eks_node_group.gpu[0]",
                        }:
                            assert change["actions"] == ["no-op"], (address, change)
                            assert not change.get("replace_paths"), (address, change)
                    if variant == "destroy":
                        assert (
                            plan["output_changes"]["capacity_binding"]["after"] is None
                        )
                        for address in (
                            "aws_launch_template.gpu[0]",
                            "aws_eks_node_group.gpu[0]",
                        ):
                            assert by_address[address]["actions"] == ["delete"]
                            assert by_address[address]["after"] is None
                        verify_gpu_destroy_plan(plan)
                        print(
                            f"Sealed real-provider {zone}: full-state GPU-only destroy accepted PASS"
                        )
                        continue
                    gpu = by_address["aws_eks_node_group.gpu[0]"]
                    assert gpu["actions"] == ["create"]
                    assert gpu["after"]["subnet_ids"] == ["subnet-00000000000000000"]
                    assert len(gpu["after_unknown"]["subnet_ids"]) == 1
                    assert gpu["after_unknown"]["subnet_ids"][0] is False
                    if variant == "recreate":
                        assert by_address["aws_launch_template.gpu[0]"]["actions"] == [
                            "create"
                        ]
                        assert verify_gpu_plan(plan, packet) == packet
                        assert verify_gpu_recreate_plan(plan, packet) == packet
                        print(
                            f"Sealed real-provider {zone}: retained-state recreate accepted PASS"
                        )
                    else:
                        assert by_address["aws_launch_template.gpu[0]"]["actions"] != [
                            "create"
                        ]
                        refuse_before_marker(plan, packet, verify_gpu_recreate_plan)
                        print(
                            f"Sealed real-provider {zone}: surviving template refused before marker PASS"
                        )
                elif variant == "moved":
                    refuse_before_marker(plan, packet)
                    print(
                        f"Sealed real-provider {zone}: moved m5[1] refuses before marker PASS"
                    )
                elif variant == "known":
                    # The literal variant supplies real provider value shapes;
                    # it cannot satisfy the configuration-reference contract.
                    # Splice only that pair into the real happy-path plan.
                    gpu_change = next(
                        resource["change"]
                        for resource in plan["resource_changes"]
                        if resource["address"] == "aws_eks_node_group.gpu[0]"
                    )
                    known = gpu_change["after"]["subnet_ids"]
                    unknown = gpu_change["after_unknown"]["subnet_ids"]
                    assert known == [literal_subnet]
                    assert (
                        isinstance(unknown, list)
                        and len(unknown) == 1
                        and unknown[0] is False
                    )
                    assert happy_plan is not None
                    spliced = copy.deepcopy(happy_plan)
                    spliced_gpu = next(
                        resource["change"]
                        for resource in spliced["resource_changes"]
                        if resource["address"] == "aws_eks_node_group.gpu[0]"
                    )
                    spliced_gpu["after"]["subnet_ids"] = copy.deepcopy(known)
                    spliced_gpu["after_unknown"]["subnet_ids"] = copy.deepcopy(unknown)
                    assert verify_gpu_plan(spliced, packet) == packet
                    print(
                        f"Sealed real-provider {zone}: literal [subnet]/[false] pair "
                        "asserted and accepted in real happy-path plan PASS"
                    )
                else:
                    happy_plan = plan
                    binding = verify_gpu_plan(plan, packet)
                    subnet = next(
                        resource
                        for resource in plan["resource_changes"]
                        if resource["address"] == 'aws_subnet.m5["0"]'
                    )
                    assert (
                        binding.zone
                        == subnet["change"]["after"]["availability_zone"]
                        == zone
                    )
                    missing = copy.deepcopy(plan)
                    del missing["configuration"]
                    refuse_before_marker(missing, packet)
                    missing_ref = copy.deepcopy(plan)
                    gpu = next(
                        resource
                        for resource in missing_ref["configuration"]["root_module"][
                            "resources"
                        ]
                        if resource["address"] == "aws_eks_node_group.gpu"
                    )
                    del gpu["expressions"]["subnet_ids"]["references"]
                    refuse_before_marker(missing_ref, packet)
                    print(
                        f"Sealed real-provider {zone}: accepted, derived AZ equals first subnet; "
                        "missing configuration/reference refuse before marker PASS"
                    )


def sealed_container(env):
    """Native entry point delegates real-provider plans to --network none."""
    command = [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--cpus",
        "2",
        "--memory",
        "6g",
    ]
    for source, target in (
        (ROOT, "/src"),
        (ROOT / ".cache/m5-provider-mirror", "/mirror"),
        (ROOT / ".cache/terraform_1.16.2_linux_amd64.zip", "/terraform.zip"),
    ):
        if not source.exists():
            raise SystemExit(f"sealed check prerequisite missing: {source}")
        command += ["--mount", f"type=bind,source={source},target={target},readonly"]
    command += ["r87-generator-tools:local", "sh", "/src/scripts/check_m5_linux.sh"]
    print(run(command, env), end="")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--terraform", default="terraform")
    parser.add_argument(
        "--sealed-provider-plans",
        action="store_true",
        help="also run the network-disabled Linux suite via Docker",
    )
    parser.add_argument(
        "--inside-sealed-container", action="store_true", help=argparse.SUPPRESS
    )
    args = parser.parse_args()
    terraform = (
        str(Path(args.terraform).resolve())
        if Path(args.terraform).is_file()
        else args.terraform
    )
    env = dict(os.environ)
    env.update(
        AWS_ACCESS_KEY_ID="offline-fixture",
        AWS_SECRET_ACCESS_KEY="offline-fixture",
        AWS_EC2_METADATA_DISABLED="true",
        TF_IN_AUTOMATION="1",
    )
    version = json.loads(run([args.terraform, "version", "-json"], env))
    if version["terraform_version"] != "1.16.2":
        raise SystemExit("Terraform 1.16.2 required; no version substitution")
    for root in ("infra/terraform/eks", "infra/terraform/eks/bootstrap"):
        command = [args.terraform, f"-chdir={root}"]
        run(command + ["fmt", "-check", "-recursive"], env)
        run(
            command + ["init", "-backend=false", "-input=false", "-lockfile=readonly"],
            env,
        )
        selected = json.loads(run(command + ["version", "-json"], env))[
            "provider_selections"
        ]
        if selected != {"registry.terraform.io/hashicorp/aws": "6.64.0"}:
            raise SystemExit(f"unexpected provider selection: {selected}")
        run(command + ["validate", "-no-color"], env)
        # The session root deliberately has an uninitialized S3 backend. Read
        # the same locked provider's schema from bootstrap, never init S3.
        schema_command = [args.terraform, "-chdir=infra/terraform/eks/bootstrap"]
        if root.endswith("eks"):
            run(
                schema_command
                + ["init", "-backend=false", "-input=false", "-lockfile=readonly"],
                env,
            )
        schema = json.loads(run(schema_command + ["providers", "schema", "-json"], env))
        resources = schema["provider_schemas"]["registry.terraform.io/hashicorp/aws"][
            "resource_schemas"
        ]
        spec = resources["aws_launch_template"]["block"]["block_types"][
            "capacity_reservation_specification"
        ]["block"]
        assert spec["attributes"]["capacity_reservation_preference"]["optional"]
        target = spec["block_types"]["capacity_reservation_target"]["block"][
            "attributes"
        ]
        assert target["capacity_reservation_resource_group_arn"]["optional"]
        assert target["capacity_reservation_id"]["optional"]
        assert (
            "configuration"
            in resources["aws_resourcegroups_group"]["block"]["block_types"]
        )
        rows = []
        for line in io.StringIO(run(command + ["test", "-json", "-verbose"], env)):
            row = json.loads(line)
            if row["type"] == "test_plan":
                # Terraform repeats the large provider schema for every run.
                # Keep plan values only, within the constrained memory budget.
                row["test_plan"].pop("provider_schemas", None)
            rows.append(row)
        plans = {
            row["@testrun"]: row["test_plan"]
            for row in rows
            if row["type"] == "test_plan"
        }
        default = "default_zero_resources" if root.endswith("eks") else "default_empty"
        assert not plans[default].get("resource_changes"), (
            "default planned nonzero resources"
        )
        summary = next(
            row["test_summary"] for row in rows if row["type"] == "test_summary"
        )
        print(f"{root}: fmt/validate/schema/default/mock tests PASS {summary}")
    if args.inside_sealed_container:
        sealed_provider_plans(terraform, env)
    elif args.sealed_provider_plans:
        sealed_container(env)
    else:
        print(
            "Sealed real-provider plans NOT RUN; use --sealed-provider-plans (Docker required)"
        )
    output = run(
        [
            sys.executable,
            "-m",
            "unittest",
            "discover",
            "-s",
            "python/tests",
            "-p",
            "test_m5_infra_safety.py",
            "-v",
        ],
        env,
    )
    print(output, end="")
    print("INF-019 offline controller and plan regression tests PASS")


if __name__ == "__main__":
    main()
