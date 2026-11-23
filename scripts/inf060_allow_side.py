"""CPU-only rehearsal of the instance-role Terraform path and RunInstances authorization."""

import base64
import re
import subprocess
import time

import inf060_operator_packet as remote
import inf060_probe_spec as spec
from inf060_probe_operator import ProbePorts, native_preflight

FREE_RESOURCES = spec.RESOURCES - {"aws_instance.task[0]"}
ALLOW_SIDE_SECONDS = 1200


def verify_free_plan(plan, inputs):
    rows = {
        row["address"]: row["change"]["actions"] for row in plan["resource_changes"]
    }
    spec.check(
        plan.get("applyable") is True
        and plan.get("errored") is False
        and rows == {name: ["create"] for name in FREE_RESOURCES}
        and {name: row["value"] for name, row in plan["variables"].items()} == inputs,
        "allow_side_plan_scope",
    )


def tag_list(mapping):
    return [{"Key": key, "Value": value} for key, value in sorted(mapping.items())]


def run_instances_input(vm, existing, root_device):
    disk = vm["root_block_device"][0]
    metadata = vm["metadata_options"][0]
    return {
        "DryRun": True,
        "MinCount": 1,
        "MaxCount": 1,
        "ImageId": vm["ami"],
        "InstanceType": vm["instance_type"],
        "Placement": {"AvailabilityZone": existing["zone"]},
        "NetworkInterfaces": [
            {
                "DeviceIndex": 0,
                "SubnetId": existing["subnet"],
                "Groups": [existing["group"]],
                "AssociatePublicIpAddress": vm["associate_public_ip_address"],
                "DeleteOnTermination": True,
            }
        ],
        "IamInstanceProfile": {"Name": existing["profile"]},
        "InstanceInitiatedShutdownBehavior": vm["instance_initiated_shutdown_behavior"],
        "MetadataOptions": {
            aws: metadata[key]
            for aws, key in (
                ("HttpEndpoint", "http_endpoint"),
                ("HttpTokens", "http_tokens"),
                ("HttpProtocolIpv6", "http_protocol_ipv6"),
                ("HttpPutResponseHopLimit", "http_put_response_hop_limit"),
                ("InstanceMetadataTags", "instance_metadata_tags"),
            )
            if metadata.get(key) is not None
        },
        "BlockDeviceMappings": [
            {
                "DeviceName": root_device,
                "Ebs": {
                    "Encrypted": disk["encrypted"],
                    "DeleteOnTermination": disk["delete_on_termination"],
                    "VolumeType": disk["volume_type"],
                    "VolumeSize": disk["volume_size"],
                    "Iops": disk["iops"],
                    "Throughput": disk["throughput"],
                },
            }
        ],
        "TagSpecifications": [
            {"ResourceType": "instance", "Tags": tag_list(vm["tags_all"])},
            {"ResourceType": "volume", "Tags": tag_list(vm["volume_tags"])},
        ],
        "UserData": base64.b64encode(vm["user_data"].encode()).decode(),
    }


def run(packet, manifest):
    start = time.time()
    runtime = packet / "allow-side-runtime"
    runtime.mkdir(mode=0o700)
    ports = ProbePorts(packet, manifest, None, runtime)
    ports.deadline = start + ALLOW_SIDE_SECONDS
    tf = packet / "terraform"
    folder = packet / "operator-host"
    cfg = spec.load(tf / "input.tfvars.json")
    receipt = {
        "stages": {},
        "qualified_instance_role": True,
        "gpu_launch_called": False,
        "destroy_completed": False,
        "manifest_sha256": spec.facts(packet / "manifest.json")["sha256"],
        "supervisor_complete": False,
        "supervisor_exit": 1,
        "mock": True,
    }
    terraform = "terraform"

    def command(name, seconds, *args):
        row = ports.command(
            [terraform, *args],
            min(start + ALLOW_SIDE_SECONDS, time.time() + seconds),
            name,
        )
        receipt["stages"][name] = {
            k: row[k] for k in ("exit", "elapsed_s", "log_sha256")
        }
        return ports.runtime / row["log"]

    command("init", 210, "init", "-input=false", "-lockfile=readonly", "-no-color")
    version = spec.load(command("version", 30, "version", "-json"))
    receipt["version"] = {
        "terraform": version["terraform_version"],
        "provider": version["provider_selections"][
            "registry.terraform.io/hashicorp/aws"
        ],
        "platform": version["platform"],
    }
    spec.check(
        receipt["version"]
        == {"terraform": "1.16.2", "provider": "6.64.0", "platform": "linux_amd64"},
        "allow_side_provider",
    )
    native_preflight(ports, packet, manifest, time.time())
    receipt["native_preflight"] = "pass"
    saved = folder / "allow-side.tfplan"
    plan = spec.load(command("show_saved_plan", 90, "show", "-json", saved))
    verify_free_plan(plan, cfg)
    spec.check(
        plan == spec.load(folder / "allow-side.json"), "allow_side_plan_show_binding"
    )
    receipt["planned_resources"] = sorted(FREE_RESOURCES)
    receipt["plan_sha256"] = spec.facts(saved)["sha256"]

    try:
        command("apply", 240, "apply", "-input=false", "-no-color", saved)
        state = spec.load(command("show_applied", 60, "show", "-json"))
        rows = {
            row["address"]: row["values"]
            for row in state["values"]["root_module"]["resources"]
        }
        spec.check(set(rows) == FREE_RESOURCES, "allow_side_applied_scope")
        paid = spec.load(tf / "create.json")
        vm = next(
            row["change"]["after"]
            for row in paid["resource_changes"]
            if row["address"] == "aws_instance.task[0]"
        )
        existing = {
            "zone": rows["aws_subnet.task[0]"]["availability_zone"],
            "subnet": rows["aws_subnet.task[0]"]["id"],
            "group": rows["aws_security_group.task[0]"]["id"],
            "profile": rows["aws_iam_instance_profile.task[0]"]["name"],
        }
        ports.deadline = min(start + 900, time.time() + 50)
        image = ports.aws("ec2", "describe-images", ["--image-ids", spec.AMI])[
            "Images"
        ][0]
        data = run_instances_input(vm, existing, image["RootDeviceName"])
        path = runtime / "dry-run.private.json"
        spec.save(path, data)
        result = subprocess.run(
            [
                "aws",
                "ec2",
                "run-instances",
                "--dry-run",
                "--cli-input-json",
                "file://" + str(path),
            ],
            capture_output=True,
            timeout=45,
            check=False,
        )
        error = re.search(rb"An error occurred \(([A-Za-z0-9._]+)\)", result.stderr)
        code = error[1].decode() if error else "unclassified"
        receipt["run_instances"] = {
            "decision": code,
            "exit_code": result.returncode,
            "DryRun": data["DryRun"],
            "image": data["ImageId"],
            "instance_type": data["InstanceType"],
            "placement": data["Placement"],
            "metadata": data["MetadataOptions"],
            "root": data["BlockDeviceMappings"],
            "tag_specifications": data["TagSpecifications"],
            "shutdown_behavior": data["InstanceInitiatedShutdownBehavior"],
            "same_subnet_group_profile_as_free_apply": True,
        }
        spec.check(
            result.returncode != 0 and code == "DryRunOperation",
            "allow_side_dry_run:" + code,
        )
    finally:
        # Inventory runs even if destroy reports an error. Keep state and
        # evidence on the operator if either proof is missing.
        try:
            command(
                "destroy",
                300,
                "destroy",
                "-input=false",
                "-auto-approve",
                "-var-file=input.tfvars.json",
                "-no-color",
            )
            receipt["destroy_completed"] = True
        finally:
            try:
                receipt["inventory"] = ports.inventory(start + ALLOW_SIDE_SECONDS)
            finally:
                receipt["elapsed_seconds"] = time.time() - start
                spec.save(packet / "allow-side-result.json", receipt)
    remote.require_zero(receipt["inventory"])
    for state in tf.glob("terraform.tfstate*"):
        state.replace(runtime / state.name)
    return receipt
