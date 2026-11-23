"""Closed CPU clock rehearsal bindings shared by sealing and launch."""

import hashlib
import json
import re
import tarfile
from collections import Counter
from pathlib import Path

from inference_platform.eks_deployment import NGINX_IMAGE, PROMETHEUS_IMAGE, REDIS_IMAGE
from m5_descriptive_cleanup import pages

SESSION = "m5-desc-r420-cpu"
PLAN_DIRECTORY = "cpu-clock"
OPERATOR_TYPE = "m6i.2xlarge"
WORKER_TYPE = "c6i.2xlarge"
NODE_COUNT = 3
IMAGE_ARCHIVE = "clock-images.tar.gz"
IMAGE_TAGS = {"gateway": "mti-gateway:stage1", "client": "mti-fake:stage1"}
SERVICE_IMAGES = {
    "redis": REDIS_IMAGE,
    "streaming-ingress": NGINX_IMAGE,
    "telemetry": PROMETHEUS_IMAGE,
}
CPU_MARKER = "INF-060 CPU EKS REHEARSAL APPROVED"
STANDARD_QUOTA_CODE = "L-1216C47A"
REQUIRED_VCPUS = 32
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
BLOB = re.compile(r"blobs/sha256/([0-9a-f]{64})")


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def canonical_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def blob_digest(path):
    binding = BLOB.fullmatch(path)
    if not binding:
        raise ValueError("cpu_clock:image_blob")
    return "sha256:" + binding[1]


def archive_index_bindings(index, manifest):
    """Join Docker's legacy tag/config layout to its OCI manifest identities."""
    rows = {}
    for role, tag in IMAGE_TAGS.items():
        [legacy] = [row for row in manifest if tag in row["RepoTags"]]
        [descriptor] = [
            row
            for row in index["manifests"]
            if row.get("annotations", {}).get("io.containerd.image.name")
            in {tag, "docker.io/library/" + tag}
        ]
        config = blob_digest(legacy["Config"])
        manifest_digest = descriptor["digest"]
        if (
            not DIGEST.fullmatch(manifest_digest)
            or config == manifest_digest
            or descriptor.get("annotations", {}).get("config.digest", config) != config
        ):
            raise ValueError("cpu_clock:image_digest")
        rows[role] = {
            "config_digest": config,
            "manifest_digest": manifest_digest,
            "layer_digests": [blob_digest(path) for path in legacy["Layers"]],
        }
    return rows


def archive_image_bindings(path):
    """Read bounded metadata only. The enclosing archive is sealed separately."""
    with tarfile.open(path, "r:gz") as archive:

        def read(name, expected=None):
            member = archive.getmember(name)
            if not member.isfile() or not 0 < member.size <= 1024**2:
                raise ValueError("cpu_clock:image_metadata")
            with archive.extractfile(member) as stream:
                raw = stream.read()
            if expected and "sha256:" + hashlib.sha256(raw).hexdigest() != expected:
                raise ValueError("cpu_clock:image_digest")
            return json.loads(raw)

        def read_blob(value):
            return read("blobs/" + value.replace(":", "/"), value)

        images = archive_index_bindings(read("index.json"), read("manifest.json"))
        for facts in images.values():
            config = read_blob(facts["config_digest"])
            manifest = read_blob(facts["manifest_digest"])
            if (config["os"], config["architecture"]) != ("linux", "amd64"):
                raise ValueError("cpu_clock:image_platform")
            check_pushed_content(manifest, facts)
            facts["diff_ids"] = config["rootfs"]["diff_ids"]
    check_image_bindings(images, images)
    return images


def check_image_bindings(actual, expected):
    if (
        set(expected) != set(IMAGE_TAGS)
        or any(
            set(row)
            != {"manifest_digest", "config_digest", "layer_digests", "diff_ids"}
            or row["manifest_digest"] == row["config_digest"]
            or not row["layer_digests"]
            or len(row["diff_ids"]) != len(row["layer_digests"])
            or any(
                not DIGEST.fullmatch(value)
                for value in [
                    row["manifest_digest"],
                    row["config_digest"],
                    *row["layer_digests"],
                    *row["diff_ids"],
                ]
            )
            for row in expected.values()
        )
        or actual != expected
    ):
        raise ValueError("cpu_clock:image_digest")


def check_loaded_image(inspected, facts):
    # Classic Docker exposes the config ID. The containerd store can expose
    # the manifest ID instead. RootFS still exposes the ordered diff IDs.
    if (
        inspected["Id"] not in {facts["config_digest"], facts["manifest_digest"]}
        or inspected["RootFS"]["Layers"] != facts["diff_ids"]
        or (inspected["Os"], inspected["Architecture"]) != ("linux", "amd64")
    ):
        raise ValueError("cpu_clock:image_digest")


def check_pushed_content(manifest, facts):
    if (
        manifest["config"]["digest"] != facts["config_digest"]
        or [layer["digest"] for layer in manifest["layers"]] != facts["layer_digests"]
    ):
        raise ValueError("cpu_clock:image_digest")


def standard_quota_readback(sdk):
    quota = sdk.client("service-quotas").get_service_quota(
        ServiceCode="ec2", QuotaCode=STANDARD_QUOTA_CODE
    )["Quota"]["Value"]
    ec2 = sdk.client("ec2")
    instances = pages(
        ec2,
        "describe_instances",
        "Reservations",
        Filters=[{"Name": "instance-state-name", "Values": ["pending", "running"]}],
    )
    occupied = Counter(
        row["InstanceType"]
        for reservation in instances
        for row in reservation["Instances"]
        if not row.get("InstanceLifecycle")
        and row.get("Placement", {}).get("Tenancy") != "host"
        and row["InstanceType"][0] in "acdhimrtz"
        and not row["InstanceType"].startswith(("dl", "hpc", "inf", "mac", "trn"))
    )
    vcpus = {}
    types = sorted(occupied)
    for start in range(0, len(types), 100):
        vcpus.update(
            {
                row["InstanceType"]: row["VCpuInfo"]["DefaultVCpus"]
                for row in pages(
                    ec2,
                    "describe_instance_types",
                    "InstanceTypes",
                    InstanceTypes=types[start : start + 100],
                )
            }
        )
    if set(vcpus) != set(occupied) or any(
        type(count) is not int or count <= 0 for count in vcpus.values()
    ):
        raise ValueError("cpu_clock:quota_inventory")
    running = sum(count * vcpus[name] for name, count in occupied.items())
    return {
        "quota_vcpus": quota,
        "running_vcpus": running,
        "required_vcpus": REQUIRED_VCPUS,
        "fits": running + REQUIRED_VCPUS <= quota,
    }


def verify_cpu_plan(plan):
    changes = plan["resource_changes"]
    if any(row["change"]["actions"] != ["create"] for row in changes):
        raise ValueError("cpu_clock:plan_create_only")
    if any(
        row["type"] in {"aws_launch_template", "aws_ec2_capacity_reservation"}
        or (row["type"] == "aws_eks_node_group" and row["name"] != "cpu")
        for row in changes
    ):
        raise ValueError("cpu_clock:gpu_resource")
    nodes = [
        row["change"]["after"] for row in changes if row["type"] == "aws_eks_node_group"
    ]
    if (
        len(nodes) != 1
        or nodes[0]["instance_types"] != [WORKER_TYPE]
        or nodes[0]["ami_type"] != "AL2023_x86_64_STANDARD"
        or nodes[0]["capacity_type"] != "ON_DEMAND"
        or nodes[0]["scaling_config"]
        != [
            {"min_size": NODE_COUNT, "desired_size": NODE_COUNT, "max_size": NODE_COUNT}
        ]
        or nodes[0]["labels"] != {"m5-role": "cpu"}
        or nodes[0].get("taint")
    ):
        raise ValueError("cpu_clock:cpu_node_group")
    host = [row["change"]["after"] for row in changes if row["type"] == "aws_instance"]
    if len(host) != 1 or host[0]["instance_type"] != OPERATOR_TYPE:
        raise ValueError("cpu_clock:operator_instance")
    addons = [
        row["change"]["after"]
        for row in changes
        if row["type"] == "aws_eks_addon"
        and row["change"]["after"]["addon_name"] == "vpc-cni"
    ]
    if len(addons) != 1 or json.loads(
        addons[0].get("configuration_values") or "{}"
    ) != {"enableNetworkPolicy": "true"}:
        raise ValueError("cpu_clock:network_policy")
    pins = plan["configuration"]["root_module"]["module_calls"]["eks"]["expressions"][
        "pins"
    ]
    if not {"module.operator.public_ip", "module.operator.role_arn"} <= set(
        pins["references"]
    ):
        raise ValueError("cpu_clock:operator_api_binding")
    policy = next(
        row["change"]["after"]["policy"]
        for row in changes
        if row["address"] == "aws_iam_role_policy.operator"
    )
    return json.loads(policy)


def verify_cpu_binding(directory, manifest):
    directory = Path(directory)
    cpu = manifest["descriptive"]["cpu_clock_rehearsal"]
    if (
        manifest["session"] != SESSION
        or manifest["timing"]["capacity_wait_budget_seconds"] != 0
        or manifest["alternatives"] != [cpu["selection"]]
        or cpu["selection"]["directory"] != PLAN_DIRECTORY
        or manifest["descriptive"]["streaming"]["gpu_hourly_usd"] != 0
    ):
        raise ValueError("cpu_clock:packet_scope")
    expected = manifest["host_manifest"]["gate_a_inputs"]
    if (
        set(expected["inventory"]) != {IMAGE_ARCHIVE}
        or expected.get("s3_staging") is not None
        or expected["bundle_path"] != "cpu-images.tar"
        or expected["bundle_bytes"] != manifest["files"]["cpu-images.tar"]["bytes"]
        or expected["bundle_sha256"] != manifest["files"]["cpu-images.tar"]["sha256"]
    ):
        raise ValueError("cpu_clock:image_archive_binding")
    build = json.loads((directory / "cpu-image-producer.json").read_bytes())
    check_image_bindings(build["images"], cpu["images"])
    if (
        build["source"] != manifest["source_commit"]
        or build["archive"] != expected["inventory"][IMAGE_ARCHIVE]
        or build["operator_ami"] != manifest["host_manifest"]["ami"]
    ):
        raise ValueError("cpu_clock:image_archive_binding")
    if cpu["service_images"] != SERVICE_IMAGES:
        raise ValueError("cpu_clock:service_images")
    if {row["directory"] for row in manifest["plans"]} != {
        "bootstrap",
        "backstop",
        PLAN_DIRECTORY,
    } or len(manifest["plans"]) != 3:
        raise ValueError("cpu_clock:plan_roots")
    for row in manifest["plans"]:
        prefix = row["directory"] + "/"
        if (
            manifest["files"][prefix + "create.tfplan"]["sha256"] != row["sha256"]
            or manifest["files"][prefix + "show.stdout"]["sha256"] != row["json_sha256"]
        ):
            raise ValueError("cpu_clock:plan_hash_pair")
    plan = json.loads((directory / PLAN_DIRECTORY / "show.stdout").read_bytes())
    policy = verify_cpu_plan(plan)
    if canonical_digest(policy) != cpu["operator_policy_sha256"]:
        raise ValueError("cpu_clock:operator_policy")
    if canonical_digest(policy_actions(policy)) != cpu["operator_actions_sha256"]:
        raise ValueError("cpu_clock:operator_actions")
    backstop = json.loads((directory / "backstop/show.stdout").read_bytes())
    policy = json.loads(
        next(
            row["change"]["after"]["policy"]
            for row in backstop["resource_changes"]
            if row["type"] == "aws_iam_role_policy"
        )
    )
    if (
        canonical_digest(policy) != manifest["cleanup_policy_sha256"]
        or canonical_digest(policy_actions(policy)) != cpu["backstop_actions_sha256"]
    ):
        raise ValueError("cpu_clock:backstop_policy_actions")


def policy_actions(policy):
    actions = set()
    for row in policy["Statement"]:
        value = row["Action"]
        actions.update([value] if isinstance(value, str) else value)
    return sorted(actions)
