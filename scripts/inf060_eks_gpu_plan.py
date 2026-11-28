"""Closed binding and read-only quota checks for the INF-060 GPU plan."""

import json
import re
import tarfile

from inf060_eks_cpu_plan import STANDARD_QUOTA_CODE, quota_readback
from inference_platform.eks_deployment import MODEL, REVISION, VLLM_IMAGE
from inference_platform.inf060_eks_packet import (
    CORPUS_NAME,
    file_sha,
    seal_timing,
    transfer_rate,
)
from inference_platform.inf060_eks_receipts import schedule_digest
from inference_platform.inf060_eks_schedule import LEVELS
from inference_platform.stage_c_tokenizer import FILE_HASHES

GPU_SESSION = "m5-desc-inf060-r423"
GPU_MARKER = "GPU EKS PLAN APPROVED"
GPU_QUOTA = "L-DB2E81BA"


def write_gpu_streaming_module(path):
    # Transform only the copied GPU packet module. Legacy roots and their
    # generated configurations keep the original conditional policy value.
    source = path.read_bytes()
    before = b'each.key == "vpc-cni" && var.cpu_clock_rehearsal ?'
    after = b'each.key == "vpc-cni" ?'
    if source.count(before) != 1:
        raise ValueError("streaming_vpc_cni_source_binding")
    path.write_bytes(source.replace(before, after))


def streaming_quota(sdk):
    gpu = quota_readback(sdk, GPU_QUOTA, 8, families="gv", all_lifecycles=True)
    standard = quota_readback(
        sdk,
        STANDARD_QUOTA_CODE,
        24,
        families="acdhimrtz",
        excluded=("dl", "hpc", "inf", "mac", "trn"),
    )
    return {"gpu": gpu, "standard": standard}


def require_streaming_quota(readback):
    if not readback["gpu"]["fits"] or readback["gpu"]["running_vcpus"]:
        raise ValueError("streaming_gpu_quota_busy")
    if not readback["standard"]["fits"]:
        raise ValueError("streaming_standard_quota_busy")


def verify_gpu_streaming_plan(plan):
    from m5_descriptive_eks import verify_plan

    changes = {
        row["address"]: row["change"]["after"] for row in plan["resource_changes"]
    }
    prefix = "module.eks."
    gpu = changes.get(prefix + "aws_eks_node_group.gpu[0]", {})
    cpu = changes.get(prefix + "aws_eks_node_group.cpu[0]", {})
    for group, count in ((gpu, 2), (cpu, 2)):
        if group.get("scaling_config") != [
            {"min_size": count, "desired_size": count, "max_size": count}
        ]:
            raise ValueError("streaming_node_count")
    agent = changes.get(prefix + 'aws_eks_addon.network["vpc-cni"]', {})
    if json.loads(agent.get("configuration_values") or "{}") != {
        "enableNetworkPolicy": "true"
    }:
        raise ValueError("streaming_vpc_cni_policy")
    return verify_plan(plan)


def verify_gpu_binding(directory, manifest):
    descriptive = manifest["descriptive"]
    streaming = descriptive["streaming"]
    conditions = streaming["conditions"]
    if conditions["image_digest"] != VLLM_IMAGE.split("@")[1]:
        raise ValueError("streaming_engine_digest")
    if (conditions["model"], conditions["revision"]) != (MODEL, REVISION):
        raise ValueError("streaming_model_revision")
    if (
        conditions["source"] != manifest["source_commit"]
        or conditions["schedule_sha256"] != schedule_digest()
        or conditions["limits"]["window_labels"] != list(LEVELS)
        or descriptive.get("cpu_clock_rehearsal")
        or descriptive["timing"] != manifest["timing"]
        or manifest["timing"]
        != seal_timing(
            manifest["timing"], laptop_rate=transfer_rate(streaming["laptop_transfer"])
        )
    ):
        raise ValueError("streaming_plan_binding")
    corpus = streaming["corpus"]
    path = directory / CORPUS_NAME
    if (
        corpus["measured"] != 7350
        or corpus["setup"] != 122
        or corpus["tokenizer_revision"] != REVISION
        or corpus["tokenizer_files"] != FILE_HASHES
        or path.stat().st_size != corpus["bytes"]
        or file_sha(path) != corpus["sha256"]
        or conditions["pins"]["corpus_sha256"] != corpus["sha256"]
    ):
        raise ValueError("streaming_corpus_digest")
    inputs = manifest["host_manifest"]["gate_a_inputs"]
    if inputs["bundle_path"] != "streaming-inputs.tar":
        raise ValueError("streaming_corpus_bundle")
    bundle = directory / inputs["bundle_path"]
    if (
        inputs["inventory"]
        != {CORPUS_NAME: {key: corpus[key] for key in ("bytes", "sha256")}}
        or bundle.stat().st_size != inputs["bundle_bytes"]
        or file_sha(bundle) != inputs["bundle_sha256"]
    ):
        raise ValueError("streaming_corpus_bundle")
    with tarfile.open(bundle, "r:") as archive:
        [member] = list(archive)
        if (
            not member.isfile()
            or member.name != CORPUS_NAME
            or member.size != corpus["bytes"]
        ):
            raise ValueError("streaming_corpus_bundle")
        import hashlib

        with archive.extractfile(member) as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != corpus["sha256"]:
                raise ValueError("streaming_corpus_digest")
    for alternative in manifest["alternatives"]:
        verify_gpu_streaming_plan(
            json.loads(
                (directory / alternative["directory"] / "show.stdout").read_bytes()
            )
        )


def proof_input(packet, destination, commit):
    from m5_descriptive_eks import verify_packet_files

    manifest_path = packet / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    if manifest["source_commit"] != commit or (packet / "consumed.json").exists():
        raise ValueError("streaming_kind_unconsumed_source")
    verify_packet_files(packet, manifest)
    verify_gpu_binding(packet, manifest)
    names = [
        "manifest.json",
        CORPUS_NAME,
        "streaming-inputs.tar",
        *(row["directory"] + "/show.stdout" for row in manifest["alternatives"]),
    ]
    inventory = {
        name: {
            "bytes": (packet / name).stat().st_size,
            "sha256": file_sha(packet / name),
        }
        for name in names
    }
    bundle = destination / "gpu-kind-inputs.tar"
    with tarfile.open(bundle, "x") as tar:
        for name in names:
            tar.add(packet / name, arcname=name, recursive=False)
    return {
        "bundle_path": bundle.name,
        "bundle_bytes": bundle.stat().st_size,
        "bundle_sha256": file_sha(bundle),
        "inventory": inventory,
    }


def provider_inputs(directory, roots):
    if (
        len(roots) != len(set(roots))
        or roots[:2] != ["bootstrap", "backstop"]
        or len(roots) < 3
        or any(not re.fullmatch(r"zone-us-east-1[a-f]", name) for name in roots[2:])
    ):
        raise ValueError("streaming_provider_roots")
    paths = [directory / "cleanup.zip"]
    for folder in (*roots, "eks", "package_a"):
        paths.extend(
            path
            for path in (directory / folder).iterdir()
            if path.is_file()
            and (
                path.suffix in {".tf", ".json", ".sh"}
                or path.name == ".terraform.lock.hcl"
            )
            and not path.name.endswith(".command.json")
        )
    return {
        path.relative_to(directory).as_posix(): {
            "bytes": path.stat().st_size,
            "sha256": file_sha(path),
        }
        for path in sorted(paths)
    }


def provider_proof_input(packet, destination, commit):
    request_path = packet / "provider-request.json"
    request = json.loads(request_path.read_bytes())
    if request["source_commit"] != commit or request["inputs"] != provider_inputs(
        packet, request["roots"]
    ):
        raise ValueError("streaming_provider_request_binding")
    binding = {
        **request["inputs"],
        request_path.name: {
            "bytes": request_path.stat().st_size,
            "sha256": file_sha(request_path),
        },
    }
    bundle = destination / "provider-inputs.tar"
    with tarfile.open(bundle, "x") as tar:
        for name in binding:
            tar.add(packet / name, arcname=name, recursive=False)
    return {
        "bundle_path": bundle.name,
        "bundle_bytes": bundle.stat().st_size,
        "bundle_sha256": file_sha(bundle),
        "inventory": binding,
    }
