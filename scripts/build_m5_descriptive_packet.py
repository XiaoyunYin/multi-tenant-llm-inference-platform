"""Read-only DEC-100 refresh and real-provider exact-plan packet preparation.

Never Apply, reserve capacity, create state, write an approval, or publish.
Private identifiers remain only in the ignored packet; the JSON/Markdown plan
records request provenance and hashes rather than raw account identifiers.
"""

import argparse
import base64
import hashlib
import json
import math
import os
import shutil
import subprocess
import tarfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from inf060_eks_cpu_plan import (
    IMAGE_ARCHIVE,
    NODE_COUNT,
    OPERATOR_TYPE,
    PLAN_DIRECTORY,
    SERVICE_IMAGES,
    SESSION,
    STANDARD_QUOTA_CODE,
    WORKER_TYPE,
    archive_image_bindings,
    canonical_digest,
    check_image_bindings,
    policy_actions,
    verify_cpu_plan,
)
from inf060_eks_gpu_plan import (
    GPU_SESSION,
    provider_inputs,
    require_streaming_quota,
    streaming_quota,
    verify_gpu_binding,
    verify_gpu_streaming_plan,
    write_gpu_streaming_module,
)
from inference_platform.eks_deployment import MODEL, REVISION, VLLM_IMAGE
from inference_platform.inf060_eks_packet import CORPUS_NAME, seal_timing, transfer_rate
from inference_platform.inf060_eks_receipts import schedule_digest
from inference_platform.inf060_eks_schedule import (
    LEVELS,
    SEED,
    TENANTS,
    WINDOW_SECONDS,
    WINDOW_WAIT_SECONDS,
)
from inference_platform.m5_descriptive_operator import session_timing
from inference_platform.package_a_operator import python_hashes
from m5_descriptive_capacity import zone_pairs
from m5_descriptive_eks import (
    validate_cleanup_policy,
    validate_cleanup_resource_tags,
    verify_plan,
)
from m5_descriptive_payload import produce, transfer_bound

ROOT = Path(__file__).resolve().parents[1]
E10_ARCHIVE = (
    "docs/evidence/m5-l4-compatibility-round281/execution-2026-10-26/receipts.tar.gz"
)
E10_SHA256 = "a96b2b654ffd363cc485516b13d1056cb55005e7d83b0b0ea4e21da6a649aaec"


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while chunk := handle.read(1024**2):
            digest.update(chunk)
    return digest.hexdigest()


def write(path, value):
    Path(path).write_text(
        json.dumps(value, indent=2, sort_keys=True, default=str) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def validate_lambda_limits(value, function_count):
    unreserved = value.get("UnreservedConcurrentExecutions")
    if (
        type(unreserved) is not int
        or type(function_count) is not int
        or function_count < 0
    ):
        raise ValueError("descriptive:lambda_cleanup_concurrency_input")
    # Round 373 D2: unreserved pool, no reservation or quota request.
    if unreserved < 2:
        raise ValueError("descriptive:lambda_cleanup_concurrency_unavailable")


def cpu_zones(offerings):
    zones = sorted(
        row["Location"]
        for row in offerings["InstanceTypeOfferings"]
        if row["InstanceType"] == WORKER_TYPE
    )
    if len(set(zones)) < 2:
        raise ValueError("cpu_clock:two_offering_zones_required")
    return [{"zone": zones[0], "control_plane_zone": zones[1]}]


def refresh(directory, profile, *, cpu_clock=False, gpu_streaming=False):
    if cpu_clock and gpu_streaming:
        raise ValueError("streaming_variant_conflict")
    import boto3

    directory.mkdir(parents=True, exist_ok=False)
    sdk = boto3.Session(profile_name=profile, region_name="us-east-1")
    rows = []

    def read(service, method, *, absent_codes=(), **kwargs):
        started = datetime.now(UTC).isoformat()
        try:
            value = getattr(sdk.client(service), method)(**kwargs)
        except Exception as error:
            code = getattr(error, "response", {}).get("Error", {}).get("Code")
            if code not in absent_codes:
                raise
            value = {"absent": True, "error_code": code}
        value.pop("ResponseMetadata", None)
        if value.get("NextToken") or value.get("nextToken"):
            raise ValueError("descriptive:refresh_pagination_required:" + method)
        path = directory / f"{len(rows):02}-{service}-{method}.json"
        write(path, value)
        rows.append(
            {
                "service": service,
                "operation": method,
                "request": kwargs,
                "at_utc": started,
                "response": path.name,
                "sha256": sha(path),
            }
        )
        return value

    identity = read("sts", "get_caller_identity")
    lambda_settings = read("lambda", "get_account_settings")
    lambda_limits = lambda_settings["AccountLimit"]
    lambda_function_count = lambda_settings["AccountUsage"]["FunctionCount"]
    validate_lambda_limits(lambda_limits, lambda_function_count)
    session = GPU_SESSION if gpu_streaming else SESSION if cpu_clock else "m5-desc-r379"
    bucket = (
        session + "-" + hashlib.sha256(identity["Account"].encode()).hexdigest()[:12]
    )
    for service, method, kwargs, absent in (
        ("s3", "head_bucket", {"Bucket": bucket}, ("404", "NoSuchBucket")),
        ("eks", "describe_cluster", {"name": session}, ("ResourceNotFoundException",)),
        (
            "events",
            "describe_rule",
            {"Name": session + "-cleanup"},
            ("ResourceNotFoundException",),
        ),
        (
            "resource-groups",
            "get_group",
            {"GroupName": session + "-capacity"},
            ("NotFoundException",),
        ),
    ):
        if not read(service, method, absent_codes=absent, **kwargs).get("absent"):
            raise ValueError("descriptive:existing_session_resource:" + service)
    releases = {}
    profiles = (
        (("cpu", "standard"),)
        if cpu_clock
        else (("gpu", "nvidia"), ("cpu", "standard"))
    )
    for role, branch in profiles:
        base = f"/aws/service/eks/optimized-ami/1.35/amazon-linux-2023/x86_64/{branch}/recommended/"
        releases[role] = read("ssm", "get_parameter", Name=base + "release_version")[
            "Parameter"
        ]["Value"]
        image = read("ssm", "get_parameter", Name=base + "image_id")["Parameter"][
            "Value"
        ]
        read("ec2", "describe_images", ImageIds=[image])
    operator = read(
        "ssm",
        "get_parameter",
        Name="/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id",
    )["Parameter"]["Value"]
    read("ec2", "describe_images", ImageIds=[operator])
    addons = json.loads((ROOT / "infra/terraform/eks/addon-pins.json").read_bytes())
    for name, pinned in addons["addons"].items():
        value = read(
            "eks",
            "describe_addon_versions",
            addonName=name,
            kubernetesVersion="1.35",
            maxResults=100,
        )
        if not any(
            version["addonVersion"] == pinned
            for row in value["addons"]
            for version in row["addonVersions"]
        ):
            raise ValueError("descriptive:addon_unavailable:" + name)
    if cpu_clock:
        schema = read(
            "eks",
            "describe_addon_configuration",
            addonName="vpc-cni",
            addonVersion=addons["addons"]["vpc-cni"],
        )
        if "enableNetworkPolicy" not in json.loads(schema["configurationSchema"]).get(
            "definitions", {}
        ).get("VpcCni", {}).get("properties", {}):
            raise ValueError("cpu_clock:cni_policy_schema")
    types = (
        (WORKER_TYPE, OPERATOR_TYPE)
        if cpu_clock
        else ("g6.xlarge", WORKER_TYPE, OPERATOR_TYPE)
    )
    quota = read(
        "service-quotas",
        "get_service_quota",
        ServiceCode="ec2",
        QuotaCode=STANDARD_QUOTA_CODE if cpu_clock else "L-DB2E81BA",
    )["Quota"]["Value"]
    if not cpu_clock:
        read(
            "service-quotas",
            "get_service_quota",
            ServiceCode="ec2",
            QuotaCode="L-1216C47A",
        )
    read(
        "ec2",
        "describe_instance_types",
        InstanceTypes=list(types),
    )
    offerings = read(
        "ec2",
        "describe_instance_type_offerings",
        LocationType="availability-zone",
        Filters=[
            {
                "Name": "instance-type",
                "Values": [WORKER_TYPE] if cpu_clock else ["g6.xlarge", WORKER_TYPE],
            },
        ],
        MaxResults=100,
    )
    zones = cpu_zones(offerings) if cpu_clock else zone_pairs(offerings)
    if quota < (32 if cpu_clock else 8):
        raise ValueError("descriptive:quota_or_offering")
    read(
        "ec2",
        "describe_instances",
        Filters=[{"Name": "instance-state-name", "Values": ["pending", "running"]}],
        MaxResults=100,
    )
    prices = {}
    for instance in types:
        filters = {
            "regionCode": "us-east-1",
            "instanceType": instance,
            "operatingSystem": "Linux",
            "tenancy": "Shared",
            "preInstalledSw": "NA",
            "capacitystatus": "Used",
        }
        value = read(
            "pricing",
            "get_products",
            ServiceCode="AmazonEC2",
            Filters=[
                {"Type": "TERM_MATCH", "Field": k, "Value": v}
                for k, v in filters.items()
            ],
            MaxResults=100,
        )
        prices[instance] = hourly(value, instance)
    eks_prices = read(
        "pricing",
        "get_products",
        ServiceCode="AmazonEKS",
        Filters=[
            {"Type": "TERM_MATCH", "Field": "regionCode", "Value": "us-east-1"},
            # The regional catalog also contains hundreds of Auto Mode SKUs.
            # Select the standard control-plane operation before pagination.
            {"Type": "TERM_MATCH", "Field": "operation", "Value": "CreateOperation"},
        ],
        MaxResults=100,
    )
    prices["eks"] = hourly(eks_prices, "eks", usage="perCluster")
    ipv4 = read(
        "pricing",
        "get_products",
        ServiceCode="AmazonVPC",
        Filters=[
            {"Type": "TERM_MATCH", "Field": "regionCode", "Value": "us-east-1"},
            {
                "Type": "TERM_MATCH",
                "Field": "usagetype",
                "Value": "USE1-PublicIPv4:InUseAddress",
            },
        ],
        MaxResults=100,
    )
    prices["ipv4"] = hourly(ipv4, "ipv4")
    storage = read(
        "pricing",
        "get_products",
        ServiceCode="AmazonEC2",
        Filters=[
            {"Type": "TERM_MATCH", "Field": "regionCode", "Value": "us-east-1"},
            {"Type": "TERM_MATCH", "Field": "volumeApiName", "Value": "gp3"},
        ],
        MaxResults=100,
    )
    prices["gp3_gib_month"] = unit_rate(storage, "gp3", {"GB-Mo", "GB-Month"})
    value = {
        "schema": "m5-descriptive-live-inputs.v1",
        "at_utc": datetime.now(UTC).isoformat(),
        "account": identity["Account"],
        "caller_arn": identity["Arn"],
        "releases": releases,
        "operator_ami": operator,
        ("standard_quota_vcpus" if cpu_clock else "gpu_quota_vcpus"): quota,
        "zone_pairs": zones,
        "lambda_account_limits": lambda_limits,
        "lambda_function_count": lambda_function_count,
        "prices": prices,
        "sources": rows,
    }
    if gpu_streaming:
        value["streaming_quota"] = streaming_quota(sdk)
        require_streaming_quota(value["streaming_quota"])
    write(directory / "refresh.json", value)
    return value


def hourly(value, name, usage=None):
    return unit_rate(value, name, {"Hrs", "Hours", "hours", "hour"}, usage=usage)


def unit_rate(value, name, units, usage=None):
    rates = set()
    for raw in value["PriceList"]:
        product = json.loads(raw)
        if usage and usage not in product["product"]["attributes"].get("usagetype", ""):
            continue
        for term in product.get("terms", {}).get("OnDemand", {}).values():
            for dimension in term["priceDimensions"].values():
                price = float(dimension["pricePerUnit"]["USD"])
                if dimension["unit"] in units and price > 0:
                    rates.add(price)
    if len(rates) != 1:
        raise ValueError(
            "descriptive:price_ambiguous:" + name + ":" + str(sorted(rates))
        )
    return rates.pop()


def e10_startup_evidence():
    archive = ROOT / E10_ARCHIVE
    if sha(archive) != E10_SHA256:
        raise ValueError("descriptive:e10_startup_archive_hash")
    member = "results/runtime/lifecycle.jsonl"
    log = "results/l4-engine.log"
    with tarfile.open(archive) as source:
        raw = source.extractfile(member).read()
        log_hash = hashlib.sha256(source.extractfile(log).read()).hexdigest()
    events = [json.loads(line) for line in raw.splitlines()]
    starts = [row for row in events if row.get("event") == "process_start"]
    ready = [row for row in events if row.get("event") == "startup"]
    if len(starts) != 1 or len(ready) != 1:
        raise ValueError("descriptive:e10_startup_events")
    start, end = starts[0], ready[0]
    if (
        start["boot_id"] != end["boot_id"]
        or start["pod_uid"] != end["pod_uid"]
        or start["restart_count"] != end["restart_count"]
        or end["mono_ns"] <= start["mono_ns"]
    ):
        raise ValueError("descriptive:e10_startup_lineage")
    return {
        "authority": "Claude Round 373 D1",
        "source": E10_ARCHIVE,
        "source_sha256": E10_SHA256,
        "source_member": member,
        "source_member_sha256": hashlib.sha256(raw).hexdigest(),
        "corroborating_member": log,
        "corroborating_member_sha256": log_hash,
        "process_start_wall_ns": start["wall_ns"],
        "startup_wall_ns": end["wall_ns"],
        "process_start_mono_ns": start["mono_ns"],
        "startup_mono_ns": end["mono_ns"],
        "engine_start_seconds": [(end["mono_ns"] - start["mono_ns"]) / 1e9],
        "scope": "cold g6.xlarge, pinned vLLM 0.29.0 image and R1 model revision; E10, not aggregate R1 Ready",
    }


def startup_bound(path):
    expected = e10_startup_evidence()
    value = json.loads(Path(path).read_bytes()) if path is not None else expected
    if value != expected:
        raise ValueError("descriptive:e10_startup_evidence")
    durations = value["engine_start_seconds"]
    return {
        "seconds": max(300, math.ceil(max(durations) * 2 + 60)),
        "rule": "max(300, ceil(2 * largest recorded engine start + 60))",
        "evidence": value,
        "evidence_sha256": hashlib.sha256(
            json.dumps(value, sort_keys=True).encode()
        ).hexdigest(),
    }


def forecast(live, *, cpu_clock=False):
    hourly_rate = (
        (0 if cpu_clock else 2 * live["prices"]["g6.xlarge"])
        + (NODE_COUNT if cpu_clock else 2) * live["prices"][WORKER_TYPE]
        + live["prices"][OPERATOR_TYPE]
        + live["prices"]["eks"]
        + (NODE_COUNT + 1 if cpu_clock else 5) * live["prices"]["ipv4"]
        + (100 + NODE_COUNT * 40 if cpu_clock else 580)
        * live["prices"]["gp3_gib_month"]
        / 720
    )
    return hourly_rate, math.ceil((5.5 * hourly_rate + 10) * 1.25 * 100) / 100


def source_bundle(destination, commit):
    destination = Path(destination).resolve()
    binding = produce(ROOT, commit, destination)
    write(destination.with_suffix(".payload.json"), binding)
    return destination


def prepare(
    directory,
    commit,
    refresh_path,
    startup_path,
    *,
    cpu_images=None,
    streaming_inputs=None,
    provider_preview=False,
    provider_results=None,
):
    directory = directory.resolve()
    current = (
        subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT).decode().strip()
    )
    if current != commit or subprocess.check_output(
        ["git", "status", "--porcelain", "--", "python", "scripts", "infra", "deploy"],
        cwd=ROOT,
    ):
        raise ValueError("descriptive:committed_clean_code_required")
    live = json.loads(refresh_path.read_bytes())
    validate_lambda_limits(
        live.get("lambda_account_limits", {}), live.get("lambda_function_count")
    )
    offering_source = next(
        r
        for r in live["sources"]
        if r["operation"] == "describe_instance_type_offerings"
    )
    cpu_clock = cpu_images is not None
    gpu_streaming = streaming_inputs is not None
    if cpu_clock and gpu_streaming:
        raise ValueError("streaming_variant_conflict")
    if (provider_preview or provider_results) and not gpu_streaming:
        raise ValueError("streaming_provider_variant")
    if provider_preview and provider_results:
        raise ValueError("streaming_provider_mode")
    if gpu_streaming:
        require_streaming_quota(live["streaming_quota"])
    expected_quota = "standard_quota_vcpus" if cpu_clock else "gpu_quota_vcpus"
    offering = json.loads(
        (refresh_path.parent / offering_source["response"]).read_bytes()
    )
    zones = cpu_zones(offering) if cpu_clock else zone_pairs(offering)
    if zones != live["zone_pairs"]:
        raise ValueError("descriptive:live_zone_set_changed")
    hourly_rate, forecast_usd = forecast(live, cpu_clock=cpu_clock)
    descriptive_ledger = ROOT / "docs/evidence/m5-descriptive-eks/spend-ledger.json"
    prior = (
        json.loads(descriptive_ledger.read_bytes())["cumulative_product_estimate_usd"]
        if descriptive_ledger.exists()
        else json.loads(
            (ROOT / "docs/evidence/m5-package-a/spend-ledger.json").read_bytes()
        )["prior_spend_usd"]
    )
    if not directory.resolve().is_relative_to((ROOT / ".cache").resolve()):
        raise ValueError("descriptive:packet_root")
    directory.mkdir(parents=True, exist_ok=False)
    bundle = source_bundle(directory / "source.bundle", commit)
    upload_bound = transfer_bound(bundle.stat().st_size)
    session = GPU_SESSION if gpu_streaming else SESSION if cpu_clock else "m5-desc-r379"
    bucket = session + "-" + hashlib.sha256(live["account"].encode()).hexdigest()[:12]
    group = (
        f"arn:aws:resource-groups:us-east-1:{live['account']}:group/{session}-capacity"
    )
    terraform = ROOT / ".tools/terraform/1.16.2/terraform.exe"
    cli = Path(shutil.which("aws"))
    plugin = ROOT / ".cache/session-manager-plugin/bin/bin/session-manager-plugin.exe"
    tools = {
        key: {"path": str(path), "sha256": sha(path)}
        for key, path in (("terraform", terraform), ("aws", cli), ("plugin", plugin))
    }
    for name, source in (
        ("package_a", "package_a"),
        ("eks", "eks"),
        ("bootstrap", "eks/bootstrap"),
        ("backstop", "m5_descriptive_backstop"),
    ):
        target = directory / name
        target.mkdir()
        for path in (ROOT / "infra/terraform" / source).iterdir():
            if path.is_file() and (
                path.suffix in {".tf", ".json", ".sh"}
                or path.name == ".terraform.lock.hcl"
            ):
                shutil.copyfile(path, target / path.name)
        if not (target / ".terraform.lock.hcl").exists():
            shutil.copyfile(
                ROOT / "infra/terraform/eks/.terraform.lock.hcl",
                target / ".terraform.lock.hcl",
            )
    if gpu_streaming:
        write_gpu_streaming_module(directory / "eks" / "main.tf")
    cleanup_zip = directory / "cleanup.zip"
    with zipfile.ZipFile(cleanup_zip, "w", zipfile.ZIP_DEFLATED) as archive:
        item = zipfile.ZipInfo("m5_descriptive_cleanup.py", (2026, 1, 1, 0, 0, 0))
        archive.writestr(
            item, (ROOT / "scripts/m5_descriptive_cleanup.py").read_bytes()
        )
    cleanup_hash = base64.b64encode(bytes.fromhex(sha(cleanup_zip))).decode()
    (directory / "live-inputs").mkdir()
    shutil.copyfile(refresh_path, directory / "live-inputs/refresh.json")
    for row in live["sources"]:
        source = (refresh_path.parent / row["response"]).resolve()
        if (
            not source.is_relative_to(refresh_path.parent.resolve())
            or source.name != row["response"]
            or sha(source) != row["sha256"]
        ):
            raise ValueError("descriptive:live_input_changed")
        shutil.copyfile(source, directory / "live-inputs" / source.name)
    plans = []
    requested = []
    delegated = (
        json.loads((provider_results / "provider-plans.json").read_bytes())
        if provider_results
        else None
    )

    def plan(root, variables):
        write(root / "input.tfvars.json", variables)
        requested.append(root.name)
        if provider_preview:
            return None
        env = {
            **os.environ,
            "AWS_PROFILE": "admin-learning",
            "TF_PLUGIN_CACHE_DIR": str(ROOT / ".cache/terraform-plugins"),
        }
        for stage, argv in (
            ("init", ["init", "-backend=false", "-input=false", "-lockfile=readonly"]),
            (
                "plan",
                [
                    "plan",
                    "-input=false",
                    "-refresh=false",
                    "-var-file=input.tfvars.json",
                    "-out=create.tfplan",
                ],
            ),
            ("show", ["show", "-json", "create.tfplan"]),
        ):
            if delegated and stage in {"plan", "show"}:
                continue
            write(
                root / (stage + ".command.json"),
                {"argv": [str(terraform), "-chdir=" + str(root), *argv]},
            )
            with (
                (root / (stage + ".stdout")).open("wb") as out,
                (root / (stage + ".stderr")).open("wb") as err,
            ):
                subprocess.run(
                    [str(terraform), "-chdir=" + str(root), *argv],
                    check=True,
                    stdout=out,
                    stderr=err,
                    env=env,
                    timeout=900,
                )
        if delegated:
            binding = delegated["plans"][root.name]
            for file in ("create.tfplan", "show.stdout"):
                source = provider_results / root.name / file
                if sha(source) != binding[file]:
                    raise ValueError("streaming_provider_result_digest")
                shutil.copyfile(source, root / file)
        result = json.loads((root / "show.stdout").read_bytes())
        plans.append(
            {
                "directory": root.name,
                "sha256": sha(root / "create.tfplan"),
                "json_sha256": sha(root / "show.stdout"),
                "resources": [
                    {"address": r["address"], "actions": r["change"]["actions"]}
                    for r in result["resource_changes"]
                ],
            }
        )
        return result

    plan(
        directory / "bootstrap",
        {
            "enable_bootstrap": True,
            "offline_validation": False,
            "name": session,
            "state_bucket": bucket,
        },
    )
    backstop = plan(
        directory / "backstop",
        {
            "session": session,
            "account": live["account"],
            "state_bucket": bucket,
            "zip_path": "../cleanup.zip"
            if gpu_streaming
            else str(cleanup_zip.resolve()),
            "zip_sha256_base64": cleanup_hash,
        },
    )
    if not provider_preview:
        policy = next(
            r["change"]["after"]["policy"]
            for r in backstop["resource_changes"]
            if r["type"] == "aws_iam_role_policy"
        )
        validate_cleanup_policy(json.loads(policy), session)
        policy_hash = hashlib.sha256(
            json.dumps(json.loads(policy), sort_keys=True).encode()
        ).hexdigest()
    alternatives = []
    for pair in zones:
        first, second = pair["zone"], pair["control_plane_zone"]
        target = directory / (PLAN_DIRECTORY if cpu_clock else "zone-" + first)
        shutil.copytree(
            ROOT / "infra/terraform/m5_descriptive",
            target,
            ignore=shutil.ignore_patterns(".terraform", "*.tfstate*"),
        )
        result = plan(
            target,
            {
                "session": session,
                "source_commit": commit,
                "operator_ami": live["operator_ami"],
                "zones": [first, second],
                "gpu_release": live["releases"].get("gpu", ""),
                "cpu_release": live["releases"]["cpu"],
                "capacity_group_arn": group,
                "quota_vcpus": live[expected_quota],
                "prior_spend_usd": prior,
                "session_forecast_usd": forecast_usd,
                **(
                    {"cpu_clock_rehearsal": True, "cpu_clock_account": live["account"]}
                    if cpu_clock
                    else {}
                ),
            },
        )
        if not provider_preview:
            operator_policy = (
                verify_cpu_plan(result) if cpu_clock else verify_plan(result)
            )
            if gpu_streaming:
                verify_gpu_streaming_plan(result)
            validate_cleanup_resource_tags(result, session, json.loads(policy))
        alternatives.append({**pair, "directory": target.name})
    if provider_preview or delegated:
        request = {
            "source_commit": commit,
            "roots": requested,
            "inputs": provider_inputs(directory, requested),
        }
        write(directory / "provider-request.json", request)
        if provider_preview:
            return request
        if delegated["request"] != request or delegated["applied"] is not False:
            raise ValueError("streaming_provider_request_binding")
        if set(delegated["plans"]) != set(requested):
            raise ValueError("streaming_provider_plan_set")
        write(directory / "provider-plans.json", delegated)
    write(directory / "plans.json", plans)
    startup = (
        {
            "seconds": 180,
            "evidence": {"basis": "pinned CPU kind readiness bound, no GPU staging"},
        }
        if cpu_clock
        else startup_bound(startup_path)
    )
    write(directory / "startup-evidence.json", startup["evidence"])
    if cpu_clock:
        inputs, images = cpu_image_input(
            directory, cpu_images, commit, live["operator_ami"]
        )
        upload_bound += transfer_bound(inputs["bundle_bytes"])
    if gpu_streaming:
        inputs, corpus, laptop_transfer = streaming_input(
            directory, streaming_inputs, commit
        )
        upload_bound += transfer_bound(inputs["bundle_bytes"])
    timing = session_timing(startup["seconds"], upload_bound)
    if gpu_streaming:
        timing = seal_timing(timing, laptop_rate=transfer_rate(laptop_transfer))
    if cpu_clock:
        workload = 3 * WINDOW_WAIT_SECONDS + 956
        available = (
            timing["infrastructure_before_capacity_wait_seconds"]
            + timing["minimum_workload_seconds"]
            - workload
        )
        timing.update(
            minimum_workload_seconds=workload,
            infrastructure_before_capacity_wait_seconds=available,
            remaining_infrastructure_seconds=available,
            capacity_wait_budget_seconds=0,
        )
    if (
        timing["remaining_infrastructure_seconds"]
        < timing["apply_through_staging_reserve_seconds"]
    ):
        raise ValueError("descriptive:payload_exceeds_session_budget")
    pins = json.loads((ROOT / "deploy/package-a/pins.json").read_bytes())
    # Root gp3 / IPv4 rates are the accepted Package A basis. The EKS/EC2 rates
    # above come from live products; $10 covers ECR/logs/cleanup/network variance.
    host = {
        "schema": "m5-descriptive-host.v1",
        "role": "descriptive_operator",
        "workload": "m5-descriptive",
        "session": "dec077-" + session,
        "region": "us-east-1",
        "source_commit": commit,
        "pins": pins,
        "python_sha256": python_hashes(commit),
        "bundle_sha256": sha(bundle),
        "bundle_bytes": bundle.stat().st_size,
        "upload_timeout_s": upload_bound,
        "source_payload": json.loads(bundle.with_suffix(".payload.json").read_bytes()),
        "python_executable": "/opt/dec077/repo/python/.venv/bin/python",
        "operator_tools": tools,
        "session_manager_plugin_path": str(plugin.relative_to(ROOT)),
        "instance_type": "m6i.2xlarge",
        "ami": live["operator_ami"],
        "on_demand_usd_per_hour": live["prices"]["m6i.2xlarge"],
        "hourly_all_resources_usd": hourly_rate,
        "hard_cap_usd": math.ceil(prior + forecast_usd + 10),
        "prior_spend_usd": prior,
        "cleanup_cost_reserve_usd": 10,
    }
    manifest = {
        "schema": "m5-descriptive-exact-plan.v1",
        "source_commit": commit,
        "session": session,
        "account": live["account"],
        "state_bucket": bucket,
        "capacity_group_arn": group,
        "operator_tools": tools,
        "cleanup_zip_sha256_base64": cleanup_hash,
        "cleanup_policy_sha256": policy_hash,
        "lambda_concurrency": {
            "reserved": False,
            "minimum_unreserved": 2,
            "observed_limits": live["lambda_account_limits"],
            "observed_function_count": live["lambda_function_count"],
            "required_witness": "synchronous RequestResponse armed:true at original deadline before GPU capacity",
        },
        "plans": plans,
        "alternatives": alternatives,
        "host_manifest": host,
        "descriptive": {
            "session": session,
            "source_commit": commit,
            "startup_seconds": startup["seconds"],
            "timing": timing,
        },
        "timing": timing,
        "capacity_wait_basis": {
            "source": "docs/evidence/m5-descriptive-eks-r376/execution-receipt.sanitized.json",
            "observed_provision_s": 1581.078,
            "apply_staging_rule": "ceil(2 * observed_provision_s + 60)",
            "wait_rule": "max(0, infrastructure_before_capacity_wait_seconds - apply_through_staging_reserve_seconds)",
            "bootstrap_and_arming_cannot_extend_wait": True,
        },
        "startup_bound": startup,
        "session_seconds": 18000,
        "cleanup_reserve_seconds": 1800,
        "forecast_usd": forecast_usd,
        "payload_transfer": {
            "bytes": bundle.stat().st_size,
            "bound_s": upload_bound,
            "minimum_bytes_per_s": 100000,
            "passes": 2,
            "overhead_s": 60,
        },
        "forecast_basis": {
            "hourly_usd": hourly_rate,
            "maximum_hours_including_cleanup": 5.5,
            "source_upload_seconds_inside_session": upload_bound,
            "capacity_wait_seconds_inside_session": timing[
                "capacity_wait_budget_seconds"
            ],
            "fixed_other_usd": 10,
            "margin": 1.25,
        },
        "live_inputs_sha256": sha(refresh_path),
        "applied": False,
        "marker": False,
        "sequence": [
            "immutable original deadline",
            "bootstrap (state bucket and capacity group)",
            "backstop Apply and deployed witness",
            "bounded cycling R1 AZ capacity check; cancel/verify each failure; >=60 s between cycles",
            "one selected saved composed Apply",
            "Package A bootstrap/upload",
            "shared provision/smoke/load/gateway rollout/replica rollout/export/retrieve",
            "destroy main and verify GPU termination",
            "cancel reservations",
            "empty bucket and destroy bootstrap",
            "validate product inventories",
            "destroy backstop",
            "final inventory",
        ],
        "receipts": [
            "consumed",
            "arming-witness",
            "capacity readbacks",
            "capacity-wait.json with every probe and separate elapsed time",
            "host runner",
            "client placement and image digest",
            "client JSONL and hashes",
            "rollout Ready/client serving/health",
            "Prometheus/events",
            "frozen retrieval",
            "service inventories",
            "cost and spend ledger",
        ],
        "files": {},
    }
    if gpu_streaming:
        host["gate_a_inputs"] = inputs
        manifest["descriptive"]["gpu_streaming"] = True
        manifest["descriptive"]["streaming"] = {
            "laptop_transfer": laptop_transfer,
            "corpus": corpus,
            "gpu_hourly_usd": 2 * live["prices"]["g6.xlarge"],
            "conditions": {
                "source": commit,
                "artifact_path": "inf060-gpu-eks-streaming",
                "model": MODEL,
                "revision": REVISION,
                "engine_version": "0.29.0",
                "image_digest": VLLM_IMAGE.split("@")[1],
                "engine_flags": ["--enable-log-requests", "--max-log-len", "0"],
                "gpu_type": "g6.xlarge/L4",
                "gpu_count": 2,
                "capacity_type": "on-demand",
                "zone": None,
                "policy": "round_robin",
                "tenants": list(TENANTS),
                "seed": SEED,
                "run_count": 1,
                "schedule_sha256": schedule_digest(),
                "pins": {
                    **SERVICE_IMAGES,
                    "corpus_sha256": corpus["sha256"],
                    "logging_sha256": sha(ROOT / "deploy/inf060/vllm-logging.json"),
                    "tokenizer_files": corpus["tokenizer_files"],
                },
                "limits": {
                    "window_seconds": WINDOW_SECONDS,
                    "window_labels": list(LEVELS),
                },
            },
        }
        manifest["payload_transfer"]["bytes"] += inputs["bundle_bytes"]
        manifest["sequence"][6:7] = [
            "policy and corpus readbacks; cold and resumed operator-to-pod transfer gate",
            "smoke, warm-up and four guarded windows; freeze and verify each checkpoint and final",
        ]
    if cpu_clock:
        host["gate_a_inputs"] = inputs
        manifest["descriptive"]["cpu_clock_rehearsal"] = {
            "selection": alternatives[0],
            "images": images,
            "service_images": SERVICE_IMAGES,
            "operator_policy_sha256": canonical_digest(operator_policy),
            "operator_actions_sha256": canonical_digest(
                policy_actions(operator_policy)
            ),
            "backstop_actions_sha256": canonical_digest(
                policy_actions(json.loads(policy))
            ),
        }
        manifest["descriptive"]["streaming"] = {
            "gpu_hourly_usd": 0,
            "conditions": {
                "source": commit,
                "artifact_path": "inf060-cpu-eks-clock-rehearsal",
                "model": "cpu-sse-mock",
                "revision": sha(ROOT / "scripts/inf060_kind_engine.py"),
                "engine_version": "cpu-mock",
                "image_digest": images["client"]["manifest_digest"],
                "engine_flags": ["epoch-frontend-abort-fixture"],
                "gpu_type": None,
                "gpu_count": 0,
                "capacity_type": "on-demand-cpu",
                "zone": [
                    alternatives[0]["zone"],
                    alternatives[0]["control_plane_zone"],
                ],
                "policy": "round_robin",
                "tenants": list(TENANTS),
                "seed": SEED,
                "run_count": 1,
                "schedule_sha256": schedule_digest(),
                "pins": {"images": images, **SERVICE_IMAGES},
                "limits": {"window_seconds": WINDOW_SECONDS, "window_labels": ["8"]},
            },
        }
        manifest["payload_transfer"]["bytes"] += inputs["bundle_bytes"]
        manifest["sequence"] = [
            "verify exact committed CPU review, all bindings and live standard vCPU headroom; consume once",
            "arm original deadline; apply saved bootstrap and cleanup backstop; verify witness",
            "recheck and record live standard vCPU headroom; apply one saved CPU-only composed plan without capacity reservation",
            "bootstrap; stage bound source and images; confirm role, CNI and cross-node policy",
            "measure idle and exec fallback; run smoke, warmup and a single 600 s 8 req/s window",
            "verify peak and whole-window clocks; freeze, retrieve and independently recount",
            "destroy main and bootstrap; verify zero while independent backstop is armed",
            "destroy backstop and verify final inventory",
        ]
    manifest["files"] = {
        p.relative_to(directory).as_posix(): {
            "bytes": p.stat().st_size,
            "sha256": sha(p),
        }
        for p in sorted(directory.rglob("*"))
        if p.is_file() and ".terraform" not in p.parts
    }
    if cpu_clock:
        from inf060_eks_cpu_plan import verify_cpu_binding

        verify_cpu_binding(directory, manifest)
    if gpu_streaming:
        verify_gpu_binding(directory, manifest)
    write(directory / "manifest.json", manifest)
    return manifest


def streaming_input(directory, producer, commit):
    corpus = json.loads((producer / "streaming-corpus.json").read_bytes())
    transfer = json.loads((producer / "inf060-ssm-transfer.json").read_bytes())
    if corpus["source"] != transfer["source"]:
        raise ValueError("streaming_input_source")
    subprocess.run(
        [
            "git",
            "diff",
            "--exit-code",
            corpus["source"],
            commit,
            "--",
            "python/src/inference_platform/inf060_eks_packet.py",
            "python/src/inference_platform/inf060_eks_schedule.py",
            "python/src/inference_platform/stage_c_tokenizer.py",
            "python/src/inference_platform/stage_c_prompts.py",
            "python/uv.lock",
        ],
        cwd=ROOT,
        check=True,
    )
    source = producer / CORPUS_NAME
    facts = {"bytes": source.stat().st_size, "sha256": sha(source)}
    if any(corpus[key] != value for key, value in facts.items()):
        raise ValueError("streaming_corpus_digest")
    shutil.copyfile(source, directory / CORPUS_NAME)
    write(
        directory / "streaming-input-receipt.json",
        {"corpus": corpus, "transfer": transfer},
    )
    bundle = directory / "streaming-inputs.tar"
    with tarfile.open(bundle, "x") as output, source.open("rb") as stream:
        member = tarfile.TarInfo(CORPUS_NAME)
        member.size = facts["bytes"]
        output.addfile(member, stream)
    return (
        {
            "bundle_path": bundle.name,
            "bundle_sha256": sha(bundle),
            "bundle_bytes": bundle.stat().st_size,
            "inventory": {CORPUS_NAME: facts},
        },
        corpus,
        transfer,
    )


def cpu_image_input(directory, images, commit, operator_ami):
    receipt = json.loads((images / "images.json").read_bytes())
    archive = images / IMAGE_ARCHIVE
    facts = {"bytes": archive.stat().st_size, "sha256": sha(archive)}
    if (
        receipt["source"] != commit
        or receipt["archive"] != facts
        or receipt["operator_ami"] != operator_ami
    ):
        raise ValueError("cpu_clock:image_producer_binding")
    check_image_bindings(archive_image_bindings(archive), receipt["images"])
    write(directory / "cpu-image-producer.json", receipt)
    bundle = directory / "cpu-images.tar"
    with tarfile.open(bundle, "x") as output:
        member = tarfile.TarInfo(IMAGE_ARCHIVE)
        member.size = facts["bytes"]
        with archive.open("rb") as stream:
            output.addfile(member, stream)
    return {
        "bundle_path": bundle.name,
        "bundle_sha256": sha(bundle),
        "bundle_bytes": bundle.stat().st_size,
        "inventory": {IMAGE_ARCHIVE: facts},
    }, receipt["images"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    refreshed = sub.add_parser("refresh")
    refreshed.add_argument("--directory", type=Path, required=True)
    refreshed.add_argument("--profile", default="admin-learning")
    refreshed.add_argument("--cpu-clock", action="store_true")
    refreshed.add_argument("--gpu-streaming", action="store_true")
    prepared = sub.add_parser("prepare")
    prepared.add_argument("--directory", type=Path, required=True)
    prepared.add_argument("--commit", required=True)
    prepared.add_argument("--refresh", type=Path, required=True)
    prepared.add_argument("--startup-evidence", type=Path)
    prepared.add_argument("--cpu-images", type=Path)
    prepared.add_argument("--streaming-inputs", type=Path)
    prepared.add_argument("--provider-preview", action="store_true")
    prepared.add_argument("--provider-results", type=Path)
    args = parser.parse_args()
    if args.mode == "refresh":
        value = refresh(
            args.directory,
            args.profile,
            cpu_clock=args.cpu_clock,
            gpu_streaming=args.gpu_streaming,
        )
        print(
            json.dumps(
                {
                    "complete": True,
                    "requests": len(value["sources"]),
                    "at_utc": value["at_utc"],
                }
            )
        )
    else:
        value = prepare(
            args.directory,
            args.commit,
            args.refresh,
            args.startup_evidence,
            cpu_images=args.cpu_images,
            streaming_inputs=args.streaming_inputs,
            provider_preview=args.provider_preview,
            provider_results=args.provider_results,
        )
        if args.provider_preview:
            print(
                json.dumps(
                    {
                        "complete": True,
                        "planned_roots": value["roots"],
                        "applied": False,
                    }
                )
            )
            return
        print(
            json.dumps(
                {
                    "complete": True,
                    "manifest_sha256": sha(args.directory / "manifest.json"),
                    "plans": len(value["plans"]),
                    "applied": False,
                }
            )
        )


if __name__ == "__main__":
    main()
