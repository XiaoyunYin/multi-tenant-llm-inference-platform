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
import tempfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from inference_platform.package_a_cloud import transfer_seconds
from inference_platform.m5_descriptive_operator import session_timing
from inference_platform.package_a_operator import python_hashes
from m5_descriptive_eks import (
    validate_cleanup_policy,
    validate_cleanup_resource_tags,
    verify_plan,
)

ROOT = Path(__file__).resolve().parents[1]
SCRATCH = Path(
    r"D:\coding agent files\multi-tenant-llm-inference-platform\codex\r373-work"
)
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


def refresh(directory, profile):
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
    session = "m5-desc-r372"
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
    for role, branch in (("gpu", "nvidia"), ("cpu", "standard")):
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
    quota = read(
        "service-quotas", "get_service_quota", ServiceCode="ec2", QuotaCode="L-DB2E81BA"
    )["Quota"]["Value"]
    read(
        "service-quotas", "get_service_quota", ServiceCode="ec2", QuotaCode="L-1216C47A"
    )
    read(
        "ec2",
        "describe_instance_types",
        InstanceTypes=["g6.xlarge", "c6i.2xlarge", "m6i.2xlarge"],
    )
    offerings = read(
        "ec2",
        "describe_instance_type_offerings",
        LocationType="availability-zone",
        Filters=[
            {"Name": "instance-type", "Values": ["g6.xlarge", "c6i.2xlarge"]},
            {"Name": "location", "Values": ["us-east-1c", "us-east-1b"]},
        ],
        MaxResults=100,
    )
    if quota < 8 or not all(
        any(
            row["InstanceType"] == "g6.xlarge" and row["Location"] == zone
            for row in offerings["InstanceTypeOfferings"]
        )
        for zone in ("us-east-1c", "us-east-1b")
    ):
        raise ValueError("descriptive:quota_or_offering")
    read(
        "ec2",
        "describe_instances",
        Filters=[{"Name": "instance-state-name", "Values": ["pending", "running"]}],
        MaxResults=100,
    )
    prices = {}
    for instance in ("g6.xlarge", "c6i.2xlarge", "m6i.2xlarge"):
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
        "gpu_quota_vcpus": quota,
        "lambda_account_limits": lambda_limits,
        "lambda_function_count": lambda_function_count,
        "prices": prices,
        "sources": rows,
    }
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


def forecast(live):
    hourly_rate = (
        2 * live["prices"]["g6.xlarge"]
        + 2 * live["prices"]["c6i.2xlarge"]
        + live["prices"]["m6i.2xlarge"]
        + live["prices"]["eks"]
        + 5 * live["prices"]["ipv4"]
        + 580 * live["prices"]["gp3_gib_month"] / 720
    )
    return hourly_rate, math.ceil((5.5 * hourly_rate + 10) * 1.25 * 100) / 100


def source_bundle(destination, commit):
    """The Git -C working directory must not reinterpret the output path."""
    destination = Path(destination).resolve()
    SCRATCH.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="packet-source-", dir=SCRATCH) as tmp:
        clone = Path(tmp) / "source.git"
        subprocess.run(
            [
                "git",
                "clone",
                "--bare",
                "--no-local",
                "--depth",
                "1",
                "--branch",
                "main",
                ROOT.as_uri(),
                str(clone),
            ],
            check=True,
            capture_output=True,
        )
        observed = (
            subprocess.check_output(["git", "-C", str(clone), "rev-parse", "HEAD"])
            .decode()
            .strip()
        )
        if observed != commit:
            raise ValueError("descriptive:source_moved")
        argv = ["git", "-C", str(clone), "bundle", "create", str(destination), "--all"]
        write(destination.with_suffix(".command.json"), {"argv": argv})
        result = subprocess.run(argv, capture_output=True)
        destination.with_suffix(".stderr").write_bytes(result.stderr)
        result.check_returncode()
    return destination


def prepare(directory, commit, refresh_path, startup_path):
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
    hourly_rate, forecast_usd = forecast(live)
    prior = json.loads(
        (ROOT / "docs/evidence/m5-package-a/spend-ledger.json").read_bytes()
    )["prior_spend_usd"]
    if not directory.resolve().is_relative_to((ROOT / ".cache").resolve()):
        raise ValueError("descriptive:packet_root")
    directory.mkdir(parents=True, exist_ok=False)
    session = "m5-desc-r372"
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

    def plan(root, variables):
        write(root / "input.tfvars.json", variables)
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
            "zip_path": str(cleanup_zip.resolve()),
            "zip_sha256_base64": cleanup_hash,
        },
    )
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
    for first, second in (("us-east-1c", "us-east-1b"), ("us-east-1b", "us-east-1c")):
        target = directory / ("zone-" + first)
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
                "gpu_release": live["releases"]["gpu"],
                "cpu_release": live["releases"]["cpu"],
                "capacity_group_arn": group,
                "quota_vcpus": live["gpu_quota_vcpus"],
                "prior_spend_usd": prior,
                "session_forecast_usd": forecast_usd,
            },
        )
        verify_plan(result)
        validate_cleanup_resource_tags(result, session, json.loads(policy))
        alternatives.append({"zone": first, "directory": target.name})
    write(directory / "plans.json", plans)
    startup = startup_bound(startup_path)
    write(directory / "startup-evidence.json", startup["evidence"])
    timing = session_timing(startup["seconds"])
    bundle = source_bundle(directory / "source.bundle", commit)
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
        "upload_timeout_s": transfer_seconds(bundle.stat().st_size),
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
        "startup_bound": startup,
        "session_seconds": 18000,
        "cleanup_reserve_seconds": 1800,
        "forecast_usd": forecast_usd,
        "forecast_basis": {
            "hourly_usd": hourly_rate,
            "maximum_hours_including_cleanup": 5.5,
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
            "R1 sequential AZ capacity check",
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
    manifest["files"] = {
        p.relative_to(directory).as_posix(): {
            "bytes": p.stat().st_size,
            "sha256": sha(p),
        }
        for p in sorted(directory.rglob("*"))
        if p.is_file() and ".terraform" not in p.parts
    }
    write(directory / "manifest.json", manifest)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    refreshed = sub.add_parser("refresh")
    refreshed.add_argument("--directory", type=Path, required=True)
    refreshed.add_argument("--profile", default="admin-learning")
    prepared = sub.add_parser("prepare")
    prepared.add_argument("--directory", type=Path, required=True)
    prepared.add_argument("--commit", required=True)
    prepared.add_argument("--refresh", type=Path, required=True)
    prepared.add_argument("--startup-evidence", type=Path)
    args = parser.parse_args()
    if args.mode == "refresh":
        value = refresh(args.directory, args.profile)
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
            args.directory, args.commit, args.refresh, args.startup_evidence
        )
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
