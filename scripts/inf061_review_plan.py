"""Save provider plans on a routine CPU host and finish read-only IAM sealing."""

import argparse
import hashlib
import json
import os
import subprocess
import tarfile
from pathlib import Path

import inf060_operator_packet as operator
import inf060_diagnostics as diagnostics
import inf060_probe_spec as spec
import inf061_packet as benchmark
from inf060_policy_gate import seal
from prepare_inf060_probe import ROOT, git, prepare

LIVE = ROOT / "docs/INF061_R455_LIVE_INPUTS.json"


def price_query(service, filters):
    return [
        "pricing",
        "get-products",
        "--service-code",
        service,
        "--filters",
        json.dumps(
            [
                {"Type": "TERM_MATCH", "Field": key, "Value": value}
                for key, value in filters.items()
            ]
        ),
    ]


def inputs(work):
    live = spec.load(LIVE)
    plan = spec.load(ROOT / "docs/INF061_FINAL_PLAN.json")
    zone = live["zone"]
    images = {row["shape"]: row for row in live["images"]}
    gpu, cpu = images[spec.SHAPE], images[operator.SHAPE]
    common = {"regionCode": live["region"]}
    current = {
        "session": plan["session"],
        "zone": zone,
        "region": live["region"],
        "ami": [
            {
                "ImageId": gpu["ami"],
                "State": gpu["state"],
                "Architecture": gpu["architecture"],
            }
        ],
        "shape": {"type": spec.SHAPE, "vcpus": 4, "gpu": [{"Name": "L4", "Count": 1}]},
        "quota_vcpus": live["gpu_vcpu_quota"],
        "offerings": [
            {"Location": zone, "InstanceType": t, "LocationType": "availability-zone"}
            for t in live["offered"]
        ],
        "zone_states": [{"ZoneName": zone, "State": live["zone_state"]}],
        "account_nonterminated_instances": live["nonterminated_instances"],
        "owned_capacity_reservations": live["active_pending_capacity_reservations"],
        "session_route_tables": live["session_route_tables"],
        "rates": {
            "compute_usd_per_h": live["gpu_compute"],
            "operator_compute_usd_per_h": live["cpu_compute"],
            "gp3_usd_per_gib_month": live["gp3"],
            "ipv4_usd_per_h": live["ipv4"],
        },
        "queries": {
            "compute": price_query(
                "AmazonEC2",
                {
                    **common,
                    "instanceType": spec.SHAPE,
                    "operatingSystem": "Linux",
                    "tenancy": "Shared",
                    "preInstalledSw": "NA",
                    "capacitystatus": "Used",
                    "licenseModel": "No License required",
                },
            ),
            "gp3": price_query("AmazonEC2", {**common, "volumeApiName": "gp3"}),
            "ipv4": price_query(
                "AmazonVPC", {**common, "usagetype": "USE1-PublicIPv4:InUseAddress"}
            ),
        },
        "receipt_sha256": spec.facts(LIVE)["sha256"],
    }
    spec.check(
        zone == plan["zone"] and live["operator_zone"] == spec.ZONE,
        "benchmark_zone_binding",
    )
    cpu_inputs = {
        "ami": cpu["ami"],
        "ami_available": cpu["state"],
        "quotavcpus": live["standard_vcpu_quota"],
        "shape": operator.SHAPE,
        "route_count": live["session_route_tables"],
        "offerings": [
            {
                "Location": spec.ZONE,
                "InstanceType": t,
                "LocationType": "availability-zone",
            }
            for t in live["operator_offered"]
        ],
        "rate": live["cpu_compute"],
        "session": "dec077-op-inf061-r455",
    }
    path, op_path = work / "live.json", work / "operator.json"
    spec.save(path, current)
    spec.save(op_path, cpu_inputs)
    return path, op_path


def aws(profile, service, action, argv):
    return json.loads(
        subprocess.check_output(
            [
                "aws",
                "--profile",
                profile,
                "--region",
                spec.REGION,
                service,
                action,
                *argv,
                "--output",
                "json",
                "--no-cli-pager",
            ],
            timeout=60,
        )
    )


def review_plans(work, output):
    if os.name != "posix":
        raise ValueError("inf061:use_routine_cpu_for_provider_plans")
    work.mkdir()
    src = git("rev-parse", "HEAD").decode().strip()
    path = ROOT / ".cache/inf061-native-review"
    live, op = inputs(work)
    (ROOT / ".cache/terraform-plugins").mkdir(parents=True, exist_ok=True)
    try:
        prepare(src, path, live, None, work, op, inf061=True, routine_plan_only=True)
    except subprocess.CalledProcessError as error:
        print(
            json.dumps(
                {
                    "provider_diagnostic": diagnostics.tail(
                        (error.stderr or b"") + (error.output or b"")
                    )
                }
            )
        )
        raise
    manifest = spec.verify_packet(path)
    spec.check(not (path / "consumed.json").exists(), "review_consume")
    with tarfile.open(output, "x:gz") as archive:
        for file in sorted(p for p in path.rglob("*") if p.is_file()):
            archive.add(
                file, arcname=file.relative_to(path).as_posix(), recursive=False
            )
    print(
        json.dumps(
            {
                "source": src,
                "gpu_plan_sha256": manifest["sealed_plans"]["create_sha256"],
                "operator_plan_sha256": manifest["operator_host"]["create_sha256"],
                "archive": spec.facts(output),
                "applies": 0,
                "policy_simulation_pending": True,
            }
        )
    )


def finish(directory, profile):
    """Verify the account and the deferred simulation, then check both saved plans."""
    manifest = spec.verify_packet(directory)
    spec.check(benchmark.is_benchmark(manifest), "benchmark_schema")
    source = manifest["source_commit"]
    git("merge-base", "--is-ancestor", source, "refs/remotes/origin/main")
    spec.check(not (directory / "consumed.json").exists(), "review_consume")
    account = aws(profile, "sts", "get-caller-identity", [])["Account"]
    spec.check(
        hashlib.sha256(account.encode()).hexdigest() == manifest["account_id_sha256"],
        "plan_account",
    )
    folder = directory / "operator-host"
    for name, facts in manifest["operator_host"]["artifacts"].items():
        spec.check(
            spec.facts(spec.safe_file(folder, name)) == facts, "draft_operator_artifact"
        )
    spec.check(
        "policy-simulation.json" not in manifest["operator_host"]["artifacts"],
        "review_already_sealed",
    )
    record = seal(
        lambda service, action, argv: aws(profile, service, action, argv),
        folder / "policy.json",
        folder / "actions.json",
        account,
        manifest["session"],
        spec.AMI,
        zone=manifest["zone"],
    )
    spec.save(folder / "policy-simulation.json", record)
    manifest["operator_host"]["artifacts"]["policy-simulation.json"] = spec.facts(
        folder / "policy-simulation.json"
    )
    operator.verify(directory, manifest)
    spec.save(directory / "manifest.json", manifest)
    spec.verify_packet(directory)
    return {
        "manifest": spec.facts(directory / "manifest.json"),
        "gpu_plan_sha256": manifest["sealed_plans"]["create_sha256"],
        "operator_plan_sha256": manifest["operator_host"]["create_sha256"],
        "policy_sha256": manifest["operator_host"]["role_policy_sha256"],
        "policy_cases": len(record["results"]),
        "applies": 0,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    modes = parser.add_subparsers(dest="mode", required=True)
    routine = modes.add_parser("routine")
    routine.add_argument("--work", required=True, type=Path)
    routine.add_argument("--output", required=True, type=Path)
    finalize = modes.add_parser("seal")
    finalize.add_argument("--directory", required=True, type=Path)
    finalize.add_argument("--profile", default="admin-learning")
    args = parser.parse_args()
    if args.mode == "routine":
        review_plans(args.work, args.output)
    else:
        print(
            json.dumps(finish(args.directory, args.profile), indent=2, sort_keys=True)
        )
