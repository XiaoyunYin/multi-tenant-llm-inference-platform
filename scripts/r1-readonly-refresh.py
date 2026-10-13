"""Read-only R1 prices, offerings, AMIs, quotas, request history, inventory and usage.

No request submission, Terraform plan or Apply. Raw replies remain in ignored storage.
"""

import argparse
import datetime as dt
import hashlib
import json
import subprocess
from decimal import ROUND_CEILING, Decimal
from pathlib import Path

from inference_platform.r1_lifecycle import M4_PHASE_CAP_USD, R1_SESSION_CAP_USD


def price(document, unit):
    rates = set()
    for text in document["PriceList"]:
        product = json.loads(text)
        for term in product["terms"]["OnDemand"].values():
            for dimension in term["priceDimensions"].values():
                if (
                    dimension["unit"] == unit
                    and dimension.get("beginRange", "0") == "0"
                ):
                    rates.add(Decimal(dimension["pricePerUnit"]["USD"]))
    if len(rates) != 1:
        raise ValueError(f"ambiguous/missing {unit} price: {rates}")
    return next(iter(rates))


def estimate_costs(gpu_price, cpu_price, storage_price, ipv4_price):
    hourly = (
        2 * gpu_price
        + 2 * cpu_price
        + Decimal(480) * storage_price / Decimal(720)
        + 4 * ipv4_price
    )
    reservation_allowance = Decimal(2) * gpu_price * Decimal(10) / Decimal(60)
    phase = (
        (Decimal(12) * hourly + Decimal(9) + reservation_allowance)
        * Decimal(2)
        * Decimal("1.15")
    ).quantize(Decimal("0.01"), rounding=ROUND_CEILING)
    session = (
        (Decimal(5) * hourly + Decimal(3) + reservation_allowance)
        * Decimal(2)
        * Decimal("1.15")
    ).quantize(Decimal("0.01"), rounding=ROUND_CEILING)
    if session > R1_SESSION_CAP_USD:
        raise ValueError(
            "reservation-inclusive R1 estimate exceeds DEC-058 session cap"
        )
    if phase > M4_PHASE_CAP_USD:
        raise ValueError("reservation-inclusive M4 estimate exceeds DEC-058 phase cap")
    return {
        "hourly_usd": hourly,
        "reservation_allowance_usd": reservation_allowance,
        "m4_estimate_usd": phase,
        "session_estimate_usd": session,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", default="admin-learning")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    records = {}

    def aws(name, service, operation, *argv):
        command = [
            "aws",
            "--profile",
            args.profile,
            "--region",
            "us-east-1",
            service,
            operation,
            *argv,
            "--output",
            "json",
            "--no-cli-pager",
            "--cli-connect-timeout",
            "10",
            "--cli-read-timeout",
            "30",
        ]
        started = dt.datetime.now(dt.UTC).isoformat()
        result = subprocess.run(command, capture_output=True, check=False, timeout=120)
        (args.output / (name + ".raw.json")).write_bytes(result.stdout)
        (args.output / (name + ".stderr")).write_bytes(result.stderr)
        records[name] = {
            "argv": command,
            "captured_at": started,
            "exit": result.returncode,
            "raw_sha256": hashlib.sha256(result.stdout).hexdigest(),
        }
        (args.output / "queries.json").write_text(
            json.dumps(records, indent=2), encoding="utf-8"
        )
        if result.returncode:
            raise RuntimeError(name + " failed; private stderr retained")
        return json.loads(result.stdout)

    def quote(name, service, filters, unit):
        encoded = json.dumps(
            [
                {"Type": "TERM_MATCH", "Field": field, "Value": value}
                for field, value in filters.items()
            ]
        )
        return price(
            aws(
                name,
                "pricing",
                "get-products",
                "--service-code",
                service,
                "--filters",
                encoded,
            ),
            unit,
        )

    identity = aws("identity", "sts", "get-caller-identity")
    gpu_price, cpu_price = [
        quote(
            shape + "-price",
            "AmazonEC2",
            {
                "instanceType": shape,
                "regionCode": "us-east-1",
                "operatingSystem": "Linux",
                "tenancy": "Shared",
                "preInstalledSw": "NA",
                "capacitystatus": "Used",
                "licenseModel": "No License required",
            },
            "Hrs",
        )
        for shape in ("g6.xlarge", "c6i.2xlarge")
    ]
    storage = quote(
        "gp3-price",
        "AmazonEC2",
        {"regionCode": "us-east-1", "volumeApiName": "gp3"},
        "GB-Mo",
    )
    ipv4 = quote(
        "ipv4-price",
        "AmazonVPC",
        {"regionCode": "us-east-1", "usagetype": "USE1-PublicIPv4:InUseAddress"},
        "Hrs",
    )
    shapes = aws(
        "shapes",
        "ec2",
        "describe-instance-types",
        "--instance-types",
        "g6.xlarge",
        "c6i.2xlarge",
    )
    offerings = aws(
        "offerings",
        "ec2",
        "describe-instance-type-offerings",
        "--location-type",
        "availability-zone",
        "--filters",
        "Name=instance-type,Values=g6.xlarge,c6i.2xlarge",
    )
    gvt = aws(
        "gvt-quota",
        "service-quotas",
        "get-service-quota",
        "--service-code",
        "ec2",
        "--quota-code",
        "L-DB2E81BA",
    )
    standard = aws(
        "standard-quota",
        "service-quotas",
        "get-service-quota",
        "--service-code",
        "ec2",
        "--quota-code",
        "L-1216C47A",
    )
    history = aws(
        "inf057-history",
        "service-quotas",
        "list-requested-service-quota-change-history-by-quota",
        "--service-code",
        "ec2",
        "--quota-code",
        "L-DB2E81BA",
    )
    instances = aws("instances", "ec2", "describe-instances")
    volumes = aws("volumes", "ec2", "describe-volumes")
    addresses = aws("addresses", "ec2", "describe-addresses")
    end = (dt.datetime.now(dt.UTC).date() + dt.timedelta(days=1)).isoformat()
    billing = aws(
        "account-usage",
        "ce",
        "get-cost-and-usage",
        "--time-period",
        "Start=2026-09-16,End=" + end,
        "--granularity",
        "DAILY",
        "--metrics",
        "UnblendedCost",
    )
    ami = {}
    for role, parameter in (
        (
            "gpu",
            "/aws/service/deeplearning/ami/x86_64/base-oss-nvidia-driver-gpu-ubuntu-24.04/latest/ami-id",
        ),
        (
            "cpu",
            "/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id",
        ),
    ):
        identifier = aws(
            role + "-ami-parameter", "ssm", "get-parameter", "--name", parameter
        )["Parameter"]["Value"]
        image = aws(role + "-ami", "ec2", "describe-images", "--image-ids", identifier)[
            "Images"
        ]
        if (
            len(image) != 1
            or image[0]["State"] != "available"
            or image[0]["Architecture"] != "x86_64"
        ):
            raise ValueError("exact AMI unavailable/incompatible")
        ami[role] = {
            "id": identifier,
            "name": image[0]["Name"],
            "architecture": image[0]["Architecture"],
        }
    live = [
        item
        for reservation in instances["Reservations"]
        for item in reservation["Instances"]
        if item["State"]["Name"] in {"pending", "running", "stopping", "stopped"}
    ]
    usage = {"gvt_vcpu": 0, "standard_vcpu": 0}
    if live:
        live_shapes = aws(
            "live-shapes",
            "ec2",
            "describe-instance-types",
            "--instance-types",
            *sorted({x["InstanceType"] for x in live}),
        )
        vcpus = {
            x["InstanceType"]: x["VCpuInfo"]["DefaultVCpus"]
            for x in live_shapes["InstanceTypes"]
        }
        for item in live:
            if item["State"]["Name"] in {"pending", "running"}:
                usage[
                    "gvt_vcpu"
                    if item["InstanceType"].startswith(("g", "vt"))
                    else "standard_vcpu"
                ] += vcpus[item["InstanceType"]]
    estimates = estimate_costs(gpu_price, cpu_price, storage, ipv4)
    hourly = estimates["hourly_usd"]
    phase = estimates["m4_estimate_usd"]
    session = estimates["session_estimate_usd"]
    account = sum(
        Decimal(x["Total"]["UnblendedCost"]["Amount"]) for x in billing["ResultsByTime"]
    )
    floor = max(account, Decimal("24.4492146028"))
    summary = {
        "schema": "r1-readonly-refresh.v1",
        "region": "us-east-1",
        "aws_profile": args.profile,
        "captured_at": dt.datetime.now(dt.UTC).isoformat(),
        "account_id_sha256": hashlib.sha256(identity["Account"].encode()).hexdigest(),
        "prices_usd": {
            "gpu_hour": str(gpu_price),
            "cpu_hour": str(cpu_price),
            "gp3_gib_month": str(storage),
            "ipv4_hour": str(ipv4),
        },
        "hourly_usd": str(hourly),
        "capacity_reservation_allowance_usd": str(
            estimates["reservation_allowance_usd"]
        ),
        "m4_estimate_usd": str(phase),
        "m4_cap_usd": str(M4_PHASE_CAP_USD),
        "m4_estimate_fits": phase <= M4_PHASE_CAP_USD,
        "session_estimate_usd": str(session),
        "session_cap_usd": str(R1_SESSION_CAP_USD),
        "session_estimate_fits": session <= R1_SESSION_CAP_USD,
        "estimate_fits": phase <= M4_PHASE_CAP_USD and session <= R1_SESSION_CAP_USD,
        "account_unblended_usd": str(account),
        "billing_estimated": any(x.get("Estimated") for x in billing["ResultsByTime"]),
        "historical_project_floor_usd": "24.4492146028",
        "conservative_current_floor_usd": str(floor),
        "floor_plus_m4_usd": str(floor + phase),
        "below_150_checkpoint": floor + phase < 150,
        "not_settled_project_attribution": True,
        "quotas": {
            "gvt": gvt["Quota"]["Value"],
            "standard": standard["Quota"]["Value"],
        },
        "current_usage": usage,
        "live_instance_count": len(live),
        "volume_count": len(volumes["Volumes"]),
        "elastic_address_count": len(addresses["Addresses"]),
        "unexpected_project_instances": sum(
            x.get("Tags")
            and any(
                t["Key"] == "Project"
                and t["Value"] == "multi-tenant-llm-inference-platform"
                for t in x["Tags"]
            )
            or 0
            for x in live
        ),
        "ami": ami,
        "shapes": shapes,
        "offerings": offerings,
        "inf057_history": [
            {
                k: v
                for k, v in x.items()
                if k
                in {"Id", "DesiredValue", "Status", "Created", "LastUpdated", "CaseId"}
            }
            for x in history["RequestedQuotas"]
        ],
        "queries": records,
        "mutation_count": 0,
    }
    (args.output / "summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                k: summary[k]
                for k in (
                    "estimate_fits",
                    "session_estimate_usd",
                    "session_cap_usd",
                    "m4_estimate_usd",
                    "m4_cap_usd",
                    "capacity_reservation_allowance_usd",
                    "quotas",
                    "current_usage",
                    "floor_plus_m4_usd",
                    "below_150_checkpoint",
                )
            }
        )
    )


if __name__ == "__main__":
    main()
