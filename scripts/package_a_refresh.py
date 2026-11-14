"""DEC-077 read-only AWS offering/quota/price/AMI and local byte refresh.

Raw account-bearing API replies remain ignored. No Create, Apply, quota request,
reservation or other billable mutation is present.
"""

import argparse
import datetime as dt
import hashlib
import json
import subprocess
from pathlib import Path

from inference_platform.inf037b_nic import instance_type_facts
from inference_platform.inf037b_driver import refresh_driver

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--output", type=Path, required=True)
parser.add_argument("--profile", default="admin-learning")
parser.add_argument(
    "--instance-type", choices=("m6i.2xlarge", "c6i.2xlarge"), required=True
)
parser.add_argument(
    "--gpu-release",
    help="Exact managed node release_version; optional public component refresh",
)
parser.add_argument("--gpu-driver-package", default="nvidia-kmod (default)")
options = parser.parse_args()
out = options.output
out.mkdir(parents=True, exist_ok=False)
records = {}


def query(name, service, operation, *args):
    argv = [
        "aws",
        "--profile",
        options.profile,
        "--region",
        "us-east-1",
        service,
        operation,
        *args,
        "--output",
        "json",
        "--no-cli-pager",
        "--cli-connect-timeout",
        "10",
        "--cli-read-timeout",
        "40",
    ]
    r = subprocess.run(argv, capture_output=True, timeout=100)
    (out / (name + ".raw.json")).write_bytes(r.stdout)
    (out / (name + ".stderr")).write_bytes(r.stderr)
    records[name] = {
        "utc": dt.datetime.now(dt.UTC).isoformat(),
        "argv": argv,
        "exit": r.returncode,
        "sha256": hashlib.sha256(r.stdout).hexdigest(),
    }
    (out / "queries.json").write_text(json.dumps(records, indent=2))
    r.check_returncode()
    return json.loads(r.stdout)


shape = query(
    "shape", "ec2", "describe-instance-types", "--instance-types", options.instance_type
)["InstanceTypes"][0]
offering = query(
    "offerings",
    "ec2",
    "describe-instance-type-offerings",
    "--location-type",
    "availability-zone",
    "--filters",
    "Name=instance-type,Values=" + options.instance_type,
)
quota = query(
    "quota",
    "service-quotas",
    "get-service-quota",
    "--service-code",
    "ec2",
    "--quota-code",
    "L-1216C47A",
)
usage = query(
    "usage",
    "ec2",
    "describe-instances",
    "--filters",
    "Name=instance-state-name,Values=pending,running,stopping,stopped",
)
ami = query(
    "ami",
    "ssm",
    "get-parameter",
    "--name",
    "/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id",
)["Parameter"]["Value"]
image = query("image", "ec2", "describe-images", "--image-ids", ami)["Images"][0]


def price(name, service, filters, unit):
    doc = query(
        name,
        "pricing",
        "get-products",
        "--service-code",
        service,
        "--filters",
        json.dumps(
            [{"Type": "TERM_MATCH", "Field": k, "Value": v} for k, v in filters.items()]
        ),
    )
    values = {
        float(d["pricePerUnit"]["USD"])
        for p in doc["PriceList"]
        for t in json.loads(p)["terms"]["OnDemand"].values()
        for d in t["priceDimensions"].values()
        if d["unit"] == unit and d.get("beginRange", "0") == "0"
    }
    if len(values) != 1:
        raise ValueError(values)
    return values.pop()


compute = price(
    "compute-price",
    "AmazonEC2",
    {
        "instanceType": options.instance_type,
        "regionCode": "us-east-1",
        "operatingSystem": "Linux",
        "tenancy": "Shared",
        "preInstalledSw": "NA",
        "capacitystatus": "Used",
        "licenseModel": "No License required",
    },
    "Hrs",
)
ebs = price(
    "ebs-price",
    "AmazonEC2",
    {"regionCode": "us-east-1", "volumeApiName": "gp3"},
    "GB-Mo",
)
ip = price(
    "ipv4-price",
    "AmazonVPC",
    {"regionCode": "us-east-1", "usagetype": "USE1-PublicIPv4:InUseAddress"},
    "Hrs",
)
summary = {
    "utc": dt.datetime.now(dt.UTC).isoformat(),
    "region": "us-east-1",
    "instance_type": shape["InstanceType"],
    "vcpus": shape["VCpuInfo"]["DefaultVCpus"],
    "memory_mib": shape["MemoryInfo"]["SizeInMiB"],
    "instance_type_facts": instance_type_facts(
        (out / "shape.raw.json").read_bytes(), records["shape"]
    ),
    "availability_zones": [x["Location"] for x in offering["InstanceTypeOfferings"]],
    "standard_vcpu_quota": quota["Quota"]["Value"],
    "active_instance_count": sum(len(x["Instances"]) for x in usage["Reservations"]),
    "ami": ami,
    "ami_name": image["Name"],
    "ami_creation_date": image["CreationDate"],
    "on_demand_usd_per_hour": compute,
    "gp3_usd_per_gib_month": ebs,
    "ipv4_usd_per_hour": ip,
    "raw_query_hashes": {k: v["sha256"] for k, v in records.items()},
}
if options.gpu_release:
    driver, raw = refresh_driver(
        options.gpu_release, package=options.gpu_driver_package
    )
    (out / "gpu-driver.raw.json").write_bytes(raw)
    summary["eks_gpu_driver"] = driver
identity = query("identity", "sts", "get-caller-identity")
summary["account_id_sha256"] = hashlib.sha256(identity["Account"].encode()).hexdigest()
pins = json.loads(Path("deploy/package-a/pins.json").read_bytes())
summary["image_bytes"] = {}
for label, name in [
    ("python", pins["python_image"]),
    ("node", pins["node_image"]),
    ("redis", pins["redis_image"]),
    (
        "gateway_base",
        "alpine:3.22.1@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1",
    ),
]:
    summary["image_bytes"][label] = json.loads(
        subprocess.check_output(["docker", "image", "inspect", name])
    )[0]["Size"]
summary["image_byte_method"] = (
    "Read-only Docker image inspect Size; worksheet separately budgets 4x expansion and 3 node filesystems"
)
summary["observed_export_bytes"] = json.loads(
    Path("docs/evidence/m5-package-a/sizing-native.json").read_bytes()
)["export_bytes"]
summary["raw_query_hashes"] = {k: v["sha256"] for k, v in records.items()}
(out / "sanitized.json").write_text(json.dumps(summary, indent=2) + "\n")
print(json.dumps(summary, indent=2))
