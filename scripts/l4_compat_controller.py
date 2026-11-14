"""Separately gated future L4 execution using DEC-077 SSM/transfer/teardown ports.

No action occurs on import. Preparation/rehearsals never invoke execute mode.
"""

import argparse
import base64
import hashlib
import json
import os
import shlex
import subprocess
import time
from pathlib import Path

from inference_platform.l4_compat import (
    DEADLINE_S,
    FREEZE_S,
    READY_BY_S,
    REQUESTS_S,
    PINS,
    need,
)
from inference_platform.package_a_cloud import (
    save,
    sha,
    transfer_seconds,
    EXPORT_MAX_BYTES,
)
from inference_platform.package_a_operator import (
    ROOT,
    Ports,
    git,
    readiness_shell,
    validate_review_marker,
)

SESSION = "dec077-l4-20261026"


def preflight(ports, manifest):
    """Future read-only execution gate; packet production never calls this."""
    answers = {}
    for name, query in manifest["preflight_queries"].items():
        answers[name] = ports.aws(query[0], query[1], query[2:])
        save(ports.runtime / ("preflight-" + name + ".json"), answers[name])
    images = answers["ami"]["Images"]
    need(
        len(images) == 1
        and images[0]["ImageId"] == PINS["ami"]
        and images[0]["State"] == "available",
        "ami_available",
    )
    shape = next(
        r for r in answers["shape"]["InstanceTypes"] if r["InstanceType"] == "g6.xlarge"
    )
    need(
        shape["VCpuInfo"]["DefaultVCpus"] == 4
        and sum(g["Count"] for g in shape["GpuInfo"]["Gpus"]) == 1
        and shape["GpuInfo"]["Gpus"][0]["Name"] == "L4",
        "gpu_shape",
    )
    need(
        any(
            r["Location"] == PINS["zone"] and r["InstanceType"] == "g6.xlarge"
            for r in answers["offerings"]["InstanceTypeOfferings"]
        ),
        "offering",
    )
    need(answers["quota"]["Quota"]["Value"] >= 4, "gvt_quota")
    need(
        not any(
            x["State"]["Name"] != "terminated"
            for r in answers["instances"]["Reservations"]
            for x in r["Instances"]
        ),
        "active_instance_inventory",
    )
    rates = {}
    for name, unit in (("compute", "Hrs"), ("gp3", "GB-Mo"), ("ipv4", "Hrs")):
        values = {
            float(d["pricePerUnit"]["USD"])
            for raw in answers[name]["PriceList"]
            for term in json.loads(raw)["terms"].get("OnDemand", {}).values()
            for d in term["priceDimensions"].values()
            if d["unit"] == unit
        }
        need(len(values) == 1, "price_dimension:" + name)
        rates[name] = values.pop()
    hourly = rates["compute"] + rates["gp3"] * PINS["root_gib"] / 720 + rates["ipv4"]
    need(0 < hourly <= manifest["hourly_all_resources_usd"], "price_ceiling")
    save(
        ports.runtime / "preflight-result.json",
        {"rates_usd": rates, "hourly_usd": hourly, "reservations": 0},
    )


class L4Ports(Ports):
    def __init__(self, *args, **kwargs):
        super().__init__(
            *args, runtime_directory=os.environ["L4_ATTEMPT_DIRECTORY"], **kwargs
        )

    def instance_ids(self):
        response = self.aws(
            "ec2",
            "describe-instances",
            ["--filters", "Name=tag:Session,Values=" + SESSION],
        )
        return [
            x["InstanceId"]
            for r in response["Reservations"]
            for x in r["Instances"]
            if x["State"]["Name"] != "terminated"
        ]

    def bootstrap(self, end):
        self.deadline = end
        ready_end = min(end, time.time() + 180)
        while time.time() < ready_end:
            info = self.aws(
                "ssm",
                "describe-instance-information",
                [
                    "--filters",
                    json.dumps([{"Key": "InstanceIds", "Values": [self.host]}]),
                ],
            )["InstanceInformationList"]
            if len(info) == 1 and info[0]["PingStatus"] == "Online":
                break
            time.sleep(min(2, max(0, ready_end - time.time())))
        else:
            raise TimeoutError("l4:ssm_registration")
        self.ssm(
            self.host,
            readiness_shell(),
            timeout_s=min(300, max(1, int(end - time.time()))),
        )
        commands = ["set -eu"]
        for name in ("package_a_host.py", "l4_compat_service.py"):
            value = base64.b64encode((ROOT / "scripts" / name).read_bytes()).decode()
            commands.append(
                "printf %s " + shlex.quote(value) + " | base64 -d > /opt/dec077/" + name
            )
        commands.append(
            "nohup "
            + shlex.join(
                [
                    "python3",
                    "/opt/dec077/l4_compat_service.py",
                    "--token",
                    self.token,
                    "--manifest-sha256",
                    self.manifest_hash,
                    "--deadline",
                    str(self.origin + READY_BY_S + REQUESTS_S + FREEZE_S),
                    "--origin",
                    str(self.origin),
                ]
            )
            + " >/opt/dec077/host.log 2>&1 </dev/null &"
        )
        commands += [
            "i=0; until curl -fsS --max-time 1 -H "
            + shlex.quote("Authorization: Bearer " + self.token)
            + " http://127.0.0.1:22280/status; do "
            + 'i=$((i+1)); if [ "$i" -ge 20 ]; then '
            + "cat /opt/dec077/host.log; exit 1; fi; sleep 1; done"
        ]
        self.ssm(self.host, commands, timeout_s=min(60, max(1, int(end - time.time()))))
        self.request("/status", end=min(end, time.time() + 60))
        return {"ssm": "L4 service ready"}

    def inventory(self, end):
        self.deadline = end
        results = {"active_instances": self.instance_ids()}
        for label, operation, key in (
            ("volumes", "describe-volumes", "Volumes"),
            ("interfaces", "describe-network-interfaces", "NetworkInterfaces"),
            ("vpcs", "describe-vpcs", "Vpcs"),
        ):
            results[label] = self.aws(
                "ec2", operation, ["--filters", "Name=tag:Session,Values=" + SESSION]
            )[key]
        for label, operation, key, field in (
            ("roles", "list-roles", "Roles", "RoleName"),
            (
                "profiles",
                "list-instance-profiles",
                "InstanceProfiles",
                "InstanceProfileName",
            ),
        ):
            results[label] = [
                r[field]
                for r in self.aws("iam", operation, [])[key]
                if r[field].startswith(SESSION + "-")
            ]
        results["terraform_resources"] = (
            (
                subprocess.check_output(
                    [
                        self.manifest["operator_tools"]["terraform"]["path"],
                        f"-chdir={self.directory / 'terraform'}",
                        "state",
                        "list",
                    ],
                    timeout=max(0.001, end - time.time()),
                )
                .decode()
                .splitlines()
            )
            if (self.directory / "terraform/terraform.tfstate").exists()
            else []
        )
        results["empty"] = all(not v for v in results.values())
        save(self.runtime / "inventory.json", results)
        return results


def execute(args):
    directory = args.directory.resolve()
    manifest = json.loads((directory / "manifest.json").read_bytes())
    plan_hash = manifest["sealed_plans"]["create_sha256"]
    need(
        args.owner_approved_hash == plan_hash
        and sha(directory / "terraform/create.tfplan") == plan_hash,
        "owner_exact_hash",
    )
    need(not (directory / "consumed.json").exists(), "already_consumed")
    need(not (directory / "terraform/terraform.tfstate").exists(), "preexisting_state")
    validate_review_marker(
        git("show", "HEAD:REVIEW.md").decode(),
        (plan_hash, sha(directory / "manifest.json"), args.review_target),
        prefix="DEC-092 L4 PLAN APPROVED",
    )
    # Bind every uploaded source, including operator/service code, to the fixed
    need(os.name == "nt", "reviewed_windows_operator")
    # reviewed commit and current invocation. No source_commit cycle in the tar.
    sources = json.loads((directory / "sources.json").read_bytes())
    for name, facts in sources.items():
        if name.startswith("overlay/"):
            continue
        need(
            hashlib.sha256(git("show", args.review_target + ":" + name)).hexdigest()
            == facts["sha256"]
            and hashlib.sha256(
                (ROOT / name).read_bytes().replace(b"\r\n", b"\n")
            ).hexdigest()
            == facts["sha256"],
            "reviewed_source:" + name,
        )
    for tool in manifest["operator_tools"].values():
        need(sha(tool["path"]) == tool["sha256"], "operator_tool")
    need(sha(directory / "source.bundle") == manifest["bundle_sha256"], "bundle_hash")
    need(
        sha(directory / "sources.json") == manifest["source_manifest_file_sha256"],
        "source_manifest_file",
    )
    for path in (ROOT / "infra/terraform/l4_compat").iterdir():
        if path.is_file():
            need(
                sha(path) == sha(directory / "terraform" / path.name),
                "cleanup_configuration",
            )
    need(
        json.loads((directory / "terraform/input.tfvars.json").read_bytes())
        == manifest["sealed_plans"]["variables"],
        "cleanup_variables",
    )
    # This command is wrapped by the independent deadline supervisor. Absence of
    # its durable original origin refuses before any provider call.
    origin = float(os.environ["L4_T0_EPOCH"])
    need(0 <= time.time() - origin < 60, "external_origin")
    with (Path(os.environ["L4_ATTEMPT_DIRECTORY"]) / "operator.lock").open(
        "xb"
    ) as stream:
        stream.write(str(os.getpid()).encode())
        stream.flush()
        os.fsync(stream.fileno())
    ports = L4Ports(directory, manifest, profile=args.profile)
    ports.origin, ports.started = origin, origin
    ports.deadline = origin + READY_BY_S
    # Account/shape/price availability checks are future execution preflights;
    # there are deliberately no provider refresh calls during packet creation.
    account = ports.aws("sts", "get-caller-identity", [])
    need(
        hashlib.sha256(account["Account"].encode()).hexdigest()
        == manifest["account_id_sha256"],
        "account",
    )
    ports.command(
        ["terraform", "init", "-input=false", "-lockfile=readonly"],
        min(origin + READY_BY_S, time.time() + 120),
        "init",
    )
    preflight(ports, manifest)
    need(time.time() + 60 < origin + 600, "apply_reserve")
    try:
        ports.apply(min(origin + 600, origin + READY_BY_S))
        ports.bootstrap(origin + READY_BY_S)
        ports.upload(origin + READY_BY_S)
        ports.run_checks(origin + READY_BY_S + REQUESTS_S + FREEZE_S)
    finally:
        try:
            result = ports.retrieve(
                origin
                + READY_BY_S
                + REQUESTS_S
                + FREEZE_S
                + transfer_seconds(EXPORT_MAX_BYTES)
            )
            need(
                result.get("complete") is True and not result.get("truncated_files"),
                "complete_retrieval",
            )
        finally:
            if ports.child:
                from inference_platform.session_stop import stop_forward

                stop_forward(ports.child)
        # Independent parent handles teardown and final inventory even if this
        # process, transfer or finally is killed. The host timer is separate.


def cleanup(args):
    directory = args.directory.resolve()
    manifest = json.loads((directory / "manifest.json").read_bytes())
    ports = L4Ports(directory, manifest, profile=args.profile, recovering=True)
    origin = float(os.environ["L4_T0_EPOCH"])
    end = origin + DEADLINE_S
    result = (
        ports.teardown(
            end - 60, skip_destroy=not (directory / "consumed.json").exists()
        )
        if args.mode == "cleanup"
        else ports.inventory(end)
    )
    save(ports.runtime / (args.mode + "-l4.json"), result)
    need(
        result.get("destroy_completed") is True
        if args.mode == "cleanup"
        else result.get("empty") is True,
        args.mode,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("execute", "cleanup", "inventory"))
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--profile", default="admin-learning")
    parser.add_argument("--review-target", default=os.environ.get("L4_REVIEW_TARGET"))
    parser.add_argument(
        "--owner-approved-hash", default=os.environ.get("L4_OWNER_APPROVED_HASH")
    )
    args = parser.parse_args()
    execute(args) if args.mode == "execute" else cleanup(args)
