"""Build and hash a review-only native probe packet from one committed source."""

import argparse
import ast
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import inf060_probe_spec as spec

ROOT = Path(__file__).resolve().parents[1]
PILOT = "docs/evidence/m5-l4-compatibility-round281/"
TF_ROOT = "infra/terraform/l4_compat/"
OPERATOR = "scripts/inf060_probe_operator.py"
AGENT = (
    "package_a_host.py",
    "l4_compat_service.py",
    "inf060_probe_agent.py",
    "inf060_diagnostics.py",
)
HOST = (
    "inf060_diagnostics.py",
    "inf060_probe_spec.py",
    "inf060_probe_host.py",
    "inf060_probe_client.py",
    "inf060_probe_engine.py",
)
MODULE = "python/src/inference_platform/"
READBACK = PILOT + "execution-2026-10-26/receipts.tar.gz"


def git(*args):
    return subprocess.check_output(["git", "-C", str(ROOT), *args])


def gitblob(source, path):
    return git("show", source + ":" + path)


def bytes_facts(value):
    return {"bytes": len(value), "sha256": hashlib.sha256(value).hexdigest()}


def historical(source):
    raw = gitblob(source, READBACK)
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        weights = json.load(archive.extractfile("results/model-manifest.json"))
        cmds = json.load(archive.extractfile("results/host-commands.json"))
    names = ("l4-stage-launch", "l4-stage-inspect", "stage-wait")
    observed = [r for r in cmds if r["stage"] in names]
    spec.check(
        len(observed) == 3 and all(r["exit_code"] == 0 for r in observed),
        "model_volume_basis",
    )
    weight_bytes = sum(row["bytes"] for row in weights["files"].values())
    seconds = sum(r["elapsed_seconds"] for r in observed)
    spec.check(weights["revision"] == spec.REVISION, "model_revision")
    shipment = (
        ("r403-routine-validation/full", 543737347),
        ("r404-routine-validation/final", 544930201),
    )
    source_observed = []
    for label, size in shipment:
        path = f"docs/evidence/{label}/lifecycle.json"
        records = json.loads(gitblob(source, path))["phases"]
        row = next(
            r for r in records if r["name"] == "upload" and r["status"] == "PASS"
        )
        source_observed.append(
            {
                "receipt": path,
                "bytes": size,
                "elapsed_s": row["elapsed_s"],
                "bytes_per_s": size / row["elapsed_s"],
            }
        )
    source_floor = min(500_000, int(min(r["bytes_per_s"] for r in source_observed)))
    weight_floor = int(weight_bytes / seconds)
    return (
        weights,
        weight_bytes,
        source_floor,
        weight_floor,
        {
            "ssm_uploads": source_observed,
            "source_floor_bytes_per_s": source_floor,
            "model_stage": {
                "receipt": READBACK,
                "archive_sha256": bytes_facts(raw)["sha256"],
                "elapsed_s": seconds,
                "bytes": weight_bytes,
                "bytes_per_s": weight_bytes / seconds,
                "basis": "one observed same-pilot model transfer including launch and verification",
            },
        },
    )


def host_sources(source):
    names = set(git("ls-tree", "-rz", "--name-only", source).decode().split("\0")[:-1])
    selected = {f"scripts/{name}" for name in HOST}
    selected.update(("go.mod", "go.sum", spec.LOG_CONFIG))
    pending = [MODULE + "inf060_streaming_probe.py", MODULE + "__init__.py"]
    while pending:
        path = pending.pop()
        if path in selected:
            continue
        selected.add(path)
        for item in ast.walk(ast.parse(gitblob(source, path))):
            if isinstance(item, ast.ImportFrom) and item.level == 1 and item.module:
                candidate = MODULE + item.module.replace(".", "/") + ".py"
                if candidate in names:
                    pending.append(candidate)
    go_packages = ["cmd/gateway"]
    seen = set()
    imports = re.compile(
        rb'"multi-tenant-llm-inference-platform/(internal/[a-z0-9_/]+)"'
    )
    while go_packages:
        package = go_packages.pop()
        if package in seen:
            continue
        seen.add(package)
        sources = {
            path
            for path in names
            if path.startswith(package + "/")
            and (
                path.endswith(".lua")
                or path.endswith(".go")
                and not path.endswith("_test.go")
            )
            and (path.endswith(".lua") or path.rsplit("/", 1)[0] == package)
        }
        spec.check(sources, "go_source_closure")
        selected.update(sources)
        for path in sources:
            if path.endswith(".go"):
                go_packages += [
                    match.decode() for match in imports.findall(gitblob(source, path))
                ]
    return {name: gitblob(source, name) for name in sorted(selected)}


def bundle(path, items):
    with (
        path.open("xb") as out,
        gzip.GzipFile(filename="", fileobj=out, mode="wb", mtime=0) as zipped,
    ):
        with tarfile.open(fileobj=zipped, mode="w") as archive:
            for name, value in sorted(items.items()):
                member = tarfile.TarInfo(name)
                member.size = len(value)
                archive.addfile(member, io.BytesIO(value))


def validate_inputs(live):
    spec.check(
        live["region"] == spec.REGION
        and live["zone"] == spec.ZONE
        and re.fullmatch(r"dec077-inf060-[a-z0-9-]+", live["session"]),
        "live_region_session",
    )
    spec.check(
        len(live["ami"]) == 1
        and live["ami"][0]["ImageId"] == spec.AMI
        and live["ami"][0]["State"] == "available"
        and live["ami"][0]["Architecture"] == "x86_64",
        "live_ami",
    )
    spec.check(
        live["shape"]
        == {"type": spec.SHAPE, "vcpus": 4, "gpu": [{"Name": "L4", "Count": 1}]}
        and live["quota_vcpus"] >= 4
        and any(
            r["Location"] == spec.ZONE and r["InstanceType"] == spec.SHAPE
            for r in live["offerings"]
        )
        and any(
            r["ZoneName"] == spec.ZONE and r["State"] == "available"
            for r in live["zone_states"]
        ),
        "live_shape_offering_quota",
    )
    spec.check(
        all(
            live[k] == 0
            for k in (
                "account_nonterminated_instances",
                "owned_capacity_reservations",
                "session_route_tables",
            )
        ),
        "unexpected_preflight_inventory",
    )


def prepare(source, output, inputs, profile, scratch, operator_inputs=None):
    spec.check(
        re.fullmatch(r"[0-9a-f]{40}", source)
        and git("rev-parse", source).decode().strip() == source,
        "source_commit",
    )
    git("merge-base", "--is-ancestor", source, "refs/remotes/origin/main")
    output = output.resolve()
    spec.check(output.is_relative_to(ROOT / ".cache"), "packet_directory")
    live = spec.load(inputs)
    validate_inputs(live)
    tf = ROOT / ".tools/terraform/1.16.2/terraform.exe"
    aws = Path(shutil.which("aws") or "missing")
    plugin = ROOT / ".cache/session-manager-plugin/bin/bin/session-manager-plugin.exe"
    for tool in (tf, aws, plugin):
        spec.check(tool.is_file(), "operator_tool")
    output.mkdir(parents=True, exist_ok=False)
    terraform = output / "terraform"
    terraform.mkdir()
    for file in spec.TERRAFORM_FILES:
        raw = gitblob(source, TF_ROOT + file)
        if operator_inputs and file == "main.tf":
            from inf060_operator_packet import gpu_main

            raw = gpu_main(raw.decode()).encode()
        if operator_inputs and file == "versions.tf":
            raw = raw.replace(
                b"skip_metadata_api_check     = true",
                b"skip_metadata_api_check     = false",
            )
        (terraform / file).write_bytes(raw)
    weights, weights_bytes, source_floor, weights_floor, observed = historical(source)
    pins = json.loads(gitblob(source, PILOT + "manifest.json"))["pins"]
    spec.check(
        (pins["vllm"], pins["model"], pins["revision"])
        == (spec.VLLM_IMAGE, spec.MODEL, spec.REVISION),
        "pilot_pins",
    )
    tools = json.loads(gitblob(source, "deploy/package-a/pins.json"))
    spec.save(
        output / "tools.json",
        {"go": tools["go"], **{k: pins[k] for k in ("vllm", "redis", "nginx")}},
    )
    spec.save(output / "engine.json", spec.engine())
    spec.save(output / "requests.json", spec.request_manifest())
    spec.save(output / "model.json", weights)
    spec.save(output / "live-inputs.json", {**live, "transfer_observations": observed})
    items = host_sources(source)
    (output / spec.LOG_CONFIG).parent.mkdir(parents=True)
    (output / spec.LOG_CONFIG).write_bytes(items[spec.LOG_CONFIG])
    for name in ("engine.json", "requests.json", "model.json", "tools.json"):
        items[name] = (output / name).read_bytes()
    spec.save(
        output / "sources.json", {name: bytes_facts(raw) for name, raw in items.items()}
    )
    items["sources.json"] = (output / "sources.json").read_bytes()
    bundle(output / spec.SOURCE_REF, items)
    binary = spec.facts(output / spec.SOURCE_REF)
    variables = {
        "enable_task": True,
        "ami": spec.AMI,
        "instance_type": spec.SHAPE,
        "root_gib": 128,
        "host_timer_seconds": spec.HOST_TIMER_S,
        "session": live["session"],
        "source_sha256": spec.facts(output / "sources.json")["sha256"],
    }
    spec.save(terraform / "input.tfvars.json", variables)
    budget = spec.budget(
        binary["bytes"], source_floor, weights_bytes, weights_floor, live["rates"]
    )
    work = scratch.resolve()
    tf_data = work / (output.name + "-tf-data")
    tf_data.mkdir(exist_ok=False)
    environment = {
        **os.environ,
        "AWS_PROFILE": profile,
        "TF_IN_AUTOMATION": "1",
        "TF_DATA_DIR": str(tf_data),
        "TF_PLUGIN_CACHE_DIR": str(ROOT / ".cache/terraform-plugins"),
    }

    def command(*argv):
        return subprocess.check_output(
            [str(tf), *argv],
            cwd=terraform,
            env=environment,
            timeout=180,
            stderr=subprocess.STDOUT,
        )

    (work / (output.name + "-init.log")).write_bytes(
        command("init", "-input=false", "-lockfile=readonly")
    )
    (work / (output.name + "-plan.log")).write_bytes(
        command(
            "plan",
            "-input=false",
            "-refresh=false",
            "-var-file=input.tfvars.json",
            "-out=create.tfplan",
        )
    )
    (terraform / "create.json").write_bytes(command("show", "-json", "create.tfplan"))
    spec.verify_plan(
        spec.load(terraform / "create.json"),
        variables,
        (terraform / "user-data.sh").read_text(encoding="utf-8"),
    )
    commands = {
        role: [
            sys.executable,
            str(ROOT / OPERATOR),
            mode,
            "--directory",
            str(output),
            "--profile",
            profile,
        ]
        for role, mode in (
            ("controller", "execute"),
            ("cleanup", "cleanup"),
            ("inventory", "inventory"),
        )
    }
    if operator_inputs:
        import inf060_operator_packet as remote

        commands = remote.commands()
    spec.save(output / "commands.json", commands)
    files = {
        name: spec.facts(spec.safe_file(output, name))
        for name in sorted(spec.ARTIFACTS)
    }
    account = json.loads(
        subprocess.check_output(
            [
                str(aws),
                "--profile",
                profile,
                "--region",
                spec.REGION,
                "sts",
                "get-caller-identity",
                "--output",
                "json",
            ],
            timeout=45,
        )
    )["Account"]
    manifest = {
        "schema": spec.SCHEMA,
        "source_commit": source,
        "session": live["session"],
        "region": spec.REGION,
        "zone": spec.ZONE,
        "ami": spec.AMI,
        "instance_type": spec.SHAPE,
        "root_gib": 128,
        "artifacts": files,
        "bundle_bytes": binary["bytes"],
        "bundle_sha256": binary["sha256"],
        "weight_bytes": weights_bytes,
        "cleanup_cost_reserve_usd": 1,
        "account_id_sha256": hashlib.sha256(account.encode()).hexdigest(),
        "sealed_plans": {
            "create_sha256": files["terraform/create.tfplan"]["sha256"],
            "create_json_sha256": files["terraform/create.json"]["sha256"],
        },
        "operator_tools": {
            k: {"path": str(p), **spec.facts(p)}
            for k, p in (
                ("aws", aws),
                ("terraform", tf),
                ("plugin", plugin),
                ("python", Path(sys.executable)),
            )
        },
        "session_manager_plugin_path": str(plugin.relative_to(ROOT)),
        "bootstrap_sources": {
            name: bytes_facts(gitblob(source, "scripts/" + name)) for name in AGENT
        },
        "approval_state": "unapproved",
        **budget,
    }
    if operator_inputs:
        manifest["operator_host"] = remote.build_host(
            output,
            source,
            spec.load(operator_inputs),
            account,
            environment,
            tf,
        )
        manifest["operator_tools"] = remote.TOOLS
        manifest["session_manager_plugin_path"] = remote.TOOLS["plugin"]["path"]
        remote.verify(output, manifest)
    spec.save(output / "manifest.json", manifest)
    spec.verify_packet(output)
    return {
        "directory": str(output),
        "source": source,
        "manifest": spec.facts(output / "manifest.json"),
        "plan": manifest["sealed_plans"],
        "bundle": binary,
        "budget": budget,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--live-inputs", type=Path, required=True)
    parser.add_argument("--operator-inputs", type=Path)
    parser.add_argument("--scratch", type=Path, default=Path(os.environ["TMPDIR"]))
    parser.add_argument("--profile", default="admin-learning")
    args = parser.parse_args()
    print(
        json.dumps(
            prepare(
                args.source,
                args.output,
                args.live_inputs,
                args.profile,
                args.scratch,
                args.operator_inputs,
            ),
            indent=2,
        )
    )
