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
import urllib.request
from pathlib import Path

import inf060_probe_spec as spec
import inf061_packet as benchmark

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
    "inf061_packet.py",
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


def validate_inputs(live, *, zone=spec.ZONE):
    spec.check(
        live["region"] == spec.REGION
        and live["zone"] == zone
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
            r["Location"] == zone and r["InstanceType"] == spec.SHAPE
            for r in live["offerings"]
        )
        and any(
            r["ZoneName"] == zone and r["State"] == "available"
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


def routine_account():
    # Render IAM ARNs from the instance identity document. No role credentials
    # are requested or kept by the review-only builder.
    base = "http://169.254.169.254/latest/"
    client = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(
        base + "api/token",
        method="PUT",
        headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"},
    )
    with client.open(request, timeout=5) as response:
        token = response.read(4096).decode()
    request = urllib.request.Request(
        base + "dynamic/instance-identity/document",
        headers={"X-aws-ec2-metadata-token": token},
    )
    with client.open(request, timeout=5) as response:
        identity = json.loads(response.read(4096))
    account = identity["accountId"]
    spec.check(
        identity["region"] == spec.REGION and re.fullmatch(r"[0-9]{12}", account),
        "routine_identity_document",
    )
    return account


def gpu_provider_versions(raw, *, inf061=False):
    raw = raw.replace(
        b"skip_metadata_api_check     = true",
        b"skip_metadata_api_check     = false",
    )
    if not inf061:
        return raw
    marker = b'provider "aws" {\n'
    spec.check(raw.count(marker) == 1, "benchmark_provider_template")
    return (
        raw.replace(marker, marker + b"  max_retries = var.provider_attempts\n")
        + b'\nvariable "provider_attempts" {\n  type = number\n}\n'
    )


def prepare(
    source,
    output,
    inputs,
    profile,
    scratch,
    operator_inputs=None,
    *,
    inf061=False,
    routine_plan_only=False,
    inf061_hunt=False,
):
    spec.check(
        re.fullmatch(r"[0-9a-f]{40}", source)
        and git("rev-parse", source).decode().strip() == source,
        "source_commit",
    )
    if routine_plan_only:
        spec.check(
            inf061
            and os.name == "posix"
            and git("rev-parse", "HEAD").decode().strip() == source,
            "routine_plan_only_source",
        )
    else:
        git("merge-base", "--is-ancestor", source, "refs/remotes/origin/main")
    output = output.resolve()
    spec.check(output.is_relative_to(ROOT / ".cache"), "packet_directory")
    live = spec.load(inputs)
    from inf061_capacity import PLAN_SOURCE

    spec.check(not inf061_hunt or inf061, "capacity_benchmark_required")
    plan_path = PLAN_SOURCE if inf061_hunt else "docs/INF061_FINAL_PLAN.json"
    plan_bytes = gitblob(source, plan_path) if inf061 else None
    plan = json.loads(plan_bytes) if inf061 else None
    zone = plan["zone"] if inf061 else spec.ZONE
    if inf061:
        spec.check(
            zone in benchmark.GPU_ZONES and plan["session"] == live["session"],
            "benchmark_zone_session",
        )
    validate_inputs(live, zone=zone)
    spec.check(not inf061 or operator_inputs is not None, "benchmark_requires_operator")
    tf = (
        Path(shutil.which("terraform") or "missing")
        if routine_plan_only
        else (ROOT / ".tools/terraform/1.16.2/terraform.exe")
    )
    aws = Path(shutil.which("aws") or "missing")
    plugin = (
        Path(shutil.which("session-manager-plugin") or "missing")
        if routine_plan_only
        else ROOT / ".cache/session-manager-plugin/bin/bin/session-manager-plugin.exe"
    )
    for tool in (tf,) if routine_plan_only else (tf, aws, plugin):
        spec.check(tool.is_file(), "operator_tool")
    output.mkdir(parents=True, exist_ok=False)
    terraform = output / "terraform"
    terraform.mkdir()
    for file in spec.TERRAFORM_FILES:
        raw = gitblob(source, TF_ROOT + file)
        if operator_inputs and file == "main.tf":
            from inf060_operator_packet import gpu_main

            raw = gpu_main(raw.decode(), zone=zone).encode()
        if operator_inputs and file == "versions.tf":
            raw = gpu_provider_versions(raw, inf061=inf061)
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
    extra = set()
    if inf061:
        (output / "benchmark.json").write_bytes(plan_bytes)
        with urllib.request.urlopen(plan["quality"]["url"], timeout=45) as response:
            data = response.read(1024**2 + 1)
        spec.check(
            len(data) <= 1024**2
            and bytes_facts(data)["sha256"] == plan["quality"]["source_sha256"],
            "quality_dataset_binding",
        )
        (output / "quality.jsonl").write_bytes(data)
        extra = benchmark.EXTRA
        for name in (
            "inf061_native_host",
            "inf061_native_workload",
            "prometheus_snapshot",
            "rehearse_inf061_final",
            "rehearse_inf061_l4",
        ):
            path = "scripts/" + name + ".py"
            items[path] = gitblob(source, path)
        for name in extra:
            items[name] = (output / name).read_bytes()
        tools_out = spec.load(output / "tools.json")
        dcgm = json.loads(gitblob(source, "deploy/eks/dcgm-exporter.json"))
        tools_out["dcgm"] = dcgm["spec"]["template"]["spec"]["containers"][0]["image"]
        tools_out["prometheus"] = plan["observability"]["prometheus"]
        spec.save(output / "tools.json", tools_out)
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
        "host_timer_seconds": plan["gpu_timer_s"] if inf061 else spec.HOST_TIMER_S,
        "session": live["session"],
        "source_sha256": spec.facts(output / "sources.json")["sha256"],
    }
    if inf061:
        variables["provider_attempts"] = benchmark.APPLY_ATTEMPTS
    spec.save(terraform / "input.tfvars.json", variables)
    budget = (
        benchmark.budget(plan, live["rates"])
        if inf061
        else spec.budget(
            binary["bytes"], source_floor, weights_bytes, weights_floor, live["rates"]
        )
    )
    work = scratch.resolve()
    tf_data = work / (output.name + "-tf-data")
    tf_data.mkdir(exist_ok=False)
    environment = {
        **os.environ,
        **({"AWS_PROFILE": profile} if profile else {}),
        "TF_IN_AUTOMATION": "1",
        "TF_DATA_DIR": str(tf_data),
        "TF_PLUGIN_CACHE_DIR": str(ROOT / ".cache/terraform-plugins"),
    }
    if routine_plan_only:
        # Both providers skip credential validation and account API discovery.
        # Fixture credentials keep the real provider's plan-only path offline,
        # even if a credential-chain setting changes on the routine host.
        environment.update(
            AWS_ACCESS_KEY_ID="offline-fixture",
            AWS_SECRET_ACCESS_KEY="offline-fixture",
            AWS_EC2_METADATA_DISABLED="true",
            AWS_CONFIG_FILE="/dev/null",
            AWS_SHARED_CREDENTIALS_FILE="/dev/null",
        )
        for entry in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_SESSION_TOKEN"):
            environment.pop(entry, None)

    def command(*argv, root=terraform):
        return subprocess.check_output(
            [str(tf), *argv],
            cwd=root,
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
        timer=variables["host_timer_seconds"],
        zone=zone,
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
        for name in sorted(spec.ARTIFACTS | extra)
    }
    account = (
        routine_account()
        if routine_plan_only
        else json.loads(
            subprocess.check_output(
                [
                    str(aws),
                    *(["--profile", profile] if profile else []),
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
    )
    capacity = None
    if inf061_hunt:
        from inf060_operator_packet import gpu_main
        from inf061_capacity import ROOTS, options

        capacity = {
            "options": options(),
            "plans": {},
        }
        spec.check(plan["capacity_hunt"] == capacity["options"], "capacity_options")
        for az, name in ROOTS.items():
            root = output / name
            root.mkdir(parents=True, exist_ok=(root == terraform))
            for file in (*spec.TERRAFORM_FILES, "input.tfvars.json"):
                if root != terraform:
                    (root / file).write_bytes((terraform / file).read_bytes())
            main = gitblob(source, TF_ROOT + "main.tf").decode()
            (root / "main.tf").write_bytes(
                gpu_main(main, zone=az, open_capacity=True).encode()
            )
            if root != terraform:
                command("init", "-input=false", "-lockfile=readonly", root=root)
            command(
                "plan",
                "-input=false",
                "-refresh=false",
                "-var-file=input.tfvars.json",
                "-out=create.tfplan",
                root=root,
            )
            (root / "create.json").write_bytes(
                command("show", "-json", "create.tfplan", root=root)
            )
            for file in (
                *spec.TERRAFORM_FILES,
                "input.tfvars.json",
                "create.tfplan",
                "create.json",
            ):
                files[name + "/" + file] = spec.facts(root / file)
            capacity["plans"][az] = {
                "create_sha256": files[name + "/create.tfplan"]["sha256"],
                "json_sha256": files[name + "/create.json"]["sha256"],
            }
    manifest = {
        **({"capacity_hunt": capacity} if capacity else {}),
        "schema": benchmark.SCHEMA if inf061 else spec.SCHEMA,
        "source_commit": source,
        "session": live["session"],
        "region": spec.REGION,
        "zone": zone,
        "ami": spec.AMI,
        "instance_type": spec.SHAPE,
        "root_gib": 128,
        "artifacts": files,
        "bundle_bytes": binary["bytes"],
        "bundle_sha256": binary["sha256"],
        "weight_bytes": weights_bytes,
        "weights_floor_bps": weights_floor,
        "source_floor_bps": source_floor,
        "cleanup_cost_reserve_usd": 1,
        "account_id_sha256": hashlib.sha256(account.encode()).hexdigest(),
        "sealed_plans": {
            "create_sha256": files["terraform/create.tfplan"]["sha256"],
            "create_json_sha256": files["terraform/create.json"]["sha256"],
        },
        "operator_tools": {}
        if routine_plan_only
        else {
            k: {"path": str(p), **spec.facts(p)}
            for k, p in (
                ("aws", aws),
                ("terraform", tf),
                ("plugin", plugin),
                ("python", Path(sys.executable)),
            )
        },
        "session_manager_plugin_path": None
        if routine_plan_only
        else str(plugin.relative_to(ROOT)),
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
            timer=plan["operator_timer_s"] if inf061 else remote.TIMER,
            defer_simulation=routine_plan_only,
            capacity=capacity,
        )
        manifest["operator_tools"] = remote.TOOLS
        manifest["session_manager_plugin_path"] = remote.TOOLS["plugin"]["path"]
        if not routine_plan_only:
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
    parser.add_argument("--inf061", action="store_true")
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
                inf061=args.inf061,
            ),
            indent=2,
        )
    )
