"""Manifest, approval gates and phase contract for the native INF-060 probe."""

import hashlib
import json
import math
import re
import tarfile
from pathlib import Path

import inf061_packet as benchmark

PREFIX = "NATIVE PROBE PLAN APPROVED"
SCHEMA = "inf060-native-probe-v1"
HOST_TIMER_S = 4200
CLEANUP_S = 600
TOTAL_S = HOST_TIMER_S + CLEANUP_S
READY_S = 2700
ARM_S = 180
RESTART_S = 480
VERIFY_S = 240
EXPORT_BYTES = 32 * 1024**2
SEED = 399060
REGION = "us-east-1"
ZONE = "us-east-1a"
SHAPE = "g6.xlarge"
AMI = "ami-0c244e62d32d4ca4e"
VLLM_IMAGE = "docker.io/vllm/vllm-openai@sha256:082ca6f035279109041ffd3fe0695cb568b29bc580b35c4f297a66a08b216c1b"
IMAGE_PYTHON = "python3"
MODEL = "Qwen/Qwen2.5-7B-Instruct"
REVISION = "a09a35458c702b33eeacc393d103063234e8bc28"
LOG_CONFIG = "deploy/inf060/vllm-logging.json"
LOG_CONFIG_SHA = "fd481b158ee0fb6bcee91eddd4016b4546ee7c387165f89573495457dc5dae79"
SOURCE_REF = "source.bundle"
PHASES = ("prepare", "control", "restart", "logged", "freeze")
PORT = 22281
REMOTE = "/opt/dec077/inf060"
TERRAFORM_FILES = (".terraform.lock.hcl", "main.tf", "versions.tf", "user-data.sh")
ENGINE_ENV = {
    "TZ": "UTC",
    "VLLM_LOGGING_LEVEL": "INFO",
    "VLLM_LOGGING_COLOR": "0",
    "NO_COLOR": "1",
    "VLLM_WORKER_MULTIPROC_METHOD": "spawn",
    "VLLM_LOGGING_CONFIG_PATH": "/packet/" + LOG_CONFIG,
    "HF_HUB_OFFLINE": "1",
}
ENGINE_ARGV = [
    IMAGE_PYTHON,
    "-m",
    "vllm.entrypoints.launchers.api_server.entry",
    "--model",
    "/model",
    "--served-model-name",
    MODEL,
    "--dtype",
    "bfloat16",
    "--max-model-len",
    "8192",
    "--gpu-memory-utilization",
    "0.90",
    "--host",
    "127.0.0.1",
    "--port",
    "8000",
]
ARTIFACTS = {
    SOURCE_REF,
    "sources.json",
    "engine.json",
    "requests.json",
    "model.json",
    "tools.json",
    "live-inputs.json",
    "commands.json",
    LOG_CONFIG,
    "terraform/create.tfplan",
    "terraform/create.json",
    "terraform/input.tfvars.json",
    *("terraform/" + name for name in TERRAFORM_FILES),
}
RESOURCES = {
    "aws_vpc.task[0]",
    "aws_internet_gateway.task[0]",
    "aws_subnet.task[0]",
    "aws_route_table.task[0]",
    "aws_route_table_association.task[0]",
    "aws_security_group.task[0]",
    "aws_iam_role.task[0]",
    "aws_iam_role_policy_attachment.ssm[0]",
    "aws_iam_instance_profile.task[0]",
    "aws_instance.task[0]",
}


def check(condition, reason):
    if not condition:
        raise ValueError("inf060:" + reason)


def data(value):
    return (
        json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n"
    ).encode()


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data(value))


def load(path):
    return json.loads(path.read_bytes())


def facts(path):
    with path.open("rb") as stream:
        return {
            "bytes": path.stat().st_size,
            "sha256": hashlib.file_digest(stream, "sha256").hexdigest(),
        }


def safe_file(root, relative):
    path = root / relative
    check(
        path.resolve().is_relative_to(root.resolve())
        and path.is_file()
        and not path.is_symlink(),
        "artifact_missing:" + relative,
    )
    return path


def engine():
    return {
        arm: {"image": VLLM_IMAGE, "env": ENGINE_ENV, "argv": [*ENGINE_ARGV, *flags]}
        for arm, flags in (
            ("control", ["--no-enable-log-requests"]),
            ("logged", ["--enable-log-requests", "--max-log-len", "0"]),
        )
    }


def verify_engine(value):
    check(
        all(arm["argv"][:1] == [IMAGE_PYTHON] for arm in value.values()),
        "engine_interpreter",
    )
    check(value == engine(), "engine_image_argv_env")


def request_manifest():
    rows = []
    for cohort, count in (("warmup", 30), ("measured", 120)):
        for slot in range(count):
            alias = len(rows)
            canary = (
                "INF060-"
                + hashlib.sha256(f"{SEED}:{cohort}:{slot}".encode()).hexdigest()[:24]
            )
            rows.append(
                {
                    "alias": alias,
                    "cohort": cohort,
                    "slot": slot,
                    "canary": canary,
                    "cancel": cohort == "measured" and slot % 5 == 2,
                }
            )
    return {
        "seed": SEED,
        "prompt_tokens": 1024,
        "max_tokens": 32,
        "slots": rows,
        "rate_per_s": 1,
        "warmup_s": 30,
        "window_s": 120,
        "drain_s": 30,
        "request_deadline_s": 30,
        "in_flight_max": 64,
        "prompt_recipe": "canary + pinned filler; pinned chat template must render exactly 1024 tokens",
    }


def transfer(size, bytes_per_second):
    check(size >= 0 and 0 < bytes_per_second < math.inf, "transfer_input")
    return 2 * math.ceil(size / bytes_per_second) + 60


def budget(bundle_bytes, source_bps, weight_bytes, weight_bps, prices):
    source_s = transfer(bundle_bytes, source_bps)
    weights_s = transfer(weight_bytes, weight_bps)
    export_s = transfer(EXPORT_BYTES, source_bps)
    readiness_fixed = 600 + 300 + 690 + 480
    work = READY_S + 2 * ARM_S + RESTART_S + VERIFY_S + export_s
    check(
        readiness_fixed + source_s + weights_s <= READY_S and work <= HOST_TIMER_S,
        "deadline_envelope",
    )
    hourly = (
        prices["compute_usd_per_h"]
        + prices["gp3_usd_per_gib_month"] * 128 / 720
        + prices["ipv4_usd_per_h"]
    )
    check(0 < hourly < math.inf, "price")
    estimate = (TOTAL_S / 3600 * max(2, hourly) + 2) * 1.15
    return {
        "deadline_seconds": TOTAL_S,
        "host_timer_seconds": HOST_TIMER_S,
        "cleanup_seconds": CLEANUP_S,
        "inventory_reserve_seconds": 60,
        "ready_by_seconds": READY_S,
        "arm_seconds": ARM_S,
        "restart_seconds": RESTART_S,
        "verify_seconds": VERIFY_S,
        "work_seconds": work,
        "export_seconds": export_s,
        "readiness_fixed_seconds": readiness_fixed,
        "upload_timeout_s": source_s,
        "weights_timeout_s": weights_s,
        "source_floor_bps": source_bps,
        "weights_floor_bps": weight_bps,
        "export_max_bytes": EXPORT_BYTES,
        "live_hourly_usd": hourly,
        "hourly_all_resources_usd": max(2, hourly),
        "forecast_usd": estimate,
        "hard_cap_usd": math.ceil(100 * estimate) / 100,
    }


def approval(review, manifest, digest):
    """Require one exact line in the latest committed Claude round."""
    headings = list(re.finditer(r"(?m)^## Claude Round [0-9]+\b[^\n]*$", review))
    check(headings, "review_missing")
    latest = review[headings[-1].end() :]
    next_heading = re.search(r"(?m)^## ", latest)
    if next_heading:
        latest = latest[: next_heading.start()]
    prefix = benchmark.PREFIX if benchmark.is_benchmark(manifest) else PREFIX
    rows = [line for line in latest.splitlines() if line.startswith(prefix)]
    expected = (
        benchmark.approval_line(manifest, digest)
        if benchmark.is_benchmark(manifest)
        else f"{PREFIX} manifest={digest} plan={manifest['sealed_plans']['create_sha256']} source={manifest['source_commit']}"
    )
    check(rows == [expected] and review.count(expected) == 1, "approval_marker")
    check(
        re.search(r"(?m)^- Verdict: (?:\*\*)?NO_BLOCKING_FINDINGS\b", latest),
        "review_verdict",
    )


def verify_plan(
    raw, values, userdata, *, timer=HOST_TIMER_S, zone=ZONE, open_capacity=False
):
    check(
        raw.get("applyable") and raw.get("complete") and not raw.get("errored"),
        "plan_incomplete",
    )
    changes = {r["address"]: r["change"] for r in raw["resource_changes"]}
    check(
        set(changes)
        == RESOURCES
        | ({"aws_launch_template.native_capacity"} if open_capacity else set())
        and all(r["actions"] == ["create"] for r in changes.values()),
        "plan_resource_scope",
    )
    current = {k: v["value"] for k, v in raw["variables"].items()}
    check(current == values, "plan_variables")
    if "provider_attempts" in values:
        expressions = raw["configuration"]["provider_config"]["aws"]["expressions"]
        check(
            expressions["max_retries"]["references"] == ["var.provider_attempts"],
            "benchmark_provider_attempts_binding",
        )

    def after(address):
        return changes[address]["after"]

    vm = after("aws_instance.task[0]")
    if open_capacity:
        template = after("aws_launch_template.native_capacity")
        [placement] = template["placement"]
        [reservation] = template["capacity_reservation_specification"]
        instance_expr = next(
            row["expressions"]
            for row in raw["configuration"]["root_module"]["resources"]
            if row["address"] == "aws_instance.task"
        )
        [template_expr] = instance_expr["launch_template"]
        check(
            template["name"] == values["session"] + "-capacity"
            and template["tags"]["Session"] == values["session"]
            and placement["availability_zone"] == zone
            and placement["tenancy"] == "default"
            and template["ebs_optimized"] in (False, "false")
            and reservation["capacity_reservation_preference"]
            == "capacity-reservations-only"
            and not reservation.get("capacity_reservation_target")
            and template_expr["id"]["references"]
            == [
                "aws_launch_template.native_capacity.id",
                "aws_launch_template.native_capacity",
            ]
            and template_expr["version"]["constant_value"] == "1"
            and "capacity_reservation_specification" not in instance_expr,
            "capacity_template_binding",
        )
    disk = vm["root_block_device"][0]
    check(
        vm["instance_type"] == SHAPE
        and vm["ami"] == AMI
        and vm["instance_initiated_shutdown_behavior"] == "terminate"
        and vm["metadata_options"][0]["http_tokens"] == "required"
        and vm["associate_public_ip_address"]
        and disk["encrypted"]
        and disk["delete_on_termination"]
        and disk["volume_type"] == "gp3"
        and disk["volume_size"] == 128
        and disk["iops"] == 3000
        and disk["throughput"] == 125,
        "single_l4_shape",
    )
    marker = chr(36) + "{host_timer_seconds}"
    check(
        "systemctl enable --now dec077-terminate.timer" in userdata
        and "Persistent=true" in userdata
        and "shutdown -h now" in userdata
        and marker in userdata
        and vm["user_data"] == userdata.replace(marker, str(timer)),
        "timer",
    )
    group = next(
        resource
        for resource in raw["configuration"]["root_module"]["resources"]
        if resource["address"] == "aws_security_group.task"
    )
    check(
        after("aws_subnet.task[0]")["availability_zone"] == zone
        and not after("aws_security_group.task[0]").get("ingress")
        and "ingress" not in group["expressions"]
        and [row["cidr_block"] for row in after("aws_route_table.task[0]")["route"]]
        == ["0.0.0.0/0"]
        and after("aws_iam_role_policy_attachment.ssm[0]")["policy_arn"]
        == "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
        "route_security_or_iam",
    )


def verify_packet(root):
    root = Path(root).resolve()
    manifest = load(root / "manifest.json")
    native = benchmark.is_benchmark(manifest)
    check(
        manifest["schema"] in {SCHEMA, benchmark.SCHEMA}
        and re.fullmatch(r"[0-9a-f]{40}", manifest["source_commit"]),
        "manifest",
    )
    if native and "capacity_hunt" in manifest:
        from inf061_capacity import PRIMARY_ZONE, ROOTS

        alternatives = {
            f"{root}/{file}"
            for zone, root in ROOTS.items()
            if zone != PRIMARY_ZONE
            for file in (
                *TERRAFORM_FILES,
                "create.tfplan",
                "create.json",
                "input.tfvars.json",
            )
        }
    else:
        alternatives = set()
    check(
        manifest["artifacts"].keys()
        == (ARTIFACTS | benchmark.EXTRA | alternatives if native else ARTIFACTS),
        "artifact_set",
    )
    for relative, bound in manifest["artifacts"].items():
        check(facts(safe_file(root, relative)) == bound, "artifact_hash:" + relative)
    verify_engine(load(root / "engine.json"))
    check(load(root / "tools.json")["vllm"] == VLLM_IMAGE, "stager_image_digest")
    check(facts(root / LOG_CONFIG)["sha256"] == LOG_CONFIG_SHA, "logging_config")
    check(load(root / "requests.json") == request_manifest(), "requests")
    model = load(root / "model.json")
    check(
        model["revision"] == REVISION
        and sum(f["bytes"] for f in model["files"].values())
        == manifest["weight_bytes"],
        "model_size_revision",
    )
    blob = manifest["artifacts"][SOURCE_REF]
    check(
        blob
        == {"bytes": manifest["bundle_bytes"], "sha256": manifest["bundle_sha256"]},
        "bundle_binding",
    )
    sources = load(root / "sources.json")
    with tarfile.open(root / SOURCE_REF, mode="r:gz") as archive:
        names = archive.getnames()
        check(
            len(names) == len(set(names))
            and set(names) == sources.keys() | {"sources.json"},
            "bundle_members",
        )
        for member in archive:
            check(member.isfile(), "bundle_member_type")
            bound = (
                manifest["artifacts"]["sources.json"]
                if member.name == "sources.json"
                else sources[member.name]
            )
            check(member.size == bound["bytes"], "bundle_member_length")
            with archive.extractfile(member) as stream:
                check(
                    hashlib.file_digest(stream, "sha256").hexdigest()
                    == bound["sha256"],
                    "bundle_member_hash",
                )
    for name in (
        "engine.json",
        "model.json",
        "tools.json",
        "requests.json",
        LOG_CONFIG,
    ):
        check(
            sources[name] == manifest["artifacts"][name],
            "host_artifact_binding:" + name,
        )
    live = load(root / "live-inputs.json")
    rates = live["rates"]
    zone = ZONE
    if native:
        plan = load(root / "benchmark.json")
        zone = plan["zone"]
        check(
            zone in benchmark.GPU_ZONES and plan["session"] == manifest["session"],
            "benchmark_zone_session",
        )
        for name in benchmark.EXTRA:
            check(
                sources[name] == manifest["artifacts"][name], "benchmark_host_binding"
            )
        check(
            plan["quality"]["source_sha256"]
            == manifest["artifacts"]["quality.jsonl"]["sha256"],
            "quality_binding",
        )
        hunt = manifest.get("capacity_hunt")
        check(bool(hunt) == bool(plan.get("capacity_hunt")), "capacity_binding")
        if hunt is not None:
            from inf061_capacity import PRIMARY_ZONE, validate_binding

            check(
                zone == PRIMARY_ZONE and hunt["options"] == plan["capacity_hunt"],
                "capacity_primary_binding",
            )
            validate_binding(root, manifest)
        expected = benchmark.budget(plan, rates)
    else:
        expected = budget(
            blob["bytes"],
            manifest["source_floor_bps"],
            manifest["weight_bytes"],
            manifest["weights_floor_bps"],
            rates,
        )
    check(zone == live["zone"] == manifest["zone"], "gpu_zone_binding")
    check(manifest["hard_cap_usd"] >= expected["forecast_usd"], "over_cap")
    check(all(manifest[k] == v for k, v in expected.items()), "budget_binding")
    cfg = load(root / "terraform/input.tfvars.json")
    check(
        cfg
        == {
            "enable_task": True,
            "ami": AMI,
            "instance_type": SHAPE,
            "root_gib": 128,
            "host_timer_seconds": expected["host_timer_seconds"],
            "session": manifest["session"],
            "source_sha256": manifest["artifacts"]["sources.json"]["sha256"],
            **({"provider_attempts": benchmark.APPLY_ATTEMPTS} if native else {}),
        },
        "terraform_inputs",
    )
    check(
        manifest["sealed_plans"]["create_sha256"]
        == manifest["artifacts"]["terraform/create.tfplan"]["sha256"],
        "plan_binary_hash",
    )
    verify_plan(
        load(root / "terraform/create.json"),
        cfg,
        (root / "terraform/user-data.sh").read_text(encoding="utf-8"),
        timer=expected["host_timer_seconds"],
        zone=zone,
        open_capacity="capacity_hunt" in manifest,
    )
    return manifest
