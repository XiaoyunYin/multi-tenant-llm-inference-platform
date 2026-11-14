"""DEC-077 exact-plan preparation and SSM paid lifecycle (Apply marker gated)."""

import argparse
import ast
import base64
import hashlib
import http.client
import json
import math
import os
import re
import secrets
import shlex
import shutil
import subprocess
import tempfile
import time
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

from . import package_a_cloud as package_a_cloud_module
from .package_a_cloud import (
    APPLY_S,
    CAP_USD,
    CLEANUP_S,
    COST_FIXED_USD,
    CPU_VALIDATION_CHECKS,
    DEADLINE_S,
    EXPORT_MAX_BYTES,
    HOST_TIMER_S,
    INSTANCE_TYPE,
    PRIOR_SPEND_USD,
    TASK_CHECKS,
    Lifecycle,
    run_exe,
    save,
    selected_checks,
    sha,
    timing_worksheet,
    transfer_seconds,
    utc,
)
from .package_a_images import KIND_LOCAL_IMAGE_TAGS
from .package_a_secrets import control_token
from .r1_cloud_operator import (
    Operator,
    aws_cli_argv,
    ssm_send_command_args,
    windows_command_line_length,
)
from .session_stop import pid_is_running, stop_forward

ROOT = Path(__file__).resolve().parents[3]
SPEND_LEDGER_PATH = ROOT / "docs/evidence/m5-package-a/spend-ledger.json"
WINDOWS_COMMAND_LINE_LIMIT = 30_000
SSM_PARAMETER_BYTES_LIMIT = 60_000


def ssm_registration_window_s(manifest):
    """Give Gate A's endpoint-dependent hosts a longer registration window."""
    return (
        600
        if manifest.get("workload") in {"r366-gate-a", "routine-tests", "m5-descriptive"}
        else 180
    )


def operator_aws_cli_pairs():
    """Collect literal service/operation pairs used by the operator modules."""
    paths = (
        Path(__file__),
        Path(__file__).with_name("r1_cloud_operator.py"),
    )
    pairs = set()
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or len(node.args) < 2:
                continue
            function = node.func
            is_operation_call = (
                isinstance(function, ast.Attribute) and function.attr in {"aws", "_tagged"}
            ) or (
                path.name == "r1_cloud_operator.py"
                and isinstance(function, ast.Name)
                and function.id == "aws"
            )
            if not is_operation_call:
                continue
            service, operation = node.args[:2]
            if (
                isinstance(service, ast.Constant)
                and isinstance(service.value, str)
                and isinstance(operation, ast.Constant)
                and isinstance(operation.value, str)
            ):
                pairs.add((service.value, operation.value))
    return tuple(sorted(pairs))


def gate_a_command_line_records(directory, manifest):
    """Size all Gate A SSM command lines with the actual bootstrap and token shape."""
    source = (ROOT / "scripts/package_a_host.py").read_bytes()
    token = "0" * 64
    manifest_hash = "f" * 64
    deadline = 9_999_999_999
    parameters = [
        (
            "receiver.readiness",
            "i-00000000000000000",
            {"commands": gate_a_readiness_shell(receiver=True), "executionTimeout": ["300"]},
        ),
        (
            "sender.readiness",
            "i-00000000000000000",
            {"commands": gate_a_readiness_shell(), "executionTimeout": ["300"]},
        ),
        *[
            (
                f"{role}.bootstrap",
                "i-00000000000000000",
                {
                    "commands": bootstrap_shell(source, token, manifest_hash, deadline),
                    "executionTimeout": ["60"],
                },
            )
            for role in ("receiver", "sender")
        ],
    ]
    parameters.append(
        (
            "teardown.recovery-unmount",
            "i-00000000000000000",
            {
                "commands": [
                    "set -eu; sync; mountpoint -q /recovery && umount /recovery; ! mountpoint -q /recovery"
                ]
            },
        )
    )
    runtime = Path(directory) / "operator"
    path = runtime / "ssm-parameters-0123456789abcdef.json"
    inputs = {"aws_profile": "admin-learning", "region": manifest.get("region", "us-east-1")}
    records = []
    for step, host, value in parameters:
        args = ssm_send_command_args(host, path)
        argv = aws_cli_argv(inputs, "ssm", "send-command", args)
        length = windows_command_line_length(argv)
        parameter_bytes = len(json.dumps(value).encode("utf-8"))
        records.append(
            {
                "step": step,
                "argv_length": length,
                "parameter_bytes": parameter_bytes,
            }
        )
        if length >= WINDOWS_COMMAND_LINE_LIMIT:
            raise ValueError(f"gate_a_packet:windows_command_line:{step}:{length}")
        if parameter_bytes >= SSM_PARAMETER_BYTES_LIMIT:
            raise ValueError(f"gate_a_packet:ssm_parameter_bytes:{step}:{parameter_bytes}")
    return records


def cpu_command_line_records(directory, manifest):
    """Apply the R459/R462 limits to the unchanged single-host launchers."""
    source = (ROOT / "scripts/package_a_host.py").read_bytes()
    if source != git("show", manifest["source_commit"] + ":scripts/package_a_host.py"):
        raise ValueError("cpu_packet:host_source_changed")
    inputs = {"aws_profile": "admin-learning", "region": manifest["region"]}
    path = Path(directory) / "operator/ssm-parameters-0123456789abcdef.json"
    rows = []
    for step, commands, timeout in (
        ("readiness", readiness_shell(), "300"),
        ("bootstrap", bootstrap_shell(source, "0" * 64, "f" * 64, 9_999_999_999), "60"),
    ):
        value = {"commands": commands, "executionTimeout": [timeout]}
        argv = aws_cli_argv(
            inputs, "ssm", "send-command", ssm_send_command_args("i-00000000000000000", path)
        )
        length = windows_command_line_length(argv)
        size = len(json.dumps(value).encode("utf-8"))
        if length >= WINDOWS_COMMAND_LINE_LIMIT:
            raise ValueError("cpu_packet:windows_command_line:" + step)
        if size >= SSM_PARAMETER_BYTES_LIMIT:
            raise ValueError("cpu_packet:ssm_parameter_bytes:" + step)
        rows.append({"step": step, "argv_length": length, "parameter_bytes": size})
    return rows


def cpu_cli_preflight(executable, directory):
    rows = []
    for index, (service, operation) in enumerate(operator_aws_cli_pairs()):
        result = run_exe(
            [str(executable), service, operation, "--generate-cli-skeleton"],
            cwd=ROOT,
            output=Path(directory) / f"aws-cli-parse-{index:02}.log",
            timeout=30,
            env={**os.environ, "AWS_EC2_METADATA_DISABLED": "true"},
        )
        if result["exit"] != 0:
            raise ValueError("cpu_packet:aws_cli_parse:" + service + ":" + operation)
        rows.append({"service": service, "operation": operation, **result})
    return rows


def git(*argv, repo=ROOT):
    return subprocess.check_output(["git", "-C", str(repo), *argv])


def python_hashes(commit):
    names = git("ls-tree", "-r", "--name-only", "-z", commit, "python")
    return {
        name.decode(): hashlib.sha256(git("show", commit + ":" + name.decode())).hexdigest()
        for name in names.split(b"\0")
        if name
    }


def presigned_s3_get(operator_ports, bucket, key, expires_in):
    """Sign the exact input object in memory; never persist or log the URL."""
    import boto3
    from botocore.config import Config

    region = operator_ports.manifest.get("region", "us-east-1")
    session = boto3.Session(
        profile_name=operator_ports.inputs["aws_profile"],
        region_name=region,
    )
    client = session.client("s3", region_name=region, config=Config(signature_version="s3v4"))
    url = client.generate_presigned_url(
        "get_object",
        Params={"Bucket": bucket, "Key": key},
        ExpiresIn=expires_in,
        HttpMethod="GET",
    )
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.query or parsed.fragment:
        raise ValueError("gate_a_input_s3_presign_invalid")
    return url


def gate_a_pre_p_operation_window(operator_ports, end, now):
    manifest = operator_ports.manifest
    operation = manifest.get("gate_a_operation", {})
    operation_ms = operation.get("operation_pass_max_ms")
    retrieval_reserve = manifest.get("retrieval_timeout_s")
    cleanup_reserve = manifest.get("cleanup_seconds")
    lifecycle_deadline = getattr(operator_ports, "lifecycle_deadline_epoch", None)
    if (
        isinstance(operation_ms, bool)
        or not isinstance(operation_ms, int)
        or operation_ms <= 0
        or isinstance(retrieval_reserve, bool)
        or not isinstance(retrieval_reserve, (int, float))
        or retrieval_reserve < 0
        or isinstance(cleanup_reserve, bool)
        or not isinstance(cleanup_reserve, (int, float))
        or cleanup_reserve < 0
        or isinstance(lifecycle_deadline, bool)
        or not isinstance(lifecycle_deadline, (int, float))
    ):
        raise ValueError("gate_a_input_operation_reserve_config")
    operation_s = operation_ms / 1000
    required_remaining = operation_s + retrieval_reserve + cleanup_reserve
    remaining = lifecycle_deadline - now
    if remaining < required_remaining or end - now < operation_s:
        raise TimeoutError("gate_a_input_operation_window")
    return {
        "operation_window_required_s": required_remaining,
        "remaining_lifecycle_s_before_P": remaining,
    }


def gate_a_remote_input_paths(paths):
    """Map staged logical inputs to absolute Linux paths for the remote role."""
    if not isinstance(paths, dict):
        raise ValueError("gate_a:input_paths")
    input_root = PurePosixPath("/opt/dec077/gate-a-inputs")
    input_fields = {
        "source_path": "source",
        "fixture_proof_path": "fixture_proof",
        "sizing_proof_path": "sizing_proof",
        "spool_path": "spool",
        "spool_manifest_path": "spool_manifest",
        "specs_path": "sanitizer_specs",
        "sanitizer_key_path": "sanitizer_key",
        "expected_archive_inventory_path": "expected_archive_inventory",
    }
    result = {}
    for field, logical in input_fields.items():
        name = paths.get(logical)
        if not isinstance(name, str) or not name or "\\" in name:
            raise ValueError("gate_a:input_path:" + logical)
        relative = PurePosixPath(name)
        if relative.is_absolute() or ".." in relative.parts or not relative.parts:
            raise ValueError("gate_a:input_path:" + logical)
        result[field] = (input_root / relative).as_posix()
    return result


def validate_prior_spend_ledger(root=None, ledger_path=None):
    """Require every consumed packet under .cache to have one ledger classification."""
    root = Path(root or ROOT).resolve()
    ledger_path = Path(ledger_path or SPEND_LEDGER_PATH)
    try:
        ledger = json.loads(ledger_path.read_bytes())
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("prior_spend_ledger_unreadable") from exc
    entries = ledger.get("entries") if isinstance(ledger, dict) else None
    if not isinstance(entries, list):
        raise ValueError("prior_spend_ledger_invalid")

    classified = {}
    paid_rows = []
    allowed = {"dec077_paid", "other_cap", "not_paid"}
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or entry.get("classification") not in allowed:
            raise ValueError(f"prior_spend_ledger_invalid_entry:{index}")
        packet_dirs = entry.get("packet_dirs")
        if packet_dirs is None:
            packet_dirs = [entry.get("packet_dir")]
        if not packet_dirs or any(not isinstance(value, str) or not value for value in packet_dirs):
            raise ValueError(f"prior_spend_ledger_invalid_entry:{index}")
        for packet_dir in packet_dirs:
            normalized = Path(packet_dir).as_posix()
            if normalized in classified:
                raise ValueError(f"prior_spend_ledger_duplicate:{normalized}")
            classified[normalized] = entry["classification"]
        if entry["classification"] == "dec077_paid":
            paid_rows.append(entry)
        elif entry["classification"] == "other_cap" and not entry.get("governing_dec"):
            raise ValueError(f"prior_spend_ledger_missing_dec:{index}")
        elif entry["classification"] == "not_paid" and not entry.get("reason"):
            raise ValueError(f"prior_spend_ledger_missing_reason:{index}")

    cache = root / ".cache"
    consumed_dirs = set()
    if cache.is_dir():
        for current, directories, files in os.walk(cache):
            current_path = Path(current)
            if (
                current_path != cache
                and (current_path / "PLAN.md").is_file()
                and (current_path / "REVIEW.md").is_file()
            ):
                directories.clear()
                continue
            directories[:] = [
                name for name in directories if name not in {".git", ".venv", "node_modules"}
            ]
            if "consumed.json" in files:
                consumed_dirs.add(current_path.relative_to(root).as_posix())
    missing = sorted(consumed_dirs - classified.keys())
    if missing:
        raise ValueError("prior_spend_ledger_incomplete:" + ",".join(missing))

    try:
        paid_total = sum(float(entry["task_cost_usd"]) for entry in paid_rows)
        declared_prior = float(ledger["prior_spend_usd"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("prior_spend_ledger_invalid_paid_total") from exc
    canonical_prior = float(package_a_cloud_module.PRIOR_SPEND_USD)
    if not math.isclose(paid_total, declared_prior, rel_tol=0.0, abs_tol=1e-9) or not math.isclose(
        declared_prior, canonical_prior, rel_tol=0.0, abs_tol=1e-9
    ):
        raise ValueError("prior_spend_ledger_total_mismatch")
    return ledger


def sealed_command(
    directory, name, *, module="/repo/infra/terraform/package_a", expected_managed=10, gate_a=False
):
    command = [
        "docker",
        "create",
        "--name",
        name,
        "--network",
        "none",
        "--memory",
        "768m",
        "--memory-swap",
        "768m",
        "--cpus",
        "2",
        "--pids-limit",
        "128",
        "--mount",
        f"type=bind,source={ROOT},target=/repo,readonly",
        "--mount",
        f"type=bind,source={directory},target=/packet",
        "python:3.12.7-slim-bookworm@sha256:60d9996b6a8a3689d36db740b49f4327be3be09a21122bd02fb8895abb38b50d",
        "python",
        "/repo/scripts/package_a_sealed.py",
        "--module",
        module,
        "--expected-managed",
        str(expected_managed),
    ]
    if gate_a:
        command.append("--gate-a")
    return command


def validate_real_dependency_preflight_receipt(receipt, commit):
    """Reject incomplete $0 Redis/race/image-resolution evidence before planning."""
    receipt = receipt if isinstance(receipt, dict) else {}
    from inference_platform.package_a_workload import validate_workload_preflight

    validate_workload_preflight(receipt)
    validate_kind_no_cluster_receipt(receipt.get("kind_no_cluster", {}))
    images = receipt.get("images")
    go = receipt.get("go_real_redis")
    race = receipt.get("go_real_redis_race")
    e2e = receipt.get("gateway_redis_e2e")
    validate_linux_e2e_receipt(e2e)
    redis_cleanup = receipt.get("redis_cleanup")
    resolution = receipt.get("containerd_image_resolution")
    resolved_images = resolution.get("images") if isinstance(resolution, dict) else None
    control = resolution.get("control") if isinstance(resolution, dict) else None
    control_inspect = control.get("inspect") if isinstance(control, dict) else None
    control_import = control.get("import") if isinstance(control, dict) else None
    container_name = resolution.get("container_name") if isinstance(resolution, dict) else None
    node_image = resolution.get("node_image") if isinstance(resolution, dict) else None
    start = resolution.get("start") if isinstance(resolution, dict) else None
    ready = resolution.get("ready") if isinstance(resolution, dict) else None
    expected_start = [
        "docker",
        "run",
        "--detach",
        "--rm",
        "--privileged",
        "--memory",
        "512m",
        "-v",
        "/var/lib/containerd",
        "--name",
        container_name,
        "--entrypoint",
        "containerd",
        node_image,
    ]
    expected_import = [
        "docker",
        "exec",
        "-i",
        container_name,
        "ctr",
        "--namespace=k8s.io",
        "images",
        "import",
        "--all-platforms",
        "--digests",
        "--snapshotter=overlayfs",
        "-",
    ]
    if (
        receipt.get("schema") != "dec077-real-dependency-preflight-v1"
        or receipt.get("complete") is not True
        or receipt.get("billable_actions") != 0
        or receipt.get("source_head") != commit
        or receipt.get("zero_skips") is not True
        or not isinstance(go, dict)
        or go.get("complete") is not True
        or go.get("passed_tests", 0) < 1
        or go.get("skipped_tests") != 0
        or not isinstance(race, dict)
        or race.get("complete") is not True
        or race.get("exit_code") != 0
        or race.get("passed_tests", 0) < 1
        or race.get("skipped_tests") != 0
        or not isinstance(e2e, dict)
        or e2e.get("passed_tests") != 1
        or e2e.get("skipped_tests") != 0
        or not isinstance(images, dict)
        or set(images) != set(KIND_LOCAL_IMAGE_TAGS)
        or any(
            not isinstance(item, dict)
            or item.get("complete") is not True
            or item.get("platform") != "linux/amd64"
            or item.get("local_tag") != KIND_LOCAL_IMAGE_TAGS[name]
            or not isinstance(item.get("pinned_reference"), str)
            or not re.search(r"@sha256:[0-9a-f]{64}$", item.get("pinned_reference", ""))
            or not isinstance(item.get("config_digest"), str)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", item["config_digest"])
            or not isinstance(item.get("commands"), list)
            or len(item["commands"]) < 3
            for name, item in images.items()
        )
        or not isinstance(redis_cleanup, dict)
        or redis_cleanup.get("container_removed") is not True
        or not isinstance(resolution, dict)
        or resolution.get("schema") != "dec077-containerd-image-resolution-v1"
        or resolution.get("complete") is not True
        or resolution.get("container_removed") is not True
        or not isinstance(container_name, str)
        or not container_name
        or node_image != json.loads((ROOT / "deploy/k8s/pins.json").read_bytes())["node_image"]
        or not isinstance(start, dict)
        or start.get("exit_code") != 0
        or start.get("command") != expected_start
        or not isinstance(ready, dict)
        or ready.get("exit_code") != 0
        or ready.get("command") != ["docker", "exec", container_name, "ctr", "version"]
        or not isinstance(resolution.get("cleanup"), dict)
        or resolution["cleanup"].get("exit_code") != 0
        or resolution["cleanup"].get("command") != ["docker", "rm", "-f", container_name]
        or not isinstance(resolved_images, dict)
        or set(resolved_images) != set(images)
        or not isinstance(control, dict)
        or control.get("expected_failure") is not True
        or not isinstance(control_inspect, dict)
        or control_inspect.get("exit_code", 0) == 0
        or not isinstance(control_import, dict)
        or control_import.get("exit_code") != 0
        or not isinstance(control.get("archive_path"), str)
        or not isinstance(control.get("archive_sha256"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", control["archive_sha256"])
        or not isinstance(control.get("export_commands"), list)
        or len(control["export_commands"]) < 3
    ):
        raise ValueError("real_dependency_preflight_incomplete_or_wrong_head")
    for name, image in images.items():
        resolved = resolved_images[name]
        if (
            not isinstance(resolved, dict)
            or resolved.get("local_tag") != image["local_tag"]
            or resolved.get("pinned_reference") != image["pinned_reference"]
            or resolved.get("config_digest") != image["config_digest"]
            or resolved.get("archive_sha256") != image.get("sha256")
            or resolved.get("import", {}).get("exit_code") != 0
            or resolved.get("import", {}).get("command") != expected_import
            or resolved.get("inspect", {}).get("exit_code") != 0
            or resolved.get("inspect", {}).get("command")
            != ["docker", "exec", container_name, "crictl", "inspecti", image["local_tag"]]
            or resolved.get("inspect", {}).get("resolved_image_id") != image["config_digest"]
        ):
            raise ValueError("containerd_image_resolution_mismatch:" + name)
    if control_import.get("command") != expected_import or control_inspect.get("command") != [
        "docker",
        "exec",
        container_name,
        "crictl",
        "inspecti",
        control["pinned_reference"],
    ]:
        raise ValueError("containerd_digest_control_command_mismatch")
    return True


def validate_linux_e2e_receipt(e2e):
    from .package_a_images import LINUX_E2E_IMAGE

    e2e = e2e if isinstance(e2e, dict) else {}
    build = e2e.get("build", {})
    if (
        e2e.get("runtime") != "linux-container"
        or e2e.get("python_image") != LINUX_E2E_IMAGE
        or e2e.get("container_removed") is not True
        or not isinstance(build, dict)
        or build.get("exit_code") != 0
        or [build.get(k) for k in ("GOOS", "GOARCH", "CGO_ENABLED")] != ["linux", "amd64", "0"]
        or not re.fullmatch(r"[0-9a-f]{64}", build.get("binary_sha256", ""))
    ):
        raise ValueError("linux_e2e_preflight_unverified")


def bind_linux_e2e_files(e2e, root):
    for evidence in (e2e["build"], e2e["cleanup"], e2e["verify_removed"]):
        path = (root / evidence.get("log", "")).resolve()
        if (
            root not in path.parents
            or not path.is_file()
            or sha(path) != evidence.get("log_sha256")
        ):
            raise ValueError("linux_e2e_log_missing_or_changed")
    binary = (root / e2e["build"].get("binary_path", "")).resolve()
    if (
        root not in binary.parents
        or not binary.is_file()
        or sha(binary) != e2e["build"]["binary_sha256"]
    ):
        raise ValueError("linux_e2e_binary_missing_or_changed")


def sealed_plans(
    directory,
    *,
    module=None,
    expected_managed=10,
    gate_a=False,
):
    """Stage large immutable archives through Docker's API, not Windows mmap."""
    name = "dec077-sealed-" + secrets.token_hex(6)
    try:
        run_exe(
            sealed_command(
                directory,
                name,
                module=module or "/repo/infra/terraform/package_a",
                expected_managed=expected_managed,
                gate_a=gate_a,
            ),
            cwd=ROOT,
            output=directory / "sealed-create.log",
            timeout=60,
        )
        for label, source, target in (
            ("mirror", ROOT / ".cache/m5-provider-mirror", "/mirror"),
            ("terraform", ROOT / ".cache/terraform_1.16.2_linux_amd64.zip", "/terraform.zip"),
        ):
            size = (
                sum(p.stat().st_size for p in source.rglob("*") if p.is_file())
                if source.is_dir()
                else source.stat().st_size
            )
            run_exe(
                ["docker", "cp", str(source), name + ":" + target],
                cwd=ROOT,
                output=directory / ("sealed-copy-" + label + ".log"),
                timeout=transfer_seconds(size),
            )
        return run_exe(
            ["docker", "start", "-a", name], cwd=ROOT, output=directory / "sealed.log", timeout=600
        )
    finally:
        run_exe(
            ["docker", "rm", "-f", name],
            cwd=ROOT,
            output=directory / "sealed-remove.log",
            timeout=30,
        )


def validate_workload_preflight_files(receipt, root):
    """Rehash workload inputs and every execution/answer/cleanup output before prepare."""
    expected = {
        "workload-manifest.json",
        "gateway-env.json",
        "cache-salt.secret",
        "nginx.conf",
        "nginx-answer.json",
        "nginx-receipt.json",
    }
    files = receipt.get("workload_files_sha256", {})
    if set(files) != expected:
        raise ValueError("workload_preflight_files_missing")
    records = [receipt["gateway_config"]] + [
        receipt["nginx_start"].get(name, {})
        for name in ("start", "inspect", "logs", "cleanup", "verify_removed")
    ]
    for record in records:
        if not record.get("log"):
            raise ValueError("workload_preflight_log_missing")
        files = {**files, record["log"]: record.get("log_sha256")}
    for name, expected_hash in files.items():
        path = (root / name).resolve()
        if root not in path.parents or not path.is_file() or sha(path) != expected_hash:
            raise ValueError("workload_preflight_file_changed:" + name)


def validate_kind_no_cluster_receipt(record):
    pins = json.loads((ROOT / "deploy/k8s/pins.json").read_bytes())
    if not isinstance(record, dict):
        raise ValueError("kind_no_cluster_receipts_required")
    files = record.get("files_sha256")
    if not isinstance(files, dict):
        raise ValueError("kind_no_cluster_receipts_required")
    platform = "windows" if os.name == "nt" else "linux"
    if (
        record.get("schema") != "package-a-kind-no-cluster-v1"
        or record.get("complete") is not True
        or record.get("billable_actions") != 0
        or record.get("skipped_tests") != 0
        or record.get("coverage_percent") != 100
        or record.get("line_coverage_percent") != 100
        or record.get("kubectl_sha256") != pins[f"kubectl_{platform}_amd64_sha256"]
        or record.get("rehearsal_sha256") != sha(ROOT / "scripts/rehearse_eks_package_a.py")
        or not {"api/transcript.json", "walk/coverage.json", "walk/success/receipt.json"}.issubset(
            files
        )
    ):
        raise ValueError("kind_no_cluster_receipts_required")


def bind_workload_preflight(receipt, root):
    """Revalidate workload evidence before prepare can create a source bundle."""
    validate_workload_preflight_files(receipt, root)
    record = receipt.get("kind_no_cluster", {})
    validate_kind_no_cluster_receipt(record)
    kind_root = (root / "kind-no-cluster").resolve()
    for name, expected in record["files_sha256"].items():
        path = (kind_root / name).resolve()
        if kind_root not in path.parents or not path.is_file() or sha(path) != expected:
            raise ValueError("kind_no_cluster_file_changed:" + name)
    api = json.loads((kind_root / "api/transcript.json").read_bytes())
    walk = json.loads((kind_root / "walk/coverage.json").read_bytes())
    success = json.loads((kind_root / "walk/success/receipt.json").read_bytes())
    if (
        api.get("complete") is not True
        or api.get("kubectl_sha256") != record["kubectl_sha256"]
        or walk.get("coverage_percent") != 100
        or walk.get("line_coverage_percent") != 100
        or walk.get("missing_statement_lines") != []
        or walk.get("missing_executable_lines") != []
        or walk.get("source_sha256") != record["rehearsal_sha256"]
        or success.get("error")
        or success.get("replacement_and_prior_template_rollback") is not True
        or success.get("owned_cluster_cleanup_verified") is not True
    ):
        raise ValueError("kind_no_cluster_evidence_incomplete")


def validate_host_refresh(refresh):
    if (
        refresh["instance_type"] != INSTANCE_TYPE
        or refresh["memory_mib"] != 16384
        or refresh["vcpus"] != 8
    ):
        raise ValueError("host_shape_refresh")


def host_check_preflight_binding(checks):
    if checks not in (TASK_CHECKS, CPU_VALIDATION_CHECKS):
        raise ValueError("real_dependency_preflight_required")
    return {
        "status": "REPLACED_BY_HOST_CHECKS",
        "host_checks": list(checks),
        "authority": (
            "Claude Round 344 (DEC-041/DEC-087; DEC-093 note)"
            if checks == CPU_VALIDATION_CHECKS
            else "Claude Round 290 (DEC-041/DEC-087; DEC-093 note)"
        ),
    }


def validated_preflight_binding(preflight, commit):
    preflight_path = Path(preflight).resolve()
    try:
        preflight_path.relative_to(ROOT)
    except ValueError as exc:
        raise ValueError("preflight_receipt_must_be_inside_repository") from exc
    preflight_receipt = json.loads(preflight_path.read_bytes())
    validate_real_dependency_preflight_receipt(preflight_receipt, commit)
    preflight_root = preflight_path.parent
    for section in (
        "go_real_redis",
        "go_real_redis_race",
        "gateway_build",
        "gateway_redis_e2e",
        "gateway_config",
    ):
        evidence = preflight_receipt.get(section, {})
        evidence_path = (preflight_root / evidence.get("log", "")).resolve()
        if (
            not evidence.get("log")
            or preflight_root not in evidence_path.parents
            or not evidence_path.is_file()
            or sha(evidence_path) != evidence.get("log_sha256")
        ):
            raise ValueError("preflight_log_missing_or_changed:" + section)
    bind_linux_e2e_files(preflight_receipt["gateway_redis_e2e"], preflight_root)
    bind_workload_preflight(preflight_receipt, preflight_root)
    containerd = preflight_receipt["containerd_image_resolution"]
    containerd_logs = [
        containerd.get("start", {}),
        containerd.get("ready", {}),
        containerd.get("cleanup", {}),
        *(
            evidence
            for image in containerd["images"].values()
            for evidence in (
                *image.get("export_commands", []),
                image.get("import", {}),
                image.get("inspect", {}),
            )
        ),
        containerd["control"].get("import", {}),
        containerd["control"].get("inspect", {}),
        *containerd["control"].get("export_commands", []),
    ]
    if containerd.get("verify_removed"):
        containerd_logs.append(containerd["verify_removed"])
    for evidence in containerd_logs:
        evidence_path = (preflight_root / evidence.get("log", "")).resolve()
        if (
            not evidence.get("log")
            or preflight_root not in evidence_path.parents
            or not evidence_path.is_file()
            or sha(evidence_path) != evidence.get("log_sha256")
        ):
            raise ValueError("containerd_preflight_log_missing_or_changed")
    for name, image in preflight_receipt["images"].items():
        archive_path = (preflight_root / image["archive_path"]).resolve()
        if (
            preflight_root not in archive_path.parents
            or not archive_path.is_file()
            or sha(archive_path) != image.get("sha256")
        ):
            raise ValueError("preflight_image_archive_missing_or_changed:" + name)
    control_path = (preflight_root / containerd["control"]["archive_path"]).resolve()
    if (
        preflight_root not in control_path.parents
        or not control_path.is_file()
        or sha(control_path) != containerd["control"].get("archive_sha256")
    ):
        raise ValueError("preflight_digest_control_archive_missing_or_changed")
    return {
        "receipt_path": preflight_path.relative_to(ROOT).as_posix(),
        "receipt_sha256": sha(preflight_path),
        "source_head": preflight_receipt["source_head"],
        "go_real_redis": preflight_receipt["go_real_redis"],
        "go_real_redis_race": preflight_receipt.get("go_real_redis_race"),
        "gateway_redis_e2e": preflight_receipt["gateway_redis_e2e"],
        "images": preflight_receipt["images"],
        "containerd_image_resolution": containerd,
        "gateway_config": preflight_receipt["gateway_config"],
        "nginx_start": preflight_receipt["nginx_start"],
        "workload_files_sha256": preflight_receipt["workload_files_sha256"],
        "kind_no_cluster": preflight_receipt["kind_no_cluster"],
    }


def prepare(directory, refresh, *, commit=None, preflight=None, checks=TASK_CHECKS):
    selected_checks(checks)
    validate_prior_spend_ledger(ROOT)
    directory = Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=False)
    commit = commit or git("rev-parse", "HEAD").decode().strip()
    if preflight is None:
        preflight_binding = host_check_preflight_binding(checks)
    else:
        preflight_binding = validated_preflight_binding(preflight, commit)
    refresh = json.loads(Path(refresh).read_bytes())
    validate_host_refresh(refresh)
    if (
        "us-east-1a" not in refresh["availability_zones"]
        or refresh["standard_vcpu_quota"] < 8
        or refresh["active_instance_count"]
    ):
        raise ValueError("offering_or_quota_or_active_usage")
    shallow = directory / "shallow.git"
    git(
        "clone",
        "--bare",
        "--no-local",
        "--depth",
        "1",
        "--branch",
        "main",
        ROOT.as_uri(),
        str(shallow),
    )
    if git("rev-parse", "HEAD", repo=shallow).decode().strip() != commit:
        raise ValueError("source_moved_during_bundle")
    bundle = directory / "source.bundle"
    git("bundle", "create", str(bundle), "--all", repo=shallow)
    git("bundle", "verify", str(bundle))
    tree_bytes = sum(
        int(row.split()[3]) for row in git("ls-tree", "-rl", commit).decode().splitlines()
    )
    # Real base image and kind layer sizes from read-only registry/local inspect;
    # data uses the observed full export bytes, conservatively expanded for both
    # source/materialization copies. Both sizing scratch trees are serial.
    # The containerd image-store API reports compressed Size. Budget four copies
    # of those actual bytes for unpacking/layer work, plus three node filesystems.
    image_bytes = 4 * sum(refresh["image_bytes"].values())
    data_bytes = refresh["observed_export_bytes"] * 6
    worksheet = {
        "source_tree_bytes": tree_bytes,
        "bundle_bytes": bundle.stat().st_size,
        "images_bytes": image_bytes,
        "kind_three_nodes_bytes": 12 * refresh["image_bytes"]["node"],
        "data_scratch_bytes": data_bytes,
        "os_tools_caches_reserve_bytes": 24 * 1024**3,
    }
    if tuple(checks) == CPU_VALIDATION_CHECKS:
        # One stage copy at a time: tracked bytes, shallow Git objects and
        # 16 MiB metadata margin. Seed/build caches use the existing 24 GiB
        # OS/tools/cache reserve; image archives are never copied.
        worksheet["cpu_stage_source_copy_bytes"] = tree_bytes + bundle.stat().st_size + 16 * 1024**2
    minimum = sum(worksheet.values()) * 1.25
    root_gib = max(64, math.ceil(minimum / 1024**3 / 8) * 8)
    if root_gib > 100 or bundle.stat().st_size > 256 * 1024**2:
        raise ValueError("storage_or_bundle_bound")
    hourly = (
        refresh["on_demand_usd_per_hour"]
        + refresh["ipv4_usd_per_hour"]
        + root_gib * refresh["gp3_usd_per_gib_month"] / 720
    )
    timing = timing_worksheet(
        bundle.stat().st_size,
        checks,
        hourly_all_resources_usd=hourly,
        prior_spend_usd=PRIOR_SPEND_USD,
        cleanup_cost_reserve_usd=1.0,
        cap_usd=CAP_USD,
    )
    task_cost = timing["cost_hours"] * hourly + COST_FIXED_USD
    cumulative_cost = PRIOR_SPEND_USD + task_cost
    if timing["cost_guard_margin_s"] <= 0:
        raise ValueError("cost_guard_budget_exceeds_guard_time")
    if cumulative_cost >= CAP_USD:
        raise ValueError("cost_forecast_cap")
    manifest = {
        "schema": "dec077-exact-inputs-v1",
        "created_at_utc": utc(),
        "source_commit": commit,
        "bundle_bytes": bundle.stat().st_size,
        "bundle_sha256": sha(bundle),
        "python_sha256": python_hashes(commit),
        "pins": json.loads((ROOT / "deploy/package-a/pins.json").read_bytes()),
        "instance_type": refresh["instance_type"],
        "ami": refresh["ami"],
        "region": "us-east-1",
        "on_demand_usd_per_hour": refresh["on_demand_usd_per_hour"],
        "hourly_all_resources_usd": hourly,
        "account_id_sha256": refresh["account_id_sha256"],
        "refresh": refresh,
        "root_gib": root_gib,
        "storage_worksheet": worksheet,
        "task_cost_usd": task_cost,
        "cumulative_cost_usd": cumulative_cost,
        "prior_spend_usd": PRIOR_SPEND_USD,
        "hard_cap_usd": CAP_USD,
        "ceiling_usd": 300,
        **timing,
        "retrieval_forecast_bytes": EXPORT_MAX_BYTES,
        "cleanup_cost_reserve_usd": 1.0,
        "python_executable": "/opt/dec077/repo/python/.venv/bin/python",
        "local_real_dependency_preflight": preflight_binding,
    }
    plugin = ROOT / ".cache/session-manager-plugin/bin/bin/session-manager-plugin.exe"
    manifest["operator_tools"] = {}
    for label, exe, argv in (
        ("aws", Path(shutil.which("aws") or "missing-aws"), ["--version"]),
        ("terraform", ROOT / ".tools/terraform/1.16.2/terraform.exe", ["version", "-json"]),
        ("plugin", plugin, ["--version"]),
    ):
        if not exe.is_file():
            raise ValueError("operator_tool_missing:" + label)
        result = run_exe(
            [exe, *argv], cwd=ROOT, output=directory / (label + "-version.log"), timeout=30
        )
        manifest["operator_tools"][label] = {
            "path": str(exe),
            "sha256": sha(exe),
            "version_log_sha256": result["log_sha256"],
        }
        if (
            label == "terraform"
            and json.loads((directory / (label + "-version.log")).read_bytes())["terraform_version"]
            != "1.16.2"
        ):
            raise ValueError("operator_terraform_version")
    manifest["session_manager_plugin_path"] = str(plugin.relative_to(ROOT))
    if tuple(checks) == CPU_VALIDATION_CHECKS:
        manifest["operator_command_line_preflight"] = cpu_command_line_records(directory, manifest)
        manifest["operator_aws_cli_preflight"] = cpu_cli_preflight(
            manifest["operator_tools"]["aws"]["path"], directory
        )
    variables = {
        "enable_task": True,
        "ami": manifest["ami"],
        "instance_type": manifest["instance_type"],
        "session": "dec077-20261019",
        "source_commit": commit,
        "root_gib": root_gib,
        "host_timer_seconds": HOST_TIMER_S,
    }
    save(directory / "input.tfvars.json", variables)
    sealed_plans(directory)
    manifest["sealed_plans"] = json.loads((directory / "sealed-plans.json").read_bytes())
    save(directory / "manifest.json", manifest)
    return manifest


def bootstrap_shell(source, token, manifest_hash, deadline):
    """All literal SSM shell strings are exercised under sh by the rehearsal."""
    return [
        "set -eu",
        "test -f /opt/dec077/user-data.done",
        "test -f /sys/fs/cgroup/cgroup.controllers",
        "printf %s "
        + shlex.quote(base64.b64encode(source).decode())
        + " | base64 -d > /opt/dec077/host.py",
        "nohup "
        + shlex.join(
            [
                "python3",
                "/opt/dec077/host.py",
                "--token",
                token,
                "--manifest-sha256",
                manifest_hash,
                "--deadline",
                str(deadline),
            ]
        )
        + " >/opt/dec077/host.log 2>&1 </dev/null &",
        "i=0; until curl -fsS --max-time 2 -H "
        + shlex.quote("Authorization: Bearer " + token)
        + " http://127.0.0.1:22280/status; do i=$((i+1)); test $i -lt 20 || exit 1; sleep 1; done",
    ]


def readiness_shell():
    return [
        "set -eu",
        "cloud-init status --wait",
        "systemctl is-active --quiet dec077-terminate.timer",
        "test -f /opt/dec077/user-data.done",
    ]


def gate_a_readiness_shell(*, receiver=False):
    commands = [
        "set -eu",
        "cloud-init status --wait",
        "systemctl is-active --quiet gate-a-maximum-lifetime.timer",
        "test -f /opt/dec077/user-data.done",
        "test -f /sys/fs/cgroup/cgroup.controllers",
    ]
    if receiver:
        commands.append("mountpoint -q /recovery")
    return commands


def render_user_data():
    return (
        (ROOT / "infra/terraform/package_a/user-data.sh")
        .read_text()
        .replace("${host_timer_seconds}", str(HOST_TIMER_S))
    )


def latest_claude_round(review):
    try:
        rounds = review.split("\n## Claude review rounds\n", 1)[1].split("\n## Findings\n", 1)[0]
    except IndexError as exc:
        raise ValueError("no_committed_review_round") from exc
    if "\n## Findings\n" not in review:
        raise ValueError("no_committed_findings_boundary")
    headings = list(re.finditer(r"(?m)^### Round (\d+)\b", rounds))
    if not headings:
        raise ValueError("no_committed_review_round")
    return rounds[headings[-1].start() :]


def claude_round_span(review):
    """Return the review-round body and its offsets in the full review file."""
    start_marker, end_marker = "\n## Claude review rounds\n", "\n## Findings\n"
    try:
        start = review.index(start_marker) + len(start_marker)
        end = review.index(end_marker, start)
    except ValueError as exc:
        raise ValueError("no_committed_review_round") from exc
    return start, end, review[start:end]


def validate_review_marker(review, required, *, prefix="DEC-077 CPU PLAN APPROVED"):
    rounds_start, rounds_end, rounds = claude_round_span(review)
    latest = latest_claude_round(review)
    marker_line = r"(?m)^- " + prefix + r"(?:[^\r\n]*)$"
    tuple_pattern = r"(?m)^- " + prefix + r" ([0-9a-f]{64}) ([0-9a-f]{64}) ([0-9a-f]{40})$"
    marker_lines = re.findall(marker_line, latest)
    expected_line = "- " + prefix + " " + " ".join(required)
    latest_start = rounds.rfind(latest)
    prior_rounds = rounds[:latest_start] if latest_start >= 0 else rounds
    outside_markers = re.findall(marker_line, review[:rounds_start] + review[rounds_end:])
    replayed_markers = [
        marker for marker in re.findall(tuple_pattern, prior_rounds) if marker == required
    ]
    if (
        marker_lines != [expected_line]
        or outside_markers
        or replayed_markers
        or re.search(r"(?m)^- Review basis: (?:\*\*)?COMMITTED\b", latest) is None
        or re.search(r"(?m)^- Verdict: (?:\*\*)?NO_BLOCKING_FINDINGS\b", latest) is None
    ):
        raise ValueError("committed_exact_plan_marker_required")


def require_marker(directory, manifest):
    require_loadable_packet(directory)
    plan = directory / "terraform/create.tfplan"
    expected = manifest["sealed_plans"]["create_sha256"]
    if sha(plan) != expected:
        raise ValueError("saved_plan_changed")
    # Review must be committed. Ignore the working copy and older rounds.
    review = git("show", "HEAD:REVIEW.md").decode()
    required = (expected, sha(directory / "manifest.json"), manifest["source_commit"])
    validate_review_marker(review, required)
    if (directory / "consumed.json").exists():
        raise ValueError("saved_plan_already_consumed")


def load_packet_manifest(directory):
    directory = Path(directory).resolve()
    require_loadable_packet(directory)
    return json.loads((directory / "manifest.json").read_bytes())


def require_loadable_packet(directory):
    directory = Path(directory)
    if ".refused-" in directory.name:
        raise ValueError("gate_a_packet:refused_directory")
    if not (directory / "manifest.json").is_file():
        raise ValueError("gate_a_packet:manifest_missing")


def executing_binding(directory, manifest):
    # Documentation descendants may carry Claude's marker; executing code must
    # remain exactly the committed bundle source, including staged/working bytes.
    paths = ("python", "scripts", "infra", "deploy", "internal", "cmd", "go.mod", "go.sum")
    git("diff", "--exit-code", manifest["source_commit"], "HEAD", "--", *paths)
    git("diff", "--exit-code", manifest["source_commit"], "--", *paths)
    if git("status", "--porcelain", "--untracked-files=all", "--", *paths):
        raise ValueError("executing_code_not_clean")
    for row in manifest["operator_tools"].values():
        if sha(row["path"]) != row["sha256"]:
            raise ValueError("operator_tool_changed")
    module = ROOT / (
        "infra/terraform/gate_a"
        if manifest.get("workload") == "r366-gate-a"
        else "infra/terraform/package_a"
    )
    for source in module.iterdir():
        if source.is_file() and sha(source) != sha(directory / "terraform" / source.name):
            raise ValueError("terraform_cleanup_configuration_changed")
    if (
        json.loads((directory / "terraform/input.tfvars.json").read_bytes())
        != manifest["sealed_plans"]["variables"]
    ):
        raise ValueError("terraform_cleanup_variables_changed")


class Ports(Operator):
    def __init__(
        self,
        directory,
        manifest,
        *,
        profile="admin-learning",
        recovering=False,
        runtime_directory=None,
        credential_directory=None,
        manifest_path=None,
    ):
        self.directory, self.manifest = Path(directory), manifest
        runtime_root = Path(runtime_directory) if runtime_directory else self.directory
        runtime = runtime_root / "operator"
        if recovering:
            runtime.mkdir(parents=True, exist_ok=True)
            runtime = Path(tempfile.mkdtemp(prefix="recovery-", dir=runtime))
        super().__init__(
            ROOT,
            {
                "aws_profile": profile,
                "region": "us-east-1",
                "session_manager_plugin_path": manifest["session_manager_plugin_path"],
            },
            runtime,
            time.time() + DEADLINE_S,
        )
        self.host, self.channel, self.child = None, None, None
        self.token_error = None
        self.registration_path = runtime_root / "operator/ssm-registration.json"
        self.ssm_online = False
        try:
            self.token = control_token(
                Path(credential_directory) if credential_directory else runtime_root,
                create=not recovering,
            )
        except (OSError, ValueError):
            if not recovering:
                raise
            self.token, self.token_error = None, "recovery_control_token_unavailable"
        self.reconnects = 0
        self.started = None
        self.manifest_path = (
            Path(manifest_path) if manifest_path else self.directory / "manifest.json"
        )
        self.manifest_bytes = self.manifest_path.read_bytes()
        if json.loads(self.manifest_bytes) != manifest:
            raise ValueError("manifest_changed_during_operator_start")
        self.manifest_hash = hashlib.sha256(self.manifest_bytes).hexdigest()
        # Keep reachability evidence at the persistent role root so cleanup
        # recovery can find it after creating a fresh temporary runtime.
        reachable = runtime_root / "operator/host-reachable.json"
        self.status_answered = False
        if recovering:
            try:
                self.ssm_online = (
                    json.loads(self.registration_path.read_bytes()).get("ping_status") == "Online"
                )
            except (OSError, ValueError, AttributeError):
                pass
            try:
                self.status_answered = (
                    json.loads(reachable.read_bytes()).get("manifest_sha256") == self.manifest_hash
                )
            except (OSError, ValueError, AttributeError):
                pass  # Missing/damaged evidence cannot delay cleanup.

    def remember_status(self):
        # Bootstrap's successful curl and RPC status are both actual answers.
        # Retain the fact across operator death without persisting credentials.
        if not self.status_answered:
            save(self.runtime / "host-reachable.json", {"manifest_sha256": self.manifest_hash})
            self.status_answered = True

    def redact(self, text):
        return (
            super().redact(text).replace(self.token, "[REDACTED]")
            if self.token
            else super().redact(text)
        )

    def aws(self, service, operation, args, *, deadline=None):
        try:
            return super().aws(service, operation, args, deadline=deadline)
        except subprocess.CalledProcessError as exc:
            # Preserve callers' retry contract; argv/output may contain tokens.
            raise subprocess.CalledProcessError(
                exc.returncode, ["aws", service, operation]
            ) from None
        except subprocess.TimeoutExpired as exc:
            raise subprocess.TimeoutExpired(["aws", service, operation], exc.timeout) from None

    def task_cost(self, start, now):
        # Conservative bound, not a CUR/billing reconciliation. Include at least
        # 60 seconds of EC2 billing, full storage/IP lifetime and $1 other costs.
        return (
            max(60, now - start) / 3600 * self.manifest["hourly_all_resources_usd"] + COST_FIXED_USD
        )

    def cumulative_cost(self, start, now):
        return self.manifest.get("prior_spend_usd", 0) + self.task_cost(start, now)

    def command(self, argv, deadline, name):
        argv = list(argv)
        if argv[0] in self.manifest["operator_tools"]:
            argv[0] = self.manifest["operator_tools"][argv[0]]["path"]
        output = self.runtime / (name + ".log")
        # Exclusive reservation also fences concurrent callers and survives a
        # crash before the command receipt. Never reuse a receipt name.
        with output.with_suffix(".reserved").open("xb"):
            if output.exists() or output.with_suffix(".command.json").exists():
                raise FileExistsError("command_receipt_exists:" + name)
        return run_exe(
            argv,
            cwd=self.directory / "terraform",
            output=output,
            timeout=max(0.001, deadline - time.time()),
            env={**os.environ, "AWS_PROFILE": self.inputs["aws_profile"]},
        )

    def apply(self, end):
        self.started = time.time()
        self.deadline = end
        # First possible billable operation is already inside Lifecycle.finally.
        if (
            sha(self.directory / "terraform/create.tfplan")
            != self.manifest["sealed_plans"]["create_sha256"]
        ):
            raise ValueError("saved_plan_changed_before_consume")
        # Exclusive creation fences concurrent invocations; never replace this
        # durable consume even if Apply has an ambiguous or failed reply.
        with (self.directory / "consumed.json").open("xb") as stream:
            stream.write(
                json.dumps(
                    {"utc": utc(), "plan_sha256": self.manifest["sealed_plans"]["create_sha256"]}
                ).encode()
            )
            stream.flush()
            os.fsync(stream.fileno())
        self.command(
            ["terraform", "apply", "-input=false", "-auto-approve", "create.tfplan"],
            min(end, time.time() + APPLY_S),
            "apply",
        )
        self.host = self.instance_ids()[0]
        return {"instance": self.host}

    def instance_ids(self):
        session = self.manifest.get("session", "dec077-20261019")
        response = self.aws(
            "ec2", "describe-instances", ["--filters", f"Name=tag:Session,Values={session}"]
        )
        return [
            x["InstanceId"]
            for reservation in response["Reservations"]
            for x in reservation["Instances"]
            if x["State"]["Name"] != "terminated"
        ]

    def phase(self, name, operation):
        recorder = getattr(self, "phase_runner", None)
        return operation() if recorder is None else recorder(name, operation)

    def bootstrap_source(self):
        return (ROOT / "scripts/package_a_host.py").read_bytes()

    def bootstrap(self, end):
        self.deadline = end
        if self.host is None:
            raise ValueError("host_unavailable")
        self.ssm_online = False
        # EC2 running does not establish SSM registration or IAM propagation.
        registration_started = time.monotonic()
        ready_end = min(end, time.time() + ssm_registration_window_s(self.manifest))
        self.deadline = ready_end
        last_ping_status = "not_reported"
        while True:
            if ready_end - time.time() < 5:
                elapsed_s = time.monotonic() - registration_started
                raise TimeoutError(
                    "ssm_registration_deadline "
                    f"elapsed_s={elapsed_s:.3f} last_ping_status={last_ping_status}"
                )
            rows = self.aws(
                "ssm",
                "describe-instance-information",
                ["--filters", json.dumps([{"Key": "InstanceIds", "Values": [self.host]}])],
            )["InstanceInformationList"]
            last_ping_status = (
                str(rows[0].get("PingStatus", "missing"))
                if len(rows) == 1
                else "no_instance_information"
            )
            if len(rows) == 1 and last_ping_status == "Online":
                self.ssm_online = True
                save(self.registration_path, {"ping_status": last_ping_status})
                break
            if ready_end - time.time() < 5:
                elapsed_s = time.monotonic() - registration_started
                raise TimeoutError(
                    "ssm_registration_deadline "
                    f"elapsed_s={elapsed_s:.3f} last_ping_status={last_ping_status}"
                )
            hard_cap = self.manifest.get("hard_cap_usd", CAP_USD)
            if (
                self.cumulative_cost(self.started, time.time())
                + self.manifest["cleanup_cost_reserve_usd"]
                >= hard_cap
            ):
                raise RuntimeError("cost_cap_during_ssm_registration")
            time.sleep(min(2, max(0, ready_end - time.time())))
        self.deadline = end
        # A live timer must have been armed by user data before we upload anything.
        readiness = (
            gate_a_readiness_shell(receiver=self.manifest.get("role") == "gate_a_receiver")
            if self.manifest.get("workload") == "r366-gate-a"
            else readiness_shell()
        )
        self.phase(
            "readiness",
            lambda: self.ssm(
                self.host,
                readiness,
                timeout_s=300,
                step=f"{self.manifest.get('role', 'host')}.readiness",
            ),
        )
        self.ssm(
            self.host,
            bootstrap_shell(
                self.bootstrap_source(),
                self.token,
                self.manifest_hash,
                end,
            ),
            timeout_s=60,
            step=f"{self.manifest.get('role', 'host')}.bootstrap",
        )
        self.remember_status()
        return {"ssm": "bootstrap_complete"}

    def request(self, path, data=None, headers=None, *, end):
        self.deadline = end
        if self.token is None:
            raise ValueError(self.token_error)
        backoff = 0.5
        opened = 0
        while time.time() < end:
            try:
                if self.child is None:
                    self.channel, self.child = self.tunnel(self.host)
                    opened = time.time()
                if self.child.poll() is not None:
                    raise ConnectionError("forward_exited")
                result = self.rpc(self.channel, path, self.token, data, headers)
                if path == "/status":
                    self.remember_status()
                return result
            except (OSError, http.client.HTTPException) as exc:
                if (
                    isinstance(exc, ConnectionRefusedError)
                    and self.child
                    and self.child.poll() is None
                    and time.time() - opened < 10
                ):
                    time.sleep(min(0.5, max(0, end - time.time())))
                    continue
                try:
                    if self.child:
                        stop_forward(self.child)
                finally:
                    self.child = None
                self.reconnects += 1
                save(
                    self.runtime / "transport.json",
                    {"reconnects": self.reconnects, "path": path, "error": type(exc).__name__},
                )
                time.sleep(min(backoff, max(0, end - time.time())))
                backoff = min(10, backoff * 2)
        raise TimeoutError("ssm_transport_absolute_deadline")

    def upload(self, end):
        end = min(end, time.time() + self.manifest["upload_timeout_s"])
        self.request("/manifest", self.manifest_bytes, end=end)
        bundle = self.directory / "source.bundle"
        if sha(bundle) != self.manifest["bundle_sha256"]:
            raise ValueError("bundle_changed")
        with bundle.open("rb") as stream:
            while stream.tell() < bundle.stat().st_size:
                offset = json.loads(self.request("/status", end=end)[0])["offset"]
                stream.seek(offset)
                data = stream.read(1024**2)
                if not data:
                    break
                try:
                    self.request(
                        f"/upload/{offset}",
                        data,
                        {"X-Chunk-SHA256": hashlib.sha256(data).hexdigest()},
                        end=end,
                    )
                except RuntimeError:
                    # Ambiguous append: status provides the authoritative offset.
                    observed = json.loads(self.request("/status", end=end)[0])["offset"]
                    if observed != offset + len(data):
                        raise
        return json.loads(self.phase("staging", lambda: self.request("/stage", b"", end=end))[0])

    def upload_gate_a_inputs(self, end, *, operator_ports=None):
        if operator_ports is not None:
            gate_a_pre_p_operation_window(operator_ports, end, time.time())
        binding = self.manifest.get("gate_a_inputs")
        if not isinstance(binding, dict):
            raise ValueError("gate_a_input_manifest_missing")
        relative = Path(binding.get("bundle_path", ""))
        bundle = (self.directory / relative).resolve()
        if (
            self.directory.resolve() not in bundle.parents
            or not bundle.is_file()
            or bundle.stat().st_size != binding.get("bundle_bytes")
            or sha(bundle) != binding.get("bundle_sha256")
        ):
            raise ValueError("gate_a_input_bundle_local_binding")
        staging = binding.get("s3_staging")
        if staging is not None:
            if operator_ports is None:
                raise ValueError("gate_a_input_s3_operator_missing")
            bucket, key = staging.get("bucket"), staging.get("key")
            if (
                bucket != self.manifest.get("bucket_name")
                or not isinstance(key, str)
                or not key.startswith(f"gate-a/{self.manifest.get('session', '')}/input/")
                or staging.get("bundle_bytes") != bundle.stat().st_size
                or staging.get("bundle_sha256") != binding["bundle_sha256"]
            ):
                raise ValueError("gate_a_input_s3_packet_binding")
            lifecycle_start = getattr(operator_ports, "lifecycle_start_epoch", None)
            offset = staging.get("upload_deadline_offset_s")
            if (
                isinstance(lifecycle_start, bool)
                or not isinstance(lifecycle_start, (int, float))
                or isinstance(offset, bool)
                or not isinstance(offset, int)
                or offset <= 0
            ):
                raise ValueError("gate_a_input_s3_absolute_deadline")
            absolute_upload_deadline = lifecycle_start + offset
            stage_end = min(end, absolute_upload_deadline)
            if stage_end <= time.time():
                raise TimeoutError("gate_a_input_s3_upload_deadline")
            aws = operator_ports.manifest["operator_tools"]["aws"]["path"]
            operator_ports.command(
                [
                    aws,
                    "--profile",
                    operator_ports.inputs["aws_profile"],
                    "--region",
                    "us-east-1",
                    "s3",
                    "cp",
                    str(bundle),
                    f"s3://{bucket}/{key}",
                    "--only-show-errors",
                ],
                stage_end,
                "gate-a-inputs-s3-upload",
            )
            head = operator_ports.aws(
                "s3api",
                "head-object",
                ["--bucket", bucket, "--key", key],
                deadline=stage_end,
            )
            if head.get("ContentLength") != bundle.stat().st_size:
                raise ValueError("gate_a_input_s3_upload_length")
            while True:
                expires_in = math.floor(stage_end - time.time())
                if expires_in < 1:
                    raise TimeoutError("gate_a_input_s3_presign_deadline")
                download_url = presigned_s3_get(operator_ports, bucket, key, expires_in)
                # The signing call itself can cross an epoch-second boundary.
                # Check after it returns, then recompute and re-sign if needed.
                if time.time() + expires_in <= stage_end:
                    break
            receipt = json.loads(
                self.phase(
                    "staging",
                    lambda: self.request(
                        "/stage-inputs",
                        json.dumps(
                            {"deadline_epoch": stage_end, "download_url": download_url},
                            separators=(",", ":"),
                        ).encode(),
                        end=stage_end,
                    ),
                )[0]
            )
            if (
                receipt.get("bundle_sha256") != binding["bundle_sha256"]
                or receipt.get("inventory") != binding["inventory"]
                or receipt.get("readback_verified") is not True
                or receipt.get("s3_staging_key") != key
            ):
                raise ValueError("gate_a_input_stage_readback")
            receipt.update(
                upload_deadline_epoch=absolute_upload_deadline,
                **gate_a_pre_p_operation_window(operator_ports, end, time.time()),
            )
            save(self.runtime / "gate-a-pre-p-staging.json", receipt)
            return receipt
        while True:
            state = json.loads(self.request("/status", end=end)[0])
            offset = state.get("input_offset")
            if not isinstance(offset, int) or not 0 <= offset <= bundle.stat().st_size:
                raise ValueError("gate_a_input_resume_offset")
            if offset == bundle.stat().st_size:
                break
            with bundle.open("rb") as stream:
                stream.seek(offset)
                data = stream.read(min(1024**2, bundle.stat().st_size - offset))
            if not data:
                raise ValueError("gate_a_input_bundle_truncated")
            self.request(
                f"/input-upload/{offset}",
                data,
                {"X-Chunk-SHA256": hashlib.sha256(data).hexdigest()},
                end=end,
            )
        receipt = json.loads(
            self.phase("staging", lambda: self.request("/stage-inputs", b"", end=end))[0]
        )
        if (
            receipt.get("bundle_sha256") != binding["bundle_sha256"]
            or receipt.get("inventory") != binding["inventory"]
            or receipt.get("readback_verified") is not True
        ):
            raise ValueError("gate_a_input_stage_readback")
        if operator_ports is not None:
            receipt.update(gate_a_pre_p_operation_window(operator_ports, end, time.time()))
        save(self.runtime / "gate-a-pre-p-staging.json", receipt)
        return receipt

    def run_checks(self, end):
        hard_cap = self.manifest.get("hard_cap_usd", CAP_USD)
        self.request("/start", b"", end=end)
        previous_progress = None
        while time.time() < end:
            if (
                self.cumulative_cost(self.started, time.time())
                + self.manifest["cleanup_cost_reserve_usd"]
                >= hard_cap
            ):
                raise RuntimeError("cost_cap_during_run")
            state = json.loads(self.request("/status", end=end)[0])
            progress = state.get("routine_stages")
            if self.manifest.get("role") == "routine_tests" and progress != previous_progress:
                print(json.dumps({"routine_stages": progress}), flush=True)
                previous_progress = progress
            if state["runner_exit"] is not None:
                if state["runner_exit"] != 0:
                    raise RuntimeError("runner_failed:" + str(state["runner_exit"]))
                return state
            time.sleep(min(5, max(0, end - time.time())))
        raise TimeoutError("runner_original_work_deadline")

    def retrieve(self, end):
        started = time.time()

        def unreachable(reason):
            result = {
                "complete": False,
                "status": "unreachable",
                "reason": reason,
                "elapsed_s": time.time() - started,
            }
            save(self.runtime / "retrieval.json", result)
            return result

        if not self.status_answered:
            return unreachable("status_never_answered")
        # Locate ambiguous Apply effects even when Apply never returned an ID.
        self.deadline = end
        if self.host is None:
            ids = self.instance_ids()
            self.host = ids[0] if ids else None
        if self.host is None:
            return {"complete": True, "no_host_or_receipts": True}
        reachability_end = min(end, started + transfer_seconds(EXPORT_MAX_BYTES))
        try:
            meta = json.loads(self.request("/freeze", b"", end=reachability_end)[0])
        except TimeoutError:
            return unreachable("freeze_unanswered")
        # An acknowledged freeze gets the full byte-based transfer/reconnect
        # budget, still bounded by the original absolute cleanup end.
        end = min(end, time.time() + transfer_seconds(meta["bytes"]))
        destination = self.runtime / "receipts.tar.gz"
        with destination.open("wb") as stream:
            while stream.tell() < meta["bytes"]:
                data, headers = self.request("/archive/" + str(stream.tell()), end=end)
                if not data or hashlib.sha256(data).hexdigest() != headers["X-Chunk-SHA256"]:
                    raise ValueError("archive_chunk_hash")
                stream.write(data)
        if sha(destination) != meta["sha256"] or destination.stat().st_size != meta["bytes"]:
            raise ValueError("archive_final_binding")
        save(self.runtime / "retrieval.json", {**meta, "complete": True})
        return {**meta, "complete": True}

    def teardown(self, end, *, skip_destroy=False):
        self.deadline = end
        failures = []
        try:
            if self.child:
                stop_forward(self.child)
                self.child = None
        except Exception as exc:
            failures.append("stop_forward:" + str(exc))
        try:
            # Terminate by owned session tag first, including ambiguous Apply;
            # Terraform then destroys networking, identity and all tracked state.
            ids = self.instance_ids()
            if ids:
                self.aws("ec2", "terminate-instances", ["--instance-ids", *ids])
                self.command(
                    [
                        "aws",
                        "--profile",
                        self.inputs["aws_profile"],
                        "--region",
                        "us-east-1",
                        "ec2",
                        "wait",
                        "instance-terminated",
                        "--instance-ids",
                        *ids,
                    ],
                    end - 60,  # Reserve for post-termination Terraform destroy.
                    "wait-terminated",
                )
        except Exception as exc:
            failures.append("terminate:" + str(exc))
        try:
            if not skip_destroy:
                self.command(
                    [
                        self.manifest["operator_tools"]["terraform"]["path"],
                        "destroy",
                        "-input=false",
                        "-auto-approve",
                        "-var-file=input.tfvars.json",
                    ],
                    end,
                    "destroy",
                )
        except Exception as exc:
            failures.append("destroy:" + str(exc))
        return {"destroy_completed": not failures, "errors": failures}

    def inventory(self, end):
        self.deadline = end
        results = {}
        for label, service, op, key in (
            ("volumes", "ec2", "describe-volumes", "Volumes"),
            ("interfaces", "ec2", "describe-network-interfaces", "NetworkInterfaces"),
            ("vpcs", "ec2", "describe-vpcs", "Vpcs"),
        ):
            results[label] = self.aws(
                service, op, ["--filters", "Name=tag:Session,Values=dec077-20261019"]
            )[key]
        results["active_instances"] = self.instance_ids()
        for label, op, key, name in (
            ("roles", "list-roles", "Roles", "RoleName"),
            ("profiles", "list-instance-profiles", "InstanceProfiles", "InstanceProfileName"),
        ):
            results[label] = [
                row[name]
                for row in self.aws("iam", op, [])[key]
                if row[name].startswith("dec077-20261019-")
            ]
        state = subprocess.check_output(
            [
                self.manifest["operator_tools"]["terraform"]["path"],
                f"-chdir={self.directory / 'terraform'}",
                "state",
                "list",
            ],
            timeout=max(0.001, end - time.time()),
        )
        results["terraform_resources"] = state.decode().splitlines()
        results["empty"] = all(not x for x in results.values())
        save(self.runtime / "teardown-inventory.json", results)
        return results


class GateAOperator:
    """Two-host Gate A runner coordination and ownership-safe teardown."""

    def __init__(self, ports):
        self.ports = ports
        self.session = ports.manifest["session"]
        self.bucket = ports.manifest["bucket_name"]

    def _tagged(self, service, operation, key, extra=()):
        response = self.ports.aws(
            service,
            operation,
            ["--filters", f"Name=tag:Session,Values={self.session}", *extra],
        )
        return response[key]

    def _receiver_id(self):
        rows = self._tagged(
            "ec2",
            "describe-instances",
            "Reservations",
            ["Name=tag:Role,Values=receiver", "Name=instance-state-name,Values=pending,running"],
        )
        instances = [instance for row in rows for instance in row["Instances"]]
        if len(instances) != 1:
            raise ValueError("gate_a:receiver_instance_count")
        return instances[0]["InstanceId"]

    def _receiver_reported_online(self):
        for ports in getattr(self, "role_ports", []):
            if getattr(ports, "role_name", None) == "receiver":
                return getattr(ports, "ssm_online", False) is True
        return False

    def _host_record(self, role):
        reservations = self._tagged(
            "ec2",
            "describe-instances",
            "Reservations",
            ["Name=tag:Role,Values=" + role, "Name=instance-state-name,Values=running"],
        )
        instances = [instance for row in reservations for instance in row["Instances"]]
        if len(instances) != 1:
            raise ValueError("gate_a:" + role + "_instance_count")
        instance = instances[0]
        if (
            not instance.get("PrivateIpAddress")
            or instance.get("PublicIpAddress")
            or instance.get("PublicDnsName")
        ):
            raise ValueError("gate_a:" + role + "_addressing")
        return instance

    def _role_ports(self, role, host, manifest, end):
        role_root = self.ports.directory / "operator" / "gate-a-roles"
        role_root.mkdir(parents=True, exist_ok=True)
        manifest_path = role_root / (role + ".manifest.json")
        save(manifest_path, manifest)
        ports = Ports(
            self.ports.directory,
            manifest,
            profile=self.ports.inputs["aws_profile"],
            runtime_directory=role_root / role,
            credential_directory=self.ports.directory,
            manifest_path=manifest_path,
        )
        ports.host = host
        ports.started = self.ports.started or time.time()
        ports.deadline = end
        ports.role_name = role
        if not hasattr(self, "role_ports"):
            self.role_ports = []
        self.role_ports.append(ports)
        return ports

    @staticmethod
    def _runner_state(ports, end):
        while time.time() < end:
            value = json.loads(ports.request("/status", end=end)[0])
            runner = value.get("runner_status") or {}
            if runner.get("status") in {"FAILED", "REFUSED"} or value.get("runner_exit") not in (
                None,
                0,
            ):
                raise RuntimeError("gate_a:runner_failed:" + str(runner.get("error", "unknown")))
            yield value
            time.sleep(min(1, max(0, end - time.time())))
        raise TimeoutError("gate_a:runner_deadline")

    def run_roles(self, end):
        self.role_ports = []
        try:
            return self._run_roles(end)
        finally:
            for ports in self.role_ports:
                if ports.child is not None:
                    try:
                        stop_forward(ports.child)
                    except Exception as exc:
                        save(
                            ports.runtime / "tunnel-cleanup-error.json",
                            {"error": type(exc).__name__},
                        )
                    ports.child = None

    def retrieve_roles(self, end):
        """Fetch each reachable role's frozen runner archive before teardown."""
        if not getattr(self, "role_ports", None):
            self.role_ports = []
            role_root = self.ports.directory / "operator" / "gate-a-roles"
            for role in ("receiver", "sender"):
                manifest_path = role_root / (role + ".manifest.json")
                if not manifest_path.is_file():
                    continue
                try:
                    host = self._host_record(role)
                except (OSError, ValueError):
                    continue
                manifest = json.loads(manifest_path.read_bytes())
                ports = Ports(
                    self.ports.directory,
                    manifest,
                    profile=self.ports.inputs["aws_profile"],
                    recovering=True,
                    runtime_directory=role_root / role,
                    credential_directory=self.ports.directory,
                    manifest_path=manifest_path,
                )
                ports.host = host["InstanceId"]
                ports.role_name = role
                self.role_ports.append(ports)
        receipts = {}
        for ports in self.role_ports:
            role = getattr(ports, "role_name", "unknown")
            prior = getattr(ports, "gate_a_retrieval", None)
            try:
                receipts[role] = prior if prior is not None else ports.retrieve(end)
                ports.gate_a_retrieval = receipts[role]
            except BaseException as exc:
                receipts[role] = {"complete": False, "error": type(exc).__name__ + ":" + str(exc)}
            finally:
                if ports.child is not None:
                    try:
                        stop_forward(ports.child)
                    except Exception as exc:
                        save(
                            ports.runtime / "tunnel-cleanup-error.json",
                            {"error": type(exc).__name__},
                        )
                    ports.child = None
        return {
            "complete": set(receipts) == {"receiver", "sender"}
            and all(value.get("complete") is True for value in receipts.values()),
            "roles": receipts,
        }

    def _run_roles(self, end):
        """Stage and run receiver first, then sender, using the existing SSM host service."""
        runner_config = self.ports.manifest.get("gate_a_runner")
        if not isinstance(runner_config, dict):
            raise ValueError("gate_a:runner_configuration")
        common = runner_config.get("common")
        roles = runner_config.get("roles")
        if (
            not isinstance(common, dict)
            or not isinstance(roles, dict)
            or set(roles)
            != {
                "receiver",
                "sender",
            }
        ):
            raise ValueError("gate_a:runner_configuration")
        sender_host = self._host_record("sender")
        receiver_host = self._host_record("receiver")
        receiver_ip = receiver_host["PrivateIpAddress"]
        session_deadline = end

        receiver_manifest = {
            **common,
            **roles["receiver"],
            "workload": "r366-gate-a",
            "role": "gate_a_receiver",
            "deadline_epoch": session_deadline,
        }
        receiver_config = dict(receiver_manifest["gate_a_receiver"])
        receiver_config.update(
            private_address=receiver_ip,
            recovery_root="/recovery",
            bucket=self.bucket,
            service=True,
            run_readiness=True,
            service_timeout_s=max(1, math.floor(end - time.time())),
        )
        receiver_manifest["gate_a_receiver"] = receiver_config
        receiver = self._role_ports("receiver", receiver_host["InstanceId"], receiver_manifest, end)
        receiver.bootstrap(end)
        receiver.upload(end)
        receiver.request("/start", b"", end=end)
        listening = False
        for state in self._runner_state(receiver, end):
            report = state.get("runner_status", {})
            if report.get("status") == "LISTENING":
                address = report.get("receiver_address")
                if address != [receiver_ip, receiver_config["port"]]:
                    raise ValueError("gate_a:receiver_private_address")
                listening = True
                break
        if not listening:
            raise TimeoutError("gate_a:receiver_not_listening")

        sender_manifest = {
            **common,
            **roles["sender"],
            "workload": "r366-gate-a",
            "role": "gate_a_sender",
            "deadline_epoch": session_deadline,
            "bucket_name": self.bucket,
            "bucket_prefix": self.ports.manifest.get("bucket_prefix", f"gate-a/{self.session}/"),
            "gate_a_inputs": self.ports.manifest.get("gate_a_inputs"),
        }
        sender_config = dict(sender_manifest["gate_a_sender"])
        sender_config["receiver_private_address"] = receiver_ip
        sender_config.setdefault("transfer_port", receiver_config["port"])
        staged = self.ports.manifest.get("gate_a_inputs")
        if not isinstance(staged, dict) or not isinstance(staged.get("paths"), dict):
            raise ValueError("gate_a:input_paths")
        sender_config.update(gate_a_remote_input_paths(staged["paths"]))
        sender_manifest["gate_a_sender"] = sender_config
        sender = self._role_ports("sender", sender_host["InstanceId"], sender_manifest, end)
        sender.bootstrap(end)
        sender.upload(end)
        staging = sender.upload_gate_a_inputs(end, operator_ports=self.ports)
        sender.run_checks(end)
        receiver.run_checks(end)
        sender_receipt = sender.retrieve(end)
        receiver_receipt = receiver.retrieve(end)
        sender.gate_a_retrieval = sender_receipt
        receiver.gate_a_retrieval = receiver_receipt
        result = {
            "schema": "package-a-gate-a-operator-run-v1",
            "source_commit": common["source_commit"],
            "sender": {
                "instance_id": sender_host["InstanceId"],
                "private_ip": sender_host["PrivateIpAddress"],
                "retrieval": sender_receipt,
            },
            "receiver": {
                "instance_id": receiver_host["InstanceId"],
                "private_ip": receiver_ip,
                "retrieval": receiver_receipt,
            },
            "pre_p_staging": staging,
            "complete": sender_receipt.get("complete") is True
            and receiver_receipt.get("complete") is True,
        }
        save(self.ports.directory / "final" / "gate-a-run.json", result)
        return result

    def _unmount_recovery(self, receiver_id, end):
        command = self.ports.send_ssm_command(
            receiver_id,
            {
                "commands": [
                    "set -eu; sync; mountpoint -q /recovery && "
                    "umount /recovery; "
                    "! mountpoint -q /recovery"
                ]
            },
            deadline=end,
            step="teardown.recovery-unmount",
        )["Command"]["CommandId"]
        while time.time() < end:
            try:
                state = self.ports.aws(
                    "ssm",
                    "get-command-invocation",
                    ["--command-id", command, "--instance-id", receiver_id],
                )
            except subprocess.CalledProcessError:
                time.sleep(min(1, max(0, end - time.time())))
                continue
            status = state.get("Status")
            if status == "Success":
                return {"status": status, "command_id": command}
            if status in {"Cancelled", "TimedOut", "Failed", "Undeliverable", "Terminated"}:
                raise RuntimeError("gate_a:recovery_unmount:" + str(status))
            time.sleep(min(1, max(0, end - time.time())))
        raise TimeoutError("gate_a:recovery_unmount_deadline")

    def teardown(self, end):
        """Attempt normal cleanup, then force host termination before destroy on error."""
        events, failures = [], []

        def record_failure(step, exc):
            failures.append(f"{step}:{type(exc).__name__}:{exc}")
            events.append({"step": step, "complete": False, "error": type(exc).__name__})

        try:
            volumes = self._tagged(
                "ec2",
                "describe-volumes",
                "Volumes",
                ["Name=tag:Role,Values=recovery-volume"],
            )
            if len(volumes) > 1:
                raise ValueError("gate_a:recovery_volume_count")
            if volumes and volumes[0].get("Attachments", []):
                volume = volumes[0]
                receiver_id = self._receiver_id()
                if self._receiver_reported_online():
                    events.append({"step": "unmount", **self._unmount_recovery(receiver_id, end)})
                else:
                    events.append({"step": "unmount", "status": "skipped_never_registered"})
                self.ports.aws("ec2", "detach-volume", ["--volume-id", volume["VolumeId"]])
                self.ports.command(
                    [
                        self.ports.manifest["operator_tools"]["aws"]["path"],
                        "--profile",
                        self.ports.inputs["aws_profile"],
                        "--region",
                        "us-east-1",
                        "ec2",
                        "wait",
                        "volume-available",
                        "--volume-ids",
                        volume["VolumeId"],
                    ],
                    end,
                    "gate-a-volume-detached",
                )
                events.append({"step": "detach", "volume_id": volume["VolumeId"]})
        except Exception as exc:
            record_failure("pre_destroy", exc)

        if not failures:
            try:
                events.append({"step": "s3_delete", **self._delete_s3_prefix()})
            except Exception as exc:
                record_failure("s3_delete", exc)

        if failures:
            try:
                instances = self._tagged(
                    "ec2",
                    "describe-instances",
                    "Reservations",
                    [
                        "Name=tag:Role,Values=sender,receiver",
                        "Name=instance-state-name,Values=pending,running,stopping,stopped",
                    ],
                )
                ids = [
                    row["InstanceId"]
                    for reservation in instances
                    for row in reservation.get("Instances", [])
                ]
                if ids:
                    self.ports.aws("ec2", "terminate-instances", ["--instance-ids", *ids])
                    events.append({"step": "fallback_terminate", "instance_ids": ids})
                    self.ports.command(
                        [
                            self.ports.manifest["operator_tools"]["aws"]["path"],
                            "--profile",
                            self.ports.inputs["aws_profile"],
                            "--region",
                            "us-east-1",
                            "ec2",
                            "wait",
                            "instance-terminated",
                            "--instance-ids",
                            *ids,
                        ],
                        end,
                        "gate-a-fallback-terminated",
                    )
                    events.append({"step": "fallback_wait", "instance_ids": ids})
                else:
                    events.append({"step": "fallback_terminate", "instance_ids": []})
            except Exception as exc:
                record_failure("fallback_terminate_or_wait", exc)

        try:
            self.ports.command(
                [
                    self.ports.manifest["operator_tools"]["terraform"]["path"],
                    "destroy",
                    "-input=false",
                    "-auto-approve",
                    "-var-file=input.tfvars.json",
                ],
                end,
                "gate-a-destroy",
            )
            events.append({"step": "destroy", "complete": True})
        except Exception as exc:
            record_failure("destroy", exc)

        try:
            inventory = self.inventory(end)
            if not inventory["empty"]:
                failures.append("inventory:gate_a:teardown_inventory_nonempty")
        except Exception as exc:
            inventory = {"empty": False, "error": type(exc).__name__}
            record_failure("inventory", exc)
        return {
            "events": events,
            "inventory": inventory,
            "complete": not failures and inventory.get("empty") is True,
            "errors": failures,
        }

    def _delete_s3_prefix(self):
        """Empty this session's versioning-off bucket prefix before Terraform delete."""
        prefix = self.ports.manifest.get("bucket_prefix", f"gate-a/{self.session}/")
        token = None
        deleted, pages = 0, 0
        while True:
            args = ["--bucket", self.bucket, "--prefix", prefix]
            if token is not None:
                args.extend(("--continuation-token", token))
            page = self.ports.aws("s3api", "list-objects-v2", args)
            pages += 1
            objects = page.get("Contents", [])
            if objects:
                result = self.ports.aws(
                    "s3api",
                    "delete-objects",
                    [
                        "--bucket",
                        self.bucket,
                        "--delete",
                        json.dumps(
                            {"Objects": [{"Key": row["Key"]} for row in objects], "Quiet": True}
                        ),
                    ],
                )
                if result.get("Errors"):
                    raise RuntimeError("gate_a:s3_delete_failed")
                deleted += len(result.get("Deleted", objects))
            if not page.get("IsTruncated"):
                break
            token = page.get("NextContinuationToken")
            if not token:
                raise ValueError("gate_a:s3_list_continuation")
        final = self.ports.aws(
            "s3api", "list-objects-v2", ["--bucket", self.bucket, "--prefix", prefix]
        )
        if final.get("Contents"):
            raise RuntimeError("gate_a:s3_prefix_not_empty")
        return {"bucket": self.bucket, "prefix": prefix, "deleted": deleted, "pages": pages}

    def inventory(self, end):
        self.ports.deadline = end
        instances = self._tagged("ec2", "describe-instances", "Reservations")
        active_instances = [
            row["InstanceId"]
            for reservation in instances
            for row in reservation["Instances"]
            if row["State"]["Name"] != "terminated"
        ]
        buckets = [
            row["Name"]
            for row in self.ports.aws("s3api", "list-buckets", [])["Buckets"]
            if row["Name"] == self.bucket
        ]
        bucket_prefix_objects = []
        if buckets:
            bucket_prefix_objects = self.ports.aws(
                "s3api",
                "list-objects-v2",
                [
                    "--bucket",
                    self.bucket,
                    "--prefix",
                    self.ports.manifest.get("bucket_prefix", f"gate-a/{self.session}/"),
                ],
            ).get("Contents", [])
        results = {
            "instances": active_instances,
            "volumes": [
                row["VolumeId"] for row in self._tagged("ec2", "describe-volumes", "Volumes")
            ],
            "network_interfaces": [
                row["NetworkInterfaceId"]
                for row in self._tagged("ec2", "describe-network-interfaces", "NetworkInterfaces")
            ],
            "vpcs": [row["VpcId"] for row in self._tagged("ec2", "describe-vpcs", "Vpcs")],
            "subnets": [
                row["SubnetId"] for row in self._tagged("ec2", "describe-subnets", "Subnets")
            ],
            "route_tables": [
                row["RouteTableId"]
                for row in self._tagged("ec2", "describe-route-tables", "RouteTables")
            ],
            "internet_gateways": [
                row["InternetGatewayId"]
                for row in self._tagged("ec2", "describe-internet-gateways", "InternetGateways")
            ],
            "vpc_endpoints": [
                row["VpcEndpointId"]
                for row in self._tagged("ec2", "describe-vpc-endpoints", "VpcEndpoints")
            ],
            "security_groups": [
                row["GroupId"]
                for row in self._tagged("ec2", "describe-security-groups", "SecurityGroups")
            ],
            "nat_gateways": [
                row["NatGatewayId"]
                for row in self.ports.aws(
                    "ec2",
                    "describe-nat-gateways",
                    ["--filter", f"Name=tag:Session,Values={self.session}"],
                )["NatGateways"]
                if row["State"] != "deleted"
            ],
            "public_addresses": [
                row["AllocationId"]
                for row in self._tagged("ec2", "describe-addresses", "Addresses")
            ],
            "iam_roles": [
                row["RoleName"]
                for row in self.ports.aws("iam", "list-roles", [])["Roles"]
                if row["RoleName"].startswith(self.session + "-")
            ],
            "instance_profiles": [
                row["InstanceProfileName"]
                for row in self.ports.aws("iam", "list-instance-profiles", [])["InstanceProfiles"]
                if row["InstanceProfileName"].startswith(self.session + "-")
            ],
            "buckets": buckets,
            "bucket_prefix_objects": bucket_prefix_objects,
        }
        state = subprocess.check_output(
            [
                self.ports.manifest["operator_tools"]["terraform"]["path"],
                f"-chdir={self.ports.directory / 'terraform'}",
                "state",
                "list",
            ],
            timeout=max(0.001, end - time.time()),
        )
        results["terraform_resources"] = state.decode().splitlines()
        results["empty"] = all(not rows for rows in results.values())
        save(self.ports.runtime / "gate-a-teardown-inventory.json", results)
        return results


class GateALifecycle:
    """DEC-077 lifecycle with the same durable apply/cleanup rules for two hosts."""

    def __init__(self, ports, manifest, output, *, clock=time.time):
        self.ports, self.manifest = ports, manifest
        self.output, self.clock = Path(output), clock
        self.operator = GateAOperator(ports)
        self.receipt = {
            "schema": "dec077-gate-a-final-v1",
            "events": [],
            "complete": False,
            "binding": {
                key: manifest.get(key)
                for key in ("source_commit", "session", "bucket_name", "sealed_plans")
            },
            "cost_method": (
                "Conservative duration bound for two c6i.2xlarge hosts, gp3 roots and recovery volume, "
                "one NAT gateway and its public address; S3 and NAT data costs use packet allowances."
            ),
        }

    def checkpoint(self):
        now = self.clock()
        reserve = CLEANUP_S + transfer_seconds(EXPORT_MAX_BYTES)
        if now >= self.end - reserve:
            raise RuntimeError("gate_a:deadline_reserve")
        task = self.ports.task_cost(self.start, now)
        cumulative = self.ports.cumulative_cost(self.start, now)
        self.receipt["task_cost_usd"] = task
        self.receipt["cumulative_cost_usd"] = cumulative
        if cumulative + self.manifest["cleanup_cost_reserve_usd"] >= self.cap:
            raise RuntimeError("gate_a:cost_cap")

    def call(self, name, operation):
        self.checkpoint()
        self.receipt["events"].append(name)
        save(self.output / "lifecycle.json", self.receipt)
        result = operation()
        self.receipt[name] = result
        self.checkpoint()
        return result

    def run(self):
        self.output.mkdir(parents=True, exist_ok=True)
        self.start = self.clock()
        self.ports.last_ssm_failure = None
        self.end = self.start + self.manifest.get("session_deadline_s", DEADLINE_S)
        self.ports.lifecycle_start_epoch = self.start
        self.ports.lifecycle_deadline_epoch = self.end
        self.cap = self.manifest.get("hard_cap_usd", CAP_USD)
        self.receipt.update(first_possible_billable_at_epoch=self.start, deadline_epoch=self.end)
        save(self.output / "lifecycle.json", self.receipt)
        run_end = self.end - CLEANUP_S - transfer_seconds(EXPORT_MAX_BYTES)
        try:
            self.call("apply", lambda: self.ports.apply(run_end))
            self.call("run_roles", lambda: self.operator.run_roles(run_end))
        except BaseException as exc:
            halt = type(exc).__name__ + ":" + str(exc)
            ssm_failure = getattr(self.ports, "last_ssm_failure", None)
            if isinstance(ssm_failure, dict):
                halt += f"; step={ssm_failure['step']}; argv_length={ssm_failure['argv_length']}"
            self.receipt["halt"] = halt
        finally:
            retrieval_end = self.end - CLEANUP_S
            try:
                self.receipt["events"].append("retrieve")
                self.receipt["retrieve"] = self.operator.retrieve_roles(retrieval_end)
            except BaseException as exc:
                self.receipt["retrieve"] = {
                    "complete": False,
                    "error": type(exc).__name__ + ":" + str(exc),
                }
            try:
                self.receipt["events"].append("teardown")
                self.receipt["teardown"] = self.operator.teardown(self.end)
            except BaseException as exc:
                self.receipt["teardown"] = {
                    "complete": False,
                    "error": type(exc).__name__ + ":" + str(exc),
                }
            final_now = self.clock()
            self.receipt["task_cost_usd"] = self.ports.task_cost(self.start, final_now)
            self.receipt["cumulative_cost_usd"] = self.ports.cumulative_cost(self.start, final_now)
            self.receipt["hard_cap_usd"] = self.cap
            self.receipt["counts_against_ceiling_usd"] = 300
            self.receipt["complete"] = (
                "halt" not in self.receipt
                and self.receipt.get("run_roles", {}).get("complete") is True
                and self.receipt.get("retrieve", {}).get("complete") is True
                and self.receipt.get("teardown", {}).get("complete") is True
                and self.receipt.get("teardown", {}).get("inventory", {}).get("empty") is True
                and self.receipt["cumulative_cost_usd"] < self.cap
                and self.clock() <= self.end
            )
            save(self.output / "lifecycle.json", self.receipt)
        return self.receipt


def apply(directory, profile):
    directory = Path(directory).resolve()
    manifest = load_packet_manifest(directory)
    require_marker(directory, manifest)
    executing_binding(directory, manifest)
    ports = Ports(directory, manifest, profile=profile)
    identity = ports.aws("sts", "get-caller-identity", [])
    if hashlib.sha256(identity["Account"].encode()).hexdigest() != manifest["account_id_sha256"]:
        raise ValueError("refreshed_account_mismatch")
    ports.command(
        ["terraform", "init", "-input=false", "-lockfile=readonly"],
        time.time() + 300,
        "native-init",
    )
    # Acquire before entering the finally path: a losing concurrent invocation
    # must not tear down the winning invocation's host.
    with (directory / "operator.lock").open("xb") as stream:
        stream.write(json.dumps({"pid": os.getpid(), "utc": utc()}).encode())
        stream.flush()
        os.fsync(stream.fileno())
    # No billable action above. All subsequent cloud calls live in the lifecycle.
    lifecycle_type = GateALifecycle if manifest.get("workload") == "r366-gate-a" else Lifecycle
    result = lifecycle_type(ports, manifest, directory / "final").run()
    return result


def recover(directory, profile):
    """Cleanup-only crash recovery; never reapply or extend paid execution."""
    directory = Path(directory).resolve()
    owner = json.loads((directory / "operator.lock").read_bytes())["pid"]
    if pid_is_running(owner):
        raise ValueError("original_operator_still_running")
    manifest = load_packet_manifest(directory)
    executing_binding(directory, manifest)
    prior = json.loads((directory / "final/lifecycle.json").read_bytes())
    # Cleanup may be late after a disconnected/crashed operator; record the
    # breach, then remove charges rather than refusing the cleanup itself.
    original_end = prior["deadline_epoch"]
    cleanup_end = max(original_end, time.time() + CLEANUP_S)
    ports = Ports(directory, manifest, profile=profile, recovering=True)
    if manifest.get("workload") == "r366-gate-a":
        operator = GateAOperator(ports)
        receipt = {
            "schema": "dec077-gate-a-recovery-v1",
            "original_deadline_epoch": original_end,
            "late_cleanup": time.time() > original_end,
            "paid_execution_resumed": False,
        }
        try:
            ports.command(
                ["terraform", "init", "-input=false", "-lockfile=readonly"],
                cleanup_end,
                "gate-a-recovery-native-init",
            )
        except BaseException as exc:
            receipt["terraform_init"] = {"error": type(exc).__name__ + ":" + str(exc)}
        try:
            receipt["retrieve"] = operator.retrieve_roles(
                min(cleanup_end, time.time() + transfer_seconds(EXPORT_MAX_BYTES))
            )
        except BaseException as exc:
            receipt["retrieve"] = {"complete": False, "error": type(exc).__name__ + ":" + str(exc)}
        try:
            receipt["teardown"] = operator.teardown(cleanup_end)
        except BaseException as exc:
            receipt["teardown"] = {"complete": False, "error": type(exc).__name__ + ":" + str(exc)}
        try:
            receipt["inventory"] = operator.inventory(cleanup_end)
        except BaseException as exc:
            receipt["inventory"] = {"empty": False, "error": type(exc).__name__ + ":" + str(exc)}
        final_now = time.time()
        receipt["task_cost_usd"] = ports.task_cost(
            prior["first_possible_billable_at_epoch"], final_now
        )
        receipt["cumulative_cost_usd"] = ports.cumulative_cost(
            prior["first_possible_billable_at_epoch"], final_now
        )
        save(ports.runtime / "gate-a-recovery.json", receipt)
        return receipt
    receipt = {
        "schema": "dec077-recovery-v1",
        "original_deadline_epoch": original_end,
        "late_cleanup": time.time() > original_end,
        "paid_execution_resumed": False,
    }
    for name, end in (
        ("retrieve", min(cleanup_end, time.time() + transfer_seconds(EXPORT_MAX_BYTES))),
        ("teardown", cleanup_end),
        ("inventory", cleanup_end),
    ):
        try:
            receipt[name] = getattr(ports, name)(end)
        except Exception as exc:
            receipt[name] = {"error": str(exc)}
    final_now = time.time()
    receipt["task_cost_usd"] = ports.task_cost(prior["first_possible_billable_at_epoch"], final_now)
    receipt["cumulative_cost_usd"] = ports.cumulative_cost(
        prior["first_possible_billable_at_epoch"], final_now
    )
    save(ports.runtime / "recovery.json", receipt)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action", choices=("prepare", "apply", "rehearse", "recover", "gate-a-teardown")
    )
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--refresh", type=Path)
    parser.add_argument("--preflight", type=Path)
    parser.add_argument("--cpu-validation", action="store_true")
    parser.add_argument("--profile", default="admin-learning")
    args = parser.parse_args()
    if args.action == "prepare":
        if args.refresh is None:
            parser.error("prepare requires read-only --refresh")
        prepare(
            args.directory,
            args.refresh,
            preflight=args.preflight,
            checks=CPU_VALIDATION_CHECKS if args.cpu_validation else TASK_CHECKS,
        )
    elif args.action == "apply":
        result = apply(args.directory, args.profile)
        raise SystemExit(0 if result["complete"] else 1)
    elif args.action == "recover":
        result = recover(args.directory, args.profile)
        raise SystemExit(0 if result.get("inventory", {}).get("empty") else 1)
    elif args.action == "gate-a-teardown":
        manifest = load_packet_manifest(args.directory)
        if manifest.get("workload") != "r366-gate-a":
            raise ValueError("gate_a:manifest_workload")
        ports = Ports(args.directory, manifest, profile=args.profile)
        ports.command(
            ["terraform", "init", "-input=false", "-lockfile=readonly"],
            time.time() + 300,
            "gate-a-native-init",
        )
        receipt = GateAOperator(ports).teardown(time.time() + CLEANUP_S)
        save(args.directory / "final/gate-a-teardown.json", receipt)
        raise SystemExit(0 if receipt["complete"] else 1)
    else:
        result = subprocess.run(
            [
                "uv",
                "run",
                "--project",
                "python",
                "--locked",
                "python",
                "scripts/check_package_a_cloud.py",
                "--output",
                str(args.directory),
            ],
            cwd=ROOT,
            check=False,
        )
        raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
