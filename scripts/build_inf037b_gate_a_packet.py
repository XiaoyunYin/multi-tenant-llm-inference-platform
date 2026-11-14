"""Build the reviewed, unconsumed exact-plan packet for Gate A offline."""

import argparse
import hashlib
import json
import math
import os
import secrets
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [
    str(ROOT / "python/tests"),
    str(ROOT / "scripts"),
    str(ROOT / "python/src"),
]

from inference_platform.inf037b_archive import encode, file_facts, sha  # noqa: E402
from inference_platform.inf037b_campaign import sanitized_campaign  # noqa: E402
from inference_platform.inf037b_contract import ATTEMPT_MS, RESET_MS  # noqa: E402
from build_inf037b_gate_a_spool import RAW_BYTES_ALLOWANCE  # noqa: E402
from inference_platform.inf037b_gate_a import (  # noqa: E402
    GATE_A_OPERATION_CUTOFF_MS,
    gate_a_binding,
    validate_export_sizing_proof,
    verify_wire_spool,
)
from inference_platform.inf037b_maximum import current_sources, load_maximum  # noqa: E402
from inference_platform.package_a_cloud import (  # noqa: E402
    APPLY_S,
    CLEANUP_S,
    COST_FIXED_USD,
    DEADLINE_S,
    EXPORT_MAX_BYTES,
    HOST_TIMER_S,
    PRIOR_SPEND_USD,
    run_exe,
    save,
    sha as package_sha,
    transfer_seconds,
    utc,
)
from inference_platform.package_a_operator import (  # noqa: E402
    gate_a_command_line_records,
    operator_aws_cli_pairs,
    python_hashes,
    sealed_plans,
    validate_host_refresh,
)

GIB = 1024**3
GATE_A_MINIO_IMAGE = (
    "ghcr.io/coollabsio/minio@sha256:"
    "69b55a1c1c5dc285ce04db96689f5b2102317fc77a50680a1874ca6efd1c87f9"
)
EXPECTED_MANAGED_RESOURCES = 34
RECOVERY_COPIES = 8
S3_STANDARD_GB_MONTH = 0.023
S3_PUT_PER_1000 = 0.005
S3_GET_PER_1000 = 0.0004
S3_LIST_PER_1000 = 0.005
NAT_GATEWAY_PER_HOUR = 0.045
NAT_PROCESSING_PER_GB = 0.045
NAT_PROCESSING_ALLOWANCE_GB = 5
INTERFACE_ENDPOINT_COUNT = 3
INTERFACE_ENDPOINT_PER_HOUR = 0.01
INTERFACE_ENDPOINT_PROCESSING_PER_GB = 0.01
INTERFACE_ENDPOINT_PROCESSING_ALLOWANCE_GB = 5
INTERFACE_ENDPOINT_PRICING_SOURCE = "https://aws.amazon.com/privatelink/pricing/"
AVERAGE_MONTH_HOURS = 730


def preflight_operator_aws_cli(aws_executable, directory, *, runner=run_exe):
    """Parse every literal AWS service operation without credentials or requests."""
    result = []
    for index, (service, operation) in enumerate(operator_aws_cli_pairs()):
        output = (
            Path(directory) / f"aws-cli-parse-{index:02d}-{service}-{operation}.log"
        )
        command = [str(aws_executable), service, operation, "--generate-cli-skeleton"]
        receipt = runner(
            command,
            cwd=ROOT,
            output=output,
            timeout=30,
            env={**os.environ, "AWS_EC2_METADATA_DISABLED": "true"},
        )
        if receipt.get("exit") != 0:
            raise ValueError(f"gate_a_packet:aws_cli_parse:{service}:{operation}")
        result.append(
            {
                "service": service,
                "operation": operation,
                "exit": receipt["exit"],
                "log_sha256": receipt["log_sha256"],
            }
        )
    return result


def remove_tree(path, *, platform_name=None):
    """Remove a scratch tree, clearing read-only Git pack files on Windows."""
    platform_name = os.name if platform_name is None else platform_name
    if platform_name != "nt":
        shutil.rmtree(path)
        return

    def retry_readonly(function, target, error):
        os.chmod(target, stat.S_IREAD | stat.S_IWRITE)
        function(target)

    shutil.rmtree(path, onerror=retry_readonly)


def preserve_refusal_diagnostics(directory):
    """Copy only bounded command diagnostics into a non-packet sibling."""
    directory = Path(directory)
    refused = directory.with_name(
        directory.name + ".refused-" + datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
    )
    refused.mkdir(parents=False, exist_ok=False)
    if not directory.is_dir() or directory.is_symlink():
        return refused
    suffixes = (".log", ".stdout", ".stderr", ".command.json")
    for source in sorted(directory.rglob("*")):
        if (
            source.is_symlink()
            or not source.is_file()
            or source.stat().st_size > 1024**2
        ):
            continue
        if not source.name.endswith(suffixes):
            continue
        destination = refused / source.relative_to(directory)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    return refused


def inventory(root):
    root = Path(root)
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("gate_a_packet:symlink")
        if path.is_file():
            result[path.relative_to(root).as_posix()] = file_facts(path)
    if not result:
        raise ValueError("gate_a_packet:empty_inventory")
    return result


def run_git(*argv):
    return subprocess.check_output(["git", *map(str, argv)], cwd=ROOT)


def deterministic_tar(source_files, destination):
    destination = Path(destination)
    with tarfile.open(destination, "w", format=tarfile.PAX_FORMAT) as archive:
        for arcname, path in sorted(source_files.items()):
            relative = Path(arcname)
            if relative.is_absolute() or ".." in relative.parts or "\\" in arcname:
                raise ValueError("gate_a_packet:input_path")
            info = tarfile.TarInfo(arcname)
            info.size = Path(path).stat().st_size
            info.mode, info.uid, info.gid = 0o600, 0, 0
            info.uname = info.gname = ""
            info.mtime = 0
            info.pax_headers = {}
            with Path(path).open("rb") as stream:
                archive.addfile(info, stream)


def verify_tar_inventory(bundle, expected_inventory):
    observed = {}
    with tarfile.open(bundle, "r:") as archive:
        members = archive.getmembers()
        if any(not member.isfile() for member in members):
            raise ValueError("gate_a_packet:input_archive_member")
        if {member.name for member in members} != set(expected_inventory):
            raise ValueError("gate_a_packet:input_archive_inventory")
        for member in members:
            expected = expected_inventory[member.name]
            if member.size != expected["bytes"]:
                raise ValueError("gate_a_packet:input_archive_length")
            source = archive.extractfile(member)
            if source is None:
                raise ValueError("gate_a_packet:input_archive_member")
            digest = hashlib.sha256()
            size = 0
            with source:
                while chunk := source.read(1024 * 1024):
                    digest.update(chunk)
                    size += len(chunk)
            observed[member.name] = {"bytes": size, "sha256": digest.hexdigest()}
    if observed != expected_inventory:
        raise ValueError("gate_a_packet:input_archive_hash")
    return observed


def verify_packet_checksums(directory):
    for line in (
        (Path(directory) / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
    ):
        expected, name = line.split("  ", 1)
        if package_sha(Path(directory) / name) != expected:
            raise ValueError("gate_a_packet:recorded_input_changed:" + name)


def verify_live_inputs(
    fixture, fixture_proof, sizing_proof, spool, spool_manifest, specs, expected
):
    for label, root in (("fixture", fixture), ("spool", spool)):
        for name, facts in expected.items():
            prefix = label + "/"
            if name.startswith(prefix):
                if file_facts(Path(root) / name.removeprefix(prefix)) != facts:
                    raise ValueError("gate_a_packet:source_input_changed:" + name)
    for name, path in (
        ("fixture-proof.json", fixture_proof),
        ("sizing-proof.json", sizing_proof),
        ("spool-manifest.json", spool_manifest),
        ("sanitizer-specs.json", specs),
    ):
        if file_facts(path) != expected[name]:
            raise ValueError("gate_a_packet:source_input_changed:" + name)


def make_source_bundle(directory, commit):
    shallow = Path(directory) / "shallow.git"
    run_git(
        "clone",
        "--bare",
        "--no-local",
        "--depth",
        "1",
        "--branch",
        "main",
        ROOT.as_uri(),
        shallow,
    )
    actual = (
        subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=shallow)
        .decode()
        .strip()
    )
    if actual != commit:
        raise ValueError("gate_a_packet:source_moved_during_bundle")
    bundle = Path(directory) / "source.bundle"
    subprocess.run(
        ["git", "bundle", "create", bundle, "--all"], cwd=shallow, check=True
    )
    run_git("bundle", "verify", bundle)
    remove_tree(shallow)
    return bundle


def gate_a_runner_common(common):
    """Add source-bundle transfer bounds shared by both Gate A role manifests."""
    return {**common, "upload_timeout_s": transfer_seconds(common["bundle_bytes"])}


def _write_input_bundle(
    directory,
    fixture,
    proof,
    sizing,
    spool,
    spool_manifest,
    specs,
    key,
    archive_inventory,
    pins,
):
    source_files = {}
    for label, root in (("fixture", fixture), ("spool", spool)):
        for name in inventory(root):
            source_files[f"{label}/{name}"] = Path(root) / name
    for name, path in (
        ("fixture-proof.json", proof),
        ("sizing-proof.json", sizing),
        ("spool-manifest.json", spool_manifest),
        ("sanitizer-specs.json", specs),
        ("sanitizer-key.bin", key),
        ("expected-archive-inventory.json", archive_inventory),
        ("pins.json", pins),
    ):
        source_files[name] = path
    input_inventory = {
        name: file_facts(path) for name, path in sorted(source_files.items())
    }
    bundle = Path(directory) / "gate-a-inputs.tar"
    deterministic_tar(source_files, bundle)
    if bundle.stat().st_size > 8 * GIB:
        raise ValueError("gate_a_packet:input_bundle_limit")
    return bundle, input_inventory


def validate_fixture_inputs(fixture, fixture_proof, sizing_proof):
    """Validate committed producer output against the canonical synthetic binding."""
    pin_binding = gate_a_binding()["pins"]
    fixture_proof = Path(fixture_proof)
    fixture_inventory = inventory(fixture)
    fixture_value = load_maximum(
        {"path": str(fixture_proof), "sha256": sha(fixture_proof.read_bytes())},
        pin_binding,
    )
    if fixture_inventory != fixture_value["fixture_inventory"]:
        raise ValueError("gate_a_packet:fixture_inventory")
    sizing = json.loads(Path(sizing_proof).read_bytes())
    validate_export_sizing_proof(
        sizing,
        fixture_inventory,
        pins=pin_binding,
        fixture_proof_sha256=sha(fixture_proof.read_bytes()),
    )
    if (
        fixture_value.get("registered_archive_rows") != 701_418
        or fixture_value.get("schedule_ms") != [ATTEMPT_MS] * 3 + [RESET_MS] * 2
    ):
        raise ValueError("gate_a_packet:registered_fixture")
    return pin_binding, fixture_value, fixture_inventory, sizing


def _s3_manifest_facts(manifest):
    data = encode({"schema": "inf037b-s3-archive-manifest-v1", "manifest": manifest})
    return {"bytes": len(data), "sha256": sha(data)}


def cost_forecast(
    *, refresh, recovery_gib, archive_inventory, spool_inventory, input_bundle_bytes=0
):
    archive_bytes = sum(row["bytes"] for row in archive_inventory.values())
    spool_bytes = sum(row["bytes"] for row in spool_inventory.values())
    archive_data_objects = len(archive_inventory) + len(spool_inventory)
    input_objects = int(input_bundle_bytes > 0)
    data_objects = archive_data_objects + input_objects
    archive_manifest_bytes = _s3_manifest_facts(
        {"archive/" + name: value for name, value in archive_inventory.items()}
    )["bytes"]
    spool_manifest_bytes = _s3_manifest_facts(
        {"spool/" + name: value for name, value in spool_inventory.items()}
    )["bytes"]
    manifest_bytes = archive_manifest_bytes + spool_manifest_bytes
    stored_bytes = archive_bytes + spool_bytes + manifest_bytes + input_bundle_bytes
    put_requests = data_objects + 2
    get_requests = 2 * archive_data_objects + 6 + input_objects
    list_requests = 2
    s3_put = put_requests * S3_PUT_PER_1000 / 1000
    s3_get = get_requests * S3_GET_PER_1000 / 1000
    s3_list = list_requests * S3_LIST_PER_1000 / 1000
    s3_storage = (
        stored_bytes
        / GIB
        * S3_STANDARD_GB_MONTH
        * DEADLINE_S
        / 3600
        / AVERAGE_MONTH_HOURS
    )
    nat_processing = NAT_PROCESSING_ALLOWANCE_GB * NAT_PROCESSING_PER_GB
    endpoint_hourly = INTERFACE_ENDPOINT_COUNT * INTERFACE_ENDPOINT_PER_HOUR
    endpoint_processing = (
        INTERFACE_ENDPOINT_PROCESSING_ALLOWANCE_GB
        * INTERFACE_ENDPOINT_PROCESSING_PER_GB
    )
    ledger = json.loads(
        (ROOT / "docs/evidence/m5-package-a/spend-ledger.json").read_bytes()
    )
    historical = next(
        item
        for item in ledger["entries"]
        if item.get("packet_dir") == ".cache/dec086-seventh-packet-ae0f538"
    )
    if historical.get("task_cost_usd") != 1.4625619234173461:
        raise ValueError("gate_a_packet:package_a_cost_basis")
    historical_two_host_basis = 2 * historical["task_cost_usd"]
    root_gib = 80
    root_volume_gib = 2 * root_gib
    compute_hourly = 2 * refresh["on_demand_usd_per_hour"]
    storage_hourly = (
        (root_volume_gib + recovery_gib)
        * refresh["gp3_usd_per_gib_month"]
        / AVERAGE_MONTH_HOURS
    )
    ipv4_hourly = refresh["ipv4_usd_per_hour"]  # NAT gateway public IPv4 only.
    nat_hourly = NAT_GATEWAY_PER_HOUR
    fixed_hourly = (
        compute_hourly + storage_hourly + ipv4_hourly + nat_hourly + endpoint_hourly
    )
    variable = (
        nat_processing + endpoint_processing + s3_put + s3_get + s3_list + s3_storage
    )
    hourly_all_resources = fixed_hourly + variable / (DEADLINE_S / 3600)
    task = hourly_all_resources * (DEADLINE_S / 3600) + COST_FIXED_USD
    return {
        "schema": "r366-gate-a-cost-forecast-v1",
        "basis": "six-hour maximum lifecycle window; no discount or free tier",
        "historical_package_a_basis": {
            "ledger_path": "docs/evidence/m5-package-a/spend-ledger.json",
            "line": 68,
            "one_host_task_cost_usd": historical["task_cost_usd"],
            "two_host_extrapolation_usd": historical_two_host_basis,
            "role": "observed Package A host-task comparison; direct six-hour Gate A forecast below governs",
        },
        "refresh_utc": refresh["utc"],
        "source": "cached read-only refresh; no AWS call in packet build",
        "duration_hours": DEADLINE_S / 3600,
        "hosts": {
            "count": 2,
            "type": "c6i.2xlarge",
            "rate_usd_per_hour_each": refresh["on_demand_usd_per_hour"],
            "cost_usd": compute_hourly * (DEADLINE_S / 3600),
        },
        "root_volumes": {
            "count": 2,
            "size_gib_each": root_gib,
            "gp3_usd_per_gib_month": refresh["gp3_usd_per_gib_month"],
            "cost_usd": root_volume_gib
            * refresh["gp3_usd_per_gib_month"]
            * DEADLINE_S
            / 3600
            / AVERAGE_MONTH_HOURS,
        },
        "recovery_volume": {
            "size_gib": recovery_gib,
            "gp3_usd_per_gib_month": refresh["gp3_usd_per_gib_month"],
            "cost_usd": recovery_gib
            * refresh["gp3_usd_per_gib_month"]
            * DEADLINE_S
            / 3600
            / AVERAGE_MONTH_HOURS,
        },
        "nat_gateway": {
            "usd_per_hour": NAT_GATEWAY_PER_HOUR,
            "hours": DEADLINE_S / 3600,
            "cost_usd": nat_hourly * (DEADLINE_S / 3600),
            "processing_allowance_gib": NAT_PROCESSING_ALLOWANCE_GB,
            "processing_usd_per_gib": NAT_PROCESSING_PER_GB,
            "processing_cost_usd": nat_processing,
        },
        "ssm_interface_endpoints": {
            "count": INTERFACE_ENDPOINT_COUNT,
            "services": ["ssm", "ssmmessages", "ec2messages"],
            "availability_zones_per_endpoint": 1,
            "hours": DEADLINE_S / 3600,
            "usd_per_endpoint_hour": INTERFACE_ENDPOINT_PER_HOUR,
            "hourly_cost_usd": endpoint_hourly,
            "processing_allowance_gb": INTERFACE_ENDPOINT_PROCESSING_ALLOWANCE_GB,
            "processing_usd_per_gb": INTERFACE_ENDPOINT_PROCESSING_PER_GB,
            "processing_cost_usd": endpoint_processing,
            "pricing_source": INTERFACE_ENDPOINT_PRICING_SOURCE,
        },
        "public_ipv4": {
            "count": 1,
            "purpose": "NAT gateway address; neither host has a public IPv4",
            "usd_per_hour": ipv4_hourly,
            "cost_usd": ipv4_hourly * (DEADLINE_S / 3600),
        },
        "s3_standard": {
            "data_object_count": data_objects,
            "manifest_object_count": 2,
            "put_requests": put_requests,
            "get_requests": get_requests,
            "list_requests": list_requests,
            "put_request_cost_usd": s3_put,
            "get_request_cost_usd": s3_get,
            "list_request_cost_usd": s3_list,
            "stored_bytes": stored_bytes,
            "input_staging_bytes": input_bundle_bytes,
            "input_staging_object_count": int(input_bundle_bytes > 0),
            "retention_hours": DEADLINE_S / 3600,
            "storage_usd_per_gib_month": S3_STANDARD_GB_MONTH,
            "storage_cost_usd": s3_storage,
            "deletes": "one or more DeleteObjects calls; no Delete request charge",
        },
        "allowances": {
            "archive_bytes": archive_bytes,
            "spool_raw_and_index_bytes": spool_bytes,
            "recovery_volume_gib": recovery_gib,
        },
        "hourly_all_resources_usd": hourly_all_resources,
        "task_cost_usd": task,
        "task_cost_forecast_usd": task,
        "cleanup_reserve_usd": 2.0,
        "prior_spend_usd": PRIOR_SPEND_USD,
        "hard_cap_usd": max(30, math.ceil(PRIOR_SPEND_USD + task + 3.0)),
    }


def _build_packet(
    directory,
    *,
    fixture,
    fixture_proof,
    sizing_proof,
    spool_output,
    specs,
    refresh_path,
):
    directory = Path(directory).resolve()
    fixture, fixture_proof, sizing_proof, spool_output, specs = map(
        Path, (fixture, fixture_proof, sizing_proof, spool_output, specs)
    )
    if directory.exists():
        raise FileExistsError("gate_a_packet:fresh_output_required")
    refresh = json.loads(Path(refresh_path).read_bytes())
    validate_host_refresh(refresh)
    if (
        "us-east-1a" not in refresh["availability_zones"]
        or refresh["standard_vcpu_quota"] < 16
        or refresh["active_instance_count"] != 0
    ):
        raise ValueError("gate_a_packet:offering_quota_or_usage")
    commit = run_git("rev-parse", "HEAD").decode().strip()
    clean = run_git(
        "status",
        "--porcelain",
        "--",
        "python",
        "scripts",
        "infra",
        "deploy",
        "internal",
        "cmd",
        "go.mod",
        "go.sum",
    )
    if clean:
        raise ValueError("gate_a_packet:source_worktree_dirty")
    pin_binding, fixture_value, fixture_inventory, sizing = validate_fixture_inputs(
        fixture, fixture_proof, sizing_proof
    )

    spool_manifest_path = spool_output / "manifest.json"
    spool_manifest = json.loads(spool_manifest_path.read_bytes())
    staged_fixture, staged_spool = (
        spool_output / "staged/fixture",
        spool_output / "staged/spool",
    )
    if inventory(staged_fixture) != fixture_inventory:
        raise ValueError("gate_a_packet:staged_fixture")
    spool_result = verify_wire_spool(
        staged_spool,
        expected_inventory=spool_manifest["spool"]["inventory"],
        minimum_raw_bytes=RAW_BYTES_ALLOWANCE,
        objects=14,
    )
    if spool_result["raw_bytes"] < RAW_BYTES_ALLOWANCE:
        raise ValueError("gate_a_packet:spool_below_floor")
    if spool_manifest["fixture"]["proof_sha256"] != sha(fixture_proof.read_bytes()):
        raise ValueError("gate_a_packet:spool_fixture_proof")
    if spool_manifest["fixture"]["source_lf_sha256"] != current_sources():
        raise ValueError("gate_a_packet:spool_source_current")

    directory.mkdir(parents=True)
    source_bundle = make_source_bundle(directory, commit)
    if source_bundle.stat().st_size > 256 * 1024**2:
        raise ValueError("gate_a_packet:source_bundle_limit")
    source_bytes = sum(
        int(row.split()[3])
        for row in run_git("ls-tree", "-rl", commit).decode().splitlines()
    )
    input_root = directory / "input-build"
    input_root.mkdir()
    key_path = input_root / "sanitizer-key.bin"
    key_path.write_bytes(secrets.token_bytes(32))
    pins_path = input_root / "pins.json"
    pins_path.write_bytes(encode(gate_a_binding()))
    expected_archive_path = input_root / "expected-archive-inventory.json"
    scratch_root = Path(
        r"D:\coding agent files\multi-tenant-llm-inference-platform\codex"
    )
    if not scratch_root.is_dir():
        scratch_root = ROOT / ".cache"
    scratch_root.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="r366-gate-a-sanitized-", dir=scratch_root
    ) as temporary:
        sanitized = Path(temporary) / "sanitized"
        sanitized_campaign(
            staged_fixture,
            sanitized,
            json.loads(specs.read_bytes()),
            key=key_path.read_bytes(),
        )
        expected_archive = inventory(sanitized)
        expected_archive_path.write_bytes(encode(expected_archive))
    input_bundle, input_inventory = _write_input_bundle(
        directory,
        staged_fixture,
        fixture_proof,
        sizing_proof,
        staged_spool,
        spool_manifest_path,
        specs,
        key_path,
        expected_archive_path,
        pins_path,
    )
    verify_tar_inventory(input_bundle, input_inventory)
    packet_pins_path = directory / "pins.json"
    shutil.copy2(pins_path, packet_pins_path)
    shutil.rmtree(input_root)
    archive_bytes = sum(row["bytes"] for row in expected_archive.values())
    spool_total = spool_result["raw_bytes"] + spool_result["index_bytes"]
    total_store_bytes = archive_bytes + spool_total
    recovery_bytes = total_store_bytes * RECOVERY_COPIES
    recovery_before_margin = recovery_bytes / GIB
    recovery_volume_gib = math.ceil(recovery_bytes * 1.25 / GIB)
    cost = cost_forecast(
        refresh=refresh,
        recovery_gib=recovery_volume_gib,
        archive_inventory=expected_archive,
        spool_inventory=spool_result["inventory"],
        input_bundle_bytes=input_bundle.stat().st_size,
    )

    tool_root = ROOT / ".tools/terraform/1.16.2/terraform.exe"
    plugin = ROOT / ".cache/session-manager-plugin/bin/bin/session-manager-plugin.exe"
    aws = shutil.which("aws")
    tools = {}
    for label, executable, argv in (
        ("aws", Path(aws or "missing-aws"), ["--version"]),
        ("terraform", tool_root, ["version", "-json"]),
        ("plugin", plugin, ["--version"]),
    ):
        if not executable.is_file():
            raise ValueError("gate_a_packet:operator_tool_missing:" + label)
        version = directory / (label + "-version.log")
        result = run_exe([executable, *argv], cwd=ROOT, output=version, timeout=30)
        tools[label] = {
            "path": str(executable),
            "sha256": package_sha(executable),
            "version_log_sha256": result["log_sha256"],
        }
        if (
            label == "terraform"
            and json.loads(version.read_bytes())["terraform_version"] != "1.16.2"
        ):
            raise ValueError("gate_a_packet:terraform_version")

    session = "r366-gate-a-20261102"
    bucket = f"mti-r366-gatea-{refresh['account_id_sha256'][:12]}-{commit[:8]}"
    bucket_prefix = f"gate-a/{session}/"
    variables = {
        "ami": refresh["ami"],
        "session": session,
        "source_commit": commit,
        "bucket_name": bucket,
        "recovery_volume_gib": recovery_volume_gib,
        "root_gib": 80,
        "transfer_port": 38473,
        "host_timer_seconds": HOST_TIMER_S,
    }
    save(directory / "input.tfvars.json", variables)
    terraform_target = directory / "terraform"
    terraform_target.mkdir()
    for source in (ROOT / "infra/terraform/gate_a").iterdir():
        if source.is_file():
            shutil.copy2(source, terraform_target / source.name)

    input_names = {
        "source": "fixture",
        "fixture_proof": "fixture-proof.json",
        "sizing_proof": "sizing-proof.json",
        "spool": "spool",
        "spool_manifest": "spool-manifest.json",
        "sanitizer_specs": "sanitizer-specs.json",
        "sanitizer_key": "sanitizer-key.bin",
        "expected_archive_inventory": "expected-archive-inventory.json",
        "pins": "pins.json",
    }
    gate_a_inputs = {
        "bundle_path": "gate-a-inputs.tar",
        "bundle_bytes": input_bundle.stat().st_size,
        "bundle_sha256": package_sha(input_bundle),
        "inventory": input_inventory,
        "paths": input_names,
        "fixture": {
            "proof_sha256": package_sha(fixture_proof),
            "source_lf_sha256": fixture_value["source_lf_sha256"],
            "rows": fixture_value["registered_archive_rows"],
            "bytes": sum(row["bytes"] for row in fixture_inventory.values()),
            "inventory_sha256": sha(encode(fixture_inventory)),
        },
        "spool": {
            "manifest_sha256": package_sha(spool_manifest_path),
            "inventory_sha256": spool_result["inventory_sha256"],
            "raw_bytes": spool_result["raw_bytes"],
            "index_bytes": spool_result["index_bytes"],
            "objects": spool_result["object_count"],
            "allowance_floor_bytes": RAW_BYTES_ALLOWANCE,
        },
        "pins": {
            "path": input_names["pins"],
            "sha256": input_inventory[input_names["pins"]]["sha256"],
            "binding": gate_a_binding(),
        },
        "s3_staging": {
            "bucket": bucket,
            "key": bucket_prefix + "input/gate-a-inputs.tar",
            "bundle_bytes": input_bundle.stat().st_size,
            "bundle_sha256": package_sha(input_bundle),
            "upload_deadline_offset_s": DEADLINE_S
            - APPLY_S
            - CLEANUP_S
            - GATE_A_OPERATION_CUTOFF_MS // 1000,
        },
        "archive": {
            "expected_inventory_sha256": sha(encode(expected_archive)),
            "bytes": archive_bytes,
            "objects": len(expected_archive),
        },
        "recovery_volume_sizing": {
            "archive_plus_spool_bytes": total_store_bytes,
            "copies_on_recovery_device": RECOVERY_COPIES,
            "copy_breakdown": {
                "receiver_transfer_staging": 1,
                "durable_recovery_store": 1,
                "per_phase_readback_trees": 4,
                "full_retrieval_trees": 2,
            },
            "pre_margin_gib": recovery_before_margin,
            "margin_percent": 25,
            "provisioned_gib": recovery_volume_gib,
        },
    }
    terraform_module = "/repo/infra/terraform/gate_a"
    sealed_plans(
        directory,
        module=terraform_module,
        expected_managed=EXPECTED_MANAGED_RESOURCES,
        gate_a=True,
    )
    sealed = json.loads((directory / "sealed-plans.json").read_bytes())
    manifest = {
        "schema": "dec077-exact-inputs-v1",
        "workload": "r366-gate-a",
        "created_at_utc": utc(),
        "source_commit": commit,
        "source_bundle_bytes": source_bundle.stat().st_size,
        "bundle_bytes": source_bundle.stat().st_size,
        "bundle_sha256": package_sha(source_bundle),
        "python_sha256": python_hashes(commit),
        "pins": json.loads((ROOT / "deploy/package-a/pins.json").read_bytes()),
        "instance_type": "c6i.2xlarge",
        "ami": refresh["ami"],
        "region": "us-east-1",
        "on_demand_usd_per_hour": refresh["on_demand_usd_per_hour"],
        "hourly_all_resources_usd": cost["hourly_all_resources_usd"],
        "account_id_sha256": refresh["account_id_sha256"],
        "refresh": refresh,
        "refresh_freshness": "cached read-only refresh; no AWS call made by this packet builder",
        "root_gib": 80,
        "session": session,
        "bucket_name": bucket,
        "bucket_prefix": bucket_prefix,
        "bucket_versioning": "off",
        "source_tree_bytes": source_bytes,
        "hard_cap_usd": cost["hard_cap_usd"],
        "prior_spend_usd": PRIOR_SPEND_USD,
        "task_cost_usd": cost["task_cost_usd"],
        "cumulative_cost_usd": PRIOR_SPEND_USD + cost["task_cost_usd"],
        "ceiling_usd": 300,
        "deadline_seconds": DEADLINE_S,
        "host_timer_seconds": HOST_TIMER_S,
        "cleanup_seconds": CLEANUP_S,
        "apply_forecast_s": APPLY_S,
        "upload_timeout_s": transfer_seconds(source_bundle.stat().st_size),
        "gate_a_input_staging": {
            "transport": "sender-read-only-s3-staging-prefix",
            "object_key": bucket_prefix + "input/gate-a-inputs.tar",
            "bundle_bytes": input_bundle.stat().st_size,
            "bundle_sha256": package_sha(input_bundle),
            "inventory_sha256": sha(encode(input_inventory)),
            "operator_upload_before_P": True,
            "sender_role_permission": "s3:GetObject only for this session input object",
            "reason": "no recorded rate exists for the approximately 3.2 GB SSM-forwarded /input-upload path; use same-region S3 staging to avoid an unmeasured upload-duration assumption",
            "upload_deadline": {
                "kind": "absolute_epoch",
                "origin_field": "lifecycle_start_epoch",
                "offset_seconds": gate_a_inputs["s3_staging"][
                    "upload_deadline_offset_s"
                ],
                "runtime_receipt_field": "upload_deadline_epoch",
            },
            "upload_deadline_offset_s": gate_a_inputs["s3_staging"][
                "upload_deadline_offset_s"
            ],
            "upload_deadline_epoch_source": "lifecycle_start_epoch plus upload_deadline_offset_s; one shared absolute epoch deadline covers local S3 put and sender S3 get",
            "pre_p_operation_window": "before P, remaining lifecycle time must cover 1,740-second operation, full retrieval_timeout_s and cleanup_seconds",
            "boto3_readiness_dependency": {
                "version": "1.43.123",
                "source": "python/pyproject.toml and python/uv.lock",
                "mount": "host virtual-environment site-packages mounted read-only at /gate-a-host-site-packages",
                "container_path": "/gate-a-host-site-packages/boto3/__init__.py",
            },
            "readback": "sender computes bundle SHA-256 and extracts/verifies every input inventory fact before P",
        },
        "retrieval_timeout_s": transfer_seconds(EXPORT_MAX_BYTES),
        "cleanup_cost_reserve_usd": cost["cleanup_reserve_usd"],
        "python_executable": "/opt/dec077/repo/python/.venv/bin/python",
        "operator_tools": tools,
        "session_manager_plugin_path": str(plugin.relative_to(ROOT)),
        "expected_managed_resources": EXPECTED_MANAGED_RESOURCES,
        "sealed_plans": sealed,
        "gate_a_inputs": gate_a_inputs,
        "gate_a_operation": {
            "measured_start": "sender monotonic start in run_gate_a_export after input hash readback and runner readiness",
            "measured_deadline_offset_ms": 1_740_000,
            "registered_o_export_max_ms": 1_800_000,
            "operation_pass_max_ms": 1_740_000,
            "transfer_formula_max_ms": 3_600_000,
            "shared_control_ms": 60_000,
            "shared_control_measured": False,
            "archive_raw_bytes": sizing["raw_bytes"],
            "reconnect_bound_ms": sizing["reconnect_bound_ms"],
            "max_reconnects_total": 1,
            "max_reconnect_seconds_total": sizing["reconnect_bound_ms"] / 1000,
            "formula_rate_source": "floor(archive_readback_bytes * 1000 / upper_archive_transfer_elapsed_ms), measured after archive transfer",
            "formula_evaluated_after_transfer": True,
            "spool_objects": 14,
            "spool_formula_inclusion": False,
        },
        "planned_receipts": [
            "source-current fixture proof, full fixture inventory and source pins",
            "export-sizing proof with raw_bytes and accepted_round_321 reconnect_bound_ms derivation",
            "spool manifest, allowance binding, raw/index inventory and index-to-raw verification",
            "pre-P sender staging bundle hash, per-file hash readback and durable staging receipt",
            "sanitizer, materializer, source and archive inventory/join receipts",
            "archive and spool transfer manifests, chunk offsets, attempts, induced drop and resume receipt",
            "both stores' durable acknowledgements, per-phase readback hashes and full retrieval inventory hashes",
            "sender O_export monotonic bracket, observed archive rate, transfer formula and verdict",
            "sender and receiver runner.json plus retrieved frozen logs",
            "lifecycle, teardown sequence, empty tagged inventory and post-consumption spend ledger row",
        ],
        "teardown_sequence": [
            "retrieve both sender and receiver frozen receipts",
            "unmount the recovery volume on the receiver",
            "detach and delete the standalone recovery volume",
            "empty and delete the non-versioned S3 bucket",
            "destroy both hosts and all tagged network/IAM resources",
            "verify no session-tagged hosts, volume, bucket, network resources or runner state remain",
        ],
        "gate_a_cost_forecast": cost,
        "gate_a_runner": {
            "common": gate_a_runner_common(
                {
                    "source_commit": commit,
                    "bundle_bytes": source_bundle.stat().st_size,
                    "bundle_sha256": package_sha(source_bundle),
                    "python_sha256": python_hashes(commit),
                    "pins": json.loads(
                        (ROOT / "deploy/package-a/pins.json").read_bytes()
                    ),
                    "python_executable": "/opt/dec077/repo/python/.venv/bin/python",
                    "session_manager_plugin_path": str(plugin.relative_to(ROOT)),
                    "session": session,
                    "region": "us-east-1",
                    "instance_type": "c6i.2xlarge",
                    "ami": refresh["ami"],
                    "on_demand_usd_per_hour": refresh["on_demand_usd_per_hour"],
                    "hourly_all_resources_usd": cost["hourly_all_resources_usd"],
                    "prior_spend_usd": PRIOR_SPEND_USD,
                    "hard_cap_usd": cost["hard_cap_usd"],
                    "cleanup_cost_reserve_usd": cost["cleanup_reserve_usd"],
                    "deadline_epoch": None,
                    "checks": [],
                }
            ),
            "roles": {
                "receiver": {
                    "gate_a_receiver": {
                        "host": "0.0.0.0",
                        "port": variables["transfer_port"],
                        "region": "us-east-1",
                        "endpoint_url": None,
                        "bucket": bucket,
                        "prefix": bucket_prefix,
                        "transfer_root": "/recovery/transfers",
                        "max_total_bytes": 8 * GIB,
                        "max_objects": 1024,
                        "service_timeout_s": DEADLINE_S,
                    }
                },
                "sender": {
                    "gate_a_sender": {
                        "receiver_private_address": "from_describe_instances",
                        "transfer_port": variables["transfer_port"],
                        "expected_pins": pin_binding,
                        "minimum_spool_raw_bytes": RAW_BYTES_ALLOWANCE,
                        "binding": gate_a_binding(),
                        "pins_path": "/opt/dec077/gate-a-inputs/pins.json",
                    }
                },
            },
        },
    }
    manifest["operator_command_line_preflight"] = gate_a_command_line_records(
        directory, manifest
    )
    manifest["operator_aws_cli_preflight"] = preflight_operator_aws_cli(
        tools["aws"]["path"], directory
    )
    save(directory / "manifest.json", manifest)
    checksummed = [
        "source.bundle",
        "gate-a-inputs.tar",
        "manifest.json",
        "pins.json",
        "input.tfvars.json",
        "sealed-plans.json",
        "terraform/create.tfplan",
        "terraform/destroy.tfplan",
        "terraform/.terraform.lock.hcl",
    ]
    checksums = "".join(
        f"{package_sha(directory / name)}  {name}\n" for name in checksummed
    )
    (directory / "SHA256SUMS").write_text(checksums, encoding="utf-8", newline="\n")
    verify_packet_checksums(directory)
    verify_tar_inventory(input_bundle, input_inventory)
    verify_live_inputs(
        staged_fixture,
        fixture_proof,
        sizing_proof,
        staged_spool,
        spool_manifest_path,
        specs,
        input_inventory,
    )
    return {
        "packet": str(directory),
        "source_commit": commit,
        "source_bundle_sha256": package_sha(source_bundle),
        "input_bundle_sha256": package_sha(input_bundle),
        "manifest_sha256": package_sha(directory / "manifest.json"),
        "create_plan_sha256": sealed["create_sha256"],
        "destroy_plan_sha256": sealed["destroy_sha256"],
        "fixture": gate_a_inputs["fixture"],
        "spool": gate_a_inputs["spool"],
        "archive": gate_a_inputs["archive"],
        "cost": cost,
        "plan_network": "none",
        "marker": False,
        "apply": False,
    }


def build_packet(
    directory,
    *,
    fixture,
    fixture_proof,
    sizing_proof,
    spool_output,
    specs,
    refresh_path,
):
    directory = Path(directory).resolve()
    cache_root = (ROOT / ".cache").resolve()
    if directory == cache_root or cache_root not in directory.parents:
        raise ValueError("gate_a_packet:output_must_be_under_cache")
    if directory.exists():
        raise FileExistsError("gate_a_packet:fresh_output_required")
    try:
        return _build_packet(
            directory,
            fixture=fixture,
            fixture_proof=fixture_proof,
            sizing_proof=sizing_proof,
            spool_output=spool_output,
            specs=specs,
            refresh_path=refresh_path,
        )
    except BaseException:
        if directory.exists() and not directory.is_symlink():
            try:
                preserve_refusal_diagnostics(directory)
            finally:
                remove_tree(directory)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--fixture-proof", type=Path, required=True)
    parser.add_argument("--sizing-proof", type=Path, required=True)
    parser.add_argument("--spool-output", type=Path, required=True)
    parser.add_argument("--specs", type=Path, required=True)
    parser.add_argument("--refresh", type=Path, required=True)
    args = parser.parse_args()
    result = build_packet(
        args.directory,
        fixture=args.fixture,
        fixture_proof=args.fixture_proof,
        sizing_proof=args.sizing_proof,
        spool_output=args.spool_output,
        specs=args.specs,
        refresh_path=args.refresh,
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
