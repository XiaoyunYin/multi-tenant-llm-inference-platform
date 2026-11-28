"""PID 1 owns this service. Only structured, bounded results reach the observer."""

import argparse
import hashlib
import json
import os
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path

import inf060_diagnostics as diagnostics
import inf060_operator_packet as remote
import inf060_probe_results as results
import inf060_probe_spec as spec
import inf061_packet as benchmark


def verify_environment(packet, manifest):
    spec.check(
        not any(
            k in os.environ
            for k in (
                "AWS_ACCESS_KEY_ID",
                "AWS_SECRET_ACCESS_KEY",
                "AWS_SESSION_TOKEN",
                "AWS_PROFILE",
                "AWS_WEB_IDENTITY_TOKEN_FILE",
                "AWS_CONTAINER_CREDENTIALS_FULL_URI",
            )
        ),
        "inherited_credentials",
    )
    spec.check(
        all(
            os.environ.get(k) == "/dev/null"
            for k in ("AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE")
        ),
        "credential_files",
    )
    who = json.loads(
        subprocess.check_output(
            ["aws", "sts", "get-caller-identity", "--output", "json"], timeout=30
        )
    )
    expected = (
        "arn:aws:sts::"
        + who["Account"]
        + ":assumed-role/"
        + manifest["operator_host"]["session"]
        + "-cpu/"
    )
    spec.check(
        who["Arn"].startswith(expected)
        and hashlib.sha256(who["Account"].encode()).hexdigest()
        == manifest["account_id_sha256"],
        "instance_role_identity",
    )
    subprocess.run(
        ["systemctl", "is-active", "--quiet", "dec077-terminate.timer"], check=True
    )
    deadline = int(Path("/etc/dec077/deadline").read_text())
    wait = manifest.get("capacity_hunt", {}).get("options", {}).get("wait_s", 0)
    spec.check(
        deadline - time.time() >= manifest["deadline_seconds"] + wait + 1200,
        "operator_remaining_lifetime",
    )
    with tarfile.open(packet / "operator-host/runtime.tar.gz") as archive:
        for member in archive:
            spec.check(
                member.isfile()
                and spec.facts(spec.safe_file(Path(remote.ROOT), member.name))["sha256"]
                == hashlib.file_digest(
                    archive.extractfile(member), "sha256"
                ).hexdigest(),
                "operator_source_delivery",
            )


def untagged_denial():
    cmd = ["aws", "ec2", "create-vpc", "--cidr-block", "10.77.0.0/24", "--dry-run"]
    result = subprocess.run(cmd, capture_output=True, timeout=45)
    spec.check(
        result.returncode != 0 and b"(UnauthorizedOperation)" in result.stderr,
        "untagged_ec2_permission",
    )
    return {
        "action": "ec2:CreateVpc",
        "tags": 0,
        "dry_run": True,
        "error_code": "UnauthorizedOperation",
        "exit_code": result.returncode,
    }


def arm_summary(archive, arm):
    matches = [
        m for m in archive if m.isfile() and m.name == "results/" + arm + ".json"
    ]
    if not matches:
        return None
    spec.check(len(matches) == 1 and matches[0].size <= spec.EXPORT_BYTES, "arm_result")
    row = json.load(archive.extractfile(matches[0]))
    join = row["abort_join"]
    # Whitelist aggregate data. Individual observations, request identifiers,
    # logs, hostnames and raw metric labels stay on the operator.
    summary = {
        k: int(row[k])
        for k in ("scheduled", "assigned_cancels", "client_cpu_ns", "engine_cpu_usec")
    }
    summary["outcomes"] = {
        k: int(v)
        for k, v in row["outcomes"].items()
        if k in {"complete", "cancelled", "failed", "missed_offer", "rejected"}
    }
    spec.check(len(summary["outcomes"]) == len(row["outcomes"]), "unknown_outcome")
    summary["join"] = {
        k: int(join[k])
        for k in (
            "orphan_abort_count",
            "sent",
            "identity_joins",
            "timing_joins",
            "frontend_abort_lines",
            "stock_abort_matches",
        )
    }
    summary["clock"] = {
        k: int(row["clock"][k])
        for k in (
            "offset_lo_ns",
            "offset_hi_ns",
            "sampled_offset_variation_ns",
            "stamp_resolution_ns",
            "minimum_interval_width_ns",
        )
    }
    return summary


def failure_record(packet, attempt):
    try:
        record = diagnostics.collect(attempt)
        binding = diagnostics.publish(packet / "failure-diagnostics.json", record)
        return {
            "status": "available",
            **binding,
            "preview": diagnostics.preview(record),
            "inline": record,
        }
    except Exception as exc:
        return {
            "status": "diagnostics_unavailable",
            "error": diagnostics.exception_record(exc),
        }


def save_witness(packet, name, receipt):
    raw = diagnostics.encoded(receipt)
    if len(raw) > diagnostics.SSM_STDOUT_BYTES and "diagnostics" in receipt:
        reduced = {
            key: value
            for key, value in receipt["diagnostics"].items()
            if key != "inline"
        }
        raw = diagnostics.encoded({**receipt, "diagnostics": reduced})
    spec.check(len(raw) <= diagnostics.SSM_STDOUT_BYTES, "witness_stdout_limit")
    (packet / name).write_bytes(raw)


def hunt_failure(packet, manifest, *, reason, error_type):
    from inf060_probe_operator import ProbePorts
    from inf061_capacity import close_reservation

    close_reservation(packet, manifest, time.time() + 120)
    ports = ProbePorts(packet, manifest, None, packet / "capacity-run", recovering=True)
    counts = ports.inventory(time.time() + 60)
    remote.require_zero(counts, capacity=True)
    path = packet / "capacity-wait.json"
    report = spec.load(path) if path.is_file() else {"elapsed_s": 0, "probes": []}
    receipt = {
        "manifest_sha256": spec.facts(packet / "manifest.json")["sha256"],
        "source": manifest["source_commit"],
        "supervisor_complete": False,
        "destroy_completed": True,
        "inventory": counts,
        "capacity": {
            "elapsed_s": report["elapsed_s"],
            "probes": len(report["probes"]),
            "reason": reason or report["status"],
            "error_type": error_type,
        },
        "benchmark": {"status": "results_unavailable"},
    }
    save_witness(packet, "verified-cleanup.json", receipt)
    save_witness(packet, "remote-result.json", receipt)


def hunt(packet, manifest):
    from inf060_probe_operator import ProbePorts, native_preflight
    from inf061_capacity import Hunter

    work = packet / "capacity-run"
    work.mkdir()
    ports = ProbePorts(packet, manifest, None, work)
    try:
        native_preflight(ports, packet, manifest, time.time(), capacity_stage="hunting")
        return Hunter(packet, manifest).select()
    except Exception as exc:
        path = packet / "capacity-wait.json"
        hunt_failure(
            packet,
            manifest,
            reason=None if path.is_file() else "capacity_preflight",
            error_type=type(exc).__name__,
        )
        return None


def run(mock_host=None, mock_failure=None):
    packet = Path(remote.PACKET)
    manifest = spec.verify_packet(packet)
    remote.verify(packet, manifest)
    verify_environment(packet, manifest)
    imports = remote.import_runtime(remote.ROOT)
    with (packet / "remote-started").open("x") as start:
        start.write(str(time.time()))
    if mock_host and os.environ.get("INF060_REHEARSAL_EXIT_BEFORE_APPLY") == "1":
        return 1
    failure = diagnostics.injected_failure(mock_host, mock_failure)
    denial = untagged_denial() if mock_host and not failure else None
    controls = []
    allow_side = None
    if mock_host and not failure:
        from rehearse_inf060_probe import mutations

        with tempfile.TemporaryDirectory() as tmp:
            controls = mutations(packet, Path(tmp))
        if "actions_sha256" in manifest["operator_host"]:
            from inf060_allow_side import run as rehearse_permissions

            allow_side = rehearse_permissions(packet, manifest)
            verify_environment(packet, manifest)
    capacity = "capacity_hunt" in manifest
    if capacity:
        selection = hunt(packet, manifest)
        if selection is None:
            return 1
    launch = [
        "/usr/bin/python3",
        remote.ROOT + "/scripts/inf060_probe_operator.py",
        "launch",
        "--directory",
        str(packet),
        "--instance-role",
    ]
    if mock_host:
        launch += ["--mock-host", mock_host]
    if failure:
        launch += ["--mock-failure", failure]
    code = subprocess.run(launch, check=False).returncode
    attempts = list((packet / "supervisor").glob("attempt-*"))
    if capacity and not attempts:
        spec.check(
            not (packet / "consumed.json").exists(), "capacity_consume_unverified"
        )
        hunt_failure(
            packet,
            manifest,
            reason="capacity_controller_not_started",
            error_type="ChildProcessError",
        )
        return 1
    spec.check(len(attempts) == 1, "remote_supervisor_attempt")
    attempt = attempts[0]
    stages = spec.load(attempt / "deadline.json")
    failed = (
        failure_record(packet, attempt) if code != 0 or not stages["complete"] else None
    )
    cleanup = spec.load(attempt / "probe-cleanup.json")
    inventory = spec.load(attempt / "probe-inventory.json")
    spec.check(cleanup["destroy_completed"] is True, "gpu_destroy_unverified")
    remote.require_zero(inventory, capacity=capacity)
    receipt = {
        "manifest_sha256": spec.facts(packet / "manifest.json")["sha256"],
        "source": manifest["source_commit"],
        "supervisor_complete": stages["complete"],
        "supervisor_exit": code,
        "supervisor_stages": stages["stages"],
        "origin_epoch": stages["t0_epoch"],
        "deadline_epoch": stages["deadline_epoch"],
        "elapsed_seconds": stages["elapsed_seconds"],
        "destroy_completed": True,
        "inventory": inventory,
        "mock": bool(mock_host),
        "isolated_imports": imports,
        "denial": denial,
        "image_inputs": {
            k: manifest["artifacts"][k]
            for k in ("tools.json", "engine.json", spec.LOG_CONFIG)
        },
    }
    if capacity:
        report = spec.load(packet / "capacity-wait.json")
        receipt["capacity"] = {
            "probes": len(report["probes"]),
            "elapsed_s": report["elapsed_s"],
            "zone": selection["zone"],
            "selected_epoch": selection["selected_epoch"],
        }
    receipt["mutations"] = controls
    if failed is not None:
        receipt["diagnostics"] = failed
    if allow_side is not None:
        receipt["allow_side"] = allow_side
    # Persist teardown proof even if reduction or transfer of an arm fails.
    save_witness(packet, "verified-cleanup.json", receipt)
    archive = attempt / "operator/receipts.tar.gz"
    if benchmark.is_benchmark(manifest):
        try:
            receipt["benchmark"] = benchmark.capture(
                archive, packet / "inf061-receipts.tar.gz"
            )
        except Exception as exc:
            receipt["benchmark"] = {
                "status": "results_unavailable",
                "error": diagnostics.exception_record(exc),
            }
        save_witness(packet, "remote-result.json", receipt)
        return code
    try:
        receipt["results"] = results.publish(
            packet / "probe-results.json",
            archive,
            complete=stages["complete"],
            mock=bool(mock_host),
        )
    except Exception as exc:
        receipt["results"] = {
            "status": "results_unavailable",
            "error": diagnostics.exception_record(exc),
        }
    # Recovery still has the result binding if reducing the inline arms fails.
    save_witness(packet, "verified-cleanup.json", receipt)
    if archive.exists():
        with tarfile.open(archive) as stream:
            receipt["arms"] = {
                arm: arm_summary(stream, arm) for arm in ("control", "logged")
            }
        spec.check(
            not stages["complete"] or all(receipt["arms"].values()), "missing_arm"
        )
    save_witness(packet, "remote-result.json", receipt)
    return code


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--mock-host")
    parser.add_argument("--mock-failure", choices=diagnostics.FAILURES)
    args = parser.parse_args()
    raise SystemExit(run(args.mock_host, args.mock_failure))
