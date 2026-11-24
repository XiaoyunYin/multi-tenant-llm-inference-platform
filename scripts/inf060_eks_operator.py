"""Laptop streaming sequence, verified snapshots and lifecycle receipts."""

import hashlib
import json
import shutil
import tarfile
import time
from pathlib import Path

from inference_platform.inf060_eks_packet import (
    ARCHIVE_BYTES,
    TRANSFER_SECONDS,
    bound,
    require_window_budget,
    transfer_rate,
)
from inference_platform.inf060_eks_receipts import (
    ARCHIVE_LIMIT,
    EXPANDED_LIMIT,
    FILES,
    build,
    payload,
    verify,
)
from inference_platform.inf060_eks_schedule import LEVELS
from inference_platform.m5_descriptive_operator import phase_deadline
from inference_platform.private_identifier_scan import find_identifier_violations


def extract_verified(archive, dest, expected):
    archive, dest = Path(archive), Path(dest)
    if archive.stat().st_size != expected["bytes"] or expected["bytes"] > ARCHIVE_LIMIT:
        raise ValueError("streaming_archive_size")
    with archive.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != expected["sha256"]:
            raise ValueError("streaming_archive_digest")
    dest.mkdir()
    try:
        seen, expanded = set(), 0
        with tarfile.open(archive, "r|gz") as tar:
            for member in tar:
                expanded += member.size
                if (
                    member.name not in FILES | {"manifest.json"}
                    or member.name in seen
                    or not member.isfile()
                    or expanded > EXPANDED_LIMIT
                ):
                    raise ValueError("streaming_archive_member")
                seen.add(member.name)
                with (
                    tar.extractfile(member) as source,
                    (dest / member.name).open("xb") as writer,
                ):
                    shutil.copyfileobj(source, writer)
        return verify(dest, witness=expected["manifest_sha256"])
    except BaseException:
        shutil.rmtree(dest)
        raise


def retrieve(host, label, expected, dest, deadline, account_hash=None, on_bytes=None):
    if not 0 < expected["bytes"] <= ARCHIVE_LIMIT:
        raise ValueError("streaming_archive_limit")
    start = time.monotonic()
    tmp = dest.with_suffix(".tar.gz.part")
    with tmp.open("xb") as stream:
        while (offset := stream.tell()) < expected["bytes"]:
            data, headers = host.request(
                f"/inf060-snapshot/{label}/{offset}", end=deadline
            )
            if on_bytes is not None:
                on_bytes(len(data))
            if (
                not 0 < len(data) <= expected["bytes"] - offset
                or hashlib.sha256(data).hexdigest() != headers["X-Chunk-SHA256"]
            ):
                raise ValueError("streaming_chunk_binding")
            stream.write(data)
    manifest = extract_verified(tmp, dest, expected)
    if account_hash and any(
        find_identifier_violations(
            {"docs/evidence/" + member.name: member.read_bytes()}, account_hash
        )
        for member in dest.iterdir()
    ):
        shutil.rmtree(dest)
        raise ValueError("streaming_private_identifier")
    tmp.unlink()
    return {
        "status": "verified",
        **expected,
        "elapsed_s": time.monotonic() - start,
    }, manifest


def attach_local(directory, retrieval, teardown, cost):
    paths = {
        "retrieval.json": retrieval,
        "teardown.json": teardown,
        "cost.json": cost,
    }
    manifest_path = directory / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    original = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    for name, value in paths.items():
        data = payload(value)
        (directory / name).write_bytes(data)
        manifest["files"][name] = {
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
    manifest["remote_manifest_sha256"] = original
    manifest_path.write_bytes(payload(manifest))
    verify(directory)


def execute_streaming(ports, output):
    output = Path(output)
    output.mkdir()
    phases = []
    transfers = {}
    failed = None
    started = time.monotonic()
    lifecycle = output / "operation.json"
    timing = ports.manifest["timing"]
    descriptive = ports.manifest["descriptive"]
    gpu = descriptive.get("gpu_streaming")
    rates = {"laptop": None, "pod": None}
    probe = {}
    checkpoint_bounds = 0
    pod_bytes = 0
    laptop_bytes = 0

    def run(name, callback, *args):
        stamp = time.monotonic()
        item = {"phase": name, "status": "running"}
        phases.append(item)
        try:
            result = callback(*args)
        except Exception as exc:
            item.update(status="failed", exception=type(exc).__name__)
            raise
        else:
            item["status"] = "passed"
            return result
        finally:
            item["elapsed_s"] = time.monotonic() - stamp
            lifecycle.write_bytes(payload({"phases": phases, "transfers": transfers}))

    def collect(label, phase, deadline):
        nonlocal checkpoint_bounds, pod_bytes
        try:
            expected = run(phase, ports.remote, phase)
            transfer_window = 956
            if gpu:
                transfer_window = bound(expected["bytes"], rates["laptop"])
                pod_bytes = expected.get("pod_receipt_bytes", pod_bytes)
                if label != "final":
                    charge = transfer_window + bound(
                        max(1, expected.get("pod_window_bytes", 0)), rates["pod"]
                    )
                    final_bound = sum(
                        bound(ARCHIVE_BYTES, rate) for rate in rates.values()
                    )
                    if checkpoint_bounds + charge + final_bound > TRANSFER_SECONDS:
                        raise TimeoutError("streaming_checkpoint_transfer_reserve")
                    checkpoint_bounds += charge
            destination = output / ("results-" + label)
            args = (
                ports.host,
                label,
                expected,
                destination,
                min(deadline, time.time() + transfer_window),
                hashlib.sha256(ports.manifest["account"].encode()).hexdigest(),
            )
            record, manifest = run(
                "retrieve-" + label,
                retrieve,
                *args,
                *((count_laptop_bytes,) if gpu else ()),
            )
            transfers[label] = record
            return destination, manifest
        except Exception as exc:
            transfers[label] = {
                "status": "results_unavailable",
                "exception": type(exc).__name__,
            }
            raise

    def count_laptop_bytes(size):
        nonlocal laptop_bytes
        laptop_bytes += size

    destination = None
    last_snapshot = None
    teardown, inventory = {}, {}
    cpu_clock = descriptive.get("cpu_clock_rehearsal")
    levels = ("8",) if cpu_clock else LEVELS
    try:
        if gpu:
            rates["laptop"] = transfer_rate(descriptive["streaming"]["laptop_transfer"])
        run("provision", ports.provision)
        if gpu:
            probe = run(
                "operator-pod-transfer-probe", ports.remote, "stream-transfer-probe"
            )
            rates["pod"] = transfer_rate(probe)
            final_bounds = {
                hop: bound(ARCHIVE_BYTES, rate) for hop, rate in rates.items()
            }
            if (
                sum(final_bounds.values()) > TRANSFER_SECONDS
                or ports.end - time.time()
                < timing["minimum_workload_seconds"]
                + sum(final_bounds.values())
                + timing["cleanup_reserve_seconds"]
            ):
                raise TimeoutError("streaming_post_probe_budget")
            (output / "transfer-gate.json").write_bytes(
                payload(
                    {
                        "probe": probe,
                        "rates": rates,
                        "worst_final_seconds": final_bounds,
                    }
                )
            )
        for label in ("smoke", "warmup", *levels):
            if gpu and label in LEVELS:
                run(
                    "guard-" + label,
                    require_window_budget,
                    label,
                    ports.end - time.time(),
                    rates["laptop"],
                    rates["pod"],
                )
            run("window-" + label, ports.remote, "stream-window-" + label)
            if label in LEVELS:
                last_snapshot, _ = collect(
                    label,
                    "stream-snapshot-" + label,
                    phase_deadline(ports.end, timing, "load"),
                )
    except Exception as exc:
        failed = exc
    finally:
        try:
            mode = (
                "stream-final" if failed is None and not cpu_clock else "stream-partial"
            )
            destination, manifest = collect(
                "final", mode, phase_deadline(ports.end, timing, "retrieve")
            )
            if failed is None:
                if cpu_clock:
                    verify_cpu_clock_results(destination)
                elif not manifest["complete"]:
                    raise ValueError("streaming_incomplete")
        except Exception as exc:
            failed = failed or exc
        # Preserve both proofs even if one cleanup operation raises.
        for name, target in (("teardown", teardown), ("inventory", inventory)):
            try:
                result = run(name, getattr(ports, name))
                if result.get("complete") is not True:
                    raise ValueError("streaming_" + name + "_unverified")
                target.update(result)
            except Exception as exc:
                failed = failed or exc
                target.update(complete=False, exception=type(exc).__name__)
        elapsed = time.monotonic() - started
        basis = ports.manifest["forecast_basis"]
        cost = {
            "estimates": True,
            "elapsed_s": elapsed,
            "platform_usd": (
                elapsed / 3600 * basis["hourly_usd"] + basis["fixed_other_usd"]
            )
            * basis["margin"],
            "gpu_usd": elapsed
            / 3600
            * ports.manifest["descriptive"]["streaming"]["gpu_hourly_usd"],
            "basis": "session allocation over lifecycle; reserves included in platform estimate",
        }
        cleanup = {
            "teardown_complete": teardown.get("complete", False),
            "inventory_complete": inventory.get("complete", False),
        }
        proof = inventory.get("inventory", {})
        cleanup["inventory_counts"] = {
            key: len(value["resources"])
            for key, value in proof.get("inventories", {}).items()
        }
        cleanup["supplemental_counts"] = {
            key: len(value) for key, value in proof.get("extra", {}).items()
        }
        if gpu:
            totals = {
                "laptop_operator_archive_bytes": laptop_bytes,
                "operator_pod_receipt_bytes": pod_bytes,
                "operator_pod_probe_bytes": sum(
                    row["bytes"] for row in probe.get("passes", {}).values()
                ),
                "checkpoint_transfer_bound_s": checkpoint_bounds,
            }
            transfers["totals"] = totals
        for name, value in (
            ("retrieval", transfers),
            ("teardown", cleanup),
            ("cost", cost),
        ):
            (output / (name + ".json")).write_bytes(payload(value))
        lifecycle.write_bytes(payload({"phases": phases, "transfers": transfers}))
        if destination is None:
            destination = output / "results-final"
            if last_snapshot is not None:
                shutil.copytree(last_snapshot, destination)
            else:
                build(
                    destination,
                    ports.manifest["descriptive"]["streaming"]["conditions"],
                    {},
                    {"status": "remote_unavailable", "phases": phases},
                )
        (output / "final-original-manifest.json").write_bytes(
            (destination / "manifest.json").read_bytes()
        )
        attach_local(destination, transfers, cleanup, cost)
    if failed is not None:
        raise failed


def verify_cpu_clock_results(directory):
    levels = json.loads((directory / "levels.json").read_bytes())
    clocks = json.loads((directory / "clocks.json").read_bytes())
    observers = json.loads((directory / "observers.json").read_bytes())
    diagnostics = json.loads((directory / "diagnostics.json").read_bytes())
    records = {row["phase"]: row for row in diagnostics["records"]}
    proof = records["cpu-clock-policy"]
    if (
        proof["nodes"] != 3
        or proof["agent"] != {"enabled": True, "desired": 3, "ready": 3}
        or not proof["policy"]["passed"]
        or proof["policy"]["allowed"] != [{"engine": True, "clock": True}] * 2
        or proof["policy"]["denied"] != [{"engine": True, "clock": False}] * 2
    ):
        raise ValueError("cpu_clock:policy_recount")
    for name, rows in (
        ("idle", proof["idle"]),
        ("fallback", proof["fallback"]),
        ("peak", records["cpu-clock-peak"]["replicas"]),
    ):
        if (
            len(rows) != 2
            or {row["replica"] for row in rows} != {1, 2}
            or any(row.get("width_ns") is None for row in rows)
            or (name == "peak" and any(row.get("running", 0) <= 0 for row in rows))
            or (name == "idle" and any(row.get("running") != 0 for row in rows))
        ):
            raise ValueError("cpu_clock:" + name + "_measurement")
    if levels["8"]["scheduled"] != 4800 or levels["8"]["rate_unavailable_reason"]:
        raise ValueError("cpu_clock:whole_window")
    if observers["8"].get("suppression") != "PASS" or {
        row["generation"]
        for row in clocks["8"] + observers["8"].get("clock_refusals", [])
    } != {1, 2}:
        raise ValueError("cpu_clock:whole_window_observers")
