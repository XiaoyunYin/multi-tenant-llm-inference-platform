"""Offline :50 replay and :42 sizing/transfer raw-evidence producers.

Only disposable local journals/archives are written. No executor, provider or
paid entry point is configured. Maximum-fixture authority and recovery bounds
must be bound by the later exact plan; synthetic tests confer neither.
"""

import copy
import hashlib
import tempfile
from pathlib import Path

from .inf037b_archive import (
    encode,
    export_archive,
    safe_file,
    sha,
    strict_json,
    verify_archive,
)
from .inf037b_attempts import AttemptController
from .inf037b_contract import ATTEMPT_MS, RESET_MS
from .inf037b_export_runtime import export_memoization
from .inf037b_resolver import allowance, exact, integer, require, span

PHASES = (600000, 30000, 300000, 600000, 30000)
FILE_CHUNK_BYTES = 1024 * 1024


def file_facts(path):
    digest = hashlib.sha256()
    size = 0
    with Path(path).open("rb") as stream:
        while chunk := stream.read(FILE_CHUNK_BYTES):
            size += len(chunk)
            digest.update(chunk)
    return {"bytes": size, "sha256": digest.hexdigest()}


def recipe():
    """Full maximum logical schedule, including both full reset/setup paths."""
    return [
        {"phase": phase, "index": index, "waits_ms": list(waits)}
        for phase, index, waits in (
            ("attempt", 1, PHASES),
            ("reset", 1, (RESET_MS,)),
            ("attempt", 2, PHASES),
            ("reset", 2, (RESET_MS,)),
            ("attempt", 3, PHASES),
        )
    ]


def elapsed(first, last):
    exact(
        (last["clock_id"], last["boot_id"]),
        (first["clock_id"], first["boot_id"]),
        "observations:clock_identity",
    )
    lo, hi = span(first["ms"], "observations:start")
    end_lo, end_hi = span(last["ms"], "observations:end")
    require(
        bool(first["clock_id"])
        and bool(first["boot_id"])
        and 0 <= lo <= hi <= end_lo <= end_hi
        and hi - lo <= 100
        and end_hi - end_lo <= 100,
        "observations:clock_order",
    )
    return [max(0, end_lo - hi), end_hi - lo]


def run_replay(journal, sample):
    """Run the accepted attempt controller with virtual waits and real fsyncs."""
    controller = AttemptController(journal)
    virtual, samples, trace = 0, [], []
    for item in recipe():
        first = copy.deepcopy(sample())
        begin = virtual
        index = item["index"]
        if item["phase"] == "reset":
            controller.begin_reset(virtual, remaining_ms=10000000, export_cleanup_ms=0)
            controller.allocate(virtual, remaining_ms=10000000, export_cleanup_ms=0)
            virtual += RESET_MS
            controller.setup_complete(virtual, preconditions=True, reasons=[])
        else:
            if index == 1:
                controller.allocate(virtual, remaining_ms=10000000, export_cleanup_ms=0)
                controller.setup_complete(virtual, preconditions=True, reasons=[])
            for stage, wait in enumerate(item["waits_ms"], 1):
                trace.append(
                    {
                        "attempt": index,
                        "stage": stage,
                        "begin_ms": virtual,
                        "end_ms": virtual + wait,
                    }
                )
                virtual += wait
            controller.end_attempt(
                virtual,
                measurement_valid=True,
                reasons=[],
                operational_outcomes=[],
                replacement_usable_by_deadline=True,
            )
        last = copy.deepcopy(sample())
        samples.append(
            {
                "phase": item["phase"],
                "index": index,
                "virtual_ms": [begin, virtual],
                "start": first,
                "end": last,
            }
        )
    return {"samples": samples, "trace": trace, "journal_hex": journal.read_bytes().hex()}


def capture_replay(*, binding, sample, work):
    # Caller must bracket this whole operation with the setup command deadline.
    # Construction/validation are included in preparation, not hidden rollout time.
    require(not work.exists(), "observations:fresh_replay_workspace")
    work.mkdir(parents=True)
    before = copy.deepcopy(sample())
    result = run_replay(work / "attempts.jsonl", sample)
    after = copy.deepcopy(sample())
    return encode(
        {
            "schema": "inf037b-replay-capture-v1",
            **binding,
            "recipe": recipe(),
            "nonmutating": True,
            "start": before,
            "end": after,
            **result,
        }
    )


def replay_observations(raw, *, binding):
    value = strict_json(raw)
    exact(value["schema"], "inf037b-replay-capture-v1", "observations:replay_schema")
    for key, expected in binding.items():
        exact(value[key], expected, "observations:replay_binding")
    require(binding["t0_ms"] <= value["start"]["ms"][0], "observations:setup_origin")
    exact(value["recipe"], recipe(), "observations:maximum_schedule")
    exact(value["nonmutating"], True, "observations:nonmutating")
    total = elapsed(value["start"], value["end"])
    # Independently reconstruct the expected journal and every virtual phase.
    # Never accept a supplied verdict/report or use a successful rollout outcome.
    with tempfile.TemporaryDirectory() as directory:
        replay = run_replay(Path(directory) / "attempts.jsonl", lambda: value["start"])
    exact(value["journal_hex"], replay["journal_hex"], "observations:replay_journal")
    exact(value["trace"], replay["trace"], "observations:replay_trace")
    exact(len(value["samples"]), 5, "observations:replay_samples")
    result = {"attempt": [], "reset": []}
    previous = value["start"]
    for item, expected in zip(value["samples"], replay["samples"], strict=True):
        for key in ("phase", "index", "virtual_ms"):
            exact(item[key], expected[key], "observations:replay_sample_join")
        elapsed(previous, item["start"])
        observation = elapsed(item["start"], item["end"])
        result[item["phase"]].append(observation)
        previous = item["end"]
    elapsed(previous, value["end"])
    for phase, values in result.items():
        allowance(phase, values, ATTEMPT_MS if phase == "attempt" else RESET_MS)
    return {
        "observations_ms": result,
        "virtual_schedule_ms": [ATTEMPT_MS] * 3 + [RESET_MS] * 2,
        "capture_elapsed_ms": total,
        "raw_sha256": sha(raw),
        "nonmutating": True,
    }


def inventory(root):
    return {
        p.relative_to(root).as_posix(): file_facts(p)
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }


@export_memoization
def capture_export(
    *,
    binding,
    source,
    sanitized,
    destination,
    sanitize,
    sample,
    reconnect_ms,
    network_transfer=None,
    after_transfer=None,
):
    """Capture real sanitization, interrupted copy/resume and readback evidence.

    `sanitize` is the accepted source-to-sanitized adapter, normally
    sanitized_campaign with the exact-plan maximum fixture/specs/key bound.
    No network client is provided here. Local copies are test observations only.
    """
    first = copy.deepcopy(sample())
    verify_archive(source)
    source_files = inventory(source)
    sanitize(source, sanitized)
    verify_archive(sanitized)
    safe_files = inventory(sanitized)
    transfer_start = copy.deepcopy(sample())
    size = sum(p["bytes"] for p in safe_files.values())
    network_result = None
    if network_transfer is None:
        interrupted = export_archive(sanitized, destination, byte_budget=max(1, size // 2))
        reconnect_start = copy.deepcopy(sample())
        resumed = export_archive(sanitized, destination)
        destination_files = inventory(destination)
        destination_artifacts = {name: destination / name for name in destination_files}
        transfer_end = None
        reconnect_elapsed_ms = None
    else:
        network_result = network_transfer(
            sanitized=sanitized,
            sanitized_inventory=safe_files,
            destination=destination,
            transfer_start=copy.deepcopy(transfer_start),
        )
        interrupted = network_result["interrupted"]
        reconnect_start = copy.deepcopy(network_result.get("reconnect_start", transfer_start))
        resumed = network_result["resumed"]
        transfer_start = copy.deepcopy(network_result.get("transfer_start", transfer_start))
        destination_files = network_result["destination_inventory"]
        destination_artifacts = network_result["destination_artifacts"]
        transfer_end = copy.deepcopy(network_result["transfer_end"])
        reconnect_elapsed_ms = network_result["reconnect_elapsed_ms"]
    exact(source_files, inventory(source), "observations:source_unchanged")
    require(not interrupted["complete"] and resumed["complete"], "observations:transfer_resume")
    artifacts = {
        prefix + "/" + name: root / name
        for prefix, root, files in (
            ("source", source, source_files),
            ("sanitized", sanitized, safe_files),
        )
        for name in files
    }
    artifacts.update(
        {"destination/" + name: destination_artifacts[name] for name in destination_files}
    )
    post_transfer = after_transfer(network_result) if after_transfer is not None else None
    last = copy.deepcopy(sample())
    evidence = {
        "schema": "inf037b-export-capture-v1",
        **binding,
        "source": source_files,
        "sanitized": safe_files,
        "destination": destination_files,
        "start": first,
        "end": last,
        "transfer_start": transfer_start,
        "reconnect_start": reconnect_start,
        "reconnect_bound_ms": reconnect_ms,
        "interrupted": interrupted,
        "resumed": resumed,
    }
    if transfer_end is not None:
        evidence["transfer_end"] = transfer_end
        evidence["reconnect_elapsed_ms"] = reconnect_elapsed_ms
    if post_transfer is not None:
        evidence["gate_a_post_transfer"] = post_transfer
    return encode(evidence), artifacts


def validate_export_archives(value, artifacts, *, readback=False):
    """Validate archive semantics during the export branch, after readback."""
    _export_archives(value, artifacts, readback=readback)


def _export_archives(value, artifacts, *, readback=False):
    if isinstance(value, (bytes, str)):
        value = strict_json(value)
    roots = {}
    for prefix in ("source", "sanitized", "destination"):
        observed = {}
        root = None
        for name, facts in value[prefix].items():
            key = prefix + "/" + name
            require(key in artifacts, "observations:archive_artifact")
            artifact = artifacts[key]
            if isinstance(artifact, dict):
                require(
                    set(artifact) == {"path", "bytes", "sha256"}, "observations:archive_manifest"
                )
                path = Path(artifact["path"])
            elif isinstance(artifact, (str, Path)):
                path = Path(artifact)
            else:
                require(False, "observations:archive_path")
            actual = (
                {"bytes": artifact["bytes"], "sha256": artifact["sha256"]}
                if readback and isinstance(artifact, dict)
                else file_facts(path)
            )
            exact(actual, facts, "observations:archive_bytes")
            if isinstance(artifact, dict):
                exact(
                    actual,
                    {"bytes": artifact["bytes"], "sha256": artifact["sha256"]},
                    "observations:archive_manifest",
                )
            relative = Path(name)
            candidate = path.parents[len(relative.parts) - 1]
            exact(path, safe_file(candidate, name), "observations:archive_path")
            if root is None:
                root = candidate
            else:
                exact(candidate, root, "observations:archive_path")
            observed[name] = actual
        require(root is not None, "observations:archive_inventory")
        exact(observed, value[prefix], "observations:archive_inventory")
        if not readback or prefix in {"source", "sanitized"}:
            verified = verify_archive(root, known_files=observed)
            require(
                not any(r["integrity_errors"] for r in verified["segments"].values()),
                "observations:archive_integrity",
            )
            registration = strict_json((root / "registration.json").read_bytes())
            exact(registration["sanitized"], prefix != "source", "observations:sanitized_label")
        roots[prefix] = root
    if not readback:
        provenance = strict_json(
            (roots["sanitized"] / "source-integrity.receipt.json").read_bytes()
        )
        exact(
            provenance["source_manifest_sha256"],
            value["source"]["SHA256SUMS"]["sha256"],
            "observations:sanitizer_source",
        )
        require(
            not provenance["segments"] and provenance["pending_sse_streams"] == 0,
            "observations:sanitizer_complete",
        )
    for receipt in (value["interrupted"], value["resumed"]):
        exact(
            receipt["source_manifest_sha256"],
            value["sanitized"]["SHA256SUMS"]["sha256"],
            "observations:transfer_source",
        )


def export_observations(raw, *, binding, artifacts, maximum_fixture, sizing_proof, readback=False):
    """Derive bytes/rate/O_export from raw archive bytes and raw readbacks.

    maximum_fixture is a subject/pins/hash-bound pre-session proof input. It is
    NOT synthesized from a row's `full_fixture...` flag. Later exact-plan review
    must establish its size/coverage authority; tests use an explicit synthetic
    proof for a compact adapter fixture, never a live maximum-size claim.
    """
    value = strict_json(raw)
    exact(value["schema"], "inf037b-export-capture-v1", "observations:export_schema")
    for key, expected in binding.items():
        exact(value[key], expected, "observations:export_binding")
    require(binding["t0_ms"] <= value["start"]["ms"][0], "observations:setup_origin")
    exact(
        maximum_fixture["subject"],
        "lifecycle:maximum_export_fixture",
        "observations:fixture_subject",
    )
    exact(maximum_fixture["pins"], binding["pins"], "observations:fixture_pins")
    exact(
        maximum_fixture["schedule_ms"],
        [ATTEMPT_MS] * 3 + [RESET_MS] * 2,
        "observations:fixture_schedule",
    )
    exact(
        maximum_fixture["source_inventory_sha256"],
        sha(encode(value["source"])),
        "observations:fixture_source",
    )
    exact(sizing_proof["subject"], "lifecycle:export_sizing", "observations:sizing_subject")
    exact(sizing_proof["pins"], binding["pins"], "observations:sizing_pins")
    require(
        "reconnect_bound_ms" in sizing_proof,
        "observations:reconnect_proof_bound_missing",
    )
    require(
        integer(sizing_proof["reconnect_bound_ms"]) and sizing_proof["reconnect_bound_ms"] >= 0,
        "observations:reconnect_proof_bound",
    )
    exact(
        value["reconnect_bound_ms"],
        sizing_proof["reconnect_bound_ms"],
        "observations:reconnect_capture_bound",
    )
    total = elapsed(value["start"], value["end"])
    transfer = elapsed(value["transfer_start"], value.get("transfer_end", value["end"]))
    if "reconnect_elapsed_ms" in value:
        reconnect_ms = value["reconnect_elapsed_ms"]
        require(integer(reconnect_ms) and reconnect_ms >= 0, "observations:reconnect_elapsed")
    else:
        elapsed(value["transfer_start"], value["reconnect_start"])
        reconnect_ms = elapsed(value["reconnect_start"], value["end"])[1]
    elapsed(value["start"], value["transfer_start"])
    require(
        integer(value["reconnect_bound_ms"]) and reconnect_ms <= value["reconnect_bound_ms"],
        "observations:reconnect_bound",
    )
    exact(value["interrupted"]["complete"], False, "observations:interrupted")
    exact(value["resumed"]["complete"], True, "observations:resumed")
    exact(value["sanitized"], value["destination"], "observations:transfer_readback")
    _export_archives(value, artifacts, readback=readback)
    raw_bytes = sum(p["bytes"] for p in value["source"].values())
    transferred = sum(p["bytes"] for p in value["destination"].values())
    require(transferred <= 2 * raw_bytes, "observations:archive_margin")
    require(transfer[1] > 0 and transferred > 0 and raw_bytes > 0, "observations:transfer_duration")
    rate = transferred * 1000 // transfer[1]
    require(rate > 0, "observations:transfer_rate")
    allowance("export", [total], 3_600_000)
    return {
        "observation_ms": total,
        "transfer": {
            "raw_bytes": raw_bytes,
            "maximum_archive_bytes": 2 * raw_bytes,
            "minimum_bytes_per_second": rate,
            "reconnect_ms": sizing_proof["reconnect_bound_ms"],
            "attempts": 3,
            "reset_durations_ms": [RESET_MS] * 2,
            "full_fixture_sanitized_and_verified": True,
            "uses_rollout_compression": False,
        },
        "raw_sha256": sha(raw),
        "source_inventory_sha256": sha(encode(value["source"])),
        "paid_ready": False,
    }
