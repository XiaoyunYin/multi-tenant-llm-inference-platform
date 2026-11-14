"""$0 post-join timing on SetupCommands; no branch/planned-host timing claim.

Build/materialize the full maximum archive outside the post-join timer. Run the
real capture, durable object copy/readback and branch archive validation. Only
after ConcurrentPreparation returns switch from the recorded fixture clock to
elapsed wall time. Every post-join validation/write is the production code path.
"""

import argparse
import copy
import hashlib
import json
import math
import os
import platform
import sys
import time
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "python/tests"), str(ROOT / "scripts")]

from inf037b_fitness_fixture import attach  # noqa: E402
from inf037b_setup_fixture import creation_raw, fixture, inventory, scope  # noqa: E402
from inf037b_observations_fixture import attach as observations  # noqa: E402
from test_inf037b_collectors import Records  # noqa: E402
from time_inf037b_three_attempts import build  # noqa: E402

from inference_platform.inf037b_archive import encode, sha, strict_json  # noqa: E402
from inference_platform.inf037b_campaign import materialize_bundle, sanitized_campaign  # noqa: E402
from inference_platform.inf037b_durable_ports import DurableStore  # noqa: E402
from inference_platform.inf037b_preparation import ConcurrentPreparation  # noqa: E402
from inference_platform.inf037b_maximum import current_sources, load_maximum  # noqa: E402
from inference_platform.inf037b_setup import SetupCommands  # noqa: E402
from inference_platform import inf037b_setup_observations as exports  # noqa: E402


def fitness_volume(value):
    """1,311 offers * 13.7 rows plus six 513-row clock streams, >=1,500 B/row.

    Existing fitness predicates remain the compact recorded controls. Additional
    valid controller precondition envelopes model serialization/normalization
    volume, not extra traffic, outcomes or probe duration.
    """
    offers = math.ceil(120 * 10.92)
    target = math.ceil(offers * 13.7) + 6 * 513
    raw = strict_json(value["fitness_raw"])
    records = Records()
    for i in range(max(0, target - len(raw["raw"]))):
        row = records.row(
            "controller", "precondition", 2000, name="post-join-volume", value="x" * 700
        )
        row.update(
            session_id=value["binding"]["session_id"],
            attempt_id="setup",
            stage=[],
            source_identity="timing-volume",
            source_seq=i,
            record_id="post-join-volume-" + str(i),
            collector_boot_id="host",
        )
        # Include the JSON newline in the 1,500-byte average assumption.
        row["payload"]["value"] += "x" * max(0, 1500 - len(encode(row)))
        raw["raw"].append(row)
    for row in raw["raw"]:
        row["collector_boot_id"] = "host"
    raw["raw"].sort(key=lambda r: r["observed_mono_ns"])
    value["fitness_raw"] = encode(raw)
    return {
        "offers": offers,
        "rows_per_offer": 13.7,
        "clock_rows": 6 * 513,
        "target_rows": target,
        "actual_rows": len(raw["raw"]),
        "minimum_synthetic_row_bytes": 1500,
        "fitness_raw_bytes": len(value["fitness_raw"]),
    }


def run(work, output):
    work.mkdir(parents=True)
    source = work / "source"
    print("Build current full three-attempt/two-reset maximum fixture", flush=True)
    specs, rows = build(source, reset_ms=300000, include_reset_capture=True)
    materialize_bundle(source, specs)
    value = observations(attach(fixture()), boot="host")
    assumptions = fitness_volume(value)
    at = [512000]

    def capture_clock():
        at[0] += 1
        return {"clock_id": "measurement", "boot_id": "host", "ms": [at[0]] * 2}

    print("Capture full archive outside post-join timer", flush=True)
    raw, paths = exports.capture_export(
        binding=value["binding"],
        source=source,
        sanitized=work / "sanitized",
        destination=work / "destination",
        sanitize=lambda src, dst: sanitized_campaign(
            src, dst, specs, key=b"post-join-local-key" * 2
        ),
        sample=capture_clock,
        reconnect_ms=1000,
    )
    exported = strict_json(raw)
    value.update(export_raw=raw, export_artifacts=paths)
    maximum_path = value["maximum_fixture_proof"]["path"]
    maximum = strict_json(value["artifacts"][maximum_path])
    maximum.update(
        source_inventory_sha256=sha(encode(exported["source"])),
        scope="current_full_three_attempt_two_reset_fixture",
    )
    value["artifacts"][maximum_path] = encode(maximum)
    value["maximum_fixture_proof"]["sha256"] = sha(value["artifacts"][maximum_path])
    sizing_path = value["lifecycle"]["transfer"]["sizing_proof"]["path"]
    sizing = strict_json(value["artifacts"][sizing_path])
    sizing["raw_bytes"] = sum(p["bytes"] for p in exported["source"].values())
    value["artifacts"][sizing_path] = encode(sizing)
    value["lifecycle"]["transfer"]["sizing_proof"]["sha256"] = sha(
        value["artifacts"][sizing_path]
    )
    store = DurableStore(work / "setup", {}, initialize=True)
    joined = [None]
    clock = [1000]

    def sample():
        n = (
            clock[0]
            if joined[0] is None
            else 513100 + math.ceil((time.perf_counter() - joined[0]) * 1000)
        )
        return {"clock_id": "measurement", "boot_id": "host", "ms": [n, n]}

    def capture(stop):
        return raw, paths

    def gpu(stop):
        return {
            k: v
            for k, v in {**value, "raw": encode(value["bundle"])}.items()
            if k not in {"export_raw", "export_artifacts"}
        }

    port, _ = inventory(scope())
    command = SetupCommands(
        store=store,
        binding=value["binding"],
        sample=sample,
        inventory=port,
        scope=scope(),
        collect=lambda op, stop: creation_raw(
            value["binding"], 1000, source_inventory=exported["source"]
        ),
        capture=capture,
        gpu=gpu,
    )
    command("creation", 1_801_000, {"measurement_deadline_ms": 1_801_000})
    original = ConcurrentPreparation.__call__

    def collected(adapter, op, stop):
        # Both branch start samples are at original P. On each returned port,
        # end/join advance to the end of the recorded setup fixture. The timer
        # covers only real post-join control time, not these synthetic branches.
        data = original(adapter, op, stop)
        joined[0] = time.perf_counter()
        return data

    # Set the branch end clock only after both start samples, via a barrier.
    from threading import Barrier

    barrier = Barrier(2)
    original_capture, original_gpu = command.collect.capture, command.collect.gpu

    def branch_capture(stop):
        barrier.wait(timeout=5)
        result = original_capture(stop)
        clock[0] = 513100
        return result

    def branch_gpu(stop):
        barrier.wait(timeout=5)
        result = original_gpu(stop)
        clock[0] = 513100
        return result

    command.collect.capture, command.collect.gpu = branch_capture, branch_gpu
    facts = exports.file_facts
    calls = []

    def checked_facts(path):
        if joined[0] is not None:
            calls.append(str(path))
        return facts(path)

    print(
        "Persist/read back and validate maximum objects inside both branches",
        flush=True,
    )

    with (
        patch.object(ConcurrentPreparation, "__call__", collected),
        patch.object(exports, "file_facts", checked_facts),
    ):
        command("preparation", 1_801_000, {"measurement_deadline_ms": 1_801_000})
    elapsed = (time.perf_counter() - joined[0]) * 1000
    # Inspect state after timing; the final durable write is already in common_ms.
    state = store.read()
    fitness_hex = value["fitness_raw"].hex().encode()
    copies = encode(state).count(fitness_hex)
    receipt = {
        "schema": "inf037b-post-join-timing-v1",
        "python": platform.python_version(),
        "platform": platform.platform(),
        "cost_usd": 0,
        "assumptions": assumptions,
        "maximum_source_rows": rows,
        "archive_inventory": {
            p: exported[p] for p in ("source", "sanitized", "destination")
        },
        "archive_files": len(paths),
        "archive_bytes": sum(
            f["bytes"]
            for p in ("source", "sanitized", "destination")
            for f in exported[p].values()
        ),
        "post_join_wall_ms": elapsed,
        "completion": command.last_completion,
        "common_limit_ms": 60000,
        "margin_ms": 60000 - command.last_completion["common_ms"],
        "post_join_file_facts_calls": calls,
        "fitness_hex_copies": copies,
        "state_bytes": (store.path / "state.json").stat().st_size,
        "scope": "real post-join code; recorded branch clocks; excludes branch/planned-host bounds",
        "inputs_lf_sha256": {
            str(p.relative_to(ROOT)).replace("\\", "/"): hashlib.sha256(
                p.read_bytes().replace(b"\r\n", b"\n")
            ).hexdigest()
            for p in [
                Path(__file__),
                *sorted((ROOT / "python/src/inference_platform").glob("inf037b*.py")),
                *(
                    ROOT / "python/tests" / name
                    for name in (
                        "inf037b_setup_fixture.py",
                        "inf037b_fitness_fixture.py",
                        "inf037b_observations_fixture.py",
                        "test_inf037b_collectors.py",
                    )
                ),
                ROOT / "scripts/time_inf037b_three_attempts.py",
            ]
        },
    }
    output.write_text(json.dumps(receipt, indent=2, allow_nan=False) + "\n")
    assert not calls and copies == 1
    assert receipt["completion"]["common_ms"] < 45000, (
        "insufficient margin; stop and report options"
    )
    print(
        json.dumps(
            {
                k: receipt[k]
                for k in ("completion", "margin_ms", "archive_bytes", "state_bytes")
            }
        ),
        flush=True,
    )


def replay(work, output, previous):
    """Repeat only the requested post-join section from real durable readbacks.

    A fresh benchmark store receives hard links to the completed capture's
    immutable objects. Each link is fsynced and independently hash-read back
    outside the timer. No live operation is retried or receipt rewritten.
    """
    from inference_platform.inf037b_durable_ports import sync_directory
    from inference_platform.inf037b_resolver import exact

    inputs = [
        Path(__file__),
        *sorted((ROOT / "python/src/inference_platform").glob("inf037b*.py")),
        *(
            ROOT / "python/tests" / name
            for name in (
                "inf037b_setup_fixture.py",
                "inf037b_fitness_fixture.py",
                "inf037b_observations_fixture.py",
                "test_inf037b_collectors.py",
            )
        ),
        ROOT / "scripts/time_inf037b_three_attempts.py",
    ]

    def hashes():
        return {
            p.relative_to(ROOT).as_posix(): sha(p.read_bytes().replace(b"\r\n", b"\n"))
            for p in inputs
        }

    before = hashes()
    state = DurableStore(previous, {}).read()
    fork = copy.deepcopy(state["preparation_fork"])
    exact(fork["export"]["archive_verified"], True, "timing:completed_readback")
    exact(fork["complete"]["join_ack"], True, "timing:completed_join")
    raw = bytes.fromhex(fork["export"]["raw_hex"])
    exported = strict_json(raw)
    value = observations(attach(fixture()), boot="host")
    assumptions = fitness_volume(value)
    exact(sha(value["fitness_raw"]), fork["gpu"]["sha256"], "timing:fitness_volume")
    value["fitness_raw"] = bytes.fromhex(fork["gpu"]["raw_hex"])
    work.mkdir(parents=True)
    store_path = work / "setup"
    objects = work / "setup.objects" / "readback"
    manifest = {}
    for key, facts in fork["export"]["artifacts"].items():
        target = objects / key
        target.parent.mkdir(parents=True, exist_ok=True)
        os.link(facts["path"], target)
        with target.open("rb") as stream:
            os.fsync(stream.fileno())
        exact(
            exports.file_facts(target),
            {k: facts[k] for k in ("bytes", "sha256")},
            "timing:link_readback",
        )
        manifest[key] = {**facts, "path": str(target.resolve())}
    for directory in sorted(
        (p for p in (work / "setup.objects").rglob("*") if p.is_dir()),
        key=lambda p: -len(p.parts),
    ):
        sync_directory(directory)
    sync_directory(work / "setup.objects")
    sync_directory(work)
    fork["export"]["artifacts"] = manifest
    maximum_path = value["maximum_fixture_proof"]["path"]
    maximum = strict_json(value["artifacts"][maximum_path])
    rows = 0
    for key, facts in manifest.items():
        if key.startswith("source/raw/") and key.endswith(".jsonl"):
            with Path(facts["path"]).open("rb") as stream:
                rows += sum(
                    chunk.count(b"\n")
                    for chunk in iter(lambda: stream.read(1024 * 1024), b"")
                )
    if rows != 701_418:
        raise RuntimeError("maximum_fixture_registered_row_count")
    maximum.update(
        registered_archive_rows=rows,
        source_inventory_sha256=sha(encode(exported["source"])),
        scope="current_full_three_attempt_two_reset_fixture",
        fixture_inventory=exported["source"],
        source_lf_sha256=current_sources(),
    )
    value["artifacts"][maximum_path] = encode(maximum)
    value["maximum_fixture_proof"]["sha256"] = sha(value["artifacts"][maximum_path])
    sizing_path = value["lifecycle"]["transfer"]["sizing_proof"]["path"]
    sizing = strict_json(value["artifacts"][sizing_path])
    sizing["raw_bytes"] = sum(f["bytes"] for f in exported["source"].values())
    value["artifacts"][sizing_path] = encode(sizing)
    value["lifecycle"]["transfer"]["sizing_proof"]["sha256"] = sha(
        value["artifacts"][sizing_path]
    )
    creation = copy.deepcopy(state["creation"])
    maximum_file = work / "maximum.json"
    maximum_file.write_bytes(encode(maximum))
    exact(
        load_maximum(
            {"path": str(maximum_file), "sha256": sha(encode(maximum))},
            value["binding"]["pins"],
        ),
        maximum,
        "timing:maximum_authority_join",
    )
    creation["data"].pop("raw", None)
    creation["data"].pop("raw_bytes", None)
    creation["data"]["raw_reference"] = ["creation", "capture"]
    creation["data"]["maximum_fixture_sha256"] = sha(encode(maximum))
    store = DurableStore(
        store_path,
        {
            "binding": value["binding"],
            "creation": creation,
            "preparation_fork": fork,
        },
        initialize=True,
    )
    started = [None]

    class ReadbackReplay(ConcurrentPreparation):
        def __call__(self, operation, stop):
            exact(operation, "preparation", "timing:post_join_only")
            result = {
                **value,
                "raw": encode(value["bundle"]),
                "export_raw": raw,
                "export_artifacts": manifest,
                "preparation_receipt": fork["complete"],
            }
            started[0] = time.perf_counter()
            return result

    def sample():
        at = 513100 + (
            0
            if started[0] is None
            else math.ceil((time.perf_counter() - started[0]) * 1000)
        )
        return {"clock_id": "measurement", "boot_id": "host", "ms": [at, at]}

    port, _ = inventory(scope())
    command = SetupCommands(
        store=store,
        binding=value["binding"],
        sample=sample,
        inventory=port,
        scope=scope(),
        collect=None,
        maximum_fixture=maximum,
    )
    command.collect = object.__new__(ReadbackReplay)
    facts = exports.file_facts
    calls = []

    def counted(path):
        calls.append(str(path))
        return facts(path)

    # These two assertions precede the timed run and bind the actual branch
    # evidence and independently reread objects to the current fixture/proofs.
    command.validate_preparation(
        {**value, "export_raw": raw, "preparation_receipt": fork["complete"]},
        creation["data"],
    )
    with patch.object(exports, "file_facts", counted):
        command("preparation", 1_801_000, {"measurement_deadline_ms": 1_801_000})
    elapsed = (time.perf_counter() - started[0]) * 1000
    result_state = store.read()
    copies = encode(result_state).count(value["fitness_raw"].hex().encode())
    receipt = {
        "schema": "inf037b-post-join-timing-v1",
        "cost_usd": 0,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "cpu_max": Path("/sys/fs/cgroup/cpu.max").read_text().strip(),
        "memory_max": Path("/sys/fs/cgroup/memory.max").read_text().strip(),
        "assumptions": assumptions,
        "maximum_source_rows": rows,
        "archive_inventory": {
            p: exported[p] for p in ("source", "sanitized", "destination")
        },
        "archive_bytes": sum(f["bytes"] for f in manifest.values()),
        "archive_files": len(manifest),
        "original_branch_raw_sha256": fork["export"]["sha256"],
        "maximum_fixture_proof": maximum,
        "maximum_fixture_proof_sha256": sha(encode(maximum)),
        "replay_readback_manifest_sha256": sha(encode(manifest)),
        "post_join_wall_ms": elapsed,
        "completion": command.last_completion,
        "common_limit_ms": 60000,
        "margin_ms": 60000 - command.last_completion["common_ms"],
        "post_join_file_facts_calls": calls,
        "fitness_hex_copies": copies,
        "state_bytes": (store.path / "state.json").stat().st_size,
        "scope": "current real post-join path replaying actual durable branch readbacks; excludes branch/planned-host timing",
        "inputs_lf_sha256": before,
        "inputs_unchanged": hashes() == before,
    }
    output.write_text(json.dumps(receipt, indent=2, allow_nan=False) + "\n")
    assert not calls and copies == 1 and receipt["inputs_unchanged"]
    assert command.last_completion["common_ms"] < 45000, (
        "insufficient margin; stop and report options"
    )
    print(
        json.dumps(
            {
                k: receipt[k]
                for k in ("completion", "margin_ms", "archive_bytes", "state_bytes")
            }
        ),
        flush=True,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--replay-state", type=Path)
    args = parser.parse_args()
    if args.replay_state:
        replay(args.work, args.output, args.replay_state)
    else:
        run(args.work, args.output)
