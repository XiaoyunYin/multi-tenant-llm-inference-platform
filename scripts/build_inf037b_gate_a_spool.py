"""Stage the maximum archive and its Gate A raw/index wire model."""

import argparse
import hashlib
import json
import os
import shutil
import time
from pathlib import Path

from inference_platform.inf037b_archive import encode, file_facts, sha
from inference_platform.inf037b_contract import ATTEMPT_MS, RESET_MS
from inference_platform.inf037b_gate_a import gate_a_binding
from inference_platform.inf037b_maximum import load_maximum
from time_inf037b_wire import owner

ROOT = Path(__file__).resolve().parents[1]
ALLOWANCE_ID = "r436-round318.maximum-archive-as-wire-floor"
FIXTURE_ID = "v4-r315.source-current-maximum-export-fixture"
GENERATOR_ID = "gate-a.capture-owner-retainer.v1"
RAW_BYTES_ALLOWANCE = 1_615_101_807
REGISTERED_ARCHIVE_ROWS = 701_418
REGISTERED_SCHEDULE_MS = [ATTEMPT_MS] * 3 + [RESET_MS] * 2
CHUNK_BYTES = 64 * 1024


def inventory(root):
    root = Path(root)
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"gate_a_spool:symlink:{path.relative_to(root)}")
        if path.is_file():
            result[path.relative_to(root).as_posix()] = file_facts(path)
    if not result:
        raise ValueError("gate_a_spool:empty_inventory")
    return result


def copy_file(source, target):
    target.parent.mkdir(parents=True, exist_ok=True)
    with Path(source).open("rb") as reader, Path(target).open("xb") as writer:
        shutil.copyfileobj(reader, writer, length=1024 * 1024)
        writer.flush()
        os.fsync(writer.fileno())


def sync_file(path, *, platform_name=None):
    platform_name = os.name if platform_name is None else platform_name
    mode = "r+b" if platform_name == "nt" else "rb"
    with Path(path).open(mode) as stream:
        os.fsync(stream.fileno())


def sync_directory(path, *, platform_name=None):
    platform_name = os.name if platform_name is None else platform_name
    if platform_name == "nt":
        # Windows has no directory-fsync primitive; only local packet staging
        # uses this branch. Gate A execution and host receipts run on Linux.
        return
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def sync_tree(root, *, platform_name=None):
    platform_name = os.name if platform_name is None else platform_name
    root = Path(root)
    for path in sorted(Path(root).rglob("*"), key=lambda item: -len(item.parts)):
        if path.is_file():
            sync_file(path, platform_name=platform_name)
        elif path.is_dir():
            sync_directory(path, platform_name=platform_name)
    sync_directory(root, platform_name=platform_name)
    sync_directory(root.parent, platform_name=platform_name)


def build(
    fixture,
    fixture_proof_path,
    output,
    *,
    expected_pins,
    raw_bytes_allowance=RAW_BYTES_ALLOWANCE,
):
    fixture, output = Path(fixture).resolve(), Path(output).resolve()
    fixture_proof_path = Path(fixture_proof_path).resolve()
    if not fixture.is_dir() or fixture.is_symlink():
        raise ValueError("gate_a_spool:fixture_directory")
    if not fixture_proof_path.is_file() or fixture_proof_path.is_symlink():
        raise ValueError("gate_a_spool:fixture_proof")
    if output.exists():
        raise ValueError("gate_a_spool:output_exists")
    source_inventory = inventory(fixture)
    proof_hash = sha(fixture_proof_path.read_bytes())
    fixture_proof = json.loads(fixture_proof_path.read_text(encoding="utf-8"))
    fixture_proof = load_maximum(
        {"path": str(fixture_proof_path), "sha256": proof_hash},
        gate_a_binding()["pins"],
    )
    if expected_pins != gate_a_binding()["pins"]:
        raise ValueError("gate_a_spool:synthetic_binding")
    if fixture_proof.get("registered_archive_rows") != REGISTERED_ARCHIVE_ROWS:
        raise ValueError("gate_a_spool:registered_archive_rows")
    if fixture_proof["schedule_ms"] != REGISTERED_SCHEDULE_MS:
        raise ValueError("gate_a_spool:registered_schedule")
    if fixture_proof["fixture_inventory"] != source_inventory:
        raise ValueError("gate_a_spool:fixture_proof_inventory")
    source_bytes = sum(facts["bytes"] for facts in source_inventory.values())

    output.mkdir(parents=True)
    staged = output / "staged"
    staged.mkdir()
    staged_fixture = staged / "fixture"
    staged_fixture.mkdir()
    for relative in source_inventory:
        copy_file(fixture / relative, staged_fixture / relative)
    sync_tree(staged_fixture)
    staged_fixture_inventory = inventory(staged_fixture)
    if staged_fixture_inventory != source_inventory:
        raise ValueError("gate_a_spool:fixture_stage_readback")

    work = output / "work"
    capture = owner(work / "capture-owner")
    retainers = {kind: capture.retainer(kind) for kind in capture.sources}
    sequence = 0
    fixture_rows = 0
    for relative in source_inventory:
        kind = Path(relative).stem.split(".")[0]
        kind = kind if kind in retainers else "controller"
        file_records = 0
        is_raw_jsonl = relative.startswith("raw/") and relative.endswith(".jsonl")
        last_byte = None
        with (staged_fixture / relative).open("rb") as stream:
            while chunk := stream.read(CHUNK_BYTES):
                if is_raw_jsonl:
                    fixture_rows += chunk.count(b"\n")
                    last_byte = chunk[-1]
                start_ns = time.monotonic_ns()
                retainers[kind](
                    start_ns,
                    time.monotonic_ns(),
                    chunk,
                    {"fixture_file": relative, "model": "maximum-archive-as-wire"},
                )
                sequence += 1
                file_records += 1
                if file_records % 16 == 0:
                    retainers[kind].barrier()
        if is_raw_jsonl and last_byte not in (None, ord("\n")):
            capture.close()
            shutil.rmtree(work, ignore_errors=True)
            raise ValueError("gate_a_spool:fixture_jsonl_terminator")
        retainers[kind].barrier()
    if fixture_rows != REGISTERED_ARCHIVE_ROWS:
        capture.close()
        shutil.rmtree(work, ignore_errors=True)
        raise ValueError("gate_a_spool:fixture_archive_rows")
    capture_receipt = capture.close()
    source_spool = capture.root / "wire"
    staged_spool = staged / "spool"
    shutil.copytree(source_spool, staged_spool)
    sync_tree(staged_spool)
    source_spool_inventory = inventory(source_spool)
    staged_spool_inventory = inventory(staged_spool)
    if staged_spool_inventory != source_spool_inventory:
        raise ValueError("gate_a_spool:spool_stage_readback")

    raw_bytes = sum(
        facts["bytes"]
        for name, facts in staged_spool_inventory.items()
        if name.endswith(".bin")
    )
    index_bytes = sum(
        facts["bytes"]
        for name, facts in staged_spool_inventory.items()
        if name.endswith(".jsonl")
    )
    spool_files = len(staged_spool_inventory)
    if raw_bytes < raw_bytes_allowance or spool_files != 14:
        raise ValueError("gate_a_spool:allowance_or_object_count")
    if not capture_receipt["transport_clean"]:
        raise ValueError("gate_a_spool:capture_not_clean")

    source_files = {
        path.relative_to(ROOT).as_posix(): path
        for path in sorted((ROOT / "python/src/inference_platform").glob("inf037b*.py"))
    }
    source_files["scripts/time_inf037b_wire.py"] = ROOT / "scripts/time_inf037b_wire.py"
    source_files["scripts/build_inf037b_gate_a_spool.py"] = Path(__file__)
    generator_files = {
        name: hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()
        for name, path in source_files.items()
    }
    allowance = {"id": ALLOWANCE_ID, "raw_bytes": raw_bytes_allowance}
    manifest = {
        "schema": "inf037b-gate-a-spool-v2",
        "fixture": {
            "id": FIXTURE_ID,
            "proof_sha256": proof_hash,
            "source_lf_sha256": fixture_proof["source_lf_sha256"],
            "pins": fixture_proof["pins"],
            "schedule_ms": fixture_proof["schedule_ms"],
            "registered_archive_rows": fixture_rows,
            "bytes": source_bytes,
            "inventory": staged_fixture_inventory,
            "inventory_sha256": sha(encode(staged_fixture_inventory)),
        },
        "spool": {
            "id": "r436-round318.maximum-archive-as-wire.spool",
            "inventory": staged_spool_inventory,
            "inventory_sha256": sha(encode(staged_spool_inventory)),
            "raw_bytes": raw_bytes,
            "index_bytes": index_bytes,
            "file_count": spool_files,
            "object_count": spool_files,
        },
        "generator": {
            "id": GENERATOR_ID,
            "files": generator_files,
            "sha256": sha(encode(generator_files)),
            "chunk_bytes": CHUNK_BYTES,
            "retained_records": sequence,
            "owner_retainer": "CaptureOwner.retainer(controller)",
        },
        "allowance": {**allowance, "sha256": sha(encode(allowance))},
        "pre_p_staging": {
            "fixture_inventory_sha256": sha(encode(inventory(staged_fixture))),
            "spool_inventory_sha256": sha(encode(inventory(staged_spool))),
            "file_count": len(staged_fixture_inventory) + spool_files + 1,
            "readback_verified": True,
        },
        "capture_receipt": {
            "transport_clean": capture_receipt["transport_clean"],
            "spool_bytes": capture_receipt["spool_bytes"],
            "spool_files": capture_receipt["spool_files"],
            "spool_barriers": capture_receipt["spool_barriers"],
        },
    }
    encoded = encode(manifest)
    with (output / "manifest.json").open("xb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    copy_file(output / "manifest.json", staged / "manifest.json")
    staged_manifest = (staged / "manifest.json").read_bytes()
    if staged_manifest != encoded:
        raise ValueError("gate_a_spool:manifest_stage_readback")
    sync_tree(staged)
    sync_directory(output)
    checksum = (sha(encoded) + "  manifest.json\n").encode("utf-8")
    with (output / "manifest.sha256").open("xb") as stream:
        stream.write(checksum)
        stream.flush()
        os.fsync(stream.fileno())
    if (output / "manifest.sha256").read_bytes() != checksum:
        raise ValueError("gate_a_spool:manifest_checksum_readback")
    sync_directory(output)
    shutil.rmtree(work)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--fixture-proof", type=Path, required=True)
    parser.add_argument("--expected-pins", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--allowance-bytes", type=int, default=RAW_BYTES_ALLOWANCE)
    args = parser.parse_args()
    expected_pins = json.loads(args.expected_pins.read_text(encoding="utf-8"))
    manifest = build(
        args.fixture,
        args.fixture_proof,
        args.output,
        expected_pins=expected_pins,
        raw_bytes_allowance=args.allowance_bytes,
    )
    print(
        json.dumps(
            {
                "manifest_sha256": sha(encode(manifest)),
                "fixture_files": len(manifest["fixture"]["inventory"]),
                "fixture_bytes": manifest["fixture"]["bytes"],
                "registered_archive_rows": manifest["fixture"][
                    "registered_archive_rows"
                ],
                "spool_files": manifest["spool"]["file_count"],
                "raw_bytes": manifest["spool"]["raw_bytes"],
                "index_bytes": manifest["spool"]["index_bytes"],
                "generator_sha256": manifest["generator"]["sha256"],
                "allowance_sha256": manifest["allowance"]["sha256"],
            },
            sort_keys=True,
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
