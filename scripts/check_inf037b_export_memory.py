"""Measure archive export RSS growth with realistic JSONL rows."""

import argparse
import ast
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python/tests"))
sys.path.insert(0, str(ROOT / "python/src"))

from inf037b_setup_fixture import fixture  # noqa: E402
from inference_platform.inf037b_archive import (  # noqa: E402
    Archive,
    encode,
    envelope,
    sha,
    strict_json,
)
from inference_platform.inf037b_contract import REGISTRATION_ID, SOURCE_KINDS  # noqa: E402
from inference_platform.inf037b_durable_ports import DurableStore  # noqa: E402
from inference_platform.inf037b_setup import SetupCommands, persist_archive_artifacts  # noqa: E402
from inference_platform.inf037b_setup_observations import (  # noqa: E402
    capture_export,
    export_observations,
    file_facts,
    inventory,
)

ROW_TARGET_BYTES = 2500
RSS_DELTA_LIMIT = 64 * 1024 * 1024
ROW_GROWTH_LIMIT = 1500


def _seen_map_keeps_hashes(source):
    function = next(
        node
        for node in ast.parse(source).body
        if isinstance(node, ast.FunctionDef) and node.name == "archive_receipts"
    )
    hash_assignment = any(
        isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "row_hash"
            for target in node.targets
        )
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Attribute)
        and node.value.func.attr == "hexdigest"
        for node in ast.walk(function)
    )
    seen_assignments = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Subscript)
            and isinstance(target.value, ast.Name)
            and target.value.id == "seen"
            for target in node.targets
        )
    ]
    return (
        hash_assignment
        and bool(seen_assignments)
        and all(
            isinstance(node.value, ast.Tuple)
            and bool(node.value.elts)
            and isinstance(node.value.elts[0], ast.Name)
            and node.value.elts[0].id == "row_hash"
            for node in seen_assignments
        )
    )


def assert_seen_hash_guard():
    source = (ROOT / "python/src/inference_platform/inf037b_archive.py").read_text(
        encoding="utf-8"
    )
    if not _seen_map_keeps_hashes(source):
        raise AssertionError(
            "archive_receipts.seen must retain a row hash, not the row"
        )
    mutant = source.replace(
        "seen[key] = row_hash, location", "seen[key] = row, location"
    )
    if mutant == source or _seen_map_keeps_hashes(mutant):
        raise AssertionError(
            "whole-row seen-map mutant was not rejected by the memory check"
        )


def _rss_kib(field):
    for line in Path("/proc/self/status").read_text(encoding="ascii").splitlines():
        if line.startswith(field + ":"):
            return int(line.split()[1])
    raise RuntimeError(f"{field} is unavailable in /proc/self/status")


def reset_peak_rss():
    with Path("/proc/self/clear_refs").open("w", encoding="ascii") as stream:
        stream.write("5\n")


def rewrite_manifest(root):
    files = inventory(root)
    data = "".join(
        f"{facts['sha256']}  {name}\n"
        for name, facts in sorted(files.items())
        if name != "SHA256SUMS"
    ).encode()
    with (root / "SHA256SUMS").open("wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def sanitize(source, destination):
    shutil.copytree(source, destination)
    registration = strict_json((destination / "registration.json").read_bytes())
    registration["sanitized"] = True
    (destination / "registration.json").write_bytes(encode(registration))
    provenance = {
        "source_manifest_sha256": file_facts(source / "SHA256SUMS")["sha256"],
        "segments": {},
        "pending_sse_streams": 0,
    }
    (destination / "source-integrity.receipt.json").write_bytes(encode(provenance))
    rewrite_manifest(destination)


def build_jsonl_archive(root, pins, target_bytes):
    archive = Archive.create(
        root,
        {"registration_id": REGISTRATION_ID, "pins": pins},
    )
    for source_kind in SOURCE_KINDS:
        if source_kind != "controller":
            (root / "raw" / f"{source_kind}.jsonl").touch()
    paths = (
        root / "attempts.jsonl",
        root / "raw" / "controller.jsonl",
        root / "cohorts" / "requests.jsonl",
        root / "events" / "traffic.jsonl",
    )

    empty = encode(envelope({"padding": ""}, seq=0))
    padding_bytes = max(0, ROW_TARGET_BYTES - len(empty))
    sample = encode(envelope({"padding": "x" * padding_bytes}, seq=0))
    row_count = max(1, round(target_bytes / len(sample)))
    archive_bytes = 0
    writers = [path.open("wb") for path in paths]
    try:
        for sequence in range(row_count):
            row = encode(envelope({"padding": "x" * padding_bytes}, seq=sequence))
            writers[sequence % len(writers)].write(row)
            archive_bytes += len(row)
        for stream in writers:
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        for stream in writers:
            stream.close()
    archive.seal()
    return row_count, archive_bytes


def worker(
    target_mb, source_path, row_count, archive_jsonl_bytes, source_archive_bytes
):
    cfg = fixture()
    binding = cfg["binding"]
    source = Path(source_path)
    if not source.is_dir():
        raise FileNotFoundError(source)

    cache_root = Path(tempfile.gettempdir())
    with tempfile.TemporaryDirectory(
        prefix=f"inf037b-export-{target_mb}-", dir=cache_root
    ) as directory:
        work = Path(directory)
        sanitized = work / "sanitized"
        destination = work / "destination"

        # Each worker is a fresh process. Imports, compact fixture setup and the
        # on-disk JSONL fixture are complete before the RSS high-water reset.
        baseline_rss_bytes = _rss_kib("VmRSS") * 1024
        reset_peak_rss()

        now = [binding["t0_ms"]]

        def sample():
            now[0] += 1
            return {
                "clock_id": "memory-test-clock",
                "boot_id": "memory-test-host",
                "ms": [now[0], now[0]],
            }

        export_raw, artifacts = capture_export(
            binding=binding,
            source=source,
            sanitized=sanitized,
            destination=destination,
            sanitize=sanitize,
            sample=sample,
            reconnect_ms=1000,
        )
        value = strict_json(export_raw)
        sizing_path = cfg["lifecycle"]["transfer"]["sizing_proof"]["path"]
        sizing = strict_json(cfg["artifacts"][sizing_path])
        sizing["raw_bytes"] = sum(fact["bytes"] for fact in value["source"].values())
        sizing["reconnect_bound_ms"] = 1000
        maximum = {
            "subject": "lifecycle:maximum_export_fixture",
            "pins": binding["pins"],
            "schedule_ms": [1560000] * 3 + [300000] * 2,
            "source_inventory_sha256": sha(encode(value["source"])),
        }
        store = DurableStore(work / "setup-store", {"binding": None}, initialize=True)
        manifest = persist_archive_artifacts(store, artifacts)
        command = object.__new__(SetupCommands)
        command.store = store
        command._capture("export_archives", export_raw, manifest, file_manifest=True)
        state_size = (store.path / "state.json").stat().st_size
        result = export_observations(
            export_raw,
            binding=binding,
            artifacts=manifest,
            maximum_fixture=maximum,
            sizing_proof=sizing,
        )
        assert result["transfer"]["raw_bytes"] == sizing["raw_bytes"]
        assert all(
            set(item) == {"path", "bytes", "sha256"} for item in manifest.values()
        )
        peak_rss_bytes = _rss_kib("VmHWM") * 1024
        growth = max(0, peak_rss_bytes - baseline_rss_bytes)
        return {
            "payload_target_mb": target_mb,
            "archive_jsonl_bytes": archive_jsonl_bytes,
            "source_archive_bytes": source_archive_bytes,
            "rows": row_count,
            "average_jsonl_bytes_per_row": archive_jsonl_bytes / row_count,
            "baseline_rss_bytes": baseline_rss_bytes,
            "peak_rss_bytes": peak_rss_bytes,
            "peak_rss_growth_bytes": growth,
            "growth_bytes_per_row": growth / row_count,
            "growth_bytes_per_archive_byte": growth / source_archive_bytes,
            "state_file_bytes": state_size,
            "archive_file_count": len(manifest),
        }


def build_measurement(target_mb):
    cfg = fixture()
    cache_root = Path(tempfile.gettempdir())
    with tempfile.TemporaryDirectory(
        prefix=f"inf037b-memory-fixture-{target_mb}-", dir=cache_root
    ) as directory:
        source = Path(directory) / "source"
        rows, archive_bytes = build_jsonl_archive(
            source,
            cfg["binding"]["pins"],
            target_mb * 1024 * 1024,
        )
        source_archive_bytes = sum(item["bytes"] for item in inventory(source).values())
        result = subprocess.run(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "--worker",
                str(target_mb),
                str(source),
                str(rows),
                str(archive_bytes),
                str(source_archive_bytes),
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        return json.loads(result.stdout.strip().splitlines()[-1])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--worker",
        nargs=5,
        metavar=("MB", "SOURCE", "ROWS", "JSONL_BYTES", "ARCHIVE_BYTES"),
    )
    args = parser.parse_args()
    if args.worker:
        if platform.system() != "Linux":
            parser.error("fresh-process RSS measurement requires Linux /proc")
        print(
            json.dumps(
                worker(
                    int(args.worker[0]),
                    args.worker[1],
                    int(args.worker[2]),
                    int(args.worker[3]),
                    int(args.worker[4]),
                )
            )
        )
        return 0
    if platform.system() != "Linux":
        parser.error("fresh-process RSS measurement requires Linux /proc")

    assert_seen_hash_guard()
    records = [build_measurement(size) for size in (10, 100)]
    row_delta = records[1]["rows"] - records[0]["rows"]
    byte_delta = records[1]["source_archive_bytes"] - records[0]["source_archive_bytes"]
    growth_delta = (
        records[1]["peak_rss_growth_bytes"] - records[0]["peak_rss_growth_bytes"]
    )
    growth_per_row = growth_delta / row_delta
    growth_per_byte = growth_delta / byte_delta
    state_growth = records[1]["state_file_bytes"] - records[0]["state_file_bytes"]
    passed = (
        records[0]["peak_rss_growth_bytes"] > 0
        and records[1]["peak_rss_growth_bytes"] > records[0]["peak_rss_growth_bytes"]
        and growth_delta > 0
        and growth_delta < RSS_DELTA_LIMIT
        and growth_per_row < ROW_GROWTH_LIMIT
        and state_growth <= 1024
    )
    receipt = {
        "measurements": records,
        "peak_rss_growth_10_to_100_mb_bytes": growth_delta,
        "growth_bytes_per_added_row_10_to_100_mb": growth_per_row,
        "growth_bytes_per_added_archive_byte_10_to_100_mb": growth_per_byte,
        "state_file_growth_bytes": state_growth,
        "whole_row_seen_mutant_rejected": True,
        "limits": {
            "peak_rss_growth_10_to_100_mb_bytes_lt": RSS_DELTA_LIMIT,
            "growth_bytes_per_added_row_lt": ROW_GROWTH_LIMIT,
            "state_file_growth_bytes_lte": 1024,
        },
        "passed": passed,
        "python": platform.python_version(),
        "platform": platform.system(),
        "inputs": {
            path: sha((ROOT / path).read_bytes().replace(b"\r\n", b"\n"))
            for path in (
                "scripts/check_inf037b_export_memory.py",
                "python/src/inference_platform/inf037b_archive.py",
                "python/src/inference_platform/inf037b_setup.py",
                "python/src/inference_platform/inf037b_setup_observations.py",
                "python/tests/inf037b_setup_fixture.py",
                "python/tests/test_inf037b_observations.py",
            )
        },
        "scope": "local synthetic JSONL archive with about 2.5 KB rows; not maximum-cardinality or live timing evidence",
    }
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(receipt, indent=2) + "\n", encoding="utf-8", newline="\n"
        )
    print(json.dumps(receipt, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
