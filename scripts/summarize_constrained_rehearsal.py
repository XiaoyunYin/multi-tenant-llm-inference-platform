"""Audit completed local constrained exports and record the fail-closed host bound."""

import argparse
import hashlib
import json
import shutil
import tarfile
from pathlib import Path

from inference_platform.disk_records import jsonl_rows, write_json
from inference_platform.host_headroom import REQUIRED_ROLES, source_fingerprint


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def levels(value):
    if isinstance(value, dict):
        if "concurrency" in value and "records" in value:
            yield value
        for key, child in value.items():
            if key not in ("records", "metrics"):
                yield from levels(child)
    elif isinstance(value, list):
        for child in value:
            yield from levels(child)


def summarize(repo, session, evidence, output):
    receipt = json.load((session / "export-receipt.json").open())
    archive = session / "evidence.tar.gz"
    if sha(archive) != receipt["sha256"]:
        raise ValueError("session archive receipt mismatch")
    exported = session / "export"
    for line in (exported / "SHA256SUMS.txt").read_text().splitlines():
        expected, name = line.split("  ", 1)
        target = (exported / name).resolve()
        if not target.is_relative_to(exported.resolve()) or sha(target) != expected:
            raise ValueError("export checksum mismatch")
    artifact = json.load((session / "stage-c-artifact.json").open())
    finalization = json.load((exported / "session-finalization.json").open())
    if (
        artifact["status"] != "completed"
        or finalization["errors"]
        or any(not row["reaped"] for row in finalization["children"])
    ):
        raise ValueError("incomplete session or child cleanup")
    if (session / "private").exists():
        raise ValueError("private input cleanup incomplete")
    for number in range(1, 5):
        sealed = json.load((exported / f"run-{number}.receipt.json").open())
        if (
            sealed["sha256"] != sha(session / f"sealed-runs/run-{number}.tar.gz")
            or sealed["run_status"] != "completed"
            or not sealed["sealed_before_next_run"]
            or sealed["raw_prompt_token_inputs_included"]
        ):
            raise ValueError("completed-run seal is incomplete or mismatched")
    joined = artifact["decision_event_export"]
    if (
        joined["joined_decision_count"] <= 0
        or joined["observed_correlation_count"] <= 0
        or joined["request_lifetime_bound_violation_count"]
    ):
        raise ValueError("missing correlation evidence or invalid request windows")
    bank = list(levels(artifact["timed_runs"]))
    if any(row["unmatched_dispatched_request_count"] for row in bank):
        raise ValueError("unmatched per-level terminal evidence")
    volume = sum(len(row["records"]) for row in bank)
    if (
        volume < 6937
        or len(artifact["timed_runs"]) != 4
        or any(row["status"] != "completed" for row in artifact["timed_runs"])
    ):
        raise ValueError("full live volume / completed four runs required")
    sweeps = [row for row in bank if row.get("load_mode") == "sustained_closed_loop"]
    if len(sweeps) != 20 or any(row["planned_load_seconds"] != 90 for row in sweeps):
        raise ValueError("full ten-level 90-second sweeps required")
    peaks = json.load((exported / "host-footprint-peaks.json").open())
    for role in REQUIRED_ROLES:
        if peaks["processes"][role]["peak_rss_bytes"] <= 0:
            raise ValueError("missing session process peak")
    count = 0
    first = last = None
    peak = 0
    for sample in jsonl_rows(session / "host-process-samples.jsonl"):
        host = sample["host"]
        if (
            host["status"] != "available"
            or host["cgroup"]["memory.max"] != "6442450944"
            or host["cgroup"]["cpu.max"] != "200000 100000"
        ):
            raise ValueError("container limits / host series mismatch")
        if first is None:
            first = host
        last = host
        peak = max(peak, int(host["cgroup"]["memory.peak"]))
        count += 1
    delta = last["oom_kill"] - first["oom_kill"]
    events = dict(line.split() for line in last["cgroup"]["memory.events"].splitlines())
    if delta or int(events["oom_kill"]) or peak > 0.60 * 6 * 1024**3:
        raise ValueError("host headroom or OOM bound failed")
    manifest = json.load((exported / "staging-manifest.json").open())
    from inference_platform.stage_c_session import git

    fingerprint = source_fingerprint(repo)
    if any(
        hashlib.sha256(
            git(repo, "show", manifest["source_commit"] + ":" + path)
        ).hexdigest()
        != value
        for path, value in fingerprint.items()
    ):
        raise ValueError("headroom source differs from executed committed source")
    evidence.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive) as handle:
        if set(handle.getnames()) != {path.name for path in exported.iterdir()}:
            raise ValueError("archive file set differs from verified export")
        for member in handle.getmembers():
            if not member.isfile() or Path(member.name).name != member.name:
                raise ValueError("archive contains an unsafe member")
            digest = hashlib.sha256()
            with handle.extractfile(member) as stream:
                while chunk := stream.read(1024 * 1024):
                    digest.update(chunk)
            if digest.hexdigest() != sha(exported / member.name):
                raise ValueError("archive member differs from verified export")
    # Full archives/streams stay in the ignored local evidence store. Only
    # retrieval instructions, SHA256 manifests, receipts and compact digests commit.
    local = session
    entries = [{"path": path.relative_to(local).as_posix(), "bytes": path.stat().st_size,
                "sha256": sha(path)} for path in sorted(local.rglob("*")) if path.is_file()]
    write_json(evidence / "local-store-manifest.json", {
        "schema": "inf011-local-evidence-store.v1", "local_store": local.relative_to(repo).as_posix(),
        "files": entries, "off_machine_copy": "pending owner choice; no remote backup claimed",
        "retrieval": "Resolve local_store under repository root; verify each file SHA256/length before extraction. Full archives are ignored; existing Git history is unchanged."})
    digests = []
    for number in range(1, 5):
        seal = json.load((session / f"sealed-runs/run-{number}.receipt.json").open())
        digest = seal["measurement_digest"]
        source = session / "sealed-runs" / digest["path"]
        if source.stat().st_size != digest["bytes"] or sha(source) != digest["sha256"]:
            raise ValueError("measurement digest checksum/size mismatch")
        shutil.copyfile(source, evidence / source.name)
        shutil.copyfile(session / f"sealed-runs/run-{number}.receipt.json", evidence / f"run-{number}.receipt.json")
        digests.append({**digest, "run_number": number, "path": (evidence / source.name).relative_to(repo).as_posix()})
    from inference_platform.stage_c_digest import DIGEST_LIMIT, FINAL_LIMIT
    if any(row["bytes"] > DIGEST_LIMIT for row in digests) or receipt["bytes"] > FINAL_LIMIT:
        raise ValueError("digest/final export reserve bound failed")
    summary = {
        "schema": "inf011-constrained-run-summary.v1",
        "status": "passed",
        "source_commit": manifest["source_commit"],
        "manifest_sha256": sha(exported / "staging-manifest.json"),
        "gateway_artifact": manifest["gateway_artifact"],
        "measured_request_count": volume,
        "per_level_failure_splits": [
            {
                "level_index": n,
                "concurrency": row["concurrency"],
                "request_count": len(row["records"]),
                "load_mode": row["load_mode"],
                "failure_split": row["failure_split"],
                "unmatched_dispatched_request_count": row[
                    "unmatched_dispatched_request_count"
                ],
            }
            for n, row in enumerate(bank)
        ],
        "joined_correlation_count": artifact["decision_event_export"][
            "joined_decision_count"
        ],
        "correlation_summary": {
            key: value
            for key, value in artifact["decision_event_export"].items()
            if key not in ("capture", "routing_to_event_observation")
        },
        "completed_runs": [row["run_kind"] for row in artifact["timed_runs"]],
        "sample_count": count,
        "process_peaks": peaks["processes"],
        "peak_memory_bytes": peak,
        "memory_budget_bytes": 6 * 1024**3,
        "peak_memory_fraction": peak / (6 * 1024**3),
        "oom_kill_delta": delta,
        "aws_calls_made": False,
        "gpu_measurements": False,
        "private_inputs_removed": True,
        "children_reaped": True,
        "basis": "Full 90-second-level synthetic runtime; real staged gateway/controller; conservative local 2 CPU / 6 GiB bound because GPU-host spare memory is unknown; sampled through first export, then final sampler evidence packed",
    }
    write_json(evidence / "summary.json", summary)
    write_json(
        evidence / "archive-receipt.json",
        {
            "schema": "inf011-local-evidence-receipt.v1",
            "sha256": receipt["sha256"],
            "bytes": archive.stat().st_size,
            "source_commit": manifest["source_commit"],
            "basis": "Local CPU synthetic evidence; no GPU or AWS",
        },
    )
    write_json(evidence / "staging-manifest.json", manifest)
    for name in (
        "host-footprint-peaks.json",
        "session-finalization.json",
        "SHA256SUMS.txt",
    ):
        if name != "SHA256SUMS.txt":
            shutil.copyfile(exported / name, evidence / name)
    sums = "".join(
        f"{sha(path)}  {path.name}\n"
        for path in sorted(evidence.iterdir())
        if path.is_file() and path.name != "SHA256SUMS.txt"
    )
    (evidence / "SHA256SUMS.txt").write_text(sums, encoding="utf-8", newline="\n")
    bound = {
        "schema": "inf011-constrained-rehearsal.v1",
        "status": "passed",
        "source_files_sha256": fingerprint,
        "source_commit": manifest["source_commit"],
        "memory_budget_bytes": 6 * 1024**3,
        "cpu_limit": 2,
        "measured_request_count": volume,
        "completed_run_count": 4,
        "peak_memory_bytes": peak,
        "oom_kill_delta": delta,
        "host_series_sample_count": count,
        "process_peaks": peaks["processes"],
        "evidence_sha256": {
            path.relative_to(repo).as_posix(): sha(path)
            for path in (
                *(repo / row["path"] for row in digests),
                evidence / "local-store-manifest.json",
                evidence / "summary.json",
                evidence / "host-footprint-peaks.json",
            )
        },
        "basis": summary["basis"],
        "measurement_digests": digests,
        "final_export_bytes": receipt["bytes"],
    }
    write_json(output, bound)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--session", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    summarize(
        args.repo.resolve(),
        args.session.resolve(),
        args.evidence.resolve(),
        args.output.resolve(),
    )
