"""Fail-closed, offline pre-PlanPaid host budget check."""

import hashlib
import json
from pathlib import Path

RECEIPT = "docs/evidence/round60-fixes/constrained-rehearsal.json"
REQUIRED_ROLES = ("host_controller", "capture", "gateway", "sampler")


def source_fingerprint(root):
    from .stage_c_session import git, source_paths

    paths = source_paths(root, "HEAD")
    paths.append("infra/terraform/pilot/user-data.sh.tftpl")
    paths += [
        p
        for p in git(root, "ls-tree", "-r", "--name-only", "HEAD").decode().splitlines()
        if p.startswith(("cmd/", "internal/")) and p.endswith(".go")
    ]
    return {p: hashlib.sha256(git(root, "show", "HEAD:" + p)).hexdigest() for p in sorted(paths)}


def headroom_fitness(root, receipt_path=None):
    path = Path(receipt_path) if receipt_path else root / RECEIPT
    try:
        row = json.loads(path.read_text(encoding="utf-8"))
        if row["schema"] != "inf011-constrained-rehearsal.v1" or row["status"] != "passed":
            raise ValueError("passing constrained rehearsal required")
        if row["source_files_sha256"] != source_fingerprint(root):
            raise ValueError("headroom receipt differs from committed executable sources")
        budget = row["memory_budget_bytes"]
        if (
            type(budget) is not int
            or not 0 < budget <= 6 * 1024**3
            or row["cpu_limit"] > 2
            or row["cpu_limit"] <= 0
        ):
            raise ValueError("conservative 2 CPU / 6 GiB or tighter bound required")
        if row["measured_request_count"] < 6937 or row["completed_run_count"] != 4:
            raise ValueError("all four full runs at live volume required")
        if (
            row["peak_memory_bytes"] > 0.60 * budget
            or row["peak_memory_bytes"] <= 0
            or row["oom_kill_delta"] != 0
        ):
            raise ValueError("60 percent headroom bound exceeded or OOM observed")
        if row["host_series_sample_count"] <= 0:
            raise ValueError("host series required")
        for role in REQUIRED_ROLES:
            peak = row["process_peaks"][role]
            if peak["peak_rss_bytes"] <= 0 or peak["peak_cpu_percent"] < 0:
                raise ValueError("missing process footprint")
        for name, expected in row["evidence_sha256"].items():
            target = (root / name).resolve()
            if not target.is_relative_to(root.resolve()):
                raise ValueError("evidence escapes repository")
            digest = hashlib.sha256()
            with target.open("rb") as stream:
                while block := stream.read(1024 * 1024):
                    digest.update(block)
            if digest.hexdigest() != expected:
                raise ValueError("headroom evidence checksum mismatch")
        if not row["evidence_sha256"]:
            raise ValueError("headroom evidence missing")
        return True, f"{path}: full-volume peak {row['peak_memory_bytes']}/{budget} bytes; <=60%"
    except (OSError, KeyError, ValueError, TypeError) as error:
        return False, f"{path}: {error}"
