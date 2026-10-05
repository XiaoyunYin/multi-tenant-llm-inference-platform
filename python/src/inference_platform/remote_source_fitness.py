"""Fail-closed pre-PlanPaid proof of pristine sources through remote bootstrap/recovery."""

import hashlib
import json
from pathlib import Path

from .host_headroom import source_fingerprint
from .stage_c_session import ENTRYPOINT, bootstrap_commands, git, sha, source_paths

RECEIPT = "docs/evidence/round62-r102/receipt.json"
STEPS = (
    "before_bootstrap",
    "server_started",
    "payload_put",
    "fake_readiness",
    "capture_started",
    "forward_status",
    "command_status",
    "server_killed",
    "command_restart",
    "restarted_forward_status",
    "restarted_command_status",
    "worker_finished",
)


def remote_fingerprint(root):
    return {
        **source_fingerprint(root),
        "scripts/rehearse_stage_c_remote.py": hashlib.sha256(
            git(root, "show", "HEAD:scripts/rehearse_stage_c_remote.py")
        ).hexdigest(),
    }


def remote_source_fitness(root, receipt_path=None):
    path = Path(receipt_path) if receipt_path else root / RECEIPT
    try:
        row = json.loads(path.read_text(encoding="utf-8"))
        if row["schema"] != "inf011-clean-remote-rehearsal.v1" or row["status"] != "passed":
            raise ValueError("passing clean remote rehearsal required")
        if row["source_files_sha256"] != remote_fingerprint(root):
            raise ValueError("clean remote receipt differs from committed executable sources")
        proof_path = (root / row["proof_path"]).resolve()
        manifest_path = (root / row["manifest_path"]).resolve()
        if not all(p.is_relative_to(root.resolve()) for p in (proof_path, manifest_path)):
            raise ValueError("clean remote evidence escapes repository")
        if sha(proof_path) != row["proof_sha256"] or sha(manifest_path) != row["manifest_sha256"]:
            raise ValueError("clean remote evidence checksum mismatch")
        proof = json.loads(proof_path.read_text(encoding="utf-8"))
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        expected = {
            name: hashlib.sha256(git(root, "show", "HEAD:" + name)).hexdigest()
            for name in source_paths(root, "HEAD")
        }
        if expected != {f["path"]: f["sha256"] for f in manifest["files"]}:
            raise ValueError("remote rehearsal manifest differs from committed sources")
        if (
            manifest["entrypoint"]["path"] != ENTRYPOINT
            or manifest["entrypoint"]["sha256"] != expected[ENTRYPOINT]
        ):
            raise ValueError("remote rehearsal entrypoint pin mismatch")
        if manifest["gateway_artifact"]["goos"] != "linux":
            raise ValueError("real Linux bundle required")
        if row["source_commit"] != manifest["source_commit"]:
            raise ValueError("remote rehearsal source commit mismatch")
        if row["steps"] != list(STEPS) or [c["step"] for c in proof["checkpoints"]] != list(STEPS):
            raise ValueError("remote rehearsal steps missing or reordered")
        for checkpoint in proof["checkpoints"]:
            if checkpoint["files_sha256"] != expected:
                raise ValueError("remote staged tree differs from manifest")
            if checkpoint["tree"] != ("bundle" if checkpoint["step"] in STEPS[:2] else "staged"):
                raise ValueError("installed staged tree not checked")
        if (
            proof["status"] != "passed"
            or proof["inherited_bytecode_variable"] is not False
            or proof["initial_environment"]
            != {
                "PATH": "/opt/round58-venv/bin:/usr/local/bin:/usr/bin:/bin",
                "HOME": "/tmp",
                "LANG": "C.UTF-8",
            }
            or proof.get("shared_capture_started") is not True
            or proof.get("real_capture", {}).get("host_prepare_paths_before_capture") is not True
            or proof.get("real_capture", {}).get("continuous_decoded_block_stored_count", 0) <= 0
            or proof["fake_readiness"] != "ready"
            or proof["worker_returncode"] != 0
            or proof["same_worker_identity_after_restart"] is not True
            or proof["aws_calls_made"] is not False
            or row["aws_calls_made"] is not False
        ):
            raise ValueError("clean environment/readiness/recovery proof missing")
        commands = bootstrap_commands(
            git(root, "show", "HEAD:" + manifest["entrypoint"]["path"]),
            row["manifest_sha256"],
            manifest,
            "/opt/inf011/reviewed",
            "local-clean-remote-fixture",
            22280,
            rehearse=True,
        )
        if (
            proof["bootstrap_commands_sha256"]
            != hashlib.sha256(json.dumps(commands).encode()).hexdigest()
        ):
            raise ValueError("rehearsal did not execute current exact bootstrap commands")
        return (
            True,
            f"{path}: clean Linux bootstrap, readiness, both status paths and restart; {len(STEPS)} pristine-tree checks",
        )
    except (OSError, KeyError, ValueError, TypeError) as error:
        return False, f"{path}: {error}"
