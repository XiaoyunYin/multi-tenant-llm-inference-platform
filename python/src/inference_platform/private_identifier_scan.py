"""Detect the bound AWS account identifier in tracked files and IAM ARNs in evidence."""

import hashlib
import json
import re
import subprocess
from pathlib import Path

ACCOUNT_TOKEN = re.compile(rb"(?<![0-9])[0-9]{12}(?![0-9])")
IAM_ARN = re.compile(rb"arn:aws:iam::[0-9]{12}:")


def find_identifier_violations(files, account_id_sha256):
    """Return path/line-only findings; never include matched identifier bytes."""
    findings = []
    for relative, content in files.items():
        lines = content.splitlines()
        for line_number, line in enumerate(lines, start=1):
            if relative.startswith("docs/evidence/") and IAM_ARN.search(line):
                findings.append(f"{relative}:{line_number}: IAM account ARN in evidence")
            for token in ACCOUNT_TOKEN.findall(line):
                if hashlib.sha256(token).hexdigest() == account_id_sha256:
                    findings.append(
                        f"{relative}:{line_number}: token matches bound AWS account hash"
                    )
    return findings


def tracked_file_bytes(repo):
    root = Path(repo).resolve()
    paths = subprocess.check_output(["git", "-C", str(root), "ls-files", "-z"]).split(b"\0")
    files = {}
    for raw_path in filter(None, paths):
        relative = raw_path.decode("utf-8", errors="strict").replace("\\", "/")
        path = root / Path(relative)
        if path.is_symlink():
            files[relative] = path.readlink().as_posix().encode("utf-8")
        elif path.is_file():
            files[relative] = path.read_bytes()
    return files


def staged_file_bytes(repo):
    """Read the complete Git index tree, not worktree bytes or just a diff."""
    root = Path(repo).resolve()
    entries = subprocess.check_output(["git", "-C", str(root), "ls-files", "--stage", "-z"]).split(
        b"\0"
    )
    indexed = []
    for entry in filter(None, entries):
        metadata, raw_path = entry.split(b"\t", 1)
        mode, object_id, stage = metadata.split()
        if stage != b"0":
            raise ValueError("staged tree contains unresolved merge entries")
        relative = raw_path.decode("utf-8", errors="strict").replace("\\", "/")
        if mode in {b"100644", b"100755", b"120000"}:
            indexed.append((relative, object_id.decode("ascii")))
    if not indexed:
        return {}
    batch = subprocess.check_output(
        ["git", "-C", str(root), "cat-file", "--batch"],
        input=b"".join(object_id.encode("ascii") + b"\n" for _, object_id in indexed),
    )
    files = {}
    offset = 0
    for relative, object_id in indexed:
        header_end = batch.index(b"\n", offset)
        returned_id, kind, size_bytes = batch[offset:header_end].split()
        if returned_id.decode("ascii") != object_id or kind != b"blob":
            raise ValueError("staged tree blob lookup failed")
        size = int(size_bytes)
        start, end = header_end + 1, header_end + 1 + size
        files[relative] = batch[start:end]
        if batch[end : end + 1] != b"\n":
            raise ValueError("staged tree blob framing invalid")
        offset = end + 1
    return files


def check_repo(repo):
    root = Path(repo).resolve()
    inputs = json.loads((root / "docs/R1_SESSION_INPUTS.json").read_bytes())
    digest = inputs.get("account_id_sha256")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("R1 inputs do not contain a valid account_id_sha256")
    files = tracked_file_bytes(root)
    return len(files), find_identifier_violations(files, digest)


def check_staged_repo(repo):
    """Scan every staged blob using the repository's bound account hash."""
    root = Path(repo).resolve()
    files = staged_file_bytes(root)
    try:
        inputs = json.loads(files["docs/R1_SESSION_INPUTS.json"])
    except (KeyError, json.JSONDecodeError) as exc:
        raise ValueError("staged R1 inputs are missing or invalid") from exc
    digest = inputs.get("account_id_sha256")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("R1 inputs do not contain a valid account_id_sha256")
    return len(files), find_identifier_violations(files, digest)
