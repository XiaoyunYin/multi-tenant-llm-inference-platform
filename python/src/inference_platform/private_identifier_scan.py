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


def check_repo(repo):
    root = Path(repo).resolve()
    inputs = json.loads((root / "docs/R1_SESSION_INPUTS.json").read_bytes())
    digest = inputs.get("account_id_sha256")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("R1 inputs do not contain a valid account_id_sha256")
    files = tracked_file_bytes(root)
    return len(files), find_identifier_violations(files, digest)
