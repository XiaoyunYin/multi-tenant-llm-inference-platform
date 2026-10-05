"""Reject new large binary evidence; historical blobs remain untouched."""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

BASELINE = "6cfd473"  # Saved Round59; grandfather history, never rewrite it.
LIMIT = 5_000_000  # Decimal 5 MB; do not leave a 242,880-byte unit ambiguity.


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args])


def check(root, base=BASELINE, revision="HEAD", allowlist=None):
    allowed = allowlist or {}
    if git(root, "cat-file", "-t", revision).strip() == b"commit":
        # Inspect every new reachable blob, including one committed then deleted.
        # Excluding base reachability grandfathers immutable history by object ID.
        entries = git(root, "rev-list", "--objects", f"{base}..{revision}").decode().splitlines()
        targets = []
        for line in entries:
            oid, _, path = line.partition(" ")
            if path and git(root, "cat-file", "-t", oid).strip() == b"blob":
                targets.append((path, oid))
    else:
        # Also support git write-tree for pre-commit/staged-copy verification.
        paths = git(root, "diff", "--name-only", "--diff-filter=ACMR", "-z", base, revision).decode().split("\0")
        targets = [(path, f"{revision}:{path}") for path in filter(None, paths)]
    checked = 0
    for path, blob in targets:
        size = int(git(root, "cat-file", "-s", blob))
        if size <= LIMIT:
            continue
        data = git(root, "show", blob)
        try:
            data.decode("utf-8", errors="strict")
            binary = b"\0" in data
        except UnicodeError:
            binary = True
        if binary:
            checked += 1
            expected = {"bytes": size, "sha256": hashlib.sha256(data).hexdigest()}
            if allowed.get(path) != expected:
                raise ValueError(f"new binary evidence exceeds 5 MB (5000000 bytes): {path} ({size} bytes); use ignored .cache/evidence-store with committed receipts/manifests")
    return {"large_binary_allowlisted": checked, "base": base, "revision": revision}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--base", default=BASELINE)
    parser.add_argument("--revision", default="HEAD")
    args = parser.parse_args()
    try:
        allowed = json.loads((args.root / "scripts/evidence-binary-allowlist.json").read_text())
        print(check(args.root, args.base, args.revision, allowed))
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Evidence size guard failed: {error}\n")
