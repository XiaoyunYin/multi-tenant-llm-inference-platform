"""Validate experiment evidence against committed Git blob bytes, not checkout text."""

import argparse
import hashlib
import json
import posixpath
import re
import subprocess
from pathlib import Path


def git_bytes(root: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(root), *args])


def strict_json(text: str):
    def reject_constant(value):
        raise ValueError(f"non-JSON constant {value}")

    def unique_members(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON member {key}")
            result[key] = value
        return result

    return json.loads(
        text, parse_constant=reject_constant, object_pairs_hook=unique_members
    )


def check(root: Path, revision: str = "HEAD") -> dict[str, int]:
    paths = (
        git_bytes(
            root, "ls-tree", "-r", "--name-only", "-z", revision, "--", "experiments"
        )
        .decode("utf-8")
        .split("\0")
    )
    paths = [path for path in paths if path]
    blobs = {}

    def blob(path):
        if path not in paths:
            raise ValueError(
                f"checksum target is not committed under experiments: {path}"
            )
        if path not in blobs:
            blobs[path] = git_bytes(root, "show", f"{revision}:{path}")
        return blobs[path]

    counts = {
        "json_files": 0,
        "jsonl_files": 0,
        "checksum_manifests": 0,
        "checksum_entries": 0,
    }
    for path in paths:
        if path.endswith((".json", ".jsonl")):
            data = blob(path)
            if data.startswith(b"\xef\xbb\xbf"):
                raise ValueError(f"UTF-8 BOM is forbidden: {path}")
            text = data.decode("utf-8", errors="strict")
            if "\r" in text:
                raise ValueError(f"JSON evidence requires LF endings: {path}")
            try:
                if path.endswith(".jsonl"):
                    for number, line in enumerate(text.splitlines(), 1):
                        try:
                            strict_json(line)
                        except ValueError as error:
                            raise ValueError(f"line {number}: {error}") from error
                    counts["jsonl_files"] += 1
                else:
                    strict_json(text)
                    counts["json_files"] += 1
            except ValueError as error:
                raise ValueError(f"invalid strict JSON in {path}: {error}") from error
        if posixpath.basename(path) == "SHA256SUMS.txt":
            text = blob(path).decode("utf-8", errors="strict")
            if text.startswith("\ufeff"):
                raise ValueError(f"UTF-8 BOM is forbidden: {path}")
            seen = set()
            lines = text.splitlines()
            if not lines:
                raise ValueError(f"empty checksum manifest: {path}")
            for line in lines:
                match = re.fullmatch(r"([0-9a-fA-F]{64}) [ *](.+)", line)
                if match is None:
                    raise ValueError(f"invalid SHA256SUMS line in {path}")
                digest, relative = match.groups()
                if relative.startswith(("/", "\\")) or "\\" in relative:
                    raise ValueError(f"invalid checksum path in {path}: {relative}")
                base = posixpath.dirname(path)
                # Original M3 manifest is stored in captures/ but addresses
                # captures/... from the session root; newer manifests are local.
                if posixpath.basename(base) == "captures" and relative.startswith(
                    "captures/"
                ):
                    base = posixpath.dirname(base)
                target = posixpath.normpath(posixpath.join(base, relative))
                if not target.startswith("experiments/") or target in seen:
                    raise ValueError(
                        f"outside/duplicate checksum target in {path}: {relative}"
                    )
                seen.add(target)
                actual = hashlib.sha256(blob(target)).hexdigest()
                if actual != digest.lower():
                    raise ValueError(
                        f"stale checksum in {path}: {target}; expected {digest}, committed {actual}"
                    )
                counts["checksum_entries"] += 1
            counts["checksum_manifests"] += 1
    return counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument("--revision", default="HEAD")
    args = parser.parse_args()
    try:
        counts = check(args.root, args.revision)
    except (ValueError, UnicodeError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Evidence check failed: {error}\n")
    print(f"Committed {args.revision} experiment evidence passed: {counts}")


if __name__ == "__main__":
    main()
