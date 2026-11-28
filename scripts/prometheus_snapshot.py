"""Export and verify a Prometheus TSDB snapshot over a local admin forward."""

import argparse
import hashlib
import json
import re
import tarfile
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath

MAX_ARCHIVE = 512 * 1024**2
MAX_EXPANDED = 2 * 1024**3
MAX_MEMBERS = 20_000
SNAPSHOT_NAME = re.compile(r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]+")
BLOCK_NAME = re.compile(r"[0-9A-HJKMNP-TV-Z]{26}")


def hash_file(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def snapshot(url, storage, archive):
    endpoint = urllib.parse.urlsplit(url)
    if endpoint.scheme != "http" or endpoint.hostname not in {"127.0.0.1", "::1"}:
        raise ValueError("Prometheus admin API requires a loopback forward")
    req = urllib.request.Request(
        url.rstrip("/") + "/api/v1/admin/tsdb/snapshot?skip_head=false",
        data=b"",
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=120) as response:
        result = json.load(response)
    name = result.get("data", {}).get("name", "")
    if result.get("status") != "success" or not SNAPSHOT_NAME.fullmatch(name):
        raise ValueError("invalid Prometheus snapshot response")
    source = storage / "snapshots" / name
    files = sorted(path for path in source.rglob("*") if path.is_file())
    if not files or len(files) > MAX_MEMBERS:
        raise ValueError("TSDB snapshot file count")
    if sum(path.stat().st_size for path in files) > MAX_EXPANDED:
        raise ValueError("TSDB snapshot expanded byte cap")
    for path in files:
        if path.is_symlink() or not path.resolve().is_relative_to(source.resolve()):
            raise ValueError("TSDB snapshot file outside owned snapshot")
        if not BLOCK_NAME.fullmatch(path.relative_to(source).parts[0]):
            raise ValueError("TSDB snapshot contains a non-block path")
    checksum = archive.with_suffix(archive.suffix + ".sha256")
    if checksum.exists():
        raise FileExistsError(checksum)
    stream = archive.open("xb")
    try:
        with stream:
            # Prometheus snapshots hardlink immutable blocks. Tar each file as
            # regular content so restore cannot follow an archive hardlink.
            with tarfile.open(fileobj=stream, mode="w:gz", dereference=True) as output:
                for path in files:
                    output.add(
                        path,
                        arcname=path.relative_to(source).as_posix(),
                        recursive=False,
                    )
        compressed_bytes = archive.stat().st_size
        if compressed_bytes > MAX_ARCHIVE:
            raise ValueError("TSDB snapshot compressed byte cap")
        digest = hash_file(archive)
        with checksum.open("x", encoding="ascii", newline="\n") as sidecar:
            sidecar.write(digest + "\n")
    except BaseException:
        archive.unlink()
        raise
    return {"sha256": digest, "bytes": compressed_bytes, "files": len(files)}


def restore(archive, digest, target):
    if not re.fullmatch(r"[0-9a-f]{64}", digest) or hash_file(archive) != digest:
        raise ValueError("TSDB archive SHA-256 mismatch")
    if archive.stat().st_size > MAX_ARCHIVE or target.exists():
        raise ValueError("TSDB archive size or existing restore directory")
    # Preflight the entire member map and byte total before writing anything.
    with tarfile.open(archive, "r:gz") as stream:
        members = {}
        expanded = 0
        for member in stream:
            path = PurePosixPath(member.name)
            if (
                not member.isfile()
                or not path.parts
                or not BLOCK_NAME.fullmatch(path.parts[0])
                or ".." in path.parts
                or any(
                    not re.fullmatch(r"[A-Za-z0-9_.-]+", part) for part in path.parts
                )
                or path in members
                or len(members) >= MAX_MEMBERS
            ):
                raise ValueError("invalid TSDB archive member")
            expanded += member.size
            if expanded > MAX_EXPANDED:
                raise ValueError("TSDB archive expanded byte cap")
            members[path] = member
        if not members or any(path.parent in members for path in members):
            raise ValueError("empty or conflicting TSDB snapshot members")
        target.mkdir()
        for member in members.values():
            stream.extract(member, target, filter="data")
    return {"sha256": digest, "files": len(members), "expanded_bytes": expanded}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    export = commands.add_parser("export")
    export.add_argument("--url", default="http://127.0.0.1:9090")
    export.add_argument("--storage", type=Path, required=True)
    export.add_argument("--archive", type=Path, required=True)
    recover = commands.add_parser("restore")
    recover.add_argument("--archive", type=Path, required=True)
    recover.add_argument("--sha256", required=True)
    recover.add_argument("--storage", type=Path, required=True)
    args = parser.parse_args()
    if args.action == "export":
        result = snapshot(args.url, args.storage, args.archive)
    else:
        result = restore(args.archive, args.sha256, args.storage)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
