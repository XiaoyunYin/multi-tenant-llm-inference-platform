"""Fail-closed verification for the exact R1 staging bundle bound by inputs."""

import hashlib
import io
import json
import re
import tarfile
from pathlib import Path, PurePosixPath

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_GIT_HEAD = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_MAX_BUNDLE_BYTES = 128 * 1024 * 1024
_MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
_MAX_MEMBERS = 10_000


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _safe_repo_file(repo, relative):
    if not isinstance(relative, str) or "\\" in relative or ":" in relative:
        raise ValueError("reviewed bundle path must be repo-relative POSIX path")
    path = PurePosixPath(relative)
    if path.is_absolute() or not path.parts or ".." in path.parts or "." in path.parts:
        raise ValueError("reviewed bundle path must be repo-relative POSIX path")
    root = Path(repo).resolve()
    resolved = (root / Path(*path.parts)).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("reviewed bundle path escapes the repository") from exc
    return resolved


def validate_reviewed_bundle(repo, inputs):
    """Verify the bound archive, its manifest members, Python sources and gateway head."""
    bundle_path = _safe_repo_file(repo, inputs.get("bundle_path"))
    if not bundle_path.is_file():
        raise FileNotFoundError("reviewed staging bundle is missing")

    expected_bundle_sha = inputs.get("bundle_sha256")
    if not isinstance(expected_bundle_sha, str) or not _SHA256.fullmatch(expected_bundle_sha):
        raise ValueError("reviewed bundle SHA256 input is invalid")
    bundle_bytes = bundle_path.read_bytes()
    if len(bundle_bytes) > _MAX_BUNDLE_BYTES:
        raise ValueError("reviewed staging bundle exceeds the size bound")
    if _sha(bundle_bytes) != expected_bundle_sha:
        raise ValueError("reviewed staging bundle SHA256 mismatch")

    expected_head = inputs.get("source_head")
    if not isinstance(expected_head, str) or not _GIT_HEAD.fullmatch(expected_head):
        raise ValueError("bound source_head is invalid")
    source_hashes = inputs.get("source_sha256")
    if not isinstance(source_hashes, dict):
        raise ValueError("bound source_sha256 must be an object")

    try:
        archive = tarfile.open(fileobj=io.BytesIO(bundle_bytes), mode="r:gz")
    except (tarfile.TarError, OSError) as exc:
        raise ValueError("reviewed staging bundle is not a readable gzip tar archive") from exc

    with archive:
        members = archive.getmembers()
        if not members or len(members) > _MAX_MEMBERS:
            raise ValueError("reviewed staging bundle has an invalid member count")
        by_name = {}
        total_size = 0
        for member in members:
            name = member.name
            path = PurePosixPath(name)
            if (
                not name
                or "\\" in name
                or path.is_absolute()
                or ".." in path.parts
                or "." in path.parts
                or not member.isreg()
                or name in by_name
            ):
                raise ValueError("reviewed staging bundle has an unsafe or duplicate member")
            total_size += member.size
            if total_size > _MAX_ARCHIVE_BYTES:
                raise ValueError("reviewed staging bundle expands beyond the size bound")
            by_name[name] = member

        if "payload.json" not in by_name:
            raise ValueError("reviewed staging bundle is missing payload.json")
        payload_member = by_name["payload.json"]
        payload_stream = archive.extractfile(payload_member)
        if payload_stream is None:
            raise ValueError("reviewed staging bundle payload.json is unreadable")
        try:
            payload = json.loads(payload_stream.read())
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("reviewed staging bundle payload.json is invalid") from exc
        if not isinstance(payload, dict) or set(payload) != {"source_head", "files"}:
            raise ValueError("reviewed staging bundle payload.json has an invalid shape")
        if payload.get("source_head") != expected_head:
            raise ValueError("reviewed staging bundle source_head differs from bound source_head")

        files = payload.get("files")
        if not isinstance(files, dict) or "payload.json" in files or "bin/gateway" not in files:
            raise ValueError("reviewed staging bundle payload manifest is incomplete")
        if set(by_name) != set(files) | {"payload.json"}:
            raise ValueError("reviewed staging bundle members differ from payload.json")

        python_count = 0
        gateway_sha = None
        for name, expected_digest in files.items():
            if (
                not isinstance(name, str)
                or not isinstance(expected_digest, str)
                or not _SHA256.fullmatch(expected_digest)
            ):
                raise ValueError("reviewed staging bundle payload manifest entry is invalid")
            stream = archive.extractfile(by_name[name])
            if stream is None:
                raise ValueError(f"reviewed staging bundle member is unreadable: {name}")
            actual_digest = _sha(stream.read())
            if actual_digest != expected_digest:
                raise ValueError(f"reviewed staging bundle payload hash mismatch: {name}")
            if name.startswith("python/"):
                python_count += 1
                bound_digest = source_hashes.get(name)
                if bound_digest is None:
                    raise ValueError(f"bundled Python source is missing from source_sha256: {name}")
                if bound_digest != actual_digest:
                    raise ValueError(f"bundled Python source differs from source_sha256: {name}")
            if name == "bin/gateway":
                gateway_sha = actual_digest

        if python_count == 0:
            raise ValueError("reviewed staging bundle contains no bundled Python sources")

    return {
        "bundle_sha256": expected_bundle_sha,
        "source_head": expected_head,
        "python_files": python_count,
        "payload_files": len(files),
        "gateway_sha256": gateway_sha,
    }
