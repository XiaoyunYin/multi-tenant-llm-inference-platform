"""Loopback-only DEC-077 upload, runner and frozen-log service over R1 SSM.

Run with the Ubuntu AMI's system Python. The measured commands use the separately
pinned Python. Authentication and source binding precede extraction/execution.
"""

import argparse
import hashlib
import hmac
import io
import json
import math
import os
import re
import signal
import shutil
import subprocess
import tarfile
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit
from urllib.request import Request, urlopen

CHUNK = 1024**2
MAX_BUNDLE = 256 * CHUNK
ROUTINE_MAX_BUNDLE = 2 * 1024**3
MAX_INPUT_BUNDLE = 8 * 1024**3
# Hard compressed receipt/log bound; matches the lifecycle reserve and forecast.
EXPORT_MAX_BYTES = 32 * CHUNK
EXPORT_FILE_MAX_BYTES = CHUNK
EXPORT_FILE_EDGE_BYTES = CHUNK // 2


def host_environment():
    """One explicit SSM child environment, shared by bootstrap and DEC-100 phases."""
    return {
        "HOME": "/root",
        "GOPATH": "/root/go",
        "GOMODCACHE": "/root/go/pkg/mod",
        "GOCACHE": "/root/.cache/go-build",
        "XDG_CACHE_HOME": "/root/.cache",
        "LANG": "C.UTF-8",
        "PATH": "/opt/dec077/tools/go/bin:/opt/dec077/tools/uv-x86_64-unknown-linux-gnu:/opt/dec077/tools/docker:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "PYTHONPATH": "/opt/dec077/repo/python/src",
    }


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(CHUNK), b""):
            result.update(block)
    return result.hexdigest()


def verify_sparse_payload(repo, binding):
    """Verify materialized bytes/modes, not merely the sealed HEAD's tree."""
    repo = Path(repo)

    def git(*argv):
        return subprocess.check_output(["git", "-C", str(repo), *argv], timeout=120)

    if git("rev-parse", "HEAD").decode().strip() != binding["source_commit"]:
        raise ValueError("descriptive:payload_commit")
    for path in binding["paths"]:
        git("add", "--force", "--sparse", "--", path)
    actual_tree = git("write-tree").decode().strip()
    for path, expected in binding["paths"].items():
        actual = git("rev-parse", actual_tree + ":" + path).decode().strip()
        if actual != expected:
            raise ValueError("descriptive:payload_tree:" + path)
    if git("status", "--porcelain"):
        raise ValueError("descriptive:payload_worktree")
    return {
        "source_commit": binding["source_commit"],
        "paths": binding["paths"],
        "verified": True,
    }


def stage_sparse_payload(repo, pack, binding):
    repo, pack = Path(repo), Path(pack)
    if binding.get("format") != "git-pack-sparse-v1" or not binding.get("paths"):
        raise ValueError("descriptive:payload_format")
    for path, oid in binding["paths"].items():
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", path) or path in {".", "..", ".git"}:
            raise ValueError("descriptive:payload_path")
        if not re.fullmatch(r"[0-9a-f]{40}", oid):
            raise ValueError("descriptive:payload_identity")

    def git(*argv, **kwargs):
        return subprocess.check_output(
            ["git", "-C", str(repo), *argv], timeout=120, **kwargs
        )

    if not repo.exists():
        repo.mkdir()
        git("init")
        # A promisor pack explicitly permits omitted evidence/history blobs.
        # No network remote exists; an accidental omitted read cannot fetch it.
        git("config", "core.sparseCheckout", "true")
        git("config", "extensions.partialClone", "payload")
        git("config", "remote.payload.promisor", "true")
        with pack.open("rb") as source:
            git("index-pack", "--stdin", "--promisor", stdin=source)
        (repo / ".git/shallow").write_text(binding["source_commit"] + "\n")
        git("update-ref", "--no-deref", "HEAD", binding["source_commit"])
        (repo / ".git/info/sparse-checkout").write_text(
            "".join("/" + p + "\n" for p in binding["paths"])
        )
        git("read-tree", "-mu", "HEAD")
        git("fsck", "--full")
    return verify_sparse_payload(repo, binding)


def validate_gate_a_s3_get_url(url, *, bucket, key, local_minio_origin=None):
    if not isinstance(url, str):
        raise ValueError("gate_a_input_s3_download_url")
    parsed = urlsplit(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    local_minio = local_minio_origin or os.environ.get("MINIO_TEST_ENDPOINT")
    path_key = unquote(parsed.path.lstrip("/"))
    try:
        port = parsed.port
    except ValueError:
        raise ValueError("gate_a_input_s3_download_url") from None
    virtual_hosted_aws = parsed.hostname == f"{bucket}.s3.amazonaws.com" or (
        parsed.hostname is not None
        and parsed.hostname.startswith(f"{bucket}.s3.")
        and parsed.hostname.endswith(".amazonaws.com")
    )
    path_hosted_aws = (
        parsed.hostname is not None
        and parsed.hostname.startswith("s3.")
        and parsed.hostname.endswith(".amazonaws.com")
    )
    valid_aws_url = (
        parsed.scheme == "https"
        and port in (None, 443)
        and (
            (virtual_hosted_aws and path_key == key)
            or (path_hosted_aws and path_key == f"{bucket}/{key}")
        )
    )
    valid_minio_url = (
        parsed.scheme == "http"
        and local_minio == origin
        and path_key == f"{bucket}/{key}"
    )
    query = parse_qs(parsed.query, keep_blank_values=True)
    if (
        not parsed.query
        or parsed.username is not None
        or parsed.password is not None
        or not parsed.hostname
        or not (valid_aws_url or valid_minio_url)
        or (valid_aws_url and query.get("X-Amz-Algorithm") != ["AWS4-HMAC-SHA256"])
    ):
        raise ValueError("gate_a_input_s3_download_url")
    return parsed


def sync_directory(path):
    if os.name != "posix":
        raise OSError("gate_a:directory_fsync_requires_posix")
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class Host:
    def __init__(self, directory, token, manifest_hash, deadline):
        self.root, self.token = Path(directory), token
        self.manifest_hash, self.deadline = manifest_hash, deadline
        self.root.mkdir(parents=True, exist_ok=True)
        self.partial = self.root / "source.bundle"
        self.input_partial = self.root / "gate-a-inputs.tar"
        self.input_stage = self.root / "gate-a-inputs"
        self.input_receipt = self.root / "gate-a-inputs-staged.json"
        self.repo = self.root / "repo"
        self.output = self.root / "results"
        self.manifest = None
        self.child = None
        self.log = None
        self.frozen = None
        self.lock = threading.RLock()
        self.freeze_lock = threading.Lock()
        self.freeze_started = None
        self.freeze_finished = None
        self.freeze_failed = False
        self.cancelled = False

    def _archive_entries(self):
        entries = []
        if self.output.exists():
            entries.append((self.output, "results"))
            entries.extend(
                (path, (Path("results") / path.relative_to(self.output)).as_posix())
                for path in self.output.rglob("*")
            )
        for name in ("bootstrap.log", "runtime.json", "stage.json"):
            source = self.root / name
            if source.exists():
                entries.append((source, name))
        staged_receipt = self.root / "gate-a-inputs-staged.json"
        if staged_receipt.is_file():
            entries.append((staged_receipt, staged_receipt.name))
        return sorted(entries, key=lambda row: (row[1].count("/"), row[1]))

    def _write_archive(self, destination, entries, *, truncated=None):
        cut_by_path = {item["path"]: item for item in truncated or ()}
        with tarfile.open(destination, "w:gz", compresslevel=1) as stream:
            for source, arcname in entries:
                item = cut_by_path.get(arcname)
                if item is not None and item.get("dropped"):
                    continue
                if item is not None:
                    with source.open("rb") as raw:
                        first = raw.read(EXPORT_FILE_EDGE_BYTES)
                        raw.seek(-EXPORT_FILE_EDGE_BYTES, os.SEEK_END)
                        last = raw.read(EXPORT_FILE_EDGE_BYTES)
                    content = first + last
                    info = stream.gettarinfo(str(source), arcname=arcname)
                    info.size = len(content)
                    stream.addfile(info, io.BytesIO(content))
                else:
                    stream.add(source, arcname=arcname, recursive=False)
            if truncated is not None:
                content = (
                    json.dumps(truncated, indent=2, sort_keys=True) + "\n"
                ).encode()
                info = tarfile.TarInfo("truncated.json")
                info.size = len(content)
                stream.addfile(info, io.BytesIO(content))

    def _build_archive(self):
        archive = self.root / "receipts.tar.gz"
        temporary_archive = self.root / "receipts.tar.gz.tmp"
        # Raw logs and receipts only; fixture construction scratch is not
        # part of the export. Existing files survive a failed runner.
        entries = self._archive_entries()
        self._write_archive(temporary_archive, entries)
        limit = (
            512 * CHUNK
            if self.manifest
            and self.manifest.get("role") in {"routine_tests", "descriptive_operator"}
            else EXPORT_MAX_BYTES
        )
        bounded = temporary_archive.stat().st_size > limit
        if (
            bounded
            and self.manifest
            and self.manifest.get("role") == "descriptive_operator"
        ):
            raise ValueError("descriptive:receipt_export_limit")
        truncated = []
        if bounded:
            for source, arcname in entries:
                if (
                    source.is_file()
                    and not source.is_symlink()
                    and source.stat().st_size > EXPORT_FILE_MAX_BYTES
                ):
                    truncated.append(
                        {
                            "path": arcname,
                            "original_bytes": source.stat().st_size,
                            "sha256": digest(source),
                            "dropped": False,
                        }
                    )
            self._write_archive(temporary_archive, entries, truncated=truncated)
            droppable = sorted(
                (
                    item
                    for item in truncated
                    if (
                        Path(item["path"]).suffix.lower()
                        in {".log", ".out", ".err", ".stdout", ".stderr"}
                        or ".log." in Path(item["path"]).name.lower()
                    )
                    and Path(item["path"]).suffix.lower() != ".json"
                    and "receipt" not in Path(item["path"]).name.lower()
                ),
                key=lambda item: (-item["original_bytes"], item["path"]),
            )
            for item in droppable:
                if temporary_archive.stat().st_size <= EXPORT_MAX_BYTES:
                    break
                item["dropped"] = True
                self._write_archive(temporary_archive, entries, truncated=truncated)
            if temporary_archive.stat().st_size > EXPORT_MAX_BYTES:
                # Keep the best bounded attempt for diagnosis even when
                # non-log evidence alone cannot fit the transfer bound.
                os.replace(temporary_archive, archive)
                raise ValueError("receipt_archive_exceeds_32_mib_after_cut_logs")
        os.replace(temporary_archive, archive)
        return {
            "bytes": archive.stat().st_size,
            "sha256": digest(archive),
            "bounded": bounded,
            "truncated_files": truncated,
        }

    def background_freeze(self):
        # Preserve the sealed Gate A and descriptive_operator archive protocol.
        return (self.manifest or {}).get("role") == "routine_tests"

    def _freeze_status(self):
        # Caller holds only freeze_lock, never the lock used for runner I/O.
        if self.freeze_finished is not None:
            if self.freeze_failed:
                return {
                    "state": "failed",
                    "reason": "archive_build_failed",
                    "freeze_elapsed_s": self.freeze_finished - self.freeze_started,
                }
            return {
                "state": "ready",
                **self.frozen,
                "freeze_elapsed_s": self.freeze_finished - self.freeze_started,
            }
        for name in ("receipts.tar.gz.tmp", "receipts.tar.gz"):
            try:
                written = (self.root / name).stat().st_size
            except FileNotFoundError:
                continue
            break
        else:
            written = 0
        return {
            "state": "archiving",
            "bytes_written": written,
            "freeze_elapsed_s": time.monotonic() - self.freeze_started,
        }

    def _finish_freeze(self):
        try:
            with self.lock:
                self.cancel()
            result = self._build_archive()
        except Exception:
            result = None
        with self.freeze_lock:
            self.frozen = result
            self.freeze_failed = result is None
            self.freeze_finished = time.monotonic()

    def start_freeze(self):
        with self.freeze_lock:
            if self.freeze_started is None:
                self.freeze_started = time.monotonic()
                try:
                    threading.Thread(target=self._finish_freeze, daemon=True).start()
                except RuntimeError:
                    self.freeze_failed = True
                    self.freeze_finished = time.monotonic()
            return self._freeze_status()

    def status(self):
        result = {
            "offset": self.partial.stat().st_size if self.partial.exists() else 0,
            "manifest_bound": self.manifest is not None,
            "staged": (self.repo / ".git").exists(),
            "runner_exit": self.child.poll() if self.child else None,
            "runner_started": self.child is not None,
            "cancelled": self.cancelled,
        }
        if isinstance(self.manifest, dict) and "gate_a_inputs" in self.manifest:
            result.update(
                input_offset=self.input_partial.stat().st_size
                if self.input_partial.exists()
                else 0,
                gate_a_inputs_staged=self.input_receipt.is_file(),
            )
        if (
            isinstance(self.manifest, dict)
            and self.manifest.get("role") == "routine_tests"
        ):
            progress = self.output / "runner/routine/results.json"
            try:
                if progress.stat().st_size <= 1024**2:
                    value = json.loads(progress.read_bytes())
                    if value.get("source_commit") == self.manifest.get("source_commit"):
                        result["routine_stages"] = [
                            {
                                key: row[key]
                                for key in ("name", "status", "elapsed_s")
                                if key in row
                            }
                            for row in value["stages"][-8:]
                        ]
            except (OSError, ValueError, KeyError, TypeError):
                pass  # Progress is optional; never alter the runner's outcome.
        runner_receipt = self.output / "runner" / "runner.json"
        if not runner_receipt.is_file():
            runner_receipt = self.output / "runner.json"
        if runner_receipt.is_file():
            try:
                runner = json.loads(runner_receipt.read_bytes())
                result["runner_status"] = {
                    key: runner[key]
                    for key in ("role", "status", "receiver_address", "error")
                    if key in runner
                }
            except (OSError, ValueError):
                result["runner_status"] = {"status": "UNREADABLE"}
        if self.freeze_started is not None:
            with self.freeze_lock:
                result["freeze"] = self._freeze_status()
        return result

    def _verify_gate_a_staging(self):
        binding = self.manifest.get("gate_a_inputs")
        if not isinstance(binding, dict) or not self.input_receipt.is_file():
            raise ValueError("gate_a_inputs_not_staged_before_P")
        receipt = json.loads(self.input_receipt.read_bytes())
        expected = binding.get("inventory")
        staging = binding.get("s3_staging")
        if (
            receipt.get("bundle_sha256") != binding.get("bundle_sha256")
            or receipt.get("bundle_bytes") != binding.get("bundle_bytes")
            or receipt.get("inventory") != expected
            or (
                staging is not None
                and receipt.get("s3_staging_key") != staging.get("key")
            )
            or not isinstance(expected, dict)
        ):
            raise ValueError("gate_a_input_stage_receipt_changed")
        observed = {}
        for path in sorted(self.input_stage.rglob("*")):
            if path.is_symlink():
                raise ValueError("gate_a_input_stage_symlink")
            if path.is_file():
                relative = path.relative_to(self.input_stage).as_posix()
                observed[relative] = {
                    "bytes": path.stat().st_size,
                    "sha256": digest(path),
                }
        if observed != expected:
            raise ValueError("gate_a_input_stage_changed")
        return receipt

    def _download_gate_a_s3_input(self, url, *, deadline, expected_bytes, bucket, key):
        validate_gate_a_s3_get_url(url, bucket=bucket, key=key)
        partial = self.input_partial.with_name(self.input_partial.name + ".download")
        if partial.exists() or self.input_partial.exists():
            raise ValueError("gate_a_input_s3_download_state")
        timeout = max(1, math.floor(deadline - time.time()))
        request = Request(url, headers={"Accept-Encoding": "identity"})
        size = 0
        try:
            with (
                urlopen(request, timeout=timeout) as response,
                partial.open("xb") as writer,
            ):
                if getattr(response, "status", 200) != 200:
                    raise ValueError("gate_a_input_s3_download_status")
                while True:
                    if time.time() >= deadline:
                        raise TimeoutError("gate_a_input_s3_download_deadline")
                    socket_stream = getattr(
                        getattr(getattr(response, "fp", None), "raw", None),
                        "_sock",
                        None,
                    )
                    if socket_stream is not None:
                        socket_stream.settimeout(max(0.001, deadline - time.time()))
                    chunk = response.read(CHUNK)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > expected_bytes:
                        raise ValueError("gate_a_input_s3_download_length")
                    writer.write(chunk)
                writer.flush()
                os.fsync(writer.fileno())
            if size != expected_bytes:
                raise ValueError("gate_a_input_s3_download_length")
            os.replace(partial, self.input_partial)
            sync_directory(self.root)
        except BaseException as exc:
            try:
                partial.unlink(missing_ok=True)
            except OSError:
                pass
            if isinstance(exc, (TimeoutError, ValueError)):
                raise
            raise ValueError(
                "gate_a_input_s3_download_failed:" + type(exc).__name__
            ) from None

    def cancel(self):
        self.cancelled = True
        if self.child and self.child.poll() is None:
            os.killpg(self.child.pid, signal.SIGKILL)
            self.child.wait(timeout=10)
        if self.log:
            self.log.close()
            self.log = None
        return self.status()

    def command(self, argv, timeout=120):
        # Explicit argv; never run uploaded command text as a shell.
        return subprocess.run(
            argv, check=True, capture_output=True, timeout=timeout
        ).stdout

    def dispatch(self, path, data, headers):
        # Cancellation, status and frozen retrieval remain available after work
        # deadline. Only the independently armed host timer terminates the host.
        if path == "/status":
            return self.status()
        if path == "/cancel":
            return self.cancel()
        if path == "/freeze":
            if self.background_freeze():
                return self.start_freeze()
            self.cancel()
            if self.frozen is None:
                self.frozen = self._build_archive()
            return self.frozen
        if path.startswith("/archive/"):
            if self.frozen is None:
                raise ValueError("freeze_before_retrieve")
            offset = int(path.rsplit("/", 1)[1])
            if not 0 <= offset < self.frozen["bytes"]:
                raise ValueError("invalid_archive_offset")
            with (self.root / "receipts.tar.gz").open("rb") as stream:
                stream.seek(offset)
                block = stream.read(CHUNK)
            return block
        if path.startswith("/inf060-snapshot/"):
            # This response is authenticated by the existing loopback handler.
            # Only the frozen, scoped projection is reachable through it.
            import re

            match = re.fullmatch(
                r"/inf060-snapshot/(0\.25|1|3|8|final)/([0-9]{1,8})", path
            )
            if not match or not (self.manifest or {}).get("descriptive", {}).get(
                "streaming"
            ):
                raise ValueError("streaming_snapshot_binding")
            label, offset = match[1], int(match[2])
            archive = (
                self.root / "descriptive-private" / ("snapshot-" + label + ".tar.gz")
            )
            size = archive.stat().st_size
            if archive.is_symlink() or not 0 <= offset < size <= 64 * 1024**2:
                raise ValueError("streaming_snapshot_limit")
            with archive.open("rb") as stream:
                stream.seek(offset)
                return stream.read(CHUNK)
        if self.cancelled or time.time() >= self.deadline:
            raise TimeoutError("host_work_deadline")
        if path == "/manifest":
            if hashlib.sha256(data).hexdigest() != self.manifest_hash:
                raise ValueError("manifest_hash_mismatch")
            value = json.loads(data)
            if self.manifest is not None and self.manifest != value:
                raise ValueError("manifest_changed")
            self.manifest = value
            return {"bound": True}
        if self.manifest is None:
            raise ValueError("manifest_required")
        if path.startswith("/upload/"):
            offset = int(path.rsplit("/", 1)[1])
            if (
                not 0 < len(data) <= CHUNK
                or self.status()["offset"] != offset
                or offset + len(data)
                > min(
                    ROUTINE_MAX_BUNDLE
                    if self.manifest.get("role")
                    in {"routine_tests", "descriptive_operator"}
                    else MAX_BUNDLE,
                    self.manifest["bundle_bytes"],
                )
                or hashlib.sha256(data).hexdigest() != headers.get("X-Chunk-SHA256")
            ):
                raise ValueError("upload_chunk_binding")
            with self.partial.open("ab") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            return self.status()
        if path.startswith("/input-upload/"):
            binding = self.manifest.get("gate_a_inputs")
            if not isinstance(binding, dict):
                raise ValueError("gate_a_input_manifest_required")
            offset = int(path.rsplit("/", 1)[1])
            expected_bytes = binding.get("bundle_bytes")
            expected_hash = binding.get("bundle_sha256")
            if (
                not 0 < len(data) <= CHUNK
                or self.status().get("input_offset") != offset
                or not isinstance(expected_bytes, int)
                or not 0 < expected_bytes <= MAX_INPUT_BUNDLE
                or offset + len(data) > expected_bytes
                or hashlib.sha256(data).hexdigest() != headers.get("X-Chunk-SHA256")
            ):
                raise ValueError("gate_a_input_chunk_binding")
            with self.input_partial.open("ab") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            return self.status()
        if path == "/stage-inputs":
            binding = self.manifest.get("gate_a_inputs")
            if not isinstance(binding, dict):
                raise ValueError("gate_a_input_manifest_or_stage_state")
            if self.input_receipt.exists():
                return self._verify_gate_a_staging()
            expected_bytes = binding.get("bundle_bytes")
            expected_hash = binding.get("bundle_sha256")
            expected_inventory = binding.get("inventory")
            s3_staging = binding.get("s3_staging")
            if (
                type(expected_bytes) is not int
                or not 0 < expected_bytes <= MAX_INPUT_BUNDLE
                or not isinstance(expected_hash, str)
                or len(expected_hash) != 64
                or not isinstance(expected_inventory, dict)
                or not expected_inventory
            ):
                raise ValueError("gate_a_input_bundle_binding")
            stage_request = json.loads(data) if data else {}
            stage_deadline = min(
                self.deadline,
                float(stage_request.get("deadline_epoch", self.deadline)),
            )
            if s3_staging is not None:
                session_prefix = f"gate-a/{self.manifest.get('session', '')}/input/"
                bucket, key = s3_staging.get("bucket"), s3_staging.get("key")
                if (
                    not isinstance(bucket, str)
                    or bucket != self.manifest.get("bucket_name")
                    or not isinstance(key, str)
                    or not key.startswith(session_prefix)
                    or s3_staging.get("bundle_bytes") != expected_bytes
                    or s3_staging.get("bundle_sha256") != expected_hash
                    or self.input_partial.exists()
                ):
                    raise ValueError("gate_a_input_s3_binding")
                download_url = stage_request.get("download_url")
                if not isinstance(download_url, str):
                    raise ValueError("gate_a_input_s3_download_url")
                if stage_deadline - time.time() < 1:
                    raise TimeoutError("gate_a_input_s3_deadline")
                self._download_gate_a_s3_input(
                    download_url,
                    deadline=stage_deadline,
                    expected_bytes=expected_bytes,
                    bucket=bucket,
                    key=key,
                )
            if (
                not isinstance(expected_bytes, int)
                or self.input_partial.stat().st_size != expected_bytes
                or digest(self.input_partial) != expected_hash
                or not isinstance(expected_inventory, dict)
                or not expected_inventory
                or self.input_stage.exists()
            ):
                raise ValueError("gate_a_input_bundle_binding")
            staging_root = Path(
                tempfile.mkdtemp(prefix="gate-a-inputs-", dir=self.root)
            )
            observed = {}
            try:
                with tarfile.open(self.input_partial, "r:*") as archive:
                    members = archive.getmembers()
                    for member in members:
                        relative = Path(member.name)
                        if (
                            relative.is_absolute()
                            or ".." in relative.parts
                            or "\\" in member.name
                            or not member.isfile()
                            or member.name not in expected_inventory
                            or member.name in observed
                        ):
                            raise ValueError("gate_a_input_archive_member")
                        expected = expected_inventory[member.name]
                        if member.size != expected.get("bytes"):
                            raise ValueError("gate_a_input_archive_length")
                        source = archive.extractfile(member)
                        if source is None:
                            raise ValueError("gate_a_input_archive_member")
                        target = staging_root / relative
                        target.parent.mkdir(parents=True, exist_ok=True)
                        digest_value, size = hashlib.sha256(), 0
                        with source, target.open("xb") as writer:
                            while chunk := source.read(CHUNK):
                                size += len(chunk)
                                digest_value.update(chunk)
                                writer.write(chunk)
                            writer.flush()
                            os.fsync(writer.fileno())
                        facts = {"bytes": size, "sha256": digest_value.hexdigest()}
                        if facts != expected:
                            raise ValueError("gate_a_input_archive_hash")
                        observed[member.name] = facts
                if observed != expected_inventory:
                    raise ValueError("gate_a_input_inventory")
                directories = sorted(
                    (path for path in staging_root.rglob("*") if path.is_dir()),
                    key=lambda path: len(path.parts),
                    reverse=True,
                )
                for directory in (*directories, staging_root):
                    sync_directory(directory)
                os.replace(staging_root, self.input_stage)
                sync_directory(self.root)
                inventory_bytes = (
                    json.dumps(observed, sort_keys=True, separators=(",", ":")) + "\n"
                ).encode()
                receipt = {
                    "schema": "package-a-gate-a-staging-v1",
                    "bundle_bytes": expected_bytes,
                    "bundle_sha256": expected_hash,
                    "s3_staging_key": s3_staging.get("key")
                    if s3_staging is not None
                    else None,
                    "inventory": observed,
                    "inventory_sha256": hashlib.sha256(inventory_bytes).hexdigest(),
                    "readback_verified": True,
                }
                pending_receipt = self.input_receipt.with_suffix(".pending")
                pending_receipt.write_bytes(
                    (json.dumps(receipt, sort_keys=True) + "\n").encode()
                )
                with pending_receipt.open("rb") as stream:
                    os.fsync(stream.fileno())
                os.replace(pending_receipt, self.input_receipt)
                sync_directory(self.root)
                return receipt
            finally:
                if staging_root.exists():
                    shutil.rmtree(staging_root)
        if path == "/stage":
            if digest(self.partial) != self.manifest["bundle_sha256"]:
                raise ValueError("source_bundle_hash")
            head = self.manifest["source_commit"]
            if len(head) != 40 or any(c not in "0123456789abcdef" for c in head):
                raise ValueError("invalid_source_commit")
            if self.manifest.get("source_payload") is not None:
                binding = self.manifest["source_payload"]
                if binding.get("source_commit") != head:
                    raise ValueError("descriptive:payload_commit")
                stage_sparse_payload(self.repo, self.partial, binding)
            elif not self.repo.exists():
                self.command(["git", "init", str(self.repo)])
                # Product bundles keep their historical shallow contract. The
                # routine plan/history suites require the complete private graph.
                if self.manifest.get("role") == "routine_tests":
                    if self.manifest.get("source_history") != "complete":
                        raise ValueError("routine_source_history_required")
                else:
                    (self.repo / ".git/shallow").write_text(head + "\n")
                self.command(
                    ["git", "-C", str(self.repo), "bundle", "verify", str(self.partial)]
                )
                self.command(
                    ["git", "-C", str(self.repo), "fetch", str(self.partial), "HEAD"]
                )
                self.command(
                    ["git", "-C", str(self.repo), "checkout", "--detach", "FETCH_HEAD"]
                )
                self.command(["git", "-C", str(self.repo), "fsck", "--full"])
                if (
                    self.manifest.get("role") == "routine_tests"
                    and self.command(
                        [
                            "git",
                            "-C",
                            str(self.repo),
                            "rev-parse",
                            "--is-shallow-repository",
                        ]
                    ).strip()
                    != b"false"
                ):
                    raise ValueError("routine_source_history_incomplete")
            # Verify every Python file against git bytes and the reviewed map.
            actual = (
                self.command(["git", "-C", str(self.repo), "rev-parse", "HEAD"])
                .decode()
                .strip()
            )
            names = self.command(
                ["git", "-C", str(self.repo), "ls-files", "-z", "python"]
            )
            observed = {
                name.decode(): digest(self.repo / name.decode())
                for name in names.split(b"\0")
                if name
            }
            if actual != head or observed != self.manifest["python_sha256"]:
                raise ValueError("source_python_hash_binding")
            (self.root / "stage.json").write_text(
                json.dumps({"head": actual, "python_sha256": observed})
            )
            return {"staged": True, "head": actual, "python_files": len(observed)}
        if path == "/start":
            if self.child:
                return self.status()
            if not (self.root / "stage.json").exists():
                raise ValueError("start_once_after_stage")
            if "gate_a_inputs" in self.manifest:
                self._verify_gate_a_staging()
            runtime = {**self.manifest, "deadline_epoch": self.deadline}
            runtime_path = self.root / "runtime.json"
            runtime_path.write_text(json.dumps(runtime))
            self.log = (self.root / "bootstrap.log").open("ab")
            self.child = subprocess.Popen(
                [
                    "sh",
                    str(self.repo / "scripts/package_a_bootstrap.sh"),
                    str(runtime_path),
                    str(self.output),
                ],
                cwd=self.repo,
                env=host_environment(),
                stdout=self.log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            return self.status()
        raise ValueError("unknown_path")


def server(host, port=22280):
    class Handler(BaseHTTPRequestHandler):
        def serve(self):
            if not hmac.compare_digest(
                self.headers.get("Authorization", ""), "Bearer " + host.token
            ):
                self.send_error(403)
                return
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 <= size <= 8 * CHUNK:
                    raise ValueError("request_size")
                data = self.rfile.read(size)
                if len(data) != size:
                    raise ValueError("short_request")
                if host.background_freeze() and (
                    self.path == "/freeze"
                    or (self.path == "/status" and host.freeze_started is not None)
                ):
                    result = host.dispatch(self.path, data, self.headers)
                else:
                    with host.lock:
                        result = host.dispatch(self.path, data, self.headers)
                body = (
                    result if isinstance(result, bytes) else json.dumps(result).encode()
                )
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("X-Chunk-SHA256", hashlib.sha256(body).hexdigest())
                self.end_headers()
                self.wfile.write(body)
            except Exception as exc:
                message = str(exc)
                if host.token:
                    message = message.replace(host.token, "[redacted]")
                body = f"{type(exc).__name__}: {message[:200]}".encode("utf-8")
                self.send_response(409)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        do_GET = do_POST = serve

        def log_message(self, *args):
            pass

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--token", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--deadline", type=float, required=True)
    parser.add_argument("--directory", type=Path, default=Path("/opt/dec077"))
    args = parser.parse_args()
    host = Host(args.directory, args.token, args.manifest_sha256, args.deadline)

    def watchdog():
        while time.time() < host.deadline:
            time.sleep(min(1, max(0, host.deadline - time.time())))
        with host.lock:
            host.cancel()

    threading.Thread(target=watchdog, daemon=True).start()
    server(host).serve_forever()


if __name__ == "__main__":
    main()
