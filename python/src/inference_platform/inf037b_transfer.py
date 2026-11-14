"""Bounded archive socket transfer and S3-compatible durable artifact storage."""

from __future__ import annotations

import hashlib
import math
import os
import socket
import socketserver
import threading
import time
import uuid
from pathlib import Path, PurePosixPath

from .inf037b_archive import IntegrityError, encode, file_facts, safe_file, sha, strict_json
from .inf037b_durable_ports import DurableStore, sync_directory
from .inf037b_resolver import exact, integer, require

MAX_FRAME_BYTES = 64 * 1024
DEFAULT_CHUNK_BYTES = 4 * 1024 * 1024
MAX_S3_PUT_BYTES = 5 * 1024 * 1024 * 1024


def _safe_key(value):
    require(isinstance(value, str) and value and "\\" not in value, "transfer:artifact_key")
    path = PurePosixPath(value)
    require(
        not path.is_absolute() and all(part not in {"", ".", ".."} for part in path.parts),
        "transfer:artifact_key",
    )
    exact(path.as_posix(), value, "transfer:artifact_key")
    return path.as_posix()


def _hash_file(path, hasher_factory=hashlib.sha256, check_deadline=None):
    digest = hasher_factory()
    size = 0
    with Path(path).open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            if check_deadline is not None:
                check_deadline()
            size += len(chunk)
            digest.update(chunk)
    if check_deadline is not None:
        check_deadline()
    return {"bytes": size, "sha256": digest.hexdigest()}


def _artifact_facts(
    artifacts,
    *,
    max_total_bytes,
    max_objects,
    hasher_factory=hashlib.sha256,
    check_deadline=None,
):
    require(integer(max_total_bytes), "transfer:byte_bound")
    require(integer(max_objects), "transfer:object_bound")
    require(max_total_bytes > 0 and max_objects > 0, "transfer:positive_bound")
    require(
        isinstance(artifacts, dict) and 0 < len(artifacts) <= max_objects, "transfer:object_count"
    )
    facts = {}
    total = 0
    for key, source in artifacts.items():
        key = _safe_key(key)
        require(key not in facts, "transfer:duplicate_key")
        source = Path(source)
        require(source.is_file() and not source.is_symlink(), f"transfer:source_file:{key}")
        facts[key] = _hash_file(source, hasher_factory, check_deadline)
        total += facts[key]["bytes"]
        require(total <= max_total_bytes, "transfer:byte_bound")
    return dict(sorted(facts.items()))


def _validate_facts(manifest, *, max_total_bytes, max_objects):
    require(integer(max_total_bytes), "transfer:byte_bound")
    require(integer(max_objects), "transfer:object_bound")
    require(max_total_bytes > 0 and max_objects > 0, "transfer:positive_bound")
    require(
        isinstance(manifest, dict) and 0 < len(manifest) <= max_objects, "transfer:object_count"
    )
    total = 0
    result = {}
    for raw_key, facts in manifest.items():
        key = _safe_key(raw_key)
        exact(set(facts), {"bytes", "sha256"}, "transfer:manifest_fields")
        require(integer(facts["bytes"]), "transfer:manifest_length")
        require(facts["bytes"] >= 0, "transfer:manifest_length")
        require(
            isinstance(facts["sha256"], str)
            and len(facts["sha256"]) == 64
            and all(c in "0123456789abcdef" for c in facts["sha256"]),
            "transfer:manifest_hash",
        )
        require(key not in result, "transfer:duplicate_key")
        result[key] = dict(facts)
        total += facts["bytes"]
        require(total <= max_total_bytes, "transfer:byte_bound")
    return dict(sorted(result.items()))


def _restore_export_archive_directories(files):
    roots = {}
    for key, path in files.items():
        parts = PurePosixPath(key).parts
        if len(parts) >= 2 and parts[0] in {"source", "sanitized", "destination"}:
            roots[parts[0]] = Path(path).parents[len(parts) - 2]
    for root in roots.values():
        for directory in ("raw", "cohorts", "events"):
            (root / directory).mkdir(mode=0o700, parents=True, exist_ok=True)


def _read_frame(stream):
    raw = stream.readline(MAX_FRAME_BYTES + 1)
    if not raw:
        raise EOFError("transfer:ack_missing")
    require(len(raw) <= MAX_FRAME_BYTES and raw.endswith(b"\n"), "transfer:frame_size")
    return strict_json(raw)


def _write_frame(stream, value):
    raw = encode(value)
    require(len(raw) <= MAX_FRAME_BYTES, "transfer:frame_size")
    stream.write(raw)
    stream.flush()


def _check_ack_join(response, *, transfer_id, request_id, key):
    exact(
        (response.get("transfer_id"), response.get("request_id"), response.get("key")),
        (transfer_id, request_id, key),
        "transfer:ack_join",
    )


class _TransferTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class SocketArchiveReceiver:
    """Single-transfer TCP receiver with fsynced offsets and exact ack joins.

    Run this service inside the receiving ProcessCalls group. A reconnect asks
    for the durable per-file offset before sending another bounded chunk.
    """

    def __init__(
        self,
        directory,
        *,
        transfer_id,
        manifest,
        max_total_bytes,
        max_objects,
        chunk_bytes=DEFAULT_CHUNK_BYTES,
        hasher_factory=hashlib.sha256,
        after_data_fsync=None,
    ):
        require(isinstance(transfer_id, str) and transfer_id, "transfer:transfer_id")
        require(integer(chunk_bytes), "transfer:chunk_size")
        require(0 < chunk_bytes <= 64 * 1024 * 1024, "transfer:chunk_size")
        self.transfer_id = transfer_id
        self.manifest = _validate_facts(
            manifest, max_total_bytes=max_total_bytes, max_objects=max_objects
        )
        self.manifest_sha256 = sha(encode(self.manifest))
        self.chunk_bytes = chunk_bytes
        self.hasher_factory = hasher_factory
        self.after_data_fsync = after_data_fsync
        self.root = Path(directory)
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.data_root = self.root / "objects"
        self.data_root.mkdir(mode=0o700, exist_ok=True)
        sync_directory(self.root)
        state_path = self.root / "state"
        initial = {
            "transfer_id": transfer_id,
            "manifest_sha256": self.manifest_sha256,
            "files": {
                key: {"bytes": 0, "prefix_sha256": self.hasher_factory().hexdigest()}
                for key in self.manifest
            },
            "events": [],
        }
        self.state = DurableStore(state_path, initial, initialize=True)
        state = self.state.read()
        exact(state["transfer_id"], transfer_id, "transfer:resume_id")
        exact(state["manifest_sha256"], self.manifest_sha256, "transfer:resume_manifest")
        exact(set(state["files"]), set(self.manifest), "transfer:resume_inventory")
        state.setdefault("events", [])
        self.hashers = {}
        recovered = False
        for key, facts in self.manifest.items():
            item = state["files"][key]
            path = safe_file(self.data_root, key)
            offset = item["bytes"]
            require(0 <= offset <= facts["bytes"], "transfer:resume_offset")
            if offset == 0:
                if path.exists():
                    require(path.is_file() and not path.is_symlink(), "transfer:resume_file")
                    length = path.stat().st_size
                    require(length <= facts["bytes"], "transfer:resume_length")
                    if length:
                        self._truncate_unacknowledged(path, key, length, 0, state)
                        recovered = True
                elif facts["bytes"] == 0:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    with path.open("xb") as stream:
                        stream.flush()
                        os.fsync(stream.fileno())
                    sync_directory(path.parent)
                digest = self.hasher_factory()
            else:
                require(path.is_file() and not path.is_symlink(), "transfer:resume_file")
                length = path.stat().st_size
                require(length >= offset, "transfer:resume_length")
                require(length <= facts["bytes"], "transfer:resume_length")
                if length > offset:
                    self._truncate_unacknowledged(path, key, length, offset, state)
                    recovered = True
                digest = self.hasher_factory()
                with path.open("rb") as stream:
                    remaining = offset
                    while remaining:
                        chunk = stream.read(min(1024 * 1024, remaining))
                        if not chunk:
                            break
                        digest.update(chunk)
                        remaining -= len(chunk)
            exact(digest.hexdigest(), item["prefix_sha256"], "transfer:resume_hash")
            self.hashers[key] = digest
            if offset == facts["bytes"]:
                exact(digest.hexdigest(), facts["sha256"], "transfer:file_hash")
        if recovered:
            self.state.write(state)
        self.events = list(state["events"])
        self._faults = {}
        self._fault_lock = threading.Lock()
        self._state_lock = threading.RLock()
        self.server = None
        self.thread = None

    def _truncate_unacknowledged(self, path, key, previous, offset, state):
        with path.open("r+b") as stream:
            stream.truncate(offset)
            stream.flush()
            os.fsync(stream.fileno())
        sync_directory(path.parent)
        state.setdefault("events", []).append(
            {
                "event": "truncated_unacknowledged_bytes",
                "key": key,
                "from_bytes": previous,
                "to_bytes": offset,
            }
        )

    def inject_once(self, name):
        require(name in {"drop_ack", "late_ack", "duplicate_ack", "stale_ack"}, "transfer:fault")
        self.inject_n(name, 1)

    def inject_n(self, name, count):
        require(name in {"drop_ack", "late_ack", "duplicate_ack", "stale_ack"}, "transfer:fault")
        require(integer(count) and count > 0, "transfer:fault_count")
        with self._fault_lock:
            self._faults[name] = self._faults.get(name, 0) + count

    def _take_fault(self):
        with self._fault_lock:
            for name in ("drop_ack", "late_ack", "duplicate_ack", "stale_ack"):
                if self._faults.get(name, 0):
                    self._faults[name] -= 1
                    return name
        return None

    def start(self, host="127.0.0.1", port=0):
        receiver = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(10)
                stream = self.request.makefile("rwb")
                try:
                    request = _read_frame(stream)
                    with receiver._state_lock:
                        response = receiver._handle(request, stream)
                    fault = receiver._take_fault() if request.get("op") == "chunk" else None
                    if fault == "drop_ack":
                        receiver.events.append(
                            {"event": "ack_dropped", "request_id": request["request_id"]}
                        )
                        return
                    if fault == "late_ack":
                        receiver.events.append(
                            {"event": "ack_late", "request_id": request["request_id"]}
                        )
                        time.sleep(0.25)
                    if fault == "stale_ack":
                        response["request_id"] = "stale-" + response["request_id"]
                    encoded = encode(response)
                    if fault == "duplicate_ack":
                        receiver.events.append(
                            {"event": "ack_duplicated", "request_id": request["request_id"]}
                        )
                        stream.write(encoded + encoded)
                    else:
                        stream.write(encoded)
                    stream.flush()
                except (BrokenPipeError, ConnectionResetError, TimeoutError, OSError) as exc:
                    receiver.events.append(
                        {"event": "client_disconnected", "reason": type(exc).__name__}
                    )
                except Exception as exc:
                    try:
                        _write_frame(
                            stream,
                            {
                                "status": "refused",
                                "reason": str(exc)
                                if isinstance(exc, IntegrityError)
                                else "transfer:receiver_error",
                            },
                        )
                    except OSError:
                        pass
                finally:
                    stream.close()

        self.server = _TransferTCPServer((host, port), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self

    @property
    def address(self):
        require(self.server is not None, "transfer:receiver_not_started")
        return self.server.server_address

    def _handle(self, request, stream):
        # Chunk frames have a JSON header followed by exactly data_length bytes.
        if request.get("op") == "chunk":
            length = request.get("data_length")
            require(integer(length), "transfer:chunk_length")
            require(0 < length <= self.chunk_bytes, "transfer:chunk_length")
            data = stream.read(length)
            exact(len(data), length, "transfer:chunk_body")
            request["_data"] = data
        return self._handle_validated(request)

    def _verify_saved_file(self, path, item, facts):
        offset = item["bytes"]
        if offset == 0:
            require(not path.exists() or path.stat().st_size == 0, "transfer:resume_length")
            return
        require(path.is_file() and not path.is_symlink(), "transfer:resume_file")
        exact(path.stat().st_size, offset, "transfer:resume_length")
        digest = self.hasher_factory()
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
        exact(digest.hexdigest(), item["prefix_sha256"], "transfer:resume_hash")
        if offset == facts["bytes"]:
            exact(digest.hexdigest(), facts["sha256"], "transfer:file_hash")

    def _handle_validated(self, request):
        exact(request["transfer_id"], self.transfer_id, "transfer:transfer_id")
        request_id = request.get("request_id")
        require(isinstance(request_id, str) and request_id, "transfer:request_id")
        key = _safe_key(request.get("key"))
        require(key in self.manifest, "transfer:unknown_key")
        state = self.state.read()
        item = state["files"][key]
        facts = self.manifest[key]
        path = safe_file(self.data_root, key)
        if request.get("op") == "status":
            if item["bytes"]:
                require(path.is_file() and not path.is_symlink(), "transfer:resume_file")
                exact(path.stat().st_size, item["bytes"], "transfer:resume_length")
            else:
                require(not path.exists() or path.stat().st_size == 0, "transfer:resume_length")
            exact(self.hashers[key].hexdigest(), item["prefix_sha256"], "transfer:resume_hash")
            return {
                "status": "ok",
                "transfer_id": self.transfer_id,
                "request_id": request_id,
                "key": key,
                "manifest_sha256": self.manifest_sha256,
                "offset": item["bytes"],
                "prefix_sha256": item["prefix_sha256"],
            }
        exact(request.get("op"), "chunk", "transfer:operation")
        offset, length, data = request.get("offset"), request.get("data_length"), request["_data"]
        require(integer(offset), "transfer:offset")
        require(integer(length), "transfer:chunk_length")
        exact(length, len(data), "transfer:chunk_body")
        require(0 < length <= self.chunk_bytes, "transfer:chunk_length")
        require(offset + length <= facts["bytes"], "transfer:chunk_range")
        if offset < item["bytes"]:
            require(offset + length <= item["bytes"], "transfer:duplicate_chunk_range")
            with path.open("rb") as saved:
                saved.seek(offset)
                exact(saved.read(length), data, "transfer:duplicate_chunk_mismatch")
        else:
            exact(offset, item["bytes"], "transfer:offset_order")
            path.parent.mkdir(parents=True, exist_ok=True)
            created = not path.exists()
            with path.open("xb" if created else "r+b") as target:
                target.seek(offset)
                exact(target.write(data), len(data), "transfer:short_write")
                target.flush()
                os.fsync(target.fileno())
            if created:
                sync_directory(path.parent)
            if self.after_data_fsync is not None:
                self.after_data_fsync(key, offset, len(data))
            digest = self.hashers[key]
            digest.update(data)
            item = {"bytes": offset + length, "prefix_sha256": digest.copy().hexdigest()}
            if item["bytes"] == facts["bytes"]:
                exact(item["prefix_sha256"], facts["sha256"], "transfer:file_hash")
            state["files"][key] = item
            self.state.write(state)
            if item["bytes"] == facts["bytes"]:
                self._verify_saved_file(path, item, facts)
        return {
            "status": "ok",
            "transfer_id": self.transfer_id,
            "request_id": request_id,
            "key": key,
            "offset": item["bytes"],
            "prefix_sha256": item["prefix_sha256"],
            "durable": True,
        }

    def artifact_paths(self):
        state = self.state.read()
        result = {}
        for key, facts in self.manifest.items():
            item = state["files"][key]
            exact(item["bytes"], facts["bytes"], "transfer:incomplete")
            path = safe_file(self.data_root, key)
            require(path.is_file() and not path.is_symlink(), "transfer:resume_file")
            exact(path.stat().st_size, item["bytes"], "transfer:resume_length")
            exact(self.hashers[key].hexdigest(), item["prefix_sha256"], "transfer:resume_hash")
            exact(item["prefix_sha256"], facts["sha256"], "transfer:file_hash")
            result[key] = path
        return result

    def close(self):
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
            self.thread.join(timeout=5)
            self.server = None
            self.thread = None

    def __enter__(self):
        return self.start()

    def __exit__(self, exc_type, exc, tb):
        self.close()


class SocketArchiveTransfer:
    """Transfer a manifest-bound file set with per-chunk durable offset acks."""

    def __init__(
        self,
        *,
        chunk_bytes=DEFAULT_CHUNK_BYTES,
        timeout_s=5,
        retries=3,
        transfer_timeout_s=3600,
        max_reconnects=None,
        max_reconnect_seconds=60,
        hasher_factory=hashlib.sha256,
        monotonic=time.monotonic,
    ):
        require(integer(chunk_bytes), "transfer:chunk_size")
        require(integer(retries), "transfer:retry_count")
        require(0 < chunk_bytes <= 64 * 1024 * 1024 and retries >= 0, "transfer:client_bounds")
        require(0 < timeout_s <= 60, "transfer:timeout")
        require(0 < transfer_timeout_s <= 24 * 60 * 60, "transfer:deadline_bound")
        if max_reconnects is None:
            max_reconnects = retries
        require(integer(max_reconnects) and max_reconnects >= 0, "transfer:reconnect_bound")
        require(
            isinstance(max_reconnect_seconds, (int, float))
            and math.isfinite(max_reconnect_seconds)
            and max_reconnect_seconds >= 0,
            "transfer:reconnect_bound",
        )
        self.chunk_bytes, self.timeout_s, self.retries = chunk_bytes, timeout_s, retries
        self.transfer_timeout_s = transfer_timeout_s
        self.max_reconnects = max_reconnects
        self.max_reconnect_seconds = max_reconnect_seconds
        self.hasher_factory, self.monotonic = hasher_factory, monotonic

    def _exchange(self, address, request, data=None, *, timeout_s=None):
        timeout = self.timeout_s if timeout_s is None else timeout_s
        with socket.create_connection(address, timeout=timeout) as connection:
            connection.settimeout(timeout)
            stream = connection.makefile("rwb")
            _write_frame(stream, request)
            if data is not None:
                stream.write(data)
                stream.flush()
            response = _read_frame(stream)
            require(response.get("status") == "ok", response.get("reason", "transfer:peer_refused"))
            # One request per TCP connection: extra response bytes are a duplicate ack.
            extra = stream.read(1)
            require(not extra, "transfer:duplicate_ack")
            return response

    def transfer(
        self,
        artifacts,
        address,
        *,
        transfer_id,
        max_total_bytes,
        max_objects,
        deadline_monotonic=None,
        max_reconnects=None,
        max_reconnect_seconds=None,
        gate_a_phase=None,
    ):
        started = self.monotonic()
        if deadline_monotonic is not None:
            require(
                type(deadline_monotonic) in (int, float) and math.isfinite(deadline_monotonic),
                "transfer:deadline_bound",
            )
        deadline = (
            started + self.transfer_timeout_s if deadline_monotonic is None else deadline_monotonic
        )
        reconnect_limit = self.max_reconnects if max_reconnects is None else max_reconnects
        reconnect_seconds_limit = (
            self.max_reconnect_seconds if max_reconnect_seconds is None else max_reconnect_seconds
        )
        require(integer(reconnect_limit) and reconnect_limit >= 0, "transfer:reconnect_bound")
        require(
            isinstance(reconnect_seconds_limit, (int, float))
            and math.isfinite(reconnect_seconds_limit)
            and reconnect_seconds_limit >= 0,
            "transfer:reconnect_bound",
        )
        metrics = {"attempts": 0, "reconnect_attempts": 0, "reconnect_seconds": 0.0}
        reconnect_started = None

        def receipt():
            pending = self.monotonic() - reconnect_started if reconnect_started is not None else 0.0
            return {
                **metrics,
                "reconnect_seconds": metrics["reconnect_seconds"] + pending,
                "elapsed_seconds": self.monotonic() - started,
                "deadline_seconds": deadline - started,
                "reconnect_budget_count": reconnect_limit,
                "reconnect_budget_seconds": reconnect_seconds_limit,
            }

        def refuse(reason):
            error = IntegrityError(reason)
            error.receipt = receipt()
            raise error

        def check_deadline():
            if self.monotonic() >= deadline:
                refuse("transfer:deadline")

        def failed_exchange():
            nonlocal reconnect_started
            metrics["reconnect_attempts"] += 1
            if reconnect_started is None:
                reconnect_started = self.monotonic()
            if metrics["reconnect_attempts"] > reconnect_limit:
                refuse("transfer:reconnect_budget")
            if self.monotonic() >= deadline:
                refuse("transfer:deadline")
            if self.monotonic() - reconnect_started > reconnect_seconds_limit:
                refuse("transfer:reconnect_budget")

        def exchanged(request, data=None, *, operation_deadline=False):
            check_deadline()
            timeout = (
                deadline - self.monotonic()
                if operation_deadline
                else min(self.timeout_s, deadline - self.monotonic())
            )
            if reconnect_started is not None and not operation_deadline:
                reconnect_remaining = (
                    reconnect_seconds_limit
                    - metrics["reconnect_seconds"]
                    - (self.monotonic() - reconnect_started)
                )
                if reconnect_remaining <= 0:
                    refuse("transfer:reconnect_budget")
                timeout = min(timeout, reconnect_remaining)
            metrics["attempts"] += 1
            response = self._exchange(address, request, data, timeout_s=timeout)
            check_deadline()
            return response

        def reconcile_status(key, expected, manifest_hash, local_id, prefix_hasher):
            nonlocal reconnect_started
            status_id = hashlib.sha256(
                f"status:{local_id}:{metrics['attempts']}:".encode()
            ).hexdigest()
            status = exchanged(
                {
                    "op": "status",
                    "transfer_id": transfer_id,
                    "request_id": status_id,
                    "key": key,
                }
            )
            _check_ack_join(status, transfer_id=transfer_id, request_id=status_id, key=key)
            exact(status["manifest_sha256"], manifest_hash, "transfer:ack_join")
            offset = status["offset"]
            require(integer(offset), "transfer:resume_offset")
            require(0 <= offset <= expected["bytes"], "transfer:resume_offset")
            prefix = self.hasher_factory()
            with Path(artifacts[key]).open("rb") as stream:
                remaining = offset
                while remaining:
                    check_deadline()
                    chunk = stream.read(min(1024 * 1024, remaining))
                    require(chunk, "transfer:source_truncated")
                    prefix.update(chunk)
                    remaining -= len(chunk)
            exact(status["prefix_sha256"], prefix.hexdigest(), "transfer:resume_hash")
            if offset == expected["bytes"]:
                exact(prefix.hexdigest(), expected["sha256"], "transfer:resume_hash")
            if reconnect_started is not None:
                metrics["reconnect_seconds"] += self.monotonic() - reconnect_started
                reconnect_started = None
                if metrics["reconnect_seconds"] > reconnect_seconds_limit:
                    refuse("transfer:reconnect_budget")
            return offset, prefix

        check_deadline()
        manifest = _artifact_facts(
            artifacts,
            max_total_bytes=max_total_bytes,
            max_objects=max_objects,
            hasher_factory=self.hasher_factory,
            check_deadline=check_deadline,
        )
        check_deadline()
        manifest_hash = sha(encode(manifest))
        if gate_a_phase is not None:
            phase = gate_a_phase.get("phase")
            require(phase in {"archive", "spool"}, "transfer:gate_a_phase")
            require(transfer_id.startswith(f"gate-a-{phase}-"), "transfer:gate_a_phase")
            request_id = sha(encode([transfer_id, "manifest", manifest_hash]))
            response = exchanged(
                {
                    "op": "manifest",
                    "transfer_id": transfer_id,
                    "request_id": request_id,
                    "key": "__manifest__",
                    "manifest": manifest,
                    "manifest_sha256": manifest_hash,
                    "max_total_bytes": max_total_bytes,
                    "max_objects": max_objects,
                    "phase": gate_a_phase["phase"],
                    "induce_drop": gate_a_phase["induce_drop"],
                }
            )
            _check_ack_join(
                response, transfer_id=transfer_id, request_id=request_id, key="__manifest__"
            )
            exact(response["manifest_sha256"], manifest_hash, "transfer:manifest_hash")
        data_elapsed = None
        for key, expected in manifest.items():
            local_id = f"{transfer_id}:{key}"
            prefix = self.hasher_factory()
            offset = None
            source = Path(artifacts[key])
            while offset != expected["bytes"]:
                check_deadline()
                if offset is None:
                    try:
                        offset, prefix = reconcile_status(
                            key, expected, manifest_hash, local_id, prefix
                        )
                        if offset == expected["bytes"]:
                            break
                    except (OSError, EOFError, TimeoutError, ConnectionError):
                        failed_exchange()
                        continue
                with source.open("rb") as stream:
                    stream.seek(offset)
                    data = stream.read(min(self.chunk_bytes, expected["bytes"] - offset))
                require(data, "transfer:source_truncated")
                request_id = sha(encode([transfer_id, key, offset, len(data), manifest_hash]))
                next_prefix = prefix.copy()
                next_prefix.update(data)
                try:
                    response = exchanged(
                        {
                            "op": "chunk",
                            "transfer_id": transfer_id,
                            "request_id": request_id,
                            "key": key,
                            "offset": offset,
                            "data_length": len(data),
                        },
                        data,
                    )
                except (OSError, EOFError, TimeoutError, ConnectionError):
                    failed_exchange()
                    offset = None
                    continue
                _check_ack_join(response, transfer_id=transfer_id, request_id=request_id, key=key)
                exact(response["offset"], offset + len(data), "transfer:ack_join")
                exact(response["durable"], True, "transfer:ack_join")
                exact(response["prefix_sha256"], next_prefix.hexdigest(), "transfer:ack_hash")
                offset = response["offset"]
                prefix = next_prefix
                if offset == expected["bytes"]:
                    exact(prefix.hexdigest(), expected["sha256"], "transfer:file_hash")
            if expected["bytes"] == 0:
                exact(prefix.hexdigest(), expected["sha256"], "transfer:file_hash")
        data_elapsed = self.monotonic() - started
        receiver_receipt = None
        if gate_a_phase is not None:
            request_id = sha(encode([transfer_id, "complete", manifest_hash]))
            response = exchanged(
                {
                    "op": "complete",
                    "transfer_id": transfer_id,
                    "request_id": request_id,
                    "key": "__phase__",
                    "manifest_sha256": manifest_hash,
                },
                operation_deadline=True,
            )
            _check_ack_join(
                response, transfer_id=transfer_id, request_id=request_id, key="__phase__"
            )
            exact(response.get("durable"), True, "transfer:phase_receipt")
            receiver_receipt = response.get("receiver_receipt")
            require(isinstance(receiver_receipt, dict), "transfer:phase_receipt")
        elapsed = self.monotonic() - started
        result = {
            "schema": "inf037b-socket-transfer-v1",
            "transfer_id": transfer_id,
            "manifest_sha256": manifest_hash,
            "manifest": manifest,
            "bytes": sum(facts["bytes"] for facts in manifest.values()),
            "objects": len(manifest),
            **receipt(),
            "elapsed_seconds": elapsed,
        }
        if data_elapsed is not None:
            result["data_elapsed_seconds"] = data_elapsed
        if receiver_receipt is not None:
            result["receiver_receipt"] = receiver_receipt
        return result


class S3ArchiveStore:
    """S3-compatible object store with explicit bounds and independent readback."""

    def __init__(self, client, *, bucket, prefix, max_total_bytes, max_objects):
        require(isinstance(bucket, str) and bucket, "transfer:s3_bucket")
        self.client, self.bucket = client, bucket
        self.prefix = _safe_key(prefix.rstrip("/"))
        self.max_total_bytes, self.max_objects = max_total_bytes, max_objects

    @classmethod
    def client_for_endpoint(cls, endpoint_url=None, *, region="us-east-1"):
        import boto3
        from botocore.config import Config

        return boto3.client(
            "s3",
            endpoint_url=endpoint_url,
            region_name=region,
            config=Config(
                signature_version="s3v4",
                retries={"mode": "standard", "max_attempts": 3},
                connect_timeout=10,
                read_timeout=60,
                s3={"addressing_style": "path"},
            ),
        )

    def _put_file(self, key, path, facts):
        require(facts["bytes"] <= MAX_S3_PUT_BYTES, "transfer:s3_single_put_bound")
        with Path(path).open("rb") as body:
            response = self.client.put_object(
                Bucket=self.bucket,
                Key=key,
                Body=body,
                ContentLength=facts["bytes"],
                Metadata={"sha256": facts["sha256"]},
            )
        request_meta = response.get("ResponseMetadata", {})
        exact(request_meta.get("HTTPStatusCode"), 200, "transfer:s3_put_ack")
        etag = response.get("ETag")
        require(isinstance(etag, str) and etag, "transfer:s3_put_ack")
        return {
            "bucket": self.bucket,
            "key": key,
            "bytes": facts["bytes"],
            "sha256": facts["sha256"],
            "etag": etag,
            "version_id": response.get("VersionId"),
            "request_id": request_meta.get("RequestId"),
        }

    def _get_file(self, ack, destination, expected):
        kwargs = {"Bucket": self.bucket, "Key": ack["key"]}
        if ack.get("version_id") is not None:
            kwargs["VersionId"] = ack["version_id"]
        response = self.client.get_object(**kwargs)
        exact(
            response.get("ResponseMetadata", {}).get("HTTPStatusCode"), 200, "transfer:s3_get_ack"
        )
        exact(response.get("ContentLength"), expected["bytes"], "transfer:s3_length")
        exact(
            response.get("Metadata", {}).get("sha256"),
            expected["sha256"],
            "transfer:s3_metadata_hash",
        )
        destination = Path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(destination.name + ".pending-" + uuid.uuid4().hex)
        size = 0
        try:
            body = response["Body"]
            with temporary.open("xb") as writer:
                while chunk := body.read(1024 * 1024):
                    size += len(chunk)
                    require(size <= expected["bytes"], "transfer:s3_length")
                    exact(writer.write(chunk), len(chunk), "transfer:s3_short_write")
                writer.flush()
                os.fsync(writer.fileno())
            body.close()
            exact(size, expected["bytes"], "transfer:s3_length")
            exact(file_facts(temporary), expected, "transfer:s3_hash_length")
            os.replace(temporary, destination)
            sync_directory(destination.parent)
        finally:
            if temporary.exists():
                temporary.unlink()
                sync_directory(temporary.parent)
        return destination

    def persist_archive_artifacts(self, artifacts):
        manifest = _artifact_facts(
            artifacts,
            max_total_bytes=self.max_total_bytes,
            max_objects=self.max_objects,
        )
        manifest_hash = sha(encode(manifest))
        objects = {}
        for key, facts in manifest.items():
            object_key = f"{self.prefix}/{manifest_hash}/{key}"
            objects[key] = self._put_file(object_key, artifacts[key], facts)
        index_data = encode({"schema": "inf037b-s3-archive-manifest-v1", "manifest": manifest})
        index_facts = {"bytes": len(index_data), "sha256": sha(index_data)}
        index_key = f"{self.prefix}/manifests/{index_facts['sha256']}.json"
        # The manifest is small and deterministic; stage it as a local file so
        # it follows the same ContentLength and independent GET verification.
        import tempfile

        with tempfile.TemporaryDirectory(prefix="inf037b-s3-manifest-") as directory:
            local_manifest = Path(directory) / "manifest.json"
            local_manifest.write_bytes(index_data)
            manifest_ack = self._put_file(index_key, local_manifest, index_facts)
            downloaded = self._get_file(
                manifest_ack, Path(directory) / "manifest.readback", index_facts
            )
            exact(downloaded.read_bytes(), index_data, "transfer:s3_manifest_readback")
        return {
            "schema": "inf037b-s3-archive-receipt-v1",
            "bucket": self.bucket,
            "prefix": self.prefix,
            "manifest_sha256": manifest_hash,
            "manifest_object": manifest_ack,
            "objects": objects,
        }

    def retrieve_archive_artifacts(self, receipt, destination):
        exact(receipt["schema"], "inf037b-s3-archive-receipt-v1", "transfer:s3_receipt")
        exact(receipt["bucket"], self.bucket, "transfer:s3_bucket")
        require(receipt["prefix"].startswith(self.prefix), "transfer:s3_prefix")
        destination = Path(destination)
        manifest_ack = receipt["manifest_object"]
        manifest_path = self._get_file(
            manifest_ack,
            destination / ".archive-manifest.json",
            {"bytes": manifest_ack["bytes"], "sha256": manifest_ack["sha256"]},
        )
        manifest_document = strict_json(manifest_path.read_bytes())
        exact(manifest_document["schema"], "inf037b-s3-archive-manifest-v1", "transfer:s3_manifest")
        manifest = _validate_facts(
            manifest_document["manifest"],
            max_total_bytes=self.max_total_bytes,
            max_objects=self.max_objects,
        )
        exact(sha(encode(manifest)), receipt["manifest_sha256"], "transfer:s3_manifest_hash")
        exact(set(receipt["objects"]), set(manifest), "transfer:s3_receipt_inventory")
        result = {}
        for key, facts in manifest.items():
            ack = receipt["objects"][key]
            exact(ack["bytes"], facts["bytes"], "transfer:s3_receipt_length")
            exact(ack["sha256"], facts["sha256"], "transfer:s3_receipt_hash")
            result[key] = self._get_file(ack, safe_file(destination, key), facts)
        _restore_export_archive_directories(result)
        return result


def retrieve_posix_artifacts(manifest, destination):
    """Copy a durable POSIX object manifest to a clean retrieval directory."""
    require(isinstance(manifest, dict) and manifest, "transfer:posix_manifest")
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    result = {}
    for key, facts in manifest.items():
        _safe_key(key)
        exact(set(facts), {"path", "bytes", "sha256"}, "transfer:posix_manifest")
        source = Path(facts["path"])
        require(source.is_file() and not source.is_symlink(), "transfer:posix_source")
        target = safe_file(destination, key)
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(target.name + ".pending-" + uuid.uuid4().hex)
        try:
            digest, size = hashlib.sha256(), 0
            with source.open("rb") as reader, temporary.open("xb") as writer:
                while chunk := reader.read(1024 * 1024):
                    size += len(chunk)
                    digest.update(chunk)
                    exact(writer.write(chunk), len(chunk), "transfer:posix_short_write")
                writer.flush()
                os.fsync(writer.fileno())
            exact(
                {"bytes": size, "sha256": digest.hexdigest()},
                {"bytes": facts["bytes"], "sha256": facts["sha256"]},
                "transfer:posix_hash_length",
            )
            os.replace(temporary, target)
            sync_directory(target.parent)
        finally:
            if temporary.exists():
                temporary.unlink()
                sync_directory(temporary.parent)
        result[key] = target
    _restore_export_archive_directories(result)
    return result


def persist_to_both(
    *,
    recovery_store,
    s3_store,
    artifacts,
    max_total_bytes,
    max_objects,
    recovery_readback,
    s3_readback,
):
    """Persist and retrieve the exact artifact set from both required stores."""
    require(recovery_store is not None and s3_store is not None, "transfer:both_stores_required")
    require(str(recovery_store.path.resolve()) != s3_store.bucket, "transfer:distinct_stores")
    source_manifest = _artifact_facts(
        artifacts, max_total_bytes=max_total_bytes, max_objects=max_objects
    )
    from .inf037b_setup import persist_archive_artifacts

    posix_manifest = persist_archive_artifacts(recovery_store, artifacts)
    s3_receipt = persist_archive_artifacts(s3_store, artifacts)
    posix_files = retrieve_posix_artifacts(posix_manifest, recovery_readback)
    s3_files = s3_store.retrieve_archive_artifacts(s3_receipt, s3_readback)
    for manifest in (posix_files, s3_files):
        exact(set(manifest), set(source_manifest), "transfer:store_inventory")
        for key, path in manifest.items():
            exact(file_facts(path), source_manifest[key], "transfer:store_hash_length")
    return {
        "source_manifest_sha256": sha(encode(source_manifest)),
        "recovery": {"manifest": posix_manifest, "readback": posix_files},
        "s3": {"receipt": s3_receipt, "readback": s3_files},
    }
