"""Durable owner for real collector transports, under the ProcessCalls fence.

The secured wire spool is separate from the normalized/sanitized archive.
It contains response bytes, never request credentials. A deployment must export
both inventories. No reconnect, relist or new owner clears a loss or retries an
interrupted capture operation.
"""

import copy
import http.client
import ipaddress
import math
import os
import socket
import ssl
import threading
import time
from collections import OrderedDict
from concurrent.futures import FIRST_EXCEPTION, ThreadPoolExecutor, wait
from pathlib import Path
from urllib.parse import urlsplit

from .inf037b_archive import Archive, IntegrityError, encode, file_facts, sha, strict_json
from .inf037b_bounded import bounded_json
from .inf037b_capture_inventory import (
    POD_RETAINERS,
    validate_capture_budgets,
    validate_source_inventory,
    wire_files,
    wire_index_record,
)
from .inf037b_command import require_group_leader
from .inf037b_contract import REGISTRATION_ID, SOURCE_KINDS
from .inf037b_durable_ports import sync_directory
from .inf037b_export_runtime import active_batch
from .inf037b_live import ClockAdapter, LiveRows, WatchCutoff
from .inf037b_producer_contracts import WatchBudget, guarded_response, validate_kube_identities
from .inf037b_producer_limits import refuse
from .inf037b_resolver import exact, require
from .inf037b_sources import validate_payload
from .inf037b_stream import StreamingArchiveWriter
from .inf037b_wire_units import UnitReads

# Settlement only, never extra collection time. Counts against the caller's
# capture-command budget, together with close/seal/hash and descriptor write.
WORKER_GRACE_SECONDS = 0.5


def wire_records(directory):
    """Verify legacy reads or protocol units, retaining physical raw order.

    Unit spans may interleave on a shared source. Expose the same logical
    contiguous offset contract to existing consumers, and keep physical_spans
    explicitly; validate the complete physical partition and every unit hash.
    Index rows themselves remain reservation/sequence ordered by the writer.
    """
    for index in sorted(Path(directory).glob("*.jsonl")):
        logical_offset, physical = 0, []
        with index.open("rb") as entries, index.with_suffix(".bin").open("rb") as raw:
            for line in entries:
                require(line.endswith(b"\n"), "capture:torn_wire_index")
                record = strict_json(line)
                require(
                    type(record["length"]) is int and record["length"] >= 0, "capture:wire_length"
                )
                if "physical_spans" not in record:
                    exact(record["offset"], logical_offset, "capture:wire_offset")
                spans = record.get("physical_spans", [[record["offset"], record["length"]]])
                require(type(spans) is list, "capture:wire_spans")
                pieces = []
                for span in spans:
                    require(
                        type(span) is list
                        and len(span) == 2
                        and all(type(n) is int and n >= 0 for n in span),
                        "capture:wire_spans",
                    )
                    at, size = span
                    if size:
                        raw.seek(at)
                        piece = raw.read(size)
                        exact(len(piece), size, "capture:wire_length")
                        pieces.append(piece)
                        physical.append((at, size))
                body = b"".join(pieces)
                exact(len(body), record["length"], "capture:wire_length")
                exact(sha(body), record["sha256"], "capture:wire_hash")
                if "physical_spans" in record:
                    require(
                        type(record.get("read_count")) is int and 0 <= record["read_count"] < 2**63,
                        "capture:wire_read_count",
                    )
                else:
                    # Legacy data has exactly its original offset/length rule.
                    exact(record["offset"], logical_offset, "capture:wire_offset")
                record["offset"] = logical_offset
                logical_offset += len(body)
                yield record, body
            cursor = 0
            for at, size in sorted(physical):
                exact(at, cursor, "capture:wire_partition")
                cursor += size
            raw.seek(0, 2)
            exact(raw.tell(), cursor, "capture:unindexed_wire_bytes")


class DeadlineHTTP:
    """One absolute deadline, TLS verification, bounded reads, no redirects/retry."""

    def __init__(
        self, base, *, stop_ns, retain, token=None, ca=None, local_test=False, internal=False
    ):
        url = urlsplit(base)
        private = False
        if internal and url.hostname:
            try:
                private = ipaddress.ip_address(url.hostname).is_private
            except ValueError:
                private = url.hostname.endswith((".svc", ".svc.cluster.local"))
        require(
            url.scheme == "https"
            or (url.scheme == "http" and internal and private)
            or (local_test and url.scheme == "http" and url.hostname in {"127.0.0.1", "localhost"}),
            "capture:tls",
        )
        require(
            not url.username and not url.password and not url.query and not url.fragment,
            "capture:endpoint",
        )
        require(url.path in {"", "/"}, "capture:endpoint_path")
        self.url, self.stop_ns, self.retain, self.token = url, stop_ns, retain, token
        self.context = ssl.create_default_context(cafile=ca)
        self.cutoff_event, self.socket_lock = threading.Event(), threading.Lock()
        self.socket = None
        self.barrier = getattr(retain, "barrier", lambda: None)
        self.complete = getattr(retain, "complete", lambda *args: None)
        self.producer_reject = lambda reason: refuse(
            self.retain, reason, time.monotonic_ns(), time.monotonic_ns()
        )
        self.watch_budget = WatchBudget(
            stop_ns=stop_ns,
            reject=self.producer_reject,
            state=getattr(retain, "producer_state", None),
        )

    def remaining(self, *, watch=False, cutoff=False):
        remaining = (self.stop_ns - time.monotonic_ns()) / 1e9
        if cutoff and remaining <= 0:
            raise WatchCutoff()
        require(remaining > 0, "capture:deadline")
        return remaining if watch else min(1.0, remaining)

    def cutoff(self):
        require(time.monotonic_ns() >= self.stop_ns, "capture:early_cutoff")
        self.cutoff_event.set()
        with self.socket_lock:
            if self.socket is not None:
                try:
                    self.socket.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass  # Worker owns classification and connection.close().

    def read(self, callback, *, watch):
        # Header and body reads share the same cause rule. Predicate/storage
        # exceptions outside a socket read never become an orderly cutoff.
        try:
            return callback()
        except Exception as exc:
            if watch and (
                self.cutoff_event.is_set()
                or (isinstance(exc, TimeoutError) and time.monotonic_ns() >= self.stop_ns)
            ):
                raise WatchCutoff(str(exc)) from exc
            raise

    def chunks(self, path, *, limit, watch=False, unit_retainer=None):
        retain = unit_retainer or UnitReads(self.retain, mode="watch_line" if watch else "body")
        require(path.startswith("/") and not path.startswith("//"), "capture:request_path")
        start, total = time.monotonic_ns(), 0
        if watch:
            self.watch_bytes = 0
        connection = None
        try:
            cls = (
                http.client.HTTPSConnection
                if self.url.scheme == "https"
                else http.client.HTTPConnection
            )
            kwargs = {"context": self.context} if self.url.scheme == "https" else {}
            connection = cls(
                self.url.hostname, self.url.port, timeout=self.remaining(watch=watch), **kwargs
            )
            connection.response_class = guarded_response(retain, time.monotonic_ns, client=False)
            headers = {"Authorization": "Bearer " + self.token()} if self.token else {}
            connection.request("GET", path, headers=headers)
            sock = connection.sock
            with self.socket_lock:
                self.socket = sock
            response = self.read(connection.getresponse, watch=watch)
            metadata = {
                "path": path,
                "status": response.status,
                "headers": list(response.getheaders()),
            }
            retain(start, time.monotonic_ns(), b"", metadata)
            self.status = response.status
            yield b"", dict(response.getheaders())
            while True:
                if response.isclosed():
                    if watch and self.cutoff_event.is_set():
                        raise WatchCutoff("EOF")
                    require(response.length in (None, 0), "capture:truncated_response")
                    return
                if watch and time.monotonic_ns() >= self.stop_ns:
                    raise WatchCutoff()
                sock.settimeout(self.remaining(watch=watch, cutoff=watch))
                before = time.monotonic_ns()
                length = min(65536, limit - total + 1)
                chunk = self.read(lambda length=length: response.read1(length), watch=watch)
                after = time.monotonic_ns()
                retain(before, after, chunk, {"path": path})
                if watch:
                    self.watch_bytes += len(chunk)
                if watch and (self.cutoff_event.is_set() or (chunk and after >= self.stop_ns)):
                    raise WatchCutoff()
                require(after <= self.stop_ns, "capture:deadline")
                total += len(chunk)
                require(total <= limit, "capture:response_limit")
                if not chunk:
                    require(response.length in (None, 0), "capture:truncated_response")
                    return
                yield chunk, dict(response.getheaders())
        except WatchCutoff:
            raise
        except Exception as exc:
            retain(start, time.monotonic_ns(), b"", {"path": path, "error": str(exc)})
            raise
        finally:
            retain.finish("close" if watch else "body")
            if connection:
                connection.close()
            with self.socket_lock:
                self.socket = None

    def get(self, path):
        body, headers = bytearray(), {}
        try:
            for chunk, response_headers in self.chunks(path, limit=8_388_608):
                body.extend(chunk)
                headers = response_headers
        finally:
            self.barrier()  # Complete response/partial bytes durable before normalization.
        if self.status != 200:
            self.retain(
                time.monotonic_ns(), time.monotonic_ns(), b"", {"error": "capture:http_status"}
            )
            self.barrier()
            require(False, "capture:http_status")
        data = bytes(body)
        if path.startswith(("/api/", "/apis/")):
            validate_kube_identities(strict_json(data), self.producer_reject)
        return data, headers

    def lines(self, path, *, max_line=1_048_576):
        pending = bytearray()
        retain = UnitReads(self.retain, mode="watch_line")
        # Watch lifetime is bounded by stop_ns; total bytes are not a line limit.
        start = time.monotonic_ns()
        try:
            self.watch_budget.connect()
            for chunk, _ in self.chunks(path, limit=2**63 - 1, watch=True, unit_retainer=retain):
                self.barrier()  # One read batch, before any event predicate.
                require(self.status == 200, "capture:http_status")
                pending.extend(chunk)
                while (newline := pending.find(b"\n")) >= 0:
                    require(newline + 1 <= max_line, "capture:line_limit")
                    line = bytes(pending[: newline + 1])
                    del pending[: newline + 1]
                    retain.line(len(line))
                    self.barrier()
                    self.watch_budget.event(strict_json(line))
                    yield line
                    self.complete(start, time.monotonic_ns(), b"", {"watch_batch": True})
                require(len(pending) <= max_line, "capture:line_limit")
            require(not pending, "capture:torn_line")
        except WatchCutoff:
            self.barrier()
            raise
        except Exception as exc:
            self.retain(start, time.monotonic_ns(), b"", {"path": path, "error": str(exc)})
            self.barrier()
            raise


class CaptureOwner:
    """Single durable capture intent joined to an accepted Port operation store.

    sources maps transport names to allowed normalized (kind, identity,
    generation) triples. The map and accepted operation are immutable pins.
    The ProcessCalls parent remains responsible for a stuck worker/process.
    """

    def __init__(
        self,
        *,
        store,
        operation_store,
        operation,
        binding,
        root,
        sources,
        attempt,
        stages,
        boot_path=Path("/proc/sys/kernel/random/boot_id"),
    ):
        require(not active_batch(), "capture:export_context_at_open")
        self.store, self.operation_store = store, operation_store
        self.operation, self.binding = copy.deepcopy(operation), copy.deepcopy(binding)
        self.label = sha(encode([operation["operation"], operation["key"]]))
        self.root, self.sources = Path(root), copy.deepcopy(sources)
        require(bool(sources) and all(sources.values()), "capture:sources")
        if "capture_inventory" in self.binding:
            validate_source_inventory(self.sources, self.binding["capture_inventory"])
        if "capture_budgets" in self.binding:
            validate_capture_budgets(self.sources, self.binding["capture_budgets"])
        triples = [tuple(triple) for values in sources.values() for triple in values]
        require(
            all(
                len(t) == 3 and t[0] in SOURCE_KINDS and all(type(v) is str and bool(v) for v in t)
                for t in triples
            )
            and len(triples) == len(set(triples)),
            "capture:source_inventory",
        )
        require(
            (attempt == "setup" or (type(attempt) is int and attempt in (1, 2, 3)))
            and bool(stages)
            and all(type(s) is int and s in range(1, 6) for s in stages),
            "capture:scope",
        )
        self.attempt, self.stages, self.boot_path = attempt, list(stages), Path(boot_path)
        self.boot = self.boot_path.read_text().strip()
        require(bool(self.boot), "capture:boot")
        exact(
            operation["body"]["capture"],
            {"sources": sources, "attempt": attempt, "stages": stages, "boot_id": self.boot},
            "capture:operation_scope",
        )
        self.lock, self.failed, self.closed = threading.RLock(), False, False
        self.io_lock = threading.RLock()
        self.client_completions = []
        self.group_tick_intervals_ms = []
        self.sequence, self.clock_rows, self.builders = 0, [], {}
        self.lineage_admissions, self.slot_generations = {}, {}
        self.operation_sha256 = sha(encode(self.operation))
        self.wire, self.fsync_count, self.barrier_count = {}, 0, 0
        self.join()
        with self.store.lock():
            state = self.store.read()
            require("capture" not in state, "capture:interrupted_no_retry")
            state["capture"] = {
                "binding": binding,
                "operation": operation,
                "sources": sources,
                "boot_id": self.boot,
                "attempt": attempt,
                "stages": stages,
            }
            self.store.write(state)
        self.root.mkdir(mode=0o700, exist_ok=False)
        sync_directory(self.root.parent)
        (self.root / "wire").mkdir(mode=0o700)
        self._open_wire_sources()
        sync_directory(self.root / "wire")
        sync_directory(self.root)
        self.archive = Archive.create(
            self.root / "archive", {"registration_id": REGISTRATION_ID, "pins": binding["pins"]}
        )
        self.archive_pending, self.archive_directories = set(), set()
        self.archive_directory_barrier()
        sync_directory(self.root)
        self.writer = StreamingArchiveWriter(self.archive.root, append_write=self.archive_write)

    def _open_wire_sources(self):
        inventory = self.binding.get("capture_inventory")
        if inventory is not None:
            validate_source_inventory(self.sources, inventory)
        for source, files in wire_files(self.sources).items():
            self.wire[source] = {
                "data": (self.root / files["data"]).open("x+b"),
                "index": (self.root / files["index"]).open("x+b"),
                "offset": 0,
                "index_bytes": 0,
                "records": 0,
                "pending": [],
                "index_pending": [],
                "barriers": 0,
            }

    def archive_directory_barrier(self):
        with self.lock:
            directories = [
                self.archive.root,
                *(p for p in self.archive.root.rglob("*") if p.is_dir()),
            ]
        for path in sorted(directories, key=lambda p: -len(p.parts)):
            sync_directory(path)

    def archive_write(self, path, data, mode):
        # Explicit capture ownership: never register appends with the export
        # runtime's ContextVar, including when a caller has an export batch.
        with self.lock:
            created = not path.exists()
            self.archive_pending.add(path)
            if created:
                self.archive_directories.add(path.parent)
            with path.open(mode) as stream:
                exact(stream.write(data), len(data), "capture:archive_short_write")
                stream.flush()

    def archive_barrier(self):
        with self.io_lock:
            with self.lock:
                paths, directories = self.archive_pending, self.archive_directories
                self.archive_pending, self.archive_directories = set(), set()
            for path in sorted(paths):
                with path.open("rb") as stream:
                    os.fsync(stream.fileno())
            for path in sorted(directories):
                sync_directory(path)

    def complete(self, source, start, end, body, metadata):
        with self.io_lock:
            self.archive_barrier()
            self.retain(source, start, end, body, metadata)
            self.barrier(source)

    def client_complete(self, source, *args):
        with self.lock:
            self.client_completions.append((source, args))

    def group_barrier(self):
        with self.io_lock:
            # Take the completion watermark BEFORE the archive watermark.
            # Concurrent new completions belong to the following tick.
            with self.lock:
                completions, self.client_completions = self.client_completions, []
            first_error = None
            try:
                self.archive_barrier()
            except Exception as error:
                first_error = error
            for source, args in completions:
                try:
                    self.retain(source, *args)
                except Exception as error:
                    if first_error is None:
                        first_error = error
            for source in self.sources:
                try:
                    self.barrier(source)
                except Exception as error:
                    if first_error is None:
                        first_error = error
            if first_error is not None:
                raise first_error

    def join(self):
        with self.operation_store.lock():
            operation = self.operation_store.read()["operations"][self.label]
            generation = self.generation()
            exact(operation, self.operation, "capture:operation_store")
            exact(operation["body"]["binding"], self.binding, "capture:binding")
            self.operation_generation = generation

    def generation(self):
        stat = (self.operation_store.path / "state.json").stat()
        return stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns

    def join_current(self):
        # DurableStore atomically replaces its snapshot. Under the existing
        # single-writer/OS-lock authority, unchanged generation reuses the joined
        # envelope hash; external change-and-restore is not an authority model.
        with self.lock:
            with self.operation_store.lock():
                if self.generation() == self.operation_generation:
                    return
            self.join()

    def retainer(self, source, *, uid=None, process_generation=None):
        """Bind each pod adapter to its identities without changing wire stamps.

        Owner markers are private to owner call sites, never adapter input.
        This binds transport identity; only the owner's Kubernetes sink can
        admit a UID for normalized slot rows.
        """
        if uid is not None or process_generation is not None:
            require(
                source in POD_RETAINERS
                and all(type(v) is str and v for v in (uid, process_generation)),
                "capture:pod_retainer_identity",
            )

        def arguments(start, end, body, metadata):
            require(metadata.get("owner_record") is not True, "capture:adapter_owner_record")
            metadata = dict(metadata)
            if uid is not None:
                for key, value in (("uid", uid), ("process_generation", process_generation)):
                    require(
                        key not in metadata or metadata[key] == value,
                        "capture:pod_retainer_identity",
                    )
                    metadata[key] = value
            return start, end, body, metadata

        def retain(*args):
            self.retain(source, *arguments(*args))

        retain.loss = lambda reason: self.loss(source + ":" + reason)
        with self.lock:
            if not hasattr(self, "producer_states"):
                self.producer_states = {}
            retain.producer_state = self.producer_states.setdefault(source, {})
        retain.remaining_raw_bytes = lambda: (
            self.binding["capture_budgets"][source]["raw_bytes"] - self.wire[source]["offset"]
            if "capture_budgets" in self.binding
            else 8_388_608
        )
        retain.barrier = lambda: self.barrier(source)
        retain.complete = lambda *args: self.complete(source, *arguments(*args))
        retain.client_complete = lambda *args: self.client_complete(source, *arguments(*args))
        retain.supports_units = True
        retain.unit_begin = lambda metadata, close: self.unit_begin(
            source, arguments(0, 0, b"", metadata)[3], close
        )
        retain.unit_read = lambda a, b, data, metadata: self.unit_read(
            source, *arguments(a, b, data, metadata)
        )
        retain.unit_finish = lambda token, a, b, data, spans, metadata: self.unit_finish(
            source, token, a, b, data, spans, arguments(a, b, data, metadata)[3]
        )
        return retain

    def loss(self, reason):
        with self.lock:
            self.failed = True
        with self.io_lock:
            try:
                self.group_barrier()
            finally:
                # A deferred completion can itself overflow. Preserve this
                # loss even if settling that completion raises another loss.
                with self.store.lock():
                    state = self.store.read()
                    state["capture"].setdefault("losses", []).append(str(reason))
                    self.store.write(state)

    def retain(self, source, start, end, body, metadata):
        violation = None
        with self.lock:
            require(not self.closed and source in self.sources, "capture:source")
            if source in POD_RETAINERS and metadata.get("owner_record") is not True:
                require(
                    type(metadata) is dict
                    and all(
                        type(metadata.get(key)) is str and metadata[key]
                        for key in ("uid", "process_generation")
                    ),
                    "capture:pod_metadata:" + source,
                )
            segment = self.wire[source]
            offset = segment["offset"]
            digest = sha(body)
            record = wire_index_record(
                source=source,
                operation_sha256=self.operation_sha256,
                start_ns=start,
                end_ns=end,
                sequence=self.sequence,
                offset=offset,
                length=len(body),
                sha256=digest,
                metadata=metadata,
            )
            if "unit_queue" in segment or "read_count" in metadata:
                value = strict_json(record)
                value.update(
                    physical_spans=[[offset, len(body)]] if body else [],
                    read_count=metadata.get("read_count", 0 if metadata.get("owner_record") else 1),
                )
                record = encode(value)
            budgets = self.binding.get("capture_budgets")
            if budgets is not None:
                require(
                    all(type(t) is int and -(2**63) <= t < 2**63 for t in (start, end)),
                    "capture:timestamp_int64",
                )
                totals = {
                    "raw": offset + len(body),
                    "index": segment["index_bytes"] + len(record),
                    "records": segment["records"] + 1,
                }
                for kind, key in (
                    ("raw", "raw_bytes"),
                    ("index", "index_bytes"),
                    ("records", "records"),
                ):
                    if totals[kind] > budgets[source][key]:
                        violation = "capture:budget:" + source + ":" + kind
                        break
            if violation is None:
                self._write_wire(segment, body, record, offset, digest)
                if source in POD_RETAINERS and metadata.get("owner_record") is not True:
                    if not hasattr(self, "slot_generations"):
                        self.slot_generations = {}
                    self.slot_generations.setdefault((source, metadata["uid"]), set()).add(
                        metadata["process_generation"]
                    )
        # Do not acquire io_lock through loss while holding the append lock.
        if violation is not None:
            self.loss(violation)
            require(False, violation)
        if metadata.get("error"):
            self.loss(source + ":" + metadata["error"])

    def unit_begin(self, source, metadata, close):
        with self.lock:
            require(not self.closed and source in self.sources, "capture:source")
            if source in POD_RETAINERS:
                require(
                    all(
                        type(metadata.get(k)) is str and metadata[k]
                        for k in ("uid", "process_generation")
                    ),
                    "capture:pod_metadata:" + source,
                )
            segment = self.wire[source]
            budget = self.binding.get("capture_budgets", {}).get(source)
            if budget is not None and segment["records"] >= budget["records"]:
                violation = "capture:budget:" + source + ":records"
            else:
                sequence = self.sequence
                self.sequence += 1
                segment["records"] += 1
                segment.setdefault("unit_queue", OrderedDict())[sequence] = None
                segment.setdefault("unit_closers", {})[sequence] = close
                return sequence
        self.loss(violation)
        require(False, violation)

    def unit_read(self, source, start, end, body, metadata):
        violation = None
        with self.lock:
            require(not self.closed, "capture:closed")
            segment = self.wire[source]
            offset = segment["offset"]
            budget = self.binding.get("capture_budgets", {}).get(source)
            if budget is not None and offset + len(body) > budget["raw_bytes"]:
                violation = "capture:budget:" + source + ":raw"
            else:
                exact(segment["data"].write(body), len(body), "capture:wire_short_write")
                segment["offset"] += len(body)
                segment["pending"].append((offset, len(body), sha(body)))
                if source in POD_RETAINERS:
                    if not hasattr(self, "slot_generations"):
                        self.slot_generations = {}
                    self.slot_generations.setdefault((source, metadata["uid"]), set()).add(
                        metadata["process_generation"]
                    )
        if violation:
            self.loss(violation)
            require(False, violation)
        return offset

    def unit_finish(self, source, token, start, end, body, spans, metadata):
        violation = None
        with self.lock:
            segment = self.wire[source]
            require(token in segment["unit_closers"], "capture:unit_token")
            value = strict_json(
                wire_index_record(
                    source=source,
                    operation_sha256=self.operation_sha256,
                    start_ns=start,
                    end_ns=end,
                    sequence=token,
                    offset=spans[0][0] if spans else segment["offset"],
                    length=len(body),
                    sha256=sha(body),
                    metadata=metadata,
                )
            )
            value.update(physical_spans=spans, read_count=metadata["read_count"])
            budget = self.binding.get("capture_budgets", {}).get(source)
            try:
                record = (
                    encode(value)
                    if budget is None
                    else bounded_json(
                        value,
                        limit=budget["index_bytes"] - segment["index_bytes"],
                        loss=lambda reason: None,
                    )
                )
            except IntegrityError:
                violation = "capture:budget:" + source + ":index"
            if violation is None:
                segment["index_bytes"] += len(record)
                segment["unit_queue"][token] = record
                del segment["unit_closers"][token]
                self._flush_unit_queue(segment)
        if violation:
            self.loss(violation)
            require(False, violation)

    def _flush_unit_queue(self, segment):
        queue = segment["unit_queue"]
        while queue and next(iter(queue.values())) is not None:
            _, record = queue.popitem(last=False)
            index_offset = segment["index"].tell()
            exact(segment["index"].write(record), len(record), "capture:index_short_write")
            segment["index_pending"].append((index_offset, len(record), sha(record)))
            # A completed index may follow an already durable raw read batch.
            segment["pending"].append((segment["offset"], 0, sha(b"")))

    def _write_wire(self, segment, body, record, offset, digest):
        """Called only by retain, with its lock held and budget already checked."""
        exact(segment["data"].write(body), len(body), "capture:wire_short_write")
        index_offset = segment["index"].tell()
        if "unit_queue" in segment:
            segment["unit_queue"][self.sequence] = record
            self._flush_unit_queue(segment)
        else:
            exact(segment["index"].write(record), len(record), "capture:index_short_write")
            segment["index_pending"].append((index_offset, len(record), sha(record)))
        segment["offset"] += len(body)
        segment["index_bytes"] += len(record)
        segment["records"] += 1
        segment["pending"].append((offset, len(body), digest))
        self.sequence += 1

    def barrier(self, source):
        with self.io_lock:
            with self.lock:
                segment = self.wire[source]
                if not segment["pending"]:
                    return
                snapshot = []
                for key, pending in (("data", "pending"), ("index", "index_pending")):
                    stream = segment[key]
                    stream.flush()
                    snapshot.append((stream.name, segment[pending]))
                    segment[pending] = []
            # Verify only the new raw spans, not the whole growing segment.
            # Independent read handles never move an appending writer's offset.
            for path, spans in snapshot:
                with open(path, "rb") as stream:
                    os.fsync(stream.fileno())
                    self.fsync_count += 1
                    for offset, length, digest in spans:
                        stream.seek(offset)
                        exact(sha(stream.read(length)), digest, "capture:wire_readback")
            self.barrier_count += 1
            segment["barriers"] += 1

    def slot_lineage(self, source, row):
        """Decision 6: static triples alone cannot admit a slot UID."""
        physical = source
        if source == "kubernetes" and row["source_kind"] == "vllm":
            # NodeLifecycleAdapter uses the accepted shared Kubernetes row
            # stream; its wire provenance still belongs to the slot retainer.
            physical = "lifecycle:slot" + str(row["payload"].get("slot"))
        if (
            physical not in POD_RETAINERS
            or not physical.endswith(("slot0", "slot1"))
            or row["source_kind"] != "vllm"
        ):
            return False
        payload = row["payload"]
        uid, slot = payload.get("pod_uid"), int(physical[-1])
        require(
            type(uid) is str
            and bool(uid)
            and row["source_identity"] == "vllm:" + uid
            and type(payload.get("slot")) is int
            and payload.get("slot") == slot
            and getattr(self, "lineage_admissions", {}).get(uid, {}).get("slot") == slot,
            "capture:lineage:uid_unadmitted",
        )
        triple = [row[k] for k in ("source_kind", "source_identity", "source_generation")]
        require(
            triple in self.sources[source]
            or row["source_generation"]
            in getattr(self, "slot_generations", {}).get((physical, uid), set()),
            "capture:lineage:generation_unbound",
        )
        return True

    def record_admission(self, row):
        """Only called after this owner's authoritative Kubernetes row appends.

        The immutable physical source inventory stays unchanged. Admissions
        consume that source's wire/index budgets and survive in its descriptor.
        No other owner's row or a native adapter can invoke this sink path.
        """
        payload = row["payload"]
        uid, slot = payload.get("pod_uid"), payload.get("slot")
        require(
            type(uid) is str and uid and type(slot) is int and slot in (0, 1),
            "capture:lineage:observation",
        )
        admission = {
            "uid": uid,
            "slot": slot,
            "record_id": row["record_id"],
            "row_sha256": sha(encode(row)),
        }
        with self.io_lock:
            previous = getattr(self, "lineage_admissions", {}).get(uid)
            if previous is not None:
                exact(previous["slot"], slot, "capture:lineage:slot_changed")
                return
            self.retain(
                "kubernetes",
                row["capture_start_mono_ns"],
                row["capture_end_mono_ns"],
                encode(admission),
                {"owner_record": True, "event": "lineage_admission"},
            )
            with self.store.lock():
                state = self.store.read()
                state["capture"].setdefault("lineage_admissions", []).append(admission)
                self.store.write(state)
            with self.lock:
                if not hasattr(self, "lineage_admissions"):
                    self.lineage_admissions = {}
                self.lineage_admissions[uid] = admission

    def rows(self, source):
        require(source in self.sources, "capture:source")
        if source in self.builders:
            return self.builders[source]

        def sink(row):
            original = row
            appended = False
            try:
                with self.lock:
                    self.join_current()
                    exact(self.boot_path.read_text().strip(), self.boot, "capture:boot_changed")
                    triple = [
                        row[k] for k in ("source_kind", "source_identity", "source_generation")
                    ]
                    slot_lineage = self.slot_lineage(source, row)
                    require(slot_lineage or triple in self.sources[source], "capture:lineage")
                    row = copy.deepcopy(row)
                    row["stage"] = self.stages
                    validate_payload(row)
                    self.writer.append("raw/" + row["source_kind"] + ".jsonl", row)
                    appended = True
                    if row["source_kind"] == "clocks":
                        self.clock_rows.append(row)
                if (
                    source == "kubernetes"
                    and row["source_kind"] == "kubernetes"
                    and row["source_identity"] == "kubernetes"
                    and row["error"] is None
                    and row["payload"]["event"]
                    in ("pod_created", "scheduled", "container_state", "ready")
                ):
                    self.record_admission(row)
                if row["error"]:
                    self.loss(source + ":" + row["error"])
            except Exception as exc:
                try:
                    if not appended:
                        self.retain(
                            source,
                            row["capture_start_mono_ns"],
                            row["capture_end_mono_ns"],
                            encode(original),
                            {"owner_record": True, "normalized": True, "rejected": True},
                        )
                finally:
                    self.loss(source + ":" + str(exc))
                raise

        self.builders[source] = LiveRows(
            self.binding["session_id"],
            self.boot,
            attempt=self.attempt,
            sink=sink,
            on_loss=lambda: self.loss(source + ":adapter_loss"),
        )
        if not hasattr(self, "normalized_sequence"):
            self.normalized_sequence, self.normalized_sequence_lock = {}, threading.RLock()
        # Native, metrics and lifecycle may share one normalized UID/generation
        # while keeping separate bounded wire sources. Keep one sequence grid.
        self.builders[source].sequence = self.normalized_sequence
        self.builders[source].lock = self.normalized_sequence_lock
        return self.builders[source]

    def local_clock(self, rows):
        start = time.monotonic_ns()
        boot = self.boot_path.read_text().strip()
        if boot != self.boot:
            self.loss("capture:boot_changed")
            require(False, "capture:boot_changed")
        return ClockAdapter(rows).mapping(
            "measurement", boot, start // 1_000_000, start, time.monotonic_ns()
        )

    def periodic(self, name, collect, *, period_ms, stop_ns, stop_event, start_ns=None):
        require(type(period_ms) is int and 0 < period_ms <= 1000, "capture:cadence")
        next_ns = time.monotonic_ns() if start_ns is None else start_ns
        require(type(next_ns) is int and next_ns >= 0, "capture:schedule_origin")
        try:
            while not stop_event.is_set() and next_ns + period_ms * 1_000_000 <= stop_ns:
                delay = next_ns - time.monotonic_ns()
                if delay > 0 and stop_event.wait(delay / 1e9):
                    break
                start = time.monotonic_ns()
                require(start - next_ns < period_ms * 1_000_000, "capture:missed_slot")
                self.join_current()
                collect()
                end = time.monotonic_ns()
                self.complete(
                    name,
                    start,
                    end,
                    b"",
                    {"owner_record": True, "scheduled_ns": next_ns, "period_ms": period_ms},
                )
                require(not self.failed, "capture:adapter_failed")
                settled_ns = time.monotonic_ns()
                require(settled_ns <= stop_ns, "capture:deadline")
                require(settled_ns - next_ns < period_ms * 1_000_000, "capture:missed_slot")
                next_ns += period_ms * 1_000_000
        except Exception as exc:
            try:
                self.retain(
                    name,
                    start,
                    time.monotonic_ns(),
                    b"",
                    {
                        "owner_record": True,
                        "scheduled_ns": next_ns,
                        "error": str(exc),
                        "missed_slot": True,
                    },
                )
            finally:
                try:
                    self.loss(name + ":" + str(exc))
                finally:
                    stop_event.set()
            raise
        finally:
            # If the response barrier preceded normalization, its completion
            # metadata rides the next batch; settle the final tail here.
            self.barrier(name)

    def watch(self, name, adapter, resource_version):
        start = time.monotonic_ns()
        try:
            for _ in adapter.watch_pods(resource_version):
                pass  # LiveRows sink owns each row; never append it twice.
        except WatchCutoff as exc:
            require(time.monotonic_ns() >= adapter.http.stop_ns, "capture:early_cutoff")
            self.complete(
                name,
                start,
                time.monotonic_ns(),
                b"",
                {
                    "owner_record": True,
                    "end": "cutoff",
                    "cutoff_exception": str(exc),
                    "stop_ns": adapter.http.stop_ns,
                    "bytes": adapter.http.watch_bytes,
                    "last_resource_version": adapter.last_resource_version,
                },
            )
            return
        except Exception as exc:
            self.loss(name + ":" + str(exc))
            raise
        self.loss(name + ":watch_disconnected")

    def action(self, name, collect, *, stop_ns):
        start = time.monotonic_ns()
        try:
            self.join_current()
            collect()
            self.complete(
                name,
                start,
                time.monotonic_ns(),
                b"",
                {"owner_record": True, "action_completed": True},
            )
            require(
                time.monotonic_ns() <= stop_ns and not self.failed, "capture:action_failed_or_late"
            )
        except Exception as exc:
            try:
                self.retain(
                    name, start, time.monotonic_ns(), b"", {"owner_record": True, "error": str(exc)}
                )
            finally:
                self.loss(name + ":" + str(exc))
            raise

    def run(self, *, periodic, watches, stop_ns, actions=None, action_sources=None):
        """Run adapter methods concurrently inside the command's process group.

        All workers share the same absolute cutoff. A failure is durable before
        exiting so ProcessCalls immediately fences descendants, as preparation
        does. No Python future cancellation is claimed to stop network effects.
        """
        require_group_leader()
        actions = actions or {}
        action_sources = action_sources or {name: [name] for name in actions}
        exact(set(action_sources), set(actions), "capture:action_sources")
        require(
            all(
                name in sources and set(sources) <= set(self.sources)
                for name, sources in action_sources.items()
            ),
            "capture:action_sources",
        )
        exact(
            {name for name, _, _ in periodic}
            | set(watches)
            | {source for sources in action_sources.values() for source in sources},
            set(self.sources),
            "capture:task_sources",
        )
        require(stop_ns > time.monotonic_ns(), "capture:deadline")
        for adapter, _ in watches.values():
            exact(adapter.http.stop_ns, stop_ns, "capture:watch_cutoff")
        stop_event = threading.Event()
        pool = ThreadPoolExecutor(max_workers=len(periodic) + len(watches) + len(actions) + 1)
        barrier_stop = threading.Event()
        self.group_tick_intervals_ms = []

        def group_tick():
            try:
                last, tick = time.monotonic_ns(), time.monotonic_ns() + 200_000_000
                while not barrier_stop.wait(max(0, (tick - time.monotonic_ns()) / 1e9)):
                    now = time.monotonic_ns()
                    self.group_tick_intervals_ms.append((now - last) / 1e6)
                    self.group_barrier()
                    last, tick = now, tick + 200_000_000
            except Exception as exc:
                self.loss("capture:group_barrier:" + str(exc))
                raise

        barrier_future = pool.submit(group_tick)
        try:
            futures = [
                pool.submit(
                    self.periodic,
                    name,
                    collect,
                    period_ms=period,
                    stop_ns=stop_ns,
                    stop_event=stop_event,
                )
                for name, period, collect in periodic
            ]

            def watch(name, adapter, version):
                self.watch(name, adapter, version)
                require(not self.failed, "capture:watch_ended")

            futures.extend(pool.submit(watch, name, *args) for name, args in watches.items())

            futures.extend(
                pool.submit(self.action, name, collect, stop_ns=stop_ns)
                for name, collect in actions.items()
            )
            done, pending = wait(
                futures,
                timeout=max(0, (stop_ns - time.monotonic_ns()) / 1e9),
                return_when=FIRST_EXCEPTION,
            )
            failed = any(f.exception() for f in done) or self.failed
            stop_event.set()
            if not failed:
                # Never extend collection. Shut down sockets at the common
                # cutoff, then allow bounded durable end-record settlement.
                for adapter, _ in watches.values():
                    adapter.http.cutoff()
                done, pending = wait(futures, timeout=WORKER_GRACE_SECONDS)
            if pending or any(f.exception() for f in done) or self.failed:
                self.loss("capture:workers_failed_or_unsettled")
                os._exit(76)
                raise ValueError("capture:exit_returned")
            barrier_stop.set()
            barrier_future.result(timeout=WORKER_GRACE_SECONDS)
            return self.close()
        finally:
            barrier_stop.set()
            stop_event.set()
            pool.shutdown(wait=False, cancel_futures=True)

    def close(self):
        require(not active_batch(), "capture:export_context_at_close")
        close_start_ns = time.monotonic_ns()
        with self.io_lock:
            require(not self.closed, "capture:closed")
            self.join()
            if self.boot_path.read_text().strip() != self.boot:
                self.loss("capture:boot_changed")
            for source in self.sources:
                active = list(self.wire[source].get("unit_closers", {}).values())
                for finish in active:
                    finish("refusal")
                if active:
                    self.loss("capture:uncompleted_protocol_unit:" + source)
            self.group_barrier()
            self.writer.close_raw()
            report = self.archive.seal()
            self.archive_directory_barrier()  # New receipt/seal entries precede the closed descriptor.
            if any(r["integrity_errors"] for r in report["segments"].values()):
                self.loss("capture:archive_integrity")
            for source in self.sources:
                self.barrier(source)
                for key in ("data", "index"):
                    self.wire[source][key].close()
            files = {
                p.relative_to(self.root).as_posix(): file_facts(p)
                for p in sorted(self.root.rglob("*"))
                if p.is_file()
            }
            with self.store.lock():
                state = self.store.read()
                state["capture"].update(
                    files=files,
                    archive=report,
                    transport_clean=not self.failed,
                    closed=True,
                    close_start_ns=close_start_ns,
                    inventory_hashed_ns=time.monotonic_ns(),
                    spool_bytes=sum(v["bytes"] for p, v in files.items() if p.startswith("wire/")),
                    spool_files=sum(p.startswith("wire/") for p in files),
                    spool_fsyncs=self.fsync_count,
                    spool_barriers=self.barrier_count,
                    client_group_ticks={
                        "count": len(self.group_tick_intervals_ms),
                        "max_ms": max(self.group_tick_intervals_ms, default=None),
                        "p99_ms": sorted(self.group_tick_intervals_ms)[
                            math.ceil(len(self.group_tick_intervals_ms) * 0.99) - 1
                        ]
                        if self.group_tick_intervals_ms
                        else None,
                        "over_250_ms": sum(v > 250 for v in self.group_tick_intervals_ms),
                    },
                )
                self.store.write(state)
            self.closed = True
            return state["capture"]
