"""Opt-in, source-only vLLM observer helper for the reviewed draft-r18 protocol.

This file is copied verbatim to vllm/v1/engine/stage_c_observer.py by the
overlay builder. It deliberately imports only the standard library. No engine
operation or native event serialization is performed by this helper.
"""

import collections
import hashlib
import importlib.util
import json
import os
import re
import struct
import sys
import threading
import time
from dataclasses import dataclass, replace
from pathlib import Path

CADENCE_NS = 100_000_000
SOURCE_COMMIT = "98dff2a81d747d1dba01a47f939f48c3526d4206"
V2_OUTPUT = "vllm.v1.worker.gpu.async_utils.AsyncOutput"
EXECUTOR = "vllm.v1.executor.uniproc_executor.UniProcExecutor"
MAX_SLOTS = 48_001
MAX_PATCHED_SLOTS = 18_001
MAX_PHYSICAL = 3891
MAX_OWNERS = 128
MAX_LINKS = MAX_OWNERS * 512
MAX_ASSOCIATIONS = 1024
MAX_GENERATED = 128_349
GENERATED_SLOTS = 262_144
GENERATED_ROW = struct.Struct("<32sQQIIQ")
_registrations = []
_observer = None
_process_start = time.monotonic_ns()


def qualified(value):
    cls = value if isinstance(value, type) else type(value)
    return cls.__module__ + "." + cls.__qualname__


def register(instance, function, path):
    """Executed constructors register themselves; file inspection is insufficient."""
    if os.environ.get("STAGE_C_OBSERVER_MANIFEST") and len(_registrations) < 1024:
        _registrations.append((instance, function, path, os.getpid(), _process_start))


def mutation(instance):
    """Called on actual owner/allocator mutation paths in the four-file overlay."""
    if os.environ.get("STAGE_C_OBSERVER_MANIFEST"):
        instance._stage_c_mutations = getattr(instance, "_stage_c_mutations", 0) + 1


def call(method, *args):
    """Observation failure cannot change the native operation's result/exception."""
    observer = _observer
    if observer is None:
        return None
    try:
        return getattr(observer, method)(*args)
    except Exception as exc:
        try:
            observer.fail(type(exc).__name__)
        except Exception:
            pass
        return None


def start(engine, path):
    global _observer
    register(engine, "EngineCore.__init__", path)
    name = os.environ.get("STAGE_C_OBSERVER_MANIFEST")
    if not name:
        return
    # Read immutable startup inputs before measured capture. Startup refusal is
    # explicit; runtime helper errors only invalidate observation.
    manifest = json.loads(Path(name).read_bytes())
    _observer = StageCObserver(engine, manifest)
    # Constructor completion precedes admission. Inspect the actual in-process
    # runner, then retain the per-wait concrete-output check as a runtime guard.
    _observer.admit()
    _observer.worker = threading.Thread(target=_observer.run, name="stage-c-observer", daemon=True)
    _observer.worker.start()


class Refusal(ValueError):
    pass


class NativeDomain:
    """Frozen full-hash membership and bounded, forward-only generated guard.

    Called only by the owner thread. The host replays the same insertion records
    independently. No native object, tokens or salt enters the backing store.
    The taint dictionary is bounded by occupied slots; Python RSS is additional
    to the fixed packed allocation and must be measured in source fitness.
    """

    def __init__(self, frozen, *, limit=MAX_GENERATED, slots=GENERATED_SLOTS):
        if not 0 < limit < slots or slots & (slots - 1):
            raise Refusal("generated_capacity")
        self.frozen = frozen
        self.frozen_keys = {}
        for full, membership in frozen.items():
            raw, key = self.decode(full)
            if type(membership.get("in_W")) is not bool:
                raise Refusal("frozen_membership")
            if key in self.frozen_keys and self.frozen_keys[key] != raw:
                raise Refusal("frozen_collision")
            self.frozen_keys[key] = raw
        self.limit, self.slots = limit, slots
        self.store = bytearray(slots * GENERATED_ROW.size)
        self.count = self.ordinal = 0
        self.collisions = self.aliases = self.refusals = 0
        self.tainted = {}
        self.invalid_since = None

    @staticmethod
    def decode(full):
        raw = bytes.fromhex(full) if isinstance(full, str) else full
        if not isinstance(raw, bytes) or len(raw) != 36 or raw[-4:] != bytes(4):
            raise Refusal("native_encoding")
        return raw[:32], int.from_bytes(raw[:32], "big") & ((1 << 64) - 1)

    def find(self, key):
        position = key & (self.slots - 1)
        for _ in range(self.slots):
            offset = position * GENERATED_ROW.size
            row = GENERATED_ROW.unpack_from(self.store, offset)
            if row[4] == 0 or row[1] == key:
                return offset, row
            position = (position + 1) & (self.slots - 1)
        raise Refusal("generated_load")

    def overflow(self, stamp):
        self.refusals += 1
        if self.invalid_since is None:
            self.invalid_since = stamp
        return "overflow"

    def insertion(self, full, request_index, block_index, prompt_tokens, stamp):
        self.ordinal += 1
        raw, key = self.decode(full)
        full = (raw + bytes(4)).hex()
        if any(
            type(v) is not int or v < 0 for v in (request_index, block_index, prompt_tokens, stamp)
        ):
            raise Refusal("native_provenance")
        if request_index >= 14_261 or block_index >= 512:
            return self.overflow(stamp)
        if block_index < prompt_tokens // 16:
            return "prompt" if full in self.frozen else "unknown"
        if block_index - prompt_tokens // 16 >= 9:
            return self.overflow(stamp)
        offset, previous = self.find(key)
        if previous[4] == 0 and self.count >= self.limit:
            return self.overflow(stamp)
        frozen = self.frozen_keys.get(key)
        collision = (frozen is not None and frozen != raw) or (
            previous[4] != 0 and previous[0] != raw
        )
        alias = previous[4] != 0 and previous[0] == raw
        alias = alias or frozen == raw
        if previous[4] == 0:
            GENERATED_ROW.pack_into(
                self.store, offset, raw, key, request_index, block_index, 1, self.ordinal
            )
            self.count += 1
        if collision:
            self.collisions += 1
            self.tainted.setdefault(key, stamp)
            return "collision"
        if alias:
            self.aliases += 1
            return "alias"
        return "generated"

    def key_valid(self, full, stamp):
        _, key = self.decode(full)
        return (self.invalid_since is None or stamp < self.invalid_since) and (
            key not in self.tainted or stamp < self.tainted[key]
        )

    def unregistered(self, full, stamp):
        """Unknown request taints its key unless it is an identical frozen alias.

        Retaining the full hash also detects a later registered collision after
        this physical block is evicted. Only actual store exhaustion is global.
        """
        self.ordinal += 1
        raw, key = self.decode(full)
        offset, previous = self.find(key)
        if previous[4] == 0:
            if self.count >= self.limit:
                return self.overflow(stamp)
            GENERATED_ROW.pack_into(self.store, offset, raw, key, (1 << 64) - 1, 0, 1, self.ordinal)
            self.count += 1
        frozen = self.frozen_keys.get(key)
        if (frozen is not None and frozen != raw) or (previous[4] and previous[0] != raw):
            self.collisions += 1
            self.tainted.setdefault(key, stamp)
        elif frozen == raw or (previous[4] and previous[0] == raw):
            self.aliases += 1
        # Frozen full-hash identity proves membership without request provenance.
        # An existing collision remains tainted; aliases never repair history.
        if frozen != raw:
            self.tainted.setdefault(key, stamp)
        return "unregistered"

    def membership(self, full, stamp, *, generated=False):
        raw, key = self.decode(full)
        if not self.key_valid(full, stamp):
            return None
        if generated:
            frozen = self.frozen.get(full)
            if frozen is not None:
                return frozen["in_W"]
            _, row = self.find(key)
            return False if row[4] and row[0] == raw else None
        value = self.frozen.get(full)
        return None if value is None else value["in_W"]


class ScanBudget:
    """Source-start credits; failures and crossing attempts are never refunded."""

    def __init__(self, origin, first_slot=0, last_slot=MAX_SLOTS - 1):
        self.origin = origin
        if not 0 <= first_slot <= last_slot < MAX_SLOTS:
            raise Refusal("slot_bounds")
        self.first_slot, self.last_slot = first_slot, last_slot
        self.used = collections.Counter()
        self.refusals = collections.Counter()
        self.last_wait = -1

    def slot(self, stamp):
        return (stamp - self.origin) // CADENCE_NS

    def reserve(self, kind, stamp, wait=None):
        slot = self.slot(stamp)
        if (
            kind not in ("ordinary", "seed", "idle")
            or not self.first_slot <= slot <= self.last_slot
        ):
            self.refusals["slot"] += 1
            return False
        if kind == "seed":
            if wait is None or wait <= self.last_wait:
                self.refusals["wait"] += 1
                return False
            self.last_wait = wait
        key = (slot, kind)
        if self.used[key]:
            self.refusals[kind] += 1
            return False
        self.used[key] = 1
        return True


@dataclass(frozen=True)
class Continuity:
    owner: tuple
    handled: int
    resets: int
    callbacks: int


@dataclass(frozen=True)
class Scan:
    identity: int
    start: int
    end: int
    epoch: int
    thread: int
    kind: str
    continuity: Continuity
    physical: tuple
    owners: tuple
    pending: tuple
    preceding_token: int | None
    scheduled: tuple


@dataclass
class Certificate:
    identity: int
    kind: str
    scan: Scan
    entry: int
    exit: int | None = None

    def contains(self, stamp, epoch, thread):
        return (
            self.exit is not None
            and self.scan.epoch == epoch
            and self.scan.thread == thread
            and max(self.scan.end, self.entry) <= stamp < self.exit
        )


def idle_reusable(scan, continuity, pending, resolved):
    return scan is not None and scan.continuity == continuity and not pending and resolved


class TwoSlotTransport:
    """Explicit publication under a mutex; producers never wait for the mutex.

    Single owner writes WRITING->READY. The worker alone writes
    READY->READING->FREE. Data are immutable before publication. A failed
    try-lock is an observation loss, not permission to overwrite a live slot.
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.states = ["FREE", "FREE"]
        self.data = [None, None]
        self.drops = 0
        self.abandoned = set()  # single-owner state; worker never touches it

    def reserve(self):
        if not self.lock.acquire(False):
            self.drops += 1
            return None
        try:
            for i in self.abandoned:
                if self.states[i] != "WRITING":
                    raise Refusal("transport_owner")
                self.data[i] = None
                self.states[i] = "FREE"
            self.abandoned.clear()
            for i, state in enumerate(self.states):
                if state == "FREE":
                    self.states[i] = "WRITING"
                    return i
            self.drops += 1
            return None
        finally:
            self.lock.release()

    def publish(self, i, value):
        if not self.lock.acquire(False):
            # Worker cannot read WRITING. Reclaim under the next owner try-lock;
            # never overwrite a READY/READING slot or wait on the engine thread.
            self.abandoned.add(i)
            self.drops += 1
            return False
        try:
            if self.states[i] != "WRITING":
                raise Refusal("transport_owner")
            self.data[i] = value
            self.states[i] = "READY"
            return True
        finally:
            self.lock.release()

    def discard(self, i):
        self.abandoned.add(i)

    def take(self):
        with self.lock:
            for i, state in enumerate(self.states):
                if state == "READY":
                    self.states[i] = "READING"
                    return i, self.data[i]
        return None

    def release(self, i):
        with self.lock:
            if self.states[i] != "READING":
                raise Refusal("transport_reader")
            self.data[i] = None
            self.states[i] = "FREE"


class Records:
    """Bounded small metadata channel with no producer mutex wait."""

    def __init__(self, capacity=1024):
        self.lock = threading.Lock()
        self.rows = collections.deque()
        self.capacity = capacity

    def put(self, row):
        if not self.lock.acquire(False):
            return False
        try:
            if len(self.rows) >= self.capacity:
                return False
            self.rows.append(row)
            return True
        finally:
            self.lock.release()

    def drain(self):
        with self.lock:
            rows = tuple(self.rows)
            self.rows.clear()
            return rows


def readiness(engine, output_class):
    values = {
        "async_scheduling": engine.vllm_config.scheduler_config.async_scheduling,
        "batch_queue_size": engine.batch_queue_size,
        "executor": qualified(engine.model_executor),
        "step_fn": (
            getattr(engine.step_fn, "__self__", None) is engine,
            getattr(engine.step_fn, "__func__", None)
            is getattr(type(engine), "step_with_batch_queue", None),
        ),
        "runner": (engine.vllm_config.use_v2_model_runner, output_class),
    }
    expected = {
        "async_scheduling": True,
        "batch_queue_size": 2,
        "executor": EXECUTOR,
        "step_fn": (True, True),
        "runner": (True, V2_OUTPUT),
    }
    if values != expected or type(values["async_scheduling"]) is not bool:
        raise Refusal("readiness_shape")
    return values


def bytecode_receipt(paths):
    """Inspect the effective target cache view, including alternate prefixes.

    A source-only overlay requires absence, even for a valid checked-hash pyc.
    -B only prevents writes; it never excuses a loadable shadow. Call in the
    serving interpreter before import, symmetrically for both arms.
    """
    result = []
    kinds = {0: "timestamp", 1: "unchecked_hash", 3: "checked_hash"}
    for name in paths:
        path = Path(name).resolve()
        if not path.is_file():
            raise Refusal("activation_missing_source")
        candidates = {path.with_suffix(".pyc"), Path(importlib.util.cache_from_source(str(path)))}
        candidates.update(path.parent.glob("__pycache__/" + path.stem + ".*.pyc"))
        found = []
        for candidate in sorted(candidates):
            if candidate.exists():
                data = candidate.read_bytes()
                if len(data) < 16 or data[:4] != importlib.util.MAGIC_NUMBER:
                    raise Refusal("bytecode_magic")
                flags = int.from_bytes(data[4:8], "little")
                if flags not in kinds:
                    raise Refusal("bytecode_flags")
                found.append({"path": str(candidate), "flags": flags, "kind": kinds[flags]})
        result.append(
            {"source": str(path), "caches": found, "dont_write_bytecode": sys.dont_write_bytecode}
        )
    return result


def require_source_imports(paths):
    receipt = bytecode_receipt(paths)
    if not sys.dont_write_bytecode:
        raise Refusal("bytecode_writes_enabled")
    if any(row["caches"] for row in receipt):
        raise Refusal("bytecode_shadow")
    return receipt


class StageCObserver:
    def __init__(self, engine, manifest, clock=time.monotonic_ns):
        self.engine, self.manifest, self.clock = engine, manifest, clock
        self.thread = threading.get_ident()
        self.pool = engine.scheduler.kv_cache_manager.block_pool
        self.managers = engine.scheduler.kv_cache_manager.coordinator.single_type_managers
        self.origin = manifest["cadence_start_ns"]
        self.budget = ScanBudget(self.origin, *manifest["patched_slots"])
        self.transport = TwoSlotTransport()
        self.records = Records()
        self.epoch = manifest["reset_epoch"]
        self.generations = [0] * len(self.pool.blocks)
        self.provenance = [None] * len(self.pool.blocks)
        self.scheduled = ()
        self.serials = {"handled": 0, "resets": 0, "callbacks": 0}
        self.last_post = None
        self.active = None
        self.scan_id = self.block_id = self.wait_id = 0
        self.associations = {}
        self.association_lock = threading.Lock()
        self.next_token = 0
        self.last_enqueued = None
        self.resolved_tokens = set()
        self.resolved_order = collections.deque()
        self.boundary_lock = threading.Lock()
        self.event_live = None
        self.event_token = None
        self.event_sequence = None
        self.pending_scans = {}
        self.loss = collections.Counter()
        self.gaps = collections.Counter()
        self.integrity = {}
        self.certificate_losses = {}
        self.first_failure = None
        self.stop = threading.Event()
        self.worker = None
        self.last_worker_slot = -1
        self.bytes_written = 0
        self.readiness_values = None
        self.insertion_cost_ns = self.insertion_checks = 0
        self.engine_ids = {}
        self.identity_refusals = collections.Counter()
        self.readiness_guard_ns = self.readiness_guard_checks = 0
        self.validate_manifest()
        self.domain = NativeDomain(self.manifest["native_domain"])

    def validate_manifest(self):
        required = {
            "source_commit",
            "cadence_start_ns",
            "reset_epoch",
            "requests",
            "native_domain",
            "output_path",
            "writer_quota_bytes",
            "activation",
            "manifest_sha256",
            "patched_slots",
        }
        if set(self.manifest) != required or self.manifest["source_commit"] != SOURCE_COMMIT:
            raise Refusal("manifest_schema")
        if len(self.pool.blocks) != MAX_PHYSICAL or len(self.managers) != 1:
            raise Refusal("pool_shape")
        if self.pool.hash_block_size != 16 or not self.pool.enable_kv_cache_events:
            raise Refusal("hash_shape")
        scheduler = self.engine.scheduler
        if scheduler.connector is not None or scheduler.ec_connector is not None:
            raise Refusal("connector")
        if type(self.managers[0]).__name__ != "FullAttentionManager":
            raise Refusal("attention_shape")
        if self.manifest["writer_quota_bytes"] <= 0:
            raise Refusal("writer_quota")
        if self.budget.last_slot - self.budget.first_slot + 1 > MAX_PATCHED_SLOTS:
            raise Refusal("patched_slot_count")
        # The domain is a forward full-key map, including group bytes. The
        # serving-host salted domain check must supply this manifest; no CPU
        # no-salt diagnostic is promoted to a readiness result.
        seen = {}
        for key, value in self.manifest["native_domain"].items():
            raw = bytes.fromhex(key)
            if len(raw) != 36 or raw[-4:] != bytes(4):
                raise Refusal("native_key")
            external = int.from_bytes(raw[:-4], "big") & ((1 << 64) - 1)
            if external in seen and seen[external] != key:
                raise Refusal("native_collision")
            seen[external] = key
            if set(value) != {"digest", "in_W"} or len(bytes.fromhex(value["digest"])) != 32:
                raise Refusal("native_membership")
        registrations = {}
        expected_instances = {
            "EngineCore.__init__": self.engine,
            "Scheduler.__init__": self.engine.scheduler,
            "BlockPool.__init__": self.pool,
            "ZmqEventPublisher.__init__": scheduler.kv_event_publisher,
        }
        for instance, function, path, pid, started in _registrations:
            if (
                pid == os.getpid()
                and started == _process_start
                and expected_instances.get(function) is instance
            ):
                registrations[function] = (
                    str(Path(path).resolve()),
                    qualified(instance),
                    id(instance),
                )
        for function in (
            "EngineCore.__init__",
            "Scheduler.__init__",
            "BlockPool.__init__",
            "ZmqEventPublisher.__init__",
        ):
            if function not in registrations:
                raise Refusal("activation_missing:" + function)
        actual_paths = {k: v[0] for k, v in registrations.items()}
        actual_paths["helper"] = str(Path(__file__).resolve())
        for function, (path, digest) in self.manifest["activation"].items():
            if actual_paths.get(function) != path:
                raise Refusal("activation_path")
            if hashlib.sha256(Path(path).read_bytes()).hexdigest() != digest:
                raise Refusal("activation_hash")
        if set(self.manifest["activation"]) != set(actual_paths):
            raise Refusal("activation_set")
        self.activation_receipt = require_source_imports(actual_paths.values())
        self.execution_receipt = registrations
        if len(bytes.fromhex(self.manifest["manifest_sha256"])) != 32:
            raise Refusal("manifest_binding")
        indexes = set()
        for binding in self.manifest["requests"].values():
            index = binding["per_request_index"]
            if type(index) is not int or not 0 <= index < 14_261 or index in indexes:
                raise Refusal("request_identity")
            indexes.add(index)

    def fail(self, cause, scope="source", stamp=None):
        stamp = self.clock() if stamp is None else stamp
        self.loss[cause] += 1
        self.integrity[scope] = min(stamp, self.integrity.get(scope, stamp))
        if scope == "source" and self.first_failure is None:
            self.first_failure = (stamp, cause)

    def gap(self, cause, stamp):
        slot = self.budget.slot(stamp)
        if self.budget.first_slot <= slot <= self.budget.last_slot:
            self.gaps[slot, cause] += 1

    def record(self, row):
        if not self.records.put(row):
            if row["kind"] in ("entry", "exit"):
                identity = row["id"]
                if (
                    identity not in self.certificate_losses
                    and len(self.certificate_losses) >= MAX_SLOTS
                ):
                    self.fail("certificate_loss_capacity")
                    return
                stamp = row["entry"] if row["kind"] == "entry" else row["exit"]
                self.loss["metadata_loss"] += 1
                self.certificate_losses.setdefault(identity, stamp)
                return
            scope = {
                "provenance": "domain",
                "reset": "owner",
                "reset_result": "owner",
            }.get(row["kind"], "source")
            # Insertion time, not a later flush/consumption time, is the taint.
            stamp = row["provenance"][-1] if row["kind"] == "provenance" else self.clock()
            self.fail("metadata_loss", scope, stamp)

    def admit(self):
        runner = self.engine.model_executor.driver_worker.worker.model_runner
        if qualified(runner) != "vllm.v1.worker.gpu.model_runner.GPUModelRunner":
            raise Refusal("readiness_runner")
        module = sys.modules[type(runner).__module__]
        self.readiness_values = readiness(self.engine, qualified(module.AsyncOutput))
        return self.readiness_values

    def request_binding(self, rid):
        match = re.fullmatch(r"((?:cmpl|chatcmpl)-[A-Za-z0-9][A-Za-z0-9_-]*)-[0-9a-f]{8}", rid)
        external = None if match is None else match[1]
        binding = self.manifest["requests"].get(external)
        if binding is None:
            self.identity_refusals["unregistered"] += 1
            return None, None
        live = set(self.engine.scheduler.requests)
        live.update(key for m in self.managers for key in m.req_to_blocks)
        # Both colliding owners refuse while live, independent of iteration or
        # cache-hook order. No random suffix is sent to the host.
        if any(
            other != rid and re.fullmatch(re.escape(external) + r"-[0-9a-f]{8}", other)
            for other in live
        ):
            self.identity_refusals["concurrent_binding"] += 1
            return external, None
        self.engine_ids[external] = rid
        return external, binding

    def continuity(self):
        return Continuity(
            (
                getattr(self.pool, "_stage_c_mutations", 0),
                getattr(self.engine.scheduler, "_stage_c_mutations", 0),
            ),
            self.serials["handled"],
            self.serials["resets"],
            self.serials["callbacks"],
        )

    def serial(self, kind):
        self.serials[kind] += 1

    def observe_schedule(self, output):
        self.scheduled = tuple(output.num_scheduled_tokens)

    def observe_allocation(self, pool, blocks):
        if pool is self.pool:
            for block in blocks:
                self.generations[block.block_id] += 1
                self.provenance[block.block_id] = None

    def observe_cache(self, pool, request, block_index, block, full):
        if pool is not self.pool or threading.get_ident() != self.thread:
            raise Refusal("cache_owner")
        start = self.clock()
        _external, binding = self.request_binding(request.request_id)
        if binding is None or binding.get("prompt_tokens") != request.num_prompt_tokens:
            # Explicit unknown provenance remains local to this physical alias.
            # It must not masquerade as session capacity overflow.
            status = self.domain.unregistered(full, start)
            self.provenance[block.block_id] = (
                None,
                block_index,
                request.num_prompt_tokens,
                full.hex(),
                status,
                start,
            )
            self.record(
                {
                    "kind": "provenance",
                    "physical_id": block.block_id,
                    "generation": self.generations[block.block_id],
                    "epoch": self.epoch,
                    "provenance": self.provenance[block.block_id],
                    "cost_ns": self.clock() - start,
                }
            )
            return
        index = binding["per_request_index"]
        status = self.domain.insertion(full, index, block_index, request.num_prompt_tokens, start)
        provenance = (index, block_index, request.num_prompt_tokens, full.hex(), status, start)
        self.provenance[block.block_id] = provenance
        end = self.clock()
        if block_index >= request.num_prompt_tokens // 16:
            self.insertion_checks += 1
            self.insertion_cost_ns += end - start
            self.record(
                {
                    "kind": "provenance",
                    "physical_id": block.block_id,
                    "generation": self.generations[block.block_id],
                    "epoch": self.epoch,
                    "provenance": provenance,
                    "cost_ns": end - start,
                }
            )

    def pending(self):
        result = tuple(self.pool.kv_event_queue)
        if len(result) > MAX_LINKS:
            raise Refusal("pending_count")
        if any(m._pending_cow_copies or m._pending_boundary_state_offloads for m in self.managers):
            raise Refusal("unsupported_pending_transition")
        if self.engine.scheduler.deferred_frees:
            raise Refusal("unsupported_deferred_fence")
        return result

    def capture(self, kind, wait=None):
        start = self.clock()
        if threading.get_ident() != self.thread:
            raise Refusal("owner_thread")
        if not self.budget.reserve(kind, start, wait):
            self.gap("scan_budget", start)
            return None
        slot = self.transport.reserve()
        if slot is None:
            self.gap("snapshot_buffer", start)
            return None
        try:
            continuity = self.continuity()
            physical = []
            # Walk existing free links, rather than invoking a cache helper.
            free_ids = set()
            block = self.pool.free_block_queue.fake_free_list_head.next_free_block
            while block is not self.pool.free_block_queue.fake_free_list_tail:
                if block is None or block.block_id in free_ids:
                    raise Refusal("free_queue_cycle")
                free_ids.add(block.block_id)
                block = block.next_free_block
            if len(free_ids) != self.pool.free_block_queue.num_free_blocks:
                raise Refusal("free_queue_count")
            for block in self.pool.blocks:
                aliases = set(self.pool.cached_block_hashes_by_block.get(block.block_id, ()))
                if block.block_hash is not None:
                    aliases.add(block.block_hash)
                aliases = tuple(sorted(aliases))
                # Full attention, equal hash/block sizes: at most one alias.
                if len(aliases) > 1:
                    raise Refusal("unsupported_alias_count")
                physical.append(
                    (
                        block.block_id,
                        self.generations[block.block_id],
                        block.ref_cnt,
                        block.is_null,
                        aliases,
                        block.block_id in free_ids,
                        self.provenance[block.block_id],
                    )
                )
            owners = []
            manager = self.managers[0]
            if len(manager.req_to_blocks) > MAX_OWNERS:
                raise Refusal("owner_count")
            for owner_number, (rid, blocks) in enumerate(manager.req_to_blocks.items()):
                if len(blocks) > 512:
                    raise Refusal("owner_position")
                request = self.engine.scheduler.requests.get(rid)
                hashes = () if request is None else tuple(request.block_hashes)
                external, binding = self.request_binding(rid)
                if request is None or (
                    binding is not None
                    and binding.get("prompt_tokens") != request.num_prompt_tokens
                ):
                    binding = None
                for position, block in enumerate(blocks):
                    full = hashes[position] + bytes(4) if position < len(hashes) else None
                    owners.append(
                        (
                            external if binding is not None else f"unregistered:{owner_number}",
                            None if binding is None else binding["per_request_index"],
                            position,
                            block.block_id,
                            rid in self.scheduled,
                            full,
                            None if request is None else request.num_prompt_tokens,
                        )
                    )
            if len(owners) > MAX_LINKS or continuity != self.continuity():
                raise Refusal("owner_copy")
            pending = self.pending()
            end = self.clock()
            if self.budget.slot(start) != self.budget.slot(end):
                self.gap("cross_slot_scan", start)
                self.transport.discard(slot)
                return None
            self.scan_id += 1
            scan = Scan(
                self.scan_id,
                start,
                end,
                self.epoch,
                self.thread,
                kind,
                continuity,
                tuple(physical),
                tuple(owners),
                pending,
                self.last_enqueued,
                self.scheduled,
            )
            if not self.transport.publish(slot, ("scan", scan)):
                self.gap("snapshot_publication", start)
                return None
            # Full arrays are owned only by the two transport slots, then the
            # source file. Reuse/holds retain lightweight immutable provenance.
            scan = replace(scan, physical=(), owners=())
            if pending:
                if len(self.pending_scans) >= MAX_ASSOCIATIONS:
                    self.fail("pending_associations", "events")
                    return None
                self.pending_scans[scan.identity] = scan
            if kind == "ordinary":
                self.last_post = scan
            return scan
        except Refusal as exc:
            self.transport.discard(slot)
            if str(exc) in ("owner_count", "owner_position", "pending_count", "owner_copy"):
                self.gap(str(exc), start)
                return None
            raise
        except Exception:
            self.transport.discard(slot)
            raise

    def capture_due(self):
        self.capture("ordinary")

    def before_wait(self, future):
        self.wait_id += 1
        output = getattr(future, "async_output", None)
        if output is None:
            # Resolved execute-model futures still consume no certificate.
            return None
        start = self.clock()
        readiness(self.engine, qualified(output))
        self.readiness_guard_ns += self.clock() - start
        self.readiness_guard_checks += 1
        scan = self.capture("seed", self.wait_id)
        return self.open_block("gpu", scan)

    def before_idle(self, block):
        if not block:
            return None
        pending = self.pending()
        scan = self.last_post
        resolved = scan is not None and self.boundary_ready(scan.preceding_token)
        if not idle_reusable(scan, self.continuity(), pending, resolved):
            scan = self.capture("idle")
            if scan is None or scan.pending or not self.boundary_ready(scan.preceding_token):
                return None
        return self.open_block("idle", scan)

    def boundary_ready(self, token):
        if not self.boundary_lock.acquire(False):
            self.gap("boundary_lock", self.clock())
            return False
        try:
            return token in self.resolved_tokens
        finally:
            self.boundary_lock.release()

    def open_block(self, kind, scan):
        if scan is None:
            return None
        self.block_id += 1
        self.active = Certificate(self.block_id, kind, scan, self.clock())
        self.record(
            {
                "kind": "entry",
                "id": self.block_id,
                "block_kind": kind,
                "scan_id": scan.identity,
                "entry": self.active.entry,
                "epoch": self.epoch,
                "thread": self.thread,
            }
        )
        return self.active

    def after_wait(self, certificate):
        if certificate is not None:
            certificate.exit = self.clock()
            self.record(
                {
                    "kind": "exit",
                    "id": certificate.identity,
                    "exit": certificate.exit,
                    "epoch": self.epoch,
                    "thread": self.thread,
                }
            )
            if self.active is certificate:
                self.active = None

    def observe_reset(self):
        self.serial("resets")
        self.epoch += 1
        self.last_post = None
        if self.boundary_lock.acquire(False):
            try:
                self.resolved_tokens.clear()
                self.resolved_order.clear()
            finally:
                self.boundary_lock.release()
        else:
            self.fail("reset_boundary_lock", "certificates")
        self.pending_scans.clear()
        self.record({"kind": "reset", "epoch": self.epoch, "observed_ns": self.clock()})

    def reset_result(self, result, error):
        self.record(
            {
                "kind": "reset_result",
                "epoch": self.epoch,
                "result": result,
                "error": error,
                "observed_ns": self.clock(),
            }
        )

    def observe_enqueue(self, batch, returned=False, error=False):
        if not self.association_lock.acquire(False):
            self.fail("sideband_lock", "events")
            return
        try:
            existing = next((v for v in self.associations.values() if v["object"] is batch), None)
            if not returned and not error:
                if existing is not None or len(self.associations) >= MAX_ASSOCIATIONS:
                    self.fail("sideband_capacity", "events")
                    return
                self.next_token += 1
                existing = {
                    "object": batch,
                    "token": self.next_token,
                    "epoch": self.epoch,
                    "entry_ns": self.clock(),
                    "enqueue_ns": None,
                    "sequence": None,
                    "publish_ns": None,
                    "error": False,
                }
                self.associations[self.next_token] = existing
                events = tuple(batch.events)
                # Identity is proved while the exact native objects are held;
                # no address-only matching and no post-return value reread.
                prefixes = []
                for scan in self.pending_scans.values():
                    n = len(scan.pending)
                    exact = len(events) >= n and all(
                        left is right for left, right in zip(scan.pending, events[:n], strict=True)
                    )
                    prefixes.append((scan.identity, n, exact))
                self.pending_scans.clear()
                existing["prefixes"] = tuple(prefixes)
                existing["events"] = tuple(event_values(event) for event in events)
            elif existing is None:
                self.fail("sideband_unmatched", "events")
            elif error:
                existing["error"] = True
            else:
                existing["enqueue_ns"] = self.clock()
                self.last_enqueued = existing["token"]
        finally:
            self.association_lock.release()

    def observe_sequence(self, batch, sequence):
        self.association_update(batch, "sequence", sequence)

    def observe_send(self, batch, error=False):
        self.association_update(
            batch, "error" if error else "publish_ns", True if error else self.clock()
        )

    def association_update(self, batch, key, value):
        if not self.association_lock.acquire(False):
            self.fail("sideband_lock", "events")
            return
        try:
            row = next((v for v in self.associations.values() if v["object"] is batch), None)
            if row is None:
                self.fail("sideband_unmatched", "events")
            else:
                row[key] = value
        finally:
            self.association_lock.release()

    def drain_associations(self):
        # Worker may wait on its mutex. Engine/publisher only try-lock it.
        with self.association_lock:
            complete = [
                key
                for key, row in self.associations.items()
                if row["error"] or (row["enqueue_ns"] is not None and row["publish_ns"] is not None)
            ]
            rows = []
            for key in complete:
                row = self.associations.pop(key)
                rows.append({k: v for k, v in row.items() if k != "object"})
            return rows

    def run(self):
        try:
            with Path(self.manifest["output_path"]).open("xb") as stream:
                self.write(
                    stream,
                    {
                        "kind": "activation",
                        "pid": os.getpid(),
                        "start_ns": _process_start,
                        "epoch": self.epoch,
                        "manifest_sha256": self.manifest["manifest_sha256"],
                        "paths": self.activation_receipt,
                        "executed": self.execution_receipt,
                    },
                )
                while not self.stop.is_set():
                    for row in self.records.drain():
                        self.write(stream, row)
                    for row in self.drain_associations():
                        self.write(stream, {"kind": "batch", **row})
                        self.apply_batch(row)
                    item = self.transport.take()
                    if item is not None:
                        index, (kind, scan) = item
                        try:
                            if kind == "scan":
                                self.write(stream, {"kind": "scan", "scan": scan_to_row(scan)})
                                self.resolve_boundary(scan)
                        finally:
                            self.transport.release(index)
                    stamp = self.clock()
                    slot = self.budget.slot(stamp)
                    if (
                        self.budget.first_slot <= slot <= self.budget.last_slot
                        and slot > self.last_worker_slot
                    ):
                        self.last_worker_slot = slot
                        publisher = self.engine.scheduler.kv_event_publisher
                        start = self.clock()
                        depth = publisher._event_queue.qsize()
                        end = self.clock()
                        observed = self.clock()
                        certificate = self.active
                        # Only the immutable copy is used; the worker never
                        # dereferences pool, owners, events or a native batch.
                        self.write(
                            stream,
                            {
                                "kind": "slot",
                                "slot": slot,
                                "observed_ns": stamp,
                                "certificate": None
                                if certificate is None
                                else certificate.identity,
                                "scan_id": None
                                if certificate is None
                                else certificate.scan.identity,
                                "queue": [start, end, observed, depth],
                            },
                        )
                    self.stop.wait(0.001)
                for row in self.records.drain():
                    self.write(stream, row)
                for row in self.drain_associations():
                    self.write(stream, {"kind": "batch", **row})
                while (item := self.transport.take()) is not None:
                    index, (kind, scan) = item
                    try:
                        if kind == "scan":
                            self.write(stream, {"kind": "scan", "scan": scan_to_row(scan)})
                    finally:
                        self.transport.release(index)
                self.write(
                    stream,
                    self.receipt(),
                )
        except Exception as exc:
            self.fail("worker:" + type(exc).__name__)
            # Worker-only bounded refusal sidecar. Missing/failed sidecar still
            # cannot yield a complete source: the final receipt is absent.
            try:
                path = Path(self.manifest["output_path"] + ".failure.json")
                data = json.dumps(
                    {"complete": False, "first_failure": self.first_failure}, separators=(",", ":")
                ).encode()
                with path.open("xb") as failure:
                    failure.write(data[:1024])
                    failure.flush()
                    os.fsync(failure.fileno())
            except OSError:
                pass

    def receipt(self):
        return {
            "kind": "receipt",
            "loss": dict(self.loss),
            "first_failure": self.first_failure,
            "integrity": dict(self.integrity),
            "certificate_losses": sorted(self.certificate_losses.items()),
            "gaps": [[slot, cause, n] for (slot, cause), n in sorted(self.gaps.items())],
            "readiness": self.readiness_values,
            "readiness_guard": [self.readiness_guard_checks, self.readiness_guard_ns],
            "request_identity_refusals": dict(self.identity_refusals),
            "attempts": [[slot, kind, n] for (slot, kind), n in self.budget.used.items()],
            "refusals": dict(self.budget.refusals),
            "transport_drops": self.transport.drops,
            "generated": {
                "entries": self.domain.count,
                "aliases": self.domain.aliases,
                "collisions": self.domain.collisions,
                "refusals": self.domain.refusals,
                "invalid_since": self.domain.invalid_since,
                "packed_bytes": len(self.domain.store),
                "checks": self.insertion_checks,
                "cost_ns": self.insertion_cost_ns,
            },
        }

    def apply_batch(self, row):
        sequence = row["sequence"]
        if row["error"] or sequence is None:
            self.event_live = None
            return
        if self.event_sequence is not None and sequence != self.event_sequence + 1:
            self.event_live = None
        self.event_sequence, self.event_token = sequence, row["token"]
        for kind, keys, group in row["events"]:
            if kind == "AllBlocksCleared":
                self.event_live = set()
            elif group != 0:
                self.event_live = None
            elif self.event_live is not None:
                if kind == "BlockStored":
                    self.event_live.update(keys)
                elif kind == "BlockRemoved":
                    self.event_live.difference_update(keys)

    def resolve_boundary(self, scan):
        if scan.pending or scan.preceding_token != self.event_token or self.event_live is None:
            return
        keys = [
            int.from_bytes(key[:-4], "big") & ((1 << 64) - 1)
            for _, _, _, _, aliases, _, _ in scan.physical
            for key in aliases
        ]
        if set(keys) == self.event_live:
            with self.boundary_lock:
                if scan.preceding_token not in self.resolved_tokens:
                    if len(self.resolved_tokens) >= MAX_ASSOCIATIONS:
                        self.resolved_tokens.remove(self.resolved_order.popleft())
                    self.resolved_tokens.add(scan.preceding_token)
                    self.resolved_order.append(scan.preceding_token)

    def write(self, stream, row):
        data = json.dumps(row, separators=(",", ":"), allow_nan=False).encode() + b"\n"
        if len(data) + self.bytes_written > self.manifest["writer_quota_bytes"]:
            raise Refusal("writer_quota")
        stream.write(data)
        self.bytes_written += len(data)

    def close(self):
        self.stop.set()
        if self.worker is not None:
            self.worker.join(timeout=1)
            if self.worker.is_alive():
                self.fail("worker_close_timeout")


def scan_to_row(scan):
    return {
        "identity": scan.identity,
        "start": scan.start,
        "end": scan.end,
        "epoch": scan.epoch,
        "thread": scan.thread,
        "scan_kind": scan.kind,
        "physical": [
            [i, gen, ref, null, [k.hex() for k in aliases], free, provenance]
            for i, gen, ref, null, aliases, free, provenance in scan.physical
        ],
        "owners": [
            [rid, index, pos, physical, scheduled, None if full is None else full.hex(), prompt]
            for rid, index, pos, physical, scheduled, full, prompt in scan.owners
        ],
        "pending_count": len(scan.pending),
        "preceding_token": scan.preceding_token,
    }


def event_values(event):
    name = type(event).__name__
    if name == "AllBlocksCleared":
        return (name, (), None)
    if name not in ("BlockStored", "BlockRemoved"):
        raise Refusal("event_kind")
    keys = tuple(event.block_hashes)
    if any(type(key) is not int or not 0 <= key < 1 << 64 for key in keys):
        raise Refusal("event_encoding")
    # Deliberately never copy token IDs, extra_keys or cache salts.
    return (name, keys, event.group_idx)
