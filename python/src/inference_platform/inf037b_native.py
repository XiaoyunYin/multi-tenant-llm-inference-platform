"""Opt-in, source-pinned v0.29.0 request observations; no inference policy calls.

The overlay appends installers to three pinned modules. Each original method is
called once, with identical arguments/results/exceptions. Capture failures are
sticky and make retrieval refuse, rather than changing engine request handling.
"""

import asyncio
import functools
import hashlib
import json
import os
import sqlite3
import sys
import threading
import time
from contextlib import closing
from pathlib import Path

BASE_FILES = {
    "vllm/v1/engine/core.py": "f990e260cebf0826d08cfd30955c0c7a85b9af00504841b91759ca5bc7b036f6",
    "vllm/v1/engine/input_processor.py": "91dde56a548c09613ee9aaef8c43631481d12dc1bd439fddc12c6569f5e2e799",
    "vllm/v1/engine/async_llm.py": "46b1df9cb7466552e9ebd52f896eecc7e9e81bbf966077171f320366b7fcbbad",
    "vllm/v1/core/sched/scheduler.py": "abca7134821e2fb5cc8572df5c4a0b570ecf702646254327bc786fc452074983",
    "vllm/entrypoints/openai/chat_completion/serving.py": "ea1f76074a9587c8054f54d30a6ba748b6a5fc4d90dd82c801504505c1da1f92",
    "vllm/entrypoints/serve/engine/serving.py": "70143311acc2230b925e7f3603b8b9314f029ff5e98d5af990b3bdca691331f1",
}
TARGETS = {
    "core": ("vllm/v1/engine/core.py", "EngineCore"),
    "input": ("vllm/v1/engine/input_processor.py", "InputProcessor"),
    "api": ("vllm/v1/engine/async_llm.py", "AsyncLLM"),
    "scheduler": ("vllm/v1/core/sched/scheduler.py", "Scheduler"),
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode()


def check(condition, reason):
    if not condition:
        raise ValueError("native:" + reason)


def build_overlay(source, destination):
    source, destination = Path(source), Path(destination)
    check(not destination.exists(), "overlay_exists")
    original = {name: (source / name).read_bytes().replace(b"\r\n", b"\n") for name in BASE_FILES}
    check({name: digest(data) for name, data in original.items()} == BASE_FILES, "base_sources")
    destination.mkdir(parents=True)
    manifest = {
        "schema": "inf037b-native-overlay-v1",
        "version": "0.29.0",
        "base": dict(BASE_FILES),
        "files": {},
        "helper_sha256": digest(Path(__file__).read_bytes()),
    }
    for kind, (name, cls) in TARGETS.items():
        footer = (
            "\nfrom inference_platform.inf037b_native import install as _inf037b_install\n"
            f"_inf037b_install({kind!r}, {cls}, __file__)\n"
        ).encode()
        data = original[name] + footer
        compile(data, name, "exec")
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        manifest["files"][name] = digest(data)
    for name in BASE_FILES.keys() - manifest["files"].keys():
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(original[name])
        manifest["files"][name] = digest(original[name])
    package = destination / "inference_platform"
    package.mkdir()
    (package / "__init__.py").write_bytes(b"")
    (package / "inf037b_native.py").write_bytes(Path(__file__).read_bytes())
    (destination / "native-manifest.json").write_bytes(encoded(manifest))
    return manifest


class NativeEmitter:
    def __init__(self, root, origin):
        self.root, self.origin = Path(root), dict(origin)
        self.failed, self.lock = False, threading.RLock()
        self.closed, self.roles = False, {}
        self.abort_context = threading.local()
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.db = sqlite3.connect(
            self.root / "events.sqlite", timeout=0.25, check_same_thread=False
        )
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS meta(value BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS requests(
                id TEXT PRIMARY KEY, external TEXT UNIQUE NOT NULL, accepted INTEGER DEFAULT 0,
                intent TEXT, acknowledged INTEGER DEFAULT 0, terminal BLOB, confirmed INTEGER DEFAULT 0);
            CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY, value BLOB NOT NULL);
        """)
        with self.db:
            values = self.db.execute("SELECT value FROM meta").fetchall()
            if not values:
                self.db.execute("INSERT INTO meta VALUES (?)", (encoded(origin),))
            else:
                check(values == [(encoded(origin),)], "origin_changed")
        # SQLite FULL synchronizes commits; retain the new DB directory entry too.
        for path in (self.root, self.root.parent):
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)

    def _event(self, event, **fields):
        pid = os.getpid()
        ancestry, parent = [], pid
        while parent and len(ancestry) < 64:
            values = Path(f"/proc/{parent}/stat").read_text().rsplit(")", 1)[1].split()
            ancestry.append({"pid": parent, "start": values[19]})
            if parent == self.origin["supervisor_pid"]:
                break
            parent = int(values[1])
        check(
            ancestry[-1]
            == {"pid": self.origin["supervisor_pid"], "start": self.origin["supervisor_start"]},
            "process_lineage",
        )
        row = {
            "event": event,
            "mono_ns": time.monotonic_ns(),
            "pid": pid,
            "process_start": Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19],
            "ancestry": ancestry,
            **fields,
        }
        self.db.execute("INSERT INTO events(value) VALUES (?)", (encoded(row),))
        return row

    def observe(self, method, *args):
        # An observer error never retries/aborts an inference or replaces its
        # exception. A failed native source cannot supply fitness evidence.
        with self.lock:
            if self.failed or self.closed:
                return
            try:
                with self.db:
                    getattr(self, method)(*args)
            except Exception as exc:
                self.failed = True
                try:
                    with (self.root / "FAILED").open("xb") as stream:
                        stream.write(encoded({"error": str(exc)}))
                        stream.flush()
                        os.fsync(stream.fileno())
                    fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
                    try:
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                except OSError:
                    pass  # Missing required endpoints still refuse downstream.

    def identity(self, internal, external):
        check(
            isinstance(internal, str)
            and bool(internal)
            and isinstance(external, str)
            and bool(external),
            "request_identity",
        )
        self.db.execute("INSERT INTO requests(id,external) VALUES (?,?)", (internal, external))
        self._event("identity", internal=internal, external=external)

    def installed(self, kind, source_sha256):
        self.roles[kind] = source_sha256
        self._event("installed", kind=kind, source_sha256=source_sha256)

    def close(self):
        with self.lock:
            self.closed = True
            self.db.close()

    def after_fork(self):
        # Before-fork holds this emitter's lock: the connection is idle, never
        # inherited in the middle of an observation/SQLite mutex operation.
        roles = dict(self.roles)
        self.db.close()
        self.__init__(self.root, self.origin)
        for kind, source in roles.items():
            self.observe("installed", kind, source)

    def accept(self, internal):
        changed = self.db.execute(
            "UPDATE requests SET accepted=1 WHERE id=? AND accepted=0", (internal,)
        ).rowcount
        check(changed == 1, "accept_identity_or_duplicate")
        self._event("accept", internal=internal)

    def abort_intent(self, internal, cause):
        check(cause in ("CancelledError", "GeneratorExit"), "abort_cause")
        changed = self.db.execute(
            "UPDATE requests SET intent=? WHERE id=? AND intent IS NULL", (cause, internal)
        ).rowcount
        check(changed == 1, "abort_identity_or_duplicate")
        self._event("abort_intent", internal=internal, cause=cause)

    def abort_ack(self, internal):
        changed = self.db.execute(
            "UPDATE requests SET acknowledged=1 WHERE id=? AND intent IS NOT NULL AND acknowledged=0",
            (internal,),
        ).rowcount
        check(changed == 1, "abort_ack_without_intent")
        self._event("abort_ack", internal=internal)
        self.confirm(internal)

    def terminal(self, internal, status):
        row = self.db.execute(
            "SELECT accepted,terminal FROM requests WHERE id=?", (internal,)
        ).fetchone()
        check(row is not None and row[0] == 1 and row[1] is None, "terminal_identity_or_duplicate")
        event = self._event(
            "native_end",
            internal=internal,
            status=status,
            abort_rpc=internal in getattr(self.abort_context, "active", ()),
        )
        self.db.execute("UPDATE requests SET terminal=? WHERE id=?", (encoded(event), internal))
        self.confirm(internal)

    def confirm(self, internal):
        row = self.db.execute(
            "SELECT intent,acknowledged,terminal,confirmed FROM requests WHERE id=?", (internal,)
        ).fetchone()
        if row is None or row[2] is None or row[3]:
            return
        terminal = json.loads(row[2])
        status = terminal["status"]
        reason = {"FINISHED_STOPPED": "stop", "FINISHED_LENGTH_CAPPED": "length"}.get(status)
        if (
            status == "FINISHED_ABORTED"
            and terminal["abort_rpc"]
            and row[0] is not None
            and row[1] == 1
        ):
            reason = "client_cancel_abort"
        if reason is not None:
            self._event("terminal", internal=internal, terminal=terminal, terminal_reason=reason)
            self.db.execute("UPDATE requests SET confirmed=1 WHERE id=?", (internal,))


NATIVE_READ_BOUND_S = 1.0
NATIVE_READ_BUSY_S = 0.25
NATIVE_READ_PAUSE_S = 0.01
NATIVE_READ_ATTEMPTS = 100


def read_events(root, after=-1):
    root = Path(root)
    check(type(after) is int and after >= -1, "offset")
    check(not (root / "FAILED").exists(), "capture_lost")
    check((root / "events.sqlite").is_file(), "emitter_missing")
    deadline = time.monotonic() + NATIVE_READ_BOUND_S

    def remaining():
        left = deadline - time.monotonic()
        if left <= 0:
            raise sqlite3.OperationalError("native_reader_deadline")
        return left

    for attempt in range(NATIVE_READ_ATTEMPTS):
        db = None
        try:
            db = sqlite3.connect(
                f"file:{(root / 'events.sqlite').as_posix()}?mode=ro"
                + ("" if (root / "events.sqlite-wal").exists() else "&immutable=1"),
                uri=True,
                timeout=min(NATIVE_READ_BUSY_S, remaining()),
            )
            db.execute("BEGIN")
            # BEGIN is deferred; clip the first real read's lock wait to the
            # same total deadline after connection/transaction setup.
            db.execute(
                "PRAGMA busy_timeout=" + str(int(min(NATIVE_READ_BUSY_S, remaining()) * 1000))
            )
            # BEGIN is deferred: this first read actually opens the snapshot.
            origin_row = db.execute("SELECT value FROM meta").fetchone()
            remaining()
        except sqlite3.OperationalError:
            if db is not None:
                db.close()
            left = deadline - time.monotonic()
            if attempt == NATIVE_READ_ATTEMPTS - 1 or left <= 0:
                raise
            time.sleep(min(NATIVE_READ_PAUSE_S, left))
            if time.monotonic() >= deadline:
                raise
        except BaseException:
            if db is not None:
                db.close()
            raise
        else:
            break
    with closing(db):
        origin = json.loads(origin_row[0])
        rows = db.execute(
            "SELECT seq,value FROM events WHERE seq>? ORDER BY seq LIMIT 513", (after + 1,)
        ).fetchall()
        # SQLite sequences start at1; public source sequences start at0.
        events = [{"sequence": seq - 1, **json.loads(value)} for seq, value in rows[:512]]
        maximum = db.execute("SELECT coalesce(max(seq),0)-1 FROM events").fetchone()[0]
    check(after <= maximum, "offset_future")
    check(not (root / "FAILED").exists(), "capture_lost")
    return {
        "schema": "inf037b-native-events-v1",
        "origin": origin,
        "events": events,
        "next": events[-1]["sequence"] if events else after,
        "more": len(rows) > 512,
    }


_emitter = None
_fork_registered, _fork_lock = False, None


def register_fork():
    global _fork_registered
    if _fork_registered:
        return

    def before():
        global _fork_lock
        if _emitter is not None and not _emitter.closed:
            _fork_lock = _emitter.lock
            _fork_lock.acquire()

    def parent():
        global _fork_lock
        if _fork_lock is not None:
            _fork_lock.release()
            _fork_lock = None

    def child():
        global _fork_lock
        try:
            if _fork_lock is not None:
                _emitter.after_fork()
        except Exception as exc:
            _emitter.failed = False
            _emitter.lock = threading.RLock()
            _emitter.observe("fork_capture_failed:" + str(exc))
        finally:
            _fork_lock = None

    os.register_at_fork(before=before, after_in_parent=parent, after_in_child=child)
    _fork_registered = True


def install(kind, cls, module_file):
    global _emitter
    if "INF037B_NATIVE_ROOT" not in os.environ:
        return
    check(sys.implementation.name == "cpython" and sys.version_info >= (3, 11), "interpreter")
    root = Path(os.environ["INF037B_NATIVE_ROOT"])
    manifest_path = Path(os.environ["INF037B_NATIVE_MANIFEST"])
    manifest = json.loads(manifest_path.read_bytes())
    check(manifest["base"] == BASE_FILES and manifest["version"] == "0.29.0", "manifest")
    check(manifest["helper_sha256"] == digest(Path(__file__).read_bytes()), "helper_source")
    name = TARGETS[kind][0]
    check(digest(Path(module_file).read_bytes()) == manifest["files"][name], "installed_source")
    source = Path(module_file).resolve().parents[len(Path(name).parts) - 1]
    check(set(manifest["files"]) == set(BASE_FILES), "source_inventory")
    check(
        all(
            digest((source / path).read_bytes()) == expected
            for path, expected in manifest["files"].items()
        ),
        "runtime_sources",
    )
    capture = Path(os.environ["CAPTURE_ROOT"])
    check(root.resolve() == (capture / "native").resolve(), "capture_root")
    origin = json.loads((capture / "supervisor-origin.json").read_bytes())
    check(origin["pod_uid"] == os.environ["POD_UID"], "pod_uid")
    origin.update(
        node_boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        node=os.environ["NODE_NAME"],
        helper_sha256=manifest["helper_sha256"],
        manifest_sha256=digest(manifest_path.read_bytes()),
        model_sha256=os.environ["MODEL_SHA256"],
        runtime_sha256=os.environ["RUNTIME_SHA256"],
    )
    if _emitter is None:
        _emitter = NativeEmitter(root, origin)
        register_fork()
    else:
        check(
            _emitter.root.resolve() == root.resolve() and _emitter.origin == origin,
            "origin_changed",
        )
    attach(kind, cls, _emitter)
    _emitter.observe("installed", kind, manifest["files"][name])


def attach(kind, cls, emitter):
    check(not cls.__dict__.get("_inf037b_observed", False), "already_installed")
    cls._inf037b_observed = True
    if kind == "input":
        original = cls.assign_request_id

        @functools.wraps(original)
        def assigned(request):
            result = original(request)
            emitter.observe("identity", request.request_id, request.external_req_id)
            return result

        cls.assign_request_id = staticmethod(assigned)
    elif kind == "api":
        original, generate_code = cls.abort, cls.generate.__code__

        @functools.wraps(original)
        async def aborted(self, request_id, internal=False):
            exc, caller = sys.exception(), sys._getframe(1)
            cancelled = (
                internal
                and isinstance(request_id, str)
                and isinstance(exc, (asyncio.CancelledError, GeneratorExit))
                and caller.f_code is generate_code
                and caller.f_locals.get("self") is self
            )
            if cancelled:
                emitter.observe("abort_intent", request_id, type(exc).__name__)
            result = await original(self, request_id, internal=internal)
            if cancelled:
                emitter.observe("abort_ack", request_id)
            return result

        cls.abort = aborted
    elif kind == "core":
        original = cls.abort_requests

        @functools.wraps(original)
        def aborted_requests(self, request_ids):
            prior = getattr(emitter.abort_context, "active", ())
            values = (
                (request_ids,)
                if isinstance(request_ids, str)
                else tuple(request_ids)
                if type(request_ids) in (list, tuple)
                else ()
            )
            emitter.abort_context.active = values
            try:
                return original(self, request_ids)
            finally:
                emitter.abort_context.active = prior

        cls.abort_requests = aborted_requests
    elif kind == "scheduler":
        added, freed = cls.add_request, cls._free_request

        @functools.wraps(added)
        def accepted(self, request):
            existed = request.request_id in self.requests
            result = added(self, request)
            if not existed and self.requests.get(request.request_id) is request:
                emitter.observe("accept", request.request_id)
            return result

        @functools.wraps(freed)
        def ended(self, request, delay_free_blocks=False):
            result = freed(self, request, delay_free_blocks=delay_free_blocks)
            emitter.observe("terminal", request.request_id, request.status.name)
            return result

        cls.add_request, cls._free_request = accepted, ended
    else:
        check(False, "installer_kind")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    built = build_overlay(args.source, args.output)
    args.receipt.write_bytes(
        encoded(
            {
                "schema": "inf037b-native-build-v1",
                "manifest": built,
                "manifest_sha256": digest((args.output / "native-manifest.json").read_bytes()),
                "original_function_bodies_unchanged": True,
                "compiled_overlay_files": len(TARGETS),
                "native_runtime_execution": "NOT_RUN",
                "paid_action": False,
            }
        )
    )
