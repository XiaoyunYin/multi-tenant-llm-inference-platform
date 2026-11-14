"""Linux filesystem authority for v4 ports. No network or paid entry point.

The parent must already be a persistent, operator-owned recovery directory.
Unsupported directory fsync/locking fails closed; Windows is not emulated.
"""

import copy
import os
import secrets
from contextlib import contextmanager
from pathlib import Path

from .inf037b_archive import IntegrityError, encode, sha, strict_json
from .inf037b_resolver import exact, integer, require


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class DurableStore:
    """Atomic checksummed snapshot, real file+directory barriers and OS lock.

    A missing initialized snapshot never becomes an empty authority. After any
    ambiguous I/O the object is poisoned; reopen re-barriers and verifies it.
    Temporary files are never authoritative, including after a torn write.
    """

    def __init__(self, directory, initial, *, initialize=False):
        if os.name != "posix":
            raise OSError("ports:posix_directory_durability_required")
        self.path = Path(directory)
        self.failed = False
        created = False
        if initialize:
            try:
                self.path.mkdir(mode=0o700)
                created = True
            except FileExistsError:
                pass
        else:
            require(self.path.is_dir(), "ports:initialization_required")
        sync_directory(self.path.parent)
        with self.lock():
            if created:
                self.write(copy.deepcopy(initial))
            # A completed rename with a lost directory ack is reconciled before
            # exposing recovered facts to any external operation.
            self.read()
            sync_directory(self.path)

    @contextmanager
    def lock(self):
        import fcntl

        require(not self.failed, "ports:store_poisoned")
        with (self.path / "lock").open("a+b") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                yield
            finally:
                fcntl.flock(stream, fcntl.LOCK_UN)

    def read(self):
        require(not self.failed, "ports:store_poisoned")
        try:
            envelope = strict_json((self.path / "state.json").read_bytes())
            exact(set(envelope), {"schema", "payload", "sha256"}, "ports:store_envelope")
            exact(envelope["schema"], "inf037b-durable-v1", "ports:store_schema")
            exact(sha(encode(envelope["payload"])), envelope["sha256"], "ports:store_hash")
            return envelope["payload"]
        except OSError:
            self.failed = True
            raise
        except (ValueError, TypeError, KeyError, RecursionError) as exc:
            self.failed = True
            raise IntegrityError("ports:corrupt_store") from exc

    def write(self, payload):
        require(not self.failed, "ports:store_poisoned")
        data = encode(
            {"schema": "inf037b-durable-v1", "payload": payload, "sha256": sha(encode(payload))}
        )
        temporary = self.path / ("pending-" + secrets.token_hex(16))
        try:
            with temporary.open("xb") as stream:
                exact(stream.write(data), len(data), "ports:short_write")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path / "state.json")
            sync_directory(self.path)
            exact((self.path / "state.json").read_bytes(), data, "ports:write_readback")
        except BaseException:
            self.failed = True
            raise


class FileJournal:
    """One OS-fenced writer held until close; stale instances cannot append.

    The origin has two barriers: an anchor, then its timestamped controller row.
    t0 samples completion of the anchor's file+directory fsync, never a clock
    before slow I/O. No ODCR call is possible until the timestamped row also
    passes both barriers. An interrupted unsealed anchor fails closed on reopen.
    """

    def __init__(self, directory, clock, *, initialize=False):
        self.store = DurableStore(
            directory, {"epoch": 0, "rows": [], "anchor": None}, initialize=initialize
        )
        self.clock = clock
        self.closed = True
        self.lease = self.store.lock()
        self.lease.__enter__()
        try:
            state = self.store.read()
            require(state["anchor"] is None, "ports:unsealed_origin")
            require(integer(state["epoch"]), "ports:fence_epoch")
            self.epoch = state["epoch"] + 1
            state["epoch"] = self.epoch
            self.store.write(state)
            self.closed = False
        except BaseException:
            self.lease.__exit__(None, None, None)
            raise

    def close(self):
        if not self.closed:
            self.closed = True
            self.lease.__exit__(None, None, None)

    def _state(self):
        require(not self.closed, "ports:stale_writer")
        state = self.store.read()
        exact(state["epoch"], self.epoch, "ports:stale_fence")
        require(state["anchor"] is None, "ports:unsealed_origin")
        return state

    def read(self):
        return copy.deepcopy(self._state()["rows"])

    def _append(self, state, row):
        exact(row["seq"], len(state["rows"]) + 1, "ports:journal_sequence")
        state["rows"].append(copy.deepcopy(row))
        self.store.write(state)

    def append_fsync(self, row):
        state = self._state()
        require(row["event"] != "billing_origin", "ports:origin_requires_anchor")
        self._append(state, row)
        return True

    def append_origin_fsync(self, row):
        state = self._state()
        exact(row["event"], "billing_origin", "ports:origin_event")
        require(
            not any(r["event"] == "billing_origin" for r in state["rows"]),
            "ports:origin_once",
        )
        exact(row["seq"], len(state["rows"]) + 1, "ports:origin_sequence")
        state["anchor"] = copy.deepcopy(row)
        self.store.write(state)
        now = self.clock()
        require(integer(now) and now >= 0, "ports:origin_clock")
        persisted = copy.deepcopy(row)
        persisted["data"]["t0_ms"] = now
        state["anchor"] = None
        self._append(state, persisted)
        return {"fsync": True, "row": persisted}
