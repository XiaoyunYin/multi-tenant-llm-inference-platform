"""Private, repeatable disk sequences; JSON serialization never builds a session string."""

import json
import os
import sqlite3
import tempfile
import threading
import weakref
from collections import OrderedDict
from itertools import chain
from pathlib import Path

_CONNECTION_LIMIT = 32
_CONNECTION_LOCK = threading.RLock()
_CONNECTIONS = OrderedDict()


class _Cursor:
    """Keep an iterated query's connection out of the idle eviction set."""

    def __init__(self, owner, cursor):
        self.owner, self.cursor = owner, cursor
        self.rowcount = cursor.rowcount
        if cursor.description is None:
            cursor.close()
            self.cursor = None
        else:
            owner.readers += 1

    def close(self):
        with _CONNECTION_LOCK:
            if self.cursor is not None:
                try:
                    self.cursor.close()
                finally:
                    self.cursor = None
                    self.owner.readers -= 1

    def fetchone(self):
        with _CONNECTION_LOCK:
            if self.cursor is None:
                return None
            row = self.cursor.fetchone()
            if row is None:
                self.close()
            return row

    def fetchall(self):
        with _CONNECTION_LOCK:
            try:
                return self.cursor.fetchall() if self.cursor is not None else []
            finally:
                self.close()

    def __iter__(self):
        return self

    def __next__(self):
        row = self.fetchone()
        if row is None:
            raise StopIteration
        return row

    def __del__(self):
        self.close()


class _Database:
    """A private database with a bounded, process-wide cache of open connections.

    Idle eviction commits the private rows before closing. Reopening keeps each
    list's SQL namespace, including callers' auxiliary index tables. Active query
    cursors hold a lease until exhausted or closed, so eviction cannot invalidate
    a streaming reader. Backing files live until their owning DiskList closes.
    """

    def __init__(self, path):
        self.path, self.connection = path, None
        self.readers, self.closed = 0, False

    def _disconnect(self, *, preserve):
        if self.connection is not None:
            try:
                if preserve:
                    self.connection.commit()
            finally:
                self.connection.close()
                self.connection = None
                _CONNECTIONS.pop(id(self), None)

    def _connection(self):
        if self.closed:
            raise sqlite3.ProgrammingError("DiskList database is closed")
        if self.connection is None:
            while len(_CONNECTIONS) >= _CONNECTION_LIMIT:
                for key, reference in list(_CONNECTIONS.items()):
                    database = reference()
                    if database is None:
                        _CONNECTIONS.pop(key)
                        break
                    if not database.readers:
                        database._disconnect(preserve=True)
                        break
                else:
                    raise RuntimeError("DiskList connection bound: all connections have readers")
            self.connection = sqlite3.connect(self.path, check_same_thread=False)
            self.connection.execute("pragma cache_size=-4096")
            self.connection.execute("pragma temp_store=FILE")
            _CONNECTIONS[id(self)] = weakref.ref(self)
        _CONNECTIONS.move_to_end(id(self))
        return self.connection

    def _statement(self, method, args):
        with _CONNECTION_LOCK:
            connection = self._connection()
            self.readers += 1
            try:
                return _Cursor(self, getattr(connection, method)(*args))
            finally:
                self.readers -= 1

    def execute(self, *args):
        return self._statement("execute", args)

    def executemany(self, *args):
        return self._statement("executemany", args)

    def executescript(self, *args):
        return self._statement("executescript", args)

    def close(self):
        with _CONNECTION_LOCK:
            self._disconnect(preserve=False)
            self.closed = True


class DiskList(list):
    """A JSON-array compatible sequence backed by a bounded SQLite page cache.

    Use json.dump/iterencode, not json.dumps's C fast path. No raw dataset is
    retained in the inherited list. Append is safe for recorder worker threads.
    """

    def __init__(self, values=()):
        super().__init__()
        fd, name = tempfile.mkstemp(prefix="inf011-records-", suffix=".sqlite")
        os.close(fd)
        self.path = Path(name)
        self.db = _Database(name)
        self.db.execute("create table rows (n integer primary key, value text not null)")
        self.lock = threading.RLock()
        self.count = 0
        self.extend(values)

    def append(self, value):
        text = json.dumps(value, separators=(",", ":"), allow_nan=False)
        with self.lock:
            self.db.execute("insert into rows values (?,?)", (self.count, text))
            self.count += 1

    def extend(self, values):
        for value in values:
            self.append(value)

    def __len__(self):
        return self.count

    def __iter__(self):
        # Finalized sequences are read after all producer threads are reaped.
        for (text,) in self.db.execute("select value from rows order by n"):
            yield json.loads(text)

    def __reversed__(self):
        for (text,) in self.db.execute("select value from rows order by n desc"):
            yield json.loads(text)

    def __getitem__(self, index):
        if isinstance(index, slice):
            return [self[i] for i in range(*index.indices(self.count))]
        if index < 0:
            index += self.count
        row = self.db.execute("select value from rows where n=?", (index,)).fetchone()
        if row is None:
            raise IndexError(index)
        return json.loads(row[0])

    def __eq__(self, other):
        return len(self) == len(other) and all(a == b for a, b in zip(self, other, strict=True))

    def __add__(self, other):
        return DiskList(chain(self, other))

    def __radd__(self, other):
        return DiskList(chain(other, self))

    def __iadd__(self, other):
        self.extend(other)
        return self

    def window(self, start, end):
        return DiskWindow(self, start, end)

    def __setitem__(self, index, value):
        if not isinstance(index, int):
            raise TypeError("disk rows require an integer replacement index")
        if index < 0:
            index += self.count
        with self.lock:
            updated = self.db.execute(
                "update rows set value=? where n=?", (json.dumps(value), index)
            )
        if not updated.rowcount:
            raise IndexError(index)

    def ordered(self, keys):
        if not all(key.replace("_", "").isalnum() for key in keys):
            raise ValueError("invalid sort key")
        order = ",".join(f"json_extract(value,'$.{key}')" for key in keys)
        for (text,) in self.db.execute("select value from rows order by " + order + ",n"):
            yield json.loads(text)

    def close(self):
        if getattr(self, "db", None) is not None:
            self.db.close()
            self.db = None
            self.path.unlink(missing_ok=True)

    def __del__(self):
        self.close()


def ordered_rows(rows, keys):
    return (
        rows.ordered(keys)
        if isinstance(rows, DiskList)
        else iter(sorted(rows, key=lambda row: tuple(row.get(key, 0) for key in keys)))
    )


class DiskWindow:
    def __init__(self, rows, start, end):
        self.rows, self.start, self.end = rows, start, end

    def __len__(self):
        return max(0, self.end - self.start)

    def __iter__(self):
        return (self.rows[i] for i in range(self.start, self.end))

    def __getitem__(self, index):
        if isinstance(index, slice):
            return [self[i] for i in range(*index.indices(len(self)))]
        if index < 0:
            index += len(self)
        if not 0 <= index < len(self):
            raise IndexError(index)
        return self.rows[self.start + index]

    def __eq__(self, other):
        return len(self) == len(other) and all(a == b for a, b in zip(self, other, strict=True))


def write_json(path, value):
    """Stream even disk-backed arrays; atomically replace only a complete file."""
    path = Path(path)
    pending = path.with_name(path.name + ".pending")
    try:
        with pending.open("w", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        pending.replace(path)
    finally:
        pending.unlink(missing_ok=True)


def jsonl_rows(path):
    with Path(path).open(encoding="utf-8") as stream:
        for line in stream:
            if line.strip():
                yield json.loads(line)
