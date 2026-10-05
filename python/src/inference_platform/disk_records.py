"""Private, repeatable disk sequences; JSON serialization never builds a session string."""

import json
import os
import sqlite3
import tempfile
import threading
from itertools import chain
from pathlib import Path


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
        self.db = sqlite3.connect(name, check_same_thread=False)
        self.db.execute("pragma cache_size=-4096")
        self.db.execute("pragma temp_store=FILE")
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
