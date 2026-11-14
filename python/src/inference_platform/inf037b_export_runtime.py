"""Operation-local export optimizations; no global syscall patch or stale stat cache.

Archives have one writer. Concurrent external writers remain unsupported. Fresh
byte inventories detect persistent input changes, not adversarial change-and-restore.
"""

import copy
import os
from collections import OrderedDict
from contextvars import ContextVar
from functools import wraps

_batch = ContextVar("export_durability_batch", default=None)
_memo = ContextVar("export_memoization", default=None)


def active_batch():
    """Whether this caller owns an export batch; capture open/close cannot nest."""
    return _batch.get() is not None


def defer_file(path, *, immediate=False):
    batch = _batch.get()
    if batch is None:
        return False
    batch[1].add(path.parent)
    if not immediate:
        batch[0].add(path)
        return True
    return False


def created_directory(path):
    batch = _batch.get()
    if batch is not None:
        batch[1].update((path, path.parent))


def synchronize(files, directories, *, platform_name=None):
    platform_name = os.name if platform_name is None else platform_name
    for path in sorted(files):
        mode = "r+b" if platform_name == "nt" else "rb"
        with path.open(mode) as handle:
            os.fsync(handle.fileno())
    if platform_name == "nt":
        # Windows has no directory-fsync primitive. This branch is for local
        # packet generation only; Gate A host execution uses the Linux branch.
        return
    # Child entries before the directory entries that name them.
    for path in sorted(directories, key=lambda p: (-len(p.parts), str(p))):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def barrier():
    """Durably flush and clear the active operation batch before a seal."""
    batch = _batch.get()
    if batch is None:
        return
    files, directories = batch
    synchronize(files, directories)
    files.clear()
    directories.clear()


def batched_durability(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        files, directories = set(), set()
        token = _batch.set((files, directories))
        try:
            return function(*args, **kwargs)
        finally:
            _batch.reset(token)
            synchronize(files, directories)

    return wrapped


def export_memoization(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        if _memo.get() is not None:
            return function(*args, **kwargs)
        token = _memo.set(OrderedDict())
        try:
            return function(*args, **kwargs)
        finally:
            _memo.reset(token)

    return wrapped


def inventory(root, *, report=False):
    from .inf037b_archive import IntegrityError, file_facts

    paths = (
        [
            root / "registration.json",
            root / "attempts.jsonl",
            root / "raw",
            *sorted((root / "raw").glob("*.jsonl")),
        ]
        if report
        else sorted(root.rglob("*"))
    )
    observed = {}
    for path in paths:
        if path.is_symlink():
            raise IntegrityError("memoization_symlink_input")
        name = path.relative_to(root).as_posix()
        observed[name] = file_facts(path) if path.is_file() else {"directory": path.is_dir()}
    return observed


def fresh_result(key, observe, produce):
    """Hash on every access and again after a miss; retain at most eight results.

    Entries are replaced on inventory change, never accumulated by file version.
    Returned mutable reports/receipts cannot poison the saved result.
    """
    from .inf037b_archive import IntegrityError

    cache = _memo.get()
    if cache is None:
        return produce()
    before = observe()
    saved = cache.get(key)
    if saved is not None and saved[0] == before:
        cache.move_to_end(key)
        return copy.deepcopy(saved[1])
    cache.pop(key, None)
    value = produce()
    if before != observe():
        raise IntegrityError("memoization_input_changed")
    cache[key] = (before, copy.deepcopy(value))
    if len(cache) > 8:
        cache.popitem(last=False)
    return value
