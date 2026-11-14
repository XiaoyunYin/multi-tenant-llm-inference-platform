"""Redis 8.2.9 scalar/pair/fixed snapshot shapes, including error alternatives.

Source citations/hashes and derivations: docs/INF037B_368_CAPTURE_DERIVATION.md.
The server is standalone, default-user only, with no loadable modules; error
supersets include the pinned server's shared fixed errors and Lua wrappers.
"""

import json
import re

from .inf037b_archive import strict_json
from .inf037b_producer_contracts import REPORT_BYTES
from .inf037b_producer_limits import ProducerLimit

# server.c:2025-2060, acl.c:3240-3284. This longest fixed server failure is
# conservative for these read/auth commands as well as the EVAL entry point.
FIXED_SERVER_ERROR = "MISCONF Redis is configured to save RDB snapshots, but it's currently unable to persist to disk. Commands that may modify the data set are disabled, because this instance is configured to report errors during writes if RDB snapshotting fails (stop-writes-on-bgsave-error option). Please check the Redis logs for details about the RDB error."
AUTH_NOPASS = "ERR AUTH <password> called without any password configured for the default user. Are you sure your configuration is correct?"
# script_lua.c:1712-1727: function hash40, source @user_script12,
# line decimal20. Include both an error's source prefix and its suffix.
LUA_WRAPPER_BYTES = len(" script: , on @user_script:.") + 40 + 20 + len("ERR user_script: ") + 20
ERROR_LINE_BYTES = max(len(FIXED_SERVER_ERROR), len(AUTH_NOPASS)) + LUA_WRAPPER_BYTES + 3


def bulk_bytes(n):
    return n + len(str(n)) + 5


# Two report writers, three possible n values per writer, B<=10 active slots.
# Redis util.h:28 bounds WITHSCORES text by MAX_D2STRING_CHARS=128.
ARRAYS = {
    "reports": (4, (191, REPORT_BYTES)),
    "lows": (12, (193, 128)),
    "state": (8, (9, 20)),
    "active": (20, (228, 128)),
}


def snapshot_body_bytes():
    # coordinator.go tenantPattern/reservationPattern and fixed Lua keys use
    # ASCII without quote/backslash/control characters. Numbers are ASCII.
    # Each report value embeds exactly six JSON key quotes; cjson escapes those
    # six quotes once inside the enclosing snapshot. No generic 6x expansion.
    def array_bound(name, count, caps):
        return (
            2
            + max(0, count - 1)
            + sum(2 + caps[i % 2] + (6 if name == "reports" and i % 2 else 0) for i in range(count))
        )

    fields = {name: array_bound(name, count, caps) for name, (count, caps) in ARRAYS.items()}
    fields.update(redis_time_ms=20, capture_order=2 + 20)
    return 2 + len(fields) - 1 + sum(len(json.dumps(k)) + 1 + n for k, n in fields.items())


def fixed_contract(kind):
    if kind == "AUTH":
        return {"bytes": max(5, ERROR_LINE_BYTES), "elements": 1, "depth": 0, "shape": kind}
    if kind == "TIME":
        return {
            "bytes": max(4 + bulk_bytes(20) + bulk_bytes(6), ERROR_LINE_BYTES),
            "elements": 3,
            "depth": 1,
            "bulk": 20,
            "shape": kind,
        }
    if kind == "snapshot":
        cap = snapshot_body_bytes()
        return {
            "bytes": max(bulk_bytes(cap), ERROR_LINE_BYTES),
            "elements": 1,
            "depth": 0,
            "bulk": cap,
            "shape": kind,
        }
    raise ValueError("redis_shape:kind")


def validate_reply(value, kind, reject):
    reason = "capture:producer:resp_" + kind.lower() + "_shape"
    if kind == "AUTH":
        if value != b"OK":
            reject(reason)
    elif kind == "TIME":
        if not isinstance(value, list) or len(value) != 2:
            reject(reason)
        seconds, micros = value
        if (
            not isinstance(seconds, bytes)
            or len(seconds) > 20
            or not re.fullmatch(rb"-?[0-9]+", seconds)
            or not -(2**63) <= int(seconds) < 2**63
            or not isinstance(micros, bytes)
            or len(micros) > 6
            or not micros.isdigit()
            or not 0 <= int(micros) <= 999999
        ):
            reject(reason)
    else:
        try:
            if not value.isascii():
                reject("capture:producer:resp_snapshot_non_ascii")
            data = strict_json(value)
            if set(data) != {*ARRAYS, "redis_time_ms", "capture_order"}:
                reject(reason)
            if (
                type(data["redis_time_ms"]) is not int
                or not -(2**63) <= data["redis_time_ms"] < 2**63
            ):
                reject(reason)
            if (
                type(data["capture_order"]) is not str
                or not data["capture_order"].isdigit()
                or len(data["capture_order"]) > 20
            ):
                reject(reason)
            if not data["capture_order"].isascii():
                reject("capture:producer:resp_snapshot_non_ascii")
            for key, (count, caps) in ARRAYS.items():
                items = data[key]
                if items == {}:  # Redis Lua cjson encodes an empty table as {}.
                    continue
                if type(items) is not list or len(items) > count or len(items) % 2:
                    reject(reason)
                for i, item in enumerate(items):
                    if type(item) is not str or len(item.encode()) > caps[i % 2]:
                        reject(reason)
                    if not item.isascii():
                        reject("capture:producer:resp_snapshot_non_ascii")
        except ProducerLimit:
            raise
        except (TypeError, ValueError, UnicodeError):
            reject(reason)
