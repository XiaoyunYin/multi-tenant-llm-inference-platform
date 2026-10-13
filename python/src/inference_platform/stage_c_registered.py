"""Source-bound remainder serializer contracts, validated before compression.

The producer supplies captured source tables, never a second sizing encoder.
The observational producer and paid admission remain separate prerequisites.
"""

import base64
import gzip
import hashlib
import json
import math
import os
import re
import struct
import time
from collections import Counter

from .disk_records import write_json
from .stage_c_wire import compressed_sections, member, unpadded

REGISTRATION = "stage-c-remainder-v1"
GATEWAY_CODES = tuple(
    "admission_unavailable client_cancelled completed gateway_capacity internal_error "
    "invalid_request model_not_allowed no_healthy_backend request_too_large shutting_down "
    "stream_interrupted system_capacity tenant_concurrency_limit tenant_rate_limit "
    "unauthenticated unsupported_media_type unsupported_parameter upstream_failure "
    "upstream_protocol_error upstream_timeout write_failure".split()
)
CLASSES = tuple(
    "completed vllm_pre_content_rejection vllm_in_stream_error gateway_protocol_rejection "
    "gateway_no_healthy_backend other_or_unestablished".split()
)
FAILURE_FIELDS = (
    "http_status",
    "gateway_terminal_code",
    "class",
    "client_error_body_code",
    "upstream_error_body_code",
)


class RetentionError(ValueError):
    def __init__(self, flag, table, allowed=None, attempted=None):
        super().__init__(f"{flag}: {table}; allowed={allowed}, attempted={attempted}")
        self.receipt = {
            "flag": flag,
            "table": table,
            "allowed": allowed,
            "attempted_count": attempted
            if type(attempted) is int and attempted.bit_length() <= 128
            else None,
            "attempted_type": type(attempted).__name__,
            "first_hit_monotonic_ns": time.monotonic_ns(),
            "dependent_outputs": "unavailable",
            "full_measured_session_acceptance": False,
        }


def encoded(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def integer(value, bits, name, *, nullable=False, signed=False, maximum=None):
    if nullable and value is None:
        return value
    low = -(1 << (bits - 1)) if signed else 0
    high = (1 << (bits - int(signed))) - 1 if maximum is None else maximum
    if type(value) is not int or not low <= value <= high:
        raise RetentionError("retention_field_overflow", name, high, value)
    return value


def enum(value, values, name, *, nullable=False):
    if nullable and value is None:
        return 0
    if value not in values:
        raise RetentionError("retention_enum_overflow", name)
    return values.index(value) + int(nullable)


def count(rows, limit, name):
    if len(rows) > limit:
        raise RetentionError("retention_count_ceiling_hit", name, limit, len(rows))


def byte_bound(data, limit, name):
    if len(data) > limit:
        raise RetentionError("retention_byte_ceiling_hit", name, limit, len(data))


def median(values):
    return sorted(values)[math.ceil(len(values) / 2) - 1] if values else None


def failure_codebook(tuples):
    """Exact typed tuples, null before value; a ninth tuple refuses the whole run."""
    strings = sorted({row[3] for row in tuples if type(row[3]) is str})
    count(strings, 8, "client_body_code_enum")
    for value in strings:
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", value, flags=re.ASCII):
            raise RetentionError("failure_code_overflow", "client_error_body_code")
    typed = []
    for row in tuples:
        if len(row) != 5:
            raise RetentionError("failure_code_overflow", "failure_tuple_width")
        http, gateway, category, client, upstream = row
        if http is not None and (type(http) is not int or not 100 <= http <= 599):
            raise RetentionError("failure_code_overflow", "http_status")
        gateway_id = enum(gateway, GATEWAY_CODES, "gateway_terminal_code", nullable=True)
        class_id = enum(category, CLASSES, "class")
        if client is None:
            kind, value = 0, 0
        elif type(client) is str:
            kind, value = 1, strings.index(client)
        else:
            kind, value = 2, integer(client, 32, "client_error_body_code")
        integer(upstream, 32, "upstream_error_body_code", nullable=True)
        mask = sum(
            int(item is None) << bit for bit, item in enumerate((http, gateway, client, upstream))
        )
        typed.append((http or 0, gateway_id, class_id, kind, value, upstream or 0, mask))
    unique = set(typed)
    if len(unique) > 8:
        raise RetentionError("failure_code_overflow", "failure_split_codebook.v1", 8, len(unique))

    def key(row):
        http, gateway, category, kind, client, upstream, mask = row
        return (
            (not bool(mask & 1), http),
            (not bool(mask & 2), gateway),
            category,
            (kind != 0, kind, client),
            (not bool(mask & 8), upstream),
        )

    ordered = sorted(unique, key=key)
    codebook = {
        "schema": "failure_split_codebook.v1",
        "row_schema": "c_level.v1",
        "failure_split_basis": "Exact request-ID join; source-shaped native error metadata, not traceback counts; health failures separate",
        "failure_tuple_schema": [
            "http_status",
            "gateway_terminal_code",
            "class",
            "client_body_kind",
            "client_body_value",
            "upstream_error_body_code",
            "null_mask",
        ],
        "gateway_terminal_enum": [None, *GATEWAY_CODES],
        "class_enum": CLASSES,
        "client_body_kind_enum": ["null", "string", "integer"],
        "client_body_code_enum": strings,
        "failure_null_mask_bits": [
            "http_status",
            "gateway_terminal_code",
            "client_error_body_code",
            "upstream_error_body_code",
        ],
        "failure_codes": ordered,
        "row_enums": {
            "arm": ["control", "patched"],
            "row_status": ["complete", "partial", "missing", "invalid"],
            "load_mode": [
                "sustained_closed_loop",
                "reference_population",
                "reference_replay",
                "not_applicable",
            ],
            "screen_status": ["not_applicable", "valid", "inconclusive", "invalid"],
            "diagnostic_status": ["not_applicable", "valid", "incomplete", "invalid"],
        },
    }
    byte_bound(encoded(codebook), 2113, "failure_split_codebook.v1")
    return codebook, [ordered.index(row) for row in typed]


def decode_failures(codebook):
    result = []
    for http, gateway, category, kind, client, upstream, mask in codebook["failure_codes"]:
        result.append(
            (
                None if mask & 1 else http,
                None if mask & 2 else codebook["gateway_terminal_enum"][gateway],
                codebook["class_enum"][category],
                None
                if mask & 4
                else codebook["client_body_code_enum"][client]
                if kind == 1
                else client,
                None if mask & 8 else upstream,
            )
        )
    return result


def source_bindings(run):
    binding = run["source_binding"]
    if set(binding) != {"run_sha256", "source_sha256", "registration_sha256"}:
        raise RetentionError("retention_schema_overflow", "source_binding")
    for key, value in binding.items():
        if type(value) is not str or not re.fullmatch("[0-9a-f]{64}", value):
            raise RetentionError("retention_field_overflow", key)
    return binding


LAG_STATUS = (
    "observed",
    "observed_after_request_window",
    "no_new_full_blocks_expected",
    "excluded_request_failed_before_content",
    "no_post_decision_store_event",
    "no_identity_specific_store_cache_state_unknown",
    "missing_decision",
    "invalid_clock",
    "publisher_gap",
    "sideband_loss",
)
OUTCOMES = (
    "completed",
    "pre-content-rejection",
    "in-stream-error",
    "timeout",
    "cancelled",
    "partial",
    "drain-cut",
    "transport-error",
    "unknown",
    "pending",
)
MATCH_BASIS = (
    "identity-specific-digest",
    "failed-before-content",
    "cached-no-full-block",
    "known-cache-before-next-decision",
    "unknown-cache-before-next-decision",
    "unavailable",
)

# Field descriptions are the recovery schema. '?' always has a distinct null bit.
REQUEST_SCHEMA = (
    "per_request_index:H level_index:B worker_index:B? worker_cycle:B? prefix_ordinal:B? "
    "reset_epoch:B replica_index:B group_index:B prompt_identity_sha256:sha "
    "dispatch_ns:Q first_content_ns:Q? terminal_ns:Q? censor_ns:Q? outcome:outcome "
    "prompt_tokens:H? completion_tokens:B? cached_prompt_tokens:H? event_lag_status:lag "
    "event_lag_ns:q? validity_flags:Q"
)
LAG_SCHEMA = (
    "per_request_index:H level_index:B reset_epoch:B replica_index:B group_index:B "
    "prompt_identity_sha256:sha status:lag match_basis:basis exclusion_flags:Q "
    "routing_decision_monotonic_ns:Q? gateway_terminal_monotonic_ns:Q? request_lifetime_ns:Q? "
    "publisher_flush_allowance_ns:Q store_observation_window_end_monotonic_ns:Q? "
    "next_same_identity_decision_monotonic_ns:Q? event_observed_monotonic_ns:Q? "
    "routing_to_event_observation_ns:q? event_sequence:Q? matched_token_block_digests:set "
    "excluded_shared_digest_count:H clock_pair_index:B validity_flags:Q"
)
MANIFEST_SCHEMA = (
    "per_request_index:H block_position:H token_block_digest:sha native_cached_key:key in_W:bool"
)
ENUMS = {"outcome": OUTCOMES, "lag": LAG_STATUS, "basis": MATCH_BASIS}


def digest_bytes(value, name, maximum=32, *, exact=True):
    if type(value) is not str or not re.fullmatch(r"(?:[0-9a-f]{2})*", value):
        raise RetentionError("retention_field_overflow", name)
    data = bytes.fromhex(value)
    if len(data) > maximum or (exact and len(data) != maximum):
        raise RetentionError("retention_field_overflow", name, maximum, len(data))
    return data


def pack_rows(rows, schema, limit, name):
    """Validate all columns/types before DEFLATE; no implicit field omission."""
    count(rows, limit, name)
    fields = [token.split(":") for token in schema.split()]
    keys = {field for field, _ in fields}
    data = bytearray()
    for row in rows:
        if set(row) != keys:
            raise RetentionError("retention_schema_overflow", name)
        bitmap = 0
        packed = bytearray()
        for i, (field, kind) in enumerate(fields):
            value = row[field]
            if kind.endswith("?"):
                if value is None:
                    bitmap |= 1 << i
                    value = 0
                kind = kind[:-1]
            if kind in ENUMS:
                packed.append(enum(value, ENUMS[kind], field))
            elif kind == "bool":
                if type(value) is not bool:
                    raise RetentionError("retention_field_overflow", field)
                packed.append(int(value))
            elif kind == "sha":
                packed.extend(digest_bytes(value, field))
            elif kind == "key":
                key = digest_bytes(value, field, 64, exact=False)
                packed.extend(bytes([len(key)]) + key.ljust(64, b"\0"))
            elif kind == "set":
                count(value, 384 if name.startswith("run4") else 2, field)
                if value != sorted(set(value)):
                    raise RetentionError("retention_schema_overflow", field)
                packed.extend(struct.pack("<H", len(value)))
                for child in value:
                    packed.extend(digest_bytes(child, field))
            else:
                integer(value, struct.calcsize(kind) * 8, field, signed=kind == "q")
                packed.extend(struct.pack("<" + kind, value))
        data.extend(bitmap.to_bytes((len(fields) + 7) // 8, "little"))
        data.extend(packed)
    return bytes(data)


def unpack_rows(data, schema, number):
    fields = [token.split(":") for token in schema.split()]
    position, rows = 0, []
    for _ in range(number):
        size = (len(fields) + 7) // 8
        bitmap = int.from_bytes(data[position : position + size], "little")
        position += size
        row = {}
        for i, (field, kind) in enumerate(fields):
            nullable = kind.endswith("?")
            kind = kind.rstrip("?")
            if kind in ENUMS or kind == "bool":
                value = data[position]
                value = ENUMS[kind][value] if kind in ENUMS else bool(value)
                position += 1
            elif kind == "sha":
                value = data[position : position + 32].hex()
                position += 32
            elif kind == "key":
                size = data[position]
                value = data[position + 1 : position + 1 + size].hex()
                position += 65
            elif kind == "set":
                size = struct.unpack_from("<H", data, position)[0]
                position += 2
                value = [data[p : p + 32].hex() for p in range(position, position + size * 32, 32)]
                position += size * 32
            else:
                value = struct.unpack_from("<" + kind, data, position)[0]
                position += struct.calcsize(kind)
            row[field] = None if nullable and bitmap & (1 << i) else value
        rows.append(row)
    if position != len(data):
        raise RetentionError("retention_schema_overflow", "packed_trailing_bytes")
    # Recovery applies entry validation too, including flags, ranges and joins below.
    if pack_rows(rows, schema, number, "recovered") != data:
        raise RetentionError("retention_schema_overflow", "noncanonical_packed_rows")
    return rows


def validate_exact(run, *, number):
    requests, lags = run["requests"], run["lags"]
    limit = 3624 if number == 3 else 14259
    count(requests, limit, "requests_exact.v1")
    count(lags, limit, "lag_exact.v1")
    if len(requests) != len(lags):
        raise RetentionError("retention_join_failure", "lag_exact.v1")
    level_counts = Counter(row["level_index"] for row in requests)
    if number == 3:
        for level, n in level_counts.items():
            if n > (1 if level < 24 else 1200):
                raise RetentionError(
                    "retention_count_ceiling_hit",
                    f"run3.level.{level}",
                    1 if level < 24 else 1200,
                    n,
                )
    else:
        ceilings = [45 * c for c in (1, 2, 4, 8, 12, 16, 24, 32, 48, 64)]
        ceilings += [n for n in (32, 48, 56, 60, 68, 76, 92) for _ in range(2)]
        ceilings += [180, 720, 2880, 60, 60]
        for level, n in level_counts.items():
            integer(level, 8, "level_index", maximum=28)
            if n > ceilings[level]:
                raise RetentionError(
                    "retention_count_ceiling_hit", f"run4.level.{level}", ceilings[level], n
                )
    for i, (request, lag) in enumerate(zip(requests, lags, strict=True)):
        if request["per_request_index"] != i or lag["per_request_index"] != i:
            raise RetentionError("retention_join_failure", "per_request_index")
        for key in (
            "level_index",
            "reset_epoch",
            "replica_index",
            "group_index",
            "prompt_identity_sha256",
        ):
            if request[key] != lag[key]:
                raise RetentionError("retention_join_failure", key)
        for key in ("replica_index", "group_index"):
            if request[key] != 0:
                raise RetentionError("retention_field_overflow", key, 0, request[key])
        if lag["exclusion_flags"] & ~127:
            raise RetentionError("retention_enum_overflow", "unknown_flag_bits")
        bounds = {
            "level_index": 26 if number == 3 else 28,
            "worker_index": 63,
            "worker_cycle": 44,
            "prefix_ordinal": 91,
            "reset_epoch": 2 if number == 3 else 9,
        }
        for key, bound in bounds.items():
            integer(
                request[key],
                64,
                key,
                nullable=key in ("worker_index", "worker_cycle", "prefix_ordinal"),
                maximum=bound,
            )
        if number == 4 and (request["level_index"] < 10 or 24 <= request["level_index"] < 27):
            concurrency = (
                (1, 2, 4, 8, 12, 16, 24, 32, 48, 64)[request["level_index"]]
                if request["level_index"] < 10
                else (4, 16, 64)[request["level_index"] - 24]
            )
            integer(request["worker_index"], 8, "worker_index", maximum=concurrency - 1)
        prompt = request["prompt_tokens"]
        if prompt is not None and prompt not in ((34,) if number == 3 else (6144, 1024)):
            raise RetentionError("retention_field_overflow", "prompt_tokens")
        for key, bound in (
            ("completion_tokens", 1 if number == 3 or prompt == 1024 else 128),
            ("cached_prompt_tokens", prompt or (34 if number == 3 else 6144)),
        ):
            integer(request[key], 64, key, nullable=True, maximum=bound)
        if lag["publisher_flush_allowance_ns"] != 1_000_000_000:
            raise RetentionError("retention_field_overflow", "publisher_flush_allowance_ns")
        integer(lag["clock_pair_index"], 8, "clock_pair_index", maximum=7 if number == 3 else 23)
        count(
            lag["matched_token_block_digests"],
            2 if number == 3 else 64 if prompt == 1024 else 384,
            "matched_token_block_digests",
        )
        integer(
            lag["excluded_shared_digest_count"],
            16,
            "excluded_shared_digest_count",
            maximum=2 if number == 3 else 64 if prompt == 1024 else 384,
        )
        if (
            request["event_lag_status"] != lag["status"]
            or request["event_lag_ns"] != lag["routing_to_event_observation_ns"]
        ):
            raise RetentionError("retention_join_failure", "event_lag")
    pack_rows(requests, REQUEST_SCHEMA, limit, "requests_exact.v1")
    pack_rows(lags, LAG_SCHEMA, limit, "run4.lag" if number == 4 else "lag_exact.v1")
    if number == 3:
        validate_run3_constants(run)


def validate_run3_constants(run):
    """Reject identity entropy outside the registered fixed-prompt Run 3 source."""
    requests = run["requests"]
    if len({row["prompt_identity_sha256"] for row in requests}) != 1:
        raise RetentionError("retention_join_failure", "run3_prompt_identity_constant")
    membership = run["membership"]
    if len(membership) != len(requests) * 2:
        raise RetentionError("retention_join_failure", "run3_membership_coverage")
    seen, by_position = set(), {0: set(), 1: set()}
    for row in membership:
        request_index = integer(row["per_request_index"], 16, "per_request_index")
        position = integer(row["block_position"], 16, "block_position", maximum=1)
        if request_index >= len(requests) or (request_index, position) in seen:
            raise RetentionError("retention_join_failure", "run3_membership_coverage")
        seen.add((request_index, position))
        digest = digest_bytes(row["token_block_digest"], "token_block_digest")
        native_key = digest_bytes(
            row["native_cached_key"], "native_cached_key", maximum=64, exact=False
        )
        by_position[position].add((digest, native_key))
    expected = {(index, position) for index in range(len(requests)) for position in (0, 1)}
    if seen != expected or any(len(values) != 1 for values in by_position.values()):
        raise RetentionError("retention_join_failure", "run3_membership_constants")
    registered_digests = {digest for values in by_position.values() for digest, _ in values}
    for lag in run["lags"]:
        if any(
            digest_bytes(value, "matched_token_block_digests") not in registered_digests
            for value in lag["matched_token_block_digests"]
        ):
            raise RetentionError("retention_join_failure", "run3_lag_matched_digest_subset")


def protected_bytes(value):
    """The protected rows are retained byte-equivalently, with conservation checks."""
    if value["schema"] != "rewarm_convergence_compact.v1":
        raise RetentionError("retention_schema_overflow", "rewarm_convergence_compact.v1")
    allocations = {
        "reset_rows": (3, 512),
        "cold_rows": (24, 1024),
        "window_rows": (36, 512),
        "histogram_rows": (720, 544),
    }
    if set(value) != {"schema", "header", *allocations}:
        raise RetentionError("retention_schema_overflow", "protected_fields")
    widths = {"reset_rows": 11, "cold_rows": 16, "window_rows": 19, "histogram_rows": 23}
    seen = {name: set() for name in allocations}
    for name, (maximum, width) in allocations.items():
        count(value[name], maximum, name)
        if len(value[name]) != maximum:
            raise RetentionError("retention_schema_overflow", f"missing_{name}")
        for row in value[name]:
            if len(row) != widths[name]:
                raise RetentionError("retention_schema_overflow", name + ".width")
            integer(row[0], 8, name + ".reset", maximum=2)
            key = row[0] if name == "reset_rows" else tuple(row[:2])
            if key in seen[name]:
                raise RetentionError("retention_join_failure", name + ".duplicate")
            seen[name].add(key)
            bools, strings = (), ()
            if name == "reset_rows":
                bools, strings = (2, 7), (1, 10)
                enum(row[1], ("success", "failed", "missing", "unestablished"), "reset_result")
                enum(
                    row[10],
                    ("unestablished", "converged", "censored", "timeout", "missing", "invalid"),
                    "convergence_status",
                )
            elif name == "cold_rows":
                bools, strings = (12, 13, 14), (2, 7, 15)
                integer(row[1], 8, "cold_ordinal", maximum=7)
                if not isinstance(row[2], str) or not re.fullmatch(r"[0-9a-f]{32,64}", row[2]):
                    raise RetentionError("retention_schema_overflow", "cold_request_identity")
                enum(row[7], OUTCOMES, "cold_outcome")
                enum(row[15], ("valid", "invalid", "missing", "partial"), "cold_status")
            elif name == "window_rows":
                bools, strings = (14, 15, 16, 17), (18,)
                integer(row[1], 8, "window_index", maximum=11)
                enum(row[18], ("complete", "partial", "missing", "invalid"), "window_status")
            else:
                bools = (2,)
                integer(row[1], 8, "bin_index", maximum=239)
            for i, atom in enumerate(row):
                if i in bools:
                    if type(atom) is not bool:
                        raise RetentionError("retention_enum_overflow", name + ".bool")
                elif i not in strings:
                    integer(atom, 64, name + ".integer", nullable=True)
            byte_bound(encoded(row) + b",", width, name)
            for atom in row:
                if type(atom) is int:
                    integer(atom, 64, name)
                elif atom is not None and type(atom) not in (bool, str):
                    raise RetentionError("retention_field_overflow", name)
    byte_bound(
        encoded({"schema": value["schema"], "header": value["header"]}), 16384, "protected_header"
    )
    hist = {}
    for row in value["histogram_rows"]:
        if (
            len(row) != 23
            or not 0 <= row[0] <= 2
            or not 0 <= row[1] < 240
            or type(row[2]) is not bool
        ):
            raise RetentionError("retention_schema_overflow", "histogram_row")
        if tuple(row[:2]) in hist or (row[1] >= 120 and any(row[3:13])) or row[22] != 0:
            raise RetentionError("retention_conservation_failure", "histogram_row")
        hist[tuple(row[:2])] = row
    for reset in range(3):
        rows = [row for (epoch, _), row in hist.items() if epoch == reset]
        dispatch = sum(sum(row[3:13]) for row in rows)
        finalized = sum(sum(row[13:23]) for row in rows)
        pending = sum(row[12] for row in rows)
        if dispatch != finalized + pending:
            raise RetentionError("retention_conservation_failure", "protected_outcomes")
    for row in value["window_rows"]:
        if len(row) != 19 or row[1] not in range(12):
            raise RetentionError("retention_schema_overflow", "window_row")
        bins = [hist.get((row[0], i)) for i in range(row[1] * 10, (row[1] + 1) * 10)]
        if (
            any(child is None for child in bins)
            or row[12] != sum(sum(child[3:13]) for child in bins)
            or row[13] != sum(sum(child[13:23]) for child in bins)
        ):
            raise RetentionError("retention_conservation_failure", "window_outcomes")
    data = encoded(value)
    return data


def encode_run3(run):
    validate_exact(run, number=3)
    protected = protected_bytes(run["rewarm_convergence_compact"])
    packed = {}
    report = {}
    for name, schema, limit in (
        ("requests", REQUEST_SCHEMA, 3624),
        ("lags", LAG_SCHEMA, 3624),
        ("membership", MANIFEST_SCHEMA, 7248),
    ):
        data = pack_rows(run[name], schema, limit, name)
        packed[name] = {"schema": schema, "count": len(run[name]), "data": unpadded(data).decode()}
        report[name] = {
            "packed_bytes": len(data),
            "base64_bytes": len(unpadded(data)),
        }
    membership_keys = set()
    for row in run["membership"]:
        key = (row["per_request_index"], row["block_position"])
        if key in membership_keys or key[0] >= len(run["requests"]) or key[1] > 1:
            raise RetentionError("retention_join_failure", "membership")
        membership_keys.add(key)
    if len(membership_keys) != len(run["requests"]) * 2:
        raise RetentionError("retention_join_failure", "membership_coverage")
    for reset in range(3):
        sustained_n = sum(row["level_index"] == 24 + reset for row in run["requests"])
        hist_n = sum(
            sum(row[3:13])
            for row in run["rewarm_convergence_compact"]["histogram_rows"]
            if row[0] == reset
        )
        if sustained_n != hist_n:
            raise RetentionError("retention_conservation_failure", "sustained_cohort")
    from .stage_c_resources import legends, level_summaries, pack_summaries

    measurements = level_summaries(run, 27)
    dictionaries = run["dictionaries"]
    if set(dictionaries) != {"clocks", "levels", "resets"}:
        raise RetentionError("retention_schema_overflow", "run3_dictionaries")
    for name, fmt, expected in (
        ("clocks", "QQqQQQQQ", 8),
        ("levels", "Q" * 7, 27),
        ("resets", "Q" * 4, 3),
    ):
        if len(dictionaries[name]) != expected:
            raise RetentionError("retention_join_failure", "run3_" + name)
        fixed_rows(dictionaries[name], fmt, expected, "run3_" + name)
    validate_cache_config(run["cache_config"])
    native = native_bytes(run["native_counters"])
    measurement_data = b"".join(
        native[i * 176 : (i + 1) * 176] + pack_summaries(row) for i, row in enumerate(measurements)
    )
    if len(measurement_data) != 27 * 512:
        raise RetentionError("retention_join_failure", "run3_measurement_count")
    report["level_measurements"] = {"packed_bytes": len(measurement_data)}
    document = {
        "schema": "stage-c-remainder-run3.v1",
        "level_measurements": unpadded(measurement_data).decode("ascii"),
        "gateway_cpu_ticks_per_second": run["gateway_cpu_ticks_per_second"],
        "measurement_legend": {
            "native": " ".join(key + ":" + NATIVE_KINDS[key] for key in NATIVE_FIELDS),
            **legends(),
        },
        "source_binding": source_bindings(run),
        "tables": packed,
        "rewarm_convergence_compact": json.loads(protected),
        "dictionaries": run["dictionaries"],
        "receipt": run["retention_receipt"],
        "cache_config": run["cache_config"],
        "index_entries": 0,
        "routing_consumer_backlog": None,
        "index_status": "stateless_not_applicable",
    }
    # Every entry guard above precedes the first DEFLATE invocation.
    protected_gzip = gzip.compress(protected, mtime=0)
    byte_bound(protected_gzip, 480000, "protected_component")
    spans = [
        (
            "framing.header",
            encoded(
                {
                    key: value
                    for key, value in document.items()
                    if key not in ("tables", "rewarm_convergence_compact", "level_measurements")
                }
            )[:-1]
            + b',"tables":{',
        )
    ]
    for i, (name, row) in enumerate(packed.items()):
        spans.append((name, (b"," if i else b"") + encoded(name) + b":" + encoded(row)))
    spans.extend(
        [
            ("framing.tables_end", b'},"rewarm_convergence_compact":'),
            ("protected", protected),
            ("framing.measurements_key", b',"level_measurements":'),
            ("level_measurements", encoded(document["level_measurements"])),
            ("framing.end", b"}"),
        ]
    )
    data, wire_report = compressed_sections(spans)
    for name, row in packed.items():
        report[name]["standalone_gzip_bytes"] = len(gzip.compress(row["data"].encode(), mtime=0))
    report["protected"] = {
        "raw_bytes": len(protected),
        "standalone_gzip_bytes": len(protected_gzip),
        "allocation": 480000,
    }
    report["member1"] = wire_report
    report["member2"] = {
        "status": "not_applicable",
        "reason": "Run 3 has no Run 4 projection extension",
    }
    return data, report


COMPACT_SCHEMA = (
    "per_request_index:H level_index:B outcome:B event_lag_status:B dispatch_ns:Q "
    "first_content_ns:Q? terminal_ns:Q? censor_ns:Q? event_lag_ns:q? validity_flags:Q exclusion_flags:Q"
)
C_FIELDS = (
    "level_index arm phase_id exposure_id concurrency row_status load_mode duration_ns "
    "planned_load_s minimum_cycle_s sampler_started_before_load dispatch_n unmatched_dispatched_n "
    "censored_ttft_n screen_status screen_dispatch_n screen_completion_n screen_ttft_success_n "
    "screen_unsuccessful_n screen_exposure_start_ns screen_exposure_end_ns screen_ttft_p50_ns "
    "screen_prefix_match_n screen_prefix_equal_n diagnostic_status diagnostic_valid_n "
    "diagnostic_invalid_n preemption_delta running_peak waiting_peak"
).split()
C_MAX = (
    28,
    1,
    9,
    28,
    64,
    3,
    3,
    2**64 - 1,
    65535,
    65535,
    None,
    14259,
    14259,
    14259,
    3,
    14259,
    14259,
    14259,
    14259,
    2**64 - 1,
    2**64 - 1,
    2**64 - 1,
    60,
    60,
    3,
    48001,
    48001,
    2**32 - 1,
    65535,
    65535,
)
C_NULLABLE = {
    "duration_ns",
    "screen_exposure_start_ns",
    "screen_exposure_end_ns",
    "screen_ttft_p50_ns",
    "screen_prefix_match_n",
    "screen_prefix_equal_n",
    "preemption_delta",
    "running_peak",
    "waiting_peak",
}
NATIVE_FIELDS = (
    "usage_peak usage_valid_n usage_invalid_n hits_before hits_after queries_before queries_after "
    "hits_created_before hits_created_after queries_created_before queries_created_after "
    "bracket_before_ns bracket_after_ns hits_delta queries_delta counter_status "
    "preemptions_before preemptions_after preemptions_delta preemptions_status "
    "running_peak running_valid_n running_invalid_n waiting_peak waiting_valid_n waiting_invalid_n "
    "diagnostic_valid_n diagnostic_invalid_n counter_reset_n counter_missing_n"
).split()
NATIVE_FLOAT = {
    "usage_peak",
    "hits_created_before",
    "hits_created_after",
    "queries_created_before",
    "queries_created_after",
}


NATIVE_KINDS = {
    name: "d"
    if name in NATIVE_FLOAT
    else "B"
    if name.endswith("status")
    else "H"
    if name.endswith("_n") or name in ("running_peak", "waiting_peak")
    else "I"
    if name == "preemptions_delta"
    else "Q"
    for name in NATIVE_FIELDS
}


def native_bytes(rows):
    count(rows, 29, "native_counter_projection.v1")
    result = bytearray()
    for row in rows:
        if set(row) != set(NATIVE_FIELDS):
            raise RetentionError("retention_schema_overflow", "native_counter_projection.v1")
        integer(row["counter_status"], 8, "counter_status", maximum=3)
        integer(row["preemptions_status"], 8, "preemptions_status", maximum=3)
        for stem, status_field in (
            ("hits", "counter_status"),
            ("queries", "counter_status"),
            ("preemptions", "preemptions_status"),
        ):
            if row[status_field] == 0:
                before, after, delta = (
                    row[stem + "_before"],
                    row[stem + "_after"],
                    row[stem + "_delta"],
                )
                if before is None or after is None or after < before or delta != after - before:
                    raise RetentionError("retention_conservation_failure", stem + ".delta")
            elif row[stem + "_delta"] is not None:
                raise RetentionError("retention_conservation_failure", stem + ".invalid_delta")
        mask, data = 0, bytearray()
        for i, field in enumerate(NATIVE_FIELDS):
            value = row[field]
            if value is None:
                mask |= 1 << i
                value = 0
            kind = NATIVE_KINDS[field]
            if field in NATIVE_FLOAT:
                if (
                    type(value) not in (float, int)
                    or not math.isfinite(value)
                    or value < 0
                    or (field == "usage_peak" and value > 1)
                ):
                    raise RetentionError("retention_field_overflow", field)
            else:
                integer(
                    value,
                    struct.calcsize("<" + kind) * 8,
                    field,
                    maximum=3
                    if field.endswith("status")
                    else 48001
                    if field.endswith("_n")
                    else None,
                )
            data.extend(struct.pack("<" + kind, value))
        result.extend((data + struct.pack("<IQ", mask, 0)).ljust(176, b"\0"))
    return bytes(result)


def recover_native(data):
    rows = []
    for start in range(0, len(data), 176):
        offset, row = start, {}
        for field in NATIVE_FIELDS:
            kind = NATIVE_KINDS[field]
            row[field] = struct.unpack_from("<" + kind, data, offset)[0]
            offset += struct.calcsize("<" + kind)
        mask, flags = struct.unpack_from("<IQ", data, offset)
        if mask >> 30 or flags or any(data[offset + 12 : start + 176]):
            raise RetentionError("retention_schema_overflow", "native_mask_padding")
        for i, field in enumerate(NATIVE_FIELDS):
            if mask & (1 << i):
                if row[field] != 0:
                    raise RetentionError("retention_schema_overflow", "native_null_placeholder")
                row[field] = None
        rows.append(row)
    native_bytes(rows)
    return rows


def compact_requests(run, ids):
    result = bytearray()
    for row, lag, failure_tuple_id in zip(run["requests"], run["lags"], ids, strict=True):
        mask = sum(
            int(row[field] is None) << i
            for i, field in enumerate(
                ("first_content_ns", "terminal_ns", "censor_ns", "event_lag_ns")
            )
        )
        mask |= enum(row["outcome"], OUTCOMES, "administrative_outcome_id") << 4
        for field in ("validity_flags", "exclusion_flags"):
            value = row[field] if field == "validity_flags" else lag[field]
            integer(value, 64, field)
        result.extend(
            struct.pack(
                "<HBBBQQQQqQQB",
                row["per_request_index"],
                row["level_index"],
                failure_tuple_id,
                enum(row["event_lag_status"], LAG_STATUS, "event_lag_status"),
                row["dispatch_ns"],
                row["first_content_ns"] or 0,
                row["terminal_ns"] or 0,
                row["censor_ns"] or 0,
                row["event_lag_ns"] or 0,
                row["validity_flags"],
                lag["exclusion_flags"],
                mask,
            )
        )
    return bytes(result)


def screen_fields(requests, row):
    """Derive screen summaries only from resident request fields and c-row bounds."""
    start, end = row["screen_exposure_start_ns"], row["screen_exposure_end_ns"]
    screen = [
        request
        for request in requests
        if request["level_index"] == row["level_index"]
        and start is not None
        and end is not None
        and start <= request["dispatch_ns"] < end
    ]
    success = [request for request in screen if request["outcome"] == "completed"]
    ttft = [
        request["first_content_ns"] - request["dispatch_ns"]
        for request in success
        if request["first_content_ns"] is not None
    ]
    return {
        "screen_dispatch_n": len(screen),
        "screen_completion_n": len(success),
        "screen_ttft_success_n": len(ttft),
        "screen_unsuccessful_n": len(screen) - len(success),
        "screen_ttft_p50_ns": median(ttft),
    }


def level_rows(run, ids):
    rows = run["level_aggregates"]
    count(rows, 29, "c_level.v1")
    output = []
    for i, source in enumerate(rows):
        if set(source) != set(C_FIELDS):
            raise RetentionError("retention_schema_overflow", "c_level.v1")
        row = {key: source[key] for key in C_FIELDS}
        if row["level_index"] != i:
            raise RetentionError("retention_join_failure", "level_index")
        cohort = [request for request in run["requests"] if request["level_index"] == i]
        if row["dispatch_n"] != len(cohort):
            raise RetentionError("retention_conservation_failure", "dispatch_n")
        expected = screen_fields(cohort, row)
        for field, value in expected.items():
            if row[field] != value:
                raise RetentionError("retention_conservation_failure", field)
        for key, maximum in zip(C_FIELDS, C_MAX, strict=True):
            if key == "sampler_started_before_load":
                if type(row[key]) is not bool:
                    raise RetentionError("retention_field_overflow", key)
            else:
                integer(row[key], 64, key, nullable=key in C_NULLABLE, maximum=maximum)
        for key in ("diagnostic_valid_n", "diagnostic_invalid_n", "running_peak", "waiting_peak"):
            if row[key] != run["native_counters"][i][key]:
                raise RetentionError("retention_conservation_failure", key)
        if row["preemption_delta"] != run["native_counters"][i]["preemptions_delta"]:
            raise RetentionError("retention_conservation_failure", "preemption_delta")
        byte_bound(encoded(row), 1024, "c_level.v1")
        output.append(row)
    for request in run["requests"]:
        if request["level_index"] >= len(rows):
            raise RetentionError("retention_join_failure", "level_index")
    if len(run["native_counters"]) != len(rows):
        raise RetentionError("retention_join_failure", "native_level_index")
    # The code->count pairs have exactly the same source rows as dispatch_n.
    splits = Counter(
        (row["level_index"], code) for row, code in zip(run["requests"], ids, strict=True)
    )
    if sum(splits.values()) != len(run["requests"]):
        raise RetentionError("retention_conservation_failure", "failure_splits")
    return output


def validate_cache_config(config):
    if (
        set(config)
        != {"num_gpu_blocks", "block_size", "kv_cache_size_tokens", "enable_prefix_caching"}
        or type(config["enable_prefix_caching"]) is not bool
    ):
        raise RetentionError("retention_schema_overflow", "cache_config")
    for field in ("num_gpu_blocks", "block_size", "kv_cache_size_tokens"):
        integer(config[field], 64, "cache_config." + field)
    if (
        config["num_gpu_blocks"] != 3891
        or config["block_size"] != 16
        or config["kv_cache_size_tokens"] != 62256
    ):
        raise RetentionError("retention_join_failure", "frozen_cache_config")


def encode_run4(run):
    validate_exact(run, number=4)
    if len(run["failure_tuples"]) != len(run["requests"]):
        raise RetentionError("retention_join_failure", "failure_tuples")
    book, ids = failure_codebook(run["failure_tuples"])
    a = compact_requests(run, ids)
    from .stage_c_resources import legends, level_summaries, pack_summaries

    measurements = level_summaries(run, 29)
    native = native_bytes(run["native_counters"])
    if len(native) != 29 * 176:
        raise RetentionError("retention_join_failure", "native_level_count")
    b = b"".join(
        native[i * 176 : (i + 1) * 176] + pack_summaries(row) for i, row in enumerate(measurements)
    )
    rows = level_rows(run, ids)
    validate_cache_config(run["cache_config"])
    header = {
        "schema": "stage-c-remainder-run4.v1",
        "source_binding": source_bindings(run),
        "failure_split_codebook": book,
        "administrative_outcome_enum": list(OUTCOMES),
        "run_receipt": run["retention_receipt"],
        "measurement_schema": "level_measurements.v1",
        "gateway_cpu_ticks_per_second": run["gateway_cpu_ticks_per_second"],
        "measurement_legend": {
            "native": " ".join(key + ":" + NATIVE_KINDS[key] for key in NATIVE_FIELDS),
            **legends(),
        },
        "index_entries": 0,
        "routing_consumer_backlog": None,
        "index_status": "stateless_not_applicable",
        "cache_config": run["cache_config"],
    }
    prefix = encoded(header)[:-1] + b',"a":"'
    middle = b'","b":"'
    suffix = b'","c":' + encoded(rows) + b"}"
    # (c) includes surrounding JSON and gzip/DEFLATE framing, bounded before compression.
    byte_bound(prefix + middle + b'","c":' + b"}", 16384 - 128, "first_member_envelope")
    for data, allocation, name in ((a, 884058, "a.packed"), (b, 14848, "b.packed")):
        byte_bound(data, allocation, name)
    # The extension projector is mandatory. Missing evidence cannot become an empty member.
    extension = project_extension(run)
    projection_names = (
        "snapshot_counts.v1",
        "phase_measurement_summary.v1",
        "reference_outcomes.v1",
        "lag_witness.v1",
    )
    second_spans = [
        (
            "extension.envelope",
            b"\n"
            + encoded(
                {key: value for key, value in extension.items() if key not in projection_names}
            )[:-1],
        )
    ]
    second_spans.extend(
        (name, b"," + encoded(name) + b":" + encoded(extension[name])) for name in projection_names
    )
    second_spans.append(("extension.end", b"}"))
    extension_raw = b"".join(data for _, data in second_spans)
    byte_bound(extension_raw, 40772, "extension_json")
    first, first_report = member(
        [
            ("c.prefix", prefix, False),
            ("a", unpadded(a), True),
            ("c.middle", middle, False),
            ("b", unpadded(b), True),
            ("c.rows_suffix", suffix, False),
        ]
    )
    for name, allocation in (("a", 886361), ("b", 14888)):
        if first_report["sections"][name]["literal_charge_bytes"] > allocation:
            raise RetentionError(
                "retention_byte_ceiling_hit",
                name,
                allocation,
                first_report["sections"][name]["literal_charge_bytes"],
            )
    byte_bound(first, 963713, "member1")
    second, second_report = compressed_sections(second_spans)
    fallback = len(second) > 40900
    if fallback:
        second, second_report = member([(name, data, False) for name, data in second_spans])
    byte_bound(second, 40900, "member2")
    report = {
        "member1": first_report,
        "member2": {
            **second_report,
            "raw_bytes": len(extension_raw),
            "gzip_bytes": len(second),
            "gzip_framing_bytes": 18,
            "stored_fallback": fallback,
        },
        "a_packed_bytes": len(a),
        "b_packed_bytes": len(b),
        "c_row_raw_bytes": [len(encoded(row)) for row in rows],
        "first_envelope_raw_bytes": len(prefix) + len(middle) + len(suffix) - len(encoded(rows)),
    }
    return first + second, report


SNAPSHOT_FIELDS = (
    "snapshot_index:H cadence_slot:H arm:B phase:B reset_epoch:B status:B observed_ns:Q "
    "scan_duration_ns:Q sample_age_ns:Q cached:H shared:H non_shared:H evictable:H capacity:H "
    "reserved_null:H active_physical:H event_live:H owner_link_n:I unscheduled_holder_n:H "
    "temporary_cow_refs:Q temporary_fence_refs:Q unexplained_n:H ambiguous_n:H orphan_n:Q "
    "missing_owner_n:Q sequence_gap_n:Q sideband_drop_n:Q exporter_drop_n:Q missed_slot_n:I "
    "validity_flags:Q queue_depth:Q queue_read_ns:Q queue_read_cost_ns:Q queue_age_ns:Q "
    "join_sequence:Q presence_bitmap:Q"
)
QUANTITIES = ("cached", "shared", "non_shared", "evictable", "capacity", "lag", "queue")


def set_commitment(values):
    if values != sorted(set(values)):
        raise RetentionError("retention_schema_overflow", "matched_set")
    return hashlib.sha256(
        b"stage-c-matched-set-v1\0"
        + struct.pack(">I", len(values))
        + b"".join(digest_bytes(value, "matched_digest") for value in values)
    ).digest()


def vector(samples, start, end):
    """Integral uses adjacent valid actual samples, with no extrapolation over gaps."""
    eligible = [row for row in samples if start <= row[0] < end]
    valid = [row for row in eligible if row[1] is not None and row[2]]
    for stamp, value, ok in samples:
        integer(stamp, 64, "sample_ns")
        integer(value, 64, "sample_value", nullable=True)
        if type(ok) is not bool:
            raise RetentionError("retention_field_overflow", "sample_valid")
    if not valid:
        return bytes(32) + struct.pack("<IIQ", 0, len(eligible), 0) + bytes(24), False
    low, high = min(row[1] for row in valid), max(row[1] for row in valid)
    total = sum(row[1] for row in valid)
    integral = exposure = 0
    for left, right in zip(eligible, eligible[1:], strict=False):
        gap = right[0] - left[0]
        if gap <= 0:
            raise RetentionError("retention_schema_overflow", "sample_order")
        if (
            left[1] is not None
            and right[1] is not None
            and left[2]
            and right[2]
            and gap <= 200_000_000
        ):
            integral += left[1] * gap
            exposure += gap
    integer(total, 128, "sample_sum")
    integer(integral, 128, "sample_integral")
    return (
        struct.pack("<QQ", low, high)
        + total.to_bytes(16, "little")
        + struct.pack(
            "<IIQ",
            len(valid),
            len(eligible) - len(valid),
            next(row[0] for row in valid if row[1] == high),
        )
        + integral.to_bytes(16, "little")
        + struct.pack("<Q", exposure)
    ), True


def fixed_rows(rows, fmt, limit, name):
    count(rows, limit, name)
    result = bytearray()
    for row in rows:
        if len(row) != len(fmt):
            raise RetentionError("retention_schema_overflow", name)
        for value, kind in zip(row, fmt, strict=True):
            integer(value, struct.calcsize(kind) * 8, name, signed=kind == "q")
        result.extend(struct.pack("<" + fmt, *row))
    return bytes(result)


def project_extension(run):
    """Project all eligible host measurements and fixed selections, never choose valid rows."""
    exposures = run["exposures"]
    count(exposures, 29, "phase_measurement_summary.v1")
    if len(exposures) != 29:
        raise RetentionError("retention_join_failure", "missing_phase_slots")
    snapshots = run["snapshot_count_sources"]
    reference_levels = [*range(10, 24), 27, 28]
    manifests = run["reference_manifest"]
    if set(manifests) != {str(i) for i in reference_levels}:
        raise RetentionError("retention_join_failure", "reference_manifest_levels")
    manifest_hashes = []
    for level in reference_levels:
        identities = manifests[str(level)]
        cohort = [r for r in run["requests"] if r["level_index"] == level]
        if len(cohort) > len(identities) or len(set(identities)) != len(identities):
            raise RetentionError("retention_join_failure", "reference_manifest_count")
        ordinals = set()
        for request in cohort:
            ordinal = request["prefix_ordinal"]
            if (
                ordinal is None
                or ordinal >= len(identities)
                or ordinal in ordinals
                or request["prompt_identity_sha256"] != identities[ordinal]
            ):
                raise RetentionError("retention_join_failure", "reference_prefix_identity")
            ordinals.add(ordinal)
        manifest_hashes.append(
            hashlib.sha256(
                b"stage-c-reference-manifest-v1\0"
                + struct.pack(">I", len(identities))
                + b"".join(digest_bytes(v, "reference_identity") for v in identities)
            ).hexdigest()
        )
    if manifest_hashes != run["extension_header"]["reference_manifest_hashes"]:
        raise RetentionError("retention_join_failure", "reference_manifest_binding")
    for replay in (17, 28):
        population = [r for r in run["requests"] if r["level_index"] == replay - 1]
        replay_rows = [r for r in run["requests"] if r["level_index"] == replay]
        population_by_ordinal = {r["prefix_ordinal"]: r for r in population}
        matching = [
            (population_by_ordinal[b["prefix_ordinal"]], b)
            for b in replay_rows
            if b["prefix_ordinal"] in population_by_ordinal
            and population_by_ordinal[b["prefix_ordinal"]]["prompt_identity_sha256"]
            == b["prompt_identity_sha256"]
        ]
        equal = sum(
            a["cached_prompt_tokens"] is not None
            and b["cached_prompt_tokens"] is not None
            and a["cached_prompt_tokens"] == b["cached_prompt_tokens"]
            for a, b in matching
        )
        c = run["level_aggregates"][replay]
        if c["row_status"] == 2:
            if c["screen_prefix_match_n"] is not None or c["screen_prefix_equal_n"] is not None:
                raise RetentionError("retention_conservation_failure", "missing_reference_screen")
        elif c["screen_prefix_match_n"] != len(matching) or c["screen_prefix_equal_n"] != equal:
            raise RetentionError("retention_conservation_failure", "reference_equality_counts")
    count(snapshots, 48001, "snapshot_exact.v1")
    pack_rows(snapshots, SNAPSHOT_FIELDS, 48001, "snapshot_count_sources")
    slots = set()
    for snapshot in snapshots:
        slot = snapshot["cadence_slot"]
        integer(slot, 16, "cadence_slot", maximum=48000)
        if slot in slots:
            raise RetentionError("retention_join_failure", "duplicate_cadence_slot")
        slots.add(slot)
        for field, maximum in (
            ("arm", 3),
            ("phase", 4),
            ("reset_epoch", 9),
            ("status", 3),
            ("cached", 3891),
            ("shared", 3891),
            ("non_shared", 3891),
            ("evictable", 3891),
            ("capacity", 3891),
            ("reserved_null", 3891),
            ("active_physical", 3891),
            ("event_live", 3891),
            ("owner_link_n", 128 * 512),
            ("unscheduled_holder_n", 128),
        ):
            integer(snapshot[field], 64, field, maximum=maximum)
    selected, summaries = bytearray(), bytearray()
    selected_indexes = []
    for level, phase in enumerate(exposures):
        if set(phase) != set(
            "start_ns end_ns arm phase reset_epoch samples matcher_rule_violations missing_duplicate_joins validity_flags source_reconciliation".split()
        ):
            raise RetentionError("retention_schema_overflow", "phase_fields")
        start, end = phase["start_ns"], phase["end_ns"]
        integer(start, 64, "exposure_start")
        integer(end, 64, "exposure_end")
        if end < start or phase["arm"] not in (0, 1):
            raise RetentionError("retention_field_overflow", "exposure")
        patched = phase["arm"] == 1
        integer(phase["arm"], 8, "phase_arm", maximum=1)
        integer(phase["phase"], 8, "phase_kind", maximum=4)
        integer(phase["reset_epoch"], 8, "phase_epoch", maximum=9)
        if (
            patched != (level >= 24)
            or phase["reset_epoch"] != run["level_aggregates"][level]["phase_id"]
        ):
            raise RetentionError("retention_join_failure", "phase_level_epoch")
        quantities = QUANTITIES if patched else ("cached", "lag")
        if set(phase["samples"]) != set(quantities):
            raise RetentionError("retention_schema_overflow", "phase_quantity_fields")
        vectors, presence = bytearray(), 0
        for i, quantity in enumerate(quantities):
            samples = phase["samples"][quantity]
            if quantity == "lag":
                samples = [
                    [
                        row["routing_decision_monotonic_ns"],
                        row["routing_to_event_observation_ns"],
                        True,
                    ]
                    for row in run["lags"]
                    if row["level_index"] == level and row["status"] == "observed"
                ]
            count(samples, 48001, "phase_samples")
            data, present = vector(samples, start, end)
            presence |= int(present) << i
            vectors.extend(data)
        scope = fixed_rows(
            [[phase["arm"], phase["phase"], phase["reset_epoch"], level, start, end]],
            "BBBBQQ",
            1,
            "phase_scope",
        )
        cohort = [row for row in run["requests"] if row["level_index"] == level]
        lags = [row for row in run["lags"] if row["level_index"] == level]
        reconciliation = [
            len(cohort),
            len(cohort),
            len(lags),
            sum(row["status"] in LAG_STATUS[:2] for row in lags),
            sum(row["excluded_shared_digest_count"] for row in lags),
            sum(row["status"] == "invalid_clock" for row in lags),
            phase["matcher_rule_violations"],
            phase["missing_duplicate_joins"],
        ]
        row = (
            scope
            + vectors
            + fixed_rows([reconciliation], "I" * 8, 1, "request_reconciliation")
            + fixed_rows([[phase["validity_flags"]]], "Q", 1, "phase_validity")
            + fixed_rows([phase["source_reconciliation"]], "Q" * 8, 1, "source_reconciliation")
            + struct.pack("<Q", presence)
        )
        row = row.ljust(640 if patched else 288, b"\0")
        byte_bound(row, 640 if patched else 288, "phase_measurement_summary.v1")
        summaries.extend(row)
        if patched:
            # Select nominal cadence slot, even when the source snapshot is missing/invalid.
            midpoint = (start + end) // 2
            slot = min(
                range(48001),
                key=lambda i: (abs(run["cadence_start_ns"] + i * 100_000_000 - midpoint), i),
            )
            matches = [row for row in snapshots if row["cadence_slot"] == slot]
            if run["level_aggregates"][level]["row_status"] == 2:
                matches = []
            if not matches:
                source = {token.split(":")[0]: 0 for token in SNAPSHOT_FIELDS.split()}
                source.update(
                    cadence_slot=slot,
                    arm=1,
                    phase=phase["phase"],
                    reset_epoch=phase["reset_epoch"],
                    status=2,
                )
            else:
                source = matches[0]
                if (source["arm"], source["phase"], source["reset_epoch"]) != (
                    1,
                    phase["phase"],
                    phase["reset_epoch"],
                ):
                    raise RetentionError("retention_join_failure", "snapshot_phase_epoch")
            data = pack_rows([source], SNAPSHOT_FIELDS, 1, "snapshot_counts.v1")
            # This row has no nullable fields; the schema's bitmap adds five unused bytes.
            data = data[(len(SNAPSHOT_FIELDS.split()) + 7) // 8 :]
            byte_bound(data, 174, "snapshot_counts.v1")
            selected.extend(data.ljust(176, b"\0"))
            selected_indexes.append(source["snapshot_index"])
    byte_bound(bytes(summaries), 10112, "phase_measurement_summary.v1")
    byte_bound(bytes(selected), 880, "snapshot_counts.v1")
    references = bytearray()
    for request in run["requests"]:
        ordinal = request["prefix_ordinal"]
        if ordinal is not None:
            cached = request["cached_prompt_tokens"]
            integer(cached, 16, "cached_prompt_tokens", nullable=True, maximum=1024)
            references.extend(
                struct.pack(
                    "<HBBHBB",
                    request["per_request_index"],
                    request["level_index"],
                    ordinal,
                    cached or 0,
                    enum(request["outcome"], OUTCOMES, "reference_outcome"),
                    int(cached is None),
                )
            )
    byte_bound(bytes(references), 7872, "reference_outcomes.v1")
    witnesses = bytearray()
    witness_schema = LAG_SCHEMA.replace("matched_token_block_digests:set ", "")
    for level in range(len(exposures)):
        candidates = [row for row in run["lags"] if row["level_index"] == level]
        if not candidates:
            # An absent phase has an explicit absent slot, never a replacement witness.
            witnesses.extend(bytes(192))
            continue
        source = candidates[0]
        row = {key: value for key, value in source.items() if key != "matched_token_block_digests"}
        data = pack_rows([row], witness_schema, 1, "lag_witness.v1")
        data += struct.pack("<H", len(source["matched_token_block_digests"])) + set_commitment(
            source["matched_token_block_digests"]
        )
        byte_bound(data, 192, "lag_witness.v1")
        witnesses.extend(data.ljust(192, b"\0"))
    extension = {
        "schema": "stage-c-remainder-extension.v1",
        "source_binding": source_bindings(run),
        "snapshot_counts.v1": unpadded(bytes(selected)).decode(),
        "phase_measurement_summary.v1": unpadded(bytes(summaries)).decode(),
        "reference_outcomes.v1": unpadded(bytes(references)).decode(),
        "lag_witness.v1": unpadded(bytes(witnesses)).decode(),
    }
    header = run["extension_header"]
    if set(header) != {
        "clocks",
        "levels",
        "epochs",
        "global_counters",
        "first_hit_receipts",
        "reference_manifest_hashes",
    }:
        raise RetentionError("retention_schema_overflow", "extension_header_fields")
    for name, fmt, maximum in (
        ("clocks", "QQqQQQQQ", 24),
        ("levels", "Q" * 4, 29),
        ("epochs", "Q" * 4, 10),
        ("global_counters", "Q", 64),
        ("first_hit_receipts", "Q" * 8, 8),
    ):
        extension[name] = unpadded(fixed_rows(header[name], fmt, maximum, name)).decode()
    hashes = header["reference_manifest_hashes"]
    count(hashes, 16, "reference_manifest_hashes")
    extension["reference_manifest_hashes"] = unpadded(
        b"".join(digest_bytes(value, "reference_manifest_sha256") for value in hashes)
    ).decode()
    envelope = {
        key: value
        for key, value in extension.items()
        if key
        not in (
            "snapshot_counts.v1",
            "phase_measurement_summary.v1",
            "reference_outcomes.v1",
            "lag_witness.v1",
        )
    }
    byte_bound(encoded(envelope), 8192, "extension_envelope")
    return extension


def seal_registered(path, run):
    """Called by stage_c_digest.seal_digest on the actual checkpoint path."""
    pending = path.with_suffix(".pending")
    failure_path = path.with_name(path.name + ".failure.json")
    try:
        source_bindings(run)
        if run["run_number"] == 4:
            data, report = encode_run4(run)
        elif run["run_number"] == 3:
            data, report = encode_run3(run)
        else:
            raise RetentionError("retention_schema_overflow", "run_number")
        byte_bound(data, 1048576, "complete_digest")
        with pending.open("wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        pending.replace(path)
        failure_path.unlink(missing_ok=True)
        receipt = {
            "schema": "stage-c-registered-digest-receipt.v1",
            "run_number": run["run_number"],
            "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data),
            "path": path.name,
            "limit_bytes": 1048576,
            "registration": REGISTRATION,
            "event_lag_status": run["event_lag_status"],
            "per_request_detail_dropped": False,
            "per_request_count": len(run["requests"]),
            "sections": report,
        }
        if run["run_number"] == 3:
            protected = run["rewarm_convergence_compact"]
            receipt["protected"] = {
                "sha256": hashlib.sha256(encoded(protected)).hexdigest(),
                "row_counts": {
                    name: len(protected[name])
                    for name in ("reset_rows", "cold_rows", "window_rows", "histogram_rows")
                },
                "validity": "unestablished",
            }
        return receipt
    except RetentionError as error:
        write_json(
            failure_path,
            {
                "schema": "stage-c-retention-failure.v1",
                "registration": REGISTRATION,
                "run_number": run.get("run_number"),
                "observed_count": (
                    len(run["requests"]) if isinstance(run.get("requests"), list) else None
                ),
                **error.receipt,
            },
        )
        path.unlink(missing_ok=True)
        if run.get("run_number") == 3:
            try:
                return preserve_protected(path, run, error.receipt)
            except BaseException:
                # The failure receipt is already durable. Keep the refusal bound
                # to that receipt if protected-only recovery cannot be built.
                raise error from None
        raise
    except (KeyError, TypeError, IndexError, struct.error, ValueError, OverflowError) as error:
        schema_error = RetentionError("retention_schema_overflow", "registered_source")
        write_json(
            failure_path,
            {
                "schema": "stage-c-retention-failure.v1",
                "registration": REGISTRATION,
                "run_number": run.get("run_number"),
                "observed_count": (
                    len(run["requests"]) if isinstance(run.get("requests"), list) else None
                ),
                **schema_error.receipt,
                "failure_type": type(error).__name__,
            },
        )
        path.unlink(missing_ok=True)
        if run.get("run_number") == 3:
            failure = json.loads(failure_path.read_text(encoding="utf-8"))
            try:
                return preserve_protected(path, run, failure)
            except BaseException:
                raise schema_error from error
        raise schema_error from error
    finally:
        pending.unlink(missing_ok=True)


def preserve_protected(path, run, failure):
    pending = path.with_suffix(".pending")
    # Run 3 exact-row exhaustion invalidates lag, while the independently
    # validated protected convergence/outcome layout remains recoverable.
    protected = protected_bytes(run["rewarm_convergence_compact"])
    document = {
        "schema": "stage-c-remainder-run3-protected-only.v1",
        "source_binding": source_bindings(run),
        "rewarm_convergence_compact": json.loads(protected),
        "failure": failure,
        "exact_lag_status": "unavailable",
    }
    data = gzip.compress(encoded(document), mtime=0)
    byte_bound(data, 480000, "protected_component")
    with pending.open("wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    pending.replace(path)
    return {
        "schema": "stage-c-registered-digest-receipt.v1",
        "registration": REGISTRATION,
        "run_number": 3,
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
        "limit_bytes": 1048576,
        "path": path.name,
        "event_lag_status": "unavailable",
        "per_request_count": 0,
        "per_request_detail_dropped": True,
        "full_measured_session_acceptance": False,
        "failure": failure,
        "protected": {
            "sha256": hashlib.sha256(protected).hexdigest(),
            "row_counts": {
                name: len(run["rewarm_convergence_compact"][name])
                for name in ("reset_rows", "cold_rows", "window_rows", "histogram_rows")
            },
            "validity": "unestablished",
        },
    }


def final_metadata_projection(session):
    """Receipts reference recovered bounded digests; never repeat protected/source rows."""
    runs = []
    for number in range(1, 5):
        path = session / "sealed-runs" / f"run-{number}.digest.receipt.json"
        failure = session / "sealed-runs" / f"run-{number}.digest.json.gz.failure.json"
        if failure.exists():
            row = {
                "run_number": number,
                "status": "unavailable",
                "failure": json.loads(failure.read_text(encoding="utf-8")),
            }
            if number == 3 and path.exists():
                receipt = json.loads(path.read_text(encoding="utf-8"))
                if (
                    receipt.get("schema") == "stage-c-registered-digest-receipt.v1"
                    and receipt.get("run_number") == 3
                    and receipt.get("registration") == REGISTRATION
                    and isinstance(receipt.get("sha256"), str)
                    and isinstance(receipt.get("bytes"), int)
                    and isinstance(receipt.get("protected"), dict)
                    and isinstance(receipt.get("failure"), dict)
                    and receipt.get("event_lag_status") == "unavailable"
                    and receipt.get("per_request_count") == 0
                    and receipt.get("per_request_detail_dropped") is True
                    and receipt.get("full_measured_session_acceptance") is False
                ):
                    row.update(
                        status="protected_only",
                        digest_sha256=receipt["sha256"],
                        digest_bytes=receipt["bytes"],
                        protected=receipt["protected"],
                    )
            if row["status"] != "protected_only":
                archive_path = session / "sealed-runs" / f"run-{number}.receipt.json"
                if archive_path.exists():
                    archive_receipt = json.loads(archive_path.read_text(encoding="utf-8"))
                    if archive_receipt.get("measurement_digest", {}).get("status") == "refused":
                        row.update(status="refused", archive_receipt=archive_receipt)
            runs.append(row)
        elif path.exists():
            receipt = json.loads(path.read_text(encoding="utf-8"))
            runs.append(
                {
                    "run_number": number,
                    "status": "sealed",
                    "digest_sha256": receipt["sha256"],
                    "digest_bytes": receipt["bytes"],
                    "per_request_count": receipt["per_request_count"],
                    "event_lag_status": receipt["event_lag_status"],
                    "protected": receipt.get("protected"),
                }
            )
        else:
            runs.append({"run_number": number, "status": "not_sealed"})
    return {
        "schema": "stage-c-remainder-final-receipts.v1",
        "runs": runs,
        "acceptance": "unestablished",
        "run3_exact_lag_adequacy": "unestablished",
    }


def unpack_fixed(data, fmt):
    width = struct.calcsize("<" + fmt)
    if len(data) % width:
        raise RetentionError("retention_schema_overflow", "fixed_row_width")
    return [list(struct.unpack_from("<" + fmt, data, i)) for i in range(0, len(data), width)]


def recover_extension(extension, levels):
    result = {}
    raw = from_base64(extension["snapshot_counts.v1"])
    if len(raw) % 176:
        raise RetentionError("retention_schema_overflow", "snapshot_row_width")
    fields = [token.split(":") for token in SNAPSHOT_FIELDS.split()]
    fmt = "".join(kind for _, kind in fields)
    result["snapshot_counts"] = []
    for i in range(0, len(raw), 176):
        values = struct.unpack_from("<" + fmt, raw, i)
        if raw[i + 174 : i + 176] != b"\0\0":
            raise RetentionError("retention_schema_overflow", "snapshot_padding")
        result["snapshot_counts"].append(dict(zip((key for key, _ in fields), values, strict=True)))
    result["reference_outcomes"] = [
        dict(
            zip(
                (
                    "per_request_index",
                    "level_index",
                    "prefix_ordinal",
                    "cached_prompt_tokens",
                    "outcome",
                    "presence_status",
                ),
                row,
                strict=True,
            )
        )
        for row in unpack_fixed(from_base64(extension["reference_outcomes.v1"]), "HBBHBB")
    ]
    for row in result["reference_outcomes"]:
        row["outcome"] = OUTCOMES[row["outcome"]]
        row["cached_prompt_tokens"] = (
            None if row["presence_status"] & 1 else row["cached_prompt_tokens"]
        )
    schema = LAG_SCHEMA.replace("matched_token_block_digests:set ", "")
    witness_width = 134
    raw = from_base64(extension["lag_witness.v1"])
    result["lag_witnesses"] = []
    for i in range(0, len(raw), 192):
        if not any(raw[i : i + 192]):
            result["lag_witnesses"].append({"level_index": i // 192, "present": False})
            continue
        row = unpack_rows(raw[i : i + witness_width], schema, 1)[0]
        row["matched_digest_count"] = struct.unpack_from("<H", raw, i + witness_width)[0]
        row["matched_digest_set_sha256"] = raw[i + witness_width + 2 : i + witness_width + 34].hex()
        result["lag_witnesses"].append(row)
    raw, offset = from_base64(extension["phase_measurement_summary.v1"]), 0
    result["phase_summaries"] = []
    for level in levels:
        quantities = QUANTITIES if level["arm"] == 1 else ("cached", "lag")
        row, vectors = {"scope": unpack_fixed(raw[offset : offset + 20], "BBBBQQ")[0]}, {}
        position = offset + 20
        for quantity in quantities:
            low, high = struct.unpack_from("<QQ", raw, position)
            total = int.from_bytes(raw[position + 16 : position + 32], "little")
            valid_n, invalid_n, maximum_ns = struct.unpack_from("<IIQ", raw, position + 32)
            integral = int.from_bytes(raw[position + 48 : position + 64], "little")
            exposure = struct.unpack_from("<Q", raw, position + 64)[0]
            vectors[quantity] = {
                "min": low,
                "max": high,
                "sum": total,
                "valid_n": valid_n,
                "invalid_n": invalid_n,
                "maximum_ns": maximum_ns,
                "integral": integral,
                "exposure_ns": exposure,
            }
            position += 72
        row["vectors"] = vectors
        row["request_reconciliation"] = unpack_fixed(raw[position : position + 32], "I" * 8)[0]
        row["validity_flags"] = struct.unpack_from("<Q", raw, position + 32)[0]
        row["source_reconciliation"] = unpack_fixed(raw[position + 40 : position + 104], "Q" * 8)[0]
        row["presence"] = struct.unpack_from("<Q", raw, position + 104)[0]
        result["phase_summaries"].append(row)
        offset += 640 if level["arm"] == 1 else 288
    if offset != len(raw):
        raise RetentionError("retention_schema_overflow", "phase_summary_width")
    return result


def from_base64(value):
    if type(value) is not str or not re.fullmatch(r"[A-Za-z0-9+/]*", value):
        raise RetentionError("retention_schema_overflow", "base64")
    result = base64.b64decode(value + "=" * (-len(value) % 4), validate=True)
    if unpadded(result).decode() != value:
        raise RetentionError("retention_schema_overflow", "noncanonical_base64")
    return result


def recover_registered(data):
    """Recover exclusively from gzip bytes, checking schemas and composite bindings."""
    raw = gzip.decompress(data)
    decoder = json.JSONDecoder()
    text = raw.decode("ascii")
    first, end = decoder.raw_decode(text)
    if first["schema"] == "stage-c-remainder-run3-protected-only.v1":
        source_bindings({"source_binding": first["source_binding"]})
        protected_bytes(first["rewarm_convergence_compact"])
        return {
            "run_number": 3,
            "protected": first["rewarm_convergence_compact"],
            "failure": first["failure"],
            "exact_lag_status": "unavailable",
            "source_binding": first["source_binding"],
        }
    if first["schema"] == "stage-c-remainder-run3.v1":
        if text[end:].strip():
            raise RetentionError("retention_schema_overflow", "run3_trailing_document")
        tables = {
            name: unpack_rows(from_base64(row["data"]), row["schema"], row["count"])
            for name, row in first["tables"].items()
        }
        source_bindings({"source_binding": first["source_binding"]})
        protected_bytes(first["rewarm_convergence_compact"])
        from .stage_c_resources import unpack_summaries

        measurement_data = from_base64(first["level_measurements"])
        if len(measurement_data) != 27 * 512:
            raise RetentionError("retention_schema_overflow", "run3_measurement_count")
        measurements = [
            unpack_summaries(measurement_data[i + 176 : i + 512])
            for i in range(0, len(measurement_data), 512)
        ]
        return {
            "run_number": 3,
            "measurements": measurements,
            "native_counters": recover_native(
                b"".join(
                    measurement_data[i : i + 176] for i in range(0, len(measurement_data), 512)
                )
            ),
            "gateway_cpu_ticks_per_second": first["gateway_cpu_ticks_per_second"],
            **tables,
            "protected": first["rewarm_convergence_compact"],
            "dictionaries": first["dictionaries"],
            "cache_config": first["cache_config"],
            "index_entries": first["index_entries"],
            "routing_consumer_backlog": first["routing_consumer_backlog"],
            "source_binding": first["source_binding"],
        }
    if first["schema"] != "stage-c-remainder-run4.v1" or not text[end:].startswith("\n"):
        raise RetentionError("retention_schema_overflow", "run4_members")
    if first.get("administrative_outcome_enum") != list(OUTCOMES):
        raise RetentionError("retention_schema_overflow", "administrative_outcome_enum")
    second = json.loads(text[end:])
    if (
        second["schema"] != "stage-c-remainder-extension.v1"
        or first["source_binding"] != second["source_binding"]
    ):
        raise RetentionError("retention_join_failure", "member_source_binding")
    source_bindings({"source_binding": first["source_binding"]})
    a, b = from_base64(first["a"]), from_base64(first["b"])
    byte_bound(a, 884058, "a.packed")
    byte_bound(b, 14848, "b.packed")
    if len(a) % 62 or len(b) != 29 * 512:
        raise RetentionError("retention_schema_overflow", "row_width")
    tuples = decode_failures(first["failure_split_codebook"])
    requests = []
    fields = "per_request_index level_index failure_tuple_id event_lag_status dispatch_ns first_content_ns terminal_ns censor_ns event_lag_ns validity_flags exclusion_flags null_mask".split()
    for i in range(0, len(a), 62):
        row = dict(zip(fields, struct.unpack_from("<HBBBQQQQqQQB", a, i), strict=True))
        packed_mask = row["null_mask"]
        outcome_id = packed_mask >> 4
        row["null_mask"] = packed_mask & 15
        if outcome_id >= len(OUTCOMES):
            raise RetentionError("retention_enum_overflow", "administrative_outcome_id")
        if row["per_request_index"] != i // 62:
            raise RetentionError("retention_join_failure", "compact_index_or_null_mask")
        for bit, field in enumerate(
            ("first_content_ns", "terminal_ns", "censor_ns", "event_lag_ns")
        ):
            if row["null_mask"] & (1 << bit):
                if row[field] != 0:
                    raise RetentionError("retention_schema_overflow", "null_placeholder")
                row[field] = None
        row["outcome"] = OUTCOMES[outcome_id]
        row["failure_tuple"] = tuples[row["failure_tuple_id"]]
        row["event_lag_status"] = LAG_STATUS[row["event_lag_status"]]
        requests.append(row)
    from .stage_c_resources import unpack_summaries

    natives = recover_native(b"".join(b[i : i + 176] for i in range(0, len(b), 512)))
    measurements = [unpack_summaries(b[i + 176 : i + 512]) for i in range(0, len(b), 512)]
    for c_row in first["c"]:
        expected = screen_fields(requests, c_row)
        for field, value in expected.items():
            if c_row.get(field) != value:
                raise RetentionError("retention_conservation_failure", "recovered." + field)
    return {
        "run_number": 4,
        "requests": requests,
        "native_counters": natives,
        "measurements": measurements,
        "gateway_cpu_ticks_per_second": first["gateway_cpu_ticks_per_second"],
        "cache_config": first["cache_config"],
        "index_entries": first["index_entries"],
        "routing_consumer_backlog": first["routing_consumer_backlog"],
        "level_aggregates": first["c"],
        "extension": second,
        **recover_extension(second, first["c"]),
        "source_binding": first["source_binding"],
    }
