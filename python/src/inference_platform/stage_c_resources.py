"""Bounded host summaries; no individual resource trajectory is digest-resident."""

import math
import struct

from .stage_c_registered import RetentionError, count, integer

GATEWAY_SCHEMA = (
    "pid:I start_ticks:Q valid_n:H pid_change_n:H missing_n:H access_error_n:H "
    "non_monotonic_n:H identity_mismatch_n:H sample_n:H cpu_decrease_n:H missed_slot_n:H pair_n:H "
    "first_ns:Q last_ns:Q first_cpu_ticks:Q last_cpu_ticks:Q cpu_ticks:Q duration_ns:Q "
    "max_pair_ticks:Q max_pair_duration_ns:Q max_pair_end_ns:Q rss_min:Q rss_max:Q "
    "rss_max_ns:Q rss_integral:U rss_exposure_ns:Q rss_last:Q peak_rss_last:Q "
    "excluded_pair_n:H status:B"
)
EVICTION_SCHEMA = (
    "removed:Q covered_seconds:H gap_seconds:H max_per_second:Q max_time_ns:Q status:B flags:B"
)
HIST_SCHEMA = " ".join(f"bucket_{i}:I" for i in range(11)) + " count:Q sum_bits:Q status:B"
LOOKUP_BOUNDS = (0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1)
TOKENIZE_BOUNDS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5)


def pack_fixed(row, schema, size, mask_size):
    fields = [item.split(":") for item in schema.split()]
    if set(row) != {name for name, _ in fields}:
        raise RetentionError("retention_schema_overflow", "level_measurement_fields")
    data, mask = bytearray(), 0
    for i, (name, kind) in enumerate(fields):
        value = row[name]
        if name in ("status", "flags") and value is None:
            raise RetentionError("retention_enum_overflow", name)
        if value is None:
            mask |= 1 << i
            value = 0
        bits = 128 if kind == "U" else struct.calcsize("<" + kind) * 8
        integer(
            value,
            bits,
            name,
            maximum=3
            if name in ("status", "flags")
            else 48001
            if name.endswith("_n")
            else 4801
            if name in ("covered_seconds", "gap_seconds")
            else None,
        )
        if kind == "U":
            data.extend(value.to_bytes(16, "little"))
        else:
            data.extend(struct.pack("<" + kind, value))
    if schema == GATEWAY_SCHEMA:
        sample_fields = (
            "valid_n",
            "missing_n",
            "access_error_n",
            "non_monotonic_n",
            "identity_mismatch_n",
        )
        if any(row[name] is None for name in (*sample_fields, "sample_n")):
            raise RetentionError("retention_schema_overflow", "gateway_sample_counts")
        if sum(row[name] for name in sample_fields) != row["sample_n"]:
            raise RetentionError("retention_conservation_failure", "gateway_resources.sample_n")
    data.extend(mask.to_bytes(mask_size, "little"))
    if len(data) > size:
        raise RetentionError("retention_byte_ceiling_hit", "subrecord", size, len(data))
    return bytes(data).ljust(size, b"\0")


def unpack_fixed(data, schema, size, mask_size):
    if len(data) != size:
        raise RetentionError("retention_schema_overflow", "subrecord_width")
    result, offset = {}, 0
    fields = [item.split(":") for item in schema.split()]
    for name, kind in fields:
        width = 16 if kind == "U" else struct.calcsize("<" + kind)
        result[name] = int.from_bytes(data[offset : offset + width], "little")
        offset += width
    mask = int.from_bytes(data[offset : offset + mask_size], "little")
    if mask >> len(fields) or any(data[offset + mask_size :]):
        raise RetentionError("retention_schema_overflow", "subrecord_mask_padding")
    for i, (name, _) in enumerate(fields):
        if mask & (1 << i):
            if result[name]:
                raise RetentionError("retention_schema_overflow", "subrecord_null_placeholder")
            result[name] = None
    pack_fixed(result, schema, size, mask_size)
    return result


def gateway_summary(samples):
    count(samples, 48001, "gateway_samples")
    fields = [item.split(":")[0] for item in GATEWAY_SCHEMA.split()]
    result = dict.fromkeys(fields, None)
    counters = "valid_n pid_change_n missing_n access_error_n non_monotonic_n identity_mismatch_n sample_n cpu_decrease_n missed_slot_n pair_n excluded_pair_n".split()
    result.update(dict.fromkeys(counters, 0))
    result.update(cpu_ticks=0, duration_ns=0, rss_integral=0, rss_exposure_ns=0, status=2)
    anchor, previous, previous_valid, valid = None, None, False, []
    for sample in samples:
        result["sample_n"] += 1
        if set(sample) != set(
            "slot pid start_ticks monotonic_ns cpu_ticks rss_bytes peak_rss_bytes status".split()
        ):
            raise RetentionError("retention_schema_overflow", "gateway_sample")
        integer(sample["slot"], 16, "gateway_slot", maximum=48000)
        status = sample["status"]
        if status not in ("ok", "missing", "access_error"):
            raise RetentionError("retention_enum_overflow", "gateway_sample_status")
        good = status == "ok"
        result["missing_n"] += status == "missing"
        result["access_error_n"] += status == "access_error"
        if good:
            for name in (
                "pid",
                "start_ticks",
                "monotonic_ns",
                "cpu_ticks",
                "rss_bytes",
                "peak_rss_bytes",
            ):
                integer(sample[name], 32 if name == "pid" else 64, "gateway." + name)
            identity = sample["pid"], sample["start_ticks"]
            if anchor is None:
                anchor = identity
                result["pid"], result["start_ticks"] = identity
            good = identity == anchor
            if not good:
                result["identity_mismatch_n"] += 1
            if previous and previous["status"] == "ok":
                result["pid_change_n"] += identity != (previous["pid"], previous["start_ticks"])
        decreased, monotonic = False, True
        if previous:
            gap = sample["slot"] - previous["slot"]
            if gap <= 0:
                raise RetentionError("retention_join_failure", "gateway_slot_order")
            result["missed_slot_n"] += gap - 1
            same_anchor = (
                status == "ok"
                and previous["status"] == "ok"
                and (sample["pid"], sample["start_ticks"]) == anchor
                and (previous["pid"], previous["start_ticks"]) == anchor
            )
            if same_anchor:
                monotonic = sample["monotonic_ns"] > previous["monotonic_ns"]
                result["non_monotonic_n"] += not monotonic
                if good and previous_valid:
                    decreased = sample["cpu_ticks"] < previous["cpu_ticks"]
                    result["cpu_decrease_n"] += decreased
            pair = good and previous_valid and monotonic and not decreased and gap == 1
            if pair:
                delta = sample["cpu_ticks"] - previous["cpu_ticks"]
                duration = sample["monotonic_ns"] - previous["monotonic_ns"]
                result["pair_n"] += 1
                result["cpu_ticks"] += delta
                result["duration_ns"] += duration
                result["rss_integral"] += previous["rss_bytes"] * duration
                result["rss_exposure_ns"] += duration
                if result["max_pair_ticks"] is None or delta > result["max_pair_ticks"]:
                    result.update(
                        max_pair_ticks=delta,
                        max_pair_duration_ns=duration,
                        max_pair_end_ns=sample["monotonic_ns"],
                    )
            else:
                result["excluded_pair_n"] += 1
        good = good and monotonic
        if good:
            result["valid_n"] += 1
            valid.append(sample)
        previous, previous_valid = sample, good
    if valid:
        first, last = valid[0], valid[-1]
        maximum = max(row["rss_bytes"] for row in valid)
        result.update(
            first_ns=first["monotonic_ns"],
            last_ns=last["monotonic_ns"],
            first_cpu_ticks=first["cpu_ticks"],
            last_cpu_ticks=last["cpu_ticks"],
            rss_min=min(row["rss_bytes"] for row in valid),
            rss_max=maximum,
            rss_max_ns=next(row["monotonic_ns"] for row in valid if row["rss_bytes"] == maximum),
            rss_last=last["rss_bytes"],
            peak_rss_last=last["peak_rss_bytes"],
            status=1
            if any(
                result[key]
                for key in (
                    "pid_change_n",
                    "missing_n",
                    "access_error_n",
                    "non_monotonic_n",
                    "identity_mismatch_n",
                    "cpu_decrease_n",
                    "missed_slot_n",
                )
            )
            else 0,
        )
    pack_fixed(result, GATEWAY_SCHEMA, 176, 4)
    return result


def cpu_values(summary, ticks_per_second):
    integer(ticks_per_second, 64, "gateway_cpu_ticks_per_second")
    if not ticks_per_second:
        raise RetentionError("retention_field_overflow", "gateway_cpu_ticks_per_second")
    return {
        "level_mean_cores": summary["cpu_ticks"] * 1e9 / ticks_per_second / summary["duration_ns"]
        if summary["duration_ns"]
        else None,
        "max_delta_pair_cores": summary["max_pair_ticks"]
        * 1e9
        / ticks_per_second
        / summary["max_pair_duration_ns"]
        if summary["max_pair_duration_ns"]
        else None,
        "one_tick_per_100ms_cores": 10 / ticks_per_second,
    }


def eviction_summary(bins):
    count(bins, 4801, "eviction_bins")
    result = dict(
        removed=0,
        covered_seconds=0,
        gap_seconds=0,
        max_per_second=None,
        max_time_ns=None,
        status=2,
        flags=0,
    )
    seen = set()
    for row in bins:
        integer(row["second_ns"], 64, "eviction_bin_ns")
        if row["second_ns"] in seen:
            raise RetentionError("retention_join_failure", "eviction_duplicate_bin")
        seen.add(row["second_ns"])
        identities = row["removed_identities"]
        for value in identities:
            if not isinstance(value, str) or len(value) != 64:
                raise RetentionError("retention_schema_overflow", "removed_full_block_identity")
            try:
                bytes.fromhex(value)
            except ValueError as error:
                raise RetentionError(
                    "retention_schema_overflow", "removed_full_block_identity"
                ) from error
        if any(type(row[key]) is not bool for key in ("gap", "reset", "valid")):
            raise RetentionError("retention_enum_overflow", "eviction_status")
        result["flags"] |= int(row["reset"]) << 1
        if not row["valid"] or row["gap"] or row["reset"]:
            result["gap_seconds"] += 1
            result["flags"] |= 1
            continue
        n = len(set(identities))
        result["removed"] += n
        result["covered_seconds"] += 1
        if result["max_per_second"] is None or n > result["max_per_second"]:
            result.update(max_per_second=n, max_time_ns=row["second_ns"])
    if result["covered_seconds"]:
        result["status"] = 1 if result["gap_seconds"] else 0
    pack_fixed(result, EVICTION_SCHEMA, 32, 2)
    return result


def histogram_summary(bracket):
    result = dict.fromkeys([item.split(":")[0] for item in HIST_SCHEMA.split()], None)
    if type(bracket["reset"]) is not bool or type(bracket["missing"]) is not bool:
        raise RetentionError("retention_enum_overflow", "histogram_status")
    result["status"] = 2 if bracket["missing"] else 1 if bracket["reset"] else 0
    if result["status"] == 0:
        before, after = bracket["before"], bracket["after"]
        for row in (before, after):
            if len(row["buckets"]) != 11:
                raise RetentionError("retention_schema_overflow", "histogram_buckets")
            for value in row["buckets"]:
                integer(value, 64, "histogram_source_bucket")
            integer(row["count"], 64, "histogram_source_count")
            if row["buckets"] != sorted(row["buckets"]) or row["buckets"][-1] != row["count"]:
                raise RetentionError("retention_conservation_failure", "histogram_source")
            if type(row["sum"]) is not float or not math.isfinite(row["sum"]) or row["sum"] < 0:
                raise RetentionError("retention_field_overflow", "histogram_source_sum")
        deltas = [b - a for a, b in zip(before["buckets"], after["buckets"], strict=True)]
        delta_sum = after["sum"] - before["sum"]
        if deltas != sorted(deltas) or any(value < 0 for value in deltas) or delta_sum < 0:
            raise RetentionError("retention_conservation_failure", "histogram_unmarked_reset")
        result.update({f"bucket_{i}": value for i, value in enumerate(deltas)})
        result.update(
            count=after["count"] - before["count"],
            sum_bits=struct.unpack("<Q", struct.pack("<d", delta_sum))[0],
        )
    pack_fixed(result, HIST_SCHEMA, 64, 2)
    return result


def level_summaries(run, n):
    if len(run["measurement_sources"]) != n:
        raise RetentionError("retention_join_failure", "measurement_levels")
    cpu_values(
        dict(cpu_ticks=0, duration_ns=0, max_pair_ticks=None, max_pair_duration_ns=None),
        run["gateway_cpu_ticks_per_second"],
    )
    rows = []
    for i, source in enumerate(run["measurement_sources"]):
        if source["level_index"] != i:
            raise RetentionError("retention_join_failure", "measurement_level_index")
        rows.append(
            dict(
                gateway=gateway_summary(source["gateway_samples"]),
                eviction=eviction_summary(source["eviction_bins"]),
                lookup=histogram_summary(source["lookup"]),
                tokenize=histogram_summary(source["tokenize"]),
            )
        )
    return rows


def legends():
    return dict(
        gateway=GATEWAY_SCHEMA,
        eviction=EVICTION_SCHEMA,
        histogram=HIST_SCHEMA,
        lookup_bounds_seconds=[*LOOKUP_BOUNDS, "+Inf"],
        tokenize_bounds_seconds=[*TOKENIZE_BOUNDS, "+Inf"],
        gateway_status=["valid", "partial", "missing", "invalid"],
        eviction_status=["valid", "lower_bound", "missing", "invalid"],
        histogram_status=["valid", "reset", "missing", "invalid"],
    )


def pack_summaries(row):
    return (
        pack_fixed(row["gateway"], GATEWAY_SCHEMA, 176, 4)
        + pack_fixed(row["eviction"], EVICTION_SCHEMA, 32, 2)
        + pack_fixed(row["lookup"], HIST_SCHEMA, 64, 2)
        + pack_fixed(row["tokenize"], HIST_SCHEMA, 64, 2)
    )


def unpack_summaries(data):
    return dict(
        gateway=unpack_fixed(data[:176], GATEWAY_SCHEMA, 176, 4),
        eviction=unpack_fixed(data[176:208], EVICTION_SCHEMA, 32, 2),
        lookup=unpack_fixed(data[208:272], HIST_SCHEMA, 64, 2),
        tokenize=unpack_fixed(data[272:336], HIST_SCHEMA, 64, 2),
    )
