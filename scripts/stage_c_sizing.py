"""No-cost source-bound ceiling evidence through the real checkpoint serializer.

Run the Go host-input traversal first; this script never implements a digest encoder.
"""

import argparse
import collections
import gzip
import hashlib
import json
import math
import random
import struct
import sys
import tempfile
import zlib
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python/tests"))
from deflate_structure import blocks  # noqa: E402
from remainder_fixtures import fixture  # noqa: E402

from inference_platform.disk_records import write_json  # noqa: E402
from inference_platform.stage_c_checkpoint import checkpoint_run, seal_run  # noqa: E402
from inference_platform.stage_c_digest import measurement_digest, seal_digest  # noqa: E402
from inference_platform.stage_c_registered import (  # noqa: E402
    C_FIELDS,
    C_MAX,
    FAILURE_FIELDS,
    SNAPSHOT_FIELDS,
    RetentionError,
    encoded,
    final_metadata_projection,
    recover_registered,
)
from inference_platform.stage_c_resources import cpu_values  # noqa: E402
from inference_platform.stage_c_session import export  # noqa: E402
from inference_platform.stage_c_wire import member, unpadded  # noqa: E402


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def distribution(values):
    ordered = sorted(values)
    return dict(
        n=len(values),
        unique=len(set(values)),
        min=ordered[0] if values else None,
        p50=ordered[math.ceil(len(values) / 2) - 1] if values else None,
        p95=ordered[math.ceil(len(values) * 0.95) - 1] if values else None,
        max=ordered[-1] if values else None,
    )


def compare(
    report,
    table,
    column,
    source,
    expected,
    recovered,
    basis="resident-exact",
    keys="ordinal",
):
    common = min(len(expected), len(recovered))
    equal = sum(expected[i] == recovered[i] for i in range(common))
    null_mismatch = sum(
        (expected[i] is None) != (recovered[i] is None) for i in range(common)
    )
    row = dict(
        table=table,
        column=column,
        basis=basis,
        source=len(source),
        expected_resident=len(expected),
        recovered=len(recovered),
        equal=equal,
        missing=max(0, len(expected) - len(recovered)),
        changed=common - equal,
        null_mismatch=null_mismatch,
        coverage_keys=keys,
    )
    report.append(row)
    if (
        row["missing"]
        or row["changed"]
        or row["null_mismatch"]
        or len(recovered) != len(expected)
    ):
        raise AssertionError(f"survival failure: {table}.{column}: {row}")


def compare_table(report, name, source, expected, recovered, basis="resident-exact"):
    columns = list(source[0]) if source else list(expected[0]) if expected else []
    for field in columns:
        compare(
            report,
            name,
            field,
            [row[field] for row in source],
            [row[field] for row in expected],
            [row[field] for row in recovered],
            basis,
        )


def vector_oracle(samples, start, end):
    eligible = [row for row in samples if start <= row[0] < end]
    good = [row for row in eligible if row[2] and row[1] is not None]
    result = dict(
        min=min((row[1] for row in good), default=0),
        max=max((row[1] for row in good), default=0),
        sum=sum(row[1] for row in good),
        valid_n=len(good),
        invalid_n=len(eligible) - len(good),
        maximum_ns=0,
        integral=0,
        exposure_ns=0,
    )
    result["maximum_ns"] = next((row[0] for row in good if row[1] == result["max"]), 0)
    for i in range(1, len(eligible)):
        left, right = eligible[i - 1], eligible[i]
        duration = right[0] - left[0]
        if (
            0 < duration <= 200_000_000
            and left[2]
            and right[2]
            and left[1] is not None
            and right[1] is not None
        ):
            result["integral"] += left[1] * duration
            result["exposure_ns"] += duration
    return result


def resource_oracle(samples):
    """Independent pair-set implementation, separate from the serializer's fold."""
    anchor = next(
        ((s["pid"], s["start_ticks"]) for s in samples if s["status"] == "ok"), None
    )
    identities = [(s["pid"], s["start_ticks"]) for s in samples]
    acceptable = [
        s["status"] == "ok"
        and identities[i] == anchor
        and (
            i == 0
            or samples[i - 1]["status"] != "ok"
            or identities[i - 1] != anchor
            or s["monotonic_ns"] > samples[i - 1]["monotonic_ns"]
        )
        for i, s in enumerate(samples)
    ]
    pairs = [
        (samples[i - 1], samples[i])
        for i in range(1, len(samples))
        if acceptable[i - 1]
        and acceptable[i]
        and samples[i]["slot"] == samples[i - 1]["slot"] + 1
        and samples[i]["cpu_ticks"] >= samples[i - 1]["cpu_ticks"]
    ]
    valid = [s for i, s in enumerate(samples) if acceptable[i]]
    max_pair = max(
        pairs, key=lambda p: p[1]["cpu_ticks"] - p[0]["cpu_ticks"], default=None
    )
    rss_max = max((s["rss_bytes"] for s in valid), default=None)
    row = dict(
        pid=anchor[0] if anchor else None,
        start_ticks=anchor[1] if anchor else None,
        valid_n=len(valid),
        sample_n=len(samples),
        pid_change_n=sum(
            identities[i] != identities[i - 1]
            for i in range(1, len(samples))
            if samples[i]["status"] == samples[i - 1]["status"] == "ok"
        ),
        missing_n=sum(s["status"] == "missing" for s in samples),
        access_error_n=sum(s["status"] == "access_error" for s in samples),
        identity_mismatch_n=sum(
            sample["status"] == "ok" and identities[i] != anchor
            for i, sample in enumerate(samples)
        ),
        non_monotonic_n=sum(
            samples[i]["monotonic_ns"] <= samples[i - 1]["monotonic_ns"]
            for i in range(1, len(samples))
            if samples[i]["status"] == samples[i - 1]["status"] == "ok"
            and identities[i] == identities[i - 1] == anchor
        ),
        cpu_decrease_n=sum(
            samples[i]["cpu_ticks"] < samples[i - 1]["cpu_ticks"]
            for i in range(1, len(samples))
            if acceptable[i - 1]
            and samples[i]["status"] == "ok"
            and identities[i] == anchor
        ),
        missed_slot_n=sum(
            samples[i]["slot"] - samples[i - 1]["slot"] - 1
            for i in range(1, len(samples))
        ),
        pair_n=len(pairs),
        first_ns=valid[0]["monotonic_ns"] if valid else None,
        last_ns=valid[-1]["monotonic_ns"] if valid else None,
        first_cpu_ticks=valid[0]["cpu_ticks"] if valid else None,
        last_cpu_ticks=valid[-1]["cpu_ticks"] if valid else None,
        cpu_ticks=sum(b["cpu_ticks"] - a["cpu_ticks"] for a, b in pairs),
        duration_ns=sum(b["monotonic_ns"] - a["monotonic_ns"] for a, b in pairs),
        max_pair_ticks=max_pair[1]["cpu_ticks"] - max_pair[0]["cpu_ticks"]
        if max_pair
        else None,
        max_pair_duration_ns=max_pair[1]["monotonic_ns"] - max_pair[0]["monotonic_ns"]
        if max_pair
        else None,
        max_pair_end_ns=max_pair[1]["monotonic_ns"] if max_pair else None,
        rss_min=min((s["rss_bytes"] for s in valid), default=None),
        rss_max=rss_max,
        rss_max_ns=next(
            (s["monotonic_ns"] for s in valid if s["rss_bytes"] == rss_max), None
        ),
        rss_integral=sum(
            a["rss_bytes"] * (b["monotonic_ns"] - a["monotonic_ns"]) for a, b in pairs
        ),
        rss_exposure_ns=sum(b["monotonic_ns"] - a["monotonic_ns"] for a, b in pairs),
        rss_last=valid[-1]["rss_bytes"] if valid else None,
        peak_rss_last=valid[-1]["peak_rss_bytes"] if valid else None,
        excluded_pair_n=max(0, len(samples) - 1) - len(pairs),
        status=2,
    )
    if valid:
        row["status"] = int(
            any(
                row[k]
                for k in (
                    "pid_change_n",
                    "missing_n",
                    "access_error_n",
                    "non_monotonic_n",
                    "identity_mismatch_n",
                    "cpu_decrease_n",
                    "missed_slot_n",
                )
            )
        )
    return row


def histogram_oracle(source):
    status = 2 if source["missing"] else 1 if source["reset"] else 0
    result = {f"bucket_{i}": None for i in range(11)}
    result.update(count=None, sum_bits=None, status=status)
    if not status:
        a, b = source["before"], source["after"]
        result.update(
            {f"bucket_{i}": b["buckets"][i] - a["buckets"][i] for i in range(11)}
        )
        result.update(
            count=b["count"] - a["count"],
            sum_bits=struct.unpack("<Q", struct.pack("<d", b["sum"] - a["sum"]))[0],
        )
    return result


def eviction_oracle(bins):
    valid = [b for b in bins if b["valid"] and not b["gap"] and not b["reset"]]
    amounts = [len(set(b["removed_identities"])) for b in valid]
    maximum = max(amounts, default=None)
    return dict(
        removed=sum(amounts),
        covered_seconds=len(valid),
        gap_seconds=len(bins) - len(valid),
        max_per_second=maximum,
        max_time_ns=next(
            (
                b["second_ns"]
                for b, n in zip(valid, amounts, strict=True)
                if n == maximum
            ),
            None,
        ),
        status=1 if len(valid) < len(bins) and valid else 0 if valid else 2,
        flags=int(len(valid) < len(bins)) | (int(any(b["reset"] for b in bins)) << 1),
    )


def bind_host(run, host):
    """Use numerical observations derived by Go from all source joins/owners."""
    base = run["cadence_start_ns"]
    sources = []
    names = (
        "cached",
        "shared",
        "non_shared",
        "evictable",
        "capacity",
        "reserved_null",
        "active_physical",
        "event_live",
    )
    for observation in host["snapshots"]:
        slot = observation["slot"]
        source = {token.split(":")[0]: 0 for token in SNAPSHOT_FIELDS.split()}
        patched = 27000 <= slot <= 45000
        source.update(
            snapshot_index=slot,
            cadence_slot=slot,
            arm=int(patched),
            status=int(not observation["valid"]),
            reset_epoch=observation["reset"],
            phase=observation["phase"],
            observed_ns=observation["observed_ns"],
            owner_link_n=observation["owner_links"],
            unscheduled_holder_n=observation["unscheduled"],
            queue_depth=observation["queue"] if patched else 0,
            queue_read_ns=observation["observed_ns"],
            sequence_gap_n=observation["gap"],
            sideband_drop_n=observation["drops"],
            temporary_cow_refs=observation["temporary"],
            temporary_fence_refs=observation["fence"],
            ambiguous_n=observation["ambiguous"],
            orphan_n=observation["orphan"],
            missing_owner_n=observation["missing_owner"],
            unexplained_n=observation["unexplained"],
            presence_bitmap=(1 << 36) - 1 if patched else 0,
            validity_flags=int(not observation["valid"]),
        )
        source.update(dict(zip(names, observation["counts"], strict=True)))
        sources.append(source)
        if patched:
            cached = observation["counts"][0]
            active = observation["active_limit"]
            shared = observation["shared_limit"]
            assert shared == min(active, 1537 + observation["reset"] * 31)
            # Independent closed-form oracle for this source population: the
            # 13*owner + 7*position residues cover every active block (see README).
            assert observation["counts"] == [
                cached,
                shared,
                active - shared,
                max(0, cached - active),
                3891 - active + shared,
                1,
                active,
                cached,
            ]
            assert (
                observation["owner_links"] == 65536 and observation["unscheduled"] == 85
            )
    run["snapshot_count_sources"] = sources
    for level, phase in enumerate(run["exposures"]):
        samples = [
            s
            for s in sources
            if phase["start_ns"] <= s["observed_ns"] < phase["end_ns"]
        ]
        mapping = dict(
            cached="cached",
            shared="shared",
            non_shared="non_shared",
            evictable="evictable",
            capacity="capacity",
            queue="queue_depth",
        )
        for quantity, field in mapping.items():
            if phase["arm"] == 0 and quantity != "cached":
                continue
            phase["samples"][quantity] = [
                [s["observed_ns"], s[field], s["status"] == 0] for s in samples
            ]
        phase["source_reconciliation"] = [
            sum(s["sequence_gap_n"] for s in samples),
            sum(s["sideband_drop_n"] for s in samples),
            0,
            sum(s["orphan_n"] for s in samples),
            sum(s["ambiguous_n"] for s in samples),
            sum(s["unexplained_n"] for s in samples),
            sum(s["missing_owner_n"] for s in samples),
            sum(s["status"] != 0 for s in samples),
        ]
    return base


def bind_variant_source(run, bindings, composite):
    """Refresh source hashes after making one adversarial source-shaped fixture."""
    run["source_binding"] = {
        "registration_sha256": bindings[
            "docs/INF047_STAGE_C_REMAINDER_PREREGISTRATION.md"
        ],
        "source_sha256": composite,
        "run_sha256": hashlib.sha256(encoded(run)).hexdigest(),
    }


def randomize_run3_timestamps(run, seed, *, maximum_width=False):
    rng = random.Random(seed)
    u64_max, i64_max = (1 << 64) - 1, (1 << 63) - 1
    for request, lag in zip(run["requests"], run["lags"], strict=True):
        if maximum_width:
            request["dispatch_ns"] = u64_max
            for name in ("first_content_ns", "terminal_ns", "censor_ns"):
                if request[name] is not None:
                    request[name] = u64_max
            lag["routing_decision_monotonic_ns"] = u64_max
            for name in (
                "gateway_terminal_monotonic_ns",
                "request_lifetime_ns",
                "store_observation_window_end_monotonic_ns",
                "next_same_identity_decision_monotonic_ns",
                "event_observed_monotonic_ns",
            ):
                if lag[name] is not None:
                    lag[name] = u64_max
            if request["event_lag_ns"] is not None:
                request["event_lag_ns"] = lag["routing_to_event_observation_ns"] = (
                    i64_max
                )
            if lag["event_sequence"] is not None:
                lag["event_sequence"] = u64_max
        else:
            # Each independent origin/offset carries 63-bit entropy while preserving
            # the source's null patterns and request/lag equality constraints.
            dispatch = rng.randrange(1 << 61, 1 << 62)
            terminal_offset = rng.randrange(1 << 61)
            request["dispatch_ns"] = dispatch
            if request["first_content_ns"] is not None:
                request["first_content_ns"] = dispatch + rng.randrange(
                    terminal_offset + 1
                )
            if request["terminal_ns"] is not None:
                request["terminal_ns"] = dispatch + terminal_offset
            if request["censor_ns"] is not None:
                request["censor_ns"] = dispatch + rng.randrange(1 << 61)
            routing = dispatch + rng.randrange(1 << 61)
            lag["routing_decision_monotonic_ns"] = routing
            terminal = request["terminal_ns"]
            lag["gateway_terminal_monotonic_ns"] = terminal
            lag["request_lifetime_ns"] = (
                terminal - dispatch if terminal is not None else None
            )
            lag["store_observation_window_end_monotonic_ns"] = (
                terminal + rng.randrange(1 << 30) if terminal is not None else None
            )
            lag["next_same_identity_decision_monotonic_ns"] = (
                dispatch + (1 << 60) + rng.randrange(1 << 60)
            )
            if request["event_lag_ns"] is not None:
                event_lag = rng.randrange(1 << 61)
                request["event_lag_ns"] = lag["routing_to_event_observation_ns"] = (
                    event_lag
                )
                lag["event_observed_monotonic_ns"] = routing + event_lag
            else:
                lag["event_observed_monotonic_ns"] = None
            if lag["event_sequence"] is not None:
                lag["event_sequence"] = rng.randrange(1 << 63)
    for clock in run["dictionaries"]["clocks"]:
        if maximum_width:
            clock[0], clock[1], clock[2] = u64_max, u64_max, i64_max
        else:
            monotonic = rng.randrange(1 << 63)
            wall = monotonic + rng.randrange(1 << 30)
            clock[0], clock[1], clock[2] = wall, monotonic, wall - monotonic


def randomize_run3_validity_words(run, seed):
    rng = random.Random(seed)
    for request in run["requests"]:
        request["validity_flags"] = rng.randrange(1 << 64)
    for lag in run["lags"]:
        lag["validity_flags"] = rng.randrange(1 << 64)


def run3_sizing_variants(output, bindings, composite):
    variants = []
    for name, seed, maximum_width, random_validity_words in (
        ("random_63bit_timestamps_sequences", 470176, False, False),
        (
            "random_63bit_timestamps_sequences_random_validity_words",
            470176,
            False,
            True,
        ),
        ("maximum_registered_timestamp_sequence_width", 470177, True, False),
    ):
        run = fixture(3, ceiling=True)
        randomize_run3_timestamps(run, seed, maximum_width=maximum_width)
        if random_validity_words:
            randomize_run3_validity_words(run, seed)
        bind_variant_source(run, bindings, composite)
        with tempfile.TemporaryDirectory(dir=ROOT / ".cache") as temp:
            receipt = seal_run(Path(temp), 3, run, core_only=True)["measurement_digest"]
            data = (Path(temp) / "sealed-runs" / "run-3.digest.json.gz").read_bytes()
            recovered = recover_registered(data)
            assert recovered["run_number"] == 3
            assert recovered["source_binding"] == run["source_binding"]
            variants.append(
                dict(
                    name=name,
                    seed=seed,
                    digest_bytes=len(data),
                    digest_sha256=hashlib.sha256(data).hexdigest(),
                    per_request_count=receipt["per_request_count"],
                    event_lag_status=receipt["event_lag_status"],
                    source_binding=run["source_binding"],
                )
            )

    refusal_variants = []
    for name, mutate, expected_table in (
        (
            "per_request_prompt_identity",
            lambda run: (
                run["requests"][1].update(prompt_identity_sha256="f" * 64)
                or run["lags"][1].update(prompt_identity_sha256="f" * 64)
            ),
            "run3_prompt_identity_constant",
        ),
        (
            "per_reset_membership_digest",
            lambda run: run["membership"][0].update(token_block_digest="f" * 64),
            "run3_membership_constants",
        ),
        (
            "per_reset_native_key",
            lambda run: run["membership"][0].update(native_cached_key="f" * 128),
            "run3_membership_constants",
        ),
        (
            "lag_matched_digest_outside_registered_set",
            lambda run: run["lags"][0].update(matched_token_block_digests=["f" * 64]),
            "run3_lag_matched_digest_subset",
        ),
    ):
        run = fixture(3, ceiling=True)
        mutate(run)
        bind_variant_source(run, bindings, composite)
        with tempfile.TemporaryDirectory(dir=ROOT / ".cache") as temp:
            session = Path(temp)
            archive_receipt = seal_run(session, 3, run, core_only=True)
            digest = archive_receipt["measurement_digest"]
            failure_path = session / "sealed-runs" / "run-3.digest.json.gz.failure.json"
            failure = json.loads(failure_path.read_text(encoding="utf-8"))
            assert failure["table"] == expected_table
            assert failure["full_measured_session_acceptance"] is False
            assert digest["per_request_count"] == 0
            assert (session / "sealed-runs" / "run-3.tar.gz").exists()
            refusal_variants.append(
                dict(
                    name=name,
                    status="protected_only_refusal",
                    flag=failure["flag"],
                    table=failure["table"],
                    failure_receipt_sha256=hashlib.sha256(
                        failure_path.read_bytes()
                    ).hexdigest(),
                    archive_receipt_sha256=archive_receipt["sha256"],
                    exact_lag_status=digest["event_lag_status"],
                    full_measured_session_acceptance=False,
                )
            )
    write_json(
        output / "run-3-sizing-variants.json",
        {
            "schema": "stage-c-run3-adversarial-sizing.v1",
            "basis": "registered Run 3 ceiling fixture through seal_run; no producer, R167, exact-lag adequacy, or paid action",
            "identity_registration": {
                "prompt_identity": "one constant per run across resets",
                "membership": "two position-indexed digest/native-key pairs constant across requests and resets",
            },
            "registration_refusal_variants": refusal_variants,
            "valid_sizing_variants": variants,
        },
    )
    return variants, refusal_variants


def survival(run, got, host=None):
    report = []
    n = run["run_number"]
    if n == 3:
        for name in ("requests", "lags", "membership"):
            compare_table(report, name, run[name], run[name], got[name])
        for name in ("reset_rows", "cold_rows", "window_rows", "histogram_rows"):
            for i in range(len(run["rewarm_convergence_compact"][name][0])):
                compare(
                    report,
                    "protected." + name,
                    str(i),
                    [r[i] for r in run["rewarm_convergence_compact"][name]],
                    [r[i] for r in run["rewarm_convergence_compact"][name]],
                    [r[i] for r in got["protected"][name]],
                )
        for name, rows in run["dictionaries"].items():
            for i in range(len(rows[0])):
                compare(
                    report,
                    "dictionary." + name,
                    str(i),
                    [r[i] for r in rows],
                    [r[i] for r in rows],
                    [r[i] for r in got["dictionaries"][name]],
                )
        for key, value in json.loads(
            encoded(run["rewarm_convergence_compact"]["header"])
        ).items():
            compare(
                report,
                "protected.header",
                key,
                [value],
                [value],
                [got["protected"]["header"][key]],
            )
    else:
        compact = set(got["requests"][0]) & set(run["requests"][0])
        references = {r["per_request_index"]: r for r in got["reference_outcomes"]}
        for field in run["requests"][0]:
            source = [r[field] for r in run["requests"]]
            if field in compact:
                compare(
                    report,
                    "requests",
                    field,
                    source,
                    source,
                    [r[field] for r in got["requests"]],
                )
            elif field in ("prefix_ordinal", "cached_prompt_tokens"):
                indexes = list(references)
                compare(
                    report,
                    "requests",
                    field,
                    source,
                    [run["requests"][i][field] for i in indexes],
                    [references[i][field] for i in indexes],
                    "reference-only",
                    "per_request_index",
                )
            else:
                compare(report, "requests", field, source, [], [], "host-only")
        outcome = next(
            row
            for row in report
            if row["table"] == "requests" and row["column"] == "outcome"
        )
        assert outcome == dict(
            table="requests",
            column="outcome",
            basis="resident-exact",
            source=14259,
            expected_resident=14259,
            recovered=14259,
            equal=14259,
            missing=0,
            changed=0,
            null_mismatch=0,
            coverage_keys="ordinal",
        )
        for j, field in enumerate(FAILURE_FIELDS):
            compare(
                report,
                "failure_tuple",
                field,
                [r[j] for r in run["failure_tuples"]],
                [r[j] for r in run["failure_tuples"]],
                [r["failure_tuple"][j] for r in got["requests"]],
            )
        witnesses = got["lag_witnesses"]
        witness_source = [
            next(r for r in run["lags"] if r["level_index"] == level)
            for level in range(29)
        ]
        lag_to_compact = dict(
            per_request_index="per_request_index",
            level_index="level_index",
            status="event_lag_status",
            routing_to_event_observation_ns="event_lag_ns",
            exclusion_flags="exclusion_flags",
        )
        for field in run["lags"][0]:
            source = [r[field] for r in run["lags"]]
            if field in lag_to_compact:
                compare(
                    report,
                    "lags",
                    field,
                    source,
                    source,
                    [r[lag_to_compact[field]] for r in got["requests"]],
                )
            elif field == "matched_token_block_digests":
                compare(
                    report,
                    "lags",
                    field,
                    source,
                    [],
                    [],
                    "not-resident; count/set hash is not member recovery",
                )
                compare(
                    report,
                    "lags",
                    "matched_digest_members",
                    [None] * sum(len(x) for x in source),
                    [],
                    [],
                    "not-resident",
                )
            else:
                compare(
                    report,
                    "lags",
                    field,
                    source,
                    [r[field] for r in witness_source],
                    [r[field] for r in witnesses],
                    "fixed-witness-only",
                    "first dispatch ordinal per level",
                )
        for source, witness in zip(witness_source, witnesses, strict=True):
            values = source["matched_token_block_digests"]
            digest = hashlib.sha256(
                b"stage-c-matched-set-v1\0"
                + struct.pack(">I", len(values))
                + b"".join(bytes.fromhex(v) for v in values)
            ).hexdigest()
            assert (
                witness["matched_digest_count"] == len(values)
                and witness["matched_digest_set_sha256"] == digest
            )
        compare_table(
            report,
            "c_level",
            run["level_aggregates"],
            run["level_aggregates"],
            got["level_aggregates"],
        )
        selected = []
        for phase in run["exposures"][24:]:
            midpoint = (phase["start_ns"] + phase["end_ns"]) // 2
            slot = min(
                range(48001),
                key=lambda i: (abs(run["cadence_start_ns"] + i * 10**8 - midpoint), i),
            )
            selected.append(
                next(
                    r
                    for r in run["snapshot_count_sources"]
                    if r["cadence_slot"] == slot
                )
            )
        compare_table(
            report,
            "snapshot_counts",
            run["snapshot_count_sources"],
            selected,
            got["snapshot_counts"],
            "fixed-witness-only",
        )
        for level, phase in enumerate(run["exposures"]):
            for quantity, actual in got["phase_summaries"][level]["vectors"].items():
                samples = phase["samples"][quantity]
                if quantity == "lag":
                    samples = [
                        [
                            r["routing_decision_monotonic_ns"],
                            r["routing_to_event_observation_ns"],
                            True,
                        ]
                        for r in run["lags"]
                        if r["level_index"] == level and r["status"] == "observed"
                    ]
                expected = vector_oracle(samples, phase["start_ns"], phase["end_ns"])
                compare_table(
                    report,
                    f"phase.{level}.{quantity}",
                    [expected],
                    [expected],
                    [actual],
                    "host-computed aggregate",
                )
            scope = got["phase_summaries"][level]["scope"]
            expected_scope = [
                phase["arm"],
                phase["phase"],
                phase["reset_epoch"],
                level,
                phase["start_ns"],
                phase["end_ns"],
            ]
            for i, name in enumerate(
                ("arm", "phase", "reset", "level", "start_ns", "end_ns")
            ):
                compare(
                    report,
                    f"phase.{level}.scope",
                    name,
                    [expected_scope[i]],
                    [expected_scope[i]],
                    [scope[i]],
                )
            for i, value in enumerate(phase["source_reconciliation"]):
                compare(
                    report,
                    f"phase.{level}.source_reconciliation",
                    str(i),
                    [value],
                    [value],
                    [got["phase_summaries"][level]["source_reconciliation"][i]],
                    "host-computed aggregate",
                )
        for name, fmt in (
            ("clocks", "QQqQQQQQ"),
            ("levels", "QQQQ"),
            ("epochs", "QQQQ"),
            ("global_counters", "Q"),
            ("first_hit_receipts", "QQQQQQQQ"),
        ):
            raw = got["extension"][name]
            import base64

            data = base64.b64decode(raw + "=" * (-len(raw) % 4))
            decoded = list(struct.iter_unpack("<" + fmt, data))
            for i in range(len(fmt)):
                source = [row[i] for row in run["extension_header"][name]]
                compare(
                    report,
                    "extension_header." + name,
                    str(i),
                    source,
                    source,
                    [row[i] for row in decoded],
                )
        raw = got["extension"]["reference_manifest_hashes"]
        data = base64.b64decode(raw + "=" * (-len(raw) % 4))
        hashes = [data[i : i + 32].hex() for i in range(0, len(data), 32)]
        compare(
            report,
            "extension_header",
            "reference_manifest_hashes",
            run["extension_header"]["reference_manifest_hashes"],
            run["extension_header"]["reference_manifest_hashes"],
            hashes,
        )
        if host:
            registration = (
                ROOT / "docs/INF047_STAGE_C_REMAINDER_PREREGISTRATION.md"
            ).read_text(encoding="utf-8")
            for table, total in (
                ("snapshot_exact.v1", host["snapshot_rows"]),
                ("snapshot_live_set_join.v1", host["physical_join_rows"]),
                ("snapshot_request_owner.v1", host["owner_link_rows"]),
                ("snapshot_sideband.v1", host["sideband_rows"]),
            ):
                line = next(
                    line
                    for line in registration.splitlines()
                    if line.startswith("| `" + table + "`")
                )
                columns = line.split("|", 3)[2].split("`")[1].split(", ")
                assert len(columns) == host["source_field_counts"][table]
                for column in columns:
                    report.append(
                        dict(
                            table=table,
                            column=column,
                            basis="host-only input; numerical projection and five counter witnesses audited separately",
                            source=total,
                            expected_resident=0,
                            recovered=0,
                            equal=0,
                            missing=0,
                            changed=0,
                            null_mismatch=0,
                            coverage_keys="full source-row traversal; no individual identity/trajectory recovery",
                        )
                    )
    if n == 4 and host:
        for column in (
            "per_request_index",
            "block_position",
            "token_block_digest",
            "native_cached_key",
            "in_W",
        ):
            report.append(
                dict(
                    table="membership_capacity_fixture",
                    column=column,
                    basis="host-only independent capacity fixture; not extra reference prompt blocks",
                    source=host["manifest_capacity_rows"],
                    expected_resident=0,
                    recovered=0,
                    equal=0,
                    missing=0,
                    changed=0,
                    null_mismatch=0,
                    coverage_keys="14,259 x 384 capacity traversal; phase-tight workload ceiling is 5,160,576",
                )
            )
    compare_table(
        report,
        "native",
        run["native_counters"],
        run["native_counters"],
        got["native_counters"],
    )
    for part, oracle in (
        ("gateway", lambda s: resource_oracle(s["gateway_samples"])),
        ("eviction", lambda s: eviction_oracle(s["eviction_bins"])),
        ("lookup", lambda s: histogram_oracle(s["lookup"])),
        ("tokenize", lambda s: histogram_oracle(s["tokenize"])),
    ):
        expected = [oracle(source) for source in run["measurement_sources"]]
        compare_table(
            report,
            part,
            expected,
            expected,
            [r[part] for r in got["measurements"]],
            "host-computed aggregate",
        )
    for field, value in run["cache_config"].items():
        compare(
            report,
            "envelope.cache_config",
            field,
            [value],
            [value],
            [got["cache_config"][field]],
        )
    compare(report, "envelope", "index_entries", [0], [0], [got["index_entries"]])
    compare(
        report,
        "envelope",
        "routing_consumer_backlog",
        [None],
        [None],
        [got["routing_consumer_backlog"]],
    )
    compare(
        report,
        "envelope",
        "gateway_cpu_ticks_per_second",
        [run["gateway_cpu_ticks_per_second"]],
        [run["gateway_cpu_ticks_per_second"]],
        [got["gateway_cpu_ticks_per_second"]],
    )
    for field in run["measurement_sources"][0]["gateway_samples"][0]:
        total = sum(len(row["gateway_samples"]) for row in run["measurement_sources"])
        report.append(
            dict(
                table="gateway_samples",
                column=field,
                basis="host-only; bounded summaries separately audited",
                source=total,
                expected_resident=0,
                recovered=0,
                equal=0,
                missing=0,
                changed=0,
                null_mismatch=0,
                coverage_keys="all source samples; no trajectory recovery",
            )
        )
    return report


def faults(output):
    rows = []
    cases = [
        (
            "ninth_tuple",
            lambda r: r.__setitem__(
                "failure_tuples",
                [
                    (200, "completed", "completed", i % 9, 0)
                    for i in range(len(r["requests"]))
                ],
            ),
        ),
        (
            "http_range",
            lambda r: r["failure_tuples"].__setitem__(
                0, (600, "completed", "completed", None, None)
            ),
        ),
        (
            "gateway_enum",
            lambda r: r["failure_tuples"].__setitem__(
                0, (200, "NEW_CODE", "completed", None, None)
            ),
        ),
        (
            "client_width",
            lambda r: r["failure_tuples"].__setitem__(
                0, (200, "completed", "completed", "x" * 33, None)
            ),
        ),
        (
            "upstream_width",
            lambda r: r["failure_tuples"].__setitem__(
                0, (200, "completed", "completed", None, 2**32)
            ),
        ),
        ("time_width", lambda r: r["requests"][0].__setitem__("dispatch_ns", 2**64)),
        ("lag_enum", lambda r: r["lags"][0].__setitem__("status", "NEW_STATUS")),
        (
            "native_enum",
            lambda r: r["native_counters"][0].__setitem__("counter_status", 4),
        ),
        (
            "gateway_cpu_width",
            lambda r: r["measurement_sources"][0]["gateway_samples"][0].__setitem__(
                "cpu_ticks", 2**64
            ),
        ),
        (
            "histogram_width",
            lambda r: r["measurement_sources"][1]["lookup"]["after"].update(
                buckets=[2**40] * 11, count=2**40
            ),
        ),
        (
            "snapshot_count",
            lambda r: r.__setitem__(
                "snapshot_count_sources", [r["snapshot_count_sources"][0]] * 48002
            ),
        ),
        ("level_enum", lambda r: r["level_aggregates"][0].__setitem__("row_status", 4)),
        ("missing_required", lambda r: r.pop("measurement_sources")),
    ]
    for label, mutate in cases:
        run = fixture(4)
        mutate(run)
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "digest.gz"
            with patch(
                "inference_platform.stage_c_registered.member",
                side_effect=AssertionError("DEFLATE reached"),
            ):
                try:
                    seal_digest(path, measurement_digest(Path(d), run, Path(d)))
                    raise AssertionError("fault accepted: " + label)
                except RetentionError:
                    pass
            receipt = json.loads(
                path.with_name(path.name + ".failure.json").read_text(encoding="utf-8")
            )
            assert not path.exists() and not receipt["full_measured_session_acceptance"]
            rows.append(
                dict(
                    case=label,
                    distinct_failure_tuples_reached=len(set(run["failure_tuples"])),
                    receipt=receipt,
                )
            )
    # Run 3's independent protected evidence survives exact-lag degradation unchanged.
    run = fixture(3)
    run["requests"] *= 13
    run["lags"] *= 13
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "digest.gz"
        receipt = seal_digest(path, measurement_digest(Path(d), run, Path(d)))
        recovered = recover_registered(path.read_bytes())
        assert encoded(recovered["protected"]) == encoded(
            run["rewarm_convergence_compact"]
        )
        assert receipt["full_measured_session_acceptance"] is False
        rows.append(
            dict(case="run3_exact_guard", receipt=receipt, protected_byte_equal=True)
        )
    for label, mutate, expected_type in (
        (
            "run4_raw_keyerror_registered_source",
            lambda value: value.pop("gateway_cpu_ticks_per_second"),
            "KeyError",
        ),
        (
            "run4_raw_typeerror_registered_source",
            lambda value: value.__setitem__("source_binding", None),
            "TypeError",
        ),
        (
            "run4_raw_null_requests_registered_source",
            lambda value: value.__setitem__("requests", None),
            "TypeError",
        ),
    ):
        run = fixture(4)
        mutate(run)
        with tempfile.TemporaryDirectory() as temp:
            session = Path(temp)
            (session / "gateway.log").write_text("", encoding="utf-8")
            with (
                patch(
                    "inference_platform.stage_c_session.disk_snapshot", return_value={}
                ),
                patch(
                    "inference_platform.stage_c_checkpoint.seal_run",
                    wraps=seal_run,
                ) as seal_spy,
            ):
                receipt = checkpoint_run(session, 4, run)
            assert seal_spy.call_count == 1
            digest = receipt["measurement_digest"]
            failure_path = session / "sealed-runs" / "run-4.digest.json.gz.failure.json"
            failure = json.loads(failure_path.read_text(encoding="utf-8"))
            archive_receipt_path = session / "sealed-runs" / "run-4.receipt.json"
            archive_receipt = json.loads(
                archive_receipt_path.read_text(encoding="utf-8")
            )
            projected = final_metadata_projection(session)
            projection_run = next(
                row for row in projected["runs"] if row["run_number"] == 4
            )
            assert failure["failure_type"] == expected_type
            assert failure["observed_count"] == (
                len(run["requests"]) if isinstance(run.get("requests"), list) else None
            )
            assert digest["status"] == "refused"
            assert digest["flag"] == "retention_schema_overflow"
            assert digest["table"] == "registered_source"
            assert (
                digest["failure_receipt_sha256"]
                == hashlib.sha256(failure_path.read_bytes()).hexdigest()
            )
            assert (session / "sealed-runs" / "run-4.tar.gz").exists()
            assert archive_receipt["measurement_digest"] == digest
            assert projection_run["status"] == "refused"
            rows.append(
                dict(
                    case=label,
                    scenario="real_checkpoint_run",
                    failure_type=expected_type,
                    observed_count=failure["observed_count"],
                    seal_calls=seal_spy.call_count,
                    distinct_failure_tuples_reached=len(set(run["failure_tuples"])),
                    flag=failure["flag"],
                    table=failure["table"],
                    failure_receipt_sha256=hashlib.sha256(
                        failure_path.read_bytes()
                    ).hexdigest(),
                    archive_receipt_sha256=hashlib.sha256(
                        archive_receipt_path.read_bytes()
                    ).hexdigest(),
                    final_projection_status=projection_run["status"],
                )
            )
    run = fixture(3)
    run.pop("gateway_cpu_ticks_per_second")
    with tempfile.TemporaryDirectory() as temp:
        session = Path(temp)
        (session / "gateway.log").write_text("", encoding="utf-8")
        with patch("inference_platform.stage_c_session.disk_snapshot", return_value={}):
            receipt = checkpoint_run(session, 3, run)
        digest = receipt["measurement_digest"]
        failure_path = session / "sealed-runs" / "run-3.digest.json.gz.failure.json"
        failure = json.loads(failure_path.read_text(encoding="utf-8"))
        assert digest["per_request_detail_dropped"] is True
        assert digest["event_lag_status"] == "unavailable"
        assert failure["table"] == "registered_source"
        archive_path = session / "sealed-runs" / "run-3.tar.gz"
        archive_receipt_path = session / "sealed-runs" / "run-3.receipt.json"
        assert archive_path.exists() and archive_receipt_path.exists()
        projection = final_metadata_projection(session)
        projection_run = next(
            row for row in projection["runs"] if row["run_number"] == 3
        )
        assert projection_run["status"] == "protected_only"
        rows.append(
            dict(
                case="run3_raw_keyerror_protected_only",
                scenario="real_checkpoint_run",
                failure_type="KeyError",
                flag=failure["flag"],
                table=failure["table"],
                failure_receipt_sha256=hashlib.sha256(
                    failure_path.read_bytes()
                ).hexdigest(),
                digest_status="protected_only",
                exact_lag_status=digest["event_lag_status"],
                full_measured_session_acceptance=False,
            )
        )
    run = fixture(3)
    run["requests"] = None
    with tempfile.TemporaryDirectory() as temp:
        session = Path(temp)
        (session / "gateway.log").write_text("", encoding="utf-8")
        with (
            patch("inference_platform.stage_c_session.disk_snapshot", return_value={}),
            patch(
                "inference_platform.stage_c_checkpoint.seal_run", wraps=seal_run
            ) as seal_spy,
        ):
            receipt = checkpoint_run(session, 3, run)
        assert seal_spy.call_count == 1
        digest = receipt["measurement_digest"]
        failure_path = session / "sealed-runs" / "run-3.digest.json.gz.failure.json"
        failure = json.loads(failure_path.read_text(encoding="utf-8"))
        archive_path = session / "sealed-runs" / "run-3.tar.gz"
        archive_receipt_path = session / "sealed-runs" / "run-3.receipt.json"
        archive_receipt = json.loads(archive_receipt_path.read_text(encoding="utf-8"))
        projected = final_metadata_projection(session)
        projection_run = next(
            row for row in projected["runs"] if row["run_number"] == 3
        )
        assert digest["per_request_detail_dropped"] is True
        assert digest["event_lag_status"] == "unavailable"
        assert digest["full_measured_session_acceptance"] is False
        assert failure["observed_count"] is None
        assert failure["table"] == "registered_source"
        assert archive_path.exists() and archive_receipt_path.exists()
        assert archive_receipt["measurement_digest"] == digest
        assert projection_run["status"] == "protected_only"
        rows.append(
            dict(
                case="run3_raw_null_requests_protected_only",
                scenario="real_checkpoint_run",
                failure_type="TypeError",
                seal_calls=seal_spy.call_count,
                flag=failure["flag"],
                table=failure["table"],
                observed_count=failure["observed_count"],
                failure_receipt_sha256=hashlib.sha256(
                    failure_path.read_bytes()
                ).hexdigest(),
                archive_receipt_sha256=hashlib.sha256(
                    archive_receipt_path.read_bytes()
                ).hexdigest(),
                digest_status="protected_only",
                exact_lag_status=digest["event_lag_status"],
                final_projection_status=projection_run["status"],
                full_measured_session_acceptance=False,
            )
        )
    run3_refusal_cases = (
        (
            "run3_null_rewarm_fallback_refused",
            lambda value: value.__setitem__("rewarm_convergence_compact", None),
            False,
        ),
        (
            "run3_null_source_binding_fallback_refused",
            lambda value: value.__setitem__("source_binding", None),
            False,
        ),
        (
            "run3_invalid_protected_schema_fallback_refused",
            lambda value: value["rewarm_convergence_compact"].__setitem__(
                "schema", "x"
            ),
            True,
        ),
        (
            "run3_invalid_binding_hash_fallback_refused",
            lambda value: value["source_binding"].__setitem__("run_sha256", "ZZ"),
            True,
        ),
    )
    for label, mutate, export_both in run3_refusal_cases:
        run = fixture(3)
        mutate(run)
        with tempfile.TemporaryDirectory() as temp:
            session = Path(temp)
            (session / "gateway.log").write_text("", encoding="utf-8")
            with (
                patch(
                    "inference_platform.stage_c_session.disk_snapshot", return_value={}
                ),
                patch(
                    "inference_platform.stage_c_checkpoint.seal_run", wraps=seal_run
                ) as seal_spy,
            ):
                receipt = checkpoint_run(session, 3, run)
            assert seal_spy.call_count == 1
            digest = receipt["measurement_digest"]
            failure_path = session / "sealed-runs" / "run-3.digest.json.gz.failure.json"
            failure = json.loads(failure_path.read_text(encoding="utf-8"))
            archive_path = session / "sealed-runs" / "run-3.tar.gz"
            archive_receipt_path = session / "sealed-runs" / "run-3.receipt.json"
            archive_receipt = json.loads(
                archive_receipt_path.read_text(encoding="utf-8")
            )
            projection = final_metadata_projection(session)
            projection_run = next(
                row for row in projection["runs"] if row["run_number"] == 3
            )
            failure_hash = hashlib.sha256(failure_path.read_bytes()).hexdigest()
            assert digest["status"] == "refused"
            assert digest["flag"] == failure["flag"]
            assert digest["table"] == failure["table"]
            assert digest["failure_receipt_sha256"] == failure_hash
            assert archive_path.exists() and archive_receipt_path.exists()
            assert archive_receipt["measurement_digest"] == digest
            assert projection_run["status"] == "refused"
            assert projection_run["archive_receipt"] == archive_receipt
            export_artifact_sha256 = []
            if export_both:
                manifest = session / "staging-manifest.json"
                write_json(manifest, dict(schema="fixture"))
                for recovery in (False, True):
                    export(session, manifest, recovery=recovery)
                    artifact = session / "export" / "stage-c-artifact.json"
                    assert artifact.is_file()
                    artifact_run = next(
                        row
                        for row in json.loads(artifact.read_text(encoding="utf-8"))[
                            "runs"
                        ]
                        if row["run_number"] == 3
                    )
                    assert artifact_run["status"] == "refused"
                    export_artifact_sha256.append(sha(artifact))
            rows.append(
                dict(
                    case=label,
                    scenario="real_checkpoint_run",
                    seal_calls=seal_spy.call_count,
                    failure_type=failure.get("failure_type"),
                    flag=digest["flag"],
                    table=digest["table"],
                    failure_receipt_sha256=failure_hash,
                    archive_sha256=sha(archive_path),
                    archive_receipt_sha256=sha(archive_receipt_path),
                    digest_status=digest["status"],
                    final_projection_status=projection_run["status"],
                    export_modes=(["normal", "recovery"] if export_both else []),
                    export_artifact_sha256=export_artifact_sha256,
                )
            )
    write_json(output / "faults.json", rows)
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output
    output.mkdir(parents=True, exist_ok=True)
    host = json.loads(args.host.read_text(encoding="utf-8"))
    assert (
        host["snapshot_rows"],
        host["physical_join_rows"],
        host["owner_link_rows"],
        host["sideband_rows"],
    ) == (48001, 70041891, 1179713536, 18001)
    source_files = [
        ROOT / "docs/INF047_STAGE_C_REMAINDER_PREREGISTRATION.md",
        ROOT / "internal/gateway/handler.go",
        ROOT / "internal/admission/coordinator.go",
        *sorted((ROOT / "python/src/inference_platform").glob("stage_c_*.py")),
        ROOT / "python/tests/remainder_fixtures.py",
        ROOT / "scripts/stage_c_host_fixture.go",
        Path(__file__),
    ]
    bindings = {path.relative_to(ROOT).as_posix(): sha(path) for path in source_files}
    results = dict(
        schema="stage-c-sizing-evidence.v1",
        status="IN_PROGRESS",
        source_files=bindings,
        limits=dict(digest=1048576, run3_protected=480000, final_metadata=32000),
        run3_exact_lag_adequacy="unestablished",
        paid_action=False,
        host={key: value for key, value in host.items() if key != "snapshots"},
        runs={},
    )
    results["host_snapshot_distributions"] = {
        name: distribution(
            [
                row["counts"][i]
                for row in host["snapshots"]
                if i == 0 or row["owner_links"]
            ]
        )
        for i, name in enumerate(
            (
                "cached",
                "shared",
                "non_shared",
                "evictable",
                "capacity",
                "reserved_null",
                "active",
                "event_live",
            )
        )
    }
    results["host_adverse_counts"] = {
        name: sum(row[name] for row in host["snapshots"])
        for name in (
            "gap",
            "drops",
            "duplicate",
            "replay",
            "ambiguous",
            "orphan",
            "missing_owner",
            "unexplained",
            "temporary",
            "fence",
        )
    }
    composite = hashlib.sha256(encoded(bindings)).hexdigest()
    with tempfile.TemporaryDirectory(dir=ROOT / ".cache") as temp:
        session = Path(temp)
        for number in (3, 4):
            run = fixture(number, ceiling=True)
            if number == 4:
                bind_host(run, host)
            run["source_binding"] = {
                "registration_sha256": bindings[
                    "docs/INF047_STAGE_C_REMAINDER_PREREGISTRATION.md"
                ],
                "source_sha256": composite,
                "run_sha256": hashlib.sha256(encoded(run)).hexdigest(),
            }
            receipt = seal_run(session, number, run, core_only=True)[
                "measurement_digest"
            ]
            data = (
                session / "sealed-runs" / f"run-{number}.digest.json.gz"
            ).read_bytes()
            recovered = recover_registered(data)
            report = survival(run, recovered, host if number == 4 else None)
            write_json(output / f"run-{number}-survival.json", report)
            (output / f"run-{number}.digest.json.gz").write_bytes(data)
            wire = receipt["sections"]
            if number == 4:
                inflater = zlib.decompressobj(31)
                raw = inflater.decompress(data)
                first = data[: -len(inflater.unused_data)]
                parsed = blocks(first)
                assert [row["kind"] for row in parsed] == [0, 2, 0, 2, 0]
                first_doc = json.loads(raw)
                assert (
                    parsed[1]["data"] == first_doc["a"].encode()
                    and parsed[3]["data"] == first_doc["b"].encode()
                )
                assert gzip.decompress(data) == raw + gzip.decompress(
                    inflater.unused_data
                )
                wire["independent_block_structure"] = [
                    dict(kind=r["kind"], raw_bytes=len(r["data"]), bits=r["bits"])
                    for r in parsed
                ]
            results["runs"][str(number)] = dict(
                bytes=len(data),
                sections=wire,
                survival_columns=len(report),
                source_binding=run["source_binding"],
                outcomes=dict(
                    collections.Counter(r["outcome"] for r in run["requests"])
                ),
                lag_statuses=dict(
                    collections.Counter(r["status"] for r in run["lags"])
                ),
                dispatch_ns=distribution([r["dispatch_ns"] for r in run["requests"]]),
                event_lag_ns=distribution(
                    [
                        r["routing_to_event_observation_ns"]
                        for r in run["lags"]
                        if r["routing_to_event_observation_ns"] is not None
                    ]
                ),
                gateway_resource_example=recovered["measurements"][0]["gateway"],
                cpu_primary=cpu_values(recovered["measurements"][0]["gateway"], 100),
                gateway_levels=[
                    dict(
                        level_index=i,
                        **cpu_values(row["gateway"], 100),
                        valid_pairs=row["gateway"]["pair_n"],
                        excluded_pairs=row["gateway"]["excluded_pair_n"],
                        identity_mismatch_n=row["gateway"]["identity_mismatch_n"],
                        sample_n=row["gateway"]["sample_n"],
                        pid_change_n=row["gateway"]["pid_change_n"],
                        cpu_decrease_n=row["gateway"]["cpu_decrease_n"],
                        missed_slot_n=row["gateway"]["missed_slot_n"],
                    )
                    for i, row in enumerate(recovered["measurements"])
                ],
                referential_integrity_failures=0,
            )
            if number == 4:
                level0 = results["runs"]["4"]["gateway_levels"][0]
                assert level0["valid_pairs"] == 888
                assert level0["excluded_pairs"] == 10
                assert round(level0["level_mean_cores"], 10) == 1.5095720495
        run3_variants, run3_identity_refusals = run3_sizing_variants(
            output, bindings, composite
        )
        run3_candidates = [
            dict(
                name="registered_ceiling_fixture",
                digest_bytes=results["runs"]["3"]["bytes"],
            ),
            *(
                {"name": row["name"], "digest_bytes": row["digest_bytes"]}
                for row in run3_variants
            ),
        ]
        results["run3_registration_refusals"] = run3_identity_refusals
        results["run3_sizing_variants"] = run3_variants
        results["run3_worst_case_under_registered_constraints"] = {
            **max(run3_candidates, key=lambda row: row["digest_bytes"]),
            "basis": "largest measured digest among the registered ceiling fixture, random 63-bit timestamps/sequences with random validity words, the random timestamp/sequence variant, and the maximum-width timestamp/sequence variant",
        }
        # Exercise the actual allowlisted metadata exporter with an intentionally huge
        # summary that must be replaced by digest receipts, not repeated in the tar.
        write_json(
            session / "stage-c-summary.json", dict(unbounded_rows=["x" * 1000] * 1000)
        )
        manifest = session / "staging-manifest.json"
        write_json(manifest, dict(schema="fixture", source_sha256=composite))
        for number in (1, 2):
            write_json(
                session / "sealed-runs" / f"run-{number}.digest.receipt.json",
                dict(
                    schema="stage-c-registered-digest-receipt.v1",
                    registration="stage-c-remainder-v1",
                    run_number=number,
                    sha256=hashlib.sha256(
                        f"metadata-receipt-{number}".encode()
                    ).hexdigest(),
                    bytes=1048576,
                    limit_bytes=1048576,
                    path=f"run-{number}.digest.json.gz",
                    per_request_count=14259,
                    event_lag_status="unestablished",
                    protected=None,
                ),
            )
        final = export(session, manifest)
        projection = final_metadata_projection(session)
        assert "unbounded_rows" not in json.dumps(projection)
        results["final_metadata"] = {
            key: value for key, value in final.items() if key != "archive"
        }
        results["final_metadata"]["receipt_projection_raw_bytes"] = len(
            encoded(projection)
        )
        results["final_metadata"]["receipt_projection_gzip_bytes"] = len(
            gzip.compress(encoded(projection), mtime=0)
        )
        results["final_metadata"]["runs1_2_basis"] = (
            "worst-width receipt placeholders only; their digest sizing is a later admission prerequisite"
        )
    rng = random.Random(470150)
    spans = [
        ("prefix", b'{"a":"', False),
        ("a", unpadded(rng.randbytes(884058)), True),
        ("middle", b'","b":"', False),
        ("b", unpadded(rng.randbytes(14848)), True),
        ("suffix", b'"}', False),
    ]
    uniform, report = member(spans)
    assert [r["kind"] for r in blocks(uniform)] == [0, 2, 0, 2, 0]
    assert report["sections"]["a"]["literal_charge_bytes"] <= 886361
    assert report["sections"]["b"]["literal_charge_bytes"] <= 14888
    results["uniform_full_width_carriers"] = report
    c = dict(zip(C_FIELDS, C_MAX, strict=True))
    c["sampler_started_before_load"] = False
    assert len(encoded(c)) == 766
    results["c_max_raw_row_bytes"] = len(encoded(c))
    fault_rows = faults(output)
    results["fault_cases"] = len(fault_rows)
    results["fault_injection_distinct_failure_tuples_reached"] = max(
        row.get("distinct_failure_tuples_reached", 0) for row in fault_rows
    )
    results["transfer_seconds"] = dict(
        payload_500000_Bps={n: r["bytes"] / 500000 for n, r in results["runs"].items()},
        final_100_Bps=results["final_metadata"]["bytes"] / 100,
        final_run4_plus_metadata_fallback=math.ceil(
            results["runs"]["4"]["bytes"] / 12288
        )
        * 2.4
        + results["final_metadata"]["bytes"] / 100,
    )
    results["status"] = "PASS_FOR_SYNTHETIC_SIZING_ONLY"
    write_json(output / "results.json", results)
    checksums = "".join(
        f"{sha(path)}  {path.name}\n"
        for path in sorted(output.iterdir())
        if path.is_file() and path.name != "SHA256SUMS.txt"
    )
    (output / "SHA256SUMS.txt").write_text(checksums, encoding="utf-8", newline="\n")
    print(
        json.dumps(
            dict(
                status=results["status"],
                run_bytes={n: r["bytes"] for n, r in results["runs"].items()},
                final_metadata_bytes=results["final_metadata"]["bytes"],
            )
        )
    )


if __name__ == "__main__":
    main()
