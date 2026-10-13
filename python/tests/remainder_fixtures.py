"""Deterministic source-shaped inputs for the real checkpoint serializer."""

import hashlib
import random

from inference_platform.stage_c_registered import (
    C_FIELDS,
    LAG_STATUS,
    NATIVE_FIELDS,
    OUTCOMES,
    REGISTRATION,
    median,
)


def fixture(number, *, ceiling=False):
    rng = random.Random(470150 + number)
    identity = rng.randbytes(32).hex()
    common_digests = sorted(rng.randbytes(32).hex() for _ in range(2))
    native_keys = [rng.randbytes(64).hex() for _ in range(2)]
    clocks = []
    for i in range(8 if number == 3 else 24):
        monotonic = 8_731_982_100_000_000 + i * 200_000_000_000 + rng.randrange(1000)
        wall = 1_760_000_000_000_000_000 + monotonic - 8_731_982_100_000_000 + i * 10
        clocks.append([wall, monotonic, wall - monotonic, 100, 100, 1000, 10, 0])
    run = {
        "retention_registration": REGISTRATION,
        "run_number": number,
        "status": "completed",
        "event_lag_status": "established",
        "requests": [],
        "lags": [],
        "membership": [],
        "source_binding": {
            key: hashlib.sha256(f"fixture-{number}-{key}".encode()).hexdigest()
            for key in ("run_sha256", "source_sha256", "registration_sha256")
        },
        "retention_receipt": {
            "count_ceiling_hit": False,
            "field_overflow": False,
            "run3_exact_lag_adequacy": "unestablished",
        },
        "dictionaries": {"clocks": clocks},
    }
    base = 8_731_982_100_000_000
    if number == 3:
        groups = []
        for reset in range(3):
            groups.extend((reset, reset * 8 + cold, 1, cold) for cold in range(8))
            groups.append((reset, 24 + reset, 1200 if ceiling else 100, None))
    else:
        control = [45 * c for c in (1, 2, 4, 8, 12, 16, 24, 32, 48, 64)]
        reference = [n for n in (32, 48, 56, 60, 68, 76, 92) for _ in range(2)]
        patched = [180, 720, 2880, 60, 60]
        groups = [
            (
                0 if i < 10 else 1 + (i - 10) // 2 if i < 24 else 8 if i < 27 else 9,
                i,
                n if ceiling else 30,
                None,
            )
            for i, n in enumerate(control + reference + patched)
        ]
        run.update(
            failure_tuples=[],
            native_counters=[],
            level_aggregates=[],
            exposures=[],
            snapshot_count_sources=[],
            cadence_start_ns=base,
            cache_config={
                "num_gpu_blocks": 3891,
                "block_size": 16,
                "kv_cache_size_tokens": 62256,
                "enable_prefix_caching": True,
            },
        )
    control_concurrency = (1, 2, 4, 8, 12, 16, 24, 32, 48, 64)
    reference_identities = {}
    for reset, level, n, _cold in groups:
        concurrency = (
            control_concurrency[level]
            if number == 4 and level < 10
            else (4, 16, 64)[level - 24]
            if number == 4 and 24 <= level < 27
            else 1
        )
        start = base + level_start(number, level) * 10**9 + rng.randrange(10**6)
        for ordinal in range(n):
            i = len(run["requests"])
            status = LAG_STATUS[i % len(LAG_STATUS)]
            outcome = OUTCOMES[i % len(OUTCOMES)]
            reference = number == 4 and (10 <= level < 24 or level >= 27)
            prompt = 34 if number == 3 else 1024 if reference else 6144
            if number == 3:
                prompt_identity = identity
            elif reference:
                corpus = (level - 10) // 2 if level < 24 else 3
                prompt_identity = reference_identities.setdefault(
                    (corpus, ordinal), rng.randbytes(32).hex()
                )
            else:
                prompt_identity = rng.randbytes(32).hex()
            dispatch = (
                start
                + (
                    ordinal // concurrency * 2_000_000_000 + ordinal % concurrency * 10000
                    if number == 4 and not reference
                    else ordinal * (80_000_000_000 // max(n, 1))
                )
                + rng.randrange(1000)
            )
            first = (
                dispatch + rng.randrange(10**7, 10**9)
                if outcome in ("completed", "partial", "in-stream-error")
                else None
            )
            terminal = (
                dispatch + rng.randrange(10**9, 30 * 10**9)
                if outcome not in ("drain-cut", "pending")
                else None
            )
            censor = dispatch + 60 * 10**9 + rng.randrange(10**8) if terminal is None else None
            lag = rng.randrange(10**6, 10**10) if status in LAG_STATUS[:2] else None
            request = {
                "per_request_index": i,
                "level_index": level,
                "worker_index": 0 if number == 3 else None if reference else ordinal % concurrency,
                "worker_cycle": None if number == 3 or reference else ordinal // concurrency,
                "prefix_ordinal": ordinal if reference else None,
                "reset_epoch": reset,
                "replica_index": 0,
                "group_index": 0,
                "prompt_identity_sha256": prompt_identity,
                "dispatch_ns": dispatch,
                "first_content_ns": first,
                "terminal_ns": terminal,
                "censor_ns": censor,
                "outcome": outcome,
                "prompt_tokens": prompt,
                "completion_tokens": 1 if prompt != 6144 else rng.randrange(129),
                "cached_prompt_tokens": rng.randrange(prompt + 1) if i % 4 else None,
                "event_lag_status": status,
                "event_lag_ns": lag,
                "validity_flags": i % 16,
            }
            matched = (
                (
                    common_digests
                    if number == 3
                    else sorted(rng.randbytes(32).hex() for _ in range(64 if reference else 384))
                )
                if status in LAG_STATUS[:2]
                else []
            )
            lag_row = {
                "per_request_index": i,
                "level_index": level,
                "reset_epoch": reset,
                "replica_index": 0,
                "group_index": 0,
                "prompt_identity_sha256": prompt_identity,
                "status": status,
                "match_basis": "identity-specific-digest" if matched else "unavailable",
                "exclusion_flags": i % 128,
                "routing_decision_monotonic_ns": dispatch + 3271,
                "gateway_terminal_monotonic_ns": terminal,
                "request_lifetime_ns": terminal - dispatch if terminal is not None else None,
                "publisher_flush_allowance_ns": 1_000_000_000,
                "store_observation_window_end_monotonic_ns": terminal + 10**9
                if terminal is not None
                else None,
                "next_same_identity_decision_monotonic_ns": dispatch
                + 70 * 10**9
                + rng.randrange(10**6),
                "event_observed_monotonic_ns": dispatch + 3271 + lag if lag is not None else None,
                "routing_to_event_observation_ns": lag,
                "event_sequence": i * 7 + rng.randrange(7) if matched else None,
                "matched_token_block_digests": matched,
                "excluded_shared_digest_count": rng.randrange(3),
                "clock_pair_index": i % (8 if number == 3 else 24),
                "validity_flags": i % 16,
            }
            run["requests"].append(request)
            run["lags"].append(lag_row)
            if number == 3:
                for position, digest in enumerate(common_digests):
                    run["membership"].append(
                        {
                            "per_request_index": i,
                            "block_position": position,
                            "token_block_digest": digest,
                            "native_cached_key": native_keys[position],
                            "in_W": True,
                        }
                    )
            else:
                # Ten administrative/terminal outcomes can share exact error metadata.
                # This does not merge distinct tuples: the repeated tuple really is equal.
                failure = (
                    (200, "completed", "completed", None, 0)
                    if outcome == "completed"
                    else (None, None, "other_or_unestablished", None, 0)
                )
                if outcome == "pre-content-rejection":
                    failure = (502, "upstream_failure", "vllm_pre_content_rejection", 400, 400)
                elif outcome == "in-stream-error":
                    failure = (
                        200,
                        "stream_interrupted",
                        "vllm_in_stream_error",
                        "stream_interrupted",
                        500,
                    )
                elif outcome == "transport-error":
                    failure = (
                        400,
                        "invalid_request",
                        "gateway_protocol_rejection",
                        "invalid_request",
                        None,
                    )
                elif outcome == "unknown":
                    failure = (503, "no_healthy_backend", "gateway_no_healthy_backend", None, None)
                elif outcome == "cancelled":
                    failure = (None, "client_cancelled", "other_or_unestablished", None, None)
                elif outcome == "timeout":
                    failure = (504, "upstream_timeout", "other_or_unestablished", None, None)
                run["failure_tuples"].append(failure)
        if number == 4:
            native = native_source(rng, level % 4)
            native["bracket_before_ns"] = start - rng.randrange(10**6)
            native["bracket_after_ns"] = start + 90 * 10**9 + rng.randrange(10**6)
            run["native_counters"].append(native)
            cohort = [row for row in run["requests"] if row["level_index"] == level]
            success = [row for row in cohort if row["outcome"] == "completed"]
            c = dict.fromkeys(C_FIELDS, 0)
            c.update(
                level_index=level,
                arm=int(level >= 24),
                phase_id=reset,
                exposure_id=level,
                concurrency=concurrency,
                row_status=0,
                load_mode=(2 if level % 2 == 1 and level < 24 or level == 28 else 1)
                if reference
                else 0,
                duration_ns=90 * 10**9 + rng.randrange(10**8),
                planned_load_s=90,
                minimum_cycle_s=2,
                sampler_started_before_load=True,
                dispatch_n=n,
                unmatched_dispatched_n=0,
                censored_ttft_n=sum(row["first_content_ns"] is None for row in cohort),
                screen_status=1,
                screen_dispatch_n=n,
                screen_completion_n=len(success),
                screen_ttft_success_n=len(success),
                screen_unsuccessful_n=n - len(success),
                screen_exposure_start_ns=start,
                screen_exposure_end_ns=start + 90 * 10**9,
                screen_ttft_p50_ns=median(
                    [row["first_content_ns"] - row["dispatch_ns"] for row in success]
                ),
                screen_prefix_match_n=None,
                screen_prefix_equal_n=None,
                diagnostic_status=level % 4,
                diagnostic_valid_n=native["diagnostic_valid_n"],
                diagnostic_invalid_n=native["diagnostic_invalid_n"],
                preemption_delta=native["preemptions_delta"],
                running_peak=native["running_peak"],
                waiting_peak=native["waiting_peak"],
            )
            run["level_aggregates"].append(c)
            samples = {}
            for quantity in (
                ("cached", "shared", "non_shared", "evictable", "capacity", "lag", "queue")
                if level >= 24
                else ("cached", "lag")
            ):
                samples[quantity] = [
                    [
                        start + j * 100_000_000 + rng.randrange(1000),
                        None if j % 43 == 0 else rng.randrange(3892),
                        j % 37 != 0,
                    ]
                    for j in range(900 if ceiling else 20)
                ]
            run["exposures"].append(
                {
                    "start_ns": start,
                    "end_ns": start + 90 * 10**9,
                    "arm": int(level >= 24),
                    "phase": (2 if level % 2 == 1 and level < 24 or level == 28 else 1)
                    if reference
                    else 0,
                    "reset_epoch": reset,
                    "samples": samples,
                    "matcher_rule_violations": 0,
                    "missing_duplicate_joins": 0,
                    "validity_flags": level % 16,
                    "source_reconciliation": [rng.randrange(100) for _ in range(8)],
                }
            )
            if level >= 24:
                from inference_platform.stage_c_registered import SNAPSHOT_FIELDS

                slot = round((start + 45 * 10**9 - base) / 100_000_000)
                snapshot = {token.split(":")[0]: 0 for token in SNAPSHOT_FIELDS.split()}
                snapshot.update(
                    snapshot_index=slot,
                    cadence_slot=slot,
                    arm=1,
                    phase=(2 if level % 2 == 1 and level < 24 or level == 28 else 1)
                    if reference
                    else 0,
                    reset_epoch=reset,
                    status=0,
                    observed_ns=base + slot * 100_000_000 + rng.randrange(10000),
                    scan_duration_ns=rng.randrange(10**5),
                    cached=rng.randrange(3892),
                    shared=rng.randrange(1000),
                    queue_depth=rng.randrange(10**6),
                    queue_read_ns=base + slot * 100_000_000,
                    queue_read_cost_ns=rng.randrange(10**5),
                    presence_bitmap=(1 << 36) - 1,
                )
                run["snapshot_count_sources"].append(snapshot)
    if number == 4:
        run["reference_manifest"] = {
            str(level): [
                row["prompt_identity_sha256"]
                for row in run["requests"]
                if row["level_index"] == level
            ]
            for level in list(range(10, 24)) + [27, 28]
        }
        for replay in (17, 28):
            population = [r for r in run["requests"] if r["level_index"] == replay - 1]
            replays = [r for r in run["requests"] if r["level_index"] == replay]
            row = run["level_aggregates"][replay]
            row["screen_prefix_match_n"] = len(replays)
            row["screen_prefix_equal_n"] = sum(
                a["cached_prompt_tokens"] is not None
                and b["cached_prompt_tokens"] is not None
                and a["cached_prompt_tokens"] == b["cached_prompt_tokens"]
                for a, b in zip(population, replays, strict=True)
            )
    run["gateway_cpu_ticks_per_second"] = 100
    run["measurement_sources"] = [
        measurement_source(
            i,
            run["exposures"][i]["start_ns"]
            if number == 4
            else base + level_start(number, i) * 10**9,
            rng,
            ceiling,
            sample_count=(100 if i < 24 else 1200) if number == 3 and ceiling else None,
        )
        for i in range(27 if number == 3 else 29)
    ]
    run["cache_config"] = dict(
        num_gpu_blocks=3891, block_size=16, kv_cache_size_tokens=62256, enable_prefix_caching=True
    )
    if number == 3:
        run["native_counters"] = [native_source(rng) for _ in range(27)]
        run["rewarm_convergence_compact"] = protected(run, rng)
        run["dictionaries"]["levels"] = [
            [
                i,
                i // 8 if i < 24 else i - 24,
                int(i >= 24),
                1,
                base + level_start(number, i) * 10**9,
                base + (level_start(number, i) + (10 if i < 24 else 120)) * 10**9,
                0,
            ]
            for i in range(27)
        ]
        run["dictionaries"]["resets"] = [[i, 0, 0, 0] for i in range(3)]
    else:
        run["extension_header"] = {
            "clocks": run["dictionaries"]["clocks"],
            "levels": [
                [
                    i,
                    run["exposures"][i]["start_ns"],
                    run["exposures"][i]["end_ns"],
                    run["level_aggregates"][i]["phase_id"],
                ]
                for i in range(29)
            ],
            "epochs": [[i, base + i * 400 * 10**9, rng.randrange(10**6), 0] for i in range(10)],
            "global_counters": [[rng.randrange(10**12)] for _ in range(64)],
            "first_hit_receipts": [[0] * 8 for _ in range(8)],
            "reference_manifest_hashes": [
                hashlib.sha256(
                    b"stage-c-reference-manifest-v1\0"
                    + len(values).to_bytes(4, "big")
                    + b"".join(bytes.fromhex(v) for v in values)
                ).hexdigest()
                for values in run["reference_manifest"].values()
            ],
        }
    return run


def protected(run, rng):
    value = {
        "schema": "rewarm_convergence_compact.v1",
        "header": {
            "prompt_sha256": run["requests"][0]["prompt_identity_sha256"],
            "replica": "engine-0",
            "outcomes": OUTCOMES,
            "clock": "same-host monotonic ns",
            "counter_labels": ["vllm:prefix_cache_hits_total", "vllm:prefix_cache_queries_total"],
        },
        "reset_rows": [],
        "cold_rows": [],
        "window_rows": [],
        "histogram_rows": [],
    }
    for reset in range(3):
        sustained = [row for row in run["requests"] if row["level_index"] == 24 + reset]
        start = min(row["dispatch_ns"] for row in sustained)
        hist = [[reset, i, True, *([0] * 20)] for i in range(240)]
        for row in sustained:
            outcome = OUTCOMES.index(row["outcome"])
            b = (row["dispatch_ns"] - start) // 10**9
            hist[b][3 + outcome] += 1
            if outcome != 9:
                end = row["terminal_ns"] or row["censor_ns"]
                hist[min(239, (end - start) // 10**9)][13 + outcome] += 1
        value["histogram_rows"].extend(hist)
        value["reset_rows"].append(
            [
                reset,
                "success",
                True,
                start - 20 * 10**9,
                start,
                start + 120 * 10**9,
                start + 240 * 10**9,
                True,
                None,
                start + 120 * 10**9,
                "unestablished",
            ]
        )
        h, q = rng.randrange(10**12), rng.randrange(10**12)
        for window in range(12):
            bins = hist[window * 10 : (window + 1) * 10]
            n, final = sum(sum(row[3:13]) for row in bins), sum(sum(row[13:23]) for row in bins)
            t = start + window * 10 * 10**9
            value["window_rows"].append(
                [
                    reset,
                    window,
                    t,
                    t + 10 * 10**9,
                    t + rng.randrange(10**6),
                    t + 10 * 10**9 + rng.randrange(10**6),
                    h,
                    h + n * 32,
                    q,
                    q + n * 34,
                    n * 32,
                    n * 34,
                    n,
                    final,
                    True,
                    True,
                    window == 5,
                    window == 7,
                    "partial" if window in (5, 7) else "complete",
                ]
            )
            h, q = h + n * 32, q + n * 34
        for row in run["requests"]:
            if row["reset_epoch"] == reset and row["level_index"] < 24:
                value["cold_rows"].append(
                    [
                        reset,
                        row["level_index"] % 8,
                        rng.randbytes(16).hex(),
                        row["dispatch_ns"],
                        row["first_content_ns"],
                        row["terminal_ns"],
                        row["censor_ns"],
                        row["outcome"],
                        q,
                        q + 34,
                        h,
                        h + 32,
                        True,
                        True,
                        False,
                        "valid",
                    ]
                )
    return value


def native_source(rng, status=0):
    row = {key: rng.randrange(10**9, 10**12) for key in NATIVE_FIELDS}
    for key in NATIVE_FIELDS:
        if key.endswith("_n"):
            row[key] = rng.randrange(900)
    row.update(
        usage_peak=rng.random(),
        hits_created_before=1700000000.125,
        hits_created_after=1700000000.125,
        queries_created_before=1700000000.125,
        queries_created_after=1700000000.125,
        counter_status=0,
        preemptions_status=0,
        preemptions_delta=rng.randrange(10**6),
        running_peak=rng.randrange(65),
        waiting_peak=rng.randrange(128),
    )
    row["bracket_before_ns"] = 8_731_982_100_000_000 + rng.randrange(10**9)
    row["bracket_after_ns"] = row["bracket_before_ns"] + 90 * 10**9
    for stem in ("hits", "queries", "preemptions"):
        row[stem + "_after"] = row[stem + "_before"] + rng.randrange(1000000)
        row[stem + "_delta"] = row[stem + "_after"] - row[stem + "_before"] if status == 0 else None
    row["counter_status"] = row["preemptions_status"] = status
    row["counter_reset_n"] = int(status == 1)
    row["counter_missing_n"] = int(status == 2)
    if status == 1:
        row["hits_created_after"] += 90
        row["queries_created_after"] += 90
    if status == 2:
        for field in (
            "hits_after",
            "queries_after",
            "preemptions_after",
            "usage_peak",
            "running_peak",
            "waiting_peak",
        ):
            row[field] = None
    return row


def measurement_source(level, start, rng, ceiling, sample_count=None):
    samples, cpu = [], rng.randrange(10**9)
    for i in range(sample_count if sample_count is not None else 900 if ceiling else 20):
        cpu += rng.randrange(1, 30)
        samples.append(
            dict(
                slot=i,
                pid=4172,
                start_ticks=871239172,
                monotonic_ns=start + i * 100_000_000 + rng.randrange(1000),
                cpu_ticks=cpu,
                rss_bytes=70_000_000 + rng.randrange(10**7),
                peak_rss_bytes=100_000_000 + rng.randrange(10**7),
                status="ok",
            )
        )
    # Combined adversarial trace: PID change, recovery, CPU decrease and a real missing slot.
    samples[3]["pid"] += 1
    samples[6]["cpu_ticks"] = samples[5]["cpu_ticks"] - 1
    del samples[9]
    samples[12]["status"] = "access_error"
    samples[15]["status"] = "missing"
    samples[17]["monotonic_ns"] = samples[16]["monotonic_ns"] - 1
    bins = []
    for i in range((sample_count // 10 if sample_count is not None else 90) if ceiling else 3):
        ids = [rng.randbytes(32).hex() for _ in range(rng.randrange(1, 10))]
        bins.append(
            dict(
                second_ns=start + i * 10**9,
                removed_identities=ids + ids[:1],
                valid=i % 17 != 0,
                gap=i % 17 == 0,
                reset=i == 2,
            )
        )

    def hist(offset):
        before = [100000 + i * 1000 for i in range(11)]
        increments = sorted(rng.randrange(1, 100000) for _ in range(11))
        return dict(
            before=dict(buckets=before, count=before[-1], sum=1000.1234567890123),
            after=dict(
                buckets=[a + b for a, b in zip(before, increments, strict=True)],
                count=before[-1] + increments[-1],
                sum=1111.9876543210123,
            ),
            reset=(level + offset) % 7 == 0,
            missing=(level + offset) % 11 == 0,
        )

    return dict(
        level_index=level,
        gateway_samples=samples,
        eviction_bins=bins,
        lookup=hist(0),
        tokenize=hist(1),
    )


def level_start(number, level):
    return (
        ((level // 8) * 320 + (level % 8) * 10 if level < 24 else (level - 24) * 320 + 80)
        if number == 3
        else level * 100
        if level < 24
        else 2700 + (level - 24) * 300
    )
