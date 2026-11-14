"""Synthetic raw observations for :36-:40; no live fitness or timing claims."""

import copy

from inf037b_engine_fixture import cache_labels, pod
from test_inf037b_collectors import CONTENT, DONE, FINISH, USAGE, Records
from test_inf037b_resolver import fixture as resolved_fixture

from inference_platform.inf037b_archive import encode, sha, strict_json
from inference_platform.inf037b_live import (
    KubernetesAdapter,
    LifecycleReceiptProducer,
    LiveRows,
    VLLMAdapter,
)
from inference_platform.inf037b_packet import workload_trace


def configuration():
    rows = resolved_fixture()
    fields = {
        "sse": (
            "duration_ms",
            "offers_per_100s",
            "max_tokens",
            "alternating_gateways",
            "pod_deletions",
        ),
        "equivalence": (
            "R",
            "W",
            "ttl_ms",
            "hold_ms",
            "workload_config",
        ),
        "publication": (
            "ttl_ms",
            "discovery_ms",
            "health_ms",
            "publication_ms",
            "discovery_timeout_ms",
            "health_timeout_ms",
        ),
        "ingress": ("request_timeout_ms", "transport_drain_ms", "grace_ms"),
    }
    return {
        "schema": "inf037b-fitness-config-v1",
        "probe_start_ms": 1000,
        "probe_end_ms": 121000,
        "roles": ["measurement", "gateway0", "gateway1", "node0", "node1"],
        "slots": {
            str(s): {
                "uid": f"probe-uid{s}",
                "node": f"node{s}",
                "boot_id": f"nodeboot{s}" if s else "nodeboot",
                "process_generation": f"process-probe-uid{s}",
            }
            for s in (0, 1)
        },
        "clocks": [
            {"clock_id": clock, "boot_id": boot}
            for clock, boot in (
                ("redis", "redisboot"),
                ("node:node0", "nodeboot"),
                ("node:node1", "nodeboot1"),
                ("gateway0", "gboot0"),
                ("gateway1", "gboot1"),
                ("client", "clientboot"),
            )
        ],
        "redis_boot_id": "redisboot",
        "addition_uid": "node_cached-uid",
        "tls": {
            f"gateway{s}": {"version": "TLSv1.3", "verified": True, "peer_sha256": "e" * 64}
            for s in (0, 1)
        },
        **{name: {k: copy.deepcopy(rows[name][k]) for k in keys} for name, keys in fields.items()},
    }


def attach(value):
    """Repin the test bundle and add raw fitness, replacing five verdict fixtures."""
    value = copy.deepcopy(value)
    config = configuration()
    pins = value["binding"]["pins"]
    pins["configuration"] = sha(encode(config))

    def repin(obj):
        if isinstance(obj, dict):
            for key, item in obj.items():
                if key in ("pins", "effective_pins"):
                    obj[key] = copy.deepcopy(pins)
                else:
                    repin(item)
        elif isinstance(obj, list):
            for item in obj:
                repin(item)

    repin(value)
    for path, data in value["artifacts"].items():
        parsed = strict_json(data)
        repin(parsed)
        value["artifacts"][path] = encode(parsed)
    value["lifecycle"]["transfer"]["sizing_proof"]["sha256"] = sha(
        value["artifacts"]["proof/sizing.json"]
    )
    value["artifacts"]["fitness/config.json"] = encode(config)
    r, raw, offers = Records(), [], []
    for slot, identity in config["slots"].items():
        uid, process = identity["uid"], identity["process_generation"]
        lifecycle = LifecycleReceiptProducer()
        lifecycle.created(uid, int(slot))
        lifecycle.ingest(
            {
                "pod_uid": uid,
                "sequence": 0,
                "boot_id": process,
                "event": "supervisor_start",
                "mono_ns": 1000000000,
            }
        )
        now_ns = [1_000_000_000]
        rows = LiveRows(
            value["binding"]["session_id"],
            "boot0",
            clock=lambda now_ns=now_ns: now_ns[0],
            sink=raw.append,
        )
        obj = pod()
        obj["metadata"].update(uid=uid, name="vllm-" + slot)
        obj["spec"]["nodeName"] = identity["node"]
        obj["status"]["containerStatuses"][0]["imageID"] = obj["spec"]["containers"][0]["image"]
        KubernetesAdapter(
            rows, None, "test", slot_names={"vllm-" + slot: int(slot)}, lifecycle=lifecycle
        ).pod_observations(obj)
        now_ns[0] += 1_000_000
        rows.row(
            "kubernetes",
            "kubernetes",
            rows.boot,
            "startup",
            {"pod_uid": uid, "slot": int(slot), "reason": "independent_supervisor"},
        )
        now_ns[0] += 1_000_000

        class Native:
            def get(self, path):
                if path == "/metrics":
                    return ("vllm:cache_config_info{" + cache_labels() + "} 1").encode(), {}
                return encode({"data": [{"max_model_len": 8192}]}), {}

        VLLMAdapter(
            rows,
            Native(),
            pod_uid=uid,
            slot=int(slot),
            process_generation=process,
            model_sha256=pins["model"],
            runtime_sha256=pins["runtime"],
            semantics_sha256=pins["engine"],
            lifecycle=lifecycle,
        ).engine_config()
    for role in config["roles"]:
        raw.append(
            r.row(
                "controller",
                "resolution",
                1000,
                name="configuration:" + role,
                input_sha256=pins["configuration"],
                value=copy.deepcopy(pins),
            )
        )
        for at in range(1000, 122001, 1000):
            raw.append(
                r.row(
                    "controller",
                    "resource",
                    at,
                    role=role,
                    window_start_ms=max(1000, at - 1000),
                    window_end_ms=at,
                    limit_known=True,
                    value={"cpu_ppm": 700000, "nic_ppm": 700000},
                )
            )

    def request(
        rid,
        gateway,
        slot,
        offered,
        opened,
        first,
        terminal,
        *,
        cancel=False,
        prefix="prefix0",
        index=0,
    ):
        uid = config["slots"][str(slot)]["uid"]
        rows, offer = r.request(
            rid,
            gateway,
            uid=uid,
            slot=slot,
            offered=offered,
            opened=opened,
            first=first,
            terminal=terminal,
            outcome="cancel" if cancel else "terminal",
            data=CONTENT if cancel else CONTENT,
        )
        if not cancel:
            rows.append(
                r.row(
                    "client",
                    "sse",
                    terminal,
                    request_id=rid,
                    gateway_uid=gateway,
                    chunk_hex=(FINISH + USAGE + DONE).hex(),
                )
            )
        for row in rows:
            p = row["payload"]
            if p.get("config_sha256") is not None:
                p["config_sha256"] = pins["configuration"]
            if p.get("offer_index") is not None:
                p["offer_index"] = index
            if p.get("prefix_id") is not None:
                p["prefix_id"] = prefix
        offer.update(config_sha256=pins["configuration"], prefix_id=prefix, offer_index=index)
        offers.append(offer)
        raw.extend(rows)
        for event, at in (("accept", opened), ("terminal", terminal + (10 if cancel else 0))):
            raw.append(
                r.row(
                    "vllm",
                    event,
                    at,
                    request_id=rid,
                    pod_uid=uid,
                    slot=slot,
                    model_sha256=pins["model"],
                    runtime_sha256=pins["runtime"],
                    process_generation="process-" + uid,
                    **(
                        {"terminal_reason": "client_cancel_abort"}
                        if cancel and event == "terminal"
                        else {}
                    ),
                )
            )
        if cancel:
            raw.append(
                r.row(
                    "gateway",
                    "upstream_close",
                    terminal + 5,
                    request_id=rid,
                    gateway_uid=gateway,
                    backend_uid=uid,
                    backend_slot=slot,
                    reservation_id="reservation-" + rid,
                )
            )
            raw.append(
                r.row(
                    "redis",
                    "release",
                    terminal + 20,
                    request_id=rid,
                    redis_time_ms=terminal + 20,
                    reservation_id="reservation-" + rid,
                    result="released",
                )
            )

    for item in workload_trace("pre", 1, 120000):
        at = 1000 + item["scheduled_ms_numerator"] // item["scheduled_ms_denominator"]
        request(
            item["request_id"],
            item["gateway_uid"],
            (item["offer_index"] // 2) % 2,
            at,
            at + 1,
            at + 2,
            at + 1000,
            prefix=item["prefix_id"],
            index=item["offer_index"],
        )
    for gateway in ("gateway0", "gateway1"):
        for slot in (0, 1):
            rid = f"ingress-{gateway}-{slot}"
            request(rid, gateway, slot, 130000, 130010, 130020, 130100)
            raw.append(
                r.row(
                    "controller",
                    "precondition",
                    130000,
                    name="tls:" + rid,
                    value=config["tls"][gateway],
                )
            )
        request("cancel-" + gateway, gateway, 0, 131000, 131010, 131020, 131030, cancel=True)
    for slot in (0, 1):
        raw.append(r.row("vllm", "sample", 92000, pod_uid=f"probe-uid{slot}", slot=slot))
    for i, name in enumerate(
        ("known2", "known1", "known0", "expired", "unknown", "hold_start", "hold_end")
    ):
        at = 140000 + i * 10000
        n = int(name[-1]) if name.startswith("known") else 2
        stored = at - 8000 if name == "expired" else at - (2500 if name == "hold_end" else 0)
        reports = {
            g: {
                "n": n,
                "unknown": name == "unknown",
                "stored_ms": stored,
                "expires_ms": stored + 8000,
            }
            for g in ("gateway0", "gateway1")
        }
        raw.append(
            r.row(
                "redis",
                "snapshot",
                at,
                redis_time_ms=at,
                snapshot_id=name,
                config_sha256=pins["configuration"],
                reports=reports,
                lows=[],
                state={
                    "n": 1 if name == "hold_start" else n,
                    "candidate": 2 if name == "hold_start" else None,
                    "since_ms": at - 1 if name == "hold_start" else at,
                    "until_ms": at + 20000,
                },
                occupied=0,
                active_reservations=[],
                store_order=2 * i,
            )
        )
        if i < 5:
            raw.append(
                r.row(
                    "redis",
                    "admit",
                    at,
                    redis_time_ms=at,
                    snapshot_id=name,
                    result=5 * n if name.startswith("known") else "refuse",
                    store_order=2 * i + 1,
                )
            )
            for gateway in ("gateway0", "gateway1"):
                raw.append(
                    r.row(
                        "gateway",
                        "admit",
                        at,
                        gateway_uid=gateway,
                        snapshot_id=name,
                        store_order=2 * i + 1,
                        effective_n=n if name.startswith("known") else 0,
                        effective_b=5 * n if name.startswith("known") else 0,
                        decision="observed" if name.startswith("known") else "refused",
                    )
                )
    for source_name, name, at, order, n in (
        ("known1", "cached_stop_known1", 189000, 30, 1),
        ("known2", "cached_restore_known2", 512200, 32, 2),
        ("known2", "post_outage_known2", 512300, 34, 2),
        ("known2", "post_outage_agreement", 512400, 36, 2),
    ):
        source = next(
            row
            for row in raw
            if row["source_kind"] == "redis"
            and row["payload"]["event"] == "snapshot"
            and row["payload"].get("snapshot_id") == source_name
        )
        snapshot = copy.deepcopy(source)
        snapshot["payload"].update(snapshot_id=name, redis_time_ms=at, store_order=order)
        snapshot["payload"]["state"].update(n=n, candidate=None, since_ms=at, until_ms=at + 20000)
        for report in snapshot["payload"]["reports"].values():
            report.update(n=n, unknown=False, stored_ms=at - 1000, expires_ms=at + 7000)
        snapshot["source_time"]["value"] = at
        snapshot["observed_mono_ns"] = at * 1000000
        snapshot["capture_start_mono_ns"] = at * 1000000
        snapshot["capture_end_mono_ns"] = at * 1000000
        raw.append(snapshot)
    # Hold endpoints are 2s apart and share live reports for the whole interval.
    for row in raw:
        if row["payload"].get("snapshot_id") == "hold_end":
            row["source_time"]["value"] = 192000
            row["payload"]["redis_time_ms"] = 192000
            for report in row["payload"]["reports"].values():
                report.update(stored_ms=191000, expires_ms=199000)
    for gateway in ("gateway0", "gateway1"):
        member = {"uid": "node_cached-uid", "healthy": True, "sampled": True, "ready": True}
        for at, order, sid in (
            (191000, 11, "untrusted_label"),
            (508100, 20, "prior"),
            (511200, 22, "next"),
        ):
            raw.append(
                r.row(
                    "redis",
                    "report_store",
                    at,
                    gateway_uid=gateway,
                    redis_time_ms=at,
                    snapshot_id=sid,
                    store_order=order,
                    report_success=True,
                    report_known=True,
                    report_complete=True,
                    n=2,
                )
            )
        raw.append(
            r.row(
                "gateway",
                "report_result",
                191100,
                gateway_uid=gateway,
                report_success=True,
                last_success_redis_ms=191000,
            )
        )
        raw.append(r.row("gateway", "health", 511050, gateway_uid=gateway, members=[member]))
        raw.append(
            r.row(
                "gateway",
                "install",
                511100,
                gateway_uid=gateway,
                replacement_uid="node_cached-uid",
                membership_known=True,
                members=[member],
                install_redis_ms_bounds=[511100, 511100],
                store_order=21,
            )
        )
        raw.append(
            r.row(
                "gateway",
                "report_result",
                512000,
                gateway_uid=gateway,
                report_success=True,
                last_success_redis_ms=511200,
            )
        )
    for source in config["clocks"]:
        for at in range(1000, 513001, 1000):
            raw.append(
                r.row(
                    "clocks",
                    "mapping",
                    at,
                    clock_id=source["clock_id"],
                    boot_id=source["boot_id"],
                    local_mono_ms=at,
                    local_wall_ms=at,
                    remote_ms=at,
                    send_ms=at,
                    receive_ms=at,
                )
            )
    raw.sort(key=lambda row: row["source_time"]["value"])
    seqs = {}
    for row in raw:
        p, kind = row["payload"], row["source_kind"]
        clock = None
        if kind == "gateway":
            clock = p["gateway_uid"]
        elif kind in ("redis", "client"):
            clock = kind
        elif kind == "vllm" and p["event"] != "engine_config":
            clock = "node:node" + str(p["slot"])
        if clock is not None:
            row["source_time"]["clock_id"] = clock
            row["source_generation"] = next(
                c["boot_id"] for c in config["clocks"] if c["clock_id"] == clock
            )
            row["source_identity"] = p.get("gateway_uid") or p.get("pod_uid") or kind
        key = row["source_kind"], row["source_identity"], row["source_generation"]
        row["source_seq"] = seqs.get(key, 0)
        row["record_id"] = str(key) + str(row["source_seq"])
        seqs[key] = row["source_seq"] + 1
        row.update(session_id=value["binding"]["session_id"], attempt_id="setup", stage=[])
        row["collector_boot_id"] = "fixture-boot"

    def history(uid, boot, end, signal=False):
        return [
            {
                "pod_uid": uid,
                "node_boot_id": boot,
                "boot_id": "process-" + uid,
                "sequence": i,
                "mono_ns": at * 1000000,
                "event": "supervisor_start"
                if i == 0
                else "process_start"
                if signal and i == 1
                else "signal"
                if signal and at == end
                else "heartbeat",
                **({"pid": 200} if signal else {}),
                **(
                    {"signal": "SIGTERM", "signal_data": {"receipt_ns": at * 1000000}}
                    if signal and at == end
                    else {}
                ),
            }
            for i, at in enumerate(range(1000, end + 1, 1000))
        ]

    value["fitness_raw"] = encode(
        {
            "schema": "inf037b-setup-v1",
            **value["binding"],
            "raw": raw,
            "requests": offers,
            "fitness_configuration": "fitness/config.json",
            "supervisors_source_sha256": pins["supervisor"],
            "supervisors": {
                s["uid"]: history(s["uid"], s["boot_id"], 121000) for s in config["slots"].values()
            },
            "signal_processes": {
                slot: {
                    "uid": "signal-setup-" + slot,
                    "supervisor_sha256": pins["supervisor"],
                    "events": history("signal-setup-" + slot, s["boot_id"], 95000, True),
                    "origin": {
                        "pod_uid": "signal-setup-" + slot,
                        "role": "setup_signal",
                        "slot": int(slot),
                        "node": s["node"],
                        "node_boot_id": s["boot_id"],
                        "supervisor_sha256": pins["supervisor"],
                        "boot_id": "process-signal-setup-" + slot,
                        "supervisor_pid": 100,
                        "supervisor_start": "1",
                    },
                }
                for slot, s in config["slots"].items()
            },
        }
    )
    # No pre-resolved rows are available to the new producer path.
    value.pop("other_rows")
    return value
