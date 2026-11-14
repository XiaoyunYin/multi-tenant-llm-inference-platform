"""Recorded synthetic setup streams; no configured network or provider."""

import copy

from test_inf037b_collectors import Records
from test_inf037b_resolver import PINS
from test_inf037b_resolver import fixture as resolver_fixture
from test_inf037b_terminal import Backend

from inference_platform.inf037b_archive import encode, sha
from inference_platform.inf037b_resolver import BOUNDS_MS
from inference_platform.inf037b_terminal import CleanupScope


def creation_raw(binding, ready, *, source_inventory=None, boot="host"):
    records = Records()
    raw = [
        records.row("controller", "precondition", ready, name=k, value=True)
        for k in ("capacity", "bootstrap", "control_plane", "nodes")
    ]
    for row in raw:
        row.update(session_id=binding["session_id"], attempt_id="setup", stage=[])
    inventory = source_inventory or {"fixture": {"bytes": 7, "sha256": sha(b"fixture")}}
    checkpoint = {"clock_id": "measurement", "boot_id": boot, "ms": [binding["t0_ms"]] * 2}
    staging = {
        "binding": binding,
        "pins": binding["pins"],
        "verified": True,
        "copy": {"start": checkpoint, "end": checkpoint},
        "hash": {"start": checkpoint, "end": checkpoint},
        "expected_inventory": inventory,
        "actual_inventory": inventory,
        "manifest_sha256": sha(encode(inventory)),
    }
    return encode(
        {
            "schema": "inf037b-setup-v1",
            **binding,
            "raw": raw,
            "ready": {"clock_id": "measurement", "boot_id": boot, "ms": [ready] * 2},
            "staging": staging,
        }
    )


def fixture():
    files = [{"path": "model/weights", "bytes": 32, "sha256": "b" * 64}]
    pins = {**PINS, "model": sha(encode(files))}
    r, rows, offers, cases = Records(), [], [], []
    for name, created, free, started, completion in (
        ("cold", 1001, 1100, 210900, 211100),
        ("node_cached", 301200, 271200, 511000, 511200),
    ):
        uid = name + "-uid"
        for event, at in (
            ("pod_created", created),
            ("gpu_free", free),
            ("scheduled", max(created, free)),
            ("startup", started),
            ("ready", completion - 150),
        ):
            rows.append(r.row("kubernetes", event, at, pod_uid=uid, slot=0, node_pseudonym="node0"))
        rows.append(
            r.row(
                "vllm",
                "sample",
                completion - 100,
                pod_uid=uid,
                slot=0,
                process_generation="process-" + name,
                model_sha256=pins["model"],
                runtime_sha256=pins["runtime"],
                health_ready=True,
                reset_generation="reset0",
                metric_semantics_sha256="a" * 64,
                running=0,
                waiting=0,
                prefix_query_tokens_total=0,
                prefix_hit_tokens_total=0,
                preemptions_total=0,
            )
        )
        member = {"uid": uid, "ready": True, "healthy": True, "sampled": True}
        for gateway in ("gateway0", "gateway1"):
            for event in ("install", "health"):
                rows.append(
                    r.row(
                        "gateway",
                        event,
                        completion - 100,
                        gateway_uid=gateway,
                        membership_known=True,
                        members=[member],
                    )
                )
            reqrows, offer = r.request(
                name + gateway,
                gateway,
                uid=uid,
                slot=0,
                offered=completion - 95,
                opened=completion - 90,
                first=completion - 80,
                terminal=completion,
            )
            rows.extend(reqrows)
            offers.append(offer)
        cache_at = created - 1 if name == "cold" else free + 100
        witness = {
            "node": "node0",
            "boot_id": "nodeboot",
            "complete": True,
            "observation_ms": [cache_at, cache_at],
            "begin_ns": cache_at * 1000000,
            "end_ns": cache_at * 1000000,
            "model_cache_state": name,
            "image_cache_state": "node_cached",
            "files": [] if name == "cold" else files,
            "activity": {
                "complete": True,
                "interval_ms": [cache_at, created],
                "mutations": [],
                "begin_ns": cache_at * 1000000,
                "end_ns": created * 1000000,
            },
        }
        times = sorted({*range(created, completion + 1, 1000), started, completion})
        lineage = [
            {
                "pod_uid": uid,
                "node_boot_id": "nodeboot",
                "boot_id": "process-" + name,
                "sequence": i,
                "mono_ns": at * 1_000_000,
                "event": "supervisor_start"
                if i == 0
                else "startup"
                if at == started
                else "heartbeat",
            }
            for i, at in enumerate(times)
        ]
        cases.append(
            {
                "name": name,
                "uid": uid,
                "node": "node0",
                "slot": 0,
                "cache": witness,
                "lineage": lineage,
            }
        )
    rows.extend(
        [
            r.row(
                "kubernetes", "signal", 211200, pod_uid="cold-uid", signal="SIGTERM", grace_ms=45000
            ),
            r.row(
                "vllm", "process_end", 256200, pod_uid="cold-uid", process_generation="process-cold"
            ),
            r.row("controller", "action", 271200, name="cached_create_request"),
        ]
    )
    serving = ["node_cached-uid", "other-slot"]
    rows.append(
        # Slot 1 serves before the registered cold stop and throughout caching.
        # This startup-only fixture does not model the separate 120 s probe.
        r.row("kubernetes", "ready", 211125, pod_uid="other-slot", slot=1, node_pseudonym="node1")
    )
    for gateway in ("gateway0", "gateway1"):
        rows.append(
            r.row(
                "gateway",
                "install",
                511250,
                gateway_uid=gateway,
                membership_known=True,
                members=[
                    {"uid": uid, "ready": True, "healthy": True, "sampled": True} for uid in serving
                ],
            )
        )
        rows.append(r.row("client", "live_set", 511250, gateway_uid=gateway, request_ids=[]))
    rows.append(r.row("redis", "snapshot", 511250, occupied=0, active_reservations=[]))
    rows.append(r.row("controller", "precondition", 511300, name="restored", value=True))
    for at in range(1000, 512001, 1000):
        rows.append(
            r.row(
                "clocks",
                "mapping",
                at,
                clock_id="node:node0",
                boot_id="nodeboot",
                local_mono_ms=at,
                local_wall_ms=at,
                remote_ms=at,
                send_ms=at,
                receive_ms=at,
            )
        )
    rows.sort(key=lambda row: row["observed_mono_ns"])
    seqs = {}
    for row in rows:
        key = row["source_kind"], row["source_identity"], row["source_generation"]
        row["source_seq"] = seqs.get(key, 0)
        seqs[key] = row["source_seq"] + 1
        row.update(session_id="setup-session", attempt_id="setup", stage=[])
    component_paths, artifacts = {}, {}

    def proof(name, bound):
        path = "proof/" + name + ".json"
        artifacts[path] = encode(
            {
                "pins": pins,
                "subject": ("lifecycle:" if name in BOUNDS_MS else "startup:") + name,
                "bound_ms": bound,
                "bounded_failure_recovery": True,
                "timeout_recovery_ms": [bound],
            }
        )
        return path

    for name, bound in {
        "grace": 45000,
        "kill_release": 15000,
        "controller_scheduler": 30000,
    }.items():
        component_paths[name] = proof(name, bound)
    other = resolver_fixture()
    for row in other.values():
        row["pins"] = copy.deepcopy(pins)
        if "effective_pins" in row:
            row["effective_pins"] = copy.deepcopy(pins)
    lifecycle = other.pop("lifecycle")
    other.pop("startup")
    for name, bound in BOUNDS_MS.items():
        lifecycle["phases"][name]["offline_proof"]["path"] = proof(name, bound)
    artifacts["proof/sizing.json"] = encode(
        {
            "subject": "lifecycle:export_sizing",
            "pins": pins,
            "fixture": "synthetic maximum raw bytes",
            "raw_bytes": 450000,
        }
    )
    lifecycle["transfer"]["sizing_proof"] = {
        "path": "proof/sizing.json",
        "sha256": sha(artifacts["proof/sizing.json"]),
    }

    # Proof pins in other accepted rows are input fixtures, not this producer's scope.
    def repin(obj):
        if isinstance(obj, dict):
            for key, val in obj.items():
                if key == "pins":
                    obj[key] = copy.deepcopy(pins)
                else:
                    repin(val)
        elif isinstance(obj, list):
            for val in obj:
                repin(val)

    repin(other)
    bundle = {
        "schema": "inf037b-setup-v1",
        "session_id": "setup-session",
        "t0_ms": 1000,
        "pins": pins,
        "raw": rows,
        "requests": offers,
        "cases": cases,
        "model_manifest": files,
        "model_manifest_sha256": pins["model"],
        "component_proofs": component_paths,
        "serving_uids": serving,
    }
    binding = {k: bundle[k] for k in ("session_id", "pins", "t0_ms")}
    return {
        "bundle": bundle,
        "binding": binding,
        "artifacts": artifacts,
        "other_rows": other,
        "lifecycle": lifecycle,
    }


def inventory(scope, tick=lambda: None):
    backend = Backend(scope)

    class ReadOnly:
        def inventory(self, category, descriptor, stop):
            tick()
            return backend.inventory(category, descriptor, stop)

        def capacity_inventory(self, descriptor, stop):
            tick()
            return {
                "complete": True,
                "scope_sha256": sha(encode(descriptor)),
                "tokens": {scope.tokens[0]: ["cr-fixture"]},
                "members": ["cr-fixture"],
            }

    return ReadOnly(), backend


def scope():
    return CleanupScope(
        "setup-session",
        "setup-group",
        ("original-token",),
        ("i-fixture",),
        1000,
        "state-source",
        "independent-export",
    )
