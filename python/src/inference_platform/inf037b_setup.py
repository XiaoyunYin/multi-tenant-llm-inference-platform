"""Setup-only raw collector -> v4 startup/lifecycle rows with injected ports.

The command dispatcher is called inside injected ProcessCalls commands. Other
fitness rows and offline proofs are explicit inputs, never successful defaults.
Interrupted setup refuses rather than performing a second startup/probe.
"""

import copy
import hashlib
import os
import secrets
from pathlib import Path

from .inf037b_archive import IntegrityError, encode, safe_file, sha, strict_json
from .inf037b_live import LifecycleReceiptProducer
from .inf037b_requests import RequestJoin
from .inf037b_resolver import (
    BOUNDS_MS,
    allowance,
    exact,
    integer,
    provenance,
    require,
    resolve,
    span,
    startup,
)
from .inf037b_sources import SourceJoin
from .inf037b_terminal import SnapshotProducer, rehearse


def persist_archive_artifacts(store, artifacts):
    """Fsync archive files beside the durable store and return only their manifest."""
    object_store_write = getattr(store, "persist_archive_artifacts", None)
    if callable(object_store_write):
        return object_store_write(artifacts)

    from .inf037b_durable_ports import sync_directory
    from .inf037b_setup_observations import file_facts

    require(hasattr(store, "path"), "setup:archive_store_path")
    store_path = Path(store.path)
    base = store_path.parent / (store_path.name + ".objects")

    def sync(path):
        if os.name == "posix":
            sync_directory(path)
        else:
            raise OSError("setup:archive_directory_fsync_required")

    if not base.exists():
        base.mkdir(mode=0o700, parents=True)
        sync(base.parent)
    require(base.is_dir() and not base.is_symlink(), "setup:archive_object_directory")

    source_paths, facts = {}, {}
    for key, source in artifacts.items():
        require(isinstance(key, str) and "/" in key, "setup:archive_path")
        source = Path(source)
        require(source.is_file() and not source.is_symlink(), "setup:archive_source_file")
        source_paths[key] = source
        facts[key] = file_facts(source)
    address = sha(encode(facts))
    root = base / address
    if not root.exists():
        root.mkdir(mode=0o700)
        sync(base)
    require(root.is_dir() and not root.is_symlink(), "setup:archive_object_root")

    for prefix in ("source", "sanitized", "destination"):
        archive_root = root / prefix
        if not archive_root.exists():
            archive_root.mkdir(mode=0o700)
            sync(root)
        for directory in ("raw", "cohorts", "events"):
            child = archive_root / directory
            if not child.exists():
                child.mkdir(mode=0o700)
                sync(archive_root)

    manifest = {}
    for key, source in source_paths.items():
        target = safe_file(root, key)
        parent = root
        for component in Path(key).parts[:-1]:
            child = parent / component
            if not child.exists():
                child.mkdir(mode=0o700)
                sync(parent)
            require(child.is_dir() and not child.is_symlink(), "setup:archive_object_directory")
            parent = child
        if not target.exists():
            temporary = target.with_name(target.name + ".pending-" + secrets.token_hex(12))
            digest = hashlib.sha256()
            size = 0
            try:
                with source.open("rb") as reader, temporary.open("xb") as writer:
                    while chunk := reader.read(1024 * 1024):
                        size += len(chunk)
                        digest.update(chunk)
                        if writer.write(chunk) != len(chunk):
                            raise OSError("setup:archive_short_write")
                    writer.flush()
                    os.fsync(writer.fileno())
                actual = {"bytes": size, "sha256": digest.hexdigest()}
                exact(actual, facts[key], "setup:archive_copy_integrity")
                os.replace(temporary, target)
                sync(target.parent)
            finally:
                if temporary.exists():
                    temporary.unlink()
                    sync(temporary.parent)
        actual = file_facts(target)
        exact(actual, facts[key], "setup:archive_object_integrity")
        manifest[key] = {
            "path": str(target.resolve()),
            "bytes": actual["bytes"],
            "sha256": actual["sha256"],
        }
    existing = {path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()}
    exact(existing, set(facts), "setup:archive_object_inventory")
    return manifest


class SetupCollector:
    """Keep exact raw bytes; use the accepted schema/order/clock/SSE joins."""

    def __init__(self, data, *, session_id, pins, t0_ms):
        require(type(data) is bytes, "setup:raw_bytes")
        self.data, self.digest = data, sha(data)
        self.bundle = strict_json(data)
        exact(self.bundle["schema"], "inf037b-setup-v1", "setup:schema")
        exact(self.bundle["session_id"], session_id, "setup:session")
        exact(self.bundle["pins"], pins, "setup:pins")
        exact(self.bundle["t0_ms"], t0_ms, "setup:original_t0")
        rows = self.bundle["raw"]
        require(type(rows) is list and bool(rows), "setup:raw_rows")
        for row in rows:
            exact(row["session_id"], session_id, "setup:row_session")
            exact(row["attempt_id"], "setup", "setup:no_rollout")
            exact(row["stage"], [], "setup:no_event_stages")
            require(row["error"] is None and row["missing_reason"] is None, "setup:capture_loss")
        self.join = SourceJoin(rows)
        require(not self.join.errors, "setup:source_join")
        self.rows = self.join.rows
        require(all(t0_ms <= r["time_ms_bounds"][0] for r in self.rows), "setup:before_t0")
        # One collector boot and source generation per identity: reopening a
        # transport cannot erase an epoch change in this single setup run.
        for key in ("collector_boot_id",):
            require(len({r[key] for r in rows}) == 1, "setup:collector_boot")
        identities = {}
        for row in rows:
            identities.setdefault((row["source_kind"], row["source_identity"]), set()).add(
                row["source_generation"]
            )
        require(all(len(v) == 1 for v in identities.values()), "setup:source_boot")

    def find(self, kind, event, **fields):
        return [
            r
            for r in self.rows
            if r["source_kind"] == kind
            and r["payload"]["event"] == event
            and all(r["payload"].get(k) == v for k, v in fields.items())
        ]

    def one(self, kind, event, **fields):
        rows = self.find(kind, event, **fields)
        require(len(rows) == 1, "setup:unique:" + event)
        return rows[0]

    def at(self, kind, event, **fields):
        return self.one(kind, event, **fields)["time_ms_bounds"]

    def row(self, pins):
        times = [r["time_ms_bounds"] for r in self.rows]
        return {
            "phase": "bringup",
            "attempt_id": None,
            "probe_count": 1,
            "pins": copy.deepcopy(pins),
            "sources": [
                {
                    "path": "setup/raw.json",
                    "sha256": self.digest,
                    "sequence": [
                        min(r["source_seq"] for r in self.rows),
                        max(r["source_seq"] for r in self.rows),
                    ],
                }
            ],
            "observation_ms": [min(t[0] for t in times), max(t[1] for t in times)],
            "clock_uncertainty_ms": [0, max((t[1] - t[0]) for t in times)],
            "clock_id": "measurement",
            "selected_ms": max(t[1] for t in times),
        }


def offline_proof(artifacts, path, pins, bound, subject):
    """Resolve the proof reference from its actual immutable artifact bytes."""
    require(path in artifacts, "setup:proof_artifact")
    data = artifacts[path]
    require(type(data) is bytes, "setup:proof_bytes")
    value = strict_json(data)
    exact(value["pins"], pins, "setup:proof_pins")
    exact(value.get("subject"), subject, "setup:proof_subject")
    exact(value["bound_ms"], bound, "setup:proof_bound")
    exact(value["bounded_failure_recovery"], True, "setup:bounded_failure_recovery")
    parts = value["timeout_recovery_ms"]
    require(
        type(parts) is list
        and bool(parts)
        and all(integer(v) and v >= 0 for v in parts)
        and sum(parts) <= bound,
        "setup:proof_components",
    )
    return {
        "path": path,
        "sha256": sha(data),
        "pins": copy.deepcopy(pins),
        "bounded_failure_recovery": True,
    }


def creation_observation(data, binding):
    c = SetupCollector(data, **binding)
    components = {}
    for name in ("capacity", "bootstrap", "control_plane", "nodes"):
        row = c.one("controller", "precondition", name=name)
        exact(row["payload"]["value"], True, "setup:creation_ready:" + name)
        components[name] = row["time_ms_bounds"]
    ready = max(interval[1] for interval in components.values())
    observation = [
        max(interval[0] for interval in components.values()) - binding["t0_ms"],
        ready - binding["t0_ms"],
    ]
    allowance("creation", [observation], BOUNDS_MS["creation"])
    return {
        "raw": strict_json(data),
        "raw_bytes": data.decode("utf-8"),
        "raw_sha256": sha(data),
        "components": components,
        "ready_ms": ready,
        "observation_ms": observation,
        "staging": c.bundle.get("staging"),
        "ready": c.bundle.get("ready"),
    }


def startup_row(collector, *, pins, artifacts):
    """One cold then same-node cached check; Pending never reduces D_bind."""
    c, bundle = collector, collector.bundle
    specs = bundle["cases"]
    exact([s["name"] for s in specs], ["cold", "node_cached"], "setup:case_order")
    require(specs[0]["uid"] != specs[1]["uid"], "setup:fresh_cached_uid")
    exact(specs[0]["node"], specs[1]["node"], "setup:same_node")
    exact(specs[0]["slot"], specs[1]["slot"], "setup:same_gpu_slot")
    expected_files = bundle["model_manifest"]
    require(type(expected_files) is list and bool(expected_files), "setup:model_manifest")
    require(len({f["path"] for f in expected_files}) == len(expected_files), "setup:model_paths")
    for file in expected_files:
        require(
            type(file["path"]) is str
            and bool(file["path"])
            and integer(file["bytes"])
            and file["bytes"] > 0,
            "setup:model_file",
        )
        from .inf037b_resolver import proof

        proof({"path": file["path"], "sha256": file["sha256"]}, "setup:model_file")
    exact(sha(encode(expected_files)), bundle["model_manifest_sha256"], "setup:model_manifest_hash")
    # The exact-plan model pin binds the complete file manifest, not a filename.
    exact(bundle["model_manifest_sha256"], pins["model"], "setup:pinned_model_manifest")
    requests = RequestJoin(c.rows, bundle["requests"], c.row(pins)["selected_ms"])
    require(not requests.errors, "setup:request_join")
    require(len(requests.cohorts) == 4, "setup:four_startup_requests")
    result = c.row(pins)
    result.update(
        components_ms={"grace": 45_000, "kill_release": 15_000, "controller_scheduler": 30_000},
        cases={},
    )
    paths = list(bundle["component_proofs"].values())
    require(len(paths) == len(set(paths)), "setup:distinct_proof_paths")
    result["component_proofs"] = {
        name: offline_proof(
            artifacts, bundle["component_proofs"][name], pins, bound, "startup:" + name
        )
        for name, bound in result["components_ms"].items()
    }
    for spec in specs:
        uid, name = spec["uid"], spec["name"]
        created = c.at("kubernetes", "pod_created", pod_uid=uid)
        free = c.at("kubernetes", "gpu_free", pod_uid=uid)
        ready = c.at("kubernetes", "ready", pod_uid=uid)
        started = c.at("kubernetes", "startup", pod_uid=uid)
        for event in ("pod_created", "gpu_free", "scheduled", "startup", "ready"):
            payload = c.one("kubernetes", event, pod_uid=uid)["payload"]
            exact(payload["node_pseudonym"], spec["node"], "setup:node_lineage")
            exact(payload["slot"], spec["slot"], "setup:slot_lineage")
        require(created[1] <= started[0] <= started[1] <= ready[0], "setup:startup_order")
        witness = spec["cache"]
        exact(witness["node"], spec["node"], "setup:cache_node")
        exact(witness["complete"], True, "setup:cache_complete")
        exact(witness["model_cache_state"], name, "setup:cache_state")
        require(witness["image_cache_state"] in ("cold", "node_cached"), "setup:image_cache")
        cache_at = span(witness["observation_ms"], "setup:cache_time")
        mapped_cache = c.join.clocks.map(
            "node:" + spec["node"],
            witness["boot_id"],
            witness["begin_ns"] // 1_000_000,
            (witness["end_ns"] + 999_999) // 1_000_000,
        )
        exact(mapped_cache, cache_at, "setup:cache_clock_join")
        require(
            bundle["t0_ms"] <= cache_at[0] <= cache_at[1] < created[0],
            "setup:cache_before_creation",
        )
        exact(witness["files"], [] if name == "cold" else expected_files, "setup:cache_files")
        if name == "node_cached":
            window = witness["activity"]
            exact(window["complete"], True, "setup:cache_activity_complete")
            exact(window["interval_ms"], [cache_at[0], created[1]], "setup:cache_activity_window")
            mapped_activity = c.join.clocks.map(
                "node:" + spec["node"],
                witness["boot_id"],
                window["begin_ns"] // 1_000_000,
                (window["end_ns"] + 999_999) // 1_000_000,
            )
            exact(mapped_activity, window["interval_ms"], "setup:cache_activity_clock_join")
            exact(window["mutations"], [], "setup:no_cache_population")
        # Replay original independent supervisor records with the accepted sticky
        # loss/sequence/boot/gap validator. A boolean lineage flag is insufficient.
        lineage = LifecycleReceiptProducer()
        lineage.created(uid, spec["slot"])
        events = spec["lineage"]
        require(bool(events), "setup:lineage")
        for event in events:
            exact(event["pod_uid"], uid, "setup:lineage_uid")
            exact(event["node_boot_id"], witness["boot_id"], "setup:node_boot")
            lineage.ingest(event)
        history = c.join.clocks.map(
            "node:" + spec["node"],
            witness["boot_id"],
            events[0]["mono_ns"] // 1_000_000,
            (events[-1]["mono_ns"] + 999_999) // 1_000_000,
        )
        require(history is not None and history[0] <= created[0], "setup:lineage_origin")
        tail = c.join.clocks.map(
            "node:" + spec["node"],
            witness["boot_id"],
            events[-1]["mono_ns"] // 1_000_000,
            events[-1]["mono_ns"] // 1_000_000,
        )
        # Supervisor mono timestamps are mapped by the same boot-aware mapper.
        mapped_start = c.join.clocks.map(
            "node:" + spec["node"],
            witness["boot_id"],
            next(e["mono_ns"] // 1_000_000 for e in events if e["event"] == "startup"),
            next(e["mono_ns"] // 1_000_000 for e in events if e["event"] == "startup"),
        )
        exact(mapped_start, started, "setup:supervisor_startup_join")
        completions = {}
        for gateway in ("gateway0", "gateway1"):
            cohorts = [
                r
                for r in requests.cohorts
                if r["backend_uid"] == uid and r["gateway_uid"] == gateway
            ]
            require(len(cohorts) == 1, "setup:single_startup_request")
            request = cohorts[0]
            require(
                request["outcome"] == "complete" and request["identity_join_valid"],
                "setup:completion",
            )
            opened, completion = request["upstream_open_ms_bounds"], request["terminal_ms_bounds"]
            require(ready[1] <= opened[0], "setup:ready_before_request")
            installs = [
                r
                for r in c.find("gateway", "install", gateway_uid=gateway)
                if r["time_ms_bounds"][1] <= opened[0]
            ]
            require(bool(installs), "setup:installed_route")
            view = max(installs, key=lambda r: r["time_ms_bounds"][1])["payload"]

            def eligible(member, uid=uid):
                return (
                    member.get("uid") == uid
                    and all(member.get(k) is True for k in ("ready", "healthy", "sampled"))
                    and not member.get("terminating", False)
                )

            require(
                view["membership_known"] is True and any(eligible(m) for m in view["members"]),
                "setup:eligible_route",
            )
            require(
                any(
                    r["time_ms_bounds"][1] <= opened[0]
                    and opened[1] - r["time_ms_bounds"][0] <= 1000
                    and any(eligible(m) for m in r["payload"]["members"])
                    for r in c.find("gateway", "health", gateway_uid=gateway)
                ),
                "setup:fresh_health",
            )
            native = [
                r
                for r in c.find("vllm", "sample", pod_uid=uid)
                if r["time_ms_bounds"][1] <= opened[0]
                and opened[1] - r["time_ms_bounds"][0] <= 1000
            ]
            require(bool(native), "setup:native_metrics")
            sample = max(native, key=lambda r: r["time_ms_bounds"][1])["payload"]
            exact(sample["model_sha256"], pins["model"], "setup:native_model")
            exact(sample["runtime_sha256"], pins["runtime"], "setup:native_runtime")
            exact(sample["process_generation"], lineage.process_boot(uid), "setup:process_lineage")
            exact(sample["health_ready"], True, "setup:native_ready")
            require(
                all(
                    sample.get(key) is not None
                    for key in (
                        "reset_generation",
                        "metric_semantics_sha256",
                        "running",
                        "waiting",
                        "prefix_query_tokens_total",
                        "prefix_hit_tokens_total",
                        "preemptions_total",
                    )
                ),
                "setup:native_fields",
            )
            require(
                tail[0] >= completion[1],
                "setup:lineage_through_completion",
            )
            completions[gateway] = completion
        result["cases"][name] = {
            "pod_creation_ms": created,
            "gpu_free_ms": free,
            "completions_ms": completions,
            "model_cache_verified": True,
            "image_cache_known": True,
            "lifecycle_lineage": True,
            "clocks_joined": True,
        }
    cold, cached = specs
    signal = c.at("kubernetes", "signal", pod_uid=cold["uid"], signal="SIGTERM")
    exited = c.at("vllm", "process_end", pod_uid=cold["uid"])
    exact(
        c.one("vllm", "process_end", pod_uid=cold["uid"])["payload"]["process_generation"],
        cold["lineage"][0]["boot_id"],
        "setup:exit_process",
    )
    release = result["cases"]["node_cached"]["gpu_free_ms"]
    require(
        release[1] <= cached["cache"]["observation_ms"][0]
        and release[1] <= result["cases"]["node_cached"]["pod_creation_ms"][0],
        "setup:cached_after_gpu_release",
    )
    last_cold = max(v[1] for v in result["cases"]["cold"]["completions_ms"].values())
    require(
        last_cold < signal[0] and signal[1] <= exited[0] <= exited[1] <= release[0],
        "setup:exit_release_order",
    )
    grace = c.one("kubernetes", "signal", pod_uid=cold["uid"])["payload"]["grace_ms"]
    exact(grace, 45_000, "setup:configured_grace")
    result["release_elapsed_ms"] = [
        0,
        max(0, release[1] - signal[0] - grace, release[1] - exited[0]),
    ]
    request_create = c.at("controller", "action", name="cached_create_request")
    cached_created = result["cases"]["node_cached"]["pod_creation_ms"]
    require(request_create[1] <= cached_created[0], "setup:creation_request_order")
    result["controller_elapsed_ms"] = [0, cached_created[1] - request_create[0]]
    restored = c.at("controller", "precondition", name="restored")
    exact(
        c.one("controller", "precondition", name="restored")["payload"]["value"],
        True,
        "setup:restoration_ack",
    )
    require(
        max(v[1] for v in result["cases"]["node_cached"]["completions_ms"].values()) <= restored[0],
        "setup:restore_after_startups",
    )
    serving = bundle["serving_uids"]
    require(
        type(serving) is list and len(serving) == 2 and len(set(serving)) == 2,
        "setup:two_distinct_serving_uids",
    )
    placements = []
    for uid in serving:
        ready = c.one("kubernetes", "ready", pod_uid=uid)
        require(ready["time_ms_bounds"][1] <= restored[0], "setup:serving_ready_before_restore")
        payload = ready["payload"]
        require(
            type(payload["slot"]) is int
            and payload["slot"] in (0, 1)
            and bool(payload["node_pseudonym"]),
            "setup:serving_placement",
        )
        placements.append((payload["slot"], payload["node_pseudonym"]))
        if uid == cached["uid"]:
            exact(placements[-1], (cached["slot"], cached["node"]), "setup:cached_serving_slot")
    exact({p[0] for p in placements}, {0, 1}, "setup:distinct_serving_slots")
    require(len({p[1] for p in placements}) == 2, "setup:distinct_serving_nodes")
    require(cached["uid"] in serving, "setup:cached_serving_uid")
    for gateway in ("gateway0", "gateway1"):

        def latest(kind, event, **fields):
            candidates = [
                r for r in c.find(kind, event, **fields) if r["time_ms_bounds"][1] <= restored[0]
            ]
            require(bool(candidates), "setup:restore_observation")
            row = max(candidates, key=lambda r: r["time_ms_bounds"][1])
            require(restored[1] - row["time_ms_bounds"][0] <= 2000, "setup:restore_freshness")
            return row["payload"]

        view = latest("gateway", "install", gateway_uid=gateway)
        exact(view["membership_known"], True, "setup:restore_known")
        members = view["members"]
        require(
            len(members) == 2 and len({m["uid"] for m in members}) == 2,
            "setup:two_distinct_member_uids",
        )
        exact({m["uid"] for m in members}, set(bundle["serving_uids"]), "setup:restored_uids")
        require(
            len(members) == 2
            and all(
                all(m.get(k) is True for k in ("ready", "healthy", "sampled"))
                and not m.get("terminating", False)
                for m in members
            ),
            "setup:two_serving_slots",
        )
        exact(
            latest("client", "live_set", gateway_uid=gateway)["request_ids"],
            [],
            "setup:drained_traffic",
        )
    redis = c.one("redis", "snapshot")["payload"]
    redis_at = c.at("redis", "snapshot")
    require(
        restored[1] - 2000 <= redis_at[0] <= redis_at[1] <= restored[0], "setup:drain_freshness"
    )
    exact(redis["active_reservations"], [], "setup:drained_reservations")
    exact(redis["occupied"], 0, "setup:drained_occupied")
    result.update(
        case_order=["cold", "node_cached"],
        **dict.fromkeys(
            (
                "two_slots_restored",
                "probe_traffic_empty",
                "reservations_empty",
                "cached_same_node",
                "cached_files_verified",
                "no_cache_population",
                "setup_pod_exit_gpu_release",
                "no_rollout",
                "cold_model_cache_empty",
            ),
            True,
        ),
    )
    provenance(result, pins, "startup")
    startup(result)
    return result


def cleanup_observation(*, inventory, scope, stop, sample):
    """O_cleanup includes scoped inventory reads AND the nonmutating model replay.

    sample returns boot/clock identity and a conservative common-timeline bracket.
    Offline test outputs are synthetic observations, never live O_i evidence.
    """
    first = sample()
    previous = span(first["ms"], "setup:cleanup_start")[0]

    def checked():
        nonlocal previous
        value = sample()
        exact(
            (value["clock_id"], value["boot_id"]),
            (first["clock_id"], first["boot_id"]),
            "setup:cleanup_clock_boot",
        )
        lo, hi = span(value["ms"], "setup:cleanup_sample")
        require(previous <= lo <= hi <= stop and hi - lo <= 100, "setup:cleanup_clock")
        previous = lo
        return value

    require(
        bool(first["clock_id"])
        and bool(first["boot_id"])
        and scope.t0_ms <= first["ms"][0]
        and first["ms"][1] < stop
        and first["ms"][1] - first["ms"][0] <= 100,
        "setup:cleanup_start",
    )
    snapshot = SnapshotProducer(inventory, lambda: checked()["ms"][1]).produce(scope, stop)
    replay = rehearse(snapshot)
    last = checked()
    elapsed = [max(0, last["ms"][0] - first["ms"][1]), last["ms"][1] - first["ms"][0]]
    allowance("cleanup", [elapsed], BOUNDS_MS["cleanup"])
    return {
        "observation_ms": elapsed,
        "start": first,
        "end": last,
        "snapshot": strict_json(snapshot),
        "snapshot_sha256": sha(snapshot),
        "rehearsal": replay,
        "nonmutating": True,
        "paid_ready": False,
    }


class SetupCommands:
    """Command-side producer/collector/resolver integration on a durable store.

    collect returns exact setup bytes, artifacts and the remaining resolver rows.
    Supplying both capture and gpu installs the concurrent preparation adapter;
    collect then supplies creation only. The provider transports remain injected.
    It must be bounded by stop. The ProcessCalls parent owns child fencing.
    A saved intent without a result refuses on reopen: no implicit second probe.
    """

    def __init__(
        self,
        *,
        store,
        binding,
        collect,
        inventory,
        scope,
        sample,
        capture=None,
        gpu=None,
        row5_stage=None,
        row5_control=None,
        maximum_fixture=None,
    ):
        self.store, self.binding, self.collect = store, binding, collect
        self.inventory, self.scope, self.sample = inventory, scope, sample
        self.maximum_fixture = maximum_fixture
        exact(scope.session_id, binding["session_id"], "setup:scope_session")
        exact(scope.t0_ms, binding["t0_ms"], "setup:scope_t0")
        if capture is not None or gpu is not None:
            from .inf037b_preparation import ConcurrentPreparation

            require(
                callable(capture)
                and callable(gpu)
                and callable(row5_stage)
                and callable(row5_control),
                "setup:both_preparation_ports",
            )
            self.collect = ConcurrentPreparation(
                store=store,
                binding=binding,
                sample=sample,
                capture=capture,
                gpu=gpu,
                creation=lambda stop: collect("creation", stop),
                row5_stage=row5_stage,
                row5_control=row5_control,
            )

    def fitness_rows(self, collected, setup):
        from .inf037b_setup_fitness import FitnessProducer

        require(collected.get("fitness_raw") is not None, "setup:fitness_raw_required")
        producer = FitnessProducer(
            collected["fitness_raw"],
            binding=self.binding,
            artifacts=collected["artifacts"],
            setup=setup,
        )
        require(
            producer.c.row(self.binding["pins"])["selected_ms"] <= self.sample()["ms"][1],
            "setup:fitness_future_source",
        )
        return producer.produce()

    def lifecycle_input(self, collected):
        from .inf037b_setup_observations import export_observations, replay_observations

        require(collected.get("replay_raw") is not None, "setup:replay_raw_required")
        require(collected.get("export_raw") is not None, "setup:export_raw_required")
        artifacts = collected["artifacts"]
        proof = collected["maximum_fixture_proof"]
        require(proof["path"] in artifacts, "setup:maximum_fixture_artifact")
        maximum = getattr(self, "maximum_fixture", None)
        if maximum is not None:
            exact(artifacts[proof["path"]], encode(maximum), "setup:maximum_artifact")
        exact(sha(artifacts[proof["path"]]), proof["sha256"], "setup:maximum_fixture_hash")
        sizing_ref = collected["lifecycle"]["transfer"]["sizing_proof"]
        require(sizing_ref["path"] in artifacts, "setup:sizing_artifact")
        exact(sha(artifacts[sizing_ref["path"]]), sizing_ref["sha256"], "setup:sizing_hash")
        replay = replay_observations(collected["replay_raw"], binding=self.binding)
        exported = export_observations(
            collected["export_raw"],
            binding=self.binding,
            artifacts=collected["export_artifacts"],
            maximum_fixture=strict_json(artifacts[proof["path"]]),
            sizing_proof=strict_json(artifacts[sizing_ref["path"]]),
            readback=self._concurrent(),
        )
        exact(
            collected["lifecycle"]["transfer"].get("reconnect_ms"),
            exported["transfer"]["reconnect_ms"],
            "observations:transfer_reconnect_bound",
        )
        current = self.sample()
        endpoints = [strict_json(collected[name])["end"] for name in ("replay_raw", "export_raw")]
        require(
            all(
                (p["clock_id"], p["boot_id"]) == (current["clock_id"], current["boot_id"])
                for p in endpoints
            ),
            "setup:observations_clock",
        )
        require(
            max(p["ms"][1] for p in endpoints) <= current["ms"][1],
            "setup:observations_future_source",
        )
        row = copy.deepcopy(collected["lifecycle"])
        for phase in ("attempt", "reset"):
            row["phases"][phase]["observations_ms"] = replay["observations_ms"][phase]
        row["phases"]["export"]["observations_ms"] = [exported["observation_ms"]]
        row["replay_nonmutating"] = replay["nonmutating"]
        row["replay_virtual_schedule_ms"] = replay["virtual_schedule_ms"]
        row["transfer"] = {
            **exported["transfer"],
            "sizing_proof": collected["lifecycle"]["transfer"]["sizing_proof"],
        }
        row.setdefault("sources", []).extend(
            {"path": "setup/" + name + ".json", "sha256": sha(collected[name]), "sequence": [0, 0]}
            for name in ("replay_raw", "export_raw")
        )
        return row

    def _concurrent(self):
        from .inf037b_preparation import ConcurrentPreparation

        return isinstance(getattr(self, "collect", None), ConcurrentPreparation)

    def _capture(self, operation, raw, artifacts=None, *, file_manifest=False, reference=None):
        require(type(raw) is bytes, "setup:capture_bytes")
        capture = {
            "raw_sha256": sha(raw),
            "artifacts": copy.deepcopy(artifacts or {})
            if file_manifest
            else {
                path: {"hex": data.hex(), "sha256": sha(data)}
                for path, data in (artifacts or {}).items()
            },
        }
        with self.store.lock():
            state = self.store.read()
            if reference is None:
                capture["raw_hex"] = raw.hex()
            else:
                record = state
                for part in reference:
                    record = record[part]
                exact(
                    record.get("sha256", record.get("raw_sha256")),
                    sha(raw),
                    "setup:raw_reference_hash",
                )
                capture["raw_reference"] = list(reference)
            state.setdefault(operation, {})["capture"] = capture
            self.store.write(state)

    def _persist_export_artifacts(self, artifacts):
        if self._concurrent():
            return self._joined_export_artifacts(artifacts)
        return persist_archive_artifacts(self.store, artifacts)

    def _joined_export_artifacts(self, artifacts):
        """Reuse this command's durable branch readback; only stat after join."""
        with self.store.lock():
            state = self.store.read()
        branch = state["preparation_fork"]["export"]
        exact(branch["archive_verified"], True, "setup:archive_branch_verified")
        exact(artifacts, branch["artifacts"], "setup:archive_branch_manifest")
        base = self.store.path.parent / (self.store.path.name + ".objects")
        require(base.is_dir() and not base.is_symlink(), "setup:archive_objects")
        base = base.resolve()
        for facts in artifacts.values():
            path = Path(facts["path"])
            require(path.is_absolute() and path.is_relative_to(base), "setup:archive_under_objects")
            require(path.is_file(), "setup:archive_object_file")
            require(
                not any(p.is_symlink() for p in (path, *path.parents) if p != base),
                "setup:archive_object_symlink",
            )
            exact(path.resolve(), path, "setup:archive_object_resolved")
            exact(path.stat().st_size, facts["bytes"], "setup:archive_object_size")
        return copy.deepcopy(artifacts)

    def completion_observation(self, data, creation, completed):
        from .inf037b_preparation import preparation_receipt

        return preparation_receipt(
            data["fork_receipt"], binding=self.binding, ready=creation["ready"], completed=completed
        )

    def validate_staging(self, creation):
        from .inf037b_preparation import staging_receipt

        require(
            type(creation.get("staging")) is dict and type(creation.get("ready")) is dict,
            "setup:staging_required",
        )
        exact(creation["ready"]["ms"][1], creation["ready_ms"], "setup:staging_P")
        maximum = getattr(self, "maximum_fixture", None)
        if maximum is not None:
            exact(
                creation["staging"]["manifest_sha256"],
                maximum["source_inventory_sha256"],
                "setup:maximum_at_P",
            )
        return staging_receipt(creation["staging"], binding=self.binding, ready=creation["ready"])

    def validate_preparation(self, collected, creation):
        from .inf037b_preparation import admit_branch_evidence, preparation_receipt

        require("preparation_receipt" in collected, "setup:fork_join_required")
        receipt = preparation_receipt(
            collected["preparation_receipt"],
            binding=self.binding,
            ready=creation["ready"],
            completed=self.sample(),
        )
        admit_branch_evidence(
            collected, binding=self.binding, receipt=collected["preparation_receipt"]
        )
        expected = creation["staging"]["manifest_sha256"]
        maximum = getattr(self, "maximum_fixture", None)
        if maximum is not None:
            exact(
                creation["maximum_fixture_sha256"], sha(encode(maximum)), "setup:original_maximum"
            )
        exported = strict_json(collected["export_raw"])
        exact(sha(encode(exported["source"])), expected, "setup:staged_capture_inventory")
        return receipt

    def __call__(self, operation, stop, context):
        require(operation in {"creation", "preparation", "resolution"}, "setup:operation")
        exact(stop, context["measurement_deadline_ms"], "setup:command_deadline")
        descriptor = {"binding": self.binding, "stop": stop, "context": context}
        maximum = getattr(self, "maximum_fixture", None)
        if maximum is not None:
            descriptor["maximum_fixture_sha256"] = sha(encode(maximum))
        with self.store.lock():
            state = self.store.read()
            if state.get("binding") is None:
                state["binding"] = copy.deepcopy(self.binding)
                self.store.write(state)
            exact(state["binding"], self.binding, "setup:immutable_binding")
            if operation in state:
                old = state[operation]
                exact(old["descriptor"], descriptor, "setup:original_command")
                require("result" in old, "setup:interrupted_no_reprobe")
                if operation == "preparation":
                    self.last_completion = self.completion_observation(
                        old["data"], state["creation"]["data"], self.sample()
                    )
                return copy.deepcopy(old["result"])
            state[operation] = {"descriptor": copy.deepcopy(descriptor)}
            self.store.write(state)
        now = self.sample()["ms"][1]
        require(self.binding["t0_ms"] <= now < stop, "setup:command_start")
        if operation == "creation":
            raw = self.collect(operation, stop)
            self._capture(operation, raw)
            data = creation_observation(raw, self.binding)
            ready = data["ready_ms"]
            require(self.binding["t0_ms"] <= ready <= stop, "setup:readiness_deadline")
            exact(
                set(data["components"]),
                {"capacity", "bootstrap", "control_plane", "nodes"},
                "setup:creation_components",
            )
            for interval in data["components"].values():
                lo, hi = span(interval, "setup:creation_component")
                require(
                    self.binding["t0_ms"] <= lo <= hi <= ready, "setup:creation_component_range"
                )
            data["observation_ms"] = [ready - self.binding["t0_ms"]] * 2
            allowance("creation", [data["observation_ms"]], BOUNDS_MS["creation"])
            data["staging_receipt"] = self.validate_staging(data)
            # Exact creation bytes already live in creation.capture.
            data.pop("raw")
            data.pop("raw_bytes")
            data["raw_reference"] = ["creation", "capture"]
            if maximum is not None:
                data["maximum_fixture_sha256"] = sha(encode(maximum))
            result = True
        elif operation == "preparation":
            collected = self.collect(operation, stop)
            if collected.get("preparation_receipt") is not None:
                self._capture("preparation_join", encode(collected["preparation_receipt"]))
            archive_manifest = None
            raw, artifacts = collected["raw"], collected["artifacts"]
            # Retain refused startup/cache/lineage/proof input before validation.
            self._capture(operation, raw, artifacts)
            fitness_raw = collected.get("fitness_raw")
            if fitness_raw is not None:
                # Capture before any predicate; a refusal retains exact raw bytes.
                self._capture(
                    "fitness",
                    fitness_raw,
                    artifacts,
                    reference=("preparation_fork", "gpu") if self._concurrent() else None,
                )
            for key, name in (("replay_raw", "replay"), ("export_raw", "export_probe")):
                if collected.get(key) is not None:
                    self._capture(
                        name,
                        collected[key],
                        artifacts,
                        reference=("preparation_fork", "export")
                        if key == "export_raw" and self._concurrent()
                        else None,
                    )
            if collected.get("export_raw") is not None:
                try:
                    archive_manifest = self._persist_export_artifacts(collected["export_artifacts"])
                except OSError as exc:
                    raise IntegrityError("v4:setup:archive_persist_io") from exc
                collected["export_artifacts"] = archive_manifest
                self._capture(
                    "export_archives",
                    collected["export_raw"],
                    archive_manifest,
                    file_manifest=True,
                    reference=("export_probe", "capture"),
                )
            c = SetupCollector(raw, **self.binding)
            paths = (
                list(c.bundle["component_proofs"].values())
                + [p["offline_proof"]["path"] for p in collected["lifecycle"]["phases"].values()]
                + [collected["lifecycle"]["transfer"]["sizing_proof"]["path"]]
            )
            require(len(paths) == len(set(paths)), "setup:distinct_proof_paths")
            row = startup_row(c, pins=self.binding["pins"], artifacts=artifacts)
            other_rows = self.fitness_rows(collected, c)
            require(row["selected_ms"] <= self.sample()["ms"][1], "setup:future_source")
            cleanup = cleanup_observation(
                inventory=self.inventory, scope=self.scope, stop=stop, sample=self.sample
            )
            with self.store.lock():
                prior = self.store.read()
            require("result" in prior.get("creation", {}), "setup:creation_required")
            preparation = self.validate_preparation(collected, prior["creation"]["data"])
            lifecycle = self.lifecycle_input(collected)
            ready_lower = max(v[0] for v in prior["creation"]["data"]["components"].values())
            elapsed = self.sample()["ms"][1] - ready_lower
            allowance("preparation", [[elapsed, elapsed]], BOUNDS_MS["preparation"])
            observation_sources = lifecycle.get("sources", [])
            lifecycle.update(c.row(self.binding["pins"]))
            lifecycle["sources"].extend(observation_sources)
            for phase, observation in (
                ("creation", prior["creation"]["data"]["observation_ms"]),
                ("preparation", [elapsed, elapsed]),
                ("cleanup", cleanup["observation_ms"]),
            ):
                lifecycle["phases"][phase]["observations_ms"] = [observation]
            for phase, item in lifecycle["phases"].items():
                item["offline_proof"] = offline_proof(
                    artifacts,
                    item["offline_proof"]["path"],
                    self.binding["pins"],
                    BOUNDS_MS[phase],
                    "lifecycle:" + phase,
                )
            paths = [p["path"] for p in row["component_proofs"].values()] + [
                p["offline_proof"]["path"] for p in lifecycle["phases"].values()
            ]
            require(len(paths) == len(set(paths)), "setup:distinct_proof_paths")
            transfer = lifecycle["transfer"]
            sizing_path = transfer["sizing_proof"]["path"]
            require(sizing_path in artifacts, "setup:sizing_artifact")
            exact(
                sha(artifacts[sizing_path]), transfer["sizing_proof"]["sha256"], "setup:sizing_hash"
            )
            require(sizing_path not in paths, "setup:distinct_proof_paths")
            sizing = strict_json(artifacts[sizing_path])
            exact(sizing.get("subject"), "lifecycle:export_sizing", "setup:sizing_subject")
            exact(sizing.get("pins"), self.binding["pins"], "setup:sizing_pins")
            require(
                integer(sizing.get("raw_bytes")) and sizing["raw_bytes"] >= 0, "setup:sizing_bytes"
            )
            exact(transfer["raw_bytes"], sizing["raw_bytes"], "setup:sizing_raw_bytes")
            lifecycle["sources"].append(
                {"path": "setup/cleanup.json", "sha256": sha(encode(cleanup)), "sequence": [0, 0]}
            )
            lifecycle["selected_ms"] = self.sample()["ms"][1]
            lifecycle["observation_ms"][1] = lifecycle["selected_ms"]
            data = {
                "raw_reference": ["preparation", "capture"],
                "raw_sha256": sha(raw),
                "fitness_raw_sha256": sha(fitness_raw) if fitness_raw is not None else None,
                "startup": row,
                "cleanup": cleanup,
                "lifecycle": lifecycle,
                "other_rows": other_rows,
                "preparation_receipt": preparation,
                "fork_receipt": collected.get("preparation_receipt"),
                "artifacts": {
                    path: {"sha256": sha(value), "bytes": value.decode("utf-8")}
                    for path, value in artifacts.items()
                },
            }
            result = True
        else:
            with self.store.lock():
                prior = self.store.read()
            require("result" in prior.get("preparation", {}), "setup:preparation_required")
            prepared = prior["preparation"]["data"]
            prepared["preparation_receipt"] = self.completion_observation(
                prepared, prior["creation"]["data"], self.sample()
            )
            prepared["lifecycle"]["phases"]["preparation"]["observations_ms"] = [
                [prepared["preparation_receipt"]["elapsed_ms"]] * 2
            ]
            rows = {
                **prepared["other_rows"],
                "startup": prepared["startup"],
                "lifecycle": prepared["lifecycle"],
            }
            result = resolve(rows, pins=self.binding["pins"])
            data = {"setup_sha256": sha(encode(prepared))}
        completed = self.sample()["ms"][1]
        require(now <= completed <= stop, "setup:command_completion")
        if operation == "creation":
            require(data["ready_ms"] <= completed, "setup:creation_future_source")
        with self.store.lock():
            state = self.store.read()
            state[operation].update(data=data, result=copy.deepcopy(result))
            self.store.write(state)
        # Charge the final durable result write, not just the computation before
        # it. Replays and resolution recheck this same bound, so an interrupted
        # or late candidate result cannot bypass completion admission.
        completed = self.sample()
        require(
            now <= completed["ms"][0] <= completed["ms"][1] <= stop,
            "setup:durable_command_completion",
        )
        if operation == "preparation":
            self.last_completion = self.completion_observation(
                data, prior["creation"]["data"], completed
            )
        return result
