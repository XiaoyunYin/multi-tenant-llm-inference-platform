"""Bounded preparation execution adapter and pre-P fixture admission.

Branch ports execute inside the preparation ProcessCalls group. They must not
detach children; its watchdog/fence owns failure, timeout and parent recovery.
An interrupted SetupCommands intent is never retried. Receipts are setup proof,
not evidence of actual stores, scheduling or planned-host performance.
"""

import copy
import os
import shutil
from concurrent.futures import FIRST_EXCEPTION, ThreadPoolExecutor, wait
from pathlib import Path
from threading import Lock

from .inf037b_archive import IntegrityError, encode, sha, strict_json
from .inf037b_contract import PREPARATION_BRANCH_MS, PREPARATION_OVERHEAD_MS
from .inf037b_resolver import exact, require, span


def stage_fixture(*, source, destination, expected_inventory, binding, sample):
    """Copy a prebuilt fixture, fsync, then independently hash the staged files.

    Called during creation, before P; no fixture construction or timed capture
    occurs here. The expected inventory comes from the exact-plan maximum proof.
    A partial destination is retained for diagnosis and never reused or retried.
    """
    from .inf037b_durable_ports import sync_directory
    from .inf037b_setup_observations import file_facts

    require(os.name == "posix", "preparation:staging_platform")
    source, destination = Path(source), Path(destination)
    require(not destination.exists(), "preparation:staging_fresh")
    files = {p.relative_to(source).as_posix(): p for p in source.rglob("*") if p.is_file()}
    require(not any(p.is_symlink() for p in source.rglob("*")), "preparation:staging_symlink")
    exact(set(files), set(expected_inventory), "preparation:staging_inventory")
    receipt = {
        "binding": copy.deepcopy(binding),
        "pins": copy.deepcopy(binding["pins"]),
        "expected_inventory": copy.deepcopy(expected_inventory),
        "verified": False,
    }
    receipt["copy"] = {"start": sample()}
    destination.mkdir(parents=True)
    for path, original in files.items():
        target = destination / path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(original, target)
        with target.open("r+b") as stream:
            os.fsync(stream.fileno())
    for directory in sorted(
        (p for p in destination.rglob("*") if p.is_dir()), key=lambda p: len(p.parts), reverse=True
    ):
        sync_directory(directory)
    sync_directory(destination)
    sync_directory(destination.parent)
    receipt["copy"]["end"] = sample()
    receipt["hash"] = {"start": sample()}
    actual = {path: file_facts(destination / path) for path in files}
    exact(actual, expected_inventory, "preparation:staging_readback")
    receipt["hash"]["end"] = sample()
    receipt.update(actual_inventory=actual, manifest_sha256=sha(encode(actual)), verified=True)
    return receipt


def interval(value, binding, clock, previous=0):
    require(all(type(v) is str and bool(v) for v in clock), "preparation:clock_identity")
    exact((value["clock_id"], value["boot_id"]), clock, "preparation:clock")
    lo, hi = span(value["ms"], "preparation:sample")
    require(binding["t0_ms"] <= previous <= lo <= hi, "preparation:order")
    require(hi - lo <= 100, "preparation:uncertainty")
    return lo, hi


def staging_receipt(raw, *, binding, ready):
    """Admit separately booked copy/hash stages, including full inventory pins."""
    exact(raw["binding"], binding, "preparation:staging_binding")
    clock = (ready["clock_id"], ready["boot_id"])
    bounds = []
    previous = binding["t0_ms"]
    for name in ("copy", "hash"):
        start, end = raw[name]["start"], raw[name]["end"]
        lo, hi = interval(start, binding, clock, previous)
        elo, ehi = interval(end, binding, clock, hi)
        bounds.append([max(0, elo - hi), ehi - lo])
        previous = ehi
    interval(ready, binding, clock, previous)
    exact(raw["verified"], True, "preparation:staging_verified")
    # The full fixture inventory, not a row count or an asserted hash flag.
    expected = raw["expected_inventory"]
    require(type(expected) is dict and bool(expected), "preparation:fixture_inventory")
    for path, facts in expected.items():
        require(type(path) is str and bool(path), "preparation:fixture_path")
        require(
            type(facts["bytes"]) is int
            and facts["bytes"] >= 0
            and type(facts["sha256"]) is str
            and len(facts["sha256"]) == 64
            and all(c in "0123456789abcdef" for c in facts["sha256"]),
            "preparation:fixture_facts",
        )
    exact(raw["actual_inventory"], expected, "preparation:fixture_hashes")
    exact(raw["manifest_sha256"], sha(encode(expected)), "preparation:fixture_manifest")
    exact(raw["pins"], binding["pins"], "preparation:fixture_pins")
    return {
        "copy_ms": bounds[0],
        "hash_ms": bounds[1],
        "ready": ready,
        "manifest_sha256": raw["manifest_sha256"],
        "verified": True,
    }


def preparation_receipt(raw, *, binding, ready, completed):
    """Validate absolute branch cutoffs, common overhead and durable join."""
    exact(raw["binding"], binding, "preparation:binding")
    exact(raw["ready"], ready, "preparation:original_P")
    clock = (ready["clock_id"], ready["boot_id"])
    rlo, rhi = interval(ready, binding, clock, binding["t0_ms"])
    fork_lo, fork_hi = interval(raw["fork"], binding, clock, rhi)
    durations, ends = {}, []
    exact(set(raw["branches"]), {"export", "gpu"}, "preparation:branches")
    for name, item in raw["branches"].items():
        lo, hi = interval(item["start"], binding, clock, fork_hi)
        elo, ehi = interval(item["end"], binding, clock, hi)
        # Work and its durable acknowledgement share the same absolute cutoff.
        require(ehi - lo <= PREPARATION_BRANCH_MS, "preparation:branch_bound")
        require(
            ehi <= rlo + PREPARATION_BRANCH_MS + PREPARATION_OVERHEAD_MS,
            "preparation:branch_cutoff",
        )
        exact(item["success"], True, "preparation:branch_success")
        exact(item["durable_ack"], True, "preparation:branch_ack")
        require(
            type(item["sha256"]) is str
            and len(item["sha256"]) == 64
            and all(c in "0123456789abcdef" for c in item["sha256"]),
            "preparation:branch_hash",
        )
        durations[name] = ehi - lo
        ends.append((elo, ehi))
    jlo, jhi = interval(raw["join"], binding, clock, max(v[1] for v in ends))
    clo, chi = interval(completed, binding, clock, jhi)
    total = chi - rlo
    # Whole span minus overlapping work: never sum branches or hide control time.
    overlap_lower = min(v[0] for v in ends) - max(
        item["start"]["ms"][1] for item in raw["branches"].values()
    )
    require(overlap_lower >= 0, "preparation:fork_overlap")
    common = (
        max(item["start"]["ms"][1] for item in raw["branches"].values())
        - rlo
        + chi
        - max(v[0] for v in ends)
    )
    require(common <= PREPARATION_OVERHEAD_MS, "preparation:shared_overhead")
    require(total <= 1_800_000, "preparation:total_bound")
    exact(raw["join_ack"], True, "preparation:join_ack")
    return {
        "elapsed_ms": total,
        "common_ms": common,
        "branches_ms": durations,
        "ready": ready,
        "join": raw["join"],
        "complete": True,
    }


class PreparationFork:
    """Run exactly two bounded ports concurrently; persist each ack and the join.

    persist must return only after durable acknowledgement, within stop_ms.
    Branch failure propagates to ProcessCalls; its process-group fence kills any
    unfinished sibling before terminal export/cleanup. No retry is introduced.
    """

    def __init__(self, *, binding, ready, sample, branches, persist, exit_command=None):
        self.binding, self.ready, self.sample = binding, ready, sample
        self.branches, self.persist = branches, persist
        self.exit_command = os._exit if exit_command is None else exit_command

    def run(self, stop_ms):
        exact(set(self.branches), {"export", "gpu"}, "preparation:fork_ports")
        receipt = {
            "binding": copy.deepcopy(self.binding),
            "ready": self.ready,
            "fork": self.sample(),
            "branches": {},
        }
        cutoff = min(stop_ms, self.ready["ms"][0] + 1_800_000)

        failures, failure_lock = [], Lock()

        def work(name, port):
            try:
                return branch(name, port)
            except BaseException as error:
                with failure_lock:
                    failures.append((name, error))
                raise

        def branch(name, port):
            start = self.sample()
            branch_stop = min(cutoff, start["ms"][0] + PREPARATION_BRANCH_MS)
            value = port(branch_stop)
            require(type(value) is bytes, "preparation:port_bytes")
            item = {"start": start, "success": True, "sha256": sha(value)}
            ack = self.persist(name, item, branch_stop)
            exact(ack, True, "preparation:persist_ack")
            item.update(end=self.sample(), durable_ack=ack)
            return item

        pool = ThreadPoolExecutor(max_workers=2)
        try:
            futures = {name: pool.submit(work, name, port) for name, port in self.branches.items()}
            done, pending = wait(
                futures.values(),
                timeout=max(0, cutoff - self.sample()["ms"][1]) / 1000,
                return_when=FIRST_EXCEPTION,
            )
            with failure_lock:
                failed = list(failures)
            if failed or pending:
                name, error = (
                    failed[0]
                    if failed
                    else ("timeout", TimeoutError("preparation:absolute_cutoff"))
                )
                failure = {
                    "binding": self.binding,
                    "ready": self.ready,
                    "cutoff_ms": cutoff,
                    "branch": name,
                    "reason": type(error).__name__ + ":" + str(error),
                    "observed": self.sample(),
                }
                try:
                    exact(self.persist("failure", failure, cutoff), True, "preparation:failure_ack")
                finally:
                    # ThreadPoolExecutor joins running workers at interpreter exit.
                    # The durable refusal must precede an immediate command exit;
                    # ProcessCalls then fences this entire group, including ports.
                    self.exit_command(1)
                raise error
            for name, future in futures.items():
                receipt["branches"][name] = future.result()
            receipt["join_ack"] = self.persist("join", receipt, cutoff)
            receipt["join"] = self.sample()
            exact(self.persist("complete", receipt, cutoff), True, "preparation:complete_ack")
            preparation_receipt(
                receipt, binding=self.binding, ready=self.ready, completed=self.sample()
            )
            return receipt
        finally:
            # Never wait past the absolute watchdog for a failed sibling.
            pool.shutdown(wait=False, cancel_futures=True)


def admit_branch_evidence(collected, *, binding, receipt):
    """Join the exact admitted bytes and their conservative endpoints to each fork.

    Fitness endpoints come from the accepted raw source joins, including capture
    brackets, rather than a second claimed bracket. Remote source clocks retain
    their existing mappings; the common measurement boot is the collector boot.
    4d must supply its verified received signal via pre_export_received.
    """
    from .inf037b_setup import SetupCollector

    export = strict_json(collected["export_raw"])
    fitness = SetupCollector(collected["fitness_raw"], **binding)
    times = fitness.row(binding["pins"])["observation_ms"]
    # Include the actual collection brackets, rounded outward to milliseconds.
    times[0] = min(times[0], min(r["capture_start_mono_ns"] // 1_000_000 for r in fitness.rows))
    times[1] = max(
        times[1], max((r["capture_end_mono_ns"] + 999_999) // 1_000_000 for r in fitness.rows)
    )
    gpu = {
        key: {
            "clock_id": "measurement",
            "boot_id": fitness.rows[0]["collector_boot_id"],
            "ms": [at, at],
        }
        for key, at in zip(("start", "end"), times, strict=True)
    }
    for name, raw_name, evidence in (("export", "export_raw", export), ("gpu", "fitness_raw", gpu)):
        branch = receipt["branches"][name]
        exact(branch["sha256"], sha(collected[raw_name]), "preparation:" + name + "_raw_hash")
        clock = (branch["start"]["clock_id"], branch["start"]["boot_id"])
        lo, hi = interval(evidence["start"], binding, clock, binding["t0_ms"])
        elo, ehi = interval(evidence["end"], binding, clock, hi)
        require(branch["start"]["ms"][0] <= lo, "preparation:" + name + "_evidence_start")
        require(ehi <= branch["end"]["ms"][1], "preparation:" + name + "_evidence_end")
    signal = collected.get("pre_export_received")
    if signal is not None:
        clock = (export["start"]["clock_id"], export["start"]["boot_id"])
        _, signal_hi = interval(signal, binding, clock, binding["t0_ms"])
        require(signal_hi <= export["start"]["ms"][0], "preparation:capture_after_signal")


class ConcurrentPreparation:
    """SetupCommands.collect adapter for real concurrent capture/GPU ports.

    Called only inside its ProcessCalls group. capture(stop) runs the accepted
    capture_export adapter and returns (exact raw bytes, artifact paths).
    gpu(stop, row5_stage) performs startup/fitness and returns SetupCommands' collected
    inputs with fitness_raw. Ports never detach children. Provider/store/API
    authority, placement interlocks and independent host-loss fencing remain
    their later scope-table rows; this adapter grants none of those authorities.
    """

    def __init__(self, *, store, binding, sample, capture, gpu, creation, row5_stage, row5_control):
        self.store, self.binding, self.sample = store, binding, sample
        self.capture, self.gpu, self.creation = capture, gpu, creation
        require(callable(row5_control), "preparation:row5_composition_required")
        require(callable(row5_stage), "preparation:row5_composition_required")
        self.row5_stage = row5_stage
        self.row5_control = row5_control
        self.writer = Lock()

    def __call__(self, operation, stop):
        if operation == "creation":
            return self.creation(stop)
        exact(operation, "preparation", "preparation:collect_operation")
        with self.store.lock():
            state = self.store.read()
            exact(state["binding"], self.binding, "preparation:collect_binding")
            require("result" in state.get("creation", {}), "preparation:creation_required")
            ready = copy.deepcopy(state["creation"]["data"]["ready"])
            require("preparation_fork" not in state, "preparation:interrupted_no_retry")
            state["preparation_fork"] = {"binding": self.binding, "ready": ready, "stop_ms": stop}
            self.store.write(state)
        outputs = {}

        def capture(branch_stop):
            from .inf037b_setup import persist_archive_artifacts
            from .inf037b_setup_observations import validate_export_archives

            raw, artifacts = self.capture(branch_stop)
            require(type(raw) is bytes, "preparation:capture_bytes")
            # Persistence/readback belongs to the export branch, before its ack.
            manifest = persist_archive_artifacts(self.store, artifacts)
            outputs["export"] = {
                "export_raw": raw,
                "export_artifacts": manifest,
            }
            # Retain refused raw evidence too. This candidate is not a branch
            # acknowledgement; only the later successful fork persist can set
            # archive_verified and durable_ack after semantic validation.
            persist("export", {"sha256": sha(raw), "archive_verified": False}, branch_stop)
            validate_export_archives(strict_json(raw), manifest)
            return raw

        def gpu(branch_stop):
            # PreparationFork deadlines are milliseconds; the stage and real
            # HTTP/diagnostic ports use absolute monotonic nanoseconds.
            value = self.gpu(branch_stop, self.row5_stage)
            require(
                type(value) is dict and type(value.get("fitness_raw")) is bytes,
                "preparation:gpu_bytes",
            )
            require(
                not ({"export_raw", "export_artifacts", "preparation_receipt"} & value.keys()),
                "preparation:branch_ownership",
            )
            known_requests = value.pop("row5_known_requests", None)
            require(type(known_requests) is list, "preparation:row5_request_partition")
            row5 = self.row5_control(branch_stop * 1_000_000, copy.deepcopy(value))
            require(
                type(row5) is dict
                and type(row5.get("fitness_raw")) is bytes
                and type(row5.get("row5_control_requests")) is list
                and type(row5.get("row5_evidence")) is dict
                and type(row5.get("artifacts", {})) is dict,
                "preparation:row5_capture",
            )
            from .inf037b_row5 import ROW5_ALL_CONTROLS
            from .inf037b_row5_sequence import STAGES

            def pairs(items):
                return [
                    (item.get("snapshot_id"), item.get("gateway_uid"))
                    for item in items
                    if isinstance(item, dict)
                ]

            for items, names in (
                (known_requests, STAGES),
                (row5["row5_control_requests"], ("unknown", "expired", "post_outage_known2")),
            ):
                actual = pairs(items)
                require(
                    len(items) == 2 * len(names)
                    and len(actual) == len(items)
                    and all(isinstance(n, str) and isinstance(g, str) for n, g in actual)
                    and set(actual) == {(n, g) for n in names for g in ("gateway0", "gateway1")},
                    "preparation:row5_request_partition",
                )
            control_requests = known_requests + row5["row5_control_requests"]

            expected_pairs = {
                (name, gateway)
                for name in ROW5_ALL_CONTROLS
                for gateway in ("gateway0", "gateway1")
            }
            control_pairs = [
                (item.get("snapshot_id"), item.get("gateway_uid"))
                for item in control_requests
                if isinstance(item, dict)
            ]
            control_ids = [item.get("request_id") for item in control_requests]
            if (
                len(control_pairs) != len(control_requests)
                or any(
                    not isinstance(name, str) or not isinstance(gateway, str)
                    for name, gateway in control_pairs
                )
                or set(control_pairs) != expected_pairs
                or any(
                    not isinstance(request_id, str) or not request_id for request_id in control_ids
                )
                or len(set(control_ids)) != len(control_ids)
                or any(request_id.startswith("rsv_d1a6") for request_id in control_ids)
            ):
                raise IntegrityError("preparation:row5_request_partition")
            base = strict_json(value["fitness_raw"])
            addition = strict_json(row5["fitness_raw"])
            if row5["row5_evidence"].get("schema") != "inf037b-row5-evidence-v1":
                raise IntegrityError("preparation:row5_evidence")
            for field in ("schema", "session_id", "pins", "t0_ms"):
                exact(addition.get(field), base.get(field), "preparation:row5_binding")
            require(
                type(addition.get("raw")) is list
                and not any(
                    not isinstance(item, dict) or item.get("attempt_id") != "setup"
                    for item in addition["raw"]
                ),
                "preparation:row5_capture",
            )
            base_ids = {item.get("request_id") for item in base.get("requests", [])}
            require(
                not base_ids.intersection(control_ids),
                "preparation:row5_request_partition",
            )
            exact(
                row5["row5_evidence"]["configuration_sha256"],
                base.get("pins", {}).get("configuration"),
                "preparation:row5_configuration_binding",
            )
            base["raw"].extend(addition["raw"])
            base["row5_control_requests"] = copy.deepcopy(control_requests)
            base["row5_evidence"] = copy.deepcopy(row5["row5_evidence"])
            value["fitness_raw"] = encode(base)
            artifacts = value.setdefault("artifacts", {})
            for path, data in row5.get("artifacts", {}).items():
                require(type(path) is str and type(data) is bytes, "preparation:row5_artifact")
                if path in artifacts:
                    exact(artifacts[path], data, "preparation:row5_artifact_collision")
                artifacts[path] = data
            outputs["gpu"] = value
            return value["fitness_raw"]

        def persist(name, value, cutoff):
            # fcntl locks are nonblocking: serialize the two local writers before
            # taking the existing store's cross-process lock. No second store.
            with self.writer, self.store.lock():
                state = self.store.read()
                record = copy.deepcopy(value)
                if name in ("export", "gpu"):
                    raw = outputs[name]["export_raw" if name == "export" else "fitness_raw"]
                    record["raw_hex"] = raw.hex()
                    if name == "export":
                        record["artifacts"] = copy.deepcopy(outputs[name]["export_artifacts"])
                        record["archive_verified"] = record.get("archive_verified", True)
                state["preparation_fork"][name] = record
                self.store.write(state)
            require(self.sample()["ms"][1] <= cutoff, "preparation:persist_cutoff")
            return True

        receipt = PreparationFork(
            binding=self.binding,
            ready=ready,
            sample=self.sample,
            branches={"export": capture, "gpu": gpu},
            persist=persist,
        ).run(stop)
        return {**outputs["gpu"], **outputs["export"], "preparation_receipt": receipt}
