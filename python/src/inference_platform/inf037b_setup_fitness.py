"""Offline :36-:40 producers from retained raw setup evidence, never verdict fixtures.

Configuration is exact-byte hash-bound; collection is read-only. Live authority
and the later exact plan's source inventory remain separate admission obligations.
"""

import copy
import json
import math

from .inf037b_archive import encode, sha, strict_json
from .inf037b_engine import cache_config
from .inf037b_live import LifecycleReceiptProducer
from .inf037b_packet import workload_trace
from .inf037b_requests import RequestJoin
from .inf037b_resolver import (
    clocks,
    equivalence,
    exact,
    ingress,
    integer,
    publication,
    require,
    sse,
)
from .inf037b_setup import SetupCollector
from .r1_spec import ENGINE_FLAGS, IMAGE, MODEL, REVISION, parse_engine_argv

GATEWAYS = ("gateway0", "gateway1")


def check_restoration_hold(snapshots, rows, hold_ms):
    """Validate the Redis cached-stop restoration hold from its snapshots."""
    from .inf037b_sources import ClockMapper

    cached_stop = snapshots["cached_stop_known1"]
    hold = snapshots["hold_start"]
    restored = snapshots["hold_end"]
    a, b = hold["payload"], restored["payload"]
    redis_boot = hold["source_generation"]
    mapper = ClockMapper([row for row in rows if row.get("source_kind") == "clocks"])
    for snapshot in (cached_stop, hold, restored):
        payload = snapshot["payload"]
        exact(snapshot["source_generation"], redis_boot, "fitness:redis_clock")
        mapped = mapper.map("redis", redis_boot, payload["redis_time_ms"], payload["redis_time_ms"])
        require(mapped is not None and not mapper.errors, "fitness:redis_clock")
        exact(mapped, snapshot["time_ms_bounds"], "fitness:redis_store_clock_join")

    exact(a["state"].get("n"), 1, "fitness:hold_original_n")
    exact(a["state"].get("candidate"), 2, "fitness:hold_candidate")
    since_ms = a["state"].get("since_ms")
    require(
        integer(since_ms)
        and since_ms <= a["redis_time_ms"]
        and since_ms > cached_stop["payload"]["redis_time_ms"],
        "fitness:hold_since",
    )
    exact(b["state"].get("n"), 2, "fitness:restored_n")
    require(
        b["redis_time_ms"] - since_ms >= hold_ms,
        "fitness:restoration_hold",
    )
    for sample in rows:
        payload = sample.get("payload", {})
        if (
            sample.get("source_kind") != "redis"
            or payload.get("event") != "snapshot"
            or not a["redis_time_ms"] <= payload.get("redis_time_ms", -1) <= b["redis_time_ms"]
        ):
            continue
        exact(set(payload["reports"]), set(GATEWAYS), "fitness:hold_reports")
        require(
            all(
                report["n"] == 2
                and report["unknown"] is False
                and report["expires_ms"] > b["redis_time_ms"]
                for report in payload["reports"].values()
            ),
            "fitness:hold_fresh",
        )
        exact(payload["active_reservations"], [], "fitness:hold_reservations")
    require(a["state"]["until_ms"] > b["redis_time_ms"], "fitness:hold_expiry")


def fitness_request_joins(rows, probe_offers, control_offers, capture_end_ms):
    """Keep registered row 5 control requests outside the fixed probe cohort."""
    require(type(probe_offers) is list and type(control_offers) is list, "fitness:control_requests")
    ids = [o.get("request_id") for o in probe_offers if isinstance(o, dict)]
    require(
        len(ids) == len(probe_offers) and all(isinstance(i, str) and i for i in ids),
        "fitness:control_requests",
    )
    control_ids = []
    if control_offers:
        names = {
            "known0",
            "known1",
            "known2",
            "cached_stop_known1",
            "cached_restore_known2",
            "unknown",
            "expired",
            "post_outage_known2",
        }
        require(
            all(
                isinstance(o, dict)
                and isinstance(o.get("request_id"), str)
                and bool(o["request_id"])
                and isinstance(o.get("snapshot_id"), str)
                and o["snapshot_id"] in names
                and o.get("gateway_uid") in GATEWAYS
                for o in control_offers
            ),
            "fitness:control_requests",
        )
        pairs = [(o["snapshot_id"], o["gateway_uid"]) for o in control_offers]
        require(
            len(pairs) == len(names) * len(GATEWAYS)
            and set(pairs) == {(n, g) for n in names for g in GATEWAYS},
            "fitness:control_requests",
        )
        control_ids = [o["request_id"] for o in control_offers]
        require(
            len(set(control_ids)) == len(control_ids) and not set(ids).intersection(control_ids),
            "fitness:control_requests",
        )
    control_ids = set(control_ids)
    probe_rows = [r for r in rows if r["payload"].get("request_id") not in control_ids]
    control_rows = [r for r in rows if r["payload"].get("request_id") in control_ids]
    probe = RequestJoin(probe_rows, probe_offers, capture_end_ms)
    require(not probe.errors and not probe.operational, "fitness:request_join")
    control = RequestJoin(control_rows, control_offers, capture_end_ms)
    require(not control.errors and not control.operational, "fitness:control_request_join")
    return probe, control


class FitnessProducer:
    def __init__(self, raw, *, binding, artifacts, setup, allow_offline_fixture=False):
        self.c = SetupCollector(raw, **binding)
        self.allow_offline_fixture = allow_offline_fixture
        self.setup = setup
        self.pins = binding["pins"]
        path = self.c.bundle["fitness_configuration"]
        require(path in artifacts, "fitness:configuration_artifact")
        exact(sha(artifacts[path]), self.pins["configuration"], "fitness:configuration_hash")
        self.config = strict_json(artifacts[path])
        exact(self.config["schema"], "inf037b-fitness-config-v1", "fitness:configuration_schema")
        exact(
            set(self.config["roles"]),
            {"measurement", "gateway0", "gateway1", "node0", "node1"},
            "fitness:required_roles",
        )
        exact(
            {p["clock_id"] for p in self.config["clocks"]},
            {"redis", "node:node0", "node:node1", "gateway0", "gateway1", "client"},
            "fitness:required_clocks",
        )
        exact(len(self.config["clocks"]), 6, "fitness:single_clock_boot_inventory")
        self.start, self.end = self.config["probe_start_ms"], self.config["probe_end_ms"]
        exact(self.end - self.start, 120000, "fitness:single_probe_duration")
        require(binding["t0_ms"] <= self.start < self.end, "fitness:probe_origin")
        exact(set(self.config["slots"]), {"0", "1"}, "fitness:slots")
        slots = list(self.config["slots"].values())
        require(
            len({s["uid"] for s in slots}) == 2 and len({s["node"] for s in slots}) == 2,
            "fitness:distinct_placements",
        )
        for row in self.c.rows:
            p, kind = row["payload"], row["source_kind"]
            clock = None
            if kind == "gateway":
                require(p["gateway_uid"] in GATEWAYS, "fitness:gateway_source")
                clock = p["gateway_uid"]
            elif kind == "client":
                clock = "client"
            elif kind == "redis":
                clock = "redis"
            elif kind == "vllm" and p.get("event") == "engine_config":
                # These two HTTP responses have collector capture brackets,
                # not a timestamp supplied by the remote node. Preserve the
                # adapter's actual measurement clock and supervisor generation.
                exact(row["source_time"]["clock_id"], "measurement", "engine:source_clock")
                exact(
                    row["source_generation"], p["process_generation"], "engine:generation_unjoined"
                )
                continue
            elif kind == "vllm":
                require(str(p["slot"]) in self.config["slots"], "fitness:native_source_slot")
                clock = "node:" + self.config["slots"][str(p["slot"])]["node"]
            if clock is not None:
                exact(row["source_time"]["clock_id"], clock, "fitness:source_clock_identity")
                expected_boot = next(
                    c["boot_id"] for c in self.config["clocks"] if c["clock_id"] == clock
                )
                exact(row["source_generation"], expected_boot, "fitness:source_clock_boot")
        for role in self.config["roles"]:
            ack = self.c.one("controller", "resolution", name="configuration:" + role)
            exact(
                ack["payload"]["input_sha256"],
                self.pins["configuration"],
                "fitness:effective_config",
            )
            exact(ack["payload"]["value"], self.pins, "fitness:effective_pins")
            require(ack["time_ms_bounds"][1] <= self.start, "fitness:config_before_probe")
        self.requests, self.control_requests = fitness_request_joins(
            self.c.rows,
            self.c.bundle["requests"],
            self.c.bundle.get("row5_control_requests", []),
            self.c.row(self.pins)["selected_ms"],
        )
        require(not self.requests.errors and not self.requests.operational, "fitness:request_join")
        self.by_id = {r["request_id"]: r for r in self.requests.cohorts}
        self.native_events = {}
        self.request_events = {}
        for r in self.c.rows:
            p = r["payload"]
            if p.get("request_id"):
                self.request_events.setdefault(
                    (r["source_kind"], p["event"], p["request_id"]), []
                ).append(r)
            if r["source_kind"] == "vllm" and r["payload"]["event"] in ("accept", "terminal"):
                key = r["payload"]["event"], r["payload"].get("request_id")
                require(key not in self.native_events, "fitness:unique_native_request")
                self.native_events[key] = r

    def base(self):
        row = self.c.row(self.pins)
        row["sources"][0]["path"] = "setup/fitness-raw.json"
        row["sources"].extend(self.setup.row(self.pins)["sources"])
        row["sources"].append(
            {
                "path": self.c.bundle["fitness_configuration"],
                "sha256": self.pins["configuration"],
                "sequence": [0, 0],
            }
        )
        return row

    def native(self, request):
        uid, slot, rid = request["backend_uid"], request["backend_slot"], request["request_id"]
        exact(uid, self.config["slots"][str(slot)]["uid"], "fitness:direct_uid")
        require(
            ("accept", rid) in self.native_events and ("terminal", rid) in self.native_events,
            "fitness:native_endpoints",
        )
        accepted = self.native_events["accept", rid]
        ended = self.native_events["terminal", rid]
        for row in (accepted, ended):
            exact(row["payload"]["pod_uid"], uid, "fitness:native_uid")
            exact(row["payload"]["slot"], slot, "fitness:native_slot")
            exact(row["payload"]["model_sha256"], self.pins["model"], "fitness:native_model")
            exact(row["payload"]["runtime_sha256"], self.pins["runtime"], "fitness:native_runtime")
            exact(
                row["payload"]["process_generation"],
                self.config["slots"][str(slot)]["process_generation"],
                "fitness:native_process",
            )
        opened = request["upstream_open_ms_bounds"]
        require(
            opened is not None
            and opened[1] <= accepted["time_ms_bounds"][0] <= ended["time_ms_bounds"][0],
            "fitness:native_order",
        )
        return accepted["time_ms_bounds"], ended["time_ms_bounds"]

    def probe(self):
        row = self.base()
        settings = self.config["sse"]
        row.update(copy.deepcopy(settings))
        expected = workload_trace("pre", 1, 120000)
        probe = [r for r in self.requests.cohorts if r["request_id"].startswith("a1-pre-")]
        exact(len(probe), len(expected), "fitness:probe_offers")
        samples, traffic, dispatch = [], dict.fromkeys(GATEWAYS, 0), []
        natives = {}
        for scheduled in expected:
            request = self.by_id[scheduled["request_id"]]
            offer = next(
                o for o in self.c.bundle["requests"] if o["request_id"] == request["request_id"]
            )
            for key in ("offer_index", "prefix_id", "gateway_uid"):
                exact(offer[key], scheduled[key], "fitness:scheduled_" + key)
            at = (
                self.start
                + scheduled["scheduled_ms_numerator"] // scheduled["scheduled_ms_denominator"]
            )
            exact(offer["scheduled_ms"], at, "fitness:scheduled_time")
            events = self.request_events.get(
                (
                    "client",
                    "offer" if request["outcome"] != "missed_offer" else "missed",
                    request["request_id"],
                ),
                [],
            )
            require(len(events) == 1, "fitness:single_offer")
            actual = events[0]["payload"]
            for key in ("offer_index", "prefix_id", "gateway_uid", "config_sha256"):
                exact(actual[key], offer[key], "fitness:actual_offer_" + key)
            dispatched = request["dispatch_ms_bounds"]
            if request["outcome"] != "missed_offer":
                require(dispatched is not None and dispatched[0] >= at, "fitness:dispatch")
                require(
                    request["identity_join_valid"] and request["outcome"] == "complete",
                    "fitness:probe_completion",
                )
                rid = request["request_id"]
                if ("accept", rid) in self.native_events or ("terminal", rid) in self.native_events:
                    natives[rid] = self.native(request)
                else:
                    # V3 per-request native events are optional. The live probe
                    # uses the directly joined route UID/slot and the accepted
                    # upstream-open -> client-terminal convention. Supervisor
                    # lineage below binds that target for the complete probe.
                    exact(
                        request["backend_uid"],
                        self.config["slots"][str(request["backend_slot"])]["uid"],
                        "fitness:direct_uid",
                    )
                    natives[rid] = (
                        request["upstream_open_ms_bounds"],
                        request["terminal_ms_bounds"],
                    )
                traffic[request["gateway_uid"]] += 1
            dispatch.append((at, None if dispatched is None else dispatched[1] - at))
        require(
            not self.c.find("kubernetes", "deletion") and not self.c.find("kubernetes", "signal"),
            "fitness:no_probe_deletion",
        )
        # Independent supervisor history on each pinned node covers the whole probe.
        exact(
            self.c.bundle["supervisors_source_sha256"],
            self.pins["supervisor"],
            "fitness:supervisor_source",
        )
        for slot, target in self.config["slots"].items():
            receipts = LifecycleReceiptProducer()
            receipts.created(target["uid"], int(slot))
            events = self.c.bundle["supervisors"][target["uid"]]
            for event in events:
                exact(event["pod_uid"], target["uid"], "fitness:supervisor_uid")
                exact(event["node_boot_id"], target["boot_id"], "fitness:supervisor_node_boot")
                exact(event["boot_id"], target["process_generation"], "fitness:supervisor_process")
                receipts.ingest(event)
            mapped = self.c.join.clocks.map(
                "node:" + target["node"],
                target["boot_id"],
                events[0]["mono_ns"] // 1000000,
                events[-1]["mono_ns"] // 1000000,
            )
            require(
                mapped is not None and mapped[1] >= self.end and mapped[0] <= self.start,
                "fitness:supervisor_window",
            )
            # Signal the separate setup process, never a serving UID. Heartbeats
            # alone cannot establish actual signal instrumentation fitness.
            signal = self.c.bundle["signal_processes"][slot]
            require(
                signal["uid"] not in {s["uid"] for s in self.config["slots"].values()},
                "fitness:separate_signal_process",
            )
            exact(signal["supervisor_sha256"], self.pins["supervisor"], "fitness:signal_source")
            supervisor = LifecycleReceiptProducer()
            supervisor.created(signal["uid"], int(slot))
            for event in signal["events"]:
                exact(event["pod_uid"], signal["uid"], "fitness:signal_uid")
                exact(event["node_boot_id"], target["boot_id"], "fitness:signal_node_boot")
                supervisor.ingest(event)
            observed = [e for e in signal["events"] if e["event"] == "signal"]
            require(
                len(observed) == 1 and observed[0].get("signal") == "SIGTERM",
                "fitness:actual_signal",
            )
            received = observed[0].get("signal_data", {}).get("receipt_ns")
            require(
                type(received) is int and 0 <= received <= observed[0]["mono_ns"],
                "fitness:signal_receipt",
            )
            at = received // 1000000
            mapped = self.c.join.clocks.map(
                "node:" + target["node"], target["boot_id"], at, (received + 999999) // 1000000
            )
            require(
                mapped is not None and self.start + 90000 <= mapped[0] <= mapped[1] <= self.end,
                "fitness:signal_clock_join",
            )
            origin = signal.get("origin")
            require(type(origin) is dict, "fitness:signal_origin")
            for key, expected in (
                ("pod_uid", signal["uid"]),
                ("role", "setup_signal"),
                ("slot", int(slot)),
                ("node", target["node"]),
                ("node_boot_id", target["boot_id"]),
                ("supervisor_sha256", self.pins["supervisor"]),
            ):
                exact(origin.get(key), expected, "fitness:signal_origin")
            exact(origin.get("boot_id"), observed[0]["boot_id"], "fitness:signal_origin")
            require(
                type(origin.get("supervisor_pid")) is int
                and origin["supervisor_pid"] > 0
                and origin.get("supervisor_start"),
                "fitness:signal_origin",
            )
            starts = [e for e in signal["events"] if e["event"] == "process_start"]
            require(
                len(starts) == 1
                and starts[0]["pid"] == observed[0]["pid"]
                and starts[0]["pid"] != origin["supervisor_pid"],
                "fitness:signal_origin",
            )

        # Retain every candidate in order; the resolver uses each slot's FIRST.
        for candidate in sorted(
            (r for r in self.c.find("vllm", "sample") if not r["payload"].get("observation_error")),
            key=lambda r: r["time_ms_bounds"][0],
        ):
            lo, hi = candidate["time_ms_bounds"]
            if not self.start + 90000 <= lo <= hi <= self.end:
                continue
            p = candidate["payload"]
            slot = p["slot"]
            exact(p["pod_uid"], self.config["slots"][str(slot)]["uid"], "fitness:sample_uid")
            bounds = {g: [0, 0] for g in (*GATEWAYS, "target")}
            for request in probe:
                if request["request_id"] not in natives:
                    continue
                for group in (request["gateway_uid"], "target"):
                    if group == "target" and request["backend_slot"] != slot:
                        continue
                    opened, ended = (
                        natives[request["request_id"]]
                        if group == "target"
                        else (request["upstream_open_ms_bounds"], request["terminal_ms_bounds"])
                    )
                    bounds[group][0] += int(opened[1] < lo and hi < ended[0])
                    bounds[group][1] += int(opened[0] <= hi and lo <= ended[1])
            samples.append({"at_ms": hi - self.start, "slot": slot, **bounds})
        windows = []
        for index in range(4):
            begin, end = self.start + index * 30000, self.start + (index + 1) * 30000
            offers = [v for at, v in dispatch if begin <= at < end]
            lateness = sorted(v for v in offers if v is not None)
            resources = []
            for role in self.config["roles"]:
                observations = []
                for resource in self.c.find("controller", "resource", role=role):
                    p = resource["payload"]
                    lo, hi = p.get("window_start_ms"), p.get("window_end_ms")
                    require(
                        resource["source_time"]["clock_id"] == "measurement"
                        and integer(lo)
                        and integer(hi)
                        and lo <= hi <= resource["time_ms_bounds"][1]
                        and hi - lo <= 2000,
                        "fitness:resource_interval",
                    )
                    if lo <= end and begin <= hi:
                        observations.append({**resource, "time_ms_bounds": [lo, hi]})
                self.cover(observations, begin, end, "fitness:resource_cadence")
                for r in observations:
                    exact(r["payload"]["limit_known"], True, "fitness:resource_limit")
                    require(
                        all(
                            integer(r["payload"]["value"].get(k)) and r["payload"]["value"][k] >= 0
                            for k in ("cpu_ppm", "nic_ppm")
                        ),
                        "fitness:resource_values",
                    )
                    resources.append(r["payload"]["value"])
            require(bool(lateness), "fitness:dispatch_window")
            windows.append(
                {
                    "start_ms": index * 30000,
                    "duration_ms": 30000,
                    "misses_ppm": [
                        0,
                        math.ceil(1000000 * sum(v is None for v in offers) / len(offers)),
                    ],
                    "p95_lateness_ms": [0, lateness[math.ceil(0.95 * len(lateness)) - 1]],
                    **{k: [0, max(p[k] for p in resources)] for k in ("cpu_ppm", "nic_ppm")},
                }
            )
        row.update(
            gateway_traffic=traffic,
            live_samples=samples,
            windows=windows,
            identity_complete=True,
            supervisor_receipt_joined=True,
            signal_clock_joined=True,
        )
        sse(row)
        return row

    @staticmethod
    def cover(rows, start, end, reason):
        require(bool(rows), reason)
        times = sorted(r["time_ms_bounds"] for r in rows)
        covered = times[0][1]
        require(times[0][0] <= start, reason)
        for lo, hi in times[1:]:
            require(lo - covered <= 2000, reason)
            covered = max(covered, hi)
        require(covered >= end, reason)

    def clock_row(self):
        row = self.base()
        begin = min(row["observation_ms"][0], self.setup.row(self.pins)["observation_ms"][0])
        end = max(row["selected_ms"], self.setup.row(self.pins)["selected_ms"])
        expected = {(s["clock_id"], s["boot_id"]) for s in self.config["clocks"]}
        exact(set(self.c.join.clocks.maps), expected, "fitness:clock_inventory")
        widths, gaps = [], []
        for clock, boot in expected:
            maps = self.c.join.clocks.maps[clock, boot]
            require(
                maps[0]["send_ms"] <= begin and maps[-1]["receive_ms"] >= end,
                "fitness:entire_setup_clock",
            )
            mapped = self.c.join.clocks.map(
                clock, boot, maps[0]["remote_ms"], maps[-1]["remote_ms"]
            )
            require(mapped is not None, "fitness:clock_continuity")
            offsets = [
                (p["send_ms"] - p["remote_ms"], p["receive_ms"] - p["remote_ms"]) for p in maps
            ]
            widths.append(max(p[1] for p in offsets) - min(p[0] for p in offsets))
            gaps.extend(
                b["local_mono_ms"] - a["local_mono_ms"]
                for a, b in zip(maps, maps[1:], strict=False)
            )
        for r in self.setup.rows:
            if r["source_kind"] == "clocks":
                p = r["payload"]
                require(
                    (p["clock_id"], p["boot_id"]) in expected, "fitness:startup_clock_inventory"
                )
                exact(
                    self.c.join.clocks.map(
                        p["clock_id"], p["boot_id"], p["remote_ms"], p["remote_ms"]
                    ),
                    self.setup.join.clocks.map(
                        p["clock_id"], p["boot_id"], p["remote_ms"], p["remote_ms"]
                    ),
                    "fitness:startup_clock_join",
                )
        require(bool(gaps), "fitness:clock_endpoints")
        row.update(
            maximum_uncertainty_ms=[0, max(widths)],
            maximum_gap_ms=[0, max(gaps)],
            cadence_ms=1000,
            entire_setup=True,
            probe_and_both_startups=True,
            all_endpoint_sequences_joined=True,
            boot_ids_complete=True,
            drift_applied=True,
            cross_boot_interpolation=False,
            clock_step_interpolation=False,
            overlap_order_assertion=False,
        )
        clocks(row)
        return row

    def redis_time(self, row):
        p = row["payload"]
        mapped = self.c.join.clocks.map(
            "redis", self.config["redis_boot_id"], p["redis_time_ms"], p["redis_time_ms"]
        )
        require(mapped is not None, "fitness:redis_clock")
        exact(mapped, row["time_ms_bounds"], "fitness:redis_store_clock_join")
        return mapped

    def engine_observations(self):
        """Join startup edges, running pod objects, engine reports and supervisor boots."""
        observed = []
        engines = self.c.find("vllm", "engine_config")
        running = [
            r
            for r in self.c.find("kubernetes", "container_state")
            if r["payload"].get("container_state") == "running"
        ]
        slots = self.config["slots"]
        require(engines and running, "engine:missing_source")
        expected_uids = {s["uid"] for s in slots.values()}
        for r in engines + running:
            require(r["payload"].get("pod_uid") in expected_uids, "engine:uid_unjoined")
        exact(
            self.c.bundle.get("supervisors_source_sha256"),
            self.pins["supervisor"],
            "engine:supervisor_source",
        )
        for slot, identity in slots.items():
            uid, process = identity["uid"], identity["process_generation"]
            native = [r for r in engines if r["payload"].get("pod_uid") == uid]
            pods = [r for r in running if r["payload"].get("pod_uid") == uid]
            require(native and pods, "engine:missing_source")
            successful = [
                r
                for r in native
                if r.get("error") is None and not r["payload"].get("observation_error")
            ]
            failed = [r for r in native if r["payload"].get("observation_error")]
            require(len(successful) == len(pods) == 1, "engine:ambiguous_source")
            report, pod = successful[0], pods[0]
            startups = self.c.find("kubernetes", "startup", pod_uid=uid)
            require(
                len(startups) == 1
                and startups[0].get("error") is None
                and startups[0]["time_ms_bounds"][1] <= report["time_ms_bounds"][0],
                "fitness:engine_report_before_startup",
            )
            require(
                all(r["time_ms_bounds"][1] < report["time_ms_bounds"][0] for r in failed),
                "engine:failed_then_serving_order",
            )
            p, k = report["payload"], pod["payload"]
            exact(p.get("process_generation"), process, "engine:generation_unjoined")
            for source in (p, k):
                exact(source.get("slot"), int(slot), "engine:uid_unjoined")
            histories = self.c.bundle.get("supervisors", {}).get(uid)
            require(histories, "engine:missing_source")
            lifecycle = LifecycleReceiptProducer()
            lifecycle.created(uid, int(slot))
            for event in histories:
                exact(event.get("pod_uid"), uid, "engine:uid_unjoined")
                exact(event.get("boot_id"), process, "engine:generation_unjoined")
                exact(event.get("node_boot_id"), identity["boot_id"], "engine:generation_unjoined")
                lifecycle.ingest(event)
            exact(lifecycle.process_boot(uid), process, "engine:generation_unjoined")
            require(not lifecycle.lost, "engine:generation_unjoined")
            require(
                report.get("error") is None and pod.get("error") is None, "engine:missing_source"
            )
            for key in (
                "engine_command",
                "engine_args",
                "engine_argv_sha256",
                "engine_flags",
                "resource_version",
                "container_id",
                "restart_count",
                "gpu_count",
            ):
                require(k.get(key) is not None, "engine:missing_source:" + key)
            exact(
                k["engine_command"],
                ["python3", "/capture-code/capture_runtime.py"],
                "engine:flag_mismatch:command",
            )
            exact(k["restart_count"], 0, "engine:generation_unjoined")
            exact(k.get("image_sha256"), IMAGE.rsplit(":", 1)[1], "engine:flag_mismatch:image")
            exact(k["node_pseudonym"], identity["node"], "engine:uid_unjoined")
            exact(
                k["engine_argv_sha256"],
                sha(encode({"command": k["engine_command"], "args": k["engine_args"]})),
                "engine:argv_hash",
            )
            flags = parse_engine_argv(k["engine_args"])
            exact(k["engine_flags"], flags, "engine:source_disagreement:parsed_args")
            require(
                p.get("cache_config_labels") is not None and p.get("max_model_len") is not None,
                "engine:missing_source",
            )
            labels = p["cache_config_labels"]
            # Validate the retained labels with the same strict native-series parser.
            text = ",".join(key + "=" + json.dumps(value) for key, value in labels.items())
            cache_config(("vllm:cache_config_info{" + text + "} 1").encode())
            require(type(p["max_model_len"]) is int, "engine:flag_mismatch:max_model_len")
            for name, value in {
                "block_size": labels["block_size"],
                "gpu_memory_utilization": labels["gpu_memory_utilization"],
                "enable_prefix_caching": labels["enable_prefix_caching"] == "True",
                "max_model_len": p["max_model_len"],
            }.items():
                arg = flags.get("--" + name.replace("_", "-"))
                if name == "enable_prefix_caching":
                    exact(arg, value, "engine:source_disagreement:" + name)
                else:
                    require(
                        arg is not None and float(arg) == float(value),
                        "engine:source_disagreement:" + name,
                    )
            for name, value in ENGINE_FLAGS.items():
                expected = True if value is True else str(value)
                flag = "--" + name.replace("_", "-")
                actual = flags.get(flag)
                if name == "gpu_memory_utilization" and actual is not None:
                    require(float(actual) == value, "engine:flag_mismatch:" + name)
                else:
                    exact(actual, expected, "engine:flag_mismatch:" + name)
            extra = {
                "--model": MODEL,
                "--revision": REVISION,
                "--host": "0.0.0.0",
                "--port": "8000",
                "--shutdown-timeout": "35",
            }
            for name, value in extra.items():
                exact(flags.get(name), value, "engine:flag_mismatch:" + name)
            exact(
                set(flags),
                {"--" + key.replace("_", "-") for key in ENGINE_FLAGS} | set(extra),
                "engine:flag_mismatch:flag_set",
            )
            exact(k["gpu_count"], "1", "engine:flag_mismatch:gpu_count")
            for key in ("model", "runtime"):
                exact(p.get(key + "_sha256"), self.pins[key], "engine:flag_mismatch:" + key)
            require(
                pod["time_ms_bounds"][1] <= report["time_ms_bounds"][0],
                "engine:observation_order",
            )
            observed.append(
                {
                    "slot": int(slot),
                    "pod_uid": uid,
                    "process_generation": process,
                    "executed_flags": flags,
                    "argv_sha256": k["engine_argv_sha256"],
                    "resource_version": k["resource_version"],
                    "cache_config_labels": labels,
                    "max_model_len": p["max_model_len"],
                    "failed_config_attempts": [
                        {
                            "error": r["payload"]["observation_error"],
                            "time_ms_bounds": r["time_ms_bounds"],
                            "raw_ref": r["raw_ref"],
                        }
                        for r in failed
                    ],
                    "num_gpu_blocks": int(labels["num_gpu_blocks"]),
                    "r0_num_gpu_blocks_reference": 3891,
                    "effective_flags": [
                        {
                            "flag": flag,
                            "value": value,
                            "source": "executed_arguments",
                            "raw_ref": pod["raw_ref"],
                        }
                        for flag, value in flags.items()
                    ]
                    + [
                        {
                            "flag": key,
                            "value": labels[key],
                            "source": "engine_reported:cache_config_info",
                            "raw_ref": report["raw_ref"],
                        }
                        for key in (
                            "block_size",
                            "num_gpu_blocks",
                            "gpu_memory_utilization",
                            "enable_prefix_caching",
                        )
                    ]
                    + [
                        {
                            "flag": "max_model_len",
                            "value": p["max_model_len"],
                            "source": "engine_reported:/v1/models",
                            "raw_ref": report["raw_ref"],
                        }
                    ],
                    "sources": [pod["raw_ref"], report["raw_ref"]],
                }
            )
        return observed

    def equivalence_row(self):
        from .inf037b_row5 import validate_control_evidence
        from .inf037b_row5_capture import select_row5_snapshots

        snapshots = select_row5_snapshots(self.c.rows)
        row5 = None
        if self.control_requests.expected:
            row5 = validate_control_evidence(
                self.c.bundle.get("row5_evidence"),
                self.c.bundle.get("row5_control_requests"),
                configuration_sha256=self.pins["configuration"],
                binding={
                    "session_id": self.c.bundle["session_id"],
                    "pins": self.c.bundle["pins"],
                    "t0_ms": self.c.bundle["t0_ms"],
                },
                snapshots=snapshots,
                rows=self.c.rows,
                control_cohorts=self.control_requests.cohorts,
            )
        else:
            require(self.allow_offline_fixture, "fitness:row5_control_requests_required")
        row = self.base()
        # Engine claims cannot be supplied or overridden by declared config.
        row.update(
            {
                key: copy.deepcopy(self.config["equivalence"][key])
                for key in ("R", "W", "ttl_ms", "hold_ms", "workload_config")
            }
        )
        engines = self.engine_observations()
        row.update(
            engine_observations=engines,
            block_size=int(engines[0]["cache_config_labels"]["block_size"]),
            length=engines[0]["max_model_len"],
            max_seqs=int(engines[0]["executed_flags"]["--max-num-seqs"]),
            l4_per_node=1,
        )
        controls = row5["controls"] if row5 is not None else {}
        if row5 is None:
            for name in ("known2", "known1", "known0", "expired", "unknown"):
                snap = snapshots[name]
                p = snap["payload"]
                self.redis_time(snap)
                exact(p["active_reservations"], [], "fitness:unexplained_reservations")
                exact(p["occupied"], 0, "fitness:occupied")
                exact(p["config_sha256"], self.pins["configuration"], "fitness:redis_configuration")
                exact(set(p["reports"]), set(GATEWAYS), "fitness:report_inventory")
                now = p["redis_time_ms"]
                reports = list(p["reports"].values())
                for report in reports:
                    exact(
                        report["expires_ms"] - report["stored_ms"],
                        row["ttl_ms"],
                        "fitness:report_ttl",
                    )
                    require(report["stored_ms"] <= now, "fitness:report_future")
                known = [r["n"] for r in reports if r["expires_ms"] > now and r["unknown"] is False]
                unknown = any(r["unknown"] for r in reports if r["expires_ms"] > now)
                if name.startswith("known"):
                    n = int(name[-1])
                    exact(known, [n, n], "fitness:known_reports")
                    exact(unknown, False, "fitness:known_reports")
                    exact(p["state"]["n"], n, "fitness:effective_n")
                    result = n * (row["R"] + row["W"])
                else:
                    require(
                        (not known and not unknown) if name == "expired" else unknown,
                        "fitness:expired_unknown",
                    )
                    result = "refuse"
                operation = self.c.one("redis", "admit", snapshot_id=name)
                self.redis_time(operation)
                op = operation["payload"]
                require(
                    p["store_order"] < op["store_order"] and now == op["redis_time_ms"],
                    "fitness:operation_store_order",
                )
                exact(op["result"], result, "fitness:control_result")
                for gateway in GATEWAYS:
                    ack = self.c.one("gateway", "admit", snapshot_id=name, gateway_uid=gateway)[
                        "payload"
                    ]
                    exact(ack["store_order"], op["store_order"], "fitness:control_ack_order")
                    exact(
                        ack["decision"],
                        "refused" if result == "refuse" else "observed",
                        "fitness:control_ack",
                    )
                    if result != "refuse":
                        exact(ack["effective_n"], n, "fitness:control_ack_n")
                        exact(ack["effective_b"], result, "fitness:control_ack_b")
                controls[name] = result
        check_restoration_hold(snapshots, self.c.rows, row["hold_ms"])
        restored = snapshots["hold_end"]
        b = restored["payload"]
        ages = {}
        # Redis TIME and expires are on the SAME clock. The atomic TIME value
        # has no cross-clock offset error; redis_time above verifies its mapping.
        now = b["redis_time_ms"]
        for gateway in GATEWAYS:
            restored_report = b["reports"][gateway]
            stored = restored_report["expires_ms"] - row["ttl_ms"]
            ages[gateway] = [now - stored, now - stored]
            require(
                0 <= ages[gateway][0] <= ages[gateway][1] <= 1000, "equivalence:report_age:range"
            )
            stores = [
                s
                for s in self.c.find("redis", "report_store", gateway_uid=gateway)
                if s["payload"]["redis_time_ms"] <= now
            ]
            require(
                integer(b["store_order"])
                and all(integer(s["payload"]["store_order"]) for s in stores)
                and len({s["payload"]["store_order"] for s in stores}) == len(stores),
                "fitness:restored_store_order",
            )
            stores.sort(key=lambda s: s["payload"]["store_order"])
            require(
                all(
                    a["payload"]["redis_time_ms"] <= b["payload"]["redis_time_ms"]
                    for a, b in zip(stores, stores[1:], strict=False)
                ),
                "fitness:restored_store_order",
            )
            stores = [s for s in stores if s["payload"]["store_order"] < b["store_order"]]
            require(bool(stores), "fitness:restored_store")
            store = max(stores, key=lambda s: s["payload"]["store_order"])
            at = self.redis_time(store)
            exact(store["payload"]["redis_time_ms"], stored, "fitness:restored_store_time")
            exact(store["payload"]["n"], 2, "fitness:restored_report_n")
            require(
                all(
                    store["payload"].get(k) is True
                    for k in ("report_success", "report_known", "report_complete")
                ),
                "fitness:restored_store_state",
            )
            acknowledgements = [
                r
                for r in self.c.find("gateway", "report_result", gateway_uid=gateway)
                if r["payload"]["last_success_redis_ms"] == stored
                and r["time_ms_bounds"][0] >= at[1]
                and r["payload"]["report_success"] is True
            ]
            require(bool(acknowledgements), "fitness:report_ack_store")
        row.update(
            effective_pins=copy.deepcopy(self.pins),
            controls=controls,
            report_ages_ms=ages,
            operation_store_joined=True,
            unexplained_reservations=0,
            restoration_controls_pass=True,
        )
        if row5 is not None:
            row.update(row5_controls=row5, controls=row5["controls"])
        equivalence(row)
        return row

    def publication_row(self):
        row = self.base()
        row.update(copy.deepcopy(self.config["publication"]))
        gateways, health_ages = {}, []
        for gateway in GATEWAYS:
            installs = self.c.find(
                "gateway",
                "install",
                gateway_uid=gateway,
                replacement_uid=self.config["addition_uid"],
            )
            require(bool(installs), "fitness:publication_install")
            install = min(installs, key=lambda r: r["time_ms_bounds"][0])
            p = install["payload"]
            mapped = self.c.join.clocks.map(
                "redis", self.config["redis_boot_id"], *p["install_redis_ms_bounds"]
            )
            exact(mapped, install["time_ms_bounds"], "fitness:install_clock_join")
            exact(
                self.config["addition_uid"],
                self.setup.bundle["cases"][1]["uid"],
                "fitness:startup_addition_uid",
            )
            ready = self.setup.at("kubernetes", "ready", pod_uid=self.config["addition_uid"])
            require(ready[1] <= mapped[0], "fitness:addition_after_ready")
            stores = self.c.find("redis", "report_store", gateway_uid=gateway)
            stores.sort(key=lambda r: r["payload"]["store_order"])
            for store in stores:
                self.redis_time(store)
                for key in ("report_success", "report_known", "report_complete"):
                    exact(store["payload"][key], True, "fitness:publication_report")
            orders = [s["payload"]["store_order"] for s in stores]
            require(
                len(set(orders)) == len(orders) and p["store_order"] not in orders,
                "fitness:store_order_distinct",
            )
            require(
                all(
                    a["time_ms_bounds"][1] <= b["time_ms_bounds"][0]
                    for a, b in zip(stores, stores[1:], strict=False)
                ),
                "fitness:store_time_order",
            )
            before = [s for s in stores if s["payload"]["store_order"] < p["store_order"]]
            after = [s for s in stores if s["payload"]["store_order"] > p["store_order"]]
            require(bool(before) and bool(after), "fitness:publication_adjacent_stores")
            prior, following = before[-1], after[0]
            health = [
                r
                for r in self.c.find("gateway", "health", gateway_uid=gateway)
                if r["time_ms_bounds"][1] <= mapped[0]
            ]
            require(bool(health), "fitness:publication_health")
            h = max(health, key=lambda r: r["time_ms_bounds"][1])
            require(
                any(
                    m["uid"] == self.config["addition_uid"] and m["healthy"] is True
                    for m in h["payload"]["members"]
                ),
                "fitness:addition_healthy",
            )
            health_ages.append(mapped[1] - h["time_ms_bounds"][0])
            gateways[gateway] = {
                "preceding_store_ms": prior["time_ms_bounds"],
                "install_ms": mapped,
                "next_store_ms": following["time_ms_bounds"],
                "store_clock_joined": True,
                "atomic_order": [
                    prior["payload"]["store_order"],
                    p["store_order"],
                    following["payload"]["store_order"],
                ],
            }
        row.update(gateways=gateways, fresh_health_ms=[0, max(health_ages)])
        publication(row)
        return row

    def ingress_row(self):
        row = self.base()
        row.update(copy.deepcopy(self.config["ingress"]))
        joins, cancellations = {}, {}
        for gateway in GATEWAYS:
            for slot in (0, 1):
                rid = f"ingress-{gateway}-{slot}"
                request = self.by_id[rid]
                exact(request["gateway_uid"], gateway, "fitness:ingress_gateway")
                exact(request["backend_slot"], slot, "fitness:ingress_slot")
                require(
                    request["identity_join_valid"] and request["outcome"] == "complete",
                    "fitness:ingress_completion",
                )
                self.native(request)
                tls = self.c.one("controller", "precondition", name="tls:" + rid)
                exact(self.config["tls"][gateway]["verified"], True, "fitness:tls_verified")
                require(
                    self.config["tls"][gateway]["version"] in ("TLSv1.2", "TLSv1.3"),
                    "fitness:tls_version",
                )
                exact(tls["payload"]["value"], self.config["tls"][gateway], "fitness:tls_peer")
                require(
                    tls["time_ms_bounds"][1] <= request["upstream_open_ms_bounds"][0],
                    "fitness:tls_before_open",
                )
                stream = request["stream"]
                require(stream["complete"] and not stream["errors"], "fitness:ingress_sse")
                joins[f"g{gateway[-1]}s{slot}"] = {
                    "identity_exact": True,
                    "valid_finish_done": True,
                    "tls": True,
                    "incremental": True,
                    "upstream_attempts": len(
                        self.c.find("gateway", "upstream_open", request_id=rid)
                    ),
                    "false_completion": False,
                    "content_ms": stream["first_content_ms_bounds"],
                    "terminal_ms": request["terminal_ms_bounds"],
                }
            rid = "cancel-" + gateway
            request = self.by_id[rid]
            cancel = self.c.one("client", "cancel", request_id=rid)
            closed = self.c.one("vllm", "terminal", request_id=rid)
            closes = self.c.find("gateway", "upstream_close", request_id=rid)
            require(len(closes) == 1, "fitness:cancel_upstream_close")
            upstream = closes[0]
            exact(
                [
                    upstream["payload"].get(k)
                    for k in ("gateway_uid", "backend_uid", "backend_slot", "reservation_id")
                ],
                [
                    gateway,
                    request["backend_uid"],
                    request["backend_slot"],
                    request["reservation_id"],
                ],
                "fitness:cancel_close_identity",
            )
            # Schema extension proposed for independent review (R360 option b).
            # It must originate at the native abort path, never at the gateway.
            exact(
                closed["payload"].get("terminal_reason"),
                "client_cancel_abort",
                "fitness:cancel_native_abort",
            )
            released = self.c.one("redis", "release", request_id=rid)
            self.native(request)
            exact(request["gateway_uid"], gateway, "fitness:cancel_gateway")
            exact(
                released["payload"]["reservation_id"],
                request["reservation_id"],
                "fitness:cancel_reservation",
            )
            self.redis_time(released)
            require(
                request["outcome"] != "complete" and not request["stream"]["complete"],
                "fitness:cancel_false_completion",
            )
            exact(released["payload"]["result"], "released", "fitness:cancel_release")
            start = cancel["time_ms_bounds"]
            require(
                start[1] <= closed["time_ms_bounds"][0]
                and start[1] <= released["time_ms_bounds"][0],
                "fitness:cancel_order",
            )
            require(
                start[1] <= upstream["time_ms_bounds"][0]
                and upstream["time_ms_bounds"][1] <= closed["time_ms_bounds"][0],
                "fitness:cancel_close_order",
            )
            finish = max(closed["time_ms_bounds"][1], released["time_ms_bounds"][1])
            cancellations[gateway] = {
                "count": 1,
                "upstream_closed": True,
                "release_elapsed_ms": [0, finish - start[0]],
            }
        row.update(joins=joins, cancellations=cancellations)
        ingress(row)
        return row

    def produce(self):
        # Continuous clocks are checked first; no later producer may waive a gap.
        result = {
            "clocks": self.clock_row(),
            "sse": self.probe(),
            "equivalence": self.equivalence_row(),
            "publication": self.publication_row(),
            "ingress": self.ingress_row(),
        }
        expected = (
            {e["request_id"] for e in workload_trace("pre", 1, 120000)}
            | {f"ingress-{g}-{s}" for g in GATEWAYS for s in (0, 1)}
            | {"cancel-" + g for g in GATEWAYS}
        )
        exact(set(self.by_id), expected, "fitness:single_probe_request_inventory")
        require(not self.c.join.clocks.errors, "fitness:clock_errors")
        return result
