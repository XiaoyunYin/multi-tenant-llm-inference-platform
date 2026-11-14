"""Separate setup-signal source: the API delete is a trigger, never the proof."""

import ipaddress
import time
from urllib.parse import quote

from .inf037b_archive import strict_json
from .inf037b_capture import DeadlineHTTP
from .inf037b_eks_cluster import pod_path
from .inf037b_live import ClockAdapter, LifecycleReceiptProducer
from .inf037b_resolver import exact, require
from .inf037b_sources import ClockMapper


class SetupSignal:
    def __init__(
        self,
        *,
        owner,
        runtime,
        slot,
        node,
        template,
        node_http,
        pins,
        offset_ms,
        pod_http=None,
        clock=time.monotonic_ns,
        sleep=time.sleep,
    ):
        require(type(slot) is int and slot in (0, 1), "signal:slot")
        require(
            type(offset_ms) is int and 90000 <= offset_ms < 120000, "signal:preannounced_offset"
        )
        require("lifecycle:setup" in owner.sources, "signal:capture_source")
        exact(template["metadata"]["name"], "setup-signal-" + str(slot), "signal:pod_name")
        exact(template["metadata"]["labels"]["inf037b-role"], "setup_signal", "signal:pod_role")
        require("app" not in template["metadata"]["labels"], "signal:serving_labels")
        exact(template["spec"]["nodeName"], node["name"], "signal:node")
        self.owner, self.runtime, self.slot, self.node, self.template = (
            owner,
            runtime,
            slot,
            node,
            template,
        )
        self.node_options, self.pod_options, self.pins = node_http, pod_http, pins
        self.offset_ms, self.clock, self.sleep = offset_ms, clock, sleep
        self.uid, self.origin = None, None
        self.path = pod_path(runtime.config["namespace"], "setup-signal-" + str(slot))
        self.key = "setup-signal:" + runtime.binding["session_id"] + ":" + str(slot)

    def http(self, options, stop_ns):
        return DeadlineHTTP(
            **options,
            stop_ns=stop_ns,
            retain=self.owner.retainer(
                "lifecycle:setup",
                uid=self.uid,
                process_generation=self.origin["boot_id"] if self.origin else "origin",
            ),
        )

    def node_read(self, suffix, stop_ns):
        path = "/lifecycle/" + quote(self.uid, safe="") + suffix
        return self.http(self.node_options, stop_ns).get(path)

    def origin_check(self, origin):
        for key, value in (
            ("pod_uid", self.uid),
            ("role", "setup_signal"),
            ("slot", self.slot),
            ("node", self.node["name"]),
            ("node_boot_id", self.node["boot_id"]),
            ("supervisor_sha256", self.pins["supervisor"]),
        ):
            exact(origin.get(key), value, "signal:origin:" + key)
        require(
            origin.get("supervisor_pid")
            and origin.get("supervisor_start")
            and origin.get("boot_id"),
            "signal:origin_lineage",
        )
        if self.origin is not None:
            exact(origin, self.origin, "signal:origin_changed")
        self.origin = origin

    def map_clock(self, stop_ns):
        rows = self.owner.rows("lifecycle:setup")
        begin = rows.clock()
        body, _ = self.http(self.node_options, stop_ns).get("/clock")
        end = rows.clock()
        data = strict_json(body)
        exact(data["boot_id"], self.node["boot_id"], "signal:clock_boot")
        ClockAdapter(rows).mapping(
            "node:" + self.node["name"], data["boot_id"], data["mono_ns"] // 1_000_000, begin, end
        )

    def ready(self, before_ns):
        stop = before_ns // 1_000_000
        self.runtime.write(self.key + ":create", "POST", self.path, self.template, stop)
        while self.clock() < before_ns:
            pod = self.runtime.read(self.path, stop)["value"]
            uid = pod["metadata"]["uid"]
            if self.uid is not None:
                exact(uid, self.uid, "signal:pod_uid")
            self.uid = uid
            exact(pod["spec"]["nodeName"], self.node["name"], "signal:node")
            if any(
                c.get("type") == "Ready" and c.get("status") == "True"
                for c in pod.get("status", {}).get("conditions", [])
            ):
                options = self.pod_options
                if options is None:
                    ip = ipaddress.ip_address(pod["status"]["podIP"])
                    require(ip.is_private and not ip.is_loopback, "signal:pod_address")
                    host = "[" + str(ip) + "]" if ip.version == 6 else str(ip)
                    options = {"base": "http://" + host + ":9101", "internal": True}
                raw, _ = self.http(options, before_ns).get("/ready")
                value = strict_json(raw)
                exact(
                    (value["ready"], value["pod_uid"], value["role"]),
                    (True, uid, "setup_signal"),
                    "signal:ready",
                )
                raw, _ = self.node_read("/origin", before_ns)
                self.origin_check(strict_json(raw))
                exact(value["boot_id"], self.origin["boot_id"], "signal:ready_boot")
                self.map_clock(before_ns)
                require(
                    self.clock() < before_ns,
                    "transport:unresolved:setup_signal_launcher:late_ready",
                )
                return
            self.sleep(min(0.05, max(0, (before_ns - self.clock()) / 1e9)))
        require(False, "transport:unresolved:setup_signal_launcher:ready_before_probe")

    def trigger(self, start_ns, stop_ns):
        at = start_ns + self.offset_ms * 1_000_000
        self.sleep(max(0, (at - self.clock()) / 1e9))
        require(
            self.origin is not None
            and start_ns + 90_000_000_000 <= self.clock() < start_ns + 120_000_000_000,
            "signal:trigger_window",
        )
        self.map_clock(stop_ns)
        require(self.clock() < start_ns + 120_000_000_000, "signal:trigger_window")
        self.runtime.write(
            self.key + ":delete",
            "DELETE",
            self.path,
            {"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": self.uid}},
            stop_ns // 1_000_000,
        )
        return self.proof(start_ns, stop_ns)

    def proof(self, start_ns, stop_ns):
        body, _ = self.node_read("/origin", stop_ns)
        self.origin_check(strict_json(body))
        collector = LifecycleReceiptProducer()
        collector.created(self.uid, self.slot)
        events, offset = [], 0
        while self.clock() < stop_ns:
            body, headers = self.node_read("/events?offset=" + str(offset), stop_ns)
            exact(headers.get("X-Capture-Boot"), self.origin["boot_id"], "signal:spool_boot")
            exact(int(headers["X-Capture-Next"]), offset + len(body), "signal:spool_length")
            for line in body.splitlines():
                event = strict_json(line)
                exact(event["node_boot_id"], self.node["boot_id"], "signal:node_boot")
                exact(event["boot_id"], self.origin["boot_id"], "signal:process_boot")
                collector.ingest(event)
                events.append(event)
            offset += len(body)
            if events and events[-1]["event"] == "process_end":
                break
            # An API delete reply precedes kubelet signal/exit. Read only the
            # newly committed suffix, using the original operation cutoff.
            self.sleep(min(0.05, max(0, (stop_ns - self.clock()) / 1e9)))
        require(events and events[-1]["event"] == "process_end", "signal:process_not_exited")
        starts = [e for e in events if e["event"] == "process_start"]
        signals = [e for e in events if e["event"] == "signal"]
        require(
            len(starts) == len(signals) == 1 and signals[0].get("signal") == "SIGTERM",
            "signal:receipt",
        )
        require(starts[0]["pid"] != self.origin["supervisor_pid"], "signal:child_lineage")
        exact(signals[0]["pid"], starts[0]["pid"], "signal:child_lineage")
        exact(events[-1]["pid"], starts[0]["pid"], "signal:child_lineage")
        received = signals[0]["signal_data"]["receipt_ns"]
        require(
            type(received) is int and 0 <= received <= signals[0]["mono_ns"], "signal:receipt_time"
        )
        self.map_clock(stop_ns)
        mapped = ClockMapper(self.owner.clock_rows).map(
            "node:" + self.node["name"],
            self.node["boot_id"],
            received // 1_000_000,
            (received + 999999) // 1_000_000,
        )
        require(
            mapped is not None
            and start_ns // 1_000_000 + 90000
            <= mapped[0]
            <= mapped[1]
            <= (start_ns + 120_000_000_000) // 1_000_000,
            "signal:receipt_window",
        )
        return {
            "uid": self.uid,
            "origin": self.origin,
            "supervisor_sha256": self.pins["supervisor"],
            "events": events,
            "signal_ms_bounds": mapped,
        }
