"""02-C source-pinned transports; no replacement controller or capture runner.

The caller supplies discovered node/Pod endpoints and the original cutoff.
02-E owns installation of the returned periodic callbacks on the same owner.
"""

import copy
import ipaddress
from pathlib import Path

from . import inf037b_native
from .inf037b_archive import encode, sha, strict_json
from .inf037b_capture import DeadlineHTTP
from .inf037b_eks_campaign import bind_replacement
from .inf037b_live import NodeCacheAdapter
from .inf037b_resolver import exact, require


class NativeSpoolHTTP:
    """UID-scoped node-persistent native source, including after Pod exit."""

    def __init__(self, http, uid):
        from urllib.parse import quote

        self.http, self.prefix = http, "/native/" + quote(uid, safe="")

    def get(self, path):
        require(path.startswith("/native/events?after="), "transport:native_path")
        return self.http.get(self.prefix + path[len("/native") :])


class PodTransports:
    def __init__(self, *, owner, pins, manifest, nodes, endpoints):
        self.owner, self.pins, self.manifest = owner, copy.deepcopy(pins), copy.deepcopy(manifest)
        self.nodes, self.endpoints = copy.deepcopy(nodes), copy.deepcopy(endpoints)
        exact(owner.binding["pins"], pins, "transport:owner_pins")
        exact(manifest["schema"], "inf037b-native-overlay-v1", "transport:manifest")
        exact(manifest["base"], inf037b_native.BASE_FILES, "transport:manifest")
        exact(set(manifest["files"]), set(inf037b_native.BASE_FILES), "transport:manifest")
        exact(manifest["version"], "0.29.0", "transport:manifest")
        exact(
            manifest["helper_sha256"],
            sha(Path(inf037b_native.__file__).read_bytes()),
            "transport:helper_pin",
        )
        require(set(nodes) == {"0", "1"} and set(endpoints) == {"0", "1"}, "transport:slots")

    def http(self, source, options, stop, uid=None, generation=None):
        return DeadlineHTTP(
            **options,
            stop_ns=stop * 1_000_000,
            retain=self.owner.retainer(source, uid=uid, process_generation=generation)
            if uid
            else self.owner.retainer(source),
        )

    def cache(self, slot, stop):
        node = self.nodes[str(slot)]
        adapter = NodeCacheAdapter(
            self.owner.rows("kubernetes"),
            self.http("kubernetes", self.endpoints[str(slot)]["node_http"], stop),
            node["name"],
        )
        adapter.clock()
        value = adapter.capture()
        exact(value["boot_id"], node["boot_id"], "transport:cache_boot")
        exact(value["image"], node["image"], "transport:cache_image")
        adapter.clock()
        return adapter

    def pod_http(self, pod, slot, port):
        # Re-derive each replacement's actual endpoint from the observed Pod;
        # never keep the former UID's address. Local forwards are test-only.
        override = self.endpoints[str(slot)].get("local_test_pod_http")
        if override is not None:
            require(override.get("local_test") is True, "transport:test_endpoint")
            return override
        address = ipaddress.ip_address(pod["status"]["podIP"])
        require(address.is_private and not address.is_loopback, "transport:pod_address")
        host = "[" + str(address) + "]" if address.version == 6 else str(address)
        return {"base": "http://" + host + ":" + str(port), "internal": True}

    def __call__(self, pod, slot, stop):
        uid = pod["metadata"]["uid"]
        exact(
            self.owner.lineage_admissions.get(uid, {}).get("slot"),
            slot,
            "transport:uid_not_observed",
        )
        node, endpoints = self.nodes[str(slot)], self.endpoints[str(slot)]
        exact(pod["spec"]["nodeName"], node["name"], "transport:node")
        statuses = [c for c in pod["status"]["containerStatuses"] if c["name"] == "vllm"]
        require(
            len(statuses) == 1
            and statuses[0]["restartCount"] == 0
            and "running" in statuses[0]["state"],
            "transport:container_restart_or_state",
        )
        exact(
            statuses[0].get("imageID", "").rsplit("sha256:", 1)[-1],
            node["image"].rsplit("sha256:", 1)[-1],
            "transport:container_image",
        )
        # The node-spooled origin is read through the same retained slot source.
        native = NativeSpoolHTTP(
            self.http("native:slot" + str(slot), endpoints["node_http"], stop, uid, "origin-read"),
            uid,
        )
        body, _ = native.get("/native/events?after=-1")
        raw = strict_json(body)
        exact(raw["schema"], "inf037b-native-events-v1", "transport:native_schema")
        origin = raw["origin"]
        for key, expected in (
            ("pod_uid", uid),
            ("slot", slot),
            ("node", node["name"]),
            ("node_boot_id", node["boot_id"]),
            ("model_sha256", self.pins["model"]),
            ("runtime_sha256", self.pins["runtime"]),
            ("helper_sha256", self.manifest["helper_sha256"]),
            ("manifest_sha256", sha(encode(self.manifest))),
        ):
            exact(origin.get(key), expected, "transport:origin:" + key)
        require(
            type(origin.get("supervisor_pid")) is int
            and origin["supervisor_pid"] > 0
            and origin.get("supervisor_start")
            and origin.get("boot_id"),
            "transport:origin_lineage",
        )
        return {
            "uid": uid,
            "origin": origin,
            "manifest": self.manifest,
            "process_generation": origin["boot_id"],
            "node": node["name"],
            "node_boot_id": node["boot_id"],
            "metrics_http": self.pod_http(pod, slot, 8000),
            "native_http": endpoints["node_http"],
            "native_spool": True,
            "lifecycle_http": self.pod_http(pod, slot, 9101),
            "spool_http": endpoints["node_http"],
            "original_stop_ms": stop,
        }

    def adapters(self, pod, slot, stop, *, request_ids, lifecycle):
        spec = self(pod, slot, stop)
        result = bind_replacement(
            self.owner,
            slot,
            spec,
            stop_ns=stop * 1_000_000,
            pins=self.pins,
            request_ids=request_ids,
            lifecycle=lifecycle,
        )
        return spec, result

    def setup_signal(self, slot, *, runtime, template, offset_ms):
        from .inf037b_eks_signal import SetupSignal

        return SetupSignal(
            owner=self.owner,
            runtime=runtime,
            slot=slot,
            node=self.nodes[str(slot)],
            template=template,
            node_http=self.endpoints[str(slot)]["node_http"],
            pins=self.pins,
            offset_ms=offset_ms,
        )

    @staticmethod
    def periodic(adapters):
        # No new thread or deadline; attach these to the existing capture owner.
        node = adapters["lifecycle"]
        slot = str(adapters["metrics"].slot)
        return [
            ("lifecycle:slot" + slot, 1000, node.clock),
            ("lifecycle:slot" + slot, 500, node.poll),
            ("native:slot" + slot, 500, adapters["native"].poll),
        ]
