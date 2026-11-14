"""Live Part 5 API census and durable permission; no provider or paid entry point."""

import copy
import hmac
import threading
import time
from http.server import BaseHTTPRequestHandler
from urllib.parse import quote, urlencode

from .inf037b_archive import encode, sha, strict_json
from .inf037b_contract import MAX_PLACEMENT_OBSERVATION_AGE_MS
from .inf037b_placement import Observation, check_placement, quantity_bytes
from .inf037b_resolver import SessionDeadline, exact, require
from .inf037b_row5 import BoundedRBACHTTP

GATE = "inf037b.example/export-placement"


# Project admission ceilings for the fixed program, not measured deployed counts.
# Workload replica/surge sources: eks_deployment.resources/workload; single-shot
# roles: inf037b_eks_commands schedule, terminal and placement Jobs. An added Pod
# consumes this finite census allowance; N+1 always refuses before projection.
FIXED_POD_TERMS = {
    "redis_recreate_replica": 1,
    "gateway_stateful_slots": 2,
    "vllm_stateful_slots": 2,
    "ingress_replica_plus_rollout_surge": 2,
    "telemetry_replica_plus_rollout_surge": 2,
    "setup_signal_slots": 2,
    "measurement": 1,
    "generator": 1,
    "export": 1,
    "cleanup": 1,
    "configuration_smoke": 1,
}


def census_bound(role):
    require(role in ("cpu", "gpu"), "placement_api:census_role")
    # vpc-cni and kube-proxy on both roles; observer, device plugin and optional
    # independent witness on GPU. All three local DS pin maxSurge=0.
    daemonsets = 2 if role == "cpu" else 5
    coredns = 2 if role == "cpu" else 0
    fixed = sum(FIXED_POD_TERMS.values())
    return {
        "daemonsets": daemonsets,
        "coredns": coredns,
        "fixed_schedule": fixed,
        "terminal": 44,
        "N": daemonsets + coredns + fixed + 44,
    }


def validate_coredns_configuration(configuration, schema):
    """Validate the types/keys actually used against the exact AWS schema.

    Reject an unknown type/constraint instead of silently ignoring a new schema.
    This deliberately supports only the pinned placement configuration surface.
    """

    def check(value, rule):
        supported = {
            "$ref",
            "$schema",
            "definitions",
            "type",
            "enum",
            "minimum",
            "maximum",
            "required",
            "properties",
            "additionalProperties",
            "items",
            "title",
            "description",
            "default",
        }
        require(rule.keys() <= supported, "placement_api:coredns_schema_unsupported")
        if "$ref" in rule:
            target = schema
            for part in rule["$ref"].removeprefix("#/").split("/"):
                target = target[part]
            return check(value, target)
        kinds = rule.get("type", [])
        kinds = [kinds] if isinstance(kinds, str) else kinds
        types = {
            "object": dict,
            "array": list,
            "integer": int,
            "string": str,
            "boolean": bool,
            "null": type(None),
        }
        require(
            not kinds or any(type(value) is types[k] for k in kinds), "placement_api:coredns_schema"
        )
        if "enum" in rule:
            require(value in rule["enum"], "placement_api:coredns_schema")
        if type(value) is int:
            require(
                rule.get("minimum", value) <= value <= rule.get("maximum", value),
                "placement_api:coredns_schema",
            )
        if isinstance(value, dict):
            require(set(rule.get("required", [])) <= value.keys(), "placement_api:coredns_schema")
            for key, item in value.items():
                child = rule.get("properties", {}).get(key, rule.get("additionalProperties", True))
                require(child is not False, "placement_api:coredns_schema")
                if isinstance(child, dict):
                    check(item, child)
        if isinstance(value, list) and "items" in rule:
            for item in value:
                check(item, rule["items"])

    check(configuration, schema)
    exact(configuration["replicaCount"], 2, "placement_api:coredns_replicas")
    exact(configuration["nodeSelector"], {"m5-role": "cpu"}, "placement_api:coredns_cpu")
    exact(configuration["autoScaling"], {"enabled": False}, "placement_api:coredns_autoscaling")
    require(
        not any(
            t.get("key") == "nvidia.com/gpu" or t.get("operator") == "Exists" and not t.get("key")
            for t in configuration["tolerations"]
        ),
        "placement_api:coredns_gpu_toleration",
    )
    return True


class PlacementAPI:
    """Reuses the accepted bounded TLS JSON transport, including raw retention.

    The journal/archive receives the original defaulted API objects and every
    request/response fragment. Evaluator projections never replace those bytes.
    """

    def __init__(self, base, *, token, clock, retain, ca=None, local_test=False, census_limit=None):
        self.base, self.token, self.clock, self.retain = base, token, clock, retain
        self.ca, self.local_test = ca, local_test
        require(
            census_limit is None
            or type(census_limit) is int
            and 44 <= census_limit <= max(census_bound(r)["N"] for r in ("cpu", "gpu")),
            "placement_api:census_limit_binding",
        )
        self.census_limit = (
            census_limit
            if census_limit is not None
            else max(census_bound(role)["N"] for role in ("cpu", "gpu"))
        )
        self.records = []
        self.exchange_lock = threading.RLock()
        self.watch_bytes = 0

    def request(self, method, path, stop, body=None):
        with self.exchange_lock:
            return self._request(method, path, stop, body)

    def _request(self, method, path, stop, body=None):
        anchor = time.monotonic_ns()
        remaining = stop - self.clock()
        require(remaining > 0, "placement_api:deadline")
        fragments = []

        def retain(start, end, data, metadata):
            fragments.append(
                {
                    "start_ns": start,
                    "end_ns": end,
                    "bytes": len(data),
                    "sha256": sha(data),
                    "raw_hex": data.hex(),
                    "metadata": metadata,
                }
            )
            self.retain(start, end, data, metadata)

        if getattr(self.retain, "supports_units", False) is True:
            retain.supports_units = True
            retain.unit_begin = self.retain.unit_begin
            retain.unit_read = self.retain.unit_read

            def finish_unit(token, start, end, data, spans, metadata):
                fragments.append(
                    {
                        "start_ns": start,
                        "end_ns": end,
                        "bytes": len(data),
                        "sha256": sha(data),
                        "raw_hex": data.hex(),
                        "metadata": metadata,
                    }
                )
                self.retain.unit_finish(token, start, end, data, spans, metadata)

            retain.unit_finish = finish_unit
        for name in ("barrier", "complete", "loss", "remaining_raw_bytes", "producer_state"):
            if hasattr(self.retain, name):
                setattr(retain, name, getattr(self.retain, name))
        transport = BoundedRBACHTTP(
            self.base,
            token=self.token,
            deadline_ns=anchor + remaining * 1_000_000,
            retain=retain,
            ca=self.ca,
            local_test=self.local_test,
        )
        try:
            return transport.json_request(method, path, body)
        finally:
            self.records.append({"method": method, "path": path, "fragments": fragments})

    def watch_lines(self, path, stop):
        anchor = time.monotonic_ns()
        remaining = stop - self.clock()
        require(remaining > 0, "placement_api:watch_deadline")
        self.watch_transport = BoundedRBACHTTP(
            self.base,
            token=self.token,
            deadline_ns=anchor + remaining * 1000000,
            retain=self.retain,
            ca=self.ca,
            local_test=self.local_test,
        )
        try:
            yield from self.watch_transport.lines(path)
        finally:
            self.watch_bytes = getattr(self.watch_transport, "watch_bytes", 0)

    def cutoff_watch(self):
        self.watch_transport.cutoff()

    def census(self, node, stop, *, role=None):
        limit = (
            min(self.census_limit, census_bound(role)["N"])
            if role is not None
            else self.census_limit
        )
        rows, pages, token, seen, rv = [], [], "", set(), None
        total_bytes, tokens = 0, set()
        while True:
            params = {"fieldSelector": "spec.nodeName=" + node["name"], "limit": "100"}
            if token:
                params["continue"] = token
            page = self.request("GET", "/api/v1/pods?" + urlencode(params), stop)
            pages.append(page)
            total_bytes += len(encode(page))
            require(total_bytes <= 8_388_608, "placement_api:census_size")
            current = page["metadata"]["resourceVersion"]
            require(type(current) is str and bool(current), "placement_api:census_rv")
            if rv is not None:
                exact(current, rv, "placement_api:mixed_census_rv")
            rv = current
            require(type(page["items"]) is list, "placement_api:census_items")
            for pod in page["items"]:
                uid = pod["metadata"]["uid"]
                require(
                    type(uid) is str
                    and bool(uid)
                    and type(pod["metadata"].get("resourceVersion")) is str
                    and bool(pod["metadata"]["resourceVersion"]),
                    "placement_api:census_pod_identity",
                )
                require(uid not in seen, "placement_api:duplicate_pod")
                seen.add(uid)
                exact(pod["spec"]["nodeName"], node["name"], "placement_api:wrong_node")
                rows.append(pod)
                require(
                    len(rows) <= limit,
                    "placement_api:census_pod_limit",
                )
            token = page["metadata"].get("continue", "")
            if not token:
                require(
                    page["metadata"].get("remainingItemCount", 0) in (0, None),
                    "placement_api:partial_census",
                )
                break
            require(token not in tokens, "placement_api:continue_cycle")
            tokens.add(token)
            require(len(pages) <= limit, "placement_api:page_cap")
        return {"node": node, "resourceVersion": rv, "complete": True, "pods": rows, "pages": pages}


def effective_memory(spec, status=None):
    """Effective scheduler memory (Kubernetes v1.34 component-helpers/resource).

    Includes sequential/restartable init, pod-level requests, resize status and
    overhead. Source: kubernetes/kubernetes v1.34.0, resource/helpers.go.
    """
    status = status or {}
    statuses = {
        c["name"]: c
        for key in ("containerStatuses", "initContainerStatuses")
        for c in status.get(key, [])
    }
    infeasible = any(
        c.get("type") == "PodResizePending" and c.get("reason") == "Infeasible"
        for c in status.get("conditions", [])
    )

    def memory(container, use_status=True):
        requested = quantity_bytes(
            container.get("resources", {}).get("requests", {}).get("memory", "0")
        )
        observed = statuses.get(container.get("name"), {}) if use_status else {}
        if observed.get("resources") is not None:
            actual = quantity_bytes(observed["resources"].get("requests", {}).get("memory", "0"))
            allocated = quantity_bytes(observed.get("allocatedResources", {}).get("memory", "0"))
            return max(actual, allocated) if infeasible else max(requested, actual, allocated)
        return requested

    running, init_peak = 0, 0
    for container in spec.get("initContainers", []):
        if container.get("restartPolicy") == "Always":
            running += memory(container)
            init_peak = max(init_peak, running)
        else:
            init_peak = max(init_peak, running + memory(container, False))
    requested = max(sum(memory(c) for c in spec["containers"]) + running, init_peak)
    pod_memory = spec.get("resources", {}).get("requests", {}).get("memory")
    if pod_memory is not None:
        requested = quantity_bytes(pod_memory)
    return requested + quantity_bytes(spec.get("overhead", {}).get("memory", "0"))


def project(raw, phase):
    """Only normalize API metadata/gate mechanics; preserve all pod resources."""
    job, pod, node, census = (copy.deepcopy(raw[key]) for key in ("job", "pod", "node", "requests"))
    census["pods"] = [
        {
            "uid": p["metadata"]["uid"],
            "node_name": p["spec"]["nodeName"],
            "role": p["metadata"].get("labels", {}).get("inf037b-role"),
            "memory_requests": [str(effective_memory(p["spec"], p.get("status")))],
            "phase": p.get("status", {}).get("phase"),
        }
        for p in census["pods"]
    ]
    identity = {"name": node["metadata"]["name"], "uid": node["metadata"]["uid"]}
    placement = {
        "scheduled": phase != "pre_schedule",
        "job_uid": job["metadata"]["uid"],
        "pod_uid": pod["metadata"]["uid"],
    }
    if phase != "pre_schedule":
        placement.update(node_name=pod["spec"].get("nodeName"), node_uid=identity["uid"])
    return {
        "job": job,
        "pod": pod,
        "node": node,
        "requests": census,
        "placement": placement,
        "verified": identity,
    }


class ExportPlacement:
    """One immutable release/start sequence, with no retry-until-fresh admission.

    `journal` is the accepted DurableStore interface; tests supply the explicit
    portable file journal. `repository` is 4c's two-store publisher/readback.
    """

    def __init__(
        self,
        *,
        api,
        signal_api,
        journal,
        repository,
        root,
        binding,
        destination,
        namespace,
        job,
        pod,
        node,
        clock,
        clock_id,
        boot_id,
    ):
        from pathlib import Path

        self.api, self.signal_api, self.journal, self.repository = (
            api,
            signal_api,
            journal,
            repository,
        )
        self.root, self.binding, self.destination = Path(root), copy.deepcopy(binding), destination
        self.namespace, self.job, self.pod, self.node = namespace, job, pod, copy.deepcopy(node)
        self.clock, self.clock_id, self.boot_id = clock, clock_id, boot_id
        require(bool(clock_id) and bool(boot_id), "placement_api:clock")
        exact(repository.binding["controller"], binding, "placement_api:store_controller")
        self.deadline = SessionDeadline(binding["C_ms"], binding["D_session_ms"], binding["t0_ms"])
        self.identity = {
            "binding": binding,
            "destination": destination,
            "namespace": namespace,
            "job": job,
            "pod": pod,
            "node": node,
            "clock_id": clock_id,
            "boot_id": boot_id,
        }
        with journal.lock():
            state = journal.read()
            state.setdefault("export_placement", {"identity": self.identity, "events": []})
            exact(
                state["export_placement"]["identity"], self.identity, "placement_api:reopen_binding"
            )
            journal.write(state)

    def state(self):
        with self.journal.lock():
            return self.journal.read()["export_placement"]

    def save(self, **fields):
        with self.journal.lock():
            state = self.journal.read()
            state["export_placement"].update(copy.deepcopy(fields))
            self.journal.write(state)

    def path(self, resource, name):
        prefix = "/apis/batch/v1" if resource == "jobs" else "/api/v1"
        return (
            prefix
            + "/namespaces/"
            + quote(self.namespace, safe="")
            + "/"
            + resource
            + "/"
            + quote(name, safe="")
        )

    def collect(self, phase, stop):
        raw, reads = {}, {}

        def read(key, call):
            start = self.clock()
            wire_start = len(self.api.records)
            raw[key] = call()
            reads[key] = {
                "wire_records": [wire_start, len(self.api.records)],
                "api_json_sha256": sha(encode(raw[key])),
                "ms": [start, self.clock()],
                "clock_id": self.clock_id,
                "boot_id": self.boot_id,
                "uncertainty_ms": 0,
            }

        read("job", lambda: self.api.request("GET", self.path("jobs", self.job), stop))
        read("pod", lambda: self.api.request("GET", self.path("pods", self.pod), stop))
        read(
            "node",
            lambda: self.api.request(
                "GET", "/api/v1/nodes/" + quote(self.node["name"], safe=""), stop
            ),
        )
        for obj in (raw["job"], raw["pod"], raw["node"]):
            require(
                all(
                    type(obj["metadata"].get(k)) is str and bool(obj["metadata"][k])
                    for k in ("uid", "resourceVersion")
                ),
                "placement_api:object_identity",
            )
        owners = raw["pod"]["metadata"]["ownerReferences"]
        require(
            len(owners) == 1
            and owners[0].get("controller") is True
            and owners[0].get("kind") == "Job"
            and owners[0].get("name") == self.job,
            "placement_api:job_controller",
        )
        identity = {"name": raw["node"]["metadata"]["name"], "uid": raw["node"]["metadata"]["uid"]}
        exact(identity, self.node, "placement_api:node_uid")
        role = raw["node"]["metadata"].get("labels", {}).get("m5-role")
        read(
            "requests",
            lambda: (
                self.api.census(self.node, stop, role=role)
                if role is not None
                else self.api.census(self.node, stop)
            ),
        )
        # Re-read node identity, not a configuration assertion.
        read(
            "verified",
            lambda: self.api.request(
                "GET", "/api/v1/nodes/" + quote(self.node["name"], safe=""), stop
            ),
        )
        exact(
            {key: raw["verified"]["metadata"][key] for key in ("name", "uid")},
            self.node,
            "placement_api:refreshed_identity",
        )
        projected = project(raw, phase)
        reads["placement"] = copy.deepcopy(reads["pod"])
        observations = {
            key: Observation(encode(value), reads[key]["ms"][0]) for key, value in projected.items()
        }
        for key in ("job", "pod", "node"):
            index = reads[key]["wire_records"][0]
            chunks = [
                bytes.fromhex(f["raw_hex"])
                for f in self.api.records[index]["fragments"]
                if f["metadata"].get("direction") == "response"
            ]
            original = b"".join(chunks)
            exact(strict_json(original), raw[key], "placement_api:raw_projection_join")
            observations[key] = Observation(original, reads[key]["ms"][0])
        control = {
            "clock_id": self.clock_id,
            "boot_id": self.boot_id,
            "reads": reads,
            "decision_ms": self.clock(),
            "ack_ms": None,
            "signal_ms": None,
            "acknowledged": False,
            "received_once": False,
            "pod_uid": raw["pod"]["metadata"]["uid"],
            "source_hashes": {key: sha(o.raw) for key, o in observations.items()},
        }
        self.save(
            **{
                phase: {
                    "raw": raw,
                    "reads": reads,
                    "observations": {
                        k: {"raw_hex": o.raw.hex(), "observed_ms": o.observed_ms}
                        for k, o in observations.items()
                    },
                    "control": control,
                    "collected_control": copy.deepcopy(control),
                }
            }
        )
        return raw, observations, control

    def publish(self, name, value, stop):
        self.root.mkdir(parents=True, exist_ok=True)
        path = self.root / (name + ".json")
        payload = encode(value)
        if path.exists():
            exact(path.read_bytes(), payload, "placement_api:archive_immutable")
        else:
            path.write_bytes(payload)
        receipt = self.repository.publish("placement:" + name, {name + ".json": path}, stop)
        self.repository.access(receipt, stop)
        self.save(**{name + "_store_receipt": receipt})
        return sha(payload)

    @staticmethod
    def observations(saved):
        return {
            k: Observation(bytes.fromhex(v["raw_hex"]), v["observed_ms"])
            for k, v in saved["observations"].items()
        }

    def evaluate(self, pre, post, controls, now, stage=None):
        return check_placement(
            verified=pre["verified"],
            pre_schedule=pre,
            pre_export=post,
            deadline=self.deadline,
            now_ms=now,
            control=copy.deepcopy(controls),
            stage=stage,
        )

    def projected_control(self, control, now, *, acknowledgement=True, signal=True):
        """Planning predicates only. This copy is never factual control evidence."""
        value = copy.deepcopy(control)
        if acknowledgement and not value["acknowledged"]:
            value.update(acknowledged=True, ack_ms=now)
        if signal and not value["received_once"]:
            value.update(received_once=True, signal_ms=now)
        return value

    def acknowledge(self, phase, name, control, stop):
        receipt = self.state().get(name + "_store_receipt")
        if receipt is None:
            return
        # Re-access the exact publication: flags derive from both durable stores,
        # not merely from returning from a callback or a literal Boolean.
        self.repository.access(receipt, stop)
        exact(set(receipt["acknowledgements"]), {"recovery", "s3"}, "placement_api:both_store_ack")
        at = self.clock()
        proposed = self.projected_control(control, at)
        checked = (
            check_placement(
                verified=self.observations(self.state()["pre_schedule"])["verified"],
                pre_schedule=self.observations(self.state()["pre_schedule"]),
                pre_export=None,
                deadline=self.deadline,
                now_ms=at,
                control={"pre_schedule": proposed},
                stage="pre_schedule",
            )
            if phase == "pre_schedule"
            else None
        )
        if checked is not None and checked["decision"] != "EXPORT":
            return
        control.update(acknowledged=True, ack_ms=at)
        self.persist_control(phase, control)

    def persist_control(self, phase, control):
        saved = self.state()[phase]
        saved["control"] = copy.deepcopy(control)
        self.save(**{phase: saved})

    def run(self, stop):
        try:
            state = self.state()
            if "permission" in state:
                return self.validate(state["permission"], self.clock())
            require("intent" not in state, "placement_api:interrupted_no_retry")
            self.save(intent={"at_ms": self.clock(), "stop_ms": stop})
            raw, pre, first = self.collect("pre_schedule", stop)
            gates = raw["pod"]["spec"].get("schedulingGates")
            exact(gates, [{"name": GATE}], "placement_api:scheduling_gate")
            require(not raw["pod"]["spec"].get("nodeName"), "placement_api:already_bound")
            now = self.clock()
            projected = self.projected_control(first, now)
            decision = self.evaluate(pre, None, {"pre_schedule": projected}, now, "pre_schedule")
            self.save(pre_schedule_projected=decision)
            require(
                decision["decision"] == "EXPORT",
                "placement_api:pre_schedule:" + str(decision["reason"]),
            )
            digest = self.publish("pre-schedule", {"raw": raw, "projected": decision}, stop)
            self.acknowledge("pre_schedule", "pre-schedule", first, stop)
            now = self.clock()
            projected = self.projected_control(first, now, acknowledgement=False)
            ready = self.evaluate(pre, None, {"pre_schedule": projected}, now, "pre_schedule")
            require(
                ready["decision"] == "EXPORT", "placement_api:pre_release:" + str(ready["reason"])
            )
            # Full replacement carries both UID and resourceVersion preconditions.
            replacement = copy.deepcopy(raw["pod"])
            replacement["spec"]["schedulingGates"] = []
            self.save(
                release_intent={
                    "pod_uid": replacement["metadata"]["uid"],
                    "resourceVersion": replacement["metadata"]["resourceVersion"],
                    "decision_sha256": digest,
                }
            )
            released = self.api.request("PUT", self.path("pods", self.pod), stop, replacement)
            exact(
                released["metadata"]["uid"],
                replacement["metadata"]["uid"],
                "placement_api:release_uid",
            )
            exact(released["spec"].get("schedulingGates", []), [], "placement_api:release_gates")
            first.update(received_once=True, signal_ms=self.clock())
            self.persist_control("pre_schedule", first)
            first_decision = self.evaluate(
                pre, None, {"pre_schedule": first}, first["signal_ms"], "pre_schedule"
            )
            require(
                first_decision["decision"] == "EXPORT",
                "placement_api:release_age:" + str(first_decision["reason"]),
            )
            self.save(release=released, release_control=first)
            # All next reads strictly follow the actual release acknowledgement.
            while self.clock() <= first["signal_ms"]:
                require(self.clock() < stop, "placement_api:deadline")
                time.sleep(0.001)
            # Wait for scheduling, without refreshing the admission census.
            schedule_stop = min(stop, min(v["ms"][0] for v in first["reads"].values()) + 60_000)
            while True:
                scheduled = self.api.request("GET", self.path("pods", self.pod), schedule_stop)
                exact(
                    scheduled["metadata"]["uid"],
                    replacement["metadata"]["uid"],
                    "placement_api:scheduled_uid",
                )
                if scheduled["spec"].get("nodeName"):
                    break
                require(self.clock() < schedule_stop, "placement_api:scheduling_deadline")
                time.sleep(0.05)
            raw_post, post, second = self.collect("pre_export", stop)
            now = self.clock()
            projected = self.projected_control(second, now)
            candidate = self.evaluate(
                pre, post, {"pre_schedule": first, "pre_export": projected}, now
            )
            self.save(candidate_projected=candidate)
            require(
                candidate["decision"] == "EXPORT",
                "placement_api:pre_export:" + str(candidate["reason"]),
            )
            digest = self.publish("pre-export", {"raw": raw_post, "projected": candidate}, stop)
            self.acknowledge("pre_export", "pre-export", second, stop)
            signal = {
                "pod_uid": second["pod_uid"],
                "stop_ms": stop,
                "decision_sha256": digest,
                "binding": self.binding,
                "clock_id": self.clock_id,
                "boot_id": self.boot_id,
            }
            signal["authorization"] = {
                "pre_schedule": self.state()["pre_schedule"]["observations"],
                "pre_export": self.state()["pre_export"]["observations"],
                "control": {"pre_schedule": first, "pre_export": second},
                "candidate": {"raw": raw_post, "projected": candidate},
            }
            self.save(signal_intent=signal)
            received = self.signal_api.request("PUT", "/start", stop, signal)
            exact(received["signal"], signal, "placement_api:signal_join")
            exact(received["received_once"], True, "placement_api:signal_once")
            second.update(
                received_once=received["received_once"], signal_ms=received["received_ms"]
            )
            self.persist_control("pre_export", second)
            self.save(signal_receipt=received)
            require(
                received["decision"]["decision"] == "EXPORT",
                "placement_api:receiver_refused:" + str(received["decision"]["reason"]),
            )
            require(second["signal_ms"] <= self.clock(), "placement_api:signal_future")
            final = self.evaluate(
                pre, post, {"pre_schedule": first, "pre_export": second}, second["signal_ms"]
            )
            self.save(
                final_decision=final,
                signal_receipt=received,
                final_control={"pre_schedule": first, "pre_export": second},
            )
            require(
                final["decision"] == "EXPORT",
                "placement_api:received_signal:" + str(final["reason"]),
            )
            exact(received["decision"], final, "placement_api:receiver_decision_join")
            self.publish(
                "final",
                {
                    "decision": final,
                    "signal": received,
                    "api_wire": self.api.records,
                    "signal_wire": self.signal_api.records,
                },
                stop,
            )
            permission = {
                "binding": self.binding,
                "destination": self.destination,
                "decision": final,
                "decision_sha256": sha(encode(final)),
                "start_signal": received,
                "candidate_sha256": digest,
                "pod_uid": second["pod_uid"],
            }
            self.save(permission=permission)
            return self.validate(permission, self.clock())
        except Exception as exc:
            error = type(exc).__name__ + ":" + str(exc)
            errors = [*self.state().get("refusals", []), {"at_ms": self.clock(), "error": error}]
            self.save(refusal=error, refusals=errors)
            # Includes all exact raw API objects collected before refusal.
            try:
                self.publish(
                    "refusal-" + str(len(errors)),
                    {
                        "state": self.state(),
                        "api_wire": self.api.records,
                        "signal_wire": self.signal_api.records,
                    },
                    stop,
                )
            except Exception as archive_error:
                self.save(
                    refusal_archive_error=type(archive_error).__name__ + ":" + str(archive_error)
                )
            raise

    def validate(self, permission, now):
        state = self.state()
        exact(permission, state["permission"], "placement_api:permission_immutable")
        exact(permission["binding"], self.binding, "placement_api:permission_binding")
        exact(
            permission["start_signal"]["signal"]["decision_sha256"],
            permission["candidate_sha256"],
            "placement_api:decision_signal_join",
        )
        recomputed = self.evaluate(
            self.observations(state["pre_schedule"]),
            self.observations(state["pre_export"]),
            state["final_control"],
            permission["start_signal"]["received_ms"],
        )
        exact(permission["decision"], recomputed, "placement_api:decision_reproduction")
        require(recomputed["decision"] == "EXPORT", "placement_api:no_export_on_refusal")
        exact(permission["decision_sha256"], sha(encode(recomputed)), "placement_api:decision_hash")
        require(now < self.deadline.effective_ms, "placement_api:permission_expired")
        require(
            now < permission["start_signal"]["signal"]["stop_ms"], "placement_api:permission_cutoff"
        )
        require(
            all(
                0 <= now - v["ms"][0] <= MAX_PLACEMENT_OBSERVATION_AGE_MS
                for v in state["final_control"]["pre_export"]["reads"].values()
            ),
            "placement_api:permission_stale",
        )
        return permission


class PlacementPorts:
    def __init__(self, factory):
        self.factory = factory

    def permission(self, stop):
        f = self.factory
        f.port.deadline(stop)
        runtime = f.config.get("export_placement")
        require(runtime is not None, "eks:unfinished:4e_export_placement_inputs")
        require(isinstance(runtime, ExportPlacement), "placement_api:runtime")
        exact(runtime.binding, f.binding, "placement_api:factory_binding")
        result = runtime.run(stop)
        f.port.deadline(stop, completed=True)
        return result


def join_permission(permission, factory):
    runtime = factory.config.get("export_placement")
    require(isinstance(runtime, ExportPlacement), "eks:unfinished:4e_export_placement_inputs")
    exact(runtime.binding, factory.binding, "placement_api:factory_binding")
    return runtime.validate(permission, factory.clock())


class DurableStartSignal:
    """Held-exporter receive/take interlock. No start callback on REFUSE.

    The deployment binds the expected controller, Pod UID and validated common
    clock/boot. A lost response can be read back, but never opens a second start.
    """

    def __init__(self, *, journal, binding, pod_uid, clock_id, boot_id, clock):
        self.journal, self.binding, self.pod_uid = journal, binding, pod_uid
        self.clock_id, self.boot_id, self.clock = clock_id, boot_id, clock

    def receive(self, signal):
        with self.journal.lock():
            state = self.journal.read()
            old = state.get("export_start_signal")
            if old is not None:
                exact(old["signal"], signal, "placement_api:duplicate_signal_changed")
                state["duplicate_start_signal"] = {
                    "at_ms": self.clock(),
                    "sha256": sha(encode(signal)),
                    "count": state.get("duplicate_start_signal", {}).get("count", 0) + 1,
                }
                self.journal.write(state)
                require(False, "placement_api:duplicate_signal")
            exact(signal["binding"], self.binding, "placement_api:signal_binding")
            exact(signal["pod_uid"], self.pod_uid, "placement_api:signal_uid")
            exact(
                (signal["clock_id"], signal["boot_id"]),
                (self.clock_id, self.boot_id),
                "placement_api:signal_clock",
            )
            auth = signal["authorization"]
            exact(
                sha(encode(auth["candidate"])),
                signal["decision_sha256"],
                "placement_api:received_decision_hash",
            )
            exact(
                auth["candidate"]["projected"]["decision"],
                "EXPORT",
                "placement_api:signal_before_export",
            )
            now = self.clock()
            require(
                type(signal["stop_ms"]) is int and now < signal["stop_ms"],
                "placement_api:signal_deadline",
            )
            controls = copy.deepcopy(auth["control"])
            controls["pre_export"].update(signal_ms=now, received_once=True)
            pre = ExportPlacement.observations({"observations": auth["pre_schedule"]})
            post = ExportPlacement.observations({"observations": auth["pre_export"]})
            exact(controls["pre_export"]["pod_uid"], self.pod_uid, "placement_api:received_pod_uid")
            candidate = auth["candidate"]["projected"]
            original = check_placement(
                verified=pre["verified"],
                pre_schedule=pre,
                pre_export=post,
                deadline=SessionDeadline(
                    self.binding["C_ms"], self.binding["D_session_ms"], self.binding["t0_ms"]
                ),
                now_ms=candidate["now_ms"],
                control={
                    phase: candidate["phases"][phase]["control"]
                    for phase in ("pre_schedule", "pre_export")
                },
            )
            exact(original, candidate, "placement_api:received_candidate_join")
            decision = check_placement(
                verified=pre["verified"],
                pre_schedule=pre,
                pre_export=post,
                deadline=SessionDeadline(
                    self.binding["C_ms"], self.binding["D_session_ms"], self.binding["t0_ms"]
                ),
                now_ms=now,
                control=controls,
            )
            receipt = {
                "signal": signal,
                "received_ms": now,
                "received_once": True,
                "decision": decision,
            }
            state["export_start_signal"] = receipt
            self.journal.write(state)
            # The durable receive write is inside age, not free after admission.
            received_ms = self.clock()
            require(received_ms < signal["stop_ms"], "placement_api:signal_deadline")
            controls["pre_export"]["signal_ms"] = received_ms
            final = check_placement(
                verified=pre["verified"],
                pre_schedule=pre,
                pre_export=post,
                deadline=SessionDeadline(
                    self.binding["C_ms"], self.binding["D_session_ms"], self.binding["t0_ms"]
                ),
                now_ms=received_ms,
                control=controls,
            )
            receipt.update(received_ms=controls["pre_export"]["signal_ms"], decision=final)
            state["export_start_signal"] = receipt
            self.journal.write(state)
            return copy.deepcopy(receipt)

    def lookup(self):
        with self.journal.lock():
            return copy.deepcopy(self.journal.read().get("export_start_signal"))

    def take(self):
        with self.journal.lock():
            state = self.journal.read()
            receipt = state.get("export_start_signal")
            require(
                receipt is not None and receipt["decision"]["decision"] == "EXPORT",
                "placement_api:held_no_export",
            )
            require(not state.get("duplicate_start_signal"), "placement_api:duplicate_signal")
            require(not state.get("export_start_taken"), "placement_api:start_once")
            state["export_start_taken"] = True
            self.journal.write(state)
            now = self.clock()
            require(now < receipt["signal"]["stop_ms"], "placement_api:held_cutoff")
            require(
                now
                < SessionDeadline(
                    self.binding["C_ms"], self.binding["D_session_ms"], self.binding["t0_ms"]
                ).effective_ms,
                "placement_api:held_deadline",
            )
            require(
                all(
                    0 <= now - v["ms"][0] <= MAX_PLACEMENT_OBSERVATION_AGE_MS
                    for v in receipt["signal"]["authorization"]["control"]["pre_export"][
                        "reads"
                    ].values()
                ),
                "placement_api:held_stale",
            )
            return copy.deepcopy(receipt)


def held_exporter(interlock, export, *, stop=None):
    """The held Pod calls this entry only after its receive service is ready.

    A missing/refused signal never calls export; a crash after take cannot run
    the exporter a second time. External export settlement remains Part 4/4c.
    """
    while stop is not None and interlock.lookup() is None:
        require(interlock.clock() < stop, "placement_api:held_wait_deadline")
        time.sleep(0.05)
    receipt = interlock.take()
    return export(receipt)


def signal_handler(interlock, token):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_PUT(self):
            if self.path != "/start" or not hmac.compare_digest(
                self.headers.get("Authorization", ""), "Bearer " + token()
            ):
                self.send_error(403)
                return
            try:
                length = int(self.headers["Content-Length"])
                require(0 < length <= 8_388_608, "placement_api:signal_size")
                raw = self.rfile.read(length)
                exact(len(raw), length, "placement_api:signal_truncated")
                result = interlock.receive(strict_json(raw))
                payload = encode(result)
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            except (ValueError, KeyError, TypeError):
                self.send_error(409)

    return Handler
