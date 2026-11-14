"""Cluster-side authority over the accepted API client and durable port protocol.

This module has no AWS/provider client. Deployment inputs bind the final image,
source inventory, device producer and capture budgets; absent inputs refuse.
"""

import copy
import threading
import time
from urllib.parse import quote

from .inf037b_archive import encode, sha, strict_json
from .inf037b_contract import SESSION_ENVELOPE_MS
from .inf037b_eks_placement import PlacementAPI
from .inf037b_resolver import exact, require

# Implementation freshness cap derived from v4-r315 :41 and resolver.startup
# kill_release <= 15,000 ms. This adds no registered budget or allowance.
DEVICE_REPORT_MAX_AGE_MS = 15_000

SETUP_ORDER = ("begin", "cold", "two_serving", "stop_cold_and_drain", "node_cached")
PORTS = (
    "4d_cluster_authority",
    "4d_setup_lifecycle",
    "4d_device_release_observer",
    "4d_startup_observation",
    "4d_campaign_actions",
    "part2_setup_runtime",
    "campaign_capture_runtime",
)
INPUTS = dict(
    zip(
        PORTS,
        (
            "4e_cluster_inputs",
            "4e_setup_lifecycle_inputs",
            "4e_device_release_inputs",
            "4e_startup_inputs",
            "4e_campaign_action_inputs",
            "4e_part2_capture_inputs",
            "4e_campaign_capture_inputs",
        ),
        strict=True,
    )
)


def pod_path(namespace, name):
    return "/api/v1/namespaces/" + quote(namespace, safe="") + "/pods/" + quote(name, safe="")


def identity(value):
    meta = value["metadata"]
    require(
        all(type(meta.get(k)) is str and bool(meta[k]) for k in ("name", "uid", "resourceVersion")),
        "cluster:api_identity",
    )
    return {k: meta[k] for k in ("name", "uid", "resourceVersion")}


def declared_join(expected, actual):
    if type(expected) is dict:
        require(
            type(actual) is dict and expected.keys() <= actual.keys(), "cluster:effect_object_join"
        )
        for key, value in expected.items():
            declared_join(value, actual[key])
    elif type(expected) is list:
        require(type(actual) is list and len(expected) == len(actual), "cluster:effect_object_join")
        for a, b in zip(expected, actual, strict=True):
            declared_join(a, b)
    else:
        exact(actual, expected, "cluster:effect_object_join")


class ClusterRuntime:
    def __init__(self, *, api, journal, binding, pins, config, clock, inputs=None, wait=time.sleep):
        require(isinstance(api, PlacementAPI), "cluster:api_client")
        require(
            set(config.get("nodes", {})) == {"0", "1"}
            and set(config.get("slots", {})) == {"0", "1"},
            "eks:unfinished:4e_cluster_inputs",
        )
        require(
            len({node["uid"] for node in config["nodes"].values()}) == 2, "cluster:distinct_nodes"
        )
        self.api, self.journal, self.binding, self.pins, self.config, self.clock = (
            api,
            journal,
            copy.deepcopy(binding),
            copy.deepcopy(pins),
            copy.deepcopy(config),
            clock,
        )
        self.inputs = dict(inputs or {})
        if "fixed_actions" in self.inputs:
            from .inf037b_eks_actions import fixed_action_inputs

            produced = fixed_action_inputs(config, pins, **self.inputs["fixed_actions"])
            for name, value in produced.items():
                require(name not in self.inputs, "actions:duplicate_input:" + name)
                self.inputs[name] = value
        self.wait = wait
        self.guard = threading.RLock()
        self.active_capture = {}
        with journal.lock():
            state = journal.read()
            state.setdefault(
                "cluster_runtime",
                {
                    "identity": {"binding": binding, "pins": pins, "config": config},
                    "receipts": {},
                    "writes": {},
                    "setups": [],
                },
            )
            exact(
                state["cluster_runtime"]["identity"],
                {"binding": binding, "pins": pins, "config": config},
                "cluster:reopen_binding",
            )
            if "fixed_actions" in self.inputs:
                digest = sha(encode(self.inputs["fixed_actions"]))
                state["cluster_runtime"].setdefault("fixed_actions_sha256", digest)
                exact(
                    state["cluster_runtime"]["fixed_actions_sha256"], digest, "actions:reopen_pin"
                )
            for key in ("setup_results", "initial_holders", "absences"):
                state["cluster_runtime"].setdefault(key, {})
            journal.write(state)

    def state(self):
        with self.journal.lock():
            return self.journal.read()["cluster_runtime"]

    def update(self, fn):
        with self.journal.lock():
            state = self.journal.read()
            fn(state["cluster_runtime"])
            self.journal.write(state)

    def deadline(self, stop):
        require(
            self.binding["t0_ms"]
            <= self.clock()
            < stop
            <= min(self.binding["D_session_ms"], self.binding["t0_ms"] + SESSION_ENVELOPE_MS),
            "cluster:deadline",
        )

    def read(self, path, stop, *, absent=False):
        with self.api.exchange_lock:
            self.deadline(stop)
            begin = self.clock()
            index = len(self.api.records)
            try:
                value = self.api.request("GET", path, stop)
            except (OSError, ValueError):
                records = self.api.records[index:]
                statuses = [
                    f["metadata"].get("status")
                    for r in records
                    for f in r["fragments"]
                    if f["metadata"].get("direction") == "response_headers"
                ]
                if not (absent and statuses == [404]):
                    raise
                value = None
            end = self.clock()
            records = copy.deepcopy(self.api.records[index:])
            record = {
                "path": path,
                "read_ms": [begin, end],
                "wire": records,
                "value": value,
                "value_sha256": sha(encode(value)),
            }
            self.update(lambda state: state.setdefault("reads", []).append(record))
            return record

    def snapshot(self, stop):
        raw = {
            "cluster": self.read(self.config["cluster_path"], stop),
            "nodes": {},
            "pods": {},
            "censuses": {},
        }
        for slot, node in self.config["nodes"].items():
            raw["nodes"][str(slot)] = self.read(
                "/api/v1/nodes/" + quote(node["name"], safe=""), stop
            )
            actual = raw["nodes"][str(slot)]["value"]
            identity(actual)
            exact(actual["metadata"]["uid"], node["uid"], "cluster:node_uid")
            index = len(self.api.records)
            begin = self.clock()
            node_identity = {"name": node["name"], "uid": node["uid"]}
            role = actual["metadata"].get("labels", {}).get("m5-role")
            census = (
                self.api.census(node_identity, stop, role=role)
                if role is not None
                else self.api.census(node_identity, stop)
            )
            raw["censuses"][str(slot)] = {
                "value": census,
                "wire": copy.deepcopy(self.api.records[index:]),
                "read_ms": [begin, self.clock()],
            }
        for slot, spec in self.config["slots"].items():
            record = self.read(pod_path(self.config["namespace"], spec["name"]), stop, absent=True)
            pod = record["value"]
            if pod is not None:
                identity(pod)
                exact(
                    pod["metadata"]["labels"]["inf037b-session"],
                    self.binding["session_id"],
                    "cluster:pod_session",
                )
                exact(pod["metadata"]["labels"]["inf037b-slot"], str(slot), "cluster:pod_slot")
                if pod["spec"].get("nodeName"):
                    exact(
                        pod["spec"]["nodeName"],
                        self.config["nodes"][str(slot)]["name"],
                        "cluster:pod_node",
                    )
            raw["pods"][str(slot)] = record
        return raw

    def proof(self, port, raw, subject=None, extra=None):
        data = {
            "port": port,
            "binding": self.binding,
            "pins": self.pins,
            "subject": subject,
            "raw": raw,
            "extra": extra or {},
        }
        result = strict_json(encode({**data, "proof_sha256": sha(encode(data))}))
        self.update(lambda state: state["receipts"].update({result["proof_sha256"]: result}))
        return result

    def verify(self, value, port, subject=None):
        exact(value["binding"], self.binding, "cluster:receipt_binding")
        exact(value["pins"], self.pins, "cluster:receipt_pins")
        exact(value["port"], port, "cluster:receipt_port")
        exact(value["subject"], subject, "cluster:receipt_subject")
        data = {k: v for k, v in value.items() if k != "proof_sha256"}
        exact(value["proof_sha256"], sha(encode(data)), "cluster:receipt_hash")
        exact(value, self.state()["receipts"][value["proof_sha256"]], "cluster:retained_receipt")
        return value

    def authority(self, stop, context):
        raw = self.snapshot(stop)
        cluster = raw["cluster"]["value"]
        identity(cluster)
        exact(
            cluster["metadata"]["uid"], self.config["cluster_uid"], "cluster:authority_cluster_join"
        )
        return self.proof("4d_cluster_authority", raw, context)

    def setup(self, stop):
        plan = self.inputs.get("setup")
        require(plan is not None, "eks:unfinished:4e_setup_lifecycle_inputs")
        exact(plan["pins"], self.pins, "cluster:setup_pin_join")
        exact(list(plan["steps"]), list(SETUP_ORDER), "cluster:fixed_setup_order")
        return self.proof(
            "4d_setup_lifecycle", self.snapshot(stop), extra={"plan_sha256": sha(encode(plan))}
        )

    def device(self, stop):
        config = self.inputs.get("device")
        require(config is not None, "eks:unfinished:4e_device_release_inputs")
        raw = self.snapshot(stop)
        reports = {}
        for slot, spec in config.items():
            source = self.read(spec["producer_pod_path"], stop)["value"]
            identity(source)
            exact(source["metadata"]["uid"], spec["producer_uid"], "cluster:device_producer_uid")
            exact(
                source["spec"]["nodeName"],
                self.config["nodes"][str(slot)]["name"],
                "cluster:device_producer_node",
            )
            exact(
                source["spec"]["serviceAccountName"],
                spec["service_account"],
                "cluster:device_producer_authority",
            )
            require(
                any(c["image"] == spec["image"] for c in source["spec"]["containers"]),
                "cluster:device_producer_pin",
            )
            if "collector" in spec:
                from .inf037b_device import DeviceReleaseProducer

                require(
                    isinstance(spec["collector"], DeviceReleaseProducer), "cluster:device_collector"
                )
                spec["collector"].publish(self.api, spec["report_path"], stop)
            witness = self.read(spec["report_path"], stop)
            report = strict_json(witness["value"]["data"]["receipt.json"])
            exact(report["schema"], "inf037b-device-release-v1", "cluster:device_schema")
            exact(
                report["node_uid"],
                raw["nodes"][str(slot)]["value"]["metadata"]["uid"],
                "cluster:device_node_join",
            )
            exact(report["producer_uid"], source["metadata"]["uid"], "cluster:device_source_join")
            exact(report["pins"], self.pins, "cluster:device_pins")
            exact(report["device_ids"], spec["device_ids"], "cluster:device_ids")
            exact(report["complete"], True, "cluster:device_complete")
            require(
                type(report["allocations"]) is list and type(report["processes"]) is list,
                "cluster:device_inventory",
            )
            low, high = report["observation_ms"]
            require(
                self.binding["t0_ms"] <= low <= high <= self.clock() <= stop, "cluster:device_clock"
            )
            reports[str(slot)] = {"source": source, "witness": witness, "report": report}
        return self.proof("4d_device_release_observer", raw, extra={"reports": reports})

    def free_device(self, observer, slot, uid, *, since_ms=None):
        self.verify(observer, "4d_device_release_observer")
        report = observer["extra"]["reports"][str(slot)]["report"]
        low, high = report["observation_ms"]
        since_ms = self.binding["t0_ms"] if since_ms is None else since_ms
        require(low >= since_ms, "cluster:device_before_absence")
        require(0 <= self.clock() - low <= DEVICE_REPORT_MAX_AGE_MS, "cluster:device_report_stale")
        devices = set(report["device_ids"])
        require(
            all(
                a["device_id"] not in devices and a.get("pod_uid") != uid
                for a in report["allocations"]
            ),
            "cluster:device_still_allocated",
        )
        require(
            all(
                p["device_id"] not in devices and p.get("pod_uid") != uid
                for p in report["processes"]
            ),
            "cluster:device_process_live",
        )
        require(
            uid
            not in [r["source"]["metadata"]["uid"] for r in observer["extra"]["reports"].values()],
            "cluster:device_not_independent",
        )
        return {
            "pod_uid": uid,
            "slot": slot,
            "node_uid": report["node_uid"],
            "device_ids": report["device_ids"],
            "observation_ms": report["observation_ms"],
            "proof_sha256": observer["proof_sha256"],
        }

    def target(self, target):
        role = target.get("role")
        if role == "slot_pod":
            slot = str(target["slot"])
            require(slot in self.config["slots"], "cluster:target_slot")
            return pod_path(self.config["namespace"], self.config["slots"][slot]["name"])
        if role == "setup_result":
            result = self.state()["setup_results"][target["step"]]
            if "action" in target:
                return result["actions"][target["action"]]["path"]
            return result["path"]
        require(role == "object", "cluster:target_role")
        return self.config["objects"][target["name"]]["path"]

    def expected_target(self, source, before, path, owner):
        kind = source.get("from")
        if kind == "absent":
            require(before is None, "cluster:create_target_exists")
            return {"uid": None, "source": source}
        require(before is not None, "cluster:missing_write_target")
        if kind == "initial_slot":
            record = self.state()["initial_holders"][str(source["slot"])]
            uid = record["uid"]
        elif kind == "setup_result":
            result = self.state()["setup_results"][source["step"]]
            if "action" in source:
                record = result["actions"][source["action"]]
                uid = identity(record["observed"])["uid"]
            else:
                record, uid = result, result["uid"]
        elif kind == "object":
            record = self.config["objects"][source["name"]]
            uid = record["uid"]
        else:
            from .inf037b_capture import CaptureOwner

            require(
                kind == "admitted_slot" and isinstance(owner, CaptureOwner),
                "cluster:target_uid_source",
            )
            owner.join_current()
            exact(owner.binding["session_id"], self.binding["session_id"], "cluster:target_owner")
            uid = identity(before)["uid"]
            record = owner.lineage_admissions.get(uid)
            require(record is not None and record["slot"] == source["slot"], "cluster:target_uid")
            record = {"path": path, "admission": record, "owner_root": str(owner.root)}
        exact(record["path"], path, "cluster:target_path")
        exact(identity(before)["uid"], uid, "cluster:target_uid")
        return {"uid": uid, "source": source, "record": record}

    def action(self, key, template, stop, *, owner=None):
        exact(
            set(template), {"method", "target", "expected_uid", "body"}, "cluster:action_template"
        )
        old = self.state()["writes"].get(key)
        path = old["path"] if old is not None else self.target(template["target"])
        return self.write(
            key, template["method"], path, template["body"], stop, template=template, owner=owner
        )

    def gone(self, path, uid, stop, *, pending=False):
        while True:
            read = self.read(path, stop, absent=True)
            value = read["value"]
            if value is None or (uid is not None and identity(value)["uid"] != uid):
                return read
            require(
                pending and bool(value["metadata"].get("deletionTimestamp")),
                "cluster:holder_not_gone",
            )
            remaining = stop - self.clock()
            require(remaining > 0, "cluster:effect_unsettled")
            self.wait(min(0.5, remaining / 1000))
            require(self.clock() < stop, "cluster:effect_unsettled")

    def wait_absent(self, path, uid, stop):
        """Wait for the bound controller effect; never infer absence from phase."""
        while True:
            read = self.read(path, stop, absent=True)
            pod = read["value"]
            if pod is None:
                self.remember_absence(path, uid, read)
                return read
            exact(identity(pod)["uid"], uid, "cluster:drain_holder_changed")
            self.deadline(stop)
            self.wait(min(0.05, max(0, stop - self.clock()) / 1000))

    def wait_slot(self, slot, stop):
        path = pod_path(self.config["namespace"], self.config["slots"][str(slot)]["name"])
        while True:
            read = self.read(path, stop, absent=True)
            pod = read["value"]
            if pod is not None and pod["spec"].get("nodeName"):
                identity(pod)
                exact(
                    pod["spec"]["nodeName"],
                    self.config["nodes"][str(slot)]["name"],
                    "cluster:setup_result_node",
                )
                require(not pod["metadata"].get("deletionTimestamp"), "cluster:terminating_result")
                return read
            self.deadline(stop)
            self.wait(min(0.05, max(0, stop - self.clock()) / 1000))

    def remember_absence(self, path, uid, read):
        for slot, spec in self.config["slots"].items():
            if path != pod_path(self.config["namespace"], spec["name"]):
                continue

            def save(state, slot=slot):
                old = state["absences"].get(slot)
                if old is None or old["uid"] != uid:
                    state["absences"][slot] = {
                        "uid": uid,
                        "path": path,
                        "observed_gone_ms": read["read_ms"][1],
                        "read": read,
                    }

            self.update(save)

    def write(self, key, method, path, body, stop, *, template=None, owner=None):
        """Fill a static template from one retained read, then never resend."""
        require(method in ("PUT", "POST", "DELETE"), "cluster:write_method")
        descriptor = copy.deepcopy(
            {"method": method, "path": path, "body": body, "template": template}
        )
        with self.guard:
            old = self.state()["writes"].get(key)
            if old is None:
                before_read = self.read(path, stop, absent=True)
                before = before_read["value"]
                request = copy.deepcopy(body)
                selected = None
                if method == "POST":
                    require(before is None, "cluster:create_target_exists")
                else:
                    require(before is not None, "cluster:missing_write_target")
                if template is not None:
                    selected = self.expected_target(template["expected_uid"], before, path, owner)
                    require(
                        not ({"uid", "resourceVersion"} & request.get("metadata", {}).keys())
                        and "preconditions" not in request,
                        "cluster:template_preconditions",
                    )
                    if method in ("PUT", "POST"):
                        meta = request.setdefault("metadata", {})
                        meta.setdefault("name", path.rsplit("/", 1)[1])
                        exact(meta["name"], path.rsplit("/", 1)[1], "cluster:target_name")
                    if method == "PUT":
                        request["metadata"].update(
                            uid=identity(before)["uid"],
                            resourceVersion=identity(before)["resourceVersion"],
                        )
                    elif method == "DELETE":
                        request.setdefault("apiVersion", "v1")
                        request.setdefault("kind", "DeleteOptions")
                        request["preconditions"] = {
                            k: identity(before)[k] for k in ("uid", "resourceVersion")
                        }
                if method == "PUT":
                    meta = identity(before)
                    exact(request["metadata"]["uid"], meta["uid"], "cluster:write_uid")
                    exact(
                        request["metadata"]["resourceVersion"],
                        meta["resourceVersion"],
                        "cluster:write_rv",
                    )
                elif method == "DELETE":
                    pre = request["preconditions"]
                    require(
                        set(pre) in ({"uid"}, {"uid", "resourceVersion"}),
                        "cluster:delete_preconditions",
                    )
                    exact(pre["uid"], identity(before)["uid"], "cluster:delete_preconditions")
                    if "resourceVersion" in pre:
                        exact(
                            pre["resourceVersion"],
                            identity(before)["resourceVersion"],
                            "cluster:delete_preconditions",
                        )
                if method in ("PUT", "POST"):
                    request["metadata"].setdefault("annotations", {})["inf037b-operation"] = key
                old = {
                    "method": method,
                    "path": path,
                    "body": request,
                    "before": before,
                    "before_read": before_read,
                    "target_source": selected,
                    "descriptor": descriptor,
                    "intent_ms": self.clock(),
                }
                created = [False]

                def reserve(state):
                    if key not in state["writes"]:
                        state["writes"][key] = old
                        created[0] = True
                    else:
                        exact(
                            state["writes"][key]["descriptor"],
                            descriptor,
                            "cluster:concurrent_intent",
                        )

                self.update(reserve)
                if not created[0]:
                    return self.write(key, method, path, body, stop, template=template, owner=owner)
                try:
                    returned = self.api.request(
                        method, path.rsplit("/", 1)[0] if method == "POST" else path, stop, request
                    )
                    self.update(lambda state: state["writes"][key].update(reply=returned))
                except (OSError, ValueError) as exc:
                    error = type(exc).__name__ + ":" + str(exc)
                    self.update(lambda state: state["writes"][key].update(error=error))
            else:
                require("descriptor" in old, "cluster:legacy_intent_unsettled")
                exact((old["method"], old["path"]), (method, path), "cluster:effect_identity")
                exact(old["descriptor"], descriptor, "cluster:effect_body")
            if method == "DELETE":
                try:
                    read = self.gone(path, identity(old["before"])["uid"], stop, pending=True)
                except ValueError as exc:
                    if "holder_not_gone" in str(exc):
                        require(False, "cluster:effect_unsettled")
                    raise
                observed = read["value"]
                self.remember_absence(path, identity(old["before"])["uid"], read)
            else:
                observed = self.read(path, stop, absent=True)["value"]
                require(observed is not None, "cluster:effect_unsettled")
                exact(
                    observed["metadata"].get("annotations", {}).get("inf037b-operation"),
                    key,
                    "cluster:effect_operation_join",
                )
                if method == "PUT":
                    exact(
                        observed["metadata"]["uid"],
                        old["before"]["metadata"]["uid"],
                        "cluster:effect_uid",
                    )
                for field in ("spec", "data"):
                    if field in old["body"]:
                        declared_join(old["body"][field], observed.get(field))
                if old["body"].get("kind") in ("ConfigMap", "Secret"):
                    for field in ("data", "binaryData"):
                        exact(
                            observed.get(field, {}),
                            old["body"].get(field, {}),
                            "cluster:configuration_readback",
                        )
                identity(observed)
            result = {
                "method": method,
                "path": path,
                "observed": observed,
                "intent_sha256": sha(
                    encode(
                        {
                            k: old[k]
                            for k in (
                                "method",
                                "path",
                                "body",
                                "before_read",
                                "target_source",
                                "descriptor",
                                "intent_ms",
                            )
                        }
                    )
                ),
                "complete": True,
            }
            self.update(lambda state: state["writes"][key].update(result=result))
            return result

    def admission_device(self, slot, old_uid, since, stop):
        limit = min(stop, self.clock() + DEVICE_REPORT_MAX_AGE_MS)
        reason = "cluster:device_report_deadline"
        while self.clock() < limit:
            try:
                proof = self.device(limit)
            except ValueError as exc:
                # The last retained report still failed admission and the next
                # bounded read could not finish before this step's cutoff.
                if any(
                    token in str(exc)
                    for token in (
                        "transport_deadline",
                        "placement_api:deadline",
                        "cluster:deadline",
                    )
                ):
                    require(False, reason)
                raise
            try:
                release = self.free_device(proof, slot, old_uid, since_ms=since)
                return proof, release
            except ValueError as exc:
                if "device_before_absence" in str(exc):
                    reason = "cluster:device_before_absence"
                elif any(
                    token in str(exc) for token in ("device_still_allocated", "device_process_live")
                ):
                    report = proof["extra"]["reports"][str(slot)]["report"]
                    devices = set(report["device_ids"])
                    # Old/unnamed occupants may lag exit. A different live UID
                    # is a conflicting owner, including when another list's old
                    # occupant caused free_device's first refusal.
                    for field, failure in (
                        ("allocations", "cluster:device_still_allocated"),
                        ("processes", "cluster:device_process_live"),
                    ):
                        require(
                            not any(
                                row["device_id"] in devices
                                and row.get("pod_uid") not in (None, "", old_uid)
                                for row in report[field]
                            ),
                            failure,
                        )
                    reason = (
                        "cluster:device_still_allocated"
                        if "device_still_allocated" in str(exc)
                        else "cluster:device_process_live"
                    )
                elif "device_report_stale" in str(exc):
                    reason = "cluster:device_report_stale"
                else:
                    raise
            self.wait(min(0.5, max(0, limit - self.clock()) / 1000))
        require(False, reason)

    def setup_effect(self, name, key, stop):
        plan = self.inputs.get("setup")
        require(plan is not None, "eks:unfinished:4e_setup_lifecycle_inputs")
        exact(plan["pins"], self.pins, "cluster:setup_pin_join")
        with self.guard:
            state = self.state()
            done = state["setups"]
            require(name in SETUP_ORDER, "cluster:setup_step")
            if name not in done:
                exact(name, SETUP_ORDER[len(done)], "cluster:setup_sequence")
            if name in state["setup_results"]:
                exact(state["setup_results"][name]["request_key"], key, "cluster:setup_effect_key")
                return copy.deepcopy(state["setup_results"][name])
            step = plan["steps"][name]
            if name == "begin" and not state["initial_holders"]:
                initial = {}
                for slot, spec in self.config["slots"].items():
                    path = pod_path(self.config["namespace"], spec["name"])
                    read = self.read(path, stop, absent=True)
                    initial[slot] = {
                        "path": path,
                        "uid": None if read["value"] is None else identity(read["value"])["uid"],
                        "read": read,
                    }
                self.update(lambda state: state["initial_holders"].update(initial))
            results, release = [], None
            slot = step.get("result_slot")
            if name == "node_cached":
                cold = state["setup_results"]["cold"]
                exact(slot, cold["slot"], "cluster:cached_slot")
                exact(
                    self.config["nodes"][str(slot)]["uid"], cold["node_uid"], "cluster:cached_node"
                )
            if name in ("cold", "node_cached") and slot is not None:
                state = self.state()
                require("begin" in state["setup_results"], "cluster:begin_not_settled")
                previous = (
                    state["initial_holders"][str(slot)]
                    if name == "cold"
                    else state["setup_results"]["cold"]
                )
                old_uid = previous["uid"]
                path = previous["path"]
                read = self.gone(path, old_uid, stop, pending=True)
                self.remember_absence(path, old_uid, read)
                absence = self.state()["absences"][str(slot)]
                since = max(
                    absence["observed_gone_ms"], state["setup_results"]["begin"]["settled_ms"]
                )
                proof, release = self.admission_device(slot, old_uid, since, stop)
                release.update(
                    proof_sha256=proof["proof_sha256"], absence=absence, old_pod_uid=old_uid
                )
            for index, action in enumerate(step["actions"]):
                results.append(self.action(key + ":" + str(index), action, stop))
            if step.get("drain_initial"):
                for previous in self.state()["initial_holders"].values():
                    self.wait_absent(previous["path"], previous["uid"], stop)
            for stage in step.get("drain_results", []):
                previous = self.state()["setup_results"][stage]
                self.wait_absent(previous["path"], previous["uid"], stop)
            placed = {str(i): self.wait_slot(i, stop) for i in step.get("wait_slots", [])}
            result = {
                "binding": self.binding,
                "request_key": key,
                "actions": results,
                "settled_ms": self.clock(),
                "placement_reads": placed,
            }
            if slot is not None:
                path = self.target({"role": "slot_pod", "slot": slot})
                pod = (placed[str(slot)] if str(slot) in placed else self.read(path, stop))["value"]
                node = self.config["nodes"][str(slot)]
                exact(pod["spec"]["nodeName"], node["name"], "cluster:setup_result_node")
                result.update(uid=identity(pod)["uid"], slot=slot, node_uid=node["uid"], path=path)
                if release is not None:
                    release["pod_uid"] = result["uid"]
                    result["device_release"] = release
            result["settled_ms"] = self.clock()
            result = strict_json(encode(result))  # Same receipt on initial return and reopen.

            def settle(state):
                if name not in state["setups"]:
                    state["setups"].append(name)
                state["setup_results"][name] = result

            self.update(settle)
            return result


class ClusterEffectAuthority:
    """Adapter for LifecycleAuthorityPort's accepted intent/settlement protocol."""

    def __init__(self, runtime):
        self.runtime = runtime

    def call(self, operation, key, sequence, body):
        if operation == "intent.settle":
            require(body["retry"] is False, "cluster:no_blind_retry")
            return self.call(body["operation"], key, sequence, body["body"])
        exact(body["binding"], self.runtime.binding, "cluster:effect_binding")
        exact(body["pins"], self.runtime.pins, "cluster:effect_pins")
        name = operation.removeprefix("eks.setup.")
        require(operation == "eks.setup." + name and name in SETUP_ORDER, "cluster:effect_scope")
        result = self.runtime.setup_effect(name, key, body["stop_ms"])
        return {
            "request_key": key,
            "body_sha256": sha(encode(body)),
            "complete": True,
            "result": result,
        }

    def reconcile(self, operation, key, sequence, body):
        # setup_effect never repeats an ambiguous write: every old write is read.
        return self.call(operation, key, sequence, body)


class ClusterPorts:
    def __init__(self, factory):
        self.factory = factory

    def runtime(self, port):
        runtime = self.factory.config.get("cluster_runtime")
        require(isinstance(runtime, ClusterRuntime), "eks:unfinished:" + INPUTS[port])
        exact(runtime.binding, self.factory.binding, "cluster:factory_binding")
        exact(runtime.pins, self.factory.config["pins"], "cluster:factory_pins")
        return runtime

    def authority(self, stop, context):
        return self.runtime("4d_cluster_authority").authority(stop, context)

    def setup(self, stop):
        return self.runtime("4d_setup_lifecycle").setup(stop)

    def device(self, stop):
        return self.runtime("4d_device_release_observer").device(stop)

    def startup(self, name, receipt, stop):
        from .inf037b_eks_cluster_runtime import startup

        return startup(self.runtime("4d_startup_observation"), name, receipt, stop)

    def setup_runtime(self, stop):
        from .inf037b_eks_cluster_runtime import setup_runtime

        return setup_runtime(self.runtime("part2_setup_runtime"), stop)

    def campaign_runtime(self, operation, stop, context, *, reset, sequence_checkpoint):
        from .inf037b_eks_cluster_runtime import campaign_runtime

        return campaign_runtime(
            self.runtime("campaign_capture_runtime"),
            operation,
            stop,
            context,
            reset,
            sequence_checkpoint,
        )

    def actions(self, operation, owner, stop, context, bind, *, reset):
        from .inf037b_eks_cluster_runtime import campaign_actions

        return campaign_actions(
            self.runtime("4d_campaign_actions"), operation, owner, stop, context, bind, reset
        )

    def setup_effect(self, name, key, body, stop):
        from .inf037b_eks_commands import LifecycleAuthorityPort

        f = self.factory
        r = self.runtime("4d_setup_lifecycle")
        r.verify(body["authority"], "4d_setup_lifecycle")
        exact(
            body["authority"]["extra"]["plan_sha256"],
            sha(encode(r.inputs["setup"])),
            "cluster:setup_plan_changed",
        )
        r.verify(body["device_observer"], "4d_device_release_observer")
        port = LifecycleAuthorityPort(
            f.port.store,
            ClusterEffectAuthority(r),
            f.binding,
            f.config["pins"],
            f.clock,
            f.port.driver_key,
        )
        return port.effect("eks.setup." + name, key, body, stop)


def join_cluster(value, factory, port, subject=None):
    proof = getattr(value, "proof", None)
    if proof is None:
        proof = value.get("proof", value)
    runtime = ClusterPorts(factory).runtime(port)
    runtime.verify(proof, port, subject)
    if port == "4d_startup_observation":
        case = runtime.inputs["startup"][subject["name"]]
        exact(
            proof["extra"]["owner_root"], str(case["owner"].root), "cluster:consumer_startup_root"
        )
        exact(
            set(value["sampler"]["adapters"]),
            {subject["receipt"]["uid"]},
            "cluster:consumer_startup_uid",
        )
    if port in ("part2_setup_runtime", "campaign_capture_runtime"):
        if port == "campaign_capture_runtime":
            exact(
                {
                    tuple(row["stream"]): row["next"]
                    for row in proof["extra"]["entry_sequence_checkpoint"]
                },
                {tuple(row["stream"]): row["next"] for row in subject["checkpoint"]},
                "cluster:consumer_entry_checkpoint",
            )
        owner = value["owner"]
        exact(str(owner.root), proof["extra"]["owner_root"], "cluster:consumer_owner_root")
        exact(
            sha(encode(owner.sources)), proof["extra"]["sources_sha256"], "cluster:consumer_sources"
        )
        exact(owner.binding["pins"], runtime.pins, "cluster:consumer_pins")
        owner.join_current()
        if port == "part2_setup_runtime":
            row5_owner = value["row5_owner"]
            exact(value["row5"]["owner"], row5_owner, "cluster:consumer_row5_owner")
            exact(
                str(row5_owner.root),
                proof["extra"]["row5_owner_root"],
                "cluster:consumer_row5_root",
            )
            exact(
                sha(encode(row5_owner.sources)),
                proof["extra"]["row5_sources_sha256"],
                "cluster:consumer_row5_sources",
            )
            require(row5_owner.root != owner.root, "cluster:consumer_owner_split")
            row5_owner.join_current()
            for role, candidate in (
                ("fitness_probe_and_signal", owner),
                ("row5_controls_and_restoration", row5_owner),
            ):
                instance = factory.capture_spec(role)
                exact(candidate.binding, instance["binding"], "cluster:consumer_scope_binding")
                exact(candidate.sources, instance["sources"], "cluster:consumer_scope_sources")
            exact(value["probe_owner"], owner, "cluster:consumer_probe_owner")
    return proof
