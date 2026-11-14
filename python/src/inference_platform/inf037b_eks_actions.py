"""Fixed 02-D action producers; live UID/RV always come from ClusterRuntime.

The rendered controller and configuration objects are pinned inputs, not API
snapshots chosen after a failed smoke. This module neither allocates an attempt
nor declares a terminal Pod's node allocations reclaimed.
"""

import copy
from urllib.parse import quote

from .inf037b_archive import encode, sha
from .inf037b_contract import TARGET_ORDER
from .inf037b_resolver import exact, require


def pinned_object(record):
    obj = copy.deepcopy(record["object"])
    exact(sha(encode(obj)), record["sha256"], "actions:pinned_object")
    require(
        not ({"uid", "resourceVersion"} & obj["metadata"].keys()) and "status" not in obj,
        "actions:static_object",
    )
    return obj


def object_action(config, name, obj):
    path = config["objects"][name]["path"]
    exact(path.rsplit("/", 1)[1], obj["metadata"]["name"], "actions:object_name")
    exact(obj["metadata"]["namespace"], config["namespace"], "actions:object_namespace")
    return {
        "method": "PUT",
        "target": {"role": "object", "name": name},
        "expected_uid": {"from": "object", "name": name},
        "body": obj,
    }


def configuration_actions(config, records):
    """The same exact pinned objects are used for apply and rollback.

    Caller pins the whole record list in the reviewed deployment binding. Every
    object is verified before any effect; a changed rollback never partly runs.
    """
    require(type(records) is list, "actions:configuration_records")
    require(len({r["name"] for r in records}) == len(records), "actions:duplicate_object")
    for record in records:
        exact(
            config["objects"][record["name"]]["sha256"],
            record["sha256"],
            "actions:configuration_pin",
        )
    actions = []
    for record in records:
        obj = pinned_object(record)
        require(
            obj["kind"] in ("ConfigMap", "Secret") and "stringData" not in obj,
            "actions:canonical_configuration",
        )
        actions.append(object_action(config, record["name"], obj))
    return actions


def restore_configuration(runtime, key, records, stop):
    from .inf037b_eks_collectors import PROJECT_WINDOWS_MS

    begin = runtime.clock()
    actions = configuration_actions(runtime.config, records)
    with runtime.journal.lock():
        state = runtime.journal.read()
        windows = state["cluster_runtime"].setdefault("configuration_windows", {})
        if key not in windows:
            now = runtime.clock()
            cutoff = min(stop, begin + PROJECT_WINDOWS_MS["configuration_smoke_rollback"])
            require(now < cutoff, "eks:scope_timeout:configuration_smoke_rollback")
            windows[key] = {"start_ms": begin, "original_stop_ms": stop, "stop_ms": cutoff}
            runtime.journal.write(state)
        window = windows[key]
    exact(window["original_stop_ms"], stop, "actions:configuration_original_cutoff")
    require(
        window["stop_ms"]
        <= min(stop, window["start_ms"] + PROJECT_WINDOWS_MS["configuration_smoke_rollback"]),
        "actions:configuration_window",
    )
    stop = window["stop_ms"]
    require(runtime.clock() < stop, "eks:scope_timeout:configuration_smoke_rollback")
    return [runtime.action(key + ":" + str(i), action, stop) for i, action in enumerate(actions)]


def fixed_action_inputs(config, pins, controller, configuration):
    """Produce the accepted setup order and three fixed campaign target slots.

    The existing two-replica StatefulSet is scaled, never replaced with another
    controller topology. Setup waits for authoritative old-UID absence before
    cold/cached admission; device-free and startup evaluators are unchanged.
    """
    obj = pinned_object(controller)
    name = controller["name"]
    exact(config["objects"][name]["sha256"], controller["sha256"], "actions:controller_pin")
    exact((obj["apiVersion"], obj["kind"]), ("apps/v1", "StatefulSet"), "actions:controller")
    exact(obj["spec"]["replicas"], 2, "actions:two_slots")
    path = (
        "/apis/apps/v1/namespaces/"
        + quote(config["namespace"], safe="")
        + "/statefulsets/"
        + quote(obj["metadata"]["name"], safe="")
    )
    exact(config["objects"][name]["path"], path, "actions:controller_path")
    for slot in (0, 1):
        exact(
            config["slots"][str(slot)]["name"],
            obj["metadata"]["name"] + "-" + str(slot),
            "actions:controller_slot",
        )
    engine = next(c for c in obj["spec"]["template"]["spec"]["containers"] if c["name"] == "vllm")
    require(engine["image"].endswith("@sha256:" + pins["runtime"]), "actions:runtime_pin")
    restore = configuration_actions(config, configuration)

    def scale(replicas):
        body = copy.deepcopy(obj)
        body["spec"]["replicas"] = replicas
        return object_action(config, name, body)

    steps = {
        "begin": {"actions": [*restore, scale(0)], "drain_initial": True},
        "cold": {"actions": [scale(1)], "result_slot": 0, "wait_slots": [0]},
        "two_serving": {"actions": [scale(2)], "result_slot": 1, "wait_slots": [0, 1]},
        "stop_cold_and_drain": {
            "actions": [scale(0)],
            "drain_results": ["cold", "two_serving"],
        },
        "node_cached": {"actions": [scale(2)], "result_slot": 0, "wait_slots": [0, 1]},
    }
    campaign = {}
    for attempt, target in enumerate(TARGET_ORDER, 1):
        campaign["attempt:" + str(attempt)] = {
            "target_slot": target,
            "effects": [
                {
                    "method": "DELETE",
                    "target": {"role": "slot_pod", "slot": target},
                    "expected_uid": {"from": "admitted_slot", "slot": target},
                    "body": {},
                }
            ],
            "replacement": True,
        }
        campaign["attempt_setup:" + str(attempt)] = {
            "target_slot": target,
            "effects": [*restore, scale(0)] if attempt > 1 else [*restore, scale(2)],
            "drain_slots": [0, 1] if attempt > 1 else [],
            "after_drain": [scale(2)] if attempt > 1 else [],
            "replacement_slots": [0, 1] if attempt > 1 else [],
        }
    return {
        "setup": {
            "pins": copy.deepcopy(pins),
            "steps": steps,
            "controller_sha256": controller["sha256"],
            "configuration_sha256": sha(encode(configuration)),
        },
        "campaign_actions": campaign,
    }
