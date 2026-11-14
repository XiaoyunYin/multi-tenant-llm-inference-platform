"""Cluster-side compositions for the accepted setup/campaign consumers.

Capture owners, image/endpoints and operational budgets are final 4e inputs.
Missing inputs never become synthetic startup, GPU-free or serving evidence.
"""

import copy
import time

from .inf037b_archive import encode, sha
from .inf037b_capture import CaptureOwner, DeadlineHTTP
from .inf037b_capture_inventory import require_eks_capture_binding
from .inf037b_composition import RetainedStartupRows, SamplerComposition
from .inf037b_contract import TARGET_ORDER
from .inf037b_eks_cluster import pod_path
from .inf037b_eks_placement import PlacementAPI
from .inf037b_live import KubernetesAdapter, VLLMAdapter
from .inf037b_resolver import exact, require


class BoundActions(dict):
    """Callable action map with a separately joined serializable receipt."""


class KubernetesCaptureHTTP:
    """Existing adapter interface, using PlacementAPI for reads and watches."""

    def __init__(self, api, stop):
        self.api, self.stop = api, stop
        self.stop_ns = stop * 1000000
        self.watch_bytes = 0

    def get(self, path):
        with self.api.exchange_lock:
            before = len(self.api.records)
            self.api.request("GET", path, self.stop)
            fragments = self.api.records[before]["fragments"]
            body = b"".join(
                bytes.fromhex(f["raw_hex"])
                for f in fragments
                if f["metadata"].get("direction") == "response"
            )
            headers = next(
                (
                    dict(f["metadata"]["headers"])
                    for f in fragments
                    if f["metadata"].get("direction") == "response_headers"
                ),
                {},
            )
            # The exact bytes have already been retained by this owner. Do not
            # accumulate a second in-memory wire archive over a whole campaign.
            del self.api.records[before:]
            return body, headers

    def lines(self, path):
        try:
            yield from self.api.watch_lines(path, self.stop)
        finally:
            self.watch_bytes = self.api.watch_bytes

    def cutoff(self):
        self.api.cutoff_watch()


def capture_owner(runtime, value, binding, *, expected_attempt, checkpoint=None):
    owner = value["owner"]
    require(isinstance(owner, CaptureOwner), "cluster:capture_owner_type")
    require_eks_capture_binding(owner.binding, owner.sources)
    exact(owner.binding["session_id"], binding["session_id"], "cluster:capture_session")
    exact(owner.binding["pins"], runtime.pins, "cluster:capture_pins")
    exact(owner.attempt, expected_attempt, "cluster:capture_attempt")
    if expected_attempt != "setup":
        exact(owner.stages, [1, 2, 3, 4, 5], "cluster:capture_stages")
    owner.join_current()
    if checkpoint is not None:
        exact(
            owner.normalized_sequence,
            {tuple(r["stream"]): r["next"] for r in checkpoint},
            "cluster:capture_checkpoint_join",
        )
    return owner


def setup_runtime(runtime, stop):
    inputs = runtime.inputs.get("setup_runtime")
    require(inputs is not None, "eks:unfinished:4e_part2_capture_inputs")
    owner = capture_owner(runtime, inputs, runtime.binding, expected_attempt="setup")
    row5_owner = inputs["row5_owner"]
    exact(inputs["row5"]["owner"], row5_owner, "cluster:setup_owner_join")
    capture_owner(runtime, {"owner": row5_owner}, runtime.binding, expected_attempt="setup")
    require(owner.root != row5_owner.root, "cluster:setup_owner_split")
    exact(inputs["probe_owner"], owner, "cluster:setup_probe_owner")
    require(
        callable(inputs["probe_runtime"]) and callable(inputs["collect_inputs"]),
        "cluster:setup_collectors",
    )
    raw = runtime.snapshot(stop)
    proof = runtime.proof(
        "part2_setup_runtime",
        raw,
        extra={
            "owner_root": str(owner.root),
            "sources_sha256": sha(encode(owner.sources)),
            "row5_owner_root": str(row5_owner.root),
            "row5_sources_sha256": sha(encode(row5_owner.sources)),
            "stop_ms": stop,
        },
    )
    result = dict(inputs)
    result["proof"] = proof

    def probe(cutoff):
        exact(cutoff, stop, "cluster:probe_original_stop")
        return inputs["probe_runtime"](cutoff)

    def collect(cutoff):
        exact(cutoff, stop, "cluster:collect_original_stop")
        owner.join_current()
        return inputs["collect_inputs"](cutoff)

    result.update(probe_runtime=probe, collect_inputs=collect)
    return result


def startup(runtime, name, receipt, stop):
    cases = runtime.inputs.get("startup")
    require(cases is not None and name in cases, "eks:unfinished:4e_startup_inputs")
    inputs = cases[name]
    if "cold" in cases and "node_cached" in cases:
        require(
            cases["cold"]["owner"].root != cases["node_cached"]["owner"].root,
            "cluster:startup_case_owner_split",
        )
    setup_inputs = runtime.inputs.get("setup_runtime", {})
    for role in ("owner", "row5_owner"):
        if role in setup_inputs:
            require(
                inputs["owner"].root != setup_inputs[role].root, "cluster:startup_scope_owner_split"
            )
    slot = receipt["slot"]
    raw = runtime.snapshot(stop)
    pod = raw["pods"][str(slot)]["value"]
    exact(pod["metadata"]["uid"], receipt["uid"], "cluster:startup_uid_join")
    exact(
        raw["nodes"][str(slot)]["value"]["metadata"]["uid"],
        receipt["node_uid"],
        "cluster:startup_node_join",
    )
    require(
        any(
            "running" in c.get("state", {})
            for c in pod.get("status", {}).get("containerStatuses", [])
            if c.get("name") == "vllm"
        ),
        "cluster:startup_container",
    )
    owner = inputs["owner"]
    require(isinstance(owner, CaptureOwner), "cluster:startup_owner")
    exact(owner.binding["pins"], runtime.pins, "cluster:startup_pins")
    exact(owner.lineage_admissions[receipt["uid"]]["slot"], slot, "cluster:startup_watch_admission")
    transports = inputs.get("transports")
    bound = None
    if transports is not None:
        from .inf037b_eks_transports import PodTransports

        require(
            isinstance(transports, PodTransports) and transports.owner is owner,
            "cluster:startup_transports",
        )
        bound, adapters = transports.adapters(
            pod, slot, stop, request_ids=inputs["request_ids"], lifecycle=inputs["lifecycle"]
        )
        spec = {"http": bound["metrics_http"], "process_generation": bound["process_generation"]}
    else:
        spec = inputs["metrics"][str(slot)]
    adapter = VLLMAdapter(
        owner.rows("metrics:slot" + str(slot)),
        DeadlineHTTP(
            **spec["http"],
            stop_ns=stop * 1000000,
            retain=owner.retainer(
                "metrics:slot" + str(slot),
                uid=receipt["uid"],
                process_generation=spec["process_generation"],
            ),
        ),
        pod_uid=receipt["uid"],
        slot=slot,
        process_generation=spec["process_generation"],
        model_sha256=runtime.pins["model"],
        runtime_sha256=runtime.pins["runtime"],
        semantics_sha256=runtime.pins["metric_semantics"],
        lifecycle=inputs["lifecycle"],
    )
    proof = runtime.proof(
        "4d_startup_observation",
        raw,
        {"name": name, "receipt": receipt},
        extra={"owner_root": str(owner.root), "pod_uid": receipt["uid"]},
    )
    sampler = {
        "adapters": {receipt["uid"]: adapter},
        "startup_rows": {
            receipt["uid"]: RetainedStartupRows(
                owner.archive.root / "raw", receipt["uid"], owner.lock
            )
        },
        "flush": owner.archive_barrier,
    }
    if "scheduler" in inputs:
        sampler["scheduler"] = inputs["scheduler"]
    result = {
        "proof": proof,
        "sampler": sampler,
        "stop_event": inputs["stop_event"],
        "owner": owner,
        **{
            key: inputs[key]
            for key in ("collector_bundle", "capture_start_ns", "capture_stop_ns", "watches")
            if key in inputs
        },
    }
    if bound is not None:
        result.update(
            transport_spec=bound,
            transport_adapters=adapters,
            transport_periodic=transports.periodic(adapters),
        )
    return result


def campaign_runtime(runtime, operation, stop, context, reset, checkpoint):
    entries = runtime.inputs.get("campaign_runtime")
    require(entries is not None, "eks:unfinished:4e_campaign_capture_inputs")
    attempt = context["input"]["attempt"]
    key = operation + ":" + str(attempt)
    require(key in entries, "eks:unfinished:4e_campaign_capture_inputs:" + key)
    inputs = entries[key]
    owner = capture_owner(
        runtime, inputs, runtime.binding, expected_attempt=attempt, checkpoint=checkpoint
    )
    with owner.normalized_sequence_lock:
        entry_checkpoint = [
            {"stream": list(stream), "next": sequence}
            for stream, sequence in sorted(owner.normalized_sequence.items())
        ]
    exact(str(owner.root), str(inputs["root"]), "cluster:campaign_owner_join")
    spec = inputs["spec"]
    exact(spec["attempt_index"], attempt, "cluster:campaign_attempt")
    exact(spec["target_slot"], TARGET_ORDER[attempt - 1], "cluster:campaign_target")
    lifecycle = inputs["lifecycle"]
    # The campaign API wire belongs to this exact capture owner, not the
    # separate control/placement retainer. Reuse the same bounded API client.
    capture_api = PlacementAPI(
        runtime.api.base,
        token=runtime.api.token,
        clock=runtime.clock,
        retain=owner.retainer("kubernetes"),
        ca=runtime.api.ca,
        local_test=runtime.api.local_test,
    )
    kube = KubernetesAdapter(
        owner.rows("kubernetes"),
        KubernetesCaptureHTTP(capture_api, stop),
        runtime.config["namespace"],
        slot_names={v["name"]: int(k) for k, v in runtime.config["slots"].items()},
        lifecycle=lifecycle,
    )
    snapshot = kube.snapshot()
    require(
        kube.pod_resource_version is not None and all(row.get("error") is None for row in snapshot),
        "cluster:campaign_snapshot",
    )
    proof = runtime.proof(
        "campaign_capture_runtime",
        runtime.snapshot(stop),
        {"operation": operation, "context": context, "reset": reset, "checkpoint": checkpoint},
        extra={
            "owner_root": str(owner.root),
            "sources_sha256": sha(encode(owner.sources)),
            "entry_sequence_checkpoint": entry_checkpoint,
        },
    )
    result = {
        **inputs,
        "owner": owner,
        "spec": spec,
        "periodic": [*(inputs.get("periodic", [])), ("kubernetes", 500, kube.snapshot)],
        "watches": {**inputs.get("watches", {}), "kubernetes": (kube, kube.pod_resource_version)},
        "proof": proof,
        "replacement_adapters": {},
        "replacement_samplers": {},
    }
    # Dynamic replacement adapters are read by stable callbacks on the same
    # slot retainers. No second owner or new files are allocated for a new UID.
    for slot in runtime.config["slots"]:
        for kind in ("native", "lifecycle", "metrics"):

            def collect(slot=int(slot), kind=kind):
                for uid, adapters in tuple(result["replacement_adapters"].items()):
                    if adapters["metrics"].slot == slot:
                        if kind == "metrics":
                            result["replacement_samplers"][uid].poll(
                                uid, deadline_ns=stop * 1000000
                            )
                        else:
                            adapters[kind].poll()

            result["periodic"].append((kind + ":slot" + str(slot), 500, collect))
    if type(inputs.get("collector_bundle")) is dict:
        result["collector_bundle"] = {**inputs["collector_bundle"], "kubernetes": kube}
    runtime.active_capture[key] = result
    return result


def campaign_actions(runtime, operation, owner, stop, context, bind, reset):
    plans = runtime.inputs.get("campaign_actions")
    require(plans is not None, "eks:unfinished:4e_campaign_action_inputs")
    attempt = context["input"]["attempt"]
    key = operation + ":" + str(attempt)
    plan = copy.deepcopy(plans[key])
    exact(plan["target_slot"], TARGET_ORDER[attempt - 1], "cluster:action_target_join")
    capture = runtime.active_capture.get(key)
    require(capture is not None and capture["owner"] is owner, "cluster:action_owner")
    target_slot = plan["target_slot"]
    raw = runtime.snapshot(stop)
    proof = runtime.proof(
        "4d_campaign_actions",
        raw,
        {"operation": operation, "context": context, "reset": reset},
        extra={"plan_sha256": sha(encode(plan)), "owner_root": str(owner.root)},
    )

    def action():
        runtime.deadline(stop)
        if operation == "attempt":
            at = capture["spec"]["pre_end_ms"]
            while runtime.clock() < at:
                runtime.deadline(stop)
                time.sleep(min(0.05, (at - runtime.clock()) / 1000))
        for index, step in enumerate(plan["effects"]):
            boundary = getattr(result, "boundary", None)
            if boundary is not None:
                boundary()
            try:
                runtime.action(
                    context["operation_key"] + ":cluster:" + str(index), step, stop, owner=owner
                )
            finally:
                if boundary is not None:
                    boundary()
        for drained in plan.get("drain_slots", []):
            original = raw["pods"][str(drained)]["value"]
            require(original is not None, "cluster:drain_missing_holder")
            path = pod_path(
                runtime.config["namespace"], runtime.config["slots"][str(drained)]["name"]
            )
            absent = runtime.wait_absent(path, original["metadata"]["uid"], stop)
            runtime.admission_device(
                drained, original["metadata"]["uid"], absent["read_ms"][1], stop
            )
        for index, step in enumerate(plan.get("after_drain", []), len(plan["effects"])):
            boundary = getattr(result, "boundary", None)
            if boundary is not None:
                boundary()
            try:
                runtime.action(
                    context["operation_key"] + ":cluster:" + str(index), step, stop, owner=owner
                )
            finally:
                if boundary is not None:
                    boundary()
        replacements = plan.get(
            "replacement_slots", [target_slot] if plan.get("replacement") else []
        )
        for slot in replacements:
            path = pod_path(runtime.config["namespace"], runtime.config["slots"][str(slot)]["name"])
            original = raw["pods"][str(slot)]["value"]["metadata"]["uid"]
            while True:
                pod = runtime.read(path, stop, absent=True)["value"]
                if pod is not None and pod["metadata"]["uid"] != original:
                    break
                runtime.deadline(stop)
                time.sleep(0.05)
            uid = pod["metadata"]["uid"]
            # Never infer continuous creation history from a list/read.
            while uid not in owner.lineage_admissions:
                runtime.deadline(stop)
                time.sleep(0.01)
            builder = capture.get("replacement_spec")
            require(callable(builder), "eks:unfinished:4e_replacement_transport_inputs")
            spec = builder(pod, slot, stop)
            exact(spec["uid"], uid, "cluster:replacement_spec_uid")
            exact(spec["origin"]["pod_uid"], uid, "cluster:replacement_origin_uid")
            adapters = bind(
                slot, spec, request_ids=capture["request_ids"], lifecycle=capture["lifecycle"]
            )
            capture["replacement_samplers"][uid] = SamplerComposition(
                {uid: adapters["metrics"]},
                {uid: RetainedStartupRows(owner.archive.root / "raw", uid, owner.lock)},
                flush=owner.archive_barrier,
            )
            capture["replacement_adapters"][uid] = adapters
        return proof

    result = BoundActions({"kubernetes": action})
    result.fixed_action_count = len(plan["effects"])
    result.boundary = None
    result.proof = proof
    return result
