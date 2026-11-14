"""Campaign owner/traffic binding; the lifecycle parent remains ledger writer."""

import math
import threading
import time
from concurrent.futures import ThreadPoolExecutor, wait
from pathlib import Path

from .inf037b_archive import encode, sha, strict_json
from .inf037b_campaign import OfflineCampaign, materialize_bundle, registered_offers
from .inf037b_capture import DeadlineHTTP
from .inf037b_contract import RESET_MS, TARGET_ORDER
from .inf037b_eks_cluster import join_cluster
from .inf037b_eks_collectors import ScopeWindow, compose
from .inf037b_live import REQUEST_TIMEOUT_SECONDS, NodeLifecycleAdapter, VLLMAdapter
from .inf037b_probe import NativeRequestAdapter
from .inf037b_resolver import exact, require


def bind_replacement(owner, slot, spec, *, stop_ns, pins, request_ids, lifecycle):
    """Watch admission precedes even adapter construction, on attempts/resets."""
    uid = spec["uid"]
    exact(
        getattr(owner, "lineage_admissions", {}).get(uid, {}).get("slot"),
        slot,
        "eks:replacement_uid_not_observed",
    )
    exact(spec["origin"]["pod_uid"], uid, "eks:replacement_origin")
    exact(spec["origin"]["slot"], slot, "eks:replacement_slot")

    def http(kind, options):
        return DeadlineHTTP(
            **options,
            stop_ns=stop_ns,
            retain=owner.retainer(
                kind + ":slot" + str(slot), uid=uid, process_generation=spec["process_generation"]
            ),
        )

    metrics = VLLMAdapter(
        owner.rows("metrics:slot" + str(slot)),
        http("metrics", spec["metrics_http"]),
        pod_uid=uid,
        slot=slot,
        process_generation=spec["process_generation"],
        model_sha256=pins["model"],
        runtime_sha256=pins["runtime"],
        semantics_sha256=pins["metric_semantics"],
        lifecycle=lifecycle,
    )
    native_http = http("native", spec["native_http"])
    if spec.get("native_spool"):
        from .inf037b_eks_transports import NativeSpoolHTTP

        native_http = NativeSpoolHTTP(native_http, uid)
    native = NativeRequestAdapter(
        owner.rows("native:slot" + str(slot)),
        native_http,
        origin=spec["origin"],
        manifest=spec["manifest"],
        slot=slot,
        request_ids=request_ids,
        clock_rows=owner.clock_rows,
        clock_id="node:" + spec["node"],
    )
    node = NodeLifecycleAdapter(
        owner.rows("kubernetes"),
        http("lifecycle", spec["lifecycle_http"]),
        uid,
        slot,
        lifecycle,
        clock_id="node:" + spec["node"],
        clock_boot=spec["node_boot_id"],
        spool_http=http("lifecycle", spec["spool_http"]) if "spool_http" in spec else None,
    )
    return {"metrics": metrics, "native": native, "lifecycle": node}


def traffic(*, offers, clients, arguments, stop_ns, clock=time.monotonic_ns, sleep=time.sleep):
    """The registered offered grid, bounded fanout, misses instead of retries."""
    # Each invocation owns one alternating gateway half of the registered grid.
    limit = math.ceil(10.92 * REQUEST_TIMEOUT_SECONDS / 2)
    pool = ThreadPoolExecutor(max_workers=limit)
    available = threading.BoundedSemaphore(limit)
    futures = []
    try:
        for offer in offers:
            at = offer["scheduled_ms"] * 1_000_000
            if at > clock():
                sleep((at - clock()) / 1e9)
            client = clients[offer["gateway_uid"]]
            if clock() >= stop_ns or not available.acquire(blocking=False):
                client.missed(offer)
                continue

            def dispatch(client=client, offer=offer):
                try:
                    return client.request(offer=offer, deadline_ns=stop_ns, **arguments(offer))
                finally:
                    available.release()

            futures.append(pool.submit(dispatch))
        done, pending = wait(futures, timeout=max(0, (stop_ns - clock()) / 1e9))
        require(not pending, "campaign:unsettled_traffic")
        for future in done:
            future.result()
    finally:
        pool.shutdown(wait=False, cancel_futures=True)


class ParentCampaign:
    """Parent/finalizer only: never opened as a second writer by a phase child.

    Reuses the offline bridge's allocation, semantic finish and all-slot close.
    4c must bind the aggregate archive/parent journal before live use. No new
    replacement policy or controller state machine is introduced here.
    """

    def __init__(self, root, spec):
        self.campaign = OfflineCampaign(Path(root), spec)

    def allocate(self, now, *, deadline, reserve):
        return self.campaign.start_attempt(
            now, absolute_deadline_ms=deadline, export_cleanup_ms=reserve
        )

    def finish(self, now, *, deadline, reserve):
        return self.campaign.finish_attempt(
            now, absolute_deadline_ms=deadline, export_cleanup_ms=reserve
        )

    def close(self, now, reason, specs):
        slots = self.campaign.journal.close_slots(
            now, self.campaign.journal._stop_reason() or reason
        )
        bundle = materialize_bundle(self.campaign.root, specs)
        return {"slots": slots, "materialized": bundle, "paid_ready": False}


def retained_report(root, attempt, expected_sha256):
    """Read the 4c-pinned parent-produced report without reopening its writer.

    OfflineCampaign.report() reopens AttemptController and may finish interrupted
    transitions. Only the parent/finalizer may do that; a phase child reads bytes.
    """
    raw = (Path(root) / "events" / f"attempt-{attempt:02d}.json").read_bytes()
    exact(sha(raw), expected_sha256, "campaign:sealed_report")
    return strict_json(raw)


def setup_reset(operation, attempt, sealed, stop):
    if operation != "attempt_setup" or attempt == 1:
        return None
    reset = sealed["reset"]
    exact(reset["index"], attempt - 1, "campaign:reset_identity")
    row = reset["begin_reset"]
    exact(sha(encode(row)), reset["begin_reset_sha256"], "campaign:reset_record")
    begin = row["payload"]
    exact(begin["event"], "reset_start", "campaign:reset_begin")
    require(
        begin["now_ms"] <= stop <= begin["deadline_ms"] <= begin["now_ms"] + RESET_MS,
        "campaign:reset_cutoff",
    )
    return reset


class CampaignCaptureScope:
    def __init__(self, factory):
        self.factory = factory

    def __call__(self, operation, stop, context):
        f = self.factory
        require(operation != "reset", "eks:reset_is_attempt_setup")
        f.port.validate_context(operation, stop, context)
        attempt = context["input"]["attempt"]
        require(type(attempt) is int and attempt in (1, 2, 3), "campaign:attempt")
        f.dependency("4c_attempt_start")(stop, context)
        # This must bind the parent's actual journal and continuous normalized
        # sequence checkpoint, not allocate/recover an attempt in this child.
        sealed = f.dependency("4c_campaign_capture")(operation, stop, context)
        reset = setup_reset(operation, attempt, sealed, stop)
        authority = f.dependency("4d_cluster_authority")(stop, context)
        join_cluster(authority, f, "4d_cluster_authority", context)
        checkpoint = sealed["sequence_checkpoint"]
        runtime = f.dependency("campaign_capture_runtime")(
            operation, stop, context, reset=reset, sequence_checkpoint=checkpoint
        )
        runtime_proof = join_cluster(
            runtime,
            f,
            "campaign_capture_runtime",
            {"operation": operation, "context": context, "reset": reset, "checkpoint": checkpoint},
        )
        owner = runtime["owner"]
        exact(
            {
                tuple(row["stream"]): row["next"]
                for row in runtime_proof["extra"]["entry_sequence_checkpoint"]
            },
            {tuple(row["stream"]): row["next"] for row in checkpoint},
            "campaign:sequence_checkpoint",
        )
        scope = ("attempt_setup:" if operation == "attempt_setup" else "attempt:") + str(attempt)
        instance = f.capture_spec(scope.replace(":", "_"))
        exact(owner.binding, instance["binding"], "campaign:owner_binding")
        exact(owner.sources, instance["sources"], "campaign:owner_sources")
        exact(owner.attempt, attempt, "campaign:owner_attempt")
        exact(owner.stages, [1, 2, 3, 4, 5], "campaign:same_five_stage_owner")
        exact(sealed["binding"], f.binding, "campaign:sealed_binding")
        key = context["operation_key"]
        with f.port.store.lock():
            state = f.port.store.read()
            require(
                sha(encode(["eks.campaign.capture", key])) not in state["operations"],
                "campaign:interrupted_no_retry",
            )
            f.port.intent(
                state,
                "eks.campaign.capture",
                key,
                {"sealed": sealed, "stop_ms": stop, "scope": scope},
            )

        def bind(slot, spec, **kwargs):
            return bind_replacement(
                owner, slot, spec, stop_ns=stop * 1_000_000, pins=f.config["pins"], **kwargs
            )

        actions = f.dependency("4d_campaign_actions")(
            operation, owner, stop, context, bind, reset=reset
        )
        join_cluster(
            actions,
            f,
            "4d_campaign_actions",
            {"operation": operation, "context": context, "reset": reset},
        )
        resources = f.resource_windows(owner, stop, start=False)
        source_bundle = runtime.get("collector_bundle")
        require(source_bundle is not None, "capture:unresolved:collector_bindings:" + scope)
        require("capture_start_ns" in runtime, "capture:unresolved:collector_window:" + scope)
        window = ScopeWindow(
            scope,
            runtime["capture_start_ns"],
            stop * 1000000,
            f.config["pins"]["configuration"],
            getattr(actions, "fixed_action_count", 0),
        )
        collectors = compose(
            owner,
            window,
            source_bundle,
            resources={a.source: a for a in resources.adapters.values()},
            replacements=runtime,
        )
        # Traffic actions retain their existing original-time grid. Only fixed
        # cluster effects receive the boundary reads accounted above.
        if actions:
            require(
                hasattr(actions, "fixed_action_count"),
                "capture:unresolved:fixed_action_count:" + scope,
            )
            actions.boundary = collectors.boundary
        collectors.boundary()
        periodic = collectors.periodic
        if operation == "attempt":
            spec = runtime["spec"]
            exact(spec["attempt_index"], attempt, "campaign:spec_attempt")
            exact(spec["target_slot"], TARGET_ORDER[attempt - 1], "campaign:target_order")
            offers = registered_offers(
                attempt, spec["traffic_start_ms"], stop, f.config["pins"]["configuration"]
            )
            # One action per existing client retainer, all under the same owner.
            for gateway in ("gateway0", "gateway1"):
                selected = [offer for offer in offers if offer["gateway_uid"] == gateway]
                actions["client:" + gateway] = lambda selected=selected: traffic(
                    offers=selected,
                    clients=runtime["clients"],
                    arguments=runtime["request_arguments"],
                    stop_ns=stop * 1_000_000,
                )
        try:
            descriptor = owner.run(
                periodic=periodic,
                watches=runtime["watches"],
                actions=actions,
                stop_ns=stop * 1_000_000,
            )
        finally:
            with f.port.store.lock():
                state = f.port.store.read()
                state["values"]["campaign/candidate/" + key] = {
                    "root": str(owner.root),
                    "closed": owner.closed,
                    "attempt": attempt,
                    "scope": scope,
                    "reset": reset,
                }
                f.port.store.write(state)
        # 4c joins sealed owner archives into the one aggregate, with the real
        # parent ledger and capture window. It cannot omit adverse/unused slots.
        joined = f.dependency("4c_campaign_materialize")(
            operation, descriptor, owner.root, stop, context
        )
        if operation != "attempt":
            return f.port.invoke(
                operation, stop, context, {"capture": descriptor, "joined": joined, "reset": reset}
            )
        report = retained_report(joined["root"], attempt, joined["attempt_report_sha256"])
        end = descriptor["close_start_ns"] // 1_000_000
        require(spec["traffic_start_ms"] <= end <= stop, "campaign:measurement_end")
        return {
            "measurement_end_ms": end,
            "measurement_valid": report["measurement_valid"],
            "reasons": report["validity_reasons"],
            "operational_outcomes": report["operational_outcomes"],
            "replacement_usable_by_deadline": report["stages"]["stage4"][
                "replacement_usable_by_deadline"
            ],
        }
