"""Durable serialized effect authority behind the injectable v4 byte transport.

The effect/read/reconcile callbacks supply bounded provider I/O. Reconcile must
return an explicit known effect/no-effect receipt; a missing provider row is
unknown. No provider, credentials, network listener or paid CLI is installed.
"""

import copy
import re

from .inf037b_archive import encode, sha, strict_json
from .inf037b_durable_ports import DurableStore
from .inf037b_resolver import exact, integer, require

OPERATIONS = {
    "gate": {"application.apply", "application.lookup"},
    "capacity": {"odcr.acquire", "odcr.lookup", "odcr.add", "odcr.members", "odcr.cancel"},
    "backstop": {"backstop.arm", "backstop.lookup"},
}
EFFECTS = {"application.apply", "odcr.acquire", "odcr.add", "odcr.cancel", "backstop.arm"}

# Existing protocol, new executor namespace. Capacity cancellation stays with
# accepted 4a; it is deliberately absent from this provider executor.
EKS_EFFECTS = {
    "eks.creation",
    "eks.creation.allocate",
    "eks.creation.ready",
    "eks.terminal.commit_export",
    "eks.terminal.preserve_state",
    "eks.terminal.delete_nodes",
} | {
    "eks.terminal.delete_" + category
    for category in (
        "ingress",
        "nlb",
        "controllers",
        "capacity_group",
        "cluster",
        "identity",
        "registry",
        "logs",
        "volumes",
        "interfaces",
        "security_groups",
        "ips",
        "endpoints",
        "nat",
        "network",
        "state_versions",
        "lockfiles",
        "state_storage",
        "bootstrap",
    )
}
OPERATIONS["eks"] = EKS_EFFECTS | {"eks.inventory", "eks.terminal.inventory"}
EFFECTS |= EKS_EFFECTS
OPERATIONS["eks_host"] = {"eks.host.stage", "eks.host.reverify", "eks.host.replay_export"}
EFFECTS |= {"eks.host.stage", "eks.host.replay_export"}


def validate_cancel_receipt(ids, result):
    """The provider and client use the same terminal cancellation predicate."""
    exact(result["verified"], True, "ports:cancel_verified")
    exact(result["complete"], True, "ports:cancel_complete")
    returned = result["reservation_ids"]
    require(
        type(returned) is list and all(type(i) is str and i for i in returned),
        "ports:cancel_ids",
    )
    exact(len(returned), len(set(returned)), "ports:cancel_duplicates")
    require(set(ids) <= set(returned), "ports:cancel_expected_ids")
    exact(result["states"], dict.fromkeys(returned, "cancelled"), "ports:cancel_states")
    require(integer(result["stop_ms"]) and result["stop_ms"] >= 0, "ports:cancel_time")


class FencedAuthority:
    def __init__(
        self, directory, identity, namespace, *, effect, read, reconcile, initialize=False
    ):
        require(namespace in OPERATIONS, "authority:namespace")
        self.store = DurableStore(
            directory, {"watermark": 0, "pending": None, "completed": {}}, initialize=initialize
        )
        self.identity, self.namespace = identity, namespace
        self.effect, self.read, self.reconcile = effect, read, reconcile

    def _complete(self, state, pending, result, *, executed=True):
        if pending["operation"] == "odcr.cancel" and executed:
            try:
                validate_cancel_receipt(pending["body"]["expected_ids"], result)
            except (ValueError, TypeError, KeyError):
                # The effect may have stopped billing, but an invalid read-back
                # cannot advance the fence. Reconcile the same pending intent.
                return False
        state["completed"][pending["operation_key"]] = dict(
            pending, result=copy.deepcopy(result), executed=executed
        )
        state["watermark"] = pending["sequence"]
        state["pending"] = None
        self.store.write(state)
        return True

    def _recover(self, state, retry=None):
        pending = state["pending"]
        if pending is None:
            return True
        receipt = self.reconcile(
            pending["operation"], pending["key"], copy.deepcopy(pending["body"])
        )
        exact(set(receipt), {"known", "executed", "result"}, "authority:reconciliation_shape")
        if receipt["known"] is not True:
            return False
        require(type(receipt["executed"]) is bool, "authority:reconciliation_execution")
        if receipt["executed"]:
            return self._complete(state, pending, receipt["result"])
        else:
            exact(receipt["result"], None, "authority:not_executed_result")
            # Cancellation is always safe to finish, even when an older
            # completed intent is queried before its own retry arrives.
            if pending["operation"] == "odcr.cancel" or (
                retry == pending and pending["operation"] != "application.apply"
            ):
                result = self.effect(
                    pending["operation"], pending["key"], copy.deepcopy(pending["body"])
                )
                return self._complete(state, pending, result)
            else:
                self._complete(state, pending, None, executed=False)
        return True

    def _query(self, state, operation, key, body):
        # This ledger is the application authority; an external lagging read
        # cannot erase a completed Apply. No effect is inferred from an intent.
        if operation == "application.lookup":
            label = sha(encode(["application.apply", key]))
            completed = state["completed"].get(label)
            if completed is not None:
                return copy.deepcopy(completed["result"])
        result = self.read(operation, key, body)
        if operation == "odcr.lookup":
            acquisition = state["completed"].get(sha(encode(["odcr.acquire", key])))
            cancellation = state["completed"].get(sha(encode(["odcr.cancel", key])))
            if cancellation is not None and cancellation["executed"] and result is None:
                # A confirmed cancellation survives omission from the provider list.
                known = acquisition["result"] if acquisition is not None else None
                return None if known is None else dict(known, state="cancelled")
            if acquisition is not None:
                known = acquisition["result"]
                if known is None:
                    exact(result, None, "authority:refused_token")
                else:
                    require(type(result) is dict, "authority:acquired_token_present")
                    exact(
                        result.get("reservation_id"),
                        known["reservation_id"],
                        "authority:token_identity",
                    )
            if cancellation is not None and result is not None:
                exact(result.get("state"), "cancelled", "authority:cancelled_token")
        return result

    def __call__(self, raw, timeout_ms):
        request = strict_json(raw)
        exact(
            set(request),
            {
                "schema",
                "authority_id",
                "namespace",
                "operation",
                "key",
                "minimum_sequence",
                "nonce",
                "body",
            },
            "authority:request_keys",
        )
        exact(request["schema"], "inf037b-authority-v1", "authority:schema")
        exact(request["authority_id"], self.identity, "authority:identity")
        exact(request["namespace"], self.namespace, "authority:binding")
        require(
            request["operation"] in OPERATIONS[self.namespace] | {"intent.settle"},
            "authority:operation",
        )
        require(type(request["key"]) is str and bool(request["key"]), "authority:key")
        require(
            type(request["nonce"]) is str and re.fullmatch(r"[0-9a-f]{32}", request["nonce"]),
            "authority:nonce",
        )
        minimum = request["minimum_sequence"]
        require(integer(minimum) and minimum >= 0, "authority:sequence")
        require(integer(timeout_ms) and 0 < timeout_ms <= 10_000, "authority:timeout")
        operation, key, body = (request[k] for k in ("operation", "key", "body"))
        with self.store.lock():
            state = self.store.read()
            status, result = "ambiguous", None
            settling = operation == "intent.settle"
            retry = False
            if settling:
                exact(set(body), {"operation", "body", "retry"}, "authority:settlement_shape")
                retry = body["retry"]
                require(type(retry) is bool, "authority:settlement_retry")
                operation, body = body["operation"], body["body"]
                require(
                    operation in EFFECTS & OPERATIONS[self.namespace], "authority:settlement_effect"
                )
                # Only cancel may be replayed during a lookup. All other absent
                # effects are abandoned; Apply never runs from a read/reconcile.
                require(not retry or operation == "odcr.cancel", "authority:settlement_cancel_only")
                require(operation != "odcr.cancel" or retry, "authority:settlement_cancel_retry")
            effect_request = operation in EFFECTS
            label = sha(encode([operation, key]))
            pending = {
                "operation_key": label,
                "operation": operation,
                "key": key,
                "body": body,
                "sequence": minimum,
            }
            resume = pending if effect_request and (not settling or retry) else None
            if self._recover(state, resume):
                if effect_request:
                    previous = state["completed"].get(label)
                    if previous is not None:
                        exact(previous["body"], body, "authority:idempotent_binding")
                        exact(previous["sequence"], minimum, "authority:idempotent_sequence")
                        result = previous["result"]
                        status = "confirmed"
                    else:
                        exact(minimum, state["watermark"] + 1, "authority:next_sequence")
                        state["pending"] = copy.deepcopy(pending)
                        self.store.write(state)
                        if settling and not retry:
                            self._complete(state, pending, None, executed=False)
                        else:
                            result = self.effect(operation, key, copy.deepcopy(body))
                            if not self._complete(state, pending, result):
                                result = None
                        if state["pending"] is None:
                            status = "confirmed"
                elif state["watermark"] >= minimum:
                    result = self._query(state, operation, key, body)
                    status = "confirmed"
            return encode(
                {
                    "request_sha256": sha(raw),
                    "authority_id": self.identity,
                    "namespace": self.namespace,
                    "status": status,
                    "complete": status == "confirmed",
                    "settled_sequence": state["watermark"],
                    "proof_id": sha(encode(state)),
                    "result": result,
                    "executed": state["completed"].get(label, {}).get("executed"),
                }
            )
