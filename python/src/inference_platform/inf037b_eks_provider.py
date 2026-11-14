"""Injected EKS provider behind the accepted authority protocol.

No SDK, credentials, Apply or cleanup driver is installed here. A deployment
client must return fenced, scoped readbacks, including explicit reconciliation;
an eventually consistent empty Describe response is not such a client.
"""

import copy

from .inf037b_archive import encode, sha
from .inf037b_authority import EFFECTS, FencedAuthority
from .inf037b_ports import Port
from .inf037b_resolver import exact, require


class ProviderBackend:
    def __init__(self, *, binding, pins, client, clock):
        self.binding, self.pins = copy.deepcopy((binding, pins))
        self.client, self.clock = client, clock

    def request(self, operation, key, body):
        exact(body["binding"], self.binding, "eks_provider:binding")
        if "pins" in body:
            exact(body["pins"], self.pins, "eks_provider:pins")
        require(self.clock() < body["stop_ms"], "eks_provider:deadline")
        scope = body.get("scope", body.get("body", {}).get("scope"))
        if scope is not None:
            for field in ("session_id", "t0_ms", "group", "tokens"):
                exact(scope[field], self.binding[field], "eks_provider:scope:" + field)
        return {"operation": operation, "key": key, "body": copy.deepcopy(body)}

    def observed(self, request, observation):
        # The injected client is an account-scoped authority, not a permissive
        # list API. Its exact request and known/settled evidence are mandatory.
        require(type(observation) is dict, "eks_provider:unknown")
        exact(observation["request_sha256"], sha(encode(request)), "eks_provider:request_join")
        exact(observation["binding"], self.binding, "eks_provider:read_binding")
        require(
            observation["known"] is True
            and observation["complete"] is True
            and observation["settled"] is True,
            "eks_provider:unknown",
        )
        require(self.clock() <= request["body"]["stop_ms"], "eks_provider:deadline")
        return copy.deepcopy(observation["result"])

    def effect(self, operation, key, body):
        request = self.request(operation, key, body)
        result = self.observed(request, self.client.execute(request))
        return {
            "request_key": key,
            "body_sha256": sha(encode(body)),
            "complete": True,
            "result": result,
        }

    def read(self, operation, key, body):
        request = self.request(operation, key, body)
        result = self.observed(request, self.client.read(request))
        require(type(result) is dict, "eks_provider:inventory_unknown")
        exact(result["complete"], True, "eks_provider:inventory_complete")
        if operation == "eks.inventory":
            exact(
                result["application"],
                {k: self.binding[k] for k in ("session_id", "plan_hash")},
                "eks_provider:application",
            )
            exact(result["settled"], True, "eks_provider:inventory_settled")
        else:
            exact(
                result["scope_sha256"], sha(encode(body["scope"])), "eks_provider:inventory_scope"
            )
        return result

    def reconcile(self, operation, key, body):
        request = self.request(operation, key, body)
        try:
            observation = self.client.reconcile(request)
            if not isinstance(observation, dict) or observation.get("known") is not True:
                return {"known": False, "executed": False, "result": None}
            result = self.observed(request, observation)
            require(type(observation["executed"]) is bool, "eks_provider:execution")
            executed = observation["executed"]
            if not executed:
                exact(result, None, "eks_provider:not_executed")
            return {
                "known": True,
                "executed": executed,
                "result": {
                    "request_key": key,
                    "body_sha256": sha(encode(body)),
                    "complete": True,
                    "result": result,
                }
                if executed
                else None,
            }
        except (OSError, ValueError, KeyError, TypeError):
            # Including provider outage or deadline: uncertainty is not absence.
            return {"known": False, "executed": False, "result": None}

    def authority(self, directory, identity, *, initialize=False):
        return FencedAuthority(
            directory,
            identity,
            "eks",
            effect=self.effect,
            read=self.read,
            reconcile=self.reconcile,
            initialize=initialize,
        )


class ScopedAuthority(Port):
    """A durable remote cursor separate from local lifecycle bookkeeping.

    The wire protocol and Port intent/settlement rules are unchanged. Every
    parent sequence is bound to its remote intent; restart only settles it.
    """

    def __init__(self, directory, authority, *, initialize=False, store=None):
        if store is None:
            super().__init__(directory, authority, initialize=initialize)
        else:
            self.store, self.authority = store, authority
        self.identity, self.namespace = authority.identity, authority.namespace

    def call(self, operation, key, minimum, body):
        with self.store.lock():
            state = self.store.read()
            settling = operation == "intent.settle"
            if settling:
                exact(body["retry"], False, "eks_provider:no_blind_retry")
                operation, body = body["operation"], body["body"]
            if operation not in EFFECTS:
                return self.query(state, operation, key, body)
            label = sha(encode([operation, key]))
            prior = state["operations"].get(label)
            parent = state["values"].get("parent/" + label)
            if prior is None:
                require(not settling, "eks_provider:missing_intent")
                self.intent(state, operation, key, body)
                state["values"]["parent/" + label] = minimum
                self.store.write(state)
            else:
                exact(parent, minimum, "eks_provider:parent_sequence")
                exact(prior["body"], body, "eks_provider:intent_body")
            if prior is not None or settling:
                return self.settle(state, operation, key, retry=False)
            return self.authority.call(operation, key, state["operations"][label]["sequence"], body)
