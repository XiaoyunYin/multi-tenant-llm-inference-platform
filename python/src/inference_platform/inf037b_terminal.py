"""Offline export/cleanup adapters. No provider, client, credentials or launcher.

An injected backend must provide bounded, request-key-idempotent effects and
complete scoped inventories. Capacity cancellation remains owned by accepted 4a.
"""

import copy
import time
from contextlib import contextmanager
from dataclasses import dataclass

from .inf037b_archive import encode, sha, strict_json
from .inf037b_authority import validate_cancel_receipt
from .inf037b_resolver import exact, integer, require

INVENTORIES = (
    "ingress",
    "nlb",
    "target_groups",
    "controllers",
    "instances",
    "cluster",
    "identity",
    "reservations",
    "capacity_group",
    "volumes",
    "interfaces",
    "security_groups",
    "ips",
    "logs",
    "registry",
    "endpoints",
    "nat",
    "network",
    "state_versions",
    "lockfiles",
    "state_storage",
    "bootstrap",
)


@dataclass(frozen=True)
class CleanupScope:
    session_id: str
    group: str
    tokens: tuple
    instance_ids: tuple
    t0_ms: int
    state_storage_id: str
    state_destination: str

    def descriptor(self):
        for value in (self.session_id, self.group, self.state_storage_id, self.state_destination):
            require(type(value) is str and bool(value), "terminal:scope_string")
        require(self.state_storage_id != self.state_destination, "terminal:independent_destination")
        for values in (self.tokens, self.instance_ids):
            require(
                type(values) is tuple
                and all(type(v) is str and v for v in values)
                and len(values) == len(set(values)),
                "terminal:scope_ids",
            )
        require(integer(self.t0_ms) and self.t0_ms >= 0, "terminal:t0")
        return {
            "session_id": self.session_id,
            "group": self.group,
            "tokens": list(self.tokens),
            "instance_ids": list(self.instance_ids),
            "t0_ms": self.t0_ms,
            "state_storage_id": self.state_storage_id,
            "state_destination": self.state_destination,
        }


class TerminalAdapters:
    """Serializable intent-before-effect adapter with identical-request replay.

    Store is the accepted DurableStore interface. Backend delete/export actions
    durably deduplicate full key/body/deadline requests, including lost replies;
    an ambiguous effect is retried only under that identical key. No live backend
    is provided. Inventories are never cached and always run after a cleanup
    failure. Individual actions do not imply that cleanup as a whole succeeded.
    """

    def __init__(self, *, store, scope, backend, capacity, clock):
        self.store, self.scope = store, scope.descriptor()
        self.backend, self.capacity, self.clock = backend, capacity, clock
        self.scope_hash = sha(encode(self.scope))
        with self.store.lock():
            stored = self.store.read()
            self.last_report = (
                copy.deepcopy(stored.get("last_report"))
                if stored.get("binding") == self.scope
                else None
            )

    def _time(self, stop, *, completed=False):
        now = self.clock()
        require(
            integer(now)
            and now >= self.scope["t0_ms"]
            and integer(stop)
            and (now <= stop if completed else now < stop),
            "terminal:deadline",
        )
        return now

    def _effect(self, state, request, label, body, stop, effect):
        key = request + ":" + label
        descriptor = {"body": body, "stop_ms": stop}
        old = state["steps"].get(key)
        if old is None:
            old = {"request": descriptor}
            state["steps"][key] = old
            self.store.write(state)
        exact(old["request"], descriptor, "terminal:identical_step")
        if "result" not in old:
            self._time(stop)
            value = effect(key, copy.deepcopy(body))
            self._time(stop, completed=True)
            old["result"] = copy.deepcopy(value)
            self.store.write(state)
        self._time(stop, completed=True)
        return copy.deepcopy(old["result"])

    def _backend_effect(self, state, request, label, body, stop):
        def invoke(key, payload):
            result = self.backend.effect(label, key, payload, stop)
            exact(result["request_key"], key, "terminal:effect_key")
            exact(result["body_sha256"], sha(encode(payload)), "terminal:effect_body")
            exact(result["accepted"], True, "terminal:effect_ack")
            if label in {"export", "preserve_state"}:
                exact(result["verified"], True, "terminal:export_verified")
                require(
                    type(result["manifest_sha256"]) is str
                    and len(result["manifest_sha256"]) == 64
                    and all(c in "0123456789abcdef" for c in result["manifest_sha256"]),
                    "terminal:export_manifest",
                )
                exact(
                    result["destination"],
                    self.scope["state_destination"],
                    "terminal:export_destination",
                )
            return result

        return self._effect(state, request, label, body, stop, invoke)

    def _inventory(self, category, stop):
        # The transport still receives the preserved absolute cutoff when it is
        # exhausted. It must return/refuse immediately, rather than extend it.
        result = self.backend.inventory(category, copy.deepcopy(self.scope), stop)
        self._time(stop, completed=True)
        exact(result["complete"], True, "terminal:inventory_complete")
        exact(result["scope_sha256"], self.scope_hash, "terminal:inventory_scope")
        require(type(result["resources"]) is list, "terminal:inventory_rows")
        return result["resources"]

    def _empty(self, category, stop):
        exact(self._inventory(category, stop), [], "terminal:remaining_" + category)

    def _terminated(self, stop, rows=None):
        rows = self._inventory("instances", stop) if rows is None else rows
        ids = [r["id"] for r in rows]
        require(
            len(ids) == len(set(ids)) and set(self.scope["instance_ids"]) <= set(ids),
            "terminal:instance_coverage",
        )
        require(all(r["state"] == "terminated" for r in rows), "terminal:instance_terminated")

    def _delete(self, state, request, category, stop, *, verify=None):
        self._backend_effect(state, request, "delete_" + category, {"scope": self.scope}, stop)
        for item in verify or (category,):
            self._empty(item, stop)

    def _capacity(self, state, request, stop):
        # Port methods retain the original acquisition/cancellation token, group,
        # expected IDs, fenced sequence and billing origin from accepted 4a.
        self._terminated(stop)
        for token in self.scope["tokens"]:

            def cancel(key, body, token=token):
                result = self.capacity.cancel(token, self.scope["group"])
                validate_cancel_receipt(result["reservation_ids"], result)
                exact(self.capacity.cancellation(token), result, "terminal:cancel_readback")
                ledger = self.capacity.ledger(token, self.scope["t0_ms"])
                exact(ledger["t0_ms"], self.scope["t0_ms"], "terminal:ledger_origin")
                exact(ledger["stop_ms"], result["stop_ms"], "terminal:ledger_stop")
                return {"cancellation": result, "ledger": ledger}

            self._effect(
                state,
                request,
                "capacity_" + token,
                {"token": token, "group": self.scope["group"], "t0_ms": self.scope["t0_ms"]},
                stop,
                cancel,
            )
        exact(self.capacity.members(self.scope["group"]), [], "terminal:group_members")
        self._delete(state, request, "capacity_group", stop)

    def _cleanup(self, state, request, stop):
        errors = []
        try:
            self._delete(state, request, "ingress", stop)
            self._delete(state, request, "nlb", stop, verify=("nlb", "target_groups"))
            self._delete(state, request, "controllers", stop)
            self._backend_effect(state, request, "delete_nodes", {"scope": self.scope}, stop)
            self._terminated(stop)
            self._capacity(state, request, stop)
            self._delete(state, request, "cluster", stop)
            self._delete(state, request, "identity", stop)
            # Destination is independent of state/bootstrap being removed. A
            # failed preservation never permits deletion of versions/lockfiles.
            self._backend_effect(state, request, "preserve_state", {"scope": self.scope}, stop)
            for category in (
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
            ):
                self._delete(state, request, category, stop)
        except Exception as error:
            errors.append(type(error).__name__ + ":" + str(error))
        inventories, read_times = {}, {}
        # Always visit every inventory, even after export/deletion/provider errors
        # or an expired cutoff. Unknown/failed inventory never becomes empty.
        for category in INVENTORIES:
            inventories[category] = None
            try:
                observation = self.backend.inventory(category, copy.deepcopy(self.scope), stop)
                # Keep raw rows even when completeness/scope/deadline validation
                # fails. Unknown reads remain explicit nulls, never empty lists.
                inventories[category] = copy.deepcopy(observation.get("resources"))
                self._time(stop, completed=True)
                exact(observation["complete"], True, "terminal:inventory_complete")
                exact(observation["scope_sha256"], self.scope_hash, "terminal:inventory_scope")
                rows = observation["resources"]
                require(type(rows) is list, "terminal:inventory_rows")
                inventories[category] = rows
                if category == "instances":
                    self._terminated(stop, rows)
                elif category == "reservations":
                    require(
                        all(r["state"] == "cancelled" for r in rows), "terminal:reservation_active"
                    )
                else:
                    exact(rows, [], "terminal:remaining_" + category)
            except Exception as error:
                errors.append(category + ":" + str(error))
            finally:
                read_times[category] = self.clock()
        self.last_report = {
            "request_key": request,
            "inventories": inventories,
            "read_ms": read_times,
            "errors": errors,
            "paid_ready": False,
        }
        state["last_report"] = copy.deepcopy(self.last_report)
        self.store.write(state)
        require(not errors, "terminal:cleanup_unverified:" + ";".join(errors))
        return True

    def __call__(self, operation, stop_ms, context):
        require(operation in {"export", "cleanup"}, "terminal:operation")
        require(
            type(context) is dict
            and type(context.get("operation_key")) is str
            and context["operation_key"].endswith(":" + operation),
            "terminal:request_key",
        )
        exact(context["operation_label"], operation, "terminal:operation_label")
        exact(context["measurement_deadline_ms"], stop_ms, "terminal:cutoff")
        request = context["operation_key"]
        with self.store.lock():
            state = self.store.read()
            if state.get("binding") is None:
                state.update(binding=self.scope, requests={}, steps={})
                self.store.write(state)
            exact(state["binding"], self.scope, "terminal:scope_binding")
            descriptor = {"context": copy.deepcopy(context), "stop_ms": stop_ms}
            descriptor["request_key"] = request
            if operation not in state["requests"]:
                state["requests"][operation] = descriptor
                self.store.write(state)
            exact(state["requests"][operation], descriptor, "terminal:identical_request")
            if operation == "export":
                self._backend_effect(state, request, "export", {"scope": self.scope}, stop_ms)
                return True
            return self._cleanup(state, request, stop_ms)


def _snapshot(data):
    require(type(data) is bytes, "rehearsal:snapshot_bytes")
    state = strict_json(data)
    exact(state["schema"], "inf037b-cleanup-snapshot-v1", "rehearsal:schema")
    descriptor = state["scope"]
    scope = CleanupScope(
        **{
            **descriptor,
            "tokens": tuple(descriptor["tokens"]),
            "instance_ids": tuple(descriptor["instance_ids"]),
        }
    )
    exact(scope.descriptor(), descriptor, "rehearsal:scope")
    require(
        integer(state["captured_ms"])
        and integer(state["stop_ms"])
        and scope.t0_ms <= state["captured_ms"] < state["stop_ms"],
        "rehearsal:time",
    )
    exact(set(state["inventories"]), set(INVENTORIES), "rehearsal:categories")
    for observation in [*state["inventories"].values(), state["capacity"]]:
        interval = observation["read_interval_ms"]
        require(
            type(interval) is list
            and len(interval) == 2
            and all(integer(value) for value in interval)
            and scope.t0_ms <= interval[0] <= interval[1] <= state["captured_ms"],
            "rehearsal:read_interval",
        )
    for category, observation in state["inventories"].items():
        exact(observation["complete"], True, "rehearsal:complete")
        exact(observation["scope_sha256"], sha(encode(descriptor)), "rehearsal:inventory_scope")
        rows = observation["resources"]
        require(type(rows) is list, "rehearsal:rows")
        ids = [r["id"] for r in rows]
        require(
            all(type(i) is str and i for i in ids) and len(ids) == len(set(ids)),
            "rehearsal:resource_ids",
        )
        if category == "instances":
            require(set(scope.instance_ids) <= set(ids), "rehearsal:instance_coverage")
    capacity = state["capacity"]
    exact(capacity["complete"], True, "rehearsal:capacity_complete")
    exact(capacity["scope_sha256"], sha(encode(descriptor)), "rehearsal:capacity_scope")
    exact(set(capacity["tokens"]), set(scope.tokens), "rehearsal:original_tokens")
    require(all(type(ids) is list for ids in capacity["tokens"].values()), "rehearsal:token_ids")
    ids = [i for values in capacity["tokens"].values() for i in values]
    require(len(ids) == len(set(ids)), "rehearsal:reservation_ownership")
    reservations = state["inventories"]["reservations"]["resources"]
    exact(set(ids), {r["id"] for r in reservations}, "rehearsal:reservation_coverage")
    require(
        type(capacity["members"]) is list
        and len(capacity["members"]) == len(set(capacity["members"]))
        and set(capacity["members"]) <= set(ids),
        "rehearsal:group_members",
    )
    return state, scope


class SnapshotProducer:
    """Read only the injected inventory port; never receives a capacity writer.

    inventory(category, scope, stop) returns the terminal observation contract.
    capacity_inventory(scope, stop) returns complete/scope_sha256, original-token
    to reservation-ID lists, and authoritative group members. Reads must be
    bounded by stop and describe the same scoped world; unknown data refuses.
    """

    def __init__(self, inventory, clock):
        self.inventory, self.clock = inventory, clock

    def produce(self, scope, stop):
        descriptor = scope.descriptor()
        observations = {}
        previous = scope.t0_ms

        def checked_read(read):
            nonlocal previous
            before = self.clock()
            require(integer(before) and previous <= before < stop, "rehearsal:read_start")
            value = copy.deepcopy(read())
            after = self.clock()
            require(integer(after) and before <= after < stop, "rehearsal:read_end")
            previous = after
            return {**value, "read_interval_ms": [before, after]}

        for category in INVENTORIES:
            observations[category] = checked_read(
                lambda category=category: self.inventory.inventory(
                    category, copy.deepcopy(descriptor), stop
                )
            )
        capacity = checked_read(
            lambda: self.inventory.capacity_inventory(copy.deepcopy(descriptor), stop)
        )
        data = encode(
            {
                "schema": "inf037b-cleanup-snapshot-v1",
                "scope": descriptor,
                "inventories": observations,
                "capacity": capacity,
                "captured_ms": self.clock(),
                "stop_ms": stop,
            }
        )
        _snapshot(data)
        return data


class SnapshotBackend:
    """Deletion model over a private decode of immutable snapshot bytes."""

    def __init__(self, snapshot):
        self.snapshot = snapshot
        state, scope = _snapshot(snapshot)
        self.scope = scope.descriptor()
        self.resources = {k: copy.deepcopy(v["resources"]) for k, v in state["inventories"].items()}
        self.members = list(state["capacity"]["members"])
        self.requests, self.actions = {}, []

    def effect(self, label, key, body, stop):
        exact(body, {"scope": self.scope}, "rehearsal:effect_scope")
        request = {"label": label, "body": body, "stop_ms": stop}
        if key in self.requests:
            old, result = self.requests[key]
            exact(request, old, "rehearsal:identical_effect")
            return copy.deepcopy(result)
        self.actions.append(label)
        if label == "delete_nodes":
            for row in self.resources["instances"]:
                row["state"] = "terminated"
        elif label.startswith("delete_"):
            category = label.removeprefix("delete_")
            require(category in INVENTORIES, "rehearsal:delete_category")
            if category == "capacity_group":
                exact(self.members, [], "rehearsal:empty_group")
            self.resources[category] = []
            if category == "nlb":
                self.resources["target_groups"] = []
        else:
            require(label in {"export", "preserve_state"}, "rehearsal:effect")
        result = {"accepted": True, "request_key": key, "body_sha256": sha(encode(body))}
        if label in {"export", "preserve_state"}:
            result.update(
                verified=True,
                manifest_sha256=sha(encode(self.resources)),
                destination=self.scope["state_destination"],
            )
        self.requests[key] = (copy.deepcopy(request), copy.deepcopy(result))
        return result

    def inventory(self, category, scope, stop):
        exact(scope, self.scope, "rehearsal:inventory_scope")
        return {
            "complete": True,
            "scope_sha256": sha(encode(scope)),
            "resources": copy.deepcopy(self.resources[category]),
        }


class SnapshotCapacity:
    """Model cancellation only; contains no accepted/live capacity port."""

    def __init__(self, backend):
        require(type(backend) is SnapshotBackend, "rehearsal:model_backend")
        self.backend = backend
        self.state, _ = _snapshot(backend.snapshot)
        self.receipts = {}

    def cancel(self, token, group):
        exact(group, self.state["scope"]["group"], "rehearsal:group")
        require(token in self.state["capacity"]["tokens"], "rehearsal:token")
        if token not in self.receipts:
            ids = self.state["capacity"]["tokens"][token]
            for row in self.backend.resources["reservations"]:
                if row["id"] in ids:
                    row["state"] = "cancelled"
            self.backend.members = [i for i in self.backend.members if i not in ids]
            self.backend.actions.append("cancel:" + token)
            self.receipts[token] = {
                "verified": True,
                "complete": True,
                "reservation_ids": list(ids),
                "states": {i: "cancelled" for i in ids},
                "stop_ms": self.state["captured_ms"],
            }
        return copy.deepcopy(self.receipts[token])

    def cancellation(self, token):
        return copy.deepcopy(self.receipts.get(token))

    def ledger(self, token, t0):
        stop = self.receipts[token]["stop_ms"]
        return {
            "t0_ms": t0,
            "stop_ms": stop,
            "billed_ms": stop - t0,
            "cost_micros": 0,
            "model_only": True,
        }

    def members(self, group):
        exact(group, self.state["scope"]["group"], "rehearsal:group")
        return list(self.backend.members)


class _RehearsalStore:
    def __init__(self):
        self.state = {"binding": None}

    @contextmanager
    def lock(self):
        yield

    def read(self):
        return copy.deepcopy(self.state)

    def write(self, state):
        self.state = copy.deepcopy(state)


def rehearse(snapshot, *, backend=None, capacity=None):
    """Run the actual terminal adapter on exact model types, never live ports.

    Optional models are a test seam. Subclasses and arbitrary duck-typed/live
    adapters refuse before any call. Only model wall overhead is observed;
    model ledger zero cost is not a price or a live cleanup allowance.
    """
    state, scope = _snapshot(snapshot)
    original = sha(snapshot)
    if backend is None:
        backend = SnapshotBackend(snapshot)
    require(type(backend) is SnapshotBackend, "rehearsal:model_backend")
    exact(backend.snapshot, snapshot, "rehearsal:original_snapshot")
    require(not backend.requests, "rehearsal:fresh_model")
    if capacity is None:
        capacity = SnapshotCapacity(backend)
    require(type(capacity) is SnapshotCapacity, "rehearsal:model_capacity")
    require(
        capacity.backend is backend and not capacity.receipts, "rehearsal:capacity_model_binding"
    )
    adapter = TerminalAdapters(
        store=_RehearsalStore(),
        scope=scope,
        backend=backend,
        capacity=capacity,
        clock=lambda: state["captured_ms"],
    )
    start = time.monotonic_ns()
    for operation in ("export", "cleanup"):
        adapter(
            operation,
            state["stop_ms"],
            {
                "operation_key": original + ":" + operation,
                "operation_label": operation,
                "measurement_deadline_ms": state["stop_ms"],
            },
        )
    exact(sha(snapshot), original, "rehearsal:snapshot_unchanged")
    return {
        "snapshot_sha256": original,
        "snapshot_unchanged": True,
        "wall_ms": (time.monotonic_ns() - start) / 1_000_000,
        "actions": list(backend.actions),
        "report": copy.deepcopy(adapter.last_report),
        "model_only": True,
        "paid_ready": False,
    }
