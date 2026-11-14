"""Offline 4a -> 4b composition. All creation, phase and terminal I/O is injected.

No provider or live command is configured. The creation port must durably
deduplicate its lifecycle request and expose a complete request-bound inventory.
"""

import copy
from pathlib import Path

from .inf037b_controller import utc_ms
from .inf037b_lifecycle import LifecycleDriver, ProcessCalls
from .inf037b_resolver import SessionDeadline, exact, require
from .inf037b_terminal import CleanupScope, TerminalAdapters


def controller_binding(controller):
    """Derive from replay-validated durable 4a records, never caller literals."""
    rows = controller.journal.read()

    def fact(event):
        return [r["data"] for r in rows if r["event"] == event]

    bound, origin, consumed = (fact(event) for event in ("bound", "billing_origin", "consumed"))
    require(len(bound) == len(origin) == len(consumed) == 1, "integration:consumed_records")
    plans = bound[0]
    selected = [p for p in plans if p["plan_hash"] == consumed[0]["plan_hash"]]
    require(len(selected) == 1, "integration:consumed_plan")
    plan = selected[0]
    exact(consumed[0]["session_id"], plan["session_id"], "integration:session")
    applied = [r for r in rows if r["event"] == "applied" and r["data"] is True]
    require(len(applied) == 1, "integration:applied_required")
    exact(applied[0]["index"], plans.index(plan), "integration:applied_plan")
    tokens = [r["data"]["token"] for r in rows if r["event"] == "acquire_intent"]
    require(bool(tokens) and len(tokens) == len(set(tokens)), "integration:original_tokens")
    return {
        "session_id": plan["session_id"],
        "group": plan["capacity"]["group_arn"],
        "tokens": tokens,
        "t0_ms": origin[0]["t0_ms"],
        "C_ms": utc_ms(plan["C"]),
        "D_session_ms": utc_ms(plan["D_session"]),
        "plan_hash": plan["plan_hash"],
    }


class CreationRecords:
    """Instance identities are durable before any CleanupScope is constructed.

    An interrupted create can precede its first instance. Its complete inventory
    then establishes an empty expected-ID tuple; it still owns session capacity,
    group and state resources. Unknown inventory blocks scope construction.
    """

    def __init__(self, store, binding, port):
        self.store, self.binding, self.port = store, binding, port
        with store.lock():
            state = store.read()
            if state.get("binding") is None:
                state = {"binding": binding, "intent": None, "instance_ids": []}
                store.write(state)
            exact(state["binding"], binding, "integration:original_4a_binding")

    def record(self, instance_id):
        require(type(instance_id) is str and bool(instance_id), "integration:instance_id")
        with self.store.lock():
            state = self.store.read()
            require(state["intent"] is not None, "integration:creation_intent_required")
            if instance_id not in state["instance_ids"]:
                state["instance_ids"].append(instance_id)
                self.store.write(state)

    def create(self, stop, context):
        descriptor = {"stop_ms": stop, "context": copy.deepcopy(context)}
        with self.store.lock():
            state = self.store.read()
            if state["intent"] is None:
                state["intent"] = descriptor
                self.store.write(state)
            exact(state["intent"], descriptor, "integration:creation_request")
        return self.port.create(context["operation_key"], stop, context, self.record)

    def scope(self, stop, state_storage_id, state_destination):
        with self.store.lock():
            state = self.store.read()
        if not state.get("settled"):
            # Apply precedes the lifecycle creation/readiness call. Even with
            # no local creation intent it may already own instances. Inventory
            # must settle the original 4a Apply, not infer absence from that gap.
            request = {k: self.binding[k] for k in ("session_id", "plan_hash")}
            observation = self.port.inventory(copy.deepcopy(request), stop)
            exact(observation["application"], request, "integration:creation_inventory_key")
            exact(observation["complete"], True, "integration:creation_inventory_complete")
            exact(observation["settled"], True, "integration:creation_effects_settled")
            ids = observation["instance_ids"]
            require(
                type(ids) is list
                and all(type(i) is str and i for i in ids)
                and len(ids) == len(set(ids)),
                "integration:creation_inventory_ids",
            )
            require(
                set(state["instance_ids"]) <= set(ids), "integration:creation_inventory_coverage"
            )
            with self.store.lock():
                state = self.store.read()
                for instance_id in ids:
                    if instance_id not in state["instance_ids"]:
                        state["instance_ids"].append(instance_id)
                state["settled"] = copy.deepcopy(observation)
                self.store.write(state)
        return CleanupScope(
            self.binding["session_id"],
            self.binding["group"],
            tuple(self.binding["tokens"]),
            tuple(state["instance_ids"]),
            self.binding["t0_ms"],
            state_storage_id,
            state_destination,
        )


class IntegratedLifecycle:
    """Consume/recover accepted 4a, then run the real durable lifecycle driver.

    The caller has already marked/acquired using the accepted Controller. This
    composition never creates another marker, acquisition token or Apply path.
    Export/cleanup are lazily bound after creation inventory is durable.
    """

    def __init__(
        self,
        *,
        controller,
        attempts,
        creation_store,
        terminal_store,
        creation,
        phases,
        backend,
        clock,
        state_storage_id,
        state_destination,
        commands=None,
        test_callable=False,
    ):
        self.controller, self.attempts = controller, Path(attempts)
        self.creation_store, self.terminal_store = creation_store, terminal_store
        self.creation, self.phases, self.backend, self.clock = creation, phases, backend, clock
        self.state_storage_id, self.state_destination = state_storage_id, state_destination
        require(
            (commands is not None and test_callable is False)
            or (commands is None and test_callable is True),
            "integration:commands_required_or_explicit_test_seam",
        )
        self.commands = commands
        self.driver, self.terminal, self.records = None, None, None

    def execute_command(self, operation, stop, context):
        """Dispatch inside a supplied command after reopening its injected ports.

        The command entry point reconstructs this composition on the same durable
        stores. It calls this dispatcher, never run(): only the parent consumes
        and owns the driver lease. No provider or command is configured here.
        The explicit callable test seam uses the identical dispatcher.
        """
        if self.records is None:
            binding = controller_binding(self.controller)
            # A running command must not retain the 4a writer lease: a reopened
            # parent needs those records before it can fence this command.
            self.controller.journal.close()
            self.records = CreationRecords(self.creation_store, binding, self.creation)
        if operation == "creation":
            return self.records.create(stop, context)
        if operation in {"export", "cleanup"}:
            if self.terminal is None:
                scope = self.records.scope(stop, self.state_storage_id, self.state_destination)
                self.terminal = TerminalAdapters(
                    store=self.terminal_store,
                    scope=scope,
                    backend=self.backend,
                    capacity=self.controller.capacity,
                    clock=self.clock,
                )
            return self.terminal(operation, stop, context)
        return self.phases(operation, stop, context)

    def run(self):
        status = self.controller.recover()
        if status["consumed"] is None:
            self.controller.consume()
        binding = controller_binding(self.controller)
        deadline = SessionDeadline(binding["C_ms"], binding["D_session_ms"], binding["t0_ms"])
        if self.commands is not None:
            # Admission is complete. Release its file-writer lease before a
            # command reopens those records; LifecycleDriver owns serialization
            # from here. Children only read 4a records, never consume/recover.
            self.controller.journal.close()
        # Pass ProcessCalls itself so LifecycleDriver supplies its durable
        # spawned/fenced callbacks for every phase, including terminal commands.
        execute = (
            ProcessCalls(self.commands, self.clock)
            if self.commands is not None
            else self.execute_command
        )
        self.driver = LifecycleDriver(
            deadline=deadline, clock=self.clock, execute=execute, attempts=self.attempts
        )
        return self.driver.run()
