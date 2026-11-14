"""Offline real-process composition fixture; persistent synthetic provider only."""

import argparse
import copy
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import test_inf037b_controller as legacy
from inf037b_ports_support import Journal, Responses, Rig
from test_inf037b_terminal import Backend

from inference_platform.inf037b_archive import IntegrityError, inspect_segment
from inference_platform.inf037b_attempts import AttemptController
from inference_platform.inf037b_durable_ports import DurableStore
from inference_platform.inf037b_integration import IntegratedLifecycle
from inference_platform.inf037b_lifecycle import LifecycleJournal, group_members
from inference_platform.inf037b_terminal import CleanupScope


class PersistentResponses(Responses):
    def __init__(self, world, root):
        super().__init__(world, root)
        self.provider = DurableStore(root / "provider", {}, initialize=True)
        with self.provider.lock():
            state = self.provider.read()
        if state:
            self.world.now, self.world.trace = state["now"], state["trace"]
            for name in ("gate", "capacity", "backstop"):
                vars(getattr(self, name)).update(state[name])
            self.application_inputs = state["application_inputs"]

    def save(self):
        state = {
            name: {k: v for k, v in vars(getattr(self, name)).items() if k != "world"}
            for name in ("gate", "capacity", "backstop")
        }
        state.update(
            now=self.world.now, trace=self.world.trace, application_inputs=self.application_inputs
        )
        with self.provider.lock():
            self.provider.write(state)

    def backend(self, operation, key, body):
        result = super().backend(operation, key, body)
        self.save()
        return result


class PersistentRig(Rig):
    def __init__(self, root):
        self.root = root
        root.mkdir(exist_ok=True)
        self.world = legacy.World()
        self.responses = PersistentResponses(self.world, root)
        self.plans = legacy.plans()
        self.journal = Journal(root / "journal", self.world)
        self.journal.initialized = (root / "journal").exists()
        self.gate = None
        self.ports(initialize=True)

    def close(self):
        if hasattr(self, "journal"):
            self.journal.close()


class PersistentBackend(Backend):
    def __init__(self, rig, root):
        self.rig = rig
        scope = CleanupScope(
            rig.plans[0].session_id,
            rig.plans[0].capacity.group_arn,
            (),
            (),
            rig.world.now,
            "state-source",
            "independent-export",
        )
        super().__init__(scope)
        self.store = DurableStore(root / "provider-backend", {}, initialize=True)
        with self.store.lock():
            state = self.store.read()
        if state:
            for name in ("resources", "requests", "executions", "member_checks"):
                setattr(self, name, state[name])
        self.creation_calls = state.get("creation_calls", [])
        self.fence_observations = state.get("fence_observations", [])
        self.root = root
        members = rig.capacity.members

        def checked_members(group):
            result = members(group)
            self.member_checks.append(result)
            self.save()
            return result

        rig.capacity.members = checked_members

    def save(self):
        with self.store.lock():
            self.store.write(
                {
                    k: getattr(self, k)
                    for k in (
                        "resources",
                        "requests",
                        "executions",
                        "member_checks",
                        "creation_calls",
                        "fence_observations",
                    )
                }
            )

    def effect(self, *args):
        marker = self.root / "acting-child.json"
        if marker.exists():
            identity = json.loads(marker.read_text())
            alive = bool(group_members(identity["group"]))
            self.fence_observations.append({"effect": args[0], "child_executable": alive})
            assert not alive, "terminal effect overlapped old composed child"
        result = super().effect(*args)
        self.save()
        return result

    def inventory(self, category, scope, stop):
        result = super().inventory(category, scope, stop)
        if category == "reservations":
            result["resources"] = [
                {"id": r["reservation_id"], "state": r["state"]}
                for r in self.rig.responses.capacity.results.values()
                if r
            ]
        return result


class Creation:
    def __init__(self, backend, scenario):
        self.backend, self.scenario = backend, scenario

    def create(self, key, stop, context, record):
        self.backend.creation_calls.append(
            {"key": key, "stop": stop, "context": copy.deepcopy(context)}
        )
        self.backend.save()
        if self.scenario == "before_instance":
            raise OSError("creation interrupted before first instance")
        self.backend.resources["instances"] = [
            {"id": "i-created-1", "state": "running"},
            {"id": "i-created-2", "state": "running"},
        ]
        self.backend.save()
        if self.scenario == "before_record":
            raise OSError("creation lost reply before identity receipt")
        for row in self.backend.resources["instances"]:
            record(row["id"])
        return True

    def inventory(self, application, stop):
        return {
            "application": application,
            "complete": True,
            "settled": True,
            "instance_ids": [r["id"] for r in self.backend.resources["instances"]],
        }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--cut", type=int)
    parser.add_argument("--delay", type=int, default=0)
    parser.add_argument("--restart-delay", type=int, default=0)
    parser.add_argument("--scenario", default="normal")
    parser.add_argument("--processes", action="store_true")
    parser.add_argument("--command")
    args = parser.parse_args()
    root = args.root
    root.mkdir(exist_ok=True)
    rig = PersistentRig(root / "ports")
    controller = rig.open()
    if args.command:
        pass  # A child reopens ports; only the parent owns admission/recovery.
    elif not controller.rows or controller._get("billing_origin") is None:
        controller.mark()
        if args.scenario == "first_partial":
            rig.responses.capacity.outcomes = ["partial", "ok"]
        controller.acquire()
        if args.scenario == "first_partial":
            controller.acquire()
        rig.world.now += args.delay
        rig.responses.save()
    else:
        rig.world.now += args.restart_delay
        rig.responses.save()
    backend = PersistentBackend(rig, root)
    if (
        args.scenario == "apply_before_creation"
        and not backend.creation_calls
        and not backend.executions
    ):
        backend.resources["instances"] = [{"id": "i-from-apply", "state": "running"}]
        backend.save()
    cuts = []

    def point(kind, event, key=None):
        cuts.append({"kind": kind, "event": event, "key": key})
        if args.cut == len(cuts):
            os.kill(os.getpid(), signal.SIGKILL)

    append, attempt_write, store_write = (
        LifecycleJournal.append,
        AttemptController._write,
        DurableStore.write,
    )

    def lifecycle_write(self, event, *a, **kw):
        append(self, event, *a, **kw)
        if event == "call_start":
            point("lifecycle", event, kw["key"])

    def attempt_start(self, event, *a, **kw):
        attempt_write(self, event, *a, **kw)
        if event in {"attempt_start", "reset_start", "traffic_start"}:
            point("attempt", event)

    def creation_write(self, state):
        store_write(self, state)
        if self.path.name == "creation-records":
            point("creation", "record", list(state.get("instance_ids", [])))

    acknowledged = rig.journal.acknowledged

    def controller_write(row):
        acknowledged(row)
        if row["event"] in {"consume_intent", "consumed", "applied"}:
            point("controller", row["event"], row["index"])
        if row["event"] == "applied" and args.scenario == "apply_before_creation":
            os.kill(os.getpid(), signal.SIGKILL)

    rig.journal.acknowledged = controller_write

    LifecycleJournal.append, AttemptController._write, DurableStore.write = (
        lifecycle_write,
        attempt_start,
        creation_write,
    )

    def phases(operation, stop, context):
        if args.command and args.scenario == "acting_child" and operation == "preparation":
            grandchild = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
            marker = root / "acting-child.json"
            temporary = marker.with_suffix(".tmp")
            temporary.write_text(
                json.dumps(
                    {
                        "pid": os.getpid(),
                        "grandchild": grandchild.pid,
                        "group": os.getpgrp(),
                    }
                )
            )
            temporary.replace(marker)
            while True:
                time.sleep(0.01)
        rig.world.now += 10
        rig.responses.save()
        if operation == "attempt":
            return {
                "measurement_valid": True,
                "reasons": [],
                "operational_outcomes": [],
                "replacement_usable_by_deadline": True,
                "measurement_end_ms": rig.world.now,
            }
        return True

    def clock():
        if args.processes:
            with rig.responses.provider.lock():
                current = rig.responses.provider.read()
            rig.world.now, rig.world.trace = current["now"], current["trace"]
        return rig.world.clock()

    operations = (
        "creation",
        "preparation",
        "resolution",
        "packet_barrier",
        "attempt_setup",
        "attempt",
        "reset",
        "export",
        "cleanup",
    )
    commands = (
        {
            operation: [
                sys.executable,
                str(Path(__file__).resolve()),
                "--root",
                str(root),
                "--scenario",
                args.scenario,
                "--command",
                operation,
            ]
            for operation in operations
        }
        if args.processes
        else None
    )
    integration = IntegratedLifecycle(
        controller=controller,
        attempts=root / "attempts.jsonl",
        creation_store=DurableStore(root / "creation-records", {"binding": None}, initialize=True),
        terminal_store=DurableStore(root / "terminal", {"binding": None}, initialize=True),
        creation=Creation(backend, args.scenario),
        phases=phases,
        backend=backend,
        clock=clock,
        state_storage_id="state-source",
        state_destination="independent-export",
        commands=commands,
        test_callable=commands is None,
    )
    if args.command:
        context = json.load(sys.stdin)
        result = integration.execute_command(
            args.command, context["measurement_deadline_ms"], context
        )
        print(json.dumps(result))
        rig.close()
        return
    try:
        result = integration.run()
    except IntegrityError as error:
        result = {"integration_refusal": str(error), "status": controller.status()}
    if args.processes:
        # Commands own their injected adapters; read their durable external
        # synthetic state afresh instead of inspecting stale parent objects.
        rig.close()
        rig = PersistentRig(root / "ports")
        controller = rig.open()
        backend = PersistentBackend(rig, root)
    rows = (
        inspect_segment(root / "lifecycle.jsonl")[1] if (root / "lifecycle.jsonl").exists() else []
    )
    print(
        json.dumps(
            {
                "result": result,
                "cuts": cuts,
                "controller_rows": controller.journal.read(),
                "lifecycle": rows,
                "attempts": inspect_segment(root / "attempts.jsonl")[1]
                if (root / "attempts.jsonl").exists()
                else [],
                "creation": integration.creation_store.read(),
                "terminal": integration.terminal_store.read(),
                "provider_trace": rig.world.trace,
                "executions": backend.executions,
                "creation_calls": backend.creation_calls,
                "fence_observations": backend.fence_observations,
            }
        )
    )
    rig.close()


if __name__ == "__main__":
    main()
