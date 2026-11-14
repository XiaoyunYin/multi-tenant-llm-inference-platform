"""ProcessCalls command composition. Providers are explicit deployment ports.

Only the parent admits/consumes and owns LifecycleDriver. This entry point
reopens accepted 4a records and the existing stores, never runs admission again.
The deployment factory is executable, payload-pinned code, not evidence input.
"""

import argparse
import importlib
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

from .inf037b_archive import encode, strict_json
from .inf037b_durable_ports import DurableStore
from .inf037b_integration import CreationRecords, controller_binding
from .inf037b_maximum import load_maximum
from .inf037b_resolver import exact, require
from .inf037b_setup import SetupCommands
from .inf037b_terminal import TerminalAdapters

OPERATIONS = (
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


@dataclass(frozen=True)
class CommandPorts:
    controller: object
    creation: object
    capture: object
    gpu: object
    row5_stage: object
    row5_control: object
    inventory: object
    sample: object
    phases: object
    backend: object


def require_group_leader():
    require(os.name == "posix", "command:posix")
    require(os.getpgrp() == os.getpid(), "command:group_leader")


def dispatch(config, operation, context, factory):
    # Must precede factory imports/effects and installation of os._exit by
    # PreparationFork. Calling from the controller process is a wiring refusal.
    require_group_leader()
    require(operation in OPERATIONS, "command:operation")
    stop = context["measurement_deadline_ms"]
    maximum = None
    if operation in {"creation", "preparation", "resolution"}:
        require(config.get("maximum_fixture") is not None, "command:maximum_fixture_required")
        try:
            maximum = load_maximum(config["maximum_fixture"], config["pins"])
        except FileNotFoundError:
            require(False, "command:maximum_fixture_missing")
    ports = factory(config)
    require(type(ports) is CommandPorts, "command:ports")
    binding = controller_binding(ports.controller)
    ports.controller.journal.close()
    root = Path(config["directory"])
    records = CreationRecords(
        DurableStore(root / "creation", {"binding": None}, initialize=True),
        binding,
        ports.creation,
    )

    def scope():
        return records.scope(stop, config["state_storage_id"], config["state_destination"])

    if operation in {"creation", "preparation", "resolution"}:
        # Setup can be constructed before creation has produced any instances.
        # Its cleanup snapshot resolves the settled scope only when requested.
        require(callable(ports.row5_control), "command:row5_control_port")
        require(callable(ports.row5_stage), "command:row5_stage_port")
        lazy_scope = SimpleNamespace(
            session_id=binding["session_id"],
            t0_ms=binding["t0_ms"],
            descriptor=lambda: scope().descriptor(),
        )
        setup = SetupCommands(
            store=DurableStore(root / "setup", {}, initialize=True),
            binding={
                "session_id": binding["session_id"],
                "t0_ms": binding["t0_ms"],
                "pins": config["pins"],
            },
            collect=lambda op, cutoff: records.create(cutoff, context),
            capture=ports.capture,
            gpu=ports.gpu,
            row5_stage=ports.row5_stage,
            row5_control=ports.row5_control,
            inventory=ports.inventory,
            scope=lazy_scope,
            sample=ports.sample,
            maximum_fixture=maximum,
        )
        return setup(operation, stop, context)
    if operation in {"export", "cleanup"}:
        settled_scope = scope()
        terminal = TerminalAdapters(
            store=DurableStore(root / "terminal", {"binding": None}, initialize=True),
            scope=settled_scope,
            backend=ports.backend,
            capacity=ports.controller.capacity,
            clock=lambda: ports.sample()["ms"][1],
        )
        return terminal(operation, stop, context)
    return ports.phases(operation, stop, context)


def commands(config_path):
    """Supply this mapping to the existing IntegratedLifecycle/ProcessCalls."""
    return {
        op: [sys.executable, "-m", __name__, "--config", str(config_path), "--operation", op]
        for op in OPERATIONS
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--operation", choices=OPERATIONS, required=True)
    args = parser.parse_args()
    require_group_leader()
    config = strict_json(args.config.read_bytes())
    context = strict_json(sys.stdin.buffer.read())
    module, separator, name = config["factory"].partition(":")
    exact(separator, ":", "command:factory")
    factory = getattr(importlib.import_module(module), name)
    result = dispatch(config, args.operation, context, factory)
    sys.stdout.buffer.write(encode(result))


if __name__ == "__main__":
    # Factories import CommandPorts by its canonical module name.
    from .inf037b_command import main as command_main

    command_main()
