"""EKS command shell for the existing dispatcher, authorities and ProcessCalls.

This is not another lifecycle driver. Deployment supplies reopened accepted 4a
ports and real effect/read authorities. Missing collectors, 4c and 4d refuse.
No AWS transport, plan, admission or success implementation is installed here.
"""

import copy
import re
from dataclasses import asdict
from pathlib import Path

from .inf037b_archive import encode, sha
from .inf037b_capture import CaptureOwner
from .inf037b_capture_inventory import require_eks_capture_binding, wire_files
from .inf037b_command import OPERATIONS, CommandPorts, commands
from .inf037b_contract import MAX_ATTEMPTS, MAX_RESETS, SESSION_ENVELOPE_MS, TARGET_ORDER
from .inf037b_eks_campaign import CampaignCaptureScope
from .inf037b_eks_fixture import StagedCreation
from .inf037b_eks_observations import SetupObservationScope
from .inf037b_eks_probe import compose_probe
from .inf037b_eks_setup import SetupLifecycleScope
from .inf037b_integration import controller_binding
from .inf037b_lifecycle import EXIT_RESERVE_MS, ProcessCalls
from .inf037b_ports import Port
from .inf037b_resolver import SessionDeadline, exact, require


def capture_instance_schedule():
    """Fixed implementation partition (Round 335), independent of UID counts.

    One owner per live scope, including a failed partial capture. Rows whose
    remaining producer ports do not yet determine their complete wire source
    set stay unresolved; known retainers are shown but never called complete.
    """
    from .inf037b_capture_inventory import code_ref, source_inventory

    scopes = []

    def add(
        scope,
        lines,
        *,
        artifact=None,
        slots=(0, 1),
        separate_setup=False,
        unresolved=None,
        source_names=None,
        attempt="setup",
        target=None,
        resource_roles=(),
        shared=None,
    ):
        owner_id = None if artifact or shared else scope.replace(":", "_")
        names = (
            []
            if artifact or shared
            else [
                entry["name"]
                for entry in source_inventory(
                    slots=slots,
                    separate_setup=separate_setup,
                    source_names=source_names,
                    resource_roles=resource_roles,
                )["sources"]
            ]
        )
        scopes.append(
            {
                "scope": scope,
                "owner_id": owner_id,
                "status": "shared"
                if shared
                else "artifact_only"
                if artifact
                else "unresolved"
                if unresolved
                else "owner",
                "artifact_only": bool(artifact),
                "shared_with": shared,
                "v4_lines": lines,
                "slots": list(slots),
                "separate_setup": separate_setup,
                "attempt": attempt,
                "target_slot": target,
                "declared_sources": names if not unresolved else None,
                "known_sources": names,
                "reason": (
                    "Reset captured by the next attempt setup (Claude decision 7, Round 339)."
                    if shared
                    else artifact or unresolved
                ),
                "max_owners": 0 if artifact or shared else 1,
            }
        )

    add(
        "creation_readiness",
        [24, 54, 100],
        artifact="Creation authority raw receipt and pre-P file copy/hash receipts are persisted artifacts by LifecycleAuthorityPort.create / SetupCommands; no live collector transport is opened.",
    )
    add(
        "configuration_smoke_rollback",
        [24, 37],
        unresolved="Complete smoke/rollback command-to-source routing is the command-factory gap; current code has no complete live source set.",
    )
    for name in ("cold_startup", "cached_startup"):
        add(
            name,
            [41, 44],
            unresolved="Round 341 binds the cluster API ports and joins independent device report/node/producer identity. The actual independent node producer, clock mapping, lifecycle/cache transports and final capture budgets remain 4e_device_release_inputs/4e_startup_inputs; source closure stays unresolved under v4 :41/:44.",
        )
    add(
        "fitness_probe_and_signal",
        [36, 40],
        separate_setup=True,
        resource_roles=("measurement", "gateway0", "gateway1", "node0", "node1"),
    )
    add(
        "row5_controls_and_restoration",
        [24, 37, 44],
        slots=(),
        source_names=(
            "gateway0",
            "gateway1",
            "client:gateway0",
            "client:gateway1",
            "redis",
            "diagnostic",
            "rbac",
            "clocks",
        ),
    )
    add(
        "replay_and_export_observation",
        [42, 50, 100, 102],
        artifact="The source-current maximum, replay, sanitizer/materializer and Part 4 transfer consume immutable archives and persist manifests/timing receipts; they do not open another live wire owner.",
    )
    for attempt in range(1, MAX_ATTEMPTS + 1):
        add(
            f"attempt_setup:{attempt}",
            [10, 28, 58],
            attempt=attempt,
            resource_roles=("generator", "gateway0", "gateway1"),
            unresolved="Rounds 339/341 bind the parent/checkpoint, cluster authority and conditional campaign actions. Final device/native/capture transports and source definitions remain 4e_campaign_capture_inputs/4e_campaign_action_inputs; full source closure stays incomplete.",
        )
        add(
            f"attempt:{attempt}",
            [10, 28, 58],
            attempt=attempt,
            target=TARGET_ORDER[attempt - 1],
            resource_roles=("generator", "gateway0", "gateway1"),
            unresolved="All five stages share one owner; Rounds 339/341 bind sealed journals, cluster API capture and actions. Independent device/native endpoints, complete owner source definitions and byte budgets remain explicit 4e inputs.",
        )
    for reset in range(1, MAX_RESETS + 1):
        add(
            f"reset:{reset}",
            [10, 28, 58],
            slots=(),
            attempt=reset + 1,
            shared="attempt_setup_" + str(reset + 1),
        )
    for op in ("export", "cleanup"):
        add(
            op,
            [24, 59, 60, 64, 70],
            slots=(),
            unresolved="Round 339 implements 4c store manifests/acknowledgements and sealed materialized export inputs. Round 342 wires recovery/store/host/provider components. Final independent endpoints, identities, catalogue allocation authority and budgets remain 4e inputs; complete provider wire source names cannot yet be enumerated.",
        )
    for row in scopes:
        if row["scope"] == "fitness_probe_and_signal":
            row["resolved_components"] = [
                code_ref("inf037b_eks_probe.py", "compose_probe"),
                code_ref("inf037b_capture.py", "CaptureOwner.slot_lineage"),
                code_ref("inf037b_capture.py", "CaptureOwner.record_admission"),
            ]
            row["resolved_components"].append(code_ref("inf037b_resources.py", "ResourceAdapter"))
            row["resolved_components"].append(
                code_ref("inf037b_eks_cluster_runtime.py", "setup_runtime")
            )
            row["missing_interfaces"] = ["campaign_resource_bindings", "4e_part2_capture_inputs"]
        elif row["scope"] in {"export", "cleanup"}:
            row["resolved_components"] = [
                code_ref("inf037b_eks_terminal.py", "TerminalBackend"),
                code_ref("inf037b_eks_terminal.py", "TerminalReceiver"),
                code_ref("inf037b_terminal.py", "TerminalAdapters"),
                code_ref("inf037b_eks_stores.py", "RecoveryRepository"),
                code_ref("inf037b_eks_packet.py", "PacketPorts.terminal_inputs"),
                code_ref("inf037b_eks_placement.py", "ExportPlacement"),
                code_ref("inf037b_eks_execution.py", "ExecutionRuntime"),
                code_ref("inf037b_eks_provider.py", "ProviderBackend"),
            ]
            row["missing_interfaces"] = [
                "4e_execution_runtime",
                "4e_recovery_store_binding",
                "4e_export_host",
                "4e_terminal_capture_catalog",
                "4e_terminal_export_transport",
                "4e_provider_client",
                "4e_export_placement_inputs",
            ]
        elif row["scope"].startswith(("attempt:", "attempt_setup:")):
            row["resolved_components"] = [
                code_ref("inf037b_eks_campaign.py", "CampaignCaptureScope"),
                code_ref("inf037b_eks_packet.py", "CanonicalPacket.capture"),
                code_ref("inf037b_eks_packet.py", "CanonicalPacket.materialize"),
                code_ref("inf037b_eks_cluster.py", "ClusterRuntime.authority"),
                code_ref("inf037b_eks_cluster_runtime.py", "campaign_runtime"),
                code_ref("inf037b_eks_cluster_runtime.py", "campaign_actions"),
            ]
            row["missing_interfaces"] = [
                "4e_campaign_capture_inputs",
                "4e_cluster_inputs",
                "4e_campaign_action_inputs",
                "4e_replacement_transport_inputs",
                "4e_campaign_archive_inputs",
            ]
        elif row["scope"] in {"cold_startup", "cached_startup"}:
            row["resolved_components"] = [
                code_ref("inf037b_eks_setup.py", "validate_setup_inputs"),
                code_ref("inf037b_eks_setup.py", "SetupLifecycleScope"),
                code_ref("inf037b_eks_cluster.py", "ClusterRuntime.device"),
                code_ref("inf037b_eks_cluster_runtime.py", "startup"),
            ]
            row["missing_interfaces"] = [
                "4e_device_release_inputs",
                "4e_setup_lifecycle_inputs",
                "4e_startup_inputs",
            ]
    resolved = {
        row["owner_id"]: {"sources": row["declared_sources"]}
        for row in scopes
        if row["status"] == "owner"
    }
    files = whole_run_wire_files(resolved)
    missing = [
        {
            "scope": row["scope"],
            "owner_id": row["owner_id"],
            "input": row["reason"],
            "v4_lines": row["v4_lines"],
        }
        for row in scopes
        if row["status"] == "unresolved"
    ]
    return {
        "schema": "inf037b-capture-instance-schedule-v2",
        "logical_scopes": scopes,
        "max_owner_instances": sum(row["max_owners"] for row in scopes),
        "uid_generations_are_file_multiplier": False,
        "known_wire_files": files,
        "known_wire_file_count": len(files),
        "whole_run_wire_file_count": None if missing else len(files),
        "wire_file_count_expression": f"{len(files)} plus {len(missing)} unresolved owner rows"
        if missing
        else str(len(files)),
        "missing": missing,
    }


def whole_run_wire_files(instances):
    """Pure layout arithmetic; count needs no invented 4e budget values.

    Live construction separately requires both inventory and budgets. Equal
    source names in different owners always create separate pairs, even empty.
    """
    paths = []
    for instance_id, instance in instances.items():
        require(
            type(instance_id) is str and bool(re.fullmatch(r"[A-Za-z0-9_-]+", instance_id)),
            "eks:instance_id",
        )
        names = list(instance["sources"])
        require(
            all(type(name) is str and name for name in names) and len(names) == len(set(names)),
            "eks:source_names",
        )
        paths.extend(
            instance_id + "/" + path
            for files in wire_files(names).values()
            for path in files.values()
        )
    return sorted(paths)


class UnfinishedPort:
    def __init__(self, name):
        self.name = name

    def __call__(self, *args, **kwargs):
        require(False, "eks:unfinished:" + self.name)


class LifecycleAuthorityPort(Port):
    """Use accepted Port intents and Authority's request/ack binding protocol.

    Store is the reopened DurableStore in production. Provider authority must
    settle ambiguous effects; the client never retries an interrupted phase.
    """

    def __init__(self, store, authority, binding, pins, clock, driver_key):
        self.store, self.authority = store, authority
        self.binding, self.pins = copy.deepcopy((binding, pins))
        self.clock, self.driver_key = clock, driver_key
        with store.lock():
            state = store.read()
            bound = {"controller": self.binding, "pins": self.pins, "driver_key": driver_key}
            if "eks_binding" not in state:
                state["eks_binding"] = bound
                store.write(state)
            exact(state["eks_binding"], bound, "eks:original_binding")

    def deadline(self, stop, *, completed=False):
        now = self.clock()
        effective = min(self.binding["D_session_ms"], self.binding["t0_ms"] + SESSION_ENVELOPE_MS)
        require(
            type(stop) is int
            and type(now) is int
            and self.binding["t0_ms"] <= now
            and (now <= stop if completed else now < stop)
            and stop <= effective,
            "eks:deadline",
        )

    def validate_context(self, operation, stop, context):
        require(operation in OPERATIONS, "eks:operation")
        attempt = context.get("input", {}).get("attempt")
        label = operation + (":" + str(attempt) if attempt is not None else "")
        exact(context["operation_label"], label, "eks:operation_label")
        exact(context["operation_key"], self.driver_key + ":" + label, "eks:effect_key")
        exact(context["measurement_deadline_ms"], stop, "eks:original_cutoff")
        self.deadline(stop)

    def invoke(self, operation, stop, context, payload=None):
        self.validate_context(operation, stop, context)
        key = context["operation_key"]
        body = {
            "binding": self.binding,
            "pins": self.pins,
            "stop_ms": stop,
            "context": context,
            "payload": payload,
        }
        return self.effect("eks." + operation, key, body, stop)

    def effect(self, name, key, body, stop):
        self.deadline(stop)
        with self.store.lock():
            state = self.store.read()
            old = state["operations"].get(sha(encode([name, key])))
            sequence = self.intent(state, name, key, body)
            label = sha(encode([name, key]))
            cached = state["values"].get(label)
            if cached is None:
                receipt = (
                    self.settle(state, name, key)
                    if old is not None
                    else self.authority.call(name, key, sequence, body)
                )
                require(type(receipt) is dict, "eks:interrupted_unsettled")
                exact(receipt["request_key"], key, "eks:receipt_key")
                exact(receipt["body_sha256"], sha(encode(body)), "eks:receipt_body")
                exact(receipt["complete"], True, "eks:receipt_incomplete")
                self.deadline(stop, completed=True)
                state["values"][label] = copy.deepcopy(receipt)
                self.store.write(state)
                cached = receipt
        self.deadline(stop, completed=True)
        return copy.deepcopy(cached["result"])

    def inventory(self, application, stop):
        exact(
            application,
            {k: self.binding[k] for k in ("session_id", "plan_hash")},
            "eks:inventory_application",
        )
        self.deadline(stop)
        with self.store.lock():
            result = self.query(
                self.store.read(),
                "eks.inventory",
                self.binding["session_id"],
                {"binding": self.binding, "stop_ms": stop},
            )
        self.deadline(stop, completed=True)
        exact(result["application"], application, "eks:inventory_application")
        exact(result["complete"], True, "eks:inventory_incomplete")
        exact(result["settled"], True, "eks:inventory_unsettled")
        return result

    def create(self, key, stop, context, record):
        exact(key, context["operation_key"], "eks:effect_key")
        result = self.invoke("creation", stop, context)
        ids = result["instance_ids"]
        require(
            type(ids) is list
            and all(type(i) is str and i for i in ids)
            and len(set(ids)) == len(ids),
            "eks:creation_ids",
        )
        for instance in ids:
            record(instance)
        return bytes.fromhex(result["raw_hex"])


class TerminalAuthorityPort:
    """TerminalAdapters keeps dependency ordering and the verified-empty rule."""

    def __init__(self, factory):
        self.factory = factory

    def scope(self, scope):
        for key in ("session_id", "t0_ms", "group", "tokens"):
            exact(scope[key], self.factory.binding[key], "eks:terminal_scope:" + key)

    def effect(self, label, key, body, stop):
        self.scope(body["scope"])
        operation = "export" if label == "export" else "cleanup"
        exact(
            key,
            self.factory.port.driver_key + ":" + operation + ":" + label,
            "eks:terminal_effect_key",
        )
        if label in {"export", "preserve_state"}:
            self.factory.dependency("4c_recovery_stores")(stop)
            if label == "export":
                self.factory.dependency("4d_export_permission")(stop)
        port = self.factory.port
        return port.effect(
            "eks.terminal." + label,
            key,
            {"binding": self.factory.binding, "stop_ms": stop, "body": body},
            stop,
        )

    def inventory(self, category, scope, stop):
        self.scope(scope)
        port = self.factory.port
        port.deadline(stop)
        with port.store.lock():
            result = port.query(
                port.store.read(),
                "eks.terminal.inventory",
                category,
                {"binding": self.factory.binding, "scope": scope, "stop_ms": stop},
            )
        port.deadline(stop, completed=True)
        exact(result["complete"], True, "eks:terminal_inventory_incomplete")
        return result


class EKSCommandFactory:
    """Production shell called by dispatch after accepted 4a has been reopened.

    The executable deployment composition supplies these existing authorities;
    no caller-provided success defaults can complete missing slice interfaces.
    """

    def __init__(self, *, controller, authority, store, clock, config, implementations=None):
        runtimes = {"cluster_runtime", "execution_runtime"}
        self.config = copy.deepcopy({k: v for k, v in config.items() if k not in runtimes})
        for name in runtimes & config.keys():
            self.config[name] = config[name]
        self.binding = controller_binding(controller)
        self.admission_rows = copy.deepcopy(controller.journal.read())
        deadline = SessionDeadline(
            self.binding["C_ms"], self.binding["D_session_ms"], self.binding["t0_ms"]
        )
        # Exact binding used by LifecycleDriver.run; ProcessCalls owns fencing.
        driver_binding = {
            "deadline": asdict(deadline),
            "attempt_path": str(Path(config["attempts"]).resolve()),
            "exit_reserve_ms": EXIT_RESERVE_MS,
            "child_fence_protocol": "linux-bootstrap-v1",
        }
        self.port = LifecycleAuthorityPort(
            store, authority, self.binding, config["pins"], clock, sha(encode(driver_binding))
        )
        self.controller, self.clock = controller, clock
        self.implementations = dict(implementations or {})

    def dependency(self, name):
        from .inf037b_eks_cluster import PORTS, ClusterPorts
        from .inf037b_eks_execution import PORTS as EXECUTION_PORTS
        from .inf037b_eks_execution import execution_port

        if name in EXECUTION_PORTS and name not in self.implementations:
            return execution_port(self, name)

        if name in PORTS and name not in self.implementations:
            ports = ClusterPorts(self)
            return dict(
                zip(
                    PORTS,
                    (
                        ports.authority,
                        ports.setup,
                        ports.device,
                        ports.startup,
                        ports.actions,
                        ports.setup_runtime,
                        ports.campaign_runtime,
                    ),
                    strict=True,
                )
            )[name]
        if name == "4d_export_permission" and name not in self.implementations:
            from .inf037b_eks_placement import PlacementPorts

            return PlacementPorts(self).permission
        if name == "campaign_resource_windows" and name not in self.implementations:
            return self.resource_windows
        if name not in self.implementations and name in {
            "4c_packet_barrier",
            "4c_attempt_start",
            "4c_campaign_capture",
            "4c_campaign_materialize",
            "4c_terminal_export_inputs",
        }:
            from .inf037b_eks_packet import PacketPorts

            ports = PacketPorts(self)
            return {
                "4c_packet_barrier": ports.barrier,
                "4c_attempt_start": ports.attempt_start,
                "4c_campaign_capture": ports.capture,
                "4c_campaign_materialize": ports.materialize,
                "4c_terminal_export_inputs": ports.terminal_inputs,
            }[name]
        if name not in self.implementations and name in {
            "4c_export_stores",
            "4c_export_artifact_access",
            "4c_recovery_stores",
            "4c_recovery_supervisor",
        }:
            from .inf037b_eks_stores import RecoveryPorts

            ports = RecoveryPorts(self)
            return {
                "4c_export_stores": ports.export_stores,
                "4c_export_artifact_access": ports.artifact_access,
                "4c_recovery_stores": ports.recovery_stores,
                "4c_recovery_supervisor": ports.supervisor,
            }[name]
        return self.implementations.get(name, UnfinishedPort(name))

    def resource_windows(self, owner, stop, *, start=True):
        from .inf037b_resources import ResourceWindows

        bindings = self.dependency("campaign_resource_bindings")(owner, stop)
        expected = (
            {"measurement", "gateway0", "gateway1", "node0", "node1"}
            if owner.attempt == "setup"
            else {"generator", "gateway0", "gateway1"}
        )
        exact(set(bindings), expected, "eks:resource_roles")
        windows = ResourceWindows(owner, bindings, stop * 1_000_000)
        return windows.start() if start else windows

    def setup_probe(self, owner, runtime):
        return compose_probe(self, owner, runtime)

    def recovery_supervisor(self):
        from .inf037b_eks_supervisor import RecoveryBinding

        return RecoveryBinding(self)

    def run_setup_probe(self, owner, runtime, stop):
        self.port.deadline(stop)
        # Campaign collection owns the missing independent CPU/NIC emitter.
        # Do not run a nominally successful probe without that source port.
        windows = self.resource_windows(owner, stop, start=False)
        try:
            exact(
                runtime["booking"]["branch_stop_ns"], stop * 1_000_000, "eks:probe_original_cutoff"
            )
            probe = self.setup_probe(owner, runtime)
            from .inf037b_eks_probe import compose_probe_collectors

            compose_probe_collectors(
                self, owner, runtime, actions={"diagnostic": probe.run}, resources=windows
            )
            self.port.deadline(stop, completed=True)
            return probe.store.read()["single_probe"]
        finally:
            windows.close()

    def phases(self, operation, stop, context):
        require(operation != "reset", "eks:reset_is_attempt_setup")
        if operation == "packet_barrier":
            return self.dependency("4c_packet_barrier")(stop, context)
        require(operation in {"attempt_setup", "attempt", "reset"}, "eks:phase")
        return CampaignCaptureScope(self)(operation, stop, context)

    def capture_spec(self, instance_id):
        row = next(
            (
                row
                for row in capture_instance_schedule()["logical_scopes"]
                if row["owner_id"] == instance_id
            ),
            None,
        )
        require(row is not None, "eks:capture_instance_not_in_table:" + instance_id)
        require(row["status"] == "owner", "eks:unresolved:capture_sources:" + instance_id)
        instance = copy.deepcopy(self.config.get("capture_instances", {}).get(instance_id))
        require(type(instance) is dict, "eks:unfinished:capture_instance:" + instance_id)
        require_eks_capture_binding(instance["binding"], instance["sources"])
        exact(set(instance["sources"]), set(row["declared_sources"]), "eks:capture_source_set")
        exact(instance["binding"]["pins"], self.config["pins"], "eks:capture_pins")
        exact(instance["binding"]["session_id"], self.binding["session_id"], "eks:capture_session")
        return instance

    def open_capture(self, instance_id, **owner_args):
        instance = self.capture_spec(instance_id)
        from .inf037b_eks_owner_registry import AllocatedOwners

        registry = AllocatedOwners(self.port.store, self.binding)
        registry.allocate(
            instance_id,
            owner_args["root"],
            instance["binding"],
            instance["sources"],
            owner_args["store"].path,
        )
        try:
            owner = CaptureOwner(
                binding=instance["binding"], sources=instance["sources"], **owner_args
            )
        except BaseException as error:
            registry.failed(instance_id, error)
            raise
        registry.opened(instance_id)
        return owner

    def capture_catalog(self):
        from .inf037b_eks_owner_registry import AllocatedOwners

        return AllocatedOwners(self.port.store, self.binding).catalog()

    def __call__(self, config):
        exact(config, self.config, "eks:factory_config")
        setup = SetupLifecycleScope(self)
        from .inf037b_eks_terminal import TerminalBackend

        terminal = TerminalBackend(self, TerminalAuthorityPort(self))
        return CommandPorts(
            controller=self.controller,
            creation=self.staged_creation(),
            capture=SetupObservationScope(self),
            gpu=setup.gpu,
            row5_stage=setup.stage,
            row5_control=setup.control,
            inventory=terminal,
            sample=self.dependency("clock_sample"),
            phases=self.phases,
            backend=terminal,
        )

    def process_calls(self, config_path):
        return ProcessCalls(commands(config_path), self.clock)

    def staged_creation(self):
        return StagedCreation(
            self.port,
            self.config,
            self.dependency("clock_sample"),
            host_stage=self.dependency("export_host_stage_fixture"),
            host_reverify=self.dependency("export_host_reverify_fixture"),
        )
