"""Recovery/export composition of accepted ports; final deployment inputs are 4e.

This installs neither a provider SDK nor a second effect or HTTP protocol.
Remote host work uses Authority/ScopedAuthority; a host path is never used as
a controller-local fallback. Missing endpoints, mounted stores and account
identities refuse individually. Portable tests establish joins, not durability.
"""

import copy
import threading
from pathlib import Path

from .inf037b_archive import durable_write, encode, file_facts, sha, strict_json
from .inf037b_eks_fixture import fixture_inventory
from .inf037b_eks_provider import ScopedAuthority
from .inf037b_eks_stores import ArtifactHTTPAccess, RecoveryRepository, validate_binding
from .inf037b_resolver import SessionDeadline, exact, require
from .inf037b_resources import validate_resource_binding
from .inf037b_transfer import S3ArchiveStore, SocketArchiveTransfer

PORTS = {
    "4d_recovery_store_runtime",
    "4d_independent_recovery",
    "export_host_replay_export",
    "terminal_export_transport",
    "4d_campaign_archive_inputs",
    "4d_terminal_capture_inventory",
    "export_host_stage_fixture",
    "export_host_reverify_fixture",
    "clock_sample",
    "campaign_resource_bindings",
}


class BoundResult(dict):
    def __init__(self, value, proof):
        super().__init__(value)
        self.proof = proof


def projection(value):
    if isinstance(value, RecoveryRepository):
        return {"repository_binding": value.binding}
    if isinstance(value, SocketArchiveTransfer):
        return {
            "max_reconnects": value.max_reconnects,
            "max_reconnect_seconds": value.max_reconnect_seconds,
        }
    if isinstance(value, bytes):
        return {"bytes": len(value), "sha256": sha(value)}
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {k: projection(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [projection(v) for v in value]
    return value


class ExecutionRuntime:
    """Explicit deployment wiring, with durable source and response custody.

    journal is DurableStore in deployment. The source document is immutable and
    hash-pinned by 4e; it binds host/endpoint/store/owner identities, not verdicts.
    It contains no credential or success default. Objects are provided separately.
    """

    def __init__(self, *, binding, pins, source, journal, clock, components):
        self.binding, self.pins = copy.deepcopy((binding, pins))
        self.source, self.store, self.clock = copy.deepcopy(source), journal, clock
        self.components = dict(components)
        self.last_clock = None
        self.clock_lock = threading.Lock()
        raw = Path(source["path"]).read_bytes()
        exact(sha(raw), source["sha256"], "execution:source_hash")
        self.inputs = strict_json(raw)
        exact(self.inputs["binding"], self.binding, "execution:binding")
        exact(self.inputs["pins"], self.pins, "execution:pins")
        with journal.lock():
            state = journal.read()
            original = {"source": source, "binding": self.binding, "pins": self.pins}
            if "execution" not in state:
                state["execution"] = original
                state["execution_receipts"] = []
                journal.write(state)
            exact(state["execution"], original, "execution:original")

    def need(self, key):
        require(key in self.inputs, "eks:unfinished:4e_" + key)
        return copy.deepcopy(self.inputs[key])

    def component(self, key, cls):
        value = self.components.get(key)
        require(isinstance(value, cls), "eks:unfinished:4e_" + key)
        return value

    def check(self, factory, stop):
        exact(self.binding, factory.binding, "execution:controller_join")
        exact(self.pins, factory.config["pins"], "execution:pin_join")
        exact(
            sha(Path(self.source["path"]).read_bytes()),
            self.source["sha256"],
            "execution:source_hash",
        )
        exact(
            self.inputs,
            strict_json(Path(self.source["path"]).read_bytes()),
            "execution:source_content",
        )
        factory.port.deadline(stop)

    def retain(self, port, request, result):
        artifacts = {}
        if port == "export_host_replay_export":
            repo = self.component("repository", RecoveryRepository)
            exact(
                repo.binding, self.need("recovery_store_binding"), "execution:custody_store_binding"
            )
            root = Path(repo.binding["recovery"]["root"]).resolve()
            require(root.is_dir(), "execution:custody_recovery_root")
            metadata = repo.metadata_root.resolve()
            require(metadata.is_relative_to(root), "execution:custody_root")
            from .inf037b_durable_ports import sync_directory

            parent = root
            for part in metadata.relative_to(root).parts:
                child = parent / part
                child.mkdir(mode=0o700, exist_ok=True)
                sync_directory(parent)
                parent = child
            for name in ("replay_raw", "export_raw"):
                data = result[name]
                require(type(data) is bytes, "execution:custody_bytes")
                target = repo.metadata_root / ("custody-" + sha(data))
                require(not target.is_symlink(), "execution:custody_path")
                if not target.exists():
                    durable_write(target, data)
                    sync_directory(repo.metadata_root)
                exact(
                    file_facts(target),
                    {"bytes": len(data), "sha256": sha(data)},
                    "execution:custody_readback",
                )
                artifacts[name] = {
                    "path": str(target),
                    "store_id": repo.binding["recovery"]["identity"],
                    **file_facts(target),
                }
        receipt = {
            "port": port,
            "source_sha256": self.source["sha256"],
            "request": request,
            "result": projection(result),
            **({"artifacts": artifacts} if artifacts else {}),
        }
        receipt = strict_json(encode(receipt))
        with self.store.lock():
            state = self.store.read()
            state["execution_receipts"].append(receipt)
            self.store.write(state)
        return receipt

    def repository(self, factory, stop):
        self.check(factory, stop)
        binding = validate_binding(self.need("recovery_store_binding"))
        exact(binding, factory.config["recovery_store_binding"], "execution:store_config")
        exact(binding["controller"], self.binding, "execution:store_controller")
        exact(binding["pins"], self.pins, "execution:store_pins")
        repo = self.component("repository", RecoveryRepository)
        exact(repo.binding, binding, "execution:repository_binding")
        require(isinstance(repo.accessor, ArtifactHTTPAccess), "execution:artifact_access")
        external = repo.store_ports["s3_store"]
        require(isinstance(external, S3ArchiveStore), "execution:s3_store")
        exact(
            (external.bucket, external.prefix),
            (binding["s3"]["bucket"], binding["s3"]["prefix"]),
            "execution:s3_location",
        )
        exact(
            str(Path(repo.store_ports["recovery_store"]).resolve()),
            str(Path(binding["recovery"]["root"]).resolve()),
            "execution:recovery_location",
        )
        exact(
            repo.accessor.url.geturl(),
            self.need("artifact_access_url"),
            "execution:access_endpoint",
        )
        return self.bound("4d_recovery_store_runtime", {"stop_ms": stop}, {"repository": repo})

    def independent(self, factory, stop):
        self.check(factory, stop)
        from .inf037b_eks_host_bindings import IndependentHosts

        hosts = self.need("recovery_supervisor")
        require(hosts["controller_host"] != hosts["supervisor_host"], "execution:independence")
        reader = self.component("independent_hosts", IndependentHosts)
        exact(reader.binding, self.binding, "execution:host_binding")
        exact(reader.pins, self.pins, "execution:host_pins")
        exact(
            reader.hosts["controller"]["instance_id"],
            hosts["controller_host"],
            "execution:controller_instance",
        )
        exact(
            reader.hosts["supervisor"]["instance_id"],
            hosts["supervisor_host"],
            "execution:supervisor_instance",
        )
        identities = reader.observe(stop)
        backstop = factory.controller.backstop
        exact(backstop.authority.identity, hosts["authority_id"], "execution:supervisor_authority")
        deadline = SessionDeadline(
            self.binding["C_ms"], self.binding["D_session_ms"], self.binding["t0_ms"]
        ).effective_ms
        require(
            backstop.confirmed(self.binding["session_id"], deadline) is True,
            "execution:supervisor_unconfirmed",
        )
        # confirmed() performs a fresh remote lookup of durable/armed/alive and
        # the original deadline, through the already accepted BackstopPort.
        result = {"binding": self.binding, "D_eff_ms": deadline, **hosts, "identities": identities}
        return self.bound("4d_independent_recovery", {"stop_ms": stop}, result)

    def host(self, port, request):
        endpoint = self.need("export_host")
        channel = self.component("export_host", ScopedAuthority)
        exact(channel.identity, endpoint["authority_id"], "execution:host_authority")
        exact(channel.namespace, "eks_host", "execution:host_namespace")
        expected = {
            "session_id": self.binding["session_id"],
            "t0_ms": self.binding["t0_ms"],
            "pins": self.pins,
        }
        exact(request["binding"], expected, "execution:host_binding")
        if "destination" in request:
            exact(request["destination"], endpoint["destination"], "execution:host_destination")
        operation = {
            "export_host_stage_fixture": "eks.host.stage",
            "export_host_reverify_fixture": "eks.host.reverify",
            "export_host_replay_export": "eks.host.replay_export",
        }[port]
        # The host authority owns durable intent + reconciliation. Its input is
        # hash-bound; caller retries only settle the same operation, never send.
        key = request.get("request_key", port + ":" + sha(encode(request)))
        result = channel.call(operation, key, 0, request)
        require(type(result) is dict, "execution:host_unknown")
        exact(result["binding"], expected, "execution:host_result_binding")
        exact(result["destination"], endpoint["destination"], "execution:host_result_destination")
        if port == "export_host_replay_export":
            result = copy.deepcopy(result)
            for field in ("replay_raw", "export_raw"):
                result[field] = bytes.fromhex(result.pop(field + "_hex"))
        return self.bound(port, request, result)

    def transport(self, factory, stop):
        self.check(factory, stop)
        inputs = self.need("terminal_export_transport")
        transfer = self.component("terminal_transfer", SocketArchiveTransfer)
        require(
            inputs["max_total_bytes"] > 0 and inputs["max_objects"] > 0, "execution:transfer_bounds"
        )
        exact(transfer.max_reconnects, inputs["max_reconnects"], "execution:transfer_reconnects")
        exact(
            transfer.max_reconnect_seconds,
            inputs["max_reconnect_seconds"],
            "execution:transfer_seconds",
        )
        require(
            inputs["max_reconnects"] >= 0 and inputs["max_reconnect_seconds"] >= 0,
            "execution:reconnect_budget",
        )
        return self.bound(
            "terminal_export_transport",
            {"stop_ms": stop},
            {**inputs, "address": tuple(inputs["address"]), "transfer": transfer},
        )

    def archive_inputs(self, factory, stop):
        self.check(factory, stop)
        inputs = self.need("campaign_archive_inputs")
        references = inputs["references"]
        result = {}
        for name in ("specs", "registration", "sanitizer_key"):
            reference = references[name]
            raw = Path(reference["path"]).read_bytes()
            exact(sha(raw), reference["sha256"], "execution:archive_input:" + name)
            result[name] = raw if name == "sanitizer_key" else strict_json(raw)
        for spec in result["specs"]:
            exact(spec["config_sha256"], self.pins["configuration"], "execution:spec_configuration")
        exact(
            sha(result["sanitizer_key"]),
            factory.config["sanitizer_key_sha256"],
            "execution:sanitizer_pin",
        )
        result["aggregate_parent"] = Path(inputs["aggregate_parent"])
        return self.bound("4d_campaign_archive_inputs", {"stop_ms": stop}, result)

    def catalog(self, factory, stop):
        self.check(factory, stop)
        # This is the owner's allocated catalogue, including failed/partial
        # owners, not a glob of the successful materializations.
        source = self.need("terminal_capture_catalog")
        raw = Path(source["path"]).read_bytes()
        catalog = strict_json(raw)
        exact(catalog["binding"], self.binding, "execution:catalog_binding")
        from .inf037b_eks_owner_registry import AllocatedOwners

        allocated = AllocatedOwners(factory.port.store, self.binding).allocations()
        exact(
            [r["owner_id"] for r in allocated],
            source["allocated_owner_ids"],
            "execution:catalog_allocated_registry",
        )
        exact(
            {r["owner_id"]: r["root"] for r in allocated},
            source["roots"],
            "execution:catalog_allocated_roots",
        )
        actual = factory.capture_catalog()
        require(actual["complete"] is True, "execution:catalog_unclosed_registry")
        require(catalog["complete"] is True, "execution:catalog_incomplete")
        exact(
            [o["owner_id"] for o in catalog["owners"]],
            source["allocated_owner_ids"],
            "execution:catalog_coverage",
        )
        require(
            len(source["allocated_owner_ids"]) == len(set(source["allocated_owner_ids"])),
            "execution:catalog_duplicates",
        )
        for owner in catalog["owners"]:
            require(owner["descriptor"]["closed"] is True, "execution:catalog_open")
            exact(owner["root"], source["roots"][owner["owner_id"]], "execution:catalog_root")
            exact(
                fixture_inventory(owner["root"]),
                owner["descriptor"]["files"],
                "execution:catalog_files",
            )
        exact(actual, catalog, "execution:catalog_descriptor_store")
        return self.bound(
            "4d_terminal_capture_inventory", {"stop_ms": stop, "catalog_sha256": sha(raw)}, catalog
        )

    def clock_sample(self, factory):
        self.check(factory, factory.binding["D_session_ms"])
        identity = self.need("measurement_clock")
        require(
            bool(identity["clock_id"]) and bool(identity["boot_id"]), "execution:clock_identity"
        )
        with self.clock_lock:
            lo = self.clock()
            boot = Path(identity["boot_id_path"]).read_text(encoding="ascii").strip()
            hi = self.clock()
            exact(boot, identity["boot_id"], "execution:boot_identity")
            require(lo <= hi, "execution:clock_order")
            require(self.last_clock is None or lo >= self.last_clock, "execution:clock_regressed")
            self.last_clock = hi
            return {"clock_id": identity["clock_id"], "boot_id": boot, "ms": [lo, hi]}

    def resources(self, factory, owner, stop):
        self.check(factory, stop)
        owner.join_current()
        exact(owner.binding["session_id"], self.binding["session_id"], "execution:resource_owner")
        exact(owner.binding["pins"], self.pins, "execution:resource_pins")
        role = "setup" if owner.attempt == "setup" else "campaign"
        result = self.need("resource_bindings")[role]
        # Generation, boot, code hash, cgroup CPU and interface capacity are
        # deployment inputs. ResourceAdapter still reads/joins the real HTTP
        # producer on every sample; this binding is not a resource observation.
        require(bool(result), "execution:resource_bindings_empty")
        for role, spec in result.items():
            validate_resource_binding(role, spec)
        self.retain(
            "campaign_resource_bindings", {"owner": str(owner.root), "stop_ms": stop}, result
        )
        return result

    def dependency(self, name, factory):
        methods = {
            "4d_recovery_store_runtime": lambda stop: self.repository(factory, stop),
            "4d_independent_recovery": lambda stop: self.independent(factory, stop),
            "terminal_export_transport": lambda stop: self.transport(factory, stop),
            "4d_campaign_archive_inputs": lambda stop: self.archive_inputs(factory, stop),
            "4d_terminal_capture_inventory": lambda stop: self.catalog(factory, stop),
            "clock_sample": lambda: self.clock_sample(factory),
            "campaign_resource_bindings": lambda owner, stop: self.resources(factory, owner, stop),
        }
        if name.startswith("export_host_"):

            def call(request):
                self.check(factory, request["stop_ms"])
                result = self.host(name, request)
                factory.port.deadline(request["stop_ms"], completed=True)
                return result

            return call
        return methods[name]

    def bound(self, port, request, result):
        proof = self.retain(port, request, result)
        return BoundResult(result, proof)

    def verify(self, value, factory, port):
        proof = getattr(value, "proof", None)
        require(type(proof) is dict, "execution:consumer_proof")
        exact(proof["port"], port, "execution:consumer_port")
        exact(proof["source_sha256"], self.source["sha256"], "execution:consumer_source")
        exact(projection(value), proof["result"], "execution:consumer_result")
        with self.store.lock():
            require(proof in self.store.read()["execution_receipts"], "execution:consumer_retained")
        exact(self.binding, factory.binding, "execution:consumer_binding")
        if port == "4d_recovery_store_runtime":
            require(
                value["repository"] is self.components["repository"],
                "execution:consumer_repository",
            )
        if port == "terminal_export_transport":
            require(
                value["transfer"] is self.components["terminal_transfer"],
                "execution:consumer_transfer",
            )


def execution_port(factory, name):
    def call(*args, **kwargs):
        runtime = factory.config.get("execution_runtime")
        require(
            isinstance(runtime, ExecutionRuntime),
            "eks:unfinished:" + name + ":4e_execution_runtime",
        )
        return runtime.dependency(name, factory)(*args, **kwargs)

    return call


def join_execution(value, factory, port):
    # Explicit injected unit-test implementations retain their existing checks.
    # The wired production runtime must also prove custody at the consumer.
    if "execution_runtime" in getattr(factory, "config", {}):
        runtime = factory.config["execution_runtime"]
        require(isinstance(runtime, ExecutionRuntime), "execution:consumer_runtime")
        runtime.verify(value, factory, port)
