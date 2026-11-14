"""Artifact-only Part 3 binding; host and 4c transports remain explicit ports.

The host entry point composes existing replay/sanitizer/transfer code. Nothing
builds a maximum, changes virtual/real wait rules, or supplies a local fallback
for a missing export host, store or retrieval adapter.
"""

import copy
from pathlib import Path

from .inf037b_archive import durable_write, encode, sha, strict_json
from .inf037b_campaign import sanitized_campaign
from .inf037b_eks_fixture import fixture_inventory
from .inf037b_eks_stores import join_access, seal_receipt
from .inf037b_maximum import load_maximum
from .inf037b_resolver import BOUNDS_MS, exact, require
from .inf037b_setup import offline_proof
from .inf037b_setup_observations import (
    capture_export,
    capture_replay,
    elapsed,
    export_observations,
    inventory,
    replay_observations,
    validate_export_archives,
)
from .inf037b_transfer import persist_to_both


def read_input(reference):
    require(
        type(reference) is dict and {"path", "sha256"} <= reference.keys(), "part3:input_reference"
    )
    path = Path(reference["path"])
    require(path.is_file() and not path.is_symlink(), "part3:input_missing")
    raw = path.read_bytes()
    exact(sha(raw), reference["sha256"], "part3:input_hash")
    return raw


def wait_proofs(references, binding):
    require(
        type(references) is dict and set(references) == {"attempt", "reset"},
        "part3:real_wait_proofs_required",
    )
    artifacts, proofs = {}, {}
    for phase in ("attempt", "reset"):
        path = "proof/real-wait-" + phase + ".json"
        artifacts[path] = read_input(references[phase])
        proofs[phase] = offline_proof(
            artifacts, path, binding["pins"], BOUNDS_MS[phase], "lifecycle:" + phase
        )
    return proofs, artifacts


def execute_on_export_host(
    request, *, context, sample, sanitizer_key, network_transfer, store_ports
):
    """Called by the future host role, never directly as a controller fallback.

    context is supplied by that role's node/volume/mount authority, including
    host-local input paths and a fresh work directory. network_transfer uses
    capture_export's accepted interrupted/resumed/retrieved-path interface;
    store_ports are persist_to_both's real recovery/S3 bindings.
    """
    exact(request["scope"], "replay_and_export_observation", "part3:scope")
    exact(context["destination"], request["destination"], "part3:host_destination")
    binding = request["binding"]
    for name in ("maximum_fixture", "maximum_fixture_specs", "export_sizing_proof"):
        exact(context[name]["sha256"], request["inputs"][name]["sha256"], "part3:host_input")
    maximum = load_maximum(context["maximum_fixture"], binding["pins"])
    source = Path(context["fixture_root"])
    exact(fixture_inventory(source), maximum["fixture_inventory"], "part3:fixture_inventory")
    specs = strict_json(read_input(context["maximum_fixture_specs"]))
    sizing = strict_json(read_input(context["export_sizing_proof"]))
    for phase in ("attempt", "reset"):
        exact(
            context["real_wait_proofs"][phase]["sha256"],
            request["inputs"]["real_wait_proofs"][phase]["sha256"],
            "part3:host_input",
        )
    real_wait, proof_artifacts = wait_proofs(context["real_wait_proofs"], binding)
    exact(sha(sanitizer_key), request["sanitizer_key_sha256"], "part3:sanitizer_key")
    require(callable(network_transfer), "part3:network_transfer_required")
    require(store_ports is not None, "part3:4c_stores_required")
    work = Path(context["work"])
    require(not work.exists(), "part3:fresh_workspace")
    work.mkdir(parents=True)
    replay_raw = capture_replay(binding=binding, sample=sample, work=work / "replay")
    durable_write(work / "replay.capture.json", replay_raw)
    replay = replay_observations(replay_raw, binding=binding)
    sanitized, destination = work / "sanitized", work / "retrieved"
    persisted = {}

    def sanitize(raw, output):
        # Unchanged sanitized_campaign performs source reproduction, semantic
        # comparison, materialize_bundle and sanitized reproduction for all specs.
        sanitized_campaign(raw, output, specs, key=sanitizer_key)

    def persist_readbacks(result):
        artifacts = {
            prefix + "/" + name: root / name
            for prefix, root in (("source", source), ("sanitized", sanitized))
            for name in inventory(root)
        }
        # 4c must retrieve the remote receiver's objects to real host paths.
        # An opaque remote path/dict is never opened on the controller as local.
        for name, path in result["destination_artifacts"].items():
            require(isinstance(path, Path), "part3:retrieval_paths_required")
            artifacts["destination/" + name] = path
        native = persist_to_both(artifacts=artifacts, **store_ports)
        persisted.update(seal_receipt(native, request["stores"], artifacts))

    first = [copy.deepcopy(request["operation_start"])]

    def export_sample():
        # Keep the actual entry bracket taken before host re-verification and
        # replay; do not hide those reads/writes outside the export operation.
        return first.pop() if first else sample()

    export_raw, artifacts = capture_export(
        binding=binding,
        source=source,
        sanitized=sanitized,
        destination=destination,
        sanitize=sanitize,
        sample=export_sample,
        reconnect_ms=sizing["reconnect_bound_ms"],
        network_transfer=network_transfer,
        after_transfer=persist_readbacks,
    )
    validate_export_archives(export_raw, artifacts)
    exported = export_observations(
        export_raw,
        binding=binding,
        artifacts=artifacts,
        maximum_fixture=maximum,
        sizing_proof=sizing,
    )
    return {
        "binding": binding,
        "destination": request["destination"],
        "replay_raw": replay_raw,
        "export_raw": export_raw,
        "export_artifacts": artifacts,
        "replay": replay,
        "export": exported,
        "real_wait_proofs": real_wait,
        "proof_artifacts": proof_artifacts,
        "store_receipt": persisted,
        "paid_ready": False,
    }


class SetupObservationScope:
    def __init__(self, factory):
        self.factory = factory

    def __call__(self, stop):
        f = self.factory
        f.port.deadline(stop)
        start = f.dependency("clock_sample")()
        stage = f.staged_creation()
        verified = stage.reverify(stop)
        elapsed(verified["ready"], start)
        maximum, _ = stage.validate(check_source=False)
        inputs = {
            name: f.config.get(name)
            for name in (
                "maximum_fixture",
                "maximum_fixture_specs",
                "export_sizing_proof",
                "real_wait_proofs",
            )
        }
        real_wait, _ = wait_proofs(inputs["real_wait_proofs"], stage.binding)
        sizing = strict_json(read_input(inputs["export_sizing_proof"]))
        exact(sizing["subject"], "lifecycle:export_sizing", "part3:sizing_subject")
        exact(sizing["pins"], stage.binding["pins"], "part3:sizing_pins")
        exact(
            sizing["raw_bytes"],
            sum(facts["bytes"] for facts in maximum["fixture_inventory"].values()),
            "part3:sizing_bytes",
        )
        require(type(f.config.get("sanitizer_key_sha256")) is str, "part3:sanitizer_pin_required")
        request = {
            "scope": "replay_and_export_observation",
            "binding": stage.binding,
            "destination": verified["destination"],
            "operation_start": start,
            "stop_ms": stop,
            "inputs": inputs,
            "sanitizer_key_sha256": f.config["sanitizer_key_sha256"],
        }
        stores = f.dependency("4c_export_stores")(copy.deepcopy(request))
        require(type(stores) is dict, "part3:4c_store_binding")
        request["stores"] = stores
        key = f.port.driver_key + ":preparation:part3"
        with f.port.store.lock():
            state = f.port.store.read()
            require(
                sha(encode(["eks.part3", key])) not in state["operations"],
                "part3:interrupted_no_retry",
            )
            f.port.intent(state, "eks.part3", key, request)
        result = f.dependency("export_host_replay_export")(request)
        from .inf037b_eks_execution import join_execution

        join_execution(result, f, "export_host_replay_export")
        exact(result["binding"], stage.binding, "part3:result_binding")
        exact(result["destination"], verified["destination"], "part3:result_destination")
        require(
            type(result["export_raw"]) is bytes and type(result["replay_raw"]) is bytes,
            "part3:capture_bytes",
        )
        with f.port.store.lock():
            state = f.port.store.read()
            state["values"]["part3/candidate/" + key] = {
                "export_raw_hex": result["export_raw"].hex(),
                "replay_raw_hex": result["replay_raw"].hex(),
                "destination": verified["destination"],
                "validated": False,
            }
            f.port.store.write(state)
        accessed = f.dependency("4c_export_artifact_access")(result, stop)
        artifacts = accessed["export_artifacts"]
        join_access(accessed, result["store_receipt"], stores)
        # Real file/semantic checks require the explicit 4c access adapter;
        # never interpret a receiver-local path as a controller-local path.
        replay = replay_observations(result["replay_raw"], binding=stage.binding)
        exported = export_observations(
            result["export_raw"],
            binding=stage.binding,
            artifacts=artifacts,
            maximum_fixture=maximum,
            sizing_proof=sizing,
        )
        exact(result["real_wait_proofs"], real_wait, "part3:real_wait_join")
        f.port.deadline(stop, completed=True)
        with f.port.store.lock():
            state = f.port.store.read()
            state["values"]["part3/" + key] = {
                "replay_raw_hex": result["replay_raw"].hex(),
                "replay": replay,
                "export_raw_sha256": sha(result["export_raw"]),
                "export": exported,
                "real_wait_proofs": real_wait,
                "destination": verified["destination"],
                "store_manifest_sha256": result["store_receipt"]["source_manifest_sha256"],
                "validated": True,
                "paid_ready": False,
            }
            f.port.store.write(state)
        return result["export_raw"], artifacts

    def evidence(self):
        f = self.factory
        key = "part3/" + f.port.driver_key + ":preparation:part3"
        with f.port.store.lock():
            value = f.port.store.read()["values"].get(key)
        require(value is not None, "part3:evidence_unavailable")
        return value
