"""Creation-only binding of the prebuilt maximum to pre-P copy/hash receipts.

No generator, compact substitute or new replay/sizing harness lives here. The
exact plan pins the proof/spec bytes; load_maximum joins their source authority.
The final-source build/admission remains a 4e/4f prerequisite.
"""

import copy
from pathlib import Path, PurePosixPath

from .inf037b_archive import encode, file_facts, sha, strict_json
from .inf037b_contract import MAX_ATTEMPTS, TARGET_ORDER
from .inf037b_maximum import load_maximum
from .inf037b_preparation import staging_receipt
from .inf037b_resolver import exact, require, span
from .inf037b_setup import creation_observation

MAXIMUM_FIXTURE_ROWS = 701_418  # Current maximum producer; Round 319 authority.


def fixture_inventory(directory):
    directory = Path(directory)
    require(directory.is_dir() and not directory.is_symlink(), "eks:fixture_missing:source")
    paths = list(directory.rglob("*"))
    require(not any(path.is_symlink() for path in paths), "eks:fixture_symlink")
    return {
        path.relative_to(directory).as_posix(): file_facts(path) for path in paths if path.is_file()
    }


class StagedCreation:
    """Allocate the export node/volume, stage there, then publish readiness P.

    Its raw receipt must contain these exact pre-P facts, never a synthesized
    or rebased ready time. Existing Port intents persist interrupted staging;
    a partial copy is evidence and cannot be rebuilt/retried in-session.
    """

    def __init__(self, port, config, sample, *, host_stage, host_reverify):
        self.port, self.config, self.sample = port, config, sample
        self.host_stage, self.host_reverify = host_stage, host_reverify
        self.binding = {
            "session_id": port.binding["session_id"],
            "t0_ms": port.binding["t0_ms"],
            "pins": copy.deepcopy(port.pins),
        }

    def reference(self, name):
        reference = self.config.get(name)
        require(
            type(reference) is dict and {"path", "sha256"} <= reference.keys(),
            "eks:fixture_input:" + name,
        )
        path = Path(reference["path"])
        require(path.is_file() and not path.is_symlink(), "eks:fixture_missing:" + name)
        raw = path.read_bytes()
        exact(sha(raw), reference["sha256"], "eks:fixture_hash:" + name)
        return raw

    def validate(self, *, check_source=True):
        self.reference("maximum_fixture")
        proof = load_maximum(self.config["maximum_fixture"], self.binding["pins"])
        require(type(proof.get("registered_archive_rows")) is int, "eks:fixture_rows")
        exact(proof.get("registered_archive_rows"), MAXIMUM_FIXTURE_ROWS, "eks:fixture_rows")
        exact(
            proof.get("scope"), "current_full_three_attempt_two_reset_fixture", "eks:fixture_scope"
        )
        raw_spec = self.reference("maximum_fixture_specs")
        specs = strict_json(raw_spec)
        exact(raw_spec, encode(specs), "eks:fixture_specs_canonical")
        require(type(specs) is list and len(specs) == MAX_ATTEMPTS, "eks:fixture_specs_schedule")
        require(
            all(
                type(s) is dict
                and type(s.get("attempt_index")) is int
                and type(s.get("target_slot")) is int
                for s in specs
            ),
            "eks:fixture_specs_schedule",
        )
        exact([s.get("attempt_index") for s in specs], [1, 2, 3], "eks:fixture_specs_schedule")
        exact(
            [s.get("target_slot") for s in specs], list(TARGET_ORDER), "eks:fixture_specs_targets"
        )
        require("maximum_fixture_source" in self.config, "eks:fixture_input:source")
        mount = self.config.get("export_fixture_mount_path")
        require(
            type(mount) is str and PurePosixPath(mount).is_absolute(),
            "eks:fixture_input:export_mount",
        )
        source = Path(self.config["maximum_fixture_source"]).absolute()
        if check_source:
            exact(fixture_inventory(source), proof["fixture_inventory"], "eks:fixture_inventory")
        return proof, source

    def destination(self, value):
        require(
            type(value) is dict
            and set(value) == {"node_uid", "volume_id", "mount_path"}
            and all(type(v) is str and v for v in value.values()),
            "eks:fixture_destination",
        )
        mount = self.config.get("export_fixture_mount_path")
        require(
            type(mount) is str and PurePosixPath(mount).is_absolute(),
            "eks:fixture_input:export_mount",
        )
        exact(value["mount_path"], mount, "eks:fixture_export_mount")
        return copy.deepcopy(value)

    def allocate(self, key, stop, context, proof):
        result = self.port.effect(
            "eks.creation.allocate",
            key,
            {
                "binding": self.port.binding,
                "pins": self.binding["pins"],
                "stop_ms": stop,
                "context": context,
                "maximum_fixture": self.config["maximum_fixture"],
                "inventory_sha256": proof["source_inventory_sha256"],
                "export_fixture_mount_path": self.config.get("export_fixture_mount_path"),
            },
            stop,
        )
        exact(result["created"], True, "eks:fixture_export_host_not_created")
        exact(result["ready"], False, "eks:fixture_P_before_staging")
        return result

    def point(self, stop):
        self.port.deadline(stop)
        point = self.sample()
        lo, hi = span(point["ms"], "eks:fixture_clock")
        require(self.binding["t0_ms"] <= lo <= hi <= stop, "eks:fixture_deadline")
        return point

    def stage(self, key, stop, proof, source, destination):
        descriptor = {
            "binding": self.binding,
            "stop_ms": stop,
            "proof": self.config["maximum_fixture"],
            "specs": self.config["maximum_fixture_specs"],
            "inventory_sha256": proof["source_inventory_sha256"],
            "source": str(source),
            "destination": destination,
        }
        port, label = self.port, "fixture/" + key
        with port.store.lock():
            state = port.store.read()
            old = state["operations"].get(sha(encode(["eks.fixture_stage", key])))
            port.intent(state, "eks.fixture_stage", key, descriptor)
            receipt = state["values"].get(label)
            require(old is None or receipt is not None, "eks:fixture_interrupted_no_retry")
        if receipt is None:
            # No controller-local copy fallback. The real host-side adapter is
            # unfinished until the export node/volume/mount is available.
            receipt = self.host_stage(
                {**descriptor, "expected_inventory": proof["fixture_inventory"], "request_key": key}
            )
            exact(receipt["destination"], destination, "eks:fixture_staging_destination")
            staging_receipt(receipt, binding=self.binding, ready=self.point(stop))
            with port.store.lock():
                state = port.store.read()
                state["values"][label] = copy.deepcopy(receipt)
                port.store.write(state)
        exact(receipt["destination"], destination, "eks:fixture_staging_destination")
        return receipt

    def create(self, key, stop, context, record):
        self.port.validate_context("creation", stop, context)
        exact(key, context["operation_key"], "eks:effect_key")
        proof, source = self.validate()
        allocated = self.allocate(key, stop, context, proof)
        ids = allocated["instance_ids"]
        require(
            type(ids) is list
            and all(type(i) is str and i for i in ids)
            and len(ids) == len(set(ids)),
            "eks:creation_ids",
        )
        for instance in ids:
            record(instance)
        destination = self.destination(allocated["export_destination"])
        receipt = self.stage(key, stop, proof, source, destination)
        payload = {
            "staging": receipt,
            "maximum_fixture_sha256": sha(encode(proof)),
            "maximum_fixture_specs": self.config["maximum_fixture_specs"],
            "export_destination": destination,
            "inventory_sha256": proof["source_inventory_sha256"],
        }
        result = self.port.effect(
            "eks.creation.ready",
            key,
            {
                "binding": self.port.binding,
                "pins": self.binding["pins"],
                "stop_ms": stop,
                "context": context,
                "allocation_sha256": sha(encode(allocated)),
                "payload": payload,
            },
            stop,
        )
        exact(result["instance_ids"], ids, "eks:fixture_readiness_instances")
        exact(result["export_destination"], destination, "eks:fixture_readiness_destination")
        raw = bytes.fromhex(result["raw_hex"])
        bundle = strict_json(raw)
        exact(bundle.get("staging"), receipt, "eks:fixture_readiness_staging")
        exact(bundle.get("export_destination"), destination, "eks:fixture_readiness_destination")
        exact(
            bundle.get("maximum_fixture_sha256"),
            payload["maximum_fixture_sha256"],
            "eks:fixture_readiness_proof",
        )
        exact(
            bundle.get("maximum_fixture_specs"),
            payload["maximum_fixture_specs"],
            "eks:fixture_readiness_specs",
        )
        observed = creation_observation(raw, self.binding)
        exact(observed["ready"]["ms"][1], observed["ready_ms"], "eks:fixture_original_P")
        staging_receipt(receipt, binding=self.binding, ready=observed["ready"])
        self.port.deadline(stop, completed=True)
        return raw

    def reverify(self, stop):
        """Preparation/export reads the same host volume that was staged at P."""
        self.port.deadline(stop)
        key = self.port.driver_key + ":creation"
        with self.port.store.lock():
            state = self.port.store.read()
            allocated = state["values"].get(sha(encode(["eks.creation.allocate", key])))
            receipt = state["values"].get("fixture/" + key)
            ready = state["values"].get(sha(encode(["eks.creation.ready", key])))
        require(
            allocated is not None and receipt is not None and ready is not None,
            "eks:fixture_not_ready",
        )
        destination = self.destination(allocated["result"]["export_destination"])
        exact(receipt["destination"], destination, "eks:fixture_staging_destination")
        proof, _ = self.validate(check_source=False)
        result = self.host_reverify(
            {
                "binding": self.binding,
                "destination": destination,
                "expected_inventory": proof["fixture_inventory"],
                "proof": self.config["maximum_fixture"],
                "specs": self.config["maximum_fixture_specs"],
                "stop_ms": stop,
            }
        )
        exact(result["binding"], self.binding, "eks:fixture_reverify_binding")
        exact(result["destination"], destination, "eks:fixture_reverify_destination")
        exact(
            result["actual_inventory"], proof["fixture_inventory"], "eks:fixture_staged_inventory"
        )
        exact(result["verified"], True, "eks:fixture_reverify")
        self.port.deadline(stop, completed=True)
        return {**result, "ready": strict_json(bytes.fromhex(ready["result"]["raw_hex"]))["ready"]}

    def inventory(self, application, stop):
        return self.port.inventory(application, stop)
