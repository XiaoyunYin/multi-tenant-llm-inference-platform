"""Gate A source-bound proof, transfer sequence and refusal rules."""

from __future__ import annotations

import json
import math
import os
import socketserver
import threading
import time
from pathlib import Path

from .inf037b_archive import encode, file_facts, sha
from .inf037b_capture import wire_records
from .inf037b_contract import ATTEMPT_MS, RESET_MS
from .inf037b_durable_ports import DurableStore, sync_directory
from .inf037b_maximum import current_sources, load_maximum
from .inf037b_resolver import ceil_minute, exact, integer, require
from .inf037b_setup_observations import capture_export, validate_export_archives
from .inf037b_transfer import (
    S3ArchiveStore,
    SocketArchiveReceiver,
    SocketArchiveTransfer,
    _read_frame,
    _TransferTCPServer,
    _write_frame,
    persist_to_both,
    retrieve_posix_artifacts,
)

GATE_A_OPERATION_CUTOFF_MS = 1_740_000
REGISTERED_O_EXPORT_MAX_MS = 1_800_000
REGISTERED_TRANSFER_MAX_MS = 3_600_000
PROPOSED_RECONNECT_COMPONENT_MS = 5_000
PROPOSED_RECONNECT_BOUND_MS = 3 * PROPOSED_RECONNECT_COMPONENT_MS
TRANSFER_TIMEOUT_S = 5


def _json_safe(value):
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {key: _json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    return value


def inventory(root: Path) -> dict:
    root = Path(root)
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("gate_a:symlink")
        if path.is_file():
            result[path.relative_to(root).as_posix()] = file_facts(path)
    require(bool(result), "gate_a:empty_inventory")
    return result


def produce_export_sizing_proof(
    source,
    *,
    pins,
    fixture_proof_sha256,
    reconnect_bound_ms=PROPOSED_RECONNECT_BOUND_MS,
):
    """Build the source-current proof with the Round 321 reconnect allowance."""
    files = inventory(Path(source))
    require(integer(reconnect_bound_ms) and reconnect_bound_ms > 0, "gate_a:reconnect_bound")
    exact(len(fixture_proof_sha256), 64, "gate_a:fixture_proof_hash")
    require(
        all(character in "0123456789abcdef" for character in fixture_proof_sha256),
        "gate_a:fixture_proof_hash",
    )
    derivation = {
        "transport_timeout_s": TRANSFER_TIMEOUT_S,
        "connect_ms": PROPOSED_RECONNECT_COMPONENT_MS,
        "status_exchange_ms": PROPOSED_RECONNECT_COMPONENT_MS,
        "one_chunk_resend_ms": PROPOSED_RECONNECT_COMPONENT_MS,
    }
    derived_bound = sum(
        derivation[key] for key in ("connect_ms", "status_exchange_ms", "one_chunk_resend_ms")
    )
    exact(reconnect_bound_ms, derived_bound, "gate_a:reconnect_derivation")
    return {
        "schema": "inf037b-export-sizing-proof-v1",
        "subject": "lifecycle:export_sizing",
        "pins": pins,
        "source_lf_sha256": current_sources(),
        "fixture_proof_sha256": fixture_proof_sha256,
        "source_inventory_sha256": sha(encode(files)),
        "raw_bytes": sum(facts["bytes"] for facts in files.values()),
        "reconnect_bound_ms": reconnect_bound_ms,
        "reconnect_bound_status": "accepted_round_321",
        "reconnect_derivation": {**derivation, "sum_ms": derived_bound},
    }


def validate_export_sizing_proof(proof, source_inventory, *, pins, fixture_proof_sha256):
    exact(proof.get("schema"), "inf037b-export-sizing-proof-v1", "gate_a:sizing_schema")
    exact(proof.get("subject"), "lifecycle:export_sizing", "gate_a:sizing_subject")
    exact(proof.get("pins"), pins, "gate_a:sizing_pins")
    exact(proof.get("source_lf_sha256"), current_sources(), "gate_a:sizing_sources")
    exact(proof.get("fixture_proof_sha256"), fixture_proof_sha256, "gate_a:sizing_fixture")
    exact(
        proof.get("source_inventory_sha256"),
        sha(encode(source_inventory)),
        "gate_a:sizing_inventory",
    )
    exact(
        proof.get("raw_bytes"),
        sum(facts["bytes"] for facts in source_inventory.values()),
        "gate_a:sizing_raw_bytes",
    )
    require(
        integer(proof.get("reconnect_bound_ms")) and proof["reconnect_bound_ms"] > 0,
        "gate_a:sizing_reconnect_bound",
    )
    exact(
        proof.get("reconnect_bound_status"),
        "accepted_round_321",
        "gate_a:sizing_reconnect_bound_status",
    )
    derivation = proof.get("reconnect_derivation", {})
    exact(derivation.get("sum_ms"), proof["reconnect_bound_ms"], "gate_a:reconnect_derivation")
    return proof


def verify_wire_spool(root, *, expected_inventory=None, minimum_raw_bytes=0, objects=14):
    """Verify every index span against its raw segment without retaining bodies."""
    root = Path(root)
    files = inventory(root)
    for _, _body in wire_records(root):
        pass
    raw_bytes = sum(facts["bytes"] for name, facts in files.items() if name.endswith(".bin"))
    index_bytes = sum(facts["bytes"] for name, facts in files.items() if name.endswith(".jsonl"))
    exact(len(files), objects, "gate_a:spool_object_count")
    require(raw_bytes >= minimum_raw_bytes, "gate_a:spool_raw_allowance")
    require(raw_bytes > 0 and index_bytes > 0, "gate_a:spool_empty")
    if expected_inventory is not None:
        exact(files, expected_inventory, "gate_a:spool_inventory")
    return {
        "inventory": files,
        "object_count": len(files),
        "raw_bytes": raw_bytes,
        "index_bytes": index_bytes,
        "inventory_sha256": sha(encode(files)),
        "index_verified_against_raw": True,
    }


def gate_a_binding():
    """Return the fixed synthetic binding used to produce Gate A offline inputs."""
    from .inf037b_resolver import PIN_NAMES

    pins = dict.fromkeys(PIN_NAMES, "a" * 64)
    pins["model"] = "de29607ab9763afcdfccdc834a39ad1e7c5ad1398498725eeeff4d3b81fb5f32"
    pins["configuration"] = "6ad1f17587e6a248143c67a65a90b493b9748a2005a938b8120a20bfdee2590a"
    return {"session_id": "setup-session", "pins": pins, "t0_ms": 1000}


def _compact_phase_receipt(full_receipt):
    compact = {
        "phase": full_receipt["phase"],
        "transfer_id": full_receipt["transfer_id"],
        "manifest_sha256": full_receipt["manifest_sha256"],
        "events": full_receipt["events"],
        "object_count": full_receipt["object_count"],
        "total_bytes": full_receipt["total_bytes"],
    }
    compact["store_receipt"] = {
        "recovery": {
            "manifest": {
                key: {"bytes": facts["bytes"], "sha256": facts["sha256"]}
                for key, facts in full_receipt["store_receipt"]["recovery"]["manifest"].items()
            },
            "manifest_sha256": sha(encode(full_receipt["store_receipt"]["recovery"]["manifest"])),
        },
        "s3": {
            "manifest_sha256": full_receipt["store_receipt"]["s3"]["receipt"]["manifest_sha256"],
            "objects": {
                key: {"bytes": value["bytes"], "sha256": value["sha256"]}
                for key, value in full_receipt["store_receipt"]["s3"]["receipt"]["objects"].items()
            },
        },
        "readback_verified": True,
    }
    if full_receipt["phase"] == "spool":
        retrieval = full_receipt["full_retrieval"]
        compact["full_retrieval"] = {
            "complete": retrieval["complete"],
            "object_count": retrieval["object_count"],
            "stores": {
                store: {
                    "objects": value["objects"],
                    "bytes": value["bytes"],
                    "inventory_sha256": value["inventory_sha256"],
                }
                for store, value in retrieval["stores"].items()
            },
            "inventories_equal": retrieval["stores"]["recovery"]["inventory_sha256"]
            == retrieval["stores"]["s3"]["inventory_sha256"],
        }
    return compact


def transfer_formula_ms(raw_bytes, minimum_bytes_per_second, reconnect_bound_ms):
    require(integer(raw_bytes) and raw_bytes > 0, "gate_a:raw_bytes")
    require(
        integer(minimum_bytes_per_second) and minimum_bytes_per_second > 0,
        "gate_a:transfer_rate",
    )
    require(integer(reconnect_bound_ms) and reconnect_bound_ms >= 0, "gate_a:reconnect_bound")
    # Same resolver arithmetic: archive maximum = 2*raw and transfer safety = 2*maximum.
    return ceil_minute(
        4 * raw_bytes * 1000 + reconnect_bound_ms * minimum_bytes_per_second,
        minimum_bytes_per_second,
    )


def gate_a_verdict(*, operation_ms, o_export_ms, transfer_formula_ms_value):
    for name, value in (
        ("operation_ms", operation_ms),
        ("o_export_ms", o_export_ms),
        ("transfer_formula_ms", transfer_formula_ms_value),
    ):
        require(integer(value) and value >= 0, "gate_a:" + name)
    checks = (
        (operation_ms <= GATE_A_OPERATION_CUTOFF_MS, "gate_a:o_export_capture_cutoff"),
        (o_export_ms <= REGISTERED_O_EXPORT_MAX_MS, "gate_a:registered_o_export"),
        (transfer_formula_ms_value <= REGISTERED_TRANSFER_MAX_MS, "gate_a:transfer_formula"),
    )
    refusal = next((reason for passed, reason in checks if not passed), None)
    return {
        "schema": "inf037b-gate-a-verdict-v1",
        "status": "PASS" if refusal is None else "REFUSED",
        "reason": refusal,
        "operation_ms": operation_ms,
        "operation_cutoff_ms": GATE_A_OPERATION_CUTOFF_MS,
        "o_export_ms": o_export_ms,
        "registered_o_export_max_ms": REGISTERED_O_EXPORT_MAX_MS,
        "transfer_formula_ms": transfer_formula_ms_value,
        "registered_transfer_max_ms": REGISTERED_TRANSFER_MAX_MS,
        "shared_control_ms": 60_000,
        "shared_control_measured": False,
    }


class GateAReceiverRole:
    """One bounded Package A runner role for an archive or spool phase."""

    def __init__(
        self,
        *,
        phase,
        transfer_id,
        manifest,
        recovery_root,
        bucket,
        prefix,
        max_total_bytes,
        max_objects,
        port,
        receipt_path,
        previous_phases=(),
        endpoint_url=None,
        region="us-east-1",
        induce_drop=False,
        transfer_root=None,
        host="0.0.0.0",
        timeout_s=1_740,
    ):
        require(phase in {"archive", "spool"}, "gate_a:receiver_phase")
        self.phase, self.transfer_id, self.manifest = phase, transfer_id, manifest
        self.recovery_root = Path(recovery_root)
        self.bucket, self.prefix = bucket, prefix
        self.max_total_bytes, self.max_objects = max_total_bytes, max_objects
        self.port, self.receipt_path = port, Path(receipt_path)
        self.previous_phases = list(previous_phases)
        self.endpoint_url, self.region = endpoint_url, region
        self.induce_drop, self.host, self.timeout_s = induce_drop, host, timeout_s
        self.transfer_root = (
            Path(transfer_root) if transfer_root else self.recovery_root / "transfers"
        )
        self.receiver = None

    def start(self):
        self.attach().start(self.host, self.port)
        return self.receiver.address

    def attach(self):
        require(self.receiver is None, "gate_a:receiver_already_attached")
        self.receiver = SocketArchiveReceiver(
            self.transfer_root / self.phase,
            transfer_id=self.transfer_id,
            manifest=self.manifest,
            max_total_bytes=self.max_total_bytes,
            max_objects=self.max_objects,
        )
        if self.induce_drop:
            self.receiver.inject_once("drop_ack")
        return self.receiver

    def wait_complete(self):
        require(self.receiver is not None, "gate_a:receiver_not_started")
        deadline = time.monotonic() + self.timeout_s
        while time.monotonic() < deadline:
            state = self.receiver.state.read()
            if all(
                state["files"][key]["bytes"] == facts["bytes"]
                for key, facts in self.receiver.manifest.items()
            ):
                return
            time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
        raise TimeoutError("gate_a:receiver_deadline")

    def finish(self):
        require(self.receiver is not None, "gate_a:receiver_not_started")
        try:
            self.wait_complete()
            artifacts = self.receiver.artifact_paths()
            recovery_store = DurableStore(
                self.recovery_root / "archive-state", {"schema": "gate-a"}, initialize=True
            )
            s3_store = S3ArchiveStore(
                S3ArchiveStore.client_for_endpoint(self.endpoint_url, region=self.region),
                bucket=self.bucket,
                prefix=self.prefix,
                max_total_bytes=self.max_total_bytes,
                max_objects=self.max_objects,
            )
            store_receipt = persist_to_both(
                recovery_store=recovery_store,
                s3_store=s3_store,
                artifacts=artifacts,
                max_total_bytes=self.max_total_bytes,
                max_objects=self.max_objects,
                recovery_readback=self.recovery_root / "retrieved" / self.phase / "recovery",
                s3_readback=self.recovery_root / "retrieved" / self.phase / "s3",
            )
            receipt = {
                "schema": "inf037b-gate-a-receiver-phase-v1",
                "phase": self.phase,
                "transfer_id": self.transfer_id,
                "manifest_sha256": self.receiver.manifest_sha256,
                "events": list(self.receiver.events),
                "object_count": len(artifacts),
                "total_bytes": sum(facts["bytes"] for facts in self.receiver.manifest.values()),
                "store_receipt": store_receipt,
                "durable_acknowledgements": True,
                "readback_verified": True,
            }
            if self.phase == "spool":
                all_phases = [*self.previous_phases, receipt]
                receipt["full_retrieval"] = self.retrieve_all(all_phases, s3_store)
            self.write_receipt(receipt)
            return receipt
        finally:
            self.receiver.close()

    def run(self):
        self.start()
        return self.finish()

    def retrieve_all(self, phases, s3_store):
        require({row["phase"] for row in phases} == {"archive", "spool"}, "gate_a:retrieval_phases")
        inventory_by_store = {}
        total_objects = 0
        for store_name in ("recovery", "s3"):
            observed = {}
            for row in phases:
                phase = row["phase"]
                phase_receipt = row["store_receipt"]
                target = self.recovery_root / "retrieved" / "complete" / store_name / phase
                if store_name == "recovery":
                    paths = retrieve_posix_artifacts(phase_receipt["recovery"]["manifest"], target)
                else:
                    paths = s3_store.retrieve_archive_artifacts(
                        phase_receipt["s3"]["receipt"], target
                    )
                observed.update({f"{phase}/{key}": file_facts(path) for key, path in paths.items()})
            require(bool(observed), "gate_a:retrieval_empty")
            total_objects = len(observed)
            inventory_by_store[store_name] = {
                "objects": total_objects,
                "bytes": sum(facts["bytes"] for facts in observed.values()),
                "inventory": observed,
                "inventory_sha256": sha(encode(observed)),
            }
        exact(
            inventory_by_store["recovery"]["inventory"],
            inventory_by_store["s3"]["inventory"],
            "gate_a:retrieval_store_equality",
        )
        return {
            "complete": True,
            "object_count": total_objects,
            "stores": inventory_by_store,
        }

    def write_receipt(self, value):
        self.receipt_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.receipt_path.with_name(self.receipt_path.name + ".pending")
        with temporary.open("xb") as stream:
            data = encode(_json_safe(value))
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, self.receipt_path)
        sync_directory(self.receipt_path.parent)


def make_socket_transfer(*, reconnect_bound_ms, max_reconnects):
    return SocketArchiveTransfer(
        timeout_s=TRANSFER_TIMEOUT_S,
        transfer_timeout_s=GATE_A_OPERATION_CUTOFF_MS / 1000,
        max_reconnects=max_reconnects,
        max_reconnect_seconds=reconnect_bound_ms / 1000,
    )


def run_gate_a_export(
    *,
    source,
    sanitized,
    destination,
    spool_root,
    fixture_proof,
    fixture_proof_sha256,
    sizing_proof,
    expected_pins,
    spool_manifest,
    sanitize,
    send_phase,
    sample,
    monotonic=time.monotonic,
    minimum_spool_raw_bytes=0,
    registered_fixture_rows=701_418,
    binding=None,
    expected_archive_inventory=None,
):
    """Run the sender sequence through the Package A receiver-role adapter.

    `send_phase` starts the same receiver host/port for each bounded manifest,
    sends with SocketArchiveTransfer, obtains the phase receipt, and after the
    spool phase returns its full two-store retrieval receipt. Its adapter runs
    over the sender's private-address socket; tests bind it to a local socket.
    """
    started = monotonic()
    deadline = started + GATE_A_OPERATION_CUTOFF_MS / 1000
    maximum = load_maximum(fixture_proof, expected_pins)
    exact(
        maximum.get("registered_archive_rows"),
        registered_fixture_rows,
        "gate_a:fixture_rows",
    )
    exact(
        maximum.get("schedule_ms"),
        [ATTEMPT_MS] * 3 + [RESET_MS] * 2,
        "gate_a:fixture_schedule",
    )
    source_inventory = inventory(Path(source))
    exact(source_inventory, maximum["fixture_inventory"], "gate_a:fixture_inventory")
    exact(spool_manifest.get("schema"), "inf037b-gate-a-spool-v2", "gate_a:spool_schema")
    exact(
        spool_manifest.get("fixture", {}).get("proof_sha256"),
        fixture_proof_sha256,
        "gate_a:spool_fixture_proof",
    )
    exact(
        spool_manifest.get("fixture", {}).get("source_lf_sha256"),
        current_sources(),
        "gate_a:spool_fixture_sources",
    )
    exact(spool_manifest.get("fixture", {}).get("pins"), expected_pins, "gate_a:spool_fixture_pins")
    exact(
        spool_manifest.get("fixture", {}).get("inventory"),
        source_inventory,
        "gate_a:spool_fixture_inventory",
    )
    exact(
        spool_manifest.get("fixture", {}).get("registered_archive_rows"),
        registered_fixture_rows,
        "gate_a:spool_fixture_rows",
    )
    exact(
        spool_manifest.get("fixture", {}).get("schedule_ms"),
        [ATTEMPT_MS] * 3 + [RESET_MS] * 2,
        "gate_a:spool_fixture_schedule",
    )
    exact(
        spool_manifest.get("allowance", {}).get("id"),
        "r436-round318.maximum-archive-as-wire-floor",
        "gate_a:spool_allowance_id",
    )
    exact(
        spool_manifest.get("allowance", {}).get("raw_bytes"),
        minimum_spool_raw_bytes,
        "gate_a:spool_allowance_floor",
    )
    exact(
        spool_manifest.get("generator", {}).get("id"),
        "gate-a.capture-owner-retainer.v1",
        "gate_a:spool_generator",
    )
    validate_export_sizing_proof(
        sizing_proof,
        source_inventory,
        pins=expected_pins,
        fixture_proof_sha256=fixture_proof_sha256,
    )
    reconnect_bound_ms = sizing_proof["reconnect_bound_ms"]
    archive_state = {}
    phase_receipts = []
    transfer_metrics = {}

    def archive_transfer(*, sanitized, sanitized_inventory, destination, transfer_start):
        if expected_archive_inventory is not None:
            exact(
                sanitized_inventory, expected_archive_inventory, "gate_a:archive_expected_inventory"
            )
        artifacts = {"archive/" + name: Path(sanitized) / name for name in sanitized_inventory}
        source_manifest_sha256 = sha((Path(sanitized) / "SHA256SUMS").read_bytes())
        receiver_result = send_phase(
            phase="archive",
            artifacts=artifacts,
            manifest=sanitized_inventory,
            transfer_id="gate-a-archive-" + fixture_proof_sha256[:16],
            max_total_bytes=max(1, 2 * sizing_proof["raw_bytes"]),
            max_objects=len(artifacts),
            deadline_monotonic=deadline,
            max_reconnects=1,
            max_reconnect_seconds=reconnect_bound_ms / 1000,
            induce_drop=True,
            previous_phases=(),
        )
        transfer_receipt = receiver_result["transfer_receipt"]
        receiver_receipt = receiver_result["receiver_receipt"]
        require(
            any(event.get("event") == "ack_dropped" for event in receiver_receipt["events"]),
            "gate_a:induced_drop_missing",
        )
        require(
            transfer_receipt["reconnect_attempts"] == 1,
            "gate_a:induced_reconnect_missing",
        )
        elapsed_ms = receiver_result["upper_transfer_elapsed_ms"]
        require(integer(elapsed_ms) and elapsed_ms > 0, "gate_a:transfer_elapsed")
        actual_reconnect_ms = math.ceil(transfer_receipt["reconnect_seconds"] * 1000)
        require(actual_reconnect_ms <= reconnect_bound_ms, "gate_a:reconnect_bound")
        destination_files = {
            key.removeprefix("archive/"): {
                "bytes": facts["bytes"],
                "sha256": facts["sha256"],
            }
            for key, facts in receiver_receipt["store_receipt"]["recovery"]["manifest"].items()
        }
        require(set(destination_files) == set(sanitized_inventory), "gate_a:archive_inventory")
        destination_artifacts = {
            name: {
                "path": (Path("/gate-a-receiver-readback") / name).as_posix(),
                **facts,
            }
            for name, facts in destination_files.items()
        }
        transfer_metrics.update(
            transfer_receipt=transfer_receipt,
            receiver_receipt=receiver_receipt,
            upper_transfer_elapsed_ms=elapsed_ms,
            readback_bytes=sum(facts["bytes"] for facts in destination_files.values()),
            reconnect_elapsed_ms=actual_reconnect_ms,
        )
        archive_state["receiver"] = receiver_result
        phase_receipts.append(receiver_receipt)
        transfer_end = receiver_result["transfer_end"]
        return {
            "interrupted": {
                "complete": False,
                "event": "induced_drop_ack",
                "source_manifest_sha256": source_manifest_sha256,
            },
            "resumed": {
                "complete": True,
                **transfer_receipt,
                "source_manifest_sha256": source_manifest_sha256,
            },
            "destination_inventory": destination_files,
            "destination_artifacts": destination_artifacts,
            "transfer_end": transfer_end,
            "transfer_start": receiver_result["transfer_start"],
            "reconnect_elapsed_ms": actual_reconnect_ms,
        }

    def spool_and_store(_archive_result):
        require(monotonic() < deadline, "gate_a:deadline")
        verified_spool = verify_wire_spool(
            spool_root,
            expected_inventory=spool_manifest["spool"]["inventory"],
            minimum_raw_bytes=minimum_spool_raw_bytes,
            objects=14,
        )
        spool_artifacts = {
            "spool/" + name: Path(spool_root) / name for name in verified_spool["inventory"]
        }
        archive_receiver = archive_state["receiver"]
        archive_receipt = archive_receiver["receiver_receipt"]["store_receipt"]
        used_reconnects = archive_receiver["transfer_receipt"]["reconnect_attempts"]
        used_seconds = archive_receiver["transfer_receipt"]["reconnect_seconds"]
        spool_total_bytes = sum(facts["bytes"] for facts in verified_spool["inventory"].values())
        archive_object_count = len(
            archive_receiver["receiver_receipt"]["store_receipt"]["recovery"]["manifest"]
        )
        spool_receiver = send_phase(
            phase="spool",
            artifacts=spool_artifacts,
            manifest=verified_spool["inventory"],
            transfer_id="gate-a-spool-" + spool_manifest["spool"]["inventory_sha256"][:16],
            max_total_bytes=2 * sizing_proof["raw_bytes"] + spool_total_bytes,
            max_objects=archive_object_count + 14,
            deadline_monotonic=deadline,
            max_reconnects=max(0, 1 - used_reconnects),
            max_reconnect_seconds=max(0.0, reconnect_bound_ms / 1000 - used_seconds),
            induce_drop=False,
            previous_phases=[archive_receiver["receiver_receipt"]],
        )
        phase_receipts.append(spool_receiver["receiver_receipt"])
        require(monotonic() < deadline, "gate_a:deadline")
        retrieval = spool_receiver["receiver_receipt"].get("full_retrieval", {})
        exact(retrieval.get("complete"), True, "gate_a:full_retrieval")
        exact(
            retrieval.get("object_count"),
            len(archive_receiver["receiver_receipt"]["store_receipt"]["recovery"]["manifest"]) + 14,
            "gate_a:full_retrieval_count",
        )
        return {
            "spool_verification": verified_spool,
            "spool_transfer": spool_receiver["transfer_receipt"],
            "archive_store_receipt": archive_receipt,
            "spool_receiver_receipt": spool_receiver["receiver_receipt"],
            "full_retrieval": retrieval,
        }

    capture_raw, artifacts = capture_export(
        binding=binding or {"pins": expected_pins},
        source=source,
        sanitized=sanitized,
        destination=destination,
        sanitize=sanitize,
        sample=sample,
        reconnect_ms=reconnect_bound_ms,
        network_transfer=archive_transfer,
        after_transfer=spool_and_store,
    )
    validate_export_archives(capture_raw, artifacts, readback=True)
    operation_ms = math.ceil((monotonic() - started) * 1000)
    transfer_rate = (
        transfer_metrics["readback_bytes"] * 1000 // transfer_metrics["upper_transfer_elapsed_ms"]
    )
    require(transfer_rate > 0, "gate_a:transfer_rate")
    formula = transfer_formula_ms(sizing_proof["raw_bytes"], transfer_rate, reconnect_bound_ms)
    verdict = gate_a_verdict(
        operation_ms=operation_ms,
        o_export_ms=operation_ms,
        transfer_formula_ms_value=formula,
    )
    return {
        "schema": "inf037b-gate-a-sender-receipt-v1",
        "status": verdict["status"],
        "verdict": verdict,
        "operation_deadline_monotonic": deadline,
        "operation_ms": operation_ms,
        "o_export_ms": operation_ms,
        "raw_bytes": sizing_proof["raw_bytes"],
        "archive_readback_bytes": transfer_metrics["readback_bytes"],
        "upper_transfer_elapsed_ms": transfer_metrics["upper_transfer_elapsed_ms"],
        "minimum_bytes_per_second": transfer_rate,
        "reconnect_bound_ms": reconnect_bound_ms,
        "reconnect_elapsed_ms": transfer_metrics["reconnect_elapsed_ms"],
        "transfer_formula_ms": formula,
        "capture_export_sha256": sha(capture_raw),
        "capture_export": json.loads(capture_raw),
        "archive_transfer": transfer_metrics["transfer_receipt"],
        "phase_receipts": phase_receipts,
        "post_transfer": json.loads(capture_raw).get("gate_a_post_transfer"),
    }


class GateAReceiverSupervisor:
    """Package A receiver role for two bounded phases on one private TCP listener."""

    def __init__(self, config, *, sleep=time.sleep, monotonic=time.monotonic):
        self.config = dict(config)
        self.sleep, self.monotonic = sleep, monotonic
        self.lock = threading.RLock()
        self.current = None
        self.phases = []
        self.server = None
        self.thread = None
        self.service_deadline = None

    def start(self):
        supervisor = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(60)
                stream = self.request.makefile("rwb")
                receiver = None
                request = None
                try:
                    request = _read_frame(stream)
                    operation = request.get("op")
                    if operation == "manifest":
                        with supervisor.lock:
                            expected_phase = "archive" if not supervisor.phases else "spool"
                            exact(request.get("phase"), expected_phase, "gate_a:phase_order")
                            require(supervisor.current is None, "gate_a:phase_busy")
                            transfer_id = request.get("transfer_id")
                            require(
                                isinstance(transfer_id, str)
                                and transfer_id.startswith("gate-a-" + expected_phase + "-"),
                                "gate_a:transfer_id",
                            )
                            manifest = request.get("manifest")
                            exact(
                                sha(encode(manifest)),
                                request.get("manifest_sha256"),
                                "gate_a:manifest_hash",
                            )
                            role = GateAReceiverRole(
                                phase=expected_phase,
                                transfer_id=transfer_id,
                                manifest=manifest,
                                recovery_root=supervisor.config["recovery_root"],
                                bucket=supervisor.config["bucket"],
                                prefix=supervisor.config["prefix"],
                                max_total_bytes=request["max_total_bytes"],
                                max_objects=request["max_objects"],
                                port=supervisor.config["port"],
                                receipt_path=Path(supervisor.config["recovery_root"])
                                / "receipts"
                                / f"{transfer_id}.json",
                                previous_phases=supervisor.phases,
                                endpoint_url=supervisor.config.get("endpoint_url"),
                                region=supervisor.config.get("region", "us-east-1"),
                                induce_drop=request.get("induce_drop", False),
                                transfer_root=supervisor.config.get("transfer_root"),
                                host=supervisor.config.get("host", "0.0.0.0"),
                                timeout_s=max(
                                    1,
                                    math.ceil(supervisor.service_deadline - supervisor.monotonic()),
                                ),
                            )
                            role.attach()
                            supervisor.current = role
                            receiver = role.receiver
                        _write_frame(
                            stream,
                            {
                                "status": "ok",
                                "transfer_id": transfer_id,
                                "request_id": request["request_id"],
                                "key": "__manifest__",
                                "manifest_sha256": receiver.manifest_sha256,
                            },
                        )
                        return

                    if operation == "complete":
                        with supervisor.lock:
                            transfer_id = request.get("transfer_id")
                            prior = next(
                                (
                                    row
                                    for row in supervisor.phases
                                    if row.get("transfer_id") == transfer_id
                                ),
                                None,
                            )
                            role = supervisor.current
                            if prior is None:
                                require(
                                    role is not None and role.receiver is not None,
                                    "gate_a:phase_not_started",
                                )
                                exact(transfer_id, role.transfer_id, "gate_a:transfer_id")
                                receiver = role.receiver
                                exact(
                                    request.get("manifest_sha256"),
                                    receiver.manifest_sha256,
                                    "gate_a:manifest_hash",
                                )
                                full_receipt = role.finish()
                                supervisor.phases.append(full_receipt)
                                supervisor.current = None
                            else:
                                exact(
                                    request.get("manifest_sha256"),
                                    prior["manifest_sha256"],
                                    "gate_a:manifest_hash",
                                )
                                full_receipt = prior
                        compact = _compact_phase_receipt(full_receipt)
                        _write_frame(
                            stream,
                            {
                                "status": "ok",
                                "transfer_id": transfer_id,
                                "request_id": request["request_id"],
                                "key": "__phase__",
                                "durable": True,
                                "receiver_receipt": compact,
                            },
                        )
                        return

                    with supervisor.lock:
                        role = supervisor.current
                        require(
                            role is not None and role.receiver is not None,
                            "gate_a:phase_not_started",
                        )
                        receiver = role.receiver

                    with receiver._state_lock:
                        response = receiver._handle(request, stream)
                    fault = receiver._take_fault() if operation == "chunk" else None
                    if fault == "drop_ack":
                        receiver.events.append(
                            {"event": "ack_dropped", "request_id": request["request_id"]}
                        )
                        return
                    if fault == "late_ack":
                        receiver.events.append(
                            {"event": "ack_late", "request_id": request["request_id"]}
                        )
                        time.sleep(0.25)
                    if fault == "stale_ack":
                        response["request_id"] = "stale-" + response["request_id"]
                    encoded = encode(response)
                    if fault == "duplicate_ack":
                        receiver.events.append(
                            {"event": "ack_duplicated", "request_id": request["request_id"]}
                        )
                        stream.write(encoded + encoded)
                    else:
                        stream.write(encoded)
                    stream.flush()
                except (BrokenPipeError, ConnectionResetError, TimeoutError, OSError) as exc:
                    if receiver is not None:
                        receiver.events.append(
                            {"event": "client_disconnected", "reason": type(exc).__name__}
                        )
                except Exception as exc:
                    try:
                        _write_frame(
                            stream,
                            {
                                "status": "refused",
                                "reason": str(exc)
                                if isinstance(exc, ValueError)
                                else "transfer:receiver_error",
                            },
                        )
                    except OSError:
                        pass
                finally:
                    stream.close()

        self.server = _TransferTCPServer(
            (self.config.get("host", "0.0.0.0"), self.config["port"]), Handler
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.service_deadline = self.monotonic() + self.config["service_timeout_s"]
        return self.server.server_address

    def wait(self):
        require(self.server is not None, "gate_a:receiver_not_started")
        try:
            while self.monotonic() < self.service_deadline:
                if len(self.phases) == 2 and self.current is None:
                    return {"complete": True, "phases": self.phases}
                self.sleep(min(0.25, max(0.0, self.service_deadline - self.monotonic())))
            raise TimeoutError("gate_a:receiver_service_deadline")
        finally:
            self.server.shutdown()
            self.server.server_close()
            self.thread.join(timeout=5)

    def run(self):
        self.start()
        return self.wait()


class GateASenderRole:
    """Package A sender role for the source-current fixture and staged wire spool."""

    def __init__(self, config, output, *, sleep=time.sleep, monotonic=time.monotonic):
        self.config, self.output = dict(config), Path(output)
        for name in (
            "specs_path",
            "sanitizer_key_path",
            "fixture_proof_path",
            "sizing_proof_path",
            "spool_manifest_path",
            "source_path",
            "spool_path",
            "expected_archive_inventory_path",
        ):
            if name in self.config:
                self.config[name] = Path(self.config[name]).resolve()
        self.sleep, self.monotonic = sleep, monotonic
        try:
            self.boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        except OSError as exc:
            raise ValueError("gate_a:sender_linux_boot_id") from exc

    def sample(self):
        value = math.floor(self.monotonic() * 1000)
        return {
            "clock_id": "gate-a-sender-monotonic",
            "boot_id": self.boot_id,
            "ms": [value, value],
        }

    def phase_sender(self, **phase):
        artifacts = phase["artifacts"]
        manifest = phase["manifest"]
        prefix = phase["phase"] + "/"
        require(
            all(name.startswith(prefix) for name in artifacts),
            "gate_a:sender_manifest_prefix",
        )
        exact(
            {
                name.removeprefix(prefix): file_facts(path)
                for name, path in sorted(artifacts.items())
            },
            manifest,
            "gate_a:sender_manifest_facts",
        )
        transfer_id = phase["transfer_id"]
        address = (self.config["receiver_private_address"], self.config["transfer_port"])
        transfer = SocketArchiveTransfer(
            timeout_s=TRANSFER_TIMEOUT_S,
            transfer_timeout_s=GATE_A_OPERATION_CUTOFF_MS / 1000,
            max_reconnects=phase["max_reconnects"],
            max_reconnect_seconds=phase["max_reconnect_seconds"],
            monotonic=self.monotonic,
        )
        transfer_start = self.sample()
        start_ms = transfer_start["ms"][0]
        started = self.monotonic()
        transfer_receipt = transfer.transfer(
            artifacts,
            address,
            transfer_id=transfer_id,
            max_total_bytes=phase["max_total_bytes"],
            max_objects=phase["max_objects"],
            deadline_monotonic=phase["deadline_monotonic"],
            max_reconnects=phase["max_reconnects"],
            max_reconnect_seconds=phase["max_reconnect_seconds"],
            gate_a_phase={"phase": phase["phase"], "induce_drop": phase["induce_drop"]},
        )
        transfer_end = self.sample()
        require(self.monotonic() >= started, "gate_a:monotonic_order")
        upper_transfer_elapsed_ms = transfer_end["ms"][0] - start_ms
        require(upper_transfer_elapsed_ms > 0, "gate_a:transfer_elapsed")
        receiver_receipt = transfer_receipt["receiver_receipt"]
        exact(receiver_receipt.get("phase"), phase["phase"], "gate_a:result_phase")
        exact(receiver_receipt.get("transfer_id"), transfer_id, "gate_a:result_join")
        return {
            "transfer_receipt": transfer_receipt,
            "receiver_receipt": receiver_receipt,
            "upper_transfer_elapsed_ms": upper_transfer_elapsed_ms,
            "transfer_start": transfer_start,
            "transfer_end": transfer_end,
        }

    def run(self):
        from .inf037b_campaign import sanitized_campaign

        config = self.config
        specs = json.loads(Path(config["specs_path"]).read_bytes())
        key = Path(config["sanitizer_key_path"]).read_bytes()
        require(len(key) >= 32, "gate_a:sanitizer_key")
        fixture_proof_sha256 = sha(Path(config["fixture_proof_path"]).read_bytes())
        sizing_proof = json.loads(Path(config["sizing_proof_path"]).read_bytes())
        spool_manifest = json.loads(Path(config["spool_manifest_path"]).read_bytes())

        def sanitize(source, destination):
            return sanitized_campaign(source, destination, specs, key=key)

        self.output.mkdir(parents=True, exist_ok=True)
        result = run_gate_a_export(
            source=config["source_path"],
            sanitized=self.output / "sanitized",
            destination=self.output / "destination",
            spool_root=config["spool_path"],
            fixture_proof={"path": config["fixture_proof_path"], "sha256": fixture_proof_sha256},
            fixture_proof_sha256=fixture_proof_sha256,
            sizing_proof=sizing_proof,
            expected_pins=config["expected_pins"],
            spool_manifest=spool_manifest,
            sanitize=sanitize,
            send_phase=self.phase_sender,
            sample=self.sample,
            monotonic=self.monotonic,
            minimum_spool_raw_bytes=config.get("minimum_spool_raw_bytes", 1_615_101_807),
            registered_fixture_rows=config.get("registered_fixture_rows", 701_418),
            binding=config["binding"],
            expected_archive_inventory=json.loads(
                Path(config["expected_archive_inventory_path"]).read_bytes()
            ),
        )
        save_path = self.output / "gate-a-sender.json"
        save_path.write_bytes(encode(result))
        with save_path.open("rb") as stream:
            os.fsync(stream.fileno())
        sync_directory(self.output)
        return result
