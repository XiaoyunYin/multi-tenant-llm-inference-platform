from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from inference_platform.inf037b_archive import encode, file_facts, sha
from inference_platform.inf037b_gate_a import (
    GATE_A_OPERATION_CUTOFF_MS,
    REGISTERED_O_EXPORT_MAX_MS,
    REGISTERED_TRANSFER_MAX_MS,
    GateASenderRole,
    gate_a_binding,
    gate_a_verdict,
    produce_export_sizing_proof,
    transfer_formula_ms,
    validate_export_sizing_proof,
)
from inference_platform.inf037b_maximum import current_sources
from inference_platform.inf037b_resolver import ceil_minute

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from build_inf037b_gate_a_packet import cost_forecast, validate_fixture_inputs  # noqa: E402


class GateAVerdictTests(unittest.TestCase):
    def verdict(self, *, operation_ms, o_export_ms=None, formula_ms=None):
        return gate_a_verdict(
            operation_ms=operation_ms,
            o_export_ms=operation_ms if o_export_ms is None else o_export_ms,
            transfer_formula_ms_value=(
                REGISTERED_TRANSFER_MAX_MS if formula_ms is None else formula_ms
            ),
        )

    def test_capture_cutoff_is_inclusive_and_refuses_one_ms_over(self):
        self.assertEqual(self.verdict(operation_ms=1_740_000)["status"], "PASS")
        result = self.verdict(operation_ms=1_740_001)
        self.assertEqual(result["status"], "REFUSED")
        self.assertEqual(result["reason"], "gate_a:o_export_capture_cutoff")
        self.assertEqual(result["operation_cutoff_ms"], GATE_A_OPERATION_CUTOFF_MS)

    def test_registered_o_export_and_transfer_formula_boundaries_are_inclusive(self):
        self.assertEqual(
            self.verdict(
                operation_ms=1_740_000,
                o_export_ms=REGISTERED_O_EXPORT_MAX_MS,
                formula_ms=REGISTERED_TRANSFER_MAX_MS,
            )["status"],
            "PASS",
        )
        over_o_export = self.verdict(
            operation_ms=1_740_000, o_export_ms=REGISTERED_O_EXPORT_MAX_MS + 1
        )
        self.assertEqual(over_o_export["reason"], "gate_a:registered_o_export")
        over_formula = self.verdict(
            operation_ms=1_740_000, formula_ms=REGISTERED_TRANSFER_MAX_MS + 1
        )
        self.assertEqual(over_formula["reason"], "gate_a:transfer_formula")

    def test_forecast_includes_three_ssm_interface_endpoints(self):
        forecast = cost_forecast(
            refresh={
                "utc": "2026-11-02T00:00:00+00:00",
                "on_demand_usd_per_hour": 0.34,
                "gp3_usd_per_gib_month": 0.08,
                "ipv4_usd_per_hour": 0.005,
            },
            recovery_gib=32,
            archive_inventory={"archive.bin": {"bytes": 100}},
            spool_inventory={"raw.bin": {"bytes": 50}},
            input_bundle_bytes=200,
        )
        endpoints = forecast["ssm_interface_endpoints"]
        self.assertEqual(endpoints["count"], 3)
        self.assertEqual(endpoints["services"], ["ssm", "ssmmessages", "ec2messages"])
        self.assertAlmostEqual(endpoints["hourly_cost_usd"], 0.03)
        self.assertAlmostEqual(endpoints["processing_cost_usd"], 0.05)
        expected_task = (
            forecast["hosts"]["cost_usd"]
            + forecast["root_volumes"]["cost_usd"]
            + forecast["recovery_volume"]["cost_usd"]
            + forecast["nat_gateway"]["cost_usd"]
            + forecast["nat_gateway"]["processing_cost_usd"]
            + forecast["public_ipv4"]["cost_usd"]
            + endpoints["hourly_cost_usd"] * forecast["duration_hours"]
            + endpoints["processing_cost_usd"]
            + forecast["s3_standard"]["put_request_cost_usd"]
            + forecast["s3_standard"]["get_request_cost_usd"]
            + forecast["s3_standard"]["list_request_cost_usd"]
            + forecast["s3_standard"]["storage_cost_usd"]
            + 1.0
        )
        self.assertAlmostEqual(forecast["task_cost_usd"], expected_task)

    def test_archive_formula_uses_resolver_ceil_minute_arithmetic(self):
        raw_bytes, rate, reconnect_ms = 1_615_101_807, 900_000, 15_000
        expected = ceil_minute(4 * raw_bytes * 1000 + reconnect_ms * rate, rate)
        self.assertEqual(transfer_formula_ms(raw_bytes, rate, reconnect_ms), expected)

    def test_sizing_proof_binds_inventory_and_the_proposed_reconnect_budget(self):
        from inference_platform.inf037b_archive import file_facts, sha

        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            data = b"registered-source-bytes"
            (source / "client.jsonl").write_bytes(data)
            pins = {"fixture": "a" * 64}
            fixture_hash = sha(b"source-current-fixture-proof")
            proof = produce_export_sizing_proof(
                source,
                pins=pins,
                fixture_proof_sha256=fixture_hash,
            )
            facts = {"client.jsonl": file_facts(source / "client.jsonl")}
            self.assertEqual(proof["raw_bytes"], len(data))
            self.assertEqual(proof["reconnect_bound_ms"], 15_000)
            self.assertEqual(proof["reconnect_bound_status"], "accepted_round_321")
            self.assertEqual(proof["reconnect_derivation"]["sum_ms"], 15_000)
            self.assertIs(
                validate_export_sizing_proof(
                    proof, facts, pins=pins, fixture_proof_sha256=fixture_hash
                ),
                proof,
            )

    def test_sizing_proof_refuses_pending_reconnect_status(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            data = b"registered-source-bytes"
            (source / "client.jsonl").write_bytes(data)
            pins = {"fixture": "a" * 64}
            fixture_hash = sha(b"source-current-fixture-proof")
            proof = produce_export_sizing_proof(
                source,
                pins=pins,
                fixture_proof_sha256=fixture_hash,
            )
            proof["reconnect_bound_status"] = "proposal_pending_exact_plan_review"
            facts = {"client.jsonl": file_facts(source / "client.jsonl")}
            with self.assertRaisesRegex(ValueError, "gate_a:sizing_reconnect_bound_status"):
                validate_export_sizing_proof(
                    proof, facts, pins=pins, fixture_proof_sha256=fixture_hash
                )

    @unittest.skipUnless(os.name == "posix", "fixture capture requires POSIX fsync")
    def test_fixture_producer_output_passes_packet_builder_validation(self):
        from inf037b_fitness_fixture import attach as attach_fitness
        from inf037b_observations_fixture import attach as attach_observations
        from inf037b_setup_fixture import fixture as setup_fixture

        produced = attach_observations(attach_fitness(setup_fixture()), boot="gate-a-source")
        proof_name = produced["maximum_fixture_proof"]["path"]
        proof_value = json.loads(produced["artifacts"][proof_name])
        raw = json.loads(produced["export_raw"])
        with tempfile.TemporaryDirectory(prefix="gate-a-producer-packet-validation-") as temporary:
            root = Path(temporary)
            fixture = root / "fixture"
            fixture.mkdir()
            for name in raw["source"]:
                target = fixture / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(produced["export_artifacts"]["source/" + name], target)
            fixture_inventory = {
                path.relative_to(fixture).as_posix(): file_facts(path)
                for path in sorted(fixture.rglob("*"))
                if path.is_file()
            }
            proof_value.update(
                registered_archive_rows=701_418,
                schedule_ms=[1_560_000] * 3 + [300_000] * 2,
                fixture_inventory=fixture_inventory,
                source_inventory_sha256=sha(encode(fixture_inventory)),
                source_lf_sha256=current_sources(),
            )
            proof_path = root / "fixture-proof.json"
            proof_path.write_bytes(encode(proof_value))
            sizing = produce_export_sizing_proof(
                fixture,
                pins=gate_a_binding()["pins"],
                fixture_proof_sha256=sha(proof_path.read_bytes()),
            )
            sizing_path = root / "sizing-proof.json"
            sizing_path.write_bytes(encode(sizing))
            pins, value, observed, _ = validate_fixture_inputs(fixture, proof_path, sizing_path)
            self.assertEqual(pins, gate_a_binding()["pins"])
            self.assertEqual(value["fixture_inventory"], observed)
            self.assertEqual(value["pins"], produced["binding"]["pins"])

    def test_archive_transfer_bracket_includes_receiver_store_readback_ack(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = root / "file.bin"
            artifact.write_bytes(b"archive bytes")
            manifest = {"file.bin": {"bytes": artifact.stat().st_size}}
            import hashlib

            manifest["file.bin"]["sha256"] = hashlib.sha256(artifact.read_bytes()).hexdigest()
            clock = {"value": 10.0}

            class RecordingTransfer:
                def __init__(self, **_kwargs):
                    pass

                def transfer(self, _artifacts, _address, **kwargs):
                    clock["value"] += 0.25  # sender has sent the archive bytes
                    data_elapsed_seconds = 0.25
                    clock["value"] += 2.25  # receiver stores, reads back, then acknowledges
                    return {
                        "data_elapsed_seconds": data_elapsed_seconds,
                        "elapsed_seconds": 2.5,
                        "reconnect_attempts": 0,
                        "reconnect_seconds": 0.0,
                        "receiver_receipt": {
                            "phase": "archive",
                            "transfer_id": kwargs["transfer_id"],
                        },
                    }

            sender = GateASenderRole(
                {"receiver_private_address": "10.0.0.2", "transfer_port": 38473},
                root / "out",
                monotonic=lambda: clock["value"],
            )
            with patch(
                "inference_platform.inf037b_gate_a.SocketArchiveTransfer", RecordingTransfer
            ):
                result = sender.phase_sender(
                    artifacts={"archive/file.bin": artifact},
                    manifest=manifest,
                    transfer_id="gate-a-archive-fixture",
                    max_total_bytes=1024,
                    max_objects=1,
                    deadline_monotonic=100.0,
                    max_reconnects=1,
                    max_reconnect_seconds=15.0,
                    induce_drop=True,
                    phase="archive",
                )
            self.assertEqual(result["upper_transfer_elapsed_ms"], 2500)
            self.assertEqual(result["transfer_receipt"]["data_elapsed_seconds"], 0.25)


if __name__ == "__main__":
    unittest.main()
