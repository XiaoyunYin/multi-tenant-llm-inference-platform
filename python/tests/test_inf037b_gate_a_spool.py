"""Source-current maximum proof and Gate A spool-floor coverage."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from build_inf037b_gate_a_spool import (  # noqa: E402
    REGISTERED_ARCHIVE_ROWS,
    REGISTERED_SCHEDULE_MS,
    build,
    sync_tree,
)

from inference_platform.inf037b_archive import IntegrityError, encode, file_facts, sha  # noqa: E402
from inference_platform.inf037b_gate_a import gate_a_binding, verify_wire_spool  # noqa: E402
from inference_platform.inf037b_maximum import current_sources  # noqa: E402


class GateASpoolTests(unittest.TestCase):
    PINS = gate_a_binding()["pins"]

    def make_fixture(self, root):
        fixture = root / "fixture"
        fixture.mkdir()
        row_files = {
            "raw/client.jsonl": b"x\n" * (REGISTERED_ARCHIVE_ROWS - 6),
            "raw/clocks.jsonl": b"x\n",
            "raw/controller.jsonl": b"x\n",
            "raw/gateway.jsonl": b"x\n",
            "raw/kubernetes.jsonl": b"x\n",
            "raw/redis.jsonl": b"x\n",
            "raw/vllm.jsonl": b"x\n",
        }
        files = {
            **row_files,
            "registration.json": b"{}\n",
            "attempts.jsonl": b"{}\n",
            "SHA256SUMS": b"test fixture\n",
        }
        for name, content in files.items():
            path = fixture / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        facts = {name: file_facts(fixture / name) for name in files}
        proof = root / "maximum-fixture.json"
        proof_value = {
            "subject": "lifecycle:maximum_export_fixture",
            "pins": self.PINS,
            "schedule_ms": REGISTERED_SCHEDULE_MS,
            "source_lf_sha256": current_sources(),
            "registered_archive_rows": REGISTERED_ARCHIVE_ROWS,
            "fixture_inventory": facts,
            "source_inventory_sha256": sha(encode(facts)),
        }
        proof.write_bytes(encode(proof_value))
        return fixture, proof, facts

    def refresh_fixture_proof(self, fixture, proof):
        value = json.loads(proof.read_text(encoding="utf-8"))
        facts = {
            path.relative_to(fixture).as_posix(): file_facts(path)
            for path in sorted(fixture.rglob("*"))
            if path.is_file()
        }
        value["fixture_inventory"] = facts
        value["source_inventory_sha256"] = sha(encode(facts))
        proof.write_bytes(encode(value))

    def test_windows_packet_staging_syncs_files_without_directory_fsync(self):
        with tempfile.TemporaryDirectory(prefix="gate-a-windows-sync-") as temporary:
            root = Path(temporary)
            nested = root / "nested"
            nested.mkdir()
            payload = nested / "record.bin"
            payload.write_bytes(b"packet-source")
            with patch.object(
                os, "open", side_effect=AssertionError("directory fsync unsupported")
            ):
                sync_tree(root, platform_name="nt")
            self.assertEqual(payload.read_bytes(), b"packet-source")

    def test_source_current_maximum_stages_and_records_actual_fixture_and_spool(self):
        with tempfile.TemporaryDirectory(prefix="inf037b-gate-a-spool-") as temporary:
            root = Path(temporary)
            fixture, proof, facts = self.make_fixture(root)
            expected_fixture_bytes = sum(item["bytes"] for item in facts.values())
            result = build(
                fixture,
                proof,
                root / "output",
                expected_pins=self.PINS,
                raw_bytes_allowance=7,
            )

            self.assertEqual(result["fixture"]["inventory"], facts)
            self.assertEqual(result["fixture"]["bytes"], expected_fixture_bytes)
            self.assertEqual(result["fixture"]["registered_archive_rows"], REGISTERED_ARCHIVE_ROWS)
            self.assertEqual(result["fixture"]["schedule_ms"], REGISTERED_SCHEDULE_MS)
            self.assertEqual(result["spool"]["raw_bytes"], expected_fixture_bytes)
            self.assertGreaterEqual(result["spool"]["raw_bytes"], result["allowance"]["raw_bytes"])
            self.assertEqual(result["spool"]["file_count"], 14)
            self.assertGreater(result["spool"]["index_bytes"], 0)
            self.assertEqual(result["generator"]["id"], "gate-a.capture-owner-retainer.v1")
            self.assertTrue(result["pre_p_staging"]["readback_verified"])
            output = root / "output"
            client_prefix = sha(b"client")
            self.assertTrue((output / "staged/fixture/raw/client.jsonl").is_file())
            self.assertTrue((output / f"staged/spool/{client_prefix}.bin").is_file())
            self.assertTrue((output / f"staged/spool/{client_prefix}.jsonl").is_file())
            self.assertTrue((output / "manifest.sha256").is_file())

    def test_raw_spool_below_allowance_refuses(self):
        with tempfile.TemporaryDirectory(prefix="inf037b-gate-a-floor-") as temporary:
            root = Path(temporary)
            fixture, proof, facts = self.make_fixture(root)
            fixture_bytes = sum(item["bytes"] for item in facts.values())
            with self.assertRaisesRegex(ValueError, "gate_a_spool:allowance_or_object_count"):
                build(
                    fixture,
                    proof,
                    root / "output",
                    expected_pins=self.PINS,
                    raw_bytes_allowance=fixture_bytes + 1,
                )

    def test_registered_archive_row_count_is_required(self):
        with tempfile.TemporaryDirectory(prefix="inf037b-gate-a-rows-") as temporary:
            root = Path(temporary)
            fixture, proof, _ = self.make_fixture(root)
            value = json.loads(proof.read_text(encoding="utf-8"))
            value["registered_archive_rows"] -= 1
            proof.write_bytes(encode(value))

            with self.assertRaisesRegex(ValueError, "gate_a_spool:registered_archive_rows"):
                build(
                    fixture,
                    proof,
                    root / "output",
                    expected_pins=self.PINS,
                    raw_bytes_allowance=1,
                )
            self.assertFalse((root / "output").exists())

    def test_raw_fixture_with_one_fewer_row_refuses_even_with_matching_proof_inventory(self):
        with tempfile.TemporaryDirectory(prefix="inf037b-gate-a-short-rows-") as temporary:
            root = Path(temporary)
            fixture, proof, _ = self.make_fixture(root)
            client = fixture / "raw/client.jsonl"
            client.write_bytes(client.read_bytes()[:-2])
            self.refresh_fixture_proof(fixture, proof)

            with self.assertRaisesRegex(ValueError, "gate_a_spool:fixture_archive_rows"):
                build(
                    fixture,
                    proof,
                    root / "output",
                    expected_pins=self.PINS,
                    raw_bytes_allowance=1,
                )
            self.assertFalse((root / "output/manifest.json").exists())

    def test_raw_fixture_final_row_without_newline_refuses_even_with_matching_proof_inventory(self):
        with tempfile.TemporaryDirectory(prefix="inf037b-gate-a-no-terminator-") as temporary:
            root = Path(temporary)
            fixture, proof, _ = self.make_fixture(root)
            client = fixture / "raw/client.jsonl"
            # Preserve the independent newline count so the terminator guard,
            # rather than the row-count guard, is the one that refuses.
            client.write_bytes(b"\n" + client.read_bytes()[:-1])
            self.refresh_fixture_proof(fixture, proof)

            with self.assertRaisesRegex(ValueError, "gate_a_spool:fixture_jsonl_terminator"):
                build(
                    fixture,
                    proof,
                    root / "output",
                    expected_pins=self.PINS,
                    raw_bytes_allowance=1,
                )
            self.assertFalse((root / "output/manifest.json").exists())

    def test_corrupted_raw_spool_byte_refuses_on_record_hash(self):
        with tempfile.TemporaryDirectory(prefix="inf037b-gate-a-corrupt-wire-") as temporary:
            root = Path(temporary)
            fixture, proof, _ = self.make_fixture(root)
            result = build(
                fixture,
                proof,
                root / "output",
                expected_pins=self.PINS,
                raw_bytes_allowance=1,
            )
            spool = root / "output/staged/spool"
            raw_path = next(spool.glob("*.bin"))
            with raw_path.open("r+b") as stream:
                first = stream.read(1)
                stream.seek(0)
                stream.write(bytes([first[0] ^ 1]))
            with self.assertRaisesRegex(IntegrityError, "capture:wire_hash"):
                verify_wire_spool(
                    spool,
                    expected_inventory=None,
                    minimum_raw_bytes=1,
                    objects=result["spool"]["object_count"],
                )

    def test_proof_source_hash_or_fixture_hash_mismatch_refuses_before_staging(self):
        with tempfile.TemporaryDirectory(prefix="inf037b-gate-a-proof-") as temporary:
            root = Path(temporary)
            fixture, proof, _ = self.make_fixture(root)
            value = json.loads(proof.read_text(encoding="utf-8"))
            value["source_lf_sha256"] = {}
            proof.write_bytes(encode(value))
            with self.assertRaisesRegex(IntegrityError, "maximum:current_sources"):
                build(
                    fixture,
                    proof,
                    root / "stale",
                    expected_pins=self.PINS,
                    raw_bytes_allowance=1,
                )
            self.assertFalse((root / "stale").exists())

            value["source_lf_sha256"] = current_sources()
            value["fixture_inventory"]["raw/client.jsonl"]["sha256"] = "0" * 64
            value["source_inventory_sha256"] = sha(encode(value["fixture_inventory"]))
            proof.write_bytes(encode(value))
            with self.assertRaisesRegex(ValueError, "gate_a_spool:fixture_proof_inventory"):
                build(
                    fixture,
                    proof,
                    root / "wrong-fixture",
                    expected_pins=self.PINS,
                    raw_bytes_allowance=1,
                )
            self.assertFalse((root / "wrong-fixture").exists())


if __name__ == "__main__":
    unittest.main()
