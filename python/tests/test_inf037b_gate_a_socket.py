from __future__ import annotations

import json
import os
import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from inference_platform.inf037b_archive import encode, sha
from inference_platform.inf037b_contract import ATTEMPT_MS, RESET_MS, SOURCE_KINDS
from inference_platform.inf037b_gate_a import (
    GateAReceiverRole,
    GateAReceiverSupervisor,
    GateASenderRole,
    gate_a_binding,
    inventory,
    produce_export_sizing_proof,
)
from inference_platform.inf037b_maximum import current_sources
from inference_platform.inf037b_transfer import SocketArchiveTransfer


class GateASocketIntegrationTests(unittest.TestCase):
    @unittest.skipUnless(
        os.environ.get("MINIO_TEST_ENDPOINT"),
        "set MINIO_TEST_ENDPOINT to run the real MinIO/POSIX/socket integration",
    )
    def test_manifest_handshake_two_stores_and_two_phases_share_one_listener(self):
        import boto3

        endpoint = os.environ["MINIO_TEST_ENDPOINT"]
        bucket = "gate-a-test-" + uuid.uuid4().hex[:20]
        client = boto3.client(
            "s3",
            endpoint_url=endpoint,
            region_name="us-east-1",
            aws_access_key_id=os.environ.get("MINIO_TEST_ACCESS_KEY", "minioadmin"),
            aws_secret_access_key=os.environ.get("MINIO_TEST_SECRET_KEY", "minioadmin"),
        )
        client.create_bucket(Bucket=bucket)
        temporary = tempfile.TemporaryDirectory(prefix="gate-a-socket-")
        root = Path(temporary.name)
        recovery = root / "recovery"
        recovery.mkdir()
        supervisor = GateAReceiverSupervisor(
            {
                "recovery_root": recovery,
                "bucket": bucket,
                "prefix": "gate-a/test-session",
                "endpoint_url": endpoint,
                "region": "us-east-1",
                "port": 0,
                "private_address": "127.0.0.1",
                "service_timeout_s": 180,
            }
        )
        host, port = supervisor.start()
        result_box = {}

        def wait_receiver():
            try:
                result_box["result"] = supervisor.wait()
            except BaseException as exc:  # surfaced in the test thread below
                result_box["error"] = exc

        waiter = threading.Thread(target=wait_receiver, daemon=True)
        waiter.start()
        try:
            original_finish = GateAReceiverRole.finish
            finish_calls = {"archive": 0, "spool": 0}

            def delayed_finish(role):
                finish_calls[role.phase] += 1
                time.sleep(6 if role.phase == "archive" else 60)
                return original_finish(role)

            archive_path = root / "archive.bin"
            archive_path.write_bytes(b"archive-data" * 8192)
            with patch.object(GateAReceiverRole, "finish", delayed_finish):
                archive = SocketArchiveTransfer(
                    timeout_s=2,
                    transfer_timeout_s=120,
                    max_reconnects=1,
                    max_reconnect_seconds=10,
                ).transfer(
                    {"archive/archive.bin": archive_path},
                    (host, port),
                    transfer_id="gate-a-archive-" + "a" * 16,
                    max_total_bytes=1_000_000,
                    max_objects=1,
                    gate_a_phase={"phase": "archive", "induce_drop": True},
                )
                request_id = sha(
                    encode(
                        [
                            archive["transfer_id"],
                            "complete",
                            archive["manifest_sha256"],
                        ]
                    )
                )
                repeated = SocketArchiveTransfer(timeout_s=2)._exchange(
                    (host, port),
                    {
                        "op": "complete",
                        "transfer_id": archive["transfer_id"],
                        "request_id": request_id,
                        "key": "__phase__",
                        "manifest_sha256": archive["manifest_sha256"],
                    },
                    timeout_s=2,
                )
                self.assertEqual(repeated["receiver_receipt"], archive["receiver_receipt"])
            self.assertEqual(archive["reconnect_attempts"], 1)
            self.assertEqual(finish_calls["archive"], 1)
            self.assertTrue(
                any(
                    event["event"] == "ack_dropped"
                    for event in archive["receiver_receipt"]["events"]
                )
            )

            spool_root = root / "spool"
            spool_root.mkdir()
            spool = {}
            for index in range(14):
                path = spool_root / f"object-{index:02}.bin"
                path.write_bytes(bytes([index]) * (index + 1))
                spool[f"spool/{path.name}"] = path
            with patch.object(GateAReceiverRole, "finish", delayed_finish):
                stored = SocketArchiveTransfer(
                    timeout_s=2,
                    transfer_timeout_s=120,
                    max_reconnects=0,
                    max_reconnect_seconds=0,
                ).transfer(
                    spool,
                    (host, port),
                    transfer_id="gate-a-spool-" + "b" * 16,
                    max_total_bytes=1_000_000,
                    max_objects=15,
                    gate_a_phase={"phase": "spool", "induce_drop": False},
                )
            self.assertEqual(finish_calls["spool"], 1)
            self.assertEqual(stored["receiver_receipt"]["full_retrieval"]["complete"], True)
            self.assertEqual(stored["receiver_receipt"]["full_retrieval"]["object_count"], 15)
            waiter.join(timeout=10)
            self.assertFalse(waiter.is_alive())
            if "error" in result_box:
                raise result_box["error"]
            self.assertTrue(result_box["result"]["complete"])
            self.assertEqual(len(result_box["result"]["phases"]), 2)
            self.assertTrue(
                (recovery / "retrieved/complete/recovery/archive/archive/archive.bin").is_file()
            )
        finally:
            if waiter.is_alive():
                supervisor.service_deadline = supervisor.monotonic()
                supervisor.server.shutdown()
                waiter.join(timeout=5)
            for row in client.list_objects_v2(Bucket=bucket).get("Contents", []):
                client.delete_object(Bucket=bucket, Key=row["Key"])
            client.delete_bucket(Bucket=bucket)
            temporary.cleanup()

    @unittest.skipUnless(
        os.environ.get("MINIO_TEST_ENDPOINT"),
        "set MINIO_TEST_ENDPOINT to run the real sender/supervisor/MinIO/POSIX integration",
    )
    def test_sender_run_sanitizes_transfers_archive_and_spool_and_writes_verdict(self):
        import boto3
        from test_inf037b_collectors import CampaignTests

        endpoint = os.environ["MINIO_TEST_ENDPOINT"]
        bucket = "gate-a-e2e-" + uuid.uuid4().hex[:18]
        client = boto3.client(
            "s3",
            endpoint_url=endpoint,
            region_name="us-east-1",
            aws_access_key_id=os.environ.get("MINIO_TEST_ACCESS_KEY", "minioadmin"),
            aws_secret_access_key=os.environ.get("MINIO_TEST_SECRET_KEY", "minioadmin"),
        )
        client.create_bucket(Bucket=bucket)
        temporary = tempfile.TemporaryDirectory(prefix="gate-a-sender-e2e-")
        root = Path(temporary.name)
        campaign_case = CampaignTests(
            "test_partial_stage_capture_report_and_immutable_reproduction"
        )
        campaign_case.setUp()
        self.addCleanup(campaign_case.doCleanups)
        campaign, _ = campaign_case.campaign(name="gate-a-e2e-campaign")
        campaign.materialize()
        source = campaign.root
        binding = gate_a_binding()
        source_inventory = inventory(source)
        fixture_proof_value = {
            "subject": "lifecycle:maximum_export_fixture",
            "pins": binding["pins"],
            "schedule_ms": [ATTEMPT_MS] * 3 + [RESET_MS] * 2,
            "source_inventory_sha256": sha(encode(source_inventory)),
            "scope": "small-real-campaign-fixture-for-gate-a-sender-integration-test",
            "registered_archive_rows": 1,
            "fixture_inventory": source_inventory,
            "source_lf_sha256": current_sources(),
        }
        fixture_proof_path = root / "fixture-proof.json"
        fixture_proof_path.write_bytes(encode(fixture_proof_value))
        sizing = produce_export_sizing_proof(
            source,
            pins=binding["pins"],
            fixture_proof_sha256=sha(fixture_proof_path.read_bytes()),
        )
        sizing_path = root / "sizing-proof.json"
        sizing_path.write_bytes(encode(sizing))

        spool_root = root / "spool"
        spool_root.mkdir()
        for kind in SOURCE_KINDS:
            body = b"gate-a-e2e-wire-" + kind.encode()
            name = sha(kind.encode())
            (spool_root / f"{name}.bin").write_bytes(body)
            record = {"offset": 0, "length": len(body), "sha256": sha(body)}
            (spool_root / f"{name}.jsonl").write_bytes(encode(record))
        spool_inventory = inventory(spool_root)
        spool_manifest = {
            "schema": "inf037b-gate-a-spool-v2",
            "fixture": {
                "proof_sha256": sha(fixture_proof_path.read_bytes()),
                "source_lf_sha256": current_sources(),
                "pins": binding["pins"],
                "inventory": source_inventory,
                "registered_archive_rows": 1,
                "schedule_ms": [ATTEMPT_MS] * 3 + [RESET_MS] * 2,
            },
            "spool": {
                "inventory": spool_inventory,
                "inventory_sha256": sha(encode(spool_inventory)),
            },
            "allowance": {
                "id": "r436-round318.maximum-archive-as-wire-floor",
                "raw_bytes": 1,
            },
            "generator": {"id": "gate-a.capture-owner-retainer.v1"},
        }
        spool_manifest_path = root / "spool-manifest.json"
        spool_manifest_path.write_bytes(encode(spool_manifest))

        key_path = root / "sanitizer-key.bin"
        key_path.write_bytes(b"gate-a-e2e-sanitizer-key-32-bytes!!")
        specs = [campaign.spec]
        specs_path = root / "specs.json"
        specs_path.write_bytes(encode(specs))
        from inference_platform.inf037b_campaign import sanitized_campaign

        expected_root = root / "expected-sanitized"
        sanitized_campaign(source, expected_root, specs, key=key_path.read_bytes())
        expected_inventory_path = root / "expected-archive-inventory.json"
        expected_inventory_path.write_bytes(encode(inventory(expected_root)))

        recovery = root / "recovery"
        recovery.mkdir()
        supervisor = GateAReceiverSupervisor(
            {
                "recovery_root": recovery,
                "bucket": bucket,
                "prefix": "gate-a/e2e-session",
                "endpoint_url": endpoint,
                "region": "us-east-1",
                "port": 0,
                "service_timeout_s": 180,
            }
        )
        host, port = supervisor.start()
        receiver_result = {}

        def wait_receiver():
            try:
                receiver_result["result"] = supervisor.wait()
            except BaseException as exc:
                receiver_result["error"] = exc

        waiter = threading.Thread(target=wait_receiver, daemon=True)
        waiter.start()
        output = root / "sender-output"
        config = {
            "receiver_private_address": host,
            "transfer_port": port,
            "specs_path": specs_path,
            "sanitizer_key_path": key_path,
            "fixture_proof_path": fixture_proof_path,
            "sizing_proof_path": sizing_path,
            "spool_manifest_path": spool_manifest_path,
            "source_path": source,
            "spool_path": spool_root,
            "expected_pins": binding["pins"],
            "minimum_spool_raw_bytes": 1,
            "registered_fixture_rows": 1,
            "binding": binding,
            "expected_archive_inventory_path": expected_inventory_path,
        }
        try:
            result = GateASenderRole(config, output).run()
            waiter.join(timeout=10)
            self.assertFalse(waiter.is_alive())
            if "error" in receiver_result:
                raise receiver_result["error"]
            self.assertTrue(receiver_result["result"]["complete"])
            self.assertEqual(result["verdict"]["status"], "PASS")
            saved = json.loads((output / "gate-a-sender.json").read_bytes())
            self.assertEqual(saved["verdict"], result["verdict"])
            self.assertTrue(saved["phase_receipts"])
            self.assertEqual(len(saved["phase_receipts"]), 2)
            self.assertTrue((recovery / "retrieved/complete/recovery/spool").is_dir())
        finally:
            if waiter.is_alive():
                supervisor.service_deadline = supervisor.monotonic()
                supervisor.server.shutdown()
                waiter.join(timeout=5)
            for row in client.list_objects_v2(Bucket=bucket).get("Contents", []):
                client.delete_object(Bucket=bucket, Key=row["Key"])
            client.delete_bucket(Bucket=bucket)
            temporary.cleanup()


class GateASenderManifestPathTests(unittest.TestCase):
    def test_manifest_string_paths_are_normalized_for_sender_role(self):
        names = (
            "specs_path",
            "sanitizer_key_path",
            "fixture_proof_path",
            "sizing_proof_path",
            "spool_manifest_path",
            "source_path",
            "spool_path",
            "expected_archive_inventory_path",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = {name: str(root / name) for name in names}
            with patch("inference_platform.inf037b_gate_a.Path.read_text", return_value="boot-id"):
                role = GateASenderRole(config, root / "sender")
            for name in names:
                with self.subTest(name=name):
                    self.assertIsInstance(role.config[name], Path)
                    self.assertEqual(role.config[name], Path(config[name]).resolve())


if __name__ == "__main__":
    unittest.main()
