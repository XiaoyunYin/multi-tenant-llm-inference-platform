from __future__ import annotations

import hashlib
import io
import json
import tarfile
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from package_a_host import Host


class GateAHostInputStagingTests(unittest.TestCase):
    def _archive(self):
        payload = b"source-current fixture member"
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            info = tarfile.TarInfo("fixture/raw/client.jsonl")
            info.size = len(payload)
            info.mode = 0o600
            archive.addfile(info, io.BytesIO(payload))
        return buffer.getvalue(), payload

    def _manifest(self, archive, payload):
        inventory = {
            "fixture/raw/client.jsonl": {
                "bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        }
        return {
            "gate_a_inputs": {
                "bundle_bytes": len(archive),
                "bundle_sha256": hashlib.sha256(archive).hexdigest(),
                "inventory": inventory,
            }
        }

    def _stage(self, host, manifest, archive, chunk_bytes=64):
        encoded = json.dumps(manifest, sort_keys=True).encode()
        host.manifest_hash = hashlib.sha256(encoded).hexdigest()
        host.dispatch("/manifest", encoded, {})
        offset = 0
        while offset < len(archive):
            chunk = archive[offset : offset + chunk_bytes]
            host.dispatch(
                f"/input-upload/{offset}",
                chunk,
                {"X-Chunk-SHA256": hashlib.sha256(chunk).hexdigest()},
            )
            offset += len(chunk)
        return host.dispatch("/stage-inputs", b"", {})

    def test_hash_bound_gate_a_input_stage_is_fsynced_and_read_back(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive, payload = self._archive()
            manifest = self._manifest(archive, payload)
            root = Path(temporary) / "host"
            host = Host(root, "token", "unused", time.time() + 60)
            receipt = self._stage(host, manifest, archive)
            self.assertTrue(receipt["readback_verified"])
            self.assertEqual(receipt["inventory"], manifest["gate_a_inputs"]["inventory"])
            staged = root / "gate-a-inputs/fixture/raw/client.jsonl"
            self.assertEqual(staged.read_bytes(), payload)
            self.assertTrue((root / "gate-a-inputs-staged.json").is_file())

    def test_gate_a_input_inventory_mismatch_refuses_before_stage(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive, payload = self._archive()
            manifest = self._manifest(archive, payload)
            manifest["gate_a_inputs"]["inventory"]["fixture/raw/client.jsonl"]["sha256"] = "0" * 64
            host = Host(Path(temporary) / "host", "token", "unused", time.time() + 60)
            with self.assertRaisesRegex(ValueError, "gate_a_input_archive_hash"):
                self._stage(host, manifest, archive)
            self.assertFalse(host.input_stage.exists())
            self.assertFalse(host.input_receipt.exists())

    def test_gate_a_input_read_only_s3_staging_is_downloaded_and_hash_verified(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive, payload = self._archive()
            manifest = self._manifest(archive, payload)
            staging = {
                "bucket": "gate-a-test-bucket",
                "key": "gate-a/r366-test-session/input/gate-a-inputs.tar",
                "bundle_bytes": len(archive),
                "bundle_sha256": hashlib.sha256(archive).hexdigest(),
            }
            manifest.update(session="r366-test-session", bucket_name=staging["bucket"])
            manifest["gate_a_inputs"]["s3_staging"] = staging
            host = Host(Path(temporary) / "host", "token", "unused", time.time() + 60)
            host.manifest = manifest
            signed_url = (
                "https://gate-a-test-bucket.s3.us-east-1.amazonaws.com/"
                "gate-a/r366-test-session/input/gate-a-inputs.tar?"
                "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=secret"
            )

            response = io.BytesIO(archive)
            response.status = 200

            with patch("package_a_host.urlopen", return_value=response) as open_url:
                receipt = host.dispatch(
                    "/stage-inputs",
                    json.dumps(
                        {"deadline_epoch": time.time() + 30, "download_url": signed_url}
                    ).encode(),
                    {},
                )
            self.assertEqual(open_url.call_args.args[0].full_url, signed_url)
            self.assertEqual(receipt["s3_staging_key"], staging["key"])
            self.assertEqual(receipt["bundle_sha256"], staging["bundle_sha256"])
            self.assertEqual((host.input_stage / "fixture/raw/client.jsonl").read_bytes(), payload)
            self.assertNotIn(signed_url.encode(), host.input_receipt.read_bytes())

    def test_gate_a_s3_stage_refuses_without_presigned_url(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive, payload = self._archive()
            manifest = self._manifest(archive, payload)
            staging = {
                "bucket": "gate-a-test-bucket",
                "key": "gate-a/r366-test-session/input/gate-a-inputs.tar",
                "bundle_bytes": len(archive),
                "bundle_sha256": hashlib.sha256(archive).hexdigest(),
            }
            manifest.update(session="r366-test-session", bucket_name=staging["bucket"])
            manifest["gate_a_inputs"]["s3_staging"] = staging
            host = Host(Path(temporary) / "host", "token", "unused", time.time() + 60)
            host.manifest = manifest
            with self.assertRaisesRegex(ValueError, "gate_a_input_s3_download_url"):
                host.dispatch("/stage-inputs", b"{}", {})
            self.assertFalse(host.input_partial.exists())
            self.assertFalse(host.input_stage.exists())

    def test_gate_a_s3_stage_refuses_sigv2_url(self):
        with self.assertRaisesRegex(ValueError, "gate_a_input_s3_download_url"):
            from package_a_host import validate_gate_a_s3_get_url

            validate_gate_a_s3_get_url(
                "https://gate-a-test-bucket.s3.us-east-1.amazonaws.com/"
                "gate-a/r366-test-session/input/gate-a-inputs.tar?"
                "AWSAccessKeyId=fixture&Signature=secret&Expires=900",
                bucket="gate-a-test-bucket",
                key="gate-a/r366-test-session/input/gate-a-inputs.tar",
            )

    def test_gate_a_s3_stage_accepts_sigv4_path_style_url(self):
        from package_a_host import validate_gate_a_s3_get_url

        parsed = validate_gate_a_s3_get_url(
            "https://s3.us-east-1.amazonaws.com/gate-a-test-bucket/"
            "gate-a/r366-test-session/input/gate-a-inputs.tar?"
            "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=secret",
            bucket="gate-a-test-bucket",
            key="gate-a/r366-test-session/input/gate-a-inputs.tar",
        )
        self.assertEqual(parsed.hostname, "s3.us-east-1.amazonaws.com")

    def test_gate_a_runner_start_refuses_without_pre_p_staging_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive, payload = self._archive()
            manifest = self._manifest(archive, payload)
            host = Host(Path(temporary) / "host", "token", "unused", time.time() + 60)
            host.manifest = manifest
            (host.root / "stage.json").write_text("{}")
            with self.assertRaisesRegex(ValueError, "gate_a_inputs_not_staged_before_P"):
                host.dispatch("/start", b"", {})
            self.assertIsNone(host.child)

    def test_gate_a_staged_inputs_are_rechecked_before_runner_start(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive, payload = self._archive()
            manifest = self._manifest(archive, payload)
            host = Host(Path(temporary) / "host", "token", "unused", time.time() + 60)
            self._stage(host, manifest, archive)
            (host.root / "stage.json").write_text("{}")
            (host.input_stage / "fixture/raw/client.jsonl").write_bytes(payload + b"changed")
            with self.assertRaisesRegex(ValueError, "gate_a_input_stage_changed"):
                host.dispatch("/start", b"", {})
            self.assertIsNone(host.child)


if __name__ == "__main__":
    unittest.main()
