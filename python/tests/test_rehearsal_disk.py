"""The rehearsal provider is explicit; the real admission gate remains mandatory."""

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from inference_platform.host_disk import MINIMUM_FREE_BYTES, require_disk_headroom
from inference_platform.stage_c import _runtime_readiness
from inference_platform.stage_c_session import record_disk_readiness


class RehearsalDiskTest(unittest.TestCase):
    def test_rehearsal_records_labelled_provider_without_reading_host(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch("inference_platform.stage_c_session.disk_snapshot") as real_disk,
        ):
            result = record_disk_readiness(Path(directory), rehearse=True)
            recorded = json.loads((Path(directory) / "disk-readiness.json").read_text())
        real_disk.assert_not_called()
        self.assertEqual(recorded["source"], "rehearsal")
        self.assertEqual(recorded["status"], "available")
        self.assertEqual(recorded["free_bytes"], MINIMUM_FREE_BYTES)
        self.assertEqual(result["status"], "ok")

    def test_non_rehearsal_gates_exact_real_snapshot_and_records_failure(self):
        for free in (MINIMUM_FREE_BYTES, MINIMUM_FREE_BYTES - 1):
            real = {"status": "available", "free_bytes": free}
            with (
                self.subTest(free=free),
                tempfile.TemporaryDirectory() as directory,
                patch(
                    "inference_platform.stage_c_session.disk_snapshot", return_value=real
                ) as disk,
                patch("inference_platform.host_disk.rehearsal_disk_snapshot") as rehearsal,
                patch(
                    "inference_platform.host_disk.require_disk_headroom",
                    wraps=require_disk_headroom,
                ) as gate,
            ):
                if free == MINIMUM_FREE_BYTES:
                    self.assertEqual(
                        record_disk_readiness(Path(directory), rehearse=False)["status"], "ok"
                    )
                else:
                    with self.assertRaisesRegex(RuntimeError, "below 60 GiB"):
                        record_disk_readiness(Path(directory), rehearse=False)
                disk.assert_called_once_with(refresh=True)
                gate.assert_called_once_with(real)
                self.assertIs(gate.call_args.args[0], real)
                rehearsal.assert_not_called()
                self.assertEqual(
                    json.loads((Path(directory) / "disk-readiness.json").read_text()), real
                )

    def test_non_rehearsal_runtime_rechecks_real_disk_before_health(self):
        config = SimpleNamespace(protocol_version="r0-v2", local_rehearsal=False)
        with (
            patch(
                "inference_platform.host_disk.disk_snapshot",
                return_value={"status": "available", "free_bytes": MINIMUM_FREE_BYTES - 1},
            ) as disk,
            patch("inference_platform.host_disk.rehearsal_disk_snapshot") as rehearsal,
            patch("inference_platform.stage_c._health_preflight") as health,
        ):
            result = _runtime_readiness(config, 100)
        self.assertEqual(result["status"], "failed")
        disk.assert_called_once_with(refresh=True)
        rehearsal.assert_not_called()
        health.assert_not_called()
