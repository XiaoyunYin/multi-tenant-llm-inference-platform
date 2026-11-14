"""Verified frozen evidence survives every archive-deduplication failure."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from inference_platform.routine_aws_tests import prune_verified_run, save, selection, sha


class RoutinePruneTest(unittest.TestCase):
    def test_descriptive_rehearsal_is_a_closed_boolean_selector(self):
        self.assertEqual(
            selection({"descriptive_eks_rehearsal": True}), {"descriptive_eks_rehearsal": True}
        )
        for invalid in ("command", 1, ["aws", "eks"]):
            with (
                self.subTest(invalid=invalid),
                self.assertRaisesRegex(ValueError, "descriptive_eks_rehearsal"),
            ):
                selection({"descriptive_eks_rehearsal": invalid})

    def fixture(self, root):
        directory = root / ".cache/routine-tests/run"
        archive = directory / "operator/receipts.tar.gz"
        archive.parent.mkdir(parents=True)
        archive.write_bytes(b"frozen receipts")
        save(
            directory / "lifecycle.json",
            {
                "retrieval": {"complete": True, "sha256": sha(archive)},
                "cleanup": {"verified": True},
            },
        )
        store = root / ".cache/evidence-store" / sha(archive) / archive.name
        return directory, archive, store

    def test_verified_archives_share_storage_and_second_prune_frees_nothing(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            directory, archive, store = self.fixture(root)
            result = prune_verified_run(directory, root=root)
            self.assertEqual(result["status"], "PASS")
            self.assertEqual(result["logical_bytes_freed"], len(b"frozen receipts"))
            self.assertTrue(archive.samefile(store))
            self.assertEqual(prune_verified_run(directory, root=root)["logical_bytes_freed"], 0)
            receipt = json.loads((directory / "lifecycle.json").read_bytes())
            self.assertEqual(receipt["archive_storage"]["mode"], "hardlink")
            self.assertTrue(receipt["cleanup"]["verified"])

    def test_bad_store_or_link_or_replace_keeps_original_evidence(self):
        for fault in ("store", "link", "replace"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                directory, archive, store = self.fixture(root)
                if fault == "store":
                    store.parent.mkdir(parents=True)
                    store.write_bytes(b"corrupt store")
                    result = prune_verified_run(directory, root=root)
                else:
                    target = "os.link" if fault == "link" else "os.replace"
                    original = os.link if fault == "link" else os.replace

                    def fail_archive_only(
                        source, destination, *, fault=fault, archive=archive, original=original
                    ):
                        if fault == "link" or Path(destination) == archive:
                            raise OSError("archive replacement denied")
                        return original(source, destination)

                    with patch(
                        "inference_platform.routine_aws_tests." + target,
                        side_effect=fail_archive_only,
                    ):
                        result = prune_verified_run(directory, root=root)
                self.assertEqual(result["status"], "FAILED")
                self.assertEqual(archive.read_bytes(), b"frozen receipts")
                self.assertFalse(archive.with_name("receipts.verified-link").exists())
                self.assertTrue(
                    json.loads((directory / "lifecycle.json").read_bytes())["cleanup"]["verified"]
                )

    def test_existing_link_candidate_is_never_deleted_on_refusal(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            directory, archive, _ = self.fixture(root)
            foreign = archive.with_name("receipts.verified-link")
            foreign.write_bytes(b"preexisting pending evidence")
            self.assertEqual(prune_verified_run(directory, root=root)["status"], "FAILED")
            self.assertEqual(foreign.read_bytes(), b"preexisting pending evidence")
            self.assertEqual(archive.read_bytes(), b"frozen receipts")


if __name__ == "__main__":
    unittest.main()
