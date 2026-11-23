"""Offline refusal cases for the isolated operator runtime and teardown fence."""

import tarfile
import tempfile
import unittest
from pathlib import Path

from inf060_aws_operator import cleanup_branch
from inf060_operator_packet import COUNTERS, RUNTIME_DATA, verify_runtime
from prepare_inf060_probe import bundle, bytes_facts


class OperatorRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.zero = {key: 0 for key in COUNTERS - {"terraform_resources"}}
        self.zero["empty"] = True
        self.preapply = {
            "service_terminal": True,
            "supervisor_lock_absent": True,
            "consume_absent": True,
            "state_present": False,
            "terraform_resources": 0,
        }

    def test_preapply_exit_allows_operator_destroy(self):
        self.assertEqual(
            cleanup_branch(self.zero, preapply=self.preapply),
            "gpu_never_applied_or_empty_state",
        )

    def test_empty_persisted_state_with_consume_marker_allows_destroy(self):
        self.assertEqual(
            cleanup_branch(
                self.zero,
                preapply={
                    **self.preapply,
                    "consume_absent": False,
                    "state_present": True,
                },
            ),
            "gpu_never_applied_or_empty_state",
        )

    def test_verified_normal_teardown_allows_destroy(self):
        witness = {
            "destroy_completed": True,
            "inventory": {**self.zero, "terraform_resources": 0},
        }
        self.assertEqual(
            cleanup_branch(self.zero, witness=witness), "verified_gpu_teardown"
        )

    def test_withhold_if_remote_or_provider_state_is_ambiguous(self):
        for change in (
            {"service_terminal": False},
            {"supervisor_lock_absent": False},
            {"terraform_resources": 1},
            {"terraform_resources": None},
            {"consume_absent": False},
        ):
            with (
                self.subTest(change=change),
                self.assertRaisesRegex(ValueError, "gpu_teardown_ambiguous"),
            ):
                cleanup_branch(self.zero, preapply={**self.preapply, **change})
        with self.assertRaisesRegex(ValueError, "gpu_teardown_ambiguous"):
            cleanup_branch(self.zero)
        with self.assertRaisesRegex(ValueError, "inventory_unverified"):
            cleanup_branch({**self.zero, "volumes": 1}, preapply=self.preapply)

    def test_missing_bound_data_refused_after_archive_is_repacked(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "runtime.tar.gz"
            mutant = root / "mutant.tar.gz"
            items = {"scripts/entry.py": b"pass", RUNTIME_DATA[0]: b"{}"}
            facts = {name: bytes_facts(data) for name, data in items.items()}
            bundle(source, items)
            verify_runtime(source, facts)
            with (
                tarfile.open(source) as archive,
                tarfile.open(mutant, "w:gz") as output,
            ):
                entry = archive.getmember("scripts/entry.py")
                output.addfile(entry, archive.extractfile(entry))
            with self.assertRaisesRegex(ValueError, "operator_runtime_data:"):
                verify_runtime(mutant, facts)
