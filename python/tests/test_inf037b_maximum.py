"""Exact-payload/source-current maximum proof and original P joins."""

import copy
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from test_inf037b_preparation import BINDING, admitted, point, staged

from inference_platform.inf037b_archive import IntegrityError, encode, sha
from inference_platform.inf037b_maximum import current_sources, load_maximum
from inference_platform.inf037b_setup import SetupCommands


def proof():
    inventory = {
        name: {"bytes": 7, "sha256": "a" * 64}
        for name in ("registration.json", "attempts.jsonl", "SHA256SUMS", "raw/controller.jsonl")
    }
    return {
        "subject": "lifecycle:maximum_export_fixture",
        "pins": BINDING["pins"],
        "schedule_ms": [1560000] * 3 + [300000] * 2,
        "source_lf_sha256": current_sources(),
        "fixture_inventory": inventory,
        "source_inventory_sha256": sha(encode(inventory)),
    }


class MaximumTests(unittest.TestCase):
    def test_exact_hash_canonical_subject_pins_schedule_sources_and_inventory(self):
        value = proof()
        with TemporaryDirectory() as directory:
            path = Path(directory) / "maximum"

            def load(item, *, padding=b"", digest=None):
                raw = padding + encode(item)
                path.write_bytes(raw)
                return load_maximum(
                    {"path": str(path), "sha256": digest or sha(raw)}, BINDING["pins"]
                )

            self.assertEqual(load(value), value)
            with self.assertRaisesRegex(IntegrityError, "maximum:artifact_hash"):
                load(value, digest="b" * 64)
            with self.assertRaisesRegex(IntegrityError, "maximum:canonical"):
                load(value, padding=b" ")
            changes = [
                ("subject", "wrong", "subject"),
                ("pins", {}, "pins"),
                ("schedule_ms", [1560000] * 3, "schedule"),
                ("source_lf_sha256", {}, "current_sources"),
                ("fixture_inventory", [], "inventory"),
                (
                    "fixture_inventory",
                    {"registration.json": {"bytes": 1, "sha256": "a" * 64}},
                    "archive_inventory",
                ),
                ("source_inventory_sha256", "b" * 64, "inventory_hash"),
            ]
            for field, bad, reason in changes:
                changed = {**value, field: bad}
                with (
                    self.subTest(reason=reason),
                    self.assertRaisesRegex(IntegrityError, "maximum:" + reason),
                ):
                    load(changed)
            for kind in ("path", "bytes", "hash"):
                changed = copy.deepcopy(value)
                if kind == "path":
                    changed["fixture_inventory"]["../escape"] = {"bytes": 0, "sha256": "a" * 64}
                else:
                    changed["fixture_inventory"]["raw/controller.jsonl"][
                        "bytes" if kind == "bytes" else "sha256"
                    ] = -1 if kind == "bytes" else "z" * 64
                changed["source_inventory_sha256"] = sha(encode(changed["fixture_inventory"]))
                with (
                    self.subTest(kind=kind),
                    self.assertRaisesRegex(IntegrityError, "maximum:" + kind),
                ):
                    load(changed)

    def test_pinned_maximum_is_required_at_original_P_and_in_preparation(self):
        command = object.__new__(SetupCommands)
        command.binding = BINDING
        command.sample = lambda: point(1_800_010)
        command.maximum_fixture = {"source_inventory_sha256": staged()["manifest_sha256"]}
        creation = {
            "staging": staged(),
            "ready": point(10),
            "ready_ms": 10,
            "maximum_fixture_sha256": sha(encode(command.maximum_fixture)),
        }
        self.assertTrue(command.validate_staging(creation)["verified"])
        self.assertTrue(command.validate_preparation(admitted(), creation)["complete"])
        command.maximum_fixture["source_inventory_sha256"] = "b" * 64
        with self.assertRaisesRegex(IntegrityError, "setup:maximum_at_P"):
            command.validate_staging(creation)
        with self.assertRaisesRegex(IntegrityError, "setup:original_maximum"):
            command.validate_preparation(admitted(), creation)
        command.maximum_fixture = {"a": "new proof"}
        data = {
            "artifacts": {"maximum.json": b"wrong"},
            "maximum_fixture_proof": {"path": "maximum.json", "sha256": sha(b"wrong")},
            "replay_raw": b"raw",
            "export_raw": b"raw",
        }
        with self.assertRaisesRegex(IntegrityError, "setup:maximum_artifact"):
            command.lifecycle_input(data)
