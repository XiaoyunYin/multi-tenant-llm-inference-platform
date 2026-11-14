"""Thin sequence failures must preserve the teardown/inventory path."""

import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from inference_platform.m5_descriptive_client import (
    client_resources,
    control,
    first_serving,
    pushed_digest,
)
from inference_platform.m5_descriptive_operator import PHASES, execute, file_inventory, load


class Ports:
    substitutions = ["unit fixture; real kind path is a separate AWS stage"]

    def __init__(self, failure=None):
        self.calls, self.failure = [], failure

    def result(self, name):
        self.calls.append(name)
        if name == self.failure:
            raise ValueError("injected:" + name)
        return {"complete": True}

    def provision(self):
        return self.result("provision")

    def smoke(self):
        return self.result("smoke")

    def load(self, levels):
        if levels != (1, 4, 16):
            raise AssertionError("levels")
        return self.result("load")

    def rollout(self, app):
        return self.result("gateway_rollout" if app == "gateway" else "replica_rollout")

    def export(self):
        return self.result("export")

    def retrieve(self):
        return self.result("retrieve")

    def teardown(self):
        return self.result("teardown")

    def inventory(self):
        return self.result("inventory")


class OperatorTests(unittest.TestCase):
    def test_work_failure_attempts_existing_client_export_before_teardown(self):
        with tempfile.TemporaryDirectory() as tmp:
            ports = Ports("replica_rollout")
            with self.assertRaisesRegex(ValueError, "replica_rollout"):
                execute(ports, Path(tmp) / "run", deadline=time.monotonic() + 1000)
            self.assertEqual(ports.calls[-4:], ["export", "retrieve", "teardown", "inventory"])
            receipt = json.loads((Path(tmp) / "run/receipt.json").read_bytes())
            self.assertFalse(receipt["complete"])
            self.assertIn("replica_rollout", receipt["halt"])

    def test_frozen_inventory_streams_file_hashes(self):
        import hashlib

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "record.jsonl").write_bytes(b"row\n" * 300000)
            with patch.object(Path, "read_bytes", side_effect=AssertionError("unbounded read")):
                observed = file_inventory(root)
            self.assertEqual(
                observed["record.jsonl"],
                {"bytes": 1200000, "sha256": hashlib.sha256(b"row\n" * 300000).hexdigest()},
            )

    def test_image_digest_uses_exact_pushed_repository_not_the_original_local_name(self):
        expected = "localhost:5001/client@sha256:" + "a" * 64
        inspection = {"RepoDigests": ["mti-fake@sha256:" + "a" * 64, expected]}
        self.assertEqual(pushed_digest(inspection, "localhost:5001/client"), expected)
        for rows in (inspection["RepoDigests"][:1], [expected, expected], [expected[:-1]]):
            with self.assertRaisesRegex(ValueError, "pushed_image_digest"):
                pushed_digest({"RepoDigests": rows}, "localhost:5001/client")

    def test_client_job_is_cpu_tls_secret_mounted_and_never_retried(self):
        image = "registry.invalid/client@sha256:" + "a" * 64
        with patch("inference_platform.m5_descriptive_client.time.time", return_value=100):
            items = client_resources("mti-m5-test", image, 1100)["items"]
        job = next(i for i in items if i["kind"] == "Job")
        spec = job["spec"]["template"]["spec"]
        self.assertEqual(job["spec"]["backoffLimit"], 0)
        self.assertEqual(job["spec"]["activeDeadlineSeconds"], 1000)
        self.assertEqual(spec["nodeSelector"], {"m5-role": "cpu"})
        self.assertEqual(spec["restartPolicy"], "Never")
        self.assertEqual(spec["containers"][0]["image"], image)
        self.assertEqual(spec["volumes"][1]["secret"]["secretName"], "load-client")
        self.assertEqual(spec["volumes"][2]["configMap"]["name"], "load-client-ca")
        self.assertEqual(len([i for i in items if i["kind"] == "Job"]), 1)

    def test_first_replacement_serving_is_completed_slot_after_same_clock_ready(self):
        records = [
            {"completion_monotonic_ns": t, "backend_slot": slot, "outcome": outcome}
            for t, slot, outcome in (
                (95, 0, "completed"),
                (101, 1, "completed"),
                (102, 0, "partial_stream"),
                (110, 0, "completed"),
                (130, 0, "completed"),
            )
        ]
        self.assertEqual(first_serving(records, 100, 0), 10)
        self.assertIsNone(first_serving(records, 140, 0))

    def test_short_client_controls_are_idempotent_and_hash_bound_on_retrieval(self):
        import base64

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            task = base64.b64encode(b'{"label":"load","kind":"load"}').decode()
            self.assertEqual(control(root, "submit", [task]), {"submitted": "load"})
            self.assertEqual(control(root, "submit", [task]), {"submitted": "load"})
            changed = base64.b64encode(b'{"label":"load","kind":"smoke"}').decode()
            with self.assertRaisesRegex(ValueError, "task_changed"):
                control(root, "submit", [changed])
            (root / "clients").mkdir()
            (root / "clients/sample.jsonl").write_bytes(b"record\n")
            self.assertEqual(control(root, "inventory", []), file_inventory(root / "clients"))
            self.assertEqual(
                base64.b64decode(control(root, "read", ["sample.jsonl", "0"])["base64"]),
                b"record\n",
            )
            with self.assertRaisesRegex(ValueError, "client_path"):
                control(root, "read", ["../../secret", "0"])

    def test_artifact_label_cannot_escape_client_directory(self):
        with self.assertRaisesRegex(ValueError, "client_artifact_label"):
            load(None, (), duration=1, deadline=time.monotonic() + 1000, label="../escape")

    def test_exact_order_and_every_failure_still_inventories(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ports = Ports()
            result = execute(ports, root / "baseline", deadline=time.monotonic() + 1000)
            self.assertTrue(result["complete"])
            self.assertEqual(tuple(ports.calls), PHASES)
            for failure in PHASES:
                ports = Ports(failure)
                with self.subTest(failure=failure), self.assertRaisesRegex(ValueError, "injected"):
                    execute(ports, root / failure, deadline=time.monotonic() + 1000)
                self.assertEqual(ports.calls[-2:], ["teardown", "inventory"])
                receipt = json.loads((root / failure / "receipt.json").read_bytes())
                self.assertEqual(
                    [row["name"] for row in receipt["phases"] if row["status"] == "FAILED"],
                    [failure],
                )

    def test_deadline_refuses_work_but_not_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            ports = Ports()
            with self.assertRaisesRegex(TimeoutError, "session_deadline"):
                execute(ports, Path(directory) / "run", deadline=time.monotonic() + 299)
            self.assertEqual(ports.calls, ["teardown", "inventory"])
            for invalid in (float("nan"), float("inf")):
                with self.assertRaisesRegex(ValueError, "finite_original_deadline"):
                    execute(ports, Path(directory) / "invalid", deadline=invalid)

    def test_incomplete_inventory_cannot_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            ports = Ports()
            ports.inventory = lambda: {"complete": False}
            with self.assertRaisesRegex(ValueError, "inventory_incomplete"):
                execute(ports, Path(directory) / "run", deadline=time.monotonic() + 1000)
            receipt = json.loads((Path(directory) / "run/receipt.json").read_bytes())
            self.assertEqual(receipt["phases"][-1]["status"], "FAILED")

    def test_retrieval_bytes_bind_and_mismatch_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "data").write_bytes(b"real file")
            original = file_inventory(root)
            (root / "data").write_bytes(b"changed")
            self.assertNotEqual(original, file_inventory(root))
            ports = Ports()
            ports.export = lambda: original
            ports.retrieve = lambda: file_inventory(root)
            with self.assertRaisesRegex(ValueError, "retrieval_hash_mismatch"):
                execute(ports, root / "run", deadline=time.monotonic() + 1000)
            self.assertEqual(ports.calls[-2:], ["teardown", "inventory"])
            receipt = json.loads((root / "run/receipt.json").read_bytes())
            self.assertEqual(
                next(row for row in receipt["phases"] if row["name"] == "retrieve")["status"],
                "FAILED",
            )
