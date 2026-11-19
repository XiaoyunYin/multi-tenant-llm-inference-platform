"""Thin sequence failures must preserve the teardown/inventory path."""

import json
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from inference_platform.m5_descriptive_client import (
    client_resources,
    control,
    first_serving,
    pushed_digest,
    run_task,
)
from inference_platform.m5_descriptive_cluster import ClusterPorts
from inference_platform.m5_descriptive_operator import (
    PHASES,
    execute,
    file_inventory,
    load,
    session_timing,
    task_poll_budget,
    task_work_seconds,
)


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
    def test_submitted_production_task_budgets_fit_the_reserved_window(self):
        timing = session_timing(640, 140)
        cases = (
            ({"kind": "smoke"}, 50, 80),
            ({"kind": "load", "levels": [1], "duration": 120}, 240, 270),
            ({"kind": "load", "levels": [1, 4, 16], "duration": 600}, 2160, 2190),
            ({"kind": "load", "levels": [4], "duration": 600, "replacement": {}}, 770, 800),
            ({"kind": "load", "levels": [4], "duration": 900, "replacement": {}}, 1030, 1060),
        )
        budgets = []
        for task, expected_work, expected_budget in cases:
            with self.subTest(task=task):
                work = task_work_seconds(task, 640, timing["rollout_action_seconds"])
                budget = task_poll_budget(task, 640, timing["rollout_action_seconds"])
                self.assertEqual(work, expected_work)
                self.assertEqual(budget, expected_budget)
                self.assertGreaterEqual(budget, work)
                budgets.append(budget)
        self.assertEqual(sum(budgets), timing["minimum_workload_seconds"])
        historical_poll = (
            640 + max(timing["gateway_rollout_seconds"], timing["vllm_rollout_seconds"]) + 180
        )
        self.assertEqual(historical_poll, 1720)
        self.assertLess(historical_poll, task_work_seconds(cases[2][0], 640, 120))

    def test_submit_and_status_subprocess_are_capped_by_the_work_deadline(self):
        ports = ClusterPorts()
        ports.startup_seconds = 640
        ports.rollout_action = 120
        ports.deadline = 115
        ports.results = {}
        ports.client_control = Mock(
            side_effect=[{"submitted": "load"}, {"status": "PASS", "result": {"observed": True}}]
        )
        with patch("inference_platform.m5_descriptive_cluster.time.monotonic", return_value=100):
            ports.start_task("load", levels=[1, 4, 16], duration=600)
            self.assertEqual(ports.finish_task("load"), {"observed": True})
        self.assertEqual(
            [call.kwargs["deadline"] for call in ports.client_control.call_args_list], [115, 115]
        )
        record = ports.results["task_polls"]["load"]
        self.assertEqual(record["poll_budget_s"], 2190)
        self.assertEqual(record["effective_budget_s"], 15)
        self.assertEqual(record["status"], "PASS")

    def test_gateway_observer_can_read_ready_after_the_measured_window(self):
        observer = SimpleNamespace(thread=Mock(), stop=Mock(), error=None, ready_ns=None)
        observer.thread.is_alive.return_value = False
        clock = [100]

        def finished_load(*args, **kwargs):
            clock[0] += 600
            return []

        def join(*, timeout):
            if observer.ready_ns is None:
                observer.stop.set.assert_not_called()
                self.assertEqual(timeout, 190)
                observer.ready_ns = 880_000_000_000

        observer.thread.join.side_effect = join
        with (
            patch("inference_platform.m5_descriptive_client.load", side_effect=finished_load),
            patch(
                "inference_platform.m5_descriptive_client.time.monotonic",
                side_effect=lambda: clock[0],
            ),
        ):
            result = run_task(
                {
                    "kind": "load",
                    "label": "gateway_rollout",
                    "levels": [4],
                    "duration": 600,
                    "replacement": {
                        "target": "gateway-0",
                        "old_uid": "old",
                        "observe_seconds": 790,
                    },
                },
                SimpleNamespace(namespace="test", deadline=1200, corpus=None),
                observer_factory=Mock(return_value=observer),
            )
        observer.stop.set.assert_called_once()
        self.assertEqual(result["replacement"]["ready_monotonic_ns"], 880_000_000_000)

    def test_diagnostics_only_export_retrieves_then_halts_instead_of_claiming_complete(self):
        with tempfile.TemporaryDirectory() as tmp:
            ports = Ports()
            frozen = {"kind": "repo-free-diagnostics", "files": {}}
            ports.export = lambda: ports.calls.append("export") or frozen
            ports.retrieve = lambda: ports.calls.append("retrieve") or frozen
            with self.assertRaisesRegex(RuntimeError, "descriptive:diagnostics_only_export"):
                execute(ports, Path(tmp) / "run", deadline=time.monotonic() + 1000)
            self.assertEqual(ports.calls[-4:], ["export", "retrieve", "teardown", "inventory"])
            receipt = json.loads((Path(tmp) / "run/receipt.json").read_bytes())
            self.assertFalse(receipt["complete"])
            self.assertEqual(receipt["phases"][-3]["status"], "PASS")

    def test_diagnostics_only_after_work_failure_preserves_original_halt(self):
        with tempfile.TemporaryDirectory() as tmp:
            ports = Ports("provision")
            frozen = {"kind": "repo-free-diagnostics", "files": {}}
            ports.export = lambda: ports.calls.append("export") or frozen
            ports.retrieve = lambda: ports.calls.append("retrieve") or frozen
            with self.assertRaisesRegex(ValueError, "injected:provision"):
                execute(ports, Path(tmp) / "run", deadline=time.monotonic() + 1000)
            self.assertEqual(ports.calls[-4:], ["export", "retrieve", "teardown", "inventory"])
            receipt = json.loads((Path(tmp) / "run/receipt.json").read_bytes())
            self.assertIn("injected:provision", receipt["halt"])

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

    def test_gateway_replacement_never_claims_backend_slot_serving_time(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rows = [{"completion_monotonic_ns": 110, "backend_slot": 0, "outcome": "completed"}]
            (root / "records.jsonl").write_text(json.dumps(rows[0]) + "\n")
            ports = SimpleNamespace(output=root, deadline=time.monotonic() + 10, corpus=None)
            for target in ("gateway-0", "vllm-0"):
                observer = SimpleNamespace(thread=Mock(), stop=Mock(), error=None, ready_ns=100)
                observer.thread.is_alive.return_value = False
                with (
                    self.subTest(target=target),
                    patch(
                        "inference_platform.m5_descriptive_client.load",
                        return_value=[{"client_records": {"path": "records.jsonl"}}],
                    ),
                ):
                    value = run_task(
                        {
                            "kind": "load",
                            "label": "rollout",
                            "levels": [4],
                            "duration": 1,
                            "replacement": {"target": target, "old_uid": "old"},
                        },
                        SimpleNamespace(**vars(ports), namespace="test"),
                        observer_factory=Mock(return_value=observer),
                    )["replacement"]
                self.assertEqual(value["ready_monotonic_ns"], 100)
                if target == "gateway-0":
                    self.assertEqual(
                        value["first_serving"], "not_applicable: gateway identity not exposed"
                    )
                    self.assertNotIn("first_completed_backend_slot", value)
                    self.assertNotIn("first_completed_after_ready_ns", value)
                else:
                    self.assertEqual(value["first_completed_backend_slot"], 0)
                    self.assertEqual(value["first_completed_after_ready_ns"], 10)
                    self.assertNotIn("first_serving", value)

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
