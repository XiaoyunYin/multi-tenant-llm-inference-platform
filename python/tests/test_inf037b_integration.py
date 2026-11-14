"""Accepted real 4a ports -> real lifecycle with fake persistent transports."""

import copy
import json
import os
import signal
import subprocess
import sys
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from test_inf037b_terminal import Backend, Capacity, Cut, MemoryStore

from inference_platform.inf037b_archive import IntegrityError
from inference_platform.inf037b_durable_ports import DurableStore
from inference_platform.inf037b_integration import CreationRecords, IntegratedLifecycle
from inference_platform.inf037b_lifecycle import group_members
from inference_platform.inf037b_terminal import INVENTORIES, CleanupScope, TerminalAdapters

CASES = []


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def worker_command(
        self, root, *, cut=None, delay=0, scenario="normal", restart_delay=0, processes=False
    ):
        command = [
            sys.executable,
            str(Path(__file__).with_name("inf037b_integration_worker.py")),
            "--root",
            str(root),
            "--delay",
            str(delay),
            "--scenario",
            scenario,
        ]
        if cut:
            command += ["--cut", str(cut)]
        command += ["--restart-delay", str(restart_delay)]
        if processes:
            command.append("--processes")
        return command

    def worker(self, root, **kwargs):
        command = self.worker_command(root, **kwargs)
        return subprocess.run(command, capture_output=True, text=True, timeout=40)

    def result(self, response):
        self.assertEqual(response.returncode, 0, response.stderr)
        return json.loads(response.stdout)

    def assert_terminal(self, data):
        scope = data["terminal"]["binding"]
        rows = data["controller_rows"]
        origin = next(r["data"] for r in rows if r["event"] == "billing_origin")
        tokens = [r["data"]["token"] for r in rows if r["event"] == "acquire_intent"]
        self.assertEqual(scope["t0_ms"], origin["t0_ms"])
        self.assertEqual(scope["tokens"], tokens)
        bound = rows[0]["data"][0]
        self.assertEqual(scope["session_id"], bound["session_id"])
        self.assertEqual(scope["group"], bound["capacity"]["group_arn"])
        self.assertEqual(scope["instance_ids"], data["creation"]["instance_ids"])
        self.assertEqual(sum(r[0] == "apply" for r in data["provider_trace"]), 1)
        self.assertEqual(sum(r[0] == "cancel" for r in data["provider_trace"]), len(tokens))
        report = data["terminal"]["last_report"]
        self.assertEqual(report["errors"], [])
        self.assertEqual(set(report["inventories"]), set(INVENTORIES))
        self.assertEqual(len(data["executions"]), len(set(data["executions"])))

    def test_accepted_4a_late_consume_drives_original_lifecycle_and_cleanup_scope(self):
        data = self.result(self.worker(self.root / "late", delay=1_700_000))
        self.assert_terminal(data)
        self.assertTrue(data["result"]["attempts"]["three_valid_events"])
        self.assertEqual(data["result"]["refusals"], [])
        consumed = next(r["data"] for r in data["controller_rows"] if r["event"] == "consumed")
        t0 = data["terminal"]["binding"]["t0_ms"]
        self.assertEqual(consumed["consumed_ms"] - t0, 1_700_000)
        creation = next(
            r["payload"] for r in data["lifecycle"] if r["payload"]["event"] == "call_start"
        )
        self.assertEqual(creation["stop_ms"], t0 + 1_800_000)
        self.assertEqual(data["result"]["D_eff_ms"], t0 + 18_000_000)
        CASES.append({"case": "late_consume", "receipt": data})

    def test_late_consume_after_creation_window_cancels_without_consumption_or_apply(self):
        data = self.result(self.worker(self.root / "too-late", delay=1_800_001))
        self.assertEqual(sum(r[0] == "apply" for r in data["provider_trace"]), 0)
        self.assertEqual(data["result"]["status"]["sessions"], 0)
        self.assertEqual(len(data["result"]["status"]["ledger"]), 1)
        self.assertEqual(sum(r[0] == "cancel" for r in data["provider_trace"]), 1)
        self.assertEqual(data["creation_calls"], [])
        self.assertEqual(data["executions"], [])
        self.assertEqual(data["lifecycle"], [])
        CASES.append({"case": "late_creation_refusal", "receipt": data})

    def test_applied_instances_are_journaled_when_creation_call_never_started(self):
        root = self.root / "apply-before-creation"
        dead = self.worker(root, scenario="apply_before_creation")
        self.assertEqual(dead.returncode, -signal.SIGKILL, dead.stderr)
        data = self.result(
            self.worker(
                root,
                restart_delay=1_800_001,
                scenario="apply_before_creation",
            )
        )
        self.assert_terminal(data)
        self.assertEqual(data["creation_calls"], [])
        self.assertIsNone(data["creation"]["intent"])
        self.assertEqual(data["creation"]["instance_ids"], ["i-from-apply"])
        self.assertEqual(data["terminal"]["binding"]["instance_ids"], ["i-from-apply"])
        CASES.append({"case": "apply_before_creation", "receipt": data})

    def test_composition_requires_commands_or_explicit_callable_test_seam(self):
        with self.assertRaisesRegex(IntegrityError, "commands_required"):
            IntegratedLifecycle(
                controller=None,
                attempts=self.root / "attempts",
                creation_store=None,
                terminal_store=None,
                creation=None,
                phases=None,
                backend=None,
                clock=None,
                state_storage_id="source",
                state_destination="destination",
            )

    def test_process_composition_fences_every_creation_setup_attempt_and_terminal_command(self):
        data = self.result(self.worker(self.root / "processes", processes=True))
        self.assert_terminal(data)
        self.assertTrue(data["result"]["attempts"]["three_valid_events"])
        rows = [r["payload"] for r in data["lifecycle"]]
        starts = [r for r in rows if r["event"] == "call_start"]
        self.assertEqual(
            {r["operation"] for r in starts},
            {
                "creation",
                "preparation",
                "resolution",
                "packet_barrier",
                "attempt_setup",
                "attempt",
                "export",
                "cleanup",
            },
        )
        for start in starts:
            key = start["key"]
            spawn = [i for i, r in enumerate(rows) if r["event"] == "spawned" and r["key"] == key]
            fenced = [
                i for i, r in enumerate(rows) if r["event"] == "child_fenced" and r["key"] == key
            ]
            end = [i for i, r in enumerate(rows) if r["event"] == "call_end" and r["key"] == key]
            self.assertEqual(len(spawn), 1)
            self.assertEqual(len(fenced), 1)
            self.assertEqual(len(end), 1)
            self.assertLess(spawn[0], fenced[0])
            self.assertLess(fenced[0], end[0])
        CASES.append({"case": "all_composed_commands_fenced", "receipt": data})

    def test_real_process_composition_sigkill_reopen_fences_child_before_export_cleanup(self):
        root = self.root / "acting"
        process = subprocess.Popen(
            self.worker_command(root, processes=True, scenario="acting_child"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        identity = None
        try:
            marker = root / "acting-child.json"
            limit = time.monotonic() + 20
            while not marker.exists() and process.poll() is None and time.monotonic() < limit:
                time.sleep(0.01)
            self.assertTrue(marker.exists(), "composed preparation child never acted")
            identity = json.loads(marker.read_text())
            self.assertIn(identity["pid"], group_members(identity["group"]))
            self.assertIn(identity["grandchild"], group_members(identity["group"]))
            process.kill()
            process.communicate(timeout=5)
            self.assertEqual(process.returncode, -signal.SIGKILL)
            self.assertIn(identity["pid"], group_members(identity["group"]))
            data = self.result(
                self.worker(root, processes=True, scenario="acting_child", restart_delay=10000)
            )
            self.assert_terminal(data)
            self.assertEqual(group_members(identity["group"]), [])
            self.assertTrue(data["fence_observations"])
            self.assertTrue(all(not r["child_executable"] for r in data["fence_observations"]))
            rows = [r["payload"] for r in data["lifecycle"]]
            fence = next(
                i
                for i, r in enumerate(rows)
                if r["event"] == "child_fenced" and r["identity"]["pid"] == identity["pid"]
            )
            terminals = [
                i
                for i, r in enumerate(rows)
                if r["event"] == "call_start" and r["operation"] in {"export", "cleanup"}
            ]
            self.assertEqual(len(terminals), 2)
            self.assertTrue(all(fence < i for i in terminals))
            CASES.append({"case": "composed_acting_child_sigkill", "receipt": data})
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=5)
            if identity and group_members(identity["group"]):
                os.killpg(identity["group"], signal.SIGKILL)

    def test_creation_interrupted_before_instance_or_before_identity_receipt_reconciles_scope(self):
        for scenario, ids in (
            ("before_instance", []),
            ("before_record", ["i-created-1", "i-created-2"]),
        ):
            with self.subTest(scenario=scenario):
                data = self.result(self.worker(self.root / scenario, scenario=scenario))
                self.assert_terminal(data)
                self.assertEqual(data["terminal"]["binding"]["instance_ids"], ids)
                self.assertEqual(data["creation"]["settled"]["instance_ids"], ids)
                self.assertFalse(data["result"]["measurement_started"])
                CASES.append({"case": scenario, "receipt": data})

    def test_sigkill_at_every_durable_start_and_creation_record_reopens_without_new_apply(self):
        reference = self.result(self.worker(self.root / "reference"))
        observations = []
        for cut, label in enumerate(reference["cuts"], 1):
            with self.subTest(cut=cut, label=label):
                root = self.root / str(cut)
                dead = self.worker(root, cut=cut)
                self.assertEqual(dead.returncode, -signal.SIGKILL, dead.stderr)
                prefixes = {p.name: p.read_bytes() for p in root.glob("*.jsonl")}
                data = self.result(self.worker(root, restart_delay=10_000))
                self.assert_terminal(data)
                self.assertLessEqual(len(data["creation_calls"]), 1)
                for name, content in prefixes.items():
                    self.assertTrue((root / name).read_bytes().startswith(content))
                for row in data["lifecycle"]:
                    if row["payload"]["event"] == "call_start":
                        request = row["payload"]
                        key = request["context"]["operation_key"]
                        if request["operation"] in {"export", "cleanup"}:
                            stored = data["terminal"]["requests"][request["operation"]]
                            self.assertEqual(stored["request_key"], key)
                            self.assertEqual(stored["stop_ms"], request["stop_ms"])
                before = {p.name: p.read_bytes() for p in root.glob("*.jsonl")}
                replay = self.result(self.worker(root))
                self.assertEqual(replay["executions"], data["executions"])
                for name, content in before.items():
                    self.assertEqual((root / name).read_bytes(), content)
                observations.append(
                    {
                        "cut": cut,
                        **label,
                        "scope": data["terminal"]["binding"],
                        "refusals": data["result"]["refusals"],
                    }
                )
        CASES.append({"case": "integrated_sigkill_starts", "cuts": observations})

    def test_scope_keeps_all_original_tokens_after_partial_acquisition_and_az_advance(self):
        data = self.result(self.worker(self.root / "two-tokens", scenario="first_partial"))
        self.assert_terminal(data)
        self.assertEqual(len(data["terminal"]["binding"]["tokens"]), 2)
        self.assertEqual(len([r for r in data["controller_rows"] if r["event"] == "ledger"]), 1)
        self.assertEqual(data["result"]["refusals"], [])
        CASES.append({"case": "all_original_tokens", "receipt": data})

    def test_changed_4a_binding_and_unknown_creation_inventory_refuse_scope(self):
        binding = dict(
            session_id="fixture",
            group="original-group",
            tokens=["original-token"],
            t0_ms=17,
            C_ms=50,
            D_session_ms=18_000_050,
            plan_hash="a" * 64,
        )
        store = MemoryStore()

        class Port:
            observation = {
                "application": {"session_id": "fixture", "plan_hash": "a" * 64},
                "complete": True,
                "settled": True,
                "instance_ids": ["i-original"],
            }

            def create(self, key, stop, context, record):
                record("i-original")
                return True

            def inventory(self, application, stop):
                return copy.deepcopy(self.observation)

        port = Port()
        records = CreationRecords(store, binding, port)
        records.create(1000, {"operation_key": "original:creation"})
        for field, bad in (
            ("application", {"session_id": "other", "plan_hash": "a" * 64}),
            ("complete", False),
            ("settled", False),
            ("instance_ids", []),
            ("instance_ids", ["i-original", "i-original"]),
        ):
            with self.subTest(field=field, bad=bad):
                original = copy.deepcopy(port.observation)
                port.observation[field] = bad
                with self.assertRaises(IntegrityError):
                    records.scope(2000, "source", "destination")
                port.observation = original
        with self.assertRaises(IntegrityError):
            CreationRecords(store, {**binding, "t0_ms": 18}, port)

    def test_real_durable_report_success_failure_and_lost_write_ack_reload_exact_rows(self):
        scope = CleanupScope(
            "fixture", "group", ("token",), ("i-created",), 17, "source", "destination"
        )
        context = dict(
            operation_key="fixture:cleanup",
            operation_label="cleanup",
            measurement_deadline_ms=10000,
        )
        for failed in (False, True):
            with self.subTest(failed=failed):
                backend = Backend(scope)
                capacity = Capacity(backend)
                backend.bad_inventory = "nlb" if failed else None
                path = self.root / str(failed)
                store = DurableStore(path, {"binding": None}, initialize=True)
                adapter = TerminalAdapters(
                    store=store,
                    scope=scope,
                    backend=backend,
                    capacity=capacity,
                    clock=lambda backend=backend: backend.now,
                )
                write = store.write

                def cut_report(state, write=write, store=store):
                    write(state)
                    if "last_report" in state:
                        store.failed = True
                        raise Cut("report write acknowledgement lost")

                with patch.object(store, "write", side_effect=cut_report):
                    with self.assertRaises(Cut):
                        adapter("cleanup", 10000, context)
                report = copy.deepcopy(adapter.last_report)
                reopened = TerminalAdapters(
                    store=DurableStore(path, {}),
                    scope=scope,
                    backend=backend,
                    capacity=capacity,
                    clock=lambda backend=backend: backend.now,
                )
                self.assertEqual(reopened.last_report, report)
                if failed:
                    self.assertIsNone(report["inventories"]["nlb"])
                    with self.assertRaises(IntegrityError):
                        reopened("cleanup", 10000, context)
                else:
                    self.assertTrue(reopened("cleanup", 10000, context))
                self.assertEqual(reopened.last_report, report)
                CASES.append({"case": "durable_report", "failed": failed, "report": report})


def load_tests(loader, tests, pattern):
    return (
        loader.loadTestsFromTestCase(IntegrationTests)
        if os.name == "posix"
        else unittest.TestSuite()
    )
