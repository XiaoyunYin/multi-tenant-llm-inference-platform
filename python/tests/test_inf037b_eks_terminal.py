"""Real inventory HTTP, tiny archives and explicit store/transfer unit seams."""

import copy
import threading
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from test_inf037b_terminal import Backend, Capacity, MemoryStore

from inference_platform.inf037b_archive import Archive, encode, sha, strict_json
from inference_platform.inf037b_contract import REGISTRATION_ID
from inference_platform.inf037b_eks_commands import (
    LifecycleAuthorityPort,
    TerminalAuthorityPort,
    UnfinishedPort,
)
from inference_platform.inf037b_eks_terminal import TerminalBackend, TerminalReceiver
from inference_platform.inf037b_ports import Authority
from inference_platform.inf037b_setup_observations import inventory
from inference_platform.inf037b_terminal import INVENTORIES, CleanupScope, TerminalAdapters
from inference_platform.inf037b_transfer import SocketArchiveTransfer


class TerminalBindingTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.scope = CleanupScope("s", "g", ("t",), ("i-1",), 17, "state", "recovery")
        self.provider, self.bad_scope, self.bad_readback = Backend(self.scope), False, False
        case = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                raw = self.rfile.read(int(self.headers["Content-Length"]))
                request = strict_json(raw)
                body, key, operation = request["body"], request["key"], request["operation"]
                if operation == "eks.terminal.inventory":
                    if key == "capacity_inventory":
                        value = {
                            "complete": True,
                            "scope_sha256": sha(encode(body["scope"])),
                            "tokens": {"t": ["cr-fixture"]},
                            "members": ["cr-fixture"],
                        }
                    else:
                        value = case.provider.inventory(key, body["scope"], body["stop_ms"])
                    if case.bad_scope:
                        value["scope_sha256"] = "0" * 64
                    result = value
                else:
                    if operation == "eks.terminal.commit_export":
                        value = {
                            "manifest_sha256": sha(encode(body["manifest"])),
                            "acknowledgements": {"recovery": True, "s3": True},
                            "readbacks": {"recovery": body["manifest"], "s3": body["manifest"]},
                        }
                        if case.bad_readback:
                            value["readbacks"]["s3"] = {}
                    else:
                        value = case.provider.effect(
                            operation.removeprefix("eks.terminal."),
                            key,
                            body["body"],
                            body["stop_ms"],
                        )
                    result = {
                        "request_key": key,
                        "body_sha256": sha(encode(body)),
                        "complete": True,
                        "result": value,
                    }
                answer = encode(
                    {
                        "request_sha256": sha(raw),
                        "authority_id": "fixture",
                        "namespace": "eks",
                        "status": "confirmed",
                        "complete": True,
                        "settled_sequence": request["minimum_sequence"],
                        "proof_id": "http-witness",
                        "result": result,
                    }
                )
                self.send_response(200)
                self.send_header("Content-Length", str(len(answer)))
                self.end_headers()
                self.wfile.write(answer)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)

        def transport(raw, timeout):
            request = urllib.request.Request(f"http://127.0.0.1:{server.server_port}", data=raw)
            with urllib.request.urlopen(request, timeout=timeout / 1000) as response:
                return response.read()

        binding = {
            "session_id": "s",
            "group": "g",
            "tokens": ["t"],
            "t0_ms": 17,
            "C_ms": 10000,
            "D_session_ms": 18010000,
        }
        self.store = MemoryStore()
        self.store.state = {"sequence": 0, "operations": {}, "values": {}}
        port = LifecycleAuthorityPort(
            self.store, Authority("fixture", "eks", transport), binding, {}, lambda: 100, "driver"
        )
        self.dependencies = {
            "4c_recovery_stores": lambda stop: {"binding": binding, "destination": "recovery"}
        }
        self.factory = SimpleNamespace(
            binding=binding,
            port=port,
            clock=lambda: 100,
            dependency=lambda name: self.dependencies.get(name, UnfinishedPort(name)),
        )
        self.backend = TerminalBackend(self.factory, TerminalAuthorityPort(self.factory))
        self.terminal_store = MemoryStore()
        self.adapter = TerminalAdapters(
            store=self.terminal_store,
            scope=self.scope,
            backend=self.backend,
            capacity=Capacity(self.provider),
            clock=lambda: 100,
        )

    def context(self, operation):
        return {
            "operation_key": self.factory.port.driver_key + ":" + operation,
            "operation_label": operation,
            "measurement_deadline_ms": 10000,
        }

    def test_real_http_cleanup_order_and_nonmutating_snapshot(self):
        before = copy.deepcopy(self.provider.resources)
        snapshot, model = self.backend.snapshot(self.scope, 10000)
        self.assertTrue(snapshot)
        self.assertTrue(model["model_only"])
        self.assertEqual(self.provider.resources, before)
        self.assertEqual(self.provider.executions, [])
        self.assertTrue(self.adapter("cleanup", 10000, self.context("cleanup")))
        actions = self.provider.executions
        for first, second in (
            ("delete_ingress", "delete_nlb"),
            ("delete_nlb", "delete_controllers"),
            ("delete_nodes", "delete_cluster"),
            ("preserve_state", "delete_state_versions"),
            ("delete_state_storage", "delete_bootstrap"),
        ):
            self.assertLess(actions.index(first), actions.index(second))
        self.assertEqual(self.adapter.last_report["errors"], [])
        self.assertEqual(set(self.adapter.last_report["inventories"]), set(INVENTORIES))

    def test_nonempty_inventory_refuses_and_failure_receipt_survives_reopen(self):
        original = self.provider.inventory

        def remain(category, scope, stop):
            result = original(category, scope, stop)
            if category == "network":
                result["resources"] = [{"id": "leftover"}]
            return result

        self.provider.inventory = remain
        with self.assertRaisesRegex(ValueError, "remaining_network"):
            self.adapter("cleanup", 10000, self.context("cleanup"))
        reopened = TerminalAdapters(
            store=self.terminal_store,
            scope=self.scope,
            backend=self.backend,
            capacity=Capacity(self.provider),
            clock=lambda: 100,
        )
        self.assertEqual(reopened.last_report["inventories"]["network"], [{"id": "leftover"}])
        self.assertTrue(reopened.last_report["errors"])
        self.assertEqual(self.provider.visits[-len(INVENTORIES) :], list(INVENTORIES))
        self.assertTrue(self.store.read()["values"]["terminal/receipts"])

    def test_wrong_scope_raw_observation_is_retained_before_refusal(self):
        self.bad_scope = True
        with self.assertRaisesRegex(ValueError, "terminal_inventory_scope"):
            self.backend.inventory("ingress", self.scope.descriptor(), 10000)
        receipt = self.store.read()["values"]["terminal/receipts"][-1]
        self.assertEqual(receipt["result"]["scope_sha256"], "0" * 64)
        self.assertIn("terminal_inventory_scope", receipt["error"])

    def test_lifecycle_still_cleans_after_missing_export_permission(self):
        from test_inf037b_lifecycle import DriverTests

        fixture = DriverTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        original = fixture.execute

        def execute(operation, stop, context):
            if operation in {"export", "cleanup"}:
                self.factory.port.driver_key = context["operation_key"].removesuffix(
                    ":" + operation
                )
                return self.adapter(operation, stop, context)
            return original(operation, stop, context)

        fixture.driver.execute = execute
        report = fixture.driver.run()
        self.assertIn("unfinished:4d_export_permission", " ".join(report["refusals"]))
        self.assertTrue(any(row["operation"] == "cleanup" for row in report["calls"]))
        self.assertEqual(self.adapter.last_report["errors"], [])
        failures = [row for row in self.store.read()["values"]["terminal/receipts"] if row["error"]]
        self.assertTrue(any("4d_export_permission" in row["error"] for row in failures))

    def prepare_export(self):
        root = self.root / "sanitized"
        Archive.create(root, {"registration_id": REGISTRATION_ID}, sanitized=True).seal()
        self.manifest = inventory(root)
        from test_inf037b_eks_placement import PlacementBindingTests

        placement_case = PlacementBindingTests(methodName="runTest")
        placement_case.binding_override = self.factory.binding
        placement_case.setUp()
        self.addCleanup(placement_case.doCleanups)
        self.factory.config = {"export_placement": placement_case.runtime}
        self.factory.clock = placement_case.clock
        permission = placement_case.runtime.run(1000000)
        proof = {"binding": self.factory.binding, "destination": "recovery"}
        self.dependencies.update(
            {
                "4c_recovery_stores": lambda stop: proof,
                "4d_export_permission": lambda stop: permission,
                "4c_terminal_export_inputs": lambda stop: {
                    "binding": self.factory.binding,
                    "sanitized": root,
                    "inventory": self.manifest,
                    "retained_artifacts": {},
                    "retained_manifest": {},
                },
            }
        )
        transfer = SocketArchiveTransfer()
        self.dependencies["terminal_export_transport"] = lambda stop: {
            "transfer": transfer,
            "address": ("127.0.0.1", 1),
            "max_total_bytes": 1000000,
            "max_objects": 100,
        }
        return transfer

    def test_export_joins_socket_manifest_and_both_real_authority_readbacks(self):
        transfer = self.prepare_export()
        with patch.object(
            transfer, "transfer", return_value={"transfer_id": "unit", "manifest": self.manifest}
        ) as send:
            self.assertTrue(self.adapter("export", 10000, self.context("export")))
        self.assertEqual(send.call_args.kwargs["max_total_bytes"], 1000000)
        self.assertIn("deadline_monotonic", send.call_args.kwargs)
        rows = self.store.read()["values"]["terminal/receipts"]
        receipt = [row for row in rows if row["kind"] == "effect"][-1]["result"]
        self.assertEqual(receipt["stores"]["readbacks"]["s3"], self.manifest)

    def test_one_store_readback_cannot_satisfy_export(self):
        transfer = self.prepare_export()
        self.bad_readback = True
        with patch.object(
            transfer, "transfer", return_value={"transfer_id": "unit", "manifest": self.manifest}
        ):
            with self.assertRaisesRegex(ValueError, "terminal_readback:s3"):
                self.adapter("export", 10000, self.context("export"))

    def test_terminal_transfer_includes_unchanged_retained_wire_and_rechecks_its_hash(self):
        from inference_platform.inf037b_archive import file_facts

        transfer = self.prepare_export()
        wire = self.root / "retained-wire.bin"
        wire.write_bytes(b"raw retained wire")
        key = "retained-owners/attempt_1/wire/raw.bin"
        retained_manifest = {key: file_facts(wire)}
        original = self.dependencies["4c_terminal_export_inputs"]
        self.dependencies["4c_terminal_export_inputs"] = lambda stop: {
            **original(stop),
            "retained_artifacts": {key: wire},
            "retained_manifest": retained_manifest,
        }
        manifest = {**self.manifest, **retained_manifest}
        with patch.object(
            transfer, "transfer", return_value={"transfer_id": "unit", "manifest": manifest}
        ) as send:
            self.assertTrue(self.adapter("export", 10000, self.context("export")))
            self.assertEqual(send.call_args.args[0][key], wire)
        wire.write_bytes(b"same length wrong")
        with self.assertRaisesRegex(ValueError, "terminal_retained_inventory"):
            self.backend.export("driver:export:export", {"scope": self.scope.descriptor()}, 10000)

    def test_receiver_uses_both_stores_and_verifies_actual_readback_files(self):
        path = self.root / "small.json"
        path.write_bytes(b'{"witness":true}\n')
        manifest = inventory(self.root)
        # root has just one file; portable stores are an explicit unit seam.
        artifacts = {"small.json": path}
        manifest = {"small.json": manifest["small.json"]}
        result = {
            "source_manifest_sha256": sha(encode(manifest)),
            "recovery": {"readback": artifacts},
            "s3": {"readback": artifacts},
        }
        receiver = TerminalReceiver(
            store_ports={
                "recovery_store": object(),
                "s3_store": object(),
                "recovery_readback": self.root / "a",
                "s3_readback": self.root / "b",
            },
            max_total_bytes=100,
            max_objects=1,
            clock=lambda: 100,
        )
        with patch(
            "inference_platform.inf037b_eks_terminal.persist_to_both", return_value=result
        ) as persist:
            receipt = receiver.commit(artifacts, manifest, 10000)
        self.assertEqual(receipt["acknowledgements"], {"recovery": True, "s3": True})
        self.assertIsNotNone(persist.call_args.kwargs["s3_store"])
        path.write_bytes(b"corrupt")
        with self.assertRaisesRegex(ValueError, "terminal_received_inventory"):
            receiver.commit(artifacts, manifest, 10000)
        receiver.clock = lambda: 10000
        with (
            patch("inference_platform.inf037b_eks_terminal.persist_to_both") as persist,
            self.assertRaisesRegex(ValueError, "terminal_receiver_deadline"),
        ):
            receiver.commit(artifacts, manifest, 10000)
        persist.assert_not_called()

    def test_refused_placement_permission_never_reaches_transfer(self):
        transfer = self.prepare_export()
        original = self.dependencies["4d_export_permission"]
        permission = copy.deepcopy(original(10000))
        permission["decision"]["decision"] = "REFUSE"
        self.dependencies["4d_export_permission"] = lambda stop: permission
        with patch.object(
            transfer, "transfer", return_value={"transfer_id": "unit", "manifest": self.manifest}
        ) as send:
            with self.assertRaisesRegex(ValueError, "placement_api:permission_immutable"):
                self.adapter("export", 10000, self.context("export"))
            send.assert_not_called()
