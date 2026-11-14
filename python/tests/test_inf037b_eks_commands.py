"""Portable command-shell contracts, real HTTP and a real native child.

The HTTP service is a protocol fixture, not AWS/Kubernetes or a fence proof.
Linux ProcessCalls fencing/reopen and durable stores remain host validation.
"""

import copy
import json
import os
import subprocess
import sys
import threading
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from test_inf037b_capture_inventory import SnapshotStore

from inference_platform.inf037b_archive import IntegrityError, encode, sha, strict_json
from inference_platform.inf037b_capture_inventory import source_inventory, wire_files
from inference_platform.inf037b_command import OPERATIONS, CommandPorts, commands
from inference_platform.inf037b_eks_commands import (
    EKSCommandFactory,
    capture_instance_schedule,
    whole_run_wire_files,
)
from inference_platform.inf037b_lifecycle import ProcessCalls
from inference_platform.inf037b_ports import Authority
from inference_platform.inf037b_row5_kind import row5_runtime_sources


def shell(root, url, implementations=None):
    """Explicit synthetic 4a journal; original binding extraction is real."""
    plan = {
        "session_id": "s",
        "plan_hash": "a" * 64,
        "C": "2026-01-01T00:00:00Z",
        "D_session": "2026-01-01T05:00:00Z",
        "capacity": {"group_arn": "fixture-group"},
    }
    rows = [
        {"event": "bound", "data": [plan]},
        {"event": "billing_origin", "data": {"t0_ms": 1767225600000}},
        {"event": "consumed", "data": {"session_id": "s", "plan_hash": plan["plan_hash"]}},
        {"event": "acquire_intent", "data": {"token": "original-token"}},
        {"event": "applied", "index": 0, "data": True},
    ]
    controller = SimpleNamespace(
        journal=SimpleNamespace(read=lambda: rows, close=lambda: None), capacity=object()
    )

    def transport(raw, timeout):
        request = urllib.request.Request(url, data=raw, method="POST")
        with urllib.request.urlopen(request, timeout=timeout / 1000) as response:
            return response.read()

    config = {
        "pins": {"source": "fixture"},
        "attempts": str(root / "attempts"),
        "capture_instances": {},
    }
    return EKSCommandFactory(
        controller=controller,
        authority=Authority("fixture", "eks", transport),
        store=SnapshotStore(root / "store", {"sequence": 0, "operations": {}, "values": {}}),
        clock=lambda: 1767225600001,
        config=config,
        implementations=implementations,
    )


class EKSCommandsTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory(prefix="r334-eks-")))
        self.requests, self.corrupt = [], False
        case = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                raw = self.rfile.read(int(self.headers["Content-Length"]))
                request = strict_json(raw)
                case.requests.append(request)
                body, key = request["body"], request["key"]
                if request["operation"] == "eks.inventory":
                    result = {
                        "application": {k: body["binding"][k] for k in ("session_id", "plan_hash")},
                        "complete": True,
                        "settled": True,
                        "instance_ids": ["instance"],
                    }
                elif request["operation"] == "eks.terminal.inventory":
                    result = {
                        "complete": True,
                        "scope_sha256": sha(encode(body["scope"])),
                        "resources": [],
                    }
                else:
                    value = (
                        {"instance_ids": ["instance"], "raw_hex": b"real-response".hex()}
                        if request["operation"] == "eks.creation"
                        else {"observed": True}
                    )
                    if request["operation"].startswith("eks.terminal."):
                        value = {
                            "request_key": key,
                            "body_sha256": sha(encode(body["body"])),
                            "accepted": True,
                        }
                    result = {
                        "request_key": "wrong" if case.corrupt else key,
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
                        "proof_id": "fixture-proof",
                        "result": result,
                    }
                )
                self.send_response(200)
                self.send_header("Content-Length", str(len(answer)))
                self.end_headers()
                self.wfile.write(answer)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 2)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.url = f"http://127.0.0.1:{self.server.server_port}/"
        self.factory = shell(self.root, self.url)

    def context(self, op, attempt=None):
        label = op + (":" + str(attempt) if attempt else "")
        return {
            "operation_key": self.factory.port.driver_key + ":" + label,
            "operation_label": label,
            "measurement_deadline_ms": 1767225601000,
            "kill_cutoff_ms": 1767225600999,
            "input": {} if attempt is None else {"attempt": attempt},
        }

    def test_factory_uses_command_ports_and_existing_process_calls_mapping(self):
        ports = self.factory(self.factory.config)
        self.assertIs(type(ports), CommandPorts)
        mapping = commands(self.root / "config")
        self.assertEqual(set(mapping), set(OPERATIONS))
        if os.name == "posix":
            calls = self.factory.process_calls(self.root / "config")
            self.assertIsInstance(calls, ProcessCalls)
            self.assertEqual(calls.commands, mapping)
        else:
            with self.assertRaisesRegex(IntegrityError, "process_platform"):
                self.factory.process_calls(self.root / "config")

    def test_creation_real_http_keeps_origin_effect_inventory_and_deduplicates(self):
        context = self.context("creation")
        ids = []
        self.assertEqual(
            self.factory.port.create(
                context["operation_key"], context["measurement_deadline_ms"], context, ids.append
            ),
            b"real-response",
        )
        self.assertEqual(ids, ["instance"])
        self.factory.port.create(
            context["operation_key"], context["measurement_deadline_ms"], context, lambda _: None
        )
        self.assertEqual(len(self.requests), 1)
        bound = self.requests[0]["body"]
        self.assertEqual(bound["binding"], self.factory.binding)
        self.assertEqual(bound["binding"]["tokens"], ["original-token"])
        app = {k: self.factory.binding[k] for k in ("session_id", "plan_hash")}
        self.assertEqual(
            self.factory.port.inventory(app, context["measurement_deadline_ms"])["instance_ids"],
            ["instance"],
        )

    def test_bad_key_late_cutoff_changed_body_and_bad_receipt_refuse(self):
        context = self.context("creation")
        for update, reason in (
            ({"operation_key": "other:creation"}, "effect_key"),
            ({"measurement_deadline_ms": 1767225602000}, "original_cutoff"),
        ):
            with self.subTest(reason=reason), self.assertRaisesRegex(IntegrityError, reason):
                self.factory.port.invoke("creation", 1767225601000, {**context, **update})
        with self.assertRaisesRegex(IntegrityError, "deadline"):
            self.factory.port.invoke(
                "creation", 1767225600001, {**context, "measurement_deadline_ms": 1767225600001}
            )
        self.corrupt = True
        with self.assertRaisesRegex(IntegrityError, "receipt_key"):
            self.factory.port.invoke("creation", 1767225601000, context)
        # The lost/malformed receipt is not an excuse for a fresh effect.
        changed = {**context, "kill_cutoff_ms": 1767225600998}
        with self.assertRaisesRegex(IntegrityError, "operation_binding"):
            self.factory.port.invoke("creation", 1767225601000, changed)

    def test_unfinished_collectors_4c_4d_and_export_refuse_by_name(self):
        ports = self.factory(self.factory.config)
        self.assertIs(ports.inventory, ports.backend)
        self.assertTrue(callable(ports.inventory.capacity_inventory))
        with self.assertRaisesRegex(IntegrityError, "unfinished:4e_device_release_inputs"):
            ports.gpu(1767225601000, ports.row5_stage)
        with self.assertRaisesRegex(IntegrityError, "unfinished:4e_device_release_inputs"):
            ports.row5_stage("known0", 1767225601000000000)
        with self.assertRaisesRegex(IntegrityError, "eks:reset_is_attempt_setup"):
            ports.phases("reset", 1767225601000, self.context("reset", 2))
        for operation in ("packet_barrier", "attempt_setup", "attempt"):
            with (
                self.subTest(operation=operation),
                self.assertRaisesRegex(IntegrityError, "unfinished:4c"),
            ):
                ports.phases(operation, 1767225601000, self.context(operation, 1))
        self.factory.implementations["4c_attempt_start"] = lambda *_: None
        self.factory.implementations["4c_campaign_capture"] = lambda *_: {
            "binding": self.factory.binding
        }
        with self.assertRaisesRegex(IntegrityError, "unfinished:4e_cluster_inputs"):
            ports.phases("attempt", 1767225601000, self.context("attempt", 1))
        scope = {k: self.factory.binding[k] for k in ("session_id", "t0_ms", "group", "tokens")}
        with self.assertRaisesRegex(IntegrityError, "unfinished:4c_recovery_stores"):
            ports.backend.effect(
                "export",
                self.factory.port.driver_key + ":export:export",
                {"scope": scope},
                1767225601000,
            )
        self.assertEqual(self.requests, [])
        with self.assertRaisesRegex(IntegrityError, "unfinished:clock_sample"):
            ports.capture(1767225601000)

    def test_terminal_port_preserves_original_scope_key_and_inventory(self):
        ports = self.factory(self.factory.config)
        scope = {k: self.factory.binding[k] for k in ("session_id", "t0_ms", "group", "tokens")}
        key = self.factory.port.driver_key + ":cleanup:delete_ingress"
        receipt = ports.backend.effect("delete_ingress", key, {"scope": scope}, 1767225601000)
        self.assertEqual(receipt["request_key"], key)
        self.assertTrue(receipt["accepted"])
        self.assertEqual(self.requests[0]["body"]["binding"], self.factory.binding)
        observation = ports.backend.inventory("ingress", scope, 1767225601000)
        self.assertEqual(
            observation, {"complete": True, "scope_sha256": sha(encode(scope)), "resources": []}
        )
        with self.assertRaisesRegex(IntegrityError, "terminal_effect_key"):
            ports.backend.effect("delete_ingress", "other-key", {"scope": scope}, 1767225601000)
        with self.assertRaisesRegex(IntegrityError, "terminal_scope:t0_ms"):
            ports.backend.inventory("ingress", {**scope, "t0_ms": 0}, 1767225601000)

    def test_factory_capture_requires_inventory_and_budgets_before_any_owner(self):
        for missing in ("capture_inventory", "capture_budgets"):
            binding = {"pins": self.factory.config["pins"], "session_id": "s"}
            binding[
                {"capture_inventory": "capture_budgets", "capture_budgets": "capture_inventory"}[
                    missing
                ]
            ] = {}
            self.factory.config["capture_instances"] = {
                "row5_controls_and_restoration": {"sources": {}, "binding": binding}
            }
            with (
                self.subTest(missing=missing),
                self.assertRaisesRegex(IntegrityError, "eks_missing:" + missing),
            ):
                self.factory.open_capture("row5_controls_and_restoration")

    def test_fixed_owner_table_counts_resolved_rows_without_uid_multiplier(self):
        schedule = capture_instance_schedule()
        attempts = [s for s in schedule["logical_scopes"] if s["scope"].startswith("attempt:")]
        resets = [s for s in schedule["logical_scopes"] if s["scope"].startswith("reset:")]
        self.assertEqual([s["target_slot"] for s in attempts], [0, 1, 0])
        self.assertEqual(len(resets), 2)
        self.assertEqual(schedule["max_owner_instances"], 13)
        self.assertEqual(len(schedule["logical_scopes"]), 17)
        self.assertFalse(schedule["uid_generations_are_file_multiplier"])
        self.assertEqual(schedule["known_wire_file_count"], 62)
        self.assertEqual(schedule["wire_file_count_expression"], "62 plus 11 unresolved owner rows")
        self.assertIsNone(schedule["whole_run_wire_file_count"])
        self.assertEqual(len(schedule["missing"]), 11)
        self.assertEqual(
            len({row["owner_id"] for row in schedule["logical_scopes"] if row["owner_id"]}), 13
        )
        self.assertTrue(
            all(
                row["v4_lines"] and (row["owner_id"] or row["artifact_only"] or row["shared_with"])
                for row in schedule["logical_scopes"]
            )
        )
        self.assertEqual([r["shared_with"] for r in resets], ["attempt_setup_2", "attempt_setup_3"])
        self.assertTrue(all(r["owner_id"] is None and not r["known_sources"] for r in resets))

    def test_open_capture_requires_table_membership_and_exact_declared_sources(self):
        sources = row5_runtime_sources({"gateway0": "g0", "gateway1": "g1"}, "boot")
        binding = {
            "session_id": "s",
            "pins": self.factory.config["pins"],
            "capture_inventory": source_inventory(slots=(), source_names=list(sources)),
            "capture_budgets": {
                name: {"raw_bytes": 0, "index_bytes": 0, "records": 0} for name in sources
            },
        }
        name = "row5_controls_and_restoration"
        self.factory.config["capture_instances"] = {name: {"sources": sources, "binding": binding}}
        with patch("inference_platform.inf037b_eks_commands.CaptureOwner") as constructor:

            def constructed(**kwargs):
                registry = self.factory.port.store.read()["allocated_capture_owners"]
                self.assertEqual(registry["owners"][0]["owner_id"], name)
                self.assertFalse(registry["owners"][0]["opened"])
                return constructor.return_value

            constructor.side_effect = constructed
            self.assertIs(
                self.factory.open_capture(
                    name,
                    root=str(self.root / "component"),
                    store=SnapshotStore(self.root / "owner-journal", {}),
                ),
                constructor.return_value,
            )
            self.assertEqual(constructor.call_args.kwargs["sources"], sources)
        self.assertTrue(
            self.factory.port.store.read()["allocated_capture_owners"]["owners"][0]["opened"]
        )
        for invalid, reason in (
            ("made_up", "not_in_table"),
            ("cold_startup", "unresolved:capture_sources"),
            ("creation_readiness", "not_in_table"),
        ):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(IntegrityError, reason):
                self.factory.open_capture(invalid)

    def test_separately_rooted_owner_files_include_empty_sources(self):
        sources = {"s": [["controller", "s", "boot"]]}
        binding = {
            "capture_inventory": {
                "schema": "inf037b-capture-inventory-v1",
                "sources": [{"name": "s"}],
                "wire_files": sorted(wire_files(sources)["s"].values()),
            },
            "capture_budgets": {"s": {"raw_bytes": 0, "index_bytes": 0, "records": 0}},
        }
        instance = {"sources": sources, "binding": binding}
        actual = whole_run_wire_files({"first": instance, "second": copy.deepcopy(instance)})
        self.assertEqual(len(actual), 4)
        self.assertEqual(len(set(actual)), 4)
        with self.assertRaisesRegex(IntegrityError, "instance_id"):
            whole_run_wire_files({"../escape": instance})

    def test_real_native_child_runs_authority_command_port_over_http(self):
        child_root = self.root / "child"
        child_root.mkdir()
        code = """import json,sys
from pathlib import Path
from test_inf037b_eks_commands import shell
f=shell(Path(sys.argv[1]),sys.argv[2])
ctx={"input":{},"operation_label":"creation","operation_key":f.port.driver_key+":creation","measurement_deadline_ms":1767225601000}
ids=[]
raw=f.port.create(ctx["operation_key"],ctx["measurement_deadline_ms"],ctx,ids.append)
print(json.dumps({"raw":raw.decode(),"ids":ids}))
"""
        result = subprocess.run(
            [sys.executable, "-c", code, str(child_root), self.url],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {"raw": "real-response", "ids": ["instance"]})


if __name__ == "__main__":
    unittest.main()
