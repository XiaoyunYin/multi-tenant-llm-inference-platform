"""Real TCP authority with an injected portable provider, never cloud evidence."""

import copy
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from inf037b_eks_supervisor_worker import FileJournal

from inference_platform.inf037b_archive import encode, sha
from inference_platform.inf037b_authority import EKS_EFFECTS
from inference_platform.inf037b_eks_provider import ProviderBackend, ScopedAuthority
from inference_platform.inf037b_eks_supervisor import AuthorityHTTP, supervisor_handler
from inference_platform.inf037b_ports import Authority


class ProviderTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.binding = {
            "session_id": "test-session",
            "plan_hash": "a" * 64,
            "t0_ms": 0,
            "group": "unit-group",
            "tokens": ["unit-token"],
        }
        self.pins = {"configuration": "b" * 64}
        self.body = {"binding": self.binding, "pins": self.pins, "stop_ms": 10000}
        self.rows, self.count, self.drop, self.unknown = {}, 0, False, False
        self.bad = None
        case = self

        class Client:
            def response(self, request, result, **extra):
                value = {
                    "request_sha256": sha(encode(request)),
                    "binding": case.binding,
                    "known": True,
                    "complete": True,
                    "settled": True,
                    "result": result,
                    **extra,
                }
                if case.bad:
                    value.update(case.bad)
                return value

            def execute(self, request):
                case.count += 1
                result = {"applied": request["operation"]}
                case.rows[request["key"]] = result
                if case.drop:
                    case.drop = False
                    raise OSError("lost provider reply")
                return self.response(request, result)

            def read(self, request):
                if case.unknown:
                    raise OSError("provider unavailable")
                result = {
                    "complete": True,
                    "settled": True,
                    "resources": [],
                    "application": {k: case.binding[k] for k in ("session_id", "plan_hash")},
                }
                if "scope" in request["body"]:
                    result["scope_sha256"] = sha(encode(request["body"]["scope"]))
                return self.response(request, result)

            def reconcile(self, request):
                if case.unknown:
                    raise OSError("provider unavailable")
                result = case.rows.get(request["key"])
                return self.response(request, result, executed=result is not None)

        self.backend = ProviderBackend(
            binding=self.binding, pins=self.pins, client=Client(), clock=lambda: 100
        )
        with patch("inference_platform.inf037b_authority.DurableStore", FileJournal):
            self.server_authority = self.backend.authority(
                self.root / "server", "unit-provider", initialize=True
            )
        self.server = ThreadingHTTPServer(
            ("127.0.0.1", 0), supervisor_handler(self.server_authority, lambda: "unit-secret")
        )
        thread = threading.Thread(target=self.server.serve_forever)
        thread.start()
        self.addCleanup(thread.join, 2)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.channel = Authority(
            "unit-provider",
            "eks",
            AuthorityHTTP(
                f"http://127.0.0.1:{self.server.server_port}/authority",
                token=lambda: "unit-secret",
                local_test=True,
            ),
        )
        self.remote = self.open()

    def open(self):
        directory = self.root / "client"
        return ScopedAuthority(
            directory,
            self.channel,
            store=FileJournal(
                directory, {"sequence": 0, "operations": {}, "values": {}}, initialize=True
            ),
        )

    def test_local_sequence_gaps_use_a_separate_contiguous_remote_cursor(self):
        for index, parent in enumerate((17, 49, 62)):
            result = self.remote.call("eks.creation.allocate", str(index), parent, self.body)
            self.assertTrue(result["complete"])
        self.assertEqual(self.server_authority.store.read()["watermark"], 3)
        self.assertEqual(self.count, 3)

    def test_every_provider_effect_settles_lost_reply_after_restart_without_repeat(self):
        for index, operation in enumerate(sorted(EKS_EFFECTS)):
            with self.subTest(operation=operation):
                key = "effect-" + str(index)
                self.drop = True
                with self.assertRaises(OSError):
                    self.remote.call(operation, key, 100 + index, self.body)
                self.remote = self.open()
                result = self.remote.call(operation, key, 100 + index, self.body)
                self.assertEqual(result["result"], {"applied": operation})
        self.assertEqual(self.count, len(EKS_EFFECTS))

    def test_unknown_inventory_is_never_empty(self):
        self.unknown = True
        with self.assertRaises(OSError):
            self.remote.call("eks.inventory", "inventory", 0, self.body)

    def test_unknown_reconciliation_does_not_repeat(self):
        self.drop = True
        with self.assertRaises(OSError):
            self.remote.call("eks.creation.allocate", "lost", 17, self.body)
        self.unknown = True
        with self.assertRaises(OSError):
            self.open().call("eks.creation.allocate", "lost", 17, self.body)
        self.assertEqual(self.count, 1)

    def test_inventory_success_and_terminal_scope(self):
        self.assertEqual(
            self.remote.call("eks.inventory", "inventory", 0, self.body)["resources"], []
        )
        body = {
            **self.body,
            "scope": {k: self.binding[k] for k in ("session_id", "t0_ms", "group", "tokens")},
        }
        result = self.remote.call("eks.terminal.inventory", "volumes", 0, body)
        self.assertEqual(result["scope_sha256"], sha(encode(body["scope"])))

    def test_wrong_request_hash_refuses_before_inventory_acceptance(self):
        self.bad = {"request_sha256": "f" * 64}
        with self.assertRaises(OSError):
            self.remote.call("eks.inventory", "inventory", 0, self.body)

    def test_wrong_binding_refuses_before_effect(self):
        body = copy.deepcopy(self.body)
        body["binding"]["session_id"] = "foreign"
        with self.assertRaisesRegex(ValueError, "eks_provider:binding"):
            self.backend.effect("eks.creation.allocate", "one", body)
        self.assertEqual(self.count, 0)

    def test_changed_body_on_restart_refuses(self):
        self.remote.call("eks.creation.allocate", "same", 17, self.body)
        with self.assertRaisesRegex(ValueError, "intent_body"):
            self.open().call("eks.creation.allocate", "same", 17, {**self.body, "extra": 1})
        self.assertEqual(self.count, 1)

    def test_changed_parent_sequence_refuses(self):
        self.remote.call("eks.creation.allocate", "same", 17, self.body)
        with self.assertRaisesRegex(ValueError, "parent_sequence"):
            self.open().call("eks.creation.allocate", "same", 18, self.body)

    def test_settlement_never_allows_retry(self):
        with self.assertRaisesRegex(ValueError, "no_blind_retry"):
            self.remote.call(
                "intent.settle",
                "same",
                17,
                {"operation": "eks.creation.allocate", "body": self.body, "retry": True},
            )

    def test_incomplete_provider_receipt_refuses(self):
        self.bad = {"settled": False}
        with self.assertRaisesRegex(ValueError, "eks_provider:unknown"):
            self.backend.read("eks.inventory", "inventory", self.body)

    def test_foreign_terminal_scope_refuses(self):
        scope = {k: self.binding[k] for k in ("session_id", "t0_ms", "group", "tokens")}
        scope["group"] = "foreign"
        with self.assertRaisesRegex(ValueError, "scope:group"):
            self.backend.read("eks.terminal.inventory", "volumes", {**self.body, "scope": scope})

    def test_expired_request_refuses(self):
        with self.assertRaisesRegex(ValueError, "eks_provider:deadline"):
            self.backend.read("eks.inventory", "inventory", {**self.body, "stop_ms": 100})
