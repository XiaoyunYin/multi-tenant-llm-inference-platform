"""Tiny real HTTP + portable file-store protocol; not S3/POSIX evidence."""

import copy
import http.client
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import Mock

from inf037b_eks_store_fixture import portable_persist, store_binding
from inf037b_eks_supervisor_worker import FileJournal

from inference_platform.inf037b_archive import encode
from inference_platform.inf037b_eks_commands import EKSCommandFactory
from inference_platform.inf037b_eks_stores import (
    ArtifactHTTPAccess,
    RecoveryRepository,
    join_access,
)
from inference_platform.inf037b_resolver import SessionDeadline


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.controller = {"session_id": "s", "C_ms": 10000, "D_session_ms": 18010000, "t0_ms": 17}
        self.pins = {"test": "a" * 64}
        self.binding = store_binding(self.root, self.controller, self.pins)
        path = self.root / "input.json"
        path.write_bytes(b'{"small":true}\n')
        self.artifacts = {"source/input.json": path}
        self.persist_count, self.drop = 0, False
        case = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                if self.headers.get("Authorization") != "Bearer test-token":
                    self.send_error(403)
                    return
                digest, name, key = self.path.strip("/").split("/", 2)
                base = (
                    Path(case.binding["recovery"]["root"])
                    if name == "recovery"
                    else case.root / "unit-s3"
                )
                source = base / "objects" / digest / key
                if not source.is_file():
                    self.send_error(404)
                    return
                data = source.read_bytes()
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                receipt = case.repository.publish("one", case.artifacts, 10000)
                if case.drop:
                    self.close_connection = True
                    return
                data = encode(receipt)
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=self.server.serve_forever)
        thread.start()
        self.addCleanup(thread.join, 2)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.access = ArtifactHTTPAccess(
            f"http://127.0.0.1:{self.server.server_port}",
            token=lambda: "test-token",
            root=self.root / "retrieved",
            clock=lambda: 100,
            local_test=True,
        )
        self.journal = FileJournal(self.root / "unit-recovery/journal", {}, initialize=True)
        self.repository = self.open()

    def persist(self, *, artifacts, **kwargs):
        self.persist_count += 1
        return portable_persist(artifacts, self.binding, self.root)

    def open(self, binding=None):
        return RecoveryRepository(
            binding=binding or self.binding,
            journal=self.journal,
            store_ports={},
            access=self.access,
            clock=lambda: 100,
            metadata_root=self.root / "unit-recovery/meta",
            persist=self.persist,
        )

    def publish(self):
        return self.repository.publish("one", self.artifacts, 10000)

    def stored_file(self, receipt, name="s3"):
        base = self.root / ("unit-s3" if name == "s3" else "unit-recovery")
        return base / "objects" / receipt["source_manifest_sha256"] / "source/input.json"

    def test_lost_http_ack_reopens_the_same_receipt_without_repeating_persistence(self):
        self.drop = True
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=2)
        try:
            connection.request("POST", "/publish", body=b"{}")
            with self.assertRaises(http.client.RemoteDisconnected):
                connection.getresponse()
        finally:
            connection.close()
        reopened = self.open()
        receipt = reopened.publish("one", self.artifacts, 10000)
        accessed = reopened.access(receipt, 10000)
        self.assertEqual(join_access(accessed, receipt, self.binding), receipt["manifest"])
        self.assertEqual(self.persist_count, 1)
        self.assertEqual(set(accessed["store_readbacks"]), {"recovery", "s3"})

    def test_missing_store_refuses(self):
        receipt = self.publish()
        self.stored_file(receipt).unlink()
        with self.assertRaisesRegex(ValueError, "4c:access_missing"):
            self.repository.access(receipt, 10000)

    def test_stale_store_refuses_hash(self):
        receipt = self.publish()
        path = self.stored_file(receipt)
        path.write_bytes(b"x" * path.stat().st_size)
        with self.assertRaisesRegex(ValueError, "4c:access_hash"):
            self.repository.access(receipt, 10000)

    def test_partial_store_refuses_length(self):
        receipt = self.publish()
        self.stored_file(receipt).write_bytes(b"x")
        with self.assertRaisesRegex(ValueError, "4c:access_length"):
            self.repository.access(receipt, 10000)

    def test_restart_preserves_versions_ack_identities_and_store_binding(self):
        receipt = self.publish()
        reopened = self.open()
        self.assertEqual(reopened.publish("one", self.artifacts, 10000), receipt)
        self.assertEqual(
            reopened.access(receipt, 10000)["export_artifacts"]["source/input.json"].read_bytes(),
            b'{"small":true}\n',
        )
        wrong = copy.deepcopy(self.binding)
        wrong["s3"]["bucket"] = "different"
        with self.assertRaisesRegex(ValueError, "4c:reopen_binding"):
            self.open(wrong)

    def test_post_seal_source_mutation_is_not_a_new_publication(self):
        self.publish()
        self.artifacts["source/input.json"].write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "4c:publication_immutable"):
            self.repository.publish("one", self.artifacts, 10000)
        self.assertEqual(self.persist_count, 1)

    def test_manifest_and_store_receipt_joins_refuse_at_access(self):
        receipt = self.publish()
        bad = copy.deepcopy(receipt)
        bad["source_manifest_sha256"] = "b" * 64
        with self.assertRaisesRegex(ValueError, "part3:store_manifest_join"):
            self.repository.access(bad, 10000)
        bad = copy.deepcopy(receipt)
        bad["s3"]["receipt"]["objects"]["source/input.json"]["request_id"] = None
        with self.assertRaisesRegex(ValueError, "4c:s3_ack_identity"):
            self.repository.access(bad, 10000)

    def test_all_four_factory_ports_bind_original_session_and_supervisor_checkpoint(self):
        deadline = SessionDeadline(
            self.controller["C_ms"], self.controller["D_session_ms"], self.controller["t0_ms"]
        ).effective_ms
        backstop = SimpleNamespace(
            store=FileJournal(
                self.root / "backstop", {"values": {"deadline/s": deadline}}, initialize=True
            ),
            authority=SimpleNamespace(identity="independent-authority"),
        )
        factory = SimpleNamespace(
            binding=self.controller,
            config={
                "pins": self.pins,
                "state_destination": "independent-destination",
                "recovery_store_binding": self.binding,
            },
            implementations={
                "4d_recovery_store_runtime": lambda stop: {"repository": self.repository}
            },
            controller=SimpleNamespace(backstop=backstop),
            port=SimpleNamespace(deadline=Mock()),
        )
        factory.dependency = lambda name: EKSCommandFactory.dependency(factory, name)
        request = {"binding": {"session_id": "s", "t0_ms": 17, "pins": self.pins}, "stop_ms": 10000}
        self.assertEqual(factory.dependency("4c_export_stores")(request), self.binding)
        receipt = self.publish()
        self.assertEqual(
            set(
                factory.dependency("4c_export_artifact_access")({"store_receipt": receipt}, 10000)[
                    "export_artifacts"
                ]
            ),
            set(self.artifacts),
        )
        self.assertEqual(
            factory.dependency("4c_recovery_stores")(10000)["binding"], self.controller
        )
        proof = factory.dependency("4c_recovery_supervisor")(10000)
        self.assertEqual(proof["D_eff_ms"], deadline)
        self.assertEqual(
            proof["checkpoint_sha256"],
            proof["store_receipt"]["manifest"]["control/supervisor.json"]["sha256"],
        )
        self.assertEqual(len(proof["store_receipt"]["acknowledgements"]), 2)

    def test_uncertain_internal_store_failure_needs_reconciliation_not_a_repeat(self):
        self.repository.persist = Mock(side_effect=TimeoutError("unknown write"))
        with self.assertRaises(TimeoutError):
            self.publish()
        with self.assertRaisesRegex(ValueError, "4c:publication_pending"):
            self.publish()
        self.assertEqual(self.repository.persist.call_count, 1)

    def test_receipt_from_same_stores_with_different_policy_binding_refuses(self):
        from inference_platform.inf037b_eks_stores import validate_receipt

        receipt = self.publish()
        changed = copy.deepcopy(self.binding)
        changed["s3"]["policy_sha256"]["access"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "4c:receipt_store_binding"):
            validate_receipt(receipt, changed, receipt["manifest"])
