"""Compact API-wiring witnesses, not a registered maximum or POSIX run.

Real load_maximum, source/spec hashes, actual byte inventories, HTTP authority
and factory path; the host stager alone is a portable copy/receipt fixture.
Maximum cardinality is a pinned-proof assertion here. Its source-current real
generator/build and full POSIX staging remain 4e/4f and AWS-host obligations.
"""

import copy
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from inf037b_setup_fixture import creation_raw
from test_inf037b_eks_commands import shell

from inference_platform.inf037b_archive import IntegrityError, encode, sha, strict_json
from inference_platform.inf037b_eks_fixture import MAXIMUM_FIXTURE_ROWS, fixture_inventory
from inference_platform.inf037b_maximum import current_sources


class FixtureTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory(prefix="r335-fixture-")))
        self.requests, self.stage_calls, self.early_ready = [], [], False
        self.trace, self.bad_ready_destination = [], False
        self.export_destination = {
            "node_uid": "fixture-node",
            "volume_id": "fixture-volume",
            "mount_path": "/fixture",
        }
        self.remote_volume = self.root / "export-host-volume"
        self.now = 1767225600010
        case = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                raw = self.rfile.read(int(self.headers["Content-Length"]))
                request = strict_json(raw)
                case.requests.append(request)
                body = request["body"]
                if request["operation"] == "eks.creation.allocate":
                    case.trace.append("allocate")
                    case.remote_volume.mkdir(exist_ok=True)
                    value = {
                        "created": True,
                        "ready": False,
                        "instance_ids": ["instance"],
                        "export_destination": copy.deepcopy(case.export_destination),
                    }
                else:
                    case.trace.append("P")
                    payload = body["payload"]
                    ready = payload["staging"]["hash"]["end"]["ms"][1] + (
                        -1 if case.early_ready else 5
                    )
                    case.now = max(case.now, ready)
                    binding = {
                        "session_id": body["binding"]["session_id"],
                        "t0_ms": body["binding"]["t0_ms"],
                        "pins": body["pins"],
                    }
                    bundle = strict_json(
                        creation_raw(
                            binding,
                            ready,
                            source_inventory=payload["staging"]["actual_inventory"],
                            boot="host",
                        )
                    )
                    destination = copy.deepcopy(case.export_destination)
                    if case.bad_ready_destination:
                        destination["volume_id"] = "another-volume"
                    bundle.update(
                        staging=payload["staging"],
                        maximum_fixture_sha256=payload["maximum_fixture_sha256"],
                        maximum_fixture_specs=payload["maximum_fixture_specs"],
                        export_destination=destination,
                    )
                    value = {
                        "instance_ids": ["instance"],
                        "export_destination": destination,
                        "raw_hex": encode(bundle).hex(),
                    }
                result = {
                    "request_key": request["key"],
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
        self.factory = shell(
            self.root,
            f"http://127.0.0.1:{self.server.server_port}/",
            {
                "clock_sample": self.point,
                "export_host_stage_fixture": self.portable_stage_witness,
                "export_host_reverify_fixture": self.host_reverify,
            },
        )
        self.source = self.root / "source"
        (self.source / "raw").mkdir(parents=True)
        for name in ("registration.json", "attempts.jsonl", "SHA256SUMS", "raw/controller.jsonl"):
            (self.source / name).write_bytes(b"API fixture\n")
        self.proof = {
            "subject": "lifecycle:maximum_export_fixture",
            "pins": self.factory.config["pins"],
            "schedule_ms": [1560000] * 3 + [300000] * 2,
            "source_lf_sha256": current_sources(),
            "fixture_inventory": fixture_inventory(self.source),
            "registered_archive_rows": MAXIMUM_FIXTURE_ROWS,
            "scope": "current_full_three_attempt_two_reset_fixture",
        }
        self.proof["source_inventory_sha256"] = sha(encode(self.proof["fixture_inventory"]))
        self.proof_path, self.specs_path = self.root / "proof", self.root / "specs"
        self.specs = [
            {"attempt_index": i, "target_slot": slot} for i, slot in enumerate((0, 1, 0), 1)
        ]
        self.write_inputs()
        self.factory.config.update(
            maximum_fixture_source=str(self.source),
            export_fixture_mount_path="/fixture",
            fixture_test_destination=copy.deepcopy(self.export_destination),
        )

    def point(self):
        self.now += 1
        return {"clock_id": "measurement", "boot_id": "host", "ms": [self.now, self.now]}

    def write_inputs(self):
        for name, path, data in (
            ("maximum_fixture", self.proof_path, self.proof),
            ("maximum_fixture_specs", self.specs_path, self.specs),
        ):
            path.write_bytes(encode(data))
            self.factory.config[name] = {"path": str(path), "sha256": sha(path.read_bytes())}

    def portable_stage_witness(self, request):
        self.stage_calls.append(request)
        if not self.remote_volume.is_dir():
            raise IntegrityError("test:export_host_not_created")
        self.trace.append("stage")
        source, target, sample = Path(request["source"]), self.remote_volume / "fixture", self.point
        receipt = {
            "binding": copy.deepcopy(request["binding"]),
            "pins": copy.deepcopy(request["binding"]["pins"]),
            "expected_inventory": copy.deepcopy(request["expected_inventory"]),
            "destination": copy.deepcopy(request["destination"]),
        }
        receipt["copy"] = {"start": sample()}
        target.mkdir()
        for name in request["expected_inventory"]:
            (target / name).parent.mkdir(parents=True, exist_ok=True)
            (target / name).write_bytes((source / name).read_bytes())
        receipt["copy"]["end"] = sample()
        receipt["hash"] = {"start": sample()}
        actual = fixture_inventory(target)
        receipt["hash"]["end"] = sample()
        receipt.update(actual_inventory=actual, manifest_sha256=sha(encode(actual)), verified=True)
        return receipt

    def host_reverify(self, request):
        self.assertEqual(request["destination"], self.export_destination)
        return {
            "binding": request["binding"],
            "destination": copy.deepcopy(self.export_destination),
            "actual_inventory": fixture_inventory(self.remote_volume / "fixture"),
            "verified": True,
        }

    def test_staging_is_after_allocation_bound_to_export_volume_before_P(self):
        raw, _ = self.create()
        self.assertEqual(self.trace, ["allocate", "stage", "P"])
        bundle = strict_json(raw)
        self.assertEqual(bundle["export_destination"], self.export_destination)
        self.assertEqual(bundle["staging"]["destination"], self.export_destination)
        self.factory.staged_creation().reverify(1767225601000)

    def test_other_destination_refuses_at_P(self):
        self.bad_ready_destination = True
        with self.assertRaisesRegex(IntegrityError, "fixture_readiness_destination"):
            self.create()

    def test_missing_host_stager_refuses_after_allocation_without_local_fallback(self):
        del self.factory.implementations["export_host_stage_fixture"]
        with self.assertRaisesRegex(IntegrityError, "unfinished:export_host_stage_fixture"):
            self.create()
        self.assertEqual(self.trace, ["allocate"])
        self.assertFalse((self.root / "staged").exists())
        self.assertFalse((self.remote_volume / "fixture").exists())

    def create(self):
        port = self.factory(self.factory.config).creation
        context = {
            "input": {},
            "operation_label": "creation",
            "operation_key": self.factory.port.driver_key + ":creation",
            "measurement_deadline_ms": 1767225601000,
        }
        ids = []
        return port.create(
            context["operation_key"], context["measurement_deadline_ms"], context, ids.append
        ), ids

    def test_factory_creation_binds_proof_specs_inventory_and_pre_P_receipt(self):
        raw, ids = self.create()
        bundle = strict_json(raw)
        self.assertEqual(ids, ["instance"])
        self.assertEqual(len(self.stage_calls), 1)
        stage = bundle["staging"]
        self.assertEqual(
            stage["binding"],
            {
                "session_id": "s",
                "pins": self.factory.config["pins"],
                "t0_ms": self.factory.binding["t0_ms"],
            },
        )
        self.assertEqual(stage["actual_inventory"], self.proof["fixture_inventory"])
        self.assertLessEqual(stage["hash"]["end"]["ms"][1], bundle["ready"]["ms"][0])
        payload = self.requests[-1]["body"]["payload"]
        self.assertEqual(
            payload["maximum_fixture_sha256"], self.factory.config["maximum_fixture"]["sha256"]
        )
        self.assertEqual(
            payload["maximum_fixture_specs"], self.factory.config["maximum_fixture_specs"]
        )
        self.assertEqual(self.requests[-1]["body"]["binding"], self.factory.binding)

    def test_wrong_effect_key_refuses_before_staging_intent_or_copy(self):
        port = self.factory(self.factory.config).creation
        context = {
            "input": {},
            "operation_label": "creation",
            "operation_key": "wrong:creation",
            "measurement_deadline_ms": 1767225601000,
        }
        with self.assertRaisesRegex(IntegrityError, "eks:effect_key"):
            port.create(
                context["operation_key"],
                context["measurement_deadline_ms"],
                context,
                lambda _: None,
            )
        self.assertEqual(self.stage_calls, [])
        self.assertEqual(self.factory.port.store.read()["operations"], {})

    def test_stale_source_hash_schedule_row_count_and_pins_refuse_before_P(self):
        original = copy.deepcopy(self.proof)
        for field, bad, reason in (
            ("source_lf_sha256", {}, "maximum:current_sources"),
            ("schedule_ms", [1560000] * 3, "maximum:schedule"),
            ("registered_archive_rows", 3, "eks:fixture_rows"),
            (
                "scope",
                "synthetic_compact_adapter_fixture_not_maximum_cardinality",
                "eks:fixture_scope",
            ),
            ("pins", {}, "maximum:pins"),
        ):
            self.proof = {**original, field: bad}
            self.write_inputs()
            with self.subTest(field=field), self.assertRaisesRegex(IntegrityError, reason):
                self.create()
        self.assertEqual(self.stage_calls, [])
        self.assertEqual(self.requests, [])

    def test_proof_hash_and_missing_inputs_refuse_by_name_before_P(self):
        self.factory.config["maximum_fixture"]["sha256"] = "b" * 64
        with self.assertRaisesRegex(IntegrityError, "fixture_hash:maximum_fixture"):
            self.create()
        self.write_inputs()
        self.proof_path.unlink()
        with self.assertRaisesRegex(IntegrityError, "fixture_missing:maximum_fixture"):
            self.create()
        self.factory.config.pop("maximum_fixture")
        with self.assertRaisesRegex(IntegrityError, "fixture_input:maximum_fixture"):
            self.create()
        self.assertEqual(self.requests, [])

    def test_changed_or_missing_fixture_refuses_before_P(self):
        path = self.source / "raw/controller.jsonl"
        path.write_bytes(b"changed")
        with self.assertRaisesRegex(IntegrityError, "eks:fixture_inventory"):
            self.create()
        path.unlink()
        with self.assertRaisesRegex(IntegrityError, "eks:fixture_inventory"):
            self.create()
        self.assertEqual(self.requests, [])
        self.assertEqual(self.stage_calls, [])

    def test_spec_schedule_and_hash_refuse(self):
        self.specs.pop()
        self.write_inputs()
        with self.assertRaisesRegex(IntegrityError, "fixture_specs_schedule"):
            self.create()
        self.factory.config["maximum_fixture_specs"]["sha256"] = "b" * 64
        with self.assertRaisesRegex(IntegrityError, "fixture_hash:maximum_fixture_specs"):
            self.create()

    def test_changed_staged_copy_refuses_without_restage_or_new_P(self):
        self.create()
        (self.remote_volume / "fixture/raw/controller.jsonl").write_bytes(b"changed")
        with self.assertRaisesRegex(IntegrityError, "fixture_staged_inventory"):
            self.factory.staged_creation().reverify(1767225601000)
        self.assertEqual(len(self.stage_calls), 1)
        self.assertEqual(len(self.requests), 2)

    def test_actual_P_must_follow_staging_no_rebase(self):
        self.early_ready = True
        with self.assertRaisesRegex(IntegrityError, "preparation:order"):
            self.create()

    def test_interrupted_stage_refuses_without_retry(self):
        stage = Mock(side_effect=OSError("interrupted"))
        with patch.dict(self.factory.implementations, {"export_host_stage_fixture": stage}):
            with self.assertRaisesRegex(OSError, "interrupted"):
                self.create()
            with self.assertRaisesRegex(IntegrityError, "fixture_interrupted_no_retry"):
                self.create()
            self.assertEqual(stage.call_count, 1)
        self.assertEqual([r["operation"] for r in self.requests], ["eks.creation.allocate"])


if __name__ == "__main__":
    unittest.main()
