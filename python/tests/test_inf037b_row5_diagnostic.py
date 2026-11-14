"""Diagnostic process boundary; live config provenance remains a caller obligation."""

import copy
import json
import os
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from inference_platform.inf037b_archive import IntegrityError, sha
from inference_platform.inf037b_live import LiveRows, RedisAdapter, RedisWire
from inference_platform.inf037b_row5_diagnostic import (
    DiagnosticProcess,
    diagnostic_receipts_from_capture,
    parse_dial_addr,
)


class DiagnosticProcessTests(unittest.TestCase):
    def setUp(self):
        self.binary = Path(__file__)
        self.capture = Mock()
        self.redis = Mock()
        self.port = DiagnosticProcess(
            binary=self.binary,
            binary_sha256=sha(self.binary.read_bytes()),
            capture=self.capture,
            source="diagnostic",
            redis=self.redis,
            dial_addr="127.0.0.1:6379",
        )
        self.config = {
            "redis_addr": "127.0.0.1:6379",
            "namespace": "row5-test",
            "global_capacity": 10,
            "lease_ms": 60000,
            "tombstone_ms": 60000,
            "running": 4,
            "waiting": 1,
            "ttl_ms": 8000,
            "hold_ms": 2000,
            "capture": True,
        }
        self.rid = "rsv_d1a6" + "a" * 28

    def run_port(self, **changes):
        args = dict(
            config=self.config,
            gateway_configs={"gateway0": self.config, "gateway1": self.config},
            measured_tenants=["measured"],
            reservation_id=self.rid,
            deadline_ns=time.monotonic_ns() + 10_000_000_000,
        )
        args.update(changes)
        return self.port._run(**args)

    def test_dial_addr_requires_host_and_valid_port(self):
        self.assertEqual(parse_dial_addr("127.0.0.1:6380"), ("127.0.0.1", 6380))
        self.assertEqual(parse_dial_addr("[::1]:6380"), ("::1", 6380))
        for address in (
            "",
            "redis",
            "redis:0",
            "redis:65536",
            "redis:6379/path",
            "bad host:6379",
            "bad_host:6379",
        ):
            with (
                self.subTest(address=address),
                self.assertRaisesRegex(IntegrityError, "diagnostic_dial_addr"),
            ):
                parse_dial_addr(address)

    def test_process_receipt_is_retained_and_registered(self):
        result = Mock(
            returncode=0,
            stdout=(
                '{"reservation_id":"' + self.rid + '","decision":"allowed",'
                '"capacity":10,"released":true}'
            ).encode(),
            stderr=b"",
        )
        with patch(
            "inference_platform.inf037b_row5_diagnostic.diagnostic_process", return_value=result
        ):
            receipt = self.run_port()
        self.assertEqual(receipt["reservation_id"], self.rid)
        self.assertEqual(self.port.receipt_hashes[self.rid], sha(result.stdout))
        self.assertEqual(self.capture.complete.call_count, 2)
        intent = self.capture.complete.call_args_list[0]
        self.assertEqual(json.loads(intent.args[3])["dial_addr"], self.port.dial_addr)
        self.assertEqual(intent.args[4]["dial_addr"], self.port.dial_addr)
        self.redis.register_diagnostic.assert_called_once_with(receipt)
        with self.assertRaisesRegex(IntegrityError, "diagnostic_receipt_duplicate"):
            self.run_port()

    def test_both_gateway_capture_configurations_are_joined_before_process(self):
        capture = {
            "root": "root",
            "descriptor": {},
            "expected_binding": {"session": "x"},
            "expected_operation": {"key": "x"},
            "expected_descriptor_sha256": "a" * 64,
            "source": "wire",
            "gateway_boot": "boot0",
        }
        captures = {"gateway0": capture, "gateway1": dict(capture, gateway_boot="boot1")}
        result = Mock(
            returncode=0,
            stdout=(
                '{"reservation_id":"' + self.rid + '","decision":"system_capacity",'
                '"capacity":0,"released":false}'
            ).encode(),
            stderr=b"",
        )
        with (
            patch(
                "inference_platform.inf037b_row5_capture.gateway_resolved_config_from_capture",
                return_value=self.config,
            ) as configs,
            patch(
                "inference_platform.inf037b_row5_diagnostic.diagnostic_process", return_value=result
            ),
        ):
            receipt = self.port.run_from_captures(
                config=self.config,
                gateway_captures=captures,
                measured_tenants=["measured"],
                reservation_id=self.rid,
                deadline_ns=time.monotonic_ns() + 5_000_000_000,
            )
        self.assertEqual(configs.call_count, 2)
        self.assertEqual(receipt["decision"], "system_capacity")
        self.assertEqual(
            {call.kwargs["gateway_uid"] for call in configs.call_args_list},
            {"gateway0", "gateway1"},
        )
        captures["gateway1"] = dict(capture)
        with (
            patch(
                "inference_platform.inf037b_row5_capture.gateway_resolved_config_from_capture",
                return_value=self.config,
            ),
            self.assertRaisesRegex(IntegrityError, "diagnostic_config_mismatch"),
        ):
            self.port.run_from_captures(
                config=self.config,
                gateway_captures=captures,
                measured_tenants=["measured"],
                reservation_id="rsv_d1a6" + "b" * 28,
                deadline_ns=time.monotonic_ns() + 5_000_000_000,
            )

        captures["gateway1"] = dict(capture, gateway_boot="boot1")
        changed = copy.deepcopy(self.config)
        changed["global_capacity"] += 1
        with (
            patch(
                "inference_platform.inf037b_row5_capture.gateway_resolved_config_from_capture",
                side_effect=[self.config, changed],
            ),
            self.assertRaisesRegex(IntegrityError, "diagnostic_config_mismatch"),
        ):
            self.port.run_from_captures(
                config=self.config,
                gateway_captures=captures,
                measured_tenants=["measured"],
                reservation_id="rsv_d1a6" + "c" * 28,
                deadline_ns=time.monotonic_ns() + 5_000_000_000,
            )

    def test_mismatch_tenant_and_binary_refuse_before_start(self):
        altered = copy.deepcopy(self.config)
        altered["lease_ms"] += 1
        with self.assertRaisesRegex(IntegrityError, "diagnostic_config_mismatch"):
            self.run_port(gateway_configs={"gateway0": self.config, "gateway1": altered})
        with self.assertRaisesRegex(IntegrityError, "diagnostic_tenant_overlap"):
            self.run_port(measured_tenants=["row5-diagnostic"])
        self.port.binary_sha256 = "b" * 64
        with self.assertRaisesRegex(IntegrityError, "diagnostic_binary"):
            self.run_port()
        self.capture.complete.assert_not_called()

    def test_invalid_configuration_and_timeout_refuse(self):
        invalid = copy.deepcopy(self.config)
        invalid["capture"] = False
        with self.assertRaisesRegex(IntegrityError, "diagnostic_config_mismatch"):
            self.run_port(
                config=invalid, gateway_configs={"gateway0": invalid, "gateway1": invalid}
            )
        from subprocess import TimeoutExpired

        with patch(
            "inference_platform.inf037b_row5_diagnostic.diagnostic_process",
            side_effect=TimeoutExpired("diagnostic", 5, output=b"partial", stderr=b"lost"),
        ):
            with self.assertRaisesRegex(IntegrityError, "diagnostic_process"):
                self.run_port()
        self.assertEqual(self.capture.complete.call_count, 2)
        self.assertEqual(self.capture.complete.call_args.args[3], b"partial")
        self.redis.register_diagnostic.assert_not_called()

    def test_capture_reader_requires_a_successful_process_terminal(self):
        from inference_platform.inf037b_archive import encode

        binding = {"session": "test"}
        sources = {"diagnostic": [["controller", "operator", "boot"]]}
        operation = {
            "body": {
                "binding": binding,
                "capture": {"sources": sources, "attempt": "setup", "boot_id": "collector"},
            }
        }
        descriptor = {
            "binding": binding,
            "operation": operation,
            "sources": sources,
            "attempt": "setup",
            "boot_id": "collector",
            "closed": True,
            "transport_clean": True,
        }
        config = self.config
        intent = encode(
            {
                "config": config,
                "gateway0": config,
                "gateway1": config,
                "dial_addr": "127.0.0.1:6379",
                "reservation_id": self.rid,
            }
        )
        terminal = encode(
            {
                "reservation_id": self.rid,
                "decision": "system_capacity",
                "capacity": 0,
                "released": False,
            }
        )

        def record(body, seq, offset, metadata):
            return (
                {
                    "source": "diagnostic",
                    "operation_sha256": sha(encode(operation)),
                    "sequence": seq,
                    "start_ns": seq * 2,
                    "end_ns": seq * 2 + 1,
                    "offset": offset,
                    "length": len(body),
                    "sha256": sha(body),
                    "metadata": metadata,
                },
                body,
            )

        rows = [
            record(
                intent,
                0,
                0,
                {
                    "event": "diagnostic_intent",
                    "binary_sha256": "a" * 64,
                    "dial_addr": "127.0.0.1:6379",
                },
            ),
            record(
                terminal,
                1,
                len(intent),
                {"event": "diagnostic_terminal", "returncode": 1, "stderr_hex": ""},
            ),
        ]
        with (
            patch("inference_platform.inf037b_probe.capture_rows", return_value=iter(())),
            patch("inference_platform.inf037b_capture.wire_records", return_value=iter(rows)),
            self.assertRaisesRegex(IntegrityError, "diagnostic_capture_incomplete"),
        ):
            diagnostic_receipts_from_capture(
                "unused",
                descriptor,
                expected_binding=binding,
                expected_operation=operation,
                expected_descriptor_sha256=sha(encode(descriptor)),
                source="diagnostic",
                source_generation="boot",
                binary_sha256="a" * 64,
                gateway_configs={"gateway0": config, "gateway1": config},
            )

    def test_error_and_invalid_release_are_captured_and_fail_closed(self):
        result = Mock(returncode=1, stdout=b"{}", stderr=b"failed")
        with patch(
            "inference_platform.inf037b_row5_diagnostic.diagnostic_process", return_value=result
        ):
            with self.assertRaisesRegex(IntegrityError, "diagnostic_process"):
                self.run_port()
        self.assertEqual(self.capture.complete.call_count, 2)
        self.redis.register_diagnostic.assert_not_called()
        with self.assertRaisesRegex(IntegrityError, "diagnostic_receipt_duplicate"):
            self.run_port()

    def test_invalid_receipt_and_late_or_failed_capture_do_not_register(self):
        result = Mock(
            returncode=0,
            stdout=(
                '{"reservation_id":"' + self.rid + '","decision":"allowed",'
                '"capacity":10,"released":false}'
            ).encode(),
            stderr=b"",
        )
        with patch(
            "inference_platform.inf037b_row5_diagnostic.diagnostic_process", return_value=result
        ):
            with self.assertRaisesRegex(IntegrityError, "diagnostic_receipt"):
                self.run_port()
        self.redis.register_diagnostic.assert_not_called()
        self.assertEqual(self.capture.complete.call_count, 2)

        new = "rsv_d1a6" + "b" * 28
        with self.assertRaisesRegex(IntegrityError, "diagnostic_deadline"):
            self.run_port(reservation_id=new, deadline_ns=time.monotonic_ns() - 1)
        self.assertNotIn(new, self.port.used)

        self.capture.complete.side_effect = OSError("capture lost")
        with self.assertRaisesRegex(OSError, "capture lost"):
            self.run_port(reservation_id=new)
        self.assertIn(new, self.port.used)
        self.redis.register_diagnostic.assert_not_called()

    def test_real_diagnostic_uses_redis_capture_and_no_gateway_ack(self):
        binary, addr = os.getenv("ROW5_DIAGNOSTIC_BIN"), os.getenv("REDIS_TEST_ADDR")
        if not binary or not addr:
            self.skipTest("requires Linux diagnostic binary and isolated Redis")
        import tempfile
        import uuid

        from inference_platform.inf037b_archive import encode
        from inference_platform.inf037b_capture import CaptureOwner, wire_records
        from inference_platform.inf037b_durable_ports import DurableStore
        from inference_platform.inf037b_probe import capture_rows

        host, port = addr.rsplit(":", 1)
        wire = RedisWire(host, int(port), tls=False, local_test=True)
        self.addCleanup(wire.close)
        self.config.update(redis_addr="redis:6379", namespace="diagnostic-" + uuid.uuid4().hex)
        redis = RedisAdapter(
            LiveRows("diagnostic", "collector"), wire, self.config["namespace"], "a" * 64
        )
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        boot = root / "boot"
        boot.write_text("collector-boot")
        binding = {"session_id": "row5-diagnostic", "pins": {"source": "a" * 64}}
        sources = {"diagnostic": [["controller", "operator", "operator-boot"]]}
        operation = {
            "operation": "capture",
            "key": "diagnostic-test",
            "sequence": 1,
            "body": {
                "binding": binding,
                "capture": {
                    "sources": sources,
                    "attempt": "setup",
                    "stages": [1, 2, 3, 4, 5],
                    "boot_id": "collector-boot",
                },
            },
        }
        operations = DurableStore(
            root / "operations",
            {"operations": {sha(encode(["capture", "diagnostic-test"])): operation}},
            initialize=True,
        )
        owner = CaptureOwner(
            store=DurableStore(root / "store", {}, initialize=True),
            operation_store=operations,
            operation=operation,
            binding=binding,
            root=root / "retained",
            sources=sources,
            attempt="setup",
            stages=[1, 2, 3, 4, 5],
            boot_path=boot,
        )
        self.port = DiagnosticProcess(
            binary=binary,
            binary_sha256=sha(Path(binary).read_bytes()),
            capture=owner,
            source="diagnostic",
            redis=redis,
            dial_addr=addr,
        )
        receipt = self.run_port()
        descriptor = owner.close()
        self.assertTrue(descriptor["transport_clean"])
        list(capture_rows(owner.root, descriptor))
        wire_log = list(wire_records(owner.root / "wire"))
        self.assertEqual(
            [r[0]["metadata"]["event"] for r in wire_log],
            ["diagnostic_intent", "diagnostic_terminal"],
        )
        self.assertIn(self.rid.encode(), wire_log[1][1])
        self.assertEqual(wire_log[0][0]["metadata"]["dial_addr"], addr)
        binding_args = {
            "expected_binding": binding,
            "expected_operation": operation,
            "expected_descriptor_sha256": sha(encode(descriptor)),
            "source": "diagnostic",
            "source_generation": "operator-boot",
            "binary_sha256": sha(Path(binary).read_bytes()),
            "gateway_configs": {"gateway0": self.config, "gateway1": self.config},
        }
        retained = diagnostic_receipts_from_capture(owner.root, descriptor, **binding_args)
        self.assertEqual(len(retained), 1)
        self.assertEqual({k: retained[0][k] for k in receipt}, receipt)
        self.assertLessEqual(retained[0]["process_start_ns"], retained[0]["process_end_ns"])
        self.assertEqual(retained[0]["receipt_sha256"], sha(wire_log[1][1]))
        with self.assertRaisesRegex(IntegrityError, "diagnostic_capture_descriptor"):
            diagnostic_receipts_from_capture(
                owner.root, descriptor, **dict(binding_args, expected_descriptor_sha256="0" * 64)
            )
        with self.assertRaisesRegex(IntegrityError, "diagnostic_config_mismatch"):
            diagnostic_receipts_from_capture(
                owner.root,
                descriptor,
                **dict(binding_args, gateway_configs={"gateway0": {}, "gateway1": {}}),
            )
        wire_file = next((owner.root / "wire").glob("*.bin"))
        wire_file.write_bytes(wire_file.read_bytes() + b"tampered")
        with self.assertRaisesRegex(IntegrityError, "probe:capture_inventory"):
            diagnostic_receipts_from_capture(owner.root, descriptor, **binding_args)
        self.assertEqual(receipt["decision"], "capacity_reports_expired")
        operations = redis.operations()
        self.assertEqual(len(operations), 1)
        self.assertEqual(operations[0]["payload"]["reservation_id"], self.rid)
        self.assertNotIn("request_id", operations[0]["payload"])
        self.assertFalse(receipt["released"])


if __name__ == "__main__":
    unittest.main()
