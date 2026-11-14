"""Small real child pipes and owner-backed pre-retain request overflow."""

import subprocess
import sys
import time
import unittest
from unittest.mock import patch

import test_inf037b_capture_inventory as inventory_tests

from inference_platform.inf037b_archive import IntegrityError, encode
from inference_platform.inf037b_bounded import bounded_json, diagnostic_process
from inference_platform.inf037b_row5 import BoundedRBACHTTP


class BoundedTests(unittest.TestCase):
    def owner(self):
        fixture = inventory_tests.InventoryTests(methodName="runTest")
        self.addCleanup(fixture.doCleanups)
        owner = fixture.worker_owner()
        owner.binding["capture_budgets"] = {
            name: {"raw_bytes": 100000, "index_bytes": 100000, "records": 100}
            for name in owner.sources
        }
        return owner

    def test_real_process_overflow_keeps_bounded_partial_and_sticky_loss(self):
        for pipe in ("stdout", "stderr"):
            with self.subTest(pipe=pipe):
                owner = self.owner()
                with self.assertRaisesRegex(IntegrityError, "diagnostic_output_size"):
                    diagnostic_process(
                        [sys.executable, "-c", f"import sys; sys.{pipe}.buffer.write(b'x'*65536)"],
                        input=b"",
                        timeout=3,
                        capture=owner,
                        source="diagnostic",
                        clock=time.monotonic_ns,
                    )
                self.assertTrue(owner.failed)
                self.assertTrue(
                    any(
                        "diagnostic_output_size" in item
                        for item in owner.store.read()["capture"]["losses"]
                    )
                )
                self.assertLessEqual(owner.wire["diagnostic"]["offset"], 16384 + 4096)
                self.assertGreater(owner.wire["diagnostic"]["offset"], 16384)

    def test_process_success_preserves_existing_terminal_format(self):
        owner = self.owner()
        result = diagnostic_process(
            [sys.executable, "-c", "print('{}')"],
            input=b"",
            timeout=3,
            capture=owner,
            source="diagnostic",
            clock=time.monotonic_ns,
        )
        self.assertEqual(
            (result.returncode, result.stdout, result.stderr),
            (0, b"{}\r\n" if sys.platform == "win32" else b"{}\n", b""),
        )
        self.assertEqual(owner.wire["diagnostic"]["records"], 0)
        self.assertFalse(owner.failed)

    def test_process_timeout_retains_bounded_stdout_for_terminal_and_loss(self):
        owner = self.owner()
        with self.assertRaises(subprocess.TimeoutExpired) as caught:
            diagnostic_process(
                [
                    sys.executable,
                    "-c",
                    "import sys,time; print('partial',flush=True); time.sleep(2)",
                ],
                input=b"",
                timeout=0.2,
                capture=owner,
                source="diagnostic",
                clock=time.monotonic_ns,
            )
        self.assertIn(b"partial", caught.exception.stdout)
        self.assertIn("diagnostic:diagnostic_timeout", owner.store.read()["capture"]["losses"])

    def test_rbac_projection_refuses_before_encoding_or_connecting_with_sticky_loss(self):
        owner = self.owner()
        owner.binding["capture_budgets"]["rbac"]["raw_bytes"] = 64
        http = BoundedRBACHTTP(
            "http://localhost",
            token=lambda: "unit",
            deadline_ns=time.monotonic_ns() + 2_000_000_000,
            retain=owner.retainer("rbac"),
            local_test=True,
        )
        with (
            patch("http.client.HTTPConnection") as connect,
            patch(
                "inference_platform.inf037b_bounded.json.dumps", wraps=__import__("json").dumps
            ) as dump,
        ):
            with self.assertRaisesRegex(IntegrityError, "fitness:rbac_request_size"):
                http.json_request("PUT", "/role", {"rules": "x" * 100000})
            connect.assert_not_called()
            self.assertTrue(
                all(
                    not isinstance(call.args[0], str) or len(call.args[0]) <= 1024
                    for call in dump.call_args_list
                )
            )
        self.assertIn("rbac:fitness:rbac_request_size", owner.store.read()["capture"]["losses"])
        self.assertEqual(owner.wire["rbac"]["offset"], 0)

    def test_bounded_json_matches_canonical_escape_and_exact_size(self):
        value = {"z": [None, True, 1, 1.25], "a": ('"\\\n\u1234' * 400)}
        expected = encode(value)
        self.assertEqual(bounded_json(value, limit=len(expected), loss=lambda _: None), expected)
        losses = []
        with self.assertRaisesRegex(IntegrityError, "rbac_request_size"):
            bounded_json(value, limit=len(expected) - 1, loss=losses.append)
        self.assertEqual(losses, ["fitness:rbac_request_size"])


if __name__ == "__main__":
    unittest.main()
