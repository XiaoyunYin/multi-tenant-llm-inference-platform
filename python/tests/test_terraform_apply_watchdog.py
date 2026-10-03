import contextlib
import io
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path

from inference_platform.terraform_apply_watchdog import bounded_apply


class ApplyWatchdogTest(unittest.TestCase):
    def run_child(self, source, seconds=0.3):
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory) / "watchdog.json"
            output = io.StringIO()
            started = time.monotonic()
            with contextlib.redirect_stdout(output):
                code = bounded_apply(
                    [sys.executable, "-u", "-c", source], receipt, seconds, grace=0.2
                )
            self.assertLess(time.monotonic() - started, 5)
            return code, json.loads(receipt.read_text()), output.getvalue()

    def test_capacity_retries_interrupt_with_classified_abort_and_destroy_request(self):
        code, receipt, output = self.run_child(
            "import sys,time; print('InsufficientInstanceCapacity',file=sys.stderr,flush=True); time.sleep(30)"
        )
        self.assertEqual(code, 124)
        self.assertEqual(receipt["abort_reason"], "capacity")
        self.assertTrue(receipt["deadline_exceeded"])
        self.assertTrue(receipt["destroy_requested"])
        self.assertIn("Destroy and VerifyTeardown", output)

    def test_silent_sdk_retry_still_has_deadline_without_inventing_capacity(self):
        code, receipt, _ = self.run_child("import time; time.sleep(30)")
        self.assertEqual(code, 124)
        self.assertEqual(receipt["abort_reason"], "apply_deadline")
        self.assertFalse(receipt["capacity_error_observed"])

    def test_success_and_immediate_capacity_failure_preserve_exit_codes(self):
        code, receipt, _ = self.run_child("print('Apply complete!')", seconds=3)
        self.assertEqual(code, 0)
        self.assertFalse(receipt["destroy_requested"])
        code, receipt, _ = self.run_child(
            "import sys; print('InsufficientHostCapacity'); sys.exit(1)", seconds=3
        )
        self.assertEqual(code, 1)
        self.assertEqual(receipt["abort_reason"], "capacity")

    def test_interrupt_ignored_is_force_stopped(self):
        code, receipt, _ = self.run_child(
            "import signal,time; signal.signal(signal.SIGBREAK if hasattr(signal,'SIGBREAK') else signal.SIGINT, signal.SIG_IGN); print('insufficient capacity',flush=True); time.sleep(30)"
        )
        self.assertEqual(code, 124)
        self.assertTrue(receipt["forced_process_tree_stop"])
