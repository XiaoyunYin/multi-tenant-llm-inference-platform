import threading
import time
import unittest

from inference_platform.r1_calibration_rows import CalibrationRows


class CalibrationRowsTests(unittest.TestCase):
    def test_bounded_identity_salt_order_and_no_dispatch_tokenization(self):
        caller, calls = threading.get_ident(), []

        def build(identity, salt, tokenizer):
            calls.append((threading.get_ident(), identity, salt))
            return {"id": identity, "tokens": [len(calls)] * 16}

        rows = CalibrationRows(2, "salt-cal", None, build, set(), time.perf_counter() + 5)
        try:
            for cycle in range(5):
                for worker in range(4):
                    self.assertEqual(
                        rows.take(worker)["id"], f"cal-{worker // 2}-2-{worker}-cycle-{cycle}"
                    )
            self.assertLessEqual(rows.high_water, 8)
            self.assertTrue(all(tid != caller and salt == "salt-cal" for tid, _, salt in calls))
        finally:
            rows.close()
        self.assertFalse(rows.thread.is_alive())

    def test_first_block_collision_propagates_and_producer_stops(self):
        def build(identity, salt, tokenizer):
            return {"id": identity, "tokens": [1] * 16}

        with self.assertRaisesRegex(ValueError, "first-block collision"):
            CalibrationRows(1, "salt", None, build, {(1,) * 16}, time.perf_counter() + 5)
