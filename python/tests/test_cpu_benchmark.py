import os
import unittest

from inference_platform.cpu_benchmark import completion_accounting, native_process, percentile


class CPUAnalysisTests(unittest.TestCase):
    def test_completion_observers_keep_failed_clients_failed(self):
        result = {
            "warmup": {"counts": {"completed": 2, "failed": 0, "partial": 0}},
            "measurement": {
                "counts": {"completed": 3, "failed": 1, "partial": 1, "not_dispatched": 10}
            },
        }
        delta = {"gateway0": {"inference_gateway_completed_total": 6}}
        account = completion_accounting(delta, result)
        self.assertEqual(account["server_excess_indeterminate"], 1)
        self.assertEqual(result["measurement"]["counts"]["completed"], 3)
        for impossible in (4, 8):
            delta["gateway0"]["inference_gateway_completed_total"] = impossible
            with self.assertRaises(AssertionError):
                completion_accounting(delta, result)
        result["measurement"]["counts"]["failed"] = 0
        result["measurement"]["counts"]["partial"] = 0
        delta["gateway0"]["inference_gateway_completed_total"] = 6
        with self.assertRaises(AssertionError):
            completion_accounting(delta, result)
        delta["gateway0"]["inference_gateway_completed_total"] = 5
        self.assertEqual(completion_accounting(delta, result)["server_excess_indeterminate"], 0)

    def test_population_sample_rule_and_nearest_rank(self):
        self.assertIsNone(percentile(list(range(1999)), 0.99))
        self.assertIsNone(percentile(list(range(39)), 0.5))
        self.assertEqual(percentile(list(range(1, 2001)), 0.99), 1980)

    def test_native_resources_are_actual_process_values(self):
        sample = native_process(os.getpid())
        self.assertIsNotNone(sample)
        self.assertGreaterEqual(sample["cpu_seconds"], 0)
        self.assertGreater(sample["rss_bytes"], 0)
