import os
import unittest
from unittest.mock import Mock

from inference_platform.cpu_benchmark import (
    ADMISSION_ARMS,
    Campaign,
    admission_arm_order,
    completion_accounting,
    native_process,
    percentile,
)


class CPUAnalysisTests(unittest.TestCase):
    def test_admission_arm_order_rotates_in_each_block(self):
        orders = [admission_arm_order(block) for block in range(1, 6)]
        self.assertEqual(orders[0], ADMISSION_ARMS)
        self.assertEqual(orders[4], orders[0])
        for arm in ADMISSION_ARMS:
            self.assertEqual({order.index(arm) for order in orders[:4]}, set(range(4)))

    def test_admission_redis_persistence_is_read_back(self):
        campaign = Campaign.__new__(Campaign)
        campaign.redis = Mock(side_effect=["appendonly\nno", "appendfsync\neverysec"])
        campaign.redis_aof = False
        self.assertEqual(
            campaign.redis_persistence(), {"appendonly": "no", "appendfsync": "everysec"}
        )
        self.assertEqual(
            [call.args for call in campaign.redis.call_args_list],
            [
                ("CONFIG", "GET", "appendonly"),
                ("CONFIG", "GET", "appendfsync"),
            ],
        )
        campaign.redis_aof = True
        campaign.redis = Mock(side_effect=["appendonly\nyes", "appendfsync\neverysec"])
        with self.assertRaisesRegex(ValueError, "appendfsync"):
            campaign.redis_persistence()

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
