import unittest

from inference_platform.r1_generator_probe import summarize_sweep


class GeneratorProbeTests(unittest.TestCase):
    def test_nonmonotone_sweep_retains_low_rate_failure_without_calling_it_the_high_load_knee(self):
        cases = [
            {"nominal_stub_rate": 40, "qualified_20ms": False, "reissue_rate_per_wall_s": 39},
            {"nominal_stub_rate": 80, "qualified_20ms": True, "reissue_rate_per_wall_s": 79},
            {"nominal_stub_rate": 320, "qualified_20ms": True, "reissue_rate_per_wall_s": 304},
            {"nominal_stub_rate": 400, "qualified_20ms": False, "reissue_rate_per_wall_s": 357},
        ]
        result = summarize_sweep(cases)
        self.assertEqual(result["highest_qualified_tested_reissue_rate"], 304)
        self.assertEqual(result["first_failed_nominal_rate"], 40)
        self.assertEqual(result["first_higher_failed_nominal_rate"], 400)
        self.assertEqual(result["failed_nominal_rates"], [40, 400])
        self.assertFalse(result["exact_maximum_established"])
        self.assertFalse(result["all_lower_loads_certified"])
        result = summarize_sweep([cases[0]])
        self.assertIsNone(result["highest_qualified_tested_reissue_rate"])
        self.assertIsNone(result["first_higher_failed_nominal_rate"])
        result = summarize_sweep([cases[1]])
        self.assertIsNone(result["first_failed_nominal_rate"])
