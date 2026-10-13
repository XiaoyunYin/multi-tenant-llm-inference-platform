import importlib.util
import re
import unittest
from decimal import Decimal
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "r1_readonly_refresh", ROOT / "scripts/r1-readonly-refresh.py"
)
REFRESH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REFRESH)


class R1CostEstimateTests(unittest.TestCase):
    def test_terraform_gate_cap_matches_lifecycle_cap(self):
        terraform = (ROOT / "infra/terraform/r1/main.tf").read_text(encoding="utf-8")
        match = re.search(r"m4_estimate_usd\s*<=\s*([0-9]+(?:\.[0-9]+)?)", terraform)
        self.assertIsNotNone(match)
        self.assertEqual(Decimal(match.group(1)), REFRESH.M4_PHASE_CAP_USD)

    def test_committed_prices_reproduce_dec_058_reservation_inclusive_caps(self):
        estimates = REFRESH.estimate_costs(
            Decimal("0.8048000000"),
            Decimal("0.3400000000"),
            Decimal("0.0800000000"),
            Decimal("0.0050000000"),
        )
        self.assertEqual(
            estimates["reservation_allowance_usd"], Decimal("0.2682666666666666666666666667")
        )
        self.assertEqual(estimates["session_estimate_usd"], Decimal("34.70"))
        self.assertEqual(estimates["m4_estimate_usd"], Decimal("86.54"))

    def test_refresh_refuses_prices_that_exceed_either_dec_058_cap(self):
        with self.assertRaisesRegex(ValueError, "R1 estimate exceeds"):
            REFRESH.estimate_costs(
                Decimal("1.00"),
                Decimal("0.34"),
                Decimal("0.08"),
                Decimal("0.005"),
            )


if __name__ == "__main__":
    unittest.main()
