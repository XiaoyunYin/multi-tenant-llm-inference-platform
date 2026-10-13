"""Public context selection must retain portable tests and expose omissions."""

import importlib.util
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "public_runner", Path(__file__).resolve().parents[1] / "run_public_python_tests.py"
)
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


class PublicSelectionTest(unittest.TestCase):
    def case(self, identity):
        case = unittest.FunctionTestCase(lambda: None)
        case.id = lambda: identity
        return case

    def test_missing_private_spec_cases_reported_portable_siblings_retained(self):
        identities = [
            "test_r1.ManifestTests.test_exact_pinned_manifest_and_sentinel",
            "test_r1_cloud.CloudTests.test_host_spec_artifact_checks_identical_registered_bytes_without_git",
            "test_r1_cloud.CloudTests.test_bundle_integrity_inventory_and_traversal_before_execution",
            "test_r1.ResetTests.test_generator_cannot_dispatch_during_pending_preparation",
        ]
        suite = unittest.TestSuite(
            [unittest.TestSuite(self.case(i) for i in identities)]
        )
        selected, omitted = RUNNER.select(suite)
        self.assertEqual([case.id() for case in selected], identities[2:])
        self.assertEqual([row["case"] for row in omitted], identities[:2])
        self.assertTrue(all(row["reason"] for row in omitted))

    def test_prefix_collision_does_not_hide_unrelated_cases(self):
        case = self.case("test_r1.ManifestTestsExtra.test_case")
        selected, omitted = RUNNER.select(unittest.TestSuite([case]))
        self.assertEqual(list(selected), [case])
        self.assertEqual(omitted, [])


if __name__ == "__main__":
    unittest.main()
