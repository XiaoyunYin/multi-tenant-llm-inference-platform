"""Code-derived missing-input coverage and the unchanged CPU preparation gate."""

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from inference_platform.inf037b_archive import encode
from inference_platform.inf037b_eks_commands import capture_instance_schedule
from inference_platform.package_a_cloud import TASK_CHECKS, selected_checks
from inference_platform.package_a_operator import host_check_preflight_binding

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "four_e_inputs", ROOT / "scripts/build_inf037b_4e_inputs.py"
)
producer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(producer)


class InputInventoryTests(unittest.TestCase):
    def test_committed_output_matches_current_code_and_assignments(self):
        self.assertEqual(producer.OUTPUT.read_bytes(), encode(producer.inventory()))

    def test_repeated_generation_is_byte_identical(self):
        self.assertEqual(encode(producer.inventory()), encode(producer.inventory()))

    def test_every_unresolved_owner_scope_is_inventoried(self):
        report = producer.inventory()
        names = {r["id"] for r in report["inputs"] if r["id"].startswith("capture_scope:")}
        expected = {
            "capture_scope:" + r["scope"]
            for r in capture_instance_schedule()["logical_scopes"]
            if r["status"] == "unresolved"
        }
        self.assertEqual(names, expected)
        self.assertEqual(len(expected), 11)

    def test_runtime_fallback_reason_keeps_its_port_qualifier(self):
        report = producer.inventory()
        row = next(r for r in report["inputs"] if r["id"] == "4e_execution_runtime")
        self.assertIn("eks:unfinished:<port>:4e_execution_runtime", row["refusal_templates"])

    def fixture(self, name, text):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        path = root / "python/src/inference_platform" / name
        path.parent.mkdir(parents=True)
        path.write_text(text, encoding="utf-8")
        return root

    def test_literal_stops_dependencies_and_runtime_key_domains_are_discovered(self):
        root = self.fixture(
            "inf037b_eks_execution.py",
            "class Runtime:\n"
            " def call(self):\n"
            "  require(False, 'eks:unfinished:4e_new_explicit')\n"
            "  self.need('new_document')\n"
            "  self.component('new_component', object)\n"
            "  factory.dependency('new_named_interface')\n",
        )
        entries, _ = producer.collect(root, include_schedule=False)
        self.assertEqual(
            set(entries),
            {"4e_new_explicit", "4e_new_document", "4e_new_component", "new_named_interface"},
        )
        self.assertEqual(entries["4e_new_document"]["consumers"][0]["line"], 4)

    def test_unbounded_dynamic_runtime_key_refuses_inventory(self):
        root = self.fixture(
            "inf037b_eks_execution.py", "class Runtime:\n def run(self, key):\n  self.need(key)\n"
        )
        with self.assertRaisesRegex(ValueError, "4e_inventory:dynamic_key"):
            producer.collect(root, include_schedule=False)

    def test_new_unassigned_input_is_not_silently_omitted(self):
        entries, _ = producer.collect()
        entries["4e_new_unassigned"] = {"id": "4e_new_unassigned", "consumers": []}
        rules = json.loads(producer.ASSIGNMENTS.read_bytes())
        with self.assertRaisesRegex(ValueError, "assignment_coverage.*4e_new_unassigned"):
            producer.assign(entries, rules)

    def test_duplicate_policy_assignment_refuses(self):
        entries, _ = producer.collect()
        rules = json.loads(producer.ASSIGNMENTS.read_bytes())
        rules["rules"].append(copy.deepcopy(rules["rules"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate_assignment"):
            producer.assign(entries, rules)

    def test_cli_check_rejects_stale_output(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        output = root / "inventory.json"
        output.write_bytes(b"{}\n")
        with patch("sys.argv", ["build", "--check", "--output", str(output)]):
            with self.assertRaisesRegex(ValueError, "4e_inventory:stale_output"):
                producer.main()


class CPUPreparationGateTests(unittest.TestCase):
    def test_existing_replacement_is_only_for_the_accepted_three_checks(self):
        self.assertEqual(TASK_CHECKS, ("race", "e2e", "row5"))
        self.assertEqual(
            host_check_preflight_binding(TASK_CHECKS)["status"], "REPLACED_BY_HOST_CHECKS"
        )
        with self.assertRaisesRegex(ValueError, "real_dependency_preflight_required"):
            host_check_preflight_binding(("linux", "eks_host"))

    def test_requested_cpu_validation_is_not_an_existing_task_label(self):
        with self.assertRaisesRegex(ValueError, "invalid_task_checks"):
            selected_checks(("eks_cpu_validation",))
