"""Public context selection must retain portable tests and expose omissions."""

import ast
import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

SPEC = importlib.util.spec_from_file_location(
    "public_runner", Path(__file__).resolve().parents[1] / "run_public_python_tests.py"
)
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


class PublicSelectionTest(unittest.TestCase):
    def test_matrix_helpers_work_without_the_private_runner_pythonpath(self):
        root = Path(__file__).resolve().parents[2]
        env = {**os.environ, "PYTHONPATH": str(root / "python/src")}
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "unittest",
                "test_public_python_selection.PublicSelectionTest.test_case_shards_keep_every_case_once_and_use_measured_weights",
                "test_public_python_selection.PublicSelectionTest.test_matrix_verification_refuses_missing_cases_and_slow_or_failed_job",
            ],
            cwd=root / "scripts/tests",
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("Ran 2 tests", completed.stderr)

    def test_private_catalog_uses_real_exact_cases_and_keeps_portable_siblings(self):
        self.assertEqual(
            RUNNER.PRIVATE_MODULES,
            {
                "test_remote_source_fitness",
                "test_stage_c_fitness",
                "test_stage_c_preflight",
                "test_stage_c_protocol",
                "test_stage_c_session",
                "test_stage_c_sizing",
                "test_routine_prune",
            },
        )
        self.assertEqual(set(RUNNER.PRIVATE_MODULE_REASONS), RUNNER.PRIVATE_MODULES)
        root = Path(__file__).resolve().parents[2]
        for identity, reason in RUNNER.PRIVATE_CASES.items():
            self.assertTrue(reason)
            parts = identity.split(".")
            if len(parts) == 2:
                self.assertEqual(identity, "test_r1.ManifestTests")
                continue
            self.assertEqual(len(parts), 3, identity)
            module, owner, method = parts
            tree = ast.parse((root / "python/tests" / (module + ".py")).read_bytes())
            classes = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)}
            self.assertIn(owner, classes, identity)
            self.assertIn(
                method,
                {n.name for n in classes[owner].body if isinstance(n, ast.FunctionDef)},
                identity,
            )
        identities = list(RUNNER.PRIVATE_CASES)
        siblings = [name + "_portable_sibling" for name in identities]
        selected, omitted = RUNNER.select(
            unittest.TestSuite(self.case(name) for name in identities + siblings)
        )
        self.assertEqual([case.id() for case in selected], siblings)
        self.assertEqual([row["case"] for row in omitted], identities)

    def test_parent_and_real_child_import_only_the_exported_fixture_and_source_first(
        self,
    ):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, body in {
                "scripts/run_public_python_tests.py": Path(RUNNER.__file__).read_text(
                    encoding="utf-8"
                ),
                "scripts/cpu_test_runner.py": (
                    Path(RUNNER.__file__).parent / "cpu_test_runner.py"
                ).read_text(),
                "python/src/inference_platform/__init__.py": "",
                "python/src/inference_platform/package_a_cpu_validation.py": (
                    "def result_record(result, passed):\n"
                    " return {'run':result.testsRun,'passed':passed,'failures':len(result.failures),'errors':len(result.errors),'skips':[]}\n"
                ),
                "python/src/production_helper.py": "VALUE = 'exported-source'\n",
                "python/tests/fixture_helper.py": "VALUE = 'exported-fixture'\n",
                "wrong/production_helper.py": "VALUE = 'wrong-source'\n",
                "wrong/fixture_helper.py": "VALUE = 'wrong-fixture'\n",
                "python/tests/test_child.py": (
                    "import subprocess, sys, unittest\n"
                    "import production_helper\n"
                    "class ChildTests(unittest.TestCase):\n"
                    " def test_child(self):\n"
                    "  self.assertEqual(production_helper.VALUE, 'exported-source')\n"
                    "  code = 'import production_helper, fixture_helper; "
                    "print(production_helper.VALUE, fixture_helper.VALUE)'\n"
                    "  value = subprocess.check_output([sys.executable, '-c', code], text=True)\n"
                    "  self.assertEqual(value.strip(), 'exported-source exported-fixture')\n"
                ),
            }.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(body, encoding="utf-8", newline="\n")
            result = subprocess.run(
                [sys.executable, str(root / "scripts/run_public_python_tests.py")],
                cwd=root,
                env={**os.environ, "PYTHONPATH": str(root / "wrong")},
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Ran 1 test", result.stderr)

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

    def test_case_shards_keep_every_case_once_and_use_measured_weights(self):
        suite = [self.case(f"test_demo.C.test_{i}") for i in range(12)]
        weights = {
            "cases": {suite[0].id(): 100},
            "modules": {"test_demo.py": {"weight_s": 12}},
        }
        divided = RUNNER.shards(suite, 4, weights)
        self.assertEqual(
            sorted(c.id() for group in divided for c in group),
            sorted(c.id() for c in suite),
        )
        self.assertEqual(len(next(group for group in divided if suite[0] in group)), 1)
        self.assertEqual(
            [[c.id() for c in group] for group in divided],
            [
                [c.id() for c in group]
                for group in RUNNER.shards(list(reversed(suite)), 4, weights)
            ],
        )

    def test_matrix_verification_refuses_missing_cases_and_slow_or_failed_job(self):
        import copy
        import hashlib
        from verify_public_shards import verify

        names = ["test_x.C.test_one", "test_x.C.test_two"]
        digest = hashlib.sha256("\n".join(names).encode()).hexdigest()
        reports = [
            {
                "shard": i,
                "count": 2,
                "selected_cases": [names[i]],
                "catalog_sha256": digest,
                "public_cases": 2,
                "result": {"errors": 0, "failures": 0},
            }
            for i in range(2)
        ]
        jobs = [{"shard": i, "exit_code": 0, "elapsed_s": 100} for i in range(2)]
        checks = {"exit_code": 0, "elapsed_s": 10}
        self.assertTrue(verify(reports, jobs, checks)["complete"])
        broken = copy.deepcopy(reports)
        broken[1]["selected_cases"] = []
        with self.assertRaisesRegex(ValueError, "union"):
            verify(broken, jobs, checks)
        for elapsed, status in ((900, 0), (100, 1)):
            with self.assertRaisesRegex(ValueError, "failed_or_15_minute_job"):
                verify(
                    reports,
                    [jobs[0], {**jobs[1], "elapsed_s": elapsed, "exit_code": status}],
                    checks,
                )
            with self.assertRaisesRegex(ValueError, "failed_or_15_minute_checks_job"):
                verify(reports, jobs, {"elapsed_s": elapsed, "exit_code": status})

    def test_readme_sentences_derive_from_actual_selector(self):
        root = Path(__file__).resolve().parents[2]
        sys.path.insert(0, str(root / "python/tests"))
        modules = sorted(
            p.stem
            for p in (root / "python/tests").glob("test_*.py")
            if p.stem not in RUNNER.PRIVATE_MODULES
        )
        suite = unittest.TestSuite(
            unittest.defaultTestLoader.loadTestsFromName(name) for name in modules
        )
        _, omitted = RUNNER.select(suite)
        report = {
            "private_record_modules_excluded": sorted(RUNNER.PRIVATE_MODULES),
            "private_record_cases_excluded": omitted,
        }
        template = root / "scripts/public_snapshot/README.public.md"
        # In the exported tree the rendered README replaces the private template.
        readme = template if template.exists() else root / "README.md"
        text = readme.read_text(encoding="utf-8")
        self.assertEqual(RUNNER.update_readme(text, report), text)


if __name__ == "__main__":
    unittest.main()
