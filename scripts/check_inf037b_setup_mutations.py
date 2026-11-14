"""Statement-deletion mutations for setup fitness, observations and setup guards."""

import argparse
import ast
import hashlib
import importlib
import inspect
import io
import json
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python/tests"))

MODULES = {
    "fitness": ROOT / "python/src/inference_platform/inf037b_setup_fitness.py",
    "observations": ROOT
    / "python/src/inference_platform/inf037b_setup_observations.py",
    "setup": ROOT / "python/src/inference_platform/inf037b_setup.py",
}
TEST_MODULES = (
    "test_inf037b_fitness",
    "test_inf037b_observations",
    "test_inf037b_setup",
)
MODULE_IMPORTS = {
    "fitness": ("inf037b_setup_fitness", "FitnessProducer"),
    "observations": ("inf037b_setup_observations", "export_observations"),
    "setup": ("inf037b_setup", "SetupCommands"),
}
FALLBACK_TESTS = {
    ("setup", "startup_row"): (
        "test_inf037b_setup.SetupTests.test_raw_missing_cache_lineage_release_restoration_and_wrong_pins_refuse",
        "test_inf037b_setup.SetupTests.test_component_and_U_plus_one_cannot_hide_in_pending_or_creation",
        "test_inf037b_setup.SetupTests.test_restoration_distinct_uids_slots_nodes_and_cached_binding",
        "test_inf037b_setup.SetupTests.test_startup_serving_guards_refuse_by_named_reason",
    ),
    ("setup", "latest"): (
        "test_inf037b_setup.SetupTests.test_restoration_distinct_uids_slots_nodes_and_cached_binding",
        "test_inf037b_setup.SetupTests.test_raw_missing_cache_lineage_release_restoration_and_wrong_pins_refuse",
    ),
    ("setup", "cleanup_observation"): (
        "test_inf037b_setup.SetupTests.test_cleanup_O_includes_inventory_and_replay_with_upper_bound_and_no_effect",
        "test_inf037b_setup.SetupTests.test_cleanup_O_range_deadline_boot_and_regression_refuse",
    ),
    ("setup", "checked"): (
        "test_inf037b_setup.SetupTests.test_cleanup_O_range_deadline_boot_and_regression_refuse",
        "test_inf037b_setup.SetupTests.test_cleanup_O_includes_inventory_and_replay_with_upper_bound_and_no_effect",
    ),
    ("setup", "lifecycle_input"): (
        "test_inf037b_observations.ObservationTests.test_commands_capture_derive_resolve_and_require_both_raw_inputs",
        "test_inf037b_observations.ObservationTests.test_preparation_observation_includes_raw_derivation_and_validation",
        "test_inf037b_observations.ObservationTests.test_export_reconnect_bound_is_pinned_by_sizing_proof",
    ),
    ("setup", "_capture"): (
        "test_inf037b_observations.ObservationTests.test_commands_capture_derive_resolve_and_require_both_raw_inputs",
        "test_inf037b_observations.ObservationTests.test_preparation_observation_includes_raw_derivation_and_validation",
    ),
    ("setup", "__call__"): (
        "test_inf037b_setup.SetupTests.test_setup_reopen_never_reprobes_an_interrupted_collection",
        "test_inf037b_setup.SetupTests.test_creation_result_lost_ack_replays_once_and_binding_context_changes_refuse",
        "test_inf037b_setup.SetupTests.test_setup_future_source_refuses_before_cleanup",
        "test_inf037b_observations.ObservationTests.test_commands_capture_derive_resolve_and_require_both_raw_inputs",
        "test_inf037b_observations.ObservationTests.test_preparation_observation_includes_raw_derivation_and_validation",
    ),
    ("setup", "__init__"): (
        "test_inf037b_setup.SetupTests.test_setup_collector_guards_refuse_by_named_reason",
        "test_inf037b_setup.SetupTests.test_proof_subject_path_missing_and_sizing_refusals",
    ),
}
EQUIVALENT_SITES = {
    "observations:export_observations:observations:archive_inventory#2": (
        "The observed map is built by iterating the declared map; each observed value is already "
        "exact-checked against its declared file facts. Its keys therefore match by construction, "
        "so this final exact-map check adds no rejection behavior. The separate empty-root guard "
        "remains named and tested."
    ),
    "fitness:equivalence_row:fitness:known_reports#2": (
        "There are exactly two reports by the preceding report_inventory exact check. The first "
        "known_reports exact requires two n values, and `known` includes a report only when its "
        "unknown field is exactly False. Therefore that first exact already implies `unknown is "
        "False`; the second exact adds no behavior."
    ),
    "setup:lifecycle_input:setup:sizing_hash#1": (
        "SetupCommands.__call__ immediately rechecks the same sizing artifact SHA-256 before "
        "accepting preparation, so deleting this earlier lifecycle_input check cannot admit a "
        "changed proof; the command-level hash test still refuses it."
    ),
    "setup:__call__:setup:sizing_artifact#1": (
        "lifecycle_input checks the same sizing proof path before deriving the export row; a "
        "missing proof is already refused with setup:sizing_artifact."
    ),
    "setup:__call__:setup:sizing_hash#1": (
        "lifecycle_input checks the same sizing proof SHA-256 before deriving the export row; a "
        "changed proof is already refused with setup:sizing_hash."
    ),
    "setup:__call__:setup:sizing_subject#1": (
        "export_observations checks the source-bound sizing subject before SetupCommands reaches "
        "this duplicate subject assertion."
    ),
    "setup:__call__:setup:sizing_pins#1": (
        "export_observations checks the sizing proof pins against the effective setup pins before "
        "SetupCommands reaches this duplicate pin assertion."
    ),
    "setup:__call__:setup:readiness_deadline#1": (
        "A ready_ms value beyond stop cannot survive the later command_completion and "
        "creation_future_source checks: ready_ms <= completed <= stop implies ready_ms <= stop. "
        "The direct named-refusal test confirms the earlier reason, while the later checks make "
        "its deletion non-admitting."
    ),
    "setup:__call__:setup:distinct_proof_paths#2": (
        "The first distinct_proof_paths check includes the same component and phase proof paths "
        "plus the sizing proof path; lifecycle_input retains those phase paths. Thus the later "
        "subset check cannot discover a collision that the first check missed."
    ),
    "setup:__call__:setup:distinct_proof_paths#3": (
        "The first distinct_proof_paths check already includes the sizing proof path and rejects "
        "any path collision, so this later sizing_path-not-in-paths assertion is implied."
    ),
}


def call_name(node):
    if isinstance(node.func, ast.Name):
        return node.func.id
    return getattr(node.func, "attr", "")


def owners(tree):
    functions = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    return {
        id(node): min(
            (
                func
                for func in functions
                if func.lineno < node.lineno <= func.end_lineno
            ),
            key=lambda func: func.end_lineno - func.lineno,
            default=None,
        )
        for node in ast.walk(tree)
        if hasattr(node, "lineno")
    }


def sites(tree, module_name):
    parent = {
        id(child): node
        for node in ast.walk(tree)
        for child in ast.iter_child_nodes(node)
    }
    owner = owners(tree)
    occurrences = {}
    result = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or call_name(node) not in {
            "require",
            "exact",
        }:
            continue
        statement = parent.get(id(node))
        if not isinstance(statement, ast.Expr) or statement.value is not node:
            raise AssertionError(
                f"non-statement guard at {node.lineno}: {ast.unparse(node)}"
            )
        function = owner[id(node)]
        function_name = function.name if function else "<module>"
        reason_node = node.args[-1] if node.args else None
        reason = (
            reason_node.value
            if isinstance(reason_node, ast.Constant)
            and isinstance(reason_node.value, str)
            else None
        )
        key = (
            function_name,
            reason if reason is not None else ast.unparse(reason_node),
        )
        occurrence = occurrences.get(key, 0) + 1
        occurrences[key] = occurrence
        site_id = f"{module_name}:{function_name}:{key[1]}#{occurrence}"
        result.append(
            {
                "module": module_name,
                "line": node.lineno,
                "column": node.col_offset,
                "function": function_name,
                "call": call_name(node),
                "reason": reason,
                "reason_expr": ast.unparse(reason_node) if reason_node else "",
                "site_id": site_id,
                "statement": statement,
            }
        )
    return sorted(result, key=lambda item: (item["line"], item["column"]))


def string_constants(node):
    return {
        item.value
        for item in ast.walk(node)
        if isinstance(item, ast.Constant) and isinstance(item.value, str)
    }


def reason_prefix(node, function_name):
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str):
            return node.left.value
    if isinstance(node, ast.Name) and node.id == "reason" and function_name == "cover":
        return "fitness:resource_cadence"
    if isinstance(node, ast.Name) and node.id == "reason":
        return "fitness:"
    return None


def test_registry():
    registry = []
    for module_name in TEST_MODULES:
        path = ROOT / "python/tests" / f"{module_name}.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for cls in (node for node in tree.body if isinstance(node, ast.ClassDef)):
            if cls.name in {"ProcessSetupTests", "ExportMemoryTests"}:
                continue
            for method in (
                node
                for node in cls.body
                if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")
            ):
                registry.append(
                    {
                        "test_id": f"{module_name}.{cls.name}.{method.name}",
                        "module": module_name,
                        "class": cls.name,
                        "method": method.name,
                        "constants": string_constants(method),
                    }
                )
    return registry


def candidates(site, source_tree, registry):
    if site["reason"] is not None:
        matches = [item for item in registry if site["reason"] in item["constants"]]
        if matches:
            return matches
    else:
        node = next(
            n
            for n in ast.walk(source_tree)
            if isinstance(n, ast.Call)
            and n.lineno == site["line"]
            and n.col_offset == site["column"]
        )
        prefix = reason_prefix(node.args[-1], site["function"]) if node.args else None
        if prefix is not None:
            matches = [
                item
                for item in registry
                if any(value.startswith(prefix) for value in item["constants"])
            ]
            if matches:
                return matches
    ids = FALLBACK_TESTS.get((site["module"], site["function"]), ())
    if not ids:
        ids = tuple(
            item["test_id"]
            for item in registry
            if item["module"]
            == TEST_MODULES[
                0
                if site["module"] == "fitness"
                else 1
                if site["module"] == "observations"
                else 2
            ]
        )
    wanted = set(ids)
    return [item for item in registry if item["test_id"] in wanted]


class DeleteGuard(ast.NodeTransformer):
    def __init__(self, site):
        self.site = site
        self.changed = False

    def visit_Expr(self, node):
        value = node.value
        if (
            isinstance(value, ast.Call)
            and (value.lineno, value.col_offset)
            == (self.site["line"], self.site["column"])
            and call_name(value) in {"require", "exact"}
        ):
            self.changed = True
            return ast.copy_location(ast.Pass(), node)
        return self.generic_visit(node)


def import_targets(modules, mutant_label):
    for label, (module_name, symbol) in MODULE_IMPORTS.items():
        module = modules[label]
        if label == mutant_label:
            assert getattr(module, "__codex_mutant_marker__", None) is not None, (
                label,
                module.__name__,
                getattr(module, "__codex_mutant_marker__", None),
            )
        assert module.__name__.endswith(module_name), (
            label,
            module.__name__,
            module_name,
        )
        for test_module in modules["tests"]:
            if label == "fitness" and test_module.__name__ == "test_inf037b_fitness":
                assert getattr(test_module, symbol) is getattr(module, symbol)
            elif (
                label == "observations"
                and test_module.__name__ == "test_inf037b_observations"
            ):
                assert getattr(test_module, symbol) is getattr(module, symbol)
            elif label == "setup" and test_module.__name__ in {
                "test_inf037b_setup",
                "test_inf037b_observations",
            }:
                assert getattr(test_module, symbol) is getattr(module, symbol)


def load_test_modules():
    return [importlib.reload(importlib.import_module(name)) for name in TEST_MODULES]


def make_suite(test_modules, selected=None):
    wanted = set(selected) if selected is not None else None
    suite = unittest.TestSuite()
    for module in test_modules:
        for name, cls in vars(module).items():
            if not inspect.isclass(cls) or not issubclass(cls, unittest.TestCase):
                continue
            if cls.__module__ != module.__name__:
                continue
            if cls.__name__ in {"ExportMemoryTests", "ProcessSetupTests"}:
                continue
            for method in unittest.defaultTestLoader.getTestCaseNames(cls):
                test_id = f"{module.__name__}.{cls.__name__}.{method}"
                if wanted is None or test_id in wanted:
                    suite.addTest(cls(method))
    return suite


def run_tests(test_modules, selected=None, mutant_site=None):
    stream = io.StringIO()
    old_site = os.environ.get("INF037B_MUTATION_SITE_ID")
    if mutant_site is None:
        os.environ.pop("INF037B_MUTATION_SITE_ID", None)
    else:
        os.environ["INF037B_MUTATION_SITE_ID"] = mutant_site
    try:
        result = unittest.TextTestRunner(stream=stream, verbosity=0, failfast=True).run(
            make_suite(test_modules, selected)
        )
    finally:
        if old_site is None:
            os.environ.pop("INF037B_MUTATION_SITE_ID", None)
        else:
            os.environ["INF037B_MUTATION_SITE_ID"] = old_site
    failures = [test.id() for test, _ in result.failures + result.errors]
    return result, failures, stream.getvalue()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--limit", type=int, default=0, help="Debug only: run the first N sites"
    )
    args = parser.parse_args()

    originals, metadata = {}, {}
    parsed, all_sites = {}, []
    imported = {}
    for label, path in MODULES.items():
        source = path.read_text(encoding="utf-8").replace("\r\n", "\n")
        tree = ast.parse(source)
        parsed[label] = (path, source, tree)
        module_name = path.stem
        module = importlib.import_module(f"inference_platform.{module_name}")
        imported[label] = module
        originals[label] = compile(source, str(path), "exec")
        metadata[label] = {
            key: module.__dict__[key]
            for key in ("__name__", "__package__", "__file__", "__spec__")
        }
        all_sites.extend(sites(tree, label))
    if args.limit:
        all_sites = all_sites[: args.limit]

    registry = test_registry()
    # Small named smoke baseline; full module receipts are run separately.
    baseline_modules = load_test_modules()
    baseline_names = [
        "test_inf037b_fitness.FitnessTests.test_all_five_rows_derive_without_resolver_fixtures_and_leave_inputs_unchanged",
        "test_inf037b_observations.ObservationTests.test_export_raw_bytes_margin_rate_and_real_resumable_copy",
        "test_inf037b_setup.SetupTests.test_raw_startups_equality_pending_delayed_creation_and_provenance",
    ]
    baseline_result, baseline_failures, baseline_output = run_tests(
        baseline_modules, baseline_names
    )
    if not baseline_result.wasSuccessful() or baseline_result.skipped:
        raise SystemExit("baseline must pass without skips: " + baseline_output)

    records = []
    try:
        for index, site in enumerate(all_sites, 1):
            label = site["module"]
            path, source, tree = parsed[label]
            transformed = DeleteGuard(site)
            mutant_tree = transformed.visit(ast.parse(source))
            if not transformed.changed:
                raise AssertionError(
                    "mutation operator failed to replace guard with pass"
                )
            module = imported[label]
            module.__dict__.clear()
            module.__dict__.update(metadata[label])
            exec(
                compile(ast.fix_missing_locations(mutant_tree), str(path), "exec"),
                module.__dict__,
            )
            module.__dict__["__codex_mutant_marker__"] = site["site_id"]
            test_modules = load_test_modules()
            modules_with_tests = {"tests": test_modules, **imported}
            import_targets(modules_with_tests, label)
            selected = candidates(site, tree, registry)
            selected_ids = [item["test_id"] for item in selected]
            equivalent = EQUIVALENT_SITES.get(site["site_id"])
            if selected_ids:
                result, failures, output = run_tests(
                    test_modules, selected_ids, mutant_site=site["site_id"]
                )
                killer = failures[0] if failures else None
                attempted = selected_ids
            else:
                failures, output = [], ""
                attempted = []
                killer = None
            row = {
                "index": index,
                "site_id": site["site_id"],
                "module": label,
                "line": site["line"],
                "function": site["function"],
                "call": site["call"],
                "reason": site["reason"],
                "reason_expr": site["reason_expr"],
                "mutation": "statement_delete_require_exact_to_pass",
                "registered_candidates": selected_ids,
                "attempted": attempted,
                "killed": killer is not None,
                "killer_test": killer,
                "equivalent_reason": equivalent,
                "failure_output": output if killer else None,
            }
            records.append(row)
            print(
                json.dumps(
                    {k: row[k] for k in ("index", "site_id", "killed", "killer_test")}
                ),
                flush=True,
            )
    finally:
        for label, module in imported.items():
            module.__dict__.clear()
            module.__dict__.update(metadata[label])
            exec(originals[label], module.__dict__)

    survivors = [
        row for row in records if not row["killed"] and row["equivalent_reason"] is None
    ]
    equivalents = [row for row in records if row["equivalent_reason"] is not None]
    equivalent_killed_overlaps = [row["site_id"] for row in equivalents if row["killed"]]
    receipt = {
        "baseline": {
            "tests": baseline_result.testsRun,
            "skips": len(baseline_result.skipped),
            "failures": baseline_failures,
        },
        "source_lf_sha256": {
            label: hashlib.sha256(source.encode()).hexdigest()
            for label, (_, source, _) in parsed.items()
        },
        "test_lf_sha256": {
            name: hashlib.sha256(
                (ROOT / "python/tests" / f"{name}.py")
                .read_text(encoding="utf-8")
                .replace("\r\n", "\n")
                .encode()
            ).hexdigest()
            for name in TEST_MODULES
        },
        "harness_lf_sha256": hashlib.sha256(
            Path(__file__).read_text(encoding="utf-8").replace("\r\n", "\n").encode()
        ).hexdigest(),
        "runner_asserted_imported_mutant_identity": True,
        "mutation": "each require/exact call statement replaced individually with pass",
        "complete": not args.limit,
        "registered_killer_source": "test methods containing the exact refusal reason or matching dynamic reason prefix; unregistered mutants remain explicit survivors",
        "excluded_from_mutant_killers": [
            "ProcessSetupTests (real child-process path is covered by the pinned setup suite)",
            "ExportMemoryTests (scaled RSS path is covered by the pinned setup suite)",
        ],
        "mutants": records,
        "killed": len(records) - len(survivors) - len(equivalents),
        "equivalent": equivalents,
        "equivalent_count": len(equivalents),
        "equivalent_killed_overlaps": equivalent_killed_overlaps,
        "survivors": survivors,
        "unexplained_survivors": survivors,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(receipt, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    print(
        f"{receipt['killed']}/{len(records)} non-equivalent guards killed; "
        f"{receipt['equivalent_count']} equivalents; "
        f"{len(equivalent_killed_overlaps)} equivalent sites also fail their named-refusal test; "
        f"{len(survivors)} unexplained survivors"
    )
    return bool(survivors)


if __name__ == "__main__":
    raise SystemExit(main())
