"""Offline single-site controller receipt; reload the test module per mutant.

Same require/exact delete and numeric one-tick-loosen operators as slice (1),
plus every refusal call and deletion of the deadline/remaining-work wiring.
No repository source is modified.
"""

import argparse
import ast
import contextlib
import hashlib
import importlib
import io
import json
import sys
import unittest
from pathlib import Path

from check_inf037b_resolver_mutations import Mutate, sites

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python/tests"))
from inference_platform import inf037b_controller as controller  # noqa: E402

OMITTED_MATRIX = "test_every_public_call_order_into_consumed_and_refused_states"
EQUIVALENT = {
    ("'controller:utc_nonnegative'", "loosen"): (
        "UTC literals have whole-second precision: utc_ms returns multiples of 1000. "
        "Loosening >=0 to >=-1 admits no additional literal."
    ),
    ("'controller:bound_first'", "delete"): (
        "journal_bound rejects every non-bound first row; journal_duplicate rejects "
        "a second (bound,-1). Thus no accepted prefix can reach a later first bound row."
    ),
    ("'controller:journal_bound'", "delete"): (
        "The constructor's reopened_binding exact check rejects any prefix lacking "
        "bound; bound_first prevents adding bound after another row. No public call "
        "or backend effect is reachable from such a prefix."
    ),
}

EXPECTED = {
    "'controller:readiness_cutoff'": [
        "test_readiness_cutoff_refuses_before_consumption_and_apply"
    ],
    "'controller:acquired_ids_cancelled'": [
        "test_cancellation_ids_include_both_durable_and_lookup_identities"
    ],
    "'controller:cancelled_lookup'": [
        "test_post_cancel_lookup_must_be_cancelled_with_and_without_origin"
    ],
    "'controller:partial_cost'": [
        "test_partial_cost_does_not_depend_on_receipt_id_list"
    ],
    "'controller:application_receipt'": [
        "test_application_receipt_is_bound_before_reconciling_applied"
    ],
}
STATEMENT_EQUIVALENT = {
    (
        "_replay: require(not self.facts, 'controller:bound_first')",
        "statement_delete",
    ): (EQUIVALENT[("'controller:bound_first'", "delete")]),
    (
        "_replay: require(self._get('bound') is not None, 'controller:journal_bound')",
        "statement_delete",
    ): EQUIVALENT[("'controller:journal_bound'", "delete")],
}


def controller_sites(tree):
    result = sites(tree)
    statement_calls = {
        id(n.value)
        for n in ast.walk(tree)
        if isinstance(n, ast.Expr) and isinstance(n.value, ast.Call)
    }
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = (
            node.func.id
            if isinstance(node.func, ast.Name)
            else getattr(node.func, "attr", "")
        )
        if name in {"refusal", "check_consume", "remaining_work", "SessionDeadline"}:
            # A constructor used as a statement is a literal-validation gate.
            if name == "SessionDeadline" and id(node) not in statement_calls:
                continue
            result.append(
                (node.lineno, node.col_offset, name, ast.unparse(node), False)
            )
    return sorted(result)


def statement_sites(tree):
    result = []
    definitions = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]
    for node in ast.walk(tree):
        if not isinstance(node, ast.stmt) or isinstance(
            node, (ast.FunctionDef, ast.ClassDef, ast.Import, ast.ImportFrom, ast.Pass)
        ):
            continue
        if (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            continue
        owners = [d for d in definitions if d.lineno < node.lineno <= d.end_lineno]
        owner = (
            min(owners, key=lambda d: d.end_lineno - d.lineno).name
            if owners
            else "<module>"
        )
        label = owner + ": " + ast.unparse(node).splitlines()[0]
        result.append((node.lineno, node.col_offset, type(node).__name__, label, False))
        if isinstance(node, ast.If):
            result.append((node.lineno, node.col_offset, "negate_if", label, False))
    return sorted(result)


class StatementMutate(ast.NodeTransformer):
    def __init__(self, site):
        self.site = site

    def visit(self, node):
        if (
            getattr(node, "lineno", None),
            getattr(node, "col_offset", None),
        ) == self.site[:2]:
            if self.site[2] == "negate_if" and isinstance(node, ast.If):
                node.test = ast.UnaryOp(op=ast.Not(), operand=node.test)
                return self.generic_visit(node)
            if type(node).__name__ == self.site[2] and isinstance(node, ast.stmt):
                return ast.copy_location(ast.Pass(), node)
        return super().visit(node)


def expected_tests(site, kills):
    planned = EXPECTED.get(site[3])
    label = site[3]
    if "controller:readiness_cutoff" in label:
        planned = [
            "test_fallback_acquire_readiness_cutoff_cancels_without_create"
            if site[0] < controller.Controller._admit.__code__.co_firstlineno
            else "test_readiness_cutoff_refuses_before_consumption_and_apply"
        ]
    if label in {
        "_complete_consume: admitted = True",
        "_complete_consume: if admitted and (not isinstance(exc, ApplyNotExecuted)):",
        "_complete_consume: raise",
    }:
        planned = ["test_unknown_apply_oserror_holds_capacity_until_reconciliation"]
    if label.startswith(
        ("_write: self._validate_candidate", "_origin: self._validate_candidate")
    ):
        planned = ["test_write_and_origin_validate_candidate_before_append"]
    elif label in {
        "_complete_consume: consumption = self.gate.consumption(self.session_id)",
        "_complete_consume: if consumption is None:",
    }:
        planned = [
            "test_oserror_after_consume_commit_applies_and_journals_without_cancel",
            "test_oserror_before_consume_commit_queries_before_zero_session_refusal",
        ]
    elif label in {
        "refuse: if self._get('rejected', index) is not None:",
        "refuse: self._cancel(index)",
    }:
        planned = [
            "test_refuse_after_failed_cancel_returns_status_without_rewriting_rejection"
        ]
    elif label == "_complete_consume: self._admit(index)":
        planned = ["test_post_consume_journal_delay_rechecks_time_before_apply"]
    elif label.startswith("_complete_consume: self._write('applied'"):
        planned = [
            "test_completed_recover_uses_applied_row_without_apply_or_arm",
            "test_lost_apply_reply_reconciles_without_reapply_or_cancellation",
        ]
    elif label in {
        "acquire: if self._get('rejected', index) is not None:",
        "acquire: self._cancel(index)",
    }:
        planned = ["test_rejected_acquire_retries_cancel_without_reverification"]
    elif label in {"recover: self.acquire()", "recover: self.mark()"}:
        planned = [
            "test_recover_alone_from_every_journal_cut_resumes_only_pending_operation"
        ]
    elif label.startswith("_cancel: self._write('advanced'"):
        planned = [
            "test_no_origin_stop_recovers_alone_through_advance",
            "test_recover_alone_from_every_journal_cut_resumes_only_pending_operation",
        ]
    if planned:
        matched = next(
            (kill for name in planned for kill in kills if kill.startswith(name + " ")),
            None,
        )
        return matched, planned
    return kills[0] if kills else None, None


class ControllerMutate(Mutate):
    def visit_Call(self, node):
        if (node.lineno, node.col_offset) == self.site[:2] and self.site[2] in {
            "refusal",
            "check_consume",
            "remaining_work",
            "SessionDeadline",
        }:
            node.func = ast.Name(id="mutant_noop", ctx=ast.Load())
            return node
        return super().visit_Call(node)


def run(priority=None):
    import test_inf037b_controller as tests

    importlib.reload(tests)
    stream = io.StringIO()
    with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
        names = unittest.defaultTestLoader.getTestCaseNames(tests.ControllerTests)
        names = list(dict.fromkeys((priority or []) + names))
        result = unittest.TextTestRunner(stream=stream, failfast=True).run(
            unittest.TestSuite(
                tests.ControllerTests(name) for name in names if name != OMITTED_MATRIX
            )
        )
    kills = sorted({str(test) for test, _ in result.failures + result.errors})
    return result.wasSuccessful(), kills


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--operators", choices=("all", "checks", "statements"), default="all"
    )
    args = parser.parse_args()
    path = Path(controller.__file__)
    source = path.read_text(encoding="utf-8")
    original = compile(source, str(path), "exec")
    records = []
    try:
        passed, failures = run()
        if not passed:
            raise SystemExit("baseline failed: " + repr(failures))
        controller.mutant_noop = lambda *args, **kwargs: None
        passes = []
        if args.operators in ("all", "checks"):
            passes.extend(
                (site, mode, "checks")
                for site in controller_sites(ast.parse(source))
                for mode in (("delete", "loosen") if site[4] else ("delete",))
            )
        if args.operators in ("all", "statements"):
            passes.extend(
                (
                    site,
                    "if_negate" if site[2] == "negate_if" else "statement_delete",
                    "statements",
                )
                for site in statement_sites(ast.parse(source))
            )
        for site, mode, operator_pass in passes:
            tree = (
                ControllerMutate(site, mode)
                if operator_pass == "checks"
                else StatementMutate(site)
            ).visit(ast.parse(source))
            exec(
                compile(ast.fix_missing_locations(tree), str(path), "exec"),
                controller.__dict__,
            )
            _, priority = expected_tests(site, [])
            passed, kills = run(priority)
            expected, planned = expected_tests(site, kills)
            record = {
                "operator_pass": operator_pass,
                "line": site[0],
                "kind": site[2],
                "check": site[3],
                "mutation": mode,
                "killed": not passed,
                "expected_test": expected,
                "tests": kills,
            }
            if planned:
                record["planned_tests"] = planned
                record["expected_control_missing"] = not passed and expected is None
            records.append(record)
            if passed:
                record["survivor_reason"] = (
                    EQUIVALENT if operator_pass == "checks" else STATEMENT_EQUIVALENT
                ).get((site[3], mode))
            print(json.dumps(record), flush=True)
            exec(original, controller.__dict__)
    finally:
        exec(original, controller.__dict__)
    survivors = [row for row in records if not row["killed"]]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(
            {
                "controller_lf_sha256": hashlib.sha256(source.encode()).hexdigest(),
                "tests_lf_sha256": hashlib.sha256(
                    (ROOT / "python/tests/test_inf037b_controller.py")
                    .read_text(encoding="utf-8")
                    .encode()
                ).hexdigest(),
                "baseline": "PASS",
                "normal_suite_only": [OMITTED_MATRIX],
                "operators": args.operators,
                "failfast": True,
                "priority_controls": True,
                "statement_exclusions": [
                    "imports",
                    "function/class definitions",
                    "docstrings",
                    "pass (no behavior)",
                ],
                "mutants": records,
                "survivors": survivors,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"{len(records) - len(survivors)}/{len(records)} mutants killed")
    print("Survivors: " + json.dumps(survivors, sort_keys=True))
    return any(row.get("survivor_reason") is None for row in survivors) or any(
        row.get("expected_control_missing") for row in records
    )


if __name__ == "__main__":
    sys.exit(main())
