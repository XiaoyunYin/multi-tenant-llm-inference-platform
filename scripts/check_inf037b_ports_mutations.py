"""Single-site port guards, numeric boundaries and durability/effect mutations.

No source file is edited. Fresh module namespaces and reloaded test bindings are
used per mutant. Each new test also runs against a named semantic fault mutant.
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
from unittest.mock import patch

from check_inf037b_resolver_mutations import Mutate, sites

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python/tests"))
from inference_platform import inf037b_controller as controller  # noqa: E402
from inference_platform import inf037b_durable_ports as durable  # noqa: E402
from inference_platform import inf037b_authority as authority  # noqa: E402
from inference_platform import inf037b_ports as ports  # noqa: E402

MODULES = {
    "durable": durable,
    "controller": controller,
    "authority": authority,
    "ports": ports,
}
MATRICES = {
    "test_effect_delivery_and_authority_death_recovery_cut_matrix",
    "test_accepted_row_cut_and_every_public_call_matrix",
    "test_accepted_external_effect_cut_matrix",
    "test_accepted_recover_alone_row_cut_matrix",
    "test_accepted_consumed_stop_cleanup_row_cut_matrix",
    "test_accepted_no_origin_cleanup_row_cut_matrix",
}


class Fault(ast.NodeTransformer):
    def __init__(self, kind, owner=None, point=None):
        self.kind, self.owner, self.point = kind, owner, point

    def visit_FunctionDef(self, node):
        if node.name == self.owner:
            if self.kind == "drop_settlement":
                node.body = [ast.Return(ast.Constant(None))]
                return node
            if self.kind == "omit_cancel_record":
                for child in ast.walk(node):
                    if (
                        isinstance(child, ast.If)
                        and "cancellation is not None" in ast.unparse(child.test)
                        and "result is None" in ast.unparse(child.test)
                    ):
                        child.test = ast.Constant(False)
                return node
            if self.kind == "drop_append":
                node.body = [ast.Return(ast.Constant(True))]
                return node
            if self.kind in {"no_application", "no_consumption"}:
                node.body = [ast.Return(ast.Constant(None))]
                return node
            if self.kind == "no_backstop":
                node.body = [ast.Return(ast.Constant(False))]
                return node
            if self.kind == "wrong_git_blob":
                node.body = [ast.Return(ast.Constant(b"uncommitted fixture"))]
                return node
            if self.kind == "drop_reconcile":
                for statement in ast.walk(node):
                    if (
                        isinstance(statement, (ast.Expr, ast.Return))
                        and isinstance(statement.value, ast.Call)
                        and ast.unparse(statement.value.func) == "self._complete"
                    ):
                        statement.value = ast.Constant(None)
                        break
                return node
            if self.kind == "drop_application_ledger":
                node.body = [n for n in node.body if not isinstance(n, ast.If)]
                return node
            if self.kind in {"drop_anchor", "drop_completion_write"}:
                for statement in node.body:
                    if (
                        isinstance(statement, ast.Expr)
                        and isinstance(statement.value, ast.Call)
                        and ast.unparse(statement.value.func) == "self.store.write"
                    ):
                        node.body.remove(statement)
                        break
                return node
            if self.kind == "rearm":
                branch = next(n for n in node.body if isinstance(n, ast.With))
                condition = next(n for n in branch.body if isinstance(n, ast.If))
                condition.body = [
                    n for n in condition.body if not isinstance(n, ast.Return)
                ]
                return node
            if self.kind == "moving_cancel_time":
                for child in ast.walk(node):
                    if (
                        isinstance(child, ast.Return)
                        and isinstance(child.value, ast.Call)
                        and ast.unparse(child.value.func) == "copy.deepcopy"
                    ):
                        child.value = ast.Call(
                            func=ast.Name(id="dict", ctx=ast.Load()),
                            args=[child.value],
                            keywords=[
                                ast.keyword(arg="stop_ms", value=ast.Constant(-1))
                            ],
                        )
                        break
                return node
        return self.generic_visit(node)

    def visit_If(self, node):
        condition = ast.unparse(node.test)
        if (
            self.kind in {"unknown_cleanup", "refuse_fenced"}
            and condition == "admitted and (not isinstance(exc, ApplyNotExecuted))"
        ):
            node.test = ast.Constant(self.kind == "refuse_fenced")
        if (
            self.kind == "accept_invalid_cancel"
            and condition == "pending['operation'] == 'odcr.cancel' and executed"
        ):
            node.test = ast.Constant(False)
        if self.kind == "fence_pending_cancel" and condition.startswith(
            "pending['operation'] == 'odcr.cancel' or"
        ):
            node.test = ast.Constant(False)
        if self.kind == "execute_abandoned" and condition == "settling and (not retry)":
            node.test = ast.Constant(False)
        if (
            self.kind == "certify_unseen"
            and ast.unparse(node.test) == "state['watermark'] >= minimum"
        ):
            node.test = ast.Constant(True)
        if (
            self.kind == "settle_unknown"
            and ast.unparse(node.test) == "receipt['known'] is not True"
        ):
            node.test = ast.Constant(False)
        return self.generic_visit(node)

    def visit_Compare(self, node):
        if (
            self.kind == "resume_pending_apply"
            and ast.unparse(node) == "pending['operation'] != 'application.apply'"
        ):
            return ast.copy_location(ast.Constant(True), node)
        return self.generic_visit(node)

    def visit_Call(self, node):
        if self.point == (node.lineno, node.col_offset):
            return ast.copy_location(ast.Constant(None), node)
        return self.generic_visit(node)


def hash_file(path):
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def run(names=None, all_tests=False):
    import inf037b_ports_support as support
    import test_inf037b_ports as tests
    import test_inf037b_controller as legacy

    # Controller mutants redefine ReviewedPlan; legacy factories must bind the
    # same class, otherwise an import-identity error could masquerade as a kill.
    importlib.reload(legacy)
    importlib.reload(support)
    importlib.reload(tests)
    cases = [
        (
            tests.PlatformTests,
            "test_unsupported_platform_refuses_before_any_filesystem_effect",
        )
    ]
    cases += [
        (tests.PortsTests, name)
        for name in unittest.defaultTestLoader.getTestCaseNames(tests.PortsTests)
    ]
    chosen = [
        (cls, name)
        for cls, name in cases
        if (name in names if names else all_tests or name not in MATRICES)
    ]
    stream = io.StringIO()
    with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
        result = unittest.TextTestRunner(stream=stream, failfast=True).run(
            unittest.TestSuite(cls(name) for cls, name in chosen)
        )
    return (
        result.wasSuccessful(),
        [str(t) for t, _ in result.failures + result.errors],
        len(result.skipped),
    )


def proof_fault(name):
    """Semantic faults selected by the behavior each named test observes."""
    if name in {
        "test_cancel_verification_blocks_advance_and_recovery_records_cost",
        "test_unverified_cancel_authority_death_recovers_original_stop_and_cost",
        "test_invalid_cancel_results_remain_pending_on_effect_and_reconcile",
    }:
        return {"module": "authority", "kind": "accept_invalid_cancel", "owner": None}
    if (
        name
        == "test_delayed_original_apply_before_settle_is_fenced_after_authority_restart"
    ):
        return {"module": "authority", "kind": "resume_pending_apply", "owner": None}
    if name in {
        "test_lost_acquire_request_is_fenced_and_cleanup_advances",
        "test_lost_add_request_is_fenced_and_cleanup_advances",
        "test_lost_cancel_request_retries_identically_and_advances",
        "test_lost_apply_request_is_fenced_consumed_stop_and_cleanup",
        "test_effect_delivery_and_authority_death_recovery_cut_matrix",
        "test_lost_add_after_partial_acquire_preserves_positive_ledger",
    }:
        return {"module": "ports", "kind": "drop_settlement", "owner": "settle"}
    if name == "test_lost_arm_request_refuses_before_odcr_without_rearm":
        return {"module": "ports", "kind": "rearm", "owner": "arm"}
    if name == "test_omitted_after_cancel_uses_durable_stop_and_advances":
        return {"module": "authority", "kind": "omit_cancel_record", "owner": "_query"}
    guard_map = {
        "test_settlement_binding_namespace_and_retry_policy": "authority:settlement_shape",
        "test_known_not_executed_requires_boolean_and_empty_result": "authority:reconciliation_execution",
        "test_fenced_apply_requires_explicit_execution_proof": "ports:execution_proof",
        "test_invalid_origin_clock_and_fence_epoch_fail_closed": "ports:origin_clock",
        "test_journal_sequence_and_origin_entrypoint_refuse_before_append": "ports:journal_sequence",
        "test_torn_truncated_corrupt_or_missing_store_refuses_reopen": "ports:store_hash",
        "test_request_response_binding_and_unknown_stale_reads": "ports:response_request",
        "test_authority_configuration_and_invalid_bytes_fail_closed": "ports:timeout",
        "test_markers_bind_binary_json_payload_source_pins_and_latest_commit": "ports:exact_marker",
        "test_git_source_reads_committed_blob_not_worktree": "ports:review_commit",
        "test_application_absence_unavailable_contradictory_and_disappeared": "ports:application_binding",
        "test_lagging_absent_and_contradictory_token_reads_never_advance": "ports:reservation_disappeared",
        "test_cancel_missing_ids_wrong_states_or_time_never_acknowledges": "ports:cancel_expected_ids",
        "test_backstop_binding_independence_and_expiration": "ports:independent_backstop",
        "test_gate_requires_markers_current_bindings_and_valid_admission": "ports:marker_required",
        "test_entire_ordered_artifact_set_and_review_marker_count": "ports:marker_count",
        "test_changed_marker_application_pins_and_stored_receipt_refuse": "ports:immutable_marker",
        "test_operation_rebinding_member_shapes_and_cost_boundaries": "ports:operation_binding",
        "test_malformed_reservation_acquisition_and_group_ack_refuse": "ports:acquire_shape",
        "test_short_write_and_corrupt_readback_never_acknowledge": "ports:short_write",
        "test_application_without_consumption_and_wrong_arm_ack_refuse": "ports:application_without_consume",
        "test_authority_request_identity_schema_nonce_and_bounds": "authority:identity",
        "test_authority_effect_sequences_and_duplicate_body_binding": "authority:next_sequence",
        "test_authority_token_fence_rejects_lag_without_client_cached_receipt": "authority:acquired_token_present",
    }
    if name in guard_map:
        return {"kind": "guard", "label": guard_map[name]}
    if name.startswith("test_accepted"):
        return {"module": "durable", "kind": "drop_append", "owner": "append_fsync"}
    special = {
        "test_authority_lost_directory_ack_recovers_without_reexecuting": (
            "authority",
            "drop_completion_write",
            "_complete",
        ),
        "test_authority_never_certifies_an_unseen_or_unsettled_fence": (
            "authority",
            "certify_unseen",
            None,
        ),
        "test_authority_reconciles_lost_effect_without_executing_it_again": (
            "authority",
            "drop_reconcile",
            "_recover",
        ),
        "test_authority_application_ledger_overrules_a_lagging_downstream_read": (
            "authority",
            "drop_application_ledger",
            "_query",
        ),
        "test_authority_reconciliation_needs_an_explicit_known_receipt": (
            "authority",
            "settle_unknown",
            None,
        ),
        "test_application_lost_reply_reconciles_without_second_apply": (
            "ports",
            "no_application",
            "application",
        ),
        "test_unavailable_application_holds_consumed_capacity_until_recovery": (
            "ports",
            "no_application",
            "application",
        ),
        "test_cancel_twice_survives_reopen_with_expected_ids_and_same_time": (
            "ports",
            "moving_cancel_time",
            "cancel",
        ),
        "test_backstop_absence_death_lost_reply_and_no_later_rearm": (
            "ports",
            "rearm",
            "arm",
        ),
        "test_real_backstop_peer_death_and_restart_cannot_rearm": (
            "ports",
            "rearm",
            "arm",
        ),
        "test_origin_samples_completed_barrier_and_unsealed_anchor_refuses": (
            "durable",
            "drop_anchor",
            "append_origin_fsync",
        ),
        "test_v4_84_to_90_in_both_saved_az_orders": ("ports", "no_backstop", "arm"),
        "test_consume_directory_ack_loss_recovers_committed_session": (
            "ports",
            "no_consumption",
            "consumption",
        ),
    }
    if name in special:
        module, kind, owner = special[name]
        return {"module": module, "kind": kind, "owner": owner}
    if name in {
        "test_one_writer_stale_owner_and_fence_mismatch_refuse",
        "test_duplicate_and_concurrent_consume_is_one_durable_session",
        "test_writer_process_exit_releases_fence_without_losing_rows",
    }:
        return {"module": "durable", "kind": "syscall", "call": "fcntl.flock"}
    if name == "test_unsupported_platform_refuses_before_any_filesystem_effect":
        return {"module": "durable", "kind": "platform"}
    if name == "test_torn_temporary_write_and_replace_failure_preserve_prefix":
        return {"module": "durable", "kind": "syscall", "call": "os.replace"}
    return {"module": "durable", "kind": "syscall", "call": "os.fsync"}


def planned_test(label):
    if label.startswith("ports:cancel_"):
        return "test_invalid_cancel_results_remain_pending_on_effect_and_reconcile"
    if label in {
        "authority:settlement_shape",
        "authority:settlement_retry",
        "authority:settlement_effect",
        "authority:settlement_cancel_only",
        "authority:settlement_cancel_retry",
    }:
        return "test_settlement_binding_namespace_and_retry_policy"
    if label in {"authority:reconciliation_execution", "authority:not_executed_result"}:
        return "test_known_not_executed_requires_boolean_and_empty_result"
    if label in {"ports:execution_proof", "ports:fenced_apply_result"}:
        return "test_fenced_apply_requires_explicit_execution_proof"
    groups = {
        "test_torn_truncated_corrupt_or_missing_store_refuses_reopen": [
            "store_envelope",
            "store_schema",
            "store_hash",
        ],
        "test_file_and_directory_fsync_failures_never_acknowledge": ["store_poisoned"],
        "test_short_write_and_corrupt_readback_never_acknowledge": [
            "short_write",
            "write_readback",
        ],
        "test_invalid_origin_clock_and_fence_epoch_fail_closed": [
            "fence_epoch",
            "origin_clock",
        ],
        "test_one_writer_stale_owner_and_fence_mismatch_refuse": [
            "stale_writer",
            "stale_fence",
        ],
        "test_origin_samples_completed_barrier_and_unsealed_anchor_refuses": [
            "unsealed_origin",
            "origin_once",
        ],
        "test_journal_sequence_and_origin_entrypoint_refuse_before_append": [
            "journal_sequence",
            "origin_event",
            "origin_requires_anchor",
            "origin_sequence",
        ],
        "test_authority_configuration_and_invalid_bytes_fail_closed": [
            "authority_identity",
            "transport",
            "timeout",
        ],
        "test_request_response_binding_and_unknown_stale_reads": [
            "response_request",
            "response_authority",
            "response_namespace",
            "response_unknown",
            "response_complete",
            "response_lag",
            "proof_id",
        ],
        "test_markers_bind_binary_json_payload_source_pins_and_latest_commit": [
            "show_binding",
            "source_pin",
            "artifact_pins",
            "commit",
            "review_sections",
            "review_round",
            "committed_review",
            "review_verdict",
            "exact_marker",
            "marker_replay",
        ],
        "test_entire_ordered_artifact_set_and_review_marker_count": [
            "marker_count",
            "artifacts_required",
            "distinct_artifacts",
            "shared_artifacts",
            "ordered_artifacts",
        ],
        "test_gate_requires_markers_current_bindings_and_valid_admission": [
            "marker_descriptor",
            "marker_required",
            "consume_clock",
            "apply_without_consume",
            "apply_hash",
        ],
        "test_duplicate_and_concurrent_consume_is_one_durable_session": ["one_consume"],
        "test_changed_marker_application_pins_and_stored_receipt_refuse": [
            "immutable_marker",
            "application_artifacts",
            "apply_marker",
            "applied_binding",
        ],
        "test_application_absence_unavailable_contradictory_and_disappeared": [
            "application_binding",
            "application_disappeared",
        ],
        "test_application_without_consumption_and_wrong_arm_ack_refuse": [
            "application_without_consume",
            "arm_receipt",
        ],
        "test_malformed_reservation_acquisition_and_group_ack_refuse": [
            "reservation_shape",
            "acquire_shape",
            "add_receipt",
        ],
        "test_lagging_absent_and_contradictory_token_reads_never_advance": [
            "reservation_disappeared",
            "reservation_identity",
            "cancel_regression",
        ],
        "test_operation_rebinding_member_shapes_and_cost_boundaries": [
            "operation_binding",
            "members_shape",
            "member_duplicates",
            "cost_rate",
            "ledger_time",
        ],
        "test_cancel_missing_ids_wrong_states_or_time_never_acknowledges": [
            "cancel_verified",
            "cancel_complete",
            "cancel_ids",
            "cancel_duplicates",
            "cancel_expected_ids",
            "cancel_states",
            "cancel_time",
        ],
        "test_backstop_binding_independence_and_expiration": [
            "independent_backstop",
            "backstop_expired",
            "backstop_not_armed",
            "backstop_session",
            "backstop_deadline",
            "backstop_durable",
            "backstop_arm_id",
        ],
        "test_backstop_absence_death_lost_reply_and_no_later_rearm": [
            "immutable_backstop"
        ],
    }
    if label.startswith("authority:"):
        if label.endswith(
            (
                "refused_token",
                "acquired_token_present",
                "token_identity",
                "cancelled_token",
            )
        ):
            return (
                "test_authority_token_fence_rejects_lag_without_client_cached_receipt"
            )
        if label.endswith("reconciliation_shape"):
            return "test_authority_reconciliation_needs_an_explicit_known_receipt"
        if label.endswith(
            ("idempotent_binding", "idempotent_sequence", "next_sequence")
        ):
            return "test_authority_effect_sequences_and_duplicate_body_binding"
        return "test_authority_request_identity_schema_nonce_and_bounds"
    suffix = label.split(":")[-1]
    return next((test for test, labels in groups.items() if suffix in labels), None)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--native-git", action="store_true")
    args = parser.parse_args()
    if args.native_git:
        import test_inf037b_ports_git as tests

        stream = io.StringIO()
        baseline = unittest.TextTestRunner(stream=stream).run(
            unittest.defaultTestLoader.loadTestsFromTestCase(tests.GitSourceTests)
        )
        with patch.object(
            ports.GitReviewSource, "__call__", return_value=b"uncommitted fixture"
        ):
            result = unittest.TextTestRunner(stream=stream).run(
                unittest.defaultTestLoader.loadTestsFromTestCase(tests.GitSourceTests)
            )
        receipt = {
            "baseline_pass": baseline.wasSuccessful(),
            "baseline_skips": len(baseline.skipped),
            "mutant": "GitReviewSource.__call__ returns worktree bytes",
            "killed_by": [str(t) for t, _ in result.failures + result.errors],
            "tests_lf_sha256": hash_file(
                ROOT / "python/tests/test_inf037b_ports_git.py"
            ),
            "ports_lf_sha256": hash_file(Path(ports.__file__)),
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(receipt, indent=2) + "\n", encoding="utf-8", newline="\n"
        )
        return (
            not receipt["baseline_pass"]
            or not receipt["killed_by"]
            or receipt["baseline_skips"]
        )
    sources = {
        key: Path(module.__file__).read_text(encoding="utf-8")
        for key, module in MODULES.items()
    }
    inputs = [Path(module.__file__) for module in MODULES.values()] + [
        Path(__file__),
        ROOT / "scripts/check_inf037b_resolver_mutations.py",
        ROOT / "python/tests/test_inf037b_ports.py",
        ROOT / "python/tests/inf037b_ports_support.py",
        ROOT / "python/tests/fixtures/inf037b_ports_authority.json",
    ]
    input_hashes = {str(p.relative_to(ROOT)): hash_file(p) for p in inputs}
    metadata = {
        key: {
            name: module.__dict__[name]
            for name in ("__name__", "__package__", "__file__", "__spec__")
        }
        for key, module in MODULES.items()
    }

    def install(changes=None):
        for key, module in MODULES.items():
            module.__dict__.clear()
            module.__dict__.update(metadata[key])
            tree = ast.parse(sources[key])
            if changes and changes[0] == key:
                tree = changes[1].visit(tree)
            exec(
                compile(
                    ast.fix_missing_locations(tree), metadata[key]["__file__"], "exec"
                ),
                module.__dict__,
            )
            module.mutant_noop = lambda *_, **__: None

    install()
    passed, failures, skips = run()
    if not passed or skips:
        raise SystemExit("baseline failed: " + repr(failures))
    records = []
    try:
        for key, source in sources.items():
            if key == "controller":
                continue  # Only the new typed-outcome branch is changed in this slice.
            for site in sites(ast.parse(source)):
                for mode in ("delete", "loosen") if site[4] else ("delete",):
                    install((key, Mutate(site, mode)))
                    planned = planned_test(site[3].strip("'\""))
                    passed, killers, skips = run([planned]) if planned else run()
                    if passed and planned:
                        passed, killers, skips = run()
                    row = {
                        "module": key,
                        "line": site[0],
                        "check": site[3],
                        "operator": mode,
                        "planned_test": planned,
                        "killed": not passed,
                        "tests": killers,
                        "skips": skips,
                    }
                    records.append(row)
                    print(json.dumps(row), flush=True)
        for key, kind, test in (
            (
                "authority",
                "accept_invalid_cancel",
                "test_invalid_cancel_results_remain_pending_on_effect_and_reconcile",
            ),
            (
                "authority",
                "resume_pending_apply",
                "test_delayed_original_apply_before_settle_is_fenced_after_authority_restart",
            ),
            (
                "controller",
                "unknown_cleanup",
                "test_fenced_apply_requires_explicit_execution_proof",
            ),
            (
                "controller",
                "refuse_fenced",
                "test_lost_apply_request_is_fenced_consumed_stop_and_cleanup",
            ),
            (
                "authority",
                "fence_pending_cancel",
                "test_effect_delivery_and_authority_death_recovery_cut_matrix",
            ),
            (
                "authority",
                "execute_abandoned",
                "test_lost_apply_request_is_fenced_consumed_stop_and_cleanup",
            ),
        ):
            install((key, Fault(kind)))
            passed, killers, skips = run([test], all_tests=True)
            row = {
                "module": key,
                "check": kind,
                "operator": "semantic_boundary",
                "planned_test": test,
                "killed": not passed,
                "tests": killers,
                "skips": skips,
            }
            records.append(row)
            print(json.dumps(row), flush=True)
        for node in ast.walk(ast.parse(sources["durable"])):
            if not isinstance(node, ast.Call):
                continue
            call = ast.unparse(node.func)
            if call not in {"os.fsync", "os.replace", "fcntl.flock", "stream.flush"}:
                continue
            if call == "fcntl.flock" and "LOCK_EX" not in ast.unparse(node):
                continue  # Closing the with-owned descriptor also releases the lock.
            install(("durable", Fault("syscall", point=(node.lineno, node.col_offset))))
            passed, killers, skips = run()
            row = {
                "module": "durable",
                "line": node.lineno,
                "check": call,
                "operator": "syscall_delete",
                "killed": not passed,
                "tests": killers,
                "skips": skips,
            }
            records.append(row)
            print(json.dumps(row), flush=True)
        install()
        import test_inf037b_ports as tests

        names = unittest.defaultTestLoader.getTestCaseNames(
            tests.PortsTests
        ) + unittest.defaultTestLoader.getTestCaseNames(tests.PlatformTests)
        proofs = []
        for name in names:
            fault = proof_fault(name)
            if fault["kind"] == "guard":
                matches = [
                    (key, site)
                    for key, source in sources.items()
                    for site in sites(ast.parse(source))
                    if site[3].strip("'\"") == fault["label"]
                ]
                key, site = matches[0]
                transform = Mutate(site, "delete")
            else:
                key = fault["module"]
                tree = ast.parse(sources[key])
                if fault["kind"] == "syscall":
                    node = next(
                        n
                        for n in ast.walk(tree)
                        if isinstance(n, ast.Call)
                        and ast.unparse(n.func) == fault["call"]
                    )
                    transform = Fault("syscall", point=(node.lineno, node.col_offset))
                elif fault["kind"] == "platform":

                    class Platform(ast.NodeTransformer):
                        def visit_If(self, node):
                            if ast.unparse(node.test) == "os.name != 'posix'":
                                return ast.Pass()
                            return self.generic_visit(node)

                    transform = Platform()
                else:
                    transform = Fault(fault["kind"], fault["owner"])
            install((key, transform))
            passed, killers, skips = run([name], all_tests=True)
            row = {
                "test": name,
                "mutant": fault,
                "killed": not passed,
                "killers": killers,
                "skips": skips,
            }
            proofs.append(row)
            print(json.dumps(row), flush=True)
    finally:
        install()
    survivors = [row for row in records if not row["killed"]]
    if input_hashes != {str(p.relative_to(ROOT)): hash_file(p) for p in inputs}:
        raise SystemExit("mutation inputs changed during run")
    receipt = {
        "baseline": "PASS",
        "baseline_skips": 0,
        "input_lf_sha256": input_hashes,
        "scope": "every durable/authority/ports require/exact deletion and numeric one-tick loosening; fsync/flush/replace/OS-lock deletion; six controller/authority semantic boundaries including verified cancellation and delayed pending Apply",
        "per_mutant_test_reload": True,
        "clean_module_namespaces": True,
        "matrices_excluded_per_guard_mutant": sorted(MATRICES),
        "matrix_fault_proofs_run_each": True,
        "mutants": records,
        "survivors": survivors,
        "new_test_fault_proofs": proofs,
        "source_lf_sha256": {
            key: hash_file(Path(module.__file__)) for key, module in MODULES.items()
        },
        "tests_lf_sha256": hash_file(ROOT / "python/tests/test_inf037b_ports.py"),
        "support_lf_sha256": hash_file(ROOT / "python/tests/inf037b_ports_support.py"),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(receipt, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    print(
        f"{len(records) - len(survivors)}/{len(records)} mutants killed; {sum(p['killed'] for p in proofs)}/{len(proofs)} new tests have named fault proofs"
    )
    return bool(survivors) or any(not p["killed"] or p["skips"] for p in proofs)


if __name__ == "__main__":
    sys.exit(main())
