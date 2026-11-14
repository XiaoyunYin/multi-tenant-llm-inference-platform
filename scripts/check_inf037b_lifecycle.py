"""Reproduce the first 4b slice, baseline absence, and named guard/fault kills."""

import argparse
import ast
import contextlib
import hashlib
import importlib
import io
import json
import os
import platform
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python/tests"))

FILES = [
    "python/src/inference_platform/inf037b_lifecycle.py",
    "python/tests/test_inf037b_lifecycle.py",
    "python/tests/test_inf037b_lifecycle_recovery.py",
    "python/tests/inf037b_lifecycle_worker.py",
    "scripts/check_inf037b_lifecycle.py",
    "python/src/inference_platform/inf037b_authority.py",
    "python/src/inference_platform/inf037b_controller.py",
    "python/src/inference_platform/inf037b_attempts.py",
    "python/src/inference_platform/inf037b_resolver.py",
    "python/src/inference_platform/inf037b_ports.py",
    "python/src/inference_platform/inf037b_durable_ports.py",
    "python/src/inference_platform/inf037b_archive.py",
    "python/src/inference_platform/inf037b_contract.py",
    "scripts/check_inf037b_resolver_mutations.py",
    "python/tests/inf037b_ports_support.py",
    "python/tests/test_inf037b_controller.py",
    "python/tests/test_inf037b_ports.py",
    "python/tests/test_inf037b_placement.py",
    "python/tests/test_inf037b_resolver.py",
]


def hashes():
    return {
        p: hashlib.sha256((ROOT / p).read_bytes().replace(b"\r\n", b"\n")).hexdigest()
        for p in FILES
    }


def run_tests(module=None, *, names=None, failfast=False):
    stream = io.StringIO()
    if names is not None:
        suite = unittest.defaultTestLoader.loadTestsFromNames(names)
    elif module is None:
        import test_inf037b_lifecycle
        import test_inf037b_lifecycle_recovery

        suite = unittest.TestSuite(
            unittest.defaultTestLoader.loadTestsFromModule(m)
            for m in (test_inf037b_lifecycle, test_inf037b_lifecycle_recovery)
        )
    else:
        suite = unittest.defaultTestLoader.loadTestsFromModule(module)
    with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
        result = unittest.TextTestRunner(
            stream=stream, verbosity=2, failfast=failfast
        ).run(suite)
    return result, stream.getvalue()


BASELINE = "a033f5ec67b94203bda2b50e3c7ff2af15720563"
ADMISSION_BASELINE = "628f1d9ccd78d29c33fcea229a7b9662660ad101"
RECOVERY_BASELINE = "78a101fe7124b039a29e91810e4ee7474ef0bdde"


def recovery_baseline(archive_path):
    source = archive_path.read_bytes()
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        with tarfile.open(fileobj=io.BytesIO(source)) as archive:
            archive.extractall(root, filter="data")
        for name in (
            "test_inf037b_lifecycle.py",
            "test_inf037b_lifecycle_recovery.py",
            "inf037b_lifecycle_worker.py",
        ):
            (root / "python/tests" / name).write_bytes(
                (ROOT / "python/tests" / name).read_bytes()
            )
        code = """
import contextlib,hashlib,io,json,pathlib,sys,unittest
root=pathlib.Path(sys.argv[1]).resolve()
sys.path[:0]=[str(root/'python/src'),str(root/'python/tests')]
from inference_platform import inf037b_lifecycle as module
import test_inf037b_lifecycle_recovery as tests
assert pathlib.Path(module.__file__).resolve().is_relative_to(root)
records=[]
for name in tests.ROUND259_TESTS:
    stream=io.StringIO()
    with contextlib.redirect_stdout(stream),contextlib.redirect_stderr(stream):
        r=unittest.TextTestRunner(stream=stream,verbosity=2,failfast=name.startswith('test_sigkill_')).run(unittest.TestSuite([tests.RecoveryTests(name)]))
    records.append({'test':name,'tests':r.testsRun,'skips':len(r.skipped),'failed':not r.wasSuccessful(),
                    'failures':[t.id() for t,_ in r.failures],'errors':[t.id() for t,_ in r.errors],
                    'output':stream.getvalue()})
paths={}
for name in ('inf037b_lifecycle','inf037b_attempts','inf037b_resolver','inf037b_controller','inf037b_authority'):
    p=root/'python/src/inference_platform'/ (name+'.py')
    paths[name]={'path':str(p.resolve()),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
print(json.dumps({'cases':records,'module_inputs':paths,'all_failed':all(r['failed'] for r in records),
                  'skips':sum(r['skips'] for r in records)}))
"""
        response = subprocess.run(
            [sys.executable, "-c", code, str(root)],
            capture_output=True,
            text=True,
            env={
                **os.environ,
                "PYTHONPATH": os.pathsep.join(
                    (str(root / "python/src"), str(root / "python/tests"))
                ),
            },
            check=True,
        )
        result = json.loads(response.stdout)
        require_all = result["all_failed"] and result["skips"] == 0
        return {
            "base": RECOVERY_BASELINE,
            "archive_sha256": hashlib.sha256(source).hexdigest(),
            "basis": "R346 process-identity/barrier APIs and R347 checked malformed completion at isolated 78a101f; changed existing R348 matrices are mutation controls",
            **result,
            "pass": require_all,
        }


def baseline(archive_path=None, *, admission=False):
    revision = ADMISSION_BASELINE if admission else BASELINE
    source = (
        archive_path.read_bytes()
        if archive_path
        else subprocess.check_output(
            ["git", "-C", str(ROOT), "archive", revision, "python"]
        )
    )
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        with tarfile.open(fileobj=io.BytesIO(source)) as archive:
            archive.extractall(root, filter="data")
        (root / "python/tests/test_inf037b_lifecycle.py").write_bytes(
            (ROOT / "python/tests/test_inf037b_lifecycle.py").read_bytes()
        )
        code = """
import hashlib,io,json,pathlib,sys,unittest
root=pathlib.Path(sys.argv[1]).resolve()
admission=sys.argv[2]=='admission'
sys.path[:0]=[str(root/'python/src'),str(root/'python/tests')]
from inference_platform import inf037b_controller,inf037b_attempts,inf037b_resolver,inf037b_authority
modules=[inf037b_controller,inf037b_attempts,inf037b_resolver,inf037b_authority]
if admission:
    from inference_platform import inf037b_lifecycle
    modules.append(inf037b_lifecycle)
paths={m.__name__:str(pathlib.Path(m.__file__).resolve()) for m in modules}
assert all(pathlib.Path(p).is_relative_to(root) for p in paths.values()),paths
import test_inf037b_lifecycle as tests
assert (tests.lifecycle is not None)==admission,'unexpected baseline driver presence'
stream=io.StringIO()
suite=(unittest.TestSuite([tests.DriverTests('test_expired_first_setup_budget_refuses_before_durable_attempt_start')])
       if admission else unittest.defaultTestLoader.loadTestsFromModule(tests))
r=unittest.TextTestRunner(stream=stream).run(suite)
print(json.dumps({'paths':paths,'tests':r.testsRun,'skips':len(r.skipped),
 'source_sha256':{m.__name__:hashlib.sha256(pathlib.Path(m.__file__).read_bytes()).hexdigest() for m in modules},
 'failures':[t.id() for t,_ in r.failures],'errors':[t.id() for t,_ in r.errors],
 'cases':tests.CASES,'output':stream.getvalue(),
 'basis':'first-start slot allocated with expired setup budget' if admission else 'new 4b API absent; each test asserts absence explicitly'}))
assert len(r.failures)==(2 if admission else r.testsRun) and not r.skipped and not r.errors
"""
        response = subprocess.run(
            [
                sys.executable,
                "-c",
                code,
                str(root),
                "admission" if admission else "absence",
            ],
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONPATH": ""},
            check=True,
        )
        return {
            "base": revision,
            "archive_sha256": hashlib.sha256(source).hexdigest(),
            **json.loads(response.stdout),
        }


class Semantic(ast.NodeTransformer):
    def __init__(self, kind, line=None):
        self.kind, self.line = kind, line
        self.changed = 0

    def visit_If(self, node):
        self.generic_visit(node)
        expression = ast.unparse(node.test)
        if self.kind == "missing_leader" and expression.startswith(
            "record is None and (not owned) or"
        ):
            node.test = node.test.values[1]
            self.changed += 1
        if self.kind == "observation_binding" and "authoritative" in expression:
            node.test = ast.Constant(False)
            self.changed += 1
        if (
            self.kind == "observation_shape"
            and expression == "not isinstance(observation, dict)"
        ):
            node.test = ast.Constant(False)
            self.changed += 1
        if self.kind == "states_shape" and expression == "not isinstance(states, dict)":
            node.test = ast.Constant(False)
            self.changed += 1
        if self.kind == "accepted_any" and expression.startswith("all("):
            node.test.func.id = "any"
            self.changed += 1
        if self.kind == "rerun_all" and expression.startswith("any("):
            node.test.func.id = "all"
            self.changed += 1
        return node

    def visit_Call(self, node):
        self.generic_visit(node)
        expression = ast.unparse(node.func)
        if (
            self.kind == "boot_check"
            and expression == "exact"
            and len(node.args) == 3
            and ast.unparse(node.args[2]) == "'lifecycle:child_boot'"
        ):
            self.changed += 1
            return ast.Constant(None)
        if self.kind == "first_traffic_cap" and expression == "min":
            kept = [
                a
                for a in node.args
                if ast.unparse(a) != "self.deadline.billing_origin_ms + 3600000"
            ]
            self.changed += len(node.args) - len(kept)
            node.args = kept
        if self.kind == "reopen_fence" and expression == "self._fence_pending":
            self.changed += 1
            return ast.Constant(None)
        if self.kind == "spawn_barrier" and expression == "spawned":
            self.changed += 1
            # Release before durability: the callback's deliberate pause lets
            # the target act in the exact Popen-to-row gap under test.
            return ast.Call(
                ast.Name("mutant_release", ast.Load()),
                [
                    ast.Name("proc", ast.Load()),
                    node.args[0],
                    ast.Name("spawned", ast.Load()),
                ],
                [],
            )
        if self.kind == "kill_group" and expression == "os.killpg":
            self.changed += 1
            return ast.Constant(None)
        if (
            self.kind == "remaining_call"
            and expression == "self.remaining"
            and node.lineno == self.line
        ):
            self.changed += 1
            return ast.Constant(None)
        if (
            self.kind == "fresh_setup_time"
            and expression == "self.attempts.setup_complete"
        ):
            node.args[0] = ast.Call(
                ast.Attribute(ast.Name("self", ast.Load()), "now", ast.Load()), [], []
            )
            self.changed += 1
        if (
            self.kind == "fresh_attempt_end"
            and expression == "self.attempts.end_attempt"
            and ast.unparse(node.args[0]) == "end_ms"
        ):
            node.args[0] = ast.Call(
                ast.Attribute(ast.Name("self", ast.Load()), "now", ast.Load()), [], []
            )
            self.changed += 1
        if (
            self.kind == "drop_writer_lock"
            and expression == "fcntl.flock"
            and ast.unparse(node.args[1]) != "fcntl.LOCK_UN"
        ):
            self.changed += 1
            return ast.Constant(None)
        if (
            self.kind == "terminal_ack"
            and expression == "exact"
            and len(node.args) == 3
            and ast.unparse(node.args[2]) == "'lifecycle:' + operation + '_ack'"
        ):
            node.func.id = "mutant_noop"
            self.changed += 1
        return node

    def visit_FunctionDef(self, node):
        self.generic_visit(node)
        target = {"finish_fence": "_finish", "except_fence": "run"}.get(self.kind)
        if node.name == target:
            candidates = [
                n
                for n in ast.walk(node)
                if isinstance(n, ast.If)
                and ast.unparse(n.test) == "not self._safe_fence()"
            ]
            chosen = candidates[-1] if self.kind == "except_fence" else candidates[0]
            chosen.test = ast.Constant(False)
            self.changed += 1
        return node

    def visit_Assign(self, node):
        self.generic_visit(node)
        target = ast.unparse(node.targets[0])
        if (
            self.kind == "reserve_inside"
            and target == "kill_ms"
            and isinstance(node.value, ast.IfExp)
            and ast.unparse(node.value.test) == "operation == 'attempt'"
            and ast.unparse(node.value.orelse) == "stop_ms - 1000"
        ):
            node.value.body = ast.BinOp(
                ast.Name("stop_ms", ast.Load()),
                ast.Sub(),
                ast.Name("EXIT_RESERVE_MS", ast.Load()),
            )
            self.changed += 1
        if self.kind == "drop_exit_charge" and target == "extra":
            node.value = ast.Constant(0)
            self.changed += 1
        if (
            self.kind == "rebase_campaign"
            and target == "self.campaign_origin"
            and isinstance(node.value, ast.IfExp)
        ):
            node.value.body = ast.Call(
                ast.Attribute(ast.Name("self", ast.Load()), "now", ast.Load()), [], []
            )
            self.changed += 1
        return node

    def visit_Attribute(self, node):
        self.generic_visit(node)
        if (
            self.kind == "use_completion_as_exit"
            and ast.unparse(node) == "self.last_exit_ms"
            and isinstance(node.ctx, ast.Load)
        ):
            self.changed += 1
            return ast.Name("checked_ms", ast.Load())
        return node


LEGACY = "test_inf037b_lifecycle.DriverTests."
NEW = "test_inf037b_lifecycle_recovery.RecoveryTests."

GUARDS = {
    "lifecycle:interrupted_setup": (
        NEW
        + "test_sigkill_every_durable_row_reopens_without_reallocation_or_rebased_anchors",
    ),
    "lifecycle:interrupted_measurement": (
        NEW
        + "test_sigkill_every_durable_row_reopens_without_reallocation_or_rebased_anchors",
    ),
    "lifecycle:cancel_operation": (
        LEGACY + "test_cancel_operation_and_expected_id_contract",
    ),
    "lifecycle:cancel_ids": (
        LEGACY + "test_cancel_operation_and_expected_id_contract",
    ),
    "lifecycle:process_platform": (LEGACY + "test_process_platform_guard",),
    "lifecycle:process_reserve": (
        LEGACY + "test_process_success_error_output_and_reserve",
    ),
    "lifecycle:process_exit": (
        LEGACY + "test_process_success_error_output_and_reserve",
    ),
    "lifecycle:process_cutoff": (
        LEGACY + "test_process_late_completion_is_rejected_after_reap",
    ),
    "lifecycle:process_output": (
        LEGACY + "test_process_success_error_output_and_reserve",
    ),
    "lifecycle:deadline": (LEGACY + "test_deadline_object_is_required",),
    "lifecycle:clock": (
        LEGACY + "test_clock_rejects_regression_noninteger_and_boolean",
    ),
    "lifecycle:call_cutoff": (
        LEGACY + "test_call_rejects_expired_and_extended_cutoff",
    ),
    "lifecycle:call_overrun": (
        LEGACY + "test_creation_readiness_equality_and_one_tick_late",
    ),
    "lifecycle:single_run": (
        LEGACY + "test_single_instance_refuses_and_completed_journal_reopens",
    ),
    "lifecycle:creation_ack": (
        LEGACY + "test_nonacknowledged_phase_never_counts_as_success",
    ),
    "lifecycle:preparation_ack": (
        LEGACY + "test_nonacknowledged_phase_never_counts_as_success",
    ),
    "lifecycle:packet_barrier": (
        LEGACY + "test_every_prestart_failure_closes_three_unattempted_slots",
    ),
    "lifecycle:setup_start_budget": (
        LEGACY + "test_expired_first_setup_budget_refuses_before_durable_attempt_start",
    ),
    "lifecycle:attempt_ready": (
        LEGACY + "test_failed_attempt_setup_is_allocated_and_cannot_start_traffic",
    ),
    "lifecycle:outcome_shape": (
        NEW + "test_wrong_legacy_field_types_never_allocate_later_attempts",
    ),
    "lifecycle:measurement_end": (
        NEW + "test_invalid_reported_end_after_deadline_or_exit_aborts_at_deadline",
    ),
    "lifecycle:original_binding": (
        NEW
        + "test_reopen_rejects_changed_session_binding_and_missing_original_journal",
    ),
    "lifecycle:journal_chain": (
        NEW + "test_torn_or_rechained_journal_refuses_without_external_calls",
    ),
    "lifecycle:interrupted_call": (
        NEW
        + "test_sigkill_every_durable_row_reopens_without_reallocation_or_rebased_anchors",
    ),
}


def mutations(validation_path=None):
    from check_inf037b_resolver_mutations import Mutate, sites
    from inference_platform import inf037b_lifecycle as module
    import test_inf037b_lifecycle as tests
    import test_inf037b_lifecycle_recovery as recovery

    source = Path(module.__file__).read_text()
    original = compile(source, str(module.__file__), "exec")
    records = []

    if validation_path:
        validation = json.loads(validation_path.read_text())
        assert validation["inputs"] == hashes(), "validation source mismatch"
        assert (
            validation["mode"] == "validate"
            and validation["platform"] == platform.system()
        )
        assert validation["python"] == platform.python_version()
        assert (
            validation["tests"] == 60
            and not validation["failures"]
            and validation["skips"] == 0
        )
        validation_basis = {
            "receipt_sha256": hashlib.sha256(validation_path.read_bytes()).hexdigest(),
            "inputs": validation["inputs"],
            "tests": validation["tests"],
            "skips": validation["skips"],
            "failures": validation["failures"],
        }
    else:
        normal, output = run_tests()
        if not normal.wasSuccessful() or normal.skipped:
            raise SystemExit("unmutated baseline failed:\n" + output)
        validation_basis = {
            "tests": normal.testsRun,
            "skips": len(normal.skipped),
            "failures": [],
        }

    def check(tree, label, names):
        exec(
            compile(ast.fix_missing_locations(tree), str(module.__file__), "exec"),
            module.__dict__,
        )
        module.__mutant_source__ = (
            "mutant_noop = lambda *args, **kwargs: None\n" + ast.unparse(tree)
        )
        if label.startswith("spawn_barrier"):
            module.__mutant_source__ += "\ndef mutant_release(proc, identity, callback):\n    proc.stdin.write(b'1'); proc.stdin.flush(); return callback(identity)\n"
        importlib.reload(tests)
        importlib.reload(recovery)
        result, output = run_tests(names=names, failfast=True)
        assert "NameError: name 'mutant_noop'" not in output, output
        if "lifecycle:interrupted_setup" in label:
            assert "recovery manufactured traffic" in output, output
        if "lifecycle:interrupted_measurement" in label:
            assert "True is not False" in output, output
        killers = sorted({t.id() for t, _ in result.failures + result.errors})
        record = {
            "mutation": label,
            "selected_tests": names,
            "killed": bool(killers),
            "killers": killers,
            "skips": len(result.skipped),
            "output": output,
        }
        records.append(record)
        print(
            json.dumps({k: v for k, v in record.items() if k != "output"}), flush=True
        )
        exec(original, module.__dict__)
        del module.__mutant_source__

    try:
        module.mutant_noop = lambda *args, **kwargs: None

        def mutant_release(proc, identity, callback):
            proc.stdin.write(b"1")
            proc.stdin.flush()
            return callback(identity)

        module.mutant_release = mutant_release
        selected = {}
        for site in sites(ast.parse(source)):
            label = site[3].strip("'")
            if label in GUARDS:
                if label not in selected or label == "lifecycle:call_overrun":
                    selected[label] = site
        assert set(selected) == set(GUARDS), set(GUARDS) - set(selected)
        for label, site in selected.items():
            # Deliberate guard families, not an exhaustive all-AST claim.
            # The one-tick controls apply to the accepted legacy inequalities.
            for mode in ("delete", "loosen") if site[4] else ("delete",):
                check(
                    Mutate(site, mode).visit(ast.parse(source)),
                    f"{site[3]}:{site[0]}:{mode}",
                    GUARDS[label],
                )
        semantic = [
            (kind, None, names)
            for kind, names in {
                "missing_leader": (
                    NEW
                    + "test_real_missing_leader_with_live_grandchild_refuses_reopen_fence",
                ),
                "finish_fence": (
                    NEW + "test_process_export_unconfirmed_fence_blocks_cleanup",
                ),
                "except_fence": (
                    NEW
                    + "test_process_attempt_unconfirmed_fence_writes_no_stop_or_attempt_end",
                ),
                "boot_check": (
                    NEW + "test_process_spawned_different_boot_refuses_without_signal",
                ),
                "reopen_fence": (
                    NEW
                    + "test_real_sigkill_spawned_matrix_fences_setup_attempt_and_grandchildren",
                ),
                "spawn_barrier": (
                    NEW
                    + "test_real_sigkill_spawned_matrix_fences_setup_attempt_and_grandchildren",
                ),
                "observation_binding": (
                    LEGACY
                    + "test_cancel_missing_stale_unbound_and_malformed_stay_unknown",
                ),
                "observation_shape": (
                    LEGACY
                    + "test_cancel_missing_stale_unbound_and_malformed_stay_unknown",
                ),
                "states_shape": (
                    LEGACY
                    + "test_cancel_missing_stale_unbound_and_malformed_stay_unknown",
                ),
                "accepted_any": (
                    LEGACY
                    + "test_cancel_three_answers_include_partial_acceptance_and_unknown",
                ),
                "rerun_all": (
                    LEGACY
                    + "test_cancel_three_answers_include_partial_acceptance_and_unknown",
                ),
                "kill_group": (
                    LEGACY + "test_process_kills_descendants_even_after_parent_exits",
                ),
                "reserve_inside": (
                    NEW + "test_real_process_separate_measurement_and_kill_cutoffs",
                ),
                "fresh_setup_time": (
                    NEW
                    + "test_checked_completion_survives_ticking_clock_for_attempt_and_reset",
                ),
                "fresh_attempt_end": (
                    NEW
                    + "test_checked_completion_survives_ticking_clock_for_attempt_and_reset",
                ),
                "drop_exit_charge": (
                    NEW
                    + "test_remaining_checks_charge_one_reserve_per_remaining_attempt",
                ),
                "use_completion_as_exit": (
                    NEW
                    + "test_invalid_reported_end_after_deadline_or_exit_aborts_at_deadline",
                ),
                "drop_writer_lock": (
                    NEW + "test_sigkill_writer_lease_releases_only_on_process_death",
                ),
                "rebase_campaign": (
                    NEW
                    + "test_sigkill_completed_attempt_receipt_keeps_checked_end_after_restart_delay",
                ),
                "terminal_ack": (
                    LEGACY + "test_nonacknowledged_phase_never_counts_as_success",
                ),
                "first_traffic_cap": (
                    NEW
                    + "test_sigkill_late_completed_receipt_does_not_become_a_timely_ack",
                ),
            }.items()
        ]
        semantic += [
            (
                "remaining_call",
                n.lineno,
                (
                    LEGACY
                    + "test_all_remaining_work_is_checked_after_setup_before_traffic_execution",
                ),
            )
            for n in ast.walk(ast.parse(source))
            if isinstance(n, ast.Call) and ast.unparse(n.func) == "self.remaining"
        ]
        for kind, line, names in semantic:
            transform = Semantic(kind, line)
            tree = transform.visit(ast.parse(source))
            assert transform.changed == 1, (
                kind,
                line,
                transform.changed,
            )
            check(tree, f"{kind}:{line}", names)
    finally:
        exec(original, module.__dict__)
        if hasattr(module, "__mutant_source__"):
            del module.__mutant_source__
    return {
        "unmutated_validation": validation_basis,
        "mutants": records,
        "survivors": [r["mutation"] for r in records if not r["killed"]],
        "skips": sum(r["skips"] for r in records),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--validation-receipt",
        type=Path,
        help="reuse a passing full suite only after exact input/runtime/hash verification",
    )
    parser.add_argument(
        "--baseline-archive",
        type=Path,
        help="git archive a033f5e python, prepared on the host (image has no Git)",
    )
    parser.add_argument(
        "--mode",
        choices=(
            "validate",
            "mutate",
            "baseline",
            "admission-baseline",
            "recovery-baseline",
            "regression",
        ),
        default="validate",
    )
    args = parser.parse_args()
    result = {
        "inputs": hashes(),
        "python": platform.python_version(),
        "platform": platform.system(),
        "mode": args.mode,
        "basis": "offline synthetic provider and schedule; real files/processes",
    }
    if args.mode == "recovery-baseline":
        result["baseline"] = recovery_baseline(args.baseline_archive)
        failed = not result["baseline"]["pass"]
    elif args.mode in {"baseline", "admission-baseline"}:
        result["baseline"] = baseline(
            args.baseline_archive, admission=args.mode == "admission-baseline"
        )
        failed = False
    elif args.mode == "mutate":
        result.update(mutations(args.validation_receipt))
        failed = bool(result["survivors"] or result["skips"])
    else:
        import test_inf037b_lifecycle as tests
        import test_inf037b_lifecycle_recovery as recovery
        from inference_platform.inf037b_resolver import BOUNDS_MS

        start = time.monotonic_ns()
        names = (
            [
                "test_inf037b_controller",
                "test_inf037b_ports",
                "test_inf037b_placement",
                "test_inf037b_resolver",
            ]
            if args.mode == "regression"
            else None
        )
        outcome, output = run_tests(names=names)
        result.update(
            tests=outcome.testsRun,
            skips=len(outcome.skipped),
            failures=[t.id() for t, _ in outcome.failures + outcome.errors],
            output=output,
            cases=tests.CASES + recovery.CASES,
            elapsed_ms=(time.monotonic_ns() - start) / 1_000_000,
            phase_bounds_ms=BOUNDS_MS,
            envelope_ms=sum(
                v * {"attempt": 3, "reset": 2}.get(k, 1) for k, v in BOUNDS_MS.items()
            ),
            attempt_wait_components_ms=[600_000, 30_000, 300_000, 600_000, 30_000],
            cleanup_and_export_reserve_ms=3_600_000,
        )
        failed = not outcome.wasSuccessful() or bool(outcome.skipped)
        if args.mode == "regression":
            failed = failed or outcome.testsRun != 231
        print(output)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return bool(failed)


if __name__ == "__main__":
    sys.exit(main())
