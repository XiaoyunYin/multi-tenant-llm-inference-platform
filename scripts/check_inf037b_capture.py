"""Scoped row3/R372 summary receipts; raw subprocess logs stay ignored."""

import argparse
import ast
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from check_inf037b_command import run

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "python/src/inference_platform"
SEMANTICS = [
    "test_inf037b_command.CommandTests.test_concurrent_export_refuses_" + suffix
    for suffix in (
        "segment_integrity_error",
        "wrong_sanitized_label",
        "another_sanitizer_source",
        "pending_sse",
    )
]
CAPTURE = ["test_inf037b_capture"]
GROUPS = {
    "transports": ["test_inf037b_capture", "test_inf037b_live", "test_inf037b_probe"],
    "consumers": [
        "test_inf037b_collectors.StreamTests",
        "test_inf037b_export_runtime",
        "test_inf037b_sanitization_regressions",
        "test_runtime_observers",
    ],
    "setup": [
        "test_inf037b_preparation",
        "test_inf037b_preparation_adapter",
        "test_inf037b_command",
        "test_inf037b_maximum",
        "test_inf037b_setup",
        "test_inf037b_fitness",
        "test_inf037b_observations",
    ],
    "lifecycle": [
        "test_inf037b_lifecycle",
        "test_inf037b_lifecycle_recovery",
        "test_inf037b_integration",
        "test_inf037b_terminal",
    ],
}


def hashes():
    paths = [
        *SOURCE.glob("inf037b*.py"),
        *(ROOT / "python/tests").glob("*inf037b*.py"),
        ROOT / "scripts/check_inf037b_command.py",
        ROOT / "scripts/check_inf037b_probe_go.py",
        ROOT / "scripts/check_inf037b_client_controls.py",
        ROOT / "scripts/time_inf037b_client.py",
        ROOT / "deploy/eks/setup-controls.json",
        ROOT / "scripts/time_inf037b_wire.py",
        Path(__file__),
        ROOT / "deploy/eks/capture_runtime.py",
        *(ROOT / "internal").rglob("*.go"),
        ROOT / "go.mod",
        ROOT / "go.sum",
    ]
    return {
        p.relative_to(ROOT).as_posix(): hashlib.sha256(
            p.read_bytes().replace(b"\r\n", b"\n")
        ).hexdigest()
        for p in sorted(paths)
    }


def mutations():
    filename = "inf037b_setup_observations.py"
    source = (SOURCE / filename).read_text()
    yield (
        filename,
        "R372 validate_export_archives readback=True",
        "_export_archives(value, artifacts)\n",
        "_export_archives(value, artifacts, readback=True)\n",
        SEMANTICS,
    )
    function = next(
        node
        for node in ast.parse(source).body
        if isinstance(node, ast.FunctionDef) and node.name == "_export_archives"
    )
    lines = source.splitlines(keepends=True)
    for index, node in enumerate(
        n
        for n in ast.walk(function)
        if isinstance(n, ast.If) and ast.unparse(n.test) == "not readback"
    ):
        original = "".join(lines[node.body[0].lineno - 1 : node.body[-1].end_lineno])
        replacement = " " * node.body[0].col_offset + "pass\n"
        yield (
            filename,
            f"R372 if not readback body {index + 1} pass",
            original,
            replacement,
            SEMANTICS,
        )
    filename = "inf037b_capture.py"
    source = (SOURCE / filename).read_text()
    reasons = {
        "capture:tls",
        "capture:endpoint",
        "capture:endpoint_path",
        "capture:request_path",
        "capture:line_limit",
        "capture:torn_line",
        "capture:http_status",
        "capture:source_inventory",
        "capture:operation_scope",
        "capture:operation_store",
        "capture:binding",
        "capture:interrupted_no_retry",
        "capture:lineage",
        "capture:missed_slot",
    }
    for node in ast.walk(ast.parse(source)):
        if (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Name)
            and node.value.func.id in {"exact", "require"}
            and isinstance(node.value.args[-1], ast.Constant)
            and node.value.args[-1].value in reasons
        ):
            original = ast.get_source_segment(source, node)
            yield (
                filename,
                f"remove {node.value.args[-1].value} at {node.lineno}",
                original,
                "pass",
                CAPTURE,
            )
    for label, original, replacement in (
        (
            "truncated body accepted",
            'if not chunk:\n                    require(response.length in (None, 0), "capture:truncated_response")',
            "if not chunk:\n                    pass",
        ),
        (
            "raw bytes discarded",
            'segment["data"].write(body)',
            'segment["data"].write(b"")',
        ),
        ("accept unknown lineage", "triple in self.sources[source]", "True"),
        (
            "clear sticky loss at close",
            "transport_clean=not self.failed",
            "transport_clean=True",
        ),
        (
            "omit operation rejoin",
            "                    self.join_current()",
            "                    pass",
        ),
        (
            "R373 cutoff recorded as loss",
            '"end": "cutoff",',
            '"end": "cutoff", "error": "cutoff_is_loss",',
        ),
        (
            "R373 settlement grace removed",
            "wait(futures, timeout=WORKER_GRACE_SECONDS)",
            "wait(futures, timeout=0)",
        ),
        (
            "R373 one second watch cap restored",
            "return remaining if watch else min(1.0, remaining)",
            "return min(1.0, remaining)",
        ),
        (
            "R374 omit response durability barrier",
            "self.barrier()  # Complete response/partial bytes durable before normalization.",
            "pass  # No durable response barrier.",
        ),
        (
            "R374 concurrent cached joins without owner lease",
            "with self.lock:\n            with self.operation_store.lock():\n"
            "                if self.generation() == self.operation_generation:\n"
            "                    return\n            self.join()",
            "with self.operation_store.lock():\n"
            "            if self.generation() == self.operation_generation:\n"
            "                return\n        self.join()",
        ),
    ):
        yield filename, label, original, replacement, CAPTURE

    yield (
        "inf037b_live.py",
        "R373 lifecycle cutoff counted as loss",
        "if not cutoff:",
        "if True:",
        CAPTURE,
    )
    yield (
        "inf037b_live.py",
        "R374 RESP normalization without barrier",
        "self.barrier()\n\n        def decoded",
        "pass\n\n        def decoded",
        CAPTURE,
    )


def round277_mutations():
    runner = [
        "test_inf037b_capture.CaptureTests.test_real_runner_watch_cutoff_eof_and_unsettled_grace"
    ]
    order = [
        "test_inf037b_capture.CaptureTests.test_archive_slot_and_rejected_row_barriers_precede_completion_and_loss"
    ]
    for label, original, replacement, tests in (
        (
            "R373 cutoff narrowed to OSError",
            "except Exception as exc:\n            if watch and (",
            "except OSError as exc:\n            if watch and (",
            runner,
        ),
        (
            "R374 slot archive barrier removed",
            "            self.archive_barrier()\n            self.retain(source, start, end, body, metadata)",
            "            self.retain(source, start, end, body, metadata)",
            order,
        ),
        (
            "R374 archive barrier after completion record",
            "            self.archive_barrier()\n            self.retain(source, start, end, body, metadata)",
            "            self.retain(source, start, end, body, metadata)\n            self.archive_barrier()",
            order,
        ),
        (
            "R374 rejected-row archive barrier skipped",
            "            self.failed = True\n            self.archive_barrier()",
            "            self.failed = True\n            if 'capture:lineage' not in str(reason):\n                self.archive_barrier()",
            order,
        ),
        (
            "R375 partial final slot admitted",
            "next_ns + period_ms * 1_000_000 <= stop_ns",
            "next_ns < stop_ns",
            [
                "test_inf037b_capture.CaptureTests.test_real_runner_partial_final_slot_closes_and_period_overrun_refuses"
            ],
        ),
    ):
        yield "inf037b_capture.py", label, original, replacement, tests

    native_tests = "test_inf037b_probe.NativeTests."
    probe_tests = "test_inf037b_probe.ProbeTests."
    selected = {
        "inf037b_native.py": {
            "base_sources": [
                native_tests
                + "test_overlay_pins_all_sources_and_disabled_install_has_no_side_effect"
            ],
            "runtime_sources": [
                native_tests
                + "test_overlay_pins_all_sources_and_disabled_install_has_no_side_effect"
            ],
        },
        "inf037b_probe.py": {
            **dict.fromkeys(
                (
                    "probe:native_source",
                    "probe:native_lineage",
                    "probe:native_abort_cause",
                    "probe:native_abort_status",
                    "probe:native_abort_path",
                    "probe:native_end_reference",
                ),
                [
                    native_tests
                    + "test_native_adapter_requires_source_lineage_cause_and_real_request_bijection"
                ],
            ),
            "probe:already_allocated": [
                probe_tests
                + "test_single_fixed_probe_schedule_controls_and_irrevocable_intent"
            ],
            "probe:setup_owner": [
                probe_tests + "test_probe_cannot_run_on_an_attempt_capture"
            ],
            "probe:capture_row_owner": [
                probe_tests + "test_probe_rejects_client_rows_from_another_capture"
            ],
            "probe:closed_clean_capture_required": [
                probe_tests
                + "test_tls_sse_cancel_and_already_finished_control_retain_original_bytes"
            ],
        },
        "inf037b_capture.py": {
            **dict.fromkeys(
                ("capture:export_context_at_open", "capture:export_context_at_close"),
                [
                    "test_inf037b_capture.CaptureTests.test_capture_archive_barrier_is_independent_of_export_batch"
                ],
            ),
            "capture:action_failed_or_late": [
                "test_inf037b_capture.CaptureTests.test_real_runner_actions_share_capture_fence_and_absolute_cutoff"
            ],
        },
    }
    for filename, reasons in selected.items():
        source = (SOURCE / filename).read_text()
        for node in ast.walk(ast.parse(source)):
            if (
                isinstance(node, ast.Expr)
                and isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Name)
                and node.value.func.id in {"check", "exact", "require"}
                and isinstance(node.value.args[-1], ast.Constant)
                and node.value.args[-1].value in reasons
            ):
                reason = node.value.args[-1].value
                yield (
                    filename,
                    "remove " + reason,
                    ast.get_source_segment(source, node),
                    "pass",
                    reasons[reason],
                )
    for filename, label, original, replacement, tests in (
        (
            "inf037b_probe.py",
            "native ID join iterates a concurrently mutated binding map",
            "bindings.copy().items()",
            "bindings.items()",
            [
                native_tests
                + "test_native_adapter_requires_source_lineage_cause_and_real_request_bijection"
            ],
        ),
        (
            "inf037b_probe.py",
            "native endpoint without kernel-boot clock join",
            "time_bounds=bounds,",
            "time_bounds=None,",
            [
                native_tests
                + "test_native_adapter_requires_source_lineage_cause_and_real_request_bijection"
            ],
        ),
        (
            "inf037b_capture.py",
            "omit receipt/seal directory durability at close",
            "self.archive_directory_barrier()  # New receipt/seal entries precede the closed descriptor.",
            "pass",
            [
                "test_inf037b_capture.CaptureTests.test_archive_seal_directories_are_durable_before_closed_descriptor"
            ],
        ),
        (
            "inf037b_native.py",
            "native abort without cause/ack",
            'status == "FINISHED_ABORTED"\n            and terminal["abort_rpc"]\n            and row[0] is not None\n            and row[1] == 1',
            'status == "FINISHED_ABORTED" and terminal["abort_rpc"]',
            [
                native_tests
                + "test_abort_is_native_processed_with_exact_cancel_cause_and_ack"
            ],
        ),
        (
            "inf037b_native.py",
            "non-RPC abort classified as client cancellation",
            'status == "FINISHED_ABORTED"\n            and terminal["abort_rpc"]\n            and row[0] is not None\n            and row[1] == 1',
            'status == "FINISHED_ABORTED" and row[0] is not None and row[1] == 1',
            [
                native_tests
                + "test_abort_is_native_processed_with_exact_cancel_cause_and_ack"
            ],
        ),
        (
            "inf037b_native.py",
            "native abort RPC context removed",
            "emitter.abort_context.active = values",
            "emitter.abort_context.active = ()",
            [
                native_tests
                + "test_abort_is_native_processed_with_exact_cancel_cause_and_ack"
            ],
        ),
        (
            "inf037b_native.py",
            "fork process lineage not rebound",
            'self.observe("installed", kind, source)',
            "pass",
            [
                native_tests
                + "test_fork_reopens_sqlite_and_rebinds_installed_process_lineage"
            ],
        ),
        (
            "inf037b_probe.py",
            "probe metadata bypasses the capture owner lock",
            "require_group_leader()\n        with self.owner.lock, self.store.lock():",
            "require_group_leader()\n        with self.store.lock():",
            [
                probe_tests
                + "test_probe_intent_serializes_with_capture_loss_on_the_same_store"
            ],
        ),
        (
            "inf037b_native.py",
            "unrelated caller classified as client cancellation",
            "and caller.f_code is generate_code",
            "and True",
            [
                native_tests
                + "test_abort_is_native_processed_with_exact_cancel_cause_and_ack"
            ],
        ),
        (
            "inf037b_probe.py",
            "shortened registered probe trace",
            'workload_trace("pre", 1, 120000)',
            'workload_trace("pre", 1, 119000)',
            [
                probe_tests
                + "test_single_fixed_probe_schedule_controls_and_irrevocable_intent"
            ],
        ),
        (
            "inf037b_live.py",
            "unverified TLS client accepted",
            "if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:",
            "if False:",
            [
                probe_tests
                + "test_tls_sse_cancel_and_already_finished_control_retain_original_bytes"
            ],
        ),
        (
            "inf037b_live.py",
            "gateway event normalized before response-ID binding",
            "self.defer_request_bindings\n",
            "False\n",
            [
                probe_tests
                + "test_gateway_waits_for_response_identity_without_repolling_or_loss"
            ],
        ),
    ):
        yield filename, label, original, replacement, tests


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--group", choices=GROUPS)
    parser.add_argument("--mutations", action="store_true")
    parser.add_argument("--round277-mutations", action="store_true")
    parser.add_argument(
        "--fix-mutations",
        action="store_true",
        help="R373/R374 import closure; excludes unchanged R372 mutants",
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    before = hashes()
    summary = {
        "schema": "inf037b-capture-summary-v1",
        "python": platform.python_version(),
        "platform": platform.platform(),
        "inputs_lf_sha256": before,
        "paid_ready": False,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if args.mutations or args.fix_mutations or args.round277_mutations:
        with tempfile.TemporaryDirectory() as directory:
            overlay = Path(directory)
            package = overlay / "inference_platform"
            package.mkdir()
            (package / "__init__.py").write_text(f"__path__.append({str(SOURCE)!r})\n")
            cases = list(
                round277_mutations() if args.round277_mutations else mutations()
            )
            baseline_tests = (
                sorted({test for *_, tests in cases for test in tests})
                if args.round277_mutations
                else CAPTURE
                if args.fix_mutations
                else CAPTURE + SEMANTICS
            )
            baseline = run(overlay, baseline_tests)
            print(baseline["output"], flush=True)
            assert baseline["exit_code"] == 0
            baseline.pop("output")
            summary.update(baseline=baseline, mutants=[])
            for filename, label, original, replacement, tests in cases:
                if args.fix_mutations and filename not in {
                    "inf037b_capture.py",
                    "inf037b_live.py",
                }:
                    continue
                source = (SOURCE / filename).read_text()
                assert source.count(original) == 1, (label, source.count(original))
                changed = source.replace(original, replacement)
                compile(changed, filename, "exec")
                path = package / filename
                path.write_text(changed)
                try:
                    result = run(overlay, tests)
                finally:
                    path.unlink()
                failures = [
                    line
                    for line in result.pop("output").splitlines()
                    if line.startswith(("FAIL:", "ERROR:", "Ran ", "FAILED"))
                ]
                killed = result["exit_code"] != 0
                summary["mutants"].append(
                    {
                        "file": filename,
                        "label": label,
                        "original": original,
                        "replacement": replacement,
                        "mutated_lf_sha256": hashlib.sha256(
                            changed.encode()
                        ).hexdigest(),
                        "killed": killed,
                        "failure_summary": failures,
                        **result,
                    }
                )
                print(label, "KILLED" if killed else "SURVIVED", flush=True)
            summary["killed"] = sum(m["killed"] for m in summary["mutants"])
            summary["survivors"] = len(summary["mutants"]) - summary["killed"]
        success = summary["survivors"] == 0
    else:
        assert args.group
        command = [sys.executable, "-m", "unittest", *GROUPS[args.group], "-v"]
        start = time.monotonic_ns()
        result = subprocess.run(
            command, capture_output=True, timeout=1500, env=os.environ, cwd=ROOT
        )
        output = result.stdout + result.stderr
        text = output.decode(errors="replace")
        args.output.with_suffix(".log").write_bytes(output)
        count = re.search(r"Ran (\d+) tests?", text)
        summary.update(
            group=args.group,
            command=command,
            exit_code=result.returncode,
            tests=int(count[1]) if count else 0,
            skips=int(re.search(r"skipped=(\d+)", text)[1])
            if "skipped=" in text
            else 0,
            elapsed_ms=(time.monotonic_ns() - start) / 1e6,
            log_sha256=hashlib.sha256(output).hexdigest(),
        )
        print(text, flush=True)
        success = (
            result.returncode == 0 and summary["tests"] > 0 and summary["skips"] == 0
        )
    summary["inputs_unchanged"] = hashes() == before
    args.output.write_text(json.dumps(summary, indent=2, allow_nan=False) + "\n")
    assert success and summary["inputs_unchanged"], summary


if __name__ == "__main__":
    main()
