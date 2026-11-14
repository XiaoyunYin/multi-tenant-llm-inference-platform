"""Round280 changed-refusal-only sweep; full-path mutants live in the rehearsal."""

import argparse
import hashlib
import json
import os
import tempfile
from pathlib import Path

from check_inf037b_command import ROOT, SOURCE, run

L = "test_l4_revision.RevisionTests."


def cases():
    yield (
        "inf037b_live.py",
        "one-token guard depends on coalesced finish",
        'decoder.finish or payload.get("max_tokens") == 1',
        "decoder.finish",
        L + "test_one_token_separate_finish_refuses_cancellation_intent",
    )
    yield (
        "scripts/l4_compat_controller.py",
        "first status uses readiness cutoff",
        "end=min(end, time.time() + 60)",
        "end=end",
        L + "test_first_status_has_sixty_second_bound_and_ssm_wait_keeps_log",
    )
    yield (
        "scripts/l4_compat_controller.py",
        "CPU marker accepted for L4",
        'prefix="DEC-092 L4 PLAN APPROVED"',
        'prefix="DEC-077 CPU PLAN APPROVED"',
        L + "test_controller_uses_l4_marker_tuple",
    )
    yield (
        "scripts/l4_compat_controller.py",
        "fixed credential runtime reused",
        'runtime_directory=os.environ["L4_ATTEMPT_DIRECTORY"]',
        "runtime_directory=args[0]",
        L + "test_l4_ports_credentials_and_reservations_are_per_attempt",
    )
    yield (
        "scripts/l4_compat_controller.py",
        "missing Terraform state queried",
        '(self.directory / "terraform/terraform.tfstate").exists()',
        "True",
        L + "test_no_state_inventory_empty_but_existing_state_errors_propagate",
    )
    yield (
        "scripts/l4_compat_host.py",
        "engine death ignored",
        '.strip()\n                    == b"true"',
        ".strip() is not None",
        L + "test_engine_death_refuses_before_health_request",
    )
    yield (
        "scripts/l4_compat_host.py",
        "Redis retry bound ignored",
        "time.time() + 0.2 < redis_end",
        "True",
        L + "test_redis_retries_then_pong_and_bounds_persistent_failure",
    )
    yield (
        "scripts/l4_compat_host.py",
        "Redis PONG not required",
        '== b"PONG"',
        "is not None",
        L + "test_redis_retries_then_pong_and_bounds_persistent_failure",
    )
    yield (
        "scripts/l4_compat_host.py",
        "duplicate chat IDs accepted",
        'len({r["request_id"] for r in chats}) == 7',
        "True",
        L + "test_audit_probes_retained_and_duplicate_chat_ids_refuse",
    )


def bindings():
    result = {}
    paths = [
        ROOT / "python/src/inference_platform/l4_compat.py",
        ROOT / "python/src/inference_platform/inf037b_live.py",
        ROOT / "python/tests/test_l4_compat.py",
        ROOT / "python/tests/test_l4_revision.py",
        ROOT / "python/src/inference_platform/package_a_operator.py",
        ROOT / "scripts/rehearse_l4_compat.py",
        *ROOT.glob("scripts/l4_compat*"),
        ROOT / "scripts/prepare_l4_compat.py",
        ROOT / "scripts/finalize_l4_compat.py",
        ROOT / "scripts/package_a_host.py",
        Path(__file__),
        ROOT / "scripts/package_a_sealed.py",
        *ROOT.glob("infra/terraform/l4_compat/*"),
        ROOT / "infra/terraform/l4_compat/.terraform.lock.hcl",
    ]
    for path in paths:
        if path.is_file():
            result[path.relative_to(ROOT).as_posix()] = hashlib.sha256(
                path.read_bytes().replace(b"\r\n", b"\n")
            ).hexdigest()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    before = bindings()
    tests = sorted({case[-1] for case in cases()})
    with tempfile.TemporaryDirectory() as directory:
        overlay = Path(directory)
        package = overlay / "inference_platform"
        package.mkdir()
        script_overlay = overlay / "scripts"
        script_overlay.mkdir()
        os.environ["L4_SCRIPT_OVERLAY"] = str(script_overlay)
        (package / "__init__.py").write_text(f"__path__.append({str(SOURCE)!r})\n")
        baseline = run(overlay, tests + ["test_l4_compat", "test_l4_revision"])
        print(baseline["output"], flush=True)
        assert baseline["exit_code"] == 0
        baseline.pop("output")
        results = []
        for filename, label, original, replacement, test in cases():
            source = (
                ROOT / filename
                if filename.startswith("scripts/")
                else SOURCE / filename
            ).read_text()
            assert source.count(original) == 1, (label, source.count(original))
            changed = source.replace(original, replacement)
            compile(changed, filename, "exec")
            path = (
                script_overlay / Path(filename).name
                if filename.startswith("scripts/")
                else package / filename
            )
            path.write_text(changed)
            try:
                result = run(overlay, [test])
            finally:
                path.unlink()
            result["failure_summary"] = [
                s
                for s in result.pop("output").splitlines()
                if s.startswith(("FAIL:", "ERROR:", "Ran ", "FAILED"))
            ]
            results.append(
                {
                    "file": filename,
                    "label": label,
                    "killed": result["exit_code"] != 0,
                    "original": original,
                    "replacement": replacement,
                    **result,
                }
            )
            print(label, results[-1]["killed"], flush=True)
    summary = {
        "baseline": baseline,
        "mutants": results,
        "killed": sum(r["killed"] for r in results),
        "survivors": sum(not r["killed"] for r in results),
        "inputs_lf_sha256": before,
        "inputs_unchanged": bindings() == before,
        "provider_calls": 0,
    }
    args.output.write_text(json.dumps(summary, indent=2) + "\n")
    assert summary["survivors"] == 0 and summary["inputs_unchanged"]


if __name__ == "__main__":
    main()
