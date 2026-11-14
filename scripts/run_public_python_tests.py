"""Run portable snapshot tests; report cases requiring omitted private records.

The private all suite still runs every case through run_python_tests.py.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import unittest
from pathlib import Path

PRIVATE_MODULES = {
    "test_remote_source_fitness",
    "test_stage_c_fitness",
    "test_stage_c_preflight",
    "test_stage_c_protocol",
    "test_stage_c_session",
    "test_stage_c_sizing",
    "test_routine_prune",
}
PRIVATE_CASES = {
    "test_r1.ManifestTests": "setUpClass requires private 3d3c36a preregistration history",
    "test_r1_cloud.CloudTests.test_host_spec_artifact_checks_identical_registered_bytes_without_git": "reads private 3d3c36a preregistration blob",
    "test_r1_fixture_target.FixtureTargetTests.test_committed_packet_window_schema_and_demonstrated_wall_rate": "reads omitted private Round87 measurement receipts",
}


# Exact private-record joins only. Portable siblings and the full private suite
# retain their original checks; no new class-wide exclusion is introduced.
PRIVATE_CASES.update(
    {
        name: "Reads the private committed HEAD:REVIEW.md approval markers."
        for name in (
            "test_package_a_cloud.PackageACloudTests.test_committed_marker_missing_duplicate_wrong_hash_and_consumed_refuse",
        )
    }
)
PRIVATE_CASES.update(
    {
        name: "Requires omitted private .githooks/pre-commit."
        for name in (
            "test_r1_private_identifier_scan.PrivateIdentifierScanTests.test_staged_tree_refuses_fake_iam_arn_before_commit",
        )
    }
)
PRIVATE_CASES.update(
    {
        name: "Requires omitted private docs/INF037B_4E_INPUT_ASSIGNMENTS.json."
        for name in (
            "test_inf037b_4e_inputs.InputInventoryTests.test_cli_check_rejects_stale_output",
            "test_inf037b_4e_inputs.InputInventoryTests.test_duplicate_policy_assignment_refuses",
            "test_inf037b_4e_inputs.InputInventoryTests.test_every_unresolved_owner_scope_is_inventoried",
            "test_inf037b_4e_inputs.InputInventoryTests.test_new_unassigned_input_is_not_silently_omitted",
            "test_inf037b_4e_inputs.InputInventoryTests.test_repeated_generation_is_byte_identical",
            "test_inf037b_4e_inputs.InputInventoryTests.test_runtime_fallback_reason_keeps_its_port_qualifier",
        )
    }
)
PRIVATE_CASES.update(
    {
        name: "Requires omitted private docs/INF037B_4E_INPUT_INVENTORY.json."
        for name in (
            "test_inf037b_4e_inputs.InputInventoryTests.test_committed_output_matches_current_code_and_assignments",
        )
    }
)
PRIVATE_CASES.update(
    {
        name: "Requires omitted private docs/INF037B_PRODUCER_CONTRACT_SOURCES.json."
        for name in (
            "test_inf037b_capture_inventory.EnvelopeTests.test_source_proof_pins_match_enforced_contracts_and_allowance_is_unchanged",
        )
    }
)
PRIVATE_CASES.update(
    {
        name: "Requires omitted private docs/INF037B_REGISTRATION_V4_R315.md."
        for name in (
            "test_inf037b_collectors.PacketTests.test_hash_bound_manifest_missing_inputs_and_trace",
            "test_inf037b_core.ArchiveTests.test_registration_v4_binding_and_v3_preservation",
            "test_inf037b_eks_packet.PacketTests.test_all_five_factory_ports_and_terminal_sanitized_inputs",
            "test_inf037b_eks_packet.PacketTests.test_altered_allowance_is_not_reused_as_a_decision",
            "test_inf037b_eks_packet.PacketTests.test_canonical_exact_bytes_two_store_barrier_and_restart",
            "test_inf037b_eks_packet.PacketTests.test_capture_materializes_immutable_parent_report_checkpoint_and_shared_reset",
            "test_inf037b_eks_packet.PacketTests.test_catalog_omitting_campaign_owner_refuses",
            "test_inf037b_eks_packet.PacketTests.test_definition_bytes_must_match_the_effective_pin",
            "test_inf037b_eks_packet.PacketTests.test_durability_timeout_does_not_rebase_resolution",
            "test_inf037b_eks_packet.PacketTests.test_exact_sixty_second_durability_boundary_passes",
            "test_inf037b_eks_packet.PacketTests.test_lost_final_ack_refuses_even_when_both_stores_completed",
            "test_inf037b_eks_packet.PacketTests.test_maximum_inventory_bytes_must_match_resolved_transfer_size",
            "test_inf037b_eks_packet.PacketTests.test_missing_observation_refuses_and_persists_all_invalidated_outcomes",
            "test_inf037b_eks_packet.PacketTests.test_missing_reset_start_refuses",
            "test_inf037b_eks_packet.PacketTests.test_noncontinuous_owner_sequence_refuses_and_preserves_invalidated_slots",
            "test_inf037b_eks_packet.PacketTests.test_partial_second_store_refuses_before_start",
            "test_inf037b_eks_packet.PacketTests.test_post_seal_mutation_refuses_before_start_and_keeps_parent_outcomes",
            "test_inf037b_eks_packet.PacketTests.test_post_session_review_preserves_all_outcomes_and_invalidates_on_mutation",
            "test_inf037b_eks_packet.PacketTests.test_real_lifecycle_order_setup_attempt_reset_next_setup_materializes",
            "test_inf037b_eks_packet.PacketTests.test_real_process_cut_after_barrier_intent_refuses_on_reopen",
            "test_inf037b_eks_packet.PacketTests.test_rewritten_parent_prefix_refuses_materialization",
            "test_inf037b_eks_packet.PacketTests.test_stale_input_hash_refuses",
            "test_inf037b_eks_packet.PacketTests.test_start_after_attempt_end_refuses",
            "test_inf037b_eks_packet.PacketTests.test_start_intent_cut_refuses_without_another_start",
        )
    }
)
PRIVATE_CASES.update(
    {
        name: "Requires omitted private docs/evidence/m5-package-a/round237-source-audit.json."
        for name in (
            "test_package_a_round238.Round238Tests.test_r321_host_gate_status_comes_from_the_sample",
        )
    }
)
PRIVATE_CASES.update(
    {
        name: "Requires omitted private docs/evidence/m5-package-a/spend-ledger.json."
        for name in (
            "test_inf037b_gate_a.GateAVerdictTests.test_forecast_includes_three_ssm_interface_endpoints",
            "test_package_a_capture.CaptureTests.test_prepare_refuses_unclassified_consumed_packets",
            "test_package_a_capture.CaptureTests.test_prior_spend_ledger_matches_prior_spend_and_cap",
            "test_package_a_cloud.PackageACloudTests.test_prepare_host_checks_replace_preflight_only_for_exact_task_route",
            "test_package_a_cloud.PackageACloudTests.test_prepare_records_exact_host_preflight_replacement",
            "test_package_a_cloud.PackageACloudTests.test_prepare_supplied_preflight_still_validates_receipt",
            "test_package_a_round238.Round238Tests.test_r322_prepare_records_task_and_cumulative_forecasts",
            "test_package_a_round238.Round238Tests.test_r322_prepare_refuses_budget_sum_past_cost_guard_time",
            "test_package_a_workload.WorkloadTests.test_r312_prepare_calls_binding_before_bundle_or_terraform",
        )
    }
)
PRIVATE_CASES.update(
    {
        name: "Requires omitted private docs/evidence/r369-addon-refresh/coredns-configuration.json."
        for name in (
            "test_inf037b_eks_placement.PlacementBindingTests.test_r369_pinned_coredns_schema_and_census_n_plus_one",
        )
    }
)

PRIVATE_MODULE_REASONS = {
    name: "Requires omitted private stage-C admission or preregistration records."
    for name in PRIVATE_MODULES
}
PRIVATE_MODULE_REASONS["test_routine_prune"] = (
    "Imports the private routine AWS operator deliberately excluded from the snapshot."
)


def cases(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from cases(item)
        else:
            yield item


def select(suite):
    selected, omitted = [], []
    for case in cases(suite):
        identity = case.id()
        reason = next(
            (
                reason
                for key, reason in PRIVATE_CASES.items()
                if identity == key or identity.startswith(key + ".")
            ),
            None,
        )
        if reason:
            omitted.append({"case": identity, "reason": reason})
        else:
            selected.append(case)
    return unittest.TestSuite(selected), omitted


def omission_sentences(report):
    modules = len(report["private_record_modules_excluded"])
    count = len(report["private_record_cases_excluded"])
    return (
        f"{modules} private-record-dependent Python modules, private PLAN checks, paid approval/payload preflight and private snapshot-builder tests are omitted from this snapshot check command; their files may be retained for source inspection.",
        f"Public Python checks report {modules} private-record module exclusions and {count} exact private-record-dependent case exclusions, derived from the selector. Portable sibling tests still run; the private full suite runs all cases.",
    )


def update_readme(text, report):
    first, second = omission_sentences(report)
    text, n1 = re.subn(
        r"(?:Six|\d+) private-record-dependent Python modules,.*?source inspection\.",
        lambda _: first,
        text,
    )
    text, n2 = re.subn(
        r"Public Python checks report .*?the private full suite runs all cases\.",
        lambda _: second,
        text,
    )
    if (n1, n2) != (1, 1):
        raise ValueError("public_readme:omission_sentence_location")
    return text


def shards(selected, count, weights):
    from weighted_test_shards import distribute

    frequencies = {}
    for case in selected:
        module = case.id().split(".")[0]
        frequencies[module] = frequencies.get(module, 0) + 1
    module_weights = weights.get("modules", {})
    case_weights = weights.get("cases", {})
    return distribute(
        selected,
        count,
        lambda case: case_weights.get(
            case.id(),
            module_weights.get(case.id().split(".")[0] + ".py", {}).get("weight_s", 1)
            / frequencies[case.id().split(".")[0]],
        ),
        lambda case: case.id(),
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index", type=int, default=0)
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--all-shards", action="store_true")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--write-readme", type=Path)
    args = parser.parse_args()
    if not 0 <= args.index < args.count <= 64:
        parser.error("invalid public shard")
    directory = Path(__file__).resolve().parents[1] / "python/tests"
    own_paths = [str(directory.parent / "src"), str(directory)]
    sys.path[:0] = own_paths
    # Real child-command fixtures must import helpers from this exported checkout,
    # just as the private runner does, without falling back to a private tree.
    inherited = os.environ.get("PYTHONPATH", "")
    os.environ["PYTHONPATH"] = os.pathsep.join(
        [
            *own_paths,
            *[p for p in inherited.split(os.pathsep) if p and p not in own_paths],
        ]
    )
    modules = sorted(
        p.stem for p in directory.glob("test_*.py") if p.stem not in PRIVATE_MODULES
    )
    suite = unittest.TestSuite(
        unittest.defaultTestLoader.loadTestsFromName(name) for name in modules
    )
    suite, omitted = select(suite)
    report = {
        "private_record_modules_excluded": sorted(PRIVATE_MODULES),
        "private_record_module_reasons": PRIVATE_MODULE_REASONS,
        "private_record_cases_excluded": omitted,
        "public_cases": suite.countTestCases(),
    }
    if args.write_readme:
        args.write_readme.write_text(
            update_readme(args.write_readme.read_text(encoding="utf-8"), report),
            encoding="utf-8",
            newline="\n",
        )
        return 0
    selected = list(cases(suite))
    report["catalog_sha256"] = hashlib.sha256(
        "\n".join(sorted(case.id() for case in selected)).encode()
    ).hexdigest()
    if args.all_shards:
        records = []
        for index in range(args.count):
            started = time.monotonic()
            target = args.report / f"shard-{index}.json" if args.report else None
            command = [
                sys.executable,
                __file__,
                "--index",
                str(index),
                "--count",
                str(args.count),
            ]
            if target:
                command += ["--report", str(target)]
            completed = subprocess.run(command, check=False)
            elapsed = time.monotonic() - started
            records.append(
                {
                    "shard": index,
                    "elapsed_s": elapsed,
                    "exit_code": completed.returncode,
                }
            )
        print(json.dumps({"public_shards": records}), flush=True)
        return int(any(r["exit_code"] or r["elapsed_s"] >= 900 for r in records))
    if args.count > 1:
        root = directory.parents[1]
        weights = json.loads(
            (root / "deploy/package-a/cpu-test-weights.json").read_bytes()
        )
        measured = root / "deploy/package-a/public-test-weights.json"
        if measured.exists():
            weights["cases"] = json.loads(measured.read_bytes())["cases"]
        selected = shards(selected, args.count, weights)[args.index]
    identities = [case.id() for case in selected]
    report.update(
        shard=args.index,
        count=args.count,
        selected_cases=identities,
        selected_sha256=hashlib.sha256("\n".join(identities).encode()).hexdigest(),
    )
    print(json.dumps(report), flush=True)
    # Keep module/class fixture grouping intact within each case shard. Splitting
    # a long module retains every selected case, rather than hiding slow cases.
    from cpu_test_runner import ModuleSuite, ProgressResult

    timings = {}

    class TimedResult(ProgressResult):
        def startTest(self, test):
            self.started = time.monotonic()
            super().startTest(test)

        def stopTest(self, test):
            timings[test.id()] = time.monotonic() - self.started
            super().stopTest(test)

    groups = {}
    for case in selected:
        groups.setdefault(case.id().split(".")[0], []).append(case)
    suite = unittest.TestSuite(
        ModuleSuite(name, unittest.TestSuite(group)) for name, group in groups.items()
    )
    started = time.monotonic()
    result = unittest.TextTestRunner(verbosity=2, resultclass=TimedResult).run(suite)
    from inference_platform.package_a_cpu_validation import result_record

    report.update(
        elapsed_s=time.monotonic() - started,
        case_seconds=timings,
        result=result_record(result, result.passed),
    )
    print(json.dumps({"cpu_result": report["result"]}), flush=True)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return int(not result.wasSuccessful())


if __name__ == "__main__":
    raise SystemExit(main())
