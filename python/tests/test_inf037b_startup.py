"""Startup semantics and slow-loading replacement controls (offline only)."""

import copy

import test_inf037b_collectors as fixtures

from inference_platform.inf037b_campaign import (
    OfflineCampaign,
    materialize_bundle,
    reproduce,
    sanitized_campaign,
)
from inference_platform.inf037b_coverage import registered_coverage
from inference_platform.inf037b_sources import SourceJoin


def tearDownModule():
    fixtures.tearDownModule()


class StartupTests(fixtures.FixtureCase):
    def test_lifecycle_uid_without_creation_or_receipt_remains_expected(self):
        for event in ("container_state", "scheduled", "gpu_free", "signal", "deletion"):
            with self.subTest(event=event):
                records = fixtures.Records()
                rows = [
                    records.row(
                        "kubernetes",
                        "snapshot",
                        0,
                        endpoints=[],
                        resource_version="0",
                        list_valid=True,
                    ),
                    records.row(
                        "kubernetes",
                        event,
                        100,
                        pod_uid="new0",
                        slot=0,
                        container_state="running",
                        image_cache_state="cold",
                        model_cache_state="cold",
                    ),
                ]
                coverage = registered_coverage(SourceJoin(rows), 0, 10000)
                results = [
                    r for r in coverage["results"] if r.get("payload_match") == {"pod_uid": "new0"}
                ]
                self.assertEqual(len(results), 1, coverage)
                self.assertEqual(results[0]["absent_intervals"], [])
                self.assertTrue(results[0]["gaps_ms"])
                self.capture("startup_inventory_without_creation_" + event, rows, coverage)

    def test_loading_waiver_requires_cumulative_independent_lifecycle(self):
        records = fixtures.Records()
        created = records.row("kubernetes", "pod_created", 100, pod_uid="new0", slot=0)
        proof = records.row(
            "kubernetes",
            "container_state",
            10000,
            pod_uid="new0",
            slot=0,
            container_state="metrics_not_started",
            reason="continuous_lifecycle_since_pod_creation",
            image_cache_state="cold",
            model_cache_state="cold",
        )
        for mode in (
            "complete",
            "ordinary_snapshot",
            "missing_creation",
            "duplicate_creation",
            "missing_reason",
            "errored",
            "missing",
            "sample_contradiction",
            "ready_contradiction",
            "short_proof",
            "uncertain_proof",
            "earlier_errored_receipt",
            "earlier_missing_receipt",
            "errored_container_state",
            "missing_container_state",
            "untimed_error",
            "untimed_missing",
            "overlapping_error",
            "later_error",
            "other_pod_error",
        ):
            with self.subTest(mode=mode):
                rows = copy.deepcopy([created, proof])
                if mode == "ordinary_snapshot":
                    rows[1]["payload"]["container_state"] = "running"
                elif mode == "missing_creation":
                    rows.pop(0)
                elif mode == "duplicate_creation":
                    rows.append(records.row("kubernetes", "pod_created", 101, pod_uid="new0"))
                elif mode == "missing_reason":
                    rows[1]["payload"]["reason"] = "scrape_failed"
                elif mode == "errored":
                    rows[1]["error"] = "lifecycle_capture_lost"
                elif mode == "missing":
                    rows[1]["missing_reason"] = "lifecycle_capture_lost"
                elif mode.endswith("contradiction"):
                    rows.append(
                        records.row(
                            "vllm" if mode.startswith("sample") else "kubernetes",
                            "sample" if mode.startswith("sample") else "ready",
                            1000,
                            pod_uid="new0",
                        )
                    )
                elif mode == "short_proof":
                    rows[1]["source_time"]["value"] = 7000
                elif mode == "uncertain_proof":
                    rows[1]["source_time"]["value"] = 9900
                    rows[1]["uncertainty_ns"] = 100000000
                elif mode in (
                    "earlier_errored_receipt",
                    "earlier_missing_receipt",
                    "errored_container_state",
                    "missing_container_state",
                    "untimed_error",
                    "untimed_missing",
                    "overlapping_error",
                    "later_error",
                    "other_pod_error",
                ):
                    loss = records.row(
                        "kubernetes",
                        "container_state",
                        11000
                        if mode == "later_error"
                        else 10050
                        if mode == "overlapping_error"
                        else 5000,
                        pod_uid="other0" if mode == "other_pod_error" else "new0",
                        container_state="metrics_not_started" if "receipt" in mode else "running",
                        reason="continuous_lifecycle_since_pod_creation"
                        if "receipt" in mode
                        else "container_started",
                    )
                    loss["missing_reason" if "missing" in mode else "error"] = (
                        "lifecycle_capture_lost"
                    )
                    if mode.startswith("untimed"):
                        loss["uncertainty_ns"] = 101000000
                    elif mode == "overlapping_error":
                        loss["uncertainty_ns"] = 100000000
                    rows.append(loss)
                # Keep new0 in inventory even when its proof is unusable.
                rows.append(
                    records.row(
                        "kubernetes",
                        "snapshot",
                        0,
                        endpoints=[{"uid": "new0", "serving": False}],
                        resource_version="0",
                        list_valid=True,
                    )
                )
                joined = SourceJoin(self.joined(rows))
                coverage = registered_coverage(joined, 0, 10000)
                contract = next(
                    c for c in coverage["contracts"] if c["payload_match"] == {"pod_uid": "new0"}
                )
                result = next(
                    r for r in coverage["results"] if r.get("payload_match") == {"pod_uid": "new0"}
                )
                if mode in ("complete", "later_error", "other_pod_error"):
                    self.assertEqual(contract["absent_intervals"], [[0, 10000]])
                    self.assertEqual(len(contract["lifecycle_proofs"]), 2)
                    self.assertEqual(result["gaps_ms"], [])
                elif mode == "uncertain_proof":
                    self.assertEqual(contract["absent_intervals"], [[0, 9800]])
                else:
                    self.assertTrue(result["gaps_ms"], result)
                    if mode != "short_proof":
                        self.assertEqual(contract["absent_intervals"], [])
                self.capture("startup_loading_" + mode, rows, coverage)

    def test_loading_capture_loss_is_inadequate(self):
        def capture_loss(row):
            if row["payload"].get("reason") == "container_started":
                row["error"] = "lifecycle_capture_lost"
            return False

        campaign, rows = fixtures.complete_campaign_fixture(
            self.root / "capture-loss", metrics_loading=True, end=931000, drop=capture_loss
        )
        report = campaign.report()
        self.assertFalse(report["measurement_valid"], report["validity_reasons"])
        self.assertIsNone(report["stages"]["stage4"]["replacement_usable_by_deadline"])
        self.assertIn("required_source_gap", report["validity_reasons"])
        journal = campaign.finish_attempt(
            931000, absolute_deadline_ms=10000000, export_cleanup_ms=0
        )
        stops = [e["reason"] for e in campaign.journal.events if e["event"] == "campaign_stop"]
        self.assertIn("replacement_usability_not_established", stops)
        self.assertNotIn("previous_replacement_never_usable", stops)
        fixtures.Round193Tests.retain(
            self,
            "startup_campaign_capture_loss",
            campaign,
            report,
            source_rows=rows,
            finished_journal=journal,
        )

    def test_slow_loading_never_usable_and_missing_proof_are_distinct(self):
        for missing_proof in (False, True):
            with self.subTest(missing_proof=missing_proof):
                root = self.root / ("missing" if missing_proof else "complete")
                campaign, rows = fixtures.complete_campaign_fixture(
                    root,
                    metrics_loading=True,
                    end=931000,
                    drop=(
                        lambda row: row["payload"].get("container_state") == "metrics_not_started"
                    )
                    if missing_proof
                    else None,
                )
                before = campaign.report()
                stage4 = before["stages"]["stage4"]
                self.assertIsNone(stage4["startup_ms_bounds"])
                self.assertIsNone(stage4["ready_ms_bounds"])
                self.assertIsNone(stage4["usable_ms_bounds"])
                self.assertIs(
                    before["measurement_valid"], not missing_proof, before["validity_reasons"]
                )
                self.assertIs(
                    stage4["replacement_usable_by_deadline"], None if missing_proof else False
                )
                if missing_proof:
                    # A plain running-container row cannot excuse missing metrics.
                    self.assertIn("required_source_gap", before["validity_reasons"])
                else:
                    for budget in before["stages"]["addition_budgets"]:
                        self.assertEqual(budget["age_budget_status"], "not_applicable")
                        self.assertEqual(budget["renewal_budget_status"], "not_applicable")
                journal = campaign.finish_attempt(
                    931000,
                    absolute_deadline_ms=10000000,
                    export_cleanup_ms=0,
                )
                stops = [
                    e["reason"] for e in campaign.journal.events if e["event"] == "campaign_stop"
                ]
                self.assertIn(
                    "replacement_usability_not_established"
                    if missing_proof
                    else "previous_replacement_never_usable",
                    stops,
                )
                materialize_bundle(root, [campaign.spec])
                exported = sanitized_campaign(
                    root,
                    self.root / ("safe-missing" if missing_proof else "safe-complete"),
                    [campaign.spec],
                    key=b"startup-fixture-only-key-00000000",
                )
                safe_root = self.root / ("safe-missing" if missing_proof else "safe-complete")
                after = OfflineCampaign(safe_root, exported["specs"][0]).report()
                self.assertEqual(before["stage_eligibility"], after["stage_eligibility"])
                self.assertIs(
                    after["stages"]["stage4"]["replacement_usable_by_deadline"],
                    None if missing_proof else False,
                )
                self.assertTrue(reproduce(safe_root, attempt_index=1)["reproduced"])
                fixtures.Round193Tests.retain(
                    self,
                    "startup_campaign_" + ("missing" if missing_proof else "complete"),
                    campaign,
                    before,
                    source_rows=rows,
                    finished_journal=journal,
                    sanitized_report=after["stages"],
                    sanitized_archive=exported["archive"],
                )
