"""Synthetic, offline registration-v3 core fixtures; emit inspectable decisions.

INF037B_FIXTURE_OUTPUT optionally writes the actual statuses/reasons/receipts.
This does not implement source joins or assert EKS fitness.
"""

import copy
import hashlib
import json
import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from inference_platform.inf037b_archive import (
    Archive,
    IntegrityError,
    encode,
    envelope,
    export_archive,
    inspect_segment,
    sanitized_copy,
    verify_archive,
)
from inference_platform.inf037b_attempts import AttemptController, Refused
from inference_platform.inf037b_budget import (
    Bounds,
    both_gateways,
    classify,
    gateway_budget,
    stage1_scope,
)
from inference_platform.inf037b_contract import (
    AGE_MS,
    ATTEMPT_MS,
    CAMPAIGN_MS,
    GATEWAYS,
    REGISTRATION_GIT_BLOB_SHA256,
    REGISTRATION_ID,
    REGISTRATION_PATH,
    RENEWAL_MS,
    RESET_MS,
    SOURCE_KINDS,
    STAGE1_CATEGORIES,
    TTL_MS,
)
from inference_platform.inf037b_fitness import (
    Component,
    SourceBracket,
    StartupCase,
    startup_fitness,
)

OUTPUTS = {}


def capture(name, value):
    OUTPUTS[name] = value
    return value


def tearDownModule():
    if output := os.environ.get("INF037B_FIXTURE_OUTPUT"):
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(OUTPUTS, indent=2, sort_keys=True) + "\n", encoding="utf-8")


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.archive = Archive.create(
            self.root / "raw-archive", {"registration_id": REGISTRATION_ID}
        )

    def failure(self, name, fn, expected):
        with self.assertRaisesRegex(IntegrityError, expected) as caught:
            fn()
        capture(name, {"valid": False, "reason": str(caught.exception)})

    def test_layout_finalize_duplicate_and_exact_byte_hash(self):
        self.assertTrue((self.archive.root / "cohorts").is_dir())
        self.assertTrue((self.archive.root / "cohorts/requests.jsonl").is_file())
        self.assertTrue((self.archive.root / "events").is_dir())
        for kind in SOURCE_KINDS:
            self.assertTrue((self.archive.root / f"raw/{kind}.jsonl").is_file())
        row = envelope({"event": "observed"}, seq=7)
        self.archive.append("raw/controller.jsonl", row)
        self.archive.append("raw/controller.jsonl", row)
        receipt = capture(
            "archive_segment_finalization", self.archive.finalize_segment("raw/controller.jsonl")
        )
        self.assertEqual(
            receipt,
            {
                "bytes": len(encode(row)) * 2,
                "row_count": 2,
                "first_sequence": 7,
                "last_sequence": 7,
                "sha256": hashlib.sha256(encode(row) * 2).hexdigest(),
                "duplicate_count": 1,
                "torn_tail_offset": None,
                "integrity_errors": [],
            },
        )
        self.failure(
            "append_finalized_segment",
            lambda: self.archive.append("raw/controller.jsonl", row),
            "segment_finalized",
        )
        self.archive.seal()
        sums = (self.archive.root / "SHA256SUMS").read_text()
        self.assertNotIn("  SHA256SUMS", sums)
        self.assertIn("  registration.json", sums)
        self.assertTrue(verify_archive(self.archive.root)["verified"])
        self.failure(
            "append_sealed_archive",
            lambda: self.archive.append("attempts.jsonl", row),
            "archive_sealed",
        )

    def test_truncated_jsonl_seals_sanitizes_and_exports(self):
        path = self.archive.root / "raw/controller.jsonl"
        valid = encode(envelope({"value": 1}, seq=0))
        tail = b'{"private":"fixture-secret'
        path.write_bytes(valid + tail)
        before = path.read_bytes()
        sealed = capture("torn_tail_sealed", self.archive.seal())
        receipt = sealed["segments"]["raw/controller.jsonl"]
        self.assertEqual(receipt["row_count"], 1)
        self.assertEqual(receipt["bytes"], len(before))
        self.assertEqual(receipt["sha256"], hashlib.sha256(before).hexdigest())
        self.assertEqual(receipt["torn_tail_offset"], len(valid))
        self.assertEqual(
            receipt["integrity_errors"], [{"reason": "truncated_jsonl", "byte_offset": len(valid)}]
        )
        self.failure(
            "torn_tail_without_sanitizer_refused",
            lambda: sanitized_copy(self.archive.root, self.root / "unsafe", copy.deepcopy),
            "torn_tail_requires_explicit_sanitizer",
        )
        sanitized = sanitized_copy(
            self.archive.root,
            self.root / "sanitized",
            copy.deepcopy,
            transform_tail=lambda data: data.replace(b"fixture-secret", b"redacted"),
        )
        self.assertEqual(
            (sanitized.root / "raw/controller.jsonl").read_bytes(),
            valid + tail.replace(b"fixture-secret", b"redacted"),
        )
        sanitized_receipt = capture("torn_tail_sanitized", verify_archive(sanitized.root))
        self.assertEqual(
            sanitized_receipt["segments"]["raw/controller.jsonl"]["integrity_errors"],
            receipt["integrity_errors"],
        )
        exported = capture(
            "torn_tail_exported", export_archive(sanitized.root, self.root / "export")
        )
        self.assertTrue(exported["complete"])
        self.assertEqual(exported["verification"], sanitized_receipt)
        provenance = capture(
            "torn_tail_source_receipt",
            json.loads((self.root / "export/source-integrity.receipt.json").read_bytes()),
        )
        self.assertEqual(provenance["segments"]["raw/controller.jsonl"], receipt)
        self.assertEqual(path.read_bytes(), before)
        path.write_bytes(before + b"x")
        self.failure(
            "torn_tail_post_seal_mutation",
            lambda: verify_archive(self.archive.root),
            "hash_mismatch",
        )
        self.failure("torn_tail_reseal_mutation", self.archive.seal, "hash_mismatch")

    def test_rotation_resume_and_strict_json(self):
        row = envelope({"v": 1}, seq=0)
        self.archive.append("raw/controller.jsonl", row)
        reopened = Archive(self.archive.root)
        segment = reopened.new_raw_segment("controller", 1)
        reopened.append(segment, envelope({"v": 2}, seq=1))
        result = capture("archive_rotated_segments", reopened.seal())
        self.assertEqual(result["segments"][segment]["first_sequence"], 1)
        invalid = self.root / "invalid.jsonl"
        invalid.write_bytes(encode(row).replace(b'"v":1', b'"v":1,"v":2'))
        self.failure(
            "duplicate_json_member", lambda: inspect_segment(invalid), "duplicate_json_member"
        )
        invalid.write_bytes(encode(row).replace(b'"v":1', b'"v":NaN'))
        self.failure("nonfinite_json", lambda: inspect_segment(invalid), "nonfinite_json")

    def test_registration_v4_binding_and_v3_preservation(self):
        repo = Path(__file__).resolve().parents[2]
        data = (repo / REGISTRATION_PATH).read_bytes()
        # Git autocrlf is not a registration revision; bind the committed LF blob.
        self.assertEqual(
            hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest(), REGISTRATION_GIT_BLOB_SHA256
        )
        self.assertEqual(REGISTRATION_ID, "inf037b-v4-r315")
        prior_v4 = (repo / "docs/INF037B_REGISTRATION_V4.md").read_bytes()
        self.assertEqual(
            hashlib.sha256(prior_v4.replace(b"\r\n", b"\n")).hexdigest(),
            "02ba808f529622242b86ec0df0f464786608569f957123c97a8754e177d4d0ca",
        )
        self.assertEqual(
            hashlib.sha256(
                (repo / "docs/INF037B_PRE_REGISTRATION.md").read_bytes().replace(b"\r\n", b"\n")
            ).hexdigest(),
            "05812e4560ec869a2d87171f93d064ed61a3ba0d3a0240def1e946219d958a34",
        )

    def test_hash_mismatch_and_receipt_mismatch(self):
        self.archive.append("raw/controller.jsonl", envelope({}, seq=0))
        self.archive.seal()
        path = self.archive.root / "raw/controller.jsonl"
        path.write_bytes(path.read_bytes() + b"\n")
        self.failure("hash_mismatch", lambda: verify_archive(self.archive.root), "hash_mismatch")
        # Rehashing a modified receipt is insufficient: verification recomputes counts.
        path.write_bytes(encode(envelope({}, seq=0)))
        sidecar = path.with_suffix(".receipt.json")
        receipt = json.loads(sidecar.read_bytes())
        receipt["row_count"] += 1
        sidecar.write_bytes(encode(receipt))
        manifest = self.archive.root / "SHA256SUMS"
        manifest.write_bytes(
            manifest.read_bytes().replace(
                hashlib.sha256(encode({**receipt, "row_count": 1})).hexdigest().encode(),
                hashlib.sha256(sidecar.read_bytes()).hexdigest().encode(),
            )
        )
        self.failure(
            "receipt_count_mismatch",
            lambda: verify_archive(self.archive.root),
            "segment_receipt_mismatch",
        )

    def test_conflicting_duplicates_seal_sanitize_and_export(self):
        row = envelope({"value": 1}, seq=0)
        self.archive.append("raw/controller.jsonl", row)
        conflict = copy.deepcopy(row)
        conflict["payload"]["value"] = 2
        self.archive.append("raw/controller.jsonl", conflict)
        self.archive.finalize_segment("raw/controller.jsonl")
        # Cross-segment conflicts retain both streams, including finalized segments.
        self.archive.append("attempts.jsonl", conflict)
        invalid = copy.deepcopy(row)
        del invalid["collector_boot_id"]
        self.failure(
            "missing_common_envelope",
            lambda: self.archive.append("attempts.jsonl", invalid),
            "missing_common_envelope",
        )
        before = {
            name: (self.archive.root / name).read_bytes()
            for name in ("raw/controller.jsonl", "attempts.jsonl")
        }
        sealed = capture("conflicting_duplicates_sealed", self.archive.seal())
        error = sealed["segments"]["raw/controller.jsonl"]["integrity_errors"][0]
        self.assertEqual(error["reason"], "conflicting_duplicate")
        self.assertEqual(
            error["record_key"],
            {field: row[field] for field in ("source_identity", "source_generation", "record_id")},
        )
        self.assertEqual(
            error["locations"],
            [
                {"segment": "attempts.jsonl", "line": 1, "byte_offset": 0},
                {"segment": "raw/controller.jsonl", "line": 1, "byte_offset": 0},
            ],
        )
        self.assertIn(error, sealed["segments"]["attempts.jsonl"]["integrity_errors"])
        self.assertEqual(self.archive.seal(), sealed)
        self.assertEqual(
            self.archive.finalize_segment("raw/controller.jsonl"),
            sealed["segments"]["raw/controller.jsonl"],
        )
        sanitized = sanitized_copy(
            self.archive.root,
            self.root / "sanitized",
            copy.deepcopy,
            transform_key=copy.deepcopy,
        )
        capture("conflicting_duplicates_sanitized", verify_archive(sanitized.root))
        exported = capture(
            "conflicting_duplicates_exported", export_archive(sanitized.root, self.root / "export")
        )
        self.assertTrue(exported["complete"])
        self.assertEqual(exported["verification"]["segments"], sealed["segments"])
        for name, data in before.items():
            self.assertEqual((self.archive.root / name).read_bytes(), data)
            self.assertEqual((self.root / "export" / name).read_bytes(), data)
        (self.root / "export/attempts.jsonl").write_bytes(b"changed")
        self.failure(
            "conflict_post_export_mutation",
            lambda: verify_archive(self.root / "export"),
            "hash_mismatch",
        )

    def test_duplicate_keys_are_source_and_generation_scoped(self):
        row = envelope({"value": 1}, seq=0)
        self.archive.append("raw/controller.jsonl", row)
        for field in ("source_identity", "source_generation"):
            independent = copy.deepcopy(row)
            independent[field] = "independent"
            independent["payload"]["value"] = 2
            self.archive.append("attempts.jsonl", independent)
        result = capture("source_scoped_duplicate_keys", self.archive.seal())
        self.assertTrue(all(not r["integrity_errors"] for r in result["segments"].values()))

    def test_sanitization_retains_conflict_provenance_if_payloads_merge(self):
        raw_key = {
            "source_identity": "node-7.internal.example",
            "source_generation": "pod-uid-raw-7",
            "record_id": "record-raw-42",
        }
        first = envelope({"secret": 1}, seq=0)
        first.update(raw_key)
        second = copy.deepcopy(first)
        second["payload"]["secret"] = 2
        self.archive.append("raw/controller.jsonl", first)
        self.archive.append("attempts.jsonl", second)
        sealed = self.archive.seal()

        def sanitize(row):
            row["payload"].clear()
            row.update(
                source_identity="node-a",
                source_generation="generation-a",
                record_id="record-a",
            )
            return row

        def sanitize_key(key):
            return {
                "source_identity": "node-a",
                "source_generation": "generation-a",
                "record_id": "record-a",
            }

        sanitized = sanitized_copy(
            self.archive.root,
            self.root / "sanitized",
            sanitize,
            transform_key=sanitize_key,
        )
        result = capture("merged_conflict_sanitized", verify_archive(sanitized.root))
        self.assertTrue(all(not r["integrity_errors"] for r in result["segments"].values()))
        export_archive(sanitized.root, self.root / "export")
        provenance = capture(
            "merged_conflict_source_receipt",
            json.loads((self.root / "export/source-integrity.receipt.json").read_bytes()),
        )
        error = provenance["segments"]["attempts.jsonl"]["integrity_errors"][0]
        self.assertEqual(error["reason"], "conflicting_duplicate")
        self.assertEqual(
            error["record_key"],
            {
                "source_identity": "node-a",
                "source_generation": "generation-a",
                "record_id": "record-a",
            },
        )
        self.assertEqual(len(error["locations"]), 2)
        self.assertEqual(
            provenance["segments"]["attempts.jsonl"]["sha256"],
            sealed["segments"]["attempts.jsonl"]["sha256"],
        )
        export_bytes = b"".join(
            path.read_bytes() for path in (self.root / "export").rglob("*") if path.is_file()
        )
        for raw_value in raw_key.values():
            self.assertNotIn(raw_value.encode(), export_bytes)
        capture(
            "merged_conflict_export_has_sanitized_key",
            {
                "raw_keys_absent": True,
                "transformed_record_key": error["record_key"],
                "reason": error["reason"],
                "locations": error["locations"],
            },
        )

    def test_conflict_receipt_requires_key_sanitizer(self):
        row = envelope({"value": 1}, seq=0)
        self.archive.append("raw/controller.jsonl", row)
        conflict = copy.deepcopy(row)
        conflict["payload"]["value"] = 2
        self.archive.append("raw/controller.jsonl", conflict)
        self.archive.seal()
        self.failure(
            "conflict_key_without_sanitizer_refused",
            lambda: sanitized_copy(self.archive.root, self.root / "sanitized", copy.deepcopy),
            "conflict_keys_require_explicit_sanitizer",
        )

    def test_failed_first_export_does_not_block_correct_retry(self):
        self.archive.append("raw/controller.jsonl", envelope({"value": 1}, seq=0))
        self.archive.seal()
        sanitized = sanitized_copy(self.archive.root, self.root / "sanitized", copy.deepcopy)
        destination = self.root / "export"
        self.failure(
            "export_first_raw_archive_refused",
            lambda: export_archive(self.archive.root, destination),
            "export_requires_separate_sanitized_archive",
        )
        prior = json.loads((self.root / "export.export-receipt.json").read_bytes())
        self.assertNotIn("source_manifest_sha256", prior)
        self.assertFalse(destination.exists())
        retried = capture(
            "export_retry_after_pre_manifest_failure", export_archive(sanitized.root, destination)
        )
        self.assertTrue(retried["complete"])
        self.assertTrue(verify_archive(destination)["verified"])

    def test_refused_export_mistakes_preserve_partial_resume_receipt(self):
        self.archive.append("raw/controller.jsonl", envelope({"value": "archive-a"}, seq=0))
        self.archive.seal()
        sanitized_a = sanitized_copy(self.archive.root, self.root / "sanitized-a", copy.deepcopy)
        manifest_a = hashlib.sha256((sanitized_a.root / "SHA256SUMS").read_bytes()).hexdigest()

        raw_b = Archive.create(self.root / "raw-b", {"registration_id": REGISTRATION_ID})
        raw_b.append("raw/controller.jsonl", envelope({"value": "archive-b"}, seq=0))
        raw_b.seal()
        sanitized_b = sanitized_copy(raw_b.root, self.root / "sanitized-b", copy.deepcopy)
        self.assertNotEqual(
            hashlib.sha256((sanitized_b.root / "SHA256SUMS").read_bytes()).hexdigest(), manifest_a
        )

        mistakes = (
            ("raw_archive", self.archive.root, "export_requires_separate_sanitized_archive"),
            ("missing_path", self.root / "missing-source", "missing_SHA256SUMS"),
            ("other_sanitized_archive", sanitized_b.root, "resume_source_changed"),
        )
        fixture = {}
        for name, mistaken_source, expected_reason in mistakes:
            destination = self.root / f"export-{name}"
            partial = export_archive(sanitized_a.root, destination, byte_budget=11)
            self.assertFalse(partial["complete"])
            receipt_path = destination.with_name(destination.name + ".export-receipt.json")
            before_mistake = json.loads(receipt_path.read_bytes())
            self.assertEqual(before_mistake["source_manifest_sha256"], manifest_a)

            self.failure(
                f"export_{name}_refused_after_partial_a",
                lambda src=mistaken_source, dest=destination: export_archive(src, dest),
                expected_reason,
            )
            after_mistake = json.loads(receipt_path.read_bytes())
            self.assertEqual(after_mistake["source_manifest_sha256"], manifest_a)
            self.assertEqual(after_mistake, before_mistake)

            completed = export_archive(sanitized_a.root, destination)
            self.assertTrue(completed["complete"])
            self.assertTrue(verify_archive(destination)["verified"])
            persisted = json.loads(receipt_path.read_bytes())
            self.assertEqual(persisted["source_manifest_sha256"], manifest_a)
            fixture[name] = {
                "mistake_reason": expected_reason,
                "manifest_preserved_after_mistake": True,
                "resume_complete": completed["complete"],
                "resume_verified": True,
                "manifest_after_resume": persisted["source_manifest_sha256"],
            }
        capture("export_refused_mistakes_preserve_partial_receipt", fixture)

    def test_export_interrupt_resume_and_separate_raw(self):
        row = envelope({"secret_mapping": "fixture-private", "join_id": "pseudonym1"}, seq=0)
        self.archive.append("raw/controller.jsonl", row)
        self.archive.seal()
        before = {
            p.relative_to(self.archive.root).as_posix(): p.read_bytes()
            for p in self.archive.root.rglob("*")
            if p.is_file()
        }

        def sanitize(record):
            transformed = copy.deepcopy(record)
            transformed["payload"].pop("secret_mapping", None)
            return transformed

        sanitized = sanitized_copy(self.archive.root, self.root / "sanitized", sanitize)
        destination = self.root / "export"
        partial = capture(
            "export_interrupted", export_archive(sanitized.root, destination, byte_budget=11)
        )
        self.assertFalse(partial["complete"])
        self.assertEqual(sum(partial["resume_offsets"].values()), 11)
        persisted = json.loads((self.root / "export.export-receipt.json").read_bytes())
        self.assertEqual(partial, persisted)
        complete = capture("export_resumed", export_archive(sanitized.root, destination))
        self.assertTrue(complete["complete"])
        self.assertEqual(complete["reason"], "counts_and_hashes_verified")
        self.assertTrue(verify_archive(destination)["verified"])
        self.assertTrue((destination / "cohorts").is_dir())
        self.assertTrue((destination / "events").is_dir())
        self.assertNotIn(b"fixture-private", (destination / "raw/controller.jsonl").read_bytes())
        self.assertIn(b"pseudonym1", (destination / "raw/controller.jsonl").read_bytes())
        self.assertEqual(
            before,
            {
                p.relative_to(self.archive.root).as_posix(): p.read_bytes()
                for p in self.archive.root.rglob("*")
                if p.is_file()
            },
        )
        self.failure(
            "raw_export_refused",
            lambda: export_archive(self.archive.root, self.root / "unsafe"),
            "requires_separate_sanitized",
        )

    def test_resume_corruption_fails_with_incomplete_receipt(self):
        self.archive.seal()
        sanitized = sanitized_copy(self.archive.root, self.root / "sanitized", copy.deepcopy)
        destination = self.root / "export"
        partial = export_archive(sanitized.root, destination, byte_budget=9)
        first = next(iter(partial["resume_offsets"]))
        (destination / first).write_bytes(b"corrupted")
        self.failure(
            "resume_corrupt_prefix",
            lambda: export_archive(sanitized.root, destination),
            "resume_prefix_mismatch",
        )
        receipt = capture(
            "export_corrupt_incomplete_receipt",
            json.loads((self.root / "export.export-receipt.json").read_bytes()),
        )
        self.assertFalse(receipt["complete"])
        self.assertEqual(receipt["resume_offsets"][first], 9)


class BudgetTests(unittest.TestCase):
    def test_completed_boundaries(self):
        for label, limit, values in (
            ("age", AGE_MS, (2999, 3000, 3001)),
            ("renewal", RENEWAL_MS, (3099, 3100, 3101)),
        ):
            for value in values:
                with self.subTest(label=label, value=value):
                    result = capture(f"{label}_{value}", classify(Bounds(value, value), limit))
                    self.assertEqual(result["status"], "within" if value <= limit else "exceeded")
            result = capture(f"{label}_uncertainty", classify(Bounds(limit - 1, limit + 1), limit))
            self.assertEqual(result["status"], "indeterminate")

    def test_open_renewal_boundaries(self):
        for lower, upper, expected in (
            (2000, 2001, "right_censored"),
            (3100, 3200, "right_censored"),
            (3101, 3200, "exceeded"),
        ):
            result = capture(
                f"open_renewal_{lower}",
                gateway_budget(
                    "gateway0",
                    "new0",
                    capture_end=Bounds(5000 + lower, 5000 + upper),
                    capture_complete=True,
                    installation=Bounds(5000, 5000),
                    preceding_store_ms=4000,
                ),
            )
            self.assertEqual(result["renewal_budget_status"], expected)
            self.assertEqual(result["renewal_elapsed_lower_bound_ms"], lower)
            self.assertEqual(result["age_budget_status"], "within")
            self.assertFalse(result["validity_reasons"])

    def test_no_installation_and_one_gateway_only(self):
        inputs = {
            g: {"capture_end": Bounds(10_000, 10_000), "capture_complete": True} for g in GATEWAYS
        }
        results = capture("no_installation_both_gateways", both_gateways("new0", **inputs))
        for row in results:
            for field in ("age", "renewal"):
                self.assertEqual(row[f"{field}_budget_status"], "not_applicable")
                self.assertEqual(
                    row[f"{field}_budget_reason"], "replacement_not_installed_before_attempt_end"
                )
            self.assertFalse(row["validity_reasons"])
        inputs["gateway0"].update(
            installation=Bounds(5000, 5000),
            preceding_store_ms=1999,
            renewal_store=Bounds(8101, 8101),
        )
        results = capture("installation_one_gateway_only", both_gateways("new0", **inputs))
        self.assertEqual(results[0]["age_budget_status"], "exceeded")
        self.assertEqual(results[0]["renewal_budget_status"], "exceeded")
        self.assertEqual(results[1]["age_budget_status"], "not_applicable")
        self.assertFalse(results[0]["validity_reasons"])
        with self.assertRaisesRegex(ValueError, "both gateways"):
            both_gateways("new0", gateway0=inputs["gateway0"])

    def test_missing_join_clock_or_capture_are_validity_reasons(self):
        base = {
            "capture_end": Bounds(10_000, 10_000),
            "capture_complete": True,
            "installation": Bounds(5000, 5000),
            "preceding_store_ms": 4000,
        }
        for label, changes, reason in (
            ("missing_join", {"preceding_store_ms": None}, "missing_preceding_report_store_join"),
            ("missing_clock", {"clock_evidence": False}, "missing_required_clock_evidence"),
            ("missing_capture", {"capture_complete": False}, "incomplete_installation_capture"),
            (
                "stored_after_installation",
                {"preceding_store_ms": 5001},
                "report_not_proven_preceding_by_store_time",
            ),
            (
                "ambiguous_store_order",
                {"store_order_evidenced": False},
                "missing_preceding_report_store_join",
            ),
        ):
            result = capture(label, gateway_budget("gateway0", "new0", **(base | changes)))
            self.assertIn(reason, result["validity_reasons"])
            self.assertIsNone(result["age_budget_status"])
        no_install = capture(
            "no_installation_capture_gap",
            gateway_budget("gateway0", "new0", capture_end=Bounds(10, 10), capture_complete=False),
        )
        self.assertIsNone(no_install["age_budget_status"])

    def test_stage1_exact_claim_boundary_and_nonzero_preservation(self):
        result = capture("stage1_zero_coverage", stage1_scope())
        for name in STAGE1_CATEGORIES:
            self.assertEqual(result[name], {"count": 0, "coverage": "not_exercised_max_tokens_1"})
        with self.assertRaisesRegex(ValueError, "raw references"):
            stage1_scope({"partial_after_content": 1})
        result = capture(
            "stage1_unexpected_nonzero",
            stage1_scope({"partial_after_content": 1}, raw_refs=["raw/client.jsonl:record1"]),
        )
        self.assertEqual(result["partial_after_content"]["count"], 1)
        self.assertEqual(result["max_tokens"], 1)
        self.assertEqual(result["sigterm_coverage_scope"], "queued_or_prefill")


PINS = {
    "controller": "synthetic-deployment",
    "configuration_sha256": "fixture-config",
    "kubernetes_version": "fixture-version-not-an-EKS-pin",
}


def bracket(lower, upper=None, *, mapping_uncertainty_ms=0):
    return SourceBracket(
        Bounds(lower, lower if upper is None else upper),
        "synthetic-source",
        PINS,
        "mapped-fixture-clock",
        "fixture-clock-record",
        mapping_uncertainty_ms,
    )


def components(grace=35_000, scheduler=1000):
    return [
        Component(name, bound, "synthetic-bound", PINS)
        for name, bound in (
            ("termination_grace", grace),
            ("kill_device_release", 2000),
            ("controller_scheduler", scheduler),
        )
    ]


def cases(duration=200_000, pod=0, gpu=38_000):
    return [
        StartupCase(
            cache,
            "node_cached",
            bracket(pod),
            bracket(gpu),
            {g: bracket(max(pod, gpu) + duration) for g in GATEWAYS},
            "fixture-sigterm",
            "fixture-cache-state",
        )
        for cache in ("cold", "node_cached")
    ]


class FitnessTests(unittest.TestCase):
    def evaluate(self, label, *, allowance=None, startup=None, grace=35_000, pins=None):
        return capture(
            label,
            startup_fitness(
                components=components() if allowance is None else allowance,
                configured_grace_ms=grace,
                cases=cases() if startup is None else startup,
                required_pins=PINS if pins is None else pins,
            ),
        )

    def test_270_plus_35_plus_2_plus_1_fails(self):
        result = self.evaluate("startup_308_seconds", startup=cases(duration=270_000))
        self.assertFalse(result["fit"])
        self.assertEqual(result["d_bind_ms"], 38_000)
        for case in result["cases"]:
            self.assertEqual(case["gateways"]["gateway0"]["d_bind_plus_upper_ms"], 308_000)

    def test_observation_bracket_width_is_not_mapping_uncertainty(self):
        startup = cases(duration=200_000, pod=0, gpu=0)
        startup[0] = replace(startup[0], pod_creation=bracket(0, 1000))
        result = self.evaluate("startup_one_second_observation_bracket", startup=startup)
        self.assertTrue(result["fit"])
        self.assertEqual(result["cases"][0]["t_start_ms_bounds"], [0, 1000])
        self.assertTrue(all(row["fits"] for row in result["cases"][0]["gateways"].values()))

        startup = cases()
        startup[0] = replace(
            startup[0],
            pod_creation=bracket(0, mapping_uncertainty_ms=101),
        )
        result = self.evaluate("startup_101ms_mapping_uncertainty", startup=startup)
        self.assertFalse(result["fit"])
        self.assertIn(
            "cold:clock_uncertainty_exceeds_registered_bound",
            result["reasons"],
        )

        exact = cases(duration=262_000, pod=0, gpu=38_000)
        exact[0] = replace(
            exact[0],
            pod_creation=bracket(0, mapping_uncertainty_ms=100),
            gpu_free=bracket(38_000, mapping_uncertainty_ms=100),
            usable_by_gateway={
                gateway: bracket(300_000, mapping_uncertainty_ms=100) for gateway in GATEWAYS
            },
        )
        result = self.evaluate("startup_exact_300_seconds_with_mapping_uncertainty", startup=exact)
        self.assertFalse(result["fit"])
        self.assertIn(
            "cold:startup_deadline_infeasible:gateway0",
            result["reasons"],
        )
        self.assertEqual(
            result["cases"][0]["gateways"]["gateway0"]["d_bind_plus_upper_ms"],
            300_200,
        )

        missing = cases()
        missing[0] = replace(missing[0], pod_creation=bracket(0, mapping_uncertainty_ms=None))
        result = self.evaluate("startup_missing_clock_mapping", startup=missing)
        self.assertFalse(result["fit"])
        self.assertIn("cold:missing_clock_mapping", result["reasons"])

        absent = object.__new__(SourceBracket)
        object.__setattr__(absent, "bounds", Bounds(0, 0))
        object.__setattr__(absent, "source", "synthetic-source")
        object.__setattr__(absent, "pins", PINS)
        object.__setattr__(absent, "clock_id", "mapped-fixture-clock")
        object.__setattr__(absent, "evidence_ref", "fixture-clock-record")
        missing = cases()
        missing[0] = replace(missing[0], pod_creation=absent)
        result = self.evaluate("startup_absent_clock_mapping_field", startup=missing)
        self.assertFalse(result["fit"])
        self.assertIn("cold:missing_clock_mapping", result["reasons"])

        overlap = cases(duration=1000, pod=1000, gpu=1000)
        overlap[0] = replace(
            overlap[0],
            pod_creation=bracket(1000, 1010, mapping_uncertainty_ms=100),
            gpu_free=bracket(1000, 1010, mapping_uncertainty_ms=100),
            usable_by_gateway={
                gateway: bracket(1050, 1060, mapping_uncertainty_ms=100) for gateway in GATEWAYS
            },
        )
        result = self.evaluate("startup_order_unknown_after_mapping_widening", startup=overlap)
        self.assertFalse(result["fit"])
        self.assertIn("usable_start_order_unknown:gateway0", result["cases"][0]["reasons"])

        for origin in (0, 100):
            translated = cases(duration=261_850, pod=origin, gpu=origin)
            translated = [
                replace(
                    case,
                    pod_creation=bracket(origin, mapping_uncertainty_ms=100),
                    gpu_free=bracket(origin, mapping_uncertainty_ms=100),
                    usable_by_gateway={
                        gateway: bracket(origin + 261_850, mapping_uncertainty_ms=100)
                        for gateway in GATEWAYS
                    },
                )
                for case in translated
            ]
            result = self.evaluate(
                f"startup_translated_origin_{origin}_mapping_uncertainty", startup=translated
            )
            self.assertFalse(result["fit"])
            for case_report in result["cases"]:
                self.assertEqual(case_report["t_start_ms_bounds"], [origin - 100, origin + 100])
                for gateway_report in case_report["gateways"].values():
                    self.assertEqual(gateway_report["d_bind_plus_upper_ms"], 300_050)
                    self.assertFalse(gateway_report["fits"])

        overlap = cases(duration=50, pod=0, gpu=0)
        overlap = [
            replace(
                case,
                pod_creation=bracket(0, mapping_uncertainty_ms=0),
                gpu_free=bracket(0, mapping_uncertainty_ms=0),
                usable_by_gateway={
                    gateway: bracket(50, mapping_uncertainty_ms=100) for gateway in GATEWAYS
                },
            )
            for case in overlap
        ]
        result = self.evaluate("startup_signed_order_overlap_uncertainty", startup=overlap)
        self.assertFalse(result["fit"])
        for case_report in result["cases"]:
            self.assertEqual(case_report["t_start_ms_bounds"], [0, 0])
            self.assertEqual(case_report["gateways"], {})
            self.assertEqual(
                case_report["reasons"],
                [
                    "usable_start_order_unknown:gateway0",
                    "usable_start_order_unknown:gateway1",
                ],
            )

    def test_configured_grace_and_late_or_early_pod(self):
        larger = self.evaluate(
            "larger_configured_grace",
            allowance=components(grace=90_000),
            grace=90_000,
            startup=cases(duration=210_000, gpu=93_000),
        )
        self.assertEqual(larger["d_bind_ms"], 93_000)
        self.assertFalse(larger["fit"])
        ignored = self.evaluate("grace_cannot_assume_35_seconds", grace=90_000)
        self.assertIn("grace_does_not_match_configured_value", ignored["reasons"])
        late = self.evaluate(
            "pod_created_after_gpu_release",
            allowance=components(scheduler=3000),
            startup=cases(pod=40_000, gpu=38_000),
        )
        self.assertTrue(late["fit"])
        self.assertEqual(late["d_bind_ms"], 40_000)
        self.assertEqual(late["cases"][0]["t_start_ms_bounds"], [40_000, 40_000])
        early = self.evaluate("pending_wait_retained", startup=cases(pod=1000))
        self.assertTrue(early["fit"])
        self.assertEqual(early["d_bind_ms"], 38_000)
        self.assertEqual(early["cases"][0]["t_start_ms_bounds"], [38_000, 38_000])

    def test_component_source_bound_and_pins_are_individual(self):
        for field, value, prefix in (
            ("source", "", "unsourced_component"),
            ("bound_ms", None, "unbounded_component"),
            ("pins", {}, "unpinned_component"),
        ):
            allowance = components()
            allowance[2] = replace(allowance[2], **{field: value})
            result = self.evaluate(f"component_missing_{field}", allowance=allowance)
            self.assertFalse(result["fit"])
            self.assertIn(f"{prefix}:controller_scheduler", result["reasons"])
        allowance = components() + [Component("extra_wait", 1000, "", {})]
        self.assertFalse(
            self.evaluate("additional_component_unsourced", allowance=allowance)["fit"]
        )

    def test_both_cache_cases_and_each_gateway_are_required(self):
        startup = cases()
        self.assertFalse(self.evaluate("missing_node_cached_case", startup=startup[:1])["fit"])
        startup[1] = replace(startup[1], usable_by_gateway={"gateway0": bracket(238_000)})
        self.assertFalse(
            self.evaluate("cached_missing_gateway1_completion", startup=startup)["fit"]
        )
        startup = cases()
        startup[0] = replace(
            startup[0],
            gpu_free=replace(startup[0].gpu_free, clock_id="unrelated-source-wall-clock"),
        )
        result = self.evaluate("unrelated_source_clocks", startup=startup)
        self.assertFalse(result["fit"])
        self.assertIn("cold:unrelated_mapped_clock_timelines", result["reasons"])

    def test_missing_signal_unknown_cache_and_clock_uncertainty_fail(self):
        for label, change, reason in (
            ("missing_signal", {"signal_evidence": ""}, "missing_signal_evidence"),
            ("unknown_cache", {"image_cache": "unknown"}, "unknown_cache_state"),
            ("missing_gpu_free", {"gpu_free": None}, "missing_source_clock_bracket"),
            (
                "clock_over_100ms",
                {"pod_creation": bracket(0, mapping_uncertainty_ms=101)},
                "clock_uncertainty_exceeds_registered_bound",
            ),
        ):
            startup = cases()
            startup[0] = replace(startup[0], **change)
            result = self.evaluate(label, startup=startup)
            self.assertFalse(result["fit"])
            self.assertIn(f"cold:{reason}", result["reasons"])
        startup = cases(duration=262_000)
        startup[0] = replace(startup[0], gpu_free=bracket(38_000, 38_100))
        self.assertTrue(self.evaluate("startup_exact_300_seconds", startup=startup)["fit"])

    def test_round187_unschedulable_flush_is_not_a_usable_bound(self):
        # Synthetic observation supplied by Round187, not a verified EKS default.
        allowance = components(scheduler=300_000)
        allowance[2] = replace(
            allowance[2],
            source="REVIEW.md Round187 observation: only unschedulable-pod flush bound supplied (5min); fixture assumption",
        )
        result = self.evaluate(
            "round187_pending_deployment_flush_5min",
            allowance=allowance,
            startup=cases(pod=1000, gpu=37_000, duration=1000),
        )
        self.assertFalse(result["fit"])
        self.assertEqual(result["d_bind_ms"], 337_000)
        self.assertEqual(result["readiness_action"], "stop_readiness")
        pins = PINS | {"kubernetes_version": ""}
        result = self.evaluate("unresolved_real_kubernetes_pin", pins=pins)
        self.assertFalse(result["fit"])
        self.assertIn("unresolved_controller_configuration_or_kubernetes_pin", result["reasons"])


class AttemptTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "attempts.jsonl"
        self.controller = AttemptController(self.path)

    def allocate(self, time=0):
        return self.controller.allocate(
            time, remaining_ms=CAMPAIGN_MS + 1000, export_cleanup_ms=1000
        )

    def start(self, time=0):
        self.allocate(time)
        self.controller.setup_complete(time, preconditions=True, reasons=[])

    def end(self, time, *, valid=True, usable=True):
        self.controller.end_attempt(
            time,
            measurement_valid=valid,
            reasons=[] if valid else ["fixture_missing_signal"],
            operational_outcomes=["fixture_adverse_timeout"] if not usable else [],
            replacement_usable_by_deadline=usable,
        )

    def reset(self, time):
        self.controller.begin_reset(time, remaining_ms=CAMPAIGN_MS, export_cleanup_ms=0)

    def test_start_is_durable_before_setup_and_precondition_consumes(self):
        self.allocate()
        reopened = AttemptController(self.path)
        self.assertEqual(reopened.report()["slots"][0]["state"], "in_progress")
        self.assertEqual(reopened.events[-1]["event"], "attempt_start")
        reopened.setup_complete(1, preconditions=False, reasons=["prior_report_age_over_1s"])
        result = capture("precondition_failure_consumes_attempt", reopened.report())
        self.assertFalse(result["full_acceptance_reachable"])
        self.assertFalse(result["slots"][0]["measurement_valid"])
        self.assertEqual(result["slots"][1]["state"], "not_attempted")
        reopened.record_one_event_decision(
            2, authority="Xiaoyun", decision_ref="fixture-only-existing-DEC-reference"
        )
        self.assertTrue(reopened.report()["one_event_decision_recorded"])
        self.assertFalse(reopened.report()["one_event_label_eligible"])

    def test_three_inadequate_fourth_and_replacement_refused(self):
        for index in range(3):
            if index:
                self.reset(index * 10)
            self.start(index * 10)
            self.end(index * 10 + 1, valid=False)
        result = capture("three_inadequate_attempts", self.controller.report())
        self.assertEqual(len(result["slots"]), 3)
        self.assertFalse(result["three_valid_events"])
        with self.assertRaisesRegex(Refused, "three_total_attempt_cap") as caught:
            self.allocate(40)
        capture("fourth_attempt_refused", str(caught.exception))
        with self.assertRaisesRegex(Refused, "replacement_attempt_forbidden") as caught:
            self.controller.allocate(
                40, remaining_ms=CAMPAIGN_MS, export_cleanup_ms=0, replacement=True
            )
        capture("replacement_attempt_refused", str(caught.exception))

    def test_two_valid_is_incomplete_and_recorded_stop_rule_is_explicit(self):
        for index in range(3):
            if index:
                self.reset(index * 10)
            self.start(index * 10)
            self.end(index * 10 + 1, valid=index != 0)
        before = capture("two_valid_one_inadequate_incomplete", self.controller.report())
        self.assertFalse(before["three_valid_events"])
        self.assertFalse(before["full_acceptance_reachable"])
        self.assertFalse(before["one_event_label_eligible"])
        self.controller.record_one_event_decision(
            30, authority="Xiaoyun", decision_ref="synthetic-existing-section6.4-decision"
        )
        after = capture("recorded_section6_4_decision", self.controller.report())
        self.assertTrue(after["one_event_label_eligible"])
        self.assertFalse(after["three_valid_events"])

    def test_crash_during_reset_replays_and_torn_journal_refuses(self):
        self.start()
        self.end(1000)
        self.reset(1000)
        self.allocate(1001)
        self.controller = AttemptController(self.path)
        self.controller.setup_complete(301000, preconditions=True, reasons=[])
        result = capture("reset_reopened_at_exact_deadline", self.controller.report())
        self.assertEqual(result["slots"][1]["state"], "in_progress")
        with self.path.open("ab") as stream:
            stream.write(b'{"torn":')
        with self.assertRaisesRegex(IntegrityError, "truncated_jsonl") as caught:
            AttemptController(self.path)
        capture("torn_attempt_journal_refused", str(caught.exception))

    def test_reset_at_300_seconds_and_campaign_arithmetic(self):
        time = 0
        for index in range(3):
            if index:
                self.reset(time)
                time += RESET_MS
            self.start(time)
            time += ATTEMPT_MS
            self.end(time)
        result = capture("three_full_attempts_two_full_resets", self.controller.report())
        self.assertTrue(result["three_valid_events"])
        self.assertEqual(time, 5_280_000)
        self.assertEqual(CAMPAIGN_MS, 5_280_000)
        self.assertEqual(ATTEMPT_MS, 1_560_000)
        self.assertEqual(TTL_MS, 8000)
        self.assertEqual(
            len([r for r in result["reset_receipts"] if r["event"] == "reset_complete"]), 2
        )

    def test_reset_failure_before_allocation_vs_setup_failure(self):
        self.start()
        self.end(1000)
        self.reset(1000)
        self.controller.fail_reset(1001, "reset_preparation_failure")
        result = capture(
            "reset_failure_before_allocation",
            self.controller.close_slots(1001, "reset_preparation_failure"),
        )
        self.assertEqual(result["slots"][1]["state"], "not_attempted")
        self.assertEqual(result["slots"][1]["reason"], "reset_preparation_failure")
        _, rows = inspect_segment(self.path)
        self.assertEqual(len([r for r in rows if r["payload"]["event"] == "not_attempted"]), 2)
        self.controller = AttemptController(Path(self.tmp.name) / "second.jsonl")
        self.start()
        self.end(1000)
        self.reset(1000)
        self.allocate(1001)
        self.controller.setup_complete(
            1002, preconditions=False, reasons=["setup_fresh_report_missing"]
        )
        result = capture("setup_failure_after_allocation", self.controller.report())
        self.assertFalse(result["slots"][1]["measurement_valid"])
        self.assertEqual(result["slots"][2]["reason"], "reset_setup_failure")

    def test_reset_expiry_before_and_after_allocation(self):
        self.start()
        self.end(1000)
        self.reset(1000)
        with self.assertRaisesRegex(Refused, "reset_expired"):
            self.allocate(301001)
        result = capture("reset_expiry_before_allocation", self.controller.report())
        self.assertEqual(result["slots"][1]["state"], "not_attempted")
        self.controller = AttemptController(Path(self.tmp.name) / "after.jsonl")
        self.start()
        self.end(1000)
        self.reset(1000)
        self.allocate(1001)
        with self.assertRaisesRegex(Refused, "reset_expired") as caught:
            self.controller.setup_complete(301001, preconditions=True, reasons=[])
        capture("setup_complete_expiry_refused", str(caught.exception))
        result = capture("reset_expiry_after_allocation", self.controller.report())
        self.assertFalse(result["slots"][1]["measurement_valid"])
        self.assertEqual(result["slots"][2]["reason"], "reset_expired")
        self.assertEqual(AttemptController(self.path.with_name("after.jsonl")).report(), result)
        self.assertFalse(
            any(
                e["event"] in ("reset_complete", "traffic_start") and e["now_ms"] > 1000
                for e in self.controller.events
            )
        )
        with self.assertRaisesRegex(Refused, "campaign_stopped"):
            self.allocate(301002)

    def test_end_during_reset_setup_stops_and_survives_reopen(self):
        self.start()
        self.end(1000)
        self.reset(1000)
        self.assertEqual(self.allocate(1001), 2)
        self.end(1002, valid=False)
        result = capture("end_attempt_during_reset_setup", self.controller.report())
        self.assertFalse(result["slots"][1]["measurement_valid"])
        self.assertEqual(result["slots"][2]["state"], "not_attempted")
        self.assertEqual(result["slots"][2]["reason"], "reset_setup_failure")
        self.assertEqual(
            [e["event"] for e in self.controller.events][-4:],
            ["attempt_end", "reset_failed", "campaign_stop", "not_attempted"],
        )
        self.controller = AttemptController(self.path)
        self.assertEqual(self.controller.report(), result)
        with self.assertRaisesRegex(Refused, "campaign_stopped") as caught:
            self.allocate(1003)
        capture("reset_setup_end_further_allocation_refused", str(caught.exception))
        with self.assertRaisesRegex(Refused, "durable_attempt_start_required"):
            self.controller.setup_complete(1003, preconditions=True, reasons=[])

    def test_reset_cannot_allocate_twice_when_replaying_old_open_reset(self):
        self.start()
        self.end(1000)
        self.reset(1000)
        self.allocate(1001)
        # Replay a journal made by the old end_attempt bypass, before R226.
        self.controller._write(
            "attempt_end",
            1002,
            attempt=2,
            measurement_valid=False,
            reasons=["interrupted_setup"],
            operational_outcomes=[],
            replacement_usable_by_deadline=None,
        )
        self.controller = AttemptController(self.path)
        with self.assertRaisesRegex(Refused, "campaign_stopped") as caught:
            self.allocate(1003)
        capture("old_reset_interrupted_setup_refused", str(caught.exception))
        self.assertEqual(self.controller.report()["slots"][2]["state"], "not_attempted")
        self.assertEqual(
            self.controller.report()["slots"][2]["reason"],
            "reset_setup_failure",
        )

    def test_never_usable_later_ready_does_not_reopen_remaining_slots(self):
        self.start()
        self.end(300_000, usable=False)
        result = capture(
            "never_usable_valid_adverse",
            self.controller.close_slots(300_000, "previous_replacement_never_usable"),
        )
        self.assertTrue(result["slots"][0]["measurement_valid"])
        self.assertEqual(result["slots"][1]["reason"], "previous_replacement_never_usable")
        reopened = AttemptController(self.path)
        with self.assertRaisesRegex(Refused, "campaign_stopped"):
            reopened.begin_reset(300001, remaining_ms=CAMPAIGN_MS, export_cleanup_ms=0)
        with self.assertRaisesRegex(Refused, "campaign_stopped"):
            reopened.allocate(300001, remaining_ms=CAMPAIGN_MS, export_cleanup_ms=0)
        capture("late_ready_still_stopped", reopened.report())

    def test_interrupted_stop_transitions_recover_at_every_journal_row(self):
        scenarios = (
            ("fail_reset", "reset_failure"),
            ("end_attempt_reset_failure", "end_attempt"),
            ("setup_complete_failed_preconditions", "setup_failure"),
            ("never_usable_stop", "never_usable"),
            ("setup_complete_successful_reset", "setup_success"),
        )
        fixture = {}
        for name, kind in scenarios:
            full_path = self.path.with_name(f"r231-{name}-full.jsonl")
            full = AttemptController(full_path)
            if kind == "never_usable":
                full.allocate(0, remaining_ms=CAMPAIGN_MS, export_cleanup_ms=0)
                full.setup_complete(0, preconditions=True, reasons=[])
                transition_start = len(full.rows)
                full.end_attempt(
                    300_000,
                    measurement_valid=True,
                    reasons=[],
                    operational_outcomes=[],
                    replacement_usable_by_deadline=False,
                )
            elif kind == "setup_success":
                full.allocate(0, remaining_ms=CAMPAIGN_MS, export_cleanup_ms=0)
                full.setup_complete(0, preconditions=True, reasons=[])
                full.end_attempt(
                    1000,
                    measurement_valid=True,
                    reasons=[],
                    operational_outcomes=[],
                    replacement_usable_by_deadline=True,
                )
                full.begin_reset(1000, remaining_ms=CAMPAIGN_MS, export_cleanup_ms=0)
                full.allocate(1001, remaining_ms=CAMPAIGN_MS, export_cleanup_ms=0)
                transition_start = len(full.rows)
                full.setup_complete(1002, preconditions=True, reasons=[])
            else:
                full.allocate(0, remaining_ms=CAMPAIGN_MS, export_cleanup_ms=0)
                full.setup_complete(0, preconditions=True, reasons=[])
                full.end_attempt(
                    1000,
                    measurement_valid=True,
                    reasons=[],
                    operational_outcomes=[],
                    replacement_usable_by_deadline=True,
                )
                full.begin_reset(1000, remaining_ms=CAMPAIGN_MS, export_cleanup_ms=0)
                full.allocate(1001, remaining_ms=CAMPAIGN_MS, export_cleanup_ms=0)
                transition_start = len(full.rows)
                if kind == "reset_failure":
                    full.fail_reset(1002, "reset_expired")
                elif kind == "end_attempt":
                    full.end_attempt(
                        1002,
                        measurement_valid=False,
                        reasons=["setup_aborted"],
                        operational_outcomes=["deletion_not_issued"],
                        replacement_usable_by_deadline=None,
                    )
                else:
                    full.setup_complete(
                        1002,
                        preconditions=False,
                        reasons=["setup_precondition_failed"],
                    )

            expected_report = full.report()
            full_lines = full_path.read_bytes().splitlines(keepends=True)
            transition_lines = full_lines[transition_start:]
            cuts = []
            for cut_after in range(1, len(transition_lines) + 1):
                prefix = b"".join(full_lines[:transition_start] + transition_lines[:cut_after])
                recovered_path = self.path.with_name(f"r231-{name}-cut-{cut_after}.jsonl")
                recovered_path.write_bytes(prefix)
                recovered = AttemptController(recovered_path)
                self.assertEqual(recovered.report(), expected_report, (name, cut_after))
                self.assertEqual(recovered._stop_reason(), full._stop_reason())
                current_attempt = recovered._open_attempt()
                recovered_state = {
                    "traffic_attempts": [
                        event["attempt"] for event in recovered._of("traffic_start")
                    ],
                    "open_attempt": current_attempt["attempt"] if current_attempt else None,
                    "reset_open": recovered._open_reset() is not None,
                }
                current_full = full._open_attempt()
                full_state = {
                    "traffic_attempts": [event["attempt"] for event in full._of("traffic_start")],
                    "open_attempt": current_full["attempt"] if current_full else None,
                    "reset_open": full._open_reset() is not None,
                }
                if kind == "setup_success" and cut_after < 3:
                    full_state = {
                        "traffic_attempts": [1],
                        "open_attempt": 2,
                        "reset_open": False,
                    }
                self.assertEqual(recovered_state, full_state, (name, cut_after))
                if kind == "setup_success" and cut_after < 3:
                    self.assertNotIn(
                        "reset_setup_failure",
                        [event["reason"] for event in recovered._of("campaign_stop")],
                    )

                probes = (
                    (
                        "start_traffic",
                        lambda controller: controller.setup_complete(
                            2000, preconditions=True, reasons=[]
                        ),
                    ),
                    (
                        "open_reset",
                        lambda controller: controller.begin_reset(
                            2000, remaining_ms=CAMPAIGN_MS, export_cleanup_ms=0
                        ),
                    ),
                    (
                        "allocate",
                        lambda controller: controller.allocate(
                            2000, remaining_ms=CAMPAIGN_MS, export_cleanup_ms=0
                        ),
                    ),
                )
                refusals = {}
                for probe_name, probe in probes:
                    probe_path = self.path.with_name(
                        f"r231-{name}-cut-{cut_after}-{probe_name}.jsonl"
                    )
                    probe_path.write_bytes(prefix)
                    reopened = AttemptController(probe_path)
                    before = len(reopened.events)
                    with self.assertRaises(Refused) as caught:
                        probe(reopened)
                    self.assertEqual(len(reopened.events), before, (name, cut_after, probe_name))
                    refusals[probe_name] = str(caught.exception)
                cuts.append(
                    {
                        "cut_after_transition_row": cut_after,
                        "transition_rows": [
                            json.loads(line)["payload"]["event"] for line in transition_lines
                        ],
                        "report_matches_uncut": True,
                        "recovered_journal_state": recovered_state,
                        "refusals": refusals,
                    }
                )
            fixture[name] = cuts

        post_recovery = []
        recovered_journals = []
        for cut_after in (1, 2):
            path = self.path.with_name(
                f"r231-setup_complete_successful_reset-cut-{cut_after}.jsonl"
            )
            reopened = AttemptController(path)
            self.assertEqual(reopened.report(), full.report())
            current = reopened._open_attempt()
            self.assertIsNotNone(current)
            traffic_attempts = [event["attempt"] for event in reopened._of("traffic_start")]
            self.assertNotIn(current["attempt"], traffic_attempts)
            self.assertIsNone(reopened._open_reset())

            refusals = {}
            for name, probe in (
                (
                    "setup_complete",
                    lambda c: c.setup_complete(1003, preconditions=True, reasons=[]),
                ),
                (
                    "begin_reset",
                    lambda c: c.begin_reset(1003, remaining_ms=CAMPAIGN_MS, export_cleanup_ms=0),
                ),
                (
                    "allocate",
                    lambda c: c.allocate(1003, remaining_ms=CAMPAIGN_MS, export_cleanup_ms=0),
                ),
            ):
                with self.assertRaises(Refused) as caught:
                    probe(reopened)
                refusals[name] = str(caught.exception)

            reopened.end_attempt(
                1003,
                measurement_valid=False,
                reasons=["controller_interrupted_before_traffic"],
                operational_outcomes=["traffic_not_started"],
                replacement_usable_by_deadline=None,
            )
            self.assertEqual(
                reopened.report()["slots"][1]["reasons"],
                ["controller_interrupted_before_traffic"],
            )
            self.assertNotEqual(reopened.report()["slots"][1]["reasons"], ["reset_setup_failure"])
            reopened.begin_reset(1003, remaining_ms=CAMPAIGN_MS, export_cleanup_ms=0)
            allocated = reopened.allocate(1004, remaining_ms=CAMPAIGN_MS, export_cleanup_ms=0)
            self.assertEqual(allocated, 3)
            post_recovery.append(
                {
                    "report_before_operator_end": full.report(),
                    "journal_state_before_operator_end": {
                        "traffic_attempts": traffic_attempts,
                        "open_attempt": current["attempt"],
                        "reset_open": False,
                    },
                    "refusals": refusals,
                    "operator_end_reason": reopened.report()["slots"][1]["reasons"],
                    "next_allocation": allocated,
                    "report_after_allocation": reopened.report(),
                }
            )
            recovered_journals.append(path.read_bytes())
        self.assertEqual(post_recovery[0], post_recovery[1])
        self.assertEqual(recovered_journals[0], recovered_journals[1])
        fixture["setup_success_crash_points_converge"] = post_recovery

        capture("interrupted_stop_transition_recovery", fixture)
        self.assertEqual(len(fixture["fail_reset"]), 4)
        self.assertEqual(len(fixture["end_attempt_reset_failure"]), 4)
        self.assertEqual(len(fixture["setup_complete_failed_preconditions"]), 5)
        self.assertEqual(len(fixture["never_usable_stop"]), 4)
        self.assertEqual(len(fixture["setup_complete_successful_reset"]), 3)
        self.assertTrue(
            all(
                all(
                    cut["report_matches_uncut"]
                    and set(cut["refusals"]) == {"start_traffic", "open_reset", "allocate"}
                    for cut in cuts
                )
                for name, cuts in fixture.items()
                if name != "setup_success_crash_points_converge"
            )
        )

    def test_remaining_absolute_time_and_monotonic_fail_closed(self):
        with self.assertRaisesRegex(Refused, "insufficient_remaining_absolute_time"):
            self.controller.allocate(0, remaining_ms=ATTEMPT_MS + 9, export_cleanup_ms=10)
        capture("insufficient_time_first_attempt", self.controller.report())
        self.controller = AttemptController(Path(self.tmp.name) / "other.jsonl")
        self.start()
        self.end(1000)
        with self.assertRaisesRegex(Refused, "insufficient_remaining_absolute_time"):
            self.controller.begin_reset(
                1000, remaining_ms=RESET_MS + ATTEMPT_MS + 9, export_cleanup_ms=10
            )
        capture("insufficient_time_reset", self.controller.report())
        with self.assertRaisesRegex(Refused, "monotonic_clock_regressed"):
            self.controller.record_one_event_decision(
                999, authority="Xiaoyun", decision_ref="fixture-ref"
            )


if __name__ == "__main__":
    unittest.main()
