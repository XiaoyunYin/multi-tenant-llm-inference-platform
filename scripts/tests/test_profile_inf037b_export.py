"""Controls for R366 sampling and non-invasive phase instrumentation."""

import importlib.util
from contextlib import ExitStack, contextmanager
import os
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "profile_export", REPO / "scripts/profile_inf037b_export.py"
)
profile = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(profile)
SUMMARY_SPEC = importlib.util.spec_from_file_location(
    "summarize_export", REPO / "scripts/summarize_inf037b_export_profile.py"
)
summary = importlib.util.module_from_spec(SUMMARY_SPEC)
SUMMARY_SPEC.loader.exec_module(summary)

import test_inf037b_collectors as fixtures  # noqa: E402


@contextmanager
def legacy_candidate_operations(candidate):
    # The archived experiment replaces per-write fsync globally. Exercise its
    # original unbatched seams, rather than nesting it over production batches
    # (whose directory descriptors that experiment never intercepted before).
    with ExitStack() as stack:
        for owner, name in (
            (profile.packet, "sanitized_sources"),
            (profile.campaign, "materialize_bundle"),
        ):
            function = getattr(owner, name)
            stack.enter_context(
                patch.object(owner, name, getattr(function, "__wrapped__", function))
            )
        with candidate.candidate_operations():
            yield


class ExportProfileTests(unittest.TestCase):
    def test_capture_inventory_phase_names_are_comparable_across_sample_sizes(self):
        samples = []
        for fraction in (5, 10, 25):
            samples.append(
                {
                    "raw_rows": fraction,
                    "calls": [
                        {
                            "phase": "capture_export",
                            "parent": None,
                            "seconds": fraction + 2,
                            "cpu_seconds": fraction + 1,
                        },
                        {
                            "phase": "sanitized_campaign",
                            "parent": "capture_export",
                            "seconds": fraction,
                            "cpu_seconds": fraction,
                        },
                        {
                            "phase": f"capture_inventory_raw-{fraction}",
                            "parent": "capture_export",
                            "seconds": 1,
                            "cpu_seconds": 0.5,
                        },
                    ],
                }
            )
        result = summary.summarize({"full_rows": 100, "samples": samples})
        self.assertEqual(
            result["phases"]["capture_inventory_source"]["sample_seconds"], [1, 1, 1]
        )
        self.assertAlmostEqual(
            result["phases"]["capture_export"]["affine_full_seconds"], 102
        )
        self.assertAlmostEqual(
            result["phases"]["capture_export"]["affine_full_cpu_seconds"], 101
        )

    def test_block_sample_bounds_artificial_gaps_independently_of_row_count(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            full = work / "full"
            (full / "raw").mkdir(parents=True)
            for name in ("registration.json", "attempts.jsonl"):
                (full / name).write_bytes(b"unchanged")
            (full / "raw/client.jsonl").write_bytes(
                b"".join(f"{i}\n".encode() for i in range(10_000))
            )
            counts = profile.sample_fixture(full, work / "sample", 5)
            rows = [
                int(line)
                for line in (work / "sample/raw/client.jsonl").read_bytes().splitlines()
            ]
            self.assertEqual(len(rows), 500)
            self.assertEqual(counts["client.jsonl"]["blocks"], 10)
            self.assertEqual(sum(b != a + 1 for a, b in zip(rows, rows[1:])), 9)

    def test_affine_extrapolation_retains_fixed_work(self):
        model = summary.fit([5, 10, 25], [12, 22, 52])
        self.assertAlmostEqual(model["intercept_seconds"], 2)
        self.assertAlmostEqual(model["seconds_per_row"], 2)
        self.assertAlmostEqual(model["r_squared"], 1)

    def test_comparison_residual_does_not_double_count_nested_reports(self):
        def call(phase, parent, seconds):
            return {"phase": phase, "parent": parent, "seconds": seconds}

        result = summary.phases(
            {
                "calls": [
                    call("sanitized_campaign", "capture_export", 100),
                    call("raw_reproduce_spec_1", "sanitized_campaign", 20),
                    call("raw_report_spec_1", "raw_reproduce_spec_1", 10),
                    call("raw_report_spec_1", "sanitized_campaign", 10),
                    call("sanitized_report_spec_1", "sanitized_campaign", 8),
                    call("sanitized_sources", "sanitized_campaign", 30),
                    call("materialize_bundle", "sanitized_campaign", 15),
                    call("sanitized_reproduce_spec_1", "sanitized_campaign", 10),
                    call("capture_export", None, 120),
                ]
            }
        )
        self.assertEqual(result["report_comparison_and_mapping"], 15)
        self.assertEqual(result["raw_report_spec_1"], 10)
        self.assertNotIn("sanitized_report_spec_1", result)

    def test_instrumentation_preserves_accepted_export_bytes_and_restores_functions(
        self,
    ):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            raw = work / "raw"
            fixture, _ = fixtures.CampaignTests.campaign(
                SimpleNamespace(root=work), name="raw"
            )
            specs = [fixture.spec]
            profile.campaign.materialize_bundle(raw, specs)
            original = profile.campaign.reproduce
            direct = work / "direct"
            profile.campaign.sanitized_campaign(
                raw, direct, specs, key=b"control-key" * 4
            )
            timed = work / "timed"
            timings = profile.Timings()
            with timings.instrument(raw), timings.span("capture_export"):

                def sanitize(source, destination):
                    with timings.span("sanitized_campaign"):
                        return profile.campaign.sanitized_campaign(
                            source, destination, specs, key=b"control-key" * 4
                        )

                captured, _ = profile.observations.capture_export(
                    binding={},
                    source=raw,
                    sanitized=timed,
                    destination=work / "destination",
                    sanitize=sanitize,
                    sample=lambda: {},
                    reconnect_ms=1_000,
                )
            self.assertIs(profile.campaign.reproduce, original)
            self.assertEqual(
                (direct / "SHA256SUMS").read_bytes(),
                (timed / "SHA256SUMS").read_bytes(),
            )
            self.assertTrue(captured)
            phases = {call["phase"] for call in timings.calls}
            self.assertTrue(
                {
                    "raw_reproduce_spec_1",
                    "raw_report_spec_1",
                    "sanitized_report_spec_1",
                    "sanitized_sources",
                    "materialize_bundle",
                    "sanitized_reproduce_spec_1",
                    "capture_verify_source",
                    "capture_verify_sanitized",
                    "transfer_interrupted",
                    "transfer_resume_and_verify_readback",
                }
                <= phases
            )

    # Candidate controls use Linux procfs; native Windows discovery omits them.
    if os.name == "posix":

        def test_candidate_preserves_bytes_and_invalidates_both_caches_on_changed_input(
            self,
        ):
            import profile_inf037b_export_candidate as candidate

            with tempfile.TemporaryDirectory() as directory:
                work = Path(directory)
                fixture, _ = fixtures.CampaignTests.campaign(
                    SimpleNamespace(root=work), name="raw"
                )
                raw, specs = fixture.root, [fixture.spec]
                profile.campaign.materialize_bundle(raw, specs)
                direct = work / "direct"
                profile.campaign.sanitized_campaign(
                    raw, direct, specs, key=b"candidate-control-key" * 2
                )
                with legacy_candidate_operations(candidate):
                    safe = work / "candidate"
                    profile.observations.capture_export(
                        binding={},
                        source=raw,
                        sanitized=safe,
                        destination=work / "destination",
                        sanitize=lambda source, target: (
                            profile.campaign.sanitized_campaign(
                                source, target, specs, key=b"candidate-control-key" * 2
                            )
                        ),
                        sample=lambda: {},
                        reconnect_ms=1_000,
                    )
                    self.assertEqual(
                        (direct / "SHA256SUMS").read_bytes(),
                        (safe / "SHA256SUMS").read_bytes(),
                    )
                    candidate.archive.verify_archive(raw)
                    profile.campaign.OfflineCampaign(raw, specs[0]).report()
                    source = raw / "raw/client.jsonl"
                    source.write_bytes(b"corrupted\n")
                    with self.assertRaises(profile.campaign.IntegrityError):
                        candidate.archive.verify_archive(raw)
                    with self.assertRaises(profile.campaign.IntegrityError):
                        profile.campaign.OfflineCampaign(raw, specs[0]).report()

        def test_candidate_batch_propagates_file_and_directory_sync_failure(self):
            import profile_inf037b_export_candidate as candidate

            real_sync = os.fsync
            for target in ("file", "directory"):
                with (
                    self.subTest(target=target),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    path = Path(directory) / "evidence"

                    def sync(fd):
                        kind = (
                            "directory"
                            if stat.S_ISDIR(os.fstat(fd).st_mode)
                            else "file"
                        )
                        if kind == target:
                            raise OSError("injected " + target + " fsync failure")
                        real_sync(fd)

                    with patch.object(candidate.os, "fsync", sync):
                        operation = candidate.batch(
                            lambda: candidate.archive.durable_write(path, b"evidence")
                        )
                        with self.assertRaisesRegex(OSError, "injected " + target):
                            operation()

    def test_stratified_sample_is_repeatable_and_preserves_journal_and_registered_inputs(
        self,
    ):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            full = work / "full"
            (full / "raw").mkdir(parents=True)
            (full / "registration.json").write_bytes(b"registered inputs")
            (full / "attempts.jsonl").write_bytes(b"journal")
            for name, count in (("a", 41), ("b", 100)):
                (full / "raw" / f"{name}.jsonl").write_bytes(
                    b"".join(f"{i}\n".encode() for i in range(count))
                )
            first, second = work / "first", work / "second"
            counts = profile.sample_fixture(full, first, 25)
            self.assertEqual(counts, profile.sample_fixture(full, second, 25))
            self.assertEqual([c["sample"] for c in counts.values()], [10, 25])
            for path in first.rglob("*"):
                if path.is_file():
                    self.assertEqual(
                        path.read_bytes(),
                        (second / path.relative_to(first)).read_bytes(),
                    )
            self.assertEqual(
                (full / "registration.json").read_bytes(),
                (first / "registration.json").read_bytes(),
            )
            self.assertEqual(
                (full / "attempts.jsonl").read_bytes(),
                (first / "attempts.jsonl").read_bytes(),
            )

    def test_instrumentation_restores_functions_after_failure(self):
        original = profile.campaign.reproduce
        with self.assertRaisesRegex(RuntimeError, "injected"):
            with profile.Timings().instrument(Path("raw")):
                raise RuntimeError("injected")
        self.assertIs(profile.campaign.reproduce, original)


if __name__ == "__main__":
    unittest.main()
