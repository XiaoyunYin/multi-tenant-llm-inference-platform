"""Source-binding, container-manifest, and feasibility controls for sizing."""

import importlib.util
import contextlib
import io
import json
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = ROOT / "scripts" / "size_inf037b_sanitized_export.py"
SPEC = importlib.util.spec_from_file_location(
    "size_inf037b_sanitized_export", SCRIPT_PATH
)
SIZING = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SIZING)


class SizingProvenanceTest(unittest.TestCase):
    def test_r303_records_events_and_sampled_anon_peak_headroom(self):
        if not hasattr(SIZING, "CgroupAnonSampler"):
            self.fail("producer does not sample cgroup memory.stat anon")
        root, limits = self.fake_cgroup()
        (root / "memory.peak").write_text("9999", encoding="ascii")
        with SIZING.CgroupAnonSampler(root, True) as sampler:
            self.assertEqual(sampler.peak, 4000)
            (root / "memory.stat").write_text(
                "anon 7000\nfile 99999\n", encoding="ascii"
            )
            sampler.sample()
            (root / "memory.stat").write_text(
                "anon 1000\nfile 99999\n", encoding="ascii"
            )
            peak = sampler.finish()
        observed = SIZING.final_container_cgroup(
            {"constrained_host": self.constrained_host(), "container_cgroup": limits},
            root,
            anon_peak=peak,
        )
        self.assertEqual(
            observed["memory.events"],
            {"low": 1, "high": 2, "max": 3, "oom": 0, "oom_kill": 0},
        )
        self.assertEqual(observed["memory.stat.anon_peak_sampled_bytes"], 7000)
        self.assertEqual(observed["anon_headroom_bytes"], 256 * 1024**2 - 7000)
        self.assertGreaterEqual(sampler.samples, 3)

    def test_r303_oom_kill_refuses_receipt(self):
        root, limits = self.fake_cgroup()
        (root / "memory.peak").write_text("9999", encoding="ascii")
        (root / "memory.events").write_text(
            "low 0\nhigh 0\nmax 5\noom 1\noom_kill 1\n", encoding="ascii"
        )
        with self.assertRaisesRegex(SIZING.SourceBindingError, "oom_kill"):
            SIZING.final_container_cgroup(
                {
                    "constrained_host": self.constrained_host(),
                    "container_cgroup": limits,
                },
                root,
            )

    def test_r303_finalizer_rejects_oom_kill_and_missing_evidence(self):
        (self.repo / ".git/info/exclude").write_text(
            "manifest.json\nraw.json\nfinal.json\nfake-cgroup/\n", encoding="utf-8"
        )
        manifest = SIZING.source_manifest(
            self.repo, self.temp_sources("fixture_used"), self.constrained_host()
        )
        manifest_path = self.repo / "manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        receipt, _ = self.matching_raw_receipt(manifest)
        raw = self.repo / "raw.json"
        raw.write_text(json.dumps(receipt), encoding="utf-8")
        SIZING.finalize_container_receipt(
            self.repo, manifest_path, raw, self.repo / "final.json"
        )
        for variant in ("killed", "missing_events", "missing_anon", "wrong_headroom"):
            import copy

            value = copy.deepcopy(receipt)
            group = value["container_cgroup"]
            if variant == "killed":
                group["memory.events"]["oom_kill"] = 1
            elif variant == "missing_events":
                del group["memory.events"]
            elif variant == "missing_anon":
                del group["memory.stat.anon_peak_sampled_bytes"]
            else:
                group["anon_headroom_bytes"] += 1
            raw = self.repo / "raw.json"
            raw.write_text(json.dumps(value), encoding="utf-8")
            with (
                self.subTest(variant=variant),
                self.assertRaisesRegex(
                    SIZING.SourceBindingError,
                    "oom_kill|memory.events|anon_peak|headroom",
                ),
            ):
                SIZING.finalize_container_receipt(
                    self.repo, manifest_path, raw, self.repo / "final.json"
                )

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        for relative_path in (
            *SIZING.PINNED_HARNESS_FILES,
            "python/src/inference_platform/__init__.py",
            "python/src/inference_platform/used.py",
            "python/tests/fixture_used.py",
            "python/tests/other_used.py",
        ):
            path = self.repo / relative_path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(f"# {relative_path}\n".encode("utf-8"))
        self.git("init", "-q")
        self.git("config", "user.name", "Sizing test")
        self.git("config", "user.email", "sizing-test@example.invalid")
        self.git("add", "--all")
        self.git("commit", "-q", "-m", "test source baseline")

    def git(self, *args):
        return (
            subprocess.run(
                ["git", "-C", str(self.repo), *args],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            .stdout.decode("utf-8")
            .strip()
        )

    def temp_sources(self, *names):
        return {name: self.repo / "python" / "tests" / f"{name}.py" for name in names}

    @staticmethod
    def constrained_host():
        return {
            "memory_limit_bytes": 256 * 1024**2,
            "memory_swap_total_bytes": 256 * 1024**2,
            "docker_cpus": 1.0,
            "docker_pids": 64,
            "host_total_ram_bytes": 8 * 1024**3,
            "docker_vm_mem_total_bytes": 8 * 1024**3,
            "available_sampled_at_utc": "2026-10-18T12:00:00+00:00",
        }

    def fake_cgroup(self, **overrides):
        values = {
            "memory.max": str(256 * 1024**2),
            "memory.swap.max": "0",
            "pids.max": "64",
            "cpu.max": "100000 100000",
        }
        values.update(overrides)
        root = self.repo / "fake-cgroup"
        root.mkdir()
        for filename, value in values.items():
            (root / filename).write_text(value, encoding="ascii")
        (root / "memory.events").write_text(
            "low 1\nhigh 2\nmax 3\noom 0\noom_kill 0\n", encoding="ascii"
        )
        (root / "memory.stat").write_text("anon 4000\nfile 9000\n", encoding="ascii")
        return root, values

    def matching_raw_receipt(self, manifest, *, start_offset_seconds=12):
        cgroup_root, expected = self.fake_cgroup()
        (cgroup_root / "memory.peak").write_text("12345", encoding="ascii")
        sample_time = datetime(2026, 10, 18, 12, 0, tzinfo=timezone.utc)
        start_time = sample_time + timedelta(seconds=start_offset_seconds)
        receipt = {
            "source_commit": manifest["source_commit"],
            "source_manifest_sha256": manifest["manifest_sha256"],
            "container_started_at_utc": start_time.isoformat(),
            "container_cgroup": {
                **expected,
                "memory.peak": "12345",
                "memory.events": {
                    "low": 1,
                    "high": 2,
                    "max": 3,
                    "oom": 0,
                    "oom_kill": 0,
                },
                "memory.stat.anon_peak_sampled_bytes": 4000,
                "anon_headroom_bytes": 256 * 1024**2 - 4000,
            },
        }
        return receipt, sample_time.isoformat()

    def test_dirty_non_inference_platform_module_refuses(self):
        module_file = self.repo / "python/tests/fixture_used.py"
        module_file.write_bytes(b"# changed after commit\n")

        with self.assertRaisesRegex(
            SIZING.SourceBindingError,
            r"git status --porcelain.*python/tests/fixture_used.py",
        ):
            SIZING.source_manifest(self.repo, self.temp_sources("fixture_used"))

    def test_import_guard_rejects_dirty_non_inference_module(self):
        module_file = self.repo / "python/tests/fixture_used.py"
        module_file.write_bytes(b"# changed after commit\n")
        finder = SIZING.HeadBoundImportFinder(self.repo, SIZING.head_commit(self.repo))

        with self.assertRaisesRegex(
            SIZING.SourceBindingError,
            r"git status --porcelain.*python/tests/fixture_used.py",
        ):
            finder.find_spec("fixture_used", [str(module_file.parent)])

    def test_recorded_source_commit_is_current_head(self):
        imported = {
            "inference_platform": self.repo
            / "python/src/inference_platform/__init__.py",
            "inference_platform.used": self.repo
            / "python/src/inference_platform/used.py",
        }
        manifest = SIZING.source_manifest(self.repo, imported)

        self.assertEqual(manifest["source_commit"], self.git("rev-parse", "HEAD"))
        self.assertEqual(
            set(manifest["file_sha256"]),
            {
                *SIZING.PINNED_HARNESS_FILES,
                "python/src/inference_platform/__init__.py",
                "python/src/inference_platform/used.py",
            },
        )
        self.assertEqual(
            manifest["modules"],
            {
                "inference_platform": "python/src/inference_platform/__init__.py",
                "inference_platform.used": "python/src/inference_platform/used.py",
            },
        )
        self.assertEqual(len(manifest["manifest_sha256"]), 64)

    def test_real_head_manifest_includes_collector_fixture_module(self):
        SIZING.import_sizing_modules(ROOT)
        fixture_module = sys.modules["test_inf037b_collectors"]
        sources = {
            "__main__": SCRIPT_PATH,
            "time_inf037b_three_attempts": Path(
                sys.modules["time_inf037b_three_attempts"].__file__
            ),
            "test_inf037b_collectors": Path(fixture_module.__file__),
        }
        sources.update(
            {
                name: source
                for name, source in SIZING.imported_repo_sources(ROOT).items()
                if name == "inference_platform"
                or name.startswith("inference_platform.")
            }
        )

        manifest = SIZING.source_manifest(ROOT, sources)

        self.assertEqual(manifest["source_commit"], SIZING.head_commit(ROOT))
        self.assertEqual(
            manifest["modules"]["test_inf037b_collectors"],
            "python/tests/test_inf037b_collectors.py",
        )
        self.assertIn(
            "python/tests/test_inf037b_collectors.py", manifest["file_sha256"]
        )

    def test_container_refuses_bytes_changed_after_manifest(self):
        source = self.temp_sources("fixture_used")
        manifest = SIZING.source_manifest(self.repo, source)
        source["fixture_used"].write_bytes(b"# changed after host manifest\n")

        with self.assertRaisesRegex(
            SIZING.SourceBindingError, "bytes differ from source manifest"
        ):
            SIZING.verify_container_sources(self.repo, manifest, source)

    def test_container_refuses_manifest_omitting_loaded_module(self):
        manifest = SIZING.source_manifest(self.repo, self.temp_sources("fixture_used"))

        with self.assertRaisesRegex(
            SIZING.SourceBindingError,
            "repo module is missing from source manifest: other_used",
        ):
            SIZING.verify_container_sources(
                self.repo,
                manifest,
                self.temp_sources("fixture_used", "other_used"),
            )

    def test_infeasible_limit_prevents_docker_runner(self):
        calls = []

        result = SIZING.run_if_feasible(
            5 * 1024**3,
            16 * 1024**3,
            4 * 1024**3,
            lambda: calls.append("docker run"),
        )

        self.assertEqual(result["status"], "infeasible_on_host")
        self.assertEqual(result["exceeded_limits"], ["docker_vm_mem_total"])
        self.assertEqual(calls, [])

    def test_constrained_host_record_includes_all_docker_limits(self):
        with (
            mock.patch.object(
                SIZING, "physical_memory_bytes", return_value=8 * 1024**3
            ),
            mock.patch.object(
                SIZING, "docker_vm_mem_total_bytes", return_value=8 * 1024**3
            ),
            mock.patch.object(
                SIZING, "available_memory_bytes", return_value=3_000 * 1024**2
            ),
            mock.patch.object(
                SIZING,
                "utc_now_iso",
                return_value="2026-10-18T12:00:00+00:00",
            ),
        ):
            record = SIZING.constrained_host_record(
                256 * 1024**2, 256 * 1024**2, 1.0, 64
            )

        self.assertEqual(record["memory_limit_bytes"], 256 * 1024**2)
        self.assertEqual(record["memory_swap_total_bytes"], 256 * 1024**2)
        self.assertEqual(record["docker_cpus"], 1.0)
        self.assertEqual(record["docker_pids"], 64)
        self.assertEqual(
            record["available_sampled_at_utc"], "2026-10-18T12:00:00+00:00"
        )

    def test_container_cgroup_limits_match_constrained_manifest(self):
        cgroup_root, expected = self.fake_cgroup()

        observed = SIZING.verify_container_cgroup(
            {"constrained_host": self.constrained_host()}, cgroup_root
        )

        self.assertEqual(observed, expected)

    def test_container_refuses_memory_limit_mismatch(self):
        cgroup_root, _ = self.fake_cgroup(**{"memory.max": str(256 * 1024**2 + 1)})

        with self.assertRaisesRegex(SIZING.SourceBindingError, "memory.max"):
            SIZING.verify_container_cgroup(
                {"constrained_host": self.constrained_host()}, cgroup_root
            )

    def test_container_refuses_swap_limit_mismatch(self):
        cgroup_root, _ = self.fake_cgroup(**{"memory.swap.max": "1"})

        with self.assertRaisesRegex(SIZING.SourceBindingError, "memory.swap.max"):
            SIZING.verify_container_cgroup(
                {"constrained_host": self.constrained_host()}, cgroup_root
            )

    def test_container_refuses_pids_limit_mismatch(self):
        cgroup_root, _ = self.fake_cgroup(**{"pids.max": "65"})

        with self.assertRaisesRegex(SIZING.SourceBindingError, "pids.max"):
            SIZING.verify_container_cgroup(
                {"constrained_host": self.constrained_host()}, cgroup_root
            )

    def test_container_refuses_cpu_limit_mismatch(self):
        cgroup_root, _ = self.fake_cgroup(**{"cpu.max": "100001 100000"})

        with self.assertRaisesRegex(SIZING.SourceBindingError, "cpu.max"):
            SIZING.verify_container_cgroup(
                {"constrained_host": self.constrained_host()}, cgroup_root
            )

    def test_container_refuses_missing_cgroup_file(self):
        cgroup_root, _ = self.fake_cgroup()
        (cgroup_root / "memory.swap.max").unlink()

        with self.assertRaisesRegex(SIZING.SourceBindingError, "memory.swap.max"):
            SIZING.verify_container_cgroup(
                {"constrained_host": self.constrained_host()}, cgroup_root
            )

    def test_container_checks_cgroup_before_repository_import(self):
        cgroup_root, _ = self.fake_cgroup(**{"memory.max": str(256 * 1024**2 + 1)})
        manifest = SIZING.seal_manifest(
            {
                "schema": SIZING.MANIFEST_SCHEMA,
                "source_commit": "test",
                "modules": {},
                "file_sha256": {name: "0" * 64 for name in SIZING.PINNED_HARNESS_FILES},
                "constrained_host": self.constrained_host(),
            }
        )
        artifact_dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, artifact_dir, ignore_errors=True)
        manifest_path = artifact_dir / "manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

        with (
            mock.patch.object(
                SIZING,
                "utc_now_iso",
                return_value="2026-10-18T12:00:12+00:00",
            ),
            mock.patch.object(SIZING, "import_sizing_modules") as import_modules,
        ):
            with self.assertRaisesRegex(SIZING.SourceBindingError, "memory.max"):
                SIZING.run_container_preflight(
                    self.repo, manifest_path, cgroup_root=cgroup_root
                )
        import_modules.assert_not_called()

    def test_container_refuses_constrained_cgroup_without_manifest_record(self):
        cgroup_root, _ = self.fake_cgroup()

        with self.assertRaisesRegex(SIZING.SourceBindingError, "no constrained_host"):
            SIZING.verify_container_cgroup({}, cgroup_root)

    def test_final_container_cgroup_refuses_changed_limits(self):
        cgroup_root, _ = self.fake_cgroup()
        (cgroup_root / "memory.peak").write_text("12345", encoding="ascii")
        provenance = {
            "constrained_host": self.constrained_host(),
            "container_cgroup": SIZING.verify_container_cgroup(
                {"constrained_host": self.constrained_host()}, cgroup_root
            ),
        }
        (cgroup_root / "pids.max").write_text("65", encoding="ascii")

        with self.assertRaisesRegex(SIZING.SourceBindingError, "pids.max"):
            SIZING.final_container_cgroup(provenance, cgroup_root)

    def test_final_container_cgroup_records_memory_peak(self):
        cgroup_root, _ = self.fake_cgroup()
        (cgroup_root / "memory.peak").write_text("45678", encoding="ascii")
        constrained_host = self.constrained_host()
        provenance = {
            "constrained_host": constrained_host,
            "container_cgroup": SIZING.verify_container_cgroup(
                {"constrained_host": constrained_host}, cgroup_root
            ),
        }

        observed = SIZING.final_container_cgroup(provenance, cgroup_root)

        self.assertEqual(observed["memory.peak"], 45678)
        self.assertEqual(observed["memory.max"], str(256 * 1024**2))

    def test_container_records_start_before_cgroup_check(self):
        manifest = SIZING.source_manifest(
            self.repo, self.temp_sources("fixture_used"), self.constrained_host()
        )
        manifest_path = self.repo / "manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        cgroup_root, expected = self.fake_cgroup()
        events = []
        started_at = "2026-10-18T12:00:12+00:00"
        previous_finders = list(sys.meta_path)
        self.addCleanup(
            lambda: sys.meta_path.__setitem__(slice(None), previous_finders)
        )

        with (
            mock.patch.object(
                SIZING,
                "utc_now_iso",
                side_effect=lambda: events.append("start") or started_at,
            ),
            mock.patch.object(
                SIZING,
                "verify_container_cgroup",
                side_effect=lambda *_args, **_kwargs: (
                    events.append("cgroup") or expected
                ),
            ),
            mock.patch.object(SIZING, "import_sizing_modules"),
            mock.patch.object(SIZING, "imported_repo_sources", return_value={}),
            mock.patch.object(
                SIZING,
                "verify_container_sources",
                return_value={"source_commit": manifest["source_commit"]},
            ),
        ):
            _, provenance = SIZING.run_container_preflight(
                self.repo, manifest_path, cgroup_root=cgroup_root
            )

        self.assertEqual(events, ["start", "cgroup"])
        self.assertEqual(provenance["container_started_at_utc"], started_at)

    def test_preflight_refuses_stale_host_gate_sample_before_import(self):
        constrained_host = self.constrained_host()
        manifest = SIZING.source_manifest(
            self.repo, self.temp_sources("fixture_used"), constrained_host
        )
        manifest_path = self.repo / "manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        cgroup_root, _ = self.fake_cgroup()
        start_time = "2026-10-18T12:05:31+00:00"
        error = None

        with (
            mock.patch.object(SIZING, "utc_now_iso", return_value=start_time),
            mock.patch.object(SIZING, "import_sizing_modules") as import_modules,
        ):
            try:
                SIZING.run_container_preflight(
                    self.repo, manifest_path, cgroup_root=cgroup_root
                )
            except SIZING.SourceBindingError as exc:
                error = exc
            import_modules.assert_not_called()

        self.assertIsNotNone(error, "stale host-gate sample must be refused")
        self.assertRegex(str(error), "exceeds the 330s limit")

    def test_preflight_refuses_start_31_seconds_before_sample(self):
        constrained_host = self.constrained_host()
        manifest = SIZING.source_manifest(
            self.repo, self.temp_sources("fixture_used"), constrained_host
        )
        manifest_path = self.repo / "manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        cgroup_root, _ = self.fake_cgroup()
        start_time = "2026-10-18T11:59:29+00:00"
        error = None

        with (
            mock.patch.object(SIZING, "utc_now_iso", return_value=start_time),
            mock.patch.object(SIZING, "import_sizing_modules") as import_modules,
        ):
            try:
                SIZING.run_container_preflight(
                    self.repo, manifest_path, cgroup_root=cgroup_root
                )
            except SIZING.SourceBindingError as exc:
                error = exc
            import_modules.assert_not_called()

        self.assertIsNotNone(error, "container start 31s before sample must be refused")
        self.assertRegex(str(error), "negative beyond the 30-second")

    def test_host_gate_gap_refuses_non_utc_offset_timestamp(self):
        constrained_host = self.constrained_host()
        constrained_host["available_sampled_at_utc"] = "2026-10-18T20:00:00+08:00"

        with self.assertRaisesRegex(SIZING.SourceBindingError, "UTC offset"):
            SIZING.host_gate_sample_gap_seconds(
                constrained_host, "2026-10-18T12:00:12+00:00"
            )

    def test_main_container_mode_writes_finalizable_raw_receipt(self):
        source_paths = {
            "__main__": SCRIPT_PATH,
            "time_inf037b_three_attempts": ROOT
            / "scripts"
            / "time_inf037b_three_attempts.py",
            "inference_platform": ROOT
            / "python"
            / "src"
            / "inference_platform"
            / "__init__.py",
            "inference_platform.inf037b_archive": ROOT
            / "python"
            / "src"
            / "inference_platform"
            / "inf037b_archive.py",
            "inference_platform.inf037b_campaign": ROOT
            / "python"
            / "src"
            / "inference_platform"
            / "inf037b_campaign.py",
        }

        def build(raw_root, **_kwargs):
            raw_root.mkdir(parents=True, exist_ok=True)
            return [{"expected_offers": []} for _ in range(3)], 1

        def materialize_bundle(_raw_root, _specs):
            return None

        def sanitized_campaign(_raw_root, destination, specs, **_kwargs):
            destination.mkdir(parents=True, exist_ok=True)
            (destination / "archive.bin").write_bytes(b"fake sanitized archive")
            return {"specs": specs, "source_manifest_sha256": "a" * 64}

        def verify_archive(_destination):
            return {"segments": {"raw/attempt-1": {"row_count": 1}}}

        fake_time = types.ModuleType("time_inf037b_three_attempts")
        fake_time.__file__ = str(source_paths["time_inf037b_three_attempts"])
        fake_time.build = build

        fake_platform = types.ModuleType("inference_platform")
        fake_platform.__file__ = str(source_paths["inference_platform"])
        fake_platform.__path__ = [str(source_paths["inference_platform"].parent)]
        fake_archive = types.ModuleType("inference_platform.inf037b_archive")
        fake_archive.__file__ = str(source_paths["inference_platform.inf037b_archive"])
        fake_archive.verify_archive = verify_archive
        fake_campaign = types.ModuleType("inference_platform.inf037b_campaign")
        fake_campaign.__file__ = str(
            source_paths["inference_platform.inf037b_campaign"]
        )
        fake_campaign.materialize_bundle = materialize_bundle
        fake_campaign.sanitized_campaign = sanitized_campaign
        fake_platform.inf037b_archive = fake_archive
        fake_platform.inf037b_campaign = fake_campaign
        fake_modules = {
            "time_inf037b_three_attempts": fake_time,
            "inference_platform": fake_platform,
            "inference_platform.inf037b_archive": fake_archive,
            "inference_platform.inf037b_campaign": fake_campaign,
        }

        constrained_host = self.constrained_host()
        constrained_host["available_sampled_at_utc"] = "2026-10-18T12:00:00+00:00"
        manifest = SIZING.source_manifest(ROOT, source_paths, constrained_host)
        artifact_dir = Path(self.temp.name)
        manifest_path = artifact_dir / "main-manifest.json"
        raw_path = artifact_dir / "main-raw.json"
        finalized_path = artifact_dir / "main-final.json"
        work_path = artifact_dir / "main-work"
        work_path.mkdir()
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        cgroup_root, _ = self.fake_cgroup()
        (cgroup_root / "memory.peak").write_text("12345", encoding="ascii")

        started_at = "2026-10-18T12:00:12+00:00"
        previous_finders = list(sys.meta_path)
        real_preflight = SIZING.run_container_preflight
        real_final_container_cgroup = SIZING.final_container_cgroup
        real_anon_sampler = SIZING.CgroupAnonSampler

        def preflight_with_fake_cgroup(repo, source_manifest_path):
            return real_preflight(repo, source_manifest_path, cgroup_root=cgroup_root)

        def final_cgroup_with_fake_root(provenance, _default_root=None, **kwargs):
            return real_final_container_cgroup(provenance, cgroup_root, **kwargs)

        def stub_source_verification(_repo, candidate, _imported_sources):
            return {
                name: candidate[name]
                for name in (
                    "source_commit",
                    "manifest_sha256",
                    "modules",
                    "file_sha256",
                )
            }

        try:
            with (
                mock.patch.dict(sys.modules, fake_modules),
                mock.patch.object(
                    SIZING,
                    "imported_repo_sources",
                    return_value=source_paths,
                ),
                mock.patch.object(
                    SIZING,
                    "verify_container_sources",
                    side_effect=stub_source_verification,
                ),
                mock.patch.object(
                    SIZING,
                    "run_container_preflight",
                    side_effect=preflight_with_fake_cgroup,
                ),
                mock.patch.object(
                    SIZING,
                    "final_container_cgroup",
                    side_effect=final_cgroup_with_fake_root,
                ),
                mock.patch.object(
                    SIZING,
                    "CgroupAnonSampler",
                    side_effect=lambda _root, enabled, *, progress_path: (
                        real_anon_sampler(
                            cgroup_root,
                            enabled,
                            progress_path=artifact_dir / "anon-progress.json",
                        )
                    ),
                ),
                mock.patch.object(SIZING, "utc_now_iso", return_value=started_at),
                mock.patch.object(SIZING, "rss", return_value=1),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                return_code = SIZING.main(
                    [
                        "--container-mode",
                        "--source-manifest",
                        str(manifest_path),
                        "--output",
                        str(raw_path),
                        "--work",
                        str(work_path),
                    ]
                )
        finally:
            sys.meta_path[:] = previous_finders

        self.assertEqual(return_code, 0)
        raw_receipt = json.loads(raw_path.read_text(encoding="utf-8"))
        self.assertIn("memory.peak", raw_receipt["container_cgroup"])
        self.assertEqual(raw_receipt["container_cgroup"]["memory.peak"], 12345)
        self.assertEqual(raw_receipt["container_started_at_utc"], started_at)
        self.assertGreater(
            json.loads((artifact_dir / "anon-progress.json").read_bytes())[
                "sample_count"
            ],
            0,
        )

        finalized = SIZING.finalize_container_receipt(
            ROOT, manifest_path, raw_path, finalized_path
        )

        self.assertEqual(finalized["container_cgroup"]["memory.peak"], 12345)
        self.assertEqual(finalized["container_started_at_utc"], started_at)
        self.assertTrue(finalized_path.exists())

    def test_finalizer_records_matching_cgroup_and_gate_sample_gap(self):
        constrained_host = self.constrained_host()
        manifest = SIZING.source_manifest(
            self.repo,
            self.temp_sources("fixture_used"),
            constrained_host,
        )
        artifact_dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, artifact_dir, ignore_errors=True)
        manifest_path = artifact_dir / "manifest.json"
        raw_path = artifact_dir / "raw.json"
        output_path = artifact_dir / "final.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        receipt, sampled_at = self.matching_raw_receipt(manifest)
        constrained_host["available_sampled_at_utc"] = sampled_at
        manifest = SIZING.source_manifest(
            self.repo,
            self.temp_sources("fixture_used"),
            constrained_host,
        )
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        receipt["source_manifest_sha256"] = manifest["manifest_sha256"]
        raw_path.write_text(json.dumps(receipt), encoding="utf-8")

        finalized = SIZING.finalize_container_receipt(
            self.repo, manifest_path, raw_path, output_path
        )

        self.assertEqual(finalized["container_cgroup"]["memory.peak"], "12345")
        self.assertEqual(finalized["constrained_host"], constrained_host)
        self.assertEqual(finalized["host_total_ram_bytes"], 8 * 1024**3)
        self.assertEqual(finalized["docker_vm_mem_total_bytes"], 8 * 1024**3)
        self.assertEqual(finalized["host_gate_sample_to_container_start_seconds"], 12)
        self.assertEqual(json.loads(output_path.read_text()), finalized)

    def test_finalizer_refuses_stale_host_gate_sample(self):
        constrained_host = self.constrained_host()
        manifest = SIZING.source_manifest(
            self.repo,
            self.temp_sources("fixture_used"),
            constrained_host,
        )
        artifact_dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, artifact_dir, ignore_errors=True)
        manifest_path = artifact_dir / "manifest.json"
        raw_path = artifact_dir / "raw.json"
        output_path = artifact_dir / "final.json"
        receipt, sampled_at = self.matching_raw_receipt(
            manifest, start_offset_seconds=331
        )
        constrained_host["available_sampled_at_utc"] = sampled_at
        manifest = SIZING.source_manifest(
            self.repo,
            self.temp_sources("fixture_used"),
            constrained_host,
        )
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        receipt["source_manifest_sha256"] = manifest["manifest_sha256"]
        raw_path.write_text(json.dumps(receipt), encoding="utf-8")

        with self.assertRaisesRegex(SIZING.SourceBindingError, "host-gate sample age"):
            SIZING.finalize_container_receipt(
                self.repo, manifest_path, raw_path, output_path
            )
        self.assertFalse(output_path.exists())

    def test_finalizer_refuses_raw_receipt_limit_mismatch(self):
        constrained_host = self.constrained_host()
        manifest = SIZING.source_manifest(
            self.repo,
            self.temp_sources("fixture_used"),
            constrained_host,
        )
        artifact_dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, artifact_dir, ignore_errors=True)
        manifest_path = artifact_dir / "manifest.json"
        raw_path = artifact_dir / "raw.json"
        output_path = artifact_dir / "final.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        raw_receipt = {
            "source_commit": manifest["source_commit"],
            "source_manifest_sha256": manifest["manifest_sha256"],
            "container_cgroup": {
                "memory.max": str(256 * 1024**2 + 1),
                "memory.swap.max": "0",
                "pids.max": "64",
                "cpu.max": "100000 100000",
                "memory.peak": "12345",
            },
        }
        raw_path.write_text(json.dumps(raw_receipt), encoding="utf-8")

        with self.assertRaisesRegex(SIZING.SourceBindingError, "memory.max"):
            SIZING.finalize_container_receipt(
                self.repo, manifest_path, raw_path, output_path
            )
        self.assertFalse(output_path.exists())


if __name__ == "__main__":
    unittest.main()
