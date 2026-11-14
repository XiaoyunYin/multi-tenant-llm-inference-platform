import hashlib
import importlib.util
import json
import os
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from package_a_kind_walk import coverage, rehearsal, walk  # noqa: E402


class KindHarnessTests(unittest.TestCase):
    def test_pinned_runtime_accepts_plain_and_build_suffixed_uv(self):
        from inference_platform.kind_rollout import validate_runtime

        for uv in ("uv 0.9.5", "uv 0.9.5 (build 123)"):
            validate_runtime("3.12.7", uv)
        for python, uv in (("3.12.8", "uv 0.9.5"), ("3.12.7", "uv 0.9.50"), ("3.12.7", "uv 0.9.4")):
            with self.assertRaisesRegex(ValueError, "required"):
                validate_runtime(python, uv)

    def test_r328_publisher_modes_before_atomic_publication(self):
        import io
        import stat
        from unittest.mock import Mock

        from inference_platform import stage_c_tokenizer as tokenizer

        data = b"pinned test bytes"
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            replace = os.replace
            modes = []

            def publish(source, target):
                modes.append(stat.S_IMODE(source.stat().st_mode))
                replace(source, target)

            response = Mock()
            response.__enter__ = lambda _: io.BytesIO(data)
            response.__exit__ = lambda *args: None
            with (
                patch.object(tokenizer, "FILE_HASHES", {"file": hashlib.sha256(data).hexdigest()}),
                patch.object(tokenizer.urllib.request, "urlopen", return_value=response),
                patch.object(tokenizer.os, "replace", side_effect=publish),
                patch.object(Path, "chmod", autospec=True, wraps=Path.chmod) as chmod,
            ):
                # Windows verifies the call; POSIX separately verifies actual bits.
                chmod.side_effect = lambda path, mode: os.chmod(path, mode)
                tokenizer.verified_files(cache, fetch=True)
                chmod.assert_called_once()
                self.assertEqual(chmod.call_args.args[1], 0o644)
            if os.name == "posix":
                self.assertEqual(modes, [0o644])

    def test_r328_build_normalizes_warm_cache(self):
        import shutil
        import stat

        from inference_platform import kind_rollout as rollout
        from inference_platform import stage_c_tokenizer as tokenizer

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cache = root / "cache" / "revision"
            cache.mkdir(parents=True)
            (cache / "tokenizer.json").write_text("warm cache")
            (cache / "tokenizer.json").chmod(0o600)
            (root / "python/src/inference_platform").mkdir(parents=True)
            with (
                patch.object(rollout, "ROOT", root),
                patch.object(tokenizer, "verified_files"),
                patch.object(tokenizer, "cache_directory", return_value=cache),
                patch.object(rollout, "run", return_value=""),
                patch.object(Path, "chmod", autospec=True) as chmod,
            ):
                chmod.side_effect = lambda path, mode: os.chmod(path, mode)
                c = rollout.Campaign.__new__(rollout.Campaign)
                c.pins = {"redis_image": "pinned"}
                c.build()
                modes = {
                    call.args[0].relative_to(root).as_posix(): call.args[1]
                    for call in chmod.call_args_list
                }
                self.assertIn(".cache/kind-build/tokenizer", modes)
                self.assertEqual(modes[".cache/kind-build/tokenizer"], 0o755)
                self.assertEqual(modes[".cache/kind-build/tokenizer/revision"], 0o755)
                self.assertEqual(
                    modes[".cache/kind-build/tokenizer/revision/tokenizer.json"], 0o644
                )
            if os.name == "posix":
                for path in (root / ".cache/kind-build/tokenizer").rglob("*"):
                    self.assertEqual(
                        stat.S_IMODE(path.stat().st_mode), 0o755 if path.is_dir() else 0o644
                    )
            # Windows chmod(0600) is read/write; restore for TemporaryDirectory cleanup.
            shutil.rmtree(root / ".cache")

    def test_r328_fake_refuses_before_serving(self):
        import contextlib
        import io
        from unittest.mock import Mock

        from inference_platform import kind_fake

        backend = Mock()
        backend.start.side_effect = AssertionError("served without tokenizer")
        backend._server.chat_tokenizer = None
        backend._server.tokenizer_error = "permission denied"
        with (
            patch.object(kind_fake, "FakeBackend", return_value=backend),
            patch.dict(os.environ, POD_NAME="vllm-0", POD_UID="uid"),
            patch.object(kind_fake.threading, "Event") as event,
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            self.assertNotEqual(kind_fake.main(), 0)
            backend.start.assert_not_called()
            event.return_value.wait.assert_not_called()
        row = json.loads(output.getvalue())
        self.assertEqual(row["msg"], "tokenizer unavailable")
        self.assertEqual(row["tokenizer_error"], "permission denied")

    def test_r328_image_self_test_fails_closed_and_records_success(self):
        from test_package_a_cloud import Runner

        for value in ({"tokenizer_available": True, "probe_tokens": 34, "uid": 65532}, {}, None):
            with tempfile.TemporaryDirectory() as directory:
                runner = Runner(
                    ROOT,
                    Path(directory) / "out",
                    {
                        "checks": ["kind"],
                        "python_executable": sys.executable,
                        "pins": {
                            "python_image": "base",
                            "redis_image": "redis",
                            "node_image": "node",
                        },
                    },
                )
                calls = []

                def call(argv, name, calls=calls, value=value, runner=runner, **kwargs):
                    calls.append((argv, name))
                    if name == "fake-tokenizer-self-test" and value is None:
                        raise RuntimeError("check_exit:tokenizer")
                    path = runner.output / (name + ".log")
                    path.write_text(json.dumps(value if name == "fake-tokenizer-self-test" else []))
                    return {"log": path.name, "exit": 0}

                runner.call = call
                if value and value.get("uid") == 65532:
                    runner.prepare_images()
                    self.assertIn("fake_tokenizer_self_test", runner.receipt)
                    self.assertTrue(runner.receipt["fake_tokenizer_self_test"]["complete"])
                    argv = next(argv for argv, name in calls if name == "fake-tokenizer-self-test")
                    self.assertNotIn("--user", argv)
                    self.assertEqual(argv[argv.index("--entrypoint") + 1], "python")
                    self.assertIn("mti-fake:stage1", argv)
                else:
                    with self.assertRaises(RuntimeError):
                        runner.prepare_images()
                    self.assertFalse(runner.receipt["fake_tokenizer_self_test"]["complete"])
                    self.assertFalse(any(name.startswith("image-") for _, name in calls))

    def test_r325_deadline_covers_retained_low_and_candidate_hold(self):
        from rehearse_eks_package_a import admission_settings, admission_timing

        from inference_platform.package_a_workload import preflight_manifest

        env = admission_settings(preflight_manifest())
        self.assertEqual(env["BACKEND_DISCOVERY"], "endpointslices")
        timing = admission_timing(env)
        # admit.lua retains lows for TTL + hold, then starts a full candidate hold.
        self.assertGreaterEqual(
            timing["deadline_s"],
            timing["report_ttl_s"]
            + 2 * timing["hold_down_s"]
            + timing["health_freshness_s"]
            + 2 * timing["report_period_s"]
            + 5,
        )
        self.assertEqual(timing["deadline_s"], 20)
        self.assertEqual(timing["reader_timeout_s"], 5)
        static = admission_timing({**env, "BACKEND_DISCOVERY": "static"})
        self.assertEqual(static["deadline_s"], 21)
        with self.assertRaisesRegex(ValueError, "admission_deadline_exceeds_work_budget"):
            admission_timing({**env, "ADMISSION_REPORT_TTL": "300s"})

    def test_r325_walk_waits_for_redis_hold_down_before_streams(self):
        with tempfile.TemporaryDirectory() as directory:
            result = walk(Path(directory) / "hold-down")
            records = result["receipt"]["admission_capacity"]
            self.assertEqual(len(records), 3)
            self.assertEqual(records[0]["values"], [0, 0, 0, 2])
            self.assertEqual(records[0]["deadline_s"], 20)
            self.assertAlmostEqual(records[0]["health_freshness_s"], 1.85)
            self.assertTrue(all(row["complete"] for row in records))
            self.assertIn("kind_phase:success", "\n".join(result["phases"]))
            reads = [row["argv"] for row in result["commands"] if "HGET" in row["argv"]]
            self.assertTrue(reads)
            self.assertTrue(all("deploy/redis" in row and row[-1] == "n" for row in reads))

    def test_r325_stuck_capacity_retains_diagnostics_and_verified_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            result = walk(Path(directory) / "stuck", mode="capacity-stuck")
            self.assertIn("admission_capacity_not_restored:last_n=0", result["error"])
            record = result["receipt"]["admission_capacity"][0]
            self.assertFalse(record["complete"])
            self.assertEqual(set(record["values"]), {0})
            self.assertGreaterEqual(record["wait_s"], record["deadline_s"])
            self.assertTrue(result["receipt"]["owned_cluster_cleanup_verified"])
            diagnostics = result["receipt"]["diagnostics"]
            self.assertTrue(diagnostics["files"])
            for suffix in ("state", "reports"):
                self.assertTrue(
                    any("capacity-" + suffix in row["path"] for row in diagnostics["files"])
                )

    def kind_receipt(self, root):
        pins = json.loads((ROOT / "deploy/k8s/pins.json").read_bytes())
        platform = "windows" if os.name == "nt" else "linux"
        kubectl_hash = pins[f"kubectl_{platform}_amd64_sha256"]
        source_hash = hashlib.sha256(
            (ROOT / "scripts/rehearse_eks_package_a.py").read_bytes()
        ).hexdigest()
        values = {
            "api/transcript.json": {
                "complete": True,
                "kubectl_sha256": kubectl_hash,
            },
            "walk/coverage.json": {
                "coverage_percent": 100,
                "line_coverage_percent": 100,
                "missing_statement_lines": [],
                "missing_executable_lines": [],
                "source_sha256": source_hash,
            },
            "walk/success/receipt.json": {
                "replacement_and_prior_template_rollback": True,
                "owned_cluster_cleanup_verified": True,
            },
        }
        files = {}
        for name, value in values.items():
            path = root / "kind-no-cluster" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            data = (json.dumps(value, indent=2) + "\n").encode()
            path.write_bytes(data)
            files[name] = hashlib.sha256(data).hexdigest()
        return {
            "schema": "package-a-kind-no-cluster-v1",
            "complete": True,
            "billable_actions": 0,
            "skipped_tests": 0,
            "coverage_percent": 100,
            "line_coverage_percent": 100,
            "kubectl_sha256": kubectl_hash,
            "rehearsal_sha256": source_hash,
            "files_sha256": files,
        }

    def test_r314_prepare_binding_rejects_missing_or_changed_kind_receipts(self):
        from inference_platform import package_a_operator as operator

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record = self.kind_receipt(root)
            bind = getattr(operator, "bind_workload_preflight", None)
            if bind is None:
                self.fail("prepare has no kind-receipt binding function")
            with patch.object(operator, "validate_workload_preflight_files"):
                bind({"kind_no_cluster": record}, root)
                for name in (
                    "api/transcript.json",
                    "walk/coverage.json",
                    "walk/success/receipt.json",
                ):
                    path = root / "kind-no-cluster" / name
                    original = path.read_bytes()
                    path.write_bytes(b"changed after preflight")
                    with (
                        self.subTest(name=name),
                        self.assertRaisesRegex(ValueError, "kind_no_cluster_file_changed"),
                    ):
                        bind({"kind_no_cluster": record}, root)
                    path.write_bytes(original)
                (root / "kind-no-cluster/api/transcript.json").unlink()
                with self.assertRaisesRegex(ValueError, "kind_no_cluster_file_changed"):
                    bind({"kind_no_cluster": record}, root)

    def test_r314_walk_covers_every_statement_through_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            try:
                report = coverage(Path(directory) / "walk")
            except Exception as exc:
                self.fail(
                    f"scripted main walk did not produce coverage: {type(exc).__name__}:{exc}"
                )
            self.assertEqual(report["coverage_percent"], 100)
            self.assertEqual(report["line_coverage_percent"], 100)
            self.assertEqual(report["line_coverage"]["covered"], report["line_coverage"]["total"])
            self.assertFalse(report["missing_statement_lines"])
            receipt = json.loads((Path(directory) / "walk/success/receipt.json").read_bytes())
            self.assertEqual(
                len(receipt["sigterm_nonzero_live_and_both_streams_complete"]["streams"]), 4
            )
            provenance = json.loads(
                (Path(directory) / "walk/success/fixture-provenance.json").read_bytes()
            )
            fixture = json.loads((ROOT / "python/tests/fixtures/package_a_pods.json").read_bytes())

            def scalar_count(value):
                if isinstance(value, dict):
                    return sum(scalar_count(child) for child in value.values())
                if isinstance(value, list):
                    return sum(scalar_count(child) for child in value)
                return 1

            self.assertEqual(len(provenance["synthetic_fields"]), scalar_count(fixture))
            self.assertTrue(provenance["kind_fake_log_provenance"]["synthetic_fields"])
            log_sidecar = json.loads(
                (ROOT / "python/tests/fixtures/package_a_kind_fake.provenance.json").read_bytes()
            )
            self.assertEqual(
                log_sidecar["source_sha256"],
                hashlib.sha256(
                    (ROOT / "python/src/inference_platform/kind_fake.py").read_bytes()
                ).hexdigest(),
            )

    def test_nonzero_last_drained_log_refuses_and_preserves_diagnostics_and_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            result = walk(Path(directory) / "nonzero-drain", mode="drain-nonzero")
        self.assertTrue(result["error"].startswith("AssertionError:"), result["error"])
        self.assertIn("last stream drained", result["error"])
        self.assertTrue(result["receipt"]["diagnostics"]["files"])
        self.assertTrue(result["receipt"]["owned_cluster_cleanup_verified"])

    def test_r314_json_path_mutant_fails_the_walk(self):
        with tempfile.TemporaryDirectory() as directory:
            try:
                report = coverage(Path(directory) / "baseline-walk")
            except Exception as exc:
                self.fail(
                    f"scripted main walk did not produce coverage: {type(exc).__name__}:{exc}"
                )
            self.assertEqual(report["line_coverage_percent"], 100)
        source = (ROOT / "scripts/rehearse_eks_package_a.py").read_text(encoding="utf-8")
        original = 'initial["vllm-" + str(i)]["spec"]["nodeName"]'
        mutant = 'initial["vllm-" + str(i)]["spec"]["nodeName_mutant"]'
        self.assertIn(original, source)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rehearse_eks_package_a.py"
            path.write_text(source.replace(original, mutant, 1), encoding="utf-8")
            module = rehearsal(source_path=path)
            module.ROOT = ROOT
            with self.assertRaisesRegex(AssertionError, "scripted_walk_failed"):
                walk(Path(directory) / "mutant-walk", module=module)

    def test_r310_main_deadline_captures_diagnostics_and_cleans_up(self):
        with tempfile.TemporaryDirectory() as directory:
            try:
                result = walk(Path(directory) / "deadline", mode="deadline")
            except Exception as exc:
                self.fail(
                    f"deadline did not retain diagnostics and cleanup: {type(exc).__name__}:{exc}"
                )
            self.assertTrue(result["receipt"]["error"])
            self.assertTrue(result["receipt"]["diagnostics"]["files"])
            self.assertTrue(result["receipt"]["owned_cluster_cleanup_verified"])
            self.assertTrue(result["error"].startswith("TimeoutExpired:"))
            self.assertLess(result["clock_seconds"], 600)
            self.assertLessEqual(result["receipt"]["owned_cluster_cleanup_elapsed_seconds"], 590)
            self.assertTrue(
                any(line.startswith("kind_phase:readiness ") for line in result["phases"])
            )
            self.assertTrue(
                any(line.startswith("kind_phase:diagnostics ") for line in result["phases"])
            )
            self.assertTrue(
                any(line.startswith("kind_phase:cleanup ") for line in result["phases"])
            )
            self.assertTrue(result["receipt"]["phase_started_s"])
            budget = result["receipt"]["timeout_budget"]
            self.assertEqual(budget["outer_seconds"], 600)
            self.assertEqual(budget["work_seconds"], 290)
            self.assertEqual(budget["cleanup_reserve_seconds"], 310)
            self.assertEqual(budget["receipt_reserve_seconds"], 10)
            readiness = next(
                row
                for row in result["commands"]
                if "--for=jsonpath={.status.readyReplicas}=2" in row["argv"]
            )
            self.assertLessEqual(readiness["timeout"], 11)

    def test_r317_success_phases_have_times_and_wait_uses_work_cap(self):
        from inference_platform import package_a_cloud

        with tempfile.TemporaryDirectory() as directory:
            result = walk(Path(directory) / "success")
            entries = result["receipt"]["phase_started_s"]
            self.assertEqual(len(entries), len(result["phases"]))
            self.assertEqual(
                [row["phase"] for row in entries],
                [line.split(":", 1)[1].split(" ", 1)[0] for line in result["phases"]],
            )
            seconds = [row["phase_started_s"] for row in entries]
            self.assertTrue(all(a < b for a, b in zip(seconds[:-1], seconds[1:], strict=True)))
            self.assertEqual(entries[0]["phase"], "create")
            shared_timeout = getattr(package_a_cloud, "KIND_RUNNER_TIMEOUT_S", None)
            self.assertEqual(shared_timeout, package_a_cloud.CALL_TIMEOUTS["kind"][0])
            self.assertEqual(shared_timeout, package_a_cloud.BUDGETS["kind"])

            capped = walk(Path(directory) / "wait-cap", mode="wait-cap")
            self.assertEqual(capped["error"], "TimeoutError:kind_internal_deadline:work")
            self.assertFalse(capped["wait_predicate_called"])
            self.assertTrue(capped["receipt"]["diagnostics"]["files"])
            self.assertTrue(capped["receipt"]["owned_cluster_cleanup_verified"])

    def test_r317_call_with_no_work_time_records_error_diagnostics_and_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            result = walk(Path(directory) / "no-work", mode="no-work")
            receipt = result["receipt"]
            self.assertEqual(result["error"], "TimeoutError:kind_internal_deadline:work")
            self.assertTrue(receipt["diagnostics"]["files"])
            self.assertTrue(receipt["owned_cluster_cleanup_verified"])
            self.assertTrue(receipt["phase_started_s"])

    def test_r310_removed_timeout_cap_is_rejected(self):
        source = (ROOT / "scripts/rehearse_eks_package_a.py").read_text(encoding="utf-8")
        capped = "return run(argv, timeout=budget.cap(timeout), **kwargs)"
        uncapped = "return run(argv, timeout=timeout, **kwargs)"
        self.assertIn(capped, source)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rehearse_eks_package_a.py"
            path.write_text(source.replace(capped, uncapped, 1), encoding="utf-8")
            module = rehearsal(source_path=path)
            module.ROOT = ROOT
            output = Path(directory) / "uncapped"
            with self.assertRaisesRegex(
                AssertionError, "deadline_diagnostics_cleanup_reserve_failed"
            ):
                walk(output, mode="deadline", module=module)
            result = json.loads((output / "walk.json").read_bytes())
            self.assertIn("uncapped_work_timeout", result["error"])
            self.assertFalse(result["error"].startswith("TimeoutExpired:"))

    def test_r311_archives_disappear_after_load_and_output_stays_small(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "walk"
            result = walk(output)
            self.assertEqual(result["post_archive_large_files"], [])
            self.assertTrue(result["archive_paths_absent"])
            for command in result["commands"]:
                argv = command["argv"]
                if "image-archive" in argv:
                    archive = Path(argv[argv.index("image-archive") + 1])
                    self.assertTrue(archive.is_relative_to(output.parent))
            self.assertEqual(len(result["receipt"]["image_archives"]), 4)
            for record in result["receipt"]["image_archives"]:
                self.assertGreater(record["bytes"], 1024**2)
                self.assertEqual(Path(record["archive_path"]).name, record["archive_path"])
                self.assertTrue(record["removed_after_load"])
            self.assertFalse(
                [p for p in output.rglob("*") if p.is_file() and p.stat().st_size > 1024**2]
            )

    def test_r311_host_enforces_forecast_archive_bound_without_deleting_evidence(self):
        from inference_platform.package_a_cloud import EXPORT_MAX_BYTES, transfer_seconds

        spec = importlib.util.spec_from_file_location(
            "package_a_host", ROOT / "scripts/package_a_host.py"
        )
        host = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(host)
        if not hasattr(host, "EXPORT_MAX_BYTES"):
            self.fail("host freeze has no enforced archive bound")
        self.assertEqual(host.EXPORT_MAX_BYTES, EXPORT_MAX_BYTES)
        self.assertEqual(transfer_seconds(EXPORT_MAX_BYTES), 196)
        with tempfile.TemporaryDirectory() as directory:
            owner = host.Host(directory, "fixture", "fixture", 0)
            owner.output.mkdir()
            (owner.output / "receipt.json").write_text('{"complete":false}')
            # Small bound makes this a cheap deterministic overflow control.
            with (
                patch.object(host, "EXPORT_MAX_BYTES", 10),
                self.assertRaisesRegex(ValueError, "archive_exceeds"),
            ):
                owner.dispatch("/freeze", b"", {})
            self.assertIsNone(owner.frozen)
            self.assertTrue((Path(directory) / "receipts.tar.gz").exists())
            with tarfile.open(Path(directory) / "receipts.tar.gz", "r:gz") as archive:
                self.assertIn("results/receipt.json", archive.getnames())


if __name__ == "__main__":
    unittest.main()
