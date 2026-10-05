import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from inference_platform.fake_backend import FakeBackend, FakeBackendConfig
from inference_platform.stage_c_fitness import check_fitness
from inference_platform.stage_c_prompts import exact_prompt
from inference_platform.stage_c_session import (
    ENTRYPOINT,
    export,
    install_bundle,
    prepare,
    require_approval,
    run_session,
    sha,
    verify_sources,
)


def entrypoint_failure_context(session, artifact, stdout="", stderr=""):
    finalization = json.loads(
        (session / "export/session-finalization.json").read_text(encoding="utf-8")
    )
    context = {
        "status": artifact.get("status"),
        "reason": artifact.get("reason"),
        "readiness": artifact.get("readiness"),
        "timed_runs": [
            {"status": run.get("status"), "reason": run.get("stop_reason")}
            for run in artifact.get("timed_runs", [])
        ],
        "finalization_errors": finalization.get("errors"),
        "children": finalization.get("children"),
    }
    return (
        json.dumps(context, indent=2)
        + "\n"
        + stdout
        + stderr
        + (session / "gateway.log").read_text(encoding="utf-8")
    )


class SessionExportTest(unittest.TestCase):
    def test_full_logs_stay_out_of_bounded_final_metadata_export(self):
        with tempfile.TemporaryDirectory() as directory:
            session = Path(directory)
            (session / "gateway.log").write_bytes(b"external error: \xff\r\n")
            (session / "stage-c-artifact.json").write_text(
                '{"status":"completed"}\n', encoding="utf-8"
            )
            manifest = session / "manifest.json"
            manifest.write_bytes(b"{}\n")
            receipt = export(session, manifest)
            self.assertFalse((session / "export/gateway.log").exists())
            self.assertLess(receipt["bytes"], 32000)
            self.assertTrue((session / "evidence.tar.gz").exists())


class SessionEntrypointTest(unittest.TestCase):
    def test_fake_tokenizer_accepts_real_top_sweep_bursts_without_tcp_rejection(self):
        with FakeBackend(FakeBackendConfig()) as backend:
            for wave in range(3):
                barrier = threading.Barrier(64)

                def request(index, barrier=barrier, wave=wave):
                    barrier.wait(timeout=10)
                    return exact_prompt(
                        backend.base_url,
                        "test",
                        f"burst-{wave}-{index}",
                        6144,
                        time.perf_counter() + 10,
                    )[1]

                with ThreadPoolExecutor(max_workers=64) as executor:
                    tokens = list(executor.map(request, range(64)))
                self.assertTrue(all(len(row) == 6144 for row in tokens))

    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[2]
        cls.directory = tempfile.TemporaryDirectory(
            prefix="reviewed-stage-c-", dir=cls.root / ".cache"
        )
        cls.path = Path(cls.directory.name)
        cls.payload = cls.path / "payload"
        cls.manifest = prepare(cls.root, cls.payload, "windows" if os.name == "nt" else "linux")

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def test_extra_helper_and_modified_committed_source_fail_provenance(self):
        sources = self.payload / "sources"
        rogue = sources / "session-prepare.py"
        rogue.write_text("print('unreviewed')", encoding="utf-8")
        try:
            with self.assertRaisesRegex(ValueError, "extra=.*session-prepare"):
                verify_sources(sources, self.manifest, self.root)
            inputs = json.loads(
                (self.root / "docs/INF011_STAGE_C_SESSION_INPUTS.json").read_text(encoding="utf-8")
            )
            launcher = (self.root / "infra/terraform/pilot/user-data.sh.tftpl").read_text(
                encoding="utf-8"
            )
            rows = check_fitness(launcher, inputs, self.root, sources)
            self.assertFalse(
                next(row for row in rows if row["prerequisite"] == "staged_payload_git_provenance")[
                    "provided"
                ]
            )
            # Even including its hash in a new manifest cannot make it a Git-tracked source.
            forged = json.loads(json.dumps(self.manifest))
            forged["files"].append({"path": rogue.name, "sha256": sha(rogue)})
            with self.assertRaisesRegex(ValueError, "not tracked in git"):
                verify_sources(sources, forged, self.root)
        finally:
            rogue.unlink()
        entry = sources / ENTRYPOINT
        original = entry.read_bytes()
        try:
            entry.write_bytes(original + b"\n# unreviewed\n")
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                verify_sources(sources, self.manifest, self.root)
        finally:
            entry.write_bytes(original)

    def test_bundle_installer_rejects_unreviewed_helpers_before_execution(self):
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w:gz") as archive:
            for name in ["staging-manifest.json", self.manifest["gateway_artifact"]["path"]] + [
                "sources/" + row["path"] for row in self.manifest["files"]
            ]:
                archive.add(self.payload / name, arcname=name)
            info = tarfile.TarInfo("per-session-helper.py")
            info.size = 4
            archive.addfile(info, io.BytesIO(b"pass"))
        with self.assertRaisesRegex(ValueError, "unreviewed"):
            install_bundle(
                data.getvalue(),
                self.path / "bad-install",
                sha(self.payload / "staging-manifest.json"),
            )
        self.assertFalse((self.path / "bad-install").exists())

    def test_fitness_rejects_helper_beside_sources_in_entire_payload(self):
        from inference_platform.stage_c_fitness import verify_staged_directory

        verify_staged_directory(self.payload, self.manifest, self.root)
        rogue = self.payload / "session-controller.py"
        rogue.write_text("pass\n", encoding="utf-8")
        try:
            with self.assertRaisesRegex(ValueError, "untracked staged payload.*session-controller"):
                verify_staged_directory(self.payload, self.manifest, self.root)
        finally:
            rogue.unlink()

    def test_reviewed_snapshot_can_be_rebuilt_with_identical_manifest_and_gateway(self):
        rebuilt = self.path / "rebuilt"
        prepare(
            self.root,
            rebuilt,
            self.manifest["gateway_artifact"]["goos"],
            self.manifest["source_commit"],
        )
        self.assertEqual(
            sha(rebuilt / "staging-manifest.json"), sha(self.payload / "staging-manifest.json")
        )
        self.assertEqual(
            sha(rebuilt / self.manifest["gateway_artifact"]["path"]),
            self.manifest["gateway_artifact"]["sha256"],
        )

    def test_closed_paid_gate_refuses_remote_controller_without_any_aws_call(self):
        with self.assertRaisesRegex(ValueError, "gate closed"):
            require_approval(self.root, "0" * 64)

    def test_committed_entrypoint_real_gateway_delayed_backend_and_complete_export(self):
        session = self.path / "rehearsal"
        scratch = self.path / "scratch"
        shutil.copytree(self.payload, scratch)
        environment = {
            **os.environ,
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": str(scratch / "sources/python/src"),
        }
        command = [
            sys.executable,
            "-c",
            # Exercise the exact staged module through runpy's -m semantics.
            # Its 1.5s fake startup delay can expire before the controller's first
            # probe on a slower host. Inject one unready observation explicitly;
            # subsequent probes and all inference/exports use the real services.
            "import runpy,sys; from unittest.mock import patch; "
            "import inference_platform.stage_c_readiness as readiness; "
            "original_wait=readiness.wait_readiness; first=[True]\n"
            "def delayed_probe(url,timeout):\n"
            "    if first[0]:\n"
            "        first[0]=False\n"
            "        return False\n"
            "    return readiness.health_probe(url,timeout)\n"
            "def controlled_wait(*args,**kwargs):\n"
            "    return original_wait(*args,probe=delayed_probe,**kwargs)\n"
            "sys.argv=['inference_platform.stage_c_session',*sys.argv[1:]]\n"
            "with patch.object(readiness,'wait_readiness',controlled_wait):\n"
            "    runpy.run_module('inference_platform.stage_c_session',run_name='__main__')\n",
            "--payload",
            str(scratch),
            "--manifest-sha256",
            sha(self.payload / "staging-manifest.json"),
            "--session",
            str(session),
            "--rehearse",
            "--quick",
        ]
        completed = subprocess.run(
            command, env=environment, capture_output=True, text=True, timeout=300
        )
        artifact = json.loads(
            (session / "export/stage-c-artifact.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            completed.returncode,
            0,
            entrypoint_failure_context(session, artifact, completed.stdout, completed.stderr),
        )
        self.assertEqual(artifact["status"], "completed")
        disk = json.loads((session / "export/disk-readiness.json").read_text(encoding="utf-8"))
        self.assertEqual(disk["source"], "rehearsal")
        self.assertEqual(
            artifact["readiness"]["gate"]["checks"]["root_disk"]["source"], "rehearsal"
        )
        self.assertTrue(all(run["status"] == "completed" for run in artifact["timed_runs"]))
        self.assertGreater(artifact["decision_event_export"]["observed_correlation_count"], 0)
        self.assertEqual(
            artifact["decision_event_export"]["request_lifetime_bound_violation_count"], 0
        )
        self.assertIn("1 s", artifact["decision_event_export"]["basis"])
        readiness = artifact["readiness_wait"]
        self.assertFalse(readiness["attempts"][0]["endpoints"][0]["healthy"])
        self.assertGreater(len(readiness["attempts"]), 1)
        self.assertEqual(readiness["status"], "ready")
        finalizer = json.loads(
            (session / "export/session-finalization.json").read_text(encoding="utf-8")
        )
        self.assertTrue(all(child["reaped"] for child in finalizer["children"]))
        self.assertEqual(finalizer["errors"], [])
        self.assertFalse((session / "private").exists())
        for line in (session / "export/SHA256SUMS.txt").read_text(encoding="utf-8").splitlines():
            digest, name = line.split("  ", 1)
            raw = (session / "export" / name).read_bytes()
            if not name.endswith(".tar.gz"):
                self.assertFalse(raw.startswith(b"\xef\xbb\xbf"))
                self.assertNotIn(b"\r\n", raw)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), digest)
        receipt = json.loads((session / "export-receipt.json").read_text(encoding="utf-8"))
        self.assertEqual(receipt["sha256"], sha(session / "evidence.tar.gz"))

    def test_finalizer_failure_is_named_in_entrypoint_assertion(self):
        from inference_platform.session_stop import stop_child

        session = self.path / "finalizer-failure"
        scratch = self.path / "finalizer-scratch"
        shutil.copytree(self.payload, scratch)
        args = SimpleNamespace(
            payload=scratch,
            session=session,
            rehearse=True,
            quick=True,
            manifest_sha256=sha(scratch / "staging-manifest.json"),
        )

        def fail_after_reap(child):
            stop_child(child)
            raise OSError("injected stop_child regression")

        with patch("inference_platform.session_stop.stop_child", side_effect=fail_after_reap):
            code = run_session(args)
        artifact = json.loads(
            (session / "export/stage-c-artifact.json").read_text(encoding="utf-8")
        )
        self.assertEqual(code, 1)
        with self.assertRaisesRegex(AssertionError, "injected stop_child regression"):
            self.assertEqual(code, 0, entrypoint_failure_context(session, artifact))
