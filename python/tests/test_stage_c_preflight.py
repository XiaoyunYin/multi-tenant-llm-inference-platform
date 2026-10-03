import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from inference_platform.stage_c_session import (
    BUNDLE,
    ENTRYPOINT,
    bind_approved_inputs,
    git,
    preflight,
    prepare,
    require_approval,
    sha,
    verify_sources,
    write_json,
)


class PreflightTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[2]
        cls.powershell_executable = shutil.which("powershell") or shutil.which("pwsh")
        if cls.powershell_executable is None:
            raise RuntimeError("PowerShell is required for the wrapper preflight tests")
        cls.temp = tempfile.TemporaryDirectory(dir=cls.root / ".cache", prefix="preflight-")
        cls.directory = Path(cls.temp.name)
        cls.repo = cls.directory / "synthetic"
        cls.repo.mkdir()
        git(cls.repo, "init")
        git(cls.repo, "config", "user.name", "Binding test")
        git(cls.repo, "config", "user.email", "binding@example.invalid")
        # Borrow source objects for blob verification, but create only synthetic
        # inputs commits. This repository has no REVIEW.md or approval marker.
        objects = Path(git(cls.root, "rev-parse", "--git-path", "objects").decode().strip())
        if not objects.is_absolute():
            objects = cls.root / objects
        (cls.repo / ".git/objects/info/alternates").write_text(
            objects.resolve().as_posix() + "\n", encoding="utf-8", newline="\n"
        )
        cls.payload = cls.repo / ".cache/payload"
        cls.manifest = prepare(cls.root, cls.payload, "linux")
        cls.inputs_path = cls.repo / "docs/INF011_STAGE_C_SESSION_INPUTS.json"
        cls.inputs_path.parent.mkdir()
        cls.plan = "a" * 64
        cls.manifest_hash = sha(cls.payload / "staging-manifest.json")
        cls.inputs = {
            "plan_sha256": cls.plan,
            "region": "us-east-1",
            "aws_profile": "admin-learning",
            "staging": {
                "manifest_sha256": cls.manifest_hash,
                "entrypoint_path": ENTRYPOINT,
                "entrypoint_sha256": cls.manifest["entrypoint"]["sha256"],
                "source_commit": cls.manifest["source_commit"],
                "gateway_artifact": cls.manifest["gateway_artifact"],
                "bundle_sha256": sha(cls.payload / BUNDLE),
                "payload_directory": ".cache/payload",
            },
            "target_only_note": "Return target inputs even if non-binding metadata later changes",
        }
        write_json(cls.inputs_path, cls.inputs)
        git(cls.repo, "add", "docs")
        git(cls.repo, "commit", "-m", "Synthetic inputs without approval")
        cls.target = git(cls.repo, "rev-parse", "HEAD").decode().strip()
        cls.receipt = cls.directory / "receipt.json"
        cls.plugin_dir = cls.directory / "plugin"
        cls.plugin_dir.mkdir()
        cls.plugin = cls.plugin_dir / (
            "session-manager-plugin.cmd" if os.name == "nt" else "session-manager-plugin"
        )
        cls.plugin.write_text(
            "@exit /b 0\n" if os.name == "nt" else "#!/bin/sh\nexit 0\n", encoding="utf-8"
        )
        cls.plugin.chmod(0o755)

    @classmethod
    def tearDownClass(cls):
        for bundle in cls.directory.rglob(BUNDLE):
            bundle.chmod(0o644)
        cls.temp.cleanup()

    def tearDown(self):
        git(self.repo, "reset", "--hard", self.target)

    def invoke(self):
        # Mock only marker discovery. Binding, Git and payload checks are real.
        with (
            patch(
                "inference_platform.stage_c_session.find_approval_target", return_value=self.target
            ),
            patch("shutil.which", return_value=str(self.plugin)),
        ):
            return preflight(self.repo, None, self.plan, None, self.receipt)

    def wrapper(self, environment):
        return subprocess.run(
            [
                self.powershell_executable,
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(self.root / "scripts/inf011-pilot.ps1"),
                "-Action",
                "PreflightDryRun",
                "-PreflightRepo",
                str(self.repo),
                "-PreflightPlanHash",
                self.plan,
                "-PreflightBindingTarget",
                self.target,
            ],
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
        )

    def test_untouched_payload_passes_bound_receipt_and_reproducible_archive(self):
        receipt = self.invoke()
        self.assertEqual(receipt["status"], "passed")
        self.assertFalse(receipt["aws_calls_made"])
        self.assertEqual(receipt["plan_sha256"], self.plan)
        self.assertEqual(receipt["manifest_sha256"], self.manifest_hash)
        self.assertEqual(receipt["approval_target"], self.target)
        self.assertEqual(receipt["approval_head"], self.target)
        self.assertEqual(receipt["bundle_sha256"], sha(self.payload / BUNDLE))
        self.assertEqual(json.loads(self.receipt.read_text()), receipt)
        rebuilt = self.directory / "rebuilt"
        prepare(self.root, rebuilt, "linux", self.manifest["source_commit"])
        self.assertEqual(sha(rebuilt / BUNDLE), receipt["bundle_sha256"])

    def test_binding_returns_target_inputs_and_refuses_dirty_nonbinding_metadata(self):
        newer = {**self.inputs, "target_only_note": "Later committed metadata"}
        write_json(self.inputs_path, newer)
        with self.assertRaisesRegex(ValueError, "clean and committed"):
            bind_approved_inputs(self.repo, self.target, self.plan)
        git(self.repo, "add", "docs")
        git(self.repo, "commit", "-m", "Nonbinding metadata")
        self.assertEqual(bind_approved_inputs(self.repo, self.target, self.plan), self.inputs)

    def test_every_binding_field_and_staged_repin_refuses(self):
        for key in ("plan_sha256", "region", "aws_profile", "staging"):
            changed = json.loads(json.dumps(self.inputs))
            changed[key] = (
                "changed" if key != "staging" else {**changed[key], "extra_pin": "changed"}
            )
            write_json(self.inputs_path, changed)
            for staged in (False, True):
                if staged:
                    git(self.repo, "add", "docs")
                with self.assertRaisesRegex(ValueError, "differs from approved target"):
                    bind_approved_inputs(self.repo, self.target, self.plan)
            git(self.repo, "reset", "--hard", self.target)

    def test_historical_uncommitted_and_committed_repin_refuse(self):
        historical = self.directory / "historical"
        subprocess.run(
            ["git", "clone", "--shared", "--no-checkout", str(self.root), str(historical)],
            check=True,
            capture_output=True,
        )
        git(historical, "checkout", "e1dca83")
        git(historical, "config", "user.name", "Binding test")
        git(historical, "config", "user.email", "binding@example.invalid")
        path = historical / "docs/INF011_STAGE_C_SESSION_INPUTS.json"
        inputs = json.loads(path.read_text(encoding="utf-8"))
        plan = inputs["plan_sha256"]
        review_hash = sha(historical / "REVIEW.md")
        inputs["staging"] = self.inputs["staging"]
        write_json(path, inputs)
        for committed in (False, True):
            if committed:
                git(historical, "add", "docs/INF011_STAGE_C_SESSION_INPUTS.json")
                git(historical, "commit", "-m", "Unapproved re-pin")
            with self.assertRaisesRegex(ValueError, "differs from approved target"):
                require_approval(historical, plan)
            with self.assertRaisesRegex(ValueError, "differs from approved target"):
                preflight(historical, self.payload, plan, self.manifest_hash, self.receipt)
            self.assertFalse(self.receipt.exists())
            self.assertEqual(sha(historical / "REVIEW.md"), review_hash)

    def test_extra_pyc_fails_shared_wrapper_gate_and_removes_stale_receipt(self):
        self.invoke()
        rogue = self.payload / "sources/python/src/inference_platform/extra.pyc"
        rogue.write_bytes(b"unreviewed bytecode")
        original_bundle = sha(self.payload / BUNDLE)
        try:
            with self.assertRaisesRegex(ValueError, "extra=.*extra.pyc"):
                self.invoke()
            self.assertFalse(self.receipt.exists())
            if os.name == "nt":
                environment = {
                    **os.environ,
                    "PATH": str(self.plugin_dir) + os.pathsep + os.environ["PATH"],
                    "PYTHONDONTWRITEBYTECODE": "1",
                }
                result = self.wrapper(environment)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("extra.pyc", result.stdout + result.stderr)
                self.assertNotIn("Apply preflight seam passed", result.stdout)
            self.assertEqual(sha(self.payload / BUNDLE), original_bundle)
        finally:
            rogue.unlink()

    def test_missing_plugin_closed_latest_gate_refuse(self):
        self.invoke()
        with (
            patch(
                "inference_platform.stage_c_session.find_approval_target", return_value=self.target
            ),
            patch("shutil.which", return_value=None),
            self.assertRaisesRegex(ValueError, "plugin does not resolve"),
        ):
            preflight(self.repo, self.payload, self.plan, self.manifest_hash, self.receipt)
        self.assertFalse(self.receipt.exists())
        with self.assertRaisesRegex(ValueError, "gate closed"):
            require_approval(self.root, self.plan)

    def test_modified_gateway_and_forged_manifest_source_fail(self):
        binary = self.payload / "gateway"
        original = binary.read_bytes()
        binary.write_bytes(original + b"changed")
        try:
            with self.assertRaisesRegex(ValueError, "gateway artifact hash mismatch"):
                self.invoke()
        finally:
            binary.write_bytes(original)
        manifest = json.loads(json.dumps(self.manifest))
        source = self.payload / "sources" / ENTRYPOINT
        original = source.read_bytes()
        source.write_bytes(original + b"\n# forged\n")
        manifest["entrypoint"]["sha256"] = sha(source)
        next(row for row in manifest["files"] if row["path"] == ENTRYPOINT)["sha256"] = sha(source)
        try:
            with self.assertRaisesRegex(ValueError, "not the committed git blob"):
                verify_sources(self.payload / "sources", manifest, self.repo)
        finally:
            source.write_bytes(original)

    @unittest.skipUnless(os.name == "nt", "PowerShell wrapper seam requires Windows")
    def test_wrapper_untouched_payload_passes_and_absent_plugin_refuses(self):
        environment = {
            **os.environ,
            "PATH": str(self.plugin_dir) + os.pathsep + os.environ["PATH"],
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        result = self.wrapper(environment)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Apply preflight seam passed", result.stdout)
        receipt = json.loads((self.repo / ".cache/stage-c-preflight/receipt.json").read_text())
        self.assertEqual(receipt["approval_basis"], "binding_rehearsal_only")
        self.assertEqual(receipt["approval_target"], self.target)
        tools_path = {
            str(Path(path).parent)
            for path in (self.powershell_executable, shutil.which("uv"), shutil.which("git"))
        }
        environment["PATH"] = os.pathsep.join(sorted(tools_path))
        result = self.wrapper(environment)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("session-manager-plugin does not resolve", result.stdout + result.stderr)
        self.assertFalse((self.repo / ".cache/stage-c-preflight/receipt.json").exists())
