"""Linux durability E2E launch and retained byte bindings on any operator host."""

import copy
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.append(str(Path(__file__).resolve().parents[1]))
import package_a_local_preflight as preflight  # noqa: E402
from inference_platform.package_a_cloud import sha
from inference_platform.package_a_operator import (
    bind_linux_e2e_files,
    validate_linux_e2e_receipt,
)


class LinuxE2ETests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def exercise(self, *, fail=False, remaining=""):
        evidence, calls = {}, []

        def run(argv, *, output, **kw):
            argv = list(map(str, argv))
            calls.append(argv)
            if argv[0] == "go":
                self.assertEqual(
                    [kw["env"][k] for k in ("GOOS", "GOARCH", "CGO_ENABLED")],
                    ["linux", "amd64", "0"],
                )
                Path(argv[argv.index("-o") + 1]).write_bytes(b"linux-gateway")
            if argv[:2] == ["docker", "run"]:
                self.assertIn("container:owned-redis", argv)
                self.assertIn(preflight.LINUX_E2E_IMAGE, argv)
                self.assertIn("M5_PACKAGE_A_BIN=/tmp/gateway", argv)
                if fail:
                    raise RuntimeError("injected e2e failure")
            log = remaining if argv[:2] == ["docker", "ps"] else "Ran 1 test\nOK\n"
            output.write_text(log)
            return {
                "command": argv,
                "exit_code": 0,
                "log": output.name,
                "log_sha256": sha(output),
            }, log

        with patch.object(preflight, "run", side_effect=run):
            try:
                preflight.run_linux_gateway_e2e(self.root, "owned-redis", evidence)
            finally:
                self.evidence, self.calls = evidence, calls
        return evidence

    def test_real_linux_launch_and_byte_binding(self):
        receipt = self.exercise()
        validate_linux_e2e_receipt(receipt)
        bind_linux_e2e_files(receipt, self.root)
        self.assertTrue(receipt["container_removed"])
        self.assertEqual(self.calls[-2][:3], ["docker", "rm", "-f"])

    def test_failed_e2e_still_cleans_owned_container(self):
        with self.assertRaisesRegex(RuntimeError, "injected e2e failure"):
            self.exercise(fail=True)
        self.assertTrue(self.evidence["container_removed"])
        self.assertEqual(self.calls[-1][:3], ["docker", "ps", "-aq"])

    def test_cleanup_remaining_container_refuses(self):
        with self.assertRaisesRegex(ValueError, "linux_e2e_cleanup_unverified"):
            self.exercise(remaining="still-owned-id\n")

    def test_runtime_refuses_each_missing_or_wrong_binding(self):
        good = self.exercise()
        for key, value in (
            ("runtime", "windows-native"),
            ("python_image", "unpinned"),
            ("container_removed", False),
            ("build", {}),
            ("build", {**good["build"], "GOOS": "windows"}),
            ("build", {**good["build"], "exit_code": 1}),
            ("build", {**good["build"], "binary_sha256": "invalid"}),
        ):
            with (
                self.subTest(key=key, value=value),
                self.assertRaisesRegex(ValueError, "linux_e2e_preflight_unverified"),
            ):
                validate_linux_e2e_receipt({**good, key: value})

    def test_changed_log_refuses(self):
        good = self.exercise()
        for name in ("build", "cleanup", "verify_removed"):
            wrong = copy.deepcopy(good)
            wrong[name]["log_sha256"] = "a" * 64
            with self.assertRaisesRegex(ValueError, "linux_e2e_log_missing_or_changed"):
                bind_linux_e2e_files(wrong, self.root)

    def test_changed_binary_refuses(self):
        good = self.exercise()
        (self.root / good["build"]["binary_path"]).write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "linux_e2e_binary_missing_or_changed"):
            bind_linux_e2e_files(good, self.root)
