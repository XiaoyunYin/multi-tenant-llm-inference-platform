"""Verified frozen evidence survives every archive-deduplication failure."""

import json
import os
import subprocess
import tempfile
import time
import unittest
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from inference_platform.routine_aws_tests import prune_verified_run, save, selection, sha


class RoutinePruneTest(unittest.TestCase):
    def test_descriptive_rehearsal_is_a_closed_boolean_selector(self):
        self.assertEqual(
            selection({"descriptive_eks_rehearsal": True}), {"descriptive_eks_rehearsal": True}
        )
        for invalid in ("command", 1, ["aws", "eks"]):
            with (
                self.subTest(invalid=invalid),
                self.assertRaisesRegex(ValueError, "descriptive_eks_rehearsal"),
            ):
                selection({"descriptive_eks_rehearsal": invalid})

    def test_payload_validation_selector_is_boolean_and_history_bundle_unchanged(self):
        self.assertEqual(
            selection({"descriptive_payload_validation": True}),
            {"descriptive_payload_validation": True},
        )
        with self.assertRaisesRegex(ValueError, "descriptive_payload_validation"):
            selection({"descriptive_payload_validation": "shell"})

    def fixture(self, root):
        directory = root / ".cache/routine-tests/run"
        archive = directory / "operator/receipts.tar.gz"
        archive.parent.mkdir(parents=True)
        archive.write_bytes(b"frozen receipts")
        save(
            directory / "lifecycle.json",
            {
                "retrieval": {"complete": True, "sha256": sha(archive)},
                "cleanup": {"verified": True},
            },
        )
        store = root / ".cache/evidence-store" / sha(archive) / archive.name
        return directory, archive, store

    def test_verified_archives_share_storage_and_second_prune_frees_nothing(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            directory, archive, store = self.fixture(root)
            result = prune_verified_run(directory, root=root)
            self.assertEqual(result["status"], "PASS")
            self.assertEqual(result["logical_bytes_freed"], len(b"frozen receipts"))
            self.assertTrue(archive.samefile(store))
            self.assertEqual(prune_verified_run(directory, root=root)["logical_bytes_freed"], 0)
            receipt = json.loads((directory / "lifecycle.json").read_bytes())
            self.assertEqual(receipt["archive_storage"]["mode"], "hardlink")
            self.assertTrue(receipt["cleanup"]["verified"])

    def test_bad_store_or_link_or_replace_keeps_original_evidence(self):
        for fault in ("store", "link", "replace"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                directory, archive, store = self.fixture(root)
                if fault == "store":
                    store.parent.mkdir(parents=True)
                    store.write_bytes(b"corrupt store")
                    result = prune_verified_run(directory, root=root)
                else:
                    target = "os.link" if fault == "link" else "os.replace"
                    original = os.link if fault == "link" else os.replace

                    def fail_archive_only(
                        source, destination, *, fault=fault, archive=archive, original=original
                    ):
                        if fault == "link" or Path(destination) == archive:
                            raise OSError("archive replacement denied")
                        return original(source, destination)

                    with patch(
                        "inference_platform.routine_aws_tests." + target,
                        side_effect=fail_archive_only,
                    ):
                        result = prune_verified_run(directory, root=root)
                self.assertEqual(result["status"], "FAILED")
                self.assertEqual(archive.read_bytes(), b"frozen receipts")
                self.assertFalse(archive.with_name("receipts.verified-link").exists())
                self.assertTrue(
                    json.loads((directory / "lifecycle.json").read_bytes())["cleanup"]["verified"]
                )

    def test_existing_link_candidate_is_never_deleted_on_refusal(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            directory, archive, _ = self.fixture(root)
            foreign = archive.with_name("receipts.verified-link")
            foreign.write_bytes(b"preexisting pending evidence")
            self.assertEqual(prune_verified_run(directory, root=root)["status"], "FAILED")
            self.assertEqual(foreign.read_bytes(), b"preexisting pending evidence")
            self.assertEqual(archive.read_bytes(), b"frozen receipts")


class PublicIdentityTests(unittest.TestCase):
    def workflow(self):
        return (
            Path(__file__).resolve().parents[2] / "scripts/public_snapshot/ci.public.yml"
        ).read_text()

    def test_preparation_is_unique_to_python_job_and_read_literally(self):
        from inference_platform.routine_snapshot import preparation_command

        body = self.workflow()
        self.assertEqual(body.count("id: service-account-fixture"), 1)
        self.assertNotIn("service-account-fixture", body.split("\n  python:\n")[0])
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "workflow.yml"
            changed = body.replace("sudo -n install -d", "sudo -n install -d -m 0750")
            path.write_text(changed)
            self.assertIn("install -d -m 0750", preparation_command(path))
            for invalid in (
                changed.replace("  python:", "  other:"),
                changed + "\n        id: service-account-fixture\n",
            ):
                path.write_text(invalid)
                with self.assertRaisesRegex(ValueError, "workflow_preparation"):
                    preparation_command(path)

    def test_process_launch_has_real_nonroot_uid_guard_and_owned_group(self):
        from inference_platform.routine_snapshot import public_command, public_process

        user = SimpleNamespace(pw_name="public-fixture", pw_uid=1001, pw_gid=1001)
        with self.assertRaisesRegex(ValueError, "root_forbidden"):
            public_command(SimpleNamespace(pw_uid=0), ["pwsh"])
        with (
            patch("inference_platform.routine_snapshot.subprocess.Popen") as launch,
            patch("inference_platform.routine_snapshot.os.killpg"),
        ):
            launch.return_value.communicate.return_value = (b"witness", None)
            launch.return_value.returncode = 0
            result = public_process(
                user,
                ["pwsh", "-File", "scripts/check-public.ps1"],
                cwd="public-tree",
                env={"PUBLIC_ONLY": "yes", "PATH": "/usr/bin:/bin"},
                deadline=time.time() + 30,
            )
            argv = launch.call_args.args[0]
            self.assertEqual(
                argv[:4],
                ["/usr/sbin/runuser", "--user", "public-fixture", "--preserve-environment"],
            )
            self.assertNotIn("/usr/sbin", launch.call_args.kwargs["env"]["PATH"].split(":"))
            self.assertIn('test "$(/usr/bin/id -u)" -eq "$1"', " ".join(argv))
            self.assertIn("1001", argv)
            self.assertEqual(argv[-3:], ["pwsh", "-File", "scripts/check-public.ps1"])
            self.assertTrue(launch.call_args.kwargs["start_new_session"])
            self.assertEqual(result.returncode, 0)

    @unittest.skipUnless(
        hasattr(os, "geteuid") and os.geteuid() == 0, "POSIX host ownership fixture"
    )
    def test_real_uid_launcher_works_with_public_path_without_sbin(self):
        import pwd

        from inference_platform.routine_snapshot import public_process

        user = pwd.getpwnam("nobody")
        result = public_process(
            user,
            ["/usr/bin/id", "-u"],
            cwd="/",
            env={"PATH": "/usr/bin:/bin"},
            stdout=subprocess.PIPE,
            deadline=time.time() + 10,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(int(result.stdout), user.pw_uid)
        self.assertGreater(int(result.stdout), 0)

    def test_exported_workflow_filename_comes_from_the_producer_mapping(self):
        from inference_platform.routine_snapshot import exported_workflow

        with tempfile.TemporaryDirectory() as folder:
            template = Path(folder) / "ci.public.yml"
            policy = template.with_name("allowlist.json")
            source = "scripts/public_snapshot/ci.public.yml"
            policy.write_text(
                json.dumps({"replacements": {".github/workflows/another.yml": source}})
            )
            self.assertEqual(exported_workflow(template), Path(".github/workflows/another.yml"))
            for mapping in (
                {"../../credentials": source},
                {".github/workflows/a.yml": source, ".github/workflows/b.yml": source},
            ):
                policy.write_text(json.dumps({"replacements": mapping}))
                with self.assertRaisesRegex(ValueError, "workflow_export_mapping"):
                    exported_workflow(template)

    def test_host_uses_template_command_and_rejects_an_unrelated_negative_error(self):
        from inference_platform import routine_snapshot as runner

        user = SimpleNamespace(pw_name="public-fixture", pw_uid=1001, pw_gid=1001)
        for permission in (True, False):
            with self.subTest(permission=permission), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                tree, output = root / "snapshot", root / "results"
                output.mkdir()
                command = self.workflow().replace(
                    "sudo -n install -d", "sudo -n install -d -m 0750"
                )
                template = root / "ci.public.yml"
                template.write_text(command)
                policy = json.loads(
                    (
                        Path(__file__).resolve().parents[2]
                        / "scripts/public_snapshot/allowlist.json"
                    ).read_bytes()
                )
                template.with_name("allowlist.json").write_text(json.dumps(policy))
                name = next(
                    k
                    for k, v in policy["replacements"].items()
                    if v == "scripts/public_snapshot/ci.public.yml"
                )
                exported = tree / name
                exported.parent.mkdir(parents=True)
                exported.write_text(command)

                def child(_user, argv, *, permission=permission, **kwargs):
                    if "-c" in argv:
                        return subprocess.CompletedProcess(
                            argv,
                            0,
                            json.dumps(
                                {"uid": 1001, "gid": 1001, "var_run_writable": False}
                            ).encode(),
                        )
                    if "unittest" in argv:
                        body = (
                            (
                                "PermissionError: [Errno 13] /var/run/secrets\nRan 1 test\n"
                                "FAILED (errors=1)\n"
                            )
                            if permission
                            else "ModuleNotFoundError: unavailable\n"
                        )
                        kwargs["stdout"].write(body.encode())
                        return subprocess.CompletedProcess(argv, 1)
                    return subprocess.CompletedProcess(argv, 0)

                public_env = {"M5_PACKAGE_A_BIN": str(tree / ".cache/kind-build/gateway")}
                with (
                    patch.object(
                        runner,
                        "public_workspace",
                        return_value=nullcontext((user, tree, public_env, {})),
                    ),
                    patch.object(runner, "public_process", side_effect=child),
                    patch("inference_platform.routine_snapshot.subprocess.run") as root_command,
                ):
                    if permission:
                        runner.run_public_check(
                            tree, template, root / "tools", output, time.time() + 60
                        )
                    else:
                        with self.assertRaisesRegex(ValueError, "negative_control_not_permission"):
                            runner.run_public_check(
                                tree, template, root / "tools", output, time.time() + 60
                            )
                    root_command.assert_called_once()  # Only sudo installation may run as root.
                receipt = json.loads((output / "public-identity.json").read_bytes())
                self.assertEqual(receipt["complete"], permission)
                self.assertTrue(all(p["argv"][0] == "/usr/sbin/runuser" for p in receipt["phases"]))
                if permission:
                    prepared = next(
                        p for p in receipt["phases"] if p["name"] == "workflow_preparation"
                    )
                    self.assertEqual(prepared["argv"][-1], runner.preparation_command(template))
                    self.assertEqual(receipt["phases"][-1]["argv"][-1], "scripts/check-public.ps1")
                    self.assertTrue(
                        json.loads((output / "public-permission-negative.json").read_bytes())[
                            "verified"
                        ]
                    )

    def test_public_timeout_kills_only_its_owned_process_group(self):
        import signal

        from inference_platform.routine_snapshot import public_process

        user = SimpleNamespace(pw_name="public-fixture", pw_uid=1001, pw_gid=1001)
        with (
            patch("inference_platform.routine_snapshot.subprocess.Popen") as launch,
            patch("inference_platform.routine_snapshot.os.killpg") as kill,
        ):
            launch.return_value.pid = 123456
            launch.return_value.communicate.side_effect = subprocess.TimeoutExpired("fixture", 1)
            with self.assertRaises(subprocess.TimeoutExpired):
                public_process(user, ["pwsh"], cwd="public-tree", env={}, deadline=time.time() + 30)
            kill.assert_called_once_with(123456, signal.SIGKILL)
            launch.return_value.wait.assert_called_once()

    @unittest.skipUnless(
        hasattr(os, "geteuid") and os.geteuid() == 0, "POSIX host ownership fixture"
    )
    def test_public_workspace_restores_root_ownership_and_never_opens_private_parent(self):
        from inference_platform.routine_snapshot import public_workspace

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            private, tools = root / "private", root / "tools"
            private.mkdir(mode=0o700)
            tree = private / "snapshot"
            tree.mkdir()
            (tree / "tracked").write_bytes(b"public source")
            owner = tree.stat()
            for relative in (
                "go/bin/go",
                "python/bin/python3.12",
                "uv-x86_64-unknown-linux-gnu/uv",
            ):
                path = tools / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"pinned executable fixture")
                path.chmod(0o755)
            user = SimpleNamespace(pw_name="public-fixture", pw_uid=1001, pw_gid=1001)
            with (
                patch("pwd.getpwnam", return_value=user),
                patch.dict(
                    os.environ,
                    {"AWS_ACCESS_KEY_ID": "fixture", "TF_PLUGIN_CACHE_DIR": str(private)},
                ),
            ):
                with public_workspace(tree, tools) as (_, public_tree, env, _facts):
                    self.assertFalse(tree.exists())
                    self.assertEqual(public_tree.stat().st_uid, 1001)
                    self.assertEqual(private.stat().st_mode & 0o777, 0o700)
                    self.assertNotIn("AWS_ACCESS_KEY_ID", env)
                    self.assertNotIn("TF_PLUGIN_CACHE_DIR", env)
                    self.assertEqual(env["TMP"], env["TMPDIR"])
                    self.assertEqual(env["TEMP"], env["TMPDIR"])
                    self.assertEqual(env["AWS_EC2_METADATA_DISABLED"], "true")
                    self.assertNotIn(str(private), env["PYTHONPATH"])
                    self.assertTrue(Path(env["UV_PYTHON"]).exists())
                    gateway_parent = Path(env["M5_PACKAGE_A_BIN"]).parent
                    self.assertEqual(gateway_parent.stat().st_uid, user.pw_uid)
                    self.assertEqual(gateway_parent.stat().st_gid, user.pw_gid)
            self.assertEqual(tree.stat().st_uid, owner.st_uid)
            self.assertEqual((tree / "tracked").read_bytes(), b"public source")


class LinuxPrerequisiteTests(unittest.TestCase):
    def test_every_module_referencing_git_gets_the_stage_prerequisite(self):
        import ast
        import re

        from inference_platform.routine_aws_tests import linux_module_expression

        root = Path(__file__).resolve().parents[2]
        modules = set()
        for directory in (root / "python/tests", root / "scripts/tests"):
            for path in directory.glob("test_*.py"):
                # Conservative inventory includes command strings, helper calls
                # and executable probes, rather than guessing a named allowlist.
                if any(
                    isinstance(n, ast.Constant)
                    and isinstance(n.value, str)
                    and re.search(r"\bgit\b", n.value, re.IGNORECASE)
                    for n in ast.walk(ast.parse(path.read_bytes()))
                ):
                    modules.add(path.stem)
        self.assertIn("test_m5_descriptive_provider", modules)
        self.assertIn("test_public_snapshot", modules)
        for name in sorted(modules):
            with self.subTest(module=name):
                tree = ast.parse(linux_module_expression([name]))
                calls = [
                    n
                    for n in tree.body
                    if isinstance(n, ast.Expr) and isinstance(n.value, ast.Call)
                ]
                commands = [ast.literal_eval(n.value.args[0]) for n in calls[:3]]
                self.assertEqual(commands[0], ["apt-get", "update"])
                self.assertEqual(
                    commands[1], ["apt-get", "install", "-y", "--no-install-recommends", "git"]
                )
                self.assertEqual(commands[2], ["git", "--version"])
                self.assertTrue(
                    all(
                        any(
                            k.arg == "check" and ast.literal_eval(k.value) for k in n.value.keywords
                        )
                        for n in calls[:3]
                    )
                )
                self.assertIn(repr([name]), linux_module_expression([name]))

    def test_unknown_future_module_and_non_git_module_get_git_too(self):
        from inference_platform.routine_aws_tests import linux_module_expression

        for name in ("test_future_consumer", "test_records", "test_m5_descriptive_provider"):
            self.assertIn("['git','--version']", linux_module_expression([name]))


if __name__ == "__main__":
    unittest.main()
