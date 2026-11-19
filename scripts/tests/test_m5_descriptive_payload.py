import hashlib
import json
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from inference_platform.m5_descriptive_operator import session_timing
from inference_platform.package_a_cloud import verified_source
from inference_platform.package_a_operator import Ports
from m5_descriptive_payload import (
    git,
    produce,
    source_paths,
    transfer_bound,
    validate_reads,
)
from package_a_host import stage_sparse_payload, verify_sparse_payload


def fixture(root):
    root.mkdir()
    git(root, "init", "-b", "main")
    for name, data in {
        "host.py": b"a = ROOT / 'python/src'\n",
        "python/src/example.py": b"value = 1\n",
        "docs/evidence.txt": b"not host input\n" * 1000,
        ".gitignore": b".cache/\n.venv/\n",
        ".gitattributes": b"* text=auto eol=lf\n",
    }.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    git(root, "add", ".")
    git(
        root,
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "-m",
        "fixture",
    )
    return git(root, "rev-parse", "HEAD").decode().strip()


class PayloadTests(unittest.TestCase):
    def test_current_host_read_graph_excludes_history_and_contains_build_inputs(self):
        paths = source_paths(Path(__file__).resolve().parents[2])
        self.assertNotIn("docs", paths)
        self.assertNotIn("experiments", paths)
        self.assertTrue(
            {
                "python",
                "scripts",
                "deploy",
                "cmd",
                "internal",
                "go.mod",
                "go.sum",
                ".tool-versions",
            }
            <= set(paths),
            paths,
        )

    def test_isolated_rehearsal_tunnel_uses_bound_test_port(self):
        from inference_platform.r1_cloud_operator import Operator
        from unittest.mock import Mock

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            owner = SimpleNamespace(
                repo=root,
                runtime=root,
                inputs={
                    "aws_profile": "fixture",
                    "region": "us-east-1",
                    "session_manager_plugin_path": "plugin",
                    "ssm_remote_port": 22281,
                },
            )
            child = Mock(pid=None)
            with patch(
                "inference_platform.r1_cloud_operator.subprocess.Popen",
                return_value=child,
            ) as popen:
                Operator.tunnel(owner, "fixture-host")
            argv = popen.call_args.args[0]
            self.assertEqual(
                json.loads(argv[argv.index("--parameters") + 1])["portNumber"],
                ["22281"],
            )

    def test_transfer_publication_leaves_runner_directory_uncreated(self):
        import subprocess
        import sys
        from m5_descriptive_transfer_check import publish_transfer_record

        if sys.platform == "win32":
            self.skipTest("real POSIX shell runs on AWS Linux")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            def ssm(command):
                result = subprocess.run(
                    ["sh", "-c", command], check=True, capture_output=True
                )
                return {"StandardOutputContent": result.stdout.decode()}

            publish_transfer_record(ssm, {"complete": True}, root)
            self.assertEqual(
                json.loads((root / "payload-transfer.json").read_text()),
                {"complete": True},
            )
            self.assertFalse((root / "results/runner").exists())
            (root / "results/runner").mkdir(parents=True, exist_ok=False)

    def test_remote_marker_generation_uses_posix_paths_on_windows(self):
        from pathlib import PureWindowsPath
        from m5_descriptive_transfer_check import publish_transfer_record

        calls = []

        def ssm(command):
            calls.append(command)
            return {
                "StandardOutputContent": hashlib.sha256(
                    b'{"complete": true}'
                ).hexdigest()
                + "  /opt/dec077/payload-transfer.json\n"
            }

        with patch("m5_descriptive_transfer_check.Path", PureWindowsPath, create=True):
            publish_transfer_record(ssm, {"complete": True})
        self.assertNotIn("\\", calls[0])
        self.assertIn(" > /opt/dec077/payload-transfer.json;", calls[0])
        self.assertTrue(
            calls[0].endswith("sha256sum /opt/dec077/payload-transfer.json")
        )
        with self.assertRaisesRegex(ValueError, "transfer_marker_readback"):
            publish_transfer_record(
                lambda c: {"StandardOutputContent": "wrong"}, {"complete": True}
            )

    def test_real_pack_preserves_commit_trees_and_existing_executing_checks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, restored = root / "source", root / "restored"
            commit = fixture(source)
            with patch("m5_descriptive_payload.ENTRYPOINTS", ("host.py",)):
                binding = produce(source, commit, root / "source.bundle")
                validate_reads(source, binding["paths"])
            result = stage_sparse_payload(restored, root / "source.bundle", binding)
            self.assertTrue(result["verified"])
            self.assertFalse((restored / "docs").exists())
            self.assertEqual(
                git(restored, "rev-parse", "HEAD").decode().strip(), commit
            )
            self.assertEqual(
                binding["paths"]["python"],
                git(source, "rev-parse", commit + ":python").decode().strip(),
            )
            hashes = {
                "python/src/example.py": hashlib.sha256(b"value = 1\n").hexdigest()
            }
            self.assertEqual(
                verified_source(restored, commit, hashes)["commit"], commit
            )
            (restored / "python/src/example.py").write_bytes(b"value = 2\n")
            with self.assertRaisesRegex(ValueError, "payload_tree:python"):
                verify_sparse_payload(restored, binding)

    def test_runtime_unlisted_read_refuses_even_for_a_dynamic_missing_path(self):
        from inference_platform.m5_payload_guard import install_read_guard

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            deactivate = install_read_guard(root, {"python": "fixture"})
            try:
                name = "UNLISTED" + ".txt"
                with self.assertRaisesRegex(
                    ValueError, "payload_unlisted_read:UNLISTED.txt"
                ):
                    (root / name).read_bytes()
            finally:
                deactivate()

    def test_new_unlisted_host_read_refuses_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "source"
            commit = fixture(root)
            with patch("m5_descriptive_payload.ENTRYPOINTS", ("host.py",)):
                binding = produce(root, commit, root.parent / "source.bundle")
                (root / "host.py").write_text("a = ROOT / 'UNLISTED.txt'\n")
                with self.assertRaisesRegex(
                    ValueError, "payload_unlisted_read:UNLISTED.txt"
                ):
                    validate_reads(root, binding["paths"])

    def test_two_pass_slow_link_bound_is_reserved_inside_fixed_deadline(self):
        self.assertEqual(transfer_bound(200001), 66)
        self.assertEqual(transfer_bound(150051721), 3062)
        timing = session_timing(640, transfer_bound(138550001))
        self.assertEqual(timing["source_upload_budget_seconds"], 2832)
        self.assertEqual(timing["infrastructure_before_capacity_wait_seconds"], 3272)
        self.assertEqual(timing["capacity_wait_budget_seconds"], 49)
        self.assertEqual(timing["remaining_infrastructure_seconds"], 3223)
        self.assertEqual(timing["session_seconds"], 18000)
        oversized = session_timing(640, 3062)
        self.assertEqual(oversized["capacity_wait_budget_seconds"], 0)
        self.assertLess(
            oversized["remaining_infrastructure_seconds"],
            oversized["apply_through_staging_reserve_seconds"],
        )

    def test_chunk_receipts_survive_success_and_failed_exchange(self):
        for fail in (False, True):
            with self.subTest(fail=fail), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "source.bundle").write_bytes(b"source")
                owner = SimpleNamespace(
                    directory=root,
                    runtime=root,
                    reconnects=2,
                    forward_sessions=3,
                    manifest={
                        "upload_timeout_s": 60,
                        "bundle_sha256": hashlib.sha256(b"source").hexdigest(),
                    },
                    manifest_bytes=b"{}",
                    phase=lambda name, operation: operation(),
                )

                def request(path, *args, **kwargs):
                    if path.startswith("/upload/") and fail:
                        raise TimeoutError("forced")
                    return (json.dumps({"offset": 0}).encode(), {})

                owner.request = request
                if fail:
                    with self.assertRaisesRegex(TimeoutError, "forced"):
                        Ports.upload(owner, time.time() + 60)
                else:
                    Ports.upload(owner, time.time() + 60)
                record = json.loads((root / "source-transfer.jsonl").read_text())
                self.assertEqual((record["offset"], record["bytes"]), (0, 6))
                self.assertEqual(
                    (record["reconnect_count"], record["forward_session_count"]), (2, 3)
                )
                self.assertGreaterEqual(record["elapsed_s"], 0)
                self.assertEqual(record["error"] is not None, fail)
