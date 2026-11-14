"""Round280 regressions for the changed L4 paths, without provider access."""

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from inference_platform.l4_compat import requests
from inference_platform.package_a_operator import validate_review_marker

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
if os.environ.get("L4_SCRIPT_OVERLAY"):
    sys.path.insert(0, os.environ["L4_SCRIPT_OVERLAY"])
import l4_compat_controller as controller
import l4_compat_host as runner
from l4_compat_deadline import supervise


class RevisionTests(unittest.TestCase):
    def test_one_token_separate_finish_refuses_cancellation_intent(self):
        from inference_platform import inf037b_live
        from inference_platform.inf037b_live import ClientSSEAdapter, LiveRows

        retained = []
        client = ClientSSEAdapter(
            LiveRows("l4", "test"),
            "gateway0",
            "a" * 64,
            retain=lambda lo, hi, body, metadata: retained.append(metadata),
        )
        response = Mock(status=200)
        response.getheaders.return_value = []
        response.getheader.return_value = "gateway-owned-id"
        response.read1.side_effect = [
            b'data: {"choices":[{"index":0,"delta":{"content":"x"},"finish_reason":null}]}\n\n',
            b'data: {"choices":[{"index":0,"delta":{},"finish_reason":"length"}]}\n\n',
            b"",
        ]
        connection = Mock(sock=None)
        connection.getresponse.return_value = response
        with patch.object(inf037b_live.http.client, "HTTPConnection", return_value=connection):
            rows = client.request(
                "http://localhost/v1/chat/completions",
                {"max_tokens": 1},
                {"request_id": "offer", "offer_index": 0, "prefix_id": "p", "scheduled_ms": 0},
                credential="test",
                local_test=True,
                cancel_after_content=True,
            )
        self.assertFalse(any(row["payload"]["event"] == "cancel" for row in rows))
        self.assertTrue(
            any(row.get("error") == "client_cancel_already_complete" for row in retained)
        )

    def test_controller_uses_l4_marker_tuple(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "terraform").mkdir()
            (root / "terraform/create.tfplan").write_bytes(b"plan")
            plan = controller.sha(root / "terraform/create.tfplan")
            (root / "manifest.json").write_text(
                json.dumps({"sealed_plans": {"create_sha256": plan}})
            )
            required = (plan, controller.sha(root / "manifest.json"), "c" * 40)
            review = (
                "\n## Claude review rounds\n\n### Round 280\n"
                "- Review basis: COMMITTED\n- Verdict: NO_BLOCKING_FINDINGS\n"
                "- DEC-092 L4 PLAN APPROVED " + " ".join(required) + "\n\n## Findings\n"
            )
            args = SimpleNamespace(
                directory=root, owner_approved_hash=plan, review_target=required[2]
            )
            with (
                patch.object(controller, "git", return_value=review.encode()),
                patch.object(controller.os, "name", "nt"),
            ):
                with self.assertRaises(FileNotFoundError):
                    controller.execute(args)  # valid L4 marker reaches the next source-binding gate

    def test_l4_ports_credentials_and_reservations_are_per_attempt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = {"session_manager_plugin_path": "fake", "operator_tools": {}}
            (root / "manifest.json").write_text(json.dumps(manifest))
            ports = []
            for name in ("first", "second"):
                attempt = root / name
                attempt.mkdir()
                with patch.dict(os.environ, L4_ATTEMPT_DIRECTORY=str(attempt)):
                    ports.append(controller.L4Ports(root, manifest))
            self.assertNotEqual(ports[0].token, ports[1].token)
            self.assertNotEqual(ports[0].runtime, ports[1].runtime)
            self.assertFalse((root / "control-token.secret").exists())

    def test_marker_prefix_and_tuple_rules(self):
        required = ("a" * 64, "b" * 64, "c" * 40)
        prefix = "DEC-092 L4 PLAN APPROVED"
        review = (
            "\n## Claude review rounds\n\n### Round 280\n"
            "- Review basis: COMMITTED\n- Verdict: NO_BLOCKING_FINDINGS\n"
            "- " + prefix + " " + " ".join(required) + "\n\n## Findings\n"
        )
        validate_review_marker(review, required, prefix=prefix)
        for bad in (
            review.replace(prefix, "DEC-077 CPU PLAN APPROVED"),
            review.replace("COMMITTED", "PROVISIONAL"),
            review.replace("NO_BLOCKING_FINDINGS", "CHANGES_REQUESTED"),
            review.replace(required[0], "d" * 64),
            review + "\n- " + prefix + " " + " ".join(required),
            review.replace(
                "\n\n## Findings", "\n- " + prefix + " " + " ".join(required) + "\n\n## Findings"
            ),
        ):
            with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, "marker_required"):
                validate_review_marker(bad, required, prefix=prefix)

    def test_same_supervisor_command_reruns_with_separate_attempt_and_released_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code = "import pathlib,os; p=pathlib.Path(os.environ['L4_ATTEMPT_DIRECTORY']); (p/'child').touch()"
            commands = {
                k: [sys.executable, "-c", code] for k in ("controller", "cleanup", "inventory")
            }
            first = supervise(commands, root / "supervisor", work_seconds=3, cleanup_seconds=3)
            second = supervise(commands, root / "supervisor", work_seconds=3, cleanup_seconds=3)
            self.assertTrue(first["complete"] and second["complete"])
            self.assertNotEqual(first["attempt_directory"], second["attempt_directory"])
            self.assertFalse((root / "supervisor/supervisor.lock").exists())
            (root / "supervisor/supervisor.lock").touch()
            with self.assertRaises(FileExistsError):
                supervise(commands, root / "supervisor", work_seconds=3, cleanup_seconds=3)

    def test_packet_lock_fences_other_output_without_cleaning_its_owner(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock = root / "supervisor.lock"
            lock.write_text("other owner")
            commands = {"controller": [sys.executable, "-c", "pass", "--directory", str(root)]}
            with self.assertRaises(FileExistsError):
                supervise(commands, root / "other-output", work_seconds=3, cleanup_seconds=3)
            self.assertEqual(lock.read_text(), "other owner")
            self.assertFalse((root / "other-output/supervisor.lock").exists())

    def test_no_state_inventory_empty_but_existing_state_errors_propagate(self):
        with tempfile.TemporaryDirectory() as directory:
            ports = controller.L4Ports.__new__(controller.L4Ports)
            ports.directory, ports.runtime = Path(directory), Path(directory)
            ports.manifest = {"operator_tools": {"terraform": {"path": "terraform"}}}
            ports.instance_ids = lambda: []
            ports.aws = lambda *a: {
                "Volumes": [],
                "NetworkInterfaces": [],
                "Vpcs": [],
                "Roles": [],
                "InstanceProfiles": [],
            }
            with patch.object(controller.subprocess, "check_output") as state:
                self.assertTrue(ports.inventory(time.time() + 5)["empty"])
                state.assert_not_called()
                (ports.directory / "terraform").mkdir()
                (ports.directory / "terraform/terraform.tfstate").touch()
                state.side_effect = subprocess.CalledProcessError(1, "terraform")
                with self.assertRaises(subprocess.CalledProcessError):
                    ports.inventory(time.time() + 5)

    def test_engine_death_refuses_before_health_request(self):
        instance = runner.Run.__new__(runner.Run)
        instance.deadline, instance.children, instance.containers = (
            time.time() + 10,
            [],
            ["l4-engine"],
        )
        instance.call = Mock(return_value=b"false\n")
        with patch.object(runner.urllib.request, "urlopen") as health:
            with self.assertRaisesRegex(ValueError, "engine_died"):
                instance.ready("http://127.0.0.1:8000/health")
            health.assert_not_called()

    def test_redis_retries_then_pong_and_bounds_persistent_failure(self):
        instance = runner.Run.__new__(runner.Run)
        instance.deadline = time.time() + 20
        instance.call = Mock(
            side_effect=[subprocess.CalledProcessError(1, "redis"), b"LOADING", b"PONG\n"]
        )
        with patch.object(runner.time, "sleep"):
            instance.redis_ready()
        self.assertEqual(instance.call.call_count, 3)
        instance.deadline = time.time() + 0.05
        instance.call = Mock(return_value=b"LOADING")
        with patch.object(runner.time, "sleep", side_effect=AssertionError("unbounded retry")):
            with self.assertRaisesRegex(ValueError, "redis_readiness_deadline"):
                instance.redis_ready()

    def test_first_status_has_sixty_second_bound_and_ssm_wait_keeps_log(self):
        instance = controller.L4Ports.__new__(controller.L4Ports)
        instance.host, instance.token, instance.manifest_hash = "i-fake", "secret", "a" * 64
        instance.origin = time.time()
        instance.aws = Mock(return_value={"InstanceInformationList": [{"PingStatus": "Online"}]})
        instance.ssm, instance.request = Mock(), Mock()
        instance.bootstrap(time.time() + 2700)
        end = instance.request.call_args.kwargs["end"]
        self.assertLessEqual(end - time.time(), 60)
        shell = instance.ssm.call_args.args[1]
        self.assertIn("cat /opt/dec077/host.log; exit 1", shell[-1])

    def test_audit_probes_retained_and_duplicate_chat_ids_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            instance = runner.Run.__new__(runner.Run)
            instance.output, instance.packet = root, root
            (root / "overlay").mkdir()
            (root / "overlay/native-manifest.json").write_text("{}")
            (root / "native-events.json").write_text('{"events":[],"origin":{}}')
            instance.results = []
            audit = [
                {"method": "GET", "uri": uri, "body": "", "request_id": ""}
                for uri in ("/health", "/metrics")
            ]
            gateways = {}
            for row in requests():
                rid = row["id"]
                instance.results.append(
                    {**row, "request_ids": [rid], "duration_seconds": 1, "cancel_ns": None}
                )
                audit.append(
                    {
                        "method": "POST",
                        "uri": "/v1/chat/completions",
                        "body": json.dumps({**row["payload"], "ignore_eos": True}),
                        "request_id": rid,
                    }
                )
                name = f"phase{row['slot']}-{row['gateway']}-events.jsonl"
                gateways.setdefault(name, []).extend(
                    [
                        {"event": event, "data": {"request_id": rid, "result": "released"}}
                        for event in ("upstream_close", "release")
                    ]
                )
            for name, rows in gateways.items():
                (root / name).write_text("\n".join(json.dumps(r) for r in rows))

            def write():
                (root / "upstream.jsonl").write_text("\n".join(json.dumps(r) for r in audit))

            write()
            with patch.object(runner, "native_summary", return_value={}):
                instance.analyze()
                report = json.loads((root / "compatibility.json").read_bytes())
                self.assertEqual(
                    report["audit_rows"],
                    {"total": 9, "chat": 7, "health": 1, "metrics": 1, "other": 0},
                )
                audit[-1]["request_id"] = audit[-2]["request_id"]
                write()
                with self.assertRaisesRegex(ValueError, "audit_chat_inventory"):
                    instance.analyze()


if __name__ == "__main__":
    unittest.main()
