from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from inference_platform.package_a_operator import (
    GateALifecycle,
    GateAOperator,
    Ports,
    bootstrap_shell,
    gate_a_command_line_records,
    gate_a_pre_p_operation_window,
    gate_a_remote_input_paths,
    presigned_s3_get,
)
from inference_platform.r1_cloud_operator import Operator, windows_command_line_length

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from gate_a_operator_rehearsal import render_gate_a_user_data  # noqa: E402
from package_a_host import validate_gate_a_s3_get_url  # noqa: E402

from inference_platform.package_a_cloud import HOST_TIMER_S  # noqa: E402


class FakePorts:
    def __init__(self, *, failure=None):
        self.directory = Path(tempfile.mkdtemp())
        (self.directory / "terraform").mkdir()
        self.runtime = self.directory / "operator"
        self.runtime.mkdir()
        self.manifest = {
            "session": "r366-test-session",
            "bucket_name": "gate-a-test-bucket",
            "operator_tools": {
                "terraform": {"path": "terraform"},
                "aws": {"path": "aws"},
            },
        }
        self.inputs = {"aws_profile": "test"}
        self.failure = failure
        self.role_ports = [SimpleNamespace(role_name="receiver", ssm_online=True)]
        self.events = []
        self.volume_seen = False
        self.instance_seen = False
        self.bucket_exists = True
        self.s3_objects = [{"Key": "gate-a/r366-test-session/archive/fixture"}]

    def aws(self, service, operation, args):
        self.events.append((service, operation))
        if self.failure == "detach" and (service, operation) == ("ec2", "detach-volume"):
            raise RuntimeError("injected detach failure")
        if self.failure == "s3_delete" and (service, operation) == ("s3api", "delete-objects"):
            raise RuntimeError("injected S3 delete failure")
        if (service, operation) == ("ec2", "describe-volumes"):
            if not self.volume_seen:
                self.volume_seen = True
                return {
                    "Volumes": [
                        {
                            "VolumeId": "vol-0123456789abcdef0",
                            "Attachments": [{"InstanceId": "i-0123456789abcdef0"}],
                        }
                    ]
                }
            return {"Volumes": []}
        if (service, operation) == ("ec2", "describe-instances"):
            if "Name=tag:Role,Values=receiver" in args:
                return {"Reservations": [{"Instances": [{"InstanceId": "i-0123456789abcdef0"}]}]}
            if "Name=tag:Role,Values=sender,receiver" in args:
                return {
                    "Reservations": [
                        {
                            "Instances": [
                                {"InstanceId": "i-sender", "State": {"Name": "running"}},
                                {"InstanceId": "i-receiver", "State": {"Name": "running"}},
                            ]
                        }
                    ]
                }
            return {"Reservations": []}
        if (service, operation) == ("ec2", "describe-network-interfaces"):
            return {"NetworkInterfaces": []}
        if (service, operation) == ("ec2", "describe-vpcs"):
            return {"Vpcs": []}
        if (service, operation) == ("ec2", "describe-subnets"):
            return {"Subnets": []}
        if (service, operation) == ("ec2", "describe-route-tables"):
            return {"RouteTables": []}
        if (service, operation) == ("ec2", "describe-internet-gateways"):
            return {"InternetGateways": []}
        if (service, operation) == ("ec2", "describe-vpc-endpoints"):
            return {"VpcEndpoints": []}
        if (service, operation) == ("ec2", "describe-security-groups"):
            return {"SecurityGroups": []}
        if (service, operation) == ("ec2", "describe-nat-gateways"):
            return {"NatGateways": []}
        if (service, operation) == ("ec2", "describe-addresses"):
            return {"Addresses": []}
        if (service, operation) == ("iam", "list-roles"):
            return {"Roles": []}
        if (service, operation) == ("iam", "list-instance-profiles"):
            return {"InstanceProfiles": []}
        if (service, operation) == ("ssm", "send-command"):
            return {"Command": {"CommandId": "cmd-1"}}
        if (service, operation) == ("ssm", "get-command-invocation"):
            return {"Status": "Failed" if self.failure == "unmount" else "Success"}
        if (service, operation) == ("s3api", "list-buckets"):
            return {
                "Buckets": ([{"Name": self.manifest["bucket_name"]}] if self.bucket_exists else [])
            }
        if (service, operation) == ("s3api", "list-objects-v2"):
            return {"Contents": list(self.s3_objects)} if self.s3_objects else {}
        if (service, operation) == ("s3api", "delete-objects"):
            deleted = list(self.s3_objects)
            self.s3_objects.clear()
            payload = json.loads(args[args.index("--delete") + 1])
            if payload.get("Quiet") is True:
                return {}
            return {"Deleted": deleted}
        return {}

    def command(self, argv, end, name):
        self.events.append(("command", name))
        if self.failure == "waiter" and name == "gate-a-volume-detached":
            raise RuntimeError("injected detach waiter failure")
        if name == "gate-a-destroy":
            self.bucket_exists = False
        return {"exit": 0}

    def send_ssm_command(self, host, parameters, *, deadline=None, step="ssm.send-command"):
        return self.aws("ssm", "send-command", ["--parameters", "file://temporary.json"])


class GateAOperatorTests(unittest.TestCase):
    def test_teardown_skips_unmount_before_receiver_ssm_registration(self):
        ports = FakePorts()
        ports.role_ports[0].ssm_online = False
        operator = GateAOperator(ports)
        operator.role_ports = ports.role_ports
        with patch(
            "inference_platform.package_a_operator.subprocess.check_output", return_value=b""
        ):
            receipt = operator.teardown(10**20)
        self.assertTrue(receipt["complete"])
        self.assertTrue(receipt["inventory"]["empty"])
        self.assertIn({"step": "unmount", "status": "skipped_never_registered"}, receipt["events"])
        self.assertNotIn(("ssm", "send-command"), ports.events)
        self.assertIn(("ec2", "detach-volume"), ports.events)

    def test_gate_a_user_data_renderer_matches_templatefile_inputs_per_role(self):
        receiver = render_gate_a_user_data("receiver", "vol-0123456789abcdef0")
        sender = render_gate_a_user_data("sender", "")

        for role, rendered in (("receiver", receiver), ("sender", sender)):
            self.assertIn(f"printf '%s\\n' '{role}'", rendered)
            self.assertIn(
                f"systemd-run --unit=gate-a-maximum-lifetime --on-active={HOST_TIMER_S}s",
                rendered,
            )
            self.assertNotIn("${role}", rendered)
            self.assertNotIn("${host_timer_seconds}", rendered)
            self.assertNotIn("${recovery_volume_id}", rendered)
        self.assertIn("volume_id='vol-0123456789abcdef0'", receiver)
        self.assertIn(
            "${volume_id//-/}",
            receiver,
        )
        self.assertIn("volume_id=''", sender)
        with self.assertRaisesRegex(ValueError, "gate_a_user_data_role"):
            render_gate_a_user_data("unknown", "")

    def test_quiet_delete_teardown_records_count_and_completes_with_empty_inventory(self):
        ports = FakePorts()
        operator = GateAOperator(ports)
        operator.role_ports = ports.role_ports
        with patch(
            "inference_platform.package_a_operator.subprocess.check_output", return_value=b""
        ):
            receipt = operator.teardown(10**20)
        self.assertTrue(receipt["complete"])
        self.assertEqual(
            [event for event in receipt["events"]],
            [
                {"step": "unmount", "status": "Success", "command_id": "cmd-1"},
                {"step": "detach", "volume_id": "vol-0123456789abcdef0"},
                {
                    "step": "s3_delete",
                    "bucket": "gate-a-test-bucket",
                    "prefix": "gate-a/r366-test-session/",
                    "deleted": 1,
                    "pages": 1,
                },
                {"step": "destroy", "complete": True},
            ],
        )
        self.assertLess(
            ports.events.index(("ssm", "send-command")),
            ports.events.index(("ec2", "detach-volume")),
        )
        self.assertLess(
            ports.events.index(("ec2", "detach-volume")),
            ports.events.index(("s3api", "list-objects-v2")),
        )
        self.assertLess(
            ports.events.index(("s3api", "list-objects-v2")),
            ports.events.index(("command", "gate-a-destroy")),
        )
        self.assertLess(
            ports.events.index(("s3api", "delete-objects")),
            ports.events.index(("command", "gate-a-destroy")),
        )
        self.assertTrue(receipt["inventory"]["empty"])

    def test_each_pre_destroy_failure_terminates_hosts_then_destroys_and_inventories(self):
        for failure in ("unmount", "detach", "waiter", "s3_delete"):
            with self.subTest(failure=failure):
                ports = FakePorts(failure=failure)
                operator = GateAOperator(ports)
                operator.role_ports = ports.role_ports
                with patch(
                    "inference_platform.package_a_operator.subprocess.check_output",
                    return_value=b"",
                ):
                    receipt = operator.teardown(10**20)
                self.assertFalse(receipt["complete"])
                self.assertTrue(receipt["inventory"]["empty"])
                self.assertIn(("ec2", "terminate-instances"), ports.events)
                self.assertIn(("command", "gate-a-fallback-terminated"), ports.events)
                self.assertIn(("command", "gate-a-destroy"), ports.events)
                self.assertIn(("ec2", "describe-instances"), ports.events)
                self.assertLess(
                    ports.events.index(("ec2", "terminate-instances")),
                    ports.events.index(("command", "gate-a-destroy")),
                )
                inventory_index = (
                    len(ports.events) - 1 - ports.events[::-1].index(("ec2", "describe-instances"))
                )
                self.assertGreater(
                    inventory_index, ports.events.index(("command", "gate-a-destroy"))
                )

    def test_s3api_delete_empties_more_than_1000_keys_across_pages(self):
        class PagedPorts(FakePorts):
            def __init__(self):
                super().__init__()
                self.s3_objects = [
                    {"Key": f"gate-a/r366-test-session/input/{index:04d}"} for index in range(1001)
                ]
                self.page_calls = 0

            def aws(self, service, operation, args):
                self.events.append((service, operation))
                if (service, operation) == ("s3api", "list-objects-v2"):
                    self.page_calls += 1
                    if self.page_calls == 1:
                        objects = self.s3_objects[:1000]
                    elif self.page_calls == 2:
                        self.assert_continuation(args)
                        objects = list(self.s3_objects)
                    else:
                        objects = []
                    return {
                        "Contents": objects,
                        "IsTruncated": self.page_calls == 1,
                        "NextContinuationToken": "page-2" if self.page_calls == 1 else None,
                    }
                if (service, operation) == ("s3api", "delete-objects"):
                    payload = json.loads(args[args.index("--delete") + 1])
                    keys = {row["Key"] for row in payload["Objects"]}
                    self.s3_objects = [row for row in self.s3_objects if row["Key"] not in keys]
                    if payload.get("Quiet") is True:
                        return {}
                    return {"Deleted": payload["Objects"]}
                return super().aws(service, operation, args)

            @staticmethod
            def assert_continuation(args):
                if args[args.index("--continuation-token") + 1] != "page-2":
                    raise AssertionError("missing continuation token")

        ports = PagedPorts()
        receipt = GateAOperator(ports)._delete_s3_prefix()
        self.assertEqual(receipt["deleted"], 1001)
        self.assertEqual(receipt["pages"], 2)
        self.assertEqual(ports.page_calls, 3)  # two pages plus the final empty check
        self.assertEqual(ports.s3_objects, [])
        self.assertTrue(all(service == "s3api" for service, _ in ports.events))


class GateASsmTransportTests(unittest.TestCase):
    def test_bound_gate_a_command_lines_use_files_and_stay_under_windows_limit(self):
        with tempfile.TemporaryDirectory(prefix="gate-a-packet-very-long-runtime-") as temporary:
            records = gate_a_command_line_records(
                Path(temporary) / "bound-packet",
                {"region": "us-east-1"},
            )
        self.assertEqual(
            [row["step"] for row in records],
            [
                "receiver.readiness",
                "sender.readiness",
                "receiver.bootstrap",
                "sender.bootstrap",
                "teardown.recovery-unmount",
            ],
        )
        self.assertTrue(all(row["argv_length"] < 30_000 for row in records))
        bootstrap_records = [row for row in records if row["step"].endswith(".bootstrap")]
        self.assertEqual(len(bootstrap_records), 2)
        self.assertTrue(all(row["parameter_bytes"] > 40_000 for row in bootstrap_records))

    def test_packet_command_line_guard_refuses_at_its_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            with patch("inference_platform.package_a_operator.WINDOWS_COMMAND_LINE_LIMIT", 1):
                with self.assertRaisesRegex(
                    ValueError, "gate_a_packet:windows_command_line:receiver.readiness"
                ):
                    gate_a_command_line_records(Path(temporary) / "packet", {"region": "us-east-1"})

    def test_packet_parameter_size_guard_refuses_padded_host_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scripts = root / "scripts"
            scripts.mkdir()
            host_source = (ROOT / "scripts/package_a_host.py").read_bytes()
            (scripts / "package_a_host.py").write_bytes(host_source + b"# padding\n" * 1800)
            with patch("inference_platform.package_a_operator.ROOT", root):
                with self.assertRaisesRegex(
                    ValueError,
                    r"gate_a_packet:ssm_parameter_bytes:receiver\.bootstrap:6[0-9]{4,}",
                ):
                    gate_a_command_line_records(root / "packet", {"region": "us-east-1"})

    def test_ssm_parameter_file_is_owner_only_and_removed_after_send_call(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = Path(temporary) / "operator"
            runtime.mkdir()
            operator = Operator.__new__(Operator)
            operator.runtime = runtime
            operator.inputs = {"aws_profile": "admin-learning", "region": "us-east-1"}
            operator.deadline = time.time() + 30
            operator.ready_abort = threading.Event()
            observed = {}

            def fake_aws(service, operation, args, *, deadline=None):
                if operation == "send-command":
                    parameter = args[args.index("--parameters") + 1]
                    observed["argv_length"] = windows_command_line_length(
                        [
                            "aws",
                            "--profile",
                            "admin-learning",
                            "--region",
                            "us-east-1",
                            "ssm",
                            "send-command",
                            *args,
                            "--output",
                            "json",
                            "--no-cli-pager",
                        ]
                    )
                    self.assertLess(observed["argv_length"], 30_000)
                    self.assertTrue(parameter.startswith("file://"))
                    path = Path(parameter.removeprefix("file://"))
                    observed["path"] = path
                    observed["parameters"] = json.loads(path.read_bytes())
                    if os.name != "nt":
                        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                    return {"Command": {"CommandId": "cmd-test"}}
                return {"Status": "Success"}

            operator.aws = fake_aws
            token = "0" * 64
            source = (ROOT / "scripts/package_a_host.py").read_bytes()
            command = bootstrap_shell(source, token, "f" * 64, 9_999_999_999)
            operator.ssm(
                "i-00000000000000000",
                command,
                timeout_s=30,
                step="receiver.bootstrap",
            )
            self.assertEqual(observed["parameters"]["commands"], command)
            self.assertTrue(any(token in line for line in observed["parameters"]["commands"]))
            self.assertLess(observed["argv_length"], 30_000)
            self.assertFalse(observed["path"].exists())

    def test_lifecycle_halt_records_failed_ssm_step_and_length_without_argv(self):
        with tempfile.TemporaryDirectory() as temporary:

            class LifecyclePorts:
                def __init__(self):
                    self.manifest = {
                        "session": "r366-test-session",
                        "bucket_name": "gate-a-test-bucket",
                        "session_deadline_s": 10_000,
                        "cleanup_cost_reserve_usd": 0,
                        "hard_cap_usd": 100,
                    }
                    self.last_ssm_failure = None

                @staticmethod
                def task_cost(start, now):
                    return 0

                @staticmethod
                def cumulative_cost(start, now):
                    return 0

                @staticmethod
                def apply(end):
                    return {"applied": True}

            ports = LifecyclePorts()

            def fail_run_roles(operator, end):
                ports.last_ssm_failure = {
                    "step": "receiver.bootstrap",
                    "argv_length": 1492,
                }
                raise OSError("CreateProcess failed")

            with (
                patch.object(GateAOperator, "run_roles", fail_run_roles),
                patch.object(
                    GateAOperator,
                    "retrieve_roles",
                    return_value={"complete": True},
                ),
                patch.object(
                    GateAOperator,
                    "teardown",
                    return_value={"complete": True, "inventory": {"empty": True}},
                ),
            ):
                receipt = GateALifecycle(
                    ports,
                    ports.manifest,
                    Path(temporary) / "final",
                    clock=lambda: 1_000,
                ).run()

        self.assertEqual(
            receipt["halt"],
            "OSError:CreateProcess failed; step=receiver.bootstrap; argv_length=1492",
        )
        self.assertNotIn("0" * 64, receipt["halt"])


class GateAInputOperatorTests(unittest.TestCase):
    def test_remote_input_paths_are_linux_posix_paths_on_windows_operator(self):
        mapped = gate_a_remote_input_paths(
            {
                "source": "fixture",
                "fixture_proof": "fixture-proof.json",
                "sizing_proof": "sizing-proof.json",
                "spool": "spool",
                "spool_manifest": "spool-manifest.json",
                "sanitizer_specs": "sanitizer-specs.json",
                "sanitizer_key": "sanitizer-key.bin",
                "expected_archive_inventory": "expected-archive-inventory.json",
            }
        )
        self.assertEqual(
            mapped["specs_path"],
            "/opt/dec077/gate-a-inputs/sanitizer-specs.json",
        )
        self.assertTrue(all("\\" not in value for value in mapped.values()))

    def operator_ports(self, *, lifecycle_deadline=22_600):
        return SimpleNamespace(
            manifest={
                "region": "us-east-1",
                "operator_tools": {"aws": {"path": "/usr/bin/aws"}},
                "gate_a_operation": {"operation_pass_max_ms": 1_740_000},
                "retrieval_timeout_s": 124,
                "cleanup_seconds": 600,
            },
            inputs={"aws_profile": "gate-a-test"},
            lifecycle_start_epoch=1_000,
            lifecycle_deadline_epoch=lifecycle_deadline,
            command=lambda *_args: None,
            aws=lambda *_args, **_kwargs: {"ContentLength": 4},
        )

    def test_presign_is_for_exact_get_key_and_deadline_expiry(self):
        operator = self.operator_ports()
        session = MagicMock()
        session.client.return_value.generate_presigned_url.return_value = (
            "https://bucket.s3.us-east-1.amazonaws.com/gate-a/session/input.tar?"
            "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=secret"
        )
        from botocore.config import Config

        with patch("boto3.Session", return_value=session) as create_session:
            result = presigned_s3_get(operator, "bucket", "gate-a/session/input.tar", 900)
        create_session.assert_called_once_with(profile_name="gate-a-test", region_name="us-east-1")
        session.client.assert_called_once()
        self.assertEqual(session.client.call_args.args, ("s3",))
        self.assertEqual(session.client.call_args.kwargs["region_name"], "us-east-1")
        config = session.client.call_args.kwargs["config"]
        self.assertIsInstance(config, Config)
        self.assertEqual(config.signature_version, "s3v4")
        session.client.return_value.generate_presigned_url.assert_called_once_with(
            "get_object",
            Params={"Bucket": "bucket", "Key": "gate-a/session/input.tar"},
            ExpiresIn=900,
            HttpMethod="GET",
        )
        self.assertIn("X-Amz-Signature=secret", result)

    def test_real_offline_presign_is_sigv4_and_host_validator_accepts_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            credentials = Path(temporary) / "credentials"
            credentials.write_text(
                "[round323-fixture]\n"
                "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
                "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
                encoding="utf-8",
            )
            operator = self.operator_ports()
            operator.manifest["region"] = "us-west-2"
            operator.inputs["aws_profile"] = "round323-fixture"
            with patch.dict(
                os.environ,
                {
                    "AWS_SHARED_CREDENTIALS_FILE": str(credentials),
                    "AWS_CONFIG_FILE": str(Path(temporary) / "config"),
                    "AWS_EC2_METADATA_DISABLED": "true",
                    "AWS_PROFILE": "",
                },
                clear=False,
            ):
                url = presigned_s3_get(operator, "gate-a-test-bucket", "gate-a/test/input.tar", 900)
            self.assertIn("X-Amz-Algorithm=AWS4-HMAC-SHA256", url)
            validate_gate_a_s3_get_url(
                url, bucket="gate-a-test-bucket", key="gate-a/test/input.tar"
            )

    def test_gate_a_stage_uses_absolute_deadline_and_does_not_save_presigned_url(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = root / "gate-a-inputs.tar"
            bundle.write_bytes(b"data")
            digest = hashlib.sha256(b"data").hexdigest()
            inventory = {"fixture/raw/client.jsonl": {"bytes": 4, "sha256": digest}}
            key = "gate-a/r366-test-session/input/gate-a-inputs.tar"
            sender = Ports.__new__(Ports)
            sender.directory = root
            sender.runtime = root / "operator"
            sender.runtime.mkdir()
            sender.manifest = {
                "session": "r366-test-session",
                "bucket_name": "gate-a-test-bucket",
                "gate_a_inputs": {
                    "bundle_path": "gate-a-inputs.tar",
                    "bundle_bytes": 4,
                    "bundle_sha256": digest,
                    "inventory": inventory,
                    "s3_staging": {
                        "bucket": "gate-a-test-bucket",
                        "key": key,
                        "bundle_bytes": 4,
                        "bundle_sha256": digest,
                        "upload_deadline_offset_s": 18_660,
                    },
                },
            }
            operator = self.operator_ports()
            signed_url = "https://bucket.s3.us-east-1.amazonaws.com/input.tar?sig=secret"
            receipt = {
                "bundle_sha256": digest,
                "inventory": inventory,
                "readback_verified": True,
                "s3_staging_key": key,
            }
            requests = []

            def request(path, data, *, end):
                requests.append((path, json.loads(data), end))
                return json.dumps(receipt).encode(), {}

            sender.request = request
            clock = [1_001]
            signed_expiries = []

            def sign(*args):
                signed_expiries.append(args[-1])
                if len(signed_expiries) == 1:
                    # Model signing crossing an epoch-second boundary.
                    clock[0] = 1_002
                return signed_url

            with (
                patch(
                    "inference_platform.package_a_operator.time.time",
                    side_effect=lambda: clock[0],
                ),
                patch(
                    "inference_platform.package_a_operator.presigned_s3_get",
                    side_effect=sign,
                ) as sign,
            ):
                staged = sender.upload_gate_a_inputs(21_000, operator_ports=operator)

            self.assertEqual(requests[0][0], "/stage-inputs")
            self.assertEqual(requests[0][1]["download_url"], signed_url)
            self.assertEqual(requests[0][2], 19_660)
            self.assertEqual(signed_expiries, [18_659, 18_658])
            self.assertEqual(sign.call_count, 2)
            self.assertEqual(staged["upload_deadline_epoch"], 19_660)
            self.assertNotIn(signed_url, (sender.runtime / "gate-a-pre-p-staging.json").read_text())

    def test_pre_p_refuses_when_lifecycle_window_cannot_fit_operation_and_retrieval(self):
        operator = self.operator_ports(lifecycle_deadline=3_463)
        with self.assertRaisesRegex(TimeoutError, "gate_a_input_operation_window"):
            gate_a_pre_p_operation_window(operator, end=10_000, now=1_000)

    def test_upload_refuses_before_request_when_lifecycle_window_is_too_short(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sender = Ports.__new__(Ports)
            sender.directory = root
            sender.runtime = root / "operator"
            sender.runtime.mkdir()
            sender.request = MagicMock()
            operator = self.operator_ports(lifecycle_deadline=3_463)
            with patch("inference_platform.package_a_operator.time.time", return_value=1_000):
                with self.assertRaisesRegex(TimeoutError, "gate_a_input_operation_window"):
                    sender.upload_gate_a_inputs(10_000, operator_ports=operator)
            sender.request.assert_not_called()


if __name__ == "__main__":
    unittest.main()
