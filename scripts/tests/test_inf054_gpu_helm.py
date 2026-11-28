"""Capacity selection clocks and saved-root dispatch in the real paired launcher."""

import datetime as dt
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from inf054_gpu_helm import (
    BINDING,
    CAP_LIMIT_USD,
    MARKER,
    SESSION,
    SESSION_SECONDS,
    gpu_helm_estimate,
    gpu_helm_forecast,
    gpu_helm_timing,
)
from inference_platform.m5_descriptive_operator import phase_deadline
from m5_descriptive_capacity import select_capacity
from m5_descriptive_cleanup import PAIR_WORK_SECONDS, deadline
from m5_descriptive_eks import EKSports, arm, run_packet, session_seconds


class GPUEnvelopeTests(unittest.TestCase):
    def test_preserves_both_reserves_and_old_sessions(self):
        sealed = gpu_helm_timing(300, 432)
        self.assertEqual(SESSION_SECONDS, 54784)
        self.assertEqual(sealed["selected_work_seconds"], 32284)
        self.assertEqual(sealed["retrieval_reserve_seconds"], 4416)
        self.assertEqual(sealed["minimum_workload_seconds"], 22296)
        self.assertEqual(sealed["dcgm_ready_seconds"], 120)
        self.assertEqual(sealed["dcgm_later_ready_seconds"], 45)
        self.assertEqual(sealed["dcgm_diagnostics_seconds"], 60)
        self.assertEqual(sealed["selected_slack_seconds"], 117)
        self.assertEqual(sealed["cleanup_reserve_seconds"], 1800)
        self.assertEqual(sealed["source_upload_budget_seconds"], 432)
        self.assertEqual(sealed["remaining_infrastructure_seconds"], 3223)
        self.assertEqual(sealed["capacity_wait_budget_seconds"], 21600)
        self.assertEqual(session_seconds({"descriptive": {}}), 18000)
        self.assertEqual(
            session_seconds(
                {"descriptive": {BINDING: True}, "session_seconds": SESSION_SECONDS}
            ),
            SESSION_SECONDS,
        )
        self.assertEqual(gpu_helm_estimate(2.8630444444444443, attempts=2), 71.69)
        self.assertEqual(CAP_LIMIT_USD, 72.00)
        self.assertEqual(gpu_helm_forecast(2.8630444444444443), 35.85)
        self.assertEqual(gpu_helm_forecast(2.8765), 36.00)
        with self.assertRaisesRegex(ValueError, "inf054_gpu_cost_envelope"):
            gpu_helm_forecast(2.877)

    def test_refuses_insufficient_work_envelope(self):
        with self.assertRaisesRegex(ValueError, "inf054_gpu_capacity_envelope"):
            gpu_helm_timing(300, 2710)
        with self.assertRaisesRegex(ValueError, "inf054_gpu_cost_envelope"):
            gpu_helm_forecast(4)

    def test_paired_provision_late_selection_uses_full_work_and_reserve(self):
        self.paired_late_selection(through_entrypoint=False)

    def test_paired_launcher_entrypoint_reaches_only_selected_composed_apply(self):
        self.paired_late_selection(through_entrypoint=True)

    def paired_late_selection(self, *, through_entrypoint):
        epoch = 1795750000
        wall = epoch
        armed = epoch + 300
        start_wait = 0
        calls = []
        selected_stop = None
        parameter = None

        def now():
            return wall

        def sleep(seconds):
            nonlocal wall
            # Advance virtual time after the first complete zone cycle.
            self.assertEqual(seconds, 60)
            wall = start_wait + 5 * 3600 + 50 * 60

        def put(**request):
            nonlocal parameter
            self.assertEqual(request["Overwrite"], parameter is not None)
            parameter = json.loads(request["Value"])

        def get(**_):
            return {"Parameter": {"Value": json.dumps(parameter)}}

        def terraform(root, *args):
            nonlocal wall
            self.assertEqual(args, ("apply", "-input=false", "create.tfplan"))
            calls.append((root.name, wall, ports.end))
            if root.name == "backstop":
                wall = armed

        def reserve(stop):
            self.assertGreater(stop, now())
            self.assertFalse((ports.directory / "composed-apply-started.json").exists())
            if now() == start_wait:
                return {"result": "capacity_unavailable"}
            return {"result": "success", "capacity_reservation_id": "cr-fixture"}

        def aws(service, operation, args, *, deadline):
            nonlocal selected_stop
            self.assertEqual(
                (service, operation), ("ec2", "modify-capacity-reservation")
            )
            selected_stop = dt.datetime.fromisoformat(
                args[args.index("--end-date") + 1]
            ).timestamp()
            self.assertGreater(deadline, now())

        group = Mock()
        group.can_paginate.return_value = False
        group.list_group_resources.return_value = {
            "ResourceIdentifiers": [
                {
                    "ResourceArn": "arn:aws:ec2:us-east-1:fixture:capacity-reservation/cr-fixture"
                }
            ]
        }
        ssm = SimpleNamespace(put_parameter=put, get_parameter=get)
        sdk = Mock()
        sdk.client.side_effect = lambda name, **kw: {
            "ssm": ssm,
            "resource-groups": group,
        }[name]
        timing = gpu_helm_timing(300, 430)
        with tempfile.TemporaryDirectory() as folder:
            ports = EKSports.__new__(EKSports)
            ports.directory = Path(folder)
            ports.profile = "fixture"
            ports.manifest = {
                "source_commit": "1" * 40,
                "descriptive": {BINDING: True},
                "session": SESSION,
                "operator_tools": {
                    "terraform": {
                        "path": str(ports.directory / "fixture-tool"),
                        "sha256": hashlib.sha256(b"fixture tool").hexdigest(),
                    }
                },
                "host_manifest": {"session_manager_plugin_path": "fixture-plugin"},
                "capacity_group_arn": "group-fixture",
                "account": "fixture",
                "session_seconds": SESSION_SECONDS,
                "timing": timing,
                "alternatives": [
                    {"directory": "zone-us-east-1b", "zone": "us-east-1b"},
                    {"directory": "zone-us-east-1c", "zone": "us-east-1c"},
                ],
            }
            (ports.directory / "fixture-tool").write_bytes(b"fixture tool")
            manifest = ports.directory / "manifest.json"
            manifest.write_text(json.dumps(ports.manifest))
            manifest_hash = hashlib.sha256(manifest.read_bytes()).hexdigest()
            approval = f"## Claude Round 0\n{MARKER} manifest={manifest_hash} source={'1' * 40}\n"

            def output(argv, **_kwargs):
                if argv == ["git", "show", "HEAD:REVIEW.md"]:
                    return approval.encode()
                if argv[:2] == ["git", "status"]:
                    return b""
                return json.dumps(outputs).encode()

            ports.sdk = sdk
            ports.tf = terraform
            ports.aws = aws
            ports.remote = Mock(return_value={"complete": True})
            ports.check_streaming_quota = Mock()
            ports.started, ports.end = epoch, epoch + SESSION_SECONDS
            ports.deadline, ports.selected_epoch = ports.end, None
            ports.capacity = SimpleNamespace(
                inputs={},
                directory=ports.directory,
                reserve_capacity=Mock(side_effect=reserve),
                cancel_session_capacity_reservations=Mock(return_value=True),
                describe_capacity_reservations=lambda *args: [
                    {
                        "State": "active",
                        "AvailableInstanceCount": 2,
                        "TotalInstanceCount": 2,
                        "InstanceMatchCriteria": "targeted",
                        "EndDate": dt.datetime.fromtimestamp(
                            selected_stop, dt.UTC
                        ).isoformat(),
                    }
                ],
            )

            def search(adapter):
                nonlocal start_wait
                start_wait = now()
                return select_capacity(adapter, clock=now, epoch=now, sleep=sleep)

            outputs = {
                "repository_url": {"value": "registry.invalid"},
                "operator_instance": {"value": "fixture-host"},
            }
            with (
                patch(
                    "m5_descriptive_eks.time",
                    SimpleNamespace(time=now, monotonic=now, sleep=sleep),
                ),
                patch(
                    "m5_descriptive_eks.arm",
                    side_effect=lambda *a, **k: arm(*a, **k, now=now),
                ),
                patch(
                    "m5_descriptive_eks.arming_witness", return_value={"armed": True}
                ),
                patch("m5_descriptive_eks.select_capacity", side_effect=search),
                patch(
                    "m5_descriptive_eks.subprocess.check_output",
                    side_effect=output,
                ),
                patch("m5_descriptive_eks.DescriptiveHost.bootstrap", autospec=True),
                patch("m5_descriptive_eks.DescriptiveHost.upload", autospec=True),
                patch(
                    "m5_descriptive_eks.DescriptiveHost.upload_gate_a_inputs",
                    autospec=True,
                ),
                patch("m5_descriptive_eks.DescriptiveHost.run_checks", autospec=True),
                patch("m5_descriptive_eks.DescriptiveHost.ssm", autospec=True),
                patch.dict(
                    "os.environ",
                    {
                        "SESSION": ports.manifest["session"],
                        "SESSION_SECONDS": str(SESSION_SECONDS),
                    },
                ),
            ):
                if through_entrypoint:
                    ports.export = Mock(return_value={"sha256": "fixture"})
                    ports.retrieve = Mock(return_value={"sha256": "fixture"})
                    ports.teardown = Mock(return_value={"complete": True})
                    ports.inventory = Mock(return_value={"complete": True})
                    with (
                        patch("m5_descriptive_eks.subprocess.run"),
                        patch("m5_descriptive_eks.verify_packet_files"),
                        patch("m5_descriptive_eks.verify_gpu_helm"),
                        patch("m5_descriptive_eks.EKSports", return_value=ports),
                    ):
                        run_packet(
                            SimpleNamespace(
                                packet=ports.directory,
                                profile=ports.profile,
                                recover=False,
                                cleanup_only=False,
                                approved_manifest_sha256=manifest_hash,
                            )
                        )
                    execution = json.loads(
                        (ports.directory / "execution/receipt.json").read_bytes()
                    )
                    self.assertTrue(execution["complete"])
                    witness = execution["phases"][0]["result"]
                else:
                    witness = ports.provision()
                self.assertEqual(deadline(ssm, "fixture-parameter"), ports.end)
                with patch.object(
                    ssm,
                    "get_parameter",
                    return_value={
                        "Parameter": {
                            "Value": json.dumps(
                                {**parameter, "deadline_epoch": ports.end + 1}
                            )
                        }
                    },
                ):
                    self.assertEqual(deadline(ssm, "fixture-parameter"), 0)

            self.assertEqual(ports.selected_epoch - start_wait, 21000)
            self.assertEqual(ports.end - ports.selected_epoch, PAIR_WORK_SECONDS)
            self.assertEqual(selected_stop, ports.end)
            self.assertEqual(
                [row[0] for row in calls], ["bootstrap", "backstop", "zone-us-east-1b"]
            )
            self.assertEqual(calls[-1][2], ports.end)
            self.assertEqual(witness["capacity_zone"], "us-east-1b")
            self.assertEqual(ports.host.started, ports.selected_epoch)
            self.assertEqual(
                ports.capacity.cancel_session_capacity_reservations.call_count, 2
            )
            self.assertTrue((ports.directory / "composed-apply-started.json").is_file())
            self.assertEqual(
                ports.end - phase_deadline(ports.end, timing, "retrieve"), 1800
            )
            self.assertEqual(
                ports.end - phase_deadline(ports.end, timing, "export"), 4008
            )
            self.assertEqual(
                ports.end - phase_deadline(ports.end, timing, "provision"), 6216
            )
            self.assertEqual(ports.selected_epoch + PAIR_WORK_SECONDS, ports.deadline)
