"""R577, R579 and R580 bindings without AWS or Docker."""

import copy
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import m5_descriptive_eks as operator
from inf060_eks_cpu_plan import (
    archive_index_bindings,
    check_image_bindings,
    check_loaded_image,
    check_pushed_content,
    standard_quota_readback,
)
from inference_platform.inf060_eks_clock import PORT
from inference_platform.inf060_eks_resources import CLIENT_LABELS, serving_resources
from inference_platform.m5_descriptive import resources

FIXTURE = (
    Path(__file__).resolve().parents[1] / "fixtures/inf060-cpu-r419-image-indices.json"
)


class CpuClockBindings(unittest.TestCase):
    def test_archive_manifest_config_swap_is_refused(self):
        fixture = json.loads(FIXTURE.read_bytes())
        images = archive_index_bindings(fixture["index.json"], fixture["manifest.json"])
        gateway = images["gateway"]
        self.assertEqual(
            gateway["manifest_digest"],
            "sha256:ee0ea7b3a6905a2d9ddf3e8013906408927b9eac9b8a7add959edd9716c23f64",
        )
        self.assertEqual(
            gateway["config_digest"],
            "sha256:db5cfa10a105b5103a4706f6ffd72b302ba7fdc51360b30f13c6f981ff9896af",
        )
        self.assertEqual(len(images["client"]["layer_digests"]), 9)
        # Diff IDs belong to the config blob, outside the two retained indices.
        for row in images.values():
            row["diff_ids"] = row["layer_digests"]
        check_image_bindings(images, copy.deepcopy(images))
        swapped = copy.deepcopy(images)
        swapped["gateway"].update(
            config_digest=gateway["manifest_digest"],
            manifest_digest=gateway["config_digest"],
        )
        with self.assertRaisesRegex(ValueError, "^cpu_clock:image_digest$"):
            check_image_bindings(images, swapped)

    def test_loaded_image_both_stores_and_pushed_layers(self):
        fixture = json.loads(FIXTURE.read_bytes())
        image = archive_index_bindings(fixture["index.json"], fixture["manifest.json"])[
            "gateway"
        ]
        image["diff_ids"] = ["sha256:" + "1" * 64, "sha256:" + "2" * 64]
        inspected = {
            "Os": "linux",
            "Architecture": "amd64",
            "RootFS": {"Layers": image["diff_ids"]},
        }
        for identity in (image["config_digest"], image["manifest_digest"]):
            with self.subTest(identity=identity):
                check_loaded_image({**inspected, "Id": identity}, image)
        with self.assertRaisesRegex(ValueError, "^cpu_clock:image_digest$"):
            check_loaded_image({**inspected, "Id": "sha256:" + "3" * 64}, image)
        pushed = {
            "config": {"digest": image["config_digest"]},
            "layers": [{"digest": digest} for digest in image["layer_digests"]],
        }
        check_pushed_content(pushed, image)
        pushed["layers"].reverse()
        with self.assertRaisesRegex(ValueError, "^cpu_clock:image_digest$"):
            check_pushed_content(pushed, image)

    def test_clock_readiness_probes_localhost_and_keeps_peer_policy(self):
        image = "example.invalid/gateway@sha256:" + "a" * 64
        manifest = serving_resources(
            resources("mti-m5-clock-fixture", image), image, "{}"
        )
        engine = next(
            row
            for row in manifest["items"]
            if row["kind"] == "StatefulSet" and row["metadata"]["name"] == "vllm"
        )
        container = next(
            row
            for row in engine["spec"]["template"]["spec"]["containers"]
            if row["name"] == "clock-server"
        )
        probe = container["readinessProbe"]
        self.assertNotIn("tcpSocket", probe)
        self.assertIn(f"('127.0.0.1', {PORT})", probe["exec"]["command"][2])
        policy = next(
            row for row in manifest["items"] if row["kind"] == "NetworkPolicy"
        )
        self.assertEqual(
            policy["spec"]["ingress"],
            [
                {"ports": [{"protocol": "TCP", "port": 8000}]},
                {
                    "ports": [{"protocol": "TCP", "port": PORT}],
                    "from": [{"podSelector": {"matchLabels": CLIENT_LABELS}}],
                },
            ],
        )

    def test_immediate_standard_quota_readback_fails_closed_when_busy(self):
        ec2 = Mock()
        ec2.can_paginate.return_value = False
        quotas = Mock()
        quotas.get_service_quota.return_value = {"Quota": {"Value": 32}}
        sdk = SimpleNamespace(client={"ec2": ec2, "service-quotas": quotas}.__getitem__)
        extras = [
            {"InstanceType": "g6.xlarge"},
            {"InstanceType": "dl1.24xlarge"},
            {"InstanceType": "hpc7a.12xlarge"},
            {"InstanceType": "inf2.xlarge"},
            {"InstanceType": "trn1.2xlarge"},
            {"InstanceType": "m6i.2xlarge", "InstanceLifecycle": "spot"},
            {"InstanceType": "mac2.metal", "Placement": {"Tenancy": "host"}},
        ]
        ec2.describe_instances.return_value = {"Reservations": [{"Instances": extras}]}
        self.assertEqual(
            standard_quota_readback(sdk),
            {
                "quota_vcpus": 32,
                "running_vcpus": 0,
                "required_vcpus": 32,
                "fits": True,
            },
        )
        ec2.describe_instance_types.assert_not_called()
        ec2.describe_instances.return_value["Reservations"][0]["Instances"].append(
            {"InstanceType": "c6i.2xlarge"}
        )
        ec2.describe_instance_types.return_value = {
            "InstanceTypes": [
                {
                    "InstanceType": "c6i.2xlarge",
                    "VCpuInfo": {"DefaultVCpus": 8},
                }
            ]
        }
        self.assertEqual(
            standard_quota_readback(sdk),
            {
                "quota_vcpus": 32,
                "running_vcpus": 8,
                "required_vcpus": 32,
                "fits": False,
            },
        )
        ec2.describe_instance_types.assert_called_once_with(
            InstanceTypes=["c6i.2xlarge"]
        )
        self.assertEqual(ec2.describe_instances.call_count, 2)
        self.assertEqual(quotas.get_service_quota.call_count, 2)

    def test_quota_change_during_arming_refuses_cpu_root_apply(self):
        with tempfile.TemporaryDirectory() as directory:
            ports = operator.EKSports.__new__(operator.EKSports)
            ports.directory = Path(directory)
            ports.started, ports.end, ports.sdk = 1, 18001, object()
            ports.tf = Mock()
            ports.manifest = {
                "descriptive": {
                    "cpu_clock_rehearsal": {"selection": {"directory": "cpu-clock"}}
                }
            }
            (ports.directory / "manifest.json").write_text(json.dumps(ports.manifest))
            busy = {
                "quota_vcpus": 32,
                "running_vcpus": 8,
                "required_vcpus": 32,
                "fits": False,
            }
            with (
                patch.object(operator, "arm"),
                patch.object(operator, "arming_witness", return_value={"armed": True}),
                patch.object(
                    operator, "standard_quota_readback", return_value=busy
                ) as readback,
                self.assertRaisesRegex(ValueError, "^cpu_clock:standard_quota_busy$"),
            ):
                ports.provision()
            readback.assert_called_once_with(ports.sdk)
            self.assertEqual(
                [call.args[0].name for call in ports.tf.call_args_list],
                ["bootstrap", "backstop"],
            )
            self.assertEqual(
                json.loads(
                    (ports.directory / "cpu-quota-before-apply.json").read_bytes()
                ),
                busy,
            )
            self.assertFalse((ports.directory / "selected-plan.json").exists())


if __name__ == "__main__":
    unittest.main()
