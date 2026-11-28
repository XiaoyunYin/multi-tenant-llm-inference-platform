"""Refusals for the allow-side plan and input to the no-launch authorizer."""

import unittest
from pathlib import Path

from inf060_allow_side import FREE_RESOURCES, run_instances_input, verify_free_plan
from inf060_operator_packet import gpu_main
from inf060_operator_policy import operator_policy
from inf060_policy_gate import action_cases
from prepare_inf060_probe import gpu_provider_versions


class AllowSideTests(unittest.TestCase):
    def test_any_instance_in_the_rehearsal_plan_refuses(self):
        cfg = {"session": "dec077-inf060-fixture"}
        changes = [
            {"address": name, "change": {"actions": ["create"]}}
            for name in FREE_RESOURCES
        ]
        plan = {
            "applyable": True,
            "errored": False,
            "variables": {"session": {"value": cfg["session"]}},
            "resource_changes": changes,
        }
        verify_free_plan(plan, cfg)
        changes.append(
            {"address": "aws_instance.task[0]", "change": {"actions": ["create"]}}
        )
        with self.assertRaisesRegex(ValueError, "allow_side_plan_scope"):
            verify_free_plan(plan, cfg)

    def test_exact_metadata_omits_computed_defaults_and_forces_dry_run(self):
        vm = {
            "ami": "ami-00000000000000000",
            "instance_type": "g6.xlarge",
            "associate_public_ip_address": True,
            "instance_initiated_shutdown_behavior": "terminate",
            "metadata_options": [
                {
                    "http_endpoint": "enabled",
                    "http_protocol_ipv6": "disabled",
                    "http_tokens": "required",
                }
            ],
            "root_block_device": [
                {
                    "encrypted": True,
                    "delete_on_termination": True,
                    "volume_type": "gp3",
                    "volume_size": 128,
                    "iops": 3000,
                    "throughput": 125,
                }
            ],
            "tags_all": {"Session": "test", "Inf060Target": "test"},
            "volume_tags": {"Session": "test"},
            "user_data": "fixture",
        }
        network = {
            "zone": "us-east-1a",
            "subnet": "fixture-subnet",
            "group": "fixture-group",
            "profile": "fixture-profile",
        }
        request = run_instances_input(vm, network, "/dev/sda1")
        self.assertIs(request["DryRun"], True)
        self.assertEqual(request["InstanceType"], "g6.xlarge")
        self.assertEqual(
            request["MetadataOptions"],
            {
                "HttpEndpoint": "enabled",
                "HttpProtocolIpv6": "disabled",
                "HttpTokens": "required",
            },
        )
        self.assertEqual(request["NetworkInterfaces"][0]["SubnetId"], network["subnet"])
        self.assertEqual(request["IamInstanceProfile"]["Name"], network["profile"])
        self.assertTrue(request["BlockDeviceMappings"][0]["Ebs"]["Encrypted"])

    def test_runinstances_policy_gate_covers_all_resource_contexts(self):
        rows = action_cases(
            "ec2:RunInstances", "000000000000", "fixture", "ami-00000000000000000"
        )
        cases = {label: context for label, _, context in rows}
        self.assertEqual(
            set(cases),
            {
                "ami",
                "instance",
                "volume",
                "network_interface",
                "subnet",
                "security_group",
            },
        )
        self.assertEqual(cases["instance"]["aws:RequestTag/Session"], "fixture")
        self.assertEqual(cases["instance"]["ec2:MetadataHttpTokens"], "required")
        self.assertEqual(cases["subnet"]["ec2:ResourceTag/Session"], "fixture")
        self.assertIs(cases["volume"]["ec2:Encrypted"], True)

    def test_gpu_zone_moves_in_render_policy_and_simulation_context(self):
        root = Path(__file__).resolve().parents[2]
        tf = (root / "infra/terraform/l4_compat/main.tf").read_text()
        self.assertIn(
            'availability_zone       = "us-east-1b"', gpu_main(tf, zone="us-east-1b")
        )
        self.assertEqual(
            gpu_main(tf, zone="us-east-1b").replace("us-east-1b", "us-east-1a"),
            gpu_main(tf),
        )
        subject = ("000000000000", "dec077-inf060-fixture", "ami-00000000000000000")
        policy = operator_policy(*subject, zone="us-east-1b")
        matches = [
            entry["Condition"]["StringEquals"]["ec2:AvailabilityZone"]
            for entry in policy["Statement"]
            if "ec2:AvailabilityZone"
            in entry.get("Condition", {}).get("StringEquals", {})
        ]
        self.assertEqual(matches, ["us-east-1b"])
        rows = action_cases("ec2:RunInstances", *subject, zone="us-east-1b")
        self.assertEqual(
            next(
                values["ec2:AvailabilityZone"]
                for name, _, values in rows
                if name == "instance"
            ),
            "us-east-1b",
        )

    def test_provider_attempts_reference_and_declaration_ship_together(self):
        source = (
            Path(__file__).resolve().parents[2]
            / "infra/terraform/l4_compat/versions.tf"
        )
        original = source.read_bytes().replace(b"\r\n", b"\n")
        for raw, expected in (
            (gpu_provider_versions(original, inf061=True), 1),
            (gpu_provider_versions(original), 0),
        ):
            self.assertEqual(
                raw.count(b"max_retries = var.provider_attempts"), expected
            )
            self.assertEqual(raw.count(b'variable "provider_attempts"'), expected)
