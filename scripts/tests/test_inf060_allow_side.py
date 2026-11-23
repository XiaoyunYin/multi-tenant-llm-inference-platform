"""Refusals for the allow-side plan and input to the no-launch authorizer."""

import unittest

from inf060_allow_side import FREE_RESOURCES, run_instances_input, verify_free_plan
from inf060_policy_gate import action_cases


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
