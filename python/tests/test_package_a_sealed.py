import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import package_a_sealed  # noqa: E402


class GateAReceiverIngressTests(unittest.TestCase):
    def setUp(self):
        self.change = {
            "after": {
                "ingress": [
                    {
                        "from_port": 38473,
                        "to_port": 38473,
                        "protocol": "tcp",
                        "cidr_blocks": [],
                        "ipv6_cidr_blocks": [],
                        "prefix_list_ids": [],
                        "self": False,
                    }
                ]
            },
            "after_unknown": {
                "ingress": [
                    {
                        "cidr_blocks": [],
                        "ipv6_cidr_blocks": [],
                        "prefix_list_ids": [],
                        "security_groups": True,
                    }
                ]
            },
        }
        self.configuration = {
            "expressions": {
                "ingress": {
                    "references": [
                        "var.transfer_port",
                        "aws_security_group.hosts.id",
                        "aws_security_group.hosts",
                    ]
                }
            }
        }

    def validate(self):
        package_a_sealed.validate_gate_a_receiver_ingress(self.change, self.configuration, 38473)

    def test_accepts_unknown_security_group_id_bound_to_sender(self):
        self.validate()

    def test_refuses_cidr_ingress(self):
        changed = copy.deepcopy(self.change)
        changed["after"]["ingress"][0]["cidr_blocks"] = ["0.0.0.0/0"]
        with self.assertRaisesRegex(ValueError, "unexpected_gate_a_receiver_ingress"):
            package_a_sealed.validate_gate_a_receiver_ingress(changed, self.configuration, 38473)

    def test_refuses_non_sender_source(self):
        configuration = copy.deepcopy(self.configuration)
        configuration["expressions"]["ingress"]["references"] = [
            "var.transfer_port",
            "aws_security_group.unrelated.id",
            "aws_security_group.unrelated",
        ]
        with self.assertRaisesRegex(ValueError, "unexpected_gate_a_receiver_ingress"):
            package_a_sealed.validate_gate_a_receiver_ingress(self.change, configuration, 38473)

    def test_refuses_wrong_transfer_port(self):
        with self.assertRaisesRegex(ValueError, "unexpected_gate_a_receiver_ingress"):
            package_a_sealed.validate_gate_a_receiver_ingress(
                self.change, self.configuration, 38474
            )


class GateAInterfaceEndpointTests(unittest.TestCase):
    def setUp(self):
        fixture_path = Path(__file__).parent / "fixtures/gate_a_real_create_plan_endpoints.json"
        self.fixture = json.loads(fixture_path.read_bytes())
        self.rows = self.fixture["resource_changes"]
        self.configuration = self.fixture["configuration"]

    def test_accepts_all_three_single_az_ssm_interface_endpoints(self):
        package_a_sealed.validate_gate_a_interface_endpoints(self.rows, self.configuration)

    def test_accepts_known_single_subnet_after_value(self):
        rows = copy.deepcopy(self.rows)
        for row in rows:
            row["change"].setdefault("after", {})["subnet_ids"] = ["subnet-gate-a"]
            row["change"].setdefault("after_unknown", {})["subnet_ids"] = False
        package_a_sealed.validate_gate_a_interface_endpoints(rows, self.configuration)

    def test_refuses_missing_or_misconfigured_interface_endpoint(self):
        for rows in (
            self.rows[:-1],
            self.rows[:-1]
            + [
                {
                    "type": "aws_vpc_endpoint",
                    "change": {
                        "after": {
                            "vpc_endpoint_type": "Gateway",
                            "service_name": "com.amazonaws.us-east-1.ec2messages",
                            "subnet_ids": ["subnet-gate-a"],
                        }
                    },
                }
            ],
        ):
            with self.subTest(rows=rows):
                with self.assertRaisesRegex(ValueError, "unexpected_gate_a_interface_endpoints"):
                    package_a_sealed.validate_gate_a_interface_endpoints(rows, self.configuration)

    def test_refuses_configuration_that_references_a_second_subnet(self):
        configuration = copy.deepcopy(self.configuration)
        expression = configuration["root_module"]["resources"][0]["expressions"]["subnet_ids"]
        expression["references"].append("aws_subnet.other.id")
        with self.assertRaisesRegex(ValueError, "unexpected_gate_a_interface_endpoints"):
            package_a_sealed.validate_gate_a_interface_endpoints(self.rows, configuration)


class GateAInstanceDependencyTests(unittest.TestCase):
    def setUp(self):
        fixture_path = Path(__file__).parent / "fixtures/gate_a_real_instance_dependencies.json"
        self.configuration = json.loads(fixture_path.read_bytes())["configuration"]

    def test_accepts_real_terraform_instance_configuration_shape(self):
        package_a_sealed.validate_gate_a_instance_dependencies(self.configuration)

    def test_refuses_when_either_instance_lacks_network_readiness_dependencies(self):
        configuration = copy.deepcopy(self.configuration)
        sender = next(
            row
            for row in configuration["root_module"]["resources"]
            if row["address"] == "aws_instance.sender"
        )
        sender["depends_on"].remove("aws_vpc_endpoint.ssm")
        with self.assertRaisesRegex(ValueError, "unexpected_gate_a_instance_dependencies"):
            package_a_sealed.validate_gate_a_instance_dependencies(configuration)


if __name__ == "__main__":
    unittest.main()
