"""Real locked boto3 over real HTTP; the AWS responses are declared fixtures."""

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

import boto3

from inference_platform.inf037b_eks_provider_client import AccountReadClient


class ProviderClientTest(unittest.TestCase):
    def setUp(self):
        self.account, self.session_id, self.now = "000000000000", "fixture-session", 100
        self.owner, self.tag, self.ids, self.cycle = (
            self.account,
            self.session_id,
            ["i-a", "i-b"],
            False,
        )
        self.requests = []
        self.pins = {}
        self.boots = {"i-a": "boot-a", "i-b": "boot-b"}
        case = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                instance = self.path.rsplit("/", 1)[-1]
                data = json.dumps(
                    {
                        "instance_id": instance,
                        "boot_id": case.boots[instance],
                        "session_id": case.session_id,
                        "pins": case.pins,
                    }
                ).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self):
                fields = parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
                action = fields["Action"][0]
                case.requests.append(fields)
                if action == "GetCallerIdentity":
                    body = f'<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Account>{case.account}</Account><UserId>fixture</UserId></GetCallerIdentityResult><ResponseMetadata><RequestId>fixture-request</RequestId></ResponseMetadata></GetCallerIdentityResponse>'
                else:
                    case.assertEqual(action, "DescribeInstances")
                    index = 1 if "NextToken" in fields else 0
                    ids = case.ids[index : index + 1]
                    items = "".join(
                        f"<item><instanceId>{key}</instanceId><instanceState><code>16</code><name>running</name></instanceState><placement><availabilityZone>us-east-1a</availabilityZone></placement><tagSet><item><key>Session</key><value>{case.tag}</value></item></tagSet></item>"
                        for key in ids
                    )
                    token = "<nextToken>page-two</nextToken>" if index == 0 or case.cycle else ""
                    body = f'<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><requestId>fixture-request</requestId><reservationSet><item><ownerId>{case.owner}</ownerId><instancesSet>{items}</instancesSet></item></reservationSet>{token}</DescribeInstancesResponse>'
                encoded = body.encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/xml")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=self.server.serve_forever)
        thread.start()
        self.addCleanup(thread.join, 2)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        session = boto3.Session(
            aws_access_key_id="fixture-key",
            aws_secret_access_key="fixture-secret",
            region_name="us-east-1",
        )
        self.client = AccountReadClient(
            session,
            account=self.account,
            region="us-east-1",
            session_id=self.session_id,
            clock=lambda: self.now,
            endpoint=f"http://127.0.0.1:{self.server.server_port}",
            local_test=True,
        )

    def test_real_sdk_paginates_complete_known_hosts_and_reads_only(self):
        rows = self.client.hosts(["i-a", "i-b"], 10000)
        self.assertEqual(set(rows), {"i-a", "i-b"})
        self.assertEqual(
            [r["Action"][0] for r in self.requests],
            ["GetCallerIdentity", "DescribeInstances", "DescribeInstances"],
        )
        self.assertEqual(self.requests[-1]["NextToken"], ["page-two"])

    def test_missing_host_is_unknown_and_scope_drift_refuses(self):
        for fault, reason in (
            ("owner", "resource_account"),
            ("tag", "session_tag"),
            ("missing", "host_inventory_unknown"),
        ):
            with self.subTest(fault=fault):
                self.owner, self.tag, self.ids = self.account, self.session_id, ["i-a", "i-b"]
                if fault == "owner":
                    self.owner = "111111111111"
                if fault == "tag":
                    self.tag = "foreign"
                if fault == "missing":
                    self.ids = ["i-a"]
                with self.assertRaisesRegex(ValueError, reason):
                    self.client.hosts(["i-a", "i-b"], 10000)

    def test_caller_drift_deadline_and_duplicate_page_refuse(self):
        self.account = "111111111111"
        with self.assertRaisesRegex(ValueError, "caller_account"):
            self.client.hosts(["i-a", "i-b"], 10000)
        self.account = self.owner
        self.now = 10000
        with self.assertRaisesRegex(ValueError, "deadline"):
            self.client.hosts(["i-a"], 10000)
        self.now, self.cycle = 100, True
        with self.assertRaisesRegex(ValueError, "foreign_or_duplicate_host|pagination_cycle"):
            self.client.hosts(["i-a", "i-b"], 10000)

    def test_no_effect_map_never_executes_or_infers_absence(self):
        with self.assertRaisesRegex(ValueError, "sealed_effect_resource_map"):
            self.client.execute({"operation": "eks.creation"})
        with self.assertRaisesRegex(ValueError, "complete_scoped_resource_inventory"):
            self.client.read({"operation": "eks.inventory"})
        self.assertFalse(self.client.reconcile({})["known"])
        self.assertEqual(self.requests, [])
