import contextlib
import datetime
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs

from inference_platform.r1_cloud_operator import Operator
from inference_platform.r1_lifecycle import (
    CAPACITY_RESERVATION_END_GRACE_SECONDS,
    ROLES,
    ConsumeGate,
    Production,
    committed_approval,
    execute,
    sha,
    summarize_capacity_events,
)
from inference_platform.r1_lifecycle import (
    main as lifecycle_main,
)
from inference_platform.r1_lifecycle_rehearsal import Virtual, fixture_inputs
from inference_platform.r1_spec import encoded


def production_adapter(repo, inputs, directory):
    repo = Path(repo)
    inputs.setdefault("terraform", ".tools/terraform/1.16.2/terraform.exe")
    terraform = (repo / inputs["terraform"]).resolve()
    terraform.parent.mkdir(parents=True, exist_ok=True)
    terraform.write_bytes(b"unit terraform binary")
    return Production(repo, inputs, directory)


def write_bundle(path, files, source_head):
    manifest = {
        "source_head": source_head,
        "files": {name: sha(data) for name, data in files.items()},
    }
    payload = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    with tarfile.open(path, "w:gz") as archive:
        for name, data in {**files, "payload.json": payload}.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    return sha(path.read_bytes())


class PaidLifecycleTests(unittest.TestCase):
    def test_bundle_source_mismatch_refuses_before_lifecycle_consume_or_aws(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            plan, inputs = fixture_inputs("success")
            inputs["source_head"] = "a" * 40
            inputs["source_sha256"] = {
                "python/src/inference_platform/example.py": sha(b"current source\n")
            }
            bundle_path = repo / "bundle.tar.gz"
            files = {
                "python/src/inference_platform/example.py": b"bundled source\n",
                "bin/gateway": b"gateway",
            }
            inputs["bundle_path"] = bundle_path.name
            inputs["bundle_sha256"] = write_bundle(bundle_path, files, inputs["source_head"])
            inputs_path = repo / "inputs.json"
            inputs["commands"] = {"ready": ["fixture", "--inputs", "inputs.json"]}
            inputs_path.write_text(json.dumps(inputs), encoding="utf-8")
            gate = ConsumeGate(repo / "consume.sqlite3")
            adapter = production_adapter(repo, inputs, repo / "runtime")
            with (
                patch.object(adapter, "aws") as aws,
                patch.object(adapter, "command") as command,
                patch.object(adapter, "reserve_capacity") as reserve,
            ):
                result = execute(
                    adapter,
                    plan,
                    inputs,
                    gate,
                    lambda _: {inputs["plan_sha256"]},
                    repo / "receipt.json",
                    inputs_path=inputs_path,
                )
                aws.assert_not_called()
                command.assert_not_called()
                reserve.assert_not_called()
            self.assertIn("differs from source_sha256", result["error"])
            self.assertEqual(result["apply_count"], 0)
            self.assertIsNone(gate.plan_status(inputs["plan_sha256"]))
            self.assertFalse(any(event["event"] == "plan_consumed" for event in result["events"]))

    def test_preconsume_probe_failures_leave_gate_row_absent_and_can_retry(self):
        with tempfile.TemporaryDirectory() as root:
            folder = Path(root)
            plan, inputs = fixture_inputs("success")
            gate = ConsumeGate(folder / "consume.sqlite3")

            class Probe(Virtual):
                def __init__(self, scenario, result, error_code):
                    super().__init__(scenario)
                    self.probe_result, self.error_code = result, error_code

                def reserve_capacity(self, deadline):
                    return {
                        "result": self.probe_result,
                        "error_code": self.error_code,
                        "zone": "us-east-1b",
                        "cleanup_verified": True,
                    }

            for index, (result_name, error_code) in enumerate(
                (
                    ("capacity_unavailable", "Server.InsufficientInstanceCapacity"),
                    ("create_error", "UnauthorizedOperation"),
                )
            ):
                output = folder / f"failure-{index}.json"
                result = execute(
                    Probe("success", result_name, error_code),
                    plan,
                    inputs,
                    gate,
                    lambda _: None,
                    output,
                )
                events = result["events"]
                probe = next(
                    event for event in events if event["event"] == "fixture_capacity_probe"
                )
                ended = next(event for event in events if event["event"] == "fixture_work_ended")
                self.assertEqual(probe["result"], result_name)
                self.assertEqual(probe["error_code"], error_code)
                self.assertEqual(probe["zone"], "us-east-1b")
                self.assertFalse(probe["consumed"])
                self.assertEqual(result["exit_code"], 2)
                self.assertEqual(result["apply_count"], 0)
                self.assertIsNone(result["gate_plan_status"])
                self.assertIsNone(ended["gate_plan_status"])
                self.assertNotIn("fixture_plan_consumed", [event["event"] for event in events])
                self.assertNotIn("fixture_destroy_started", [event["event"] for event in events])
                self.assertIsNone(gate.plan_status(inputs["plan_sha256"]))

            retry = execute(
                Virtual("success"),
                plan,
                inputs,
                gate,
                lambda _: None,
                folder / "retry.json",
            )
            self.assertEqual(retry["apply_count"], 1)
            self.assertIsNone(retry["error"])
            self.assertEqual(gate.plan_status(inputs["plan_sha256"]), "verified")

    def test_successful_capacity_probe_precedes_consume_apply_and_cancellation(self):
        with tempfile.TemporaryDirectory() as root:
            folder = Path(root)
            plan, inputs = fixture_inputs("success")
            inputs["session_estimate_usd"] = "34.70"
            inputs["m4_estimate_usd"] = "86.54"
            gate = ConsumeGate(folder / "consume.sqlite3")
            result = execute(
                Virtual("success"),
                plan,
                inputs,
                gate,
                lambda _: None,
                folder / "receipt.json",
            )
            events = result["events"]
            names = [event["event"] for event in events]
            probe = names.index("fixture_capacity_probe")
            consumed = names.index("fixture_plan_consumed")
            first_host = names.index("fixture_host_created")
            cancelled = next(
                index
                for index, event in enumerate(events)
                if event["event"] == "fixture_capacity_reservation_cancelled"
                and event.get("reason") == "gpu_hosts_running"
            )
            ready = names.index("fixture_ready")
            destroy = names.index("fixture_destroy_started")
            verified = names.index("fixture_teardown_verified")
            self.assertLess(probe, consumed)
            self.assertLess(consumed, first_host)
            self.assertLess(first_host, cancelled)
            self.assertLess(cancelled, ready)
            self.assertLess(ready, destroy)
            self.assertLess(destroy, verified)
            self.assertEqual(result["apply_count"], 1)
            self.assertEqual(result["gate_plan_status"], "verified")
            self.assertEqual(
                gate.recovery_inputs(inputs["plan_sha256"])["_capacity_reservation_id"],
                "fixture-capacity-reservation",
            )

    def test_estimate_over_fixed_r1_cap_stops_before_capacity_probe(self):
        with tempfile.TemporaryDirectory() as root:
            folder = Path(root)
            plan, inputs = fixture_inputs("success")
            inputs["session_estimate_usd"] = "34.71"

            class NoProbe(Virtual):
                def reserve_capacity(self, deadline):
                    raise AssertionError("over-cap session must stop before any reservation")

            gate = ConsumeGate(folder / "consume.sqlite3")
            result = execute(
                NoProbe("success"),
                plan,
                inputs,
                gate,
                lambda _: None,
                folder / "receipt.json",
            )
            self.assertIn("$34.70 cap", result["error"])
            self.assertEqual(result["apply_count"], 0)
            self.assertIsNone(result["gate_plan_status"])

    def test_capacity_cancel_failure_halts_even_if_idempotent_retry_cleans_up(self):
        with tempfile.TemporaryDirectory() as root:
            folder = Path(root)
            plan, inputs = fixture_inputs("success")
            gate = ConsumeGate(folder / "consume.sqlite3")

            class CancelFailure(Virtual):
                def __init__(self):
                    super().__init__("success")
                    self.cancel_calls = 0

                def cancel_capacity(self, reservation_id, deadline):
                    self.cancel_calls += 1
                    if self.cancel_calls == 1:
                        return {
                            "verified": False,
                            "state": "active",
                            "cancel_requested": True,
                        }
                    return {
                        "verified": True,
                        "state": "cancelled",
                        "cancel_requested": True,
                    }

            adapter = CancelFailure()
            result = execute(adapter, plan, inputs, gate, lambda _: None, folder / "receipt.json")
            events = result["events"]
            names = [event["event"] for event in events]
            failed = names.index("fixture_capacity_reservation_cancel_failed")
            retried = names.index("fixture_capacity_reservation_cancelled")
            destroy = names.index("fixture_destroy_started")
            self.assertEqual(adapter.cancel_calls, 2)
            self.assertLess(failed, retried)
            self.assertLess(retried, destroy)
            self.assertIn("capacity-reservation-cancel-failed", result["remaining_inventory"])
            self.assertEqual(gate.plan_status(inputs["plan_sha256"]), "uncertain")
            with self.assertRaisesRegex(ValueError, "paid work halted"):
                gate.consume("b" * 64, {})

    def test_partial_preconsume_reservation_cancel_failure_halts_without_consuming(self):
        with tempfile.TemporaryDirectory() as root:
            folder = Path(root)
            plan, inputs = fixture_inputs("success")
            gate = ConsumeGate(folder / "consume.sqlite3")

            class PartialReservation(Virtual):
                def reserve_capacity(self, deadline):
                    return {
                        "result": "partial",
                        "error_code": "ReservationAttributesMismatch",
                        "zone": "us-east-1b",
                        "capacity_reservation_id": "fixture-partial-cr",
                        "state": "active",
                    }

                def cancel_capacity(self, reservation_id, deadline):
                    return {"verified": False, "state": "active", "cancel_requested": True}

            result = execute(
                PartialReservation("success"),
                plan,
                inputs,
                gate,
                lambda _: None,
                folder / "receipt.json",
            )
            names = [event["event"] for event in result["events"]]
            self.assertEqual(result["apply_count"], 0)
            self.assertEqual(result["exit_code"], 2)
            self.assertIsNone(gate.plan_status(inputs["plan_sha256"]))
            self.assertIn("fixture_capacity_reservation_cancel_failed", names)
            self.assertIn("fixture_teardown_verified", names)
            with self.assertRaisesRegex(ValueError, "paid work halted"):
                gate.consume("b" * 64, {})

    def test_r140_cloudtrail_fixture_uses_embedded_utc_time_and_top_level_instance_type(self):
        fixture = json.loads(
            (
                Path(__file__).parent / "fixtures/cloudtrail_capacity_runinstances_redacted.json"
            ).read_text(encoding="utf-8")
        )
        summary = summarize_capacity_events(fixture, fallback_zone="us-east-1b")
        self.assertEqual(summary["capacity_event_count"], 1)
        self.assertEqual(summary["instance_type_counts"], {"g6.xlarge": 1})
        self.assertEqual(summary["availability_zone"], "us-east-1b")
        self.assertEqual(
            summary["time_span_utc"],
            {
                "start_utc": "2026-10-07T21:20:48Z",
                "end_utc": "2026-10-07T21:20:48Z",
            },
        )

    def test_r140_cloudtrail_instance_set_fallback_counts_items_and_normalizes_offsets(self):
        response = {
            "Events": [
                {
                    "EventTime": "2026-10-07T09:00:00-07:00",
                    "CloudTrailEvent": json.dumps(
                        {
                            "eventTime": "2026-10-07T17:00:00+01:00",
                            "eventName": "RunInstances",
                            "errorCode": "Server.InsufficientInstanceCapacity",
                            "requestParameters": {
                                "instancesSet": {
                                    "items": [
                                        {"instanceType": "g6.xlarge"},
                                        {"instanceType": "g6.xlarge"},
                                    ]
                                }
                            },
                        }
                    ),
                }
            ]
        }
        summary = summarize_capacity_events(response, fallback_zone="us-east-1b")
        self.assertEqual(summary["instance_type_counts"], {"g6.xlarge": 2})
        self.assertEqual(summary["time_span_utc"]["start_utc"], "2026-10-07T16:00:00Z")

    def test_production_capacity_probe_distinguishes_capacity_and_other_cli_errors(self):
        for stderr, expected_result, expected_code in (
            (
                "An error occurred (Server.InsufficientInstanceCapacity) while creating",
                "capacity_unavailable",
                "Server.InsufficientInstanceCapacity",
            ),
            (
                "An error occurred (UnauthorizedOperation) while creating",
                "create_error",
                "UnauthorizedOperation",
            ),
        ):
            with (
                self.subTest(expected_result=expected_result),
                tempfile.TemporaryDirectory() as root,
            ):
                repo = Path(root)
                output = repo / "attempt"
                output.mkdir()
                inputs = {
                    "terraform": "terraform.exe",
                    "session_id": "unit-session",
                    "gpu_type": "g6.xlarge",
                    "availability_zone": "us-east-1b",
                    "region": "us-east-1",
                    "aws_profile": "fake",
                }
                adapter = production_adapter(repo, inputs, output)
                (output / "capacity-reservation-create.stderr").write_text(stderr, encoding="utf-8")
                with patch.object(
                    adapter,
                    "aws",
                    side_effect=RuntimeError("capacity-reservation-create exited 255"),
                ) as aws:
                    probe = adapter.reserve_capacity(time.perf_counter() + 10)
                self.assertEqual(probe["result"], expected_result)
                self.assertEqual(probe["error_code"], expected_code)
                self.assertEqual(probe["zone"], "us-east-1b")
                self.assertFalse(probe["cleanup_verified"])
                self.assertEqual(aws.call_args.args[:2], ("ec2", "create-capacity-reservation"))

    @unittest.skipUnless(shutil.which("aws"), "AWS CLI is not installed in this environment")
    def test_real_aws_cli_capacity_reservation_argv_uses_local_fake_ec2_endpoint(self):
        def run_case(case_name, transition, expected_result):
            state = {
                "current": "pending",
                "transitions": [transition],
                "end_date": None,
                "create_received_at": None,
                "requests": [],
            }

            def reservation_body(current, date):
                date = date or "2026-10-07T23:00:00Z"
                return (
                    "<capacityReservationId>cr-0abc1234</capacityReservationId>"
                    "<instanceType>g6.xlarge</instanceType><availabilityZone>us-east-1b</availabilityZone>"
                    "<instancePlatform>Linux/UNIX</instancePlatform><instanceMatchCriteria>open</instanceMatchCriteria>"
                    "<tenancy>default</tenancy><totalInstanceCount>2</totalInstanceCount>"
                    "<availableInstanceCount>2</availableInstanceCount><state>"
                    + current
                    + "</state>"
                    + "<endDateType>limited</endDateType><endDate>"
                    + date
                    + "</endDate>"
                )

            class Handler(BaseHTTPRequestHandler):
                def log_message(self, *args):
                    pass

                def do_POST(self):
                    length = int(self.headers.get("Content-Length", "0"))
                    params = parse_qs(self.rfile.read(length).decode("utf-8"))
                    state["requests"].append(params)
                    action = params["Action"][0]
                    if action == "CreateCapacityReservation":
                        state["create_received_at"] = datetime.datetime.now(datetime.UTC)
                        state["end_date"] = params["EndDate"][0]
                        state["client_token"] = params["ClientToken"][0]
                        body = reservation_body("pending", state["end_date"])
                        response = (
                            '<CreateCapacityReservationResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">'
                            "<requestId>local-create</requestId><capacityReservation>"
                            + body
                            + "</capacityReservation></CreateCapacityReservationResponse>"
                        )
                    elif action == "DescribeCapacityReservations":
                        if state["transitions"]:
                            state["current"] = state["transitions"].pop(0)
                        response = (
                            '<DescribeCapacityReservationsResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">'
                            "<requestId>local-describe</requestId><capacityReservationSet><item>"
                            + reservation_body(state["current"], state["end_date"])
                            + "</item></capacityReservationSet></DescribeCapacityReservationsResponse>"
                        )
                    elif action == "CancelCapacityReservation":
                        state["current"] = "cancelled"
                        response = (
                            '<CancelCapacityReservationResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">'
                            "<requestId>local-cancel</requestId><return>true</return>"
                            "</CancelCapacityReservationResponse>"
                        )
                    else:
                        self.send_error(400, "unexpected action")
                        return
                    payload = response.encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/xml; charset=utf-8")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)

            server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with tempfile.TemporaryDirectory() as root:
                    repo = Path(root)
                    output = repo / "attempt"
                    output.mkdir()
                    credentials = repo / "credentials"
                    credentials.write_text(
                        "[fake-ec2]\naws_access_key_id = TESTACCESSKEY\n"
                        "aws_secret_access_key = TESTSECRETKEY\n",
                        encoding="utf-8",
                    )
                    config = repo / "config"
                    config.write_text(
                        "[profile fake-ec2]\nregion = us-east-1\noutput = json\n",
                        encoding="utf-8",
                    )
                    plan, inputs = fixture_inputs("success")
                    inputs["aws_profile"] = "fake-ec2"
                    inputs["session_id"] = "unit-session"
                    inputs["region"] = "us-east-1"
                    inputs["availability_zone"] = "us-east-1b"
                    inputs["gpu_type"] = "g6.xlarge"
                    inputs["cpu_type"] = "c6i.2xlarge"
                    adapter = production_adapter(repo, inputs, output)
                    gate = ConsumeGate(repo / "consume.sqlite3")
                    endpoint = f"http://127.0.0.1:{server.server_port}"
                    apply_calls = []

                    def apply_stub(_plan, _deadline, record):
                        apply_calls.append(True)
                        record("apply_invoked")

                    with (
                        patch.dict(
                            os.environ,
                            {
                                "AWS_ENDPOINT_URL_EC2": endpoint,
                                "AWS_SHARED_CREDENTIALS_FILE": str(credentials),
                                "AWS_CONFIG_FILE": str(config),
                                "AWS_ACCESS_KEY_ID": "TESTACCESSKEY",
                                "AWS_SECRET_ACCESS_KEY": "TESTSECRETKEY",
                                "AWS_EC2_METADATA_DISABLED": "true",
                            },
                        ),
                        patch.object(adapter, "preflight", return_value=None),
                        patch.object(adapter, "apply", side_effect=apply_stub),
                        patch.object(adapter, "ready", return_value=None),
                        patch.object(adapter, "measure", return_value=None),
                        patch.object(adapter, "wait_until", return_value=None),
                        patch.object(adapter, "quota_denied_after", return_value=False),
                        patch.object(adapter, "close_admissions", return_value=None),
                        patch.object(adapter, "export", return_value=True),
                        patch.object(adapter, "destroy", return_value=None),
                        patch.object(adapter, "verify_teardown", return_value=[]),
                        patch(
                            "inference_platform.r1_lifecycle.CAPACITY_RESERVATION_PENDING_TIMEOUT_SECONDS",
                            15,
                        ),
                        patch(
                            "inference_platform.r1_lifecycle.CAPACITY_RESERVATION_SETTLE_TIMEOUT_SECONDS",
                            15,
                        ),
                        patch(
                            "inference_platform.r1_lifecycle.CAPACITY_RESERVATION_POLL_SECONDS",
                            0.001,
                        ),
                        patch.object(adapter, "command", wraps=adapter.command) as command,
                    ):
                        t0 = datetime.datetime.now(datetime.UTC)
                        result = execute(
                            adapter,
                            plan,
                            inputs,
                            gate,
                            lambda _inputs: None,
                            output / "receipt.json",
                        )

                    actions = [item["Action"][0] for item in state["requests"]]
                    expected_actions = (
                        [
                            "CreateCapacityReservation",
                            "DescribeCapacityReservations",
                            "DescribeCapacityReservations",
                            "CancelCapacityReservation",
                            "DescribeCapacityReservations",
                            "DescribeCapacityReservations",
                            "DescribeCapacityReservations",
                            "DescribeCapacityReservations",
                        ]
                        if expected_result == "success"
                        else [
                            "CreateCapacityReservation",
                            "DescribeCapacityReservations",
                            "DescribeCapacityReservations",
                        ]
                    )
                    self.assertEqual(
                        actions,
                        expected_actions,
                        f"{case_name}: {state['requests']}",
                    )
                    event_names = [event["event"] for event in result["events"]]
                    probe_events = [
                        event for event in result["events"] if event["event"] == "capacity_probe"
                    ]
                    self.assertTrue(probe_events, result["events"])
                    probe_event = probe_events[0]
                    self.assertEqual(
                        probe_event["result"],
                        expected_result,
                        f"{case_name}: {probe_event}; {state['requests']}",
                    )
                    self.assertEqual(result["exit_code"], 0 if expected_result == "success" else 2)
                    self.assertEqual(bool(apply_calls), expected_result == "success")
                    self.assertEqual(
                        gate.plan_status(inputs["plan_sha256"]),
                        "verified" if expected_result == "success" else None,
                    )
                    with gate.connect() as db:
                        halt_rows = db.execute("SELECT COUNT(*) FROM halt").fetchone()[0]
                    self.assertEqual(halt_rows, 0)
                    create_request = state["requests"][0]
                    self.assertEqual(len(create_request["ClientToken"][0]), 36)
                    self.assertEqual(
                        str(uuid.UUID(create_request["ClientToken"][0])),
                        create_request["ClientToken"][0],
                    )
                    self.assertEqual(uuid.UUID(create_request["ClientToken"][0]).version, 4)
                    self.assertEqual(state["client_token"], create_request["ClientToken"][0])
                    describe_requests = [
                        request
                        for request in state["requests"]
                        if request["Action"][0] == "DescribeCapacityReservations"
                    ]
                    self.assertTrue(
                        any(
                            "cr-0abc1234"
                            in " ".join(value for values in request.values() for value in values)
                            for request in describe_requests
                        )
                    )
                    self.assertTrue(
                        any(
                            "unit-session"
                            in " ".join(value for values in request.values() for value in values)
                            and "INF-040"
                            in " ".join(value for values in request.values() for value in values)
                            for request in describe_requests
                        )
                    )
                    create_command = command.call_args_list[0].args[0]
                    self.assertEqual(
                        create_command[:7],
                        [
                            "aws",
                            "--region",
                            "us-east-1",
                            "--profile",
                            "fake-ec2",
                            "ec2",
                            "create-capacity-reservation",
                        ],
                    )
                    self.assertEqual(
                        create_command[create_command.index("--client-token") + 1],
                        state["client_token"],
                    )
                    for flag, value in (
                        ("--instance-type", "g6.xlarge"),
                        ("--instance-platform", "Linux/UNIX"),
                        ("--availability-zone", "us-east-1b"),
                        ("--instance-count", "2"),
                        ("--instance-match-criteria", "open"),
                        ("--tenancy", "default"),
                        ("--end-date-type", "limited"),
                    ):
                        self.assertEqual(create_command[create_command.index(flag) + 1], value)
                    tags = create_command[create_command.index("--tag-specifications") + 1]
                    self.assertIn("Project,Value=multi-tenant-llm-inference-platform", tags)
                    self.assertIn("Session,Value=" + inputs["session_id"], tags)
                    self.assertIn("Milestone,Value=INF-040", tags)
                    expected_end = datetime.datetime.fromisoformat(
                        state["end_date"].replace("Z", "+00:00")
                    )
                    self.assertGreaterEqual(
                        expected_end,
                        t0 + datetime.timedelta(seconds=899),
                    )
                    self.assertLessEqual(
                        expected_end,
                        state["create_received_at"]
                        + datetime.timedelta(seconds=CAPACITY_RESERVATION_END_GRACE_SECONDS),
                    )
                    if expected_result == "success":
                        self.assertIn("plan_consumed", event_names)
                        self.assertLess(
                            event_names.index("plan_consumed"), event_names.index("apply_invoked")
                        )
                        self.assertIn("CancelCapacityReservation", actions)
                        self.assertLess(
                            actions.index("CreateCapacityReservation"),
                            actions.index("CancelCapacityReservation"),
                        )
                        self.assertEqual(state["current"], "cancelled")
                        self.assertEqual(actions[-1], "DescribeCapacityReservations")
                    else:
                        self.assertNotIn("plan_consumed", event_names)
                        self.assertEqual(actions.count("CancelCapacityReservation"), 0)
                        self.assertEqual(probe_event["error_code"], "CapacityReservationFailed")
                        self.assertFalse(probe_event["consumed"])
                    return actions, state["requests"]
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

        active_actions, active_requests = run_case("pending-active", "active", "success")
        failed_actions, failed_requests = run_case("pending-failed", "failed", "create_error")
        self.assertNotEqual(
            active_requests[0]["ClientToken"][0], failed_requests[0]["ClientToken"][0]
        )
        self.assertEqual(
            active_actions[0:2], ["CreateCapacityReservation", "DescribeCapacityReservations"]
        )
        self.assertEqual(
            failed_actions[0:2], ["CreateCapacityReservation", "DescribeCapacityReservations"]
        )

    def test_stubbed_pending_forever_times_out_without_cancel(self):
        with tempfile.TemporaryDirectory() as root:
            repo = Path(root)
            output = repo / "attempt"
            output.mkdir()
            plan, inputs = fixture_inputs("success")
            inputs["session_id"] = "unit-session"
            inputs["aws_profile"] = "fake-ec2"
            inputs["availability_zone"] = "us-east-1b"
            adapter = production_adapter(repo, inputs, output)
            calls = []

            def aws(_service, operation, args, _deadline, name):
                calls.append((operation, args, name))
                if operation == "create-capacity-reservation":
                    return {
                        "CapacityReservation": {
                            "CapacityReservationId": "cr-pending-forever",
                            "State": "pending",
                            "AvailabilityZone": "us-east-1b",
                            "InstanceType": "g6.xlarge",
                            "InstancePlatform": "Linux/UNIX",
                            "Tenancy": "default",
                            "InstanceMatchCriteria": "open",
                            "TotalInstanceCount": 2,
                            "AvailableInstanceCount": 2,
                        }
                    }
                if operation == "describe-capacity-reservations":
                    return {
                        "CapacityReservations": [
                            {
                                "CapacityReservationId": "cr-pending-forever",
                                "State": "pending",
                                "AvailabilityZone": "us-east-1b",
                                "InstanceType": "g6.xlarge",
                                "InstancePlatform": "Linux/UNIX",
                                "Tenancy": "default",
                                "InstanceMatchCriteria": "open",
                                "TotalInstanceCount": 2,
                                "AvailableInstanceCount": 2,
                            }
                        ]
                    }
                raise AssertionError("pending reservation must never be cancelled")

            gate = ConsumeGate(repo / "consume.sqlite3")
            with (
                patch.object(adapter, "aws", side_effect=aws),
                patch.object(adapter, "preflight", return_value=None),
                patch.object(
                    adapter,
                    "apply",
                    side_effect=AssertionError("pending reservation must stop before Apply"),
                ),
                patch(
                    "inference_platform.r1_lifecycle.CAPACITY_RESERVATION_PENDING_TIMEOUT_SECONDS",
                    0.002,
                ),
                patch(
                    "inference_platform.r1_lifecycle.CAPACITY_RESERVATION_SETTLE_TIMEOUT_SECONDS",
                    0.002,
                ),
                patch("inference_platform.r1_lifecycle.CAPACITY_RESERVATION_POLL_SECONDS", 0.001),
            ):
                result = execute(
                    adapter,
                    plan,
                    inputs,
                    gate,
                    lambda _inputs: None,
                    output / "receipt.json",
                )

            events = result["events"]
            names = [event["event"] for event in events]
            probe = next(event for event in events if event["event"] == "capacity_probe")
            failed = names.index("capacity_reservation_cancel_failed")
            self.assertEqual(probe["result"], "partial")
            self.assertEqual(probe["error_code"], "ReservationPendingTimeout")
            self.assertEqual(probe["state"], "pending")
            self.assertFalse(probe["cleanup_verified"])
            self.assertLess(names.index("capacity_probe"), failed)
            self.assertEqual(result["exit_code"], 2)
            self.assertEqual(result["apply_count"], 0)
            self.assertIsNone(result["gate_plan_status"])
            self.assertIsNone(gate.plan_status(inputs["plan_sha256"]))
            with gate.connect() as db:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM halt").fetchone()[0], 1)
            self.assertGreaterEqual(
                sum(operation == "describe-capacity-reservations" for operation, _, _ in calls), 2
            )
            wait_names = {name for _, _, name in calls}
            self.assertIn("capacity-reservation-pending-probe", wait_names)
            self.assertIn("capacity-reservation-pending-settle", wait_names)
            self.assertNotIn(
                "cancel-capacity-reservation", [operation for operation, _, _ in calls]
            )

    def test_ready_failure_uses_one_bounded_ssm_diagnostic_per_host_then_destroys(self):
        with tempfile.TemporaryDirectory() as root:
            folder = Path(root)
            prod = production_adapter(folder, {"runtime_directory": "runtime"}, folder)
            runtime = folder / "runtime"
            runtime.mkdir()
            (runtime / "operator-context.json").write_bytes(
                encoded(
                    {
                        "hosts": {role: {"id": role} for role in ROLES},
                        "control_token": "PRIVATE_TOKEN",
                    }
                )
            )
            calls = []

            class Failure(Virtual):
                def close_admissions(self, deadline):
                    raise AssertionError("forward close before readiness")

                def export(self, deadline):
                    raise AssertionError("forward export before readiness")

                def readiness_diagnostics(self, deadline):
                    self_bound = deadline - self.now()
                    self_test.assertEqual(self_bound, 60)
                    with patch.object(prod, "now", return_value=self.now()):
                        return prod.readiness_diagnostics(deadline)

                def destroy(self, deadline, record):
                    self_test.assertEqual(sorted(x[0] for x in calls), sorted(ROLES))
                    super().destroy(deadline, record)

            def ssm(op, host, commands, *, timeout_s=None):
                self.assertEqual(timeout_s, 45)
                calls.append((host, commands, op.deadline - time.time()))
                if host == "gpu-0":
                    raise TimeoutError("diagnostic unavailable")
                return {"Status": "Success", "StandardOutputContent": "diagnostic output"}

            self_test = self
            plan, inputs = fixture_inputs("readiness_failure")
            with patch.object(Operator, "ssm", autospec=True, side_effect=ssm):
                result = execute(
                    Failure("readiness_failure"),
                    plan,
                    inputs,
                    ConsumeGate(folder / "gate"),
                    lambda _: None,
                    folder / "receipt",
                )
            self.assertFalse(result["export_complete"])
            self.assertEqual(result["remaining_inventory"], [])
            events = [x["event"] for x in result["events"]]
            self.assertNotIn("fixture_export_attempted", events)
            self.assertLess(
                events.index("fixture_readiness_diagnostics_finished"),
                events.index("fixture_destroy_attempted"),
            )
            for _, commands, remaining in calls:
                self.assertGreater(remaining, 0)
                self.assertLessEqual(remaining, 60)
                script = "\n".join(commands)
                for path in (
                    "cloud-init status",
                    "/var/log/cloud-init-output.log",
                    "/opt/r1/bootstrap.log",
                    "disk-before-pull.json",
                    "systemctl status",
                    "ss -ltnp",
                    "ps -ef --forest",
                    "/proc/$pid/cgroup",
                    "journalctl",
                    "/etc/hosts",
                ):
                    self.assertIn(path, script)
            diagnostics = (runtime / "readiness-diagnostics.jsonl").read_bytes()
            self.assertEqual(len(diagnostics.splitlines()), 4)
            self.assertNotIn(b"PRIVATE_TOKEN", diagnostics)

    def test_closed_quota_case_with_granted_value_is_not_a_denial(self):
        with tempfile.TemporaryDirectory() as root:
            adapter = production_adapter(
                Path(root), {"inf057_request_id": "unit-request"}, Path(root)
            )
            for desired, current, expected in ((8, 8, False), (48, 8, True), (48, 48, False)):
                with patch.object(
                    adapter,
                    "aws",
                    side_effect=[
                        {"RequestedQuota": {"Status": "CASE_CLOSED", "DesiredValue": desired}},
                        {"Quota": {"Value": current}},
                    ],
                ):
                    self.assertEqual(adapter.quota_denied_after(), expected)

    def test_crashed_process_consumption_survives_and_blocks_other_plans(self):
        with tempfile.TemporaryDirectory() as root:
            database = Path(root) / "gate.sqlite3"
            code = "from inference_platform.r1_lifecycle import ConsumeGate; import os,sys; ConsumeGate(sys.argv[1]).consume('a'*64, {'region':'us-east-1'}); os._exit(17)"
            result = subprocess.run([sys.executable, "-c", code, str(database)], check=False)
            self.assertEqual(result.returncode, 17)
            gate = ConsumeGate(database)
            self.assertEqual(gate.recovery_inputs("a" * 64), {"region": "us-east-1"})
            with self.assertRaisesRegex(ValueError, "requires verified teardown"):
                gate.consume("b" * 64)
            gate.finish("a" * 64, True)
            with self.assertRaisesRegex(ValueError, "already consumed"):
                gate.consume("a" * 64)

    def test_inventory_error_is_not_empty_and_persists_paid_halt(self):
        class QueryFailure(Virtual):
            def verify_teardown(self, deadline):
                raise RuntimeError("credentials expired")

        with tempfile.TemporaryDirectory() as root:
            plan, inputs = fixture_inputs("success")
            gate = ConsumeGate(Path(root) / "gate.sqlite3")
            result = execute(
                QueryFailure("success"),
                plan,
                inputs,
                gate,
                lambda _: None,
                Path(root) / "receipt.json",
            )
            self.assertIn("paid work halted", result["error"])
            self.assertIn("credentials expired", result["remaining_inventory"][0])
            with self.assertRaisesRegex(ValueError, "paid work halted"):
                ConsumeGate(gate.path).consume("b" * 64)

    def test_production_apply_uses_only_verified_copy_and_never_replans(self):
        with tempfile.TemporaryDirectory() as root:
            repo = Path(root)
            directory = repo / "evidence"
            directory.mkdir()
            secret = b"s" * 32
            (repo / "secret").write_bytes(secret)
            plan, inputs = fixture_inputs("success")
            inputs.update(
                aws_profile="unit",
                session_id="test",
                availability_zone="us-east-1b",
                session_manager_plugin_path=".cache/session-manager-plugin/bin/session-manager-plugin.exe",
                session_manager_plugin_sha256=sha(b"unit-plugin"),
                bundle_path="bundle",
                bundle_sha256="0" * 64,
                cache_secret_path="secret",
                cache_secret_sha256=sha(secret),
                gpu_ami="ami-1",
                cpu_ami="ami-2",
                account_id_sha256=sha(b"unit-account"),
            )
            inputs["source_head"] = "a" * 40
            bundled_python = b"unit source\n"
            inputs["source_sha256"] = {
                "python/src/inference_platform/example.py": sha(bundled_python)
            }
            inputs["bundle_sha256"] = write_bundle(
                repo / inputs["bundle_path"],
                {
                    "python/src/inference_platform/example.py": bundled_python,
                    "bin/gateway": b"unit gateway",
                },
                inputs["source_head"],
            )
            plugin = repo / inputs["session_manager_plugin_path"]
            plugin.parent.mkdir(parents=True)
            plugin.write_bytes(b"unit-plugin")
            instances = [
                {
                    "tags": {"Role": role, "Session": "test"},
                    "instance_type": "g6.xlarge" if role.startswith("gpu") else "c6i.2xlarge",
                    "ami": "ami-1" if role.startswith("gpu") else "ami-2",
                    "capacity_reservation_specification": (
                        [{"capacity_reservation_preference": "capacity-reservations-only"}]
                        if role.startswith("gpu")
                        else []
                    ),
                    "tenancy": "default" if role.startswith("gpu") else None,
                    "root_block_device": [
                        {
                            "volume_size": 200 if role.startswith("gpu") else 40,
                            "volume_type": "gp3",
                            "encrypted": True,
                            "delete_on_termination": True,
                            "iops": 3000,
                            "throughput": 125,
                        }
                    ],
                }
                for role in ROLES
            ]
            document = {
                "variables": {
                    "aws_region": {"value": "us-east-1"},
                    "aws_profile": {"value": "unit"},
                    "availability_zone": {"value": "us-east-1b"},
                    "m4_estimate_usd": {"value": 85.92},
                },
                "resource_changes": [
                    {"type": "aws_instance", "change": {"actions": ["create"], "after": x}}
                    for x in instances
                ],
            }
            calls = []
            adapter = production_adapter(repo, inputs, directory)

            def tf(args, deadline, name):
                calls.append(args)
                return encoded(document if name == "saved-plan" else {})

            with (
                patch.object(adapter, "tf", side_effect=tf),
                patch.object(
                    adapter,
                    "command",
                    side_effect=lambda argv, deadline, name: (
                        b"1.0\n"
                        if Path(argv[0]).name.startswith("session-manager-plugin")
                        else b"Terraform v1.16.2\non windows_amd64\n"
                        if Path(argv[0]).name.startswith("terraform")
                        else b"aws-cli/2.0\n"
                    ),
                ),
                patch.object(
                    adapter,
                    "aws",
                    side_effect=lambda service, operation, *args: (
                        {"Quota": {"Value": 32}}
                        if operation == "get-service-quota"
                        else {"Reservations": []}
                        if operation == "describe-instances"
                        else {"Account": "unit-account"}
                    ),
                ),
                patch.object(adapter, "verify_teardown", return_value=[]),
                patch(
                    "inference_platform.terraform_apply_watchdog.bounded_apply", return_value=0
                ) as apply_watchdog,
            ):
                preflight_events = []
                adapter.preflight(
                    plan,
                    inputs,
                    lambda event, **fields: preflight_events.append({"event": event, **fields}),
                )
                self.assertEqual(
                    preflight_events,
                    [
                        {
                            "event": "operator_toolchain",
                            "session_manager_plugin": {
                                "path": inputs["session_manager_plugin_path"],
                                "sha256": inputs["session_manager_plugin_sha256"],
                                "version": "1.0",
                            },
                            "aws_version": "aws-cli/2.0",
                            "terraform": {
                                "path": str(adapter.terraform),
                                "sha256": sha(adapter.terraform.read_bytes()),
                                "version": "Terraform v1.16.2\non windows_amd64",
                            },
                        }
                    ],
                )
                adapter.apply(plan, time.perf_counter() + 5, lambda *a, **k: None)
                self.assertEqual(adapter.plan_path.read_bytes(), plan)
                apply_argv = apply_watchdog.call_args.args[0]
                self.assertEqual(apply_argv, adapter.apply_argv())
                self.assertEqual(apply_argv[-4], "apply")
                self.assertEqual(apply_argv[-1], str(adapter.plan_path))
                self.assertEqual(apply_watchdog.call_args.args[1].name, "apply-watchdog.json")
                self.assertFalse(any("plan" in argv for argv in calls))
                adapter.plan_path.write_bytes(b"changed")
                with self.assertRaisesRegex(ValueError, "consumed plan changed"):
                    adapter.apply(plan, time.perf_counter() + 5, lambda *a, **k: None)

    def test_apply_watchdog_uses_one_cloudtrail_page_then_destroys_and_verifies(self):
        cloudtrail_capacity = {
            "Events": [
                {
                    "EventTime": "2026-10-07T18:20:00Z",
                    "CloudTrailEvent": json.dumps(
                        {
                            "eventName": "RunInstances",
                            "errorCode": "Server.InsufficientInstanceCapacity",
                            "eventTime": "2026-10-07T18:20:00Z",
                            "userIdentity": {"accountId": "DO_NOT_PERSIST_123456789012"},
                            "requestParameters": {
                                "placement": {"availabilityZone": "us-east-1b"},
                                "instancesSet": {"items": [{"instanceType": "g6.xlarge"}]},
                            },
                        }
                    ),
                }
            ]
        }
        no_capacity = {"Events": []}
        fake_source = """
import signal
import time
signal.signal(getattr(signal, 'SIGBREAK', signal.SIGINT), signal.SIG_IGN)
while True:
    print('Still creating', flush=True)
    time.sleep(.03)
"""

        for cloudtrail, expected_cause, expected_source in (
            (cloudtrail_capacity, "capacity", "cloudtrail"),
            (no_capacity, "timeout", "watchdog"),
        ):
            with self.subTest(expected_cause=expected_cause), tempfile.TemporaryDirectory() as root:
                repo = Path(root)
                plan, inputs = fixture_inputs("success")
                inputs.update(
                    terraform="fake-terraform.exe",
                    aws_profile="unit",
                    region="us-east-1",
                    availability_zone="us-east-1b",
                )
                output = repo / "attempt"
                output.mkdir()
                adapter = production_adapter(repo, inputs, output)
                adapter.plan_path.write_bytes(plan)
                adapter.apply_watchdog_seconds = 0.25
                adapter.apply_interrupt_grace_s = 0.15
                adapter.apply_argv = lambda: [sys.executable, "-u", "-c", fake_source]
                aws_calls = []

                def aws(
                    service,
                    operation,
                    args,
                    deadline,
                    name,
                    captured_calls=aws_calls,
                    response=cloudtrail,
                ):
                    captured_calls.append((service, operation, args, name))
                    return response

                final_receipt = output / "lifecycle.json"
                with (
                    patch.object(adapter, "preflight", return_value=None),
                    patch.object(adapter, "aws", side_effect=aws),
                    patch.object(
                        adapter,
                        "reserve_capacity",
                        return_value={
                            "result": "success",
                            "zone": "us-east-1b",
                            "capacity_reservation_id": "cr-fixture",
                            "state": "active",
                        },
                    ),
                    patch.object(
                        adapter,
                        "cancel_capacity",
                        return_value={
                            "verified": True,
                            "state": "cancelled",
                            "cancel_requested": True,
                        },
                    ),
                    patch.object(adapter, "readiness_diagnostics", return_value=[]),
                    patch.object(
                        adapter, "cancel_session_capacity_reservations", return_value=True
                    ),
                    patch.object(adapter, "destroy") as destroy,
                    patch.object(adapter, "verify_teardown", return_value=[]),
                    patch.object(adapter, "ready") as ready,
                    contextlib.redirect_stdout(io.StringIO()),
                ):
                    result = execute(
                        adapter,
                        plan,
                        inputs,
                        ConsumeGate(output / "consume.sqlite3"),
                        lambda _: None,
                        final_receipt,
                    )

                watchdog = json.loads((output / "apply-watchdog.json").read_text())
                final = json.loads(final_receipt.read_text())
                events = final["events"]
                names = [event["event"] for event in events]
                abort = next(event for event in events if event["event"] == "infrastructure_abort")
                self.assertEqual(result["apply_count"], 1)
                self.assertEqual(abort["cause"], expected_cause)
                self.assertEqual(abort["source"], expected_source)
                self.assertTrue(watchdog["deadline_exceeded"])
                self.assertTrue(watchdog["forced_process_tree_stop"])
                self.assertLess(watchdog["elapsed_seconds"], 5)
                self.assertEqual(len(aws_calls), 1)
                self.assertEqual(aws_calls[0][0:2], ("cloudtrail", "lookup-events"))
                self.assertIn("--no-paginate", aws_calls[0][2])
                self.assertLess(names.index("apply_started"), names.index("infrastructure_abort"))
                self.assertLess(names.index("infrastructure_abort"), names.index("destroy_started"))
                self.assertLess(names.index("destroy_started"), names.index("destroy_finished"))
                self.assertLess(names.index("destroy_finished"), names.index("teardown_verified"))
                destroy.assert_called_once()
                ready.assert_not_called()
                self.assertIn("Still creating", (output / "apply.stdout").read_text())
                self.assertNotIn("DO_NOT_PERSIST_123456789012", final_receipt.read_text())
                if expected_cause == "capacity":
                    self.assertEqual(abort["capacity_event_count"], 1)
                    self.assertEqual(abort["error_code"], "Server.InsufficientInstanceCapacity")
                    self.assertEqual(abort["availability_zone"], "us-east-1b")
                    self.assertEqual(abort["instance_type_counts"], {"g6.xlarge": 1})
                else:
                    self.assertEqual(abort["capacity_event_count"], 0)
                    self.assertIsNone(abort["error_code"])
                    self.assertEqual(abort["availability_zone"], "us-east-1b")

    def test_plugin_absent_or_hash_mismatch_refuses_before_consuming_gate_or_applying(self):
        for case, payload, expected, error in (
            ("absent", None, "0" * 64, "plugin is missing"),
            ("wrong-hash", b"wrong plugin", "0" * 64, "SHA256 mismatch"),
        ):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as root:
                repo = Path(root)
                directory = repo / "evidence"
                directory.mkdir()
                plan, inputs = fixture_inputs("success")
                inputs.update(
                    session_manager_plugin_path=".cache/session-manager-plugin/bin/session-manager-plugin.exe",
                    session_manager_plugin_sha256=expected,
                )
                inputs["source_head"] = "a" * 40
                bundled_python = b"unit source\n"
                inputs["source_sha256"] = {
                    "python/src/inference_platform/example.py": sha(bundled_python)
                }
                inputs["bundle_path"] = "bundle.tar.gz"
                inputs["bundle_sha256"] = write_bundle(
                    repo / inputs["bundle_path"],
                    {
                        "python/src/inference_platform/example.py": bundled_python,
                        "bin/gateway": b"unit gateway",
                    },
                    inputs["source_head"],
                )
                if payload is not None:
                    plugin = repo / inputs["session_manager_plugin_path"]
                    plugin.parent.mkdir(parents=True)
                    plugin.write_bytes(payload)
                adapter = production_adapter(repo, inputs, directory)
                gate = ConsumeGate(repo / "gate.sqlite3")
                receipt = directory / "lifecycle.json"
                with patch.object(adapter, "apply") as apply:
                    result = execute(adapter, plan, inputs, gate, lambda _: None, receipt)
                self.assertIn(error, result["error"])
                self.assertEqual(result["apply_count"], 0)
                self.assertEqual(adapter.aws_calls, 0)
                apply.assert_not_called()
                with self.assertRaisesRegex(ValueError, "no durable recovery binding"):
                    gate.recovery_inputs(inputs["plan_sha256"])

    def test_pinned_plugin_directory_is_first_in_production_and_tunnel_child_paths(self):
        with tempfile.TemporaryDirectory() as root:
            repo = Path(root)
            relative = Path(".cache/session-manager-plugin/bin/session-manager-plugin.exe")
            plugin = repo / relative
            plugin.parent.mkdir(parents=True)
            plugin.write_bytes(b"unit-plugin")
            inputs = {
                "session_manager_plugin_path": relative.as_posix(),
                "aws_profile": "unit",
                "region": "us-east-1",
            }
            plugin_dir = str(plugin.parent.resolve())
            production_directory = repo / "production"
            production_directory.mkdir()
            adapter = production_adapter(repo, inputs, production_directory)
            output = adapter.command(
                [sys.executable, "-c", "import os; print(os.environ['PATH'].split(os.pathsep)[0])"],
                time.perf_counter() + 10,
                "path-check",
            )
            self.assertEqual(output.decode().strip(), plugin_dir)

            operator = Operator(repo, inputs, repo / "operator", time.time() + 10)
            with patch("inference_platform.r1_cloud_operator.subprocess.Popen") as popen:
                operator.tunnel("i-unit")
            child_path = popen.call_args.kwargs["env"]["PATH"]
            self.assertEqual(child_path.split(os.pathsep)[0], plugin_dir)

    def test_relative_production_directory_makes_show_and_apply_plan_paths_absolute(self):
        with tempfile.TemporaryDirectory() as root:
            repo = Path(root)
            original_directory = Path.cwd()
            try:
                os.chdir(repo)
                plugin = repo / ".cache/session-manager-plugin/bin/session-manager-plugin.exe"
                plugin.parent.mkdir(parents=True)
                plugin.write_bytes(b"unit plugin")
                plan = b"saved plan"
                inputs = {
                    "terraform": ".tools/terraform/1.16.2/terraform.exe",
                    "session_manager_plugin_path": plugin.relative_to(repo).as_posix(),
                    "session_manager_plugin_sha256": sha(plugin.read_bytes()),
                    "aws_profile": "unit",
                    "region": "us-east-1",
                    "plan_sha256": sha(plan),
                    "source_head": "a" * 40,
                }
                bundled_python = b"unit source\n"
                inputs["source_sha256"] = {
                    "python/src/inference_platform/example.py": sha(bundled_python)
                }
                inputs["bundle_path"] = "bundle.tar.gz"
                inputs["bundle_sha256"] = write_bundle(
                    repo / inputs["bundle_path"],
                    {
                        "python/src/inference_platform/example.py": bundled_python,
                        "bin/gateway": b"unit gateway",
                    },
                    inputs["source_head"],
                )
                adapter = production_adapter(repo, inputs, Path("relative-output"))
                adapter.directory.mkdir(parents=True)
                calls = []

                with (
                    patch.object(
                        adapter,
                        "command",
                        side_effect=lambda argv, deadline, name: (
                            b"1.0\n"
                            if name == "plugin-version"
                            else b"aws-cli/2.0\n"
                            if name == "aws-version"
                            else b"Terraform v1.16.2\n"
                        ),
                    ),
                    patch.object(
                        adapter,
                        "tf",
                        side_effect=lambda args, deadline, name: calls.append(args) or b"{}",
                    ),
                    patch(
                        "inference_platform.terraform_apply_watchdog.bounded_apply",
                        return_value=0,
                    ) as apply_watchdog,
                ):
                    with self.assertRaises(KeyError):
                        adapter.preflight(plan, inputs)
                    adapter.apply(plan, time.perf_counter() + 5, lambda *a, **k: None)

                self.assertEqual(calls[0][0:2], ["show", "-json"])
                self.assertEqual(calls[0][-1], str(adapter.plan_path))
                self.assertTrue(Path(calls[0][-1]).is_absolute())
                apply_argv = apply_watchdog.call_args.args[0]
                self.assertEqual(apply_argv[-4], "apply")
                self.assertEqual(apply_argv[-1], str(adapter.plan_path))
                self.assertTrue(Path(apply_argv[-1]).is_absolute())
            finally:
                os.chdir(original_directory)

    def test_output_overlapping_runtime_is_refused_before_gate_or_mkdir(self):
        for output_kind in ("equal", "inside", "contains"):
            with self.subTest(output_kind=output_kind), tempfile.TemporaryDirectory() as root:
                repo = Path(root)
                runtime = repo / ".cache/runtime"
                output = {
                    "equal": runtime,
                    "inside": runtime / "nested/output",
                    "contains": repo / ".cache",
                }[output_kind]
                inputs = {
                    "runtime_directory": ".cache/runtime",
                    "commands": {"ready": ["fixture", "--inputs", "inputs.json"]},
                    "bundle_path": "artifacts/bundle/payload.tar.gz",
                    "session_manager_plugin_path": "artifacts/plugin/session-manager-plugin.exe",
                    "terraform": "artifacts/terraform/terraform.exe",
                }
                inputs_path = repo / "inputs.json"
                inputs_path.write_text(json.dumps(inputs), encoding="utf-8")
                saved_plan = repo / "plans/reviewed.tfplan"
                saved_plan.parent.mkdir()
                saved_plan.write_bytes(b"plan")
                argv = [
                    "r1_lifecycle",
                    "--repo",
                    str(repo),
                    "--inputs",
                    str(inputs_path),
                    "--saved-plan",
                    str(saved_plan),
                    "--output",
                    str(output),
                    "--apply",
                ]
                stderr = io.StringIO()
                with (
                    patch.object(sys, "argv", argv),
                    patch("inference_platform.r1_lifecycle.Production") as production,
                    patch("inference_platform.r1_lifecycle.execute") as execute_lifecycle,
                    patch(
                        "inference_platform.r1_lifecycle.subprocess.check_output"
                    ) as check_output,
                    patch("sys.stderr", stderr),
                ):
                    with self.assertRaises(SystemExit) as result:
                        lifecycle_main()

                self.assertEqual(result.exception.code, 2)
                self.assertIn("runtime_directory", stderr.getvalue())
                self.assertFalse(output.exists())
                self.assertFalse(runtime.exists())
                production.assert_not_called()
                execute_lifecycle.assert_not_called()
                check_output.assert_not_called()
                self.assertFalse((repo / "r1-paid-consumption.sqlite3").exists())

    def test_operator_ready_uses_absolute_pinned_terraform_path(self):
        with tempfile.TemporaryDirectory() as root:
            repo = Path(root)
            inputs = {"terraform": ".tools/terraform/1.16.2/terraform.exe"}
            terraform = repo / inputs["terraform"]
            terraform.parent.mkdir(parents=True)
            terraform.write_bytes(b"unit terraform")
            operator = Operator(repo, inputs, repo / "operator", time.time() + 30)
            with patch(
                "inference_platform.r1_cloud_operator.subprocess.check_output",
                side_effect=subprocess.CalledProcessError(1, "terraform output"),
            ) as check_output:
                with self.assertRaises(subprocess.CalledProcessError):
                    operator.ready()
            argv = check_output.call_args.args[0]
            self.assertTrue(Path(argv[0]).is_absolute())
            self.assertEqual(Path(argv[0]), (repo / inputs["terraform"]).resolve())

    def test_removed_terraform_cli_override_is_rejected_before_output_or_gate(self):
        with tempfile.TemporaryDirectory() as root:
            repo = Path(root)
            output = repo / "output"
            argv = [
                "r1_lifecycle",
                "--repo",
                str(repo),
                "--inputs",
                str(repo / "inputs.json"),
                "--saved-plan",
                str(repo / "plan.tfplan"),
                "--output",
                str(output),
                "--apply",
                "--terraform",
                str(repo / "different-terraform.exe"),
            ]
            with (
                patch.object(sys, "argv", argv),
                patch("inference_platform.r1_lifecycle.Production") as production,
                patch("inference_platform.r1_lifecycle.execute") as execute_lifecycle,
                patch("inference_platform.r1_lifecycle.subprocess.check_output") as check_output,
                patch("sys.stderr", io.StringIO()),
            ):
                with self.assertRaises(SystemExit) as result:
                    lifecycle_main()
            self.assertEqual(result.exception.code, 2)
            self.assertFalse(output.exists())
            production.assert_not_called()
            execute_lifecycle.assert_not_called()
            check_output.assert_not_called()
            self.assertFalse((repo / "r1-paid-consumption.sqlite3").exists())

    def test_mismatched_legacy_terraform_override_refuses_without_binding(self):
        with tempfile.TemporaryDirectory() as root:
            repo = Path(root)
            inputs = {"terraform": ".tools/terraform/1.16.2/terraform.exe"}
            bound = repo / inputs["terraform"]
            bound.parent.mkdir(parents=True)
            bound.write_bytes(b"bound terraform")
            different = repo / "different-terraform.exe"
            different.write_bytes(b"different terraform")
            directory = repo / "evidence"
            directory.mkdir()
            gate = ConsumeGate(repo / "gate.sqlite3")
            with (
                patch.object(Production, "apply") as apply,
                patch.object(Production, "aws") as aws,
            ):
                with self.assertRaisesRegex(ValueError, "differs from the reviewed inputs"):
                    Production(repo, inputs, directory, str(different))
            apply.assert_not_called()
            aws.assert_not_called()
            with self.assertRaisesRegex(ValueError, "no durable recovery binding"):
                gate.recovery_inputs("a" * 64)

    def test_real_teardown_queries_ec2_storage_network_iam_and_state(self):
        with tempfile.TemporaryDirectory() as root:
            adapter = production_adapter(
                Path(root),
                {"region": "us-east-1", "session_id": "case", "aws_profile": "unit"},
                Path(root),
            )
            operations, reservation_filters = [], []

            def aws(service, operation, args, deadline, name):
                operations.append((service, operation))
                if operation == "describe-instances":
                    return {"Reservations": [{"Instances": [{"State": {"Name": "terminated"}}]}]}
                if operation == "describe-capacity-reservations":
                    reservation_filters.extend(args)
                    return {
                        "CapacityReservations": [
                            {"State": "active"},
                            {"State": "pending"},
                            {"State": "cancelled"},
                        ]
                    }
                if operation == "describe-volumes":
                    return {"Volumes": [{"VolumeId": "unit-leftover"}]}
                if operation == "list-roles":
                    return {"Roles": [{"RoleName": "r1-case-leftover"}]}
                if operation == "list-instance-profiles":
                    return {"InstanceProfiles": []}
                return {"Items": []}

            with (
                patch.object(adapter, "aws", side_effect=aws),
                patch.object(adapter, "tf", return_value=b"{}"),
            ):
                remaining = adapter.verify_teardown(time.perf_counter() + 5)
            self.assertEqual(remaining, ["volumes", "capacity-reservations", "iam-roles"])
            self.assertEqual(len(operations), 12)
            self.assertIn("--filters", reservation_filters)
            self.assertIn(
                "Name=tag:Project,Values=multi-tenant-llm-inference-platform",
                reservation_filters,
            )
            self.assertIn("Name=tag:Session,Values=case", reservation_filters)
            self.assertIn("Name=tag:Milestone,Values=INF-040", reservation_filters)
            with patch.object(adapter, "aws", side_effect=RuntimeError("query failed")):
                with self.assertRaisesRegex(RuntimeError, "query failed"):
                    adapter.verify_teardown(time.perf_counter() + 5)

    def test_recover_cancels_twice_before_destroy_and_verifies_session_tagged_reservations(self):
        with tempfile.TemporaryDirectory() as root:
            repo = Path(root)
            (repo / ".git").mkdir()
            inputs = {
                "plan_sha256": sha(b"plan"),
                "commands": {"ready": ["fixture", "--inputs", "inputs.json"]},
                "terraform": "artifacts/terraform/terraform.exe",
                "region": "us-east-1",
                "aws_profile": "unit",
                "session_id": "unit-session",
                "runtime_directory": ".cache/r1-runtime",
                "bundle_path": "artifacts/bundle/payload.tar.gz",
                "session_manager_plugin_path": "artifacts/plugin/session-manager-plugin.exe",
            }
            terraform = repo / inputs["terraform"]
            terraform.parent.mkdir(parents=True)
            terraform.write_bytes(b"unit terraform")
            input_path = repo / "inputs.json"
            input_path.write_text(json.dumps(inputs), encoding="utf-8")
            saved_plan = repo / "plans/plan.tfplan"
            saved_plan.parent.mkdir()
            saved_plan.write_bytes(b"plan")
            output = repo / "recover-output"
            gate = ConsumeGate(repo / ".git/r1-paid-consumption.sqlite3")
            gate.consume(
                inputs["plan_sha256"],
                {
                    **inputs,
                    "_capacity_reservation_id": "cr-private-test",
                    "_approval_review_round": 109,
                    "_approval_plan_sha256": [inputs["plan_sha256"], "b" * 64],
                },
            )
            actions, describe_args = [], []
            reservations = [
                {"CapacityReservationId": "cr-private-test", "State": "active"},
                {"CapacityReservationId": "cr-unrecorded-second", "State": "active"},
            ]

            def aws(self, service, operation, args, deadline, name):
                if operation == "describe-capacity-reservations":
                    describe_args.extend(args)
                    return {"CapacityReservations": [dict(item) for item in reservations]}
                if operation == "describe-instances":
                    return {"Reservations": []}
                if operation == "list-roles":
                    return {"Roles": []}
                if operation == "list-instance-profiles":
                    return {"InstanceProfiles": []}
                return {"Items": []}

            def cancel(self, reservation_id, deadline):
                actions.append(("cancel", reservation_id))
                for item in reservations:
                    if item["CapacityReservationId"] == reservation_id:
                        item["State"] = "cancelled"
                return {"verified": True, "state": "cancelled", "cancel_requested": True}

            def destroy(self, deadline, record):
                actions.append(("destroy", None))

            argv = [
                "r1_lifecycle",
                "--repo",
                str(repo),
                "--inputs",
                str(input_path),
                "--saved-plan",
                str(saved_plan),
                "--output",
                str(output),
                "--recover",
            ]
            with (
                patch.object(sys, "argv", argv),
                patch(
                    "inference_platform.r1_lifecycle.subprocess.check_output",
                    return_value=".git",
                ),
                patch.object(Production, "cancel_capacity", new=cancel),
                patch.object(Production, "destroy", new=destroy),
                patch.object(Production, "aws", new=aws),
                patch.object(Production, "tf", return_value=b"{}"),
            ):
                exit_code = lifecycle_main()

            recovery = json.loads((output / "recovery.json").read_text(encoding="utf-8"))
            self.assertEqual(exit_code, 0)
            self.assertEqual(
                actions,
                [
                    ("cancel", "cr-private-test"),
                    ("cancel", "cr-unrecorded-second"),
                    ("cancel", "cr-private-test"),
                    ("destroy", None),
                ],
            )
            self.assertEqual(recovery["remaining"], [])
            self.assertTrue(recovery["verified"])
            self.assertIn("--filters", describe_args)
            self.assertIn(
                "Name=tag:Project,Values=multi-tenant-llm-inference-platform",
                describe_args,
            )
            self.assertIn("Name=tag:Session,Values=unit-session", describe_args)
            self.assertIn("Name=tag:Milestone,Values=INF-040", describe_args)
            self.assertEqual(gate.plan_status(inputs["plan_sha256"]), "verified")

    def test_exact_review_binding_refuses_stale_source_or_wrong_latest_hash(self):
        with tempfile.TemporaryDirectory() as root:
            repo = Path(root)
            source = repo / "source.py"
            source.write_bytes(b"reviewed")
            inputs = {
                "plan_sha256": "a" * 64,
                "source_head": "b" * 40,
                "source_sha256": {"source.py": sha(b"reviewed")},
            }
            path = repo / "inputs.json"
            path.write_bytes(encoded(inputs))
            review = (
                "\n## Claude review rounds\n### Round 88\n- R1 PAID PLAN APPROVED: plan_sha256="
                + "a" * 64
                + "; target="
                + "b" * 40
                + "; review_round=88\n\n## Findings\n"
            )

            def git(argv):
                if argv[3] in {"status", "merge-base"}:
                    return (
                        b" M source.py"
                        if argv[3] == "status" and source.read_bytes() != b"reviewed"
                        else b""
                    )
                if argv[-1] == "HEAD:REVIEW.md":
                    return review.encode()
                if argv[-1].endswith(":inputs.json"):
                    return path.read_bytes()
                return b"reviewed"

            with patch("inference_platform.r1_lifecycle.subprocess.check_output", side_effect=git):
                committed_approval(repo, path)(inputs)
                source.write_bytes(b"changed")
                with self.assertRaisesRegex(ValueError, "clean committed"):
                    committed_approval(repo, path)(inputs)
                source.write_bytes(b"reviewed")
                inputs["plan_sha256"] = "c" * 64
                with self.assertRaisesRegex(ValueError, "latest committed Claude"):
                    committed_approval(repo, path)(inputs)


class RoutineTunnelStopTests(unittest.TestCase):
    def test_windows_hung_taskkill_reaps_only_the_owned_forward_tree(self):
        from types import SimpleNamespace
        from unittest.mock import Mock

        from inference_platform.session_stop import stop_forward

        child = Mock(pid=421, r1_ssm_log=None)
        child.poll.return_value = None
        child.wait.return_value = 1
        live = {
            421: (99, "aws.exe"),
            422: (421, "aws.exe"),
            423: (422, "session-manager-plugin.exe"),
            701: (99, "aws.exe"),
            702: (701, "session-manager-plugin.exe"),
        }
        kernel = Mock()
        kernel.OpenProcess.side_effect = lambda access, inherit, pid: pid
        kernel.WaitForSingleObject.side_effect = lambda pid, ms: 258 if pid in live else 0

        def stop(pid, code):
            del live[pid]
            return True

        kernel.TerminateProcess.side_effect = stop
        child.terminate.side_effect = lambda: live.pop(421)
        with (
            patch("inference_platform.session_stop.os", SimpleNamespace(name="nt")),
            patch(
                "inference_platform.session_stop.ctypes.WinDLL", return_value=kernel, create=True
            ),
            patch(
                "inference_platform.session_stop.windows_processes", side_effect=lambda: dict(live)
            ),
            patch(
                "inference_platform.session_stop.subprocess.run",
                side_effect=subprocess.TimeoutExpired("taskkill", 5),
            ),
        ):
            receipt = stop_forward(child)
        self.assertTrue(receipt["reaped"])
        self.assertTrue(receipt["descendants_verified"])
        self.assertEqual(receipt["descendants_observed"], 2)
        self.assertEqual(receipt["tree_stop_error"], "TimeoutExpired")
        self.assertEqual(set(live), {701, 702})
        child.terminate.assert_called_once_with()
