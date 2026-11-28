"""Exercise the native controller's real saved-plan and cleanup methods."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import inf060_apply as apply_watch
import inf060_diagnostics as diagnostics
import inf060_probe_spec as spec
import inf061_packet as benchmark
from inf060_probe_operator import ProbePorts


CAPACITY_ERROR = (
    "Server.InsufficientInstanceCapacity: We currently do not have sufficient "
    "g6.xlarge capacity in the Availability Zone you requested (us-east-1a). … "
    "You can currently get g6.xlarge capacity by not specifying an Availability "
    "Zone in your request or choosing us-east-1b, us-east-1c, us-east-1d, us-east-1f."
)
PRIVATE_TEXT = "arn:aws:iam::123456789012:role/example 203.0.113.21"


def executable(folder, name, source):
    script = folder / (name + ".py" if os.name == "nt" else name)
    script.write_text("#!/usr/bin/env python3\n" + source, encoding="utf-8")
    if os.name == "nt":
        (folder / (name + ".cmd")).write_text(
            f'@"{sys.executable}" "{script}" %*\n', encoding="utf-8"
        )
    else:
        script.chmod(0o700)


class SavedApplyTests(unittest.TestCase):
    def exercise(self, mode, expected):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            terraform = directory / "terraform"
            terraform.mkdir()
            plan = terraform / "create.tfplan"
            plan.write_bytes(b"synthetic saved plan")
            programs = directory / "bin"
            programs.mkdir()
            executable(
                programs,
                "terraform",
                f"""
import sys, time
from pathlib import Path

if sys.argv[1] == 'destroy':
    assert '-var=provider_attempts=25' in sys.argv
    Path('destroyed').touch(exist_ok=False)
elif sys.argv[1] == 'apply':
    if {mode!r} == 'capacity':
        print({PRIVATE_TEXT!r}, flush=True)
        print({CAPACITY_ERROR!r}, file=sys.stderr, flush=True)
    elif {mode!r} == 'other':
        print('AWS UnauthorizedOperation ' + {PRIVATE_TEXT!r}, flush=True)
        sys.exit(7)
    time.sleep(60)
else:
    sys.exit(99)
""",
            )
            executable(
                programs,
                "aws",
                """
import sys
assert 'describe-instances' in sys.argv
print('{"Reservations": []}')
""",
            )
            with (
                patch.dict(
                    os.environ,
                    {"PATH": str(programs) + os.pathsep + os.environ["PATH"]},
                ),
                patch(
                    "inference_platform.r1_cloud_operator.aws_cli_argv",
                    side_effect=lambda inputs, service, operation, args: [
                        shutil.which("aws"),
                        service,
                        operation,
                        *args,
                    ],
                ),
            ):
                manifest = {
                    "schema": benchmark.SCHEMA,
                    "zone": "us-east-1a",
                    "session": "dec077-inf060-fixture",
                    "operator_tools": {
                        "terraform": {"path": shutil.which("terraform")}
                    },
                    "sealed_plans": {"create_sha256": spec.facts(plan)["sha256"]},
                    "session_manager_plugin_path": "unused",
                }
                spec.save(directory / "manifest.json", manifest)
                ports = ProbePorts(directory, manifest, None, directory)
                before = time.monotonic()
                with self.assertRaises(expected) as raised:
                    ports.apply(time.time() + (1.5 if mode == "timeout" else 30))
                self.assertLess(time.monotonic() - before, 6)
                diagnostics.write(
                    directory / "controller-error.json",
                    diagnostics.exception_record(raised.exception),
                )
                cleanup = ports.teardown(time.time() + 90)
            self.assertTrue(cleanup["destroy_completed"], cleanup)
            self.assertTrue((terraform / "destroyed").exists())
            self.assertTrue((directory / "consumed.json").is_file())
            record = diagnostics.collect(directory)
            self.assertNotIn(PRIVATE_TEXT, json.dumps(record))
            self.assertNotIn("123456789012", json.dumps(record))
            self.assertNotIn("203.0.113.21", json.dumps(record))
            return record

    def test_capacity_stops_running_fake_and_reaches_destroy(self):
        record = self.exercise("capacity", ValueError)
        self.assertEqual(
            record["controller_error"]["message"], "inf060:gpu_capacity_unavailable"
        )
        facts = record["apply"]
        self.assertEqual(facts["reason"], "gpu_capacity_unavailable")
        self.assertEqual(facts["requested_zone"], "us-east-1a")
        self.assertEqual(
            facts["suggested_zones"],
            ["us-east-1b", "us-east-1c", "us-east-1d", "us-east-1f"],
        )
        self.assertIn(
            "AWS InsufficientInstanceCapacity",
            record["gpu_archive"]["tails"]["apply"]["lines"],
        )

    def test_silent_fake_still_times_out_and_retains_tail(self):
        record = self.exercise("timeout", subprocess.TimeoutExpired)
        self.assertEqual(record["apply"]["reason"], "apply_timeout")
        self.assertEqual(record["gpu_archive"]["tails"]["apply"]["lines"], [])

    def test_other_apply_error_retains_redacted_tail(self):
        record = self.exercise("other", RuntimeError)
        self.assertEqual(record["apply"]["reason"], "apply_error")
        self.assertEqual(record["apply"]["exit_code"], 7)
        self.assertEqual(
            record["gpu_archive"]["tails"]["apply"]["lines"],
            ["AWS UnauthorizedOperation"],
        )

    def test_cloudtrail_readback_counts_only_the_session_role(self):
        def read_events(service, action, args):
            self.assertEqual((service, action), ("cloudtrail", "lookup-events"))
            name = args[1].split("=")[-1]
            return {
                "Events": [
                    {
                        "CloudTrailEvent": json.dumps(
                            {
                                "eventName": name,
                                "userIdentity": {
                                    "sessionContext": {
                                        "sessionIssuer": {"userName": role}
                                    }
                                },
                                "errorCode": "Server.InsufficientInstanceCapacity",
                                "errorMessage": PRIVATE_TEXT,
                            }
                        )
                    }
                    for role in ("fixture-operator", "another-operator")
                    if name == "RunInstances"
                ]
            }

        value = apply_watch.cloudtrail_create_readback(
            read_events, "fixture-operator", 1, 2
        )
        self.assertEqual(
            value["events"]["RunInstances"]["outcomes"],
            {"Server.InsufficientInstanceCapacity": 1},
        )
        self.assertNotIn(PRIVATE_TEXT, json.dumps(value))
