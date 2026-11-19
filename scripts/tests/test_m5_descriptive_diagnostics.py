import json
import hashlib
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from inference_platform.m5_descriptive_operator import execute, session_timing
from m5_descriptive_diagnostics import COLLECTOR, collect, write_cost
from m5_descriptive_eks import EKSports, main


class DiagnosticsTests(unittest.TestCase):
    def test_collector_enters_export_bracket_after_upload_deadline_expired(self):
        with tempfile.TemporaryDirectory() as tmp:
            end = time.time() + 10
            host = SimpleNamespace(host="fixture", token="secret", deadline=0)

            def ssm(*args, **kwargs):
                self.assertGreater(host.deadline, time.time())
                self.assertLessEqual(host.deadline, end)
                self.assertLessEqual(kwargs["timeout_s"], 10)
                return {
                    "StandardOutputContent": 'PREBOOTSTRAP_DIAGNOSTICS={"complete":true}'
                }

            host.ssm = ssm
            collect(host, tmp, end)
            self.assertTrue(
                json.loads((Path(tmp) / "prebootstrap-diagnostics.json").read_bytes())[
                    "complete"
                ]
            )

    def test_repo_free_collector_reads_real_partial_file_and_memory(self):
        if sys.platform == "win32":
            self.skipTest(
                "Linux /proc and systemd collector; also exercised by AWS forced halt"
            )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "source.bundle").write_bytes(b"partial upload")
            (root / "bootstrap.log").write_text("credential-test-secret\n")
            code = (
                COLLECTOR
                + "\nprint(json.dumps(capture(Path("
                + repr(tmp)
                + "), 'credential-test-secret')))"
            )
            result = json.loads(subprocess.check_output([sys.executable, "-c", code]))
            self.assertEqual(result["partial_upload"]["bytes"], 14)
            self.assertEqual(
                result["partial_upload"]["sha256"],
                hashlib.sha256(b"partial upload").hexdigest(),
            )
            self.assertTrue(result["partial_upload"]["hash_complete"])
            self.assertTrue(result["partial_upload"]["stable"])
            self.assertNotIn("credential-test-secret", json.dumps(result))
            self.assertIn("MemAvailable", result["memory"])
            self.assertGreater(result["disk"]["free"], 0)

    def test_repo_free_collector_embeds_the_exact_shared_value_redactor(self):
        from inference_platform.credential_redaction import redact_values

        namespace = {}
        exec(COLLECTOR, namespace)
        for message in (
            "denied: Your authorization token has expired. Reauthenticate and try again.",
            "no basic auth credentials",
            "arn:aws:iam::123456789012:role/operator is not authorized to perform: ecr:InitiateLayerUpload",
            "error: You must be logged in to the server (Unauthorized)",
            "Authorization: Bearer test-bearer --token=test-token aws_secret_access_key=test-secret",
            "Basic c2VjcmV0OnBhc3N3b3Jk",
        ):
            with self.subTest(message=message):
                self.assertEqual(
                    namespace["redact_values"](message, environment={}),
                    redact_values(message, environment={}),
                )
        self.assertNotIn("REDACTED credential line", COLLECTOR)

    def test_forced_prebootstrap_halt_preserves_diagnostics_and_cost_then_cleans(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            host = SimpleNamespace(
                host="fixture",
                token="secret",
                ssm=lambda *a, **k: {
                    "StandardOutputContent": 'PREBOOTSTRAP_DIAGNOSTICS={"complete":true,"partial_upload":{"bytes":14}}'
                },
            )
            ports = EKSports.__new__(EKSports)
            ports.bootstrap_complete = False
            ports.directory, ports.host, ports.end = root, host, time.time() + 18000
            ports.manifest = {"timing": session_timing(640)}
            ports.substitutions = ["CPU host; forced pre-bootstrap halt"]
            ports.provision = lambda: (_ for _ in ()).throw(
                RuntimeError("forced_prebootstrap_halt")
            )
            ports.teardown = lambda: {"complete": True}
            ports.inventory = lambda: {"complete": True}
            (root / "manifest.json").write_text(
                json.dumps(
                    {
                        "forecast_basis": {
                            "hourly_usd": 2.8630444444444443,
                            "fixed_other_usd": 10,
                            "margin": 1.25,
                        },
                        "host_manifest": {"prior_spend_usd": 48.31773637433106},
                    }
                )
            )
            (root / "consumed.json").write_text(
                json.dumps({"started_epoch": time.time() - 10})
            )
            with self.assertRaisesRegex(RuntimeError, "forced_prebootstrap_halt"):
                try:
                    execute(
                        ports,
                        root / "execution",
                        deadline=time.monotonic() + 18000,
                        rehearsal=True,
                    )
                finally:
                    write_cost(root)
            receipt = json.loads((root / "execution/receipt.json").read_bytes())
            self.assertEqual(
                [(p["name"], p["status"]) for p in receipt["phases"]],
                [
                    ("provision", "FAILED"),
                    ("export", "PASS"),
                    ("retrieve", "PASS"),
                    ("teardown", "PASS"),
                    ("inventory", "PASS"),
                ],
            )
            self.assertTrue((root / "prebootstrap-diagnostics.json").is_file())
            self.assertTrue(
                json.loads((root / "operator-cost.json").read_bytes())["consumed"]
            )

    def test_collection_failure_is_recorded_without_raising(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = collect(None, tmp, time.time() - 1)
            self.assertEqual(result["kind"], "repo-free-diagnostics")
            self.assertFalse(
                json.loads((Path(tmp) / "prebootstrap-diagnostics.json").read_bytes())[
                    "complete"
                ]
            )

    def test_entrypoint_finally_writes_cost_even_on_preconsume_refusal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "manifest.json").write_text("{}")
            with (
                patch("sys.argv", ["operator", "--packet", tmp]),
                patch(
                    "m5_descriptive_eks.run_packet", side_effect=ValueError("refused")
                ),
            ):
                with self.assertRaisesRegex(ValueError, "refused"):
                    main()
            result = json.loads((root / "operator-cost.json").read_bytes())
            self.assertFalse(result["consumed"])
            self.assertEqual(result["task_cost_estimate_usd"], 0)

    def test_cost_matches_accepted_round376_formula(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "manifest.json").write_text(
                json.dumps(
                    {
                        "forecast_basis": {
                            "hourly_usd": 2.8630444444444443,
                            "fixed_other_usd": 10,
                            "margin": 1.25,
                        },
                        "host_manifest": {"prior_spend_usd": 33.28773637433106},
                    }
                )
            )
            (root / "consumed.json").write_text('{"started_epoch":0}')
            self.assertEqual(
                write_cost(root, now=2544.0607028007507)["task_cost_estimate_usd"],
                15.03,
            )
