import hashlib
import json
import subprocess
from types import SimpleNamespace
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from inference_platform.eks_deployment import resources
from inference_platform.package_a_operator import Ports
from inference_platform.r1_spec import parse_engine_argv
from test_eks_package_a import INPUTS
from l4_compat_container import ENGINE_ENV, engine_argv
from l4_compat_fake_engine import validate_engine_argv
import l4_compat_controller


class LaunchParity(unittest.TestCase):
    def test_descriptive_container_keeps_round281_engine_and_spawn_parity(self):
        from inference_platform.m5_descriptive import resources as descriptive

        objects = descriptive(
            "mti-m5-parity", "example.invalid/gateway@sha256:" + "a" * 64
        )["items"]
        container = next(
            o
            for o in objects
            if o["kind"] == "StatefulSet" and o["metadata"]["name"] == "vllm"
        )["spec"]["template"]["spec"]["containers"][0]
        accepted = next(
            o
            for o in resources(INPUTS, "runtime-code")["items"]
            if o["kind"] == "StatefulSet" and o["metadata"]["name"] == "vllm"
        )["spec"]["template"]["spec"]["containers"][0]
        self.assertEqual(container["image"], accepted["image"])
        # DEC-100 deliberately removes the capture wrapper. Normalize only the
        # CLI's positional model spelling; every engine flag must still agree.
        self.assertEqual(container["command"], ["vllm", "serve"])
        self.assertEqual(container["args"][0], "Qwen/Qwen2.5-7B-Instruct")
        self.assertEqual(
            parse_engine_argv(["--model", *container["args"]]),
            parse_engine_argv(accepted["args"]),
        )
        self.assertEqual({e["name"]: e["value"] for e in container["env"]}, ENGINE_ENV)

    def test_engine_argument_parser_rejects_invalid_or_duplicate_flags(self):
        self.assertEqual(
            parse_engine_argv(["--value", "16", "--enabled"]),
            {"--value": "16", "--enabled": True},
        )
        for args in (["--a", "1", "--a", "2"], ["positional"], ["--a", None]):
            with self.subTest(args=args), self.assertRaises(ValueError):
                parse_engine_argv(args)

    def test_eks_argv_and_environment(self):
        items = resources(INPUTS, "runtime-code")["items"]
        workload = next(
            x
            for x in items
            if x["kind"] == "StatefulSet" and x["metadata"]["name"] == "vllm"
        )
        container = workload["spec"]["template"]["spec"]["containers"][0]
        args = container["args"]
        parsed = parse_engine_argv(args)
        # R1_PRE_REGISTRATION.md:40 and INF037B_PRE_REGISTRATION.md:19.
        # Independent literals ensure mutations of the shared definition fail.
        expected = {
            "--dtype": "bfloat16",
            "--max-model-len": "8192",
            "--block-size": "16",
            "--max-num-seqs": "16",
            "--max-num-queued-reqs": "32",
            "--gpu-memory-utilization": "0.90",
            "--enable-prefix-caching": True,
            "--generation-config": "vllm",
            "--model": "Qwen/Qwen2.5-7B-Instruct",
            "--revision": "a09a35458c702b33eeacc393d103063234e8bc28",
            "--host": "0.0.0.0",
            "--port": "8000",
            "--shutdown-timeout": "35",
        }
        self.assertEqual(parsed, expected)
        self.assertEqual(
            ENGINE_ENV,
            {
                e["name"]: e["value"]
                for e in container["env"]
                if e["name"].startswith("VLLM_")
            },
        )
        validate_engine_argv(engine_argv())
        with self.assertRaises(SystemExit):
            validate_engine_argv(["serve", "/model", *engine_argv()[2:]])

    def test_cleanup_wait_budget_and_timeout(self):
        for duration, expected in ((390, True), (481, False)):
            ports = Ports.__new__(Ports)
            ports.child = None
            ports.inputs = {"aws_profile": "fixture"}
            ports.manifest = {"operator_tools": {"terraform": {"path": "terraform"}}}
            ports.instance_ids = lambda: ["i-fixture"]
            ports.aws = lambda *a: None
            calls = []

            def command(argv, deadline, name):
                calls.append(name)
                if name == "wait-terminated" and 1000 + duration > deadline:
                    raise TimeoutError()

            ports.command = command
            with patch(
                "inference_platform.package_a_operator.time.time", return_value=1000
            ):
                result = ports.teardown(1540)
            self.assertEqual(result["destroy_completed"], expected)
            self.assertEqual(calls, ["wait-terminated", "destroy"])

    def test_real_terraform_unconsumed_cleanup_does_not_create_state(self):
        import os
        import time

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            directory = root / "terraform"
            directory.mkdir()
            (directory / "main.tf").write_text(
                'terraform { required_version = ">= 1.0" }\n'
            )
            terraform = (
                Path(__file__).resolve().parents[2]
                / ".tools/terraform/1.16.2/terraform.exe"
                if os.name == "nt"
                else Path("/usr/local/bin/terraform")
            )
            subprocess.run(
                [
                    str(terraform),
                    f"-chdir={directory}",
                    "init",
                    "-backend=false",
                    "-input=false",
                ],
                check=True,
                capture_output=True,
            )
            plan = directory / "create.tfplan"
            plan.write_bytes(b"fake-plan")
            digest = hashlib.sha256(plan.read_bytes()).hexdigest()
            manifest = {
                "sealed_plans": {"create_sha256": digest},
                "operator_tools": {"terraform": {"path": str(terraform)}},
            }
            (root / "manifest.json").write_text(json.dumps(manifest))
            ports = Ports.__new__(Ports)
            ports.child, ports.directory, ports.runtime = None, root, root
            ports.inputs, ports.manifest = {"aws_profile": "fixture"}, manifest
            calls = []
            ports.instance_ids = lambda: ["i-fixture"]
            ports.aws = lambda *args: calls.append("terminate")
            ports.command = lambda *args: calls.append(args[2])
            args = SimpleNamespace(directory=root, profile="fixture", mode="cleanup")
            with (
                patch.object(l4_compat_controller, "L4Ports", return_value=ports),
                patch.dict(os.environ, {"L4_T0_EPOCH": str(time.time())}),
            ):
                l4_compat_controller.cleanup(args)
            self.assertEqual(calls, ["terminate", "wait-terminated"])
            self.assertFalse((directory / "terraform.tfstate").exists())
            self.assertFalse((root / "consumed.json").exists())
            ports.apply(time.time() + 120)
            self.assertTrue((root / "consumed.json").exists())
            self.assertEqual(calls[-1], "apply")

    def test_preexisting_state_refused_before_consume(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "terraform").mkdir()
            plan = root / "terraform/create.tfplan"
            plan.write_bytes(b"fixture")
            digest = hashlib.sha256(b"fixture").hexdigest()
            (root / "manifest.json").write_text(
                json.dumps({"sealed_plans": {"create_sha256": digest}})
            )
            (root / "terraform/terraform.tfstate").write_text("{}")
            args = SimpleNamespace(
                directory=root, owner_approved_hash=digest, review_target="unused"
            )
            with self.assertRaisesRegex(ValueError, "preexisting_state"):
                l4_compat_controller.execute(args)
            self.assertFalse((root / "consumed.json").exists())
