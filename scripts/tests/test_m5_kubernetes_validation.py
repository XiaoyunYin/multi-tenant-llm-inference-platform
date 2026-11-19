import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from inference_platform.routine_aws_tests import kubernetes_storage_source, selection
from inference_platform.m5_descriptive import resources
from m5_descriptive_remote import EKSClusterPorts
from validate_m5_kubernetes import APISERVER, ETCD, ObjectCollector


class KubernetesValidationTests(unittest.TestCase):
    def test_fixture_storage_uses_a_real_terraform_exact_guard_and_preserves_product(
        self,
    ):
        original = (
            Path(__file__).resolve().parents[2] / "infra/terraform/package_a/main.tf"
        ).read_text()
        transformed = kubernetes_storage_source(original)
        binary = shutil.which("terraform")
        self.assertIsNotNone(binary, "DEC-099 host must install pinned Terraform")
        self.assertIn("var.root_gib <= 100", original)
        with self.assertRaisesRegex(ValueError, "storage_validation_shape"):
            kubernetes_storage_source(original.replace("var.root_gib <= 100", "true"))
        for text, cases in (
            (original, ((100, True), (200, False))),
            (transformed, ((200, True), (100, False), (199, False), (201, False))),
        ):
            variable = re.search(
                r'variable "root_gib" \{.*?\n\}', text, re.DOTALL
            ).group()
            with tempfile.TemporaryDirectory() as tmp:
                (Path(tmp) / "main.tf").write_text(
                    variable + '\noutput "root" { value = var.root_gib }\n'
                )
                subprocess.run(
                    [binary, "init", "-backend=false", "-input=false"],
                    cwd=tmp,
                    capture_output=True,
                    check=True,
                )
                for size, accepted in cases:
                    with self.subTest(size=size, fixture=text is transformed):
                        result = subprocess.run(
                            [
                                binary,
                                "plan",
                                "-input=false",
                                "-no-color",
                                f"-var=root_gib={size}",
                            ],
                            cwd=tmp,
                            capture_output=True,
                        )
                        self.assertEqual(
                            result.returncode == 0, accepted, result.stderr.decode()
                        )
        self.assertEqual(
            (
                Path(__file__).resolve().parents[2]
                / "infra/terraform/package_a/main.tf"
            ).read_text(),
            original,
        )

    def test_stager_controller_and_timeout_and_real_inventory_join(self):
        for remaining, expected in ((4000, 2700), (89, 89), (0, None)):
            with (
                self.subTest(remaining=remaining),
                tempfile.TemporaryDirectory() as tmp,
            ):
                ports = EKSClusterPorts.__new__(EKSClusterPorts)
                ports.output, ports.namespace = Path(tmp), "mti-m5-fixture"
                ports.work_deadline_epoch, ports.results = 1000 + remaining, {}
                calls = []

                def k(*args):
                    calls.append(args)
                    if args[:2] == ("get", "pods"):
                        return json.dumps(
                            {
                                "items": [
                                    {
                                        "metadata": {"name": f"stage-{i}"},
                                        "spec": {"nodeName": f"gpu-{i}"},
                                    }
                                    for i in range(2)
                                ]
                            }
                        )
                    if args[0] == "exec":
                        return '{"files":{"weights":{"sha256":"fixture"}}}'
                    return ""

                ports.k = k
                with (
                    patch("m5_descriptive_remote.time.time", return_value=1000),
                    patch(
                        "m5_descriptive_remote.time.monotonic",
                        side_effect=[12.5, 19.75],
                    ),
                ):
                    if expected is None:
                        with self.assertRaisesRegex(
                            TimeoutError, "model_work_deadline"
                        ):
                            ports.stage_model()
                        self.assertFalse(any(c[0] == "rollout" for c in calls))
                    else:
                        result = ports.stage_model()
                        self.assertEqual(
                            result["files"]["weights"]["sha256"], "fixture"
                        )
                        self.assertIn(
                            (
                                "rollout",
                                "status",
                                "daemonset/model-stager",
                                f"--timeout={expected}s",
                            ),
                            calls,
                        )
                        wait = next(c for c in calls if c[0] == "wait")
                        self.assertEqual(
                            wait[1], "--for=jsonpath={.status.desiredNumberScheduled}=2"
                        )
                        self.assertLess(
                            calls.index(wait),
                            next(i for i, c in enumerate(calls) if c[0] == "rollout"),
                        )
                        staging = ports.results["model_staging"]
                        self.assertEqual(staging["start_monotonic"], 12.5)
                        self.assertEqual(staging["end_monotonic"], 19.75)
                        self.assertEqual(staging["elapsed_s"], 7.25)
                        self.assertTrue(ports.results["model_staging"]["hashes_match"])
                        self.assertEqual(len(ports.results["model_staging"]["pods"]), 2)
                        self.assertIn(
                            ("delete", "daemonset/model-stager", "--wait=true"), calls
                        )
                spec = json.loads((Path(tmp) / "model-stager.json").read_bytes())[
                    "spec"
                ]["template"]["spec"]
                self.assertNotIn("activeDeadlineSeconds", spec)
                self.assertEqual(spec["nodeSelector"], {"m5-role": "gpu"})
                serving = next(
                    o
                    for o in resources(
                        "mti-m5-fixture", "fixture.invalid/image@sha256:" + "a" * 64
                    )["items"]
                    if o["kind"] == "StatefulSet" and o["metadata"]["name"] == "vllm"
                )
                envelope = serving["spec"]["template"]["spec"]["containers"][0][
                    "resources"
                ]
                for category in ("requests", "limits"):
                    self.assertEqual(
                        spec["containers"][0]["resources"][category]["memory"],
                        envelope[category]["memory"],
                    )
                self.assertEqual(
                    spec["containers"][0]["terminationMessagePolicy"],
                    "FallbackToLogsOnError",
                )

    def test_validation_selection_is_closed_and_api_images_are_digest_pinned(self):
        self.assertTrue(
            selection({"descriptive_kubernetes_validation": True})[
                "descriptive_kubernetes_validation"
            ]
        )
        with self.assertRaisesRegex(ValueError, "descriptive_kubernetes_validation"):
            selection({"descriptive_kubernetes_validation": "yes"})
        self.assertIn(":v1.35.0@sha256:", APISERVER)
        self.assertIn("@sha256:", ETCD)

    def test_controller_wait_cannot_restart_or_extend_the_staging_deadline(self):
        with tempfile.TemporaryDirectory() as tmp:
            ports = EKSClusterPorts.__new__(EKSClusterPorts)
            ports.output, ports.namespace = Path(tmp), "mti-m5-fixture"
            ports.work_deadline_epoch, ports.results = 1089, {}
            calls, now = [], [1000]

            def k(*args):
                calls.append(args)
                if args[0] == "wait":
                    now[0] = 1090

            ports.k = k
            with patch("m5_descriptive_remote.time.time", side_effect=lambda: now[0]):
                with self.assertRaisesRegex(TimeoutError, "model_work_deadline"):
                    ports.stage_model()
            self.assertFalse(any(c[0] == "rollout" for c in calls))

    def test_collector_refuses_a_new_unhandled_transport_call(self):
        collector = ObjectCollector.__new__(ObjectCollector)
        with self.assertRaisesRegex(ValueError, "uncollected_call"):
            collector.k("replace", "--raw=/something")


if __name__ == "__main__":
    unittest.main()
