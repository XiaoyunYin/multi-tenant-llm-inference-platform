"""R604 real Helm renders and R605 command-layer preflight."""

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from inf054_autoscaling import serving_values
import yaml
from inf054_dec100 import Dec100Workload, engine_container
from inf063_chart import CHART, chart_checks, command, documents, install_helm
from rehearse_inf054_kind import CLUSTER, cleanup_kind, kind_proof_ports

GATEWAY = "localhost:5001/gateway@sha256:" + "a" * 64
CLIENT = "localhost:5001/client@sha256:" + "b" * 64


class KindAdapterTests(unittest.TestCase):
    def test_provision_uses_composed_namespace_and_pushed_digests(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            system = "windows" if os.name == "nt" else "linux"
            suffix = ".exe" if os.name == "nt" else ""
            pins = {"node_image": "fixture-pinned-kind-image"}
            for tool in ("kind", "kubectl"):
                path = root / (tool + suffix)
                path.write_bytes(tool.encode())
                pins[f"{tool}_{system}_amd64_sha256"] = hashlib.sha256(
                    path.read_bytes()
                ).hexdigest()
            campaign = SimpleNamespace(tools=root, pins=pins)
            ports = kind_proof_ports(root, "tape", campaign)
            commands = []

            def shell(argv, **kwargs):
                argv = list(map(str, argv))
                commands.append(argv)
                result = ""
                if argv[:3] == ["docker", "image", "inspect"]:
                    digest = GATEWAY if "/gateway:" in argv[-1] else CLIENT
                    result = json.dumps([{"RepoDigests": [digest]}])
                if argv[1:3] == ["get", "nodes"]:
                    result = CLUSTER + "-control-plane"
                encoding = (lambda value: value) if kwargs.get("text") else str.encode
                return subprocess.CompletedProcess(
                    argv, 0, encoding(result), encoding("")
                )

            with patch("subprocess.run", side_effect=shell):
                result = ports.provision()
            payload = json.loads((root / "inf054-images.secret").read_bytes())
            self.assertEqual(ports.namespace, "mti-m5-desc-r447-helm")
            self.assertEqual(payload["images"], {"gateway": GATEWAY, "client": CLIENT})
            self.assertTrue(result["policy_agent"]["enabled"])
            taint = next(row for row in commands if "taint" in row)
            self.assertEqual(taint[taint.index("-n") + 1], ports.namespace)
            self.assertTrue(any(CLIENT in row and "pull" in row for row in commands))

    def test_cleanup_retries_falls_back_and_records_remaining(self):
        replies = iter(["inf054-worker", "inf054-worker", "inf054-worker"])
        calls = []

        def invoke(*args, timeout):
            calls.append((args, timeout))
            if args[1:3] == ("ps", "-a"):
                return SimpleNamespace(stdout=next(replies))
            raise subprocess.TimeoutExpired(args, timeout)

        with patch("rehearse_inf054_kind.command", side_effect=invoke):
            result = cleanup_kind(SimpleNamespace(kind="kind"))
        self.assertEqual(
            [args[1] for args, _ in calls],
            [
                "delete",
                "ps",
                "delete",
                "ps",
                "rm",
                "ps",
            ],
        )
        self.assertTrue(all(timeout <= 45 for _, timeout in calls))
        self.assertEqual(result["remaining"], ["inf054-worker"])
        self.assertTrue(result["requires_enclosing_zero"])
        self.assertFalse(result["kind_teardown_verified"])


class RenderedEngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        name = cls.enterClassContext(tempfile.TemporaryDirectory())
        cls.helm = install_helm(Path(name))

    def test_dcgm_render_checks_memory_and_cpu(self):
        self.assertTrue(chart_checks(self.helm)["dcgm_offline_valid"])

    def assert_unique_yaml_keys(self, stream):
        def visit(node):
            if isinstance(node, yaml.MappingNode):
                seen = set()
                for key, value in node.value:
                    self.assertIsInstance(key, yaml.ScalarNode)
                    identity = (key.tag, key.value)
                    self.assertNotIn(
                        identity,
                        seen,
                        f"duplicate YAML key {key.value!r} at line {key.start_mark.line + 1}",
                    )
                    seen.add(identity)
                    visit(value)
            elif isinstance(node, yaml.SequenceNode):
                for value in node.value:
                    visit(value)

        for doc in yaml.compose_all(stream, Loader=yaml.SafeLoader):
            visit(doc)

    def render(self, *, cpu, startup_failures=None, arm="keda"):
        # Exercise the owned namespace, values merge and template invocation.
        # Kubernetes calls and the post-render install are the only stubs.
        from test_inf054_dec100 import ClusterIO

        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            chart = CHART
            if startup_failures is not None:
                chart = root / "chart"
                shutil.copytree(CHART, chart)
                defaults = chart / "values.yaml"
                values = yaml.safe_load(defaults.read_bytes())
                values["engine"]["startupProbe"]["failureThreshold"] = startup_failures
                defaults.write_text(yaml.safe_dump(values), encoding="utf-8")
            receipt = root / "engine-render.json"
            cluster = ClusterIO()
            rendered = []

            def invoke(*args, timeout):
                if "template" in args:
                    result = command(*args, timeout=timeout)
                    self.assert_unique_yaml_keys(result.stdout)
                    rendered.extend(documents(result.stdout))
                    return result
                return SimpleNamespace(stdout="")

            @contextmanager
            def skip_backend(prepared, end):
                yield prepared

            with (
                patch("inf054_dec100.CHART", chart),
                patch("inf054_helm_releases.CHART", chart),
            ):
                workload = Dec100Workload(
                    cluster,
                    self.helm,
                    None,
                    "tape",
                    root,
                    cleanup_end=time.monotonic() + 90,
                    cpu=cpu,
                    helm_invoke=invoke,
                    rendered_receipt=receipt,
                )
                workload.helm.backend = skip_backend
                with workload.release(
                    arm, 1, serving_values(arm), time.monotonic() + 60
                ) as prepared:
                    seconds = prepared.engine_readiness_s
            return json.loads(receipt.read_bytes()), rendered, seconds

    def test_cpu_run_values_have_no_gpu_and_no_plugin(self):
        data, rendered, _ = self.render(cpu=True)
        self.assertEqual(data["engine_node_selector"], {"m5-role": "cpu"})
        self.assertFalse(data["device_plugin_present"])
        for workload in rendered:
            pod = workload.get("spec", {}).get("template", {}).get("spec", {})
            for container in pod.get("containers", []) + pod.get("initContainers", []):
                for resource in ("requests", "limits"):
                    self.assertNotIn(
                        "nvidia.com/gpu",
                        container.get("resources", {}).get(resource, {}),
                    )

    def test_gpu_run_values_keep_exactly_one_gpu(self):
        data, _, _ = self.render(cpu=False)
        self.assertEqual(data["engine_node_selector"], {"m5-role": "gpu"})
        self.assertEqual(int(data["engine_resources"]["requests"]["nvidia.com/gpu"]), 1)
        self.assertEqual(int(data["engine_resources"]["limits"]["nvidia.com/gpu"]), 1)

    def test_gpu_readiness_covers_the_rendered_startup_allowance(self):
        _, rendered, seconds = self.render(cpu=False)
        _, engine = engine_container(rendered)
        probe = engine["startupProbe"]
        expected = probe["periodSeconds"] * probe["failureThreshold"] + 2 + 30
        self.assertGreater(expected, 180)
        self.assertEqual(seconds, expected)

    def test_gpu_readiness_follows_changed_chart_defaults(self):
        _, _, original = self.render(cpu=False)
        _, _, changed = self.render(cpu=False, startup_failures=700)
        self.assertEqual(original, 672)
        self.assertEqual(changed, 732)

    def test_all_gpu_arms_have_unique_mapping_keys_and_parallel_engine(self):
        for arm in ("fixed-1", "keda", "fixed-2"):
            with self.subTest(arm=arm):
                _, rendered, _ = self.render(cpu=False, arm=arm)
                [engine] = [
                    resource
                    for resource in rendered
                    if resource["kind"] == "StatefulSet"
                    and resource["metadata"]["name"] == "vllm"
                ]
                self.assertEqual(engine["spec"]["podManagementPolicy"], "Parallel")


if __name__ == "__main__":
    unittest.main()
