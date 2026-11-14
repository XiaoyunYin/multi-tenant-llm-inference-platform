import contextlib
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def rehearsal():
    spec = importlib.util.spec_from_file_location(
        "rehearse_eks_package_a", ROOT / "scripts/rehearse_eks_package_a.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RehearsalDiagnosticsTests(unittest.TestCase):
    def test_work_budget_accepts_the_outer_row5_timeout_and_preserves_default(self):
        module = rehearsal()
        with patch.object(module.time, "monotonic", return_value=100.0):
            default = module.WorkBudget()
            row5 = module.WorkBudget(1320)

        self.assertEqual(default.end - default.started, module.KIND_RUNNER_TIMEOUT_S)
        self.assertEqual(row5.end - row5.started, 1320)
        self.assertEqual(row5.work_end - row5.started, 1320 - module.KIND_CLEANUP_RESERVE_S)
        self.assertEqual(row5.cleanup_end - row5.started, 1320 - module.KIND_RECEIPT_RESERVE_S)

    def test_work_budget_rejects_time_that_cannot_cover_reserved_cleanup(self):
        module = rehearsal()
        with self.assertRaisesRegex(ValueError, "kind_runner_timeout_must_exceed_reserved_time"):
            module.WorkBudget(module.KIND_CLEANUP_RESERVE_S + module.KIND_RECEIPT_RESERVE_S)

    def test_gateway_rollout_failure_records_diagnostics_before_cluster_cleanup(self):
        module = rehearsal()
        events = []
        gateway_image = "mti-gateway:fixture"
        local_images = (gateway_image, "mti-fake:stage1")
        archived = {
            tag: "sha256:" + str(index) * 64
            for index, tag in enumerate(module.KIND_LOCAL_IMAGE_TAGS.values(), start=1)
        }
        local_digests = {
            gateway_image: "sha256:" + "f" * 64,
            "mti-fake:stage1": "sha256:" + "e" * 64,
        }
        loaded_images = set(archived) | set(local_images)
        diagnostic_timeouts = []
        nodes = [
            "m5-package-a-diagnostics-control-plane",
            "m5-package-a-diagnostics-worker",
            "m5-package-a-diagnostics-worker2",
        ]

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repo"
            output = Path(directory) / "output"
            (root / ".tools").mkdir(parents=True)
            (root / "deploy/k8s").mkdir(parents=True)
            (root / "deploy/eks").mkdir(parents=True)
            (root / "deploy/local").mkdir(parents=True)
            tool_suffix = ".exe" if os.name == "nt" else ""
            tool_bytes = {"kind": b"stub kind", "kubectl": b"stub kubectl"}
            tool_hashes = {}
            for name, data in tool_bytes.items():
                path = root / ".tools" / (name + tool_suffix)
                path.write_bytes(data)
                tool_hashes[name] = hashlib.sha256(data).hexdigest()
            pins = json.loads((ROOT / "deploy/k8s/pins.json").read_bytes())
            for name in tool_hashes:
                pins[f"{name}_{'windows' if os.name == 'nt' else 'linux'}_amd64_sha256"] = (
                    tool_hashes[name]
                )
            (root / "deploy/k8s/pins.json").write_text(json.dumps(pins))
            (root / "deploy/eks/capture_runtime.py").write_text("pass\n")
            (root / "deploy/local/tenants.json").write_text("{}\n")

            def repo_tag(reference):
                if "/" not in reference:
                    return "docker.io/library/" + reference
                first = reference.split("/", 1)[0]
                return reference if "." in first or ":" in first else "docker.io/" + reference

            def stub_run(
                argv, *, timeout=180, check=True, return_status=False, return_details=False
            ):
                command = [str(value) for value in argv]
                if return_details:
                    events.append("diagnostic")
                    diagnostic_timeouts.append(timeout)
                    if "get" in command and "events" in command:
                        raise subprocess.TimeoutExpired(
                            command, timeout, output="partial events", stderr="stub timeout"
                        )
                    if "logs" in command and "--previous" in command:
                        return {
                            "returncode": 1,
                            "stdout": "",
                            "stderr": 'previous terminated container "gateway" in pod "gateway-0" not found',
                        }
                    if "get" in command and "pods" in command and "-o" in command:
                        pod_data = {
                            "items": [
                                {
                                    "metadata": {"name": "gateway-0"},
                                    "spec": {"containers": [{"name": "gateway"}]},
                                }
                            ]
                        }
                        return {"returncode": 0, "stdout": json.dumps(pod_data), "stderr": ""}
                    return {"returncode": 0, "stdout": "diagnostic output\n", "stderr": ""}

                if command[:3] == ["docker", "image", "save"]:
                    path = Path(command[command.index("--output") + 1])
                    config = b'{"os":"linux","architecture":"amd64"}'
                    archived[command[-1]] = "sha256:" + hashlib.sha256(config).hexdigest()
                    with tarfile.open(path, "w") as archive:
                        for name, data in (
                            (
                                "manifest.json",
                                json.dumps(
                                    [
                                        {
                                            "Config": "config.json",
                                            "RepoTags": [command[-1]],
                                            "Layers": ["layer.tar"],
                                        }
                                    ]
                                ).encode(),
                            ),
                            ("config.json", config),
                            ("layer.tar", b"fixture"),
                        ):
                            info = tarfile.TarInfo(name)
                            info.size = len(data)
                            archive.addfile(info, io.BytesIO(data))
                if return_status:
                    reference = command[-1]
                    digest = archived.get(reference, local_digests.get(reference))
                    return 0, json.dumps(
                        {"status": {"id": digest, "repoTags": [repo_tag(reference)]}}
                    )
                if Path(command[0]).name.startswith("kind"):
                    if command[1:3] == ["get", "clusters"]:
                        return ""
                    if command[1:3] == ["create", "cluster"]:
                        events.append("cluster-created")
                        Path(command[command.index("--kubeconfig") + 1]).write_text("stub\n")
                    if command[1:3] == ["delete", "cluster"]:
                        events.append("cluster-delete")
                    return ""
                if "wait" in command and "statefulset/gateway" in command:
                    events.append("gateway-rollout-failure")
                    raise RuntimeError("injected gateway rollout failure")
                if "get" in command and "pods" in command and "-l" in command:
                    return json.dumps(
                        {
                            "items": [
                                {
                                    "metadata": {"name": "observer-1"},
                                    "spec": {"nodeName": nodes[1]},
                                },
                                {
                                    "metadata": {"name": "observer-2"},
                                    "spec": {"nodeName": nodes[2]},
                                },
                            ]
                        }
                    )
                if command[:3] == ["docker", "image", "inspect"] and "--format" in command:
                    return local_digests[command[-1]]
                if command[:3] == ["docker", "image", "inspect"]:
                    return "{}"
                if command[:3] == ["docker", "exec", nodes[1]] and command[3:] == [
                    "sh",
                    "-c",
                    "command -v crictl",
                ]:
                    return "/usr/bin/crictl"
                if "sha256sum" in command:
                    return "a" * 64 + " /usr/bin/crictl"
                if command[:3] == ["docker", "ps", "-aq"]:
                    return ""
                return ""

            class FakeProcess:
                def terminate(self):
                    events.append("forward-terminate")

                def wait(self, timeout=None):
                    events.append("forward-wait")
                    return 0

            class FakeConnection:
                def __enter__(self):
                    return self

                def __exit__(self, *_args):
                    return False

            class FakeHTTP:
                count = 0

                def __init__(self, *_args, **_kwargs):
                    self.node = nodes[1 + self.count]
                    type(self).count += 1

                def get(self, path):
                    import time

                    value = (
                        {"boot_id": "fixture-boot", "mono_ns": time.monotonic_ns()}
                        if path == "/clock"
                        else {
                            "schema": "m5-node-cache-v1",
                            "node": self.node,
                            "complete": True,
                            "boot_id": "fixture-boot",
                            "end_ns": time.monotonic_ns(),
                            "image_cache_state": "cold",
                            "model_cache_state": "cold",
                        }
                    )
                    return json.dumps(value).encode(), {}

            with (
                patch.object(module, "ROOT", root),
                patch.object(module, "run", side_effect=stub_run),
                patch.object(module, "resources", return_value={"items": []}),
                patch.object(
                    module,
                    "admission_settings",
                    return_value={"ADMISSION_NAMESPACE": "mti-m5-package-a"},
                ),
                patch.object(module, "mutate_kind_manifest", return_value=loaded_images),
                patch.object(module, "HTTP", FakeHTTP),
                patch.object(module, "free_port", side_effect=iter(range(31000, 31010)).__next__),
                patch.object(module, "time") as fake_time,
                patch.object(module.socket, "create_connection", return_value=FakeConnection()),
                patch("subprocess.Popen", side_effect=lambda *_args, **_kwargs: FakeProcess()),
                patch.object(
                    sys,
                    "argv",
                    [
                        "rehearse_eks_package_a.py",
                        "--output",
                        str(output),
                        "--gateway-image",
                        gateway_image,
                        "--cluster",
                        "m5-package-a-diagnostics",
                    ],
                ),
                contextlib.redirect_stdout(io.StringIO()),
                self.assertRaisesRegex(RuntimeError, "injected gateway rollout failure"),
            ):
                fake_time.monotonic.side_effect = [float(index) for index in range(1000)]
                fake_time.sleep.return_value = None
                module.main()

            receipt = json.loads((output / "receipt.json").read_bytes())
            self.assertEqual(receipt["error"], "RuntimeError:injected gateway rollout failure")
            diagnostics = receipt["diagnostics"]
            self.assertFalse(diagnostics["complete"], diagnostics)
            self.assertTrue(
                any("TimeoutExpired" in item["error"] for item in diagnostics["failures"])
            )
            self.assertTrue(diagnostics["warnings"])  # missing previous logs are permitted
            self.assertTrue(diagnostics["files"])
            commands = [item["command"] for item in diagnostics["commands"]]
            self.assertTrue(
                any(
                    "get" in command
                    and "pods,deploy,sts,ds,svc,endpointslices" in command
                    and "wide" in command
                    for command in commands
                )
            )
            self.assertTrue(
                any(
                    "get" in command
                    and "events" in command
                    and "--sort-by=.lastTimestamp" in command
                    for command in commands
                )
            )
            self.assertTrue(
                any("describe" in command and "pods" in command for command in commands)
            )
            self.assertTrue(
                any("logs" in command and "--tail=200" in command for command in commands)
            )
            self.assertTrue(
                any(
                    "logs" in command and "--previous" in command and "--tail=200" in command
                    for command in commands
                )
            )
            for node in nodes:
                self.assertTrue(
                    any(
                        command[:5] == ["docker", "exec", node, "crictl", "ps"] and "-a" in command
                        for command in commands
                    )
                )
            self.assertLessEqual(max(diagnostic_timeouts), module.DIAGNOSTIC_COMMAND_TIMEOUT_S)
            for file_record in diagnostics["files"]:
                path = output / file_record["path"]
                data = path.read_bytes()
                self.assertLessEqual(file_record["bytes"], 256 * 1024)
                self.assertEqual(file_record["bytes"], len(data))
                self.assertEqual(file_record["sha256"], hashlib.sha256(data).hexdigest())

            failure_index = events.index("gateway-rollout-failure")
            first_diagnostic_index = events.index("diagnostic")
            last_diagnostic_index = len(events) - 1 - events[::-1].index("diagnostic")
            delete_index = events.index("cluster-delete")
            self.assertLess(failure_index, first_diagnostic_index)
            self.assertLess(last_diagnostic_index, delete_index)
            self.assertGreaterEqual(events.count("diagnostic"), 5)

    def test_hanging_diagnostic_stops_at_command_and_total_capture_bounds(self):
        module = rehearsal()
        now = [0.0]
        timeouts = []

        def hanging_run(argv, *, timeout, check, return_details):
            self.assertFalse(check)
            self.assertTrue(return_details)
            timeouts.append(timeout)
            now[0] += timeout
            raise subprocess.TimeoutExpired(
                argv, timeout, output=b"x" * 300000, stderr=b"still running"
            )

        with tempfile.TemporaryDirectory() as directory:
            with (
                patch.object(module.time, "monotonic", side_effect=lambda: now[0]),
                patch.object(module, "run", side_effect=hanging_run),
            ):
                result = module.capture_kind_diagnostics(
                    directory,
                    "kubectl",
                    "kubeconfig",
                    "kind-test",
                    "mti-test",
                    ["kind-test-control-plane"],
                )
            self.assertEqual(timeouts, [15, 15, 15, 15])
            self.assertEqual(result["elapsed_seconds"], 60)
            self.assertFalse(result["complete"])
            self.assertTrue(result["failures"])
            first = Path(directory) / result["files"][0]["path"]
            self.assertEqual(first.stat().st_size, 256 * 1024)
            self.assertLessEqual(max(timeouts), module.DIAGNOSTIC_COMMAND_TIMEOUT_S)


if __name__ == "__main__":
    unittest.main()
