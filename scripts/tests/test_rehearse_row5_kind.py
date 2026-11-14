"""Offline entry-point checks; neither case creates a real kind cluster."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "rehearse_row5_kind.py"
KUBECTL = ROOT / ".tools" / ("kubectl.exe" if os.name == "nt" else "kubectl")
KUBECTL = Path(os.environ.get("ROW5_TEST_KUBECTL", str(KUBECTL)))

RESOURCE_KINDS = {
    "namespaces": "Namespace",
    "serviceaccounts": "ServiceAccount",
    "secrets": "Secret",
    "configmaps": "ConfigMap",
    "services": "Service",
    "pods": "Pod",
    "statefulsets": "StatefulSet",
    "deployments": "Deployment",
    "roles": "Role",
    "rolebindings": "RoleBinding",
    "poddisruptionbudgets": "PodDisruptionBudget",
    "endpointslices": "EndpointSlice",
}


class FakeKubernetesAPI:
    """Small API fixture with discovery, resources, and independently started gateway pods."""

    def __init__(self, *, started=True):
        self.objects = {}
        self.requests = []
        self.ready_replicas = {"gateway": 0, "vllm": 0}
        self.gateway_started = started
        state = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def log_message(self, *_args):
                pass

            def send_json(self, value, status=200, *, content_type="application/json"):
                body = (json.dumps(value, separators=(",", ":")) + "\n").encode()
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def send_watch(self, values):
                body = b"".join(
                    (
                        json.dumps(
                            {"type": "MODIFIED", "object": value}, separators=(",", ":")
                        )
                        + "\n"
                    ).encode()
                    for value in values
                )
                self.send_response(200)
                self.send_header("Content-Type", "application/json;stream=watch")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)
                self.close_connection = True

            def discovery(self, path):
                groups = {
                    "apps/v1": [
                        ("statefulsets", "StatefulSet"),
                        ("deployments", "Deployment"),
                    ],
                    "rbac.authorization.k8s.io/v1": [
                        ("roles", "Role"),
                        ("rolebindings", "RoleBinding"),
                    ],
                    "policy/v1": [("poddisruptionbudgets", "PodDisruptionBudget")],
                    "discovery.k8s.io/v1": [("endpointslices", "EndpointSlice")],
                }
                if path == "/api":
                    return {
                        "apiVersion": "v1",
                        "kind": "APIVersions",
                        "versions": ["v1"],
                        "serverAddressByClientCIDRs": [],
                    }
                if path == "/api/v1":
                    core = [
                        ("namespaces", "Namespace", False),
                        ("serviceaccounts", "ServiceAccount", True),
                        ("secrets", "Secret", True),
                        ("configmaps", "ConfigMap", True),
                        ("services", "Service", True),
                        ("pods", "Pod", True),
                    ]
                    return {
                        "apiVersion": "v1",
                        "kind": "APIResourceList",
                        "groupVersion": "v1",
                        "resources": [
                            {
                                "name": name,
                                "singularName": "",
                                "namespaced": namespaced,
                                "kind": kind,
                                "verbs": [
                                    "get",
                                    "list",
                                    "watch",
                                    "create",
                                    "patch",
                                    "delete",
                                    "update",
                                ],
                            }
                            for name, kind, namespaced in core
                        ],
                    }
                if path == "/apis":
                    return {
                        "apiVersion": "v1",
                        "kind": "APIGroupList",
                        "groups": [
                            {
                                "name": group_version.rsplit("/", 1)[0],
                                "versions": [
                                    {
                                        "groupVersion": group_version,
                                        "version": group_version.rsplit("/", 1)[1],
                                    }
                                ],
                                "preferredVersion": {
                                    "groupVersion": group_version,
                                    "version": group_version.rsplit("/", 1)[1],
                                },
                            }
                            for group_version in groups
                        ],
                    }
                if path.startswith("/apis/"):
                    group_version = path.removeprefix("/apis/")
                    if group_version in groups:
                        return {
                            "apiVersion": "v1",
                            "kind": "APIResourceList",
                            "groupVersion": group_version,
                            "resources": [
                                {
                                    "name": name,
                                    "singularName": "",
                                    "namespaced": True,
                                    "kind": kind,
                                    "verbs": [
                                        "get",
                                        "list",
                                        "watch",
                                        "create",
                                        "patch",
                                        "delete",
                                        "update",
                                    ],
                                }
                                for name, kind in groups[group_version]
                            ],
                        }
                return None

            def route(self):
                parts = urlsplit(self.path).path.strip("/").split("/")
                if len(parts) >= 2 and parts[0] == "api":
                    api_version, rest = parts[1], parts[2:]
                elif len(parts) >= 3 and parts[0] == "apis":
                    api_version, rest = parts[1] + "/" + parts[2], parts[3:]
                else:
                    return None
                namespace = ""
                if rest and rest[0] == "namespaces" and len(rest) >= 3:
                    namespace, resource, *tail = rest[1:]
                elif rest:
                    resource, *tail = rest
                else:
                    return None
                kind = RESOURCE_KINDS.get(resource)
                if kind is None:
                    return None
                return api_version, kind, namespace, tail[0] if tail else None

            def do_GET(self):
                state.requests.append(("GET", self.path))
                discovery = self.discovery(urlsplit(self.path).path)
                if discovery is not None:
                    return self.send_json(discovery)
                route = self.route()
                if route is None:
                    return self.send_json(
                        {
                            "kind": "Status",
                            "apiVersion": "v1",
                            "status": "Failure",
                            "reason": "NotFound",
                            "code": 404,
                        },
                        404,
                    )
                api_version, kind, namespace, name = route
                if name:
                    value = state.object_for(kind, namespace, name)
                    if value is None:
                        return self.send_json(
                            {
                                "kind": "Status",
                                "apiVersion": "v1",
                                "status": "Failure",
                                "reason": "NotFound",
                                "details": {"name": name, "kind": kind},
                                "code": 404,
                            },
                            404,
                        )
                    value = state.with_status(value)
                    if "watch=true" in urlsplit(self.path).query:
                        return self.send_watch([value])
                    return self.send_json(value)
                items = [
                    state.with_status(value)
                    for (
                        object_kind,
                        object_namespace,
                        _,
                    ), value in state.objects.items()
                    if object_kind == kind
                    and (not namespace or object_namespace == namespace)
                ]
                if kind == "Pod":
                    items.extend(
                        state.gateway_pod(name, namespace)
                        for name in ("gateway-0", "gateway-1")
                    )
                result = {
                    "apiVersion": api_version,
                    "kind": kind + "List",
                    "metadata": {"resourceVersion": "1"},
                    "items": items,
                }
                if "watch=true" in urlsplit(self.path).query:
                    return self.send_watch(items)
                return self.send_json(result)

            def do_POST(self):
                state.requests.append(("POST", self.path))
                if self.route() is None:
                    return self.send_json(
                        {
                            "kind": "Status",
                            "apiVersion": "v1",
                            "status": "Failure",
                            "reason": "NotFound",
                            "code": 404,
                        },
                        404,
                    )
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                value = json.loads(body)
                kind = value["kind"]
                metadata = value.setdefault("metadata", {})
                namespace = metadata.get("namespace", "")
                metadata.setdefault("uid", "uid-" + metadata.get("name", "object"))
                metadata.setdefault("resourceVersion", "1")
                state.objects[(kind, namespace, metadata["name"])] = value
                return self.send_json(state.with_status(value), 201)

            def do_PATCH(self):
                state.requests.append(("PATCH", self.path))
                return self.send_json(
                    {
                        "kind": "Status",
                        "apiVersion": "v1",
                        "status": "Failure",
                        "reason": "NotFound",
                        "code": 404,
                    },
                    404,
                )

        class QuietServer(ThreadingHTTPServer):
            def handle_error(self, *_args):
                pass

        self.server = QuietServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def with_status(self, value):
        result = json.loads(json.dumps(value))
        if result.get("kind") == "StatefulSet":
            name = result["metadata"]["name"]
            replicas = result.get("spec", {}).get("replicas", 1)
            ready = self.ready_replicas.get(name, 0)
            result["status"] = {
                "observedGeneration": 1,
                "replicas": replicas,
                "readyReplicas": ready,
                "updatedReplicas": ready,
                "currentRevision": name + "-abc",
                "updateRevision": name + "-abc",
            }
        return result

    def gateway_pod(self, name, namespace):
        return {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": name,
                "namespace": namespace,
                "uid": "uid-" + name,
                "resourceVersion": "1",
                "creationTimestamp": "2026-10-29T00:00:00Z",
                "labels": {"app": "gateway"},
            },
            "spec": {"containers": [{"name": "gateway"}]},
            "status": {
                "containerStatuses": [
                    {
                        "name": "gateway",
                        "started": self.gateway_started,
                        "ready": False,
                    }
                ]
            },
        }

    def object_for(self, kind, namespace, name):
        if kind == "Pod" and name in ("gateway-0", "gateway-1"):
            return self.gateway_pod(name, namespace)
        return self.objects.get((kind, namespace, name))

    @property
    def base(self):
        return f"http://127.0.0.1:{self.server.server_port}"

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


class RehearseRow5EntryPointTests(unittest.TestCase):
    def test_refused_timed_step_retains_elapsed_time(self):
        from scripts.rehearse_row5_kind import Refusal, timed_step

        report = {"timings_ms": {}}

        def refuse():
            raise Refusal("readiness_refused")

        with self.assertRaisesRegex(Refusal, "readiness_refused"):
            timed_step(report, "gateway-readiness", refuse)

        self.assertEqual(set(report["timings_ms"]), {"step:gateway-readiness"})
        self.assertGreaterEqual(report["timings_ms"]["step:gateway-readiness"], 0)

    def test_wait_refusal_detail_includes_step_name(self):
        from scripts.rehearse_row5_kind import Refusal, wait_for_step

        class Budget:
            @staticmethod
            def cap(timeout):
                return timeout

        report = {"timings_ms": {}}
        with self.assertRaises(Refusal) as caught:
            wait_for_step(
                lambda: False,
                0,
                step_name="known1-pods-ready",
                budget=Budget(),
                report=report,
            )

        self.assertEqual(caught.exception.name, "kind_behavior_deadline")
        self.assertEqual(caught.exception.detail, "step=known1-pods-ready")
        self.assertIn("step:wait-known1-pods-ready", report["timings_ms"])

    def test_row5_port_forward_wait_has_a_named_step(self):
        from scripts import rehearse_row5_kind

        wait_calls = []

        def wait(predicate, timeout, **kwargs):
            wait_calls.append((predicate, timeout, kwargs))

        with tempfile.TemporaryDirectory() as temporary:
            logs = []
            with (
                patch.object(
                    rehearse_row5_kind.package_a, "free_port", return_value=26379
                ),
                patch.object(rehearse_row5_kind.package_a.subprocess, "Popen"),
            ):
                port = rehearse_row5_kind.package_a.start_forward(
                    "kubectl",
                    "config",
                    "kind-row5",
                    "row5",
                    Path(temporary),
                    "service/redis",
                    6379,
                    [],
                    logs,
                    wait,
                    step_name="port-forward-service-redis-ready",
                )
            for log in logs:
                log.close()

        self.assertEqual(port, 26379)
        self.assertEqual(len(wait_calls), 1)
        self.assertEqual(
            wait_calls[0][2], {"step_name": "port-forward-service-redis-ready"}
        )

    def test_rendered_manifest_images_match_expected_set(self):
        from scripts import rehearse_row5_kind

        gateway_image = "mti-gateway:stage1"
        _, used_images = rehearse_row5_kind.render_row5_manifest(
            "mti-m5-row5-package-a", gateway_image
        )
        rehearse_row5_kind.check_row5_manifest_images(used_images, gateway_image)
        with self.assertRaises(rehearse_row5_kind.Refusal) as caught:
            rehearse_row5_kind.check_row5_manifest_images(
                [*used_images, "dec077-kind/python:amd64"], gateway_image
            )
        self.assertEqual(caught.exception.name, "kind_manifest_image_set")

    def test_refusal_detail_is_written_to_result_receipt(self):
        from scripts import rehearse_row5_kind

        def create_cluster(
            _kind, _cluster, _image, _config, kubeconfig, *_args, **_kwargs
        ):
            Path(kubeconfig).write_text("kubeconfig\n", encoding="utf-8")

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output"
            stderr = io.StringIO()

            resources = {
                "items": [
                    {
                        "kind": "Pod",
                        "metadata": {"name": name, "labels": {"app": app}},
                        "status": {
                            "containerStatuses": [
                                {"name": app, "restartCount": int(app == "vllm")}
                            ]
                        },
                    }
                    for name, app in (
                        ("gateway-0", "gateway"),
                        ("vllm-0", "vllm"),
                        ("redis-0", "redis"),
                    )
                ]
            }
            diagnostic_calls = []

            def run(argv, *, return_status=False, **kwargs):
                if not return_status:
                    return ""
                diagnostic_calls.append((argv, kwargs))
                if "get" not in argv:
                    return (
                        (1, "synthetic previous log failure")
                        if "--previous" in argv
                        else (0, "synthetic logs")
                    )
                if (
                    argv[argv.index("get") + 1]
                    == "pods,statefulsets,deployments,endpointslices"
                ):
                    return 0, json.dumps(resources)
                if argv[argv.index("get") + 1] == "events":
                    return 0, '{"items": []}'
                return 0, "unexpected get"

            def delete_cluster(*_args, **_kwargs):
                self.assertTrue((output / "diagnostics" / "resources.json").exists())
                self.assertTrue((output / "diagnostics" / "events.json").exists())

            with (
                patch.object(
                    rehearse_row5_kind,
                    "_tool",
                    side_effect=lambda _path, name, _pins: (name, False),
                ),
                patch.object(rehearse_row5_kind.package_a, "run", side_effect=run),
                patch.object(
                    rehearse_row5_kind.package_a,
                    "create_kind_cluster",
                    side_effect=create_cluster,
                ),
                patch.object(
                    rehearse_row5_kind.package_a,
                    "delete_kind_cluster",
                    side_effect=delete_cluster,
                ),
                patch.object(
                    rehearse_row5_kind,
                    "_run_live",
                    side_effect=rehearse_row5_kind.Refusal("x", "d"),
                ),
                patch("sys.stderr", stderr),
            ):
                result = rehearse_row5_kind.main(
                    [
                        "--output",
                        str(output),
                        "--gateway-image",
                        "mti-gateway:stage1",
                        "--cluster",
                        "row5-refusal-detail",
                        "--kind-bin",
                        "kind",
                        "--kubectl-bin",
                        "kubectl",
                    ]
                )

            report = json.loads((output / "result.json").read_text(encoding="utf-8"))
            self.assertEqual(result, 1)
            self.assertEqual(report["refusal"], "x")
            self.assertEqual(report["refusal_detail"], "d")
            self.assertIn("row5_kind_refusal:x:d", stderr.getvalue())
            diagnostics = json.loads(
                (output / "diagnostics" / "diagnostics.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertGreaterEqual(diagnostics["command_count"], 6)
            self.assertTrue(
                any(
                    command.get("error") == "kubectl_exit:1"
                    for command in diagnostics["commands"]
                )
            )
            self.assertTrue(
                (output / "diagnostics" / "pod-gateway-0-current.log").exists()
            )
            self.assertTrue(
                (
                    output / "diagnostics" / "pod-vllm-0-container-vllm-previous.log"
                ).exists()
            )
            self.assertTrue(
                all(
                    kwargs.get("timeout")
                    == rehearse_row5_kind.ROW5_KIND_DIAGNOSTIC_COMMAND_TIMEOUT_S
                    for _argv, kwargs in diagnostic_calls
                )
            )

    def test_restore_hold_start_refuses_n2_before_candidate_snapshot(self):
        from scripts.rehearse_row5_kind import Refusal, restoration_hold_start_label

        self.assertEqual(
            restoration_hold_start_label({"n": 1, "candidate": 2}, 100), "hold_start"
        )
        with self.assertRaisesRegex(Refusal, "kind_restore_hold_start_missed"):
            restoration_hold_start_label({"n": 2, "candidate": None}, 200)

    def test_restore_window_covers_ttl_and_hold_after_readiness_allowance(self):
        from scripts.rehearse_row5_kind import restore_window_s

        config = {"ttl_ms": 8000, "hold_ms": 2000}
        self.assertGreaterEqual(
            restore_window_s(config),
            90 + (config["ttl_ms"] + config["hold_ms"]) / 1000 + 10,
        )

    def test_restore_hold_start_waits_through_twelve_seconds_without_candidate(self):
        from scripts.rehearse_row5_kind import (
            restore_window_s,
            wait_for_restoration_hold_start,
        )

        clock = {"now": 0.0}
        labels = []
        config = {"ttl_ms": 8000, "hold_ms": 2000}

        def monotonic():
            return clock["now"]

        def sleep(seconds):
            clock["now"] += seconds

        def live_snapshot(*, label_if):
            state = (
                {"n": 1, "candidate": None}
                if clock["now"] < 12
                else {"n": 1, "candidate": 2}
            )
            label = label_if(state, round(clock["now"] * 1000))
            if label:
                labels.append(label)
                return {"snapshot_id": label, "payload": {"state": state}}
            return None

        result = wait_for_restoration_hold_start(
            live_snapshot,
            restore_window_s(config),
            monotonic=monotonic,
            sleep=sleep,
        )
        self.assertGreaterEqual(clock["now"], 12)
        self.assertEqual(result["snapshot_id"], "hold_start")
        self.assertEqual(labels, ["hold_start"])

    def test_missing_hold_end_snapshot_has_named_refusal(self):
        from scripts.rehearse_row5_kind import Refusal, require_hold_end_snapshot

        with self.assertRaisesRegex(Refusal, "kind_restore_hold_end_snapshot_missing"):
            require_hold_end_snapshot(lambda _name: None)

    def test_operator_namespace_role_covers_rendered_endpoint_reader_rules(self):
        from scripts import rehearse_row5_kind

        namespace = "mti-m5-row5-rbac-test"
        rendered, _ = rehearse_row5_kind.render_row5_manifest(
            namespace, "example.invalid/gateway:test"
        )
        endpoint_reader = next(
            item
            for item in rendered["items"]
            if item["kind"] == "Role" and item["metadata"]["name"] == "endpoint-reader"
        )
        operator = rehearse_row5_kind.operator_rbac_manifest(namespace, endpoint_reader)
        namespace_role = next(
            item
            for item in operator["items"]
            if item["kind"] == "Role" and item["metadata"]["namespace"] == namespace
        )
        binding = next(
            item
            for item in operator["items"]
            if item["kind"] == "RoleBinding"
            and item["metadata"]["namespace"] == namespace
        )
        self.assertEqual(namespace_role["rules"], endpoint_reader["rules"])
        self.assertEqual(binding["subjects"][0]["name"], "row5-operator")
        self.assertEqual(binding["roleRef"]["name"], namespace_role["metadata"]["name"])
        self.assertEqual(
            next(item for item in operator["items"] if item["kind"] == "ClusterRole")[
                "rules"
            ],
            [
                {
                    "apiGroups": ["rbac.authorization.k8s.io"],
                    "resources": ["roles"],
                    "resourceNames": ["endpoint-reader"],
                    "verbs": ["get", "update"],
                },
                {
                    "apiGroups": ["rbac.authorization.k8s.io"],
                    "resources": ["rolebindings"],
                    "resourceNames": ["gateway-endpoints"],
                    "verbs": ["get"],
                },
                {
                    "apiGroups": ["authorization.k8s.io"],
                    "resources": ["subjectaccessreviews"],
                    "verbs": ["create"],
                },
            ],
        )

    def test_kind_create_failure_is_named_and_own_cluster_is_deleted(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fake_bin = root / "fake-bin"
            fake_bin.mkdir()
            log = root / "kind-calls.jsonl"
            fake = fake_bin / ("kind.cmd" if os.name == "nt" else "kind")
            fake_py = root / "fake_kind.py"
            fake_py.write_text(
                r"""
import json, os, sys
args = sys.argv[1:]
def option(name):
    return args[args.index(name) + 1]
if args == ["get", "clusters"]:
    row = {"command": args, "argv": args}
    code = 0
elif args[:2] == ["create", "cluster"]:
    assert option("--name").startswith("row5-")
    config = json.load(open(option("--config"), encoding="utf-8"))
    assert config["kind"] == "Cluster"
    assert option("--image").startswith("kindest/node:")
    assert args == ["create", "cluster", "--name", option("--name"), "--image", option("--image"), "--config", option("--config"), "--kubeconfig", option("--kubeconfig")]
    row = {"command": args[:3], "argv": args, "name": option("--name"), "config": option("--config"), "image": option("--image"), "kubeconfig": option("--kubeconfig")}
    code = 19
elif args[:2] == ["delete", "cluster"]:
    assert args == ["delete", "cluster", "--name", option("--name"), "--kubeconfig", option("--kubeconfig")]
    row = {"command": args[:3], "argv": args, "name": option("--name"), "kubeconfig": option("--kubeconfig")}
    code = 0
else:
    raise AssertionError("unexpected kind argv: " + repr(args))
with open(os.environ["ROW5_KIND_LOG"], "a", encoding="utf-8") as stream:
    stream.write(json.dumps(row) + "\n")
sys.exit(code)
""",
                encoding="utf-8",
            )
            if os.name == "nt":
                fake.write_text(
                    "@echo off\r\n"
                    + f'"{sys.executable}" "{fake_py}" %*\r\n'
                    + "exit /b %ERRORLEVEL%\r\n",
                    encoding="utf-8",
                )
            else:
                fake.write_text(
                    f"#!{sys.executable}\n" + fake_py.read_text(encoding="utf-8"),
                    encoding="utf-8",
                )
                fake.chmod(0o755)
            output = root / "result"
            environment = os.environ.copy()
            environment["PATH"] = str(fake_bin) + os.pathsep + environment["PATH"]
            environment["ROW5_KIND_LOG"] = str(log)
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--output",
                    str(output),
                    "--gateway-image",
                    "example.invalid/gateway:test",
                    "--cluster",
                    "row5-create-test",
                    "--kind-bin",
                    "kind",
                    "--kubectl-bin",
                    sys.executable,
                ],
                env=environment,
                capture_output=True,
                text=True,
                timeout=20,
            )
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("row5_kind_refusal:kind_create_failed", result.stderr)
            report = json.loads((output / "result.json").read_text(encoding="utf-8"))
            self.assertEqual(report["refusal"], "kind_create_failed")
            calls = [
                json.loads(line)
                for line in log.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(
                [row["command"] for row in calls],
                [
                    ["get", "clusters"],
                    ["create", "cluster", "--name"],
                    ["delete", "cluster", "--name"],
                ],
            )
            self.assertEqual(calls[1]["name"], "row5-create-test")
            self.assertTrue(calls[1]["config"].endswith("kind.json"))
            self.assertTrue(calls[1]["image"].startswith("kindest/node:"))
            self.assertEqual(calls[2]["name"], "row5-create-test")

    def run_manifest_apply(self, *, started):
        self.assertTrue(KUBECTL.is_file(), f"pinned kubectl missing: {KUBECTL}")
        with (
            tempfile.TemporaryDirectory() as temporary,
            FakeKubernetesAPI(started=started) as api,
        ):
            root = Path(temporary)
            output = root / "output"
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--output",
                    str(output),
                    "--gateway-image",
                    "example.invalid/gateway:test",
                    "--cluster",
                    "row5-api-test",
                    "--kubectl-bin",
                    str(KUBECTL),
                    "--api-server",
                    api.base,
                    "--readiness-timeout",
                    "1",
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            report = json.loads((output / "result.json").read_text(encoding="utf-8"))
            resources = {
                (kind, value["metadata"].get("name"))
                for (kind, _namespace, _name), value in api.objects.items()
            }
            expected = {
                ("Role", "endpoint-reader"),
                ("RoleBinding", "gateway-endpoints"),
                ("StatefulSet", "gateway"),
                ("StatefulSet", "vllm"),
                ("Deployment", "redis"),
                ("Service", "gateway"),
                ("Service", "redis"),
                ("Service", "vllm"),
            }
            self.assertTrue(expected <= resources, resources)
            self.assertTrue(
                any(
                    method == "GET" and urlsplit(path).path.endswith("/statefulsets")
                    for method, path in api.requests
                ),
                api.requests,
            )
            return result, report, api.requests, resources

    def test_manifest_apply_waits_until_both_gateway_containers_start(self):
        result, report, requests, resources = self.run_manifest_apply(started=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(report["status"], "api_steps_complete")
        self.assertIsNone(report["refusal"])
        expected = {
            ("Role", "endpoint-reader"),
            ("RoleBinding", "gateway-endpoints"),
            ("StatefulSet", "gateway"),
            ("StatefulSet", "vllm"),
            ("Deployment", "redis"),
            ("Service", "gateway"),
            ("Service", "redis"),
            ("Service", "vllm"),
        }
        self.assertTrue(expected <= resources, resources)
        pod_reads = [
            urlsplit(path).path.rsplit("/", 1)[-1]
            for method, path in requests
            if method == "GET" and "/pods/" in urlsplit(path).path
        ]
        self.assertEqual(list(dict.fromkeys(pod_reads)), ["gateway-0", "gateway-1"])
        self.assertGreaterEqual(pod_reads.count("gateway-0"), 2)
        self.assertGreaterEqual(pod_reads.count("gateway-1"), 2)

    def test_manifest_apply_refuses_when_gateway_container_did_not_start(self):
        result, report, _requests, _resources = self.run_manifest_apply(started=False)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(report["status"], "refused")
        self.assertEqual(report["refusal"], "kind_first_readiness_wait")
        self.assertIn("kind_first_readiness_wait", result.stderr)
        self.assertIn("timed out waiting for the condition", result.stderr.lower())
        self.assertNotIn("only available for RollingUpdate", result.stderr)


if __name__ == "__main__":
    unittest.main()
