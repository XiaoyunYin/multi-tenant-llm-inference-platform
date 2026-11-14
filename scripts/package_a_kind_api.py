"""Use the hash-pinned kubectl against a loopback fake Kubernetes API; no cluster."""

import argparse
import ast
import contextlib
import copy
import hashlib
import json
import importlib.util
import os
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from inference_platform.package_a_workload import preflight_manifest

ROOT = Path(__file__).resolve().parents[1]


def rehearsal():
    spec = importlib.util.spec_from_file_location(
        "kind_rehearsal", ROOT / "scripts/rehearse_eks_package_a.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def rendered_kind_manifest():
    module = rehearsal()
    manifest = preflight_manifest()
    local = ("mti-gateway:r314", "mti-fake:stage1")
    module.mutate_kind_manifest(
        manifest,
        local[0],
        {
            "redis": module.REDIS_IMAGE,
            "nginx": module.NGINX_IMAGE,
            "prometheus": module.PROMETHEUS_IMAGE,
            "python": module.PYTHON_IMAGE,
        },
        local,
    )
    return manifest


def pinned_kubectl():
    pins = json.loads((ROOT / "deploy/k8s/pins.json").read_bytes())
    platform = "windows" if os.name == "nt" else "linux"
    path = ROOT / ".tools" / ("kubectl.exe" if os.name == "nt" else "kubectl")
    # Missing, wrong version or changed bytes fail. There is no skip path.
    if (
        hashlib.sha256(path.read_bytes()).hexdigest()
        != pins[f"kubectl_{platform}_amd64_sha256"]
    ):
        raise ValueError("pinned_kubectl_sha256_mismatch")
    version = json.loads(
        subprocess.check_output([str(path), "version", "--client", "-o", "json"])
    )
    if version["clientVersion"]["gitVersion"] != pins["kubectl_version"]:
        raise ValueError("pinned_kubectl_version_mismatch")
    return path


class FakeAPI:
    def __init__(self):
        self.ready = 0
        self.pod = None
        self.requests = []
        self.statefulsets = {
            o["metadata"]["name"]: o
            for o in rendered_kind_manifest()["items"]
            if o["kind"] == "StatefulSet"
        }

    def object(self, name):
        value = copy.deepcopy(self.statefulsets[name])
        value["metadata"].update(resourceVersion="1", uid="scripted-sts-" + name)
        value["status"] = {
            "replicas": 2,
            "readyReplicas": self.ready,
            "currentReplicas": 2,
        }
        return value

    @contextlib.contextmanager
    def serve(self):
        state = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args):
                pass

            def send_json(self, value, code=200):
                self.request_record["response_code"] = code
                data = json.dumps(value).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(data)
                self.close_connection = True

            def do_GET(self):
                url = urlsplit(self.path)
                path, query = url.path, parse_qs(url.query)
                self.request_record = {
                    "path": path,
                    "query": query,
                    "readyReplicas": state.ready,
                    "pod_uid": state.pod["metadata"]["uid"] if state.pod else None,
                }
                state.requests.append(self.request_record)
                if path == "/api":
                    return self.send_json(
                        {
                            "kind": "APIVersions",
                            "apiVersion": "v1",
                            "versions": ["v1"],
                            "serverAddressByClientCIDRs": [],
                        }
                    )
                if path == "/apis":
                    return self.send_json(
                        {
                            "kind": "APIGroupList",
                            "apiVersion": "v1",
                            "groups": [
                                {
                                    "name": "apps",
                                    "versions": [
                                        {"groupVersion": "apps/v1", "version": "v1"}
                                    ],
                                    "preferredVersion": {
                                        "groupVersion": "apps/v1",
                                        "version": "v1",
                                    },
                                }
                            ],
                        }
                    )
                if path in ("/api/v1", "/apis/apps/v1"):
                    apps = path.endswith("apps/v1")
                    return self.send_json(
                        {
                            "kind": "APIResourceList",
                            "apiVersion": "v1",
                            "groupVersion": "apps/v1" if apps else "v1",
                            "resources": [
                                {
                                    "name": "statefulsets" if apps else "pods",
                                    "singularName": "statefulset" if apps else "pod",
                                    "namespaced": True,
                                    "kind": "StatefulSet" if apps else "Pod",
                                    "verbs": ["get", "list", "watch", "delete"],
                                }
                            ],
                        }
                    )
                is_sts = "/statefulsets" in path
                resource = "statefulsets" if is_sts else "pods"
                tail = path.split("/" + resource, 1)[-1].strip("/")
                selector = query.get("fieldSelector", [""])[0]
                selected_name = (
                    selector.removeprefix("metadata.name=")
                    if selector.startswith("metadata.name=")
                    else None
                )
                if not (is_sts or "/pods" in path):
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
                if query.get("watch", [""])[0] in ("true", "1"):
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    try:
                        # No events for an unchanged object: kubectl must honor
                        # its own timeout while the watch hangs.
                        previous = (
                            state.object(tail or selected_name or "vllm")
                            if is_sts
                            else state.pod
                        )
                        for _ in range(30):
                            value = (
                                state.object(tail or selected_name or "vllm")
                                if is_sts
                                else state.pod
                            )
                            if value and value != previous:
                                previous = value
                                self.wfile.write(
                                    (
                                        json.dumps(
                                            {
                                                "type": "MODIFIED"
                                                if is_sts
                                                else "ADDED",
                                                "object": value,
                                            }
                                        )
                                        + "\n"
                                    ).encode()
                                )
                                self.wfile.flush()
                            time.sleep(0.1)
                    except (
                        BrokenPipeError,
                        ConnectionResetError,
                        ConnectionAbortedError,
                    ):
                        pass
                    self.close_connection = True
                    return
                value = state.object(tail) if is_sts and tail else state.pod
                if tail:
                    if value is None:
                        return self.send_json(
                            {
                                "kind": "Status",
                                "apiVersion": "v1",
                                "status": "Failure",
                                "reason": "NotFound",
                                "message": f'{resource} "{tail}" not found',
                                "details": {"name": tail, "kind": resource},
                                "code": 404,
                            },
                            404,
                        )
                    return self.send_json(value)
                items = (
                    [state.object(name) for name in state.statefulsets]
                    if is_sts
                    else ([state.pod] if state.pod else [])
                )
                if selected_name:
                    items = [
                        item
                        for item in items
                        if item["metadata"]["name"] == selected_name
                    ]
                return self.send_json(
                    {
                        "kind": "StatefulSetList" if is_sts else "PodList",
                        "apiVersion": "apps/v1" if is_sts else "v1",
                        "metadata": {"resourceVersion": "1"},
                        "items": items,
                    }
                )

            def do_DELETE(self):
                self.request_record = {
                    "method": "DELETE",
                    "path": self.path,
                    "pod_uid": state.pod["metadata"]["uid"] if state.pod else None,
                }
                state.requests.append(self.request_record)
                assert self.path.endswith("/pods/vllm-0")
                old = state.pod
                state.pod = None
                self.send_json(old)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield f"http://127.0.0.1:{server.server_port}"
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


def pod(uid):
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "vllm-0",
            "namespace": "mti-m5-package-a",
            "uid": uid,
            "resourceVersion": uid,
        },
        "status": {
            "phase": "Running",
            "conditions": [{"type": "Ready", "status": "True"}],
        },
    }


def replacement_blocks(source):
    """Extract only delete/create/identity/Ready at both actual main sites.

    This does not walk the rest of main (R314 item 5 is a separate task).
    """
    blocks = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Try):
            continue
        for index, statement in enumerate(node.body):
            if (
                isinstance(statement, ast.Expr)
                and isinstance(statement.value, ast.Call)
                and ast.unparse(statement.value.func) == "k"
                and [getattr(a, "value", None) for a in statement.value.args[:3]]
                == ["delete", "pod", "vllm-0"]
            ):
                block = node.body[index : index + 4]
                assert len(block) == 4
                assert isinstance(block[2], ast.Assert), "new UID must precede Ready"
                assert "--for=create" in ast.unparse(block[1])
                assert "--for=condition=Ready" in ast.unparse(block[3])
                blocks.append(block)
    assert len(blocks) == 2, "both replacement sites must be tested"
    return blocks


def check_api(output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    kubectl = pinned_kubectl()
    api, commands = FakeAPI(), []
    (output / "unused-config").write_text(
        json.dumps(
            {
                "apiVersion": "v1",
                "kind": "Config",
                "clusters": [],
                "contexts": [],
                "users": [],
            }
        ),
        encoding="utf-8",
    )
    with api.serve() as url:
        prefix = [
            str(kubectl),
            "--kubeconfig",
            str(output / "unused-config"),
            "--server",
            url,
            "--cache-dir",
            str(output / "discovery"),
            "-n",
            "mti-m5-package-a",
        ]

        def command(*args, expected):
            begin = time.monotonic()
            completed = subprocess.run(
                [*prefix, *args], capture_output=True, text=True, timeout=10
            )
            record = {
                "argv": list(args),
                "exit_code": completed.returncode,
                "stdout": completed.stdout,
                "stderr": completed.stderr,
                "elapsed_seconds": time.monotonic() - begin,
            }
            commands.append(record)
            if expected == "pass":
                assert completed.returncode == 0, record
            else:
                assert completed.returncode != 0 and expected in completed.stderr, (
                    record
                )
            return record

        for name in ("vllm", "gateway"):
            command(
                "rollout",
                "status",
                "statefulset/" + name,
                "--timeout=1s",
                expected="rollout status is only available for RollingUpdate strategy type",
            )
            api.ready = 0
            command(
                "wait",
                "--for=jsonpath={.status.readyReplicas}=2",
                "statefulset/" + name,
                "--timeout=1s",
                expected="timed out",
            )
            api.ready = 2
            command(
                "wait",
                "--for=jsonpath={.status.readyReplicas}=2",
                "statefulset/" + name,
                "--timeout=2s",
                expected="pass",
            )
        command(
            "wait",
            "--for=condition=Ready",
            "pod/vllm-0",
            "--timeout=1s",
            expected="(NotFound)",
        )
        # Exercise the actual main's replacement sequence, including delayed create.
        module = rehearsal()

        source = Path(module.__file__).read_text(encoding="utf-8")
        # Execute the actual initial readiness loop against the rendered objects.
        # This is the pre-fix behavioural control: bed15c3 issues rollout status.
        loops = [
            node
            for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.For)
            and ast.unparse(node.target) == "name"
            and ast.unparse(node.iter) == "('vllm', 'gateway')"
        ]
        assert len(loops) == 1

        def actual_k(*args, **kwargs):
            command(
                *(
                    arg if not arg.startswith("--timeout=") else "--timeout=2s"
                    for arg in args
                ),
                expected="pass",
            )

        exec(
            compile(ast.Module(body=loops, type_ignores=[]), module.__file__, "exec"),
            {"k": actual_k},
        )
        blocks = replacement_blocks(source)
        old_uid = "scripted-old-vllm-uid"
        for index, block in enumerate(blocks):
            previous_uid = old_uid
            api.pod = pod(previous_uid)
            replacement = []

            def k(*args, **kwargs):
                if args[:3] == ("delete", "pod", "vllm-0"):
                    command(*args, "--timeout=2s", expected="pass")
                    return ""
                if "--for=create" in args:
                    argv = [
                        *prefix,
                        *[
                            arg if not arg.startswith("--timeout=") else "--timeout=5s"
                            for arg in args
                        ],
                    ]
                    process = subprocess.Popen(
                        argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
                    )
                    try:
                        time.sleep(0.5)
                        assert api.pod is None
                        assert process.poll() is None, (
                            "create wait returned while absent"
                        )
                        new_uid = f"scripted-new-vllm-uid-{index}"
                        api.pod = pod(new_uid)
                        replacement.append(new_uid)
                        stdout, stderr = process.communicate(timeout=8)
                        commands.append(
                            {
                                "argv": argv[len(prefix) :],
                                "exit_code": process.returncode,
                                "stdout": stdout,
                                "stderr": stderr,
                                "absent_wait_observed": True,
                                "old_uid": previous_uid,
                                "new_uid": new_uid,
                            }
                        )
                        assert process.returncode == 0, commands[-1]
                        return stdout
                    finally:
                        if process.poll() is None:
                            process.kill()
                            process.wait(timeout=5)
                return command(
                    *[
                        arg if not arg.startswith("--timeout=") else "--timeout=2s"
                        for arg in args
                    ],
                    expected="pass",
                )["stdout"]

            def pods():
                text = k("get", "pods", "-o", "json")
                return {p["metadata"]["name"]: p for p in json.loads(text)["items"]}

            exec(
                compile(
                    ast.Module(body=block, type_ignores=[]), module.__file__, "exec"
                ),
                {
                    "k": k,
                    "pods": pods,
                    "old_uids": {"vllm-0": "scripted-old-vllm-uid"},
                    "new_uid": previous_uid,
                },
            )
            assert replacement, "actual replacement block omitted create wait"
            old_uid = replacement[0]
    transcript = {
        "schema": "package-a-kind-fake-api-v1",
        "complete": True,
        "kubectl_sha256": hashlib.sha256(kubectl.read_bytes()).hexdigest(),
        "statefulsets": api.statefulsets,
        "commands": commands,
        "requests": api.requests,
    }
    (output / "transcript.json").write_text(
        json.dumps(transcript, indent=2) + "\n", encoding="utf-8"
    )
    return transcript


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = check_api(args.output)
    print(
        json.dumps(
            {"complete": result["complete"], "commands": len(result["commands"])}
        )
    )
