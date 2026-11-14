"""One in-cluster CPU Job: TLS load, same-clock Ready observation and frozen JSONL.

kubectl exec submits short control messages and retrieves bounded file chunks.
No request stream traverses the operator or its tunnels.
"""

import argparse
import base64
import json
import os
import re
import ssl
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from types import SimpleNamespace

from .calibration import CalibrationConfig
from .m5_descriptive import stream
from .m5_descriptive_operator import build_corpus, file_inventory, load

DATA = Path("/results")
LABEL = re.compile(r"[a-z][a-z0-9_]{0,40}")


def pushed_digest(inspection, repository):
    """Docker may put its original local-name digest before the pushed one."""
    values = [
        value for value in inspection["RepoDigests"] if value.startswith(repository + "@sha256:")
    ]
    if len(values) != 1 or not re.fullmatch(
        re.escape(repository) + r"@sha256:[0-9a-f]{64}", values[0]
    ):
        raise ValueError("descriptive:pushed_image_digest")
    return values[0]


def client_resources(namespace, image, deadline_epoch, *, cpu="2"):
    """Secret/CA contents are supplied separately and never enter a ConfigMap."""
    from .eks_deployment import image_pin

    image_pin(image)
    metadata = {"name": "load-client", "namespace": namespace}
    return {
        "apiVersion": "v1",
        "kind": "List",
        "items": [
            {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": metadata},
            {
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "Role",
                "metadata": metadata,
                "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"]}],
            },
            {
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "RoleBinding",
                "metadata": metadata,
                "subjects": [
                    {"kind": "ServiceAccount", "name": "load-client", "namespace": namespace}
                ],
                "roleRef": {
                    "apiGroup": "rbac.authorization.k8s.io",
                    "kind": "Role",
                    "name": "load-client",
                },
            },
            {
                "apiVersion": "batch/v1",
                "kind": "Job",
                "metadata": metadata,
                "spec": {
                    "backoffLimit": 0,
                    "activeDeadlineSeconds": max(1, int(deadline_epoch - time.time())),
                    "template": {
                        "metadata": {"labels": {"app": "load-client"}},
                        "spec": {
                            "restartPolicy": "Never",
                            "serviceAccountName": "load-client",
                            "nodeSelector": {"m5-role": "cpu"},
                            "securityContext": {
                                "runAsUser": 65532,
                                "runAsNonRoot": True,
                                "fsGroup": 65532,
                            },
                            "containers": [
                                {
                                    "name": "client",
                                    "image": image,
                                    "command": [
                                        "python",
                                        "-u",
                                        "-m",
                                        "inference_platform.m5_descriptive_client",
                                        "serve",
                                    ],
                                    "readinessProbe": {
                                        "exec": {"command": ["test", "-f", "/results/ready"]},
                                        "periodSeconds": 1,
                                    },
                                    "env": [
                                        {"name": "M5_NAMESPACE", "value": namespace},
                                        {"name": "M5_DEADLINE_EPOCH", "value": str(deadline_epoch)},
                                    ],
                                    "resources": {
                                        "requests": {"cpu": cpu, "memory": "1Gi"},
                                        "limits": {"cpu": "4", "memory": "4Gi"},
                                    },
                                    "securityContext": {
                                        "allowPrivilegeEscalation": False,
                                        "capabilities": {"drop": ["ALL"]},
                                    },
                                    "volumeMounts": [
                                        {"name": "results", "mountPath": "/results"},
                                        {
                                            "name": "credential",
                                            "mountPath": "/credential",
                                            "readOnly": True,
                                        },
                                        {"name": "ca", "mountPath": "/ca", "readOnly": True},
                                    ],
                                }
                            ],
                            "volumes": [
                                {"name": "results", "emptyDir": {"sizeLimit": "4Gi"}},
                                {"name": "credential", "secret": {"secretName": "load-client"}},
                                {"name": "ca", "configMap": {"name": "load-client-ca"}},
                            ],
                        },
                    },
                },
            },
        ],
    }


def first_serving(records, ready_ns, slot):
    values = [
        r["completion_monotonic_ns"]
        for r in records
        if r.get("outcome") == "completed"
        and r.get("backend_slot") == slot
        and isinstance(r.get("completion_monotonic_ns"), int)
        and r["completion_monotonic_ns"] >= ready_ns
    ]
    return min(values) - ready_ns if values else None


class ReadyObserver:
    def __init__(self, namespace, target, old_uid):
        self.namespace, self.target, self.old_uid = namespace, target, old_uid
        self.stop = threading.Event()
        self.ready_ns = None
        self.error = None
        self.thread = threading.Thread(target=self.run)

    def run(self):
        context = ssl.create_default_context(
            cafile="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
        )
        token = Path("/var/run/secrets/kubernetes.io/serviceaccount/token").read_text().strip()
        url = (
            f"https://kubernetes.default.svc/api/v1/namespaces/{self.namespace}/pods/{self.target}"
        )
        while not self.stop.is_set():
            try:
                request = urllib.request.Request(url, headers={"Authorization": "Bearer " + token})
                with urllib.request.urlopen(request, context=context, timeout=3) as response:
                    pod = json.load(response)
                observed = time.perf_counter_ns()
                if pod["metadata"]["uid"] != self.old_uid and any(
                    c["type"] == "Ready" and c["status"] == "True"
                    for c in pod.get("status", {}).get("conditions", [])
                ):
                    self.ready_ns = observed
                    return
            except urllib.error.HTTPError as error:
                error.close()
                if error.code != 404:
                    self.error = f"descriptive:client_ready_http_{error.code}"
                    return
            except (OSError, ValueError) as error:
                self.error = "descriptive:client_ready:" + type(error).__name__
                return
            self.stop.wait(0.25)


def run_task(task, ports, *, observer_factory=ReadyObserver):
    if "deadline_epoch" in task:
        ports = SimpleNamespace(
            **{
                **vars(ports),
                "deadline": min(
                    ports.deadline,
                    time.monotonic() + task["deadline_epoch"] - time.time(),
                ),
            }
        )
    if task["kind"] == "smoke":
        config = CalibrationConfig(
            url=ports.client_url,
            token=ports.credential,
            tenant_id=ports.tenant_id,
            model=ports.model,
            run_id="m5-smoke",
            max_tokens=1,
            timeout_seconds=30,
        )
        samples = []
        stop = min(ports.deadline, time.monotonic() + 30)
        while time.monotonic() < stop:
            sample = stream(
                config,
                "a" * 64,
                time.perf_counter_ns(),
                "synthetic",
                stop,
                tls_context=ports.tls_context,
            )
            samples.append(sample)
            if sample["outcome"] == "completed":
                break
            time.sleep(min(0.25, max(0, stop - time.monotonic())))
        else:
            raise ValueError("descriptive:smoke_not_completed")
        for path, expected in (
            ("/", 404),
            ("/metrics", 404),
            ("/admin", 404),
            ("/v1/chat/completions", 401),
        ):
            request = urllib.request.Request(
                ports.client_url + path,
                data=b"{}" if expected == 401 else None,
                headers={"Content-Type": "application/json"},
            )
            try:
                with urllib.request.urlopen(
                    request, context=ports.tls_context, timeout=5
                ) as response:
                    status = response.status
            except urllib.error.HTTPError as error:
                status = error.code
                error.close()
            if status != expected:
                raise ValueError("descriptive:smoke_boundary")
        return {
            "stream": sample,
            "startup_probe_attempts": samples,
            "tls_verified": True,
            "admin_paths_404": True,
            "unauthenticated_status": 401,
            "load_path": "in_cluster_tls_clusterip",
        }
    if task["kind"] != "load":
        raise ValueError("descriptive:client_task_kind")
    observer = None
    if "replacement" in task:
        replacement = task["replacement"]
        observer = observer_factory(ports.namespace, replacement["target"], replacement["old_uid"])
        observer.thread.start()
    try:
        result = load(
            ports,
            task["levels"],
            duration=task["duration"],
            deadline=ports.deadline,
            corpus=ports.corpus,
            label=task["label"],
        )
    finally:
        if observer:
            observer.stop.set()
            observer.thread.join(timeout=5)
    value = {"levels": result}
    if observer:
        if observer.thread.is_alive() or observer.error or observer.ready_ns is None:
            raise ValueError(observer.error or "descriptive:client_ready_not_observed")
        rows = [
            json.loads(line)
            for item in result
            for line in (Path(ports.output) / item["client_records"]["path"])
            .read_text()
            .splitlines()
        ]
        delay = first_serving(rows, observer.ready_ns, 0)
        if task["replacement"]["target"] == "vllm-0" and delay is None:
            raise ValueError("descriptive:replacement_serving_not_observed")
        value["replacement"] = {
            "ready_monotonic_ns": observer.ready_ns,
            "first_completed_backend_slot": 0,
            "first_completed_after_ready_ns": delay,
            "gateway_identity": "not exposed by client response; no per-gateway serving claim",
        }
    return value


def safe_path(root, name):
    path = (root / name).resolve()
    if not path.is_relative_to(root.resolve()) or path.is_symlink():
        raise ValueError("descriptive:client_path")
    return path


def control(root, mode, arguments):
    root = Path(root)
    if mode == "submit":
        raw = base64.b64decode(arguments[0], validate=True)
        task = json.loads(raw)
        if not LABEL.fullmatch(task["label"]):
            raise ValueError("descriptive:client_label")
        path = root / (task["label"] + ".task")
        if path.exists():
            if path.read_bytes() != raw:
                raise ValueError("descriptive:client_task_changed")
        else:
            temp = root / (task["label"] + ".pending")
            with temp.open("xb") as handle:
                handle.write(raw)
            temp.rename(path)
        return {"submitted": task["label"]}
    if mode == "status":
        path = safe_path(root, arguments[0] + ".result")
        return json.loads(path.read_bytes()) if path.exists() else {"status": "RUNNING"}
    if mode == "inventory":
        return file_inventory(root / "clients")
    if mode == "read":
        path = safe_path(root / "clients", arguments[0])
        with path.open("rb") as handle:
            handle.seek(int(arguments[1]))
            return {"base64": base64.b64encode(handle.read(65536)).decode()}
    if mode == "observe":
        from urllib.parse import urlsplit

        url = urlsplit(arguments[0])
        if (
            url.scheme != "http"
            or url.path not in {"/metrics", "/health", "/readyz"}
            or url.port not in {8000, 8080}
            or url.username
            or url.password
        ):
            raise ValueError("descriptive:observation_target")
        with urllib.request.urlopen(arguments[0], timeout=5) as response:
            body = response.read(2 * 1024**2 + 1)
            status = response.status
        if len(body) > 2 * 1024**2:
            raise ValueError("descriptive:scrape_limit")
        return {"status": status, "base64": base64.b64encode(body).decode()}
    raise ValueError("descriptive:client_control")


def serve(root=DATA):
    root.mkdir(exist_ok=True)
    credential = json.loads(Path("/credential/client.json").read_bytes())
    namespace = os.environ["M5_NAMESPACE"]
    # Computed once. Subsequent commands cannot extend the original deadline.
    deadline = time.monotonic() + float(os.environ["M5_DEADLINE_EPOCH"]) - time.time()
    ports = SimpleNamespace(
        output=root,
        namespace=namespace,
        deadline=deadline,
        client_url=f"https://streaming-ingress.{namespace}.svc:8443",
        credential=credential["token"],
        tenant_id=credential["tenant_id"],
        model=credential["model"],
        corpus=credential.get("corpus") or build_corpus(),
        tls_context=ssl.create_default_context(cafile="/ca/tls.crt"),
        metrics_endpoints=(("gateway", "http://gateway:8080"),),
    )
    (root / "ready").touch()
    while time.monotonic() < deadline:
        for path in sorted(root.glob("*.task")):
            destination = path.with_suffix(".result")
            if destination.exists():
                continue
            try:
                value = {"status": "PASS", "result": run_task(json.loads(path.read_bytes()), ports)}
            except Exception as error:
                value = {"status": "FAILED", "error": type(error).__name__ + ":" + str(error)}
            pending = destination.with_suffix(".pending")
            pending.write_text(json.dumps(value))
            pending.rename(destination)
        time.sleep(0.1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "mode", choices=("serve", "submit", "status", "inventory", "read", "observe")
    )
    parser.add_argument("arguments", nargs="*")
    args = parser.parse_args()
    if args.mode == "serve":
        serve()
    else:
        print(json.dumps(control(DATA, args.mode, args.arguments)))


if __name__ == "__main__":
    main()
