"""Real 1.35 API serialization fixture; no scheduler, kubelet or EKS claim."""

import copy
import json
import subprocess
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

from inference_platform.eks_deployment import resources
from inference_platform.inf037b_archive import sha
from inference_platform.inf037b_capture import DeadlineHTTP
from inference_platform.inf037b_eks_placement import PlacementAPI

APISERVER = "registry.k8s.io/kube-apiserver:v1.35.0@sha256:32f98b308862e1cf98c900927d84630fb86a836a480f02752a779eb85c1489f3"
ETCD = "registry.k8s.io/etcd:3.6.6-0@sha256:60a30b5d81b2217555e2cfb9537f655b7ba97220b99c39ee2e162a7127225890"
ROOT = Path(__file__).resolve().parents[1]


def command(argv):
    return subprocess.check_output(argv, stderr=subprocess.STDOUT, timeout=180)


def periodic_objects():
    """Use the registered two-slot Pod template, not a shortened API body."""
    model = {"fixture.safetensors": {"sha256": "a" * 64, "bytes": 1}}
    inputs = {
        "namespace": "mti-m5-purpose",
        "gateway_image": "fixture.invalid/gateway@sha256:" + "a" * 64,
        "config_sha256": "a" * 64,
        "tls_secret": "gateway-tls",
        "operator_cidrs": ["192.0.2.0/24"],
        "crictl_host_path": "/usr/bin/crictl",
        "crictl_sha256": "a" * 64,
        "model_manifest": model,
        "model_manifest_sha256": sha(
            json.dumps(model, sort_keys=True, separators=(",", ":")).encode()
        ),
        "r": 4,
        "w": 1,
    }
    objects = resources(inputs, (ROOT / "deploy/eks/capture_runtime.py").read_text())
    if isinstance(objects, dict):
        objects = objects["items"]
    serving = next(
        o
        for o in objects
        if o["kind"] == "StatefulSet" and o["metadata"]["name"] == "vllm"
    )
    result = []
    for slot in range(2):
        template = copy.deepcopy(serving["spec"]["template"])
        template["metadata"].update(
            name="vllm-" + str(slot), namespace=inputs["namespace"]
        )
        template["spec"]["nodeName"] = "purpose-gpu-" + str(slot)
        for claim in serving["spec"].get("volumeClaimTemplates", []):
            template["spec"].setdefault("volumes", []).append(
                {
                    "name": claim["metadata"]["name"],
                    "persistentVolumeClaim": {
                        "claimName": claim["metadata"]["name"] + "-vllm-" + str(slot)
                    },
                }
            )
        result.append({"apiVersion": "v1", "kind": "Pod", **template})
    return serving, result


@contextmanager
def kubernetes(retain, diagnostics):
    suffix = str(time.monotonic_ns())
    names = ["purpose-etcd-" + suffix, "purpose-api-" + suffix]
    with tempfile.TemporaryDirectory(prefix="purpose-kube-") as folder:
        config = Path(folder)
        try:
            command(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-days",
                    "1",
                    "-subj",
                    "/CN=purpose-api",
                    "-addext",
                    "subjectAltName=IP:127.0.0.1",
                    "-keyout",
                    str(config / "key.pem"),
                    "-out",
                    str(config / "cert.pem"),
                ]
            )
            token = "purpose-local-fixture"
            (config / "tokens.csv").write_text(
                token + ",purpose,purpose,system:masters\n"
            )
            command(["docker", "pull", ETCD])
            command(["docker", "pull", APISERVER])
            command(
                [
                    "docker",
                    "run",
                    "--rm",
                    "-d",
                    "--name",
                    names[0],
                    "--network",
                    "host",
                    "--entrypoint",
                    "/usr/local/bin/etcd",
                    ETCD,
                    "--listen-client-urls=http://127.0.0.1:12379",
                    "--advertise-client-urls=http://127.0.0.1:12379",
                    "--listen-peer-urls=http://127.0.0.1:12380",
                    "--initial-advertise-peer-urls=http://127.0.0.1:12380",
                    "--initial-cluster=default=http://127.0.0.1:12380",
                    "--data-dir=/tmp/etcd",
                ]
            )
            command(
                [
                    "docker",
                    "run",
                    "--rm",
                    "-d",
                    "--name",
                    names[1],
                    "--network",
                    "host",
                    "--mount",
                    f"type=bind,source={config},target=/config,readonly",
                    "--user",
                    "0:0",
                    "--entrypoint",
                    "/usr/local/bin/kube-apiserver",
                    APISERVER,
                    "--bind-address=127.0.0.1",
                    "--advertise-address=127.0.0.1",
                    "--secure-port=16443",
                    "--etcd-servers=http://127.0.0.1:12379",
                    "--service-cluster-ip-range=10.43.0.0/24",
                    "--tls-cert-file=/config/cert.pem",
                    "--tls-private-key-file=/config/key.pem",
                    "--service-account-issuer=https://kubernetes.default.svc",
                    "--service-account-signing-key-file=/config/key.pem",
                    "--service-account-key-file=/config/cert.pem",
                    "--token-auth-file=/config/tokens.csv",
                    "--authorization-mode=AlwaysAllow",
                ]
            )
            until = time.monotonic_ns() + 120000000000
            # Bootstrap readiness precedes the booked capture window. Failed
            # readiness polls are not failed measurements in the wire owner.
            http = DeadlineHTTP(
                "https://127.0.0.1:16443",
                stop_ns=until,
                retain=lambda *args: None,
                token=lambda: token,
                ca=str(config / "cert.pem"),
            )
            while True:
                try:
                    if http.get("/readyz")[0].strip() == b"ok":
                        break
                except (OSError, ValueError):
                    if time.monotonic_ns() >= until:
                        raise
                time.sleep(0.25)
            version = json.loads(http.get("/version")[0])
            if version["gitVersion"] != "v1.35.0":
                raise ValueError("purpose:kubernetes_version")
            api = PlacementAPI(
                "https://127.0.0.1:16443",
                token=lambda: token,
                ca=str(config / "cert.pem"),
                clock=lambda: time.monotonic_ns() // 1000000,
                retain=retain,
            )
            stop = time.monotonic_ns() // 1000000 + 60000
            ns = "mti-m5-purpose"
            api.request(
                "POST",
                "/api/v1/namespaces",
                stop,
                {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": ns}},
            )
            controller, pods = periodic_objects()
            saved_controller = api.request(
                "POST", f"/apis/apps/v1/namespaces/{ns}/statefulsets", stop, controller
            )
            for account in sorted(
                {
                    "default",
                    *(p["spec"].get("serviceAccountName", "default") for p in pods),
                }
            ):
                api.request(
                    "POST",
                    f"/api/v1/namespaces/{ns}/serviceaccounts",
                    stop,
                    {
                        "apiVersion": "v1",
                        "kind": "ServiceAccount",
                        "metadata": {"name": account},
                    },
                )
            seeded = []
            for slot, pod in enumerate(pods):
                pod["metadata"]["ownerReferences"] = [
                    {
                        "apiVersion": "apps/v1",
                        "kind": "StatefulSet",
                        "name": "vllm",
                        "uid": saved_controller["metadata"]["uid"],
                        "controller": True,
                        "blockOwnerDeletion": True,
                    }
                ]
                saved = api.request("POST", f"/api/v1/namespaces/{ns}/pods", stop, pod)
                seeded.append(
                    {
                        "kind": "Pod",
                        "name": saved["metadata"]["name"],
                        "uid": saved["metadata"]["uid"],
                    }
                )
                endpoint = {
                    "apiVersion": "discovery.k8s.io/v1",
                    "kind": "EndpointSlice",
                    "metadata": {
                        "name": "vllm-purpose-" + str(slot),
                        "namespace": ns,
                        "labels": {"kubernetes.io/service-name": "vllm"},
                    },
                    "addressType": "IPv4",
                    "ports": [{"name": "http", "port": 8000, "protocol": "TCP"}],
                    "endpoints": [
                        {
                            "addresses": ["192.0.2." + str(10 + slot)],
                            "conditions": {
                                "ready": True,
                                "serving": True,
                                "terminating": False,
                            },
                            "targetRef": {
                                "kind": "Pod",
                                "namespace": ns,
                                "name": saved["metadata"]["name"],
                                "uid": saved["metadata"]["uid"],
                            },
                        }
                    ],
                }
                saved = api.request(
                    "POST",
                    f"/apis/discovery.k8s.io/v1/namespaces/{ns}/endpointslices",
                    stop,
                    endpoint,
                )
                seeded.append(
                    {
                        "kind": "EndpointSlice",
                        "name": saved["metadata"]["name"],
                        "uid": saved["metadata"]["uid"],
                    }
                )
            yield {
                "base": "https://127.0.0.1:16443",
                "ca": str(config / "cert.pem"),
                "token": token,
                "version": version["gitVersion"],
                "objects": seeded,
                "paths": [
                    f"/api/v1/namespaces/{ns}/pods?labelSelector=app%3Dvllm",
                    f"/apis/discovery.k8s.io/v1/namespaces/{ns}/endpointslices?labelSelector=kubernetes.io%2Fservice-name%3Dvllm",
                ],
            }
        finally:
            Path(diagnostics).mkdir(parents=True, exist_ok=True)
            for name in reversed(names):
                logs = subprocess.run(
                    ["docker", "logs", name],
                    capture_output=True,
                    timeout=30,
                    check=False,
                )
                (
                    Path(diagnostics)
                    / ("apiserver.log" if name == names[1] else "etcd.log")
                ).write_bytes(logs.stdout + logs.stderr)
                subprocess.run(
                    ["docker", "rm", "-f", "-v", name],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=30,
                    check=False,
                )
