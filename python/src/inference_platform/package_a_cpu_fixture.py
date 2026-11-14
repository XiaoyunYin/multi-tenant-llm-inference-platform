"""Owned kind API fixtures for CPU validation; no host-RAM sizing inputs."""

import copy
import json
import subprocess
import time
from pathlib import Path

from .inf037b_eks_placement import GATE, effective_memory
from .inf037b_placement import ISOLATION_POLICY, MEMORY_BYTES, quantity_bytes
from .package_a_cloud import save

NAMESPACE = "package-a-cpu-validation"


class KubectlAPI:
    def __init__(self, kubeconfig):
        self.argv = [".tools/kubectl", "--kubeconfig", str(kubeconfig)]

    def request(self, method, path, body=None):
        command = {"GET": "get", "POST": "create", "PUT": "replace", "PATCH": "patch"}[method]
        argv = [*self.argv, command, "--raw", path]
        if body is not None:
            argv.extend(["-f", "-"])
        return json.loads(
            subprocess.check_output(
                argv, input=None if body is None else json.dumps(body).encode(), timeout=60
            )
        )


def produce(api, directory, *, api_binding, boot_id, image, wait=time.sleep):
    """All node capacity, requests, UIDs and defaulted Pods come from this API."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    nodes = [
        n
        for n in api.request("GET", "/api/v1/nodes")["items"]
        if "node-role.kubernetes.io/control-plane" not in n["metadata"]["labels"]
    ]
    nodes.sort(key=lambda n: n["metadata"]["name"])
    if len(nodes) != 2:
        raise ValueError("cpu_fixture:two_workers_required")
    api.request(
        "POST",
        "/api/v1/namespaces",
        {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": NAMESPACE}},
    )
    cm = api.request(
        "POST",
        f"/api/v1/namespaces/{NAMESPACE}/configmaps",
        {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "conditional"},
            "data": {"probe": "initial"},
        },
    )
    if not cm["metadata"].get("uid"):
        raise ValueError("cpu_fixture:configmap_uid")
    identities, fillers = {}, []
    for index, node in enumerate(nodes):
        name = node["metadata"]["name"]
        identities[name] = {"name": name, "uid": node["metadata"]["uid"]}
        # Existing system Pods are explicitly labelled, without changing resources.
        pods = api.request("GET", "/api/v1/pods?fieldSelector=spec.nodeName%3D" + name)["items"]
        requested = 0
        for pod in pods:
            requested += effective_memory(pod["spec"], pod.get("status"))
            pod = copy.deepcopy(pod)
            pod["metadata"].setdefault("labels", {})["inf037b-role"] = "system"
            api.request(
                "PUT",
                f"/api/v1/namespaces/{pod['metadata']['namespace']}/pods/"
                + pod["metadata"]["name"],
                pod,
            )
        residual = MEMORY_BYTES - index
        filler = quantity_bytes(node["status"]["allocatable"]["memory"]) - requested - residual
        if filler < 0:
            raise ValueError("cpu_fixture:allocatable_below_required_residual")
        api.request(
            "POST",
            f"/api/v1/namespaces/{NAMESPACE}/pods",
            {
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {"name": f"filler-{index}", "labels": {"inf037b-role": "system"}},
                "spec": {
                    "nodeName": name,
                    "containers": [
                        {
                            "name": "hold",
                            "image": image,
                            "command": ["sh", "-c", "sleep 18000"],
                            "resources": {"requests": {"memory": str(filler)}},
                        }
                    ],
                },
            },
        )
        fillers.append(
            {
                "node": identities[name],
                "allocatable_bytes": quantity_bytes(node["status"]["allocatable"]["memory"]),
                "existing_requests_bytes": requested,
                "filler_bytes": filler,
                "residual_bytes": residual,
            }
        )
    cases = {}
    for label in ("fit", "short", "release", "conflict"):
        node = nodes[int(label == "short")]
        name = node["metadata"]["name"]
        api.request(
            "POST",
            f"/apis/batch/v1/namespaces/{NAMESPACE}/jobs",
            {
                "apiVersion": "batch/v1",
                "kind": "Job",
                "metadata": {"name": label},
                "spec": {
                    "backoffLimit": 0,
                    "template": {
                        "metadata": {"labels": {"inf037b-role": "export"}},
                        "spec": {
                            "restartPolicy": "Never",
                            "schedulingGates": [{"name": GATE}],
                            "nodeSelector": {"kubernetes.io/hostname": name},
                            "affinity": {
                                "podAntiAffinity": {
                                    "requiredDuringSchedulingIgnoredDuringExecution": ISOLATION_POLICY
                                }
                            },
                            "containers": [
                                {
                                    "name": "export",
                                    "image": image,
                                    "command": ["sh", "-c", "sleep 18000"],
                                    "resources": {
                                        "requests": {"memory": "12Gi"},
                                        "limits": {"memory": "12Gi"},
                                    },
                                }
                            ],
                        },
                    },
                },
            },
        )
        stop = time.monotonic() + 60
        while True:
            pods = api.request(
                "GET", f"/api/v1/namespaces/{NAMESPACE}/pods?" + "labelSelector=job-name%3D" + label
            )["items"]
            if len(pods) == 1:
                pod = pods[0]
                if pod["spec"].get("nodeName") or pod["spec"].get("schedulingGates") != [
                    {"name": GATE}
                ]:
                    raise ValueError("cpu_fixture:pod_not_held")
                cases[label] = {
                    "namespace": NAMESPACE,
                    "job": label,
                    "pod": pod["metadata"]["name"],
                    "node": identities[name],
                }
                break
            if time.monotonic() >= stop:
                raise ValueError("cpu_fixture:pod_deadline")
            wait(0.1)
    placement = {"api": api_binding, "boot_id": boot_id, "cases": cases}
    cluster = {
        "api": api_binding,
        "nodes": identities,
        "conditional_configmap_path": f"/api/v1/namespaces/{NAMESPACE}/configmaps/conditional",
    }
    save(directory / "placement.json", placement)
    save(directory / "cluster.json", cluster)
    save(
        directory / "capacity.json",
        {"fillers": fillers, "source": "real API allocatable and effective requests"},
    )
    return placement, cluster


def main():
    import argparse
    import base64

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kubeconfig", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--image", required=True)
    args = parser.parse_args()
    api = KubectlAPI(args.kubeconfig)
    kube = json.loads(
        subprocess.check_output(
            [*api.argv, "config", "view", "--raw", "--minify", "-o", "json"], timeout=30
        )
    )
    args.output.mkdir(parents=True, exist_ok=True)
    ca = args.output / "ca.crt"
    ca.write_bytes(base64.b64decode(kube["clusters"][0]["cluster"]["certificate-authority-data"]))
    # A dedicated token is needed because PlacementAPI intentionally uses bearer TLS.
    subprocess.check_call(
        [*api.argv, "create", "serviceaccount", "cpu-validation", "-n", "default"], timeout=30
    )
    subprocess.check_call(
        [
            *api.argv,
            "create",
            "clusterrolebinding",
            "cpu-validation",
            "--clusterrole=cluster-admin",
            "--serviceaccount=default:cpu-validation",
        ],
        timeout=30,
    )
    token = args.output / "token.secret"
    token.write_bytes(
        subprocess.check_output(
            [*api.argv, "create", "token", "cpu-validation", "-n", "default", "--duration=6h"],
            timeout=30,
        )
    )
    token.chmod(0o600)
    produce(
        api,
        args.output,
        api_binding={
            "base": kube["clusters"][0]["cluster"]["server"],
            "token_file": str(token),
            "ca": str(ca),
        },
        boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        image=args.image,
    )


if __name__ == "__main__":
    main()
