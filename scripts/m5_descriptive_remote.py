"""Package A operator host operations; every Kubernetes phase is ClusterPorts.

Invoked by bounded SSM commands under the locked venv after Package A bootstrap.
No provisioning or approval occurs here; original deadlines arrive in the bound
runtime manifest. Kubernetes client traffic remains entirely in its CPU Job.
"""

import argparse
import base64
import copy
import json
import os
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path

from inference_platform import kind_rollout
from inference_platform.eks_deployment import MODEL, REVISION, VLLM_IMAGE
from inference_platform.m5_descriptive import resources
from inference_platform.m5_descriptive_client import pushed_digest
from inference_platform.m5_descriptive_cluster import ClusterPorts
from inference_platform.m5_descriptive_operator import phase_deadline

ROOT = Path(__file__).resolve().parents[1]


class EKSClusterPorts(ClusterPorts):
    substitutions = []

    def __init__(self, output, manifest):
        self.output = Path(output)
        self.output.mkdir(parents=True, exist_ok=True)
        self.binding = manifest["descriptive"]
        self.namespace = "mti-" + self.binding["session"]
        self.cluster = self.binding["session"]
        self.context = self.cluster
        self.kubeconfig = self.output / "kubeconfig"
        self.campaign = kind_rollout.Campaign(self.output)
        self.timing = self.binding["timing"]
        self.original_end = manifest["deadline_epoch"]
        self.deadline_epoch = phase_deadline(self.original_end, self.timing, "retrieve")
        self.work_deadline_epoch = phase_deadline(
            self.original_end, self.timing, "load"
        )
        self.deadline = time.monotonic() + self.work_deadline_epoch - time.time()
        self.startup_seconds = self.binding["startup_seconds"]
        self.warmup_duration, self.load_duration = 120, 600
        self.rollout_duration, self.rollout_action = self.timing["rollout_seconds"], 120
        self.corpus = None
        self.model, self.tenant_id = MODEL, "m5-descriptive"
        credential = self.output / "credential.secret"
        if not credential.exists():
            with credential.open("x") as handle:
                handle.write(secrets.token_urlsafe(32))
            credential.chmod(0o600)
        self.credential = credential.read_text()
        state = self.output / "state.json"
        stored = json.loads(state.read_bytes()) if state.exists() else {}
        for name in ("client_pod", "client_placement", "client_image"):
            if name in stored:
                setattr(self, name, stored[name])
        self.results = stored.get("results", {})
        self.commands, self.forwarders = [], []

    def save(self):
        (self.output / "state.json").write_text(
            json.dumps(
                {
                    **{
                        name: getattr(self, name)
                        for name in ("client_pod", "client_placement", "client_image")
                        if hasattr(self, name)
                    },
                    "results": self.results,
                }
            )
        )

    def render_manifest(self, source):
        result = copy.deepcopy(source)
        vllm = next(
            o
            for o in result["items"]
            if o["kind"] == "StatefulSet" and o["metadata"]["name"] == "vllm"
        )
        # Same argv and spawn setting as Round 281; only this explicitly
        # declared cache-only preparation difference is added after parity.
        vllm["spec"]["template"]["spec"]["containers"][0]["env"].append(
            {"name": "HF_HUB_OFFLINE", "value": "1"}
        )
        vllm["spec"]["template"]["spec"]["containers"][0]["startupProbe"][
            "failureThreshold"
        ] = self.startup_seconds
        return result

    def images(self):
        import boto3

        self.campaign.build()
        repository = self.binding["repository_url"]
        auth = boto3.client("ecr", region_name="us-east-1").get_authorization_token()[
            "authorizationData"
        ][0]
        user, password = (
            base64.b64decode(auth["authorizationToken"]).decode().split(":", 1)
        )
        subprocess.run(
            [
                "docker",
                "login",
                "--username",
                user,
                "--password-stdin",
                repository.split("/")[0],
            ],
            input=password.encode(),
            check=True,
            capture_output=True,
            timeout=30,
        )
        result = {}
        try:
            for role, source in (
                ("gateway", "mti-gateway:stage1"),
                ("client", "mti-fake:stage1"),
            ):
                tag = f"{repository}:{role}-{self.binding['source_commit']}"
                self.call(["docker", "tag", source, tag])
                self.call(["docker", "push", tag], timeout=900)
                result[role] = pushed_digest(
                    json.loads(self.call(["docker", "image", "inspect", tag]))[0],
                    repository,
                )
        finally:
            self.call(["docker", "logout", repository.split("/")[0]])
        self.client_image = result["client"]
        return result

    def stage_model(self):
        script = (ROOT / "scripts/m5_descriptive_model.py").read_text()
        self.k(
            "create", "configmap", "model-stager", "--from-literal=stage.py=" + script
        )
        pod = {
            "activeDeadlineSeconds": max(
                1, int(self.work_deadline_epoch - time.time())
            ),
            "nodeSelector": {"m5-role": "gpu"},
            "automountServiceAccountToken": False,
            "tolerations": [
                {"key": "nvidia.com/gpu", "operator": "Exists", "effect": "NoSchedule"}
            ],
            "containers": [
                {
                    "name": "stage",
                    "image": VLLM_IMAGE,
                    "command": [
                        "python3",
                        "/stage/stage.py",
                        MODEL,
                        REVISION,
                        "/model/hub",
                        "/evidence/manifest.json",
                    ],
                    "resources": {
                        "requests": {"cpu": "1", "memory": "1Gi"},
                        "limits": {"cpu": "2", "memory": "4Gi"},
                    },
                    "readinessProbe": {
                        "exec": {"command": ["test", "-f", "/evidence/ready"]},
                        "periodSeconds": 2,
                    },
                    "volumeMounts": [
                        {"name": "script", "mountPath": "/stage", "readOnly": True},
                        {"name": "model", "mountPath": "/model"},
                        {"name": "evidence", "mountPath": "/evidence"},
                    ],
                }
            ],
            "volumes": [
                {"name": "script", "configMap": {"name": "model-stager"}},
                {
                    "name": "model",
                    "hostPath": {
                        "path": "/var/cache/mti-m5/models",
                        "type": "DirectoryOrCreate",
                    },
                },
                {"name": "evidence", "emptyDir": {}},
            ],
        }
        manifest = {
            "apiVersion": "apps/v1",
            "kind": "DaemonSet",
            "metadata": {"name": "model-stager", "namespace": self.namespace},
            "spec": {
                "selector": {"matchLabels": {"app": "model-stager"}},
                "template": {
                    "metadata": {"labels": {"app": "model-stager"}},
                    "spec": pod,
                },
            },
        }
        path = self.output / "model-stager.json"
        path.write_text(json.dumps(manifest))
        self.k("apply", "-f", path)
        self.k("rollout", "status", "daemonset/model-stager", "--timeout=2700s")
        pods = json.loads(
            self.k("get", "pods", "-l", "app=model-stager", "-o", "json")
        )["items"]
        if len(pods) != 2 or len({p["spec"]["nodeName"] for p in pods}) != 2:
            raise ValueError("descriptive:model_two_nodes")
        inventories = [
            json.loads(
                self.k(
                    "exec",
                    p["metadata"]["name"],
                    "--",
                    "cat",
                    "/evidence/manifest.json",
                )
            )
            for p in pods
        ]
        if inventories[0] != inventories[1]:
            raise ValueError("descriptive:model_node_hash_mismatch")
        self.k("delete", "daemonset/model-stager", "--wait=true")
        self.k("delete", "configmap/model-stager")
        return inventories[0]

    def provision(self):
        import boto3

        self.campaign.install_tools()
        self.call(["systemctl", "start", "docker"])
        cluster = boto3.client("eks", region_name="us-east-1").describe_cluster(
            name=self.cluster
        )["cluster"]
        self.kubeconfig.write_text(
            json.dumps(
                {
                    "apiVersion": "v1",
                    "kind": "Config",
                    "clusters": [
                        {
                            "name": self.cluster,
                            "cluster": {
                                "server": cluster["endpoint"],
                                "certificate-authority-data": cluster[
                                    "certificateAuthority"
                                ]["data"],
                            },
                        }
                    ],
                    "contexts": [
                        {
                            "name": self.context,
                            "context": {"cluster": self.cluster, "user": "operator"},
                        }
                    ],
                    "current-context": self.context,
                    "users": [
                        {
                            "name": "operator",
                            "user": {
                                "exec": {
                                    "apiVersion": "client.authentication.k8s.io/v1",
                                    "interactiveMode": "Never",
                                    "command": sys.executable,
                                    "args": [
                                        str(ROOT / "scripts/m5_eks_token.py"),
                                        self.cluster,
                                    ],
                                }
                            },
                        }
                    ],
                }
            )
        )
        namespace = self.output / "namespace.json"
        namespace.write_text(
            json.dumps(
                {
                    "apiVersion": "v1",
                    "kind": "Namespace",
                    "metadata": {"name": self.namespace},
                }
            )
        )
        self.k("apply", "-f", namespace)
        self.k("wait", "--for=condition=Ready", "nodes", "--all", "--timeout=600s")
        images = self.images()
        self.results["model"] = self.stage_model()
        result = self.deploy(resources(self.namespace, images["gateway"]))
        # ECR account/repository names remain private. Frozen evidence keeps only
        # digest identities and file hashes; raw SDK/SSM receipts are not public.
        result["images"] = {
            role: image.split("@")[-1] for role, image in images.items()
        }
        result["model"] = self.results["model"]
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "phase",
        choices=(
            "provision",
            "smoke",
            "load",
            "gateway_rollout",
            "replica_rollout",
            "export",
            "retrieve",
        ),
    )
    args = parser.parse_args()
    manifest = json.loads(Path("/opt/dec077/runtime.json").read_bytes())
    # Secrets/kubeconfig never enter the host agent's archive walk, even when
    # a phase fails before export. Only explicitly frozen files are copied out.
    ports = EKSClusterPorts(Path("/opt/dec077/descriptive-private"), manifest)
    receipts = Path("/opt/dec077/results/runner/descriptive")
    receipts.mkdir(exist_ok=True)
    remaining = (
        phase_deadline(ports.original_end, ports.timing, args.phase) - time.time()
    )
    if remaining <= 0:
        raise TimeoutError("descriptive:retrieval_cleanup_reserve")
    # SSM returns only the small result, not 24KiB of the beginning of a Docker
    # build. Real subprocess output stays in frozen host logs.
    sys.stdout.flush()
    sys.stderr.flush()
    original = os.dup(1)
    with (receipts / (args.phase + ".log")).open("ab") as log:
        os.dup2(log.fileno(), 1)
        os.dup2(log.fileno(), 2)
        try:
            if args.phase in {"gateway_rollout", "replica_rollout"}:
                result = ports.rollout(
                    "gateway" if args.phase == "gateway_rollout" else "vllm"
                )
            elif args.phase == "load":
                result = ports.load((1, 4, 16))
            else:
                result = getattr(ports, args.phase)()
        finally:
            sys.stdout.flush()
            sys.stderr.flush()
            os.dup2(original, 1)
            os.dup2(original, 2)
            os.close(original)
    ports.save()
    encoded = json.dumps(result, sort_keys=True)
    (receipts / (args.phase + ".json")).write_text(encoded)
    if args.phase == "retrieve":
        for name in ("frozen", "retrieved"):
            shutil.copytree(ports.output / name, receipts / name)
    print("DESCRIPTIVE_PHASE_RESULT=" + encoded)


if __name__ == "__main__":
    main()
