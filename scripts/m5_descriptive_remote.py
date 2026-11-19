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
import sys
import time
from pathlib import Path

from inference_platform import kind_rollout
from inference_platform.eks_deployment import MODEL, REVISION, VLLM_IMAGE
from inference_platform.m5_descriptive import resources
from inference_platform.m5_descriptive_client import pushed_digest
from inference_platform.m5_descriptive_cluster import ClusterPorts
from inference_platform.m5_descriptive_operator import phase_deadline
from inference_platform.command_diagnostics import checked_process, stderr_tail

ROOT = Path(__file__).resolve().parents[1]


STATE_FIELDS = (
    "client_pod",
    "client_placement",
    "client_image",
    "results",
    "replacements",
    "owned",
    "registry_owned",
    "backstop_armed",
)


def resolve_tool_paths(campaign):
    """Rebind every new process to bootstrap's existing pinned files; no download."""
    import hashlib

    system = "windows" if os.name == "nt" else "linux"
    suffix = ".exe" if os.name == "nt" else ""
    for name in ("kind", "kubectl"):
        path = campaign.tools / (name + suffix)
        expected = campaign.pins[f"{name}_{system}_amd64_sha256"]
        if (
            not path.is_file()
            or hashlib.sha256(path.read_bytes()).hexdigest() != expected
        ):
            raise ValueError("descriptive:pinned_tool_missing_or_changed:" + name)
        setattr(campaign, name, path)


class EKSClusterPorts(ClusterPorts):
    substitutions = []

    def __init__(self, output, manifest):
        self.output = Path(output)
        self.output.mkdir(parents=True, exist_ok=True)
        self.binding = manifest["descriptive"]
        self.namespace = "mti-" + self.binding["session"]
        self.cluster = self.binding["session"]
        self.context = self.binding.get("kubernetes_context", self.cluster)
        self.kubeconfig = self.output / "kubeconfig"
        self.timing = self.binding["timing"]
        if "original_deadline_epoch" not in self.binding:
            raise ValueError("descriptive:original_deadline_missing")
        self.original_end = self.binding["original_deadline_epoch"]
        if manifest["deadline_epoch"] != phase_deadline(
            self.original_end, self.timing, "provision"
        ):
            raise ValueError("descriptive:host_work_deadline_mismatch")
        self.campaign = kind_rollout.Campaign(self.output)
        resolve_tool_paths(self.campaign)
        self.deadline_epoch = phase_deadline(self.original_end, self.timing, "retrieve")
        self.work_deadline_epoch = phase_deadline(
            self.original_end, self.timing, "load"
        )
        self.deadline = time.monotonic() + self.work_deadline_epoch - time.time()
        self.startup_seconds = self.binding["startup_seconds"]
        self.warmup_duration = self.binding.get("warmup_seconds", 120)
        self.load_duration = self.binding.get("load_seconds", 600)
        self.rollout_durations = {
            "gateway": self.timing["gateway_rollout_seconds"],
            "vllm": self.timing["vllm_rollout_seconds"],
        }
        self.rollout_duration = max(self.rollout_durations.values())
        self.rollout_action = self.timing["rollout_action_seconds"]
        self.minimum_workload_seconds = self.timing["minimum_workload_seconds"]
        self.corpus = None
        self.model = self.binding.get("model", MODEL)
        self.tenant_id = self.binding.get("tenant_id", "m5-descriptive")
        credential = self.output / "credential.secret"
        if not credential.exists():
            with credential.open("x") as handle:
                handle.write(secrets.token_urlsafe(32))
            credential.chmod(0o600)
        self.credential = credential.read_text()
        self.owned = self.registry_owned = self.backstop_armed = False
        self.replacements = {}
        state = self.output / "state.json"
        stored = json.loads(state.read_bytes()) if state.exists() else {}
        for name in STATE_FIELDS:
            if name in stored:
                setattr(self, name, stored[name])
        self.results = stored.get("results", {})
        self.commands, self.forwarders = [], []

    def save(self):
        path = self.output / "state.json"
        previous = json.loads(path.read_bytes()) if path.exists() else {}
        data = {name: previous[name] for name in STATE_FIELDS if name in previous}
        data.update(
            {name: getattr(self, name) for name in STATE_FIELDS if hasattr(self, name)}
        )
        path.write_text(json.dumps(data))

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
        checked_process(
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
            secrets=(password,),
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
        started = time.monotonic()
        script = (ROOT / "scripts/m5_descriptive_model.py").read_text()
        self.k(
            "create", "configmap", "model-stager", "--from-literal=stage.py=" + script
        )
        pod = {
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
                        # The pinned downloader exceeded 4Gi in the real
                        # two-node rehearsal. Staging precedes serving; reuse
                        # the serving pod's existing memory envelope.
                        "requests": {"cpu": "1", "memory": "8Gi"},
                        "limits": {"cpu": "2", "memory": "12Gi"},
                    },
                    "terminationMessagePolicy": "FallbackToLogsOnError",
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
        remaining = int(self.work_deadline_epoch - time.time())
        if remaining <= 0:
            raise TimeoutError("descriptive:model_work_deadline")
        # A brand-new DaemonSet can report desired=ready=0 before its controller
        # observes it; rollout status alone treats that transient state as done.
        stager_end = min(self.work_deadline_epoch, time.time() + 2700)
        self.k(
            "wait",
            "--for=jsonpath={.status.desiredNumberScheduled}=2",
            "daemonset/model-stager",
            f"--timeout={min(2700, remaining)}s",
        )
        remaining = int(stager_end - time.time())
        if remaining <= 0:
            raise TimeoutError("descriptive:model_work_deadline")
        self.k(
            "rollout",
            "status",
            "daemonset/model-stager",
            f"--timeout={min(2700, remaining)}s",
        )
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
        ended = time.monotonic()
        self.results["model_staging"] = {
            "start_monotonic": started,
            "end_monotonic": ended,
            "elapsed_s": ended - started,
            "pods": [
                {"pod": p["metadata"]["name"], "node": p["spec"]["nodeName"]}
                for p in pods
            ],
            "inventories": inventories,
            "rollout_timeout_s": min(2700, remaining),
            "hashes_match": True,
        }
        self.k("delete", "daemonset/model-stager", "--wait=true")
        self.k("delete", "configmap/model-stager")
        return inventories[0]

    def provision(self):
        import boto3

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
    from inference_platform.m5_payload_guard import install_read_guard

    install_read_guard(ROOT, manifest["source_payload"]["paths"])
    # Secrets/kubeconfig never enter the host agent's archive walk, even when
    # a phase fails before export. Only explicitly frozen files are copied out.
    ports = EKSClusterPorts(Path("/opt/dec077/descriptive-private"), manifest)
    receipts = Path("/opt/dec077/results/runner/descriptive")
    receipts.mkdir(exist_ok=True)
    ports.phase_logs = receipts
    from package_a_host import host_environment

    ports.results.setdefault("phase_processes", {})[args.phase] = {
        "pid": os.getpid(),
        "original_deadline_epoch": ports.original_end,
        "host_work_deadline_epoch": manifest["deadline_epoch"],
        "work_deadline_epoch": ports.work_deadline_epoch,
        "phase_start_epoch": time.time(),
        "environment": {name: os.environ.get(name) for name in host_environment()},
    }
    remaining = (
        phase_deadline(ports.original_end, ports.timing, args.phase) - time.time()
    )
    if remaining <= 0:
        raise TimeoutError("descriptive:retrieval_cleanup_reserve")
    # SSM returns only the small result, not 24KiB of the beginning of a Docker
    # build. Real subprocess output stays in frozen host logs.
    sys.stdout.flush()
    sys.stderr.flush()
    original_stdout, original_stderr = os.dup(1), os.dup(2)
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
        except Exception as error:
            print(
                stderr_tail(
                    type(error).__name__ + ":" + str(error), secrets=(ports.credential,)
                ),
                file=sys.stderr,
                flush=True,
            )
            raise
        finally:
            try:
                ports.save()
            finally:
                sys.stdout.flush()
                sys.stderr.flush()
                os.dup2(original_stdout, 1)
                os.dup2(original_stderr, 2)
                os.close(original_stdout)
                os.close(original_stderr)
    encoded = json.dumps(result, sort_keys=True)
    (receipts / (args.phase + ".json")).write_text(encoded)
    if args.phase == "retrieve":
        for name in ("frozen", "retrieved"):
            shutil.copytree(ports.output / name, receipts / name)
    print("DESCRIPTIVE_PHASE_RESULT=" + encoded)


if __name__ == "__main__":
    main()
