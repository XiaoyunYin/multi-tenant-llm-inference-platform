"""DEC-100 CPU rehearsal on a disposable routine AWS host; never calls AWS/EKS."""

import argparse
import copy
import json
import os
import shutil
import hashlib
import shlex
import subprocess
import time
import tomllib
from pathlib import Path

from inference_platform import kind_rollout
from inference_platform.eks_deployment import NGINX_IMAGE, PROMETHEUS_IMAGE, REDIS_IMAGE
from inference_platform.m5_descriptive import resources
from inference_platform.m5_descriptive_client import pushed_digest
from inference_platform.m5_descriptive_cluster import ClusterPorts
from inference_platform.m5_descriptive_operator import execute
from inference_platform.package_a_images import save_amd64_archive

ROOT = Path(__file__).resolve().parents[1]
REGISTRY_IMAGE = "registry:3.0.0@sha256:6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e"
REGISTRY_HOSTS = (
    'server = "http://m5-descriptive-registry:5000"\n'
    '[host."http://m5-descriptive-registry:5000"]\n'
    '  capabilities = ["pull", "resolve"]\n'
)


def registry_configured(config):
    plugins = tomllib.loads(config).get("plugins", {})
    return any(
        "/etc/containerd/certs.d"
        in plugins.get(name, {}).get("registry", {}).get("config_path", "").split(":")
        for name in ("io.containerd.grpc.v1.cri", "io.containerd.cri.v1.images")
    )


def kind_config():
    return {
        "kind": "Cluster",
        "apiVersion": "kind.x-k8s.io/v1alpha4",
        "containerdConfigPatches": [
            '[plugins."io.containerd.grpc.v1.cri".registry]\n'
            '  config_path = "/etc/containerd/certs.d"\n'
        ],
        "nodes": [
            {"role": "control-plane", "labels": {"m5-role": "cpu"}},
            {"role": "worker", "labels": {"m5-role": "gpu"}},
            {"role": "worker", "labels": {"m5-role": "gpu"}},
        ],
    }


class KindPorts(ClusterPorts):
    substitutions = [
        "kind instead of EKS; provider-specific provisioning and teardown",
        "CPU FakeBackend instead of vLLM/GPU",
        "local image registry instead of ECR",
        "short load and rollout windows",
    ]

    def __init__(self, output):
        self.output = Path(output)
        self.output.mkdir()
        self.cluster, self.namespace = "m5-dec100", "mti-m5-descriptive"
        self.campaign = kind_rollout.Campaign(self.output)
        self.kubeconfig = self.output / "kubeconfig"
        self.forwarders = []
        self.deadline = time.monotonic() + 1800
        self.credential, self.tenant_id, self.model = (
            "local-dev-token",
            "tenant-local",
            "test-model",
        )
        self.commands, self.results = [], {}
        self.owned = False
        self.registry_owned = False
        self.backstop_armed = False
        self.context = "kind-" + self.cluster
        self.deadline_epoch = time.time() + 1800
        self.startup_seconds = 180
        self.warmup_duration, self.load_duration = 2, 3
        self.rollout_duration, self.rollout_action = 30, 2
        self.corpus = None

    def provision(self):
        self.campaign.install_tools()
        if (
            self.cluster
            in self.call([self.campaign.kind, "get", "clusters"]).splitlines()
        ):
            raise ValueError("descriptive:existing_cluster")
        registry = "m5-descriptive-registry"
        if self.call(
            ["docker", "ps", "-aq", "--filter", "name=^/" + registry + "$"]
        ).strip():
            raise ValueError("descriptive:existing_registry")
        callback = (
            "export PATH="
            + shlex.quote(os.environ["PATH"])
            + "; "
            + (
                shlex.join(
                    [
                        str(self.campaign.kind),
                        "delete",
                        "cluster",
                        "--name",
                        self.cluster,
                    ]
                )
                + "; "
                + shlex.join(
                    [shutil.which("docker"), "rm", "-fv", "m5-descriptive-registry"]
                )
            )
        )
        unit = "m5-descriptive-cleanup"
        self.call(
            [
                "systemd-run",
                "--unit=" + unit,
                "--on-calendar=@" + str(int(self.deadline_epoch)),
                "--timer-property=AccuracySec=1s",
                "/bin/sh",
                "-c",
                callback,
            ]
        )
        self.call(["systemctl", "is-active", "--quiet", unit + ".timer"])
        self.backstop_armed = True
        self.results["backstop"] = {
            "armed": True,
            "original_deadline_epoch": self.deadline_epoch,
            "provider": "kind substitution: host systemd instead of independent AWS EventBridge/Lambda",
            "unit": unit,
            "callback_sha256": hashlib.sha256(callback.encode()).hexdigest(),
        }
        self.campaign.build()
        # Record intent before an ambiguous docker run can create a container.
        self.registry_owned = True
        self.call(
            [
                "docker",
                "run",
                "-d",
                "--rm",
                "--name",
                "m5-descriptive-registry",
                "-p",
                "127.0.0.1:5001:5000",
                REGISTRY_IMAGE,
            ]
        )
        config = kind_config()
        (self.output / "kind.json").write_text(json.dumps(config))
        self.owned = True
        self.call(
            [
                self.campaign.kind,
                "create",
                "cluster",
                "--name",
                self.cluster,
                "--image",
                self.campaign.pins["node_image"],
                "--config",
                self.output / "kind.json",
                "--kubeconfig",
                self.kubeconfig,
                "--wait",
                "180s",
            ],
            240,
        )
        self.k(
            "taint",
            "nodes",
            self.cluster + "-control-plane",
            "node-role.kubernetes.io/control-plane-",
        )
        self.call(["docker", "network", "connect", "kind", "m5-descriptive-registry"])
        hosts = self.output / "registry-hosts.toml"
        hosts.write_text(REGISTRY_HOSTS)
        for node in self.call(
            [self.campaign.kind, "get", "nodes", "--name", self.cluster]
        ).splitlines():
            target = "/etc/containerd/certs.d/localhost:5001/hosts.toml"
            self.call(
                [
                    "docker",
                    "exec",
                    node,
                    "mkdir",
                    "-p",
                    "/etc/containerd/certs.d/localhost:5001",
                ]
            )
            self.call(["docker", "cp", hosts, node + ":" + target])
            if self.call(["docker", "exec", node, "cat", target]) != REGISTRY_HOSTS:
                raise ValueError("descriptive:registry_config_readback")
            effective = self.call(
                ["docker", "exec", node, "containerd", "config", "dump"]
            )
            if not registry_configured(effective):
                raise ValueError("descriptive:registry_config_path")
        for image in ("mti-gateway:stage1", "mti-fake:stage1"):
            self.call(
                [
                    self.campaign.kind,
                    "load",
                    "docker-image",
                    image,
                    "--name",
                    self.cluster,
                ]
            )
        replacements = {}
        image_receipts = {}
        for name, image in (
            ("redis", REDIS_IMAGE),
            ("nginx", NGINX_IMAGE),
            ("prometheus", PROMETHEUS_IMAGE),
        ):
            self.call(["docker", "pull", image])
            tag = "mti-descriptive/" + name + ":pinned"
            archive = self.output / (name + ".tar")

            def archive_call(argv, **kwargs):
                # Preserve helper's return-status contract, used by archive save.
                result = subprocess.run(
                    list(map(str, argv)),
                    cwd=ROOT,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=kwargs.get("timeout", 180),
                )
                self.commands.append(
                    {"argv": list(map(str, argv)), "exit_code": result.returncode}
                )
                if kwargs.get("return_status"):
                    return (
                        result.returncode,
                        result.stdout.decode() + result.stderr.decode(),
                    )
                result.check_returncode()
                return result.stdout.decode()

            image_receipts[name] = save_amd64_archive(
                image, archive, archive_call, local_tag=tag
            )
            self.call(
                [
                    self.campaign.kind,
                    "load",
                    "image-archive",
                    archive,
                    "--name",
                    self.cluster,
                ]
            )
            archive.unlink()
            replacements[image] = tag
        self.replacements = replacements
        self.call(["docker", "tag", "mti-fake:stage1", "localhost:5001/client:source"])
        self.call(["docker", "push", "localhost:5001/client:source"])
        self.client_image = pushed_digest(
            json.loads(
                self.call(
                    ["docker", "image", "inspect", "localhost:5001/client:source"]
                )
            )[0],
            "localhost:5001/client",
        )
        # Exercise the same CRI pull path as the client Job, including registry
        # resolution, before waiting for Kubernetes scheduling/readiness.
        for node in self.call(
            [self.campaign.kind, "get", "nodes", "--name", self.cluster]
        ).splitlines():
            self.call(["docker", "exec", node, "crictl", "pull", self.client_image])
        result = self.deploy(
            resources(self.namespace, "example.invalid/gateway@sha256:" + "a" * 64)
        )
        result.update(
            image_config_ids=self.campaign.image_ids, upstream_images=image_receipts
        )
        return result

    def render_manifest(self, source):
        replacements = self.replacements
        manifest = copy.deepcopy(source)
        manifest["items"] = [o for o in manifest["items"] if o["kind"] != "DaemonSet"]
        for obj in manifest["items"]:
            if obj["kind"] not in {"Deployment", "StatefulSet"}:
                continue
            pod = obj["spec"]["template"]["spec"]
            container = pod["containers"][0]
            container["image"] = replacements.get(
                container["image"], container["image"]
            )
            container["imagePullPolicy"] = "Never"
            if obj["metadata"]["name"] == "gateway":
                container["image"] = "mti-gateway:stage1"
            if obj["metadata"]["name"] == "vllm":
                container.update(
                    image="mti-fake:stage1",
                    command=["python", "/mock/entry.py"],
                    args=[],
                    env=[
                        {"name": name, "valueFrom": {"fieldRef": {"fieldPath": field}}}
                        for name, field in (
                            ("POD_NAME", "metadata.name"),
                            ("POD_UID", "metadata.uid"),
                        )
                    ],
                    volumeMounts=[
                        {"name": "mock", "mountPath": "/mock", "readOnly": True}
                    ],
                    resources={
                        "requests": {"cpu": "100m", "memory": "64Mi"},
                        "limits": {"cpu": "1", "memory": "256Mi"},
                    },
                )
                pod["volumes"] = [
                    {"name": "mock", "configMap": {"name": "mock-backend"}}
                ]
        manifest["items"].append(
            {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {"name": "mock-backend", "namespace": self.namespace},
                "data": {
                    "entry.py": "from inference_platform import kind_fake\nkind_fake.STREAM_CHUNKS=4\nkind_fake.STREAM_CHUNK_DELAY_MS=50\nraise SystemExit(kind_fake.main())\n"
                },
            }
        )
        return manifest

    def deploy(self, source):
        return super().deploy(source)

    def teardown(self):
        # Bounded failure diagnostics before deleting the only controller state.
        if self.owned and self.kubeconfig.exists():
            for label, args in (
                ("pods", ["get", "pods", "-o", "wide"]),
                ("client", ["describe", "pod", "-l", "job-name=load-client"]),
                ("events", ["get", "events", "-o", "json"]),
                ("client-log", ["logs", "job/load-client", "--tail=80"]),
            ):
                try:
                    text = self.call(
                        [
                            self.campaign.kubectl,
                            "--kubeconfig",
                            self.kubeconfig,
                            "-n",
                            self.namespace,
                            *args,
                        ],
                        timeout=15,
                    )
                    (self.output / ("diagnostic-" + label + ".log")).write_text(
                        text[-65536:]
                    )
                except Exception as error:
                    (self.output / ("diagnostic-" + label + ".error")).write_text(
                        type(error).__name__
                    )
        for process, log in self.forwarders:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            log.close()
        if self.owned:
            self.call(
                [
                    self.campaign.kind,
                    "delete",
                    "cluster",
                    "--name",
                    self.cluster,
                    "--kubeconfig",
                    self.kubeconfig,
                ],
                180,
            )
        if self.registry_owned:
            if self.call(
                ["docker", "ps", "-aq", "--filter", "name=^/m5-descriptive-registry$"]
            ).strip():
                self.call(["docker", "rm", "-fv", "m5-descriptive-registry"])
        if self.backstop_armed:
            self.stop_backstop()
        return {"complete": True, "backstop_timer_inactive": True}

    def stop_backstop(self):
        unit = "m5-descriptive-cleanup"
        self.call(["systemctl", "stop", unit + ".timer"])
        loaded = self.call(
            ["systemctl", "show", "-p", "LoadState", "--value", unit + ".service"]
        ).strip()
        if loaded != "not-found":
            self.call(["systemctl", "stop", unit + ".service"])
        if (
            self.call(
                ["systemctl", "show", "-p", "ActiveState", "--value", unit + ".timer"]
            ).strip()
            != "inactive"
        ):
            raise ValueError("descriptive:backstop_timer_still_active")
        self.backstop_armed = False

    def inventory(self):
        clusters = self.call([self.campaign.kind, "get", "clusters"]).splitlines()
        containers = self.call(
            [
                "docker",
                "ps",
                "-aq",
                "--filter",
                "label=io.x-k8s.kind.cluster=" + self.cluster,
            ]
        ).splitlines()
        registry = self.call(
            ["docker", "ps", "-aq", "--filter", "name=^/m5-descriptive-registry$"]
        ).splitlines()
        if self.cluster in clusters or containers or registry:
            raise ValueError("descriptive:inventory_nonempty")
        return {
            "complete": True,
            "cluster": 0,
            "containers": 0,
            "registry_containers": 0,
            "aws_resources": "not created by rehearsal",
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    ports = KindPorts(args.output / "host")
    try:
        receipt = execute(
            ports, args.output / "sequence", deadline=ports.deadline, rehearsal=True
        )
        print(
            json.dumps(
                {
                    "complete": receipt["complete"],
                    "phases": [p["name"] for p in receipt["phases"]],
                }
            )
        )
    finally:
        (args.output / "commands.json").write_text(
            json.dumps(ports.commands, indent=2, sort_keys=True) + "\n"
        )
        # No key/credential/cache outputs are frozen into routine receipts.
        for name in (
            "tls.key",
            "cache-salt.secret",
            "tenants.secret",
            "client.secret",
            "kubeconfig",
        ):
            (ports.output / name).unlink(missing_ok=True)


if __name__ == "__main__":
    main()
