"""DEC-099 real Kubernetes validation of production descriptive EKS objects.

No AWS API or product Apply. Dry-run uses pinned standalone Kubernetes 1.35;
staging uses two tainted kind workers and the actual model materializer.
"""

import argparse
import importlib.util
import json
import shutil
import subprocess
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

from inference_platform import kind_rollout
from inference_platform.m5_descriptive import resources
from inference_platform.m5_descriptive_operator import (
    file_digest,
    phase_deadline,
    session_timing,
)
from inf037b_purpose_kube import APISERVER, ETCD
from m5_descriptive_remote import EKSClusterPorts
from rehearse_m5_descriptive import kind_config

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "fixture.invalid/image@sha256:" + "a" * 64
FORBIDDEN = "activeDeadlineSeconds: Forbidden: activeDeadlineSeconds in DaemonSet is not Supported"


def command(argv, **kwargs):
    return subprocess.check_output(
        list(map(str, argv)),
        stderr=subprocess.STDOUT,
        timeout=kwargs.pop("timeout", 180),
        **kwargs,
    ).decode()


def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def make_ports(output, cluster="m5-object-validation"):
    campaign = kind_rollout.Campaign(output)
    campaign.install_tools()
    original_end = time.time() + 14400
    return EKSClusterPorts(
        output,
        {
            "deadline_epoch": phase_deadline(
                original_end, session_timing(640, 140), "provision"
            ),
            "descriptive": {
                "session": cluster,
                "original_deadline_epoch": original_end,
                "kubernetes_context": "kind-" + cluster,
                "startup_seconds": 640,
                "timing": session_timing(640, 140),
            },
        },
    )


class ObjectCollector(EKSClusterPorts):
    """Intercept transport only; production methods generate ALL object bodies.

    Readiness and inventory placeholders only let materialization reach the end.
    They are not evidence of readiness; each body still meets the real API below.
    """

    def k(self, *args):
        if args[0] == "apply":
            value = json.loads(Path(args[2]).read_bytes())
            self.objects.extend(value["items"] if value["kind"] == "List" else [value])
        elif args[0] == "create":
            value = json.loads(
                self.call(
                    [
                        self.campaign.kubectl,
                        "-n",
                        self.namespace,
                        *args,
                        "--dry-run=client",
                        "-o=json",
                    ]
                )
            )
            self.objects.append(value)
        elif args[:2] == ("get", "pods"):
            if "app=model-stager" in args:
                return json.dumps(
                    {
                        "items": [
                            {
                                "metadata": {"name": "stage-" + str(i)},
                                "spec": {"nodeName": "node-" + str(i)},
                            }
                            for i in range(2)
                        ]
                    }
                )
            return json.dumps(
                {
                    "items": [
                        {
                            "metadata": {"name": "client"},
                            "spec": {"nodeName": "cpu"},
                            "status": {"containerStatuses": [{"imageID": IMAGE}]},
                        }
                    ]
                }
            )
        elif args[0] == "exec":
            return "{}"
        elif args[0] not in {"wait", "rollout", "delete"}:
            raise ValueError("kubernetes_validation:uncollected_call:" + str(args))
        return ""


def collect_objects(ports):
    ports.__class__ = ObjectCollector
    ports.objects = []
    ports.client_image = IMAGE
    ports.stage_model()
    ports.deploy(resources(ports.namespace, IMAGE))
    # Namespace is also applied by provision before staging. Use deploy's exact
    # same namespace generator, and create it before the other dry runs.
    unique = {}
    for obj in ports.objects:
        unique[(obj["kind"], obj["metadata"]["name"])] = obj
    return sorted(unique.values(), key=lambda o: o["kind"] != "Namespace")


@contextmanager
def api_server(output, kubectl):
    suffix = str(time.monotonic_ns())
    names = ["descriptive-etcd-" + suffix, "descriptive-api-" + suffix]
    with tempfile.TemporaryDirectory(prefix="descriptive-api-") as folder:
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
                    "/CN=descriptive-api",
                    "-addext",
                    "subjectAltName=IP:127.0.0.1",
                    "-keyout",
                    str(config / "key.pem"),
                    "-out",
                    str(config / "cert.pem"),
                ]
            )
            token = "descriptive-local-fixture"
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
            kubeconfig = config / "kubeconfig"
            write(
                kubeconfig,
                {
                    "apiVersion": "v1",
                    "kind": "Config",
                    "clusters": [
                        {
                            "name": "api",
                            "cluster": {
                                "server": "https://127.0.0.1:16443",
                                "certificate-authority": str(config / "cert.pem"),
                            },
                        }
                    ],
                    "contexts": [
                        {"name": "api", "context": {"cluster": "api", "user": "api"}}
                    ],
                    "current-context": "api",
                    "users": [{"name": "api", "user": {"token": token}}],
                },
            )
            argv = [kubectl, "--kubeconfig", kubeconfig]
            end = time.monotonic() + 120
            while True:
                try:
                    if command([*argv, "get", "--raw=/readyz"]).strip() == "ok":
                        break
                except subprocess.CalledProcessError:
                    if time.monotonic() >= end:
                        raise
                time.sleep(0.5)
            version = json.loads(command([*argv, "get", "--raw=/version"]))
            if version["gitVersion"] != "v1.35.0":
                raise ValueError("kubernetes_validation:minor")
            yield argv, version
        finally:
            for name in reversed(names):
                logs = subprocess.run(
                    ["docker", "logs", name], capture_output=True, timeout=30
                )
                (output / (name.split("-")[1] + ".log")).write_bytes(
                    logs.stdout + logs.stderr
                )
                subprocess.run(
                    ["docker", "rm", "-fv", name], capture_output=True, timeout=60
                )
            for name in names:
                if (
                    subprocess.run(
                        ["docker", "inspect", name], capture_output=True
                    ).returncode
                    == 0
                ):
                    raise ValueError("kubernetes_validation:api_cleanup:" + name)


def historical_stager(ports, scratch):
    source = subprocess.check_output(
        ["git", "show", "7c742a2:scripts/m5_descriptive_remote.py"], cwd=ROOT
    )
    path = scratch / "historical_remote.py"
    path.write_bytes(source)
    spec = importlib.util.spec_from_file_location("historical_stager", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # The historical function's ROOT followed its scratch file; bind to the
    # scratch source tree containing the unchanged materializer, never edit HEAD.
    module.ROOT = ROOT
    ports.objects = []
    module.EKSClusterPorts.stage_model(ports)
    return next(o for o in ports.objects if o["kind"] == "DaemonSet")


def dry_run(output):
    ports = make_ports(output / "materialized")
    objects = collect_objects(ports)
    receipt = {"apiserver": APISERVER, "etcd": ETCD, "objects": [], "complete": False}
    try:
        with api_server(output, ports.campaign.kubectl) as (argv, version):
            receipt["version"] = version["gitVersion"]
            ns = next(o for o in objects if o["kind"] == "Namespace")
            path = output / "namespace.json"
            write(path, ns)
            command([*argv, "apply", "-f", path])
            for i, obj in enumerate(objects):
                path = output / f"object-{i}.json"
                write(path, obj)
                try:
                    answer = command([*argv, "apply", "--dry-run=server", "-f", path])
                except subprocess.CalledProcessError as error:
                    receipt["objects"].append(
                        {
                            "kind": obj["kind"],
                            "name": obj["metadata"]["name"],
                            "sha256": file_digest(path),
                            "status": "FAILED",
                            "message": error.output.decode(errors="replace"),
                        }
                    )
                    raise
                receipt["objects"].append(
                    {
                        "kind": obj["kind"],
                        "name": obj["metadata"]["name"],
                        "sha256": file_digest(path),
                        "result": answer.strip(),
                        "status": "PASS",
                    }
                )
            with tempfile.TemporaryDirectory(prefix="old-stager-") as folder:
                obj = historical_stager(ports, Path(folder))
                path = Path(folder) / "old-daemonset.json"
                write(path, obj)
                try:
                    command([*argv, "apply", "--dry-run=server", "-f", path])
                except subprocess.CalledProcessError as error:
                    message = error.output.decode()
                    if FORBIDDEN not in message:
                        raise
                    receipt["negative_control"] = {
                        "source": "7c742a2",
                        "status": "REFUSED_EXPECTED",
                        "message": message.strip(),
                        "sha256": file_digest(path),
                    }
                else:
                    raise ValueError("kubernetes_validation:old_stager_survived")
            receipt["complete"] = True
    finally:
        write(output / "result.json", receipt)


def scheduling(ports, output):
    workers = json.loads(ports.k("get", "nodes", "-l", "m5-role=gpu", "-o=json"))[
        "items"
    ]
    for node in workers:
        ports.k(
            "patch",
            "node",
            node["metadata"]["name"],
            "--subresource=status",
            "--type=merge",
            "-p",
            json.dumps(
                {
                    "status": {
                        "capacity": {"nvidia.com/gpu": "1"},
                        "allocatable": {"nvidia.com/gpu": "1"},
                    }
                }
            ),
        )
    manifest = ports.render_manifest(resources(ports.namespace, IMAGE))
    selected = [
        o
        for o in manifest["items"]
        if (o["kind"], o["metadata"]["name"])
        in {
            ("StatefulSet", "vllm"),
            ("DaemonSet", "nvidia-device-plugin"),
            ("Service", "vllm"),
        }
    ]
    path = output / "scheduling.json"
    write(path, {"apiVersion": "v1", "kind": "List", "items": selected})
    ports.k("apply", "-f", path)
    end = time.monotonic() + 180
    while True:
        pods = json.loads(ports.k("get", "pods", "-l", "app=vllm", "-o=json"))["items"]
        if (
            len(pods) == 2
            and len({p["spec"].get("nodeName") for p in pods}) == 2
            and all(p["spec"].get("nodeName") for p in pods)
        ):
            break
        if time.monotonic() >= end:
            raise TimeoutError("kubernetes_validation:two_gpu_scheduling")
        time.sleep(1)
    worker_names = {n["metadata"]["name"] for n in workers}
    for pod in pods:
        if pod["spec"]["nodeName"] not in worker_names:
            raise ValueError("kubernetes_validation:wrong_node")
        model = next(v for v in pod["spec"]["volumes"] if v["name"] == "model")
        mount = next(
            v
            for v in pod["spec"]["containers"][0]["volumeMounts"]
            if v["name"] == "model"
        )
        if (
            model["hostPath"]["path"] != "/var/cache/mti-m5/models"
            or mount["mountPath"] != "/root/.cache/huggingface"
        ):
            raise ValueError("kubernetes_validation:model_mount")
        command(
            [
                "docker",
                "exec",
                pod["spec"]["nodeName"],
                "test",
                "-d",
                "/var/cache/mti-m5/models/hub",
            ]
        )
    plugin_end = time.monotonic() + 120
    while True:
        plugins = json.loads(
            ports.k("get", "pods", "-l", "app=nvidia-device-plugin", "-o=json")
        )["items"]
        if (
            len(plugins) == 2
            and {p["spec"].get("nodeName") for p in plugins} == worker_names
        ):
            break
        if time.monotonic() >= plugin_end:
            raise TimeoutError("kubernetes_validation:plugin_scheduling")
        time.sleep(1)
    time.sleep(30)
    return {
        "claim": "scheduling and model hostPath only; no GPU runtime or serving claim",
        "gpu_capacity_substitution": "manual Node status advertises one GPU on each CPU kind worker; no GPU device",
        "scheduled_vllm_pods": pods,
        "scheduled_plugin_pods": plugins,
        "pods": json.loads(ports.k("get", "pods", "-o=json"))["items"],
        "nodes": json.loads(ports.k("get", "nodes", "-o=json"))["items"],
        "expected_cpu_failures": "CPU-only runtime failures are expected; actual Pod states and logs are retained. Running/initializing is not serving readiness. No GPU runtime claim.",
    }


def stager(output):
    ports = make_ports(output / "runtime", "m5-stager-validation")
    receipt = {
        "complete": False,
        "initial_free_disk_bytes": shutil.disk_usage("/").free,
        "substitutions": [
            "kind instead of EKS provisioning; real EKSClusterPorts.stage_model unchanged",
            "CPU kind workers instead of L4 hosts; same selectors, taints, pinned image and real model download",
            "manual extended GPU capacity for scheduling only; no fake model or shortened materializer",
            "worker image/model filesystems share one routine-host disk instead of separate L4 root volumes",
        ],
    }
    config = kind_config()
    for node in config["nodes"][1:]:
        node["kubeadmConfigPatches"] = [
            "kind: JoinConfiguration\nnodeRegistration:\n  taints:\n  - key: nvidia.com/gpu\n    value: 'true'\n    effect: NoSchedule\n"
        ]
    write(output / "kind.json", config)
    try:
        command(
            [
                ports.campaign.kind,
                "create",
                "cluster",
                "--name",
                ports.cluster,
                "--image",
                ports.campaign.pins["node_image"],
                "--config",
                output / "kind.json",
                "--kubeconfig",
                ports.kubeconfig,
                "--wait",
                "180s",
            ],
            timeout=360,
        )
        ports.k("create", "namespace", ports.namespace)
        ports.k("wait", "--for=condition=Ready", "nodes", "--all", "--timeout=180s")
        receipt["stager_nodes"] = json.loads(
            ports.k("get", "nodes", "-l", "m5-role=gpu", "-o=json")
        )["items"]
        if len(receipt["stager_nodes"]) != 2:
            raise ValueError("kubernetes_validation:two_labelled_workers_required")
        started = time.monotonic()
        receipt["model"] = ports.stage_model()
        receipt["readbacks"] = ports.results["model_staging"]
        receipt["stage_elapsed_s"] = time.monotonic() - started
        receipt["stage_commands"] = ports.commands
        receipt["scheduling"] = scheduling(ports, output)
        receipt["complete"] = True
    finally:
        receipt["stage_commands"] = ports.commands
        receipt["final_free_disk_bytes_before_cluster_deletion"] = shutil.disk_usage(
            "/"
        ).free
        for kind in ("pods", "events", "daemonsets", "nodes"):
            result = subprocess.run(
                [
                    str(ports.campaign.kubectl),
                    "--kubeconfig",
                    str(ports.kubeconfig),
                    "-n",
                    ports.namespace,
                    "get",
                    kind,
                    "-o=json",
                ],
                capture_output=True,
                timeout=30,
            )
            (output / (kind + ".json")).write_bytes(result.stdout)
        pods_path = output / "pods.json"
        if pods_path.stat().st_size:
            for pod in json.loads(pods_path.read_bytes()).get("items", []):
                for previous in (False, True):
                    name = pod["metadata"]["name"]
                    result = subprocess.run(
                        [
                            str(ports.campaign.kubectl),
                            "--kubeconfig",
                            str(ports.kubeconfig),
                            "-n",
                            ports.namespace,
                            "logs",
                            name,
                            "--all-containers",
                            "--tail=80",
                            *(["--previous"] if previous else []),
                        ],
                        capture_output=True,
                        timeout=30,
                    )
                    (
                        output / (name + ("-previous" if previous else "") + ".log")
                    ).write_bytes((result.stdout + result.stderr)[-8192:])
        command(
            [ports.campaign.kind, "delete", "cluster", "--name", ports.cluster],
            timeout=180,
        )
        receipt["cleanup_verified"] = (
            ports.cluster
            not in command([ports.campaign.kind, "get", "clusters"]).splitlines()
        )
        write(output / "result.json", receipt)
        if not receipt["cleanup_verified"]:
            raise ValueError("kubernetes_validation:kind_cleanup")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("dry-run", "stager"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True)
    {"dry-run": dry_run, "stager": stager}[args.mode](args.output)
