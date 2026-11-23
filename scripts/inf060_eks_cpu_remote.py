"""Approved CPU clock rehearsal workload on the DEC-100 operator host."""

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from inf060_eks_cpu_plan import (
    IMAGE_ARCHIVE,
    IMAGE_TAGS,
    NODE_COUNT,
    SERVICE_IMAGES,
    check_loaded_image,
    check_pushed_content,
)
from inf060_eks_remote import StreamingClusterPorts
from rehearse_inf060_kind import CLOCK_PROBE, PEER_PROBE, fallback_clock

ROOT = Path(__file__).resolve().parents[1]


class CpuClockPorts(StreamingClusterPorts):
    image_archive = Path("/opt/dec077/gate-a-inputs") / IMAGE_ARCHIVE

    @property
    def cpu(self):
        return self.binding["cpu_clock_rehearsal"]

    def prepare_images(self):
        self.call(
            ["docker", "load", "-i", self.image_archive],
            timeout=900,
        )
        loaded = {}
        for role, tag in IMAGE_TAGS.items():
            [inspected] = json.loads(self.call(["docker", "image", "inspect", tag]))
            check_loaded_image(inspected, self.cpu["images"][role])
            loaded[role] = {
                "id": inspected["Id"],
                "diff_ids": inspected["RootFS"]["Layers"],
            }
        self.results["cpu_clock_image_load"] = loaded

    def check_pushed_image(self, role, image, ecr):
        repository, digest = image.rsplit("@", 1)
        reply = ecr.batch_get_image(
            repositoryName=repository.split("/", 1)[1],
            imageIds=[{"imageDigest": digest}],
            acceptedMediaTypes=[
                "application/vnd.docker.distribution.manifest.v2+json",
                "application/vnd.oci.image.manifest.v1+json",
            ],
        )
        entries = reply["images"]
        if len(entries) != 1 or entries[0]["imageId"]["imageDigest"] != digest:
            raise ValueError("cpu_clock:ecr_digest_readback")
        body = entries[0]["imageManifest"]
        if "sha256:" + hashlib.sha256(body.encode()).hexdigest() != digest:
            raise ValueError("cpu_clock:ecr_digest_readback")
        manifest = json.loads(body)
        check_pushed_content(manifest, self.cpu["images"][role])
        self.results.setdefault("cpu_clock_image_push", {})[role] = {
            "manifest_digest": digest,
            "config_digest": manifest["config"]["digest"],
            "layer_digests": [row["digest"] for row in manifest["layers"]],
        }

    def stage_model(self):
        return {"engine": "cpu-sse-mock", "weights_staged": False}

    def deploy(self, source):
        wanted = {"enabled": True, "desired": NODE_COUNT, "ready": NODE_COUNT}
        if not self.policy_agent()["enabled"]:
            raise ValueError("stream_network_policy")
        self.wait(lambda: self.policy_agent() == wanted, seconds=120)
        self.results["cpu_clock_policy_agent"] = wanted
        return super().deploy(source)

    def render_manifest(self, source):
        result = super().render_manifest(source)
        result["items"] = [row for row in result["items"] if row["kind"] != "DaemonSet"]
        result["items"].append(
            {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {"name": "cpu-clock-engine", "namespace": self.namespace},
                "immutable": True,
                "data": {
                    "engine.py": (ROOT / "scripts/inf060_kind_engine.py").read_text(
                        encoding="utf-8"
                    )
                },
            }
        )
        for row in result["items"]:
            name = row["metadata"]["name"]
            if name in SERVICE_IMAGES and row["kind"] == "Deployment":
                [container] = row["spec"]["template"]["spec"]["containers"]
                if container["image"] != self.cpu["service_images"][name]:
                    raise ValueError("cpu_clock:service_image_changed")
            if row["kind"] != "StatefulSet" or name != "vllm":
                continue
            spec = row["spec"]["template"]["spec"]
            spec["nodeSelector"] = {"m5-role": "cpu"}
            spec.pop("tolerations")
            spec["volumes"] = [
                {"name": "mock", "configMap": {"name": "cpu-clock-engine"}}
            ]
            spec["containers"][0].update(
                image=self.client_image,
                command=["python", "-u", "/mock/engine.py"],
                args=[],
                env=[],
                resources={
                    "requests": {"cpu": "100m", "memory": "64Mi"},
                    "limits": {"cpu": "2", "memory": "256Mi"},
                },
                volumeMounts=[{"name": "mock", "mountPath": "/mock", "readOnly": True}],
            )
        return result

    def client_job(self):
        result = super().client_job()
        job = next(row for row in result["items"] if row["kind"] == "Job")
        job["spec"]["template"]["spec"]["affinity"] = {
            "podAntiAffinity": {
                "requiredDuringSchedulingIgnoredDuringExecution": [
                    {
                        "labelSelector": {"matchLabels": {"app": "vllm"}},
                        "topologyKey": "kubernetes.io/hostname",
                    }
                ]
            }
        }
        return result

    def from_client(self, code, *args):
        return json.loads(
            self.k(
                "exec",
                self.client_pod,
                "-c",
                "client",
                "--",
                "python",
                "-c",
                code,
                *args,
            )
        )

    def prove_policy(self, replicas):
        pods = json.loads(self.k("get", "pods", "-l", "app=vllm", "-o", "json"))[
            "items"
        ]
        engine_nodes = {row["spec"]["nodeName"] for row in pods}
        node = self.client_placement["node"]
        if len(engine_nodes) != 2 or node in engine_nodes:
            raise ValueError("cpu_clock:cross_node_placement")
        ips = [row["ip"] for _, row in replicas]
        allowed = self.from_client(PEER_PROBE, *ips)
        self.k(
            "run",
            "unlabelled-peer",
            "--restart=Never",
            "--image=" + self.client_image,
            "--overrides="
            + json.dumps(
                {"spec": {"nodeName": node, "automountServiceAccountToken": False}}
            ),
            "--command",
            "--",
            "python",
            "-c",
            PEER_PROBE,
            *ips,
        )
        self.k(
            "wait",
            "--for=jsonpath={.status.phase}=Succeeded",
            "pod/unlabelled-peer",
            "--timeout=90s",
        )
        peer = json.loads(self.k("get", "pod/unlabelled-peer", "-o", "json"))
        if peer["spec"]["nodeName"] != node or "inf060-role" in peer["metadata"].get(
            "labels", {}
        ):
            raise ValueError("cpu_clock:denied_peer_placement")
        denied = json.loads(self.k("logs", "unlabelled-peer"))
        return {
            "allowed": allowed,
            "denied": denied,
            "passed": allowed == [{"engine": True, "clock": True}] * 2
            and denied == [{"engine": True, "clock": False}] * 2,
        }

    def provision(self):
        result = super().provision()
        replicas = sorted(self.streams().items())
        if len(replicas) != 2:
            raise ValueError("cpu_clock:replicas")
        record = {
            "phase": "cpu-clock-policy",
            "nodes": NODE_COUNT,
            "agent": self.results["cpu_clock_policy_agent"],
            "policy": self.prove_policy(replicas),
        }
        self.results.setdefault("stream_diagnostics", []).append(record)
        if not record["policy"]["passed"]:
            raise ValueError("cpu_clock:policy_probe")
        record["idle"] = self.from_client(CLOCK_PROBE, self.namespace, "idle")
        record["fallback"] = [
            {
                "replica": index,
                **fallback_clock(
                    [
                        self.campaign.kubectl,
                        "--kubeconfig",
                        self.kubeconfig,
                        "--context",
                        self.context,
                        "-n",
                        self.namespace,
                        "exec",
                        "-i",
                        name,
                        "-c",
                        "clock-server",
                        "--",
                    ],
                    facts["identity"][0],
                ),
            }
            for index, (name, facts) in enumerate(replicas, 1)
        ]
        # Only anonymous replica indexes, counts and clock offsets are exported.
        return {"clock_policy": record, "images": result["images"]}

    def peak_measurement(self):
        def active():
            try:
                return bool(self.client_file("8-journal.jsonl", 48 * 1024**2))
            except ValueError:
                return False

        self.wait(active, seconds=60)
        return self.from_client(CLOCK_PROBE, self.namespace, "peak")

    def stream_window(self, label):
        if label not in {"smoke", "warmup", "8"}:
            raise ValueError("cpu_clock:window_scope")
        if label != "8":
            return super().stream_window(label)
        with ThreadPoolExecutor(max_workers=1) as pool:
            observed = pool.submit(self.peak_measurement)
            result = super().stream_window(label)
        self.results.setdefault("stream_diagnostics", []).append(
            {"phase": "cpu-clock-peak", "replicas": observed.result()}
        )
        return result
