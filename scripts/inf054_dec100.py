"""Bind the INF-054 workload to DEC-100 Kubernetes and Prometheus ports."""

import base64
import contextlib
import json
import re
import subprocess
import time
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import yaml
from inf054_dcgm import (
    CADVISOR_S,
    LATER_WAIT_S,
    WAIT_S,
    capture_memory,
    require_dcgm,
    write_receipt,
)
from inf054_helm_releases import HelmReleases
from inf054_eks_workload import (
    READY_HOLD_S,
    READY_PROBE_S,
    SAMPLE_ERRORS,
    engine_readiness_seconds,
)
from inf063_chart import CHART
from prometheus_snapshot import SNAPSHOT_NAME

from inference_platform.inf054_eks_client import LONG_PROBE_CAP, LONG_PROBE_STOP
from inference_platform.package_a_workload import test_tls_command, write_kind_secret


PROMQL = {
    "running": 'sum(vllm:num_requests_running{job="vllm"})',
    "waiting": 'sum(vllm:num_requests_waiting{job="vllm"})',
    "kv_fraction": 'max(vllm:kv_cache_usage_perc{job="vllm"})',
    "gpu_memory_mib": "max(DCGM_FI_DEV_FB_USED)",
    "dcgm_gpu_util_pct": "max(DCGM_FI_DEV_GPU_UTIL)",
    "scrape": 'up{job="vllm"}',
}
MOCK = Path(__file__).with_name("inf054_kind_engine.py")
# The membership pair or HPA/API pair has two reads, measured at about 0.29 s each.
READINESS_POLL_S = 4


def write(path, data):
    path.write_text(json.dumps(data, allow_nan=False) + "\n", encoding="utf-8")
    return path


def read_json(url, deadline, *, post=False):
    left = deadline - time.monotonic()
    if left <= 0:
        raise TimeoutError("inf054_http_deadline")
    request = urllib.request.Request(url, data=b"" if post else None)
    with urllib.request.urlopen(request, timeout=left) as response:
        body = response.read(1024**2 + 1)
    if len(body) > 1024**2:
        raise ValueError("inf054_http_size")
    value = json.loads(body)
    if value.get("status") != "success":
        raise ValueError("inf054_prometheus_response")
    return value["data"]


def pod_name(pod):
    name = (pod.get("metadata") or {}).get("name")
    if not name:
        raise ValueError("inf054_pod_name")
    return name


def replica(pod):
    name = pod_name(pod)
    if name not in {"vllm-0", "vllm-1"}:
        raise ValueError("inf054_engine_ordinal")
    return int(name[-1])


def overlapping_streams(rows, at):
    return [
        {"index": index, "outcome": row["outcome"]}
        for index, row in enumerate(rows)
        if at is not None
        and row["replica_ordinal"] == 1
        and row.get("ttft_s") is not None
        and row["dispatch_s"] + row["ttft_s"] < at < row["dispatch_s"] + row["closed_s"]
    ]


def engine_container(objects):
    engines = [
        row["spec"]["template"]["spec"]
        for row in objects
        if row["kind"] == "StatefulSet" and row["metadata"]["name"] == "vllm"
    ]
    [engine] = engines
    [container] = [row for row in engine["containers"] if row["name"] == "vllm"]
    return engine, container


def rendered_engine(objects, *, cpu):
    """Check workload resource ownership in the actual render and reduce it."""
    engine, container = engine_container(objects)
    role = "cpu" if cpu else "gpu"
    plugin = any(
        row["kind"] == "DaemonSet" and "device-plugin" in row["metadata"]["name"]
        for row in objects
    )
    if engine.get("nodeSelector") != {"m5-role": role} or (cpu and plugin):
        raise ValueError("inf054_rendered_engine_placement")
    for row in objects:
        pod = (
            row["spec"]["template"]["spec"]
            if row["kind"] in {"DaemonSet", "Deployment", "StatefulSet", "Job"}
            else row["spec"]
            if row["kind"] == "Pod"
            else {}
        )
        for candidate in [*pod.get("containers", []), *pod.get("initContainers", [])]:
            for field in ("requests", "limits"):
                limits = candidate.get("resources", {}).get(field, {})
                if cpu and "nvidia.com/gpu" in limits:
                    raise ValueError("inf054_rendered_cpu_gpu_resource")
    resources = container["resources"]
    if not cpu and any(
        int(resources[key].get("nvidia.com/gpu", 0)) != 1
        for key in ("requests", "limits")
    ):
        raise ValueError("inf054_rendered_gpu_count")
    return {
        "engine_resources": resources,
        "engine_node_selector": engine["nodeSelector"],
        "device_plugin_present": plugin,
    }


class Dec100Workload:
    """Run chart releases in separate namespaces using the owned kube context."""

    def __init__(
        self,
        cluster,
        helm,
        rendered,
        sha256,
        work,
        *,
        cleanup_end,
        cpu=False,
        rehearsal_burst_s=None,
        helm_invoke=None,
        rendered_receipt=None,
        split_readiness=None,
        mock_health_delay_s=0,
        mock_gpu_diagnostics=False,
    ):
        self.cluster = cluster
        self.rendered = rendered
        self.sha256 = sha256
        self.work = work
        self.cleanup_end = cleanup_end
        self.cpu = cpu
        self.split_readiness = not cpu if split_readiness is None else split_readiness
        if (mock_health_delay_s or mock_gpu_diagnostics) and not cpu:
            raise ValueError("inf054_mock_requires_cpu")
        self.mock_health_delay_s = mock_health_delay_s
        self.mock_gpu_diagnostics = mock_gpu_diagnostics
        self.rehearsal_burst_s = rehearsal_burst_s
        self.values = yaml.safe_load((CHART / "values.yaml").read_bytes())

        def check_render(objects):
            if rendered_receipt is not None:
                write(rendered_receipt, rendered_engine(objects, cpu=cpu))
            if self.split_readiness:
                _, container = engine_container(objects)
                seconds = engine_readiness_seconds(container["startupProbe"])
                if seconds != engine_readiness_seconds(
                    self.values["engine"]["startupProbe"]
                ):
                    raise ValueError("inf054_rendered_startup_probe_bound")
                return seconds
            return None

        self.helm = HelmReleases(
            helm,
            cluster.kubeconfig,
            cluster.context,
            work,
            self.namespace,
            self.backend,
            **({"invoke": helm_invoke} if helm_invoke else {}),
            rendered=check_render if self.split_readiness or rendered_receipt else None,
        )

    @contextlib.contextmanager
    def namespace(self, arm, cycle, end):
        preparation_started = time.monotonic()
        c = self.cluster
        previous = c.namespace
        c.namespace = f"{previous}-{arm}-{cycle}"
        work = self.work / c.namespace
        work.mkdir()
        values = {"gatewayImage": c.gateway_image, "clientImage": c.client_image}
        env = [
            {
                **row,
                "value": {
                    "GATEWAY_TOTAL_TIMEOUT": "120s",
                    "ADMISSION_LEASE": "180s",
                }.get(row["name"], row.get("value")),
            }
            if row["name"] in {"GATEWAY_TOTAL_TIMEOUT", "ADMISSION_LEASE"}
            else row
            for row in self.values["gateway"]["env"]
        ]
        values["gateway"] = {"env": env}
        if self.cpu:
            values["engine"] = {
                "image": c.client_image,
                "nodeRole": "cpu",
                "mockConfigMap": "inf054-engine",
                "command": ["python", "-u", "/mock/engine.py"],
                "args": [],
                "env": [{"name": "INF054_CPU_WORKLOAD", "value": "1"}],
                "resources": {
                    "requests": {
                        "cpu": "100m",
                        "memory": "64Mi",
                        "nvidia.com/gpu": None,
                    },
                    "limits": {"cpu": "2", "memory": "256Mi", "nvidia.com/gpu": None},
                },
            }
            values["devicePlugin"] = {"enabled": False}
            if self.mock_health_delay_s:
                values["engine"]["env"].append(
                    {
                        "name": "INF054_MOCK_HEALTH_DELAY_S",
                        "value": str(self.mock_health_delay_s),
                    }
                )
            if self.mock_gpu_diagnostics:
                values["engine"]["env"].append(
                    {"name": "INF054_MOCK_LONG_STREAM", "value": "1"}
                )
        try:
            c.k("create", "namespace", c.namespace, deadline=end)
            salt = work / "cache-salt.secret"
            write_kind_secret(salt)
            tenants = c.tenant_configuration()
            if (not self.cpu and (arm, cycle) == ("keda", 3)) or (
                self.mock_gpu_diagnostics and arm == "keda"
            ):
                for tenant in tenants["tenants"]:
                    tenant["max_output_tokens"] = LONG_PROBE_CAP
            config = write(work / "tenants.secret", tenants)
            credentials = write(work / "client.secret", c.client_credentials())
            c.k(
                "create",
                "secret",
                "generic",
                "gateway-config",
                f"--from-file=tenants.json={config}",
                f"--from-file=cache-salt.secret={salt}",
                deadline=end,
            )
            c.call(
                test_tls_command(work)
                + [
                    "-addext",
                    "subjectAltName=DNS:streaming-ingress",
                ],
                timeout=max(0.1, end - time.monotonic()),
            )
            c.k(
                "create",
                "secret",
                "tls",
                "gateway-tls",
                f"--cert={work / 'tls.crt'}",
                f"--key={work / 'tls.key'}",
                deadline=end,
            )
            c.k(
                "create",
                "secret",
                "generic",
                "load-client",
                f"--from-file=client.json={credentials}",
                deadline=end,
            )
            c.k(
                "create",
                "configmap",
                "load-client-ca",
                f"--from-file=tls.crt={work / 'tls.crt'}",
                deadline=end,
            )
            if self.cpu:
                c.k(
                    "create",
                    "configmap",
                    "inf054-engine",
                    f"--from-file=engine.py={MOCK}",
                    deadline=end,
                )
            yield SimpleNamespace(
                name=c.namespace,
                values=values,
                work=work,
                cleanup_end=self.cleanup_end,
                arm=arm,
                cycle=cycle,
                preparation_started=preparation_started,
            )
        finally:
            try:
                c.k(
                    "delete",
                    "namespace",
                    c.namespace,
                    "--ignore-not-found",
                    "--wait=true",
                    f"--timeout={max(1, int(self.cleanup_end - time.monotonic()))}s",
                    deadline=self.cleanup_end,
                )
            finally:
                c.namespace = previous

    def dcgm_enabled(self, arm, cycle):
        return not self.cpu or (
            self.mock_gpu_diagnostics and (arm, cycle) == ("fixed-2", 1)
        )

    @contextlib.contextmanager
    def backend(self, prepared, end):
        c = self.cluster
        resources = c.client_job()
        [job] = [obj for obj in resources["items"] if obj["kind"] == "Job"]
        job["spec"]["template"]["spec"]["affinity"] = {
            "podAntiAffinity": {
                "requiredDuringSchedulingIgnoredDuringExecution": [
                    {
                        "labelSelector": {"matchLabels": {"app": "vllm"}},
                        "topologyKey": "kubernetes.io/hostname",
                    },
                ]
            },
        }
        forwarders = len(c.forwarders)
        dcgm = self.dcgm_enabled(prepared.arm, prepared.cycle)
        receipt = self.work / f"dcgm-gate-{prepared.arm}-{prepared.cycle}.json"
        role = "cpu,inf054-dcgm=true" if self.cpu else "gpu"
        witness = None
        window = None
        try:
            if dcgm and self.cpu:
                configure_mock_dcgm(c, end)
            c.k(
                "apply",
                "-f",
                write(prepared.work / "client.json", resources),
                deadline=end,
            )
            c.k(
                "wait",
                "pod",
                "-l",
                "job-name=load-client",
                "--for=condition=Ready",
                f"--timeout={max(1, int(end - time.monotonic()))}s",
                deadline=end,
            )
            [client] = (
                json.loads(
                    c.k(
                        "get",
                        "pods",
                        "-l",
                        "job-name=load-client",
                        "-o",
                        "json",
                        deadline=end,
                    )
                ).get("items")
                or []
            )
            name = pod_name(client)
            c.k(
                "cp",
                self.rendered,
                f"{name}:/results/tape.jsonl",
                "-c",
                "client",
                deadline=end,
            )
            # A Service port-forward exits if no selected pod is running yet.
            # Wait for the telemetry Deployment within this release's deadline.
            c.k(
                "wait",
                "deployment/telemetry",
                "--for=condition=Available",
                f"--timeout={max(1, int(end - time.monotonic()))}s",
                deadline=end,
            )
            port = c.forward("svc/telemetry", 9090, deadline=end)
            if self.split_readiness and time.monotonic() >= end:
                raise TimeoutError("inf054_preparation_deadline")
            window = ClusterWindow(
                c,
                client,
                port,
                self.sha256,
                prepared.arm,
                rehearsal_burst_s=self.rehearsal_burst_s,
                gpu_metrics=not self.cpu,
                long_downscale=not self.cpu or self.mock_gpu_diagnostics,
            )
            trail = self.work / f"{prepared.name}-readiness.jsonl"
            if self.split_readiness:
                window.readiness(
                    window.origin + prepared.engine_readiness_s,
                    trail=trail,
                    preparation_s=window.origin - prepared.preparation_started,
                )
            else:
                window.readiness(end, trail=trail)
            if dcgm:
                wait = (
                    WAIT_S
                    if (prepared.arm, prepared.cycle) == ("fixed-1", 1)
                    else LATER_WAIT_S
                )
                witness = require_dcgm(window, receipt, node_role=role, wait_s=wait)
            yield window
        finally:
            if witness is not None:
                witness["before_uninstall"] = capture_memory(
                    window,
                    min(self.cleanup_end, time.monotonic() + CADVISOR_S),
                    role,
                )
                write_receipt(receipt, witness)
            for process, logfile in c.forwarders[forwarders:]:
                try:
                    process.terminate()
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                finally:
                    logfile.close()
            del c.forwarders[forwarders:]

    def release(self, arm, cycle, values, end):
        return self.helm.release(
            arm,
            cycle,
            {**values, "dcgm": {"enabled": self.dcgm_enabled(arm, cycle)}},
            end,
        )


def configure_mock_dcgm(cluster, end, *, crash=False):
    spec = {
        "nodeSelector": {"m5-role": "cpu", "inf054-dcgm": "true"},
        "volumes": [{"name": "mock", "configMap": {"name": "inf054-engine"}}],
        "containers": [
            {
                "name": "dcgm-exporter",
                "image": cluster.client_image,
                "command": ["python", "-u", "/mock/engine.py"],
                "env": [
                    {"name": "INF054_MOCK_DCGM", "value": "1"},
                    {"name": "INF054_MOCK_DCGM_CRASH", "value": "1" if crash else "0"},
                    {"name": "PORT", "value": "9400"},
                ],
                "resources": {
                    "requests": {"cpu": "100m", "memory": "1Gi"},
                    "limits": {"cpu": "500m", "memory": "1Gi"},
                },
                "ports": [{"name": "metrics", "containerPort": 9400}],
                "volumeMounts": [{"name": "mock", "mountPath": "/mock"}],
                "readinessProbe": {
                    "httpGet": {"path": "/health", "port": "metrics"},
                    "periodSeconds": 2,
                },
            }
        ],
    }
    cluster.k(
        "patch",
        "daemonset",
        "dcgm-exporter",
        "--type=json",
        "-p",
        json.dumps([{"op": "replace", "path": "/spec/template/spec", "value": spec}]),
        deadline=end,
    )


class ClusterWindow:
    def __init__(
        self,
        cluster,
        client,
        port,
        sha256,
        arm,
        *,
        rehearsal_burst_s=None,
        gpu_metrics=False,
        long_downscale=False,
    ):
        self.cluster = cluster
        self.client = pod_name(client)
        self.node = (client.get("spec") or {}).get("nodeName")
        if not self.node:
            raise ValueError("inf054_client_node")
        self.url = f"http://127.0.0.1:{port}"
        self.sha256 = sha256
        self.arm = arm
        self.rehearsal_burst_s = rehearsal_burst_s
        self.gpu_metrics = gpu_metrics
        self.long_downscale = long_downscale
        self.ordinals = {}
        self.scale = []
        self.origin = time.monotonic()
        self.per_replica_scrapes = {}
        self.scale_out = None
        self.null_endpoint_slices = 0
        self.absent_endpoint_slices = 0

    def k(self, deadline, *args, **bounds):
        return self.cluster.k(*args, deadline=deadline, **bounds)

    def get(self, end, kind, *args):
        body = self.k(end, "get", kind, *args, "-o", "json")
        return (json.loads(body) or {}) if body.strip() else {}

    def probe(self, end, mode):
        rehearsal_args = (
            ("--rehearsal-burst-seconds", str(self.rehearsal_burst_s))
            if mode == "window" and self.rehearsal_burst_s is not None
            else ()
        )
        reply = self.k(
            end,
            "exec",
            self.client,
            "-c",
            "client",
            "--",
            "python",
            "-m",
            "inference_platform.inf054_eks_client",
            "--mode",
            mode,
            "--tape",
            "/results/tape.jsonl",
            "--sha256",
            self.sha256,
            "--deadline",
            str(time.time() + end - time.monotonic() - 1),
            *rehearsal_args,
            # The pod's application deadline cannot bound the outer kubectl exec.
            timeout=end - time.monotonic(),
        )
        if len(reply) > 4 * 1024**2:
            raise ValueError("inf054_client_reply_size")
        return json.loads(reply)

    def engine_pods(self, end):
        return self.get(end, "pods", "-l", "app=vllm").get("items") or []

    def engine_slices(self, end):
        return (
            self.get(
                end, "endpointslices", "-l", "kubernetes.io/service-name=vllm"
            ).get("items")
            or []
        )

    def membership(self, end):
        return self.membership_states(self.engine_pods(end), self.engine_slices(end))

    def membership_states(self, pods, slices):
        if pods is None:
            return None
        self.null_endpoint_slices += sum(
            "endpoints" in group and group["endpoints"] is None
            for group in (slices or [])
        )
        self.absent_endpoint_slices += sum(
            "endpoints" not in group for group in (slices or [])
        )
        eligible = {
            uid
            for group in (slices or [])
            for endpoint in group.get("endpoints") or []
            if (endpoint.get("conditions") or {}).get("ready") is True
            if (uid := (endpoint.get("targetRef") or {}).get("uid"))
        }
        states = []
        for pod in pods:
            ordinal = replica(pod)
            metadata = pod.get("metadata") or {}
            uid = metadata.get("uid")
            if not uid:
                raise ValueError("inf054_engine_uid")
            node = (pod.get("spec") or {}).get("nodeName")
            if node == self.node:
                raise ValueError("inf054_client_engine_colocated")
            self.ordinals[uid] = ordinal
            terminating = bool(metadata.get("deletionTimestamp"))
            states.append(
                {
                    "ordinal": ordinal,
                    "scheduled": bool(node),
                    "started": (pod.get("status") or {}).get("phase") == "Running",
                    "ready": uid in eligible and not terminating
                    if slices is not None
                    else None,
                    "terminating": terminating,
                }
            )
        return sorted(states, key=lambda row: row["ordinal"])

    def desired(self, end):
        spec = self.get(end, "statefulset", "vllm").get("spec") or {}
        # apps/v1 defaults an unspecified replica count to one.
        replicas = spec.get("replicas")
        return 1 if replicas is None else replicas

    def readiness(self, end, *, trail=None, preparation_s=None):
        def record(event, **fields):
            if trail is not None:
                with trail.open("a", encoding="utf-8", newline="\n") as stream:
                    stream.write(
                        json.dumps(
                            {
                                "at_s": time.monotonic() - self.origin,
                                "event": event,
                                **fields,
                            }
                        )
                        + "\n"
                    )

        expected = 2 if self.arm == "fixed-2" else 1
        if preparation_s is not None:
            record(
                "prepared", elapsed_s=preparation_s, readiness_bound_s=end - self.origin
            )
        until = None
        probe_completed = False
        while end - (now := time.monotonic()) >= READINESS_POLL_S:
            try:
                members = self.membership(now + READINESS_POLL_S)
            except (TimeoutError, subprocess.TimeoutExpired):
                record("membership_poll_timeout")
                continue
            record(
                "membership",
                replicas=members,
                null_endpoint_slices=self.null_endpoint_slices,
                absent_endpoint_slices=self.absent_endpoint_slices,
            )
            if sum(row["ready"] for row in members) == expected:
                until = until or time.monotonic() + READY_HOLD_S
                if time.monotonic() >= until:
                    if not probe_completed:
                        now = time.monotonic()
                        if end - now < READY_PROBE_S:
                            break
                        receipt = self.probe(now + READY_PROBE_S, "readiness")
                        probe_completed = receipt["rows"][0]["outcome"] == "completed"
                        record("readiness_probe", completed=probe_completed)
                    if probe_completed:
                        metric = None
                        if self.arm == "keda":
                            now = time.monotonic()
                            if end - now < READINESS_POLL_S:
                                break
                            try:
                                metric = self.external_metrics(now + READINESS_POLL_S)
                            except (TimeoutError, subprocess.TimeoutExpired):
                                record("external_metric_poll_timeout")
                        if self.arm != "keda" or metric is not None:
                            record("ready", expected=expected, external_metric=metric)
                            return
            else:
                until = None
                probe_completed = False
            time.sleep(0.25)
        record("readiness_timeout", expected=expected)
        raise TimeoutError("inf054_ready_or_membership")

    def external_metrics(self, end):
        hpa = self.get(end, "hpa", "keda-hpa-vllm", "--ignore-not-found")
        spec = hpa.get("spec") or {}
        metrics = spec.get("metrics") or []
        if not metrics:
            return None
        candidates = [row["external"] for row in metrics if row.get("external")]
        if len(candidates) != 1:
            raise ValueError("inf054_external_metric_count")
        [external] = candidates
        if external.get("target") != {"type": "AverageValue", "averageValue": "2"}:
            raise ValueError("inf054_external_target")
        scale_down = (spec.get("behavior") or {}).get("scaleDown") or {}
        if scale_down.get("stabilizationWindowSeconds") != 900:
            raise ValueError("inf054_hpa_stabilization")
        name = (external.get("metric") or {}).get("name")
        if not name:
            raise ValueError("inf054_external_metric_name")
        metric = urllib.parse.quote(name, safe="")
        selector = urllib.parse.urlencode(
            {"labelSelector": "scaledobject.keda.sh/name=vllm"}
        )
        route = f"/apis/external.metrics.k8s.io/v1beta1/namespaces/{self.cluster.namespace}/{metric}?{selector}"
        items = json.loads(self.k(end, "get", "--raw", route)).get("items") or []
        if not items:
            return None
        return {
            "target": external["target"],
            "scale_down_stabilization_s": 900,
            "series": len(items),
        }

    def query(self, end, query):
        path = "/api/v1/query?" + urllib.parse.urlencode({"query": query})
        return read_json(self.url + path, end)["result"]

    def targets(self, end):
        return read_json(self.url + "/api/v1/targets?state=active", end)[
            "activeTargets"
        ]

    def scale_state(self, end):
        names = ["statefulset/vllm"]
        if self.arm == "keda":
            names.append("hpa/keda-hpa-vllm")
        result = self.get(end, *names, "--ignore-not-found")
        items = result.get("items") or [result]
        sts = next((row for row in items if row.get("kind") == "StatefulSet"), None)
        hpa = next(
            (row for row in items if row.get("kind") == "HorizontalPodAutoscaler"), {}
        )
        return (
            None if sts is None else (sts.get("spec") or {}).get("replicas", 1),
            (hpa.get("status") or {}).get("desiredReplicas"),
        )

    def observe(self, end):
        started = time.monotonic()
        errors = {}

        def read(name, function):
            try:
                return function()
            except SAMPLE_ERRORS as error:
                errors[name] = type(error).__name__
                return None

        pods = read("pods", lambda: self.engine_pods(end))
        slices = read("endpointslices", lambda: self.engine_slices(end))
        replicas = read("membership", lambda: self.membership_states(pods, slices))
        scale = read("statefulset_hpa", lambda: self.scale_state(end))
        want, hpa = scale if scale is not None else (None, None)
        if self.arm == "keda" and hpa is None and scale is not None:
            errors["hpa_desired"] = "MissingValue"
        if want is None and scale is not None:
            errors["desired"] = "MissingValue"
        self.scale.append(
            {
                "at_s": started - self.origin,
                "desired": want,
                "hpa_desired": hpa,
                "replicas": replicas,
                "read_errors": dict(errors),
            }
        )
        if self.arm == "keda" and want == 2 and self.scale_out is None:
            self.scale_out = time.monotonic()
        result = {
            "ready": sum(row["ready"] for row in replicas)
            if replicas is not None and slices is not None
            else None,
            "desired": want,
            "read_errors": errors,
        }
        # CPU proof has no DCGM exporter. A missing GPU series is only an
        # observer failure on the GPU path.
        for field, query in PROMQL.items():
            if not self.gpu_metrics and field in {
                "gpu_memory_mib",
                "dcgm_gpu_util_pct",
            }:
                continue
            result[field] = read(field, lambda: self.read_gauge(end, field, query))
        return result

    def read_gauge(self, end, field, query):
        series = self.query(end, query)
        if field == "scrape":
            seen = {}
            for row in series:
                match = re.fullmatch(
                    r"vllm-([01])\.vllm:[0-9]+", row["metric"]["instance"]
                )
                if match:
                    seen[int(match[1])] = row["value"][1] == "1"
            self.per_replica_scrapes = {str(i): seen.get(i) for i in range(2)}
            return self.per_replica_scrapes
        return float(series[0]["value"][1]) if len(series) == 1 else None

    def window(self, end):
        return self.safe_rows(self.probe(end, "window"))

    def safe_rows(self, reply):
        for row in reply["rows"]:
            row["replica_ordinal"] = self.ordinals.get(row.pop("uid", None))
        return reply["rows"]

    def downscale(self, end):
        """Observe actual KEDA action while keeping in-flight probes in the client pod."""
        if self.long_downscale:
            return self.gpu_downscale(end)
        from concurrent.futures import ThreadPoolExecutor

        if self.scale_out is None:
            return {"observed": False, "reason": "no_scale_out"}
        marker = self.scale_out + 810
        while time.monotonic() < min(end, marker):
            if self.desired(end) == 1:
                return {"observed": False, "reason": "scale_down_before_probe"}
            time.sleep(min(1, max(0, marker - time.monotonic())))
        if end - time.monotonic() < 355:
            return {"observed": False, "reason": "probe_deadline"}
        stopped = None
        with ThreadPoolExecutor(max_workers=1) as worker:
            pending = worker.submit(self.probe, end, "downscale")
            while not pending.done():
                if self.desired(end) == 1:
                    stopped = time.time()
                    break
                time.sleep(0.25)
            reply = pending.result(timeout=max(0, end - time.monotonic()))
        rows = self.safe_rows(reply)
        at = None if stopped is None else stopped - reply["start_epoch"]
        overlap = [
            row["outcome"]
            for row in rows
            if at is not None
            and row["replica_ordinal"] == 1
            and row.get("ttft_s") is not None
            and row["dispatch_s"] + row["ttft_s"]
            < at
            < row["dispatch_s"] + row["closed_s"]
        ]
        return {
            "observed": stopped is not None,
            "probe_stop_s": at,
            "probe_overlaps": overlap,
            "probes": rows,
            "precontent_502": sum(row.get("http_status") == 502 for row in rows),
        }

    def gpu_downscale(self, end):
        """Keep offering until the ordinal leaves discovery and Kubernetes."""
        from collections import Counter
        from concurrent.futures import ThreadPoolExecutor

        observations = {
            "desired_one": None,
            "pod_deletion_timestamp": None,
            "termination_first_seen": None,
            "termination_started_estimate": None,
            "endpoint_last_seen": None,
            "endpoint_removed": None,
            "pod_gone": None,
        }
        errors = Counter()

        def read(name, readout):
            try:
                return readout()
            except SAMPLE_ERRORS as error:
                errors[f"{name}:{type(error).__name__}"] += 1
                return None

        # The stable ordinal name identifies the disappearing endpoint even
        # while its Ready condition is false. Do not use a failed read as absence.
        with ThreadPoolExecutor(max_workers=1) as worker:
            pending = worker.submit(self.probe, end, "gpu-downscale")
            while time.monotonic() + READINESS_POLL_S < end:
                if pending.done() and pending.exception() is not None:
                    break
                cutoff = time.monotonic() + READINESS_POLL_S
                desired = read("replicas", lambda: self.desired(cutoff))
                if desired == 1 and observations["desired_one"] is None:
                    observations["desired_one"] = time.time()
                pod = read(
                    "pod",
                    lambda: self.get(cutoff, "pod", "vllm-1", "--ignore-not-found"),
                )
                if pod is not None:
                    metadata = pod.get("metadata") or {}
                    deletion = metadata.get("deletionTimestamp")
                    if deletion and observations["pod_deletion_timestamp"] is None:
                        observations["pod_deletion_timestamp"] = datetime.fromisoformat(
                            deletion
                        ).timestamp()
                        observations["termination_first_seen"] = time.time()
                        if (
                            grace := metadata.get("deletionGracePeriodSeconds")
                        ) is not None:
                            observations["termination_started_estimate"] = (
                                observations["pod_deletion_timestamp"] - grace
                            )
                    if not pod and observations["pod_gone"] is None and desired == 1:
                        observations["pod_gone"] = time.time()
                slices = read("endpoints", lambda: self.engine_slices(cutoff))
                if slices is not None:
                    names = {
                        (endpoint.get("targetRef") or {}).get("name")
                        for group in slices
                        for endpoint in group.get("endpoints") or []
                    }
                    if "vllm-1" in names:
                        observations["endpoint_last_seen"] = time.time()
                        observations["endpoint_removed"] = None
                    elif (
                        "vllm-0" in names
                        and observations["endpoint_last_seen"] is not None
                        and observations["endpoint_removed"] is None
                    ):
                        observations["endpoint_removed"] = time.time()
                if (
                    observations["endpoint_removed"] is not None
                    and observations["pod_gone"] is not None
                ):
                    if pending.done():
                        break
                    confirmation = read(
                        "stop_probe",
                        lambda: self.k(
                            min(end, time.monotonic() + READINESS_POLL_S),
                            "exec",
                            self.client,
                            "-c",
                            "client",
                            "--",
                            "touch",
                            LONG_PROBE_STOP,
                        ),
                    )
                    if confirmation is not None:
                        break
                time.sleep(max(0, min(1, cutoff - time.monotonic())))
            reply = pending.result(timeout=max(0, end - time.monotonic()))
        rows = self.safe_rows(reply)
        relative = {
            name: None if at is None else at - reply["start_epoch"]
            for name, at in observations.items()
        }
        overlap = {
            name: overlapping_streams(rows, at)
            for name, at in relative.items()
            if name != "endpoint_last_seen"
        }
        return {
            "observed": observations["desired_one"] is not None,
            "probe_stop_s": relative["desired_one"],
            "probe_overlaps": [row["outcome"] for row in overlap["desired_one"]],
            "output_cap": LONG_PROBE_CAP,
            "events_epoch": observations,
            "events_since_probe_s": relative,
            "overlap": overlap,
            "removal_observed": relative["endpoint_removed"] is not None
            and relative["pod_gone"] is not None,
            "read_errors": dict(errors),
            "probes": rows,
            "precontent_502": sum(row.get("http_status") == 502 for row in rows),
        }

    def freeze_tsdb(self, end):
        name = read_json(
            self.url + "/api/v1/admin/tsdb/snapshot?skip_head=false", end, post=True
        )["name"]
        if not SNAPSHOT_NAME.fullmatch(name):
            raise ValueError("inf054_snapshot_name")
        [pod] = self.get(end, "pods", "-l", "app=telemetry").get("items") or []
        target = pod_name(pod)
        archive = "/data/inf054-snapshot.tar.gz"
        # The Prometheus image contains BusyBox tar and sha256sum.
        self.k(
            end,
            "exec",
            target,
            "--",
            "sh",
            "-ec",
            'cd "/data/snapshots/$1"; find . -type f -print | sed "s|^./||" | tar -czf "$2" -T -',
            "sh",
            name,
            archive,
            timeout=end - time.monotonic(),
        )
        size = int(self.k(end, "exec", target, "--", "wc", "-c", archive).split()[0])
        digest = self.k(
            end,
            "exec",
            target,
            "--",
            "sha256sum",
            archive,
            timeout=end - time.monotonic(),
        ).split()[0]
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("inf054_snapshot_digest")

        def read(offset, wanted, deadline):
            if offset % 1024**2 or not 0 < wanted <= 1024**2:
                raise ValueError("inf054_snapshot_chunk")
            chunk = self.k(
                deadline,
                "exec",
                target,
                "--",
                "sh",
                "-ec",
                'dd if="$1" bs=1048576 skip="$2" count=1 2>/dev/null | base64',
                "sh",
                archive,
                str(offset // 1024**2),
            )
            return base64.b64decode("".join(chunk.split()), validate=True)

        return {"bytes": size, "sha256": digest}, read
