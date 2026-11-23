"""Shared Kubernetes-side DEC-100 operations for kind and EKS adapters."""

import base64
import hashlib
import json
import shutil
import socket
import subprocess
import time
from pathlib import Path

from .command_diagnostics import checked_process, stderr_tail
from .m5_descriptive_client import client_resources
from .m5_descriptive_operator import (
    TASK_CONTROL_MARGIN_SECONDS,
    file_inventory,
    task_poll_budget,
    task_work_seconds,
)
from .package_a_workload import test_tls_command, write_kind_secret

ROOT = Path(__file__).resolve().parents[3]


class ClusterPorts:
    def call(self, argv, timeout=180):
        started = time.monotonic()
        try:
            result = checked_process(
                list(map(str, argv)),
                cwd=ROOT,
                capture_output=True,
                timeout=timeout,
                secrets=(getattr(self, "credential", ""),),
            )
        except subprocess.CalledProcessError as error:
            self.commands.append(
                {
                    "argv": [str(argv[0])],
                    "exit_code": error.returncode,
                    "elapsed_s": time.monotonic() - started,
                }
            )
            (self.output / "failure.stderr").write_text(str(error))
            raise
        self.commands.append(
            {
                "argv": list(map(str, argv)),
                "exit_code": result.returncode,
                "elapsed_s": time.monotonic() - started,
            }
        )
        return result.stdout.decode()

    def k(self, *args, deadline=None):
        requested = [arg for arg in args if str(arg).startswith("--timeout=")]
        timeout = (
            float(str(requested[-1]).split("=", 1)[1].removesuffix("s")) + 30 if requested else 180
        )
        if deadline is not None:
            timeout = min(timeout, deadline - time.monotonic())
            if timeout <= 0:
                raise TimeoutError("descriptive:readiness_deadline")
        return self.call(
            [
                self.campaign.kubectl,
                "--kubeconfig",
                self.kubeconfig,
                "--context",
                self.context,
                "-n",
                self.namespace,
                *args,
            ],
            timeout=timeout,
        )

    def wait(self, predicate, seconds=120, *, deadline=None):
        end = min(
            self.deadline,
            time.monotonic() + seconds,
            deadline if deadline is not None else self.deadline,
        )
        while time.monotonic() < end:
            if predicate():
                return
            time.sleep(min(0.25, max(0, end - time.monotonic())))
        raise TimeoutError("descriptive:readiness_deadline")

    def forward(self, target, remote):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        log = (self.output / f"forward-{port}.log").open("wb")
        process = subprocess.Popen(
            [
                str(self.campaign.kubectl),
                "--kubeconfig",
                str(self.kubeconfig),
                "--context",
                self.context,
                "-n",
                self.namespace,
                "port-forward",
                target,
                f"{port}:{remote}",
                "--address",
                "127.0.0.1",
            ],
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        self.forwarders.append((process, log))

        def ready():
            if process.poll() is not None:
                raise RuntimeError("descriptive:forward_exited")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                    return True
            except OSError:
                return False

        self.wait(ready, 20)
        return port

    def tenant_configuration(self):
        tenants = json.loads((ROOT / "deploy/local/tenants.json").read_bytes())
        for tenant in tenants["tenants"]:
            tenant["tenant_id"] = self.tenant_id
            tenant["credential_sha256"] = hashlib.sha256(self.credential.encode()).hexdigest()
            tenant["models"] = [self.model]
            tenant["max_concurrent"] = 64
            tenant["request_rate_limit"] = 10000
            tenant["request_rate_window_ms"] = 1000
        return tenants

    def client_credentials(self):
        return {
            "token": self.credential,
            "tenant_id": self.tenant_id,
            "model": self.model,
            "corpus": self.corpus,
        }

    def client_job(self):
        return client_resources(self.namespace, self.client_image, self.deadline_epoch)

    def deploy(self, source):
        manifest = self.render_manifest(source)
        namespace_file = self.output / "namespace.json"
        namespace_file.write_text(
            json.dumps(
                {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": self.namespace}}
            )
        )
        self.k("apply", "-f", namespace_file)
        secret = self.output / "cache-salt.secret"
        write_kind_secret(secret)
        # Rehearsal and real session use the same admission-neutral tenant budget.
        tenants_path = self.output / "tenants.secret"
        tenants_path.write_text(json.dumps(self.tenant_configuration()))
        self.k(
            "create",
            "secret",
            "generic",
            "gateway-config",
            "--from-file=tenants.json=" + str(tenants_path),
            "--from-file=cache-salt.secret=" + str(secret),
        )
        command = test_tls_command(self.output)
        command += [
            "-addext",
            f"subjectAltName=DNS:localhost,DNS:streaming-ingress,DNS:streaming-ingress.{self.namespace}.svc,DNS:streaming-ingress.{self.namespace}.svc.cluster.local,IP:127.0.0.1",
        ]
        self.call(command)
        self.k(
            "create",
            "secret",
            "tls",
            "gateway-tls",
            "--cert=" + str(self.output / "tls.crt"),
            "--key=" + str(self.output / "tls.key"),
        )
        path = self.output / "resources.json"
        path.write_text(json.dumps(manifest))
        self.k("apply", "-f", path)
        for kind, name in (
            ("deployment", "redis"),
            ("statefulset", "vllm"),
            ("statefulset", "gateway"),
            ("deployment", "streaming-ingress"),
            ("deployment", "telemetry"),
        ):
            timeout = f"--timeout={self.startup_seconds}s"
            if kind == "statefulset":
                self.k(
                    "wait", "--for=jsonpath={.status.readyReplicas}=2", kind + "/" + name, timeout
                )
            else:
                self.k("rollout", "status", kind + "/" + name, timeout)
        credential_path = self.output / "client.secret"
        credential_path.write_text(json.dumps(self.client_credentials()))
        self.k(
            "create",
            "secret",
            "generic",
            "load-client",
            "--from-file=client.json=" + str(credential_path),
        )
        self.k(
            "create",
            "configmap",
            "load-client-ca",
            "--from-file=tls.crt=" + str(self.output / "tls.crt"),
        )
        client = self.client_job()
        client_path = self.output / "client-job.json"
        client_path.write_text(json.dumps(client))
        self.k("apply", "-f", client_path)
        self.k(
            "wait", "--for=condition=Ready", "pod", "-l", "job-name=load-client", "--timeout=180s"
        )
        pod = json.loads(self.k("get", "pods", "-l", "job-name=load-client", "-o", "json"))["items"]
        if len(pod) != 1:
            raise ValueError("descriptive:one_client_job_required")
        pod = pod[0]
        self.client_pod = pod["metadata"]["name"]
        self.client_placement = {
            "node": pod["spec"]["nodeName"],
            "node_sha256": hashlib.sha256(pod["spec"]["nodeName"].encode()).hexdigest(),
            "node_role": "cpu",
            "image_digest": pod["status"]["containerStatuses"][0]["imageID"].split("@")[-1],
        }
        # Only control, observation and retrieval use kubectl. No load port forward.
        self.metrics_endpoints = ()
        return {
            "source_manifest_sha256": hashlib.sha256(
                json.dumps(source, sort_keys=True).encode()
            ).hexdigest(),
            "deployed_manifest_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "client_placement": self.client_placement,
            "scaling": "fixed",
        }

    def client_control(self, mode, *args, deadline=None):
        return json.loads(
            self.k(
                "exec",
                self.client_pod,
                "--",
                "python",
                "-m",
                "inference_platform.m5_descriptive_client",
                mode,
                *args,
                deadline=deadline,
            )
        )

    def start_task(self, label, kind="load", *, started=None, **values):
        task = {"kind": kind, "label": label, **values}
        if hasattr(self, "work_deadline_epoch"):
            task["deadline_epoch"] = self.work_deadline_epoch
        started = time.monotonic() if started is None else started
        budget = task_poll_budget(task, self.startup_seconds, self.rollout_action)
        cutoff = min(self.deadline, started + budget)
        receipt = {
            "kind": kind,
            "levels": task.get("levels", []),
            "duration_s": task.get("duration"),
            "replacement": "replacement" in task,
            "max_work_s": task_work_seconds(task, self.startup_seconds, self.rollout_action),
            "control_margin_s": TASK_CONTROL_MARGIN_SECONDS,
            "poll_budget_s": budget,
            "effective_budget_s": max(0, cutoff - started),
            "started_monotonic": started,
            "status": "SUBMITTING",
        }
        self.results.setdefault("task_polls", {})[label] = receipt
        if not hasattr(self, "_task_deadlines"):
            self._task_deadlines = {}
        self._task_deadlines[label] = cutoff
        encoded = base64.b64encode(json.dumps(task, sort_keys=True).encode()).decode()
        result = self.client_control(
            "submit", encoded, deadline=min(cutoff, started + TASK_CONTROL_MARGIN_SECONDS)
        )
        receipt["status"] = "SUBMITTED"
        return result

    def finish_task(self, label):
        holder = []
        receipt = self.results["task_polls"][label]
        cutoff = self._task_deadlines[label]
        poll_started = time.monotonic()

        def done():
            try:
                result = self.client_control("status", label, deadline=cutoff)
            except subprocess.TimeoutExpired as error:
                if time.monotonic() >= cutoff:
                    raise TimeoutError("descriptive:readiness_deadline") from error
                raise
            if result["status"] == "FAILED":
                raise ValueError(result["error"])
            if result["status"] == "PASS":
                holder.append(result["result"])
                return True
            return False

        try:
            self.wait(done, receipt["poll_budget_s"], deadline=cutoff)
        except Exception:
            receipt["status"] = "FAILED"
            raise
        else:
            receipt["status"] = "PASS"
        finally:
            finished = time.monotonic()
            receipt["elapsed_s"] = finished - receipt["started_monotonic"]
            receipt["poll_elapsed_s"] = finished - poll_started
        return holder[0]

    def smoke(self):
        if self.deadline - time.monotonic() < self.minimum_workload_seconds:
            raise TimeoutError("descriptive:remaining_workload_window")
        self.start_task("smoke", "smoke")
        value = self.finish_task("smoke")
        cutoff = self._task_deadlines["smoke"]
        services = json.loads(self.k("get", "services", "-o", "json", deadline=cutoff))["items"]
        if any(s["spec"]["type"] != "ClusterIP" for s in services):
            raise ValueError("descriptive:public_service")
        counts = {}
        for app in ("gateway", "vllm"):
            pods = json.loads(
                self.k("get", "pods", "-l", "app=" + app, "-o", "json", deadline=cutoff)
            )["items"]
            counts[app] = len({p["metadata"]["uid"] for p in pods})
        if counts != {"gateway": 2, "vllm": 2}:
            raise ValueError("descriptive:smoke_topology")
        value.update(
            uid_counts=counts, services="ClusterIP", client_placement=self.client_placement
        )
        self.results["smoke"] = value
        return value

    def load(self, levels):
        self.start_task("warmup", levels=[1], duration=self.warmup_duration)
        self.results["warmup"] = self.finish_task("warmup")
        self.start_task("load", levels=list(levels), duration=self.load_duration)
        value = self.finish_task("load")
        if not all(row["summary"]["completed"] for row in value["levels"]):
            raise ValueError("descriptive:no_completed_load")
        if self.substitutions and any(row["summary"]["rejected"] for row in value["levels"]):
            raise ValueError("descriptive:healthy_rehearsal_rejected")
        self.results["load"] = value
        return value

    def rollout(self, app):
        started = time.monotonic()
        target = app + "-0"
        before = json.loads(
            self.k(
                "get",
                "pod",
                target,
                "-o",
                "json",
                deadline=min(self.deadline, started + TASK_CONTROL_MARGIN_SECONDS),
            )
        )
        old_uid = before["metadata"]["uid"]
        label = app + "_rollout"
        duration = (
            self.rollout_durations[app]
            if hasattr(self, "rollout_durations")
            else self.rollout_duration
        )
        self.start_task(
            label,
            started=started,
            levels=[4],
            duration=duration,
            replacement={
                "target": target,
                "old_uid": old_uid,
                "observe_seconds": self.rollout_action
                + self.startup_seconds
                + TASK_CONTROL_MARGIN_SECONDS,
            },
        )
        time.sleep(min(self.rollout_action, max(0, self.deadline - time.monotonic())))
        action = time.monotonic()
        cutoff = self._task_deadlines[label]
        end = min(cutoff, action + self.startup_seconds)
        self.k("delete", "pod", target, "--wait=false", deadline=end)
        excluded = None
        replacement = None
        while time.monotonic() < end:
            endpoints = json.loads(
                self.k(
                    "get",
                    "endpointslices",
                    "-l",
                    "kubernetes.io/service-name=" + app,
                    "-o",
                    "json",
                    deadline=end,
                )
            )
            included = any(
                e.get("targetRef", {}).get("uid") == old_uid
                and e.get("conditions", {}).get("ready") is True
                and not e.get("conditions", {}).get("terminating", False)
                for item in endpoints["items"]
                for e in item.get("endpoints", [])
            )
            if not included and excluded is None:
                excluded = time.monotonic() - action
            pod = json.loads(self.k("get", "pods", "-l", "app=" + app, "-o", "json", deadline=end))[
                "items"
            ]
            replacement = next(
                (
                    p
                    for p in pod
                    if p["metadata"]["name"] == target
                    and p["metadata"]["uid"] != old_uid
                    and any(
                        c["type"] == "Ready" and c["status"] == "True"
                        for c in p.get("status", {}).get("conditions", [])
                    )
                ),
                None,
            )
            if replacement and excluded is not None:
                break
            time.sleep(min(0.25, max(0, end - time.monotonic())))
        if replacement is None or excluded is None:
            raise TimeoutError("descriptive:replacement_readiness")
        ready = time.monotonic() - action
        remote = 8000 if app == "vllm" else 8080
        observed = self.client_control(
            "observe",
            f"http://{replacement['status']['podIP']}:{remote}/"
            + ("health" if app == "vllm" else "readyz"),
            deadline=cutoff,
        )
        if observed["status"] != 200:
            raise ValueError("descriptive:replacement_health")
        health = time.monotonic() - action
        outcome = self.finish_task(label)
        record = {
            "app": app,
            "old_generation_sha256": hashlib.sha256(old_uid.encode()).hexdigest(),
            "endpoint_excluded_observed_s": excluded,
            "replacement_ready_observed_s": ready,
            "replacement_health_observed_s": health,
            "client": outcome,
            "gateway_internal_exclusion": "unavailable; EndpointSlice observation only",
            "max_surge": 0,
        }
        self.results[label] = record
        return record

    def retrieve_clients(self):
        directory = self.output / "clients"
        directory.mkdir()
        inventory = self.client_control("inventory")
        for name, facts in inventory.items():
            path = (directory / name).resolve()
            if not path.is_relative_to(directory.resolve()):
                raise ValueError("descriptive:client_retrieval_path")
            with path.open("xb") as handle:
                offset = 0
                while offset < facts["bytes"]:
                    block = base64.b64decode(
                        self.client_control("read", name, str(offset))["base64"], validate=True
                    )
                    if not block or len(block) > min(65536, facts["bytes"] - offset):
                        raise ValueError("descriptive:client_retrieval_length")
                    handle.write(block)
                    offset += len(block)
        if file_inventory(directory) != inventory:
            raise ValueError("descriptive:client_retrieval_hash")
        return inventory

    def export(self):
        client_present = hasattr(self, "client_pod")
        clients = self.retrieve_clients() if client_present else None
        directory = self.output / "frozen"
        directory.mkdir()
        (directory / "client-records.json").write_text(
            json.dumps(
                {
                    "status": "present" if client_present else "absent",
                    "reason": None if client_present else "client_pod_not_created",
                    "inventory": clients,
                },
                sort_keys=True,
            )
        )
        observations = {}
        observed = {}
        for kind in ("events", "pods"):
            try:
                observed[kind] = json.loads(self.k("get", kind, "-o", "json"))["items"]
                observations[kind] = {"status": "present", "count": len(observed[kind])}
            except Exception as error:
                if client_present:
                    raise
                observations[kind] = {
                    "status": "unavailable",
                    "error": stderr_tail(str(error), secrets=(getattr(self, "credential", ""),)),
                }
                observed[kind] = []
        (directory / "observations.json").write_text(json.dumps(observations, sort_keys=True))
        events = observed["events"]
        (directory / "events.json").write_text(
            json.dumps(
                [
                    {
                        "type": e.get("type"),
                        "reason": e.get("reason"),
                        "count": e.get("count", 1),
                    }
                    for e in events
                ],
                sort_keys=True,
            )
        )
        (directory / "results.json").write_text(json.dumps(self.results, sort_keys=True))
        (directory / "pod-states.json").write_text(
            json.dumps(
                [
                    {
                        "name": pod["metadata"]["name"],
                        "uid_sha256": hashlib.sha256(pod["metadata"]["uid"].encode()).hexdigest(),
                        "phase": pod.get("status", {}).get("phase"),
                        "conditions": [
                            {
                                key: condition.get(key)
                                for key in ("type", "status", "lastTransitionTime")
                            }
                            for condition in pod.get("status", {}).get("conditions", [])
                        ],
                    }
                    for pod in observed["pods"]
                ],
                sort_keys=True,
            )
        )
        if client_present:
            shutil.copytree(self.output / "clients", directory / "clients")
        logs = getattr(self, "phase_logs", None)
        if logs is not None:
            destination = directory / "phase-logs"
            destination.mkdir()
            for source in sorted(Path(logs).glob("*.log")):
                with source.open("rb") as handle:
                    handle.seek(0, 2)
                    handle.seek(max(0, handle.tell() - 8192))
                    tail = stderr_tail(
                        handle.read(8192), secrets=(getattr(self, "credential", ""),)
                    )
                (destination / source.name).write_text(tail)
        if not client_present:
            return file_inventory(directory)
        # Collect all four independent serving endpoints, not a Service sample.
        for app, remote in (("gateway", 8080), ("vllm", 8000)):
            for index in range(2):
                pod = json.loads(self.k("get", "pod", f"{app}-{index}", "-o", "json"))
                observed = self.client_control(
                    "observe", f"http://{pod['status']['podIP']}:{remote}/metrics"
                )
                body = base64.b64decode(observed["base64"], validate=True)
                if len(body) > 2 * 1024**2:
                    raise ValueError("descriptive:scrape_limit")
                (directory / f"{app}-{index}.prom").write_bytes(body)
        return file_inventory(directory)

    def retrieve(self):
        destination = self.output / "retrieved"
        shutil.copytree(self.output / "frozen", destination)
        return file_inventory(destination)
