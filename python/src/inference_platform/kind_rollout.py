"""Create, measure and delete the CPU-only INF-037a kind cluster in one command."""

import argparse
import concurrent.futures
import hashlib
import http.client
import json
import os
import platform
import shutil
import statistics
import subprocess
import threading
import time
import urllib.request
from collections import Counter
from datetime import datetime
from pathlib import Path

from .kind_fake import STREAM_CHUNK_DELAY_MS, STREAM_CHUNKS

ROOT = Path(__file__).resolve().parents[3]
NAMESPACE = "mti-stage1"
CLUSTER = "mti-stage1"
WORKERS = 8
WORKER_STAGGER_SECONDS = 0.4
EXPECTED_CONTENT = "".join(f"token-{i} " for i in range(STREAM_CHUNKS))


def write_json(path, value):
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )


def run(*args, env=None, timeout=300, capture=True):
    result = subprocess.run(
        [str(arg) for arg in args],
        cwd=ROOT,
        env=env,
        timeout=timeout,
        check=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        text=True,
        encoding="utf-8",
    )
    return result.stdout.strip() if capture else ""


def unix_ns(value):
    seconds, _, fraction = value.removesuffix("Z").partition(".")
    return int(datetime.fromisoformat(seconds + "+00:00").timestamp()) * 1_000_000_000 + int(
        (fraction + "000000000")[:9]
    )


def generation(value):
    return hashlib.sha256(value.encode()).hexdigest()[:20]


def stream_result(events, status=200, transport_error=None):
    content, finish, done, usage, errors = "", False, False, False, 0
    finish_at, usage_at, done_at = [], [], []
    for index, event in enumerate(events):
        if event == "[DONE]":
            done = True
            done_at.append(index)
            continue
        try:
            value = json.loads(event)
            if "error" in value:
                errors += 1
            for choice in value.get("choices", []):
                content += choice.get("delta", {}).get("content", "")
                finish |= choice.get("finish_reason") == "stop"
                if choice.get("finish_reason") == "stop":
                    finish_at.append(index)
            usage |= value.get("usage", {}).get("completion_tokens") == STREAM_CHUNKS
            if "usage" in value:
                usage_at.append(index)
        except (ValueError, TypeError, AttributeError):
            errors += 1
    complete = (
        status == 200
        and done
        and finish
        and usage
        and not errors
        and content == EXPECTED_CONTENT
        and transport_error is None
        and len(finish_at) == len(usage_at) == len(done_at) == 1
        and finish_at[0] < usage_at[0] < done_at[0] == len(events) - 1
    )
    return {
        "outcome": "completed" if complete else "partial" if content else "failed",
        "content_bytes": len(content.encode()),
        "finish": finish,
        "done": done,
        "usage": usage,
        "error_events": errors,
        "false_complete": done and not complete,
    }


def request_stream(event, worker, sequence):
    started, start_wall = time.perf_counter_ns(), time.time_ns()
    events, error, status, request_id, first = [], None, 0, None, None
    connection = http.client.HTTPConnection("127.0.0.1", 18080, timeout=135)
    try:
        payload = json.dumps(
            {
                "model": "test-model",
                "messages": [{"role": "user", "content": "CPU rollout probe"}],
                "stream": True,
                "max_tokens": STREAM_CHUNKS,
            }
        )
        connection.request(
            "POST",
            "/v1/chat/completions",
            payload,
            {
                "Authorization": "Bearer local-dev-token",
                "Content-Type": "application/json",
            },
        )
        response = connection.getresponse()
        status, request_id = response.status, response.getheader("X-Request-ID")
        if status == 200:
            while line := response.readline():
                if line.startswith(b"data: "):
                    if first is None:
                        first = (time.perf_counter_ns() - started) / 1e6
                    events.append(line[6:].decode("utf-8").strip())
        else:
            response.read()
    except (OSError, http.client.HTTPException, UnicodeError) as exc:
        error = type(exc).__name__
    finally:
        connection.close()
    return {
        "event": event,
        "worker": worker,
        "sequence": sequence,
        "request_id": request_id,
        "started_unix_ns": start_wall,
        "ended_unix_ns": time.time_ns(),
        "status": status,
        "duration_ms": (time.perf_counter_ns() - started) / 1e6,
        "first_event_ms": first,
        "transport_error": error,
        **stream_result(events, status, error),
    }


def distribution(values):
    values = sorted(values)
    if not values:
        return {"n": 0}
    return {
        "n": len(values),
        "min": values[0],
        "empirical_median": statistics.median(values),
        "mean": statistics.mean(values),
        "p95": values[int((len(values) - 1) * 0.95)] if len(values) >= 400 else None,
        "p95_sample_rule_met": len(values) >= 400,
        "max": values[-1],
    }


def pod_stream_coverage(rows, routes, terminals, pod, gen, service, deleted, sigterm):
    """Count routed requests until their gateway terminal timestamp.

    Deletion is the first observed deleting Pod snapshot (with a bracket in
    the stage), not the API's future deletion deadline. Backend intervals are
    gateway-observed; its real active count at SIGTERM is also required below.
    """
    intervals = []
    for row in rows:
        route = routes.get(row["request_id"])
        if route is None:
            continue
        matches = (
            route["pod"] == pod and route["pod_generation"] == gen
            if service == "gateway"
            else route.get("backend_id") == pod and route.get("backend_generation") == gen
        )
        if not matches:
            continue
        terminal = terminals.get(row["request_id"])
        if terminal is None:
            raise ValueError("coverage request lacks terminal timestamp")
        began = route["router_decision_unix_ns"]
        ended = terminal["time_unix_ns"]
        if ended < began:
            raise ValueError("coverage interval ends before routing")
        intervals.append((row["request_id"], began, ended))
    after = [
        {"request_id": rid, "terminal_unix_ns": end, "ran_after_sigterm_ms": (end - sigterm) / 1e6}
        for rid, begin, end in intervals
        if begin <= sigterm < end
    ]
    return {
        "streams_inflight_at_deletion": sum(begin <= deleted < end for _, begin, end in intervals),
        "streams_inflight_at_sigterm": len(after),
        "streams_after_sigterm": after,
        "last_stream_terminal_after_sigterm_ms": max(
            (r["ran_after_sigterm_ms"] for r in after), default=None
        ),
        "interval_basis": "gateway routing decision to gateway terminal; deletion first observed",
    }


def require_sigterm_coverage(stages):
    if not stages:
        raise ValueError("no terminated pods to validate")
    for stage in stages:
        if stage["streams_inflight_at_sigterm"] == 0:
            raise ValueError(f"zero streams at SIGTERM: {stage['pod']}")
        # The fake's own counter prevents mistaking downstream buffering for
        # an active backend request. Gateway intervals use its own logs.
        if stage.get("backend_active_at_sigterm") == 0:
            raise ValueError(f"zero backend requests at SIGTERM: {stage['pod']}")


class Campaign:
    def __init__(self, output):
        self.output = output
        self.pins = json.loads((ROOT / "deploy/k8s/pins.json").read_text())
        self.tools = ROOT / ".tools"
        self.tools.mkdir(exist_ok=True)
        self.kubeconfig = ROOT / ".cache/kind-stage1.config"
        self.logs, self.samples, self.streams, self.followers = [], [], [], {}
        self.lock = threading.Lock()
        self.observer_stop = threading.Event()
        self.observer_error = None

    def install_tools(self):
        if platform.machine().lower() not in {"amd64", "x86_64"}:
            raise ValueError("this pinned campaign supports amd64 only")
        system = "windows" if os.name == "nt" else "linux"
        suffix = ".exe" if os.name == "nt" else ""
        self.kind, self.kubectl = self.tools / ("kind" + suffix), self.tools / ("kubectl" + suffix)
        for path, url, key in [
            (
                self.kind,
                f"https://kind.sigs.k8s.io/dl/{self.pins['kind_version']}/kind-{system}-amd64",
                f"kind_{system}_amd64_sha256",
            ),
            (
                self.kubectl,
                f"https://dl.k8s.io/release/{self.pins['kubectl_version']}/bin/{system}/amd64/kubectl{suffix}",
                f"kubectl_{system}_amd64_sha256",
            ),
        ]:
            if not path.exists():
                with urllib.request.urlopen(url, timeout=60) as response:
                    path.write_bytes(response.read())
            if hashlib.sha256(path.read_bytes()).hexdigest() != self.pins[key]:
                raise ValueError(f"tool checksum mismatch: {path.name}")
            if os.name != "nt":
                path.chmod(0o755)
        if self.pins["kind_version"] not in run(self.kind, "version"):
            raise ValueError("kind version mismatch")
        if run("go", "version").split()[2] != "go1.26.6":
            raise ValueError("Go 1.26.6 required")
        if platform.python_version() != "3.12.7" or not run("uv", "--version").startswith(
            "uv 0.9.5 "
        ):
            raise ValueError("Python 3.12.7 and uv 0.9.5 required")

    def k(self, *args, **kwargs):
        return run(
            self.kubectl,
            "--kubeconfig",
            self.kubeconfig,
            "--context",
            f"kind-{CLUSTER}",
            "-n",
            NAMESPACE,
            *args,
            **kwargs,
        )

    def pods(self):
        return json.loads(self.k("get", "pods", "-o", "json"))["items"]

    def build(self):
        from .stage_c_tokenizer import cache_directory, verified_files

        verified_files(fetch=True)
        build = ROOT / ".cache/kind-build"
        build.mkdir(parents=True, exist_ok=True)
        env = dict(os.environ, GOOS="linux", GOARCH="amd64", CGO_ENABLED="0", GOTOOLCHAIN="local")
        run("go", "build", "-trimpath", "-o", build / "gateway", "./cmd/gateway", env=env)
        requirements = run(
            "uv",
            "export",
            "--project",
            "python",
            "--locked",
            "--group",
            "dev",
            "--no-emit-project",
            "--format",
            "requirements-txt",
        )
        (build / "requirements.txt").write_text(requirements + "\n", encoding="utf-8", newline="\n")
        shutil.copytree(
            ROOT / "python/src/inference_platform",
            build / "inference_platform",
            dirs_exist_ok=True,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
        shutil.copytree(
            cache_directory(), build / "tokenizer" / cache_directory().name, dirs_exist_ok=True
        )
        for name in ["gateway", "fake", "redis"]:
            run(
                "docker",
                "build",
                "--platform",
                "linux/amd64",
                "--provenance=false",
                "-t",
                f"mti-{name}:stage1",
                "-f",
                ROOT / f"deploy/k8s/{name}.Dockerfile",
                build,
                capture=False,
                timeout=600,
            )
        run("docker", "pull", self.pins["redis_image"], capture=False)
        self.image_ids = {
            name: run("docker", "image", "inspect", "--format", "{{.Id}}", name)
            for name in ["mti-gateway:stage1", "mti-fake:stage1", "mti-redis:stage1"]
        }
        paths = (
            list((ROOT / "cmd/gateway").glob("*.go"))
            + list((ROOT / "internal").rglob("*.go"))
            + list((ROOT / "python/src/inference_platform").glob("*.py"))
            + list((ROOT / "deploy/k8s").glob("*"))
            + [
                ROOT / "go.mod",
                ROOT / "go.sum",
                ROOT / "python/uv.lock",
                ROOT / "python/pyproject.toml",
                ROOT / "scripts/m5-stage1.ps1",
                ROOT / ".tool-versions",
                ROOT / "deploy/local/tenants.json",
                ROOT / "deploy/local/cache-salt.secret.example",
            ]
        )
        self.source_hashes = {
            str(p.relative_to(ROOT)).replace("\\", "/"): hashlib.sha256(
                p.read_bytes().replace(b"\r\n", b"\n")
            ).hexdigest()
            for p in paths
            if p.is_file()
        }

    def follow(self, pod):
        name, uid = pod["metadata"]["name"], pod["metadata"]["uid"]
        if not any(
            "running" in status.get("state", {})
            for status in pod.get("status", {}).get("containerStatuses", [])
        ):
            return
        if uid in self.followers:
            return
        process = subprocess.Popen(
            [
                str(self.kubectl),
                "--kubeconfig",
                str(self.kubeconfig),
                "-n",
                NAMESPACE,
                "logs",
                "-f",
                name,
                "--pod-running-timeout=60s",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
        )

        def consume():
            for line in process.stdout:
                try:
                    raw = json.loads(line)
                    msg = raw.get("msg")
                    if msg not in {
                        "gateway started",
                        "gateway draining",
                        "gateway stopped",
                        "last stream drained",
                        "request routed",
                        "request terminal",
                        "backend discovery changed",
                        "SIGTERM received",
                        "fake started",
                    }:
                        continue
                    # Exact allowlist: no credential, salt, address, prompt or raw API payload.
                    record = {
                        k: raw[k]
                        for k in [
                            "msg",
                            "request_id",
                            "backend_id",
                            "router_decision_unix_ns",
                            "cause",
                            "code",
                            "committed",
                            "duration_ms",
                            "grace_expired",
                            "active",
                            "signal",
                        ]
                        if k in raw
                    }
                    record.update(
                        pod=name,
                        pod_generation=generation(uid),
                        time_unix_ns=raw.get("time_unix_ns") or unix_ns(raw["time"]),
                    )
                    if "backend_generation" in raw:
                        record["backend_generation"] = (
                            generation(raw["backend_generation"])
                            if raw["backend_generation"]
                            else ""
                        )
                    if "backends" in raw and isinstance(raw["backends"], list):
                        record["backends"] = [
                            value.split("@")[0] + "@" + generation(value.split("@")[1])
                            for value in raw["backends"]
                        ]
                    if raw.get("error"):
                        record["discovery_error"] = True
                    with self.lock:
                        self.logs.append(record)
                except (ValueError, KeyError, TypeError):
                    continue
            process.stdout.close()

        thread = threading.Thread(target=consume)
        thread.start()
        self.followers[uid] = (process, thread)

    def observe(self):
        while not self.observer_stop.is_set():
            try:
                pods = self.pods()
                now = time.time_ns()
                for pod in pods:
                    if pod["metadata"]["labels"].get("app") in {"gateway", "fake"}:
                        self.follow(pod)
                        ready = any(
                            c["type"] == "Ready" and c["status"] == "True"
                            for c in pod.get("status", {}).get("conditions", [])
                        )
                        with self.lock:
                            self.samples.append(
                                {
                                    "kind": "pod",
                                    "time_unix_ns": now,
                                    "pod": pod["metadata"]["name"],
                                    "generation": generation(pod["metadata"]["uid"]),
                                    "ready": ready,
                                    "deleting": "deletionTimestamp" in pod["metadata"],
                                }
                            )
                slices = json.loads(self.k("get", "endpointslices", "-o", "json"))["items"]
                now = time.time_ns()
                for service in ["gateway", "fake"]:
                    entries = []
                    for item in slices:
                        if item["metadata"]["labels"].get("kubernetes.io/service-name") != service:
                            continue
                        for endpoint in item.get("endpoints", []):
                            ref = endpoint.get("targetRef", {})
                            entries.append(
                                {
                                    "pod": ref.get("name"),
                                    "generation": generation(ref.get("uid", "")),
                                    "ready": endpoint["conditions"].get("ready") is True,
                                    "terminating": endpoint["conditions"].get("terminating")
                                    is True,
                                }
                            )
                    with self.lock:
                        self.samples.append(
                            {
                                "kind": "endpointslices",
                                "time_unix_ns": now,
                                "service": service,
                                "endpoints": entries,
                            }
                        )
            except Exception as exc:
                self.observer_error = type(exc).__name__
                return
            self.observer_stop.wait(0.25)

    def wait(self, predicate, timeout=90):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.observer_error:
                raise RuntimeError(f"observer failed: {self.observer_error}")
            with self.lock:
                result = predicate()
            if result:
                return result
            time.sleep(0.1)
        raise TimeoutError("campaign condition timed out")

    def reservations(self):
        script = "local active=0; for _,k in ipairs(redis.call('KEYS',ARGV[1])) do if redis.call('GET',k)=='active' then active=active+1 end end; return {redis.call('ZCARD',ARGV[2]),redis.call('ZCARD',ARGV[3]),active}"
        result = self.k(
            "exec",
            "deploy/redis",
            "--",
            "redis-cli",
            "--raw",
            "EVAL",
            script,
            "0",
            "mti:kind:v1:{admission}:tenant:*:reservation:*",
            "mti:kind:v1:{admission}:global:active",
            "mti:kind:v1:{admission}:tenant:tenant-local:active",
        )
        return dict(
            zip(
                ["global_zcard", "tenant_zcard", "active_reservation_keys"],
                map(int, result.splitlines()),
                strict=True,
            )
        )

    def event(self, name):
        old_pods = [p for p in self.pods() if p["metadata"]["labels"].get("app") == "gateway"]
        old = {p["metadata"]["name"]: generation(p["metadata"]["uid"]) for p in old_pods}
        if len(old) != 2:
            raise ValueError("measurement requires exactly two gateways before event")
        target_pod = next(p for p in self.pods() if p["metadata"]["name"] == "fake-1")
        target_gen = generation(target_pod["metadata"]["uid"])
        unchanged_gen = generation(
            next(p["metadata"]["uid"] for p in self.pods() if p["metadata"]["name"] == "fake-0")
        )
        stop = threading.Event()

        def worker(index):
            sequence = 0
            if stop.wait(index * WORKER_STAGGER_SECONDS):
                return
            while not stop.is_set():
                result = request_stream(name, index, sequence)
                with self.lock:
                    self.streams.append(result)
                sequence += 1
                stop.wait(0.1)

        start = time.time_ns()
        with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
            futures = [pool.submit(worker, i) for i in range(WORKERS)]
            try:

                def live():
                    routed = [
                        r
                        for r in self.logs
                        if r["msg"] == "request routed" and r["time_unix_ns"] >= start
                    ]
                    terminal_ids = {
                        r.get("request_id") for r in self.logs if r["msg"] == "request terminal"
                    }
                    active = [r for r in routed if r["request_id"] not in terminal_ids]
                    return (
                        active
                        if len(active) == WORKERS
                        and set(old).issubset({r["pod"] for r in active})
                        and any(r["backend_generation"] == target_gen for r in active)
                        else None
                    )

                active = self.wait(live)
                time.sleep(2)  # overlap delivered content, not only initial role frames
                active = self.wait(live)
                before = self.reservations()
                trigger = time.time_ns()
                print(
                    f"{name}: trigger with {len(active)} active routed streams, reservations={before}",
                    flush=True,
                )
                if name == "gateway-rollout":
                    self.k("rollout", "restart", "deployment/gateway")
                    self.k("rollout", "status", "deployment/gateway", "--timeout=180s")
                    self.wait(
                        lambda: all(
                            any(
                                r["pod_generation"] == gen and r["msg"] == "last stream drained"
                                for r in self.logs
                            )
                            for gen in old.values()
                        ),
                        timeout=150,
                    )
                else:
                    # Partition 1 replaces only ordinal 1, with no backend surge.
                    self.k(
                        "patch",
                        "statefulset",
                        "fake",
                        "--type=merge",
                        "-p",
                        json.dumps(
                            {
                                "spec": {
                                    "template": {
                                        "metadata": {
                                            "annotations": {"mti-stage1-roll": str(trigger)}
                                        }
                                    }
                                }
                            }
                        ),
                    )
                    self.k("rollout", "status", "statefulset/fake", "--timeout=180s")
                    self.wait(
                        lambda: any(
                            r["msg"] == "request routed"
                            and r.get("backend_id") == "fake-1"
                            and r.get("backend_generation") != target_gen
                            and r["time_unix_ns"] >= trigger
                            for r in self.logs
                        )
                    )
                current_backends = [
                    p for p in self.pods() if p["metadata"]["labels"].get("app") == "fake"
                ]
                if (
                    len(current_backends) != 2
                    or generation(
                        next(
                            p["metadata"]["uid"]
                            for p in current_backends
                            if p["metadata"]["name"] == "fake-0"
                        )
                    )
                    != unchanged_gen
                ):
                    raise ValueError("backend rollout changed the untargeted replica")
                time.sleep(3)
            finally:
                stop.set()
                for future in futures:
                    future.result(timeout=140)
        time.sleep(1)
        after = self.reservations()
        if any(after.values()):
            raise ValueError(f"reservations did not reconcile: {after}")
        self.wait(
            lambda: all(
                r["request_id"] is None
                or any(
                    log.get("request_id") == r["request_id"] and log["msg"] == "request terminal"
                    for log in self.logs
                )
                for r in self.streams
                if r["event"] == name
            ),
            timeout=15,
        )
        with self.lock:
            rows = [r.copy() for r in self.streams if r["event"] == name]
            logs = [r.copy() for r in self.logs]
            samples = [r.copy() for r in self.samples]
        terminal = {r["request_id"]: r for r in logs if r["msg"] == "request terminal"}
        routes = {r["request_id"]: r for r in logs if r["msg"] == "request routed"}
        for row in rows:
            route = routes.get(row["request_id"], {})
            row.update(
                gateway=route.get("pod"),
                gateway_generation=route.get("pod_generation"),
                backend=route.get("backend_id"),
                backend_generation=route.get("backend_generation"),
            )
            if row["request_id"] and row["request_id"] not in terminal:
                raise ValueError("client request lacks gateway terminal record")
            row["gateway_cause"] = terminal.get(row["request_id"], {}).get("cause")
            if row["false_complete"] or (row["gateway_cause"] == "completed") != (
                row["outcome"] == "completed"
            ):
                raise ValueError("false completion or client/server completion mismatch")
        stages = []
        victims = old if name == "gateway-rollout" else {"fake-1": target_gen}
        for pod, gen in victims.items():
            sig = next(
                r["time_unix_ns"]
                for r in logs
                if r["pod_generation"] == gen
                and r["msg"] in {"gateway draining", "SIGTERM received"}
            )
            drained = next(
                r["time_unix_ns"]
                for r in logs
                if r["pod_generation"] == gen and r["msg"] == "last stream drained"
            )
            if any(
                r.get("grace_expired") or r.get("active", 0) != 0
                for r in logs
                if r["pod_generation"] == gen and r["msg"] == "last stream drained"
            ):
                raise ValueError("drain exceeded grace")
            service = "gateway" if name == "gateway-rollout" else "fake"
            pod_samples = sorted(
                (s for s in samples if s["kind"] == "pod" and s["generation"] == gen),
                key=lambda s: s["time_unix_ns"],
            )
            deleted = next(s["time_unix_ns"] for s in pod_samples if s["deleting"])
            deletion_prior = max(
                (
                    s["time_unix_ns"]
                    for s in pod_samples
                    if s["time_unix_ns"] < deleted and not s["deleting"]
                ),
                default=trigger,
            )
            coverage = pod_stream_coverage(rows, routes, terminal, pod, gen, service, deleted, sig)
            if service == "fake":
                coverage["backend_active_at_sigterm"] = next(
                    r["active"]
                    for r in logs
                    if r["pod_generation"] == gen and r["msg"] == "SIGTERM received"
                )
            relevant = [
                s for s in samples if s["kind"] == "endpointslices" and s["service"] == service
            ]
            removed = next(
                s["time_unix_ns"]
                for s in relevant
                if s["time_unix_ns"] >= trigger
                and not any(
                    e["generation"] == gen and e["ready"] and not e["terminating"]
                    for e in s["endpoints"]
                )
            )
            prior = max(
                (s["time_unix_ns"] for s in relevant if s["time_unix_ns"] < removed),
                default=trigger,
            )
            discoveries = {}
            if name == "backend-rollout":
                identity = pod + "@" + gen
                for gateway in old:
                    discoveries[gateway] = next(
                        r["time_unix_ns"]
                        for r in logs
                        if r["pod"] == gateway
                        and r["msg"] == "backend discovery changed"
                        and r["time_unix_ns"] >= trigger
                        and identity not in r["backends"]
                    )
                    if any(
                        r["msg"] == "request routed"
                        and r["pod"] == gateway
                        and r.get("backend_generation") == gen
                        and r["time_unix_ns"] > discoveries[gateway]
                        for r in logs
                    ):
                        raise ValueError("gateway routed a removed backend generation")
            ready_samples = [
                s
                for s in samples
                if s["kind"] == "pod"
                and s["time_unix_ns"] >= trigger
                and s["ready"]
                and not s["deleting"]
                and (
                    s["pod"].startswith("gateway-") and s["generation"] not in old.values()
                    if name == "gateway-rollout"
                    else s["pod"] == pod and s["generation"] != gen
                )
            ]
            replacements = {}
            for s in ready_samples:
                replacements.setdefault(
                    s["generation"], {"pod": s["pod"], "ready_observed_unix_ns": s["time_unix_ns"]}
                )
            for replacement_gen, replacement in replacements.items():
                routed = [
                    r
                    for r in logs
                    if r["msg"] == "request routed"
                    and r["time_unix_ns"] >= trigger
                    and (
                        r["pod_generation"] == replacement_gen
                        if name == "gateway-rollout"
                        else r["backend_generation"] == replacement_gen
                    )
                ]
                if not routed:
                    raise ValueError("replacement was never routed live traffic")
                replacement["first_routed_unix_ns"] = min(
                    r["router_decision_unix_ns"] for r in routed
                )
            stages.append(
                {
                    "pod": pod,
                    "generation": gen,
                    "deletion_observed_unix_ns": deleted,
                    "deletion_observation_bracket_ns": [deletion_prior, deleted],
                    "sigterm_unix_ns": sig,
                    "endpoint_removed_observed_unix_ns": removed,
                    "endpoint_removed_observation_bracket_ns": [prior, removed],
                    "gateway_discovery_removed_unix_ns": discoveries,
                    "last_stream_drained_unix_ns": drained,
                    "replacements": replacements,
                    "drain_after_sigterm_ms": (drained - sig) / 1e6,
                    **coverage,
                }
            )
        counts = dict(Counter(r["outcome"] for r in rows))
        for outcome in ["completed", "failed", "partial"]:
            counts.setdefault(outcome, 0)
        summary = {
            "event": name,
            "trigger_unix_ns": trigger,
            "live_at_trigger": active,
            "counts": counts,
            "failure_statuses": dict(
                Counter(str(r["status"]) for r in rows if r["outcome"] != "completed")
            ),
            "false_completions": sum(r["false_complete"] for r in rows),
            "reservations_before": before,
            "reservations_after": after,
            "untargeted_backend_generation": unchanged_gen,
            "duration_ms": distribution([r["duration_ms"] for r in rows]),
            "first_event_ms": distribution(
                [r["first_event_ms"] for r in rows if r["first_event_ms"] is not None]
            ),
            "gateway_counts": dict(Counter(r["gateway"] for r in rows)),
            "backend_counts": dict(Counter(r["backend"] for r in rows)),
            "outliers": sorted(rows, key=lambda r: r["duration_ms"], reverse=True)[:5],
            "stages": stages,
            "sigterm_coverage_required": True,
            "sigterm_coverage_passed": all(
                s["streams_inflight_at_sigterm"] > 0 and s.get("backend_active_at_sigterm", 1) > 0
                for s in stages
            ),
        }
        write_json(self.output / f"{name}.json", summary)
        with (self.output / f"{name}-streams.jsonl").open(
            "w", encoding="utf-8", newline="\n"
        ) as stream:
            for row in rows:
                stream.write(json.dumps(row, sort_keys=True) + "\n")
        # Preserve full rows and coverage on failure; a zero count cannot be
        # hidden by the overall completed/reservation PASS checks.
        require_sigterm_coverage(stages)
        print(json.dumps(summary, indent=2), flush=True)

    def execute(self):
        self.output.mkdir(parents=True, exist_ok=False)
        self.install_tools()
        if CLUSTER in run(self.kind, "get", "clusters").splitlines():
            raise ValueError("refusing to reuse or delete a preexisting stage1 cluster")
        self.build()
        created = False
        try:
            created = True  # clean up partially created clusters as well
            run(
                self.kind,
                "create",
                "cluster",
                "--name",
                CLUSTER,
                "--config",
                ROOT / "deploy/k8s/kind.yaml",
                "--kubeconfig",
                self.kubeconfig,
                "--wait",
                "120s",
                capture=False,
            )
            run(
                self.kind,
                "load",
                "docker-image",
                "--name",
                CLUSTER,
                "mti-gateway:stage1",
                "mti-fake:stage1",
                "mti-redis:stage1",
                capture=False,
            )
            self.k("apply", "-f", ROOT / "deploy/k8s/resources.yaml", capture=False)
            self.k(
                "create",
                "configmap",
                "local-config",
                f"--from-file=tenants.json={ROOT / 'deploy/local/tenants.json'}",
                f"--from-file=cache-salt.secret={ROOT / 'deploy/local/cache-salt.secret.example'}",
            )
            for resource in ["deployment/redis", "statefulset/fake", "deployment/gateway"]:
                self.k("rollout", "status", resource, "--timeout=180s", capture=False)
            allowed = self.k(
                "auth",
                "can-i",
                "list",
                "endpointslices.discovery.k8s.io",
                "--as=system:serviceaccount:mti-stage1:gateway",
            )
            denied = self.k(
                "auth", "can-i", "--list", "--as=system:serviceaccount:mti-stage1:gateway"
            )
            write_json(
                self.output / "rbac.json",
                {"list_endpointslices": allowed, "effective_rules": denied},
            )
            observer = threading.Thread(target=self.observe)
            observer.start()
            try:
                self.wait(lambda: len([r for r in self.logs if r["msg"] == "gateway started"]) == 2)
                self.event("gateway-rollout")
                self.event("backend-rollout")
            finally:
                self.observer_stop.set()
                observer.join(timeout=20)
                for process, thread in self.followers.values():
                    if process.poll() is None:
                        process.terminate()
                    process.wait(timeout=10)
                    thread.join(timeout=10)
            write_json(
                self.output / "logs.json", sorted(self.logs, key=lambda r: r["time_unix_ns"])
            )
            write_json(self.output / "observations.json", self.samples)
            write_json(self.output / "source-hashes.json", self.source_hashes)
            write_json(
                self.output / "environment.json",
                {
                    "scope": "Kubernetes (kind, local, mock vLLM backends)",
                    "pins": self.pins,
                    "image_ids": self.image_ids,
                    "go": run("go", "version"),
                    "python": platform.python_version(),
                    "docker": run("docker", "version", "--format", "{{.Server.Version}}"),
                    "streams": {
                        "workers": WORKERS,
                        "worker_start_stagger_seconds": WORKER_STAGGER_SECONDS,
                        "chunks": STREAM_CHUNKS,
                        "chunk_delay_ms": STREAM_CHUNK_DELAY_MS,
                        "expected_duration_seconds": STREAM_CHUNKS * STREAM_CHUNK_DELAY_MS / 1000,
                    },
                    "clock_basis": "client durations use perf_counter_ns; pod event times and controller observations use UTC wall time on one local Docker host; observation brackets are explicit",
                },
            )
        finally:
            write_json(
                self.output / "logs.json", sorted(self.logs, key=lambda r: r["time_unix_ns"])
            )
            write_json(self.output / "observations.json", self.samples)
            write_json(self.output / "client-observations.json", self.streams)
            write_json(self.output / "source-hashes.json", self.source_hashes)
            if created:
                run(self.kind, "delete", "cluster", "--name", CLUSTER, capture=False)
                remaining = CLUSTER in run(self.kind, "get", "clusters").splitlines()
                containers = run(
                    "docker", "ps", "-aq", "--filter", f"label=io.x-k8s.kind.cluster={CLUSTER}"
                ).splitlines()
                write_json(
                    self.output / "teardown.json",
                    {
                        "cluster_absent": not remaining,
                        "remaining_cluster_containers": len(containers),
                    },
                )
                if remaining or containers:
                    raise ValueError("cluster deletion verification failed")
                self.kubeconfig.unlink(missing_ok=True)
            paths = sorted(
                p for p in self.output.iterdir() if p.is_file() and p.name != "SHA256SUMS.txt"
            )
            (self.output / "SHA256SUMS.txt").write_text(
                "".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n" for p in paths),
                encoding="utf-8",
                newline="\n",
            )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    Campaign(args.output.resolve()).execute()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
