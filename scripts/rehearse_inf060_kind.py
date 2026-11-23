"""Run the INF-060 production-duration and fault rehearsals on a DEC-099 host."""

import argparse
import hashlib
import json
import os
import secrets
import select
import shutil
import subprocess
import sys
import tarfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.request import Request, urlopen

from inf060_eks_operator import attach_local, execute_streaming, retrieve
from inf060_eks_remote import StreamingClusterPorts, diagnostic
from package_a_host import Host, server

from inference_platform.eks_deployment import MODEL, REVISION
from inference_platform.inf060_eks_clock import EXCHANGES, bracket, wall_mapping
from inference_platform.inf060_eks_receipts import (
    ARCHIVE_LIMIT,
    CONDITIONS,
    build,
    payload,
    schedule_digest,
    verify,
)
from inference_platform.inf060_eks_schedule import LEVELS
from inference_platform.kind_rollout import Campaign
from inference_platform.m5_descriptive import resources
from inference_platform.m5_descriptive_cluster import ClusterPorts

ROOT = Path(__file__).resolve().parents[1]
CLUSTER = "inf060-rehearsal"
CLIENT_IMAGE = "mti-fake:stage1"
GATEWAY_IMAGE = "mti-gateway:stage1"
CALICO_VERSION = "v3.31.4"
CALICO_SHA256 = "6e89ee080d6dae58c620c47e3fcb7a9bfc40748422c868c924b7482dd5145ce2"
FAULTS = ("abort-faults", "replacement", "canary", "client-crash", "engine-crash")
CLIENT_FAULT = """
import os
import time
from inference_platform import inf060_eks_client as client

mode = os.environ["INF060_KIND_FAULT"]
client.WINDOW_SECONDS = 8 if mode == "deadline-close" else 44
if mode == "deadline-close":
    client.REQUEST_CAP_SECONDS = 2
production_schedule = client.schedule
client.schedule = lambda level: [
    row for row in production_schedule(level)
    if row["slot_ns"] < client.WINDOW_SECONDS * 10**9
]
if mode == "abort-faults":
    offers, mapping = client.run_offers, client.wall_mapping
    observe = client.observe_stream
    def coalesced(chunks, *args, **kwargs):
        def read_pairs():
            iterator = iter(chunks)
            for first in iterator:
                yield first + next(iterator, b"")
        return observe(read_pairs(), *args, **kwargs)
    def delayed(*args, **kwargs):
        time.sleep(0.45)
        return offers(*args, **kwargs)
    started = []
    def stepped():
        if not started:
            started.append(time.monotonic())
        offset, width = mapping()
        return offset + (10_000_000 if time.monotonic() >= started[0] + 5 else 0), width
    client.run_offers, client.wall_mapping, client.observe_stream = delayed, stepped, coalesced
elif mode == "client-crash":
    attempt = client.attempt
    def crash(row, *args):
        if row["slot_ns"] >= 3 * 10**9:
            os._exit(70)
        return attempt(row, *args)
    client.attempt = crash
client.serve(client.ROOT)
"""

PEER_PROBE = """
import json, socket, sys
def reach(ip, port):
    try:
        with socket.create_connection((ip, port), 2):
            return True
    except OSError:
        return False
print(json.dumps([{"engine": reach(ip, 8000), "clock": reach(ip, 8765)} for ip in sys.argv[1:]]))
"""

CLOCK_PROBE = """
import json, sys, time
from inference_platform.inf060_eks_client import pods, scrape
from inference_platform.inf060_eks_clock import ClockStream, bracket, wall_mapping

namespace, load = sys.argv[1:]
peers = pods(namespace)
out = []
for number, name in enumerate(sorted(peers), 1):
    peer = peers[name]
    end = time.monotonic() + 35
    while True:
        gauge = scrape(peer["ip"], 0.2)["running"]
        if load == "idle" or gauge or time.monotonic() >= end:
            break
        time.sleep(0.035)
    stream = ClockStream(peer["ip"], peer["identity"][0], time.monotonic() + 5)
    try:
        a, first = wall_mapping(), stream.exchange()
        last, b = stream.exchange(), wall_mapping()
        same = pods(namespace)[name]["identity"] == peer["identity"]
        out.append({"replica": number, "running": gauge, **bracket(first, last, [a, b], same_generation=same)})
    finally:
        stream.close()
print(json.dumps(out))
"""


def write(path, value):
    path.write_bytes(payload(value))


def command(*argv, seconds=180):
    return subprocess.run(
        list(map(str, argv)), cwd=ROOT, check=True, capture_output=True, timeout=seconds
    ).stdout


def fallback_clock(argv, expected_uid):
    """Measure the same exchange over a separate kubectl exec -i transport."""
    code = (
        "import os,sys,uuid;"
        "from inference_platform.inf060_eks_clock import serve_stream;"
        "serve_stream(sys.stdin.buffer,sys.stdout.buffer,[os.environ['POD_UID'],uuid.uuid4().hex])"
    )
    with subprocess.Popen(
        [*map(str, argv), "python", "-u", "-c", code],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        bufsize=0,
    ) as child:

        def receive():
            if not select.select([child.stdout], [], [], 5)[0]:
                raise TimeoutError("kind_fallback_clock_deadline")
            return json.loads(child.stdout.readline(512))

        try:
            hello = receive()
            if hello[0] != expected_uid:
                raise ValueError("kind_fallback_clock_uid")
            first_mapping = wall_mapping()
            samples = []
            for index in range(2 * EXCHANGES):
                start = time.monotonic_ns()
                child.stdin.write(payload(index))
                value = receive()
                end = time.monotonic_ns()
                if value[0] != index:
                    raise ValueError("kind_fallback_clock_sequence")
                samples.append({"c1": start, "c4": end, "e2": value[1], "e3": value[1]})
            return bracket(
                samples[:EXCHANGES],
                samples[EXCHANGES:],
                [first_mapping, wall_mapping()],
                same_generation=True,
            )
        finally:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=10)


def disconnect_reader(host):
    code = (
        "import os,sys,time,urllib.request;"
        "u=urllib.request.Request(sys.argv[1],headers={'Authorization':'Bearer '+os.environ['REHEARSAL_SECRET']});"
        "r=urllib.request.urlopen(u,timeout=10); r.read(1); print('connected',flush=True); time.sleep(120)"
    )
    with subprocess.Popen(
        [sys.executable, "-c", code, host.base + "/inf060-snapshot/0.25/0"],
        env={**os.environ, "REHEARSAL_SECRET": host.token},
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    ) as child:
        try:
            if (
                not select.select([child.stdout], [], [], 15)[0]
                or child.stdout.readline() != b"connected\n"
            ):
                return {"connected": False}
            child.kill()
            return {"connected": True, "receiver_exit": child.wait(timeout=10)}
        finally:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=10)


class RehearsalTransport:
    """Use the real authenticated route and chunk headers through a local HTTP hop."""

    def __init__(self, root, manifest, end):
        self.token = secrets.token_urlsafe(24)
        host = Host(
            root, self.token, hashlib.sha256(payload(manifest)).hexdigest(), end
        )
        host.manifest = manifest
        self.server = server(host, port=0)
        self.base = "http://127.0.0.1:" + str(self.server.server_port)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def request(self, route, *, end):
        left = end - time.time()
        if left <= 0:
            raise TimeoutError("streaming_transfer_deadline")
        request = Request(
            self.base + route, headers={"Authorization": "Bearer " + self.token}
        )
        with urlopen(request, timeout=min(10, left)) as response:
            return response.read(), dict(response.headers)

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


class KindPorts(StreamingClusterPorts):
    def __init__(self, campaign, kubeconfig, run, name):
        self.campaign, self.kubeconfig = campaign, kubeconfig
        self.run, self.scenario = run, name
        run.mkdir()
        self.output = run / "descriptive-private"
        self.output.mkdir()
        self.context = "kind-" + CLUSTER
        self.namespace = "mti-m5-inf060-" + name
        self.end = time.time() + (2 * 3600 if name == "production" else 1080)
        self.deadline_epoch = self.end - 150
        self.work_deadline_epoch = self.end - 240
        self.deadline = time.monotonic() + self.work_deadline_epoch - time.time()
        self.client_image = (
            "example.invalid/fixture@" + campaign.image_ids[CLIENT_IMAGE]
        )
        self.model, self.tenant_id = MODEL, "inf060-kind"
        self.credential = secrets.token_urlsafe(32)
        self.results, self.commands, self.forwarders = {}, [], []
        self.startup_seconds = 180
        conditions = {
            "source": command("git", "rev-parse", "HEAD").decode().strip(),
            "artifact_path": "kind-cpu-rehearsal",
            "model": MODEL,
            "revision": REVISION,
            "engine_version": "cpu-mock",
            "image_digest": campaign.image_ids[CLIENT_IMAGE],
            "engine_flags": ["epoch-frontend-abort-fixture"],
            "gpu_type": None,
            "gpu_count": 0,
            "capacity_type": "routine-cpu",
            "zone": None,
            "policy": "round_robin",
            "tenants": ["inf060-a", "inf060-b"],
            "seed": 399060,
            "run_count": 1,
            "schedule_sha256": schedule_digest(),
            "pins": {
                "kind": campaign.pins["node_image"],
                "calico_manifest_sha256": CALICO_SHA256,
            },
            "limits": {
                "scenario": name,
                "window_seconds": {"production": 600, "deadline-close": 8}.get(
                    name, 44
                ),
            },
        }
        if set(conditions) != CONDITIONS:
            raise ValueError("kind_conditions")
        self.binding = {"streaming": {"conditions": conditions, "gpu_hourly_usd": 0}}
        self.manifest = {
            "account": "kind-rehearsal",
            "timing": {"cleanup_reserve_seconds": 150, "retrieval_reserve_seconds": 90},
            "forecast_basis": {"hourly_usd": 0, "fixed_other_usd": 0, "margin": 1},
            "descriptive": self.binding,
        }
        self.host = RehearsalTransport(run, self.manifest, self.end)
        self.measurements = {}
        self.removed = False

    def render_manifest(self, source):
        rendered = super().render_manifest(source)
        rendered["items"] = [
            item for item in rendered["items"] if item["kind"] != "DaemonSet"
        ]
        rendered["items"].append(
            {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {"name": "kind-inf060-faults", "namespace": self.namespace},
                "data": {
                    "engine.py": (ROOT / "scripts/inf060_kind_engine.py").read_text(
                        encoding="utf-8"
                    ),
                    "client.py": CLIENT_FAULT,
                },
            }
        )
        for item in rendered["items"]:
            if item["kind"] != "StatefulSet":
                continue
            pod = item["spec"]["template"]["spec"]
            main = pod["containers"][0]
            if item["metadata"]["name"] == "gateway":
                main.update(image=GATEWAY_IMAGE, imagePullPolicy="Never")
                continue
            main.update(
                image=CLIENT_IMAGE,
                imagePullPolicy="Never",
                command=["python", "-u", "/kind/engine.py"],
                args=[],
                resources={
                    "requests": {"cpu": "100m", "memory": "64Mi"},
                    "limits": {"cpu": "2", "memory": "256Mi"},
                },
                volumeMounts=[{"name": "kind", "mountPath": "/kind", "readOnly": True}],
            )
            pod["volumes"] = [
                {"name": "kind", "configMap": {"name": "kind-inf060-faults"}}
            ]
            pod["containers"][1].update(image=CLIENT_IMAGE, imagePullPolicy="Never")
        return rendered

    def client_job(self):
        objects = super().client_job()
        spec = objects["items"][-1]["spec"]["template"]["spec"]
        for container in spec["containers"]:
            container.update(image=CLIENT_IMAGE, imagePullPolicy="Never")
        if self.scenario != "production":
            client = spec["containers"][0]
            client["command"] = ["python", "-u", "/kind/client.py"]
            client["env"].append({"name": "INF060_KIND_FAULT", "value": self.scenario})
            client["volumeMounts"].append(
                {"name": "kind", "mountPath": "/kind", "readOnly": True}
            )
            spec["volumes"].append(
                {"name": "kind", "configMap": {"name": "kind-inf060-faults"}}
            )
        return objects

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

    def prove_policy(self):
        ips = [row["ip"] for _, row in sorted(self.streams().items())]
        allowed = self.from_client(PEER_PROBE, *ips)
        self.k(
            "run",
            "unlabelled-peer",
            "--restart=Never",
            "--image=" + CLIENT_IMAGE,
            "--image-pull-policy=Never",
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
        denied = json.loads(self.k("logs", "unlabelled-peer"))
        expected = [{"engine": True, "clock": True}] * 2
        return {
            "allowed": allowed,
            "denied": denied,
            "passed": allowed == expected
            and denied == [{"engine": True, "clock": False}] * 2,
        }

    def provision(self):
        # The exact same injected workload and client objects, with kind
        # replacing only the EKS VPC-CNI readiness gate and provider operations.
        result = ClusterPorts.deploy(self, resources(self.namespace, self.client_image))
        try:
            self.measurements["policy"] = self.prove_policy()
        except Exception as error:
            self.measurements["policy"] = {
                "passed": False,
                "error": type(error).__name__,
            }
        if self.scenario == "production":
            try:
                self.measurements["idle"] = self.from_client(
                    CLOCK_PROBE, self.namespace, "idle"
                )
            except Exception as error:
                self.measurements["idle"] = {"error": type(error).__name__}
            self.measurements["fallback"] = []
            for alias, (name, peer) in enumerate(sorted(self.streams().items()), 1):
                try:
                    snapshot = fallback_clock(
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
                        peer["identity"][0],
                    )
                except Exception as error:
                    snapshot = {"error": type(error).__name__}
                self.measurements["fallback"].append({"replica": alias, **snapshot})
        if self.scenario in {
            "abort-faults",
            "canary",
            "engine-crash",
            "deadline-close",
        }:
            for pod in ("vllm-0", "vllm-1"):
                self.k(
                    "exec",
                    pod,
                    "-c",
                    "vllm",
                    "--",
                    "python",
                    "-c",
                    "from pathlib import Path; import sys; Path('/tmp/rehearsal-mode').write_text(sys.argv[1])",
                    self.scenario,
                )
        return result

    def after_start(self, label):
        def started():
            try:
                self.client_file(label + "-journal.jsonl", 48 * 1024**2)
                return True
            except ValueError:
                return False

        self.wait(started, seconds=60)
        if self.scenario == "replacement":
            time.sleep(2)
            self.k(
                "delete", "pod", "vllm-0", "--grace-period=0", "--force", "--wait=false"
            )
            return {"replacement_submitted": True}
        return self.from_client(CLOCK_PROBE, self.namespace, "peak")

    def window(self, label):
        if (
            self.scenario == "production" and label in LEVELS
        ) or self.scenario == "replacement":
            with ThreadPoolExecutor(max_workers=1) as pool:
                concurrent = pool.submit(self.after_start, label)
                try:
                    return self.stream_window(label)
                finally:
                    try:
                        self.measurements["during-" + label] = concurrent.result()
                    except Exception as error:
                        self.measurements["during-" + label] = {
                            "error": type(error).__name__
                        }
        return self.stream_window(label)

    def remote(self, phase):
        if phase.startswith("stream-window-"):
            return self.window(phase.removeprefix("stream-window-"))
        if phase.startswith("stream-snapshot-"):
            label = phase.removeprefix("stream-snapshot-")
            binding = self.stream_freeze(label)
            if label == "0.25":
                self.measurements["disconnect"] = disconnect_reader(self.host)
            return binding
        if phase in {"stream-partial", "stream-final"}:
            return self.stream_freeze("final", complete=phase == "stream-final")
        raise ValueError("kind_phase")

    def teardown(self):
        if not self.removed:
            self.k(
                "delete",
                "namespace",
                self.namespace,
                "--ignore-not-found=true",
                "--timeout=150s",
            )
            self.removed = True
        return {"complete": True}

    def inventory(self):
        names = json.loads(self.k("get", "namespaces", "-o", "json"))["items"]
        count = sum(item["metadata"]["name"] == self.namespace for item in names)
        self.measurements["remaining_namespaces"] = count
        return {"complete": count == 0}


def fault_window(ports, output):
    output.mkdir()
    failure = None
    ports.provision()
    try:
        ports.remote("stream-window-8")
    except Exception as error:
        failure = diagnostic("8", "stream_job", error)
        ports.results.setdefault("stream_diagnostics", []).append(failure)
    binding = ports.remote("stream-partial")
    record, manifest = retrieve(
        ports.host, "final", binding, output / "results-final", time.time() + 90
    )
    if manifest["complete"]:
        raise ValueError("kind_fault_complete")
    if ports.scenario in {"engine-crash", "client-crash"}:
        pods = json.loads(ports.k("get", "pods", "-o", "json"))["items"]
        statuses = [
            row
            for pod in pods
            for row in pod.get("status", {}).get("containerStatuses", [])
        ]
        ports.measurements["engine_restarts"] = sum(
            row["restartCount"] for row in statuses if row["name"] == "vllm"
        )
        ports.measurements["client_exit_codes"] = [
            row["state"]["terminated"]["exitCode"]
            for row in statuses
            if row["name"] == "client" and "terminated" in row.get("state", {})
        ]
    return {"fault": failure, "retrieval": record}


def file_binding(path):
    with path.open("rb") as source:
        return {
            "bytes": path.stat().st_size,
            "sha256": hashlib.file_digest(source, "sha256").hexdigest(),
        }


def transfer_faults(ports):
    parent = ports.run
    final = ports.output / "snapshot-final"
    archive = ports.output / "snapshot-final.tar.gz"
    expected = {
        **file_binding(archive),
        "manifest_sha256": file_binding(final / "manifest.json")["sha256"],
    }

    class Corrupt:
        def request(self, route, *, end):
            data, headers = ports.host.request(route, end=end)
            return bytes([data[0] ^ 1]) + data[1:], headers

    summary = {}

    def refuse(name, host, binding, deadline, reason):
        try:
            retrieve(host, "final", binding, parent / name, deadline)
        except (ValueError, TimeoutError) as error:
            summary[name] = {
                "passed": str(error) == reason,
                "reason": type(error).__name__,
            }
        else:
            summary[name] = {"passed": False, "reason": "accepted"}

    end = time.time() + 90
    refuse(
        "oversize",
        ports.host,
        {**expected, "bytes": ARCHIVE_LIMIT + 1},
        end,
        "streaming_archive_limit",
    )
    refuse("corrupt_chunk", Corrupt(), expected, end, "streaming_chunk_binding")
    refuse(
        "transfer_deadline",
        ports.host,
        expected,
        time.time() - 1,
        "streaming_transfer_deadline",
    )

    # Exercise the same transfer path with hashes rebound around a schema fault.
    with tarfile.open(archive, "r:gz") as saved:
        temporary = parent / "saved-final.tar.gz"
        if any(
            member.name not in {path.name for path in final.iterdir()}
            for member in saved
        ):
            raise ValueError("kind_snapshot_member")
    archive.rename(temporary)
    try:
        mutant = parent / "missing-field"
        shutil.copytree(final, mutant)
        requests = mutant / "requests.jsonl"
        rows = [json.loads(line) for line in requests.read_bytes().splitlines()]
        next(row for row in rows if row["outcome"] == "completed").pop("validated_done")
        requests.write_bytes(b"".join(map(payload, rows)))
        manifest_file = mutant / "manifest.json"
        manifest = json.loads(manifest_file.read_bytes())
        manifest["files"]["requests.jsonl"] = file_binding(requests)
        write(manifest_file, manifest)
        with tarfile.open(archive, "x:gz") as tar:
            for path in sorted(mutant.iterdir()):
                tar.add(path, arcname=path.name, recursive=False)
        refuse(
            "missing_member_field",
            ports.host,
            {
                **file_binding(archive),
                "manifest_sha256": file_binding(manifest_file)["sha256"],
            },
            time.time() + 90,
            "streaming_required_observation",
        )
    finally:
        temporary.replace(archive)
    archive.rename(temporary)
    try:
        bulk = parent / "bulk-fixture"
        shutil.copytree(final, bulk)
        extra = (
            ARCHIVE_LIMIT
            - 1024**2
            - sum(path.stat().st_size for path in bulk.iterdir())
        )
        if extra <= 0:
            raise ValueError("kind_bulk_fixture_size")
        member = bulk / "observers.json"
        with member.open("ab") as stream:
            block = b" " * 1024**2
            for _ in range(extra // len(block)):
                stream.write(block)
            stream.write(block[: extra % len(block)])
        manifest_path = bulk / "manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        manifest["files"][member.name] = file_binding(member)
        write(manifest_path, manifest)
        # Whitespace and an uncompressed gzip member exercise the transfer cap
        # without adding fabricated observations to the expected receipt.
        with tarfile.open(archive, "x:gz", compresslevel=0) as tar:
            for path in sorted(bulk.iterdir()):
                tar.add(path, arcname=path.name, recursive=False)
        record, checked = retrieve(
            ports.host,
            "final",
            {
                **file_binding(archive),
                "manifest_sha256": file_binding(manifest_path)["sha256"],
            },
            parent / "bulk-readback",
            time.time() + 956,
        )
        summary["bulk_transfer"] = {
            **record,
            "passed": checked["complete"]
            and record["bytes"] >= ARCHIVE_LIMIT - 2 * 1024**2,
        }
    finally:
        temporary.replace(archive)
    return summary


def checks_for(name, result, operation):
    levels = json.loads((result / "levels.json").read_bytes())
    clocks = json.loads((result / "clocks.json").read_bytes())
    observers = json.loads((result / "observers.json").read_bytes())
    level = levels["8"]
    seen = level["scheduled"] - sum(
        level["outcomes"].get(key, 0) for key in ("unreached", "unresolved")
    )
    observed = operation["measurements"]
    checks = {}
    if name == "production":
        checks.update(
            four_complete_windows=all(
                (levels[label]["elapsed_s"] or 0) >= 600 for label in LEVELS
            ),
            idle_clock_replica_widths=isinstance(observed.get("idle"), list)
            and len(observed["idle"]) == 2
            and all(row["running"] == 0 for row in observed["idle"]),
            fallback_widths=len(observed.get("fallback", [])) == 2
            and all("width_ns" in row for row in observed["fallback"]),
            receiver_killed=observed.get("disconnect", {}).get("receiver_exit") == -9,
        )
        for label in LEVELS:
            current = observed.get("during-" + label)
            checks["peak-" + label] = (
                isinstance(current, list)
                and len(current) == 2
                and all(row["running"] > 0 for row in current)
            )
        for mutation, proof in operation.get("transfer_faults", {}).items():
            checks[mutation] = proof["passed"]
    elif name == "abort-faults":
        cancels = [
            json.loads(line)
            for line in (result / "cancels.jsonl").read_bytes().splitlines()
        ]
        checks.update(
            missed_offers=level["outcomes"].get("missed", 0) > 0,
            coalesced_content=level["same_read_content_pairs"] > 0,
            eos_before_cancel=any(
                row["cancel_status"] == "finished_before_cancel" for row in cancels
            ),
            duplicate_abort=level["abort_status"].get("duplicate_abort", 0) > 0,
            missing_abort=level["abort_status"].get("missing_abort", 0) > 0,
            orphan_abort=sum(level["orphans_by_generation"].values()) > 0,
            deadline_close_abort=level["non_cancel_aborts"]["matched"] > 0,
            stepped_clock=any(row["status"] == "clock_step" for row in clocks["8"]),
        )
    elif name == "replacement":
        checks["generation_refused"] = any(
            row["status"] == "clock_generation" for row in clocks["8"]
        )
    elif name == "canary":
        checks["suppression_refused_canary"] = observers["8"].get(
            "suppression"
        ) == "REFUSED" and any(
            row.get("canary_lines", 0) for row in observers["8"]["log_scans"]
        )
    elif name == "client-crash":
        checks["crashed_and_retrieved_live_rows"] = (
            70 in observed.get("client_exit_codes", []) and seen > 0
        )
    elif name == "engine-crash":
        checks["crashed_and_retrieved_live_rows"] = (
            observed.get("engine_restarts", 0) > 0 and seen > 0
        )
    elif name == "deadline-close":
        checks["deadline_close_abort"] = (
            level["non_cancel_aborts"].get("matched_by_reason", {}).get("deadline", 0)
            > 0
        )
    return checks


def configure(campaign, output):
    campaign.install_tools()
    campaign.build()
    kubeconfig = output / "kind.kubeconfig"
    config = output / "kind.json"
    write(
        config,
        {
            "kind": "Cluster",
            "apiVersion": "kind.x-k8s.io/v1alpha4",
            "networking": {"disableDefaultCNI": True, "podSubnet": "192.168.0.0/16"},
            "nodes": [
                {"role": "control-plane", "labels": {"m5-role": "cpu"}},
                {"role": "worker", "labels": {"m5-role": "gpu"}},
                {"role": "worker", "labels": {"m5-role": "gpu"}},
            ],
        },
    )
    command(
        campaign.kind,
        "create",
        "cluster",
        "--name",
        CLUSTER,
        "--image",
        campaign.pins["node_image"],
        "--config",
        config,
        "--kubeconfig",
        kubeconfig,
        seconds=360,
    )
    url = f"https://raw.githubusercontent.com/projectcalico/calico/{CALICO_VERSION}/manifests/calico.yaml"
    with urlopen(url, timeout=30) as source:
        manifest = source.read(1024**2)
    if hashlib.sha256(manifest).hexdigest() != CALICO_SHA256:
        raise ValueError("kind_calico_binding")
    cni = output / "calico.yaml"
    cni.write_bytes(manifest)
    kubectl = [
        campaign.kubectl,
        "--kubeconfig",
        kubeconfig,
        "--context",
        "kind-" + CLUSTER,
    ]
    command(*kubectl, "create", "-f", cni)
    command(
        *kubectl,
        "wait",
        "--for=condition=Ready",
        "--all",
        "nodes",
        "--timeout=240s",
        seconds=270,
    )
    command(
        *kubectl,
        "taint",
        "nodes",
        CLUSTER + "-control-plane",
        "node-role.kubernetes.io/control-plane-",
    )
    command(
        campaign.kind,
        "load",
        "docker-image",
        CLIENT_IMAGE,
        GATEWAY_IMAGE,
        "--name",
        CLUSTER,
        seconds=480,
    )
    return kubeconfig


def run_scenario(campaign, kubeconfig, work, evidence, name):
    started = time.monotonic()
    ports = KindPorts(campaign, kubeconfig, work / name, name)
    output = evidence / name
    operation = {}
    try:
        if name == "production":
            execute_streaming(ports, output)
            operation["transfer_faults"] = transfer_faults(ports)
        else:
            operation.update(fault_window(ports, output))
    except Exception as error:
        operation["error"] = diagnostic(name, "stream_receipt", error)
    finally:
        try:
            ports.teardown()
        finally:
            inventory = ports.inventory()
            ports.host.close()
    elapsed = time.monotonic() - started
    result = output / "results-final"
    if not result.exists():
        build(
            result,
            ports.binding["streaming"]["conditions"],
            {},
            {"status": "remote_unavailable", "records": [operation.get("error")]},
        )
    retained = verify(result)
    if name != "production":
        attach_local(
            result,
            {"final": operation.get("retrieval", {"status": "results_unavailable"})},
            {"teardown_complete": True, "inventory_complete": inventory["complete"]},
            {"elapsed_s": elapsed, "gpu_usd": 0, "routine_cost": "see_lifecycle"},
        )
    operation.update(
        elapsed_s=elapsed,
        measurements=ports.measurements,
        inventory=inventory,
        complete=retained["complete"],
        recounted=True,
    )
    operation["checks"] = checks_for(name, result, operation)
    write(output / "kind.json", operation)
    if not inventory["complete"]:
        raise ValueError("kind_namespace_remaining")
    return operation


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--deadline-only", action="store_true")
    args = parser.parse_args(argv)
    if os.name != "posix" or not Path("/opt/dec077/runtime.json").is_file():
        raise SystemExit("INF-060 kind rehearsal requires a DEC-099 CPU host")
    runtime = json.loads(Path("/opt/dec077/runtime.json").read_bytes())
    if runtime.get("role") != "routine_tests":
        raise SystemExit("INF-060 kind rehearsal requires the routine_tests role")
    args.output.mkdir()
    work = ROOT / ".cache" / "inf060-kind-rehearsal"
    work.mkdir()
    campaign = Campaign(work)
    batches = {}
    try:
        kubeconfig = configure(campaign, work)
        for name in (
            ("deadline-close",) if args.deadline_only else ("production", *FAULTS)
        ):
            batches[name] = run_scenario(campaign, kubeconfig, work, args.output, name)
            write(args.output / "rehearsal.json", {"runs": batches})
    finally:
        if hasattr(campaign, "kind"):
            command(campaign.kind, "delete", "cluster", "--name", CLUSTER, seconds=240)
            clusters = command(campaign.kind, "get", "clusters").decode().splitlines()
            containers = command(
                "docker",
                "ps",
                "-aq",
                "--filter",
                "label=io.x-k8s.kind.cluster=" + CLUSTER,
            ).splitlines()
            empty = CLUSTER not in clusters and not containers
            write(
                args.output / "cluster-teardown.json",
                {"verified": empty, "containers": len(containers)},
            )
            if not empty:
                raise ValueError("kind_cluster_remaining")
    return int(
        not (
            (
                batches["deadline-close"]["complete"] is False
                if args.deadline_only
                else batches["production"]["complete"]
            )
            and all("error" not in result for result in batches.values())
            and all(
                result["measurements"].get("policy", {}).get("passed")
                for result in batches.values()
            )
            and all(result["recounted"] for result in batches.values())
            and all(all(result["checks"].values()) for result in batches.values())
        )
    )


if __name__ == "__main__":
    sys.exit(main())
