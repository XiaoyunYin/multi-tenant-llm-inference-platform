"""Remote EKS adapter for the separate INF-060 streaming phase selection."""

import hashlib
import json
import re
import subprocess
import tarfile
import tempfile
import time
from collections import Counter
from pathlib import Path

from inf060_diagnostics import EXCEPTIONS, scrub_line
from inf060_probe_client import FORMAT, suppress
from inference_platform.eks_deployment import MODEL, REVISION, VLLM_IMAGE
from inference_platform.inf060_eks_client import generation
from inference_platform.inf060_eks_clock import interval
from inference_platform.inf060_eks_packet import (
    CORPUS_NAME,
    PHASE_WAITS,
    PROBE_CHUNK_BYTES,
    bound,
    file_sha,
    measure_transfer,
    transfer_rate,
)
from inference_platform.inf060_eks_receipts import (
    ARCHIVE_LIMIT,
    EXPANDED_LIMIT,
    build,
    payload,
)
from inference_platform.inf060_eks_resources import client_job, serving_resources
from inference_platform.inf060_eks_schedule import LEVELS, TENANTS, WINDOW_WAIT_SECONDS
from inference_platform.inf060_streaming_probe import (
    ABORT_LINE,
    GATEWAY_REQUEST_ID,
    SentCancel,
    join_abort_rows,
)
from m5_descriptive_remote import EKSClusterPorts

ROOT = Path(__file__).resolve().parents[1]
LOG_LIMIT = 4 * 1024**2
CHECKS = {
    "stream_submit",
    "stream_deadline",
    "stream_job",
    "stream_generation",
    "stream_capture",
    "stream_suppression",
    "stream_receipt",
    "stream_network_policy",
}


def scan_logs(raw):
    canaries = re.findall(r"INF060CANARY[0-9a-f]{20}", raw.decode("utf-8"))
    lines, counts = suppress(raw, set(canaries))
    counts["epoch_lines"] = sum(
        FORMAT.match(line) is not None for line in (lines or ())
    )
    if (
        counts["token_field_lines"]
        or counts["stock_timestamp_lines"]
        or not counts["epoch_lines"]
    ):
        counts["status"] = "REFUSED"
    return (lines if counts["status"] == "PASS" else []), counts


def cancel_observations(rows, logs, clocks):
    def sent(row):
        return row.get("cancel_status") == "sent"

    attempts = [
        SentCancel(
            row["alias"],
            row.get("generation", 0),
            row.get("private_request_id"),
            row["cancel_close_monotonic_ns"],
        )
        for row in rows
        if sent(row)
    ]
    scheduled = {
        row["private_request_id"]: row
        for row in rows
        if GATEWAY_REQUEST_ID.fullmatch(row.get("private_request_id") or "")
    }
    seen_non_cancel = {}
    expected_non_cancel = sum(bool(row.get("client_close_reason")) for row in rows)
    cancel_logs = {}
    unexpected = []
    for alias, lines in logs.items():
        cancel_logs[alias] = []
        for line in lines:
            match = ABORT_LINE.fullmatch(line.rstrip("\r\n"))
            row = scheduled.get(match["request_id"]) if match else None
            if row is None or (sent(row) and row.get("generation") == alias):
                cancel_logs[alias].append(line)
            elif row.get("client_close_reason") and row.get("generation") == alias:
                seen_non_cancel[row["alias"]] = row["client_close_reason"]
            else:
                unexpected.append({"request_alias": row["alias"], "generation": alias})
    joined, counts = join_abort_rows(attempts, cancel_logs)
    for row in joined:
        if row["backend_generation"] == 0:
            row["abort_status"] = "unknown_generation"
        row["timing_status"] = "unresolved"
        row["timing_interval_ns"] = row["upper_ns"] = row["width_ns"] = None
        if (bounds := clocks.get(row["backend_generation"])) and row["abort_log_stamp"]:
            lo, hi = interval(
                row["abort_log_stamp"], row["cancel_close_monotonic_ns"], bounds
            )
            row["upper_ns"], row["width_ns"] = hi, hi - lo
            if lo >= 0:
                row["timing_status"], row["timing_interval_ns"] = "bounded", [lo, hi]
    return (
        joined,
        counts,
        {
            "expected": expected_non_cancel,
            "matched": len(seen_non_cancel),
            "matched_by_reason": dict(Counter(seen_non_cancel.values())),
        },
        unexpected,
    )


def diagnostic(phase, check, exc=None, raw=b""):
    frames = []
    if exc:
        tb = exc.__traceback__
        while tb:
            code = tb.tb_frame.f_code
            path = Path(code.co_filename).resolve()
            if any(
                path.is_relative_to(ROOT / directory)
                for directory in (
                    "scripts",
                    "python/src/inference_platform",
                )
            ):
                frames.append(
                    {
                        "file": Path(code.co_filename).name,
                        "line": tb.tb_lineno,
                        "function": code.co_name,
                    }
                )
            tb = tb.tb_next
    source = raw[-4096:].decode(errors="replace")
    return {
        "phase": phase,
        "check": check if check in CHECKS else "stream_receipt",
        "exception": type(exc).__name__
        if exc and type(exc).__name__ in EXCEPTIONS
        else None,
        "frames": frames[-8:],
        "log": {
            "locations": [scrub_line(line) for line in source.splitlines()[-32:]],
            "source_bytes": len(raw),
            "truncated": len(raw) > 4096,
        },
    }


class StreamingClusterPorts(EKSClusterPorts):
    corpus_path = Path("/opt/dec077/gate-a-inputs") / CORPUS_NAME

    def policy_agent(self):
        node = json.loads(
            self.k("-n", "kube-system", "get", "daemonset", "aws-node", "-o", "json")
        )
        status = node.get("status") or {}
        template = (node.get("spec") or {}).get("template") or {}
        containers = (template.get("spec") or {}).get("containers") or []
        enabled = any(
            row.get("name") in {"aws-eks-nodeagent", "aws-network-policy-agent"}
            and "--enable-network-policy=true" in (row.get("args") or [])
            for row in containers
        )
        return {
            "enabled": enabled,
            "desired": status.get("desiredNumberScheduled", 0),
            "ready": status.get("numberReady", 0),
        }

    def deploy(self, source):
        agent = self.policy_agent()
        if self.binding.get("gpu_streaming") and agent["enabled"]:
            self.wait(
                lambda: (
                    self.policy_agent() == {"enabled": True, "desired": 4, "ready": 4}
                ),
                seconds=120,
            )
            agent = self.policy_agent()
        if (
            not agent["enabled"]
            or not agent["desired"]
            or agent["ready"] != agent["desired"]
        ):
            raise ValueError("stream_network_policy")
        result = super().deploy(source)
        if self.binding.get("gpu_streaming"):
            replicas = sorted(self.streams().items())
            if len(replicas) != 2:
                raise ValueError("stream_generation")
            policy = self.prove_policy(replicas)
            self.results.setdefault("stream_diagnostics", []).append(
                {"phase": "gpu-streaming-policy", "agent": agent, "policy": policy}
            )
            if not policy["passed"]:
                raise ValueError("stream_network_policy")
            self.stage_corpus()
        return result

    def render_manifest(self, source):
        logging = ROOT / "deploy/inf060/vllm-logging.json"
        if self.binding.get("gpu_streaming"):
            pins = self.binding["streaming"]["conditions"]["pins"]
            if file_sha(logging) != pins["logging_sha256"]:
                raise ValueError("streaming_logging_config")
        rendered = serving_resources(
            super().render_manifest(source),
            self.client_image,
            logging.read_text(encoding="utf-8"),
        )
        if self.binding.get("gpu_streaming"):
            stateful = next(
                item
                for item in rendered["items"]
                if item["kind"] == "StatefulSet" and item["metadata"]["name"] == "vllm"
            )
            self.check_engine(stateful["spec"]["template"]["spec"]["containers"][0])
        return rendered

    @staticmethod
    def check_engine(engine):
        if engine["image"] != VLLM_IMAGE:
            raise ValueError("streaming_engine_digest")
        args = engine["args"]
        if (
            not args
            or args[0] != MODEL
            or "--revision" not in args
            or args[args.index("--revision") + 1 : args.index("--revision") + 2]
            != [REVISION]
        ):
            raise ValueError("streaming_model_revision")
        if (
            "--enable-log-requests" not in args
            or "--max-log-len" not in args
            or args[args.index("--max-log-len") + 1 : args.index("--max-log-len") + 2]
            != ["0"]
        ):
            raise ValueError("streaming_logging_flags")

    def engine_generation(self, pod, alias):
        engine = next(c for c in pod["spec"]["containers"] if c["name"] == "vllm")
        self.check_engine(engine)
        digest = next(
            c["imageID"].split("@")[-1]
            for c in pod["status"]["containerStatuses"]
            if c["name"] == "vllm"
        )
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise ValueError("streaming_engine_readback")
        return {
            "generation": alias,
            "image_id": digest,
            "image": VLLM_IMAGE,
            "command": engine["command"],
            "args": engine["args"],
            "env": {
                row["name"]: row["value"]
                for row in engine["env"]
                if row["name"]
                in {
                    "VLLM_WORKER_MULTIPROC_METHOD",
                    "HF_HUB_OFFLINE",
                    "VLLM_LOGGING_CONFIG_PATH",
                    "VLLM_LOGGING_LEVEL",
                    "VLLM_LOGGING_COLOR",
                    "NO_COLOR",
                    "TZ",
                }
            },
        }

    def client_job(self):
        settings = {
            "namespace": self.namespace,
            "host": "streaming-ingress." + self.namespace + ".svc",
        }
        if self.binding.get("gpu_streaming"):
            settings["corpus_sha256"] = self.binding["streaming"]["corpus"]["sha256"]
        return client_job(
            super().client_job(),
            settings,
        )

    def client_credentials(self):
        return {
            "tokens": {
                tenant: hashlib.sha256(
                    (self.credential + "/" + tenant).encode()
                ).hexdigest()
                for tenant in TENANTS
            },
        }

    def tenant_configuration(self):
        definition = super().tenant_configuration()
        template = definition["tenants"][0]
        return {
            "tenants": [
                {
                    **template,
                    "tenant_id": tenant,
                    "credential_sha256": hashlib.sha256(token.encode()).hexdigest(),
                }
                for tenant, token in self.client_credentials()["tokens"].items()
            ]
        }

    def streams(self):
        result = {}
        pods = json.loads(self.k("get", "pods", "-l", "app=vllm", "-o", "json"))[
            "items"
        ]
        for pod in pods:
            name = pod["metadata"]["name"]
            if name not in {"vllm-0", "vllm-1"}:
                raise ValueError("stream_generation")
            identity = generation(pod)
            identities = self.results.setdefault("stream_generations", [])
            if identity not in identities:
                identities.append(identity)
                if self.binding.get("gpu_streaming"):
                    self.results.setdefault("stream_diagnostics", []).append(
                        {
                            "phase": "engine-generation",
                            **self.engine_generation(pod, len(identities)),
                        }
                    )
            result[name] = {
                "alias": identities.index(identity) + 1,
                "ip": pod["status"]["podIP"],
                "identity": identity,
            }
        return result

    def private_k(self, *args, limit, seconds=120, stdin=None):
        argv = [
            str(self.campaign.kubectl),
            "--kubeconfig",
            str(self.kubeconfig),
            "--context",
            self.context,
            "-n",
            self.namespace,
            *args,
        ]
        with tempfile.TemporaryFile(dir=self.output) as stream:
            result = subprocess.run(
                argv,
                stdout=stream,
                stdin=stdin,
                stderr=subprocess.DEVNULL,
                timeout=seconds,
                check=False,
            )
            if result.returncode or stream.tell() > limit:
                raise ValueError("stream_capture")
            stream.seek(0)
            return stream.read(limit + 1)

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
        from rehearse_inf060_kind import PEER_PROBE

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

    def stage_corpus(self):
        expected = self.binding["streaming"]["corpus"]
        if (
            self.corpus_path.stat().st_size != expected["bytes"]
            or file_sha(self.corpus_path) != expected["sha256"]
        ):
            raise ValueError("streaming_corpus_digest")
        command = ["python", "-m", "inference_platform.inf060_eks_client"]
        with self.corpus_path.open("rb") as input_file:
            self.private_k(
                "exec",
                "-i",
                self.client_pod,
                "-c",
                "client",
                "--",
                *command,
                "receive-corpus",
                expected["sha256"],
                limit=0,
                stdin=input_file,
            )
        fact = json.loads(
            self.private_k(
                "exec",
                self.client_pod,
                "-c",
                "client",
                "--",
                *command,
                "verify-corpus",
                limit=512,
            )
        )
        if fact != {"sha256": expected["sha256"], "verified": True}:
            raise ValueError("streaming_corpus_digest")
        self.results.setdefault("stream_diagnostics", []).append(
            {"phase": "corpus", **fact}
        )

    def stream_transfer_probe(self):
        if not self.binding.get("gpu_streaming"):
            raise ValueError("streaming_probe_variant")
        end = min(
            self.deadline,
            time.monotonic()
            + self.timing["streaming_components"]["in_session_transfer_probe_s"],
        )

        def read(offset):
            remaining = end - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("streaming_pod_transfer_probe")
            return self.private_k(
                "exec",
                self.client_pod,
                "-c",
                "result-reader",
                "--",
                "python",
                "-m",
                "inference_platform.inf060_eks_client",
                "probe-chunk",
                str(offset),
                limit=PROBE_CHUNK_BYTES,
                seconds=min(remaining, 120),
            )

        # Each chunk opens a fresh exec stream. The resumed pass restarts
        # the reader at the verified midpoint without replaying the prefix.
        receipt = measure_transfer(read, lambda: None)
        receipt["transport"] = "kubectl-exec-offset-chunks"
        self.results["streaming_pod_rate"] = transfer_rate(receipt)
        self.results.setdefault("stream_diagnostics", []).append(
            {"phase": "operator-pod-transfer", **receipt}
        )
        return receipt

    def client_file(self, name, limit):
        if self.binding.get("gpu_streaming") and not name.endswith("-status.json"):
            return self.streamed_client_file(name, limit)
        return self.private_k(
            "exec",
            self.client_pod,
            "-c",
            "result-reader",
            "--",
            "cat",
            "/results/" + name,
            limit=limit,
        )

    def streamed_client_file(self, name, limit):
        # Use the same offset-sized exec transport as the pre-smoke gate.
        path = "/results/" + name
        command = [
            "exec",
            self.client_pod,
            "-c",
            "result-reader",
            "--",
            "python",
            "-c",
        ]
        raw_size = self.private_k(
            *command,
            "from pathlib import Path;import sys;print(Path(sys.argv[1]).stat().st_size)",
            path,
            limit=32,
            seconds=10,
        )
        size = int(raw_size)
        if not 0 <= size <= limit:
            raise ValueError("stream_capture")
        if size == 0:
            return b""
        rate = self.results.get("streaming_pod_rate", 150_000)
        end = min(self.deadline, time.monotonic() + bound(size, rate))
        data = bytearray()
        for offset in range(0, size, PROBE_CHUNK_BYTES):
            remaining = end - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("streaming_pod_receipt_deadline")
            length = min(PROBE_CHUNK_BYTES, size - offset)
            chunk = self.private_k(
                *command,
                "import sys;f=open(sys.argv[1],'rb');f.seek(int(sys.argv[2]));sys.stdout.buffer.write(f.read(int(sys.argv[3])))",
                path,
                str(offset),
                str(length),
                limit=length,
                seconds=min(remaining, 120),
            )
            self.results["streaming_pod_receipt_bytes"] = self.results.get(
                "streaming_pod_receipt_bytes", 0
            ) + len(chunk)
            if len(chunk) != length:
                raise ValueError("stream_capture")
            data.extend(chunk)
        return bytes(data)

    def engine_cpu(self, name):
        try:
            raw = self.private_k(
                "exec",
                name,
                "-c",
                "vllm",
                "--",
                "cat",
                "/sys/fs/cgroup/cpu.stat",
                limit=2048,
                seconds=5,
            )
            fields = dict(line.split() for line in raw.decode().splitlines())
            return int(fields["usage_usec"])
        except (OSError, KeyError, ValueError, subprocess.TimeoutExpired):
            return None

    def observe(self, label, backends, started_cpu=None):
        try:
            journal = self.client_file(label + "-journal.jsonl", 48 * 1024**2)
            rows = [
                json.loads(line)
                for line in journal.splitlines(keepends=True)[1:]
                if line.endswith(b"\n")
            ]
        except ValueError:
            rows = []
        try:
            details = json.loads(self.client_file(label + "-details.json", 4 * 1024**2))
        except ValueError:
            details = {}
        try:
            current = self.streams()
        except Exception:
            current = {}
        scans, logs = [], {}
        offsets = self.results.setdefault("stream_log_offsets", {})
        for name, replica in backends.items():
            alias = replica["alias"]
            try:
                if (
                    not current.get(name)
                    or current[name]["identity"] != replica["identity"]
                ):
                    raise ValueError("stream_generation")
                raw = self.private_k(
                    "logs",
                    name,
                    "-c",
                    "vllm",
                    "--limit-bytes",
                    str(LOG_LIMIT + 1),
                    limit=LOG_LIMIT,
                )
                lines, counts = scan_logs(raw)
                previous = offsets.get(str(alias))
                start = previous["bytes"] if previous else 0
                if (
                    previous
                    and hashlib.sha256(raw[:start]).hexdigest() != previous["sha256"]
                ):
                    raise ValueError("stream_capture")
                offsets[str(alias)] = {
                    "bytes": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                }
                if counts["status"] == "PASS":
                    if previous:
                        logs[alias] = raw[start:].decode().splitlines()
                    else:
                        logs[alias] = lines
                elif "stream_suppression" not in self.results.setdefault(
                    "stream_failures", []
                ):
                    self.results["stream_failures"].append("stream_suppression")
                scans.append(
                    {"generation": alias, "new_bytes": len(raw) - start, **counts}
                )
            except Exception as exc:
                scans.append({"generation": alias, "status": "unavailable"})
                self.results.setdefault("stream_diagnostics", []).append(
                    diagnostic(label, "stream_capture", exc)
                )
        bounds = {
            row["generation"]: row["bounds"]
            for row in details.get("clocks", [])
            if "bounds" in row and row["generation"] in logs
        }
        joined, orphans, non_cancel_aborts, unexpected = cancel_observations(
            rows, logs, bounds
        )
        for row in rows:
            row.pop("private_request_id", None)
        gauges = details.get("gauges", [])
        frontend_cpu, engine_cpu = {}, {}
        for name, replica in backends.items():
            alias = replica["alias"]
            samples = [
                row["frontend_cpu_s"]
                for row in gauges
                if row["generation"] == alias and "frontend_cpu_s" in row
            ]
            frontend_cpu[str(alias)] = (
                samples[-1] - samples[0]
                if len(samples) >= 2 and samples == sorted(samples)
                else None
            )
            a = (started_cpu or {}).get(name)
            b = self.engine_cpu(name) if current.get(name) == replica else None
            engine_cpu[str(alias)] = (
                (b - a) / 1e6 if a is not None and b is not None and b >= a else None
            )
        return {
            "requests": rows,
            "cancels": joined,
            "orphans": orphans,
            "non_cancel_aborts": non_cancel_aborts,
            "unexpected_abort_observations": unexpected,
            "gauges": gauges,
            "clocks": details.get("clocks", []),
            "drain_ns": details.get("drain_ns"),
            "observers": {
                "client_cpu_s": details.get("client_cpu_s"),
                "frontend_cpu_s": frontend_cpu,
                "engine_cpu_s": engine_cpu,
                "engine_cpu_basis": "container_cgroup_usage_delta",
                "start_ns": details.get("start_ns"),
                "end_of_drain": details.get("end_of_drain", []),
                "clock_refusals": details.get("clock_refusals", []),
                "log_scans": scans,
                "suppression": "PASS"
                if len(scans) == 2 and all(scan["status"] == "PASS" for scan in scans)
                else "REFUSED",
            },
        }

    def stream_window(self, label):
        backends = self.streams()
        if len(backends) != 2:
            raise ValueError("stream_generation")
        if label == "smoke":
            startup = self.observe("startup", backends)
            (self.output / "window-startup.json").write_bytes(payload(startup))
            if startup["observers"]["suppression"] != "PASS":
                raise ValueError("stream_suppression")
        engine_cpu = {name: self.engine_cpu(name) for name in backends}
        self.results["active_stream"] = {
            "label": label,
            "backends": backends,
            "engine_cpu": engine_cpu,
        }
        self.save()
        self.k(
            "exec",
            self.client_pod,
            "-c",
            "client",
            "--",
            "python",
            "-m",
            "inference_platform.inf060_eks_client",
            "submit",
            json.dumps(
                {
                    "label": label,
                    "backends": backends,
                    "deadline_epoch": self.work_deadline_epoch,
                }
            ),
            deadline=self.deadline,
        )

        finish = None
        next_pod_check = 0

        def status():
            nonlocal finish, next_pod_check
            try:
                finish = json.loads(self.client_file(label + "-status.json", 4096))
            except ValueError:
                if time.monotonic() >= next_pod_check:
                    next_pod_check = time.monotonic() + 2
                    pod = json.loads(
                        self.k("get", "pod", self.client_pod, "-o", "json")
                    )
                    if any(
                        row["name"] == "client" and "terminated" in row.get("state", {})
                        for row in pod.get("status", {}).get("containerStatuses", [])
                    ):
                        raise ValueError("stream_job") from None
                return None
            return finish

        wait = (
            PHASE_WAITS[label]
            if self.binding.get("gpu_streaming")
            else WINDOW_WAIT_SECONDS
        )
        self.wait(status, seconds=wait)
        result = self.observe(label, backends, engine_cpu)
        (self.output / ("window-" + label + ".json")).write_bytes(payload(result))
        del self.results["active_stream"]
        if (
            finish["status"] != "complete"
            or result["observers"]["suppression"] != "PASS"
        ):
            raise ValueError("stream_job")
        if label == "smoke" and not any(
            row["outcome"] == "completed" for row in result["requests"]
        ):
            raise ValueError("stream_job")
        return {"status": "complete", "label": label}

    def stream_freeze(self, label, *, complete=False):
        diag = self.results.get("stream_diagnostics", [])
        windows = {}
        active = self.results.get("active_stream")
        if active and active["label"] in LEVELS:
            try:
                windows[active["label"]] = self.observe(
                    active["label"], active["backends"]
                )
            except Exception as exc:
                diag = diag + [diagnostic(active["label"], "stream_capture", exc)]
        for setup in ("startup", "smoke", "warmup"):
            path = self.output / ("window-" + setup + ".json")
            if path.is_file():
                diag = diag + [
                    {
                        "phase": setup,
                        "observers": json.loads(path.read_bytes())["observers"],
                    }
                ]
        for level in LEVELS:
            path = self.output / ("window-" + level + ".json")
            if path.is_file():
                windows[level] = json.loads(path.read_bytes())
        directory = self.output / ("snapshot-" + label)
        diagnostics = {
            "status": "partial" if not complete else "complete",
            "records": diag[-12:],
        }
        conditions = self.binding["streaming"]["conditions"]
        try:
            build(directory, conditions, windows, diagnostics, complete=complete)
        except (ValueError, KeyError) as exc:
            if not complete:
                raise
            diagnostics = {
                "status": "partial",
                "records": (diag + [diagnostic("final", "stream_receipt", exc)])[-12:],
            }
            directory = self.output / "snapshot-final-partial"
            build(directory, conditions, windows, diagnostics)
        archive = self.output / ("snapshot-" + label + ".tar.gz")
        files = sorted(directory.iterdir())
        if sum(path.stat().st_size for path in files) > EXPANDED_LIMIT:
            raise ValueError("streaming_expanded_limit")
        with tarfile.open(archive, "x:gz") as tar:
            for path in files:
                tar.add(path, arcname=path.name, recursive=False)
        size = archive.stat().st_size
        if size > ARCHIVE_LIMIT:
            raise ValueError("stream_receipt")
        with archive.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        hop_bytes = {}
        if self.binding.get("gpu_streaming"):
            total = self.results.get("streaming_pod_receipt_bytes", 0)
            hop_bytes = {
                "pod_receipt_bytes": total,
                "pod_window_bytes": total
                - self.results.get("streaming_pod_checkpoint_bytes", 0),
            }
            self.results["streaming_pod_checkpoint_bytes"] = total
        return {
            "bytes": size,
            "sha256": digest,
            "manifest_sha256": hashlib.sha256(
                (directory / "manifest.json").read_bytes()
            ).hexdigest(),
            **hop_bytes,
        }
