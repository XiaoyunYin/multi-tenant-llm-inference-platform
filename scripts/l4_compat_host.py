"""Seven real requests on the separately approved host; never creates cloud resources.

The DEC-077 operator must arm its external first-action watchdog before launch,
upload/hash-verify this packet and pass that unchanged UTC origin. The cloud-init
timer is a separate host backstop. Neither deadline can be extended here.
"""

import argparse
import base64
import http.client
import json
import os
import secrets
import signal
import sqlite3
import ssl
import subprocess
import time
import urllib.request
from pathlib import Path
from unittest.mock import patch

from inference_platform.inf037b_archive import encode, file_facts, sha
from inference_platform.inf037b_controls import CONTROL_TOKENS, control_tenants
from inference_platform.inf037b_live import ClientSSEAdapter, LiveRows
from inference_platform.l4_compat import (
    EXPORT_BYTES,
    PINS,
    READY_BY_S,
    REQUESTS_S,
    measured_booking,
    native_summary,
    need,
    read_summary,
    requests,
)
from inference_platform.package_a_cloud import save


class Run:
    def __init__(self, packet, output, t0):
        self.packet, self.output, self.t0 = packet.resolve(), output.resolve(), t0
        output.mkdir(parents=True, exist_ok=False)
        self.ready_by, self.work_by = t0 + READY_BY_S, t0 + READY_BY_S + REQUESTS_S
        self.deadline = self.ready_by
        self.children, self.containers, self.logs, self.results = [], [], [], []
        self.command_receipts, self.stage_receipts = [], {}
        self.owner = secrets.token_hex(16)
        self.private = packet / ".private"
        self.private.mkdir(mode=0o700, exist_ok=False)

    def call(self, argv, *, timeout=60, name=None, env=None):
        left = self.deadline - time.time()
        need(left > 0, "absolute_deadline")
        started, code = time.monotonic(), None
        try:
            result = subprocess.run(
                list(map(str, argv)),
                cwd=self.packet,
                env=env,
                capture_output=True,
                timeout=min(timeout, left),
            )
            code = result.returncode
        finally:
            self.command_receipts.append(
                {
                    "stage": name or str(argv[0]),
                    "exit_code": code,
                    "elapsed_seconds": time.monotonic() - started,
                }
            )
            save(self.output / "host-commands.json", self.command_receipts)
        if name:
            (self.output / (name + ".stdout")).write_bytes(result.stdout)
            (self.output / (name + ".stderr")).write_bytes(result.stderr)
        result.check_returncode()
        return result.stdout

    def stage(self, name, callback):
        started, code = time.monotonic(), 1
        try:
            result = callback()
            code = 0
            return result
        finally:
            self.stage_receipts[name] = {
                "exit_code": code,
                "elapsed_seconds": time.monotonic() - started,
            }
            save(self.output / "host-stages.json", self.stage_receipts)

    def docker(self, name, image, argv, *, env=(), mounts=(), gpu=False):
        need(name not in self.containers, "container_reuse")
        self.containers.append(name)  # cleanup also covers ambiguous creation.
        command = [
            "docker",
            "run",
            "-d",
            "--name",
            name,
            "--network",
            "host",
            "--label",
            "l4-owner=" + self.owner,
        ]
        if gpu:
            command += ["--gpus", "all", "--pid", "host", "--ipc", "host"]
        for value in env:
            command += ["-e", value]
        for value in mounts:
            command += ["-v", str(value)]
        result = self.call(
            [*command, "--entrypoint", argv[0], image, *argv[1:]], name=name + "-launch"
        )
        self.call(["docker", "inspect", name], name=name + "-inspect")
        return result

    def process(self, argv, name, env):
        log = (self.output / (name + ".log")).open("wb")
        self.logs.append(log)
        child = subprocess.Popen(
            list(map(str, argv)),
            cwd=self.packet,
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        self.children.append(child)
        start = (
            Path(f"/proc/{child.pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
        )
        save(
            self.output / (name + "-process.json"),
            {
                "pid": child.pid,
                "start": start,
                "binary": file_facts(Path(argv[0])),
                "config_sha256": sha(Path(env["TENANT_CONFIG_PATH"]).read_bytes()),
                "backend": env["BACKENDS"],
                "gateway_uid": env["POD_UID"],
                "kernel_boot": Path("/proc/sys/kernel/random/boot_id")
                .read_text()
                .strip(),
            },
        )
        return child

    def ready(self, url):
        while True:
            need(time.time() + 1 < self.deadline, "readiness_deadline")
            need(all(p.poll() is None for p in self.children), "gateway_died")
            if "l4-engine" in self.containers:
                need(
                    self.call(
                        ["docker", "inspect", "-f", "{{.State.Running}}", "l4-engine"]
                    ).strip()
                    == b"true",
                    "engine_died",
                )
            try:
                with urllib.request.urlopen(
                    url, timeout=min(1, self.deadline - time.time())
                ) as response:
                    if response.status == 200:
                        return
            except OSError:
                time.sleep(0.2)

    def redis_ready(self):
        redis_end = min(self.deadline, time.time() + 20)
        while True:
            try:
                need(
                    self.call(
                        [
                            "docker",
                            "exec",
                            "l4-redis",
                            "redis-cli",
                            "-p",
                            "16379",
                            "PING",
                        ],
                        timeout=max(0.001, redis_end - time.time()),
                        name="redis-ready",
                    ).strip()
                    == b"PONG",
                    "redis_ping",
                )
                return
            except (
                subprocess.CalledProcessError,
                subprocess.TimeoutExpired,
                ValueError,
            ):
                need(time.time() + 0.2 < redis_end, "redis_readiness_deadline")
                time.sleep(0.2)

    def client_request(self, row, credentials, context):
        gateway, rid = row["gateway"], row["id"]
        captured, reads = [], []

        def retain(lo, hi, body, metadata):
            captured.append(
                {"bracket_ns": [lo, hi], "hex": body.hex(), "metadata": metadata}
            )

        client = ClientSSEAdapter(
            LiveRows("l4", "local-kernel"), gateway, self.config_hash, retain=retain
        )
        original = http.client.HTTPResponse.read1

        def bracketed(response, *args, **kwargs):
            lo = time.monotonic_ns()
            chunk = original(response, *args, **kwargs)
            reads.append({"bracket_ns": [lo, time.monotonic_ns()], "hex": chunk.hex()})
            return chunk

        begin = time.monotonic_ns()
        need(time.time() + 30 <= self.work_by, "request_reserve")
        offer = {
            "request_id": rid,
            "offer_index": len(self.results),
            "prefix_id": "p000",
            "scheduled_ms": begin // 1_000_000,
        }
        with patch.object(http.client.HTTPResponse, "read1", bracketed):
            normalized = client.request(
                "https://localhost:"
                + ("8443" if gateway == "gateway0" else "8444")
                + "/v1/chat/completions",
                row["payload"],
                offer,
                credential=credentials[row["slot"]],
                context=context,
                cancel_after_content=row["cancel"],
            )
        end = time.monotonic_ns()
        result = {
            "id": rid,
            "slot": row["slot"],
            "gateway": gateway,
            "begin_ns": begin,
            "end_ns": end,
            "duration_seconds": (end - begin) / 1e9,
            "raw": captured,
            "reads": reads,
            "normalized": normalized,
            "request_ids": client.request_ids,
        }
        self.results.append(result)
        save(self.output / (rid + ".json"), result)  # even a refusal is retained first.
        need(len(client.request_ids) == 1, "gateway_request_identity")
        tls = [r["metadata"]["tls"] for r in captured if "tls" in r["metadata"]]
        need(
            len(tls) == 1 and tls[0]["verified"] and tls[0]["peer_sha256"] == self.peer,
            "tls_peer",
        )
        cancellations = [r for r in normalized if r["payload"]["event"] == "cancel"]
        if row.get("refusal"):
            need(
                not cancellations
                and any(
                    "client_cancel_already_complete" in r["metadata"].get("error", "")
                    for r in captured
                ),
                "one_token_refusal",
            )
        else:
            need(not any(r["error"] for r in normalized), "client_error")
            need(bool(cancellations) == row["cancel"], "cancellation_intent")
            result["stream"] = read_summary(
                reads, completed=not row["cancel"], tokens=row["payload"]["max_tokens"]
            )
        result["cancel_ns"] = (
            cancellations[0]["capture_start_mono_ns"] if cancellations else None
        )
        save(self.output / (rid + ".json"), result)

    def run(self):
        # Refuse before pulling images, staging weights or starting processes.
        self.call(["systemctl", "is-active", "--quiet", "dec077-terminate.timer"])
        deadline = int(Path("/etc/dec077/deadline").read_text())
        need(
            deadline <= self.t0 + 4200 and time.time() < self.ready_by,
            "independent_timer",
        )
        manifest = json.loads((self.packet / "sources.json").read_bytes())
        for name, facts in manifest.items():
            need(file_facts(self.packet / name) == facts, "payload_source:" + name)
        spec = json.loads((self.packet / "packet.json").read_bytes())
        need(
            sha(encode(manifest)) == spec["sources_sha256"] and spec["pins"] == PINS,
            "packet_manifest",
        )
        save(
            self.output / "origin.json",
            {
                "t0_epoch": self.t0,
                "timer_epoch": deadline,
                "ready_by_epoch": self.ready_by,
                "work_by_epoch": self.work_by,
                "packet": spec,
                "source_manifest": manifest,
            },
        )
        self.call(
            [
                "nvidia-smi",
                "--query-gpu=name,uuid,memory.total,driver_version",
                "--format=csv",
            ],
            name="gpu",
        )
        gpu_lines = (self.output / "gpu.stdout").read_text().strip().splitlines()
        need(len(gpu_lines) == 2 and "L4" in gpu_lines[1], "l4_gpu")
        for index in (0, 1):
            self.call(
                [
                    "go",
                    "build",
                    "-trimpath",
                    "-o",
                    self.private / f"gateway{index}",
                    "./cmd/gateway",
                ],
                timeout=300,
                name=f"build-gateway{index}",
                env={
                    **os.environ,
                    "GOFLAGS": "-buildvcs=false",
                    "GOTOOLCHAIN": "local",
                },
            )
        for name in ("go", "docker"):
            self.call([name, "version"], name=name + "-version")
        for name in ("vllm", "redis", "nginx"):
            self.call(["docker", "pull", PINS[name]], timeout=600, name="pull-" + name)
            self.call(["docker", "image", "inspect", PINS[name]], name="image-" + name)
        self.call(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                self.private / "tls.key",
                "-out",
                self.private / "tls.crt",
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost",
                "-days",
                "1",
            ],
            name="tls-generation",
        )
        context = ssl.create_default_context(cafile=str(self.private / "tls.crt"))
        self.peer = sha(
            ssl.PEM_cert_to_DER_cert((self.private / "tls.crt").read_text())
        )
        (self.output / "tls.crt").write_bytes((self.private / "tls.crt").read_bytes())
        credentials = {slot: secrets.token_urlsafe(32) for slot in (0, 1)}
        tenants = {
            "tenants": control_tenants(
                {s: sha(v.encode()) for s, v in credentials.items()}
            )
        }
        save(self.private / "tenants.json", tenants)
        self.config_hash = sha((self.private / "tenants.json").read_bytes())
        (self.private / "salt").write_bytes(
            base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=") + b"\n"
        )
        model = self.private / "model"
        model.mkdir()
        mounts = [
            f"{self.packet}:/packet:ro",
            f"{self.output}:/evidence",
            f"{model}:/model",
        ]
        env = ["PYTHONPATH=/packet/python/src", "PYTHONDONTWRITEBYTECODE=1"]
        self.docker(
            "l4-stage",
            PINS["vllm"],
            ["python3", "/packet/scripts/l4_compat_container.py", "stage"],
            mounts=mounts,
            env=env,
        )
        status = self.call(
            ["docker", "wait", "l4-stage"], timeout=1200, name="stage-wait"
        )
        need(status.strip() == b"0", "model_stage")
        self.docker(
            "l4-engine",
            PINS["vllm"],
            ["python3", "/packet/scripts/l4_compat_container.py", "serve"],
            mounts=mounts,
            env=env,
            gpu=True,
        )
        self.stage(
            "engine_readiness", lambda: self.ready("http://127.0.0.1:8000/health")
        )
        self.docker(
            "l4-redis",
            PINS["redis"],
            [
                "redis-server",
                "--bind",
                "127.0.0.1",
                "--port",
                "16379",
                "--save",
                "",
                "--appendonly",
                "no",
            ],
        )
        self.redis_ready()
        # Body audit sees the exact generated upstream payload, including ignore_eos.
        # TLS ingress and audit proxy both disable buffering and upstream retries.
        config = """events {}\nhttp { log_format body escape=json '{"method":"$request_method","uri":"$uri","request_id":"$http_x_request_id","body":"$request_body","status":$status}';
access_log /evidence/upstream.jsonl body;
server { listen 127.0.0.1:8002; location / { proxy_pass http://127.0.0.1:8000; proxy_http_version 1.1; proxy_buffering off; proxy_request_buffering off; proxy_next_upstream off; proxy_read_timeout 35s; } }
"""
        for index in (0, 1):
            config += f"""server {{ listen 127.0.0.1:{8443 + index} ssl; ssl_certificate /private/tls.crt; ssl_certificate_key /private/tls.key; access_log off;
location / {{ proxy_pass http://127.0.0.1:{8080 + index}; proxy_http_version 1.1; proxy_buffering off; proxy_request_buffering off; proxy_next_upstream off; proxy_read_timeout 35s; }} }}\n"""
        config += "}\n"
        (self.private / "nginx.conf").write_text(config)
        self.docker(
            "l4-nginx",
            PINS["nginx"],
            ["nginx", "-g", "daemon off;", "-c", "/private/nginx.conf"],
            mounts=[f"{self.private}:/private:ro", f"{self.output}:/evidence"],
        )
        # Each alias phase has its own retained gateway generations; one engine
        # is never presented as two independent simultaneous replicas.
        for slot in (0, 1):
            if slot == 0:
                # Five first-alias requests, gateway shutdown and the second
                # alias's bounded readiness all precede the original ready_by.
                need(time.time() + 230 <= self.ready_by, "phase0_readiness_reserve")
            phase = []
            for index in (0, 1):
                name = f"phase{slot}-gateway{index}"
                environment = {
                    **os.environ,
                    "GATEWAY_HTTP_ADDR": f"127.0.0.1:{8080 + index}",
                    "BACKENDS": f"vllm-{slot}=http://127.0.0.1:8002",
                    "TENANT_CONFIG_PATH": str(self.private / "tenants.json"),
                    "CACHE_SALT_SECRET_FILE": str(self.private / "salt"),
                    "REDIS_ADDR": "127.0.0.1:16379",
                    "ADMISSION_NAMESPACE": "l4-compat",
                    "POD_UID": name,
                    "GATEWAY_MEASUREMENT_PATH": str(
                        self.output / (name + "-events.jsonl")
                    ),
                    "ADMISSION_RUNNING": "4",
                    "ADMISSION_WAITING": "1",
                    "OTEL_SDK_DISABLED": "true",
                }
                phase.append(
                    self.process([self.private / f"gateway{index}"], name, environment)
                )
                self.ready(f"http://127.0.0.1:{8080 + index}/readyz")
            need(time.time() <= self.ready_by, "readiness_deadline")
            self.deadline = self.work_by
            for row in requests():
                if row["slot"] == slot:
                    self.client_request(row, credentials, context)
            for child in phase:
                os.killpg(child.pid, signal.SIGTERM)
                child.wait(timeout=min(10, self.work_by - time.time()))
                self.children.remove(child)
            # Startup of the second alias uses the original readiness cutoff.
            self.deadline = self.ready_by
        self.deadline = self.work_by
        self.call(
            ["docker", "exec", "l4-redis", "redis-cli", "-p", "16379", "--scan"],
            name="redis-final-keys",
        )

    def freeze(self):
        # Runs on success and failure; no retries, truncation or dropping bytes.
        for child in self.children:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=10)
        for name in reversed(self.containers):
            inspect = subprocess.run(
                ["docker", "inspect", name], capture_output=True, timeout=15
            )
            if inspect.returncode:
                continue
            identity = json.loads(inspect.stdout)[0]
            if identity["Config"]["Labels"].get("l4-owner") != self.owner:
                continue  # An unsuccessful create cannot claim another owner's container.
            (self.output / (name + "-final-inspect.json")).write_bytes(inspect.stdout)
            result = subprocess.run(
                ["docker", "stop", "-t", "5", name], capture_output=True, timeout=15
            )
            (self.output / (name + "-stop.log")).write_bytes(
                result.stdout + result.stderr
            )
            result = subprocess.run(
                ["docker", "logs", name], capture_output=True, timeout=15
            )
            (self.output / (name + ".log")).write_bytes(result.stdout + result.stderr)
            subprocess.run(
                ["docker", "rm", "-f", name],
                check=True,
                capture_output=True,
                timeout=15,
            )
        for stream in self.logs:
            stream.close()
        native = self.output / "runtime/native"
        if (native / "events.sqlite").exists():
            with sqlite3.connect(
                f"file:{native / 'events.sqlite'}?mode=ro", uri=True
            ) as db:
                need(
                    db.execute("PRAGMA integrity_check").fetchall() == [("ok",)],
                    "sqlite_integrity",
                )
                events = [
                    json.loads(r[0])
                    for r in db.execute("SELECT value FROM events ORDER BY seq")
                ]
                origin = json.loads(db.execute("SELECT value FROM meta").fetchone()[0])
            save(
                self.output / "native-events.json",
                {"origin": origin, "events": events, "integrity_check": "ok"},
            )
        need(not (native / "FAILED").exists(), "native_loss")
        files = {
            p.relative_to(self.output).as_posix(): file_facts(p)
            for p in sorted(self.output.rglob("*"))
            if p.is_file()
        }
        need(
            sum(f["bytes"] for f in files.values()) <= EXPORT_BYTES,
            "complete_export_bound",
        )
        save(self.output / "inventory.json", files)

    def final_inventory(self):
        files = {
            p.relative_to(self.output).as_posix(): file_facts(p)
            for p in sorted(self.output.rglob("*"))
            if p.is_file() and p.name != "inventory.json"
        }
        need(
            sum(f["bytes"] for f in files.values()) <= EXPORT_BYTES,
            "complete_export_bound",
        )
        save(self.output / "inventory.json", files)

    def analyze(self):
        retained = json.loads((self.output / "native-events.json").read_bytes())
        audit = [
            json.loads(line)
            for line in (self.output / "upstream.jsonl").read_bytes().splitlines()
        ]
        chats = [
            r
            for r in audit
            if r["method"] == "POST" and r["uri"] == "/v1/chat/completions"
        ]
        need(
            len(chats) == 7 and len({r["request_id"] for r in chats}) == 7,
            "audit_chat_inventory",
        )
        upstream = [json.loads(row["body"]) for row in chats]
        parameters = {r["request_id"]: json.loads(r["body"]) for r in chats}
        need(
            len(upstream) == 7
            and sorted(x["max_tokens"] for x in upstream) == [1] + [CONTROL_TOKENS] * 6
            and all(x["ignore_eos"] is True for x in upstream),
            "upstream_parameters",
        )
        report = []
        released = set()
        for result in self.results:
            gateway_id = next(iter(result["request_ids"]))
            expected = next(r for r in requests() if r["id"] == result["id"])
            need(
                gateway_id in parameters
                and parameters[gateway_id]["max_tokens"]
                == expected["payload"]["max_tokens"]
                and parameters[gateway_id]["ignore_eos"] is True,
                "upstream_request_join",
            )
            native = native_summary(
                retained["events"],
                external="chatcmpl-" + gateway_id,
                cancel_ns=result["cancel_ns"],
                manifest=json.loads(
                    (self.packet / "overlay/native-manifest.json").read_bytes()
                ),
                origin=retained["origin"],
            )
            gateway = [
                json.loads(line)
                for line in (
                    self.output
                    / f"phase{result['slot']}-{result['gateway']}-events.jsonl"
                )
                .read_bytes()
                .splitlines()
            ]
            joined = [r for r in gateway if r["data"].get("request_id") == gateway_id]
            need(
                {"upstream_close", "release"} <= {r["event"] for r in joined},
                "gateway_close_release",
            )
            need(
                any(
                    r["event"] == "release" and r["data"]["result"] == "released"
                    for r in joined
                ),
                "redis_release",
            )
            released.add(gateway_id)
            report.append(
                {
                    "id": result["id"],
                    "duration_seconds": result["duration_seconds"],
                    "native": native,
                    "stream": result.get("stream"),
                    "gateway_events": joined,
                    "upstream_parameters": parameters[gateway_id],
                }
            )
        need(len(report) == 7, "request_set")
        need(len(released) == 7, "release_set")
        need(set(parameters) == released, "upstream_inventory")
        save(
            self.output / "compatibility.json",
            {
                "requests": report,
                "booking": measured_booking(
                    [
                        r["duration_seconds"]
                        for r in report
                        if r["id"] != "one-token-refusal"
                    ]
                ),
                "audit_rows": {
                    "total": len(audit),
                    "chat": len(chats),
                    "health": sum(r["uri"] == "/health" for r in audit),
                    "metrics": sum(r["uri"] == "/metrics" for r in audit),
                    "other": sum(
                        r not in chats and r["uri"] not in ("/health", "/metrics")
                        for r in audit
                    ),
                },
                "scope": "compatibility/timing only; not EKS, two-slot fitness or R366 planned-host acceptance",
            },
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packet", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--t0-epoch", type=float, required=True)
    args = parser.parse_args()
    run = Run(args.packet, args.output, args.t0_epoch)
    try:
        try:
            run.stage("run", run.run)
        except BaseException as exc:
            save(
                run.output / "failure.json",
                {"error": type(exc).__name__ + ":" + str(exc)},
            )
            raise
        finally:
            run.stage("freeze", run.freeze)
        run.stage("analyze", run.analyze)
    finally:
        run.final_inventory()
