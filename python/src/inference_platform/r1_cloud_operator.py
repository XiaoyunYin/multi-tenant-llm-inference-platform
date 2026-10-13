"""Source-bound SSM staging/control and verified operator-side recovery export."""

import argparse
import base64
import concurrent.futures
import hashlib
import http.client
import io
import json
import os
import re
import secrets
import shlex
import socket
import subprocess
import tarfile
import threading
import time
from pathlib import Path

from .archive_transfer import ARCHIVE_BYTES_PER_SECOND, CHUNK_TIMEOUT_SECONDS
from .r1_evidence import restore
from .r1_manifest import build, tenant_salt
from .r1_spec import SPEC_COMMIT, encoded
from .session_stop import stop_forward, terminate_forward_session

BUNDLE_CHUNK_BYTES = 1024**2
READY_HEALTH_FAILURES = 6


class ChannelError(OSError):
    pass


class BundleOffsetError(ValueError):
    pass


def cloud_init_commands():
    return [
        "cloud_code=0; cloud-init status --wait --format json >/opt/r1/cloud-init-status.json || cloud_code=$?",
        'case "$cloud_code" in 0|2) ;; *) exit "$cloud_code" ;; esac',
        "test -f /opt/r1/user-data.done",
    ]


def bootstrap_commands(script, token, bundle_sha256, deadline):
    """Launch the registered host bootstrap and require a process and listener."""
    argv = [
        "python3",
        "-B",
        "/opt/r1/bootstrap.py",
        "--token=" + token,
        "--bundle-sha256",
        bundle_sha256,
        "--deadline-unix-s",
        str(deadline),
    ]
    commands = [
        "set -eu",
        "install -d -m 0700 /opt/r1",
        *cloud_init_commands(),
        "test $(cat /etc/r1/deadline_epoch) -le "
        + str(int(deadline))
        + " || { printf '%s\\n' "
        + str(int(deadline))
        + " > /etc/r1/deadline_epoch; printf '%s\\n' "
        + shlex.join(
            [
                "[Timer]",
                "OnCalendar=@" + str(int(deadline)),
                "Persistent=true",
                "AccuracySec=1s",
                "Unit=r1-terminate.service",
                "[Install]",
                "WantedBy=timers.target",
            ]
        )
        + " > /etc/systemd/system/r1-terminate.timer; systemctl daemon-reload; "
        + "systemctl restart r1-terminate.timer; }",
        "printf %s "
        + shlex.quote(base64.b64encode(script).decode())
        + " | base64 -d > /opt/r1/bootstrap.py",
    ]
    return commands + [
        "nohup " + shlex.join(argv) + " >/opt/r1/bootstrap.log 2>&1 </dev/null &",
        "bootstrap_end=$(( $(date +%s) + 30 )); "
        "while ! { timeout 2 pgrep -f '^(/[^ ]*/)?python3 -B /opt/r1/bootstrap.py( |$)' >/dev/null && "
        "timeout 2 ss -H -ltn 'sport = :22280' | grep -q '127.0.0.1:22280'; }; do "
        "[ $(date +%s) -lt \"$bootstrap_end\" ] || { echo 'bootstrap not running/listening'; "
        "exit 1; }; sleep 1; done",
    ]


def host_diagnostic_commands():
    """One bounded SSM check; redact argv tokens before any output leaves the host."""
    source = """import re,subprocess
def run(command):
    try:
        result=subprocess.run(['timeout','2','sh','-c',command],stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT,timeout=3)
        return result.returncode,result.stdout.decode('utf-8',errors='replace')
    except subprocess.TimeoutExpired:
        return 124,'capture timed out'
process,_=run("pgrep -f '^(/[^ ]*/)?python3 -B /opt/r1/bootstrap.py( |$)'")
code,sockets=run("ss -H -ltn 'sport = :22280'")
print('R1_BOOTSTRAP_HEALTH='+('running-listening' if process==0 and code==0
                            and '127.0.0.1:22280' in sockets else 'not-running'))
captures=[
 ('systemctl status r1-bootstrap','systemctl status --no-pager --full r1-bootstrap'),
 ('bootstrap.log','tail -c 2048 /opt/r1/bootstrap.log'),
 ('ss -ltnp','ss -ltnp'),
 ('bootstrap/ssm process forest',"ps -ef --forest | grep -E 'bootstrap|ssm'"),
 ('bootstrap cgroups',"for pid in $(pgrep -f '^(/[^ ]*/)?python3 -B /opt/r1/bootstrap.py( |$)'); do "
  "case \\\"$pid\\\" in ''|0|*[!0-9]*) continue;; esac; "
  "echo /proc/$pid/cgroup; cat /proc/$pid/cgroup; done"),
 ('SSM agent journal',"journalctl --no-pager -n 60 --since=-40min "
  "-u snap.amazon-ssm-agent.amazon-ssm-agent.service -u amazon-ssm-agent.service"),
 ('/etc/hosts','cat /etc/hosts'),
 ('cloud-init','cloud-init status --long'),
 ('cloud-init-output.log','tail -c 2048 /var/log/cloud-init-output.log'),
 ('disk-before-pull.json','cat /opt/r1/disk-before-pull.json')]
for label,command in captures:
    code,output=run(command)
    output=re.sub(r'(--token(?:=|\\s+))\\S+',r'\\1[REDACTED]',output)
    output=re.sub(r'(Bearer\\s+)\\S+',r'\\1[REDACTED]',output)
    print('\\n--- '+label+' (exit '+str(code)+') ---')
    print(output.encode('utf-8')[-1536:].decode('utf-8',errors='ignore'))
"""
    return ["timeout 35 python3 - <<'R1_DIAGNOSTICS'\n" + source + "R1_DIAGNOSTICS"]


class Forward:
    """Fresh tunnels after transport faults; bind latency has its own bounded grace."""

    def __init__(self, operator, host, token, role, action):
        self.operator, self.host, self.token = operator, host, token
        self.role, self.action = role, action
        self.port, self.child, self.opened, self.reconnects = None, None, 0, 0
        self.started = time.time()
        self.status_failures, self.health_checked = 0, False

    def log(self, event, **fields):
        with (self.operator.runtime / f"{self.role}-{self.action}-channel.jsonl").open("ab") as out:
            out.write(
                encoded(
                    {
                        "event": event,
                        "elapsed_s": time.time() - self.started,
                        "reconnects": self.reconnects,
                        **fields,
                    }
                )
                + b"\n"
            )

    def close(self):
        if self.child is not None:
            try:
                result = terminate_forward_session(self.child)
                self.log("ssm_session_termination", **result)
            finally:
                try:
                    stop_forward(self.child)
                finally:
                    self.child = None

    def request(self, path, data=None, headers=None, retry_transport=True):
        backoff = 0.5
        while time.time() < self.operator.deadline:
            if self.action == "ready" and self.operator.ready_abort.is_set():
                raise RuntimeError("ready aborted after another host's bootstrap failure")
            try:
                if self.child is None:
                    self.port, self.child = self.operator.tunnel(self.host)
                    self.opened = time.time()
                if self.child.poll() is not None:
                    raise ChannelError("forward exited")
                if headers is None:
                    result = self.operator.rpc(self.port, path, self.token, data)
                else:
                    result = self.operator.rpc(self.port, path, self.token, data, headers)
                if path == "/status":
                    self.status_failures = 0
                return result
            except (OSError, http.client.HTTPException) as exc:
                # R108: a live fresh helper may take seconds to bind. Do not churn
                # helpers during that grace, but never extend the absolute cutoff.
                if (
                    isinstance(exc, ConnectionRefusedError)
                    and self.child
                    and self.child.poll() is None
                    and time.time() - self.opened < 10
                ):
                    time.sleep(min(0.5, max(0, self.operator.deadline - time.time())))
                    continue
                self.close()
                self.reconnects += 1
                self.log("reconnect", path=path, error=type(exc).__name__)
                if self.action == "ready" and path == "/status":
                    self.status_failures += 1
                    if self.status_failures >= READY_HEALTH_FAILURES and not self.health_checked:
                        self.health_checked = True
                        healthy = self.operator.bootstrap_health(self.host, self.role)
                        self.log(
                            "bootstrap_health",
                            running_listening=healthy,
                            consecutive_failures=self.status_failures,
                        )
                        if not healthy:
                            self.operator.ready_abort.set()
                            raise RuntimeError(
                                "ready bootstrap not running/listening; diagnostics recorded"
                            ) from exc
                if not retry_transport:
                    raise
                time.sleep(min(backoff, max(0, self.operator.deadline - time.time())))
                backoff = min(5, backoff * 2)
        raise TimeoutError("channel unavailable at original absolute deadline")


def bundle(repo, output, uv_linux, cache_secret):
    def git(*args):
        return subprocess.check_output(["git", "-C", str(repo), *args])

    if git("status", "--porcelain", "--untracked-files=no").strip():
        raise ValueError("bundle requires committed clean source")
    head = git("rev-parse", "HEAD").decode().strip()
    files = {}
    for name in (
        git("ls-files", "python/src", "python/pyproject.toml", "python/uv.lock", "python/README.md")
        .decode()
        .splitlines()
    ):
        files[name] = git("show", "HEAD:" + name)
    secret = cache_secret.read_bytes()
    if len(secret) != 32:
        raise ValueError("exact 32-byte cache salt secret required")
    bank = output.parent / "paid-manifests"
    build(bank, tenant_salt(secret))
    for path in bank.iterdir():
        files["manifests/" + path.name] = path.read_bytes()
    files["docs/R1_PRE_REGISTRATION.md"] = git("show", SPEC_COMMIT + ":docs/R1_PRE_REGISTRATION.md")
    for name in ("http-strict.json", "generator-600s.json"):
        files["readiness/" + name] = git("show", "HEAD:docs/evidence/round87-r1-readiness/" + name)
    gateway = output.parent / "gateway-linux"
    subprocess.run(
        ["go", "build", "-trimpath", "-o", str(gateway), "./cmd/gateway"],
        cwd=repo,
        env={
            **os.environ,
            "GOOS": "linux",
            "GOARCH": "amd64",
            "CGO_ENABLED": "0",
            "GOTOOLCHAIN": "local",
        },
        check=True,
    )
    files["bin/gateway"], files["bin/uv"] = gateway.read_bytes(), uv_linux.read_bytes()
    manifest = {
        "source_head": head,
        "files": {name: hashlib.sha256(data).hexdigest() for name, data in files.items()},
    }
    files["payload.json"] = encoded(manifest)
    with output.open("xb") as stream, tarfile.open(fileobj=stream, mode="w:gz") as archive:
        for name, data in sorted(files.items()):
            item = tarfile.TarInfo(name)
            item.size, item.mtime, item.mode = (
                len(data),
                0,
                0o755 if name.startswith("bin/") else 0o600,
            )
            archive.addfile(item, io.BytesIO(data))
    return {
        "source_head": head,
        "bundle_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
        "bundle_bytes": output.stat().st_size,
        "payload_manifest": manifest,
        "gateway_go_version": subprocess.check_output(["go", "version"], text=True).strip(),
        "uv_linux_sha256": hashlib.sha256(files["bin/uv"]).hexdigest(),
        "cache_secret_sha256": hashlib.sha256(secret).hexdigest(),
    }


class Operator:
    def __init__(self, repo, inputs, runtime, deadline):
        self.repo, self.inputs, self.runtime, self.deadline = (
            Path(repo).resolve(),
            inputs,
            runtime,
            deadline,
        )
        runtime.mkdir(parents=True, exist_ok=True)
        self.context_path = runtime / "operator-context.json"
        self.failure_lock = threading.Lock()
        self.ready_abort = threading.Event()

    def aws(self, service, operation, args, *, deadline=None):
        result = subprocess.check_output(
            [
                "aws",
                "--profile",
                self.inputs["aws_profile"],
                "--region",
                self.inputs["region"],
                service,
                operation,
                *args,
                "--output",
                "json",
                "--no-cli-pager",
            ],
            timeout=max(0.001, min(self.deadline, deadline or self.deadline) - time.time()),
            env={**os.environ, "AWS_CLI_OUTPUT_ENCODING": "utf-8"},
        )
        try:
            return json.loads(result.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            if service == "ssm" and operation == "get-command-invocation":
                # Selected response only; never save send-command's token parameters.
                path = self.runtime / f"ssm-parse-{threading.get_ident()}-{time.time_ns()}.stdout"
                path.write_bytes(result)
                with (
                    self.failure_lock,
                    (self.runtime / "ssm-parse-failures.jsonl").open("ab") as out,
                ):
                    out.write(
                        encoded(
                            {
                                "raw_file": path.name,
                                "bytes": len(result),
                                "sha256": hashlib.sha256(result).hexdigest(),
                            }
                        )
                        + b"\n"
                    )
            raise

    def ssm(self, host, commands, *, timeout_s=None):
        end = min(self.deadline, time.time() + timeout_s) if timeout_s else self.deadline

        def aws(service, operation, args):
            if timeout_s is None:
                return self.aws(service, operation, args)
            return self.aws(service, operation, args, deadline=end)

        response = aws(
            "ssm",
            "send-command",
            [
                "--instance-ids",
                host,
                "--document-name",
                "AWS-RunShellScript",
                "--parameters",
                json.dumps(
                    {
                        "commands": commands,
                        "executionTimeout": [str(max(1, int(end - time.time())))],
                    }
                ),
            ],
        )
        identifier = response["Command"]["CommandId"]
        while time.time() < end:
            if timeout_s is None and self.ready_abort.is_set():
                raise RuntimeError("SSM wait aborted after ready host failure")
            try:
                result = aws(
                    "ssm",
                    "get-command-invocation",
                    ["--command-id", identifier, "--instance-id", host],
                )
            except (subprocess.CalledProcessError, UnicodeDecodeError, json.JSONDecodeError):
                time.sleep(min(1, max(0, end - time.time())))
                continue
            if result["Status"] in {"Pending", "InProgress", "Delayed"}:
                time.sleep(min(1, max(0, end - time.time())))
                continue
            if result["Status"] != "Success":
                role = host
                if self.context_path.exists():
                    binding = json.loads(self.context_path.read_bytes())
                    role = next((r for r, h in binding["hosts"].items() if h["id"] == host), host)
                failure = {
                    "role": role,
                    "instance": host,
                    "CommandId": identifier,
                    "Status": result["Status"],
                    "ResponseCode": result.get("ResponseCode"),
                }
                for key in ("StandardOutputContent", "StandardErrorContent"):
                    failure[key] = self.redact(
                        result.get(key, "").encode("utf-8")[-4096:].decode("utf-8", errors="ignore")
                    )
                # Only selected invocation fields; parameters contain the control token.
                with self.failure_lock, (self.runtime / "ssm-failures.jsonl").open("ab") as out:
                    out.write(encoded(failure) + b"\n")
                raise RuntimeError(
                    f"SSM {role} ({host}) command {identifier} failed: {failure['Status']} "
                    f"code={failure['ResponseCode']}; stderr tail: {failure['StandardErrorContent']}"
                )
            return result
        raise TimeoutError("SSM command deadline")

    def redact(self, text):
        text = re.sub(r"(--token(?:=|\s+))\S+", r"\1[REDACTED]", text)
        text = re.sub(r"(Bearer\s+)\S+", r"\1[REDACTED]", text)
        if self.context_path.exists():
            context = json.loads(self.context_path.read_bytes())
            for key in ("control_token", "agent_token", "credential", "secret"):
                if context.get(key):
                    text = text.replace(context[key], "[REDACTED]")
        return text

    def bootstrap_health(self, host, role):
        try:
            invocation = self.ssm(host, host_diagnostic_commands(), timeout_s=45)
            result = {
                key: self.redact(str(invocation.get(key, "")))
                for key in (
                    "CommandId",
                    "Status",
                    "ResponseCode",
                    "StandardOutputContent",
                    "StandardErrorContent",
                )
            }
            healthy = result["StandardOutputContent"].splitlines()[0] == (
                "R1_BOOTSTRAP_HEALTH=running-listening"
            )
        except Exception as exc:
            result, healthy = {"error": self.redact(str(exc))}, False
        with self.failure_lock, (self.runtime / "bootstrap-health.jsonl").open("ab") as out:
            out.write(encoded({"role": role, "running_listening": healthy, **result}) + b"\n")
        return healthy

    def tunnel(self, host):
        with socket.socket() as reserve:
            reserve.bind(("127.0.0.1", 0))
            port = reserve.getsockname()[1]
        log_path = self.runtime / (host + "-forward-" + secrets.token_hex(8) + ".log")
        log = log_path.open("xb")
        plugin_dir = (self.repo / self.inputs["session_manager_plugin_path"]).resolve().parent
        child = subprocess.Popen(
            [
                "aws",
                "--profile",
                self.inputs["aws_profile"],
                "--region",
                self.inputs["region"],
                "ssm",
                "start-session",
                "--target",
                host,
                "--document-name",
                "AWS-StartPortForwardingSession",
                "--parameters",
                json.dumps({"portNumber": ["22280"], "localPortNumber": [str(port)]}),
            ],
            env={
                **os.environ,
                "AWS_CLI_OUTPUT_ENCODING": "utf-8",
                "PATH": os.pathsep.join((str(plugin_dir), os.environ.get("PATH", ""))),
            },
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        log.close()
        child.r1_ssm_log = log_path
        child.r1_ssm_env = {**os.environ, "AWS_CLI_OUTPUT_ENCODING": "utf-8"}
        child.r1_ssm_argv = [
            "aws",
            "--profile",
            self.inputs["aws_profile"],
            "--region",
            self.inputs["region"],
        ]
        if isinstance(child.pid, int):
            log_path.with_suffix(".owner.json").write_bytes(
                encoded(
                    {
                        "invocation_token": os.environ.get("R1_OPERATOR_INVOCATION"),
                        "operator_pid": os.getpid(),
                        "forward_pid": child.pid,
                        "profile": self.inputs["aws_profile"],
                        "region": self.inputs["region"],
                    }
                )
            )
        return port, child

    def rpc(self, port, path, token, data=None, headers=None):
        remaining = self.deadline - time.time()
        if remaining <= 0:
            raise TimeoutError("operator absolute deadline")
        connection = http.client.HTTPConnection(
            "127.0.0.1", port, timeout=min(remaining, CHUNK_TIMEOUT_SECONDS)
        )
        try:
            connection.request(
                "GET" if data is None else "POST",
                path,
                body=data,
                headers={**(headers or {}), "Authorization": "Bearer " + token},
            )
            response = connection.getresponse()
            content = response.read()
            if response.status >= 500:
                raise ChannelError(f"forward HTTP {response.status}")
            if response.status == 409 and path.startswith("/bundle/"):
                raise BundleOffsetError(f"bundle conflict: {content[:300]!r}")
            if response.status != 200:
                raise RuntimeError(f"host control {response.status}: {content[:300]!r}")
            return content, dict(response.getheaders())
        finally:
            connection.close()

    def upload_bundle(self, channel, path):
        if file_sha(path) != self.inputs["bundle_sha256"]:
            raise ValueError("local reviewed bundle changed")
        size, started, chunks, resumed = path.stat().st_size, time.time(), 0, []
        if not 0 < size <= 100 * 1024**2:
            raise ValueError("bounded bundle size")
        with path.open("rb") as stream:
            while time.time() < self.deadline:
                content, _ = channel.request("/bundle")
                state = json.loads(content)
                offset = state["offset"]
                if type(offset) is not int or not 0 <= offset <= size:
                    raise ValueError("invalid host bundle offset")
                if state["staged"] or offset == size:
                    if offset != size:
                        raise ValueError("staged bundle size mismatch")
                    break
                stream.seek(offset)
                data = stream.read(min(BUNDLE_CHUNK_BYTES, size - offset))
                chunks += 1
                try:
                    channel.request(
                        f"/bundle/{offset}",
                        data,
                        {"X-Chunk-SHA256": hashlib.sha256(data).hexdigest()},
                        retry_transport=False,
                    )
                except (OSError, http.client.HTTPException, BundleOffsetError):
                    content, _ = channel.request("/bundle")
                    resume = json.loads(content)["offset"]
                    resumed.append(resume)
                    channel.log("bundle_resumed", offset=resume)
            else:
                raise TimeoutError("bundle upload absolute deadline")
        content, _ = channel.request("/bundle/commit", b"")
        if not json.loads(content)["staged"]:
            raise ValueError("bundle commit did not stage payload")
        channel.log(
            "bundle_uploaded",
            bytes=size,
            upload_elapsed_s=time.time() - started,
            chunks=chunks,
            resume_offsets=resumed,
            reconnects=channel.reconnects,
        )

    def retrieve(self, channel, url, destination, expected=None):
        state_path = destination.with_suffix(destination.suffix + ".transfer.json")
        state = json.loads(state_path.read_bytes()) if state_path.exists() else {}
        size = state.get("bytes")
        offset = destination.stat().st_size if destination.exists() else 0
        resumed_at = offset
        started = time.time()
        if offset and size is None:
            raise ValueError("partial archive missing fixed-size binding")
        if size is not None and offset > size:
            raise ValueError("partial archive exceeds fixed size")
        with destination.open("ab") as stream:
            while size is None or offset < size:
                content, headers = channel.request(f"{url}/{offset}")
                reported = int(headers["X-Archive-Size"])
                if size is not None and size != reported:
                    raise ValueError("archive changed during frozen export")
                if expected and reported != expected["bytes"]:
                    raise ValueError("segment size differs from sealed manifest")
                size = reported
                if not 0 < size <= 20 * 1024**3 or not content or offset + len(content) > size:
                    raise ValueError("archive size/chunk bounds")
                if hashlib.sha256(content).hexdigest() != headers["X-Chunk-SHA256"]:
                    raise ValueError("recovery chunk hash mismatch")
                state_path.write_bytes(encoded({"bytes": size}))
                stream.write(content)
                stream.flush()
                offset += len(content)
                channel.log("chunk", archive=destination.name, offset=offset, bytes=len(content))
        digest = file_sha(destination)
        if expected and digest != expected["sha256"]:
            raise ValueError("sealed segment SHA mismatch")
        receipt = {
            "bytes": size,
            "sha256": digest,
            "complete": offset == size,
            "elapsed_s": time.time() - started,
            "resumed_at": resumed_at,
            "minimum_rate_bps": ARCHIVE_BYTES_PER_SECOND,
            "transfer_at_floor_s": size / ARCHIVE_BYTES_PER_SECOND,
            "reconnects": channel.reconnects,
        }
        state_path.write_bytes(encoded({**receipt, "offset": offset}))
        channel.log("retrieved", **receipt)
        return receipt

    def pull_segments(self, channel, role):
        content, _ = channel.request("/segments")
        listing = json.loads(content)
        if listing.get("spool_error"):
            channel.log("spool_error", error=listing["spool_error"])
        folder = self.runtime / (role + "-segments")
        folder.mkdir(exist_ok=True)
        total = 0
        for item in listing["segments"]:
            name = item["name"]
            if len(name) != 13 or not name[:6].isdigit() or name[6:] != ".tar.gz":
                raise ValueError("invalid sealed segment name")
            destination = folder / name
            marker = destination.with_suffix(".restored")
            if not marker.exists():
                self.retrieve(channel, "/segment/" + name, destination, item)
                restore(destination, self.runtime / role)
                marker.write_bytes(encoded(item))
                channel.log("segment_restored", segment=name, bytes=item["bytes"])
            elif json.loads(marker.read_bytes()) != item:
                raise ValueError("sealed segment binding changed")
            total += item["bytes"]
        return total

    def with_host(self, role, action, context=None, stop=None):
        binding = context or json.loads(self.context_path.read_bytes())
        host, token = binding["hosts"][role]["id"], binding["control_token"]
        channel = Forward(self, host, token, role, action)
        try:
            content, _ = channel.request("/status")
            if json.loads(content)["bundle_sha256"] != self.inputs["bundle_sha256"]:
                raise ValueError("host bound to a different bundle")
            if context is not None:
                self.upload_bundle(channel, self.repo / self.inputs["bundle_path"])
            if action == "collect":
                while time.time() < self.deadline and not stop.is_set():
                    self.pull_segments(channel, role)
                    stop.wait(min(5, max(0, self.deadline - time.time())))
                return
            if action == "close":
                # Defense in depth even when the wrapper lost its measure process.
                actions = json.loads(content)["actions"]
                if "measure" in actions and actions["measure"] is None:
                    channel.log("close_refused", reason="host Session running")
                    return
            if action == "export" and role == "generator":
                while (
                    "measure" in json.loads(content)["actions"]
                    and json.loads(content)["actions"]["measure"] is None
                ):
                    channel.log("export_waits_for_session", close_sent=False)
                    self.pull_segments(channel, role)
                    time.sleep(min(1, max(0, self.deadline - time.time())))
                    content, _ = channel.request("/status")
            request = {"action": action, "deadline_unix_s": self.deadline}
            if context is not None:
                request["context"] = {**binding, "role": role}
            channel.request("/run", encoded(request))
            while time.time() < self.deadline:
                state, _ = channel.request("/status")
                code = json.loads(state)["actions"][action]
                if code is not None:
                    if code != 0:
                        raise RuntimeError(
                            f"host {role} {action} failed (exit {code}; retained host log)"
                        )
                    break
                if action == "measure":
                    self.pull_segments(channel, role)
                if action == "measure" and self.deadline - time.time() <= 2:
                    return
                time.sleep(min(1, max(0, self.deadline - time.time())))
            else:
                raise TimeoutError("host action absolute deadline")
            if action == "export":
                transfer_started = time.time()
                before = sum(
                    p.stat().st_size for p in (self.runtime / (role + "-segments")).glob("*.tar.gz")
                )
                incremental = self.pull_segments(channel, role)
                destination = self.runtime / (role + "-evidence.tar.gz")
                receipt = self.retrieve(channel, "/archive", destination)
                with tarfile.open(destination, "r:gz") as archive:
                    index = json.load(archive.extractfile("incremental-index.json"))
                for item in index["segments"]:
                    marker = self.runtime / (role + "-segments") / item["name"]
                    if not marker.exists() or file_sha(marker) != item["sha256"]:
                        raise ValueError("final segment inventory incomplete")
                receipt["incremental_bytes"] = incremental
                receipt["final_remaining_bytes"] = incremental - before + receipt["bytes"]
                receipt["final_transfer_at_floor_s"] = (
                    receipt["final_remaining_bytes"] / ARCHIVE_BYTES_PER_SECOND
                )
                receipt["final_retrieval_elapsed_s"] = time.time() - transfer_started
                receipt["remaining_window_s"] = max(0, self.deadline - time.time())
                channel.log("export_actual_sizes", **receipt)
                (self.runtime / (role + "-export.json")).write_bytes(encoded(receipt))
        finally:
            channel.log("channel_closed")
            channel.close()

    def measure(self):
        stop = threading.Event()
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            collectors = [
                pool.submit(self.with_host, role, "collect", stop=stop)
                for role in ("service", "gpu-0", "gpu-1")
            ]
            try:
                self.with_host("generator", "measure")
            finally:
                stop.set()
            for future in collectors:
                future.result()

    def monitor_measure(self):
        """Fresh independent send-command after operator error; never sends close."""
        if not self.context_path.exists():
            return False  # Measurement cannot have started without durable context.
        binding = json.loads(self.context_path.read_bytes())
        host = binding["hosts"]["generator"]["id"]
        commands = [
            "python3 - <<'PY'",
            "import json, pathlib",
            "d=pathlib.Path('/opt/r1/control')",
            "running=(d/'measure-started.json').exists() and not (d/'measure-terminal.json').exists()",
            "print(json.dumps({'running':running}))",
            "PY",
        ]
        while time.time() < self.deadline:
            try:
                result = self.ssm(host, commands)
                running = json.loads(result["StandardOutputContent"])["running"]
            except (OSError, subprocess.SubprocessError, RuntimeError, ValueError) as exc:
                with (self.runtime / "measure-recovery.jsonl").open("ab") as out:
                    out.write(
                        encoded(
                            {
                                "at": time.time(),
                                "running": "unknown",
                                "error": type(exc).__name__,
                                "close_sent": False,
                            }
                        )
                        + b"\n"
                    )
                time.sleep(min(5, max(0, self.deadline - time.time())))
                continue
            with (self.runtime / "measure-recovery.jsonl").open("ab") as out:
                out.write(
                    encoded(
                        {"at": time.time(), "running": running, "channel": "fresh SSM send-command"}
                    )
                    + b"\n"
                )
            if not running:
                return False
            time.sleep(min(5, max(0, self.deadline - time.time())))
        return True

    def reconstruct_gateway_export(self):
        folder = self.runtime / "generator/session"
        metadata = json.loads((folder / "service-export-metadata.json").read_bytes())
        receipt = json.loads((folder / "export-receipt.json").read_bytes())
        logs = {"configurations": metadata["configurations"], "gateway_logs": {}}
        for name in ("gateway-0.jsonl", "gateway-1.jsonl"):
            path = self.runtime / "service/logs" / name
            if path.exists():
                logs["gateway_logs"][name] = path.read_text(encoding="utf-8")
        data = encoded(logs) + b"\n"
        if hashlib.sha256(data).hexdigest() != receipt["sha256"]:
            raise ValueError("reconstructed service export differs from host receipt")
        (folder / "service-export.json").write_bytes(data)

    def readiness_diagnostics(self):
        """One SSM command per available host, sharing a bounded cleanup deadline."""
        if self.context_path.exists():
            hosts = json.loads(self.context_path.read_bytes())["hosts"]
        else:
            tf = (self.repo / self.inputs["terraform"]).resolve()
            hosts = json.loads(
                subprocess.check_output(
                    [
                        str(tf),
                        "-chdir=" + str(self.repo / "infra/terraform/r1"),
                        "output",
                        "-json",
                        "hosts",
                    ],
                    timeout=max(0.001, self.deadline - time.time()),
                )
            )
        commands = host_diagnostic_commands()

        def collect(role):
            host = hosts[role]["id"]
            try:
                result = self.ssm(host, commands, timeout_s=45)
                return {
                    "role": role,
                    "instance": host,
                    **{
                        key: self.redact(str(result.get(key, "")))
                        for key in (
                            "CommandId",
                            "Status",
                            "ResponseCode",
                            "StandardOutputContent",
                            "StandardErrorContent",
                        )
                    },
                }
            except Exception as exc:
                return {"role": role, "instance": host, "error": self.redact(str(exc))}

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(collect, hosts))
        with (self.runtime / "readiness-diagnostics.jsonl").open("ab") as out:
            for result in results:
                out.write(encoded(result) + b"\n")
        return results

    def ready(self):
        tf = (self.repo / self.inputs["terraform"]).resolve()
        if not tf.is_file():
            raise FileNotFoundError("reviewed Terraform binary is missing")
        hosts = json.loads(
            subprocess.check_output(
                [
                    str(tf),
                    "-chdir=" + str(self.repo / "infra/terraform/r1"),
                    "output",
                    "-json",
                    "hosts",
                ],
                timeout=30,
            )
        )
        secret = (self.repo / self.inputs["cache_secret_path"]).read_bytes()
        if hashlib.sha256(secret).hexdigest() != self.inputs["cache_secret_sha256"]:
            raise ValueError("reviewed cache secret changed")
        context = {
            "hosts": hosts,
            "agent_token": secrets.token_hex(32),
            "credential": secrets.token_hex(32),
            "control_token": secrets.token_hex(32),
            "secret": base64.urlsafe_b64encode(secret).decode().rstrip("="),
            "session_id": self.inputs["session_id"],
            "source_head": self.inputs["source_head"],
            "cpu_memory_bytes": self.inputs["cpu_memory_bytes"],
            "cpu_memory_source": self.inputs["cpu_memory_source"],
        }
        # Persist before any remote action: partial provisioning/bootstrap recovers
        # through the same authenticated channel, with no secret in export receipts.
        self.context_path.write_bytes(encoded(context))
        script = (self.repo / "scripts/r1-host-bootstrap.py").read_bytes()
        full_deadline = self.deadline + 13680  # ready cutoff=start+2400; original end=start+16080

        def host(role):
            while time.time() < self.deadline:
                status = self.aws(
                    "ssm",
                    "describe-instance-information",
                    ["--filters", "Key=InstanceIds,Values=" + hosts[role]["id"]],
                )
                if any(x["PingStatus"] == "Online" for x in status["InstanceInformationList"]):
                    break
                time.sleep(1)
            else:
                raise TimeoutError("SSM host never became online")
            self.ssm(
                hosts[role]["id"],
                bootstrap_commands(
                    script, context["control_token"], self.inputs["bundle_sha256"], full_deadline
                ),
            )
            self.with_host(role, "ready", context)

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            futures = [pool.submit(host, role) for role in hosts]
            try:
                for future in concurrent.futures.as_completed(futures):
                    future.result()
            except BaseException:
                self.ready_abort.set()
                for future in futures:
                    future.cancel()
                raise
        self.with_host("generator", "probe")


def file_sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1048576), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--inputs", type=Path)
    parser.add_argument("--action", choices=("ready", "measure", "monitor", "close", "export"))
    parser.add_argument("--deadline-unix-s", type=float)
    parser.add_argument("--build-bundle", type=Path)
    parser.add_argument("--uv-linux", type=Path)
    parser.add_argument("--cache-secret", type=Path)
    args = parser.parse_args()
    if args.build_bundle:
        args.build_bundle.parent.mkdir(parents=True, exist_ok=True)
        result = bundle(args.repo, args.build_bundle, args.uv_linux, args.cache_secret)
        args.build_bundle.with_suffix(".receipt.json").write_bytes(encoded(result))
        print(json.dumps({k: v for k, v in result.items() if k != "payload_manifest"}))
        return
    if not args.inputs or not args.action or args.deadline_unix_s is None:
        parser.error("lifecycle action needs exact inputs and an absolute deadline")
    inputs = json.loads(args.inputs.read_bytes())
    operator = Operator(
        args.repo, inputs, args.repo / inputs["runtime_directory"], args.deadline_unix_s
    )
    if args.action == "ready":
        operator.ready()
    elif args.action == "measure":
        operator.measure()
    elif args.action == "monitor":
        operator.monitor_measure()
    elif args.action == "export":
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            list(
                pool.map(
                    lambda role: operator.with_host(role, "export"),
                    ("gpu-0", "gpu-1", "service", "generator"),
                )
            )
        operator.reconstruct_gateway_export()
    else:
        operator.with_host("generator", args.action)


if __name__ == "__main__":
    main()
