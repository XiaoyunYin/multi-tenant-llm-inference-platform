"""Per-phase Linux commands for the isolated INF-060 transfer agent."""

import argparse
import base64
import hashlib
import json
import os
import secrets
import signal
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
from collections import Counter
from pathlib import Path
from urllib.request import urlopen

import inf060_diagnostics as diagnostics
from inf060_probe_client import (
    FORMAT,
    bracket,
    clock_exchange,
    join,
    latency_summary,
    request,
    run_arm,
    suppress,
)
from inf060_probe_spec import (
    ARM_S,
    EXPORT_BYTES,
    IMAGE_PYTHON,
    LOG_CONFIG,
    LOG_CONFIG_SHA,
    MODEL,
    PHASES,
    READY_S,
    RESTART_S,
    VERIFY_S,
    check,
    facts,
    load,
    save,
)


def pid_start(pid):
    return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]


def env(root, repo):
    return {
        "HOME": str(root / "home"),
        "PATH": str(root / "tools/go/bin")
        + ":/opt/dec077/tools/docker:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C.UTF-8",
        "TZ": "UTC",
        "GOTOOLCHAIN": "local",
        "GOFLAGS": "-buildvcs=false -mod=readonly",
        "CGO_ENABLED": "0",
        "GOPATH": str(root / "gopath"),
        "GOCACHE": str(root / "gocache"),
        "PYTHONPATH": str(repo / "python/src"),
        "PYTHONDONTWRITEBYTECODE": "1",
    }


class Phase:
    def __init__(self, root, origin, end, cpu, failure=None):
        self.root, self.origin, self.end, self.cpu = root, origin, end, cpu
        self.repo = root / "repo"
        self.private = root / "private"
        self.output = root / "results"
        self.engine = load(self.repo / "engine.json")
        self.requests = load(self.repo / "requests.json")
        self.pins = load(self.repo / "tools.json")
        self.data = load(root / "runtime.json")
        self.output.mkdir(exist_ok=True)
        self.private.mkdir(mode=0o700, exist_ok=True)
        (root / "home").mkdir(mode=0o700, exist_ok=True)
        self.owner = hashlib.sha256(str(root).encode()).hexdigest()[:16]
        self.failure = diagnostics.injected_failure(cpu, failure)

    def call(self, argv, limit=60):
        left = min(limit, self.end - time.time())
        check(left > 0, "phase_deadline")
        command = str(argv[0]).rsplit("/", 1)[-1]
        action = ":" + str(argv[1]) if command in {"systemctl", "docker", "go"} else ""
        try:
            result = subprocess.run(
                list(map(str, argv)),
                cwd=self.repo,
                env=env(self.root, self.repo),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=left,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            self.command_tail(error.stderr or b"")
            raise TimeoutError(f"inf060:command:{command}{action}:timeout") from None
        if result.returncode:
            self.command_tail(result.stderr)
        check(
            result.returncode == 0,
            f"command:{command}{action}:exit={result.returncode}",
        )
        return result.stdout

    def command_tail(self, raw):
        diagnostics.write(self.output / "failure-command.json", diagnostics.tail(raw))

    def timed(self, name, action, *args, **kwargs):
        wall, mono = time.time(), time.monotonic()
        code = 1
        try:
            value = action(*args, **kwargs)
            code = 0
            return value
        finally:
            save(
                self.output / ("operation-" + name + ".json"),
                {
                    "start_epoch": wall,
                    "end_epoch": time.time(),
                    "elapsed_s": time.monotonic() - mono,
                    "exit_code": code,
                },
            )

    def force_mock_failure(self, step):
        if self.failure == step:
            # These mock-only lines exercise structured failure export.
            print(
                f"{time.time():.6f} ERROR [worker.py:42] mock failure detail",
                file=sys.stderr,
            )
            print("ModuleNotFoundError: mock failure detail", file=sys.stderr)
            print(
                "Engine core initialization failed: mock failure detail",
                file=sys.stderr,
            )
            check(False, "rehearsal_" + step)

    def name(self, role):
        return "inf060-" + self.owner + "-" + role

    def docker(self, role, image, args, *, mounts=(), variables=None, gpu=False):
        name = self.name(role)
        options = [
            "docker",
            "run",
            "-d",
            "--network=host",
            "--name",
            name,
            "--label",
            "inf060-owner=" + self.owner,
        ]
        if gpu:
            options += ["--gpus", "all", "--ipc", "host"]
        for host, destination, mode in mounts:
            options += ["-v", f"{host}:{destination}:{mode}"]
        for k, v in (variables or {}).items():
            options += ["-e", k + "=" + v]
        self.call([*options, "--entrypoint", args[0], image, *args[1:]], 60)
        return name

    def check_image(self, image):
        image_row = json.loads(self.call(["docker", "image", "inspect", image]))[0]
        digests = image_row.get("RepoDigests", [])
        check(
            any(d.rsplit("@", 1)[-1] == image.rsplit("@", 1)[-1] for d in digests),
            "image_digest",
        )

    def start(self, name, argv, updates=None):
        state = self.private / (name + ".process.json")
        check(not state.exists(), "process_reuse")
        with (self.private / (name + ".log")).open("xb") as stream:
            proc = subprocess.Popen(
                list(map(str, argv)),
                cwd=self.repo,
                env={**env(self.root, self.repo), **(updates or {})},
                stdin=subprocess.DEVNULL,
                stdout=stream,
                stderr=subprocess.STDOUT,
            )
        save(state, {"pid": proc.pid, "start": pid_start(proc.pid)})

    def stop_process(self, name):
        path = self.private / (name + ".process.json")
        if not path.exists():
            return
        row = load(path)
        try:
            current = pid_start(row["pid"])
        except FileNotFoundError:
            return
        check(current == row["start"], "process_identity_changed")
        os.kill(row["pid"], signal.SIGTERM)
        for _ in range(25):
            try:
                if pid_start(row["pid"]) != row["start"]:
                    return
                status = (
                    Path(f"/proc/{row['pid']}/stat")
                    .read_text()
                    .rsplit(")", 1)[1]
                    .split()[0]
                )
                if status == "Z":
                    return
            except FileNotFoundError:
                return
            time.sleep(0.2)
        os.kill(row["pid"], signal.SIGKILL)

    def remove(self, role):
        names = (
            self.call(
                [
                    "docker",
                    "ps",
                    "-a",
                    "--filter",
                    "label=inf060-owner=" + self.owner,
                    "--format",
                    "{{.Names}}",
                ]
            )
            .decode()
            .splitlines()
        )
        if self.name(role) in names:
            self.call(["docker", "rm", "-f", "-v", self.name(role)], 25)

    def ready(self, url):
        while time.time() + 1 < self.end:
            try:
                with urlopen(url, timeout=1) as reply:
                    if reply.status == 200:
                        return
            except OSError:
                time.sleep(0.25)
        raise TimeoutError("inf060:readiness")

    def go(self):
        spec = self.pins["go"]
        tools = self.root / "tools"
        tools.mkdir(exist_ok=False)
        tar = tools / "go.tar.gz"
        with urlopen(spec["url"], timeout=15) as reply, tar.open("xb") as target:
            size = 0
            while chunk := reply.read(1024**2):
                size += len(chunk)
                check(
                    size <= spec["bytes"] and time.time() < self.end,
                    "go_download_bound",
                )
                target.write(chunk)
        check(facts(tar) == {k: spec[k] for k in ("bytes", "sha256")}, "go_digest")
        with tarfile.open(tar) as source:
            source.extractall(tools, filter="data")
        self.call(
            [
                "go",
                "build",
                "-trimpath",
                "-o",
                self.private / "gateway",
                "./cmd/gateway",
            ],
            300,
        )

    def prepare(self):
        self.call(["systemctl", "is-active", "--quiet", "dec077-terminate.timer"])
        check(
            facts(self.repo / LOG_CONFIG)["sha256"] == LOG_CONFIG_SHA, "logging_config"
        )
        self.force_mock_failure("prepare")
        if not self.cpu:
            gpu = self.call(
                ["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"]
            ).decode()
            check(gpu.strip() == "NVIDIA L4", "host_gpu")
        self.call(["systemctl", "start", "docker"])
        self.go()
        for role in ("nginx", "redis", *(() if self.cpu else ("vllm",))):
            self.timed(
                "pull-" + role, self.call, ["docker", "pull", self.pins[role]], 600
            )
            self.check_image(self.pins[role])
        if self.cpu:
            save(
                self.private / "prompts.json",
                [row["canary"] for row in self.requests["slots"]],
            )
            save(
                self.output / "model-readback.json",
                {"mode": "CPU fixture", "gpu_model_loaded": False},
            )
        else:
            model = self.private / "model"
            model.mkdir()
            stage = self.timed(
                "model-stage-start",
                self.docker,
                "stage",
                self.pins["vllm"],
                [IMAGE_PYTHON, "/packet/scripts/inf060_probe_engine.py", "stage"],
                mounts=(
                    (self.repo, "/packet", "ro"),
                    (self.private, "/private", "rw"),
                    (model, "/model", "rw"),
                ),
            )
            check(
                self.timed(
                    "model-stage-wait",
                    self.call,
                    ["docker", "wait", stage],
                    self.data["weights_timeout_s"],
                ).strip()
                == b"0",
                "model_stage",
            )
            save(
                self.output / "model-readback.json",
                load(self.private / "model-readback.json"),
            )
            self.remove("stage")
        self.docker(
            "redis",
            self.pins["redis"],
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
        redis_ready = min(self.end, time.time() + 20)
        while time.time() < redis_ready:
            try:
                if (
                    self.call(
                        [
                            "docker",
                            "exec",
                            self.name("redis"),
                            "redis-cli",
                            "-p",
                            "16379",
                            "PING",
                        ],
                        2,
                    ).strip()
                    == b"PONG"
                ):
                    break
            except ValueError:
                pass
            time.sleep(0.25)
        else:
            raise TimeoutError("inf060:redis_readiness")
        self.call(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-keyout",
                self.private / "tls.key",
                "-out",
                self.private / "tls.crt",
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost",
            ]
        )
        credential = secrets.token_urlsafe(32)
        (self.private / "credential").write_text(credential)
        (self.private / "salt").write_bytes(
            base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=") + b"\n"
        )
        save(
            self.private / "tenants.json",
            {
                "tenants": [
                    {
                        "tenant_id": "inf060-probe",
                        "credential_sha256": hashlib.sha256(
                            credential.encode()
                        ).hexdigest(),
                        "models": [MODEL],
                        "max_request_bytes": 65536,
                        "max_output_tokens": 32,
                        "request_rate_limit": 120,
                        "request_rate_window_ms": 60000,
                        "max_concurrent": 64,
                    }
                ]
            },
        )
        (self.private / "nginx.conf").write_text(
            "events {}\nhttp { access_log off; server { listen 127.0.0.1:8443 ssl; "
            "ssl_certificate /private/tls.crt; ssl_certificate_key /private/tls.key; "
            "location / { proxy_pass http://127.0.0.1:8080; proxy_http_version 1.1; "
            "proxy_buffering off; proxy_request_buffering off; proxy_next_upstream off; "
            "proxy_read_timeout 35s; } } }\n"
        )
        self.docker(
            "tls",
            self.pins["nginx"],
            ["nginx", "-g", "daemon off;", "-c", "/private/nginx.conf"],
            mounts=((self.private, "/private", "ro"),),
        )
        self.start(
            "gateway",
            [self.private / "gateway"],
            {
                "GATEWAY_HTTP_ADDR": "127.0.0.1:8080",
                "BACKENDS": "vllm-0=http://127.0.0.1:8000",
                "TENANT_CONFIG_PATH": str(self.private / "tenants.json"),
                "CACHE_SALT_SECRET_FILE": str(self.private / "salt"),
                "REDIS_ADDR": "127.0.0.1:16379",
                "ADMISSION_NAMESPACE": "inf060-probe",
                "ADMISSION_RUNNING": "16",
                "ADMISSION_WAITING": "4",
                "POD_UID": "inf060-probe",
                "OTEL_SDK_DISABLED": "true",
            },
        )
        self.launch_engine("control")
        self.ready("http://127.0.0.1:8080/readyz")
        row = self.requests["slots"][0]
        result, _ = request(
            row,
            load(self.private / "prompts.json")[0],
            credential,
            ssl.create_default_context(cafile=self.private / "tls.crt"),
            self.end,
        )
        save(
            self.output / "smoke.json",
            {
                "complete": result["outcome"] == "complete",
                "tls": "status" in result,
                "http_status": result.get("status"),
                "failure": result.get("failure"),
                "usage_completion_tokens": result.get("completion_tokens"),
            },
        )
        check(result["outcome"] == "complete", "tls_and_runtime_usage_smoke")

    def launch_engine(self, arm):
        spec = self.engine[arm]
        if self.cpu:
            self.force_mock_failure("launch_engine")
            name = "mock-" + arm
            self.timed(
                arm + "-engine-launch",
                self.start,
                name,
                [sys.executable, self.repo / "scripts/inf060_probe_engine.py", name],
            )
            engine_identity = hashlib.sha256(
                (self.private / (name + ".process.json")).read_bytes()
            ).hexdigest()
        else:
            self.check_image(spec["image"])
            name = self.timed(
                arm + "-engine-launch",
                self.docker,
                "engine",
                spec["image"],
                spec["argv"],
                variables=spec["env"],
                gpu=True,
                mounts=(
                    (self.repo, "/packet", "ro"),
                    (self.private / "model", "/model", "ro"),
                ),
            )
            row = json.loads(self.call(["docker", "inspect", name]))[0]
            cfg = row["Config"]
            loaded_env = dict(x.split("=", 1) for x in cfg["Env"])
            check(
                cfg["Image"] == spec["image"]
                and cfg["Entrypoint"] + cfg["Cmd"] == spec["argv"]
                and all(loaded_env.get(k) == v for k, v in spec["env"].items()),
                "engine_argv_env_readback",
            )
            process_env = dict(
                row.split(b"=", 1)
                for row in self.call(
                    ["docker", "exec", name, "cat", "/proc/1/environ"]
                ).split(b"\0")
                if b"=" in row
            )
            check(
                all(
                    process_env.get(k.encode()) == v.encode()
                    for k, v in spec["env"].items()
                ),
                "running_engine_env",
            )
            check(
                self.call(
                    ["docker", "exec", name, "sha256sum", "/packet/" + LOG_CONFIG]
                )
                .decode()
                .split()[0]
                == LOG_CONFIG_SHA,
                "mounted_logging_hash",
            )
            engine_identity = hashlib.sha256(row["Id"].encode()).hexdigest()
        self.timed(arm + "-engine-health", self.ready, "http://127.0.0.1:8000/health")
        logs, seen = suppress(
            self.timed(arm + "-startup-log", self.raw, arm),
            [row["canary"] for row in self.requests["slots"]],
        )
        save(self.output / (arm + "-startup-suppression.json"), seen)
        check(logs is not None, "startup_suppression")
        first = next((FORMAT.match(row) for row in logs if " INFO [" in row), None)
        check(first is not None, "epoch_logging_readback")
        save(
            self.output / (arm + "-engine.json"),
            {
                "identity_sha256": engine_identity,
                "configured_logging_sha256": LOG_CONFIG_SHA,
                "timestamp_resolution_ns": 1000,
                "startup_scan": seen,
                "mode": "cpu_mock" if self.cpu else "stock_vllm",
            },
        )

    def raw(self, arm):
        if self.cpu:
            return (self.private / ("mock-" + arm + ".log")).read_bytes()
        result = subprocess.run(
            ["docker", "logs", self.name("engine")],
            cwd=self.repo,
            env=env(self.root, self.repo),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=min(15, self.end - time.time()),
            check=False,
        )
        check(result.returncode == 0, "engine_log_retrieval")
        return result.stdout

    def engine_cpu_usec(self, arm):
        if self.cpu:
            state = load(self.private / ("mock-" + arm + ".process.json"))
            check(pid_start(state["pid"]) == state["start"], "mock_generation")
            fields = (
                Path(f"/proc/{state['pid']}/stat").read_text().rsplit(")", 1)[1].split()
            )
            return (
                (int(fields[11]) + int(fields[12]))
                * 1_000_000
                // os.sysconf("SC_CLK_TCK")
            )
        pid = int(
            self.call(
                ["docker", "inspect", "--format", "{{.State.Pid}}", self.name("engine")]
            )
        )
        path = next(
            line.removeprefix("0::")
            for line in Path(f"/proc/{pid}/cgroup").read_text().splitlines()
            if line.startswith("0::")
        )
        root = Path("/sys/fs/cgroup")
        cpu = (root / path.lstrip("/") / "cpu.stat").resolve()
        check(cpu.is_relative_to(root), "engine_cgroup")
        return int(
            next(
                line.split()[1]
                for line in cpu.read_text().splitlines()
                if line.startswith("usage_usec ")
            )
        )

    def clock(self):
        argv = [
            sys.executable,
            "-I",
            str(self.repo / "scripts/inf060_probe_engine.py"),
            "clock-server",
        ]
        if not self.cpu:
            argv = [
                "docker",
                "exec",
                "-i",
                self.name("engine"),
                IMAGE_PYTHON,
                "-I",
                "/packet/scripts/inf060_probe_engine.py",
                "clock-server",
            ]
        return clock_exchange(argv, self.end, env=env(self.root, self.repo))

    def arm(self, arm):
        before = self.clock()
        engine_cpu_before = self.engine_cpu_usec(arm)
        events, samples, client_cpu = run_arm(
            self.requests,
            load(self.private / "prompts.json"),
            (self.private / "credential").read_text(),
            self.private / "tls.crt",
            self.end,
        )
        after = self.clock()
        engine_cpu = self.engine_cpu_usec(arm) - engine_cpu_before
        check(engine_cpu >= 0, "engine_cpu_accounting")
        clock = bracket(before, after, samples)
        canaries = [row["canary"] for row in self.requests["slots"]]
        logs, receipt = suppress(self.raw(arm), canaries)
        save(self.output / (arm + "-suppression.json"), receipt)
        check(logs is not None, "suppression_refused")
        result = join(0 if arm == "control" else 1, events, logs, clock)
        if arm == "control":
            check(result["frontend_abort_lines"] == 0, "unlogged_frontend_abort")
        if self.cpu and arm == "logged":
            check(
                result["identity_joins"] > 0
                and result["orphan_abort_count"] > 0
                and receipt["stock_timestamp_lines"] == 1
                and result["stock_abort_matches"] == 0,
                "rehearsal_join_coverage",
            )
            rows, negative = suppress((canaries[0] + "\n").encode(), canaries)
            check(rows is None and negative["status"] == "REFUSED", "canary_negative")
            save(self.output / "canary-negative.json", negative)
        measured = [
            events[row["alias"]][0]
            for row in self.requests["slots"]
            if row["cohort"] == "measured"
        ]
        save(
            self.output / (arm + ".json"),
            {
                "scheduled": 120,
                "assigned_cancels": 24,
                "outcomes": dict(Counter(row["outcome"] for row in measured)),
                "observations": measured,
                "latency": latency_summary(measured),
                "clock": clock,
                "coarse_gauges": samples,
                "client_cpu_ns": client_cpu,
                "engine_cpu_usec": engine_cpu,
                "abort_join": result,
            },
        )

    def restart(self):
        if self.cpu:
            self.stop_process("mock-control")
        else:
            self.remove("engine")
        self.launch_engine("logged")
        check(
            load(self.output / "control-engine.json")["identity_sha256"]
            != load(self.output / "logged-engine.json")["identity_sha256"],
            "generation_changed",
        )

    def freeze(self):
        for role in ("engine", "stage", "tls", "redis"):
            self.remove(role)
        for name in ("mock-control", "mock-logged", "gateway"):
            self.stop_process(name)
        rows = {
            p.name: facts(p)
            for p in self.output.iterdir()
            if p.is_file() and p.name != "inventory.json"
        }
        check(
            sum(row["bytes"] for row in rows.values()) <= EXPORT_BYTES, "export_bytes"
        )
        save(self.output / "inventory.json", rows)


def capture_failure_logs(root, deadline):
    private, output = root / "private", root / "results"
    for name in ("gateway", "mock-control", "mock-logged"):
        path = private / (name + ".log")
        if path.is_file():
            diagnostics.write(
                output / ("failure-" + name + ".json"), diagnostics.file_tail(path)
            )
    owner = hashlib.sha256(str(root).encode()).hexdigest()[:16]
    for role in ("stage", "engine"):
        remaining = min(3, deadline - time.time())
        if remaining <= 0:
            break
        with tempfile.TemporaryFile(dir=root) as stream:
            try:
                subprocess.run(
                    [
                        "docker",
                        "logs",
                        "--tail",
                        str(diagnostics.TAIL_LINES),
                        f"inf060-{owner}-{role}",
                    ],
                    stdout=stream,
                    stderr=subprocess.STDOUT,
                    timeout=remaining,
                    check=True,
                    env=env(root, root / "repo"),
                )
            except (OSError, subprocess.SubprocessError):
                continue
            size = stream.seek(0, 2)
            stream.seek(max(0, size - diagnostics.TAIL_BYTES))
            diagnostics.write(
                output / ("failure-" + role + ".json"),
                diagnostics.tail(
                    stream.read(diagnostics.TAIL_BYTES), original_bytes=size
                ),
            )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=("launch", *PHASES))
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--origin", type=float, required=True)
    parser.add_argument("--end", type=float, required=True)
    parser.add_argument("--cpu-rehearsal", action="store_true")
    parser.add_argument("--mock-failure", choices=diagnostics.FAILURES)
    args = parser.parse_args()
    failure = diagnostics.injected_failure(args.cpu_rehearsal, args.mock_failure)
    check(args.end - time.time() > 0, "phase_deadline")
    if args.phase == "launch":
        cutoffs = [
            READY_S,
            READY_S + ARM_S,
            READY_S + ARM_S + RESTART_S,
            READY_S + 2 * ARM_S + RESTART_S,
            READY_S + 2 * ARM_S + RESTART_S + VERIFY_S,
        ]
        for name, cutoff in zip(PHASES, cutoffs, strict=True):
            end = min(args.origin + cutoff, args.end)
            argv = [
                "/usr/bin/env",
                "-i",
                *(f"{k}={v}" for k, v in env(args.root, args.root / "repo").items()),
                sys.executable,
                str(Path(__file__).resolve()),
                name,
                "--root",
                str(args.root),
                "--origin",
                str(args.origin),
                "--end",
                str(end),
            ]
            if args.cpu_rehearsal:
                argv.append("--cpu-rehearsal")
            if failure:
                argv.extend(["--mock-failure", failure])
            start, mono = time.time(), time.monotonic()
            code = None
            try:
                result = subprocess.run(argv, timeout=end - time.time(), check=False)
                code = result.returncode
            except subprocess.TimeoutExpired:
                diagnostics.write(
                    args.root / "results" / ("error-" + name + ".json"),
                    diagnostics.exception_record(TimeoutError("inf060:phase_deadline")),
                )
                raise
            finally:
                save(
                    args.root / "results" / ("phase-" + name + ".json"),
                    {
                        "phase": name,
                        "start_epoch": start,
                        "end_epoch": time.time(),
                        "deadline_epoch": end,
                        "exit_code": code,
                        "elapsed_s": time.monotonic() - mono,
                        "env_i": True,
                    },
                )
                if code != 0:
                    capture_failure_logs(args.root, args.end)
            check(result.returncode == 0, "phase:" + name)
        return
    try:
        phase = Phase(args.root, args.origin, args.end, args.cpu_rehearsal, failure)
        if args.phase in ("control", "logged"):
            phase.arm(args.phase)
        else:
            getattr(phase, args.phase)()
    except Exception as error:
        diagnostics.write(
            args.root / "results" / ("error-" + args.phase + ".json"),
            diagnostics.exception_record(error),
        )
        raise


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        # Exit classification only. Raw engine or transport details stay private.
        error = diagnostics.exception_record(exc)
        print(
            error["message"] if error["message"] != "[redacted]" else error["type"],
            file=sys.stderr,
        )
        raise SystemExit(1) from None
