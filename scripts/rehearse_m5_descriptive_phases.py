"""DEC-099: literal EKS phase shells on sparse-staged source, with kind Ports only.

Mount namespaces isolate /opt/dec077 from the routine runner. No EKS, reservation
or product Apply is available here. The isolated venv's sitecustomize substitutes
only the remote Ports class at main() entry; the shell and main remain unchanged.
"""

import argparse
import ast
import hashlib
import json
import inspect
import shlex
import shutil
import subprocess
import tarfile
import threading
import time
from pathlib import Path
from urllib.request import Request, urlopen

from inference_platform.command_diagnostics import stderr_tail
from inference_platform.m5_descriptive_operator import (
    file_digest,
    session_timing,
)
from inference_platform.package_a_operator import Ports
from m5_descriptive_eks import EKSports
from m5_descriptive_remote import EKSClusterPorts
from package_a_host import Host, host_environment, server
from rehearse_m5_descriptive import KindPorts

ROOT = Path(__file__).resolve().parents[1]
PHASES = (
    "provision",
    "smoke",
    "load",
    "gateway_rollout",
    "replica_rollout",
    "export",
    "retrieve",
)
SITE = r"""
import sys

def substitute_ports(frame, event, argument):
    if (event == 'call' and frame.f_code.co_name == 'main'
            and frame.f_code.co_filename == '/opt/dec077/repo/scripts/m5_descriptive_remote.py'):
        sys.setprofile(None)
        import json, time
        from pathlib import Path
        binding = json.loads(Path('/opt/dec077/runtime.json').read_bytes())['descriptive']
        if sys.argv[1] == 'smoke' and 'rehearsal_smoke_epoch' in binding:
            real_time = time.time
            offset = binding['rehearsal_smoke_epoch'] - real_time()
            time.time = lambda: real_time() + offset
        from rehearse_m5_descriptive_phases import PhaseKindPorts
        frame.f_globals['EKSClusterPorts'] = PhaseKindPorts
sys.setprofile(substitute_ports)
"""


PROVIDER_OVERRIDES = {
    "provision": "kind, local registry and short fake-backend deployment instead of EKS/ECR/model/GPU provisioning",
    "render_manifest": "CPU fake backend and local pinned images instead of vLLM/GPU and provider images",
    "teardown": "delete owned kind/registry instead of AWS resources",
    "inventory": "query owned kind/registry rather than AWS service inventories",
    "stop_backstop": "stop the rehearsal systemd timer instead of the independently deployed AWS backstop",
}


class PhaseKindPorts(EKSClusterPorts):
    """Real construction/save/load; only provider-calling operations substituted."""

    substitutions = [
        *[x for x in KindPorts.substitutions if x != "short load and rollout windows"],
        "smoke wall-clock offset to consume +2647s; monotonic clock continues normally",
    ]
    render_manifest = KindPorts.render_manifest
    teardown = KindPorts.teardown
    inventory = KindPorts.inventory
    stop_backstop = KindPorts.stop_backstop

    def provision(self):
        # Provider-only ownership fields are persisted by the real save/load.
        self.owned = self.registry_owned = self.backstop_armed = False
        self.context = self.binding["kubernetes_context"]
        # This provider setup also makes the historical-init control reach smoke:
        # ff74dc1 provision initialized its tools, but the next process did not.
        return KindPorts.provision(self)


def namespace_command(root, shell, *, share_tools=True):
    # The ordinary phase/ECR probes may reuse verified parent tools. A real
    # bootstrap must install into its own tree: overwriting a running tool fails
    # ETXTBSY and could corrupt the routine runner's dependencies.
    prefix = "set -eu; "
    if share_tools:
        prefix += (
            "mount --bind /opt/dec077/tools " + shlex.quote(str(root / "tools")) + "; "
        )
    return [
        "unshare",
        "--mount",
        "--propagation",
        "private",
        "/bin/sh",
        "-c",
        prefix
        + "mount --rbind "
        + shlex.quote(str(root))
        + " /opt/dec077; exec env -i /bin/sh -c "
        + shlex.quote(shell),
    ]


class LocalSSM(Ports):
    """Transport boundary only: literal SSM shells and real Host HTTP retrieval."""

    def __init__(self, root, runtime, manifest):
        self.root, self.runtime = root, runtime
        self.token, self.host = "phase-rehearsal-token", "local-kind-host"
        self.deadline, self.status_answered = manifest["deadline_epoch"], True
        self.child = None
        encoded = json.dumps(manifest).encode()
        self.agent = Host(
            root, self.token, hashlib.sha256(encoded).hexdigest(), self.deadline
        )
        self.agent.dispatch("/manifest", encoded, {})
        self.http = server(self.agent, port=0)
        self.thread = threading.Thread(target=self.http.serve_forever, daemon=True)
        self.thread.start()
        self.calls = []

    def ssm(self, host, commands, *, timeout_s=180, step=None):
        shell = commands[0]
        argv = namespace_command(self.root, shell, share_tools=False)
        started = time.monotonic()
        result = subprocess.run(argv, capture_output=True, timeout=timeout_s)
        self.calls.append(
            {
                "step": step,
                "shell": shell,
                "argv": argv,
                "exit_code": result.returncode,
                "elapsed_s": time.monotonic() - started,
                "environment": "env -i before literal phase shell",
            }
        )
        if result.returncode:
            raise RuntimeError(
                "local_ssm:" + stderr_tail(result.stderr, secrets=(self.token,))
            )
        return {
            "StandardOutputContent": result.stdout.decode(),
            "StandardErrorContent": result.stderr.decode(),
        }

    def request(self, path, data=b"", headers=None, *, end=None):
        request = Request(
            f"http://127.0.0.1:{self.http.server_port}" + path,
            data=data,
            headers={"Authorization": "Bearer " + self.token, **(headers or {})},
            method="POST",
        )
        with urlopen(
            request, timeout=max(1, min(30, (end or self.deadline) - time.time()))
        ) as response:
            return response.read(), dict(response.headers)

    def close(self):
        self.http.shutdown()
        self.http.server_close()
        self.thread.join(timeout=5)


def prepare(root, transfer, *, consume_epoch=None):
    root.mkdir()
    (root / "tools").mkdir()
    bundle = Path("/opt/dec100-payload/source.bundle")
    if file_digest(bundle) != transfer["payload_sha256"]:
        raise ValueError("phase_rehearsal:payload_hash")
    shutil.copyfile(bundle, root / "source.bundle")
    # Real operator runtime producer, with routine-host source/tool inputs and
    # declared provider substitutions only. One epoch is used for both cutoffs.
    routine = json.loads(Path("/opt/dec077/runtime.json").read_bytes())
    consume = time.time() if consume_epoch is None else consume_epoch
    timing = session_timing(640, 140)
    operator = EKSports.__new__(EKSports)
    operator.end = consume + 18000
    operator.manifest = {
        "host_manifest": {
            "role": "descriptive_operator",
            "workload": "m5-descriptive",
            "source_payload": transfer["binding"],
            "source_commit": transfer["binding"]["source_commit"],
            "python_sha256": routine["python_sha256"],
            "pins": routine["pins"],
            "python_executable": "/opt/dec077/repo/python/.venv/bin/python",
            "bundle_sha256": transfer["payload_sha256"],
            "bundle_bytes": bundle.stat().st_size,
        },
        "timing": timing,
        "descriptive": {
            "session": "m5-dec100",
            "source_commit": transfer["binding"]["source_commit"],
            "kubernetes_context": "kind-m5-dec100",
            "model": "test-model",
            "tenant_id": "tenant-local",
            "warmup_seconds": 120,
            "load_seconds": 600,
            "startup_seconds": 640,
            "timing": timing,
        },
    }
    manifest = operator.host_runtime(
        {"repository_url": {"value": "localhost:5001/descriptive"}}
    )
    if root.name in {"healthy", "4d15c18-init", "580168e-finish-task"}:
        manifest["descriptive"]["rehearsal_smoke_epoch"] = consume + 2647
    # This file is the operator's input, not runtime.json. Only Host /start may
    # produce the runtime used by the phase processes below.
    (root / "host-manifest.json").write_text(json.dumps(manifest))
    (root / "bootstrap-deadline.json").write_text(
        json.dumps(
            {"deadline_epoch": operator.host_work_deadline(), "consume_epoch": consume}
        )
    )
    # Exercise the real stage endpoint before bootstrap creates ignored venv
    # and build files. Its stage.json is the prerequisite consumed by /start.
    encoded = (root / "host-manifest.json").read_bytes()
    host = Host(
        root,
        "phase-rehearsal-token",
        hashlib.sha256(encoded).hexdigest(),
        operator.host_work_deadline(),
    )
    host.dispatch("/manifest", encoded, {})
    host.dispatch("/stage", b"", {})
    tools = root / "repo/.tools"
    tools.mkdir(exist_ok=True)
    for name in ("kind", "kubectl"):
        shutil.copyfile(Path("/opt/dec077/tools") / name, tools / name)
        (tools / name).chmod(0o755)
    subprocess.run(
        [
            "/opt/dec077/tools/uv-x86_64-unknown-linux-gnu/uv",
            "sync",
            "--project",
            str(root / "repo/python"),
            "--locked",
            "--python",
            "/opt/dec077/tools/python/bin/python3.12",
        ],
        check=True,
    )
    site = root / "repo/python/.venv/lib/python3.12/site-packages/sitecustomize.py"
    site.write_text(SITE)
    probe = subprocess.run(
        namespace_command(
            root,
            "test -x /opt/dec077/tools/go/bin/go && "
            "test -x /opt/dec077/repo/python/.venv/bin/python && "
            "/opt/dec077/repo/python/.venv/bin/python -B --version",
        ),
        capture_output=True,
        timeout=30,
    )
    if probe.returncode:
        raise RuntimeError(
            "phase_rehearsal:namespace_interpreter_unavailable:"
            + stderr_tail(probe.stderr)
        )
    (root / "namespace-readiness.json").write_text(
        json.dumps(
            {"tools_and_venv_visible": True, "python": probe.stdout.decode().strip()}
        )
    )
    return manifest


def start_host():
    root = Path("/opt/dec077")
    encoded = (root / "host-manifest.json").read_bytes()
    binding = json.loads((root / "bootstrap-deadline.json").read_bytes())
    host = Host(
        root,
        "phase-rehearsal-token",
        hashlib.sha256(encoded).hexdigest(),
        binding["deadline_epoch"],
    )
    host.dispatch("/manifest", encoded, {})
    host.dispatch("/start", b"", {})
    try:
        code = host.child.wait(timeout=1100)
        if code:
            raise RuntimeError("phase_rehearsal:real_bootstrap_failed:" + str(code))
        runtime = json.loads((root / "runtime.json").read_bytes())
        if runtime["deadline_epoch"] != binding["deadline_epoch"]:
            raise ValueError("phase_rehearsal:agent_deadline")
        (root / "runtime-producer.json").write_text(
            json.dumps(
                {
                    "producer": "EKSports.host_runtime -> Host /manifest /stage /start",
                    "real_bootstrap_exit": code,
                    "consume_epoch": binding["consume_epoch"],
                    "original_deadline_epoch": runtime["descriptive"][
                        "original_deadline_epoch"
                    ],
                    "agent_deadline_epoch": runtime["deadline_epoch"],
                    "runtime_sha256": file_digest(root / "runtime.json"),
                    "timing": runtime["descriptive"]["timing"],
                }
            )
        )
    finally:
        if host.child.poll() is None:
            host.cancel()
        if host.log:
            host.log.close()


def produce_runtime(root):
    program = (
        "import sys,json,hashlib; from pathlib import Path; "
        "sys.path.insert(0,'/opt/dec077/repo/scripts'); from package_a_host import Host; "
        "file_digest=lambda p: hashlib.sha256(p.read_bytes()).hexdigest()\n"
        + inspect.getsource(start_host)
        + "\nstart_host()"
    )
    shell = (
        "export "
        + " ".join(k + "=" + shlex.quote(v) for k, v in host_environment().items())
        + "; cd /opt/dec077/repo; /usr/bin/python3 -B -c "
        + shlex.quote(program)
    )
    result = subprocess.run(
        namespace_command(root, shell, share_tools=False),
        capture_output=True,
        timeout=1200,
    )
    (root / "runtime-producer.stdout").write_bytes(result.stdout)
    (root / "runtime-producer.stderr").write_text(stderr_tail(result.stderr))
    if result.returncode:
        raise RuntimeError(
            "phase_rehearsal:runtime_producer:" + stderr_tail(result.stderr)
        )
    (root / "results/runner/descriptive").mkdir(parents=True, exist_ok=True)
    return json.loads((root / "runtime.json").read_bytes())


def old_command(phase):
    return (
        "cd /opt/dec077/repo; export PATH=/opt/dec077/tools/go/bin:/opt/dec077/tools/uv-x86_64-unknown-linux-gnu:/opt/dec077/tools/docker:/usr/local/bin:/usr/bin:/bin; "
        "export PYTHONPATH=/opt/dec077/repo/python/src; "
        "/opt/dec077/repo/python/.venv/bin/python -B /opt/dec077/repo/scripts/m5_descriptive_remote.py "
        + phase
    )


def expected_refusal(name, message):
    # Observed on pinned Go 1.26.6 in the second AWS rehearsal: the module-cache
    # check precedes the build-cache check. Require the actual Go command and
    # cause, never an arbitrary failure.
    expected = (
        "go: module cache not found: neither GOMODCACHE nor GOPATH is set"
        if name == "old-shell"
        else "r538_forced_build_missing_symbol"
    )
    if "command_failed:go:exit=1;" not in message or expected not in message:
        raise ValueError("phase_rehearsal:wrong_negative_failure:" + message)
    return expected


def cleanup(host):
    program = (
        "import json,sys; from pathlib import Path; sys.path.insert(0,'/opt/dec077/repo/scripts'); "
        "from rehearse_m5_descriptive_phases import PhaseKindPorts; "
        "p=PhaseKindPorts(Path('/opt/dec077/descriptive-private'),json.loads(Path('/opt/dec077/runtime.json').read_bytes())); "
        "print(json.dumps({'teardown':p.teardown(),'inventory':p.inventory()}))"
    )
    shell = (
        "export "
        + " ".join(k + "=" + shlex.quote(v) for k, v in host_environment().items())
        + "; cd /opt/dec077/repo; /opt/dec077/repo/python/.venv/bin/python -c "
        + shlex.quote(program)
    )
    response = host.ssm(
        host.host, [shell], timeout_s=300, step="kind.teardown_inventory"
    )
    result = json.loads(response["StandardOutputContent"].splitlines()[-1])
    if not result["teardown"]["complete"] or not result["inventory"]["complete"]:
        raise ValueError("phase_rehearsal:cleanup_unverified")
    return result


def run_scenario(output, inputs, name, transfer, *, consume_epoch):
    directory = output / name
    directory.mkdir()
    root = inputs / name
    prepare(root, transfer, consume_epoch=consume_epoch)
    try:
        manifest = produce_runtime(root)
    except Exception:
        for filename in (
            "bootstrap.log",
            "runtime-producer.stdout",
            "runtime-producer.stderr",
            "runtime.json",
            "host-manifest.json",
            "bootstrap-deadline.json",
        ):
            if (root / filename).exists():
                shutil.copyfile(root / filename, directory / filename)
        raise
    # Simulate the observed smoke start without a 2,647-second sleep. The real
    # phase process uses a constant wall-clock offset; monotonic time advances.
    # Set this in the *input* before /start, never rewrite produced runtime.
    mutation = None
    original_constructor_source = None
    if name == "forced-go-failure":
        source = root / "repo/cmd/gateway/main.go"
        source.write_bytes(
            source.read_bytes()
            + b"\nfunc r538ForcedFailure(){r538_forced_build_missing_symbol()}\n"
        )
        mutation = {"path": "cmd/gateway/main.go", "sha256": file_digest(source)}
    if name == "forced-export-failure":
        source = root / "repo/python/src/inference_platform/m5_descriptive_cluster.py"
        old = source.read_text()
        needle = "    def export(self):\n"
        if old.count(needle) != 1:
            raise ValueError("phase_rehearsal:mutation_target")
        source.write_text(
            old.replace(
                needle,
                needle + "        raise RuntimeError('r538_forced_remote_export')\n",
            )
        )
        mutation = {
            "path": "python/src/inference_platform/m5_descriptive_cluster.py",
            "sha256": file_digest(source),
        }
    if name in {"ff74dc1-init", "4d15c18-init"}:
        source = root / "repo/scripts/m5_descriptive_remote.py"
        text = source.read_text()
        original_constructor_source = text
        cls = next(
            n
            for n in ast.parse(text).body
            if isinstance(n, ast.ClassDef) and n.name == "EKSClusterPorts"
        )
        node = next(
            n
            for n in cls.body
            if isinstance(n, ast.FunctionDef) and n.name == "__init__"
        )
        lines = text.splitlines(keepends=True)
        historical = (
            ROOT
            / (
                "scripts/fixtures/m5_descriptive_"
                + name.removesuffix("-init")
                + "_init.txt"
            )
        ).read_text()
        source.write_text(
            "".join(lines[: node.lineno - 1])
            + historical
            + "\n"
            + "".join(lines[node.end_lineno :])
        )
        mutation = {
            "path": "scripts/m5_descriptive_remote.py",
            "constructor_source": name.removesuffix("-init"),
            "sha256": file_digest(source),
        }
    if name == "580168e-finish-task":
        source = root / "repo/python/src/inference_platform/m5_descriptive_cluster.py"
        text = source.read_text()
        cls = next(
            node
            for node in ast.parse(text).body
            if isinstance(node, ast.ClassDef) and node.name == "ClusterPorts"
        )
        method = next(
            node
            for node in cls.body
            if isinstance(node, ast.FunctionDef) and node.name == "finish_task"
        )
        body = (
            ROOT / "scripts/fixtures/m5_descriptive_580168e_finish_task.txt"
        ).read_text()
        historical = body.replace("def finish_task(", "def _finish_task_580168e(", 1)
        recorder = """
    def finish_task(self, label):
        started = time.monotonic()
        receipt = self.results["task_polls"][label]
        receipt["historical_poll_budget_s"] = self.startup_seconds + self.rollout_duration + 180
        try:
            value = self._finish_task_580168e(label)
        except Exception:
            receipt["status"] = "FAILED"
            raise
        else:
            receipt["status"] = "PASS"
            return value
        finally:
            receipt["poll_elapsed_s"] = time.monotonic() - started
            receipt["elapsed_s"] = time.monotonic() - receipt["started_monotonic"]
"""
        lines = text.splitlines(keepends=True)
        source.write_text(
            "".join(lines[: method.lineno - 1])
            + historical
            + recorder
            + "".join(lines[method.end_lineno :])
        )
        mutation = {
            "path": "python/src/inference_platform/m5_descriptive_cluster.py",
            "body_source": "580168e",
            "body_sha256": hashlib.sha256(body.encode()).hexdigest(),
            "sha256": file_digest(source),
            "instrumentation": "Measure the historical call without modifying its poll arguments or behavior",
        }
    host = LocalSSM(root, directory, manifest)
    operator = EKSports.__new__(EKSports)
    operator.host, operator.directory = host, directory
    operator.end, operator.manifest = (
        manifest["descriptive"]["original_deadline_epoch"],
        {"timing": manifest["descriptive"]["timing"]},
    )
    operator.bootstrap_complete = True
    record = {
        "name": name,
        "runtime_producer": json.loads((root / "runtime-producer.json").read_bytes()),
        "smoke_clock": "fresh-process wall offset to consume +2647s; monotonic advances"
        if name in {"healthy", "4d15c18-init", "580168e-finish-task"}
        else "real wall clock",
        "staged_binding": transfer["binding"],
        "payload_sha256": transfer["payload_sha256"],
        "mutation_in_scratch_only": mutation,
        "phases": [],
        "only_remote_class_substitution": "EKSClusterPorts -> PhaseKindPorts",
        "provider_overrides": PROVIDER_OVERRIDES,
        "construction_save_state_loading": "inherited unchanged from EKSClusterPorts",
        "windows": {
            "warmup_s": manifest["descriptive"]["warmup_seconds"],
            "load_per_level_s": manifest["descriptive"]["load_seconds"],
            "gateway_rollout_s": manifest["descriptive"]["timing"][
                "gateway_rollout_seconds"
            ],
            "vllm_rollout_s": manifest["descriptive"]["timing"]["vllm_rollout_seconds"],
        },
    }
    try:
        if name == "forced-export-failure":
            frozen = operator.export()
            retrieved = operator.retrieve()
            diagnostic = json.loads(
                (directory / "prebootstrap-diagnostics.json").read_bytes()
            )
            if (
                frozen != retrieved
                or frozen.get("kind") != "repo-free-diagnostics"
                or not diagnostic["complete"]
            ):
                raise ValueError("phase_rehearsal:fallback_not_retrieved")
            if (
                "r538_forced_remote_export"
                not in (directory / "remote-export-failure.json").read_text()
            ):
                raise ValueError("phase_rehearsal:export_failure_not_recorded")
            record.update(
                complete=True,
                remote_export_refused=True,
                repo_free_retrieved=True,
                retrieval=frozen,
                diagnostic_complete=diagnostic["complete"],
            )
        else:
            forced = name != "healthy"
            phases = (
                ("provision", "smoke", "load")
                if name == "580168e-finish-task"
                else (
                    ("provision", "smoke")
                    if name in {"ff74dc1-init", "4d15c18-init"}
                    else (("provision",) if forced else PHASES)
                )
            )
            for phase in phases:
                started = time.monotonic()
                try:
                    if name == "old-shell":
                        host.ssm(
                            host.host,
                            [old_command(phase)],
                            timeout_s=1200,
                            step="descriptive." + phase,
                        )
                        raise ValueError("phase_rehearsal:old_shell_survived")
                    if phase == "export":
                        result = operator.export()
                        if result.get("kind") == "repo-free-diagnostics":
                            raise ValueError(
                                "phase_rehearsal:healthy_export_used_fallback"
                            )
                    elif phase == "retrieve":
                        result = operator.retrieve()
                    else:
                        result = operator.remote(phase)
                    record["phases"].append(
                        {
                            "name": phase,
                            "status": "PASS",
                            "elapsed_s": time.monotonic() - started,
                        }
                    )
                except Exception as error:
                    if not forced:
                        raise
                    message = str(error)
                    if name == "580168e-finish-task":
                        if (
                            phase != "load"
                            or "TimeoutError: descriptive:readiness_deadline"
                            not in message
                        ):
                            raise ValueError(
                                "phase_rehearsal:wrong_historical_poll_failure:"
                                + message
                            )
                    elif name == "4d15c18-init":
                        if (
                            phase != "smoke"
                            or "descriptive:remaining_workload_window" not in message
                        ):
                            raise ValueError(
                                "phase_rehearsal:wrong_deadline_failure:" + message
                            )
                    elif name == "ff74dc1-init":
                        if (
                            phase != "smoke"
                            or "AttributeError" not in message
                            or "kubectl" not in message
                        ):
                            raise ValueError(
                                "phase_rehearsal:wrong_historical_init_failure:"
                                + message
                            )
                    else:
                        expected_refusal(name, message)
                    record["phases"].append(
                        {
                            "name": phase,
                            "status": "EXPECTED_FAILURE",
                            "elapsed_s": time.monotonic() - started,
                            "error": stderr_tail(message),
                        }
                    )
            if name == "580168e-finish-task":
                state = json.loads(
                    (root / "descriptive-private/state.json").read_bytes()
                )
                task_polls = state["results"]["task_polls"]
                load = task_polls["load"]
                if (
                    record["phases"][-1]["status"] != "EXPECTED_FAILURE"
                    or load["historical_poll_budget_s"] != 1720
                    or load["max_work_s"] != 2160
                    or not 1719 <= load["poll_elapsed_s"] < 1740
                ):
                    raise ValueError("phase_rehearsal:historical_poll_not_exercised")
                record.update(complete=True, failed_at="load", task_polls=task_polls)
            elif name in {"ff74dc1-init", "4d15c18-init"}:
                if name == "4d15c18-init":
                    state = json.loads(
                        (root / "descriptive-private/state.json").read_bytes()
                    )
                    smoke = state["results"]["phase_processes"]["smoke"]
                    consume = record["runtime_producer"]["consume_epoch"]
                    if (
                        smoke["work_deadline_epoch"] != consume + 18000 - 2 * 6216
                        or abs(smoke["phase_start_epoch"] - consume - 2647) > 1
                    ):
                        raise ValueError("phase_rehearsal:historical_deadline_chain")
                    record["deadline_chain"] = smoke
                if record["phases"][-1]["status"] != "EXPECTED_FAILURE":
                    raise ValueError("phase_rehearsal:historical_init_survived")
                record.update(
                    complete=True,
                    failed_at="smoke",
                    reason=(
                        "descriptive:remaining_workload_window"
                        if name == "4d15c18-init"
                        else "AttributeError: Campaign.kubectl absent in fresh historical process"
                    ),
                )
            elif forced:
                frozen = operator.export()
                if frozen.get("kind") == "repo-free-diagnostics":
                    raise ValueError("phase_rehearsal:partial_export_fell_back")
                operator.retrieve()
                expected = expected_refusal(name, record["phases"][-1]["error"])
                with tarfile.open(directory / "receipts.tar.gz", "r:gz") as archive:
                    member = (
                        "results/runner/descriptive/retrieved/phase-logs/provision.log"
                    )
                    log = archive.extractfile(member).read().decode()
                    client = json.loads(
                        archive.extractfile(
                            "results/runner/descriptive/retrieved/client-records.json"
                        ).read()
                    )
                if expected not in log or client != {
                    "status": "absent",
                    "reason": "client_pod_not_created",
                    "inventory": None,
                }:
                    raise ValueError("phase_rehearsal:failure_evidence_missing")
                record.update(
                    complete=True,
                    compiler_message_in_halt_and_retrieved_log=True,
                    clients_absent=True,
                    archive={
                        "bytes": (directory / "receipts.tar.gz").stat().st_size,
                        "sha256": file_digest(directory / "receipts.tar.gz"),
                    },
                )
            else:
                state = json.loads(
                    (root / "descriptive-private/state.json").read_bytes()
                )
                processes = state["results"]["phase_processes"]
                if set(processes) != set(PHASES) or len(
                    {x["pid"] for x in processes.values()}
                ) != len(PHASES):
                    raise ValueError("phase_rehearsal:process_boundary")
                if any(
                    x["environment"] != host_environment() for x in processes.values()
                ):
                    raise ValueError("phase_rehearsal:environment")
                smoke = processes["smoke"]
                consume = record["runtime_producer"]["consume_epoch"]
                expected_work_end = consume + 18000 - 6216
                if (
                    smoke["work_deadline_epoch"] != expected_work_end
                    or smoke["host_work_deadline_epoch"] != expected_work_end
                    or abs(smoke["phase_start_epoch"] - consume - 2647) > 1
                ):
                    raise ValueError("phase_rehearsal:deadline_chain")
                task_polls = state["results"]["task_polls"]
                if set(task_polls) != {
                    "smoke",
                    "warmup",
                    "load",
                    "gateway_rollout",
                    "vllm_rollout",
                } or any(
                    row["status"] != "PASS"
                    or row["poll_budget_s"] < row["max_work_s"]
                    or not 0 < row["elapsed_s"] <= row["effective_budget_s"]
                    for row in task_polls.values()
                ):
                    raise ValueError("phase_rehearsal:task_polls")
                if task_polls["load"]["elapsed_s"] < 1800:
                    raise ValueError("phase_rehearsal:load_windows_shortened")
                record.update(
                    deadline_chain={
                        "consume_epoch": consume,
                        "work_deadline_epoch": smoke["work_deadline_epoch"],
                        "expected_work_deadline_epoch": expected_work_end,
                        "smoke_start_epoch": smoke["phase_start_epoch"],
                        "remaining_window_s": expected_work_end
                        - smoke["phase_start_epoch"],
                        "minimum_workload_seconds": manifest["descriptive"]["timing"][
                            "minimum_workload_seconds"
                        ],
                    },
                    complete=True,
                    phase_pids={phase: x["pid"] for phase, x in processes.items()},
                    phase_environment=host_environment(),
                    state_only="state.json",
                    task_polls=task_polls,
                    retrieved_archive={
                        "bytes": (directory / "receipts.tar.gz").stat().st_size,
                        "sha256": file_digest(directory / "receipts.tar.gz"),
                    },
                )
    finally:
        # Restore only this negative control's scratch source before verified
        # cleanup. Normal phase processes never get a runtime source patch.
        if original_constructor_source is not None:
            (root / "repo/scripts/m5_descriptive_remote.py").write_text(
                original_constructor_source
            )
            record["scratch_constructor_restored_for_cleanup"] = True
        try:
            record["cleanup"] = cleanup(host)
        finally:
            host.close()
            record["calls"] = host.calls
            receipts = root / "results/runner/descriptive"
            if receipts.exists():
                shutil.copytree(receipts, directory / "host-receipts")
            (directory / "result.json").write_text(
                json.dumps(record, indent=2, sort_keys=True) + "\n"
            )
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--payload-transfer-receipt", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    inputs = args.output / "inputs"
    inputs.mkdir()
    transfer = json.loads(args.payload_transfer_receipt.read_bytes())
    records = []
    consume_epoch = time.time()
    try:
        for name in (
            "old-shell",
            "forced-go-failure",
            "forced-export-failure",
            "ff74dc1-init",
            "4d15c18-init",
            "healthy",
            "580168e-finish-task",
        ):
            records.append(
                run_scenario(
                    args.output, inputs, name, transfer, consume_epoch=consume_epoch
                )
            )
        paired = {
            r["name"]: r["runtime_producer"]["runtime_sha256"]
            for r in records
            if r["name"] in {"healthy", "4d15c18-init", "580168e-finish-task"}
        }
        if len(set(paired.values())) != 1:
            raise ValueError("phase_rehearsal:counterfactual_runtime_mismatch")
        summary = {
            "identical_deadline_runtime_sha256": paired["healthy"],
            "complete": all(r["complete"] for r in records),
            "scenarios": records,
            "substitutions": [
                *PhaseKindPorts.substitutions,
                "Only remote Ports class replaced at real main entry via isolated venv sitecustomize",
                "SSM transport executed locally as env -i shell in a private mount namespace; real Host HTTP/archive retrieval",
                "Real Host /stage then /start on system Python; real bootstrap installs private tools, never overwrites the running routine daemon",
            ],
            "committed_source_modified": False,
            "state_between_phases": "state.json only",
        }
        (args.output / "result.json").write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n"
        )
        print(
            json.dumps(
                {
                    "complete": summary["complete"],
                    "scenarios": [r["name"] for r in records],
                }
            )
        )
    except Exception as error:
        (args.output / "result.json").write_text(
            json.dumps(
                {
                    "complete": False,
                    "scenarios": records,
                    "error": stderr_tail(type(error).__name__ + ":" + str(error)),
                },
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
        raise
    finally:
        # Never archive duplicate source, tool, venv, credential or build inputs.
        # Each scenario has already performed verified kind teardown in finally.
        if inputs.exists():
            shutil.rmtree(inputs)


if __name__ == "__main__":
    main()
