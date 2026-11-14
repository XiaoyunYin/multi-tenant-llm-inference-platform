"""Scripted, no-cluster execution of the Package A rehearsal, including failures.

Transport results model API objects and kind_fake logs. This establishes Python
control flow only; it supplies no Kubernetes controller or routing measurement.
"""

import ast
import argparse
import contextlib
import copy
import dis
import hashlib
import importlib.util
import io
import json
import subprocess
import sys
import threading
import tarfile
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def rehearsal(source_path=None):
    spec = importlib.util.spec_from_file_location(
        "kind_rehearsal", source_path or ROOT / "scripts/rehearse_eks_package_a.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def walk(output, *, mode="success", module=None):
    module = module or rehearsal()
    output = Path(output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    fixture = json.loads(
        (ROOT / "python/tests/fixtures/package_a_pods.json").read_bytes()
    )
    provenance = json.loads(
        (ROOT / "python/tests/fixtures/package_a_pods.provenance.json").read_bytes()
    )
    log_fixture = (
        (ROOT / "python/tests/fixtures/package_a_kind_fake.log")
        .read_text(encoding="utf-8")
        .splitlines()
    )
    log_provenance = json.loads(
        (
            ROOT / "python/tests/fixtures/package_a_kind_fake.provenance.json"
        ).read_bytes()
    )

    def label_scalar_fields(value, pointer=""):
        if isinstance(value, dict):
            return {
                key: labels
                for name, child in value.items()
                for key, labels in label_scalar_fields(
                    child, pointer + "/" + name.replace("~", "~0").replace("/", "~1")
                ).items()
            }
        if isinstance(value, list):
            return {
                key: labels
                for index, child in enumerate(value)
                for key, labels in label_scalar_fields(
                    child, pointer + "/" + str(index)
                ).items()
            }
        return {
            pointer or "/": {
                "classification": "synthetic_value",
                "reason": "controlled replacement derived from retrieved pod JSON shape; not observed output",
            }
        }

    provenance["synthetic_fields"] = label_scalar_fields(fixture)
    provenance["runtime_synthetic_fields"] = {
        "/items/*/spec/nodeName": "scripted node placement for the no-cluster walk",
        "/items/0/metadata/uid": "scripted generation UID used to test replacement",
        "/items/0/metadata/annotations": "scripted next-revision annotation used to test rollback",
        "/items/6/metadata/name": "synthetic overflow pod name",
        "/items/6/spec/nodeName": "synthetic unscheduled or incorrectly scheduled overflow result",
        "/items/6/status/phase": "synthetic overflow pod phase",
    }
    provenance["kind_fake_log_provenance"] = log_provenance
    cluster = "m5-package-a-scripted"
    nodes = [cluster + suffix for suffix in ("-control-plane", "-worker", "-worker2")]
    state = {
        "generation": 0,
        "overflow": False,
        "revision": False,
        "following": None,
        "capacity_n": 0,
        "capacity_polls": 0,
    }
    commands, executed, samples, ports = [], set(), [], []
    now = [0.0]
    archived = {
        tag: "sha256:" + str(i) * 64
        for i, tag in enumerate(module.KIND_LOCAL_IMAGE_TAGS.values(), 1)
    }
    local = {
        "mti-gateway:scripted": "sha256:" + "e" * 64,
        "mti-fake:stage1": "sha256:" + "f" * 64,
    }
    failure = None

    def pod_list():
        value = copy.deepcopy(fixture)
        for pod in value["items"]:
            name = pod["metadata"]["name"]
            pod["spec"]["nodeName"] = (
                nodes[1 if name.endswith("-0") or name == "observer-0" else 2]
                if name.startswith(("vllm", "observer"))
                else nodes[0]
            )
            if name == "vllm-0":
                pod["metadata"]["uid"] = (
                    f"scripted-vllm-0-generation-{state['generation']}"
                )
                pod["metadata"]["annotations"] = (
                    {"package-a-revision": "next"}
                    if state["revision"] and state["generation"] == 1
                    else {}
                )
        if state["overflow"]:
            value["items"].append(
                {
                    "metadata": {"name": "gpu-overflow"},
                    "spec": {"nodeName": "scripted-extra-node"}
                    if mode == "overflow-scheduled"
                    else {},
                    "status": {"phase": "Pending"},
                }
            )
        return value

    def fake_run(
        argv, *, timeout=180, check=True, return_status=False, return_details=False
    ):
        command = [str(v) for v in argv]
        commands.append({"argv": command, "timeout": timeout})
        now[0] += 0.001
        text = ""
        if "redis-cli" in command:
            if "HGET" in command:
                state["capacity_polls"] += 1
                if mode != "capacity-stuck" and state["capacity_polls"] >= 4:
                    state["capacity_n"] = 2
                return str(state["capacity_n"])
            return json.dumps({"n": state["capacity_n"]})
        if return_details:
            if "pods" in command and "get" in command:
                text = json.dumps(pod_list())
            return {"returncode": 0, "stdout": text, "stderr": ""}
        if return_status:
            ref = command[-1]
            first = ref.split("/", 1)[0]
            repo_tag = (
                "docker.io/library/" + ref
                if "/" not in ref
                else ref
                if "." in first or ":" in first
                else "docker.io/" + ref
            )
            return 0, json.dumps(
                {
                    "status": {
                        "id": archived.get(ref, local.get(ref)),
                        "repoTags": [repo_tag],
                    }
                }
            )
        if command[1:3] == ["create", "cluster"]:
            Path(command[command.index("--kubeconfig") + 1]).write_text("scripted\n")
            if mode == "no-work":
                now[0] = (
                    0.000001
                    + module.KIND_RUNNER_TIMEOUT_S
                    - module.KIND_CLEANUP_RESERVE_S
                )
        if command[1:3] == ["delete", "cluster"] and mode == "delete-error":
            raise RuntimeError("scripted_cluster_delete_failure")
        if command[:3] == ["docker", "ps", "-aq"] and mode == "remaining":
            return "owned-scripted-container"
        if command[:3] == ["docker", "image", "save"]:
            path = Path(command[command.index("--output") + 1])
            state.setdefault("archive_paths", []).append(str(path))
            config = json.dumps(
                {"os": "linux", "architecture": "amd64", "tag": command[-1]}
            ).encode()
            archived[command[-1]] = "sha256:" + hashlib.sha256(config).hexdigest()
            with tarfile.open(path, "w") as archive:
                for name, data in (
                    (
                        "manifest.json",
                        json.dumps(
                            [
                                {
                                    "Config": "config.json",
                                    "RepoTags": [command[-1]],
                                    "Layers": ["layer.tar"],
                                }
                            ]
                        ).encode(),
                    ),
                    ("config.json", config),
                    ("layer.tar", b"x" * (2 * 1024**2)),
                ):
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
        if command[:3] == ["docker", "image", "inspect"]:
            if "--format" in command and "post_archive_large_files" not in state:
                state["post_archive_large_files"] = [
                    path.relative_to(output).as_posix()
                    for path in output.rglob("*")
                    if path.is_file() and path.stat().st_size > 1024**2
                ]
            return local[command[-1]] if "--format" in command else "{}"
        if "command -v crictl" in command:
            return "/usr/bin/crictl"
        if "sha256sum" in command:
            return "a" * 64 + " /usr/bin/crictl"
        if "--context" in command:
            args = command[7:]
            if args[:2] == ["rollout", "status"] and args[2].startswith("statefulset/"):
                raise RuntimeError(
                    "rollout status is only available for RollingUpdate strategy type"
                )
            if args[:2] == ["get", "pods"]:
                value = pod_list()
                if "-l" in args:
                    value["items"] = [
                        p
                        for p in value["items"]
                        if p["metadata"]["name"].startswith("observer")
                    ]
                return json.dumps(value)
            if args[:2] == ["auth", "can-i"]:
                return "no\n" if mode == "auth-denied" else "yes\n"
            if args[0] == "apply":
                file = Path(args[-1]).name
                if file == "next-resources.json":
                    state["revision"] = True
                elif file == "mock-resources.json":
                    state["revision"] = False
                    if mode == "deadline" and state["generation"] == 0:
                        now[0] = 280.0
                elif file == "overflow.json":
                    state["overflow"] = True
            if args[:3] == ["delete", "pod", "gpu-overflow"]:
                state["overflow"] = False
            if args[:3] == ["delete", "pod", "vllm-0"]:
                state["generation"] += 1
                state["capacity_n"] = 0
                state["capacity_polls"] = 0
                if state["generation"] == 1:
                    first = json.loads(log_fixture[0])
                    final = json.loads(log_fixture[2])
                    if mode == "drain-incomplete":
                        final["msg"] = "unexpected drain result"
                    if mode == "drain-nonzero":
                        final["active"] = 1
                    state["following"].write(
                        (
                            json.dumps(first)
                            + "\n"
                            + log_fixture[1]
                            + "\n"
                            + json.dumps(final)
                            + "\n"
                        ).encode()
                    )
                    state["following"].flush()
            if (
                args[:2] == ["wait", "--for=jsonpath={.status.readyReplicas}=2"]
                and mode == "deadline"
            ):
                # A hung command consumes exactly the timeout it was given.
                now[0] += timeout
                if now[0] > 291:
                    raise AssertionError("uncapped_work_timeout")
                raise subprocess.TimeoutExpired(command, timeout)
        return text

    class Process:
        waits = 0

        def terminate(self):
            if mode == "process-error":
                raise RuntimeError("scripted_terminate_error")

        def wait(self, timeout=None):
            self.waits += 1
            if mode == "process-error":
                raise RuntimeError("scripted_wait_error")
            if self.waits == 1:
                raise subprocess.TimeoutExpired("scripted-log-follow", timeout)
            return 0

    def popen(argv, *, stdout, stderr):
        process = Process()
        if "port-forward" not in argv:
            state["following"] = stdout
        else:
            process.waits = 1
        return process

    class BadLog:
        def close(self):
            raise RuntimeError("scripted_log_close_error")

    def forward(
        _kubectl,
        _kubeconfig,
        _context,
        _namespace,
        _output,
        resource,
        remote,
        forwards,
        logs,
        wait,
    ):
        port = 32000 + len(ports)
        ports.append({"port": port, "resource": resource, "remote": remote})
        if mode == "wait-cap" and not state.get("wait_cap_invoked"):
            state["wait_cap_invoked"] = True
            now[0] = (
                0.000001 + module.KIND_RUNNER_TIMEOUT_S - module.KIND_CLEANUP_RESERVE_S
            )

            def ready():
                state["wait_predicate_called"] = True
                return True

            wait(ready, timeout=1)
            if state.get("wait_predicate_called"):
                raise AssertionError("wait_timeout_not_capped")
        if mode == "log-error" and len(ports) == 1:
            logs.append(BadLog())
        result = module.start_forward_original(
            _kubectl,
            _kubeconfig,
            _context,
            _namespace,
            _output,
            resource,
            remote,
            forwards,
            logs,
            wait,
        )
        return result

    def stream(port, **kwargs):
        if (
            mode == "stream-error"
            and threading.current_thread() is not threading.main_thread()
        ):
            raise RuntimeError("scripted_stream_error")
        return module.read_stream_original(port, **kwargs)

    class ObserverHTTP:
        def __init__(self, base, **_kwargs):
            port = int(base.rsplit(":", 1)[1])
            resource = next(row["resource"] for row in ports if row["port"] == port)
            self.node = nodes[1 if resource.endswith("-0") else 2]
            self.end_ns = None

        def get(self, path):
            if path == "/clock":
                data = {"boot_id": "fixture-node-boot", "mono_ns": int(now[0] * 1e9)}
            else:
                self.end_ns = int(now[0] * 1e9)
                data = {
                    "schema": "m5-node-cache-v1",
                    "node": self.node,
                    "complete": True,
                    "boot_id": "fixture-node-boot",
                    "end_ns": self.end_ns,
                    "image_cache_state": "cold",
                    "model_cache_state": "cold",
                }
            return json.dumps(data).encode(), {}

    class StreamConnection:
        def __init__(self, *_args, **_kwargs):
            self.chunks = iter(
                (
                    b'data: {"choices":[{"index":0,"delta":{"content":"fixture"},"finish_reason":null}]}\n\n',
                    b'data: {"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}\n\ndata: {"choices":[],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2,"count_source":"runtime_usage"}}\n\ndata: [DONE]\n\n',
                    b"",
                )
            )

        def request(self, _method, path, *_args):
            self.status = (
                (200 if state["capacity_n"] == 2 else 429)
                if path == "/v1/chat/completions"
                else 404
            )

        def read(self):
            return b'{"error":{"code":"system_capacity","retryable":true}}'

        def getresponse(self):
            return self

        status = 200

        def read1(self, _size):
            now[0] += 0.001
            return next(self.chunks)

        def close(self):
            pass

    def trace(frame, event, arg):
        if event == "line" and frame.f_code.co_filename == module.__file__:
            executed.add(frame.f_lineno)
        return trace

    def monotonic():
        observed = now[0]
        now[0] += 0.000001
        return observed

    fake_time = SimpleNamespace(
        monotonic=monotonic,
        monotonic_ns=lambda: int(now[0] * 1e9),
        sleep=lambda seconds: now.__setitem__(0, now[0] + seconds),
    )
    module.start_forward_original = module.start_forward
    module.read_stream_original = module.read_stream
    live_rows = module.LiveRows

    def rows(*args, **kwargs):
        sink = kwargs.get("sink")

        def retain(row):
            if row["source_kind"] == "kubernetes":
                samples.append(row)
            if sink:
                sink(row)

        kwargs["sink"] = retain
        return live_rows(*args, **kwargs, clock=lambda: int(now[0] * 1e9))

    stdout = io.StringIO()
    archive_temporary_directory = tempfile.TemporaryDirectory
    provenance["scratch_substitution"] = (
        "Image archive temp directories use the walk's writable output parent; source checkout may be read-only."
    )
    with (
        patch.object(
            module,
            "tempfile",
            SimpleNamespace(
                TemporaryDirectory=lambda **kw: archive_temporary_directory(
                    **{**kw, "dir": output.parent}
                )
            ),
        ),
        patch.object(module, "run", side_effect=fake_run),
        patch.object(module, "start_forward", side_effect=forward, create=True),
        patch.object(module, "read_stream", side_effect=stream, create=True),
        patch.object(
            module.socket,
            "create_connection",
            side_effect=lambda *_args, **_kwargs: contextlib.nullcontext(),
        ),
        patch.object(module, "LiveRows", side_effect=rows),
        patch.object(module, "HTTP", ObserverHTTP),
        patch.object(module, "free_port", side_effect=lambda: ports[-1]["port"]),
        patch.object(module.http.client, "HTTPConnection", StreamConnection),
        patch.object(module, "time", fake_time),
        patch.object(module.subprocess, "Popen", side_effect=popen),
        patch.object(module.ssl, "create_default_context", return_value=object()),
        patch.object(module.http.client, "HTTPSConnection") as https,
        patch.object(
            sys,
            "argv",
            [
                module.__file__,
                "--output",
                str(output),
                "--gateway-image",
                "mti-gateway:scripted",
                "--cluster",
                cluster,
            ],
        ),
        contextlib.redirect_stdout(stdout),
    ):
        https.return_value.getresponse.return_value.status = 404
        https.side_effect = StreamConnection
        previous_trace = sys.gettrace()
        previous_thread_trace = threading.gettrace()
        sys.settrace(trace)
        threading.settrace(trace)
        try:
            module.main()
        except Exception as exc:
            failure = f"{type(exc).__name__}:{exc}"
        finally:
            sys.settrace(previous_trace)
            threading.settrace(previous_thread_trace)
    phase_log = output / "phases.log"
    phase_log.write_text(stdout.getvalue(), encoding="utf-8")
    (output / "fixture-provenance.json").write_text(
        json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    receipt = json.loads((output / "receipt.json").read_bytes())
    result = {
        "mode": mode,
        "error": failure,
        "receipt": receipt,
        "commands": commands,
        "ports": ports,
        "cache_samples": samples,
        "executed_lines": sorted(executed),
        "clock_seconds": now[0],
        "post_archive_large_files": state.get("post_archive_large_files"),
        "archive_paths_absent": all(
            not Path(path).exists() for path in state.get("archive_paths", [])
        ),
        "wait_predicate_called": state.get("wait_predicate_called", False),
        "phases": [
            line
            for line in stdout.getvalue().splitlines()
            if line.startswith("kind_phase:")
        ],
    }
    (output / "walk.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8"
    )
    if mode == "success" and (failure or receipt.get("error")):
        raise AssertionError(f"scripted_walk_failed:{failure}:{receipt.get('error')}")
    if mode == "drain-nonzero" and (
        not failure
        or not failure.startswith("AssertionError:")
        or "last stream drained" not in failure
        or not receipt.get("diagnostics", {}).get("files")
        or not receipt.get("owned_cluster_cleanup_verified")
    ):
        raise AssertionError(f"nonzero_drain_did_not_refuse_and_cleanup:{failure}")
    if mode in {"no-work", "wait-cap"}:
        if (
            result["error"] != "TimeoutError:kind_internal_deadline:work"
            or not receipt.get("diagnostics", {}).get("files")
            or not receipt.get("owned_cluster_cleanup_verified")
        ):
            raise AssertionError("work_deadline_diagnostics_cleanup_failed")
    phase_rows = receipt.get("phase_started_s", [])
    parsed = []
    for line in result["phases"]:
        try:
            name, started_s = line.removeprefix("kind_phase:").rsplit(
                " phase_started_s=", 1
            )
            parsed.append((name, float(started_s)))
        except (ValueError, TypeError):
            raise AssertionError("phase_line_missing_started_s") from None
    if (
        len(phase_rows) != len(parsed)
        or [row.get("phase") for row in phase_rows] != [name for name, _ in parsed]
        or any(
            row.get("phase_started_s") != started_s
            for row, (_, started_s) in zip(phase_rows, parsed, strict=True)
        )
        or any(
            current[1] <= previous[1] for previous, current in zip(parsed, parsed[1:])
        )
    ):
        raise AssertionError("phase_times_missing_or_not_increasing")
    if mode == "success" and not {"readiness", "success", "cleanup"}.issubset(
        name for name, _ in parsed
    ):
        raise AssertionError("success_phase_lines_missing")
    if mode == "deadline":
        readiness_timeout = next(
            row["timeout"]
            for row in commands
            if "--for=jsonpath={.status.readyReplicas}=2" in row["argv"]
        )
        if (
            not failure
            or not failure.startswith("TimeoutExpired:")
            or not receipt.get("diagnostics")
            or not receipt.get("owned_cluster_cleanup_verified")
            or receipt.get("owned_cluster_cleanup_elapsed_seconds", 600)
            > module.KIND_RUNNER_TIMEOUT_S - module.KIND_RECEIPT_RESERVE_S
            or readiness_timeout > 11
            or not any(row["argv"][1:3] == ["delete", "cluster"] for row in commands)
            or not any(
                line.startswith("kind_phase:diagnostics ") for line in result["phases"]
            )
            or not any(
                line.startswith("kind_phase:cleanup ") for line in result["phases"]
            )
        ):
            raise AssertionError("deadline_diagnostics_cleanup_reserve_failed")
        if "uncapped_work_timeout" in failure:
            raise AssertionError(failure)
    return result


def coverage(output):
    output = Path(output)
    results = [
        walk(output / mode, mode=mode)
        for mode in (
            "success",
            "deadline",
            "no-work",
            "wait-cap",
            "stream-error",
            "process-error",
            "log-error",
            "remaining",
            "delete-error",
            "auth-denied",
            "overflow-scheduled",
            "drain-incomplete",
            "drain-nonzero",
            "capacity-stuck",
        )
    ]
    module = rehearsal()
    source = Path(module.__file__).read_text(encoding="utf-8")
    main = next(
        n
        for n in ast.parse(source).body
        if isinstance(n, ast.FunctionDef) and n.name == "main"
    )
    readiness = next(
        n
        for n in ast.walk(main)
        if isinstance(n, ast.Expr)
        and isinstance(n.value, ast.Call)
        and isinstance(n.value.func, ast.Name)
        and n.value.func.id == "phase"
        and len(n.value.args) == 1
        and isinstance(n.value.args[0], ast.Constant)
        and n.value.args[0].value == "readiness"
    )
    start = readiness.lineno
    receipt = next(
        n
        for n in ast.walk(main)
        if isinstance(n, ast.Expr)
        and "receipt.json" in ast.get_source_segment(source, n)
        and isinstance(n.value, ast.Call)
        and isinstance(n.value.func, ast.Attribute)
        and n.value.func.attr == "write_text"
    )
    target = sorted(
        {
            n.lineno
            for n in ast.walk(main)
            if isinstance(n, ast.stmt) and start <= n.lineno <= receipt.end_lineno
        }
    )
    observed = set().union(*(r["executed_lines"] for r in results))
    missing = sorted(set(target) - observed)

    def executable_lines(code):
        lines = {
            line
            for _, line in dis.findlinestarts(code)
            if start <= line <= receipt.end_lineno
        }
        for value in code.co_consts:
            if hasattr(value, "co_code"):
                lines.update(executable_lines(value))
        return lines

    line_targets = executable_lines(module.main.__code__)
    report = {
        "schema": "package-a-kind-statement-coverage-v1",
        "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "range_start": start,
        "range_end": receipt.end_lineno,
        "statement_lines": target,
        "covered_statement_lines": sorted(set(target) & observed),
        "missing_statement_lines": missing,
        "coverage_percent": 100 * (len(target) - len(missing)) / len(target),
        "executable_lines": sorted(line_targets),
        "covered_executable_lines": sorted(line_targets & observed),
        "missing_executable_lines": sorted(line_targets - observed),
        "line_coverage_percent": 100 * len(line_targets & observed) / len(line_targets),
        "line_coverage": {
            "covered": len(line_targets & observed),
            "total": len(line_targets),
        },
        "scenarios": [r["mode"] for r in results],
        "scenario_errors": {r["mode"]: r["error"] for r in results},
        "scope": "AST statement-start lines in main, including nested wrappers and failure/cleanup branches; fake k/run/forward/stream transports; no kind cluster",
    }
    (output / "coverage.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    if missing or report["missing_executable_lines"]:
        raise AssertionError(
            f"unexecuted_main_statements:{missing}:lines:{report['missing_executable_lines']}"
        )
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(coverage(args.output), sort_keys=True))
