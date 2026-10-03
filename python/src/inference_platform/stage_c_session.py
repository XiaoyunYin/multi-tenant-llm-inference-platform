"""Reviewed Stage C controller: prepare, verify, run, finalize, and export.

Source payloads contain only committed Git files. Compiled gateway artifacts are
separate and bound to that source commit. Runtime credentials are generated here,
never staged as source or exported. No Apply operation is embedded in this tool.
"""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import io
import json
import os
import re
import secrets
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import time
import urllib.request
from datetime import UTC
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ENTRYPOINT = "python/src/inference_platform/stage_c_session.py"
SOURCE_PREFIX = "python/src/inference_platform/"
CONFIG = "experiments/examples/stage-c-config.json"
ENVIRONMENT = "docs/INF011_STAGE_C_GATEWAY_ENV.json"
BUNDLE = "payload.tar.gz"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: dict) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )


def git(root: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(root), *args])


def source_paths(root: Path, commit: str) -> list[str]:
    tracked = git(root, "ls-tree", "-r", "--name-only", commit).decode().splitlines()
    return sorted(p for p in tracked if p.startswith(SOURCE_PREFIX) and p.endswith(".py")) + [
        CONFIG,
        ENVIRONMENT,
    ]


def verify_sources(payload: Path, manifest: dict, repo: Path | None = None) -> None:
    expected = {row["path"]: row for row in manifest["files"]}
    actual = {p.relative_to(payload).as_posix() for p in payload.rglob("*") if p.is_file()}
    if actual != set(expected):
        raise ValueError(
            f"unreviewed payload files: extra={sorted(actual - set(expected))}; "
            f"missing={sorted(set(expected) - actual)}"
        )
    if repo:
        tracked = set(source_paths(repo, manifest["source_commit"]))
        if set(expected) != tracked:
            raise ValueError(
                "staged source contains files not tracked in git or omits tracked source"
            )
    for path, row in expected.items():
        target = payload / path
        if target.is_symlink() or not target.resolve().is_relative_to(payload.resolve()):
            raise ValueError("unsafe staged source path")
        if sha(target) != row["sha256"]:
            raise ValueError(f"staged hash mismatch: {path}")
        if (
            repo
            and hashlib.sha256(git(repo, "show", f"{manifest['source_commit']}:{path}")).hexdigest()
            != row["sha256"]
        ):
            raise ValueError(f"staged source is not the committed git blob: {path}")
    entry = manifest["entrypoint"]
    if entry["path"] != ENTRYPOINT or entry["sha256"] != expected[ENTRYPOINT]["sha256"]:
        raise ValueError("entrypoint hash does not match manifest source")


def prepare(root: Path, destination: Path, target: str, source_commit: str = "HEAD") -> dict:
    """Build from a fresh committed snapshot, never from ignored session helpers."""
    destination.mkdir(parents=True, exist_ok=False)
    payload = destination / "sources"
    payload.mkdir()
    commit = git(root, "rev-parse", "--verify", source_commit + "^{commit}").decode().strip()
    rows = []
    for path in source_paths(root, commit):
        data = git(root, "show", f"{commit}:{path}")
        output = payload / path
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(data)
        rows.append({"path": path, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)})
    build_root = destination / "build-source"
    for path in git(root, "ls-tree", "-r", "--name-only", commit).decode().splitlines():
        if path.startswith(("cmd/", "internal/")) or path in ("go.mod", "go.sum"):
            output = build_root / path
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(git(root, "show", f"{commit}:{path}"))
    binary = destination / ("gateway.exe" if target == "windows" else "gateway")
    compiler = subprocess.check_output(["go", "version"], text=True).split()[2]
    if compiler != "go1.26.6":
        raise ValueError("reviewed gateway build requires Go 1.26.6")
    environment = {
        **os.environ,
        "GOOS": target,
        "GOARCH": "amd64",
        "CGO_ENABLED": "0",
        "GOAMD64": "v1",
        "GOFLAGS": "",
        "GOWORK": "off",
        "GOTOOLCHAIN": "local",
    }
    subprocess.run(
        [
            "go",
            "build",
            "-trimpath",
            "-buildvcs=false",
            "-o",
            str(binary.resolve()),
            "./cmd/gateway",
        ],
        cwd=build_root,
        env=environment,
        check=True,
    )
    manifest = {
        "schema": "inf011-stage-c-staging-manifest.v2",
        "source_commit": commit,
        "files": rows,
        "entrypoint": next(row for row in rows if row["path"] == ENTRYPOINT),
        "gateway_artifact": {
            "sha256": sha(binary),
            "source_commit": commit,
            "goos": target,
            "goarch": "amd64",
            "go_version": compiler,
            "path": binary.name,
            "build_argv": ["go", "build", "-trimpath", "-buildvcs=false", "./cmd/gateway"],
        },
        "source_policy": "Only tracked committed Git blobs in sources/; gateway is a separately attested build artifact; no per-session executable helpers.",
    }
    verify_sources(payload, manifest, root)
    write_json(destination / "staging-manifest.json", manifest)
    # Deterministic, hash-pinned bytes are the sole remote staging input. Imports
    # into the materialized workspace cannot change this archive.
    with (destination / BUNDLE).open("wb") as output:
        with gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as archive:
                for name in bundle_files(manifest):
                    data = (destination / name).read_bytes()
                    member = tarfile.TarInfo(name)
                    member.size = len(data)
                    member.mode = 0o755 if name == binary.name else 0o644
                    archive.addfile(member, io.BytesIO(data))
    (destination / BUNDLE).chmod(0o444)
    return manifest


def bundle_files(manifest: dict) -> list[str]:
    return ["staging-manifest.json", manifest["gateway_artifact"]["path"]] + [
        "sources/" + row["path"] for row in manifest["files"]
    ]


def verify_bundle(data: bytes, manifest: dict, manifest_hash: str) -> None:
    """Verify pinned bytes without extracting or executing any source."""
    expected = {
        "staging-manifest.json": manifest_hash,
        manifest["gateway_artifact"]["path"]: manifest["gateway_artifact"]["sha256"],
    }
    expected.update({"sources/" + row["path"]: row["sha256"] for row in manifest["files"]})
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        members = archive.getmembers()
        if (
            any(not member.isfile() for member in members)
            or len(members) != len(expected)
            or {member.name for member in members} != set(expected)
        ):
            raise ValueError("bundle contains an unreviewed or missing file")
        for member in members:
            if (
                hashlib.sha256(archive.extractfile(member).read()).hexdigest()
                != expected[member.name]
            ):
                raise ValueError(f"bundle hash mismatch: {member.name}")


def verify_pinned_payload(repo: Path, payload: Path, inputs: dict, manifest_hash: str) -> bytes:
    from .stage_c_fitness import verify_staged_directory

    staging = inputs["staging"]
    manifest_path = payload / "staging-manifest.json"
    if sha(manifest_path) != manifest_hash or manifest_hash != staging["manifest_sha256"]:
        raise ValueError("payload differs from session inputs manifest pin")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if (
        manifest["entrypoint"]["path"] != staging["entrypoint_path"]
        or manifest["entrypoint"]["sha256"] != staging["entrypoint_sha256"]
        or manifest["source_commit"] != staging["source_commit"]
        or manifest["gateway_artifact"] != staging["gateway_artifact"]
    ):
        raise ValueError("payload entrypoint/source/gateway differs from session inputs pins")
    verify_staged_directory(payload, manifest, repo)
    if manifest["gateway_artifact"]["goos"] != "linux":
        raise ValueError("EC2 requires reviewed Linux gateway")
    data = (payload / BUNDLE).read_bytes()
    if hashlib.sha256(data).hexdigest() != staging["bundle_sha256"]:
        raise ValueError("payload bundle differs from session inputs pin")
    verify_bundle(data, manifest, manifest_hash)
    return data


def preflight(
    repo: Path,
    payload: Path | None,
    plan_hash: str,
    manifest_hash: str | None,
    receipt: Path,
    *,
    rehearsal_target: str | None = None,
) -> dict:
    """No AWS calls: revalidate every local paid-session prerequisite."""
    from datetime import datetime

    receipt.unlink(missing_ok=True)  # A failed rerun cannot leave a passing receipt.
    inputs_path = repo / "docs/INF011_STAGE_C_SESSION_INPUTS.json"
    inputs_hash = sha(inputs_path)
    approval_head = git(repo, "rev-parse", "HEAD").decode().strip()
    # The explicit no-AWS rehearsal seam tests binding without inventing a marker.
    # Apply never supplies this override and always reruns the committed gate.
    approval_target = rehearsal_target or find_approval_target(repo, plan_hash)
    inputs = (
        bind_approved_inputs(repo, approval_target, plan_hash)
        if rehearsal_target
        else require_approval(repo, plan_hash)
    )
    manifest_hash = manifest_hash or inputs["staging"]["manifest_sha256"]
    payload = payload or repo / inputs["staging"]["payload_directory"]
    data = verify_pinned_payload(repo, payload, inputs, manifest_hash)
    # Verify code used for this check as well as the staged entrypoint.
    if sha(Path(__file__)) != inputs["staging"]["entrypoint_sha256"]:
        raise ValueError("executing entrypoint differs from session inputs pin")
    plugin = shutil.which("session-manager-plugin")
    if plugin is None:
        raise ValueError("session-manager-plugin does not resolve on PATH")
    if (
        sha(inputs_path) != inputs_hash
        or git(repo, "rev-parse", "HEAD").decode().strip() != approval_head
    ):
        raise ValueError("session inputs or approval HEAD changed during preflight")
    result = {
        "schema": "inf011-stage-c-preflight.v1",
        "status": "passed",
        "observed_at_utc": datetime.now(UTC).isoformat(),
        "plan_sha256": plan_hash,
        "manifest_sha256": manifest_hash,
        "bundle_sha256": hashlib.sha256(data).hexdigest(),
        "entrypoint_sha256": inputs["staging"]["entrypoint_sha256"],
        "source_commit": inputs["staging"]["source_commit"],
        "session_inputs_sha256": inputs_hash,
        "approval_head": approval_head,
        "approval_target": approval_target,
        "approval_basis": "binding_rehearsal_only"
        if rehearsal_target
        else "committed_latest_round",
        "session_manager_plugin": str(Path(plugin).resolve()),
        "aws_calls_made": False,
    }
    receipt.parent.mkdir(parents=True, exist_ok=True)
    write_json(receipt, result)
    return result


def free_port() -> int:
    with socket.socket() as handle:
        handle.bind(("127.0.0.1", 0))
        return handle.getsockname()[1]


def sampler(output: Path, pids: list[int]) -> None:
    from .clocks import measurement_clocks
    from .process_metrics import process_snapshot

    stopped = False

    def stop(*_):
        nonlocal stopped
        stopped = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    clocks = measurement_clocks(wall_clock=True)
    with output.open("w", encoding="utf-8", newline="\n") as stream:
        while not stopped:
            stream.write(
                json.dumps(
                    {
                        "unix_ns": time.time_ns(),
                        "perf_counter_ns": time.perf_counter_ns(),
                        "processes": [process_snapshot(pid) for pid in pids],
                    }
                )
                + "\n"
            )
            stream.flush()
            time.sleep(0.1)
    write_json(
        output.with_suffix(".clock.json"), {"status": "stopped", "measurement_clocks": clocks}
    )


def export(session: Path, manifest_path: Path) -> dict:
    """Explicit evidence allowlist excludes credentials, raw prompts and token IDs."""
    from .evidence_sanitize import sanitize_accounts

    evidence = session / "export"
    evidence.mkdir()
    names = [
        "staging-verification.json",
        "readiness-wait.json",
        "container-readiness-wait.json",
        "deadline-epoch.json",
        "stage-c-artifact.json",
        "session-finalization.json",
        "host-process-samples.jsonl",
        "host-process-samples.clock.json",
        "runtime-config-sanitized.json",
        "gateway.log",
        "vllm-startup.log",
        "dcgm.prom",
        "dcgm-status.json",
    ]
    encoding_warnings = []
    for name in names:
        source = session / name
        if source.is_file():
            try:
                content = source.read_text(encoding="utf-8", errors="strict")
            except UnicodeDecodeError:
                if not name.endswith(".log"):
                    raise
                # External runtime logs must not prevent export of completed runs.
                # Preserve undecodable bytes visibly rather than guess a code page.
                content = source.read_bytes().decode("utf-8", errors="backslashreplace")
                encoding_warnings.append({"file": name, "status": "non_utf8_bytes_escaped"})
            (evidence / name).write_text(
                sanitize_accounts(content.replace("\r\n", "\n").replace("\r", "\n")),
                encoding="utf-8",
                newline="\n",
            )
    (evidence / "staging-manifest.json").write_bytes(manifest_path.read_bytes())
    sums = "".join(f"{sha(p)}  {p.name}\n" for p in sorted(evidence.iterdir()) if p.is_file())
    (evidence / "SHA256SUMS.txt").write_text(sums, encoding="utf-8", newline="\n")
    archive = session / "evidence.tar.gz"
    with tarfile.open(archive, "w:gz") as stream:
        for path in sorted(evidence.iterdir()):
            stream.add(path, arcname=path.name, recursive=False)
    receipt = {
        "status": "exported",
        "archive": str(archive),
        "sha256": sha(archive),
        "bytes": archive.stat().st_size,
        "files": len(list(evidence.iterdir())),
        "finalization_started_immediately": True,
        "log_encoding_warnings": encoding_warnings,
    }
    write_json(session / "export-receipt.json", receipt)
    return receipt


def run_session(args) -> int:
    manifest_path = args.payload / "staging-manifest.json"
    if sha(manifest_path) != args.manifest_sha256:
        raise ValueError("staging manifest is not the reviewed pinned manifest")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    sources = args.payload / "sources"
    verify_sources(sources, manifest)
    if sha(Path(__file__)) != manifest["entrypoint"]["sha256"]:
        raise ValueError("running entrypoint differs from reviewed staging hash")
    binary = args.payload / manifest["gateway_artifact"]["path"]
    if sha(binary) != manifest["gateway_artifact"]["sha256"]:
        raise ValueError("gateway build artifact hash mismatch")
    from .session_stop import pid_is_running, stop_child
    from .stage_c import _config_from_json, run_stage_c
    from .stage_c_container import stage_capture_package
    from .stage_c_gateway import launch_gateway
    from .stage_c_readiness import (
        check_processes,
        inspect_container,
        read_epoch,
        wait_readiness,
        wait_startup,
    )

    session = args.session.resolve()
    session.mkdir(parents=True, exist_ok=False)
    private = session / "private"
    private.mkdir(mode=0o700)
    children = []
    result = {"status": "readiness_failed", "timed_runs": []}
    finalization = {"start": "immediately_after_last_run_or_abort", "children": [], "errors": []}
    try:
        write_json(
            session / "staging-verification.json",
            {
                "status": "verified",
                "manifest_sha256": args.manifest_sha256,
                "entrypoint": manifest["entrypoint"],
                "source_commit": manifest["source_commit"],
                "source_file_count": len(manifest["files"]),
                "untracked_source_files": [],
            },
        )
        config = json.loads((sources / CONFIG).read_text(encoding="utf-8"))
        environment = json.loads((sources / ENVIRONMENT).read_text(encoding="utf-8"))
        backend_child = None
        if args.rehearse:
            backend_url = f"http://127.0.0.1:{free_port()}"
            fake_config = {
                "backend_id": "vllm0",
                "health_ready_delay_ms": 1500,
                "long_prompt_delay_ms": 10000,
                "kv_event_blocks_per_store": 32,
                "running_capacity": 16,
                "reject_above_active": 48,
                "kv_cache_capacity_blocks": 3891,
                "runtime_shaped_metrics": True,
            }
            if args.quick:
                fake_config["long_prompt_delay_ms"] = 0
            write_json(private / "fake-config.json", fake_config)
            backend_log = (session / "vllm-startup.log").open("wb")
            backend_child = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "inference_platform.fake_backend",
                    "--config",
                    str(private / "fake-config.json"),
                    "--port",
                    backend_url.rsplit(":", 1)[1],
                ],
                stdout=backend_log,
                stderr=subprocess.STDOUT,
                env={**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"},
            )
            children.append(("fake_vllm", backend_child))
            backend_log.close()
            gateway_url = f"http://127.0.0.1:{free_port()}"
            environment["BACKENDS"] = "vllm0=" + backend_url
            config.update(
                url=gateway_url,
                reset_url=backend_url,
                tokenize_url=backend_url,
                fake_event_url=backend_url + "/kv-events",
                local_rehearsal=True,
                metrics_endpoints=[["gateway", gateway_url], ["vllm0", backend_url]],
            )
            if args.quick:
                config.update(
                    sustained_level_seconds=0.3,
                    drain_seconds=5,
                    minimum_cycle_seconds=0.05,
                    saturation_levels=[1, 2],
                    rewarm_samples=2,
                    rewarm_repeats=1,
                )
                # Control-flow CI rehearsal only; the full rehearsal preserves the 90s protocol.
            now = time.time()
            epoch = {
                "instance_boot_unix_s": now - 2015,
                "instance_termination_unix_s": now - 2015 + 14400,
                "basis": "LOCAL FAKE REHEARSAL; no instance/no AWS",
            }
            backend_pid = backend_child.pid
        else:
            if args.quick:
                raise ValueError("quick mode is restricted to no-cost fake rehearsal")
            epoch = read_epoch(args.epoch_file)
            backend_url, gateway_url = config["reset_url"], config["url"]
            container_readiness = wait_startup(
                epoch,
                config["minimum_useful_run_seconds"],
                config["evidence_export_margin_seconds"],
                inspect_container,
            )
            write_json(session / "container-readiness-wait.json", container_readiness)
            write_json(session / "readiness-wait.json", container_readiness)
            if container_readiness["status"] != "ready":
                result.update(
                    timed_runs=container_readiness["timed_runs"], readiness=container_readiness
                )
                raise RuntimeError(container_readiness["reason"])
            backend_pid = container_readiness["attempts"][-1]["state"]["Pid"]
            if not pid_is_running(backend_pid):
                raise RuntimeError("vLLM process is not running")
            try:
                stage_capture_package(sources, private)
            except (OSError, subprocess.SubprocessError) as error:
                config["kv_capture_staging_error"] = f"capture staging unavailable: {error}"
        write_json(session / "deadline-epoch.json", epoch)
        token = secrets.token_urlsafe(32)
        salt = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
        (private / "cache-salt.secret").write_text(salt + "\n", encoding="utf-8", newline="\n")
        write_json(
            private / "tenants.json",
            {
                "tenants": [
                    {
                        "tenant_id": config["tenant_id"],
                        "credential_sha256": hashlib.sha256(token.encode()).hexdigest(),
                        "models": [config["model"]],
                        "max_request_bytes": 1048576,
                        "max_output_tokens": 128,
                        "max_concurrent": 128,
                        "request_rate_limit": 4096,
                        "request_rate_window_ms": 1000,
                    }
                ]
            },
        )
        environment.update(
            TENANT_CONFIG_PATH=str(private / "tenants.json"),
            CACHE_SALT_SECRET_FILE=str(private / "cache-salt.secret"),
            GATEWAY_HTTP_ADDR=gateway_url.removeprefix("http://"),
        )
        write_json(private / "gateway-env.json", environment)
        gateway_log = (session / "gateway.log").open("wb")
        try:
            gateway = launch_gateway(
                str(binary.resolve()), private / "gateway-env.json", gateway_log
            )
        except subprocess.SubprocessError as error:
            from .stage_c_readiness import last_log_line

            raise RuntimeError(
                "gateway configuration/startup failed: " + last_log_line(session / "gateway.log")
            ) from error
        children.append(("gateway", gateway))
        gateway_log.close()
        sample_child = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "inference_platform.stage_c_session",
                "--sampler",
                str(session / "host-process-samples.jsonl"),
                "--pids",
                str(gateway.pid),
                str(backend_pid),
            ],
            env={**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"},
        )
        children.append(("sampler", sample_child))

        def alive():
            return backend_child.poll() is None if backend_child else pid_is_running(backend_pid)

        readiness = wait_readiness(
            epoch,
            tuple(config["minimum_useful_run_seconds"]),
            config["evidence_export_margin_seconds"],
            (backend_url + "/health", gateway_url + "/healthz", gateway_url + "/readyz"),
            lambda: check_processes(gateway, alive, session / "gateway.log"),
        )
        if not args.rehearse:
            readiness["container_wait"] = container_readiness
        write_json(session / "readiness-wait.json", readiness)
        if readiness["status"] != "ready":
            result.update(timed_runs=readiness["timed_runs"], readiness=readiness)
        else:
            config.update(
                token=token,
                run_id=session.name,
                gateway_config_log=str(session / "gateway.log"),
                process_pids=[gateway.pid, backend_pid],
                instance_boot_unix_s=epoch["instance_boot_unix_s"],
                instance_termination_unix_s=epoch["instance_termination_unix_s"],
                observed_readiness_unix_s=readiness["observed_readiness_unix_s"],
                decision_prompt_export_path=str(private / "restricted-prompts.jsonl"),
                decision_export_output_path=str(private / "restricted-decisions.jsonl"),
                kv_capture_output_path=str(session / "kv-event-capture.json"),
                kv_capture_stop_file=str(session / "capture.stop"),
            )
            write_json(private / "runtime-config.json", config)
            sanitized = {k: v for k, v in config.items() if k != "token"}
            sanitized["token_configured"] = True
            write_json(session / "runtime-config-sanitized.json", sanitized)
            result = run_stage_c(_config_from_json(private / "runtime-config.json"))
            result["readiness_wait"] = readiness
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        result.update(status="session_failed", reason=str(error))
    finally:
        # No idle until cutoff: capture/decision finalization belongs to run_stage_c;
        # owned children are stopped and reaped before export, even on readiness abort.
        finalization["started_unix_s"] = time.time()
        for role, child in reversed(children):
            try:
                finalization["children"].append({"role": role, **stop_child(child)})
            except (OSError, subprocess.SubprocessError) as error:
                finalization["errors"].append(f"{role}: {error}")
        if not args.rehearse:
            try:
                subprocess.run(
                    [
                        "docker",
                        "exec",
                        "inf011-vllm",
                        "rm",
                        "-f",
                        str(private / "restricted-decisions.jsonl"),
                    ],
                    check=True,
                    timeout=10,
                )
                finalization["container_raw_inputs_removed"] = True
            except (OSError, subprocess.SubprocessError) as error:
                finalization["errors"].append(f"container raw input cleanup: {error}")
            try:
                log = subprocess.run(
                    ["docker", "logs", "--tail", "2000", "inf011-vllm"],
                    capture_output=True,
                    timeout=10,
                    check=False,
                )
                (session / "vllm-startup.log").write_text(
                    (log.stdout + log.stderr).decode("utf-8", errors="replace"),
                    encoding="utf-8",
                    newline="\n",
                )
                with urllib.request.urlopen("http://127.0.0.1:9400/metrics", timeout=5) as response:
                    (session / "dcgm.prom").write_text(
                        response.read().decode("utf-8"), encoding="utf-8", newline="\n"
                    )
                write_json(
                    session / "dcgm-status.json",
                    {
                        "status": "captured",
                        "timing": "immediate finalization snapshot; per-level native metrics are in the recorder artifact",
                    },
                )
            except OSError as error:
                write_json(
                    session / "dcgm-status.json", {"status": "unavailable", "reason": str(error)}
                )
        if args.rehearse and not (session / "host-process-samples.clock.json").exists():
            from .clocks import measurement_clocks

            write_json(
                session / "host-process-samples.clock.json",
                {
                    "status": "stopped",
                    "basis": "Windows child terminated and reaped by parent",
                    "measurement_clocks": measurement_clocks(wall_clock=True),
                },
            )
        for path in private.iterdir():
            path.unlink()
        private.rmdir()
        write_json(session / "stage-c-artifact.json", result)
        write_json(session / "session-finalization.json", finalization)
        export_receipt = export(session, manifest_path)
        print(json.dumps(export_receipt))
    return int(result["status"] != "completed" or bool(finalization["errors"]))


def install_bundle(data: bytes, destination: Path, manifest_hash: str) -> dict:
    """Never extract executable helpers outside the reviewed file allowlist."""
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        members = archive.getmembers()
        if any(not m.isfile() for m in members) or len({m.name for m in members}) != len(members):
            raise ValueError("bundle must contain unique regular files only")
        manifest_bytes = archive.extractfile("staging-manifest.json").read()
        if hashlib.sha256(manifest_bytes).hexdigest() != manifest_hash:
            raise ValueError("bundle manifest is not reviewed")
        manifest = json.loads(manifest_bytes)
        allowed = {"staging-manifest.json", manifest["gateway_artifact"]["path"]} | {
            "sources/" + row["path"] for row in manifest["files"]
        }
        if {m.name for m in members} != allowed:
            raise ValueError("bundle contains an unreviewed or missing file")
        destination.mkdir(parents=True, exist_ok=False)
        for member in members:
            target = destination / member.name
            if not target.resolve().is_relative_to(destination.resolve()):
                raise ValueError("unsafe bundle path")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.extractfile(member).read())
        verify_sources(destination / "sources", manifest)
        binary = destination / manifest["gateway_artifact"]["path"]
        if sha(binary) != manifest["gateway_artifact"]["sha256"]:
            raise ValueError("bundle gateway hash mismatch")
        binary.chmod(0o755)
        return manifest


def serve_transport(destination: Path, manifest_hash: str, nonce: str, port: int) -> None:
    """Internal SSM-only loopback transfer; the same entrypoint owns the host child."""
    child = None
    termination = int(Path("/etc/inf011/deadline_epoch").read_text().strip())
    deadline = time.perf_counter() + max(0, termination - time.time())

    class Transfer(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def authorized(self):
            return secrets.compare_digest(self.headers.get("Authorization", ""), nonce)

        def reply(self, status, body, content_type="application/json"):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_PUT(self):  # noqa: N802
            nonlocal child
            if not self.authorized() or self.path != "/payload" or child is not None:
                self.reply(403, b"{}")
                return
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length < 128 * 1024 * 1024:
                self.reply(413, b"{}")
                return
            try:
                install_bundle(self.rfile.read(length), destination, manifest_hash)
                environment = {
                    **os.environ,
                    "PYTHONPATH": str(destination / "sources/python/src"),
                    "PYTHONDONTWRITEBYTECODE": "1",
                }
                with (destination / "controller.log").open("wb") as log:
                    child = subprocess.Popen(
                        [
                            sys.executable,
                            "-m",
                            "inference_platform.stage_c_session",
                            "--payload",
                            str(destination),
                            "--manifest-sha256",
                            manifest_hash,
                            "--session",
                            str(destination / "session"),
                        ],
                        env=environment,
                        stdout=log,
                        stderr=subprocess.STDOUT,
                    )
                self.reply(200, b'{"status":"started"}')
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                self.reply(400, json.dumps({"error": str(error)}).encode())

        def do_GET(self):  # noqa: N802
            if not self.authorized():
                self.reply(403, b"{}")
                return
            if self.path == "/status":
                self.reply(
                    200,
                    json.dumps(
                        {
                            "started": child is not None,
                            "finished": child is not None and child.poll() is not None,
                            "returncode": child.poll() if child else None,
                            "instance_termination_unix_s": termination,
                        }
                    ).encode(),
                )
            elif self.path == "/export" and child and child.poll() is not None:
                path = destination / "session/evidence.tar.gz"
                if path.exists():
                    self.reply(200, path.read_bytes(), "application/gzip")
                else:
                    self.reply(500, (destination / "controller.log").read_bytes())
            elif self.path == "/receipt" and child and child.poll() is not None:
                self.reply(200, (destination / "session/export-receipt.json").read_bytes())
            else:
                self.reply(404, b"{}")

    with HTTPServer(("127.0.0.1", port), Transfer) as server:
        server.timeout = 1
        while time.perf_counter() < deadline:
            server.handle_request()


def find_approval_target(repo: Path, plan_hash: str) -> str:
    """Mirror the committed latest-round approval rule; never modify its marker."""
    for argv in (
        ("diff", "--quiet", "--", "REVIEW.md"),
        ("diff", "--cached", "--quiet", "--", "REVIEW.md"),
    ):
        if subprocess.run(["git", "-C", str(repo), *argv], check=False).returncode:
            raise ValueError("paid execution gate closed: REVIEW.md must be clean and committed")
    review = git(repo, "show", "HEAD:REVIEW.md").decode("utf-8")
    span = review.split("\n## Claude review rounds\n", 1)[1].split("\n## Findings\n", 1)[0]
    rounds = list(re.finditer(r"(?m)^### Round (\d+)\b", span))
    latest = span[rounds[-1].end() :]
    markers = re.findall(
        r"(?m)^- INF-011 PAID PLAN APPROVED: plan_sha256=([0-9a-f]{64}); target=([0-9a-f]{40}); review_round=(\d+)\s*$",
        latest,
    )
    if len(markers) != 1 or markers[0][0] != plan_hash or markers[0][2] != rounds[-1][1]:
        raise ValueError(
            "paid execution gate closed: latest committed exact-plan approval required"
        )
    subprocess.run(
        ["git", "-C", str(repo), "merge-base", "--is-ancestor", markers[0][1], "HEAD"], check=True
    )
    return markers[0][1]


def bind_approved_inputs(repo: Path, target: str, plan_hash: str) -> dict:
    """Return the approved Git inputs; reject dirty files and later committed re-pins."""
    path = "docs/INF011_STAGE_C_SESSION_INPUTS.json"
    approved = json.loads(git(repo, "show", f"{target}:{path}").decode("utf-8"))
    working = json.loads((repo / path).read_text(encoding="utf-8"))
    for key in ("plan_sha256", "region", "aws_profile", "staging"):
        if working.get(key) != approved.get(key):
            raise ValueError(f"session inputs {key} differs from approved target {target}")
    for argv in (("diff", "--quiet", "--", path), ("diff", "--cached", "--quiet", "--", path)):
        if subprocess.run(["git", "-C", str(repo), *argv], check=False).returncode:
            raise ValueError("session inputs must be clean and committed against HEAD")
    if approved["plan_sha256"] != plan_hash:
        raise ValueError("plan hash differs from approved target")
    return approved


def require_approval(repo: Path, plan_hash: str) -> dict:
    return bind_approved_inputs(repo, find_approval_target(repo, plan_hash), plan_hash)


def remote_session(args) -> int:
    """Stage over SSM, execute the pinned host entrypoint, export, then tear down.

    This is only for a separately authorized, already applied instance; no Apply.
    It is never called by preparation, fitness, tests, or PlanPaid.
    """
    from datetime import datetime

    from .session_stop import stop_forward
    from .stage_c_readiness import read_epoch, readiness_window, wait_startup
    from .stage_c_transport import (
        ControlLost,
        ReconnectingTransport,
        command_batches,
        monitor_and_export,
        recover_export,
        ssm_commands,
        wait_ssm_online,
    )

    inputs = require_approval(args.repo, args.plan_sha256)
    data = verify_pinned_payload(args.repo, args.payload, inputs, args.manifest_sha256)
    if shutil.which("session-manager-plugin") is None:
        raise ValueError("session-manager-plugin does not resolve on PATH")
    manifest_path = args.payload / "staging-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    args.session.mkdir(parents=True, exist_ok=False)
    bundle = args.session / "staging.tar.gz"
    bundle.write_bytes(data)
    region, profile = inputs["region"], inputs["aws_profile"]
    if region != "us-east-1" or profile != "admin-learning":
        raise ValueError("session is bound to admin-learning/us-east-1")

    def aws(*argv, timeout=30):
        return json.loads(
            subprocess.check_output(
                [
                    "aws",
                    *argv,
                    "--region",
                    region,
                    "--profile",
                    profile,
                    "--output",
                    "json",
                    "--no-cli-pager",
                ],
                text=True,
                timeout=timeout,
                stderr=subprocess.PIPE,
            )
        )

    instance = aws("ec2", "describe-instances", "--instance-ids", args.remote_instance)[
        "Reservations"
    ][0]["Instances"][0]
    tags = {row["Key"]: row["Value"] for row in instance.get("Tags", [])}
    if (
        instance["InstanceType"] != "g6.xlarge"
        or instance["Placement"]["AvailabilityZone"] != inputs["availability_zone"]
        or instance["State"]["Name"] != "running"
        or "INF-011" not in tags.values()
    ):
        raise ValueError("existing instance does not match the reviewed session/tag/zone")
    nonce, remote_port, local_port = secrets.token_hex(32), 22280, free_port()
    destination = "/opt/inf011/reviewed-" + args.manifest_sha256[:16]
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        source = archive.extractfile("sources/" + ENTRYPOINT).read()
    encoded = base64.b64encode(source).decode()
    bootstrap = destination + "-entrypoint.py"
    quoted = shlex.quote(bootstrap + ".b64")
    commands = [f"test ! -e {shlex.quote(bootstrap)} && : > {quoted}"]
    commands += [
        f"printf %s {shlex.quote(encoded[i : i + 3000])} >> {quoted}"
        for i in range(0, len(encoded), 3000)
    ]
    commands += [
        f"base64 -d {quoted} > {shlex.quote(bootstrap)}",
        f"echo '{manifest['entrypoint']['sha256']}  {bootstrap}' | sha256sum -c -",
        "nohup python3 "
        + shlex.quote(bootstrap)
        + " --serve-transport "
        + shlex.quote(destination)
        + " --manifest-sha256 "
        + args.manifest_sha256
        + " --nonce "
        + nonce
        + " --port "
        + str(remote_port)
        + " >/opt/inf011/reviewed-transport.log 2>&1 </dev/null &",
    ]
    # Before SSM is Online the persisted file is inaccessible. LaunchTime is
    # earlier than user-data's persisted epoch, so this provisional bound cannot
    # extend readiness. Replace it with the actual file as soon as SSM is usable.
    launch = datetime.fromisoformat(str(instance["LaunchTime"]).replace("Z", "+00:00")).timestamp()
    epoch = {
        "instance_boot_unix_s": launch,
        "instance_termination_unix_s": launch + inputs["maximum_duration_hours"] * 3600,
        "basis": "conservative EC2 LaunchTime bound until persisted epoch can be fetched",
    }
    minima, margin = inputs["minimum_useful_run_seconds"], inputs["evidence_export_margin_seconds"]
    deadline, _ = readiness_window(epoch, minima, margin)
    transport, termination_deadline = None, None
    outcome = {
        "apply_called": False,
        "plan_sha256": args.plan_sha256,
        "manifest_sha256": args.manifest_sha256,
        "transport_interruptions": [],
        "ssm_command_attempts": [],
        "bootstrap_batch_bytes": [],
    }
    try:
        try:
            plugin = subprocess.run(
                ["session-manager-plugin", "--version"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            outcome["session_manager_plugin"] = {
                "returncode": plugin.returncode,
                "stdout": plugin.stdout,
                "stderr": plugin.stderr,
            }
        except (OSError, subprocess.SubprocessError) as error:
            outcome["session_manager_plugin"] = {"error": str(error)}
        readiness = wait_ssm_online(aws, args.remote_instance, epoch, minima, margin)
        write_json(args.session / "ssm-readiness-wait.json", readiness)
        outcome["ssm_readiness"] = readiness
        if readiness["status"] != "ready":
            outcome["timed_runs"] = readiness["timed_runs"]
            raise ControlLost(readiness["reason"])

        def epoch_probe(timeout):
            try:
                response = ssm_commands(
                    aws,
                    args.remote_instance,
                    [
                        "if test -s /etc/inf011/deadline_epoch; then cat /etc/inf011/deadline_epoch; else echo null; fi"
                    ],
                    min(deadline, time.perf_counter() + timeout),
                    args.session,
                    outcome["ssm_command_attempts"],
                )
                value = json.loads(response["StandardOutputContent"])
                return {"ready": isinstance(value, int) and value > 0, "persisted_value": value}
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                return {"ready": False, "error": str(error)}

        epoch_wait = wait_startup(epoch, minima, margin, epoch_probe)
        outcome["epoch_readiness"] = epoch_wait
        if epoch_wait["status"] != "ready":
            outcome["timed_runs"] = epoch_wait["timed_runs"]
            raise ControlLost(epoch_wait["reason"])
        epoch_path = args.session / "deadline-epoch.json"
        write_json(epoch_path, epoch_wait["attempts"][-1]["persisted_value"])
        persisted = read_epoch(epoch_path)
        persisted_deadline, _ = readiness_window(persisted, minima, margin)
        deadline = min(deadline, persisted_deadline)
        termination_deadline = (
            time.perf_counter() + persisted["instance_termination_unix_s"] - time.time()
        )
        outcome["persisted_epoch"] = persisted
        outcome["readiness_deadline_unix_s"] = min(
            readiness["readiness_deadline_unix_s"],
            persisted["instance_termination_unix_s"] - margin - sum(minima),
        )
        for batch in command_batches(commands):
            outcome["bootstrap_batch_bytes"].append(
                len(json.dumps({"commands": ["set -eu\n" + "\n".join(batch)]}).encode())
            )
            ssm_commands(
                aws,
                args.remote_instance,
                batch,
                deadline,
                args.session,
                outcome["ssm_command_attempts"],
            )
        flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0

        def start_forward():
            # A plugin orphan can briefly retain its listener after the CLI exits.
            # A new local port prevents it from shadowing the replacement forward.
            port = free_port()
            transport.base = f"http://127.0.0.1:{port}"
            parameters = json.dumps(
                {"portNumber": [str(remote_port)], "localPortNumber": [str(port)]}
            )
            with (args.session / "ssm-forward.log").open("ab") as log:
                return subprocess.Popen(
                    [
                        "aws",
                        "ssm",
                        "start-session",
                        "--target",
                        args.remote_instance,
                        "--document-name",
                        "AWS-StartPortForwardingSession",
                        "--parameters",
                        parameters,
                        "--region",
                        region,
                        "--profile",
                        profile,
                    ],
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    creationflags=flags,
                    start_new_session=os.name != "nt",
                )

        transport = ReconnectingTransport(
            start_forward,
            f"http://127.0.0.1:{local_port}",
            nonce,
            deadline,
            outcome["transport_interruptions"],
            stop=stop_forward,
        )
        status = json.loads(transport.get("/status"))
        if status["instance_termination_unix_s"] != persisted["instance_termination_unix_s"]:
            raise ValueError("transport termination differs from persisted epoch")
        transport.put_payload(data)
        transport.deadline = termination_deadline - 300
        monitor_and_export(transport, args.session, outcome)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        outcome["reason"] = str(error)
    finally:
        if transport and not outcome.get("export_verified"):
            recover_export(transport, args.session, outcome, termination_deadline)
        if transport:
            outcome["transport_stop"] = transport.close()
        # Immediate cleanup after verified export or any abort; no new paid plan/Apply.
        wrapper = args.repo / "scripts/inf011-pilot.ps1"
        for action in ("Destroy", "VerifyTeardown"):
            argv = [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(wrapper),
                "-Action",
                action,
                "-EvidenceDirectory",
                str(args.session / action),
            ]
            if action == "Destroy":
                argv += ["-ConfirmationText", "DESTROY INF-011 PILOT"]
            completed = subprocess.run(
                argv,
                env={**os.environ, "AWS_PROFILE": profile, "TF_VAR_aws_region": region},
                check=False,
            )
            outcome[action] = completed.returncode
        write_json(args.session / "controller-outcome.json", outcome)
    return int(
        not outcome.get("export_verified") or outcome["Destroy"] or outcome["VerifyTeardown"]
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--prepare", type=Path, help="fresh destination for committed staging snapshot"
    )
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--target", choices=("linux", "windows"), default="linux")
    parser.add_argument(
        "--source-commit", default="HEAD", help="reproduce the exact reviewed staging snapshot"
    )
    parser.add_argument("--payload", type=Path)
    parser.add_argument("--manifest-sha256")
    parser.add_argument("--session", type=Path)
    parser.add_argument("--epoch-file", type=Path, default=Path("/etc/inf011/deadline_epoch"))
    parser.add_argument("--rehearse", action="store_true")
    parser.add_argument("--quick", action="store_true")
    parser.add_argument("--sampler", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--pids", nargs="*", type=int, default=[], help=argparse.SUPPRESS)
    parser.add_argument("--serve-transport", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--nonce", help=argparse.SUPPRESS)
    parser.add_argument("--port", type=int, default=22280, help=argparse.SUPPRESS)
    parser.add_argument(
        "--remote-instance",
        help="already applied instance; requires latest committed plan approval",
    )
    parser.add_argument("--plan-sha256")
    parser.add_argument(
        "--preflight", action="store_true", help="verify local inputs; no AWS calls"
    )
    parser.add_argument("--receipt", type=Path)
    parser.add_argument(
        "--preflight-rehearsal-target", help="no-AWS binding test only; never authorizes Apply"
    )
    args = parser.parse_args()
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    if args.preflight_rehearsal_target and not args.preflight:
        parser.error("--preflight-rehearsal-target is restricted to no-AWS --preflight")
    if args.sampler:
        sampler(args.sampler, args.pids)
        return 0
    if args.serve_transport:
        serve_transport(args.serve_transport, args.manifest_sha256, args.nonce, args.port)
        return 0
    if args.prepare:
        manifest = prepare(
            args.repo.resolve(), args.prepare.resolve(), args.target, args.source_commit
        )
        print(
            json.dumps(
                {
                    "entrypoint": manifest["entrypoint"],
                    "manifest_sha256": sha(args.prepare / "staging-manifest.json"),
                    "bundle_sha256": sha(args.prepare / BUNDLE),
                }
            )
        )
        return 0
    if args.preflight:
        if not all((args.plan_sha256, args.receipt)):
            parser.error(
                "preflight requires --plan-sha256 and --receipt; payload pins come from the approved target"
            )
        print(
            json.dumps(
                preflight(
                    args.repo,
                    args.payload,
                    args.plan_sha256,
                    args.manifest_sha256,
                    args.receipt,
                    rehearsal_target=args.preflight_rehearsal_target,
                )
            )
        )
        return 0
    if not all((args.payload, args.manifest_sha256, args.session)):
        parser.error("session requires --payload, --manifest-sha256 and a fresh --session")
    if args.remote_instance:
        if not args.plan_sha256 or args.rehearse:
            parser.error("remote execution requires exact --plan-sha256 and cannot rehearse")
        return remote_session(args)
    return run_session(args)


if __name__ == "__main__":
    raise SystemExit(main())
