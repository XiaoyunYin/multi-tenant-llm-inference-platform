"""Bounded same-host capture startup and post-run decision join; no AWS actions."""

import json
import os
import subprocess
import time
from pathlib import Path, PurePosixPath

from .decision_export import export_decisions
from .disk_records import DiskList, jsonl_rows
from .kv_event_capture import (
    CORRELATION_BASIS,
    correlate_routing_events,
    load_routing_decisions,
    summarize_routing_correlations,
)
from .stage_c_container import capture_argv
from .time_budget import remaining_seconds

CAPTURE_ROOT = PurePosixPath("/opt/inf011/capture-private")


def require_capture_mount(config, deadline):
    """Fail event readiness closed if the reviewed host bind mount is absent."""
    output = PurePosixPath(config.kv_capture_output_path)
    if not output.is_relative_to(CAPTURE_ROOT):
        raise ValueError("capture output must use the private host bind mount")
    for name in (config.decision_export_output_path, config.kv_capture_stop_file):
        if PurePosixPath(name).parent != output.parent:
            raise ValueError(
                "capture decisions and stop file must share the private host directory"
            )
    mounts = json.loads(
        docker(config, ["inspect", "--format", "{{json .Mounts}}", "inf011-vllm"], deadline).stdout
    )
    if not any(
        row.get("Type") == "bind"
        and row.get("Source")
        and row.get("Destination") == str(CAPTURE_ROOT)
        and row.get("RW") is True
        for row in mounts
    ):
        raise RuntimeError("private capture host bind mount unavailable")


def prepare_paths(config):
    created = []
    try:
        for name in (config.decision_prompt_export_path, config.decision_export_output_path):
            descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(descriptor)
            created.append(Path(name))
    except OSError:
        for path in created:
            path.unlink()
        raise


def docker(config, args, deadline, *, check=True):
    return subprocess.run(
        ["docker", *args],
        shell=False,
        capture_output=True,
        text=True,
        timeout=remaining_seconds(deadline, 10),
        check=check,
    )


def start_live_capture(config, deadline):
    require_capture_mount(config, deadline)
    ready_path = config.kv_capture_output_path + ".ready"
    # A prior receipt or stop file could falsely admit a dead subscriber. Require fresh
    # session paths in the container. prepare_paths already exclusively creates the
    # restricted decisions file on the host in this shared mount; it is expected here.
    docker(
        config,
        [
            "exec",
            "--env",
            "PYTHONDONTWRITEBYTECODE=1",
            "inf011-vllm",
            "python3",
            "-B",
            "-c",
            "import os,sys; sys.exit(any(os.path.exists(p) for p in sys.argv[1:]))",
            ready_path,
            config.kv_capture_stop_file,
            config.kv_capture_output_path,
        ],
        deadline,
    )
    argv = capture_argv() + [
        "--stream-output",
        "--endpoint",
        config.kv_event_endpoint,
        "--topic",
        config.kv_event_topic,
        "--duration-seconds",
        # Keep capture alive during the join/export half of the reserved margin;
        # it must load the decision input after the final measured request.
        str(remaining_seconds(deadline + config.evidence_export_margin_seconds, 14400)),
        "--decisions",
        config.decision_export_output_path,
        "--output",
        config.kv_capture_output_path,
        "--stop-file",
        config.kv_capture_stop_file,
        "--ready-file",
        ready_path,
    ]
    # All paths are session-specific, created during reviewed SSM staging in both namespaces.
    process = subprocess.Popen(
        argv, shell=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    try:
        wait_deadline = min(deadline, time.perf_counter() + 15)
        while time.perf_counter() < wait_deadline:
            if process.poll() is not None:
                raise RuntimeError("capture process exited before subscription readiness")
            ready = docker(
                config, ["exec", "inf011-vllm", "cat", ready_path], wait_deadline, check=False
            )
            if ready.returncode == 0 and json.loads(ready.stdout).get("subscribed"):
                time.sleep(remaining_seconds(wait_deadline, 0.5))  # PUB subscription propagation
                return process
            time.sleep(remaining_seconds(wait_deadline, 0.1))
        raise RuntimeError("capture subscription readiness timed out")
    except Exception:
        try:
            docker(
                config,
                ["exec", "inf011-vllm", "touch", config.kv_capture_stop_file],
                deadline,
                check=False,
            )
        except (OSError, RuntimeError, subprocess.SubprocessError):
            pass  # Persisted session termination remains the hard ceiling.
        process.terminate()
        process.wait(timeout=5)
        raise


def finish_capture(config, events, deadline):
    """Join exact measured IDs, tokenize each distinct prompt once, then flush capture."""
    prompt_path = Path(config.decision_prompt_export_path)
    decisions_path = Path(config.decision_export_output_path)
    prompts = DiskList(jsonl_rows(prompt_path))
    index = DiskList()
    index.db.execute("create table ids(id text primary key, seen integer default 0)")
    index.db.executemany(
        "insert into ids(id) values (?)", ((row["request_id"],) for row in prompts)
    )
    wait_deadline = min(deadline, time.perf_counter() + 3)
    scoped = None
    while time.perf_counter() < wait_deadline:
        if scoped is not None:
            scoped.close()
        scoped = DiskList()
        index.db.execute("update ids set seen=0")
        for row in jsonl_rows(config.gateway_config_log):
            if row.get("msg") != "request terminal":
                continue
            updated = index.db.execute(
                "update ids set seen=seen+1 where id=?", (row.get("request_id"),)
            )
            if updated.rowcount:
                scoped.append(row)
        unmatched = index.db.execute("select count(*) from ids where seen<>1").fetchone()[0]
        if not unmatched:
            break
        remaining = wait_deadline - time.perf_counter()
        if remaining <= 0:
            break
        time.sleep(min(remaining, 0.02))
    if scoped is None or index.db.execute("select count(*) from ids where seen<>1").fetchone()[0]:
        raise RuntimeError(
            "decision export has unmatched measured request IDs after terminal flush"
        )
    index.close()
    exported = export_decisions(scoped, prompts, config.tokenize_url, deadline=deadline)
    prompts.close()
    scoped.close()
    if not exported:
        raise RuntimeError("decision export is empty")
    with decisions_path.open("w", encoding="utf-8", newline="\n") as stream:
        stream.writelines(json.dumps(row) + "\n" for row in exported)
    if events is None:
        # Decisions, stop file, metadata and growing streams share the private host mount.
        # No whole-file Docker copies in either checkpoints or final capture export.
        docker(config, ["exec", "inf011-vllm", "touch", config.kv_capture_stop_file], deadline)
        while True:
            if Path(config.kv_capture_output_path).exists():
                artifact = json.loads(
                    Path(config.kv_capture_output_path).read_text(encoding="utf-8")
                )
                artifact["event_observations"] = DiskList(
                    jsonl_rows(
                        Path(config.kv_capture_output_path).with_suffix(".observations.jsonl")
                    )
                )
                artifact["routing_to_event_observation"] = DiskList(
                    jsonl_rows(
                        Path(config.kv_capture_output_path).with_suffix(".correlations.jsonl")
                    )
                )
                return {
                    "joined_decision_count": len(exported),
                    "capture": artifact,
                    "routing_to_event_observation": artifact["routing_to_event_observation"],
                    **summarize_routing_correlations(artifact["routing_to_event_observation"]),
                }
            time.sleep(remaining_seconds(deadline, 0.1))
    wall_ns, perf_ns = time.time_ns(), time.perf_counter_ns()
    projected = load_routing_decisions(
        decisions_path, wall_to_monotonic_offset_ns=wall_ns - perf_ns
    )
    correlations = correlate_routing_events(projected, events)
    return {
        "joined_decision_count": len(exported),
        "routing_to_event_observation": correlations,
        "clock_pair": {"unix_ns": wall_ns, "monotonic_ns": perf_ns},
        **summarize_routing_correlations(correlations),
        "basis": "real gateway decisions; same-host fake publisher/perf_counter rehearsal; "
        + CORRELATION_BASIS,
    }
