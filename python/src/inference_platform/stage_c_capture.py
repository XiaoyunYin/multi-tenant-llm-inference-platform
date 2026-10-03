"""Bounded same-host capture startup and post-run decision join; no AWS actions."""

import json
import os
import subprocess
import time
from pathlib import Path

from .decision_export import export_decisions
from .kv_event_capture import (
    CORRELATION_BASIS,
    correlate_routing_events,
    load_routing_decisions,
    summarize_routing_correlations,
)
from .stage_c_container import capture_argv
from .time_budget import remaining_seconds


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
    ready_path = config.kv_capture_output_path + ".ready"
    # A prior receipt or stop file could falsely admit a dead subscriber. Require fresh
    # session paths in the container as well as the recorder's restricted host files.
    docker(
        config,
        [
            "exec",
            "inf011-vllm",
            "python3",
            "-c",
            "import os,sys; sys.exit(any(os.path.exists(p) for p in sys.argv[1:]))",
            ready_path,
            config.kv_capture_stop_file,
            config.kv_capture_output_path,
            config.decision_export_output_path,
        ],
        deadline,
    )
    argv = capture_argv() + [
        "--endpoint",
        config.kv_event_endpoint,
        "--topic",
        config.kv_event_topic,
        "--duration-seconds",
        # Keep capture alive during the join/export half of the reserved margin;
        # it must load the decision input after the final measured request.
        str(remaining_seconds(deadline + config.evidence_export_margin_seconds - 300, 14400)),
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
    prompts = [json.loads(line) for line in prompt_path.read_text(encoding="utf-8").splitlines()]
    ids = {row["request_id"] for row in prompts}
    terminals = []
    scoped = []
    # The gateway writes terminal rows on request ownership release; allow bounded flush.
    wait_deadline = min(deadline, time.perf_counter() + 3)
    while time.perf_counter() < wait_deadline:
        terminals = [
            json.loads(line)
            for line in Path(config.gateway_config_log).read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        scoped = [
            row
            for row in terminals
            if row.get("request_id") in ids and row.get("msg") == "request terminal"
        ]
        if {row["request_id"] for row in scoped} == ids:
            break
        remaining = wait_deadline - time.perf_counter()
        if remaining <= 0:
            break
        time.sleep(min(remaining, 0.02))
    if {row["request_id"] for row in scoped} != ids:
        raise RuntimeError(
            "decision export has unmatched measured request IDs after terminal flush"
        )
    terminals = [row for row in terminals if row.get("request_id") in ids]
    exported = export_decisions(terminals, prompts, config.tokenize_url, deadline=deadline)
    if not exported:
        raise RuntimeError("decision export is empty")
    with decisions_path.open("w", encoding="utf-8", newline="\n") as stream:
        stream.writelines(json.dumps(row) + "\n" for row in exported)
    if events is None:
        docker(config, ["cp", str(decisions_path), "inf011-vllm:" + str(decisions_path)], deadline)
        docker(config, ["exec", "inf011-vllm", "touch", config.kv_capture_stop_file], deadline)
        while True:
            copied = docker(
                config,
                [
                    "cp",
                    "inf011-vllm:" + config.kv_capture_output_path,
                    config.kv_capture_output_path,
                ],
                deadline,
                check=False,
            )
            if copied.returncode == 0:
                artifact = json.loads(
                    Path(config.kv_capture_output_path).read_text(encoding="utf-8")
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
