"""Offline trace of Stage C prerequisites to rendered launch or staged providers."""

from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


def capture_layout_fitness(root: Path) -> tuple[bool, str]:
    """Rehearse mkdir/cp semantics and import at the exact probe/capture PYTHONPATH."""
    package = root / "python/src/inference_platform"
    try:
        spec = importlib.util.spec_from_file_location(
            "capture_layout", package / "stage_c_container.py"
        )
        layout = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(layout)
        for path, function in (
            ("stage_c_session.py", "stage_capture_package"),
            ("stage_c.py", "publisher_probe_argv"),
            ("stage_c_capture.py", "capture_argv"),
        ):
            tree = ast.parse((package / path).read_text(encoding="utf-8"))
            if not any(
                isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == function
                for n in ast.walk(tree)
            ):
                raise ValueError(f"{path} does not call shared {function}")
        with tempfile.TemporaryDirectory() as directory:
            container = Path(directory)

            def mapped(path):
                target = container / path.replace("\\", "/").lstrip("/")
                if not target.resolve().is_relative_to(container.resolve()):
                    raise ValueError("container simulation path escapes its temporary root")
                return target

            def stage(argv, **kwargs):
                if argv[1] == "exec":
                    for path in argv[5:]:
                        mapped(path).mkdir(parents=True, exist_ok=True)
                elif argv[1] == "cp":
                    destination = mapped(argv[3].split(":", 1)[1])
                    if not destination.is_dir():
                        raise ValueError("docker cp destination directory does not exist")
                    shutil.copytree(argv[2], destination / Path(argv[2]).name)
                else:
                    raise ValueError("unexpected staging operation")

            layout.stage_capture_package(root, "/tmp/private", run=stage)
            probe = layout.publisher_probe_argv("tcp://127.0.0.1:5557", "kv-events", "test", 1)
            capture = layout.capture_argv()
            if probe[: len(capture)] != capture or "--readiness-probe" not in probe:
                raise ValueError("probe and capture module argv differ")
            search = probe[probe.index("--env") + 1].removeprefix("PYTHONPATH=")
            staged_root = mapped(search)
            code = (
                "import pathlib,inference_platform.kv_event_capture as m; "
                f"assert pathlib.Path(m.__file__).is_relative_to(pathlib.Path({str(staged_root)!r}))"
            )
            result = subprocess.run(
                [sys.executable, "-c", code],
                cwd=container,
                env={**os.environ, "PYTHONPATH": str(staged_root), "PYTHONDONTWRITEBYTECODE": "1"},
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if result.returncode:
                raise ValueError(f"staged import failed ({result.returncode}): {result.stderr}")
        return True, f"mkdir/cp package import succeeds at probe/capture PYTHONPATH={search}"
    except (OSError, ValueError, AttributeError, SyntaxError, subprocess.SubprocessError) as error:
        return False, str(error)


def vllm_publisher_binds(endpoint: str) -> bool:
    """Mirror v0.29.0 ZmqEventPublisher._socket_setup's bind/connect predicate."""
    return "*" in endpoint or "::" in endpoint or endpoint.startswith(("ipc://", "inproc://"))


def capture_uses_connect(source: str) -> bool:
    """Verify the actual capture function connects its subscriber and never binds it."""
    module = ast.parse(source)
    capture = next(
        node
        for node in module.body
        if isinstance(node, ast.FunctionDef) and node.name == "capture_zmq_event_stream"
    )
    operations = {
        node.func.attr
        for node in ast.walk(capture)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "subscriber"
    }
    return "connect" in operations and "bind" not in operations


def verify_staged_directory(payload: Path, manifest: dict, root: Path) -> None:
    """Check the whole prepared payload, including extra files beside sources/."""
    from .stage_c_session import BUNDLE, git, sha, verify_bundle, verify_sources

    if not (payload / "sources").is_dir():
        verify_sources(payload, manifest, root)
        return
    verify_sources(payload / "sources", manifest, root)
    expected_manifest = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if (payload / "staging-manifest.json").read_bytes() != expected_manifest:
        raise ValueError("staged manifest bytes differ from reviewed manifest")
    allowed = {"staging-manifest.json", manifest["gateway_artifact"]["path"]} | {
        "sources/" + row["path"] for row in manifest["files"]
    }
    if (payload / BUNDLE).exists():
        verify_bundle(
            (payload / BUNDLE).read_bytes(), manifest, sha(payload / "staging-manifest.json")
        )
        allowed.add(BUNDLE)
    # The preparation workspace retains its clean, committed build snapshot. It is
    # not uploaded: install_bundle allows only manifest, source payload and binary.
    for path in (
        git(root, "ls-tree", "-r", "--name-only", manifest["source_commit"]).decode().splitlines()
    ):
        if path.startswith(("cmd/", "internal/")) or path in ("go.mod", "go.sum"):
            target = payload / "build-source" / path
            if target.exists():
                allowed.add("build-source/" + path)
                if target.read_bytes() != git(root, "show", f"{manifest['source_commit']}:{path}"):
                    raise ValueError(f"build source is not a committed Git blob: {path}")
    actual = {path.relative_to(payload).as_posix() for path in payload.rglob("*") if path.is_file()}
    if actual != allowed:
        raise ValueError(
            f"untracked staged payload files: {sorted(actual - allowed)}; missing: {sorted(allowed - actual)}"
        )
    if (
        sha(payload / manifest["gateway_artifact"]["path"])
        != manifest["gateway_artifact"]["sha256"]
    ):
        raise ValueError("staged gateway artifact hash mismatch")


def check_fitness(
    launcher: str, inputs: dict[str, Any], root: Path, payload: Path | None = None
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []

    def trace(name: str, provided: bool, provider: str, runtime_check: str) -> None:
        records.append(
            dict(
                prerequisite=name, provided=provided, provider=provider, runtime_check=runtime_check
            )
        )

    def line(fragment: str) -> str:
        return next(
            (
                f"user-data:{i}: {s.strip()}"
                for i, s in enumerate(launcher.splitlines(), 1)
                if fragment in s
            ),
            "UNPROVIDED",
        )

    digest = inputs["runtime_image_linux_amd64_digest"]
    pinned = digest in launcher
    for name, fragment, endpoint in (
        ("vllm_health", "127.0.0.1:8000:8000", "http://127.0.0.1:8000/health"),
        ("tokenize", "--model Qwen/Qwen2.5-7B-Instruct", "http://127.0.0.1:8000/tokenize"),
        ("vllm_metrics", "--port 8000", "http://127.0.0.1:8000/metrics"),
        (
            "cache_reset",
            "--env VLLM_SERVER_DEV_MODE=1",
            "POST http://127.0.0.1:8000/reset_prefix_cache; success=true",
        ),
        ("dcgm_metrics", "127.0.0.1:9400:9400", "http://127.0.0.1:9400/metrics"),
        (
            "termination_deadline",
            "NextElapseUSecRealtime",
            "persisted /etc/inf011/deadline_epoch and timer next elapse",
        ),
    ):
        trace(name, pinned and fragment in launcher, line(fragment), endpoint)
    match = re.search(r"--kv-events-config\s+'([^']+)'", launcher)
    try:
        publisher = json.loads(match[1]) if match else {}
    except json.JSONDecodeError:
        publisher = {}
    expected = inputs.get("kv_events", {})
    capture_source = root / "python/src/inference_platform/kv_event_capture.py"
    capture_endpoint = expected.get("capture_endpoint", "")
    # The reviewed protocol uses wildcard TCP bind within the container and loopback connect.
    paired_endpoints = (
        publisher.get("endpoint") == "tcp://*:5557" and capture_endpoint == "tcp://127.0.0.1:5557"
    )
    trace(
        "kv_publisher",
        pinned
        and publisher
        == {
            "enable_kv_cache_events": True,
            "publisher": "zmq",
            "endpoint": expected.get("endpoint"),
            "topic": expected.get("topic"),
        }
        and vllm_publisher_binds(publisher.get("endpoint", ""))
        and paired_endpoints
        and expected.get("publisher_operation") == "bind"
        and expected.get("capture_operation") == "connect"
        and capture_source.exists()
        and capture_uses_connect(capture_source.read_text(encoding="utf-8"))
        and "5557:5557" not in launcher,
        line("--kv-events-config") + f"; publisher=bind, capture=connect {capture_endpoint}",
        "container connecting subscriber receives decoded BlockStored from binding PUB after unique probe",
    )
    providers = {
        "python_version": ("python/src/inference_platform/stage_c.py", "StageCConfig"),
        "clock": ("python/src/inference_platform/clocks.py", "get_clock_info"),
        "reviewed_source_imports": (
            "python/src/inference_platform/stage_c.py",
            "measurement_clocks",
        ),
        "capture_dependencies": (
            "python/src/inference_platform/stage_c_container.py",
            "shared package staging",
        ),
        "gateway_health": ("internal/gateway/handler.go", '"/healthz"'),
        "gateway_metrics": ("internal/gateway/handler.go", '"/metrics"'),
        "gateway_admission": ("cmd/gateway/main.go", '"admission_configuration"'),
        "gateway_first_item_timeout": ("cmd/gateway/main.go", '"first_item_timeout_seconds"'),
        "r0_v2_protocol": ("python/src/inference_platform/stage_c.py", '"protocol_sizing"'),
        "decision_capture_pipeline": (
            "python/src/inference_platform/stage_c_capture.py",
            "export_decisions",
        ),
        "regime_signals": ("python/src/inference_platform/calibration.py", "derive_runtime_regime"),
    }
    staging = inputs.get("staging_readiness_providers", {})
    for name, (path, symbol) in providers.items():
        source = root / path
        command = staging.get(name, "")
        if name == "capture_dependencies":
            provided, reason = capture_layout_fitness(root)
            trace(name, bool(command) and provided, reason, command)
            continue
        trace(
            name,
            bool(command) and source.exists() and symbol in source.read_text(encoding="utf-8"),
            f"SSM staged {path}: {symbol}; {command}",
            command,
        )
    configuration = root / inputs.get("gateway_launcher_config_path", "UNPROVIDED")
    environment = (
        json.loads(configuration.read_text(encoding="utf-8")) if configuration.is_file() else {}
    )
    protocol = inputs.get("protocol", {})
    sizing = inputs.get("workload_sizing", {})
    example = json.loads(
        (root / "experiments/examples/stage-c-config.json").read_text(encoding="utf-8")
    )
    from .stage_c_tokenizer import FILE_HASHES, MODEL, REVISION, prompt_path_fitness

    tokenizer_evidence = None
    try:
        if (inputs.get("model"), inputs.get("model_revision")) != (MODEL, REVISION):
            raise ValueError("session model/revision differs from tokenizer pins")
        if inputs.get("tokenizer_file_sha256") != FILE_HASHES:
            raise ValueError("session tokenizer hash pins missing or different")
        tokenizer_evidence = prompt_path_fitness(
            {
                **example,
                "max_num_seqs": sizing["max_num_seqs"],
                "rewarm_samples": example.get("rewarm_samples", 8),
                "rewarm_repeats": example.get("rewarm_repeats", 3),
            },
            fetch=True,
        )
        tokenizer_reason = (
            "real hash-pinned files; complete offline r0-v2 prompt path PASS; probe=34"
        )
    except (ImportError, OSError, ValueError, RuntimeError, KeyError) as error:
        tokenizer_reason = str(error)
    trace(
        "real_chat_prompt_fitness",
        tokenizer_evidence is not None,
        tokenizer_reason,
        "before PlanPaid: every bank/corpus and bounded sustained identity; Run 4 repeat; rewarm",
    )
    records[-1]["evidence"] = tokenizer_evidence
    from .stage_c_sizing import check_sizing

    predicates = {
        "gateway_first_item_timeout": environment == inputs.get("gateway_launcher_environment")
        and environment == inputs.get("admission", {}).get("environment")
        and environment.get("GATEWAY_FIRST_ITEM_TIMEOUT") == "120s"
        and environment.get("GATEWAY_TOTAL_TIMEOUT") == "180s"
        and environment.get("ADMISSION_LEASE") == "240s",
        "r0_v2_protocol": protocol.get("version") == "r0-v2"
        and protocol.get("seconds_per_level") == 90
        and protocol.get("reference_max_tokens") == 1
        and sizing.get("saturation_prompt_tokens") == 6144
        and sizing.get("reference_max_tokens") == 1
        and example.get("protocol_version") == "r0-v2"
        and example.get("local_rehearsal") is False
        and example.get("sustained_level_seconds") == 90
        and example.get("saturation_prompt_tokens") == sizing.get("saturation_prompt_tokens")
        and example.get("saturation_levels") == sizing.get("saturation_levels")
        and example.get("reference_prompt_tokens") == sizing.get("reference_prompt_tokens")
        and example.get("reference_prefix_counts") == sizing.get("reference_prefix_counts")
        and example.get("reference_max_tokens") == 1
        and example.get("run_time_budgets_seconds") == inputs.get("run_time_budgets_seconds")
        and check_sizing(sizing, launcher=launcher, tokenization=tokenizer_evidence)["status"]
        == "pass",
        "decision_capture_pipeline": all(
            symbol
            in (root / "python/src/inference_platform/stage_c.py").read_text(encoding="utf-8")
            for symbol in (
                "start_live_capture(config",
                "finish_capture(config",
                '"raw_prompt_token_inputs_removed"',
            )
        ),
        "regime_signals": protocol.get("regime_signals")
        == ["vllm:num_preemptions_total", "vllm:num_requests_running", "vllm:num_requests_waiting"],
    }
    for record in records:
        if record["prerequisite"] in predicates:
            record["provided"] = bool(record["provided"] and predicates[record["prerequisite"]])
    from .stage_c_session import ENTRYPOINT, git, sha, source_paths

    staging = inputs.get("staging", {})
    manifest_file = root / staging.get("manifest_path", "UNPROVIDED")
    verified = False
    reason = "staging manifest/hash/entrypoint not provided"
    try:
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        if sha(manifest_file) != staging["manifest_sha256"]:
            raise ValueError("staging manifest hash differs from session inputs")
        if (
            manifest["entrypoint"]["path"] != ENTRYPOINT
            or manifest["entrypoint"]["sha256"] != staging["entrypoint_sha256"]
        ):
            raise ValueError("entrypoint pin differs from staging manifest")
        current = {
            path: hashlib.sha256(git(root, "show", "HEAD:" + path)).hexdigest()
            for path in source_paths(root, "HEAD")
        }
        if current != {row["path"]: row["sha256"] for row in manifest["files"]}:
            raise ValueError("staged source differs from current committed source")
        if payload is not None:
            verify_staged_directory(payload, manifest, root)
        verified = True
        reason = "verified committed Git sources and exact entrypoint pin"
    except (OSError, KeyError, ValueError) as error:
        reason = str(error)
    trace(
        "reviewed_session_entrypoint",
        verified and environment.get("BACKENDS") == "vllm0=http://127.0.0.1:8000",
        f"{manifest_file}: {reason}",
        "operator invokes only stage_c_session; real gateway --check-config before launch",
    )
    trace(
        "staged_payload_git_provenance",
        verified,
        f"{manifest_file}: {reason}",
        "verify every staged source against committed Git blobs, reject extra helpers; compiled gateway is separately attested",
    )
    trace(
        "bounded_readiness_and_owned_cleanup",
        verified
        and all(
            symbol in (root / ENTRYPOINT).read_text(encoding="utf-8")
            for symbol in ("wait_readiness(", "stop_child(child)", "export(session, manifest_path)")
        ),
        ENTRYPOINT,
        "persisted deadline minus all useful runs/export; per-attempt process health; reaped sampler; immediate export",
    )
    return records


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rendered-json", type=Path, required=True)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--payload-root", type=Path, help="actual staged source directory; extra files fail"
    )
    args = parser.parse_args()
    # Terraform console quotes the JSON string returned by jsonencode(templatefile(...)).
    records = check_fitness(
        json.loads(json.loads(args.rendered_json.read_text(encoding="utf-8"))),
        json.loads(args.inputs.read_text(encoding="utf-8")),
        args.root,
        args.payload_root,
    )
    for record in records:
        print(
            f"{record['prerequisite']}: {'PROVIDED' if record['provided'] else 'UNPROVIDED'} | "
            f"{record['provider']} | runtime: {record['runtime_check']}"
        )
    if args.output:
        args.output.write_text(
            json.dumps({"prerequisites": records}, indent=2) + "\n", encoding="utf-8", newline="\n"
        )
    return int(not all(record["provided"] for record in records))


if __name__ == "__main__":
    raise SystemExit(main())
