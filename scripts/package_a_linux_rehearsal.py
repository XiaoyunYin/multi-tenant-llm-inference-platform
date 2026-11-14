"""Small Linux host stand-in: real binaries, literal sh, source import and preflight.

No Docker socket, AWS credentials or paid API. Full six-check execution remains
the future DEC-077 cloud task. This rehearsal never runs the large sizing job.
"""

import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import sys
import tarfile
import time
from pathlib import Path

sys.path.insert(0, "/repo/python/src")
sys.path.insert(0, "/repo/scripts")
from inference_platform.package_a_cloud import (  # noqa: E402
    TASK_CHECKS,
    Runner,
    memory_sample,
    run_exe,
    save,
)
from inference_platform.package_a_operator import (
    bootstrap_shell,
    readiness_shell,
    render_user_data,
)  # noqa: E402
from package_a_host import Host  # noqa: E402


def constrained_host_record(sampled):
    required = 2304 * 1024**2
    available = sampled["host"]["MemAvailable"]
    return {
        "memory_limit_bytes": 256 * 1024**2,
        "memory_swap_total_bytes": 256 * 1024**2,
        "docker_cpus": 2,
        "docker_pids": 128,
        "available_sampled_at_utc": sampled["sampled_at_utc"],
        "available_before_run_bytes": available,
        "host_total_ram_bytes": sampled["host"]["MemTotal"],
        "docker_vm_mem_total_bytes": sampled["vm"]["MemTotal"],
        "host_gate_required_bytes": required,
        "host_gate_status": "passed" if available >= required else "host_gate_failed",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("/out"))
    args = parser.parse_args()
    output = args.output
    output.mkdir(exist_ok=True)
    tools = Path("/tmp/dec077-tools")
    tools.mkdir(exist_ok=True)
    pins = json.loads(Path("/repo/deploy/package-a/pins.json").read_bytes())
    for name in ("python", "uv", "go", "docker"):
        with tarfile.open("/artifacts/" + name) as archive:
            archive.extractall(tools, filter="data")
    python = tools / "python/bin/python3.12"
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    env["PATH"] = str(tools / "docker") + os.pathsep + env["PATH"]
    versions = {}
    for name, argv in {
        "python": [python, "--version"],
        "uv": [tools / "uv-x86_64-unknown-linux-gnu/uv", "--version"],
        "go": [tools / "go/bin/go", "version"],
        "docker": [tools / "docker/docker", "--version"],
        "dockerd": [tools / "docker/dockerd", "--version"],
        "containerd": [tools / "docker/containerd", "--version"],
        "runc": [tools / "docker/runc", "--version"],
        "kind": ["/artifacts/kind", "version"],
        "kubectl": ["/artifacts/kubectl", "version", "--client=true"],
        "buildx": ["/artifacts/buildx", "version"],
        "git": ["git", "--version"],
        "curl": ["curl", "--version"],
        "sh": ["sh", "-c", "printf 'real sh\\n'"],
    }.items():
        # Mounted downloaded executables have Windows permissions; stage copies
        # in the container before chmod rather than changing read-only artifacts.
        if str(argv[0]).startswith("/artifacts/"):
            copy = tools / name
            shutil.copyfile(argv[0], copy)
            copy.chmod(0o755)
            argv[0] = copy
        versions[name] = run_exe(
            argv, cwd=output, output=output / (name + ".log"), timeout=30, env=env
        )
    bundle = Path("/bundle/source.bundle")
    head = Path("/bundle/head.txt").read_text().strip()
    manifest = {
        "checks": list(TASK_CHECKS),
        "source_commit": head,
        "bundle_bytes": bundle.stat().st_size,
        "bundle_sha256": hashlib.sha256(bundle.read_bytes()).hexdigest(),
        "python_sha256": json.loads(Path("/bundle/python-hashes.json").read_bytes()),
        "python_executable": str(python),
        "pins": pins,
        "instance_type": "rehearsal-container-not-EC2",
        "ami": "not-applicable",
        "on_demand_usd_per_hour": 0,
        "deadline_epoch": time.time() + 20000,
    }
    wire = json.dumps(manifest).encode()
    host = Host(
        output / "host",
        "test-token",
        hashlib.sha256(wire).hexdigest(),
        time.time() + 120,
    )
    host.dispatch("/manifest", wire, {})
    shutil.copyfile(bundle, host.partial)
    staged = host.dispatch("/stage", b"", {})
    # Run the literal generated SSM command strings in real sh. Only the fixed
    # /opt bootstrap location and system python PATH are fixture-bound here.
    Path("/opt/dec077").mkdir(parents=True, exist_ok=True)
    Path("/opt/dec077/user-data.done").touch()
    bin_path = Path("/tmp/dec077-bin")
    bin_path.mkdir(exist_ok=True)
    (bin_path / "python3").symlink_to(python)
    shell_env = {**env, "PATH": str(bin_path) + os.pathsep + env["PATH"]}
    # Run user data literally, with only IMDS and system services shimmed.
    # A failing arm must execute shutdown; it cannot fall through to work.
    (bin_path / "curl").write_text(
        '#!/bin/sh\ncase "$*" in\n*instance-identity*) printf \'{"pendingTime":"2026-10-19T16:00:00Z"}\';;\n*latest/api/token*) printf fixture;;\n*) exec /usr/bin/curl "$@";;\nesac\n'
    )
    (bin_path / "systemctl").write_text(
        '#!/bin/sh\ntest "${DEC077_FAIL_TIMER:-0}" = 0\n'
    )
    (bin_path / "cloud-init").write_text(
        '#!/bin/sh\nprintf "cloud-init fixture ready\\n"\n'
    )
    (bin_path / "shutdown").write_text(
        '#!/bin/sh\nprintf "shutdown called\\n" >> /out/shutdown.log\n'
    )
    for name in ("curl", "systemctl", "shutdown", "cloud-init"):
        (bin_path / name).chmod(0o755)
    user_data = output / "rendered-user-data.sh"
    user_data.write_text(render_user_data())
    run_exe(
        ["sh", user_data],
        cwd=output,
        output=output / "user-data.log",
        timeout=30,
        env=shell_env,
    )
    run_exe(
        ["sh", user_data],
        cwd=output,
        output=output / "user-data-failed-arm.log",
        timeout=30,
        env={**shell_env, "DEC077_FAIL_TIMER": "1"},
        expected="refuse",
    )
    if not (output / "shutdown.log").exists():
        raise AssertionError("failed_arm_did_not_shutdown")
    run_exe(
        ["sh", "-c", "\n".join(readiness_shell())],
        cwd=output,
        output=output / "ssm-readiness-shell.log",
        timeout=30,
        env=shell_env,
    )
    shell = "\n".join(
        bootstrap_shell(
            Path("/repo/scripts/package_a_host.py").read_bytes(),
            "shell-token",
            hashlib.sha256(wire).hexdigest(),
            time.time() + 30,
        )
    )
    run_exe(
        ["sh", "-c", shell],
        cwd=output,
        output=output / "ssm-shell.log",
        timeout=30,
        env=shell_env,
    )
    # Verify real cgroup files and source-bound lightweight sizing preflight.
    env["PYTHONPATH"] = str(host.repo / "python/src")
    runner = Runner(host.repo, output / "runner", manifest, execute=run_exe)
    runner.env = {**env, "PYTHONDONTWRITEBYTECODE": "1"}
    runner.prepare_images = lambda: None  # no daemon/socket in this stand-in
    samples = iter(
        [memory_sample()] * 3
        + [
            {
                **memory_sample(),
                "host": {"MemAvailable": 0, "MemTotal": 32 * 1024**3},
                "vm": {"MemAvailable": 0, "MemTotal": 32 * 1024**3},
            }
        ]
        * 20
    )
    runner.sample = lambda: next(samples)
    invoked = []

    def preflight_only(name):
        invoked.append(name)
        return runner.call(
            [python, "scripts/size_inf037b_sanitized_export.py", "--preflight-only"],
            "native-preflight",
        )

    runner.check = preflight_only
    # The lightweight command is also exercised when the stand-in VM's actual
    # available memory cannot admit the full native sizing job.
    runner.call(
        [python, "scripts/size_inf037b_sanitized_export.py", "--preflight-only"],
        "native-light-preflight",
    )
    runner.call(
        [
            python,
            "scripts/size_inf037b_sanitized_export.py",
            "--write-source-manifest",
            output / "smoke-source.json",
        ],
        "real-host-manifest",
    )
    spec = importlib.util.spec_from_file_location(
        "sizing_fixture", host.repo / "scripts/size_inf037b_sanitized_export.py"
    )
    sizing = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sizing)
    smoke = json.loads((output / "smoke-source.json").read_bytes())
    sampled = memory_sample()
    smoke["constrained_host"] = constrained_host_record(sampled)
    save(output / "smoke-source.json", sizing.seal_manifest(smoke))
    runner.call(
        [
            python,
            "scripts/size_inf037b_sanitized_export.py",
            "--container-mode",
            "--source-manifest",
            output / "smoke-source.json",
            "--preflight-only",
        ],
        "real-cgroup-matching",
    )
    runner.run()
    checks = runner.receipt["checks"]
    if [row["name"] for row in checks] != list(TASK_CHECKS):
        raise AssertionError("rehearsal_check_tuple_changed")
    if invoked != [TASK_CHECKS[0]] or checks[0]["status"] != "PASS":
        raise AssertionError("rehearsal_must_execute_exactly_one_lightweight_preflight")
    runner.receipt["checks"][0]["status"] = "REHEARSAL_PREFLIGHT_ONLY"
    runner.receipt["rehearsal_only"] = True
    save(output / "runner/runner.json", runner.receipt)
    if [row["status"] for row in runner.receipt["checks"]][1:] != ["SKIPPED_GATE"] * (
        len(TASK_CHECKS) - 1
    ):
        raise AssertionError("rehearsal_must_not_run_heavy_commands")
    save(
        output / "linux-rehearsal.json",
        {
            "real_executables": versions,
            "source_import": staged,
            "ssm_shell_executed": True,
            "user_data_real_sh": True,
            "failed_timer_arm_shutdown": True,
            "fixture_services": ["IMDS curl", "systemctl", "shutdown"],
            "runner_checks": runner.receipt["checks"],
            "network": "none",
            "limits": {
                "memory": "256m",
                "memory_plus_swap": "256m",
                "cpus": 2,
                "pids": 128,
            },
            "limits_of_evidence": "Lightweight preflight only for the current task tuple; remaining checks have injected gate refusals; no task-suite or sizing result",
        },
    )


if __name__ == "__main__":
    main()
