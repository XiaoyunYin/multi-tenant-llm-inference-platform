"""Dedicated CPU-host cgroup case; target and emitter have separate cgroups."""

import argparse
import json
import subprocess
import time
import tempfile
from pathlib import Path


def commands(image, repo, name, relative, spool_root):
    target, emitter = name + "-target", name + "-emitter"
    return (
        [
            "docker",
            "run",
            "-d",
            "--rm",
            "--name",
            target,
            "--cpus",
            "1",
            "--network",
            "none",
            "--mount",
            f"type=bind,source={repo},target=/repo,readonly",
            "--mount",
            f"type=bind,source={spool_root},target=/native-spools",
            "-e",
            "PYTHONPATH=/repo/python/src",
            "-e",
            "PYTHONDONTWRITEBYTECODE=1",
            image,
            "python",
            "-c",
            "import time; time.sleep(150)",
        ],
        [
            "docker",
            "run",
            "--rm",
            "--name",
            emitter,
            "--cpus",
            "1",
            "--network",
            "host",
            "--cgroupns=host",
            "--mount",
            f"type=bind,source={spool_root},target=/native-spools,readonly",
            "-e",
            "INF037B_NATIVE_READONLY_ROOT=/native-spools",
            "--mount",
            f"type=bind,source={repo},target=/repo,readonly",
            "-e",
            "PYTHONDONTWRITEBYTECODE=1",
            "-e",
            "PYTHONPATH=/repo/python/src:/repo/python/tests:/repo/scripts",
            "-e",
            "INF037B_EKS_HOST_TEST=1",
            "-e",
            "INF037B_RESOURCE_CGROUP_CASE=1",
            "-e",
            "INF037B_RESOURCE_TARGET_CGROUP=" + relative,
            "-w",
            "/repo",
            image,
            "python",
            "scripts/run_package_a_cpu_cases.py",
            "--phase",
            "cgroup",
        ],
    )


def run(image, repo, name, *, state_root, execute=subprocess.run, proc=Path("/proc")):
    state_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="native-ro-", dir=state_root) as spool:
        return run_stage(image, repo, name, Path(spool), execute=execute, proc=proc)


def run_stage(image, repo, name, spool_root, *, execute, proc):
    started = time.monotonic()
    receipt = {
        "schema": "resource-cgroup-stage-v1",
        "commands": [],
        "complete": False,
        "status": "FAILED",
    }

    def call(argv, deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("resource_cgroup_stage:deadline")
        result = execute(argv, capture_output=True, timeout=min(remaining, 60))
        receipt["commands"].append(
            {"argv": list(map(str, argv)), "exit": result.returncode}
        )
        return result

    try:
        target, _ = commands(image, repo, name, "/not-yet-observed", spool_root)
        call(target, started + 70).check_returncode()
        call(
            [
                "docker",
                "exec",
                name + "-target",
                "python",
                "/repo/scripts/native_readonly_fixture.py",
                "--root",
                "/native-spools",
            ],
            started + 70,
        ).check_returncode()
        result = call(
            ["docker", "inspect", "--format", "{{.State.Pid}}", name + "-target"],
            started + 70,
        )
        result.check_returncode()
        pid = int(result.stdout.strip())
        if pid <= 0:
            raise ValueError("resource_cgroup_stage:target_pid")
        text = (proc / str(pid) / "cgroup").read_text().strip()
        if not text.startswith("0::/") or ".." in Path(text[3:]).parts:
            raise ValueError("resource_cgroup_stage:target_cgroup")
        relative = text[3:]
        receipt["target_cgroup"] = relative
        _, emitter = commands(image, repo, name, relative, spool_root)
        result = call(emitter, started + 70)
        print(result.stdout.decode("utf-8", errors="replace"), end="", flush=True)
        print(result.stderr.decode("utf-8", errors="replace"), end="", flush=True)
        result.check_returncode()
        receipt["status"] = "PASS"
    finally:
        call(["docker", "rm", "-f", name + "-emitter", name + "-target"], started + 100)
        result = call(
            ["docker", "ps", "-aq", "--filter", "name=" + name], started + 100
        )
        result.check_returncode()
        if result.stdout.strip():
            raise ValueError("resource_cgroup_stage:cleanup_unverified")
        receipt["cleanup_complete"] = True
        receipt["complete"] = receipt["status"] == "PASS"
        receipt["elapsed_s"] = time.monotonic() - started
        print(json.dumps({"resource_cgroup_stage": receipt}), flush=True)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    args = parser.parse_args()
    run(args.image, args.repo, args.name, state_root=args.state_root)


if __name__ == "__main__":
    main()
