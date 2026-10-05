"""One package layout and module command for container staging, probe and capture."""

import subprocess
from pathlib import Path

PACKAGE_ROOT = "/opt/inf011/python/src"
CONTAINER = "inf011-vllm"


def capture_argv(container: str = CONTAINER) -> list[str]:
    return [
        "docker",
        "exec",
        "--env",
        f"PYTHONPATH={PACKAGE_ROOT}",
        "--env",
        "PYTHONDONTWRITEBYTECODE=1",
        container,
        "python3",
        "-B",
        "-m",
        "inference_platform.kv_event_capture",
    ]


def publisher_probe_argv(endpoint, topic, model, duration, *, container=CONTAINER):
    return capture_argv(container) + [
        "--readiness-probe",
        "--endpoint",
        endpoint,
        "--topic",
        topic,
        "--model",
        model,
        "--duration-seconds",
        str(duration),
    ]


def stage_capture_package(
    sources: Path, private: Path, *, container=CONTAINER, run=None, timeout=30
) -> None:
    run = run or subprocess.run
    run(
        ["docker", "exec", container, "mkdir", "-p", PACKAGE_ROOT, str(private)],
        check=True,
        timeout=min(10, timeout),
    )
    run(
        [
            "docker",
            "cp",
            str(sources / "python/src/inference_platform"),
            f"{container}:{PACKAGE_ROOT}/",
        ],
        check=True,
        timeout=timeout,
    )
