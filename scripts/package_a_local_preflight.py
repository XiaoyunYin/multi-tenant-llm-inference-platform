"""Run DEC-077's $0 real-dependency Redis, gateway and image-archive preflight."""

import argparse
import hashlib
import http.client
import json
import os
import shutil
import socket
import ssl
import subprocess
import time
import uuid
from pathlib import Path

from check_package_a_kind import check as check_kind_without_cluster

from inference_platform.eks_deployment import (
    NGINX_IMAGE,
    PROMETHEUS_IMAGE,
    PYTHON_IMAGE,
    REDIS_IMAGE,
)
from inference_platform.package_a_cloud import save, utc
from inference_platform.package_a_go import (
    GoTestSummaryError,
    go_test_summary,
)
from inference_platform.package_a_images import (
    KIND_LOCAL_IMAGE_TAGS,
    LINUX_E2E_IMAGE,
    save_amd64_archive,
)
from inference_platform.package_a_workload import (
    preflight_manifest,
    workload_objects,
    write_kind_secret,
    test_tls_command,
)

ROOT = Path(__file__).resolve().parents[1]
PULLED_IMAGES = {
    "redis": REDIS_IMAGE,
    "nginx": NGINX_IMAGE,
    "prometheus": PROMETHEUS_IMAGE,
    "python": PYTHON_IMAGE,
}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run_linux_gateway_e2e(
    output, redis_name, evidence, *, image=LINUX_E2E_IMAGE, locked_site=None
):
    """Use real Linux durability on every operator host, never emulate fsync."""
    gateway = output / "gateway-e2e-linux"
    build, _ = run(
        ["go", "build", "-o", gateway, "./cmd/gateway"],
        output=output / "gateway-e2e-build.log",
        timeout=300,
        env={**os.environ, "GOOS": "linux", "GOARCH": "amd64", "CGO_ENABLED": "0"},
    )
    evidence.update(
        runtime="linux-container",
        python_image=image,
        build={
            **build,
            "binary_path": gateway.name,
            "binary_sha256": digest(gateway),
            "GOOS": "linux",
            "GOARCH": "amd64",
            "CGO_ENABLED": "0",
        },
    )
    name = "dec086-e2e-" + uuid.uuid4().hex[:10]
    argv = [
        "docker",
        "run",
        "--rm",
        "--name",
        name,
        "--network",
        "container:" + redis_name,
        "--memory",
        "1g",
        "--memory-swap",
        "1g",
        "--cpus",
        "2",
        "--pids-limit",
        "128",
        "--mount",
        f"type=bind,source={ROOT},target=/repo,readonly",
        "--mount",
        f"type=bind,source={gateway},target=/gateway,readonly",
        "-e",
        "PYTHONPATH=/repo/python/src:/repo/python/tests",
        "-e",
        "PYTHONDONTWRITEBYTECODE=1",
        "-e",
        "M5_PACKAGE_A_BIN=/tmp/gateway",
        "-e",
        "REDIS_TEST_ADDR=127.0.0.1:6379",
        "-w",
        "/repo",
        image,
        "sh",
        "-c",
        "cp /gateway /tmp/gateway && chmod +x /tmp/gateway && exec /opt/r87-probe-venv/bin/python -m unittest test_inf037b_live.GatewayRedisEndToEnd -v",
    ]
    if locked_site is not None:
        at = argv.index(image)
        argv[at:at] = [
            "--mount",
            f"type=bind,source={locked_site},target=/locked-site,readonly",
            "-e",
            "PYTHONPATH=/repo/python/src:/repo/python/tests:/locked-site",
        ]
    try:
        result, log = run(argv, output=output / "gateway-redis-e2e.log", timeout=180)
        evidence.update(result)
        return log
    finally:
        evidence["cleanup"], _ = run(
            ["docker", "rm", "-f", name],
            output=output / "gateway-e2e-remove.log",
            timeout=30,
            check=False,
        )
        evidence["verify_removed"], remaining = run(
            ["docker", "ps", "-aq", "--filter", "name=^/" + name + "$"],
            output=output / "gateway-e2e-remaining.log",
            timeout=30,
            check=False,
        )
        evidence["container_removed"] = (
            evidence["verify_removed"]["exit_code"] == 0 and not remaining.strip()
        )
        if not evidence["container_removed"]:
            raise ValueError("linux_e2e_cleanup_unverified")


def run(argv, *, output, timeout=180, env=None, check=True, stdin_path=None):
    stdin = Path(stdin_path).open("rb") if stdin_path is not None else None
    try:
        result = subprocess.run(
            [str(part) for part in argv],
            cwd=ROOT,
            env=env,
            stdin=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
    finally:
        if stdin is not None:
            stdin.close()
    Path(output).write_bytes(result.stdout)
    if check and result.returncode:
        raise RuntimeError(
            f"command_failed:{argv[0]}:{result.returncode}:{Path(output).name}"
        )
    return {
        "command": [str(part) for part in argv],
        "exit_code": result.returncode,
        "log": Path(output).name,
        "log_sha256": digest(output),
        "log_bytes": Path(output).stat().st_size,
    }, result.stdout.decode("utf-8", errors="replace")


def unused_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def run_gateway_config_preflight(output, gateway, manifest):
    objects = workload_objects(manifest)
    container = objects["StatefulSet", "gateway"]["spec"]["template"]["spec"][
        "containers"
    ][0]
    env = {e["name"]: e["value"] for e in container["env"] if "value" in e}
    env.update(
        TENANT_CONFIG_PATH=str(ROOT / "deploy/local/tenants.json"),
        CACHE_SALT_SECRET_FILE=str(output / "cache-salt.secret"),
        GATEWAY_MEASUREMENT_PATH=str(output / "gateway.jsonl"),
        POD_NAME="gateway-0",
        POD_UID="preflight-gateway-0",
        ADMISSION_GATEWAY_ID="gateway-0",
    )
    # Use exactly the same secret input as the kind rehearsal.
    write_kind_secret(output / "cache-salt.secret")
    save(output / "gateway-env.json", env)
    result, _ = run(
        [gateway, "--check-config"],
        output=output / "gateway-config.log",
        env={**os.environ, **env},
        check=False,
    )
    return {**result, "complete": result["exit_code"] == 0}


def run_nginx_preflight(output, manifest):
    objects = workload_objects(manifest)
    nginx = objects["Deployment", "streaming-ingress"]["spec"]["template"]["spec"]
    assert nginx["securityContext"]["runAsUser"] == 101
    assert nginx["containers"][0]["securityContext"]["readOnlyRootFilesystem"] is True
    config = output / "nginx.conf"
    config.write_text(objects["ConfigMap", "streaming-ingress"]["data"]["nginx.conf"])
    tls = output / "tls"
    tls.mkdir()
    run(test_tls_command(tls), output=output / "nginx-tls.log")
    # Kubernetes Secret volumes are readable by the pod's fsGroup.
    (tls / "tls.key").chmod(0o644)
    name = "dec077-nginx-" + uuid.uuid4().hex[:10]
    port = unused_port()
    section = {"container_name": name, "complete": False, "container_removed": False}
    try:
        section["start"], _ = run(
            [
                "docker",
                "run",
                "--detach",
                "--name",
                name,
                "--read-only",
                "--user",
                "101:101",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--memory",
                "128m",
                "--memory-swap",
                "128m",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,size=64m,uid=101,gid=101",
                "--mount",
                f"type=bind,source={config},target=/etc/nginx/nginx.conf,readonly",
                "--mount",
                f"type=bind,source={tls},target=/tls,readonly",
                "--add-host",
                "gateway:127.0.0.1",
                "-p",
                f"127.0.0.1:{port}:8443",
                nginx["containers"][0]["image"],
                "nginx",
                "-g",
                "daemon off;",
            ],
            output=output / "nginx-start.log",
            timeout=60,
        )
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            try:
                connection = http.client.HTTPSConnection(
                    "127.0.0.1",
                    port,
                    timeout=2,
                    context=ssl._create_unverified_context(),
                )
                try:
                    connection.request("GET", "/x")
                    section["https_status"] = connection.getresponse().status
                finally:
                    connection.close()
                break
            except (OSError, http.client.HTTPException):
                time.sleep(0.25)
        # An answered socket alone cannot establish that the process stays up.
        time.sleep(1)
        section["inspect"], state = run(
            ["docker", "inspect", "--format", "{{.State.Running}}", name],
            output=output / "nginx-inspect.log",
        )
        section["running"] = state.strip() == "true"
        section["logs"], _ = run(
            ["docker", "logs", name], output=output / "nginx-runtime.log"
        )
        save(
            output / "nginx-answer.json",
            {
                "port": 8443,
                "https_status": section.get("https_status"),
                "running": section["running"],
            },
        )
        section["complete"] = section["running"] and section.get("https_status") == 404
    finally:
        section["cleanup"], _ = run(
            ["docker", "rm", "-f", name],
            output=output / "nginx-remove.log",
            check=False,
        )
        section["verify_removed"], _ = run(
            ["docker", "inspect", name],
            output=output / "nginx-removed.log",
            check=False,
        )
        section["container_removed"] = (
            section["cleanup"]["exit_code"] == 0
            and section["verify_removed"]["exit_code"] != 0
        )
        section["complete"] = section["complete"] and section["container_removed"]
        save(output / "nginx-receipt.json", section)
    return section


def run_containerd_image_preflight(output, images, node_image):
    """Import the four tagged archives into kind's containerd and resolve them via CRI."""
    output = Path(output)
    name = "dec077-containerd-" + uuid.uuid4().hex[:10]
    section = {
        "schema": "dec077-containerd-image-resolution-v1",
        "container_name": name,
        "node_image": node_image,
        "complete": False,
        "container_removed": False,
        "images": {},
    }
    started = False
    try:
        start, container_id = run(
            [
                "docker",
                "run",
                "--detach",
                "--rm",
                "--privileged",
                "--memory",
                "512m",
                "-v",
                "/var/lib/containerd",
                "--name",
                name,
                "--entrypoint",
                "containerd",
                node_image,
            ],
            output=output / "containerd-start.log",
            timeout=90,
        )
        started = True
        section["start"] = start
        section["container_id"] = container_id.strip()
        section["start_log"] = start["log"]
        section["start_log_sha256"] = start["log_sha256"]

        deadline = time.monotonic() + 45
        while True:
            ready, ready_text = run(
                ["docker", "exec", name, "ctr", "version"],
                output=output / "containerd-ready.log",
                timeout=10,
                check=False,
            )
            if (
                ready["exit_code"] == 0
                and "Client:" in ready_text
                and "Server:" in ready_text
            ):
                section["ready"] = ready
                section["ready_log"] = ready["log"]
                section["ready_log_sha256"] = ready["log_sha256"]
                break
            if time.monotonic() >= deadline:
                raise TimeoutError("containerd_preflight_not_ready")
            time.sleep(0.5)

        import_command = [
            "docker",
            "exec",
            "-i",
            name,
            "ctr",
            "--namespace=k8s.io",
            "images",
            "import",
            "--all-platforms",
            "--digests",
            "--snapshotter=overlayfs",
            "-",
        ]
        for image_name, image in images.items():
            imported, _ = run(
                import_command,
                output=output / f"containerd-import-{image_name}.log",
                timeout=300,
                stdin_path=output / image["archive_path"],
            )
            inspected, inspect_text = run(
                [
                    "docker",
                    "exec",
                    name,
                    "crictl",
                    "inspecti",
                    image["local_tag"],
                ],
                output=output / f"containerd-inspect-{image_name}.log",
                timeout=30,
                check=False,
            )
            try:
                image_status = json.loads(inspect_text)["status"]
                observed_id = image_status["id"]
            except (json.JSONDecodeError, KeyError, TypeError) as exc:
                raise ValueError("loaded_image_not_resolvable:" + image_name) from exc
            if inspected["exit_code"] != 0 or observed_id != image["config_digest"]:
                raise ValueError("loaded_image_not_resolvable:" + image_name)
            section["images"][image_name] = {
                "pinned_reference": image["pinned_reference"],
                "local_tag": image["local_tag"],
                "config_digest": image["config_digest"],
                "archive_path": image["archive_path"],
                "archive_sha256": image["sha256"],
                "export_commands": image["commands"],
                "import": imported,
                "inspect": {
                    **inspected,
                    "resolved_image_id": observed_id,
                },
            }

        control_path = output / "images" / "redis-digest-control-linux-amd64.tar"

        def run_control_export(argv, *, timeout):
            if argv[:3] == ["docker", "buildx", "build"]:
                step = "buildx"
            elif argv[:3] == ["docker", "image", "rm"]:
                step = "cleanup"
            else:
                step = "save"
            record, _ = run(
                argv,
                output=output / f"control-redis-digest-{step}.log",
                timeout=timeout,
            )
            return record

        control_archive = save_amd64_archive(
            images["redis"]["pinned_reference"], control_path, run_control_export
        )
        control_import, _ = run(
            import_command,
            output=output / "containerd-import-digest-control.log",
            timeout=300,
            stdin_path=control_path,
        )
        control_inspect, _ = run(
            [
                "docker",
                "exec",
                name,
                "crictl",
                "inspecti",
                images["redis"]["pinned_reference"],
            ],
            output=output / "containerd-inspect-digest-control.log",
            timeout=30,
            check=False,
        )
        if control_inspect["exit_code"] == 0:
            raise ValueError("digest_archive_control_unexpectedly_resolved")
        section["control"] = {
            "pinned_reference": images["redis"]["pinned_reference"],
            "archive_path": control_path.relative_to(output).as_posix(),
            "archive_sha256": control_archive["sha256"],
            "local_tag": control_archive["local_tag"],
            "config_digest": control_archive["config_digest"],
            "export_commands": control_archive["commands"],
            "import": control_import,
            "inspect": control_inspect,
            "expected_failure": True,
        }
        section["complete"] = set(section["images"]) == set(images)
    except Exception as exc:
        section["error"] = f"{type(exc).__name__}:{exc}"
    finally:
        if started:
            cleanup, _ = run(
                ["docker", "rm", "-f", name],
                output=output / "containerd-remove.log",
                timeout=30,
                check=False,
            )
            section["cleanup"] = cleanup
            if cleanup["exit_code"] == 0:
                section["container_removed"] = True
            else:
                inspect, _ = run(
                    ["docker", "inspect", name],
                    output=output / "containerd-verify-removed.log",
                    timeout=15,
                    check=False,
                )
                section["container_removed"] = inspect["exit_code"] != 0
        section["complete"] = section["complete"] and section["container_removed"]
    return section


def run_preflight(output, *, linux_image=LINUX_E2E_IMAGE, locked_site=None):
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    (output / "images").mkdir()
    receipt = {
        "schema": "dec077-real-dependency-preflight-v1",
        "started_at_utc": utc(),
        "source_head": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip(),
        "billable_actions": 0,
        "complete": False,
        "images": {},
    }
    redis_name = "dec077-preflight-" + uuid.uuid4().hex[:10]
    redis_started = False
    try:
        package_pins = json.loads((ROOT / "deploy/package-a/pins.json").read_bytes())
        if (
            package_pins["redis_image"] != REDIS_IMAGE
            or package_pins["python_image"] != PYTHON_IMAGE
        ):
            raise ValueError("preflight_image_pins_differ_from_package_a")
        status = subprocess.check_output(
            [
                "git",
                "status",
                "--porcelain",
                "--",
                "python",
                "scripts",
                "internal",
                "cmd",
                "deploy",
                "go.mod",
                "go.sum",
            ],
            cwd=ROOT,
            text=True,
        )
        if status.strip():
            raise ValueError("preflight_executing_source_not_clean")
        receipt["kind_no_cluster"] = check_kind_without_cluster(
            output / "kind-no-cluster"
        )
        server, server_text = run(
            ["docker", "info", "--format", "{{.ServerVersion}} {{.OSType}}"],
            output=output / "docker-info.log",
            timeout=30,
        )
        receipt["docker"] = {
            "server": server_text.strip(),
            "log_sha256": server["log_sha256"],
        }
        receipt["pin_binding"] = {
            "redis_image": package_pins["redis_image"],
            "python_image": package_pins["python_image"],
            "nginx_image": NGINX_IMAGE,
            "prometheus_image": PROMETHEUS_IMAGE,
        }

        for name, image in PULLED_IMAGES.items():
            pull, _ = run(
                ["docker", "pull", image],
                output=output / f"pull-{name}.log",
                timeout=300,
            )
            archive = output / "images" / f"{name}-linux-amd64.tar"

            def run_image_command(argv, *, timeout, image_name=name):
                step = (
                    "buildx-prefetch"
                    if argv[:3] == ["docker", "buildx", "build"]
                    else "cleanup-prefetch"
                    if argv[:3] == ["docker", "image", "rm"]
                    else "save"
                )
                command, _ = run(
                    argv,
                    output=output / f"{step}-{image_name}.log",
                    timeout=timeout,
                )
                return command

            result = save_amd64_archive(
                image,
                archive,
                run_image_command,
                local_tag=KIND_LOCAL_IMAGE_TAGS[name],
                timeout=300,
            )
            receipt["images"][name] = {
                **result,
                "archive_path": archive.relative_to(output).as_posix(),
                "pull_log_sha256": pull["log_sha256"],
            }

        k8s_pins = json.loads((ROOT / "deploy/k8s/pins.json").read_bytes())
        containerd = run_containerd_image_preflight(
            output, receipt["images"], k8s_pins["node_image"]
        )
        receipt["containerd_image_resolution"] = containerd
        if containerd["complete"] is not True:
            raise ValueError(
                containerd.get("error", "containerd_image_preflight_incomplete")
            )

        port = unused_port()
        redis_run, redis_id = run(
            [
                "docker",
                "run",
                "--detach",
                "--rm",
                "--name",
                redis_name,
                "--memory",
                "512m",
                "--memory-swap",
                "512m",
                "--cpus",
                "2",
                "--pids-limit",
                "128",
                "-p",
                f"127.0.0.1:{port}:6379",
                REDIS_IMAGE,
            ],
            output=output / "redis-start.log",
            timeout=60,
        )
        redis_started = True
        receipt["redis"] = {
            "image": REDIS_IMAGE,
            "container_id": redis_id.strip(),
            "host": f"127.0.0.1:{port}",
            "memory_mib": 512,
            "memory_swap_mib": 512,
            "start_log_sha256": redis_run["log_sha256"],
        }
        ready_log = output / "redis-ready.log"
        deadline = time.monotonic() + 45
        while True:
            ready, ready_text = run(
                ["docker", "exec", redis_name, "redis-cli", "ping"],
                output=ready_log,
                timeout=10,
                check=False,
            )
            if ready["exit_code"] == 0 and ready_text.strip() == "PONG":
                receipt["redis"]["ready_log_sha256"] = ready["log_sha256"]
                break
            if time.monotonic() >= deadline:
                raise TimeoutError("real_redis_preflight_not_ready")
            time.sleep(0.5)

        env = {**os.environ, "REDIS_TEST_ADDR": f"127.0.0.1:{port}"}
        tests, test_log = run(
            ["go", "test", "-v", "-count=1", "./..."],
            output=output / "go-redis-tests.log",
            timeout=900,
            env=env,
        )
        try:
            go_summary = go_test_summary(test_log)
        except GoTestSummaryError as exc:
            receipt["go_real_redis"] = {
                **tests,
                **exc.summary,
                "complete": False,
                "redis_addr": f"127.0.0.1:{port}",
            }
            raise
        receipt["go_real_redis"] = {
            **tests,
            **go_summary,
            "complete": True,
            "redis_addr": f"127.0.0.1:{port}",
        }

        go_vars = subprocess.check_output(
            ["go", "env", "GOOS", "GOARCH", "CGO_ENABLED"], cwd=ROOT, text=True
        ).splitlines()
        race_supported = (
            len(go_vars) == 3
            and go_vars[2] == "1"
            and (go_vars[0] != "windows" or shutil.which("gcc") is not None)
        )
        if race_supported:
            race, race_log = run(
                ["go", "test", "-race", "-v", "-count=1", "./..."],
                output=output / "go-redis-race.log",
                timeout=1200,
                env=env,
            )
            try:
                race_summary = go_test_summary(race_log)
            except GoTestSummaryError as exc:
                receipt["go_real_redis_race"] = {
                    **race,
                    **exc.summary,
                    "complete": False,
                }
                raise
            receipt["go_real_redis_race"] = {
                **race,
                **race_summary,
                "complete": True,
            }
        else:
            receipt["go_real_redis_race"] = {
                "status": "UNSUPPORTED",
                "reason": "host Go race prerequisites unavailable",
                "go_env": go_vars,
                "gcc_available": shutil.which("gcc") is not None,
                "passed_tests": 0,
                "skipped_tests": 0,
                "complete": False,
            }
            raise ValueError("go_real_redis_race_unsupported")

        gateway = output / ("gateway.exe" if os.name == "nt" else "gateway")
        build, _ = run(
            ["go", "build", "-o", gateway, "./cmd/gateway"],
            output=output / "gateway-build.log",
            timeout=300,
            env=env,
        )
        receipt["gateway_build"] = {**build, "binary_sha256": digest(gateway)}
        manifest = preflight_manifest()
        save(output / "workload-manifest.json", manifest)
        receipt["gateway_config"] = run_gateway_config_preflight(
            output, gateway, manifest
        )
        receipt["nginx_start"] = run_nginx_preflight(output, manifest)
        receipt["workload_files_sha256"] = {
            name: digest(output / name)
            for name in (
                "workload-manifest.json",
                "gateway-env.json",
                "cache-salt.secret",
                "nginx.conf",
                "nginx-answer.json",
                "nginx-receipt.json",
            )
        }
        if (
            not receipt["gateway_config"]["complete"]
            or not receipt["nginx_start"]["complete"]
        ):
            raise ValueError("workload_preflight_failed")
        e2e = receipt["gateway_redis_e2e"] = {}
        if linux_image == LINUX_E2E_IMAGE and locked_site is None:
            e2e_log = run_linux_gateway_e2e(output, redis_name, e2e)
        else:
            e2e_log = run_linux_gateway_e2e(
                output, redis_name, e2e, image=linux_image, locked_site=locked_site
            )
        if (
            "Ran 1 test" not in e2e_log
            or "skipped" in e2e_log.lower()
            or "\nOK" not in e2e_log
        ):
            raise ValueError("e2e_skipped_missing_or_failed")
        receipt["gateway_redis_e2e"] = {**e2e, "passed_tests": 1, "skipped_tests": 0}
        receipt["zero_skips"] = all(
            receipt[name]["skipped_tests"] == 0
            for name in (
                "go_real_redis",
                "go_real_redis_race",
                "gateway_redis_e2e",
            )
        )
        receipt["complete"] = (
            receipt["zero_skips"]
            and receipt["go_real_redis"]["complete"]
            and receipt["go_real_redis_race"]["complete"]
            and all(
                image["complete"] and image["platform"] == "linux/amd64"
                for image in receipt["images"].values()
            )
            and receipt["containerd_image_resolution"]["complete"]
            and receipt["gateway_config"]["complete"]
            and receipt["nginx_start"]["complete"]
            and receipt["kind_no_cluster"]["complete"]
        )
        if not receipt["complete"]:
            raise ValueError("local_preflight_incomplete")
    except Exception as exc:
        receipt["error"] = f"{type(exc).__name__}:{exc}"
        raise
    finally:
        if redis_started:
            cleanup, cleanup_text = run(
                ["docker", "rm", "-f", redis_name],
                output=output / "redis-remove.log",
                timeout=30,
                check=False,
            )
            receipt["redis_cleanup"] = {
                "exit_code": cleanup["exit_code"],
                "log_sha256": cleanup["log_sha256"],
                "container_removed": cleanup["exit_code"] == 0,
            }
            if cleanup["exit_code"]:
                receipt["complete"] = False
                receipt["error"] = receipt.get(
                    "error", "redis_preflight_cleanup_failed"
                )
        receipt["finished_at_utc"] = utc()
        receipt["source_files_sha256"] = {
            "scripts/package_a_local_preflight.py": digest(__file__),
            "python/src/inference_platform/package_a_go.py": digest(
                ROOT / "python/src/inference_platform/package_a_go.py"
            ),
            "python/src/inference_platform/package_a_images.py": digest(
                ROOT / "python/src/inference_platform/package_a_images.py"
            ),
        }
        save(output / "receipt.json", receipt)
    if receipt["complete"] is not True:
        raise RuntimeError(receipt.get("error", "real_dependency_preflight_incomplete"))
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    receipt = run_preflight(args.output)
    print(
        json.dumps(
            {
                "complete": receipt["complete"],
                "source_head": receipt["source_head"],
                "go_passed": receipt["go_real_redis"]["passed_tests"],
                "go_race_passed": receipt["go_real_redis_race"]["passed_tests"],
                "e2e_passed": receipt["gateway_redis_e2e"]["passed_tests"],
                "image_archives_complete": len(receipt["images"]),
                "containerd_image_resolution_complete": receipt[
                    "containerd_image_resolution"
                ]["complete"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
