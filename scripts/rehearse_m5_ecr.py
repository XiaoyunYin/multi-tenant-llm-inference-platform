"""DEC-099 real sparse-source images(), scoped writer and cold PullOnly.

The routine operator creates the zone-equivalent repository and scoped roles
before bootstrap. Its finally path empties/deletes them and verifies ECR/IAM
absence. This stage has no EKS, GPU or capacity-probe path.
"""

import argparse
import base64
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import time
from pathlib import Path

import boto3

from inference_platform.command_diagnostics import checked_process, stderr_tail
from inference_platform.m5_descriptive_operator import session_timing
from inference_platform.m5_descriptive_operator import phase_deadline
from m5_descriptive_remote import EKSClusterPorts
from package_a_host import host_environment
from rehearse_m5_descriptive_phases import namespace_command, prepare


def write(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def login(client, repository, env):
    auth = client.get_authorization_token()["authorizationData"][0]
    user, password = base64.b64decode(auth["authorizationToken"]).decode().split(":", 1)
    checked_process(
        [
            "docker",
            "login",
            "--username",
            user,
            "--password-stdin",
            repository.split("/")[0],
        ],
        input=password.encode(),
        capture_output=True,
        timeout=30,
        env=env,
        secrets=(password,),
    )


def require_role(caller_arn, role_arn):
    account = role_arn.split(":")[4]
    name = role_arn.rsplit("/", 1)[1]
    if (
        caller_arn.split(":")[4] != account
        or ":assumed-role/" + name + "/" not in caller_arn
    ):
        raise ValueError("ecr:unexpected_principal")
    return True


def pull_work_directory(output):
    # Generated daemon data belongs to the outer fixture, outside the guarded
    # sparse repo. The outer process removes its inputs tree after the child
    # exits; fd-relative rmtree opens must not be mistaken for source reads.
    root = Path(output) / "pull-work"
    root.mkdir()
    return root


def pull_sandbox_argv(name, image, host_directory):
    """A second daemon must own a network namespace, not the host's docker0."""
    return [
        "docker",
        "run",
        "--detach",
        "--privileged",
        "--name",
        name,
        "--network",
        "bridge",
        "--mount",
        "type=bind,source=/opt/dec077/tools/docker,target=/pinned-docker,readonly",
        "--mount",
        f"type=bind,source={host_directory},target=/cold",
        "--env",
        "PATH=/pinned-docker:/usr/sbin:/usr/bin:/sbin:/bin",
        "--entrypoint",
        "/pinned-docker/dockerd",
        image,
        "--host=unix:///cold/docker.sock",
        "--data-root=/cold/data",
        "--exec-root=/cold/exec",
        "--pidfile=/cold/daemon.pid",
        "--bridge=none",
        "--iptables=false",
        "--ip-forward=false",
        "--ip-masq=false",
    ]


def primary_bridge_probe(image, env):
    # Creating a real networked container catches a removed docker0 even when
    # `docker info` and pulls still succeed. No workload or AWS resource runs.
    checked_process(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "bridge",
            "--entrypoint",
            "/bin/true",
            image,
        ],
        capture_output=True,
        timeout=60,
        env=env,
    )
    return True


def cold_pull(images, client, env, output, *, sandbox_image, host_directory):
    """A fresh pinned daemon exercises remote layer reads, without writer cache."""
    root = pull_work_directory(output)
    pull_env = {
        **env,
        "DOCKER_HOST": "unix://" + str(root / "docker.sock"),
        "DOCKER_CONFIG": str(root / "auth"),
    }
    name = "m5-ecr-cold-pull-" + str(os.getpid())
    primary_env = {
        k: v for k, v in env.items() if k not in {"DOCKER_HOST", "DOCKER_CONTEXT"}
    }
    checked_process(
        ["docker", "pull", sandbox_image],
        capture_output=True,
        timeout=300,
        env=primary_env,
    )
    isolation = {
        "network_mode": "bridge",
        "sandbox_image": sandbox_image,
        "primary_bridge_before": primary_bridge_probe(sandbox_image, primary_env),
    }
    try:
        checked_process(
            pull_sandbox_argv(name, sandbox_image, host_directory),
            capture_output=True,
            timeout=60,
            env=primary_env,
        )
        sandbox = json.loads(
            checked_process(
                ["docker", "inspect", name],
                capture_output=True,
                timeout=30,
                env=primary_env,
            ).stdout
        )[0]
        if sandbox["HostConfig"]["NetworkMode"] != "bridge" or os.readlink(
            "/proc/self/ns/net"
        ) == os.readlink(f"/proc/{sandbox['State']['Pid']}/ns/net"):
            raise ValueError("ecr:cold_network_not_isolated")
        isolation["separate_network_namespace"] = True
        end = time.monotonic() + 60
        while True:
            alive = checked_process(
                ["docker", "inspect", "--format", "{{.State.Running}}", name],
                capture_output=True,
                timeout=30,
                env=primary_env,
            ).stdout.strip()
            if alive != b"true":
                raise RuntimeError("ecr:cold_daemon_exited")
            if (
                subprocess.run(
                    ["docker", "info"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    env=pull_env,
                    timeout=10,
                ).returncode
                == 0
            ):
                break
            if time.monotonic() >= end:
                raise TimeoutError("ecr:cold_daemon_ready")
            time.sleep(0.5)
        if checked_process(
            ["docker", "image", "ls", "--quiet"],
            capture_output=True,
            timeout=30,
            env=pull_env,
        ).stdout.strip():
            raise ValueError("ecr:cold_daemon_not_empty")
        isolation["initial_images"] = 0
        repository = next(iter(images.values())).split("@")[0]
        login(client, repository, pull_env)
        facts = {}
        try:
            for role, image in images.items():
                checked_process(
                    ["docker", "pull", image],
                    capture_output=True,
                    timeout=900,
                    env=pull_env,
                )
                inspected = json.loads(
                    checked_process(
                        ["docker", "image", "inspect", image],
                        capture_output=True,
                        timeout=30,
                        env=pull_env,
                    ).stdout
                )[0]
                if image not in inspected["RepoDigests"]:
                    raise ValueError("ecr:pull_digest_readback")
                facts[role] = {
                    "digest": image.split("@")[1],
                    "config_id": inspected["Id"],
                    "layers": len(inspected["RootFS"]["Layers"]),
                    "cold_daemon": True,
                    "status": "PASS",
                }
        finally:
            checked_process(
                ["docker", "logout", repository.split("/")[0]],
                capture_output=True,
                timeout=30,
                env=pull_env,
            )
    finally:
        logs = subprocess.run(
            ["docker", "logs", name], capture_output=True, timeout=30, env=primary_env
        )
        (output / "pull-daemon.log").write_text(stderr_tail(logs.stdout + logs.stderr))
        subprocess.run(
            ["docker", "rm", "--force", "--volumes", name],
            capture_output=True,
            timeout=60,
            env=primary_env,
        )
        remaining = checked_process(
            ["docker", "ps", "-aq", "--filter", "name=^/" + name + "$"],
            capture_output=True,
            timeout=30,
            env=primary_env,
        ).stdout.strip()
        if remaining:
            raise RuntimeError("ecr:cold_daemon_cleanup_unverified")
        isolation["container_removed"] = True
        isolation["primary_bridge_after"] = primary_bridge_probe(
            sandbox_image, primary_env
        )
    return {"images": facts, "isolation": isolation}


def execute(output):
    output.mkdir(parents=True, exist_ok=True)
    manifest = json.loads(Path("/opt/dec077/runtime.json").read_bytes())
    fixture = manifest["ecr_validation"]
    record = {
        "schema": "m5-real-ecr-boundary-v1",
        "complete": False,
        "environment": {k: os.environ.get(k) for k in host_environment()},
        "repository_settings": fixture["settings"],
        "writer_policy": fixture["writer_policy"],
        "pull_policy_arn": fixture["pull_policy_arn"],
        "source_payload": manifest["source_payload"],
        "substitutions": [],
        "repository_cleanup": "routine operator finally: image deletion, force_delete=false Terraform destroy, service inventory",
    }
    started = time.monotonic()
    try:
        from inference_platform.m5_payload_guard import install_read_guard
        from m5_descriptive_remote import ROOT

        install_read_guard(ROOT, manifest["source_payload"]["paths"])
        if fixture.get("policies_verified") is not True:
            raise ValueError("ecr:fixture_policy_not_verified")
        sts = boto3.client("sts", region_name="us-east-1")
        writer = sts.get_caller_identity()
        record["writer_principal_role_verified"] = require_role(
            writer["Arn"], fixture["writer_role_arn"]
        )
        ports = EKSClusterPorts(Path("/opt/dec077/descriptive-private"), manifest)
        images = ports.images()
        record["push_elapsed_s"] = time.monotonic() - started
        record["pushed"] = {
            role: {"digest": image.split("@")[1]} for role, image in images.items()
        }
        ecr = boto3.client("ecr", region_name="us-east-1")
        readback = {}
        for role, image in images.items():
            digest = image.split("@")[1]
            rows = ecr.describe_images(
                repositoryName=fixture["repository_name"],
                imageIds=[{"imageDigest": digest}],
            )["imageDetails"]
            if len(rows) != 1 or rows[0]["imageDigest"] != digest:
                raise ValueError("ecr:writer_digest_readback")
            readback[role] = {
                "digest": digest,
                "size_bytes": rows[0]["imageSizeInBytes"],
            }
        record["ecr_digest_readback"] = readback
        record["writer_principal_sha256"] = hashlib.sha256(
            writer["Arn"].encode()
        ).hexdigest()
        temporary = sts.assume_role(
            RoleArn=fixture["pull_role_arn"],
            RoleSessionName="descriptive-pull-only",
            DurationSeconds=3600,
        )["Credentials"]
        reader = boto3.Session(
            aws_access_key_id=temporary["AccessKeyId"],
            aws_secret_access_key=temporary["SecretAccessKey"],
            aws_session_token=temporary["SessionToken"],
            region_name="us-east-1",
        )
        identity = reader.client("sts").get_caller_identity()
        record["pull_principal_role_verified"] = require_role(
            identity["Arn"], fixture["pull_role_arn"]
        )
        record["pull_principal_sha256"] = hashlib.sha256(
            identity["Arn"].encode()
        ).hexdigest()
        if record["pull_principal_sha256"] == record["writer_principal_sha256"]:
            raise ValueError("ecr:pull_principal_not_separate")
        env = {
            **os.environ,
            "AWS_ACCESS_KEY_ID": temporary["AccessKeyId"],
            "AWS_SECRET_ACCESS_KEY": temporary["SecretAccessKey"],
            "AWS_SESSION_TOKEN": temporary["SessionToken"],
        }
        from m5_descriptive_remote import ROOT

        pins = json.loads((ROOT / "deploy/package-a/pins.json").read_bytes())
        pulled = cold_pull(
            images,
            reader.client("ecr"),
            env,
            output,
            sandbox_image=pins["python_image"],
            host_directory=fixture["pull_host_directory"],
        )
        record["pulls"] = pulled["images"]
        record["cold_pull_isolation"] = pulled["isolation"]
        record["complete"] = True
    except Exception as error:
        record["error"] = stderr_tail(type(error).__name__ + ":" + str(error))
        raise
    finally:
        record["elapsed_s"] = time.monotonic() - started
        write(output / "result.json", record)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--payload-transfer-receipt", type=Path)
    args = parser.parse_args()
    if args.execute:
        execute(args.output)
        return
    args.output.mkdir(parents=True, exist_ok=False)
    routine_manifest = json.loads(args.manifest.read_bytes())
    fixture = routine_manifest["ecr_validation"]
    transfer = json.loads(args.payload_transfer_receipt.read_bytes())
    root = args.output / "inputs"
    try:
        manifest = prepare(root, transfer)
        # Docker's primary daemon resolves bind sources in the original host
        # mount namespace, outside this stage's /opt/dec077 bind substitution.
        fixture["pull_host_directory"] = str(
            (root / "results/runner/ecr/pull-work").resolve()
        )
        manifest["ecr_validation"] = fixture
        original_end = routine_manifest["deadline_epoch"]
        manifest["deadline_epoch"] = phase_deadline(
            original_end, session_timing(640), "provision"
        )
        manifest["descriptive"].update(
            session="ecr-boundary",
            original_deadline_epoch=original_end,
            startup_seconds=640,
            timing=session_timing(640),
            repository_url=fixture["repository_url"],
            source_commit=transfer["binding"]["source_commit"],
        )
        write(root / "runtime.json", manifest)
        program = "/opt/dec077/repo/python/.venv/bin/python -B /opt/dec077/repo/scripts/rehearse_m5_ecr.py --execute --output /opt/dec077/results/runner/ecr"
        shell = (
            "cd /opt/dec077/repo; export "
            + " ".join(k + "=" + shlex.quote(v) for k, v in host_environment().items())
            + "; "
            + program
        )
        result = subprocess.run(
            namespace_command(root, shell), capture_output=True, timeout=2400
        )
        (args.output / "phase.stdout").write_bytes(result.stdout)
        (args.output / "phase.stderr").write_text(stderr_tail(result.stderr))
        record = root / "results/runner/ecr/result.json"
        if record.exists():
            shutil.copyfile(record, args.output / "result.json")
        daemon_log = root / "results/runner/ecr/pull-daemon.log"
        if daemon_log.exists():
            shutil.copyfile(daemon_log, args.output / "pull-daemon.log")
        if result.returncode:
            raise RuntimeError(
                "ecr:real_images_path_failed:" + stderr_tail(result.stderr)
            )
        proof = json.loads(record.read_bytes())
        if not proof["complete"] or proof["environment"] != host_environment():
            raise ValueError("ecr:receipt_or_environment")
        proof.update(
            payload_sha256=transfer["payload_sha256"],
            shell_sha256=hashlib.sha256(shell.encode()).hexdigest(),
            same_real_constructor_and_images=True,
        )
        write(args.output / "result.json", proof)
    finally:
        if root.exists():
            shutil.rmtree(root)


if __name__ == "__main__":
    main()
