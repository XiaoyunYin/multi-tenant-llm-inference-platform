"""$0 R328 Linux cold-cache/context/image/gateway receipt; never creates kind or AWS resources."""

import argparse
import hashlib
import http.client
import io
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import time
import unittest
import uuid
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

BASE = "python:3.12.7-slim-bookworm@sha256:60d9996b6a8a3689d36db740b49f4327be3be09a21122bd02fb8895abb38b50d"
BASELINE = "2c14729c3d24a9e09c3dd8b1e17a9f1c8c873643"
ROOT = Path(__file__).resolve().parents[1]
TESTS = (
    "test_r328_publisher_modes_before_atomic_publication",
    "test_r328_build_normalizes_warm_cache",
    "test_r328_fake_refuses_before_serving",
    "test_r328_image_self_test_fails_closed_and_records_success",
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def context():
    """Run Campaign.build's real fetch/copy/normalization inside the pinned Linux base."""
    root = Path("/tmp/r328-repo")
    shutil.copytree("/input/python/src", root / "python/src")
    shutil.copytree("/input/deploy/k8s", root / "deploy/k8s")
    sys.path.insert(0, str(root / "python/src"))
    from inference_platform import kind_rollout as rollout
    from inference_platform.stage_c_tokenizer import cache_directory

    os.environ["INF011_TOKENIZER_CACHE"] = str(root / "cold-cache")
    assert not cache_directory().exists()
    commands = []

    def run(*args, **kwargs):
        commands.append([str(arg) for arg in args])
        if args[0] == "uv":
            return Path("/requirements.txt").read_text()
        return "receipt-build-only"

    # Only external Go/uv/Docker commands are substituted here. The actual
    # tokenizer download, hash checks, copytree and permission helper all run.
    with (
        patch.object(rollout, "ROOT", root),
        patch.object(rollout, "run", side_effect=run),
    ):
        campaign = rollout.Campaign.__new__(rollout.Campaign)
        campaign.pins = {"redis_image": "not-needed-for-fake-context"}
        campaign.build()
    build = root / ".cache/kind-build"
    modes = {}
    for parent in (root / "cold-cache", build / "tokenizer"):
        for path in [parent, *sorted(parent.rglob("*"))]:
            modes[str(path.relative_to(root))] = {
                "mode": oct(stat.S_IMODE(path.stat().st_mode)),
                "uid": path.stat().st_uid,
                "directory": path.is_dir(),
                **({} if path.is_dir() else {"sha256": sha(path.read_bytes())}),
            }
    (build / "linux-context.json").write_text(
        json.dumps(
            {
                "cold_cache_before_fetch": True,
                "base": BASE,
                "modes": modes,
                "build_commands_substituted": commands,
                "source_sha256": {
                    p.name: sha(p.read_bytes())
                    for p in (root / "python/src/inference_platform").glob("*.py")
                },
            },
            indent=2,
        )
        + "\n"
    )
    # GNU tar runs in Linux; stdout is binary all the way to the Docker build.
    subprocess.run(["tar", "-C", str(build), "-cf", "-", "."], check=True)


def mutant(name):
    """One mutation per new interpreter, with no changes to repository files."""
    import importlib

    module, before, after, test = {
        "publisher": (
            "stage_c_tokenizer",
            "                temporary.chmod(0o644)\n",
            "",
            TESTS[0],
        ),
        "context": (
            "kind_rollout",
            '        normalize_tokenizer_context(build / "tokenizer")\n',
            "",
            TESTS[1],
        ),
        "fail-fast": ("kind_fake", "        return 1\n", "        pass\n", TESTS[2]),
        "self-test": (
            "package_a_cloud",
            "        # Exercise the built image's real USER",
            "",
            TESTS[3],
        ),
    }[name]
    loaded = importlib.import_module("inference_platform." + module)
    source = Path(loaded.__file__).read_text()
    if name == "self-test":
        start = source.index(before)
        end = source.index('        self.receipt["images"] = {}', start)
        changed = source[:start] + source[end:]
    else:
        assert source.count(before) == 1
        changed = source.replace(before, after)
    exec(compile(changed, loaded.__file__, "exec"), loaded.__dict__)
    suite = unittest.defaultTestLoader.loadTestsFromName(
        "test_package_a_kind.KindHarnessTests." + test
    )
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    # A mutant's nonzero result must be a test failure/error, not import failure.
    assert result.testsRun == 1 and not result.skipped
    raise SystemExit(0 if result.wasSuccessful() else 1)


def unused_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def check(output):
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    receipt = {
        "schema": "r328-linux-tokenizer-v1",
        "started_at_utc": datetime.now(UTC).isoformat(),
        "source_sha256": {
            name: sha((ROOT / name).read_bytes())
            for name in (
                "scripts/check_package_a_tokenizer.py",
                "python/tests/test_package_a_kind.py",
                "python/src/inference_platform/stage_c_tokenizer.py",
                "python/src/inference_platform/kind_rollout.py",
                "python/src/inference_platform/kind_fake.py",
                "python/src/inference_platform/package_a_cloud.py",
                "deploy/k8s/fake.Dockerfile",
                "python/uv.lock",
                "cmd/gateway/main.go",
            )
        },
        "cost_usd": 0,
        "base": BASE,
        "baseline_commit": BASELINE,
        "source_base_commit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT
        )
        .decode()
        .strip(),
        "commands": [],
        "variants": {},
        "mutants": {},
        "scope": "Linux cold-cache permissions and real image USER; one real native gateway, static discovery and fixed capacity with isolated Redis; no kind cluster, AWS or packet.",
    }
    owned = []
    images = []
    processes = []
    logs = []

    def run(argv, name, *, data=None, expected=0, timeout=600):
        argv = [str(arg) for arg in argv]
        result = subprocess.run(
            argv, cwd=ROOT, input=data, capture_output=True, timeout=timeout
        )
        (output / (name + ".stdout")).write_bytes(result.stdout)
        (output / (name + ".stderr")).write_bytes(result.stderr)
        receipt["commands"].append(
            {
                "argv": argv,
                "exit": result.returncode,
                "name": name,
                "stdout_sha256": sha(result.stdout),
                "stderr_sha256": sha(result.stderr),
            }
        )
        if expected is not None and result.returncode != expected:
            raise RuntimeError(
                f"{name}:exit:{result.returncode}:"
                + result.stderr.decode(errors="replace")[-3000:]
            )
        return result

    try:
        requirements = run(
            [
                "uv",
                "export",
                "--project",
                "python",
                "--locked",
                "--group",
                "dev",
                "--no-emit-project",
                "--format",
                "requirements-txt",
            ],
            "requirements",
        ).stdout
        (output / "requirements.txt").write_bytes(requirements)
        baseline = output / "baseline"
        baseline.mkdir()
        archive = run(
            ["git", "archive", BASELINE, "python/src", "deploy/k8s"], "baseline-source"
        ).stdout
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(baseline, filter="data")
        for variant, source in (("baseline", baseline), ("fixed", ROOT)):
            print("R328: Linux cold context " + variant, flush=True)
            argv = [
                "docker",
                "run",
                "--rm",
                "--platform",
                "linux/amd64",
                "-v",
                f"{source}:/input:ro",
                "-v",
                f"{ROOT / 'scripts/check_package_a_tokenizer.py'}:/tools/receipt.py:ro",
                "-v",
                f"{output / 'requirements.txt'}:/requirements.txt:ro",
                BASE,
                "python",
                "/tools/receipt.py",
                "--context",
            ]
            tar_bytes = run(argv, variant + "-context").stdout
            with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tar:
                context_receipt = json.load(tar.extractfile("./linux-context.json"))
            expected = "0o600" if variant == "baseline" else "0o644"
            assert all(
                v["mode"] == expected
                for k, v in context_receipt["modes"].items()
                if not v["directory"]
            )
            assert all(
                v["mode"] == "0o755"
                for k, v in context_receipt["modes"].items()
                if v["directory"]
            )
            tag = "r328-fake-" + variant + ":" + uuid.uuid4().hex[:10]
            images.append(tag)
            dockerfile = (source / "deploy/k8s/fake.Dockerfile").read_bytes()
            # Include the repository's exact Dockerfile bytes in the Linux tar.
            stream = io.BytesIO(tar_bytes)
            with tarfile.open(fileobj=stream, mode="a") as tar:
                info = tarfile.TarInfo("Dockerfile")
                info.size, info.mode = len(dockerfile), 0o644
                tar.addfile(info, io.BytesIO(dockerfile))
            tar_bytes = stream.getvalue()
            run(
                [
                    "docker",
                    "build",
                    "--platform",
                    "linux/amd64",
                    "--provenance=false",
                    "-t",
                    tag,
                    "-f",
                    "Dockerfile",
                    "-",
                ],
                variant + "-build",
                data=tar_bytes,
            )
            inspect = json.loads(
                run(["docker", "image", "inspect", tag], variant + "-image").stdout
            )[0]
            assert inspect["Config"]["User"] == "65532:65532"
            receipt["variants"][variant] = {
                "linux_context": context_receipt,
                "context_tar_sha256": sha(tar_bytes),
                "dockerfile_sha256": sha(dockerfile),
                "image_id": inspect["Id"],
                "image_user": inspect["Config"]["User"],
            }

        # Execute prepare_images' exact self-test against each real image. Earlier
        # host setup/build calls and the later image inventory are substituted:
        # both actual builds and inspections are already recorded above.
        sys.path.insert(0, str(ROOT / "python/src"))
        from inference_platform.package_a_cloud import Runner

        for variant, image in zip(("baseline", "fixed"), images, strict=True):
            runner = Runner(
                ROOT,
                output / (variant + "-self-test"),
                {
                    "checks": ["kind"],
                    "python_executable": sys.executable,
                    "pins": {
                        "python_image": BASE,
                        "redis_image": "unused",
                        "node_image": "unused",
                    },
                },
            )

            def call(argv, name, image=image, variant=variant, runner=runner, **kwargs):
                if name == "fake-tokenizer-self-test":
                    actual = [
                        image if arg == "mti-fake:stage1" else arg for arg in argv
                    ]
                    row = run(
                        actual,
                        variant + "-self-test",
                        expected=None,
                        timeout=kwargs["timeout"],
                    )
                    (runner.output / "self-test.log").write_bytes(row.stdout)
                    if row.returncode:
                        raise RuntimeError("tokenizer_self_test_failed")
                    return {
                        "log": "self-test.log",
                        "exit": row.returncode,
                        "argv": actual,
                    }
                path = runner.output / (name + ".log")
                path.write_text("[]")
                return {"log": path.name, "exit": 0, "substituted": True}

            runner.call = call
            if variant == "baseline":
                try:
                    runner.prepare_images()
                except RuntimeError as error:
                    assert str(error) == "tokenizer_self_test_failed"
                else:
                    raise AssertionError("baseline image self-test must refuse")
            else:
                runner.prepare_images()
            receipt["variants"][variant]["prepare_images_self_test"] = runner.receipt[
                "fake_tokenizer_self_test"
            ]
        fixed = images[-1]
        test_env = "PYTHONPATH=/repo/python/tests:/repo/python/src:/repo/scripts/tests:/repo/scripts"
        prefix = [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "-w",
            "/repo",
            "-v",
            f"{ROOT}:/repo:ro",
            "-e",
            test_env,
            "-e",
            "PYTHONDONTWRITEBYTECODE=1",
            "--entrypoint",
            "python",
            fixed,
        ]
        run(
            prefix
            + [
                "-m",
                "unittest",
                *["test_package_a_kind.KindHarnessTests." + name for name in TESTS],
                "-v",
            ],
            "linux-posix-tests",
        )
        for name in ("publisher", "context", "fail-fast", "self-test"):
            result = run(
                prefix
                + ["/repo/scripts/check_package_a_tokenizer.py", "--mutant", name],
                "mutant-" + name,
                expected=None,
            )
            assert result.returncode == 1 and b"FAILED (" in result.stderr, (
                name,
                result.stderr,
            )
            receipt["mutants"][name] = {
                "disposition": "KILLED",
                "exit": result.returncode,
                "fresh_process": True,
                "stderr": result.stderr.decode(),
            }

        sys.path.insert(0, str(ROOT / "python/src"))
        from inference_platform.eks_deployment import REDIS_IMAGE
        from inference_platform.package_a_workload import write_kind_secret

        redis_port, gateway_port = unused_port(), unused_port()
        redis_name = "r328-redis-" + uuid.uuid4().hex[:10]
        owned.append(redis_name)
        run(
            [
                "docker",
                "run",
                "-d",
                "--name",
                redis_name,
                "-p",
                f"127.0.0.1:{redis_port}:6379",
                REDIS_IMAGE,
            ],
            "redis",
        )
        binary = output / ("gateway.exe" if os.name == "nt" else "gateway")
        run(
            ["go", "build", "-trimpath", "-o", binary, "./cmd/gateway"], "gateway-build"
        )
        receipt["gateway_binary_sha256"] = sha(binary.read_bytes())
        write_kind_secret(output / "salt")
        for variant, image in zip(("baseline", "fixed"), images, strict=True):
            port = unused_port()
            name = "r328-" + variant + "-" + uuid.uuid4().hex[:10]
            owned.append(name)
            entry = "from inference_platform import kind_fake; kind_fake.STREAM_CHUNKS=20; kind_fake.STREAM_CHUNK_DELAY_MS=500; raise SystemExit(kind_fake.main())"
            run(
                [
                    "docker",
                    "run",
                    "-d",
                    "--name",
                    name,
                    "-p",
                    f"127.0.0.1:{port}:8000",
                    "-e",
                    "POD_NAME=vllm-0",
                    "-e",
                    "POD_UID=r328-uid",
                    "--entrypoint",
                    "python",
                    image,
                    "-u",
                    "-c",
                    entry,
                ],
                variant + "-start",
            )
            for _ in range(150):
                try:
                    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
                    conn.request("GET", "/health")
                    response = conn.getresponse()
                    if (
                        response.status == 200
                        and json.loads(response.read())["healthy"]
                    ):
                        break
                except (OSError, http.client.HTTPException):
                    pass
                finally:
                    conn.close()
                time.sleep(0.1)
            else:
                raise RuntimeError("fake_health_timeout")
            payload = json.dumps(
                {
                    "model": "test-model",
                    "messages": [{"role": "user", "content": "kind engineering drain"}],
                    "max_tokens": 32,
                    "stream": True,
                }
            )

            def request(target):
                conn = http.client.HTTPConnection("127.0.0.1", target, timeout=35)
                try:
                    conn.request(
                        "POST",
                        "/v1/chat/completions",
                        payload,
                        {
                            "Content-Type": "application/json",
                            "Authorization": "Bearer local-dev-token",
                        },
                    )
                    response = conn.getresponse()
                    return response.status, response.read()
                finally:
                    conn.close()

            if variant == "baseline":
                status, body = request(port)
                assert status == 503 and json.loads(body) == {
                    "error": "pinned_chat_tokenizer_unavailable"
                }
                receipt["variants"][variant]["stream"] = {
                    "status": status,
                    "body": body.decode(),
                }
            else:
                env = {
                    **os.environ,
                    "GATEWAY_HTTP_ADDR": f"127.0.0.1:{gateway_port}",
                    "BACKEND_DISCOVERY": "static",
                    "BACKENDS": f"vllm-0=http://127.0.0.1:{port}",
                    "REDIS_ADDR": f"127.0.0.1:{redis_port}",
                    "TENANT_CONFIG_PATH": str(ROOT / "deploy/local/tenants.json"),
                    "CACHE_SALT_SECRET_FILE": str(output / "salt"),
                    "OTEL_SDK_DISABLED": "true",
                    "ADMISSION_CAPACITY_MODE": "fixed",
                }
                log = (output / "gateway.log").open("wb")
                logs.append(log)
                process = subprocess.Popen(
                    [str(binary)],
                    cwd=ROOT,
                    env=env,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                )
                processes.append(process)
                for _ in range(150):
                    try:
                        conn = http.client.HTTPConnection(
                            "127.0.0.1", gateway_port, timeout=1
                        )
                        conn.request("GET", "/readyz")
                        if conn.getresponse().status == 200:
                            break
                    except OSError:
                        pass
                    finally:
                        conn.close()
                    time.sleep(0.1)
                else:
                    raise RuntimeError("gateway_ready_timeout")
                status, body = request(gateway_port)
                events = [
                    line[6:]
                    for line in body.decode().splitlines()
                    if line.startswith("data: ")
                ]
                content = [
                    json.loads(event)["choices"][0]["delta"].get("content", "")
                    for event in events
                    if event != "[DONE]" and json.loads(event).get("choices")
                ]
                content = [part for part in content if part]
                assert (
                    status == 200 and len(content) == 20 and events[-1] == "[DONE]"
                ), (status, body)
                assert "".join(content) == "".join(f"token-{i} " for i in range(20))
                receipt["variants"][variant]["gateway_stream"] = {
                    "status": status,
                    "content_chunks": len(content),
                    "done": True,
                    "body": body.decode(),
                    "body_sha256": sha(body),
                }
            receipt["variants"][variant]["runtime_log"] = run(
                ["docker", "logs", name], variant + "-logs"
            ).stdout.decode()
        receipt["complete"] = True
    finally:
        for process in processes:
            process.terminate()
            process.wait(timeout=15)
        for log in logs:
            log.close()
        for name in owned:
            run(["docker", "rm", "-f", name], "cleanup-" + name, expected=None)
        for image in images:
            run(
                ["docker", "image", "rm", image],
                "cleanup-" + image.split(":")[0],
                expected=None,
            )
        remaining = (
            run(["docker", "ps", "-a", "--format", "{{.Names}}"], "cleanup-inventory")
            .stdout.decode()
            .splitlines()
        )
        receipt["cleanup_verified"] = not set(owned).intersection(remaining) and all(
            p.poll() is not None for p in processes
        )
        (output / "receipt.json").write_text(
            json.dumps(receipt, indent=2) + "\n", encoding="utf-8"
        )
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", action="store_true")
    parser.add_argument("--mutant")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.context:
        context()
    elif args.mutant:
        mutant(args.mutant)
    else:
        result = check(args.output)
        print(
            json.dumps(
                {
                    "complete": result["complete"],
                    "cleanup_verified": result["cleanup_verified"],
                }
            )
        )
