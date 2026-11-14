"""One $0 supervisor-to-archive rehearsal. Never calls an AWS executable/API.

Usage: uv run --project python --locked python scripts/rehearse_l4_compat.py
  --packet .cache/r280-canonical --output .cache/l4-rehearsal --mutants

Requires Windows (the production operator), Docker Desktop Linux containers,
the cached DEC-077 docker archive, and the freshly prepared source-bound packet.
The same literal supervisor argv/cwd/output/env runs a price refusal, then success.
"""

import argparse
import hashlib
import gzip
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import tarfile
import time
import uuid
from pathlib import Path

from inference_platform.package_a_cloud import save, sha
from inference_platform.inf037b_archive import encode

ROOT = Path(__file__).resolve().parents[1]
SUBSTITUTIONS = [
    "AWS responses and Terraform init/apply/wait/destroy at Ports; no AWS process/API",
    "SSM executes the literal L4Ports command lists under sh in an Ubuntu 24.04 container",
    "SSM tunnel is loopback TCP via the scratch host; real Ports.request/rpc/upload/run_checks/retrieve",
    "Review marker validation is explicitly stubbed in scratch sitecustomize; no marker is created",
    "Scratch manifest account identity is a synthetic account; source/blob/tool/bundle/plan joins remain real",
    "nvidia-smi, systemctl and EC2 host timer are scratch-host substitutes; real cloud-init uses local NoCloud seed only",
    "GPU image pull/inspect and GPU model stage/serve are replaced by l4_compat_fake_engine.py",
]
UNREACHED = [
    "EC2/IAM/SSM registration, real port-forward reconnects, live prices/quota/AMI and provider teardown",
    "Independent EC2 host termination timer and Windows-to-real-SSM behavior",
    "GPU/CUDA/driver/image compatibility and real model revision/weight downloads/hash verification",
    "l4_compat_container.stage/serve: Hugging Face selection, installed vLLM base/helper/overlay checks and exec capture_runtime",
    "vLLM installers and real input/API/core/scheduler hooks; supplied fake installed hashes are not installed-source evidence",
    "Native scheduler cancellation RPC, actual KV release, real decode throughput/control timing and measured 64-token choice",
    "EKS, simultaneous two-slot fitness, R366 planned-host export and full M5 acceptance",
]


def verify_archive_inventory(stream):
    inventory = json.load(stream.extractfile("results/inventory.json"))
    observed = {
        m.name.removeprefix("results/")
        for m in stream.getmembers()
        if m.isfile()
        and m.name.startswith("results/")
        and m.name != "results/inventory.json"
    }
    assert observed == set(inventory)
    for name, facts in inventory.items():
        data = stream.extractfile("results/" + name).read()
        assert (
            len(data) == facts["bytes"]
            and hashlib.sha256(data).hexdigest() == facts["sha256"]
        )
    return len(inventory)


def run(argv, *, cwd=ROOT, env=None, timeout=900):
    return subprocess.run(
        list(map(str, argv)), cwd=cwd, env=env, capture_output=True, timeout=timeout
    )


def checked(argv, **kwargs):
    result = run(argv, **kwargs)
    if result.returncode:
        raise RuntimeError(
            (result.stdout + result.stderr).decode(errors="replace")[-6000:]
        )
    return result


def snapshot():
    index = ROOT / ".cache" / ("l4-index-" + uuid.uuid4().hex)
    index.parent.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "GIT_INDEX_FILE": str(index)}
    try:
        checked(["git", "read-tree", "HEAD"], env=env)
        checked(
            [
                "git",
                "add",
                "python",
                "scripts",
                "infra",
                "deploy",
                "cmd",
                "internal",
                "go.mod",
                "go.sum",
            ],
            env=env,
        )
        tree = checked(["git", "write-tree"], env=env).stdout.decode().strip()
        return (
            checked(
                [
                    "git",
                    "commit-tree",
                    tree,
                    "-p",
                    "HEAD",
                    "-m",
                    "Unreferenced rehearsal source snapshot",
                ],
                env=env,
            )
            .stdout.decode()
            .strip()
        )
    finally:
        index.unlink(missing_ok=True)


def rebind_mutant(packet, source_root):
    """Rebind one explicit code mutation so it reaches its behavioral failure.

    The saved plan is still the fake provider's input, never an approvable plan
    for the mutated source tag. All RPC payload/source hashes remain real.
    """
    with tarfile.open(packet / "source.bundle") as archive:
        files = {m.name: archive.extractfile(m).read() for m in archive.getmembers()}
    sources = json.loads(files["sources.json"])
    for name in sources:
        if not name.startswith("overlay/"):
            files[name] = (source_root / name).read_bytes().replace(b"\r\n", b"\n")
        sources[name] = {
            "bytes": len(files[name]),
            "sha256": hashlib.sha256(files[name]).hexdigest(),
        }
    spec = json.loads(files["packet.json"])
    spec["sources_sha256"] = hashlib.sha256(encode(sources)).hexdigest()
    save(packet / "sources.json", sources)
    save(packet / "packet.json", spec)
    files["sources.json"] = (packet / "sources.json").read_bytes()
    files["packet.json"] = (packet / "packet.json").read_bytes()
    with (packet / "source.bundle").open("wb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as zipped:
            with tarfile.open(fileobj=zipped, mode="w") as archive:
                for name, data in sorted(files.items()):
                    info = tarfile.TarInfo(name)
                    info.size, info.mode = len(data), 0o644
                    archive.addfile(info, io.BytesIO(data))
    manifest = json.loads((packet / "manifest.json").read_bytes())
    manifest.update(
        sources_sha256=spec["sources_sha256"],
        source_manifest_file_sha256=sha(packet / "sources.json"),
        bundle_sha256=sha(packet / "source.bundle"),
        bundle_bytes=(packet / "source.bundle").stat().st_size,
    )
    save(packet / "manifest.json", manifest)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packet", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mutants", action="store_true")
    parser.add_argument(
        "--case",
        choices=("baseline", "serve-removed", "filter-removed", "engine-exit"),
        default="baseline",
    )
    parser.add_argument(
        "--docker-archive", type=Path, default=ROOT / ".cache/dec077-tools/docker"
    )
    args = parser.parse_args()
    if os.name != "nt":
        raise RuntimeError("rehearse from the production Windows operator")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    packet = output / "packet"
    shutil.copytree(
        args.packet,
        packet,
        ignore=shutil.ignore_patterns(
            "operator", "consumed.json", "control-token.secret", "operator.lock"
        ),
    )
    manifest = json.loads((packet / "manifest.json").read_bytes())
    manifest["account_id_sha256"] = hashlib.sha256(b"rehearsal-account").hexdigest()
    save(packet / "manifest.json", manifest)
    commands = {
        label: [
            sys.executable,
            str(ROOT / "scripts/l4_compat_controller.py"),
            mode,
            "--directory",
            str(packet),
        ]
        for label, mode in (
            ("controller", "execute"),
            ("cleanup", "cleanup"),
            ("inventory", "inventory"),
        )
    }
    save(packet / "commands.json", commands)
    startup = output / "startup"
    startup.mkdir()
    (startup / "sitecustomize.py").write_text(
        "import os\ntry:\n"
        "    import l4_compat_rehearsal_ports\n"
        "    l4_compat_rehearsal_ports.install()\n"
        "except BaseException:\n    os._exit(88)\n"
    )
    build = output / "build"
    build.mkdir()
    shutil.copyfile(
        ROOT / "scripts/l4_compat_rehearsal.Dockerfile", build / "Dockerfile"
    )
    shutil.copyfile(
        ROOT / "scripts/l4_compat_rehearsal_host.py",
        build / "l4_compat_rehearsal_host.py",
    )
    shutil.copyfile(args.docker_archive, build / "docker.tgz")
    assert (
        sha(build / "docker.tgz")
        == "803d433f226db4776e1768fd319fc6c6e4935a456acf84fcc0080818b854bc8f"
    )
    tag = "l4-rehearsal-host:" + uuid.uuid4().hex
    checked(["docker", "build", "-t", tag, build], timeout=900)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    host = "l4-rehearsal-" + uuid.uuid4().hex
    argv = [
        sys.executable,
        str(ROOT / "scripts/l4_compat_deadline.py"),
        "--commands",
        str(packet / "commands.json"),
        "--output",
        str(output / "supervisor"),
    ]
    environment = {
        **os.environ,
        "PYTHONPATH": os.pathsep.join(
            [str(startup), str(ROOT / "python/src"), str(ROOT / "scripts")]
        ),
        "L4_REVIEW_TARGET": snapshot(),
        "L4_OWNER_APPROVED_HASH": manifest["sealed_plans"]["create_sha256"],
        "L4_REHEARSAL_ROOT": str(output),
        "L4_REHEARSAL_HOST": host,
        "L4_REHEARSAL_PORT": str(port),
        "L4_REHEARSAL_REFUSAL": "1",
    }
    summary = {
        "basis": "$0 CPU fake pipeline rehearsal; no GPU/native-vLLM fitness or performance result",
        "input_packet": {
            "manifest_sha256": sha(args.packet / "manifest.json"),
            "sources_sha256": sha(args.packet / "sources.json"),
            "bundle_sha256": sha(args.packet / "source.bundle"),
            "plan_sha256": sha(args.packet / "terraform/create.tfplan"),
        },
        "substitutions": SUBSTITUTIONS,
        "native_checks_not_reached": UNREACHED,
        "supervisor": {
            "argv": argv,
            "cwd": str(ROOT),
            "output": str(output / "supervisor"),
            "environment": {
                k: v
                for k, v in environment.items()
                if k.startswith("L4_") or k == "PYTHONPATH"
            },
        },
        "provider_calls": 0,
        "attempts": [],
    }

    def attempt(label):
        started = time.monotonic()
        result = run(argv, env=environment, timeout=1800)
        (output / (label + ".log")).write_bytes(result.stdout + result.stderr)
        latest = max(
            (output / "supervisor").glob("attempt-*/deadline.json"),
            key=lambda p: p.stat().st_mtime_ns,
        )
        receipt = json.loads(latest.read_bytes())
        stages = latest.parent / "stages.jsonl"
        receipt["host_stages"] = (
            [json.loads(line) for line in stages.read_text().splitlines()]
            if stages.exists()
            else []
        )
        item = {
            "label": label,
            "exit_code": result.returncode,
            "elapsed_seconds": time.monotonic() - started,
            "receipt": receipt,
            "consumed": (packet / "consumed.json").exists(),
        }
        summary["attempts"].append(item)
        save(output / "summary.json", summary)
        return item, latest.parent

    try:
        checked(
            [
                "docker",
                "run",
                "-d",
                "--privileged",
                "--name",
                host,
                "-p",
                f"127.0.0.1:{port}:22281",
                tag,
            ]
        )
        for _ in range(150):
            if run(["docker", "exec", host, "docker-real", "info"]).returncode == 0:
                break
            time.sleep(0.2)
        refusal, refusal_directory = attempt("price-refusal")
        assert refusal["exit_code"] != 0 and not refusal["consumed"]
        assert (
            refusal["receipt"]["cleanup_exit"]
            == refusal["receipt"]["inventory_exit"]
            == 0
        )
        assert (
            "l4:price_dimension:compute"
            in (refusal_directory / "controller.log").read_text()
        )
        environment["L4_REHEARSAL_REFUSAL"] = "0"
        success, directory = attempt("success")
        if args.case != "baseline":
            assert success["exit_code"] != 0 and success["consumed"]
            assert (
                success["receipt"]["cleanup_exit"]
                == success["receipt"]["inventory_exit"]
                == 0
            )
            logs = b"\n".join(p.read_bytes() for p in directory.rglob("*.log"))
            if args.case == "serve-removed":
                assert b"l4:service starting loopback HTTP server" in logs
                assert any(
                    s["stage"] == "ssm-shell" and s["exit_code"] != 0
                    for s in success["receipt"]["host_stages"]
                )
            else:
                archive = directory / "operator/receipts.tar.gz"
                with tarfile.open(archive) as stream:
                    summary["inventory_files_verified"] = verify_archive_inventory(
                        stream
                    )
                    logs += stream.extractfile("bootstrap.log").read()
                    if args.case == "engine-exit":
                        stages = json.load(
                            stream.extractfile("results/host-stages.json")
                        )
                        assert stages["engine_readiness"]["exit_code"] == 1
                        assert stages["engine_readiness"]["elapsed_seconds"] < 5
                        summary["host_stages"] = stages
                assert (
                    b"l4:engine_died"
                    if args.case == "engine-exit"
                    else b"l4:audit_chat_inventory"
                ) in logs
            summary[
                "adverse_startup_passed"
                if args.case == "engine-exit"
                else "mutant_killed"
            ] = args.case
            return
        assert success["exit_code"] == 0 and success["receipt"]["complete"]
        archive = directory / "operator/receipts.tar.gz"
        retrieval = json.loads((directory / "operator/retrieval.json").read_bytes())
        assert (
            sha(archive) == retrieval["sha256"]
            and archive.stat().st_size == retrieval["bytes"]
        )
        with tarfile.open(archive) as stream:
            report = json.load(stream.extractfile("results/compatibility.json"))
            summary["host_stages"] = json.load(
                stream.extractfile("results/host-stages.json")
            )
            summary["host_commands"] = json.load(
                stream.extractfile("results/host-commands.json")
            )
            summary["inventory_files_verified"] = verify_archive_inventory(stream)
        assert (
            report["audit_rows"]["health"] > 0 and report["audit_rows"]["metrics"] > 0
        )
        summary.update(
            compatibility=report,
            archive={"bytes": archive.stat().st_size, "sha256": sha(archive)},
        )
        save(output / "summary.json", summary)
        if args.mutants:
            summary["mutants"] = []
            for case, name, original, replacement in (
                (
                    "serve-removed",
                    "scripts/l4_compat_service.py",
                    "server(host).serve_forever()",
                    "server(host)",
                ),
                (
                    "filter-removed",
                    "scripts/l4_compat_host.py",
                    'if r["method"] == "POST" and r["uri"] == "/v1/chat/completions"',
                    "if True",
                ),
                (
                    "engine-exit",
                    "scripts/l4_compat_fake_engine.py",
                    "        serve()",
                    "        raise SystemExit(23)",
                ),
            ):
                clone = output / (case + "-source")
                checked(["git", "clone", "--shared", "--no-checkout", ROOT, clone])
                checked(["git", "checkout", environment["L4_REVIEW_TARGET"]], cwd=clone)
                source = clone / name
                code = source.read_text()
                assert code.count(original) == 1
                source.write_text(code.replace(original, replacement))
                mutated_packet = output / (case + "-packet")
                shutil.copytree(args.packet, mutated_packet)
                rebind_mutant(mutated_packet, clone)
                destination = output / case
                child_environment = {
                    **os.environ,
                    "PYTHONPATH": str(clone / "python/src"),
                }
                started = time.monotonic()
                result = run(
                    [
                        sys.executable,
                        clone / "scripts/rehearse_l4_compat.py",
                        "--packet",
                        mutated_packet,
                        "--output",
                        destination,
                        "--case",
                        case,
                        "--docker-archive",
                        args.docker_archive.resolve(),
                    ],
                    cwd=clone,
                    env=child_environment,
                    timeout=1800,
                )
                (output / (case + ".log")).write_bytes(result.stdout + result.stderr)
                mutant = json.loads((destination / "summary.json").read_bytes())
                summary["mutants"].append(
                    {
                        "case": case,
                        "exit_code": result.returncode,
                        "elapsed_seconds": time.monotonic() - started,
                        "receipt": mutant,
                    }
                )
                save(output / "summary.json", summary)
                key = (
                    "adverse_startup_passed"
                    if case == "engine-exit"
                    else "mutant_killed"
                )
                assert result.returncode == 0 and mutant.get(key) == case
    finally:
        log = run(["docker", "logs", host])
        (output / "host-container.log").write_bytes(log.stdout + log.stderr)
        checked(["docker", "rm", "-f", host])
        save(output / "summary.json", summary)


if __name__ == "__main__":
    main()
