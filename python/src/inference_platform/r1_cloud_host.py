"""Production host actions for the source-bound R1 SSM lifecycle adapter."""

import argparse
import json
import os
import shutil
import subprocess
import tarfile
import time
from pathlib import Path

from .r1_export_probe import measure
from .r1_fixture_target import coverage_report, window_q
from .r1_launcher import backend_command
from .r1_manifest import load
from .r1_session import Session
from .r1_spec import IMAGE, SPEC_COMMIT, encoded
from .r1_transport import HTTP, request
from .stage_c_tokenizer import pinned_tokenizer

REDIS_IMAGE = (
    "redis:8.2.9-alpine@sha256:30abb90e62f14b737010746def3ba99cc79fe19dcdb3d37b41f21fc62e7da19d"
)


def command(argv, deadline):
    return subprocess.check_output(argv, timeout=max(0.001, deadline - time.time()))


def agent(directory, config):
    path = directory / "agent.json"
    path.write_bytes(encoded(config) + b"\n")
    with (directory / "agent.log").open("ab") as log:
        child = subprocess.Popen(
            [
                os.sys.executable,
                "-m",
                "inference_platform.r1_agent",
                "--config",
                str(path),
                "--bind",
                "0.0.0.0:8001",
            ],
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    (directory / "agent-pid.json").write_bytes(encoded({"pid": child.pid}))


def urls(context):
    hosts = context["hosts"]
    return {
        "backends": [f"http://{hosts[f'gpu-{i}']['private_ip']}:8000" for i in range(2)],
        "backend_agents": [f"http://{hosts[f'gpu-{i}']['private_ip']}:8001" for i in range(2)],
        "gateways": [f"http://{hosts['service']['private_ip']}:{8080 + i}" for i in range(2)],
        "service_agent": f"http://{hosts['service']['private_ip']}:8001",
        "generator_agent": f"http://{hosts['generator']['private_ip']}:8001",
    }


def ready(directory, context, deadline):
    shutil.copyfile("/opt/r1/cloud-init-status.json", directory / "cloud-init-status.json")
    pinned_tokenizer(fetch=True)
    role = context["role"]
    config = {
        "role": "backend" if role.startswith("gpu") else role,
        "directory": str(directory / "logs"),
        "token": context["agent_token"],
    }
    if role.startswith("gpu"):
        cache = directory / "weights"
        cache.mkdir()
        command(["docker", "pull", IMAGE], deadline)
        launcher = backend_command(str(cache))
        launcher.insert(2, "--detach")
        command(launcher, deadline)
        config["weight_cache"] = str(cache)
        while time.time() < deadline:
            try:
                request(
                    "http://127.0.0.1:8000/health",
                    time.perf_counter() + min(5, deadline - time.time()),
                )
                break
            except OSError:
                time.sleep(1)
        else:
            raise TimeoutError("resident pinned vLLM/model readiness")
    else:
        route = json.loads(command(["ip", "-json", "route", "get", "1.1.1.1"], deadline))[0]
        config.update(
            cpu_budget=8,
            catalog_memory_bytes=context["cpu_memory_bytes"],
            memory_catalog_source=context["cpu_memory_source"],
            nic=route["dev"],
            nic_limit_bps=3125000000,
            nic_limit_source="AWS c6i.2xlarge rated baseline 3.125Gbit/s; Round88 catalog",
        )
        if role == "service":
            command(
                [
                    "docker",
                    "run",
                    "-d",
                    "--name",
                    "r1-redis",
                    "--publish",
                    "127.0.0.1:6379:6379",
                    REDIS_IMAGE,
                ],
                deadline,
            )
            redis = json.loads(command(["docker", "inspect", "r1-redis"], deadline))[0]
            config.update(
                **{k: v for k, v in urls(context).items() if k in {"backends", "backend_agents"}},
                binary=str(directory / "payload/bin/gateway"),
                redis="127.0.0.1:6379",
                namespace=context["session_id"],
                credential=context["credential"],
                secret=context["secret"],
                resource_pids=[redis["State"]["Pid"]],
                export_minimum_bytes_per_second=0,
                export_link_rate_source="pending physical probe",
            )
    agent(directory, config)
    action = "/identity" if role.startswith("gpu") else "/resources"
    while time.time() < deadline:
        try:
            request(
                "http://127.0.0.1:8001" + action,
                time.perf_counter() + min(5, deadline - time.time()),
                token=context["agent_token"],
            )
            break
        except OSError:
            time.sleep(0.2)
    else:
        raise TimeoutError("authenticated host agent readiness")


def probe(directory, context, deadline):
    config = urls(context)
    clock = {"source": "chrony tracking on both distinct CPU hosts", "captured_at": time.time()}
    usable = []
    for key in ("service_agent", "generator_agent"):
        _, data = request(
            config[key] + "/resources",
            time.perf_counter() + min(5, deadline - time.time()),
            token=context["agent_token"],
        )
        receipt = json.loads(data)
        (directory / (key + "-resources.json")).write_bytes(encoded(receipt))
        usable.append(receipt["clock_usable"])
    clock["usable"] = all(usable)
    if not clock["usable"]:
        raise ValueError("physical chrony clock evidence unusable")
    receipt = measure(
        config["service_agent"], context["agent_token"], timeout=min(60, deadline - time.time())
    )
    (directory / "physical-export-probe.json").write_bytes(encoded(receipt))
    request(
        config["service_agent"] + "/export/link",
        time.perf_counter() + min(5, deadline - time.time()),
        receipt,
        token=context["agent_token"],
    )
    manifest, _ = load(
        directory / "payload/manifests",
        SPEC_COMMIT,
        spec_artifact=directory / "payload/docs/R1_PRE_REGISTRATION.md",
    )
    config.update(
        agent_token=context["agent_token"],
        credential=context["credential"],
        manifest_sha256=manifest["manifest_sha256"],
        clock_evidence=clock,
    )
    (directory / "http.json").write_bytes(encoded(config))


def run(directory, context, deadline):
    manifest, banks = load(
        directory / "payload/manifests",
        SPEC_COMMIT,
        spec_artifact=directory / "payload/docs/R1_PRE_REGISTRATION.md",
    )
    config = json.loads((directory / "http.json").read_bytes())
    io = HTTP(config, manifest, banks, directory / "session")
    # The bundle contains verified source bytes and its Git source commit, without
    # shipping private Git history to hosts. Pass that bound identity explicitly.
    result = Session(
        io,
        manifest,
        directory / "session",
        session_seconds=deadline - time.time() + 900,
        head=context["source_head"],
    ).run()
    # Gateway bytes are recovered from the service host once, then reconstructed
    # locally into the same canonical service-export format/hash.
    (directory / "session/service-export-metadata.json").write_bytes(
        encoded(
            {
                "configurations": [
                    {k: v for k, v in item.items() if k != "client_duration_s"}
                    for item in io.receipts
                ]
            }
        )
    )
    if result["frozen"]:
        (directory / "session/archive-sizing.json").write_bytes(
            encoded(
                {
                    "planning_q_upper": 400,
                    "frozen_hardware_q": result["frozen"]["q"],
                    "within_planning_q": result["frozen"]["q"] <= 400,
                    "expected_final_wire_bytes_at_upper_q": 100_000_000,
                    "floor_bytes_per_second": 500_000,
                    "expected_transfer_s": 200,
                    "export_window_s": 600,
                    "advisory_only": True,
                    "source": "Round89 archive-sizing receipt; physical q is not bounded by the fixture",
                }
            )
        )
        http = json.loads((directory / "payload/readiness/http-strict.json").read_bytes())
        window = json.loads((directory / "payload/readiness/generator-600s.json").read_bytes())
        comparison = coverage_report(
            result["frozen"]["q"],
            min(x["wall_delivered_rate"] for x in http["windows"] if x["name"].startswith("run")),
            window_q(window),
        )
        comparison["http_source_head"] = http["head"]
        (directory / "session/fixture-coverage.json").write_bytes(encoded(comparison))
    if result["error"]:
        raise RuntimeError("R1 session failed; partial records retained")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--action", choices=("ready", "probe", "measure", "close", "export"), required=True
    )
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--deadline-unix-s", type=float, required=True)
    args = parser.parse_args()
    directory, deadline = args.directory, args.deadline_unix_s
    context = json.loads((directory / "context.json").read_bytes())
    if args.action == "ready":
        ready(directory, context, deadline)
    elif args.action == "probe":
        probe(directory, context, deadline)
    elif args.action == "measure":
        run(directory, context, deadline)
    elif args.action == "close":
        request(
            urls(context)["service_agent"] + "/close",
            time.perf_counter() + max(0, deadline - time.time()),
            {},
            token=context["agent_token"],
        )
    else:
        if (directory / "measure-started.json").exists():
            while not (directory / "measure-terminal.json").exists():
                if time.time() >= deadline:
                    raise TimeoutError("measurement not sealed before recovery export cutoff")
                time.sleep(0.2)
        if context["role"] == "service":
            request(
                "http://127.0.0.1:8001/logs/manifest",
                time.perf_counter() + min(5, deadline - time.time()),
                token=context["agent_token"],
            )
        if context["role"].startswith("gpu"):
            (directory / "logs/vllm.log").write_bytes(
                command(["docker", "logs", "r1-vllm"], deadline)
            )
        # Frozen session plus host logs and physical receipts; no control context,
        # agent credentials or environment files in the exported archive.
        if (directory / "incremental-active").exists():
            print(json.dumps({"action": args.action, "complete": True, "incremental": True}))
            return  # Bootstrap seals remaining tails after this process terminates.
        with tarfile.open(directory / "evidence.tar.gz", "w:gz", compresslevel=1) as archive:
            for name in (
                "session",
                "logs",
                "agent.log",
                "disk-before-pull.json",
                "physical-export-probe.json",
                "service_agent-resources.json",
                "generator_agent-resources.json",
            ):
                path = directory / name
                if path.exists():
                    archive.add(path, arcname=name)
    print(json.dumps({"action": args.action, "complete": True}))


if __name__ == "__main__":
    try:
        main()
    finally:
        # The bootstrap starts the marker before launching uv. This finally runs
        # even on a recorded Session failure; mutable sessions are never archived.
        import sys

        if "--action" in sys.argv and sys.argv[sys.argv.index("--action") + 1] == "measure":
            destination = Path(sys.argv[sys.argv.index("--directory") + 1])
            (destination / "measure-terminal.json").write_bytes(
                encoded({"ended_unix_s": time.time()})
            )
