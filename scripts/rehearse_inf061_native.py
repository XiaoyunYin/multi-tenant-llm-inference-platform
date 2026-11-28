"""Exercise the sealed native workload and receipt path on a routine CPU host."""

import argparse
import hashlib
import json
import secrets
import shutil
import subprocess
import sys
import tarfile
import threading
import time
from pathlib import Path
from urllib.request import Request, urlopen

import inf061_packet as packet
from inf060_probe_host import env
from inf060_probe_spec import check, engine, facts, load, request_manifest, save
from inf061_native_host import CPU_STAGE_WAIT_SECONDS, CPU_WINDOW_DIVISOR
from inference_platform.package_a_operator import Ports
from l4_compat_service import L4Host
from package_a_host import server
from prepare_inf060_probe import PILOT, ROOT


class LoopbackTransfer:
    """Use the production receiver with local HTTP in place of the SSM tunnel."""

    retrieve = Ports.retrieve
    manifest = {}
    host = "routine-loopback"

    def __init__(self, endpoint, token, runtime):
        self.endpoint, self.token, self.runtime = endpoint, token, runtime
        self.status_answered = False

    def request(self, path, data=None, *, end):
        check(time.time() < end, "rehearsal_transfer_deadline")
        request = Request(
            self.endpoint + path,
            data=data,
            headers={"Authorization": "Bearer " + self.token},
        )
        with urlopen(request, timeout=max(0.01, end - time.time())) as response:
            data = response.read(1024**2 + 1)
            if path == "/status":
                self.status_answered = True
            return data, response.headers


def prepare(root):
    repo = root / "repo"
    for path in ("cmd", "internal", "scripts", "python/src"):
        shutil.copytree(
            ROOT / path,
            repo / path,
            ignore=shutil.ignore_patterns("__pycache__"),
        )
    for path in ("go.mod", "go.sum", "deploy/package-a/pins.json"):
        target = repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / path, target)
    plan = ROOT / "docs/INF061_FINAL_PLAN.json"
    shutil.copyfile(plan, repo / "benchmark.json")
    config = load(plan)
    pin = config["quality"]
    with urlopen(pin["url"], timeout=45) as response:
        data = response.read(1024**2 + 1)
    dataset = repo / "quality.jsonl"
    dataset.write_bytes(data)
    check(
        len(data) <= 1024**2 and facts(dataset)["sha256"] == pin["source_sha256"],
        "quality_dataset_binding",
    )
    package_pins = load(repo / "deploy/package-a/pins.json")
    pilot = load(ROOT / PILOT / "manifest.json")["pins"]
    save(
        repo / "tools.json",
        {
            "go": package_pins["go"],
            "redis": pilot["redis"],
            "vllm": pilot["vllm"],
            "prometheus": config["observability"]["prometheus"],
        },
    )
    save(repo / "engine.json", engine())
    save(repo / "requests.json", request_manifest())
    save(root / "runtime.json", {"weights_timeout_s": 1200})
    return config


def check_gateway(read, label, plan):
    gateway = read("gateway-env-" + label)
    sanity = read("gateway-sanity-" + label)
    tenants = {row["tenant_id"]: row for row in gateway["tenant_file"]["tenants"]}
    check(
        set(tenants) == set(sanity) == {"a", "b", "q"}
        and not any("credential_sha256" in row for row in tenants.values())
        and tenants["q"]["max_concurrent"] == plan["quality"]["concurrency"]
        and "setup_backend_id" not in tenants["q"]
        and gateway["ADMISSION_LEASE"] == "300s"
        and gateway["GATEWAY_TOTAL_TIMEOUT"] == "240s",
        "rehearsal_gateway_environment",
    )
    for tenant, row in sanity.items():
        upstream = row["upstream"]
        timed = tenant != "q"
        check(
            row["http_status"] == 200
            and upstream["include_usage"] is True
            and (
                upstream["ignore_eos"] is True
                if timed
                else upstream["ignore_eos"] in (None, False)
            ),
            "rehearsal_upstream_contract",
        )
        if timed:
            check(
                tenants[tenant]["setup_backend_id"] == "vllm-0"
                and row["outcome"] == "completed"
                and row["max_tokens"]
                == row["completion_tokens"]
                == plan["stage_a"]["output_cap"],
                "rehearsal_sanity_usage",
            )
    return gateway, sanity


def verify(archive, plan):
    with tarfile.open(archive, "r:gz") as stream:

        def read(path):
            return json.load(stream.extractfile("results/" + path + ".json"))

        benchmark = read("benchmark")
        arms = benchmark["arms"]
        check(
            benchmark["start_order"] == [arm["name"] for arm in plan["starts"]],
            "rehearsal_start_order",
        )
        check(
            all(row["status"] == "completed" for row in arms.values()),
            "rehearsal_arm_failed",
        )
        check(
            arms["fp8-64"]["kernel"] == "CutlassFP8ScaledMMLinearKernel"
            and arms["awq-64"]["kernel"] == "MarlinLinearKernel",
            "rehearsal_kernel_parser",
        )
        calls = read("native-method-calls")
        required = {
            "run",
            "prepare_benchmark",
            "run_arm",
            "run_arm_stage",
            "gateway",
            "start_engine",
            "measure",
            "send",
            "noisy",
        }
        check(
            required <= calls.keys() and calls["start_engine"] == 5,
            "rehearsal_native_calls",
        )
        labels = [arm["name"] + "-gateway" for arm in plan["starts"]]
        labels += [f"stage-c-{i}" for i in range(len(plan["stage_c"]["arms"]))]
        gateways = {label: check_gateway(read, label, plan) for label in labels}
        check(
            calls["gateway"] == calls["sanity"] == len(labels), "rehearsal_sanity_count"
        )
        quality = {}
        cells = {}
        invalid = {}
        for row in plan["starts"]:
            name = row["name"]
            for phase in row["stages"]:
                if phase == "A":
                    names = [f"{name}-a-{rate}" for rate in plan["stage_a"]["rates"]]
                elif phase == "B":
                    names = [f"{name}-b-{c}" for c in plan["stage_b"]["concurrencies"]]
                elif phase == "C":
                    names = [f"{name}-c-{a}" for a in plan["stage_c"]["arms"]]
                else:
                    scores = read(phase)
                    check(
                        len(scores["scores"]) == 8
                        and set(scores["counts"]) <= {"exact", "wrong"},
                        "rehearsal_quality_slice",
                    )
                    quality[phase] = scores["counts"]
                    continue
                for cell in names:
                    result = read(cell)
                    summary = result["b"] if phase == "C" else result["summary"]
                    rows = (
                        result["a_rows"] + result["b_rows"]
                        if phase == "C"
                        else result["rows"]
                    )
                    cap = plan["stage_" + phase.lower()]["output_cap"]
                    check(
                        all(
                            r["http_status"] == 200 and r["completion_tokens"] == cap
                            for r in rows
                            if r["outcome"] == "completed"
                        ),
                        "rehearsal_cell_usage",
                    )
                    completed = summary["outcomes"].get("completed", 0)
                    samples = result["gauges"]["samples"]
                    cells[cell] = {
                        "scheduled": summary["scheduled"],
                        "completed": completed,
                        "max_tokens": cap,
                        "cap_matched_completions": completed,
                        "gauge_samples": samples,
                    }
                    if not completed:
                        invalid[cell] = summary["outcomes"]
        if invalid:
            print(json.dumps({"fixture_zero_completion_cells": invalid}))
        check(not invalid, "rehearsal_cell_completion")
        # Closed-loop CPU cells may finish inside one 500 ms collection
        # tick. Keep the individual counts and require real samples in
        # every serving start's recorded cells.
        for name in arms:
            check(
                any(
                    cell.startswith(name + "-") and row["gauge_samples"] > 0
                    for cell, row in cells.items()
                ),
                "rehearsal_arm_missing_gauges:" + name,
            )
        stage_models = read("operation-stage-models")
        check(stage_models["exit_code"] == 0, "rehearsal_model_stage")
        tsdb = read("tsdb-receipt")
        member = stream.getmember("results/tsdb.tar.gz")
        with stream.extractfile(member) as source:
            check(
                member.size == tsdb["bytes"]
                and hashlib.file_digest(source, "sha256").hexdigest() == tsdb["sha256"],
                "rehearsal_snapshot_binding",
            )
        return {
            "arms": arms,
            "cells": cells,
            "quality": quality,
            "tsdb": tsdb,
            "model_stage": {**stage_models, "cpu_wait_limit_s": CPU_STAGE_WAIT_SECONDS},
            "gateway_environments": {
                label: result[0] for label, result in gateways.items()
            },
            "gateway_sanity": {label: result[1] for label, result in gateways.items()},
            "native_method_calls": calls,
            "window_divisor": CPU_WINDOW_DIVISOR,
        }


def run(work):
    work.mkdir(parents=True)
    root = work / "native"
    plan = prepare(root)
    repo = root / "repo"
    entry = repo / "scripts/inf061_native_host.py"
    origin = time.time()
    end = origin + plan["gpu_timer_s"]
    host = L4Host(root, secrets.token_urlsafe(32), "0" * 64, end, origin=origin)
    argv = [
        sys.executable,
        str(entry),
        "launch",
        "--root",
        str(root),
        "--origin",
        str(origin),
        "--end",
        str(end),
        "--cpu-rehearsal",
    ]
    with server(host, port=0) as http:
        thread = threading.Thread(target=http.serve_forever, daemon=True)
        thread.start()
        try:
            host.log = (root / "bootstrap.log").open("xb")
            host.child = subprocess.Popen(
                argv,
                env=env(root, repo),
                cwd=repo,
                stdout=host.log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            try:
                code = host.child.wait(timeout=3200)
            except subprocess.TimeoutExpired:
                host.cancel()
                code = host.child.returncode
            receiver = LoopbackTransfer(
                f"http://127.0.0.1:{http.server_port}", host.token, work
            )
            status = json.loads(receiver.request("/status", end=time.time() + 30)[0])
            retrieval = receiver.retrieve(time.time() + 120)
        finally:
            http.shutdown()
            thread.join()
            host.cancel()
    check(
        retrieval["complete"] and status["runner_exit"] == code, "rehearsal_retrieval"
    )
    archive = work / "inf061-native-receipts.tar.gz"
    binding = packet.capture(work / "receipts.tar.gz", archive)
    if code:
        # Publish only the reduced checks. The launch log stays on the host.
        code_label = "failure-command.json"
        safe = root / "results" / code_label
        print(
            json.dumps(
                {
                    "runner_exit": code,
                    "diagnostic": load(safe) if safe.exists() else None,
                }
            )
        )
    check(code == 0, "rehearsal_native_exit")
    readback = verify(archive, plan)
    readback.update(
        {
            "archive": binding,
            "retrieval": retrieval,
            "entrypoint": "inf061_native_host.py launch",
            "entrypoint_binding": facts(entry),
            "scope": {
                "real": [
                    "Benchmark methods",
                    "pinned model staging and tokenizer",
                    "native gateway",
                    "Redis",
                    "Docker",
                    "Prometheus",
                    "TSDB snapshot",
                    "authenticated freeze and chunk receiver",
                    "receipt allowlist",
                ],
                "substitutions": [
                    "CPU SSE serving containers",
                    "DCGM metrics endpoint",
                    "loopback HTTP instead of SSM tunnel",
                    "CPU fixture scheduling windows and quality slice",
                ],
            },
        }
    )
    save(work / "receipt.json", readback)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", required=True, type=Path)
    args = parser.parse_args()
    run(args.work)
