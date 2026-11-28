"""CPU-only rehearsal of the DEC-107 L4 schedule, evidence and resource gates."""

import argparse
import gzip
import hashlib
import json
import os
import secrets
import subprocess
import time
import urllib.request
from collections import Counter
from pathlib import Path

from inf061_packet import CAP_USD, GATEWAY_START_SECONDS, time_envelope

ROOT = Path(__file__).resolve().parents[1]
PLAN = ROOT / "docs/INF061_FINAL_PLAN.json"


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def save(path, data):
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run(*argv, timeout=240, **kwargs):
    return subprocess.run(argv, check=True, timeout=timeout, **kwargs)


def read(url):
    with urllib.request.urlopen(url, timeout=60) as response:
        return response.read()


def verify_plan():
    raw = PLAN.read_bytes()
    plan = json.loads(raw)
    require(plan["execution"] == "review-only", "execution_permission")
    for name, sha in plan["bindings"].items():
        require(digest((ROOT / name).read_bytes()) == sha, "bound_artifact")
    order = [(x["precision"], x["max_num_seqs"]) for x in plan["starts"]]
    require(
        order == [("bf16", 16), ("bf16", 32), ("bf16", 64), ("fp8", 64), ("awq", 64)],
        "engine_order",
    )
    time_envelope(plan)
    require(plan["operator_timer_s"] >= plan["gpu_timer_s"] + 900, "operator_timer")
    inputs = plan["pricing"]
    forecast = (
        2
        * inputs["margin"]
        * (
            plan["gpu_timer_s"] / 3600 * inputs["gpu_hourly_usd"]
            + plan["operator_timer_s"] / 3600 * inputs["operator_hourly_usd"]
            + inputs["fixed_usd_per_attempt"]
        )
    )
    remaining = round(plan["cap_usd"] - plan.get("prior_paid_estimate_usd", 0), 6)
    require(
        plan["cap_usd"] == CAP_USD
        and round(forecast, 6) == plan["forecast_usd"] <= remaining <= CAP_USD,
        "cap",
    )
    require(
        plan["quality"]["count"] == 1319 and plan["quality"]["max_tokens"] == 512,
        "quality_scope",
    )
    require(
        plan["stage_c"]["a_quota"] <= 20 - plan["stage_c"]["b_peak"], "tenant_bound"
    )
    return plan, digest(raw)


def load_quality(pin):
    from rehearse_inf061_l4 import quality_cases

    source = read(pin["url"])
    require(digest(source) == pin["source_sha256"], "dataset_hash")
    # The full signed-off set uses every row in committed source order.
    lines = source.splitlines()
    require(len(lines) == pin["count"], "dataset_count")
    return quality_cases_from_bytes(source, lines, pin, quality_cases)


def quality_cases_from_bytes(source, lines, pin, load):
    from tempfile import TemporaryDirectory

    canonical = b"\n".join(lines) + b"\n"
    require(digest(canonical) == pin["subset_sha256"], "dataset_lines_hash")
    with TemporaryDirectory(prefix="inf061-quality-") as directory:
        path = Path(directory) / "quality.jsonl"
        path.write_bytes(source)
        return load(path, pin)


def check_model(model, model_id):
    revision = model["revision"]
    uri = "https://huggingface.co/" + model_id
    lookup = "https://huggingface.co/api/models/" + model_id
    listing = json.loads(read(f"{lookup}/revision/{revision}?blobs=true"))
    require(listing["sha"] == revision, "model_revision")
    if "base_model" in model:
        require(
            listing["cardData"]["base_model"] == model["base_model"], "awq_ancestry"
        )
    config = json.loads(read(f"{uri}/resolve/{revision}/tokenizer_config.json"))
    require(
        digest(config["chat_template"].encode()) == model["chat_template_sha256"],
        "chat_template_hash",
    )
    files = {entry["rfilename"]: entry for entry in listing["siblings"]}
    for name, expected in model["files"].items():
        row = files[name]
        require(row["size"] == expected["bytes"], "model_file_size")
        actual = (
            row["lfs"]["sha256"]
            if "lfs" in row
            else digest(read(f"{uri}/resolve/{revision}/{name}"))
        )
        require(actual == expected["sha256"], "model_file_sha256")
    return len(model["files"])


class MockClock:
    def __init__(self, limit, reserve):
        self.now = 0
        self.limit = limit
        self.reserve = reserve

    def use(self, seconds, remaining_work=0):
        require(
            self.now + seconds + remaining_work + self.reserve <= self.limit,
            "deadline_reserve",
        )
        self.now += seconds


def quality_pass(cases, arm):
    from rehearse_inf061_l4 import score

    results = []
    for index, (_, answer) in enumerate(cases):
        wrong = {
            "bf16-first": {1, 2, 3},
            "bf16-repeat": {1, 3, 4},
            "fp8": {2, 4, 5},
            "awq": {2, 5, 6},
        }[arm]
        if index in wrong:
            results.append("truncated" if index % 2 else "invalid")
        else:
            require(score(f"FINAL: {answer:f}", answer), "quality_scorer")
            results.append("exact")
    return results


def pairs(reference, candidate):
    tally = Counter(
        zip(
            (v == "exact" for v in reference),
            (v == "exact" for v in candidate),
            strict=True,
        )
    )
    return {
        "wins": tally[False, True],
        "losses": tally[True, False],
        "discordant": tally[False, True] + tally[True, False],
        "both_exact": tally[True, True],
        "both_other": tally[False, False],
    }


def rehearse(plan, cases, work, fault=None):
    from rehearse_inf061_l4 import stream_fixture

    total = time_envelope(plan)
    caps = plan["deadline_seconds"]
    reserve = caps["retrieval"] + caps["teardown"]
    clock = MockClock(plan["gpu_timer_s"], reserve)
    phases, quality = [], {}
    clock.use(caps["provision_and_stage"])
    stream = stream_fixture()
    require(
        stream["outcome"] == "completed" and stream["completion_tokens"] == 2, "sse"
    )
    for arm in plan["starts"]:
        start = {"arm": arm["name"], "startup": "mock_ready", "stages": []}
        phases.append(start)
        clock.use(600)
        if arm["precision"] == "fp8" and fault == "fp8":
            start["startup"] = "mock_fp8_memory_refusal"
            continue
        clock.use(GATEWAY_START_SECONDS)
        for section in arm["stages"]:
            if section == "A":
                for rate in plan["stage_a"]["rates"]:
                    clock.use(165)
                    start["stages"].append(
                        {"stage": "A", "offer_rate": rate, "sse": stream}
                    )
                clock.use(60)
            if section == "B":
                for concurrency in plan["stage_b"]["concurrencies"]:
                    clock.use(240)
                    # Synthetic block readback to exercise the bound, independent
                    # of the configured sequence cap and never a GPU prediction.
                    blocks = 3891 if arm["precision"] == "bf16" else 8100
                    require(
                        64 > blocks // plan["stage_b"]["blocks_per_prompt"],
                        "kv_bound_not_reached",
                    )
                    start["stages"].append(
                        {
                            "stage": "B",
                            "concurrency": concurrency,
                            "mock_KV_blocks": blocks,
                        }
                    )
                clock.use(60)
            if section == "C":
                for name in plan["stage_c"]["arms"]:
                    clock.use(GATEWAY_START_SECONDS + 195)
                    start["stages"].append({"stage": "C", "fixture": name})
            if section.startswith("quality-"):
                clock.use(plan["quality"]["pass_limit_s"])
                quality[section.removeprefix("quality-")] = quality_pass(
                    cases, section.removeprefix("quality-")
                )
    compared = {"bf16_flip_floor": pairs(quality["bf16-first"], quality["bf16-repeat"])}
    if "fp8" in quality:
        compared["fp8_vs_bf16"] = pairs(quality["bf16-first"], quality["fp8"])
    compared["awq_vs_repeated_bf16"] = pairs(quality["bf16-repeat"], quality["awq"])
    raw = json.dumps(
        {
            "phases": phases,
            "quality": {k: dict(Counter(v)) for k, v in quality.items()},
            "paired": compared,
            "elapsed_virtual_s": clock.now,
        },
        sort_keys=True,
    ).encode()
    archive = gzip.compress(raw, mtime=0)
    destination = work / ("fp8-refused.json.gz" if fault else "mock-session.json.gz")
    destination.write_bytes(archive)
    received = destination.read_bytes()
    require(
        digest(received) == digest(archive) and gzip.decompress(received) == raw,
        "retrieval_hash",
    )
    damaged = received[:-1] + bytes([received[-1] ^ 1])
    require(digest(damaged) != digest(archive), "retrieval_mutation_accepted")
    clock.now += reserve
    require(clock.now <= total, "teardown_slot")
    return {
        "sha256": digest(archive),
        "bytes": len(archive),
        "mock_teardown": True,
        **json.loads(raw),
    }


def rehearse_containment(plan, work, *, fail=("fp8-64", "B"), fail_cleanup=False):
    """Use the native arm state machine with test-only engine and stage ports."""
    from contextlib import nullcontext

    from inf061_native_host import Benchmark

    class MockHost(Benchmark):
        def __init__(self):
            self.arms = {}
            self.active = None
            self.cleanup = []

        def deadline(self, _):
            return nullcontext()

        def start_engine(self, arm):
            require(self.active is None, "rehearsal_prior_engine_active")
            self.active = arm["name"]
            return {"kv_blocks": 8100}

        def run_arm_stage(self, name, phase, _cases):
            if (name, phase) == fail:
                raise TimeoutError("injected stage error")

        def stop_process(self, label):
            self.cleanup.append((self.active, "gateway"))
            require(label == self.active + "-gateway", "rehearsal_gateway_identity")
            if fail_cleanup and self.active == fail[0]:
                raise OSError("injected cleanup error")

        def remove(self, role):
            require(role == "engine", "rehearsal_engine_role")
            self.cleanup.append((self.active, role))
            self.active = None

    host = MockHost()
    abort = None
    try:
        for arm in plan["starts"]:
            host.run_arm(arm, ())
    except TimeoutError:
        abort = "stage_timeout"
    except OSError:
        abort = "cleanup_error"
    require(host.active is None, "rehearsal_engine_cleanup")
    report = {"arms": host.arms, "cleanup": host.cleanup, "abort": abort}
    save(work / "arm-containment.json", report)
    return report


IMAGE_PROBE = r"""
import ast
import hashlib
import importlib.util
import json
from pathlib import Path

root = Path(importlib.util.find_spec("vllm").origin).parent
files = {
    "dispatch": root / "model_executor/layers/quantization/fp8.py",
    "online": root / "model_executor/layers/quantization/online/fp8.py",
    "kernels": root / "model_executor/kernels/linear/__init__.py",
    "quantization_registry": root / "model_executor/layers/quantization/__init__.py",
    "awq_loader": root / "model_executor/layers/quantization/auto_awq.py",
    "awq_marlin_kernel": root / "model_executor/kernels/linear/mixed_precision/marlin.py",
}
src = {key: path.read_text() for key, path in files.items()}
assert "Fp8PerTensorOnlineLinearMethod" in src["dispatch"]
assert "torch.bfloat16" in src["dispatch"]
assert "class Fp8PerTensorOnlineLinearMethod" in src["online"]
assert "scaled_fp8_quant" in src["online"] and "init_fp8_linear_kernel" in src["online"]
assert "CutlassFP8ScaledMMLinearKernel" in src["kernels"]
fp8_selector = next(node for node in ast.parse(src["kernels"]).body
                    if isinstance(node, ast.FunctionDef) and node.name == "init_fp8_linear_kernel")
assert any(isinstance(node, ast.Constant) and node.value == "Selected %s for %s"
           for node in ast.walk(fp8_selector))
fp8_online = next(node for node in ast.parse(src["online"]).body
                  if isinstance(node, ast.ClassDef) and node.name == "Fp8PerTensorOnlineLinearMethod")
assert any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
           and node.func.id == "init_fp8_linear_kernel"
           and any(kw.arg == "module_name" and ast.unparse(kw.value) == "self.__class__.__name__"
                   for kw in node.keywords)
           for node in ast.walk(fp8_online))
assert '"awq": AutoAWQConfig' in src["quantization_registry"]
assert '"awq_marlin": AutoAWQConfig' in src["quantization_registry"]
assert "return [torch.half, torch.bfloat16]" in src["awq_loader"]
assert "def get_min_capability" in src["awq_loader"] and "return 75" in src["awq_loader"]
assert "choose_mp_linear_kernel(mp_linear_kernel_config)" in src["awq_loader"]
assert "for AutoAWQMarlinLinearMethod" in src["awq_loader"]
assert "Falling back to unoptimized AWQ kernels" in src["awq_loader"]
assert "MarlinLinearKernel" in src["awq_marlin_kernel"]
print(json.dumps({k: hashlib.sha256(v.read_bytes()).hexdigest() for k,v in files.items()}))
"""


def image_check(image):
    proc = run(
        "docker",
        "run",
        "--rm",
        "-i",
        "--network=none",
        "--entrypoint=python3",
        image,
        "-I",
        "-",
        input=IMAGE_PROBE,
        text=True,
        capture_output=True,
        timeout=1800,
    )
    return {
        "image": image,
        "source_sha256": json.loads(proc.stdout),
        "gpu_devices": 0,
        "scope": "pinned image source inspection; SM89 selection and fit checked at paid startup",
    }


def cpu_body(work):
    # This process and its four children share the same Docker cgroup.
    quota, period = Path("/sys/fs/cgroup/cpu.max").read_text().split()
    require(quota != "max" and int(quota) == 4 * int(period), "cpu_cgroup")
    token = secrets.token_urlsafe(32)
    config = {
        "tenants": [
            {
                "tenant_id": "fixture",
                "credential_sha256": digest(token.encode()),
                "models": ["test-model"],
                "max_request_bytes": 4096,
                "max_output_tokens": 128,
                "request_rate_limit": 10000,
                "request_rate_window_ms": 1000,
                "max_concurrent": 128,
            }
        ]
    }
    save(work / "tenants.secret", config)
    (work / "salt.secret").write_text(secrets.token_urlsafe(32))
    env = {
        **os.environ,
        "GOMAXPROCS": "4",
        "CPU_BENCH_CREDENTIAL": token,
        "BACKENDS": "fake-0=http://127.0.0.1:8001,fake-1=http://127.0.0.1:8002",
        "GATEWAY_HTTP_ADDR": "127.0.0.1:8080",
        "REDIS_ADDR": "127.0.0.1:6379",
        "ADMISSION_MODE": "redis",
        "ADMISSION_GLOBAL_CAPACITY": "128",
        "GATEWAY_MAX_CONCURRENT": "128",
        "TENANT_CONFIG_PATH": str(work / "tenants.secret"),
        "CACHE_SALT_SECRET_FILE": str(work / "salt.secret"),
        "OTEL_SDK_DISABLED": "true",
    }
    commands = {
        "redis": [
            "redis-server",
            "--bind",
            "127.0.0.1",
            "--save",
            "",
            "--appendonly",
            "no",
        ],
        "fake_frontend": [
            work / "bench",
            "-mode=fakes",
            "-addresses=127.0.0.1:8001,127.0.0.1:8002",
            "-delay=60ms",
        ],
        "gateway": [work / "gateway"],
        "load_generator": [
            work / "bench",
            "-addresses=http://127.0.0.1:8080,http://127.0.0.1:8080",
            "-concurrency=64",
            "-seconds=15",
            "-rate=32",
            "-output",
            work / "cpu-rows.jsonl.gz",
        ],
    }
    processes = {}

    def spawn(role):
        with (work / (role + ".log")).open("wb") as log:
            processes[role] = subprocess.Popen(
                commands[role], env=env, stdout=log, stderr=log
            )

    def ready():
        with urllib.request.urlopen("http://127.0.0.1:8080/readyz", timeout=1):
            return True

    try:
        for role in ("redis", "fake_frontend", "gateway"):
            spawn(role)
        for _ in range(100):
            try:
                if ready():
                    break
            except OSError:
                time.sleep(0.2)
        else:
            raise ValueError("cpu_gateway_readiness")
        ticks = os.sysconf("SC_CLK_TCK")

        def proc_ticks(process):
            fields = (
                Path(f"/proc/{process.pid}/stat").read_text().rsplit(")", 1)[1].split()
            )
            return int(fields[11]) + int(fields[12])

        before = {name: proc_ticks(proc) for name, proc in processes.items()}
        spawn("load_generator")
        child = processes.pop("load_generator")
        _, status, usage = os.wait4(child.pid, 0)
        child.returncode = os.waitstatus_to_exitcode(status)
        require(child.returncode == 0, "cpu_load_generator")
        cpu = {
            name: (proc_ticks(proc) - before[name]) / ticks
            for name, proc in processes.items()
        }
        cpu["load_generator"] = usage.ru_utime + usage.ru_stime
        with gzip.open(work / "cpu-rows.jsonl.gz", "rt") as stream:
            rows = [json.loads(line) for line in stream]
        measured = [row for row in rows if row["phase"] == "measurement"]
        outcomes = Counter(row["outcome"] for row in measured)
        require(
            sum(outcomes.values()) > 64 and set(outcomes) == {"completed"},
            "cpu_stream_outcomes",
        )
        edges = sorted(
            (row[key], change)
            for row in measured
            for key, change in (("dispatch_ns", 1), ("end_ns", -1))
        )
        active = peak = 0
        for _, change in edges:
            active += change
            peak = max(active, peak)
        require(peak == 64 and active == 0, "cpu_stream_peak")
        save(
            work / "cpu-receipt.json",
            {
                "concurrency": 64,
                "cgroup_cpu_quota": int(quota) / int(period),
                "cpu_seconds": cpu,
                "client_outcomes": outcomes,
                "peak_inflight": peak,
                "wall_workload_seconds": 15,
                "redis": subprocess.check_output(
                    ["redis-server", "--version"], text=True
                ).strip(),
            },
        )
    finally:
        for process in reversed(list(processes.values())):
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=10)
        (work / "tenants.secret").unlink(missing_ok=True)
        (work / "salt.secret").unlink(missing_ok=True)


def cpu_check(work):
    for package, name in (("./cmd/cpu-bench", "bench"), ("./cmd/gateway", "gateway")):
        run(
            "go",
            "build",
            "-o",
            work / name,
            package,
            env={**os.environ, "CGO_ENABLED": "0"},
        )
    image = json.loads((ROOT / "deploy/package-a/pins.json").read_bytes())[
        "python_image"
    ]
    run(
        "docker",
        "run",
        "--rm",
        "--cpus",
        "4",
        "--volume",
        f"{ROOT / 'scripts'}:/scripts:ro",
        "--volume",
        f"{work}:/work",
        "--entrypoint=/bin/sh",
        image,
        "-ec",
        "apt-get update -qq && apt-get install -y -qq --no-install-recommends redis-server"
        " && python /scripts/rehearse_inf061_final.py cpu-body --work /work",
        timeout=360,
    )
    return json.loads((work / "cpu-receipt.json").read_bytes())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "mode", choices=("routine", "kernel-readback", "cpu-body", "mock")
    )
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    work = args.work.resolve()
    if args.mode == "cpu-body":
        cpu_body(work)
        return
    work.mkdir()
    plan, sha = verify_plan()
    cases = load_quality(plan["quality"])
    awq = plan["awq"]
    baseline = plan["model"]
    for key in ("tokenizer.json", "tokenizer_config.json", "vocab.json", "merges.txt"):
        require(
            awq["files"][key]["sha256"] == baseline["files"][key]["sha256"],
            "tokenizer_parity",
        )
    require(
        awq["chat_template_sha256"] == baseline["chat_template_sha256"],
        "chat_template_parity",
    )
    require(
        awq["base_model"] == plan["model_id"]
        and awq["base_revision_for_comparison"] == baseline["revision"],
        "awq_base",
    )
    result = {
        "plan_sha256": sha,
        "model_files_verified": check_model(baseline, plan["model_id"]),
        "awq_files_verified": check_model(awq, awq["model_id"]),
        "tokenizer_template_parity": True,
    }
    result["full_mock"] = rehearse(plan, cases, work)
    result["fp8_arm_refusal"] = rehearse(plan, cases, work, fault="fp8")
    containment = rehearse_containment(plan, work)
    require(
        containment["abort"] is None
        and containment["arms"]["fp8-64"]["failure"]
        == {"stage": "B", "reason": "timeout"}
        and containment["arms"]["awq-64"]["status"] == "completed"
        and containment["cleanup"][-4:]
        == [
            ("fp8-64", "gateway"),
            ("fp8-64", "engine"),
            ("awq-64", "gateway"),
            ("awq-64", "engine"),
        ],
        "stage_containment",
    )
    result["fp8_stage_b_containment"] = containment
    try:
        MockClock(20, 10).use(11)
    except ValueError as exc:
        require(str(exc) == "deadline_reserve", "wrong_deadline_refusal")
        result["deadline_refusal"] = str(exc)
    else:
        raise ValueError("deadline mutation accepted")
    if args.mode in {"routine", "kernel-readback"}:
        result["fp8_image"] = image_check(plan["image"])
    if args.mode == "routine":
        result["four_cpu"] = cpu_check(work)
    save(work / "rehearsal-receipt.json", result)
    print(
        json.dumps(
            {k: result[k] for k in result if k not in {"full_mock", "fp8_arm_refusal"}},
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
