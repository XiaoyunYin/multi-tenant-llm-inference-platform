"""Native INF-061 GPU adapter over the reviewed single-L4 host primitives."""

import argparse
import concurrent.futures
import contextlib
import copy
import hashlib
import json
import os
import re
import secrets
import sys
import threading
import time
from collections import Counter
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import urlopen

from inf060_probe_host import Phase
from inf060_probe_spec import ENGINE_ENV, MODEL, REMOTE, check, facts, load, save
from inf061_native_workload import (
    Samples,
    offer,
    quality_dataset,
    render_exact,
    run_quality,
    run_window,
    tally,
)
from prometheus_snapshot import snapshot
from rehearse_inf061_final import pairs

RETAINED_ARCHIVE_BYTES = 24 * 1024**2
BASE = Path("/packet")
PIECES = ("tokenizer.json", "tokenizer_config.json", "vocab.json", "merges.txt")
GATEWAY_READY_SECONDS = 60
GATEWAY_SANITY_SECONDS = 45
TOTAL_SECONDS = 240
HARD_STOP_SECONDS = 10
RELEASE_SECONDS = 1
LEASE_MARGIN_SECONDS = 49
CPU_WINDOW_DIVISOR = 40
CPU_STAGE_WAIT_SECONDS = 2100
CPU_FIXTURE = "scripts/inf061_cpu_engine.py"
GATEWAY_EXIT_CODES = {
    b"admission lease must exceed": "admission_lease_guard",
    b"admission coordinator is unavailable": "redis_unavailable",
    b"cannot load tenant configuration": "tenant_configuration",
    b"gateway server failed": "listen_failed",
}


class StartupExit(RuntimeError):
    def __init__(self, reason, exit_code):
        super().__init__("inf061:" + reason)
        self.receipt = {"reason": reason, "exit_code": exit_code}


class CompletionGate(RuntimeError):
    def __init__(self, reason):
        super().__init__("inf061:" + reason)
        self.reason = reason


def require_completion(summary):
    if summary["outcomes"].get("completed", 0) == 0:
        raise CompletionGate("regular_cell_no_completion")


def process_alive(process, log):
    code = process.poll()
    if code is None:
        return
    with log.open("rb") as stream:
        stream.seek(max(0, log.stat().st_size - 4096))
        tail = stream.read(4096)
    reason = next(
        (code for fragment, code in GATEWAY_EXIT_CODES.items() if fragment in tail),
        "gateway_exit",
    )
    raise StartupExit(reason, code)


def gateway_environment(label, global_cap, tenants, salt):
    # Mirror the explicit inputs to cmd/gateway's lease inequality.
    lease = TOTAL_SECONDS + HARD_STOP_SECONDS + RELEASE_SECONDS + LEASE_MARGIN_SECONDS
    return {
        "GATEWAY_HTTP_ADDR": "127.0.0.1:8080",
        "GATEWAY_MAX_CONCURRENT": "768",
        "BACKENDS": "vllm-0=http://127.0.0.1:8000",
        "TENANT_CONFIG_PATH": str(tenants),
        "CACHE_SALT_SECRET_FILE": str(salt),
        "REDIS_ADDR": "127.0.0.1:16379",
        "ADMISSION_NAMESPACE": "inf061-" + label,
        "ADMISSION_GLOBAL_CAPACITY": str(global_cap),
        "ADMISSION_LEASE": f"{lease}s",
        "GATEWAY_TOTAL_TIMEOUT": f"{TOTAL_SECONDS}s",
        "GATEWAY_FIRST_ITEM_TIMEOUT": "180s",
        "GATEWAY_SHUTDOWN_HARD_STOP": f"{HARD_STOP_SECONDS}s",
        "GATEWAY_RELEASE_TIMEOUT": f"{RELEASE_SECONDS}s",
        "POD_UID": "inf061-" + label,
        "OTEL_SDK_DISABLED": "true",
    }


def cpu_windows(plan):
    scaled = copy.deepcopy(plan)
    for stage_name in ("stage_a", "stage_b", "stage_c"):
        stage_plan = scaled[stage_name]
        for key in ("window_s", "warmup_s", "drain_s", "a_lead_s", "b_window_s"):
            if key in stage_plan:
                stage_plan[key] = max(1, stage_plan[key] // CPU_WINDOW_DIVISOR)
    return scaled


def stage(plan):
    from huggingface_hub import snapshot_download
    from transformers import AutoTokenizer

    model_root = Path("/models")
    readback = {}
    for label, model_id, pin in (
        ("bf16", plan["model_id"], plan["model"]),
        ("awq", plan["awq"]["model_id"], plan["awq"]),
    ):
        dest = model_root / label
        snapshot_download(
            model_id,
            revision=pin["revision"],
            local_dir=dest,
            allow_patterns=list(pin["files"]),
        )
        readback[label] = {}
        for name, bound in pin["files"].items():
            got = facts(dest / name)
            check(got == {k: bound[k] for k in ("bytes", "sha256")}, "stage_model_hash")
            readback[label][name] = got
        tokenizer_config = load(dest / "tokenizer_config.json")
        check(
            hashlib.sha256(tokenizer_config["chat_template"].encode()).hexdigest()
            == pin["chat_template_sha256"],
            "stage_template_hash",
        )
    check(
        all(readback["bf16"][name] == readback["awq"][name] for name in PIECES),
        "stage_tokenizer_parity",
    )
    tokenizer = AutoTokenizer.from_pretrained(
        model_root / "bf16", local_files_only=True
    )
    cases = quality_dataset(plan, BASE)
    check(len(cases) == 1319, "stage_quality_count")
    prompts = {
        "short": [render_exact(tokenizer, plan["seed"] + i, 1024) for i in range(1440)],
        "long": [
            render_exact(tokenizer, plan["seed"] + 20_000 + i, 6144) for i in range(192)
        ],
        "a": render_exact(tokenizer, plan["seed"] + 30_000, 1024),
        "b": [
            render_exact(tokenizer, plan["stage_c"]["b_schedule_seed"] + i, 1024)
            for i in range(120)
        ],
    }
    save(Path("/private/prompts.json"), prompts)
    save(Path("/private/model-readback.json"), readback)


def startup_facts(raw, precision):
    # vLLM's pinned logs provide public numerical facts. Retain only these
    # captures and never copy the raw startup log into results.
    memory = re.search(r"Model loading took ([0-9.]+) GiB", raw)
    capacity = re.search(r"GPU KV cache size: ([\d,]+) tokens", raw)
    model_dtype = re.search(r"\bdtype=torch\.(bfloat16|float16|float32)", raw)
    kv_config = re.search(
        r"\bkv_cache_dtype=['\"]?(auto|bfloat16|float16|float32)\b", raw
    )
    dtype = (
        model_dtype[1]
        if kv_config and kv_config[1] == "auto" and model_dtype
        else kv_config[1]
        if kv_config and kv_config[1] != "auto"
        else None
    )
    kernel = kernel_method = None
    fp8_mode = None
    awq_fallback_warnings = 0
    if precision == "awq":
        match = re.search(r"Using (\w+) for (AutoAWQMarlinLinearMethod)", raw)
        if match:
            kernel, kernel_method = match.groups()
        awq_fallback_warnings = sum(
            "Falling back to unoptimized AWQ kernels" in line
            for line in raw.splitlines()
        )
    elif precision == "fp8":
        match = re.search(r"(?:Selected|Using) (\w+) for (Fp8\w*LinearMethod)", raw)
        if match:
            kernel, kernel_method = match.groups()
            fp8_mode = {
                "CutlassFP8ScaledMMLinearKernel": "W8A8",
                "MarlinFP8ScaledMMLinearKernel": "W8A16",
            }.get(kernel, "unclassified")
    return {
        "weight_gib": float(memory[1]) if memory else None,
        "kv_tokens": int(capacity[1].replace(",", "")) if capacity else None,
        "kv_dtype": dtype,
        "kv_dtype_config": kv_config[1] if kv_config else None,
        "kernel": kernel,
        "kernel_method": kernel_method,
        "fp8_mode": fp8_mode,
        "w8a8_eligible": fp8_mode == "W8A8",
        "awq_fallback_warnings": awq_fallback_warnings,
    }


def scrape_metrics(port, prefixes):
    result = Counter()
    with urlopen(f"http://127.0.0.1:{port}/metrics", timeout=0.4) as response:
        for raw in response.read(1024**2).decode().splitlines():
            if raw.startswith("#"):
                continue
            fields = raw.rsplit(None, 1)
            if len(fields) != 2:
                continue
            name = fields[0].split("{", 1)[0]
            if name in prefixes:
                result[prefixes[name]] += float(fields[1])
    return dict(result)


class Benchmark(Phase):
    def __init__(self, root, origin, end, *, cpu=False):
        super().__init__(root, origin, end, cpu)
        self.plan = load(self.repo / "benchmark.json")
        if cpu:
            self.plan = cpu_windows(self.plan)
            self.cpu_image = load(self.repo / "deploy/package-a/pins.json")[
                "python_image"
            ]
        self.gpu_end = end
        self.schedule = self.plan["deadline_seconds"]
        self.credentials = {name: secrets.token_urlsafe(32) for name in ("a", "b", "q")}
        self.quality = {}
        self.arms = {}
        self.telemetry_started = False

    @contextlib.contextmanager
    def deadline(self, allowed):
        prior = self.end
        check(time.time() + allowed <= prior, "inf061_next_phase_budget")
        self.end = time.time() + allowed
        try:
            yield
        finally:
            self.end = prior

    def prepare_benchmark(self):
        self.call(["systemctl", "is-active", "--quiet", "dec077-terminate.timer"])
        if not self.cpu:
            check(
                self.call(
                    ["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"]
                ).strip()
                == b"NVIDIA L4",
                "host_gpu",
            )
        self.call(["systemctl", "start", "docker"])
        self.go()
        images = (
            ("redis", "vllm", "prometheus")
            if self.cpu
            else ("redis", "vllm", "prometheus", "dcgm")
        )
        for key in images:
            self.timed(
                "pull-" + key, self.call, ["docker", "pull", self.pins[key]], 600
            )
            self.check_image(self.pins[key])
        models = self.private / "models"
        models.mkdir()
        container = self.docker(
            "stage",
            self.pins["vllm"],
            ["python3", "/packet/scripts/inf061_native_host.py", "stage"],
            mounts=(
                (self.repo, "/packet", "ro"),
                (self.private, "/private", "rw"),
                (models, "/models", "rw"),
            ),
            variables={"PYTHONPATH": "/packet/python/src"},
        )
        check(
            self.timed(
                "stage-models",
                self.call,
                ["docker", "wait", container],
                CPU_STAGE_WAIT_SECONDS if self.cpu else 1200,
            ).strip()
            == b"0",
            "stage_both_checkpoints",
        )
        self.remove("stage")
        self.prompts = load(self.private / "prompts.json")
        save(
            self.output / "model-readback.json",
            load(self.private / "model-readback.json"),
        )
        self.docker(
            "redis",
            self.pins["redis"],
            [
                "redis-server",
                "--bind",
                "127.0.0.1",
                "--port",
                "16379",
                "--appendonly",
                "no",
                "--save",
                "",
            ],
        )
        if self.cpu:
            self.call(["docker", "pull", self.cpu_image], 180)
            self.check_image(self.cpu_image)
            self.docker(
                "dcgm",
                self.cpu_image,
                ["python3", "/fixture.py", "dcgm"],
                mounts=((self.repo / CPU_FIXTURE, "/fixture.py", "ro"),),
            )
            self.ready("http://127.0.0.1:9400/metrics")
        else:
            self.call(
                [
                    "docker",
                    "run",
                    "-d",
                    "--name",
                    self.name("dcgm"),
                    "--network=host",
                    "--gpus",
                    "all",
                    "--cap-add",
                    "SYS_ADMIN",
                    "-e",
                    "DCGM_EXPORTER_INTERVAL=1000",
                    "-e",
                    "DCGM_EXPORTER_LISTEN=127.0.0.1:9400",
                    self.pins["dcgm"],
                ]
            )
        data = self.private / "tsdb"
        data.mkdir()
        os.chown(data, 65534, 65534)
        config = self.private / "prometheus.json"
        save(
            config,
            {
                "global": {"scrape_interval": "500ms", "scrape_timeout": "400ms"},
                "scrape_configs": [
                    {
                        "job_name": name,
                        "static_configs": [{"targets": [f"127.0.0.1:{port}"]}],
                    }
                    for name, port in (
                        ("gateway", 8080),
                        ("vllm", 8000),
                        ("dcgm", 9400),
                    )
                ],
            },
        )
        config.chmod(0o644)
        self.docker(
            "prometheus",
            self.pins["prometheus"],
            [
                "/bin/prometheus",
                "--config.file=/config.json",
                "--storage.tsdb.path=/data",
                "--storage.tsdb.retention.time=24h",
                "--storage.tsdb.retention.size=2GB",
                "--web.enable-admin-api",
                "--web.listen-address=127.0.0.1:9090",
            ],
            mounts=((config, "/config.json", "ro"), (data, "/data", "rw")),
        )
        self.ready("http://127.0.0.1:9090/-/ready")
        self.telemetry_started = True

    def gateway(self, label, global_cap, a_cap, b_cap):
        file = self.private / (label + "-tenants.json")
        salt = self.private / "cache-salt"
        if not salt.exists():
            salt.write_text(secrets.token_urlsafe(32))
        tenants = {
            "tenants": [
                {
                    "tenant_id": tenant,
                    "credential_sha256": hashlib.sha256(
                        self.credentials[tenant].encode()
                    ).hexdigest(),
                    "models": [MODEL],
                    "max_request_bytes": 65536,
                    "max_output_tokens": 512,
                    "request_rate_limit": 2000,
                    "request_rate_window_ms": 1000,
                    "max_concurrent": cap,
                    **({"setup_backend_id": "vllm-0"} if tenant != "q" else {}),
                }
                for tenant, cap in (
                    ("a", a_cap),
                    ("b", b_cap),
                    ("q", self.plan["quality"]["concurrency"]),
                )
            ]
        }
        save(file, tenants)
        updates = gateway_environment(label, global_cap, file, salt)
        with self.deadline(GATEWAY_READY_SECONDS):
            child = self.start(label, [self.private / "gateway"], updates)
            self.record_gateway_environment(label, updates, tenants)
            self.ready(
                "http://127.0.0.1:8080/readyz",
                check_alive=lambda: process_alive(
                    child, self.private / (label + ".log")
                ),
            )

        with self.deadline(GATEWAY_SANITY_SECONDS):
            self.sanity(label)

    def record_gateway_environment(self, label, updates, tenants):
        if self.cpu:
            save(
                self.output / f"gateway-env-{label}.json",
                {
                    **{
                        key: "[redacted]"
                        if key in {"TENANT_CONFIG_PATH", "CACHE_SALT_SECRET_FILE"}
                        else value
                        for key, value in updates.items()
                    },
                    "tenant_file": {
                        "tenants": [
                            {
                                key: value
                                for key, value in row.items()
                                if key != "credential_sha256"
                            }
                            for row in tenants["tenants"]
                        ]
                    },
                },
            )

    def sanity(self, label):
        end = time.monotonic() + max(0, self.end - time.time())
        cap = self.plan["stage_a"]["output_cap"]
        receipt = {}
        try:
            for tenant in ("a", "b", "q"):
                timed = tenant != "q"
                requested = cap if timed else 8
                row, _ = self.send(
                    self.prompts["short"][0] if timed else "Reply with the number 2.",
                    end,
                    tenant=tenant,
                    cap=requested,
                    request_id=self.cpu,
                )
                rid = row.pop("request_id", None)
                receipt[tenant] = {
                    "http_status": row.get("http_status"),
                    "completion_tokens": row.get("completion_tokens"),
                    "max_tokens": requested,
                    "outcome": row["outcome"],
                }
                if row.get("http_status") != 200:
                    raise CompletionGate("gateway_sanity_http")
                if timed and (
                    row["outcome"] != "completed" or row.get("completion_tokens") != cap
                ):
                    raise CompletionGate("gateway_sanity_usage")
                if self.cpu:
                    if not rid:
                        raise CompletionGate("gateway_sanity_fixture_identity")
                    try:
                        with urlopen(
                            "http://127.0.0.1:8000/fixture-request?"
                            + urlencode({"id": rid}),
                            timeout=max(0.01, min(2, end - time.monotonic())),
                        ) as reply:
                            receipt[tenant]["upstream"] = json.load(reply)
                    except (OSError, ValueError) as error:
                        raise CompletionGate(
                            "gateway_sanity_fixture_readback"
                        ) from error
        finally:
            save(self.output / f"gateway-sanity-{label}.json", receipt)

    def container_alive(self, container):
        state = json.loads(
            self.call(
                ["docker", "inspect", "--format", "{{json .State}}", container], 4
            )
        )
        if not state["Running"]:
            reason = "engine_oom" if state["OOMKilled"] else "engine_exit"
            raise StartupExit(reason, state["ExitCode"])

    def gauges(self):
        try:
            values = scrape_metrics(
                8000,
                {
                    "vllm:num_requests_running": "running",
                    "vllm:num_requests_waiting": "waiting",
                    "vllm:kv_cache_usage_perc": "kv",
                    "vllm:num_preemptions_total": "preemptions",
                },
            )
            values.update(
                scrape_metrics(9400, {"DCGM_FI_DEV_FB_USED": "gpu_memory_mib"})
            )
            if len(values) == 5:
                return values
        except (OSError, ValueError):
            pass
        return None

    def start_engine(self, arm):
        began = time.monotonic()
        path = (
            self.private / "models" / ("awq" if arm["precision"] == "awq" else "bf16")
        )
        mounts = ((self.repo, "/packet", "ro"), (path, "/model", "ro"))
        image, args = self.plan["image"], arm["argv"]
        if self.cpu:
            image = self.cpu_image
            args = ["python3", f"/packet/{CPU_FIXTURE}", arm["precision"]]
        container = self.docker(
            "engine",
            image,
            args,
            variables=ENGINE_ENV,
            gpu=not self.cpu,
            mounts=mounts,
        )
        self.ready(
            "http://127.0.0.1:8000/health",
            check_alive=lambda: self.container_alive(container),
        )
        logs = self.call(["docker", "logs", self.name("engine")]).decode(
            errors="replace"
        )
        info = startup_facts(logs, arm["precision"])
        check(
            info["weight_gib"] is not None and info["kv_tokens"] and info["kv_dtype"],
            "engine_startup_readback",
        )
        check(arm["precision"] == "bf16" or info["kernel"] is not None, "engine_kernel")
        check(self.gauges() is not None, "dcgm_and_engine_scrape")
        return {
            **info,
            "startup_seconds": time.monotonic() - began,
            "kv_blocks": info["kv_tokens"] // 16,
        }

    def send(
        self, prompt, deadline, tenant="b", cap=128, quality=False, *, request_id=False
    ):
        return offer(
            8080,
            self.credentials[tenant],
            prompt,
            cap,
            min(deadline, time.monotonic() + 180),
            quality=quality,
            request_id=request_id,
        )

    def measure(
        self, arm, label, window, drain, prompts, *, rate=None, concurrency=128
    ):
        check(time.time() + window + drain <= self.end, "cell_remaining")
        offsets = [
            (i / rate if rate else 0, prompt) for i, prompt in enumerate(prompts)
        ]
        with Samples(self.gauges) as gauges:
            rows = run_window(
                lambda p, d: self.send(p, d)[0],
                offsets,
                window_s=window,
                drain_s=drain,
                concurrency=concurrency,
                open_loop=rate is not None,
            )
        row = {
            "window_s": window,
            "drain_s": drain,
            "gauges": gauges.summary(),
            "summary": tally(rows, window + drain),
            "rows": rows,
        }
        save(self.output / f"{arm}-{label}.json", row)
        require_completion(row["summary"])
        return row

    def warm(self, prompts, seconds):
        run_window(
            lambda p, d: self.send(p, d)[0],
            [(i, prompts[i % len(prompts)]) for i in range(seconds)],
            window_s=seconds,
            drain_s=0,
        )

    def noisy(self, arm):
        s = self.plan["stage_c"]
        for i, name in enumerate(s["arms"]):
            label = "stage-c-" + str(i)
            try:
                self.gateway(
                    label, s["global_bound"], s["a_concurrent_limit"][i], s["b_peak"]
                )
                origin = time.monotonic() + 0.25
                duration = s["a_lead_s"] + s["b_window_s"]

                def flood():
                    if i == 0:
                        return []
                    if i == 1:
                        # Each A lane submits its next offer only after releasing the prior one.
                        def lane():
                            rows = []
                            until = origin + duration
                            while time.monotonic() < until:
                                row = self.send(
                                    self.prompts["a"], until + s["drain_s"], "a"
                                )[0]
                                rows.append(row)
                                if row["outcome"] not in {"completed", "missed_offer"}:
                                    time.sleep(0.1)
                            return rows

                        with concurrent.futures.ThreadPoolExecutor(
                            max_workers=12
                        ) as lanes:
                            return [
                                row
                                for result in lanes.map(lambda _: lane(), range(12))
                                for row in result
                            ]
                    offers = [(j / 12, self.prompts["a"]) for j in range(12 * duration)]
                    return run_window(
                        lambda p, d: self.send(p, d, "a")[0],
                        offers,
                        window_s=duration,
                        drain_s=s["drain_s"],
                        start=origin,
                    )

                with (
                    Samples(self.gauges) as gauges,
                    concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool,
                ):
                    a_pending = pool.submit(flood)
                    b = run_window(
                        lambda p, d: self.send(p, d)[0],
                        list(enumerate(self.prompts["b"][: s["b_window_s"]])),
                        window_s=s["b_window_s"],
                        drain_s=s["drain_s"],
                        start=origin + s["a_lead_s"],
                    )
                    a = a_pending.result()
                victim = tally(
                    b,
                    s["b_window_s"] + s["drain_s"],
                    slo=(s["b_slo_first_content_s"], s["b_slo_completed_s"]),
                )
                save(
                    self.output / f"{arm}-c-{name}.json",
                    {
                        "a": tally(a, duration + s["drain_s"]) if a else None,
                        "b": victim,
                        "a_rows": a,
                        "b_rows": b,
                        "gauges": gauges.summary(),
                    },
                )
                require_completion(victim)
            finally:
                self.stop_process(label)

    def run_arm_stage(self, name, phase, cases):
        label = name + "-gateway"
        if phase != "C" and not (self.private / (label + ".process.json")).exists():
            self.gateway(label, 768, 768, 768)
        if phase == "A":
            cfg = self.plan["stage_a"]
            self.warm(self.prompts["short"], cfg["warmup_s"])
            for rate in cfg["rates"]:
                data = self.measure(
                    name,
                    f"a-{rate}",
                    cfg["window_s"],
                    cfg["drain_s"],
                    self.prompts["short"][: rate * cfg["window_s"]],
                    rate=rate,
                )
                if name == "bf16-16" and data["gauges"]["running_and_waiting"] >= 16:
                    self.arms[name]["saturation_observed"] = True
        elif phase == "C":
            self.stop_process(label)
            self.noisy(name)
        elif phase == "B":
            cfg = self.plan["stage_b"]
            self.warm(self.prompts["long"], cfg["warmup_s"])
            valid = 64 > self.arms[name]["kv_blocks"] // cfg["blocks_per_prompt"]
            self.arms[name]["kv_bound_pass"] = valid
            for concurrency in cfg["concurrencies"]:
                if concurrency == 64 and not valid:
                    continue
                self.measure(
                    name,
                    f"b-{concurrency}",
                    cfg["window_s"],
                    cfg["drain_s"],
                    self.prompts["long"][
                        : cfg["requests_by_concurrency"][str(concurrency)]
                    ],
                    concurrency=concurrency,
                )
        else:
            q = self.plan["quality"]
            pass_name = phase.removeprefix("quality-")
            allowance = q["pass_limit_s"] - 1
            if self.cpu:
                cases = cases[:8]
                allowance = max(1, allowance // CPU_WINDOW_DIVISOR)
            with self.deadline(q["pass_limit_s"]):
                scores = run_quality(
                    lambda p, d: self.send(
                        p, d, tenant="q", cap=q["max_tokens"], quality=True
                    ),
                    cases,
                    q["suffix"],
                    allowance,
                    q["concurrency"],
                )
            self.quality[pass_name] = scores
            save(
                self.output / f"quality-{pass_name}.json",
                {"scores": scores, "counts": dict(Counter(scores))},
            )

    def run_arm(self, arm, cases):
        name = arm["name"]
        phase = "startup"
        receipt = self.arms[name] = {"startup": "unreached"}
        try:
            with self.deadline(600):
                receipt.update(self.start_engine(arm), startup="ready")
            for phase in arm["stages"]:
                self.run_arm_stage(name, phase, cases)
            receipt["status"] = "completed"
        except Exception as error:
            if phase == "startup":
                receipt["startup"] = "refused"
            reason = (
                "timeout"
                if isinstance(error, TimeoutError)
                else ("io_error" if isinstance(error, OSError) else "stage_error")
            )
            receipt.update(status="failed", failure={"stage": phase, "reason": reason})
            if isinstance(error, StartupExit):
                receipt["failure"].update(error.receipt)
            elif isinstance(error, CompletionGate):
                receipt["failure"]["reason"] = error.reason
            if arm["precision"] not in {"fp8", "awq"}:
                raise
        finally:
            # Attempt both exits. A cleanup error escapes arm containment so
            # the outer supervisor can tear down an ambiguous host.
            try:
                self.stop_process(name + "-gateway")
            finally:
                self.remove("engine")

    def run(self):
        try:
            with self.deadline(self.schedule["provision_and_stage"]):
                self.prepare_benchmark()
            cases = quality_dataset(self.plan, self.repo)
            for arm in self.plan["starts"]:
                self.run_arm(arm, cases)
        finally:
            compare = {}
            for name, base in (
                ("bf16-repeat", "bf16-first"),
                ("fp8", "bf16-first"),
                ("awq", "bf16-repeat"),
            ):
                if name in self.quality and base in self.quality:
                    compare[name] = pairs(self.quality[base], self.quality[name])
            receipt = {"arms": self.arms, "paired": compare}
            if self.cpu:
                receipt["start_order"] = list(self.arms)
            save(self.output / "benchmark.json", receipt)
            if self.telemetry_started:
                archive = self.output / "tsdb.tar.gz"
                info = snapshot("http://127.0.0.1:9090", self.private / "tsdb", archive)
                if info["bytes"] > RETAINED_ARCHIVE_BYTES:
                    archive.unlink()
                    archive.with_suffix(".gz.sha256").unlink()
                    raise ValueError("inf061:tsdb_export_bound")
                save(self.output / "tsdb-receipt.json", info)
            if self.cpu:
                for role in ("prometheus", "dcgm", "redis"):
                    self.remove(role)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("stage", "launch"))
    parser.add_argument("--root", type=Path)
    parser.add_argument("--origin", type=float)
    parser.add_argument("--end", type=float)
    parser.add_argument("--cpu-rehearsal", action="store_true")
    args = parser.parse_args()
    if args.mode == "stage":
        stage(load(BASE / "benchmark.json"))
        return
    if args.cpu_rehearsal:
        root = args.root.resolve()
        # The sealed agent supplies no rehearsal argument, and its sparse
        # source bundle cannot contain the fixture or use a temporary root.
        check(
            root.is_relative_to(Path("/tmp"))
            and root != Path(REMOTE)
            and (root / "repo" / CPU_FIXTURE).is_file(),
            "cpu_rehearsal_boundary",
        )
    benchmark = Benchmark(args.root, args.origin, args.end, cpu=args.cpu_rehearsal)
    if not args.cpu_rehearsal:
        benchmark.run()
        return
    codes = {
        method.__code__: name
        for name, method in vars(Benchmark).items()
        if callable(method)
    }
    calls = Counter()

    def trace(frame, event, _):
        if event == "call" and frame.f_code in codes:
            calls[codes[frame.f_code]] += 1

    sys.setprofile(trace)
    threading.setprofile(trace)
    try:
        benchmark.run()
    finally:
        sys.setprofile(None)
        threading.setprofile(None)
        save(benchmark.output / "native-method-calls.json", calls)


if __name__ == "__main__":
    main()
