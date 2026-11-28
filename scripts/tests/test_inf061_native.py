import hashlib
import io
import json
import re
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.request import Request, urlopen

import inf060_probe_spec as spec
import inf061_packet as packet
from inf061_cpu_engine import Engine, FixtureServer
from inf061_native_host import (
    Benchmark,
    CompletionGate,
    GATEWAY_READY_SECONDS,
    GATEWAY_SANITY_SECONDS,
    StartupExit,
    gateway_environment,
    startup_facts,
)
from inf061_native_workload import offer, run_quality, run_window
from rehearse_inf061_final import rehearse, rehearse_containment


STARTUP_LOG = (
    "dtype=torch.bfloat16, kv_cache_dtype=auto\n"
    "Model loading took 5.41 GiB memory and 31.2 seconds\n"
    "GPU KV cache size: 120,448 tokens,\n"
)


def stream(text, reason):
    def frame(choices, **fields):
        return {"object": "chat.completion.chunk", "choices": choices, **fields}

    values = [
        frame([{"index": 0, "delta": {"content": text}, "finish_reason": None}]),
        frame([{"index": 0, "delta": {}, "finish_reason": reason}]),
        frame(
            [],
            usage={
                "prompt_tokens": 2,
                "completion_tokens": 2,
                "total_tokens": 4,
                "count_source": "runtime_usage",
            },
        ),
    ]
    return (
        b"".join(b"data: " + json.dumps(value).encode() + b"\n\n" for value in values)
        + b"data: [DONE]\n\n"
    )


class FakeEngine(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.server.request_fields = set(body)
        question = body["messages"][0]["content"]
        if question == "bad gateway request":
            code = 400
            data = b'{"error":{"code":"invalid_request"}}'
        elif question == "denial":
            code = 429
            data = b'{"error":{"code":"tenant_concurrency_limit"}}'
        else:
            code = 200
            reason = "length" if question.startswith("truncate") else "stop"
            data = stream("Work\nFINAL: 2", reason)
        self.send_response(code)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)


class NativeBenchmarkTests(unittest.TestCase):
    def test_native_rehearsal_engine_emits_upstream_usage(self):
        with FixtureServer(("127.0.0.1", 0), Engine) as backend:
            thread = threading.Thread(target=backend.serve_forever, daemon=True)
            thread.start()
            try:
                request = Request(
                    f"http://127.0.0.1:{backend.server_port}/v1/chat/completions",
                    data=json.dumps(
                        {
                            "max_tokens": 5,
                            "ignore_eos": True,
                            "messages": [{"role": "user", "content": "fixture"}],
                            "stream_options": {"include_usage": True},
                        }
                    ).encode(),
                    headers={"X-Request-ID": "unit-fixture"},
                )
                with urlopen(request, timeout=2) as response:
                    self.assertEqual(
                        response.headers["Content-Type"], "text/event-stream"
                    )
                    frames = response.read().splitlines()
                self.assertEqual(frames[-2], b"data: [DONE]")
                usage = json.loads(frames[-4].removeprefix(b"data: "))["usage"]
                self.assertEqual(
                    usage,
                    {
                        "prompt_tokens": 1024,
                        "completion_tokens": 5,
                        "total_tokens": 1029,
                    },
                )
                # The gateway assigns the runtime_usage provenance field.
                self.assertNotIn("count_source", usage)
                with urlopen(
                    f"http://127.0.0.1:{backend.server_port}/fixture-request?id=unit-fixture",
                    timeout=2,
                ) as result:
                    readback = json.load(result)
                self.assertTrue(readback["ignore_eos"])
                self.assertTrue(readback["include_usage"])
                self.assertNotIn("fixture", json.dumps(readback))
            finally:
                backend.shutdown()
                thread.join(timeout=4)

    def test_gateway_environment_satisfies_real_lease_guard(self):
        values = gateway_environment("fixture", 20, "tenants.json", "salt")

        def seconds(name):
            return int(values[name].removesuffix("s"))

        lease = seconds("ADMISSION_LEASE")
        required = sum(
            seconds(name)
            for name in (
                "GATEWAY_TOTAL_TIMEOUT",
                "GATEWAY_SHUTDOWN_HARD_STOP",
                "GATEWAY_RELEASE_TIMEOUT",
            )
        )
        self.assertEqual(required, 251)
        self.assertEqual(lease, 300)
        self.assertGreater(lease, required)
        self.assertLess(
            seconds("GATEWAY_FIRST_ITEM_TIMEOUT"), seconds("GATEWAY_TOTAL_TIMEOUT")
        )

    def test_dead_gateway_aborts_bf16_and_preserves_retrieval_receipt(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            bench = Benchmark.__new__(Benchmark)
            bench.repo = bench.private = bench.output = root
            bench.end = time.time() + 900
            bench.schedule = {"provision_and_stage": 60}
            bench.plan = {
                "starts": [{"name": "bf16-16", "precision": "bf16", "stages": ["A"]}],
                "quality": {"concurrency": 32},
            }
            bench.credentials = {"a": "fixture-a", "b": "fixture-b", "q": "fixture-q"}
            bench.arms = {}
            bench.quality = {}
            bench.telemetry_started = bench.cpu = False
            bench.prepare_benchmark = Mock()
            bench.start_engine = Mock(return_value={})
            bench.remove = Mock()
            with (root / "bf16-16-gateway.log").open("wb") as log:
                child = subprocess.Popen(
                    [
                        sys.executable,
                        "-c",
                        "import sys; print('gateway server failed'); sys.exit(2)",
                    ],
                    stdout=log,
                )
            bench.start = Mock(return_value=child)
            start = time.monotonic()
            try:
                with (
                    patch("inf061_native_host.quality_dataset", return_value=[]),
                    patch(
                        "inf060_probe_host.urlopen", side_effect=ConnectionRefusedError
                    ),
                    self.assertRaisesRegex(StartupExit, "listen_failed"),
                ):
                    bench.run()
            finally:
                child.wait(timeout=3)
            self.assertLess(time.monotonic() - start, 4)
            self.assertEqual(
                spec.load(root / "benchmark.json")["arms"]["bf16-16"]["failure"],
                {"stage": "A", "reason": "listen_failed", "exit_code": 2},
            )
            bench.remove.assert_called_once_with("engine")
            incoming, outgoing = root / "raw.tar.gz", root / "allowlisted.tar.gz"
            with tarfile.open(incoming, "w:gz") as tar:
                tar.add(root / "benchmark.json", arcname="results/benchmark.json")
            self.assertEqual(
                packet.capture(incoming, outgoing)["files"], ["results/benchmark.json"]
            )

    def test_engine_liveness_refuses_exited_container(self):
        bench = Benchmark.__new__(Benchmark)
        bench.call = Mock(
            return_value=b'{"Running":false,"OOMKilled":true,"ExitCode":137}'
        )
        with self.assertRaises(StartupExit) as failure:
            bench.container_alive("fixture-engine")
        self.assertEqual(
            failure.exception.receipt, {"reason": "engine_oom", "exit_code": 137}
        )

    def test_client_body_is_within_gateway_supported_members(self):
        root = Path(__file__).resolve().parents[2]
        source = (root / "internal/gateway/handler.go").read_text(encoding="utf-8")
        members = source.split("supported := map[string]struct{}{", 1)[1].split(
            "\n\t}", 1
        )[0]
        supported = set(re.findall(r'"([a-z_]+)":', members))
        with ThreadingHTTPServer(("127.0.0.1", 0), FakeEngine) as backend:
            worker = threading.Thread(target=backend.serve_forever, daemon=True)
            worker.start()
            try:
                row, _ = offer(
                    backend.server_port, "fixture", "valid", 128, time.monotonic() + 2
                )
                self.assertEqual(row["outcome"], "completed")
                self.assertTrue(
                    {"model", "messages", "stream"}
                    <= backend.request_fields
                    <= supported
                )
            finally:
                backend.shutdown()
                worker.join(timeout=3)

    def test_sanity_retains_http_400_and_stops_before_another_tenant(self):
        with (
            tempfile.TemporaryDirectory() as scratch,
            ThreadingHTTPServer(("127.0.0.1", 0), FakeEngine) as backend,
        ):
            worker = threading.Thread(target=backend.serve_forever, daemon=True)
            worker.start()
            bench = Benchmark.__new__(Benchmark)
            bench.output = Path(scratch)
            bench.cpu = False
            bench.plan = {"stage_a": {"output_cap": 128}}
            bench.prompts = {"short": ["bad gateway request"]}
            bench.end = time.time() + 5
            bench.send = Mock(
                side_effect=lambda prompt, deadline, **kwargs: offer(
                    backend.server_port, "fixture", prompt, kwargs["cap"], deadline
                )
            )
            try:
                with self.assertRaisesRegex(CompletionGate, "gateway_sanity_http"):
                    bench.sanity("bf16-16-gateway")
                self.assertEqual(bench.send.call_count, 1)
                self.assertEqual(
                    spec.load(bench.output / "gateway-sanity-bf16-16-gateway.json"),
                    {
                        "a": {
                            "http_status": 400,
                            "completion_tokens": None,
                            "max_tokens": 128,
                            "outcome": "rejected",
                        },
                    },
                )
            finally:
                backend.shutdown()
                worker.join(timeout=3)

    def test_sanity_checks_timed_usage_and_quality_tenant(self):
        with tempfile.TemporaryDirectory() as scratch:
            bench = Benchmark.__new__(Benchmark)
            bench.output = Path(scratch)
            bench.cpu = False
            bench.plan = {"stage_a": {"output_cap": 128}}
            bench.prompts = {"short": ["fixture"]}
            bench.end = time.time() + 5
            timed = {
                "http_status": 200,
                "outcome": "completed",
                "completion_tokens": 128,
            }
            quality = {**timed, "completion_tokens": 2}
            bench.send = Mock(
                side_effect=[(timed, None), (timed, None), (quality, None)]
            )
            bench.sanity("bf16-16-gateway")
            self.assertEqual(
                [
                    (c.kwargs["tenant"], c.kwargs["cap"])
                    for c in bench.send.call_args_list
                ],
                [("a", 128), ("b", 128), ("q", 8)],
            )
            bench.send = Mock(return_value=(quality, None))
            with self.assertRaisesRegex(CompletionGate, "gateway_sanity_usage"):
                bench.sanity("bf16-16-gateway")

    def test_zero_completion_cell_is_retained_and_refused(self):
        with tempfile.TemporaryDirectory() as scratch:
            bench = Benchmark.__new__(Benchmark)
            bench.output = Path(scratch)
            bench.end = time.time() + 10
            bench.gauges = Mock(return_value=None)
            bench.send = Mock(
                return_value=(
                    {
                        "http_status": 400,
                        "outcome": "rejected",
                        "gateway_code": "other",
                    },
                    None,
                )
            )
            with self.assertRaisesRegex(CompletionGate, "regular_cell_no_completion"):
                bench.measure("bf16-16", "a-1", 1, 0, ["fixture"], rate=1)
            saved = spec.load(bench.output / "bf16-16-a-1.json")
            self.assertEqual(saved["summary"]["outcomes"], {"rejected": 1})

    def test_rollover_budget_counts_previous_attempts_and_capacity_refusal(self):
        root = Path(__file__).resolve().parents[2]
        plan = spec.load(root / "docs/INF061_FINAL_PLAN.json")
        inputs = spec.load(root / "docs/INF061_R455_LIVE_INPUTS.json")
        rates = {
            "compute_usd_per_h": inputs["gpu_compute"],
            "operator_compute_usd_per_h": inputs["cpu_compute"],
            "gp3_usd_per_gib_month": inputs["gp3"],
            "ipv4_usd_per_h": inputs["ipv4"],
        }
        self.assertEqual(plan["zone"], inputs["zone"])
        self.assertEqual(plan["zone"], "us-east-1b")
        self.assertEqual(plan["cap_usd"], 36)
        self.assertEqual(plan["prior_paid_estimate_usd"], 1.609266)
        self.assertEqual(packet.budget(plan, rates)["hard_cap_usd"], 34.390734)
        with self.assertRaisesRegex(ValueError, "cost_envelope"):
            packet.budget({**plan, "prior_paid_estimate_usd": 6}, rates)

    def test_gateway_start_budget_refuses_old_timer(self):
        root = Path(__file__).resolve().parents[2]
        plan = spec.load(root / "docs/INF061_FINAL_PLAN.json")
        self.assertEqual(
            packet.GATEWAY_START_SECONDS, GATEWAY_READY_SECONDS + GATEWAY_SANITY_SECONDS
        )
        self.assertEqual(packet.time_envelope(plan), 45105)
        too_short = {**plan, "gpu_timer_s": 45000}
        with self.assertRaisesRegex(ValueError, "inf061:time_envelope"):
            packet.time_envelope(too_short)
        with tempfile.TemporaryDirectory() as work:
            with self.assertRaisesRegex(ValueError, "inf061:time_envelope"):
                rehearse(too_short, [], Path(work))
            result = rehearse(plan, [], Path(work))
        self.assertEqual(result["elapsed_virtual_s"], 43605)

    def test_quality_and_offers_use_native_sse_path(self):
        with ThreadingHTTPServer(("127.0.0.1", 0), FakeEngine) as backend:
            thread = threading.Thread(target=backend.serve_forever, daemon=True)
            thread.start()
            port = backend.server_port

            def send(text, deadline):
                return offer(port, "fixture", text, 512, deadline, quality=True)

            try:
                rows = run_window(
                    lambda text, deadline: send(text, deadline)[0],
                    [(0, "complete"), (0, "denial")],
                    window_s=1,
                    drain_s=0,
                    concurrency=2,
                    open_loop=False,
                )
                self.assertEqual(
                    [r["outcome"] for r in rows], ["completed", "rejected"]
                )
                self.assertEqual(rows[0]["completion_tokens"], 2)
                self.assertEqual(rows[1]["gateway_code"], "tenant_concurrency_limit")
                cases = [
                    ("correct", Decimal(2)),
                    ("incorrect", Decimal(3)),
                    ("truncate", Decimal(2)),
                ]
                self.assertEqual(
                    run_quality(send, cases, "", 1, 3), ["exact", "wrong", "truncated"]
                )
                missed = send("correct", time.monotonic() - 1)[0]
                self.assertEqual(missed["outcome"], "missed_offer")
            finally:
                backend.shutdown()
                thread.join(timeout=4)

    def test_both_plans_in_approval_and_consumed_archive_bound(self):
        manifest = {
            "schema": packet.SCHEMA,
            "source_commit": "a" * 40,
            "sealed_plans": {"create_sha256": "b" * 64},
            "operator_host": {"create_sha256": "c" * 64},
        }
        digest = "d" * 64
        review = (
            "## Claude Round 0\n- Verdict: NO_BLOCKING_FINDINGS\n"
            + packet.approval_line(manifest, digest)
        )
        spec.approval(review, manifest, digest)
        with self.assertRaisesRegex(ValueError, "approval_marker"):
            spec.approval(review.replace("c" * 64, "e" * 64), manifest, digest)
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            source, target = root / "in.tar.gz", root / "out.tar.gz"
            with tarfile.open(source, "w:gz") as archive:
                for path, raw in (
                    ("results/benchmark.json", b"{}"),
                    ("results/private.log", b"raw"),
                ):
                    member = tarfile.TarInfo(path)
                    member.size = len(raw)
                    archive.addfile(member, io.BytesIO(raw))
            receipt = packet.capture(source, target)
            self.assertEqual(receipt["files"], ["results/benchmark.json"])
            self.assertEqual(
                receipt["sha256"], hashlib.sha256(target.read_bytes()).hexdigest()
            )

    def test_native_awq_readback_has_kernel_and_resolved_kv_dtype(self):
        raw = STARTUP_LOG + "Using MarlinLinearKernel for AutoAWQMarlinLinearMethod\n"
        self.assertEqual(
            startup_facts(raw, "awq"),
            {
                "weight_gib": 5.41,
                "kv_tokens": 120448,
                "kv_dtype": "bfloat16",
                "kv_dtype_config": "auto",
                "kernel": "MarlinLinearKernel",
                "kernel_method": "AutoAWQMarlinLinearMethod",
                "fp8_mode": None,
                "w8a8_eligible": False,
                "awq_fallback_warnings": 0,
            },
        )

    def test_native_awq_readback_counts_unoptimized_fallback(self):
        raw = (
            STARTUP_LOG
            + "Using MarlinLinearKernel for AutoAWQMarlinLinearMethod\n"
            + "Layer 'model.layers.0' is not supported by AutoAWQMarlin. "
            "Falling back to unoptimized AWQ kernels.\n"
        )
        info = startup_facts(raw, "awq")
        self.assertEqual(info["awq_fallback_warnings"], 1)
        self.assertEqual(info["kernel"], "MarlinLinearKernel")

    def test_native_fp8_selected_cutlass_readback(self):
        info = startup_facts(
            STARTUP_LOG
            + "Selected CutlassFP8ScaledMMLinearKernel for Fp8PerTensorOnlineLinearMethod\n",
            "fp8",
        )
        self.assertEqual(info["kernel"], "CutlassFP8ScaledMMLinearKernel")
        self.assertEqual(info["kernel_method"], "Fp8PerTensorOnlineLinearMethod")
        self.assertEqual(info["fp8_mode"], "W8A8")
        self.assertTrue(info["w8a8_eligible"])

    def test_native_fp8_selected_marlin_readback_is_weight_only(self):
        info = startup_facts(
            STARTUP_LOG
            + "Selected MarlinFP8ScaledMMLinearKernel for Fp8PerTensorOnlineLinearMethod\n",
            "fp8",
        )
        self.assertEqual(info["kernel"], "MarlinFP8ScaledMMLinearKernel")
        self.assertEqual(info["kernel_method"], "Fp8PerTensorOnlineLinearMethod")
        self.assertEqual(info["fp8_mode"], "W8A16")
        self.assertFalse(info["w8a8_eligible"])

    def test_native_containment_closes_both_sides_before_next_arm(self):
        plan = {
            "starts": [
                {"name": "bf16-64", "precision": "bf16", "stages": ["B"]},
                {"name": "fp8-64", "precision": "fp8", "stages": ["B", "quality-fp8"]},
                {"name": "awq-64", "precision": "awq", "stages": ["B", "quality-awq"]},
            ]
        }
        with tempfile.TemporaryDirectory() as work:
            path = Path(work)
            contained = rehearse_containment(plan, path)
            self.assertIsNone(contained["abort"])
            self.assertEqual(
                contained["arms"]["fp8-64"]["failure"],
                {"stage": "B", "reason": "timeout"},
            )
            self.assertEqual(contained["arms"]["awq-64"]["status"], "completed")
            self.assertEqual(
                contained["cleanup"][-4:],
                [
                    ("fp8-64", "gateway"),
                    ("fp8-64", "engine"),
                    ("awq-64", "gateway"),
                    ("awq-64", "engine"),
                ],
            )
            baseline = rehearse_containment(plan, path, fail=("bf16-64", "B"))
            self.assertEqual(baseline["abort"], "stage_timeout")
            self.assertEqual(list(baseline["arms"]), ["bf16-64"])
            unsafe = rehearse_containment(plan, path, fail_cleanup=True)
            self.assertEqual(unsafe["abort"], "cleanup_error")
            self.assertEqual(
                unsafe["cleanup"][-2:], [("fp8-64", "gateway"), ("fp8-64", "engine")]
            )
            self.assertNotIn("awq-64", unsafe["arms"])
