import http.client
import json
import os
import socket
import subprocess
import tempfile
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from pathlib import Path

from inference_platform.calibration import CalibrationConfig, run_calibration
from inference_platform.decision_export import export_decisions
from inference_platform.fake_backend import FailureMode, FakeBackend, FakeBackendConfig
from inference_platform.kv_event_capture import (
    correlate_routing_events,
    load_routing_decisions,
    read_http_sse_event_stream,
)

try:
    from test_admission_process_integration import _cleanup_redis_namespace
except ModuleNotFoundError:
    from python.tests.test_admission_process_integration import _cleanup_redis_namespace

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


class GatewayIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary_directory = tempfile.TemporaryDirectory()
        executable_name = "gateway.exe" if os.name == "nt" else "gateway"
        cls.gateway_executable = Path(cls.temporary_directory.name) / executable_name
        environment = os.environ.copy()
        environment.update(
            {
                "GOCACHE": str(REPOSITORY_ROOT / ".cache/go-build"),
                "GOMODCACHE": str(REPOSITORY_ROOT / ".cache/go-mod"),
                "GOTOOLCHAIN": "local",
            }
        )
        subprocess.run(
            ["go", "build", "-o", str(cls.gateway_executable), "./cmd/gateway"],
            cwd=REPOSITORY_ROOT,
            env=environment,
            check=True,
            capture_output=True,
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary_directory.cleanup()

    def setUp(self) -> None:
        self.admission_namespace = f"test:python:{os.getpid()}:{time.time_ns()}"

    def tearDown(self) -> None:
        redis_address = os.environ.get("REDIS_TEST_ADDR")
        if redis_address:
            _cleanup_redis_namespace(redis_address, self.admission_namespace)

    @contextmanager
    def running_gateway(
        self,
        backends: list[FakeBackend],
        terminal_log: Path | None = None,
        extra_environment: dict[str, str] | None = None,
    ):
        port = _free_port()
        environment = os.environ.copy()
        environment.update(
            {
                "GATEWAY_HTTP_ADDR": f"127.0.0.1:{port}",
                "BACKENDS": ",".join(
                    f"{backend.config.backend_id}={backend.base_url}" for backend in backends
                ),
                "BACKEND_METRICS_INTERVAL": "10ms",
                "BACKEND_METRICS_MAX_AGE": "250ms",
                "CACHE_SALT_SECRET_FILE": str(
                    REPOSITORY_ROOT / "deploy/local/cache-salt.secret.example"
                ),
            }
        )
        redis_address = os.environ.get("REDIS_TEST_ADDR")
        if redis_address:
            environment.update(
                {
                    "ADMISSION_MODE": "redis",
                    "REDIS_ADDR": redis_address,
                    "ADMISSION_NAMESPACE": self.admission_namespace,
                }
            )
        else:
            environment.update(
                {
                    "ADMISSION_MODE": "memory-test",
                    "ALLOW_UNSAFE_TEST_ADMISSION": "true",
                }
            )
        environment.update(extra_environment or {})
        log_stream = terminal_log.open("wb") if terminal_log else None
        process = subprocess.Popen(
            [str(self.gateway_executable)],
            cwd=REPOSITORY_ROOT,
            env=environment,
            stdout=log_stream or subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        url = f"http://127.0.0.1:{port}"
        try:
            deadline = time.monotonic() + 10
            while True:
                if process.poll() is not None:
                    output = process.stdout.read().decode() if process.stdout else ""
                    self.fail(f"gateway exited during startup: {output}")
                try:
                    with urllib.request.urlopen(f"{url}/readyz", timeout=0.2) as response:
                        if response.status == 200:
                            break
                except (OSError, urllib.error.URLError):
                    pass
                if time.monotonic() >= deadline:
                    process.terminate()
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=2)
                    output = process.stdout.read().decode() if process.stdout else ""
                    self.fail(f"gateway did not become ready: {output}")
                time.sleep(0.02)
            yield url
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
            if process.stdout:
                process.stdout.close()
            if log_stream:
                log_stream.close()

    def test_whole_approved_protocol_with_real_gateway_and_fake_runtime(self):
        from inference_platform.stage_c import StageCConfig, run_stage_c
        from inference_platform.stage_c_sizing import clustered_counts

        with (
            tempfile.TemporaryDirectory() as directory,
            FakeBackend(
                FakeBackendConfig(
                    backend_id="whole-r0",
                    first_item_delay_ms=30,
                    running_capacity=2,
                    kv_cache_capacity_blocks=128,
                    runtime_shaped_metrics=True,
                )
            ) as backend,
        ):
            root = Path(directory)
            terminal = root / "gateway.jsonl"
            tenants = root / "tenants.json"
            source = json.loads(
                (REPOSITORY_ROOT / "deploy/local/tenants.json").read_text(encoding="utf-8")
            )
            for tenant in source["tenants"]:
                tenant.update(
                    request_rate_limit=4096, request_rate_window_ms=1000, max_concurrent=128
                )
            tenants.write_text(json.dumps(source), encoding="utf-8")
            environment = {
                "GATEWAY_FIRST_ITEM_TIMEOUT": "120s",
                "GATEWAY_TOTAL_TIMEOUT": "180s",
                "ADMISSION_LEASE": "240s",
                "ADMISSION_GLOBAL_CAPACITY": "128",
                "GATEWAY_MAX_CONCURRENT": "128",
                "TENANT_CONFIG_PATH": str(tenants),
            }
            with self.running_gateway(
                [backend], terminal_log=terminal, extra_environment=environment
            ) as url:
                startup = next(
                    row
                    for row in [
                        json.loads(line)
                        for line in terminal.read_text(encoding="utf-8").splitlines()
                    ]
                    if row.get("msg") == "gateway started"
                )
                ready = time.time()
                counts = clustered_counts(128, 4, 4, [0.5, 0.8, 0.9, 1, 1.1, 1.25, 1.5])
                config = StageCConfig(
                    url=url,
                    token="local-dev-token",
                    tenant_id="tenant-local",
                    model="test-model",
                    run_id="whole-r0-v2",
                    reset_url=backend.base_url,
                    tokenize_url=backend.base_url,
                    protocol_version="r0-v2",
                    local_rehearsal=True,
                    saturation_prompt_tokens=512,
                    reference_prompt_tokens=64,
                    measured_capacity_blocks=128,
                    saturation_levels=(1, 4, 8),
                    reference_prefix_counts=tuple(counts),
                    sustained_level_seconds=0.5,
                    minimum_cycle_seconds=0.001,
                    rewarm_repeats=1,
                    rewarm_samples=2,
                    max_tokens=2,
                    sample_interval_ms=5,
                    instance_boot_unix_s=ready - 2015,
                    instance_termination_unix_s=ready - 2015 + 14400,
                    observed_readiness_unix_s=ready,
                    gateway_config_log=str(terminal),
                    expected_admission_configuration=startup["admission_configuration"],
                    decision_prompt_export_path=str(root / "prompts.jsonl"),
                    decision_export_output_path=str(root / "decisions.jsonl"),
                    fake_event_url=backend.base_url + "/kv-events",
                    metrics_endpoints=(("native", backend.base_url),),
                )
                result = run_stage_c(config)
            self.assertEqual(result["status"], "completed", result["readiness"])
            disk = json.loads((root / "disk-readiness.json").read_text(encoding="utf-8"))
            self.assertEqual(disk["source"], "rehearsal")
            self.assertEqual(
                result["readiness"]["gate"]["checks"]["root_disk"]["source"], "rehearsal"
            )
            self.assertEqual(len(result["timed_runs"]), 4)
            self.assertEqual(
                result["readiness"]["gate"]["checks"]["gateway_admission"][
                    "first_item_timeout_seconds"
                ],
                120,
            )
            self.assertTrue(
                all(c["max_tokens"] == 1 for c in result["timed_runs"][1]["candidates"])
            )
            levels = result["timed_runs"][0]["levels"]
            self.assertTrue(all(level["load_mode"] == "sustained_closed_loop" for level in levels))
            self.assertTrue(any(len(level["records"]) > level["concurrency"] for level in levels))
            identities = [
                record["prompt_sha256"] for level in levels for record in level["records"]
            ]
            self.assertEqual(len(identities), len(set(identities)))
            self.assertTrue(
                any("waiting_observed" in level["runtime_regime"]["labels"] for level in levels)
            )
            self.assertTrue(
                any(
                    "kv_pressure_preemptions_observed" in level["runtime_regime"]["labels"]
                    for level in levels
                )
            )
            self.assertGreater(result["decision_event_export"]["observed_correlation_count"], 0)
            self.assertGreater(result["decision_event_export"]["joined_decision_count"], 0)
            self.assertEqual(
                result["decision_event_export"]["request_lifetime_bound_violation_count"], 0
            )
            for row in result["decision_event_export"]["routing_to_event_observation"]:
                if row["status"] == "observed":
                    self.assertLessEqual(
                        row["routing_to_event_observation_ns"],
                        row["request_lifetime_ns"] + row["publisher_flush_allowance_ns"],
                    )
                elif row["status"] == "observed_after_request_window":
                    self.assertGreater(
                        row["routing_to_event_observation_ns"],
                        row["request_lifetime_ns"] + row["publisher_flush_allowance_ns"],
                    )
                    if row["next_same_identity_decision_monotonic_ns"] is not None:
                        self.assertLess(
                            row["event_observed_monotonic_ns"],
                            row["next_same_identity_decision_monotonic_ns"],
                        )
            self.assertGreater(
                result["fake_kv_event_rehearsal"]["inventory"]["block_removals_observed"], 0
            )
            self.assertFalse((root / "prompts.jsonl").exists())
            self.assertFalse((root / "decisions.jsonl").exists())
            self.assertTrue(result["finalization"]["raw_prompt_token_inputs_removed"])
            self.assertNotIn("expected_token_ids", json.dumps(result))
            if summary_path := os.environ.get("R0_REHEARSAL_SUMMARY_PATH"):
                summary = {
                    "schema": "inf011-r0-v2-whole-fake-rehearsal.v1",
                    "basis": "real Go gateway; fake tokenizer/runtime/events; scaled local duration and token sizes. Control-flow evidence only, no paid performance claim.",
                    "protocol_version": config.protocol_version,
                    "local_rehearsal": True,
                    "saturation_prompt_tokens": config.saturation_prompt_tokens,
                    "reference_prompt_tokens": config.reference_prompt_tokens,
                    "seconds_per_level": config.sustained_level_seconds,
                    "capacity_blocks": config.measured_capacity_blocks,
                    "status": result["status"],
                    "run_statuses": [run["status"] for run in result["timed_runs"]],
                    "reference_prefix_counts": counts,
                    "reference_max_tokens": config.reference_max_tokens,
                    "effective_first_item_timeout_seconds": 120,
                    "saturation_levels": [
                        {
                            "concurrency": level["concurrency"],
                            "requests": len(level["records"]),
                            "censored_ttft_count": level["censored_ttft_count"],
                            "runtime_regime": level["runtime_regime"],
                        }
                        for level in levels
                    ],
                    "unique_saturation_prompt_count": len(identities),
                    "joined_decision_count": result["decision_event_export"][
                        "joined_decision_count"
                    ],
                    "observed_correlation_count": result["decision_event_export"][
                        "observed_correlation_count"
                    ],
                    "max_observed_lag_ns": result["decision_event_export"]["max_observed_lag_ns"],
                    "observed_after_request_window_count": result["decision_event_export"][
                        "observed_after_request_window_count"
                    ],
                    "max_observed_after_request_window_lag_ns": result["decision_event_export"][
                        "max_observed_after_request_window_lag_ns"
                    ],
                    "excluded_counts": result["decision_event_export"]["excluded_counts"],
                    "publisher_flush_allowance_ns": result["decision_event_export"][
                        "publisher_flush_allowance_ns"
                    ],
                    "request_lifetime_bound_violation_count": result["decision_event_export"][
                        "request_lifetime_bound_violation_count"
                    ],
                    "raw_inputs_removed": result["finalization"]["raw_prompt_token_inputs_removed"],
                    "fake_event_inventory": result["fake_kv_event_rehearsal"]["inventory"],
                    "immediate_finalization": result["finalization"]["start"],
                    "clock_info": result["clock_info"],
                }
                Path(summary_path).write_text(
                    json.dumps(summary, indent=2) + "\n", encoding="utf-8", newline="\n"
                )
            print(
                "Whole r0-v2 rehearsal: four runs, seven corpora, sustained levels, native pressure/waiting signals and nonempty real-gateway event correlations"
            )

    def test_gateway_decisions_tokenize_export_and_capture_join_end_to_end(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            FakeBackend(
                FakeBackendConfig(backend_id="decision-export", first_item_delay_ms=80)
            ) as backend,
        ):
            prompts = Path(directory) / "restricted-prompts.jsonl"
            terminals = Path(directory) / "gateway.jsonl"
            decisions_path = Path(directory) / "restricted-decisions.jsonl"
            offset = time.time_ns() - time.perf_counter_ns()
            with self.running_gateway([backend], terminal_log=terminals) as url:
                run = run_calibration(
                    CalibrationConfig(
                        url=url,
                        token="local-dev-token",
                        tenant_id="tenant-a",
                        model="test-model",
                        run_id="decision-export",
                        max_tokens=2,
                        timeout_seconds=5,
                        prompt_text="distinct decision-export prompt block " * 20,
                        decision_prompt_export_path=str(prompts),
                    ),
                    (1,),
                )
                events = read_http_sse_event_stream(backend.base_url + "/kv-events")
            records = run["levels"][0]["records"]
            self.assertEqual(records[0]["outcome"], "completed")
            logs = [json.loads(line) for line in terminals.read_text(encoding="utf-8").splitlines()]
            evidence = [
                json.loads(line) for line in prompts.read_text(encoding="utf-8").splitlines()
            ]
            exported = export_decisions(logs, evidence, backend.base_url)
            decisions_path.write_text(
                "".join(json.dumps(d) + "\n" for d in exported), encoding="utf-8", newline="\n"
            )
            loaded = load_routing_decisions(decisions_path, wall_to_monotonic_offset_ns=offset)
            self.assertEqual(
                loaded[0]["gateway_terminal_monotonic_ns"],
                exported[0]["gateway_terminal_unix_ns"] - offset,
            )
            correlated = correlate_routing_events(loaded, events)
            self.assertEqual(len(correlated), 1)
            self.assertEqual(correlated[0]["request_id"], records[0]["request_id"])
            self.assertEqual(correlated[0]["status"], "observed")
            self.assertEqual(
                correlated[0]["match_basis"], "identity_specific_16_token_block_digest"
            )
            self.assertNotIn("expected_token_ids", json.dumps(correlated))
            self.assertNotIn("messages", json.dumps(run))
            with self.assertRaisesRegex(ValueError, "empty gateway decision join"):
                export_decisions([], evidence, backend.base_url)
            with self.assertRaisesRegex(ValueError, "unmatched"):
                export_decisions(logs, [{**evidence[0], "request_id": "wrong"}], backend.base_url)

    def request(self, url: str) -> tuple[int, dict[str, str], bytes]:
        request = urllib.request.Request(
            f"{url}/v1/chat/completions",
            data=json.dumps(
                {
                    "model": "test-model",
                    "messages": [{"role": "user", "content": "hello"}],
                    "stream": True,
                }
            ).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer local-dev-token",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=2) as response:
                return (
                    response.status,
                    {key.lower(): value for key, value in response.headers.items()},
                    response.read(),
                )
        except urllib.error.HTTPError as error:
            return (
                error.code,
                {key.lower(): value for key, value in error.headers.items()},
                error.read(),
            )

    def test_round_robin_streams_through_real_fake_backends(self) -> None:
        with (
            FakeBackend(FakeBackendConfig(backend_id="fake-a")) as first,
            FakeBackend(FakeBackendConfig(backend_id="fake-b")) as second,
        ):
            with self.running_gateway([first, second]) as url:
                results = [self.request(url), self.request(url)]

            for index, (status, headers, body) in enumerate(results):
                self.assertEqual(status, 200)
                self.assertEqual(
                    headers["x-inference-backend"], f"fake-{'a' if index == 0 else 'b'}"
                )
                self.assertIn(b'"count_source":"runtime_usage"', body)
                self.assertIn(b"data: [DONE]", body)
                request_id = headers["x-request-id"]
                selected = first if index == 0 else second
                self.assertEqual(selected.wait_for_terminal(request_id).terminal, "completed")

    def test_calibration_recorder_runs_through_gateway_with_aligned_samples(self) -> None:
        config = FakeBackendConfig(
            backend_id="fake-calibration",
            first_item_delay_ms=80,
            chunk_delay_ms=40,
        )
        with FakeBackend(config) as backend:
            with self.running_gateway([backend]) as url:
                result = run_calibration(
                    CalibrationConfig(
                        url=url,
                        token="local-dev-token",
                        tenant_id="tenant-local",
                        model="test-model",
                        run_id="gateway-calibration-test",
                        sample_interval_ms=10,
                        timeout_seconds=5,
                    ),
                    (1, 2),
                )

        records = [record for level in result["levels"] for record in level["records"]]
        self.assertEqual(len(records), 3)
        self.assertTrue(
            all(record["outcome"] == "completed" for record in records),
            records,
        )
        self.assertTrue(all(record["request_id"].startswith("req_") for record in records))
        self.assertTrue(
            any(
                any(
                    name.startswith("inference_gateway_backend_requests_running{") and value > 0
                    for name, value in sample.get("values", {}).items()
                )
                for level in result["levels"]
                for sample in level["metrics"]
            )
        )

    def test_backend_metrics_are_collected_and_exported_with_freshness(self) -> None:
        with (
            FakeBackend(FakeBackendConfig(backend_id="fake-a")) as first,
            FakeBackend(FakeBackendConfig(backend_id="fake-b")) as second,
        ):
            with self.running_gateway([first, second]) as url:
                deadline = time.monotonic() + 3
                body = ""
                while time.monotonic() < deadline:
                    with urllib.request.urlopen(f"{url}/metrics", timeout=1) as response:
                        body = response.read().decode("utf-8")
                    if (
                        'inference_gateway_backend_metrics_fresh{backend_id="fake-a"} 1' in body
                        and 'inference_gateway_backend_metrics_fresh{backend_id="fake-b"} 1' in body
                    ):
                        break
                    time.sleep(0.02)

        self.assertIn('inference_gateway_backend_metrics_fresh{backend_id="fake-a"} 1', body)
        self.assertIn('inference_gateway_backend_metrics_fresh{backend_id="fake-b"} 1', body)
        self.assertIn('inference_gateway_backend_requests_running{backend_id="fake-a"} 0', body)
        self.assertIn('inference_gateway_backend_requests_waiting{backend_id="fake-b"} 0', body)
        self.assertIn('inference_gateway_backend_kv_cache_usage_ratio{backend_id="fake-a"} 0', body)

    def test_malformed_first_item_maps_to_precommit_protocol_error(self) -> None:
        config = FakeBackendConfig(failure_mode=FailureMode.MALFORMED_FIRST_ITEM)
        with FakeBackend(config) as backend:
            with self.running_gateway([backend]) as url:
                status, headers, body = self.request(url)
            observation = backend.wait_for_terminal(headers["x-request-id"])

        self.assertEqual(status, 502)
        self.assertIn(b"upstream_protocol_error", body)
        self.assertEqual(observation.terminal, "malformed_first_item")

    def test_missing_upstream_usage_interrupts_committed_stream(self) -> None:
        with FakeBackend(FakeBackendConfig(emit_usage=False)) as backend:
            with self.running_gateway([backend]) as url:
                status, _, body = self.request(url)

        self.assertEqual(status, 200)
        self.assertIn(b"event: error", body)
        self.assertNotIn(b"[DONE]", body)

    def test_client_cancellation_reaches_real_fake_backend(self) -> None:
        config = FakeBackendConfig(
            failure_mode=FailureMode.STALL_AFTER_CHUNKS,
            failure_after_chunks=0,
            stall_timeout_ms=2_000,
        )
        with FakeBackend(config) as backend:
            with self.running_gateway([backend]) as url:
                parsed = urllib.parse.urlsplit(url)
                connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=2)
                payload = json.dumps(
                    {
                        "model": "test-model",
                        "messages": [{"role": "user", "content": "hello"}],
                        "stream": True,
                    }
                )
                connection.request(
                    "POST",
                    "/v1/chat/completions",
                    body=payload,
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": "Bearer local-dev-token",
                    },
                )
                response = connection.getresponse()
                request_id = response.getheader("X-Request-ID")
                self.assertTrue(response.readline().startswith(b"data: "))
                response.close()
                connection.close()
                observation = backend.wait_for_terminal(request_id, timeout=1)

        self.assertEqual(observation.terminal, "client_cancelled")
        self.assertTrue(observation.cancellation_observed)


if __name__ == "__main__":
    unittest.main()
