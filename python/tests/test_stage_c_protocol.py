import json
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from inference_platform.calibration import CalibrationConfig, derive_runtime_regime, run_calibration
from inference_platform.fake_backend import FakeBackend, FakeBackendConfig
from inference_platform.stage_c_capture import finish_capture, prepare_paths, start_live_capture
from inference_platform.stage_c_gateway import main as launch_gateway
from inference_platform.stage_c_prompts import exact_prompt, prompt_bank


class ApprovedProtocolTest(unittest.TestCase):
    def test_sustained_censored_records_are_counted_per_level(self):
        def censored(config, digest, start_ns, prompt, deadline):
            return {
                "http_status": 504,
                "first_content_offset_ns": None,
                "dispatch_offset_ns": time.perf_counter_ns() - start_ns,
            }

        config = CalibrationConfig(
            url="http://unused",
            token="test",
            tenant_id="test",
            model="test",
            run_id="censor-test",
            sample_interval_ms=1,
        )
        with (
            patch("inference_platform.calibration._metrics", return_value={"values": {}}),
            patch("inference_platform.calibration._stream_request", side_effect=censored),
        ):
            result = run_calibration(
                # Disk recorder creation and Windows thread scheduling can consume
                # the former 30 ms window before a second cycle starts. Exercise
                # sustained repetition without weakening its count assertions.
                config,
                (1, 2),
                level_duration_seconds=0.3,
                minimum_cycle_seconds=0.005,
            )
        for level in result["levels"]:
            self.assertGreater(len(level["records"]), level["concurrency"])
            self.assertEqual(level["censored_ttft_count"], len(level["records"]))

    def test_full_approved_prompt_sizes_and_first_block_distinction(self):
        with FakeBackend(FakeBackendConfig()) as backend:
            config = SimpleNamespace(tokenize_url=backend.base_url, model="test-model")
            deadline = time.perf_counter() + 5
            for target in (6144, 1024):
                prompts = prompt_bank(config, "verified-" + str(target), 2, target, deadline)
                first = []
                for i, prompt in enumerate(prompts):
                    text, tokens = exact_prompt(
                        backend.base_url,
                        "test-model",
                        "verified-" + str(target) + f"-{i}",
                        target,
                        deadline,
                    )
                    self.assertEqual(text, prompt)
                    self.assertEqual(len(tokens), target)
                    first.append(tokens[:16])
                self.assertNotEqual(*first)

    def test_native_labelled_regimes_and_counter_reset(self):
        def sample(preemptions, running, waiting):
            return {
                "values": {
                    'native.vllm:num_preemptions_total{model_name="test"}': preemptions,
                    'native.vllm:num_requests_running{model_name="test"}': running,
                    'native.vllm:num_requests_waiting{model_name="test"}': waiting,
                }
            }

        observed = derive_runtime_regime([sample(4, 1, 0), sample(7, 16, 2)])
        self.assertEqual(observed["preemptions_delta"], 3)
        self.assertEqual(observed["running_peak"], 16)
        self.assertEqual(observed["waiting_peak"], 2)
        self.assertIn("kv_pressure_preemptions_observed", observed["labels"])
        self.assertIn("waiting_observed", observed["labels"])
        reset = derive_runtime_regime([sample(7, 1, 0), sample(0, 0, 0)])
        self.assertIsNone(reset["preemptions_delta"])
        self.assertIn("regime_unestablished_missing_native_signals", reset["labels"])
        self.assertIsNone(derive_runtime_regime([])["running_peak"])

    def test_launcher_executes_reviewed_environment_without_shell(self):
        root = Path(__file__).resolve().parents[2]
        config = root / "docs/INF011_STAGE_C_GATEWAY_ENV.json"
        with (
            patch(
                "sys.argv",
                [
                    "launcher",
                    "--environment-json",
                    str(config),
                    "--gateway-binary",
                    "/opt/inf011/gateway",
                ],
            ),
            patch("inference_platform.stage_c_gateway.os.execve") as execute,
            patch("inference_platform.stage_c_gateway.subprocess.run") as validate,
        ):
            launch_gateway()
        binary, argv, environment = execute.call_args.args
        self.assertEqual(validate.call_args.args[0], [binary, "--check-config"])
        self.assertEqual(validate.call_args.kwargs["env"], environment)
        self.assertEqual(binary, argv[0])
        self.assertEqual(environment["GATEWAY_FIRST_ITEM_TIMEOUT"], "120s")
        self.assertEqual(environment["GATEWAY_TOTAL_TIMEOUT"], "180s")
        self.assertEqual(environment["ADMISSION_LEASE"], "240s")

    def test_capture_freshness_precedes_subscription_and_stale_path_fails(self):
        config = SimpleNamespace(
            kv_capture_output_path="/opt/inf011/capture-private/test/capture.json",
            kv_capture_stop_file="/opt/inf011/capture-private/test/stop",
            decision_export_output_path="/opt/inf011/capture-private/test/decisions.jsonl",
            kv_event_endpoint="tcp://127.0.0.1:5557",
            kv_event_topic="kv-events",
            evidence_export_margin_seconds=600,
        )
        process = Mock()
        process.poll.return_value = None
        receipt = SimpleNamespace(returncode=0, stdout=json.dumps({"subscribed": True}))
        with (
            patch(
                "inference_platform.stage_c_capture.docker",
                side_effect=[
                    SimpleNamespace(
                        stdout=json.dumps(
                            [
                                {
                                    "Type": "bind",
                                    "Source": "/host/private",
                                    "Destination": "/opt/inf011/capture-private",
                                    "RW": True,
                                }
                            ]
                        )
                    ),
                    receipt,
                    receipt,
                ],
            ) as docker,
            patch(
                "inference_platform.stage_c_capture.subprocess.Popen", return_value=process
            ) as launch,
            patch("inference_platform.stage_c_capture.time.sleep"),
        ):
            self.assertIs(start_live_capture(config, time.perf_counter() + 20), process)
        freshness = docker.call_args_list[1].args[1]
        self.assertIn("os.path.exists", freshness[freshness.index("-c") + 1])
        self.assertEqual(
            freshness[freshness.index("-c") + 2 :],
            [
                config.kv_capture_output_path + ".ready",
                config.kv_capture_stop_file,
                config.kv_capture_output_path,
            ],
        )
        self.assertNotIn(config.decision_export_output_path, freshness)
        self.assertIn("PYTHONDONTWRITEBYTECODE=1", freshness)
        self.assertEqual(freshness[freshness.index("python3") + 1], "-B")
        self.assertEqual(launch.call_args.kwargs["shell"], False)
        self.assertIn("--ready-file", launch.call_args.args[0])
        command = launch.call_args.args[0]
        self.assertGreater(float(command[command.index("--duration-seconds") + 1]), 300)
        with (
            patch("inference_platform.stage_c_capture.docker", side_effect=RuntimeError("stale")),
            patch("inference_platform.stage_c_capture.subprocess.Popen") as launch,
            self.assertRaisesRegex(RuntimeError, "stale"),
        ):
            start_live_capture(config, time.perf_counter() + 20)
        launch.assert_not_called()

    def test_unmatched_terminal_join_refuses_and_preexisting_raw_file_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = SimpleNamespace(
                decision_prompt_export_path=str(root / "prompts.jsonl"),
                decision_export_output_path=str(root / "decisions.jsonl"),
                gateway_config_log=str(root / "gateway.jsonl"),
                tokenize_url="http://unused",
            )
            prepare_paths(config)
            Path(config.decision_prompt_export_path).write_text(
                '{"request_id":"missing"}\n', encoding="utf-8"
            )
            Path(config.gateway_config_log).write_text("", encoding="utf-8")
            with (
                patch("inference_platform.stage_c_capture.time.perf_counter", side_effect=[0, 4]),
                self.assertRaisesRegex(RuntimeError, "unmatched measured"),
            ):
                finish_capture(config, [], 10)
            with (
                patch(
                    "inference_platform.stage_c_capture.time.perf_counter", side_effect=[0, 0, 3.1]
                ),
                self.assertRaisesRegex(RuntimeError, "unmatched measured"),
            ):
                finish_capture(config, [], 10)
            before = Path(config.decision_prompt_export_path).read_bytes()
            with self.assertRaises(FileExistsError):
                prepare_paths(config)
            self.assertEqual(Path(config.decision_prompt_export_path).read_bytes(), before)
