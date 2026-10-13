import copy
import json
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import Mock, patch

from inference_platform.r1_agent import Host
from inference_platform.r1_analysis import candidate, eligible, noise, percentile, warm_rates
from inference_platform.r1_fake import Fake
from inference_platform.r1_launcher import backend_command, gateway_environment
from inference_platform.r1_manifest import (
    build,
    epoch,
    load,
    row,
    tenant_salt,
    trace,
    trace_profile,
)
from inference_platform.r1_metrics import delta, parse
from inference_platform.r1_reset import PreparationFailed, Reset
from inference_platform.r1_session import RealClock, Session
from inference_platform.r1_spec import digest, encoded, verify_spec
from inference_platform.r1_transport import HTTP, private_url
from inference_platform.stage_c_tokenizer import pinned_tokenizer


class ManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.path = Path(cls.directory.name)
        cls.manifest = build(cls.path, "offline-r1-rehearsal")

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def test_exact_pinned_manifest_and_sentinel(self):
        value, banks = load(self.path)
        self.assertEqual(value, self.manifest)
        workload = banks["workload.jsonl"]
        self.assertEqual(len(workload), 384)
        self.assertEqual(
            len({block for item in workload for block in item["reusable_block_sha256"]}), 24192
        )
        first = {tuple(item["tokens"][:16]) for item in workload + banks["calibration.jsonl"]}
        sentinel = banks["sentinel.jsonl"][0]
        self.assertNotIn(tuple(sentinel["tokens"][:16]), first)
        self.assertEqual(len(sentinel["tokens"]), 1024)
        self.assertEqual(len(sentinel["reusable_block_sha256"]), 63)
        self.assertEqual(sentinel["request_sha256"], digest(sentinel["request"]))

    def test_other_spec_and_resealed_incompatible_inputs_refused(self):
        for commit in ("3d3c36a", "0" * 40, "HEAD"):
            with self.assertRaises(ValueError):
                verify_spec(commit)
        original = (self.path / "manifest.json").read_bytes()
        for field in ("reset_hard_s", "prefixes", "seeds", "temperature"):
            altered = copy.deepcopy(self.manifest)
            altered["fixed"][field] = 17
            altered.pop("manifest_sha256")
            altered["manifest_sha256"] = digest(altered)
            (self.path / "manifest.json").write_bytes(encoded(altered))
            try:
                with self.assertRaises(ValueError):
                    load(self.path)
            finally:
                (self.path / "manifest.json").write_bytes(original)

    def test_file_tamper_and_missing_bank_refused(self):
        original = (self.path / "sentinel.jsonl").read_bytes()
        (self.path / "sentinel.jsonl").write_bytes(original + b" ")
        try:
            with self.assertRaises(ValueError):
                load(self.path)
        finally:
            (self.path / "sentinel.jsonl").write_bytes(original)

    def test_weighted_epochs_order_and_finite_reuse(self):
        entries = epoch("measure", "b1")
        self.assertEqual(sum(int(prefix[1:]) < 96 for prefix, _ in entries), 1152)
        self.assertEqual(len(entries), 1440)
        self.assertNotEqual(entries, epoch("measure", "b2"))
        profile = trace_profile(trace("measure", "b1", 2.4, 600))
        self.assertEqual(profile["hot_share"], 0.8)
        self.assertEqual(profile["unseen"], 384)
        sample = [{"prefix": p} for p in ("p000", "p001", "p001", "p002", "p000")]
        self.assertEqual(trace_profile(sample)["reuse_distinct_blocks"]["max"], 188)
        self.assertEqual(trace_profile(sample)["reuse_requests"]["max"], 3)

    def test_dynamic_calibration_manifest_exact_and_disjoint(self):
        tokenizer = pinned_tokenizer()
        first = set()
        for cycle in range(3):
            value = row(f"cal-0-8-0-cycle-{cycle}", "offline-r1-rehearsal-cal", tokenizer)
            self.assertNotIn(tuple(value["tokens"][:16]), first)
            first.add(tuple(value["tokens"][:16]))


class ResetTests(unittest.TestCase):
    def test_generator_cannot_dispatch_during_pending_preparation(self):
        io = Fake("success")
        io.begin_preparation(1)
        with self.assertRaisesRegex(ValueError, "dispatch forbidden"):
            io.phase("run1-measure", 600, 120, q=42)

    def exercise(self, case, deadline=120):
        io, events = Fake(case), []
        io.begin_preparation(1)
        reset = Reset(io, events.append, 1, deadline)
        try:
            baseline = reset.run()
        except PreparationFailed:
            baseline = None
        return io, events, baseline

    def test_success_second_cleanup_and_probe_exclusion(self):
        io, events, baseline = self.exercise("second_reset_cleanup")
        self.assertIsNotNone(baseline)
        self.assertFalse(any(io.cache))
        self.assertEqual([item["queries"] for item in baseline], [3072, 3072])
        self.assertEqual([item["hits"] for item in baseline], [1008, 1008])
        self.assertEqual(len([e for e in events if e["event"] == "reset_reply"]), 4)
        self.assertTrue(all(not e["slot_consumed"] for e in events if "slot_consumed" in e))

    def test_false_with_work_retries_but_idle_false_does_not(self):
        for case in ("in_flight_refusal", "http200_false"):
            with self.subTest(case=case):
                io, events, baseline = self.exercise(case)
                self.assertIsNotNone(baseline)
                replies = [
                    e
                    for e in events
                    if e["event"] == "reset_reply" and e["stage"] == "clear" and e["backend"] == 0
                ]
                self.assertFalse(replies[0]["response"]["success"])
                self.assertEqual(replies[0]["response"]["status"], 200)
                self.assertGreaterEqual(
                    replies[1]["attempt_started_elapsed_s"]
                    - replies[0]["attempt_started_elapsed_s"],
                    1,
                )
        io, events, baseline = self.exercise("idle_refusal")
        self.assertIsNone(baseline)
        self.assertEqual(io.posts[(1, 0, "clear")], 1)
        self.assertIn("without observable work", events[-1]["reason"])
        self.assertEqual(events[-1]["slot_state"], "not_started")

    def test_three_attempt_exhaustion_and_uncertain_timeout(self):
        io, events, baseline = self.exercise("three_refusals")
        self.assertIsNone(baseline)
        self.assertEqual(io.posts[(1, 0, "clear")], 3)
        attempts = [e["attempt_started_elapsed_s"] for e in events if e["event"] == "reset_reply"]
        self.assertTrue(all(b - a >= 1 for a, b in zip(attempts, attempts[1:], strict=False)))
        self.assertIsNotNone(self.exercise("timeout_uncertain")[2])

    def test_overrun_and_exhaustion_record_actual_wait_and_pending(self):
        io, events, baseline = self.exercise("delayed_success")
        self.assertIsNotNone(baseline)
        waits = [e for e in events if e["event"] == "reset_overrun_wait"]
        self.assertEqual(len(waits), 1)
        self.assertEqual(waits[0]["elapsed_s"], 60)
        self.assertGreater(events[-1]["elapsed_s"], 60)
        self.assertLessEqual(events[-1]["elapsed_s"], 120)
        self.assertAlmostEqual(events[-1]["wait_elapsed_s"], events[-1]["elapsed_s"] - 60)
        for deadline in (120, 75):
            io, events, baseline = self.exercise("exhaust_before_run1", deadline)
            self.assertIsNone(baseline)
            self.assertEqual(events[-1]["elapsed_s"], deadline)
            self.assertEqual(events[-1]["wait_elapsed_s"], deadline - 60)
            self.assertEqual(events[-1]["slot_state"], "not_started")
            self.assertFalse(events[-1]["slot_consumed"])

    def test_prior_phase_expected_counters_settle_before_positive_control(self):
        io, events = Fake("success"), []
        for backend in range(2):
            io.floors[backend] = {"queries": 1024, "completions": 1}
            io.updates.append((4, backend, {"queries": 1024, "hits": 512, "completions": 1}))
        io.begin_preparation(1)
        baseline = Reset(io, events.append, 1, 120).run()
        settled = next(e for e in events if e["event"] == "counters_settled")
        self.assertGreaterEqual(settled["elapsed_s"], 5)
        self.assertEqual([x["queries"] for x in baseline], [4096, 4096])
        positive = next(
            e for e in events if e["event"] == "sentinel" and e["label"] == "positive_control"
        )
        self.assertEqual([x["hits"] for x in positive["deltas"]], [1008, 1008])

    def test_late_counters_and_failed_controls(self):
        io, events, baseline = self.exercise("late_counters")
        self.assertIsNotNone(baseline)
        probes = [e for e in events if e["event"] == "sentinel"]
        self.assertTrue(all(all(d["queries"] == 1024 for d in e["deltas"]) for e in probes))
        for case in ("positive_control_failure", "zero_hit_failure"):
            io, events, baseline = self.exercise(case)
            self.assertIsNone(baseline)
            self.assertEqual(events[-1]["slot_state"], "not_started")

    def test_one_invalid_run_continues_and_is_excluded_from_pairs(self):
        class Invalid(Fake):
            def phase(self, *args, **kwargs):
                result = super().phase(*args, **kwargs)
                if args[0] == "run1-measure":
                    result["resources_valid"] = False
                return result

        with tempfile.TemporaryDirectory() as output:
            result = Session(Invalid("success"), {"manifest_sha256": "fixture"}, output).run()
            self.assertIsNone(result["error"])
            self.assertEqual(len(result["runs"]), 6)
            self.assertEqual(
                [s["state"] for s in result["slots"][:6]], ["invalid"] + ["completed"] * 5
            )
            self.assertTrue(all(s["consumed"] for s in result["slots"][:6]))
            pair = result["noise"]["paired_differences"]["hash"]["throughput"]
            self.assertIsNone(pair["per_block"][0])
            self.assertFalse(pair["per_block_validity"][0]["valid"])
            self.assertTrue(pair["per_block_validity"][1]["valid"])
            self.assertIsNone(pair["mean"])

    def test_session_head_is_frozen_before_runtime(self):
        with tempfile.TemporaryDirectory() as output:
            with patch(
                "inference_platform.r1_session.subprocess.check_output", return_value="a" * 40
            ):
                session = Session(Fake("success"), {"manifest_sha256": "fixture"}, output)
            with patch(
                "inference_platform.r1_session.subprocess.check_output", return_value="b" * 40
            ):
                result = session.run()
        self.assertEqual(result["head"], "a" * 40)

    def test_unexpected_exceptions_persist_end_and_result_before_reraising(self):
        for exception in (KeyError("field"), TypeError("type"), RuntimeError("finish")):
            with (
                self.subTest(exception=type(exception).__name__),
                tempfile.TemporaryDirectory() as output,
            ):
                io = Fake("success")
                if isinstance(exception, RuntimeError):
                    io.finish = Mock(side_effect=exception)
                else:
                    io.runtime_fitness = Mock(side_effect=exception)
                with self.assertRaises(type(exception)):
                    Session(io, {"manifest_sha256": "fixture"}, output).run()
                result = json.loads((Path(output) / "result.json").read_bytes())
                events = [
                    json.loads(line)
                    for line in (Path(output) / "events.jsonl").read_bytes().splitlines()
                ]
                self.assertEqual(result["exception_type"], type(exception).__name__)
                self.assertEqual(events[-1]["event"], "session_end")
                self.assertEqual(events[-1]["exception_type"], type(exception).__name__)

    def test_between_runs_preserves_completed_slot(self):
        with tempfile.TemporaryDirectory() as output:
            result = Session(
                Fake("exhaust_between_runs"), {"manifest_sha256": "fixture"}, output
            ).run()
            self.assertEqual(result["slots"][0]["state"], "completed")
            self.assertTrue(result["slots"][0]["consumed"])
            self.assertEqual(result["slots"][1]["state"], "not_started")
            self.assertTrue(all(not x["consumed"] for x in result["slots"][1:]))
            records = [
                json.loads(line)
                for line in (Path(output) / "events.jsonl").read_bytes().splitlines()
            ]
            starts = [e for e in records if e["event"] == "comparison_started"]
            self.assertEqual([e["id"] for e in starts], [1])
            failure = next(e for e in records if e["event"] == "reset_preparation_failed")
            self.assertEqual(failure["pending"], 2)
            self.assertEqual(failure["elapsed_s"], 120)


class FitnessAndLauncherTests(unittest.TestCase):
    def test_agent_closes_gateways_and_observes_draining_without_closed_listener(self):
        with tempfile.TemporaryDirectory() as directory:
            host = Host({"role": "service", "directory": directory})
            process = Mock(pid=42)
            process.poll.return_value = None
            host.processes = [process]
            host.close()
            process.terminate.assert_called_once()
            with patch(
                "inference_platform.r1_agent.request",
                side_effect=AssertionError("closed listener queried"),
            ):
                self.assertEqual(
                    host.state(time.perf_counter() + 5)["gateway_processes_draining"], 1
                )
                process.poll.return_value = 0
                self.assertEqual(
                    host.state(time.perf_counter() + 5)["gateway_processes_draining"], 0
                )

    def test_actual_backend_identity_rejects_missing_dev_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            command = backend_command(str(Path(directory).resolve()))
            image_index = command.index(next(value for value in command if "@sha256:" in value))
            item = {
                "Id": "container",
                "Image": "image",
                "State": {"Running": True, "StartedAt": "utc"},
                "Config": {
                    "Image": command[image_index],
                    "Cmd": command[image_index + 1 :],
                    "Env": ["VLLM_SERVER_DEV_MODE=1"],
                },
            }
            host = Host(
                {
                    "role": "backend",
                    "directory": directory,
                    "weight_cache": str(Path(directory).resolve()),
                }
            )
            host.image_identity = {"Id": "image", "Config": {"Env": []}}
            with patch(
                "inference_platform.r1_agent.subprocess.check_output", return_value=encoded([item])
            ):
                identity = host.identity(time.perf_counter() + 5)
                self.assertRegex(identity["generation"], r"^[0-9a-f]{64}$")
            item["Config"]["Env"] = []
            with patch(
                "inference_platform.r1_agent.subprocess.check_output", return_value=encoded([item])
            ):
                with self.assertRaises(ValueError):
                    host.identity(time.perf_counter() + 5)

    def test_real_http_serialization_and_false_stream_completions(self):
        received = []
        fixture = {"done": True, "prompt_tokens": 1024, "delay": 0}

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                received.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
                self.send_response(200)
                self.send_header("X-Inference-Backend", "gpu-0")
                self.end_headers()
                time.sleep(fixture["delay"])
                chunks = [
                    {"choices": [{"delta": {"content": "x"}, "finish_reason": None}]},
                    {"choices": [{"delta": {}, "finish_reason": "length"}]},
                    {
                        "choices": [],
                        "usage": {
                            "prompt_tokens": fixture["prompt_tokens"],
                            "completion_tokens": 1,
                        },
                    },
                ]
                try:
                    for chunk in chunks:
                        self.wfile.write(b"data: " + encoded(chunk) + b"\n\n")
                    if fixture["done"]:
                        self.wfile.write(b"data: [DONE]\n\n")
                except OSError:
                    pass

            def log_message(self, format, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            io = HTTP.__new__(HTTP)
            io.clock, io.config = RealClock(), {"credential": "synthetic"}
            value = {
                "request": {
                    "model": "fixture",
                    "messages": [],
                    "max_tokens": 1,
                    "temperature": 0,
                    "stream": True,
                    "cache_salt": "salt",
                    "stream_options": {"include_usage": True},
                }
            }
            url = f"http://127.0.0.1:{server.server_port}"
            success = io.stream(url, value, time.perf_counter() + 2, gateway=True)
            self.assertTrue(success["completed"])
            self.assertEqual(success["backend_id"], "gpu-0")
            self.assertNotIn("cache_salt", received[0])
            self.assertNotIn("stream_options", received[0])
            fixture["done"] = False
            self.assertFalse(io.stream(url, value, time.perf_counter() + 2)["completed"])
            fixture.update(done=True, prompt_tokens=1025)
            self.assertFalse(io.stream(url, value, time.perf_counter() + 2)["completed"])
            fixture.update(prompt_tokens=1024, delay=0.2)
            timed = io.stream(url, value, time.perf_counter() + 0.05)
            self.assertFalse(timed["completed"])
            self.assertTrue(timed["censored"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_native_units_label_and_monotonic_identity_checks(self):
        io = Fake("success")
        a = io.snapshots(5)[0]
        b = copy.deepcopy(a)
        b["queries"] += 1024
        b["hits"] += 1008
        self.assertEqual(delta(a, b)["queries"], 1024)
        for key, value in (("generation", "other"), ("queries", -1), ("age_s", 2)):
            broken = copy.deepcopy(b)
            broken[key] = value
            with self.assertRaises(ValueError):
                delta(a, broken)
        for text in ("", 'vllm:num_requests_running{model_name="other",engine="0"} 1'):
            with self.assertRaises(ValueError):
                parse(text, "gen", 1, 1)

    def test_launcher_keeps_dev_mode_and_effective_shared_admission(self):
        command = backend_command(str(Path(tempfile.gettempdir()).resolve()))
        self.assertIn("VLLM_SERVER_DEV_MODE=1", command)
        self.assertEqual(command[command.index("--max-num-queued-reqs") + 1], "32")
        secret = b"0" * 32
        inventory = [
            {"id": f"gpu-{i}", "generation": f"g{i}", "url": f"http://10.0.0.{i + 1}:8000"}
            for i in range(2)
        ]
        with tempfile.TemporaryDirectory() as directory:
            environments = [
                gateway_environment(
                    directory,
                    inventory,
                    "127.0.0.1:6379",
                    "r1:B18",
                    "synthetic",
                    secret,
                    "hash",
                    8,
                    1,
                    18,
                    4242,
                    i,
                )
                for i in range(2)
            ]
            self.assertEqual(
                environments[0]["ADMISSION_NAMESPACE"], environments[1]["ADMISSION_NAMESPACE"]
            )
            self.assertEqual(environments[0]["GATEWAY_ROUTING_SEED"], "4242")
            self.assertEqual(environments[0]["GOMAXPROCS"], "2")
            self.assertEqual(environments[0]["GATEWAY_HASH_AFFINITY_ESCAPE_MARGIN"], "2")
            self.assertEqual(len(tenant_salt(secret)), 43)
            self.assertNotEqual(tenant_salt(secret), tenant_salt(secret, "other-tenant"))
            with self.assertRaises(ValueError):
                gateway_environment(
                    directory, inventory, "redis", "r1", "cred", secret, "hash", 8, 1, 19, 4242, 0
                )

    def test_http_incompatible_inputs_fail_before_network(self):
        for value in (
            "https://10.0.0.1",
            "http://8.8.8.8",
            "http://example.com",
            "http://user@10.0.0.1",
        ):
            with self.assertRaises(ValueError):
                private_url(value)
        with self.assertRaises(ValueError):
            HTTP({"extra": True}, {"manifest_sha256": "x"}, {}, "unused")

    def test_invalid_warm_window_is_na_and_missing_metrics_do_not_spend_repeat(self):
        window = Fake("success").phase("run1-warm-0", 30, 0, q=42)
        self.assertTrue(warm_rates(window)[1])
        window["collector_gap_max_s"] = 3
        rates, valid = warm_rates(window)
        self.assertFalse(valid)
        self.assertEqual(rates, [None, None])
        runs = [
            {
                "policy": policy,
                "block": block,
                "summary": {
                    "throughput": value,
                    "TTFT_p50": None,
                    "TTFT_p95": None,
                    "invalid_reasons": [],
                },
            }
            for block, value in (("b1", 100), ("b2", 120))
            for policy in ("hash", "ll", "rr")
        ]
        runs[0]["summary"]["throughput"] = None
        self.assertIsNone(noise(runs)["conditional_policy"])

    def test_calibration_rules_and_missing_percentile(self):
        io = Fake("success")
        eligible_result = io.phase("staircase-8", 90, 30, level=8)
        self.assertTrue(eligible(eligible_result, 8))
        queued = io.phase("staircase-12", 90, 30, level=12)
        self.assertFalse(eligible(queued, 12))
        qualified = io.phase("candidate", 60, 30, q=42)
        self.assertTrue(candidate(qualified, 1, 42))
        qualified["resources_valid"] = False
        self.assertFalse(candidate(qualified, 1, 42))
        self.assertIsNone(percentile([1] * 399, 0.95, True))
        self.assertEqual(percentile([1] * 400, 0.95, True), 1)

    def test_conditional_repeat_largest_spread_ties_and_no_clamping(self):
        runs = [
            {
                "policy": policy,
                "block": block,
                "summary": {
                    "throughput": value,
                    "TTFT_p50": 1,
                    "TTFT_p95": 1,
                    "invalid_reasons": [],
                },
            }
            for block, value in (("b1", 100), ("b2", 120))
            for policy in ("hash", "ll", "rr")
        ]
        result = noise(runs)
        self.assertEqual(result["conditional_policy"], "rr")
        self.assertGreater(result["metrics"]["throughput"]["tolerance"], 0.15)
        self.assertFalse(result["metrics"]["throughput"]["validated"])
        runs[0]["summary"]["TTFT_p95"] = None
        self.assertIsNone(noise(runs)["metrics"]["TTFT_p95"]["spread"])


if __name__ == "__main__":
    unittest.main()
