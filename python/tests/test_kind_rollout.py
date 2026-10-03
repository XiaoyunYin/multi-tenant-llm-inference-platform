"""Completion accounting must validate payload, protocol order and EOF outcome."""

import json
import unittest

from inference_platform.kind_rollout import (
    EXPECTED_CONTENT,
    pod_stream_coverage,
    require_sigterm_coverage,
    stream_result,
    unix_ns,
)


class RolloutAccountingTests(unittest.TestCase):
    def events(self):
        return [
            json.dumps(
                {"choices": [{"delta": {"content": EXPECTED_CONTENT}, "finish_reason": "stop"}]}
            ),
            json.dumps({"choices": [], "usage": {"completion_tokens": 24}}),
            "[DONE]",
        ]

    def test_complete_requires_exact_content_usage_finish_done_and_transport(self):
        self.assertEqual(stream_result(self.events())["outcome"], "completed")
        for events in [
            self.events()[:-1],
            self.events()[1:],
            self.events()[::2],
            self.events()[::-1],
            self.events() + ["[DONE]"],
        ]:
            self.assertNotEqual(stream_result(events)["outcome"], "completed")
        for error in ["IncompleteRead", "TimeoutError"]:
            self.assertNotEqual(
                stream_result(self.events(), transport_error=error)["outcome"], "completed"
            )
        self.assertEqual(stream_result([], status=503)["outcome"], "failed")
        self.assertEqual(stream_result(self.events()[:-1])["outcome"], "partial")

    def test_gateway_error_cannot_complete(self):
        events = self.events()[:-1] + [
            json.dumps({"error": {"code": "upstream_failure"}}),
            "[DONE]",
        ]
        self.assertEqual(stream_result(events)["outcome"], "partial")
        self.assertTrue(stream_result(events)["false_complete"])

    def test_wall_timestamp_keeps_nanoseconds(self):
        self.assertEqual(unix_ns("2026-10-02T00:00:00.123456789Z") % 1_000_000_000, 123456789)

    def coverage(self, end, service="gateway", gen="old"):
        rows = [{"request_id": "r1"}]
        routes = {
            "r1": {
                "pod": "gateway-a",
                "pod_generation": "old",
                "backend_id": "fake-1",
                "backend_generation": "old",
                "router_decision_unix_ns": 1_000_000,
            }
        }
        terminals = {"r1": {"time_unix_ns": end}}
        pod = "gateway-a" if service == "gateway" else "fake-1"
        return {
            "pod": pod,
            **pod_stream_coverage(rows, routes, terminals, pod, gen, service, 2_000_000, 3_000_000),
        }

    def test_each_terminated_pod_must_have_streams_at_sigterm(self):
        active = self.coverage(5_000_000)
        ended_during_prestop = self.coverage(2_500_000)
        self.assertEqual(ended_during_prestop["streams_inflight_at_deletion"], 1)
        self.assertEqual(ended_during_prestop["streams_inflight_at_sigterm"], 0)
        # A covered first gateway cannot conceal the second one's zero count.
        with self.assertRaisesRegex(ValueError, "zero streams at SIGTERM"):
            require_sigterm_coverage([active, ended_during_prestop])
        with self.assertRaisesRegex(ValueError, "zero streams at SIGTERM"):
            require_sigterm_coverage([self.coverage(3_000_000, "fake")])

    def test_positive_coverage_records_post_signal_durations(self):
        stage = self.coverage(5_000_000)
        require_sigterm_coverage([stage])
        self.assertEqual(stage["streams_inflight_at_deletion"], 1)
        self.assertEqual(stage["streams_inflight_at_sigterm"], 1)
        self.assertEqual(stage["streams_after_sigterm"][0]["ran_after_sigterm_ms"], 2.0)
        self.assertEqual(stage["last_stream_terminal_after_sigterm_ms"], 2.0)
        # Pod/IP/name reuse must not count the old generation's request.
        self.assertEqual(self.coverage(5_000_000, "fake", "new")["streams_inflight_at_sigterm"], 0)

    def test_backend_coverage_requires_backend_counter(self):
        stage = self.coverage(5_000_000, "fake")
        stage["backend_active_at_sigterm"] = 0
        with self.assertRaisesRegex(ValueError, "zero backend requests"):
            require_sigterm_coverage([stage])
        stage["backend_active_at_sigterm"] = 1
        require_sigterm_coverage([stage])
