import unittest
from unittest.mock import MagicMock, patch

from inference_platform.kv_event_capture import probe_zmq_publisher


class PublisherProbeTest(unittest.TestCase):
    def test_subscriber_triggers_untimed_request_then_requires_decoded_store(self):
        for events, status in (([{"event_type": "BlockStored"}], "ok"), ([], "unavailable")):
            calls = []
            response = MagicMock()

            def capture(endpoint, calls=calls, events=events, **kwargs):
                calls.append("subscribed")
                self.assertEqual(kwargs["topic"], "kv-events")
                self.assertTrue(kwargs["stop_after_block_stored"])
                kwargs["on_subscribed"]()
                calls.append("decoded")
                return events

            def request(*args, calls=calls, response=response, **kwargs):
                calls.append("untimed-request")
                return response

            with (
                self.subTest(status=status),
                patch(
                    "inference_platform.kv_event_capture.capture_zmq_event_stream",
                    side_effect=capture,
                ),
                patch("inference_platform.time_budget.deadline_urlopen", side_effect=request),
                patch("inference_platform.kv_event_capture.time.sleep"),
            ):
                result = probe_zmq_publisher(
                    "tcp://127.0.0.1:5557", "kv-events", "http://127.0.0.1:8000", "model", 20
                )
            self.assertEqual(calls, ["subscribed", "untimed-request", "decoded"])
            self.assertEqual(result["status"], status)
            self.assertIn("implementation", result["clock_info"]["clocks"]["perf_counter"])
