import http.client
import json
import socket
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from inference_platform.fake_backend import (
    FailureMode,
    FakeBackend,
    FakeBackendConfig,
    StreamFraming,
    _write_ready_file,
    load_backend_config,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def _request(
    backend: FakeBackend, request_id: str, *, include_usage: bool = True
) -> tuple[http.client.HTTPConnection, http.client.HTTPResponse]:
    connection = http.client.HTTPConnection("127.0.0.1", backend.port, timeout=2)
    body = json.dumps(
        {
            "model": "test-model",
            "messages": [{"role": "user", "content": "hello"}],
            "stream": True,
            "stream_options": {"include_usage": include_usage},
        }
    )
    connection.request(
        "POST",
        "/v1/chat/completions",
        body=body,
        headers={"Content-Type": "application/json", "X-Request-ID": request_id},
    )
    return connection, connection.getresponse()


class FakeBackendTest(unittest.TestCase):
    def test_success_stream_has_identity_usage_and_done(self) -> None:
        config = FakeBackendConfig(
            backend_id="fake-a",
            chunks=("first", " second"),
            prompt_tokens=7,
            completion_tokens=2,
        )
        with FakeBackend(config) as backend:
            connection, response = _request(backend, "req-success")
            try:
                body = response.read().decode("utf-8")
            finally:
                connection.close()
            observation = backend.wait_for_terminal("req-success")

        self.assertEqual(response.status, 200)
        self.assertEqual(response.getheader("X-Inference-Backend"), "fake-a")
        events = [line.removeprefix("data: ") for line in body.splitlines() if line]
        decoded = [json.loads(event) for event in events[:-1]]
        self.assertEqual(
            decoded[0]["choices"][0]["delta"],
            {"role": "assistant", "content": ""},
        )
        self.assertEqual(
            [event["choices"][0]["delta"].get("content") for event in decoded[1:3]],
            ["first", " second"],
        )
        self.assertEqual(decoded[2]["choices"][0]["finish_reason"], "stop")
        self.assertEqual(
            decoded[3]["usage"],
            {
                "prompt_tokens": 7,
                "completion_tokens": 2,
                "total_tokens": 9,
            },
        )
        self.assertEqual(events[-1], "[DONE]")
        self.assertEqual(
            [kind for kind, _ in observation.events],
            ["role", "content", "content_finish", "usage", "done"],
        )
        self.assertEqual(observation.terminal, "completed")

    def test_independent_health_endpoints_expose_identity(self) -> None:
        with (
            FakeBackend(FakeBackendConfig(backend_id="fake-a")) as first,
            FakeBackend(FakeBackendConfig(backend_id="fake-b", healthy=False)) as second,
        ):
            with urllib.request.urlopen(f"{first.base_url}/health", timeout=2) as response:
                first_health = json.load(response)
            with self.assertRaises(urllib.error.HTTPError) as caught:
                urllib.request.urlopen(f"{second.base_url}/health", timeout=2)
            second_health = json.load(caught.exception)

        self.assertEqual(first_health, {"backend_id": "fake-a", "healthy": True})
        self.assertEqual(caught.exception.code, 503)
        self.assertEqual(second_health, {"backend_id": "fake-b", "healthy": False})

    def test_metrics_expose_vllm_shaped_running_waiting_and_kv_gauges(self) -> None:
        with FakeBackend(FakeBackendConfig(first_item_delay_ms=100)) as backend:
            connection, response = _request(backend, "req-metrics-active")
            try:
                with urllib.request.urlopen(f"{backend.base_url}/metrics", timeout=2) as metrics:
                    active = metrics.read().decode("utf-8")
                response.read()
                with urllib.request.urlopen(f"{backend.base_url}/metrics", timeout=2) as metrics:
                    idle = metrics.read().decode("utf-8")
            finally:
                connection.close()

        self.assertIn("vllm:num_requests_running 1\n", active)
        self.assertIn("vllm:num_requests_waiting 0\n", active)
        self.assertIn("vllm:kv_cache_usage_perc 0\n", active)
        self.assertIn("vllm:num_requests_running 0\n", idle)

    def test_empty_completion_is_a_successful_stream_without_content(self) -> None:
        with FakeBackend(FakeBackendConfig(chunks=(), completion_tokens=0)) as backend:
            connection, response = _request(backend, "req-empty")
            try:
                body = response.read()
            finally:
                connection.close()
            observation = backend.wait_for_terminal("req-empty")

        events = [
            json.loads(line.removeprefix(b"data: "))
            for line in body.splitlines()
            if line and line != b"data: [DONE]"
        ]
        content = [
            choice["delta"].get("content")
            for event in events
            for choice in event["choices"]
            if choice["delta"].get("content")
        ]
        self.assertEqual(content, [])
        self.assertIn(b'"completion_tokens":0', body)
        self.assertIn(b"data: [DONE]", body)
        self.assertEqual(observation.terminal, "completed")

    def test_legacy_separate_finish_framing_remains_available(self) -> None:
        config = FakeBackendConfig(chunks=("text",), stream_framing=StreamFraming.SEPARATE_FINISH)
        with FakeBackend(config) as backend:
            connection, response = _request(backend, "req-separate-finish")
            try:
                response.read()
            finally:
                connection.close()
            observation = backend.wait_for_terminal("req-separate-finish")

        self.assertEqual(
            [kind for kind, _ in observation.events],
            ["role", "content", "finish", "usage", "done"],
        )

    def test_first_item_and_chunk_delays_are_observable(self) -> None:
        config = FakeBackendConfig(
            chunks=("one", "two"),
            first_item_delay_ms=30,
            chunk_delay_ms=20,
        )
        with FakeBackend(config) as backend:
            connection, response = _request(backend, "req-delays")
            try:
                response.read()
            finally:
                connection.close()
            observation = backend.wait_for_terminal("req-delays")

        offsets = [offset for _, offset in observation.events]
        self.assertGreaterEqual(offsets[0], 20_000_000)
        self.assertGreaterEqual(offsets[1] - offsets[0], 10_000_000)
        self.assertGreaterEqual(offsets[2] - offsets[1], 10_000_000)

    def test_pre_stream_and_stream_failure_modes_are_reproducible(self) -> None:
        cases = (
            (FailureMode.HTTP_ERROR, 0, 503, b"fake_backend_failure", "http_error"),
            (
                FailureMode.INVALID_CONTENT_TYPE,
                0,
                200,
                b"non-stream response",
                "invalid_content_type",
            ),
            (FailureMode.CLOSE_BEFORE_FIRST_ITEM, 0, 200, b"", "closed_before_first_item"),
            (
                FailureMode.MALFORMED_FIRST_ITEM,
                0,
                200,
                b"data: {not-json}\n\n",
                "malformed_first_item",
            ),
            (
                FailureMode.INVALID_FIRST_ITEM,
                0,
                200,
                b'"object":"not-a-chat-completion"',
                "invalid_first_item",
            ),
            (
                FailureMode.MALFORMED_AFTER_CHUNKS,
                0,
                200,
                b"data: {not-json}\n\n",
                "malformed_stream",
            ),
            (FailureMode.CLOSE_AFTER_CHUNKS, 1, 200, b'"content":"one"', "truncated_stream"),
        )
        for index, (mode, failure_after, status, marker, terminal) in enumerate(cases):
            with self.subTest(mode=mode):
                config = FakeBackendConfig(
                    chunks=("one",), failure_mode=mode, failure_after_chunks=failure_after
                )
                with FakeBackend(config) as backend:
                    request_id = f"req-failure-{index}"
                    connection, response = _request(backend, request_id)
                    try:
                        body = response.read()
                    finally:
                        connection.close()
                    observation = backend.wait_for_terminal(request_id)

                self.assertEqual(response.status, status)
                self.assertIn(marker, body)
                self.assertNotIn(b"[DONE]", body)
                self.assertEqual(observation.terminal, terminal)
                if mode in {
                    FailureMode.MALFORMED_FIRST_ITEM,
                    FailureMode.INVALID_FIRST_ITEM,
                }:
                    self.assertNotIn(b'"role":"assistant"', body)

    def test_usage_is_requested_upstream_and_may_be_omitted(self) -> None:
        cases = ((True, True), (False, True), (True, False))
        for index, (include_usage, emit_usage) in enumerate(cases):
            with self.subTest(include_usage=include_usage, emit_usage=emit_usage):
                with FakeBackend(FakeBackendConfig(emit_usage=emit_usage)) as backend:
                    connection, response = _request(
                        backend, f"req-usage-{index}", include_usage=include_usage
                    )
                    try:
                        body = response.read()
                    finally:
                        connection.close()
                self.assertEqual(b'"usage"' in body, include_usage and emit_usage)
                self.assertNotIn(b"count_source", body)

    def test_chunked_request_body_is_accepted(self) -> None:
        payload = json.dumps(
            {
                "model": "test-model",
                "messages": [{"role": "user", "content": "hello"}],
                "stream": True,
                "stream_options": {"include_usage": True},
            }
        ).encode()
        with FakeBackend(FakeBackendConfig()) as backend:
            connection = http.client.HTTPConnection("127.0.0.1", backend.port, timeout=2)
            connection.putrequest("POST", "/v1/chat/completions")
            connection.putheader("Transfer-Encoding", "chunked")
            connection.putheader("X-Request-ID", "req-chunked")
            connection.endheaders()
            midpoint = len(payload) // 2
            for chunk in (payload[:midpoint], payload[midpoint:]):
                connection.send(f"{len(chunk):X}\r\n".encode() + chunk + b"\r\n")
            connection.send(b"0\r\n\r\n")
            response = connection.getresponse()
            try:
                body = response.read()
            finally:
                connection.close()
            observation = backend.wait_for_terminal("req-chunked")

        self.assertEqual(response.status, 200)
        self.assertIn(b"[DONE]", body)
        self.assertEqual(observation.terminal, "completed")

    def test_duplicate_request_id_is_rejected_without_merging_observations(self) -> None:
        config = FakeBackendConfig(first_item_delay_ms=50)
        with FakeBackend(config) as backend:
            first_connection, first_response = _request(backend, "req-duplicate")
            second_connection, second_response = _request(backend, "req-duplicate")
            try:
                second_body = second_response.read()
                first_body = first_response.read()
            finally:
                second_connection.close()
                first_connection.close()
            observation = backend.wait_for_terminal("req-duplicate")

        self.assertEqual(second_response.status, 409)
        self.assertIn(b"duplicate_request_id", second_body)
        self.assertIn(b"[DONE]", first_body)
        self.assertEqual(
            [kind for kind, _ in observation.events],
            ["role", "content", "content_finish", "usage", "done"],
        )

    def test_client_disconnect_during_stall_is_observed(self) -> None:
        config = FakeBackendConfig(
            chunks=("unused",),
            failure_mode=FailureMode.STALL_AFTER_CHUNKS,
            failure_after_chunks=0,
            stall_timeout_ms=2_000,
        )
        backend = FakeBackend(config)
        with backend:
            connection, response = _request(backend, "req-cancel")
            self.assertTrue(response.readline().startswith(b"data: "))
            self.assertEqual(response.readline(), b"\n")
            response.close()
            connection.close()
            observation = backend.wait_for_terminal("req-cancel", timeout=1)

        self.assertEqual(observation.terminal, "client_cancelled")
        self.assertTrue(observation.cancellation_observed)

    def test_stall_times_out_and_server_context_stops_cleanly(self) -> None:
        config = FakeBackendConfig(
            chunks=(),
            failure_mode=FailureMode.STALL_AFTER_CHUNKS,
            stall_timeout_ms=20,
        )
        started = time.monotonic()
        with FakeBackend(config) as backend:
            connection, response = _request(backend, "req-stall")
            try:
                body = response.read()
            finally:
                connection.close()
            observation = backend.wait_for_terminal("req-stall")

        self.assertLess(time.monotonic() - started, 1.5)
        self.assertNotIn(b"[DONE]", body)
        self.assertEqual(observation.terminal, "stall_timeout")
        self.assertFalse(backend.running)

    def test_server_shutdown_is_not_reported_as_client_cancellation(self) -> None:
        config = FakeBackendConfig(
            failure_mode=FailureMode.STALL_AFTER_CHUNKS,
            failure_after_chunks=0,
            stall_timeout_ms=2_000,
        )
        backend = FakeBackend(config).start()
        connection, response = _request(backend, "req-shutdown")
        self.assertTrue(response.readline().startswith(b"data: "))
        self.assertEqual(response.readline(), b"\n")
        backend.close()
        observation = backend.wait_for_terminal("req-shutdown")
        response.close()
        connection.close()

        self.assertEqual(observation.terminal, "server_shutdown")
        self.assertFalse(observation.cancellation_observed)

    def test_configured_bind_port_serves_health(self) -> None:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        with FakeBackend(FakeBackendConfig(), port=port) as backend:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=2) as response:
                health = json.load(response)
        self.assertEqual(backend.port, port)
        self.assertTrue(health["healthy"])

    def test_ready_file_is_replaced_without_temporary_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "ready.json"
            path.write_text("old", encoding="utf-8")
            with FakeBackend(FakeBackendConfig(backend_id="fake-ready")) as backend:
                _write_ready_file(path, backend)
                ready = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(ready, {"backend_id": "fake-ready", "url": backend.base_url})
            self.assertEqual(list(Path(temporary_directory).iterdir()), [path])

    def test_configuration_is_strict(self) -> None:
        example = load_backend_config(REPOSITORY_ROOT / "deploy/local/fake-backend-a.json")
        self.assertEqual(example.backend_id, "fake-backend-a")
        parsed = FakeBackendConfig.from_dict(
            {"backend_id": "fake-b", "failure_mode": "close_after_chunks", "chunks": ["x"]}
        )
        self.assertEqual(parsed.failure_mode, FailureMode.CLOSE_AFTER_CHUNKS)
        self.assertEqual(parsed.chunks, ("x",))
        with self.assertRaisesRegex(ValueError, "unknown fake backend fields"):
            FakeBackendConfig.from_dict({"backend_id": "fake-a", "surprise": True})
        with self.assertRaisesRegex(ValueError, "cannot exceed"):
            FakeBackendConfig(chunks=("x",), failure_after_chunks=2)
        with self.assertRaisesRegex(ValueError, "FailureMode"):
            FakeBackendConfig(failure_mode="none")
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "fake.json"
            path.write_text('{"backend_id":"fake-a","backend_id":"fake-b"}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate JSON member"):
                load_backend_config(path)


if __name__ == "__main__":
    unittest.main()
