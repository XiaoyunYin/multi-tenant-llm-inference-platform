"""Controllable OpenAI-shaped SSE backend for local gateway tests."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import select
import socket
import threading
import time
import uuid
from collections import OrderedDict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,190}$")
_MAX_REQUEST_BYTES = 1_048_576


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON member: {key!r}")
        value[key] = item
    return value


class FailureMode(StrEnum):
    """Deterministic terminal behaviors supported by the fake backend."""

    NONE = "none"
    HTTP_ERROR = "http_error"
    INVALID_CONTENT_TYPE = "invalid_content_type"
    MALFORMED_FIRST_ITEM = "malformed_first_item"
    INVALID_FIRST_ITEM = "invalid_first_item"
    CLOSE_BEFORE_FIRST_ITEM = "close_before_first_item"
    MALFORMED_AFTER_CHUNKS = "malformed_after_chunks"
    CLOSE_AFTER_CHUNKS = "close_after_chunks"
    STALL_AFTER_CHUNKS = "stall_after_chunks"


class StreamFraming(StrEnum):
    """Successful stream shapes used for gateway compatibility tests."""

    VLLM = "vllm"
    SEPARATE_FINISH = "separate_finish"


def _require_milliseconds(name: str, value: int, *, maximum: int = 60_000) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise ValueError(f"{name} must be an integer from 0 through {maximum}")


def _require_count(name: str, value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")


@dataclass(frozen=True, slots=True)
class FakeBackendConfig:
    """Complete behavior configuration for one fake backend instance."""

    backend_id: str = "fake-backend-a"
    chunks: tuple[str, ...] = ("hello", " world")
    first_item_delay_ms: int = 0
    health_ready_delay_ms: int = 0
    long_prompt_delay_ms: int = 0
    chunk_delay_ms: int = 0
    failure_mode: FailureMode = FailureMode.NONE
    failure_after_chunks: int = 0
    stall_timeout_ms: int = 5_000
    http_error_status: int = HTTPStatus.SERVICE_UNAVAILABLE
    healthy: bool = True
    prompt_tokens: int = 4
    completion_tokens: int = 2
    emit_usage: bool = True
    stream_framing: StreamFraming = StreamFraming.VLLM
    running_capacity: int = 2
    reject_above_active: int | None = None
    kv_cache_capacity_blocks: int = 32
    kv_blocks_per_unique_prompt: int = 2
    runtime_shaped_metrics: bool = False
    kv_event_blocks_per_store: int = 1

    def __post_init__(self) -> None:
        if not isinstance(self.backend_id, str) or not _IDENTIFIER_PATTERN.fullmatch(
            self.backend_id
        ):
            raise ValueError(f"backend_id must match {_IDENTIFIER_PATTERN.pattern}")
        if not isinstance(self.chunks, tuple) or any(
            not isinstance(chunk, str) or not chunk for chunk in self.chunks
        ):
            raise ValueError("chunks must be a tuple of non-empty strings")
        _require_milliseconds("first_item_delay_ms", self.first_item_delay_ms)
        _require_milliseconds("health_ready_delay_ms", self.health_ready_delay_ms)
        _require_milliseconds("long_prompt_delay_ms", self.long_prompt_delay_ms)
        _require_milliseconds("chunk_delay_ms", self.chunk_delay_ms)
        _require_milliseconds("stall_timeout_ms", self.stall_timeout_ms)
        if not isinstance(self.failure_mode, FailureMode):
            raise ValueError("failure_mode must be a FailureMode value")
        _require_count("failure_after_chunks", self.failure_after_chunks)
        if self.failure_after_chunks > len(self.chunks):
            raise ValueError("failure_after_chunks cannot exceed the number of chunks")
        if (
            isinstance(self.http_error_status, bool)
            or not isinstance(self.http_error_status, int)
            or not 400 <= self.http_error_status <= 599
        ):
            raise ValueError("http_error_status must be an integer from 400 through 599")
        if not isinstance(self.healthy, bool):
            raise ValueError("healthy must be a boolean")
        _require_count("prompt_tokens", self.prompt_tokens)
        _require_count("completion_tokens", self.completion_tokens)
        _require_count("kv_event_blocks_per_store", self.kv_event_blocks_per_store)
        if not 1 <= self.kv_event_blocks_per_store <= 32:
            raise ValueError("kv_event_blocks_per_store must be in [1, 32]")
        if not isinstance(self.emit_usage, bool):
            raise ValueError("emit_usage must be a boolean")
        if not isinstance(self.stream_framing, StreamFraming):
            raise ValueError("stream_framing must be a StreamFraming value")
        if (
            isinstance(self.running_capacity, bool)
            or not isinstance(self.running_capacity, int)
            or self.running_capacity <= 0
        ):
            raise ValueError("running_capacity must be a positive integer")
        if self.reject_above_active is not None and (
            isinstance(self.reject_above_active, bool)
            or not isinstance(self.reject_above_active, int)
            or self.reject_above_active <= 0
        ):
            raise ValueError("reject_above_active must be a positive integer or null")
        if (
            isinstance(self.kv_cache_capacity_blocks, bool)
            or not isinstance(self.kv_cache_capacity_blocks, int)
            or self.kv_cache_capacity_blocks <= 0
        ):
            raise ValueError("kv_cache_capacity_blocks must be a positive integer")
        _require_count("kv_blocks_per_unique_prompt", self.kv_blocks_per_unique_prompt)
        if self.kv_blocks_per_unique_prompt == 0:
            raise ValueError("kv_blocks_per_unique_prompt must be positive")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> FakeBackendConfig:
        """Parse a strict JSON configuration while permitting omitted defaults."""

        if not isinstance(value, Mapping):
            raise ValueError("fake backend configuration must be a JSON object")
        allowed = set(cls.__dataclass_fields__)
        unknown = set(value) - allowed
        if unknown:
            raise ValueError(f"unknown fake backend fields: {sorted(unknown)}")
        parsed = dict(value)
        if "chunks" in parsed:
            if not isinstance(parsed["chunks"], list):
                raise ValueError("chunks must be a JSON array")
            parsed["chunks"] = tuple(parsed["chunks"])
        if "failure_mode" in parsed:
            try:
                parsed["failure_mode"] = FailureMode(parsed["failure_mode"])
            except (TypeError, ValueError) as error:
                raise ValueError(f"unknown failure_mode: {parsed['failure_mode']!r}") from error
        if "stream_framing" in parsed:
            try:
                parsed["stream_framing"] = StreamFraming(parsed["stream_framing"])
            except (TypeError, ValueError) as error:
                raise ValueError(f"unknown stream_framing: {parsed['stream_framing']!r}") from error
        return cls(**parsed)


class _WaitResult(StrEnum):
    ELAPSED = "elapsed"
    CLIENT_DISCONNECTED = "client_disconnected"
    SERVER_STOPPING = "server_stopping"


@dataclass(frozen=True, slots=True)
class RequestObservation:
    """Thread-safe snapshot of a fake backend request lifecycle."""

    request_id: str
    started_at_ns: int
    events: tuple[tuple[str, int], ...]
    terminal: str | None
    cancellation_observed: bool


@dataclass(slots=True)
class _MutableObservation:
    request_id: str
    started_at_ns: int
    events: list[tuple[str, int]] = field(default_factory=list)
    terminal: str | None = None
    cancellation_observed: bool = False


class _ObservationStore:
    def __init__(self) -> None:
        self._condition = threading.Condition()
        self._requests: dict[str, _MutableObservation] = {}
        self._cached_blocks: OrderedDict[str, None] = OrderedDict()
        self._kv_events: list[dict[str, Any]] = []
        self._prefix_queries = 0
        self._prefix_hits = 0
        self._preemptions = 0

    def start(self, request_id: str) -> bool:
        with self._condition:
            if request_id in self._requests:
                return False
            self._requests[request_id] = _MutableObservation(request_id, time.perf_counter_ns())
            self._condition.notify_all()
            return True

    def event(self, request_id: str, kind: str) -> None:
        with self._condition:
            observation = self._requests[request_id]
            observation.events.append((kind, time.perf_counter_ns() - observation.started_at_ns))
            self._condition.notify_all()

    def finish(self, request_id: str, terminal: str, *, cancelled: bool = False) -> None:
        with self._condition:
            observation = self._requests[request_id]
            if observation.terminal is None:
                observation.terminal = terminal
                observation.cancellation_observed = cancelled
            self._condition.notify_all()

    def _append_kv_event(self, event: dict[str, Any]) -> None:
        self._kv_events.append(
            {
                "sequence": len(self._kv_events),
                "batch_timestamp_s": time.time(),
                "emitted_monotonic_ns": time.perf_counter_ns(),
                "events": [event],
            }
        )

    def observe_prompt(
        self,
        request_id: str,
        prompt_digest: str,
        token_ids: list[int],
        capacity_blocks: int,
        blocks_per_prompt: int,
        runtime_shaped: bool = False,
        event_blocks: int = 1,
    ) -> bool:
        # Capacity uses actual full blocks; the legacy synthetic count is unused.
        del blocks_per_prompt
        with self._condition:
            self._prefix_queries += len(token_ids) if runtime_shaped else 1
            active = sum(r.terminal is None for r in self._requests.values())
            if runtime_shaped and active * (len(token_ids) // 16) > capacity_blocks:
                self._preemptions += 1  # Declared fake pressure signal, not GPU performance.
            block_hashes = []
            parent = prompt_digest  # caller supplies model/cache-salt scope, not the whole prompt
            for start in range(0, len(token_ids) - 15, 16):
                parent = hashlib.sha256(
                    json.dumps(
                        [parent, token_ids[start : start + 16]], separators=(",", ":")
                    ).encode()
                ).hexdigest()
                block_hashes.append(parent)
            cached = 0
            for block_hash in block_hashes:
                if block_hash not in self._cached_blocks:
                    break
                self._cached_blocks.move_to_end(block_hash)
                cached += 1
            full_hit = bool(block_hashes) and cached == len(block_hashes)
            self._prefix_hits += cached * 16 if runtime_shaped else int(full_hit)
            # Runtime-shaped chunked storage: only new full blocks, no partial tail.
            event_blocks = min(event_blocks, capacity_blocks)
            for index in range(cached, len(block_hashes), event_blocks):
                end = min(index + event_blocks, len(block_hashes))
                evicted = []
                for current in range(index, end):
                    if len(self._cached_blocks) >= capacity_blocks:
                        evicted_hash, _ = self._cached_blocks.popitem(last=False)
                        evicted.append(evicted_hash)
                    self._cached_blocks[block_hashes[current]] = None
                if evicted:
                    self._append_kv_event(
                        {
                            "type": "BlockRemoved",
                            "block_hashes": evicted,
                            "medium": "GPU",
                            "group_idx": 0,
                        }
                    )
                self._append_kv_event(
                    {
                        "type": "BlockStored",
                        "block_hashes": block_hashes[index:end],
                        "parent_block_hash": block_hashes[index - 1] if index else None,
                        "token_ids": token_ids[index * 16 : end * 16],
                        "block_size": 16,
                        "medium": "GPU",
                        "group_idx": 0,
                    }
                )
            self._condition.notify_all()
            return full_hit

    def reset_cache(self) -> None:
        with self._condition:
            for block_hash in self._cached_blocks:
                self._append_kv_event(
                    {
                        "type": "BlockRemoved",
                        "block_hashes": [block_hash],
                        "medium": "GPU",
                        "group_idx": 0,
                    }
                )
            self._cached_blocks.clear()
            self._condition.notify_all()

    def metrics_snapshot(
        self, running_capacity: int, kv_capacity_blocks: int, blocks_per_prompt: int
    ) -> dict[str, int | float]:
        del blocks_per_prompt
        with self._condition:
            active = sum(observation.terminal is None for observation in self._requests.values())
            running = min(active, running_capacity)
            waiting = max(0, active - running_capacity)
            kv_used = min(
                kv_capacity_blocks,
                len(self._cached_blocks),
            )
            return {
                "running": running,
                "waiting": waiting,
                "kv_usage": kv_used / kv_capacity_blocks,
                "prefix_queries": self._prefix_queries,
                "prefix_hits": self._prefix_hits,
                "preemptions": self._preemptions,
            }

    def kv_events_after(self, sequence: int) -> list[dict[str, Any]]:
        with self._condition:
            return [event.copy() for event in self._kv_events if event["sequence"] >= sequence]

    def wait_for_kv_event(self, sequence: int, timeout: float) -> None:
        with self._condition:
            if any(event["sequence"] >= sequence for event in self._kv_events):
                return
            self._condition.wait(timeout)

    def wait_for_terminal(self, request_id: str, timeout: float) -> RequestObservation:
        deadline = time.perf_counter() + timeout
        with self._condition:
            while True:
                observation = self._requests.get(request_id)
                if observation is not None and observation.terminal is not None:
                    return RequestObservation(
                        request_id=observation.request_id,
                        started_at_ns=observation.started_at_ns,
                        events=tuple(observation.events),
                        terminal=observation.terminal,
                        cancellation_observed=observation.cancellation_observed,
                    )
                remaining = deadline - time.perf_counter()
                if remaining <= 0:
                    raise TimeoutError(f"request {request_id!r} did not terminate")
                self._condition.wait(remaining)

    def active_count(self) -> int:
        with self._condition:
            return sum(observation.terminal is None for observation in self._requests.values())


class _FakeBackendHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    # Match an async runtime's HTTP accept queue; the engine queue/rejection
    # remains controlled by running_capacity/reject_above_active, not TCP resets.
    request_queue_size = 256
    daemon_threads = False
    block_on_close = True

    def __init__(self, config: FakeBackendConfig, host: str, port: int) -> None:
        self.config = config
        self.observations = _ObservationStore()
        self.stop_event = threading.Event()
        self.started_at = time.perf_counter()
        from .stage_c_tokenizer import pinned_tokenizer

        self.chat_tokenizer = None
        self.tokenizer_error = None
        try:
            self.chat_tokenizer = pinned_tokenizer()
        except (ImportError, OSError, ValueError) as error:
            self.tokenizer_error = str(error)
        super().__init__((host, port), _FakeBackendHandler)


class _FakeBackendHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: _FakeBackendHTTPServer

    def log_message(self, format: str, *args: object) -> None:
        del format, args

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        if parsed.path == "/metrics":
            self._write_metrics()
            return
        if parsed.path == "/kv-events":
            self._stream_kv_events(parse_qs(parsed.query))
            return
        if parsed.path != "/health":
            self._write_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return
        healthy = self.server.config.healthy and (
            time.perf_counter() - self.server.started_at
            >= self.server.config.health_ready_delay_ms / 1000
        )
        status = HTTPStatus.OK if healthy else HTTPStatus.SERVICE_UNAVAILABLE
        self._write_json(
            status,
            {"backend_id": self.server.config.backend_id, "healthy": healthy},
        )

    def _write_metrics(self) -> None:
        snapshot = self.server.observations.metrics_snapshot(
            self.server.config.running_capacity,
            self.server.config.kv_cache_capacity_blocks,
            self.server.config.kv_blocks_per_unique_prompt,
        )
        payload = (
            "# HELP vllm:num_requests_running Number of requests currently running.\n"
            "# TYPE vllm:num_requests_running gauge\n"
            f"vllm:num_requests_running {snapshot['running']}\n"
            "# HELP vllm:num_requests_waiting Number of requests waiting to be processed.\n"
            "# TYPE vllm:num_requests_waiting gauge\n"
            f"vllm:num_requests_waiting {snapshot['waiting']}\n"
            "# HELP vllm:kv_cache_usage_perc Fraction of used KV-cache blocks.\n"
            "# TYPE vllm:kv_cache_usage_perc gauge\n"
            f"vllm:kv_cache_usage_perc {snapshot['kv_usage']:g}\n"
            "# HELP vllm:prefix_cache_queries_total Prefix cache queries.\n"
            "# TYPE vllm:prefix_cache_queries_total counter\n"
            f'vllm:prefix_cache_queries_total{{model_name="test-model"}} '
            f"{snapshot['prefix_queries']}\n"
            "# HELP vllm:prefix_cache_hits_total Prefix cache hits.\n"
            "# TYPE vllm:prefix_cache_hits_total counter\n"
            f'vllm:prefix_cache_hits_total{{model_name="test-model"}} '
            f"{snapshot['prefix_hits']}\n"
            f'vllm:num_preemptions_total{{model_name="test-model"}} {snapshot["preemptions"]}\n'
            f'vllm:cache_config_info{{num_gpu_blocks="{self.server.config.kv_cache_capacity_blocks}",block_size="16"}} 1\n'
        ).encode()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/plain; version=0.0.4")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)

    def _stream_kv_events(self, query: Mapping[str, list[str]]) -> None:
        try:
            sequence = max(0, int(query.get("after", ["0"])[0]))
            duration = min(60.0, max(0.01, float(query.get("duration", ["1"])[0])))
        except (TypeError, ValueError):
            self._write_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_event_stream_query"})
            return
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        deadline = time.perf_counter() + duration
        try:
            while time.perf_counter() < deadline and not self.server.stop_event.is_set():
                batches = self.server.observations.kv_events_after(sequence)
                for batch in batches:
                    payload = json.dumps(batch, separators=(",", ":")).encode("utf-8")
                    self.wfile.write(b"data: " + payload + b"\n\n")
                    self.wfile.flush()
                    sequence = int(batch["sequence"]) + 1
                if not batches:
                    self.server.observations.wait_for_kv_event(
                        sequence, min(0.05, max(0, deadline - time.perf_counter()))
                    )
        except (BrokenPipeError, ConnectionResetError, OSError):
            self.close_connection = True
        finally:
            self.close_connection = True

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path == "/tokenize":
            self._tokenize()
            return
        if path == "/reset_prefix_cache":
            self.server.observations.reset_cache()
            self._write_json(HTTPStatus.OK, {"success": True})
            return
        if path != "/v1/chat/completions":
            self._write_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return
        request_id = self.headers.get("X-Request-ID") or f"req_fake_{uuid.uuid4().hex}"
        if not self.server.observations.start(request_id):
            # Consume the bounded body before closing. On Windows, closing a socket with
            # unread request bytes can reset the connection and discard the 409 response.
            self._discard_request_body()
            self._write_json(
                HTTPStatus.CONFLICT,
                {"error": "duplicate_request_id", "request_id": request_id},
            )
            self.close_connection = True
            return
        try:
            request = self._read_request()
            if request is None:
                self.server.observations.finish(request_id, "invalid_request")
                return
            if (
                self.server.config.reject_above_active is not None
                and self.server.observations.active_count() > self.server.config.reject_above_active
            ):
                self._write_json(HTTPStatus.TOO_MANY_REQUESTS, {"error": "fake_capacity_rejected"})
                self.server.observations.finish(request_id, "capacity_rejected")
                return
            self._stream(request_id, request)
        except OSError:
            self.server.observations.finish(request_id, "client_cancelled", cancelled=True)
        finally:
            self.close_connection = True

    def _read_request(self) -> dict[str, Any] | None:
        try:
            body = self._read_request_body()
            value = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            self._write_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_json"})
            return None
        if not isinstance(value, dict) or value.get("stream") is not True:
            self._write_json(HTTPStatus.BAD_REQUEST, {"error": "stream_required"})
            return None
        model = value.get("model")
        if not isinstance(model, str) or not model:
            self._write_json(HTTPStatus.BAD_REQUEST, {"error": "model_required"})
            return None
        return value

    def _tokenize(self) -> None:
        try:
            body = json.loads(self._read_request_body())
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            self._write_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_tokenize_json"})
            return
        if (
            not isinstance(body, dict)
            or not isinstance(body.get("model"), str)
            or not isinstance(body.get("messages"), list)
            or body.get("add_generation_prompt") is not True
        ):
            self._write_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_tokenize_request"})
            return
        if any(
            not isinstance(message, dict) or not isinstance(message.get("content"), str)
            for message in body["messages"]
        ):
            self._write_json(HTTPStatus.BAD_REQUEST, {"error": "invalid_tokenize_message"})
            return
        if self.server.chat_tokenizer is None:
            self._write_json(
                HTTPStatus.SERVICE_UNAVAILABLE, {"error": "pinned_chat_tokenizer_unavailable"}
            )
            return
        try:
            token_ids = self.server.chat_tokenizer(body["messages"])
        except ValueError:
            self._write_json(HTTPStatus.BAD_REQUEST, {"error": "unsupported_tokenize_message"})
            return
        self._write_json(
            HTTPStatus.OK,
            {"count": len(token_ids), "max_model_len": 8192, "tokens": token_ids},
        )

    def _discard_request_body(self) -> None:
        try:
            self._read_request_body()
        except (OSError, ValueError):
            pass

    def _read_request_body(self) -> bytes:
        self.connection.settimeout(2.0)
        transfer_encoding = self.headers.get("Transfer-Encoding")
        content_length_header = self.headers.get("Content-Length")
        if transfer_encoding is not None:
            if transfer_encoding.lower().strip() != "chunked" or content_length_header is not None:
                raise ValueError("invalid transfer encoding")
            return self._read_chunked_body()
        try:
            content_length = int(content_length_header or "")
        except ValueError as error:
            raise ValueError("invalid content length") from error
        if not 0 < content_length <= _MAX_REQUEST_BYTES:
            raise ValueError("invalid content length")
        body = self.rfile.read(content_length)
        if len(body) != content_length:
            raise ValueError("truncated request body")
        return body

    def _read_chunked_body(self) -> bytes:
        body = bytearray()
        while True:
            size_line = self.rfile.readline(128)
            if not size_line.endswith(b"\r\n"):
                raise ValueError("invalid chunk size line")
            size_text = size_line[:-2].split(b";", maxsplit=1)[0]
            try:
                chunk_size = int(size_text, 16)
            except ValueError as error:
                raise ValueError("invalid chunk size") from error
            if chunk_size < 0 or len(body) + chunk_size > _MAX_REQUEST_BYTES:
                raise ValueError("chunked request exceeds limit")
            if chunk_size == 0:
                trailer_bytes = 0
                while True:
                    trailer = self.rfile.readline(8_192)
                    trailer_bytes += len(trailer)
                    if trailer_bytes > _MAX_REQUEST_BYTES:
                        raise ValueError("chunk trailers exceed limit")
                    if trailer == b"\r\n":
                        return bytes(body)
                    if not trailer or not trailer.endswith(b"\r\n"):
                        raise ValueError("invalid chunk trailer")
            chunk = self.rfile.read(chunk_size)
            if len(chunk) != chunk_size or self.rfile.read(2) != b"\r\n":
                raise ValueError("truncated chunked body")
            body.extend(chunk)

    def _stream(self, request_id: str, request: dict[str, Any]) -> None:
        config = self.server.config
        if self.server.chat_tokenizer is None:
            self._write_json(
                HTTPStatus.SERVICE_UNAVAILABLE, {"error": "pinned_chat_tokenizer_unavailable"}
            )
            self.server.observations.finish(request_id, "tokenizer_unavailable")
            return
        messages = request.get("messages", [])
        try:
            token_ids = self.server.chat_tokenizer(messages)
        except ValueError:
            self._write_json(HTTPStatus.BAD_REQUEST, {"error": "unsupported_tokenize_message"})
            self.server.observations.finish(request_id, "invalid_messages")
            return
        if config.failure_mode is FailureMode.HTTP_ERROR:
            self._write_json(
                config.http_error_status,
                {"error": {"code": "fake_backend_failure", "backend_id": config.backend_id}},
            )
            self.server.observations.finish(request_id, "http_error")
            return

        if config.failure_mode is FailureMode.INVALID_CONTENT_TYPE:
            payload = b'{"unexpected":"non-stream response"}'
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.send_header("X-Inference-Backend", config.backend_id)
            self.end_headers()
            self.wfile.write(payload)
            self.server.observations.event(request_id, "invalid_content_type")
            self.server.observations.finish(request_id, "invalid_content_type")
            return

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.send_header("X-Inference-Backend", config.backend_id)
        self.end_headers()

        if self._finish_wait(request_id, self._wait(config.first_item_delay_ms)):
            return
        if len(token_ids) >= 4096 and self._finish_wait(
            request_id, self._wait(config.long_prompt_delay_ms)
        ):
            return
        prompt_material = json.dumps(
            [request.get("model"), request.get("cache_salt")],
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        prompt_digest = hashlib.sha256(prompt_material.encode("utf-8")).hexdigest()
        self.server.observations.observe_prompt(
            request_id,
            prompt_digest,
            token_ids,
            config.kv_cache_capacity_blocks,
            config.kv_blocks_per_unique_prompt,
            config.runtime_shaped_metrics,
            config.kv_event_blocks_per_store,
        )
        if config.failure_mode is FailureMode.CLOSE_BEFORE_FIRST_ITEM:
            self.server.observations.finish(request_id, "closed_before_first_item")
            return
        if config.failure_mode is FailureMode.MALFORMED_FIRST_ITEM:
            self._write_raw_event(request_id, "malformed_first_item", b"data: {not-json}\n\n")
            self.server.observations.finish(request_id, "malformed_first_item")
            return
        if config.failure_mode is FailureMode.INVALID_FIRST_ITEM:
            self._write_event(
                request_id,
                "invalid_first_item",
                {"object": "not-a-chat-completion", "choices": []},
            )
            self.server.observations.finish(request_id, "invalid_first_item")
            return

        completion_id = f"chatcmpl_{request_id}"
        model = request["model"]
        created = int(time.time())
        self._write_event(
            request_id,
            "role",
            self._chunk(
                completion_id,
                created,
                model,
                {
                    "role": "assistant",
                    **({"content": ""} if config.stream_framing is StreamFraming.VLLM else {}),
                },
                None,
            ),
        )
        if self._apply_failure(request_id, 0):
            return

        finish_emitted = False
        chunks = (
            config.chunks[: request.get("max_tokens", len(config.chunks))]
            if config.runtime_shaped_metrics
            else config.chunks
        )
        for emitted, content in enumerate(chunks, start=1):
            if self._finish_wait(request_id, self._wait(config.chunk_delay_ms)):
                return
            finish_with_content = (
                config.stream_framing is StreamFraming.VLLM
                and emitted == len(config.chunks)
                and config.failure_mode is FailureMode.NONE
            )
            self._write_event(
                request_id,
                "content_finish" if finish_with_content else "content",
                self._chunk(
                    completion_id,
                    created,
                    model,
                    {"content": content},
                    "stop" if finish_with_content else None,
                ),
            )
            finish_emitted = finish_emitted or finish_with_content
            if self._apply_failure(request_id, emitted):
                return

        if not finish_emitted:
            self._write_event(
                request_id,
                "finish",
                self._chunk(completion_id, created, model, {}, "stop"),
            )
        stream_options = request.get("stream_options")
        include_usage = (
            isinstance(stream_options, dict) and stream_options.get("include_usage") is True
        )
        if config.emit_usage and include_usage:
            self._write_event(
                request_id,
                "usage",
                {
                    "id": completion_id,
                    "object": "chat.completion.chunk",
                    "created": created,
                    "model": model,
                    "choices": [],
                    "usage": {
                        "prompt_tokens": len(token_ids)
                        if config.runtime_shaped_metrics
                        else config.prompt_tokens,
                        "completion_tokens": len(chunks)
                        if config.runtime_shaped_metrics
                        else config.completion_tokens,
                        "total_tokens": len(token_ids) + len(chunks)
                        if config.runtime_shaped_metrics
                        else config.prompt_tokens + config.completion_tokens,
                    },
                },
            )
        self._write_raw_event(request_id, "done", b"data: [DONE]\n\n")
        self.server.observations.finish(request_id, "completed")

    @staticmethod
    def _chunk(
        completion_id: str,
        created: int,
        model: str,
        delta: dict[str, str],
        finish_reason: str | None,
    ) -> dict[str, Any]:
        return {
            "id": completion_id,
            "object": "chat.completion.chunk",
            "created": created,
            "model": model,
            "choices": [{"index": 0, "delta": delta, "finish_reason": finish_reason}],
        }

    def _apply_failure(self, request_id: str, emitted_chunks: int) -> bool:
        config = self.server.config
        if emitted_chunks != config.failure_after_chunks:
            return False
        if config.failure_mode is FailureMode.MALFORMED_AFTER_CHUNKS:
            self._write_raw_event(request_id, "malformed", b"data: {not-json}\n\n")
            self.server.observations.finish(request_id, "malformed_stream")
            return True
        if config.failure_mode is FailureMode.CLOSE_AFTER_CHUNKS:
            self.server.observations.finish(request_id, "truncated_stream")
            return True
        if config.failure_mode is FailureMode.STALL_AFTER_CHUNKS:
            result = self._wait(config.stall_timeout_ms)
            if result is _WaitResult.ELAPSED:
                self.server.observations.finish(request_id, "stall_timeout")
            else:
                self._finish_wait(request_id, result)
            return True
        return False

    def _wait(self, milliseconds: int) -> _WaitResult:
        deadline = time.perf_counter() + milliseconds / 1_000
        while True:
            if self.server.stop_event.is_set():
                return _WaitResult.SERVER_STOPPING
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                return _WaitResult.ELAPSED
            readable, _, _ = select.select([self.connection], [], [], min(remaining, 0.02))
            if not readable:
                continue
            try:
                pending = self.connection.recv(1, socket.MSG_PEEK)
            except (ConnectionResetError, ConnectionAbortedError, OSError):
                return _WaitResult.CLIENT_DISCONNECTED
            if not pending:
                return _WaitResult.CLIENT_DISCONNECTED
            time.sleep(min(remaining, 0.005))

    def _finish_wait(self, request_id: str, result: _WaitResult) -> bool:
        if result is _WaitResult.ELAPSED:
            return False
        if result is _WaitResult.SERVER_STOPPING:
            self.server.observations.finish(request_id, "server_shutdown")
        else:
            self.server.observations.finish(request_id, "client_cancelled", cancelled=True)
        return True

    def _write_event(self, request_id: str, kind: str, value: Mapping[str, Any]) -> None:
        payload = json.dumps(
            value, allow_nan=False, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        self._write_raw_event(request_id, kind, b"data: " + payload + b"\n\n")

    def _write_raw_event(self, request_id: str, kind: str, payload: bytes) -> None:
        self.wfile.write(payload)
        self.wfile.flush()
        self.server.observations.event(request_id, kind)

    def _write_json(self, status: int, value: Mapping[str, Any]) -> None:
        payload = json.dumps(value, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)


class FakeBackend:
    """Lifecycle wrapper for a fake backend running on an ephemeral loopback port."""

    def __init__(
        self,
        config: FakeBackendConfig,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
    ) -> None:
        if not isinstance(host, str) or not host:
            raise ValueError("host must be a non-empty string")
        if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65_535:
            raise ValueError("port must be an integer from 0 through 65535")
        self.config = config
        self._server = _FakeBackendHTTPServer(config, host, port)
        self._thread = threading.Thread(
            target=self._serve,
            name=f"fake-backend-{config.backend_id}",
        )
        self._started = False
        self._closed = False

    def _serve(self) -> None:
        self._server.serve_forever(poll_interval=0.02)

    @property
    def base_url(self) -> str:
        host, port = self._server.server_address
        return f"http://{host}:{port}"

    @property
    def port(self) -> int:
        return int(self._server.server_address[1])

    @property
    def running(self) -> bool:
        return self._thread.is_alive()

    def start(self) -> FakeBackend:
        if self._closed or self._started:
            raise RuntimeError("fake backend can only be started once")
        self._started = True
        self._thread.start()
        return self

    def wait_for_terminal(self, request_id: str, timeout: float = 2.0) -> RequestObservation:
        return self._server.observations.wait_for_terminal(request_id, timeout)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._server.stop_event.set()
        if self.running:
            self._server.shutdown()
        self._server.server_close()
        if self._started:
            self._thread.join(timeout=2.0)
        if self.running:
            raise RuntimeError("fake backend server thread did not stop")

    def __enter__(self) -> FakeBackend:
        return self.start()

    def __exit__(self, *exc_info: object) -> None:
        del exc_info
        self.close()


def load_backend_config(path: Path) -> FakeBackendConfig:
    """Read one strict JSON fake-backend configuration."""

    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_strict_object)
    except (OSError, ValueError, UnicodeDecodeError) as error:
        raise ValueError(f"cannot load fake backend config {path}: {error}") from error
    return FakeBackendConfig.from_dict(value)


def _write_ready_file(path: Path, backend: FakeBackend) -> None:
    temporary_path = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        temporary_path.write_text(
            json.dumps({"backend_id": backend.config.backend_id, "url": backend.base_url}) + "\n",
            encoding="utf-8",
        )
        temporary_path.replace(path)
    finally:
        temporary_path.unlink(missing_ok=True)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--ready-file", type=Path)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args(argv)
    backend = FakeBackend(load_backend_config(args.config), host=args.host, port=args.port).start()
    if args.ready_file is not None:
        _write_ready_file(args.ready_file, backend)
    print(
        json.dumps({"backend_id": backend.config.backend_id, "url": backend.base_url}),
        flush=True,
    )
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        return 0
    finally:
        backend.close()


if __name__ == "__main__":
    raise SystemExit(main())
