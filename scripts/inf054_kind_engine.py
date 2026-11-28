"""SSE fixture for INF-054. Sixteen service slots feed the waiting gauge."""

import json
import os
import signal
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

seats = threading.BoundedSemaphore(16)
lock = threading.Lock()
running = waiting = 0
health_ready_at = time.monotonic() + int(
    os.environ.get("INF054_MOCK_HEALTH_DELAY_S", "0")
)
dcgm_exit_scheduled = False
GPU_LIKE_TPOT_S = 0.11707871434920514


class Engine(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def reply(self, status, body, content_type="application/json"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        global dcgm_exit_scheduled
        if os.environ.get("INF054_MOCK_DCGM") == "1":
            if self.path == "/metrics":
                self.reply(
                    200,
                    b"DCGM_FI_DEV_GPU_UTIL 0\nDCGM_FI_DEV_FB_USED 2\n",
                    "text/plain; version=0.0.4",
                )
                if os.environ.get("INF054_MOCK_DCGM_CRASH") == "1":
                    with lock:
                        if not dcgm_exit_scheduled:
                            dcgm_exit_scheduled = True
                            threading.Timer(2, os._exit, args=(1,)).start()
                return
            return self.reply(200 if self.path == "/health" else 503, b"")
        if self.path == "/health" and time.monotonic() < health_ready_at:
            return self.reply(503, b"{}")
        if self.path == "/metrics":
            if Path("/tmp/missing-scrape").exists():
                return self.reply(503, b"")
            with lock:
                body = (
                    f"vllm:num_requests_running {running}\n"
                    f"vllm:num_requests_waiting {waiting}\n"
                    "vllm:kv_cache_usage_perc 0\n"
                )
            return self.reply(200, body.encode(), "text/plain; version=0.0.4")
        return self.reply(200 if self.path in ("/health", "/v1/models") else 404, b"{}")

    def event(self, choices, **fields):
        packet = {"object": "chat.completion.chunk", "choices": choices, **fields}
        self.wfile.write(b"data: " + json.dumps(packet).encode() + b"\n\n")
        self.wfile.flush()

    def do_POST(self):
        global waiting, running
        size = int(self.headers.get("Content-Length", "0"))
        if self.path != "/v1/chat/completions" or not 0 < size < 65536:
            return self.reply(400, b"")
        body = json.loads(self.rfile.read(size))
        live = body["messages"][0]["content"].startswith("scale-down live stream")
        if not seats.acquire(blocking=False):
            with lock:
                waiting += 1
            acquired = seats.acquire(timeout=15)
            with lock:
                waiting -= 1
            if not acquired:
                return self.reply(503, b"")
        with lock:
            running += 1
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            loops, delay = (60, 1) if live else (6, 0.7)
            if live and os.environ.get("INF054_MOCK_LONG_STREAM") == "1":
                loops, delay = body["max_tokens"], GPU_LIKE_TPOT_S
            if not live and os.environ.get("INF054_CPU_WORKLOAD") == "1":
                loops, delay = min(64, body.get("max_tokens", 64)), 0.125
            for index in range(loops):
                if index:
                    time.sleep(delay)
                self.event(
                    [{"index": 0, "delta": {"content": " one"}, "finish_reason": None}]
                )
            if not live or os.environ.get("INF054_MOCK_LONG_STREAM") != "1":
                time.sleep(delay)
            self.event([{"index": 0, "delta": {}, "finish_reason": "stop"}])
            self.event(
                [],
                usage={
                    "prompt_tokens": 1024,
                    "completion_tokens": loops,
                    "total_tokens": 1024 + loops,
                },
            )
            self.wfile.write(b"data: [DONE]\n\n")
        except OSError:
            pass
        finally:
            with lock:
                running -= 1
            seats.release()


class DrainingEngineServer(ThreadingHTTPServer):
    daemon_threads = False


if __name__ == "__main__":
    with DrainingEngineServer(
        ("0.0.0.0", int(os.environ.get("PORT", "8000"))), Engine
    ) as server:

        def drain(*_):
            threading.Thread(target=server.shutdown, daemon=True).start()

        signal.signal(signal.SIGTERM, drain)
        server.serve_forever()
