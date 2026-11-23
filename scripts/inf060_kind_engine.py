"""CPU HTTP/SSE engine for the INF-060 kind rehearsal only."""

import json
import os
import re
import select
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

LOCK = threading.Lock()
MODE = Path("/tmp/rehearsal-mode")
CANARY = "INF060CANARYa41ee490d5094cd7e846"
REQUEST_ID = re.compile(r"req_[0-9a-f]{32}")
running = sequence = 0


def log(message, file="server.py", line=1):
    print(f"{time.time():.6f} INFO [{file}:{line}] {message}", flush=True)


def event(*, content=None, finish=None, usage=None):
    packet = {"object": "chat.completion.chunk", "choices": []}
    if usage is None:
        packet["choices"] = [{"index": 0, "delta": {}, "finish_reason": finish}]
        if content is not None:
            packet["choices"][0]["delta"]["content"] = content
    else:
        packet["usage"] = {
            "prompt_tokens": 1024,
            "completion_tokens": usage,
            "total_tokens": 1024 + usage,
        }
    return b"data: " + json.dumps(packet).encode() + b"\n\n"


class Engine(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_GET(self):
        with LOCK:
            count = running
        if self.path == "/metrics":
            data = (
                f"vllm:num_requests_running {count}\n"
                "vllm:num_requests_waiting 0\n"
                f"vllm:kv_cache_usage_perc {min(count, 32) / 32}\n"
                f"process_cpu_seconds_total {time.process_time()}\n"
            ).encode()
        else:
            data = b"{}"
        self.send_response(
            200 if self.path in {"/metrics", "/health", "/v1/models"} else 404
        )
        self.send_header(
            "Content-Type",
            "text/plain" if self.path == "/metrics" else "application/json",
        )
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def chunk(self, data):
        self.wfile.write(f"{len(data):x}\r\n".encode() + data + b"\r\n")
        self.wfile.flush()

    def check_close(self, seconds):
        ready, _, _ = select.select([self.connection], [], [], seconds)
        if ready:
            # No further inbound bytes are expected while this stream is open.
            self.close_connection = True
            raise ConnectionResetError()

    def do_POST(self):
        global running, sequence
        key = self.headers.get("X-Request-ID", "")
        if self.path != "/v1/chat/completions" or not REQUEST_ID.fullmatch(key):
            self.send_error(400)
            return
        size = int(self.headers.get("Content-Length", "0"))
        if not 0 < size < 1024**2:
            self.send_error(400)
            return
        self.rfile.read(size)
        mode = MODE.read_text().strip() if MODE.is_file() else "normal"
        with LOCK:
            running += 1
            sequence += 1
            number = sequence
        try:
            if mode == "engine-crash" and number == 8:
                os._exit(71)
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            if mode == "canary":
                log(CANARY)
            if mode == "abort-faults" and number % 3 == 0:
                log(f"Request chatcmpl-req_{number:032x} aborted.", "async_llm.py", 698)
            count = 2 if number % 7 == 0 else 8
            self.chunk(event(content=" one"))
            if mode == "abort-faults" and number % 7 == 1:
                self.check_close(36)
            if mode == "deadline-close" and number % 4 == 1:
                self.check_close(4)
            index = 1
            while index < count:
                self.check_close(0.10)
                combined = index == 1 and count > 2 and number % 3 == 0
                self.chunk(event(content=" one") * (2 if combined else 1))
                index += 2 if combined else 1
            self.check_close(0.18)
            self.chunk(event(finish="stop") + event(usage=count) + b"data: [DONE]\n\n")
            self.chunk(b"")
        except OSError:
            self.close_connection = True
            if mode != "abort-faults" or number % 3 != 1:
                message = f"Request chatcmpl-{key} aborted."
                log(message, "async_llm.py", 698)
                if mode == "abort-faults" and number % 3 == 2:
                    log(message, "async_llm.py", 698)
        finally:
            with LOCK:
                running -= 1


if __name__ == "__main__":
    log("kind mock engine ready")
    ThreadingHTTPServer(("0.0.0.0", 8000), Engine).serve_forever()
