"""Minimal CPU engine and DCGM endpoint for the native launch rehearsal."""

import argparse
import json
import threading
import time
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

STARTUP = {
    "bf16": "",
    "fp8": "Selected CutlassFP8ScaledMMLinearKernel for Fp8PerTensorOnlineLinearMethod",
    "awq": "Using MarlinLinearKernel for AutoAWQMarlinLinearMethod",
}


class FixtureServer(ThreadingHTTPServer):
    # The 64-concurrency cell can connect all its lanes at once, alongside
    # Prometheus and the sampler. Keep the socket backlog above that burst.
    request_queue_size = 256

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.observations = OrderedDict()
        self.observation_lock = threading.Lock()

    def record(self, identity, observation):
        if not identity or len(identity) > 128:
            return
        with self.observation_lock:
            self.observations[identity] = observation
            if len(self.observations) > 128:
                self.observations.popitem(last=False)

    def readback(self, identity):
        with self.observation_lock:
            return self.observations.pop(identity, None)


class Engine(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def response(self, body, content_type, status=200):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        url = urlsplit(self.path)
        if url.path == "/fixture-request":
            identity = parse_qs(url.query).get("id", [""])[0]
            observation = self.server.readback(identity)
            if observation is None:
                return self.response(b"", "text/plain", 404)
            return self.response(json.dumps(observation).encode(), "application/json")
        if self.path in ("/health", "/v1/models"):
            self.response(b"{}", "application/json")
        elif self.path == "/metrics":
            self.response(self.server.metrics, "text/plain; version=0.0.4")
        else:
            self.response(b"", "text/plain", 404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        if self.path != "/v1/chat/completions" or not 0 < length <= 65536:
            return self.response(b"", "text/plain", 400)
        request = json.loads(self.rfile.read(length))
        cap = request["max_tokens"]
        ignore = request.get("ignore_eos") is True
        usage = request.get("stream_options", {}).get("include_usage") is True
        tokens = cap if ignore else min(cap, 2)
        self.server.record(
            self.headers.get("X-Request-ID"),
            {
                "fields": sorted(request),
                "ignore_eos": request.get("ignore_eos"),
                "include_usage": usage,
            },
        )
        frames = [
            {
                "choices": [
                    {
                        "index": 0,
                        "delta": {
                            "content": " one" * tokens if ignore else "Work\nFINAL: 2"
                        },
                        "finish_reason": None,
                    }
                ]
            },
            {
                "choices": [
                    {
                        "index": 0,
                        "delta": {},
                        "finish_reason": "length" if tokens == cap else "stop",
                    }
                ]
            },
        ]
        if usage:
            frames.append(
                {
                    "choices": [],
                    "usage": {
                        "prompt_tokens": 1024,
                        "completion_tokens": tokens,
                        "total_tokens": 1024 + tokens,
                    },
                }
            )
        # Keep the fixture's closed-loop cells observable by the sampler.
        time.sleep(0.075)
        body = b"".join(
            b"data: "
            + json.dumps({"object": "chat.completion.chunk", **frame}).encode()
            + b"\n\n"
            for frame in frames
        )
        self.response(body + b"data: [DONE]\n\n", "text/event-stream")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("component", choices=(*STARTUP, "dcgm"))
    component = parser.parse_args().component
    if component == "dcgm":
        port, metrics = 9400, b"DCGM_FI_DEV_FB_USED 512\n"
    else:
        port, metrics = (
            8000,
            (
                b"vllm:num_requests_running 1\n"
                b"vllm:num_requests_waiting 0\n"
                b"vllm:kv_cache_usage_perc 0.125\n"
                b"vllm:num_preemptions_total 0\n"
            ),
        )
        print(
            "Initializing a V1 LLM engine (v0.29.0) with config: "
            "dtype=torch.bfloat16, kv_cache_dtype=auto",
            "Model loading took 5.41 GiB memory and 0.1 seconds",
            "GPU KV cache size: 120,448 tokens,",
            STARTUP[component],
            sep="\n",
            flush=True,
        )
    with FixtureServer(("127.0.0.1", port), Engine) as server:
        server.metrics = metrics
        server.serve_forever()


if __name__ == "__main__":
    main()
