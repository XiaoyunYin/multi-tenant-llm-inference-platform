"""Pinned model staging, clock exchange and a rehearsal-only CPU backend."""

import argparse
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def stage(packet):
    from huggingface_hub import snapshot_download
    from transformers import AutoTokenizer

    from inf060_probe_spec import MODEL, REVISION, check, facts, load, save

    pins = load(packet / "model.json")
    root = Path("/model")
    snapshot_download(
        MODEL, revision=REVISION, local_dir=root, allow_patterns=list(pins["files"])
    )
    seen = {}
    for name, expected in pins["files"].items():
        actual = facts(root / name)
        check(all(actual[k] == expected[k] for k in ("bytes", "sha256")), "weight_pin")
        seen[name] = actual
    tokenizer = AutoTokenizer.from_pretrained(root, local_files_only=True)
    rows = load(packet / "requests.json")["slots"]
    prompts = []
    for row in rows:
        prefix = row["canary"] + " Continue counting slowly:"

        def encoded(n):
            text = prefix + (" one" * n)
            tokens = tokenizer.apply_chat_template(
                [{"role": "user", "content": text}],
                tokenize=True,
                add_generation_prompt=True,
                return_dict=False,
            )
            return text, len(tokens)

        count = 1024 - encoded(0)[1]
        for adjustment in (0, -1, 1, -2, 2, -3, 3, -4, 4):
            prompt, size = encoded(count + adjustment)
            if size == 1024:
                break
        else:
            raise ValueError("inf060:rendered_prompt_length")
        prompts.append(prompt)
    save(Path("/private/prompts.json"), prompts)
    save(
        Path("/private/model-readback.json"),
        {"revision": REVISION, "files": seen, "tokens": 1024},
    )


def line(stamp, text):
    print(f"{stamp:.6f} INFO [async_llm.py:698] {text}", flush=True)


def clock_server(source, output):
    output.write(b"ready\n")
    output.flush()
    for _ in range(10):
        if source.readline(3) != b"?\n":
            return 1
        instant = time.time_ns()
        output.write(f"[{instant},{instant}]\n".encode())
        output.flush()
    return 0


def mock(logged):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_):
            return

        def do_GET(self):
            body = (
                b"vllm:num_requests_running 0\nvllm:kv_cache_usage_perc 0\n"
                if self.path == "/metrics"
                else b"{}"
            )
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def emit(self, payload):
            if payload != b"[DONE]":
                payload = b'{"object":"chat.completion.chunk",' + payload[1:]
            content = b"data: " + payload + b"\n\n"
            self.wfile.write(f"{len(content):x}\r\n".encode() + content + b"\r\n")
            self.wfile.flush()

        def do_POST(self):
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            if payload.get("stream_options", {}).get("include_usage") is not True:
                self.send_error(400)
                return
            rid = self.headers.get("X-Request-ID")
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            try:
                for _ in range(8):
                    self.emit(
                        b'{"choices":[{"index":0,"delta":{"content":"one"},"finish_reason":null}]}'
                    )
                    time.sleep(0.055)
                self.emit(
                    b'{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}'
                )
                self.emit(
                    b'{"choices":[],"usage":{"prompt_tokens":1024,"completion_tokens":8,"total_tokens":1032}}'
                )
                self.emit(b"[DONE]")
                self.wfile.write(b"0\r\n\r\n")
            except OSError:
                self.close_connection = True
                if logged:
                    line(time.time(), f"Request chatcmpl-{rid} aborted.")

    with ThreadingHTTPServer(("127.0.0.1", 8000), Handler) as server:
        line(time.time(), "CPU rehearsal frontend ready.")
        if logged:
            line(time.time(), "Request chatcmpl-req_" + "e" * 32 + " aborted.")
            print(
                "INFO 11-19 13:35:18 [async_llm.py:698] Request chatcmpl-req_"
                + "f" * 32
                + " aborted.",
                flush=True,
            )
        server.serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "mode", choices=("stage", "clock-server", "mock-control", "mock-logged")
    )
    args = parser.parse_args()
    if args.mode == "stage":
        stage(Path("/packet"))
    elif args.mode == "clock-server":
        raise SystemExit(clock_server(sys.stdin.buffer, sys.stdout.buffer))
    else:
        mock(args.mode == "mock-logged")
