"""Explicit CPU replacement for GPU staging/serving; never native GPU evidence.

Real processes own API, input, core/scheduler roles. The committed NativeEmitter
owns SQLite, identities, lineage, abort cause/ack and terminal confirmations.
The fake asserts no vLLM installer, scheduler, KV-free or model fitness.
"""

import argparse
import json
import multiprocessing as mp
import os
import select
import signal
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from inference_platform.inf037b_native import NativeEmitter, TARGETS
from inference_platform.l4_compat import PINS

ROOT = Path("/evidence/runtime/native")
MANIFEST = Path("/packet/overlay/native-manifest.json")


def emitter(origin, roles):
    result = NativeEmitter(ROOT, origin)
    manifest = json.loads(MANIFEST.read_bytes())
    for role in roles:
        result.observe("installed", role, manifest["files"][TARGETS[role][0]])
    return result


def worker(origin, roles, incoming, outgoing):
    source = emitter(origin, roles)
    outgoing.put("ready")
    while True:
        method, args = incoming.get()
        if method == "stop":
            source.close()
            return
        if method == "abort":
            source.abort_context.active = {args[0]}
            source.observe("terminal", args[0], "FINISHED_ABORTED")
            source.abort_context.active = set()
        else:
            source.observe(method, *args)
        if source.failed:
            raise RuntimeError("fake_native_emitter_failed")
        outgoing.put("ok")


def frame(delta, finish=None):
    return (
        "data: "
        + json.dumps(
            {
                "id": "fake",
                "object": "chat.completion.chunk",
                "model": PINS["model"],
                "choices": [{"index": 0, "delta": delta, "finish_reason": finish}],
            }
        )
        + "\n\n"
    ).encode()


def validate_engine_argv(argv):
    # Options and the one optional positional are taken from the archived
    # vLLM 0.29 api_server usage. Unknown options and extra positionals fail.
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("model_tag", nargs="?")
    for option in (
        "--model",
        "--served-model-name",
        "--dtype",
        "--max-model-len",
        "--gpu-memory-utilization",
        "--host",
        "--port",
        "--revision",
        "--shutdown-timeout",
    ):
        parser.add_argument(option)
    parsed = parser.parse_args(argv)
    # The fake accepts precisely the reviewed launch; this strict subset cannot
    # admit an invalid option value that the real parser would reject.
    expected = [
        "--model",
        "/model",
        "--served-model-name",
        PINS["model"],
        "--dtype",
        "bfloat16",
        "--max-model-len",
        "8192",
        "--gpu-memory-utilization",
        "0.90",
        "--host",
        "127.0.0.1",
        "--port",
        "8000",
    ]
    if argv != expected:
        parser.error("argv differs from the reviewed launch")
    return parsed


def serve():
    from l4_compat_container import engine_argv

    validate_engine_argv(engine_argv())
    origin = {
        "supervisor_pid": os.getpid(),
        "supervisor_start": Path(f"/proc/{os.getpid()}/stat")
        .read_text()
        .rsplit(")", 1)[1]
        .split()[19],
        "basis": "CPU fake engine; not native GPU installation",
    }
    source = emitter(origin, ["api"])
    context = mp.get_context("spawn")
    processes, channels = [], {}
    for role, roles in (("input", ["input"]), ("core", ["core", "scheduler"])):
        incoming, outgoing = context.Queue(), context.Queue()
        process = context.Process(
            target=worker, args=(origin, roles, incoming, outgoing)
        )
        process.start()
        assert outgoing.get(timeout=10) == "ready"
        processes.append(process)
        channels[role] = incoming, outgoing, threading.Lock()

    def call(role, method, *args):
        incoming, outgoing, lock = channels[role]
        with lock:
            incoming.put((method, args))
            assert outgoing.get(timeout=5) == "ok"

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            body = (
                b"ok"
                if self.path == "/health"
                else (
                    b'vllm:num_requests_running{model_name="fake"} 0\n'
                    b'vllm:num_requests_waiting{model_name="fake"} 0\n'
                )
            )
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            count = payload["max_tokens"]
            assert self.path == "/v1/chat/completions" and count in (1, 64)
            assert payload["ignore_eos"] is True
            internal = "fake-" + self.headers["X-Request-ID"]
            call(
                "input",
                "identity",
                internal,
                "chatcmpl-" + self.headers["X-Request-ID"],
            )
            call("core", "accept", internal)
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()

            def send(data):
                self.wfile.write(f"{len(data):x}\r\n".encode() + data + b"\r\n")
                self.wfile.flush()

            def disconnected():
                readable, _, _ = select.select([self.connection], [], [], 0)
                return bool(readable) and not self.connection.recv(1, 2)  # MSG_PEEK

            terminal = False
            try:
                send(frame({"role": "assistant", "content": ""}))
                usage = (
                    "data: "
                    + json.dumps(
                        {
                            "id": "fake",
                            "object": "chat.completion.chunk",
                            "model": PINS["model"],
                            "choices": [],
                            "usage": {
                                "prompt_tokens": 1,
                                "completion_tokens": count,
                                "total_tokens": count + 1,
                            },
                        }
                    )
                    + "\n\n"
                ).encode()
                if count == 1:
                    # Distinct vLLM SSE records produced in one decode iteration.
                    call("core", "terminal", internal, "FINISHED_LENGTH_CAPPED")
                    terminal = True
                    send(
                        frame({"content": "x"})
                        + frame({}, "length")
                        + usage
                        + b"data: [DONE]\n\n"
                    )
                else:
                    for _ in range(count):
                        if disconnected():
                            raise ConnectionResetError("client disconnected")
                        send(frame({"content": "x"}))
                        time.sleep(0.03)
                    call("core", "terminal", internal, "FINISHED_LENGTH_CAPPED")
                    terminal = True
                    send(frame({}, "length"))
                    send(usage)
                    send(b"data: [DONE]\n\n")
                self.wfile.write(b"0\r\n\r\n")
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                if not terminal:
                    source.observe("abort_intent", internal, "CancelledError")
                    call("core", "abort", internal)
                    source.observe("abort_ack", internal)
            self.close_connection = True

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 8000), Handler)
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(SystemExit(0)))
    try:
        server.serve_forever()
    finally:
        for incoming, _, _ in channels.values():
            incoming.put(("stop", ()))
        for process in processes:
            process.join(timeout=5)
        source.close()


if __name__ == "__main__":
    if sys.argv[1] == "stage":
        Path("/evidence/model-manifest.json").write_text(
            json.dumps(
                {"basis": "REHEARSAL: no weights downloaded or verified", "files": {}}
            )
        )
    elif sys.argv[1] == "serve":
        serve()
    else:
        raise ValueError("fake_engine_mode")
