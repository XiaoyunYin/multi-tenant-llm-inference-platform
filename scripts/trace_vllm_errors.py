"""Execute CPU-only admission/error projection directly from the verified pinned wheel."""

import argparse
import ast
import hashlib
import json
import logging
import sys
import types
import zipfile
from http import HTTPStatus
from pathlib import Path
from types import SimpleNamespace

WHEEL_SHA = "09d48617fc2be9c6cdcd5db480651ab0d84817b257204f2cc2e3ecbb70bbb635"


def trace(wheel):
    digest = hashlib.sha256()
    with wheel.open("rb") as stream:
        while data := stream.read(1024 * 1024):
            digest.update(data)
    if digest.hexdigest() != WHEEL_SHA:
        raise ValueError("not the verified vLLM 0.29.0 x86_64 wheel")
    files = {}
    with zipfile.ZipFile(wheel) as archive:

        def source(path):
            data = archive.read(path)
            files[path] = {
                "sha256": hashlib.sha256(data).hexdigest(),
                "bytes": len(data),
            }
            return data.decode()

        exceptions = types.ModuleType("vllm.exceptions")
        exec(
            compile(source("vllm/exceptions.py"), "vllm/exceptions.py", "exec"),
            exceptions.__dict__,
        )
        tree = ast.parse(source("vllm/v1/engine/async_llm.py"))
        admission = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == "check_admission"
        )
        namespace = {**exceptions.__dict__, "logger": logging.getLogger("wheel-trace")}
        exec(
            compile(
                ast.Module(body=[admission], type_ignores=[]),
                "pinned-admission",
                "exec",
            ),
            namespace,
        )
        admitted = []
        for count, n in ((31, 1), (32, 1), (30, 2), (31, 2)):
            host = SimpleNamespace(
                scheduler_config=SimpleNamespace(
                    max_num_queued_reqs=32, max_num_queued_tokens=None
                ),
                get_num_unfinished_requests=lambda count=count: count,
            )
            try:
                namespace["check_admission"](host, n)
                result = "admitted"
            except exceptions.QueueOverflowError:
                result = "QueueOverflowError"
            admitted.append({"unfinished": count, "n": n, "result": result})
        expected = ["admitted", "QueueOverflowError", "admitted", "QueueOverflowError"]
        if [row["result"] for row in admitted] != expected:
            raise ValueError("pinned admission contract changed")
        tree = ast.parse(
            source("vllm/entrypoints/serve/exception_handling/error_response.py")
        )
        create = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "create_error_response"
        )

        class Info:
            def __init__(self, **kwargs):
                self.value = kwargs

        class Response:
            def __init__(self, error):
                self.error = error

        namespace = {
            **exceptions.__dict__,
            "HTTPStatus": HTTPStatus,
            "ErrorResponse": Response,
            "ErrorInfo": Info,
            "sanitize_message": lambda value: value,
            "logger": logging.getLogger("wheel-trace"),
        }
        previous = sys.modules.get("vllm.exceptions")
        sys.modules["vllm.exceptions"] = exceptions
        try:
            exec(
                compile(
                    ast.Module(body=[create], type_ignores=[]),
                    "pinned-error-response",
                    "exec",
                ),
                namespace,
            )
            result = namespace["create_error_response"](
                exceptions.QueueOverflowError()
            ).error.value
        finally:
            if previous is None:
                sys.modules.pop("vllm.exceptions", None)
            else:
                sys.modules["vllm.exceptions"] = previous
        if (
            result["code"] != 503
            or result["type"] != "Service Unavailable"
            or result["param"] is not None
        ):
            raise ValueError("pinned native projection changed")
        result["message"] = (
            "Engine busy; retry later."  # Synthetic message, preserve the source-derived wire schema.
        )
        for path in (
            "vllm/entrypoints/generate/base/serving.py",
            "vllm/entrypoints/openai/chat_completion/serving.py",
            "vllm/entrypoints/openai/chat_completion/api_router.py",
            "vllm/entrypoints/serve/exception_handling/decorators.py",
            "vllm/entrypoints/serve/exception_handling/register.py",
            "vllm/entrypoints/serve/exception_handling/handlers/vllm_error.py",
            "vllm/entrypoints/serve/exception_handling/handlers/exception.py",
        ):
            if path in archive.namelist():
                source(path)
        routers = {
            path: source(path)
            for path in archive.namelist()
            if path.endswith(".py")
            and "chat_completion" in path
            and "StreamingResponse" in archive.read(path).decode(errors="replace")
        }
        if not routers:
            raise ValueError("chat StreamingResponse router not found")
    return {
        "schema": "inf011-vllm-error-source-trace.v1",
        "version": "0.29.0",
        "wheel_sha256": WHEEL_SHA,
        "wheel_url": "https://pypi.org/project/vllm/0.29.0/#files",
        "source_files": files,
        "admission_cpu_execution": admitted,
        "native_error_fixture": {"error": result},
        "wire_shapes": [
            "HTTP 503 JSON before stream creation",
            "HTTP 200 SSE error and DONE; may precede first valid chunk or follow content",
        ],
        "source_execution_basis": "Actual wheel exception classes, admission method and error projection; model/engine not loaded; no GPU/AWS",
        "message_basis": "Synthetic replacement; no upstream error message retained",
        "routers": list(routers),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(trace(args.wheel), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
