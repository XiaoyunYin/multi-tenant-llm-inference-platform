"""Bound allocations before diagnostic/RBAC bytes reach the owner retainer."""

import json
import subprocess
import threading

from .inf037b_archive import IntegrityError


def bounded_json(value, *, limit, loss):
    """Canonical JSON with a bounded output and small escaped-string chunks.

    The limit comes from the owner budget (and the transport's existing body
    ceiling), not an estimate of a deployed source's required capacity.
    """
    result = bytearray()

    def overflow():
        loss("fitness:rbac_request_size")
        raise IntegrityError("fitness:rbac_request_size")

    def emit(data):
        if len(result) + len(data) > limit:
            overflow()
        result.extend(data)

    def walk(item, depth=0):
        if depth > 64:
            overflow()
        if isinstance(item, str):
            if len(item) > limit:
                overflow()
            emit(b'"')
            for i in range(0, len(item), 1024):
                emit(json.dumps(item[i : i + 1024], ensure_ascii=True)[1:-1].encode())
            emit(b'"')
        elif type(item) is dict:
            if len(item) > limit or any(type(k) is not str for k in item):
                overflow()
            emit(b"{")
            for i, key in enumerate(sorted(item)):
                if i:
                    emit(b",")
                walk(key, depth + 1)
                emit(b":")
                walk(item[key], depth + 1)
            emit(b"}")
        elif type(item) in (list, tuple):
            if len(item) > limit:
                overflow()
            emit(b"[")
            for i, part in enumerate(item):
                if i:
                    emit(b",")
                walk(part, depth + 1)
            emit(b"]")
        else:
            emit(json.dumps(item, allow_nan=False, separators=(",", ":")).encode())

    walk(value)
    emit(b"\n")
    return bytes(result)


def diagnostic_process(argv, *, input, timeout, capture, source, clock):
    """Stream both pipes into the existing owner; bound each joined result.

    16,384 is the existing diagnostic receipt acceptance ceiling. Successful
    output keeps the existing intent/terminal wire format. Overflow retains a
    bounded partial/error record through the owner, never a truncated receipt.
    ProcessCalls retains responsibility for the process group.
    """
    proc = subprocess.Popen(
        argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    buffers, failures = {"stdout": bytearray(), "stderr": bytearray()}, []

    def read(name):
        try:
            stream = getattr(proc, name)
            while True:
                start = clock()
                chunk = stream.read1(4096)
                end = clock()
                if not chunk:
                    break
                if len(buffers[name]) + len(chunk) > 16384:
                    try:
                        capture.retain(
                            source,
                            start,
                            end,
                            bytes(buffers[name]) + chunk,
                            {
                                "event": "diagnostic_partial",
                                "pipe": name,
                                "error": "fitness:diagnostic_output_size",
                            },
                        )
                    finally:
                        raise IntegrityError("fitness:diagnostic_output_size")
                buffers[name].extend(chunk)
        except Exception as exc:
            failures.append(exc)
            try:
                proc.kill()
            finally:
                capture.loss(source + ":" + str(exc))

    threads = [threading.Thread(target=read, args=(name,)) for name in buffers]
    for thread in threads:
        thread.start()
    try:
        proc.stdin.write(input)
        proc.stdin.close()
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        proc.kill()
        proc.wait()
        for thread in threads:
            thread.join()
        exc.stdout, exc.stderr = bytes(buffers["stdout"]), bytes(buffers["stderr"])
        capture.loss(source + ":diagnostic_timeout")
        raise
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        for thread in threads:
            thread.join()
        for name in ("stdin", "stdout", "stderr"):
            getattr(proc, name).close()
    if failures:
        raise failures[0]
    return subprocess.CompletedProcess(
        argv, proc.returncode, bytes(buffers["stdout"]), bytes(buffers["stderr"])
    )
