"""Bounded, credential-redacted subprocess diagnostics for private phase logs."""

import subprocess
import sys
from pathlib import Path

from .credential_redaction import redact_values

TAIL_BYTES = 8192


def stderr_tail(value, *, secrets=(), environment=None):
    text = redact_values(value, secrets=secrets, environment=environment)
    return text.encode("utf-8")[-TAIL_BYTES:].decode("utf-8", errors="ignore")


class DiagnosticProcessError(subprocess.CalledProcessError):
    def __str__(self):
        stdout = f" stdout tail: {self.output};" if self.output else ""
        return f"command_failed:{Path(str(self.cmd[0])).name}:exit={self.returncode};{stdout} stderr tail: {self.stderr}"


def checked_process(argv, *, secrets=(), **kwargs):
    """Keep CalledProcessError compatibility and retain safe failure diagnostics."""
    kwargs.pop("check", None)
    stderr = kwargs.pop("stderr", None)
    capture = kwargs.pop("capture_output", False)
    captured = capture or kwargs.get("stdout") == subprocess.PIPE or stderr == subprocess.PIPE
    if capture:
        kwargs["stdout"] = subprocess.PIPE
    docker = Path(str(argv[0])).name.lower().removesuffix(".exe") == "docker"
    inherit_stdout = docker and kwargs.get("stdout") is None
    if inherit_stdout:
        kwargs["stdout"] = subprocess.PIPE
    result = subprocess.run(argv, stderr=subprocess.PIPE, check=False, **kwargs)
    tail = stderr_tail(result.stderr, secrets=secrets, environment=kwargs.get("env"))
    if result.returncode:
        output = (
            stderr_tail(result.stdout, secrets=secrets, environment=kwargs.get("env"))
            if docker
            else None
        )
        message = DiagnosticProcessError(result.returncode, list(argv), output=output, stderr=tail)
        print(str(message), file=sys.stderr, flush=True)
        raise message
    if not captured and tail:
        print(tail, file=sys.stderr, flush=True)
    if inherit_stdout and result.stdout:
        print(
            redact_values(result.stdout, secrets=secrets, environment=kwargs.get("env")),
            end="",
            flush=True,
        )
    return result
