"""Bounded SSM startup/bootstrap and reconnecting operator control transport."""

import json
import subprocess
import time
import urllib.request
from pathlib import Path

from .session_stop import stop_child
from .stage_c_readiness import wait_startup

OUTAGE_SECONDS = 300


class ControlLost(RuntimeError):
    pass


def wait_ssm_online(aws, instance, epoch, minima, margin, **timing):
    def probe(timeout):
        result = aws(
            "ssm",
            "describe-instance-information",
            "--filters",
            json.dumps([{"Key": "InstanceIds", "Values": [instance]}]),
            timeout=timeout,
        )
        rows = result["InstanceInformationList"]
        ping = next(
            (row.get("PingStatus") for row in rows if row["InstanceId"] == instance), "Unregistered"
        )
        return {"ready": ping == "Online", "PingStatus": ping}

    return wait_startup(epoch, minima, margin, probe, **timing)


def command_batches(commands, max_bytes=24000):
    """Bound the serialized SendCommand parameters, including JSON escaping."""
    batches, batch = [], []
    for command in commands:
        if (
            len(json.dumps({"commands": ["set -eu\n" + "\n".join(batch + [command])]}).encode())
            > max_bytes
        ):
            if not batch:
                raise ValueError("one bootstrap command exceeds SSM batch bound")
            batches.append(batch)
            batch = []
        batch.append(command)
    if batch:
        batches.append(batch)
    if any(
        len(json.dumps({"commands": ["set -eu\n" + "\n".join(b)]}).encode()) > max_bytes
        for b in batches
    ):
        raise ValueError("one bootstrap command exceeds SSM batch bound")
    return batches


def ssm_commands(aws, instance, commands, deadline, session: Path, attempts: list):
    """Sequential commands; never let AWS calls or invocation polls outlive readiness."""
    request = session / "ssm-stage-request.json"
    try:
        remaining = deadline - time.perf_counter()
        if remaining <= 0:
            raise ControlLost("skipped_readiness_deadline")
        request.write_text(
            json.dumps({"commands": ["set -eu\n" + "\n".join(commands)]}),
            encoding="utf-8",
            newline="\n",
        )
        command = aws(
            "ssm",
            "send-command",
            "--instance-ids",
            instance,
            "--document-name",
            "AWS-RunShellScript",
            "--parameters",
            "file://" + str(request.resolve()),
            timeout=min(30, remaining),
        )["Command"]["CommandId"]
        limit = min(deadline, time.perf_counter() + 120)
        while time.perf_counter() < limit:
            try:
                result = aws(
                    "ssm",
                    "get-command-invocation",
                    "--command-id",
                    command,
                    "--instance-id",
                    instance,
                    timeout=min(10, limit - time.perf_counter()),
                )
            except (OSError, subprocess.SubprocessError) as error:
                result = {"Status": "Pending", "error": str(error)}
            attempts.append(
                {
                    "unix_s": time.time(),
                    "command_id": command,
                    "Status": result["Status"],
                    "error": result.get("error"),
                }
            )
            if result["Status"] == "Success":
                return result
            if result["Status"] not in ("Pending", "InProgress", "Delayed"):
                raise RuntimeError("reviewed SSM command failed: " + str(result))
            time.sleep(max(0, min(2, limit - time.perf_counter())))
        raise ControlLost(
            "skipped_readiness_deadline"
            if time.perf_counter() >= deadline
            else "SSM bootstrap invocation timed out"
        )
    finally:
        request.unlink(missing_ok=True)  # Bootstrap contains the private transport nonce.


class ReconnectingTransport:
    def __init__(
        self,
        start_forward,
        base,
        nonce,
        deadline,
        interruptions,
        *,
        clock=time.perf_counter,
        wall_clock=time.time,
        sleep=time.sleep,
        request=None,
        stop=stop_child,
        outage_seconds=OUTAGE_SECONDS,
    ):
        self.start_forward, self.base, self.nonce = start_forward, base, nonce
        self.deadline, self.interruptions = deadline, interruptions
        self.clock, self.wall_clock, self.sleep = clock, wall_clock, sleep
        self.request = request or self.http_request
        self.stop, self.outage_seconds = stop, outage_seconds
        self.forward = None
        self.forward_started = None
        self.forward_ready = False
        self.outage_start = None
        self.backoff = 1.0

    def http_request(self, path, timeout, data=None):
        request = urllib.request.Request(
            self.base + path,
            data=data,
            headers={"Authorization": self.nonce},
            method="PUT" if data is not None else "GET",
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read()

    def close(self):
        if self.forward:
            try:
                return self.stop(self.forward)
            except (OSError, subprocess.SubprocessError) as error:
                self.interruptions.append(
                    {"unix_s": self.wall_clock(), "error": f"forward stop: {error}"}
                )
                return {"error": str(error)}
            finally:
                self.forward = None

    def retry(self, error, *, restart=True):
        now = self.clock()
        if self.outage_start is None:
            self.outage_start = now
        self.interruptions.append(
            {
                "unix_s": self.wall_clock(),
                "perf_counter_s": now,
                "error": str(error),
                "outage_seconds": now - self.outage_start,
                "restart_forward": restart,
            }
        )
        if restart:
            self.close()
        now = self.clock()
        limit = min(self.deadline, self.outage_start + self.outage_seconds)
        if now >= limit:
            raise ControlLost(
                "control_deadline" if now >= self.deadline else "sustained_transport_outage"
            )
        self.sleep(min(self.backoff, limit - now))
        self.backoff = min(15, self.backoff * 2)

    def get(self, path):
        while True:
            now = self.clock()
            limit = min(
                self.deadline,
                (self.outage_start + self.outage_seconds)
                if self.outage_start is not None
                else self.deadline,
            )
            if now >= limit:
                raise ControlLost(
                    "control_deadline" if now >= self.deadline else "sustained_transport_outage"
                )
            try:
                if self.forward is None:
                    self.forward = self.start_forward()
                    self.forward_started = self.clock()
                    self.forward_ready = False
                if self.forward.poll() is not None:
                    raise OSError(f"SSM forward exited ({self.forward.returncode})")
                remaining = limit - self.clock()
                if remaining <= 0:
                    raise ControlLost(
                        "control_deadline"
                        if self.clock() >= self.deadline
                        else "sustained_transport_outage"
                    )
                value = self.request(path, min(30, remaining))
                # Malformed status/receipt is also an interruption, not proof of completion.
                if path in ("/status", "/receipt"):
                    json.loads(value)
                self.forward_ready = True
                self.outage_start, self.backoff = None, 1.0
                return value
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                # The CLI/plugin starts asynchronously. Do not kill a live new
                # forward on connection refusal before it can bind its listener.
                restart = (
                    self.forward is None
                    or self.forward.poll() is not None
                    or self.forward_ready
                    or self.clock() - self.forward_started >= 30
                )
                self.retry(error, restart=restart)

    def put_payload(self, data):
        while not json.loads(self.get("/status"))["started"]:
            try:
                self.request("/payload", min(60, self.deadline - self.clock()), data)
            except (OSError, subprocess.SubprocessError) as error:
                # A lost PUT response may still have launched the controller. Query
                # started through a fresh forward before attempting another upload.
                self.retry(error)


def fetch_export(transport, session, outcome):
    import hashlib

    receipt = json.loads(transport.get("/receipt"))
    data = transport.get("/export")
    if hashlib.sha256(data).hexdigest() != receipt["sha256"]:
        raise ValueError("export transfer checksum mismatch")
    (session / "evidence.tar.gz").write_bytes(data)
    (session / "export-receipt.json").write_text(
        json.dumps(receipt, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    outcome["export_verified"] = True


def monitor_and_export(transport, session, outcome):
    while True:
        status = json.loads(transport.get("/status"))
        if status["finished"]:
            fetch_export(transport, session, outcome)
            return
        transport.sleep(max(0, min(5, transport.deadline - transport.clock())))


def recover_export(transport, session, outcome, termination_deadline):
    """One fresh-forward recovery window before teardown, retaining cleanup time."""
    transport.close()
    transport.deadline = min(termination_deadline - 240, transport.clock() + 60)
    transport.outage_start, transport.backoff = None, 1.0
    outcome["export_recovery_attempted"] = True
    try:
        if json.loads(transport.get("/status"))["finished"]:
            fetch_export(transport, session, outcome)
        else:
            outcome["export_recovery_error"] = "host controller still running; export unavailable"
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        outcome["export_recovery_error"] = str(error)
