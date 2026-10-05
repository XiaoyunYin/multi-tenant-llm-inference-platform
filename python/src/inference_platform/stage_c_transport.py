"""Bounded SSM startup/bootstrap and reconnecting operator control transport."""

import base64
import hashlib
import http.client
import json
import shlex
import subprocess
import time
import urllib.request
from pathlib import Path

from .session_stop import stop_child
from .stage_c_digest import FINAL_LIMIT, FORWARD_WORST_BYTES_PER_SECOND
from .stage_c_readiness import wait_startup

CLEANUP_SECONDS = 600
FORWARD_STARTUP_SECONDS = 30


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
        command_channel=None,
        live_deadline=None,
    ):
        self.start_forward, self.base, self.nonce = start_forward, base, nonce
        self.deadline, self.interruptions = deadline, interruptions
        self.clock, self.wall_clock, self.sleep = clock, wall_clock, sleep
        self.request = request or self.http_request
        self.stop, self.command_channel = stop, command_channel
        self.live_deadline = live_deadline if live_deadline is not None else deadline
        self.forward = None
        self.forward_started = None
        self.forward_ready = False
        self.forwards_started = 0
        self.outage_start = None
        self.backoff = 1.0
        self.last_channel = None

    def http_request(self, path, timeout, data=None, *, headers=None):
        from .time_budget import deadline_urlopen

        request = urllib.request.Request(
            self.base + path,
            data=data,
            headers={"Authorization": self.nonce, **(headers or {})},
            method="PUT" if data is not None else "GET",
        )
        # Socket inactivity timeouts reset on each trickle. Bound the whole
        # attempt, including continuous bytes, so a large run cannot pin polling.
        deadline = time.perf_counter() + min(timeout, max(0, self.deadline - self.clock()))
        try:
            with deadline_urlopen(request, timeout=timeout, deadline=deadline) as response:
                if headers and "Range" in headers:
                    wanted = headers["Range"].removeprefix("bytes=")
                    if response.status != 206 or not response.headers.get(
                        "Content-Range", ""
                    ).startswith(f"bytes {wanted}/"):
                        raise ValueError("archive server did not honor exact Range")
                return response.read()
        except http.client.HTTPException as error:
            raise OSError("incomplete control transfer") from error

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
        limit = self.deadline
        if now >= limit:
            raise ControlLost("control_deadline")
        self.sleep(min(self.backoff, limit - now))
        self.backoff = min(15, self.backoff * 2)

    def launch_forward(self):
        self.forward = self.start_forward()
        self.forwards_started += 1
        self.forward_started = self.clock()
        self.forward_ready = False

    def forward_starting(self):
        return (
            self.forward is not None
            and self.forward.poll() is None
            and not self.forward_ready
            and self.clock() - self.forward_started < FORWARD_STARTUP_SECONDS
        )

    def ensure_forward(self, deadline):
        """Wait for the archive forward only; command replies cannot prove readiness."""
        if self.forward is None:
            self.launch_forward()
        grace = min(deadline, self.forward_started + FORWARD_STARTUP_SECONDS)
        while self.clock() < grace:
            if self.forward.poll() is not None:
                raise OSError("archive forward exited during startup")
            try:
                json.loads(self.request("/status", min(5, grace - self.clock())))
                self.forward_ready = True
                return
            except (OSError, ValueError, subprocess.SubprocessError):
                self.sleep(min(1, max(0, grace - self.clock())))
        raise OSError("archive forward startup grace expired")

    def get(self, path):
        while True:
            now = self.clock()
            limit = self.deadline
            if now >= limit:
                raise ControlLost("control_deadline")
            try:
                if (
                    self.command_channel is not None
                    and now >= self.live_deadline
                    and self.forward is None
                ):
                    value = self.command_channel.request(path, limit, transport=self)
                    self.last_channel = "command"
                    return value
                if self.forward is None:
                    self.launch_forward()
                if self.forward.poll() is not None:
                    raise OSError(f"SSM forward exited ({self.forward.returncode})")
                remaining = limit - self.clock()
                if remaining <= 0:
                    raise ControlLost("control_deadline")
                attempt_seconds = (
                    FINAL_LIMIT / FORWARD_WORST_BYTES_PER_SECOND + 10 if path == "/export" else 30
                )
                value = self.request(path, min(attempt_seconds, remaining))
                # Malformed status/receipt is also an interruption, not proof of completion.
                if path in ("/status", "/receipt"):
                    json.loads(value)
                self.forward_ready = True
                self.last_channel = "forward"
                self.outage_start, self.backoff = None, 1.0
                return value
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                # A broken forward proves nothing about the host controller.
                # Commands capture diagnostics and read sealed data independently.
                if self.command_channel is not None:
                    try:
                        value = self.command_channel.request(path, limit, transport=self)
                        self.last_channel = "command"
                        if not self.forward_starting():
                            self.close()
                        if self.outage_start is None:
                            self.outage_start = self.clock()
                        self.interruptions.append(
                            {
                                "unix_s": self.wall_clock(),
                                "error_class": type(error).__name__,
                                "command_channel": "available",
                                "restart_forward": self.clock() < self.live_deadline,
                            }
                        )
                        return value
                    except (
                        OSError,
                        ValueError,
                        RuntimeError,
                        subprocess.SubprocessError,
                    ) as command_error:
                        self.command_channel.unavailable(command_error)
                # The CLI/plugin starts asynchronously. Do not kill a live new
                # forward on connection refusal before it can bind its listener.
                restart = self.clock() < self.live_deadline and (
                    self.forward is None
                    or self.forward.poll() is not None
                    or self.forward_ready
                    or self.clock() - self.forward_started >= FORWARD_STARTUP_SECONDS
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
    started = transport.clock()
    data = transport.get("/export")
    if hashlib.sha256(data).hexdigest() != receipt["sha256"]:
        raise ValueError("export transfer checksum mismatch")
    (session / "evidence.tar.gz").write_bytes(data)
    (session / "export-receipt.json").write_text(
        json.dumps(receipt, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    outcome["export_verified"] = True
    outcome["export_transfer"] = {
        "bytes": len(data),
        "seconds": transport.clock() - started,
        "transport": transport.last_channel,
    }


def monitor_and_export(transport, session, outcome):
    while True:
        status = json.loads(transport.get("/status"))
        from .disk_records import write_json

        for name, record in status.get("disk_records", {}).items():
            if name in (
                "disk-before-pull.json",
                "disk-readiness.json",
                *(f"disk-checkpoint-{n}.json" for n in range(1, 5)),
            ):
                write_json(session / name, record)
        if status.get("sampled_root_minimum_free_bytes") is not None:
            write_json(
                session / "sampled-root-minimum.json",
                {
                    "free_bytes": status["sampled_root_minimum_free_bytes"],
                    "basis": "controller sampler via status; no operator probe",
                },
            )
        if transport.command_channel:
            transport.command_channel.record_snapshot(status)
        for receipt in status.get("completed_runs", []):
            number = receipt["run_number"]
            target = session / "sealed-runs" / f"run-{number}.tar.gz"
            target.parent.mkdir(exist_ok=True)
            digest = receipt.get("measurement_digest")
            if digest and not (target.parent / f"run-{number}.digest.json.gz").exists():
                fetch_digest(transport, session, receipt)
        # Essential measurements take priority over every best-effort large
        # transfer, including when several runs seal between status polls.
        if not status["finished"]:
            transport.sleep(max(0, min(5, transport.deadline - transport.clock())))
            continue
        from .archive_transfer import export_window

        receipts = status.get("completed_runs", [])
        total_bytes = sum(row["bytes"] for row in receipts)
        outcome["archive_export_window"] = {
            "total_bytes": total_bytes,
            "bytes_per_second": 500_000,
            "required_seconds": export_window(total_bytes),
            "available_seconds": max(0, transport.deadline - transport.clock()),
            "archive_bytes_during_measurement": 0,
            "measurement_finished_before_fetch": True,
        }
        for receipt in receipts:
            number = receipt["run_number"]
            target = session / "sealed-runs" / f"run-{number}.tar.gz"
            if not target.exists():
                try:
                    fetch_run(transport, session, receipt)
                    outcome.get("unfetched_full_runs", {}).pop(str(number), None)
                except (OSError, ValueError, subprocess.SubprocessError) as error:
                    outcome.setdefault("unfetched_full_runs", {})[str(number)] = str(error)
        fetch_export(transport, session, outcome)
        return


def recover_export(transport, session, outcome, termination_deadline):
    """Use the reserved export window, never a new arbitrary 60-second limit."""
    transport.close()
    transport.deadline = termination_deadline - CLEANUP_SECONDS
    transport.outage_start, transport.backoff = None, 1.0
    outcome["export_recovery_attempted"] = True
    try:
        monitor_and_export(transport, session, outcome)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        outcome["export_recovery_error"] = str(error)


def fetch_run(transport, session, receipt):
    from .archive_transfer import CHUNK_BYTES, CHUNK_TIMEOUT_SECONDS, FINAL_EXPORT_RESERVE_SECONDS
    from .disk_records import write_json
    from .stage_c_checkpoint import file_sha

    number = receipt["run_number"]
    if type(number) is not int or not 1 <= number <= 4:
        raise ValueError("invalid sealed run number")
    started = transport.clock()
    archive_deadline = transport.deadline - FINAL_EXPORT_RESERVE_SECONDS
    forwards_before = transport.forwards_started
    directory = session / "sealed-runs"
    directory.mkdir(exist_ok=True)
    path = directory / f"run-{number}.tar.gz"
    pending = path.with_suffix(".pending")
    progress = directory / f"run-{number}.progress.json"
    old = json.loads(progress.read_text()) if progress.exists() else None
    if (
        old is None
        or old.get("sha256") != receipt["sha256"]
        or old.get("total_bytes") != receipt["bytes"]
    ):
        pending.write_bytes(b"")
        old = {"sha256": receipt["sha256"], "total_bytes": receipt["bytes"], "offset": 0}
        write_json(progress, old)
    offset = old["offset"]
    if (
        not 0 <= offset <= receipt["bytes"]
        or not pending.exists()
        or pending.stat().st_size < offset
    ):
        raise ValueError("invalid persisted archive offset")
    # Truncate a chunk written before a crash but not durably acknowledged.
    chunks, retries, restart_backoff = [], 0, 1.0
    with pending.open("r+b") as stream:
        stream.truncate(offset)
        stream.seek(offset)
        while offset < receipt["bytes"]:
            remaining = archive_deadline - transport.clock()
            if remaining <= 0:
                raise OSError("archive export deadline; retained resumable offset")
            end = min(offset + CHUNK_BYTES, receipt["bytes"]) - 1
            chunk_started = transport.clock()
            try:
                if transport.forward is None or not transport.forward_ready:
                    transport.ensure_forward(archive_deadline)
                remaining = archive_deadline - transport.clock()
                if remaining <= 0:
                    raise OSError("archive chunk deadline")
                data = transport.request(
                    f"/run/{number}",
                    min(CHUNK_TIMEOUT_SECONDS, remaining),
                    headers={"Range": f"bytes={offset}-{end}"},
                )
                if len(data) != end - offset + 1:
                    raise OSError("incomplete archive range")
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                retries += 1
                transport.interruptions.append(
                    {
                        "error_class": type(error).__name__,
                        "archive_offset": offset,
                        "restart_forward": True,
                    }
                )
                transport.close()
                transport.sleep(min(restart_backoff, max(0, archive_deadline - transport.clock())))
                restart_backoff = min(15, restart_backoff * 2)
                continue
            restart_backoff = 1.0
            stream.write(data)
            stream.flush()
            __import__("os").fsync(stream.fileno())
            chunks.append(
                {"offset": offset, "bytes": len(data), "seconds": transport.clock() - chunk_started}
            )
            offset += len(data)
            write_json(progress, {**old, "offset": offset})
    if file_sha(pending) != receipt["sha256"]:
        # Permit a clean retry rather than pinning corrupt data at a complete offset.
        pending.unlink()
        progress.unlink()
        raise ValueError("sealed run transfer checksum mismatch")
    pending.replace(path)
    progress.unlink()

    write_json(directory / f"run-{number}.receipt.json", receipt)
    write_json(
        directory / f"run-{number}.transfer.json",
        {
            "bytes": offset,
            "seconds": transport.clock() - started,
            "transport": "forward",
            "chunks": chunks,
            "retries": retries,
            "forwards_started": transport.forwards_started - forwards_before,
            "sha256_verified": True,
        },
    )


def fetch_digest(transport, session, receipt):
    from .disk_records import write_json
    from .stage_c_digest import DIGEST_LIMIT

    number, digest = receipt["run_number"], receipt["measurement_digest"]
    if type(number) is not int or not 1 <= number <= 4 or not 0 < digest["bytes"] <= DIGEST_LIMIT:
        raise ValueError("invalid measurement digest receipt/bound")
    started = transport.clock()
    data = transport.get(f"/digest/{number}")
    if len(data) != digest["bytes"] or hashlib.sha256(data).hexdigest() != digest["sha256"]:
        raise ValueError("measurement digest transfer checksum/size mismatch")
    directory = session / "sealed-runs"
    directory.mkdir(exist_ok=True)
    target = directory / f"run-{number}.digest.json.gz"
    pending = target.with_suffix(".pending")
    pending.write_bytes(data)
    pending.replace(target)
    write_json(directory / f"run-{number}.digest.receipt.json", digest)
    write_json(
        directory / f"run-{number}.digest.transfer.json",
        {
            "bytes": len(data),
            "seconds": transport.clock() - started,
            "transport": getattr(transport, "last_channel", "command"),
        },
    )


class CommandChannel:
    """Bounded SSM stdout chunks; no bucket, credentials or extra billable resource."""

    def __init__(self, aws, instance, destination, port, session, outcome):
        self.aws, self.instance, self.destination, self.port = aws, instance, destination, port
        self.session, self.outcome = session, outcome
        self.last_diagnostic = None
        self.last_restart = -float("inf")

    def call(self, action, deadline, *, archive="session", offset=0, size=12288):
        argv = [
            "python3",
            "-B",
            "-m",
            "inference_platform.stage_c_control",
            "--destination",
            self.destination,
            "--action",
            action,
            "--port",
            str(self.port),
            "--archive",
            archive,
            "--offset",
            str(offset),
            "--size",
            str(size),
        ]
        command = (
            "PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="
            + shlex.quote(self.destination + "/sources/python/src")
            + " "
            + shlex.join(argv)
        )
        result = ssm_commands(
            self.aws,
            self.instance,
            [command],
            deadline,
            self.session,
            self.outcome["ssm_command_attempts"],
        )
        value = json.loads(result["StandardOutputContent"])
        if not isinstance(value, dict):
            raise ValueError("invalid command-channel response")
        return value

    def record(self, name, value):
        with (self.session / name).open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(value, separators=(",", ":"), allow_nan=False) + "\n")

    def record_snapshot(self, status):
        self.record(
            "operator-host-snapshots.jsonl",
            {
                "unix_s": time.time(),
                "host": status.get("host"),
                "host_controller_alive": status.get("host_controller_alive"),
                "completed_run_count": len(status.get("completed_runs", [])),
            },
        )

    def unavailable(self, error):
        self.record(
            "host-diagnostics.jsonl",
            {
                "unix_s": time.time(),
                "status": "UNAVAILABLE_COMMAND_CHANNEL",
                "error_class": type(error).__name__,
                "last_diagnostic_available": self.last_diagnostic is not None,
                "last_known_host": self.last_diagnostic.get("host")
                if self.last_diagnostic
                else None,
            },
        )

    def request(self, path, deadline, *, transport):
        if path == "/status":
            result = self.call("snapshot", deadline)
            diagnostic = result["diagnostics"]
            self.last_diagnostic = diagnostic
            self.record(
                "host-diagnostics.jsonl",
                {"unix_s": transport.wall_clock(), "status": "CAPTURED", **diagnostic},
            )
            status = result["status"]
            status["host"] = diagnostic["host"]
            now = transport.clock()
            if (
                status["host_controller_alive"]
                and now < transport.live_deadline
                and now - self.last_restart >= 60
                and (
                    not diagnostic.get("control_port_listening")
                    or (transport.outage_start is not None and now - transport.outage_start >= 60)
                )
            ):
                # Replacing the server never replaces its durable, independent child.
                self.last_restart = now
                try:
                    self.call("restart", min(deadline, transport.live_deadline))
                except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                    self.record(
                        "host-diagnostics.jsonl",
                        {
                            "unix_s": transport.wall_clock(),
                            "status": "CONTROL_SERVER_RESTART_FAILED",
                            "error_class": type(error).__name__,
                            "host_controller_alive": True,
                        },
                    )
            if status["finished"]:
                self.call("recover", deadline)
            return json.dumps(status).encode()
        if path.startswith("/run/"):
            raise ValueError("full run archives require the forward")
        archive = (
            f"run-{int(path.rsplit('/', 1)[1])}.digest"
            if path.startswith("/digest/")
            else "session"
        )
        receipt = self.call("receipt", deadline, archive=archive)
        if path == "/receipt":
            return json.dumps(receipt).encode()
        from .stage_c_digest import DIGEST_LIMIT, FINAL_LIMIT

        bound = DIGEST_LIMIT if archive.endswith(".digest") else FINAL_LIMIT
        if not 0 < receipt["bytes"] <= bound:
            raise ValueError("command-channel measurement transfer exceeds compressed bound")
        # SSM output is capped at 24000 chars; base64 chunks stay below it.
        # The absolute export deadline bounds the complete transfer, not each chunk alone.
        parts = []
        offset = 0
        while offset < receipt["bytes"]:
            chunk = self.call("read", deadline, archive=archive, offset=offset)
            data = base64.b64decode(chunk["base64"], validate=True)
            if chunk["offset"] != offset or chunk["bytes"] != len(data) or not data:
                raise ValueError("invalid command-channel archive chunk")
            parts.append(data)
            offset += len(data)
        data = b"".join(parts)
        if len(data) != receipt["bytes"] or hashlib.sha256(data).hexdigest() != receipt["sha256"]:
            raise ValueError("command-channel archive checksum mismatch")
        return data
