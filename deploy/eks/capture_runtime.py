"""Independent single-API-process supervisor and durable metrics-start signal.

Mounted read-only into the pinned vLLM image. No log-line/scrape inference.
Never reuses a capture directory after a container restart. The node/collector
must retain the spool before pod deletion; a missing spool is capture loss.
"""

import hashlib
import http.server
import json
import os
import signal
import subprocess
import sys
import threading
import time
import urllib.parse
import uuid
from contextlib import contextmanager
from pathlib import Path

LAUNCHER_SHA256 = "393c213ea68e12936e2ed018d4b6bc9368049bf0c26ab135790ac4fee15772ed"
ENTRY_SHA256 = "db689f8486e5d2c9eb59d347e03a27ce837d014f8d3d7f84d55a0e382813ca84"


@contextmanager
def startup_guard(root):
    """Serialize the no-metrics cutoff with the child's pre-listen marker."""
    with (root / "startup.lock").open("a+b") as lock:
        if os.name == "nt":
            import msvcrt

            if lock.tell() == 0:
                lock.write(b"0")
                lock.flush()
            lock.seek(0)
            msvcrt.locking(lock.fileno(), msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                lock.seek(0)
                msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)


def durable(path, value):
    temporary = path.with_name(path.name + ".pending-" + uuid.uuid4().hex)
    try:
        with temporary.open("xb") as stream:
            stream.write(json.dumps(value, sort_keys=True).encode() + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        # Publish complete bytes without replacing a previous origin/signal.
        os.link(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    if os.name != "nt":
        fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def checked_runtime():
    import vllm
    from vllm.entrypoints.launchers import launcher
    from vllm.entrypoints.launchers.api_server import entry

    if vllm.__version__ != "0.29.0":
        raise RuntimeError("runtime_version_mismatch")
    for module, expected in ((launcher, LAUNCHER_SHA256), (entry, ENTRY_SHA256)):
        if hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest() != expected:
            raise RuntimeError("runtime_startup_signal_source_mismatch")
    return launcher, entry


def child(root, argv):
    launcher, entry = checked_runtime()
    original = launcher.NoSignalServer.startup

    async def observed_startup(server, *args, **kwargs):
        # Conservative inhibition is durable BEFORE any server may listen.
        # A crash after this marker can never turn into a loading receipt.
        with startup_guard(root):
            durable(
                root / "metrics-pending.json",
                {"mono_ns": time.monotonic_ns(), "pid": os.getpid()},
            )
        begin = time.monotonic_ns()
        if not any(
            getattr(route, "path", None) == "/metrics"
            for route in server.config.app.routes
        ):
            raise RuntimeError("native_metrics_route_missing")
        await original(server, *args, **kwargs)
        end = time.monotonic_ns()
        if not server.started:
            raise RuntimeError("native_metrics_server_not_started")
        durable(
            root / "metrics-started.json",
            {"start_ns": begin, "end_ns": end, "pid": os.getpid()},
        )

    launcher.NoSignalServer.startup = observed_startup
    sys.argv = ["vllm", *argv]
    entry.main()


def signal_child(root):
    # The identical source/version gate runs without calling entry.main().
    checked_runtime()
    stopped = threading.Event()
    previous = signal.signal(signal.SIGTERM, lambda *args: stopped.set())
    try:
        durable(
            root / "signal-child-ready.json",
            {
                "pid": os.getpid(),
                "process_start": Path("/proc/self/stat")
                .read_text()
                .rsplit(")", 1)[1]
                .split()[19],
                "launcher_sha256": LAUNCHER_SHA256,
                "entry_sha256": ENTRY_SHA256,
            },
        )
        stopped.wait()
    finally:
        signal.signal(signal.SIGTERM, previous)


class Supervisor:
    def __init__(self, root, uid, *, slot=None, role=None):
        self.root, self.uid, self.role = root, uid, role
        root.mkdir(parents=True, exist_ok=True)
        self.boot, self.sequence, self.lost = str(uuid.uuid4()), 0, False
        boot_file = Path("/proc/sys/kernel/random/boot_id")
        self.node_boot = (
            boot_file.read_text().strip() if boot_file.exists() else "native-test-host"
        )
        self.lock = threading.Lock()
        durable(
            root / "supervisor-origin.json",
            {
                "boot_id": self.boot,
                "pod_uid": uid,
                **({"slot": slot} if slot is not None else {}),
                **(
                    {
                        "role": role,
                        "node": os.environ["NODE_NAME"],
                        "node_boot_id": self.node_boot,
                        "supervisor_sha256": hashlib.sha256(
                            Path(__file__).read_bytes()
                        ).hexdigest(),
                    }
                    if role is not None
                    else {}
                ),
                "supervisor_pid": os.getpid(),
                "supervisor_start": Path("/proc/self/stat")
                .read_text()
                .rsplit(")", 1)[1]
                .split()[19]
                if os.name == "posix"
                else None,
            },
        )
        self.file = (root / "lifecycle.jsonl").open("xb")
        self.record("supervisor_start")

    def record(self, event, **data):
        with self.lock:
            if self.lost:
                raise RuntimeError("supervisor_capture_lost")
            row = {
                "schema": "vllm-supervisor-v1",
                "pod_uid": self.uid,
                "boot_id": self.boot,
                "node_boot_id": self.node_boot,
                "sequence": self.sequence,
                "mono_ns": time.monotonic_ns(),
                "wall_ns": time.time_ns(),
                "event": event,
                "capture_lost": False,
                "restart_count": 0,
                **data,
            }
            try:
                self.file.write(json.dumps(row, sort_keys=True).encode() + b"\n")
                self.file.flush()
                os.fsync(self.file.fileno())
            except OSError:
                self.lost = True
                raise
            self.sequence += 1
            return row

    def handler(self):
        supervisor = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                with supervisor.lock:
                    if supervisor.lost:
                        self.send_error(503)
                        return
                    capture_next = None
                    query = urllib.parse.parse_qs(
                        urllib.parse.urlsplit(self.path).query
                    )
                    if self.path == "/ready" and supervisor.role == "setup_signal":
                        try:
                            ready = json.loads(
                                (
                                    supervisor.root / "signal-child-ready.json"
                                ).read_bytes()
                            )
                            starts = [
                                json.loads(line)["pid"]
                                for line in (supervisor.root / "lifecycle.jsonl")
                                .read_bytes()
                                .splitlines()
                                if json.loads(line)["event"] == "process_start"
                            ]
                            current = (
                                Path("/proc", str(ready["pid"]), "stat")
                                .read_text()
                                .rsplit(")", 1)[1]
                                .split()[19]
                            )
                            if (
                                starts != [ready["pid"]]
                                or current != ready["process_start"]
                            ):
                                raise ValueError("signal_child_lineage")
                            data = json.dumps(
                                {
                                    "ready": True,
                                    "pod_uid": supervisor.uid,
                                    "boot_id": supervisor.boot,
                                    "role": "setup_signal",
                                }
                            ).encode()
                        except (OSError, ValueError, KeyError):
                            self.send_error(503, "setup_signal_not_ready")
                            return
                    elif self.path.startswith("/clock"):
                        data = json.dumps(
                            {
                                "boot_id": supervisor.boot,
                                "node_boot_id": supervisor.node_boot,
                                "mono_ns": time.monotonic_ns(),
                                "wall_ns": time.time_ns(),
                            }
                        ).encode()
                    elif self.path.startswith("/native/events?"):
                        try:
                            from inference_platform.inf037b_native import read_events

                            data = json.dumps(
                                read_events(
                                    supervisor.root / "native", int(query["after"][0])
                                )
                            ).encode()
                        except (OSError, ValueError, KeyError, ImportError):
                            self.send_error(409, "native_emitter_unavailable")
                            return
                    elif self.path.startswith("/events?"):
                        try:
                            offset = int(query["offset"][0])
                            with (supervisor.root / "lifecycle.jsonl").open(
                                "rb"
                            ) as source:
                                if (
                                    offset < 0
                                    or offset > os.fstat(source.fileno()).st_size
                                ):
                                    raise ValueError("truncated")
                                if offset:
                                    source.seek(offset - 1)
                                    if source.read(1) != b"\n":
                                        raise ValueError("unaligned")
                                source.seek(offset)
                                data = source.read(1_048_576)
                                data = data[: data.rfind(b"\n") + 1]
                                capture_next = offset + len(data)
                        except (ValueError, KeyError):
                            self.send_error(409)
                            return
                    else:
                        self.send_error(404)
                        return
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(data)))
                    self.send_header("X-Capture-Boot", supervisor.boot)
                    if capture_next is not None:
                        self.send_header("X-Capture-Next", str(capture_next))
                    self.end_headers()
                    self.wfile.write(data)

        return Handler

    def run(self, argv, *, port=9101, grace=40, on_ready=None):
        server = http.server.ThreadingHTTPServer(("0.0.0.0", port), self.handler())
        serving = threading.Thread(target=server.serve_forever, daemon=True)
        serving.start()
        process = subprocess.Popen(argv, start_new_session=os.name != "nt")
        self.record("process_start", pid=process.pid)
        signalled, seen, pending_signals = [], set(), []

        def terminate(signum, frame):
            # Never perform file I/O or take the recorder lock in a Python
            # signal handler: it can interrupt the same lock/fsync operation.
            pending_signals.append((signum, time.monotonic_ns()))

        previous = signal.signal(signal.SIGTERM, terminate)
        try:
            if on_ready:
                on_ready()
            while True:
                with startup_guard(self.root):
                    while pending_signals:
                        signum, received = pending_signals.pop(0)
                        self.record(
                            "signal",
                            signal=signal.Signals(signum).name,
                            pid=process.pid,
                            signal_data={"receipt_ns": received},
                        )
                        if not signalled:
                            signalled.append(received / 1_000_000_000)
                            process.terminate()
                    for filename, event in (
                        ("metrics-pending.json", "metrics_pending"),
                        ("metrics-started.json", "startup"),
                    ):
                        path = self.root / filename
                        if path.exists() and filename not in seen:
                            data = json.loads(path.read_bytes())
                            if data.get("pid") != process.pid:
                                self.lost = True
                                raise RuntimeError(
                                    "metrics_signal_process_lineage_mismatch"
                                )
                            self.record(event, signal_data=data)
                            seen.add(filename)
                    # Timestamp BEFORE poll: if poll still sees a live child,
                    # it was alive at this cutoff. The shared lock also proves
                    # that metrics inhibition/startup cannot precede it unseen.
                    cutoff = time.monotonic_ns()
                    if process.poll() is not None:
                        break
                    self.record("heartbeat", pid=process.pid, mono_ns=cutoff)
                if signalled and time.monotonic() - signalled[0] >= grace:
                    if os.name != "nt":
                        os.killpg(process.pid, signal.SIGKILL)
                    else:
                        process.kill()
                time.sleep(0.25)
            self.record("process_end", pid=process.pid, returncode=process.returncode)
            return process.returncode
        finally:
            signal.signal(signal.SIGTERM, previous)
            if process.poll() is None:
                if os.name != "nt":
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
                process.wait()
            server.shutdown()
            server.server_close()
            self.file.close()


def main():
    root = Path(os.environ.get("CAPTURE_ROOT", "/capture-data"))
    if len(sys.argv) > 1 and sys.argv[1] == "--signal-child":
        signal_child(root)
    elif len(sys.argv) > 1 and sys.argv[1] == "--setup-signal":
        slot = os.environ["BACKEND_SLOT"]
        if slot not in ("0", "1"):
            raise RuntimeError("native_slot_identity_missing")
        supervisor = Supervisor(
            root, os.environ["POD_UID"], slot=int(slot), role="setup_signal"
        )
        raise SystemExit(
            supervisor.run(
                [sys.executable, str(Path(__file__).resolve()), "--signal-child"]
            )
        )
    elif len(sys.argv) > 1 and sys.argv[1] == "--child":
        child(root, sys.argv[2:])
    else:
        slot = os.environ.get("BACKEND_SLOT")
        if "INF037B_NATIVE_ROOT" in os.environ and slot not in ("0", "1"):
            raise RuntimeError("native_slot_identity_missing")
        supervisor = Supervisor(
            root, os.environ["POD_UID"], slot=int(slot) if slot is not None else None
        )
        raise SystemExit(
            supervisor.run(
                [
                    sys.executable,
                    str(Path(__file__).resolve()),
                    "--child",
                    *sys.argv[1:],
                ]
            )
        )


if __name__ == "__main__":
    main()
