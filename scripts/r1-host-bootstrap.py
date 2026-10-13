"""Authenticated loopback upload/control reached only through SSM port forwarding."""

import argparse
import hashlib
import hmac
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

BUNDLE_CHUNK_BYTES = 1024**2
BUNDLE_MAX_BYTES = 100 * 1024**2


class BundleUpload:
    """Only complete, hash-verified chunks advance the durable offset."""

    def __init__(self, directory, expected, lock=None):
        self.partial = directory / "bundle.partial"
        self.destination = directory / "payload"
        self.expected = expected
        self.lock = lock or threading.Lock()
        self.staged = False

    def status(self):
        return {
            "offset": self.partial.stat().st_size if self.partial.exists() else 0,
            "staged": self.staged,
        }

    def append(self, offset, data, digest):
        # Network reads and hashing occur before the shared control lock.
        if not 0 < len(data) <= BUNDLE_CHUNK_BYTES:
            raise ValueError("bounded bundle chunk size")
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError("bundle chunk SHA mismatch")
        with self.lock:
            current = self.status()["offset"]
            if (
                self.staged
                or offset != current
                or current + len(data) > BUNDLE_MAX_BYTES
            ):
                raise ValueError("bundle offset or total size mismatch")
            with self.partial.open("ab") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            return self.status()

    def commit(self):
        # Caller holds the control lock. A repeated commit never unpacks/restarts.
        if self.staged:
            return {**self.status(), "already_staged": True}
        data = self.partial.read_bytes() if self.partial.exists() else b""
        stage = self.destination.with_name("payload-staging")
        try:
            unpack(
                data, stage, self.expected
            )  # Full SHA exactly once, before extraction.
            stage.rename(self.destination)
        except Exception:
            if stage.exists():
                shutil.rmtree(stage)
            raise
        self.staged = True
        return self.status()


def unpack(data, destination, expected):
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError("reviewed bundle SHA mismatch")
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        members = archive.getmembers()
        if len(members) > 3000 or sum(x.size for x in members) > 200 * 1024**2:
            raise ValueError("bundle exceeds fixed extraction bound")
        for member in members:
            path = Path(member.name)
            if (
                member.issym()
                or member.islnk()
                or not member.isfile()
                or path.is_absolute()
                or ".." in path.parts
            ):
                raise ValueError("unsafe bundle member")
        archive.extractall(destination, filter="data")
    verify_payload(destination)


def verify_payload(destination):
    manifest = json.loads((destination / "payload.json").read_bytes())
    actual = {
        x.relative_to(destination).as_posix()
        for x in destination.rglob("*")
        if x.is_file()
    }
    if actual != set(manifest["files"]) | {"payload.json"}:
        raise ValueError("bundle inventory mismatch")
    for name, digest in manifest["files"].items():
        if hashlib.sha256((destination / name).read_bytes()).hexdigest() != digest:
            raise ValueError("bundle file SHA mismatch")
    (destination / "bin/uv").chmod(0o755)
    (destination / "bin/gateway").chmod(0o755)


def staged_bundle_response(data, destination, expected):
    if not destination.exists():
        unpack(data, destination, expected)
        return {"staged": True}
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError("reviewed bundle SHA mismatch")
    verify_payload(destination)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        manifests = [
            member for member in archive.getmembers() if member.name == "payload.json"
        ]
        if len(manifests) != 1 or not manifests[0].isfile():
            raise ValueError("bound bundle has no unique payload manifest")
        source = archive.extractfile(manifests[0])
        if (
            source is None
            or source.read() != (destination / "payload.json").read_bytes()
        ):
            raise ValueError("staged payload differs from bound bundle")
    return {"staged": True, "already_staged": True}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--token", required=True)
    parser.add_argument("--bundle-sha256", required=True)
    parser.add_argument("--deadline-unix-s", type=float, required=True)
    parser.add_argument("--port", type=int, default=22280)
    parser.add_argument("--directory", type=Path, default=Path("/opt/r1/control"))
    args = parser.parse_args()
    directory = args.directory
    directory.mkdir(parents=True, exist_ok=True)
    binding = directory / "bundle-sha256"
    if binding.exists() and binding.read_text() != args.bundle_sha256:
        raise ValueError("existing control directory belongs to another bundle")
    binding.write_text(args.bundle_sha256)
    lock, processes = threading.Lock(), {}
    upload = BundleUpload(directory, args.bundle_sha256, lock)
    spool = None
    finalized = False
    current = directory / "payload"
    if current.exists():
        if (not upload.partial.exists()
            or hashlib.sha256(upload.partial.read_bytes()).hexdigest() != args.bundle_sha256):
            raise ValueError("existing payload lacks the bound archive")
        verify_payload(current)
        upload.staged = True

    class Handler(BaseHTTPRequestHandler):
        timeout = 30

        def reply(self, value, status=200):
            data = json.dumps(value).encode()
            self.send_response(status)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def dispatch(self):
            nonlocal spool, finalized
            if not hmac.compare_digest(
                self.headers.get("Authorization", ""), "Bearer " + args.token
            ):
                self.reply({"error": "unauthorized"}, 403)
                return
            try:
                if time.time() >= args.deadline_unix_s:
                    raise TimeoutError("host absolute lifecycle deadline")
                data = b""
                if self.command == "POST":
                    size = int(self.headers.get("Content-Length", "0"))
                    limit = (
                        BUNDLE_CHUNK_BYTES
                        if self.path.startswith("/bundle/")
                        else 65536
                    )
                    if not 0 <= size <= limit or (
                        size == 0 and self.path != "/bundle/commit"
                    ):
                        raise ValueError("bounded request size")
                    data = self.rfile.read(size)
                    if len(data) != size:
                        raise ValueError("truncated request body")
                    if (
                        self.path.startswith("/bundle/")
                        and self.path != "/bundle/commit"
                    ):
                        if time.time() >= args.deadline_unix_s:
                            raise TimeoutError("host absolute lifecycle deadline")
                        response = upload.append(
                            int(self.path.removeprefix("/bundle/")),
                            data,
                            self.headers.get("X-Chunk-SHA256", ""),
                        )
                        self.reply(response)
                        return
                with lock:
                    if time.time() >= args.deadline_unix_s:
                        raise TimeoutError("host absolute lifecycle deadline")
                    if self.command == "GET" and self.path == "/bundle":
                        self.reply(upload.status())
                        return
                    if self.command == "GET" and self.path == "/status":
                        if (
                            processes.get("export")
                            and processes["export"].poll() == 0
                            and not finalized
                        ):
                            spool.stop.set()
                            spool.thread.join(timeout=30)
                            if spool.thread.is_alive():
                                raise TimeoutError("incremental spool did not stop")
                            spool.capture(final=True)
                            with tarfile.open(
                                directory / "evidence.tar.gz", "w:gz", compresslevel=1
                            ) as archive:
                                archive.add(
                                    directory / "incremental-index.json",
                                    arcname="incremental-index.json",
                                )
                            finalized = True
                        self.reply(
                            {
                                "bundle_sha256": args.bundle_sha256,
                                "actions": {
                                    name: child.poll()
                                    for name, child in processes.items()
                                },
                            }
                        )
                        return
                    if self.command == "GET" and self.path == "/segments":
                        self.reply(spool.listing() if spool else {"segments": []})
                        return
                    if self.command == "GET" and self.path.startswith(
                        ("/archive/", "/segment/")
                    ):
                        # Fixed archive; offset and chunk size only. No arbitrary file reads.
                        offset = int(self.path.split("/")[-1])
                        if offset < 0:
                            raise ValueError("negative archive offset")
                        if self.path.startswith("/segment/"):
                            name = self.path.split("/")[2]
                            if (
                                len(name) != 13
                                or not name[:6].isdigit()
                                or name[6:] != ".tar.gz"
                            ):
                                raise ValueError("invalid segment name")
                            archive = directory / "segments" / name
                        else:
                            archive = directory / "evidence.tar.gz"
                        with archive.open("rb") as stream:
                            stream.seek(offset)
                            data = stream.read(1048576)
                        self.send_response(200)
                        self.send_header("Content-Length", str(len(data)))
                        self.send_header("X-Archive-Size", str(archive.stat().st_size))
                        self.send_header(
                            "X-Chunk-SHA256", hashlib.sha256(data).hexdigest()
                        )
                        self.end_headers()
                        self.wfile.write(data)
                        return
                    if self.command == "POST" and self.path == "/bundle/commit":
                        response = upload.commit()
                        if spool is None:
                            # Keep the verified payload inventory immutable on import.
                            sys.dont_write_bytecode = True
                            sys.path.insert(0, str(current / "python/src"))
                            from inference_platform.r1_evidence import Spool

                            spool = Spool(directory)
                            (directory / "incremental-active").touch()
                            spool.thread.start()
                        self.reply(response)
                    elif self.command == "POST" and self.path == "/run":
                        value = json.loads(data)
                        action = value["action"]
                        if action not in {
                            "ready",
                            "probe",
                            "measure",
                            "close",
                            "export",
                        }:
                            raise ValueError("invalid host action")
                        # Idempotent action admission makes a lost POST response safe.
                        # Existing processes and their deadlines are never restarted.
                        if action in processes:
                            self.reply({"started": action, "already_started": True})
                            return
                        if (
                            action in {"close", "export"}
                            and processes.get("measure")
                            and processes["measure"].poll() is None
                        ):
                            raise ValueError(
                                "host Session still running; close/export refused"
                            )
                        deadline = float(value["deadline_unix_s"])
                        if not time.time() < deadline <= args.deadline_unix_s:
                            raise ValueError(
                                "action deadline outside original envelope"
                            )
                        if "context" in value:
                            context = directory / "context.json"
                            if context.exists():
                                raise ValueError("runtime context already bound")
                            context.write_text(json.dumps(value["context"]))
                            context.chmod(0o600)
                        env = {
                            **os.environ,
                            "PYTHONPATH": str(current / "python/src"),
                            "UV_PYTHON": "3.12.7",
                            "PYTHONDONTWRITEBYTECODE": "1",
                        }
                        with (directory / (action + ".log")).open("xb") as log:
                            if action == "measure":
                                (directory / "measure-started.json").write_text("{}")
                            processes[action] = subprocess.Popen(
                                [
                                    str(current / "bin/uv"),
                                    "run",
                                    "--project",
                                    str(current / "python"),
                                    "--locked",
                                    "python",
                                    "-m",
                                    "inference_platform.r1_cloud_host",
                                    "--action",
                                    action,
                                    "--directory",
                                    str(directory),
                                    "--deadline-unix-s",
                                    str(deadline),
                                ],
                                env=env,
                                stdin=subprocess.DEVNULL,
                                stdout=log,
                                stderr=subprocess.STDOUT,
                                start_new_session=True,
                            )
                        self.reply({"started": action})
                    else:
                        raise ValueError("unknown action")
            except Exception as exc:
                with lock:
                    response = {"error": str(exc), **upload.status()}
                try:
                    self.reply(response, 409)
                except OSError:
                    pass  # A truncated/disconnected client cannot poison the server.

        do_GET = dispatch
        do_POST = dispatch

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.timeout = 1
    while time.time() < args.deadline_unix_s:
        server.handle_request()
    server.server_close()
    if spool:
        spool.stop.set()


if __name__ == "__main__":
    main()
