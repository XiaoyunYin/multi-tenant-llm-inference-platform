"""Disk-backed control recovery invoked only over the reviewed SSM command channel."""

import argparse
import base64
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from .host_diagnostics import diagnostic_bundle
from .stage_c_session import host_status, identity_alive, load_identity, sidecar


def restart_server(destination, port):
    identity = load_identity(sidecar(destination, ".server-pid.json"))
    if identity_alive(identity):
        os.kill(identity["pid"], signal.SIGTERM)
        for _ in range(10):
            if not identity_alive(identity):
                break
            time.sleep(0.1)
        if identity_alive(identity):
            os.kill(identity["pid"], signal.SIGKILL)
    manifest = json.loads((destination / "staging-manifest.json").read_text())
    bootstrap = sidecar(destination, "-entrypoint.py")
    import hashlib

    if hashlib.sha256(bootstrap.read_bytes()).hexdigest() != manifest["entrypoint"]["sha256"]:
        raise ValueError("restart entrypoint differs from reviewed bundle")
    nonce = sidecar(destination, ".nonce").read_text().strip()
    with sidecar(destination, ".restart.log").open("ab") as log:
        subprocess.Popen(
            [
                sys.executable,
                "-B",
                str(bootstrap),
                "--serve-transport",
                str(destination),
                "--manifest-sha256",
                hashlib.sha256((destination / "staging-manifest.json").read_bytes()).hexdigest(),
                "--nonce",
                nonce,
                "--port",
                str(port),
                "--epoch-file",
                str(
                    load_identity(sidecar(destination, ".epoch-path.json"))
                    or "/etc/inf011/deadline_epoch"
                ),
            ],
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            stdout=log,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )
    return {"status": "control_server_restart_requested", "host_controller_restarted": False}


def archive_path(destination, archive):
    if archive == "session":
        return destination / "session/evidence.tar.gz"
    import re

    if not re.fullmatch(r"run-[1-4](?:\.digest)?", archive):
        raise ValueError("unapproved archive name")
    suffix = ".json.gz" if archive.endswith(".digest") else ".tar.gz"
    return destination / "session/sealed-runs" / (archive + suffix)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument(
        "--action", choices=("snapshot", "restart", "recover", "receipt", "read"), required=True
    )
    parser.add_argument("--port", type=int, default=22280)
    parser.add_argument("--archive", default="session")
    parser.add_argument("--offset", type=int, default=0)
    parser.add_argument("--size", type=int, default=12288)
    args = parser.parse_args()
    destination = args.destination
    termination = int(Path("/etc/inf011/deadline_epoch").read_text())
    status = host_status(destination, termination)
    if args.action == "snapshot":
        result = {
            "status": status,
            "diagnostics": diagnostic_bundle(
                load_identity(destination / "controller-pid.json"), args.port
            ),
        }
    elif args.action == "restart":
        result = restart_server(destination, args.port)
    elif args.action == "recover":
        from .stage_c_session import export

        receipt = destination / "session/export-receipt.json"
        if receipt.exists() and (destination / "session/evidence.tar.gz").exists():
            result = json.loads(receipt.read_text())
        else:
            if status["host_controller_alive"]:
                raise ValueError("cannot recover mutable files from a live host controller")
            result = export(
                destination / "session", destination / "staging-manifest.json", recovery=True
            )
    elif args.action == "receipt":
        name = (
            "export-receipt.json" if args.archive == "session" else args.archive + ".receipt.json"
        )
        result = json.loads(
            (
                destination
                / "session"
                / ("" if args.archive == "session" else "sealed-runs")
                / name
            ).read_text()
        )
    else:
        if args.offset < 0 or not 1 <= args.size <= 12288:
            raise ValueError("unbounded command-channel read")
        path = archive_path(destination, args.archive)
        from .stage_c_digest import DIGEST_LIMIT, FINAL_LIMIT

        bound = (
            DIGEST_LIMIT
            if args.archive.endswith(".digest")
            else FINAL_LIMIT
            if args.archive == "session"
            else 0
        )
        if not bound or path.stat().st_size > bound:
            raise ValueError(
                "full archives require forward; bounded digest/session only over commands"
            )
        with path.open("rb") as stream:
            stream.seek(args.offset)
            chunk = stream.read(args.size)
        result = {
            "offset": args.offset,
            "bytes": len(chunk),
            "base64": base64.b64encode(chunk).decode(),
        }
    print(json.dumps(result, separators=(",", ":")))


if __name__ == "__main__":
    main()
