"""Thin bootstrap agent over the reviewed DEC-077 transport and tar staging."""

import argparse
import json
import subprocess
import sys
import threading
import time
from pathlib import Path

import inf060_diagnostics as diagnostics
from l4_compat_service import L4Host
from package_a_host import server


class ProbeHost(L4Host):
    def __init__(self, *args, cpu=False, failure=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.cpu = cpu
        self.failure = diagnostics.injected_failure(cpu, failure)

    def _archive_entries(self):
        log = self.root / "private-agent.log"
        if self.child and self.child.poll() not in (None, 0) and log.is_file():
            diagnostics.write(
                self.output / "failure-agent.json", diagnostics.file_tail(log)
            )
        return super()._archive_entries()

    def dispatch(self, path, data, headers):
        if path != "/start":
            return super().dispatch(path, data, headers)
        if (
            self.child
            or self.cancelled
            or time.time() >= self.deadline
            or not self.manifest
            or not (self.root / "stage.json").is_file()
        ):
            raise ValueError("inf060:host_start")
        timeout = self.manifest["weights_timeout_s"]
        if type(timeout) is not int or not 0 < timeout < 2700:
            raise ValueError("inf060:host_weights_timeout")
        self.root.joinpath("runtime.json").write_text(
            json.dumps({"weights_timeout_s": timeout})
        )
        self.log = (self.root / "bootstrap.log").open("xb")
        argv = [
            "/usr/bin/env",
            "-i",
            "PATH=/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME=" + str(self.root / "home"),
            "PYTHONPATH=" + str(self.repo / "python/src"),
            "PYTHONDONTWRITEBYTECODE=1",
            "LANG=C.UTF-8",
            sys.executable,
            str(self.repo / "scripts/inf060_probe_host.py"),
            "launch",
            "--root",
            str(self.root),
            "--origin",
            str(self.origin),
            "--end",
            str(self.deadline),
        ]
        if self.cpu:
            argv.append("--cpu-rehearsal")
        if self.failure:
            argv.extend(["--mock-failure", self.failure])
        self.child = subprocess.Popen(
            argv,
            cwd=self.repo,
            stdout=self.log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        return self.status()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--deadline", type=float, required=True)
    parser.add_argument("--origin", type=float, required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--cpu-rehearsal", action="store_true")
    parser.add_argument("--mock-failure", choices=diagnostics.FAILURES)
    args = parser.parse_args()
    host = ProbeHost(
        args.root,
        args.token_file.read_text().strip(),
        args.manifest_sha256,
        args.deadline,
        origin=args.origin,
        cpu=args.cpu_rehearsal,
        failure=args.mock_failure,
    )

    def watchdog():
        time.sleep(max(0, host.deadline - time.time()))
        with host.lock:
            host.cancel()

    threading.Thread(target=watchdog, daemon=True).start()
    server(host, port=args.port).serve_forever()


if __name__ == "__main__":
    main()
