"""DEC-077 authenticated loopback transfer service, with a tar/compat runner.

Uploaded alongside the unchanged package_a_host.py. No provider access here.
"""

import argparse
import json
import subprocess
import tarfile
import threading
import time
from pathlib import Path

from package_a_host import Host, digest, server


class L4Host(Host):
    def __init__(self, *args, origin, **kwargs):
        super().__init__(*args, **kwargs)
        self.origin = origin

    def status(self):
        return {**super().status(), "staged": (self.root / "stage.json").exists()}

    def _write_archive(self, destination, entries, *, truncated=None):
        if truncated is not None:
            raise ValueError("l4:complete_export_only")
        return super()._write_archive(destination, entries)

    def dispatch(self, path, data, headers):
        if path not in ("/stage", "/start"):
            return super().dispatch(path, data, headers)
        import time

        if self.cancelled or time.time() >= self.deadline or self.manifest is None:
            raise ValueError("l4:stage_deadline_or_binding")
        if path == "/stage":
            if digest(self.partial) != self.manifest["bundle_sha256"]:
                raise ValueError("l4:payload_hash")
            if self.repo.exists():
                raise ValueError("l4:stage_once")
            self.repo.mkdir()
            with tarfile.open(self.partial) as archive:
                members = archive.getmembers()
                names = [m.name for m in members]
                if len(set(names)) != len(names) or any(
                    not m.isfile()
                    or Path(m.name).is_absolute()
                    or ".." in Path(m.name).parts
                    for m in members
                ):
                    raise ValueError("l4:payload_inventory")
                archive.extractall(self.repo, filter="data")
            manifest = json.loads((self.repo / "sources.json").read_bytes())
            if any(
                digest(self.repo / name) != facts["sha256"]
                or (self.repo / name).stat().st_size != facts["bytes"]
                for name, facts in manifest.items()
            ):
                raise ValueError("l4:staged_sources")
            (self.root / "stage.json").write_text(json.dumps({"sources": manifest}))
            return {"staged": True, "sources": len(manifest)}
        if self.child or not (self.root / "stage.json").exists():
            raise ValueError("l4:start_once_after_stage")
        self.log = (self.root / "bootstrap.log").open("ab")
        self.child = subprocess.Popen(
            [
                "sh",
                "scripts/l4_compat_bootstrap.sh",
                str(self.repo),
                str(self.output),
                str(self.origin),
            ],
            cwd=self.repo,
            env={
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                "HOME": "/root",
                "LANG": "C.UTF-8",
            },
            stdout=self.log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        return self.status()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--token", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--deadline", type=float, required=True)
    parser.add_argument("--origin", type=float, required=True)
    args = parser.parse_args()
    host = L4Host(
        "/opt/dec077",
        args.token,
        args.manifest_sha256,
        args.deadline,
        origin=args.origin,
    )

    def watchdog():
        while time.time() < host.deadline:
            time.sleep(min(1, max(0, host.deadline - time.time())))
        with host.lock:
            host.cancel()

    threading.Thread(target=watchdog, daemon=True).start()
    print("l4:service starting loopback HTTP server and deadline watchdog", flush=True)
    server(host).serve_forever()


if __name__ == "__main__":
    main()
