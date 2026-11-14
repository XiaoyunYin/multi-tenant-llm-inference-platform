"""Read-only node clock/cache witness, running before vLLM Pod creation.

The HTTP interface cannot execute caller-supplied commands or read arbitrary
paths. CRI access is restricted in code to ListImages via a hash-pinned crictl.
"""

import hashlib
import http.server
import json
import os
import re
import sqlite3
import subprocess
import time
from pathlib import Path, PurePosixPath
from urllib.parse import parse_qs, urlsplit

MODEL_REPO = "models--Qwen--Qwen2.5-7B-Instruct"
REVISION = "a09a35458c702b33eeacc393d103063234e8bc28"


def file_hash(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        while chunk := stream.read(1_048_576):
            digest.update(chunk)
        after = os.fstat(stream.fileno())
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise ValueError("cache_file_changed_during_observation")
    return digest.hexdigest(), after.st_size


def model_cache(root, manifest):
    """Partial/escaped/mismatched caches are unknown, never relabelled cold."""
    repo = root / MODEL_REPO
    if not repo.exists() or not any(repo.iterdir()):
        return "cold", {}
    snapshot = repo / "snapshots" / REVISION
    proofs = {}
    for name, expected in manifest.items():
        relative = PurePosixPath(name)
        if (
            relative.is_absolute()
            or not relative.parts
            or ".." in relative.parts
            or "\\" in name
        ):
            raise ValueError("invalid_model_manifest_path")
        path = snapshot.joinpath(*relative.parts)
        if not path.resolve().is_relative_to(root.resolve()) or not path.is_file():
            return None, proofs
        digest, size = file_hash(path)
        proofs[name] = {"sha256": digest, "bytes": size}
        if proofs[name] != expected:
            return None, proofs
    return "node_cached", proofs


class Observer:
    def __init__(
        self,
        *,
        root,
        manifest,
        manifest_sha256,
        image,
        crictl,
        crictl_sha256,
        lifecycle_root=None,
        node,
        boot,
        runner=subprocess.run,
    ):
        if hashlib.sha256(manifest).hexdigest() != manifest_sha256:
            raise ValueError("model_manifest_pin_mismatch")
        self.manifest = json.loads(manifest)
        if not isinstance(self.manifest, dict) or not self.manifest:
            raise ValueError("complete_model_manifest_required")
        for expected in self.manifest.values():
            if (
                set(expected) != {"sha256", "bytes"}
                or type(expected["bytes"]) is not int
                or expected["bytes"] < 0
                or not isinstance(expected["sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", expected["sha256"])
            ):
                raise ValueError("invalid_model_manifest")
        if file_hash(crictl)[0] != crictl_sha256:
            raise ValueError("crictl_pin_mismatch")
        self.root, self.image, self.crictl = root, image, crictl
        self.lifecycle_root = lifecycle_root
        self.node, self.boot, self.runner = node, boot, runner

    def snapshot(self):
        start = time.monotonic_ns()
        result = self.runner(
            [
                str(self.crictl),
                "--runtime-endpoint",
                "unix:///run/containerd/containerd.sock",
                "images",
                "--output",
                "json",
            ],
            check=True,
            capture_output=True,
            timeout=5,
        )
        if len(result.stdout) > 8_388_608:
            raise ValueError("cri_inventory_oversize")
        inventory = json.loads(result.stdout)
        if not isinstance(inventory.get("images"), list):
            raise ValueError("incomplete_cri_inventory")
        cached = any(
            self.image in image.get("repoDigests", []) for image in inventory["images"]
        )
        state, proofs = model_cache(self.root, self.manifest)
        return {
            "schema": "m5-node-cache-v1",
            "node": self.node,
            "boot_id": self.boot,
            "start_ns": start,
            "end_ns": time.monotonic_ns(),
            "complete": True,
            "image": self.image,
            "image_cache_state": "node_cached" if cached else "cold",
            "model_cache_state": state,
            "model_proofs": proofs,
            "cri_inventory": inventory,
        }

    def handler(self):
        observer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                try:
                    target = urlsplit(self.path)
                    if target.path == "/clock":
                        value = {
                            "boot_id": observer.boot,
                            "mono_ns": time.monotonic_ns(),
                            "wall_ns": time.time_ns(),
                        }
                    elif target.path == "/snapshot":
                        value = observer.snapshot()
                    elif target.path.startswith("/native/") and target.path.endswith(
                        "/events"
                    ):
                        value = observer.native(
                            target.path[len("/native/") : -len("/events")],
                            parse_qs(target.query),
                        )
                    elif target.path.startswith("/lifecycle/") and target.path.endswith(
                        "/origin"
                    ):
                        uid = target.path[len("/lifecycle/") : -len("/origin")].rstrip(
                            "/"
                        )
                        observer.lifecycle(
                            uid, {"offset": ["0"]}
                        )  # Same fixed-path/UID validation.
                        value = json.loads(
                            (
                                observer.lifecycle_root / uid / "supervisor-origin.json"
                            ).read_bytes()
                        )
                    elif target.path.startswith("/lifecycle/") and target.path.endswith(
                        "/events"
                    ):
                        uid = target.path[len("/lifecycle/") : -len("/events")].rstrip(
                            "/"
                        )
                        boot, offset, data = observer.lifecycle(
                            uid, parse_qs(target.query)
                        )
                        self.send_response(200)
                        self.send_header("Content-Type", "application/x-ndjson")
                        self.send_header("Content-Length", str(len(data)))
                        self.send_header("X-Capture-Boot", boot)
                        self.send_header("X-Capture-Next", str(offset + len(data)))
                        self.end_headers()
                        self.wfile.write(data)
                        return
                    else:
                        self.send_error(404)
                        return
                    data = json.dumps(value, sort_keys=True).encode()
                    if len(data) > 8_388_608:
                        raise ValueError("node_response_oversize")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                except (
                    OSError,
                    ValueError,
                    TypeError,
                    KeyError,
                    AttributeError,
                    subprocess.SubprocessError,
                    ImportError,
                    sqlite3.Error,
                ):
                    self.send_error(503, "node_observation_unavailable")

        return Handler

    def native(self, uid, query):
        if (
            self.lifecycle_root is None
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,127}", uid)
            or ".." in uid
        ):
            raise ValueError("invalid_native_spool_identity")
        if set(query) != {"after"} or len(query["after"]) != 1:
            raise ValueError("invalid_native_spool_query")
        directory = self.lifecycle_root / uid / "native"
        if (
            directory.is_symlink()
            or (self.lifecycle_root / uid).is_symlink()
            or not directory.resolve(strict=True).is_relative_to(
                self.lifecycle_root.resolve(strict=True)
            )
        ):
            raise ValueError("invalid_native_spool_identity")
        if any(
            (directory / name).is_symlink()
            for name in ("events.sqlite", "events.sqlite-wal", "events.sqlite-shm")
        ):
            raise ValueError("invalid_native_spool_identity")
        from native_source import read_events

        value = read_events(directory, int(query["after"][0]))
        if (
            value["origin"]["pod_uid"] != uid
            or value["origin"]["node"] != self.node
            or value["origin"]["node_boot_id"] != self.boot
        ):
            raise ValueError("native_spool_origin_mismatch")
        return value

    def lifecycle(self, uid, query):
        if (
            self.lifecycle_root is None
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,127}", uid)
            or ".." in uid
        ):
            raise ValueError("invalid_lifecycle_spool_identity")
        offset_values = query.get("offset", ["0"])
        if set(query) - {"offset"} or len(offset_values) != 1:
            raise ValueError("invalid_lifecycle_spool_query")
        offset = int(offset_values[0])
        if offset < 0:
            raise ValueError("invalid_lifecycle_spool_offset")
        root = self.lifecycle_root.resolve(strict=True)
        directory = self.lifecycle_root / uid
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError("lifecycle_spool_unavailable")
        resolved = directory.resolve(strict=True)
        if not resolved.is_relative_to(root):
            raise ValueError("lifecycle_spool_path_escape")
        origin_path = directory / "supervisor-origin.json"
        stream_path = directory / "lifecycle.jsonl"
        if (
            origin_path.is_symlink()
            or stream_path.is_symlink()
            or not stream_path.is_file()
        ):
            raise ValueError("lifecycle_spool_unavailable")
        origin = json.loads(origin_path.read_bytes())
        if (
            origin.get("pod_uid") != uid
            or not isinstance(origin.get("boot_id"), str)
            or not origin["boot_id"]
        ):
            raise ValueError("lifecycle_spool_origin_mismatch")
        with stream_path.open("rb") as stream:
            size = os.fstat(stream.fileno()).st_size
            if offset > size:
                raise ValueError("lifecycle_spool_truncated")
            if offset:
                stream.seek(offset - 1)
                if stream.read(1) != b"\n":
                    raise ValueError("lifecycle_spool_unaligned")
            stream.seek(offset)
            raw = stream.read(1_048_576)
        end = raw.rfind(b"\n") + 1
        if end == 0 and raw:
            raise ValueError("lifecycle_spool_line_oversize")
        return origin["boot_id"], offset, raw[:end]


def main():
    observer = Observer(
        root=Path("/models"),
        manifest=Path("/model-manifest/manifest.json").read_bytes(),
        manifest_sha256=os.environ["MODEL_MANIFEST_SHA256"],
        image=os.environ["EXPECTED_IMAGE"],
        crictl=Path("/tools/crictl"),
        crictl_sha256=os.environ["CRICTL_SHA256"],
        lifecycle_root=Path("/lifecycle"),
        node=os.environ["NODE_NAME"],
        boot=Path("/node-boot-id").read_text().strip(),
    )
    http.server.ThreadingHTTPServer(
        ("0.0.0.0", 9102), observer.handler()
    ).serve_forever()


if __name__ == "__main__":
    main()
