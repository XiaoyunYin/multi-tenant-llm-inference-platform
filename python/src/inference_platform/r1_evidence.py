"""Immutable incremental evidence segments; final export contains only remaining tails."""

import hashlib
import io
import json
import tarfile
import threading
from pathlib import Path

from .r1_spec import encoded


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Spool:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.segments = self.directory / "segments"
        self.segments.mkdir(exist_ok=True)
        self.offsets, self.inventory = {}, []
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.error = None
        self.thread = threading.Thread(target=self.loop, daemon=True, name="r1-evidence-spool")

    def loop(self):
        try:
            while not self.stop.wait(5):
                self.capture()
        except Exception as exc:
            self.error = str(exc)

    def paths(self, final):
        for base in ("session", "logs"):
            folder = self.directory / base
            if folder.exists():
                for path in sorted(folder.rglob("*")):
                    if not path.is_file() or path.name == "service-export.json":
                        continue  # Rebuilt locally from service logs, shipped exactly once.
                    if (
                        final
                        or path.suffix == ".jsonl"
                        or (
                            base == "session"
                            and path.suffix == ".json"
                            and path.name.startswith(
                                ("run", "staircase", "candidate", "calibration-corpus")
                            )
                        )
                    ):
                        yield path
        if final:
            for name in (
                "agent.log",
                "disk-before-pull.json",
                "physical-export-probe.json",
                "service_agent-resources.json",
                "generator_agent-resources.json",
                "cloud-init-status.json",
            ):
                path = self.directory / name
                if path.exists():
                    yield path

    def capture(self, final=False):
        with self.lock:
            pieces = []
            for path in self.paths(final):
                name = path.relative_to(self.directory).as_posix()
                offset = self.offsets.get(name, 0)
                # Phase JSON is written once; wait for complete valid JSON before sealing.
                if not final and path.suffix == ".json":
                    if offset:
                        continue
                    try:
                        json.loads(path.read_bytes())
                    except (ValueError, OSError):
                        continue
                with path.open("rb") as stream:
                    stream.seek(offset)
                    while True:
                        data = stream.read(4 * 1024**2)
                        if not data:
                            break
                        if not final and path.suffix == ".jsonl":
                            data = data[: data.rfind(b"\n") + 1]
                            if not data:
                                break
                        pieces.append((name, offset, data))
                        offset += len(data)
                        stream.seek(offset)
                if pieces and sum(len(x[2]) for x in pieces) >= 8 * 1024**2:
                    self.seal(pieces)
                    pieces = []
            if pieces:
                self.seal(pieces)
            if final:
                (self.directory / "incremental-index.json").write_bytes(
                    encoded(
                        {
                            "segments": self.inventory,
                            "offsets": self.offsets,
                            "spool_error": self.error,
                        }
                    )
                )

    def seal(self, pieces):
        number = len(self.inventory)
        path = self.segments / f"{number:06d}.tar.gz"
        pending = path.with_suffix(".pending")
        metadata = [
            {"path": name, "offset": offset, "bytes": len(data), "sha256": sha(data)}
            for name, offset, data in pieces
        ]
        with tarfile.open(pending, "w:gz", compresslevel=1) as archive:
            for name, data in [
                ("pieces.json", encoded(metadata)),
                *[(str(i), item[2]) for i, item in enumerate(pieces)],
            ]:
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        pending.replace(path)
        for name, offset, data in pieces:
            self.offsets[name] = offset + len(data)
        self.inventory.append(
            {"name": path.name, "bytes": path.stat().st_size, "sha256": file_sha(path)}
        )

    def listing(self):
        with self.lock:
            return {"segments": list(self.inventory), "spool_error": self.error}


def file_sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for data in iter(lambda: stream.read(1048576), b""):
            digest.update(data)
    return digest.hexdigest()


def restore(segment, destination):
    """Replay-safe reconstruction: exact offsets, safe paths, hashes, no tar extraction."""
    with tarfile.open(segment, "r:gz") as archive:
        metadata = json.load(archive.extractfile("pieces.json"))
        for i, item in enumerate(metadata):
            relative = Path(item["path"])
            if (
                relative.is_absolute()
                or ".." in relative.parts
                or relative.parts[0]
                not in {
                    "session",
                    "logs",
                    "agent.log",
                    "disk-before-pull.json",
                    "physical-export-probe.json",
                    "service_agent-resources.json",
                    "generator_agent-resources.json",
                    "cloud-init-status.json",
                }
            ):
                raise ValueError("unsafe evidence path")
            data = archive.extractfile(str(i)).read()
            if len(data) != item["bytes"] or sha(data) != item["sha256"]:
                raise ValueError("evidence piece hash/length mismatch")
            path = destination / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            size = path.stat().st_size if path.exists() else 0
            offset = item["offset"]
            if size < offset:
                raise ValueError("evidence prefix missing")
            if size > offset:
                with path.open("rb") as stream:
                    stream.seek(offset)
                    existing = stream.read(len(data))
                    if existing != data[: len(existing)]:
                        raise ValueError("evidence replay differs")
                if len(existing) < len(data):
                    with path.open("ab") as stream:
                        stream.write(data[len(existing) :])
                continue
            with path.open("ab") as stream:
                stream.write(data)
