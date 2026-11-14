"""Inside the pinned GPU image: stage pinned weights or install verified overlay."""

import hashlib
import importlib.util
import json
import os
import shutil
import sys
from pathlib import Path

from inference_platform.inf037b_archive import encode, sha
from inference_platform.inf037b_native import BASE_FILES
from inference_platform.l4_compat import PINS, need

ROOT = Path("/packet")
EVIDENCE = Path("/evidence")


def stage():
    from huggingface_hub import HfApi, snapshot_download

    info = HfApi().model_info(
        PINS["model"], revision=PINS["revision"], files_metadata=True
    )
    need(info.sha == PINS["revision"], "model_revision")
    selected = [
        f
        for f in info.siblings
        if f.rfilename.endswith((".json", ".safetensors", ".txt", ".jinja"))
    ]
    snapshot_download(
        PINS["model"],
        revision=PINS["revision"],
        local_dir="/model",
        allow_patterns=[f.rfilename for f in selected],
    )
    files = {}
    for entry in selected:
        path = Path("/model") / entry.rfilename
        size = path.stat().st_size
        digest, blob = (
            hashlib.sha256(),
            hashlib.sha1(b"blob " + str(size).encode() + b"\0"),
        )
        with path.open("rb") as stream:
            while chunk := stream.read(1024**2):
                digest.update(chunk)
                blob.update(chunk)
        if entry.lfs:
            need(digest.hexdigest() == entry.lfs.sha256, "model_lfs_hash")
        else:
            need(blob.hexdigest() == entry.blob_id, "model_git_blob")
        files[entry.rfilename] = {
            "bytes": size,
            "sha256": digest.hexdigest(),
            "git_blob": entry.blob_id,
        }
    need(any(n.endswith(".safetensors") for n in files), "model_weights")
    (EVIDENCE / "model-manifest.json").write_bytes(
        encode({"revision": info.sha, "files": files})
    )


ENGINE_ENV = {"VLLM_WORKER_MULTIPROC_METHOD": "spawn"}


def engine_argv():
    return [
        "--model",
        "/model",
        "--served-model-name",
        PINS["model"],
        "--dtype",
        "bfloat16",
        "--max-model-len",
        "8192",
        "--gpu-memory-utilization",
        "0.90",
        "--host",
        "127.0.0.1",
        "--port",
        "8000",
    ]


def serve():
    root = Path(importlib.util.find_spec("vllm").origin).parent.parent
    manifest = json.loads((ROOT / "overlay/native-manifest.json").read_bytes())
    for name, expected in BASE_FILES.items():
        need(sha((root / name).read_bytes()) == expected, "image_base_sources")
        source = ROOT / "overlay" / name
        need(sha(source.read_bytes()) == manifest["files"][name], "overlay_sources")
        shutil.copyfile(source, root / name)
    # The full project's helper source must equal the manifest's frozen helper.
    from inference_platform import inf037b_native

    need(
        sha(Path(inf037b_native.__file__).read_bytes()) == manifest["helper_sha256"],
        "helper_pin",
    )
    os.environ.update(ENGINE_ENV)
    os.environ.update(
        CAPTURE_ROOT="/evidence/runtime",
        INF037B_NATIVE_ROOT="/evidence/runtime/native",
        INF037B_NATIVE_MANIFEST="/packet/overlay/native-manifest.json",
        POD_UID="single-l4-engine",
        NODE_NAME="single-l4-host",
        MODEL_SHA256=sha((EVIDENCE / "model-manifest.json").read_bytes()),
        RUNTIME_SHA256=PINS["vllm"].rsplit(":", 1)[1],
    )
    os.execv(
        sys.executable,
        [
            sys.executable,
            str(ROOT / "deploy/eks/capture_runtime.py"),
            *engine_argv(),
        ],
    )


if __name__ == "__main__":
    need(sys.argv[1] in ("stage", "serve"), "container_mode")
    stage() if sys.argv[1] == "stage" else serve()
