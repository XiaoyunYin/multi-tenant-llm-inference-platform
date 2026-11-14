"""Inside the pinned vLLM image: stage the exact HF cache and verify upstream hashes.

No engine, GPU allocation, overlay or serving occurs in this preparation Pod.
"""

import hashlib
import json
import time
from pathlib import Path


def stage(model, revision, cache, output):
    from huggingface_hub import HfApi, snapshot_download

    info = HfApi().model_info(model, revision=revision, files_metadata=True)
    if info.sha != revision:
        raise ValueError("descriptive:model_revision")
    selected = [
        f
        for f in info.siblings
        if f.rfilename.endswith((".json", ".safetensors", ".txt", ".jinja"))
    ]
    snapshot = Path(
        snapshot_download(
            model,
            revision=revision,
            cache_dir=cache,
            allow_patterns=[f.rfilename for f in selected],
        )
    )
    manifest = {}
    for entry in selected:
        path = snapshot / entry.rfilename
        size = path.stat().st_size
        digest = hashlib.sha256()
        blob = hashlib.sha1(b"blob " + str(size).encode() + b"\0")
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
                blob.update(chunk)
        if entry.lfs:
            valid = digest.hexdigest() == entry.lfs.sha256
        else:
            valid = blob.hexdigest() == entry.blob_id
        if not valid:
            raise ValueError("descriptive:model_hash")
        manifest[entry.rfilename] = {"bytes": size, "sha256": digest.hexdigest()}
    if not any(name.endswith(".safetensors") for name in manifest):
        raise ValueError("descriptive:model_weights")
    Path(output).write_text(
        json.dumps(
            {"model": model, "revision": revision, "files": manifest}, sort_keys=True
        )
    )
    return manifest


if __name__ == "__main__":
    import sys

    stage(*sys.argv[1:])
    Path("/evidence/ready").touch()
    # Hold for bounded control/retrieval; Pod activeDeadlineSeconds is absolute.
    while True:
        time.sleep(1)
