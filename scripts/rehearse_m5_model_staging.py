"""Routine CPU host: exact model hash staging in the pinned vLLM image, no GPU.

Run before other Docker suites on a fresh DEC-099 host. Weights and download
caches are temporary inputs and never enter the frozen receipt archive.
"""

import argparse
import json
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path

from inference_platform.eks_deployment import MODEL, REVISION, VLLM_IMAGE
from inference_platform.m5_descriptive_operator import file_digest


def run(output):
    output = Path(output)
    root = Path(__file__).resolve().parents[1]
    name = "descriptive-model-" + uuid.uuid4().hex
    existing = (
        subprocess.run(
            ["docker", "image", "inspect", VLLM_IMAGE], capture_output=True
        ).returncode
        == 0
    )
    receipt = {
        "image": VLLM_IMAGE,
        "model": MODEL,
        "revision": REVISION,
        "gpu": False,
        "source_sha256": file_digest(root / "scripts/m5_descriptive_model.py"),
        "initial_free_disk_bytes": shutil.disk_usage("/").free,
    }
    try:
        subprocess.run(["docker", "pull", VLLM_IMAGE], check=True, timeout=1200)
        with tempfile.TemporaryDirectory(prefix="descriptive-model-") as temporary:
            directory = Path(temporary)
            for folder in ("cache", "evidence"):
                (directory / folder).mkdir()
            expression = (
                "import runpy; stage=runpy.run_path('/stage.py')['stage']; stage("
                + repr(MODEL)
                + ","
                + repr(REVISION)
                + ",'/cache/hub','/evidence/manifest.json')"
            )
            subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--name",
                    name,
                    "--entrypoint",
                    "python3",
                    "-e",
                    "PYTHONDONTWRITEBYTECODE=1",
                    "-e",
                    "HF_HOME=/cache/home",
                    "-e",
                    "HF_XET_CACHE=/cache/xet",
                    "--mount",
                    f"type=bind,source={root / 'scripts/m5_descriptive_model.py'},target=/stage.py,readonly",
                    "--mount",
                    f"type=bind,source={directory / 'cache'},target=/cache",
                    "--mount",
                    f"type=bind,source={directory / 'evidence'},target=/evidence",
                    VLLM_IMAGE,
                    "-c",
                    expression,
                ],
                check=True,
                timeout=1800,
            )
            manifest = json.loads((directory / "evidence/manifest.json").read_bytes())
            receipt.update(
                complete=True,
                files=manifest["files"],
                total_bytes=sum(f["bytes"] for f in manifest["files"].values()),
            )
    finally:
        subprocess.run(["docker", "rm", "-fv", name], capture_output=True, timeout=60)
        if not existing:
            removed = subprocess.run(
                ["docker", "image", "rm", VLLM_IMAGE], capture_output=True, timeout=120
            )
            receipt["owned_image_removed"] = removed.returncode == 0
            if removed.returncode:
                receipt["complete"] = False
        output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    if receipt.get("complete") is not True:
        raise ValueError("descriptive:model_staging_rehearsal_incomplete")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    run(parser.parse_args().output)
