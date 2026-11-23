"""Measure the native probe's network and CPU staging on a routine CPU host."""

import argparse
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

import inf060_probe_spec as spec
from prepare_inf060_probe import ROOT, git, historical


def verify_model_readback(readback, model):
    # The historical manifest also carries Git provenance. The stage reports
    # the observed file sizes and contents of the complete pinned file set.
    expected = {
        name: {key: value[key] for key in ("bytes", "sha256")}
        for name, value in model["files"].items()
    }
    spec.check(
        readback["revision"] == model["revision"] == spec.REVISION
        and readback["files"] == expected
        and readback["tokens"] == 1024,
        "timing_model_digest",
    )


def audit(output):
    source = git("rev-parse", "HEAD").decode().strip()
    model, weight_bytes, source_floor, weight_floor, _ = historical(source)
    stage_limit = spec.transfer(weight_bytes, weight_floor)
    result = {
        "source_commit": source,
        "instance_type": "m6i.2xlarge",
        "region": spec.REGION,
        "image": spec.VLLM_IMAGE,
        "model": spec.MODEL,
        "revision": spec.REVISION,
        "model_bytes": weight_bytes,
        "source_floor_bytes_s": source_floor,
        "gpu_requested": False,
        "stages": {},
    }
    spec.save(output, result)

    def command(name, argv, observe_s, production_limit_s):
        epoch, start = time.time(), time.monotonic()
        try:
            proc = subprocess.run(
                argv, capture_output=True, timeout=observe_s, check=False
            )
            code = proc.returncode
        except subprocess.TimeoutExpired:
            proc, code = None, None
        elapsed = time.monotonic() - start
        result["stages"][name] = {
            "start_epoch": epoch,
            "elapsed_s": elapsed,
            "exit_code": code,
            "observation_limit_s": observe_s,
            "production_limit_s": production_limit_s,
            "margin_s": production_limit_s - elapsed,
        }
        spec.save(output, result)
        return proc

    prior = subprocess.run(
        ["docker", "image", "inspect", spec.VLLM_IMAGE], capture_output=True
    )
    result["cold_image"] = prior.returncode != 0
    result["docker_free_bytes"] = shutil.disk_usage("/var/lib/docker").free
    spec.check(
        result["cold_image"] and result["docker_free_bytes"] >= 50 * 1024**3,
        "timing_cold_disk",
    )
    pull = command("docker_pull", ["docker", "pull", spec.VLLM_IMAGE], 1500, 600)
    spec.check(pull is not None and pull.returncode == 0, "timing_image_pull")
    installed = subprocess.check_output(
        [
            "docker",
            "image",
            "inspect",
            "--format",
            "{{json .RepoDigests}}",
            spec.VLLM_IMAGE,
        ],
        text=True,
    )
    spec.check(spec.VLLM_IMAGE.rsplit("@", 1)[1] in installed, "timing_image_digest")
    with tempfile.TemporaryDirectory(prefix="inf060-timing-") as temp:
        base = Path(temp)
        packet, private, weights = (
            base / key for key in ("packet", "private", "model")
        )
        for folder in (packet / "scripts", private, weights):
            folder.mkdir(parents=True)
        for name in ("inf060_probe_engine.py", "inf060_probe_spec.py"):
            shutil.copyfile(ROOT / "scripts" / name, packet / "scripts" / name)
        spec.save(packet / "model.json", model)
        spec.save(packet / "requests.json", spec.request_manifest())
        name = "inf060-timing-model-stage"
        started = command(
            "stage_container_start",
            [
                "docker",
                "run",
                "-d",
                "--network=host",
                "--name",
                name,
                "-v",
                f"{packet}:/packet:ro",
                "-v",
                f"{private}:/private:rw",
                "-v",
                f"{weights}:/model:rw",
                "--entrypoint",
                spec.IMAGE_PYTHON,
                spec.VLLM_IMAGE,
                "/packet/scripts/inf060_probe_engine.py",
                "stage",
            ],
            60,
            60,
        )
        spec.check(
            started is not None and started.returncode == 0, "timing_model_stage_start"
        )
        try:
            waited = command("stage_wait", ["docker", "wait", name], 1500, stage_limit)
            exit_code = (
                int(waited.stdout.strip())
                if waited is not None and waited.returncode == 0
                else None
            )
            result["stages"]["stage_wait"]["container_exit_code"] = exit_code
            spec.save(output, result)
            spec.check(exit_code == 0, "timing_model_stage")
            readback = spec.load(private / "model-readback.json")
            verify_model_readback(readback, model)
            result["model_readback"] = {
                "verified_files": len(readback["files"]),
                "rendered_input_tokens": readback["tokens"],
            }
        finally:
            subprocess.run(
                ["docker", "rm", "-f", "-v", name],
                capture_output=True,
                timeout=25,
                check=True,
            )
    result["complete"] = True
    spec.save(output, result)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    audit(parser.parse_args().output)
