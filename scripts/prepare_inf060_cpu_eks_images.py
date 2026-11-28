"""Export the exact kind rehearsal images on a DEC-099 Linux host."""

import argparse
import json
import subprocess
import tempfile
from pathlib import Path

from inference_platform.kind_rollout import Campaign
from inf060_eks_cpu_plan import (
    IMAGE_ARCHIVE,
    IMAGE_TAGS,
    archive_image_bindings,
    digest,
)


def export_images(output):
    save = ["docker", "image", "save", *IMAGE_TAGS.values()]
    archive = output / IMAGE_ARCHIVE
    with (
        archive.open("xb") as stream,
        subprocess.Popen(save, stdout=subprocess.PIPE) as child,
    ):
        try:
            subprocess.run(
                ["gzip", "-n", "-1"],
                stdin=child.stdout,
                stdout=stream,
                check=True,
                timeout=600,
            )
            if child.wait(timeout=5):
                raise ValueError("cpu_clock:docker_save")
        finally:
            if child.poll() is None:
                child.kill()
    receipt = {
        "source": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], text=True
        ).strip(),
        "images": archive_image_bindings(archive),
        "operator_ami": json.loads(Path("/opt/dec077/runtime.json").read_bytes())[
            "ami"
        ],
        "archive": {"bytes": archive.stat().st_size, "sha256": digest(archive)},
    }
    (output / "images.json").write_text(
        json.dumps(receipt, indent=2) + "\n", encoding="utf-8"
    )
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--inf054-tape", action="store_true")
    args = parser.parse_args()
    output = args.output
    output.mkdir()
    campaign = Campaign(output)
    campaign.build()
    export_images(output)

    if args.inf054_tape:
        from inf054_cpu_helm import build_tape_input
        from inf063_chart import chart_checks, install_helm

        with tempfile.TemporaryDirectory(prefix="inf054-helm-") as tools:
            checks = chart_checks(install_helm(Path(tools)))
        (output / "helm-checks.json").write_text(
            json.dumps(checks) + "\n", encoding="utf-8"
        )
        build_tape_input(output)


if __name__ == "__main__":
    main()
