"""Export the exact kind rehearsal images on a DEC-099 Linux host."""

import argparse
import json
import subprocess
from pathlib import Path

from inference_platform.kind_rollout import Campaign
from inf060_eks_cpu_plan import (
    IMAGE_ARCHIVE,
    IMAGE_TAGS,
    archive_image_bindings,
    digest,
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output
    output.mkdir()
    campaign = Campaign(output)
    campaign.build()
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


if __name__ == "__main__":
    main()
