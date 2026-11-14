"""Write once the reviewed published-driver + pre-P first-contact binding."""

import argparse
import json
import os
from pathlib import Path

from inference_platform.inf037b_driver import canonical, release_evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--refresh", type=Path, required=True)
    parser.add_argument("--first-contact", type=Path, required=True)
    parser.add_argument("--node-uid", required=True)
    parser.add_argument("--release-version", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    refresh = json.loads(args.refresh.read_bytes())
    value = release_evidence(
        json.loads(args.first_contact.read_bytes()),
        refresh.get("eks_gpu_driver"),
        node_uid=args.node_uid,
        image_release=args.release_version,
    )
    with args.output.open("xb") as stream:
        stream.write(canonical(value))
        stream.flush()
        os.fsync(stream.fileno())
    if os.name != "nt":
        fd = os.open(args.output.parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


if __name__ == "__main__":
    main()
