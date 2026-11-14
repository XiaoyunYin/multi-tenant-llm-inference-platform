"""4e input producer: report current capture bounds/gaps; no sizing or cloud run."""

import argparse
from pathlib import Path

from inference_platform.inf037b_archive import encode, sha, strict_json
from inference_platform.inf037b_capture_inventory import capture_envelope


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--bindings", type=Path, help="Explicit origins/nodes/generations_complete JSON"
    )
    args = parser.parse_args()
    bindings = strict_json(args.bindings.read_bytes()) if args.bindings else {}
    report = capture_envelope(**bindings)
    report["producer"] = {
        "path": "scripts/build_inf037b_capture_envelope.py",
        "source_lf_sha256": sha(Path(__file__).read_bytes().replace(b"\r\n", b"\n")),
    }
    args.output.write_bytes(encode(report))


if __name__ == "__main__":
    main()
