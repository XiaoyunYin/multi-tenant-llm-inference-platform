#!/usr/bin/env python3
"""Replay the production row5 post-capture path from a retained kind receipt."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "receipt_root", type=Path, help="extracted results/runner/row5-kind directory"
    )
    parser.add_argument(
        "--source-root",
        type=Path,
        default=ROOT,
        help="repository checkout whose production Python modules are imported",
    )
    args = parser.parse_args()
    source = (args.source_root.resolve() / "python" / "src").as_posix()
    sys.path.insert(0, source)

    from inference_platform.inf037b_archive import IntegrityError
    from inference_platform.inf037b_row5_replay import replay

    try:
        result = replay(args.receipt_root)
    except (IntegrityError, OSError, ValueError, KeyError) as exc:
        print(json.dumps({"status": "refused", "reason": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    if result["status"] == "limited_after_proofs":
        return 2
    if result["status"] == "passed_reconstructed":
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
