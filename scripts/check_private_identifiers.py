"""Check tracked private-repository files for R1 account identifiers."""

import argparse
from pathlib import Path

from inference_platform.private_identifier_scan import check_repo, check_staged_repo


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument(
        "--staged",
        action="store_true",
        help="scan the complete Git index tree instead of tracked worktree files",
    )
    args = parser.parse_args()
    try:
        tracked, findings = (
            check_staged_repo(args.root) if args.staged else check_repo(args.root)
        )
    except (OSError, ValueError) as exc:
        parser.exit(1, f"Private identifier scan failed: {exc}\n")
    if findings:
        parser.exit(1, "Private identifier scan failed:\n" + "\n".join(findings) + "\n")
    print(f"Private identifier scan passed: {tracked} tracked files, zero findings")


if __name__ == "__main__":
    main()
