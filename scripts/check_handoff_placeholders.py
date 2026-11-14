"""Reject newly added unfilled uppercase handoff template lines."""

import argparse
import re
import subprocess
from pathlib import Path


def placeholders(text):
    return [
        line
        for line in text.splitlines()
        if re.fullmatch(r"\s*(?:[-*]\s+)?`?[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+`?\s*", line)
    ]


def check(root):
    diff = subprocess.check_output(
        [
            "git",
            "-C",
            str(root),
            "diff",
            "--cached",
            "--unified=0",
            "--",
            "REVIEW.md",
            "docs/BUILD_LOG.md",
        ]
    ).decode("utf-8")
    return placeholders(
        "\n".join(
            line[1:]
            for line in diff.splitlines()
            if line.startswith("+") and not line.startswith("+++")
        )
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staged", action="store_true", required=True)
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    args = parser.parse_args()
    findings = check(args.root)
    if findings:
        raise SystemExit("handoff:unfilled_placeholder:" + ",".join(findings))
    print("New handoff lines: no unfilled uppercase placeholders")


if __name__ == "__main__":
    main()
