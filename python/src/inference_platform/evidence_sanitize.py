"""Redact AWS account identifiers only where their syntax identifies an account."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

_ACCOUNT = "[account-redacted]"
_ARN = re.compile(r"(\barn:[a-z0-9-]+:[a-z0-9-]*:[a-z0-9-]*:)\d{12}(?=:)")
_FIELD_NAME = r"(?:Account|AccountId|account_id|recipientAccountId|ownerAccountId)"
_FIELD = re.compile(r'(["\']' + _FIELD_NAME + r'["\']\s*[:=]\s*["\'])\d{12}(?=["\'])', re.I)
_NUMBER_FIELD = re.compile(r'(["\']' + _FIELD_NAME + r'["\']\s*:\s*)\d{12}(?=\s*[,}])', re.I)
_OPTION = re.compile(r"(--account(?:-id)?(?:=|\s+)[\"']?)\d{12}(?=$|[\s\"'])")


def sanitize_accounts(text: str) -> str:
    text = _NUMBER_FIELD.sub(lambda match: match[1] + '"' + _ACCOUNT + '"', text)
    for pattern in (_ARN, _FIELD, _OPTION):
        text = pattern.sub(lambda match: match[1] + _ACCOUNT, text)
    return text


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.write_text(
        sanitize_accounts(args.source.read_text(encoding="utf-8")), encoding="utf-8", newline="\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
