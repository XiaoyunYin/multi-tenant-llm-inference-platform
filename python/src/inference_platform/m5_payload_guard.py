"""Fail closed when descriptive host Python reads an unshipped source root."""

import os
import sys
from pathlib import Path


def install_read_guard(root, paths):
    root = Path(root).resolve()
    allowed = set(paths) | {".git", ".cache", ".tools", ".venv"}
    enabled = True

    def audit(event, arguments):
        if not enabled or event not in {"open", "os.listdir", "os.scandir"}:
            return
        name = arguments[0]
        if not isinstance(name, (str, bytes, os.PathLike)):
            return
        path = Path(os.path.abspath(os.fsdecode(name)))
        try:
            relative = path.relative_to(root)
        except ValueError:
            return
        if relative.parts and relative.parts[0] not in allowed:
            raise ValueError("descriptive:payload_unlisted_read:" + relative.parts[0])

    sys.addaudithook(audit)

    def deactivate():
        nonlocal enabled
        enabled = False

    return deactivate
