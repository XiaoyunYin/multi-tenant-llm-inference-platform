"""Explicit environmental prerequisites for historical/wrapper test bodies."""

import os
import shutil
import subprocess
import unittest


def require_history(root, commit):
    result = subprocess.run(
        ["git", "cat-file", "-e", commit],
        cwd=root,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if result.returncode:
        shallow = subprocess.run(
            ["git", "rev-parse", "--is-shallow-repository"],
            cwd=root,
            capture_output=True,
            text=True,
            check=True,
        )
        if result.returncode == 1 and shallow.stdout.strip() == "true":
            raise unittest.SkipTest("shallow_source_bundle_lacks_pinned_history: " + commit)
        raise subprocess.CalledProcessError(result.returncode, result.args)


def require_powershell():
    executable = shutil.which("powershell") or shutil.which("pwsh")
    if executable is None:
        if os.name != "nt":
            raise unittest.SkipTest("non_windows_powershell_wrapper_unavailable")
        raise RuntimeError("PowerShell is required for the wrapper preflight tests")
    return executable
