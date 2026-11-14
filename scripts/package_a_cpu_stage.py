"""Run one CPU test stage in a disposable writable source copy."""

import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

# This script starts from /source before /repo/tree exists. The read-only source
# checkout must supply its pins without relying on the host venv's editable path.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "python/src"))
from inference_platform.stage_c_tokenizer import FILE_HASHES, REVISION  # noqa: E402


def input_facts(path):
    files = sorted(path.rglob("*")) if path.is_dir() else [path]
    rows = []
    for file in files:
        if file.is_file():
            with file.open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            rows.append(
                {
                    "path": file.relative_to(path).as_posix()
                    if path.is_dir()
                    else file.name,
                    "bytes": file.stat().st_size,
                    "sha256": digest,
                }
            )
    return {
        "sha256": hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest(),
        "files": rows,
    }


def declared_inputs(source, module_cache):
    tokenizer = source / ".cache/pinned-tokenizer" / REVISION
    inputs = [
        ("module_cache", module_cache, ".cache/go-mod"),
        ("tools", source / ".tools", ".tools"),
        ("gateway", source / ".cache/kind-build/gateway", ".cache/kind-build/gateway"),
        ("tokenizer", tokenizer, ".cache/pinned-tokenizer/" + REVISION),
    ]
    for name, path, _ in inputs:
        if not path.exists() or (path.is_dir() and not any(path.iterdir())):
            raise ValueError("cpu_stage:input_missing:" + name)
    for name in ("kind", "kubectl"):
        if not any(
            (source / ".tools" / (name + suffix)).is_file() for suffix in ("", ".exe")
        ):
            raise ValueError("cpu_stage:input_missing:tools:" + name)
    for name, expected in FILE_HASHES.items():
        path = tokenizer / name
        if not path.is_file():
            raise ValueError("cpu_stage:input_missing:tokenizer:" + name)
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError("cpu_stage:input_hash:tokenizer:" + name)
    return [
        {"name": name, "source": path, "destination": relative, **input_facts(path)}
        for name, path, relative in inputs
    ]


def descriptor_limits():
    try:
        import resource
    except ImportError:
        return {
            "soft": None,
            "hard": None,
            "source": "RLIMIT_NOFILE unavailable on Windows",
        }
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    return {"soft": soft, "hard": hard, "source": "RLIMIT_NOFILE (ulimit -Sn / -Hn)"}


def remove_readonly(function, path, error):
    if os.name != "nt" or not isinstance(error, PermissionError):
        raise error
    os.chmod(path, stat.S_IWRITE)
    function(path)


def tracked(root):
    names = (
        subprocess.check_output(["git", "-C", str(root), "ls-files", "-z"])
        .decode()
        .split("\0")
    )
    return {
        name: hashlib.sha256((root / name).read_bytes()).hexdigest()
        if (root / name).is_file()
        else None
        for name in names
        if name
    }


def changed(root, expected):
    current = tracked(root)
    return sorted(
        name
        for name in set(expected) | set(current)
        if current.get(name) != expected.get(name)
    )


def run_stage(source, work, module_cache, argv):
    source, work, module_cache = map(Path, (source, work, module_cache))
    inputs = declared_inputs(source, module_cache)
    expected = tracked(source)
    work.mkdir(parents=True, exist_ok=False)
    env = dict(
        os.environ,
        PYTHONPATH=os.pathsep.join(
            str(work / p) for p in (".", "scripts", "python/src", "python/tests")
        )
        + os.pathsep
        + "/locked-site",
        GOMODCACHE=str(work / ".cache/go-mod"),
        GOCACHE=str(work / ".cache/go-build"),
        GOPROXY="off",
        GOSUMDB="off",
        GOTOOLCHAIN="local",
        M5_PACKAGE_A_BIN=str(work / ".cache/kind-build/gateway"),
        INF011_TOKENIZER_CACHE=str(work / ".cache/pinned-tokenizer"),
    )
    try:
        for name in expected:
            target = work / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source / name, target)
        shutil.copytree(source / ".git", work / ".git")
        for row in inputs:
            target = work / row["destination"]
            target.parent.mkdir(parents=True, exist_ok=True)
            if row["source"].is_dir():
                shutil.copytree(row["source"], target)
            else:
                shutil.copy2(row["source"], target)
            if input_facts(target)["sha256"] != row["sha256"]:
                raise ValueError("cpu_stage:input_hash:" + row["name"])
        print(
            json.dumps(
                {
                    "cpu_stage_copy": {
                        "tracked_files": len(expected),
                        "go_network": "disabled",
                        "descriptor_limits": descriptor_limits(),
                        "ignored_inputs": [
                            dict(row, source=str(row["source"])) for row in inputs
                        ],
                    }
                }
            ),
            flush=True,
        )
        code = subprocess.call(argv, cwd=work, env=env)
        dirty = changed(work, expected)
        original_dirty = changed(source, expected)
        receipt = {
            "complete": not dirty and not original_dirty,
            "changed_tracked_files": dirty,
            "changed_original_files": original_dirty,
            "go_network": "disabled",
        }
        print(json.dumps({"cpu_stage_integrity": receipt}), flush=True)
        return code if receipt["complete"] else 1
    finally:
        shutil.rmtree(work, onexc=remove_readonly)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", type=Path, required=True)
    p.add_argument("--work", type=Path, required=True)
    p.add_argument("--module-cache", type=Path, required=True)
    p.add_argument("command", nargs=argparse.REMAINDER)
    a = p.parse_args()
    return run_stage(a.source, a.work, a.module_cache, a.command)


if __name__ == "__main__":
    raise SystemExit(main())
