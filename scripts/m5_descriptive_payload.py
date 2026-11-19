"""Commit-preserving sparse Git pack for the descriptive host, not routine CI.

Keep every tree (cheap metadata), the sealed commit, and only host source blobs.
The host uses Git's sparse/promisor support; omitted history/evidence blobs are
never fetched. The existing HEAD, Python inventory and clean-worktree checks
therefore still run against the original commit.
"""

import ast
import json
import re
import subprocess
from pathlib import Path


ENTRYPOINTS = (
    "scripts/package_a_host.py",
    "scripts/package_a_bootstrap.sh",
    "scripts/m5_descriptive_remote.py",
    "scripts/rehearse_m5_descriptive.py",
    "python/src/inference_platform/package_a_cloud.py",
    "python/src/inference_platform/kind_rollout.py",
)
GENERATED = {".cache", ".tools", ".git", ".venv"}


def git(root, *args, **kwargs):
    return subprocess.check_output(["git", "-C", str(root), *args], **kwargs)


def source_paths(root):
    """Derive coarse path roots from host entrypoints/imports and shell inputs.

    Directories deliberately include all their files, so Python dependency and
    Docker/Go build discovery need no fragile per-file handwritten allowlist.
    Git's own ignore/attribute inputs are part of its clean-worktree contract.
    """
    root = Path(root)
    pending, seen, paths = list(ENTRYPOINTS), set(), {".gitignore", ".gitattributes"}
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        seen.add(name)
        text = (root / name).read_text(encoding="utf-8")
        paths.add(name.split("/")[0])
        if name.endswith(".sh"):
            for value in re.findall(r"(?:\$repo/|\./)([\w./-]+)", text):
                paths.add(value.split("/")[0])
            if "--project python" in text:
                paths.add("python")
            if "go mod download" in text:
                paths.update(("go.mod", "go.sum"))
            continue
        tree = ast.parse(text)
        for node in ast.walk(tree):
            if not isinstance(node, ast.BinOp) or not isinstance(node.op, ast.Div):
                continue
            left = ast.unparse(node.left)
            if left not in {"ROOT", "repo", "self.repo"}:
                continue
            right = node.right
            value = right.value if isinstance(right, ast.Constant) else None
            if isinstance(right, ast.JoinedStr) and right.values:
                first = right.values[0]
                value = first.value if isinstance(first, ast.Constant) else None
            if isinstance(value, str):
                part = value.split("/")[0]
                if part and part not in GENERATED:
                    paths.add(part)
        # Only module-level imports execute at import time. Other role branches
        # in the shared runner do not enlarge the descriptive runtime graph.
        for node in tree.body:
            if not isinstance(node, ast.ImportFrom):
                continue
            module = node.module or ""
            if node.level:
                module = "inference_platform." + module
            names = [module] + [module + "." + a.name for a in node.names]
            for imported in names:
                relative = "python/src/" + imported.replace(".", "/") + ".py"
                if (root / relative).is_file():
                    pending.append(relative)
                elif (root / (imported + ".py")).is_file():
                    pending.append(imported + ".py")
                elif (root / ("scripts/" + imported + ".py")).is_file():
                    pending.append("scripts/" + imported + ".py")
    return sorted(paths)


def validate_reads(root, included):
    missing = set(source_paths(root)) - set(included)
    if missing:
        raise ValueError(
            "descriptive:payload_unlisted_read:" + ",".join(sorted(missing))
        )


def produce(root, commit, destination):
    root, destination = Path(root), Path(destination).resolve()
    if git(root, "rev-parse", "HEAD").decode().strip() != commit:
        raise ValueError("descriptive:source_moved")
    paths = source_paths(root)
    identities = {
        path: git(root, "rev-parse", commit + ":" + path).decode().strip()
        for path in paths
    }
    # All tree objects let sparse checkout construct an honest full index.
    rows = git(root, "ls-tree", "-r", "-t", commit).decode().splitlines()
    objects = {commit, git(root, "rev-parse", commit + "^{tree}").decode().strip()}
    for row in rows:
        facts, name = row.split("\t", 1)
        _, kind, oid = facts.split()
        if kind == "tree" or any(name == p or name.startswith(p + "/") for p in paths):
            if kind not in {"tree", "blob"}:
                raise ValueError("descriptive:payload_object_type")
            objects.add(oid)
    argv = ["git", "-C", str(root), "pack-objects", "--stdout"]
    with destination.open("wb") as out:
        subprocess.run(
            argv,
            input=("\n".join(sorted(objects)) + "\n").encode(),
            stdout=out,
            check=True,
        )
    destination.with_suffix(".command.json").write_text(
        json.dumps({"argv": argv, "paths": paths}) + "\n"
    )
    return {
        "format": "git-pack-sparse-v1",
        "source_commit": commit,
        "paths": identities,
    }


def transfer_bound(size):
    if type(size) is not int or size <= 0:
        raise ValueError("descriptive:payload_size")
    return 2 * ((size + 100_000 - 1) // 100_000) + 60
