"""Pinned local scan. Raw matches stay ignored; exports contain metadata only.

No baseline, ignore file, inline allow comments, path exclusions, or size cap.
Git patches cover all refs and reflogs; every stored blob and commit/tag object
is also materialized for archive/decode scanning, including unreachable objects.
"""

import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone

IMAGE = "ghcr.io/gitleaks/gitleaks@sha256:691af3c7c5a48b16f187ce3446d5f194838f91238f27270ed36eef6359a574d9"
VERSION = "v8.30.0"
ROOT = Path(__file__).resolve().parents[1]


def git(*args, binary=False):
    return subprocess.check_output(
        ["git", *args], cwd=ROOT, text=not binary, encoding=None if binary else "utf-8"
    )


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def scanner(mode, source, cache, label, log_opts=None):
    raw = cache / (label + ".raw.json")
    args = [
        "docker",
        "run",
        "--rm",
        "--network=none",
        "--read-only",
        "--mount",
        f"type=bind,src={source},dst=/source,readonly",
        "--mount",
        f"type=bind,src={ROOT / 'security'},dst=/config,readonly",
        "--mount",
        f"type=bind,src={cache},dst=/output",
        "-e",
        "GIT_CONFIG_COUNT=1",
        "-e",
        "GIT_CONFIG_KEY_0=safe.directory",
        "-e",
        "GIT_CONFIG_VALUE_0=/source",
        IMAGE,
        mode,
        "/source",
        "--config=/config/inf052-gitleaks.toml",
        "--no-banner",
        "--no-color",
        "--log-level=info",
        "--ignore-gitleaks-allow",
        "--gitleaks-ignore-path=/config/no-ignore-file",
        # Archives are scanned exactly once in the complete object inventory.
        "--max-archive-depth=" + ("0" if mode == "git" else "3"),
        "--max-decode-depth=5",
        "--max-target-megabytes=0",
        "--report-format=json",
        f"--report-path=/output/{raw.name}",
        # Non-verbose logs show counts only. Match values are retained privately
        # for triage and are NEVER printed or exported by this script.
    ]
    if log_opts:
        args.append("--log-opts=" + log_opts)
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    (cache / (label + ".private.log")).write_bytes(result.stdout)
    if result.returncode not in (0, 1) or not raw.is_file():
        raise RuntimeError(f"{label} scanner failed; inspect ignored private log")
    records = json.loads(raw.read_text(encoding="utf-8")) or []
    if result.returncode == 1 and not records:
        raise RuntimeError(f"{label} returned failure without findings")
    log = result.stdout.decode("utf-8", errors="replace")
    if any(
        "ERR " in line
        or "FTL " in line
        or ("WRN " in line and "leaks found" not in line)
        for line in log.splitlines()
    ):
        raise RuntimeError(f"{label} has unexpected scanner diagnostics")
    write_json(
        cache / (label + ".completed.json"),
        {
            "exit_code": result.returncode,
            "raw_sha256": sha(raw),
            "log_sha256": sha(cache / (label + ".private.log")),
        },
    )
    print(
        f"{label}: {len(records)} candidate hits; exit {result.returncode}", flush=True
    )
    return records, result.returncode


def materialize(cache):
    refs = git("rev-list", "--objects", "--all", "--reflog").splitlines()
    paths = dict(line.split(" ", 1) for line in refs if " " in line)
    inventory = subprocess.run(
        [
            "git",
            "cat-file",
            "--batch-all-objects",
            "--batch-check=%(objectname) %(objecttype) %(objectsize)",
        ],
        text=True,
        encoding="utf-8",
        capture_output=True,
        cwd=ROOT,
        check=True,
    ).stdout.splitlines()
    objects = [
        (oid, kind, int(size))
        for oid, kind, size in (line.split() for line in inventory)
        if kind in ("blob", "commit", "tag")
    ]
    dest = cache / "blobs"
    dest.mkdir(exist_ok=True)
    mapping = {}
    total = 0
    for oid, kind, size in objects:
        original = (
            paths.get(oid, "unreachable-blob")
            if kind == "blob"
            else "git-" + kind + "-object"
        )
        # Hash-based names prevent traversal; suffixes preserve archive handling.
        suffix = "".join(Path(original).suffixes)
        if not re.fullmatch(r"(?:\.[A-Za-z0-9_-]{1,16})*", suffix):
            suffix = ""
        name = oid + suffix
        data = git("cat-file", kind, oid, binary=True)
        if not suffix:
            suffix = ".txt"
            if data.startswith(b"\x1f\x8b"):
                suffix = ".gz"
            elif data.startswith(b"\x28\xb5\x2f\xfd"):
                suffix = ".zst"
            elif data.startswith(b"PK\x03\x04"):
                suffix = ".zip"
            name = oid + suffix
        if len(data) != size:
            raise RuntimeError("Git blob size mismatch")
        (dest / name).write_bytes(data)
        mapping[name] = {
            "object_id": oid,
            "path": original,
            "bytes": size,
            "type": kind,
        }
        total += size
    write_json(cache / "blob-inventory.private.json", mapping)
    return dest, mapping, total


def snapshot(cache, covered_hashes=None):
    dest = cache / ("tracked-" + datetime.now(timezone.utc).strftime("%H%M%S-%f"))
    dest.mkdir(exist_ok=True)
    files = git("ls-files", "-z").split("\0")[:-1]
    # Include pending preparation files before their first commit.
    files += git("ls-files", "--others", "--exclude-standard", "-z").split("\0")[:-1]
    selected, covered = [], []
    for name in files:
        src = ROOT / name
        if src.is_file():
            digest = sha(src)
            if covered_hashes and digest in covered_hashes:
                covered.append({"path": name, "sha256": digest})
                continue
            target = dest / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, target)
            selected.append(name)
    write_json(cache / "working-covered.private.json", covered)
    return dest, selected, covered


def metadata(records, mode, mapping):
    rows = []
    for hit in records:
        path = hit["File"].removeprefix("/source/")
        obj = None
        if mode == "blobs":
            # Archive member paths follow the blob filename.
            name = next((x for x in mapping if path.startswith(x)), None)
            if name is None:
                raise RuntimeError("Unmapped scanner blob path")
            obj = mapping[name]["object_id"]
            path = mapping[name]["path"] + path[len(name) :]
        row = {
            "scan": mode,
            "rule": hit["RuleID"],
            "path": path,
            "commit": hit.get("Commit") or None,
            "object_id": obj,
            "line": hit["StartLine"],
            "end_line": hit["EndLine"],
            "column": hit["StartColumn"],
            "end_column": hit["EndColumn"],
        }
        if mode == "working":
            name = next((x for x in mapping if path.startswith(x)), None)
            if name is None:
                raise RuntimeError("Unmapped working file")
            row["file_sha256"] = mapping[name]["file_sha256"]
        row["id"] = hashlib.sha256(json.dumps(row, sort_keys=True).encode()).hexdigest()
        rows.append(row)
    return rows


def export(cache, output, rows, manifest):
    dispositions_path = ROOT / "security/inf052-dispositions.json"
    dispositions = (
        json.loads(dispositions_path.read_text(encoding="utf-8"))
        if dispositions_path.exists()
        else {}
    )
    definitions = dispositions.get("definitions", {})
    locations = dispositions.get("locations", {})
    for row in rows:
        family = locations.get(row["id"])
        decision = definitions.get(family) if family else None
        if decision and (
            decision.get("status")
            not in {"PUBLIC_FIXTURE", "NON_SECRET", "LOCAL_EPHEMERAL", "SENSITIVE"}
            or not decision.get("reason")
        ):
            raise RuntimeError("Invalid finding disposition")
        row["disposition"] = decision or {
            "status": "UNTRIAGED",
            "reason": "Requires private match/context inspection",
        }
    summary = Counter(row["disposition"]["status"] for row in rows)
    manifest["candidate_hits"] = len(rows)
    manifest["dispositions"] = dict(summary)
    manifest["dispositions_sha256"] = (
        sha(dispositions_path) if dispositions_path.exists() else None
    )
    manifest["disposition_families"] = dict(
        Counter(locations.get(row["id"], "UNTRIAGED") for row in rows)
    )
    manifest["scan_result"] = (
        "REVIEW_REQUIRED"
        if any(x in summary for x in ("UNTRIAGED", "SENSITIVE"))
        else "NO_UNRESOLVED_SENSITIVE_HITS"
    )
    manifest["publication_authorized"] = False
    write_json(output / "scan-manifest.json", manifest)
    output.mkdir(parents=True, exist_ok=True)
    with (output / "findings.sanitized.jsonl.gz").open("wb") as raw:
        with gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as stream:
            for row in rows:
                if row["id"] in locations:
                    row["disposition"] = locations[row["id"]]
                stream.write((json.dumps(row, sort_keys=True) + "\n").encode("utf-8"))
    checksums = "".join(
        f"{sha(output / f)}  {f}\n"
        for f in ["scan-manifest.json", "findings.sanitized.jsonl.gz"]
    )
    (output / "SHA256SUMS.txt").write_text(checksums, encoding="utf-8", newline="\n")
    print(
        f"Sanitized export: {len(rows)} candidates, {dict(summary)}; {manifest['scan_result']}",
        flush=True,
    )
    return 1 if manifest["scan_result"] == "REVIEW_REQUIRED" else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "docs/evidence/inf052-secret-scan-2026-10-02",
    )
    parser.add_argument(
        "--export-only",
        action="store_true",
        help="Reclassify saved scans; performs NO new scan",
    )
    parser.add_argument(
        "--resume-cache",
        type=Path,
        help="Reuse completed pinned history/object passes; scan working delta freshly",
    )
    args = parser.parse_args()
    latest = ROOT / ".cache/inf052/latest-scan.private.txt"
    if args.export_only:
        cache = Path(latest.read_text(encoding="utf-8"))
        if not cache.resolve().is_relative_to((ROOT / ".cache/inf052").resolve()):
            raise RuntimeError("Private scan cache escaped ignored directory")
    elif args.resume_cache:
        cache = args.resume_cache.resolve()
        if not cache.is_relative_to((ROOT / ".cache/inf052").resolve()):
            raise RuntimeError("Resume cache escaped ignored directory")
    else:
        cache = (
            ROOT
            / ".cache/inf052"
            / datetime.now(timezone.utc).strftime("scan-%Y%m%d-%H%M%S-%f")
        )
    cache.mkdir(parents=True, exist_ok=True)
    if args.export_only:
        rows = json.loads((cache / "metadata.private.json").read_text(encoding="utf-8"))
        manifest = json.loads(
            (cache / "manifest.private.json").read_text(encoding="utf-8")
        )
    else:
        version = subprocess.check_output(
            ["docker", "run", "--rm", "--network=none", IMAGE, "version"], text=True
        ).strip()
        if version != VERSION:
            raise RuntimeError("Unexpected scanner version")
        print(
            "Scanning all refs and reflogs with pinned Gitleaks " + version, flush=True
        )
        binding = {
            "image": IMAGE,
            "config_sha256": sha(ROOT / "security/inf052-gitleaks.toml"),
            "vendor_sha256": sha(ROOT / "security/gitleaks-v8.30.0.toml"),
            "source_head": git("rev-parse", "HEAD").strip(),
        }
        if args.resume_cache:
            if (
                json.loads(
                    (cache / "scan-binding.private.json").read_text(encoding="utf-8")
                )
                != binding
            ):
                raise RuntimeError("Resume pin/source binding mismatch")
            for label in ["history", "blobs"]:
                receipt = json.loads(
                    (cache / (label + ".completed.json")).read_text(encoding="utf-8")
                )
                if (
                    receipt["exit_code"] not in (0, 1)
                    or receipt["raw_sha256"] != sha(cache / (label + ".raw.json"))
                    or receipt["log_sha256"] != sha(cache / (label + ".private.log"))
                ):
                    raise RuntimeError("Incomplete or altered resumed pass")
            history = json.loads(
                (cache / "history.raw.json").read_text(encoding="utf-8")
            )
            blobs = json.loads((cache / "blobs.raw.json").read_text(encoding="utf-8"))
            mapping = json.loads(
                (cache / "blob-inventory.private.json").read_text(encoding="utf-8")
            )
            total = sum(x["bytes"] for x in mapping.values())
            history_exit, blobs_exit = int(bool(history)), int(bool(blobs))
            print(
                "Reusing complete history/object scans with verified pins and source",
                flush=True,
            )
        else:
            write_json(cache / "scan-binding.private.json", binding)
            history, history_exit = scanner(
                "git",
                ROOT,
                cache,
                "history",
                "--all --reflog --full-history --diff-merges=separate",
            )
            dest, mapping, total = materialize(cache)
            blobs, blobs_exit = scanner("dir", dest, cache, "blobs")
        covered_hashes = {sha(cache / "blobs" / name) for name in mapping}
        dest, files, covered = snapshot(cache, covered_hashes)
        working, working_exit = scanner("dir", dest, cache, "working")
        rows = (
            metadata(history, "history", {})
            + metadata(blobs, "blobs", mapping)
            + metadata(
                working,
                "working",
                {
                    name: {"file_sha256": sha(dest / name)}
                    for name in files
                    if (dest / name).is_file()
                },
            )
        )
        manifest = {
            "date_utc": datetime.now(timezone.utc).isoformat(),
            "source_head": git("rev-parse", "HEAD").strip(),
            "scanner_image": IMAGE,
            "scanner_version": version,
            "config_sha256": sha(ROOT / "security/inf052-gitleaks.toml"),
            "vendored_rules_sha256": sha(ROOT / "security/gitleaks-v8.30.0.toml"),
            "scope": "all local refs and reflogs; ALL stored blobs plus commit/tag objects (including unreachable); tracked plus nonignored pending files",
            "commit_count": int(git("rev-list", "--all", "--reflog", "--count")),
            "ref_count": len(git("for-each-ref", "--format=%(refname)").splitlines()),
            "blob_count": sum(x["type"] == "blob" for x in mapping.values()),
            "commit_tag_object_count": sum(
                x["type"] != "blob" for x in mapping.values()
            ),
            "blob_bytes": total,
            "working_file_count": len(files) + len(covered),
            "working_scanned_file_count": len(files),
            "working_byte_identical_to_scanned_objects": len(covered),
            "working_sha256": {name: sha(dest / name) for name in files},
            "runner_sha256": sha(ROOT / "scripts/secret_scan.py"),
            "archive_depth": 3,
            "decode_depth": 5,
            "max_target_megabytes": 0,
            "ignore_file": False,
            "baseline": False,
            "inline_allow_comments": False,
            "global_path_exclusions": [],
            "exit_codes": {
                "history": history_exit,
                "blobs": blobs_exit,
                "working": working_exit,
            },
            "sanitization": "Explicit metadata whitelist; no match/secret/context/author/email/message/link values exported",
            "limits": [
                "Pattern scanner cannot prove absence of secrets",
                "Archive recursion capped at 3 and decoding at 5",
                "Ignored local working files are outside committed-history scope",
            ],
        }
        write_json(cache / "metadata.private.json", rows)
        write_json(cache / "manifest.private.json", manifest)
        latest.write_text(str(cache), encoding="utf-8", newline="\n")
    return export(cache, args.output.resolve(), rows, manifest)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        # Exceptions can contain raw scanner output or input values. Print only
        # the class; retain the detailed exception in the ignored cache.
        (ROOT / ".cache/inf052/error.private.txt").write_text(
            str(exc), encoding="utf-8"
        )
        print(
            f"Secret scan failed ({type(exc).__name__}); inspect ignored .cache/inf052/error.private.txt",
            file=sys.stderr,
        )
        sys.exit(2)
