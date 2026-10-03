"""Exercise pinned rules and the release-gate wrapper, including in offline CI.

All values below are deliberately synthetic and materialized only in an ignored
temporary directory. This test never contacts a credential provider.
"""

import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "secret_scan", Path(__file__).parents[1] / "secret_scan.py"
)
SCAN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SCAN)
FIXTURE = Path(__file__).parent / "fixtures" / "secret-scan-v8.30.0.json"
REAL_RUN = subprocess.run


def source_fingerprint(mode, source):
    """Bind a replay to all input bytes, including unreachable Git objects."""
    if mode == "git":

        def git(*args):
            return subprocess.check_output(["git", "-C", str(source), *args]).decode()

        data = json.dumps(
            {
                "objects": git(
                    "cat-file",
                    "--batch-all-objects",
                    "--batch-check=%(objectname) %(objecttype) %(objectsize)",
                ),
                "refs": git("for-each-ref", "--format=%(refname) %(objectname)"),
                "reflog_targets": sorted(
                    git("reflog", "show", "--all", "--format=%H").splitlines()
                ),
                "head_ref": git("symbolic-ref", "HEAD").strip(),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    else:
        data = json.dumps(
            [
                (p.relative_to(source).as_posix(), SCAN.sha(p))
                for p in sorted(source.rglob("*"))
                if p.is_file()
            ],
            separators=(",", ":"),
        ).encode()
    return hashlib.sha256(data).hexdigest()


def replay_scanner(args, **kwargs):
    """Mock only Docker transport; Git, materialization and export stay real.

    Reports were captured from the pinned image on these exact synthetic bytes.
    A rule/config/input change requires a new real-image capture, never an empty
    or invented success report. This is not a replacement for a release scan.
    """
    if args[0] != "docker":
        return REAL_RUN(args, **kwargs)
    required = {
        "run",
        "--rm",
        "--network=none",
        "--read-only",
        SCAN.IMAGE,
        "--config=/config/inf052-gitleaks.toml",
        "--ignore-gitleaks-allow",
        "--gitleaks-ignore-path=/config/no-ignore-file",
        "--max-decode-depth=5",
        "--max-target-megabytes=0",
        "--report-format=json",
    }
    if not required <= set(args):
        raise AssertionError("Scanner invocation lost a coverage/sandbox flag")
    mounts = [args[i + 1] for i, arg in enumerate(args) if arg == "--mount"]
    source = Path(mounts[0].split("src=", 1)[1].split(",dst=", 1)[0])
    output = Path(mounts[2].split("src=", 1)[1].split(",dst=", 1)[0])
    if not mounts[0].endswith("dst=/source,readonly") or not mounts[1].endswith(
        "dst=/config,readonly"
    ):
        raise AssertionError("Scanner source/config mounts must remain read-only")
    mode = args[args.index(SCAN.IMAGE) + 1]
    if "--max-archive-depth=" + ("0" if mode == "git" else "3") not in args:
        raise AssertionError("Scanner archive coverage changed")
    if (
        mode == "git"
        and "--log-opts=--all --reflog --full-history --diff-merges=separate"
        not in args
    ):
        raise AssertionError("Scanner history coverage changed")
    report_name = next(
        a.split("/output/", 1)[1] for a in args if a.startswith("--report-path=")
    )
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    if fixture["image"] != SCAN.IMAGE or fixture["version"] != SCAN.VERSION:
        raise AssertionError("Recorded scanner pin differs")
    for name, digest in fixture["config_sha256"].items():
        if SCAN.sha(SCAN.ROOT / "security" / name) != digest:
            raise AssertionError("Scanner config differs from real-image recording")
    recorded = fixture["cases"][report_name]
    if recorded["source_sha256"] != source_fingerprint(mode, source):
        raise AssertionError("Synthetic scanner input differs from recording")
    SCAN.write_json(output / report_name, recorded["records"])
    return subprocess.CompletedProcess(
        args, recorded["exit_code"], recorded["log"].encode()
    )


class PinnedSecretScanTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        (SCAN.ROOT / ".cache/inf052").mkdir(parents=True, exist_ok=True)
        mode = os.environ.get("SECRET_SCAN_TEST_MODE", "auto")
        if mode not in ("auto", "mock", "image"):
            raise ValueError("SECRET_SCAN_TEST_MODE must be auto, mock or image")
        available = False
        if mode != "mock":
            try:
                available = (
                    REAL_RUN(
                        ["docker", "image", "inspect", SCAN.IMAGE],
                        capture_output=True,
                        timeout=10,
                    ).returncode
                    == 0
                )
            except (OSError, subprocess.TimeoutExpired):
                pass
        if mode == "image" and not available:
            raise RuntimeError("Explicit image mode requires the cached pinned image")
        cls.image_available = available
        print(
            "Secret scanner coverage: recorded transport mock"
            + (
                " AND pinned-image integration"
                if available
                else " (mock-only selected; no pull)"
                if mode == "mock"
                else " (image unavailable; no pull)"
            ),
            flush=True,
        )

    def test_deleted_branch_archive_and_low_entropy_coverage(self):
        # The mock path always runs, even on a workstation with the image. All
        # original rule, archive, deleted/branch/orphan and sanitization checks
        # run in both paths when the image is cached. No assertion is skipped.
        modes = ["mock"] + (["image"] if self.image_available else [])
        for mode in modes:
            with self.subTest(transport=mode):
                if mode == "mock":
                    with patch.object(
                        SCAN.subprocess, "run", side_effect=replay_scanner
                    ):
                        self.check_coverage()
                else:
                    self.check_coverage()

    def check_coverage(self):
        with tempfile.TemporaryDirectory(
            prefix="fixture-", dir=SCAN.ROOT / ".cache/inf052"
        ) as td:
            root = Path(td)
            repo = root / "repo"
            repo.mkdir()
            cache = root / "private"
            cache.mkdir()

            def git(*args):
                return subprocess.check_output(
                    ["git", "-C", str(repo), *args],
                    stderr=subprocess.DEVNULL,
                    text=True,
                    env={
                        **os.environ,
                        "GIT_AUTHOR_DATE": "2000-01-01T00:00:00Z",
                        "GIT_COMMITTER_DATE": "2000-01-01T00:00:00Z",
                    },
                ).strip()

            git("init", "-b", "main")
            git("config", "user.name", "Synthetic Scan Fixture")
            git("config", "user.email", "scan@example.invalid")
            git("config", "core.autocrlf", "false")
            git("config", "commit.gpgsign", "false")
            aws_key = "AKIA" + "Q2W3E4R5T6Y7UIOP"
            github_token = "ghp_" + "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0iL3oR6"
            (repo / "deleted.txt").write_text(
                "aws_access_key_id = "
                + aws_key
                + "\ngithub_token = "
                + github_token
                + "\n",
                encoding="utf-8",
                newline="\n",
            )
            git("add", ".")
            git("commit", "-m", "synthetic deleted credentials")
            (repo / "deleted.txt").unlink()
            git("add", "-u")
            git("commit", "-m", "delete synthetic credentials")
            git("checkout", "-b", "fixture-side")
            (repo / "branch.txt").write_text(
                'aws_account_id = "'
                + "1111"
                + "2222"
                + "3333"
                + '"\nurl = "https://router.corp:443"\n',
                encoding="utf-8",
                newline="\n",
            )
            git("add", ".")
            git("commit", "-m", "synthetic side branch identifiers")
            git("checkout", "main")
            history, rc = SCAN.scanner(
                "git",
                repo,
                cache,
                "fixture-history",
                "--all --reflog --full-history --diff-merges=separate",
            )
            self.assertEqual(rc, 1)
            rules = {h["RuleID"] for h in history}
            self.assertTrue(
                {
                    "aws-access-token",
                    "github-pat",
                    "aws-account-id",
                    "internal-hostname",
                }
                <= rules,
                rules,
            )
            self.assertIn("deleted.txt", {h["File"] for h in history})
            self.assertIn("branch.txt", {h["File"] for h in history})

            archive = root / "archives"
            archive.mkdir()
            with gzip.GzipFile(
                filename=str(archive / "deleted-evidence.jsonl.gz"), mode="wb", mtime=0
            ) as out:
                out.write(
                    (
                        'Authorization: Bearer synthetic-local-token\npassword = "synthetic-fixture-password"\nurl=https://10.'
                        + "20.30.40:8443\nv6=fd12:3456::1\nredis://fixture-service:6379\n"
                    ).encode()
                )
            (archive / "salt.txt").write_text(
                __import__("base64")
                .urlsafe_b64encode(bytes(range(32)))
                .decode()
                .rstrip("=")
                + "\n",
                encoding="utf-8",
                newline="\n",
            )
            (archive / "safe.txt").write_text(
                "https://github.com/gitleaks/gitleaks\nend_ns=1790981023879000000\n",
                encoding="utf-8",
                newline="\n",
            )
            compressed, rc = SCAN.scanner("dir", archive, cache, "fixture-archive")
            self.assertEqual(rc, 1)
            rules = {h["RuleID"] for h in compressed}
            self.assertTrue(
                {
                    "literal-bearer-token",
                    "literal-credential-assignment",
                    "private-ipv4",
                    "private-ipv6",
                    "private-service-url",
                    "naked-cache-salt",
                }
                <= rules,
                rules,
            )
            self.assertFalse(any(h["File"].endswith("safe.txt") for h in compressed))
            # The committed projection must contain no match, secret, email or
            # commit message even when the raw scanner report contains them.
            rows = SCAN.metadata(history, "history", {})
            serialized = json.dumps(rows)
            for value in (
                aws_key,
                github_token,
                "1111" + "2222" + "3333",
                "router.corp",
                "scan@example.invalid",
            ):
                self.assertNotIn(value, serialized)
            self.assertFalse(any("Secret" in h or "Match" in h for h in rows))

            # All stored objects include orphan blobs and commit messages, beyond
            # what a normal git-log patch scan can see.
            orphan = (
                subprocess.check_output(
                    ["git", "-C", str(repo), "hash-object", "-w", "--stdin"],
                    input=("orphan=" + aws_key + "\n").encode(),
                )
                .decode()
                .strip()
            )
            git(
                "commit",
                "--allow-empty",
                "-m",
                "Authorization: Bearer synthetic-message-token",
            )
            project_root = SCAN.ROOT
            try:
                SCAN.ROOT = repo
                obj_dir, mapping, _ = SCAN.materialize(cache)
            finally:
                SCAN.ROOT = project_root
            stored, rc = SCAN.scanner("dir", obj_dir, cache, "fixture-objects")
            self.assertEqual(rc, 1)
            projected = SCAN.metadata(stored, "blobs", mapping)
            self.assertTrue(
                any(
                    h["object_id"] == orphan and h["rule"] == "aws-access-token"
                    for h in projected
                )
            )
            self.assertTrue(
                any(
                    h["path"] == "git-commit-object"
                    and h["rule"] == "literal-bearer-token"
                    for h in projected
                )
            )

    def test_scanner_errors_fail_closed(self):
        cases = [
            (2, b"ERR scanner failed", []),
            (1, b"WRN leaks found", []),
            (0, b"INF done", None),  # missing report
            (0, b"ERR partial read", []),
            (0, b"FTL decode failure", []),
            (0, b"WRN archive unreadable", []),
        ]
        for code, log, records in cases:
            with self.subTest(code=code, diagnostic=log):
                with tempfile.TemporaryDirectory() as td:
                    cache = Path(td)
                    if records is not None:
                        SCAN.write_json(cache / "error.raw.json", records)
                    with patch.object(
                        SCAN.subprocess,
                        "run",
                        return_value=subprocess.CompletedProcess([], code, log),
                    ):
                        with self.assertRaises(RuntimeError):
                            SCAN.scanner("dir", cache, cache, "error")
                    self.assertFalse((cache / "error.completed.json").exists())

    def test_recorded_mock_rejects_changed_source(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "source"
            source.mkdir()
            (source / "new-secret.txt").write_bytes(b"unexpected fixture input")
            with patch.object(SCAN.subprocess, "run", side_effect=replay_scanner):
                with self.assertRaisesRegex(AssertionError, "input differs"):
                    SCAN.scanner("dir", source, root, "fixture-archive")
            self.assertFalse((root / "fixture-archive.completed.json").exists())

    def test_untriaged_export_fails_closed(self):
        with tempfile.TemporaryDirectory(dir=SCAN.ROOT / ".cache/inf052") as td:
            root = Path(td)
            row = {"id": "synthetic-missing-disposition", "rule": "aws-access-token"}
            self.assertEqual(SCAN.export(root, root, [row], {}), 1)
            manifest = json.loads((root / "scan-manifest.json").read_text())
            self.assertEqual(manifest["scan_result"], "REVIEW_REQUIRED")
            self.assertFalse(manifest["publication_authorized"])

    def test_working_disposition_is_bound_to_file_bytes(self):
        hit = {
            "File": "/source/fixture.txt",
            "RuleID": "literal-bearer-token",
            "StartLine": 1,
            "EndLine": 1,
            "StartColumn": 1,
            "EndColumn": 30,
        }
        first = SCAN.metadata(
            [hit], "working", {"fixture.txt": {"file_sha256": "a" * 64}}
        )
        changed = SCAN.metadata(
            [hit], "working", {"fixture.txt": {"file_sha256": "b" * 64}}
        )
        self.assertNotEqual(first[0]["id"], changed[0]["id"])

    def test_snapshot_reuses_only_identical_bytes(self):
        with tempfile.TemporaryDirectory(dir=SCAN.ROOT / ".cache/inf052") as td:
            repo = Path(td) / "repo"
            repo.mkdir()
            subprocess.run(["git", "init", str(repo)], capture_output=True, check=True)
            (repo / "same.txt").write_bytes(b"known-public-fixture")
            (repo / "changed.txt").write_bytes(b"known-public-fixture")
            subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
            (repo / "changed.txt").write_bytes(b"new-sensitive-value!")
            (repo / "new.txt").write_bytes(b"new-untracked-value")
            cache = Path(td) / "cache"
            cache.mkdir()
            saved = SCAN.ROOT
            try:
                SCAN.ROOT = repo
                _, selected, covered = SCAN.snapshot(
                    cache, {hashlib.sha256(b"known-public-fixture").hexdigest()}
                )
            finally:
                SCAN.ROOT = saved
            self.assertEqual(set(selected), {"changed.txt", "new.txt"})
            self.assertEqual([x["path"] for x in covered], ["same.txt"])


if __name__ == "__main__":
    unittest.main()
