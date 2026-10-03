"""Explicitly recapture synthetic reports; requires the cached pinned image."""

import importlib.util
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "scanner_tests", ROOT / "scripts/tests/test_secret_scan.py"
)
TESTS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TESTS)


def main():
    os.environ["SECRET_SCAN_TEST_MODE"] = "image"
    TESTS.PinnedSecretScanTest.setUpClass()
    scan = TESTS.SCAN.scanner
    fixture = {
        "image": TESTS.SCAN.IMAGE,
        "version": TESTS.SCAN.VERSION,
        "provenance": "Real digest-pinned Gitleaks v8.30.0; synthetic fixtures only",
        "config_sha256": {
            name: TESTS.SCAN.sha(ROOT / "security" / name)
            for name in ("inf052-gitleaks.toml", "gitleaks-v8.30.0.toml")
        },
        "cases": {},
    }

    def capture(mode, source, cache, label, log_opts=None):
        records, code = scan(mode, source, cache, label, log_opts)
        # Only synthetic input is scanned, never this repository's history.
        keys = {
            "RuleID",
            "File",
            "StartLine",
            "EndLine",
            "StartColumn",
            "EndColumn",
            "Commit",
            "Secret",
            "Match",
            "Author",
            "Email",
            "Message",
        }
        fixture["cases"][label + ".raw.json"] = {
            "source_sha256": TESTS.source_fingerprint(mode, source),
            "records": [{k: v for k, v in row.items() if k in keys} for row in records],
            "exit_code": code,
            "log": (cache / (label + ".private.log")).read_text(encoding="utf-8"),
        }
        return records, code

    TESTS.SCAN.scanner = capture
    try:
        TESTS.PinnedSecretScanTest().check_coverage()
    finally:
        TESTS.SCAN.scanner = scan
    # Nothing is updated unless all original coverage assertions passed.
    TESTS.SCAN.write_json(TESTS.FIXTURE, fixture)
    print("Recorded three synthetic real-image fixtures; inspect and commit the diff.")


if __name__ == "__main__":
    main()
