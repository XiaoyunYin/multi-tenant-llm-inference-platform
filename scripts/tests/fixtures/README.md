# Secret scanner transport fixtures

`secret-scan-v8.30.0.json` contains reports captured from the digest-pinned
Gitleaks v8.30.0 image in `scripts/secret_scan.py`. Every credential, account,
email and endpoint in the reports is a deliberately public synthetic test value.
It scans only the ephemeral seeded test repositories/files, never the project
history or workstation. Git dates, LF input and gzip mtime are fixed so the
source fingerprints work on Windows and Linux.

`-Suite all` always runs the transport mock and all original assertions. When
the pinned image is cached, the same deleted-file, side-branch, archive, orphan
blob, commit-message, rule-family, safe-control and sanitization assertions also
run against that image. If Docker or the image is unavailable, the tests use
recorded reports without pulling anything. Git object traversal, snapshotting,
projection and disposition/export checks still execute normally. Error tests
exercise fatal/warning diagnostics, missing output and invalid failure results.

Replay requires exact input fingerprints, rule-file hashes, image/version and
coverage flags. Changed inputs fail; they cannot replay an old clean result.
The mock tests the wrapper contract against recorded engine behavior; it does
not execute the detector or satisfy a publication secret scan. Actual history
scans always require the pinned image. Rule changes require a new real capture.

From the repo root, with that image already cached:

```powershell
uv run --project python --locked python scripts/tests/record_secret_scan_fixture.py
$env:SECRET_SCAN_TEST_MODE = "mock"
uv run --project python --locked python -m unittest discover -s scripts/tests -p test_secret_scan.py -v
$env:SECRET_SCAN_TEST_MODE = "image"
uv run --project python --locked python -m unittest discover -s scripts/tests -p test_secret_scan.py -v
Remove-Item Env:SECRET_SCAN_TEST_MODE
```

`auto` is the default. Explicit `image` mode fails if the pin is unavailable.
Review new reports before committing; the recorder writes only after the full
coverage check succeeds. Scan logs have varying timestamps/durations; repeat
captures need not be byte-identical. The input and configuration hashes must be.
