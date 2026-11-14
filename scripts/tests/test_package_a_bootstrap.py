import importlib.util
import contextlib
import hashlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RETRY = ROOT / "scripts/package_a_bootstrap_retry.sh"
PINS_MODULE = ROOT / "scripts/package_a_bootstrap_pins.py"
SPEC = importlib.util.spec_from_file_location("package_a_bootstrap_pins", PINS_MODULE)
pins = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(pins)


class BootstrapRetryTests(unittest.TestCase):
    def setUp(self):
        self.shell = shutil.which("sh")
        if self.shell is None:
            self.skipTest("POSIX sh is required; run under Git Bash or Linux")

    def test_uv_and_go_fail_once_then_retry_succeeds(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            for name in ("uv", "go"):
                script = bin_dir / name
                script.write_text(
                    "#!/bin/sh\n"
                    'count_file="$STATE_DIR/' + name + '.count"\n'
                    'count=0; [ ! -f "$count_file" ] || count=$(cat "$count_file")\n'
                    'count=$((count + 1)); echo "$count" > "$count_file"\n'
                    '[ "$count" -gt 1 ] || exit 124\n'
                    "exit 0\n",
                    encoding="utf-8",
                )
                script.chmod(0o755)
            command = (
                f'. "{RETRY.as_posix()}"; '
                "retry_step uv_sync 3 2 0 - uv sync; "
                "retry_step go_mod_download 3 2 0 - go mod download"
            )
            result = subprocess.run(
                [self.shell, "-c", command],
                check=False,
                capture_output=True,
                text=True,
                env={
                    **os.environ,
                    "PATH": str(bin_dir) + os.pathsep + os.environ.get("PATH", ""),
                    "STATE_DIR": str(root),
                },
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            self.assertEqual((root / "uv.count").read_text().strip(), "2")
            self.assertEqual((root / "go.count").read_text().strip(), "2")
            self.assertIn("step=uv_sync attempt=1", result.stdout)
            self.assertIn("cap_s=2", result.stdout)
            self.assertIn("exit_code=1", result.stdout)

    def test_always_failing_command_exits_with_named_error_within_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "always-fails"
            binary.write_text("#!/bin/sh\nexit 124\n", encoding="utf-8")
            binary.chmod(0o755)
            command = f'. "{RETRY.as_posix()}"; retry_step uv_sync 3 1 0 - "{binary}"'
            result = subprocess.run(
                [self.shell, "-c", command],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("bootstrap_retry_exhausted:uv_sync", result.stderr)
            self.assertEqual(result.stdout.count("start_utc="), 3)

    def test_wrong_pinned_sha_refuses_without_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            calls = []

            def wrong_digest_download(command, check, timeout):
                calls.append(command)
                Path(command[6]).write_bytes(b"wrong")
                return subprocess.CompletedProcess(command, 0)

            with self.assertRaisesRegex(ValueError, "tool_sha256:fixture"):
                pins.download_one(
                    "fixture",
                    {"bytes": 5, "sha256": "0" * 64, "url": "https://example.invalid"},
                    root,
                    runner=wrong_digest_download,
                )
            self.assertEqual(len(calls), 1)

    def test_attempt_cap_allows_progress_slower_than_scaled_legacy_cap(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = b"tool"
            started = time.perf_counter()

            def slow_but_progressing(command, check, timeout):
                self.assertAlmostEqual(timeout, 1.05)
                destination = Path(command[6])
                time.sleep(0.04)
                destination.write_bytes(data)
                return subprocess.CompletedProcess(command, 0)

            with contextlib.redirect_stdout(io.StringIO()) as output:
                result = pins.download_one(
                    "fixture",
                    {
                        "bytes": len(data),
                        "sha256": hashlib.sha256(data).hexdigest(),
                        "url": "https://example.invalid/fixture",
                    },
                    root,
                    attempts=2,
                    rate_bytes_per_second=1_000,
                    overhead_s=0.05,
                    runner=slow_but_progressing,
                )
            elapsed = time.perf_counter() - started
            self.assertEqual(result.read_bytes(), data)
            self.assertGreater(elapsed, 0.02)  # scaled legacy 30 s cap
            self.assertLess(elapsed, 1.05)  # ceil(4/1,000)+0.05 s new cap
            self.assertIn("attempt=1 cap_s=1.05", output.getvalue())
            self.assertIn("elapsed_ms=", output.getvalue())

    def test_stalled_download_hits_idle_timeout_and_retries(self):
        requests = []

        class StallHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.path)
                time.sleep(0.2)
                try:
                    self.wfile.write(b"late")
                except OSError:
                    pass

            def log_message(self, format, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), StallHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                with contextlib.redirect_stdout(io.StringIO()) as output:
                    with self.assertRaisesRegex(
                        RuntimeError, "bootstrap_retry_exhausted:tool_download:stall"
                    ):
                        pins.download_one(
                            "stall",
                            {
                                "bytes": 1,
                                "sha256": "0" * 64,
                                "url": f"http://127.0.0.1:{server.server_port}/stall",
                            },
                            Path(directory),
                            attempts=2,
                            rate_bytes_per_second=100_000,
                            overhead_s=1,
                            idle_timeout_s=0.05,
                            sleep=lambda _: None,
                        )
                self.assertEqual(len(requests), 2)
                self.assertEqual(output.getvalue().count("start_utc="), 2)
                self.assertIn("exit_code=1", output.getvalue())
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_attempt_that_crosses_bootstrap_deadline_is_not_started(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "started"
            if self.shell is None:
                self.skipTest("POSIX sh is required; run under Git Bash or Linux")
            command = (
                f'. "{RETRY.as_posix()}"; '
                f'retry_step fetch 3 10 0 "$(($(date +%s)))" '
                f'sh -c "touch {marker.as_posix()}"'
            )
            result = subprocess.run(
                [self.shell, "-c", command],
                capture_output=True,
                text=True,
                check=False,
                timeout=5,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("bootstrap_deadline:fetch", result.stderr)
            self.assertFalse(marker.exists())

    def test_python_attempt_refuses_when_cap_crosses_deadline(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(
                RuntimeError, "bootstrap_deadline:tool_download:fixture"
            ):
                pins.download_one(
                    "fixture",
                    {"bytes": 2, "sha256": "0" * 64},
                    root,
                    deadline_epoch=time.time() + 0.01,
                    runner=lambda *args, **kwargs: self.fail("download must not start"),
                )

    def test_production_caps_follow_registered_download_and_cache_sizes(self):
        registered = json.loads((ROOT / "deploy/package-a/pins.json").read_bytes())
        docker_cap = pins.attempt_cap_s(registered["docker"]["bytes"])
        self.assertEqual(registered["docker"]["bytes"], 85_700_518)
        self.assertEqual(docker_cap, 116)
        self.assertEqual(pins.attempt_cap_s(95_000_000), 125)
        self.assertEqual(pins.attempt_cap_s(152_000_000), 182)


if __name__ == "__main__":
    unittest.main()
