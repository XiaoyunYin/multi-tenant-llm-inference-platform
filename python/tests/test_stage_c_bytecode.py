import ast
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path

from inference_platform.stage_c_container import capture_argv
from inference_platform.stage_c_session import bootstrap_commands, free_port


class BytecodeTest(unittest.TestCase):
    def test_entrypoint_disables_bytecode_before_other_imports(self):
        source = Path(__file__).parents[1] / "src/inference_platform/stage_c_session.py"
        statements = ast.parse(source.read_text(encoding="utf-8")).body[2:]
        self.assertEqual(ast.unparse(statements[0]), "import sys")
        self.assertEqual(ast.unparse(statements[1]), "sys.dont_write_bytecode = True")

    def test_bootstrap_and_container_capture_disable_bytecode_at_launch(self):
        commands = bootstrap_commands(
            b"source",
            "1" * 64,
            {"entrypoint": {"sha256": "2" * 64}},
            "/opt/inf011/reviewed",
            "fixture",
            22280,
        )
        self.assertTrue(commands[-1].startswith("PYTHONDONTWRITEBYTECODE=1 nohup python3 -B "))
        self.assertIn("PYTHONDONTWRITEBYTECODE=1", capture_argv())
        self.assertEqual(capture_argv()[capture_argv().index("python3") + 1], "-B")

    def test_server_without_environment_variable_never_imports_staged_package(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / "staged"
            package = destination / "sources/python/src/inference_platform"
            package.mkdir(parents=True)
            (package / "__init__.py").write_text("raise AssertionError('staged import')\n")
            (destination / "controller-pid.json").write_text(
                json.dumps({"pid": os.getpid(), "start_ticks": 0})
            )
            bootstrap = root / "entrypoint.py"
            source = Path(__file__).parents[1] / "src/inference_platform/stage_c_session.py"
            bootstrap.write_bytes(source.read_bytes())
            epoch = root / "epoch"
            epoch.write_text(str(int(time.time() + 30)))
            port = free_port()
            # Guard actual imports as well as tree hashes: -B alone could hide an
            # inappropriate staged import. Intentionally omit -B and the env var
            # here to exercise the entrypoint's own first-statement protection.
            guard = (
                "import builtins,runpy,sys; original=builtins.__import__; "
                'exec("def checked(name,*a,**k):\\n'
                " if name.startswith('inference_platform'): raise AssertionError('package import '+name)\\n"
                ' return original(name,*a,**k)"); '
                "builtins.__import__=checked; sys.argv=sys.argv[1:]; "
                "runpy.run_path(sys.argv[0],run_name='__main__')"
            )
            environment = {k: v for k, v in os.environ.items() if k != "PYTHONDONTWRITEBYTECODE"}
            environment["PYTHONPATH"] = str(package.parent)

            def snapshot():
                return {
                    p.relative_to(destination).as_posix(): hashlib.sha256(
                        p.read_bytes()
                    ).hexdigest()
                    for p in (destination / "sources").rglob("*")
                    if p.is_file()
                }

            before = snapshot()
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    guard,
                    str(bootstrap),
                    "--serve-transport",
                    str(destination),
                    "--manifest-sha256",
                    "0" * 64,
                    "--nonce",
                    "fixture",
                    "--port",
                    str(port),
                    "--epoch-file",
                    str(epoch),
                ],
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                limit = time.perf_counter() + 10
                while True:
                    if process.poll() is not None:
                        self.fail(process.communicate()[1].decode())
                    try:
                        request = urllib.request.Request(
                            f"http://127.0.0.1:{port}/status", headers={"Authorization": "fixture"}
                        )
                        with urllib.request.urlopen(request, timeout=1) as response:
                            self.assertTrue(json.load(response)["started"])
                        break
                    except OSError:
                        if time.perf_counter() >= limit:
                            self.fail("server unavailable")
                        time.sleep(0.05)
                self.assertEqual(snapshot(), before)
                self.assertFalse(list(package.rglob("*.pyc")))
            finally:
                process.terminate()
                process.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
