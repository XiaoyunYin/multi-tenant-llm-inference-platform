import hashlib
import http.client
import importlib.util
import io
import json
import os
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from inference_platform.r1_cloud_operator import Forward, Operator
from inference_platform.r1_lifecycle import Production
from inference_platform.session_stop import stop_child, terminate_operator_sessions

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "upload_bootstrap", ROOT / "scripts/r1-host-bootstrap.py"
)
BOOTSTRAP = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BOOTSTRAP)


def bundle():
    files = {"bin/uv": b"fixture uv", "bin/gateway": b"fixture gateway"}
    for name in ("__init__.py", "r1_evidence.py", "r1_spec.py"):
        path = "python/src/inference_platform/" + name
        files[path] = (ROOT / path).read_bytes()
    files["payload.json"] = json.dumps(
        {"files": {n: hashlib.sha256(b).hexdigest() for n, b in files.items()}}
    ).encode()
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return stream.getvalue()


class HostUploadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name) / "host"
        self.data = bundle()
        self.token = "fixture"
        with socket.socket() as reserve:
            reserve.bind(("127.0.0.1", 0))
            self.port = reserve.getsockname()[1]
        self.argv = [
            sys.executable,
            str(ROOT / "scripts/r1-host-bootstrap.py"),
            "--token=" + self.token,
            "--bundle-sha256",
            hashlib.sha256(self.data).hexdigest(),
            "--deadline-unix-s",
            str(time.time() + 120),
            "--directory",
            str(self.directory),
            "--port",
            str(self.port),
        ]
        self.start()

    def start(self):
        self.child = subprocess.Popen(
            self.argv,
            env={**os.environ, "PYTHONPATH": str(ROOT / "python/src")},
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        end = time.time() + 10
        while time.time() < end:
            try:
                self.request("GET", "/status")
                return
            except OSError:
                time.sleep(0.02)
        self.tearDown()
        self.fail("bootstrap did not bind")

    def tearDown(self):
        stop_child(self.child)
        self.temp.cleanup()

    def request(self, method, path, data=None, digest=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        headers = {"Authorization": "Bearer " + self.token}
        if digest is not None:
            headers["X-Chunk-SHA256"] = digest
        try:
            connection.request(method, path, data, headers)
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def chunk(self, offset, data, digest=None):
        return self.request(
            "POST", f"/bundle/{offset}", data, digest or hashlib.sha256(data).hexdigest()
        )

    def test_real_argparse_accepts_dash_leading_token_and_serves_status(self):
        stop_child(self.child)
        self.token = "-AbCdEfGh-leading-dash"
        self.argv[2] = "--token=" + self.token
        self.start()
        status, value = self.request("GET", "/status")
        self.assertEqual(status, 200)
        self.assertEqual(value["bundle_sha256"], hashlib.sha256(self.data).hexdigest())

    def test_in_order_append_and_double_commit_stages_once(self):
        halfway = len(self.data) // 2
        self.assertEqual(
            self.chunk(0, self.data[:halfway]), (200, {"offset": halfway, "staged": False})
        )
        self.assertEqual(self.chunk(halfway, self.data[halfway:])[0], 200)
        self.assertEqual(self.request("POST", "/bundle/commit", b"")[0], 200)
        marker = self.directory / "incremental-active"
        modified = marker.stat().st_mtime_ns
        status, value = self.request("POST", "/bundle/commit", b"")
        self.assertEqual(status, 200)
        self.assertTrue(value["already_staged"])
        self.assertEqual(marker.stat().st_mtime_ns, modified)
        BOOTSTRAP.verify_payload(self.directory / "payload")
        self.assertEqual((self.directory / "payload/bin/uv").read_bytes(), b"fixture uv")
        self.assertFalse(list((self.directory / "payload").rglob("*.pyc")))

    def test_restart_preserves_partial_upload_and_verified_staged_payload(self):
        half = len(self.data) // 2
        self.chunk(0, self.data[:half])
        stop_child(self.child)
        self.start()
        self.assertEqual(self.request("GET", "/bundle")[1], {"offset": half, "staged": False})
        self.chunk(half, self.data[half:])
        self.assertEqual(self.request("POST", "/bundle/commit", b"")[0], 200)
        stop_child(self.child)
        self.start()
        self.assertEqual(
            self.request("GET", "/bundle")[1], {"offset": len(self.data), "staged": True}
        )
        self.assertEqual(self.request("POST", "/bundle/commit", b"")[0], 200)

    def test_restart_with_another_bundle_refuses_existing_control_directory(self):
        stop_child(self.child)
        self.argv[self.argv.index("--bundle-sha256") + 1] = "b" * 64
        self.child = subprocess.Popen(self.argv, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        _, stderr = self.child.communicate(timeout=5)
        self.assertNotEqual(self.child.returncode, 0)
        self.assertIn(b"another bundle", stderr)

    def test_bad_hash_and_out_of_order_return_current_offset(self):
        self.chunk(0, b"abc")
        for offset, data, digest in (
            (3, b"bad", "0" * 64),
            (0, b"duplicate", None),
            (9, b"gap", None),
        ):
            with self.subTest(offset=offset, size=len(data)):
                status, value = self.chunk(offset, data, digest)
                self.assertEqual(status, 409)
                self.assertEqual(value["offset"], 3)
        self.assertEqual((self.directory / "bundle.partial").read_bytes(), b"abc")

    def test_truncated_chunk_resumes_and_stalled_body_does_not_lock_status(self):
        self.chunk(0, self.data[:10])
        with socket.create_connection(("127.0.0.1", self.port), timeout=3) as sock:
            sock.sendall(
                b"POST /bundle/10 HTTP/1.1\r\nHost: fixture\r\n"
                b"Authorization: Bearer fixture\r\nContent-Length: 100\r\n"
                b"X-Chunk-SHA256: invalid\r\n\r\npartial"
            )
            started = time.monotonic()
            self.assertEqual(self.request("GET", "/status")[0], 200)
            self.assertLess(time.monotonic() - started, 1)
            sock.shutdown(socket.SHUT_WR)
            response = sock.recv(4096)
            self.assertIn(b"409", response)
        self.assertEqual(self.request("GET", "/bundle")[1]["offset"], 10)
        self.assertEqual(self.chunk(10, self.data[10:])[0], 200)
        self.assertEqual(self.request("POST", "/bundle/commit", b"")[0], 200)

    def test_commit_full_sha_mismatch_is_refused_without_staging(self):
        self.chunk(0, b"not the reviewed bundle")
        status, value = self.request("POST", "/bundle/commit", b"")
        self.assertEqual(status, 409)
        self.assertIn("SHA mismatch", value["error"])
        self.assertFalse((self.directory / "payload").exists())
        self.assertEqual(value["offset"], len(b"not the reviewed bundle"))

    def test_oversized_advertised_body_is_refused_without_reading_it(self):
        self.chunk(0, b"abc")
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        try:
            connection.putrequest("POST", "/bundle/3")
            connection.putheader("Authorization", "Bearer fixture")
            connection.putheader("Content-Length", str(1024**2 + 1))
            connection.endheaders()
            response = connection.getresponse()
            self.assertEqual(response.status, 409)
            self.assertEqual(json.loads(response.read())["offset"], 3)
        finally:
            connection.close()


class OperatorEncodingAndCloseTests(unittest.TestCase):
    def test_operator_and_tunnel_env_force_utf8_and_decode_unicode(self):
        with tempfile.TemporaryDirectory() as root:
            folder = Path(root)
            op = Operator(
                folder,
                {
                    "aws_profile": "fixture",
                    "region": "us-east-1",
                    "session_manager_plugin_path": "plugin",
                },
                folder,
                time.time() + 10,
            )
            value = {"StandardOutputContent": "\u2192 \u2018\u2019"}
            with patch(
                "inference_platform.r1_cloud_operator.subprocess.check_output",
                return_value=json.dumps(value, ensure_ascii=False).encode(),
            ) as call:
                self.assertEqual(op.aws("ssm", "get-command-invocation", []), value)
                self.assertEqual(call.call_args.kwargs["env"]["AWS_CLI_OUTPUT_ENCODING"], "utf-8")
            with (
                patch.dict(os.environ, {"R1_OPERATOR_INVOCATION": "test-invocation"}),
                patch(
                    "inference_platform.r1_cloud_operator.subprocess.Popen",
                    return_value=MagicMock(pid=71),
                ) as call,
            ):
                op.tunnel("fixture-host")
                self.assertEqual(call.call_args.kwargs["env"]["AWS_CLI_OUTPUT_ENCODING"], "utf-8")
            registries = list(folder.glob("*.owner.json"))
            self.assertEqual(len(registries), 1)
            owner = json.loads(registries[0].read_bytes())
            self.assertEqual(owner["invocation_token"], "test-invocation")
            self.assertIsInstance(owner["operator_pid"], int)

    def test_production_command_env_and_aws_explicit_unicode_decode(self):
        with tempfile.TemporaryDirectory() as root:
            production = Production.__new__(Production)
            production.repo = production.directory = Path(root)
            production.inputs = {
                "aws_profile": "fixture",
                "region": "us-east-1",
                "session_manager_plugin_path": "plugin",
            }
            production.aws_calls = 0
            raw = production.command(
                [sys.executable, "-c", "import os; print(os.environ['AWS_CLI_OUTPUT_ENCODING'])"],
                production.now() + 10,
                "env",
            )
            self.assertEqual(raw.decode("utf-8").strip(), "utf-8")
            with patch.object(
                production, "command", return_value='{"value":"\u2192 \u2018\u2019"}'.encode()
            ):
                self.assertEqual(
                    production.aws("ssm", "fixture", [], production.now() + 1, "x"),
                    {"value": "\u2192 \u2018\u2019"},
                )

    def test_ssm_polls_retry_decode_and_json_failures_within_deadline(self):
        with tempfile.TemporaryDirectory() as root:
            op = Operator(Path(root), {}, Path(root), time.time() + 5)
            with (
                patch.object(
                    op,
                    "aws",
                    side_effect=[
                        {"Command": {"CommandId": "fixture"}},
                        UnicodeDecodeError("utf-8", b"\xa1", 0, 1, "bad"),
                        json.JSONDecodeError("bad", "?", 0),
                        {"Status": "Success"},
                    ],
                ) as call,
                patch("inference_platform.r1_cloud_operator.time.sleep"),
            ):
                self.assertEqual(op.ssm("fixture", ["fixture"])["Status"], "Success")
                self.assertEqual(call.call_count, 4)

    def test_readiness_parse_failure_retains_raw_invocation_not_parameters(self):
        for raw in (b"\xa1\xfa", b"{broken json"):
            with self.subTest(raw=raw), tempfile.TemporaryDirectory() as root:
                folder = Path(root)
                op = Operator(
                    folder,
                    {"aws_profile": "fixture", "region": "us-east-1"},
                    folder,
                    time.time() + 0.05,
                )
                op.context_path.write_text('{"hosts":{"gpu-0":{"id":"fixture"}}}')

                def aws(argv, raw=raw, **kwargs):
                    return b'{"Command":{"CommandId":"fixture"}}' if "send-command" in argv else raw

                with patch(
                    "inference_platform.r1_cloud_operator.subprocess.check_output", side_effect=aws
                ):
                    results = op.readiness_diagnostics()
                self.assertIn("error", results[0])
                files = list(folder.glob("ssm-parse-*.stdout"))
                self.assertTrue(files)
                self.assertTrue(all(p.read_bytes() == raw for p in files))
                self.assertNotIn(b"commands", (folder / "ssm-parse-failures.jsonl").read_bytes())

    def test_close_terminates_exact_child_before_stop_even_on_error_or_timeout(self):
        for outcome in (
            subprocess.CompletedProcess([], 0, b"{}"),
            subprocess.CalledProcessError(1, ["aws"]),
            subprocess.TimeoutExpired(["aws"], 10),
        ):
            with (
                self.subTest(outcome=type(outcome).__name__),
                tempfile.TemporaryDirectory() as root,
            ):
                folder = Path(root)
                (folder / "older.log").write_text("Starting session with SessionId: foreign\n")
                child = MagicMock()
                child.r1_ssm_log = folder / "own.log"
                child.r1_ssm_log.write_text("Starting session with SessionId: fixture-own\n")
                child.r1_ssm_env, child.r1_ssm_argv = {}, ["aws", "--region", "us-east-1"]
                channel = Forward(
                    Operator(folder, {}, folder, time.time() + 10), "h", "t", "gpu-0", "ready"
                )
                channel.child = child
                order = []

                def terminate(argv, outcome=outcome, order=order, **kwargs):
                    order.append("terminate")
                    self.assertEqual(argv[argv.index("--session-id") + 1], "fixture-own")
                    self.assertEqual(kwargs["timeout"], 10)
                    self.assertEqual(kwargs["env"]["AWS_CLI_OUTPUT_ENCODING"], "utf-8")
                    if isinstance(outcome, Exception):
                        raise outcome
                    return outcome

                with (
                    patch("inference_platform.session_stop.subprocess.run", side_effect=terminate),
                    patch(
                        "inference_platform.r1_cloud_operator.stop_forward",
                        side_effect=lambda _, order=order: order.append("stop"),
                    ),
                ):
                    channel.close()
                    channel.close()
                self.assertEqual(order, ["terminate", "stop"])
                self.assertIsNone(channel.child)
                event = json.loads((folder / "gpu-0-ready-channel.jsonl").read_bytes())
                self.assertEqual(
                    event["status"], "failed" if isinstance(outcome, Exception) else "terminated"
                )

    def test_forced_operator_timeout_terminates_only_owned_sessions_before_tree_stop(self):
        with tempfile.TemporaryDirectory() as root:
            folder = Path(root)
            invocation_token = "lifecycle-invocation-fixture"
            for name, token, owner in (
                ("owned", invocation_token, 987),
                ("foreign", "another-invocation", 321),
            ):
                (folder / f"{name}.owner.json").write_bytes(
                    json.dumps(
                        {
                            "invocation_token": token,
                            "operator_pid": owner,
                            "profile": "fixture",
                            "region": "us-east-1",
                        }
                    ).encode()
                )
                (folder / f"{name}.log").write_bytes(
                    f"Starting session with SessionId: fixture-{name}\n".encode()
                )
            (folder / "damaged.owner.json").write_bytes(b"{invalid")
            production = Production.__new__(Production)
            production.repo = production.directory = folder
            production.inputs = {
                "runtime_directory": ".",
                "session_manager_plugin_path": "plugin",
                "aws_profile": "fixture",
                "region": "us-east-1",
            }
            child = MagicMock(pid=321)
            child.wait.side_effect = subprocess.TimeoutExpired(["operator"], 1)
            order = []

            def terminate(argv, **kwargs):
                self.assertEqual(argv[argv.index("--session-id") + 1], "fixture-owned")
                order.append("terminate-owned")
                return subprocess.CompletedProcess(argv, 0, b"{}")

            with (
                patch(
                    "inference_platform.r1_lifecycle.subprocess.Popen", return_value=child
                ) as popen,
                patch(
                    "inference_platform.r1_lifecycle.secrets.token_urlsafe",
                    return_value=invocation_token,
                ),
                patch(
                    "inference_platform.session_stop.subprocess.run", side_effect=terminate
                ) as call,
                patch(
                    "inference_platform.r1_lifecycle.stop_forward",
                    side_effect=lambda _: order.append("stop-tree"),
                ),
            ):
                with self.assertRaises(subprocess.TimeoutExpired):
                    production.command(
                        [sys.executable, "-m", "inference_platform.r1_cloud_operator"],
                        production.now() + 1,
                        "ready",
                    )
                self.assertEqual(order, ["terminate-owned", "stop-tree"])
                self.assertEqual(
                    popen.call_args.kwargs["env"]["R1_OPERATOR_INVOCATION"], invocation_token
                )
                # Parent cleanup after Forward.close's durable receipt is idempotent.
                terminate_operator_sessions(folder, invocation_token)
                self.assertEqual(call.call_count, 1)
            receipt = json.loads((folder / "ready-session-termination.json").read_bytes())
            self.assertEqual({v["status"] for v in receipt}, {"terminated", "registry_unreadable"})
            self.assertFalse((folder / "foreign.termination.json").exists())

    def test_launcher_timeout_selects_grandchild_registry_by_invocation_token(self):
        with tempfile.TemporaryDirectory() as root:
            repo = Path(root)
            runtime = repo / "runtime"
            runtime.mkdir()
            production = Production.__new__(Production)
            production.repo = production.directory = repo
            production.inputs = {
                "runtime_directory": "runtime",
                "session_manager_plugin_path": "tools/session-manager-plugin.exe",
                "aws_profile": "fixture",
                "region": "us-east-1",
            }
            grandchild_code = "\n".join(
                (
                    "import json, os, pathlib, sys, time",
                    "runtime = pathlib.Path(sys.argv[1])",
                    "(runtime / 'grandchild.owner.json').write_text(json.dumps({",
                    "    'invocation_token': os.environ['R1_OPERATOR_INVOCATION'],",
                    "    'operator_pid': os.getpid(), 'forward_pid': os.getpid(),",
                    "    'profile': 'fixture', 'region': 'us-east-1'}), encoding='utf-8')",
                    "(runtime / 'grandchild.log').write_text(",
                    "    'Starting session with SessionId: r138-fixture-session\\n',",
                    "    encoding='utf-8')",
                    "time.sleep(60)",
                )
            )
            parent_code = "\n".join(
                (
                    "import pathlib, subprocess, sys, time",
                    "runtime = pathlib.Path(sys.argv[1])",
                    "subprocess.Popen([sys.executable, '-c', sys.argv[2], str(runtime)],",
                    "    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,",
                    "    stderr=subprocess.DEVNULL)",
                    "while not (runtime / 'grandchild.owner.json').exists():",
                    "    time.sleep(0.01)",
                    "time.sleep(60)",
                )
            )
            argv = [
                sys.executable,
                "-c",
                parent_code,
                str(runtime),
                grandchild_code,
                "inference_platform.r1_cloud_operator",
            ]
            terminate_calls = []
            observed_env = {}
            children = []
            real_popen = subprocess.Popen
            real_run = subprocess.run

            def launch(*args, **kwargs):
                if kwargs.get("cwd") == repo and "env" in kwargs:
                    observed_env.update(kwargs["env"])
                child = real_popen(*args, **kwargs)
                if kwargs.get("cwd") == repo and "env" in kwargs:
                    children.append(child)
                return child

            def run(argv, *args, **kwargs):
                if argv and argv[0] == "aws":
                    terminate_calls.append(argv)
                    return subprocess.CompletedProcess(argv, 0, b"{}", b"")
                return real_run(argv, *args, **kwargs)

            with (
                patch("inference_platform.r1_lifecycle.subprocess.Popen", side_effect=launch),
                patch("inference_platform.session_stop.subprocess.run", side_effect=run),
            ):
                with self.assertRaises(subprocess.TimeoutExpired):
                    production.command(argv, production.now() + 3.0, "ready")

            registry = json.loads((runtime / "grandchild.owner.json").read_bytes())
            self.assertTrue(observed_env["R1_OPERATOR_INVOCATION"])
            self.assertEqual(registry["invocation_token"], observed_env["R1_OPERATOR_INVOCATION"])
            self.assertNotEqual(registry["operator_pid"], children[0].pid)
            self.assertEqual(len(terminate_calls), 1)
            self.assertEqual(
                terminate_calls[0][terminate_calls[0].index("--session-id") + 1],
                "r138-fixture-session",
            )
            receipt = json.loads((repo / "ready-session-termination.json").read_bytes())
            self.assertEqual(receipt[0]["status"], "terminated")

    def test_unavailable_or_ambiguous_owned_session_never_terminates_another(self):
        for text in (
            "",
            "Starting session with SessionId: a\nStarting session with SessionId: b\n",
        ):
            with self.subTest(text=text), tempfile.TemporaryDirectory() as root:
                folder = Path(root)
                child = MagicMock()
                child.r1_ssm_log = folder / "owned.log"
                child.r1_ssm_log.write_bytes(text.encode())
                channel = Forward(
                    Operator(folder, {}, folder, time.time() + 10), "h", "t", "gpu-0", "ready"
                )
                channel.child = child
                with (
                    patch("inference_platform.session_stop.subprocess.run") as terminate,
                    patch("inference_platform.r1_cloud_operator.stop_forward") as stop,
                ):
                    channel.close()
                terminate.assert_not_called()
                stop.assert_called_once_with(child)
                self.assertEqual(child.r1_ssm_termination["status"], "session_id_unavailable")


if __name__ == "__main__":
    unittest.main()
