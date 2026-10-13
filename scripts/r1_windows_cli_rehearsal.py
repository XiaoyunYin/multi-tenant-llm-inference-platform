"""Exercise the real Windows aws CLI against loopback SSM, never AWS."""

import argparse
import hashlib
import json
import locale
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from inference_platform.r1_cloud_operator import Forward, Operator
from inference_platform.r1_spec import encoded
from inference_platform.session_stop import stop_child

ROOT = Path(__file__).resolve().parents[1]


def run(output):
    if os.name != "nt":
        raise ValueError("this receipt must be collected on the Windows operator")
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    paths = [
        "scripts/r1_windows_cli_rehearsal.py",
        "python/src/inference_platform/r1_cloud_operator.py",
        "python/src/inference_platform/session_stop.py",
    ]
    sources = {}
    for path in paths:
        data = (ROOT / path).read_bytes()
        assert (
            subprocess.check_output(["git", "show", "HEAD:" + path], cwd=ROOT) == data
        )
        sources[path] = hashlib.sha256(data).hexdigest()
    calls, stopped = [], []
    text = "\u2192 \u2018cloud-init\u2019"

    class SSM(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            target = self.headers["X-Amz-Target"]
            calls.append(
                {
                    "target": target,
                    "body": body,
                    "owned_fixture_child_alive_at_request": child.poll() is None
                    if target.endswith("TerminateSession")
                    else None,
                }
            )
            if target.endswith("GetCommandInvocation"):
                result = {
                    "Status": "Success",
                    "StandardOutputContent": text,
                    "StandardErrorContent": "",
                    "ResponseCode": 0,
                }
            elif target.endswith("TerminateSession"):
                result = {"SessionId": body["SessionId"]}
            else:
                raise AssertionError("unexpected fake SSM operation")
            data = json.dumps(result, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/x-amz-json-1.1")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), SSM)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    config, creds = output / "fake-config", output / "fake-credentials"
    config.write_bytes(b"[profile fixture]\nregion=us-east-1\n")
    # Intentionally fake static credentials, kept only in scratch, never curated.
    creds.write_bytes(
        b"[fixture]\naws_access_key_id=fixture\naws_secret_access_key=fixture\n"
    )
    env = {
        "AWS_CONFIG_FILE": str(config),
        "AWS_SHARED_CREDENTIALS_FILE": str(creds),
        "AWS_ENDPOINT_URL_SSM": f"http://127.0.0.1:{server.server_port}",
        "AWS_EC2_METADATA_DISABLED": "true",
        "AWS_MAX_ATTEMPTS": "1",
        "HTTP_PROXY": "http://127.0.0.1:9",
        "HTTPS_PROXY": "http://127.0.0.1:9",
        "NO_PROXY": "127.0.0.1,localhost",
        "AWS_CLI_OUTPUT_ENCODING": "gbk",
    }
    operator = Operator(
        ROOT,
        {"aws_profile": "fixture", "region": "us-east-1"},
        output / "operator",
        time.time() + 30,
    )
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"], start_new_session=True
    )
    child.r1_ssm_log = output / "owned-child.log"
    child.r1_ssm_log.write_bytes(
        b"Starting session with SessionId: fixture-owned-session\n"
    )
    child.r1_ssm_argv = ["aws", "--profile", "fixture", "--region", "us-east-1"]
    version = subprocess.check_output(["aws", "--version"]).decode("utf-8").strip()
    try:
        with patch.dict(os.environ, env):
            child.r1_ssm_env = dict(os.environ)
            started = time.monotonic()
            value = operator.aws(
                "ssm",
                "get-command-invocation",
                [
                    "--command-id",
                    "00000000-0000-0000-0000-000000000000",
                    "--instance-id",
                    "i-00000000000000000",
                ],
            )
            elapsed = time.monotonic() - started
            assert value["StandardOutputContent"] == text
            channel = Forward(operator, "fixture-host", "fixture", "generator", "ready")
            channel.child = child
            original_stop = stop_child

            def stop(owned):
                assert (
                    len(calls) == 2
                    and calls[-1]["target"] == "AmazonSSM.TerminateSession"
                )
                stopped.append({"terminate_received_before_stop": True})
                return original_stop(owned)

            with patch(
                "inference_platform.r1_cloud_operator.stop_forward", side_effect=stop
            ):
                channel.close()
            assert child.poll() is not None and stopped
        events = [
            json.loads(line)
            for line in (output / "operator/generator-ready-channel.jsonl")
            .read_bytes()
            .splitlines()
        ]
        assert events[-1]["status"] == "terminated"
        receipt = {
            "schema": "r1-windows-cli-local-ssm.v1",
            "platform": sys.platform,
            "python_preferred_encoding": locale.getpreferredencoding(False),
            "aws_version": version,
            "real_aws_cli": True,
            "real_aws_calls": 0,
            "endpoint": "loopback fake SSM; dead external proxy; fake static credentials",
            "inherited_output_encoding": "gbk",
            "production_output_encoding": "utf-8",
            "unicode_parsed": value["StandardOutputContent"],
            "unicode_utf8_sha256": hashlib.sha256(text.encode()).hexdigest(),
            "operator_aws_elapsed_s": elapsed,
            "http_requests": calls,
            "terminate_before_plugin_stop": stopped[0][
                "terminate_received_before_stop"
            ],
            "termination_event": events[-1],
            "owned_child_reaped": child.poll() is not None,
            "committed_sources": True,
            "source_sha256": sources,
            "source_head": subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=ROOT
            )
            .decode()
            .strip(),
        }
        (output / "receipt.json").write_bytes(encoded(receipt) + b"\n")
        print(
            json.dumps(
                {
                    k: receipt[k]
                    for k in (
                        "platform",
                        "aws_version",
                        "real_aws_calls",
                        "operator_aws_elapsed_s",
                        "terminate_before_plugin_stop",
                        "owned_child_reaped",
                    )
                },
                indent=2,
            )
        )
    finally:
        stop_child(child)
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    run(parser.parse_args().output)


if __name__ == "__main__":
    main()
