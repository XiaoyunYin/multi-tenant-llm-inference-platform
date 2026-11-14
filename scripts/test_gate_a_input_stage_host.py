"""Exercise the Ubuntu system-Python host's real /stage-inputs HTTP path.

The one-line stdin request may contain a short-lived presigned URL. This helper
never writes or prints that request; it reports only the verified receipt.
"""

import http.client
import json
import os
import shutil
import sys
import tempfile
import threading
import time
from pathlib import Path

from package_a_host import Host, server


def main():
    if shutil.which("aws") is not None:
        raise ValueError("gate_a_host_smoke:aws_cli_present")
    if os.environ.get("VIRTUAL_ENV"):
        raise ValueError("gate_a_host_smoke:venv_active")
    request = json.loads(sys.stdin.buffer.readline())
    manifest = request.get("manifest")
    download_url = request.get("download_url")
    if not isinstance(manifest, dict) or not isinstance(download_url, str):
        raise ValueError("gate_a_host_smoke:request")
    with tempfile.TemporaryDirectory(prefix="gate-a-stage-host-") as temporary:
        host = Host(
            Path(temporary), "host-smoke-token", "test-manifest", time.time() + 120
        )
        host.manifest = manifest
        service = server(host, port=0)
        worker = threading.Thread(target=service.serve_forever, daemon=True)
        worker.start()
        try:
            body = json.dumps(
                {"deadline_epoch": time.time() + 60, "download_url": download_url},
                separators=(",", ":"),
            ).encode()
            connection = http.client.HTTPConnection(
                "127.0.0.1", service.server_port, timeout=60
            )
            connection.request(
                "POST",
                "/stage-inputs",
                body=body,
                headers={
                    "Authorization": "Bearer host-smoke-token",
                    "Content-Type": "application/json",
                },
            )
            response = connection.getresponse()
            response_body = response.read()
            connection.close()
            if response.status != 200:
                print(
                    json.dumps(
                        {
                            "status": "REFUSED",
                            "http_status": response.status,
                            "reason": response_body.decode("utf-8", errors="replace")[
                                :200
                            ],
                        },
                        sort_keys=True,
                    )
                )
                return 1
            receipt = json.loads(response_body)
            if download_url.encode() in host.input_receipt.read_bytes():
                raise ValueError("gate_a_host_smoke:presigned_url_persisted")
            if receipt.get("readback_verified") is not True:
                raise ValueError("gate_a_host_smoke:readback")
            print(
                json.dumps(
                    {
                        "status": "PASS",
                        "receipt": receipt,
                        "presigned_url_saved": False,
                        "python": sys.executable,
                        "aws_cli_available": False,
                        "venv_active": False,
                    },
                    sort_keys=True,
                )
            )
            return 0
        finally:
            service.shutdown()
            worker.join(timeout=5)
            service.server_close()


if __name__ == "__main__":
    raise SystemExit(main())
