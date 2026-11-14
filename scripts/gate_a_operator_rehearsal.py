"""Exercise the Gate A operator sequence against two local Ubuntu hosts and MinIO.

Run from the Windows operator workstation with Docker Desktop. Cloud lookups and
SSM delivery are local fixtures; the source and Gate A role processes, HTTP
agent, sender/receiver transfer, MinIO and POSIX persistence are real.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tarfile
import threading
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [
    str(ROOT / "python/tests"),
    str(ROOT / "scripts"),
    str(ROOT / "python/src"),
]

import build_inf037b_gate_a_packet as packet  # noqa: E402
from test_inf037b_collectors import CampaignTests  # noqa: E402
from inference_platform.inf037b_archive import encode, sha  # noqa: E402
from inference_platform.inf037b_campaign import sanitized_campaign  # noqa: E402
from inference_platform.inf037b_contract import (  # noqa: E402
    ATTEMPT_MS,
    RESET_MS,
    SOURCE_KINDS,
)
from inference_platform.inf037b_gate_a import (  # noqa: E402
    GATE_A_OPERATION_CUTOFF_MS,
    gate_a_binding,
    produce_export_sizing_proof,
)
from inference_platform.inf037b_maximum import current_sources  # noqa: E402
from inference_platform.package_a_cloud import HOST_TIMER_S, save  # noqa: E402
from inference_platform.package_a_operator import (  # noqa: E402
    GateAOperator,
    Ports as ProductionPorts,
)

MINIO_IMAGE = packet.GATE_A_MINIO_IMAGE
PINNED_PYTHON_IMAGE = json.loads((ROOT / "deploy/package-a/pins.json").read_bytes())[
    "python_image"
]
MINIO_ACCESS_KEY = "r465" + secrets.token_hex(8)
MINIO_SECRET_KEY = secrets.token_hex(24)
AWS_PROFILE = "gate-a-r465-rehearsal"
MINIO_ENDPOINT = "http://127.0.0.1:9000"
PRESIGN_ENDPOINT = "https://s3.us-east-1.amazonaws.com"
RELAY_SCRIPT = """import socket,threading
def pump(a,b):
 try:
  while True:
   data=a.recv(65536)
   if not data: break
   b.sendall(data)
 except OSError: pass
 try: b.shutdown(socket.SHUT_WR)
 except OSError: pass
def handle(client):
 try:
  upstream=socket.create_connection(('127.0.0.1',22280),timeout=30)
  threading.Thread(target=pump,args=(client,upstream),daemon=True).start()
  pump(upstream,client)
 except OSError: pass
 finally:
  try: client.close()
  except OSError: pass
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('0.0.0.0',22281)); s.listen(64)
while True:
 c,_=s.accept(); threading.Thread(target=handle,args=(c,),daemon=True).start()
"""
FORWARD_SOURCE = """import select,socket,sys,threading
listen_port,target_port=map(int,sys.argv[1:3])
def pump(a,b):
 try:
  while True:
   ready,_,_=select.select([a,b],[],[],30)
   if not ready: continue
   for src in ready:
    data=src.recv(65536)
    if not data: return
    (b if src is a else a).sendall(data)
 except OSError: pass
def handle(client):
 try:
  remote=socket.create_connection(('127.0.0.1',target_port),timeout=30)
  pump(client,remote)
 except OSError: pass
 finally:
  try: client.close()
  except OSError: pass
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('127.0.0.1',listen_port)); s.listen(64)
while True:
 c,_=s.accept(); threading.Thread(target=handle,args=(c,),daemon=True).start()
"""
HTTPS_PROXY_SOURCE = """from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from http.client import HTTPConnection
import ssl
class Handler(BaseHTTPRequestHandler):
 def do_GET(self):
  upstream=HTTPConnection('minio',9000,timeout=600)
  headers={k:v for k,v in self.headers.items() if k.lower() not in {'connection','proxy-connection'}}
  headers['Host']=self.headers.get('Host','s3.us-east-1.amazonaws.com')
  upstream.request('GET',self.path,headers=headers)
  response=upstream.getresponse(); body=response.read()
  self.send_response(response.status)
  for key,value in response.getheaders():
   if key.lower() not in {'connection','transfer-encoding','content-length'}: self.send_header(key,value)
  self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
 def log_message(self,*args): pass
server=ThreadingHTTPServer(('0.0.0.0',443),Handler)
context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain('/tmp/r465.crt','/tmp/r465.key')
server.socket=context.wrap_socket(server.socket,server_side=True); server.serve_forever()
"""
READINESS_STANDIN = r'''"""R465-only receiver readiness stand-in; Round 324 separately ran the suite."""
import json
import sys
from pathlib import Path

Path("/opt/dec077/r465-locked-interpreter.txt").write_text(sys.executable + "\n")

def _trace(frame, event, arg):
    del arg
    if (
        event == "line"
        and frame.f_globals.get("__name__") == "__main__"
        and frame.f_code.co_filename.endswith("/inference_platform/package_a_cloud.py")
    ):
        runner = frame.f_globals.get("Runner")
        if isinstance(runner, type) and not getattr(runner, "__r465_readiness_patched__", False):
            def _stand_in(self):
                self.receipt["gate_a_readiness"] = {
                    "status": "RECORDED_STAND_IN",
                    "authority": "Claude Round 327 permits this; exact readiness argv passed separately in Round 324",
                    "unrun_here": "Docker-in-Docker MinIO readiness module suite",
                }
                (self.output / "runner.json").write_text(
                    json.dumps(self.receipt, sort_keys=True, separators=(",", ":")) + "\n",
                    encoding="utf-8",
                )

            runner.run_gate_a_readiness = _stand_in
            runner.__r465_readiness_patched__ = True
            sys.settrace(None)
    return _trace

sys.settrace(_trace)
'''


def run(argv, *, timeout=120, input_bytes=None, check=True, cwd=ROOT, env=None):
    result = subprocess.run(
        [str(value) for value in argv],
        cwd=cwd,
        env=env,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
    )
    if check and result.returncode != 0:
        tail = result.stdout.decode("utf-8", errors="replace")[-2400:]
        raise RuntimeError(f"command_exit_{result.returncode}:{argv[0]}:{tail}")
    return result


def write_file(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
    return path


def aws_executable():
    candidate = shutil.which("aws")
    if not candidate:
        raise RuntimeError("aws_cli_missing_for_local_minio_operator_fixture")
    return Path(candidate).resolve()


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def read_archive_json(archive_path, member_name):
    with tarfile.open(archive_path, "r:gz") as archive:
        member = archive.extractfile(member_name)
        if member is None:
            raise ValueError("rehearsal:missing_receipt:" + member_name)
        return json.loads(member.read())


def build_campaign_inputs(output, *, minimum_spool_raw_bytes=1):
    output.mkdir(parents=True, exist_ok=True)
    binding = gate_a_binding()
    campaign_case = CampaignTests(
        "test_partial_stage_capture_report_and_immutable_reproduction"
    )
    campaign_case.setUp()
    try:
        campaign, _ = campaign_case.campaign(name="gate-a-r465-small-campaign")
        campaign.materialize()
        source = campaign.root
        fixture_inventory = packet.inventory(source)
        fixture_proof = {
            "subject": "lifecycle:maximum_export_fixture",
            "pins": binding["pins"],
            "schedule_ms": [ATTEMPT_MS] * 3 + [RESET_MS] * 2,
            "source_inventory_sha256": sha(encode(fixture_inventory)),
            "scope": "R465 small real campaign rehearsal fixture",
            "registered_archive_rows": 1,
            "fixture_inventory": fixture_inventory,
            "source_lf_sha256": current_sources(),
        }
        fixture_proof_path = write_file(
            output / "fixture-proof.json", encode(fixture_proof)
        )
        sizing = produce_export_sizing_proof(
            source,
            pins=binding["pins"],
            fixture_proof_sha256=sha(fixture_proof_path.read_bytes()),
        )
        sizing_path = write_file(output / "sizing-proof.json", encode(sizing))

        spool = output / "spool"
        spool.mkdir()
        for kind in SOURCE_KINDS:
            body = b"r465-small-wire-" + kind.encode()
            name = sha(kind.encode())
            (spool / f"{name}.bin").write_bytes(body)
            (spool / f"{name}.jsonl").write_bytes(
                encode({"offset": 0, "length": len(body), "sha256": sha(body)})
            )
        spool_inventory = packet.inventory(spool)
        spool_manifest = {
            "schema": "inf037b-gate-a-spool-v2",
            "fixture": {
                "proof_sha256": sha(fixture_proof_path.read_bytes()),
                "source_lf_sha256": current_sources(),
                "pins": binding["pins"],
                "inventory": fixture_inventory,
                "registered_archive_rows": 1,
                "schedule_ms": [ATTEMPT_MS] * 3 + [RESET_MS] * 2,
            },
            "spool": {
                "inventory": spool_inventory,
                "inventory_sha256": sha(encode(spool_inventory)),
            },
            "allowance": {
                "id": "r436-round318.maximum-archive-as-wire-floor",
                "raw_bytes": 1,
            },
            "generator": {"id": "gate-a.capture-owner-retainer.v1"},
        }
        spool_manifest_path = write_file(
            output / "spool-manifest.json", encode(spool_manifest)
        )
        key_path = write_file(output / "sanitizer-key.bin", secrets.token_bytes(32))
        specs = [campaign.spec]
        specs_path = write_file(output / "sanitizer-specs.json", encode(specs))
        expected_root = output / "expected-sanitized"
        sanitized_campaign(source, expected_root, specs, key=key_path.read_bytes())
        expected_inventory = packet.inventory(expected_root)
        expected_inventory_path = write_file(
            output / "expected-archive-inventory.json", encode(expected_inventory)
        )
        input_bundle, input_inventory = packet._write_input_bundle(
            output,
            source,
            fixture_proof_path,
            sizing_path,
            spool,
            spool_manifest_path,
            specs_path,
            key_path,
            expected_inventory_path,
            write_file(output / "pins.json", encode(binding)),
        )
        if sum(facts["bytes"] for facts in spool_inventory.values()) <= 0:
            raise ValueError("rehearsal:spool_empty")
        if minimum_spool_raw_bytes < 1:
            raise ValueError("rehearsal:spool_allowance")
        return {
            "source": source,
            "binding": binding,
            "fixture_proof_path": fixture_proof_path,
            "sizing_path": sizing_path,
            "spool": spool,
            "spool_manifest_path": spool_manifest_path,
            "specs_path": specs_path,
            "key_path": key_path,
            "expected_inventory_path": expected_inventory_path,
            "input_bundle": input_bundle,
            "input_inventory": input_inventory,
            "fixture_inventory": fixture_inventory,
            "spool_inventory": spool_inventory,
            "sizing": sizing,
        }
    finally:
        campaign_case.doCleanups()


class LocalControlPlane:
    """EC2/SSM responses plus file-loaded SSM shell execution in Docker."""

    def __init__(self, host_containers, private_ips, forward_ports, output):
        self.host_containers = host_containers
        self.private_ips = private_ips
        self.forward_ports = forward_ports
        self.output = output
        self.command_id = 0
        self.commands = {}
        self.calls = []
        self._watchers = []

    def _container(self, instance_id):
        return self.host_containers[instance_id]

    def _install_readiness_standin_after_venv(self, container):
        deadline = time.time() + 1800
        python = "/opt/dec077/repo/python/.venv/bin/python"
        while time.time() < deadline:
            probe = subprocess.run(
                ["docker", "exec", container, python, "-c", "import boto3"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=30,
            )
            if probe.returncode == 0:
                code = "/opt/dec077/repo/python/.venv/lib/python3.12/site-packages/sitecustomize.py"
                write = subprocess.run(
                    [
                        "docker",
                        "exec",
                        "-i",
                        container,
                        "sh",
                        "-c",
                        f"umask 077; cat > {code}",
                    ],
                    input=READINESS_STANDIN.encode(),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    timeout=30,
                )
                if write.returncode != 0:
                    raise RuntimeError("rehearsal:readiness_standin_install")
                marker = subprocess.run(
                    [
                        "docker",
                        "exec",
                        container,
                        "sh",
                        "-c",
                        "touch /opt/dec077/r465-readiness-standin",
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    timeout=30,
                )
                if marker.returncode != 0:
                    raise RuntimeError("rehearsal:readiness_marker_install")
                return
            time.sleep(2)
        raise TimeoutError("rehearsal:locked_venv_not_ready_for_readiness_standin")

    def _run_ssm_command(self, instance_id, parameters):
        container = self._container(instance_id)
        commands = parameters.get("commands")
        if not isinstance(commands, list) or not commands:
            raise ValueError("rehearsal:ssm_commands")
        stdout_parts, stderr_parts, code = [], [], 0
        for command in commands:
            name = "r465-ssm-" + uuid.uuid4().hex + ".sh"
            target = "/tmp/" + name
            copied = subprocess.run(
                [
                    "docker",
                    "exec",
                    "-i",
                    container,
                    "sh",
                    "-c",
                    f"umask 077; cat > {target}",
                ],
                input=command.encode("utf-8"),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=30,
            )
            if copied.returncode != 0:
                return (
                    copied.returncode,
                    "",
                    copied.stdout.decode("utf-8", errors="replace"),
                )
            try:
                result = subprocess.run(
                    ["docker", "exec", container, "sh", "-c", "sh " + target],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=600,
                )
            except subprocess.TimeoutExpired as exc:
                return 124, "", str(exc)
            finally:
                subprocess.run(
                    ["docker", "exec", container, "rm", "-f", target],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=30,
                )
            stdout_parts.append(result.stdout.decode("utf-8", errors="replace"))
            stderr_parts.append(result.stderr.decode("utf-8", errors="replace"))
            code = result.returncode
            if code:
                break
        # The host agent and its local-only relay are now available. This is
        # the only SSM session-establishment substitution in the rehearsal.
        if code == 0 and any("/opt/dec077/host.py" in command for command in commands):
            subprocess.run(
                ["docker", "exec", "-d", container, "python3", "-c", RELAY_SCRIPT],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=30,
                check=True,
            )
            thread = threading.Thread(
                target=self._install_readiness_standin_after_venv,
                args=(container,),
                name="r465-readiness-standin-" + instance_id,
                daemon=True,
            )
            thread.start()
            self._watchers.append(thread)
        return code, "".join(stdout_parts), "".join(stderr_parts)

    def aws(self, service, operation, args, *, deadline=None):
        del deadline
        self.calls.append((service, operation))
        if service == "ec2" and operation == "describe-instances":
            role = next(
                (
                    value.removeprefix("Name=tag:Role,Values=")
                    for value in args
                    if value.startswith("Name=tag:Role,Values=")
                ),
                None,
            )
            if role not in {"sender", "receiver"}:
                instances = []
            else:
                instance_id = "i-r465-" + role
                instances = [
                    {
                        "InstanceId": instance_id,
                        "PrivateIpAddress": self.private_ips[role],
                        "State": {"Name": "running"},
                    }
                ]
            return {"Reservations": [{"Instances": instances}]}
        if service == "ssm" and operation == "describe-instance-information":
            target = None
            for value in args:
                try:
                    decoded = json.loads(value)
                except (TypeError, ValueError):
                    continue
                if isinstance(decoded, list) and decoded:
                    target = decoded[0].get("Values", [None])[0]
            return {
                "InstanceInformationList": [
                    {"InstanceId": target, "PingStatus": "Online"}
                ]
            }
        if service == "ssm" and operation == "send-command":
            target = next(
                args[index + 1]
                for index, value in enumerate(args[:-1])
                if value == "--instance-ids"
            )
            parameter_url = next(
                args[index + 1]
                for index, value in enumerate(args[:-1])
                if value == "--parameters"
            )
            if not parameter_url.startswith("file://"):
                raise ValueError("rehearsal:ssm_parameters_not_file_loaded")
            parameter_path = Path(parameter_url.removeprefix("file://"))
            parameter_bytes = parameter_path.read_bytes()
            parameters = json.loads(parameter_bytes)
            code, stdout, stderr = self._run_ssm_command(target, parameters)
            self.command_id += 1
            command_id = f"r465-{self.command_id:04d}"
            self.commands[command_id] = {
                "Status": "Success" if code == 0 else "Failed",
                "ResponseCode": code,
                "StandardOutputContent": stdout[-4096:],
                "StandardErrorContent": stderr[-4096:],
            }
            self.calls.append(
                {
                    "fixture": "ssm.send-command.file-url",
                    "instance_id": target,
                    "parameter_bytes": len(parameter_bytes),
                    "command_count": len(parameters.get("commands", [])),
                    "response_code": code,
                }
            )
            if code:
                raise subprocess.CalledProcessError(code, ["ssm", "send-command"])
            return {"Command": {"CommandId": command_id}}
        if service == "ssm" and operation == "get-command-invocation":
            command_id = next(
                args[index + 1]
                for index, value in enumerate(args[:-1])
                if value == "--command-id"
            )
            return self.commands[command_id]
        if service == "s3api":
            return None
        raise ValueError(f"rehearsal:unexpected_cloud_operation:{service}:{operation}")


def start_forward(target_port):
    local_port = free_port()
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    child = subprocess.Popen(
        [
            sys.executable,
            str(Path(__file__).resolve()),
            "--forward",
            str(local_port),
            str(target_port),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=flags,
    )
    end = time.time() + 10
    while time.time() < end:
        if child.poll() is not None:
            raise RuntimeError("rehearsal:local_forward_exited")
        try:
            with socket.create_connection(("127.0.0.1", local_port), timeout=0.2):
                return local_port, child
        except OSError:
            time.sleep(0.05)
    child.terminate()
    raise TimeoutError("rehearsal:local_forward_start")


class LocalPorts(ProductionPorts):
    def __init__(self, *args, control, **kwargs):
        self.control = control
        super().__init__(*args, **kwargs)

    def aws(self, service, operation, args, *, deadline=None):
        if service in {"ec2", "ssm"}:
            return self.control.aws(service, operation, args, deadline=deadline)
        if service == "s3api":
            command = [
                self.manifest["operator_tools"]["aws"]["path"],
                "--profile",
                self.inputs["aws_profile"],
                "--region",
                self.manifest.get("region", "us-east-1"),
                "--endpoint-url",
                MINIO_ENDPOINT,
                "s3api",
                operation,
                *map(str, args),
                "--output",
                "json",
                "--no-cli-pager",
            ]
            result = run(
                command,
                timeout=max(1, int((deadline or self.deadline) - time.time())),
                env=os.environ.copy(),
            )
            return json.loads(result.stdout.decode("utf-8"))
        raise ValueError(f"rehearsal:unexpected_top_aws:{service}:{operation}")

    def command(self, argv, deadline, name):
        argv = list(argv)
        if name == "gate-a-inputs-s3-upload":
            service_index = argv.index("s3")
            argv[service_index:service_index] = ["--endpoint-url", MINIO_ENDPOINT]
        return super().command(argv, deadline, name)


def docker_exec(container, *args, input_bytes=None, timeout=120, check=True):
    return run(
        [
            "docker",
            "exec",
            *(["-i"] if input_bytes is not None else []),
            container,
            *args,
        ],
        timeout=timeout,
        input_bytes=input_bytes,
        check=check,
    )


def render_gate_a_user_data(role, recovery_volume_id):
    """Render the Gate A Terraform templatefile inputs for one rehearsal host."""
    if role not in {"receiver", "sender"}:
        raise ValueError("rehearsal:gate_a_user_data_role")
    if role == "receiver" and not recovery_volume_id:
        raise ValueError("rehearsal:gate_a_user_data_volume")
    if role == "sender" and recovery_volume_id:
        raise ValueError("rehearsal:gate_a_user_data_sender_volume")

    template = (ROOT / "infra/terraform/gate_a/host-user-data.sh").read_text(
        encoding="utf-8"
    )
    escaped_interpolation = "\x00GATE_A_ESCAPED_INTERPOLATION\x00"
    template = template.replace("$${", escaped_interpolation)
    values = {
        "role": role,
        "host_timer_seconds": str(HOST_TIMER_S),
        "recovery_volume_id": recovery_volume_id,
    }

    def replace(match):
        key = match.group(1)
        if key not in values:
            raise ValueError("rehearsal:gate_a_user_data_unbound:" + key)
        return values[key]

    rendered = re.sub(r"\$\{([^}]+)\}", replace, template)
    rendered = rendered.replace(escaped_interpolation, "${")
    if any(f"${{{key}}}" in rendered for key in values):
        raise ValueError("rehearsal:gate_a_user_data_unrendered")
    return rendered


def _gate_a_host_stubs():
    return {
        "systemctl": """#!/bin/sh
set -eu
if [ "${1-}" = is-active ]; then
  [ "${2-}" = --quiet ] || exit 2
  armed=$(cat /run/r466-systemd-run-unit 2>/dev/null || true)
  [ -n "$armed" ] && [ "${3-}" = "$armed.timer" ]
  exit $?
fi
exit 0
""",
        "systemd-run": """#!/bin/sh
set -eu
unit=
for argument in "$@"; do
  case "$argument" in --unit=*) unit=${argument#--unit=} ;; esac
done
[ -n "$unit" ] || exit 2
printf '%s\\n' "$unit" > /run/r466-systemd-run-unit
""",
        "blkid": "#!/bin/sh\nexit 0\n",
        "wipefs": "#!/bin/sh\nexit 0\n",
        "mkfs.ext4": "#!/bin/sh\nexit 0\n",
        "mount": """#!/bin/sh
set -eu
last=
for argument in "$@"; do last=$argument; done
if [ "$last" = /recovery ]; then touch /run/r466-recovery-mounted; fi
""",
        "mountpoint": """#!/bin/sh
[ "${1-}" = -q ] && [ "${2-}" = /recovery ] && [ -f /run/r466-recovery-mounted ]
""",
        "umount": """#!/bin/sh
set -eu
[ "${1-}" = /recovery ] || exit 2
rm -f /run/r466-recovery-mounted
""",
    }


def provision_host(container, role, output, certificate, minio_credentials):
    docker_exec(
        container,
        "sh",
        "-c",
        "apt-get update && apt-get install -y python3 git curl ca-certificates util-linux iproute2 procps xz-utils",
    )
    docker_exec(
        container,
        "sh",
        "-c",
        "mkdir -p /etc/systemd/system /etc/dec077 /opt/dec077 /recovery /root/.aws /tmp/r465-bootstrap-bin /usr/local/bin /dev/disk/by-id /run",
    )
    cloud_init = '#!/bin/sh\n[ "$1" = status ]\n'
    recovery_volume_id = "vol-r466-receiver-recovery" if role == "receiver" else ""
    for command, content in _gate_a_host_stubs().items():
        docker_exec(
            container,
            "sh",
            "-c",
            f"cat > /usr/local/bin/{command} && chmod 755 /usr/local/bin/{command}",
            input_bytes=content.encode(),
        )
    for command in ("systemctl", "mountpoint", "umount"):
        content = _gate_a_host_stubs()[command]
        docker_exec(
            container,
            "sh",
            "-c",
            f"cat > /usr/bin/{command} && chmod 755 /usr/bin/{command}",
            input_bytes=content.encode(),
        )
    docker_exec(
        container,
        "sh",
        "-c",
        "cat > /usr/bin/cloud-init && chmod 755 /usr/bin/cloud-init",
        input_bytes=cloud_init.encode(),
    )
    block_device = (
        "/dev/disk/by-id/nvme-Amazon_Elastic_Block_Store_"
        + recovery_volume_id.replace("-", "")
    )
    if role == "receiver":
        docker_exec(container, "mknod", block_device, "b", "7", "0")
    user_data = output / f"user-data-{role}.sh"
    rendered_user_data = render_gate_a_user_data(role, recovery_volume_id)
    user_data.write_text(rendered_user_data, encoding="utf-8", newline="\n")
    run(["docker", "cp", str(user_data), f"{container}:/tmp/r466-gate-a-user-data.sh"])
    docker_exec(
        container,
        "sh",
        "-c",
        "PATH=/tmp/r465-bootstrap-bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin bash /tmp/r466-gate-a-user-data.sh",
        timeout=60,
    )
    armed_unit = (
        docker_exec(container, "cat", "/run/r466-systemd-run-unit")
        .stdout.decode()
        .strip()
    )
    timer_readiness = (
        docker_exec(
            container,
            "systemctl",
            "is-active",
            "--quiet",
            "gate-a-maximum-lifetime.timer",
            check=False,
        ).returncode
        == 0
    )
    recovery_mounted = (
        docker_exec(
            container,
            "mountpoint",
            "-q",
            "/recovery",
            check=False,
        ).returncode
        == 0
    )
    if (role == "receiver") != recovery_mounted:
        raise ValueError("rehearsal:user_data_recovery_mount:" + role)
    run(
        [
            "docker",
            "cp",
            str(certificate),
            f"{container}:/usr/local/share/ca-certificates/r465-minio.crt",
        ]
    )
    docker_exec(container, "update-ca-certificates", timeout=60)
    credentials, config = minio_credentials
    for local, remote in (
        (credentials, "/root/.aws/credentials"),
        (config, "/root/.aws/config"),
    ):
        run(["docker", "cp", str(local), f"{container}:{remote}"])
    docker_exec(
        container, "chmod", "600", "/root/.aws/credentials", "/root/.aws/config"
    )
    docker_exec(container, "sh", "-c", "mkdir -p /tmp/r465-ssm /opt/dec077/downloads")
    relay = output / f"agent-relay-{role}.py"
    write_file(relay, RELAY_SCRIPT)
    run(["docker", "cp", str(relay), f"{container}:/opt/dec077/r465-agent-relay.py"])
    return {
        "user_data_script": "infra/terraform/gate_a/host-user-data.sh rendered as Terraform templatefile, then run with bash",
        "user_data_sha256": packet.package_sha(user_data),
        "user_data_role": role,
        "recovery_volume_id": recovery_volume_id,
        "user_data_exit": 0,
        "systemd_run_stub_recorded_unit": armed_unit,
        "timer_readiness_requires_recorded_unit": timer_readiness,
        "recovery_mount_standin_verified": recovery_mounted,
        "system_python3": docker_exec(container, "python3", "--version")
        .stdout.decode()
        .strip(),
        "cgroup_v2_file": docker_exec(
            container, "test", "-f", "/sys/fs/cgroup/cgroup.controllers"
        ).returncode
        == 0,
        "recovery_mount_standin": "synthetic block-node and stateful mount/umount stubs; actual _unmount_recovery is run",
    }


def start_tls_certificate(output):
    certificate, key = output / "r465-minio.crt", output / "r465-minio.key"
    config = write_file(
        output / "openssl.cnf",
        "[req]\n"
        "distinguished_name=dn\n"
        "x509_extensions=v3_ca\n"
        "prompt=no\n"
        "[dn]\n"
        "CN=s3.us-east-1.amazonaws.com\n"
        "[v3_ca]\n"
        "subjectAltName=DNS:s3.us-east-1.amazonaws.com\n"
        "basicConstraints=critical,CA:TRUE\n",
    )
    run(
        [
            "openssl",
            "req",
            "-x509",
            "-config",
            str(config),
            "-nodes",
            "-days",
            "3",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(key),
            "-out",
            str(certificate),
            "-subj",
            "/CN=s3.us-east-1.amazonaws.com",
            "-addext",
            "subjectAltName=DNS:s3.us-east-1.amazonaws.com",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
        ],
        timeout=60,
    )
    return certificate, key


def create_minio_and_profile(output, names):
    network = names["network"]
    run(
        [
            "docker",
            "run",
            "--detach",
            "--rm",
            "--name",
            names["minio"],
            "--network",
            network,
            "--network-alias",
            "minio",
            "--publish",
            "127.0.0.1:9000:9000",
            "--env",
            "MINIO_ROOT_USER=" + MINIO_ACCESS_KEY,
            "--env",
            "MINIO_ROOT_PASSWORD=" + MINIO_SECRET_KEY,
            MINIO_IMAGE,
            "server",
            "/data",
            "--console-address",
            ":9001",
        ],
        timeout=120,
    )
    health_end = time.time() + 90
    while time.time() < health_end:
        result = subprocess.run(
            [
                "python",
                "-c",
                "import urllib.request; urllib.request.urlopen('http://127.0.0.1:9000/minio/health/ready',timeout=2)",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        if result.returncode == 0:
            break
        time.sleep(1)
    else:
        raise TimeoutError("rehearsal:minio_health")

    credentials = output / "aws-credentials"
    config = output / "aws-config"
    credentials.write_text(
        f"[default]\naws_access_key_id = {MINIO_ACCESS_KEY}\naws_secret_access_key = {MINIO_SECRET_KEY}\n\n"
        f"[{AWS_PROFILE}]\naws_access_key_id = {MINIO_ACCESS_KEY}\naws_secret_access_key = {MINIO_SECRET_KEY}\n",
        encoding="utf-8",
        newline="\n",
    )
    config.write_text(
        f"[profile {AWS_PROFILE}]\nregion = us-east-1\ns3 =\n  addressing_style = path\n",
        encoding="utf-8",
        newline="\n",
    )
    os.chmod(credentials, 0o600)
    os.chmod(config, 0o600)
    environment = os.environ.copy()
    environment.update(
        AWS_CONFIG_FILE=str(config),
        AWS_SHARED_CREDENTIALS_FILE=str(credentials),
        AWS_PROFILE=AWS_PROFILE,
        AWS_DEFAULT_REGION="us-east-1",
        AWS_ENDPOINT_URL_S3=PRESIGN_ENDPOINT,
        AWS_EC2_METADATA_DISABLED="true",
    )
    return credentials, config, environment


def make_host_containers(output, network, volume, names):
    containers, ports, ips = {}, {}, {}
    for role in ("receiver", "sender"):
        container = names[role]
        host_port = free_port()
        ports[role] = host_port
        run(
            [
                "docker",
                "run",
                "--detach",
                "--rm",
                "--privileged",
                "--cgroupns",
                "host",
                "--name",
                container,
                "--network",
                network,
                "--publish",
                f"127.0.0.1:{host_port}:22281",
                "--volume",
                f"{volume}:/opt/dec077/downloads",
                "ubuntu:24.04",
                "sleep",
                "infinity",
            ],
            timeout=120,
        )
        containers["i-r465-" + role] = container
        inspected = json.loads(run(["docker", "inspect", container]).stdout.decode())[0]
        network_info = next(iter(inspected["NetworkSettings"]["Networks"].values()))
        ips[role] = network_info["IPAddress"]
    return containers, ports, ips


def start_https_proxy(output, network, names, certificate, key):
    run(
        [
            "docker",
            "run",
            "--detach",
            "--rm",
            "--name",
            names["proxy"],
            "--network",
            network,
            "--network-alias",
            "s3.us-east-1.amazonaws.com",
            PINNED_PYTHON_IMAGE,
            "sleep",
            "infinity",
        ],
        timeout=120,
    )
    proxy_script = write_file(output / "https-minio-proxy.py", HTTPS_PROXY_SOURCE)
    for local, remote in (
        (proxy_script, "/tmp/r465-proxy.py"),
        (certificate, "/tmp/r465.crt"),
        (key, "/tmp/r465.key"),
    ):
        run(["docker", "cp", str(local), f"{names['proxy']}:{remote}"])
    run(
        ["docker", "exec", "-d", names["proxy"], "python", "/tmp/r465-proxy.py"],
        timeout=30,
    )


def create_gate_a_inputs(output, built, bucket, session):
    output = Path(output).resolve()
    bundle_path = Path(built["input_bundle"]).resolve()
    if output not in bundle_path.parents or not bundle_path.is_file():
        raise ValueError("rehearsal:input_bundle_not_operator_local")
    key = f"gate-a/{session}/input/gate-a-inputs.tar"
    return {
        "bundle_path": bundle_path.relative_to(output).as_posix(),
        "bundle_bytes": bundle_path.stat().st_size,
        "bundle_sha256": packet.package_sha(bundle_path),
        "inventory": built["input_inventory"],
        "paths": {
            "source": "fixture",
            "fixture_proof": "fixture-proof.json",
            "sizing_proof": "sizing-proof.json",
            "spool": "spool",
            "spool_manifest": "spool-manifest.json",
            "sanitizer_specs": "sanitizer-specs.json",
            "sanitizer_key": "sanitizer-key.bin",
            "expected_archive_inventory": "expected-archive-inventory.json",
        },
        "s3_staging": {
            "bucket": bucket,
            "key": key,
            "bundle_bytes": bundle_path.stat().st_size,
            "bundle_sha256": packet.package_sha(bundle_path),
            "upload_deadline_offset_s": 3000,
        },
    }


def phase_store_receipts_verified(phase):
    stores = phase.get("store_receipt", {})
    return (
        stores.get("readback_verified") is True
        and bool(stores.get("recovery", {}).get("manifest"))
        and bool(stores.get("s3", {}).get("objects"))
    )


def phase_receipt_summary(phase):
    stores = phase["store_receipt"]
    return {
        "phase": phase["phase"],
        "readback_verified": stores["readback_verified"],
        "recovery_manifest_sha256": stores["recovery"]["manifest_sha256"],
        "s3_manifest_sha256": stores["s3"]["manifest_sha256"],
        "object_count": phase["object_count"],
    }


def make_manifest(
    output,
    built,
    *,
    session,
    bucket,
    bundle,
    source_commit,
    aws,
    omit_gate_a_inputs=False,
):
    operation_end = time.time() + 7200
    common = packet.gate_a_runner_common(
        {
            "source_commit": source_commit,
            "bundle_bytes": bundle.stat().st_size,
            "bundle_sha256": packet.package_sha(bundle),
            "python_sha256": packet.python_hashes(source_commit),
            "pins": json.loads((ROOT / "deploy/package-a/pins.json").read_bytes()),
            "python_executable": "/opt/dec077/repo/python/.venv/bin/python",
            "session_manager_plugin_path": "fixture/session-manager-plugin",
            "session": session,
            "region": "us-east-1",
            "instance_type": "c6i.2xlarge",
            "ami": "ubuntu-24.04-container-r465",
            "on_demand_usd_per_hour": 0,
            "hourly_all_resources_usd": 1,
            "prior_spend_usd": 0,
            "hard_cap_usd": 1000,
            "cleanup_cost_reserve_usd": 1,
            "deadline_epoch": None,
            "checks": [],
        }
    )
    receiver = {
        "host": "0.0.0.0",
        "port": 38473,
        "region": "us-east-1",
        "endpoint_url": "http://minio:9000",
        "bucket": bucket,
        "prefix": f"gate-a/{session}/",
        "transfer_root": "/recovery/transfers",
        "max_total_bytes": 8 * 1024**3,
        "max_objects": 1024,
        "service_timeout_s": 7200,
    }
    sender = {
        "receiver_private_address": "from_describe_instances",
        "transfer_port": 38473,
        "expected_pins": (built or {"binding": gate_a_binding()})["binding"]["pins"],
        "minimum_spool_raw_bytes": 1,
        "registered_fixture_rows": 1,
        "binding": (built or {"binding": gate_a_binding()})["binding"],
    }
    manifest = {
        "schema": "r465-gate-a-operator-rehearsal-v1",
        "session": session,
        "region": "us-east-1",
        "bucket_name": bucket,
        "bucket_prefix": f"gate-a/{session}/",
        "source_commit": source_commit,
        "bundle_bytes": bundle.stat().st_size,
        "bundle_sha256": packet.package_sha(bundle),
        "upload_timeout_s": packet.transfer_seconds(bundle.stat().st_size),
        "operator_tools": {"aws": {"path": str(aws)}},
        "session_manager_plugin_path": "fixture/session-manager-plugin",
        "hourly_all_resources_usd": 1,
        "prior_spend_usd": 0,
        "hard_cap_usd": 1000,
        "cleanup_cost_reserve_usd": 1,
        "gate_a_operation": {"operation_pass_max_ms": GATE_A_OPERATION_CUTOFF_MS},
        "retrieval_timeout_s": 300,
        "cleanup_seconds": 300,
        "gate_a_inputs": None
        if omit_gate_a_inputs
        else create_gate_a_inputs(output, built, bucket, session),
        "gate_a_runner": {
            "common": common,
            "roles": {
                "receiver": {"gate_a_receiver": receiver},
                "sender": {"gate_a_sender": sender},
            },
        },
        "operator_deadline_epoch": operation_end,
    }
    return manifest


def setup_packet_and_minio(output, names, *, require_minio):
    network = names["network"]
    credentials, config, environment = create_minio_and_profile(output, names)
    certificate, key = start_tls_certificate(output)
    if require_minio:
        start_https_proxy(output, network, names, certificate, key)
    return (credentials, config), environment, certificate


def run_rehearsal(output, *, expected_refusal=None):
    compile(READINESS_STANDIN, "<r465-readiness-standin>", "exec")
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    name = "r465-" + uuid.uuid4().hex[:10]
    names = {
        "network": name + "-network",
        "volume": name + "-downloads",
        "minio": name + "-minio",
        "proxy": name + "-tls-proxy",
        "receiver": name + "-receiver",
        "sender": name + "-sender",
    }
    containers, ports, ips = {}, {}, {}
    original_environment = os.environ.copy()
    module = sys.modules["inference_platform.package_a_operator"]
    original_ports = module.Ports
    receipt = {
        "schema": "r465-gate-a-operator-rehearsal-v1",
        "started_at_utc": datetime.now(UTC).isoformat(),
        "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT)
        .decode()
        .strip(),
        "aws_calls": 0,
        "billable_actions": 0,
        "unchanged_paths": [
            "GateAOperator.run_roles -> _run_roles",
            "GateAOperator.retrieve_roles",
            "GateAOperator._unmount_recovery",
            "infra/terraform/gate_a/host-user-data.sh rendered per role and executed under bash",
            "Ports.bootstrap readiness and bootstrap shells",
            "Ports.upload",
            "Ports.request and _runner_state",
            "Ports.upload_gate_a_inputs",
            "Ports.run_checks",
            "Ports.retrieve",
            "scripts/package_a_host.py Host protocol and frozen receipt agent",
            "package_a_cloud Runner gate_a_receiver and gate_a_sender roles",
            "gate_a_role_reexec_target locked-venv re-exec",
            "GateASenderRole real sanitizer, materializer, archive and spool transfer",
            "GateAReceiverSupervisor real TCP receiver, POSIX and MinIO stores",
        ],
        "substitutions": [
            "EC2 describe-instances and SSM responses are in-process local fixtures",
            "SSM SendCommand reads the owner-only file:// parameter file and executes its commands in the target Ubuntu container via docker exec",
            "Session Manager port forward is a local TCP forwarder to the container's package_a_host.py agent relay on port 22281 -> 127.0.0.1:22280",
            "S3 control endpoint and signed GET target local MinIO only",
            "receiver Docker-in-Docker readiness suite is a recorded stand-in; Round 324 separately passed the exact readiness suite/argv",
            "cloud-init status is a readiness stand-in; Gate A user data itself is the committed role-specific Terraform template",
            "systemd-run records its requested unit; the systemctl readiness adapter passes only when the exact recorded unit's .timer is queried",
            "block-device formatting and mount calls use a synthetic block node and stateful command stubs; the unchanged _unmount_recovery command runs against the recorded mount state",
            "AMI SSM agent registration is represented by the in-process SSM control fixture",
        ],
    }
    try:
        created = time.time()
        run(["docker", "network", "create", names["network"]])
        run(["docker", "volume", "create", names["volume"]])
        require_minio = expected_refusal is None
        if require_minio:
            (aws_files, environment, certificate) = setup_packet_and_minio(
                output, names, require_minio=True
            )
            os.environ.clear()
            os.environ.update(environment)
        else:
            # These refusal mutants stop before S3 staging. Still launch the
            # exact operator Ports sequence through the first mutated point.
            aws_files = None
            certificate, _key = start_tls_certificate(output)
        containers, ports, ips = make_host_containers(
            output, names["network"], names["volume"], names
        )

        for role in ("receiver", "sender"):
            credential_pair = aws_files or (
                output / "unused-credentials",
                output / "unused-config",
            )
            if not aws_files:
                write_file(
                    credential_pair[0],
                    "[default]\naws_access_key_id = unused\naws_secret_access_key = unused\n",
                )
                write_file(credential_pair[1], "[default]\nregion = us-east-1\n")
            provisioning = provision_host(
                containers["i-r465-" + role], role, output, certificate, credential_pair
            )
            if (
                provisioning["user_data_exit"] != 0
                or provisioning["cgroup_v2_file"] is not True
                or not provisioning["system_python3"].startswith("Python 3.")
            ):
                raise ValueError("rehearsal:host_provisioning_shape:" + role)
            receipt[role + "_provisioning"] = provisioning

        control = LocalControlPlane(containers, ips, ports, output)
        if require_minio:
            bucket = "gate-a-r465-" + uuid.uuid4().hex[:10]
            create = run(
                [
                    str(aws_executable()),
                    "--profile",
                    AWS_PROFILE,
                    "--region",
                    "us-east-1",
                    "--endpoint-url",
                    MINIO_ENDPOINT,
                    "s3api",
                    "create-bucket",
                    "--bucket",
                    bucket,
                ],
                timeout=60,
                env=os.environ.copy(),
            )
            del create
        else:
            bucket = "gate-a-r465-mutant"

        packet_dir = output / "operator-packet"
        packet_dir.mkdir()
        (packet_dir / "terraform").mkdir()
        source_commit = receipt["source_commit"]
        if expected_refusal == "receiver.upload":
            bundle = write_file(
                packet_dir / "source.bundle",
                b"missing-timeout-mutant-does-not-reach-upload-body",
            )
            built = None
        else:
            bundle = packet.make_source_bundle(packet_dir, source_commit)
            built = (
                None
                if expected_refusal == "receiver.request"
                else build_campaign_inputs(output / "campaign")
            )
            if built is not None:
                localized_bundle = packet_dir / built["input_bundle"].name
                shutil.copyfile(built["input_bundle"], localized_bundle)
                built["input_bundle"] = localized_bundle
        manifest = make_manifest(
            packet_dir,
            built,
            session="r465-rehearsal-" + uuid.uuid4().hex[:8],
            bucket=bucket,
            bundle=bundle,
            source_commit=source_commit,
            aws=aws_executable(),
            omit_gate_a_inputs=expected_refusal is not None,
        )
        if expected_refusal == "receiver.request":
            # The mutant checkout changes the production request path; the
            # missing staged input is irrelevant because refusal is earlier.
            manifest["gate_a_inputs"] = None
        manifest_path = write_file(
            packet_dir / "manifest.json",
            json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
        )

        class TopPorts(LocalPorts):
            pass

        top = TopPorts(
            packet_dir,
            manifest,
            profile=AWS_PROFILE,
            manifest_path=manifest_path,
            control=control,
        )
        top.started = created
        top.deadline = time.time() + 7200
        top.lifecycle_start_epoch = time.time()
        top.lifecycle_deadline_epoch = top.lifecycle_start_epoch + 7200
        if require_minio:
            top.manifest["gate_a_inputs"]["s3_staging"]["upload_deadline_offset_s"] = (
                7000
            )

        class RolePorts(ProductionPorts):
            def aws(self, service, operation, args, *, deadline=None):
                return control.aws(service, operation, args, deadline=deadline)

            def tunnel(self, host):
                return start_forward(
                    ports["sender" if host == "i-r465-sender" else "receiver"]
                )

        module.Ports = RolePorts
        operator = GateAOperator(top)
        operation_end = time.time() + 7200
        receipt["operator_sequence_started_at_utc"] = datetime.now(UTC).isoformat()
        try:
            run_result = operator.run_roles(operation_end)
        except BaseException as exc:
            if not expected_refusal:
                for role_ports in getattr(operator, "role_ports", []):
                    role = getattr(role_ports, "role_name", "unknown")
                    try:
                        receipt.setdefault("failed_role_status", {})[role] = json.loads(
                            role_ports.request("/status", end=operation_end)[0]
                        )
                    except BaseException as status_exc:
                        receipt.setdefault("failed_role_status", {})[role] = {
                            "error": type(status_exc).__name__ + ":" + str(status_exc)
                        }
                receipt["failed_role_retrieval"] = operator.retrieve_roles(
                    operation_end
                )
                for role_ports in getattr(operator, "role_ports", []):
                    archive = role_ports.runtime / "receipts.tar.gz"
                    if archive.is_file():
                        try:
                            receipt.setdefault("failed_runner_receipts", {})[
                                getattr(role_ports, "role_name", "unknown")
                            ] = read_archive_json(archive, "results/runner/runner.json")
                        except BaseException as receipt_exc:
                            receipt.setdefault("failed_runner_receipts", {})[
                                getattr(role_ports, "role_name", "unknown")
                            ] = {
                                "error": type(receipt_exc).__name__
                                + ":"
                                + str(receipt_exc)
                            }
                receipt.update(
                    complete=False, refusal=type(exc).__name__ + ":" + str(exc)
                )
                save(output / "partial-receipt.json", receipt)
            if expected_refusal:
                text = type(exc).__name__ + ":" + str(exc)
                receipt["mutant_refusal"] = text
                receipt["mutant_stop"] = expected_refusal
                if expected_refusal == "receiver.upload" and not (
                    isinstance(exc, KeyError) and exc.args == ("upload_timeout_s",)
                ):
                    raise RuntimeError(
                        "rehearsal:wrong_upload_timeout_mutant_refusal:" + text
                    ) from exc
                if expected_refusal == "receiver.request" and not (
                    "unknown_path" in text or "host control 409" in text
                ):
                    raise RuntimeError(
                        "rehearsal:wrong_role_sequence_mutant_refusal:" + text
                    ) from exc
                if expected_refusal == "receiver.readiness":
                    failed_steps = [
                        getattr(role_ports, "last_ssm_failure", {}).get("step")
                        for role_ports in getattr(operator, "role_ports", [])
                    ]
                    receipt["mutant_failure_steps"] = failed_steps
                    if not any(
                        isinstance(step, str) and step.endswith(expected_refusal)
                        for step in failed_steps
                    ):
                        raise RuntimeError(
                            "rehearsal:wrong_timer_mutant_refusal:" + text
                        ) from exc
                receipt["mutant_killed"] = True
                return receipt
            raise
        if expected_refusal:
            raise AssertionError("rehearsal:mutant_survived:" + expected_refusal)

        retrieval = operator.retrieve_roles(operation_end)
        if not retrieval.get("complete") or not run_result.get("complete"):
            raise ValueError("rehearsal:role_retrieval_incomplete")
        roles = {getattr(item, "role_name", ""): item for item in operator.role_ports}
        sender_archive = roles["sender"].runtime / "receipts.tar.gz"
        receiver_archive = roles["receiver"].runtime / "receipts.tar.gz"
        sender_runner = read_archive_json(sender_archive, "results/runner/runner.json")
        sender_result = sender_runner["gate_a_sender"]
        receiver_runner = read_archive_json(
            receiver_archive, "results/runner/runner.json"
        )
        receiver_result = receiver_runner["gate_a_receiver"]
        if (
            sender_runner.get("status") != "PASS"
            or sender_result.get("status") != "PASS"
            or sender_result.get("verdict", {}).get("status") != "PASS"
            or len(sender_result.get("phase_receipts", [])) != 2
            or receiver_runner.get("status") != "PASS"
            or len(receiver_result.get("phases", [])) != 2
        ):
            raise ValueError("rehearsal:sender_or_receiver_verdict")
        for phase in sender_result["phase_receipts"]:
            if not phase_store_receipts_verified(phase):
                raise ValueError(
                    "rehearsal:phase_store_ack_readback:" + str(phase.get("phase"))
                )
        full_retrieval = sender_result["phase_receipts"][-1].get("full_retrieval", {})
        if (
            full_retrieval.get("complete") is not True
            or set(full_retrieval.get("stores", {})) != {"recovery", "s3"}
            or full_retrieval.get("inventories_equal") is not True
        ):
            raise ValueError("rehearsal:two_store_full_retrieval")

        teardown = GateAOperator(top)._unmount_recovery(
            "i-r465-receiver", operation_end
        )
        if teardown.get("status") != "Success":
            raise ValueError("rehearsal:recovery_unmount")
        for role, container in (
            ("sender", containers["i-r465-sender"]),
            ("receiver", containers["i-r465-receiver"]),
        ):
            marker = (
                docker_exec(container, "cat", "/opt/dec077/r465-locked-interpreter.txt")
                .stdout.decode()
                .strip()
            )
            expected = "/opt/dec077/repo/python/.venv/bin/python"
            if marker != expected:
                raise ValueError(
                    "rehearsal:role_did_not_reexec_locked_venv:" + role + ":" + marker
                )

        receipt.update(
            complete=True,
            sender_verdict=sender_result["verdict"],
            sender_operation_ms=sender_result["operation_ms"],
            operation_cutoff_ms=GATE_A_OPERATION_CUTOFF_MS,
            this_is_not_a_gate_a_measurement=True,
            sender_phase_receipts=[
                phase_receipt_summary(phase)
                for phase in sender_result["phase_receipts"]
            ],
            two_store_retrieval=full_retrieval,
            retrieve_roles={
                "complete": retrieval["complete"],
                "roles": sorted(retrieval["roles"]),
            },
            frozen_receipts={
                "sender": {
                    "bytes": sender_archive.stat().st_size,
                    "sha256": packet.package_sha(sender_archive),
                },
                "receiver": {
                    "bytes": receiver_archive.stat().st_size,
                    "sha256": packet.package_sha(receiver_archive),
                },
            },
            locked_venv={
                role: "/opt/dec077/repo/python/.venv/bin/python"
                for role in ("receiver", "sender")
            },
            host_steps={"unmount_recovery": teardown},
            input_bundle={
                "bytes": built["input_bundle"].stat().st_size,
                "sha256": packet.package_sha(built["input_bundle"]),
                "members": built["input_inventory"],
            },
            fixture={
                "files": len(built["fixture_inventory"]),
                "bytes": sum(
                    row["bytes"] for row in built["fixture_inventory"].values()
                ),
                "spool_objects": len(built["spool_inventory"]),
                "sizing_raw_bytes": built["sizing"]["raw_bytes"],
            },
            control_fixture_calls=control.calls,
        )
        return receipt
    except BaseException as exc:
        receipt.update(complete=False, refusal=type(exc).__name__ + ":" + str(exc))
        save(output / "partial-receipt.json", receipt)
        raise
    finally:
        module.Ports = original_ports
        os.environ.clear()
        os.environ.update(original_environment)
        for container in containers.values():
            subprocess.run(
                ["docker", "rm", "-f", container],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=60,
            )
        for container in (names["proxy"], names["minio"]):
            subprocess.run(
                ["docker", "rm", "-f", container],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=60,
            )
        for private_path in (
            output / "aws-credentials",
            output / "aws-config",
            output / "r465-minio.key",
        ):
            try:
                private_path.unlink()
            except FileNotFoundError:
                pass
        subprocess.run(
            ["docker", "volume", "rm", "-f", names["volume"]],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=60,
        )
        subprocess.run(
            ["docker", "network", "rm", names["network"]],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=60,
        )


def forward_main(argv):
    local_port, target_port = map(int, argv)
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", local_port))
    listener.listen(64)

    def handle(client):
        try:
            remote = socket.create_connection(("127.0.0.1", target_port), timeout=30)
            ready, _, _ = __import__("select").select([client, remote], [], [], 30)
            while ready:
                source = ready[0]
                data = source.recv(65536)
                if not data:
                    return
                (remote if source is client else client).sendall(data)
                ready, _, _ = __import__("select").select([client, remote], [], [], 30)
        except OSError:
            pass
        finally:
            client.close()

    while True:
        connection, _ = listener.accept()
        threading.Thread(target=handle, args=(connection,), daemon=True).start()


def main():
    if len(sys.argv) == 4 and sys.argv[1] == "--forward":
        forward_main(sys.argv[2:])
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--expect-refusal",
        choices=("receiver.upload", "receiver.request", "receiver.readiness"),
    )
    args = parser.parse_args()
    try:
        result = run_rehearsal(args.output, expected_refusal=args.expect_refusal)
        save(args.output / "receipt.json", result)
        print(
            json.dumps(
                {
                    "complete": result.get("complete", False),
                    "mutant_killed": result.get("mutant_killed"),
                    "sender_verdict": result.get("sender_verdict", {}).get("status"),
                    "retrieve_roles_complete": result.get("retrieve_roles", {}).get(
                        "complete"
                    ),
                    "output": str(args.output.resolve()),
                },
                sort_keys=True,
            )
        )
        return 0
    except BaseException as exc:
        if args.output.exists():
            failure_path = args.output / "failure.json"
            save(failure_path, {"error": type(exc).__name__, "message": str(exc)})
        print(type(exc).__name__ + ": " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
