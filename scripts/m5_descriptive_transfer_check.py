"""DEC-099 only: real laptop/SSM/Host payload transfer and failure controls."""

import hashlib
import json
import shlex
import time
from pathlib import PurePosixPath

from inference_platform.m5_descriptive_operator import execute, session_timing
from inference_platform.package_a_operator import Ports
from inference_platform.session_stop import stop_forward
from m5_descriptive_diagnostics import write_cost
from m5_descriptive_eks import EKSports
from m5_descriptive_payload import produce, transfer_bound


def publish_transfer_record(ssm, result, root="/opt/dec077"):
    # Runner deliberately creates results/runner with exist_ok=False. Nothing
    # in this pre-bootstrap validation may create that tree ahead of it.
    target = PurePosixPath(root) / "payload-transfer.json"
    data = json.dumps(result)
    response = ssm(
        "set -eu; printf '%s' "
        + shlex.quote(data)
        + " > "
        + shlex.quote(str(target))
        + "; sha256sum "
        + shlex.quote(str(target))
    )
    if not response["StandardOutputContent"].startswith(
        hashlib.sha256(data.encode()).hexdigest() + " "
    ):
        raise ValueError("descriptive:transfer_marker_readback")


def run(owner, end, root):
    directory = owner.directory / "payload-validation"
    directory.mkdir()
    payload = directory / "source.bundle"
    binding = produce(root, owner.manifest["source_commit"], payload)
    data_hash = hashlib.sha256(payload.read_bytes()).hexdigest()
    manifest = {
        **owner.manifest,
        "role": "descriptive_operator",
        "source_payload": binding,
        "bundle_bytes": payload.stat().st_size,
        "bundle_sha256": data_hash,
        "upload_timeout_s": transfer_bound(payload.stat().st_size),
    }
    manifest_path = directory / "manifest.json"
    manifest_path.write_text(json.dumps(manifest))
    ports = Ports(
        directory,
        manifest,
        profile=owner.inputs["aws_profile"],
        manifest_path=manifest_path,
    )
    ports.host, ports.started = owner.host, time.time()
    ports.inputs["ssm_remote_port"] = 22281
    ports.deadline = end

    def ssm(code):
        return owner.ssm(
            owner.host,
            [code],
            timeout_s=min(120, max(1, int(end - time.time()))),
            step="descriptive.payload_validation",
        )

    def launch(host_root):
        program = (
            "import sys;sys.path.insert(0,'/opt/dec077/repo/scripts');"
            "from package_a_host import Host,server;"
            f"server(Host({host_root!r},{ports.token!r},{ports.manifest_hash!r},{end!r}),22281).serve_forever()"
        )
        ssm(
            "set -eu; mkdir -p "
            + shlex.quote(host_root)
            + "; nohup python3 -c "
            + shlex.quote(program)
            + " >"
            + host_root
            + "/agent.log 2>&1 </dev/null & echo $! >"
            + host_root
            + "/agent.pid"
        )
        ports.request("/manifest", ports.manifest_bytes, end=end)

    def stop(host_root):
        if ports.child:
            stop_forward(ports.child)
            ports.child = None
        ssm(
            "set -eu; p=$(cat "
            + host_root
            + "/agent.pid); kill $p; i=0; while kill -0 $p 2>/dev/null; do i=$((i+1)); test $i -lt 20; sleep 1; done"
        )
        return {
            "complete": True,
            "scope": "isolated CPU-host agent stopped; routine host lifecycle owns AWS cleanup",
        }

    forced = directory / "forced-halt"
    forced.mkdir()
    forced_root = "/opt/dec100-payload-forced"
    launch(forced_root)
    with payload.open("rb") as source:
        chunk = source.read(1024**2)
    ports.request(
        "/upload/0",
        chunk,
        {"X-Chunk-SHA256": hashlib.sha256(chunk).hexdigest()},
        end=end,
    )
    harness = EKSports.__new__(EKSports)
    harness.directory, harness.host, harness.end = forced, ports, end
    harness.diagnostic_root = forced_root
    harness.bootstrap_complete = False
    # Reproduce a real failed upload: its narrow RPC deadline is exhausted.
    # The collector must enter the still-bounded export phase itself.
    ports.deadline = time.time() - 1
    harness.manifest = {"timing": session_timing(640)}
    harness.substitutions = [
        "DEC-099 CPU host; no product provisioning; forced pre-bootstrap failure; isolated test agent teardown"
    ]
    harness.provision = lambda: (_ for _ in ()).throw(
        RuntimeError("forced_prebootstrap_halt")
    )
    harness.teardown = lambda: stop(forced_root)
    harness.inventory = lambda: {
        "complete": True,
        "scope": "no product resources created by forced control",
    }
    (forced / "manifest.json").write_text(
        json.dumps(
            {
                "forecast_basis": {
                    "hourly_usd": owner.manifest["hourly_all_resources_usd"],
                    "fixed_other_usd": 10,
                    "margin": 1.25,
                },
                "host_manifest": {"prior_spend_usd": 0},
            }
        )
    )
    consumed = forced / "consumed.json"
    consumed.write_text(json.dumps({"started_epoch": time.time()}))
    try:
        execute(
            harness,
            forced / "execution",
            deadline=time.monotonic() + max(1, end - time.time()),
            rehearsal=True,
        )
    except RuntimeError as error:
        if str(error) != "forced_prebootstrap_halt":
            raise
    finally:
        write_cost(forced)
        # This is a declared CPU control fixture, never a product consume.
        consumed.rename(forced / "consumed-control-fixture.json")
    receipt = json.loads((forced / "execution/receipt.json").read_bytes())
    if receipt.get("cleanup_errors") or not json.loads(
        (forced / "prebootstrap-diagnostics.json").read_bytes()
    ).get("complete"):
        raise ValueError("descriptive:forced_halt_evidence")
    partial = json.loads((forced / "prebootstrap-diagnostics.json").read_bytes())[
        "partial_upload"
    ]
    if (
        partial["bytes"] != len(chunk)
        or partial["sha256"] != hashlib.sha256(chunk).hexdigest()
        or not partial["hash_complete"]
        or not partial["stable"]
    ):
        raise ValueError("descriptive:forced_halt_partial_binding")

    ports.reconnects, ports.forward_sessions = 0, 0
    host_root = "/opt/dec100-payload"
    launch(host_root)
    started = time.time()
    try:
        staged = ports.upload(end)
        elapsed = time.time() - started
        check = (
            "import json,sys;sys.path.insert(0,'/opt/dec077/repo/scripts');"
            "from pathlib import Path;from package_a_host import verify_sparse_payload;"
            "root=Path('/opt/dec100-payload/repo');"
            "binding=json.loads(" + repr(json.dumps(binding)) + ");"
            "p=root/'python/src/inference_platform/m5_descriptive.py';"
            "old=p.read_bytes();p.write_bytes(old+b'\\n# changed tree negative control\\n');"
            "\ntry:\n verify_sparse_payload(root,binding)\nexcept ValueError as e:\n"
            " assert str(e).startswith('descriptive:payload_tree:python'),str(e);print('CHANGED_TREE_REFUSED='+str(e))\n"
            "else:\n raise RuntimeError('changed tree accepted')\n"
            "finally:\n p.write_bytes(old)\n"
            "verify_sparse_payload(root,binding)"
        )
        response = ssm("python3 - <<'DEC100_NEGATIVE'\n" + check + "\nDEC100_NEGATIVE")
        if (
            "CHANGED_TREE_REFUSED=descriptive:payload_tree:python"
            not in response["StandardOutputContent"]
        ):
            raise ValueError("descriptive:negative_tree_witness")
        chunks = [
            json.loads(line)
            for line in (ports.runtime / "source-transfer.jsonl")
            .read_text()
            .splitlines()
        ]
        result = {
            "complete": True,
            "source_commit": owner.manifest["source_commit"],
            "payload_bytes": payload.stat().st_size,
            "payload_sha256": data_hash,
            "binding": binding,
            "elapsed_s": elapsed,
            "bytes_per_s": payload.stat().st_size / elapsed,
            "reconnects": ports.reconnects,
            "forward_sessions": ports.forward_sessions,
            "chunks": chunks,
            "staged": staged,
            "changed_tree_refused": True,
            "forced_halt_records": [
                "forced-halt/prebootstrap-diagnostics.json",
                "forced-halt/operator-cost.json",
            ],
            "host_payload_root": host_root + "/repo",
        }
        (directory / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        # Host-side rehearsal consumes this same already-verified materialization.
        publish_transfer_record(ssm, result)
        return result
    finally:
        stop(host_root)
