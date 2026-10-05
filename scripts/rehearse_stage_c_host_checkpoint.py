"""Check the actual session callback in a separate Linux host reading a capture bind mount."""

import argparse
import hashlib
import json
import subprocess
import time
from pathlib import Path


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def rehearse(payload, capture_store, output, session_name):
    manifest = json.loads(
        (payload / "staging-manifest.json").read_text(encoding="utf-8")
    )
    for row in manifest["files"]:
        if sha(payload / "sources" / row["path"]) != row["sha256"]:
            raise ValueError(
                "checkpoint test source differs from committed payload manifest"
            )
    observations = capture_store / "capture.observations.jsonl"
    size = observations.stat().st_size
    if size < 300 * 1024**2:
        raise ValueError("realistic observations must be at least 300 MiB")
    if (
        Path(session_name).name != session_name
        or (capture_store / session_name).exists()
    ):
        raise ValueError("use a fresh, single-component host session name")
    expected = json.loads((capture_store / "receipt.json").read_text(encoding="utf-8"))
    code = """import json,sys,time
from pathlib import Path
from types import SimpleNamespace
from inference_platform.stage_c_checkpoint import checkpoint_run,file_sha
root=Path('/opt/inf011/capture-private')
session=root/sys.argv[1]
session.mkdir(mode=0o700)
(session/'gateway.log').write_text('')
config=SimpleNamespace(kv_capture_output_path=str(root/'capture.json'),decision_prompt_export_path='/absent-checkpoint-prompts')
rows=[]
for n in range(1,5):
    started=time.perf_counter()
    run={'status':'completed','levels':[]}
    sealed=checkpoint_run(session,n,run,config)
    assert sealed and not run.get('checkpoint'), 'degraded seal cannot pass the realistic-path test'
    sealed['elapsed_seconds']=time.perf_counter()-started
    rows.append(sealed)
print(json.dumps({'status':'passed','observations_bytes':(root/'capture.observations.jsonl').stat().st_size,
    'observations_sha256':file_sha(root/'capture.observations.jsonl'),'checkpoints':rows}))
"""
    # Four full local archive compressions, budgeted at a conservative 1 MiB/s,
    # plus 60 seconds of startup/hash/reaping overhead. No Docker copy occurs.
    timeout = 60 + 4 * size / 1024**2
    image = "python:3.12-slim-bookworm"
    command = [
        "docker",
        "run",
        "--rm",
        "--cpus",
        "2",
        "--memory",
        "6g",
        "--memory-swap",
        "6g",
        "--network",
        "none",
        "--mount",
        f"type=bind,source={payload.resolve() / 'sources/python/src'},target=/opt/inf011/python/src,readonly",
        "--mount",
        f"type=bind,source={capture_store.resolve()},target=/opt/inf011/capture-private",
        "-e",
        "PYTHONDONTWRITEBYTECODE=1",
        "-e",
        "PYTHONPATH=/opt/inf011/python/src",
        image,
        "python",
        "-c",
        code,
        session_name,
    ]
    started = time.perf_counter()
    result = subprocess.run(command, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(
            f"independent host checkpoint failed with exit {result.returncode}"
        )
    host = json.loads(result.stdout)
    if (
        host["observations_bytes"] != size
        or host["observations_sha256"]
        != expected["real_branch_checkpoints"]["observations_sha256"]
    ):
        raise ValueError(
            "host did not read the capture writer's exact observation bytes"
        )
    if len(host["checkpoints"]) != 4 or any(
        not row["sealed_before_next_run"] for row in host["checkpoints"]
    ):
        raise ValueError("four actual host seals required")
    host.update(
        schema="inf011-independent-host-checkpoint.v1",
        source_commit=manifest["source_commit"],
        manifest_sha256=sha(payload / "staging-manifest.json"),
        bundle_sha256=sha(payload / "payload.tar.gz"),
        test_script_sha256=sha(Path(__file__)),
        elapsed_seconds=time.perf_counter() - started,
        size_derived_timeout_seconds=timeout,
        image=image,
        cpus=2,
        memory_bytes=6 * 1024**3,
        host_session=session_name,
        aws_calls_made=False,
        raw_prompt_token_inputs_included=False,
        basis="Actual session checkpoint_run callback in separate Linux host process, same writable bind mount as capture writer; no Docker cp, no GPU/AWS. Empty decision population gives unestablished lag, not a GPU measurement.",
    )
    output.write_text(json.dumps(host, indent=2) + "\n", encoding="utf-8", newline="\n")
    return host


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--payload", type=Path, required=True)
    parser.add_argument("--capture-store", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--host-session", default="independent-host-session")
    args = parser.parse_args()
    receipt = rehearse(args.payload, args.capture_store, args.output, args.host_session)
    print(
        json.dumps(
            {
                "status": receipt["status"],
                "observations_bytes": receipt["observations_bytes"],
                "four_host_seals": len(receipt["checkpoints"]),
            }
        )
    )
