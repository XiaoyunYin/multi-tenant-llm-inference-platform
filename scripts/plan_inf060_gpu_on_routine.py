"""Create saved read-only INF-060 plans with the routine host's provider."""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import boto3
from inf060_eks_gpu_plan import provider_inputs, verify_gpu_streaming_plan
from inference_platform.inf060_eks_packet import file_sha

STAGED = Path("/opt/dec077/gate-a-inputs")


def main(output):
    runtime = json.loads(Path("/opt/dec077/runtime.json").read_bytes())
    request = json.loads((STAGED / "provider-request.json").read_bytes())
    if (
        runtime["role"] != "routine_tests"
        or request["source_commit"] != runtime["source_commit"]
        or request["inputs"] != provider_inputs(STAGED, request["roots"])
    ):
        raise ValueError("streaming_provider_request_binding")
    scratch = Path(".cache/inf060-provider-plan").resolve()
    shutil.copytree(STAGED, scratch)
    cache = scratch / "provider-cache"
    cache.mkdir()
    output.mkdir()
    terraform = shutil.which("terraform")
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith(("AWS_PROFILE", "TF_CLI_ARGS"))
    }
    # Package A's provider block disables its own IMDS discovery. Only
    # this host's instance-role lease reaches the Terraform subprocess.
    credentials = boto3.Session(region_name="us-east-1").get_credentials()
    if credentials is None or credentials.method != "iam-role":
        raise ValueError("streaming_provider_instance_role_required")
    lease = credentials.get_frozen_credentials()
    env.update(
        AWS_ACCESS_KEY_ID=lease.access_key,
        AWS_SECRET_ACCESS_KEY=lease.secret_key,
        AWS_SESSION_TOKEN=lease.token,
    )
    env["TF_PLUGIN_CACHE_DIR"] = str(cache)
    version = json.loads(
        subprocess.check_output([terraform, "version", "-json"], env=env)
    )
    if version["terraform_version"] != "1.16.2":
        raise ValueError("streaming_provider_terraform_version")
    records = {}
    for name in request["roots"]:
        root = scratch / name
        target = output / name
        target.mkdir()
        subprocess.run(
            [terraform, "init", "-backend=false", "-lockfile=readonly", "-input=false"],
            cwd=root,
            env=env,
            timeout=300,
            check=True,
        )
        subprocess.run(
            [
                terraform,
                "plan",
                "-refresh=false",
                "-input=false",
                "-var-file=input.tfvars.json",
                "-out=create.tfplan",
            ],
            cwd=root,
            env=env,
            timeout=300,
            check=True,
        )
        with (target / "show.stdout").open("xb") as stream:
            subprocess.run(
                [terraform, "show", "-json", "create.tfplan"],
                cwd=root,
                env=env,
                timeout=120,
                stdout=stream,
                check=True,
            )
        if name.startswith("zone-"):
            verify_gpu_streaming_plan(json.loads((target / "show.stdout").read_bytes()))
        if any(root.glob("*.tfstate*")):
            raise ValueError("streaming_provider_state_created")
        shutil.copyfile(root / "create.tfplan", target / "create.tfplan")
        records[name] = {
            file: file_sha(target / file) for file in ("create.tfplan", "show.stdout")
        }
    (output / "provider-plans.json").write_text(
        json.dumps(
            {
                "request": request,
                "plans": records,
                "terraform": version,
                "applied": False,
                "credential_source": "routine_instance_role",
            },
            sort_keys=True,
        )
        + "\n"
    )


if __name__ == "__main__":
    main(Path(sys.argv[1]))
