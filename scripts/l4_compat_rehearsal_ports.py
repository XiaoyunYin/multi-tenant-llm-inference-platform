"""Fail-closed provider substitutions installed ONLY by the $0 entrypoint.

No production import or environment switch enables these substitutions. A scratch
sitecustomize explicitly imports this module in the rehearsal's child processes.
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

from inference_platform import package_a_operator as operator

ROOT = Path(os.environ["L4_REHEARSAL_ROOT"])
HOST = os.environ["L4_REHEARSAL_HOST"]


def record(stage, started, code, **fields):
    path = Path(os.environ["L4_ATTEMPT_DIRECTORY"]) / "stages.jsonl"
    with path.open("a") as stream:
        stream.write(
            json.dumps(
                {
                    "stage": stage,
                    "exit_code": code,
                    "elapsed_seconds": time.monotonic() - started,
                    **fields,
                }
            )
            + "\n"
        )


def aws(self, service, operation, args, **kwargs):
    applied = (ROOT / "fake-applied").exists()
    if (service, operation) == ("sts", "get-caller-identity"):
        return {"Account": "rehearsal-account"}
    if operation == "describe-images":
        return {"Images": [{"ImageId": self.manifest["ami"], "State": "available"}]}
    if operation == "describe-instance-types":
        return {
            "InstanceTypes": [
                {
                    "InstanceType": "g6.xlarge",
                    "VCpuInfo": {"DefaultVCpus": 4},
                    "GpuInfo": {"Gpus": [{"Count": 1, "Name": "L4"}]},
                }
            ]
        }
    if operation == "describe-instance-type-offerings":
        return {
            "InstanceTypeOfferings": [
                {"Location": "us-east-1a", "InstanceType": "g6.xlarge"}
            ]
        }
    if service == "service-quotas":
        return {"Quota": {"Value": 4}}
    if service == "pricing":
        query = next(
            k
            for k, v in self.manifest["preflight_queries"].items()
            if v[:2] == [service, operation] and v[2:] == args
        )
        unit, price = {
            "compute": ("Hrs", "0.8048"),
            "gp3": ("GB-Mo", "0.08"),
            "ipv4": ("Hrs", "0.005"),
        }[query]
        prices = (
            [price, "0.81"]
            if query == "compute" and os.environ["L4_REHEARSAL_REFUSAL"] == "1"
            else [price]
        )
        return {
            "PriceList": [
                json.dumps(
                    {
                        "terms": {
                            "OnDemand": {
                                "fake": {
                                    "priceDimensions": {
                                        str(i): {
                                            "unit": unit,
                                            "pricePerUnit": {"USD": p},
                                        }
                                        for i, p in enumerate(prices)
                                    }
                                }
                            }
                        }
                    }
                )
            ]
        }
    if operation == "describe-instances":
        return {
            "Reservations": [
                {
                    "Instances": [
                        {"InstanceId": "i-rehearsal", "State": {"Name": "running"}}
                    ]
                }
            ]
            if applied
            else []
        }
    if operation == "describe-instance-information":
        return {"InstanceInformationList": [{"PingStatus": "Online"}]}
    if operation == "terminate-instances":
        (ROOT / "fake-applied").unlink(missing_ok=True)
        return {}
    keys = {
        "describe-volumes": "Volumes",
        "describe-network-interfaces": "NetworkInterfaces",
        "describe-vpcs": "Vpcs",
        "list-roles": "Roles",
        "list-instance-profiles": "InstanceProfiles",
    }
    if operation in keys:
        return {keys[operation]: []}
    raise RuntimeError(f"unimplemented_fake_provider:{service}:{operation}")


def command(self, argv, deadline, name):
    started = time.monotonic()
    # Exercise the same reservation behavior while replacing the external tool.
    output = self.runtime / (name + ".log")
    with output.with_suffix(".reserved").open("xb"):
        pass
    if name == "apply":
        (ROOT / "fake-applied").touch()
    elif name == "destroy":
        (ROOT / "fake-applied").unlink(missing_ok=True)
    elif name not in ("init", "wait-terminated"):
        raise RuntimeError("unimplemented_fake_command:" + name)
    output.write_text("REHEARSAL external tool substituted: " + name + "\n")
    record("provider-command:" + name, started, 0)
    return {"exit_code": 0}


def ssm(self, host, commands, *, timeout_s=None):
    started = time.monotonic()
    # Literal production list, joined exactly as AWS-RunShellScript does.
    result = subprocess.run(
        ["docker", "exec", "-i", HOST, "sh"],
        input=("\n".join(commands) + "\n").encode(),
        capture_output=True,
        timeout=timeout_s,
    )
    count = len(list(self.runtime.glob("ssm-*.log")))
    (self.runtime / f"ssm-{count}.log").write_bytes(result.stdout + result.stderr)
    # Store command hashes, never the plaintext control token.
    import hashlib

    record(
        "ssm-shell",
        started,
        result.returncode,
        command_sha256=hashlib.sha256(
            ("\n".join(commands) + "\n").encode()
        ).hexdigest(),
    )
    result.check_returncode()
    return {"Status": "Success"}


def tunnel(self, host):
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(4200)"],
        start_new_session=os.name != "nt",
    )
    return int(os.environ["L4_REHEARSAL_PORT"]), child


def install():
    operator.Ports.aws = aws
    operator.Ports.command = command
    operator.Ports.ssm = ssm
    operator.Ports.tunnel = tunnel
    # Explicit substitution, never a real marker and never written to REVIEW.
    operator.validate_review_marker = lambda *args, **kwargs: None
    for name in ("upload", "run_checks", "retrieve", "teardown"):
        original = getattr(operator.Ports, name)

        def observed(self, *args, _name=name, _original=original, **kwargs):
            started = time.monotonic()
            code = 1
            try:
                result = _original(self, *args, **kwargs)
                code = 0
                return result
            finally:
                record(_name, started, code)

        setattr(operator.Ports, name, observed)
