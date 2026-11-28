"""Provision the dedicated CPU operator and retrieve a durable SSM witness."""

import argparse
import base64
import hashlib
import io
import inspect
import json
import os
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import tarfile
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

from inference_platform.r1_cloud_operator import Operator

from inf060_apply import cloudtrail_create_readback
import inf060_diagnostics as diagnostics
import inf060_operator_packet as remote
import inf060_probe_results as results
import inf060_probe_spec as spec
import inf061_packet as benchmark
from inf060_operator_memory import record_launch_gate
from inf060_probe_operator import checked_packet, synthetic_review
from prepare_inf060_probe import ROOT, git
from inference_platform.session_stop import stop_forward


def tagged_inventory(ports, session):
    tag = "Name=tag:Session,Values=" + session
    counts = {}
    for name, operation, key in (
        ("volumes", "describe-volumes", "Volumes"),
        ("interfaces", "describe-network-interfaces", "NetworkInterfaces"),
        ("vpcs", "describe-vpcs", "Vpcs"),
        ("subnets", "describe-subnets", "Subnets"),
        ("security_groups", "describe-security-groups", "SecurityGroups"),
        ("route_tables", "describe-route-tables", "RouteTables"),
        ("gateways", "describe-internet-gateways", "InternetGateways"),
        ("addresses", "describe-addresses", "Addresses"),
    ):
        counts[name] = len(ports.aws("ec2", operation, ["--filters", tag])[key])
    vms = ports.aws(
        "ec2",
        "describe-instances",
        [
            "--filters",
            tag,
            "Name=instance-state-name,Values=pending,running,shutting-down,stopping,stopped",
        ],
    )["Reservations"]
    counts["active_instances"] = sum(len(r["Instances"]) for r in vms)
    for name, op, key, field in (
        ("roles", "list-roles", "Roles", "RoleName"),
        (
            "profiles",
            "list-instance-profiles",
            "InstanceProfiles",
            "InstanceProfileName",
        ),
    ):
        counts[name] = sum(
            r[field].startswith(session + "-") for r in ports.aws("iam", op, [])[key]
        )
    return {**counts, "empty": not any(counts.values())}


def cleanup_branch(independent, *, witness=None, preapply=None, capacity=False):
    remote.require_zero(independent, state=False, capacity=capacity)
    if witness is not None:
        spec.check(witness.get("destroy_completed") is True, "gpu_destroy_unverified")
        remote.require_zero(witness.get("inventory", {}), capacity=capacity)
        return "verified_gpu_teardown"
    spec.check(not capacity, "capacity_teardown_witness_required")
    spec.check(
        preapply is not None
        and preapply.get("service_terminal") is True
        and preapply.get("supervisor_lock_absent") is True
        and type(preapply.get("terraform_resources")) is int
        and preapply["terraform_resources"] == 0
        and (
            preapply.get("consume_absent") is True
            or preapply.get("state_present") is True
        ),
        "gpu_teardown_ambiguous",
    )
    return "gpu_never_applied_or_empty_state"


def rehearse_principal(stack, manifest):
    from inf060_policy_gate import require_allowed, simulate

    root = stack.packet / "operator-host"
    name = manifest["operator_host"]["session"] + "-cpu"
    row = stack.ports.aws("iam", "get-role", ["--role-name", name])["Role"]
    account = row["Arn"].split(":")[4]
    spec.check(
        hashlib.sha256(account.encode()).hexdigest() == manifest["account_id_sha256"]
        and row["RoleName"] == name,
        "principal_role_binding",
    )
    traced = spec.load(root / "actions.json")["provider"]["events"]
    reads = {
        ("iam" if event["event_source"] == "iam.amazonaws.com" else "ec2")
        + ":"
        + event["event_name"]
        for event in traced
        if event["phase"] == "destroy"
        and event["event_source"] in {"iam.amazonaws.com", "ec2.amazonaws.com"}
        and event["event_name"].startswith(("Describe", "Get", "List"))
    }
    actions = reads | {
        "ec2:ModifyInstanceAttribute",
        "ec2:DescribeInstanceAttribute",
        "ec2:TerminateInstances",
    }
    result = simulate(
        stack.ports.aws,
        None,
        sorted(actions),
        account,
        manifest["session"],
        spec.AMI,
        role=row["Arn"],
        zone=manifest["zone"],
    )
    require_allowed(result)
    spec.save(
        stack.run / "principal-simulation.json", {"role": name, "results": result}
    )


def observer_window(manifest):
    from inf060_allow_side import ALLOW_SIDE_SECONDS

    return 120 + (
        ALLOW_SIDE_SECONDS if "actions_sha256" in manifest["operator_host"] else 0
    )


def preapply_readback(ports, host):
    # Use stdlib and the absolute packet path. This also works if source
    # discovery or imports prevented the service from starting.
    code = """
import json,subprocess
from pathlib import Path
p = Path(PACKET)
raw = subprocess.check_output(
    ['systemctl', 'show', 'inf060-native.service', '--property=ActiveState,MainPID,Result,ExecMainStatus'],
    text=True, timeout=15,
)
unit = dict(line.split('=', 1) for line in raw.splitlines())
state = p / 'terraform/terraform.tfstate'
backups = list(state.parent.glob('terraform.tfstate*'))
state_present = state.is_file()
terraform = json.loads(state.read_bytes())['resources'] if state_present else []
if not isinstance(terraform, list):
    raise ValueError('invalid state resources')
print(json.dumps({
    'service_terminal': unit.get('ActiveState') in {'failed','inactive'} and unit.get('MainPID') == '0',
    'service_result': unit.get('Result'),
    'service_exit': int(unit['ExecMainStatus']),
    'supervisor_lock_absent': not (p/'supervisor.lock').exists() and not (p/'supervisor/supervisor.lock').exists(),
    'consume_absent': not (p/'consumed.json').exists(),
    'state_present': state_present,
    'terraform_resources': len(terraform) if state_present or not backups else None,
}))
"""
    command = [
        "env",
        "-i",
        "PATH=/usr/bin:/bin",
        "/usr/bin/python3",
        "-I",
        "-c",
        "PACKET=" + repr(remote.PACKET) + "\n" + code,
    ]
    receipt = ports.ssm(
        host, [shlex.join(command)], timeout_s=50, step="inf060.gpu_preapply_readback"
    )
    return json.loads(receipt["StandardOutputContent"])


def setup(ports, host, packet, manifest, review):
    digest = spec.facts(packet / "manifest.json")["sha256"]
    shell = [
        "set -eu",
        "umask 077",
        "systemctl is-active --quiet dec077-terminate.timer",
        "test -f /opt/dec077/user-data.done",
        "mkdir -p /opt/inf060",
        "mkdir " + remote.ROOT,
        "cd " + remote.ROOT,
        "mkdir -p .cache/packet",
    ]
    ports.ssm(host, shell, timeout_s=60)
    # Separate binary records from the one reviewed block. No .git, profile,
    # Terraform state, transfer tokens, logs or local AWS directories enter.
    incoming = io.BytesIO()
    with tarfile.open(fileobj=incoming, mode="w:gz") as tar:
        files = (
            sorted(manifest["artifacts"])
            + ["manifest.json"]
            + [
                "operator-host/" + n
                for n in sorted(manifest["operator_host"]["artifacts"])
            ]
        )
        for name in files:
            tar.add(packet / name, arcname=name, recursive=False)
    raw = incoming.getvalue()
    spec.check(len(raw) < 8 * 1024**2, "operator_delivery_size")
    upload = remote.ROOT + "/packet.tgz"
    for offset in range(0, len(raw), 30000):
        chunk = base64.b64encode(raw[offset : offset + 30000]).decode()
        ports.ssm(
            host,
            [
                "set -eu; umask 077",
                f"test $(stat -c %s {upload} 2>/dev/null || echo 0) -eq {offset}",
                f"printf %s {chunk} | base64 -d >> {upload}",
            ],
            timeout_s=30,
        )
    block = review[review.rfind("## Claude Round ") :].split("\n## ", 1)[0]
    spec.approval(block, manifest, digest)
    shell = [
        "set -eu; umask 077",
        "cd " + remote.ROOT,
        "echo '" + hashlib.sha256(raw).hexdigest() + "  packet.tgz' | sha256sum -c -",
        "tar xzf packet.tgz -C .cache/packet",
        "echo '" + digest + "  .cache/packet/manifest.json' | sha256sum -c -",
        "tar xzf .cache/packet/operator-host/runtime.tar.gz",
        "printf %s "
        + base64.b64encode(block.encode()).decode()
        + " | base64 -d > .cache/packet/committed-review.txt",
        "mkdir -m 700 tools; cd tools",
        "export DEBIAN_FRONTEND=noninteractive; apt-get -qq update; apt-get -qq install -y unzip curl",
    ]
    for key in ("terraform", "aws", "plugin"):
        row = remote.TOOLS[key]
        shell += [
            "curl -fsSL --retry 2 --max-time 150 "
            + shlex.quote(row["url"])
            + " -o "
            + key
            + ".pkg",
            f"echo '{row['sha256']}  {key}.pkg' | sha256sum -c -",
        ]
    shell += [
        "unzip -qo terraform.pkg terraform; install -m 0755 terraform /usr/local/bin/terraform",
        "unzip -qo aws.pkg; ./aws/install --update",
        "dpkg -i plugin.pkg",
        "command -v aws terraform session-manager-plugin >/dev/null",
        "systemctl is-active --quiet dec077-terminate.timer",
    ]
    ports.ssm(host, shell, timeout_s=720, step="inf060.operator_tools")


class OperatorStack:
    def __init__(self, packet, run, profile):
        self.packet, self.run, self.profile = packet, run, profile
        self.tf = ROOT / ".tools/terraform/1.16.2/terraform.exe"
        self.tfdir = run / "terraform"
        self.timer = spec.load(packet / "manifest.json")["operator_host"]["timer_s"]
        self.ports = Operator(
            ROOT,
            {"aws_profile": profile, "region": spec.REGION},
            run / "observer",
            time.time() + self.timer + 600,
        )

    def terraform(self, *args, timeout=600):
        return subprocess.check_output(
            [str(self.tf), "-chdir=" + str(self.tfdir), *args],
            env={
                **os.environ,
                "AWS_PROFILE": self.profile,
                "TF_IN_AUTOMATION": "1",
                "TF_PLUGIN_CACHE_DIR": str(ROOT / ".cache/terraform-plugins"),
            },
            timeout=timeout,
            stderr=subprocess.STDOUT,
        )

    def create(self, manifest):
        row = tagged_inventory(self.ports, manifest["operator_host"]["session"])
        remote.require_zero(row, state=False)
        self.tfdir.mkdir()
        folder = self.packet / "operator-host"
        for f in (
            *spec.TERRAFORM_FILES,
            "policy.json",
            "input.tfvars.json",
            "create.tfplan",
        ):
            shutil.copyfile(folder / f, self.tfdir / f)
        self.terraform("init", "-input=false", "-lockfile=readonly")
        spec.check(
            spec.facts(self.tfdir / "create.tfplan")["sha256"]
            == manifest["operator_host"]["create_sha256"],
            "operator_saved_plan",
        )
        self.terraform("apply", "-input=false", "create.tfplan", timeout=900)
        host = self.terraform("output", "-raw", "instance_id").decode().strip()
        end = time.monotonic() + 240
        while time.monotonic() < end:
            rows = self.ports.aws(
                "ssm",
                "describe-instance-information",
                ["--filters", "Key=InstanceIds,Values=" + host],
            )["InstanceInformationList"]
            if rows and rows[0]["PingStatus"] == "Online":
                self.ports.ssm(
                    host,
                    [
                        "cloud-init status --wait >/dev/null || test $? = 2",
                        "systemctl is-active --quiet dec077-terminate.timer",
                    ],
                    timeout_s=180,
                )
                return host
            time.sleep(4)
        raise TimeoutError("inf060:operator_ssm")

    def destroy(self, session):
        self.terraform(
            "destroy",
            "-auto-approve",
            "-input=false",
            "-var-file=input.tfvars.json",
            timeout=600,
        )
        inv = tagged_inventory(self.ports, session)
        inv["terraform_resources"] = len(
            self.terraform("state", "list").decode().splitlines()
        )
        remote.require_zero(inv)
        return {"destroy_completed": True, "inventory": inv}

    def pre_dispatch_cleanup(self, manifest):
        spec.check(not (self.run / "dispatch.json").exists(), "submission_may_exist")
        host = self.terraform("output", "-raw", "instance_id").decode().strip()
        gpu = manifest["session"]
        script = (
            "import json,subprocess\n"
            + inspect.getsource(tagged_inventory)
            + (
                "\nclass Reader:\n def aws(self, service, op, args):\n"
                "  return json.loads(subprocess.check_output(['aws','--region','us-east-1',service,op,*args,'--output','json'],timeout=25))\n"
                "print(json.dumps(tagged_inventory(Reader()," + repr(gpu) + ")))\n"
            )
        )
        path = remote.PACKET
        aws = remote.TOOLS["aws"]
        proof = self.ports.ssm(
            host,
            [
                "set -eu; umask 077",
                "export PATH=/usr/local/bin:/usr/bin:/bin",
                f"test ! -e {path}/consumed.json && test ! -e {path}/supervisor && test ! -e {path}/terraform/terraform.tfstate && test ! -e {path}/remote-started || exit 1",
                'if ! command -v aws >/dev/null; then d=$(mktemp -d); cd "$d"; curl -fsSL --max-time 150 '
                + shlex.quote(aws["url"])
                + " -o cli.zip; echo '"
                + aws["sha256"]
                + "  cli.zip' | sha256sum -c - >&2; apt-get -qq install -y unzip >&2; unzip -q cli.zip; ./aws/install --update >&2; fi",
                "printf %s "
                + base64.b64encode(script.encode()).decode()
                + " | base64 -d | python3",
            ],
            timeout_s=300,
            step="inf060.pre_dispatch_gpu_inventory",
        )
        remote_read = json.loads(proof["StandardOutputContent"])
        remote.require_zero(remote_read, state=False)
        local = tagged_inventory(self.ports, gpu)
        remote.require_zero(local, state=False)
        spec.save(
            self.run / "gpu-verified.json",
            {
                "pre_dispatch": True,
                "gpu_state_absent": True,
                "operator": remote_read,
                "independent_inventory": local,
            },
        )
        spec.save(
            self.run / "operator-cleanup.json",
            self.destroy(manifest["operator_host"]["session"]),
        )

    def observe(self, submission):
        # A late recovery still reads the retained terminal SSM response. This
        # short read allowance never extends either host's original deadline.
        end = max(submission["end"], time.time() + 30)
        while time.time() < end:
            try:
                row = self.ports.aws(
                    "ssm",
                    "get-command-invocation",
                    [
                        "--command-id",
                        submission["command"],
                        "--instance-id",
                        submission["host"],
                    ],
                )
            except subprocess.CalledProcessError:
                time.sleep(3)
                continue
            if row["Status"] in {"Pending", "InProgress", "Delayed"}:
                time.sleep(10)
                continue
            if row["Status"] != "Success":
                return row["Status"], None
            return row["Status"], json.loads(row["StandardOutputContent"])
        raise TimeoutError("inf060:operator_witness_timeout")

    def submit(self, host, mock, *, early_exit=False, mock_failure=None):
        argv = remote.launch_sequence()
        if mock:
            argv += ["--mock-host", mock]
        if failure := diagnostics.injected_failure(mock, mock_failure):
            argv += ["--mock-failure", failure]
        if early_exit:
            spec.check(bool(mock), "forced_exit_requires_mock")
            index = argv.index("/usr/bin/python3")
            argv.insert(index, "INF060_REHEARSAL_EXIT_BEFORE_APPLY=1")
        # Run Command retains the sanitized result after the operator timer.
        # The launcher has no SSH session, child lifetime or credentials to relay.
        script = [
            "set -eu",
            shlex.join(argv),
            "while systemctl is-active --quiet inf060-native.service; do sleep 3; done",
            "cat "
            + remote.PACKET
            + "/remote-result.json || cat "
            + remote.PACKET
            + "/verified-cleanup.json || cat "
            + remote.PACKET
            + "/allow-side-result.json",
        ]
        intent = {
            "host": host,
            "end": time.time() + self.timer,
            "comment": "INF060-" + self.run.name,
        }
        with (self.run / "dispatch.json").open("x") as output:
            json.dump(intent, output)
            output.flush()
            os.fsync(output.fileno())
        parameters = self.ports._write_ssm_parameters(
            {"commands": script, "executionTimeout": [str(self.timer)]}
        )
        try:
            value = self.ports.aws(
                "ssm",
                "send-command",
                [
                    "--document-name",
                    "AWS-RunShellScript",
                    "--instance-ids",
                    host,
                    "--comment",
                    intent["comment"],
                    "--parameters",
                    "file://" + str(parameters),
                ],
            )
        finally:
            parameters.unlink(missing_ok=True)
        sub = {
            "host": host,
            "command": value["Command"]["CommandId"],
            "end": time.time() + self.timer,
        }
        spec.save(self.run / "submission.json", sub)
        return sub


def retrieve_receipt(
    stack,
    submission,
    binding,
    *,
    kind,
    filename,
    maximum,
    chunk_size,
    budget,
    chunk_timeout,
):
    timings = []
    try:
        size, digest = binding["bytes"], binding["sha256"]
        spec.check(
            binding["status"] == "available"
            and type(size) is int
            and 0 < size <= maximum
            and re.fullmatch(r"[0-9a-f]{64}", digest),
            kind + "_binding",
        )
        deadline = min(submission["end"], time.time() + budget)
        source = remote.PACKET + "/" + filename
        reader = (
            "import base64,sys; "
            "f=open(sys.argv[1],'rb'); f.seek(int(sys.argv[2])); "
            "print(base64.b64encode(f.read(int(sys.argv[3]))).decode())"
        )
        raw = bytearray()
        for offset in range(0, size, chunk_size):
            count = min(chunk_size, size - offset)
            left = min(chunk_timeout, int(deadline - time.time()))
            spec.check(left > 0, kind + "_deadline")
            began = time.monotonic()
            row = stack.ports.ssm(
                submission["host"],
                [
                    shlex.join(
                        [
                            "/usr/bin/python3",
                            "-I",
                            "-c",
                            reader,
                            source,
                            str(offset),
                            str(count),
                        ]
                    )
                ],
                timeout_s=left,
                step="inf060." + kind + "_chunk",
            )
            chunk = base64.b64decode(
                row["StandardOutputContent"].strip(), validate=True
            )
            spec.check(len(chunk) == count, kind + "_chunk_length")
            raw.extend(chunk)
            timings.append({"bytes": count, "elapsed_s": time.monotonic() - began})
        spec.check(hashlib.sha256(raw).hexdigest() == digest, kind + "_hash")
        spec.check(isinstance(json.loads(raw), dict), kind + "_json")
        (stack.run / filename).write_bytes(raw)
        return {
            "status": "verified",
            "bytes": size,
            "sha256": digest,
            "round_trips": timings,
        }
    except Exception as error:
        return {
            "status": ("diagnostics" if kind == "diagnostic" else "results")
            + "_unavailable",
            "error": diagnostics.exception_record(error),
            "round_trips": timings,
        }


def retrieve_diagnostics(stack, submission, result):
    if result is None or (
        result["supervisor_complete"] and result["supervisor_exit"] == 0
    ):
        return {"status": "not_applicable"}
    return retrieve_receipt(
        stack,
        submission,
        result.get("diagnostics", {}),
        kind="diagnostic",
        filename="failure-diagnostics.json",
        maximum=diagnostics.MAX_BYTES,
        chunk_size=diagnostics.CHUNK_BYTES,
        budget=60,
        chunk_timeout=15,
    )


def retrieve_results(stack, submission, result):
    binding = (result or {}).get("results", {})
    if binding.get("status") != "available":
        return {"status": "results_unavailable", "reason": "missing_result_binding"}
    return retrieve_receipt(
        stack,
        submission,
        binding,
        kind="results",
        filename="probe-results.json",
        maximum=results.MAX_BYTES,
        chunk_size=results.CHUNK_BYTES,
        budget=results.TRANSFER_S,
        chunk_timeout=results.CHUNK_TIMEOUT_S,
    )


def retrieve_benchmark(stack, submission, result):
    binding = (result or {}).get("benchmark", {})
    if binding.get("status") != "available":
        return {"status": "results_unavailable", "reason": "missing_benchmark_binding"}
    destination = stack.run / "inf061-receipts.tar.gz"
    partial = destination.with_suffix(".partial")
    child = None
    try:
        spec.check(
            0 < binding["bytes"] <= benchmark.EXPORT_MAX, "benchmark_transfer_size"
        )
        end = min(submission["end"], time.time() + 600)
        root = remote.PACKET
        key = secrets.token_urlsafe(32)
        stack.ports.ssm(
            submission["host"],
            [
                "set -eu; umask 077",
                f"printf %s {shlex.quote(key)} > {root}/inf061-transfer.key",
                f"systemd-run --unit inf061-receipt --property RuntimeMaxSec=600 "
                f"/usr/bin/python3 {remote.ROOT}/scripts/inf061_packet.py "
                f"{root}/inf061-receipts.tar.gz {root}/inf061-transfer.key",
            ],
            timeout_s=30,
            step="inf061.start_receipt_server",
        )
        stack.ports.inputs["ssm_remote_port"] = benchmark.RECEIPT_PORT
        stack.ports.inputs["session_manager_plugin_path"] = (
            ".cache/session-manager-plugin/bin/bin/session-manager-plugin.exe"
        )
        port, child = stack.ports.tunnel(submission["host"])
        req = Request(
            f"http://127.0.0.1:{port}/receipt",
            headers={"Authorization": "Bearer " + key},
        )
        until = min(end, time.time() + 35)
        while time.time() < until:
            try:
                response = urlopen(req, timeout=3)
                break
            except URLError:
                if child.poll() is not None:
                    raise
                time.sleep(0.25)
        else:
            raise TimeoutError("inf061:receipt_forward")
        with response, partial.open("xb") as stream:
            count = 0
            while time.time() < end and (chunk := response.read(256 * 1024)):
                count += len(chunk)
                spec.check(count <= binding["bytes"], "benchmark_transfer_oversize")
                stream.write(chunk)
        spec.check(
            spec.facts(partial)
            == {"bytes": binding["bytes"], "sha256": binding["sha256"]},
            "benchmark_transfer_digest",
        )
        partial.replace(destination)
        return {
            "status": "verified",
            "bytes": binding["bytes"],
            "sha256": binding["sha256"],
        }
    except Exception as exc:
        partial.unlink(missing_ok=True)
        return {
            "status": "results_unavailable",
            "error": diagnostics.exception_record(exc),
        }
    finally:
        if child:
            stop_forward(child)


def operate(
    packet,
    run,
    profile,
    *,
    routine=None,
    recover=False,
    early_exit=False,
    mock_failure=None,
):
    packet, run = packet.resolve(), run.resolve()
    failure = diagnostics.injected_failure(routine, mock_failure)
    if not recover:
        run.mkdir(parents=True, exist_ok=False)
    stack = OperatorStack(packet, run, profile)
    manifest = spec.verify_packet(packet)
    remote.verify(packet, manifest)
    digest = spec.facts(packet / "manifest.json")["sha256"]
    capacity = "capacity_hunt" in manifest
    marker = run / "operation.json"
    if recover:
        prior = spec.load(marker)
        spec.check(prior["manifest_sha256"] == digest, "recovery_packet")
        if (run / "submission.json").exists():
            sub = spec.load(run / "submission.json")
        else:
            intent = spec.load(run / "dispatch.json")
            rows = stack.ports.aws(
                "ssm", "list-commands", ["--instance-id", intent["host"]]
            )["Commands"]
            matches = [
                r["CommandId"] for r in rows if r["Comment"] == intent["comment"]
            ]
            spec.check(len(matches) == 1, "ambiguous_submission_do_not_relaunch")
            sub = {**intent, "command": matches[0]}
    else:
        if os.name == "nt":
            record_launch_gate(run / "memory.json", requested="aws")
        review = (
            synthetic_review(packet)
            if routine
            else git("show", "HEAD:REVIEW.md").decode()
        )
        checked_packet(packet, review)
        # Product attempts share one durable packet lock even if a different
        # observation directory is requested after losing the first reply.
        if not routine:
            with (packet / "operator-launch.lock").open("x") as lock:
                lock.write(str(run))
        spec.save(
            marker,
            {
                "manifest_sha256": digest,
                "started_epoch": time.time(),
                "mock": bool(routine),
            },
        )
        if routine:
            spec.check(
                routine.manifest["source_commit"] == manifest["source_commit"]
                and routine.manifest["instance_type"] == "m6i.2xlarge",
                "routine_source",
            )
            routine.aws(
                "ec2",
                "create-tags",
                [
                    "--resources",
                    routine.host,
                    "--tags",
                    "Key=Inf060Target,Value=" + manifest["session"],
                ],
            )
        if capacity and not routine:
            from inf061_capacity import active_reservations

            spec.check(
                not active_reservations(stack.ports.aws), "capacity_regional_not_empty"
            )
        host = stack.create(manifest)
        session = manifest["operator_host"]["session"]
        live_policy = stack.ports.aws(
            "iam",
            "get-role-policy",
            [
                "--role-name",
                session + "-cpu",
                "--policy-name",
                "native-probe-controller",
            ],
        )["PolicyDocument"]
        spec.check(
            live_policy == spec.load(packet / "operator-host/policy.json"),
            "operator_iam_readback",
        )
        instance = stack.ports.aws(
            "ec2", "describe-instances", ["--instance-ids", host]
        )["Reservations"][0]["Instances"][0]
        groups = stack.ports.aws(
            "ec2",
            "describe-security-groups",
            ["--group-ids", *[row["GroupId"] for row in instance["SecurityGroups"]]],
        )["SecurityGroups"]
        spec.check(
            instance["InstanceType"] == remote.SHAPE
            and instance["MetadataOptions"]["HttpTokens"] == "required"
            and instance["IamInstanceProfile"]["Arn"].endswith("/" + session + "-cpu")
            and len(groups) == 1
            and not groups[0]["IpPermissions"],
            "operator_live_shape",
        )
        try:
            setup(stack.ports, host, packet, manifest, review)
            if (
                routine
                and not early_exit
                and not failure
                and "actions_sha256" in manifest["operator_host"]
            ):
                rehearse_principal(stack, manifest)
        except Exception:
            stack.pre_dispatch_cleanup(manifest)
            raise
        if routine and not early_exit and not failure:
            spec.save(run / "prepared-mock.json", {"host": host, "mock": routine.host})
        else:
            sub = stack.submit(
                host,
                routine.host if routine else None,
                early_exit=early_exit,
                mock_failure=failure,
            )
    if routine and not early_exit and not failure:
        # Kill only this disposable observer. PID 1 on EC2 owns the service.
        with subprocess.Popen(
            [
                sys.executable,
                __file__,
                "submit-mock",
                "--directory",
                str(packet),
                "--run",
                str(run),
                "--profile",
                profile,
            ]
        ) as observer:
            until = time.monotonic() + observer_window(manifest)
            while (
                not (run / "observing.json").exists()
                and observer.poll() is None
                and time.monotonic() < until
            ):
                time.sleep(0.2)
            if (run / "observing.json").exists() and observer.poll() is None:
                observer.kill()
                observer.wait(timeout=10)
                spec.save(
                    run / "observer-loss.json",
                    {
                        "pid": observer.pid,
                        "exit": observer.returncode,
                        "killed_epoch": time.time(),
                    },
                )
        sub = spec.load(run / "submission.json")
    status, result = stack.observe(sub)
    independent = tagged_inventory(stack.ports, manifest["session"])
    if capacity:
        from inf061_capacity import reservation_inventory

        values = reservation_inventory(stack.ports.aws, manifest["session"])
        independent.update(values)
        independent["empty"] = independent["empty"] and not any(values.values())
    preapply = None
    try:
        remote.require_zero(independent, state=False, capacity=capacity)
        if result is not None:
            spec.check(result["manifest_sha256"] == digest, "gpu_cleanup_readback")
        else:
            spec.check(status == "Failed", "gpu_remote_terminal_unproven")
            preapply = preapply_readback(stack.ports, sub["host"])
        branch = cleanup_branch(
            independent, witness=result, preapply=preapply, capacity=capacity
        )
    except Exception as exc:
        spec.save(
            run / "teardown-incident.json",
            {
                "status": status,
                "branch": "ambiguous",
                "independent_inventory": independent,
                "preapply": preapply,
                "error_type": type(exc).__name__,
            },
        )
        raise
    spec.save(
        run / "gpu-verified.json",
        {
            "operator": result,
            "independent_inventory": independent,
            "branch": branch,
            "preapply": preapply,
        },
    )
    diagnosed = retrieve_diagnostics(stack, sub, result)
    reported = (
        retrieve_benchmark(stack, sub, result)
        if benchmark.is_benchmark(manifest)
        else retrieve_results(stack, sub, result)
    )
    outer = stack.destroy(manifest["operator_host"]["session"])
    if capacity:
        group_name = manifest["session"] + "-capacity"
        names = stack.ports.aws("resource-groups", "list-groups", [])[
            "GroupIdentifiers"
        ]
        spec.check(
            all(row["GroupName"] != group_name for row in names),
            "capacity_group_destroy_unverified",
        )
    elapsed = time.time() - spec.load(marker)["started_epoch"]
    summary = {
        "gpu": result,
        "gpu_independent_inventory": independent,
        "operator": outer,
        "cleanup_branch": branch,
        "preapply": preapply,
        "ssm_status": status,
        "diagnostics": diagnosed,
        "results": reported,
        "operator_elapsed_s": elapsed,
        "operator_estimate_usd": max(60, elapsed)
        / 3600
        * manifest["operator_host"]["hourly_usd"],
        "rehearsal_gpu_spend_usd": 0 if spec.load(marker)["mock"] else None,
    }
    if (run / "observer-loss.json").exists():
        summary["observer_loss"] = spec.load(run / "observer-loss.json")
    if (run / "principal-simulation.json").exists():
        summary["principal_simulation"] = spec.load(run / "principal-simulation.json")
    spec.save(run / "verified.json", summary)
    if (
        benchmark.is_benchmark(manifest)
        and not spec.load(marker)["mock"]
        and (result is None or not result["supervisor_complete"])
    ):
        detail = ((result or {}).get("diagnostics", {}).get("preview") or {}).get(
            "apply", {}
        )
        if detail.get("reason") != "gpu_capacity_unavailable":
            started = spec.load(marker)["started_epoch"]
            ended = time.time()
            stack.ports.deadline = ended + 45

            def lookup(service, operation, argv):
                return stack.ports.aws(
                    service, operation, argv, deadline=time.time() + 6
                )

            summary["cloudtrail_create_readback"] = cloudtrail_create_readback(
                lookup, manifest["operator_host"]["session"] + "-cpu", started, ended
            )
            spec.save(run / "verified.json", summary)
    if routine and not early_exit and not failure and result is not None:
        spec.check((run / "observer-loss.json").exists(), "observer_loss_unverified")
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("launch", "recover", "submit-mock"))
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--run", required=True, type=Path)
    parser.add_argument("--profile", default="admin-learning")
    args = parser.parse_args()
    if args.mode == "submit-mock":
        stack = OperatorStack(args.directory, args.run, args.profile)
        prepared = spec.load(args.run / "prepared-mock.json")
        spec.check(
            prepared["mock"] and spec.load(args.run / "operation.json")["mock"],
            "mock_only",
        )
        sub = stack.submit(prepared["host"], prepared["mock"])
        window = observer_window(spec.load(args.directory / "manifest.json"))
        stack.ports.ssm(
            sub["host"],
            [
                "set -eu",
                f"for n in $(seq 1 {window - 30}); do test ! -f "
                + remote.PACKET
                + "/supervisor.lock || exit 0; systemctl is-failed --quiet inf060-native.service && exit 1; sleep 1; done; exit 1",
            ],
            timeout_s=window - 15,
        )
        spec.save(args.run / "observing.json", {"pid": os.getpid()})
        stack.observe(sub)
    else:
        summary = operate(
            args.directory, args.run, args.profile, recover=args.mode == "recover"
        )
        complete = (summary["gpu"] or {}).get("supervisor_complete") and summary[
            "results"
        ]["status"] == "verified"
        raise SystemExit(0 if complete else 1)
