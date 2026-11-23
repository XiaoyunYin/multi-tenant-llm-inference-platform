"""DEC-100 provider ports; never invoked without an independently reviewed packet.

Uses the existing R1 capacity probe/cancellation and SSM parameter-file transport,
Package A host bootstrap/upload/frozen retrieval, and shared ClusterPorts on the
AWS operator. Creating a packet is separate and has no Apply side effects.
"""

import copy
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import tarfile
import time
from pathlib import Path

from inference_platform.m5_descriptive_operator import (
    execute,
    file_digest,
    phase_deadline,
)
from inference_platform.m5_infra_safety import verify_gpu_plan, wait_terminated
from inference_platform.package_a_operator import Ports
from inference_platform.r1_cloud_operator import stop_forward
from inference_platform.r1_lifecycle import Production
from m5_descriptive_cleanup import missing, pages
from m5_descriptive_diagnostics import collect, write_cost
from m5_descriptive_inventory import gpu_states, inventory
from m5_descriptive_capacity import select_capacity
from inf060_eks_cpu_plan import CPU_MARKER, standard_quota_readback, verify_cpu_binding
from package_a_host import host_environment

ROOT = Path(__file__).resolve().parents[1]


def phase_command(phase, *, isolated=False):
    if not is_streaming_phase(phase) and phase not in {
        "provision",
        "smoke",
        "load",
        "gateway_rollout",
        "replica_rollout",
        "export",
        "retrieve",
    }:
        raise ValueError("descriptive:phase_command")
    environment = " ".join(
        name + "=" + shlex.quote(value) for name, value in host_environment().items()
    )
    setup = (
        "exec /usr/bin/env -i " + environment + " "
        if isolated
        else "export " + environment + "; "
    )
    return (
        "cd /opt/dec077/repo; "
        + setup
        + shlex.join(
            [
                "/opt/dec077/repo/python/.venv/bin/python",
                "-B",
                "/opt/dec077/repo/scripts/m5_descriptive_remote.py",
                phase,
            ]
        )
    )


def is_streaming_phase(phase):
    return (
        re.fullmatch(
            r"stream-(?:window-(?:smoke|warmup|0\.25|1|3|8)|snapshot-(?:0\.25|1|3|8)|final|partial)",
            phase,
        )
        is not None
    )


def phase_budget_name(phase):
    return "export" if phase in {"stream-final", "stream-partial"} else phase


def validate_cleanup_policy(policy, session):
    """Inspect actual planned/deployed JSON, including overlapping Allow grants."""
    scoped = {
        "ec2:TerminateInstances",
        "ec2:CancelCapacityReservation",
        "ec2:DeleteLaunchTemplate",
        "ec2:ReleaseAddress",
        "ec2:DisassociateRouteTable",
        "ec2:DeleteRouteTable",
        "ec2:DeleteSubnet",
        "ec2:DetachInternetGateway",
        "ec2:DeleteInternetGateway",
        "ec2:DeleteVpc",
    }
    witnessed = set()
    for statement in policy["Statement"]:
        if statement["Effect"] != "Allow":
            continue
        actions = statement["Action"]
        actions = {actions} if isinstance(actions, str) else set(actions)
        if "*" in actions or any(
            a.startswith("ec2:") and "*" in a and a != "ec2:Describe*" for a in actions
        ):
            raise ValueError("descriptive:cleanup_policy_scope")
        protected = actions & scoped
        if not protected:
            continue
        terms = statement.get("Condition", {}).get("StringEquals", {})
        tags = {k: v for k, v in terms.items() if k.startswith("aws:ResourceTag/")}
        if terms.get("aws:RequestedRegion") != "us-east-1" or len(tags) != 1:
            raise ValueError("descriptive:cleanup_policy_scope")
        key, values = next(iter(tags.items()))
        values = {values} if isinstance(values, str) else set(values)
        expected = (
            {session, "dec077-" + session}
            if key == "aws:ResourceTag/Session"
            else {session}
            if key
            in {
                "aws:ResourceTag/eks:cluster-name",
                "aws:ResourceTag/aws:eks:cluster-name",
            }
            and protected == {"ec2:TerminateInstances"}
            else set()
        )
        if not values or not values <= expected:
            raise ValueError("descriptive:cleanup_policy_scope")
        if "ec2:CancelCapacityReservation" in protected and values != {session}:
            raise ValueError("descriptive:cleanup_reservation_tag")
        witnessed.update(protected)
    if witnessed != scoped:
        raise ValueError("descriptive:cleanup_policy_actions_missing")


def validate_cleanup_resource_tags(plan, session, policy):
    tagged = {
        "aws_instance": "ec2:TerminateInstances",
        "aws_launch_template": "ec2:DeleteLaunchTemplate",
        "aws_eip": "ec2:ReleaseAddress",
        "aws_vpc": "ec2:DeleteVpc",
        "aws_subnet": "ec2:DeleteSubnet",
        "aws_route_table": "ec2:DeleteRouteTable",
        "aws_internet_gateway": "ec2:DeleteInternetGateway",
    }
    for row in plan["resource_changes"]:
        if row["type"] not in tagged:
            continue
        owner = (
            "dec077-" + session
            if row["address"].startswith("module.operator.")
            else session
        )
        if row["change"]["after"].get("tags_all", {}).get("Session") != owner:
            raise ValueError(
                "descriptive:cleanup_resource_session_tag:" + row["address"]
            )
        if not any(
            s["Effect"] == "Allow"
            and tagged[row["type"]] in s["Action"]
            and owner in ([values] if isinstance(values, str) else values)
            for s in policy["Statement"]
            for values in [
                s.get("Condition", {})
                .get("StringEquals", {})
                .get("aws:ResourceTag/Session", [])
            ]
        ):
            raise ValueError(
                "descriptive:cleanup_resource_policy_mismatch:" + row["address"]
            )


def require_review(text, manifest, digest):
    rounds = list(re.finditer(r"(?m)^## Claude Round [0-9]+[^\n]*$", text))
    if not rounds:
        raise ValueError("descriptive:review_round_missing")
    latest = text[rounds[-1].end() :]
    marker = (
        CPU_MARKER
        if manifest.get("descriptive", {}).get("cpu_clock_rehearsal")
        else "M5 DESCRIPTIVE EKS PLAN APPROVED"
    )
    lines = re.findall(
        rf"(?m)^{re.escape(marker)} manifest=[0-9a-f]{{64}} source=[0-9a-f]{{40}}\r?$",
        latest,
    )
    expected = f"{marker} manifest={digest} source={manifest['source_commit']}"
    if [line.removesuffix("\r") for line in lines] != [expected]:
        raise ValueError("descriptive:exact_committed_review_required")


def verify_plan(plan):
    """Reuse the accepted GPU bound checker inside the composed existing root."""
    derived = copy.deepcopy(plan)
    derived["resource_changes"] = [
        r for r in derived["resource_changes"] if r["address"].startswith("module.eks.")
    ]
    for row in derived["resource_changes"]:
        row["address"] = row["address"].removeprefix("module.eks.")
    derived["configuration"]["root_module"] = plan["configuration"]["root_module"][
        "module_calls"
    ]["eks"]["module"]
    binding = verify_gpu_plan(derived)
    config = plan["configuration"]["root_module"]["module_calls"]["eks"]["expressions"][
        "pins"
    ]
    references = config.get("references", [])
    if (
        "module.operator.public_ip" not in references
        or "module.operator.role_arn" not in references
    ):
        raise ValueError("descriptive:operator_api_binding")
    for row in plan["resource_changes"]:
        if row["change"]["actions"] != ["create"]:
            raise ValueError("descriptive:initial_create_only")
    return binding


def verify_packet_files(directory, manifest):
    directory = Path(directory).resolve()
    for name, facts in manifest["files"].items():
        path = (directory / name).resolve()
        if (
            not path.is_relative_to(directory)
            or path.stat().st_size != facts["bytes"]
            or file_digest(path) != facts["sha256"]
        ):
            raise ValueError("descriptive:packet_file_changed:" + name)

    def terraform_input(name):
        return name.endswith(
            (".tf", ".tf.json", ".tfvars", ".tfvars.json", ".sh", ".terraform.lock.hcl")
        )

    # A saved create plan is immutable, but future destroy reads configuration.
    # Refuse additional unbound configuration as well as altered bound files.
    actual = {
        p.relative_to(directory).as_posix()
        for p in directory.rglob("*")
        if p.is_file() and ".terraform" not in p.parts and terraform_input(p.name)
    }
    expected = {name for name in manifest["files"] if terraform_input(name)}
    if actual != expected:
        raise ValueError("descriptive:unbound_terraform_input")


def arm(sdk, manifest, *, started, now=time.time):
    stop = started + 18000
    parameter = "/" + manifest["session"] + "/deadline"
    record = {
        "session": manifest["session"],
        "started_epoch": started,
        "deadline_epoch": stop,
    }
    ssm = sdk.client("ssm")
    try:
        ssm.put_parameter(
            Name=parameter, Type="String", Value=json.dumps(record), Overwrite=False
        )
    except Exception as error:
        if (
            getattr(error, "response", {}).get("Error", {}).get("Code")
            != "ParameterAlreadyExists"
        ):
            raise
        previous = json.loads(ssm.get_parameter(Name=parameter)["Parameter"]["Value"])
        if previous != record:
            raise ValueError("descriptive:original_deadline_changed") from error
    if now() >= stop - 900:
        raise TimeoutError("descriptive:arming_deadline")
    return record


def arming_witness(sdk, manifest, record):
    name = manifest["session"] + "-cleanup"
    events, function = sdk.client("events"), sdk.client("lambda")
    rule = events.describe_rule(Name=name)
    targets = pages(events, "list_targets_by_rule", "Targets", Rule=name)
    configuration = function.get_function_configuration(FunctionName=name)
    policy = json.loads(function.get_policy(FunctionName=name)["Policy"])
    role_policy = sdk.client("iam").get_role_policy(RoleName=name, PolicyName=name)[
        "PolicyDocument"
    ]
    if isinstance(role_policy, str):
        role_policy = json.loads(role_policy)
    validate_cleanup_policy(role_policy, manifest["session"])
    policy_digest = hashlib.sha256(
        json.dumps(role_policy, sort_keys=True).encode()
    ).hexdigest()
    actions = {
        action
        for statement in role_policy["Statement"]
        if statement["Effect"] == "Allow"
        for action in statement["Action"]
    }
    if (
        policy_digest != manifest["cleanup_policy_sha256"]
        or not {
            "eks:DeleteCluster",
            "eks:DeleteNodegroup",
            "ec2:TerminateInstances",
            "ecr:DeleteRepository",
            "ssm:GetParameter",
        }
        <= actions
    ):
        raise ValueError("descriptive:backstop_deployed_permissions")
    if (
        rule["State"] != "ENABLED"
        or rule["ScheduleExpression"] != "rate(1 minute)"
        or len(targets) != 1
        or targets[0]["Arn"] != configuration["FunctionArn"]
    ):
        raise ValueError("descriptive:backstop_not_armed")
    if (
        configuration["CodeSha256"] != manifest["cleanup_zip_sha256_base64"]
        or configuration["Environment"]["Variables"]
        != {
            "SESSION": manifest["session"],
            "PARAMETER": "/" + manifest["session"] + "/deadline",
            "STATE_BUCKET": manifest["state_bucket"],
        }
        or configuration["Handler"] != "m5_descriptive_cleanup.handler"
        or configuration["Runtime"] != "python3.12"
    ):
        raise ValueError("descriptive:backstop_code_binding")
    if not any(
        s["Principal"].get("Service") == "events.amazonaws.com"
        and s.get("Condition", {}).get("ArnLike", {}).get("AWS:SourceArn")
        == rule["Arn"]
        and s.get("Condition", {}).get("StringEquals", {}).get("AWS:SourceAccount")
        == manifest["account"]
        for s in policy["Statement"]
    ):
        raise ValueError("descriptive:backstop_invoke_permission")
    if (
        json.loads(
            sdk.client("ssm").get_parameter(
                Name="/" + manifest["session"] + "/deadline"
            )["Parameter"]["Value"]
        )
        != record
    ):
        raise ValueError("descriptive:original_deadline_changed")
    if "ReservedConcurrentExecutions" in function.get_function_concurrency(
        FunctionName=name
    ):
        raise ValueError("descriptive:backstop_unreserved_required")
    response = function.invoke(
        FunctionName=name,
        InvocationType="RequestResponse",
        Payload=json.dumps(
            {"arming_probe": True, "original_deadline_epoch": record["deadline_epoch"]}
        ).encode(),
    )
    body = response["Payload"].read(65537)
    try:
        invoked = json.loads(body)
    except (ValueError, UnicodeError) as error:
        raise ValueError("descriptive:backstop_invocation") from error
    if (
        len(body) > 65536
        or response.get("StatusCode") != 200
        or response.get("FunctionError")
        or not isinstance(invoked, dict)
        or invoked.get("armed") is not True
        or invoked.get("cleanup_started") is not False
        or invoked.get("deadline_epoch") != record["deadline_epoch"]
    ):
        raise ValueError("descriptive:backstop_invocation")
    return {
        "armed": True,
        "original_deadline_epoch": record["deadline_epoch"],
        "schedule_sha256": hashlib.sha256(
            json.dumps(rule, sort_keys=True, default=str).encode()
        ).hexdigest(),
        "permission_sha256": hashlib.sha256(
            json.dumps(policy, sort_keys=True).encode()
        ).hexdigest(),
        "deployed_policy_sha256": hashlib.sha256(
            json.dumps(role_policy, sort_keys=True).encode()
        ).hexdigest(),
        "code_sha256_base64": configuration["CodeSha256"],
        "synchronous_invocation": {
            "status_code": response["StatusCode"],
            "response": invoked,
            "response_sha256": hashlib.sha256(body).hexdigest(),
        },
    }


class Capacity(Production):
    def __init__(self, ports, *, recovering=False):
        self.ports = ports
        self.inputs = {
            "session_id": ports.manifest["session"],
            "gpu_type": "g6.xlarge",
            "availability_zone": None,
            "region": "us-east-1",
            "aws_profile": ports.profile,
        }
        self.repo, self.aws_calls = ROOT, 0
        self.directory = ports.directory / "capacity"
        self.directory.mkdir(exist_ok=recovering)

    def command(self, argv, deadline, name):
        # Preserve R1's stdout/stderr files: its capacity classifier reads the
        # recorded AWS error code before deciding whether another AZ is legal.
        if argv[0] == "aws":
            argv = [self.ports.manifest["operator_tools"]["aws"]["path"], *argv[1:]]
        return super().command(argv, deadline, name)


class EKSports:
    substitutions = []

    def __init__(self, directory, *, profile="admin-learning", recovering=False):
        import boto3

        self.directory = Path(directory).resolve()
        self.manifest = json.loads((self.directory / "manifest.json").read_bytes())
        self.sdk = boto3.Session(profile_name=profile, region_name="us-east-1")
        if (
            self.sdk.client("sts").get_caller_identity()["Account"]
            != self.manifest["account"]
        ):
            raise ValueError("descriptive:caller_account_changed")
        self.profile = profile
        consumed = (
            json.loads((self.directory / "consumed.json").read_bytes())
            if recovering
            else None
        )
        self.started = consumed["started_epoch"] if consumed else time.time()
        self.end = consumed["deadline_epoch"] if consumed else self.started + 18000
        self.deadline = time.monotonic() + self.end - time.time()
        self.host = None
        self.bootstrap_complete = False
        if not recovering and self.manifest.get("descriptive", {}).get(
            "cpu_clock_rehearsal"
        ):
            if not standard_quota_readback(self.sdk)["fits"]:
                raise ValueError("cpu_clock:standard_quota_busy")
        self.capacity = Capacity(self, recovering=recovering)
        self.owned_vpcs = []
        self.main_root = None
        self.destroy_finished_ms = 0
        selected = self.directory / "selected-plan.json"
        if recovering and selected.exists():
            self.main_root = (
                self.directory / json.loads(selected.read_bytes())["directory"]
            )
        host_manifest = self.directory / "host-manifest.json"
        if recovering and host_manifest.exists():
            self.host = Ports(
                self.directory,
                json.loads(host_manifest.read_bytes()),
                profile=profile,
                manifest_path=host_manifest,
                recovering=True,
            )

    def aws(self, service, operation, args, *, deadline=None):
        timeout = (deadline or time.monotonic() + 60) - time.monotonic()
        if timeout <= 0:
            raise TimeoutError("descriptive:aws_command_deadline")
        raw = subprocess.check_output(
            [
                self.manifest["operator_tools"]["aws"]["path"],
                "--profile",
                self.profile,
                "--region",
                "us-east-1",
                service,
                operation,
                *args,
                "--output",
                "json",
                "--no-cli-pager",
            ],
            timeout=timeout,
        )
        return json.loads(raw) if raw.strip() else {}

    def tf(self, root, *args):
        remaining = self.end - time.time() if args[0] != "destroy" else 1800
        if remaining <= 0:
            raise TimeoutError("descriptive:terraform_original_deadline")
        name = root.name + "-" + args[0] + "-" + str(time.time_ns())
        if args[0] == "destroy":
            args = (*args, "-var-file=input.tfvars.json")
        with (
            (self.directory / (name + ".stdout")).open("wb") as out,
            (self.directory / (name + ".stderr")).open("wb") as err,
        ):
            try:
                subprocess.run(
                    [
                        self.manifest["operator_tools"]["terraform"]["path"],
                        "-chdir=" + str(root),
                        *args,
                    ],
                    check=True,
                    stdout=out,
                    stderr=err,
                    timeout=max(1, remaining),
                    env={**os.environ, "AWS_PROFILE": self.profile},
                )
            finally:
                pending = sys.exception()
                try:
                    if not (
                        root.name in {"bootstrap", "backstop"} and args[0] == "destroy"
                    ):
                        self.backup_state(root, name)
                except Exception as error:
                    (self.directory / (name + ".state-backup-error.json")).write_text(
                        json.dumps(
                            {
                                "error_type": type(error).__name__,
                                "original_failure_preserved": pending is not None,
                            }
                        )
                    )
                    if pending is None:
                        raise

    def backup_state(self, root, name):
        state = root / "terraform.tfstate"
        if not state.exists():
            return
        body = state.read_bytes()
        digest = hashlib.sha256(body).hexdigest()
        key = f"{self.manifest['session']}/control-state/{root.name}/{time.time_ns()}.tfstate"
        s3 = self.sdk.client("s3")
        s3.put_object(
            Bucket=self.manifest["state_bucket"],
            Key=key,
            Body=body,
            ServerSideEncryption="AES256",
        )
        fetched = s3.get_object(Bucket=self.manifest["state_bucket"], Key=key)
        with fetched["Body"] as handle:
            observed = hashlib.sha256(handle.read()).hexdigest()
        if observed != digest:
            raise ValueError("descriptive:state_backup_readback")
        (self.directory / (name + ".state-readback.json")).write_text(
            json.dumps({"sha256": digest, "bytes": len(body)})
        )

    def make_targeted(self, identifier, *, deadline=None):
        import datetime

        stop = min(self.deadline, deadline or self.deadline, time.monotonic() + 60)
        if stop <= time.monotonic():
            raise TimeoutError("descriptive:targeted_reservation_deadline")
        # Whole seconds round the reservation fallback down, never beyond the
        # immutable session deadline. The independent backstop is authoritative.
        end_date = (
            datetime.datetime.fromtimestamp(int(self.end), datetime.UTC)
            .isoformat()
            .replace("+00:00", "Z")
        )
        self.aws(
            "ec2",
            "modify-capacity-reservation",
            [
                "--capacity-reservation-id",
                identifier,
                "--instance-match-criteria",
                "targeted",
                "--end-date-type",
                "limited",
                "--end-date",
                end_date,
            ],
            deadline=stop,
        )
        # AWS can accept a modification before Describe reflects it. Poll only
        # the readback, never repeat the modification or acquire another slot.
        while time.monotonic() < stop:
            rows = self.capacity.describe_capacity_reservations(
                stop, "targeted", identifier
            )
            if (
                len(rows) != 1
                or rows[0].get("State") != "active"
                or rows[0].get("TotalInstanceCount") != 2
                or rows[0].get("AvailableInstanceCount") != 2
            ):
                raise ValueError("descriptive:targeted_reservation")
            actual_end = rows[0].get("EndDate")
            if not isinstance(actual_end, str):
                raise ValueError("descriptive:reservation_end_date")
            actual_epoch = datetime.datetime.fromisoformat(
                actual_end.replace("Z", "+00:00")
            ).timestamp()
            if actual_epoch > int(self.end):
                raise ValueError("descriptive:reservation_end_extends_original")
            if rows[0].get(
                "InstanceMatchCriteria"
            ) == "targeted" and actual_epoch == int(self.end):
                return rows[0]
            time.sleep(min(1, max(0, stop - time.monotonic())))
        raise TimeoutError("descriptive:targeted_reservation_deadline")

    def host_runtime(self, outputs):
        """Preserve the session cutoff across the agent's work-deadline rewrite."""
        return {
            **self.manifest["host_manifest"],
            "deadline_epoch": self.end,
            "descriptive": {
                **self.manifest["descriptive"],
                "original_deadline_epoch": self.end,
                "repository_url": outputs["repository_url"]["value"],
            },
        }

    def host_work_deadline(self):
        return phase_deadline(self.end, self.manifest["timing"], "provision")

    def provision(self):
        # Supplied review hash/committed source are checked by main before this
        # method, then consume before the first write. Never retry an Apply.
        with (self.directory / "consumed.json").open("x") as handle:
            json.dump(
                {
                    "started_epoch": self.started,
                    "deadline_epoch": self.end,
                    "manifest_sha256": hashlib.sha256(
                        (self.directory / "manifest.json").read_bytes()
                    ).hexdigest(),
                },
                handle,
            )
        record = arm(self.sdk, self.manifest, started=self.started)
        self.tf(self.directory / "bootstrap", "apply", "-input=false", "create.tfplan")
        self.tf(self.directory / "backstop", "apply", "-input=false", "create.tfplan")
        witness = arming_witness(self.sdk, self.manifest, record)
        (self.directory / "arming-witness.json").write_text(
            json.dumps(witness, indent=2)
        )
        cpu = self.manifest["descriptive"].get("cpu_clock_rehearsal")
        selected = cpu["selection"] if cpu else select_capacity(self)
        if cpu:
            quota = standard_quota_readback(self.sdk)
            (self.directory / "cpu-quota-before-apply.json").write_text(
                json.dumps(quota)
            )
            if not quota["fits"]:
                raise ValueError("cpu_clock:standard_quota_busy")
        self.main_root = self.directory / selected["directory"]
        (self.directory / "selected-plan.json").write_text(json.dumps(selected))
        self.tf(self.main_root, "apply", "-input=false", "create.tfplan")
        outputs = subprocess.check_output(
            [
                self.manifest["operator_tools"]["terraform"]["path"],
                "-chdir=" + str(self.main_root),
                "output",
                "-json",
            ],
            timeout=30,
        )
        outputs = json.loads(outputs)
        runtime = self.host_runtime(outputs)
        path = self.directory / "host-manifest.json"
        path.write_text(json.dumps(runtime))
        self.host = Ports(
            self.directory, runtime, profile=self.profile, manifest_path=path
        )
        self.host.host = outputs["operator_instance"]["value"]
        self.host.started, self.host.deadline = self.started, self.end
        work_end = self.host_work_deadline()
        self.host.bootstrap(work_end)
        self.host.upload(work_end)
        if cpu:
            self.host.upload_gate_a_inputs(work_end)
        self.host.run_checks(work_end)
        self.bootstrap_complete = True
        self.host.ssm(
            self.host.host,
            [
                f'set -eu; old=$(cat /etc/dec077/deadline); stop={int(self.end)}; if [ "$old" -lt "$stop" ]; then stop=$old; fi; printf \'%s\' "$stop" > /etc/dec077/deadline; sed -i "s/^OnCalendar=.*/OnCalendar=@$stop/" /etc/systemd/system/dec077-terminate.timer; systemctl daemon-reload; systemctl restart dec077-terminate.timer; systemctl is-active --quiet dec077-terminate.timer'
            ],
            timeout_s=30,
        )
        return {
            "arming_witness": witness,
            "cluster": self.remote("provision"),
            "capacity_zone": selected["zone"],
        }

    def remote(self, phase):
        descriptive = self.manifest.get("descriptive", {})
        if is_streaming_phase(phase) and not descriptive.get("streaming"):
            raise ValueError("descriptive:streaming_binding_required")
        end = phase_deadline(
            self.end, self.manifest["timing"], phase_budget_name(phase)
        )
        if end <= time.time():
            raise TimeoutError("descriptive:phase_window:" + phase)
        self.host.deadline = end
        shell = phase_command(
            phase,
            isolated=bool(descriptive.get("cpu_clock_rehearsal")),
        )
        result = self.host.ssm(
            self.host.host,
            [shell],
            timeout_s=max(1, int(end - time.time())),
            step="descriptive." + phase,
        )
        lines = [
            line.removeprefix("DESCRIPTIVE_PHASE_RESULT=")
            for line in result["StandardOutputContent"].splitlines()
            if line.startswith("DESCRIPTIVE_PHASE_RESULT=")
        ]
        if len(lines) != 1:
            raise ValueError("descriptive:phase_result_missing_or_truncated:" + phase)
        return json.loads(lines[0])

    def smoke(self):
        return self.remote("smoke")

    def load(self, levels):
        if tuple(levels) != (1, 4, 16):
            raise ValueError("descriptive:load_levels")
        return self.remote("load")

    def rollout(self, app):
        return self.remote("gateway_rollout" if app == "gateway" else "replica_rollout")

    def export(self):
        if not getattr(self, "bootstrap_complete", True):
            self.frozen = collect(
                self.host,
                self.directory,
                phase_deadline(self.end, self.manifest["timing"], "export"),
                root=getattr(self, "diagnostic_root", "/opt/dec077"),
            )
            return self.frozen
        try:
            self.frozen = self.remote("export")
        except Exception as error:
            from inference_platform.command_diagnostics import stderr_tail

            (self.directory / "remote-export-failure.json").write_text(
                json.dumps(
                    {"error": stderr_tail(str(error), secrets=(self.host.token,))}
                )
            )
            self.frozen = collect(
                self.host,
                self.directory,
                phase_deadline(self.end, self.manifest["timing"], "export"),
                root=getattr(self, "diagnostic_root", "/opt/dec077"),
            )
        return self.frozen

    def retrieve(self):
        if getattr(self, "frozen", {}).get("kind") == "repo-free-diagnostics":
            for name, facts in self.frozen["files"].items():
                path = self.directory / name
                if (
                    path.stat().st_size != facts["bytes"]
                    or file_digest(path) != facts["sha256"]
                ):
                    raise ValueError("descriptive:diagnostics_readback")
            return self.frozen
        remote = self.remote("retrieve")
        if remote != self.frozen:
            raise ValueError("descriptive:remote_retrieval_hash")
        receipt = self.host.retrieve(
            phase_deadline(self.end, self.manifest["timing"], "retrieve")
        )
        if (
            receipt.get("complete") is not True
            or receipt.get("bounded")
            or receipt.get("truncated_files")
        ):
            raise ValueError("descriptive:frozen_retrieval_incomplete")
        prefix = "results/runner/descriptive/retrieved/"
        observed = {}
        with tarfile.open(self.host.runtime / "receipts.tar.gz", "r:gz") as archive:
            for member in archive:
                if member.isfile() and member.name.startswith(prefix):
                    name = member.name.removeprefix(prefix)
                    if (
                        name in observed
                        or name.startswith("/")
                        or ".." in Path(name).parts
                    ):
                        raise ValueError("descriptive:retrieval_member")
                    digest = hashlib.sha256()
                    size = 0
                    with archive.extractfile(member) as stream:
                        while chunk := stream.read(1024**2):
                            digest.update(chunk)
                            size += len(chunk)
                    observed[name] = {"bytes": size, "sha256": digest.hexdigest()}
        if observed != self.frozen:
            raise ValueError("descriptive:local_retrieval_hash")
        return observed

    def teardown(self):
        errors = []
        known_gpus = None
        try:
            known_gpus = frozenset(gpu_states(self.sdk, self.manifest["session"]))
        except Exception as error:
            errors.append("gpu_inventory:" + type(error).__name__)
        if self.host and self.host.child:
            try:
                stop_forward(self.host.child)
            except Exception as error:
                errors.append("stop_forward:" + type(error).__name__)
        ec2 = self.sdk.client("ec2")
        try:
            for owner in (
                self.manifest["session"],
                "dec077-" + self.manifest["session"],
            ):
                self.owned_vpcs += [
                    v["VpcId"]
                    for v in pages(
                        ec2,
                        "describe_vpcs",
                        "Vpcs",
                        Filters=[{"Name": "tag:Session", "Values": [owner]}],
                    )
                ]
        except Exception as error:
            errors.append("vpc_readback:" + type(error).__name__)
        try:
            ecr = self.sdk.client("ecr")
            images = pages(
                ecr, "list_images", "imageIds", repositoryName=self.manifest["session"]
            )
            for offset in range(0, len(images), 100):
                response = ecr.batch_delete_image(
                    repositoryName=self.manifest["session"],
                    imageIds=images[offset : offset + 100],
                )
                if response.get("failures"):
                    raise ValueError("descriptive:ecr_delete")
        except Exception as error:
            if not missing(error):
                errors.append(type(error).__name__)
        for root in [self.main_root] if self.main_root else []:
            try:
                self.tf(root, "destroy", "-auto-approve", "-input=false")
            except Exception as error:
                errors.append(type(error).__name__)
        try:
            if known_gpus is None:
                raise ValueError("descriptive:gpu_termination_inventory_unavailable")
            wait_terminated(
                lambda: gpu_states(self.sdk, self.manifest["session"], known_gpus),
                lambda: time.sleep(2),
                max_polls=300,
                old_ids=known_gpus,
            )
            (self.directory / "gpu-termination.json").write_text(
                json.dumps({"verified": True, "known_count": len(known_gpus)})
            )
            cpu = self.manifest.get("descriptive", {}).get("cpu_clock_rehearsal")
            if cpu:
                reservations = pages(
                    ec2,
                    "describe_capacity_reservations",
                    "CapacityReservations",
                    Filters=[
                        {"Name": "tag:Session", "Values": [self.manifest["session"]]},
                        {"Name": "state", "Values": ["active", "pending"]},
                    ],
                )
                if known_gpus or reservations:
                    raise ValueError("cpu_clock:unexpected_accelerator_inventory")
            elif not self.capacity.cancel_session_capacity_reservations(
                time.monotonic() + 120
            ):
                raise ValueError("descriptive:capacity_cleanup_unverified")
        except Exception as error:
            errors.append("gpu_termination_or_capacity_cleanup:" + type(error).__name__)
            # Keep recovery state and the independent schedule while GPU
            # termination or reservation cleanup remains unverified.
            raise RuntimeError(
                "descriptive:teardown_failed:" + ",".join(errors)
            ) from error
        if errors:
            raise RuntimeError("descriptive:teardown_failed:" + ",".join(errors))
        try:
            s3 = self.sdk.client("s3")
            bucket = self.manifest["state_bucket"]
            objects = pages(
                s3, "list_object_versions", "Versions", Bucket=bucket
            ) + pages(s3, "list_object_versions", "DeleteMarkers", Bucket=bucket)
            for offset in range(0, len(objects), 1000):
                response = s3.delete_objects(
                    Bucket=bucket,
                    Delete={
                        "Quiet": True,
                        "Objects": [
                            {"Key": r["Key"], "VersionId": r["VersionId"]}
                            for r in objects[offset : offset + 1000]
                        ],
                    },
                )
                if response.get("Errors"):
                    raise ValueError("descriptive:s3_delete")
        except Exception as error:
            if not missing(error):
                errors.append(type(error).__name__)
        try:
            self.tf(
                self.directory / "bootstrap", "destroy", "-auto-approve", "-input=false"
            )
        except Exception as error:
            errors.append("bootstrap_destroy:" + type(error).__name__)
        self.destroy_finished_ms = int(time.time() * 1000)
        # Keep the independent rule armed if any product cleanup failed.
        proof = inventory(
            self.sdk,
            session=self.manifest["session"],
            bucket=self.manifest["state_bucket"],
            after_ms=self.destroy_finished_ms,
            vpc_ids=self.owned_vpcs,
            output=self.directory / "teardown-inventory.json",
        )
        if errors:
            raise RuntimeError("descriptive:teardown_failed:" + ",".join(errors))
        self.tf(self.directory / "backstop", "destroy", "-auto-approve", "-input=false")
        try:
            self.sdk.client("ssm").delete_parameter(
                Name="/" + self.manifest["session"] + "/deadline"
            )
        except Exception as error:
            if not missing(error):
                raise
        return {"complete": True, "inventory": proof["validation"]}

    def inventory(self):
        result = inventory(
            self.sdk,
            session=self.manifest["session"],
            bucket=self.manifest["state_bucket"],
            after_ms=self.destroy_finished_ms,
            vpc_ids=self.owned_vpcs,
            output=self.directory / "inventory.json",
        )
        name = self.manifest["session"] + "-cleanup"
        for service, method, kwargs in (
            ("events", "describe_rule", {"Name": name}),
            ("lambda", "get_function", {"FunctionName": name}),
            ("iam", "get_role", {"RoleName": name}),
            (
                "ssm",
                "get_parameter",
                {"Name": "/" + self.manifest["session"] + "/deadline"},
            ),
        ):
            try:
                getattr(self.sdk.client(service), method)(**kwargs)
            except Exception as error:
                if missing(error):
                    continue
                raise
            raise ValueError("descriptive:backstop_inventory_nonempty:" + service)
        if pages(
            self.sdk.client("logs"),
            "describe_log_groups",
            "logGroups",
            logGroupNamePrefix="/aws/lambda/" + name,
        ):
            raise ValueError("descriptive:backstop_inventory_nonempty:logs")
        (self.directory / "inventory.json").write_text(
            json.dumps(result, indent=2, default=str)
        )
        return {"complete": True, "inventory": result}


def main():
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packet", type=Path, required=True)
    parser.add_argument("--approved-manifest-sha256")
    parser.add_argument("--cleanup-only", action="store_true")
    parser.add_argument("--profile", default="admin-learning")
    args = parser.parse_args()
    try:
        run_packet(args)
    finally:
        write_cost(args.packet)


def run_packet(args):
    if (
        not args.cleanup_only
        and file_digest(args.packet / "manifest.json") != args.approved_manifest_sha256
    ):
        raise ValueError("descriptive:independently_approved_manifest_required")
    manifest = json.loads((args.packet / "manifest.json").read_bytes())
    if not args.cleanup_only:
        require_review(
            subprocess.check_output(["git", "show", "HEAD:REVIEW.md"], cwd=ROOT).decode(
                "utf-8"
            ),
            manifest,
            args.approved_manifest_sha256,
        )
    # Existing executing binding checks source/tool hashes. The descriptive
    # packet has three reviewed roots, whose exact file inventory is separate.
    paths = (
        "python",
        "scripts",
        "infra",
        "deploy",
        "internal",
        "cmd",
        "go.mod",
        "go.sum",
    )
    subprocess.run(
        ["git", "diff", "--exit-code", manifest["source_commit"], "--", *paths],
        check=True,
    )
    if subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=all", "--", *paths],
        cwd=ROOT,
    ):
        raise ValueError("descriptive:executing_code_not_clean")
    for tool in manifest["operator_tools"].values():
        if file_digest(tool["path"]) != tool["sha256"]:
            raise ValueError("descriptive:operator_tool_changed")
    verify_packet_files(args.packet, manifest)
    if manifest["descriptive"].get("cpu_clock_rehearsal"):
        verify_cpu_binding(args.packet, manifest)
    ports = EKSports(args.packet, profile=args.profile, recovering=args.cleanup_only)
    if args.cleanup_only:
        try:
            result = ports.teardown()
        finally:
            result_inventory = ports.inventory()
        print(json.dumps({"teardown": result, "inventory": result_inventory}))
    elif manifest["descriptive"].get("streaming"):
        from inf060_eks_operator import execute_streaming

        execute_streaming(ports, args.packet / "execution")
    else:
        execute(ports, args.packet / "execution", deadline=ports.deadline)


if __name__ == "__main__":
    main()
