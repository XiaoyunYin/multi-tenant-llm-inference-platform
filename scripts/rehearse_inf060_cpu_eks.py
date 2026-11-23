"""DEC-099 fitness check of the CPU EKS review, launch and evidence boundaries."""

import argparse
import contextlib
import copy
import io
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import boto3
import m5_descriptive_eks as operator
from build_m5_descriptive_packet import cpu_image_input, source_bundle, write
from inf060_eks_cpu_plan import (
    CPU_MARKER,
    PLAN_DIRECTORY,
    SERVICE_IMAGES,
    SESSION,
    canonical_digest,
    digest,
    policy_actions,
)
from inference_platform.inf060_eks_receipts import schedule_digest
from inference_platform.inf060_eks_schedule import TENANTS, schedule
from inference_platform.m5_descriptive_operator import session_timing
from rehearse_m5_descriptive_phases import LocalSSM

ROOT = Path(__file__).resolve().parents[1]
# No AWS call reaches an SDK or CLI. The remote process retains its actual
# constructor, state reload and snapshot freezer. Only its workload is faked.
SITE = """
import sys

def substitute(frame, event, argument):
    if (event == 'call' and frame.f_code.co_name == 'main'
            and frame.f_code.co_filename == '/opt/dec077/repo/scripts/m5_descriptive_remote.py'):
        sys.setprofile(None)
        from inf060_eks_cpu_remote import CpuClockPorts
        from rehearse_inf060_cpu_eks import fixture_provision, fixture_window
        CpuClockPorts.provision = fixture_provision
        CpuClockPorts.stream_window = fixture_window
sys.setprofile(substitute)
"""


def fixture_provision(ports):
    rows = [{"replica": number, "width_ns": 20_000, "running": 0} for number in (1, 2)]
    proof = {
        "phase": "cpu-clock-policy",
        "nodes": 3,
        "agent": {"enabled": True, "desired": 3, "ready": 3},
        "policy": {
            "passed": True,
            "allowed": [{"engine": True, "clock": True}] * 2,
            "denied": [{"engine": True, "clock": False}] * 2,
        },
        "idle": rows,
        "fallback": rows,
    }
    ports.results["stream_diagnostics"] = [proof]
    return {"clock_policy": proof}


def fixture_window(ports, label):
    if label == "8":
        ports.results["stream_diagnostics"].append(
            {
                "phase": "cpu-clock-peak",
                "replicas": [
                    {"replica": number, "width_ns": 20_000, "running": 1}
                    for number in (1, 2)
                ],
            }
        )
        write(
            ports.output / "window-8.json",
            {
                "requests": [
                    {"alias": row["alias"], "outcome": "missed"}
                    for row in schedule("8")
                ],
                "drain_ns": 0,
                "clocks": [
                    {"generation": number, "status": "clock_generation"}
                    for number in (1, 2)
                ],
                "observers": {"suppression": "PASS"},
            },
        )
    return {"status": "complete", "label": label}


def change(resource, name, values, address=None):
    return {
        "type": resource,
        "name": name,
        "address": address or resource + "." + name,
        "change": {"actions": ["create"], "after": values},
    }


def snapshot_plan(policy):
    return {
        "resource_changes": [
            change("aws_instance", "task", {"instance_type": "m6i.2xlarge"}),
            change(
                "aws_eks_node_group",
                "cpu",
                {
                    "instance_types": ["c6i.2xlarge"],
                    "ami_type": "AL2023_x86_64_STANDARD",
                    "capacity_type": "ON_DEMAND",
                    "labels": {"m5-role": "cpu"},
                    "scaling_config": [
                        {"min_size": 3, "max_size": 3, "desired_size": 3}
                    ],
                },
            ),
            change(
                "aws_eks_addon",
                "network",
                {
                    "addon_name": "vpc-cni",
                    "configuration_values": '{"enableNetworkPolicy":"true"}',
                },
            ),
            change("aws_iam_role_policy", "operator", {"policy": json.dumps(policy)}),
        ],
        "configuration": {
            "root_module": {
                "module_calls": {
                    "eks": {
                        "expressions": {
                            "pins": {
                                "references": [
                                    "module.operator.public_ip",
                                    "module.operator.role_arn",
                                ]
                            },
                        }
                    }
                }
            }
        },
    }


def facts(path):
    return {"bytes": path.stat().st_size, "sha256": digest(path)}


def fixture_packet(work, producer):
    directory = work / "packet"
    directory.mkdir()
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    bundle = source_bundle(directory / "source.bundle", commit)
    routine = json.loads(Path("/opt/dec077/runtime.json").read_bytes())
    image_input, images = cpu_image_input(directory, producer, commit, routine["ami"])
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["eks:DescribeCluster"], "Resource": "*"}
        ],
    }
    main = snapshot_plan(policy)
    empty = {"resource_changes": []}
    (directory / "tool").write_bytes(b"fixture Terraform and Docker interface")
    selection = {
        "directory": PLAN_DIRECTORY,
        "zone": "us-east-1a",
        "control_plane_zone": "us-east-1b",
    }
    timing = session_timing(180, 140)
    timing["capacity_wait_budget_seconds"] = 0
    manifest = {
        "source_commit": commit,
        "session": SESSION,
        "account": "fixture",
        "timing": timing,
        "operator_tools": {
            "terraform": {"path": str(directory / "tool"), **facts(directory / "tool")}
        },
        "alternatives": [selection],
        "forecast_basis": {"hourly_usd": 0, "fixed_other_usd": 0, "margin": 1},
        "cleanup_policy_sha256": canonical_digest(policy),
        "descriptive": {
            "session": SESSION,
            "timing": timing,
            "startup_seconds": 180,
            "cpu_clock_rehearsal": {
                "selection": selection,
                "images": images,
                "service_images": SERVICE_IMAGES,
                "operator_policy_sha256": canonical_digest(policy),
                "operator_actions_sha256": canonical_digest(policy_actions(policy)),
                "backstop_actions_sha256": canonical_digest(policy_actions(policy)),
            },
            "streaming": {
                "gpu_hourly_usd": 0,
                "conditions": {
                    "source": commit,
                    "artifact_path": "cpu-clock-fitness",
                    "model": "cpu-sse-mock",
                    "revision": "fixture",
                    "engine_version": "cpu-mock",
                    "image_digest": images["client"]["manifest_digest"],
                    "engine_flags": [],
                    "gpu_type": None,
                    "gpu_count": 0,
                    "capacity_type": "fixture",
                    "zone": None,
                    "policy": "round_robin",
                    "tenants": list(TENANTS),
                    "seed": 399060,
                    "run_count": 1,
                    "schedule_sha256": schedule_digest(),
                    "pins": {},
                    "limits": {"window_seconds": 600},
                },
            },
        },
        "host_manifest": {
            "role": "descriptive_operator",
            "workload": "m5-descriptive",
            "source_commit": commit,
            "source_payload": json.loads(
                bundle.with_suffix(".payload.json").read_bytes()
            ),
            "python_sha256": routine["python_sha256"],
            "pins": routine["pins"],
            "bundle_bytes": bundle.stat().st_size,
            "bundle_sha256": digest(bundle),
            "upload_timeout_s": 140,
            "gate_a_inputs": image_input,
            "ami": routine["ami"],
        },
        "plans": [],
    }
    backstop = {
        "resource_changes": [
            change("aws_iam_role_policy", "cleanup", {"policy": json.dumps(policy)})
        ]
    }
    for name, plan in (
        ("bootstrap", empty),
        ("backstop", backstop),
        (PLAN_DIRECTORY, main),
    ):
        plan_root = directory / name
        plan_root.mkdir()
        (plan_root / "create.tfplan").write_bytes(b"fixture provider binary")
        write(plan_root / "show.stdout", plan)
        manifest["plans"].append(
            {
                "directory": name,
                "sha256": digest(plan_root / "create.tfplan"),
                "json_sha256": digest(plan_root / "show.stdout"),
            }
        )
    return directory, manifest, main


def seal(directory, manifest):
    manifest["files"] = {
        path.relative_to(directory).as_posix(): facts(path)
        for path in directory.rglob("*")
        if path.is_file() and path.name != "manifest.json"
    }
    write(directory / "manifest.json", manifest)
    return digest(directory / "manifest.json")


class FixtureHost(LocalSSM):
    def __init__(self, directory, manifest, *, manifest_path, profile):
        self.directory, self.manifest = directory, manifest
        self.manifest_bytes = json.dumps(manifest).encode()
        self.reconnects = 0
        super().__init__(directory.parent / "host", directory, manifest)

    def bootstrap(self, end):
        self.agent.deadline = end

    def run_checks(self, end):
        # The routine allocation already bootstrapped and pinned these tools.
        # Copy its locked venv into the isolated host checkout. Replace the
        # OS installer only so it cannot reconfigure the routine host.
        shutil.copytree(
            ROOT / "python/.venv", self.agent.repo / "python/.venv", symlinks=True
        )
        sites = self.agent.repo / "python/.venv/lib/python3.12/site-packages"
        (sites / "sitecustomize.py").write_text(SITE, encoding="utf-8")
        self.agent.root.joinpath("tools").mkdir()
        tools = self.agent.repo / ".tools"
        tools.mkdir()
        for name in ("kind", "kubectl"):
            shutil.copyfile(Path("/opt/dec077/tools") / name, tools / name)
            (tools / name).chmod(0o755)
        child = SimpleNamespace(poll=lambda: 0, pid=1)
        with mock.patch("package_a_host.subprocess.Popen", return_value=child) as start:
            self.request("/start", end=end)
        if (
            start.call_count != 1
            or start.call_args.kwargs["env"] != operator.host_environment()
        ):
            raise ValueError("cpu_clock:fitness_start_environment")
        (self.agent.root / "results/runner/descriptive").mkdir(
            parents=True, exist_ok=True
        )

    def ssm(self, host, commands, *, timeout_s, step=None):
        if not step:
            if "dec077-terminate.timer" not in commands[0]:
                raise ValueError("cpu_clock:unexpected_fitness_timer_command")
            self.calls.append(
                {"step": "timer", "exit_code": 0, "environment": "simulated"}
            )
            return {}
        if "/usr/bin/env -i " not in commands[0]:
            raise ValueError("cpu_clock:fitness_phase_environment")
        # Avoid replacing the routine host tools; phase venv symlinks refer to
        # those same pins. LocalSSM's mount namespace keeps the repo isolated.
        from rehearse_m5_descriptive_phases import namespace_command

        with mock.patch(
            "rehearse_m5_descriptive_phases.namespace_command",
            side_effect=lambda root, shell, **_: namespace_command(root, shell),
        ):
            return super().ssm(host, commands, timeout_s=timeout_s, step=step)


def rehearse(work, producer):
    directory, manifest, main = fixture_packet(work, producer)
    trace, calls, mutations = [], [], {}
    created = set()

    class FakeProvider(operator.EKSports):
        def tf(self, root, *argv):
            if argv[0] != "apply" or root.name in created:
                raise ValueError("cpu_clock:fitness_unexpected_tf")
            created.add(root.name)
            trace.append("apply-" + root.name)

        def teardown(self):
            if self.host:
                calls.extend(
                    {key: row[key] for key in ("step", "exit_code", "environment")}
                    for row in self.host.calls
                )
                self.host.close()
                if self.host.agent.log:
                    self.host.agent.log.close()
            for root in (PLAN_DIRECTORY, "bootstrap", "backstop"):
                trace.append("destroy-" + root)
                created.discard(root)
            return {"complete": not created}

        def inventory(self):
            trace.append("inventory")
            return {"complete": not created}

    identity = SimpleNamespace(get_caller_identity=lambda: {"Account": "fixture"})
    ssm = SimpleNamespace(put_parameter=lambda **_: {"Version": 1})
    busy = False
    quotas = SimpleNamespace(get_service_quota=lambda **_: {"Quota": {"Value": 32}})
    ec2 = SimpleNamespace(
        can_paginate=lambda _: False,
        describe_instances=lambda **_: {
            "Reservations": [{"Instances": [{"InstanceType": "m6i.2xlarge"}]}]
            if busy
            else [],
        },
        describe_instance_types=lambda **_: {
            "InstanceTypes": [
                {"InstanceType": "m6i.2xlarge", "VCpuInfo": {"DefaultVCpus": 8}}
            ],
        },
    )
    services = {"sts": identity, "ssm": ssm, "ec2": ec2, "service-quotas": quotas}
    sdk = SimpleNamespace(client=services.__getitem__)
    real_output = subprocess.check_output

    def launch(sealed):
        def check_output(argv, **kwargs):
            if argv[:3] == ["git", "show", "HEAD:REVIEW.md"]:
                return (
                    "## Claude Round 0 fixture\n"
                    f"{CPU_MARKER} manifest={sealed} source={manifest['source_commit']}\n"
                ).encode()
            if argv[0] == str(directory / "tool") and argv[-2:] == ["output", "-json"]:
                return json.dumps(
                    {
                        "operator_instance": {"value": "fixture"},
                        "repository_url": {"value": "localhost/fixture"},
                    }
                ).encode()
            return real_output(argv, **kwargs)

        with (
            mock.patch.object(operator, "EKSports", FakeProvider),
            mock.patch.object(operator, "Ports", FixtureHost),
            mock.patch.object(operator, "arming_witness", return_value={"armed": True}),
            mock.patch.object(
                operator,
                "select_capacity",
                side_effect=AssertionError("GPU capacity path"),
            ),
            mock.patch.object(boto3, "Session", return_value=sdk),
            mock.patch.object(subprocess, "check_output", side_effect=check_output),
        ):
            operator.run_packet(
                SimpleNamespace(
                    packet=directory,
                    profile="fixture",
                    cleanup_only=False,
                    approved_manifest_sha256=sealed,
                )
            )

    for name, expected in (
        ("missing-policy-flag", "cpu_clock:network_policy"),
        ("gpu-node-group", "cpu_clock:gpu_resource"),
        ("wrong-image-digest", "cpu_clock:image_digest"),
        ("swapped-image-digests", "cpu_clock:image_digest"),
        ("busy-quota", "cpu_clock:standard_quota_busy"),
    ):
        busy = name == "busy-quota"
        bad_plan, bad_manifest = copy.deepcopy(main), copy.deepcopy(manifest)
        if name == "missing-policy-flag":
            bad_plan["resource_changes"][2]["change"]["after"][
                "configuration_values"
            ] = None
        elif name == "gpu-node-group":
            bad_plan["resource_changes"].append(change("aws_eks_node_group", "gpu", {}))
        elif name in {"wrong-image-digest", "swapped-image-digests"}:
            client = bad_manifest["descriptive"]["cpu_clock_rehearsal"]["images"][
                "client"
            ]
            if name == "wrong-image-digest":
                client["config_digest"] = "sha256:" + "5" * 64
            else:
                client["config_digest"], client["manifest_digest"] = (
                    client["manifest_digest"],
                    client["config_digest"],
                )
        path = directory / PLAN_DIRECTORY / "show.stdout"
        write(path, bad_plan)
        bad_manifest["plans"][-1]["json_sha256"] = digest(path)
        try:
            launch(seal(directory, bad_manifest))
        except ValueError as error:
            if (
                str(error) != expected
                or trace
                or (directory / "consumed.json").exists()
            ):
                raise
            mutations[name] = {"refusal": str(error), "apply_calls": 0}
            if busy:
                mutations[name]["readback"] = operator.standard_quota_readback(sdk)
        else:
            raise ValueError("cpu_clock:fitness_mutation_accepted:" + name)
    busy = False
    write(directory / PLAN_DIRECTORY / "show.stdout", main)
    launch(seal(directory, manifest))
    results = directory / "execution/results-final"
    from inference_platform.inf060_eks_receipts import verify

    final = verify(results)
    proof = json.loads((directory / "execution/operation.json").read_bytes())
    if any(row["status"] != "passed" for row in proof["phases"]):
        raise ValueError("cpu_clock:fitness_phase")
    if trace != [
        "apply-bootstrap",
        "apply-backstop",
        "apply-cpu-clock",
        "destroy-cpu-clock",
        "destroy-bootstrap",
        "destroy-backstop",
        "inventory",
    ]:
        raise ValueError("cpu_clock:fitness_order")
    return {
        "status": "PASS",
        "mutations": mutations,
        "simulated_provider_order": trace,
        "phase_commands": calls,
        "verified_transfer_labels": sorted(proof["transfers"]),
        "bounded_rehearsal_manifest": final["complete"] is False,
        "durations_s": {row["phase"]: row["elapsed_s"] for row in proof["phases"]},
        "substitutions": {
            "terraform": "sealed fixture changes, Apply/destroy/inventory simulated",
            "ssm": "mount namespace and loopback Host HTTP; SSM network and OS timer simulated",
            "bootstrap": "real sparse source uploads and /start, reuse routine tooling and locked venv",
            "kubernetes": "safety and synthetic observation fixture, no EKS, ECR or live pods",
            "clock": "simulated readbacks; measured kind widths recorded in Round 418",
        },
    }


def main():
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument("--output", type=Path, required=True)
    args.add_argument("--images", type=Path, required=True)
    options = args.parse_args()
    output = options.output
    with tempfile.TemporaryDirectory(dir=output.parent) as path:
        work = Path(path)
        with contextlib.redirect_stdout(io.StringIO()):
            receipt = rehearse(work, options.images)
        write(output, receipt)


if __name__ == "__main__":
    main()
