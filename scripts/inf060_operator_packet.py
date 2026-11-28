"""Linux paths, separate operator plan and verification for INF-060."""

import hashlib
import json
import math
import os
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

import inf060_probe_spec as spec
import inf061_packet as benchmark
from inf060_operator_policy import operator_policy

ROOT = "/opt/inf060/operator"
PACKET = ROOT + "/.cache/packet"
TIMER = 7200
SHAPE = "m6i.large"
ROOT_GIB = 32
RUNTIME_DATA = ("deploy/package-a/cpu-test-weights.json",)
TOOLS = {
    "terraform": {
        "path": "/usr/local/bin/terraform",
        "url": "https://releases.hashicorp.com/terraform/1.16.2/terraform_1.16.2_linux_amd64.zip",
        "sha256": "0d17011f0c4664539b164b044903d04e296c86c13cb9f28040076c65cfb3985a",
    },
    "aws": {
        "path": "/usr/local/bin/aws",
        "url": "https://awscli.amazonaws.com/awscli-exe-linux-x86_64-2.31.26.zip",
        "sha256": "fca9d80afb77f4cf5f2df6078b30ebb123b40e5b070ee7c1d5c3fba92d6b3755",
    },
    "plugin": {
        "path": "/usr/local/bin/session-manager-plugin",
        "url": "https://s3.amazonaws.com/session-manager-downloads/plugin/1.2.707.0/ubuntu_64bit/session-manager-plugin.deb",
        "sha256": "91cc9a1a8df6f730622d5e11a8610be6e06d5858408e8029b56d0d63aedd0a68",
    },
    "python": {"path": "/usr/bin/python3"},
}
COUNTERS = {
    "active_instances",
    "volumes",
    "interfaces",
    "vpcs",
    "subnets",
    "security_groups",
    "route_tables",
    "gateways",
    "addresses",
    "roles",
    "profiles",
    "terraform_resources",
}


def require_zero(row, *, state=True, capacity=False):
    expected = COUNTERS if state else COUNTERS - {"terraform_resources"}
    if capacity:
        expected = expected | {
            "session_reservations",
            "untagged_regional_reservations",
            "foreign_regional_reservations",
            "launch_templates",
        }
    spec.check(
        set(row) == expected | {"empty"}
        and row["empty"] is True
        and all(type(row[k]) is int and row[k] == 0 for k in expected),
        "inventory_unverified",
    )


def commands():
    return {
        key: [
            TOOLS["python"]["path"],
            ROOT + "/scripts/inf060_probe_operator.py",
            mode,
            "--directory",
            PACKET,
            "--instance-role",
        ]
        for key, mode in (
            ("controller", "execute"),
            ("cleanup", "cleanup"),
            ("inventory", "inventory"),
        )
    }


def budget(live, rates, *, timer=TIMER):
    hourly = (
        live["rate"]
        + rates["ipv4_usd_per_h"]
        + ROOT_GIB * rates["gp3_usd_per_gib_month"] / 720
    )
    spec.check(0 < hourly < math.inf, "operator_price")
    estimate = hourly * timer / 3600 * 1.15
    return {
        "hourly_usd": hourly,
        "forecast_usd": estimate,
        "cap_usd": math.ceil(100 * estimate) / 100,
        "timer_s": timer,
    }


def gpu_main(main, *, zone=spec.ZONE, open_capacity=False):
    original = 'name_prefix = "${var.session}-"'
    spec.check(main.count(original) == 2, "gpu_role_name_template")
    az = f'availability_zone       = "{spec.ZONE}"'
    spec.check(main.count(az) == 1, "gpu_zone_template")
    if open_capacity:
        from inf061_capacity import OPEN_CAPACITY_PREFERENCE, open_template_placement

        placement = open_template_placement(zone)
        marker = 'resource "aws_instance" "task" {'
        spec.check(main.count(marker) == 1, "gpu_open_capacity_template")
        template = (
            'resource "aws_launch_template" "native_capacity" {\n'
            '  name = "${var.session}-capacity"\n'
            "  tags = local.tags\n"
            "  ebs_optimized = false\n"
            "  placement {\n"
            f'    availability_zone = "{placement["AvailabilityZone"]}"\n'
            f'    tenancy = "{placement["Tenancy"]}"\n'
            "  }\n"
            "  capacity_reservation_specification {\n"
            f'    capacity_reservation_preference = "{OPEN_CAPACITY_PREFERENCE}"\n'
            "  }\n"
            "}\n"
        )
        main = main.replace(
            marker,
            template
            + marker
            + (
                "\n  launch_template {\n"
                "    id = aws_launch_template.native_capacity.id\n"
                '    version = "1"\n'
                "  }"
            ),
        )
    return (
        main.replace(az, f'availability_zone       = "{zone}"')
        .replace(original, 'name = "${var.session}-gpu"')
        .replace(
            "tags        = local.tags",
            "tags        = merge(local.tags, { Inf060Target = var.session })",
        )
    )


def verify_runtime(archive, files):
    with tarfile.open(archive) as stream:
        members = stream.getmembers()
        by_name = {member.name: member for member in members}
        for name in RUNTIME_DATA:
            spec.check(
                name in by_name and name in files, "operator_runtime_data:" + name
            )
        spec.check(
            len(members) == len(by_name) and by_name.keys() == files.keys(),
            "operator_runtime_members",
        )
        for name, member in by_name.items():
            spec.check(
                member.isfile()
                and not Path(name).is_absolute()
                and ".." not in Path(name).parts,
                "operator_runtime_path",
            )
            with stream.extractfile(member) as content:
                observed = {
                    "bytes": member.size,
                    "sha256": hashlib.file_digest(content, "sha256").hexdigest(),
                }
            spec.check(observed == files[name], "operator_runtime_member:" + name)


def import_runtime(root):
    """Run both entry points with only the extracted tree and Python stdlib."""
    code = (
        "import sys,runpy;"
        "sys.path[:0]=['scripts','python/src'];"
        "import inf060_remote_service,rehearse_inf060_probe,inf060_probe_operator,inf060_allow_side;"
        "sys.argv=['inf060_remote_service','--help'];"
        "runpy.run_path('scripts/inf060_remote_service.py',run_name='__main__')"
    )
    if os.name == "posix":
        argv = ["/usr/bin/env", "-i", "/usr/bin/python3"]
        env = {}
    else:
        argv = [sys.executable]
        env = {
            key: os.environ[key]
            for key in ("SYSTEMROOT", "WINDIR", "TEMP", "TMP")
            if key in os.environ
        }
    output = subprocess.check_output(
        [*argv, "-I", "-S", "-B", "-c", code],
        cwd=root,
        env=env,
        stderr=subprocess.STDOUT,
        timeout=60,
    )
    spec.check(
        b"usage:" in output and b"--mock-host" in output, "operator_runtime_help"
    )
    return {
        "isolated": True,
        "empty_environment": os.name == "posix",
        "imports": True,
        "help_exit": 0,
    }


def build_host(
    directory,
    source,
    live,
    account,
    env,
    tf,
    *,
    timer=TIMER,
    defer_simulation=False,
    capacity=None,
):
    from inf060_allow_side import FREE_RESOURCES, verify_free_plan
    from inf060_policy_gate import ACTION_RECORD, seal
    from prepare_inf060_probe import AGENT, bundle, bytes_facts, git, gitblob

    folder = directory / "operator-host"
    folder.mkdir()
    gpu_live = spec.load(directory / "live-inputs.json")
    session, zone = gpu_live["session"], gpu_live["zone"]
    spec.check(
        live["ami_available"] == "available"
        and live["quotavcpus"] >= 2
        and live["shape"] == SHAPE
        and live["route_count"] == 0
        and any(
            row["InstanceType"] == SHAPE
            and row["Location"] == spec.ZONE
            and row["LocationType"] == "availability-zone"
            for row in live["offerings"]
        ),
        "operator_live_inputs",
    )
    spec.save(folder / "live.json", live)
    policy = operator_policy(
        account, session, spec.AMI, zone=zone, open_capacity=bool(capacity)
    )
    spec.save(folder / "policy.json", policy)
    actions = folder / "actions.json"
    actions.write_bytes(gitblob(source, ACTION_RECORD))

    def invoke(service, operation, args):
        raw = subprocess.check_output(
            [
                "aws",
                "--profile",
                env["AWS_PROFILE"],
                "--region",
                spec.REGION,
                service,
                operation,
                *args,
                "--output",
                "json",
                "--no-cli-pager",
            ],
            timeout=50,
        )
        return json.loads(raw)

    if not defer_simulation:
        spec.save(
            folder / "policy-simulation.json",
            seal(
                invoke,
                folder / "policy.json",
                actions,
                account,
                session,
                spec.AMI,
                zone=zone,
                off_zone="us-east-1e" if capacity else spec.ZONE,
            ),
        )
        if capacity:
            from inf060_policy_gate import simulate
            from inf061_capacity import (
                deny_policy_cases,
                policy_cases,
                verify_capacity_policy,
            )

            rows = simulate(
                invoke,
                policy,
                (),
                account,
                session,
                spec.AMI,
                cases=policy_cases(account, session),
            )
            denied = simulate(
                invoke,
                policy,
                (),
                account,
                session,
                spec.AMI,
                cases=deny_policy_cases(account, session),
            )
            digest = spec.facts(folder / "policy.json")["sha256"]
            receipt = {"results": rows, "denied": denied, "policy_sha256": digest}
            verify_capacity_policy(receipt, digest, account, session)
            spec.save(folder / "capacity-policy-simulation.json", receipt)
    gpu = directory / "terraform"
    rehearsal_plan = folder / "allow-side.tfplan"
    subprocess.check_output(
        [
            str(tf),
            "plan",
            "-refresh=false",
            "-input=false",
            "-var-file=input.tfvars.json",
            *("-target=" + target for target in sorted(FREE_RESOURCES)),
            "-out=" + str(rehearsal_plan),
        ],
        cwd=gpu,
        env=env,
        timeout=180,
        stderr=subprocess.STDOUT,
    )
    (folder / "allow-side.json").write_bytes(
        subprocess.check_output(
            [str(tf), "show", "-json", str(rehearsal_plan)],
            cwd=gpu,
            env=env,
            timeout=90,
        )
    )
    verify_free_plan(
        spec.load(folder / "allow-side.json"), spec.load(gpu / "input.tfvars.json")
    )
    spec.save(folder / "tools.json", TOOLS)
    spec.save(folder / "launch.json", launch_sequence())
    modules = (
        git("ls-tree", "-r", "--name-only", source, "python/src/inference_platform")
        .decode()
        .splitlines()
    )
    names = [n for n in modules if n.endswith(".py")] + [
        "scripts/" + n
        for n in (
            *AGENT,
            "inf060_probe_operator.py",
            "inf060_apply.py",
            "inf060_operator_packet.py",
            "inf060_operator_policy.py",
            "inf060_policy_gate.py",
            "inf060_allow_side.py",
            "inf060_probe_spec.py",
            "inf061_packet.py",
            "inf061_capacity.py",
            "m5_descriptive_capacity.py",
            "m5_descriptive_cleanup.py",
            "prepare_inf060_probe.py",
            "l4_compat_deadline.py",
            "inf060_remote_service.py",
            "inf060_probe_results.py",
            "rehearse_inf060_probe.py",
        )
    ]
    items = {name: gitblob(source, name) for name in [*names, *RUNTIME_DATA]}
    archive = folder / "runtime.tar.gz"
    files = {name: bytes_facts(raw) for name, raw in items.items()}
    bundle(archive, items)
    spec.save(folder / "runtime-files.json", files)
    verify_runtime(archive, files)
    with tempfile.TemporaryDirectory(
        prefix="inf060-operator-import-", dir=os.environ.get("TMPDIR")
    ) as stage:
        with tarfile.open(archive) as stream:
            stream.extractall(stage, filter="data")
        spec.save(folder / "runtime-import.json", import_runtime(stage))
    for name in spec.TERRAFORM_FILES:
        raw = gitblob(source, "infra/terraform/package_a/" + name)
        if name == "main.tf":
            text = (
                raw.decode()
                .replace(
                    'contains(["m6i.2xlarge", "c6i.2xlarge"], var.instance_type)',
                    'var.instance_type == "m6i.large"',
                )
                .replace(
                    "var.root_gib >= 64 && var.root_gib <= 100", "var.root_gib == 32"
                )
                .replace(
                    'name_prefix = "${var.session}-"', 'name = "${var.session}-cpu"'
                )
            )
            text += '\nresource "aws_iam_role_policy" "probe" {\n  role = aws_iam_role.task[0].name\n  name = "native-probe-controller"\n  policy = file("${path.module}/policy.json")\n}\n'
            raw = text.encode()
        (folder / name).write_bytes(raw)
    spec.save(
        folder / "input.tfvars.json",
        {
            "ami": live["ami"],
            "session": live["session"],
            "source_commit": source,
            "enable_task": True,
            "instance_type": SHAPE,
            "root_gib": ROOT_GIB,
            "host_timer_seconds": timer,
        },
    )
    operator_env = {**env, "TF_DATA_DIR": env["TF_DATA_DIR"] + "-operator"}
    for argv, output in [
        (["init", "-input=false", "-lockfile=readonly"], None),
        (
            [
                "plan",
                "-input=false",
                "-refresh=false",
                "-var-file=input.tfvars.json",
                "-out=create.tfplan",
            ],
            None,
        ),
        (["show", "-json", "create.tfplan"], "create.json"),
    ]:
        raw = subprocess.check_output(
            [str(tf), *argv], cwd=folder, env=operator_env, timeout=240
        )
        if output:
            (folder / output).write_bytes(raw)
    files = [
        *spec.TERRAFORM_FILES,
        "policy.json",
        "launch.json",
        "tools.json",
        "live.json",
        "input.tfvars.json",
        "create.tfplan",
        "create.json",
        "runtime.tar.gz",
        "runtime-files.json",
        "runtime-import.json",
        "actions.json",
        "allow-side.tfplan",
        "allow-side.json",
    ]
    if not defer_simulation:
        files.append("policy-simulation.json")
        if capacity:
            files.append("capacity-policy-simulation.json")
    return {
        "artifacts": {f: spec.facts(folder / f) for f in files},
        "role_policy_sha256": spec.facts(folder / "policy.json")["sha256"],
        "create_sha256": spec.facts(folder / "create.tfplan")["sha256"],
        "actions_sha256": spec.facts(actions)["sha256"],
        "session": live["session"],
        **budget(live, spec.load(directory / "live-inputs.json")["rates"], timer=timer),
    }


def launch_sequence():
    return [
        "/usr/bin/systemd-run",
        "--unit=inf060-native",
        "--property=Restart=no",
        "--property=UMask=0077",
        "--working-directory=" + ROOT,
        "/usr/bin/env",
        "-i",
        "PATH=/usr/local/bin:/usr/bin:/bin",
        "HOME=/root",
        "LANG=C.UTF-8",
        "AWS_REGION=us-east-1",
        "AWS_CONFIG_FILE=/dev/null",
        "AWS_SHARED_CREDENTIALS_FILE=/dev/null",
        "AWS_EC2_METADATA_V1_DISABLED=true",
        "PYTHONDONTWRITEBYTECODE=1",
        "PYTHONPATH=" + ROOT + "/python/src",
        "/usr/bin/python3",
        ROOT + "/scripts/inf060_remote_service.py",
    ]


def verify(directory, manifest):
    host = manifest["operator_host"]
    native = benchmark.is_benchmark(manifest)
    benchmark_plan = spec.load(directory / "benchmark.json") if native else None
    timer_s = benchmark_plan["operator_timer_s"] if native else TIMER
    capacity = manifest.get("capacity_hunt")
    folder = directory / "operator-host"
    expected = {
        *spec.TERRAFORM_FILES,
        "policy.json",
        "launch.json",
        "tools.json",
        "live.json",
        "input.tfvars.json",
        "create.tfplan",
        "create.json",
        "runtime.tar.gz",
        "runtime-files.json",
        "runtime-import.json",
    }
    if "actions_sha256" in host:
        expected |= {
            "actions.json",
            "policy-simulation.json",
            "allow-side.tfplan",
            "allow-side.json",
        }
    if capacity:
        expected.add("capacity-policy-simulation.json")
    spec.check(host["artifacts"].keys() == expected, "operator_artifact_set")
    for name, bound in host["artifacts"].items():
        spec.check(
            spec.facts(spec.safe_file(folder, name)) == bound,
            "operator_artifact:" + name,
        )
    verify_runtime(folder / "runtime.tar.gz", spec.load(folder / "runtime-files.json"))
    spec.check(
        host["create_sha256"] == host["artifacts"]["create.tfplan"]["sha256"],
        "operator_create_plan",
    )
    policy = spec.load(folder / "policy.json")
    spec.check(
        spec.facts(folder / "policy.json")["sha256"] == host["role_policy_sha256"],
        "operator_policy_hash",
    )
    role = next(
        s["Resource"] for s in policy["Statement"] if "iam:PassRole" in s["Action"]
    )
    account = role.split(":")[4]
    if "actions_sha256" in host:
        from inf060_allow_side import verify_free_plan
        from inf060_policy_gate import action_cases, action_names, require_allowed

        cases = spec.load(folder / "policy-simulation.json")
        derived = action_names(spec.load(folder / "actions.json"))
        expected_cases = {
            (action, label, tuple(sorted(context)))
            for action in derived
            for label, _, context in action_cases(
                action, account, manifest["session"], spec.AMI, zone=manifest["zone"]
            )
        }
        rows = cases["results"]
        require_allowed(rows)
        spec.check(
            cases["action_count"] == len(derived)
            and len(rows) == len(expected_cases)
            and {(r["action"], r["resource"], tuple(r["context"])) for r in rows}
            == expected_cases
            and cases["policy_sha256"] == host["role_policy_sha256"]
            and cases["actions_sha256"]
            == host["actions_sha256"]
            == host["artifacts"]["actions.json"]["sha256"]
            and cases["mutation"]["decision"] == "implicitDeny",
            "sealed_policy_simulation",
        )
        if manifest["zone"] != spec.ZONE or capacity:
            off_zone = "us-east-1e" if capacity else spec.ZONE
            spec.check(
                cases.get("zone") == manifest["zone"]
                and cases.get("off_zone", {}).get("zone") == off_zone
                and cases["off_zone"].get("decision") == "implicitDeny"
                and cases["off_zone"].get("action") == "ec2:RunInstances"
                and cases["off_zone"].get("resource") == "instance",
                "sealed_policy_zone_simulation",
            )
        verify_free_plan(
            spec.load(folder / "allow-side.json"),
            spec.load(directory / "terraform/input.tfvars.json"),
        )
    spec.check(
        hashlib.sha256(account.encode()).hexdigest() == manifest["account_id_sha256"]
        and policy
        == operator_policy(
            account,
            manifest["session"],
            spec.AMI,
            zone=manifest["zone"],
            open_capacity=bool(capacity),
        ),
        "operator_policy_scope",
    )
    plan = spec.load(folder / "create.json")
    rows = {r["address"]: r["change"] for r in plan["resource_changes"]}
    spec.check(
        plan["applyable"]
        and plan["complete"]
        and not plan["errored"]
        and set(rows) == spec.RESOURCES | {"aws_iam_role_policy.probe"}
        and all(r["actions"] == ["create"] for r in rows.values()),
        "operator_plan_resources",
    )
    if capacity:
        from inf061_capacity import verify_capacity_policy

        verify_capacity_policy(
            spec.load(folder / "capacity-policy-simulation.json"),
            host["role_policy_sha256"],
            account,
            manifest["session"],
        )
    spec.check(
        json.loads(rows["aws_iam_role_policy.probe"]["after"]["policy"]) == policy,
        "planned_operator_policy",
    )
    spec.check(
        rows["aws_subnet.task[0]"]["after"]["availability_zone"] == spec.ZONE,
        "operator_zone_changed",
    )
    vm = rows["aws_instance.task[0]"]["after"]
    live = spec.load(folder / "live.json")
    timer = (
        (folder / "user-data.sh")
        .read_text()
        .replace("${host_timer_seconds}", str(timer_s))
    )
    spec.check(
        "systemctl enable --now dec077-terminate.timer" in timer
        and "Persistent=true" in timer
        and vm["user_data"] == timer
        and host["timer_s"] == timer_s,
        "operator_timer",
    )
    spec.check(
        vm["ami"] == live["ami"]
        and vm["instance_type"] == SHAPE
        and vm["instance_initiated_shutdown_behavior"] == "terminate"
        and vm["metadata_options"][0]["http_tokens"] == "required"
        and vm["root_block_device"][0]["volume_size"] == ROOT_GIB
        and vm["root_block_device"][0]["encrypted"]
        and vm["root_block_device"][0]["delete_on_termination"]
        and not rows["aws_security_group.task[0]"]["after"].get("ingress"),
        "operator_shape",
    )
    rates = spec.load(directory / "live-inputs.json")["rates"]
    expected_budget = budget(live, rates, timer=timer_s)
    cap = benchmark.budget(benchmark_plan, rates)["hard_cap_usd"] if native else 5.37
    spec.check(
        all(host[k] == v for k, v in expected_budget.items())
        and manifest["hard_cap_usd"] == cap
        and (not native or live["rate"] == rates["operator_compute_usd_per_h"]),
        "operator_budget",
    )
    spec.check(
        spec.load(folder / "launch.json") == launch_sequence()
        and spec.load(directory / "commands.json") == commands()
        and manifest["operator_tools"] == TOOLS,
        "linux_launch_binding",
    )
