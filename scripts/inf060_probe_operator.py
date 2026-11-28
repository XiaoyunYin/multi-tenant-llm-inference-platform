"""Hash-gated one-shot launcher and real SSM paths for the native probe."""

import argparse
import base64
import hashlib
import json
import os
import re
import shlex
import sys
import time
from functools import partial
from pathlib import Path

from inference_platform.package_a_operator import Ports, readiness_shell
from inference_platform.routine_aws_tests import RoutinePorts
from inference_platform.session_stop import stop_forward

import inf060_apply as apply_watch
import inf060_diagnostics as diagnostics
import inf060_probe_spec as spec
import inf061_packet as benchmark
from l4_compat_deadline import supervise
from prepare_inf060_probe import AGENT, ROOT, git, gitblob, validate_inputs


def checked_packet(directory, review, *, remote_host=False):
    manifest = spec.verify_packet(directory)
    spec.approval(review, manifest, spec.facts(directory / "manifest.json")["sha256"])
    source = manifest["source_commit"]
    if "operator_host" in manifest:
        from inf060_operator_packet import verify

        verify(directory, manifest)
    if remote_host:
        from inf060_operator_packet import PACKET

        spec.check(
            directory == Path(PACKET) and "operator_host" in manifest,
            "remote_execution_root",
        )
        for name, expected in manifest["bootstrap_sources"].items():
            spec.check(
                spec.facts(ROOT / "scripts" / name) == expected, "bootstrap_source"
            )
        spec.check(
            not (directory / "consumed.json").exists()
            and not (directory / "terraform/terraform.tfstate").exists(),
            "already_consumed_or_state",
        )
        return manifest
    git("merge-base", "--is-ancestor", source, "HEAD")
    if benchmark.is_benchmark(manifest):
        from inf061_capacity import PLAN_SOURCE

        path = (
            PLAN_SOURCE
            if "capacity_hunt" in manifest
            else "docs/INF061_FINAL_PLAN.json"
        )
        spec.check(
            gitblob(source, path) == (directory / "benchmark.json").read_bytes(),
            "benchmark_source",
        )
    protected = [
        "python",
        "scripts",
        "infra",
        "deploy",
        "internal",
        "cmd",
        "go.mod",
        "go.sum",
    ]
    spec.check(
        not git("diff", "--name-only", source, "--", *protected),
        "operator_source_changed",
    )
    for name, expected in manifest["bootstrap_sources"].items():
        raw = gitblob(source, "scripts/" + name)
        spec.check(
            {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()} == expected,
            "bootstrap_source",
        )
    for entry in (
        () if "operator_host" in manifest else manifest["operator_tools"].values()
    ):
        spec.check(
            spec.facts(Path(entry["path"]))
            == {k: entry[k] for k in ("bytes", "sha256")},
            "operator_tool_changed",
        )
    spec.check(
        not (directory / "consumed.json").exists()
        and not (directory / "terraform/terraform.tfstate").exists(),
        "already_consumed_or_state",
    )
    return manifest


class ProbePorts(Ports):
    def __init__(
        self,
        directory,
        manifest,
        profile,
        runtime,
        *,
        cpu=False,
        recovering=False,
        failure=None,
    ):
        super().__init__(
            directory,
            manifest,
            profile=profile,
            runtime_directory=runtime,
            recovering=recovering,
        )
        self.inputs["ssm_remote_port"] = spec.PORT + (
            diagnostics.FAILURES.index(failure) + 1 if failure else 0
        )
        self.cpu = cpu
        self.failure = failure
        self.root = spec.REMOTE + ("-" + failure if failure else "")
        self.diagnostic_dir = runtime
        self.capacity_selection = None
        self.selected_root = None
        if "capacity_hunt" in manifest:
            from inf061_capacity import STATE, selected_plan

            if (directory / STATE).exists() and (
                not recovering or (directory / "consumed.json").exists()
            ):
                self.capacity_selection, self.selected_root = selected_plan(
                    directory, manifest
                )

    @property
    def terraform_directory(self):
        return self.selected_root or super().terraform_directory

    @property
    def saved_create_sha256(self):
        if self.capacity_selection is not None:
            return self.capacity_selection["plan_sha256"]
        return super().saved_create_sha256

    def command(self, argv, deadline, name):
        if name == "apply" and benchmark.is_benchmark(self.manifest):
            return super().command(
                argv,
                deadline,
                name,
                execute=partial(
                    apply_watch.run,
                    zone=(self.capacity_selection or self.manifest)["zone"],
                ),
            )
        if name == "destroy" and benchmark.is_benchmark(self.manifest):
            argv = [*argv, f"-var=provider_attempts={benchmark.DESTROY_ATTEMPTS}"]
        return super().command(argv, deadline, name)

    def request(self, path, data=None, headers=None, *, end):
        result = super().request(path, data, headers, end=end)
        if path == "/status":
            diagnostics.write(
                self.diagnostic_dir / "runner-status.json",
                diagnostics.status_body(json.loads(result[0])),
            )
        return result

    def bootstrap(self, end):
        self.deadline = end
        registration_end = min(end, time.time() + 180)
        while registration_end - time.time() > 5:
            rows = self.aws(
                "ssm",
                "describe-instance-information",
                [
                    "--filters",
                    json.dumps([{"Key": "InstanceIds", "Values": [self.host]}]),
                ],
                deadline=registration_end,
            )["InstanceInformationList"]
            if len(rows) == 1 and rows[0]["PingStatus"] == "Online":
                break
            time.sleep(2)
        else:
            raise TimeoutError("inf060:ssm_registration")
        directory = shlex.quote(self.root)
        self.ssm(
            self.host,
            [
                *readiness_shell(),
                "install -d -m 0700 " + directory,
                "test ! -e " + directory + "/runner.pid",
            ],
            timeout_s=60,
            step="inf060.timer_and_readiness",
        )
        if self.capacity_selection is not None:
            cutoff = int(
                self.capacity_selection["selected_epoch"]
                + self.manifest["host_timer_seconds"]
            )
            self.ssm(
                self.host,
                [
                    "set -eu; old=$(cat /etc/dec077/deadline); stop="
                    + str(cutoff)
                    + '; if [ "$old" -lt "$stop" ]; then stop=$old; fi;'
                    + " printf '%s' \"$stop\" > /etc/dec077/deadline;"
                    + ' sed -i "s/^OnCalendar=.*/OnCalendar=@$stop/" /etc/systemd/system/dec077-terminate.timer;'
                    + " systemctl daemon-reload; systemctl restart dec077-terminate.timer;"
                    + " systemctl is-active --quiet dec077-terminate.timer"
                ],
                timeout_s=30,
                step="inf061.selection_timer",
            )
        for name in AGENT:
            if "operator_host" in self.manifest:
                raw = (ROOT / "scripts" / name).read_bytes()
                spec.check(
                    hashlib.sha256(raw).hexdigest()
                    == self.manifest["bootstrap_sources"][name]["sha256"],
                    "bootstrap_source",
                )
            else:
                raw = gitblob(self.manifest["source_commit"], "scripts/" + name)
            encoded = shlex.quote(base64.b64encode(raw).decode())
            self.ssm(
                self.host,
                [
                    "set -eu; umask 077; printf %s "
                    + encoded
                    + " | base64 -d > "
                    + directory
                    + "/"
                    + name
                ],
                timeout_s=30,
                step="inf060.stage_" + name,
            )
        argv = [
            "/usr/bin/env",
            "-i",
            "PATH=/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG=C.UTF-8",
            "PYTHONDONTWRITEBYTECODE=1",
            "python3",
            self.root + "/inf060_probe_agent.py",
            "--root",
            self.root,
            "--token-file",
            self.root + "/token",
            "--manifest-sha256",
            self.manifest_hash,
            "--port",
            str(self.inputs["ssm_remote_port"]),
            "--deadline",
            str(
                self.origin
                + self.manifest["work_seconds"]
                - self.manifest["export_seconds"]
            ),
            "--origin",
            str(self.origin),
        ]
        if self.cpu:
            argv.append("--cpu-rehearsal")
        if self.failure:
            argv.extend(["--mock-failure", self.failure])
        self.ssm(
            self.host,
            [
                "set -eu; umask 077",
                "printf %s " + shlex.quote(self.token) + " > " + directory + "/token",
                "nohup "
                + shlex.join(argv)
                + " >"
                + directory
                + "/private-agent.log 2>&1 </dev/null &",
                "echo $! > " + directory + "/runner.pid",
                "for n in $(seq 1 20); do curl -fsS --max-time 2 -H "
                + shlex.quote("Authorization: Bearer " + self.token)
                + f" http://127.0.0.1:{self.inputs['ssm_remote_port']}/status && exit 0; sleep 1; done; exit 1",
            ],
            timeout_s=45,
            step="inf060.bootstrap",
        )
        self.remember_status()

    def inventory(self, end):
        # The same owned tag/resource inventory used by the routine runner.
        capacity = "capacity_hunt" in self.manifest
        if not capacity and (self.directory / "terraform/terraform.tfstate").is_file():
            before = self.manifest
            try:
                self.manifest = {**before, "routine_selection": {}}
                return RoutinePorts.inventory(self, end)
            finally:
                self.manifest = before
        self.deadline = end
        results = {
            "active_instances": len(self.instance_ids()),
            "terraform_resources": 0,
        }
        for label, operation, field in (
            ("volumes", "describe-volumes", "Volumes"),
            ("interfaces", "describe-network-interfaces", "NetworkInterfaces"),
            ("vpcs", "describe-vpcs", "Vpcs"),
            ("subnets", "describe-subnets", "Subnets"),
            ("security_groups", "describe-security-groups", "SecurityGroups"),
            ("route_tables", "describe-route-tables", "RouteTables"),
            ("gateways", "describe-internet-gateways", "InternetGateways"),
            ("addresses", "describe-addresses", "Addresses"),
        ):
            results[label] = len(
                self.aws(
                    "ec2",
                    operation,
                    [
                        "--filters",
                        "Name=tag:Session,Values=" + self.manifest["session"],
                    ],
                )[field]
            )
        for label, call, field, name in (
            ("roles", "list-roles", "Roles", "RoleName"),
            (
                "profiles",
                "list-instance-profiles",
                "InstanceProfiles",
                "InstanceProfileName",
            ),
        ):
            results[label] = sum(
                row[name].startswith(self.manifest["session"] + "-")
                for row in self.aws("iam", call, [])[field]
            )
        if capacity:
            from inf061_capacity import ROOTS, reservation_inventory

            for name in ROOTS.values():
                state = self.directory / name / "terraform.tfstate"
                if state.is_file():
                    resources = spec.load(state)["resources"]
                    spec.check(isinstance(resources, list), "capacity_state_inventory")
                    results["terraform_resources"] += len(resources)
                else:
                    spec.check(
                        not list(state.parent.glob("terraform.tfstate*")),
                        "capacity_state_inventory",
                    )
            results.update(reservation_inventory(self.aws, self.manifest["session"]))
        results["empty"] = not any(results.values())
        return results


def run_step(ports, name, action):
    start, mono = time.time(), time.monotonic()
    error = None
    try:
        return action()
    except Exception as exc:
        error = diagnostics.exception_record(exc)
        raise
    finally:
        diagnostics.write(
            ports.diagnostic_dir / ("step-" + name + ".json"),
            {
                "start_epoch": start,
                "end_epoch": time.time(),
                "elapsed_s": time.monotonic() - mono,
                "exit_code": int(error is not None),
                "error": error,
            },
        )


def work(ports, origin):
    before = origin + ports.manifest["ready_by_seconds"]
    work_end = origin + ports.manifest["work_seconds"]
    retrieve_at = work_end - ports.manifest["export_seconds"]
    run_step(ports, "bootstrap", lambda: ports.bootstrap(before))
    try:
        run_step(ports, "upload", lambda: ports.upload(before))
        run_step(ports, "run_checks", lambda: ports.run_checks(retrieve_at))
    finally:

        def retrieve():
            result = ports.retrieve(work_end)
            spec.check(
                result.get("complete") and not result.get("truncated_files"),
                "receipt_retrieval",
            )
            return result

        result = run_step(ports, "retrieve", retrieve)
        if ports.child:
            run_step(ports, "stop_forward", lambda: stop_forward(ports.child))
            ports.child = None
    return result


def native_preflight(ports, directory, manifest, origin, *, capacity_stage=None):
    ports.deadline = origin + 600
    account = ports.aws("sts", "get-caller-identity", [])["Account"]
    spec.check(
        hashlib.sha256(account.encode()).hexdigest() == manifest["account_id_sha256"],
        "account_changed",
    )
    live = spec.load(directory / "live-inputs.json")
    validate_inputs(live, zone=manifest["zone"])
    current = ports.aws("ec2", "describe-images", ["--image-ids", spec.AMI])["Images"]
    spec.check(len(current) == 1 and current[0]["State"] == "available", "ami_changed")
    offerings = ports.aws(
        "ec2",
        "describe-instance-type-offerings",
        [
            "--location-type",
            "availability-zone",
            "--filters",
            "Name=instance-type,Values=" + spec.SHAPE,
            "Name=location,Values=" + (ports.capacity_selection or manifest)["zone"],
        ],
    )["InstanceTypeOfferings"]
    spec.check(offerings, "offering_changed")
    quota = ports.aws(
        "service-quotas",
        "get-service-quota",
        [
            "--service-code",
            "ec2",
            "--quota-code",
            "L-DB2E81BA",
        ],
    )["Quota"]["Value"]
    spec.check(
        quota >= 4
        and (
            ports.inventory(origin + 600)["empty"]
            if capacity_stage != "selected"
            else selected_inventory(ports, manifest, origin + 600)
        ),
        "quota_or_owned_inventory",
    )
    if benchmark.is_benchmark(manifest):
        gpu_rows = ports.aws(
            "ec2",
            "describe-instances",
            [
                "--filters",
                "Name=instance-type,Values=g*,vt*",
                "Name=instance-state-name,Values=pending,running,shutting-down,stopping",
            ],
        )["Reservations"]
        spec.check(
            not any(row["Instances"] for row in gpu_rows), "benchmark_gpu_quota_busy"
        )
    for name, unit, key in (
        ("compute", "Hrs", "compute_usd_per_h"),
        ("gp3", "GB-Mo", "gp3_usd_per_gib_month"),
        ("ipv4", "Hrs", "ipv4_usd_per_h"),
    ):
        service, op, *query = live["queries"][name]
        spec.check((service, op) == ("pricing", "get-products"), "price_query")
        products = ports.aws(service, op, query)["PriceList"]
        prices = {
            float(d["pricePerUnit"]["USD"])
            for raw in products
            for term in json.loads(raw)["terms"].get("OnDemand", {}).values()
            for d in term["priceDimensions"].values()
            if d["unit"] == unit
        }
        spec.check(prices == {live["rates"][key]}, "price_changed:" + name)
    spec.check(time.time() + 60 < origin + 600, "apply_reserve")


def selected_inventory(ports, manifest, end):
    from inf061_capacity import active_reservations

    counts = ports.inventory(end)
    if counts.pop("session_reservations") != 1:
        return False
    counts.pop("empty")
    rows = active_reservations(ports.aws)
    if len(rows) != 1:
        return False
    row = rows[0]
    selection = ports.capacity_selection
    return (
        not any(counts.values())
        and row["CapacityReservationId"] == selection["reservation_id"]
        and row["AvailabilityZone"] == selection["zone"]
        and row["State"] == "active"
        and row["AvailableInstanceCount"] == 1
    )


def apply_open_capacity(ports, end):
    from inf061_capacity import open_capacity_guard, verify_open_launch

    def invoke(service, operation, args):
        return ports.aws(service, operation, args, deadline=end)

    manifest = ports.manifest
    session = manifest["session"]
    identity = invoke("sts", "get-caller-identity", [])
    expected = f"arn:aws:sts::{identity['Account']}:assumed-role/{manifest['operator_host']['session']}-cpu/"
    arn = identity["Arn"]
    operator_id = arn.removeprefix(expected)
    spec.check(
        arn.startswith(expected) and re.fullmatch(r"i-[0-9a-f]{17}", operator_id),
        "open_capacity_operator_identity",
    )
    open_capacity_guard(
        invoke, session, ports.capacity_selection, operator_id=operator_id
    )
    ports.apply(end)
    readback_end = min(end + 60, time.time() + 60)
    verify_open_launch(
        lambda service, operation, args: ports.aws(
            service, operation, args, deadline=readback_end
        ),
        session,
        ports.capacity_selection,
        operator_id=operator_id,
        launched_id=ports.host,
        end=readback_end,
    )


def command_context(directory, profile):
    commands = spec.load(directory / "commands.json")
    if profile is None:
        from inf060_operator_packet import commands as linux_commands

        spec.check(commands == linux_commands(), "supervisor_command_binding")
        return commands
    expected = {
        role: [
            sys.executable,
            str(Path(__file__).resolve()),
            mode,
            "--directory",
            str(directory),
            "--profile",
            profile,
        ]
        for role, mode in (
            ("controller", "execute"),
            ("cleanup", "cleanup"),
            ("inventory", "inventory"),
        )
    }
    spec.check(commands == expected, "supervisor_command_binding")
    return commands


def synthetic_review(directory):
    manifest = spec.load(directory / "manifest.json")
    digest = spec.facts(directory / "manifest.json")["sha256"]
    line = (
        benchmark.approval_line(manifest, digest)
        if benchmark.is_benchmark(manifest)
        else (
            f"{spec.PREFIX} manifest={digest} plan={manifest['sealed_plans']['create_sha256']} "
            f"source={manifest['source_commit']}"
        )
    )
    return (
        f"## Claude Round 0 - CPU rehearsal\n- Verdict: NO_BLOCKING_FINDINGS\n{line}\n"
    )


def routine_host(directory, manifest, profile, end):
    directory = directory.resolve()
    spec.check(
        directory.is_relative_to(ROOT / ".cache/routine-tests"), "routine_directory"
    )
    routine = spec.load(directory / "manifest.json")
    lifecycle = spec.load(directory / "lifecycle.json")
    spec.check(
        routine["role"] == "routine_tests"
        and routine["instance_type"] == "m6i.2xlarge"
        and routine["source_commit"] == manifest["source_commit"]
        and routine["routine_selection"].get("inf060_probe_rehearsal")
        and not lifecycle.get("cleanup"),
        "routine_host_binding",
    )
    ports = RoutinePorts(directory, routine, profile=profile, recovering=True)
    ports.deadline = end
    ids = ports.instance_ids()
    spec.check(len(ids) == 1, "routine_host_count")
    rows = ports.aws("ec2", "describe-instances", ["--instance-ids", ids[0]])[
        "Reservations"
    ]
    current = [vm for reservation in rows for vm in reservation["Instances"]]
    spec.check(
        len(current) == 1
        and current[0]["InstanceType"] == "m6i.2xlarge"
        and current[0]["State"]["Name"] == "running",
        "routine_cpu_only",
    )
    return ids[0]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("launch", "execute", "cleanup", "inventory"))
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--profile", default="admin-learning")
    parser.add_argument("--routine-directory", type=Path)
    parser.add_argument("--instance-role", action="store_true")
    parser.add_argument("--mock-host")
    parser.add_argument("--mock-failure", choices=diagnostics.FAILURES)
    args = parser.parse_args()
    directory = args.directory.resolve()
    spec.check(directory.is_relative_to(ROOT / ".cache"), "packet_directory")
    if args.instance_role:
        args.profile = None
        spec.check(
            os.name == "posix" and not args.routine_directory, "operator_role_host"
        )
    spec.check(
        not args.mock_host or args.instance_role, "mock_requires_remote_operator"
    )
    cpu = args.routine_directory is not None or bool(args.mock_host)
    failure = diagnostics.injected_failure(args.mock_host, args.mock_failure)
    if args.mode == "launch" and os.name == "nt" and not cpu:
        from inf060_operator_memory import record_launch_gate

        record_launch_gate(directory / "launch-memory.json", requested="laptop")
    if args.mode in ("launch", "execute"):
        review = (
            synthetic_review(directory)
            if cpu
            else (directory / "committed-review.txt").read_text()
            if args.instance_role
            else git("show", "HEAD:REVIEW.md").decode()
        )
        manifest = checked_packet(directory, review, remote_host=args.instance_role)
        spec.check(
            ("operator_host" in manifest) == args.instance_role, "use_aws_operator"
        )
        commands = command_context(directory, args.profile)
        if args.mode == "launch":
            output = directory / "supervisor"
            if args.mock_host:
                commands = {
                    name: [
                        *argv,
                        "--mock-host",
                        args.mock_host,
                        *(["--mock-failure", failure] if failure else []),
                    ]
                    for name, argv in commands.items()
                }
            elif cpu:
                commands = {
                    name: [
                        *argv,
                        "--routine-directory",
                        str(args.routine_directory.resolve()),
                    ]
                    for name, argv in commands.items()
                }
                output = args.routine_directory / "inf060-supervisor"
            origin_epoch = None
            if "capacity_hunt" in manifest:
                from inf061_capacity import selected_plan

                selection, _ = selected_plan(directory, manifest)
                origin_epoch = selection["selected_epoch"]
            return int(
                not supervise(
                    commands,
                    output,
                    work_seconds=manifest["deadline_seconds"]
                    - manifest["cleanup_seconds"],
                    cleanup_seconds=manifest["cleanup_seconds"],
                    origin_epoch=origin_epoch,
                )["complete"]
            )
        spec.check((directory / "supervisor.lock").is_file(), "supervisor_required")
    else:
        manifest = spec.verify_packet(directory)
        command_context(directory, args.profile)
    origin = float(os.environ["L4_T0_EPOCH"])
    runtime = Path(os.environ["L4_ATTEMPT_DIRECTORY"])
    started = args.mode == "execute"
    ports = ProbePorts(
        directory,
        manifest,
        args.profile,
        runtime,
        cpu=cpu,
        recovering=not started,
        failure=failure,
    )
    if started:
        spec.check(0 <= time.time() - origin < 90, "supervisor_origin")
        with (runtime / "operator.lock").open("xb") as stream:
            stream.write(str(os.getpid()).encode())
        ports.origin = ports.started = origin
        if args.mock_host:
            vm = ports.aws(
                "ec2", "describe-instances", ["--instance-ids", args.mock_host]
            )["Reservations"][0]["Instances"][0]
            tags = {r["Key"]: r["Value"] for r in vm["Tags"]}
            spec.check(
                vm["InstanceType"] == "m6i.2xlarge"
                and vm["State"]["Name"] == "running"
                and tags.get("Inf060Target") == manifest["session"]
                and tags.get("Session", "").startswith("dec077-test-"),
                "routine_cpu_only",
            )
            ports.host = args.mock_host
            spec.save(
                runtime / "provider-substitution.json",
                {"product_apply_performed": False, "cpu_host_reused": True},
            )
        elif cpu:
            ports.host = routine_host(
                args.routine_directory, manifest, args.profile, origin + 600
            )
            spec.save(
                runtime / "provider-substitution.json",
                {"product_apply_performed": False, "cpu_host_reused": True},
            )
        else:
            ports.command(
                ["terraform", "init", "-input=false", "-lockfile=readonly"],
                min(origin + 600, time.time() + 120),
                "init",
            )
            native_preflight(
                ports,
                directory,
                manifest,
                origin,
                capacity_stage="selected" if "capacity_hunt" in manifest else None,
            )
            if ports.capacity_selection is not None:
                apply_open_capacity(ports, origin + 600)
            else:
                ports.apply(origin + 600)  # FIRST POSSIBLE GPU INSTANCE LAUNCH
            groups = ports.aws(
                "ec2",
                "describe-security-groups",
                ["--filters", "Name=tag:Session,Values=" + manifest["session"]],
                deadline=origin + spec.READY_S,
            )["SecurityGroups"]
            spec.check(
                len(groups) == 1 and not groups[0]["IpPermissions"], "live_ingress"
            )
        result = work(ports, origin)
        spec.save(runtime / "probe-retrieval.json", result)
        if cpu:
            # Retain the already frozen and operator-verified bytes with the
            # outer routine receipts. No raw engine logs are in this archive.
            ports.deadline = min(origin + spec.HOST_TIMER_S, time.time() + 45)
            ports.ssm(
                ports.host,
                [
                    "set -eu",
                    "install -d -m 0700 /opt/dec077/results/inf060-probe",
                    "cp /opt/dec077/inf060/receipts.tar.gz /opt/dec077/results/inf060-probe/receipts.tar.gz",
                ],
                timeout_s=30,
                step="inf060.routine_receipt",
            )
    elif args.mode == "cleanup":
        stop = origin + manifest["deadline_seconds"] - 60
        try:
            receipt = (
                ports.teardown(stop - (90 if "capacity_hunt" in manifest else 0))
                if (directory / "consumed.json").is_file()
                else {"destroy_completed": True, "skipped": "not_consumed"}
            )
        finally:
            if "capacity_hunt" in manifest:
                from inf061_capacity import close_reservation

                available = min(stop, time.time() + 80)
                close_reservation(directory, manifest, available)
        spec.save(runtime / "probe-cleanup.json", receipt)
        spec.check(receipt["destroy_completed"], "destroy_unverified")
    else:
        receipt = ports.inventory(origin + manifest["deadline_seconds"])
        spec.save(runtime / "probe-inventory.json", receipt)
        spec.check(receipt["empty"], "inventory_not_empty")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        if sys.argv[1:2] == ["execute"] and (
            attempt := os.environ.get("L4_ATTEMPT_DIRECTORY")
        ):
            diagnostics.write(
                Path(attempt) / "controller-error.json",
                diagnostics.exception_record(error),
            )
        raise
