"""Exercise the native supervisor, selected saved plan and CPU receipt path.

The fixture uses real Terraform with local state and terraform_data instead
of provider-created compute. It never accepts an external target or a real
packet. The routine CPU engine and loopback transport match the native
workload fixture.
"""

import argparse
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import inf060_probe_operator as probe
import inf060_probe_spec as spec
import inf060_remote_service as remote
import inf061_capacity as capacity
from rehearse_inf061_native import run as run_benchmark
from test_inf061_capacity import EC2, FakeClock

SESSION = "dec077-inf060-r459-test"
CLOUD = "fake-capacity.json"
OPERATOR_SESSION = "dec077-op-inf061-fixture"
OPERATOR_ID = "i-" + "1" * 17


def terraform(root, *args):
    return subprocess.run(
        ["terraform", "-chdir=" + str(root), *args],
        check=True,
        capture_output=True,
        timeout=120,
    ).stdout


def prepare(directory):
    manifest = {
        "session": SESSION,
        "source_commit": "1" * 40,
        "schema": "inf061-native-dec108-v1",
        "operator_host": {"session": OPERATOR_SESSION},
        "session_manager_plugin_path": "fake-ssm",
        "operator_tools": {"terraform": {"path": shutil.which("terraform")}},
        "deadline_seconds": capacity.GPU_SECONDS,
        "cleanup_seconds": 600,
        "ready_by_seconds": 3600,
        "work_seconds": capacity.GPU_SECONDS - 600,
        "export_seconds": 300,
        "zone": capacity.PRIMARY_ZONE,
        "artifacts": {
            name: {} for name in ("tools.json", "engine.json", spec.LOG_CONFIG)
        },
        "capacity_hunt": {
            "plans": {},
        },
    }
    for zone, relative in capacity.ROOTS.items():
        root = directory / relative
        root.mkdir(parents=True)
        (root / "main.tf").write_text(
            f'resource "terraform_data" "instance" {{ input = "{zone}" }}\n'
        )
        (root / "input.tfvars.json").write_text("{}\n")
        terraform(root, "init", "-input=false")
        terraform(root, "plan", "-input=false", "-refresh=false", "-out=create.tfplan")
        manifest["capacity_hunt"]["plans"][zone] = {
            "create_sha256": spec.facts(root / "create.tfplan")["sha256"],
        }
    spec.save(directory / "manifest.json", manifest)
    spec.save(directory / CLOUD, {})
    (directory / "committed-review.txt").write_text("local fixture only\n")
    return manifest


def reservation_transport(directory):
    state = directory / CLOUD
    provider = EC2(SimpleNamespace(now=time.monotonic), SESSION)
    provider.rows = spec.load(state)

    def invoke(*args, **kwargs):
        if args[:2] == ("ec2", "describe-launch-templates"):
            return {"LaunchTemplates": []}
        value = provider.aws(*args, **kwargs)
        spec.save(state, provider.rows)
        return value

    return invoke


class LocalPorts(probe.ProbePorts):
    """Closed cloud fixture with real inherited Apply, destroy and inventory."""

    def __init__(self, directory, *args, **kwargs):
        super().__init__(directory, *args, **kwargs)
        self.fake_aws = reservation_transport(directory)

    def instance_ids(self):
        root = self.terraform_directory
        state = root / "terraform.tfstate"
        running = (
            state.exists()
            and spec.load(state)["resources"]
            and not (root / "terminated").exists()
        )
        return ["fixture-cpu"] if running else []

    def aws(self, service, operation, args, *, deadline=None):
        if operation == "get-caller-identity":
            account = "123456789012"
            return {
                "Account": account,
                "Arn": f"arn:aws:sts::{account}:assumed-role/{OPERATOR_SESSION}-cpu/{OPERATOR_ID}",
            }
        if operation == "describe-capacity-reservations":
            response = self.fake_aws(
                service, operation, args, time.monotonic() + 30, operation
            )
            if self.instance_ids():
                for row in response["CapacityReservations"]:
                    if (
                        row["CapacityReservationId"]
                        == self.capacity_selection["reservation_id"]
                    ):
                        row["AvailableInstanceCount"] = 0
            return response
        if operation == "describe-instances":
            rows = [{"InstanceId": OPERATOR_ID}]
            if self.instance_ids():
                rows.append(
                    {
                        "InstanceId": "fixture-cpu",
                        "CapacityReservationId": self.capacity_selection[
                            "reservation_id"
                        ],
                        "Placement": {
                            "AvailabilityZone": self.capacity_selection["zone"]
                        },
                        "Tags": [{"Key": "Session", "Value": SESSION}],
                    }
                )
            return {"Reservations": [{"Instances": rows}]}
        if operation == "terminate-instances":
            (self.terraform_directory / "terminated").write_text("yes\n")
            return {}
        fields = {
            "describe-launch-templates": "LaunchTemplates",
            "describe-volumes": "Volumes",
            "describe-network-interfaces": "NetworkInterfaces",
            "describe-vpcs": "Vpcs",
            "describe-subnets": "Subnets",
            "describe-security-groups": "SecurityGroups",
            "describe-route-tables": "RouteTables",
            "describe-internet-gateways": "InternetGateways",
            "describe-addresses": "Addresses",
            "list-roles": "Roles",
            "list-instance-profiles": "InstanceProfiles",
        }
        rows = (
            [{"IpPermissions": []}]
            if operation == "describe-security-groups" and self.instance_ids()
            else []
        )
        return {fields[operation]: rows}

    def command(self, argv, deadline, name, **kwargs):
        if argv[0] == "aws":
            spec.check(
                name == "wait-terminated" and not self.instance_ids(),
                "fixture_termination",
            )
            return {}
        args = [
            arg for arg in argv[1:] if not arg.startswith("-var=provider_attempts=")
        ]
        output = terraform(self.terraform_directory, *args)
        (self.diagnostic_dir / (name + ".log")).write_bytes(output)
        return output

    def bootstrap(self, end):
        self.host = self.instance_ids()[0]
        state = spec.load(self.terraform_directory / "terraform.tfstate")
        zone = state["resources"][0]["instances"][0]["attributes"]["input"]["value"]
        spec.check(
            zone == self.capacity_selection["zone"], "fixture_applied_saved_zone"
        )

    def upload(self, end):
        spec.check(self.host == "fixture-cpu", "fixture_bootstrap_custody")

    def run_checks(self, end):
        run_benchmark(self.diagnostic_dir / "benchmark-rehearsal")

    def retrieve(self, end):
        work = self.diagnostic_dir / "benchmark-rehearsal"
        receipt = spec.load(work / "receipt.json")["retrieval"]
        source = work / "receipts.tar.gz"
        spec.check(
            receipt["complete"] and spec.facts(source)["sha256"] == receipt["sha256"],
            "fixture_retrieval",
        )
        shutil.copyfile(source, self.runtime / "receipts.tar.gz")
        return receipt


def command_entry(directory, mode):
    manifest = spec.load(directory / "manifest.json")
    spec.check(
        manifest["session"] == SESSION and directory.name == "local-hunter-fixture",
        "local_fixture_required",
    )
    real_reservations = capacity.ReservationPorts
    commands = {
        role: [
            sys.executable,
            __file__,
            "--stage",
            phase,
            "--directory",
            str(directory),
        ]
        for role, phase in (
            ("controller", "execute"),
            ("cleanup", "cleanup"),
            ("inventory", "inventory"),
        )
    }

    def reservations(folder, session):
        value = real_reservations(folder, session)
        value.aws = reservation_transport(directory)
        return value

    def preflight(ports, _, manifest, origin, *, capacity_stage):
        spec.check(
            capacity_stage == "selected"
            and probe.selected_inventory(ports, manifest, origin + 600),
            "fixture_selected_inventory",
        )

    with (
        patch.object(probe, "ROOT", directory.parent.parent),
        patch.object(probe, "ProbePorts", LocalPorts),
        patch.object(probe, "checked_packet", return_value=manifest),
        patch.object(probe, "command_context", return_value=commands),
        patch.object(probe, "native_preflight", side_effect=preflight),
        patch.object(capacity, "ReservationPorts", side_effect=reservations),
        patch.object(spec, "verify_packet", return_value=manifest),
        patch.object(
            sys,
            "argv",
            [__file__, mode, "--directory", str(directory), "--instance-role"],
        ),
    ):
        return probe.main()


def run(work):
    directory = (work / ".cache/local-hunter-fixture").resolve()
    manifest = prepare(directory)
    clock = FakeClock()
    hunter = capacity.Hunter(directory, manifest, clock=clock.now, epoch=time.time)
    provider = EC2(clock, SESSION, leak=True)
    hunter.capacity.now = clock.now
    selected = []

    def select():
        row = hunter.select(sleep=clock.sleep)
        selected.append(row)
        spec.save(directory / CLOUD, provider.rows)
        return row

    def launch(argv, *, check):
        spec.check(argv[2] == "launch", "fixture_remote_entrypoint")
        return SimpleNamespace(returncode=command_entry(directory, "launch"))

    with (
        provider.attach(hunter.capacity),
        patch.object(remote.remote, "PACKET", str(directory)),
        patch.object(remote.remote, "verify"),
        patch.object(remote.remote, "import_runtime", return_value={}),
        patch.object(spec, "verify_packet", return_value=manifest),
        patch.object(remote, "verify_environment"),
        patch.object(remote, "subprocess", SimpleNamespace(run=launch)),
        patch.object(probe, "ProbePorts", LocalPorts),
        patch.object(probe, "native_preflight"),
        patch.object(capacity, "Hunter", return_value=SimpleNamespace(select=select)),
    ):
        code = remote.run()
    witness = spec.load(directory / "remote-result.json")
    if code:
        for log in sorted((directory / "supervisor").glob("attempt-*/*.log")):
            for line in log.read_text(errors="replace").splitlines()[-30:]:
                frame = re.search(r'File "[^"]+/([^/"]+)", line (\d+), in (\w+)', line)
                error = re.fullmatch(
                    r"(\w+(?:Error|Exception)): ([A-Za-z0-9_: .-]{1,140})", line
                )
                if frame or error:
                    print(log.name, (frame or error).groups())
    spec.check(
        code == 0
        and witness["supervisor_complete"]
        and witness["inventory"]["empty"]
        and witness["benchmark"]["status"] == "available"
        and witness["capacity"]["probes"] == 11
        and witness["origin_epoch"] == selected[0]["selected_epoch"],
        "fixture_hunter_e2e",
    )
    root = directory / capacity.ROOTS[selected[0]["zone"]]
    apply_hash = spec.load(directory / "consumed.json")["plan_sha256"]
    spec.check(
        apply_hash == spec.facts(root / "create.tfplan")["sha256"],
        "fixture_saved_plan_binding",
    )
    archive = work / "inf061-hunter-receipts.tar.gz"
    shutil.copyfile(directory / "inf061-receipts.tar.gz", archive)
    spec.check(
        spec.facts(archive)["sha256"] == witness["benchmark"]["sha256"],
        "fixture_hunter_archive_hash",
    )
    spec.save(
        work / "receipt.json",
        {
            "controllers": ["inf060_remote_service.run", "inf060_probe_operator.main"],
            "probes": len(provider.probes),
            "selected_zone": selected[0]["zone"],
            "saved_plan_sha256": apply_hash,
            "archive": spec.facts(archive),
            "stages": witness["supervisor_stages"],
            "inventory": witness["inventory"],
            "cloud_fakes": [
                "EC2/IAM and SSM",
                "Terraform cloud objects represented by local terraform_data",
                "fixture approval and live quote inputs",
            ],
            "gpu_fakes": ["CPU SSE engine", "fixture DCGM", "shortened workload"],
        },
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--work", type=Path)
    modes.add_argument("--stage", choices=("execute", "cleanup", "inventory"))
    parser.add_argument("--directory", type=Path)
    args = parser.parse_args()
    if args.stage:
        raise SystemExit(command_entry(args.directory, args.stage))
    run(args.work)
