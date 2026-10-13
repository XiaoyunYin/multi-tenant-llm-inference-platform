import copy
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from inference_platform.r1_lifecycle import ROLES, Production

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("r1_review_plan", ROOT / "scripts/r1_review_plan.py")
REVIEW_PLAN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REVIEW_PLAN)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write_bundle(repo, source_head, python_source):
    files = {
        "python/src/inference_platform/example.py": python_source,
        "bin/gateway": b"fixture gateway",
    }
    payload = json.dumps(
        {
            "source_head": source_head,
            "files": {name: sha(data) for name, data in files.items()},
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    path = repo / "bundle.tar.gz"
    with tarfile.open(path, "w:gz") as archive:
        for name, data in {**files, "payload.json": payload}.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    return path, files


def summary_fixture():
    user_data = "#!/bin/sh\necho fixture\n"
    user_data_hash = sha(user_data.encode("utf-8"))
    inputs = {
        "roles": list(ROLES),
        "gpu_type": "g6.xlarge",
        "cpu_type": "c6i.2xlarge",
        "gpu_ami": "ami-gpu-fixture",
        "cpu_ami": "ami-cpu-fixture",
        "availability_zone": "us-east-1b",
        "source_head": "a" * 40,
        "source_sha256": {"infra/terraform/r1/user-data.sh": user_data_hash},
        "bundle_sha256": "b" * 64,
        "m4_estimate_usd": "86.54",
        "session_estimate_usd": "34.70",
    }
    changes = []
    for role in ROLES:
        gpu = role.startswith("gpu")
        after = {
            "instance_type": inputs["gpu_type" if gpu else "cpu_type"],
            "ami": inputs["gpu_ami" if gpu else "cpu_ami"],
            "root_block_device": [{"volume_size": 200 if gpu else 40}],
            "metadata_options": [{"http_tokens": "required"}],
            "instance_initiated_shutdown_behavior": "terminate",
            "tags": {"Role": role, "Session": "fixture"},
            "user_data": user_data,
        }
        if gpu:
            after["capacity_reservation_specification"] = [
                {"capacity_reservation_preference": "capacity-reservations-only"}
            ]
            after["tenancy"] = "default"
        changes.append(
            {
                "type": "aws_instance",
                "change": {
                    "actions": ["create"],
                    "after": after,
                    "after_unknown": (
                        {
                            "capacity_reservation_specification": [
                                {"capacity_reservation_target": []}
                            ]
                        }
                        if gpu
                        else {
                            "capacity_reservation_specification": True,
                            "tenancy": True,
                        }
                    ),
                },
            }
        )
    changes.append(
        {
            "type": "aws_subnet",
            "change": {
                "actions": ["create"],
                "after": {"availability_zone": "us-east-1b"},
            },
        }
    )
    changes.extend(
        {
            "type": resource_type,
            "change": {"actions": ["create"], "after": {}},
        }
        for resource_type in (
            "aws_iam_instance_profile",
            "aws_iam_role",
            "aws_iam_role_policy_attachment",
            "aws_internet_gateway",
            "aws_route_table",
            "aws_route_table_association",
            "aws_security_group",
            "aws_vpc",
        )
    )
    document = {
        "variables": {},
        "resource_changes": changes,
        "configuration": {
            "root_module": {
                "resources": [{"address": "aws_instance.cpu", "depends_on": ["aws_instance.gpu"]}]
            }
        },
    }
    return document, inputs, user_data_hash


def build_summary(document, inputs, user_data_hash):
    return REVIEW_PLAN.build_plan_summary(
        document,
        inputs,
        prepared_at="2026-10-07T00:00:00Z",
        preparation_commit="c" * 40,
        plan_sha256="d" * 64,
        saved_plan_path=".cache/fixture/r1.tfplan",
        plan_bytes=1234,
        user_data_source_sha256=user_data_hash,
        embedded_committed_config_sha256={},
        terraform_sha256="e" * 64,
        production_structural_preflight="NOT RUN (fixture)",
        raw={},
    )


class R1ReviewPlanTests(unittest.TestCase):
    def test_mismatched_bundled_python_source_refuses_before_terraform_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            bundle_path = repo / "bundle.tar.gz"
            python_source = b"bundled source\n"
            payload = json.dumps(
                {
                    "source_head": "a" * 40,
                    "files": {
                        "python/src/inference_platform/example.py": sha(python_source),
                        "bin/gateway": sha(b"gateway"),
                    },
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
            with tarfile.open(bundle_path, "w:gz") as archive:
                for name, data in {
                    "python/src/inference_platform/example.py": python_source,
                    "bin/gateway": b"gateway",
                    "payload.json": payload,
                }.items():
                    member = tarfile.TarInfo(name)
                    member.size = len(data)
                    archive.addfile(member, io.BytesIO(data))
            selected = repo / "zone.json"
            selected.write_text(
                json.dumps(
                    {
                        "commands": {"review": ["review", "--inputs", "zone.json"]},
                        "bundle_path": bundle_path.name,
                        "bundle_sha256": sha(bundle_path.read_bytes()),
                        "source_head": "a" * 40,
                        "source_sha256": {
                            "python/src/inference_platform/example.py": sha(b"current source\n")
                        },
                    }
                ),
                encoding="utf-8",
            )
            previous = Path.cwd()
            try:
                os.chdir(repo)
                with (
                    patch.object(
                        sys,
                        "argv",
                        ["review", "--inputs", "zone.json", "--evidence", "e", "--refresh", "r"],
                    ),
                    patch.object(REVIEW_PLAN.subprocess, "run") as run,
                    patch.object(REVIEW_PLAN.subprocess, "check_output") as check_output,
                ):
                    with self.assertRaisesRegex(ValueError, "differs from source_sha256"):
                        REVIEW_PLAN.main()
                run.assert_not_called()
                check_output.assert_not_called()
            finally:
                os.chdir(previous)

    def test_inputs_option_reads_and_writes_only_selected_file(self):
        for option in ("default", "relative", "absolute"):
            with self.subTest(option=option), tempfile.TemporaryDirectory() as tmp:
                repo = Path(tmp)
                default = repo / "docs/R1_SESSION_INPUTS.json"
                default.parent.mkdir()
                selected = default if option == "default" else repo / "docs/zone-1d.json"
                default.write_bytes(b"untouched default input")
                sources = {
                    "infra/terraform/r1/" + name: b"fixture source"
                    for name in ("main.tf", "variables.tf", "versions.tf", "user-data.sh")
                }
                python_source = b"fixture bundled Python\n"
                sources["python/src/inference_platform/example.py"] = python_source
                for path, data in sources.items():
                    target = repo / path
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(data)
                folder = repo / "plans"
                folder.mkdir()
                (folder / "variables.tfvars.json").write_bytes(b"{}")
                saved = folder / "review.tfplan"
                inputs = {
                    "source_sha256": {path: sha(data) for path, data in sources.items()},
                    "commands": {
                        "ready": ["op", "--inputs", selected.relative_to(repo).as_posix()]
                    },
                    "terraform": "terraform-fixture",
                    "saved_plan_path": "plans/review.tfplan",
                    "source_head": "c" * 40,
                    "account_id_sha256": "account",
                    "m4_cap_usd": "86.54",
                    "m4_estimate_usd": "86.54",
                    "session_cap_usd": "34.70",
                    "session_estimate_usd": "34.70",
                    "plan_sha256": "b" * 64,
                }
                selected.write_bytes(json.dumps(inputs).encode())
                (repo / inputs["terraform"]).write_bytes(b"fixture Terraform executable")
                bundle_path, _ = write_bundle(repo, inputs["source_head"], python_source)
                inputs["bundle_path"] = bundle_path.name
                inputs["bundle_sha256"] = sha(bundle_path.read_bytes())
                inputs["source_sha256"]["python/src/inference_platform/example.py"] = sha(
                    python_source
                )
                selected.write_bytes(json.dumps(inputs).encode())
                refresh = repo / "refresh"
                refresh.mkdir()
                (refresh / "summary.json").write_bytes(json.dumps(inputs).encode())
                (refresh / "identity.raw.json").write_bytes(b"{}")
                evidence = repo / "evidence"
                evidence.mkdir()

                def run(argv, saved=saved, sources=sources, **kwargs):
                    with zipfile.ZipFile(saved, "w") as archive:
                        for path, data in sources.items():
                            archive.writestr("tfconfig/m-/" + Path(path).name, data)
                    return subprocess.CompletedProcess(argv, 0)

                def check_output(argv, sources=sources, **kwargs):
                    if argv[0] == "git":
                        if argv[1] == "rev-parse":
                            return "c" * 40 + "\n"
                        return sources[argv[-1].removeprefix("HEAD:")]
                    return b"{}"

                def preflight(plan, _inputs, folder=folder):
                    (folder / "structural-preflight/consumed.tfplan").write_bytes(plan)

                argv = ["review", "--evidence", str(evidence), "--refresh", str(refresh)]
                if option != "default":
                    argv += [
                        "--inputs",
                        str(selected) if option == "absolute" else "docs/zone-1d.json",
                    ]
                previous = Path.cwd()
                try:
                    os.chdir(repo)
                    with (
                        patch.object(sys, "argv", argv),
                        patch.object(REVIEW_PLAN.subprocess, "run", side_effect=run),
                        patch.object(
                            REVIEW_PLAN.subprocess, "check_output", side_effect=check_output
                        ),
                        patch.object(REVIEW_PLAN, "validate_resource_changes"),
                        patch.object(REVIEW_PLAN, "build_plan_summary", return_value={}),
                        patch.object(REVIEW_PLAN, "Production") as production,
                    ):
                        production.return_value.preflight.side_effect = preflight
                        REVIEW_PLAN.main()
                finally:
                    os.chdir(previous)
                updated = json.loads(selected.read_bytes())
                self.assertEqual(updated["plan_sha256"], sha(saved.read_bytes()))
                if option != "default":
                    self.assertEqual(default.read_bytes(), b"untouched default input")

    def test_helper_refuses_wrong_self_reference_before_refresh_or_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            selected = repo / "zone.json"
            selected.write_bytes(
                json.dumps(
                    {"commands": {"ready": ["op", "--inputs", "docs/R1_SESSION_INPUTS.json"]}}
                ).encode()
            )
            argv = [
                "review",
                "--inputs",
                str(selected),
                "--evidence",
                "absent",
                "--refresh",
                "absent",
            ]
            previous = Path.cwd()
            try:
                os.chdir(repo)
                with (
                    patch.object(sys, "argv", argv),
                    patch.object(REVIEW_PLAN.subprocess, "run") as run,
                    patch.object(REVIEW_PLAN.subprocess, "check_output") as check,
                ):
                    with self.assertRaisesRegex(ValueError, "own --inputs file"):
                        REVIEW_PLAN.main()
                run.assert_not_called()
                check.assert_not_called()
            finally:
                os.chdir(previous)

    def test_outputs_only_plan_is_refused_with_explicit_reason(self):
        with self.assertRaisesRegex(ValueError, "no resource_changes array.*output-only plan"):
            REVIEW_PLAN.validate_resource_changes(
                {"planned_values": {"outputs": {"hosts": {"value": {}}}}}
            )

    def test_real_instance_shape_builds_summary_and_checks_gpu_reservation(self):
        document, inputs, user_data_hash = summary_fixture()
        summary = build_summary(document, inputs, user_data_hash)

        self.assertEqual(set(summary["hosts"]), set(ROLES))
        self.assertEqual(summary["m4_cap_usd"], "86.54")
        self.assertEqual(summary["session_ceiling_usd"], "34.70")
        self.assertEqual(summary["cpu_depends_on"], ["aws_instance.gpu"])
        for role in ("gpu-0", "gpu-1"):
            self.assertEqual(
                summary["hosts"][role]["capacity_reservation_specification"][0][
                    "capacity_reservation_preference"
                ],
                "capacity-reservations-only",
            )
            self.assertEqual(summary["hosts"][role]["tenancy"], "default")
        for role in ("service", "generator"):
            self.assertEqual(
                summary["hosts"][role]["capacity_reservation_specification"],
                "not set (On-Demand default)",
            )
            self.assertEqual(summary["hosts"][role]["tenancy"], "not set (On-Demand default)")

        changed = copy.deepcopy(document)
        gpu = next(
            change["change"]["after"]
            for change in changed["resource_changes"]
            if change.get("type") == "aws_instance"
            and change["change"]["after"]["tags"]["Role"] == "gpu-0"
        )
        gpu["capacity_reservation_specification"][0]["capacity_reservation_preference"] = "open"
        with self.assertRaisesRegex(ValueError, "gpu-0.*capacity-reservations-only"):
            build_summary(changed, inputs, user_data_hash)

    def test_offline_aws_supports_production_teardown_inventory(self):
        identity = {
            "Account": "000000000000",
            "Arn": "arn:aws:iam::000000000000:user/test",
            "UserId": "test",
        }
        inputs = {
            "terraform": ".tools/terraform/1.16.2/terraform.exe",
            "region": "us-east-1",
            "aws_profile": "fake",
            "session_id": "test-session",
        }
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            terraform = repo / inputs["terraform"]
            terraform.parent.mkdir(parents=True, exist_ok=True)
            terraform.write_bytes(b"placeholder Terraform executable")
            output = repo / "output"
            output.mkdir()
            adapter = Production(repo, inputs, output)
            calls = []

            def aws(service, operation, *args):
                calls.append((service, operation))
                return REVIEW_PLAN.offline_aws(identity, service, operation, *args)

            empty_state = json.dumps({"values": {"root_module": {"resources": []}}}).encode("utf-8")
            with (
                patch.object(adapter, "aws", side_effect=aws),
                patch.object(adapter, "tf", return_value=empty_state),
            ):
                self.assertEqual(adapter.verify_teardown(adapter.now() + 60), [])

        self.assertIn(("ec2", "describe-capacity-reservations"), calls)

    def test_offline_aws_rejects_unexpected_operation_by_name(self):
        with self.assertRaisesRegex(ValueError, "unexpected offline AWS operation: s3 put-object"):
            REVIEW_PLAN.offline_aws({}, "s3", "put-object")


if __name__ == "__main__":
    unittest.main()
