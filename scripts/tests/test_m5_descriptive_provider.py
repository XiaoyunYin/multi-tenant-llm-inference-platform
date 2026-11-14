import base64
import copy
import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

from botocore.exceptions import ClientError
from build_m5_descriptive_packet import (
    E10_SHA256,
    e10_startup_evidence,
    hourly,
    source_bundle,
    startup_bound,
    validate_lambda_limits,
)

from inference_platform.m5_descriptive_cluster import ClusterPorts
from inference_platform.m5_descriptive_operator import phase_deadline, session_timing
from inference_platform.package_a_cloud import gate_a_role_reexec_target
from m5_descriptive_cleanup import clean, deadline, owned_session
from m5_descriptive_eks import (
    Capacity,
    EKSports,
    arm,
    arming_witness,
    require_review,
    validate_cleanup_policy,
    validate_cleanup_resource_tags,
    verify_packet_files,
    verify_plan,
)
from m5_descriptive_model import stage
from m5_descriptive_inventory import gpu_states, inventory
from m5_descriptive_remote import EKSClusterPorts
from m5_eks_token import token
from rehearse_m5_descriptive import (
    REGISTRY_HOSTS,
    KindPorts,
    kind_config,
    registry_configured,
)
from test_m5_infra_safety import plan_fixture


class ProviderTests(unittest.TestCase):
    def test_source_bundle_relative_destination_is_absolute_for_real_git_clone(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, packet = root / "repo", root / "packet"
            repo.mkdir()
            packet.mkdir()
            subprocess.run(
                ["git", "init", "-b", "main", str(repo)],
                check=True,
                capture_output=True,
            )
            (repo / "source.txt").write_bytes(b"exact source\n")
            subprocess.run(
                ["git", "-C", str(repo), "add", "."], check=True, capture_output=True
            )
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(repo),
                    "-c",
                    "user.name=Fixture",
                    "-c",
                    "user.email=fixture@users.noreply.github.com",
                    "commit",
                    "-m",
                    "fixture",
                ],
                check=True,
                capture_output=True,
            )
            commit = (
                subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"])
                .decode()
                .strip()
            )
            relative = Path(os.path.relpath(packet / "source.bundle", Path.cwd()))
            with (
                patch("build_m5_descriptive_packet.ROOT", repo),
                patch("build_m5_descriptive_packet.SCRATCH", root / "scratch"),
            ):
                bundle = source_bundle(relative, commit)
            self.assertEqual(bundle, (packet / "source.bundle").resolve())
            argv = json.loads(bundle.with_suffix(".command.json").read_bytes())["argv"]
            self.assertTrue(Path(argv[-2]).is_absolute())
            restored = root / "restored"
            subprocess.run(
                ["git", "clone", str(bundle), str(restored)],
                check=True,
                capture_output=True,
            )
            self.assertEqual((restored / "source.txt").read_bytes(), b"exact source\n")
            self.assertEqual(
                subprocess.check_output(
                    ["git", "-C", str(restored), "rev-parse", "HEAD"]
                )
                .decode()
                .strip(),
                commit,
            )

    @staticmethod
    def cleanup_policy():
        session = "m5-fixture"

        def grant(actions, key, value):
            return {
                "Effect": "Allow",
                "Action": actions,
                "Resource": "*",
                "Condition": {
                    "StringEquals": {"aws:RequestedRegion": "us-east-1", key: value}
                },
            }

        return {
            "Statement": [
                grant(
                    [
                        "ec2:TerminateInstances",
                        "ec2:DeleteLaunchTemplate",
                        "ec2:ReleaseAddress",
                        "ec2:DisassociateRouteTable",
                        "ec2:DeleteRouteTable",
                        "ec2:DeleteSubnet",
                        "ec2:DetachInternetGateway",
                        "ec2:DeleteInternetGateway",
                        "ec2:DeleteVpc",
                    ],
                    "aws:ResourceTag/Session",
                    [session, "dec077-" + session],
                ),
                grant(
                    ["ec2:CancelCapacityReservation"],
                    "aws:ResourceTag/Session",
                    session,
                ),
                grant(
                    ["ec2:TerminateInstances"],
                    "aws:ResourceTag/eks:cluster-name",
                    session,
                ),
                grant(
                    ["ec2:TerminateInstances"],
                    "aws:ResourceTag/aws:eks:cluster-name",
                    session,
                ),
            ]
        }

    def test_cleanup_policy_matches_real_create_plan_tags_and_refuses_foreign_resources(
        self,
    ):
        root = Path(__file__).resolve().parent
        plan = json.loads(
            (root / "fixtures/m5-descriptive-r530-create-tags.json").read_bytes()
        )
        policy = self.cleanup_policy()
        validate_cleanup_resource_tags(plan, "m5-fixture", policy)
        validate_cleanup_policy(policy, "m5-fixture")
        # Each taggable resource in the real saved create shape must satisfy
        # the session predicate, not merely a handler-side selection filter.
        for row in plan["resource_changes"]:
            changed = copy.deepcopy(plan)
            next(
                r for r in changed["resource_changes"] if r["address"] == row["address"]
            )["change"]["after"]["tags_all"]["Session"] = "foreign"
            with (
                self.subTest(address=row["address"]),
                self.assertRaisesRegex(ValueError, "cleanup_resource_session_tag"),
            ):
                validate_cleanup_resource_tags(changed, "m5-fixture", policy)
        for index in range(len(policy["Statement"])):
            bad = copy.deepcopy(policy)
            bad["Statement"][index]["Condition"]["StringEquals"] = {
                "aws:RequestedRegion": "us-east-1"
            }
            with (
                self.subTest(statement=index),
                self.assertRaisesRegex(ValueError, "cleanup_policy_scope"),
            ):
                validate_cleanup_policy(bad, "m5-fixture")
        bad = copy.deepcopy(policy)
        bad["Statement"].append(
            {"Effect": "Allow", "Action": ["ec2:TerminateInstances"], "Resource": "*"}
        )
        with self.assertRaisesRegex(ValueError, "cleanup_policy_scope"):
            validate_cleanup_policy(bad, "m5-fixture")
        bad = copy.deepcopy(policy)
        bad["Statement"][0]["Condition"]["StringEquals"]["aws:ResourceTag/Session"] = [
            "m5-fixture"
        ]
        with self.assertRaisesRegex(ValueError, "cleanup_resource_policy_mismatch"):
            validate_cleanup_resource_tags(plan, "m5-fixture", bad)

    def test_cleanup_unreserved_pool_requires_two_and_recorded_function_count(self):
        validate_lambda_limits({"UnreservedConcurrentExecutions": 2}, 0)
        validate_lambda_limits({"UnreservedConcurrentExecutions": 10}, 3)
        for value in (
            {},
            {"UnreservedConcurrentExecutions": True},
            {"UnreservedConcurrentExecutions": 1},
        ):
            with (
                self.subTest(value=value),
                self.assertRaisesRegex(ValueError, "lambda_cleanup_concurrency"),
            ):
                validate_lambda_limits(value, 0)
        for count in (None, True, -1):
            with (
                self.subTest(count=count),
                self.assertRaisesRegex(ValueError, "lambda_cleanup_concurrency_input"),
            ):
                validate_lambda_limits({"UnreservedConcurrentExecutions": 10}, count)

    def test_produced_host_manifest_covers_the_reused_ports_hard_reads(self):
        import ast

        root = Path(__file__).resolve().parents[2]
        producer = ast.parse(
            (root / "scripts/build_m5_descriptive_packet.py").read_text()
        )
        host = next(
            node.value
            for node in ast.walk(producer)
            if isinstance(node, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "host" for t in node.targets)
        )
        keys = {node.value for node in host.keys if isinstance(node, ast.Constant)}
        consumer = ast.parse(
            (root / "python/src/inference_platform/package_a_operator.py").read_text()
        )
        ports = next(
            node
            for node in consumer.body
            if isinstance(node, ast.ClassDef) and node.name == "Ports"
        )
        called = {
            "bootstrap",
            "upload",
            "run_checks",
            "retrieve",
            "request",
            "task_cost",
            "instance_ids",
        }
        reads = set()
        for method in ports.body:
            if isinstance(method, ast.FunctionDef) and method.name in called:
                for node in ast.walk(method):
                    if (
                        isinstance(node, ast.Subscript)
                        and isinstance(node.value, ast.Attribute)
                        and isinstance(node.value.value, ast.Name)
                        and node.value.value.id == "self"
                        and node.value.attr == "manifest"
                        and isinstance(node.slice, ast.Constant)
                        and isinstance(node.slice.value, str)
                    ):
                        reads.add(node.slice.value)
        # instance_ids intentionally retains Package A's legacy .get fallback;
        # this new workload must bind its own tag selector rather than use it.
        self.assertIn("session", keys)
        self.assertIn("region", keys)
        session = next(
            value
            for key, value in zip(host.keys, host.values)
            if isinstance(key, ast.Constant) and key.value == "session"
        )
        self.assertIsInstance(session, ast.BinOp)
        self.assertEqual(ast.literal_eval(session.left), "dec077-")
        self.assertEqual(session.right.id, "session")
        self.assertFalse(reads - keys, f"missing role inputs: {sorted(reads - keys)}")

    def test_backstop_still_terminates_owned_instances_when_eks_readback_fails(self):
        clients = {
            name: Mock()
            for name in (
                "eks",
                "ec2",
                "autoscaling",
                "ecr",
                "iam",
                "resource-groups",
                "logs",
                "s3",
            )
        }
        sdk = Mock()
        sdk.client.side_effect = clients.__getitem__

        def read(_client, operation, _key, **kwargs):
            if operation in {"list_nodegroups", "list_clusters"}:
                raise ClientError(
                    {"Error": {"Code": "AccessDeniedException"}}, operation
                )
            filters = kwargs.get("Filters", [])
            if (
                operation == "describe_instances"
                and filters
                and filters[0]["Name"] == "tag:eks:cluster-name"
            ):
                return [
                    {
                        "Instances": [
                            {"InstanceId": "i-owned", "State": {"Name": "running"}}
                        ]
                    }
                ]
            return []

        with patch("m5_descriptive_cleanup.pages", side_effect=read):
            result = clean(sdk, "m5-fixture", "m5-fixture-state")
        clients["ec2"].terminate_instances.assert_called_once_with(
            InstanceIds=["i-owned"]
        )
        self.assertTrue(
            any(row["step"] == "read:list_nodegroups" for row in result["errors"])
        )
        clients["s3"].delete_bucket.assert_not_called()

    def test_targeting_waits_for_readback_without_repeating_the_modification(self):
        import time
        import datetime

        ports = EKSports.__new__(EKSports)
        ports.end, ports.deadline = time.time() + 18000, time.monotonic() + 60
        ports.aws = Mock()
        ports.capacity = Mock()
        desired_end = datetime.datetime.fromtimestamp(
            int(ports.end), datetime.UTC
        ).isoformat()
        row = {
            "State": "active",
            "TotalInstanceCount": 2,
            "AvailableInstanceCount": 2,
            "InstanceMatchCriteria": "open",
            "EndDate": datetime.datetime.fromtimestamp(
                int(ports.end) - 17400, datetime.UTC
            ).isoformat(),
        }
        ports.capacity.describe_capacity_reservations.side_effect = [
            [row],
            [{**row, "InstanceMatchCriteria": "targeted"}],
            [{**row, "InstanceMatchCriteria": "targeted", "EndDate": desired_end}],
        ]
        with patch("m5_descriptive_eks.time.sleep"):
            self.assertEqual(
                ports.make_targeted("cr-fixture")["InstanceMatchCriteria"], "targeted"
            )
        self.assertEqual(ports.aws.call_count, 1)
        ports.aws.reset_mock()
        ports.deadline = time.monotonic() - 1
        with self.assertRaisesRegex(TimeoutError, "targeted_reservation_deadline"):
            ports.make_targeted("cr-fixture")
        ports.aws.assert_not_called()

    def test_expired_provisioning_deadline_never_launches_a_subprocess(self):
        import time

        ports = EKSports.__new__(EKSports)
        ports.end = time.time() - 1
        with patch("m5_descriptive_eks.subprocess.run") as run:
            with self.assertRaisesRegex(TimeoutError, "terraform_original_deadline"):
                ports.tf(Path("fixture"), "apply", "create.tfplan")
        run.assert_not_called()
        with patch("m5_descriptive_eks.subprocess.check_output") as run:
            with self.assertRaisesRegex(TimeoutError, "aws_command_deadline"):
                ports.aws("ec2", "fixture-operation", [], deadline=time.monotonic() - 1)
        run.assert_not_called()

    def test_registry_file_is_valid_toml_with_a_reachable_container_alias(self):
        import tomllib

        parsed = tomllib.loads(REGISTRY_HOSTS)
        self.assertEqual(parsed["server"], "http://m5-descriptive-registry:5000")
        self.assertEqual(set(parsed["host"]), {"http://m5-descriptive-registry:5000"})
        self.assertEqual(
            parsed["host"]["http://m5-descriptive-registry:5000"]["capabilities"],
            ["pull", "resolve"],
        )

    def test_kind_explicitly_enables_and_reads_back_the_cri_registry_path(self):
        config = kind_config()
        self.assertEqual(len(config["containerdConfigPatches"]), 1)
        self.assertTrue(registry_configured(config["containerdConfigPatches"][0]))
        self.assertTrue(
            registry_configured(
                '[plugins."io.containerd.cri.v1.images".registry]\n'
                'config_path = "/etc/containerd/certs.d:/etc/docker/certs.d"\n'
            )
        )
        self.assertFalse(registry_configured("version = 2\n"))
        self.assertFalse(
            registry_configured(
                '[plugins."io.containerd.cri.v1.images".registry]\nconfig_path = "/other"\n'
            )
        )

    def test_stopping_the_timer_does_not_fail_on_an_unloaded_oneshot_service(self):
        ports = KindPorts.__new__(KindPorts)
        ports.backstop_armed = True
        calls = []

        def call(argv):
            calls.append(argv)
            if "LoadState" in argv:
                return "not-found\n"
            if "ActiveState" in argv:
                return "inactive\n"
            return ""

        ports.call = call
        ports.stop_backstop()
        self.assertFalse(ports.backstop_armed)
        self.assertNotIn(["systemctl", "stop", "m5-descriptive-cleanup.service"], calls)
        ports.backstop_armed = True
        ports.call = lambda argv: "active" if "ActiveState" in argv else call(argv)
        with self.assertRaisesRegex(ValueError, "backstop_timer_still_active"):
            ports.stop_backstop()

    def test_routine_agent_progress_is_bounded_to_the_current_source_and_has_no_argv(
        self,
    ):
        import package_a_host as agent

        with tempfile.TemporaryDirectory() as tmp:
            host = agent.Host(Path(tmp), "fixture-token", "a" * 64, 9_999_999_999)
            host.manifest = {"role": "routine_tests", "source_commit": "a" * 40}
            path = host.output / "runner/routine/results.json"
            path.parent.mkdir(parents=True)
            value = {
                "source_commit": "a" * 40,
                "stages": [
                    {"name": "fixture", "status": "PASS", "argv": ["private input"]}
                ]
                * 12,
            }
            path.write_text(json.dumps(value))
            progress = host.status()["routine_stages"]
            self.assertEqual(len(progress), 8)
            self.assertTrue(
                all(row == {"name": "fixture", "status": "PASS"} for row in progress)
            )
            value["source_commit"] = "b" * 40
            path.write_text(json.dumps(value))
            self.assertNotIn("routine_stages", host.status())

    def test_normal_teardown_observes_literal_termination_before_cancel_and_state_deletion(
        self,
    ):
        with tempfile.TemporaryDirectory() as tmp:
            ports = EKSports.__new__(EKSports)
            ports.directory, ports.main_root = Path(tmp), Path(tmp) / "main"
            ports.sdk, ports.host, ports.owned_vpcs = Mock(), None, []
            ports.manifest = {
                "session": "m5-fixture",
                "state_bucket": "m5-fixture-state",
            }
            events = []
            states = iter(("running", "shutting-down", "terminated"))

            def read(*_args):
                state = next(states)
                events.append(state)
                return {"i-known": state}

            ports.tf = lambda root, *_args: events.append(root.name)

            def cancel(_end):
                self.assertEqual(events[-1], "terminated")
                events.append("cancel")
                return True

            ports.capacity = SimpleNamespace(
                cancel_session_capacity_reservations=cancel
            )
            with (
                patch("m5_descriptive_eks.pages", return_value=[]),
                patch("m5_descriptive_eks.gpu_states", side_effect=read),
                patch("m5_descriptive_eks.time.sleep"),
                patch("m5_descriptive_eks.inventory", return_value={"validation": {}}),
            ):
                self.assertTrue(ports.teardown()["complete"])
            self.assertEqual(
                events,
                [
                    "running",
                    "main",
                    "shutting-down",
                    "terminated",
                    "cancel",
                    "bootstrap",
                    "backstop",
                ],
            )

    def test_inventory_preserves_nonempty_service_readbacks_on_refusal(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "inventory.json"

            def read(_client, _operation, field, **_kwargs):
                return ["m5-fixture"] if field == "clusters" else []

            with patch("m5_descriptive_inventory.pages", side_effect=read):
                with self.assertRaises(ValueError):
                    inventory(
                        Mock(),
                        session="m5-fixture",
                        bucket="m5-fixture-state",
                        after_ms=0,
                        output=path,
                    )
            record = json.loads(path.read_bytes())
            self.assertEqual(
                record["inventories"]["eks_clusters"]["resources"], ["m5-fixture"]
            )
            self.assertIn("validation_error", record)

    def test_gpu_readback_keeps_known_ids_after_asg_and_tag_disappearance(self):
        def read(_client, _operation, field, **kwargs):
            if field == "Reservations" and "InstanceIds" in kwargs:
                self.assertEqual(kwargs["InstanceIds"], ["i-known"])
                return [
                    {
                        "Instances": [
                            {
                                "InstanceId": "i-known",
                                "InstanceType": "g6.xlarge",
                                "State": {"Name": "shutting-down"},
                            }
                        ]
                    }
                ]
            return []

        with patch("m5_descriptive_inventory.pages", side_effect=read):
            self.assertEqual(
                gpu_states(Mock(), "m5-fixture", ["i-known"]),
                {"i-known": "shutting-down"},
            )

    def test_failed_apply_keeps_original_error_when_partial_state_backup_also_fails(
        self,
    ):
        import time

        with tempfile.TemporaryDirectory() as tmp:
            ports = EKSports.__new__(EKSports)
            ports.directory = Path(tmp)
            ports.end, ports.profile = time.time() + 60, "fixture"
            ports.manifest = {
                "operator_tools": {"terraform": {"path": "fixture-terraform"}}
            }
            ports.backup_state = Mock(side_effect=ValueError("fixture backup failure"))
            root = ports.directory / "bootstrap"
            root.mkdir()
            failure = subprocess.CalledProcessError(1, ["fixture-terraform"])
            with patch("m5_descriptive_eks.subprocess.run", side_effect=failure):
                with self.assertRaises(subprocess.CalledProcessError) as raised:
                    ports.tf(root, "apply", "create.tfplan")
            self.assertIs(raised.exception, failure)
            receipt = json.loads(
                next(ports.directory.glob("*.state-backup-error.json")).read_bytes()
            )
            self.assertTrue(receipt["original_failure_preserved"])

    def test_packet_rejects_mutated_and_additional_terraform_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            path = directory / "main.tf"
            path.write_bytes(b"fixture")
            manifest = {
                "files": {
                    "main.tf": {
                        "bytes": 7,
                        "sha256": hashlib.sha256(b"fixture").hexdigest(),
                    }
                }
            }
            verify_packet_files(directory, manifest)
            path.write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "packet_file_changed"):
                verify_packet_files(directory, manifest)
            path.write_bytes(b"fixture")
            (directory / "override.tf.json").write_text("{}")
            with self.assertRaisesRegex(ValueError, "unbound_terraform_input"):
                verify_packet_files(directory, manifest)

    def test_phase_cutoffs_preserve_both_retrieval_hops_and_cleanup(self):
        timing = session_timing(700)
        self.assertEqual(timing["one_retrieval_seconds"], 2208)
        self.assertEqual(timing["gateway_rollout_seconds"], 600)
        self.assertEqual(timing["vllm_rollout_seconds"], 900)
        end = 18000
        self.assertEqual(phase_deadline(end, timing, "load"), 11784)
        self.assertEqual(phase_deadline(end, timing, "export"), 13992)
        self.assertEqual(phase_deadline(end, timing, "retrieve"), 16200)
        self.assertEqual(session_timing(640)["remaining_infrastructure_seconds"], 6334)
        self.assertEqual(session_timing(640)["minimum_workload_seconds"], 4170)
        with self.assertRaisesRegex(ValueError, "startup_exceeds_replacement_window"):
            session_timing(721)

    def test_capacity_preserves_r1_error_logs_and_the_pinned_cli_for_az_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            ports = SimpleNamespace(
                directory=Path(tmp),
                profile="fixture-profile",
                manifest={
                    "session": "m5-fixture",
                    "operator_tools": {"aws": {"path": "/pinned/aws"}},
                },
            )
            capacity = Capacity(ports)
            capacity.inputs["availability_zone"] = "us-east-1c"

            def insufficient(_self, argv, _deadline, name):
                self.assertEqual(argv[0], "/pinned/aws")
                self.assertEqual(argv[argv.index("--profile") + 1], "fixture-profile")
                (capacity.directory / (name + ".stderr")).write_text(
                    "An error occurred (InsufficientInstanceCapacity) when calling CreateCapacityReservation"
                )
                raise RuntimeError("fixture CLI exit")

            with patch(
                "inference_platform.r1_lifecycle.Production.command", insufficient
            ):
                outcome = capacity.reserve_capacity(capacity.now() + 60)
            self.assertEqual(outcome["result"], "capacity_unavailable")
            self.assertEqual(outcome["error_code"], "InsufficientInstanceCapacity")

    def test_provider_roots_validate_with_real_pinned_terraform(self):
        terraform = shutil.which("terraform")
        self.assertIsNotNone(
            terraform, "routine AWS runner must install pinned Terraform"
        )
        root = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as tmp:
            tree = Path(tmp) / "terraform"
            shutil.copytree(
                root / "infra/terraform",
                tree,
                ignore=shutil.ignore_patterns(".terraform", "*.tfstate*"),
            )
            cache = Path(tmp) / "plugins"
            cache.mkdir()
            for name in ("m5_descriptive", "m5_descriptive_backstop"):
                env = {**os.environ, "TF_PLUGIN_CACHE_DIR": str(cache)}
                result = subprocess.run(
                    [
                        terraform,
                        "-chdir=" + str(tree / name),
                        "init",
                        "-backend=false",
                        "-input=false",
                        "-lockfile=readonly",
                    ],
                    env=env,
                    capture_output=True,
                    timeout=300,
                )
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                result = subprocess.run(
                    [terraform, "-chdir=" + str(tree / name), "validate", "-json"],
                    env=env,
                    capture_output=True,
                    timeout=60,
                )
                self.assertEqual(result.returncode, 0, result.stdout.decode())
                self.assertTrue(json.loads(result.stdout)["valid"])

    def test_descriptive_bootstrap_reexecs_locked_venv(self):
        with patch(
            "inference_platform.package_a_cloud.sys.executable", "/standalone/python"
        ):
            self.assertEqual(
                gate_a_role_reexec_target(
                    {
                        "role": "descriptive_operator",
                        "python_executable": "/locked/.venv/bin/python",
                    }
                ),
                "/locked/.venv/bin/python",
            )

    def test_descriptive_agent_preserves_large_files_and_never_truncates_them(self):
        import os
        import package_a_host as agent

        with tempfile.TemporaryDirectory() as tmp:
            host = agent.Host(Path(tmp), "fixture-token", "a" * 64, 9_999_999_999)
            host.manifest = {"role": "descriptive_operator"}
            host.output.mkdir()
            path = host.output / "records.jsonl"
            body = os.urandom(600 * 1024)
            path.write_bytes(body)
            with patch.object(agent, "CHUNK", 1024):
                with self.assertRaisesRegex(ValueError, "receipt_export_limit"):
                    host.dispatch("/freeze", b"", {})
            self.assertEqual(path.read_bytes(), body)
            self.assertIsNone(host.frozen)

    def test_round_373_e10_source_pins_actual_events_and_rejects_changed_evidence(self):
        self.assertEqual(
            E10_SHA256,
            "a96b2b654ffd363cc485516b13d1056cb55005e7d83b0b0ea4e21da6a649aaec",
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "fixture.tar"
            # Portable synthetic archive uses the actual E10 timestamp pair;
            # no private archive dependency or new public exclusion is needed.
            rows = [
                dict(
                    event=event,
                    mono_ns=mono,
                    wall_ns=wall,
                    boot_id="fixture",
                    pod_uid="fixture",
                    restart_count=0,
                )
                for event, mono, wall in [
                    ("process_start", 701429521858, 1793062252347147361),
                    ("startup", 990940339021, 1793062541857965284),
                ]
            ]
            with tarfile.open(archive, "w") as target:
                for name, data in [
                    (
                        "results/runtime/lifecycle.jsonl",
                        b"\n".join(json.dumps(x).encode() for x in rows),
                    ),
                    (
                        "results/l4-engine.log",
                        b"synthetic log; real hash comes from pinned archive",
                    ),
                ]:
                    item = tarfile.TarInfo(name)
                    item.size = len(data)
                    target.addfile(item, io.BytesIO(data))
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            with (
                patch("build_m5_descriptive_packet.ROOT", root),
                patch("build_m5_descriptive_packet.E10_ARCHIVE", "fixture.tar"),
                patch("build_m5_descriptive_packet.E10_SHA256", digest),
            ):
                proof = e10_startup_evidence()
                self.assertEqual(
                    proof["source_member"], "results/runtime/lifecycle.jsonl"
                )
                self.assertAlmostEqual(proof["engine_start_seconds"][0], 289.510817163)
                self.assertEqual(startup_bound(None)["seconds"], 640)
                path = root / "startup.json"
                path.write_text(json.dumps(proof))
                self.assertEqual(startup_bound(path)["seconds"], 640)
                for invalid in (
                    {"engine_start_seconds": []},
                    {**proof, "engine_start_seconds": [True]},
                    {**proof, "source_sha256": "a" * 64},
                ):
                    path.write_text(json.dumps(invalid))
                    with (
                        self.subTest(invalid=invalid),
                        self.assertRaisesRegex(ValueError, "e10_startup_evidence"),
                    ):
                        startup_bound(path)
                archive.write_bytes(archive.read_bytes() + b"changed")
                with self.assertRaisesRegex(ValueError, "e10_startup_archive_hash"):
                    startup_bound(None)

    def test_live_hourly_rate_requires_one_positive_matching_rate(self):
        def price(rate):
            return json.dumps(
                {
                    "product": {"attributes": {"usagetype": "perCluster"}},
                    "terms": {
                        "OnDemand": {
                            "one": {
                                "priceDimensions": {
                                    "hour": {
                                        "unit": "Hrs",
                                        "pricePerUnit": {"USD": str(rate)},
                                    }
                                }
                            }
                        }
                    },
                }
            )

        self.assertEqual(
            hourly({"PriceList": [price(0.1)]}, "eks", usage="perCluster"), 0.1
        )
        standard = json.loads(price(0.1))
        standard["terms"]["OnDemand"]["one"]["priceDimensions"]["hour"]["unit"] = (
            "hours"
        )
        self.assertEqual(hourly({"PriceList": [json.dumps(standard)]}, "eks"), 0.1)
        with self.assertRaisesRegex(ValueError, "price_ambiguous"):
            hourly({"PriceList": [price(0.1), price(0.2)]}, "eks")

    def test_review_is_exact_latest_round_and_single_marker(self):
        manifest, digest = {"source_commit": "a" * 40}, "b" * 64
        marker = f"M5 DESCRIPTIVE EKS PLAN APPROVED manifest={digest} source={manifest['source_commit']}"
        require_review("## Claude Round 999\n" + marker, manifest, digest)
        for text in (
            "## Claude Round 998\n" + marker + "\n## Claude Round 999\n",
            "## Claude Round 999\n" + marker + "\n" + marker,
            "## Claude Round 999\n",
        ):
            with self.assertRaisesRegex(ValueError, "exact_committed_review_required"):
                require_review(text, manifest, digest)

    def test_all_kubernetes_operations_are_shared(self):
        for name in (
            "smoke",
            "load",
            "rollout",
            "export",
            "retrieve",
            "client_control",
            "retrieve_clients",
        ):
            self.assertIs(getattr(KindPorts, name), getattr(ClusterPorts, name))
            self.assertIs(getattr(EKSClusterPorts, name), getattr(ClusterPorts, name))

    def test_original_deadline_put_is_exclusive_and_never_extended(self):
        sdk, ssm = Mock(), Mock()
        sdk.client.return_value = ssm
        manifest = {"session": "m5-fixture"}
        record = arm(sdk, manifest, started=100, now=lambda: 101)
        self.assertEqual(record["deadline_epoch"], 18100)
        self.assertFalse(ssm.put_parameter.call_args.kwargs["Overwrite"])
        ssm.put_parameter.side_effect = ClientError(
            {"Error": {"Code": "ParameterAlreadyExists"}}, "PutParameter"
        )
        ssm.get_parameter.return_value = {"Parameter": {"Value": json.dumps(record)}}
        self.assertEqual(arm(sdk, manifest, started=100, now=lambda: 102), record)
        with self.assertRaisesRegex(ValueError, "original_deadline_changed"):
            arm(sdk, manifest, started=101, now=lambda: 102)

    def test_backstop_unreadable_or_malformed_deadline_fails_closed_to_cleanup(self):
        ssm = Mock()
        ssm.get_parameter.side_effect = ClientError(
            {"Error": {"Code": "ParameterNotFound"}}, "GetParameter"
        )
        self.assertEqual(deadline(ssm, "/m5-fixture/deadline"), 0)
        ssm.get_parameter.side_effect = None
        ssm.get_parameter.return_value = {
            "Parameter": {
                "Value": json.dumps(
                    {
                        "session": "m5-fixture",
                        "started_epoch": 10,
                        "deadline_epoch": 19000,
                    }
                )
            }
        }
        self.assertEqual(deadline(ssm, "/m5-fixture/deadline"), 0)
        ssm.get_parameter.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException"}}, "GetParameter"
        )
        self.assertEqual(deadline(ssm, "/m5-fixture/deadline"), 0)
        for invalid in ("other", "m5-../foreign", "m5-" + "x" * 18):
            with self.assertRaisesRegex(ValueError, "cleanup_session"):
                owned_session(invalid)

    def witness(self):
        clients = {name: Mock() for name in ("events", "lambda", "iam", "ssm")}
        sdk = Mock()
        sdk.client.side_effect = clients.__getitem__
        events, function = clients["events"], clients["lambda"]
        events.describe_rule.return_value = {
            "State": "ENABLED",
            "ScheduleExpression": "rate(1 minute)",
            "Arn": "arn:rule:fixture",
        }
        events.can_paginate.return_value = False
        events.list_targets_by_rule.return_value = {
            "Targets": [{"Arn": "arn:lambda:fixture"}]
        }
        function.get_function_configuration.return_value = {
            "FunctionArn": "arn:lambda:fixture",
            "CodeSha256": "hash",
            "Handler": "m5_descriptive_cleanup.handler",
            "Runtime": "python3.12",
            "Environment": {
                "Variables": {
                    "SESSION": "m5-fixture",
                    "PARAMETER": "/m5-fixture/deadline",
                    "STATE_BUCKET": "m5-fixture-state",
                }
            },
        }
        function.get_policy.return_value = {
            "Policy": json.dumps(
                {
                    "Statement": [
                        {
                            "Principal": {"Service": "events.amazonaws.com"},
                            "Condition": {
                                "ArnLike": {"AWS:SourceArn": "arn:rule:fixture"},
                                "StringEquals": {"AWS:SourceAccount": "000000000000"},
                            },
                        }
                    ]
                }
            )
        }
        deployed = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "eks:DeleteCluster",
                        "eks:DeleteNodegroup",
                        "ecr:DeleteRepository",
                        "ssm:GetParameter",
                    ],
                }
            ]
        }
        deployed["Statement"].extend(self.cleanup_policy()["Statement"])
        clients["iam"].get_role_policy.return_value = {"PolicyDocument": deployed}
        record = {
            "session": "m5-fixture",
            "started_epoch": 100,
            "deadline_epoch": 18100,
        }
        clients["ssm"].get_parameter.return_value = {
            "Parameter": {"Value": json.dumps(record)}
        }
        function.get_function_concurrency.return_value = {}
        function.invoke.return_value = {
            "StatusCode": 200,
            "Payload": io.BytesIO(
                json.dumps(
                    {"armed": True, "deadline_epoch": 18100, "cleanup_started": False}
                ).encode()
            ),
        }
        return (
            sdk,
            clients,
            {
                "session": "m5-fixture",
                "account": "000000000000",
                "state_bucket": "m5-fixture-state",
                "cleanup_zip_sha256_base64": "hash",
                "cleanup_policy_sha256": hashlib.sha256(
                    json.dumps(deployed, sort_keys=True).encode()
                ).hexdigest(),
            },
            record,
        )

    def test_backstop_witness_requires_real_deployed_schedule_target_permission_code_and_original_deadline(
        self,
    ):
        sdk, clients, manifest, record = self.witness()
        self.assertTrue(arming_witness(sdk, manifest, record)["armed"])
        for client, method, replacement in (
            (
                "events",
                "describe_rule",
                {"State": "DISABLED", "ScheduleExpression": "rate(1 minute)"},
            ),
            ("events", "list_targets_by_rule", {"Targets": []}),
            ("lambda", "get_policy", {"Policy": '{"Statement": []}'}),
            ("ssm", "get_parameter", {"Parameter": {"Value": "{}"}}),
            ("iam", "get_role_policy", {"PolicyDocument": {"Statement": []}}),
        ):
            sdk, clients, manifest, record = self.witness()
            getattr(clients[client], method).return_value = replacement
            with (
                self.subTest(client=client, method=method),
                self.assertRaises(ValueError),
            ):
                arming_witness(sdk, manifest, record)

    def test_backstop_sync_invocation_proves_unreserved_execution_and_original_deadline(
        self,
    ):
        sdk, clients, manifest, record = self.witness()
        value = arming_witness(sdk, manifest, record)
        self.assertEqual(
            value["synchronous_invocation"]["response"]["deadline_epoch"], 18100
        )
        call = clients["lambda"].invoke.call_args.kwargs
        self.assertEqual(call["InvocationType"], "RequestResponse")
        self.assertEqual(json.loads(call["Payload"])["original_deadline_epoch"], 18100)
        for body, error in [
            ({"armed": False, "deadline_epoch": 18100, "cleanup_started": True}, None),
            ({"armed": True, "deadline_epoch": 18101, "cleanup_started": False}, None),
            (
                {"armed": True, "deadline_epoch": 18100, "cleanup_started": False},
                "Unhandled",
            ),
        ]:
            sdk, clients, manifest, record = self.witness()
            clients["lambda"].invoke.return_value = {
                "StatusCode": 200,
                "Payload": io.BytesIO(json.dumps(body).encode()),
                "FunctionError": error,
            }
            with (
                self.subTest(body=body, error=error),
                self.assertRaisesRegex(ValueError, "backstop_invocation"),
            ):
                arming_witness(sdk, manifest, record)
        sdk, clients, manifest, record = self.witness()
        clients["lambda"].get_function_concurrency.return_value = {
            "ReservedConcurrentExecutions": 1
        }
        with self.assertRaisesRegex(ValueError, "backstop_unreserved_required"):
            arming_witness(sdk, manifest, record)
        clients["lambda"].invoke.assert_not_called()

    def test_eks_smoke_refuses_when_original_workload_window_will_not_fit(self):
        import time

        ports = EKSClusterPorts.__new__(EKSClusterPorts)
        ports.timing = session_timing(640)
        ports.minimum_workload_seconds = ports.timing["minimum_workload_seconds"]
        ports.deadline = time.monotonic() + 4169
        with self.assertRaisesRegex(TimeoutError, "remaining_workload_window"):
            ports.smoke()

    def test_kind_short_windows_exercise_the_same_workload_budget_guard(self):
        import time

        with (
            tempfile.TemporaryDirectory() as tmp,
            patch("rehearse_m5_descriptive.kind_rollout.Campaign"),
        ):
            ports = KindPorts(Path(tmp) / "host")
            self.assertEqual(ports.minimum_workload_seconds, 821)
            ports.deadline = time.monotonic() + 820
            self.assertIs(KindPorts.smoke, EKSClusterPorts.smoke)
            with self.assertRaisesRegex(TimeoutError, "remaining_workload_window"):
                ports.smoke()

    def test_production_client_windows_bind_gateway_600_and_vllm_900(self):
        import time

        with (
            tempfile.TemporaryDirectory() as tmp,
            patch("m5_descriptive_remote.kind_rollout.Campaign"),
        ):
            ports = EKSClusterPorts(
                Path(tmp),
                {
                    "descriptive": {
                        "session": "m5-fixture",
                        "timing": session_timing(640),
                        "startup_seconds": 640,
                    },
                    "deadline_epoch": time.time() + 18000,
                },
            )
            self.assertEqual(ports.startup_seconds, 640)
            self.assertEqual(ports.rollout_action, 120)
            self.assertEqual(ports.rollout_durations, {"gateway": 600, "vllm": 900})
            ports.k = Mock(return_value=json.dumps({"metadata": {"uid": "old"}}))
            ports.start_task = Mock()
            for app in ("gateway", "vllm"):
                with (
                    self.subTest(app=app),
                    patch(
                        "inference_platform.m5_descriptive_cluster.time.sleep",
                        side_effect=RuntimeError("submitted"),
                    ),
                ):
                    with self.assertRaisesRegex(RuntimeError, "submitted"):
                        ports.rollout(app)
                self.assertEqual(
                    ports.start_task.call_args.kwargs["duration"],
                    ports.rollout_durations[app],
                )

    def test_real_offline_sdk_eks_token_is_sigv4_with_cluster_header(self):
        import boto3

        sdk = boto3.Session(
            aws_access_key_id="fixture-key",
            aws_secret_access_key="fixture-secret",
            region_name="us-east-1",
        )
        value = token(sdk, "m5-fixture")
        self.assertTrue(value.startswith("k8s-aws-v1."))
        body = value.split(".", 1)[1]
        url = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)).decode()
        query = parse_qs(urlsplit(url).query)
        self.assertEqual(query["X-Amz-Algorithm"], ["AWS4-HMAC-SHA256"])
        self.assertEqual(query["X-Amz-SignedHeaders"], ["host;x-k8s-aws-id"])
        self.assertEqual(query["X-Amz-Expires"], ["60"])

    def test_composed_plan_reuses_gpu_validator_and_requires_operator_ip_and_role(self):
        source = plan_fixture()
        root = source["configuration"]["root_module"]
        for row in source["resource_changes"]:
            row["address"] = "module.eks." + row.get(
                "address", row["type"] + "." + row["name"] + "[0]"
            )
        source["configuration"]["root_module"] = {
            "module_calls": {
                "eks": {
                    "module": root,
                    "expressions": {
                        "pins": {
                            "references": [
                                "module.operator.public_ip",
                                "module.operator.role_arn",
                            ]
                        }
                    },
                }
            }
        }
        self.assertEqual(verify_plan(source).count, 2)
        broken = copy.deepcopy(source)
        broken["configuration"]["root_module"]["module_calls"]["eks"]["expressions"][
            "pins"
        ]["references"].remove("module.operator.public_ip")
        with self.assertRaisesRegex(ValueError, "operator_api_binding"):
            verify_plan(broken)

    def test_stager_verifies_upstream_lfs_hash_before_ready(self):
        content = b"fixture model weights"
        entry = SimpleNamespace(
            rfilename="model.safetensors",
            lfs=SimpleNamespace(sha256=hashlib.sha256(content).hexdigest()),
        )
        info = SimpleNamespace(sha="pinned", siblings=[entry])
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch("huggingface_hub.HfApi") as api,
            patch("huggingface_hub.snapshot_download") as download,
        ):
            root = Path(tmp)
            (root / entry.rfilename).write_bytes(content)
            api.return_value.model_info.return_value = info
            download.return_value = str(root)
            self.assertEqual(
                stage("model", "pinned", root, root / "manifest.json")[entry.rfilename][
                    "bytes"
                ],
                len(content),
            )
            entry.lfs.sha256 = "0" * 64
            with self.assertRaisesRegex(ValueError, "model_hash"):
                stage("model", "pinned", root, root / "manifest.json")
