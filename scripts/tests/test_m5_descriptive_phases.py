import json
import shlex
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from inference_platform.m5_descriptive_cluster import ClusterPorts
from inference_platform.m5_descriptive_operator import phase_deadline
from inference_platform.routine_aws_tests import selection
from m5_descriptive_eks import EKSports, phase_command
from package_a_host import Host, host_environment
from package_a_bootstrap_rehearsal import bootstrap_command
from rehearse_m5_descriptive_phases import (
    SITE,
    PhaseKindPorts,
    PROVIDER_OVERRIDES,
    expected_refusal,
    namespace_command,
)
from m5_descriptive_remote import EKSClusterPorts, resolve_tool_paths
from inference_platform.m5_descriptive_operator import session_timing
import hashlib
import os


class PhaseTests(unittest.TestCase):
    def test_ecr_stage_requires_real_payload_and_derives_the_operator_policy(self):
        from inference_platform.m5_ecr_policy import operator_ecr_actions

        for bad in (
            {"descriptive_ecr_push": True},
            {"descriptive_ecr_push": "yes", "descriptive_payload_validation": True},
        ):
            with self.assertRaises(ValueError):
                selection(bad)
        self.assertTrue(
            selection(
                {"descriptive_ecr_push": True, "descriptive_payload_validation": True}
            )["descriptive_ecr_push"]
        )
        source = (
            Path(__file__).resolve().parents[2]
            / "infra/terraform/m5_descriptive/main.tf"
        ).read_text()
        actions = operator_ecr_actions(source)
        self.assertEqual(actions["ecr_token_actions"], ["ecr:GetAuthorizationToken"])
        self.assertIn("ecr:PutImage", actions["ecr_repository_actions"])
        self.assertIn("ecr:BatchGetImage", actions["ecr_repository_actions"])
        self.assertNotIn("ecr:*", actions["ecr_repository_actions"])
        with self.assertRaisesRegex(ValueError, "ecr_policy_scope"):
            operator_ecr_actions(
                source.replace("Resource = module.eks.repository_arn", 'Resource = "*"')
            )
        with self.assertRaisesRegex(ValueError, "ecr_policy_ambiguous"):
            operator_ecr_actions(source + source)
        self.assertIn(
            "AmazonEC2ContainerRegistryPullOnly",
            (
                Path(__file__).resolve().parents[2]
                / "infra/terraform/routine_ecr/routine-ecr.tf"
            ).read_text(),
        )

    def test_pull_fixture_parent_owns_cleanup_while_source_guard_stays_active(self):
        if os.name == "nt":
            self.skipTest("POSIX fd-relative cleanup regression")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo, output = root / "repo", root / "generated"
            repo.mkdir()
            output.mkdir()
            (repo / "unlisted").write_text("unshipped source")
            code = """
import json, shutil
from pathlib import Path
from inference_platform.m5_payload_guard import install_read_guard
from rehearse_m5_ecr import pull_work_directory
repo, output = Path(__import__('sys').argv[1]), Path(__import__('sys').argv[2])
install_read_guard(repo, [])
work = pull_work_directory(output)
(work / 'exec').mkdir()
refused = []
for operation in (lambda: (repo/'unlisted').read_text(), lambda: shutil.rmtree(work)):
    try: operation()
    except ValueError as error: refused.append(str(error))
print(json.dumps({'refused': refused, 'outside_source': not work.is_relative_to(repo)}))
"""
            result = json.loads(
                subprocess.check_output(
                    [sys.executable, "-c", code, str(repo), str(output)],
                    cwd=repo,
                    env={**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)},
                )
            )
            self.assertTrue(result["outside_source"])
            self.assertEqual(
                result["refused"],
                [
                    "descriptive:payload_unlisted_read:unlisted",
                    "descriptive:payload_unlisted_read:exec",
                ],
            )
        # Cleanup here is the unguarded fixture parent, never the sparse phase.
        self.assertFalse(root.exists())

    def test_cold_pull_daemon_owns_a_private_network_and_pinned_binary(self):
        from rehearse_m5_ecr import pull_sandbox_argv

        argv = pull_sandbox_argv("owned", "pinned@sha256:abc", "/host/generated")
        self.assertEqual(argv[:2], ["docker", "run"])
        self.assertEqual(argv[argv.index("--network") + 1], "bridge")
        # Retain an exited daemon's log until the finally block removes it.
        self.assertNotIn("--rm", argv)
        self.assertIn("--privileged", argv)
        self.assertIn("type=bind,source=/host/generated,target=/cold", argv)
        self.assertIn(
            "type=bind,source=/opt/dec077/tools/docker,target=/pinned-docker,readonly",
            argv,
        )
        self.assertEqual(argv[argv.index("--entrypoint") + 1], "/pinned-docker/dockerd")
        self.assertIn("--data-root=/cold/data", argv)

    def test_cold_pull_refuses_shared_network_cached_images_or_broken_primary_bridge(
        self,
    ):
        from rehearse_m5_ecr import cold_pull

        image = "fixture/image@sha256:expected"
        for failure in (
            None,
            "shared_network",
            "host_network",
            "cache",
            "bridge",
            "cleanup",
        ):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                events = []

                def checked(argv, **kwargs):
                    events.append((argv, kwargs.get("env", {})))
                    data = b""
                    if argv[:2] == ["docker", "inspect"]:
                        data = (
                            b"true"
                            if "--format" in argv
                            else json.dumps(
                                [
                                    {
                                        "HostConfig": {
                                            "NetworkMode": "host"
                                            if failure == "host_network"
                                            else "bridge"
                                        },
                                        "State": {"Pid": 123},
                                    }
                                ]
                            ).encode()
                        )
                    elif argv[:3] == ["docker", "image", "inspect"]:
                        data = json.dumps(
                            [
                                {
                                    "RepoDigests": [image],
                                    "Id": "config",
                                    "RootFS": {"Layers": ["layer"]},
                                }
                            ]
                        ).encode()
                    elif argv[:3] == ["docker", "image", "ls"] and failure == "cache":
                        data = b"unexpected-cached-image"
                    elif argv[:3] == ["docker", "ps", "-aq"] and failure == "cleanup":
                        data = b"leftover-owned-container"
                    elif argv[:2] == ["docker", "run"] and "/bin/true" in argv:
                        if (
                            failure == "bridge"
                            and sum("/bin/true" in a for a, _ in events) == 2
                        ):
                            raise RuntimeError("primary bridge missing")
                    return subprocess.CompletedProcess(argv, 0, stdout=data, stderr=b"")

                with (
                    patch("rehearse_m5_ecr.checked_process", side_effect=checked),
                    patch(
                        "rehearse_m5_ecr.subprocess.run",
                        return_value=subprocess.CompletedProcess(
                            [], 0, stdout=b"", stderr=b""
                        ),
                    ),
                    patch("rehearse_m5_ecr.login"),
                    patch(
                        "rehearse_m5_ecr.os.readlink",
                        side_effect=[
                            "host",
                            "host" if failure == "shared_network" else "sandbox",
                        ],
                    ),
                ):
                    if failure:
                        reason = {
                            "shared_network": "cold_network_not_isolated",
                            "host_network": "cold_network_not_isolated",
                            "cache": "cold_daemon_not_empty",
                            "bridge": "primary bridge missing",
                            "cleanup": "cold_daemon_cleanup_unverified",
                        }[failure]
                        with self.assertRaisesRegex((ValueError, RuntimeError), reason):
                            cold_pull(
                                {"gateway": image},
                                Mock(),
                                {},
                                Path(tmp),
                                sandbox_image="pinned",
                                host_directory="/host/generated",
                            )
                    else:
                        proof = cold_pull(
                            {"gateway": image},
                            Mock(),
                            {},
                            Path(tmp),
                            sandbox_image="pinned",
                            host_directory="/host/generated",
                        )
                        self.assertTrue(
                            proof["isolation"]["separate_network_namespace"]
                        )
                        self.assertTrue(proof["isolation"]["container_removed"])
                        self.assertTrue(proof["isolation"]["primary_bridge_after"])
                        self.assertEqual(proof["isolation"]["initial_images"], 0)
                        probes = [a for a, _ in events if "/bin/true" in a]
                        self.assertEqual(len(probes), 2)
                        self.assertTrue(
                            all(a[a.index("--network") + 1] == "bridge" for a in probes)
                        )

    def test_ecr_actor_must_match_the_planned_writer_and_pull_roles(self):
        from rehearse_m5_ecr import require_role

        role = "arn:aws:iam::123456789012:role/planned-writer"
        self.assertTrue(
            require_role(
                "arn:aws:sts::123456789012:assumed-role/planned-writer/fixture", role
            )
        )
        for wrong in (
            "arn:aws:sts::123456789012:assumed-role/other/fixture",
            "arn:aws:sts::210987654321:assumed-role/planned-writer/fixture",
        ):
            with self.assertRaisesRegex(ValueError, "unexpected_principal"):
                require_role(wrong, role)

    def test_ecr_cleanup_deletes_image_batches_before_destroy_and_always_destroys(self):
        from inference_platform.routine_aws_tests import RoutinePorts
        from inference_platform.package_a_operator import Ports

        with tempfile.TemporaryDirectory() as tmp:
            ports = RoutinePorts.__new__(RoutinePorts)
            ports.manifest = {
                "routine_selection": {"descriptive_ecr_push": True},
                "session": "fixture",
            }
            ports.runtime = Path(tmp)
            ports.aws = Mock(
                side_effect=[
                    {"repositories": [{"repositoryName": "fixture-descriptive-ecr"}]},
                    {
                        "imageIds": [
                            {"imageDigest": "sha256:" + str(n)} for n in range(201)
                        ]
                    },
                    {},
                    {},
                    {},
                ]
            )
            with patch.object(
                Ports, "teardown", return_value={"destroy_completed": True}
            ) as destroy:
                self.assertTrue(ports.teardown(100)["destroy_completed"])
            batches = [
                x.args[2]
                for x in ports.aws.call_args_list
                if x.args[1] == "batch-delete-image"
            ]
            self.assertEqual([len(json.loads(x[-1])) for x in batches], [100, 100, 1])
            destroy.assert_called_once()
            ports.aws = Mock(side_effect=RuntimeError("failed deletion"))
            with (
                patch.object(
                    Ports, "teardown", return_value={"destroy_completed": True}
                ) as destroy,
                self.assertRaisesRegex(RuntimeError, "ecr_cleanup_failed"),
            ):
                ports.teardown(100)
            destroy.assert_called_once()

    def test_fresh_real_ports_rebind_verified_tools_and_load_provision_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            suffix = ".exe" if os.name == "nt" else ""
            system = "windows" if os.name == "nt" else "linux"
            pins = {}
            for name in ("kind", "kubectl"):
                data = (name + " pinned fixture").encode()
                (root / (name + suffix)).write_bytes(data)
                pins[f"{name}_{system}_amd64_sha256"] = hashlib.sha256(data).hexdigest()
            state = {
                "client_pod": "load-client-fixture",
                "client_image": "fixture@sha256:" + "a" * 64,
                "client_placement": {"node_role": "cpu"},
                "results": {"provision": True},
            }
            (root / "state.json").write_text(json.dumps(state))
            campaign = SimpleNamespace(
                tools=root,
                pins=pins,
                install_tools=Mock(
                    side_effect=AssertionError("no install/download in a new phase")
                ),
            )
            original_end = time.time() + 18000
            manifest = {
                "descriptive": {
                    "original_deadline_epoch": original_end,
                    "session": "fixture",
                    "startup_seconds": 640,
                    "timing": session_timing(640),
                },
                "deadline_epoch": phase_deadline(
                    original_end, session_timing(640), "provision"
                ),
            }
            with patch(
                "m5_descriptive_remote.kind_rollout.Campaign", return_value=campaign
            ):
                ports = EKSClusterPorts(root, manifest)
            ports.call = Mock(return_value="{}")
            ports.k("get", "pods")
            self.assertEqual(
                ports.call.call_args.args[0][0], root / ("kubectl" + suffix)
            )
            self.assertEqual(ports.client_pod, state["client_pod"])
            self.assertEqual(ports.results, state["results"])
            campaign.install_tools.assert_not_called()
            (root / ("kubectl" + suffix)).write_bytes(b"changed")
            with self.assertRaisesRegex(
                ValueError, "pinned_tool_missing_or_changed:kubectl"
            ):
                resolve_tool_paths(campaign)

    def test_original_deadline_and_agent_cutoff_are_bound_by_real_operator(self):
        operator = EKSports.__new__(EKSports)
        operator.end = 28000
        operator.manifest = {
            "host_manifest": {"role": "descriptive_operator"},
            "descriptive": {
                "session": "fixture",
                "startup_seconds": 640,
                "timing": session_timing(640, 140),
            },
            "timing": session_timing(640, 140),
        }
        original = operator.host_runtime(
            {"repository_url": {"value": "fixture.invalid/repo"}}
        )
        self.assertEqual(original["deadline_epoch"], operator.end)
        self.assertEqual(
            original["descriptive"]["original_deadline_epoch"], operator.end
        )
        self.assertEqual(operator.host_work_deadline(), 21784)
        agent_runtime = {**original, "deadline_epoch": operator.host_work_deadline()}
        for scenario in ("accepted", "missing", "mismatch"):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as tmp:
                runtime = json.loads(json.dumps(agent_runtime))
                if scenario == "missing":
                    del runtime["descriptive"]["original_deadline_epoch"]
                if scenario == "mismatch":
                    runtime["deadline_epoch"] = operator.end
                with (
                    patch("m5_descriptive_remote.kind_rollout.Campaign"),
                    patch("m5_descriptive_remote.resolve_tool_paths"),
                ):
                    if scenario == "accepted":
                        ports = EKSClusterPorts(Path(tmp), runtime)
                        self.assertEqual(ports.original_end, 28000)
                        self.assertEqual(ports.work_deadline_epoch, 21784)
                        self.assertEqual(ports.deadline_epoch, 26200)
                    else:
                        reason = (
                            "original_deadline_missing"
                            if scenario == "missing"
                            else "host_work_deadline_mismatch"
                        )
                        with self.assertRaisesRegex(ValueError, reason):
                            EKSClusterPorts(Path(tmp), runtime)

    def test_real_bootstrap_namespace_cannot_overwrite_live_parent_tools(self):
        root = Path("/scratch/fixture")
        bootstrap = namespace_command(root, "producer", share_tools=False)[-1]
        self.assertNotIn("mount --bind /opt/dec077/tools", bootstrap)
        self.assertIn("mount --rbind /scratch/fixture /opt/dec077", bootstrap)
        self.assertIn("exec env -i", bootstrap)
        probe = namespace_command(root, "probe")[-1]
        self.assertIn("mount --bind /opt/dec077/tools", probe)

    def test_phase_stand_in_inherits_real_construction_save_and_state_loading(self):
        self.assertIs(PhaseKindPorts.__init__, EKSClusterPorts.__init__)
        self.assertIs(PhaseKindPorts.save, EKSClusterPorts.save)
        overridden = {
            name for name, value in vars(PhaseKindPorts).items() if callable(value)
        }
        self.assertEqual(overridden, set(PROVIDER_OVERRIDES))
        for name in ("smoke", "load", "rollout", "export", "retrieve", "k"):
            self.assertIs(getattr(PhaseKindPorts, name), getattr(EKSClusterPorts, name))

    def test_bootstrap_rehearsal_uses_agent_environment_and_preserves_bare_control(
        self,
    ):
        arguments = ("/repo/bootstrap.sh", "/runtime.json", "/output")
        clean = bootstrap_command(*arguments)
        bare = bootstrap_command(*arguments, with_environment=False)
        self.assertEqual(clean[:2], ["env", "-i"])
        self.assertEqual(
            dict(item.split("=", 1) for item in clean[2 : clean.index("sh")]),
            host_environment(),
        )
        self.assertEqual(
            dict(item.split("=", 1) for item in bare[2 : bare.index("sh")]),
            {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"},
        )
        self.assertEqual(clean[-4:], ["sh", *arguments])
        self.assertEqual(bare[-4:], clean[-4:])

    def test_old_shell_requires_actual_observed_go_module_cache_refusal(self):
        observed = "go: module cache not found: neither GOMODCACHE nor GOPATH is set"
        self.assertEqual(
            expected_refusal(
                "old-shell", "command_failed:go:exit=1; stderr tail: " + observed
            ),
            observed,
        )
        for message in (
            "python: not found",
            observed,
            "command_failed:docker:exit=1; " + observed,
            "command_failed:go:exit=1; unrelated compiler failure",
        ):
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(ValueError, "wrong_negative_failure"),
            ):
                expected_refusal("old-shell", message)

    def test_literal_phase_shell_and_bootstrap_child_share_all_eight_variables(self):
        expected = {
            "HOME": "/root",
            "GOPATH": "/root/go",
            "GOMODCACHE": "/root/go/pkg/mod",
            "GOCACHE": "/root/.cache/go-build",
            "XDG_CACHE_HOME": "/root/.cache",
            "LANG": "C.UTF-8",
            "PATH": "/opt/dec077/tools/go/bin:/opt/dec077/tools/uv-x86_64-unknown-linux-gnu:/opt/dec077/tools/docker:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "PYTHONPATH": "/opt/dec077/repo/python/src",
        }
        self.assertEqual(host_environment(), expected)
        for phase in (
            "provision",
            "smoke",
            "load",
            "gateway_rollout",
            "replica_rollout",
            "export",
            "retrieve",
        ):
            shell = phase_command(phase)
            for name, value in expected.items():
                self.assertIn(name + "=" + shlex.quote(value), shell)
            self.assertIn(
                "/opt/dec077/repo/scripts/m5_descriptive_remote.py " + phase, shell
            )
        with tempfile.TemporaryDirectory() as tmp:
            host = Host(tmp, "token", "hash", time.time() + 60)
            host.manifest = {}
            (Path(tmp) / "stage.json").write_text("{}")
            with patch("package_a_host.subprocess.Popen") as spawn:
                spawn.return_value.poll.return_value = None
                host.dispatch("/start", b"", {})
                self.assertEqual(spawn.call_args.kwargs["env"], expected)
            host.log.close()

    def test_actual_remote_dispatch_uses_shared_shell(self):
        ports = EKSports.__new__(EKSports)
        ports.end = time.time() + 600
        ports.manifest = {
            "timing": {
                "cleanup_reserve_seconds": 10,
                "one_retrieval_seconds": 10,
                "retrieval_reserve_seconds": 20,
            }
        }
        ports.host = SimpleNamespace(
            host="fixture-host",
            ssm=Mock(
                return_value={
                    "StandardOutputContent": 'DESCRIPTIVE_PHASE_RESULT={"ok": true}'
                }
            ),
        )
        self.assertEqual(ports.remote("provision"), {"ok": True})
        self.assertEqual(ports.host.ssm.call_args.args[1], [phase_command("provision")])
        argv = namespace_command(Path("/test/sparse"), phase_command("provision"))
        self.assertIn("exec env -i /bin/sh -c", argv[-1])
        self.assertIn("mount --rbind /test/sparse /opt/dec077", argv[-1])
        self.assertIn("main", SITE)
        with self.assertRaises(ValueError):
            phase_command("arbitrary")

    def test_partial_export_preserves_absence_events_pods_and_phase_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ports = ClusterPorts()
            ports.output, ports.results, ports.credential = (
                root,
                {},
                "private-client-token",
            )
            ports.phase_logs = root / "logs"
            ports.phase_logs.mkdir()
            (ports.phase_logs / "provision.log").write_text(
                "compiler sentinel Bearer private-client-token"
            )
            ports.k = Mock(
                side_effect=[
                    json.dumps({"items": [{"type": "Warning", "reason": "Failed"}]}),
                    json.dumps(
                        {
                            "items": [
                                {
                                    "metadata": {"name": "partial", "uid": "uid"},
                                    "status": {"phase": "Pending"},
                                }
                            ]
                        }
                    ),
                ]
            )
            ports.retrieve_clients = Mock(
                side_effect=AssertionError("client absent must not be queried")
            )
            frozen = ports.export()
            self.assertNotIn("clients", frozen)
            self.assertEqual(
                json.loads((root / "frozen/client-records.json").read_bytes()),
                {
                    "status": "absent",
                    "reason": "client_pod_not_created",
                    "inventory": None,
                },
            )
            self.assertIn("pod-states.json", frozen)
            log = (root / "frozen/phase-logs/provision.log").read_text()
            self.assertIn("compiler sentinel", log)
            self.assertNotIn("private-client-token", log)
            self.assertEqual(ports.retrieve(), frozen)

    def test_partial_export_records_unavailable_observations_without_inventing_empty_client(
        self,
    ):
        with tempfile.TemporaryDirectory() as tmp:
            ports = ClusterPorts()
            ports.output, ports.results = Path(tmp), {}
            ports.k = Mock(side_effect=RuntimeError("cluster not created"))
            ports.export()
            observed = json.loads((Path(tmp) / "frozen/observations.json").read_bytes())
            self.assertEqual(observed["events"]["status"], "unavailable")
            self.assertFalse((Path(tmp) / "frozen/clients").exists())

    def test_failed_remote_export_falls_back_inside_same_deadline_and_hash_checks_retrieval(
        self,
    ):
        with tempfile.TemporaryDirectory() as tmp:
            ports = EKSports.__new__(EKSports)
            ports.directory, ports.end, ports.bootstrap_complete = (
                Path(tmp),
                time.time() + 120,
                True,
            )
            ports.host = SimpleNamespace(token="hidden-token")
            ports.remote = Mock(
                side_effect=RuntimeError("remote export failed hidden-token")
            )
            ports.manifest = {
                "timing": {
                    "cleanup_reserve_seconds": 10,
                    "one_retrieval_seconds": 20,
                    "retrieval_reserve_seconds": 40,
                }
            }
            path = Path(tmp) / "prebootstrap-diagnostics.json"
            path.write_text('{"complete":true}')
            import hashlib

            facts = {
                "bytes": path.stat().st_size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
            frozen = {"kind": "repo-free-diagnostics", "files": {path.name: facts}}
            with patch("m5_descriptive_eks.collect", return_value=frozen) as collect:
                self.assertEqual(ports.export(), frozen)
                self.assertEqual(
                    collect.call_args.args[2],
                    phase_deadline(ports.end, ports.manifest["timing"], "export"),
                )
            self.assertNotIn(
                "hidden-token", (Path(tmp) / "remote-export-failure.json").read_text()
            )
            self.assertEqual(ports.retrieve(), frozen)
            path.write_text("changed")
            with self.assertRaisesRegex(ValueError, "diagnostics_readback"):
                ports.retrieve()

    def test_routine_phase_rehearsal_cannot_run_without_real_payload_validation(self):
        with self.assertRaisesRegex(ValueError, "phase_rehearsal_requires_payload"):
            selection({"descriptive_phase_rehearsal": True})
        self.assertTrue(
            selection(
                {
                    "descriptive_phase_rehearsal": True,
                    "descriptive_payload_validation": True,
                }
            )["descriptive_phase_rehearsal"]
        )
        with self.assertRaises(ValueError):
            selection({"descriptive_phase_rehearsal": "yes"})


if __name__ == "__main__":
    unittest.main()
