"""Production command reconstruction, leadership and existing-store boundaries."""

import copy
import io
import os
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from inf037b_fitness_fixture import attach
from inf037b_observations_fixture import attach as observations
from inf037b_setup_fixture import fixture

from inference_platform.inf037b_archive import IntegrityError, encode, sha, strict_json
from inference_platform.inf037b_command import commands, dispatch, main, require_group_leader
from inference_platform.inf037b_durable_ports import DurableStore
from inference_platform.inf037b_lifecycle import ProcessCalls, group_members
from inference_platform.inf037b_maximum import current_sources
from inference_platform.inf037b_setup import SetupCommands


class CompletionTests(unittest.TestCase):
    def test_missing_maximum_refuses_before_factory_without_platform_emulation(self):
        # Only the entry validation component: no child/fence/durability claim.
        with patch("inference_platform.inf037b_command.require_group_leader"):
            for config, reason in (
                ({}, "maximum_fixture_required"),
                (
                    {
                        "maximum_fixture": {"path": "/missing-r335-proof", "sha256": "a" * 64},
                        "pins": {},
                    },
                    "maximum_fixture_missing",
                ),
            ):
                with self.subTest(reason=reason), self.assertRaisesRegex(IntegrityError, reason):
                    dispatch(
                        config,
                        "creation",
                        {"measurement_deadline_ms": 1},
                        lambda _: self.fail("factory ran"),
                    )

    def test_durable_command_deadline_and_nonzero_width_bounds(self):
        from test_inf037b_terminal import MemoryStore

        for bounds, refused in (
            ([1000, 1001], False),
            ([1001, 1002], True),
            ([999, 1000], True),
            ([1001, 1000], True),
        ):
            command = object.__new__(SetupCommands)
            command.binding = {"session_id": "test", "pins": {}, "t0_ms": 0}
            command.store = MemoryStore()
            command.store.state.update(
                creation={"data": {}},
                preparation={
                    "result": True,
                    "data": {
                        "other_rows": {},
                        "startup": {},
                        "lifecycle": {"phases": {"preparation": {}}},
                    },
                },
            )
            samples = iter([{"ms": [1000, 1000]}] * 3 + [{"ms": bounds}])
            command.sample = lambda samples=samples: next(samples)
            command.completion_observation = lambda *args: {"elapsed_ms": 1}
            with patch("inference_platform.inf037b_setup.resolve", return_value={}):
                if refused:
                    with (
                        self.subTest(bounds=bounds),
                        self.assertRaisesRegex(IntegrityError, "durable_command_completion"),
                    ):
                        command("resolution", 1001, {"measurement_deadline_ms": 1001})
                else:
                    self.assertEqual(
                        command("resolution", 1001, {"measurement_deadline_ms": 1001}), {}
                    )
            self.assertIn("result", command.store.read()["resolution"])


@unittest.skipUnless(os.name == "posix", "Linux process-group command contract")
class LeadershipTests(unittest.TestCase):
    def test_cli_nonleader_refuses_before_reading_config_or_importing_factory(self):
        with (
            patch("os.getpgrp", return_value=41),
            patch("os.getpid", return_value=42),
            patch.object(
                sys,
                "argv",
                ["command", "--config", "/missing-config", "--operation", "preparation"],
            ),
        ):
            with self.assertRaisesRegex(IntegrityError, "command:group_leader"):
                main()

    def test_nonleader_refuses_before_factory_or_exit_seam(self):
        with (
            patch("os.getpgrp", return_value=41),
            patch("os.getpid", return_value=42),
            patch("os._exit") as exit_command,
        ):
            with self.assertRaisesRegex(IntegrityError, "command:group_leader"):
                dispatch({}, "preparation", {}, lambda config: self.fail("factory ran"))
            exit_command.assert_not_called()
        with patch("os.name", "nt"):
            with self.assertRaisesRegex(IntegrityError, "command:posix"):
                require_group_leader()
        with patch("os.getpgrp", return_value=42), patch("os.getpid", return_value=42):
            require_group_leader()
            with self.assertRaisesRegex(IntegrityError, "command:operation"):
                dispatch({}, "unknown", {}, lambda config: self.fail("factory ran"))
            with self.assertRaisesRegex(IntegrityError, "command:ports"):
                dispatch({}, "reset", {"measurement_deadline_ms": 1}, lambda config: object())

    def test_factory_separator_refuses_before_import(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "config"
            path.write_bytes(encode({"factory": "missing_separator"}))
            with (
                patch("os.getpgrp", return_value=42),
                patch("os.getpid", return_value=42),
                patch.object(
                    sys, "argv", ["command", "--config", str(path), "--operation", "preparation"]
                ),
                patch.object(sys, "stdin", type("Input", (), {"buffer": io.BytesIO(encode({}))})()),
            ):
                with self.assertRaisesRegex(IntegrityError, "command:factory"):
                    main()


@unittest.skipUnless(os.name == "posix", "Linux command/process-group durability")
class CommandTests(unittest.TestCase):
    def config(self, root):
        value = observations(attach(fixture()))
        maximum = strict_json(value["artifacts"][value["maximum_fixture_proof"]["path"]])
        maximum.update(
            fixture_inventory=strict_json(value["export_raw"])["source"],
            source_lf_sha256=current_sources(),
        )
        proof = root / "maximum.json"
        proof.write_bytes(encode(maximum))
        config = {
            "factory": "inf037b_command_fixture:factory",
            "directory": str(root),
            "pins": attach(fixture())["binding"]["pins"],
            "state_storage_id": "state-source",
            "state_destination": "independent-export",
            "maximum_fixture": {"path": str(proof), "sha256": sha(proof.read_bytes())},
        }
        path = root / "config.json"
        path.write_bytes(encode(config))
        return config, path

    def test_real_commands_reconstruct_setup_attempt_and_lazy_terminal(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            _, path = self.config(root)
            mapping = commands(path)
            self.assertEqual(
                mapping["preparation"][:3],
                [sys.executable, "-m", "inference_platform.inf037b_command"],
            )
            calls = ProcessCalls(mapping, lambda: 1000)
            identities = []
            for op in (
                "creation",
                "preparation",
                "resolution",
                "attempt_setup",
                "export",
                "cleanup",
            ):
                context = {
                    "measurement_deadline_ms": 1_801_000,
                    "operation_key": "fixture:" + op,
                    "operation_label": op,
                }
                result = calls(op, 1_801_000, context, spawned=identities.append)
                if op in {"creation", "preparation"}:
                    self.assertIs(result, True)
                if op == "resolution":
                    self.assertFalse(result["paid_ready"])
                self.assertEqual(group_members(identities[-1]["group"]), [])
                if op == "creation":
                    self.assertNotIn("settled", DurableStore(root / "creation", {}).read())
                    self.assertFalse((root / "terminal").exists())
            state = DurableStore(root / "setup", {}).read()
            self.assertFalse((root / "post-join-facts").exists())
            for phase in ("creation", "preparation"):
                self.assertEqual(state[phase]["data"]["raw_reference"], [phase, "capture"])
                self.assertNotIn("raw_bytes", state[phase]["data"])
            fitness_hex = state["preparation_fork"]["gpu"]["raw_hex"]
            self.assertEqual(encode(state).count(fitness_hex.encode()), 1)
            self.assertEqual(
                state["fitness"]["capture"]["raw_reference"], ["preparation_fork", "gpu"]
            )
            self.assertEqual(
                state["export_probe"]["capture"]["raw_reference"], ["preparation_fork", "export"]
            )
            self.assertTrue(DurableStore(root / "creation", {}).read()["settled"]["complete"])
            row5_processes = list(
                map(int, (root / "row5-control-invoked").read_text().splitlines())
            )
            self.assertEqual(len(row5_processes), 1)
            self.assertNotIn(os.getpid(), row5_processes)
            self.assertEqual(
                (root / "row5-stage-invoked").read_text().splitlines(),
                ["known0", "known1", "known2", "cached_stop_known1", "cached_restore_known2"],
            )
            pids = list(map(int, (root / "factories").read_text().splitlines()))
            self.assertEqual(len(pids), 6)
            self.assertNotIn(os.getpid(), pids)

    def test_unknown_inventory_and_changed_binding_refuse(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            config, path = self.config(root)
            calls = ProcessCalls(commands(path), lambda: 1000)
            context = {"measurement_deadline_ms": 1_801_000, "operation_key": "creation"}
            self.assertTrue(calls("creation", 1_801_000, context))
            config["unknown_inventory"] = True
            path.write_bytes(encode(config))
            with self.assertRaisesRegex(IntegrityError, "lifecycle:process_exit"):
                calls("export", 1_801_000, {**context, "operation_key": "export"})
            self.assertFalse((root / "terminal").exists())
            config = copy.deepcopy(config)
            config["pins"]["source"] = "b" * 64
            path.write_bytes(encode(config))
            with self.assertRaisesRegex(IntegrityError, "lifecycle:process_exit"):
                calls("preparation", 1_801_000, {**context, "operation_key": "preparation"})

    def test_final_durable_write_is_charged_and_reopen_cannot_admit_late_result(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            config, path = self.config(root)
            config["late_result_write"] = True
            path.write_bytes(encode(config))
            calls = ProcessCalls(commands(path), lambda: 1000)
            context = {"measurement_deadline_ms": 1_801_000, "operation_key": "creation"}
            self.assertTrue(calls("creation", 1_801_000, context))
            prep = {**context, "operation_key": "preparation"}
            with self.assertRaisesRegex(IntegrityError, "lifecycle:process_exit"):
                calls("preparation", 1_801_000, prep)
            self.assertTrue((root / "late-result-clock").exists())
            # The durable candidate exists, but neither replay nor resolution
            # may use it without rechecking actual completion on the same clock.
            for op, ctx in (
                ("preparation", prep),
                ("resolution", {**context, "operation_key": "resolution"}),
            ):
                with (
                    self.subTest(operation=op),
                    self.assertRaisesRegex(IntegrityError, "lifecycle:process_exit"),
                ):
                    calls(op, 1_801_000, ctx)
            self.assertNotIn("result", DurableStore(root / "setup", {}).read()["resolution"])

    def test_export_archive_semantics_are_checked_before_branch_ack(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            config, path = self.config(root)
            config["bad_export_raw"] = True
            path.write_bytes(encode(config))
            calls = ProcessCalls(commands(path), lambda: 1000)
            context = {"measurement_deadline_ms": 1_801_000, "operation_key": "creation"}
            self.assertTrue(calls("creation", 1_801_000, context))
            with self.assertRaisesRegex(IntegrityError, "lifecycle:process_exit"):
                calls("preparation", 1_801_000, {**context, "operation_key": "preparation"})
            fork = DurableStore(root / "setup", {}).read()["preparation_fork"]
            self.assertEqual(fork["failure"]["branch"], "export")
            self.assertIn("observations:archive_bytes", fork["failure"]["reason"])
            self.assertFalse(fork["export"]["archive_verified"])
            self.assertNotIn("durable_ack", fork["export"])
            self.assertEqual(
                sha(bytes.fromhex(fork["export"]["raw_hex"])), fork["export"]["sha256"]
            )

    def semantic_export_refusal(self, case, reason):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            config, path = self.config(root)
            config["semantic_export_error"] = case
            path.write_bytes(encode(config))
            calls = ProcessCalls(commands(path), lambda: 1000)
            context = {"measurement_deadline_ms": 1_801_000, "operation_key": "creation"}
            self.assertTrue(calls("creation", 1_801_000, context))
            with self.assertRaisesRegex(IntegrityError, "lifecycle:process_exit"):
                calls("preparation", 1_801_000, {**context, "operation_key": "preparation"})
            fork = DurableStore(root / "setup", {}).read()["preparation_fork"]
            self.assertEqual(fork["failure"]["branch"], "export")
            self.assertIn(reason, fork["failure"]["reason"])
            self.assertFalse(fork["export"]["archive_verified"])
            self.assertNotIn("durable_ack", fork["export"])
            raw = bytes.fromhex(fork["export"]["raw_hex"])
            self.assertEqual(sha(raw), fork["export"]["sha256"])
            self.assertTrue(raw)
            exported = strict_json(raw)
            for prefix in ("source", "sanitized", "destination"):
                for name, facts in exported[prefix].items():
                    artifact = fork["export"]["artifacts"][prefix + "/" + name]
                    body = Path(artifact["path"]).read_bytes()
                    self.assertEqual(facts, {"bytes": len(body), "sha256": sha(body)})

    def test_concurrent_export_refuses_segment_integrity_error(self):
        self.semantic_export_refusal("integrity", "observations:archive_integrity")

    def test_concurrent_export_refuses_wrong_sanitized_label(self):
        self.semantic_export_refusal("label", "observations:sanitized_label")

    def test_concurrent_export_refuses_another_sanitizer_source(self):
        self.semantic_export_refusal("source", "observations:sanitizer_source")

    def test_concurrent_export_refuses_pending_sse(self):
        self.semantic_export_refusal("pending", "observations:sanitizer_complete")

    def test_maximum_refuses_before_factory_and_missing_proof_does_not_block_cleanup(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            config, path = self.config(root)
            proof_path = Path(config["maximum_fixture"]["path"])
            maximum = strict_json(proof_path.read_bytes())
            maximum["source_lf_sha256"] = {}
            proof_path.write_bytes(encode(maximum))
            config["maximum_fixture"]["sha256"] = sha(proof_path.read_bytes())
            path.write_bytes(encode(config))
            calls = ProcessCalls(commands(path), lambda: 1000)
            context = {"measurement_deadline_ms": 1_801_000, "operation_key": "fixture:creation"}
            with self.assertRaisesRegex(IntegrityError, "lifecycle:process_exit"):
                calls("creation", 1_801_000, context)
            self.assertFalse((root / "factories").exists())
            proof_path.unlink()
            self.assertTrue(
                calls(
                    "cleanup",
                    1_801_000,
                    {**context, "operation_key": "fixture:cleanup", "operation_label": "cleanup"},
                )
            )


if __name__ == "__main__":
    unittest.main()
