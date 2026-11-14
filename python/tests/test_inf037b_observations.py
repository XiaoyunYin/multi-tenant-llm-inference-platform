"""Raw replay/sizing/transfer derivation and command-side refusals."""

import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import test_inf037b_setup as setup_tests
from inf037b_fitness_fixture import attach as fitness
from inf037b_observations_fixture import attach
from inf037b_setup_fixture import fixture

from inference_platform.inf037b_archive import IntegrityError, encode, sha, strict_json
from inference_platform.inf037b_setup import SetupCommands
from inference_platform.inf037b_setup_observations import export_observations, replay_observations

CASES = []


def mutation_case(function, reason, occurrence=1):
    site = os.environ.get("INF037B_MUTATION_SITE_ID")
    return site is None or site.endswith(f":{function}:{reason}#{occurrence}")


class ObservationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.value = attach(fitness(fixture()))

    def replay(self, raw=None):
        return replay_observations(raw or self.value["replay_raw"], binding=self.value["binding"])

    def export(self, raw=None, artifacts=None, proof=None, sizing_proof=None):
        sizing_path = self.value["lifecycle"]["transfer"]["sizing_proof"]["path"]
        return export_observations(
            raw or self.value["export_raw"],
            binding=self.value["binding"],
            artifacts=self.value["export_artifacts"] if artifacts is None else artifacts,
            maximum_fixture=proof
            or strict_json(self.value["artifacts"]["proof/maximum-fixture.json"]),
            sizing_proof=sizing_proof or strict_json(self.value["artifacts"][sizing_path]),
        )

    def evaluate_export(self, raw, artifacts, *, proof=None, sizing_proof=None):
        value = strict_json(raw)
        sizing_path = self.value["lifecycle"]["transfer"]["sizing_proof"]["path"]
        maximum = copy.deepcopy(
            proof or strict_json(self.value["artifacts"]["proof/maximum-fixture.json"])
        )
        maximum["source_inventory_sha256"] = sha(encode(value["source"]))
        return export_observations(
            raw,
            binding=self.value["binding"],
            artifacts=artifacts,
            maximum_fixture=maximum,
            sizing_proof=copy.deepcopy(
                sizing_proof or strict_json(self.value["artifacts"][sizing_path])
            ),
        )

    def sync_archive_prefix(self, value, artifacts, root, prefix):
        from inference_platform.inf037b_setup_observations import inventory

        archive_root = root / prefix
        value[prefix] = inventory(archive_root)
        for name in value[prefix]:
            artifacts[prefix + "/" + name] = archive_root / name

    def refuse(self, kind, change, reason):
        raw = strict_json(self.value[kind + "_raw"])
        change(raw)
        with self.assertRaisesRegex(IntegrityError, reason) as caught:
            (self.replay if kind == "replay" else self.export)(encode(raw))
        CASES.append(
            {
                "case": kind + "_refusal",
                "reason": str(caught.exception),
                "raw_sha256": sha(encode(raw)),
            }
        )

    def copied_export_artifacts(self):
        temporary = tempfile.TemporaryDirectory(prefix="inf037b-export-test-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        copied = {}
        for prefix in ("source", "sanitized", "destination"):
            for directory in ("raw", "cohorts", "events"):
                (root / prefix / directory).mkdir(parents=True, exist_ok=True)
        for key, source in self.value["export_artifacts"].items():
            prefix, name = key.split("/", 1)
            target = root / prefix / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            copied[key] = target
        return root, copied

    @staticmethod
    def rewrite_manifest(root):
        from inference_platform.inf037b_setup_observations import inventory

        files = inventory(root)
        content = "".join(
            f"{facts['sha256']}  {name}\n"
            for name, facts in sorted(files.items())
            if name != "SHA256SUMS"
        )
        (root / "SHA256SUMS").write_text(content, encoding="utf-8", newline="\n")
        return inventory(root)

    def test_replay_full_schedule_journal_observations_and_nonmutation(self):
        original = copy.deepcopy(self.value)
        result = self.replay()
        self.assertEqual(result["virtual_schedule_ms"], [1560000] * 3 + [300000] * 2)
        self.assertEqual(
            result["observations_ms"], {"attempt": [[1, 1]] * 3, "reset": [[1, 1]] * 2}
        )
        self.assertEqual(self.value, original)
        CASES.append(
            {
                "case": "maximum_logical_replay",
                "result": result,
                "journal_sha256": sha(
                    bytes.fromhex(strict_json(self.value["replay_raw"])["journal_hex"])
                ),
            }
        )

    def test_replay_requires_a_fresh_capture_workspace(self):
        from inference_platform.inf037b_setup_observations import capture_replay

        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory) / "already-used"
            work.mkdir()
            with self.assertRaisesRegex(IntegrityError, "observations:fresh_replay_workspace"):
                capture_replay(
                    binding=self.value["binding"],
                    sample=lambda: {"clock_id": "test", "boot_id": "host", "ms": [1, 1]},
                    work=work,
                )

    def test_replay_missing_schedule_changed_journal_clock_and_overrun_refuse(self):
        cases = (
            (lambda r: r.update(schema="wrong"), "observations:replay_schema"),
            (lambda r: r.update(session_id="wrong"), "observations:replay_binding"),
            (lambda r: r["start"].update(ms=[0, 0]), "observations:setup_origin"),
            (
                lambda r: r["recipe"][0]["waits_ms"].__setitem__(0, 599999),
                "observations:maximum_schedule",
            ),
            (lambda r: r.update(nonmutating=False), "observations:nonmutating"),
            (lambda r: r.update(journal_hex=""), "observations:replay_journal"),
            (lambda r: r["trace"].pop(), "observations:replay_trace"),
            (lambda r: r["samples"].pop(), "observations:replay_samples"),
            (lambda r: r["samples"][0].update(index=2), "observations:replay_sample_join"),
            (lambda r: r["samples"][0]["end"].update(boot_id="new"), "observations:clock_identity"),
            (lambda r: r["samples"][0]["end"].update(ms=[0, 0]), "observations:clock_order"),
        )
        for mutate, reason in cases:
            with self.subTest(reason=reason):
                self.refuse("replay", mutate, reason)

        # Preserve ordering so the allowance itself is the rejecting predicate.
        def slow(r):
            for sample in r["samples"]:
                sample["start"]["ms"] = [1000000, 1000000]
                sample["end"]["ms"] = [1780001, 1780001]
            for index, sample in enumerate(r["samples"]):
                sample["start"]["ms"] = [1000000 + index * 800000] * 2
                sample["end"]["ms"] = [1780001 + index * 800000] * 2
            r["end"]["ms"] = [6000000] * 2

        self.refuse("replay", slow, "allowance:attempt:range")

    def test_export_raw_bytes_margin_rate_and_real_resumable_copy(self):
        result = self.export()
        r = strict_json(self.value["export_raw"])
        size = sum(p["bytes"] for p in r["source"].values())
        self.assertEqual(result["transfer"]["raw_bytes"], size)
        self.assertEqual(result["transfer"]["maximum_archive_bytes"], size * 2)
        self.assertEqual(result["transfer"]["reconnect_ms"], 1000)
        self.assertEqual(result["observation_ms"], [3, 3])
        self.assertFalse(r["interrupted"]["complete"])
        self.assertTrue(r["resumed"]["complete"])
        CASES.append(
            {
                "case": "compact_real_archive_resume",
                "result": result,
                "source": r["source"],
                "sanitized": r["sanitized"],
                "scope": "adapter_contract_only_not_maximum_cardinality_or_live_timing",
            }
        )

    def test_export_missing_bytes_bad_proof_incomplete_readback_and_clock_refuse(self):
        for mutate, reason in (
            (lambda r: r.update(schema="wrong"), "observations:export_schema"),
            (lambda r: r.update(session_id="wrong"), "observations:export_binding"),
            (lambda r: r["start"].update(ms=[0, 0]), "observations:setup_origin"),
            (lambda r: r.update(reconnect_bound_ms=0), "observations:reconnect_capture_bound"),
            (lambda r: r["interrupted"].update(complete=True), "observations:interrupted"),
            (lambda r: r["resumed"].update(complete=False), "observations:resumed"),
            (lambda r: r["destination"].pop("registration.json"), "observations:transfer_readback"),
            (lambda r: r["end"].update(boot_id="changed"), "observations:clock_identity"),
        ):
            self.refuse("export", mutate, reason)
        for key, changed, reason in (
            ("subject", "wrong", "observations:fixture_subject"),
            ("pins", {}, "observations:fixture_pins"),
            ("schedule_ms", [1560000] * 3, "observations:fixture_schedule"),
            ("source_inventory_sha256", "f" * 64, "observations:fixture_source"),
        ):
            proof = strict_json(self.value["artifacts"]["proof/maximum-fixture.json"])
            proof[key] = changed
            with self.assertRaisesRegex(IntegrityError, reason):
                self.export(proof=proof)
        artifacts = copy.deepcopy(self.value["export_artifacts"])
        del artifacts["source/registration.json"]
        with self.assertRaisesRegex(IntegrityError, "observations:archive_artifact"):
            self.export(artifacts=artifacts)
        _, artifacts = self.copied_export_artifacts()
        registration = artifacts["source/registration.json"]
        registration.write_bytes(registration.read_bytes() + b" ")
        with self.assertRaisesRegex(IntegrityError, "observations:archive_bytes"):
            self.export(artifacts=artifacts)
        # A fully verified/read-back archive can still exceed the pinned raw
        # margin. Keep every hash/manifest/receipt valid to test that predicate.
        raw = strict_json(self.value["export_raw"])
        root, artifacts = self.copied_export_artifacts()
        padding_size = 2 * sum(p["bytes"] for p in raw["source"].values())
        for prefix in ("sanitized", "destination"):
            archive_root = root / prefix
            (archive_root / "events" / "padding.bin").write_bytes(b"x" * padding_size)
            raw[prefix] = self.rewrite_manifest(archive_root)
            for name in raw[prefix]:
                artifacts[prefix + "/" + name] = archive_root / name
        for receipt in (raw["interrupted"], raw["resumed"]):
            receipt["source_manifest_sha256"] = sha(
                (root / "sanitized" / "SHA256SUMS").read_bytes()
            )
        with self.assertRaisesRegex(IntegrityError, "observations:archive_margin"):
            self.export(raw=encode(raw), artifacts=artifacts)

    def test_export_reconnect_bound_is_pinned_by_sizing_proof(self):
        self.assertEqual(self.export()["transfer"]["reconnect_ms"], 1000)
        raw = strict_json(self.value["export_raw"])
        raw["reconnect_bound_ms"] = 1
        with self.assertRaisesRegex(IntegrityError, "observations:reconnect_capture_bound"):
            self.export(raw=encode(raw))

        path = self.value["lifecycle"]["transfer"]["sizing_proof"]["path"]
        proof = strict_json(self.value["artifacts"][path])
        del proof["reconnect_bound_ms"]
        with self.assertRaisesRegex(IntegrityError, "observations:reconnect_proof_bound_missing"):
            export_observations(
                self.value["export_raw"],
                binding=self.value["binding"],
                artifacts=self.value["export_artifacts"],
                maximum_fixture=strict_json(self.value["artifacts"]["proof/maximum-fixture.json"]),
                sizing_proof=proof,
            )

        raw = strict_json(self.value["export_raw"])
        start = raw["transfer_start"]["ms"][0]
        raw["reconnect_start"]["ms"] = [start, start]
        raw["end"]["ms"] = [start + 1001, start + 1001]
        with self.assertRaisesRegex(IntegrityError, "observations:reconnect_bound"):
            self.export(raw=encode(raw))

        proof["subject"] = "wrong"
        with self.assertRaisesRegex(IntegrityError, "observations:sizing_subject"):
            self.export(sizing_proof=proof)

        proof = strict_json(self.value["artifacts"][path])
        proof["pins"] = {}
        with self.assertRaisesRegex(IntegrityError, "observations:sizing_pins"):
            self.export(sizing_proof=proof)

        proof = strict_json(self.value["artifacts"][path])
        proof["reconnect_bound_ms"] = -1
        with self.assertRaisesRegex(IntegrityError, "observations:reconnect_proof_bound"):
            self.export(sizing_proof=proof)

    def test_setup_transfer_reconnect_bound_is_pinned_by_sizing_proof(self):
        value = copy.deepcopy(self.value)
        replay_end = strict_json(value["replay_raw"])["end"]
        export_end = strict_json(value["export_raw"])["end"]
        now = max(replay_end["ms"][1], export_end["ms"][1])
        command = object.__new__(SetupCommands)
        command.binding = value["binding"]
        command.sample = lambda: {
            "clock_id": export_end["clock_id"],
            "boot_id": export_end["boot_id"],
            "ms": [now, now],
        }

        result = command.lifecycle_input(value)
        self.assertEqual(result["transfer"]["reconnect_ms"], 1000)
        value["lifecycle"]["transfer"]["reconnect_ms"] = 1
        with self.assertRaisesRegex(IntegrityError, "observations:transfer_reconnect_bound"):
            command.lifecycle_input(value)

    def test_capture_export_guards_refuse_mutated_source_and_incomplete_resume(self):
        from inference_platform.inf037b_packet import sanitized_sources
        from inference_platform.inf037b_setup_observations import capture_export

        source_original = Path(self.value["export_artifacts"]["source/registration.json"]).parent

        def prepare(directory, *, mutate_source=False):
            source = directory / "source"
            shutil.copytree(source_original, source)
            sanitized = directory / "sanitized"
            destination = directory / "destination"
            clock = [1000]

            def sample():
                clock[0] += 1
                return {"clock_id": "capture-test", "boot_id": "host", "ms": [clock[0]] * 2}

            def sanitize(raw, output):
                archive, _ = sanitized_sources(raw, output, key=b"capture-test-key-" * 3)
                archive.seal()
                if mutate_source:
                    path = raw / "registration.json"
                    path.write_bytes(path.read_bytes() + b" ")

            return source, sanitized, destination, sample, sanitize

        with tempfile.TemporaryDirectory(prefix="inf037b-source-mutation-") as directory:
            source, sanitized, destination, sample, sanitize = prepare(
                Path(directory), mutate_source=True
            )
            with self.assertRaisesRegex(IntegrityError, "observations:source_unchanged"):
                capture_export(
                    binding=self.value["binding"],
                    source=source,
                    sanitized=sanitized,
                    destination=destination,
                    sanitize=sanitize,
                    sample=sample,
                    reconnect_ms=1000,
                )

        with tempfile.TemporaryDirectory(prefix="inf037b-resume-cut-") as directory:
            source, sanitized, destination, sample, sanitize = prepare(Path(directory))
            with patch(
                "inference_platform.inf037b_setup_observations.export_archive",
                return_value={"complete": True},
            ):
                with self.assertRaisesRegex(IntegrityError, "observations:transfer_resume"):
                    capture_export(
                        binding=self.value["binding"],
                        source=source,
                        sanitized=sanitized,
                        destination=destination,
                        sanitize=sanitize,
                        sample=sample,
                        reconnect_ms=1000,
                    )

    def test_export_manifest_integrity_sanitizer_and_transfer_guards(self):
        root, artifacts = self.copied_export_artifacts()

        artifacts["source/attempts.jsonl"] = {
            "path": str(artifacts["source/attempts.jsonl"]),
            "bytes": 1,
        }
        with self.assertRaisesRegex(IntegrityError, "observations:archive_manifest"):
            self.export(artifacts=artifacts)

        _, artifacts = self.copied_export_artifacts()
        path = artifacts["source/attempts.jsonl"]
        from inference_platform.inf037b_setup_observations import file_facts

        facts = file_facts(path)
        artifacts["source/attempts.jsonl"] = {
            "path": str(path),
            "bytes": facts["bytes"] + 1,
            "sha256": facts["sha256"],
        }
        with self.assertRaisesRegex(IntegrityError, "observations:archive_manifest"):
            self.export(artifacts=artifacts)

        artifacts = self.value["export_artifacts"].copy()
        artifacts["source/attempts.jsonl"] = object()
        with self.assertRaisesRegex(IntegrityError, "observations:archive_path"):
            self.export(artifacts=artifacts)

        _, artifacts = self.copied_export_artifacts()
        alternate = root / "alternate-sanitized"
        shutil.copytree(root / "sanitized", alternate)
        artifacts["sanitized/registration.json"] = alternate / "registration.json"
        with self.assertRaisesRegex(IntegrityError, "observations:archive_path"):
            self.export(artifacts=artifacts)

        _, artifacts = self.copied_export_artifacts()
        with patch(
            "inference_platform.inf037b_setup_observations.verify_archive",
            return_value={"segments": {"raw/a.jsonl": {"integrity_errors": [{"reason": "bad"}]}}},
        ):
            with self.assertRaisesRegex(IntegrityError, "observations:archive_integrity"):
                self.export(artifacts=artifacts)

        for reason, change_provenance, label_value in (
            ("observations:sanitized_label", None, False),
            ("observations:sanitizer_source", "source", None),
            ("observations:sanitizer_complete", "complete", None),
        ):
            value = strict_json(self.value["export_raw"])
            copied_root, copied = self.copied_export_artifacts()
            for prefix in ("sanitized", "destination"):
                if label_value is not None:
                    registration = strict_json(
                        (copied_root / prefix / "registration.json").read_bytes()
                    )
                    registration["sanitized"] = label_value
                    (copied_root / prefix / "registration.json").write_bytes(encode(registration))
                if change_provenance:
                    receipt_path = copied_root / prefix / "source-integrity.receipt.json"
                    provenance = strict_json(receipt_path.read_bytes())
                    if change_provenance == "source":
                        provenance["source_manifest_sha256"] = "f" * 64
                    else:
                        provenance["segments"] = {"raw/controller.jsonl": {"integrity_errors": []}}
                    receipt_path.write_bytes(encode(provenance))
                self.rewrite_manifest(copied_root / prefix)
                self.sync_archive_prefix(value, copied, copied_root, prefix)
            with self.assertRaisesRegex(IntegrityError, reason):
                self.evaluate_export(encode(value), copied)

        value = strict_json(self.value["export_raw"])
        value["interrupted"]["source_manifest_sha256"] = "f" * 64
        with self.assertRaisesRegex(IntegrityError, "observations:transfer_source"):
            self.export(raw=encode(value))

        value = strict_json(self.value["export_raw"])
        value["end"] = copy.deepcopy(value["transfer_start"])
        value["reconnect_start"] = copy.deepcopy(value["transfer_start"])
        with self.assertRaisesRegex(IntegrityError, "observations:transfer_duration"):
            self.export(raw=encode(value))

        value = strict_json(self.value["export_raw"])
        far_future = value["transfer_start"]["ms"][0] + 10**15
        value["end"]["ms"] = [far_future, far_future]
        value["reconnect_start"]["ms"] = [far_future - 1, far_future - 1]
        with self.assertRaisesRegex(IntegrityError, "observations:transfer_rate"):
            self.export(raw=encode(value))

    def test_manifest_name_cannot_alias_another_file_in_the_same_archive_root(self):
        _, artifacts = self.copied_export_artifacts()
        declared = Path(artifacts["source/attempts.jsonl"])
        alias = declared.with_name("alias-attempts.jsonl")
        self.assertEqual(alias.parent, declared.parent)
        shutil.copyfile(declared, alias)
        artifacts["source/attempts.jsonl"] = alias

        with self.assertRaisesRegex(IntegrityError, "observations:archive_path"):
            self.export(artifacts=artifacts)

    def test_export_empty_declared_archive_refuses_with_named_inventory_reason(self):
        raw = strict_json(self.value["export_raw"])
        raw["source"] = {}
        with self.assertRaisesRegex(IntegrityError, "observations:archive_inventory"):
            self.evaluate_export(encode(raw), self.value["export_artifacts"])

    def test_commands_capture_derive_resolve_and_require_both_raw_inputs(self):
        command = setup_tests.SetupTests().prepare(copy.deepcopy(self.value))
        state = command.store.state
        phases = state["preparation"]["data"]["lifecycle"]["phases"]
        self.assertEqual(phases["attempt"]["observations_ms"], [[1, 1]] * 3)
        self.assertEqual(phases["reset"]["observations_ms"], [[1, 1]] * 2)
        self.assertEqual(phases["export"]["observations_ms"], [[3, 3]])
        for key in ("replay", "export_probe", "export_archives"):
            self.assertIn("capture", state[key])
        archive_manifest = state["export_archives"]["capture"]["artifacts"]
        self.assertTrue(archive_manifest)
        for item in archive_manifest.values():
            self.assertEqual(set(item), {"path", "bytes", "sha256"})
            self.assertTrue(Path(item["path"]).is_file())
        self.assertFalse(state["resolution"]["result"]["paid_ready"])
        command = object.__new__(SetupCommands)
        with self.assertRaisesRegex(IntegrityError, "setup:replay_raw_required"):
            command.lifecycle_input({})
        with self.assertRaisesRegex(IntegrityError, "setup:export_raw_required"):
            command.lifecycle_input({"replay_raw": b"{}"})
        command.binding = self.value["binding"]
        command.sample = lambda: {"clock_id": "measurement", "boot_id": "host", "ms": [513000] * 2}
        for mode, reason in (
            ("missing", "setup:maximum_fixture_artifact"),
            ("hash", "setup:maximum_fixture_hash"),
            ("future", "setup:observations_future_source"),
            ("clock", "setup:observations_clock"),
        ):
            value = copy.deepcopy(self.value)
            if mode == "missing":
                del value["artifacts"]["proof/maximum-fixture.json"]
            elif mode == "hash":
                value["artifacts"]["proof/maximum-fixture.json"] += b" "
            else:
                for key in ("replay_raw", "export_raw"):
                    raw = strict_json(value[key])

                    def change(obj, mode=mode):
                        if isinstance(obj, dict):
                            if {"clock_id", "boot_id", "ms"} <= obj.keys():
                                if mode == "clock":
                                    obj["boot_id"] = "foreign-host"
                                else:
                                    obj["ms"] = [v + 1000000 for v in obj["ms"]]
                            for item in obj.values():
                                change(item)
                        elif isinstance(obj, list):
                            for item in obj:
                                change(item)

                    change(raw)
                    value[key] = encode(raw)
            with self.subTest(mode=mode), self.assertRaisesRegex(IntegrityError, reason):
                command.lifecycle_input(value)

    @unittest.skipUnless(os.name == "posix", "archive persistence uses POSIX file semantics")
    def test_raw_captures_precede_archive_persistence_and_survive_refusals(self):
        expected_captures = {
            "preparation": "raw",
            "fitness": "fitness_raw",
            "replay": "replay_raw",
            "export_probe": "export_raw",
        }
        cases = ("missing", "symlink", "copy_oserror")
        for failure in cases:
            with self.subTest(failure=failure):
                _, export_artifacts = self.copied_export_artifacts()
                key = "source/attempts.jsonl"
                path = Path(export_artifacts[key])
                if failure == "missing":
                    path.unlink()
                    expected_reason = "setup:archive_source_file"
                elif failure == "symlink":
                    target = path.with_name("registration.json")
                    path.unlink()
                    path.symlink_to(target)
                    expected_reason = "setup:archive_source_file"
                else:
                    expected_reason = "setup:archive_persist_io"

                collected = copy.deepcopy(self.value)
                collected["raw"] = encode(collected["bundle"])
                collected["export_artifacts"] = export_artifacts
                store = setup_tests.MemoryStore()
                command = setup_tests.FixtureSetupCommands(
                    store=store,
                    binding=collected["binding"],
                    collect=lambda *_, collected=collected: collected,
                    inventory=None,
                    scope=setup_tests.scope(),
                    sample=lambda: {
                        "clock_id": "measurement",
                        "boot_id": "host",
                        "ms": [513000, 513000],
                    },
                )
                persist = command._persist_export_artifacts

                def assert_captures_then_persist(
                    artifacts, *, store=store, persist=persist, expected_captures=expected_captures
                ):
                    state_before_persist = store.read()
                    for operation in expected_captures:
                        self.assertIn("capture", state_before_persist.get(operation, {}))
                    return persist(artifacts)

                command._persist_export_artifacts = assert_captures_then_persist
                if failure == "copy_oserror":
                    original_open = Path.open
                    opens = 0

                    def fail_during_copy(
                        source, *args, target=path, path_open=original_open, **kwargs
                    ):
                        nonlocal opens
                        if source == target and args == ("rb",):
                            opens += 1
                            if opens == 2:
                                raise OSError("injected archive copy failure")
                        return path_open(source, *args, **kwargs)

                    with patch.object(Path, "open", fail_during_copy):
                        with self.assertRaisesRegex(IntegrityError, expected_reason):
                            command(
                                "preparation",
                                1801000,
                                {"measurement_deadline_ms": 1801000},
                            )
                    self.assertEqual(opens, 2)
                else:
                    with self.assertRaisesRegex(IntegrityError, expected_reason):
                        command(
                            "preparation",
                            1801000,
                            {"measurement_deadline_ms": 1801000},
                        )

                state = store.read()
                for operation, raw_key in expected_captures.items():
                    self.assertEqual(
                        bytes.fromhex(state[operation]["capture"]["raw_hex"]),
                        collected[raw_key],
                    )
                self.assertNotIn("capture", state.get("export_archives", {}))

    def test_preparation_observation_includes_raw_derivation_and_validation(self):
        from test_inf037b_terminal import MemoryStore

        command = setup_tests.SetupTests().prepare(copy.deepcopy(self.value))
        command.store = MemoryStore()
        now = [513000]
        command.sample = lambda: {"clock_id": "measurement", "boot_id": "host", "ms": [now[0]] * 2}
        original = command.lifecycle_input

        def timed(collected):
            row = original(collected)
            now[0] += 10
            return row

        command.lifecycle_input = timed
        context = {"measurement_deadline_ms": 1801000}
        command("creation", 1801000, context)
        command("preparation", 1801000, context)
        self.assertEqual(
            command.store.state["preparation"]["data"]["lifecycle"]["phases"]["preparation"][
                "observations_ms"
            ],
            [[512010, 512010]],
        )

    def test_setup_sizing_artifact_and_byte_proof_guards_refuse_by_named_reason(self):
        path = self.value["lifecycle"]["transfer"]["sizing_proof"]["path"]
        cases = (
            (
                "setup:sizing_artifact",
                lambda value: value["artifacts"].pop(path),
                "lifecycle_input",
            ),
            (
                "setup:sizing_hash",
                lambda value: value["artifacts"].__setitem__(path, value["artifacts"][path] + b" "),
                "lifecycle_input",
            ),
            (
                "setup:sizing_bytes",
                lambda value: self.set_sizing(value, path, -1),
                "__call__",
            ),
            (
                "setup:sizing_raw_bytes",
                lambda value: self.set_sizing(
                    value, path, 1 + strict_json(value["artifacts"][path])["raw_bytes"]
                ),
                "__call__",
            ),
        )
        for reason, change, function in cases:
            if not mutation_case(function, reason):
                continue
            value = copy.deepcopy(self.value)
            change(value)
            with self.assertRaisesRegex(IntegrityError, reason):
                setup_tests.SetupTests().prepare(value)

    @staticmethod
    def set_sizing(value, path, raw_bytes):
        sizing = strict_json(value["artifacts"][path])
        sizing["raw_bytes"] = raw_bytes
        value["artifacts"][path] = encode(sizing)
        value["lifecycle"]["transfer"]["sizing_proof"]["sha256"] = sha(encode(sizing))


@unittest.skipUnless(os.name == "posix", "RSS growth assertion uses POSIX resource units")
class ExportMemoryTests(unittest.TestCase):
    def test_archive_growth_keeps_peak_rss_and_setup_state_bounded(self):
        root = Path(__file__).resolve().parents[2]
        script = root / "scripts" / "check_inf037b_export_memory.py"
        with tempfile.TemporaryDirectory(prefix="inf037b-memory-receipt-") as directory:
            output = Path(directory) / "receipt.json"
            subprocess.run(
                [sys.executable, str(script), "--output", str(output)],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            )
            receipt = json.loads(output.read_text(encoding="utf-8"))
        self.assertTrue(receipt["passed"], json.dumps(receipt, sort_keys=True))
        CASES.append({"case": "scaled_export_rss_and_state", **receipt})
