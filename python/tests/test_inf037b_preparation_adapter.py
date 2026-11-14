"""Exact-byte/time admission and real filesystem/concurrent adapter controls."""

import copy
import os
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from test_inf037b_preparation import BINDING, admitted, point, staged

from inference_platform.inf037b_archive import Archive, IntegrityError, encode, sha, strict_json
from inference_platform.inf037b_contract import REGISTRATION_ID
from inference_platform.inf037b_durable_ports import DurableStore
from inference_platform.inf037b_packet import sanitized_sources
from inference_platform.inf037b_preparation import ConcurrentPreparation, PreparationFork
from inference_platform.inf037b_setup import SetupCommands
from inference_platform.inf037b_setup_observations import capture_export, inventory


def row5_stage_stub(name, stop_ns):
    return [
        {"request_id": f"known-{name}-{gateway}", "snapshot_id": name, "gateway_uid": gateway}
        for gateway in ("gateway0", "gateway1")
    ]


def known_requests():
    from inference_platform.inf037b_row5_sequence import STAGES

    return [request for name in STAGES for request in row5_stage_stub(name, 0)]


def row5_stub():
    requests = [
        {
            "request_id": f"control-{index:02d}",
            "snapshot_id": name,
            "gateway_uid": gateway,
        }
        for index, (name, gateway) in enumerate(
            (name, gateway)
            for name in ("unknown", "expired", "post_outage_known2")
            for gateway in ("gateway0", "gateway1")
        )
    ]
    return {
        "fitness_raw": encode({"schema": "inf037b-setup-v1", **BINDING, "raw": []}),
        "row5_control_requests": requests,
        "row5_evidence": {
            "schema": "inf037b-row5-evidence-v1",
            "configuration_sha256": BINDING["pins"].get("configuration"),
        },
    }


class EvidenceTests(unittest.TestCase):
    def validate(self, data):
        command = object.__new__(SetupCommands)
        command.binding = BINDING
        command.sample = lambda: point(1_800_010)
        creation = {"staging": staged(), "ready": point(10), "ready_ms": 10}
        return command.validate_preparation(data, creation)

    def test_equality_exact_bytes_and_each_hash_mismatch(self):
        data = admitted()
        self.assertTrue(self.validate(data)["complete"])
        for branch, key in (("export", "export_raw"), ("gpu", "fitness_raw")):
            with self.subTest(branch=branch):
                changed = copy.deepcopy(data)
                # Semantically identical JSON is still different raw evidence.
                changed[key] = b" \n" + changed[key]
                with self.assertRaisesRegex(IntegrityError, branch + "_raw_hash"):
                    self.validate(changed)
                changed["preparation_receipt"]["branches"][branch]["sha256"] = sha(changed[key])
                self.assertTrue(self.validate(changed)["complete"])

    def test_each_evidence_endpoint_refuses_one_tick_outside_its_branch(self):
        for branch, endpoint, at in (
            ("export", "start", 29),
            ("export", "start", 9),  # before original P as well as fork
            ("export", "end", 1_740_031),
            ("gpu", "start", 29),
            ("gpu", "end", 1_740_031),
        ):
            with self.subTest(branch=branch, endpoint=endpoint, at=at):
                data = admitted()
                key = "export_raw" if branch == "export" else "fitness_raw"
                value = strict_json(data[key])
                if branch == "export":
                    value[endpoint] = point(at)
                else:
                    row = value["raw"][0 if endpoint == "start" else -1]
                    row["source_time"]["value"] = at
                data[key] = encode(value)
                data["preparation_receipt"]["branches"][branch]["sha256"] = sha(data[key])
                with self.assertRaisesRegex(IntegrityError, branch + "_evidence_" + endpoint):
                    self.validate(data)

    def test_gpu_collection_brackets_cannot_hide_behind_in_range_source_times(self):
        for endpoint, field, at in (
            ("start", "capture_start_mono_ns", 29_999_999),
            ("end", "capture_end_mono_ns", 1_740_030_000_001),
        ):
            data = admitted()
            raw = strict_json(data["fitness_raw"])
            raw["raw"][0 if endpoint == "start" else -1][field] = at
            data["fitness_raw"] = encode(raw)
            data["preparation_receipt"]["branches"]["gpu"]["sha256"] = sha(data["fitness_raw"])
            with self.assertRaisesRegex(IntegrityError, "gpu_evidence_" + endpoint):
                self.validate(data)

    def test_clock_mapping_rows_are_collected_after_gpu_branch_start(self):
        from test_inf037b_collectors import Records

        data = admitted()
        value = strict_json(data["fitness_raw"])
        row = Records().row(
            "clocks",
            "mapping",
            30,
            clock_id="remote",
            boot_id="remote-boot",
            local_mono_ms=30,
            local_wall_ms=30,
            remote_ms=30,
            send_ms=30,
            receive_ms=30,
        )
        row.update(
            session_id=BINDING["session_id"], attempt_id="setup", stage=[], collector_boot_id="boot"
        )
        value["raw"].append(row)
        for start in (30_000_000, 29_999_999):
            row["capture_start_mono_ns"] = start
            data["fitness_raw"] = encode(value)
            data["preparation_receipt"]["branches"]["gpu"]["sha256"] = sha(data["fitness_raw"])
            if start == 30_000_000:
                self.assertTrue(self.validate(data)["complete"])
            else:
                with self.assertRaisesRegex(IntegrityError, "gpu_evidence_start"):
                    self.validate(data)

    def test_same_clock_boot_and_order_are_required(self):
        for endpoint in ("start", "end"):
            for field in ("clock_id", "boot_id"):
                data = admitted()
                raw = strict_json(data["export_raw"])
                raw[endpoint][field] = "other"
                data["export_raw"] = encode(raw)
                data["preparation_receipt"]["branches"]["export"]["sha256"] = sha(
                    data["export_raw"]
                )
                with self.subTest(endpoint=endpoint, field=field):
                    with self.assertRaisesRegex(IntegrityError, "preparation:clock"):
                        self.validate(data)
        data = admitted()
        raw = strict_json(data["fitness_raw"])
        for row in raw["raw"]:
            row["collector_boot_id"] = "other"
        data["fitness_raw"] = encode(raw)
        data["preparation_receipt"]["branches"]["gpu"]["sha256"] = sha(data["fitness_raw"])
        with self.assertRaisesRegex(IntegrityError, "preparation:clock"):
            self.validate(data)
        data = admitted()
        raw = strict_json(data["export_raw"])
        raw["start"], raw["end"] = raw["end"], raw["start"]
        data["export_raw"] = encode(raw)
        data["preparation_receipt"]["branches"]["export"]["sha256"] = sha(data["export_raw"])
        with self.assertRaisesRegex(IntegrityError, "preparation:order"):
            self.validate(data)

    def test_received_signal_hook_equality_late_and_wrong_clock(self):
        data = admitted()
        data["pre_export_received"] = point(30)
        self.assertTrue(self.validate(data)["complete"])
        data["pre_export_received"] = point(31)
        with self.assertRaisesRegex(IntegrityError, "capture_after_signal"):
            self.validate(data)
        for field in ("clock_id", "boot_id"):
            data["pre_export_received"] = {**point(30), field: "other"}
            with self.assertRaisesRegex(IntegrityError, "preparation:clock"):
                self.validate(data)

    def test_nonzero_width_conservative_endpoints(self):
        for case, reason in (
            ("start", "export_evidence_start"),
            ("end", "export_evidence_end"),
            ("signal_upper", "capture_after_signal"),
            ("capture_lower", "capture_after_signal"),
        ):
            data = admitted()
            raw = strict_json(data["export_raw"])
            if case == "start":
                raw["start"]["ms"] = [29, 31]
            elif case == "end":
                raw["end"]["ms"] = [1_740_029, 1_740_031]
            elif case == "signal_upper":
                data["pre_export_received"] = {**point(30), "ms": [29, 31]}
            else:
                raw["start"]["ms"] = [30, 32]
                data["pre_export_received"] = point(31)
            data["export_raw"] = encode(raw)
            data["preparation_receipt"]["branches"]["export"]["sha256"] = sha(data["export_raw"])
            with self.subTest(case=case), self.assertRaisesRegex(IntegrityError, reason):
                self.validate(data)


@unittest.skipUnless(os.name == "posix", "requires real Linux file/directory durability")
class AdapterTests(unittest.TestCase):
    def test_joined_manifest_stat_guards_and_raw_references(self):
        from inference_platform.inf037b_setup import persist_archive_artifacts
        from inference_platform.inf037b_setup_observations import file_facts

        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "raw"
            source.write_bytes(b"retained archive object")
            store = DurableStore(root / "setup", {}, initialize=True)
            manifest = persist_archive_artifacts(store, {"source/raw/test.jsonl": source})
            command = object.__new__(SetupCommands)
            command.store = store
            command.collect = object.__new__(ConcurrentPreparation)
            branch = {
                "artifacts": manifest,
                "archive_verified": True,
                "raw_hex": b"fitness".hex(),
                "sha256": sha(b"fitness"),
            }

            def save(record):
                with store.lock():
                    store.write(
                        {
                            "preparation_fork": {
                                "export": {k: v for k, v in record.items() if k != "raw_hex"},
                                "gpu": record,
                            }
                        }
                    )

            save(branch)
            with patch(
                "inference_platform.inf037b_setup_observations.file_facts", wraps=file_facts
            ) as facts:
                self.assertEqual(command._persist_export_artifacts(manifest), manifest)
                self.assertEqual(facts.call_count, 0)
            command._capture("fitness", b"fitness", reference=("preparation_fork", "gpu"))
            self.assertEqual(encode(store.read()).count(b"6669746e657373"), 1)
            with self.assertRaisesRegex(IntegrityError, "raw_reference_hash"):
                command._capture("fitness", b"different", reference=("preparation_fork", "gpu"))
            for case, reason in (
                ("verified", "branch_verified"),
                ("manifest", "branch_manifest"),
                ("outside", "under_objects"),
                ("size", "object_size"),
                ("missing", "object_file"),
                ("symlink", "object_symlink"),
                ("resolved", "object_resolved"),
                ("directory", "archive_objects"),
            ):
                changed = copy.deepcopy(branch)
                supplied = copy.deepcopy(manifest)
                facts = supplied["source/raw/test.jsonl"]
                target = Path(facts["path"])
                if case == "verified":
                    changed["archive_verified"] = False
                elif case == "manifest":
                    facts["sha256"] = "b" * 64
                elif case == "outside":
                    facts["path"] = str(source)
                elif case == "size":
                    facts["bytes"] += 1
                elif case == "missing":
                    facts["path"] += ".missing"
                elif case == "symlink":
                    link = target.with_name("link.jsonl")
                    link.symlink_to(target)
                    facts["path"] = str(link)
                elif case == "resolved":
                    facts["path"] = str(target.parent / ".." / "raw" / target.name)
                else:
                    base = store.path.parent / (store.path.name + ".objects")
                    base.rename(root / "held-objects")
                if case not in {"verified", "manifest"}:
                    changed["artifacts"] = copy.deepcopy(supplied)
                save(changed)
                with self.subTest(case=case), self.assertRaisesRegex(IntegrityError, reason):
                    command._persist_export_artifacts(supplied)
                if case == "directory":
                    (root / "held-objects").rename(base)

    def test_pair_binding_creation_and_branch_input_failures_refuse_without_retry(self):
        scope = SimpleNamespace(session_id=BINDING["session_id"], t0_ms=0)
        with self.assertRaisesRegex(IntegrityError, "both_preparation_ports"):
            SetupCommands(
                store=None,
                binding=BINDING,
                collect=None,
                inventory=None,
                scope=scope,
                sample=None,
                capture=lambda stop: None,
            )
        for case, reason in (
            ("binding", "collect_binding"),
            ("creation", "creation_required"),
            ("capture", "capture_bytes"),
            ("gpu", "gpu_bytes"),
            ("ownership", "branch_ownership"),
        ):
            with self.subTest(case=case), TemporaryDirectory() as directory:
                state = {
                    "binding": BINDING,
                    "creation": {"result": True, "data": {"ready": point(10)}},
                }
                if case == "binding":
                    state["binding"] = {}
                elif case == "creation":
                    state["creation"].pop("result")
                store = DurableStore(Path(directory) / "store", state, initialize=True)
                gpu = {"fitness_raw": b"raw", "row5_known_requests": known_requests()}
                if case == "gpu":
                    gpu = None
                elif case == "ownership":
                    gpu["export_raw"] = b"unowned"
                adapter = ConcurrentPreparation(
                    store=store,
                    binding=BINDING,
                    sample=lambda: point(30),
                    capture=lambda stop, case=case: (False if case == "capture" else b"raw", {}),
                    gpu=lambda stop, row5_stage, gpu=gpu: gpu,
                    creation=None,
                    row5_stage=row5_stage_stub,
                    row5_control=lambda stop, value: row5_stub(),
                )
                shutdown = ThreadPoolExecutor.shutdown
                # This in-process type-refusal test returns from the exit seam.
                # Settle its short workers before reopening their shared store.
                with (
                    patch("inference_platform.inf037b_preparation.os._exit", lambda code: None),
                    patch.object(
                        ThreadPoolExecutor,
                        "shutdown",
                        lambda pool, shutdown=shutdown, **kwargs: shutdown(
                            pool, wait=True, cancel_futures=True
                        ),
                    ),
                ):
                    with self.assertRaisesRegex(IntegrityError, reason):
                        adapter("preparation", 1000)
                if case not in ("binding", "creation"):
                    saved = store.read()["preparation_fork"]
                    self.assertIn(reason, saved["failure"]["reason"])
                    with self.assertRaisesRegex(IntegrityError, "interrupted_no_retry"):
                        adapter("preparation", 2000)

    def test_original_P_and_branch_cutoffs_are_passed_to_ports_and_persistence(self):
        stops, persisted = {}, []

        def port(name, stop):
            stops[name] = stop
            return b"raw"

        fork = PreparationFork(
            binding=BINDING,
            ready=point(10),
            sample=lambda: point(30),
            branches={name: lambda stop, name=name: port(name, stop) for name in ("export", "gpu")},
            persist=lambda name, value, stop: persisted.append((name, stop)) or True,
            exit_command=lambda code: None,
        )
        self.assertTrue(fork.run(9_000_000)["join_ack"])
        self.assertEqual(stops, {"export": 1_740_030, "gpu": 1_740_030})
        self.assertEqual(set(persisted[:2]), {("export", 1_740_030), ("gpu", 1_740_030)})
        self.assertEqual(persisted[-2:], [("join", 1_800_010), ("complete", 1_800_010)])

    def test_real_capture_and_gpu_feed_setup_and_durable_one_shot_join(self):
        from test_inf037b_collectors import Records

        with TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            Archive.create(
                source, {"registration_id": REGISTRATION_ID, "pins": BINDING["pins"]}
            ).seal()
            manifest = inventory(source)
            ready = point(int(time.monotonic() * 1000))
            staging = staged()
            staging.update(
                expected_inventory=manifest,
                actual_inventory=manifest,
                manifest_sha256=sha(encode(manifest)),
            )
            creation = {"ready": ready, "ready_ms": ready["ms"][0], "staging": staging}
            store = DurableStore(
                root / "setup",
                {"binding": BINDING, "creation": {"data": creation, "result": True}},
                initialize=True,
            )
            barrier, stops = threading.Barrier(2), {}

            def sample():
                return point(int(time.monotonic() * 1000))

            def sanitize(raw, target):
                output, _ = sanitized_sources(raw, target, key=b"test-preparation-adapter-key" * 2)
                output.seal()

            def capture(stop):
                stops["export"] = stop
                barrier.wait(timeout=2)
                return capture_export(
                    binding=BINDING,
                    source=source,
                    sanitized=root / "safe",
                    destination=root / "copy",
                    sanitize=sanitize,
                    sample=sample,
                    reconnect_ms=1000,
                )

            def gpu(stop, row5_stage):
                stops["gpu"] = stop
                barrier.wait(timeout=2)
                # The shorter capture must not cause an early join/refusal.
                time.sleep(0.03)
                at = sample()["ms"][0]
                row = Records().row("controller", "precondition", at, name="fitness", value=True)
                row.update(
                    session_id=BINDING["session_id"],
                    attempt_id="setup",
                    stage=[],
                    collector_boot_id="boot",
                )
                raw = encode({"schema": "inf037b-setup-v1", **BINDING, "raw": [row]})
                return {
                    "fitness_raw": b" \n" + raw,
                    "raw": b"startup",
                    "artifacts": {},
                    "row5_known_requests": known_requests(),
                }

            def row5_control(stop, value):
                self.assertLessEqual(sample()["ms"][1] * 1_000_000, stop)
                return row5_stub()

            creation_calls = []
            command = SetupCommands(
                store=store,
                binding=BINDING,
                sample=sample,
                capture=capture,
                gpu=gpu,
                row5_stage=row5_stage_stub,
                row5_control=row5_control,
                collect=lambda operation, stop: (
                    creation_calls.append((operation, stop)) or b"creation"
                ),
                inventory=None,
                scope=SimpleNamespace(session_id=BINDING["session_id"], t0_ms=0),
            )
            adapter = command.collect
            self.assertIsInstance(adapter, ConcurrentPreparation)
            stop = sample()["ms"][0] + 10000
            self.assertEqual(adapter("creation", stop), b"creation")
            self.assertEqual(creation_calls, [("creation", stop)])
            data = adapter("preparation", stop)
            merged = strict_json(data["fitness_raw"])
            self.assertEqual(len(merged["row5_control_requests"]), 16)
            self.assertEqual(merged["row5_evidence"]["schema"], "inf037b-row5-evidence-v1")
            self.assertTrue(command.validate_preparation(data, creation)["complete"])
            self.assertEqual(stops, {"export": stop, "gpu": stop})
            saved = DurableStore(root / "setup", {}).read()["preparation_fork"]
            self.assertEqual(saved["ready"], ready)
            self.assertEqual(saved["stop_ms"], stop)
            for branch, key in (("export", "export_raw"), ("gpu", "fitness_raw")):
                self.assertEqual(bytes.fromhex(saved[branch]["raw_hex"]), data[key])
                self.assertEqual(saved["complete"]["branches"][branch]["sha256"], sha(data[key]))
            for key, facts in data["export_artifacts"].items():
                self.assertEqual(facts, saved["export"]["artifacts"][key])
                self.assertTrue(Path(facts["path"]).is_file())
            self.assertTrue(saved["complete"]["join_ack"])
            self.assertTrue(data["export_artifacts"])
            with self.assertRaisesRegex(IntegrityError, "interrupted_no_retry"):
                adapter("preparation", stop + 1)
            with self.assertRaisesRegex(IntegrityError, "collect_operation"):
                adapter("resolution", stop)

    def test_absolute_wait_cutoff_and_failure_record_ack(self):
        # Use a short absolute cutoff; no retry or rebased P is allowed.
        now = int(time.monotonic() * 1000)
        ready = point(now)
        events, exits = [], []

        def port(stop):
            time.sleep(0.04)
            return b"bytes"

        fork = PreparationFork(
            binding=BINDING,
            ready=ready,
            sample=lambda: point(int(time.monotonic() * 1000)),
            branches={"export": port, "gpu": port},
            persist=lambda name, value, stop: events.append((name, value, stop)) or True,
            exit_command=exits.append,
        )
        with self.assertRaisesRegex(TimeoutError, "absolute_cutoff"):
            fork.run(now + 5)
        self.assertEqual(exits, [1])
        self.assertEqual(events[0][0], "failure")
        self.assertEqual(events[0][1]["cutoff_ms"], now + 5)
        self.assertEqual(events[0][1]["ready"], ready)
        # Let the test-only workers settle; production exits instead.
        time.sleep(0.05)
        events.clear()
        fork.ready = point(10)
        fork.sample = lambda: point(1_800_011)
        with self.assertRaisesRegex(TimeoutError, "absolute_cutoff"):
            fork.run(9_000_000)
        self.assertEqual(events[0][2], 1_800_010)
        self.assertEqual(events[0][1]["cutoff_ms"], 1_800_010)
        self.assertEqual(events[0][1]["ready"], point(10))
        time.sleep(0.05)
        fork.branches = {"export": lambda stop: None, "gpu": lambda stop: None}
        fork.persist = lambda *args: False
        with self.assertRaisesRegex(IntegrityError, "failure_ack"):
            fork.run(now + 1000)
        self.assertEqual(exits, [1, 1, 1])


if __name__ == "__main__":
    unittest.main()
