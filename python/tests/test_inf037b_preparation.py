"""Amendment refusal boundaries on recorded clocks and real concurrent ports."""

import copy
import os
import sys
import threading
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from inference_platform.inf037b_archive import IntegrityError, encode, sha, strict_json
from inference_platform.inf037b_preparation import (
    PreparationFork,
    preparation_receipt,
    stage_fixture,
    staging_receipt,
)
from inference_platform.inf037b_setup import SetupCommands

BINDING = {"t0_ms": 0, "pins": {"source": "a" * 64}, "session_id": "fixture"}


def point(ms):
    return {"clock_id": "measurement", "boot_id": "boot", "ms": [ms, ms]}


def staged():
    inventory = {"raw/controller.jsonl": {"bytes": 7, "sha256": "a" * 64}}
    return {
        "binding": copy.deepcopy(BINDING),
        "copy": {"start": point(1), "end": point(5)},
        "hash": {"start": point(5), "end": point(10)},
        "verified": True,
        "expected_inventory": inventory,
        "actual_inventory": copy.deepcopy(inventory),
        "manifest_sha256": sha(encode(inventory)),
        "pins": copy.deepcopy(BINDING["pins"]),
    }


def joined():
    return {
        "binding": copy.deepcopy(BINDING),
        "ready": point(10),
        "fork": point(20),
        "branches": {
            name: {
                "start": point(30),
                "end": point(1_740_030),
                "success": True,
                "durable_ack": True,
                "sha256": "a" * 64,
            }
            for name in ("export", "gpu")
        },
        "join": point(1_800_010),
        "join_ack": True,
    }


def admitted():
    from test_inf037b_collectors import Records

    records, rows = Records(), []
    for at in (30, 1_740_030):
        row = records.row("controller", "precondition", at, name=str(at), value=True)
        row.update(
            session_id=BINDING["session_id"], attempt_id="setup", stage=[], collector_boot_id="boot"
        )
        rows.append(row)
    data = {
        "preparation_receipt": joined(),
        "export_raw": encode(
            {"source": staged()["expected_inventory"], "start": point(30), "end": point(1_740_030)}
        ),
        "fitness_raw": encode({"schema": "inf037b-setup-v1", **BINDING, "raw": rows}),
    }
    for name, key in (("export", "export_raw"), ("gpu", "fitness_raw")):
        data["preparation_receipt"]["branches"][name]["sha256"] = sha(data[key])
    return data


class PreparationTests(unittest.TestCase):
    def test_failed_staging_in_real_creation_closes_campaign_before_preparation(self):
        from inf037b_setup_fixture import creation_raw, fixture, inventory, scope
        from test_inf037b_terminal import MemoryStore

        from inference_platform.inf037b_archive import strict_json
        from inference_platform.inf037b_lifecycle import LifecycleDriver
        from inference_platform.inf037b_resolver import SessionDeadline

        value = fixture()
        binding = value["binding"]
        raw = strict_json(creation_raw(binding, 2000))
        raw["ready"] = {"clock_id": "measurement", "boot_id": "host", "ms": [2000, 2000]}
        raw["staging"] = staged()
        raw["staging"].update(binding=binding, pins=binding["pins"], verified=False)
        for phase in ("copy", "hash"):
            for endpoint in ("start", "end"):
                raw["staging"][phase][endpoint].update(clock_id="measurement", boot_id="host")
                raw["staging"][phase][endpoint]["ms"] = [
                    v + 1000 for v in raw["staging"][phase][endpoint]["ms"]
                ]
        port, _ = inventory(scope())
        store = MemoryStore()
        command = SetupCommands(
            store=store,
            binding=binding,
            collect=lambda *_: encode(raw),
            inventory=port,
            scope=scope(),
            sample=lambda: {"clock_id": "measurement", "boot_id": "host", "ms": [2100, 2100]},
        )
        calls = []

        def execute(operation, stop, context):
            calls.append(operation)
            if operation == "creation":
                return command(operation, stop, context)
            self.assertIn(operation, ("export", "cleanup"))
            return True

        with TemporaryDirectory() as directory:
            driver = LifecycleDriver(
                deadline=SessionDeadline(1000, 18_001_000, 1000),
                clock=lambda: 2100,
                execute=execute,
                attempts=Path(directory) / "attempts.jsonl",
            )
            result = driver.run()
        self.assertFalse(result["measurement_started"])
        self.assertIn("staging_verified", " ".join(result["refusals"]))
        self.assertEqual(calls, ["creation", "export", "cleanup"])
        self.assertNotIn("result", store.read()["creation"])
        self.assertIn("capture", store.read()["creation"])

    @unittest.skipUnless(os.name == "posix", "requires Linux directory fsync")
    def test_real_staging_copy_hash_and_mismatch_refusal(self):
        from inference_platform.inf037b_setup_observations import file_facts

        with TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            source.mkdir()
            (source / "raw").mkdir()
            (source / "raw/data").write_bytes(b"fixture")
            expected = {"raw/data": file_facts(source / "raw/data")}
            clock = iter(range(1, 50))
            kwargs = dict(
                source=source,
                expected_inventory=expected,
                binding=BINDING,
                sample=lambda: point(next(clock)),
            )
            receipt = stage_fixture(destination=Path(directory) / "staged", **kwargs)
            self.assertTrue(self.stage(receipt, ready=point(20))["verified"])
            with self.assertRaisesRegex(IntegrityError, "staging_fresh"):
                stage_fixture(destination=Path(directory) / "staged", **kwargs)
            (source / "raw/data").write_bytes(b"changed")
            with self.assertRaisesRegex(IntegrityError, "staging_readback"):
                stage_fixture(destination=Path(directory) / "bad", **kwargs)
            (source / "extra").write_bytes(b"unexpected")
            with self.assertRaisesRegex(IntegrityError, "staging_inventory"):
                stage_fixture(destination=Path(directory) / "extra", **kwargs)
            (source / "extra").unlink()
            (source / "link").symlink_to(source / "raw/data")
            with self.assertRaisesRegex(IntegrityError, "staging_symlink"):
                stage_fixture(destination=Path(directory) / "link", **kwargs)
            with patch("inference_platform.inf037b_preparation.os.name", "nt"):
                with self.assertRaisesRegex(IntegrityError, "staging_platform"):
                    stage_fixture(destination="unused", **kwargs)

    def stage(self, raw=None, ready=None):
        return staging_receipt(raw or staged(), binding=BINDING, ready=ready or point(10))

    def join(self, raw=None, completed=None):
        return preparation_receipt(
            raw or joined(),
            binding=BINDING,
            ready=point(10),
            completed=completed or point(1_800_010),
        )

    def test_separate_staging_durations_and_inclusive_P(self):
        result = self.stage()
        self.assertEqual(result["copy_ms"], [4, 4])
        self.assertEqual(result["hash_ms"], [5, 5])
        with self.assertRaisesRegex(IntegrityError, "clock_identity"):
            self.stage(ready={"clock_id": True, "boot_id": "boot", "ms": [10, 10]})
        for modify, reason in (
            (lambda r: r.update(verified=False), "staging_verified"),
            (
                lambda r: r["actual_inventory"]["raw/controller.jsonl"].update(sha256="b" * 64),
                "fixture_hashes",
            ),
            (lambda r: r.update(manifest_sha256="b" * 64), "fixture_manifest"),
            (lambda r: r.update(pins={}), "fixture_pins"),
            (lambda r: r.update(binding={}), "staging_binding"),
            (lambda r: r["hash"].update(end=point(11)), "order"),
            (lambda r: r["copy"].update(start=point(6)), "order"),
            (lambda r: r["copy"]["end"].update(boot_id="other"), "clock"),
            (lambda r: r["copy"]["end"].update(ms=[1, 102]), "uncertainty"),
            (lambda r: r.update(expected_inventory={}), "fixture_inventory"),
            (lambda r: r.update(expected_inventory={"": {}}), "fixture_path"),
            (
                lambda r: r["expected_inventory"]["raw/controller.jsonl"].update(bytes=True),
                "fixture_facts",
            ),
        ):
            raw = staged()
            modify(raw)
            with self.subTest(reason=reason), self.assertRaisesRegex(IntegrityError, reason):
                self.stage(raw)

    def test_fork_join_equality_one_tick_failures_and_unequal_branches(self):
        result = self.join()
        self.assertEqual(result["elapsed_ms"], 1_800_000)
        self.assertEqual(result["common_ms"], 60_000)
        raw = joined()
        raw["branches"]["gpu"]["end"] = point(500_030)
        self.assertTrue(self.join(raw)["complete"])
        cases = [
            (lambda r: r.update(binding={}), "binding"),
            (lambda r: r.update(ready=point(11)), "original_P"),
            (lambda r: r["branches"].pop("gpu"), "branches"),
            (lambda r: r.update(join_ack=False), "join_ack"),
            (lambda r: r.update(join=point(1_740_029)), "order"),
        ]
        for name in ("export", "gpu"):
            cases.extend(
                [
                    (
                        lambda r, n=name: r["branches"][n].update(end=point(1_740_031)),
                        "branch_bound",
                    ),
                    (lambda r, n=name: r["branches"][n].update(success=False), "branch_success"),
                    (lambda r, n=name: r["branches"][n].update(durable_ack=False), "branch_ack"),
                    (lambda r, n=name: r["branches"][n].update(sha256="bad"), "branch_hash"),
                ]
            )
        for modify, reason in cases:
            raw = joined()
            modify(raw)
            with self.subTest(reason=reason), self.assertRaisesRegex(IntegrityError, reason):
                self.join(raw)
        with self.assertRaisesRegex(IntegrityError, "shared_overhead"):
            self.join(completed=point(1_800_011))

    def test_independent_branch_cutoff_overlap_and_total_defences(self):
        raw = joined()
        for item in raw["branches"].values():
            item.update(start=point(60_011), end=point(1_800_011))
        raw["join"] = point(1_800_011)
        with self.assertRaisesRegex(IntegrityError, "branch_cutoff"):
            self.join(raw, completed=point(1_800_011))
        raw = joined()
        raw["branches"]["export"].update(start=point(30), end=point(40))
        raw["branches"]["gpu"].update(start=point(41), end=point(50))
        raw["join"] = point(60)
        with self.assertRaisesRegex(IntegrityError, "fork_overlap"):
            self.join(raw, completed=point(60))
        raw = joined()
        for item in raw["branches"].values():
            item["end"] = point(1_740_031)
        raw["join"] = point(1_800_011)
        # Isolate the total guard from otherwise overlapping branch/overhead gates.
        with patch("inference_platform.inf037b_preparation.PREPARATION_BRANCH_MS", 1_740_001):
            with self.assertRaisesRegex(IntegrityError, "total_bound"):
                self.join(raw, completed=point(1_800_011))

    def test_production_setup_requires_staging_and_fork_join(self):
        command = object.__new__(SetupCommands)
        command.binding = BINDING
        command.sample = lambda: point(1_800_010)
        with self.assertRaisesRegex(IntegrityError, "staging_required"):
            command.validate_staging({})
        creation = {"staging": staged(), "ready": point(10), "ready_ms": 10}
        self.assertTrue(command.validate_staging(creation)["verified"])
        with self.assertRaisesRegex(IntegrityError, "staging_P"):
            command.validate_staging({**creation, "ready_ms": 11})
        with self.assertRaisesRegex(IntegrityError, "fork_join_required"):
            command.validate_preparation({}, creation)
        data = admitted()
        self.assertTrue(command.validate_preparation(data, creation)["complete"])
        exported = strict_json(data["export_raw"])
        exported["source"] = {}
        data["export_raw"] = encode(exported)
        data["preparation_receipt"]["branches"]["export"]["sha256"] = sha(data["export_raw"])
        with self.assertRaisesRegex(IntegrityError, "staged_capture_inventory"):
            command.validate_preparation(data, creation)

    def test_real_ports_overlap_and_persist_before_join(self):
        barrier = threading.Barrier(2)
        origin = time.monotonic()

        def sample():
            return point(10 + int((time.monotonic() - origin) * 1000))

        events = []

        def port(stop):
            barrier.wait(timeout=2)
            time.sleep(0.02)
            return b'  {"success":true} \n'

        fork = PreparationFork(
            binding=BINDING,
            ready=point(10),
            sample=sample,
            branches=dict.fromkeys(("export", "gpu"), port),
            persist=lambda name, value, stop: events.append(name) or True,
            exit_command=lambda code: None,
        )
        self.assertTrue(fork.run(10_000)["join_ack"])
        self.assertEqual(set(events[:2]), {"export", "gpu"})
        self.assertEqual(events[-2:], ["join", "complete"])
        self.assertEqual(
            fork.run(10_000)["branches"]["export"]["sha256"],
            sha(port_bytes := b'  {"success":true} \n'),
        )
        self.assertNotEqual(sha(port_bytes), sha(encode(strict_json(port_bytes))))
        fork.persist = lambda name, *args: name != "complete"
        with self.assertRaisesRegex(IntegrityError, "complete_ack"):
            fork.run(10_000)
        fork.branches = dict.fromkeys(("export", "gpu"), lambda stop: {"success": False})
        with self.assertRaisesRegex(IntegrityError, "port_bytes"):
            fork.run(10_000)
        fork.branches = dict.fromkeys(("export", "gpu"), port)
        fork.persist = lambda name, *args: name == "failure"
        with self.assertRaisesRegex(IntegrityError, "persist_ack"):
            fork.run(10_000)
        fork.branches = {}
        with self.assertRaisesRegex(IntegrityError, "fork_ports"):
            fork.run(10_000)

    @unittest.skipUnless(os.name == "posix", "requires accepted Linux process-group fence")
    def test_failed_branch_is_durable_and_fenced_promptly_in_both_orders(self):
        from inference_platform.inf037b_durable_ports import DurableStore
        from inference_platform.inf037b_lifecycle import ProcessCalls, group_members

        def clock():
            return int(time.monotonic() * 1000)

        program = """
import time, threading, subprocess, sys, json
from types import SimpleNamespace
from inference_platform.inf037b_durable_ports import DurableStore
from inference_platform.inf037b_setup import SetupCommands
context=json.load(sys.stdin)
started=threading.Event()
def sample():
    n=int(time.monotonic()*1000)
    return {"clock_id":"clock","boot_id":"boot","ms":[n,n]}
ready=sample()
binding={"t0_ms":ready["ms"][0],"pins":{},"session_id":"fixture"}
store=DurableStore(sys.argv[1], {"binding":binding,
    "creation":{"result":True,"data":{"ready":ready}}}, initialize=True)
def failed(stop, *args):
    assert started.wait(2)
    time.sleep(.02)
    raise RuntimeError("failed " + sys.argv[2])
def sibling(stop, *args):
    subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    started.set()
    time.sleep(30)
branches={name: failed if name==sys.argv[2] else sibling for name in ("export","gpu")}
command=SetupCommands(store=store,binding=binding,collect=lambda op,stop:None,inventory=None,
 scope=SimpleNamespace(session_id="fixture",t0_ms=binding["t0_ms"]),sample=sample,
 capture=branches["export"],gpu=branches["gpu"],row5_stage=lambda name,stop:[],row5_control=lambda stop,value:{})
command("preparation",context["measurement_deadline_ms"],context)
"""
        for branch in ("export", "gpu"):
            with self.subTest(branch=branch), TemporaryDirectory() as directory:
                identities = []
                path = Path(directory) / "failure"
                calls = ProcessCalls(
                    {"preparation": [sys.executable, "-c", program, str(path), branch]}, clock
                )
                start = time.monotonic()
                stop = clock() + 15_000
                with self.assertRaisesRegex(IntegrityError, "lifecycle:process_exit"):
                    calls(
                        "preparation",
                        stop,
                        {"measurement_deadline_ms": stop},
                        spawned=identities.append,
                    )
                self.assertLess(time.monotonic() - start, 2)
                self.assertEqual(group_members(identities[0]["group"]), [])
                state = DurableStore(path, {}).read()
                refusal = state["preparation_fork"]["failure"]
                self.assertNotIn("result", state["preparation"])
                self.assertEqual(refusal["branch"], branch)
                self.assertEqual(refusal["reason"], "RuntimeError:failed " + branch)
                self.assertLess(refusal["observed"]["ms"][1], refusal["cutoff_ms"] - 10_000)
                self.assertEqual(refusal["cutoff_ms"], stop)
                self.assertEqual(refusal["ready"], state["creation"]["data"]["ready"])


if __name__ == "__main__":
    unittest.main()
