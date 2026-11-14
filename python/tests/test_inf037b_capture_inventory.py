"""Native file creation and envelope arithmetic; no Linux durability claim."""

import copy
import socketserver
import subprocess
import sys
import threading
import time
import unittest
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from inference_platform import inf037b_capture_inventory as inventory
from inference_platform import inf037b_producer_contracts as contracts
from inference_platform.inf037b_archive import Archive, IntegrityError, encode, sha, strict_json
from inference_platform.inf037b_capture import CaptureOwner, DeadlineHTTP
from inference_platform.inf037b_contract import REGISTRATION_ID
from inference_platform.inf037b_live import REDIS_SNAPSHOT, ClientSSEAdapter, LiveRows, RedisWire
from inference_platform.inf037b_producer_limits import (
    CLIENT_DENIAL_BYTES,
    CLIENT_PENDING_BYTES,
    RESP_ARRAY_ELEMENTS,
    RESP_BULK_BYTES,
    RESP_LINE_BYTES,
    ProducerLimit,
    ReplyBudget,
    resp_contract,
)
from inference_platform.inf037b_row5_kind import row5_runtime_sources
from inference_platform.inf037b_stream import StreamingArchiveWriter

ORIGINS = (
    {"uid": "old0", "slot": 0, "node": "node0", "process_generation": "p0"},
    {"uid": "old1", "slot": 1, "node": "node1", "process_generation": "p1"},
    {"uid": "new0", "slot": 0, "node": "node0", "process_generation": "p2"},
)


class Round369PartitionTests(unittest.TestCase):
    def test_partition_pinned_maxima_use_one_times_and_missing_families_refuse(self):
        from inference_platform.inf037b_capture_inventory import admit_partition, partition_proposal

        result = partition_proposal()
        self.assertEqual(result["status"], "STOP_known_exceeds_allowance")
        self.assertGreater(result["known_raw_plus_reserve"], result["allowance"]["raw_bytes"])
        self.assertFalse(result["admitted"])
        self.assertTrue(
            all(
                r["headroom"] == (1 if r["unit_raw_bytes"] is not None else 4)
                for r in result["rows"]
            )
        )
        with self.assertRaisesRegex(ValueError, "capture_inventory:partition_allowance"):
            admit_partition(result)

    def test_partition_cannot_be_admitted_by_replacing_missing_data(self):
        from inference_platform.inf037b_capture_inventory import admit_partition, partition_proposal

        proposal = partition_proposal()
        for forged in (
            {**proposal, "rows": [], "known_raw_plus_reserve": 0, "admitted": True},
            {**proposal, "headroom": 1},
        ):
            with self.assertRaisesRegex(ValueError, "capture_inventory:partition_provenance"):
                admit_partition(forged)

    def test_project_scope_windows_are_finite_and_enforced(self):
        from inference_platform.inf037b_eks_collectors import SCOPE_WINDOWS_MS, ScopeWindow

        for scope, maximum in SCOPE_WINDOWS_MS.items():
            with self.subTest(scope=scope):
                self.assertLess(maximum, 18000000)
                ScopeWindow(scope, 0, maximum * 1000000, "source")
                with self.assertRaisesRegex(ValueError, "collectors:scope_deadline"):
                    ScopeWindow(scope, 0, maximum * 1000000 + 1, "source")


class SnapshotStore:
    """Portable durable-store substitute; no directory-fsync emulation."""

    def __init__(self, path, state):
        self.path, self.state = path, copy.deepcopy(state)
        self.reads = 0
        path.mkdir()
        self.write(state)

    @contextmanager
    def lock(self):
        yield

    def read(self):
        self.reads += 1
        return copy.deepcopy(self.state)

    def write(self, state):
        self.state = copy.deepcopy(state)
        (self.path / "state.json").write_bytes(encode(state))


class InventoryTests(unittest.TestCase):
    def worker_owner(self):
        owner, _ = self.loss_owner()
        owner.binding.update(session_id="s", pins={})
        owner.boot, owner.boot_path = "boot", owner.root / "boot"
        owner.boot_path.write_text("boot")
        owner.attempt, owner.stages = 1, [1]
        owner.builders, owner.clock_rows = {}, []
        owner.operation = {"body": {"binding": owner.binding}}
        owner.label = "operation"
        owner.operation_store = SnapshotStore(
            owner.root / "operations", {"operations": {"operation": owner.operation}}
        )
        owner.join()
        return owner

    def wire_metadata(self, owner, source):
        owner.barrier(source)
        return [
            strict_json(line)["metadata"]
            for line in Path(owner.wire[source]["index"].name).read_bytes().splitlines()
        ]

    def test_periodic_and_action_keep_owner_ticks_errors_and_payload_identity_rule(self):
        for kind in ("periodic", "action"):
            with self.subTest(kind=kind):
                owner = self.worker_owner()
                source = "metrics:slot0"
                now, calls, stopped = [0], [], [False]

                def collect(calls=calls, now=now):
                    calls.append(True)
                    if len(calls) == 2:
                        raise ValueError("worker-error")
                    now[0] += 1000

                def wait(delay, now=now):
                    now[0] += round(delay * 1e9)
                    return False

                event = SimpleNamespace(
                    is_set=lambda stopped=stopped: stopped[0],
                    wait=wait,
                    set=lambda stopped=stopped: stopped.__setitem__(0, True),
                )
                with patch(
                    "inference_platform.inf037b_capture.time.monotonic_ns",
                    side_effect=lambda now=now: now[0],
                ):
                    with self.assertRaisesRegex(ValueError, "worker-error"):
                        if kind == "periodic":
                            owner.periodic(
                                source,
                                collect,
                                period_ms=1000,
                                stop_ns=3_000_000_000,
                                stop_event=event,
                                start_ns=0,
                            )
                        else:
                            owner.action(source, collect, stop_ns=3_000_000_000)
                            owner.action(source, collect, stop_ns=3_000_000_000)
                records = self.wire_metadata(owner, source)
                self.assertTrue(
                    any(
                        r.get("scheduled_ns") == 0
                        if kind == "periodic"
                        else r.get("action_completed")
                        for r in records
                    )
                )
                self.assertTrue(any(r.get("error") == "worker-error" for r in records))
                self.assertTrue(all(r.get("owner_record") is True for r in records))
                self.assertIn(source + ":worker-error", owner.store.read()["capture"]["losses"])
                with self.assertRaisesRegex(IntegrityError, "pod_metadata"):
                    owner.retainer(source)(1, 2, b"chunk", {"path": "/metrics"})

    def test_worker_and_rejected_row_losses_survive_error_record_refusal(self):
        for kind in ("periodic", "action", "row"):
            with self.subTest(kind=kind):
                owner = self.worker_owner()
                source = "metrics:slot0"
                owner.binding["capture_budgets"][source]["index_bytes"] = 0

                def fail():
                    raise ValueError("error-record-refused")

                with self.assertRaises(IntegrityError):
                    if kind == "periodic":
                        owner.periodic(
                            source,
                            fail,
                            period_ms=1000,
                            stop_ns=time.monotonic_ns() + 2_000_000_000,
                            stop_event=threading.Event(),
                        )
                    elif kind == "action":
                        owner.action(source, fail, stop_ns=time.monotonic_ns() + 2_000_000_000)
                    else:
                        owner.rows(source).row(
                            "vllm",
                            "vllm:unadmitted",
                            "p",
                            "sample",
                            {"pod_uid": "unadmitted", "slot": 0, "process_generation": "p"},
                        )
                losses = owner.store.read()["capture"]["losses"]
                expected = "capture:lineage" if kind == "row" else "error-record-refused"
                self.assertTrue(any(expected in loss for loss in losses))
                self.assertTrue(owner.failed)

    def test_deadline_http_chunks_use_per_uid_slot_retainer(self):
        owner = self.worker_owner()

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", "6")
                self.end_headers()
                self.wfile.write(b"metric")

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        retained = owner.retainer("metrics:slot0", uid="pod-a", process_generation="process-a")
        http = DeadlineHTTP(
            f"http://127.0.0.1:{server.server_port}",
            stop_ns=time.monotonic_ns() + 5_000_000_000,
            retain=retained,
            local_test=True,
        )
        self.assertEqual(http.get("/metrics")[0], b"metric")
        records = self.wire_metadata(owner, "metrics:slot0")
        self.assertTrue(records)
        self.assertTrue(
            all(r["uid"] == "pod-a" and r["process_generation"] == "process-a" for r in records)
        )
        with self.assertRaisesRegex(IntegrityError, "adapter_owner_record"):
            retained(1, 2, b"bad", {"owner_record": True})

    def loss_owner(self):
        owner, _, _ = self.owner_files()
        owner.io_lock, owner.failed = threading.RLock(), False
        owner.archive_pending, owner.archive_directories = set(), set()
        owner.client_completions, owner.fsync_count, owner.barrier_count = [], 0, 0
        owner.store = SnapshotStore(owner.root / "store", {"capture": {}})
        owner.binding["capture_budgets"] = {
            source: {"raw_bytes": 100, "index_bytes": 10000, "records": 10}
            for source in owner.sources
        }
        barriers = []

        def flush(source):
            barriers.append(source)
            for key in ("data", "index"):
                owner.wire[source][key].flush()

        owner.barrier = flush  # Portable component, not Linux fsync evidence.
        return owner, barriers

    def test_group_barrier_drains_after_overflow_and_raises_original_error(self):
        for two_overflows in (False, True):
            with self.subTest(two_overflows=two_overflows):
                owner, barriers = self.loss_owner()
                owner.binding["capture_budgets"]["gateway0"]["raw_bytes"] = 1
                if two_overflows:
                    owner.binding["capture_budgets"]["gateway1"]["raw_bytes"] = 1
                owner.client_complete("gateway0", 1, 2, b"too-big", {})
                owner.client_complete("gateway1", 1, 2, b"ok", {})
                errors, retain = [], owner.retain

                def observed(*args, retain=retain, errors=errors):
                    try:
                        return retain(*args)
                    except Exception as error:
                        errors.append(error)
                        raise

                owner.retain = observed
                with self.assertRaisesRegex(
                    IntegrityError, "capture:budget:gateway0:raw"
                ) as caught:
                    owner.group_barrier()
                self.assertIs(caught.exception, errors[0])
                self.assertEqual(owner.client_completions, [])
                self.assertTrue(set(owner.sources) <= set(barriers))
                losses = owner.store.read()["capture"]["losses"]
                self.assertIn("capture:budget:gateway0:raw", losses)
                if two_overflows:
                    self.assertIn("capture:budget:gateway1:raw", losses)
                else:
                    files = owner.wire["gateway1"]
                    self.assertEqual(Path(files["data"].name).read_bytes(), b"ok")
                    index = strict_json(Path(files["index"].name).read_bytes())
                    self.assertEqual((index["length"], index["sha256"]), (2, sha(b"ok")))
                    self.assertIn("gateway1", barriers)

    def test_slot_retainer_keeps_two_uids_and_normalized_uid_lineages(self):
        owner, _, _ = self.owner_files()
        owner.binding.update(session_id="s", pins={})
        owner.boot, owner.boot_path = "boot", owner.root / "boot"
        owner.boot_path.write_text("boot")
        owner.attempt, owner.stages = 1, [1]
        owner.builders, owner.clock_rows = {}, []
        owner.io_lock = threading.RLock()
        owner.archive_pending, owner.archive_directories = set(), set()
        owner.sources["metrics:slot0"] = [
            ["vllm", "vllm:" + uid, generation]
            for uid, generation in (("old", "p0"), ("new", "p1"))
        ]
        owner.operation = {"body": {"binding": owner.binding}}
        owner.label = "operation"
        owner.operation_store = SnapshotStore(
            owner.root / "operations", {"operations": {"operation": owner.operation}}
        )
        owner.join()
        owner.archive = Archive.create(owner.root / "archive", {"registration_id": REGISTRATION_ID})
        owner.writer = StreamingArchiveWriter(owner.archive.root, append_write=owner.archive_write)
        owner.sources["kubernetes"] = [["kubernetes", "kubernetes", "boot"]]
        owner.store = SnapshotStore(owner.root / "store", {"capture": {}})
        rows = owner.rows("metrics:slot0")
        for uid, generation in (("old", "p0"), ("new", "p1")):
            owner.rows("kubernetes").row(
                "kubernetes", "kubernetes", "boot", "pod_created", {"pod_uid": uid, "slot": 0}
            )
            metadata = {"uid": uid, "process_generation": generation}
            owner.retain("metrics:slot0", 1, 2, uid.encode(), metadata)
            rows.row(
                "vllm",
                "vllm:" + uid,
                generation,
                "sample",
                {"pod_uid": uid, "slot": 0, "process_generation": generation},
                start_ns=1,
                end_ns=2,
            )
        for key in ("data", "index"):
            owner.wire["metrics:slot0"][key].flush()
        path = Path(owner.wire["metrics:slot0"]["index"].name)
        records = [strict_json(line) for line in path.read_bytes().splitlines()]
        self.assertEqual(
            [r["metadata"] for r in records],
            [
                {"uid": "old", "process_generation": "p0"},
                {"uid": "new", "process_generation": "p1"},
            ],
        )
        normalized = [
            strict_json(line)
            for line in (owner.archive.root / "raw/vllm.jsonl").read_bytes().splitlines()
        ]
        self.assertEqual([r["source_identity"] for r in normalized], ["vllm:old", "vllm:new"])
        self.assertEqual([r["source_generation"] for r in normalized], ["p0", "p1"])

    def test_pod_retainer_requires_identity_metadata_before_writing(self):
        owner, _, _ = self.owner_files()
        for metadata in ({}, {"uid": "u"}, {"uid": "u", "process_generation": ""}):
            with (
                self.subTest(metadata=metadata),
                self.assertRaisesRegex(IntegrityError, "pod_metadata:metrics:slot0"),
            ):
                owner.retain("metrics:slot0", 1, 2, b"bytes", metadata)
        self.assertEqual(owner.wire["metrics:slot0"]["offset"], 0)
        self.assertEqual(owner.wire["metrics:slot0"]["records"], 0)

    def test_slots_and_separate_setup_determine_files_not_uid_count(self):
        one = inventory.source_inventory(slots=(0,))
        many = inventory.source_inventory(slots=(0,), origins=(ORIGINS[0], ORIGINS[2]))
        self.assertEqual(one["wire_files"], many["wire_files"])
        self.assertEqual(one["known_wire_file_count"], 28)
        setup = inventory.source_inventory(slots=(0,), separate_setup=True)
        self.assertEqual(setup["known_wire_file_count"], 30)
        self.assertIn("lifecycle:setup", [entry["name"] for entry in setup["sources"]])
        for slots in ((True,), (2,), (0, 0)):
            with self.subTest(slots=slots), self.assertRaises(IntegrityError):
                inventory.source_inventory(slots=slots)

    def test_invalid_bindings_refuse_before_join_store_or_root(self):
        for invalid in ("inventory", "budget_set", "budget_key", "budget_type", "budget_negative"):
            with self.subTest(invalid=invalid):
                base = Path(self.enterContext(TemporaryDirectory(prefix="r334-construction-")))
                sources = {"s": [["controller", "s", "boot"]]}
                declared = {
                    "schema": "inf037b-capture-inventory-v1",
                    "sources": [{"name": "s"}],
                    "wire_files": sorted(inventory.wire_files(sources)["s"].values()),
                }
                binding = {
                    "pins": {},
                    "capture_inventory": declared,
                    "capture_budgets": {"s": {"raw_bytes": 1, "index_bytes": 1, "records": 1}},
                }
                if invalid == "inventory":
                    binding["capture_inventory"]["sources"] = []
                elif invalid == "budget_set":
                    binding["capture_budgets"] = {}
                elif invalid == "budget_key":
                    del binding["capture_budgets"]["s"]["records"]
                else:
                    binding["capture_budgets"]["s"]["records"] = (
                        True if invalid == "budget_type" else -1
                    )
                boot = base / "boot"
                boot.write_text("boot")
                operation = {
                    "operation": "capture",
                    "key": "key",
                    "body": {
                        "binding": binding,
                        "capture": {
                            "sources": sources,
                            "attempt": "setup",
                            "stages": [1],
                            "boot_id": "boot",
                        },
                    },
                }
                store = SnapshotStore(base / "store", {})
                label = sha(encode(["capture", "key"]))
                ops = SnapshotStore(base / "operations", {"operations": {label: operation}})
                with self.assertRaises(IntegrityError):
                    CaptureOwner(
                        store=store,
                        operation_store=ops,
                        operation=operation,
                        binding=binding,
                        sources=sources,
                        root=base / "capture",
                        attempt="setup",
                        stages=[1],
                        boot_path=boot,
                    )
                self.assertNotIn("capture", store.read())
                self.assertFalse((base / "capture").exists())
                self.assertEqual(ops.reads, 0, "invalid binding reached join")

    def test_eks_binding_requires_both_inventory_and_budgets(self):
        for key in ("capture_inventory", "capture_budgets"):
            with (
                self.subTest(key=key),
                self.assertRaisesRegex(IntegrityError, "eks_missing:" + key),
            ):
                inventory.require_eks_capture_binding(
                    {
                        other: {}
                        for other in ("capture_inventory", "capture_budgets")
                        if other != key
                    },
                    {},
                )

    def test_budget_exact_and_overflow_are_atomic_and_sticky(self):
        for kind in ("raw", "index", "records"):
            with self.subTest(kind=kind):
                owner, _, _ = self.owner_files()
                source = "gateway0"
                frame = inventory.wire_index_record(
                    source=source,
                    operation_sha256="a" * 64,
                    start_ns=1,
                    end_ns=2,
                    sequence=0,
                    offset=0,
                    length=3,
                    sha256=sha(b"abc"),
                    metadata={},
                )
                budgets = {
                    s: {"raw_bytes": 100, "index_bytes": 10000, "records": 10}
                    for s in owner.sources
                }
                budgets[source][
                    {"raw": "raw_bytes", "index": "index_bytes", "records": "records"}[kind]
                ] = {"raw": 3, "index": len(frame), "records": 1}[kind]
                # All three exact limits are exercised together as well.
                if kind == "records":
                    budgets[source] = {"raw_bytes": 100, "index_bytes": 10000, "records": 1}
                owner.binding["capture_budgets"] = budgets
                owner.io_lock, owner.failed = threading.RLock(), False
                owner.archive_pending, owner.archive_directories = set(), set()
                owner.client_completions, owner.fsync_count, owner.barrier_count = [], 0, 0
                owner.store = SnapshotStore(owner.root / "store", {"capture": {}})

                # Portable file-component test: loss/store and retain are real;
                # the Linux read-descriptor fsync barrier is host-only.
                def flush(source, owner=owner):
                    for key in ("data", "index"):
                        owner.wire[source][key].flush()

                owner.barrier = flush
                owner.retain(source, 1, 2, b"abc", {})
                owner.group_barrier()
                before = [
                    p.read_bytes()
                    for p in (Path(owner.wire[source][k].name) for k in ("data", "index"))
                ]
                # raw: one byte over; index: encoded frame one byte over;
                # records: one record over even when the body is empty.
                body = b"x" if kind == "raw" else b""
                if kind == "index":
                    next_frame = inventory.wire_index_record(
                        source=source,
                        operation_sha256="a" * 64,
                        start_ns=1,
                        end_ns=2,
                        sequence=1,
                        offset=3,
                        length=0,
                        sha256=sha(body),
                        metadata={},
                    )
                    budgets[source]["index_bytes"] += len(next_frame) - 1
                reason = "capture:budget:" + source + ":" + kind
                with self.assertRaisesRegex(IntegrityError, reason):
                    owner.retain(source, 1, 2, body, {})
                after = [
                    p.read_bytes()
                    for p in (Path(owner.wire[source][k].name) for k in ("data", "index"))
                ]
                self.assertEqual(after, before)
                self.assertEqual(owner.sequence, 1)
                self.assertTrue(owner.failed)
                self.assertIn(reason, owner.store.read()["capture"]["losses"])
                self.assertEqual(owner.wire["redis"]["offset"], 0)
                owner.group_barrier()
                self.assertIn(reason, owner.store.read()["capture"]["losses"])

    def test_all_budget_limits_exact_and_zero_source(self):
        owner, _, _ = self.owner_files()
        frame = inventory.wire_index_record(
            source="gateway0",
            operation_sha256="a" * 64,
            start_ns=1,
            end_ns=2,
            sequence=0,
            offset=0,
            length=3,
            sha256=sha(b"abc"),
            metadata={},
        )
        owner.binding["capture_budgets"] = {
            s: {"raw_bytes": 0, "index_bytes": 0, "records": 0} for s in owner.sources
        }
        owner.binding["capture_budgets"]["gateway0"] = {
            "raw_bytes": 3,
            "index_bytes": len(frame),
            "records": 1,
        }
        owner.retain("gateway0", 1, 2, b"abc", {})
        self.assertEqual(owner.wire["gateway0"]["index_bytes"], len(frame))
        self.assertEqual(owner.wire["redis"]["records"], 0)

    def owner_files(self, *, open_files=True):
        """Exercise the owner's real file-creation component, not DurableStore.

        The full constructor remains Linux-only and its existing suite is not
        bypassed. These row lineages are explicit component-test bindings, not
        a claim that the missing EKS factory/normalization routing is built.
        """
        declared = inventory.source_inventory(origins=ORIGINS)
        sources = row5_runtime_sources({"gateway0": "g0", "gateway1": "g1"}, "boot")
        expected = {
            *sources,
            "kubernetes",
            "node-cache:node0",
            "node-cache:node1",
            *(
                prefix + "slot" + str(slot)
                for prefix in ("metrics:", "native:", "lifecycle:")
                for slot in (0, 1)
            ),
        }
        for name in expected - sources.keys():
            sources[name] = [["controller", "component:" + name, "boot"]]
        owner = CaptureOwner.__new__(CaptureOwner)
        owner.root = Path(self.enterContext(TemporaryDirectory(prefix="r333-wire-")))
        (owner.root / "wire").mkdir()
        owner.binding, owner.sources, owner.wire = {"capture_inventory": declared}, sources, {}
        owner.lock, owner.closed = threading.RLock(), False
        owner.operation_sha256, owner.sequence = "a" * 64, 0
        if open_files:
            owner._open_wire_sources()
            for files in owner.wire.values():
                self.addCleanup(files["data"].close)
                self.addCleanup(files["index"].close)
        return owner, declared, expected

    def test_owner_creates_full_catalog_files_including_empty_sources(self):
        owner, declared, expected = self.owner_files()
        self.assertEqual(set(owner.wire), expected)
        actual = sorted(
            p.relative_to(owner.root).as_posix() for p in (owner.root / "wire").iterdir()
        )
        self.assertEqual(actual, declared["wire_files"])
        self.assertEqual(len(actual), 34)  # 8 row5 + kube + 2 nodes + 3*2 slot families.
        self.assertTrue(all((owner.root / name).stat().st_size == 0 for name in actual))
        self.assertTrue(all(e["can_be_empty"] for e in declared["sources"]))

    def test_adding_a_source_without_updating_inventory_refuses(self):
        owner, _, _ = self.owner_files(open_files=False)
        owner.sources["unexpected"] = [["controller", "unexpected", "boot"]]
        with self.assertRaisesRegex(IntegrityError, "capture_inventory:source_set"):
            owner._open_wire_sources()
        self.assertEqual(list((owner.root / "wire").iterdir()), [])

    def test_changed_layout_and_schema_refuse(self):
        owner, declared, _ = self.owner_files(open_files=False)
        for change, reason in (
            (lambda x: x["wire_files"].pop(), "source_set"),
            (lambda x: x.update(schema="wrong"), "schema"),
        ):
            with self.subTest(reason=reason):
                changed = copy.deepcopy(declared)
                change(changed)
                with self.assertRaisesRegex(IntegrityError, "capture_inventory:" + reason):
                    inventory.validate_source_inventory(owner.sources, changed)

    def test_new_row5_source_requires_inventory_classification(self):
        def added(*args):
            return {**row5_runtime_sources(*args), "new-source": [["controller", "new", "boot"]]}

        with (
            patch("inference_platform.inf037b_row5_kind.row5_runtime_sources", side_effect=added),
            self.assertRaisesRegex(
                IntegrityError, "capture_inventory:unclassified_source:new-source"
            ),
        ):
            inventory.source_inventory()

    def test_owner_writes_the_shared_exact_index_encoding(self):
        owner, _, _ = self.owner_files()
        source = "gateway0"
        owner.retain(source, 1, 2, b"abc", {"path": "/p"})
        for stream in (owner.wire[source]["data"], owner.wire[source]["index"]):
            stream.flush()
        names = inventory.wire_files([source])[source]
        actual = (owner.root / names["index"]).read_bytes()
        expected = encode(
            {
                "source": source,
                "operation_sha256": "a" * 64,
                "start_ns": 1,
                "end_ns": 2,
                "sequence": 0,
                "offset": 0,
                "length": 3,
                "sha256": sha(b"abc"),
                "metadata": {"path": "/p"},
            }
        )
        self.assertEqual(actual, expected)
        self.assertEqual((owner.root / names["data"]).read_bytes(), b"abc")

    def test_no_uid_or_missing_adapter_is_invented(self):
        result = inventory.source_inventory()
        self.assertEqual(result["known_wire_file_count"], 34)
        self.assertIsNone(result["wire_file_count"])
        self.assertFalse(result["complete"])
        self.assertEqual(result["unbound_uid_families"], [])
        gaps = {g["source"]: g for g in result["gaps"]}
        self.assertIn("resource_bindings", gaps)
        self.assertIn(41, gaps["gpu_device_release"]["v4_lines"])
        self.assertIn(106, gaps["placement_api"]["v4_lines"])
        self.assertTrue(all(g["wire_files"] is None for g in gaps.values()))

    def test_uid_origins_and_node_scope_are_explicit(self):
        for origins, nodes in (
            ([ORIGINS[0], ORIGINS[0]], ("node0", "node1")),
            ([{**ORIGINS[0], "slot": True}], ("node0", "node1")),
            ([{**ORIGINS[0], "node": "unknown"}], ("node0", "node1")),
            ([], ("node0",)),
        ):
            with self.subTest(origins=origins, nodes=nodes), self.assertRaises(IntegrityError):
                inventory.source_inventory(origins=origins, nodes=nodes)

    def contract_owner(self, source="gateway0"):
        owner = self.worker_owner()
        owner.binding["capture_budgets"][source] = {
            "raw_bytes": 40_000_000,
            "index_bytes": 5_000_000,
            "records": 10000,
        }
        return owner, owner.retainer(source)

    def response_bytes(self, owner, source="gateway0"):
        owner.barrier(source)
        return Path(owner.wire[source]["data"].name).read_bytes()

    def http_producer(self, body, status, *, pending_fixture=False):
        if pending_fixture:
            # Isolate the accepted pending-buffer regression from the new,
            # independently tested aggregate frame contract. Assertions and
            # the 1 MiB pending ceiling are unchanged.
            self.enterContext(
                patch(
                    "inference_platform.inf037b_live.client_contract",
                    return_value={
                        "frames": 6,
                        "frame_bytes": CLIENT_PENDING_BYTES + 1,
                        "body_bytes": 6 * (CLIENT_PENDING_BYTES + 1),
                    },
                )
            )

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                self.send_response(status)
                self.send_header("X-Request-ID", "request")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return f"http://127.0.0.1:{server.server_port}"

    def assert_contract_loss(self, owner, reason):
        self.assertTrue(owner.failed)
        self.assertTrue(any(reason in s for s in owner.store.read()["capture"]["losses"]))
        self.assertTrue(
            any(m.get("error", "").endswith(reason) for m in self.wire_metadata(owner, "gateway0"))
        )

    def test_real_http_denial_exact_and_plus_one_keep_rejected_bytes(self):
        prefix = b'{"error":{"code":"system_capacity"}}'
        for extra in (0, 1):
            with self.subTest(extra=extra):
                body = prefix + b" " * (CLIENT_DENIAL_BYTES + extra - len(prefix))
                owner, retain = self.contract_owner()
                client = ClientSSEAdapter(
                    LiveRows("s", "boot"), "gateway0", "a" * 64, retain=retain
                )
                url = self.http_producer(body, 429)
                offer = {
                    "request_id": "offer",
                    "offer_index": 0,
                    "prefix_id": "p",
                    "scheduled_ms": 0,
                }
                if extra:
                    reason = "capture:producer:client_denial_bytes"
                    with self.assertRaisesRegex(ProducerLimit, reason):
                        client.request(url + "/", {}, offer, credential="fixture", local_test=True)
                    self.assert_contract_loss(owner, reason)
                else:
                    rows = client.request(
                        url + "/", {}, offer, credential="fixture", local_test=True
                    )
                    self.assertTrue(any(r["payload"]["event"] == "deny" for r in rows))
                    self.assertFalse(owner.failed)
                self.assertEqual(self.response_bytes(owner), body)

    def test_real_sse_pending_exact_and_plus_one_never_clear_or_truncate(self):
        for extra in (0, 1):
            with self.subTest(extra=extra):
                # Deliberately unfinished frame, not a successful full response.
                body = b":" + b"x" * (CLIENT_PENDING_BYTES + extra - 1)
                owner, retain = self.contract_owner()
                client = ClientSSEAdapter(
                    LiveRows("s", "boot"), "gateway0", "a" * 64, retain=retain
                )
                url = self.http_producer(body, 200, pending_fixture=True)
                offer = {
                    "request_id": "offer",
                    "offer_index": 0,
                    "prefix_id": "p",
                    "scheduled_ms": 0,
                }
                if extra:
                    reason = "capture:producer:client_sse_pending"
                    with self.assertRaisesRegex(ProducerLimit, reason):
                        client.request(url + "/", {}, offer, credential="fixture", local_test=True)
                    self.assert_contract_loss(owner, reason)
                else:
                    rows = client.request(
                        url + "/", {}, offer, credential="fixture", local_test=True
                    )
                    chunks = [
                        bytes.fromhex(r["payload"]["chunk_hex"])
                        for r in rows
                        if r["payload"]["event"] == "sse"
                    ]
                    self.assertEqual(b"".join(chunks), body)
                    self.assertFalse(owner.failed)
                self.assertEqual(self.response_bytes(owner), body)

    def redis_producer(self, body, retain):
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.recv(65536)
                try:
                    self.request.sendall(body)
                except OSError:
                    pass  # Client refuses early; no retry or replacement body.

        server = socketserver.TCPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        wire = RedisWire(
            "127.0.0.1", server.server_address[1], tls=False, local_test=True, retain=retain
        )
        self.addCleanup(wire.close)
        from inference_platform.inf037b_eks_collectors import ScopeWindow, redis_counts

        wire.bind_scope_contract(redis_counts(ScopeWindow("test", 0, 1000000000, "test-source")))
        command = wire.command
        wire.command = lambda *args: (
            wire._exchange(
                args,
                {
                    "bytes": (RESP_BULK_BYTES + 16) * (RESP_ARRAY_ELEMENTS + 1),
                    "elements": RESP_ARRAY_ELEMENTS + 1,
                    "depth": 1,
                },
            )
            if args == ("generic-test-only",)
            else command(*args)
        )
        return wire

    def test_ascii_only_redis_producers_refuse_non_ascii_and_keep_wire(self):
        import json

        for escaped in (False, True):
            snapshot = self.snapshot_value()
            snapshot["reports"] = ["g\u00e9", "{}"]
            raw = json.dumps(snapshot, ensure_ascii=escaped, separators=(",", ":")).encode()
            body = self.resp(raw)
            owner, retain = self.contract_owner()
            wire = self.redis_producer(body, retain)
            reason = "capture:producer:resp_snapshot_non_ascii"
            with self.assertRaisesRegex(ProducerLimit, reason):
                wire.command("EVAL", REDIS_SNAPSHOT, 5)
            self.assert_contract_loss(owner, reason)
            self.assertEqual(self.response_bytes(owner), body)

        fields = self.audit_entry()
        fields["gateway_uid"] = "g\u00e9".encode()
        flat = [v for pair in fields.items() for v in (pair[0].encode(), pair[1])]
        body = self.resp([[[b"0-0", flat]], b"0"])
        owner, retain = self.contract_owner()
        wire = self.redis_producer(body, retain)
        reason = "capture:producer:resp_audit_non_ascii"
        with self.assertRaisesRegex(ProducerLimit, reason):
            wire.command("EVAL", contracts.AUDIT_SCRIPT, 1, "key", "0-0")
        self.assert_contract_loss(owner, reason)
        self.assertEqual(self.response_bytes(owner), body)

    def test_ascii_snapshot_maximum_includes_embedded_report_quote_escaping(self):
        from inference_platform.inf037b_redis_shapes import ARRAYS, snapshot_body_bytes

        data = self.snapshot_value()
        for name, (count, caps) in ARRAYS.items():
            data[name] = ["x" * caps[i % 2] for i in range(count)]
        report = '{"n":1000000,"expires":-9223372036854775808,"unknown":false}'
        for i in (1, 3):
            data["reports"][i] = report + " " * (ARRAYS["reports"][1][1] - len(report))
        data["redis_time_ms"] = -(2**63)
        data["capture_order"] = "9" * 20
        raw = __import__("json").dumps(data, separators=(",", ":")).encode()
        self.assertLessEqual(len(raw), snapshot_body_bytes())

    @staticmethod
    def snapshot_value():
        return {
            "reports": {},
            "lows": {},
            "state": {},
            "active": {},
            "redis_time_ms": 1,
            "capture_order": "0",
        }

    def test_real_resp_snapshot_aggregate_bytes_exact_and_plus_one(self):
        from inference_platform.inf037b_redis_shapes import snapshot_body_bytes

        cap = snapshot_body_bytes()
        raw = encode(self.snapshot_value()).rstrip()
        raw += b" " * (cap - len(raw))
        for extra in (0, 1):
            owner, retain = self.contract_owner()
            body = self.resp(raw + b" " * extra)
            wire = self.redis_producer(body, retain)
            if extra:
                with self.assertRaisesRegex(ProducerLimit, "resp_(bytes|bulk)"):
                    wire.command("EVAL", REDIS_SNAPSHOT, 5)
                self.assertTrue(owner.failed)
                self.assertTrue(body.startswith(self.response_bytes(owner)))
            else:
                self.assertEqual(wire.command("EVAL", REDIS_SNAPSHOT, 5).encode(), raw)
                self.assertEqual(self.response_bytes(owner), body)

    def test_real_resp_auth_aggregate_exact_and_plus_one(self):
        from inference_platform.inf037b_redis_shapes import ERROR_LINE_BYTES

        for extra in (0, 1):
            owner, retain = self.contract_owner()
            body = b"-" + b"x" * (ERROR_LINE_BYTES - 3 + extra) + b"\r\n"
            wire = self.redis_producer(body, retain)
            if extra:
                with self.assertRaisesRegex(ProducerLimit, "resp_bytes"):
                    wire.command("AUTH", "fixture")
                self.assert_contract_loss(owner, "capture:producer:resp_bytes")
            else:
                with self.assertRaisesRegex(IntegrityError, "redis_capture_command_failed"):
                    wire.command("AUTH", "fixture")
            self.assertEqual(self.response_bytes(owner), body)
        owner, retain = self.contract_owner()
        self.assertEqual(self.redis_producer(b"+OK\r\n", retain).command("AUTH", "fixture"), "OK")

    def test_real_resp_fixed_shapes_exact_and_plus_one(self):
        from inference_platform.inf037b_redis_shapes import ARRAYS

        for kind in ("TIME", "snapshot"):
            for extra in (0, 1):
                with self.subTest(kind=kind, extra=extra):
                    owner, retain = self.contract_owner()
                    if kind == "TIME":
                        body = self.resp([str(-(2**63)).encode(), b"999999" + b"0" * extra])
                        args = ("TIME",)
                    else:
                        data = self.snapshot_value()
                        for key, (count, caps) in ARRAYS.items():
                            data[key] = ["x" * caps[i % 2] for i in range(count)]
                        data["reports"][0] += "x" * extra
                        body = self.resp(encode(data))
                        args = ("EVAL", REDIS_SNAPSHOT, 5)
                    wire = self.redis_producer(body, retain)
                    if extra:
                        reason = "capture:producer:resp_" + kind.lower() + "_shape"
                        with self.assertRaisesRegex(ProducerLimit, reason):
                            wire.command(*args)
                        self.assert_contract_loss(owner, reason)
                    else:
                        wire.command(*args)
                    self.assertEqual(self.response_bytes(owner), body)

    def test_real_resp_time_element_count_and_depth_keep_rejected_header(self):
        cases = (
            (b"*2\r\n$1\r\n1\r\n$1\r\n2\r\n", None),
            (b"*3\r\n", "capture:producer:resp_elements"),
            (b"*2\r\n*0\r\n", "capture:producer:resp_depth"),
        )
        for body, reason in cases:
            with self.subTest(reason=reason):
                owner, retain = self.contract_owner()
                wire = self.redis_producer(body, retain)
                if reason:
                    with self.assertRaisesRegex(ProducerLimit, reason):
                        wire.command("TIME")
                    self.assert_contract_loss(owner, reason)
                else:
                    self.assertEqual(wire.command("TIME"), ["1", "2"])
                self.assertEqual(self.response_bytes(owner), body)

    def test_real_resp_element_ceilings_exact_and_plus_one(self):
        for dimension in ("line", "bulk", "array"):
            for extra in (0, 1):
                with self.subTest(dimension=dimension, extra=extra):
                    owner, retain = self.contract_owner()
                    if dimension == "line":
                        body = b"+" + b"x" * (RESP_LINE_BYTES - 3 + extra) + b"\r\n"
                        expected = "x" * (RESP_LINE_BYTES - 3)
                    elif dimension == "bulk":
                        body = b"$%d\r\n" % (RESP_BULK_BYTES + extra)
                        if not extra:
                            body += b"x" * RESP_BULK_BYTES + b"\r\n"
                        expected = "x" * RESP_BULK_BYTES
                    else:
                        body = b"*%d\r\n" % (RESP_ARRAY_ELEMENTS + extra)
                        if not extra:
                            body += b":0\r\n" * RESP_ARRAY_ELEMENTS
                        expected = [0] * RESP_ARRAY_ELEMENTS
                    wire = self.redis_producer(body, retain)
                    if extra:
                        reason = "capture:producer:resp_" + dimension
                        with self.assertRaisesRegex(ProducerLimit, reason):
                            wire.command("generic-test-only")
                        self.assert_contract_loss(owner, reason)
                    else:
                        self.assertEqual(wire.command("generic-test-only"), expected)
                    self.assertEqual(self.response_bytes(owner), body)

    def test_real_http_get_existing_body_contract_exact_and_plus_one(self):
        for extra in (0, 1):
            with self.subTest(extra=extra):
                body = b"x" * (8_388_608 + extra)
                owner, retain = self.contract_owner()
                http = DeadlineHTTP(
                    self.http_producer(body, 200),
                    stop_ns=time.monotonic_ns() + 10_000_000_000,
                    retain=retain,
                    local_test=True,
                )
                if extra:
                    with self.assertRaisesRegex(IntegrityError, "capture:response_limit"):
                        http.get("/")
                    self.assert_contract_loss(owner, "capture:response_limit")
                else:
                    self.assertEqual(http.get("/")[0], body)
                self.assertEqual(self.response_bytes(owner), body)

    def request_body(self, owner, retain, body, *, tokens=1):
        client = ClientSSEAdapter(LiveRows("s", "boot"), "gateway0", "a" * 64, retain=retain)
        offer = {"request_id": "offer", "offer_index": 0, "prefix_id": "p", "scheduled_ms": 0}
        return client.request(
            self.http_producer(body, 200) + "/",
            {"max_tokens": tokens},
            offer,
            credential="fixture",
            local_test=True,
        )

    def test_real_sse_frame_body_and_count_exact_plus_one_keep_tail(self):
        for tokens in (1, 64):
            c = contracts.client_contract(tokens)
            for kind in ("frame_bytes", "frames", "body_bytes"):
                for extra in (0, 1):
                    with self.subTest(tokens=tokens, kind=kind, extra=extra):
                        frame = b":" + b"x" * (c["frame_bytes"] - 3) + b"\n\n"
                        if kind == "frame_bytes":
                            body = frame[:-2] + b"x" * extra + b"\n\n"
                        elif kind == "frames":
                            body = b":\n\n" * (c["frames"] + extra)
                        else:
                            body = frame * c["frames"] + b"x" * extra
                        owner, retain = self.contract_owner()
                        reason = "capture:producer:client_" + kind
                        if extra:
                            with self.assertRaisesRegex(ProducerLimit, reason):
                                self.request_body(owner, retain, body, tokens=tokens)
                            self.assert_contract_loss(owner, reason)
                        else:
                            self.request_body(owner, retain, body, tokens=tokens)
                            self.assertFalse(owner.failed)
                        kept = self.response_bytes(owner)
                        self.assertTrue(kept)
                        self.assertEqual(kept, body[: len(kept)])
                        if not extra:
                            self.assertEqual(kept, body)

    def test_real_canonical_sse_contract_finishes_without_capture_loss(self):
        base = {
            "id": "chatcmpl_req_" + "a" * 32,
            "object": "chat.completion.chunk",
            "created": 1,
            "model": "test-model",
        }
        values = [
            {
                **base,
                "choices": [{"index": 0, "delta": {"role": "assistant"}, "finish_reason": None}],
            },
            {
                **base,
                "choices": [
                    {
                        "index": 0,
                        "delta": {"content": "x" * contracts.TOKEN_BYTES},
                        "finish_reason": None,
                    }
                ],
            },
            {**base, "choices": [{"index": 0, "delta": {}, "finish_reason": "length"}]},
            {
                **base,
                "choices": [],
                "usage": {
                    "prompt_tokens": 1,
                    "completion_tokens": 1,
                    "total_tokens": 2,
                    "count_source": "runtime_usage",
                },
            },
        ]
        body = (
            b"".join(b"data: " + encode(v).strip() + b"\n\n" for v in values) + b"data: [DONE]\n\n"
        )
        owner, retain = self.contract_owner()
        rows = self.request_body(owner, retain, body)
        self.assertEqual(rows[-1]["payload"]["outcome"], "complete")
        self.assertFalse(owner.failed)
        self.assertEqual(self.response_bytes(owner), body)

    def raw_http(self, raw, retain, *, client=True):
        import http.client

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                while self.rfile.readline() not in (b"\r\n", b"\n", b""):
                    pass
                try:
                    self.wfile.write(raw)
                except OSError:
                    pass

        server = socketserver.TCPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)
        conn.response_class = contracts.guarded_response(retain, time.monotonic_ns, client=client)
        self.addCleanup(conn.close)
        conn.request("GET", "/")
        return conn

    def test_real_http_header_limits_keep_rejected_lines(self):
        import http.client

        cases = [
            ("count", contracts.HEADER_COUNT, "client_header_count", True),
            ("name", contracts.HEADER_NAME_BYTES, "client_header_field", True),
            ("value", contracts.HEADER_VALUE_BYTES, "client_header_field", True),
            ("status", http.client._MAXLINE, "client_header_line", True),
            ("count", http.client._MAXHEADERS - 1, "http_header_count", False),
            ("line", http.client._MAXLINE, "http_header_line", False),
        ]
        for kind, cap, suffix, client in cases:
            for extra in (0, 1):
                with self.subTest(kind=kind, client=client, extra=extra):
                    status, headers = b"HTTP/1.1 200 OK\r\n", b"X: v\r\n"
                    if kind == "count":
                        headers *= cap + extra
                    if kind == "name":
                        headers = b"X" * (cap + extra) + b": v\r\n"
                    if kind == "value":
                        headers = b"X: " + b"x" * (cap + extra) + b"\r\n"
                    if kind == "status":
                        status = b"HTTP/1.1 200 " + b"x" * (cap + extra - 15) + b"\r\n"
                    if kind == "line":
                        headers = b"X: " + b"x" * (cap + extra - 5) + b"\r\n"
                    raw = status + headers + b"\r\n"
                    owner, retain = self.contract_owner()
                    conn = self.raw_http(raw, retain, client=client)
                    if extra:
                        reason = "capture:producer:" + suffix
                        with self.assertRaisesRegex(ProducerLimit, reason):
                            conn.getresponse()
                        self.assert_contract_loss(owner, reason)
                        kept = self.response_bytes(owner)
                        self.assertTrue(kept)
                        self.assertEqual(kept, raw[: len(kept)])
                    else:
                        response = conn.getresponse()
                        self.assertEqual(response.status, 200)
                        response.read()

    def test_real_http_aggregate_headers_and_interim_response_refuse(self):
        import http.client

        status = b"HTTP/1.1 200 " + b"x" * (http.client._MAXLINE - 15) + b"\r\n"
        header = (
            b"X" * contracts.HEADER_NAME_BYTES
            + b": "
            + b"v" * contracts.HEADER_VALUE_BYTES
            + b"\r\n"
        )
        raw = status + header * contracts.HEADER_COUNT + b"\r\n"
        self.assertEqual(len(raw), contracts.HEADER_BYTES)
        owner, retain = self.contract_owner()
        response = self.raw_http(raw, retain).getresponse()
        self.assertEqual(response.status, 200)
        response.read()
        owner, retain = self.contract_owner()
        oversized = raw[:-2] + b" \r\n"
        with self.assertRaisesRegex(ProducerLimit, "client_header_bytes"):
            self.raw_http(oversized, retain).getresponse()
        self.assertEqual(self.response_bytes(owner), oversized)
        owner, retain = self.contract_owner()
        interim = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n\r\n"
        with self.assertRaisesRegex(ProducerLimit, "client_header_responses"):
            self.raw_http(interim, retain).getresponse()
        self.assertTrue(self.response_bytes(owner).startswith(b"HTTP/1.1 100"))

    @staticmethod
    def resp(value):
        if isinstance(value, list):
            return b"*%d\r\n" % len(value) + b"".join(InventoryTests.resp(v) for v in value)
        raw = value if isinstance(value, bytes) else str(value).encode()
        return b"$%d\r\n" % len(raw) + raw + b"\r\n"

    def audit_entry(self):
        return {
            k: (
                b"0"
                if k not in {"event", "decision", "reservation_id", "gateway_uid", "report"}
                else {
                    "event": b"admit",
                    "decision": b"allowed",
                    "reservation_id": b"rsv_" + b"a" * 32,
                    "gateway_uid": b"gateway-0",
                    "report": b"",
                }[k]
            )
            for k in contracts.ADMIT_FIELDS
        }

    def test_real_resp_audit_entry_limits_and_batch_limit_keep_tail(self):
        for key, cap in contracts.ADMIT_FIELDS.items():
            for extra in (0, 1):
                with self.subTest(key=key, extra=extra):
                    fields = self.audit_entry()
                    if key == "event":
                        value = b"report_store"
                    elif key == "decision":
                        value = b"tenant_concurrency_limit"
                    elif key == "report":
                        value = b'{"n":0,"expires":0,"unknown":false}'
                        value += b" " * (cap - len(value))
                    elif key == "idempotent":
                        value = b"0"
                    elif key in {
                        "capture_seq",
                        "redis_time_ms",
                        "effective_b",
                        "effective_n",
                        "occupied",
                    }:
                        value = str(-(2**63)).encode()
                    else:
                        value = b"x" * cap
                    fields[key] = value + b"x" * extra
                    flat = [v for pair in fields.items() for v in (pair[0].encode(), pair[1])]
                    body = self.resp([[[b"0-0", flat]], b"0"])
                    owner, retain = self.contract_owner()
                    wire = self.redis_producer(body, retain)
                    if extra:
                        with self.assertRaises(ProducerLimit):
                            wire.command("EVAL", contracts.AUDIT_SCRIPT, 1, "key", "0-0")
                        self.assertTrue(owner.failed)
                    else:
                        self.assertEqual(
                            len(wire.command("EVAL", contracts.AUDIT_SCRIPT, 1, "key", "0-0")[0]), 1
                        )
                    self.assertEqual(
                        self.response_bytes(owner), body[: len(self.response_bytes(owner))]
                    )
        fields = [v for pair in self.audit_entry().items() for v in (pair[0].encode(), pair[1])]
        for extra in (0, 1):
            owner, retain = self.contract_owner()
            body = self.resp([[[b"0-0", fields]] * (contracts.AUDIT_COUNT + extra), b"0"])
            wire = self.redis_producer(body, retain)
            if extra:
                with self.assertRaises(ProducerLimit):
                    wire.command("EVAL", contracts.AUDIT_SCRIPT, 1, "key", "0-0")
                self.assertTrue(owner.failed)
            else:
                self.assertEqual(
                    len(wire.command("EVAL", contracts.AUDIT_SCRIPT, 1, "key", "0-0")[0]),
                    contracts.AUDIT_COUNT,
                )

        # Unknown fields and one extra nesting level cannot reopen a generic
        # recursive RESP path after the valid 11-field/depth-4 batch above.
        fields = [v for pair in self.audit_entry().items() for v in (pair[0].encode(), pair[1])]
        for mutation, flat, reason in (
            ("field", fields + [b"extra", b"value"], "capture:producer:resp_audit_fields"),
            ("depth", [*fields[:-1], [fields[-1]]], "capture:producer:resp_depth"),
        ):
            with self.subTest(mutation=mutation):
                body = self.resp([[[b"0-0", flat]], b"0"])
                owner, retain = self.contract_owner()
                wire = self.redis_producer(body, retain)
                with self.assertRaisesRegex(ProducerLimit, reason):
                    wire.command("EVAL", contracts.AUDIT_SCRIPT, 1, "key", "0-0")
                self.assert_contract_loss(owner, reason)
                self.assertEqual(
                    self.response_bytes(owner), body[: len(self.response_bytes(owner))]
                )

    def test_real_resp_each_dispatch_counter_and_high_water_id_limits(self):
        for kind, args, body in (
            ("AUTH", ("AUTH", "fixture"), b"+OK\r\n"),
            ("TIME", ("TIME",), self.resp([b"1", b"2"])),
            ("snapshot", ("EVAL", REDIS_SNAPSHOT, 0), self.resp(encode(self.snapshot_value()))),
            ("audit", ("EVAL", contracts.AUDIT_SCRIPT, 1, "key", "0-0"), self.resp([[], b"0"])),
        ):
            with self.subTest(kind=kind):
                owner, retain = self.contract_owner()
                wire = self.redis_producer(body, retain)
                wire.producer_state["redis_calls"] = {kind: wire.scope_contract[kind] - 1}
                wire.command(*args)
                reason = "capture:producer:redis_calls:" + kind
                with self.assertRaisesRegex(ProducerLimit, reason):
                    wire.command(*args)
                self.assert_contract_loss(owner, reason)
                self.assertEqual(self.response_bytes(owner), body)
        fields = [v for pair in self.audit_entry().items() for v in (pair[0].encode(), pair[1])]
        for kind in ("id", "high_water"):
            for extra in (0, 1):
                with self.subTest(kind=kind, extra=extra):
                    identity = b"18446744073709551615-18446744073709551615"
                    high = str(-(2**63)).encode()
                    if kind == "id":
                        identity += b"x" * extra
                    else:
                        high += b"x" * extra
                    body = self.resp([[[identity, fields]], high])
                    owner, retain = self.contract_owner()
                    wire = self.redis_producer(body, retain)
                    if extra:
                        reason = "capture:producer:resp_audit_" + kind
                        with self.assertRaisesRegex(ProducerLimit, reason):
                            wire.command("EVAL", contracts.AUDIT_SCRIPT, 1, "key", "0-0")
                        self.assert_contract_loss(owner, reason)
                    else:
                        wire.command("EVAL", contracts.AUDIT_SCRIPT, 1, "key", "0-0")
                    self.assertEqual(self.response_bytes(owner), body)

    def test_real_census_reader_project_limit_exact_and_plus_one(self):
        from inference_platform.inf037b_eks_placement import PlacementAPI

        for extra in (0, 1):
            with self.subTest(extra=extra):
                owner, retain = self.contract_owner()
                body = encode(
                    {
                        "metadata": {"resourceVersion": "1"},
                        "items": [
                            {
                                "metadata": {"uid": str(i).zfill(36), "resourceVersion": "1"},
                                "spec": {"nodeName": "node"},
                            }
                            for i in range(44 + extra)
                        ],
                    }
                )
                base = self.http_producer(body, 200)
                # Contract seam only, NOT a completed deployed N derivation.
                api = PlacementAPI(
                    base,
                    token=lambda: "fixture",
                    clock=lambda: 0,
                    retain=retain,
                    local_test=True,
                    census_limit=44,
                )
                if extra:
                    with self.assertRaisesRegex(IntegrityError, "placement_api:census_pod_limit"):
                        api.census({"name": "node"}, 10000)
                else:
                    self.assertEqual(len(api.census({"name": "node"}, 10000)["pods"]), 44)
                self.assertEqual(self.response_bytes(owner), body)

    def test_real_http_one_byte_body_reads_write_one_complete_unit(self):
        import http.client

        from inference_platform.inf037b_capture import wire_records

        owner, retain = self.contract_owner()
        body = b'{"test":"real one-byte reads"}'
        base = self.http_producer(body, 200)
        read1 = http.client.HTTPResponse.read1
        with patch.object(
            http.client.HTTPResponse, "read1", lambda response, n=-1: read1(response, min(n, 1))
        ):
            http = DeadlineHTTP(
                base, stop_ns=time.monotonic_ns() + 10000000000, retain=retain, local_test=True
            )
            self.assertEqual(http.get("/body")[0], body)
        units = [(r, b) for r, b in wire_records(owner.root / "wire") if b]
        self.assertEqual(len(units), 1)
        self.assertEqual(units[0][1], body)
        self.assertEqual(units[0][0]["read_count"], len(body))
        self.assertEqual(self.response_bytes(owner), body)

    def test_composed_collectors_real_resp_http_counters_and_boundaries(self):
        from inference_platform.inf037b_eks_collectors import ComposedCollectors, ScopeWindow
        from inference_platform.inf037b_live import ClockAdapter, RedisAdapter

        owner, retain = self.contract_owner()
        snapshot = encode(self.snapshot_value())
        seen = []
        resp = self.resp

        class Handler(socketserver.StreamRequestHandler):
            def handle(server):
                while line := server.rfile.readline():
                    count = int(line[1:])
                    args = []
                    for _ in range(count):
                        size = int(server.rfile.readline()[1:])
                        args.append(server.rfile.read(size))
                        server.rfile.read(2)
                    kind = args[0].decode()
                    if kind == "EVAL":
                        kind = "snapshot" if args[1].decode() == REDIS_SNAPSHOT else "audit"
                    seen.append(kind)
                    reply = (
                        b"+OK\r\n"
                        if kind == "AUTH"
                        else resp([b"1", b"2"])
                        if kind == "TIME"
                        else resp(snapshot)
                        if kind == "snapshot"
                        else resp([[], b"0"])
                    )
                    server.wfile.write(reply)
                    server.wfile.flush()

        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        wire = RedisWire(
            "127.0.0.1",
            server.server_address[1],
            password="fixture",
            tls=False,
            local_test=True,
            retain=retain,
        )
        self.addCleanup(wire.close)
        body = b'{"boot_id":"remote","mono_ns":1000000000}'
        base = self.http_producer(body, 200)
        http = DeadlineHTTP(
            base, stop_ns=time.monotonic_ns() + 30000000000, retain=retain, local_test=True
        )
        gateway = SimpleNamespace(
            http=http, poll=lambda: http.get("/events"), poll_lock=threading.RLock()
        )
        other = SimpleNamespace(poll=lambda: http.get("/resources"))
        rows = LiveRows("s", "boot")
        window = ScopeWindow("test", 0, 1000000000, "code-bound-test", 1)
        collectors = ComposedCollectors(
            owner,
            window,
            redis=RedisAdapter(rows, wire, "fixture", "a" * 64),
            clocks=ClockAdapter(rows),
            gateways={"gateway0": gateway},
            resources={"resource:measurement": other},
        )
        collectors.boundary()
        collectors.action(lambda: None)()
        self.assertEqual(collectors.boundaries, 3)
        for source, period, callback in collectors.periodic:
            for _ in range(window.slots(period)):
                callback()
            reason = "collectors:call_count:" + source
            with self.assertRaisesRegex(IntegrityError, reason):
                callback()
        with self.assertRaisesRegex(IntegrityError, "collectors:boundary_count"):
            collectors.boundary()
        self.assertEqual(seen.count("AUTH"), 1)  # one persistent connection, not one AUTH per call
        self.assertEqual(seen.count("TIME"), collectors.counts["TIME"])
        self.assertEqual(seen.count("snapshot"), collectors.counts["snapshot"])
        self.assertLessEqual(seen.count("audit"), collectors.counts["audit"])
        self.assertFalse(collectors.redis.lost)

    def test_composed_scope_refuses_missing_binding_and_wrong_deadline(self):
        from inference_platform.inf037b_eks_collectors import ScopeWindow, compose

        owner, _ = self.contract_owner()
        with self.assertRaisesRegex(IntegrityError, "capture:unresolved:collector_bindings"):
            compose(owner, ScopeWindow("attempt:1", 0, 1560000000000, "registered"), None)
        with self.assertRaisesRegex(IntegrityError, "collectors:scope_deadline"):
            ScopeWindow("attempt:1", 0, 1560000000001, "registered")
        self.assertIsNone(contracts.redis_scope_contract(18000)["TIME"])

    def test_one_byte_split_unit_replay_keeps_decoded_frames_and_completion_times(self):
        from inference_platform.inf037b_capture import wire_records
        from inference_platform.inf037b_requests import SSEDecoder
        from inference_platform.inf037b_wire_units import UnitReads

        body = (
            b'data: {"choices":[{"index":0,"delta":{"content":"x"},"finish_reason":null}]}\n\n'
            b'data: {"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}\n\n'
            b'data: {"choices":[],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2,"count_source":"runtime_usage"}}\n\n'
            b"data: [DONE]\n\n"
        )
        owner, retain = self.contract_owner()
        merged = UnitReads(retain, mode="sse_frame")
        baseline = SSEDecoder()
        expected = []
        pending = bytearray()
        first = 0
        reads = 0
        for i, byte in enumerate(body):
            start, end = i * 1000000, (i + 1) * 1000000
            if not pending:
                first = start
            pending.append(byte)
            reads += 1
            baseline.feed(bytes([byte]), [end // 1000000] * 2)
            merged(start, end, bytes([byte]), {"status": 200})
            merged.units()
            if pending.endswith(b"\n\n"):
                expected.append((bytes(pending), first, end, reads))
                pending.clear()
                reads = 0
        merged.finish()
        owner.barrier("gateway0")
        actual = list(wire_records(owner.root / "wire"))
        self.assertEqual(
            [(b, r["start_ns"], r["end_ns"], r["read_count"]) for r, b in actual], expected
        )
        replay = SSEDecoder()
        for record, data in actual:
            replay.feed(data, [record["end_ns"] // 1000000] * 2)
        self.assertEqual(replay.report(), baseline.report())
        self.assertTrue(replay.report()["complete"])
        self.assertEqual(self.response_bytes(owner), body)

    def test_protocol_unit_record_budget_exact_and_plus_one_and_partial_tail(self):
        from inference_platform.inf037b_capture import wire_records
        from inference_platform.inf037b_wire_units import UnitRecorder

        owner, retain = self.contract_owner()
        owner.binding["capture_budgets"]["gateway0"]["records"] = 2
        for body in (b"first", b"second"):
            unit = UnitRecorder(retain, kind="body")
            for n, byte in enumerate(body):
                unit.feed(n, n + 1, bytes([byte]))
            unit.finish("close")
        self.assertEqual(owner.wire["gateway0"]["records"], 2)
        owner.barrier("gateway0")
        self.assertEqual([b for _, b in wire_records(owner.root / "wire")], [b"first", b"second"])
        unit = UnitRecorder(retain, kind="body")
        with self.assertRaisesRegex(IntegrityError, "capture:budget:gateway0:records"):
            unit.feed(100, 101, b"excess")
        self.assertEqual(self.response_bytes(owner), b"firstsecond")

    def test_unit_index_rejects_overlap_hash_and_unindexed_tail(self):
        from inference_platform.inf037b_capture import wire_records
        from inference_platform.inf037b_wire_units import UnitRecorder

        for mutation in ("overlap", "hash", "tail"):
            with self.subTest(mutation=mutation):
                owner, retain = self.contract_owner()
                unit = UnitRecorder(retain, kind="body")
                unit.feed(0, 1, b"abc")
                unit.finish()
                owner.barrier("gateway0")
                index = Path(owner.wire["gateway0"]["index"].name)
                original = index.read_bytes()
                if mutation == "tail":
                    owner.wire["gateway0"]["data"].write(b"x")
                    owner.wire["gateway0"]["data"].flush()
                else:
                    value = strict_json(original)
                    if mutation == "overlap":
                        value["physical_spans"] = [[0, 2], [1, 1]]
                    else:
                        value["sha256"] = "0" * 64
                    index.write_bytes(encode(value))
                with self.assertRaisesRegex(IntegrityError, "capture:"):
                    list(wire_records(owner.root / "wire"))

    def test_unit_index_preserves_interleaved_raw_order_and_read_brackets(self):
        from inference_platform.inf037b_capture import wire_records
        from inference_platform.inf037b_wire_units import UnitRecorder

        owner, retain = self.contract_owner()
        a, b = UnitRecorder(retain, kind="body"), UnitRecorder(retain, kind="body")
        a.feed(10, 11, b"a")
        b.feed(20, 21, b"xyz")
        b.finish()
        a.feed(30, 31, b"b")
        a.finish()
        owner.barrier("gateway0")
        self.assertEqual(self.response_bytes(owner), b"axyzb")
        records = list(wire_records(owner.root / "wire"))
        bodies = [(r, data) for r, data in records if data]
        self.assertEqual([data for _, data in bodies], [b"ab", b"xyz"])
        self.assertEqual(
            [(r["start_ns"], r["end_ns"], r["read_count"]) for r, _ in bodies],
            [(10, 31, 2), (20, 21, 1)],
        )

    def test_real_resp_high_water_project_limit_and_report_count(self):
        from inference_platform.inf037b_live import RedisAdapter

        for extra in (0, 1):
            owner, retain = self.contract_owner()
            cap = contracts.redis_scope_contract(30)["entries"]
            body = self.resp([[], str(cap + extra).encode()])
            wire = self.redis_producer(body, retain)
            adapter = RedisAdapter(LiveRows("s", "boot"), wire, "fixture", "a" * 64)
            adapter.audit_seq = cap
            result = adapter.operations()
            if extra:
                self.assertTrue(any("capture:producer:redis_entries" in str(r) for r in result))
                self.assert_contract_loss(owner, "capture:producer:redis_entries")
            else:
                self.assertEqual(result, [])
                self.assertFalse(owner.failed)
            self.assertEqual(self.response_bytes(owner), body)
            owner, retain = self.contract_owner()
            fields = self.audit_entry()
            fields["report"] = encode(
                {"n": 1000000 + extra, "expires": 0, "unknown": False}
            ).strip()
            flat = [v for pair in fields.items() for v in (pair[0].encode(), pair[1])]
            body = self.resp([[[b"0-0", flat]], b"0"])
            wire = self.redis_producer(body, retain)
            if extra:
                reason = "capture:producer:resp_audit_type"
                with self.assertRaisesRegex(ProducerLimit, reason):
                    wire.command("EVAL", contracts.AUDIT_SCRIPT, 1, "key", "0-0")
                self.assert_contract_loss(owner, reason)
            else:
                wire.command("EVAL", contracts.AUDIT_SCRIPT, 1, "key", "0-0")
            self.assertEqual(self.response_bytes(owner), body)

    def test_real_resp_closed_dispatch_call_budget_and_named_read_error(self):
        from inference_platform.inf037b_live import RedisAdapter

        owner, retain = self.contract_owner()
        wire = self.redis_producer(self.resp([b"1", b"2"]), retain)
        wire.producer_state["redis_calls"] = {"TIME": wire.scope_contract["TIME"] - 1}
        self.assertEqual(wire.command("TIME"), ["1", "2"])
        with self.assertRaisesRegex(ProducerLimit, "redis_calls:TIME"):
            wire.command("TIME")
        self.assert_contract_loss(owner, "capture:producer:redis_calls:TIME")
        owner, retain = self.contract_owner()
        wire = self.redis_producer(b"", retain)
        with self.assertRaisesRegex(ProducerLimit, "resp_command"):
            wire.command("PING")
        self.assert_contract_loss(owner, "capture:producer:resp_command")
        owner, retain = self.contract_owner()
        body = self.resp([[], b"x" * (contracts.INT64_CHARS + 1)])
        wire = self.redis_producer(body, retain)
        row = RedisAdapter(LiveRows("s", "b"), wire, "ns", "a" * 64).operations()[0]
        self.assertEqual(row["error"], "capture:producer:resp_audit_high_water")
        self.assertEqual(self.response_bytes(owner), body)

    def test_real_http_kube_metadata_caps_keep_original_body(self):
        import json

        cases = [
            ("uid", contracts.UID_BYTES),
            ("name", contracts.NAME_BYTES),
            ("namespace", contracts.NAME_BYTES),
            ("resourceVersion", contracts.INT64_CHARS),
            ("label", contracts.LABEL_BYTES),
            ("label_key", contracts.NAME_BYTES + 1 + contracts.LABEL_BYTES),
            ("annotations", 256 * 1024),
        ]
        for key, cap in cases:
            for extra in (0, 1):
                with self.subTest(key=key, extra=extra):
                    value = "x" * (cap + extra)
                    meta = {key: value}
                    suffix = key
                    if key == "label":
                        meta = {"labels": {"k": value}}
                        suffix = "label_value"
                    if key == "label_key":
                        meta = {"labels": {value: "v"}}
                    if key == "annotations":
                        meta = {"annotations": {"k": value[1:]}}
                    body = json.dumps({"metadata": meta}).encode()
                    owner, retain = self.contract_owner()
                    http = DeadlineHTTP(
                        self.http_producer(body, 200),
                        stop_ns=time.monotonic_ns() + 30_000_000_000,
                        retain=retain,
                        local_test=True,
                    )
                    if extra:
                        reason = "capture:producer:kube_" + suffix
                        with self.assertRaisesRegex(ProducerLimit, reason):
                            http.get("/api/v1/pods")
                        self.assert_contract_loss(owner, reason)
                    else:
                        self.assertEqual(http.get("/api/v1/pods")[0], body)
                    self.assertEqual(self.response_bytes(owner), body)

    def test_real_watch_event_generation_and_reconnect_caps_share_source_state(self):
        for kind, cap in (
            ("events", contracts.WATCH_EVENTS),
            ("pod_events", contracts.POD_TRANSITIONS),
            ("generations", contracts.FIXED_POD_GENERATIONS),
        ):
            for extra in (0, 1):
                with self.subTest(kind=kind, extra=extra):
                    events = [
                        encode(
                            {
                                "type": "MODIFIED",
                                "object": {
                                    "metadata": {
                                        "uid": f"{(i // contracts.POD_TRANSITIONS if kind == 'events' else i if kind == 'generations' else 0):036d}"
                                    }
                                },
                            }
                        )
                        for i in range(cap + extra)
                    ]
                    body = b"".join(events)
                    owner, retain = self.contract_owner()
                    http = DeadlineHTTP(
                        self.http_producer(body, 200),
                        stop_ns=time.monotonic_ns() + 30_000_000_000,
                        retain=retain,
                        local_test=True,
                    )
                    if extra:
                        reason = "capture:producer:watch_" + kind
                        with self.assertRaisesRegex(ProducerLimit, reason):
                            list(http.lines("/api/v1/pods?watch=true"))
                        self.assert_contract_loss(owner, reason)
                    else:
                        self.assertEqual(list(http.lines("/api/v1/pods?watch=true")), events)
                    kept = self.response_bytes(owner)
                    self.assertEqual(kept, body[: len(kept)])
        owner, retain = self.contract_owner()
        url, stop = self.http_producer(b"", 200), time.monotonic_ns() + 30_000_000_000
        cap = contracts.watch_contract(30)["connections"]
        for _ in range(cap):
            reader = DeadlineHTTP(
                url, stop_ns=stop, retain=owner.retainer("gateway0"), local_test=True
            )
            self.assertEqual(list(reader.lines("/api/v1/pods?watch=true")), [])
        with self.assertRaisesRegex(ProducerLimit, "watch_connections"):
            list(
                DeadlineHTTP(url, stop_ns=stop, retain=retain, local_test=True).lines(
                    "/api/v1/pods?watch=true"
                )
            )
        self.assert_contract_loss(owner, "capture:producer:watch_connections")

    def test_real_http_error_context_exact_plus_one_is_not_truncated(self):
        for extra in (0, 1):
            with self.subTest(extra=extra):
                owner, original = self.contract_owner()
                text = "x" * (contracts.ERROR_TEXT_BYTES + extra)
                raised = False

                def retain(start, end, body, metadata, original=original, text=text):
                    nonlocal raised
                    original(start, end, body, metadata)
                    if body and metadata.get("status") == 200 and not raised:
                        raised = True
                        raise ValueError(text)  # labelled consumer fault after real raw custody

                for name in ("barrier", "loss", "client_complete", "producer_state"):
                    setattr(retain, name, getattr(original, name))
                if extra:
                    reason = "capture:producer:client_error_bytes"
                    with self.assertRaisesRegex(ProducerLimit, reason):
                        self.request_body(owner, retain, b"x")
                    self.assert_contract_loss(owner, reason)
                    self.assertEqual(self.response_bytes(owner), b"x" + text.encode())
                else:
                    self.request_body(owner, retain, b"x")
                    self.assertTrue(
                        any(m.get("error") == text for m in self.wire_metadata(owner, "gateway0"))
                    )
                    self.assertEqual(self.response_bytes(owner), b"x")

    def test_readiness_capacity_uses_pinned_snapshot_over_real_resp(self):
        from check_package_a_admission import read_capacity_state

        owner, retain = self.contract_owner()
        data = self.snapshot_value()
        data["state"] = ["n", "2", "until", "123"]
        body = self.resp(encode(data))
        wire = self.redis_producer(body, retain)
        self.assertEqual(read_capacity_state(wire, "ns"), ["n", "2", "until", "123"])
        self.assertEqual(self.response_bytes(owner), body)


class EnvelopeTests(unittest.TestCase):
    def test_source_proof_pins_match_enforced_contracts_and_allowance_is_unchanged(self):
        proof = strict_json(
            (inventory.ROOT / "docs/INF037B_PRODUCER_CONTRACT_SOURCES.json").read_bytes()
        )
        self.assertEqual(proof["tokenizer"]["longest_decoded_utf8_bytes"], contracts.TOKEN_BYTES)
        self.assertEqual(proof["trace"], contracts.client_contract(1))
        self.assertEqual(proof["control"], contracts.client_contract(64))
        self.assertEqual(proof["audit"], contracts.audit_reply_contract())
        self.assertIsNone(proof["census"]["node_pod_limit"])
        self.assertEqual(inventory.GATE_A["raw_bytes"], 1_618_864_547)
        self.assertEqual(inventory.GATE_A["index_bytes"], 9_119_066)

    def test_contracts_pin_existing_sources_without_closing_missing_rows(self):
        table = inventory.producer_contracts()
        self.assertEqual(table["client_denial"]["body_bytes"], 8192)
        self.assertEqual(table["client_sse_pending"]["pending_bytes"], 1_048_576)
        # Guard the original decoder ceiling, not a second invented capacity.
        node = inventory._method("inf037b_requests.py", "SSEDecoder.feed")
        import ast

        self.assertTrue(
            any(
                isinstance(x, ast.Constant) and x.value == CLIENT_PENDING_BYTES
                for x in ast.walk(node)
            )
        )
        from inference_platform.inf037b_redis_shapes import fixed_contract

        self.assertEqual(table["resp_fixed_commands"]["snapshot"], fixed_contract("snapshot"))
        self.assertEqual(table["resp_fixed_commands"]["TIME"], fixed_contract("TIME"))
        self.assertLess(fixed_contract("snapshot")["bytes"], 100000)
        self.assertLess(fixed_contract("TIME")["bytes"], 1000)
        self.assertIsNone(resp_contract(("EVAL", "other"), REDIS_SNAPSHOT))
        census = inventory.census_candidate()
        self.assertEqual(census["pages"], 66)
        self.assertEqual(census["canonical_json_bytes"], 8_388_608)
        self.assertEqual(census["raw_bytes_upper_including_rejected_read"], 66 * 8_388_608 + 1)
        self.assertGreater(
            census["historical_non_binding_context"]["raw_bytes_upper_including_rejected_read"],
            inventory.GATE_A["raw_bytes"],
        )
        audit = inventory.audit_candidate()
        self.assertEqual(audit["entries_per_reply"], 1000)
        self.assertEqual(audit["elements"], 25_003)
        self.assertEqual(audit["depth"], 4)
        self.assertEqual(
            audit["valid_reply_bytes"], contracts.audit_reply_contract()["valid_reply_bytes"]
        )
        self.assertEqual(
            inventory.producer_limit_audit()["status"], "partial_sourced_allowance_stop"
        )
        budget = ReplyBudget({"bytes": 3, "elements": 1, "depth": 0})
        self.assertIsNone(budget.add(3))
        self.assertEqual(budget.add(1), "capture:producer:resp_bytes")

    def test_scope_family_bounds_use_units_and_own_windows_without_fake_totals(self):
        rows = inventory.sourced_scope_envelopes()
        self.assertEqual(len(rows), 17)
        attempt = next(r for r in rows if r["scope"] == "attempt:1")
        self.assertEqual(attempt["duration_upper_s"], 1560)
        self.assertEqual(attempt["offers_upper_per_gateway"], 17036)
        self.assertEqual(attempt["periodic_redis_calls"]["AUTH"], 1)
        self.assertEqual(attempt["periodic_redis_calls"]["TIME"], 1561)
        for row in rows:
            self.assertIsNone(row.get("whole_scope_raw_bytes_upper"))
        unknown = next(r for r in rows if r["scope"] == "configuration_smoke_rollback")
        self.assertEqual(unknown["duration_upper_s"], 120)
        self.assertEqual(unknown["periodic_redis_calls"]["TIME"], 121)
        self.assertEqual(unknown["offers_upper_per_gateway"], 0)
        holder = inventory.allowance_holder(rows)
        self.assertGreater(
            holder["known_component_subtotal"]["raw_bytes_upper"], inventory.GATE_A["raw_bytes"]
        )
        self.assertIsNone(holder["whole_raw_bytes_upper"])

    def test_count_table_requires_the_performing_call_and_rejects_settle_citation(self):
        from inference_platform.inf037b_eks_collectors import validate_count_sources

        self.assertTrue(validate_count_sources())
        with self.assertRaisesRegex(IntegrityError, "unsourced_count:TIME"):
            validate_count_sources(
                [
                    {
                        "count": "TIME",
                        "path": "inf037b_probe.py",
                        "method": "SingleProbe.run",
                        "call": "redis",
                    }
                ]
            )

    def test_record_families_include_unscheduled_error_and_close_artifacts(self):
        catalogue = inventory.source_inventory(separate_setup=True)
        sources = {s["name"]: s for s in catalogue["sources"]}
        self.assertIn("client.request_end", sources["client:gateway0"]["wire_record_families"])
        self.assertIn("http.conditional_request_json", sources["rbac"]["wire_record_families"])
        self.assertIn("redis.completed_reply", sources["redis"]["wire_record_families"])
        self.assertIn("watch.cutoff", sources["kubernetes"]["wire_record_families"])
        for source in sources.values():
            self.assertIn("owner.rejected_normalization", source["wire_record_families"])
            self.assertIn("close_descriptor", source["nonwire_artifacts"])
            self.assertIsNone(source["schedule"]["total_read_count_cap"])
        self.assertFalse(catalogue["complete"])

    def test_supplied_operational_budgets_do_not_become_derived_producer_limits(self):
        names = [s["name"] for s in inventory.source_inventory()["sources"]]
        report = inventory.capture_envelope(
            capture_budgets={n: {"raw_bytes": 7, "index_bytes": 31, "records": 2} for n in names}
        )
        audit = report["producer_limit_audit"]
        self.assertEqual(audit["refusal"], "capture:unresolved:producer_limits")
        self.assertEqual(
            {r["family"] for r in audit["missing"]},
            {"complete_scope_source_and_index_shapes"},
        )
        self.assertTrue(
            all(r["bytes_upper"] is None and r["records_upper"] is None for r in audit["missing"])
        )
        self.assertEqual(audit["known_read_caps"]["client_chunk"]["value"], 65536)
        self.assertIsNone(report["totals"]["wire_file_count"])

    def test_hand_computed_budgeted_envelope_and_spool_objects(self):
        result = inventory.source_envelope(
            "s", budget={"raw_bytes": 7, "index_bytes": 31, "records": 2}, owner_records=5
        )
        self.assertEqual(
            (result["raw_bytes_upper"], result["index_bytes_upper"], result["records_upper"]),
            (7, 31, 2),
        )
        self.assertEqual(result["integer_abs_upper"], 2**63)
        names = [e["name"] for e in inventory.source_inventory()["sources"]]
        budgets = {s: {"raw_bytes": 7, "index_bytes": 31, "records": 2} for s in names}
        report = inventory.capture_envelope(capture_budgets=budgets)
        self.assertEqual(
            report["known_owner_budget_totals"],
            {"raw_bytes": 119, "index_bytes": 527, "records": 34},
        )
        self.assertEqual(len(report["known_owner_spool_objects"]), 34)
        self.assertEqual(sum(o["bytes_upper"] for o in report["known_owner_spool_objects"]), 646)
        self.assertTrue(all(s["status"] == "bounded" for s in report["sources"]))
        self.assertIsNone(report["totals"]["wire_file_count"])

    def test_4e_producer_imports_inventory_and_emits_one_canonical_report(self):
        directory = Path(self.enterContext(TemporaryDirectory(prefix="r333-report-")))
        bindings, output = directory / "bindings.json", directory / "report.json"
        bindings.write_bytes(encode({"origins": list(ORIGINS)}))
        result = subprocess.run(
            [
                sys.executable,
                str(inventory.ROOT / "scripts/build_inf037b_capture_envelope.py"),
                "--bindings",
                str(bindings),
                "--output",
                str(output),
            ],
            capture_output=True,
            check=True,
        )
        self.assertEqual(result.stdout, b"")
        data = output.read_bytes()
        report = strict_json(data)
        self.assertEqual(data, encode(report))
        self.assertEqual(report["totals"]["known_wire_file_count"], 34)
        self.assertEqual(report["producer"]["path"], "scripts/build_inf037b_capture_envelope.py")
        self.assertIsNone(report["totals"]["wire_file_count"])

    def test_hand_computed_reads_partial_error_and_actual_encoder_overhead(self):
        # Three 10-byte reads, then one <=2-byte partial/error record: 32 bytes.
        result = inventory.source_envelope(
            "s",
            [
                {"kind": "normal", "read_cap_bytes": 10, "max_reads": 3, "metadata_json_bytes": 3},
                {
                    "kind": "partial/error",
                    "read_cap_bytes": 2,
                    "max_reads": 1,
                    "metadata_json_bytes": 14,
                },
            ],
            integer_abs_upper=99,
        )
        # Independent literal frame. Error metadata {"error":"x"}\n has 14
        # encoded bytes, 11 more than {}\n. Pay worst-case signed counter widths.
        frame = (
            b'{"end_ns":-99,"length":-99,"metadata":{},"offset":-99,"operation_sha256":"'
            + b"f" * 64
            + b'","sequence":-99,"sha256":"'
            + b"f" * 64
            + b'","source":"s","start_ns":-99}\n'
        )
        self.assertEqual(result["raw_bytes_upper"], 32)
        self.assertEqual(result["index_bytes_upper"], 4 * len(frame) + 11)
        self.assertEqual(result["components"][1]["index_record_bytes_upper"], len(frame) + 11)
        self.assertEqual(result["status"], "bounded")

    def test_empty_source_has_zero_bytes_but_two_files(self):
        result = inventory.source_envelope(
            "empty",
            [
                {
                    "kind": "empty",
                    "read_cap_bytes": None,
                    "max_reads": 0,
                    "metadata_json_bytes": None,
                },
            ],
        )
        self.assertEqual((result["raw_bytes_upper"], result["index_bytes_upper"]), (0, 0))
        self.assertEqual(len(inventory.wire_files(["empty"])["empty"]), 2)

    def test_missing_caps_remain_unbounded_and_partial_facts_survive(self):
        result = inventory.source_envelope(
            "s",
            [
                {"kind": "normal", "read_cap_bytes": 10, "max_reads": 2, "metadata_json_bytes": 3},
                {"kind": "error", "read_cap_bytes": 5, "max_reads": 1, "metadata_json_bytes": None},
            ],
            integer_abs_upper=99,
        )
        self.assertEqual(result["raw_bytes_upper"], 25)
        self.assertIsNone(result["index_bytes_upper"])
        self.assertEqual(result["status"], "unbounded")
        result["components"][0]["max_reads"] = None
        again = inventory.source_envelope("s", result["components"], integer_abs_upper=99)
        self.assertIsNone(again["raw_bytes_upper"])

    def test_invalid_and_inadequate_counter_bounds_refuse(self):
        for value in (-1, True, 0.5, float("nan")):
            with self.subTest(value=value), self.assertRaises(IntegrityError):
                inventory.source_envelope(
                    "s", [{"read_cap_bytes": value, "max_reads": 1, "metadata_json_bytes": 3}]
                )
        with self.assertRaisesRegex(IntegrityError, "counter_bound"):
            inventory.source_envelope(
                "s",
                [{"read_cap_bytes": 10, "max_reads": 100, "metadata_json_bytes": 3}],
                integer_abs_upper=99,
            )

    def test_caps_are_taken_from_current_readers_including_oversize_byte(self):
        caps = inventory.read_caps()
        self.assertEqual(caps["get"]["retained_body_cap"], 8_388_609)
        self.assertEqual(caps["watch"]["retained_body_cap"], 2**63)
        self.assertEqual(caps["client_chunk"]["value"], 65536)
        self.assertEqual(caps["client_denial"]["value"], 8193)
        for cap in caps.values():
            line = (
                (inventory.ROOT / cap["path"])
                .read_text(encoding="utf-8")
                .splitlines()[cap["line"] - 1]
            )
            self.assertTrue(line.strip())
            self.assertEqual(len(cap["source_lf_sha256"]), 64)

    def test_report_preserves_unknown_totals_and_only_compares_gate_a_as_data(self):
        report = strict_json(encode(inventory.capture_envelope()))
        self.assertEqual(report["schema"], "inf037b-capture-envelope-v1")
        self.assertEqual(
            report["totals"],
            {
                "raw_bytes_upper": None,
                "index_bytes_upper": None,
                "known_wire_file_count": 34,
                "wire_file_count": None,
                "whole_run_known_wire_file_count": 62,
                "whole_run_wire_file_count_expression": "62 plus 11 unresolved owner rows",
                "count_scope": report["inventory"]["count_scope"],
            },
        )
        self.assertTrue(all(s["status"] == "unbounded" for s in report["sources"]))
        comparison = report["gate_a_comparison_data_only"]
        self.assertEqual(comparison["known_object_count_difference"], 20)
        self.assertEqual(
            comparison["session4"],
            {"objects": 14, "raw_bytes": 1_618_864_547, "index_bytes": 9_119_066},
        )
        self.assertIsNone(comparison["fit_verdict"])
        self.assertIsNone(report["remeasurement_inputs"]["object_count_required"])


if __name__ == "__main__":
    unittest.main()
