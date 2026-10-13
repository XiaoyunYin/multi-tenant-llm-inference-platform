import ast
import json
import tempfile
import threading
import unittest
from abc import ABC, abstractmethod
from concurrent.futures import Future
from functools import lru_cache
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from inference_platform import stage_c_observer as observer
from inference_platform.stage_c_observer import (
    CADENCE_NS,
    Certificate,
    Continuity,
    Records,
    Refusal,
    Scan,
    ScanBudget,
    TwoSlotTransport,
    idle_reusable,
    readiness,
)
from inference_platform.stage_c_observer_adapter import (
    SourceStore,
    held_valid,
    integrate,
    physical_counts,
    queue_sample,
)

ROOT = Path(__file__).resolve().parents[2]
PIN = ROOT / ".cache/inf047-vllm-v0.29.0"
MS = 1_000_000


@lru_cache
def pinned_id_functions():
    """Execute the exact pinned header, random_uuid and assign_request_id bodies.

    Apache-2.0 vLLM source; imports/type hints alone are fixture dependencies.
    No reproduction of the request-ID implementation or forced random suffix.
    """
    import subprocess
    import uuid

    if not PIN.exists():
        raise unittest.SkipTest("Exact pinned checkout required for engine request-ID fixture")
    ns = {
        "uuid": uuid,
        "MASK_64_BITS": (1 << 64) - 1,
        "envs": SimpleNamespace(VLLM_DISABLE_REQUEST_ID_RANDOMIZATION=False),
    }
    for path, name, cls in (
        ("vllm/utils/__init__.py", "random_uuid", None),
        ("vllm/entrypoints/serve/engine/serving.py", "_base_request_id", "BaseServing"),
        ("vllm/v1/engine/input_processor.py", "assign_request_id", "InputProcessor"),
    ):
        data = subprocess.check_output(
            ["git", "-C", str(PIN), "show", observer.SOURCE_COMMIT + ":" + path]
        )
        if (PIN / path).read_bytes().replace(b"\r\n", b"\n") != data:
            raise AssertionError("Pinned request-ID source worktree differs")
        tree = ast.parse(data.decode())
        nodes = (
            tree.body
            if cls is None
            else next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == cls).body
        )
        method = next(n for n in nodes if isinstance(n, ast.FunctionDef) and n.name == name)
        method.decorator_list = []  # static method, called as its underlying function
        tree.body = [
            ast.ImportFrom(module="__future__", names=[ast.alias("annotations")], level=0),
            method,
        ]
        exec(compile(ast.fix_missing_locations(tree), str(PIN / path), "exec"), ns)
    return ns


def pinned_request_id(binding="r", endpoint="chatcmpl"):
    ns = pinned_id_functions()
    base = ns["_base_request_id"](SimpleNamespace(headers={"X-Request-Id": binding}), "ignored")
    # Pinned completion/serving.py appends the input ordinal even for one prompt.
    external = f"{endpoint}-{base}" + ("-0" if endpoint == "cmpl" else "")
    request = SimpleNamespace(request_id=external, external_req_id=None)
    ns["assign_request_id"](request)
    return request.request_id, request.external_req_id


def load_classes(path, names, namespace):
    import subprocess

    data = subprocess.check_output(
        ["git", "-C", str(PIN), "show", observer.SOURCE_COMMIT + ":" + path]
    )
    if (PIN / path).read_bytes().replace(b"\r\n", b"\n") != data:
        raise AssertionError("Pinned source worktree differs")
    source = data.decode("utf-8")
    tree = ast.parse(source)
    classes = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name in names]
    if len(classes) != len(names):
        raise AssertionError("Pinned class unavailable")
    # Exact original class AST bodies, including Future.result and executor
    # collective_rpc/execute_model. Only imports, worker and completion are CPU
    # fixture dependencies. No replacement implementation of either future.
    tree.body = [
        ast.ImportFrom(module="__future__", names=[ast.alias("annotations")], level=0),
        *classes,
    ]
    exec(compile(ast.fix_missing_locations(tree), str(PIN / path), "exec"), namespace)
    return namespace


def scan(identity=1, start=4 * MS, end=5 * MS, kind="ordinary", continuity=None):
    return Scan(
        identity,
        start,
        end,
        1,
        10,
        kind,
        continuity or Continuity((0, 0), 0, 0, 0),
        (),
        (),
        (),
        0,
        (),
    )


class Engine:
    def step_with_batch_queue(self):
        pass

    def step(self):
        pass


def engine():
    value = Engine()
    value.vllm_config = SimpleNamespace(
        scheduler_config=SimpleNamespace(async_scheduling=True), use_v2_model_runner=True
    )
    executor = type("UniProcExecutor", (), {})
    executor.__module__ = "vllm.v1.executor.uniproc_executor"
    value.model_executor = executor()
    value.batch_queue_size = 2
    value.step_fn = value.step_with_batch_queue
    return value


class BudgetAndCertificatesTest(unittest.TestCase):
    def test_independent_credits_same_and_next_slot(self):
        budget = ScanBudget(0)
        for kind, stamp, wait in (
            ("ordinary", 5 * MS, None),
            ("seed", 20 * MS, 1),
            ("idle", 32 * MS, None),
        ):
            self.assertTrue(budget.reserve(kind, stamp, wait))
        self.assertEqual(sum(n for (slot, _), n in budget.used.items() if slot == 0), 3)
        for kind in ("ordinary", "seed", "idle"):
            self.assertFalse(budget.reserve(kind, 95 * MS, 2 if kind == "seed" else None))
        self.assertTrue(budget.reserve("seed", 120 * MS, 3))
        self.assertFalse(budget.reserve("seed", 130 * MS, 3))
        self.assertEqual(budget.refusals, {"ordinary": 1, "seed": 1, "idle": 1, "wait": 1})

    def test_cross_slot_failed_attempt_no_refund(self):
        budget = ScanBudget(0)
        self.assertTrue(budget.reserve("seed", 99 * MS, 1))
        self.assertFalse(budget.reserve("seed", 99 * MS, 1))
        self.assertFalse(budget.reserve("seed", 99 * MS, 2))
        self.assertTrue(budget.reserve("seed", 120 * MS, 3))

    def test_same_slot_wait_held_edges_and_age(self):
        source = scan(start=19 * MS, end=20 * MS, kind="seed")
        cert = Certificate(1, "gpu", source, 20 * MS, 570 * MS)
        for stamp in (120, 220, 320, 420, 520):
            self.assertTrue(cert.contains(stamp * MS, 1, 10))
            self.assertGreaterEqual(stamp * MS - source.end, CADENCE_NS)
        self.assertTrue(cert.contains(20 * MS, 1, 10))
        for stamp, epoch, thread in (
            (19 * MS, 1, 10),
            (570 * MS, 1, 10),
            (320 * MS, 2, 10),
            (320 * MS, 1, 11),
        ):
            self.assertFalse(cert.contains(stamp, epoch, thread))
        cert.exit = None
        self.assertFalse(cert.contains(320 * MS, 1, 10))

    def test_handled_request_at_8ms_new_idle_credit_slots_1_to_19(self):
        budget = ScanBudget(0)
        previous = scan()
        self.assertTrue(budget.reserve("ordinary", previous.start))
        after_request = Continuity((0, 0), 1, 0, 0)
        self.assertFalse(idle_reusable(previous, after_request, (), True))
        self.assertTrue(budget.reserve("idle", int(8.1 * MS)))
        seed = scan(2, int(8.1 * MS), int(8.2 * MS), "idle", after_request)
        cert = Certificate(2, "idle", seed, int(8.2 * MS), 2000 * MS)
        self.assertTrue(all(cert.contains((slot * 100 + 20) * MS, 1, 10) for slot in range(1, 20)))
        self.assertFalse(budget.reserve("idle", 9 * MS))
        self.assertEqual(budget.refusals["idle"], 1)

    def test_trailing_step_10_to_30ms_unscanned_post_31ms_idle_32ms(self):
        previous = scan()
        cert = Certificate(2, "idle", previous, 32 * MS, 2000 * MS)
        self.assertTrue(idle_reusable(previous, previous.continuity, (), True))
        self.assertTrue(all(cert.contains((slot * 100 + 20) * MS, 1, 10) for slot in range(1, 20)))
        for continuity in (
            Continuity((1, 0), 0, 0, 0),
            Continuity((0, 0), 1, 0, 0),
            Continuity((0, 0), 0, 1, 0),
            Continuity((0, 0), 0, 0, 1),
        ):
            self.assertFalse(idle_reusable(previous, continuity, (), True))
        self.assertFalse(idle_reusable(previous, previous.continuity, (object(),), True))
        self.assertFalse(idle_reusable(previous, previous.continuity, (), False))

    def test_transport_capacity_order_and_nonblocking_loss(self):
        transport = TwoSlotTransport()
        a, b = transport.reserve(), transport.reserve()
        self.assertEqual((a, b), (0, 1))
        self.assertIsNone(transport.reserve())
        self.assertTrue(transport.publish(a, ("immutable", 1)))
        self.assertEqual(transport.take(), (a, ("immutable", 1)))
        self.assertIsNone(transport.take())
        self.assertIsNone(transport.reserve())
        transport.release(a)
        self.assertEqual(transport.reserve(), a)
        with transport.lock:
            self.assertFalse(transport.publish(b, ("lost", 2)))
            self.assertIsNone(transport.reserve())
        self.assertEqual(transport.states[b], "WRITING")
        self.assertEqual(transport.reserve(), b)  # reclaim the failed publication
        self.assertEqual(transport.states[b], "WRITING")  # now reserved again
        self.assertNotIn(b, transport.abandoned)

    def test_metadata_queue_exhaustion_and_contention(self):
        records = Records(1)
        self.assertTrue(records.put((1,)))
        self.assertFalse(records.put((2,)))
        self.assertEqual(records.drain(), ((1,),))
        with records.lock:
            self.assertFalse(records.put((3,)))


class FutureAndReadinessTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not PIN.exists():
            raise unittest.SkipTest(
                "Exact local vLLM source is not installed; no GPU import substitute"
            )
        cls.ns = {"__name__": "pinned_cpu_fixture", "ABC": ABC, "abstractmethod": abstractmethod}
        load_classes("vllm/v1/outputs.py", {"AsyncModelRunnerOutput"}, cls.ns)
        cls.ns.update(
            Future=Future,
            Executor=object,
            Any=Any,
            run_method=lambda worker, method, args, kwargs: getattr(worker, method)(
                *args, **kwargs
            ),
        )
        load_classes(
            "vllm/v1/executor/uniproc_executor.py", {"AsyncOutputFuture", "UniProcExecutor"}, cls.ns
        )

    def test_real_resolved_future_from_pinned_executor(self):
        cls = self.ns["UniProcExecutor"]
        executor = cls()
        output = object()
        executor.driver_worker = SimpleNamespace(execute_model=lambda _: output)
        future = executor.execute_model(None, non_block=True)
        self.assertIs(type(future), Future)
        self.assertTrue(future.done())
        self.assertIs(future.result(), output)
        self.assertFalse(hasattr(future, "async_output"))

    def test_real_async_future_blocks_in_interface_get_output_and_closes_first(self):
        completion, entered = threading.Event(), threading.Event()
        trace = []
        base = self.ns["AsyncModelRunnerOutput"]

        class ControlledOutput(base):
            def get_output(self):
                entered.set()
                if not completion.wait(3):
                    raise AssertionError("fixture completion timeout")
                trace.append("get_output")
                return "output"

        future = self.ns["AsyncOutputFuture"](ControlledOutput(), True)

        def engine_wait():
            try:
                self.assertEqual(future.result(), "output")
            finally:
                trace.append("exit")
            trace.append("output/abort handling")

        thread = threading.Thread(target=engine_wait)
        thread.start()
        self.assertTrue(entered.wait(2))
        self.assertFalse(future.done())
        self.assertEqual(trace, [])
        completion.set()
        thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(trace, ["get_output", "exit", "output/abort handling"])
        self.assertEqual(future.result(), "output")

    def test_readiness_five_values_and_each_refusal(self):
        value = engine()
        self.assertEqual(len(readiness(value, observer.V2_OUTPUT)), 5)
        changes = (
            lambda v: setattr(v.vllm_config.scheduler_config, "async_scheduling", False),
            lambda v: setattr(v, "batch_queue_size", 1),
            lambda v: setattr(v, "model_executor", object()),
            lambda v: setattr(v, "step_fn", v.step),
            lambda v: setattr(v.vllm_config, "use_v2_model_runner", False),
        )
        for change in changes:
            with self.subTest(change=change):
                value = engine()
                change(value)
                with self.assertRaises(Refusal):
                    readiness(value, observer.V2_OUTPUT)
        for cls in (None, "vllm.v1.worker.gpu_model_runner.AsyncGPUModelRunnerOutput"):
            with self.assertRaises(Refusal):
                readiness(engine(), cls)


class ProjectionTest(unittest.TestCase):
    def test_all_five_registered_integral_cases(self):
        for left, right, q, expected in (
            (20, 120, 2, 200_000_000),
            (420, 520, 3, 300_000_000),
            (620, 720, 4, 400_000_000),
        ):
            rows = [(left // 100, left * MS, q, True, 1), (right // 100, right * MS, 9, True, 1)]
            self.assertEqual(integrate(rows, start=0, end=2000 * MS), (expected, 100 * MS, 0))
        for valid in (False, True):
            # Explicit invalid/missing slot, or an omitted slot: neither bridges.
            rows = [(8, 820 * MS, 2, True, 1), (10, 1020 * MS, 9, True, 1)]
            if not valid:
                rows.insert(1, (9, 920 * MS, None, False, 1))
            self.assertEqual(integrate(rows, start=0, end=2000 * MS), (0, 0, 200 * MS))
        rows = [(0, 20 * MS, 2, True, 1), (1, 120 * MS, 7, True, 1)]
        from inference_platform.stage_c_registered import vector

        encoded, valid = vector([[r[1], r[2], r[3]] for r in rows], 0, 200 * MS)
        self.assertTrue(valid)
        self.assertEqual(int.from_bytes(encoded[-24:-8], "little"), 200_000_000)
        self.assertEqual(int.from_bytes(encoded[-8:], "little"), 100 * MS)

    def test_exposure_and_quantity_validity(self):
        for rows in (
            [(0, 20 * MS, 2, True, 1)],
            [(0, 20 * MS, 2, True, 1), (1, 120 * MS, 9, True, 2)],
            [(0, 20 * MS, 2, False, 1), (1, 120 * MS, 9, True, 1)],
        ):
            self.assertEqual(integrate(rows, start=0, end=200 * MS)[1], 0)

    def test_delayed_adapter_and_changing_queue(self):
        source = [319 * MS, 320 * MS, 321 * MS, 3]
        before = queue_sample(source, 0, 3)
        self.assertEqual(before["queue_age_ns"], MS)
        for _consumed in (322 * MS, 600_000 * MS):
            self.assertEqual(queue_sample(source, 0, 3), before)
        self.assertEqual(queue_sample([419 * MS, 420 * MS, 421 * MS, 7], 0, 4)["queue_depth"], 7)
        for invalid in (
            [319 * MS, 318 * MS, 321 * MS, 3],
            [399 * MS, 400 * MS, 401 * MS, 3],
            [319 * MS, 320 * MS, 401 * MS, 3],
            None,
        ):
            self.assertIsNone(queue_sample(invalid, 0, 3))

    def test_held_resolution_requires_closed_exact_identity(self):
        source = {"identity": 1, "start": 19 * MS, "end": 20 * MS, "epoch": 1, "thread": 10}
        cert = {"scan_id": 1, "entry": 20 * MS, "exit": 570 * MS, "epoch": 1, "thread": 10}
        self.assertTrue(held_valid(source, cert, 320 * MS, 0, 3))
        for key, value in (
            ("scan_id", 2),
            ("entry", 321 * MS),
            ("exit", None),
            ("epoch", 2),
            ("thread", 11),
        ):
            changed = {**cert, key: value}
            self.assertFalse(held_valid(source, changed, 320 * MS, 0, 3))

    def test_physical_partition_unscheduled_shared_private_and_null(self):
        key = (bytes.fromhex("01" * 32) + bytes(4)).hex()
        private = (bytes.fromhex("02" * 32) + bytes(4)).hex()
        physical = [[i, 0, 0, i == 0, [], i != 0, None] for i in range(3891)]
        physical[1] = [1, 3, 2, False, [key], False, [0, 0, 32, key, "prompt", 0]]
        physical[2] = [2, 1, 1, False, [], False, None]
        owners = [
            ["a", 0, 0, 1, True, key, 32],
            ["b", 1, 0, 1, False, key, 32],
            ["a", 0, 1, 2, True, private, 32],
        ]
        domain = observer.NativeDomain({key: {"in_W": True}, private: {"in_W": False}})
        source = {"physical": physical, "owners": owners, "end": 1}
        external = int.from_bytes(bytes.fromhex(key)[:-4], "big") & ((1 << 64) - 1)
        result = physical_counts(source, domain, {external})
        self.assertEqual((result["shared"], result["non_shared"], result["capacity"]), (1, 1, 3890))
        self.assertEqual(result["unscheduled_holder_n"], 1)
        self.assertEqual(result["reserved_null"], 1)
        self.assertEqual(result["evictable"], 0)
        self.assertIsNone(physical_counts(source, domain, None)["cached"])
        physical[2][2] += 1
        with self.assertRaisesRegex(Refusal, "retention"):
            physical_counts(source, domain, {external})

    def test_exact_following_prefix_and_mixed_post_return_events(self):
        lines = [
            {
                "kind": "batch",
                "token": 1,
                "sequence": 0,
                "error": False,
                "prefixes": [],
                "events": [["AllBlocksCleared", [], None]],
            },
            {
                "kind": "batch",
                "token": 2,
                "sequence": 1,
                "error": False,
                "prefixes": [[1, 1, True]],
                "events": [["BlockStored", [5], 0], ["BlockStored", [7], 0]],
            },
            {"kind": "receipt", "loss": {}, "first_failure": None},
        ]
        lines.extend(
            {"kind": "subscriber", "sequence": row["sequence"], "events": row["events"]}
            for row in list(lines)
            if row["kind"] == "batch"
        )
        with tempfile.TemporaryDirectory() as directory:
            store = SourceStore(Path(directory) / "rows.db", quota_bytes=1_000_000)
            try:
                store.ingest(json.dumps(row).encode() for row in lines)
                source = {"identity": 1, "pending_count": 1, "preceding_token": 1}
                self.assertEqual(store.event_join(source), ([5], 1))
                self.assertEqual(store.event_join({**source, "identity": 2}), (None, None))
                self.assertEqual(
                    store.event_join({**source, "pending_count": 0, "preceding_token": 2}),
                    ([5, 7], 1),
                )
            finally:
                store.close()

    def test_source_failure_duplicate_and_quota_refuse(self):
        for rows, quota in (
            ([], 1000),
            ([{"kind": "receipt", "loss": {"drop": 1}, "first_failure": None}], 1000),
            ([{"kind": "receipt", "loss": {}, "first_failure": None}], 1),
        ):
            with tempfile.TemporaryDirectory() as directory:
                store = SourceStore(Path(directory) / "rows.db", quota_bytes=quota)
                try:
                    with self.assertRaises(Refusal):
                        store.ingest(json.dumps(row).encode() for row in rows)
                finally:
                    store.close()


class OwnerCaptureIntegrationTest(unittest.TestCase):
    def make_observer(self):
        from unittest.mock import patch

        import test_observer_decode_source_stop as source

        module = source.cpu_module()
        blocks = [module.KVCacheBlock(i) for i in range(3891)]
        blocks[0].is_null = True
        head, tail = SimpleNamespace(), SimpleNamespace()
        head.next_free_block = blocks[1]
        for left, right in zip(blocks[1:], [*blocks[2:], tail], strict=True):
            left.next_free_block = right
        pool = SimpleNamespace(
            blocks=blocks,
            hash_block_size=16,
            enable_kv_cache_events=True,
            kv_event_queue=[],
            cached_block_hashes_by_block={},
            free_block_queue=SimpleNamespace(
                fake_free_list_head=head, fake_free_list_tail=tail, num_free_blocks=3890
            ),
        )
        manager = SimpleNamespace(
            req_to_blocks={}, _pending_cow_copies=[], _pending_boundary_state_offloads=[]
        )
        value = engine()
        value.scheduler = SimpleNamespace(
            requests={},
            deferred_frees=[],
            kv_cache_manager=SimpleNamespace(
                block_pool=pool, coordinator=SimpleNamespace(single_type_managers=[manager])
            ),
        )
        self.stamp = 5 * MS
        manifest = {
            "cadence_start_ns": 0,
            "patched_slots": [0, 18000],
            "reset_epoch": 1,
            "native_domain": {},
            "requests": {"chatcmpl-r": {"per_request_index": 0, "prompt_tokens": 17}},
        }
        # This CPU fixture bypasses serving-file/positive-activation inspection
        # only. It executes the producer's real capture and transport methods.
        with patch.object(observer.StageCObserver, "validate_manifest", lambda _: None):
            result = observer.StageCObserver(value, manifest, clock=lambda: self.stamp)
        return result, pool, manager

    def test_patched_reset_preserves_native_result_exception_and_call_count(self):
        import importlib.util
        import subprocess

        if not PIN.exists():
            self.skipTest("Exact pinned checkout required for overlay method fixture")
        spec = importlib.util.spec_from_file_location(
            "overlay_builder", ROOT / "scripts/build_stage_c_observer_overlay.py"
        )
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        pristine = {
            p: subprocess.check_output(
                ["git", "-C", str(PIN), "show", observer.SOURCE_COMMIT + ":" + p]
            ).decode()
            for p in builder.FILES
        }
        tree = ast.parse(builder.patches(pristine)[builder.FILES[0]])
        cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "EngineCore")
        method = next(
            n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "reset_prefix_cache"
        )
        trace = []
        namespace = {"_stage_c": SimpleNamespace(call=lambda *args: trace.append(args))}
        exec(
            compile(
                ast.fix_missing_locations(ast.Module(body=[method], type_ignores=[])),
                "pinned_reset_overlay",
                "exec",
            ),
            namespace,
        )
        failure = RuntimeError("native failure")
        for outcome in (True, False, failure):
            trace.clear()
            calls = []

            def native(*args, case=outcome, observed=calls):
                observed.append(args)
                if case is failure:
                    raise failure
                return case

            engine = SimpleNamespace(scheduler=SimpleNamespace(reset_prefix_cache=native))
            if outcome is failure:
                with self.assertRaises(RuntimeError) as caught:
                    namespace["reset_prefix_cache"](engine, True, False)
                self.assertIs(caught.exception, failure)
                self.assertEqual(trace[-1], ("reset_result", None, True))
            else:
                self.assertIs(namespace["reset_prefix_cache"](engine, True, False), outcome)
                self.assertEqual(trace[-1], ("reset_result", outcome, False))
            self.assertEqual(calls, [(True, False)])
            self.assertEqual(trace[0], ("observe_reset",))

    def test_primary_native_hash_and_generated_provenance_survive_owner_release(self):
        value, pool, manager = self.make_observer()
        full = bytes.fromhex(GeneratedDomainTest.full())
        request = SimpleNamespace(request_id=pinned_request_id()[0], num_prompt_tokens=17)
        block = pool.blocks[1]
        block.set_block_hash(full, num_tokens=32)
        value.observe_cache(pool, request, 1, block, full)
        snapshot = value.capture("ordinary")
        self.assertIsNotNone(snapshot)
        index, (_, complete) = value.transport.take()
        try:
            row = observer.scan_to_row(complete)
            self.assertEqual(row["physical"][1][4], [full.hex()])
            self.assertEqual(row["physical"][1][6][1:3], (1, 17))
            self.assertEqual(physical_counts(row, value.domain, {7})["evictable"], 1)
        finally:
            value.transport.release(index)
        records = value.records.drain()
        self.assertEqual(records[0]["kind"], "provenance")
        self.assertEqual(value.insertion_checks, 1)

    def test_real_capture_budget_and_wrong_thread_fail_closed(self):
        value, _pool, _manager = self.make_observer()
        self.assertIsNotNone(value.capture("ordinary"))
        self.assertIsNone(value.capture("ordinary"))
        self.assertIsNotNone(value.capture("seed", 1))
        self.assertIsNone(value.capture("idle"))  # both transport slots unread
        self.assertIsNone(value.capture("idle"))  # spent credit, no retry
        self.assertEqual(value.gaps[0, "snapshot_buffer"], 1)
        self.assertEqual(value.loss, {})
        self.assertEqual(sum(value.budget.used.values()), 3)
        errors = []

        def wrong_thread():
            try:
                value.capture("ordinary")
            except Refusal as exc:
                errors.append(str(exc))

        thread = threading.Thread(target=wrong_thread)
        thread.start()
        thread.join(2)
        self.assertEqual(errors, ["owner_thread"])

    def test_source_store_fresh_precedence_and_valid_held_fallback(self):
        import copy

        full = GeneratedDomainTest.full()
        empty = [[i, 0, 0, i == 0, [], i != 0, None] for i in range(3891)]
        base = {
            "identity": 1,
            "start": 4 * MS,
            "end": 5 * MS,
            "epoch": 1,
            "thread": 10,
            "scan_kind": "ordinary",
            "physical": empty,
            "owners": [],
            "pending_count": 0,
            "preceding_token": 1,
        }
        generated = copy.deepcopy(empty)
        provenance = [0, 384, 6144, full, "generated", 10 * MS]
        generated[1] = [1, 1, 0, False, [full], True, provenance]
        seed = {
            **base,
            "identity": 2,
            "start": 19 * MS,
            "end": 20 * MS,
            "scan_kind": "seed",
            "physical": generated,
            "pending_count": 1,
        }
        for invalid_fresh in (False, True):
            fresh = copy.deepcopy(base)
            if invalid_fresh:
                fresh["physical"][2][2] = 1  # unexplained positive reference
            batches = [
                {
                    "kind": "batch",
                    "token": 1,
                    "sequence": 0,
                    "error": False,
                    "prefixes": [],
                    "events": [["AllBlocksCleared", [], None]],
                },
                {
                    "kind": "batch",
                    "token": 2,
                    "sequence": 1,
                    "error": False,
                    "prefixes": [[2, 1, True]],
                    "events": [["BlockStored", [7], 0]],
                },
            ]
            rows = [
                *batches,
                {"kind": "scan", "scan": fresh},
                {
                    "kind": "provenance",
                    "physical_id": 1,
                    "generation": 1,
                    "epoch": 1,
                    "provenance": provenance,
                    "cost_ns": 2,
                },
                {"kind": "scan", "scan": seed},
                {
                    "kind": "entry",
                    "id": 1,
                    "scan_id": 2,
                    "entry": 20 * MS,
                    "epoch": 1,
                    "thread": 10,
                },
                {"kind": "exit", "id": 1, "exit": 570 * MS, "epoch": 1, "thread": 10},
                {
                    "kind": "slot",
                    "slot": 0,
                    "scan_id": 2,
                    "certificate": 1,
                    "observed_ns": 30 * MS,
                    "queue": [30 * MS, 31 * MS, 32 * MS, 4],
                },
                {"kind": "receipt", "loss": {}, "first_failure": None},
            ]
            rows.extend(
                {"kind": "subscriber", "sequence": b["sequence"], "events": b["events"]}
                for b in batches
            )
            with self.subTest(invalid_fresh=invalid_fresh), tempfile.TemporaryDirectory() as d:
                store = SourceStore(Path(d) / "source.db", quota_bytes=4_000_000)
                try:
                    store.ingest(json.dumps(row).encode() for row in rows)
                    result = list(
                        store.observations(origin=0, first_slot=0, last_slot=0, epoch=1, phase=0)
                    )[0]
                    self.assertEqual(result["counts"]["cached"], int(invalid_fresh))
                    self.assertEqual(result["observed_ns"], (30 if invalid_fresh else 5) * MS)
                    self.assertEqual(result["status"], 0)
                finally:
                    store.close()

    def test_failed_or_undelivered_clear_never_repairs_event_join(self):
        for error, delivered in ((True, True), (False, False)):
            with self.subTest(error=error, delivered=delivered), tempfile.TemporaryDirectory() as d:
                store = SourceStore(Path(d) / "source.db", quota_bytes=1_000_000)
                batch = {
                    "kind": "batch",
                    "token": 1,
                    "sequence": 0,
                    "error": error,
                    "prefixes": [],
                    "events": [["AllBlocksCleared", [], None]],
                }
                rows = [batch, {"kind": "receipt", "loss": {}, "first_failure": None}]
                if delivered:
                    rows.append({"kind": "subscriber", "sequence": 0, "events": batch["events"]})
                try:
                    store.ingest(json.dumps(row).encode() for row in rows)
                    self.assertIsNone(
                        store.event_join({"preceding_token": 1, "pending_count": 0})[0]
                    )
                finally:
                    store.close()


class SerializerIntegrationTest(unittest.TestCase):
    def test_observations_keep_control_and_roundtrip_existing_digest(self):
        from remainder_fixtures import fixture

        from inference_platform.stage_c_observer_adapter import (
            attach_observations,
            seal_observations,
        )
        from inference_platform.stage_c_registered import recover_registered

        run = fixture(4)
        original_control = run["exposures"][:24]
        observations = []
        for witness in run["snapshot_count_sources"]:
            value = {k: witness.get(k, 0) for k in observer_fields()}
            queue = {
                k: witness[k]
                for k in ("queue_depth", "queue_read_ns", "queue_read_cost_ns", "queue_age_ns")
            }
            queue["observed_ns"] = witness["observed_ns"]
            observations.append(
                {
                    **witness,
                    "invalid_reason": None,
                    "counts": value,
                    "queue": queue,
                    "values": {**value, "queue": queue["queue_depth"]},
                }
            )
        attached = attach_observations(run, observations)
        self.assertEqual(attached["exposures"][:24], original_control)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "run-4.digest.json.gz"
            seal_observations(path, run, observations)
            self.assertLessEqual(path.stat().st_size, 1048576)
            recovered = recover_registered(path.read_bytes())
            snapshots = recovered["snapshot_counts"]
            self.assertEqual(len(snapshots), 5)
            self.assertEqual(
                [r["queue_age_ns"] for r in snapshots],
                [r["queue"]["queue_age_ns"] for r in observations],
            )


def observer_fields():
    return (
        "cached",
        "shared",
        "non_shared",
        "evictable",
        "capacity",
        "reserved_null",
        "active_physical",
        "event_live",
        "owner_link_n",
        "unscheduled_holder_n",
    )


class BytecodeGateTest(unittest.TestCase):
    def test_unchecked_shadow_runs_old_code_and_gate_refuses_until_masked(self):
        import importlib.util
        import py_compile
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "target.py"
            source.write_text("executed = 'old'\n", encoding="utf-8")
            cache = Path(
                py_compile.compile(
                    str(source),
                    doraise=True,
                    invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
                )
            )
            source.write_text("executed = 'patched'\n", encoding="utf-8")
            spec = importlib.util.spec_from_file_location("toy_shadow", source)
            module = importlib.util.module_from_spec(spec)
            with patch("sys.dont_write_bytecode", True):
                spec.loader.exec_module(module)
                self.assertEqual(module.executed, "old")
                receipt = observer.bytecode_receipt([source])
                self.assertEqual(receipt[0]["caches"][0]["flags"], 1)
                with self.assertRaisesRegex(Refusal, "bytecode_shadow"):
                    observer.require_source_imports([source])
                cache.unlink()  # simulate an empty effective cache view
                self.assertEqual(observer.require_source_imports([source])[0]["caches"], [])
                spec.loader.exec_module(module)
                self.assertEqual(module.executed, "patched")
                self.assertFalse(cache.exists())
            with patch("sys.dont_write_bytecode", False):
                with self.assertRaisesRegex(Refusal, "writes_enabled"):
                    observer.require_source_imports([source])

    def test_malformed_flags_missing_source_and_alternate_prefix(self):
        import importlib.util
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "target.py"
            source.write_text("pass\n", encoding="utf-8")
            legacy = source.with_suffix(".pyc")
            legacy.write_bytes(importlib.util.MAGIC_NUMBER + (2).to_bytes(4, "little") + bytes(8))
            with self.assertRaisesRegex(Refusal, "bytecode_flags"):
                observer.bytecode_receipt([source])
            legacy.unlink()
            with patch("sys.pycache_prefix", str(Path(directory) / "alternate")):
                alternate = Path(importlib.util.cache_from_source(str(source)))
                alternate.parent.mkdir(parents=True)
                alternate.write_bytes(importlib.util.MAGIC_NUMBER + bytes(12))
                self.assertEqual(observer.bytecode_receipt([source])[0]["caches"][0]["flags"], 0)
            with self.assertRaisesRegex(Refusal, "missing_source"):
                observer.bytecode_receipt([Path(directory) / "absent.py"])

    def test_writable_overlay_import_creates_cache_and_breaks_tree_identity(self):
        import hashlib
        import os
        import subprocess
        import sys

        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "target.py"
            source.write_text("pass\n", encoding="utf-8")
            before = {
                p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                for p in Path(directory).rglob("*")
                if p.is_file()
            }
            subprocess.run(
                [sys.executable, "-c", "import target"],
                cwd=directory,
                check=True,
                env={
                    key: value
                    for key, value in os.environ.items()
                    if key != "PYTHONDONTWRITEBYTECODE"
                },
            )
            after = {
                p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                for p in Path(directory).rglob("*")
                if p.is_file()
            }
            self.assertNotEqual(before, after)
            self.assertTrue(any(name.endswith(".pyc") for name in after))


class GeneratedDomainTest(unittest.TestCase):
    @staticmethod
    def full(prefix=1, key=7):
        return (prefix.to_bytes(24, "big") + key.to_bytes(8, "big") + bytes(4)).hex()

    def test_generated_unowned_evictable_and_missing_prompt(self):
        full = self.full()
        domain = observer.NativeDomain({})
        self.assertEqual(domain.insertion(full, 0, 384, 6144, 10), "generated")
        physical = [[i, 0, 0, i == 0, [], i != 0, None] for i in range(3891)]
        physical[1] = [1, 1, 0, False, [full], True, [0, 384, 6144, full, "generated", 10]]
        source = {"physical": physical, "owners": [], "end": 20}
        counts = physical_counts(source, domain, {7})
        self.assertEqual((counts["cached"], counts["evictable"], counts["non_shared"]), (1, 1, 0))
        # Non-W membership remains known after the owner is gone; active pins
        # remain zero, as the registered non_shared quantity requires.
        self.assertIs(domain.membership(full, 20, generated=True), False)
        self.assertEqual(domain.insertion(self.full(2, 8), 0, 0, 6144, 21), "unknown")
        physical[1][4] = [self.full(2, 8)]
        physical[1][6] = [0, 0, 6144, self.full(2, 8), "unknown", 21]
        source["end"] = 22
        with self.assertRaisesRegex(Refusal, "native_identity"):
            physical_counts(source, domain, {8})

    def test_both_collision_families_forward_only_and_persistent(self):
        frozen, generated = self.full(1), self.full(2)
        for mapping in ({frozen: {"in_W": True}}, {}):
            with self.subTest(frozen=bool(mapping)):
                domain = observer.NativeDomain(mapping)
                if not mapping:
                    self.assertEqual(domain.insertion(frozen, 0, 384, 6144, 10), "generated")
                self.assertEqual(domain.insertion(generated, 1, 384, 6144, 30), "collision")
                self.assertEqual(domain.collisions, 1)
                # A buffered earlier boundary remains valid after replaying
                # the later collision; a later boundary never repairs it.
                self.assertTrue(domain.key_valid(frozen, 29))
                self.assertFalse(domain.key_valid(frozen, 30))
                self.assertFalse(domain.key_valid(generated, 1000))
                domain.insertion(frozen, 0, 384, 6144, 40)
                self.assertFalse(domain.key_valid(frozen, 50))

    def test_identical_suffix_and_preemption_recache_alias(self):
        full = self.full()
        domain = observer.NativeDomain({})
        statuses = [
            domain.insertion(full, index, 384, 6144, stamp)
            for index, stamp in ((0, 10), (1, 20), (0, 30))
        ]
        self.assertEqual(statuses, ["generated", "alias", "alias"])
        self.assertEqual((domain.count, domain.aliases, domain.collisions), (1, 2, 0))
        self.assertEqual(len(domain.store), 16 * 1024 * 1024)
        self.assertEqual(observer.GENERATED_ROW.size, 64)

    def test_session_request_and_map_overflow_latch_without_growth(self):
        domain = observer.NativeDomain({}, limit=1, slots=4)
        a, b = self.full(1, 0), self.full(2, 4)  # open-address probe wrap
        domain.insertion(a, 0, 384, 6144, 10)
        before = bytes(domain.store)
        self.assertEqual(domain.insertion(b, 1, 384, 6144, 20), "overflow")
        self.assertEqual(bytes(domain.store), before)
        self.assertEqual(domain.count, 1)
        self.assertTrue(domain.key_valid(a, 19))
        self.assertFalse(domain.key_valid(a, 20))
        self.assertEqual(domain.insertion(a, 0, 393, 6144, 30), "overflow")
        self.assertEqual(domain.insertion(a, 14261, 384, 6144, 40), "overflow")
        self.assertFalse(domain.key_valid(a, 1000))

    def test_unaligned_boundary_is_generated_and_prompt_lookup_is_full_width(self):
        prompt, boundary = self.full(1, 1), self.full(2, 2)
        domain = observer.NativeDomain({prompt: {"in_W": True}})
        self.assertEqual(domain.insertion(prompt, 0, 0, 17, 10), "prompt")
        self.assertEqual(domain.insertion(boundary, 0, 1, 17, 11), "generated")
        self.assertEqual(domain.insertion(self.full(3, 1), 0, 0, 17, 12), "unknown")
        self.assertEqual(domain.collisions, 0)  # unknown prompt cannot become generated
        self.assertIsNone(domain.membership(self.full(3, 1), 12))

    def test_host_replays_provenance_and_rejects_forgery_or_loss(self):
        full = self.full()
        row = {
            "kind": "provenance",
            "physical_id": 1,
            "generation": 3,
            "epoch": 1,
            "provenance": [0, 384, 6144, full, "generated", 10],
            "cost_ns": 2,
        }
        with tempfile.TemporaryDirectory() as directory:
            store = SourceStore(Path(directory) / "source.db", quota_bytes=1_000_000)
            try:
                store.ingest(
                    json.dumps(r).encode()
                    for r in (row, {"kind": "receipt", "loss": {}, "first_failure": None})
                )
                self.assertEqual(store.domain.count, 1)
                source = {"physical": [[1, 3, 0, False, [full], True, row["provenance"]]]}
                store.verify_provenance(source)
                source["physical"][0][1] = 4
                with self.assertRaisesRegex(Refusal, "provenance_join"):
                    store.verify_provenance(source)
            finally:
                store.close()

    def test_pinned_cache_hook_classifies_actual_decode_boundary(self):
        # Execute the exact pinned caching body with the same insertion made
        # by the overlay builder. The six original regressions stay unchanged.
        import test_observer_decode_source_stop as source

        module = source.cpu_module()
        snippets = source.source_fixture()["files"]["vllm/v1/core/block_pool.py"]["snippets"]
        body = snippets["BlockPool.cache_full_blocks"]["text"]
        needle = "            if new_hashes is not None:"  # preserve native call order
        body = body.replace(
            needle,
            '            _stage_c.call("observe_cache", self, request, num_cached_blocks + i, '
            "blk, block_hash_with_group_id)\n" + needle,
        )
        calls = []
        module._stage_c = SimpleNamespace(call=lambda *args: calls.append(args))
        exec("from __future__ import annotations\nclass Hooked:\n" + body, module.__dict__)
        module.BlockPool.cache_full_blocks = module.Hooked.cache_full_blocks
        request, scheduler, pool = source.request_and_scheduler(module, prompt_tokens=17)
        self.assertEqual(calls[-1][3], 0)
        source.decode(request, scheduler, [2000] * 16)
        self.assertEqual(calls[-1][3], 1)
        full = calls[-1][-1]
        domain = observer.NativeDomain({})
        self.assertEqual(domain.insertion(full, 0, calls[-1][3], 17, 10), "generated")
        self.assertEqual(
            pool.kv_event_queue[-1].block_hashes, [module.maybe_convert_block_hash(full[:-4])]
        )


if __name__ == "__main__":
    unittest.main()
