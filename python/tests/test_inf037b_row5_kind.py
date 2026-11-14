"""Linux retained row 5 composition, with transport fakes and unchanged checkers."""

import copy
import importlib
import json
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import Mock, patch

from inference_platform.inf037b_archive import IntegrityError, encode, sha, strict_json
from inference_platform.inf037b_live import GatewayAdapter, LiveRows


class KindTests(unittest.TestCase):
    def setUp(self):
        # Keep discovery working on the old revision: every test must fail there.
        self.kind = importlib.import_module("inference_platform.inf037b_row5_kind")

    def fixture(self, *, initial_tick=True, start_window=True):
        from test_inf037b_row5_live import LiveTests

        helper = LiveTests()
        f = helper.sequence()
        # Reuse the live helper's role/clock, but remove its sequencing checker mocks.
        f.doCleanups()
        self.addCleanup(helper.doCleanups)
        directory = self.enterContext(TemporaryDirectory())
        fixture = TransportFixture(self, Path(directory), f, initial_tick=initial_tick)
        if start_window:
            fixture.clock.sleep(0.01)
            fixture.ports.start_window()
        return fixture

    def _validate_with_raw_mutation(self, fixture, result, mutate):
        candidate = copy.deepcopy(result)
        raw = strict_json(candidate["fitness_raw"])
        mutate(raw["raw"])
        candidate["fitness_raw"] = encode(raw)
        return self.kind.validate_kind_row5(
            candidate,
            fixture.ports.live.row5_stage.requests,
            configuration_sha256="a" * 64,
            binding=fixture.binding,
        )

    def _validate_control_evidence_with_row_mutation(self, fixture, result, mutate):
        from inference_platform.inf037b_row5_capture import select_row5_snapshots
        from inference_platform.inf037b_setup_fitness import fitness_request_joins
        from inference_platform.inf037b_sources import SourceJoin

        raw = strict_json(result["fitness_raw"])
        joined = SourceJoin(raw["raw"])
        self.assertFalse(joined.errors)
        snapshots = select_row5_snapshots(joined.rows)
        _, controls = fitness_request_joins(
            joined.rows,
            [],
            fixture.ports.live.row5_stage.requests,
            max(row["time_ms_bounds"][1] for row in joined.rows),
        )
        mutate(joined.rows)
        return self.kind.validate_control_evidence(
            result["row5_evidence"],
            fixture.ports.live.row5_stage.requests,
            configuration_sha256="a" * 64,
            binding=fixture.binding,
            snapshots=snapshots,
            rows=joined.rows,
            control_cohorts=controls.cohorts,
        )

    def test_one_owner_sealed_configuration_clocks_and_absolute_sample(self):
        f = self.fixture()
        ports = f.ports
        self.assertTrue(f.configuration_owner.closed)
        self.assertEqual(ports.owner.attempt, "setup")
        self.assertEqual(ports.owner.stages, [1, 2, 3, 4, 5])
        self.assertEqual(
            set(ports.owner.sources),
            {
                "gateway0",
                "gateway1",
                "client:gateway0",
                "client:gateway1",
                "redis",
                "diagnostic",
                "rbac",
                "clocks",
            },
        )
        before = time.monotonic_ns() // 1_000_000
        self.assertLessEqual(before, ports.sample())
        self.assertLessEqual(ports.sample(), time.monotonic_ns() // 1_000_000)
        ports.poll_clocks()
        self.assertEqual(
            {r["payload"]["clock_id"] for r in ports.owner.clock_rows},
            {"redis", "gateway0", "gateway1"},
        )
        self.assertTrue(all("clock=1" in p for p in f.clock_paths))
        self.assertEqual([a.offset for a in ports.live.gateways.values()], [0, 0])

    def test_early_edge_is_excluded_before_normalization_and_kind_join_passes(self):
        f = self.fixture(initial_tick=False, start_window=False)
        f.tick(poll_clocks=False)
        f.clock.sleep(0.01)
        window = f.ports.start_window()
        result = f.run()
        validated = self.kind.validate_kind_row5(
            result,
            f.ports.live.row5_stage.requests,
            configuration_sha256="a" * 64,
            binding=f.binding,
        )
        self.assertEqual(validated["controls"]["known0"], 0)
        self.assertEqual(set(window["mappings"]), {"redis", "gateway0", "gateway1"})
        self.assertEqual(
            set(result["row5_prewindow_skipped_counts"]), {"redis", "gateway0", "gateway1"}
        )
        self.assertGreater(result["row5_prewindow_skipped_counts"]["gateway0"]["capture_start"], 0)
        self.assertGreater(
            result["row5_prewindow_skipped_counts"]["gateway1"]["admission_config"], 0
        )
        self.assertTrue(
            result["row5_prewindow_skipped_counts"]["redis"].get("report_store", 0)
            + result["row5_prewindow_skipped_counts"]["redis"].get("unknown", 0)
        )
        self.assertEqual(f.ports.live.redis.audit_seq, f.order)
        from inference_platform.inf037b_row5_capture import gateway_prefix_from_capture

        for gateway in ("gateway0", "gateway1"):
            first = strict_json(
                gateway_prefix_from_capture(**f.ports.live.gateway_binding(gateway)).splitlines()[0]
            )
            self.assertEqual((first["sequence"], first["event"]), (0, "capture_start"))

    def test_missed_window_start_clock_refuses_with_source_name(self):
        f = self.fixture(initial_tick=False, start_window=False)
        with patch.object(
            f.ports.clocks,
            "redis",
            return_value={"payload": {"event": "missed"}},
        ):
            with self.assertRaisesRegex(IntegrityError, "fitness:row5_window_start_clock:redis"):
                f.ports.start_window()

    def test_early_edge_mutant_unset_cutoffs_fails_kind_join(self):
        f = self.fixture(initial_tick=False, start_window=False)
        f.tick(poll_clocks=False)
        f.clock.sleep(0.01)
        f.ports.start_window()
        for adapter in f.ports.live.gateways.values():
            adapter.capture_start_remote_ms = 0
        f.ports.live.redis.capture_start_remote_ms = 0
        result = f.run()
        with self.assertRaisesRegex(IntegrityError, "setup:source_join"):
            self.kind.validate_kind_row5(
                result,
                f.ports.live.row5_stage.requests,
                configuration_sha256="a" * 64,
                binding=f.binding,
            )

    def test_early_edge_mutant_pre_window_admit_refuses_by_name(self):
        f = self.fixture(initial_tick=False, start_window=False)
        f.tick(poll_clocks=False)
        f.emit("gateway0", "admit", {"request_id": "req_" + "a" * 32})
        f.clock.sleep(0.01)
        f.ports.start_window()
        with self.assertRaisesRegex(IntegrityError, "fitness:row5_prewindow_evidence"):
            f.run()

    def test_pre_window_redis_snapshot_is_not_allowlisted(self):
        f = self.fixture(initial_tick=False, start_window=False)
        f.ports.live.redis.capture_start_remote_ms = 10
        raw = {"redis_time_ms": 9, "capture_order": "0"}
        with patch.object(f.wire, "command", return_value=json.dumps(raw)):
            with self.assertRaisesRegex(IntegrityError, "fitness:row5_prewindow_evidence"):
                f.ports.live.redis.snapshot()

    def test_pre_window_redis_admit_is_not_allowlisted(self):
        f = self.fixture(initial_tick=False, start_window=False)
        f.operation("admit", reservation_id="rsv_" + "b" * 32)
        f.ports.live.redis.capture_start_remote_ms = f.clock() // 1_000_000 + 500_001
        with self.assertRaisesRegex(IntegrityError, "fitness:row5_prewindow_evidence"):
            f.ports.live.redis.operations()

    def test_early_edge_mutant_window_start_after_first_poll_refuses(self):
        f = self.fixture(initial_tick=False, start_window=False)
        f.tick(poll_clocks=False)
        with self.assertRaisesRegex(IntegrityError, "fitness:row5_window_start_missing"):
            f.ports.live.poll()
        with self.assertRaisesRegex(IntegrityError, "fitness:row5_window_start_after_poll"):
            f.ports.start_window()

    def test_window_start_not_before_known0_first_action_refuses(self):
        f = self.fixture()
        f.ports.window_start["sample_end_mono_ns"] = f.clock() + 1
        with self.assertRaisesRegex(IntegrityError, "fitness:row5_window_start_after_known0"):
            f.ports.live.row5_stage("known0", f.clock() + 10_000_000_000)

    def test_script_keyword_set_constructs_real_kind_row5_ports(self):
        import ast
        import hashlib

        from inference_platform.inf037b_live import LiveRows

        f = self.fixture()
        script = Path(__file__).resolve().parents[2] / "scripts" / "rehearse_row5_kind.py"
        tree = ast.parse(script.read_text(encoding="utf-8"))
        call = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "kind_row5_ports"
        )
        keyword_names = {keyword.arg for keyword in call.keywords}
        with TemporaryDirectory() as directory:
            root = Path(directory)

            class ConfigurationOwner:
                def __init__(self, path):
                    self.root = path
                    self.operation = {"operation": "capture", "key": "configuration"}

                def close(self):
                    return {"sources": f.runtime_sources}

            class StubCaptureOwner:
                def __init__(self, **arguments):
                    self.sources = arguments["sources"]
                    self.root = Path(arguments["root"])
                    self.operation = arguments["operation"]
                    self.binding = arguments["binding"]
                    self.failed = False
                    self._rows = {}

                def rows(self, source):
                    return self._rows.setdefault(
                        source, LiveRows("kind-script-test", "kernel-boot")
                    )

                def retainer(self, _source):
                    def retain(*_args, **_kwargs):
                        return None

                    retain.barrier = lambda: None
                    return retain

            stop_ns = time.monotonic_ns() + 60_000_000_000
            binary = Path(__file__).resolve()
            kwargs = {
                "store": object(),
                "operation_store": object(),
                "operation": {"operation": "capture", "key": "runtime"},
                "binding": f.binding,
                "root": root / "runtime",
                "gateways": f.gateways,
                "gateway_configuration_owner": ConfigurationOwner(root),
                "dial_addr": "127.0.0.1:6379",
                "step_timing": lambda *_args: None,
                "redis_wire": SimpleNamespace(
                    command=lambda *_args: "{}", host="127.0.0.1", port=6379
                ),
                "redis_gateway_ids": {"gateway-0": "gateway0", "gateway-1": "gateway1"},
                "slots": {"vllm-0": 0, "vllm-1": 1},
                "role": f.role,
                "binary": binary,
                "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "config": f.config,
                "measured_tenants": ["measured"],
                "configuration_sha256": "a" * 64,
                "stop_ns": stop_ns,
                "stop_collectors": lambda: None,
            }
            self.assertEqual(keyword_names, set(kwargs))
            with self.assertRaisesRegex(IntegrityError, "diagnostic_dial_addr_mismatch"):
                self.kind.kind_row5_ports(**{**kwargs, "dial_addr": "127.0.0.1:6380"})
            with (
                patch.object(self.kind, "CaptureOwner", StubCaptureOwner),
                patch.object(
                    self.kind, "gateway_resolved_config_from_capture", return_value=f.config
                ),
            ):
                ports = self.kind.kind_row5_ports(**kwargs)
        self.assertIsInstance(ports.live, self.kind.LiveRow5)
        self.assertIs(ports.live.row5_control.step_timing, kwargs["step_timing"])

    def test_live_script_starts_window_before_collection_and_persists_it_before_validation(self):
        import ast

        script = Path(__file__).resolve().parents[2] / "scripts" / "rehearse_row5_kind.py"
        tree = ast.parse(script.read_text(encoding="utf-8"))
        live = next(
            node
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == "_run_live"
        )

        class DirectCalls(ast.NodeVisitor):
            def __init__(self):
                self.calls = []
                self.assignments = []

            def visit_FunctionDef(self, node):
                if node is live:
                    for statement in node.body:
                        self.visit(statement)

            def visit_AsyncFunctionDef(self, node):
                if node is live:
                    for statement in node.body:
                        self.visit(statement)

            def visit_Call(self, node):
                self.calls.append(node)
                self.generic_visit(node)

            def visit_Assign(self, node):
                self.assignments.append(node)
                self.generic_visit(node)

        direct = DirectCalls()
        direct.visit(live)

        def call_line(predicate):
            return min(
                (node.lineno for node in direct.calls if predicate(node)),
                default=None,
            )

        ports_assignment = min(
            node.lineno
            for node in direct.assignments
            if any(isinstance(target, ast.Name) and target.id == "ports" for target in node.targets)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Name)
            and node.value.func.id == "kind_row5_ports"
        )
        window_start = call_line(
            lambda node: (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "ports"
                and node.func.attr == "start_window"
            )
        )
        collector_start = call_line(
            lambda node: (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "collector_thread"
                and node.func.attr == "start"
            )
        )
        summary_update = call_line(
            lambda node: (
                isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "control_result"
                and node.func.attr == "update"
                and node.args
                and isinstance(node.args[0], ast.Call)
                and isinstance(node.args[0].func, ast.Attribute)
                and isinstance(node.args[0].func.value, ast.Name)
                and node.args[0].func.value.id == "ports"
                and node.args[0].func.attr == "window_summary"
            )
        )
        validation = call_line(
            lambda node: (
                isinstance(node.func, ast.Name) and node.func.id == "validate_retained_kind_row5"
            )
        )
        row5_control_call = call_line(
            lambda node: (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "row5_control"
                and isinstance(node.func.value, ast.Attribute)
                and node.func.value.attr == "live"
                and isinstance(node.func.value.value, ast.Name)
                and node.func.value.value.id == "ports"
            )
        )
        retain_inputs_assignment = min(
            (
                node.lineno
                for node in direct.assignments
                if any(
                    isinstance(target, ast.Attribute)
                    and target.attr == "retain_inputs"
                    and isinstance(target.value, ast.Attribute)
                    and target.value.attr == "row5_control"
                    and isinstance(target.value.value, ast.Attribute)
                    and target.value.value.attr == "live"
                    and isinstance(target.value.value.value, ast.Name)
                    and target.value.value.value.id == "ports"
                    for target in node.targets
                )
            ),
            default=None,
        )

        self.assertIsNotNone(window_start, "_run_live must set the capture window")
        self.assertIsNotNone(collector_start, "_run_live must start its collectors")
        self.assertIsNotNone(summary_update, "_run_live must retain the window summary")
        self.assertIsNotNone(validation, "_run_live must validate retained inputs")
        self.assertIsNotNone(
            retain_inputs_assignment, "_run_live must wire pre-proof replay retention"
        )
        self.assertIsNotNone(row5_control_call, "_run_live must invoke the row5 control sequence")
        self.assertLess(ports_assignment, window_start)
        self.assertLess(window_start, collector_start)
        self.assertLess(retain_inputs_assignment, row5_control_call)
        self.assertLess(summary_update, validation)

    def test_kind_fixture_matches_go_gateway_deny_and_admit_field_sets(self):
        import re

        handler = Path(__file__).resolve().parents[2] / "internal" / "gateway" / "handler.go"
        source = handler.read_text(encoding="utf-8")
        deny = re.search(r'measurement\.Record\("deny",\s*map\[string\]any\{([^}]*)\}\)', source)
        self.assertIsNotNone(deny, "Go deny emitter must remain directly checkable")
        self.assertEqual(
            set(re.findall(r'"([a-z_]+)"\s*:', deny.group(1))),
            {"request_id", "http_status", "denial_code"},
        )
        admit = re.search(r"admissionCapture\s*:=\s*map\[string\]any\{([^}]*)\}", source)
        self.assertIsNotNone(admit, "Go admit emitter must remain directly checkable")
        admit_keys = set(re.findall(r'"([a-z_]+)"\s*:', admit.group(1)))
        self.assertNotIn("effective_n", admit_keys)
        self.assertEqual(
            admit_keys,
            {
                "request_id",
                "reservation_id",
                "admit_called",
                "decision",
                "effective_b",
                "retry_after_ms",
                "idempotent",
            },
        )
        start = source.index("if admissionResult.Decision != admission.Allowed {")
        end = source.index("\n\tif g.draining.Load()", start)
        system_capacity_path = source[start:end]
        self.assertRegex(
            system_capacity_path,
            r"status := http\.StatusTooManyRequests\s+if admissionResult\.Decision == admission\.CapacityReportsExpired \{\s+status = http\.StatusServiceUnavailable",
        )

    def test_redis_snapshot_labeler_labels_the_matching_snapshot_it_reads(self):
        f = self.fixture()
        raw = {
            "redis_time_ms": f.ports.window_start["mappings"]["redis"]["remote_ms"] + 1,
            "capture_order": "0",
            "reports": [
                "gateway0",
                json.dumps({"n": 2, "unknown": False, "expires": 9100}),
                "gateway1",
                json.dumps({"n": 2, "unknown": False, "expires": 9100}),
            ],
            "lows": [],
            "state": ["n", "1", "candidate", "2", "since", "90", "until", "5000"],
            "active": [],
        }
        with patch.object(f.wire, "command", return_value=json.dumps(raw)):
            row = f.ports.live.redis.snapshot(
                label_if=lambda state, _now: (
                    "hold_start" if state.get("n") == 1 and state.get("candidate") == 2 else None
                )
            )
        self.assertEqual(row["payload"]["snapshot_id"], "hold_start")
        self.assertEqual(
            row["payload"]["redis_time_ms"],
            f.ports.window_start["mappings"]["redis"]["remote_ms"] + 1,
        )
        self.assertLess(row["payload"]["state"]["since_ms"], row["payload"]["redis_time_ms"])

    def test_second_reader_refuses_before_offset_request(self):
        f = self.fixture()
        http = Mock()
        with self.assertRaisesRegex(IntegrityError, "fitness:row5_second_stream_reader"):
            GatewayAdapter(
                f.ports.owner.rows("gateway0"),
                http,
                "gateway0",
                slot_names={},
                config_sha256="a" * 64,
            )
        http.get.assert_not_called()

    def test_rbac_retention_between_real_diagnostics_uses_separate_source(self):
        from inference_platform.inf037b_capture import wire_records

        f = self.fixture()
        live = f.ports.live
        for i in range(2):
            live.diagnostic.run_from_captures(
                config=f.config,
                gateway_captures=live.config_captures,
                measured_tenants=["measured"],
                reservation_id="rsv_d1a6" + f"{i:028x}",
                deadline_ns=f.clock() + 5_000_000_000,
            )
            if i == 0:
                for direction, body in (("request", b"{}"), ("response", b'{"code":200}')):
                    self.kind.retain_row5_role(
                        {"owner": f.ports.owner},
                        f.clock(),
                        f.clock(),
                        body,
                        {"method": "GET", "path": "/apis/rbac/roles", "direction": direction},
                    )
        live.capture({"fitness_raw": encode({"schema": "inf037b-setup-v1", **f.binding})})
        self.assertEqual(len(live.receipts), 2)
        records = list(wire_records(f.ports.owner.root / "wire"))
        self.assertEqual(
            [r["source"] for r, _ in records if r["metadata"].get("direction")],
            ["rbac", "rbac"],
        )

    def test_final_poll_rows_are_bracketed_after_collectors_stop(self):
        from inference_platform.inf037b_probe import capture_rows
        from inference_platform.inf037b_sources import SourceJoin

        f = self.fixture()
        live = f.ports.live
        live.poll()

        def stop():
            f.clock.sleep(0.1)
            f.operation(
                "report_store",
                gateway_uid="gateway0",
                report=json.dumps(
                    {"n": 0, "unknown": False, "expires": f.clock() // 1_000_000 + 508000}
                ),
            )

        live.stop_collectors = stop
        live.settle()
        descriptor = f.ports.owner.close()
        join = SourceJoin(list(capture_rows(f.ports.owner.root, descriptor)))
        self.assertEqual(join.errors, [])
        self.assertTrue(any(r["payload"]["event"] == "report_store" for r in join.rows))

    def test_snapshot_drains_older_operations_without_consuming_newer_tail(self):
        from inference_platform.inf037b_probe import capture_rows
        from inference_platform.inf037b_sources import SourceJoin

        f = self.fixture()
        live = f.ports.live
        live.poll()
        command = f.wire.command

        def interleaved(*arguments):
            if arguments[0] != "TIME" and "XRANGE" not in arguments[1]:
                f.clock.sleep(0.005)
                f.operation(
                    "report_store",
                    gateway_uid="gateway0",
                    report=json.dumps(
                        {"n": 0, "unknown": False, "expires": f.clock() // 1_000_000 + 508000}
                    ),
                )
                f.clock.sleep(0.005)
                snapshot = command(*arguments)
                f.clock.sleep(0.005)
                f.operation("release", reservation_id="diagnostic", decision="released")
                return snapshot
            return command(*arguments)

        live.reservations["diagnostic"] = None
        f.wire.command = interleaved
        snapshot = live.row5_stage.redis.snapshot(snapshot_id="known0")
        drained, high = live.redis.audit_seq, f.order
        live.poll()
        live.settle()
        descriptor = f.ports.owner.close()
        join = SourceJoin(list(capture_rows(f.ports.owner.root, descriptor)))
        self.assertEqual(join.errors, [])
        self.assertEqual(drained, snapshot["payload"]["store_order"])
        self.assertLess(drained, high)
        redis = [r for r in join.rows if r["source_kind"] == "redis"]
        self.assertEqual(
            [r["payload"]["event"] for r in sorted(redis, key=lambda r: r["source_seq"])][-5:-2],
            ["report_store", "snapshot", "release"],
        )

    def test_replay_inputs_survive_validator_refusal_without_credentials(self):
        f = self.fixture()
        result = f.run()
        result["transport_options"] = {"credential": "must-not-be-retained"}
        requests = f.ports.live.row5_stage.requests
        with patch.object(self.kind, "validate_kind_row5", side_effect=IntegrityError("refusal")):
            with self.assertRaisesRegex(IntegrityError, "refusal"):
                self.kind.validate_retained_kind_row5(f.root, result, requests)
        saved = strict_json((f.root / "row5-control-result.json").read_bytes())
        self.assertEqual(
            saved,
            {
                k: result[k]
                for k in (
                    "row5_evidence",
                    "row5_control_requests",
                    "row5_window_start",
                    "row5_prewindow_skipped_counts",
                    "row5_recovery_batches",
                )
            },
        )
        self.assertEqual(strict_json((f.root / "row5-all-requests.json").read_bytes()), requests)
        self.assertNotIn(
            b"must-not-be-retained", (f.root / "row5-control-result.json").read_bytes()
        )

    def test_replay_input_writer_refuses_a_missing_window_field(self):
        with TemporaryDirectory() as directory:
            output = Path(directory)
            with self.assertRaisesRegex(KeyError, "row5_prewindow_skipped_counts"):
                self.kind.retain_kind_row5_inputs(
                    output,
                    {
                        "row5_evidence": {},
                        "row5_control_requests": [],
                        "row5_window_start": {},
                    },
                    [],
                )
            self.assertFalse((output / "row5-control-result.json").exists())

    def test_replay_input_writer_requires_recovery_batches(self):
        with TemporaryDirectory() as directory:
            output = Path(directory)
            with self.assertRaisesRegex(KeyError, "row5_recovery_batches"):
                self.kind.retain_kind_row5_inputs(
                    output,
                    {
                        "row5_evidence": {},
                        "row5_control_requests": [],
                        "row5_window_start": {},
                        "row5_prewindow_skipped_counts": {},
                    },
                    [],
                )
            self.assertFalse((output / "row5-control-result.json").exists())

    def test_outage_inputs_are_retained_before_a_proof_can_refuse(self):
        f = self.fixture()

        f.ports.live.row5_control.retain_inputs = self.kind.retain_kind_row5_inputs_before_proofs(
            f.root, f.ports
        )
        with patch.object(
            f.ports.live.row5_stage, "proofs", side_effect=IntegrityError("proof refusal")
        ):
            with self.assertRaisesRegex(IntegrityError, "proof refusal"):
                f.run()
        saved = strict_json((f.root / "row5-control-result.json").read_bytes())
        all_requests = strict_json((f.root / "row5-all-requests.json").read_bytes())
        staged_requests = list(f.ports.live.row5_stage.requests)
        self.assertEqual(all_requests, staged_requests)
        request_ids = [offer["request_id"] for offer in all_requests]
        self.assertEqual(len(request_ids), 16)
        self.assertEqual(len(set(request_ids)), 16)
        self.assertEqual([offer["offer_index"] for offer in all_requests], list(range(16)))
        self.assertTrue(saved["row5_recovery_batches"])
        self.assertTrue(all(batch["source_complete"] for batch in saved["row5_recovery_batches"]))
        self.assertIn("restore_outcome", saved["row5_evidence"])
        self.assertEqual(len(saved["row5_control_requests"]), 6)

        from inference_platform.inf037b_row5_replay import (
            CONTROL_ORDER,
            GATEWAYS,
            _prepare_saved_composition_inputs,
        )

        grouped = {
            name: [offer for offer in all_requests if offer["snapshot_id"] == name]
            for name in CONTROL_ORDER
        }
        replayed = {
            "grouped_offers": grouped,
            "runtime_descriptor_sha256": saved["row5_evidence"]["gateway_config_captures"][
                "gateway0"
            ]["expected_descriptor_sha256"],
            "proofs_by_control": {
                name: {
                    "gateways": {gateway: {"proof": name} for gateway in GATEWAYS},
                    "diagnostic": {"proof": name},
                }
                for name in CONTROL_ORDER
            },
        }
        requests, _ = _prepare_saved_composition_inputs(replayed, f.root, saved, all_requests)
        self.assertEqual([offer["request_id"] for offer in requests], request_ids)

    def test_redis_admit_effective_n_mismatch_refuses(self):
        f = self.fixture()
        result = f.run()

        def mutate(rows):
            admit = next(
                row
                for row in rows
                if row.get("source_kind") == "redis"
                and row.get("payload", {}).get("event") == "admit"
            )
            admit["payload"]["effective_n"] += 1

        with self.assertRaisesRegex(IntegrityError, "fitness:control_request_join"):
            self._validate_with_raw_mutation(f, result, mutate)

    def test_duplicate_redis_admit_refuses(self):
        f = self.fixture()
        result = f.run()

        def mutate(rows):
            admit = next(
                row
                for row in rows
                if row.get("source_kind") == "redis"
                and row.get("payload", {}).get("event") == "admit"
            )
            stream = [
                row
                for row in rows
                if row.get("source_kind") == "redis"
                and row.get("source_identity") == admit["source_identity"]
                and row.get("source_generation") == admit["source_generation"]
            ]
            duplicate = copy.deepcopy(admit)
            duplicate["source_seq"] = max(row["source_seq"] for row in stream) + 1
            duplicate["record_id"] = (
                f"{duplicate['source_identity']}:{duplicate['source_generation']}:{duplicate['source_seq']}"
            )
            latest = max(stream, key=lambda row: row["observed_mono_ns"])
            duplicate["observed_mono_ns"] = latest["observed_mono_ns"] + 1
            duplicate["capture_start_mono_ns"] = latest["capture_end_mono_ns"] + 1
            duplicate["capture_end_mono_ns"] = duplicate["capture_start_mono_ns"]
            duplicate["uncertainty_ns"] = 0
            source_times = [
                row["source_time"]["value"]
                for row in stream
                if isinstance(row.get("source_time"), dict)
            ]
            duplicate["source_time"]["value"] = max(source_times)
            rows.append(duplicate)

        with self.assertRaisesRegex(IntegrityError, "fitness:control_request_join"):
            self._validate_with_raw_mutation(f, result, mutate)

    def test_redis_admit_request_id_mismatch_refuses(self):
        f = self.fixture()
        result = f.run()

        def mutate(rows):
            admit = next(
                row
                for row in rows
                if row.get("source_kind") == "redis"
                and row.get("payload", {}).get("event") == "admit"
            )
            admit["payload"]["request_id"] += "-mutated"

        with self.assertRaisesRegex(IntegrityError, "fitness:control_request_join"):
            self._validate_control_evidence_with_row_mutation(f, result, mutate)

    def test_refusal_deny_with_wrong_reservation_refuses(self):
        from inference_platform import inf037b_row5_capture as capture

        f = self.fixture()
        result = f.run()
        evidence = result["row5_evidence"]
        refusal = evidence["refusals"]["unknown"]["gateway0"]
        request_id = refusal["gateway"]["gateway_request_id"]
        capture_binding = evidence["gateway_config_captures"]["gateway0"]
        prefix = capture.gateway_prefix_from_capture(**capture_binding)
        records = [strict_json(line) for line in prefix.splitlines()]
        changed = False
        for record in records:
            data = record.get("data", {})
            if record.get("event") == "deny" and data.get("request_id") == request_id:
                data["reservation_id"] = "rsv_" + "f" * 32
                changed = True
                break
        self.assertTrue(changed)
        altered_prefix = b"".join(encode(record) for record in records)
        altered_sha = sha(altered_prefix)
        evidence["gateway_reservation_ids"].append("rsv_" + "f" * 32)

        for control in evidence["known"].values():
            control["gateway0"]["capture_sha256"] = altered_sha
        for control in evidence["refusals"].values():
            proof = control["gateway0"]
            proof["gateway"]["capture_sha256"] = altered_sha
            proof["evidence_sha256"] = sha(
                encode(
                    {
                        "gateway": proof["gateway"],
                        "client": proof["client"],
                        "redis": proof["redis"],
                    }
                )
            )

        original = capture.gateway_prefix_from_capture

        def mutated_prefix(*args, **binding):
            if binding.get("gateway_uid") == "gateway0":
                return altered_prefix
            return original(*args, **binding)

        with patch.object(capture, "gateway_prefix_from_capture", side_effect=mutated_prefix):
            with self.assertRaisesRegex(IntegrityError, "fitness:refusal_absence_unproven"):
                self.kind.validate_kind_row5(
                    result,
                    f.ports.live.row5_stage.requests,
                    configuration_sha256="a" * 64,
                    binding=f.binding,
                )

    def test_existing_reader_is_not_hidden_by_later_reservation(self):
        rows = LiveRows("test", "boot")
        GatewayAdapter(rows, Mock(), "gateway0", slot_names={}, config_sha256="a" * 64)
        rows.row5_single_reader = True
        with self.assertRaisesRegex(IntegrityError, "fitness:row5_second_stream_reader"):
            GatewayAdapter(rows, Mock(), "gateway0", slot_names={}, config_sha256="a" * 64)

    def test_validation_normalizes_and_returns_validator_result_unchanged(self):
        rows = LiveRows("test", "boot").row("controller", "operator", "boot", "action", {})
        expected = object()

        def validate(*args, **kwargs):
            self.assertIn("time_ms_bounds", kwargs["rows"][0])
            self.assertIn("raw_ref", kwargs["rows"][0])
            self.assertEqual(kwargs["binding"], {"session_id": "test", "pins": {}, "t0_ms": 0})
            return expected

        with (
            patch.object(
                self.kind, "fitness_request_joins", return_value=(None, SimpleNamespace(cohorts=[]))
            ) as joins,
            patch.object(self.kind, "select_row5_snapshots", return_value={}),
            patch.object(self.kind, "check_restoration_hold") as hold_check,
            patch.object(self.kind, "validate_control_evidence", side_effect=validate),
        ):
            result = self.kind.validate_kind_row5(
                {"fitness_raw": encode({"raw": [rows]}), "row5_evidence": {}},
                [],
                configuration_sha256="a" * 64,
                binding={"session_id": "test", "pins": {}, "t0_ms": 0, "extra": True},
            )
        self.assertIs(result, expected)
        self.assertEqual(joins.call_args.args[1:3], ([], []))
        self.assertEqual(joins.call_args.args[3], joins.call_args.args[0][0]["time_ms_bounds"][1])
        hold_check.assert_called_once_with({}, joins.call_args.args[0], 2000)

    def test_join_errors_refuse_before_request_or_evidence_validation(self):
        rows = LiveRows("test", "boot")
        row = rows.row("controller", "operator", "boot", "action", {})
        conflict = copy.deepcopy(row)
        conflict["payload"]["event"] = "changed"
        with patch.object(self.kind, "fitness_request_joins") as joins:
            with self.assertRaisesRegex(IntegrityError, "setup:source_join"):
                self.kind.validate_kind_row5(
                    {"fitness_raw": encode({"raw": [row, conflict]})},
                    [],
                    configuration_sha256="a" * 64,
                    binding={},
                )
        joins.assert_not_called()

    def timing_rows(self):
        clock_rows = LiveRows("test", "boot")
        from inference_platform.inf037b_live import ClockAdapter

        clocks = ClockAdapter(clock_rows)
        rows = []
        for local in range(0, 6001, 1000):
            for clock, boot, offset in (
                ("gateway0", "g0", 100_000),
                ("gateway1", "g1", 200_000),
                ("redis", "redis", 500_000),
            ):
                rows.append(
                    clocks.mapping(
                        clock,
                        boot,
                        local + offset,
                        local * 1_000_000,
                        (local + 4) * 1_000_000,
                        wall_ms=local,
                    )
                )
        for i, gateway in enumerate(("gateway0", "gateway1")):
            builder = LiveRows("test", "boot")
            for at, error, known in (
                (500, "", True),
                (1100 + i * 10, "403 Forbidden", False),
                (4100 + i * 10, "", False),
                (4200 + i * 10, "", True),
            ):
                rows.append(
                    builder.row(
                        "gateway",
                        gateway,
                        "g" + str(i),
                        "install",
                        {"gateway_uid": gateway, "error_class": error, "membership_known": known},
                        source_ms=at + (i + 1) * 100_000,
                        clock_id=gateway,
                    )
                )
            rows.append(
                LiveRows("test", "boot").row(
                    "redis",
                    "redis",
                    "redis",
                    "report_store",
                    {"gateway_uid": gateway, "report_known": True, "n": 2, "store_order": i + 1},
                    source_ms=504300 + i * 10,
                    clock_id="redis",
                )
            )
        evidence = {
            "rbac": {"actions": [{"start_ns": 1_000_000_000}]},
            "restore_outcome": {"start_ns": 4_000_000_000},
            "last_known_stores_ms": {"gateway0": 500800, "gateway1": 500850},
        }
        return rows, evidence

    def test_timings_map_disjoint_clocks_and_preserve_interval_uncertainty(self):
        rows, evidence = self.timing_rows()
        values = self.kind.row5_timings(rows, evidence)
        for i, gateway in enumerate(("gateway0", "gateway1")):
            self.assertEqual(
                values[gateway],
                {
                    "revoke_to_first_403_ms": [100 + i * 10, 104 + i * 10],
                    "last_known_store_spread_ms": [46, 54],
                    "restore_to_first_successful_install_ms": [200 + i * 10, 204 + i * 10],
                    "restore_to_first_known2_store_ms": [300 + i * 10, 304 + i * 10],
                },
            )

    def test_missing_gateway_or_redis_mapping_refuses_timing_clock(self):
        rows, evidence = self.timing_rows()
        for clock in ("gateway0", "gateway1", "redis"):
            with (
                self.subTest(clock=clock),
                self.assertRaisesRegex(IntegrityError, "fitness:row5_timing_clock"),
            ):
                self.kind.row5_timings(
                    [r for r in rows if r["payload"].get("clock_id") != clock], evidence
                )

    def test_diagnostic_receipt_missing_or_ambiguous_is_explicit_refusal(self):
        from inference_platform.inf037b_row5_live import LiveRow5

        live = LiveRow5.__new__(LiveRow5)
        snapshot = {
            "record_id": "s",
            "source_kind": "redis",
            "payload": {"event": "snapshot", "store_order": 1},
        }
        live.rows, live.reservations = [snapshot], {}
        receipt = {"reservation_id": "rsv_d1a6" + "0" * 28}
        for receipts in ([], [receipt, receipt]):
            live.receipts = receipts
            with self.assertRaisesRegex(IntegrityError, "fitness:row5_diagnostic_receipt"):
                live.proof_inputs("known0", None, None, snapshot, snapshot, receipt)

    def test_all_five_stages_and_outage_are_accepted(self):
        f = self.fixture()
        result = f.run()
        rows = strict_json(result["fitness_raw"])["raw"]
        self.assertTrue(
            all(
                len(values) == 4
                for values in self.kind.row5_timings(rows, result["row5_evidence"]).values()
            )
        )
        self.assertEqual(len(f.ports.live.row5_stage.requests), 16)
        self.assertTrue(result["row5_evidence"]["restore_outcome"]["success"])
        expected_pairs = {
            (name, gateway)
            for name in (
                "known0",
                "known1",
                "known2",
                "cached_stop_known1",
                "cached_restore_known2",
                "post_outage_known2",
                "unknown",
                "expired",
            )
            for gateway in ("gateway0", "gateway1")
        }
        gateway_controls = {
            **result["row5_evidence"]["known"],
            **result["row5_evidence"]["refusals"],
        }
        evidence_pairs = {
            (name, gateway) for name, gateways in gateway_controls.items() for gateway in gateways
        }
        self.assertEqual(evidence_pairs, expected_pairs)
        self.assertEqual(len(evidence_pairs), 16)
        watch = [
            r
            for r in result["row5_evidence"]["rbac"]["reviews"]
            if r["phase"] == "restore" and r["verb"] == "watch"
        ]
        self.assertTrue(watch)
        self.assertTrue(all(r["allowed"] is False for r in watch))
        validated = self.kind.validate_kind_row5(
            result,
            f.ports.live.row5_stage.requests,
            configuration_sha256="a" * 64,
            binding=f.binding,
        )
        self.assertEqual(
            validated["controls"],
            {"known2": 10, "known1": 5, "known0": 0, "expired": "refuse", "unknown": "refuse"},
        )
        self.assertEqual(
            set(validated["gateway_controls"]),
            {
                "known0",
                "known1",
                "known2",
                "cached_stop_known1",
                "cached_restore_known2",
                "post_outage_known2",
            },
        )
        self.assertTrue(
            all(
                set(gateways) == {"gateway0", "gateway1"}
                for gateways in validated["gateway_controls"].values()
            )
        )

    def direct_validate(self, f, result):
        from inference_platform.inf037b_row5 import validate_control_evidence
        from inference_platform.inf037b_row5_capture import select_row5_snapshots
        from inference_platform.inf037b_setup_fitness import fitness_request_joins
        from inference_platform.inf037b_sources import SourceJoin

        raw = strict_json(result["fitness_raw"])["raw"]
        join = SourceJoin(raw)
        self.assertEqual(join.errors, [])
        rows = join.rows
        offers = f.ports.live.row5_stage.requests
        _, controls = fitness_request_joins(
            rows, [], offers, max(row["time_ms_bounds"][1] for row in rows)
        )
        return validate_control_evidence(
            result["row5_evidence"],
            offers,
            configuration_sha256="a" * 64,
            binding={key: f.binding[key] for key in ("session_id", "pins", "t0_ms")},
            snapshots=select_row5_snapshots(rows),
            rows=rows,
            control_cohorts=controls.cohorts,
        )

    def accepted_producer_packet(self):
        f = self.fixture()
        result = f.run()
        observations = result["row5_evidence"]["recovery"]["observations"]
        self.assertTrue(observations)
        self.assertTrue(
            all(
                {"gateway_uid", "poll_seq", "read_mono_ns", "time_clock", "source_event_ns"}
                <= set(observation)
                for observation in observations
            )
        )
        self.assertEqual(
            [action["phase"] for action in result["row5_evidence"]["rbac"]["actions"]],
            ["revoke", "restore"],
        )
        self.assertEqual(
            self.direct_validate(f, result)["controls"],
            {"known2": 10, "known1": 5, "known0": 0, "expired": "refuse", "unknown": "refuse"},
        )
        return f, result

    def test_validator_rejects_true_restore_watch_from_role_control_packet(self):
        f, result = self.accepted_producer_packet()
        for review in result["row5_evidence"]["rbac"]["reviews"]:
            if review["phase"] == "restore" and review["verb"] == "watch":
                review["allowed"] = True
        with self.assertRaisesRegex(IntegrityError, "^fitness:rbac_restore_reviews$"):
            self.direct_validate(f, result)

    def test_validator_rejects_true_revoke_watch_from_role_control_packet(self):
        f, result = self.accepted_producer_packet()
        for review in result["row5_evidence"]["rbac"]["reviews"]:
            if review["phase"] == "revoke" and review["verb"] == "watch":
                review["allowed"] = True
        with self.assertRaisesRegex(IntegrityError, "^fitness:rbac_revoke_reviews$"):
            self.direct_validate(f, result)

    def test_validator_rejects_sixth_recovery_source_key(self):
        f, result = self.accepted_producer_packet()
        observation = result["row5_evidence"]["recovery"]["observations"][0]
        source_event_ns = observation.pop("source_event_ns")
        with self.assertRaisesRegex(IntegrityError, "^fitness:recovery_source_incomplete$"):
            self.direct_validate(f, result)
        observation["source_event_ns"] = source_event_ns
        observation["extra"] = "unexpected"
        with self.assertRaisesRegex(IntegrityError, "^fitness:recovery_source_incomplete$"):
            self.direct_validate(f, result)

    def test_validator_rejects_recovery_time_not_bound_to_collector_read(self):
        f, result = self.accepted_producer_packet()
        observation = result["row5_evidence"]["recovery"]["observations"][0]
        # Preserve the agreement sample order so this isolates the source/read
        # binding check rather than failing a later ordering invariant.
        observation["read_mono_ns"] += 1_000_000
        with self.assertRaisesRegex(IntegrityError, "^fitness:recovery_source_incomplete$"):
            self.direct_validate(f, result)


class TransportFixture:
    """Fake transport bytes; real owner, adapters, sequencer, proofs and validator."""

    def __init__(self, case, root, sequence, *, initial_tick=True):
        from inference_platform.inf037b_capture import CaptureOwner
        from inference_platform.inf037b_durable_ports import DurableStore

        self.case, self.root, self.clock, self.role = case, root, sequence.clock, sequence.role
        self.role_port = sequence.role_port
        self.n, self.order, self.counter = 0, 0, 0
        self.audit, self.reports = [], {}
        self.raw, self.poll_seq = (
            {g: [] for g in ("gateway0", "gateway1")},
            dict.fromkeys(("gateway0", "gateway1"), 0),
        )
        self.clock_paths = []
        self.binding = {"session_id": "kind-test", "pins": {"configuration": "a" * 64}, "t0_ms": 0}
        self.config = dict(
            redis_addr="127.0.0.1:6379",
            namespace="test",
            global_capacity=100,
            lease_ms=30000,
            tombstone_ms=30000,
            running=4,
            waiting=1,
            ttl_ms=8000,
            hold_ms=2000,
            capture=True,
        )
        boot = root / "boot"
        boot.write_text("kernel-boot")
        gateways = {
            g: {"boot": g, "http": {"base": "https://" + g}, "request": {}} for g in self.raw
        }
        self.gateways = gateways
        sources = {g: [["gateway", g, g]] for g in self.raw}
        for g in self.raw:
            self.emit(g, "capture_start", {})
            config = {**self.config, "gateway_id": g.replace("gateway", "gateway-")}
            config.update(
                {
                    k + "_ns": config[k + "_ms"] * 1_000_000
                    for k in ("lease", "tombstone", "ttl", "hold")
                }
            )
            self.emit(g, "admission_config", config)

        def owner_arguments(name, inventory):
            operation = {
                "operation": "capture",
                "key": name,
                "sequence": 0,
                "body": {
                    "binding": self.binding,
                    "capture": {
                        "sources": inventory,
                        "attempt": "setup",
                        "stages": [1, 2, 3, 4, 5],
                        "boot_id": "kernel-boot",
                    },
                },
            }
            operations = DurableStore(
                root / (name + "-operations"),
                {"operations": {sha(encode(["capture", name])): operation}},
                initialize=True,
            )
            store = DurableStore(root / (name + "-store"), {}, initialize=True)
            return dict(
                store=store,
                operation_store=operations,
                operation=operation,
                binding=self.binding,
                root=root / name,
                boot_path=boot,
            )

        self.configuration_owner = CaptureOwner(
            **owner_arguments("configuration", sources),
            sources=sources,
            attempt="setup",
            stages=[1, 2, 3, 4, 5],
        )
        case.addCleanup(
            lambda: (
                self.configuration_owner.close() if not self.configuration_owner.closed else None
            )
        )
        for g in self.raw:
            self.retain_gateway(self.configuration_owner, g, 0)
        runtime = case.kind.row5_runtime_sources({g: g for g in self.raw}, "kernel-boot")
        self.runtime_sources = runtime
        # Only the HTTP transport seam is fake; it still retains every byte.
        fixture = self

        class HTTP:
            def __init__(self, base, *, retain, **kwargs):
                self.gateway, self.retain = base.removeprefix("https://"), retain

            def get(self, path):
                g = self.gateway
                if "clock=1" in path:
                    fixture.clock_paths.append(path)
                    body, headers = encode({"boot_id": g, "mono_ns": fixture.remote_ns(g)}), {}
                else:
                    offset = int(path.split("offset=")[1])
                    raw = b"".join(fixture.raw[g])
                    body, headers = (
                        raw[offset:],
                        {"X-Capture-Boot": g, "X-Capture-Next": str(len(raw))},
                    )
                at = fixture.clock()
                self.retain(
                    at, at, b"", {"path": path, "status": 200, "headers": list(headers.items())}
                )
                self.retain(at, at, body, {"path": path})
                return body, headers

        self.wire = SimpleNamespace(command=self.command, host="127.0.0.1", port=6379)
        case.enterContext(patch("inference_platform.inf037b_row5_live.DeadlineHTTP", HTTP))
        case.enterContext(patch.object(case.kind, "DeadlineHTTP", HTTP))
        self.ports = case.kind.kind_row5_ports(
            **owner_arguments("runtime", runtime),
            gateways=gateways,
            gateway_configuration_owner=self.configuration_owner,
            dial_addr="127.0.0.1:6379",
            redis_wire=self.wire,
            redis_gateway_ids={g: g for g in self.raw},
            slots={"slot0": 0, "slot1": 1},
            role=self.role,
            binary=Path(__file__),
            binary_sha256=sha(Path(__file__).read_bytes()),
            config=self.config,
            measured_tenants=["measured"],
            configuration_sha256="a" * 64,
            stop_ns=self.clock() + 120_000_000_000,
            stop_collectors=self.tick,
            clock=self.clock,
            sleep=self.sleep,
        )
        for source in runtime:
            self.ports.owner.rows(source).clock = self.clock
        mapping = self.ports.clocks.mapping
        self.ports.clocks.mapping = lambda *a, **k: mapping(
            *a, **{**k, "wall_ms": 1_750_000_000_000 + self.clock() // 1_000_000}
        )
        # Closing transport queries take time in production. The instantaneous
        # fake must advance too, so the final sample is a distinct clock point.
        final_clocks = self.ports.live.final_clocks
        self.ports.live.final_clocks = lambda: (self.clock.sleep(0.001), final_clocks())
        case.addCleanup(lambda: self.ports.owner.close() if not self.ports.owner.closed else None)
        live = self.ports.live
        for g in self.raw:
            live.clients[g].adapter.request = lambda g=g, **kwargs: self.request(g, **kwargs)
        case.enterContext(
            patch(
                "inference_platform.inf037b_row5_diagnostic.diagnostic_process",
                side_effect=self.diagnostic,
            )
        )
        if initial_tick:
            self.tick()

    def remote_ns(self, g):
        return self.clock() + (100_000 if g == "gateway0" else 200_000) * 1_000_000

    def emit(self, g, event, data):
        self.raw[g].append(
            encode(
                {
                    "schema": "gateway-measurement-v1",
                    "boot_id": g,
                    "sequence": len(self.raw[g]),
                    "mono_ns": self.remote_ns(g),
                    "event": event,
                    "data": data,
                }
            )
        )

    def retain_gateway(self, owner, g, offset):
        body = b"".join(self.raw[g])[offset:]
        path = "/internal/measurement?offset=" + str(offset)
        owner.retain(
            g,
            self.clock(),
            self.clock(),
            b"",
            {
                "path": path,
                "status": 200,
                "headers": [["X-Capture-Boot", g], ["X-Capture-Next", str(offset + len(body))]],
            },
        )
        owner.retain(g, self.clock(), self.clock(), body, {"path": path})

    def operation(self, event, **data):
        self.order += 1
        at = self.clock() // 1_000_000 + 500_000
        raw = dict(
            event=event,
            redis_time_ms=str(at),
            capture_seq=str(self.order),
            decision="",
            idempotent="0",
            occupied="0",
        )
        raw.update(data)
        self.audit.append([f"{self.order}-0", [part for pair in raw.items() for part in pair]])

    def tick(self, *, poll_clocks=True):
        unknown = not bool(self.role_port.role["rules"])
        now = self.clock() // 1_000_000 + 500_000
        for g in self.raw:
            self.poll_seq[g] += 1
            self.emit(g, "poll_start", {"poll_seq": self.poll_seq[g]})
            self.emit(
                g,
                "install",
                {
                    "poll_seq": self.poll_seq[g],
                    "membership_known": not unknown,
                    "error_class": "403 Forbidden" if unknown else "",
                    "resource_version": "1",
                    "members": [
                        {
                            "uid": f"uid{i}",
                            "name": f"slot{i}",
                            "ready": True,
                            "sampled": True,
                            "healthy": True,
                        }
                        for i in range(self.n)
                    ],
                },
            )
            old = self.reports.get(g)
            self.reports[g] = {
                "n": (
                    2 if getattr(self, "hold_since", None) is not None and self.n == 1 else self.n
                ),
                "unknown": unknown,
                "expires": old["expires"] if unknown and old else now + 8000,
            }
            self.operation(
                "unknown" if unknown else "report_store",
                gateway_uid=g,
                report=json.dumps(self.reports[g]),
            )
        if poll_clocks:
            self.ports.poll_clocks()

    def sleep(self, seconds):
        self.clock.sleep(seconds)
        self.tick()

    def command(self, *arguments):
        now = self.clock() // 1_000_000 + 500_000
        if arguments[0] == "TIME":
            return [str(now // 1000), str(now % 1000 * 1000)]
        if "XRANGE" in arguments[1]:
            cursor = int(arguments[-1].split("-")[0])
            return [self.audit[cursor:], str(self.order)]
        return json.dumps(
            {
                "redis_time_ms": now,
                "capture_order": str(self.order),
                "reports": [v for g, r in self.reports.items() for v in (g, json.dumps(r))],
                "lows": [],
                "state": ["n", str(self.n)]
                + (
                    [
                        "candidate",
                        "2",
                        "since",
                        str(self.hold_since),
                        "until",
                        str(self.hold_since + 20000),
                    ]
                    if getattr(self, "hold_since", None) is not None and self.n == 1
                    else []
                ),
                "active": [],
            }
        )

    def request(self, g, *, offer, **kwargs):
        from test_inf037b_collectors import CONTENT, DONE, FINISH, USAGE

        live = self.ports.live
        client = live.clients[g].adapter
        self.counter += 1
        req, rid = "req_" + f"{self.counter:032x}", "rsv_" + f"{self.counter:032x}"
        client.request_ids[req] = offer["request_id"]
        unknown = not bool(self.role_port.role["rules"])
        refused = unknown or self.n == 0
        code = "discovery_unknown" if unknown else "system_capacity"
        fields = {
            k: offer[k]
            for k in ("request_id", "offer_index", "prefix_id", "gateway_uid", "config_sha256")
        }
        fields.update(policy="round-robin", retry_count=0)
        rows = [
            client.rows.row(
                "client",
                "client:" + g,
                "kernel-boot",
                "offer",
                {**fields, "dispatch_ms": offer["scheduled_ms"], "lateness_ms": 0},
            )
        ]
        start = rows[0]["capture_start_mono_ns"]
        self.clock.sleep(0.002)
        common = dict(request_id=req, reservation_id=rid)
        if not unknown:
            decision = "system_capacity" if refused else "allowed"
            self.emit(
                g,
                "admit",
                {
                    **common,
                    "decision": decision,
                    "effective_b": 5 * self.n,
                    "admit_called": True,
                },
            )
            self.operation(
                "admit",
                reservation_id=rid,
                decision=decision,
                effective_n=str(self.n),
                effective_b=str(5 * self.n),
            )
        if refused:
            status = 429 if code == "system_capacity" else 503
            self.emit(
                g,
                "deny",
                {"request_id": req, "http_status": status, "denial_code": code},
            )
            body = encode({"error": {"code": code}})
        else:
            for event in ("select", "revalidate", "upstream_open"):
                self.emit(g, event, {**common, "backend_uid": "uid0", "backend_name": "slot0"})
            body = CONTENT + FINISH + USAGE + DONE
            status = 200
        source = "client:" + g
        owner = self.ports.owner
        owner.retain(
            source, start, self.clock(), b"", {"status": status, "headers": [["X-Request-ID", req]]}
        )
        owner.retain(source, start, self.clock(), body, {"status": status})
        rows.append(
            client.rows.row(
                "client", source, "kernel-boot", "receive", {**fields, "http_status": status}
            )
        )
        if refused:
            rows.append(
                client.rows.row(
                    "client",
                    source,
                    "kernel-boot",
                    "deny",
                    {**fields, "http_status": status, "denial_code": code},
                )
            )
        else:
            rows.append(
                client.rows.row(
                    "client", source, "kernel-boot", "sse", {**fields, "chunk_hex": body.hex()}
                )
            )
            self.operation("release", reservation_id=rid, decision="released")
            self.emit(g, "release", {**common, "result": "released"})
        self.clock.sleep(0.002)
        self.emit(
            g,
            "terminal",
            {
                **common,
                "code": code if refused else "completed",
                "outcome": "rejected" if refused else "complete",
            },
        )
        rows.append(
            client.rows.row(
                "client", source, "kernel-boot", "terminal", {**fields, "http_status": status}
            )
        )
        # RetainedClient ends at this row; connection.close() precedes the later wire terminal.
        rows[-1]["capture_end_mono_ns"] = self.clock()
        self.clock.sleep(0.0005)
        owner.retain(source, start, self.clock(), b"", {"client_request_end": True})
        return rows

    def diagnostic(self, *args, input, **kwargs):
        data = strict_json(input)
        rid = data["reservation_id"]
        unknown = not bool(self.role_port.role["rules"])
        now = self.clock() // 1_000_000 + 500_000
        expired = unknown and all(r["expires"] <= now for r in self.reports.values())
        decision = (
            "capacity_reports_expired" if expired else "allowed" if self.n else "system_capacity"
        )
        self.operation(
            "admit",
            reservation_id=rid,
            decision=decision,
            effective_n=str(self.n),
            effective_b=str(self.n * 5),
        )
        if decision == "allowed":
            self.operation("release", reservation_id=rid, decision="released")
        return SimpleNamespace(
            returncode=0,
            stderr=b"",
            stdout=encode(
                {
                    "reservation_id": rid,
                    "decision": decision,
                    "capacity": self.n * 5,
                    "released": decision == "allowed",
                }
            ),
        )

    def run(self):
        live = self.ports.live
        for name, n in (
            ("known0", 0),
            ("known1", 1),
            ("known2", 2),
            ("cached_stop_known1", 1),
            ("cached_restore_known2", 2),
        ):
            if name == "cached_restore_known2":
                self.hold_since = self.clock() // 1_000_000 + 500_000
                self.sleep(0.01)
                live.row5_stage.redis.snapshot(snapshot_id="hold_start")
                for _ in range(40):
                    self.sleep(0.05)
            self.n = n
            self.sleep(0.1)
            if name == "cached_restore_known2":
                live.row5_stage.redis.snapshot(snapshot_id="hold_end")
            live.row5_stage(name, self.clock() + 10_000_000_000)
        result = live.row5_control(
            self.clock() + 30_000_000_000,
            {"fitness_raw": encode({"schema": "inf037b-setup-v1", **self.binding, "raw": []})},
        )
        result.update(self.ports.window_summary())
        return result
