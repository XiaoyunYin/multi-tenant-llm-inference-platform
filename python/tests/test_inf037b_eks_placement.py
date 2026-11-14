"""Real stdlib socket API/receive protocol; not kube-apiserver or durability proof."""

import copy
import http.client
import os
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import Mock
from urllib.parse import parse_qs, urlsplit

from inf037b_eks_supervisor_worker import FileJournal
from test_inf037b_placement import fixture

from inference_platform.inf037b_archive import encode, sha, strict_json
from inference_platform.inf037b_eks_placement import (
    GATE,
    DurableStartSignal,
    ExportPlacement,
    PlacementAPI,
    PlacementPorts,
    effective_memory,
)
from inference_platform.inf037b_placement import check_placement


def assert_capacity_decision(case, decision, name):
    case.assertEqual(decision["decision"], "EXPORT" if name == "fit" else "REFUSE", decision)
    if name == "short":
        case.assertEqual(
            decision["reason"],
            "v4:placement:proof:['pre_schedule:v4:placement:residual']",
            decision,
        )


def capacity_case(case, runtime, stop, name):
    raw, phase, control = runtime.collect("pre_schedule", stop)
    case.assertEqual(raw["pod"]["spec"]["schedulingGates"], [{"name": GATE}])
    now = runtime.clock()
    proposed = runtime.projected_control(control, now)
    decision = runtime.evaluate(phase, None, {"pre_schedule": proposed}, now, "pre_schedule")
    assert_capacity_decision(case, decision, name)


def release_case(case, runtime, stop):
    raw, pre, first = runtime.collect("pre_schedule", stop)
    now = runtime.clock()
    proposed = runtime.projected_control(first, now)
    decision = runtime.evaluate(pre, None, {"pre_schedule": proposed}, now, "pre_schedule")
    case.assertEqual(decision["decision"], "EXPORT", decision)
    runtime.publish("pre-schedule", {"raw": raw, "projected": decision}, stop)
    runtime.acknowledge("pre_schedule", "pre-schedule", first, stop)
    case.assertTrue(first["acknowledged"])
    case.assertFalse(raw["pod"]["spec"].get("nodeName"))
    released = copy.deepcopy(raw["pod"])
    released["spec"]["schedulingGates"] = []
    runtime.api.request("PUT", runtime.path("pods", runtime.pod), stop, released)
    first.update(received_once=True, signal_ms=runtime.clock())
    runtime.persist_control("pre_schedule", first)
    while True:
        pod = runtime.api.request("GET", runtime.path("pods", runtime.pod), stop)
        if pod["spec"].get("nodeName"):
            break
        case.assertLess(runtime.clock(), stop)
        time.sleep(0.05)
    case.assertEqual(pod["spec"]["nodeName"], runtime.node["name"])
    _, post, second = runtime.collect("pre_export", stop)
    now = runtime.clock()
    # As in the production pre-export planning predicate, future control is a
    # projected copy; the first phase retains the actual ack/release times.
    second = runtime.projected_control(second, now)
    result = runtime.evaluate(pre, post, {"pre_schedule": first, "pre_export": second}, now)
    case.assertEqual(result["decision"], "EXPORT", result)


class PlacementBindingTests(unittest.TestCase):
    def test_r369_pinned_coredns_schema_and_census_n_plus_one(self):
        import json

        from inference_platform.inf037b_eks_placement import (
            census_bound,
            validate_coredns_configuration,
        )

        root = Path(__file__).resolve().parents[2]
        pins = json.loads((root / "infra/terraform/eks/addon-pins.json").read_bytes())
        response = json.loads(
            (root / "docs/evidence/r369-addon-refresh/coredns-configuration.json").read_bytes()
        )
        schema = json.loads(response["configurationSchema"])
        config = pins["coredns_configuration"]
        self.assertTrue(validate_coredns_configuration(config, schema))
        for bad in (
            {**config, "replicaCount": "2"},
            {**config, "nodeSelector": {"m5-role": 1}},
            {**config, "nodeSelector": {"m5-role": "gpu"}},
            {**config, "unknown": True},
        ):
            with self.assertRaisesRegex(ValueError, "placement_api:coredns"):
                validate_coredns_configuration(bad, schema)
        bound = census_bound("gpu")
        self.assertEqual(
            bound["N"],
            sum(bound[k] for k in ("daemonsets", "coredns", "fixed_schedule", "terminal")),
        )
        api = PlacementAPI(
            "https://unused", token="fixture", clock=lambda: 0, retain=lambda *a: None
        )
        n = api.census_limit

        def page(count):
            return {
                "metadata": {"resourceVersion": "1"},
                "items": [
                    {
                        "metadata": {"uid": str(i), "resourceVersion": "1"},
                        "spec": {"nodeName": "node"},
                    }
                    for i in range(count)
                ],
            }

        api.request = Mock(return_value=page(n))
        self.assertEqual(len(api.census({"name": "node"}, 100)["pods"]), n)
        api.request = Mock(return_value=page(n + 1))
        with self.assertRaisesRegex(ValueError, "placement_api:census_pod_limit"):
            api.census({"name": "node"}, 100)

    def test_r369_fixed_workload_terms_match_render_program(self):
        import ast
        import math

        from inference_platform.inf037b_eks_placement import FIXED_POD_TERMS

        root = Path(__file__).resolve().parents[2]
        program = ast.parse((root / "python/src/inference_platform/eks_deployment.py").read_bytes())
        calls = {
            n.args[1].value: n
            for n in ast.walk(program)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "workload"
        }
        redis = calls["redis"]
        self.assertEqual(ast.literal_eval(redis.args[5]), {"type": "Recreate"})
        self.assertEqual(FIXED_POD_TERMS["redis_recreate_replica"], ast.literal_eval(redis.args[2]))
        for name in ("gateway", "vllm"):
            self.assertEqual(ast.literal_eval(calls[name].args[0]), "StatefulSet")
            self.assertEqual(
                FIXED_POD_TERMS[name + "_stateful_slots"], ast.literal_eval(calls[name].args[2])
            )
        for name, key in (
            ("streaming-ingress", "ingress_replica_plus_rollout_surge"),
            ("telemetry", "telemetry_replica_plus_rollout_surge"),
        ):
            call = calls[name]
            self.assertEqual(len(call.args), 5)  # Kubernetes default RollingUpdate.
            replicas = ast.literal_eval(call.args[2])
            self.assertEqual(FIXED_POD_TERMS[key], replicas + math.ceil(replicas / 4))

    def test_r369_each_node_role_has_its_own_n_plus_one_guard(self):
        from inference_platform.inf037b_eks_placement import census_bound

        api = PlacementAPI(
            "https://unused", token="fixture", clock=lambda: 0, retain=lambda *a: None
        )
        for role in ("cpu", "gpu"):
            n = census_bound(role)["N"]

            def page(count):
                return {
                    "metadata": {"resourceVersion": "1"},
                    "items": [
                        {
                            "metadata": {"uid": str(i), "resourceVersion": "1"},
                            "spec": {"nodeName": "node"},
                        }
                        for i in range(count)
                    ],
                }

            api.request = Mock(return_value=page(n))
            self.assertEqual(len(api.census({"name": "node"}, 100, role=role)["pods"]), n)
            api.request = Mock(return_value=page(n + 1))
            with self.assertRaisesRegex(ValueError, "placement_api:census_pod_limit"):
                api.census({"name": "node"}, 100, role=role)

    def test_r369_census_counts_nonfull_continuation_pages(self):
        api = PlacementAPI(
            "https://unused", token="fixture", clock=lambda: 0, retain=lambda *a: None
        )
        page_count = 0

        def request(*args):
            nonlocal page_count
            page_count += 1
            return {"metadata": {"resourceVersion": "1", "continue": str(page_count)}, "items": []}

        api.request = request
        with self.assertRaisesRegex(ValueError, "placement_api:page_cap"):
            api.census({"name": "node"}, 100)
        self.assertEqual(page_count, api.census_limit + 1)
        with self.assertRaisesRegex(ValueError, "placement_api:census_limit_binding"):
            PlacementAPI(
                "https://unused",
                token="fixture",
                clock=lambda: 0,
                retain=lambda *a: None,
                census_limit=api.census_limit + 1,
            )

    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.now, self.mode, self.starts = 1000, None, 0
        self.binding = getattr(
            self,
            "binding_override",
            {"session_id": "s", "C_ms": 1000, "D_session_ms": 18001000, "t0_ms": 0},
        )
        args = fixture()
        self.job = strict_json(args["pre_schedule"]["job"].raw)
        self.pod = strict_json(args["pre_schedule"]["pod"].raw)
        self.node = strict_json(args["pre_schedule"]["node"].raw)
        for obj, name in (
            (self.job, "export"),
            (self.pod, "export-pod"),
            (self.node, "export-node"),
        ):
            obj["metadata"].update(name=name, resourceVersion="10")
        self.pod["metadata"]["labels"] = {"inf037b-role": "export"}
        self.pod["metadata"]["ownerReferences"][0].update(
            kind="Job", name="export", controller=True
        )
        for spec in (self.job["spec"]["template"]["spec"], self.pod["spec"]):
            spec["schedulingGates"] = [{"name": GATE}]
            spec["restartPolicy"] = "Never"
        self.peer = {
            "metadata": {
                "uid": "system-uid",
                "resourceVersion": "30",
                "labels": {"inf037b-role": "system"},
            },
            "spec": {
                "nodeName": "export-node",
                "containers": [{"resources": {"requests": {"memory": "0"}}}],
            },
        }
        self.received = DurableStartSignal(
            journal=FileJournal(self.root / "signal", {}, initialize=True),
            binding=self.binding,
            pod_uid="pod-uid",
            clock_id="clock",
            boot_id="boot",
            clock=lambda: self.now,
        )
        self.wire, self.calls, self.published = [], [], {}
        case = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def reply(self, value, status=200, drop=False):
                data = encode(value)
                if drop:
                    self.close_connection = True
                    return
                self.send_response(status)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                case.now += 1
                case.calls.append(("GET", self.path))
                u = urlsplit(self.path)
                if u.path == "/api/v1/pods":
                    if case.mode == "stale":
                        case.now += 60001
                    token = parse_qs(u.query).get("continue", [""])[0]
                    if case.mode == "gone" and token:
                        return self.reply({"reason": "Expired"}, 410)
                    items = [copy.deepcopy(case.peer)]
                    if case.pod["spec"].get("nodeName"):
                        items.append(copy.deepcopy(case.pod))
                    page = {
                        "metadata": {
                            "resourceVersion": "30",
                            "continue": "next" if not token else "",
                        },
                        "items": items[:1] if not token else items[1:],
                    }
                    if case.mode == "cycle":
                        page["metadata"]["continue"] = (
                            "next"
                            if sum(p.startswith("/api/v1/pods?") for _, p in case.calls) <= 2
                            else ""
                        )
                    if token and case.mode == "mixed":
                        page["metadata"]["resourceVersion"] = "31"
                    if token and case.mode == "duplicate":
                        page["items"] = [copy.deepcopy(case.peer)]
                    if case.mode == "partial" and token:
                        page["metadata"]["remainingItemCount"] = 1
                    if case.mode == "wrong_node":
                        page["items"] = [
                            dict(
                                copy.deepcopy(case.peer),
                                spec=dict(case.peer["spec"], nodeName="wrong"),
                            )
                        ]
                    return self.reply(page)
                if "/jobs/" in self.path:
                    return self.reply(case.job)
                if "/nodes/" in self.path:
                    value = copy.deepcopy(case.node)
                    if (
                        case.mode == "node_changed"
                        and sum("/nodes/" in p for _, p in case.calls) > 1
                    ):
                        value["metadata"]["uid"] = "changed"
                    if (
                        case.mode == "node_name_changed"
                        and sum("/nodes/" in p for _, p in case.calls) > 1
                    ):
                        value["metadata"]["name"] = "wrong-name"
                    return self.reply(value)
                return self.reply(case.pod)

            def do_PUT(self):
                case.now += 1
                body = strict_json(self.rfile.read(int(self.headers["Content-Length"])))
                case.calls.append(("PUT", self.path))
                if self.path == "/start":
                    if case.mode == "delayed":
                        case.now += 60001
                    receipt = case.received.receive(body)
                    if case.mode == "changed_signal":
                        receipt["signal"]["pod_uid"] = "different-pod"
                    return self.reply(receipt, drop=case.mode == "lost_signal")
                if (
                    case.mode == "conflict"
                    or body["metadata"]["uid"] != case.pod["metadata"]["uid"]
                    or body["metadata"]["resourceVersion"]
                    != case.pod["metadata"]["resourceVersion"]
                ):
                    return self.reply({"reason": "Conflict"}, 409)
                case.pod = body
                case.pod["metadata"]["resourceVersion"] = "11"
                case.pod["spec"]["nodeName"] = "export-node"
                if case.mode == "bound_wrong":
                    case.pod["spec"]["nodeName"] = "another"
                return self.reply(case.pod, drop=case.mode == "lost_release")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=self.server.serve_forever)
        thread.start()
        self.addCleanup(thread.join, 2)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        api = PlacementAPI(
            f"http://127.0.0.1:{self.server.server_port}",
            token=lambda: "test",
            clock=lambda: self.now,
            retain=lambda *args: self.wire.append(args),
            local_test=True,
        )
        self.journal = FileJournal(self.root / "state", {}, initialize=True)

        def publish(key, artifacts, stop):
            self.published[key] = {k: Path(v).read_bytes() for k, v in artifacts.items()}
            return {"key": key, "acknowledgements": {"recovery": True, "s3": True}}

        repository = SimpleNamespace(
            binding={"controller": self.binding}, publish=publish, access=lambda receipt, stop: True
        )
        self.options = dict(
            api=api,
            signal_api=api,
            journal=self.journal,
            repository=repository,
            root=self.root / "archives",
            binding=self.binding,
            destination="recovery",
            namespace="unit",
            job="export",
            pod="export-pod",
            node={"name": "export-node", "uid": "node-uid"},
            clock=self.clock,
            clock_id="clock",
            boot_id="boot",
        )
        self.runtime = ExportPlacement(**self.options)

    def clock(self):
        self.now += 1
        return self.now

    def test_host_capacity_body_uses_projected_control_and_capacity_reason(self):
        capacity_case(self, self.runtime, 1000000, "fit")
        self.peer["spec"]["containers"][0]["resources"]["requests"]["memory"] = "1"
        capacity_case(self, self.runtime, 1000000, "short")

    def test_host_release_body_uses_actual_release_then_fresh_projection(self):
        release_case(self, self.runtime, 1000000)

    def test_short_refusal_for_an_unrelated_reason_is_not_accepted(self):
        with self.assertRaises(AssertionError):
            assert_capacity_decision(
                self, {"decision": "REFUSE", "reason": "v4:placement:now"}, "short"
            )

    def test_exact_fit_release_pre_export_and_durable_restart(self):
        result = self.runtime.run(1000000)
        self.assertEqual(result["decision"]["decision"], "EXPORT")
        self.assertEqual(result["decision"]["phases"]["pre_export"]["residual_bytes"], 12884901888)
        self.assertTrue(self.wire)
        original = copy.deepcopy(self.calls)
        self.assertEqual(ExportPlacement(**self.options).run(1000000), result)
        self.assertEqual(self.calls, original)
        self.assertEqual(self.received.take()["decision"]["decision"], "EXPORT")
        with self.assertRaisesRegex(ValueError, "start_once"):
            self.received.take()
        state = self.runtime.state()
        self.assertEqual(state["pre_schedule"]["raw"]["pod"]["metadata"]["resourceVersion"], "10")
        self.assertEqual(len(state["pre_export"]["raw"]["requests"]["pages"]), 2)
        self.assertIn("placement:final", self.published)

    def test_one_byte_short_refuses_and_archives_without_signal(self):
        self.node["status"]["allocatable"]["memory"] = str(12884901887)
        with self.assertRaisesRegex(ValueError, "pre_schedule"):
            self.runtime.run(1000000)
        self.assertIn("placement:refusal-1", self.published)
        self.assertFalse(any(method == "PUT" for method, _ in self.calls))
        with self.assertRaisesRegex(ValueError, "held_no_export"):
            self.received.take()

    def test_census_partial_duplicate_mixed_and_expired_never_release(self):
        for mode, reason in (
            ("partial", "partial_census"),
            ("duplicate", "duplicate_pod"),
            ("mixed", "mixed_census_rv"),
            ("gone", "transport_response"),
            ("wrong_node", "wrong_node"),
        ):
            with self.subTest(mode=mode):
                self.mode = mode
                with self.assertRaisesRegex(ValueError, reason):
                    self.runtime.api.census(self.runtime.node, 1000000)
        self.assertFalse(any(method == "PUT" for method, _ in self.calls))

    def test_wrong_bound_node_refuses_pre_export(self):
        self.mode = "bound_wrong"
        with self.assertRaisesRegex(ValueError, "wrong_node"):
            self.runtime.run(1000000)
        with self.assertRaisesRegex(ValueError, "held_no_export"):
            self.received.take()

    def test_uid_rv_conflict_refuses_without_retry(self):
        self.mode = "conflict"
        with self.assertRaisesRegex(ValueError, "transport_response"):
            self.runtime.run(1000000)
        self.assertEqual(sum(method == "PUT" for method, _ in self.calls), 1)
        with self.assertRaisesRegex(ValueError, "interrupted_no_retry"):
            ExportPlacement(**self.options).run(1000000)

    def test_lost_release_ack_has_no_start_and_restart_cannot_repeat(self):
        self.mode = "lost_release"
        with self.assertRaises(http.client.RemoteDisconnected):
            self.runtime.run(1000000)
        self.assertNotIn(("PUT", "/start"), self.calls)
        with self.assertRaisesRegex(ValueError, "interrupted_no_retry"):
            ExportPlacement(**self.options).run(1000000)

    def test_delayed_signal_is_durably_refused_before_export(self):
        self.mode = "delayed"
        with self.assertRaisesRegex(ValueError, "receiver_refused"):
            self.runtime.run(1000000)
        with self.assertRaisesRegex(ValueError, "held_no_export"):
            self.received.take()
        self.assertEqual(
            self.received.journal.read()["export_start_signal"]["decision"]["decision"], "REFUSE"
        )

    def test_lost_signal_ack_is_single_durable_delivery_and_no_second_start(self):
        self.mode = "lost_signal"
        with self.assertRaises(http.client.RemoteDisconnected):
            self.runtime.run(1000000)
        state = self.received.journal.read()
        signal = state["export_start_signal"]
        self.assertEqual(self.received.lookup(), signal)
        self.assertEqual(sum(path == "/start" for _, path in self.calls), 1)
        with self.assertRaisesRegex(ValueError, "interrupted_no_retry"):
            ExportPlacement(**self.options).run(1000000)

    def test_permission_joins_candidate_hash_and_reproduced_decision(self):
        result = self.runtime.run(1000000)
        altered = copy.deepcopy(result)
        altered["candidate_sha256"] = "f" * 64
        self.runtime.save(permission=altered)
        with self.assertRaisesRegex(ValueError, "decision_signal_join"):
            self.runtime.validate(altered, self.now)

    def test_factory_named_missing_final_placement_inputs(self):
        f = SimpleNamespace(config={}, port=SimpleNamespace(deadline=Mock()))
        with self.assertRaisesRegex(ValueError, "unfinished:4e_export_placement_inputs"):
            PlacementPorts(f).permission(10)

    def test_effective_memory_includes_init_restartable_sidecar_and_overhead(self):
        spec = {
            "containers": [{"resources": {"requests": {"memory": "2Gi"}}}],
            "initContainers": [
                {"restartPolicy": "Always", "resources": {"requests": {"memory": "1Gi"}}},
                {"resources": {"requests": {"memory": "4Gi"}}},
            ],
            "overhead": {"memory": "1Gi"},
        }
        self.assertEqual(effective_memory(spec), 6 * 1024**3)

    def test_stale_census_refuses_release_and_changed_node_identity_refuses(self):
        self.mode = "stale"
        with self.assertRaisesRegex(ValueError, "observation_age"):
            self.runtime.run(1000000)
        self.assertFalse(any(method == "PUT" for method, _ in self.calls))

    def test_refreshed_node_uid_change_refuses(self):
        self.mode = "node_changed"
        with self.assertRaisesRegex(ValueError, "refreshed_identity"):
            self.runtime.run(1000000)
        self.assertFalse(any(method == "PUT" for method, _ in self.calls))

    def test_defaulted_raw_api_hashes_and_pod_defaults_are_preserved(self):
        self.pod["spec"].update(
            serviceAccountName="default", priority=0, schedulerName="default-scheduler"
        )
        self.pod["spec"]["containers"][0].update(
            imagePullPolicy="IfNotPresent", terminationMessagePath="/dev/termination-log"
        )
        permission = self.runtime.run(1000000)
        state = self.runtime.state()
        self.assertEqual(
            state["pre_schedule"]["raw"]["pod"]["spec"]["serviceAccountName"], "default"
        )
        for phase in ("pre_schedule", "pre_export"):
            for key in ("job", "pod", "node"):
                index = state[phase]["reads"][key]["wire_records"][0]
                original = b"".join(
                    bytes.fromhex(f["raw_hex"])
                    for f in self.runtime.api.records[index]["fragments"]
                    if f["metadata"].get("direction") == "response"
                )
                self.assertEqual(
                    permission["decision"]["sources"][phase + "/" + key]["sha256"], sha(original)
                )

    def test_factory_binding_and_restart_cannot_reuse_a_stale_permission(self):
        from inference_platform.inf037b_eks_commands import EKSCommandFactory

        factory = SimpleNamespace(
            binding=self.binding,
            config={"export_placement": self.runtime},
            port=SimpleNamespace(deadline=Mock()),
            implementations={},
        )
        permission = EKSCommandFactory.dependency(factory, "4d_export_permission")(1000000)
        self.assertEqual(permission["decision"]["decision"], "EXPORT")
        self.now += 60001
        with self.assertRaisesRegex(ValueError, "permission_stale"):
            ExportPlacement(**self.options).run(1000000)

    def test_effective_init_request_makes_residual_one_byte_short(self):
        self.node["status"]["allocatable"]["memory"] = str(12884901888 + 1024**3 - 1)
        self.peer["spec"]["initContainers"] = [{"resources": {"requests": {"memory": "1Gi"}}}]
        with self.assertRaisesRegex(ValueError, "residual"):
            self.runtime.run(1000000)

    def test_real_4c_publication_and_both_readbacks_precede_release(self):
        import test_inf037b_eks_stores as store_tests

        case = store_tests.StoreTests(methodName="runTest")
        case.setUp()
        self.addCleanup(case.doCleanups)
        case.binding["controller"] = self.binding
        case.journal = FileJournal(case.root / "placement-publish-journal", {}, initialize=True)
        case.repository = case.open()
        case.repository.clock = case.access.clock = lambda: self.now
        self.options["repository"] = case.repository
        runtime = ExportPlacement(**self.options)
        permission = runtime.run(1000000)
        self.assertEqual(permission["decision"]["decision"], "EXPORT")
        for name in ("pre-schedule", "pre-export", "final"):
            receipt = runtime.state()[name + "_store_receipt"]
            self.assertEqual(set(receipt["acknowledgements"]), {"recovery", "s3"})
            self.assertTrue(case.repository.access(receipt, 1000000))
        self.assertEqual(case.persist_count, 3)

    def test_late_store_ack_cannot_release_the_scheduling_gate(self):
        publish = self.runtime.repository.publish

        def delayed(*args):
            result = publish(*args)
            self.now += 60001
            return result

        self.runtime.repository.publish = delayed
        with self.assertRaisesRegex(ValueError, "pre_release"):
            self.runtime.run(1000000)
        self.assertFalse(any(method == "PUT" for method, _ in self.calls))

    def test_pod_level_and_in_place_resize_requests_are_counted(self):
        spec = {
            "containers": [{"name": "app", "resources": {"requests": {"memory": "2Gi"}}}],
            "overhead": {"memory": "1Gi"},
        }
        status = {
            "containerStatuses": [
                {
                    "name": "app",
                    "resources": {"requests": {"memory": "3Gi"}},
                    "allocatedResources": {"memory": "4Gi"},
                }
            ]
        }
        self.assertEqual(effective_memory(spec, status), 5 * 1024**3)
        spec["resources"] = {"requests": {"memory": "6Gi"}}
        self.assertEqual(effective_memory(spec, status), 7 * 1024**3)

    def test_duplicate_signal_cannot_open_the_held_exporter(self):
        self.runtime.run(1000000)
        original = self.received.lookup()
        with self.assertRaisesRegex(ValueError, "duplicate_signal"):
            self.received.receive(original["signal"])
        with self.assertRaisesRegex(ValueError, "duplicate_signal"):
            self.received.take()
        self.assertEqual(self.received.lookup(), original)

    def test_production_signal_http_handler_and_held_callback(self):
        from inference_platform.inf037b_eks_placement import held_exporter, signal_handler

        self.runtime.run(1000000)
        signal = self.received.lookup()["signal"]
        journal = FileJournal(self.root / "production-signal", {}, initialize=True)
        service = DurableStartSignal(
            journal=journal,
            binding=self.binding,
            pod_uid="pod-uid",
            clock_id="clock",
            boot_id="boot",
            clock=lambda: self.now,
        )
        server = ThreadingHTTPServer(("127.0.0.1", 0), signal_handler(service, lambda: "test"))
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            api = PlacementAPI(
                f"http://127.0.0.1:{server.server_port}",
                token=lambda: "test",
                clock=lambda: self.now,
                retain=lambda *args: None,
                local_test=True,
            )
            receipt = api.request("PUT", "/start", 1000000, signal)
            self.assertEqual(receipt["decision"]["decision"], "EXPORT")
            export = Mock(return_value="exported")
            self.assertEqual(held_exporter(service, export), "exported")
            export.assert_called_once()
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_original_operation_cutoff_bounds_received_signal_and_take(self):
        self.runtime.run(1000000)
        receipt = self.received.lookup()
        fresh = DurableStartSignal(
            journal=FileJournal(self.root / "late-signal", {}, initialize=True),
            binding=self.binding,
            pod_uid="pod-uid",
            clock_id="clock",
            boot_id="boot",
            clock=lambda: self.now,
        )
        signal = copy.deepcopy(receipt["signal"])
        signal["stop_ms"] = self.now
        with self.assertRaisesRegex(ValueError, "signal_deadline"):
            fresh.receive(signal)
        self.now = 1000000
        with self.assertRaisesRegex(ValueError, "held_cutoff"):
            self.received.take()

    def test_refreshed_node_name_with_same_uid_refuses(self):
        self.mode = "node_name_changed"
        with self.assertRaisesRegex(ValueError, "refreshed_identity"):
            self.runtime.run(1000000)
        self.assertFalse(any(method == "PUT" for method, _ in self.calls))

    def test_pod_without_scheduling_gate_refuses_before_any_put(self):
        self.pod["spec"].pop("schedulingGates")
        with self.assertRaisesRegex(ValueError, "scheduling_gate"):
            self.runtime.run(1000000)
        self.assertFalse(any(m == "PUT" for m, _ in self.calls))

    def test_refusal_control_never_claims_an_ack_or_received_signal(self):
        self.node["status"]["allocatable"]["memory"] = str(12884901887)
        with self.assertRaisesRegex(ValueError, "pre_schedule"):
            self.runtime.run(1000000)
        for phase in (
            self.runtime.state()["pre_schedule"],
            strict_json(self.published["placement:refusal-1"]["refusal-1.json"])["state"][
                "pre_schedule"
            ],
        ):
            self.assertFalse(phase["control"]["acknowledged"])
            self.assertFalse(phase["control"]["received_once"])
            self.assertIsNone(phase["control"]["ack_ms"])
            self.assertIsNone(phase["control"]["signal_ms"])

    def test_late_store_ack_is_not_recorded_as_a_valid_ack(self):
        publish = self.runtime.repository.publish

        def late(*args):
            value = publish(*args)
            self.now += 60001
            return value

        self.runtime.repository.publish = late
        with self.assertRaisesRegex(ValueError, "pre_release"):
            self.runtime.run(1000000)
        archived = strict_json(self.published["placement:refusal-1"]["refusal-1.json"])
        self.assertFalse(self.runtime.state()["pre_schedule"]["control"]["acknowledged"])
        self.assertFalse(archived["state"]["pre_schedule"]["control"]["acknowledged"])

    def test_missing_pre_export_publication_refuses_durable_ack(self):
        publish = self.runtime.publish

        def skip(name, value, stop):
            if name == "pre-export":
                return sha(encode(value))
            return publish(name, value, stop)

        self.runtime.publish = skip
        with self.assertRaisesRegex(ValueError, "placement:durable_ack"):
            self.runtime.run(1000000)
        self.assertFalse(self.runtime.state()["pre_export"]["control"]["acknowledged"])
        self.assertNotIn("permission", self.runtime.state())

    def test_receiver_changed_signal_echo_refuses(self):
        self.mode = "changed_signal"
        with self.assertRaisesRegex(ValueError, "signal_join"):
            self.runtime.run(1000000)
        self.assertNotIn("permission", self.runtime.state())

    def test_continue_token_cycle_refuses(self):
        self.mode = "cycle"
        with self.assertRaisesRegex(ValueError, "continue_cycle"):
            self.runtime.api.census(self.runtime.node, 1000000)

    def test_http_terminal_census_acceptance_or_refusal_keeps_counted_bytes(self):
        for capacity, expected in (("12Gi", "REFUSE"), ("13Gi", "EXPORT")):
            with self.subTest(capacity=capacity):
                case = PlacementBindingTests(methodName="runTest")
                case.setUp()
                self.addCleanup(case.doCleanups)
                case.peer["status"] = {"phase": "Succeeded"}
                case.peer["spec"]["containers"][0]["resources"]["requests"]["memory"] = "1Gi"
                case.node["status"]["allocatable"]["memory"] = capacity
                if expected == "REFUSE":
                    with self.assertRaisesRegex(ValueError, "residual_terminal_counted"):
                        case.runtime.run(1000000)
                    decision = case.runtime.state()["pre_schedule_projected"]
                else:
                    decision = case.runtime.run(1000000)["decision"]
                self.assertEqual(decision["decision"], expected, decision)
                facts = decision["phases"]["pre_schedule"]
                self.assertEqual(
                    facts["terminal_pods"],
                    [
                        {
                            "uid": case.peer["metadata"]["uid"],
                            "phase": "Succeeded",
                            "memory_bytes": 1024**3,
                        }
                    ],
                )
                self.assertEqual(facts["other_requests_bytes"], 1024**3)
                if expected == "REFUSE":
                    self.assertIn("residual_terminal_counted", decision["reason"])
                    self.assertEqual(case.starts, 0)

    def test_terminal_pod_request_is_counted_without_reclamation(self):
        for phase in ("Succeeded", "Failed"):
            with self.subTest(phase=phase):
                raw = {
                    "job": self.job,
                    "pod": self.pod,
                    "node": self.node,
                    "requests": {
                        "pods": [
                            dict(
                                copy.deepcopy(self.peer),
                                status={"phase": phase},
                                spec=dict(
                                    self.peer["spec"],
                                    containers=[{"resources": {"requests": {"memory": "1Gi"}}}],
                                ),
                            )
                        ]
                    },
                }
                from inference_platform.inf037b_eks_placement import project

                projected = project(raw, "pre_schedule")["requests"]["pods"][0]
                self.assertEqual(projected["phase"], phase)
                self.assertEqual(projected["memory_requests"], [str(1024**3)])
                self.assertEqual(projected["uid"], self.peer["metadata"]["uid"])

    def test_collected_controls_are_false_until_the_real_acks_and_replies(self):
        publish = self.runtime.repository.publish
        observed = []

        def verify(key, artifacts, stop):
            if key in ("placement:pre-schedule", "placement:pre-export"):
                phase = "pre_schedule" if key.endswith("pre-schedule") else "pre_export"
                control = self.runtime.state()[phase]["control"]
                self.assertFalse(control["acknowledged"])
                self.assertFalse(control["received_once"])
                self.assertIsNone(control["ack_ms"])
                self.assertIsNone(control["signal_ms"])
                observed.append(phase)
            return publish(key, artifacts, stop)

        self.runtime.repository.publish = verify
        self.assertEqual(self.runtime.run(1000000)["decision"]["decision"], "EXPORT")
        self.assertEqual(observed, ["pre_schedule", "pre_export"])
        for phase in observed:
            actual = self.runtime.state()[phase]["control"]
            self.assertTrue(actual["acknowledged"])
            self.assertTrue(actual["received_once"])
            self.assertFalse(self.runtime.state()[phase]["collected_control"]["acknowledged"])


class ReceivedAgeTests(unittest.TestCase):
    def test_received_signal_age_equal_and_plus_one(self):
        for age in (60000, 60001):
            with self.subTest(age=age), TemporaryDirectory() as temporary:
                args = fixture()
                args["control"]["pre_schedule"]["reads"] = {
                    k: dict(v, ms=[100, 100])
                    for k, v in args["control"]["pre_schedule"]["reads"].items()
                }
                auth = {
                    phase: {
                        k: {"raw_hex": v.raw.hex(), "observed_ms": v.observed_ms}
                        for k, v in args[phase].items()
                    }
                    for phase in ("pre_schedule", "pre_export")
                }
                auth["control"] = args["control"]
                args["verified"] = args["pre_schedule"]["verified"]
                auth["candidate"] = {"projected": copy.deepcopy(check_placement(**args))}
                binding = {"C_ms": 1000, "D_session_ms": 18001000, "t0_ms": 0}
                service = DurableStartSignal(
                    journal=FileJournal(Path(temporary), {}, initialize=True),
                    binding=binding,
                    pod_uid="pod-uid",
                    clock_id="common",
                    boot_id="host",
                    clock=lambda age=age: 200 + age,
                )
                signal = {
                    "binding": binding,
                    "stop_ms": 1000000,
                    "pod_uid": "pod-uid",
                    "clock_id": "common",
                    "boot_id": "host",
                    "authorization": auth,
                    "decision_sha256": sha(encode(auth["candidate"])),
                }
                receipt = service.receive(signal)
                self.assertEqual(
                    receipt["decision"]["decision"], "EXPORT" if age == 60000 else "REFUSE"
                )
                if age == 60000:
                    self.assertTrue(service.take())
                else:
                    with self.assertRaisesRegex(ValueError, "held_no_export"):
                        service.take()


class HeldExporterTests(unittest.TestCase):
    def test_no_callback_before_or_after_refused_signal(self):
        from inference_platform.inf037b_eks_placement import held_exporter

        with TemporaryDirectory() as temporary:
            journal = FileJournal(Path(temporary), {}, initialize=True)
            service = DurableStartSignal(
                journal=journal, binding={}, pod_uid="p", clock_id="c", boot_id="b", clock=lambda: 0
            )
            export = Mock()
            with self.assertRaisesRegex(ValueError, "held_no_export"):
                held_exporter(service, export)
            journal.write({"export_start_signal": {"decision": {"decision": "REFUSE"}}})
            with self.assertRaisesRegex(ValueError, "held_no_export"):
                held_exporter(service, export)
            export.assert_not_called()


@unittest.skipUnless(
    os.environ.get("INF037B_PLACEMENT_HOST_CONFIG"),
    "real kind/kube-apiserver cases run on AWS CPU host",
)
class HostPlacementTests(unittest.TestCase):
    """Host fixture owns dedicated gated Jobs/Pods and isolated 12 GiB nodes.

    Config: api {base,token_file,ca}, cases {fit,short,release,conflict}, each
    {namespace,job,pod,node:{name,uid}}. Fit has residual exactly 12 GiB;
    short has residual 12 GiB minus one byte. Only API/scheduler semantics
    are claimed here; two-store durability remains the separate host suite.
    """

    def runtime(self, name):
        config = strict_json(Path(os.environ["INF037B_PLACEMENT_HOST_CONFIG"]).read_bytes())
        case = config["cases"][name]
        root = Path(self.enterContext(TemporaryDirectory(prefix="part5-real-api-")))

        def clock():
            return time.monotonic_ns() // 1000000

        now = clock()
        binding = {
            "session_id": "part5-host-test",
            "C_ms": now,
            "D_session_ms": now + 18000000,
            "t0_ms": now,
        }
        raw = []
        api = PlacementAPI(
            config["api"]["base"],
            token=lambda: Path(config["api"]["token_file"]).read_text().strip(),
            ca=config["api"]["ca"],
            clock=clock,
            retain=lambda *args: raw.append(args),
        )
        repo = SimpleNamespace(
            binding={"controller": binding},
            publish=lambda *args: {"acknowledgements": {"recovery": True, "s3": True}},
            access=lambda *args: True,
        )
        runtime = ExportPlacement(
            api=api,
            signal_api=api,
            journal=FileJournal(root / "journal", {}, initialize=True),
            repository=repo,
            root=root / "archive",
            binding=binding,
            destination="test",
            clock=clock,
            clock_id="host-monotonic",
            boot_id=config["boot_id"],
            **case,
        )
        return runtime, clock() + 60000

    def test_real_defaulted_api_exact_fit_and_one_byte_short(self):
        for name in ("fit", "short"):
            with self.subTest(name=name):
                runtime, stop = self.runtime(name)
                capacity_case(self, runtime, stop, name)

    def test_real_api_uid_and_stale_resource_version_conflicts(self):
        runtime, stop = self.runtime("conflict")
        path = runtime.path("pods", runtime.pod)
        original = runtime.api.request("GET", path, stop)
        changed = copy.deepcopy(original)
        changed["metadata"].setdefault("annotations", {})["inf037b-test-update"] = "updated"
        fresh = runtime.api.request("PUT", path, stop, changed)
        self.assertNotEqual(
            fresh["metadata"]["resourceVersion"], original["metadata"]["resourceVersion"]
        )
        for body in (
            original,
            dict(copy.deepcopy(fresh), metadata=dict(fresh["metadata"], uid="wrong-uid")),
        ):
            with self.assertRaisesRegex(ValueError, "transport_response"):
                runtime.api.request("PUT", path, stop, body)
        held = runtime.api.request("GET", path, stop)
        self.assertFalse(held["spec"].get("nodeName"))
        self.assertEqual(held["spec"]["schedulingGates"], [{"name": GATE}])

    def test_real_scheduling_gate_release_then_fresh_pre_export(self):
        runtime, stop = self.runtime("release")
        release_case(self, runtime, stop)


def signal_case(root, now):
    args = fixture()
    args["verified"] = args["pre_schedule"]["verified"]
    binding = {"C_ms": 1000, "D_session_ms": 18001000, "t0_ms": 0}
    auth = {
        phase: {
            k: {"raw_hex": v.raw.hex(), "observed_ms": v.observed_ms}
            for k, v in args[phase].items()
        }
        for phase in ("pre_schedule", "pre_export")
    }
    auth["control"] = copy.deepcopy(args["control"])
    auth["candidate"] = {"projected": copy.deepcopy(check_placement(**args))}
    signal = {
        "binding": binding,
        "stop_ms": 1000000,
        "pod_uid": "pod-uid",
        "clock_id": "common",
        "boot_id": "host",
        "authorization": auth,
        "decision_sha256": sha(encode(auth["candidate"])),
    }
    service = DurableStartSignal(
        journal=FileJournal(root, {}, initialize=True),
        binding=binding,
        pod_uid="pod-uid",
        clock_id="common",
        boot_id="host",
        clock=lambda: now[0],
    )
    return service, signal


class SignalRefusalTests(unittest.TestCase):
    def test_take_age_exact_limit_and_one_ms_late(self):
        for age in (60000, 60001):
            with self.subTest(age=age), TemporaryDirectory() as directory:
                now = [200]
                service, signal = signal_case(Path(directory), now)
                self.assertEqual(service.receive(signal)["decision"]["decision"], "EXPORT")
                now[0] = 200 + age
                if age == 60000:
                    self.assertTrue(service.take())
                else:
                    with self.assertRaisesRegex(ValueError, "held_stale"):
                        service.take()

    def test_durable_receive_write_that_exceeds_age_records_refusal(self):
        with TemporaryDirectory() as directory:
            now = [200]
            service, signal = signal_case(Path(directory), now)
            write = service.journal.write
            advanced = [False]

            def slow(state):
                write(state)
                if not advanced[0]:
                    now[0] += 60001
                    advanced[0] = True

            service.journal.write = slow
            receipt = service.receive(signal)
            self.assertEqual(receipt["decision"]["decision"], "REFUSE")
            self.assertIn("observation_age", receipt["decision"]["reason"])
            self.assertEqual(service.lookup(), receipt)
            with self.assertRaisesRegex(ValueError, "held_no_export"):
                service.take()

    def test_receiver_reproduces_the_candidate_not_only_its_hash(self):
        with TemporaryDirectory() as directory:
            now = [200]
            service, signal = signal_case(Path(directory), now)
            signal["authorization"]["candidate"]["projected"]["reason"] = "different"
            signal["decision_sha256"] = sha(encode(signal["authorization"]["candidate"]))
            with self.assertRaisesRegex(ValueError, "received_candidate_join"):
                service.receive(signal)
