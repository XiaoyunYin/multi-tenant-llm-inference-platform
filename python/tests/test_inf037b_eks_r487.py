"""R487 negative joins against real local TCP/file component fixtures."""

import copy
import unittest
from pathlib import Path
from unittest.mock import patch

import test_inf037b_eks_cluster_checks as cluster_fixture
import test_inf037b_eks_commands as commands_fixture
import test_inf037b_eks_execution as execution_fixture
import test_inf037b_eks_host as host_fixture
import test_inf037b_eks_provider as provider_fixture
from inf037b_eks_supervisor_worker import FileJournal

from inference_platform.inf037b_archive import encode, sha
from inference_platform.inf037b_eks_cluster import ClusterPorts, pod_path
from inference_platform.inf037b_eks_commands import TerminalAuthorityPort
from inference_platform.inf037b_eks_execution import ExecutionRuntime, join_execution


class JoinTests(unittest.TestCase):
    def case(self, cls):
        c = cls("runTest")
        c.setUp()
        self.addCleanup(c.doCleanups)
        return c

    def test_catalog_actual_file_hash_refuses(self):
        c = self.case(execution_fixture.ExecutionTests)
        root = Path(c.catalog["owners"][0]["root"])
        (root / "partial.bin").write_bytes(b"changed adverse bytes")
        with self.assertRaisesRegex(ValueError, "execution:catalog_files"):
            c.call("4d_terminal_capture_inventory", 10000)

    def test_catalog_open_descriptor_refuses(self):
        c = self.case(execution_fixture.ExecutionTests)
        c.catalog["owners"][0]["descriptor"]["closed"] = False
        Path(c.inputs["terminal_capture_catalog"]["path"]).write_bytes(encode(c.catalog))
        with self.assertRaisesRegex(ValueError, "execution:catalog_open"):
            c.call("4d_terminal_capture_inventory", 10000)

    def test_consumer_requires_retained_receipt(self):
        c = self.case(execution_fixture.ExecutionTests)
        result = c.call("4d_terminal_capture_inventory", 10000)
        with c.runtime.store.lock():
            state = c.runtime.store.read()
            state["execution_receipts"] = []
            c.runtime.store.write(state)
        with self.assertRaisesRegex(ValueError, "execution:consumer_retained"):
            join_execution(result, c.factory, "4d_terminal_capture_inventory")

    def test_host_result_destination_refuses_after_real_exchange(self):
        c = self.case(host_fixture.HostTests)
        runtime, factory = c.runtime()
        original = c.remote.call

        def corrupt(*args):
            result = original(*args)
            result["destination"] = {**result["destination"], "node_uid": "foreign"}
            return result

        with (
            patch.object(c.remote, "call", side_effect=corrupt),
            self.assertRaisesRegex(ValueError, "execution:host_result_destination"),
        ):
            runtime.dependency("export_host_stage_fixture", factory)(c.request)
        self.assertEqual(c.count, 1)

    def test_supervisor_same_host_refuses(self):
        c = self.case(execution_fixture.ExecutionTests)
        inputs = copy.deepcopy(c.inputs)
        inputs["recovery_supervisor"]["supervisor_host"] = inputs["recovery_supervisor"][
            "controller_host"
        ]
        path = c.root / "same-host.json"
        path.write_bytes(encode(inputs))
        c.config["execution_runtime"] = ExecutionRuntime(
            binding=c.binding,
            pins=c.pins,
            source={"path": str(path), "sha256": sha(path.read_bytes())},
            journal=FileJournal(c.root / "same-host-state", {}, initialize=True),
            clock=lambda: 100,
            components=c.components,
        )
        with self.assertRaisesRegex(ValueError, "execution:independence"):
            c.call("4d_independent_recovery", 10000)

    def test_artifact_access_endpoint_refuses(self):
        c = self.case(execution_fixture.ExecutionTests)
        c.case.access.url = c.case.access.url._replace(path="/foreign")
        with self.assertRaisesRegex(ValueError, "execution:access_endpoint"):
            c.call("4d_recovery_store_runtime", 10000)

    def test_host_interrupted_copy_cannot_be_directly_repeated(self):
        c = self.case(host_fixture.HostTests)
        c.cut = True
        with self.assertRaisesRegex(OSError, "crash after data"):
            c.executor.effect("eks.host.stage", "same", c.request)
        c.executor = c.open()
        c.cut = False
        with self.assertRaisesRegex(ValueError, "eks_host:interrupted_no_retry"):
            c.executor.effect("eks.host.stage", "same", c.request)
        self.assertEqual(c.count, 1)

    def test_host_staged_mount_inventory_refuses(self):
        c = self.case(host_fixture.HostTests)
        original = c.executor.stage

        def corrupt(**kwargs):
            result = original(**kwargs)
            (Path(c.destination["mount_path"]) / "real.bin").write_bytes(b"wrong")
            return result

        c.executor.stage = corrupt
        with self.assertRaisesRegex(ValueError, "eks_host:staged_inventory"):
            c.executor.effect("eks.host.stage", "same", c.request)

    def test_host_reconciliation_requires_original_request(self):
        c = self.case(host_fixture.HostTests)
        c.executor.effect("eks.host.stage", "same", c.request)
        with self.assertRaisesRegex(ValueError, "eks_host:reconcile_request"):
            c.executor.reconcile("eks.host.stage", "same", {**c.request, "source": "changed"})

    def test_provider_observation_binding_refuses(self):
        c = self.case(provider_fixture.ProviderTests)
        c.bad = {"binding": {**c.binding, "session_id": "foreign"}}
        with self.assertRaisesRegex(ValueError, "eks_provider:read_binding"):
            c.backend.read("eks.inventory", "read", c.body)

    def test_terminal_inventory_scope_hash_refuses(self):
        c = self.case(provider_fixture.ProviderTests)
        original = c.backend.client.read

        def corrupt(request):
            result = original(request)
            result["result"]["scope_sha256"] = "f" * 64
            return result

        c.backend.client.read = corrupt
        body = {
            **c.body,
            "scope": {k: c.binding[k] for k in ("session_id", "t0_ms", "group", "tokens")},
        }
        with self.assertRaisesRegex(ValueError, "eks_provider:inventory_scope"):
            c.backend.read("eks.terminal.inventory", "volumes", body)

    def test_provider_inventory_application_refuses(self):
        c = self.case(provider_fixture.ProviderTests)
        original = c.backend.client.read

        def corrupt(request):
            result = original(request)
            result["result"]["application"]["plan_hash"] = "f" * 64
            return result

        c.backend.client.read = corrupt
        with self.assertRaisesRegex(ValueError, "eks_provider:application"):
            c.backend.read("eks.inventory", "read", c.body)

    def test_settle_without_local_intent_refuses(self):
        c = self.case(provider_fixture.ProviderTests)
        with self.assertRaisesRegex(ValueError, "eks_provider:missing_intent"):
            c.remote.call(
                "intent.settle",
                "missing",
                0,
                {"operation": "eks.creation.allocate", "body": c.body, "retry": False},
            )

    def test_template_cannot_supply_uid_rv_or_delete_preconditions(self):
        c = self.case(cluster_fixture.ClusterCheckTests)
        f = c.c
        for supplied in (
            {"metadata": {"uid": "self-supplied"}},
            {"metadata": {"resourceVersion": "99"}},
            {"preconditions": {"uid": "self-supplied"}},
        ):
            with self.subTest(supplied=supplied):
                template = c.template(
                    "DELETE" if "preconditions" in supplied else "PUT",
                    {"role": "object", "name": "report0"},
                    {"from": "object", "name": "report0"},
                    supplied,
                )
                before = len(f.writes)
                with self.assertRaisesRegex(ValueError, "cluster:template_preconditions"):
                    f.runtime.action("supplied:" + str(before), template, 1000000)
                self.assertEqual(len(f.writes), before)

    def test_admitted_slot_record_must_match_target_slot(self):
        c = self.case(cluster_fixture.ClusterCheckTests)
        f = c.c
        f.call("campaign_capture_runtime")
        f.objects[pod_path("unit", "engine-0")]["metadata"]["uid"] = "replacement"
        f.campaign.rows("kubernetes").row(
            "kubernetes",
            "kubernetes",
            f.campaign.boot,
            "pod_created",
            {"pod_uid": "replacement", "slot": 1, "node_pseudonym": "node1"},
        )
        f.inputs["campaign_actions"]["attempt:1"]["effects"] = [
            c.template(
                "DELETE", {"role": "slot_pod", "slot": 0}, {"from": "admitted_slot", "slot": 0}
            )
        ]
        actions = ClusterPorts(f.factory).actions(
            "attempt", f.campaign, 1000000, f.context, None, reset=None
        )
        before = len(f.writes)
        with self.assertRaisesRegex(ValueError, "cluster:target_uid"):
            actions["kubernetes"]()
        self.assertEqual(len(f.writes), before)

    def test_completed_setup_step_requires_original_request_key(self):
        c = self.case(cluster_fixture.ClusterCheckTests)
        c.through_cold()
        before = len(c.c.writes)
        with self.assertRaisesRegex(ValueError, "cluster:setup_effect_key"):
            c.c.runtime.setup_effect("cold", "changed-key", 1000000)
        self.assertEqual(len(c.c.writes), before)


class ProviderConsumerTests(unittest.TestCase):
    def setUp(self):
        self.c = provider_fixture.ProviderTests("runTest")
        self.c.setUp()
        self.addCleanup(self.c.doCleanups)
        self.f = self.factory()
        client = self.c.backend.client

        def execute(request):
            self.c.count += 1
            result = (
                {"instance_ids": ["instance-created"], "raw_hex": b"provider-created".hex()}
                if request["operation"] == "eks.creation"
                else {"deleted": True}
            )
            self.c.rows[request["key"]] = result
            if self.c.drop:
                self.c.drop = False
                raise OSError("lost provider reply")
            return client.response(request, result)

        client.execute = execute

    def factory(self):
        with patch.object(
            commands_fixture,
            "SnapshotStore",
            side_effect=lambda directory, initial: FileJournal(directory, initial, initialize=True),
        ):
            f = commands_fixture.shell(self.c.root, "http://unused.invalid")
        self.c.binding = copy.deepcopy(f.binding)
        self.c.pins = copy.deepcopy(f.config["pins"])
        self.c.backend.binding = copy.deepcopy(f.binding)
        self.c.backend.pins = copy.deepcopy(f.config["pins"])
        f.port.authority = self.c.open()
        return f

    def context(self):
        stop = self.f.binding["t0_ms"] + 1000
        return {
            "operation_key": self.f.port.driver_key + ":creation",
            "operation_label": "creation",
            "measurement_deadline_ms": stop,
            "kill_cutoff_ms": stop - 1,
            "input": {},
        }

    def scope(self):
        return {k: self.f.binding[k] for k in ("session_id", "t0_ms", "group", "tokens")}

    def test_factory_inventory_lost_read_and_reopen(self):
        app = {k: self.f.binding[k] for k in ("session_id", "plan_hash")}
        stop = self.context()["measurement_deadline_ms"]
        self.c.unknown = True
        with self.assertRaises(OSError):
            self.f.port.inventory(app, stop)
        self.c.unknown = False
        self.f = self.factory()
        self.assertEqual(self.f.port.inventory(app, stop)["application"], app)

    def test_factory_create_lost_reply_restarts_through_own_settle(self):
        context = self.context()
        self.c.drop = True
        ids = []
        with self.assertRaises(OSError):
            self.f.port.create(
                context["operation_key"], context["measurement_deadline_ms"], context, ids.append
            )
        self.f = self.factory()
        with patch.object(self.f.port, "settle", wraps=self.f.port.settle) as settle:
            raw = self.f.port.create(
                context["operation_key"], context["measurement_deadline_ms"], context, ids.append
            )
            self.assertEqual(settle.call_count, 1)
        self.assertEqual(raw, b"provider-created")
        self.assertEqual(ids, ["instance-created"])
        self.assertEqual(self.c.count, 1)

    def test_terminal_delete_lost_reply_restarts_through_own_settle(self):
        scope = self.scope()
        stop = self.context()["measurement_deadline_ms"]
        key = self.f.port.driver_key + ":cleanup:delete_ingress"
        self.c.drop = True
        with self.assertRaises(OSError):
            TerminalAuthorityPort(self.f).effect("delete_ingress", key, {"scope": scope}, stop)
        self.f = self.factory()
        with patch.object(self.f.port, "settle", wraps=self.f.port.settle) as settle:
            result = TerminalAuthorityPort(self.f).effect(
                "delete_ingress", key, {"scope": scope}, stop
            )
            self.assertEqual(settle.call_count, 1)
        self.assertEqual(result, {"deleted": True})
        self.assertEqual(self.c.count, 1)

    def test_terminal_inventory_lost_read_and_reopen(self):
        scope = self.scope()
        stop = self.context()["measurement_deadline_ms"]
        self.c.unknown = True
        with self.assertRaises(OSError):
            TerminalAuthorityPort(self.f).inventory("volumes", scope, stop)
        self.c.unknown = False
        self.f = self.factory()
        result = TerminalAuthorityPort(self.f).inventory("volumes", scope, stop)
        self.assertEqual(result["scope_sha256"], sha(encode(scope)))
        self.assertEqual(result["resources"], [])

    def test_not_executed_with_nonnull_result_stays_unknown(self):
        context = self.context()
        self.c.drop = True
        with self.assertRaises(OSError):
            self.f.port.create(
                context["operation_key"],
                context["measurement_deadline_ms"],
                context,
                lambda _: None,
            )
        client = self.c.backend.client
        client.reconcile = lambda request: client.response(
            request, {"non_null": "cannot prove no effect"}, executed=False
        )
        self.f = self.factory()
        with self.assertRaisesRegex(OSError, "ports:response_unknown"):
            self.f.port.create(
                context["operation_key"],
                context["measurement_deadline_ms"],
                context,
                lambda _: None,
            )
        self.assertEqual(self.c.count, 1)
