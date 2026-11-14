"""Real TCP Kubernetes protocol and portable journals; no hardware/host claim."""

import copy
import http.client
import json
import os
import subprocess
import sys
import threading
import time
import unittest
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

from inf037b_eks_supervisor_worker import FileJournal
from test_inf037b_eks_probe import component_owner
from test_inf037b_terminal import MemoryStore

from inference_platform.inf037b_archive import encode, sha, strict_json
from inference_platform.inf037b_capture_inventory import wire_files
from inference_platform.inf037b_device import (
    DeviceSource,
    command,
    proc_identity,
    process_start,
    smi_xml,
)
from inference_platform.inf037b_eks_cluster import (
    PORTS,
    SETUP_ORDER,
    ClusterPorts,
    ClusterRuntime,
    join_cluster,
    pod_path,
)
from inference_platform.inf037b_eks_commands import EKSCommandFactory, LifecycleAuthorityPort
from inference_platform.inf037b_eks_placement import PlacementAPI
from inference_platform.inf037b_live import LifecycleReceiptProducer


class ClusterTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.now = 1000
        self.after_write = None
        self.delete_pending = self.ignore_delete = False
        self.uid_serial = 0
        self.drop = False
        self.drop_write = False
        self.conflict = False
        self.census_partial = False
        self.gets = []
        self.writes = []
        self.wire = []
        self.binding = {"session_id": "s", "C_ms": 0, "D_session_ms": 18000000, "t0_ms": 0}
        self.pins = dict.fromkeys(
            ("configuration", "model", "runtime", "metric_semantics"), "a" * 64
        )
        self.config = {
            "cluster_path": "/api/v1/namespaces/kube-system",
            "cluster_uid": "cluster-uid",
            "namespace": "unit",
            "nodes": {
                str(i): {"name": "node" + str(i), "uid": "node-uid" + str(i)} for i in (0, 1)
            },
            "slots": {str(i): {"name": "engine-" + str(i)} for i in (0, 1)},
        }

        def meta(name, uid):
            return {"name": name, "uid": uid, "resourceVersion": "1"}

        self.objects = {
            self.config["cluster_path"]: {
                "kind": "Namespace",
                "metadata": meta("kube-system", "cluster-uid"),
            }
        }
        for i in (0, 1):
            self.objects["/api/v1/nodes/node" + str(i)] = {
                "kind": "Node",
                "metadata": meta("node" + str(i), "node-uid" + str(i)),
                "status": {"allocatable": {"memory": "24Gi"}},
            }
            self.objects[pod_path("unit", "engine-" + str(i))] = {
                "kind": "Pod",
                "metadata": dict(
                    meta("engine-" + str(i), "engine-uid" + str(i)),
                    labels={
                        "inf037b-session": "s",
                        "inf037b-slot": str(i),
                        "inf037b-role": "system",
                    },
                ),
                "spec": {
                    "nodeName": "node" + str(i),
                    "containers": [
                        {
                            "name": "vllm",
                            "command": ["/engine"],
                            "args": [],
                            "resources": {
                                "requests": {"memory": "1Gi"},
                                "limits": {"nvidia.com/gpu": "1"},
                            },
                        }
                    ],
                },
                "status": {"phase": "Running", "containerStatuses": []},
            }
        self.owner = self.owner_case("setup")
        self.row5_owner = self.owner_case("setup")
        self.cold_owner = self.owner_case("setup")
        self.cached_owner = self.owner_case("setup")
        self.campaign = self.owner_case(1)
        self.sealed_checkpoint = self.checkpoint()
        self.context = {
            "operation_key": "driver:attempt:1",
            "operation_label": "attempt:1",
            "measurement_deadline_ms": 1000000,
            "input": {"attempt": 1},
        }
        self.cold = {"uid": "engine-uid0", "slot": 0, "node_uid": "node-uid0"}
        self.inputs = {
            "setup": {"pins": self.pins, "steps": {name: {"actions": []} for name in SETUP_ORDER}},
            "device": {},
            "startup": {
                "owner": self.owner,
                "lifecycle": LifecycleReceiptProducer(),
                "metrics": {
                    "0": {
                        "http": {"base": "http://127.0.0.1:1", "local_test": True},
                        "process_generation": "process",
                    }
                },
                "stop_event": threading.Event(),
            },
            "setup_runtime": {
                "owner": self.owner,
                "probe_owner": self.owner,
                "row5_owner": self.row5_owner,
                "row5": {"owner": self.row5_owner},
                "probe_runtime": lambda stop: {"original_stop": stop},
                "collect_inputs": lambda stop: {
                    "raw": b"test",
                    "fitness_raw": b"test",
                    "artifacts": {},
                },
            },
            "campaign_runtime": {
                "attempt:1": {
                    "owner": self.campaign,
                    "root": str(self.campaign.root),
                    "spec": {"attempt_index": 1, "target_slot": 0, "pre_end_ms": 1000},
                    "lifecycle": LifecycleReceiptProducer(),
                    "periodic": [],
                    "watches": {},
                    "clients": {},
                    "request_arguments": lambda offer: {},
                }
            },
            "campaign_actions": {"attempt:1": {"target_slot": 0, "effects": []}},
        }
        startup = self.inputs["startup"]
        self.inputs["startup"] = {
            "cold": {**startup, "owner": self.cold_owner},
            "node_cached": {**startup, "owner": self.cached_owner},
        }
        for i in (0, 1):
            producer = pod_path("unit", "device-agent-" + str(i))
            report = "/api/v1/namespaces/unit/configmaps/device-" + str(i)
            self.objects[producer] = {
                "kind": "Pod",
                "metadata": meta("device-agent-" + str(i), "agent-uid" + str(i)),
                "spec": {
                    "nodeName": "node" + str(i),
                    "serviceAccountName": "device-reader",
                    "containers": [{"image": "collector@sha256:" + "b" * 64}],
                },
            }
            receipt = {
                "schema": "inf037b-device-release-v1",
                "node_uid": "node-uid" + str(i),
                "producer_uid": "agent-uid" + str(i),
                "pins": self.pins,
                "device_ids": ["gpu" + str(i)],
                "complete": True,
                "allocations": [],
                "processes": [],
                "observation_ms": [900, 901],
            }
            self.objects[report] = {
                "metadata": meta("device-" + str(i), "report-uid" + str(i)),
                "data": {"receipt.json": encode(receipt).decode()},
            }
            self.inputs["device"][str(i)] = {
                "producer_pod_path": producer,
                "producer_uid": "agent-uid" + str(i),
                "service_account": "device-reader",
                "image": "collector@sha256:" + "b" * 64,
                "report_path": report,
                "device_ids": ["gpu" + str(i)],
            }
        self.config["objects"] = {
            "report" + str(i): {
                "path": self.inputs["device"][str(i)]["report_path"],
                "uid": "report-uid" + str(i),
            }
            for i in (0, 1)
        }
        case = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def reply(self, value, status=200, drop=False):
                if drop:
                    self.close_connection = True
                    return
                data = encode(value)
                self.send_response(status)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                case.gets.append(self.path)
                if case.drop:
                    case.drop = False
                    self.close_connection = True
                    return
                u = urlsplit(self.path)
                query = parse_qs(u.query)
                if query.get("watch") == ["true"]:
                    self.send_response(200)
                    self.end_headers()
                    pod = case.objects[pod_path("unit", "engine-0")]
                    self.wfile.write(encode({"type": "ADDED", "object": pod}))
                    self.wfile.flush()
                    self.close_connection = True
                    return
                if u.path == "/api/v1/pods":
                    node = query["fieldSelector"][0].split("=", 1)[1]
                    pods = [
                        v
                        for v in case.objects.values()
                        if v.get("kind") == "Pod" and v["spec"].get("nodeName") == node
                    ]
                    return self.reply(
                        {
                            "metadata": {
                                "resourceVersion": "30",
                                "continue": "",
                                "remainingItemCount": int(case.census_partial),
                            },
                            "items": pods,
                        }
                    )
                if u.path == "/api/v1/namespaces/unit/pods":
                    return self.reply(
                        {
                            "metadata": {"resourceVersion": "30", "continue": ""},
                            "items": [
                                v
                                for v in case.objects.values()
                                if v.get("kind") == "Pod"
                                and v["metadata"]["name"].startswith("engine-")
                            ],
                        }
                    )
                if "endpointslices" in u.path:
                    return self.reply(
                        {"metadata": {"resourceVersion": "30", "continue": ""}, "items": []}
                    )
                if u.path not in case.objects:
                    return self.reply({"reason": "NotFound"}, 404)
                return self.reply(case.objects[u.path])

            def mutate(self, method):
                body = strict_json(self.rfile.read(int(self.headers["Content-Length"])))
                path = self.path
                if method == "POST":
                    path += "/" + body["metadata"]["name"]
                case.writes.append((method, path, copy.deepcopy(body)))
                before = case.objects.get(path)
                if case.conflict:
                    return self.reply({"reason": "Conflict"}, 409)
                if method in ("PUT", "DELETE"):
                    if before is None:
                        return self.reply({"reason": "NotFound"}, 404)
                    pre = body["metadata"] if method == "PUT" else body["preconditions"]
                    if "uid" not in pre or any(
                        pre[k] != before["metadata"][k]
                        for k in ("uid", "resourceVersion")
                        if k in pre
                    ):
                        return self.reply({"reason": "Conflict"}, 409)
                if method == "DELETE":
                    if case.delete_pending:
                        before["metadata"]["deletionTimestamp"] = "pending"
                    elif not case.ignore_delete:
                        del case.objects[path]
                    value = {"status": "Success"}
                else:
                    value = copy.deepcopy(body)
                    if method == "POST":
                        case.uid_serial += 1
                        value["metadata"].update(
                            uid="created-uid" + str(case.uid_serial), resourceVersion="1"
                        )
                    else:
                        value["metadata"]["resourceVersion"] = str(
                            int(before["metadata"]["resourceVersion"]) + 1
                        )
                    case.objects[path] = value
                if case.after_write is not None:
                    case.after_write(method, path, value)
                return self.reply(value, drop=case.drop_write)

            def do_PUT(self):
                self.mutate("PUT")

            def do_POST(self):
                self.mutate("POST")

            def do_DELETE(self):
                self.mutate("DELETE")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=self.server.serve_forever)
        thread.start()
        self.addCleanup(thread.join, 2)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.api = PlacementAPI(
            f"http://127.0.0.1:{self.server.server_port}",
            token=lambda: "test",
            clock=lambda: self.now,
            retain=lambda *a: self.wire.append(a),
            local_test=True,
        )
        self.journal = FileJournal(self.root / "cluster", {}, initialize=True)
        self.runtime = self.open()
        self.factory = SimpleNamespace(
            binding=self.binding,
            config={"pins": self.pins, "cluster_runtime": self.runtime},
            clock=lambda: self.now,
            implementations={},
            capture_spec=lambda role: {
                "binding": (
                    self.row5_owner if role == "row5_controls_and_restoration" else self.owner
                ).binding,
                "sources": (
                    self.row5_owner if role == "row5_controls_and_restoration" else self.owner
                ).sources,
            },
            port=SimpleNamespace(deadline=Mock()),
        )

    def test_r369_snapshot_applies_observed_node_role_census_bound(self):
        from inference_platform.inf037b_eks_placement import census_bound

        original = copy.deepcopy(self.objects)
        for role in ("cpu", "gpu"):
            with self.subTest(role=role):
                self.objects = copy.deepcopy(original)
                self.objects["/api/v1/nodes/node0"]["metadata"]["labels"] = {"m5-role": role}
                n = census_bound(role)["N"]
                existing = sum(
                    value.get("kind") == "Pod" and value["spec"].get("nodeName") == "node0"
                    for value in self.objects.values()
                )

                def add_pod(index):
                    name = "census-" + str(index)
                    self.objects[pod_path("unit", name)] = {
                        "kind": "Pod",
                        "metadata": {"name": name, "uid": name, "resourceVersion": "1"},
                        "spec": {"nodeName": "node0", "containers": []},
                        "status": {"phase": "Succeeded"},
                    }

                for i in range(n - existing):
                    add_pod(i)
                snapshot = self.runtime.snapshot(10000)
                self.assertEqual(len(snapshot["censuses"]["0"]["value"]["pods"]), n)
                self.assertEqual(
                    snapshot["nodes"]["0"]["value"]["metadata"]["labels"]["m5-role"], role
                )
                add_pod(n)
                with self.assertRaisesRegex(ValueError, "placement_api:census_pod_limit"):
                    self.runtime.snapshot(10000)

    def owner_case(self, attempt):
        owner = component_owner(self)
        owner.attempt = attempt
        owner.stages = [1, 2, 3, 4, 5]
        owner.binding["pins"] = self.pins
        owner.binding["capture_inventory"] = {
            "schema": "inf037b-capture-inventory-v1",
            "sources": [{"name": n} for n in owner.sources],
            "wire_files": sorted(
                path for files in wire_files(owner.sources).values() for path in files.values()
            ),
        }
        owner.operation["body"]["binding"] = copy.deepcopy(owner.binding)
        owner.operation_store.write({"operations": {owner.label: owner.operation}})
        owner.join()
        owner.rows("kubernetes").row(
            "kubernetes",
            "kubernetes",
            owner.boot,
            "pod_created",
            {"pod_uid": "engine-uid0", "slot": 0, "node_pseudonym": "node0"},
        )
        return owner

    def checkpoint(self):
        return [
            {"stream": list(k), "next": v} for k, v in self.campaign.normalized_sequence.items()
        ]

    def wait(self, seconds):
        self.now += max(1, round(seconds * 1000))

    def open(self):
        return ClusterRuntime(
            api=self.api,
            journal=self.journal,
            binding=self.binding,
            pins=self.pins,
            config=self.config,
            clock=lambda: self.now,
            inputs=self.inputs,
            wait=self.wait,
        )

    def call(self, port):
        self.factory.config["cluster_runtime"] = self.runtime
        fn = EKSCommandFactory.dependency(self.factory, port)
        if port == "4d_cluster_authority":
            return fn(1000000, self.context)
        if port == "4d_startup_observation":
            self.objects[pod_path("unit", "engine-0")]["status"]["containerStatuses"] = [
                {
                    "name": "vllm",
                    "state": {"running": {}},
                    "restartCount": 0,
                    "containerID": "containerd://unit",
                    "imageID": "image@sha256:" + "a" * 64,
                }
            ]
            return fn("cold", self.cold, 1000000)
        if port == "campaign_capture_runtime":
            return fn(
                "attempt",
                1000000,
                self.context,
                reset=None,
                sequence_checkpoint=self.sealed_checkpoint,
            )
        if port == "4d_campaign_actions":
            self.call("campaign_capture_runtime")
            return fn("attempt", self.campaign, 1000000, self.context, Mock(), reset=None)
        return fn(1000000)

    def subject(self, port):
        if port == "4d_cluster_authority":
            return self.context
        if port == "4d_startup_observation":
            return {"name": "cold", "receipt": self.cold}
        if port == "campaign_capture_runtime":
            return {
                "operation": "attempt",
                "context": self.context,
                "reset": None,
                "checkpoint": self.sealed_checkpoint,
            }
        if port == "4d_campaign_actions":
            return {"operation": "attempt", "context": self.context, "reset": None}
        return None

    def bad(self, port):
        if port == "4d_cluster_authority":
            self.objects[self.config["cluster_path"]]["metadata"]["uid"] = "other"
        elif port == "4d_setup_lifecycle":
            self.inputs["setup"]["pins"] = {}
        elif port == "4d_device_release_observer":
            path = self.inputs["device"]["0"]["report_path"]
            report = strict_json(self.objects[path]["data"]["receipt.json"])
            report["node_uid"] = "other"
            self.objects[path]["data"]["receipt.json"] = encode(report).decode()
        elif port == "4d_startup_observation":
            self.cold["node_uid"] = "other"
        elif port == "4d_campaign_actions":
            self.inputs["campaign_actions"]["attempt:1"]["target_slot"] = 1
        elif port == "part2_setup_runtime":
            self.inputs["setup_runtime"]["row5"]["owner"] = self.campaign
        elif port == "campaign_capture_runtime":
            self.inputs["campaign_runtime"]["attempt:1"]["root"] = "different"

    def test_conditional_write_lost_reply_reopens_without_another_put(self):
        path = self.inputs["device"]["0"]["report_path"]
        body = copy.deepcopy(self.objects[path])
        body["data"]["value"] = "new"
        self.drop_write = True
        first = self.runtime.write("write-key", "PUT", path, body, 1000000)
        second = self.open().write("write-key", "PUT", path, body, 1000000)
        self.assertEqual(first, second)
        self.assertEqual(len(self.writes), 1)

    def test_conflict_keeps_intent_and_never_repeats_on_restart(self):
        path = self.inputs["device"]["0"]["report_path"]
        body = copy.deepcopy(self.objects[path])
        self.conflict = True
        with self.assertRaisesRegex(ValueError, "effect_operation_join"):
            self.runtime.write("conflict", "PUT", path, body, 1000000)
        with self.assertRaisesRegex(ValueError, "effect_operation_join"):
            self.open().write("conflict", "PUT", path, body, 1000000)
        self.assertEqual(len(self.writes), 1)

    def test_create_and_delete_use_real_collection_path_and_preconditions(self):
        path = "/api/v1/namespaces/unit/configmaps/new"
        body = {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "new"},
            "data": {"x": "y"},
        }
        result = self.runtime.write("create", "POST", path, body, 1000000)
        created = result["observed"]
        request = {
            "apiVersion": "v1",
            "kind": "DeleteOptions",
            "preconditions": {k: created["metadata"][k] for k in ("uid", "resourceVersion")},
        }
        self.drop_write = True
        self.assertIsNone(
            self.runtime.write("delete", "DELETE", path, request, 1000000)["observed"]
        )
        self.assertIsNone(self.open().write("delete", "DELETE", path, request, 1000000)["observed"])
        self.assertEqual(len(self.writes), 2)

    def test_shape_only_and_foreign_receipts_cannot_satisfy_a_consumer(self):
        value = self.call("4d_cluster_authority")
        changed = copy.deepcopy(value)
        changed["binding"]["session_id"] = "foreign"
        with self.assertRaisesRegex(ValueError, "receipt_binding"):
            join_cluster(changed, self.factory, "4d_cluster_authority", self.context)
        with self.assertRaises(KeyError):
            join_cluster(
                {"binding": self.binding}, self.factory, "4d_cluster_authority", self.context
            )

    def test_device_free_requires_both_allocation_and_process_inventories(self):
        value = self.call("4d_device_release_observer")
        self.assertEqual(self.runtime.free_device(value, 0, "engine-uid0")["device_ids"], ["gpu0"])
        path = self.inputs["device"]["0"]["report_path"]
        data = strict_json(self.objects[path]["data"]["receipt.json"])
        data["allocations"] = [{"device_id": "gpu0", "pod_uid": "old"}]
        self.objects[path]["data"]["receipt.json"] = encode(data).decode()
        value = self.call("4d_device_release_observer")
        with self.assertRaisesRegex(ValueError, "device_still_allocated"):
            self.runtime.free_device(value, 0, "new")

    def test_setup_effect_uses_existing_port_intent_and_local_cluster_authority(self):
        path = self.inputs["device"]["0"]["report_path"]
        body = copy.deepcopy(self.objects[path])
        body["data"]["value"] = "begin"
        for field in ("uid", "resourceVersion"):
            body["metadata"].pop(field)
        template = {
            "method": "PUT",
            "target": {"role": "object", "name": "report0"},
            "expected_uid": {"from": "object", "name": "report0"},
            "body": body,
        }
        self.inputs["setup"]["steps"]["begin"]["actions"] = [template]
        store = MemoryStore()
        store.state = {"sequence": 0, "operations": {}, "values": {}}
        self.factory.port = LifecycleAuthorityPort(
            store, Mock(), self.binding, self.pins, lambda: self.now, "driver"
        )
        request = {
            "binding": self.binding,
            "pins": self.pins,
            "stop_ms": 1000000,
            "authority": self.call("4d_setup_lifecycle"),
            "device_observer": self.call("4d_device_release_observer"),
        }
        self.drop_write = True
        ports = ClusterPorts(self.factory)
        first = ports.setup_effect("begin", "driver:preparation:gpu:begin", request, 1000000)
        self.assertEqual(
            ports.setup_effect("begin", "driver:preparation:gpu:begin", request, 1000000), first
        )
        self.assertEqual(len(self.writes), 1)

    def test_one_api_client_streams_watch_bytes_and_honors_early_eof(self):
        from inference_platform.inf037b_eks_cluster_runtime import KubernetesCaptureHTTP

        bridge = KubernetesCaptureHTTP(self.api, 1000000)
        records = list(bridge.lines("/api/v1/namespaces/unit/pods?watch=true&resourceVersion=30"))
        self.assertEqual(strict_json(records[0])["type"], "ADDED")
        self.assertTrue(self.wire)

    def test_missing_final_inputs_refuse_by_port_before_api_or_writes(self):
        for port in PORTS:
            self.factory.config.pop("cluster_runtime", None)
            with self.assertRaisesRegex(ValueError, "unfinished:4e_"):
                ClusterPorts(self.factory).runtime(port)
        self.assertFalse(self.gets)
        self.assertFalse(self.writes)

    def test_campaign_uses_owner_wire_and_the_real_run_argument_shapes(self):
        value = self.call("campaign_capture_runtime")
        self.assertGreater(self.campaign.wire["kubernetes"]["offset"], 0)
        self.assertIsInstance(value["watches"], dict)
        for name, period, collect in value["periodic"]:
            self.assertIn(name, self.campaign.sources)
            self.assertEqual(period, 500)
            self.assertTrue(callable(collect))
        kube, version = value["watches"]["kubernetes"]
        self.assertEqual(version, "30")
        self.assertEqual(kube.http.stop_ns, 1000000 * 1000000)

    def test_campaign_action_reconciles_a_lost_write_and_keeps_the_original_owner(self):
        path = self.inputs["device"]["0"]["report_path"]
        body = copy.deepcopy(self.objects[path])
        body["data"]["value"] = "event"
        for field in ("uid", "resourceVersion"):
            body["metadata"].pop(field)
        template = {
            "method": "PUT",
            "target": {"role": "object", "name": "report0"},
            "expected_uid": {"from": "object", "name": "report0"},
            "body": body,
        }
        self.inputs["campaign_actions"]["attempt:1"]["effects"] = [template]
        actions = self.call("4d_campaign_actions")
        self.drop_write = True
        actions["kubernetes"]()
        self.assertEqual(len(self.writes), 1)
        # Reopening reads the old intent; it never issues a second effect.
        reopened = self.open()
        key = self.context["operation_key"] + ":cluster:0"
        reopened.action(key, template, 1000000)
        self.assertEqual(len(self.writes), 1)
        self.assertIs(self.runtime.active_capture["attempt:1"]["owner"], self.campaign)

    def test_changed_setup_plan_refuses_before_an_effect(self):
        self.factory.port = LifecycleAuthorityPort(
            MemoryStore(), Mock(), self.binding, self.pins, lambda: self.now, "driver"
        )
        request = {
            "authority": self.call("4d_setup_lifecycle"),
            "device_observer": self.call("4d_device_release_observer"),
        }
        self.inputs["setup"]["steps"]["begin"]["actions"].append({"method": "PUT"})
        with self.assertRaisesRegex(ValueError, "setup_plan_changed"):
            ClusterPorts(self.factory).setup_effect("begin", "key", request, 1000000)
        self.assertFalse(self.writes)

    def test_changed_uid_precondition_refuses_before_put(self):
        path = self.inputs["device"]["0"]["report_path"]
        body = copy.deepcopy(self.objects[path])
        body["metadata"]["uid"] = "foreign"
        with self.assertRaisesRegex(ValueError, "write_uid"):
            self.runtime.write("wrong-uid", "PUT", path, body, 1000000)
        self.assertFalse(self.writes)

    def test_early_watch_eof_poison_is_not_creation_continuity(self):
        value = self.call("campaign_capture_runtime")
        kube, _ = value["watches"]["kubernetes"]
        self.campaign.watch("kubernetes", kube, "30")
        self.assertTrue(kube.lifecycle.lost)
        self.assertTrue(self.campaign.failed)

    def test_consumer_rejects_a_changed_runtime_even_with_a_valid_retained_proof(self):
        value = self.call("part2_setup_runtime")
        value["row5"] = {"owner": self.campaign}
        with self.assertRaisesRegex(ValueError, "consumer_row5_owner"):
            join_cluster(value, self.factory, "part2_setup_runtime")

    def test_setup_retains_the_two_distinct_owner_roles_and_rejects_collapse(self):
        value = self.call("part2_setup_runtime")
        self.assertIs(value["probe_owner"], self.owner)
        self.assertIs(value["row5"]["owner"], self.row5_owner)
        self.assertNotEqual(self.owner.root, self.row5_owner.root)
        self.inputs["setup_runtime"]["row5_owner"] = self.owner
        self.inputs["setup_runtime"]["row5"]["owner"] = self.owner
        with self.assertRaisesRegex(ValueError, "setup_owner_split"):
            self.call("part2_setup_runtime")

    def test_startup_cold_and_cached_cannot_share_a_capture_owner(self):
        self.inputs["startup"]["node_cached"]["owner"] = self.cold_owner
        with self.assertRaisesRegex(ValueError, "startup_case_owner_split"):
            self.call("4d_startup_observation")

    def test_setup_consumer_joins_each_actual_factory_scope(self):
        value = self.call("part2_setup_runtime")
        self.factory.capture_spec = lambda role: {
            "binding": {**self.owner.binding, "session_id": "foreign"},
            "sources": self.campaign.sources,
        }
        with self.assertRaisesRegex(ValueError, "consumer_scope_binding"):
            join_cluster(value, self.factory, "part2_setup_runtime")

    def test_startup_cannot_reuse_the_probe_or_row5_scope(self):
        self.inputs["startup"]["cold"]["owner"] = self.row5_owner
        with self.assertRaisesRegex(ValueError, "startup_scope_owner_split"):
            self.call("4d_startup_observation")

    def test_setup_owners_keep_their_own_phase_metadata(self):
        # The five-stage requirement belongs to campaign attempts, not the two
        # separate setup scopes. The actual factory binding remains required.
        self.owner.stages = [1]
        self.row5_owner.stages = [1]
        value = self.call("part2_setup_runtime")
        join_cluster(value, self.factory, "part2_setup_runtime")
        self.assertEqual(value["probe_owner"].stages, [1])

    def test_campaign_consumer_joins_entry_checkpoint_before_snapshot_rows(self):
        from inference_platform.inf037b_eks_campaign import CampaignCaptureScope
        from inference_platform.inf037b_ports import Port

        self.inputs["campaign_runtime"]["attempt_setup:1"] = self.inputs["campaign_runtime"][
            "attempt:1"
        ]
        self.inputs["campaign_actions"]["attempt_setup:1"] = self.inputs["campaign_actions"][
            "attempt:1"
        ]
        context = {
            **self.context,
            "operation_key": "driver:attempt_setup:1",
            "operation_label": "attempt_setup:1",
        }
        store = MemoryStore()
        store.state = {"sequence": 0, "operations": {}, "values": {}}
        self.factory.port = SimpleNamespace(
            store=store, validate_context=Mock(), invoke=Mock(return_value={"phase": "setup"})
        )
        self.factory.port.intent = lambda *args: Port.intent(self.factory.port, *args)
        self.factory.resource_windows = lambda *a, **kw: SimpleNamespace(adapters={})
        self.factory.capture_spec = lambda role: {
            "binding": self.campaign.binding,
            "sources": self.campaign.sources,
        }
        ports = ClusterPorts(self.factory)
        functions = {
            "4c_attempt_start": lambda *args: None,
            "4c_campaign_capture": lambda *args: {
                "binding": self.binding,
                "sequence_checkpoint": self.sealed_checkpoint,
            },
            "4d_cluster_authority": ports.authority,
            "campaign_capture_runtime": ports.campaign_runtime,
            "4d_campaign_actions": ports.actions,
            "4c_campaign_materialize": lambda *args: {"joined": True},
        }
        self.factory.dependency = functions.__getitem__
        self.inputs["campaign_runtime"]["attempt_setup:1"].update(
            capture_start_ns=0, collector_bundle={}
        )
        with (
            patch.object(
                self.campaign, "run", return_value={"close_start_ns": 1000000 * 1000000}
            ) as run,
            patch("inference_platform.inf037b_eks_campaign.compose") as composed,
        ):
            composed.return_value.periodic = []
            result = CampaignCaptureScope(self.factory)("attempt_setup", 1000000, context)
        self.assertEqual(result, {"phase": "setup"})
        run.assert_called_once()
        self.assertNotEqual(
            self.campaign.normalized_sequence,
            {tuple(row["stream"]): row["next"] for row in self.sealed_checkpoint},
        )


def port_case(port, mode):
    def test(self):
        if mode == "refusal":
            self.bad(port)
            with self.assertRaises(ValueError):
                self.call(port)
            self.assertFalse(self.writes)
            return
        if mode == "lost_reply":
            self.drop = True
            with self.assertRaises((http.client.RemoteDisconnected, ValueError)):
                self.call(port)
            if port in ("campaign_capture_runtime", "4d_campaign_actions"):
                self.assertTrue(self.campaign.failed)
                self.assertFalse(self.writes)
                self.assertTrue(self.open().state())
                return
            self.runtime = self.open()
        value = self.call(port)
        join_cluster(value, self.factory, port, self.subject(port))
        if mode == "restart":
            self.runtime = self.open()
            self.factory.config["cluster_runtime"] = self.runtime
            join_cluster(value, self.factory, port, self.subject(port))
        self.assertTrue(self.wire)

    return test


for _port in PORTS:
    for _mode in ("success", "refusal", "lost_reply", "restart"):
        setattr(ClusterTests, "test_" + _port + "_" + _mode, port_case(_port, _mode))


@unittest.skipUnless(
    os.environ.get("INF037B_CLUSTER_HOST_CONFIG"),
    "real kind/kube-apiserver cases run on AWS CPU host",
)
class HostClusterTests(unittest.TestCase):
    def api(self):
        config = strict_json(Path(os.environ["INF037B_CLUSTER_HOST_CONFIG"]).read_bytes())

        def now():
            return time.monotonic_ns() // 1000000

        api = PlacementAPI(
            config["api"]["base"],
            token=lambda: Path(config["api"]["token_file"]).read_text().strip(),
            ca=config["api"]["ca"],
            clock=now,
            retain=lambda *a: None,
        )
        return api, config, now() + 60000

    def test_real_uid_rv_write_conflict(self):
        api, config, stop = self.api()
        path = config["conditional_configmap_path"]
        before = api.request("GET", path, stop)
        changed = copy.deepcopy(before)
        changed["data"]["probe"] = "new"
        api.request("PUT", path, stop, changed)
        with self.assertRaisesRegex(ValueError, "transport_response"):
            api.request("PUT", path, stop, before)

    def test_real_coherent_census_and_object_defaults(self):
        api, config, stop = self.api()
        for node in config["nodes"].values():
            raw = api.request("GET", "/api/v1/nodes/" + node["name"], stop)
            self.assertEqual(raw["metadata"]["uid"], node["uid"])
            self.assertTrue(api.census(node, stop)["complete"])

    def conditional_case(self):
        import uuid

        api, host, stop = self.api()
        ns = host["conditional_configmap_path"].split("/")[4]
        name = "r364-" + uuid.uuid4().hex
        path = "/api/v1/namespaces/" + ns + "/configmaps/" + name
        body = {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": name, "namespace": ns},
            "data": {"pinned": "original"},
        }
        created = api.request("POST", path.rsplit("/", 1)[0], stop, body)
        nodes = sorted(host["nodes"].values(), key=lambda n: n["name"])
        self.assertEqual(len(nodes), 2)
        config = {
            "namespace": ns,
            "nodes": {str(i): n for i, n in enumerate(nodes)},
            "slots": {str(i): {"name": "unused-" + str(i)} for i in (0, 1)},
            "objects": {
                "conditional": {
                    "path": path,
                    "uid": created["metadata"]["uid"],
                    "sha256": sha(encode(body)),
                }
            },
        }
        root = Path(self.enterContext(TemporaryDirectory(prefix="r364-real-api-")))
        journal = FileJournal(root / "journal", {}, initialize=True)
        clock = api.clock
        binding = {"session_id": name, "C_ms": clock(), "t0_ms": clock(), "D_session_ms": stop}
        args = dict(
            api=api,
            journal=journal,
            binding=binding,
            pins={"configuration": sha(encode(body))},
            config=config,
            clock=clock,
        )
        runtime = ClusterRuntime(**args)

        def cleanup():
            current = runtime.read(path, stop, absent=True)["value"]
            if current is not None:
                api.request(
                    "DELETE",
                    path,
                    stop,
                    {
                        "preconditions": {
                            k: current["metadata"][k] for k in ("uid", "resourceVersion")
                        }
                    },
                )

        self.addCleanup(cleanup)
        return runtime, args, path, body, stop

    def test_real_metadata_page_and_watch_contracts_keep_api_bytes(self):
        import threading
        from urllib.parse import quote

        from inference_platform.inf037b_capture import DeadlineHTTP
        from inference_platform.inf037b_producer_contracts import validate_kube_identities

        runtime, _, path, _, stop = self.conditional_case()
        api = runtime.api
        original = api.request("GET", path, stop)
        changed = copy.deepcopy(original)
        changed["metadata"]["labels"] = {"r367-contract": "x" * 63}
        changed["metadata"]["annotations"] = {"r367-contract": "x" * (256 * 1024 - 13)}
        written = api.request("PUT", path, stop, changed)
        validate_kube_identities(written, lambda reason: self.fail(reason))
        self.assertEqual(len(written["metadata"]["uid"]), 36)
        collection = path.rsplit("/", 1)[0]
        page = api.request("GET", collection + "?limit=1", stop)
        self.assertEqual(len(page["items"]), 1)
        continuation = page["metadata"].get("continue")
        if continuation:
            later = api.request(
                "GET", collection + "?limit=1&continue=" + quote(continuation), stop
            )
            self.assertNotEqual(
                page["items"][0]["metadata"]["uid"], later["items"][0]["metadata"]["uid"]
            )
        retained = []
        http = DeadlineHTTP(
            api.base,
            token=api.token,
            ca=api.ca,
            stop_ns=stop * 1000000,
            local_test=api.local_test,
            retain=lambda a, b, data, metadata=None: retained.append(data),
        )
        errors = []

        def update():
            time.sleep(0.2)
            try:
                body = copy.deepcopy(written)
                body["data"]["probe"] = "watch"
                api.request("PUT", path, stop, body)
            except Exception as exc:
                errors.append(exc)

        thread = threading.Thread(target=update)
        thread.start()
        try:
            events = list(
                http.lines(
                    collection
                    + "?watch=true&timeoutSeconds=1&resourceVersion="
                    + written["metadata"]["resourceVersion"]
                    + "&fieldSelector=metadata.name="
                    + written["metadata"]["name"]
                )
            )
        finally:
            thread.join(5)
        self.assertFalse(errors)
        decoded = [strict_json(line) for line in events]
        self.assertTrue(any(event["object"]["data"].get("probe") == "watch" for event in decoded))
        self.assertTrue(b'"watch"' in b"".join(retained))
        # Actual API validation, distinct from the local reader's +1 tests.
        invalid = copy.deepcopy(api.request("GET", path, stop))
        invalid["metadata"]["labels"]["r367-contract"] += "x"
        with self.assertRaisesRegex(ValueError, "transport_response"):
            api.request("PUT", path, stop, invalid)

    def test_real_delete_uid_rv_lost_reply_reopens_without_second_effect(self):
        runtime, args, path, _, stop = self.conditional_case()
        before = runtime.read(path, stop)["value"]
        for pre in (
            {"uid": "wrong-uid", "resourceVersion": before["metadata"]["resourceVersion"]},
            {"uid": before["metadata"]["uid"], "resourceVersion": "0"},
        ):
            with self.assertRaisesRegex(ValueError, "transport_response"):
                runtime.api.request("DELETE", path, stop, {"preconditions": pre})
        request = {"preconditions": {k: before["metadata"][k] for k in ("uid", "resourceVersion")}}
        real = runtime.api.request
        effects = []

        def lost(method, target, deadline, body=None):
            result = real(method, target, deadline, body)
            if method == "DELETE":
                effects.append(body)
                raise OSError("labelled lost reply after real API delete")
            return result

        with patch.object(runtime.api, "request", side_effect=lost):
            first = runtime.write("delete", "DELETE", path, request, stop)
            self.assertEqual(
                ClusterRuntime(**args).write("delete", "DELETE", path, request, stop), first
            )
        self.assertEqual(len(effects), 1)
        self.assertIsNone(runtime.read(path, stop, absent=True)["value"])

    def test_real_exact_configuration_rollback_and_pin_mismatch(self):
        from inference_platform.inf037b_eks_actions import restore_configuration

        runtime, _, path, body, stop = self.conditional_case()
        before = runtime.read(path, stop)["value"]
        before["data"] = {"pinned": "temporary smoke change"}
        runtime.api.request("PUT", path, stop, before)
        records = [{"name": "conditional", "object": body, "sha256": sha(encode(body))}]
        restored = restore_configuration(runtime, "rollback", records, stop)
        self.assertEqual(restored[0]["observed"]["data"], body["data"])
        changed = copy.deepcopy(records)
        changed[0]["object"]["data"]["pinned"] = "wrong"
        with self.assertRaisesRegex(ValueError, "actions:pinned_object"):
            restore_configuration(runtime, "wrong", changed, stop)
        self.assertEqual(runtime.read(path, stop)["value"]["data"], body["data"])

    def test_real_paginated_node_census_includes_unrelated_pods(self):
        from urllib.parse import urlencode

        api, host, stop = self.api()
        for node in host["nodes"].values():
            token, seen, rv, pages = "", set(), None, 0
            while True:
                params = {"fieldSelector": "spec.nodeName=" + node["name"], "limit": "1"}
                if token:
                    params["continue"] = token
                page = api.request("GET", "/api/v1/pods?" + urlencode(params), stop)
                pages += 1
                self.assertLess(pages, 1000)
                if rv is not None:
                    self.assertEqual(page["metadata"]["resourceVersion"], rv)
                rv = page["metadata"]["resourceVersion"]
                for pod in page["items"]:
                    self.assertNotIn(pod["metadata"]["uid"], seen)
                    seen.add(pod["metadata"]["uid"])
                    self.assertEqual(pod["spec"]["nodeName"], node["name"])
                token = page["metadata"].get("continue", "")
                if not token:
                    self.assertIn(page["metadata"].get("remainingItemCount"), (None, 0))
                    break
            self.assertTrue(seen)
            self.assertTrue(api.census(node, stop)["complete"])

    def test_real_terminal_pod_status_is_counted_in_complete_census(self):
        from inference_platform.eks_deployment import PYTHON_IMAGE
        from inference_platform.inf037b_eks_placement import effective_memory, project

        runtime, _, cm_path, _, stop = self.conditional_case()
        ns = runtime.config["namespace"]
        name = cm_path.rsplit("/", 1)[1] + "-terminal"
        path = pod_path(ns, name)
        # The short-export worker retains nearly 12 GiB for this tiny Pod;
        # the fit worker may be occupied by the preceding exporter case.
        node = runtime.config["nodes"]["1"]
        body = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": name, "namespace": ns, "labels": {"inf037b-role": "system"}},
            "spec": {
                "nodeName": node["name"],
                "restartPolicy": "Never",
                "containers": [
                    {
                        "name": "done",
                        "image": PYTHON_IMAGE,
                        "command": ["python", "-c", "pass"],
                        "resources": {"requests": {"memory": "1Mi"}},
                    }
                ],
            },
        }
        created = runtime.api.request("POST", path.rsplit("/", 1)[0], stop, body)

        def cleanup():
            current = runtime.read(path, stop, absent=True)["value"]
            if current is not None:
                runtime.api.request(
                    "DELETE",
                    path,
                    stop,
                    {
                        "preconditions": {
                            k: current["metadata"][k] for k in ("uid", "resourceVersion")
                        }
                    },
                )

        self.addCleanup(cleanup)
        # The real kubelet owns status and can advance the creation RV before
        # a test PUT. Observe this trivial Pod actually finish instead of racing
        # the kubelet with an injected terminal status at a stale RV.
        while True:
            observed = runtime.read(path, stop)["value"]
            self.assertEqual(observed["metadata"]["uid"], created["metadata"]["uid"])
            phase = observed.get("status", {}).get("phase")
            if phase in ("Succeeded", "Failed"):
                self.assertEqual(phase, "Succeeded")
                break
            self.assertLess(runtime.clock(), stop, "terminal Pod did not complete")
            time.sleep(0.1)
        census = runtime.api.census(node, stop)
        actual = next(
            p for p in census["pods"] if p["metadata"]["uid"] == created["metadata"]["uid"]
        )
        self.assertEqual(actual["status"]["phase"], "Succeeded")
        api_node = runtime.api.request("GET", "/api/v1/nodes/" + node["name"], stop)
        # Only the surrounding export Job/Pod frame is a fixture. The bound
        # terminal Pod, status subresource, node and whole census are real API.
        projected = project(
            {
                "job": {"metadata": {"uid": "fixture-job"}},
                "pod": {"metadata": {"uid": "fixture-export"}, "spec": {}},
                "node": api_node,
                "requests": census,
            },
            "pre_schedule",
        )
        counted = next(
            p for p in projected["requests"]["pods"] if p["uid"] == actual["metadata"]["uid"]
        )
        self.assertEqual(counted["phase"], "Succeeded")
        self.assertEqual(
            counted["memory_requests"], [str(effective_memory(actual["spec"], actual["status"]))]
        )
        self.assertGreater(int(counted["memory_requests"][0]), 0)


class DeviceWitnessTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.uuid = "GPU-00000000-0000-0000-0000-000000000001"
        self.cid = "1" * 64
        self.xml = self.root / "smi.xml"
        self.xml.write_bytes(
            (Path(__file__).parent / "fixtures/device/nvidia-smi.xml").read_bytes()
        )
        self.proc = self.root / "proc"
        (self.proc / "sys/kernel/random").mkdir(parents=True)
        (self.proc / "sys/kernel/random/boot_id").write_text("unit-boot")
        (self.proc / "1/ns").mkdir(parents=True)
        (self.proc / "1/ns/pid").write_text("explicit namespace fixture")
        (self.proc / "123").mkdir()
        self.stat = self.proc / "123/stat"
        self.stat.write_text("123 (fixture name) S " + "0 " * 18 + "77 0")
        (self.proc / "123/cgroup").write_text("0::/kubepods/cri-containerd-" + self.cid + ".scope")
        self.helper = self.root / "helper.json"
        self.inventory = {
            "schema": "inf037b-podresources-v1",
            "complete": True,
            "device_ids": [self.uuid],
            "allocations": [],
        }
        self.helper.write_bytes(encode(self.inventory))
        self.cri = self.root / "cri.json"
        labels = {
            "io.kubernetes.pod.uid": "target-uid",
            "io.kubernetes.pod.name": "engine",
            "io.kubernetes.pod.namespace": "unit",
        }
        self.status = {"id": self.cid, "metadata": {"name": "model"}, "labels": labels}
        self.cri.write_bytes(encode({"containers": [self.status], "status": self.status}))
        self.spec = {
            "node_uid": "node-uid0",
            "producer_uid": "agent-uid0",
            "pins": {"configuration": "a" * 64},
            "device_ids": [self.uuid],
            "boot_id": "unit-boot",
            "node_image_release": "fixture-image-release",
            "proc": str(self.proc),
            "self_pid_namespace": str(self.proc / "1/ns/pid"),
            "podresources_socket": "/fixture/kubelet.sock",
        }
        scripts = {
            "podresources": "assert sys.argv[1:]==['--socket','/fixture/kubelet.sock']; print(Path("
            + repr(str(self.helper))
            + ").read_text())",
            "nvidia_smi": "assert sys.argv[1:]==['-q','-x']; print(Path("
            + repr(str(self.xml))
            + ").read_text())",
            "crictl": "a=sys.argv[1:]; assert a[:2]==['--runtime-endpoint','unix:///run/containerd/containerd.sock']; d=json.loads(Path("
            + repr(str(self.cri))
            + ").read_text()); print(json.dumps({'containers':d['containers']} if a[2:]==['ps','-a','--output','json'] else {'status':d['status']} if a[2:]==['inspect','--output','json',"
            + repr(self.cid)
            + "] else {}))",
        }
        for key, body in scripts.items():
            path = self.root / (key + ".py")
            path.write_text(
                "import sys,json\nfrom pathlib import Path\n" + body + "\n", encoding="utf-8"
            )
            self.spec[key] = {"path": str(path), "sha256": sha(path.read_bytes())}
        evidence = self.root / "release.json"
        evidence.write_bytes(
            encode(
                {
                    "node_uid": "node-uid0",
                    "image_release": "fixture-image-release",
                    "driver_version": "560.94",
                    "nvidia_smi_sha256": self.spec["nvidia_smi"]["sha256"],
                }
            )
        )
        self.spec["driver"] = {
            "image_release": "fixture-image-release",
            "version": "560.94",
            "release_evidence": {"path": str(evidence), "sha256": sha(evidence.read_bytes())},
        }
        self.calls = []

    def execute(self, argv, deadline):
        self.calls.append(argv)
        # Labelled fake node CLIs run as real processes on both native Windows
        # and Linux. No actual driver/CRI or GPU release is claimed by fixtures.
        return command([sys._base_executable, *argv], deadline)

    def source(self):
        return DeviceSource(self.spec, run=self.execute)

    def processes(self):
        doc = ET.fromstring(self.xml.read_bytes())
        listing = doc.find("gpu/processes")
        entry = ET.SubElement(listing, "process_info")
        for key, value in [
            ("gpu_instance_id", "N/A"),
            ("compute_instance_id", "N/A"),
            ("pid", "123"),
            ("type", "C"),
            ("process_name", "fixture"),
        ]:
            ET.SubElement(entry, key).text = value
        self.xml.write_bytes(
            b'<!DOCTYPE nvidia_smi_log SYSTEM "nvsmi_device_v12.dtd">\n' + ET.tostring(doc)
        )

    def test_tls_silent_client_does_not_block_clock_and_is_closed(self):
        import socket
        import ssl

        from inference_platform.inf037b_device import device_server
        from inference_platform.package_a_workload import test_tls_command

        subprocess.run(test_tls_command(self.root), capture_output=True, check=True)
        token = self.root / "token"
        token.write_text("unit-token")
        spec = {
            **self.spec,
            "token_path": str(token),
            "tls_cert": str(self.root / "tls.crt"),
            "tls_key": str(self.root / "tls.key"),
        }
        server = device_server(spec, ("127.0.0.1", 0))
        errors = []
        server.handle_error = lambda *args: errors.append(args[1])
        accepted = threading.Event()
        get_request = server.get_request

        def accept():
            value = get_request()
            accepted.set()
            return value

        server.get_request = accept
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 3)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        with socket.create_connection(server.server_address, timeout=3) as silent:
            self.assertTrue(accepted.wait(1), "accept must not perform the TLS handshake")
            context = ssl.create_default_context(cafile=str(self.root / "tls.crt"))
            client = http.client.HTTPSConnection(
                "localhost", server.server_port, timeout=1, context=context
            )
            self.addCleanup(client.close)
            begin = time.monotonic()
            client.request("GET", "/clock", headers={"Authorization": "Bearer unit-token"})
            response = client.getresponse()
            self.assertEqual(response.status, 200)
            self.assertEqual(json.loads(response.read())["boot_id"], "unit-boot")
            self.assertLess(time.monotonic() - begin, 1.5)
            silent.settimeout(3)
            try:
                self.assertEqual(silent.recv(1), b"")
            except ConnectionResetError:
                pass
            self.assertTrue(errors, "the idle handshake timed out in its own thread")
        # Rotating the token file to empty must refuse even an old valid token.
        token.write_text(" \n")
        client.request("GET", "/clock", headers={"Authorization": "Bearer unit-token"})
        response = client.getresponse()
        self.assertEqual(response.status, 503)
        self.assertIn(b"device:token", response.read())

    def test_empty_token_refuses_startup_by_name(self):
        spec = self.root / "server.json"
        token = self.root / "token"
        token.write_text(" \n")
        spec.write_bytes(encode({**self.spec, "node_name": "unit", "token_path": str(token)}))
        result = subprocess.run(
            [sys.executable, "-m", "inference_platform.inf037b_device", "--spec", str(spec)],
            env={**os.environ, "NODE_NAME": "unit", "POD_UID": "agent"},
            capture_output=True,
            timeout=10,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"device:token", result.stderr)

    def publication(self):
        from inference_platform.inf037b_driver import published_driver

        raw = (Path(__file__).parent / "fixtures/device/eks-ami-release.json").read_bytes()
        return published_driver(
            raw, image_release="1.35.9-20261026", utc="2026-11-05T00:00:00+00:00"
        )

    def first_contact(self):
        self.spec["node_image_release"] = "1.35.9-20261026"
        self.xml.write_bytes(self.xml.read_bytes().replace(b"560.94", b"580.178.04"))
        return self.source().first_contact()

    def test_published_refresh_is_offline_and_keeps_exact_source_facts(self):
        from inference_platform.inf037b_driver import refresh_driver

        raw = (Path(__file__).parent / "fixtures/device/eks-ami-release.json").read_bytes()
        calls = []
        value, reply = refresh_driver("1.35.9-20261026", fetch=lambda url: calls.append(url) or raw)
        self.assertEqual(reply, raw)
        self.assertEqual(value["driver_version"], "580.178.04")
        self.assertEqual(value["package"], "nvidia-kmod (default)")
        self.assertEqual(value["response_sha256"], sha(raw))
        self.assertEqual(calls, [value["response_url"]])
        self.assertTrue(value["utc"].endswith("+00:00"))
        from inference_platform.inf037b_driver import published_driver

        with self.assertRaisesRegex(ValueError, "unresolved:node_driver_binding"):
            published_driver(
                raw, image_release="1.35.9-20261026", utc=value["utc"], package="containerd"
            )
        self.assertEqual(
            value["url"], "https://github.com/awslabs/amazon-eks-ami/releases/tag/v20261026"
        )

    def test_published_missing_driver_or_wrong_release_refuses_by_name(self):
        from inference_platform.inf037b_driver import published_driver

        raw = json.loads(
            (Path(__file__).parent / "fixtures/device/eks-ami-release.json").read_bytes()
        )
        for field, reason in (
            ("body", "unresolved:node_driver_binding"),
            ("tag_name", "driver_release_mismatch"),
        ):
            changed = copy.deepcopy(raw)
            changed[field] = "missing"
            with self.assertRaisesRegex(ValueError, reason):
                published_driver(
                    encode(changed),
                    image_release="1.35.9-20261026",
                    utc="2026-11-05T00:00:00+00:00",
                )

    def test_real_first_contact_evidence_accepts_and_changed_binary_refuses(self):
        from inference_platform.inf037b_driver import canonical, release_evidence

        first = self.first_contact()
        value = release_evidence(
            first,
            self.publication(),
            node_uid=self.spec["node_uid"],
            image_release=self.spec["node_image_release"],
        )
        self.assertEqual(first["nvidia_smi_sha256"], self.spec["nvidia_smi"]["sha256"])
        # A Windows operator binds the Linux node's path, not its local drive.
        linux = release_evidence(
            {**first, "nvidia_smi_path": "/tools/nvidia-smi"},
            self.publication(),
            node_uid=self.spec["node_uid"],
            image_release=self.spec["node_image_release"],
        )
        self.assertEqual(linux["nvidia_smi_path"], "/tools/nvidia-smi")
        self.assertEqual(first["raw_sha256"], sha(first["raw_xml"].encode()))
        evidence = self.root / "bound.json"
        evidence.write_bytes(canonical(value))
        self.spec["driver"] = {
            "image_release": self.spec["node_image_release"],
            "version": "580.178.04",
            "release_evidence": {"path": str(evidence), "sha256": sha(evidence.read_bytes())},
        }
        self.assertEqual(self.source().read()["driver"]["version"], "580.178.04")
        evidence.write_bytes(canonical({**value, "nvidia_smi_path": "/wrong/binary"}))
        self.spec["driver"]["release_evidence"]["sha256"] = sha(evidence.read_bytes())
        with self.assertRaisesRegex(ValueError, "driver_release_binding"):
            self.source().read()
        evidence.write_bytes(canonical(value))
        self.spec["driver"]["release_evidence"]["sha256"] = sha(evidence.read_bytes())
        binary = Path(self.spec["nvidia_smi"]["path"])
        binary.write_bytes(binary.read_bytes() + b"# changed after session pin\n")
        with self.assertRaisesRegex(ValueError, "nvidia_smi_pin"):
            self.source().read()

    def test_driver_binding_mismatches_refuse_by_name(self):
        from inference_platform.inf037b_driver import release_evidence

        first, published = self.first_contact(), self.publication()
        cases = [
            ("driver_version", "0.0", "driver_version_mismatch"),
            ("image_release", "1.35.8-20261023", "driver_release_mismatch"),
            ("node_uid", "foreign-node", "driver_node_uid_mismatch"),
        ]
        for field, value, reason in cases:
            changed = {**first, field: value}
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, reason):
                release_evidence(
                    changed,
                    published,
                    node_uid=self.spec["node_uid"],
                    image_release=self.spec["node_image_release"],
                )
        with self.assertRaisesRegex(ValueError, "unresolved:node_driver_binding"):
            release_evidence(
                first,
                None,
                node_uid=self.spec["node_uid"],
                image_release=self.spec["node_image_release"],
            )

    def test_release_evidence_cli_writes_once(self):
        from inference_platform.inf037b_driver import canonical

        first, refresh, output = (
            self.root / "first.json",
            self.root / "refresh.json",
            self.root / "evidence.json",
        )
        first.write_bytes(canonical(self.first_contact()))
        refresh.write_bytes(canonical({"eks_gpu_driver": self.publication()}))
        argv = [
            sys.executable,
            "scripts/build_inf037b_driver_evidence.py",
            "--refresh",
            str(refresh),
            "--first-contact",
            str(first),
            "--node-uid",
            self.spec["node_uid"],
            "--release-version",
            self.spec["node_image_release"],
            "--output",
            str(output),
        ]
        subprocess.run(argv, capture_output=True, check=True, timeout=10)
        original = output.read_bytes()
        result = subprocess.run(argv, capture_output=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output.read_bytes(), original)

    def test_command_error_and_overflow_keep_bounded_raw_bytes(self):
        from unittest.mock import patch

        from inference_platform import inf037b_device as device

        with self.assertRaises(device.DeviceReadError) as caught:
            command(
                [
                    sys._base_executable,
                    "-c",
                    "import sys; print('partial'); sys.stderr.write('unknown')",
                ],
                time.monotonic() + 5,
            )
        self.assertIn(b"partial", caught.exception.stdout)
        self.assertEqual(caught.exception.stderr, b"unknown")
        with patch.object(device, "CAP", 64):
            with self.assertRaises(device.DeviceReadError) as caught:
                command([sys._base_executable, "-c", "print('x'*100)"], time.monotonic() + 5)
        self.assertEqual(len(caught.exception.stdout), 64)
        self.assertIn("command_size", str(caught.exception))
        self.xml.write_bytes(b"unknown layout")
        with self.assertRaises(device.DeviceReadError) as caught:
            self.source().read()
        self.assertIn(b"unknown layout", bytes.fromhex(caught.exception.records[-1]["stdout_hex"]))

    def test_fake_cli_recorded_xml_and_both_complete_inventories(self):
        report = self.source().read()
        self.assertEqual(report["device_ids"], [self.uuid])
        self.assertEqual(report["processes"], [])
        self.assertEqual(report["allocations"], [])
        self.assertEqual(report["driver"]["path"], self.spec["nvidia_smi"]["path"])
        self.assertEqual(report["driver"]["version"], "560.94")
        self.assertEqual(len([c for c in self.calls if c[0] == self.spec["nvidia_smi"]["path"]]), 2)
        self.assertIn("raw", report)

    def test_pid_cgroup_cri_pod_join_and_allocated_idle_gpu_is_not_free(self):
        self.processes()
        self.inventory["allocations"] = [
            {"device_id": self.uuid, "namespace": "unit", "pod": "engine", "container": "model"}
        ]
        self.helper.write_bytes(encode(self.inventory))
        report = self.source().read()
        self.assertEqual(report["processes"][0]["pod_uid"], "target-uid")
        self.assertEqual(report["processes"][0]["start_ticks"], 77)
        self.assertEqual(report["allocations"][0]["pod_uid"], "target-uid")

    def test_missing_driver_binding_and_changed_pins_boot_namespace_refuse(self):
        original = json.loads(json.dumps(self.spec))
        for field in ("driver", "boot_id", "self_pid_namespace", "podresources"):
            with self.subTest(field=field):
                self.spec = json.loads(json.dumps(original))
                if field == "driver":
                    self.spec[field] = None
                elif field == "boot_id":
                    self.spec[field] = "wrong-boot"
                elif field == "self_pid_namespace":
                    other = self.root / "wrong-ns"
                    other.write_text("wrong")
                    self.spec[field] = str(other)
                else:
                    self.spec[field]["sha256"] = "0" * 64
                with self.assertRaises((ValueError, OSError)):
                    self.source().read()

    def test_partial_unmapped_and_replicated_allocations_refuse(self):
        self.inventory["complete"] = False
        self.helper.write_bytes(encode(self.inventory))
        with self.assertRaisesRegex(ValueError, "allocation_incomplete"):
            self.source().read()
        self.inventory["complete"] = True
        self.inventory["allocations"] = [
            {"device_id": self.uuid, "namespace": "missing", "pod": "engine", "container": "model"}
        ]
        self.helper.write_bytes(encode(self.inventory))
        with self.assertRaisesRegex(ValueError, "allocation_unmapped"):
            self.source().read()
        self.inventory["allocations"] = [
            {"device_id": self.uuid, "namespace": "unit", "pod": "engine", "container": "model"}
        ] * 2
        self.helper.write_bytes(encode(self.inventory))
        with self.assertRaisesRegex(ValueError, "replicated_or_time_sliced"):
            self.source().read()

    def test_unknown_xml_layout_mig_replicated_ids_and_unidentified_processes_refuse(self):
        original = self.xml.read_bytes()
        for raw in (
            original.replace(b"nvsmi_device_v12.dtd", b"unknown.dtd"),
            original.replace(b"N/A", b"Enabled"),
            original.replace(self.uuid.encode(), (self.uuid + "::0").encode()),
            original.replace(self.uuid.encode(), b"MIG-123"),
            original.replace(
                b"<processes />", b"<processes>Unidentified processes found</processes>"
            ),
        ):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                smi_xml(raw, "560.94")

    def test_inventory_change_between_the_two_reads_refuses(self):
        for change, reason in [
            ("allocation", "allocation_changed"),
            ("process", "process_inventory_changed"),
        ]:
            counts = {}
            self.inventory["allocations"] = []
            self.helper.write_bytes(encode(self.inventory))
            self.xml.write_bytes(
                (Path(__file__).parent / "fixtures/device/nvidia-smi.xml").read_bytes()
            )

            def execute(argv, deadline, change=change, counts=counts):
                raw = self.execute(argv, deadline)
                counts[argv[0]] = counts.get(argv[0], 0) + 1
                if (
                    change == "allocation"
                    and argv[0] == self.spec["podresources"]["path"]
                    and counts[argv[0]] == 1
                ):
                    self.inventory["allocations"] = [
                        {
                            "device_id": self.uuid,
                            "namespace": "unit",
                            "pod": "engine",
                            "container": "model",
                        }
                    ]
                    self.helper.write_bytes(encode(self.inventory))
                if (
                    change == "process"
                    and argv[0] == self.spec["nvidia_smi"]["path"]
                    and counts[argv[0]] == 1
                ):
                    self.processes()
                return raw

            with self.subTest(change=change), self.assertRaisesRegex(ValueError, reason):
                DeviceSource(self.spec, run=execute).read()

    def test_pid_reuse_and_exit_during_inspect_refuse(self):
        self.processes()
        real = self.execute

        def changed(argv, deadline):
            output = real(argv, deadline)
            if "inspect" in argv:
                self.stat.write_text("123 (reused) S " + "0 " * 18 + "78 0")
            return output

        with self.assertRaisesRegex(ValueError, "pid_reused"):
            DeviceSource(self.spec, run=changed).read()
        self.stat.unlink()
        with self.assertRaisesRegex(ValueError, "process_unknown"):
            proc_identity(self.proc, 123, "unit-boot")

    def test_real_http_clock_join_retention_and_lost_publish_reply_reach_unchanged_consumer(self):
        from inference_platform.inf037b_device import DeviceReleaseProducer, handler

        case = ClusterTests(methodName="runTest")
        case.setUp()
        self.addCleanup(case.doCleanups)
        self.spec["pins"] = case.pins
        cached = self.source().read()  # Real labelled CLI subprocess path first.

        ticks = [1_000_000_000]

        def tick():
            ticks[0] += 1_000_000
            return ticks[0]

        class Peer:
            spec = self.spec
            clock = staticmethod(tick)

            def read(peer):
                # Explicit logical-clock protocol fixture over real HTTP: no
                # physical GPU claim or dependence on laptop scheduler timing.
                raw = copy.deepcopy(cached)
                raw["observation_ns"] = [tick(), tick()]
                return raw

        server = ThreadingHTTPServer(("127.0.0.1", 0), handler(Peer(), lambda: "unit-token"))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)

        class Owner:
            clock_rows = []
            wire = []

            def loss(owner, reason):
                owner.failed = reason

            def retainer(owner, source):
                return lambda a, b, data, metadata: owner.wire.append(data)

            def rows(owner, source):
                return owner

            def clock(owner):
                return tick()

            def row(owner, kind, source, boot, event, payload, **kw):
                owner.clock_rows.append(
                    {
                        "record_id": str(len(owner.clock_rows)),
                        "payload": {"event": event, **payload},
                    }
                )

        owner = Owner()
        path = case.inputs["device"]["0"]["report_path"]
        source = {
            **{
                k: cached[k]
                for k in (
                    "node_uid",
                    "producer_uid",
                    "pins",
                    "device_ids",
                    "source_sha256",
                    "boot_id",
                    "clock_id",
                )
            },
            "capture_source": "device:slot0",
            "report_path": path,
            "report_uid": case.objects[path]["metadata"]["uid"],
        }
        client = DeviceReleaseProducer(
            owner=owner,
            source=source,
            http={
                "base": f"http://127.0.0.1:{server.server_port}",
                "token": lambda: "unit-token",
                "local_test": True,
            },
            stop_ns=time.monotonic_ns() + 30_000_000_000,
        )
        case.drop_write = True
        report = client.publish(case.api, path, 1000000)
        self.assertEqual(len([x for x in case.writes if x[0] == "PUT"]), 1)
        self.assertEqual(json.loads(case.objects[path]["data"]["receipt.json"]), report)
        self.assertTrue(any(b"inf037b-device-raw-v1" in raw for raw in owner.wire))
        # Only slot0 uses the real collector; the other slot remains the declared
        # existing API fixture. The original checker still owns release fitness.
        case.drop_write = False
        case.runtime.inputs["device"]["0"]["collector"] = client
        case.runtime.inputs["device"]["0"]["device_ids"] = [self.uuid]
        case.runtime.clock = lambda: owner.clock() // 1_000_000
        witness = case.call("4d_device_release_observer")
        joined = case.runtime.free_device(witness, 0, "target-uid", since_ms=0)
        self.assertEqual(joined["device_ids"], [self.uuid])
        client.source = {**source, "producer_uid": "wrong-source"}
        before = len(owner.wire)
        with self.assertRaisesRegex(ValueError, "report_identity:producer_uid"):
            client.produce()
        self.assertGreater(len(owner.wire), before)

    @unittest.skipUnless(
        os.name == "posix" and os.environ.get("INF037B_EKS_HOST_TEST") == "1",
        "real /proc child identity is required on the CPU host",
    )
    def test_device_real_proc_child_identity_and_exit(self):
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(10)"])
        try:
            boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
            first = process_start(Path("/proc"), child.pid, boot)
            self.assertEqual(first, process_start(Path("/proc"), child.pid, boot))
            self.assertGreater(first["start_ticks"], 0)
        finally:
            child.terminate()
            child.wait(timeout=2)
        with self.assertRaisesRegex(ValueError, "process_unknown"):
            process_start(Path("/proc"), child.pid, boot)

    @unittest.skipUnless(
        os.name == "posix" and os.environ.get("INF037B_EKS_HOST_TEST") == "1",
        "real Unix gRPC PodResources case is required on the CPU host",
    )
    def test_device_real_unix_grpc_server(self):
        result = subprocess.run(
            ["go", "test", "-json", "./internal/podresources", "-run", "^TestUnix$", "-count=1"],
            capture_output=True,
            timeout=300,
            check=True,
        )
        rows = [json.loads(line) for line in result.stdout.splitlines() if line.startswith(b"{")]
        self.assertTrue(
            any(r.get("Action") == "pass" and r.get("Test") == "TestUnix" for r in rows)
        )
        self.assertFalse(any(r.get("Action") == "skip" for r in rows))


@unittest.skipUnless(
    os.environ.get("INF037B_DEVICE_LIVE_SPEC"),
    "real GPU/kubelet witness only in registered combined bring-up",
)
class DeviceLiveTests(unittest.TestCase):
    def test_real_gpu_kubelet_device_witness(self):
        spec = json.loads(Path(os.environ["INF037B_DEVICE_LIVE_SPEC"]).read_bytes())
        started = time.monotonic()
        try:
            self.assertTrue(DeviceSource(spec).read()["complete"])
        finally:
            print(
                json.dumps(
                    {"device_read_elapsed_s": time.monotonic() - started, "read_deadline_s": 5}
                ),
                flush=True,
            )


class TransportTests(unittest.TestCase):
    def setUp(self):
        from inference_platform import inf037b_native as native
        from inference_platform.inf037b_eks_transports import PodTransports

        self.case = ClusterTests(methodName="runTest")
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.owner = self.case.cold_owner
        self.owner.sources["kubernetes"].append(["clocks", "clock:node:node0", "node-boot"])
        self.uid = "engine-uid0"
        self.manifest = {
            "schema": "inf037b-native-overlay-v1",
            "version": "0.29.0",
            "base": native.BASE_FILES,
            "files": native.BASE_FILES,
            "helper_sha256": sha(Path(native.__file__).read_bytes()),
        }
        self.origin = {
            "pod_uid": self.uid,
            "slot": 0,
            "node": "node0",
            "node_boot_id": "node-boot",
            "boot_id": "native-generation",
            "helper_sha256": self.manifest["helper_sha256"],
            "manifest_sha256": sha(encode(self.manifest)),
            "model_sha256": self.case.pins["model"],
            "runtime_sha256": self.case.pins["runtime"],
            "supervisor_pid": 123,
            "supervisor_start": "77",
        }
        self.calls = []
        fixture = self

        class Peer(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                fixture.calls.append(self.path)
                if self.path.startswith("/native/"):
                    value = {
                        "schema": "inf037b-native-events-v1",
                        "origin": fixture.origin,
                        "events": [],
                        "more": False,
                        "next": -1,
                    }
                elif self.path == "/clock":
                    value = {"boot_id": "node-boot", "mono_ns": time.monotonic_ns()}
                else:
                    value = {
                        "schema": "m5-node-cache-v1",
                        "complete": True,
                        "node": "node0",
                        "boot_id": "node-boot",
                        "image": "image@sha256:" + fixture.case.pins["runtime"],
                        "image_cache_state": "cold",
                        "model_cache_state": "cold",
                        "start_ns": time.monotonic_ns(),
                        "end_ns": time.monotonic_ns(),
                    }
                body = encode(value)
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Peer)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 2)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        node = {
            "name": "node0",
            "boot_id": "node-boot",
            "image": "image@sha256:" + self.case.pins["runtime"],
        }
        options = {"base": f"http://127.0.0.1:{self.server.server_port}", "local_test": True}
        self.binding = PodTransports(
            owner=self.owner,
            pins=self.case.pins,
            manifest=self.manifest,
            nodes={"0": node, "1": {**node, "name": "node1"}},
            endpoints={
                str(i): {"node_http": options, "local_test_pod_http": options} for i in (0, 1)
            },
        )
        self.pod = copy.deepcopy(self.case.objects[pod_path("unit", "engine-0")])
        self.pod["status"]["containerStatuses"] = [
            {"name": "vllm", "restartCount": 0, "state": {"running": {}}, "imageID": node["image"]}
        ]
        self.stop = time.monotonic_ns() // 1_000_000 + 30000

    def test_retained_origin_cache_and_adapters_preserve_cutoff(self):
        spec, adapters = self.binding.adapters(
            self.pod, 0, self.stop, request_ids={}, lifecycle=LifecycleReceiptProducer()
        )
        self.assertEqual(spec["original_stop_ms"], self.stop)
        self.assertEqual(spec["process_generation"], "native-generation")
        self.assertEqual(adapters["metrics"].http.stop_ns, self.stop * 1_000_000)
        self.assertEqual(adapters["lifecycle"].http.stop_ns, self.stop * 1_000_000)
        self.assertEqual(adapters["lifecycle"].spool_http.stop_ns, self.stop * 1_000_000)
        self.assertEqual(adapters["native"].http.http.stop_ns, self.stop * 1_000_000)
        self.assertTrue(
            {name for name, _, _ in self.binding.periodic(adapters)} <= set(self.owner.sources)
        )
        cache = self.binding.cache(0, self.stop)
        self.assertEqual(cache.witness["model_cache_state"], "cold")
        self.assertEqual([x[1] for x in self.binding.periodic(adapters)], [1000, 500, 500])
        wire = [p for p in (self.owner.root / "wire").iterdir() if p.is_file()]
        self.assertTrue(any(b"inf037b-native-events-v1" in p.read_bytes() for p in wire))

    def test_startup_port_returns_same_owner_transports_and_original_cutoff(self):
        from inference_platform.inf037b_eks_cluster_runtime import startup

        case = self.case
        case.objects[pod_path("unit", "engine-0")] = self.pod
        case.runtime.binding["D_session_ms"] = self.stop + 1000
        case.runtime.binding["t0_ms"] = self.stop - 30000
        case.runtime.clock = lambda: self.stop - 30000
        case.inputs["startup"]["cold"].update(transports=self.binding, request_ids={})
        result = startup(case.runtime, "cold", case.cold, self.stop)
        self.assertEqual(result["transport_spec"]["original_stop_ms"], self.stop)
        self.assertEqual(
            result["sampler"]["adapters"][self.uid].http.stop_ns, self.stop * 1_000_000
        )
        self.assertEqual([p[1] for p in result["transport_periodic"]], [1000, 500, 500])
        self.assertTrue(callable(self.binding.setup_signal))

    def test_unadmitted_restarted_wrong_origin_and_source_pins_refuse(self):
        for key in ("pod_uid", "node_boot_id", "helper_sha256", "manifest_sha256"):
            saved = self.origin[key]
            self.origin[key] = "old"
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "transport:origin:"):
                self.binding(self.pod, 0, self.stop)
            self.origin[key] = saved
        self.pod["status"]["containerStatuses"][0]["restartCount"] = 1
        with self.assertRaisesRegex(ValueError, "container_restart_or_state"):
            self.binding(self.pod, 0, self.stop)
        self.pod["metadata"]["uid"] = "unseen"
        with self.assertRaisesRegex(ValueError, "uid_not_observed"):
            self.binding(self.pod, 0, self.stop)

    def test_each_replacement_address_is_derived_again_and_external_http_refuses(self):
        from inference_platform.inf037b_capture import DeadlineHTTP

        self.binding.endpoints["0"].pop("local_test_pod_http")
        self.pod["status"]["podIP"] = "10.2.0.4"
        self.assertEqual(
            self.binding.pod_http(self.pod, 0, 8000),
            {"base": "http://10.2.0.4:8000", "internal": True},
        )
        self.pod["status"]["podIP"] = "10.2.0.5"
        self.assertEqual(self.binding.pod_http(self.pod, 0, 9101)["base"], "http://10.2.0.5:9101")
        for url in ("http://8.8.8.8:9101", "ftp://10.2.0.5:9101", "http://example.com"):
            with self.assertRaisesRegex(ValueError, "capture:tls"):
                DeadlineHTTP(
                    url, internal=True, stop_ns=self.stop * 1_000_000, retain=lambda *a: None
                )

    @unittest.skipUnless(
        os.name == "posix" and os.environ.get("INF037B_EKS_HOST_TEST") == "1",
        "real native child /proc + durable node spool required on CPU host",
    )
    def test_linux_native_child_spool_is_read_after_exit(self):
        from test_runtime_observers import module

        from inference_platform import inf037b_native as native

        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        root = self.case.root / "node-spool"
        root.mkdir()
        origin = {
            **self.origin,
            "node_boot_id": boot,
            "supervisor_pid": os.getpid(),
            "supervisor_start": Path("/proc/self/stat").read_text().rsplit(")", 1)[1].split()[19],
        }
        code = "import json,sys; from pathlib import Path; from inference_platform.inf037b_native import NativeEmitter; e=NativeEmitter(Path(sys.argv[1]),json.loads(sys.argv[2])); e.observe('installed','input','a'*64); e.close()"
        subprocess.run(
            [sys.executable, "-c", code, str(root / self.uid / "native"), json.dumps(origin)],
            capture_output=True,
            check=True,
            timeout=10,
        )
        runtime = module("node_observer")
        observer = runtime.Observer.__new__(runtime.Observer)
        observer.lifecycle_root, observer.node, observer.boot = root, "node0", boot
        with patch.dict(sys.modules, {"native_source": native}):
            from inference_platform.inf037b_capture import DeadlineHTTP
            from inference_platform.inf037b_eks_transports import NativeSpoolHTTP

            server = ThreadingHTTPServer(("127.0.0.1", 0), observer.handler())
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.addCleanup(thread.join, 2)
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
            retained = []
            http = DeadlineHTTP(
                f"http://127.0.0.1:{server.server_port}",
                local_test=True,
                stop_ns=time.monotonic_ns() + 5_000_000_000,
                retain=lambda a, b, data, meta: retained.append(data),
            )
            data, _ = NativeSpoolHTTP(http, self.uid).get("/native/events?after=-1")
            value = json.loads(data)
            self.assertTrue(any(b"inf037b-native-events-v1" in data for data in retained))
            self.assertEqual(value["events"][0]["event"], "installed")
            self.assertEqual(value["origin"], origin)
            with self.assertRaisesRegex(ValueError, "offset_future"):
                observer.native(self.uid, {"after": ["99"]})
            with self.assertRaisesRegex(ValueError, "invalid_native_spool_identity"):
                observer.native("../escape", {"after": ["-1"]})


class NativeReadonlyTests(unittest.TestCase):
    def test_portable_reader_uses_immutable_only_without_wal(self):
        import sqlite3

        from inference_platform import inf037b_native as native

        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            writer = sqlite3.connect(root / "events.sqlite")
            writer.execute("PRAGMA journal_mode=WAL")
            writer.executescript(
                "CREATE TABLE meta(value BLOB); CREATE TABLE events(seq INTEGER PRIMARY KEY,value BLOB);"
            )
            writer.execute("INSERT INTO meta VALUES (?)", (encode({"pod_uid": "portable"}),))
            writer.execute("INSERT INTO events VALUES (1,?)", (encode({"event": "installed"}),))
            writer.commit()
            connect = sqlite3.connect
            with patch.object(native.sqlite3, "connect", wraps=connect) as opened:
                self.assertEqual(native.read_events(root)["events"][0]["event"], "installed")
                self.assertNotIn("immutable", opened.call_args.args[0])
            writer.close()
            self.assertFalse((root / "events.sqlite-wal").exists())
            with patch.object(native.sqlite3, "connect", wraps=connect) as opened:
                self.assertEqual(native.read_events(root)["events"][0]["event"], "installed")
                self.assertIn("mode=ro&immutable=1", opened.call_args.args[0])

    def test_reader_bounds_open_and_first_read_recovery_and_keeps_other_errors(self):
        import sqlite3

        from inference_platform import inf037b_native as native

        root = Path(self.enterContext(TemporaryDirectory()))
        (root / "events.sqlite").touch()
        tick = [0.0]
        pauses = []

        def pause(seconds):
            pauses.append(seconds)
            tick[0] += seconds

        for failure in (sqlite3.OperationalError("open"), sqlite3.DatabaseError("other")):
            tick[0] = 0
            pauses.clear()
            with (
                self.subTest(failure=str(failure)),
                patch.object(native.time, "monotonic", side_effect=lambda: tick[0]),
                patch.object(native.time, "sleep", side_effect=pause),
                patch.object(native.sqlite3, "connect", side_effect=failure) as opened,
            ):
                with self.assertRaises(type(failure)) as caught:
                    native.read_events(root)
                self.assertIs(caught.exception, failure)
                if type(failure) is sqlite3.OperationalError:
                    self.assertGreater(opened.call_count, 1)
                    self.assertLessEqual(opened.call_count, native.NATIVE_READ_ATTEMPTS)
                    self.assertLessEqual(tick[0], native.NATIVE_READ_BOUND_S)
                    self.assertTrue(pauses)
                else:
                    self.assertEqual(opened.call_count, 1)
                    self.assertFalse(pauses)
                self.assertTrue(all(0 < c.kwargs["timeout"] <= 0.25 for c in opened.call_args_list))
        tick[0] = 0
        failure = sqlite3.OperationalError("deadline lock")

        def blocked(*args, **kwargs):
            tick[0] += kwargs["timeout"]
            raise failure

        with (
            patch.object(native.time, "monotonic", side_effect=lambda: tick[0]),
            patch.object(native.time, "sleep", side_effect=pause),
            patch.object(native.sqlite3, "connect", side_effect=blocked) as opened,
        ):
            with self.assertRaises(sqlite3.OperationalError) as caught:
                native.read_events(root)
            self.assertIs(caught.exception, failure)
            self.assertEqual(tick[0], native.NATIVE_READ_BOUND_S)
            self.assertEqual(opened.call_count, 4)
            self.assertLess(opened.call_args.kwargs["timeout"], 0.25)
        for statement in ("BEGIN", "SELECT value FROM meta"):
            tick[0] = 0
            db = Mock()

            def execute(sql, statement=statement):
                if sql == statement:
                    raise sqlite3.OperationalError("first statement")
                return Mock()

            db.execute.side_effect = execute
            with (
                self.subTest(statement=statement),
                patch.object(native.time, "monotonic", side_effect=lambda: tick[0]),
                patch.object(native.time, "sleep", side_effect=pause),
                patch.object(native.sqlite3, "connect", return_value=db) as opened,
            ):
                with self.assertRaisesRegex(sqlite3.OperationalError, "first statement"):
                    native.read_events(root)
                self.assertLessEqual(opened.call_count, native.NATIVE_READ_ATTEMPTS)
                self.assertEqual(db.close.call_count, opened.call_count)
                self.assertLessEqual(tick[0], native.NATIVE_READ_BOUND_S)
        db = Mock()
        db.execute.side_effect = sqlite3.IntegrityError("not an open error")
        with patch.object(native.sqlite3, "connect", return_value=db) as opened:
            with self.assertRaisesRegex(sqlite3.IntegrityError, "not an open error"):
                native.read_events(root)
            self.assertEqual(opened.call_count, 1)
            db.close.assert_called_once()

        db = Mock()

        def late_error(sql, *args):
            if sql == "SELECT value FROM meta":
                return SimpleNamespace(fetchone=lambda: (b"{}",))
            if sql.startswith("SELECT seq"):
                raise sqlite3.OperationalError("later query")
            return Mock()

        db.execute.side_effect = late_error
        with patch.object(native.sqlite3, "connect", return_value=db) as opened:
            with self.assertRaisesRegex(sqlite3.OperationalError, "later query"):
                native.read_events(root)
            self.assertEqual(opened.call_count, 1)
            db.close.assert_called_once()

    def test_real_lock_released_before_bound_is_waited_out_and_held_lock_raises(self):
        import sqlite3

        from inference_platform.inf037b_native import read_events

        root = Path(self.enterContext(TemporaryDirectory()))
        writer = sqlite3.connect(root / "events.sqlite")
        self.addCleanup(writer.close)
        writer.executescript(
            "CREATE TABLE meta(value BLOB); CREATE TABLE events(seq INTEGER PRIMARY KEY,value BLOB);"
        )
        writer.execute("INSERT INTO meta VALUES (?)", (encode({"pod_uid": "locked"}),))
        writer.execute("INSERT INTO events VALUES (1,?)", (encode({"event": "installed"}),))
        writer.commit()
        # A real DELETE-journal exclusive lock gives a portable blocking read.
        # Force the RO branch; actual WAL-close locking is tested in the stage.
        exists = Path.exists

        def present(path):
            return True if path == root / "events.sqlite-wal" else exists(path)

        result, errors, started = [], [], threading.Event()

        def read():
            started.set()
            try:
                result.append(read_events(root))
            except BaseException as exc:
                errors.append(exc)

        writer.execute("BEGIN EXCLUSIVE")
        with patch.object(Path, "exists", present):
            thread = threading.Thread(target=read)
            thread.start()
            self.assertTrue(started.wait(1))
            time.sleep(0.08)
            writer.commit()
            thread.join(2)
            self.assertFalse(thread.is_alive())
            self.assertFalse(errors)
            self.assertEqual(result[0]["events"][0]["event"], "installed")
            writer.execute("BEGIN EXCLUSIVE")
            try:
                with self.assertRaises(sqlite3.OperationalError):
                    read_events(root)
            finally:
                writer.rollback()

    @unittest.skipUnless(
        os.name == "posix" and os.environ.get("INF037B_NATIVE_READONLY_ROOT"),
        "dedicated read-only bind mount required on CPU host",
    )
    def test_linux_native_readonly_writer_states(self):
        import errno

        from inference_platform.inf037b_native import read_events

        root = Path(os.environ["INF037B_NATIVE_READONLY_ROOT"])
        with self.assertRaises(OSError) as caught:
            (root / "forbidden-write").write_bytes(b"never")
        self.assertEqual(caught.exception.errno, errno.EROFS)
        for state in ("open", "closed", "killed"):
            with self.subTest(state=state):
                directory = root / state
                self.assertEqual((directory / "events.sqlite-wal").exists(), state != "closed")
                value = read_events(directory)
                self.assertEqual(value["origin"]["pod_uid"], state)
                self.assertEqual(len(value["events"]), 1)
                self.assertEqual(value["events"][0]["event"], "installed")

        original_exists = Path.exists
        checks = []

        def stale_once(path):
            if path == root / "closed" / "events.sqlite-wal":
                checks.append(path)
                if len(checks) == 1:
                    return True  # Writer closed between the old check and open.
            return original_exists(path)

        import sqlite3

        connect = sqlite3.connect
        with (
            patch.object(Path, "exists", stale_once),
            patch.object(sqlite3, "connect", wraps=connect) as opened,
        ):
            value = read_events(root / "closed")
        self.assertEqual(len(value["events"]), 1)
        self.assertEqual(value["events"][0]["event"], "installed")
        self.assertEqual(opened.call_count, 2)
        self.assertNotIn("immutable", opened.call_args_list[0].args[0])
        self.assertIn("immutable=1", opened.call_args_list[1].args[0])

    @unittest.skipUnless(
        os.name == "posix" and os.environ.get("INF037B_NATIVE_READONLY_ROOT"),
        "dedicated read-only bind mount required on CPU host",
    )
    def test_linux_native_single_close_race(self):
        from native_readonly_fixture import RACE_SPOOLS

        from inference_platform.inf037b_native import read_events

        root = Path(os.environ["INF037B_NATIVE_READONLY_ROOT"]) / "race"
        self.assertEqual(int((root / "ready").read_text()), RACE_SPOOLS)
        seen, failures, reads, open_reads = set(), {}, 0, 0
        deadline = time.monotonic() + 35
        while not (root / "complete").exists() and time.monotonic() < deadline:
            index = int((root / "current").read_text())
            directory = root / str(index)
            open_reads += int((directory / "events.sqlite-wal").exists())
            try:
                value = read_events(directory)
                self.assertEqual(value["origin"]["pod_uid"], "race-" + str(index))
                self.assertEqual(len(value["events"]), 1)
                self.assertEqual(value["events"][0]["event"], "installed")
                seen.add(index)
                reads += 1
            except Exception as exc:
                key = type(exc).__name__ + ":" + str(exc)
                failures[key] = failures.get(key, 0) + 1
        self.assertTrue((root / "complete").exists(), "single-close writer did not finish")
        for index in range(RACE_SPOOLS):
            value = read_events(root / str(index))
            self.assertEqual(value["origin"]["pod_uid"], "race-" + str(index))
            self.assertEqual(len(value["events"]), 1)
            seen.add(index)
        print(
            json.dumps(
                {
                    "single_close_spools": len(seen),
                    "loop_reads": reads,
                    "open_reads": open_reads,
                    "failed_reads": failures,
                }
            ),
            flush=True,
        )
        self.assertEqual(len(seen), RACE_SPOOLS)
        self.assertGreater(open_reads, 0, "writer finished before reader started")
        self.assertFalse(failures)


class SetupSignalTests(unittest.TestCase):
    def test_serving_dispatch_and_supervisor_run_are_unchanged(self):
        import ast
        import hashlib

        from test_runtime_observers import module

        rt = module("capture_runtime")
        tree = ast.parse(Path(rt.__file__).read_text())
        run = next(
            n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name == "Supervisor"
        )
        run = next(n for n in run.body if isinstance(n, ast.FunctionDef) and n.name == "run")
        self.assertEqual(
            hashlib.sha256(ast.dump(run, include_attributes=False).encode()).hexdigest(),
            "e8daba972b98ff2bb95bd1ef3ddf0fd42939e4a2dbe0ae17fa97d7670bc55aa0",
        )
        with (
            patch.object(rt, "child") as child,
            patch.object(rt.sys, "argv", [rt.__file__, "--child", "--model", "pinned"]),
            patch.dict(os.environ, {"CAPTURE_ROOT": "fixture-root"}),
        ):
            rt.main()
            child.assert_called_once_with(Path("fixture-root"), ["--model", "pinned"])
        with (
            patch.object(rt, "Supervisor") as supervisor,
            patch.object(rt.sys, "argv", [rt.__file__, "--model", "pinned"]),
            patch.dict(
                os.environ, {"CAPTURE_ROOT": "fixture-root", "POD_UID": "uid", "BACKEND_SLOT": "0"}
            ),
        ):
            supervisor.return_value.run.return_value = 0
            with self.assertRaises(SystemExit):
                rt.main()
            self.assertEqual(
                supervisor.return_value.run.call_args.args[0][-3:], ["--child", "--model", "pinned"]
            )
            self.assertNotIn("role", supervisor.call_args.kwargs)

    def test_signal_child_reuses_version_and_source_checks(self):
        from types import ModuleType

        from test_runtime_observers import module

        rt = module("capture_runtime")
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            launcher_file = root / "launcher.py"
            entry_file = root / "entry.py"
            launcher_file.write_bytes(b"labelled launcher fixture")
            entry_file.write_bytes(b"labelled entry fixture")
            names = (
                "vllm",
                "vllm.entrypoints",
                "vllm.entrypoints.launchers",
                "vllm.entrypoints.launchers.api_server",
                "vllm.entrypoints.launchers.launcher",
                "vllm.entrypoints.launchers.api_server.entry",
            )
            modules = {name: ModuleType(name) for name in names}
            modules["vllm"].__version__ = "0.29.0"
            modules[names[-2]].__file__ = str(launcher_file)
            modules[names[-1]].__file__ = str(entry_file)
            with (
                patch.dict(sys.modules, modules),
                patch.object(rt, "LAUNCHER_SHA256", sha(launcher_file.read_bytes())),
                patch.object(rt, "ENTRY_SHA256", sha(entry_file.read_bytes())),
            ):
                self.assertEqual(rt.checked_runtime(), (modules[names[-2]], modules[names[-1]]))
                modules["vllm"].__version__ = "wrong"
                with self.assertRaisesRegex(RuntimeError, "runtime_version_mismatch"):
                    rt.checked_runtime()
                modules["vllm"].__version__ = "0.29.0"
                entry_file.write_bytes(b"changed")
                with self.assertRaisesRegex(RuntimeError, "runtime_startup_signal_source_mismatch"):
                    rt.checked_runtime()

    @unittest.skipUnless(
        os.name == "posix" and os.environ.get("INF037B_EKS_HOST_TEST") == "1",
        "real setup supervisor SIGTERM and /proc lineage required on CPU host",
    )
    def test_linux_setup_signal_mode_records_actual_sigterm(self):
        import hashlib
        import signal

        root = Path(self.enterContext(TemporaryDirectory()))
        # Labelled vLLM module/source-pin fixture only; no production bypass.
        package = root / "vllm/entrypoints/launchers/api_server"
        package.mkdir(parents=True)
        for directory in (
            root / "vllm",
            root / "vllm/entrypoints",
            root / "vllm/entrypoints/launchers",
            package,
        ):
            (directory / "__init__.py").write_text(
                "__version__='0.29.0'" if directory == root / "vllm" else ""
            )
        launcher = root / "vllm/entrypoints/launchers/launcher.py"
        launcher.write_text("class NoSignalServer: pass\n")
        entry = package / "entry.py"
        entry.write_text("def main(): raise RuntimeError('ENGINE_MUST_NOT_START')\n")
        source = Path(__file__).resolve().parents[2] / "deploy/eks/capture_runtime.py"
        program = source.read_text()
        for constant, file in (("LAUNCHER_SHA256", launcher), ("ENTRY_SHA256", entry)):
            import re

            program, count = re.subn(
                constant + r' = "[0-9a-f]{64}"',
                constant + ' = "' + hashlib.sha256(file.read_bytes()).hexdigest() + '"',
                program,
            )
            self.assertEqual(count, 1)
        runtime = root / "capture_runtime.py"
        runtime.write_text(program)
        spool = root / "signal-test-uid"
        process = subprocess.Popen(
            [sys.executable, str(runtime), "--setup-signal"],
            env={
                **os.environ,
                "PYTHONPATH": str(root),
                "POD_UID": "signal-test-uid",
                "BACKEND_SLOT": "1",
                "NODE_NAME": "node1",
                "CAPTURE_ROOT": str(spool),
            },
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            deadline = time.monotonic() + 10
            while not (spool / "signal-child-ready.json").exists():
                self.assertIsNone(process.poll())
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.02)
            origin = json.loads((spool / "supervisor-origin.json").read_bytes())
            self.assertEqual(
                (origin["role"], origin["slot"], origin["pod_uid"]),
                ("setup_signal", 1, "signal-test-uid"),
            )
            self.assertEqual(origin["supervisor_pid"], process.pid)
            self.assertEqual(
                origin["supervisor_sha256"], hashlib.sha256(runtime.read_bytes()).hexdigest()
            )
            client = http.client.HTTPConnection("127.0.0.1", 9101, timeout=2)
            try:
                client.request("GET", "/ready")
                response = client.getresponse()
                self.assertEqual(response.status, 200)
                self.assertTrue(json.loads(response.read())["ready"])
            finally:
                client.close()
            process.send_signal(signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=10)
            self.assertEqual(process.returncode, 0, (stdout, stderr))
            events = [
                json.loads(line) for line in (spool / "lifecycle.jsonl").read_bytes().splitlines()
            ]
            signals = [row for row in events if row["event"] == "signal"]
            self.assertEqual(len(signals), 1)
            self.assertEqual(signals[0]["signal"], "SIGTERM")
            self.assertLessEqual(signals[0]["signal_data"]["receipt_ns"], signals[0]["mono_ns"])
            self.assertEqual(events[-1]["event"], "process_end")
            from test_runtime_observers import module

            observer = module("node_observer").Observer.__new__(module("node_observer").Observer)
            observer.lifecycle_root, observer.node, observer.boot = (
                root,
                "node1",
                origin["node_boot_id"],
            )
            server = ThreadingHTTPServer(("127.0.0.1", 0), observer.handler())
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.addCleanup(thread.join, 2)
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
            # The Pod server is gone. Read the real node observer's retained
            # origin and lifecycle endpoints, rather than inferring from exit.
            client = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=2)
            try:
                client.request("GET", "/lifecycle/signal-test-uid/origin")
                response = client.getresponse()
                self.assertEqual(response.status, 200)
                self.assertEqual(json.loads(response.read()), origin)
                client.request("GET", "/lifecycle/signal-test-uid/events?offset=0")
                response = client.getresponse()
                self.assertEqual(response.status, 200)
                self.assertEqual(
                    [json.loads(line) for line in response.read().splitlines()], events
                )
            finally:
                client.close()

            self.assertEqual(
                signals[0]["pid"], next(e["pid"] for e in events if e["event"] == "process_start")
            )
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            process.stdout.close()
            process.stderr.close()

    def test_api_delete_window_and_node_spool_signal_proof(self):
        from types import SimpleNamespace

        from inference_platform.eks_deployment import setup_signal_pod
        from inference_platform.inf037b_eks_signal import SetupSignal
        from inference_platform.inf037b_live import LiveRows

        case = ClusterTests(methodName="runTest")
        case.setUp()
        self.addCleanup(case.doCleanups)
        clock = [time.monotonic_ns()]

        def now():
            clock[0] += 1_000_000
            return clock[0]

        def sleep(seconds):
            clock[0] += int(seconds * 1e9)

        start = clock[0] + 2_000_000_000
        stop = start + 150_000_000_000
        case.runtime.binding.update(
            t0_ms=clock[0] // 1_000_000, D_session_ms=stop // 1_000_000 + 1000
        )
        case.runtime.clock = lambda: now() // 1_000_000
        wire = []
        maps = []
        owner = SimpleNamespace(
            sources={"lifecycle:setup": []},
            clock_rows=maps,
            retainer=lambda *a, **kw: lambda a, b, data, meta: wire.append(data),
        )
        rows = LiveRows("signal-fixture", "collector", clock=now, sink=maps.append)
        owner.rows = lambda source: rows
        origin = {}
        events = []
        event_reads = []
        pending_exit = []

        class Node(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                headers = {}
                if self.path == "/clock":
                    value = {"boot_id": "nodeboot", "mono_ns": now()}
                elif self.path == "/ready":
                    value = {
                        "ready": True,
                        "role": "setup_signal",
                        "pod_uid": origin["pod_uid"],
                        "boot_id": "process",
                    }
                elif self.path.endswith("/origin"):
                    value = origin
                else:
                    value = None
                    from urllib.parse import parse_qs, urlsplit

                    offset = int(parse_qs(urlsplit(self.path).query)["offset"][0])
                    event_reads.append(offset)
                    raw = b"".join(encode(e) for e in events)
                    body = raw[offset:]
                    headers = {"X-Capture-Boot": "process", "X-Capture-Next": str(len(raw))}
                    if pending_exit:
                        events.append(pending_exit.pop())
                if value is not None:
                    body = encode(value)
                self.send_response(200)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Node)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        options = {"base": f"http://127.0.0.1:{server.server_port}", "local_test": True}

        def after(method, path, value):
            if method == "POST":
                value["status"] = {"conditions": [{"type": "Ready", "status": "True"}]}
                origin.update(
                    pod_uid=value["metadata"]["uid"],
                    role="setup_signal",
                    slot=0,
                    node="node0",
                    node_boot_id="nodeboot",
                    supervisor_sha256=case.pins["supervisor"],
                    supervisor_pid=11,
                    supervisor_start="1",
                    boot_id="process",
                )
            if method == "DELETE":
                at = now()
                for i, event in enumerate(
                    ("supervisor_start", "process_start", "signal", "process_end")
                ):
                    events.append(
                        {
                            "event": event,
                            "pod_uid": origin["pod_uid"],
                            "node_boot_id": "nodeboot",
                            "boot_id": "process",
                            "sequence": i,
                            "mono_ns": at + i * 1_000_000,
                            "pid": 22,
                            **(
                                {"signal": "SIGTERM", "signal_data": {"receipt_ns": at}}
                                if event == "signal"
                                else {}
                            ),
                        }
                    )
                pending_exit.append(events.pop())  # Exit follows the API delete reply.
                clock[0] = at + 10_000_000

        case.after_write = after
        runtime_source = (
            Path(__file__).resolve().parents[2] / "deploy/eks/capture_runtime.py"
        ).read_text()
        case.pins["supervisor"] = sha(runtime_source.encode())
        case.runtime.pins["supervisor"] = case.pins["supervisor"]
        template = setup_signal_pod({"namespace": "unit"}, 0, "node0", runtime_source)
        source = SetupSignal(
            owner=owner,
            runtime=case.runtime,
            slot=0,
            node={"name": "node0", "boot_id": "nodeboot"},
            template=template,
            node_http=options,
            pod_http=options,
            pins=case.pins,
            offset_ms=90000,
            clock=now,
            sleep=sleep,
        )
        # The logical-clock protocol fixture advances wall and monotonic time
        # together; laptop scheduler delay is not a source clock step.
        with patch("inference_platform.inf037b_live.time.time", side_effect=lambda: clock[0] / 1e9):
            source.ready(start)
            case.drop_write = True  # Lost delete response must settle the same effect.
            proof = source.trigger(start, stop)
            self.assertEqual(proof["origin"], origin)
            self.assertEqual(len(event_reads), 2)
            self.assertEqual(event_reads[0], 0)
            self.assertGreater(event_reads[1], 0)
            self.assertGreaterEqual(proof["signal_ms_bounds"][0], start // 1_000_000 + 90000)
            deletes = [x for x in case.writes if x[0] == "DELETE"]
            self.assertEqual(len(deletes), 1)
            self.assertIn("setup-signal-0", deletes[0][1])
            self.assertIn(pod_path("unit", "engine-0"), case.objects)
            self.assertTrue(any(b"receipt_ns" in raw for raw in wire))
            events[2]["signal_data"]["receipt_ns"] = start - 1_000_000
            with self.assertRaisesRegex(ValueError, "signal:receipt_window"):
                source.proof(start, stop)
            events.pop()  # A permanently absent exit must refuse, without retrying deletion.
            with self.assertRaisesRegex(ValueError, "signal:process_not_exited"):
                source.proof(start, now() + 100_000_000)


class FixedActionsTests(unittest.TestCase):
    """Real HTTP; controller and device reports are labelled protocol fixtures."""

    def setUp(self):
        from inference_platform.inf037b_eks_actions import fixed_action_inputs

        self.case = c = ClusterTests(methodName="runTest")
        c.setUp()
        self.addCleanup(c.doCleanups)
        self.pods = {
            str(i): copy.deepcopy(c.objects[pod_path("unit", "engine-" + str(i))]) for i in (0, 1)
        }
        self.controller_path = "/apis/apps/v1/namespaces/unit/statefulsets/engine"
        self.controller = {
            "apiVersion": "apps/v1",
            "kind": "StatefulSet",
            "metadata": {"name": "engine", "namespace": "unit"},
            "spec": {
                "replicas": 2,
                "template": {
                    "spec": {
                        "containers": [
                            {"name": "vllm", "image": "unit@sha256:" + c.pins["runtime"]}
                        ]
                    }
                },
            },
        }
        c.config["objects"]["controller"] = {"path": self.controller_path, "uid": "controller-uid"}
        c.objects[self.controller_path] = copy.deepcopy(self.controller)
        c.objects[self.controller_path]["metadata"].update(
            uid="controller-uid", resourceVersion="1"
        )
        path = "/api/v1/namespaces/unit/configmaps/gateway-config"
        c.config["objects"]["gateway_config"] = {"path": path, "uid": "config-uid"}
        c.objects[path] = {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "gateway-config",
                "namespace": "unit",
                "uid": "config-uid",
                "resourceVersion": "1",
            },
            "data": {"pinned": "original"},
        }
        record = copy.deepcopy(c.objects[path])
        for field in ("uid", "resourceVersion"):
            record["metadata"].pop(field)
        self.records = [{"name": "gateway_config", "object": record, "sha256": sha(encode(record))}]
        self.fixed = {
            "controller": {
                "name": "controller",
                "object": self.controller,
                "sha256": sha(encode(self.controller)),
            },
            "configuration": self.records,
        }
        c.config["objects"]["controller"]["sha256"] = self.fixed["controller"]["sha256"]
        c.config["objects"]["gateway_config"]["sha256"] = self.records[0]["sha256"]
        c.inputs.pop("setup")
        c.inputs.pop("campaign_actions")
        c.inputs["fixed_actions"] = self.fixed
        c.journal = FileJournal(c.root / "fixed", {}, initialize=True)
        c.runtime = c.open()
        c.factory.config["cluster_runtime"] = c.runtime
        self.plan = fixed_action_inputs(c.config, c.pins, **self.fixed)
        c.after_write = self.after_write
        self.generations = 0

    def after_write(self, method, path, value):
        c = self.case
        if method == "PUT" and path == self.controller_path:
            for i in (0, 1):
                target = pod_path("unit", "engine-" + str(i))
                if i >= value["spec"]["replicas"]:
                    c.objects.pop(target, None)
                elif target not in c.objects:
                    self.generations += 1
                    pod = copy.deepcopy(self.pods[str(i)])
                    pod["metadata"]["uid"] = "fresh-" + str(self.generations)
                    c.objects[target] = pod
        for spec in c.inputs["device"].values():
            report = c.objects[spec["report_path"]]
            data = strict_json(report["data"]["receipt.json"])
            data["observation_ms"] = [c.now, c.now]
            report["data"]["receipt.json"] = encode(data).decode()

    def test_fixed_setup_order_drains_and_uses_fresh_cached_uid(self):
        c = self.case
        unrelated = pod_path("unit", "other")
        c.objects[unrelated] = copy.deepcopy(self.pods["0"])
        c.objects[unrelated]["metadata"].update(name="other", uid="other")
        results = {}
        for step in SETUP_ORDER:
            results[step] = c.runtime.setup_effect(step, "setup:" + step, 1000000)
        self.assertEqual(c.runtime.state()["setups"], list(SETUP_ORDER))
        self.assertNotEqual(results["cold"]["uid"], results["node_cached"]["uid"])
        self.assertEqual(results["cold"]["node_uid"], results["node_cached"]["node_uid"])
        self.assertIn(unrelated, c.objects)
        self.assertEqual(c.objects[self.controller_path]["spec"]["replicas"], 2)
        self.assertEqual(set(results["node_cached"]["placement_reads"]), {"0", "1"})
        self.assertTrue(all("resourceVersion" in w[2]["metadata"] for w in c.writes))
        count = len(c.writes)
        self.assertEqual(
            c.open().setup_effect("node_cached", "setup:node_cached", 1000000),
            results["node_cached"],
        )
        self.assertEqual(len(c.writes), count)
        self.assertTrue(c.wire)

    def test_controller_delay_keeps_original_stop_and_never_uses_terminal_phase(self):
        c = self.case
        c.after_write = None
        for i in (0, 1):
            c.objects[pod_path("unit", "engine-" + str(i))]["status"]["phase"] = "Succeeded"
        with self.assertRaisesRegex(ValueError, "cluster:deadline"):
            c.runtime.setup_effect("begin", "blocked", c.now + 100)
        self.assertEqual(len(c.writes), 2)  # restore + scale; no repeated effect
        self.assertNotIn("begin", c.runtime.state()["setups"])
        self.assertIn(pod_path("unit", "engine-0"), c.objects)

    def test_campaign_targets_and_lost_uid_rv_delete_reopen(self):
        c = self.case
        from inference_platform.inf037b_contract import TARGET_ORDER

        self.assertEqual(
            [self.plan["campaign_actions"]["attempt:" + str(i)]["target_slot"] for i in (1, 2, 3)],
            list(TARGET_ORDER),
        )
        template = self.plan["campaign_actions"]["attempt:1"]["effects"][0]
        c.drop_write = True
        first = c.runtime.action("event", template, 1000000, owner=c.campaign)
        self.assertIsNone(first["observed"])
        self.assertEqual(
            c.writes[-1][2]["preconditions"], {"uid": "engine-uid0", "resourceVersion": "1"}
        )
        self.assertEqual(c.open().action("event", template, 1000000, owner=c.campaign), first)
        self.assertEqual(len(c.writes), 1)
        self.assertIn(pod_path("unit", "engine-1"), c.objects)

    def test_real_http_rejects_stale_uid_and_rv(self):
        c = self.case
        path = pod_path("unit", "engine-0")
        for pre in (
            {"uid": "foreign", "resourceVersion": "1"},
            {"uid": "engine-uid0", "resourceVersion": "old"},
        ):
            with self.assertRaisesRegex(ValueError, "transport_response"):
                c.api.request("DELETE", path, 1000000, {"preconditions": pre})
            self.assertIn(path, c.objects)

    def test_absence_is_only_a_complete_404_and_census_must_be_complete(self):
        c = self.case
        self.assertIsNone(c.runtime.read(pod_path("unit", "absent"), 1000000, absent=True)["value"])
        c.drop = True
        with self.assertRaises((OSError, ValueError)):
            c.runtime.read(pod_path("unit", "absent"), 1000000, absent=True)
        c.census_partial = True
        with self.assertRaisesRegex(ValueError, "partial_census"):
            c.api.census(c.config["nodes"]["0"], 1000000)
        self.assertFalse(c.writes)

    def test_r369_configuration_window_survives_reopen_and_expires(self):
        from inference_platform.inf037b_eks_actions import restore_configuration

        c = self.case
        first = restore_configuration(c.runtime, "window", self.records, 1000000)
        c.now += 30000
        self.assertEqual(restore_configuration(c.open(), "window", self.records, 1000000), first)
        writes = len(c.writes)
        with self.assertRaisesRegex(ValueError, "actions:configuration_original_cutoff"):
            restore_configuration(c.open(), "window", self.records, 2000000)
        c.now = 121000
        with self.assertRaisesRegex(ValueError, "eks:scope_timeout:configuration_smoke_rollback"):
            restore_configuration(c.open(), "window", self.records, 1000000)
        self.assertEqual(len(c.writes), writes)

    def test_rollback_pin_mismatch_refuses_before_any_write_and_exact_restore_reopens(self):
        from inference_platform.inf037b_eks_actions import restore_configuration

        c = self.case
        changed = copy.deepcopy(self.records)
        changed[0]["object"]["data"]["probe"] = "changed"
        with self.assertRaisesRegex(ValueError, "actions:pinned_object"):
            restore_configuration(c.runtime, "rollback", changed, 1000000)
        self.assertFalse(c.writes)
        c.drop_write = True
        restored = restore_configuration(c.runtime, "rollback", self.records, 1000000)
        self.assertEqual(
            restore_configuration(c.open(), "rollback", self.records, 1000000), restored
        )
        self.assertEqual(len(c.writes), 1)
        self.assertEqual(restored[0]["observed"]["data"], self.records[0]["object"]["data"])

    def test_reset_residual_gpu_allocation_blocks_restore(self):
        from inference_platform.inf037b_eks_cluster_runtime import campaign_actions

        c = self.case
        # Keep the independent protocol fixture reporting an actual residual allocation.
        report = c.objects[c.inputs["device"]["0"]["report_path"]]
        data = strict_json(report["data"]["receipt.json"])
        data["allocations"] = [{"pod_uid": "engine-uid0", "device_id": "gpu0"}]
        report["data"]["receipt.json"] = encode(data).decode()
        context = copy.deepcopy(c.context)
        context["input"]["attempt"] = 2
        context["operation_key"] = "driver:attempt_setup:2"
        c.runtime.active_capture["attempt_setup:2"] = {"owner": c.campaign}
        result = campaign_actions(
            c.runtime, "attempt_setup", c.campaign, c.now + 1000, context, Mock(), {"index": 1}
        )
        with self.assertRaisesRegex(ValueError, "cluster:device_still_allocated"):
            result["kubernetes"]()
        scales = [w[2]["spec"]["replicas"] for w in c.writes if w[1] == self.controller_path]
        self.assertEqual(scales, [0])

    def test_reset_absence_and_free_report_precede_restore_and_both_uid_bindings(self):
        from inference_platform.inf037b_eks_cluster_runtime import campaign_actions

        c = self.case
        context = copy.deepcopy(c.context)
        context["input"]["attempt"] = 2
        context["operation_key"] = "driver:attempt_setup:2"
        capture = {
            "owner": c.campaign,
            "replacement_spec": lambda pod, slot, stop: {
                "uid": pod["metadata"]["uid"],
                "origin": {"pod_uid": pod["metadata"]["uid"]},
            },
            "replacement_adapters": {},
            "replacement_samplers": {},
            "request_ids": {},
            "lifecycle": LifecycleReceiptProducer(),
        }
        c.runtime.active_capture["attempt_setup:2"] = capture

        def after(method, path, value):
            self.after_write(method, path, value)
            if method == "PUT" and path == self.controller_path and value["spec"]["replicas"] == 2:
                self.assertEqual(set(c.runtime.state()["absences"]), {"0", "1"})
                for slot in (0, 1):
                    pod = c.objects[pod_path("unit", "engine-" + str(slot))]
                    c.campaign.rows("kubernetes").row(
                        "kubernetes",
                        "kubernetes",
                        c.campaign.boot,
                        "pod_created",
                        {
                            "pod_uid": pod["metadata"]["uid"],
                            "slot": slot,
                            "node_pseudonym": "node" + str(slot),
                        },
                    )

        c.after_write = after
        bound = []

        def bind(slot, spec, **kwargs):
            bound.append((slot, spec["uid"]))
            return {"metrics": SimpleNamespace(uid=spec["uid"], slot=slot)}

        actions = campaign_actions(
            c.runtime, "attempt_setup", c.campaign, 1000000, context, bind, {"index": 1}
        )
        actions["kubernetes"]()
        self.assertEqual([slot for slot, _ in bound], [0, 1])
        self.assertEqual(set(capture["replacement_adapters"]), {uid for _, uid in bound})
        self.assertEqual(
            [w[2]["spec"]["replicas"] for w in c.writes if w[1] == self.controller_path], [0, 2]
        )
        report_gets = [p for p in c.gets if "/configmaps/device-" in p]
        self.assertTrue(report_gets)

    def test_fixed_manifest_and_configuration_identity_are_pinned_on_reopen(self):
        c = self.case
        c.inputs["fixed_actions"]["configuration"][0]["object"]["data"]["pinned"] = "different"
        with self.assertRaisesRegex(ValueError, "actions:pinned_object"):
            c.open()
        self.assertFalse(c.writes)

    def test_attempt_action_deletes_only_target_and_binds_its_replacement(self):
        from inference_platform.inf037b_eks_cluster_runtime import campaign_actions

        c = self.case
        capture = {
            "owner": c.campaign,
            "spec": {"pre_end_ms": c.now},
            "replacement_spec": lambda pod, slot, stop: {
                "uid": pod["metadata"]["uid"],
                "origin": {"pod_uid": pod["metadata"]["uid"]},
            },
            "replacement_adapters": {},
            "replacement_samplers": {},
            "request_ids": {},
            "lifecycle": LifecycleReceiptProducer(),
        }
        c.runtime.active_capture["attempt:1"] = capture

        def after(method, path, value):
            if method == "DELETE":
                pod = copy.deepcopy(self.pods["0"])
                pod["metadata"]["uid"] = "replacement"
                c.objects[path] = pod
                c.campaign.rows("kubernetes").row(
                    "kubernetes",
                    "kubernetes",
                    c.campaign.boot,
                    "pod_created",
                    {"pod_uid": "replacement", "slot": 0, "node_pseudonym": "node0"},
                )

        c.after_write = after
        bound = []

        def bind(slot, spec, **kwargs):
            bound.append((slot, spec["uid"]))
            return {"metrics": SimpleNamespace(uid=spec["uid"], slot=slot)}

        actions = campaign_actions(c.runtime, "attempt", c.campaign, 1000000, c.context, bind, None)
        actions["kubernetes"]()
        self.assertEqual(bound, [(0, "replacement")])
        self.assertEqual(len(c.writes), 1)
        self.assertEqual(c.objects[pod_path("unit", "engine-1")]["metadata"]["uid"], "engine-uid1")

    def test_configuration_readback_refuses_unpinned_extra_data(self):
        from inference_platform.inf037b_eks_actions import restore_configuration

        c = self.case

        def changed(method, path, value):
            if value.get("kind") == "ConfigMap":
                value["data"]["unpinned"] = "retained"

        c.after_write = changed
        with self.assertRaisesRegex(ValueError, "cluster:configuration_readback"):
            restore_configuration(c.runtime, "extra", self.records, 1000000)
        self.assertEqual(len(c.writes), 1)
        self.assertIn(
            "unpinned",
            c.runtime.read(c.config["objects"]["gateway_config"]["path"], 1000000)["value"]["data"],
        )
