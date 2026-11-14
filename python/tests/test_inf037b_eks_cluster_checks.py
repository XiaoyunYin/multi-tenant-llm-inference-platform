"""R482-R484 controls on the real TCP API fixture, with portable journals."""

import copy
import unittest
from unittest.mock import Mock

import test_inf037b_eks_cluster as fixture
import test_inf037b_eks_placement as placement_fixture

from inference_platform.inf037b_archive import encode, strict_json
from inference_platform.inf037b_eks_cluster import (
    DEVICE_REPORT_MAX_AGE_MS,
    ClusterEffectAuthority,
    pod_path,
)


class ClusterCheckTests(unittest.TestCase):
    def setUp(self):
        self.c = fixture.ClusterTests(methodName="runTest")
        self.c.setUp()
        self.addCleanup(self.c.doCleanups)

    def report(self, **changes):
        c = self.c
        path = c.inputs["device"]["0"]["report_path"]
        value = strict_json(c.objects[path]["data"]["receipt.json"])
        value.update(changes)
        c.objects[path]["data"]["receipt.json"] = encode(value).decode()

    def template(self, method, target, source, body=None):
        return {"method": method, "target": target, "expected_uid": source, "body": body or {}}

    def setup_plan(self):
        c = self.c
        path = pod_path("unit", "engine-0")
        pod = copy.deepcopy(c.objects[path])
        pod.pop("status", None)
        for key in ("uid", "resourceVersion"):
            pod["metadata"].pop(key, None)
        steps = c.inputs["setup"]["steps"]
        steps["begin"]["actions"] = [
            self.template(
                "DELETE", {"role": "slot_pod", "slot": 0}, {"from": "initial_slot", "slot": 0}
            )
        ]
        for name in ("cold", "node_cached"):
            steps[name].update(
                result_slot=0,
                actions=[
                    self.template("POST", {"role": "slot_pod", "slot": 0}, {"from": "absent"}, pod)
                ],
            )
        steps["stop_cold_and_drain"]["actions"] = [
            self.template(
                "DELETE",
                {"role": "setup_result", "step": "cold"},
                {"from": "setup_result", "step": "cold"},
            )
        ]

    def through_cold(self):
        c = self.c
        self.setup_plan()
        c.runtime.setup_effect("begin", "k:begin", 1000000)
        c.now = 2000
        self.report(observation_ms=[1000, 1001])
        cold = c.runtime.setup_effect("cold", "k:cold", 1000000)
        c.now = 3000
        c.runtime.setup_effect("two_serving", "k:two", 1000000)
        return cold

    def test_full_setup_templates_delete_created_uid_after_resource_version_moves(self):
        c = self.c
        cold = self.through_cold()
        path = pod_path("unit", "engine-0")
        c.objects[path]["metadata"]["resourceVersion"] = "9"
        c.now = 400000
        c.runtime.setup_effect("stop_cold_and_drain", "k:stop", 1000000)
        self.report(observation_ms=[400000, 400001])
        c.now = 400001
        cached = c.runtime.setup_effect("node_cached", "k:cached", 1000000)
        self.assertNotEqual(cached["uid"], cold["uid"])
        deletes = [body for method, path, body in c.writes if method == "DELETE"]
        self.assertEqual(deletes[-1]["preconditions"], {"uid": cold["uid"], "resourceVersion": "9"})
        self.assertGreaterEqual(cached["device_release"]["observation_ms"][0], 400000)
        self.assertEqual(
            c.runtime.state()["writes"]["k:stop:0"]["before_read"]["value"]["metadata"][
                "resourceVersion"
            ],
            "9",
        )

    def test_pre_stop_report_refuses_cached_admission(self):
        c = self.c
        self.through_cold()
        c.now = 400000
        c.runtime.setup_effect("stop_cold_and_drain", "k:stop", 1000000)
        self.report(observation_ms=[399998, 399999])
        c.now = 400001
        before = len(c.writes)
        with self.assertRaisesRegex(ValueError, "device_before_absence"):
            c.runtime.setup_effect("node_cached", "k:cached", 400502)
        self.assertEqual(len(c.writes), before)
        self.assertNotIn("node_cached", c.runtime.state()["setup_results"])

    def test_report_after_actual_absence_passes(self):
        c = self.c
        self.setup_plan()
        c.runtime.setup_effect("begin", "k:begin", 1000000)
        c.now = 1100
        self.report(observation_ms=[1000, 1001])
        result = c.runtime.setup_effect("cold", "k:cold", 1000000)
        self.assertEqual(result["device_release"]["old_pod_uid"], "engine-uid0")
        self.assertIsNone(c.runtime.state()["absences"]["0"]["read"]["value"])

    def test_deletion_timestamp_is_not_absence_or_settlement(self):
        c = self.c
        self.setup_plan()
        c.delete_pending = True
        with self.assertRaisesRegex(ValueError, "effect_unsettled"):
            c.runtime.setup_effect("begin", "k:begin", 1100)
        self.assertTrue(
            c.objects[pod_path("unit", "engine-0")]["metadata"].get("deletionTimestamp")
        )
        self.assertFalse(c.runtime.state()["absences"])

    def test_report_age_equality_passes_and_one_ms_late_refuses(self):
        c = self.c
        c.now = 900 + DEVICE_REPORT_MAX_AGE_MS
        proof = c.runtime.device(1000000)
        c.runtime.free_device(proof, 0, "old", since_ms=0)
        c.now += 1
        with self.assertRaisesRegex(ValueError, "device_report_stale"):
            c.runtime.free_device(proof, 0, "old", since_ms=0)

    def test_live_old_uid_on_another_device_still_refuses(self):
        self.report(processes=[{"device_id": "other-device", "pod_uid": "old"}])
        proof = self.c.runtime.device(1000000)
        with self.assertRaisesRegex(ValueError, "device_process_live"):
            self.c.runtime.free_device(proof, 0, "old")

    def test_old_uid_allocation_on_another_device_refuses(self):
        self.report(allocations=[{"device_id": "other-device", "pod_uid": "old"}])
        proof = self.c.runtime.device(1000000)
        with self.assertRaisesRegex(ValueError, "device_still_allocated"):
            self.c.runtime.free_device(proof, 0, "old")

    def test_cold_report_must_follow_begin_settlement_not_only_absence(self):
        c = self.c
        self.setup_plan()
        body = copy.deepcopy(c.objects[c.inputs["device"]["0"]["report_path"]])
        for field in ("uid", "resourceVersion"):
            body["metadata"].pop(field)
        c.inputs["setup"]["steps"]["begin"]["actions"].append(
            self.template(
                "PUT",
                {"role": "object", "name": "report0"},
                {"from": "object", "name": "report0"},
                body,
            )
        )

        def tick(method, path, value):
            if method == "PUT":
                c.now = 2000

        c.after_write = tick
        c.runtime.setup_effect("begin", "k:begin", 1000000)
        self.report(observation_ms=[1500, 1501])
        c.now = 2100
        with self.assertRaisesRegex(ValueError, "device_before_absence"):
            c.runtime.setup_effect("cold", "k:cold", 2601)
        self.assertEqual(c.runtime.state()["setup_results"]["begin"]["settled_ms"], 2000)

    def test_recorded_target_uid_change_refuses_before_sending(self):
        c = self.c
        self.through_cold()
        c.objects[pod_path("unit", "engine-0")]["metadata"]["uid"] = "foreign"
        before = len(c.writes)
        with self.assertRaisesRegex(ValueError, "target_uid"):
            c.runtime.setup_effect("stop_cold_and_drain", "k:stop", 1000000)
        self.assertEqual(len(c.writes), before)

    def test_lost_delete_reply_reopens_and_reads_without_resending(self):
        c = self.c
        self.through_cold()
        c.drop_write = True

        def lose_read(method, path, value):
            c.drop = True
            c.after_write = None

        c.after_write = lose_read
        with self.assertRaises(OSError):
            c.runtime.setup_effect("stop_cold_and_drain", "k:stop", 1000000)
        before = len(c.writes)
        c.runtime = c.open()
        c.runtime.setup_effect("stop_cold_and_drain", "k:stop", 1000000)
        self.assertEqual(len(c.writes), before)
        self.assertIsNone(c.runtime.state()["writes"]["k:stop:0"]["result"]["observed"])

    def test_campaign_deletes_current_admitted_replacement(self):
        from inference_platform.inf037b_eks_cluster import ClusterPorts

        c = self.c
        c.call("campaign_capture_runtime")
        c.objects[pod_path("unit", "engine-0")]["metadata"]["uid"] = "replacement"
        c.campaign.rows("kubernetes").row(
            "kubernetes",
            "kubernetes",
            c.campaign.boot,
            "pod_created",
            {"pod_uid": "replacement", "slot": 0, "node_pseudonym": "node0"},
        )
        c.inputs["campaign_actions"]["attempt:1"]["effects"] = [
            self.template(
                "DELETE", {"role": "slot_pod", "slot": 0}, {"from": "admitted_slot", "slot": 0}
            )
        ]
        actions = ClusterPorts(c.factory).actions(
            "attempt", c.campaign, 1000000, c.context, Mock(), reset=None
        )
        actions["kubernetes"]()
        self.assertEqual(
            c.writes[-1][2]["preconditions"], {"uid": "replacement", "resourceVersion": "1"}
        )
        self.assertIsNone(
            c.runtime.read(pod_path("unit", "engine-0"), 1000000, absent=True)["value"]
        )

    def test_declared_data_must_actually_land(self):
        c = self.c
        path = c.inputs["device"]["0"]["report_path"]
        body = copy.deepcopy(c.objects[path])
        body["data"]["x"] = "desired"

        def change(method, path, value):
            value["data"]["x"] = "other"

        c.after_write = change
        with self.assertRaisesRegex(ValueError, "effect_object_join"):
            c.runtime.write("data", "PUT", path, body, 1000000)

    def test_delete_same_uid_without_deletion_marker_is_unsettled(self):
        c = self.c
        c.ignore_delete = True
        path = pod_path("unit", "engine-0")
        with self.assertRaisesRegex(ValueError, "effect_unsettled"):
            c.runtime.write(
                "not-deleted", "DELETE", path, {"preconditions": {"uid": "engine-uid0"}}, 1000000
            )

    def test_put_readback_uid_must_match(self):
        c = self.c
        path = c.inputs["device"]["0"]["report_path"]
        body = copy.deepcopy(c.objects[path])
        c.after_write = lambda method, path, value: value["metadata"].update(uid="foreign")
        with self.assertRaisesRegex(ValueError, "effect_uid"):
            c.runtime.write("uid", "PUT", path, body, 1000000)

    def test_changed_body_on_restart_refuses(self):
        c = self.c
        path = c.inputs["device"]["0"]["report_path"]
        body = copy.deepcopy(c.objects[path])
        c.runtime.write("body", "PUT", path, body, 1000000)
        body["data"]["x"] = "changed"
        with self.assertRaisesRegex(ValueError, "effect_body"):
            c.open().write("body", "PUT", path, body, 1000000)

    def test_post_existing_target_refuses_before_sending(self):
        c = self.c
        path = c.inputs["device"]["0"]["report_path"]
        before = len(c.writes)
        with self.assertRaisesRegex(ValueError, "create_target_exists"):
            c.runtime.write("exists", "POST", path, copy.deepcopy(c.objects[path]), 1000000)
        self.assertEqual(len(c.writes), before)

    def test_live_process_on_device_refuses(self):
        self.report(processes=[{"device_id": "gpu0", "pod_uid": "other"}])
        proof = self.c.runtime.device(1000000)
        with self.assertRaisesRegex(ValueError, "device_process_live"):
            self.c.runtime.free_device(proof, 0, "old")

    def test_future_device_observation_refuses(self):
        self.report(observation_ms=[1001, 1002])
        with self.assertRaisesRegex(ValueError, "device_clock"):
            self.c.runtime.device(1000000)

    def test_device_producer_cannot_be_the_released_pod(self):
        proof = self.c.runtime.device(1000000)
        with self.assertRaisesRegex(ValueError, "device_not_independent"):
            self.c.runtime.free_device(proof, 0, "agent-uid0")

    def test_device_producer_node_must_match(self):
        c = self.c
        path = c.inputs["device"]["0"]["producer_pod_path"]
        c.objects[path]["spec"]["nodeName"] = "foreign"
        with self.assertRaisesRegex(ValueError, "device_producer_node"):
            c.runtime.device(1000000)

    def test_setup_step_order_is_fixed(self):
        with self.assertRaisesRegex(ValueError, "setup_sequence"):
            self.c.runtime.setup_effect("cold", "k:cold", 1000000)

    def test_settlement_cannot_request_a_blind_retry(self):
        c = self.c
        with self.assertRaisesRegex(ValueError, "no_blind_retry"):
            ClusterEffectAuthority(c.runtime).call(
                "intent.settle",
                "k",
                1,
                {
                    "retry": True,
                    "operation": "eks.setup.begin",
                    "body": {"binding": c.binding, "pins": c.pins, "stop_ms": 1000000},
                },
            )

    def test_slot_pod_session_must_match(self):
        c = self.c
        c.objects[pod_path("unit", "engine-0")]["metadata"]["labels"]["inf037b-session"] = "foreign"
        with self.assertRaisesRegex(ValueError, "pod_session"):
            c.runtime.snapshot(1000000)

    def test_release_allocation_lag_clears_within_bound(self):
        c = self.c
        cold = self.through_cold()
        c.now = 400000
        c.runtime.setup_effect("stop_cold_and_drain", "k:stop", 1000000)
        self.report(
            observation_ms=[400000, 400001],
            allocations=[{"device_id": "gpu0", "pod_uid": cold["uid"]}],
        )
        calls = []

        def wait(seconds):
            calls.append(seconds)
            c.wait(seconds)
            self.report(observation_ms=[c.now - 1, c.now], allocations=[])

        c.runtime.wait = wait
        c.now = 400002
        result = c.runtime.setup_effect("node_cached", "k:cached", 1000000)
        self.assertEqual(len(calls), 1)
        self.assertGreaterEqual(result["device_release"]["observation_ms"][0], 400002)

    def test_unnamed_device_process_lag_polls_then_clears(self):
        c = self.c
        c.now = 2000
        waits = []
        self.report(observation_ms=[2000, 2000], processes=[{"device_id": "gpu0"}])

        def wait(seconds):
            waits.append(seconds)
            c.wait(seconds)
            self.report(observation_ms=[c.now, c.now], processes=[])

        c.runtime.wait = wait
        c.runtime.admission_device(0, "old", 2000, 1000000)
        self.assertEqual(len(waits), 1)

    def test_release_lag_stops_at_implementation_bound_with_last_reason(self):
        c = self.c
        c.now = 2000
        start = c.now
        waits = []
        self.report(
            observation_ms=[2000, 2000], processes=[{"device_id": "gpu0", "pod_uid": "old"}]
        )

        def wait(seconds):
            # Delayed scheduler wakeups exercise the full real bound without
            # producing thirty copies of the same local API snapshot.
            waits.append(seconds)
            c.now += DEVICE_REPORT_MAX_AGE_MS // 2
            self.report(observation_ms=[c.now, c.now])

        c.runtime.wait = wait
        with self.assertRaisesRegex(ValueError, "cluster:device_process_live"):
            c.runtime.admission_device(0, "old", 2000, start + DEVICE_REPORT_MAX_AGE_MS + 1000)
        self.assertEqual(c.now, start + DEVICE_REPORT_MAX_AGE_MS)
        self.assertEqual(waits, [0.5, 0.5])

    def test_foreign_live_uid_refuses_without_waiting(self):
        c = self.c
        c.now = 2000
        waits = []
        self.report(
            observation_ms=[2000, 2000], allocations=[{"device_id": "gpu0", "pod_uid": "foreign"}]
        )

        def wait(seconds):
            waits.append(seconds)
            c.wait(seconds)

        c.runtime.wait = wait
        with self.assertRaisesRegex(ValueError, "cluster:device_still_allocated"):
            c.runtime.admission_device(0, "old", 2000, 3001)
        self.assertEqual(waits, [])

    def test_foreign_process_does_not_hide_behind_old_allocation_lag(self):
        c = self.c
        c.now = 2000
        waits = []
        self.report(
            observation_ms=[2000, 2000],
            allocations=[{"device_id": "gpu0", "pod_uid": "old"}],
            processes=[{"device_id": "gpu0", "pod_uid": "foreign"}],
        )

        def wait(seconds):
            waits.append(seconds)
            c.wait(seconds)

        c.runtime.wait = wait
        with self.assertRaisesRegex(ValueError, "cluster:device_process_live"):
            c.runtime.admission_device(0, "old", 2000, 3001)
        self.assertEqual(waits, [])

    def test_cached_other_slot_refuses_before_any_api_read_or_write(self):
        c = self.c
        self.through_cold()
        c.runtime.setup_effect("stop_cold_and_drain", "k:stop", 1000000)
        c.inputs["setup"]["steps"]["node_cached"]["result_slot"] = 1
        before = (len(c.gets), len(c.writes))
        with self.assertRaisesRegex(ValueError, "cluster:cached_slot"):
            c.runtime.setup_effect("node_cached", "k:cached", 1000000)
        self.assertEqual((len(c.gets), len(c.writes)), before)

    def test_cached_other_node_refuses_before_any_api_read_or_write(self):
        c = self.c
        self.through_cold()
        c.runtime.setup_effect("stop_cold_and_drain", "k:stop", 1000000)
        c.runtime.config["nodes"]["0"]["uid"] = "foreign-node"
        before = (len(c.gets), len(c.writes))
        with self.assertRaisesRegex(ValueError, "cluster:cached_node"):
            c.runtime.setup_effect("node_cached", "k:cached", 1000000)
        self.assertEqual((len(c.gets), len(c.writes)), before)

    def test_cached_absence_read_uses_cold_recorded_path(self):
        c = self.c
        cold = self.through_cold()
        c.runtime.setup_effect("stop_cold_and_drain", "k:stop", 1000000)
        c.now = 400002
        self.report(observation_ms=[400001, 400002])
        from unittest.mock import patch

        with patch.object(c.runtime, "gone", wraps=c.runtime.gone) as gone:
            c.runtime.setup_effect("node_cached", "k:cached", 1000000)
        self.assertEqual(gone.call_args.args[:2], (cold["path"], cold["uid"]))


class StoreAckTests(unittest.TestCase):
    def test_placement_requires_both_store_acknowledgements(self):
        c = placement_fixture.PlacementBindingTests(methodName="runTest")
        c.setUp()
        self.addCleanup(c.doCleanups)
        original = c.runtime.repository.publish

        def omit(key, artifacts, stop):
            receipt = original(key, artifacts, stop)
            receipt["acknowledgements"].pop("s3")
            return receipt

        c.runtime.repository.publish = omit
        with self.assertRaisesRegex(ValueError, "both_store_ack"):
            c.runtime.run(1000000)
