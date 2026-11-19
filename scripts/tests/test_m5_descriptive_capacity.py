"""Capacity ordering, cancellation and budgets without making any reservation."""

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from inference_platform.m5_descriptive_operator import session_timing
from m5_descriptive_capacity import EKS_ZONES, select_capacity, zone_pairs
from m5_descriptive_diagnostics import write_cost
from m5_descriptive_eks import EKSports


def offerings():
    return {
        "InstanceTypeOfferings": [
            {"InstanceType": kind, "Location": "us-east-1" + suffix}
            for kind in ("g6.xlarge", "c6i.2xlarge")
            for suffix in "abcdef"
        ]
    }


class Clock:
    def __init__(self):
        self.value, self.sleeps = 0.0, []

    def now(self):
        return self.value

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.value += seconds


class CapacityTests(unittest.TestCase):
    def fixture(self, root, *, succeeds_at=None, budget=400):
        clock = Clock()
        timing = session_timing(640, 138)
        timing["capacity_wait_budget_seconds"] = budget
        pairs = zone_pairs(offerings())[:2]
        ports = EKSports.__new__(EKSports)
        ports.directory = root
        ports.deadline = 18000
        ports.manifest = {
            "timing": timing,
            "alternatives": [{**p, "directory": "zone-" + p["zone"]} for p in pairs],
            "account": "fixture",
            "capacity_group_arn": "fixture-group",
        }
        ports.capacity = SimpleNamespace(inputs={}, directory=root / "capacity")
        ports.make_targeted = Mock()
        ports.sdk = Mock()
        ports.sdk.client.return_value.can_paginate.return_value = False
        ports.sdk.client.return_value.list_group_resources.return_value = {
            "ResourceIdentifiers": [
                {
                    "ResourceArn": "arn:aws:ec2:us-east-1:fixture:capacity-reservation/cr-fixture"
                }
            ]
        }
        events = []

        def reserve(deadline):
            self.assertGreater(deadline, clock.value)
            clock.value += 3
            events.append(
                ("probe", ports.capacity.inputs["availability_zone"], clock.value)
            )
            (
                ports.capacity.directory / "capacity-reservation-create.stdout"
            ).write_text("{}")
            n = sum(e[0] == "probe" for e in events)
            if n == succeeds_at:
                return {"result": "success", "capacity_reservation_id": "cr-fixture"}
            return {
                "result": "capacity_unavailable",
                "error_code": "InsufficientInstanceCapacity",
            }

        def cancel(deadline):
            self.assertGreater(deadline, clock.value)
            events.append(
                ("cancel", ports.capacity.inputs["availability_zone"], clock.value)
            )
            clock.value += 2
            (
                ports.capacity.directory
                / "capacity-reservation-session-inventory.stdout"
            ).write_text('{"CapacityReservations":[]}')
            return True

        ports.capacity.reserve_capacity = reserve
        ports.capacity.cancel_session_capacity_reservations = Mock(side_effect=cancel)
        return ports, clock, events

    def test_offerings_intersect_eks_zones_in_stable_order_with_distinct_cpu_zone(self):
        pairs = zone_pairs(offerings())
        self.assertEqual([p["zone"] for p in pairs], list(EKS_ZONES))
        self.assertTrue(all(p["zone"] != p["control_plane_zone"] for p in pairs))
        value = offerings()
        value["InstanceTypeOfferings"] = [
            r for r in value["InstanceTypeOfferings"] if r["Location"] != "us-east-1b"
        ]
        self.assertNotIn("us-east-1b", [p["zone"] for p in zone_pairs(value)])
        for rows in (
            [{"InstanceType": "g6.xlarge", "Location": "us-east-1e"}],
            [{"InstanceType": "g6.xlarge", "Location": "us-west-2a"}],
            [
                {"InstanceType": "g6.xlarge", "Location": "us-east-1a"},
                {"InstanceType": "c6i.2xlarge", "Location": "us-east-1a"},
            ],
        ):
            with self.assertRaisesRegex(ValueError, "quota_or_offering"):
                zone_pairs({"InstanceTypeOfferings": rows})

    def test_budget_reserves_observed_apply_margin_without_reducing_named_budgets(self):
        t = session_timing(640, 138)
        self.assertEqual(t["apply_through_staging_reserve_seconds"], 3223)
        self.assertEqual(t["capacity_wait_budget_seconds"], 2743)
        self.assertEqual(t["remaining_infrastructure_seconds"], 3223)
        self.assertEqual(t["minimum_workload_seconds"], 4400)
        self.assertEqual(t["retrieval_reserve_seconds"], 4416)
        self.assertEqual(t["cleanup_reserve_seconds"], 1800)
        self.assertEqual(t["initial_startup_budget_seconds"], 1280)
        self.assertEqual(t["source_upload_budget_seconds"], 138)
        self.assertEqual(
            sum(
                t[k]
                for k in (
                    "minimum_workload_seconds",
                    "retrieval_reserve_seconds",
                    "cleanup_reserve_seconds",
                    "initial_startup_budget_seconds",
                    "source_upload_budget_seconds",
                    "capacity_wait_budget_seconds",
                    "remaining_infrastructure_seconds",
                )
            ),
            18000,
        )
        shortened = session_timing(640, 2870)
        self.assertEqual(shortened["capacity_wait_budget_seconds"], 11)
        self.assertEqual(shortened["minimum_workload_seconds"], 4400)

    def test_cycles_preserve_order_minimum_spacing_cancel_before_next_and_readback_hashes(
        self,
    ):
        with tempfile.TemporaryDirectory() as tmp:
            ports, clock, events = self.fixture(Path(tmp), succeeds_at=5)
            selected = select_capacity(
                ports, clock=clock.now, sleep=clock.sleep, epoch=clock.now
            )
            self.assertEqual(selected["zone"], "us-east-1a")
            self.assertEqual(
                [e[1] for e in events if e[0] == "probe"],
                ["us-east-1a", "us-east-1b", "us-east-1a", "us-east-1b", "us-east-1a"],
            )
            self.assertEqual(
                [e[0] for e in events], ["probe", "cancel"] * 4 + ["probe"]
            )
            self.assertEqual(clock.sleeps, [60, 60])
            ports.make_targeted.assert_called_once()
            ports.sdk.client.return_value.group_resources.assert_called_once()
            record = json.loads((Path(tmp) / "capacity-wait.json").read_bytes())
            self.assertEqual(record["status"], "SELECTED")
            self.assertEqual([p["cycle"] for p in record["probes"]], [1, 1, 2, 2, 3])
            for probe in record["probes"][:-1]:
                self.assertTrue(probe["cleanup_verified"])
                self.assertEqual(probe["error_code"], "InsufficientInstanceCapacity")
                self.assertIn(
                    "capacity-reservation-session-inventory.stdout",
                    probe["readback_sha256"],
                )
                self.assertIn("at_utc", probe)

    def test_exhaustion_uses_same_named_halt_and_cannot_spend_other_reserves(self):
        with tempfile.TemporaryDirectory() as tmp:
            ports, clock, events = self.fixture(Path(tmp), budget=200)
            with self.assertRaisesRegex(
                ValueError, "capacity_unavailable_all_reviewed_zones"
            ):
                select_capacity(
                    ports, clock=clock.now, sleep=clock.sleep, epoch=clock.now
                )
            self.assertLessEqual(clock.value, 200)
            self.assertEqual(events[-1][0], "cancel")
            record = json.loads((Path(tmp) / "capacity-wait.json").read_bytes())
            self.assertEqual(record["status"], "HALTED")
            self.assertTrue(all(p["cleanup_verified"] for p in record["probes"]))
            ports.make_targeted.assert_not_called()
        with tempfile.TemporaryDirectory() as tmp:
            ports, clock, events = self.fixture(Path(tmp))
            # Bootstrap consumed all the capacity allowance. The other reserves
            # remain intact, so not even one probe is allowed.
            ports.deadline = 15027
            with self.assertRaisesRegex(
                ValueError, "capacity_unavailable_all_reviewed_zones"
            ):
                select_capacity(ports, clock=clock.now, sleep=clock.sleep)
            self.assertEqual(events, [])

    def test_unverified_cancel_or_probe_error_stops_before_any_more_probes(self):
        for failure in ("cleanup", "probe", "target"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                ports, clock, events = self.fixture(
                    Path(tmp), succeeds_at=1 if failure == "target" else None
                )
                if failure == "cleanup":
                    ports.capacity.cancel_session_capacity_reservations.side_effect = (
                        lambda _end: False
                    )
                if failure == "probe":
                    ports.capacity.reserve_capacity = Mock(
                        side_effect=RuntimeError("probe transport")
                    )
                if failure == "target":
                    ports.make_targeted.side_effect = RuntimeError("target readback")
                with self.assertRaises(RuntimeError):
                    select_capacity(ports, clock=clock.now, sleep=clock.sleep)
                ports.capacity.cancel_session_capacity_reservations.assert_called_once()
                self.assertLessEqual(sum(e[0] == "probe" for e in events), 1)

    def test_real_provision_applies_only_the_one_selected_zone_after_cycling(self):
        with tempfile.TemporaryDirectory() as tmp:
            ports, clock, events = self.fixture(Path(tmp), succeeds_at=3)
            ports.started, ports.end, ports.profile = 1000, 19000, "fixture"
            ports.manifest.update(
                descriptive={},
                host_manifest={},
                operator_tools={"terraform": {"path": "fixture"}},
            )
            (Path(tmp) / "manifest.json").write_text(json.dumps(ports.manifest))
            ports.tf, ports.remote = Mock(), Mock(return_value={"complete": True})
            output = {
                "repository_url": {"value": "registry.invalid"},
                "operator_instance": {"value": "fixture-host"},
            }
            with (
                patch("m5_descriptive_eks.arm", return_value={}),
                patch("m5_descriptive_eks.arming_witness", return_value={}),
                patch(
                    "m5_descriptive_eks.select_capacity",
                    side_effect=lambda p: select_capacity(
                        p, clock=clock.now, sleep=clock.sleep, epoch=clock.now
                    ),
                ),
                patch(
                    "m5_descriptive_eks.subprocess.check_output",
                    return_value=json.dumps(output).encode(),
                ),
                patch("m5_descriptive_eks.Ports"),
            ):
                result = ports.provision()
            self.assertEqual(result["capacity_zone"], "us-east-1a")
            self.assertEqual(
                [c.args[0].name for c in ports.tf.call_args_list],
                ["bootstrap", "backstop", "zone-us-east-1a"],
            )
            self.assertEqual(sum(e[0] == "probe" for e in events), 3)

    def test_cost_separates_wait_from_other_elapsed_without_changing_total_formula(
        self,
    ):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "manifest.json").write_text(
                json.dumps(
                    {
                        "forecast_basis": {
                            "hourly_usd": 2,
                            "fixed_other_usd": 10,
                            "margin": 1.25,
                        },
                        "host_manifest": {"prior_spend_usd": 60},
                    }
                )
            )
            (root / "consumed.json").write_text('{"started_epoch":0}')
            (root / "capacity-wait.json").write_text('{"elapsed_s":120}')
            result = write_cost(root, now=300)
            self.assertEqual(result["capacity_wait_elapsed_s"], 120)
            self.assertEqual(result["other_elapsed_s"], 180)
            self.assertEqual(result["elapsed_s"], 300)
            self.assertEqual(result["task_cost_estimate_usd"], 12.71)
