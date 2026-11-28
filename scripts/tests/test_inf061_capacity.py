"""Run the real native hunter on fake EC2 transport and a deterministic clock."""

import json
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import inf061_capacity as capacity
import inf060_probe_spec as spec


class FakeClock:
    def __init__(self):
        self.seconds = 15000

    def now(self):
        return self.seconds

    def sleep(self, seconds):
        self.seconds += seconds


class EC2:
    def __init__(self, clock, session, *, leak=False):
        self.clock = clock
        self.session = session
        self.leak = leak
        self.probes = []
        self.rows = {}
        self.canceled = []

    def attach(self, ports):
        self.ports = ports
        return patch.object(ports, "aws", side_effect=self.aws)

    def aws(self, service, name, args, deadline, filename):
        self.assert_deadline(deadline)
        if name == "get-caller-identity":
            return {"Account": "123456789012"}
        if name == "describe-capacity-reservations":
            ids = "--capacity-reservation-ids"
            rows = (
                [self.rows.get(args[args.index(ids) + 1])]
                if ids in args
                else list(self.rows.values())
            )
            return {
                "CapacityReservations": [
                    row
                    for row in rows
                    if row
                    and (
                        row["State"] == "active"
                        or ids in args
                        or "Name=state,Values=active,pending" not in args
                    )
                ]
            }
        if name == "create-capacity-reservation":
            self.probes.append(
                (self.clock.now(), args[args.index("--availability-zone") + 1])
            )
            assert args[args.index("--instance-count") + 1] == "1"
            assert args[args.index("--instance-match-criteria") + 1] == "open"
            ref = f"cr-{len(self.probes):017x}"
            row = {
                "CapacityReservationId": ref,
                "InstanceType": "g6.xlarge",
                "InstanceMatchCriteria": "open",
                "Tenancy": "default",
                "InstancePlatform": "Linux/UNIX",
                "AvailabilityZone": self.probes[-1][1],
                "State": "active",
                "TotalInstanceCount": 1,
                "AvailableInstanceCount": 1,
                "Tags": [{"Key": "Session", "Value": self.session}],
            }
            if len(self.probes) <= 10:
                if self.leak and not self.rows:
                    self.rows[ref] = row
                (self.ports.directory / (filename + ".stderr")).write_text(
                    "An error occurred (InsufficientInstanceCapacity)",
                    encoding="utf-8",
                )
                raise RuntimeError("EC2 create refused")
            self.rows[ref] = row
            return {"CapacityReservation": row}
        if name == "cancel-capacity-reservation":
            ref = args[args.index("--capacity-reservation-id") + 1]
            self.rows[ref]["State"] = "cancelled"
            self.canceled.append(ref)
            return {"Return": True}
        if name == "modify-capacity-reservation":
            ref = args[args.index("--capacity-reservation-id") + 1]
            self.rows[ref]["EndDate"] = args[args.index("--end-date") + 1]
            return {"Return": True}
        raise AssertionError((service, name))

    def assert_deadline(self, deadline):
        assert deadline > self.clock.now()


class OpenGuardTests(unittest.TestCase):
    operator = "i-" + "1" * 17
    launched = "i-" + "2" * 17
    foreign = "i-" + "3" * 17
    session = "dec077-inf060-t2r461"

    def setUp(self):
        self.selection = {"reservation_id": "cr-fixture", "zone": "us-east-1a"}
        self.slot = {
            "CapacityReservationId": "cr-fixture",
            "AvailabilityZone": "us-east-1a",
            "InstanceMatchCriteria": "open",
            "State": "active",
            "TotalInstanceCount": 1,
            "AvailableInstanceCount": 1,
            "Tags": [{"Key": "Session", "Value": self.session}],
        }
        self.slots = [self.slot]
        self.instances = [{"InstanceId": self.operator}]
        self.ports = SimpleNamespace(
            manifest={
                "session": self.session,
                "operator_host": {"session": "operator-fixture"},
            },
            capacity_selection=self.selection,
            aws=self.aws,
            apply=Mock(side_effect=self.launch),
            host=None,
        )

    def aws(self, _svc, operation, _args, *, deadline):
        if operation == "get-caller-identity":
            account = "123456789012"
            return {
                "Account": account,
                "Arn": f"arn:aws:sts::{account}:assumed-role/operator-fixture-cpu/{self.operator}",
            }
        if operation == "describe-capacity-reservations":
            return {"CapacityReservations": self.slots}
        if operation == "describe-instances":
            return {"Reservations": [{"Instances": self.instances}]}
        raise AssertionError(operation)

    def launch(self, _end):
        self.ports.host = self.launched
        self.slot["AvailableInstanceCount"] = 0
        self.instances.append(
            {
                "InstanceId": self.launched,
                "CapacityReservationId": "cr-fixture",
                "Placement": {"AvailabilityZone": "us-east-1a"},
                "Tags": [{"Key": "Session", "Value": self.session}],
            }
        )

    def require_pre_apply_refusal(self, reason):
        from inf060_probe_operator import apply_open_capacity

        with self.assertRaisesRegex(ValueError, reason):
            apply_open_capacity(self.ports, 200)
        self.ports.apply.assert_not_called()

    def test_second_reservation_refuses_before_apply(self):
        self.slots.append({**self.slot, "CapacityReservationId": "cr-foreign"})
        self.require_pre_apply_refusal("open_capacity_regional_reservation_count")

    def test_foreign_instance_refuses_before_apply_and_kills_skipped_guard_mutant(self):
        self.instances.append({"InstanceId": self.foreign})
        self.require_pre_apply_refusal("open_capacity_foreign_instance")
        with (
            patch.object(capacity, "open_capacity_guard", return_value=None),
            self.assertRaises(self.failureException),
        ):
            self.require_pre_apply_refusal("open_capacity_foreign_instance")
        self.ports.apply.assert_called_once()

    def test_missing_association_polls_in_place_without_a_second_apply(self):
        clock = FakeClock()
        reads = []

        def invoke(service, operation, args):
            reads.append(operation)
            return self.aws(service, operation, args, deadline=clock.now() + 20)

        self.ports.apply(200)
        self.instances[-1].pop("CapacityReservationId")
        self.slot["AvailableInstanceCount"] = 1

        def publish(delay):
            clock.sleep(delay)
            self.instances[-1]["CapacityReservationId"] = self.selection[
                "reservation_id"
            ]
            self.slot["AvailableInstanceCount"] = 0

        attempts = capacity.verify_open_launch(
            invoke,
            self.session,
            self.selection,
            operator_id=self.operator,
            launched_id=self.launched,
            end=clock.now() + 8,
            clock=clock.now,
            sleep=publish,
        )
        self.assertEqual(attempts, 2)
        self.assertEqual(
            reads, ["describe-capacity-reservations", "describe-instances"] * 2
        )
        self.ports.apply.assert_called_once()

    def test_missing_association_expires_without_relaxing_the_gate(self):
        clock = FakeClock()
        self.ports.apply(200)
        self.instances[-1].pop("CapacityReservationId")

        def invoke(service, operation, args):
            return self.aws(service, operation, args, deadline=clock.now() + 20)

        end = clock.now() + 3
        with self.assertRaisesRegex(TimeoutError, "open_capacity_association_pending"):
            capacity.verify_open_launch(
                invoke,
                self.session,
                self.selection,
                operator_id=self.operator,
                launched_id=self.launched,
                end=end,
                clock=clock.now,
                sleep=clock.sleep,
            )
        self.assertEqual(clock.now(), end)
        self.ports.apply.assert_called_once()

    def test_post_launch_rejects_foreign_instance_or_wrong_binding(self):
        from inf060_probe_operator import apply_open_capacity

        real = self.launch

        for flaw, reason in (
            ("foreign", "open_capacity_foreign_instance"),
            ("binding", "capacity_instance_readback"),
            ("none", None),
        ):
            self.setUp()

            def launch(end):
                real(end)
                if flaw == "foreign":
                    self.instances.append({"InstanceId": self.foreign})
                if flaw == "binding":
                    self.instances[-1]["CapacityReservationId"] = "cr-other"

            self.ports.apply.side_effect = launch
            if reason:
                with self.assertRaisesRegex(ValueError, reason):
                    apply_open_capacity(self.ports, 200)
            else:
                apply_open_capacity(self.ports, 200)
            self.ports.apply.assert_called_once()


class HunterTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)
        self.clock = FakeClock()
        self.session = "dec077-inf060-t2r457"
        plans = {}
        for zone, name in capacity.ROOTS.items():
            path = self.root / name / "create.tfplan"
            path.parent.mkdir(parents=True)
            path.write_bytes(zone.encode())
            plans[zone] = {"create_sha256": spec.facts(path)["sha256"]}
        self.manifest = {
            "session": self.session,
            "deadline_seconds": capacity.GPU_SECONDS,
            capacity.KEY: {
                "plans": plans,
            },
        }
        self.hunter = capacity.Hunter(
            self.root,
            self.manifest,
            clock=self.clock.now,
            epoch=lambda: 1750000000 + self.clock.now(),
        )
        self.hunter.capacity.now = self.clock.now

    def test_two_cycles_refuse_then_select_and_cancel(self):
        provider = EC2(self.clock, self.session, leak=True)
        with provider.attach(self.hunter.capacity):
            chosen = self.hunter.select(sleep=self.clock.sleep)
            self.assertEqual(len(provider.probes), 11)
            self.assertIn("cr-00000000000000001", provider.canceled)
            zones = [zone for _, zone in provider.probes]
            self.assertEqual(
                zones, [*capacity.ZONES, *capacity.ZONES, capacity.ZONES[0]]
            )
            self.assertEqual(provider.probes[5][0] - provider.probes[4][0], 120)
            self.assertEqual(
                chosen["hold_end_epoch"], int(chosen["selected_epoch"]) + 45120
            )
            checked, root = capacity.selected_plan(self.root, self.manifest)
            self.assertEqual(
                (checked, root), (chosen, self.root / capacity.ROOTS[zones[-1]])
            )
            ref = chosen["reservation_id"]
            self.assertTrue(
                self.hunter.capacity.cancel_session_capacity_reservations(
                    self.clock.now() + 30
                )
            )
            self.assertEqual(provider.rows[ref]["State"], "cancelled")
            recorded = json.loads((self.root / "capacity-wait.json").read_bytes())
            self.assertTrue(
                all(row["cleanup_verified"] for row in recorded["probes"][:-1])
            )

    def test_missing_cancel_stops_before_next_ec2_create(self):
        provider = EC2(self.clock, self.session, leak=True)
        with (
            provider.attach(self.hunter.capacity),
            patch.object(
                self.hunter.capacity,
                "cancel_session_capacity_reservations",
                return_value=True,
            ),
            self.assertRaisesRegex(ValueError, "capacity_regional_not_empty"),
        ):
            self.hunter.select(sleep=self.clock.sleep)
        self.assertEqual(len(provider.probes), 1)

    def test_wrong_zone_plan_refuses_before_apply(self):
        provider = EC2(self.clock, self.session)
        with provider.attach(self.hunter.capacity):
            result = self.hunter.select(sleep=self.clock.sleep)
        spec.save(self.root / capacity.STATE, {**result, "zone": capacity.ZONES[1]})
        with self.assertRaisesRegex(ValueError, "capacity_selected_plan"):
            capacity.selected_plan(self.root, self.manifest)

    def test_capacity_timing_keeps_the_reservation_epoch(self):
        provider = EC2(self.clock, self.session)
        with provider.attach(self.hunter.capacity):
            row = self.hunter.select(sleep=self.clock.sleep)
        self.assertEqual(
            datetime.fromtimestamp(row["hold_end_epoch"], UTC).timestamp(),
            int(row["selected_epoch"]) + capacity.GPU_SECONDS,
        )

    def test_operator_entrypoint_selects_before_starting_supervisor(self):
        from inf060_remote_service import run

        provider = EC2(self.clock, self.session)
        plan = {
            **self.manifest,
            "source_commit": "1" * 40,
            "schema": "inf061-native-dec108-v1",
            "artifacts": {
                key: {} for key in ("tools.json", "engine.json", spec.LOG_CONFIG)
            },
        }
        spec.save(self.root / "manifest.json", plan)
        called = []
        zero = {
            key: 0
            for key in (
                "active_instances",
                "volumes",
                "interfaces",
                "vpcs",
                "subnets",
                "security_groups",
                "route_tables",
                "gateways",
                "addresses",
                "roles",
                "profiles",
                "terraform_resources",
                "launch_templates",
                "session_reservations",
                "untagged_regional_reservations",
                "foreign_regional_reservations",
            )
        } | {"empty": True}

        def controller(argv, check):
            # Simulate only the supervisor subprocess boundary in this unit.
            # The separate native rehearsal exercises the real workload.
            self.assertIn("launch", argv)
            state, _ = capacity.selected_plan(self.root, plan)
            self.assertEqual(len(provider.probes), 11)
            self.assertTrue(
                self.hunter.capacity.cancel_session_capacity_reservations(
                    self.clock.now() + 30
                )
            )
            self.assertEqual(
                provider.rows[state["reservation_id"]]["State"], "cancelled"
            )
            called.append(state)
            attempt = self.root / "supervisor/attempt-fixture"
            attempt.mkdir(parents=True)
            spec.save(
                attempt / "deadline.json",
                {
                    "complete": True,
                    "stages": {},
                    "elapsed_seconds": 1,
                    "t0_epoch": state["selected_epoch"],
                    "deadline_epoch": state["hold_end_epoch"],
                },
            )
            spec.save(attempt / "probe-cleanup.json", {"destroy_completed": True})
            spec.save(attempt / "probe-inventory.json", zero)
            return SimpleNamespace(returncode=0)

        with (
            provider.attach(self.hunter.capacity),
            patch("inf060_remote_service.remote.PACKET", str(self.root)),
            patch("inf060_remote_service.spec.verify_packet", return_value=plan),
            patch("inf060_remote_service.remote.verify"),
            patch("inf060_remote_service.verify_environment"),
            patch("inf060_remote_service.remote.import_runtime", return_value={}),
            patch("inf060_probe_operator.ProbePorts"),
            patch("inf060_probe_operator.native_preflight"),
            patch(
                "inf061_capacity.Hunter",
                return_value=SimpleNamespace(
                    select=lambda: self.hunter.select(sleep=self.clock.sleep)
                ),
            ),
            patch("inf060_remote_service.subprocess.run", side_effect=controller),
        ):
            self.assertEqual(run(), 0)
        self.assertEqual(len(called), 1)
        result = spec.load(self.root / "remote-result.json")
        self.assertEqual(result["capacity"]["probes"], 11)
        self.assertEqual(result["origin_epoch"], called[0]["selected_epoch"])
        self.assertTrue(result["destroy_completed"])
