"""Small portable joins and real HTTP access; no host durability claim."""

import copy
import os
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import test_inf037b_eks_stores as fixture
from inf037b_eks_supervisor_worker import FileJournal

from inference_platform.inf037b_archive import encode, sha
from inference_platform.inf037b_eks_execution import (
    PORTS,
    ExecutionRuntime,
    execution_port,
    join_execution,
)
from inference_platform.inf037b_resolver import SessionDeadline
from inference_platform.inf037b_transfer import S3ArchiveStore, SocketArchiveTransfer


class ExecutionTests(unittest.TestCase):
    def setUp(self):
        self.case = fixture.StoreTests(methodName="runTest")
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.root, self.binding, self.pins = self.case.root, self.case.controller, self.case.pins
        self.pins["configuration"] = "a" * 64
        self.case.binding["pins"] = copy.deepcopy(self.pins)
        self.case.journal = FileJournal(self.root / "runtime-repository", {}, initialize=True)
        self.case.repository = self.case.open()
        self.config = {
            "pins": self.pins,
            "recovery_store_binding": self.case.binding,
            "sanitizer_key_sha256": sha(b"unit-key"),
        }
        self.factory = SimpleNamespace(
            binding=self.binding,
            config=self.config,
            port=SimpleNamespace(
                deadline=lambda *a, **k: None,
                store=FileJournal(self.root / "factory-state", {}, initialize=True),
            ),
            controller=SimpleNamespace(
                backstop=SimpleNamespace(
                    authority=SimpleNamespace(identity="supervisor"),
                    confirmed=Mock(return_value=True),
                )
            ),
        )
        repo = self.case.repository
        external = S3ArchiveStore(
            Mock(),
            bucket=repo.binding["s3"]["bucket"],
            prefix=repo.binding["s3"]["prefix"],
            max_total_bytes=10000,
            max_objects=100,
        )
        repo.store_ports = {
            "recovery_store": repo.binding["recovery"]["root"],
            "s3_store": external,
        }
        self.components = {
            "repository": repo,
            "terminal_transfer": SocketArchiveTransfer(max_reconnects=1, max_reconnect_seconds=15),
        }
        boot = self.root / "boot-id"
        boot.write_text("unit-boot", encoding="ascii")
        owner = self.root / "failed-owner"
        owner.mkdir()
        (owner / "partial.bin").write_bytes(b"partial adverse evidence")
        from inference_platform.inf037b_eks_fixture import fixture_inventory

        self.catalog = {
            "binding": self.binding,
            "complete": True,
            "owners": [
                {
                    "owner_id": "probe",
                    "root": str(owner),
                    "descriptor": {
                        "closed": True,
                        "transport_clean": False,
                        "files": fixture_inventory(owner),
                    },
                }
            ],
        }
        catalog_path = self.root / "catalog.json"
        self.authoritative_catalog = copy.deepcopy(self.catalog)
        self.factory.capture_catalog = lambda: copy.deepcopy(self.authoritative_catalog)
        catalog_path.write_bytes(encode(self.catalog))
        refs = {}
        for name, value in (
            ("registration", {"registration_id": "unit"}),
            ("specs", [{"config_sha256": self.pins["configuration"]}]),
            ("sanitizer_key", b"unit-key"),
        ):
            path = self.root / name
            path.write_bytes(value if isinstance(value, bytes) else encode(value))
            refs[name] = {"path": str(path), "sha256": sha(path.read_bytes())}
        spec = {
            "generation": "g1",
            "boot_id": "unit-boot",
            "source_sha256": "f" * 64,
            "agent_sha256": "d" * 64,
            "budget": {
                "cpu_millicores": 1000,
                "nic_bytes_per_second": 10000,
                "capacity_ref": "c" * 64,
            },
            "provenance": {
                "capacity_sha256": "c" * 64,
                "agent_sha256": "d" * 64,
                "cgroup_identity": [1, 2],
                "interface_identity": [1, 3],
                "ifindex": 7,
            },
            "http": {"host": "127.0.0.1", "port": 1},
        }
        self.inputs = {
            "binding": self.binding,
            "pins": self.pins,
            "recovery_store_binding": repo.binding,
            "artifact_access_url": repo.accessor.url.geturl(),
            "recovery_supervisor": {
                "controller_host": "i-a",
                "supervisor_host": "i-b",
                "authority_id": "supervisor",
            },
            "terminal_export_transport": {
                "address": ["127.0.0.1", 1],
                "max_total_bytes": 10000,
                "max_objects": 100,
                "max_reconnects": 1,
                "max_reconnect_seconds": 15,
            },
            "campaign_archive_inputs": {
                "references": refs,
                "aggregate_parent": str(self.root / "aggregate"),
            },
            "terminal_capture_catalog": {
                "path": str(catalog_path),
                "allocated_owner_ids": ["probe"],
                "roots": {"probe": str(owner)},
            },
            "measurement_clock": {
                "boot_id_path": str(boot),
                "boot_id": "unit-boot",
                "clock_id": "measurement",
            },
            "resource_bindings": {"setup": {"measurement": spec}, "campaign": {"generator": spec}},
        }
        from inference_platform.inf037b_eks_owner_registry import AllocatedOwners

        AllocatedOwners(self.factory.port.store, self.binding).allocate(
            "probe", owner, self.binding, {}, self.root / "owner-descriptor-state"
        )
        import json
        import urllib.request

        from test_inf037b_eks_provider_client import ProviderClientTest

        from inference_platform.inf037b_eks_host_bindings import IndependentHosts

        peer = ProviderClientTest(methodName="runTest")
        peer.setUp()
        self.addCleanup(peer.doCleanups)
        peer.session_id = peer.client.session_id = self.binding["session_id"]
        peer.tag = self.binding["session_id"]
        peer.pins = self.pins

        def witness(instance, stop):
            with urllib.request.urlopen(
                f"http://127.0.0.1:{peer.server.server_port}/identity/{instance}", timeout=5
            ) as response:
                return json.load(response)

        self.components["independent_hosts"] = IndependentHosts(
            binding=self.binding,
            pins=self.pins,
            hosts={
                r: {"instance_id": i, "boot_id": peer.boots[i]}
                for r, i in (("controller", "i-a"), ("export", "i-a"), ("supervisor", "i-b"))
            },
            account_reader=peer.client,
            witness_read=witness,
        )
        self.runtime = self.open(initialize=True)
        self.config["execution_runtime"] = self.runtime

    def open(self, *, initialize=False):
        path = self.root / "execution.json"
        if initialize:
            path.write_bytes(encode(self.inputs))
        source = {"path": str(path), "sha256": sha(path.read_bytes())}
        return ExecutionRuntime(
            binding=self.binding,
            pins=self.pins,
            source=source,
            journal=FileJournal(self.root / "execution-state", {}, initialize=True),
            clock=lambda: 100,
            components=self.components,
        )

    def call(self, name, *args):
        return execution_port(self.factory, name)(*args)

    def test_repository_joins_real_access_component_and_pinned_locations(self):
        repo = self.call("4d_recovery_store_runtime", 10000)["repository"]
        receipt = repo.publish("one", self.case.artifacts, 10000)
        self.assertEqual(repo.access(receipt, 10000)["store_readbacks"].keys(), {"recovery", "s3"})

    def test_repository_bucket_mismatch_refuses(self):
        self.components["repository"].store_ports["s3_store"].bucket = "foreign"
        with self.assertRaisesRegex(ValueError, "s3_location"):
            self.call("4d_recovery_store_runtime", 10000)

    def test_repository_lost_ack_and_restart_reuses_persisted_receipt(self):
        repo = self.call("4d_recovery_store_runtime", 10000)["repository"]
        repo.publish("same", self.case.artifacts, 10000)
        # A lost caller reply occurs after this actual publication/access; reopen
        # the composition and replay the same key, not the store effect.
        self.config["execution_runtime"] = self.open()
        recovered = self.call("4d_recovery_store_runtime", 10000)["repository"]
        recovered.publish("same", self.case.artifacts, 10000)
        self.assertEqual(self.case.persist_count, 1)

    def test_supervisor_requires_live_accepted_backstop_confirmation(self):
        result = self.call("4d_independent_recovery", 10000)
        expected = SessionDeadline(
            self.binding["C_ms"], self.binding["D_session_ms"], self.binding["t0_ms"]
        ).effective_ms
        self.assertEqual(result["D_eff_ms"], expected)
        self.factory.controller.backstop.confirmed.assert_called_once_with(
            self.binding["session_id"], expected
        )

    def test_supervisor_unconfirmed_refuses(self):
        self.factory.controller.backstop.confirmed.return_value = False
        with self.assertRaisesRegex(ValueError, "supervisor_unconfirmed"):
            self.call("4d_independent_recovery", 10000)

    def test_supervisor_lost_lookup_is_unknown_then_restart_rereads(self):
        self.factory.controller.backstop.confirmed.side_effect = OSError("lost lookup")
        with self.assertRaises(OSError):
            self.call("4d_independent_recovery", 10000)
        self.factory.controller.backstop.confirmed.side_effect = None
        self.config["execution_runtime"] = self.open()
        self.assertEqual(self.call("4d_independent_recovery", 10000)["supervisor_host"], "i-b")

    def test_transport_reuses_the_existing_socket_implementation(self):
        self.assertIs(
            self.call("terminal_export_transport", 10000)["transfer"],
            self.components["terminal_transfer"],
        )

    def test_transport_budget_mismatch_refuses(self):
        self.components["terminal_transfer"].max_reconnects = 9
        with self.assertRaisesRegex(ValueError, "transfer_reconnects"):
            self.call("terminal_export_transport", 10000)

    def test_archive_input_files_are_read_and_hash_checked(self):
        self.assertEqual(
            self.call("4d_campaign_archive_inputs", 10000)["sanitizer_key"], b"unit-key"
        )

    def test_archive_input_mutation_refuses(self):
        ref = self.inputs["campaign_archive_inputs"]["references"]["specs"]
        Path(ref["path"]).write_bytes(b"[]")
        with self.assertRaisesRegex(ValueError, "archive_input:specs"):
            self.call("4d_campaign_archive_inputs", 10000)

    def test_catalog_includes_closed_adverse_owner(self):
        result = self.call("4d_terminal_capture_inventory", 10000)
        self.assertFalse(result["owners"][0]["descriptor"]["transport_clean"])

    def test_catalog_cannot_omit_allocated_failed_owner(self):
        self.catalog["owners"] = []
        Path(self.inputs["terminal_capture_catalog"]["path"]).write_bytes(encode(self.catalog))
        with self.assertRaisesRegex(ValueError, "catalog_coverage"):
            self.call("4d_terminal_capture_inventory", 10000)

    def test_catalog_operator_list_cannot_hide_durable_allocation(self):
        from inference_platform.inf037b_eks_owner_registry import AllocatedOwners

        AllocatedOwners(self.factory.port.store, self.binding).allocate(
            "never-opened", self.root / "never-opened", self.binding, {}, self.root / "never-state"
        )
        with self.assertRaisesRegex(ValueError, "catalog_allocated_registry"):
            self.call("4d_terminal_capture_inventory", 10000)

    def test_closed_sidecar_cannot_override_an_open_owner_journal(self):
        self.authoritative_catalog["complete"] = False
        self.authoritative_catalog["owners"][0]["descriptor"]["closed"] = False
        with self.assertRaisesRegex(ValueError, "catalog_unclosed_registry"):
            self.call("4d_terminal_capture_inventory", 10000)

    def test_closed_sidecar_cannot_erase_an_adverse_owner_result(self):
        self.catalog["owners"][0]["descriptor"]["transport_clean"] = True
        Path(self.inputs["terminal_capture_catalog"]["path"]).write_bytes(encode(self.catalog))
        with self.assertRaisesRegex(ValueError, "catalog_descriptor_store"):
            self.call("4d_terminal_capture_inventory", 10000)

    def test_replay_export_custody_journal_size_does_not_scale_with_payload_bytes(self):
        result = {"replay_raw": b"r" * 100000, "export_raw": b"e" * 200000}
        receipt = self.runtime.retain("export_host_replay_export", {"request_key": "one"}, result)
        self.assertLess(len(encode(receipt)), 2500)
        self.assertNotIn("bytes_hex", str(receipt))
        for name, fact in receipt["artifacts"].items():
            self.assertEqual(Path(fact["path"]).read_bytes(), result[name])
            self.assertEqual(fact["sha256"], sha(result[name]))
        target = Path(receipt["artifacts"]["replay_raw"]["path"])
        target.write_bytes(b"replaced")
        with self.assertRaisesRegex(ValueError, "custody_readback"):
            self.runtime.retain("export_host_replay_export", {"request_key": "two"}, result)

    def test_boot_sample_uses_real_file_and_clock_bracket(self):
        self.assertEqual(
            self.call("clock_sample"),
            {"clock_id": "measurement", "boot_id": "unit-boot", "ms": [100, 100]},
        )

    @unittest.skipUnless(
        os.name == "posix" and os.environ.get("INF037B_EKS_HOST_TEST") == "1",
        "Linux measurement boot/clock runs on the CPU-validation host",
    )
    def test_real_linux_measurement_clock_is_continuous(self):
        boot = Path("/proc/sys/kernel/random/boot_id")
        identity = {
            "boot_id_path": str(boot),
            "boot_id": boot.read_text().strip(),
            "clock_id": "measurement",
        }
        self.runtime.need = lambda key: identity
        self.runtime.clock = lambda: time.monotonic_ns() // 1_000_000
        previous = None
        for _ in range(3):
            sample = self.call("clock_sample")
            self.assertEqual(sample["boot_id"], identity["boot_id"])
            self.assertLessEqual(sample["ms"][0], sample["ms"][1])
            if previous is not None:
                self.assertGreaterEqual(sample["ms"][0], previous)
            previous = sample["ms"][1]

    def test_boot_change_refuses(self):
        Path(self.inputs["measurement_clock"]["boot_id_path"]).write_text(
            "changed", encoding="ascii"
        )
        with self.assertRaisesRegex(ValueError, "boot_identity"):
            self.call("clock_sample")

    def test_clock_refuses_regression_and_reversed_brackets(self):
        for values, reason in (
            ([100, 101, 100, 102], "clock_regressed"),
            ([101, 100], "clock_order"),
        ):
            with self.subTest(reason=reason):
                self.runtime.last_clock = None
                ticks = iter(values)
                self.runtime.clock = lambda ticks=ticks: next(ticks)
                if len(values) == 4:
                    self.call("clock_sample")
                with self.assertRaisesRegex(ValueError, reason):
                    self.call("clock_sample")

    def test_resource_bindings_refuse_missing_capacity_or_source_authority(self):
        original = copy.deepcopy(self.inputs["resource_bindings"])
        for key, reason in (
            ("capacity_ref", "capacity_authority"),
            ("nic_bytes_per_second", "capacity"),
        ):
            value = copy.deepcopy(original)
            value["setup"]["measurement"]["budget"].pop(key)
            self.runtime.need = lambda name, value=value: value
            with self.assertRaisesRegex(ValueError, reason):
                self.call("campaign_resource_bindings", self.owner(), 10000)

    def owner(self):
        return SimpleNamespace(
            join_current=Mock(),
            binding={"session_id": self.binding["session_id"], "pins": self.pins},
            attempt="setup",
            root=self.root / "capture",
        )

    def test_resource_binding_joins_owner_and_preserves_real_emitter_spec(self):
        owner = self.owner()
        self.assertEqual(
            set(self.call("campaign_resource_bindings", owner, 10000)), {"measurement"}
        )
        owner.join_current.assert_called_once()

    def test_foreign_resource_owner_refuses(self):
        owner = self.owner()
        owner.binding["session_id"] = "foreign"
        with self.assertRaisesRegex(ValueError, "resource_owner"):
            self.call("campaign_resource_bindings", owner, 10000)

    def test_read_ports_reopen_after_lost_caller_reply_and_revalidate_files(self):
        calls = [
            ("terminal_export_transport", (10000,)),
            ("4d_campaign_archive_inputs", (10000,)),
            ("4d_terminal_capture_inventory", (10000,)),
            ("clock_sample", ()),
            ("campaign_resource_bindings", (self.owner(), 10000)),
        ]
        for name, args in calls:
            with self.subTest(port=name):
                self.call(name, *args)  # caller discards reply
                self.config["execution_runtime"] = self.open()
                self.assertIsNotNone(self.call(name, *args))

    def test_missing_runtime_names_every_unfinished_port(self):
        self.config.pop("execution_runtime")
        for name in PORTS:
            with self.subTest(port=name), self.assertRaisesRegex(ValueError, "unfinished:" + name):
                execution_port(self.factory, name)()

    def test_source_mutation_refuses_after_restart(self):
        path = Path(self.runtime.source["path"])
        path.write_bytes(encode({**self.inputs, "extra": True}))
        with self.assertRaisesRegex(ValueError, "original"):
            self.open()

    def test_in_memory_source_mutation_refuses(self):
        self.runtime.inputs["pins"] = {"configuration": "other"}
        with self.assertRaisesRegex(ValueError, "source_content"):
            self.call("clock_sample")

    def test_consumer_rejects_changed_result_after_retention(self):
        result = self.call("4d_terminal_capture_inventory", 10000)
        result["complete"] = False
        with self.assertRaisesRegex(ValueError, "consumer_result"):
            join_execution(result, self.factory, "4d_terminal_capture_inventory")

    def test_consumer_rejects_unretained_shape(self):
        result = dict(self.call("terminal_export_transport", 10000))
        with self.assertRaisesRegex(ValueError, "consumer_proof"):
            join_execution(result, self.factory, "terminal_export_transport")

    def test_consumer_accepts_each_retained_runtime_result(self):
        for name in (
            "4d_recovery_store_runtime",
            "4d_independent_recovery",
            "terminal_export_transport",
            "4d_campaign_archive_inputs",
            "4d_terminal_capture_inventory",
        ):
            with self.subTest(port=name):
                join_execution(self.call(name, 10000), self.factory, name)
