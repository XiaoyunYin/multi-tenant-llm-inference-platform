"""Real HTTP + counter files; no claim about deployed CPU/NIC capacities."""

import copy
import json
import os
import subprocess
import sys
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from inf037b_eks_component import resource_owner

from inference_platform.inf037b_archive import IntegrityError, encode, sha
from inference_platform.inf037b_nic import (
    baseline_bytes,
    instance_type_facts,
    nic_capacity_documents,
)
from inference_platform.inf037b_resource_agent import (
    PinnedCounters,
    ResourceProcess,
    file_identity,
    producer_from_spec,
)
from inference_platform.inf037b_resources import (
    ProcCounters,
    ResourceAdapter,
    ResourceProducer,
    resource_handler,
)


class ResourceTests(unittest.TestCase):
    def setUp(self):
        self.owner = resource_owner(self)
        self.now = 0
        self.budget = {
            "cpu_millicores": 1000,
            "nic_bytes_per_second": 1000,
            "capacity_ref": "a" * 64,
        }
        self.producer = ResourceProducer(
            role="measurement",
            binding={"session_id": "s", "pins": self.owner.binding["pins"]},
            generation="generation",
            boot="resource-boot",
            counters=lambda: {
                "cpu_ns": self.now // 2,
                "rx_bytes": self.now * 200 // 1_000_000_000,
                "tx_bytes": self.now * 100 // 1_000_000_000,
            },
            budget=self.budget,
            clock=lambda: self.now,
        )
        server = ThreadingHTTPServer(
            ("127.0.0.1", 0), resource_handler(self.producer, lambda: "unit-token")
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.spec = {
            "generation": "generation",
            "boot_id": "resource-boot",
            "budget": self.budget,
            "source_sha256": sha(
                Path(__import__("inference_platform.inf037b_resources", fromlist=["x"]).__file__)
                .read_bytes()
                .replace(b"\r\n", b"\n")
            ),
            "http": {
                "base": f"http://127.0.0.1:{server.server_port}",
                "local_test": True,
                "token": lambda: "unit-token",
            },
        }
        self.adapter = ResourceAdapter(
            self.owner, "measurement", self.spec, time.monotonic_ns() + 10_000_000_000
        )
        self.adapter.rows.clock = lambda: self.now

    def poll(self):
        with patch(
            "inference_platform.inf037b_live.time.time", return_value=1_000_000 + self.now / 1e9
        ):
            return self.adapter.poll()

    def warm(self):
        results = []
        for n in range(6):
            self.now = n * 500_000_000
            results.extend(self.poll())
        return results

    def test_real_http_windows_include_both_nic_directions_and_owner_budget(self):
        rows = self.warm()
        self.assertGreaterEqual(len(rows), 2)
        for row in rows:
            self.assertEqual(row["payload"]["value"], {"cpu_ppm": 500000, "nic_ppm": 300000})
            self.assertEqual(row["payload"]["cpu_fraction"], 0.5)
            self.assertEqual(row["payload"]["nic_fraction"], 0.3)
            self.assertLessEqual(
                row["payload"]["window_end_ms"] - row["payload"]["window_start_ms"], 2000
            )
        self.assertGreater(self.owner.wire["resource:measurement"]["offset"], 0)
        self.assertFalse(self.owner.failed)

    def test_raw_resource_overflow_persists_loss_before_normalization(self):
        self.owner.binding["capture_budgets"]["resource:measurement"]["raw_bytes"] = 1
        self.owner.operation_store.write({"operations": {self.owner.label: self.owner.operation}})
        with self.assertRaisesRegex(IntegrityError, "capture:budget:resource:measurement:raw"):
            self.poll()
        self.assertTrue(self.owner.failed)
        self.assertTrue(
            any(
                "capture:budget:resource:measurement:raw" in item
                for item in self.owner.store.read()["capture"]["losses"]
            )
        )

    def test_producer_restart_or_capacity_change_refuses(self):
        self.warm()
        self.producer.generation = "other"
        with self.assertRaisesRegex(IntegrityError, "resource:identity:generation"):
            self.poll()

    def test_raw_is_retained_before_wrong_boot_budget_code_or_provenance_refuses(self):
        original = self.producer.read
        for field, value, reason in (
            ("boot_id", "stale", "identity:boot_id"),
            ("budget", {**self.budget, "capacity_ref": "b" * 64}, "identity:budget"),
            ("source_sha256", "0" * 64, "identity:source_sha256"),
            ("provenance", {"foreign": True}, "provenance"),
        ):
            with self.subTest(field=field):
                self.spec["provenance"] = {"capacity_sha256": self.budget["capacity_ref"]}
                self.producer.read = lambda field=field, value=value: {**original(), field: value}
                before = self.owner.wire["resource:measurement"]["offset"]
                with self.assertRaisesRegex(ValueError, reason):
                    self.poll()
                self.assertGreater(self.owner.wire["resource:measurement"]["offset"], before)

    def test_window_reset_after_emission_refuses(self):
        self.warm()
        self.producer.history.clear()
        with self.assertRaisesRegex(ValueError, "window_reset"):
            self.poll()

    def test_http_clock_bracket_accepts_100ms_and_refuses_one_ns_over(self):
        self.warm()
        self.now += 500_000_000
        ticks = iter([self.now, self.now + 100_000_000])
        self.adapter.rows.clock = lambda: next(ticks, self.now + 100_000_000)
        self.assertTrue(self.poll())
        self.now += 500_000_000
        ticks = iter([self.now, self.now + 100_000_001])
        self.adapter.rows.clock = lambda: next(ticks, self.now + 100_000_001)
        before = self.owner.wire["resource:measurement"]["offset"]
        with self.assertRaisesRegex(ValueError, "clock_uncertainty"):
            self.poll()
        self.assertGreater(self.owner.wire["resource:measurement"]["offset"], before)

    def test_counter_reset_refuses_in_normalized_adapter(self):
        self.warm()
        self.producer.counters = lambda: {"cpu_ns": 0, "rx_bytes": 0, "tx_bytes": 0}
        self.now += 500_000_000
        self.poll()
        self.now += 500_000_000
        with self.assertRaisesRegex(ValueError, "counter_regressed"):
            self.poll()

    def test_proc_counter_files_verify_cpu_capacity_and_read_nic_totals(self):
        with TemporaryDirectory(prefix="r338-proc-") as directory:
            root = Path(directory)
            (root / "statistics").mkdir()
            (root / "cpu.max").write_text("100000 100000")
            (root / "cpu.stat").write_text("usage_usec 1200\n")
            (root / "statistics/rx_bytes").write_text("200")
            (root / "statistics/tx_bytes").write_text("100")
            counters = ProcCounters(root, root, **self.budget)
            self.assertEqual(counters(), {"cpu_ns": 1200000, "rx_bytes": 200, "tx_bytes": 100})
            (root / "cpu.max").write_text("200000 100000")
            with self.assertRaisesRegex(IntegrityError, "cpu_capacity_changed"):
                counters()


class ResourceAgentTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory(prefix="r359-resource-")))
        self.cgroup = self.root / "cgroups/target"
        self.interface = self.root / "nic"
        self.cgroup.mkdir(parents=True)
        (self.interface / "statistics").mkdir(parents=True)
        (self.cgroup / "cpu.max").write_text("100000 100000")
        (self.cgroup / "cpuset.cpus.effective").write_text("0-1")
        (self.cgroup.parent / "cpu.max").write_text("max 100000")
        (self.cgroup.parent / "cpuset.cpus.effective").write_text("0-1")
        (self.cgroup / "cpu.stat").write_text("usage_usec 1200\n")
        (self.interface / "ifindex").write_text("7")
        (self.interface / "statistics/rx_bytes").write_text("200")
        (self.interface / "statistics/tx_bytes").write_text("100")
        self.boot = self.root / "boot"
        self.boot.write_text("resource-boot")
        self.own = self.root / "self-cgroup"
        self.own.write_text("0::/emitter")
        token = self.root / "token"
        token.write_text("unit-token")
        self.binding = {"session_id": "s", "pins": {"source": "a" * 64}}
        nic = {
            "schema": "inf037b-nic-capacity-v1",
            "binding": self.binding,
            "boot_id": "resource-boot",
            "interface_identity": file_identity(self.interface),
            "ifindex": 7,
            "basis": "guaranteed_baseline",
            "bytes_per_second": 1000,
            "source_reference": "explicit unit fixture, not a deployment capacity claim",
        }
        self.nic = self.root / "nic-authority.json"
        self.nic.write_bytes(encode(nic))
        self.cap = {
            "schema": "inf037b-resource-capacity-v1",
            "binding": self.binding,
            "role": "measurement",
            "generation": "generation",
            "boot_id": "resource-boot",
            "cgroup": str(self.cgroup),
            "interface": str(self.interface),
            "cgroup_root": str(self.root / "cgroups"),
            "target_cgroup_relative": "/target",
            "cgroup_identity": file_identity(self.cgroup),
            "cgroup_namespace_identity": file_identity(self.own),
            "interface_identity": file_identity(self.interface),
            "ifindex": 7,
            "cpu_millicores": 1000,
            "nic_bytes_per_second": 1000,
            "nic_authority": {"path": str(self.nic), "sha256": sha(self.nic.read_bytes())},
        }
        import inference_platform.inf037b_resource_agent as agent
        import inference_platform.inf037b_resources as resources

        self.spec = {
            **{k: self.cap[k] for k in ("binding", "role", "generation", "boot_id")},
            "boot_id_path": str(self.boot),
            "token_path": str(token),
            "emitter_cgroup_path": str(self.own),
            "cgroup_namespace_path": str(self.own),
            "target_cgroup_relative": "/target",
            "source_sha256": sha(Path(resources.__file__).read_bytes().replace(b"\r\n", b"\n")),
            "agent_sha256": sha(Path(agent.__file__).read_bytes().replace(b"\r\n", b"\n")),
        }
        self.save_capacity()

    def save_capacity(self):
        path = self.root / "capacity.json"
        path.write_bytes(encode(self.cap))
        self.spec["capacity"] = {"path": str(path), "sha256": sha(path.read_bytes())}

    def test_real_child_process_serves_authenticated_counter_windows_and_boot_refusal(self):
        path = self.root / "agent.json"
        path.write_bytes(encode(self.spec))
        process = ResourceProcess(path).start()
        self.addCleanup(process.close)
        self.assertNotEqual(process.receipt["pid"], os.getpid())
        host, port = process.receipt["address"]
        request = Request(
            f"http://{host}:{port}/resources", headers={"Authorization": "Bearer unit-token"}
        )
        with self.assertRaises(HTTPError) as error:
            urlopen(f"http://{host}:{port}/resources", timeout=2)
        self.assertEqual(error.exception.code, 403)
        for _ in range(4):
            with urlopen(request, timeout=2) as response:
                row = json.load(response)
            time.sleep(0.005)
        self.assertIsNotNone(row["window"])
        self.assertEqual(row["budget"]["capacity_ref"], self.spec["capacity"]["sha256"])
        self.assertEqual(row["provenance"]["cgroup_identity"], self.cap["cgroup_identity"])
        self.assertEqual(row["source_sha256"], self.spec["source_sha256"])
        self.boot.write_text("new-boot")
        with self.assertRaises(HTTPError) as error:
            urlopen(request, timeout=2)
        self.assertEqual(error.exception.code, 503)

    def test_wrong_cgroup_interface_capacity_boot_or_counter_reset_refuses(self):
        cases = (
            "cgroup",
            "interface",
            "cpu",
            "boot",
            "reset",
            "authority",
            "independence",
            "ifindex",
        )
        for change in cases:
            with self.subTest(change=change):
                counters = PinnedCounters(self.spec)
                counters()
                if change in ("cgroup", "interface"):
                    path = self.cgroup if change == "cgroup" else self.interface
                    old = path.with_name(path.name + "-old")
                    path.rename(old)
                    path.mkdir()
                    try:
                        with self.assertRaisesRegex(ValueError, change + "_changed"):
                            counters()
                    finally:
                        path.rmdir()
                        old.rename(path)
                    continue
                path, bad, good, reason = {
                    "cpu": (
                        self.cgroup / "cpu.max",
                        "200000 100000",
                        "100000 100000",
                        "cpu_capacity_changed",
                    ),
                    "boot": (self.boot, "wrong", "resource-boot", "boot_changed"),
                    "reset": (
                        self.cgroup / "cpu.stat",
                        "usage_usec 1",
                        "usage_usec 1200",
                        "counter_regressed",
                    ),
                    "authority": (
                        self.nic,
                        "{}",
                        self.nic.read_text(),
                        "nic_capacity_authority:hash",
                    ),
                    "independence": (
                        self.own,
                        "0::/target/child",
                        "0::/emitter",
                        "emitter_not_independent",
                    ),
                    "ifindex": (self.interface / "ifindex", "8", "7", "interface_changed"),
                }[change]
                path.write_text(bad)
                try:
                    with self.assertRaisesRegex(ValueError, reason):
                        counters()
                finally:
                    path.write_bytes(good.encode())

    def test_missing_or_non_guaranteed_authority_never_uses_observed_throughput(self):
        spec = copy.deepcopy(self.spec)
        spec.pop("capacity")
        with self.assertRaisesRegex(ValueError, "unresolved:capacity_authority"):
            PinnedCounters(spec)
        for basis in ("observed_throughput", "burst", "link_speed"):
            doc = json.loads(self.nic.read_bytes())
            doc["basis"] = basis
            self.nic.write_bytes(encode(doc))
            self.cap["nic_authority"]["sha256"] = sha(self.nic.read_bytes())
            self.save_capacity()
            with self.assertRaisesRegex(ValueError, "unresolved:nic_guaranteed_baseline"):
                PinnedCounters(self.spec)

    def test_generation_boot_and_code_pins_refuse_before_serving(self):
        for key in ("generation", "boot_id", "agent_sha256", "source_sha256"):
            with self.subTest(key=key):
                spec = {**self.spec, key: "wrong"}
                with self.assertRaises(ValueError):
                    producer_from_spec(spec)

    def test_unlimited_leaf_and_stricter_ancestor_cpu_refuse(self):
        (self.cgroup / "cpu.max").write_text("max 100000")
        with self.assertRaisesRegex(ValueError, "unresolved:cpu_capacity_authority"):
            PinnedCounters(self.spec)

        (self.cgroup / "cpu.max").write_text("100000 100000")
        (self.cgroup.parent / "cpu.max").write_text("50000 100000")
        with self.assertRaisesRegex(ValueError, "cpu_capacity_changed"):
            PinnedCounters(self.spec)
        (self.cgroup.parent / "cpu.max").write_text("max 100000")
        (self.cgroup / "cpuset.cpus.effective").write_text("0")
        self.cap["cpu_millicores"] = 2000
        self.save_capacity()
        with self.assertRaisesRegex(ValueError, "cpu_capacity_changed"):
            PinnedCounters(self.spec)

    def test_private_cgroup_namespace_cannot_claim_host_relative_independence(self):
        other = self.root / "private-cgroup-namespace"
        other.write_text("different namespace")
        self.spec["cgroup_namespace_path"] = str(other)
        with self.assertRaisesRegex(ValueError, "cgroup_namespace_changed"):
            PinnedCounters(self.spec)

    def kernel_tree(self):
        root = self.cgroup.parent
        (root / "cpu.max").unlink()
        middle = root / "middle"
        leaf = middle / "leaf"
        leaf.mkdir(parents=True)
        (leaf / "cpu.max").write_text("100000 100000")
        (leaf / "cpu.stat").write_text("usage_usec 1200")
        self.cap["cgroup"] = str(leaf)
        self.cap["cgroup_identity"] = file_identity(leaf)
        self.cap["target_cgroup_relative"] = "/middle/leaf"
        self.spec["target_cgroup_relative"] = "/middle/leaf"
        self.save_capacity()
        return root, middle, leaf

    def test_kernel_root_without_cpu_max_and_controllerless_middle_accept(self):
        root, middle, leaf = self.kernel_tree()
        counters = PinnedCounters(self.spec)
        self.assertEqual(counters()["cpu_ns"], 1200000)
        self.assertEqual(producer_from_spec(self.spec).read()["role"], "measurement")
        (middle / "cpu.max").write_text("50000 100000")
        with self.assertRaisesRegex(ValueError, "cpu_capacity_changed"):
            counters()

    def test_nic_cli_document_is_accepted_by_the_pinned_counter_producer(self):
        raw = encode(
            {
                "InstanceTypes": [
                    {
                        "InstanceType": "unit.type",
                        "NetworkInfo": {
                            "NetworkCards": [{"NetworkCardIndex": 0, "BaselineBandwidthInGbps": 1}]
                        },
                    }
                ]
            }
        )
        record = instance_type_facts(
            raw, {"exit": 0, "sha256": sha(raw), "utc": "2026-11-06T00:00:00Z"}
        )
        refresh, allocation = self.root / "refresh.json", self.root / "allocation.json"
        refresh.write_bytes(encode({"instance_type_facts": record}))
        allocation.write_bytes(
            encode(
                {
                    "instance_type": "unit.type",
                    "instance_identity": "unit-host",
                    "binding": self.binding,
                    "allocations": [
                        {
                            "role": "measurement",
                            "network_card_index": 0,
                            "bytes_per_second": self.cap["nic_bytes_per_second"],
                            "boot_id": self.cap["boot_id"],
                            "interface_identity": self.cap["interface_identity"],
                            "ifindex": self.cap["ifindex"],
                        }
                    ],
                }
            )
        )
        output = self.root / "nic-documents"
        result = subprocess.run(
            [
                sys.executable,
                str(Path(__file__).resolve().parents[2] / "scripts/build_inf037b_nic_capacity.py"),
                "--refresh",
                str(refresh),
                "--allocation",
                str(allocation),
                "--output",
                str(output),
            ],
            capture_output=True,
            check=True,
        )
        document = output / "measurement.json"
        self.assertIn(sha(document.read_bytes()).encode(), result.stdout)
        self.cap["nic_authority"] = {"path": str(document), "sha256": sha(document.read_bytes())}
        self.save_capacity()
        self.assertEqual(
            producer_from_spec(self.spec).read()["budget"]["nic_bytes_per_second"], 1000
        )

    def test_missing_leaf_quota_and_bad_controller_files_refuse_by_name(self):
        root, middle, leaf = self.kernel_tree()
        (leaf / "cpu.max").unlink()
        with self.assertRaisesRegex(ValueError, "resource:unresolved:cpu_capacity_authority"):
            PinnedCounters(self.spec)
        for content in ("invalid", "100000 0", "-1 100000", "max nope"):
            (leaf / "cpu.max").write_text(content)
            with (
                self.subTest(content=content),
                self.assertRaisesRegex(ValueError, "resource:cgroup_unreadable"),
            ):
                PinnedCounters(self.spec)
        (leaf / "cpu.max").write_text("100000 100000")
        (root / "cpuset.cpus.effective").write_text("bad-cpuset")
        with self.assertRaisesRegex(ValueError, "resource:cgroup_unreadable"):
            PinnedCounters(self.spec)

    def test_nearest_effective_cpuset_is_used_and_unreadable_is_not_absent(self):
        root, middle, leaf = self.kernel_tree()
        (root / "cpuset.cpus.effective").write_text("0")
        (leaf / "cpu.max").write_text("200000 100000")
        self.cap["cpu_millicores"] = 2000
        self.save_capacity()
        with self.assertRaisesRegex(ValueError, "cpu_capacity_changed"):
            PinnedCounters(self.spec)
        (middle / "cpuset.cpus.effective").write_text("0-1")
        PinnedCounters(self.spec)()
        (middle / "cpu.max").mkdir()  # EISDIR is an I/O error, not an absent controller.
        with self.assertRaisesRegex(ValueError, "resource:cgroup_unreadable"):
            PinnedCounters(self.spec)

    @unittest.skipUnless(
        os.name == "posix" and os.environ.get("INF037B_RESOURCE_CGROUP_CASE") == "1",
        "Linux boot/cgroup-v2/NIC counters require the CPU-validation host",
    )
    def test_real_linux_boot_cgroup_and_interface_counters(self):
        # Real host source paths, not the temp counter fixture. The idle
        # --cpus 1 target is distinct from this emitter; both production
        # constructors must accept through the actual cgroupfs root.
        boot_path = Path("/proc/sys/kernel/random/boot_id")
        cgroup_root = Path("/sys/fs/cgroup")
        relative = os.environ["INF037B_RESOURCE_TARGET_CGROUP"]
        self.assertFalse(
            (cgroup_root / "cpu.max").exists(), "must walk the real host cgroupfs root"
        )
        self.assertIn(
            "ro",
            next(
                line.split()[5]
                for line in Path("/proc/self/mountinfo").read_text().splitlines()
                if line.split()[4] == "/sys/fs/cgroup"
            ).split(","),
        )
        target = cgroup_root / relative.lstrip("/")
        quota, period = (target / "cpu.max").read_text().split()
        self.assertNotEqual(quota, "max", "CPU stage requires its real finite quota")
        budget = int(quota) * 1000 // int(period)
        nic = Path("/sys/class/net/lo")
        boot = boot_path.read_text().strip()
        self.cap.update(
            cgroup=str(target),
            cgroup_root=str(cgroup_root),
            target_cgroup_relative=relative,
            cgroup_identity=file_identity(target),
            interface=str(nic),
            interface_identity=file_identity(nic),
            ifindex=int((nic / "ifindex").read_text()),
            boot_id=boot,
            cgroup_namespace_identity=file_identity("/proc/self/ns/cgroup"),
            cpu_millicores=budget,
        )
        doc = json.loads(self.nic.read_bytes())
        for key in ("boot_id", "interface_identity", "ifindex"):
            doc[key] = self.cap[key]
        doc["source_reference"] = "explicit test-only NIC allowance, not final host fitness"
        self.nic.write_bytes(encode(doc))
        self.cap["nic_authority"]["sha256"] = sha(self.nic.read_bytes())
        self.spec.update(
            boot_id=boot,
            boot_id_path=str(boot_path),
            emitter_cgroup_path="/proc/self/cgroup",
            cgroup_namespace_path="/proc/self/ns/cgroup",
            target_cgroup_relative=relative,
        )
        self.save_capacity()
        counters = PinnedCounters(self.spec)
        self.assertGreaterEqual(counters()["cpu_ns"], 0)
        producer = producer_from_spec(self.spec)
        self.assertEqual(producer.read()["budget"]["cpu_millicores"], 1000)
        counters = ProcCounters(
            target,
            nic,
            cpu_millicores=budget,
            nic_bytes_per_second=1000,
            capacity_ref=self.spec["capacity"]["sha256"],
        )
        first, last = counters(), counters()
        self.assertTrue(all(last[k] >= first[k] for k in first))
        self.assertEqual(boot_path.read_text().strip(), boot)


class NicAuthorityTests(unittest.TestCase):
    def record(self, rows=None):
        raw = encode(
            {
                "InstanceTypes": rows
                if rows is not None
                else [
                    {
                        "InstanceType": "unit.type",
                        "NetworkInfo": {
                            "NetworkCards": [
                                {
                                    "NetworkCardIndex": 0,
                                    "BaselineBandwidthInGbps": 1,
                                    "PeakBandwidthInGbps": 100,
                                },
                                {"NetworkCardIndex": 1, "BaselineBandwidthInGbps": 1},
                            ]
                        },
                    }
                ]
            }
        )
        return instance_type_facts(
            raw, {"exit": 0, "sha256": sha(raw), "utc": "2026-11-06T00:00:00+00:00"}
        )

    def allocation(self, role="measurement", card=0, rate=60000000):
        return {
            "role": role,
            "network_card_index": card,
            "bytes_per_second": rate,
            "boot_id": "unit-boot",
            "interface_identity": [1, 2 if role == "measurement" else 3],
            "ifindex": 7,
        }

    def documents(self, record, allocations=None):
        return nic_capacity_documents(
            record,
            instance_type="unit.type",
            instance_identity="unit-host",
            binding={"session_id": "unit", "pins": {"source": "a" * 64}},
            allocations=allocations if allocations is not None else [self.allocation()],
        )

    def test_decimal_gbps_conversion_rounds_down_without_binary_or_context_roundup(self):
        self.assertEqual(baseline_bytes("0.000000015999999999999999999999999999"), 1)
        self.assertEqual(baseline_bytes("1.234567891"), 154320986)
        raw = b'{"InstanceTypes":[{"InstanceType":"unit.type","NetworkInfo":{"NetworkCards":[{"NetworkCardIndex":0,"BaselineBandwidthInGbps":0.000000015999999999999999999999999999}]}}]}'
        record = instance_type_facts(
            raw, {"exit": 0, "sha256": sha(raw), "utc": "2026-11-06T00:00:00Z"}
        )
        doc = self.documents(record, [self.allocation(rate=1)])["measurement"]
        self.assertEqual(doc["source_reference"]["baseline_bytes_per_second"], 1)
        with self.assertRaisesRegex(ValueError, "nic_allocation_exceeds_baseline"):
            self.documents(record, [self.allocation(rate=2)])

    def test_document_binds_date_raw_response_type_card_allocation_and_interface(self):
        record = self.record()
        doc = self.documents(record)["measurement"]
        self.assertEqual(doc["schema"], "inf037b-nic-capacity-v1")
        self.assertEqual(doc["basis"], "guaranteed_baseline")
        self.assertEqual(doc["bytes_per_second"], 60000000)
        self.assertEqual(doc["source_reference"]["baseline_bytes_per_second"], 125000000)
        self.assertEqual(doc["source_reference"]["utc"], record["utc"])
        self.assertEqual(doc["source_reference"]["response_sha256"], record["response_sha256"])
        self.assertEqual(doc["source_reference"]["facts_sha256"], sha(encode(record)))
        self.assertEqual(doc["interface_identity"], [1, 2])
        changed = self.documents(record, [self.allocation(rate=50000000)])["measurement"]
        self.assertNotEqual(
            doc["source_reference"]["allocation_sha256"],
            changed["source_reference"]["allocation_sha256"],
        )

    def test_missing_type_missing_field_and_peak_only_refuse_named_baseline(self):
        cases = [
            [],
            [{"InstanceType": "other.type"}],
            [{"InstanceType": "unit.type"}],
            [
                {
                    "InstanceType": "unit.type",
                    "NetworkInfo": {
                        "NetworkPerformance": "Up to 100 Gbps",
                        "NetworkCards": [{"NetworkCardIndex": 0, "PeakBandwidthInGbps": 100}],
                    },
                }
            ],
            [
                {
                    "InstanceType": "unit.type",
                    "NetworkInfo": {
                        "NetworkCards": [{"NetworkCardIndex": 0, "BaselineBandwidthInGbps": None}]
                    },
                }
            ],
        ]
        for rows in cases:
            with (
                self.subTest(rows=rows),
                self.assertRaisesRegex(ValueError, "resource:unresolved:nic_guaranteed_baseline"),
            ):
                self.documents(self.record(rows))

    def test_roles_sharing_card_must_fit_aggregate_baseline(self):
        record = self.record()
        rows = [self.allocation(rate=60000000), self.allocation("generator", rate=65000000)]
        self.assertEqual(set(self.documents(record, rows)), {"measurement", "generator"})
        rows[1]["bytes_per_second"] += 1
        with self.assertRaisesRegex(ValueError, "nic_allocation_exceeds_baseline"):
            self.documents(record, rows)
        rows[1]["network_card_index"] = 1
        self.assertEqual(len(self.documents(record, rows)), 2)

    def test_bad_rates_duplicates_and_raw_response_hash_refuse(self):
        for rate in ("NaN", "Infinity", "-1", "0", True, None):
            with (
                self.subTest(rate=rate),
                self.assertRaisesRegex(ValueError, "nic_guaranteed_baseline"),
            ):
                baseline_bytes(rate)
        with self.assertRaisesRegex(ValueError, "nic_duplicate_role"):
            self.documents(self.record(), [self.allocation(), self.allocation()])
        with self.assertRaisesRegex(ValueError, "nic_refresh_hash"):
            instance_type_facts(
                b'{"InstanceTypes":[]}',
                {"exit": 0, "sha256": "0" * 64, "utc": "2026-11-06T00:00:00Z"},
            )


if __name__ == "__main__":
    unittest.main()
