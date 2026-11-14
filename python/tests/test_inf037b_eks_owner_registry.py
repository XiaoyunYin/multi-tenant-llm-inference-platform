"""Real POSIX journals/process death and the factory allocation boundary."""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from inference_platform.inf037b_durable_ports import DurableStore
from inference_platform.inf037b_eks_fixture import fixture_inventory
from inference_platform.inf037b_eks_owner_registry import AllocatedOwners


@unittest.skipUnless(os.name == "posix", "real POSIX journal on the routine AWS CPU host")
class OwnerRegistryTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.binding = {"session_id": "fixture-session", "plan_hash": "a" * 64}
        self.journal = DurableStore(self.root / "journal", {}, initialize=True)
        self.registry = AllocatedOwners(self.journal, self.binding)

    def test_process_death_after_allocation_retains_never_materialized_owner(self):
        script = """
import os,sys
from pathlib import Path
from inference_platform.inf037b_durable_ports import DurableStore
from inference_platform.inf037b_eks_owner_registry import AllocatedOwners
p=Path(sys.argv[1]); b={'session_id':'fixture-session','plan_hash':'a'*64}
r=AllocatedOwners(DurableStore(p/'journal',{}),b)
r.allocate('attempt_1',p/'raw',b,{'redis':[['redis','r','boot']]},p/'descriptor')
os._exit(19)
"""
        result = subprocess.run([sys.executable, "-c", script, str(self.root)], check=False)
        self.assertEqual(result.returncode, 19)
        reopened = AllocatedOwners(DurableStore(self.root / "journal", {}), self.binding)
        catalog = reopened.catalog(lambda _: (_ for _ in ()).throw(FileNotFoundError()))
        self.assertFalse(catalog["complete"])
        self.assertEqual([r["owner_id"] for r in catalog["owners"]], ["attempt_1"])
        self.assertFalse(catalog["owners"][0]["descriptor"]["closed"])
        with self.assertRaisesRegex(ValueError, "already_allocated"):
            reopened.allocate(
                "attempt_1", self.root / "raw2", self.binding, {}, self.root / "descriptor2"
            )

    def test_closed_adverse_descriptor_is_retained_and_changed_bytes_refuse(self):
        root = self.root / "owner"
        root.mkdir()
        (root / "partial.bin").write_bytes(b"adverse evidence")
        sources = {"redis": [["redis", "r", "boot"]]}
        self.registry.allocate("probe", root, self.binding, sources, self.root / "descriptor")
        self.registry.opened("probe")
        descriptor = {
            "closed": True,
            "transport_clean": False,
            "binding": self.binding,
            "sources": sources,
            "files": fixture_inventory(root),
        }
        DurableStore(self.root / "descriptor", {"capture": descriptor}, initialize=True)
        self.assertTrue(self.registry.catalog()["complete"])
        catalog = self.registry.catalog(lambda _: descriptor)
        self.assertTrue(catalog["complete"])
        self.assertFalse(catalog["owners"][0]["descriptor"]["transport_clean"])
        (root / "partial.bin").write_bytes(b"changed")
        self.assertFalse(self.registry.catalog(lambda _: descriptor)["complete"])

    def test_duplicate_root_or_store_and_foreign_binding_refuse(self):
        self.registry.allocate(
            "probe", self.root / "raw", self.binding, {}, self.root / "descriptor"
        )
        for root, store in (("raw", "other"), ("other", "descriptor")):
            with self.assertRaisesRegex(ValueError, "duplicate_root_or_store"):
                self.registry.allocate(
                    "other", self.root / root, self.binding, {}, self.root / store
                )
        foreign = AllocatedOwners(self.journal, {**self.binding, "session_id": "foreign"})
        with self.assertRaisesRegex(ValueError, "capture_registry:binding"):
            foreign.allocations()
