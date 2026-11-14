"""Allocated-owner custody in the existing durable controller journal.

Allocation precedes CaptureOwner construction. Crashes and failed constructors
therefore cannot disappear from a terminal catalogue of successful files.
"""

import copy
from pathlib import Path

from .inf037b_archive import encode, sha
from .inf037b_eks_fixture import fixture_inventory
from .inf037b_resolver import exact, require


class AllocatedOwners:
    def __init__(self, journal, binding):
        self.journal, self.binding = journal, copy.deepcopy(binding)

    def allocate(self, owner_id, root, binding, sources, descriptor_store):
        root, descriptor_store = Path(root).resolve(), Path(descriptor_store).resolve()
        entry = {
            "owner_id": owner_id,
            "root": str(root),
            "descriptor_store": str(descriptor_store),
            "binding": copy.deepcopy(binding),
            "sources": copy.deepcopy(sources),
            "source_set_sha256": sha(encode(sources)),
            "opened": False,
        }
        with self.journal.lock():
            state = self.journal.read()
            registry = state.setdefault(
                "allocated_capture_owners", {"binding": self.binding, "owners": []}
            )
            exact(registry["binding"], self.binding, "capture_registry:binding")
            require(
                not any(r["owner_id"] == owner_id for r in registry["owners"]),
                "capture_registry:already_allocated",
            )
            require(
                not any(
                    Path(r["root"]) == root or Path(r["descriptor_store"]) == descriptor_store
                    for r in registry["owners"]
                ),
                "capture_registry:duplicate_root_or_store",
            )
            registry["owners"].append(entry)
            self.journal.write(state)
        return copy.deepcopy(entry)

    def opened(self, owner_id):
        self._update(owner_id, {"opened": True})

    def failed(self, owner_id, error):
        # Exception text may contain endpoints/credentials. Only its class is
        # needed to explain a never-materialized or partially opened owner.
        self._update(owner_id, {"open_error": type(error).__name__})

    def _update(self, owner_id, changes):
        with self.journal.lock():
            state = self.journal.read()
            registry = state["allocated_capture_owners"]
            exact(registry["binding"], self.binding, "capture_registry:binding")
            matches = [r for r in registry["owners"] if r["owner_id"] == owner_id]
            require(len(matches) == 1, "capture_registry:allocation_missing")
            matches[0].update(changes)
            self.journal.write(state)

    def allocations(self):
        with self.journal.lock():
            registry = self.journal.read().get("allocated_capture_owners")
        require(type(registry) is dict, "capture_registry:missing")
        exact(registry["binding"], self.binding, "capture_registry:binding")
        return copy.deepcopy(registry["owners"])

    def catalog(self, read_descriptor=None):
        if read_descriptor is None:
            from .inf037b_durable_ports import DurableStore

            def read_descriptor(directory):
                store = DurableStore(directory, {})
                with store.lock():
                    return store.read()["capture"]

        owners = []
        complete = True
        for row in self.allocations():
            try:
                descriptor = copy.deepcopy(read_descriptor(row["descriptor_store"]))
                exact(descriptor["binding"], row["binding"], "capture_registry:owner_binding")
                exact(descriptor["sources"], row["sources"], "capture_registry:owner_sources")
                require(descriptor["closed"] is True, "capture_registry:open")
                exact(fixture_inventory(row["root"]), descriptor["files"], "capture_registry:files")
            except (OSError, KeyError, ValueError) as error:
                descriptor = {"closed": False, "error": type(error).__name__}
                complete = False
            owners.append(
                {"owner_id": row["owner_id"], "root": row["root"], "descriptor": descriptor}
            )
        return {"binding": self.binding, "complete": complete, "owners": owners}
