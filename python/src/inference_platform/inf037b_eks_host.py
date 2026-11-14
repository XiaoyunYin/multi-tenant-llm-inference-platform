"""Export-host fixture executor, served by the existing authority transport.

Instantiate on the export host only. Its local source is pre-delivered and
hash-verified; the controller's source path is never opened. DurableStore and
stage_fixture are the production defaults. Portable seams claim no POSIX proof.
"""

import copy
from pathlib import Path

from .inf037b_archive import encode, sha
from .inf037b_authority import FencedAuthority
from .inf037b_durable_ports import DurableStore
from .inf037b_eks_fixture import fixture_inventory
from .inf037b_preparation import stage_fixture
from .inf037b_resolver import exact, require


class HostFixtureExecutor:
    def __init__(
        self,
        *,
        binding,
        destination,
        local_source,
        local_mount,
        journal,
        sample,
        stage=stage_fixture,
    ):
        self.binding, self.destination = copy.deepcopy((binding, destination))
        self.source, self.mount = Path(local_source), Path(local_mount)
        exact(str(self.mount), destination["mount_path"], "eks_host:mount")
        self.store, self.sample, self.stage = journal, sample, stage
        with journal.lock():
            state = journal.read()
            original = {"binding": binding, "destination": destination, "source": str(self.source)}
            if "host_binding" not in state:
                state.update(host_binding=original, host_operations={})
                journal.write(state)
            exact(state["host_binding"], original, "eks_host:original")

    def check(self, request):
        exact(request["binding"], self.binding, "eks_host:binding")
        exact(request["destination"], self.destination, "eks_host:destination")
        point = self.sample()
        require(
            self.binding["t0_ms"] <= point["ms"][0] <= point["ms"][1] < request["stop_ms"],
            "eks_host:deadline",
        )

    def effect(self, operation, key, request):
        self.check(request)
        # Replay/export needs the final host's independent store/access and
        # transfer endpoints, sanitizer and sizing proof. No local-copy or
        # maximum substitute is installed while those 4e inputs are absent.
        require(operation == "eks.host.stage", "eks:unfinished:4e_replay_export_pipeline")
        label = sha(encode([operation, key]))
        with self.store.lock():
            state = self.store.read()
            previous = state["host_operations"].get(label)
            require(previous is None, "eks_host:interrupted_no_retry")
            state["host_operations"][label] = {"request": request}
            self.store.write(state)
        exact(
            fixture_inventory(self.source),
            request["expected_inventory"],
            "eks_host:source_inventory",
        )
        result = self.stage(
            source=self.source,
            destination=self.mount,
            expected_inventory=request["expected_inventory"],
            binding=self.binding,
            sample=self.sample,
        )
        exact(
            fixture_inventory(self.mount),
            request["expected_inventory"],
            "eks_host:staged_inventory",
        )
        result.update(destination=self.destination)
        self.check(request)
        with self.store.lock():
            state = self.store.read()
            state["host_operations"][label]["result"] = result
            self.store.write(state)
        return result

    def read(self, operation, key, request):
        self.check(request)
        exact(operation, "eks.host.reverify", "eks_host:operation")
        actual = fixture_inventory(self.mount)
        exact(actual, request["expected_inventory"], "eks_host:reverify_inventory")
        self.check(request)
        return {
            "binding": self.binding,
            "destination": self.destination,
            "actual_inventory": actual,
            "verified": True,
        }

    def reconcile(self, operation, key, request):
        self.check(request)
        with self.store.lock():
            prior = self.store.read()["host_operations"].get(sha(encode([operation, key])))
        if prior is None or "result" not in prior:
            return {"known": False, "executed": False, "result": None}
        exact(prior["request"], request, "eks_host:reconcile_request")
        return {"known": True, "executed": True, "result": prior["result"]}

    def authority(self, directory, identity, *, initialize=False):
        require(isinstance(self.store, DurableStore), "eks_host:durable_journal")
        return FencedAuthority(
            directory,
            identity,
            "eks_host",
            effect=self.effect,
            read=self.read,
            reconcile=self.reconcile,
            initialize=initialize,
        )
