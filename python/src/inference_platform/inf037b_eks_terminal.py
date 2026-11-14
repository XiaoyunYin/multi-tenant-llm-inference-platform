"""Terminal composition for the existing dispatcher, not another cleanup loop.

Deployment supplies the scoped provider, recovery ownership and EXPORT authority.
Small local protocol tests do not establish real empty cloud inventories.
"""

import copy
import time
from pathlib import Path

from .inf037b_archive import encode, file_facts, sha, strict_json, verify_archive
from .inf037b_resolver import exact, require
from .inf037b_setup_observations import inventory
from .inf037b_terminal import INVENTORIES, SnapshotProducer, rehearse
from .inf037b_transfer import SocketArchiveTransfer, persist_to_both


class TerminalReceiver:
    """Receiver-side commit after the existing bounded socket receiver closes.

    The secured authority invokes this with the received paths, never paths from
    a remote sender. Store ownership and lifecycle are supplied by 4c; this class
    deliberately has no per-session bucket/volume deletion operation.
    """

    def __init__(self, *, store_ports, max_total_bytes, max_objects, clock):
        self.store_ports = store_ports
        self.max_total_bytes, self.max_objects = max_total_bytes, max_objects
        self.clock = clock

    def commit(self, artifacts, manifest, stop):
        require(self.clock() < stop, "eks:terminal_receiver_deadline")
        exact(
            {key: file_facts(Path(path)) for key, path in artifacts.items()},
            manifest,
            "eks:terminal_received_inventory",
        )
        result = persist_to_both(
            artifacts=artifacts,
            max_total_bytes=self.max_total_bytes,
            max_objects=self.max_objects,
            **self.store_ports,
        )
        exact(
            result["source_manifest_sha256"], sha(encode(manifest)), "eks:terminal_store_manifest"
        )
        readbacks = {}
        for name in ("recovery", "s3"):
            readbacks[name] = {
                key: file_facts(Path(path)) for key, path in result[name]["readback"].items()
            }
            exact(readbacks[name], manifest, "eks:terminal_store_readback:" + name)
        require(self.clock() <= stop, "eks:terminal_receiver_deadline")
        return {
            "manifest_sha256": sha(encode(manifest)),
            "readbacks": readbacks,
            "acknowledgements": {"recovery": True, "s3": True},
        }


class TerminalBackend:
    def __init__(self, factory, authority):
        self.factory, self.authority = factory, authority

    def retain(self, kind, descriptor, *, result=None, error=None):
        # Preserve failure facts before TerminalAdapters reports/refuses. This
        # is the reopened operation journal, not an unbudgeted live wire sink.
        store = self.factory.port.store
        with store.lock():
            state = store.read()
            state["values"].setdefault("terminal/receipts", []).append(
                copy.deepcopy(
                    {"kind": kind, "descriptor": descriptor, "result": result, "error": error}
                )
            )
            store.write(state)

    def _read(self, category, scope, stop):
        self.authority.scope(scope)
        require(category in (*INVENTORIES, "capacity_inventory"), "eks:terminal_category")
        port = self.factory.port
        port.deadline(stop)
        with port.store.lock():
            result = port.query(
                port.store.read(),
                "eks.terminal.inventory",
                category,
                {"binding": self.factory.binding, "scope": scope, "stop_ms": stop},
            )
        port.deadline(stop, completed=True)
        return result

    def _observation(self, category, scope, stop):
        result, error = None, None
        try:
            result = self._read(category, scope, stop)
            exact(result["complete"], True, "eks:terminal_inventory_incomplete")
            exact(result["scope_sha256"], sha(encode(scope)), "eks:terminal_inventory_scope")
            if category != "capacity_inventory":
                require(type(result["resources"]) is list, "eks:terminal_inventory_rows")
            return result
        except Exception as exc:
            error = type(exc).__name__ + ":" + str(exc)
            raise
        finally:
            self.retain(
                "inventory",
                {"category": category, "scope": scope, "stop_ms": stop},
                result=result,
                error=error,
            )

    def inventory(self, category, scope, stop):
        return self._observation(category, scope, stop)

    def capacity_inventory(self, scope, stop):
        return self._observation("capacity_inventory", scope, stop)

    def snapshot(self, scope, stop):
        """Nonmutating O_i model only; SetupCommands uses this same inventory."""
        data = SnapshotProducer(self, self.factory.clock).produce(scope, stop)
        model = rehearse(data)
        self.retain(
            "cleanup_snapshot",
            {"stop_ms": stop},
            result={"snapshot_hex": data.hex(), "model": model},
        )
        return data, model

    def effect(self, label, key, body, stop):
        result, error = None, None
        try:
            if label == "export":
                result = self.export(key, body, stop)
            else:
                result = self.authority.effect(label, key, body, stop)
            return result
        except Exception as exc:
            error = type(exc).__name__ + ":" + str(exc)
            raise
        finally:
            self.retain(
                "effect",
                {"label": label, "key": key, "body": body, "stop_ms": stop},
                result=result,
                error=error,
            )

    def export(self, key, body, stop):
        f = self.factory
        self.authority.scope(body["scope"])
        exact(key, f.port.driver_key + ":export:export", "eks:terminal_effect_key")
        f.port.deadline(stop)
        ownership = f.dependency("4c_recovery_stores")(stop)
        permission = f.dependency("4d_export_permission")(stop)
        for proof in (ownership, permission):
            exact(proof["binding"], f.binding, "eks:terminal_export_binding")
            exact(
                proof["destination"],
                body["scope"]["state_destination"],
                "eks:terminal_export_destination",
            )
        from .inf037b_eks_placement import join_permission

        join_permission(permission, f)
        # Part 3/4c must supply the sealed, materialized, sanitized campaign.
        # No maximum fixture or cooked replacement result is manufactured here.
        inputs = f.dependency("4c_terminal_export_inputs")(stop)
        exact(inputs["binding"], f.binding, "eks:terminal_export_inputs")
        root = Path(inputs["sanitized"])
        verified = verify_archive(root)
        require(
            not any(row["integrity_errors"] for row in verified["segments"].values()),
            "eks:terminal_archive_integrity",
        )
        exact(
            strict_json((root / "registration.json").read_bytes())["sanitized"],
            True,
            "eks:terminal_sanitized",
        )
        manifest = inventory(root)
        exact(manifest, inputs["inventory"], "eks:terminal_export_inventory")
        from .inf037b_eks_stores import facts

        retained = inputs["retained_artifacts"]
        retained_manifest = facts(retained) if retained else {}
        exact(retained_manifest, inputs["retained_manifest"], "eks:terminal_retained_inventory")
        require(not (set(manifest) & set(retained)), "eks:terminal_artifact_collision")
        artifacts = {key: root / key for key in manifest}
        artifacts.update(retained)
        manifest.update(retained_manifest)
        runtime = f.dependency("terminal_export_transport")(stop)
        from .inf037b_eks_execution import join_execution

        join_execution(runtime, f, "terminal_export_transport")
        require(
            isinstance(runtime["transfer"], SocketArchiveTransfer), "eks:terminal_socket_transfer"
        )
        # Sample monotonic first: computation cannot extend the absolute cutoff.
        anchor = time.monotonic()
        remaining = (stop - f.clock()) / 1000
        require(remaining > 0, "eks:deadline")
        transferred = runtime["transfer"].transfer(
            artifacts,
            runtime["address"],
            transfer_id=sha(encode([f.binding, key])),
            max_total_bytes=runtime["max_total_bytes"],
            max_objects=runtime["max_objects"],
            deadline_monotonic=anchor + remaining,
        )
        exact(transferred["manifest"], manifest, "eks:terminal_transfer_inventory")
        self.retain("transfer", {"key": key, "stop_ms": stop}, result=transferred)
        # The existing fenced authority settles a lost commit reply, instead of
        # running the store effect again. Both real readbacks must join the bytes.
        committed = f.port.effect(
            "eks.terminal.commit_export",
            key,
            {
                "binding": f.binding,
                "stop_ms": stop,
                "body": body,
                "transfer_id": transferred["transfer_id"],
                "manifest": manifest,
            },
            stop,
        )
        exact(committed["manifest_sha256"], sha(encode(manifest)), "eks:terminal_commit_manifest")
        exact(
            committed["acknowledgements"], {"recovery": True, "s3": True}, "eks:terminal_two_stores"
        )
        for name in ("recovery", "s3"):
            exact(committed["readbacks"][name], manifest, "eks:terminal_readback:" + name)
        f.port.deadline(stop, completed=True)
        return {
            "request_key": key,
            "body_sha256": sha(encode(body)),
            "accepted": True,
            "verified": True,
            "manifest_sha256": sha(encode(manifest)),
            "destination": body["scope"]["state_destination"],
            "transfer": transferred,
            "stores": committed,
        }
