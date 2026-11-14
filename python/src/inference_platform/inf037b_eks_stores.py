"""4c ownership-bound manifests and two-store acknowledgement/recovery joins.

Real store/mount/access authority is a 4d input. Production persistence uses
DurableStore and Part 4 persist_to_both; portable test seams claim neither S3
durability nor POSIX-directory fencing.
"""

import copy
import http.client
import ssl
import uuid
from pathlib import Path
from urllib.parse import quote, urlsplit

from .inf037b_archive import durable_write, encode, file_facts, safe_file, sha
from .inf037b_resolver import SessionDeadline, exact, require
from .inf037b_transfer import _safe_key, persist_to_both


def facts(artifacts):
    require(type(artifacts) is dict and bool(artifacts), "4c:artifact_set")
    result = {}
    for key, path in artifacts.items():
        _safe_key(key)
        path = Path(path)
        require(path.is_file() and not path.is_symlink(), "4c:artifact_file")
        result[key] = file_facts(path)
    return dict(sorted(result.items()))


def serial(value):
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {k: serial(v) for k, v in value.items()}
    if isinstance(value, list):
        return [serial(v) for v in value]
    return value


def validate_binding(binding):
    exact(binding["schema"], "inf037b-recovery-stores-v1", "4c:store_schema")
    for name in ("recovery", "s3"):
        store = binding[name]
        for field in ("identity", "owner", "failure_domain"):
            require(type(store[field]) is str and bool(store[field]), "4c:store_identity")
        for field in ("access", "retention", "ownership", "cost"):
            digest = store["policy_sha256"][field]
            require(
                type(digest) is str
                and len(digest) == 64
                and set(digest) <= set("0123456789abcdef"),
                "4c:store_policy",
            )
    require(binding["recovery"]["outside_destroyed_resources"] is True, "4c:recovery_ownership")
    require(
        binding["s3"]["secured"] is True
        and binding["s3"]["outside_session_failure_domains"] is True,
        "4c:external_ownership",
    )
    require(
        binding["recovery"]["failure_domain"] != binding["s3"]["failure_domain"],
        "4c:independent_stores",
    )
    require(binding["recovery"]["identity"] != binding["s3"]["identity"], "4c:distinct_stores")
    require(binding["s3"]["versioning"] in ("enabled", "off"), "4c:version_policy")
    require(
        bool(binding["recovery"]["root"])
        and bool(binding["s3"]["bucket"])
        and bool(binding["s3"]["prefix"]),
        "4c:store_location",
    )
    return binding


def _s3_ack(ack, store, key, expected):
    exact(ack["bucket"], store["bucket"], "4c:s3_bucket")
    exact(ack["key"], key, "4c:s3_key")
    exact({k: ack[k] for k in ("bytes", "sha256")}, expected, "4c:s3_ack_facts")
    require(
        all(type(ack[k]) is str and bool(ack[k]) for k in ("etag", "request_id")),
        "4c:s3_ack_identity",
    )
    if store["versioning"] == "enabled":
        require(type(ack["version_id"]) is str and bool(ack["version_id"]), "4c:s3_version")
    else:
        exact(ack["version_id"], None, "4c:s3_unversioned")


def validate_receipt(receipt, binding, manifest):
    validate_binding(binding)
    exact(receipt["stores_binding_sha256"], sha(encode(binding)), "4c:receipt_store_binding")
    exact(receipt["manifest"], manifest, "4c:receipt_manifest")
    exact(receipt["source_manifest_sha256"], sha(encode(manifest)), "part3:store_manifest_join")
    recovery = receipt["recovery"]["manifest"]
    exact(set(recovery), set(manifest), "4c:recovery_inventory")
    root = Path(binding["recovery"]["root"]).resolve()
    for key, expected in manifest.items():
        exact({k: recovery[key][k] for k in ("bytes", "sha256")}, expected, "4c:recovery_facts")
        require(Path(recovery[key]["path"]).resolve().is_relative_to(root), "4c:recovery_path")
    external = receipt["s3"]["receipt"]
    store = binding["s3"]
    exact(external["schema"], "inf037b-s3-archive-receipt-v1", "4c:s3_schema")
    exact(external["bucket"], store["bucket"], "4c:s3_bucket")
    exact(external["prefix"], store["prefix"], "4c:s3_prefix")
    digest = sha(encode(manifest))
    exact(external["manifest_sha256"], digest, "4c:s3_manifest")
    exact(set(external["objects"]), set(manifest), "4c:s3_inventory")
    for key, expected in manifest.items():
        _s3_ack(
            external["objects"][key], store, store["prefix"] + "/" + digest + "/" + key, expected
        )
    index = encode({"schema": "inf037b-s3-archive-manifest-v1", "manifest": manifest})
    _s3_ack(
        external["manifest_object"],
        store,
        store["prefix"] + "/manifests/" + sha(index) + ".json",
        {"bytes": len(index), "sha256": sha(index)},
    )
    exact(
        receipt["acknowledgements"],
        {
            "recovery": {
                "store_id": binding["recovery"]["identity"],
                "version": digest,
                "receipt_sha256": sha(encode(recovery)),
            },
            "s3": {"store_id": store["identity"], "receipt_sha256": sha(encode(external))},
        },
        "4c:acknowledgement_join",
    )


def seal_receipt(native, binding, artifacts):
    require(
        type(native) is dict
        and {"recovery", "s3", "source_manifest_sha256"} <= native.keys()
        and {"manifest", "readback"} <= native["recovery"].keys()
        and {"receipt", "readback"} <= native["s3"].keys(),
        "part3:both_store_receipts",
    )
    manifest = facts(artifacts)
    value = serial(copy.deepcopy(native))
    value.update(manifest=manifest, stores_binding_sha256=sha(encode(validate_binding(binding))))
    value["acknowledgements"] = {
        "recovery": {
            "store_id": binding["recovery"]["identity"],
            "version": sha(encode(manifest)),
            "receipt_sha256": sha(encode(value["recovery"]["manifest"])),
        },
        "s3": {
            "store_id": binding["s3"]["identity"],
            "receipt_sha256": sha(encode(value["s3"]["receipt"])),
        },
    }
    validate_receipt(value, binding, manifest)
    for name in ("recovery", "s3"):
        exact(facts(value[name]["readback"]), manifest, "4c:store_readback:" + name)
    return value


def join_access(accessed, receipt, binding):
    manifest = facts(accessed["export_artifacts"])
    # This join must be recomputed on the controller, not trusted from the host.
    validate_receipt(receipt, binding, manifest)
    for name in ("recovery", "s3"):
        exact(facts(accessed["store_readbacks"][name]), manifest, "4c:access_readback:" + name)
    return manifest


class RecoveryRepository:
    def __init__(
        self,
        *,
        binding,
        journal,
        store_ports,
        access,
        clock,
        metadata_root,
        persist=persist_to_both,
        reconcile=None,
    ):
        self.binding = copy.deepcopy(validate_binding(binding))
        self.journal, self.store_ports, self.accessor, self.clock = (
            journal,
            store_ports,
            access,
            clock,
        )
        self.metadata_root, self.persist, self.reconcile = Path(metadata_root), persist, reconcile
        require(
            self.metadata_root.resolve().is_relative_to(
                Path(binding["recovery"]["root"]).resolve()
            ),
            "4c:metadata_ownership",
        )
        with journal.lock():
            state = journal.read()
            state.setdefault("4c_stores", {"binding": self.binding, "publications": {}})
            exact(state["4c_stores"]["binding"], self.binding, "4c:reopen_binding")
            journal.write(state)

    def publish(self, key, artifacts, stop):
        require(self.clock() < stop, "4c:publication_deadline")
        request = {"manifest": facts(artifacts), "stores_binding_sha256": sha(encode(self.binding))}
        with self.journal.lock():
            state = self.journal.read()
            rows = state["4c_stores"]["publications"]
            old = rows.get(key)
            if old is not None:
                exact(old["request"], request, "4c:publication_immutable")
                if "receipt" not in old:
                    require(self.reconcile is not None, "4c:publication_pending")
                    recovered = self.reconcile(key, copy.deepcopy(request), stop)
                    require(recovered.get("known") is True, "4c:publication_pending")
                    validate_receipt(recovered["receipt"], self.binding, request["manifest"])
                    old["receipt"] = recovered["receipt"]
                    self.journal.write(state)
            else:
                old = rows[key] = {"request": request}
                self.journal.write(state)
                try:
                    native = self.persist(artifacts=artifacts, **self.store_ports)
                    old["receipt"] = seal_receipt(native, self.binding, artifacts)
                except Exception as exc:
                    old["error"] = type(exc).__name__ + ":" + str(exc)
                    self.journal.write(state)
                    raise
                self.journal.write(state)
            require(self.clock() <= stop, "4c:publication_deadline")
            return copy.deepcopy(old["receipt"])

    def access(self, receipt, stop):
        require(self.clock() < stop, "4c:access_deadline")
        validate_receipt(receipt, self.binding, receipt["manifest"])
        readbacks = self.accessor(receipt, stop)
        accessed = {"export_artifacts": readbacks["recovery"], "store_readbacks": readbacks}
        join_access(accessed, receipt, self.binding)
        require(self.clock() <= stop, "4c:access_deadline")
        return accessed


class ArtifactHTTPAccess:
    """Stream exact objects to local paths; never open a remote path as local."""

    def __init__(self, url, *, token, root, clock, timeout_s=2, ca=None, local_test=False):
        self.url, self.token, self.root, self.clock, self.timeout_s = (
            urlsplit(url),
            token,
            Path(root),
            clock,
            timeout_s,
        )
        require(
            self.url.scheme == "https"
            or (local_test and self.url.scheme == "http" and self.url.hostname == "127.0.0.1"),
            "4c:access_https",
        )
        require(
            not (self.url.query or self.url.fragment or self.url.username or self.url.password),
            "4c:access_url",
        )
        self.context = ssl.create_default_context(cafile=ca)

    def __call__(self, receipt, stop):
        result = {}
        destination = self.root / uuid.uuid4().hex
        for store in ("recovery", "s3"):
            result[store] = {}
            for key, expected in receipt["manifest"].items():
                _safe_key(key)
                remaining = (stop - self.clock()) / 1000
                require(remaining > 0, "4c:access_deadline")
                cls = (
                    http.client.HTTPSConnection
                    if self.url.scheme == "https"
                    else http.client.HTTPConnection
                )
                options = {"context": self.context} if self.url.scheme == "https" else {}
                connection = cls(
                    self.url.hostname,
                    self.url.port,
                    timeout=min(remaining, self.timeout_s),
                    **options,
                )
                try:
                    path = (
                        self.url.path.rstrip("/")
                        + "/"
                        + sha(encode(receipt["manifest"]))
                        + "/"
                        + store
                        + "/"
                        + quote(key, safe="/")
                    )
                    connection.request(
                        "GET", path, headers={"Authorization": "Bearer " + self.token()}
                    )
                    response = connection.getresponse()
                    require(response.status == 200, "4c:access_missing")
                    exact(
                        response.getheader("Content-Length"),
                        str(expected["bytes"]),
                        "4c:access_length",
                    )
                    target = safe_file(destination / store, key)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    count = 0
                    with target.open("xb") as stream:
                        while chunk := response.read(min(1048576, expected["bytes"] - count + 1)):
                            require(self.clock() < stop, "4c:access_deadline")
                            count += len(chunk)
                            require(count <= expected["bytes"], "4c:access_length")
                            stream.write(chunk)
                    exact(file_facts(target), expected, "4c:access_hash")
                    result[store][key] = target
                finally:
                    connection.close()
        return result


class RecoveryPorts:
    def __init__(self, factory):
        self.factory = factory

    def repository(self, name, stop):
        f = self.factory
        f.port.deadline(stop)
        binding = f.config.get("recovery_store_binding")
        require(binding is not None, "eks:unfinished:" + name)
        runtime = f.dependency("4d_recovery_store_runtime")(stop)
        from .inf037b_eks_execution import join_execution

        join_execution(runtime, f, "4d_recovery_store_runtime")
        repository = runtime["repository"]
        require(isinstance(repository, RecoveryRepository), "4c:repository")
        exact(repository.binding, binding, "4c:runtime_binding")
        exact(binding["controller"], f.binding, "4c:controller_binding")
        exact(binding["pins"], f.config["pins"], "4c:pin_binding")
        f.port.deadline(stop, completed=True)
        return repository

    def export_stores(self, request):
        f = self.factory
        repo = self.repository("4c_export_stores", request["stop_ms"])
        exact(
            request["binding"],
            {
                "session_id": f.binding["session_id"],
                "t0_ms": f.binding["t0_ms"],
                "pins": f.config["pins"],
            },
            "4c:export_binding",
        )
        return copy.deepcopy(repo.binding)

    def artifact_access(self, result, stop):
        value = self.repository("4c_export_artifact_access", stop).access(
            result["store_receipt"], stop
        )
        self.factory.port.deadline(stop, completed=True)
        return value

    def recovery_stores(self, stop):
        f = self.factory
        f.port.deadline(stop)
        repo = self.repository("4c_recovery_stores", stop)
        return {
            "binding": f.binding,
            "destination": f.config["state_destination"],
            "stores": copy.deepcopy(repo.binding),
        }

    def supervisor(self, stop):
        f = self.factory
        repo = self.repository("4c_recovery_supervisor", stop)
        backstop = f.controller.backstop
        with backstop.store.lock():
            checkpoint = backstop.store.read()
        deadline = SessionDeadline(
            f.binding["C_ms"], f.binding["D_session_ms"], f.binding["t0_ms"]
        ).effective_ms
        exact(
            checkpoint["values"]["deadline/" + f.binding["session_id"]],
            deadline,
            "4c:supervisor_deadline",
        )
        data = encode(
            {
                "binding": f.binding,
                "authority_id": backstop.authority.identity,
                "checkpoint": checkpoint,
                "D_eff_ms": deadline,
            }
        )
        path = repo.metadata_root / (sha(data) + ".json")
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            exact(path.read_bytes(), data, "4c:supervisor_checkpoint")
        else:
            durable_write(path, data)
        receipt = repo.publish(
            "supervisor:" + f.binding["session_id"], {"control/supervisor.json": path}, stop
        )
        repo.access(receipt, stop)
        f.port.deadline(stop, completed=True)
        return {
            "binding": f.binding,
            "D_eff_ms": deadline,
            "authority_id": backstop.authority.identity,
            "checkpoint_sha256": sha(data),
            "store_receipt": receipt,
        }
