"""Portable files/ack identities for local protocol tests, never S3 evidence."""

import copy
from pathlib import Path

from inference_platform.inf037b_archive import encode, sha
from inference_platform.inf037b_eks_stores import facts


def store_binding(root, controller, pins):
    policy = dict.fromkeys(("access", "retention", "ownership", "cost"), "a" * 64)
    return {
        "schema": "inf037b-recovery-stores-v1",
        "controller": copy.deepcopy(controller),
        "pins": copy.deepcopy(pins),
        "recovery": {
            "identity": "test-volume",
            "owner": "test-operator",
            "root": str(Path(root) / "unit-recovery"),
            "outside_destroyed_resources": True,
            "failure_domain": "test-volume-domain",
            "policy_sha256": policy,
        },
        "s3": {
            "identity": "test-external",
            "owner": "test-custodian",
            "bucket": "test-only-bucket",
            "prefix": "test/session",
            "secured": True,
            "outside_session_failure_domains": True,
            "failure_domain": "test-external-domain",
            "policy_sha256": policy,
            "versioning": "off",
        },
    }


def portable_persist(artifacts, binding, root):
    manifest = facts(artifacts)
    digest = sha(encode(manifest))
    copies, readbacks = {}, {}
    for name in ("recovery", "s3"):
        base = Path(binding["recovery"]["root"]) if name == "recovery" else Path(root) / "unit-s3"
        copies[name], readbacks[name] = {}, {}
        for key, source in artifacts.items():
            target = base / "objects" / digest / key
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(Path(source).read_bytes())
            readback = base / "readback" / digest / key
            readback.parent.mkdir(parents=True, exist_ok=True)
            readback.write_bytes(target.read_bytes())
            copies[name][key], readbacks[name][key] = target, readback

    def ack(key, value):
        return {
            "bucket": binding["s3"]["bucket"],
            "key": key,
            **value,
            "etag": "opaque-test-etag",
            "request_id": sha(encode([key, value])),
            "version_id": None,
        }

    prefix = binding["s3"]["prefix"]
    index = encode({"schema": "inf037b-s3-archive-manifest-v1", "manifest": manifest})
    return {
        "source_manifest_sha256": digest,
        "recovery": {
            "manifest": {
                key: {"path": str(copies["recovery"][key]), **value}
                for key, value in manifest.items()
            },
            "readback": readbacks["recovery"],
        },
        "s3": {
            "receipt": {
                "schema": "inf037b-s3-archive-receipt-v1",
                "bucket": binding["s3"]["bucket"],
                "prefix": prefix,
                "manifest_sha256": digest,
                "objects": {
                    key: ack(prefix + "/" + digest + "/" + key, value)
                    for key, value in manifest.items()
                },
                "manifest_object": ack(
                    prefix + "/manifests/" + sha(index) + ".json",
                    {"bytes": len(index), "sha256": sha(index)},
                ),
            },
            "readback": readbacks["s3"],
        },
    }
