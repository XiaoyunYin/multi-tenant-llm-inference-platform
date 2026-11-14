"""Verify pinned producer shapes/vocabulary; no traffic, sizing, Docker or AWS."""

import argparse
import hashlib
import json
from pathlib import Path

from inference_platform.eks_deployment import VLLM_IMAGE
from inference_platform.inf037b_archive import encode
from inference_platform.inf037b_native import BASE_FILES
from inference_platform.inf037b_producer_contracts import (
    TOKEN_BYTES,
    audit_reply_contract,
    client_contract,
)
from inference_platform.stage_c_tokenizer import FILE_HASHES, REVISION, verified_files


PLATFORM_SOURCES = {
    "http-client-3.12.7.py": (
        "https://github.com/python/cpython/blob/v3.12.7/Lib/http/client.py",
        "d78f92c3b6e5aa778d2ec8ef7faa14d6005a2ba7784d9e69fd872ecc81287774",
    ),
    "kube-validation-v1.34.0.go": (
        "https://github.com/kubernetes/kubernetes/blob/v1.34.0/staging/src/k8s.io/apimachinery/pkg/util/validation/validation.go",
        "5c2a8c1bbe4916bcb0db626b5249ca83b7510b0e338978e6aab9bb8f6cd1a32f",
    ),
    "kube-objectmeta-v1.34.0.go": (
        "https://github.com/kubernetes/kubernetes/blob/v1.34.0/staging/src/k8s.io/apimachinery/pkg/api/validation/objectmeta.go",
        "b73dedf36f43e167cf4726b1455420faeb04d5ad55eddfd1cd5395746741bb55",
    ),
    "kube-rest-meta-v1.34.0.go": (
        "https://github.com/kubernetes/kubernetes/blob/v1.34.0/staging/src/k8s.io/apiserver/pkg/registry/rest/meta.go",
        "ef3164db168de9c1cacdf5620dd096a06744ef71dad278604c48012323941b39",
    ),
}


def proof(vllm_source, tokenizer, image_metadata, platform_sources):
    from tokenizers import Tokenizer

    image = json.loads(Path(image_metadata).read_bytes())
    digest = VLLM_IMAGE.split("@", 1)[1]
    if image["root"] != digest:
        raise ValueError("producer_sources:image")
    bodies = image["registry_bodies"]
    for expected, raw_body in bodies.items():
        if "sha256:" + hashlib.sha256(raw_body.encode()).hexdigest() != expected:
            raise ValueError("producer_sources:oci_hash")
    manifest = json.loads(bodies[digest])
    if "manifests" in manifest:
        child = next(
            x
            for x in manifest["manifests"]
            if x.get("platform", {}).get("architecture") == "amd64"
            and x.get("platform", {}).get("os") == "linux"
        )
        manifest = json.loads(bodies[child["digest"]])
    config_digest = manifest["config"]["digest"]
    config = json.loads(bodies[config_digest])
    commit = config["config"]["Labels"]["ai.vllm.build.commit"]
    if commit != "98dff2a81d747d1dba01a47f939f48c3526d4206":
        raise ValueError("producer_sources:commit")
    relative = "vllm/entrypoints/openai/chat_completion/serving.py"
    raw = (Path(vllm_source) / relative).read_bytes().replace(b"\r\n", b"\n")
    if hashlib.sha256(raw).hexdigest() != BASE_FILES[relative]:
        raise ValueError("producer_sources:serving")
    files = verified_files(Path(tokenizer))
    decoder = Tokenizer.from_str(files["tokenizer.json"].decode())
    lengths = [
        (len(decoder.decode([i], skip_special_tokens=False).encode()), i)
        for i in decoder.get_vocab().values()
    ]
    longest, identity = max(lengths)
    if longest != TOKEN_BYTES:
        raise ValueError("producer_sources:token_bytes")
    platform = {}
    for name, (url, expected) in PLATFORM_SOURCES.items():
        raw_source = (Path(platform_sources) / name).read_bytes()
        if hashlib.sha256(raw_source).hexdigest() != expected:
            raise ValueError("producer_sources:platform_hash:" + name)
        platform[name] = {"url": url, "sha256": expected}
    return {
        "schema": "inf037b-producer-source-derivation-v1",
        "platform_sources": platform,
        "basis": "pinned static source/vocabulary enumeration; not a measured response size",
        "image": {
            "digest": digest,
            "config_digest": config_digest,
            "commit": commit,
            "source": "python/src/inference_platform/eks_deployment.py:11",
        },
        "serving": {
            "path": relative,
            "lf_sha256": BASE_FILES[relative],
            "lines": [450, 530, 578, 710, 814, 870, 904, 910],
        },
        "tokenizer": {
            "revision": REVISION,
            "files": FILE_HASHES,
            "longest_decoded_utf8_bytes": longest,
            "witness_token_id": identity,
            "vocabulary_count": len(lengths),
        },
        "trace": client_contract(1),
        "control": client_contract(64),
        "audit": audit_reply_contract(),
        "census": {
            "node_pod_limit": None,
            "refusal": "capture:unresolved:producer_limits",
            "page_formula": "ceil((node_pod_limit + terminal_pods)/100)+1",
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vllm-source", type=Path, required=True)
    parser.add_argument("--tokenizer", type=Path, required=True)
    parser.add_argument("--image-metadata", type=Path, required=True)
    parser.add_argument("--platform-sources", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.write_bytes(
        encode(
            proof(
                args.vllm_source,
                args.tokenizer,
                args.image_metadata,
                args.platform_sources,
            )
        )
    )


if __name__ == "__main__":
    main()
