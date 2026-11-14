"""Synthetic engine inputs using the archived exact label vocabulary."""

import gzip
import hashlib
import json
from functools import cache
from pathlib import Path

from test_eks_package_a import INPUTS

from inference_platform.eks_deployment import resources

ROOT = Path(__file__).resolve().parents[2]


def pod():
    workload = next(
        x
        for x in resources(INPUTS, "runtime-code")["items"]
        if x["kind"] == "StatefulSet" and x["metadata"]["name"] == "vllm"
    )
    return {
        "metadata": {"uid": "uid0", "name": "vllm-0", "resourceVersion": "17"},
        "spec": workload["spec"]["template"]["spec"],
        "status": {
            "containerStatuses": [
                {
                    "name": "vllm",
                    "state": {"running": {}},
                    "restartCount": 0,
                    "containerID": "containerd://engine0",
                    "imageID": "sha256:" + "a" * 64,
                }
            ]
        },
    }


@cache
def cache_labels():
    # The published primary digest contains byte-identical labels to the private
    # derived chart. Keep these transport/parser fixtures usable in either tree.
    raw = (ROOT / "experiments/r0/attempt7/run-1.digest.json.gz").read_bytes()
    if hashlib.sha256(raw).hexdigest() != (
        "15f74651acf0264e405bbd91d7957da9c43d10053c247800f9f2afd86d6f1328"
    ):
        raise ValueError("fixture:archived_cache_source")
    recorded = json.loads(gzip.decompress(raw))
    metrics = recorded["run"]["levels"][0]["native_metric_aggregates"]
    sources = [key for key in metrics if key.startswith("vllm0:vllm:cache_config_info{")]
    if len(sources) != 1:
        raise ValueError("fixture:archived_cache_labels_unique")
    source = sources[0]
    return source[source.index("{") + 1 : -1]
