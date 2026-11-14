"""CPU-only real gateway/Redis purpose capture for the D2-prime size inventory.

This is a declared protocol topology, not M5 fitness, workload or GPU evidence.
The real source-current Go gateways and digest-pinned Redis run for the booked
120s configuration window at the production 250ms polling cadence. FakeBackend
stands in for vLLM; its bytes never size a vLLM family. No cap is admitted here.
"""

import argparse
import json
import os
import subprocess
import time
from collections import defaultdict
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from test_admission_process_integration import (
    AdmissionProcessIntegrationTest,
    GatewayProcess,
)
from time_inf037b_wire import owner
from inf037b_purpose_kube import APISERVER, ETCD, kubernetes

from inference_platform.fake_backend import FakeBackend, FakeBackendConfig
from inference_platform.inf037b_archive import encode, file_facts, sha
from inference_platform.inf037b_capture import DeadlineHTTP, wire_records
from inference_platform.inf037b_eks_collectors import (
    GATEWAY_POLL_MS,
    ScopeWindow,
    redis_counts,
)
from inference_platform.inf037b_live import REDIS_SNAPSHOT, RedisWire
from inference_platform.inf037b_producer_contracts import AUDIT_SCRIPT

ROOT = Path(__file__).resolve().parents[1]


def summarize_wire(root):
    groups = defaultdict(
        lambda: {"records": 0, "total_raw_bytes": 0, "max_unit_bytes": 0}
    )
    for record, data in wire_records(Path(root) / "wire"):
        source = record["source"]
        unit = record.get("metadata", {}).get("unit", "read")
        if source == "redis":
            unit = (
                "audit_reply"
                if data.startswith(b"*")
                else "snapshot_reply"
                if data.startswith(b"$")
                else unit
            )
        row = groups[source + ":" + unit]
        row["records"] += 1
        row["total_raw_bytes"] += len(data)
        row["max_unit_bytes"] = max(row["max_unit_bytes"], len(data))
    inventory = {
        p.relative_to(root).as_posix(): file_facts(p)
        for p in sorted((Path(root) / "wire").glob("*"))
    }
    return {
        "groups": dict(sorted(groups.items())),
        "wire_inventory": inventory,
        "wire_inventory_sha256": sha(encode(inventory)),
    }


def capture(output):
    output.mkdir(parents=True, exist_ok=False)
    case = AdmissionProcessIntegrationTest(methodName="runTest")
    case.setUpClass()
    gateways = []
    capture_owner = None
    wire = None
    try:
        # Production retainer and raw/index hashing, not an invented size model.
        sources = {
            name: [
                [
                    name if name in {"redis", "kubernetes"} else "gateway",
                    name,
                    "wire-receipt-boot",
                ]
            ]
            for name in ("gateway0", "gateway1", "redis", "kubernetes")
        }
        capture_owner = owner(output / "owner", sources=sources)
        namespace = "r370-purpose"
        with FakeBackend(FakeBackendConfig()) as backend, ExitStack() as stack:
            for index in range(2):
                environment = {
                    "POD_UID": "purpose-gateway-" + str(index),
                    "GATEWAY_MEASUREMENT_PATH": str(
                        output / ("gateway-" + str(index) + ".jsonl")
                    ),
                    "ADMISSION_CAPACITY_MODE": "dynamic",
                    "ADMISSION_GATEWAY_ID": "purpose-gateway-" + str(index),
                    "ADMISSION_RUNNING": "4",
                    "ADMISSION_WAITING": "1",
                    "ADMISSION_REPORT_TTL": "8s",
                    "ADMISSION_HOLD_DOWN": "2s",
                }
                with patch.dict(os.environ, environment):
                    gateways.append(
                        GatewayProcess(
                            case,
                            case.gateway_executable,
                            backend,
                            case.tenant_config,
                            case.redis_address,
                            namespace,
                            10,
                        )
                    )
            kube = stack.enter_context(
                kubernetes(
                    capture_owner.retainer("kubernetes"),
                    output / "kubernetes-diagnostics",
                )
            )
            start = time.monotonic_ns()
            window = ScopeWindow(
                "configuration_smoke_rollback",
                start,
                start + 120000 * 1000000,
                "Round370-purpose",
            )
            clients = [
                DeadlineHTTP(
                    g.url,
                    stop_ns=window.stop_ns,
                    retain=capture_owner.retainer("gateway" + str(i)),
                    local_test=True,
                )
                for i, g in enumerate(gateways)
            ]
            host, port = case.redis_address.rsplit(":", 1)
            wire = RedisWire(
                host,
                int(port),
                tls=False,
                local_test=True,
                retain=capture_owner.retainer("redis"),
                stop_ns=window.stop_ns,
            )
            wire.bind_scope_contract(redis_counts(window))
            kube_http = DeadlineHTTP(
                kube["base"],
                stop_ns=window.stop_ns,
                retain=capture_owner.retainer("kubernetes"),
                token=lambda: kube["token"],
                ca=kube["ca"],
            )
            offsets = [0, 0]
            maxima, calls = defaultdict(int), defaultdict(int)
            cursor = "0-0"
            prefix = namespace + ":{admission}:"
            for tick in range(window.slots(GATEWAY_POLL_MS)):
                target = start + tick * GATEWAY_POLL_MS * 1000000
                time.sleep(max(0, (target - time.monotonic_ns()) / 1e9))
                for index, client in enumerate(clients):
                    body, headers = client.get(
                        "/internal/measurement?offset=" + str(offsets[index])
                    )
                    offsets[index] = int(headers["X-Capture-Next"])
                    key = "gateway" + str(index) + ".http.periodic_bodies"
                    maxima[key] = max(maxima[key], len(body))
                    calls[key] += 1
                for kind, path in zip(
                    ("pods", "endpointslices"), kube["paths"], strict=True
                ):
                    body, _ = kube_http.get(path)
                    key = "kubernetes." + kind
                    maxima[key] = max(maxima[key], len(body))
                    calls[key] += 1
                wire.command(
                    "EVAL",
                    REDIS_SNAPSHOT,
                    5,
                    prefix + "capacity:reports",
                    prefix + "capacity:lows",
                    prefix + "capacity:state",
                    prefix + "global:active",
                    prefix + "global:active:capture:sequence",
                )
                entries, _ = wire.command(
                    "EVAL", AUDIT_SCRIPT, 1, prefix + "global:active:capture", cursor
                )
                if entries:
                    cursor = entries[-1][0]
            wire.close()
            wire = None
            closed = capture_owner.close()
        result = {
            "schema": "inf037b-producer-purpose-capture-v1",
            "admitted": False,
            "source_commit": subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=ROOT
            )
            .decode()
            .strip(),
            "software": {
                "gateway_executable": file_facts(case.gateway_executable),
                "redis_image": json.loads(
                    (ROOT / "deploy/package-a/pins.json").read_bytes()
                )["redis_image"],
                "kubernetes_image": APISERVER,
                "etcd_image": ETCD,
                "observed_kubernetes_version": kube["version"],
            },
            "kubernetes_periodic_objects": kube["objects"],
            "scope": window.scope,
            "duration_bound_ms": window.duration_ms,
            "poll_ms": GATEWAY_POLL_MS,
            "calls": dict(calls),
            "body_maxima": dict(maxima),
            "transport_clean": closed["transport_clean"],
            **summarize_wire(capture_owner.root),
            "substitutions": [
                "FakeBackend test-model instead of vLLM; no vLLM sizes admitted",
                "AdmissionProcessIntegrationTest launcher/tenant fixture; no M5 workload or fitness claim",
                "Real standalone API/etcd; source-rendered two-slot templates and EndpointSlices, no scheduler/kubelet/running-engine/EKS claim",
            ],
            "remaining": [
                "M5 same-version full vLLM metrics/native bodies",
                "complete Kubernetes control/watch/census/error families",
                "complete remaining source/index shapes",
            ],
        }
        (output / "summary.json").write_bytes(encode(result))
        return result
    finally:
        if wire is not None:
            wire.close()
        for gateway in gateways:
            gateway.stop()
        case.tearDownClass()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = capture(args.output)
    print(
        json.dumps(
            {"transport_clean": result["transport_clean"], "summary": "summary.json"}
        )
    )


if __name__ == "__main__":
    main()
