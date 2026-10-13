"""Measure the authenticated service-to-generator chunk path without touching logs or AWS."""

import argparse
import base64
import hashlib
import json
import os
import time
from pathlib import Path

from .r1_spec import encoded
from .r1_transport import private_url, request


def measure(service_agent, token, samples=32, timeout=60):
    private_url(service_agent)
    if type(samples) is not int or not 4 <= samples <= 256 or not 0 < timeout <= 600:
        raise ValueError("probe requires 4..256 chunks and a 0..600 s absolute budget")
    started, captured = time.perf_counter(), time.time()
    deadline = started + timeout
    expected = bytes(range(256)) * 4096
    digest = hashlib.sha256(expected).hexdigest()
    records = []
    for _ in range(samples):
        stamp = time.perf_counter()
        status, body = request(
            service_agent + "/export/probe",
            deadline,
            {"length": len(expected)},
            token,
            max_seconds=timeout,
        )
        if status != 200:
            raise ValueError("export probe refused")
        chunk = json.loads(body)
        content = base64.b64decode(chunk["base64"], validate=True)
        if (
            chunk["offset"] != 0
            or chunk["size"] != len(expected)
            or chunk["bytes"] != len(expected)
            or chunk["sha256"] != digest
            or hashlib.sha256(content).hexdigest() != digest
            or content != expected
        ):
            raise ValueError("export probe chunk integrity failed")
        elapsed = time.perf_counter() - stamp
        if time.perf_counter() > deadline:
            raise TimeoutError("export probe absolute deadline exceeded")
        records.append(
            {
                "raw_bytes": len(content),
                "wire_bytes": len(body),
                "elapsed_s": elapsed,
                "raw_bytes_per_second": len(content) / elapsed,
            }
        )
    # Raw bytes are more conservative than base64 wire throughput used by export.
    floor = int(min(row["raw_bytes_per_second"] for row in records) / 2)
    if floor <= 0:
        raise ValueError("export probe measured no usable throughput")
    source = (
        f"authenticated 1MiB chunk probe at {captured}; half slowest raw rate; receipt SHA below"
    )
    receipt = {
        "schema": "r1-export-probe.v1",
        "captured_at_unix_s": captured,
        # EC2 returns a private DNS name here. Never collect it into an exportable
        # receipt; role/process identity is already recorded by the host agent.
        "generator_hostname": "redacted-at-source",
        "service_agent": service_agent,
        "loopback": service_agent.startswith("http://127."),
        "samples": records,
        "elapsed_s": time.perf_counter() - started,
        "absolute_budget_s": timeout,
        "minimum_bytes_per_second": floor,
    }
    receipt_sha = hashlib.sha256(encoded(receipt)).hexdigest()
    return {
        **receipt,
        "measurement_sha256": receipt_sha,
        "agent_config": {
            "export_minimum_bytes_per_second": floor,
            "export_link_rate_source": source + ": " + receipt_sha,
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--service-agent", required=True)
    parser.add_argument("--token-env", default="R1_AGENT_TOKEN")
    parser.add_argument("--samples", type=int, default=32)
    parser.add_argument("--timeout", type=float, default=60)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError("probe receipt must use a new path")
    receipt = measure(args.service_agent, os.environ[args.token_env], args.samples, args.timeout)
    args.output.write_bytes(encoded(receipt) + b"\n")
    print(json.dumps(receipt["agent_config"]))


if __name__ == "__main__":
    main()
