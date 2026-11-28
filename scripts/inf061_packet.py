"""Sealed DEC-108 variant of the native single-L4 operator."""

import hashlib
import hmac
import json
import re
import shutil
import tarfile
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

SCHEMA = "inf061-native-dec108-v1"
PREFIX = "NATIVE BENCHMARK PLAN APPROVED"
EXTRA = {"benchmark.json", "quality.jsonl"}
EXPORT_MAX = 32 * 1024**2
RECEIPT_PORT = 22282
GATEWAY_START_SECONDS = 60 + 45
CAP_USD = 36
GPU_ZONES = frozenset({"us-east-1b", "us-east-1c", "us-east-1d", "us-east-1f"})
APPLY_ATTEMPTS = 1
DESTROY_ATTEMPTS = 25


def check(ok, reason):
    if not ok:
        raise ValueError("inf061:" + reason)


def is_benchmark(manifest):
    return manifest.get("schema") == SCHEMA


def time_envelope(plan):
    gateway_starts = len(plan["starts"]) + len(plan["stage_c"]["arms"])
    total = (
        sum(plan["deadline_seconds"].values()) + gateway_starts * GATEWAY_START_SECONDS
    )
    check(total <= plan["gpu_timer_s"], "time_envelope")
    return total


def budget(plan, rates):
    gpu = (
        rates["compute_usd_per_h"]
        + 128 / 720 * rates["gp3_usd_per_gib_month"]
        + rates["ipv4_usd_per_h"]
    )
    operator = (
        rates["operator_compute_usd_per_h"]
        + 32 / 720 * rates["gp3_usd_per_gib_month"]
        + rates["ipv4_usd_per_h"]
    )
    limits = plan["deadline_seconds"]
    gpu_timer, cpu_timer = plan["gpu_timer_s"], plan["operator_timer_s"]
    time_envelope(plan)
    hunt = plan.get("capacity_hunt")
    reservation = 0
    if hunt:
        from inf061_capacity import OPERATOR_SECONDS, RESERVATION_EXTRA_S, options

        check(hunt == options() and cpu_timer == OPERATOR_SECONDS, "capacity_envelope")
        reservation = RESERVATION_EXTRA_S / 3600 * rates["compute_usd_per_h"]
    else:
        check(cpu_timer == 47800, "time_envelope")
    check(gpu_timer == 45120, "time_envelope")
    cost = round(
        2
        * 1.25
        * (gpu_timer / 3600 * gpu + cpu_timer / 3600 * operator + reservation + 0.50),
        6,
    )
    prior = plan.get("prior_paid_estimate_usd", 0)
    check(type(prior) in (int, float) and 0 <= prior < CAP_USD, "prior_spend")
    remaining = round(CAP_USD - prior, 6)
    check(
        plan["cap_usd"] == CAP_USD and plan["forecast_usd"] == cost <= remaining,
        "cost_envelope",
    )
    check(
        [(a["precision"], a["max_num_seqs"]) for a in plan["starts"]]
        == [("bf16", 16), ("bf16", 32), ("bf16", 64), ("fp8", 64), ("awq", 64)]
        and plan["starts"][-1]["argv"][-2:] == ["--quantization", "awq_marlin"],
        "engine_order",
    )
    return {
        "deadline_seconds": gpu_timer,
        "host_timer_seconds": gpu_timer,
        "cleanup_seconds": limits["teardown"],
        "inventory_reserve_seconds": 60,
        "ready_by_seconds": limits["provision_and_stage"],
        "work_seconds": gpu_timer - limits["teardown"],
        "export_seconds": limits["retrieval"],
        "export_max_bytes": EXPORT_MAX,
        "weights_timeout_s": 1200,
        "upload_timeout_s": 360,
        "live_hourly_usd": gpu,
        "hourly_all_resources_usd": gpu,
        "forecast_usd": cost,
        "hard_cap_usd": remaining,
    }


def approval_line(manifest, digest):
    return (
        f"{PREFIX} manifest={digest} plan={manifest['sealed_plans']['create_sha256']} "
        f"operator={manifest['operator_host']['create_sha256']} source={manifest['source_commit']}"
    )


def capture(source, destination):
    """Publish only allowlisted result members, with no extraction or raw logs."""
    names = re.compile(
        r"results/(?:benchmark|model-readback|tsdb-receipt|native-method-calls|operation-stage-models|"
        r"gateway-(?:env|sanity)-(?:(?:bf16-(?:16|32|64)|fp8-64|awq-64)-gateway|stage-c-[0-3])|"
        r"(?:bf16-(?:16|32|64)|fp8-64|awq-64)-(?:a-(?:1|3|6|12)|b-(?:4|64)|c-(?:b_alone|a_at_quota|a_flood_quota|a_flood_lifted))|"
        r"quality-(?:bf16-first|bf16-repeat|fp8|awq)|timing-[a-z0-9-]+)\.json"
    )
    seen = set()
    with (
        tarfile.open(source, "r:gz") as incoming,
        tarfile.open(destination, "x:gz") as out,
    ):
        for member in incoming:
            tsdb = member.name in {"results/tsdb.tar.gz", "results/tsdb.tar.gz.sha256"}
            if not tsdb and not names.fullmatch(member.name):
                continue
            check(
                member.isfile()
                and member.name not in seen
                and member.size <= EXPORT_MAX,
                "receipt_member",
            )
            seen.add(member.name)
            with incoming.extractfile(member) as stream:
                if tsdb:
                    out.addfile(member, stream)
                else:
                    raw = stream.read()
                    check(isinstance(json.loads(raw), dict), "receipt_shape")
                    import io

                    out.addfile(member, io.BytesIO(raw))
    check(destination.stat().st_size <= EXPORT_MAX and seen, "receipt_bound")
    with destination.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    return {
        "status": "available",
        "sha256": digest,
        "bytes": destination.stat().st_size,
        "files": sorted(seen),
    }


def serve(receipt, token_file, lifetime=600):
    key = token_file.read_text().strip()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            return

        def do_GET(self):
            if self.path != "/receipt" or not hmac.compare_digest(
                self.headers.get("Authorization", ""), "Bearer " + key
            ):
                self.send_error(403)
                return
            self.send_response(200)
            self.send_header("Content-Length", str(receipt.stat().st_size))
            self.end_headers()
            with receipt.open("rb") as stream:
                shutil.copyfileobj(stream, self.wfile, 1024**2)

    with HTTPServer(("127.0.0.1", RECEIPT_PORT), Handler) as server:
        server.timeout = min(600, lifetime)
        server.handle_request()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("receipt", type=Path)
    parser.add_argument("token_file", type=Path)
    args = parser.parse_args()
    serve(args.receipt, args.token_file)
