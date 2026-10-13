"""No-cost failure probe of the current Stage C serializer, NOT admission sizing.

The draft has no executable remainder producer yet. Do not turn a small digest
that omits required evidence into a worst-case PASS. Exit 2 means the sizing
prerequisite remains blocked; output includes measurements and counterexamples.
No AWS, Docker, model server, or external network is used.
"""

import argparse
import gzip
import hashlib
import json
import random
import shutil
import subprocess
import tarfile
import tempfile
import threading
import time
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

from inference_platform.kv_event_capture import token_block_digests
from inference_platform.stage_c_digest import (
    DIGEST_LIMIT,
    FINAL_LIMIT,
    compact,
    measurement_digest,
    seal_digest,
)
from inference_platform.stage_c_session import export


def encoded(value):
    return json.dumps(value, separators=(",", ":"), allow_nan=False).encode()


def sizes(value):
    data = encoded(value)
    return {
        "raw_json_bytes": len(data),
        "standalone_gzip_bytes": len(gzip.compress(data, mtime=0)),
    }


def distribution(value):
    return {
        "total": sizes(value),
        "sections": {key: sizes(child) for key, child in value.items()},
    }


def write_rows(path, rows):
    path.write_bytes(b"".join(encoded(row) + b"\n" for row in rows))


class Tokenizer(BaseHTTPRequestHandler):
    def do_POST(self):
        value = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        index = int(value["messages"][0]["content"])
        data = encoded({"tokens": [index * 1000 + n for n in range(32)]})
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_args):
        pass


def exact_lag_probe(root, number, url, artifacts):
    """Exercise actual export_decisions/load/correlate/measurement_digest/seal.

    Six distinct identities cover every current correlation disposition. Exact
    rows are read from the host archive ONLY to demonstrate their absence from
    the recovered gzip; they are never used to repair recovered evidence.
    """
    session = root / f"lag-run-{number}"
    session.mkdir()
    (session / "private").mkdir()
    wall = time.time_ns()
    offset = wall - time.perf_counter_ns()
    records, terminals, prompts, events = [], [], [], []
    for i in range(6):
        identity = hashlib.sha256(f"run-{number}-request-{i}".encode()).hexdigest()[:32]
        decision = wall + i * 3_000_000_000
        terminal = decision + 200_000_000 + i * 97_321
        stamp = datetime.fromtimestamp(terminal // 10**9, UTC).strftime(
            "%Y-%m-%dT%H:%M:%S"
        )
        terminals.append(
            {
                "msg": "request terminal",
                "request_id": identity,
                "router_decision_unix_ns": decision,
                "time": f"{stamp}.{terminal % 10**9:09d}Z",
                "committed": i != 2,
                "cause": "cancelled" if i == 2 else "completed",
            }
        )
        prompt = {
            "request_id": identity,
            "model": "synthetic-local-tokenizer",
            "messages": [{"role": "user", "content": str(i)}],
            "outcome": "cancelled" if i == 2 else "completed",
            "first_content_received": i != 2,
        }
        if i in (1, 3):
            prompt["cached_prompt_tokens"] = 32 if i == 1 else 0
        prompts.append(prompt)
        records.append(
            {
                "request_id": identity,
                "dispatch_offset_ns": i * 3_000_000_000 + 93_627,
                "first_content_offset_ns": i * 3_000_000_000 + 90_123_456
                if i != 2
                else None,
                "completion_offset_ns": i * 3_000_000_000 + 200_000_000 + i * 97_321,
                "outcome": prompt["outcome"],
                "http_status": 200 if i != 2 else None,
                "prompt_tokens": 32,
                "completion_tokens": 1 if i != 2 else None,
            }
        )
        if i in (0, 5):
            events.append(
                {
                    "event_type": "BlockStored",
                    "sequence": 9_876_543_210 + i,
                    "observed_monotonic_ns": decision
                    - offset
                    + (50_987_321 if i == 0 else 1_500_987_321),
                    "token_block_digests": token_block_digests(
                        [i * 1000 + n for n in range(32)]
                    ),
                }
            )
    write_rows(session / "gateway.log", terminals)
    write_rows(session / "prompts.jsonl", prompts)
    write_rows(session / "fake-events.jsonl", events)
    run = {
        "status": "completed",
        "effective_deadline_monotonic_s": time.perf_counter() + 60,
        "levels": [{"concurrency": 4, "records": records}],
    }
    value = measurement_digest(
        session,
        run,
        session,
        SimpleNamespace(
            decision_prompt_export_path=str(session / "prompts.jsonl"), tokenize_url=url
        ),
    )
    exact = [
        json.loads(line)
        for line in (session / "event-lag-correlations.jsonl").read_text().splitlines()
    ]
    expected = {
        "observed",
        "observed_after_request_window",
        "no_new_block",
        "no_store_expected_request_failed",
        "no_post_decision_store_event",
        "no_identity_specific_store_cache_state_unknown",
    }
    assert {row["status"] for row in exact} == expected
    before = json.loads(encoded(value))
    path = session / "digest.gz"
    receipt = seal_digest(path, value)
    recovered = json.loads(gzip.decompress(path.read_bytes()))
    assert recovered == before  # Exact round-trip of what the serializer emits.
    assert "detail_degradation" not in recovered
    assert "request_id" not in encoded(recovered["event_lag"]).decode()
    shutil.copyfile(path, artifacts / f"run-{number}.current.digest.json.gz")
    (artifacts / f"run-{number}.expected-lag.json").write_bytes(encoded(exact) + b"\n")
    return {
        "input_requests": len(records),
        "host_exact_lag_rows": len(exact),
        "host_exact_lag_sections": sizes(exact),
        "host_lag_status_counts": recovered["event_lag"]["status_counts"],
        "serialized_projection_round_trip": True,
        "exact_lag_rows_recovered": 0,
        "exact_lag_input_round_trip": False,
        "omission_flag": None,
        "receipt": receipt,
        "distribution": distribution(recovered),
    }


def protected_fixture(rng):
    """All registered row counts, plausible varied populations; NOT a byte maximum.

    A 50 ms synthetic serial cadence exercises every outcome category. This is
    not a new frozen workload cadence or a claim about real vLLM performance.
    Structural zeros (drain dispatch, pending finalization) must stay zero.
    """
    result = {
        "schema": "rewarm_convergence_compact.v1",
        "header": {
            "prompt_sha256": rng.randbytes(32).hex(),
            "replica": "engine-0",
            "counter_labels": [
                "vllm:prefix_cache_hits_total",
                "vllm:prefix_cache_queries_total",
            ],
            "clock": "same-host monotonic ns",
            "outcomes": [
                "completed",
                "pre-content-rejection",
                "in-stream-error",
                "timeout",
                "cancelled",
                "partial",
                "drain-cut",
                "transport-error",
                "unknown",
                "pending",
            ],
        },
        "reset_rows": [],
        "cold_rows": [],
        "window_rows": [],
        "histogram_rows": [],
    }
    for reset in range(3):
        start = 8_731_982_100_000_000 + reset * 270 * 10**9 + rng.randrange(10**6)
        result["reset_rows"].append(
            [
                reset,
                rng.randbytes(16).hex(),
                "success",
                True,
                start - 20 * 10**9,
                start,
                start + 120 * 10**9,
                start + 240 * 10**9,
                True,
                None,
                start + 120 * 10**9,
                "unestablished",
            ]
        )
        dispatch = [[0] * 10 for _ in range(240)]
        final = [[0] * 10 for _ in range(240)]
        for b in range(120):
            for _ in range(rng.randrange(10, 21)):
                outcome = rng.randrange(10)
                dispatch[b][outcome] += 1
                if outcome != 9:
                    end = 239 if outcome == 6 else b + rng.randrange(0, 121)
                    final[end][outcome] += 1
        assert sum(map(sum, dispatch)) == sum(map(sum, final)) + sum(
            row[9] for row in dispatch
        )
        for b in range(240):
            result["histogram_rows"].append([reset, b, True, *dispatch[b], *final[b]])
        q, h = 8 * 34, 7 * 32
        for window in range(12):
            n = sum(map(sum, dispatch[window * 10 : (window + 1) * 10]))
            final_n = sum(map(sum, final[window * 10 : (window + 1) * 10]))
            t = start + window * 10 * 10**9
            result["window_rows"].append(
                [
                    reset,
                    window,
                    t,
                    t + 10 * 10**9,
                    t + rng.randrange(10**6),
                    t + 10 * 10**9 + rng.randrange(10**6),
                    h,
                    h + n * 32,
                    q,
                    q + n * 34,
                    n * 32,
                    n * 34,
                    n,
                    final_n,
                    True,
                    True,
                    False,
                    window == 7,
                    "partial" if window == 7 else "complete",
                ]
            )
            q, h = q + n * 34, h + n * 32
        for cold in range(8):
            t = start - (8 - cold) * 2 * 10**9
            cold_q, cold_h = cold * 34, max(0, cold - 1) * 32
            result["cold_rows"].append(
                [
                    reset,
                    cold,
                    rng.randbytes(16).hex(),
                    t,
                    t + rng.randrange(10**6, 10**8),
                    t + rng.randrange(10**8, 10**9),
                    "completed",
                    cold_q,
                    cold_q + 34,
                    cold_h,
                    cold_h + (32 if cold else 0),
                    34,
                    32 if cold else 0,
                    True,
                    True,
                    False,
                    None,
                    t - 71_321,
                    t + 1_000_000_791,
                    34,
                    1,
                    "observed",
                    "valid",
                    "engine-0",
                ]
            )
    return result


def branch_probe(root, mode, artifacts):
    """Non-repetitive synthetic branch stress, NOT registered run cardinality."""
    rng = random.Random(470142)
    count = 40_000 if mode == "verbose" else 100_000 if mode == "overflow" else 24
    records = []
    for i in range(count):
        dispatch = rng.randrange(10**12, 4_800 * 10**9)
        records.append(
            {
                "request_id": rng.randbytes(16).hex(),
                "outcome": "completed" if i % 7 else "cancelled",
                "dispatch_offset_ns": dispatch,
                "first_content_offset_ns": dispatch + rng.randrange(10**6, 10**11),
                "completion_offset_ns": dispatch + rng.randrange(10**11, 180 * 10**9),
                "prompt_tokens": 6144,
                "completion_tokens": rng.randrange(1, 129),
            }
        )
    protected = protected_fixture(random.Random(470143))
    run = {
        "status": "completed",
        "records": records,
        "rewarm_convergence_compact": protected,
    }
    if mode in ("native", "verbose"):
        run["metrics"] = [
            {
                "offset_ns": i * 100_000_000 + rng.randrange(100_000),
                "values": {f"vllm:stress_{j}": rng.random() for j in range(4)},
            }
            for i in range(100_000)
        ]
    projected = compact(run)
    value = {
        "schema": "inf011-measurement-digest.v2",
        "run": projected,
        "event_lag": {"status": "unestablished"},
    }
    # Use the actual request_table inside seal_digest, not a surrogate table.
    from inference_platform.stage_c_digest import request_table

    value["per_request"] = request_table(projected)
    initial = distribution(value)
    essential_before = encoded(value["per_request"])
    protected_before = encoded(protected)
    path = root / f"branch-{mode}.gz"
    failure = None
    try:
        receipt = seal_digest(path, value)
    except ValueError as error:
        receipt, failure = None, str(error)
    recovered = (
        json.loads(gzip.decompress(path.read_bytes())) if path.exists() else None
    )
    if recovered:
        shutil.copyfile(path, artifacts / path.name)
        assert encoded(recovered["per_request"]) == essential_before
        assert (
            encoded(recovered["run"]["rewarm_convergence_compact"]) == protected_before
        )
    assert encoded(value["run"]["rewarm_convergence_compact"]) == protected_before
    if mode == "native":
        assert recovered["detail_degradation"]["native_sample_detail_dropped"]
        assert not recovered["detail_degradation"].get(
            "verbose_request_detail_dropped", False
        )
    if mode == "verbose":
        assert recovered["detail_degradation"]["verbose_request_detail_dropped"]
    if mode == "overflow":
        assert (
            failure and not path.exists() and not path.with_suffix(".pending").exists()
        )
    return {
        "mode": mode,
        "synthetic_branch_request_count": count,
        "registered_full_run_sizing": False,
        "initial": initial,
        "final": distribution(recovered) if recovered else distribution(value),
        "receipt": receipt,
        "error": failure,
        "flags": value.get("detail_degradation"),
        "compressed_file_recoverable": recovered is not None,
        "essential_table_byte_identical": recovered is not None,
        "injected_protected_byte_identical": recovered is not None,
        "protected_injected_fixture": distribution(protected),
        "protected_compressed_limit_bytes": 480_000,
        "protected_production_producer_exists": False,
    }, protected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    artifacts = args.output.parent
    repository = Path(__file__).resolve().parents[1]
    result = {
        "schema": "stage-c-remainder-retention-failure-probe.v1",
        "status": "BLOCKED",
        "full_worst_case_sizing": "NOT_ESTABLISHED",
        "base_commit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=repository, text=True
        ).strip(),
        "limits": {
            "digest_bytes": DIGEST_LIMIT,
            "run3_protected_bytes": 480_000,
            "final_metadata_bytes": FINAL_LIMIT,
            "export_seconds": 600,
        },
        "source_sha256": {},
    }
    for name in (
        "stage_c_digest.py",
        "stage_c.py",
        "calibration.py",
        "decision_export.py",
        "kv_event_capture.py",
        "disk_correlation.py",
        "stage_c_session.py",
        "stage_c_transport.py",
        "disk_records.py",
        "failure_taxonomy.py",
    ):
        path = repository / "python/src/inference_platform" / name
        result["source_sha256"][path.relative_to(repository).as_posix()] = (
            hashlib.sha256(path.read_bytes()).hexdigest()
        )
    for relative in (
        "scripts/probe_stage_c_remainder_retention.py",
        "docs/INF047_STAGE_C_REMAINDER_PREREGISTRATION.md",
    ):
        result["source_sha256"][relative] = hashlib.sha256(
            (repository / relative).read_bytes()
        ).hexdigest()
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        server = ThreadingHTTPServer(("127.0.0.1", 0), Tokenizer)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}"
            result["run_lag_probes"] = {
                str(n): exact_lag_probe(root, n, url, artifacts) for n in (3, 4)
            }
        finally:
            server.shutdown()
            server.server_close()
            worker.join()
        result["degradation_probes"] = []
        for mode in ("none", "native", "verbose", "overflow"):
            row, protected = branch_probe(root, mode, artifacts)
            result["degradation_probes"].append(row)
        (artifacts / "protected.injected-fixture.json").write_bytes(
            encoded(protected) + b"\n"
        )
        # Exercise the real final exporter, including tar headers/checksums, with
        # the injected table. There is no production receipt-only projection yet.
        session = root / "final"
        session.mkdir()
        manifest = root / "manifest.json"
        manifest.write_text("{}", encoding="utf-8")
        (session / "stage-c-summary.json").write_bytes(
            encoded(
                compact(
                    {"timed_runs": [{"rewarm_convergence_compact": protected}]},
                    measurements=False,
                )
            )
        )
        try:
            final_receipt = export(session, manifest)
            with tarfile.open(session / "evidence.tar.gz", "r:gz") as archive:
                raw = sum(
                    member.size for member in archive.getmembers() if member.isfile()
                )
            result["final_export_probe"] = {
                "receipt": {**final_receipt, "archive": "final-metadata.tar.gz"},
                "raw_member_bytes": raw,
                "raw_tar_bytes": len(
                    gzip.decompress((session / "evidence.tar.gz").read_bytes())
                ),
                "member_sizes": {
                    item.name: {
                        "raw_bytes": item.stat().st_size,
                        "standalone_gzip_bytes": len(
                            gzip.compress(item.read_bytes(), mtime=0)
                        ),
                    }
                    for item in (session / "export").iterdir()
                    if item.is_file()
                },
            }
            shutil.copyfile(
                session / "evidence.tar.gz", artifacts / "final-metadata.tar.gz"
            )
        except ValueError as error:
            result["final_export_probe"] = {
                "error": str(error),
                "compressed_archive_deleted": not (
                    session / "evidence.tar.gz"
                ).exists(),
                "note": "Current compact(false) duplicates the table; receipt-only production metadata is unimplemented. This fixture is not a full metadata maximum.",
                "summary": sizes(
                    json.loads((session / "stage-c-summary.json").read_bytes())
                ),
            }
    result["transfer_arithmetic"] = {
        "basis": "Arithmetic, not measured link throughput; no AWS or SSM command",
        "forward_payload_bytes_per_second": 500_000,
        "one_max_digest_forward_seconds": DIGEST_LIMIT / 500_000,
        "four_max_digests_plus_metadata_forward_seconds": (
            4 * DIGEST_LIMIT + FINAL_LIMIT
        )
        / 500_000,
        "metadata_fallback_bytes_per_second": 100,
        "max_metadata_fallback_seconds": FINAL_LIMIT / 100,
        "digest_command_chunk_bytes": 12_288,
        "assumed_command_seconds": 2.4,
        "one_max_digest_commands_seconds": ((DIGEST_LIMIT + 12_287) // 12_288) * 2.4,
        "last_max_digest_plus_max_metadata_seconds": ((DIGEST_LIMIT + 12_287) // 12_288)
        * 2.4
        + FINAL_LIMIT / 100,
        "all_four_max_digests_plus_max_metadata_seconds": 4
        * ((DIGEST_LIMIT + 12_287) // 12_288)
        * 2.4
        + FINAL_LIMIT / 100,
    }
    result["blockers"] = [
        "Neither source path produces the draft remainder registration, protected Run 3 table or Run 4 patched arm/snapshots/joins.",
        "Exact matched/excluded lag rows are absent even before degradation, without an omission flag; summary round-trip is not input-evidence round-trip.",
        "Draft does not bind all request/snapshot/sideband/clock/manifest cardinalities and encoded fields to an executable serializer; full worst-case bytes cannot be certified.",
        "Injected protected field survives existing per-run branches, but final compact(false) has no receipt-only production projection; a small injected fixture does not establish the full final metadata maximum.",
        "Essential overflow raises and removes pending output; the direct seal does not emit a durable overflow receipt. Checkpoint salvage remains a separate path.",
    ]
    args.output.write_bytes(
        json.dumps(result, indent=2, sort_keys=True).encode() + b"\n"
    )
    print(
        f"BLOCKED: full Run 3/Run 4 sizing NOT ESTABLISHED; measured failure probes: {args.output}"
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
