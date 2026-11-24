"""Bounds, corpus identity and transfer observations for the streaming variant."""

import gzip
import hashlib
import json
import subprocess
import sys
import time
from math import ceil
from pathlib import Path

from .inf060_eks_schedule import LEVELS, SETUP_PHASES, WINDOW_WAIT_SECONDS, prompts, schedule

ARCHIVE_BYTES = 64 * 1024**2
EXPANDED_BYTES = 256 * 1024**2
PROBE_CHUNK_BYTES = 1024**2
WORKLOAD_SECONDS = 4400
TRANSFER_SECONDS = 4416
CLEANUP_SECONDS = 1800
POD_PLANNING_RATE = 150_000
CORPUS_NAME = "streaming-corpus.json.gz"
PHASE_WAITS = {"smoke": 180, "warmup": 300, **dict.fromkeys(LEVELS, WINDOW_WAIT_SECONDS)}


def bound(size, rate):
    if type(size) is not int or not 0 < size <= ARCHIVE_BYTES:
        raise ValueError("streaming_transfer_size")
    if type(rate) is not int or rate <= 0:
        raise ValueError("streaming_transfer_rate")
    return 2 * ceil(size / rate) + 60


def probe_block(offset):
    if type(offset) is not int or offset % PROBE_CHUNK_BYTES or not 0 <= offset < ARCHIVE_BYTES:
        raise ValueError("streaming_probe_offset")
    return hashlib.shake_256(f"inf060-transfer:{offset}".encode()).digest(PROBE_CHUNK_BYTES)


def measure_transfer(read, reopen):
    passes = {}
    for label in ("cold", "resumed"):
        started = time.monotonic()
        reopen()
        actual = hashlib.sha256()
        expected = hashlib.sha256()
        resume_offset = 0
        for offset in range(0, ARCHIVE_BYTES, PROBE_CHUNK_BYTES):
            if label == "resumed" and offset == ARCHIVE_BYTES // 2:
                reopen()
                resume_offset = offset
            received = read(offset)
            wanted = probe_block(offset)
            if received != wanted:
                raise ValueError("streaming_probe_chunk")
            actual.update(received)
            expected.update(wanted)
        elapsed = time.monotonic() - started
        passes[label] = {
            "bytes": ARCHIVE_BYTES,
            "elapsed_s": elapsed,
            "resume_offset": resume_offset,
            "sha256": actual.hexdigest(),
            "rate_bytes_per_s": int(ARCHIVE_BYTES / elapsed),
        }
        if actual.digest() != expected.digest():
            raise ValueError("streaming_probe_digest")
    return {
        "passes": passes,
        "worst_rate_bytes_per_s": min(row["rate_bytes_per_s"] for row in passes.values()),
    }


def transfer_rate(record):
    passes = record["passes"]
    if set(passes) != {"cold", "resumed"}:
        raise ValueError("streaming_probe_passes")
    for name, row in passes.items():
        if (
            row["bytes"] != ARCHIVE_BYTES
            or row["resume_offset"] != (ARCHIVE_BYTES // 2 if name == "resumed" else 0)
            or not row["elapsed_s"] > 0
            or row["rate_bytes_per_s"] != int(ARCHIVE_BYTES / row["elapsed_s"])
        ):
            raise ValueError("streaming_probe_pass")
    rate = min(row["rate_bytes_per_s"] for row in passes.values())
    if not rate or record["worst_rate_bytes_per_s"] != rate:
        raise ValueError("streaming_transfer_rate")
    return rate


def seal_timing(original, *, laptop_rate):
    laptop = bound(ARCHIVE_BYTES, laptop_rate)
    pod = bound(ARCHIVE_BYTES, POD_PLANNING_RATE)
    if laptop + pod > TRANSFER_SECONDS:
        raise ValueError("streaming_final_transfer_reserve")
    components = {
        "workload_s": WORKLOAD_SECONDS,
        "archive_transfers_s": TRANSFER_SECONDS,
        "cleanup_s": CLEANUP_SECONDS,
        "in_session_transfer_probe_s": pod,
        "source_upload_s": original["source_upload_budget_seconds"],
        "initial_startup_s": original["initial_startup_budget_seconds"],
        "apply_through_staging_s": original["apply_through_staging_reserve_seconds"],
    }
    wait = original["session_seconds"] - sum(components.values())
    if wait < 0:
        raise ValueError("streaming_session_budget")
    components["capacity_wait_s"] = wait
    return {
        **original,
        "receipt_limit_bytes": ARCHIVE_BYTES,
        "one_retrieval_seconds": laptop,
        "retrieval_reserve_seconds": laptop + pod,
        "minimum_workload_seconds": WORKLOAD_SECONDS,
        "infrastructure_before_capacity_wait_seconds": components["apply_through_staging_s"] + wait,
        "remaining_infrastructure_seconds": components["apply_through_staging_s"],
        "capacity_wait_budget_seconds": wait,
        "streaming_components": components,
        "streaming_phase_waits": PHASE_WAITS,
    }


def require_window_budget(label, remaining, laptop_rate, pod_rate):
    final = bound(ARCHIVE_BYTES, laptop_rate) + bound(ARCHIVE_BYTES, pod_rate)
    if remaining < PHASE_WAITS[label] + final + CLEANUP_SECONDS:
        raise TimeoutError("streaming_window_guard:" + label)


def file_sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_corpus(path, tokenize):
    rows = [row for label in (*LEVELS, *SETUP_PHASES) for row in schedule(label)]
    with path.open("xb") as output, gzip.GzipFile(fileobj=output, mode="wb", mtime=0) as archive:
        for row, messages in zip(rows, prompts(rows, tokenize), strict=True):
            tokens = tokenize(messages)
            if len(tokens) != row["input_tokens"]:
                raise ValueError("streaming_prompt_length")
            archive.write(
                (json.dumps({"slot": row, "messages": messages}, sort_keys=True) + "\n").encode()
            )
    measured = len(rows) - sum(len(schedule(label)) for label in SETUP_PHASES)
    if measured != 7350 or len({row["alias"] for row in rows}) != len(rows):
        raise ValueError("streaming_corpus_schedule")
    return {
        "sha256": file_sha(path),
        "bytes": path.stat().st_size,
        "measured": measured,
        "setup": len(rows) - measured,
    }


def load_corpus(path, expected, labels):
    if file_sha(path) != expected:
        raise ValueError("streaming_corpus_digest")
    wanted = {row["alias"]: row for label in (*LEVELS, *SETUP_PHASES) for row in schedule(label)}
    corpus = {}
    expanded = 0
    with gzip.open(path, "rb") as archive:
        while raw := archive.readline(16385):
            expanded += len(raw)
            if expanded > ARCHIVE_BYTES or len(raw) > 16384:
                raise ValueError("streaming_corpus_size")
            record = json.loads(raw)
            row = record["slot"]
            if wanted.pop(row["alias"], None) != row:
                raise ValueError("streaming_corpus_schedule")
            if row["level"] in labels:
                corpus[row["alias"]] = record["messages"]
    if wanted:
        raise ValueError("streaming_corpus_schedule")
    return corpus


def main():
    from .stage_c_tokenizer import FILE_HASHES, REVISION, pinned_tokenizer

    output = Path(sys.argv[1])
    receipt = write_corpus(output / CORPUS_NAME, pinned_tokenizer(fetch=True))
    receipt.update(
        source=subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        tokenizer_revision=REVISION,
        tokenizer_files=FILE_HASHES,
    )
    (output / "streaming-corpus.json").write_text(json.dumps(receipt, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
