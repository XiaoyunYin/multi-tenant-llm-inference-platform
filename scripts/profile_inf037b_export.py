"""Offline R366 phase measurements; never supplies a live allowance or plan.

Build the registered fixture once, then take deterministic stratified row samples.
Instrumentation wraps existing calls, without replacing their implementations.
"""

import argparse
import contextlib
import functools
import gc
import hashlib
import json
import platform
import shutil
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path[:0] = [
    str(REPO / "python/src"),
    str(REPO / "python/tests"),
    str(REPO / "scripts"),
]

from time_inf037b_three_attempts import build  # noqa: E402

from inference_platform import inf037b_campaign as campaign  # noqa: E402
from inference_platform import inf037b_packet as packet  # noqa: E402
from inference_platform import inf037b_setup_observations as observations  # noqa: E402
from inference_platform.inf037b_archive import file_facts  # noqa: E402


class Timings:
    def __init__(self):
        self.calls = []
        self.stack = []

    @contextlib.contextmanager
    def span(self, name):
        parent = self.stack[-1] if self.stack else None
        self.stack.append(name)
        start = time.perf_counter()
        try:
            yield
        finally:
            self.calls.append(
                {
                    "phase": name,
                    "parent": parent,
                    "seconds": time.perf_counter() - start,
                }
            )
            self.stack.pop()
            if parent in ("capture_export", "sanitized_campaign"):
                print(json.dumps(self.calls[-1]), flush=True)

    @contextlib.contextmanager
    def instrument(self, raw):
        patches = []

        def patch(owner, name, label):
            original = getattr(owner, name)

            @functools.wraps(original)
            def wrapped(*args, **kwargs):
                phase = label(*args, **kwargs) if callable(label) else label
                with self.span(phase):
                    return original(*args, **kwargs)

            setattr(owner, name, wrapped)
            patches.append((owner, name, original))

        patch(
            campaign,
            "reproduce",
            lambda root, spec: (
                f"{'raw' if root == raw else 'sanitized'}_reproduce_spec_{spec['attempt_index']}"
            ),
        )
        patch(
            campaign.OfflineCampaign,
            "report",
            lambda self: (
                f"{'raw' if self.root == raw else 'sanitized'}_report_spec_{self.spec['attempt_index']}"
            ),
        )
        patch(packet, "sanitized_sources", "sanitized_sources")
        patch(campaign, "materialize_bundle", "materialize_bundle")
        patch(
            observations,
            "verify_archive",
            lambda root: (
                "capture_verify_source" if root == raw else "capture_verify_sanitized"
            ),
        )
        patch(observations, "inventory", lambda root: "capture_inventory_" + root.name)
        patch(
            observations,
            "export_archive",
            lambda _src, _dst, **kw: (
                "transfer_interrupted" if kw else "transfer_resume_and_verify_readback"
            ),
        )
        try:
            yield
        finally:
            for owner, name, original in reversed(patches):
                setattr(owner, name, original)


def sample_fixture(full, destination, fraction):
    """Keep contiguous blocks spread across each segment, in original order.

    Journals/specs/expected offers and all registered numbers remain unchanged.
    Missing sampled observations are adverse data, not a valid campaign claim.
    """
    destination.mkdir()
    for directory in ("raw", "cohorts", "events"):
        (destination / directory).mkdir()
    for name in ("registration.json", "attempts.jsonl"):
        shutil.copyfile(full / name, destination / name)
    (destination / "cohorts/requests.jsonl").touch()
    counts = {}
    for source in sorted((full / "raw").glob("*.jsonl")):
        with source.open("rb") as stream:
            total = sum(1 for _ in stream)
        blocks = min(20, max(1, total // 1000))
        keep = 0
        with (
            source.open("rb") as stream,
            (destination / "raw" / source.name).open("wb") as target,
        ):
            for index, line in enumerate(stream):
                block = index * blocks // total
                start = (block * total + blocks - 1) // blocks
                end = ((block + 1) * total + blocks - 1) // blocks
                if index - start < (end - start) * fraction // 100:
                    target.write(line)
                    keep += 1
        counts[source.name] = {"full": total, "sample": keep, "blocks": blocks}
    return counts


def run(work, output, fractions):
    work.mkdir(parents=True, exist_ok=True)
    full = work / "full"
    print("building registered fixture outside all export timers", flush=True)
    specs, count = build(full, reset_ms=300_000, include_reset_capture=True)
    if count != 701_418:
        raise RuntimeError(f"registered row count differs: {count}")
    source_files = {
        p.relative_to(full).as_posix(): file_facts(p)
        for p in full.rglob("*")
        if p.is_file()
    }
    receipt = {
        "schema": "inf037b-r366-profile-v1",
        "python": platform.python_version(),
        "platform": platform.platform(),
        "cpu_max": Path("/sys/fs/cgroup/cpu.max").read_text().strip(),
        "memory_max": Path("/sys/fs/cgroup/memory.max").read_text().strip(),
        "full_rows": count,
        "full_source_files": source_files,
        "source_sha256": {
            str(p.relative_to(REPO)).replace("\\", "/"): hashlib.sha256(
                p.read_bytes()
            ).hexdigest()
            for p in [
                Path(__file__),
                REPO / "scripts/time_inf037b_three_attempts.py",
                *sorted((REPO / "python/src/inference_platform").glob("*.py")),
                REPO / "python/tests/test_inf037b_collectors.py",
            ]
        },
        "samples": [],
    }
    for fraction in fractions:
        raw, safe, destination = [
            work / f"{kind}-{fraction}" for kind in ("raw", "safe", "destination")
        ]
        counts = sample_fixture(full, raw, fraction)
        print(f"materializing {fraction}% sample outside export timer", flush=True)
        campaign.materialize_bundle(raw, specs)
        gc.collect()
        timings = Timings()

        def sanitize(source, target):
            with timings.span("sanitized_campaign"):
                return campaign.sanitized_campaign(
                    source, target, specs, key=b"step5-sizing-key-only" * 2
                )

        with timings.instrument(raw), timings.span("capture_export"):
            captured, artifacts = observations.capture_export(
                binding={},
                source=raw,
                sanitized=safe,
                destination=destination,
                sanitize=sanitize,
                sample=lambda: {"monotonic_ns": time.monotonic_ns()},
                reconnect_ms=1_000,
            )
        sample = {
            "fraction_percent": fraction,
            "row_counts": counts,
            "raw_rows": sum(c["sample"] for c in counts.values()),
            "calls": timings.calls,
            "sanitized_bytes": sum(
                file_facts(p)["bytes"] for p in safe.rglob("*") if p.is_file()
            ),
            "capture_sha256": hashlib.sha256(captured).hexdigest(),
            "artifact_count": len(artifacts),
        }
        receipt["samples"].append(sample)
        output.write_text(json.dumps(receipt, indent=2) + "\n")
        print(
            json.dumps(
                {
                    "fraction": fraction,
                    "rows": sample["raw_rows"],
                    "calls": timings.calls,
                }
            ),
            flush=True,
        )
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--fractions", type=int, nargs="+", default=[5, 10, 25])
    args = parser.parse_args()
    run(args.work, args.output, args.fractions)
