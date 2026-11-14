"""Offline performance experiment, not a production sanitizer or live adapter.

Retain all accepted calls, with fresh-byte-hash memoization and fsync batching
inside sanitization/materialization only. Final file/directory sync is timed.
"""

import argparse
import contextlib
import copy
import hashlib
import json
import os
import resource
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import profile_inf037b_export as profile  # noqa: E402

from inference_platform import inf037b_archive as archive  # noqa: E402
from inference_platform import inf037b_stream as stream  # noqa: E402


def facts(root, paths=None):
    return {
        p.relative_to(root).as_posix(): archive.file_facts(p)
        for p in sorted(paths if paths is not None else root.rglob("*"))
        if p.is_file()
    }


def batch(function):
    """Scratch batching, synchronizing all touched files before return."""
    original_sync = os.fsync

    def wrapped(*args, **kwargs):
        paths = set()

        def defer(fd):
            paths.add(Path(os.readlink(f"/proc/self/fd/{fd}")))

        with patch.object(os, "fsync", defer):
            result = function(*args, **kwargs)
        for path in sorted(paths):
            with path.open("rb") as handle:
                original_sync(handle.fileno())
        for path in sorted({p.parent for p in paths}):
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
            try:
                original_sync(fd)
            finally:
                os.close(fd)
        return result

    return wrapped


@contextlib.contextmanager
def candidate_operations():
    """Scratch experiment; patches are process-local and restored on exit."""
    verified, reports = {}, {}
    original_verify = archive.verify_archive
    original_report = profile.campaign.OfflineCampaign.report

    def verify(root, **kwargs):
        observed = facts(root)
        key = (root.resolve(), archive.sha(archive.encode(observed)))
        if key not in verified:
            verified[key] = original_verify(root, **kwargs)
            if observed != facts(root):
                raise RuntimeError("candidate verification input changed")
        return copy.deepcopy(verified[key])

    def report(self):
        paths = [
            self.root / "registration.json",
            self.root / "attempts.jsonl",
            *(self.root / "raw").rglob("*"),
        ]
        observed = facts(self.root, paths)
        key = (
            self.root.resolve(),
            archive.sha(archive.encode(self.spec)),
            archive.sha(archive.encode(observed)),
        )
        if key not in reports:
            value = original_report(self)
            if observed != facts(self.root, paths):
                raise RuntimeError("candidate report input changed")
            reports[key] = (value, self.archive_derived_reasons)
        value, reasons = copy.deepcopy(reports[key])
        self.archive_derived_reasons = reasons
        return value

    with contextlib.ExitStack() as stack:
        for module in (
            archive,
            stream,
            profile.campaign,
            profile.packet,
            profile.observations,
        ):
            stack.enter_context(patch.object(module, "verify_archive", verify))
        stack.enter_context(
            patch.object(profile.campaign.OfflineCampaign, "report", report)
        )
        stack.enter_context(
            patch.object(
                profile.packet,
                "sanitized_sources",
                batch(profile.packet.sanitized_sources),
            )
        )
        stack.enter_context(
            patch.object(
                profile.campaign,
                "materialize_bundle",
                batch(profile.campaign.materialize_bundle),
            )
        )
        yield


class CPUTimings(profile.Timings):
    @contextlib.contextmanager
    def span(self, name):
        start = resource.getrusage(resource.RUSAGE_SELF)
        with super().span(name):
            yield
        end = resource.getrusage(resource.RUSAGE_SELF)
        self.calls[-1]["cpu_seconds"] = (
            end.ru_utime + end.ru_stime - start.ru_utime - start.ru_stime
        )


def run(
    raw_root, baseline, work, output, fractions, optimize, prepare=False, spec_root=None
):
    receipt = json.loads(baseline.read_text())
    if prepare:
        receipt["samples"] = []
        initial_specs = [
            json.loads(p.read_bytes())
            for p in sorted(
                (spec_root or raw_root / "raw-5/events").glob("*.spec.json")
            )
        ]
        for fraction in fractions:
            raw = raw_root / f"raw-{fraction}"
            counts = profile.sample_fixture(raw_root / "full", raw, fraction)
            # Fixture preparation is excluded from every capture timer. All
            # touched files are fsynced before the accepted operation is timed.
            batch(profile.campaign.materialize_bundle)(raw, initial_specs)
            receipt["samples"].append(
                {
                    "fraction_percent": fraction,
                    "row_counts": counts,
                    "raw_rows": sum(c["sample"] for c in counts.values()),
                }
            )
    else:
        receipt["samples"] = [
            s for s in receipt["samples"] if s["fraction_percent"] in fractions
        ]
    receipt["experiment"] = (
        "fresh-hash-cache-and-batched-sync"
        if optimize
        else "quiet-repeat-accepted-path"
    )
    receipt["experiment_source_sha256"] = hashlib.sha256(
        Path(__file__).read_bytes()
    ).hexdigest()
    receipt["source_sha256"]["scripts/profile_inf037b_export_candidate.py"] = receipt[
        "experiment_source_sha256"
    ]
    receipt["source_sha256"]["scripts/profile_inf037b_export.py"] = hashlib.sha256(
        Path(profile.__file__).read_bytes()
    ).hexdigest()
    receipt["sampling_method"] = (
        "up to 20 contiguous blocks spread across each raw segment; verbatim rows, unchanged journal/specs/offers"
    )
    work.mkdir(parents=True, exist_ok=True)
    for sample in receipt["samples"]:
        fraction = sample["fraction_percent"]
        if fraction not in fractions:
            continue
        raw, safe, destination = (
            raw_root / f"raw-{fraction}",
            work / f"safe-{fraction}",
            work / f"destination-{fraction}",
        )
        specs = [
            json.loads(p.read_bytes())
            for p in sorted((raw / "events").glob("*.spec.json"))
        ]
        timings = CPUTimings()

        def sanitize(source, target):
            with timings.span("sanitized_campaign"):
                return profile.campaign.sanitized_campaign(
                    source, target, specs, key=b"step5-sizing-key-only" * 2
                )

        context = candidate_operations() if optimize else contextlib.nullcontext()
        with context, timings.instrument(raw), timings.span("capture_export"):
            captured, artifacts = profile.observations.capture_export(
                binding={},
                source=raw,
                sanitized=safe,
                destination=destination,
                sanitize=sanitize,
                sample=lambda: {},
                reconnect_ms=1_000,
            )
        sample["calls"] = timings.calls
        sample["capture_sha256"] = hashlib.sha256(captured).hexdigest()
        sample["artifact_count"] = len(artifacts)
        sample["sanitized_bytes"] = sum(f["bytes"] for f in facts(safe).values())
        if work != raw_root:
            sample["matches_baseline_sanitized_manifest"] = (
                safe / "SHA256SUMS"
            ).read_bytes() == (
                raw_root / f"safe-{fraction}" / "SHA256SUMS"
            ).read_bytes()
            if not sample["matches_baseline_sanitized_manifest"]:
                raise RuntimeError("candidate export differs from accepted export")
        output.write_text(json.dumps(receipt, indent=2) + "\n")
        print(
            json.dumps(
                {
                    "completed_percent": fraction,
                    "capture_seconds": timings.calls[-1]["seconds"],
                    "capture_cpu_seconds": timings.calls[-1]["cpu_seconds"],
                }
            ),
            flush=True,
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-root", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--fractions", type=int, nargs="+", default=[5, 10, 25])
    parser.add_argument("--optimize", action="store_true")
    parser.add_argument("--prepare", action="store_true")
    parser.add_argument("--spec-root", type=Path)
    args = parser.parse_args()
    run(
        args.raw_root,
        args.baseline,
        args.work,
        args.output,
        args.fractions,
        args.optimize,
        args.prepare,
        args.spec_root,
    )
