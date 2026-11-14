"""Offline lifecycle timing receipts; no provider calls or paid execution."""

import argparse
import copy
import json
import re
import tarfile
from datetime import datetime
from pathlib import Path

PHASE_MEANINGS = {
    "bootstrap": "SSM registration, readiness and host-agent launch; not the host bootstrap script.",
    "run_checks": "Contains the host bootstrap script and the requested check runner.",
}


def bootstrap_script_interval(bootstrap_log):
    """Use the first step start and last step end, including nested tool steps."""
    lines = [line for line in bootstrap_log.splitlines() if line.startswith("step=")]
    if not lines:
        return None, "bootstrap_script:no_step_lines"
    starts = [m[1] for line in lines if (m := re.search(r"\bstart_utc=(\S+)", line))]
    ends = [m[1] for line in lines if (m := re.search(r"\bend_utc=(\S+)", line))]
    if not starts or not ends:
        return None, "bootstrap_script:incomplete_step_interval"
    try:
        start = datetime.fromisoformat(starts[0].replace("Z", "+00:00"))
        end = datetime.fromisoformat(ends[-1].replace("Z", "+00:00"))
        if start.utcoffset() is None or end.utcoffset() is None:
            raise ValueError("timezone required")
        duration = (end - start).total_seconds()
    except ValueError:
        return None, "bootstrap_script:invalid_step_timestamp"
    if duration < 0:
        return None, "bootstrap_script:reversed_step_interval"
    return {
        "start_utc": starts[0],
        "end_utc": ends[-1],
        "duration_s": duration,
        "containing_phase": "run_checks",
        "accounting": "Already included in run_checks; do not add to the lifecycle phase total.",
    }, None


def build_timings_receipt(lifecycle, bootstrap_log, *, base=None):
    """Retain optional receipt metadata and derive the two distinct time domains."""
    receipt = copy.deepcopy(base) if base is not None else {}
    receipt.setdefault("schema", "dec077-lifecycle-timings-v1")
    phases = {}
    for name, phase in lifecycle["phases"].items():
        start, end = phase["monotonic_start_ns"], phase["monotonic_end_ns"]
        phases[name] = {
            "status": phase["status"],
            "duration_s": round((end - start) / 1_000_000_000, 9)
            if start is not None and end is not None
            else None,
        }
    interval, reason = bootstrap_script_interval(bootstrap_log)
    receipt.update(
        lifecycle_phase_seconds=phases,
        lifecycle_phase_total_s=round(sum(p["duration_s"] or 0 for p in phases.values()), 9),
        lifecycle_phase_meanings=copy.deepcopy(PHASE_MEANINGS),
        bootstrap_script=interval,
        bootstrap_script_reason=reason,
    )
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lifecycle", required=True, type=Path)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--bootstrap-log", type=Path)
    source.add_argument("--receipts", type=Path)
    parser.add_argument("--base", type=Path, help="Preserve additional fields from this receipt")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    if args.bootstrap_log is not None:
        bootstrap_log = args.bootstrap_log.read_text(encoding="utf-8", errors="replace")
    else:
        with tarfile.open(args.receipts, "r:gz") as archive:
            try:
                member = archive.getmember("bootstrap.log")
            except KeyError:
                bootstrap_log = ""
            else:
                stream = archive.extractfile(member) if member.isfile() else None
                bootstrap_log = stream.read().decode("utf-8", errors="replace") if stream else ""
    result = build_timings_receipt(
        json.loads(args.lifecycle.read_bytes()),
        bootstrap_log,
        base=json.loads(args.base.read_bytes()) if args.base else None,
    )
    args.output.write_bytes((json.dumps(result, indent=2) + "\n").encode("utf-8"))
    print(
        json.dumps(
            {
                "bootstrap_script": result["bootstrap_script"],
                "reason": result["bootstrap_script_reason"],
            }
        )
    )


if __name__ == "__main__":
    main()
