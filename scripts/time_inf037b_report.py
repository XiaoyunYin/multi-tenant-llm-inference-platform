"""Informational R247 timing: one report over a synthetic registered-rate attempt.

Fixture construction and archive sealing are outside the timed/traced interval.
No performance bound, paid-reset budget or real inference result is asserted.
"""

import argparse
import json
import platform
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "python/tests"))
ROOT = Path(__file__).resolve().parents[1]
from test_inf037b_collectors import complete_campaign_fixture  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    cache_root = ROOT / ".cache"
    cache_root.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=cache_root) as directory:
        campaign, count = complete_campaign_fixture(
            Path(directory) / "timing", registration_scale=True
        )
        tracemalloc.start()
        started = time.perf_counter()
        report = campaign.report()
        seconds = time.perf_counter() - started
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        receipt = {
            "informational_only": True,
            "scope": "one native report() call; one 1560-second registered-rate synthetic attempt",
            "report_calls": 1,
            "rows": count,
            "scheduled_offers": len(campaign.spec["expected_offers"]),
            "seconds": seconds,
            "peak_traced_python_bytes": peak,
            "memory_method": "tracemalloc peak during report; excludes fixture construction and native allocator/RSS",
            "python": platform.python_version(),
            "platform": platform.platform(),
            "measurement_valid": report["measurement_valid"],
            "validity_reasons": report["validity_reasons"],
            "limitations": "Not a three-attempt measurement or paid reset allowance; R247 remains open.",
        }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(json.dumps(receipt, sort_keys=True))


if __name__ == "__main__":
    main()
