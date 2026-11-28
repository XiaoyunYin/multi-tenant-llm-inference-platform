"""Recount per-instance DCGM coverage from one frozen cycle's TSDB dump."""

import argparse
import bisect
import json
import math
import re
from collections import defaultdict
from pathlib import Path

from inf054_dcgm import FIELDS

LABEL = re.compile(r'(?:^|,\s*)(__name__|instance|job)=("(?:[^"\\]|\\.)*")')


def scrape_rows(lines):
    series = defaultdict(lambda: defaultdict(dict))
    for line in lines:
        labels, sep, sample = line.strip().lstrip("{").rpartition("}")
        if not sep or 'job="dcgm"' not in labels:
            continue
        keys = {key: json.loads(value) for key, value in LABEL.findall(labels)}
        field = keys.get("__name__")
        if field not in (*FIELDS, "up") or keys.get("job") != "dcgm":
            continue
        value, stamp = sample.split()
        by_stamp = series[keys["instance"]][field]
        finite = math.isfinite(float(value)) and (field != "up" or float(value) == 1)
        by_stamp[int(stamp)] = finite and by_stamp.get(int(stamp), True)
    return series


def coverage(gauges, dump, receipt):
    stamps = [int(row["sample_epoch_s"] * 1000) for row in gauges]
    series = scrape_rows(dump)
    rows = []
    for number, (_, fields) in enumerate(sorted(series.items()), 1):
        histories = {field: sorted(fields.get(field, {})) for field in (*FIELDS, "up")}

        def fresh(field, stamp):
            history = histories[field]
            index = bisect.bisect_right(history, stamp) - 1
            return (
                index >= 0
                and stamp - history[index] < 5000
                and fields[field][history[index]]
            )

        counts = {
            field: sum(fresh(field, stamp) for stamp in stamps) for field in FIELDS
        }
        both = sum(
            all(fresh(field, stamp) for field in (*FIELDS, "up")) for stamp in stamps
        )
        rows.append(
            {
                "instance": f"instance-{number}",
                "finite_fresh_samples": counts,
                "both_samples": both,
                "fraction": both / len(stamps) if stamps else None,
            }
        )
    endings = receipt.get("before_uninstall", {}).get("nodes", [])
    expected = receipt["expected_nodes"]
    no_restarts = len(endings) == expected and all(
        node["restart_count"] == 0 for node in endings
    )
    return {
        "gauge_samples": len(stamps),
        "expected_nodes": expected,
        "observed_instances": len(rows),
        "instances": rows,
        "cycle_end_zero_restarts": no_restarts,
        "passes": (
            no_restarts
            and len(rows) == expected
            and bool(stamps)
            and all(row["fraction"] >= 0.95 for row in rows)
        ),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("gauges", type=Path)
    parser.add_argument("dump", type=Path)
    parser.add_argument("gate", type=Path)
    args = parser.parse_args()
    with args.dump.open(encoding="utf-8") as dump:
        result = coverage(
            (json.loads(line) for line in args.gauges.read_bytes().splitlines()),
            dump,
            json.loads(args.gate.read_bytes()),
        )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
