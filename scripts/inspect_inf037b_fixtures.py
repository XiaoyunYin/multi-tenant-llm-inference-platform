"""Compare every offline Slice4b fixture and produce an object inspection index."""

import argparse
import gzip
import hashlib
import json
from pathlib import Path


def digest(value):
    return hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode()
    ).hexdigest()


def inspect(native: dict, linux: dict, prior: dict | None = None):
    if native != linux:
        changed = sorted(
            k for k in native.keys() | linux.keys() if native.get(k) != linux.get(k)
        )
        raise ValueError("native/Linux fixture mismatch: " + ",".join(changed))
    prior = prior or {}
    objects = {}
    for name, value in sorted(native.items()):
        if not {"report", "archive_state"} <= value.keys():
            raise ValueError("fixture lacks report/archive state: " + name)
        state = value["archive_state"]
        if state.get("verified") is not True and "refusal" not in value:
            raise ValueError("unverified archive without explicit refusal: " + name)
        segments = state.get("segments", {})
        objects[name] = {
            "sha256": digest(value),
            "change": "added"
            if name not in prior
            else "unchanged"
            if prior[name] == value
            else "changed",
            "archive_verified": state.get("verified", False),
            "retained_rows": sum(v["row_count"] for v in segments.values()),
            "retained_bytes": sum(v["bytes"] for v in segments.values()),
            "source_integrity_errors": sum(
                len(v["integrity_errors"]) for v in segments.values()
            ),
            "report_type": type(value["report"]).__name__,
        }
    return {
        "native_linux_json_equal": True,
        "objects": objects,
        "added": sum(o["change"] == "added" for o in objects.values()),
        "changed": sum(o["change"] == "changed" for o in objects.values()),
        "unchanged": sum(o["change"] == "unchanged" for o in objects.values()),
        "removed": sorted(prior.keys() - native.keys()),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--linux", type=Path, required=True)
    parser.add_argument("--prior", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    def read(path):
        data = path.read_bytes()
        return json.loads(gzip.decompress(data) if path.suffix == ".gz" else data)

    report = inspect(
        read(args.native),
        read(args.linux),
        read(args.prior) if args.prior else None,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    for name, item in report["objects"].items():
        print(
            f"{name}: {item['change']}; archive_verified={item['archive_verified']}; rows={item['retained_rows']}; integrity_errors={item['source_integrity_errors']}; sha256={item['sha256'][:12]}"
        )
    print(
        f"PASS {len(report['objects'])} objects; added={report['added']} changed={report['changed']} removed={len(report['removed'])}"
    )


if __name__ == "__main__":
    main()
