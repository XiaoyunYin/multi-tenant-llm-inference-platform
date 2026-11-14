"""Characterize real pinned scanner coordinates without exporting matched bytes."""

import argparse
import hashlib
import json
import re
from pathlib import Path

import build_public_snapshot as builder
from snapshot_dispositions import (
    line_view,
    locate_hit,
    scanner_bytes,
    validate_fragment_map,
)

TARGETS = {
    "experiments/inf037a/kind-2026-10-02-r090/observations.json",
    *(f"experiments/r0/attempt7/run-{number}.digest.json.gz" for number in (1, 2, 4)),
}


def synthetic_translation(value):
    """Retain equality classes, discard digit labels; never retain the map.

    Unlike a fixed Caesar shift, the result does not encode the original digit
    labels. Ensure even an already canonical input never appears verbatim.
    """
    order = bytes(dict.fromkeys(value + b"0123456789"))
    labels = b"0123456789"
    table = bytes.maketrans(order, labels)
    if value.translate(table) == value:
        table = bytes.maketrans(order, b"1234567890")
    return table


def diagnose(root, report, output):
    receipt = json.loads(report.read_bytes())
    expected = receipt["scanner"]["raw_sha256"]
    matches = [
        path
        for path in (root / ".cache").glob("snapshot-scan-*/snapshot-tree.raw.json")
        if hashlib.sha256(path.read_bytes()).hexdigest() == expected
    ]
    if len(matches) != 1:
        raise ValueError("span_diagnostics:raw_receipt_binding")
    source = receipt["source_commit"]
    policy = json.loads(builder.blob(root, source, builder.POLICY))
    items = builder.source_files(root, source, policy)
    names = sorted(items, key=len, reverse=True)
    rows, fixtures, expanded, fragment_views = [], [], {}, {}
    for hit in sorted(
        json.loads(matches[0].read_bytes()),
        key=lambda h: (h["File"], h["StartLine"], h["StartColumn"]),
    ):
        path = hit["File"].removeprefix("/source/").removeprefix("./")
        name = next(
            p for p in names if path == p or path.startswith((p + "!", p + "/"))
        )
        if name not in TARGETS or hit["RuleID"] != "aws-account-id":
            continue
        if (name, path) not in expanded:
            expanded[name, path] = scanner_bytes(items[name]["data"], path[len(name) :])
        data = expanded[name, path]
        lines, line_offsets = line_view(data)
        line = hit["StartLine"]
        if not 1 <= line <= len(lines):
            continue
        base = line_offsets[line - 1]
        expected_start = base + hit["StartColumn"] - 1
        value = (hit.get("Match") or hit.get("Secret") or "").encode()
        if not re.fullmatch(rb"[0-9]{12}", value):
            raise ValueError("span_diagnostics:unexpected_account_shape")
        candidates = [
            pos
            for pos in range(
                max(base, expected_start - 1),
                min(base + len(lines[line - 1]), expected_start + 2),
            )
            if value and data[pos : pos + len(value)] == value
        ]
        if len(candidates) == 1:
            continue
        # Only coordinates/counts leave the host. Never persist match hashes for
        # unresolved hits, private values, or arbitrary source snippets.
        offsets = []
        cursor = base
        stop = base + len(lines[line - 1])
        while value and (pos := data.find(value, cursor, stop)) >= 0:
            offsets.append(pos - expected_start)
            cursor = pos + 1
        rows.append(
            {
                "path": path,
                "rule": hit["RuleID"],
                "line": line,
                "column": hit["StartColumn"],
                "end_line": hit["EndLine"],
                "end_column": hit["EndColumn"],
                "source_line_bytes": len(lines[line - 1]),
                "match_bytes": len(value),
                "secret_equals_match": hit.get("Secret", hit.get("Match"))
                == hit.get("Match", hit.get("Secret")),
                "decode_tags": [
                    tag
                    for tag in hit.get("Tags", [])
                    if tag
                    in {
                        "decoded:base64",
                        "decoded:hex",
                        "decoded:percent",
                        "decoded:url",
                    }
                    or re.fullmatch(r"decode-depth:[1-5]", tag)
                ],
                "candidate_count": len(candidates),
                "candidate_deltas": [p - expected_start for p in candidates],
                "line_occurrence_count": len(offsets),
                "nearest_line_occurrence_deltas": sorted(
                    offsets, key=lambda delta: (abs(delta), delta)
                )[:2],
            }
        )
        fragment_record = (
            receipt["scanner"].get("fragment_provenance", {}).get("files", {}).get(path)
        )
        if fragment_record:
            if path not in fragment_views:
                fragment_views[path] = validate_fragment_map(data, fragment_record)
            starts = fragment_views[path]
            selected_lo, selected_hi, fixed = locate_hit(
                data, hit, fragment_starts=starts.get(line, ())
            )
            rows[-1].update(
                resolved=True,
                resolution=fixed["SpanResolution"],
                fragment_offset=fixed["SpanFragmentOffset"],
                translated_delta=fixed["SpanColumnDelta"],
                translated_candidates=fixed["SpanCandidateCount"],
            )

        def in_longer_number(lo, hi):
            return (
                data[lo - 1 : lo].isdigit()
                or data[hi : hi + 1].isdigit()
                or (data[lo - 1 : lo] == b"." and data[lo - 2 : lo - 1].isdigit())
                or (data[hi : hi + 1] == b"." and data[hi + 1 : hi + 2].isdigit())
            )

        longer_number = (
            in_longer_number(selected_lo, selected_hi)
            if fragment_record
            else any(
                in_longer_number(
                    expected_start + delta, expected_start + delta + len(value)
                )
                for delta in offsets
            )
        )
        if longer_number and not any(
            (line == 1) == (f["StartLine"] == 1) for f in fixtures
        ):
            # Equality classes and coordinates only; even a shifted original
            # value in neighbouring digits is forbidden in the synthetic body.
            order = bytes(dict.fromkeys(value + b"0123456789"))
            for turn in range(10):
                labels = b"0123456789"
                translation = bytes.maketrans(order, labels[turn:] + labels[:turn])
                body = bytearray(b"x" * stop)
                for index, byte in enumerate(data[:stop]):
                    if byte in (10, 13):
                        body[index] = byte
                for delta in offsets:
                    pos = expected_start + delta
                    for index in range(
                        max(base, pos - 2), min(stop, pos + len(value) + 2)
                    ):
                        if data[index] in b"0123456789":
                            body[index] = translation[data[index]]
                        elif (
                            data[index] == 46
                            and data[index - 1 : index].isdigit()
                            and data[index + 1 : index + 2].isdigit()
                        ):
                            body[index] = 46
                if value not in body and value.translate(translation) != value:
                    break
            else:
                raise ValueError("span_diagnostics:sanitization")
            synthetic_frames = []
            if fragment_record:
                for frame in fragment_record["fragments"]:
                    at = frame["offset"]
                    if at >= stop:
                        break
                    part = body[at : min(stop, at + frame["bytes"])]
                    synthetic_frames.append(
                        {
                            **frame,
                            "bytes": len(part),
                            "sha256": hashlib.sha256(part).hexdigest(),
                        }
                    )
            fixtures.append(
                {
                    **{
                        key: hit[key]
                        for key in (
                            "RuleID",
                            "StartLine",
                            "EndLine",
                            "StartColumn",
                            "EndColumn",
                        )
                    },
                    "body": body.decode("ascii"),
                    "fragment_map": {
                        "bytes": len(body),
                        "sha256": hashlib.sha256(body).hexdigest(),
                        "fragments": synthetic_frames,
                    }
                    if synthetic_frames
                    else None,
                    "synthetic_match": value.translate(translation).decode(),
                    "Tags": rows[-1]["decode_tags"],
                    "source_path": path,
                }
            )
    output.mkdir(parents=True, exist_ok=False)
    for name, value in (
        (
            "refused-row-coordinates.json",
            {"source_commit": source, "raw_sha256": expected, "rows": rows},
        ),
        (
            "sanitized-real-rows.json",
            {
                "scanner": builder.IMAGE,
                "source_commit": source,
                "raw_sha256": expected,
                "sanitization": "all source bytes masked, only line lengths and occurrence equality retained",
                "rows": fixtures,
            },
        ),
    ):
        (output / name).write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
    print(
        json.dumps({"baseline_refused": len(rows), "sanitized_fixtures": len(fixtures)})
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    diagnose(args.repo, args.report, args.output)
