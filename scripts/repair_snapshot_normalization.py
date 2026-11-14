"""Repair a prior review port's LF normalization, without granting new reviews.

gitleaks v8.30.0 detect.go trims boundary LF from Match. The old regex fallback
ported the entire regex group. Only an already-approved old value identity and
the original SHA-bound, reviewed location permit this normalization repair.
"""

import argparse
import copy
import json
import re
import subprocess
import tomllib
from pathlib import Path

from port_snapshot_dispositions import digest, reviewed_match
from snapshot_dispositions import value_identity

SOURCE = "f68c65e70e701338f86664427a96fa5e631119e5"
POLICY = "scripts/public_snapshot/dispositions.json"


def normalized_entry(data, row, pattern, approved):
    if digest(data) != row["file_sha256"]:
        raise ValueError("normalization:reviewed_source_hash")
    matched = reviewed_match(data, row, pattern)
    trimmed = matched.strip(b"\n")
    if not trimmed or trimmed == matched:
        return None
    old_id = value_identity(row["path"], row["rule"], digest(matched))
    witness = approved.get(old_id)
    if (
        witness is None
        or witness.get("id") != old_id
        or witness.get("path") != row["path"]
        or witness.get("rule") != row["rule"]
        or witness.get("matched_sha256") != digest(matched)
        or witness.get("status")
        not in {"NON_SECRET", "PUBLIC_FIXTURE", "LOCAL_EPHEMERAL"}
        or row["status"] not in witness.get("reviewed_statuses", [witness["status"]])
    ):
        raise ValueError("normalization:missing_approved_value_witness")
    new_hash = digest(trimmed)
    return {
        **witness,
        "id": value_identity(row["path"], row["rule"], new_hash),
        "matched_sha256": new_hash,
        "normalization": {
            "source": SOURCE,
            "reviewed_location_id": row["id"],
            "approved_value_id": old_id,
            "source_file_sha256": row["file_sha256"],
            "rule": "gitleaks-v8.30.0-Match-boundary-LF-trim",
        },
    }


def repair(root, output):
    def blob(spec):
        return subprocess.check_output(["git", "show", spec], cwd=root)

    prior = json.loads(blob(SOURCE + ":" + POLICY))
    current = json.loads((root / POLICY).read_bytes())
    if prior["schema_version"] != 2 or current["schema_version"] != 3:
        raise ValueError("normalization:policy_schema")
    approved = {r["id"]: r for r in current["findings"]}
    patterns = {
        r["id"]: re.compile(r["regex"], re.ASCII)
        for name in ("security/gitleaks-v8.30.0.toml", "security/inf052-gitleaks.toml")
        for r in tomllib.loads(blob(SOURCE + ":" + name).decode())["rules"]
        if r["id"] == "generic-api-key"
    }
    changes = []
    # These are the three unchanged source locations left unresolved in the real
    # R370/R371 capture. No broad path/rule allowlist or new manual approval.
    path = "python/tests/test_inf037b_collectors.py"
    data = blob(SOURCE + ":" + path)
    for row in prior["findings"]:
        if row["path"] != path or row["rule"] != "generic-api-key":
            continue
        entry = normalized_entry(data, row, patterns[row["rule"]], approved)
        if entry and entry["id"] not in approved:
            approved[entry["id"]] = entry
            changes.append(entry["normalization"])
    result = copy.deepcopy(current)
    result["findings"] = [approved[k] for k in sorted(approved)]
    if changes or "normalization_repair" not in result:
        result["normalization_repair"] = {
            "source": SOURCE,
            "added": changes,
            "dropped": 0,
        }
    output.write_text(json.dumps(result, separators=(",", ":")) + "\n")
    return {"added": len(changes), "dropped": 0, "source": SOURCE}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(repair(Path(__file__).resolve().parents[1], args.output)))
