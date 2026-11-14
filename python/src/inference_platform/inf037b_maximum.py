"""Join the reviewed maximum fixture to current code and creation's staging.

The exact payload pins this proof's bytes. The later exact-plan review still
establishes maximum-cardinality authority; this module refuses stale/substituted
proofs rather than synthesizing authority from an observed small archive.
"""

from pathlib import Path, PurePosixPath

from . import inf037b_contract
from .inf037b_archive import encode, sha, strict_json
from .inf037b_contract import ATTEMPT_MS, RESET_MS
from .inf037b_resolver import exact, integer, require

ROOT = Path(inf037b_contract.__file__).resolve().parents[3]


def current_sources():
    paths = [
        *sorted((ROOT / "python/src/inference_platform").glob("inf037b*.py")),
        ROOT / "scripts/time_inf037b_three_attempts.py",
        ROOT / "python/tests/test_inf037b_collectors.py",
    ]
    return {
        p.relative_to(ROOT).as_posix(): sha(p.read_bytes().replace(b"\r\n", b"\n")) for p in paths
    }


def load_maximum(reference, pins):
    raw = Path(reference["path"]).read_bytes()
    exact(sha(raw), reference["sha256"], "maximum:artifact_hash")
    proof = strict_json(raw)
    exact(raw, encode(proof), "maximum:canonical")
    exact(proof["subject"], "lifecycle:maximum_export_fixture", "maximum:subject")
    exact(proof["pins"], pins, "maximum:pins")
    exact(proof["schedule_ms"], [ATTEMPT_MS] * 3 + [RESET_MS] * 2, "maximum:schedule")
    exact(proof["source_lf_sha256"], current_sources(), "maximum:current_sources")
    inventory = proof["fixture_inventory"]
    require(type(inventory) is dict and bool(inventory), "maximum:inventory")
    require(
        {"registration.json", "attempts.jsonl", "SHA256SUMS"} <= inventory.keys()
        and any(name.startswith("raw/") for name in inventory),
        "maximum:archive_inventory",
    )
    for name, facts in inventory.items():
        path = PurePosixPath(name)
        require(
            isinstance(name, str)
            and str(path) == name
            and not path.is_absolute()
            and ".." not in path.parts
            and "\\" not in name,
            "maximum:path",
        )
        require(
            set(facts) == {"bytes", "sha256"} and integer(facts["bytes"]) and facts["bytes"] >= 0,
            "maximum:bytes",
        )
        require(
            type(facts["sha256"]) is str
            and len(facts["sha256"]) == 64
            and all(c in "0123456789abcdef" for c in facts["sha256"]),
            "maximum:hash",
        )
    exact(sha(encode(inventory)), proof["source_inventory_sha256"], "maximum:inventory_hash")
    return proof
