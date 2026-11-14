"""Build the Gate A source-current maximum fixture and export-sizing proof."""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "python/tests"), str(ROOT / "scripts")]

from inf037b_fitness_fixture import attach  # noqa: E402
from inf037b_observations_fixture import attach as observations  # noqa: E402
from inf037b_setup_fixture import fixture as setup_fixture  # noqa: E402
from time_inf037b_three_attempts import build as build_maximum  # noqa: E402

from inference_platform.inf037b_archive import encode, file_facts, sha  # noqa: E402
from inference_platform.inf037b_campaign import materialize_bundle  # noqa: E402
from inference_platform.inf037b_contract import ATTEMPT_MS, RESET_MS  # noqa: E402
from inference_platform.inf037b_gate_a import (  # noqa: E402
    gate_a_binding,
    produce_export_sizing_proof,
)
from inference_platform.inf037b_maximum import current_sources, load_maximum  # noqa: E402


def inventory(root):
    return {
        path.relative_to(root).as_posix(): file_facts(path)
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def build(source, fixture_proof_path, sizing_proof_path, specs_path):
    source = Path(source).resolve()
    fixture_proof_path = Path(fixture_proof_path).resolve()
    sizing_proof_path = Path(sizing_proof_path).resolve()
    specs_path = Path(specs_path).resolve()
    if any(
        path.exists()
        for path in (source, fixture_proof_path, sizing_proof_path, specs_path)
    ):
        raise FileExistsError("gate_a_fixture:fresh_outputs_required")
    specs, rows = build_maximum(source, reset_ms=RESET_MS, include_reset_capture=True)
    materialize_bundle(source, specs)
    specs_path.parent.mkdir(parents=True, exist_ok=True)
    specs_path.write_bytes(encode(specs))
    source_inventory = inventory(source)
    raw_rows = 0
    for relative in sorted(source_inventory):
        if relative.startswith("raw/") and relative.endswith(".jsonl"):
            path = source / relative
            with path.open("rb") as stream:
                last = b""
                count = 0
                while chunk := stream.read(1024 * 1024):
                    count += chunk.count(b"\n")
                    last = chunk[-1:]
            if last and last != b"\n":
                raise ValueError("gate_a_fixture:jsonl_terminator")
            raw_rows += count
    if rows != 701_418 or raw_rows != 701_418:
        raise ValueError("gate_a_fixture:registered_rows")

    fixture_value = observations(attach(setup_fixture()), boot="gate-a-source")
    if fixture_value["binding"] != gate_a_binding():
        raise ValueError("gate_a_fixture:synthetic_binding")
    proof_path = fixture_value["maximum_fixture_proof"]["path"]
    proof = json.loads(fixture_value["artifacts"][proof_path])
    proof.update(
        registered_archive_rows=raw_rows,
        schedule_ms=[ATTEMPT_MS] * 3 + [RESET_MS] * 2,
        source_inventory_sha256=sha(encode(source_inventory)),
        scope="current_full_three_attempt_two_reset_fixture",
        fixture_inventory=source_inventory,
        source_lf_sha256=current_sources(),
    )
    fixture_proof_path.parent.mkdir(parents=True, exist_ok=True)
    fixture_proof_path.write_bytes(encode(proof))
    fixture_proof = load_maximum(
        {
            "path": str(fixture_proof_path),
            "sha256": sha(fixture_proof_path.read_bytes()),
        },
        fixture_value["binding"]["pins"],
    )
    sizing = produce_export_sizing_proof(
        source,
        pins=fixture_value["binding"]["pins"],
        fixture_proof_sha256=sha(fixture_proof_path.read_bytes()),
    )
    sizing_proof_path.parent.mkdir(parents=True, exist_ok=True)
    sizing_proof_path.write_bytes(encode(sizing))
    return {
        "fixture_rows": raw_rows,
        "fixture_bytes": sum(item["bytes"] for item in source_inventory.values()),
        "fixture_file_count": len(source_inventory),
        "fixture_inventory_sha256": sha(encode(source_inventory)),
        "fixture_proof_sha256": sha(fixture_proof_path.read_bytes()),
        "sizing_proof_sha256": sha(sizing_proof_path.read_bytes()),
        "sanitizer_specs_sha256": sha(specs_path.read_bytes()),
        "raw_bytes": sizing["raw_bytes"],
        "reconnect_bound_ms": sizing["reconnect_bound_ms"],
        "source_lf_sha256": fixture_proof["source_lf_sha256"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--fixture-proof", type=Path, required=True)
    parser.add_argument("--sizing-proof", type=Path, required=True)
    parser.add_argument("--specs", type=Path, required=True)
    args = parser.parse_args()
    print(
        json.dumps(
            build(args.source, args.fixture_proof, args.sizing_proof, args.specs),
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
