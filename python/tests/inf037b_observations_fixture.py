"""Compact recorded-response adapters, never a measured maximum-size fixture."""

import copy
from pathlib import Path
from tempfile import TemporaryDirectory

from test_inf037b_collectors import Records

from inference_platform.inf037b_archive import Archive, encode, sha, strict_json
from inference_platform.inf037b_contract import REGISTRATION_ID
from inference_platform.inf037b_packet import sanitized_sources
from inference_platform.inf037b_setup_observations import capture_export, capture_replay, recipe

_TEMP_DIRS = []


def attach(value, *, boot="host"):
    value = copy.deepcopy(value)
    binding = value["binding"]
    now = [512000]

    def sample():
        now[0] += 1
        return {"clock_id": "measurement", "boot_id": boot, "ms": [now[0]] * 2}

    temporary = TemporaryDirectory(prefix="inf037b-observation-fixture-")
    _TEMP_DIRS.append(temporary)
    work = Path(temporary.name)
    value["replay_raw"] = capture_replay(binding=binding, sample=sample, work=work / "replay")
    source = work / "source"
    archive = Archive.create(source, {"registration_id": REGISTRATION_ID, "pins": binding["pins"]})
    # Retain the REAL replay journal, plus all five complete virtual phase
    # recipes, in this compact archive. Full source-cardinality sizing remains
    # a separate pre-session maximum-fixture proof, as in other offline fakes.
    (source / "attempts.jsonl").write_bytes(
        bytes.fromhex(strict_json(value["replay_raw"])["journal_hex"])
    )
    records = Records()
    for i, item in enumerate(recipe()):
        archive.append(
            "raw/controller.jsonl",
            records.row("controller", "resolution", i, name="virtual_schedule", value=item),
        )
    archive.seal()

    def sanitize(raw, destination):
        output, _ = sanitized_sources(raw, destination, key=b"offline-fixture-sanitizer-key" * 2)
        output.seal()

    value["export_raw"], value["export_artifacts"] = capture_export(
        binding=binding,
        source=source,
        sanitized=work / "sanitized",
        destination=work / "copy",
        sanitize=sanitize,
        sample=sample,
        reconnect_ms=1000,
    )
    exported = strict_json(value["export_raw"])
    maximum = encode(
        {
            "subject": "lifecycle:maximum_export_fixture",
            "pins": binding["pins"],
            "schedule_ms": [1560000] * 3 + [300000] * 2,
            "source_inventory_sha256": sha(encode(exported["source"])),
            "scope": "synthetic_compact_adapter_fixture_not_maximum_cardinality",
        }
    )
    path = "proof/maximum-fixture.json"
    value["artifacts"][path] = maximum
    value["maximum_fixture_proof"] = {"path": path, "sha256": sha(maximum)}
    sizing_path = value["lifecycle"]["transfer"]["sizing_proof"]["path"]
    sizing = strict_json(value["artifacts"][sizing_path])
    sizing["raw_bytes"] = sum(p["bytes"] for p in exported["source"].values())
    sizing["reconnect_bound_ms"] = 1000
    value["artifacts"][sizing_path] = encode(sizing)
    value["lifecycle"]["transfer"]["sizing_proof"]["sha256"] = sha(encode(sizing))
    value["lifecycle"]["transfer"]["reconnect_ms"] = 1000
    return value
