"""Append-only offline archive and resumable byte export (:23, :27, :104).

Sanitization joins/policy are deferred to slice 4b. `sanitized_copy` takes an
explicit caller transform; transport only accepts an archive labelled sanitized.
Integrity receipts are sidecars, not the resolved measurement manifest of 4b.
"""

import hashlib
import json
import os
from collections.abc import Callable
from pathlib import Path

from .inf037b_contract import REGISTRATION_ID, SCHEMA_VERSION, SOURCE_KINDS, nonnegative
from .inf037b_export_runtime import barrier, created_directory, defer_file, fresh_result, inventory


class IntegrityError(ValueError):
    pass


def file_facts(path: Path, chunk_bytes: int = 1024 * 1024) -> dict:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(chunk_bytes):
            size += len(chunk)
            digest.update(chunk)
    return {"bytes": size, "sha256": digest.hexdigest()}


def encode(value: dict) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def strict_json(data: bytes) -> dict:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise IntegrityError(f"duplicate_json_member:{key}")
            result[key] = value
        return result

    def constant(value):
        raise IntegrityError(f"nonfinite_json:{value}")

    return json.loads(data, object_pairs_hook=pairs, parse_constant=constant)


def durable_write(path: Path, data: bytes, mode: str = "xb", *, immediate: bool = False) -> None:
    deferred = defer_file(path, immediate=immediate)
    with path.open(mode) as stream:
        stream.write(data)
        stream.flush()
        if not deferred:
            os.fsync(stream.fileno())


def envelope(payload: dict, *, seq: int, attempt: int | str = "setup") -> dict:
    """Synthetic controller envelope, not a fabricated live observation (:23)."""
    return {
        "schema_version": SCHEMA_VERSION,
        "registration_id": REGISTRATION_ID,
        "session_id": "offline-fixture",
        "attempt_id": attempt,
        "stage": [1, 2, 3, 4, 5],
        "source_kind": "controller",
        "source_identity": "offline-controller",
        "source_generation": "fixture-generation",
        "source_seq": seq,
        "record_id": f"controller-{seq}",
        "collector_id": "offline-core",
        "collector_boot_id": "fixture-boot",
        "observed_mono_ns": seq,
        "observed_wall_utc": "2026-10-14T00:00:00Z",
        "source_time": None,
        "capture_start_mono_ns": seq,
        "capture_end_mono_ns": seq,
        "uncertainty_ns": 0,
        "payload": payload,
        "missing_reason": "synthetic_offline_record_has_no_live_source_clock",
        "error": None,
    }


def validate_envelope(row: dict) -> None:
    required = set(envelope({}, seq=0))
    if not isinstance(row, dict) or not required <= row.keys():
        raise IntegrityError("missing_common_envelope_fields")
    if row["schema_version"] != SCHEMA_VERSION or row["registration_id"] != REGISTRATION_ID:
        raise IntegrityError("registration_or_schema_mismatch")
    if row["source_kind"] not in SOURCE_KINDS:
        raise IntegrityError("unknown_source_kind")
    for field in (
        "session_id",
        "source_identity",
        "source_generation",
        "record_id",
        "collector_id",
        "collector_boot_id",
        "observed_wall_utc",
    ):
        if not isinstance(row[field], str) or not row[field]:
            raise IntegrityError(f"missing_identity:{field}")
    if (
        not isinstance(row["payload"], dict)
        or not isinstance(row["stage"], list)
        or any(type(stage) is not int or stage not in range(1, 6) for stage in row["stage"])
    ):
        raise IntegrityError("invalid_payload_or_stage")
    for field in (
        "source_seq",
        "observed_mono_ns",
        "capture_start_mono_ns",
        "capture_end_mono_ns",
        "uncertainty_ns",
    ):
        nonnegative(row[field], field)
    if row["capture_end_mono_ns"] < row["capture_start_mono_ns"]:
        raise IntegrityError("reversed_capture_bracket")
    if row["source_time"] is None and not row["missing_reason"]:
        raise IntegrityError("null_source_time_requires_reason")
    if row["source_time"] is not None and (
        not isinstance(row["source_time"], dict)
        or not {"clock_id", "unit", "value"} <= row["source_time"].keys()
    ):
        raise IntegrityError("invalid_source_time")


def record_key(row: dict) -> tuple[str, str, str]:
    return row["source_identity"], row["source_generation"], row["record_id"]


def conflict_error(key: tuple, first: dict, current: dict) -> dict:
    return {
        "reason": "conflicting_duplicate",
        "record_key": dict(
            zip(("source_identity", "source_generation", "record_id"), key, strict=True)
        ),
        "locations": [first, current],
    }


def _tail_offset(path: Path, source_errors: bool) -> int | None:
    size = path.stat().st_size
    if not size:
        return None
    with path.open("rb") as stream:
        stream.seek(size - 1)
        if stream.read(1) == b"\n":
            return None
        offset = size
        while offset:
            take = min(64 * 1024, offset)
            offset -= take
            stream.seek(offset)
            chunk = stream.read(take)
            position = chunk.rfind(b"\n")
            if position >= 0:
                tail = offset + position + 1
                if not source_errors:
                    raise IntegrityError(f"truncated_jsonl:{path.name}")
                return tail
    if not source_errors:
        raise IntegrityError(f"truncated_jsonl:{path.name}")
    return 0


def iter_segment_rows(path: Path, *, source_errors: bool = False, segment_name: str | None = None):
    """Yield complete validated rows with bounded file reads and byte locations."""
    tail_offset = _tail_offset(path, source_errors)
    limit = tail_offset if tail_offset is not None else path.stat().st_size
    offset = 0
    with path.open("rb") as stream:
        number = 0
        while offset < limit:
            line = stream.readline(limit - offset)
            if not line or not line.endswith(b"\n"):
                raise IntegrityError(f"truncated_jsonl:{path.name}")
            number += 1
            try:
                row = strict_json(line)
                validate_envelope(row)
            except (ValueError, TypeError, KeyError) as exc:
                raise IntegrityError(f"invalid_jsonl:{path.name}:{exc}") from exc
            yield number, offset, row
            offset += len(line)


def inspect_segment(
    path: Path,
    *,
    source_errors: bool = False,
    segment_name: str | None = None,
    keep_rows: bool = True,
) -> tuple[dict, list[dict]]:
    """Strict for journal replay; archival inspection retains damaged source bytes."""
    name = segment_name or path.name
    tail_offset = _tail_offset(path, source_errors)
    facts = file_facts(path)
    rows = []
    seen = {}
    duplicates = 0
    errors = []
    count = 0
    first_sequence = last_sequence = None
    for number, offset, row in iter_segment_rows(
        path, source_errors=source_errors, segment_name=name
    ):
        count += 1
        if first_sequence is None:
            first_sequence = row["source_seq"]
        last_sequence = row["source_seq"]
        identity = record_key(row)
        location = {"segment": name, "line": number, "byte_offset": offset}
        row_hash = hashlib.sha256(encode(row)).hexdigest()
        if identity in seen:
            previous, first = seen[identity]
            if previous != row_hash:
                if not source_errors:
                    raise IntegrityError(f"conflicting_duplicate:{row['record_id']}")
                errors.append(conflict_error(identity, first, location))
            else:
                duplicates += 1
        else:
            seen[identity] = row_hash, location
        if keep_rows:
            rows.append(row)
    if tail_offset is not None:
        errors.append({"reason": "truncated_jsonl", "byte_offset": tail_offset})
    return {
        "bytes": facts["bytes"],
        "row_count": count,
        "first_sequence": first_sequence,
        "last_sequence": last_sequence,
        "sha256": facts["sha256"],
        "duplicate_count": duplicates,
        "torn_tail_offset": tail_offset,
        "integrity_errors": errors,
    }, rows


def archive_receipts(root: Path) -> dict[str, dict]:
    """Recompute local receipts and both locations of cross-segment conflicts."""
    receipts, seen = {}, {}
    for path in sorted(root.rglob("*.jsonl")):
        name = path.relative_to(root).as_posix()
        receipt, _ = inspect_segment(path, source_errors=True, segment_name=name, keep_rows=False)
        # Rebuild conflicts globally in deterministic file/arrival order.
        receipt["integrity_errors"] = [
            error
            for error in receipt["integrity_errors"]
            if error["reason"] != "conflicting_duplicate"
        ]
        receipts[name] = receipt
        for number, offset, row in iter_segment_rows(path, source_errors=True, segment_name=name):
            key = record_key(row)
            location = {"segment": name, "line": number, "byte_offset": offset}
            row_hash = hashlib.sha256(encode(row)).hexdigest()
            if key in seen:
                previous, first = seen[key]
                if previous != row_hash:
                    error = conflict_error(key, first, location)
                    for affected in dict.fromkeys((first["segment"], name)):
                        receipts[affected]["integrity_errors"].append(error)
            else:
                seen[key] = row_hash, location
    return receipts


def safe_file(root: Path, name: str) -> Path:
    path = root / name
    if (
        not name
        or "\\" in name
        or Path(name).is_absolute()
        or ".." in Path(name).parts
        or path.is_symlink()
        or not path.resolve().is_relative_to(root.resolve())
    ):
        raise IntegrityError("unsafe_archive_path")
    return path


class Archive:
    def __init__(self, root: Path):
        self.root = root

    @classmethod
    def create(cls, root: Path, registration: dict, *, sanitized: bool = False) -> "Archive":
        missing = []
        parent = root
        while not parent.exists():
            missing.append(parent)
            parent = parent.parent
        root.mkdir(parents=True, exist_ok=False)
        for path in missing:
            created_directory(path)
        for directory in ("raw", "cohorts", "events"):
            (root / directory).mkdir()
            created_directory(root / directory)
        if registration.get("registration_id") != REGISTRATION_ID:
            raise IntegrityError("registration_mismatch")
        durable_write(root / "registration.json", encode({**registration, "sanitized": sanitized}))
        for kind in SOURCE_KINDS:
            durable_write(root / f"raw/{kind}.jsonl", b"")
        durable_write(root / "attempts.jsonl", b"")
        durable_write(root / "cohorts/requests.jsonl", b"")
        return cls(root)

    def append(self, segment: str, row: dict) -> None:
        path = safe_file(self.root, segment)
        if path.suffix != ".jsonl" or (self.root / "SHA256SUMS").exists():
            raise IntegrityError("archive_sealed_or_not_jsonl")
        if path.with_suffix(".receipt.json").exists():
            raise IntegrityError("segment_finalized")
        validate_envelope(row)
        # Validate existing bytes before reopening, including after a crash.
        receipt, _ = inspect_segment(path, source_errors=True)
        if receipt["torn_tail_offset"] is not None:
            raise IntegrityError(f"truncated_jsonl:{path.name}")
        durable_write(path, encode(row), "ab")

    def new_raw_segment(self, kind: str, segment_id: int) -> str:
        """Rotate explicitly; no size threshold is selected by slice 4a (:104)."""
        if kind not in SOURCE_KINDS or (self.root / "SHA256SUMS").exists():
            raise IntegrityError("unknown_source_kind_or_sealed_archive")
        nonnegative(segment_id, "segment_id")
        name = f"raw/{kind}-{segment_id}.jsonl"
        durable_write(self.root / name, b"")
        return name

    def finalize_segment(self, segment: str) -> dict:
        path = safe_file(self.root, segment)
        if (self.root / "SHA256SUMS").exists():
            return verify_archive(self.root)["segments"][segment]
        receipt, _ = inspect_segment(path, source_errors=True, segment_name=segment)
        target = path.with_suffix(".receipt.json")
        if target.exists():
            if json.loads(target.read_bytes()) != receipt:
                raise IntegrityError("finalization_receipt_mismatch")
        else:
            durable_write(target, encode(receipt))
        return receipt

    def seal(self) -> dict:
        if (self.root / "SHA256SUMS").exists():
            return verify_archive(self.root)
        receipts = archive_receipts(self.root)
        # Check earlier local finalizations before adding cross-segment diagnostics.
        for name, receipt in receipts.items():
            path = self.root / name
            target = path.with_suffix(".receipt.json")
            local, _ = inspect_segment(path, source_errors=True, segment_name=name)
            if target.exists() and json.loads(target.read_bytes()) not in (local, receipt):
                raise IntegrityError(f"finalization_receipt_mismatch:{name}")
        for name, receipt in receipts.items():
            durable_write((self.root / name).with_suffix(".receipt.json"), encode(receipt), "wb")
        barrier()
        files = sorted(p for p in self.root.rglob("*") if p.is_file() and p.name != "SHA256SUMS")
        content = "".join(
            f"{file_facts(p)['sha256']}  {p.relative_to(self.root).as_posix()}\n" for p in files
        )
        durable_write(self.root / "SHA256SUMS", content.encode(), immediate=True)
        return verify_archive(self.root)


def verify_archive(root: Path, *, known_files: dict | None = None) -> dict:
    # Caller-supplied facts must agree with a fresh read, even on a cache hit.
    if known_files is not None:
        current = {k: v for k, v in inventory(root).items() if "sha256" in v}
        if known_files != current:
            raise IntegrityError("archive_inventory_mismatch")
    return fresh_result(
        ("verify", root.resolve()),
        lambda: inventory(root),
        lambda: _verify_archive(root, known_files=known_files),
    )


def _verify_archive(root: Path, *, known_files: dict | None = None) -> dict:
    manifest = root / "SHA256SUMS"
    if not manifest.exists():
        raise IntegrityError("missing_SHA256SUMS")
    expected = {}
    for line in manifest.read_text(encoding="utf-8").splitlines():
        try:
            digest, name = line.split("  ", 1)
        except ValueError as exc:
            raise IntegrityError("malformed_SHA256SUMS") from exc
        if name == "SHA256SUMS" or name in expected:
            raise IntegrityError("manifest_self_or_duplicate")
        path = safe_file(root, name)
        if not path.is_file():
            raise IntegrityError(f"hash_mismatch:{name}")
        observed = known_files.get(name) if known_files is not None else None
        actual_digest = observed["sha256"] if observed is not None else file_facts(path)["sha256"]
        if actual_digest != digest:
            raise IntegrityError(f"hash_mismatch:{name}")
        expected[name] = digest
    actual = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}
    if actual != set(expected) | {"SHA256SUMS"}:
        raise IntegrityError("archive_inventory_mismatch")
    if known_files is not None and set(known_files) != actual:
        raise IntegrityError("archive_inventory_mismatch")
    required = {
        "registration.json",
        "attempts.jsonl",
        "cohorts/requests.jsonl",
        *(f"raw/{k}.jsonl" for k in SOURCE_KINDS),
    }
    if not required <= actual:
        raise IntegrityError("missing_output_layout")
    if any(not (root / name).is_dir() for name in ("raw", "cohorts", "events")):
        raise IntegrityError("missing_output_layout_directory")
    if (
        json.loads((root / "registration.json").read_bytes()).get("registration_id")
        != REGISTRATION_ID
    ):
        raise IntegrityError("registration_mismatch")
    receipts = archive_receipts(root)
    for name, receipt in receipts.items():
        sidecar = (root / name).with_suffix(".receipt.json")
        if not sidecar.exists() or json.loads(sidecar.read_bytes()) != receipt:
            raise IntegrityError(f"segment_receipt_mismatch:{name}")
    return {"verified": True, "files": len(expected), "segments": receipts}


def sanitized_copy(
    raw: Path,
    destination: Path,
    transform: Callable[[dict], dict],
    *,
    transform_key: Callable[[dict], dict] | None = None,
    transform_tail: Callable[[bytes], bytes] | None = None,
) -> Archive:
    """Caller owns sanitization joins; copy leaves all original raw bytes intact."""
    verified = verify_archive(raw)
    damaged = {
        name: receipt
        for name, receipt in verified["segments"].items()
        if receipt["integrity_errors"]
    }
    if any(r["torn_tail_offset"] is not None for r in damaged.values()) and transform_tail is None:
        raise IntegrityError("torn_tail_requires_explicit_sanitizer")
    has_conflict_keys = any(
        error.get("record_key")
        for receipt in damaged.values()
        for error in receipt["integrity_errors"]
    )
    if has_conflict_keys and transform_key is None:
        raise IntegrityError("conflict_keys_require_explicit_sanitizer")
    # Later-slice artifacts require their own sanitization joins; never drop them.
    for directory in ("events", "cohorts"):
        for path in (raw / directory).rglob("*"):
            if not path.is_file() or path.name.endswith(".receipt.json"):
                continue
            if path.suffix == ".jsonl" and path.stat().st_size == 0:
                continue
            raise IntegrityError("slice4b_artifacts_require_slice4b_sanitization")
    registration = json.loads((raw / "registration.json").read_bytes())
    archive = Archive.create(destination, registration, sanitized=True)
    if damaged:
        sanitized_damaged = {}
        transformed_keys = {}
        for name, receipt in damaged.items():
            sanitized_receipt = json.loads(encode(receipt))
            for error in sanitized_receipt["integrity_errors"]:
                if "record_key" not in error:
                    continue
                raw_key = error["record_key"]
                cache_key = tuple(
                    raw_key[field]
                    for field in ("source_identity", "source_generation", "record_id")
                )
                if cache_key not in transformed_keys:
                    transformed_key = transform_key(raw_key)
                    required = {"source_identity", "source_generation", "record_id"}
                    if (
                        not isinstance(transformed_key, dict)
                        or set(transformed_key) != required
                        or any(
                            not isinstance(value, str) or not value
                            for value in transformed_key.values()
                        )
                    ):
                        raise IntegrityError("sanitized_conflict_key_must_preserve_key_fields")
                    transformed_keys[cache_key] = transformed_key
                error["record_key"] = transformed_keys[cache_key]
            sanitized_damaged[name] = sanitized_receipt
        # Provenance survives even if sanitization makes conflicting rows identical.
        durable_write(
            destination / "source-integrity.receipt.json",
            encode(
                {
                    "source_manifest_sha256": sha((raw / "SHA256SUMS").read_bytes()),
                    "segments": sanitized_damaged,
                }
            ),
        )
    for segment in sorted(raw.rglob("*.jsonl")):
        relative = segment.relative_to(raw).as_posix()
        if not (destination / relative).exists():
            (destination / relative).parent.mkdir(parents=True, exist_ok=True)
            durable_write(destination / relative, b"")
        receipt, rows = inspect_segment(segment, source_errors=True)
        for row in rows:
            archive.append(relative, transform(row))
        if receipt["torn_tail_offset"] is not None:
            tail = transform_tail(segment.read_bytes()[receipt["torn_tail_offset"] :])
            if not isinstance(tail, bytes) or not tail or b"\n" in tail or b"\r" in tail:
                raise IntegrityError("sanitized_tail_must_remain_nonempty_unterminated_bytes")
            durable_write(destination / relative, tail, "ab")
    # Cohort/event generation, including their sanitization joins, is slice 4b.
    archive.seal()
    return archive


def export_archive(source: Path, destination: Path, *, byte_budget: int | None = None) -> dict:
    """Resumes verified prefixes; receipt sits beside export, outside immutable inventory.

    byte_budget injects interruption, not a registered size/transfer allowance.
    Every exceptional exit retains an incomplete receipt with actual byte offsets.
    """
    if byte_budget is not None:
        nonnegative(byte_budget, "byte_budget")
    if source.resolve() == destination.resolve() or (
        source.resolve().is_relative_to(destination.resolve())
        or destination.resolve().is_relative_to(source.resolve())
    ):
        raise IntegrityError("export_must_be_separate")
    receipt_path = destination.with_name(destination.name + ".export-receipt.json")
    receipt = {"complete": False, "reason": "export_interrupted", "resume_offsets": {}}
    prior_receipt_exists = receipt_path.exists()
    replace_receipt = not prior_receipt_exists
    try:
        verify_archive(source)
        if not json.loads((source / "registration.json").read_bytes()).get("sanitized"):
            raise IntegrityError("export_requires_separate_sanitized_archive")
        receipt["source_manifest_sha256"] = sha((source / "SHA256SUMS").read_bytes())
        if prior_receipt_exists:
            prior = json.loads(receipt_path.read_bytes())
            prior_manifest = prior.get("source_manifest_sha256")
            destination_has_bytes = destination.exists() and any(
                path.is_file() for path in destination.rglob("*")
            )
            if prior_manifest is None and destination_has_bytes:
                raise IntegrityError("resume_receipt_missing_source_for_existing_bytes")
            if prior_manifest is not None and prior_manifest != receipt["source_manifest_sha256"]:
                raise IntegrityError("resume_source_changed")
            # A manifestless receipt came from a refused pre-manifest call. With
            # no destination bytes it is not a source-bound resume receipt (R230).
            if prior_manifest is None and not destination_has_bytes:
                replace_receipt = True
            elif prior_manifest == receipt["source_manifest_sha256"]:
                replace_receipt = True
        destination.mkdir(parents=True, exist_ok=True)
        for directory in ("raw", "cohorts", "events"):
            safe_file(destination, directory).mkdir(exist_ok=True)
        files = sorted(p.relative_to(source).as_posix() for p in source.rglob("*") if p.is_file())
        receipt["resume_offsets"] = {
            name: safe_file(destination, name).stat().st_size
            if safe_file(destination, name).exists()
            else 0
            for name in files
        }
        extras = {
            p.relative_to(destination).as_posix() for p in destination.rglob("*") if p.is_file()
        } - set(files)
        if extras:
            raise IntegrityError("unexpected_export_file")
        for name in files:
            target = safe_file(destination, name)
            origin = source / name
            source_size = origin.stat().st_size
            previous_size = target.stat().st_size if target.exists() else 0
            receipt["resume_offsets"][name] = previous_size
            if previous_size > source_size:
                raise IntegrityError(f"resume_prefix_mismatch:{name}")
            if target.exists():
                with origin.open("rb") as source_stream, target.open("rb") as target_stream:
                    while chunk := target_stream.read(1024 * 1024):
                        if source_stream.read(len(chunk)) != chunk:
                            raise IntegrityError(f"resume_prefix_mismatch:{name}")
            remaining = source_size - previous_size
            take = remaining if byte_budget is None else min(remaining, byte_budget)
            target.parent.mkdir(parents=True, exist_ok=True)
            with origin.open("rb") as source_stream, target.open("ab") as target_stream:
                source_stream.seek(previous_size)
                left = take
                while left:
                    chunk = source_stream.read(min(1024 * 1024, left))
                    if not chunk:
                        raise IntegrityError(f"source_truncated_during_export:{name}")
                    if target_stream.write(chunk) != len(chunk):
                        raise IntegrityError("short_export_write")
                    left -= len(chunk)
                target_stream.flush()
                os.fsync(target_stream.fileno())
            receipt["resume_offsets"][name] += take
            if byte_budget is not None:
                byte_budget -= take
            if take < remaining:
                return receipt
        receipt["verification"] = verify_archive(destination)
        receipt.update(complete=True, reason="counts_and_hashes_verified")
        return receipt
    except Exception as exc:
        receipt["reason"] = str(exc)
        raise
    finally:
        if replace_receipt:
            receipt_path.parent.mkdir(parents=True, exist_ok=True)
            temporary = receipt_path.with_suffix(".tmp")
            durable_write(temporary, encode(receipt), "wb")
            os.replace(temporary, receipt_path)
