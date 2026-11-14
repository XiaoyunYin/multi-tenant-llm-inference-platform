"""Single-owner offline streaming writer; never calls Archive.append (:23,104).

Open validates each existing segment once. Append updates the writer's index,
hash and receipts, retaining conflicting rows. Seal is an independent disk audit.
External writers are unsupported; a length change fails closed before append.
"""

import copy
import hashlib
from pathlib import Path

from .inf037b_archive import (
    Archive,
    IntegrityError,
    conflict_error,
    durable_write,
    encode,
    inspect_segment,
    record_key,
    safe_file,
    strict_json,
    validate_envelope,
    verify_archive,
)


class StreamingArchiveWriter:
    def _order_errors(self):
        # archive_receipts emits local tail errors first, then conflicts ordered
        # by the noncanonical occurrence's filename and line, for every segment.
        for receipt in self.receipts.values():
            receipt["integrity_errors"].sort(
                key=lambda error: (
                    error["reason"] == "conflicting_duplicate",
                    error.get("locations", [{}, {}])[-1].get("segment", ""),
                    error.get("locations", [{}, {}])[-1].get("line", 0),
                )
            )

    def __init__(self, root: Path, *, append_write=durable_write):
        self.root = root
        self.append_write = append_write
        self.closed = False
        self.raw_closed = False
        self.index = {}
        self.occurrences = {}
        self.receipts = {}
        self.hashes = {}
        self.finalized = set()
        self.local_index = {}
        opened = {}
        if (root / "SHA256SUMS").exists():
            raise IntegrityError("archive_sealed")
        paths = sorted(root.rglob("*.jsonl"))
        # Pre-register receipts so a conflict in a later segment can augment both.
        for path in paths:
            name = path.relative_to(root).as_posix()
            receipt, rows = inspect_segment(path, source_errors=True, segment_name=name)
            self.receipts[name] = receipt
            opened[name] = copy.deepcopy(receipt)
            self.local_index[name] = {}
            self.hashes[name] = hashlib.sha256(path.read_bytes())
            sidecar = path.with_suffix(".receipt.json")
            if sidecar.exists():
                stored = strict_json(sidecar.read_bytes())
                # Cross-segment errors are reconstructed below; check all byte facts now.
                if any(stored[k] != receipt[k] for k in receipt if k != "integrity_errors"):
                    raise IntegrityError("stream_open_receipt_mismatch")
                self.finalized.add(name)
            receipt["integrity_errors"] = [
                e for e in receipt["integrity_errors"] if e["reason"] != "conflicting_duplicate"
            ]
            offset = 0
            for number, (row, line) in enumerate(
                zip(rows, path.read_bytes().splitlines(), strict=False), 1
            ):
                self.local_index[name].setdefault(record_key(row), row)
                self._index(row, {"segment": name, "line": number, "byte_offset": offset})
                offset += len(line) + 1
        self._order_errors()
        for name in self.finalized:
            stored = strict_json((root / name).with_suffix(".receipt.json").read_bytes())
            if stored not in (opened[name], self.receipts[name]):
                raise IntegrityError("stream_open_diagnostics_mismatch")

    def _index(self, row, location):
        key = record_key(row)
        self.occurrences.setdefault(key, []).append((row, location))
        if key in self.index:
            prior, first = self.index[key]
            if (location["segment"], location["line"]) < (first["segment"], first["line"]):
                self.index[key] = row, location
                key_dict = dict(
                    zip(("source_identity", "source_generation", "record_id"), key, strict=True)
                )
                for receipt in self.receipts.values():
                    receipt["integrity_errors"] = [
                        e for e in receipt["integrity_errors"] if e.get("record_key") != key_dict
                    ]
                for previous, where in self.occurrences[key]:
                    if previous != row:
                        error = conflict_error(key, location, where)
                        for name in dict.fromkeys((location["segment"], where["segment"])):
                            self.receipts[name]["integrity_errors"].append(error)
                return
            if prior != row:
                error = conflict_error(key, first, location)
                for name in dict.fromkeys((first["segment"], location["segment"])):
                    self.receipts[name]["integrity_errors"].append(error)
        else:
            self.index[key] = row, location

    def append(self, segment: str, row: dict) -> None:
        if self.closed or (self.root / "SHA256SUMS").exists():
            raise IntegrityError("writer_closed_or_sealed")
        path = safe_file(self.root, segment)
        if segment not in self.receipts or segment in self.finalized:
            raise IntegrityError("unknown_or_finalized_segment")
        receipt = self.receipts[segment]
        if receipt["torn_tail_offset"] is not None:
            raise IntegrityError("torn_segment_rotate_required")
        if path.stat().st_size != receipt["bytes"]:
            raise IntegrityError("external_segment_mutation")
        validate_envelope(row)
        # Encode first: no state is advanced if serialization fails.
        data = encode(row)
        key = record_key(row)
        self.append_write(path, data, "ab")
        location = {
            "segment": segment,
            "line": receipt["row_count"] + 1,
            "byte_offset": receipt["bytes"],
        }
        # Local duplicate count follows inspect_segment, including when first seen elsewhere.
        local = self.local_index[segment]
        identical_local = key in local and local[key] == row
        local.setdefault(key, row)
        self._index(row, location)
        self.hashes[segment].update(data)
        receipt.update(
            bytes=receipt["bytes"] + len(data),
            row_count=receipt["row_count"] + 1,
            first_sequence=row["source_seq"]
            if not receipt["row_count"]
            else receipt["first_sequence"],
            last_sequence=row["source_seq"],
            sha256=self.hashes[segment].hexdigest(),
            duplicate_count=receipt["duplicate_count"] + int(identical_local),
        )

    def rotate(self, kind: str, segment_id: int) -> str:
        if self.closed:
            raise IntegrityError("writer_closed")
        name = Archive(self.root).new_raw_segment(kind, segment_id)
        receipt, _ = inspect_segment(self.root / name, source_errors=True, segment_name=name)
        self.receipts[name] = receipt
        self.hashes[name] = hashlib.sha256()
        self.local_index[name] = {}
        return name

    def finalize(self, segment: str) -> dict:
        if self.closed:
            raise IntegrityError("writer_closed")
        path = safe_file(self.root, segment)
        if path.stat().st_size != self.receipts[segment]["bytes"]:
            raise IntegrityError("external_segment_mutation")
        self._order_errors()
        # Later cross-segment conflicts can augment earlier diagnostics at seal.
        durable_write(path.with_suffix(".receipt.json"), encode(self.receipts[segment]), "wb")
        self.finalized.add(segment)
        return self.receipts[segment]

    def report(self) -> dict:
        self._order_errors()
        segments = (
            {name: receipt for name, receipt in self.receipts.items() if name.startswith("raw/")}
            if self.raw_closed
            else self.receipts
        )
        return {"closed": self.closed, "segments": segments, "indexed_keys": len(self.index)}

    def close_raw(self) -> dict:
        """Close raw receipts before separate journal/derived owners finalize."""
        if not self.closed:
            for name in self.receipts:
                if name.startswith("raw/"):
                    self.finalize(name)
            self.raw_closed = True
            self.closed = True
        return self.report()

    def seal(self) -> dict:
        if self.closed:
            return verify_archive(self.root)
        # Independent audit catches same-length edits as well as append interference.
        for name, receipt in self.receipts.items():
            actual, _ = inspect_segment(self.root / name, source_errors=True, segment_name=name)
            if any(actual[k] != receipt[k] for k in receipt if k != "integrity_errors"):
                raise IntegrityError("stream_seal_byte_mismatch")
        result = Archive(self.root).seal()
        self.closed = True
        return result
