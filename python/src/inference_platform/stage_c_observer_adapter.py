"""Host projection of draft-r18 observations; never substitutes consumption time.

Input tables are complete immutable source rows. Other sources (dispatches,
native metrics, subscriber lags and screen calibration) remain the caller's
responsibility and are passed through the existing registered serializer.
"""

import collections
import copy
import json
import sqlite3
from pathlib import Path

from .stage_c_observer import CADENCE_NS, MAX_PHYSICAL, NativeDomain, Refusal
from .stage_c_registered import QUANTITIES, seal_registered


def queue_sample(row, origin, slot):
    if row is None or len(row) != 4:
        return None
    start, end, observed, depth = row
    if any(type(v) is not int or v < 0 for v in row):
        return None
    if not start <= end <= observed:
        return None
    if any((v - origin) // CADENCE_NS != slot for v in (start, end, observed)):
        return None
    return {
        "observed_ns": observed,
        "queue_read_ns": end,
        "queue_read_cost_ns": end - start,
        "queue_age_ns": observed - end,
        "queue_depth": depth,
    }


def integrate(rows, *, start, end):
    """Left-sample numerator/duration, including explicit missing-slot gaps.

    Rows: slot, actual observation time, value-or-None, valid, exposure identity.
    Certificates determine sample validity before this function, never whether
    two valid adjacent observations can be integrated.
    """
    eligible = [r for r in rows if start <= r[1] < end]
    numerator = covered = excluded = 0
    for left, right in zip(eligible, eligible[1:], strict=False):
        if right[1] <= left[1] or right[0] <= left[0]:
            raise Refusal("sample_order")
        duration = right[1] - left[1]
        if right[0] == left[0] + 1 and left[3] and right[3] and left[4] == right[4]:
            if left[2] is None or right[2] is None:
                raise Refusal("sample_value")
            numerator += left[2] * duration
            covered += duration
        else:
            excluded += duration
    return numerator, covered, excluded


def held_valid(scan, certificate, observed, origin, slot):
    return (
        certificate is not None
        and certificate.get("exit") is not None
        and certificate["scan_id"] == scan["identity"]
        and certificate["epoch"] == scan["epoch"]
        and certificate["thread"] == scan["thread"]
        and scan["start"] <= scan["end"]
        and (scan["start"] - origin) // CADENCE_NS == (scan["end"] - origin) // CADENCE_NS
        and (observed - origin) // CADENCE_NS == slot
        and max(scan["end"], certificate["entry"]) <= observed < certificate["exit"]
    )


def physical_counts(scan, domain, event_live, *, observed_ns=None):
    physical, owners = scan["physical"], scan["owners"]
    stamp = scan.get("end", 0) if observed_ns is None else observed_ns
    if len(physical) != MAX_PHYSICAL or {r[0] for r in physical} != set(range(MAX_PHYSICAL)):
        raise Refusal("physical_completeness")
    by_id = {r[0]: r for r in physical}
    links = collections.Counter()
    membership = collections.defaultdict(set)
    unscheduled = set()
    for owner in owners:
        if len(owner) != 7:
            raise Refusal("owner_schema")
        rid, index, position, bid, scheduled, full, prompt = owner
        if bid not in by_id or not 0 <= position < 512:
            raise Refusal("owner_foreign_key")
        links[bid] += 1
        if not scheduled:
            unscheduled.add(rid)
        generated = prompt is not None and position >= prompt // 16
        if index is None or prompt is None:
            value = None  # explicit unknown owner; retain links and pin evidence
        elif full is None:
            value = False if generated else None
        elif generated:
            # Active uncached output/private tails are non-W by owner span.
            frozen = domain.frozen.get(full)
            value = (
                (False if frozen is None else frozen["in_W"])
                if domain.key_valid(full, stamp)
                else None
            )
        else:
            value = domain.membership(full, stamp)
        membership[bid].add(value)
    active = shared = non_shared = reserved = 0
    alias_keys = []
    full_by_key = {}
    partition_known = aliases_known = True
    for row in physical:
        if len(row) != 7:
            raise Refusal("physical_schema")
        bid, generation, refs, null, aliases, free, provenance = row
        if null:
            reserved += 1
            continue
        if refs != links[bid] or free != (refs == 0):
            raise Refusal("unexplained_retention")
        if len(aliases) > 1:
            raise Refusal("alias_bound")
        for alias in aliases:
            raw, key = domain.decode(alias)
            if provenance is None or len(provenance) != 6:
                raise Refusal("missing_provenance")
            _index, position, prompt, source_full, status, insertion_ns = provenance
            if source_full != alias or insertion_ns > scan["end"]:
                raise Refusal("alias_provenance")
            generated = position >= prompt // 16
            if status in ("unknown", "overflow", "collision"):
                raise Refusal("native_identity")
            value = domain.membership(alias, stamp, generated=generated)
            if value is None:
                if status != "unregistered":
                    raise Refusal("native_identity")
                aliases_known = False
            if key in full_by_key and full_by_key[key] != raw:
                raise Refusal("ambiguous_key")
            full_by_key[key] = raw
            alias_keys.append((bid, key))
        if refs:
            if None in membership[bid]:
                partition_known = False
            elif len(membership[bid]) != 1:
                raise Refusal("owner_membership")
            active += 1
            if membership[bid] == {True}:
                shared += 1
            elif membership[bid] == {False}:
                non_shared += 1
    if reserved != 1:
        raise Refusal("reserved_null")
    # Native live sets contain keys; the coherent physical copy expands each
    # known alias to all its physical IDs. Duplicate identical physical hashes
    # are legal and never deduplicated in cached or evictable counts.
    # Cached/evictable counts and the event-key join need alias identity, not W
    # membership. Unknown membership still invalidates its dependents below.
    exact = event_live is not None and set(full_by_key) == set(event_live)
    pinned = {bid for bid, row in by_id.items() if row[2] and not row[3]}
    return {
        "cached": len(alias_keys) if exact else None,
        "shared": shared if partition_known else None,
        "non_shared": non_shared if partition_known else None,
        "evictable": sum(bid not in pinned for bid, _ in alias_keys) if exact else None,
        "capacity": MAX_PHYSICAL - non_shared if partition_known else None,
        "reserved_null": reserved,
        "active_physical": active,
        "event_live": len(alias_keys) if exact else None,
        "owner_link_n": len(owners),
        "unscheduled_holder_n": len(unscheduled),
        "identity_invalid": not (partition_known and aliases_known),
    }


class SourceStore:
    """Disk-backed source processing, one decoded full snapshot at a time.

    The caller must budget source plus SQLite plus rollback bytes; quota is an
    explicit bound, never an output-discard policy. An oversized row/file refuses.
    """

    def __init__(self, path, *, quota_bytes, frozen=None):
        self.path, self.quota = Path(path), quota_bytes
        self.db = sqlite3.connect(path)
        self.db.execute("CREATE TABLE scans(id INTEGER PRIMARY KEY, row TEXT NOT NULL)")
        self.db.execute("CREATE TABLE batches(token INTEGER PRIMARY KEY, row TEXT NOT NULL)")
        self.db.execute("CREATE TABLE states(token INTEGER PRIMARY KEY, row TEXT NOT NULL)")
        self.db.execute("CREATE TABLE subscriber(seq INTEGER PRIMARY KEY, row TEXT NOT NULL)")
        self.db.execute(
            "CREATE TABLE provenance(bid INTEGER, gen INTEGER, stamp INTEGER, row TEXT)"
        )
        self.db.execute("CREATE INDEX provenance_lookup ON provenance(bid,gen,stamp)")
        self.certificates = {}
        self.orphan_exits = {}
        self.certificate_losses = {}
        self.slots = {}
        self.receipt = None
        self.raw_bytes = 0
        self.domain = NativeDomain({} if frozen is None else frozen)
        self.last_insertion = -1
        self.activation = None
        self.invalid_reset_epochs = set()
        self.gap_slots = set()

    def close(self):
        self.db.close()

    def ingest(self, lines):
        for line in lines:
            self.raw_bytes += len(line)
            if self.raw_bytes > self.quota or len(line) > 64 * 1024 * 1024:
                raise Refusal("source_quota")
            row = json.loads(line)
            kind = row["kind"]
            try:
                if kind == "activation":
                    if self.activation is not None:
                        raise Refusal("duplicate_activation")
                    self.activation = row
                elif kind == "scan":
                    source = row["scan"]
                    self.db.execute(
                        "INSERT INTO scans VALUES(?, ?)", (source["identity"], json.dumps(source))
                    )
                elif kind == "batch":
                    self.db.execute(
                        "INSERT INTO batches VALUES(?, ?)", (row["token"], json.dumps(row))
                    )
                elif kind == "provenance":
                    index, position, prompt, full, status, stamp = row["provenance"]
                    if stamp < self.last_insertion:
                        raise Refusal("provenance_order")
                    self.last_insertion = stamp
                    self.db.execute(
                        "INSERT INTO provenance VALUES(?,?,?,?)",
                        (
                            row["physical_id"],
                            row["generation"],
                            stamp,
                            json.dumps(row["provenance"]),
                        ),
                    )
                elif kind == "subscriber":
                    previous = self.db.execute(
                        "SELECT row FROM subscriber WHERE seq=?", (row["sequence"],)
                    ).fetchone()
                    events = json.dumps(row["events"])
                    if previous is not None and previous[0] != events:
                        raise Refusal("subscriber_duplicate_conflict")
                    self.db.execute(
                        "INSERT OR IGNORE INTO subscriber VALUES(?, ?)", (row["sequence"], events)
                    )
                elif kind == "entry":
                    if row["id"] in self.certificates:
                        raise Refusal("duplicate_block")
                    self.certificates[row["id"]] = row
                elif kind == "exit":
                    cert = self.certificates.get(row["id"])
                    if cert is None:
                        if row["id"] in self.orphan_exits:
                            raise Refusal("unknown_duplicate_exit")
                        # A dropped entry is a scoped certificate failure. The
                        # final receipt must prove the loss before this exit.
                        self.orphan_exits[row["id"]] = row
                    elif "exit" in cert:
                        raise Refusal("unknown_duplicate_exit")
                    else:
                        if cert["epoch"] != row["epoch"] or cert["thread"] != row["thread"]:
                            raise Refusal("closure_identity")
                        cert["exit"] = row["exit"]
                elif kind == "slot":
                    if row["slot"] in self.slots or not 0 <= row["slot"] < 48_001:
                        raise Refusal("duplicate_slot")
                    self.slots[row["slot"]] = row
                elif kind == "receipt":
                    if self.receipt is not None:
                        raise Refusal("duplicate_receipt")
                    self.receipt = row
                elif kind == "reset_result":
                    if row["error"] or row["result"] is not True:
                        self.invalid_reset_epochs.add(row["epoch"])
                elif kind != "reset":
                    raise Refusal("source_schema")
            except sqlite3.IntegrityError as exc:
                raise Refusal("duplicate_identity") from exc
            if len(self.certificates) + len(self.orphan_exits) > 48_001 or len(self.slots) > 18_001:
                raise Refusal("source_count")
            if (
                self.raw_bytes
                + sum(
                    p.stat().st_size
                    for p in (self.path, Path(str(self.path) + "-journal"))
                    if p.exists()
                )
                > self.quota
            ):
                raise Refusal("adapter_quota")
        self.db.commit()
        if self.receipt is None or self.receipt["first_failure"]:
            raise Refusal("incomplete_source")
        integrity = self.receipt.get("integrity", {})
        for identity, stamp in self.receipt.get("certificate_losses", []):
            if (
                type(identity) is not int
                or identity <= 0
                or type(stamp) is not int
                or stamp < 0
                or identity in self.certificate_losses
            ):
                raise Refusal("certificate_loss_schema")
            self.certificate_losses[identity] = stamp
        if len(self.certificate_losses) > 48_001:
            raise Refusal("source_count")
        if (
            "source" in integrity
            or (self.receipt["loss"] and not integrity and not self.certificate_losses)
            or set(integrity) - {"owner", "domain", "events", "certificates"}
            or any(type(stamp) is not int or stamp < 0 for stamp in integrity.values())
        ):
            raise Refusal("incomplete_source")
        for slot, cause, count in self.receipt.get("gaps", []):
            if (
                type(slot) is not int
                or not 0 <= slot < 48_001
                or not isinstance(cause, str)
                or type(count) is not int
                or count <= 0
            ):
                raise Refusal("gap_schema")
            self.gap_slots.add(slot)
        for row in self.orphan_exits.values():
            cutoff = self.certificate_losses.get(row["id"], integrity.get("certificates"))
            if cutoff is None or row["exit"] < cutoff:
                raise Refusal("unknown_duplicate_exit")
        # Receipt loss times are known only after ingest. An insertion lost at
        # t can change every subsequent alias/collision result, so replay only
        # the certified prefix; observations at/after t are invalidated below.
        cutoff = integrity.get("domain")
        for (encoded,) in self.db.execute("SELECT row FROM provenance ORDER BY stamp,rowid"):
            index, position, prompt, full, status, stamp = json.loads(encoded)
            if cutoff is not None and stamp >= cutoff:
                continue
            checked = (
                self.domain.unregistered(full, stamp)
                if index is None
                else self.domain.insertion(full, index, position, prompt, stamp)
            )
            if checked != status:
                raise Refusal("provenance_check")
        self.replay()

    def replay(self):
        live = None
        previous = None
        rows = self.db.execute("SELECT row FROM batches ORDER BY token")
        for (encoded,) in rows:
            row = json.loads(encoded)
            sequence = row["sequence"]
            delivery = self.db.execute(
                "SELECT row FROM subscriber WHERE seq=?", (sequence,)
            ).fetchone()
            delivered = delivery is not None and json.loads(delivery[0]) == row["events"]
            if not delivered:
                live = None
            if (
                row["error"]
                or sequence is None
                or (previous is not None and sequence != previous + 1)
            ):
                live = None
            previous = sequence
            before = None if live is None else sorted(live)
            prefixes = {n: [] for _, n, exact in row["prefixes"] if exact}
            for position, (kind, keys, group) in enumerate(row["events"], 1):
                if row["error"] or sequence is None or not delivered:
                    live = None
                elif kind == "AllBlocksCleared":
                    live = set()
                elif group != 0:
                    live = None
                elif live is not None:
                    if kind == "BlockStored":
                        live.update(keys)
                    elif kind == "BlockRemoved":
                        live.difference_update(keys)
                    else:
                        raise Refusal("event_kind")
                if position in prefixes:
                    prefixes[position] = None if live is None else sorted(live)
            state = {
                "before": before,
                "after": None if live is None else sorted(live),
                "prefixes": prefixes,
                "sequence": sequence,
                "associations": row["prefixes"],
            }
            self.db.execute("INSERT INTO states VALUES(?, ?)", (row["token"], json.dumps(state)))
            if self.raw_bytes + self.path.stat().st_size > self.quota:
                raise Refusal("adapter_quota")
        self.db.commit()

    def scan(self, identity):
        row = self.db.execute("SELECT row FROM scans WHERE id=?", (identity,)).fetchone()
        return None if row is None else json.loads(row[0])

    def verify_provenance(self, scan):
        for bid, generation, _refs, null, aliases, _free, provenance in scan["physical"]:
            if null or not aliases:
                continue
            if provenance is None:
                raise Refusal("missing_provenance")
            _index, position, prompt, _full, _status, stamp = provenance
            if position < prompt // 16 and _status != "unregistered":
                continue
            row = self.db.execute(
                "SELECT row FROM provenance WHERE bid=? AND gen=? AND stamp=?",
                (bid, generation, stamp),
            ).fetchall()
            if not any(json.loads(encoded) == provenance for (encoded,) in row):
                raise Refusal("generated_provenance_join")

    def event_join(self, scan):
        token = scan["preceding_token"]
        if scan["pending_count"]:
            # The immediately following *native* batch, never a later repair.
            row = self.db.execute(
                "SELECT row FROM states WHERE token>? ORDER BY token LIMIT 1",
                (-1 if token is None else token,),
            ).fetchone()
            if row is None:
                return None, None
            state = json.loads(row[0])
            match = [r for r in state["associations"] if r[0] == scan["identity"]]
            if len(match) != 1 or not match[0][2] or match[0][1] != scan["pending_count"]:
                return None, None
            return state["prefixes"].get(str(match[0][1])), state["sequence"]
        row = self.db.execute("SELECT row FROM states WHERE token=?", (token,)).fetchone()
        if row is None:
            return None, None
        state = json.loads(row[0])
        return state["after"], state["sequence"]

    def observations(self, *, origin, first_slot, last_slot, epoch, phase):
        fresh = {}
        for (encoded,) in self.db.execute("SELECT row FROM scans ORDER BY id"):
            scan = json.loads(encoded)
            slot = (scan["end"] - origin) // CADENCE_NS
            if scan["scan_kind"] == "ordinary" and (scan["start"] - origin) // CADENCE_NS == slot:
                if slot in fresh:
                    raise Refusal("duplicate_fresh")
                fresh[slot] = scan["identity"]
        for slot in range(first_slot, last_slot + 1):
            source = self.slots.get(slot)
            queue = queue_sample(None if source is None else source["queue"], origin, slot)
            scan = self.scan(fresh[slot]) if slot in fresh else None
            observed = None if scan is None else scan["end"]

            def evaluate(candidate, stamp, held=False, certificate_id=None):
                if candidate is None:
                    return {}, None, None
                if candidate["epoch"] != epoch:
                    return {}, None, "epoch"
                if epoch in self.invalid_reset_epochs:
                    return {}, None, "reset_failed"
                integrity = self.receipt.get("integrity", {})
                for scope in ("owner", "domain", *(("certificates",) if held else ())):
                    if scope in integrity and stamp >= integrity[scope]:
                        return {}, None, "integrity:" + scope
                if held and certificate_id in self.certificate_losses:
                    return {}, None, "integrity:certificate"
                live, sequence = self.event_join(candidate)
                event_loss = "events" in integrity and stamp >= integrity["events"]
                if event_loss:
                    live, sequence = None, None
                try:
                    self.verify_provenance(candidate)
                    counts = physical_counts(candidate, self.domain, live, observed_ns=stamp)
                    invalid = "request_identity" if counts.pop("identity_invalid") else None
                    return counts, sequence, invalid or ("integrity:events" if event_loss else None)
                except Refusal as exc:
                    return {}, None, str(exc)

            counts, sequence, invalid = evaluate(scan, observed)
            owner_quantities = ("cached", "shared", "non_shared", "evictable", "capacity")
            fresh_complete = invalid is None and all(
                counts.get(k) is not None for k in owner_quantities
            )
            if not fresh_complete and source is not None and source["scan_id"] is not None:
                candidate = self.scan(source["scan_id"])
                certificate = self.certificates.get(source["certificate"])
                if candidate is not None and held_valid(
                    candidate, certificate, source["observed_ns"], origin, slot
                ):
                    held_counts, held_sequence, held_error = evaluate(
                        candidate,
                        source["observed_ns"],
                        held=True,
                        certificate_id=source["certificate"],
                    )
                    if scan is None or (
                        held_error is None
                        and all(held_counts.get(k) is not None for k in owner_quantities)
                    ):
                        scan, observed = candidate, source["observed_ns"]
                        counts, sequence, invalid = held_counts, held_sequence, held_error
            values = {k: counts.get(k) for k in QUANTITIES if k != "lag"}
            values["queue"] = None if queue is None else queue["queue_depth"]
            complete = all(value is not None for value in values.values())
            status = (
                3
                if invalid
                else 0
                if complete
                else 1
                if any(v is not None for v in values.values())
                else 2
            )
            yield {
                "cadence_slot": slot,
                "snapshot_index": slot,
                "arm": 1,
                "phase": phase,
                "reset_epoch": epoch,
                "status": status,
                "observed_ns": origin + slot * CADENCE_NS if observed is None else observed,
                "scan_duration_ns": 0 if scan is None else scan["end"] - scan["start"],
                "sample_age_ns": 0 if scan is None else observed - scan["end"],
                "values": values,
                "counts": counts,
                "queue": queue,
                "join_sequence": sequence,
                "source_present": scan is not None,
                "invalid_reason": invalid,
            }


def attach_observations(run, observations):
    """Map to existing widths/masks and real serializer; no new resident column."""
    result = copy.deepcopy(run)
    result["snapshot_count_sources"] = [
        row for row in result["snapshot_count_sources"] if row["arm"] == 0
    ]
    sources = list(observations)
    from .stage_c_registered import SNAPSHOT_FIELDS

    fields = [token.split(":")[0] for token in SNAPSHOT_FIELDS.split()]
    for source in sources:
        row = dict.fromkeys(fields, 0)
        row["snapshot_index"] = source["cadence_slot"]
        for name in fields:
            if name in source:
                row[name] = source[name]
            elif name in source["counts"]:
                row[name] = source["counts"][name] or 0
        if source["queue"] is not None:
            row.update({k: v for k, v in source["queue"].items() if k != "observed_ns"})
        row["join_sequence"] = source["join_sequence"] or 0
        row["presence_bitmap"] = sum(
            1 << i
            for i, k in enumerate(QUANTITIES)
            if k != "lag" and source["values"].get(k) is not None
        )
        result["snapshot_count_sources"].append(row)
    for phase in result["exposures"]:
        if phase["arm"] != 1:
            continue
        for quantity in QUANTITIES:
            if quantity == "lag":
                continue
            phase["samples"][quantity] = []
            for source in sources:
                stamp = source["observed_ns"]
                if quantity == "queue" and source["queue"] is not None:
                    stamp = source["queue"]["observed_ns"]
                value = source["values"].get(quantity)
                if phase["start_ns"] <= stamp < phase["end_ns"]:
                    ok = value is not None and (
                        quantity == "queue" or source["invalid_reason"] is None
                    )
                    phase["samples"][quantity].append([stamp, value, ok])
    return result


def seal_observations(path, run, observations):
    return seal_registered(path, attach_observations(run, observations))
