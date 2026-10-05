"""Disk-indexed correlation preserving the R087/R088/R089 window rules."""

import json

from .disk_records import DiskList


def correlate(decisions, observations, allowance):
    index = DiskList()
    db = index.db
    db.executescript("""
        create table decisions(identity text, t integer);
        create index decision_time on decisions(identity,t);
        create table owners(digest text, identity text, primary key(digest,identity));
        create table events(n integer primary key, t integer, seq integer, value text);
        create table blocks(digest text, t integer, seq integer, n integer);
        create index block_time on blocks(digest,t,seq,n);
        create table shared(digest text primary key);
    """)

    def identity(row):
        return json.dumps(
            row.get("prompt_identity_sha256", row["expected_token_block_digests"]), sort_keys=True
        )

    for row in decisions:
        key = identity(row)
        db.execute(
            "insert into decisions values (?,?)", (key, row["routing_decision_monotonic_ns"])
        )
        db.executemany(
            "insert or ignore into owners values (?,?)",
            ((digest, key) for digest in set(row["expected_token_block_digests"])),
        )
    db.execute("insert into shared select digest from owners group by digest having count(*)>1")
    for n, row in enumerate(observations):
        if str(row.get("event_type", "")).lower() not in {"blockstored", "block_stored"}:
            continue
        t, seq = row["observed_monotonic_ns"], row["sequence"]
        db.execute("insert into events values (?,?,?,?)", (n, t, seq, json.dumps(row)))
        db.executemany(
            "insert into blocks values (?,?,?,?)",
            ((digest, t, seq, n) for digest in set(row.get("token_block_digests", []))),
        )
    results = DiskList()
    for decision in decisions:
        decision_ns = decision["routing_decision_monotonic_ns"]
        terminal_ns = decision.get("gateway_terminal_monotonic_ns")
        if type(terminal_ns) is not int or terminal_ns < decision_ns:
            raise ValueError("invalid or missing gateway terminal timestamp for correlation")
        end = terminal_ns + allowance
        next_ns = db.execute(
            "select min(t) from decisions where identity=? and t>?",
            (identity(decision), decision_ns),
        ).fetchone()[0]
        original = set(decision["expected_token_block_digests"])
        shared = {
            digest
            for digest in original
            if db.execute("select 1 from shared where digest=?", (digest,)).fetchone()
        }
        expected = original - shared
        failed = decision.get("no_store_expected_request_failed", False)
        no_new = decision.get("no_new_block", not original)
        earliest = None
        if not failed and not no_new:
            for digest in expected:
                candidate = db.execute(
                    "select t,seq,n from blocks where digest=? and t>? order by t,seq,n limit 1",
                    (digest, decision_ns),
                ).fetchone()
                if candidate and (earliest is None or candidate < earliest):
                    earliest = candidate
        first = (
            json.loads(
                db.execute("select value from events where n=?", (earliest[2],)).fetchone()[0]
            )
            if earliest
            else None
        )
        late = first is not None and first["observed_monotonic_ns"] > end
        if late and next_ns is not None and first["observed_monotonic_ns"] >= next_ns:
            first, late = None, False
        observed = first["observed_monotonic_ns"] if first else None
        status = (
            "no_store_expected_request_failed"
            if failed
            else "no_new_block"
            if no_new
            else "observed_after_request_window"
            if late
            else "observed"
            if first
            else "no_post_decision_store_event"
            if decision.get("cached_prompt_tokens") is not None
            else "no_identity_specific_store_cache_state_unknown"
        )
        basis = (
            "identity_specific_16_token_block_digest"
            if first
            else "request_failed_or_cancelled_before_content"
            if failed
            else "cached_prompt_tokens_or_no_full_block"
            if no_new
            else "cache_state_unknown_no_identity_specific_store_before_next_identity_decision"
            if decision.get("cached_prompt_tokens") is None
            else "no_identity_specific_store_before_next_identity_decision"
        )
        results.append(
            dict(
                request_id=decision["request_id"],
                status=status,
                match_basis=basis,
                routing_decision_monotonic_ns=decision_ns,
                gateway_terminal_monotonic_ns=terminal_ns,
                request_lifetime_ns=terminal_ns - decision_ns,
                publisher_flush_allowance_ns=allowance,
                store_observation_window_end_monotonic_ns=end,
                next_same_identity_decision_monotonic_ns=next_ns,
                event_observed_monotonic_ns=observed,
                routing_to_event_observation_ns=observed - decision_ns
                if observed is not None
                else None,
                event_sequence=first["sequence"] if first else None,
                excluded_shared_digest_count=len(shared),
                matched_token_block_digests=sorted(
                    expected.intersection(first["token_block_digests"])
                )
                if first
                else [],
            )
        )
    index.close()
    return results
