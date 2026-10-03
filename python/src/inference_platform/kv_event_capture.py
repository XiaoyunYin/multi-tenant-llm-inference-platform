"""Standalone vLLM KV-event capture and routing-decision correlation.

The live source is vLLM's versioned ZeroMQ PUB stream. JSONL is supported for
offline rehearsal. Raw token IDs and block hashes are never written to output;
only digests needed for matching are retained.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

from .clocks import measurement_clocks
from .time_budget import deadline_urlopen


def _canonical_hash(value: Any) -> str:
    if isinstance(value, bytes):
        material = value
    elif isinstance(value, str):
        material = value.encode("utf-8")
    else:
        material = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


TOKEN_BLOCK_SIZE = 16


def token_block_digests(token_ids: Sequence[int]) -> list[str]:
    """Hash full, aligned 16-token blocks in order; omit a trailing partial block."""
    if any(
        isinstance(token, bool) or not isinstance(token, int) or token < 0 for token in token_ids
    ):
        raise ValueError("token IDs must be non-negative integers")
    return [
        _canonical_hash(list(token_ids[start : start + TOKEN_BLOCK_SIZE]))
        for start in range(0, len(token_ids) - TOKEN_BLOCK_SIZE + 1, TOKEN_BLOCK_SIZE)
    ]


def _batch_parts(decoded: Any) -> tuple[float | None, Sequence[Any]]:
    if isinstance(decoded, Mapping):
        events = decoded.get("events")
        timestamp = decoded.get("ts")
    elif isinstance(decoded, (list, tuple)) and len(decoded) >= 2:
        timestamp, events = decoded[0], decoded[1]
    else:
        raise ValueError("vLLM event payload is not an EventBatch")
    if not isinstance(events, (list, tuple)):
        raise ValueError("vLLM EventBatch events field is not an array")
    if timestamp is not None and not isinstance(timestamp, (int, float)):
        raise ValueError("vLLM EventBatch timestamp is invalid")
    return (float(timestamp) if timestamp is not None else None), events


def _event_value(event: Any, key: str) -> Any:
    if isinstance(event, Mapping):
        return event.get(key)
    if isinstance(event, (list, tuple)):
        return None
    return getattr(event, key, None)


def event_observations(
    sequence: int,
    events: Sequence[Any],
    *,
    observed_monotonic_ns: int,
    batch_timestamp_s: float | None = None,
) -> list[dict[str, Any]]:
    """Normalize a decoded batch to redacted observations for correlation."""

    observations: list[dict[str, Any]] = []
    for event in events:
        event_type = _event_value(event, "type") or _event_value(event, "tag")
        block_hashes = _event_value(event, "block_hashes")
        token_ids = _event_value(event, "token_ids")
        group_idx = _event_value(event, "group_idx")
        medium = _event_value(event, "medium")
        locality = _event_value(event, "locality")
        if not isinstance(event_type, str):
            event_type = type(event).__name__
        if not isinstance(block_hashes, (list, tuple)):
            block_hashes = []
        block_size = _event_value(event, "block_size")
        if token_ids is not None and block_size not in (None, TOKEN_BLOCK_SIZE):
            raise ValueError("KV capture requires the pinned 16-token block size")
        observations.append(
            {
                "sequence": sequence,
                "event_type": event_type,
                "group_idx": group_idx,
                "medium": medium,
                "locality": locality,
                "batch_timestamp_s": batch_timestamp_s,
                "observed_monotonic_ns": observed_monotonic_ns,
                "observed_unix_ns": time.time_ns(),
                "block_hash_digests": sorted({_canonical_hash(value) for value in block_hashes}),
                "token_block_digests": token_block_digests(token_ids)
                if isinstance(token_ids, (list, tuple))
                else [],
                "token_block_size": TOKEN_BLOCK_SIZE,
                "token_count": len(token_ids) if isinstance(token_ids, (list, tuple)) else None,
            }
        )
    return observations


def derive_event_inventory(observations: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Derive a redacted cached-block live set and removal rate from event observations."""

    ordered = sorted(
        observations,
        key=lambda event: (event.get("observed_monotonic_ns", 0), event.get("sequence", 0)),
    )
    live: set[tuple[Any, Any, Any, str]] = set()
    stored_hash_count = 0
    removed_hash_count = 0
    reset_count = 0
    epochs: list[dict[str, int]] = []
    epoch = {"epoch": 0, "block_stores": 0, "block_removals": 0, "peak_live_blocks": 0}
    for event in ordered:
        event_type = str(event.get("event_type", "")).lower()
        if event_type in {"allblockscleared", "all_blocks_cleared"}:
            epochs.append({**epoch, "end_live_blocks": len(live)})
            live.clear()
            reset_count += 1
            epoch = {
                "epoch": reset_count,
                "block_stores": 0,
                "block_removals": 0,
                "peak_live_blocks": 0,
            }
            continue
        group_idx = event.get("group_idx")
        medium = event.get("medium")
        locality = event.get("locality")
        digests = event.get("block_hash_digests", [])
        if not isinstance(digests, list):
            continue
        if event_type in {"blockstored", "block_stored"}:
            for digest in digests:
                live.add((group_idx, medium, locality, str(digest)))
                stored_hash_count += 1
                epoch["block_stores"] += 1
        elif event_type in {"blockremoved", "block_removed"}:
            for digest in digests:
                live.discard((group_idx, medium, locality, str(digest)))
                removed_hash_count += 1
                epoch["block_removals"] += 1
        epoch["peak_live_blocks"] = max(epoch["peak_live_blocks"], len(live))
    epochs.append({**epoch, "end_live_blocks": len(live)})
    sequences = sorted({int(event["sequence"]) for event in ordered if "sequence" in event})
    sequence_gaps = sum(
        max(0, current - previous - 1)
        for previous, current in zip(sequences, sequences[1:], strict=False)
    )
    if len(ordered) >= 2:
        elapsed_ns = ordered[-1].get("observed_monotonic_ns", 0) - ordered[0].get(
            "observed_monotonic_ns", 0
        )
    else:
        elapsed_ns = 0
    return {
        "block_stores_observed": stored_hash_count,
        "block_removals_observed": removed_hash_count,
        "cached_live_block_count_at_end": len(live),
        "cache_reset_count": reset_count,
        "maximum_epoch_live_blocks": max(epoch["peak_live_blocks"] for epoch in epochs),
        "epochs": epochs,
        "eviction_rate_blocks_per_second": (
            removed_hash_count / (elapsed_ns / 1_000_000_000) if elapsed_ns > 0 else None
        ),
        "publisher_sequence_gap_count": sequence_gaps,
        "live_set_complete": sequence_gaps == 0,
    }


def read_jsonl_event_stream(
    lines: Iterable[str], *, clock_ns: Callable[[], int] = time.perf_counter_ns
) -> list[dict[str, Any]]:
    """Consume normalized fake EventBatch JSONL and timestamp each observation."""

    observations: list[dict[str, Any]] = []
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            batch = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"invalid fake event JSONL at line {line_number}") from error
        if not isinstance(batch, Mapping):
            raise ValueError(f"fake event JSONL at line {line_number} must be an object")
        sequence = batch.get("sequence")
        events = batch.get("events")
        timestamp = batch.get("batch_timestamp_s")
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 0:
            raise ValueError(f"fake event sequence at line {line_number} is invalid")
        if not isinstance(events, list):
            raise ValueError(f"fake event list at line {line_number} is invalid")
        observations.extend(
            event_observations(
                sequence,
                events,
                observed_monotonic_ns=batch.get("emitted_monotonic_ns", clock_ns()),
                batch_timestamp_s=timestamp,
            )
        )
    return observations


def read_http_sse_event_stream(
    endpoint: str,
    *,
    duration_seconds: float = 0.05,
    clock_ns: Callable[[], int] = time.perf_counter_ns,
    timeout_seconds: float = 2,
    deadline: float | None = None,
) -> list[dict[str, Any]]:
    """Read the fake backend's finite SSE KV-event stream for offline rehearsal."""

    if duration_seconds <= 0 or duration_seconds > 60:
        raise ValueError("fake event stream duration must be in (0, 60] seconds")
    url = f"{endpoint.rstrip('/')}?after=0&duration={duration_seconds}"
    batches: list[str] = []
    with deadline_urlopen(
        url, timeout=duration_seconds + timeout_seconds, deadline=deadline
    ) as response:
        if response.status != 200:
            raise RuntimeError(f"fake KV-event stream returned HTTP {response.status}")
        for raw_line in response:
            line = raw_line.decode("utf-8", errors="strict").strip()
            if line.startswith("data: "):
                batches.append(line[6:])
    return read_jsonl_event_stream(batches, clock_ns=clock_ns)


PUBLISHER_FLUSH_ALLOWANCE_NS = 1_000_000_000
CORRELATION_BASIS = (
    "identity-specific 16-token block overlap; decision < store observation <= gateway terminal "
    "+ 1000000000 ns (1 s) publisher-flush allowance for observed; later first stores are "
    "observed_after_request_window only before the next same-identity decision and are excluded "
    "from the in-window distribution; no matched store with unknown cached_prompt_tokens is "
    "no_identity_specific_store_cache_state_unknown; no_post_decision_store_event requires a "
    "known cached-token count that leaves at least one full prompt block to store; requests failed/cancelled before content "
    "excluded; overlap does not prove unique ownership for identical concurrent prompts"
)


def load_routing_decisions(
    path: Path, *, wall_to_monotonic_offset_ns: int | None = None
) -> list[dict[str, Any]]:
    """Load the bounded decision-export schema consumed by the capture tool."""

    decisions: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"invalid decision JSONL at line {line_number}") from error
            if not isinstance(value, Mapping):
                raise ValueError(f"decision at line {line_number} must be an object")
            request_id = value.get("request_id")
            decided_at = value.get("routing_decision_monotonic_ns")
            if decided_at is None and "router_decision_unix_ns" in value:
                wall_time = value.get("router_decision_unix_ns")
                if isinstance(wall_time, bool) or not isinstance(wall_time, int) or wall_time < 0:
                    raise ValueError(f"decision wall timestamp at line {line_number} is invalid")
                if wall_to_monotonic_offset_ns is None:
                    raise ValueError(
                        "wall-clock decisions require a wall-to-monotonic clock offset"
                    )
                decided_at = wall_time - wall_to_monotonic_offset_ns
            expected_token_ids = value.get("expected_token_ids")
            if not isinstance(request_id, str) or not request_id:
                raise ValueError(f"decision request_id at line {line_number} is invalid")
            if isinstance(decided_at, bool) or not isinstance(decided_at, int) or decided_at < 0:
                raise ValueError(f"decision monotonic timestamp at line {line_number} is invalid")
            terminal_at = value.get("gateway_terminal_monotonic_ns")
            if terminal_at is None and "gateway_terminal_unix_ns" in value:
                wall_terminal = value["gateway_terminal_unix_ns"]
                if type(wall_terminal) is not int or wall_terminal < 0:
                    raise ValueError(f"gateway terminal timestamp at line {line_number} is invalid")
                if wall_to_monotonic_offset_ns is None:
                    raise ValueError(
                        "wall-clock terminal requires a wall-to-monotonic clock offset"
                    )
                terminal_at = wall_terminal - wall_to_monotonic_offset_ns
            if type(terminal_at) is not int or terminal_at < decided_at:
                raise ValueError(f"gateway terminal timestamp at line {line_number} is invalid")
            failed = value.get("no_store_expected_request_failed", False)
            if type(failed) is not bool:
                raise ValueError(f"decision failed-request flag at line {line_number} is invalid")
            if not isinstance(expected_token_ids, list) or not expected_token_ids:
                raise ValueError(f"decision expected_token_ids at line {line_number} is invalid")
            digests = token_block_digests(expected_token_ids)
            cached_tokens = value.get("cached_prompt_tokens")
            if cached_tokens is not None and (
                isinstance(cached_tokens, bool)
                or not isinstance(cached_tokens, int)
                or not 0 <= cached_tokens <= len(expected_token_ids)
            ):
                raise ValueError(f"decision cached_prompt_tokens at line {line_number} is invalid")
            no_new_block = not digests or (
                cached_tokens is not None and cached_tokens // TOKEN_BLOCK_SIZE >= len(digests)
            )
            decisions.append(
                {
                    "request_id": request_id,
                    "routing_decision_monotonic_ns": decided_at,
                    "gateway_terminal_monotonic_ns": terminal_at,
                    "no_store_expected_request_failed": failed,
                    "expected_token_block_digests": digests,
                    "prompt_identity_sha256": hashlib.sha256(
                        json.dumps(expected_token_ids).encode()
                    ).hexdigest(),
                    "cached_prompt_tokens": cached_tokens,
                    "no_new_block": no_new_block,
                }
            )
    return decisions


def correlate_routing_events(
    decisions: Sequence[Mapping[str, Any]], observations: Sequence[Mapping[str, Any]]
) -> list[dict[str, Any]]:
    """Separate in-window stores from late stores before the next identity decision.

    This is token-block overlap, not proof of unique request ownership. A shared
    prefix or identical concurrent prompts can be ambiguous; report the basis.
    """
    stored_events = sorted(
        (
            event
            for event in observations
            if str(event.get("event_type", "")).lower() in {"blockstored", "block_stored"}
        ),
        key=lambda event: (event["observed_monotonic_ns"], event["sequence"]),
    )
    # Sustained levels produce many decisions. Index each block's ordered events
    # rather than rescanning the full capture for every request at export time.
    from bisect import bisect_right

    by_block: dict[str, list[tuple[int, int]]] = {}
    owners: dict[str, set] = {}
    by_identity: dict[Any, list[int]] = {}

    def prompt_identity(decision):
        return decision.get(
            "prompt_identity_sha256", tuple(decision["expected_token_block_digests"])
        )

    for decision in decisions:
        identity = prompt_identity(decision)
        by_identity.setdefault(identity, []).append(decision["routing_decision_monotonic_ns"])
        for digest in set(decision["expected_token_block_digests"]):
            owners.setdefault(digest, set()).add(identity)
    for times in by_identity.values():
        times.sort()
    shared = {digest for digest, identities in owners.items() if len(identities) > 1}
    for index, event in enumerate(stored_events):
        for digest in set(event.get("token_block_digests", [])):
            by_block.setdefault(digest, []).append((event["observed_monotonic_ns"], index))
    results: list[dict[str, Any]] = []
    for decision in decisions:
        decision_ns = decision["routing_decision_monotonic_ns"]
        terminal_ns = decision.get("gateway_terminal_monotonic_ns")
        if type(terminal_ns) is not int or terminal_ns < decision_ns:
            raise ValueError("invalid or missing gateway terminal timestamp for correlation")
        window_end_ns = terminal_ns + PUBLISHER_FLUSH_ALLOWANCE_NS
        identity_times = by_identity[prompt_identity(decision)]
        next_position = bisect_right(identity_times, decision_ns)
        next_decision_ns = (
            identity_times[next_position] if next_position < len(identity_times) else None
        )
        failed = decision.get("no_store_expected_request_failed", False)
        original = set(decision["expected_token_block_digests"])
        expected = original - shared
        no_new_block = decision.get("no_new_block", not original)
        candidates = []
        if not no_new_block and not failed:
            for digest in expected:
                occurrences = by_block.get(digest, [])
                position = bisect_right(occurrences, (decision_ns, len(stored_events)))
                if position < len(occurrences):
                    candidates.append(occurrences[position][1])
        first = stored_events[min(candidates)] if candidates else None
        late = first is not None and first["observed_monotonic_ns"] > window_end_ns
        if (
            late
            and next_decision_ns is not None
            and first["observed_monotonic_ns"] >= next_decision_ns
        ):
            first = None  # A repeated dispatch makes late ownership ambiguous.
            late = False
        observed_ns = first["observed_monotonic_ns"] if first else None
        results.append(
            {
                "request_id": decision["request_id"],
                "status": "no_store_expected_request_failed"
                if failed
                else "no_new_block"
                if no_new_block
                else "observed_after_request_window"
                if late
                else "observed"
                if first
                else "no_post_decision_store_event"
                if decision.get("cached_prompt_tokens") is not None
                else "no_identity_specific_store_cache_state_unknown",
                "match_basis": "identity_specific_16_token_block_digest"
                if first
                else (
                    "request_failed_or_cancelled_before_content"
                    if failed
                    else "cached_prompt_tokens_or_no_full_block"
                    if no_new_block
                    else "cache_state_unknown_no_identity_specific_store_before_next_identity_decision"
                    if decision.get("cached_prompt_tokens") is None
                    else "no_identity_specific_store_before_next_identity_decision"
                ),
                "routing_decision_monotonic_ns": decision_ns,
                "gateway_terminal_monotonic_ns": terminal_ns,
                "request_lifetime_ns": terminal_ns - decision_ns,
                "publisher_flush_allowance_ns": PUBLISHER_FLUSH_ALLOWANCE_NS,
                "store_observation_window_end_monotonic_ns": window_end_ns,
                "next_same_identity_decision_monotonic_ns": next_decision_ns,
                "event_observed_monotonic_ns": observed_ns,
                "routing_to_event_observation_ns": (
                    observed_ns - decision_ns if observed_ns is not None else None
                ),
                "event_sequence": first["sequence"] if first else None,
                "excluded_shared_digest_count": len(original & shared),
                "matched_token_block_digests": sorted(
                    expected.intersection(first["token_block_digests"])
                )
                if first
                else [],
            }
        )
    return results


def summarize_routing_correlations(correlations: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    from collections import Counter

    counts = dict(Counter(row["status"] for row in correlations))
    observed = [row for row in correlations if row["status"] == "observed"]
    late = [row for row in correlations if row["status"] == "observed_after_request_window"]
    violations = sum(
        not (
            0
            < row["routing_to_event_observation_ns"]
            <= row["request_lifetime_ns"] + row["publisher_flush_allowance_ns"]
        )
        for row in observed
    )
    return {
        "basis": CORRELATION_BASIS,
        "publisher_flush_allowance_ns": PUBLISHER_FLUSH_ALLOWANCE_NS,
        "observed_correlation_count": len(observed),
        "max_observed_lag_ns": max(
            (row["routing_to_event_observation_ns"] for row in observed), default=None
        ),
        "observed_after_request_window_count": len(late),
        "max_observed_after_request_window_lag_ns": max(
            (row["routing_to_event_observation_ns"] for row in late), default=None
        ),
        "status_counts": counts,
        "excluded_counts": {
            status: count for status, count in counts.items() if status != "observed"
        },
        "excluded_count": len(correlations) - len(observed),
        "no_store_expected_request_failed_count": counts.get("no_store_expected_request_failed", 0),
        "no_post_decision_store_event_count": counts.get("no_post_decision_store_event", 0),
        "no_identity_specific_store_cache_state_unknown_count": counts.get(
            "no_identity_specific_store_cache_state_unknown", 0
        ),
        "request_lifetime_bound_violation_count": violations,
    }


def decode_vllm_msgpack_batch(
    payload: bytes, *, sequence: int, observed_monotonic_ns: int
) -> list[dict[str, Any]]:
    """Decode the pinned EventBatch msgpack frame without retaining token IDs."""

    try:
        import msgspec
    except ImportError as error:  # pragma: no cover - exercised in capture deployment
        raise RuntimeError(
            "install msgspec in the capture environment to decode vLLM KV events"
        ) from error
    try:
        decoded = msgspec.msgpack.decode(payload)
        batch_timestamp_s, events = _batch_parts(decoded)
    except (msgspec.DecodeError, TypeError, ValueError) as error:
        raise ValueError(f"invalid vLLM EventBatch payload: {error}") from error
    return event_observations(
        sequence,
        events,
        observed_monotonic_ns=observed_monotonic_ns,
        batch_timestamp_s=batch_timestamp_s,
    )


def capture_zmq_event_stream(
    endpoint: str,
    *,
    duration_seconds: float,
    topic: str = "kv-events",
    clock_ns: Callable[[], int] = time.perf_counter_ns,
    on_subscribed: Callable[[], None] | None = None,
    stop_after_block_stored: bool = False,
    stop_file: Path | None = None,
) -> list[dict[str, Any]]:
    """Capture vLLM's PUB multipart frames: topic, uint64 sequence, msgpack batch."""

    measurement_clocks(wall_clock=True)
    if duration_seconds <= 0:
        raise ValueError("capture duration must be positive")
    try:
        import zmq
    except ImportError as error:  # pragma: no cover - exercised in capture deployment
        raise RuntimeError(
            "install pyzmq in the capture environment to subscribe to vLLM KV events"
        ) from error
    context = zmq.Context.instance()
    subscriber = context.socket(zmq.SUB)
    subscriber.setsockopt(zmq.LINGER, 0)
    subscriber.setsockopt(zmq.SUBSCRIBE, topic.encode("utf-8"))
    subscriber.connect(endpoint)
    poller = zmq.Poller()
    poller.register(subscriber, zmq.POLLIN)
    deadline = time.perf_counter() + duration_seconds
    observations: list[dict[str, Any]] = []
    try:
        if on_subscribed:
            on_subscribed()
        while time.perf_counter() < deadline and not (stop_file and stop_file.exists()):
            remaining_ms = max(1, min(100, int((deadline - time.perf_counter()) * 1_000)))
            if not dict(poller.poll(remaining_ms)).get(subscriber):
                continue
            frames = subscriber.recv_multipart()
            if len(frames) != 3 or len(frames[1]) != 8:
                raise ValueError("vLLM KV publisher emitted an invalid multipart frame")
            sequence = int.from_bytes(frames[1], "big")
            observations.extend(
                decode_vllm_msgpack_batch(
                    frames[2], sequence=sequence, observed_monotonic_ns=clock_ns()
                )
            )
            if stop_after_block_stored and any(
                event["event_type"] == "BlockStored" for event in observations
            ):
                break
    finally:
        poller.unregister(subscriber)
        subscriber.close(linger=0)
    return observations


def probe_zmq_publisher(
    endpoint: str, topic: str, probe_url: str, model: str, duration_seconds: float
) -> dict[str, Any]:
    """Subscribe before a unique untimed request; require a real decoded BlockStored."""
    import urllib.request
    import uuid

    from .time_budget import deadline_urlopen

    deadline = time.perf_counter() + duration_seconds

    def trigger() -> None:
        # Allow subscription propagation; this warm-up is outside all measured runs.
        time.sleep(0.25)
        request = urllib.request.Request(
            probe_url.rstrip("/") + "/v1/chat/completions",
            data=json.dumps(
                {
                    "model": model,
                    "messages": [
                        {
                            "role": "user",
                            "content": (f"stage-c publisher readiness {uuid.uuid4().hex} " * 32),
                        }
                    ],
                    "max_tokens": 1,
                    "stream": False,
                }
            ).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with deadline_urlopen(request, timeout=10, deadline=deadline) as response:
            response.read(64 * 1024)

    events = capture_zmq_event_stream(
        endpoint,
        topic=topic,
        duration_seconds=duration_seconds,
        on_subscribed=trigger,
        stop_after_block_stored=True,
    )
    stored = sum(event["event_type"] == "BlockStored" for event in events)
    return {
        "status": "ok" if stored else "unavailable",
        "endpoint": endpoint,
        "topic": topic,
        "decoded_block_stored_count": stored,
        "clock_info": measurement_clocks(wall_clock=True),
        "basis": "same-container ZMQ subscription and unique untimed warm-up request",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", choices=("zmq", "jsonl"), default="zmq")
    parser.add_argument(
        "--endpoint", help="vLLM KV-event publisher endpoint, e.g. tcp://127.0.0.1:5557"
    )
    parser.add_argument(
        "--events-jsonl", type=Path, help="finite normalized stream for offline rehearsal"
    )
    parser.add_argument("--topic", default="kv-events")
    parser.add_argument("--duration-seconds", type=float, default=3600)
    parser.add_argument("--stop-file", type=Path, help="Controller touches this to flush early")
    parser.add_argument("--ready-file", type=Path, help="Local subscription startup receipt")
    parser.add_argument("--decisions", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--readiness-probe", action="store_true")
    parser.add_argument("--probe-url", default="http://127.0.0.1:8000")
    parser.add_argument("--model")
    args = parser.parse_args()
    if args.readiness_probe:
        if not args.endpoint or not args.model:
            parser.error("--endpoint and --model are required for --readiness-probe")
        try:
            probe = probe_zmq_publisher(
                args.endpoint, args.topic, args.probe_url, args.model, args.duration_seconds
            )
        except (RuntimeError, ValueError, OSError) as error:
            probe = {"status": "unavailable", "reason": str(error)}
        print(json.dumps(probe))
        return int(probe["status"] != "ok")
    if args.decisions is None or args.output is None:
        parser.error("--decisions and --output are required for capture")
    clocks = measurement_clocks(wall_clock=True)
    start_wall_ns = time.time_ns()
    start_monotonic_ns = time.perf_counter_ns()
    if args.source == "zmq":
        if not args.endpoint:
            parser.error("--endpoint is required for --source zmq")
        observations = capture_zmq_event_stream(
            args.endpoint,
            duration_seconds=args.duration_seconds,
            topic=args.topic,
            stop_file=args.stop_file,
            on_subscribed=(
                lambda: args.ready_file.write_text(
                    json.dumps({"subscribed": True, "clock_info": clocks}) + "\n",
                    encoding="utf-8",
                    newline="\n",
                )
            )
            if args.ready_file
            else None,
        )
    else:
        if args.events_jsonl is None:
            parser.error("--events-jsonl is required for --source jsonl")
        with args.events_jsonl.open(encoding="utf-8") as event_file:
            observations = read_jsonl_event_stream(event_file)
    end_wall_ns = time.time_ns()
    end_monotonic_ns = time.perf_counter_ns()
    clock_offset = end_wall_ns - end_monotonic_ns
    decisions = load_routing_decisions(args.decisions, wall_to_monotonic_offset_ns=clock_offset)
    event_inventory = derive_event_inventory(observations)
    correlations = correlate_routing_events(decisions, observations)
    artifact = {
        "schema": "inf011-kv-event-capture.v2",
        "clock": "host perf_counter nanoseconds (monotonic)",
        "clock_info": clocks,
        "clock_pairs": {
            "start": {"unix_ns": start_wall_ns, "monotonic_ns": start_monotonic_ns},
            "end": {"unix_ns": end_wall_ns, "monotonic_ns": end_monotonic_ns},
            "wall_to_monotonic_offset_ns": clock_offset,
            "offset_change_ns": clock_offset - (start_wall_ns - start_monotonic_ns),
        },
        "event_observations": observations,
        "routing_to_event_observation": correlations,
        **summarize_routing_correlations(correlations),
        "raw_token_ids_retained": False,
        "raw_block_hashes_retained": False,
        "event_inventory": event_inventory,
    }
    pending_output = Path(str(args.output) + ".tmp")
    pending_output.write_text(
        json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )
    pending_output.replace(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
