"""CPU-side stream observations and a narrow export for the INF-060 clock probe."""

import re
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass

from .inf037b_requests import SSEDecoder
from .inf037b_sse_json import sse_json_loads

CANCEL_AFTER_CONTENT_EVENTS = 4
MAX_STREAM_BYTES = 1_048_576
GATEWAY_REQUEST_ID = re.compile(r"req_[0-9a-f]{32}")
# vLLM 0.29.0 logger.py, API server decoration and AsyncLLM.generate().
ABORT_LINE = re.compile(
    r"(?:\(APIServer pid=[0-9]+\) )?(?P<stamp>[0-9]{1,12}\.[0-9]{6}) INFO "
    r"\[async_llm\.py:[0-9]+\] Request chatcmpl-(?P<request_id>req_[0-9a-f]{32}) aborted\."
)


def _validated_frames(data: bytes):
    """Project fields from a batch after strict SSE validation."""
    frames = data.replace(b"\r\n", b"\n").split(b"\n\n")
    for frame in reversed(frames[:-1]):
        fields = frame.split(b"\n")
        payload = b"\n".join(
            field[5:].lstrip(b" ") for field in fields if field.startswith(b"data:")
        )
        if payload and payload != b"[DONE]":
            # SSEDecoder has already validated all complete frames in this batch.
            yield sse_json_loads(payload)


def _validated_completion_count(data: bytes) -> int:
    for value in _validated_frames(data):
        if value["choices"] == [] and "usage" in value:
            return value["usage"]["completion_tokens"]
    raise ValueError("inf060_validated_usage_missing")


def observe_stream(
    chunks: Iterable[bytes],
    *,
    cancel_assigned: bool,
    close: Callable[[], None],
    clock_ns: Callable[[], int] = time.perf_counter_ns,
    details: bool = False,
) -> dict:
    """Decode gateway SSE. A finish observed in the same read takes precedence."""
    decoder = SSEDecoder()
    content_reads = []
    bytes_read = 0
    close_ns = None
    done_ns = None
    token_count = None
    finish_reason = None
    for read_index, chunk in enumerate(chunks):
        now = clock_ns()
        bytes_read += len(chunk)
        if bytes_read > MAX_STREAM_BYTES:
            decoder.errors.append("oversize_sse")
            break
        previous = len(decoder.content)
        pending = decoder.buffer
        had_usage = decoder.usage
        had_finish = decoder.finish
        had_done = decoder.done
        decoder.feed(chunk, [now // 1_000_000, (now + 999_999) // 1_000_000])
        if decoder.done and not had_done:
            done_ns = now
        decoded = len(decoder.content) - previous
        content_reads.extend([(read_index, now, decoded >= 2)] * decoded)
        if decoder.errors:
            break
        if details and decoder.finish and not had_finish:
            finish_reason = next(
                value["choices"][0]["finish_reason"]
                for value in _validated_frames(pending + chunk)
                if value["choices"] and value["choices"][0].get("finish_reason") is not None
            )
        if decoder.usage and not had_usage:
            token_count = _validated_completion_count(pending + chunk)
        if (
            cancel_assigned
            and len(content_reads) >= CANCEL_AFTER_CONTENT_EVENTS
            and not decoder.finish
        ):
            close()
            close_ns = clock_ns()
            break

    complete = decoder.report()["complete"]
    if not complete:
        token_count = None
    one_event_per_token = (
        token_count is not None and token_count >= 2 and token_count == len(content_reads)
    )
    token_gaps, transport_gaps = [], []
    same_read_pairs = coalesced_read_gaps = 0
    for (first_read, first_ns, _), (second_read, second_ns, coalesced_read) in zip(
        content_reads, content_reads[1:], strict=False
    ):
        same_read_pairs += first_read == second_read
        coalesced_read_gaps += coalesced_read
        gaps = token_gaps if one_event_per_token and not coalesced_read else transport_gaps
        gaps.append(second_ns - first_ns)
    cancel_status = "not_assigned"
    if cancel_assigned:
        if close_ns is not None:
            cancel_status = "sent"
        elif decoder.finish and not decoder.errors:
            cancel_status = "finished_before_cancel"
        else:
            cancel_status = "not_sent_unfinished"

    result = {
        "cancel_assigned": cancel_assigned,
        "cancel_status": cancel_status,
        "cancel_close_monotonic_ns": close_ns,
        "complete": complete,
        "content_event_count": len(content_reads),
        "first_content_monotonic_ns": content_reads[0][1] if content_reads else None,
        "completion_tokens": token_count,
        "token_itl_eligible": bool(token_gaps),
        "token_itl_ns": token_gaps,
        "transport_content_gaps_ns": transport_gaps,
        "same_read_content_pairs": same_read_pairs,
        "coalesced_read_excluded_gaps": coalesced_read_gaps,
    }
    if details:
        result.update(
            content_events=[[read, instant] for read, instant, _ in content_reads],
            finish_reason=finish_reason,
            validated_done=complete,
            done_ns=done_ns if complete else None,
        )
    return result


def summarize_same_read_by_level(
    observations_by_level: Mapping[float, Iterable[dict]],
) -> dict[float, dict[str, int]]:
    """Keep transport coalescing counts for each scheduled rate."""
    report = {}
    for level, observations in observations_by_level.items():
        pairs = affected = excluded = 0
        for row in observations:
            count = row["same_read_content_pairs"]
            pairs += count
            affected += count > 0
            excluded += row["coalesced_read_excluded_gaps"]
        report[level] = {
            "same_read_content_pairs": pairs,
            "same_read_affected_requests": affected,
            "coalesced_read_excluded_gaps": excluded,
        }
    return report


@dataclass(frozen=True)
class SentCancel:
    """The runner assigns numeric aliases before sending; raw IDs are private."""

    request_alias: int
    backend_generation: int
    gateway_request_id: str | None
    close_monotonic_ns: int


def join_abort_rows(
    sent_cancels: Iterable[SentCancel],
    logs_by_generation: Mapping[int, Iterable[str]],
) -> tuple[list[dict], dict[int, int]]:
    """Join frontend observations and count unmatched frontend lines by generation."""
    attempts = tuple(sent_cancels)
    matched = {}
    aliases = set()
    if any(type(generation) is not int or generation < 0 for generation in logs_by_generation):
        raise ValueError("invalid_backend_generation")
    orphan_counts = dict.fromkeys(logs_by_generation, 0)
    for attempt in attempts:
        if any(
            type(value) is not int or value < 0
            for value in (
                attempt.request_alias,
                attempt.backend_generation,
                attempt.close_monotonic_ns,
            )
        ):
            raise ValueError("invalid_cancel_observation")
        if attempt.request_alias in aliases:
            raise ValueError("duplicate_cancel_alias")
        aliases.add(attempt.request_alias)
        orphan_counts.setdefault(attempt.backend_generation, 0)
        if GATEWAY_REQUEST_ID.fullmatch(attempt.gateway_request_id or ""):
            key = (attempt.backend_generation, attempt.gateway_request_id)
            if key in matched:
                raise ValueError("duplicate_cancel_request_id")
            matched[key] = []

    for generation, lines in logs_by_generation.items():
        for line in lines:
            match = ABORT_LINE.fullmatch(line.rstrip("\r\n"))
            if match is not None:
                times = matched.get((generation, match["request_id"]))
                if times is None:
                    orphan_counts[generation] += 1
                elif len(times) < 2:  # Two timestamps establish ambiguity.
                    times.append(match["stamp"])

    rows = []
    for attempt in attempts:
        times = matched.get((attempt.backend_generation, attempt.gateway_request_id))
        stamp = None
        if times is None:
            status = "missing_gateway_request_id"
        elif not times:
            status = "missing_abort"
        elif len(times) > 1:
            status = "duplicate_abort"
        else:
            status = "joined"
            stamp = times[0]
        rows.append(
            {
                "request_alias": attempt.request_alias,
                "backend_generation": attempt.backend_generation,
                "cancel_close_monotonic_ns": attempt.close_monotonic_ns,
                "abort_status": status,
                "abort_log_stamp": stamp,
            }
        )
    return rows, orphan_counts
