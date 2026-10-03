"""Join gateway decisions to restricted transient recorder prompts and /tokenize IDs.

Never commit these raw inputs/outputs; export only capture's digest projection.
"""

import argparse
import json
import os
import re
import threading
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .time_budget import deadline_urlopen

_write_lock = threading.Lock()


def append_prompt(
    path: str,
    request_id: str,
    payload: dict[str, Any],
    *,
    outcome: str,
    first_content_received: bool,
) -> None:
    row = {"request_id": request_id, "model": payload["model"], "messages": payload["messages"]}
    row.update(outcome=outcome, first_content_received=first_content_received)
    with _write_lock:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(row) + "\n")


def gateway_terminal_unix_ns(terminal: dict[str, Any]) -> int:
    """Project slog's RFC3339 terminal time without rounding away nanoseconds."""
    stamp = terminal.get("time", "")
    match = re.fullmatch(r"(.{19})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})", stamp)
    if not match:
        raise ValueError("invalid gateway terminal timestamp")
    whole = datetime.fromisoformat(match[1] + match[3]).astimezone(UTC)
    delta = whole - datetime(1970, 1, 1, tzinfo=UTC)
    return (delta.days * 86400 + delta.seconds) * 1_000_000_000 + int(
        (match[2] or "").ljust(9, "0")
    )


def export_decisions(
    terminals: list[dict[str, Any]],
    prompts: list[dict[str, Any]],
    tokenize_url: str,
    *,
    timeout_seconds: float = 5,
    deadline: float | None = None,
) -> list[dict[str, Any]]:
    if not prompts or len(prompts) > 100_000:
        raise ValueError("prompt manifest must contain 1..100000 requests")
    by_id = {p["request_id"]: p for p in prompts}
    if len(by_id) != len(prompts):
        raise ValueError("duplicate recorder request ID")
    decisions = []
    seen = set()
    token_cache = {}
    for terminal in terminals:
        if terminal.get("msg") != "request terminal" or not terminal.get("router_decision_unix_ns"):
            continue  # Startup/admission failures made no routing decision.
        request_id = terminal["request_id"]
        if request_id in seen or request_id not in by_id:
            raise ValueError("duplicate or unmatched gateway decision")
        seen.add(request_id)
        prompt = by_id[request_id]
        request = urllib.request.Request(
            tokenize_url.rstrip("/") + "/tokenize",
            data=json.dumps(
                {
                    "model": prompt["model"],
                    "messages": prompt["messages"],
                    "add_generation_prompt": True,
                }
            ).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        cache_key = request.data
        if cache_key not in token_cache:
            with deadline_urlopen(request, timeout=timeout_seconds, deadline=deadline) as response:
                token_cache[cache_key] = json.load(response)["tokens"]
        tokens = token_cache[cache_key]
        if not tokens or any(type(t) is not int or t < 0 for t in tokens):
            raise ValueError("invalid /tokenize IDs")
        row = {
            "request_id": request_id,
            "router_decision_unix_ns": terminal["router_decision_unix_ns"],
            "gateway_terminal_unix_ns": gateway_terminal_unix_ns(terminal),
            "no_store_expected_request_failed": (
                terminal.get("committed") is False and terminal.get("cause") != "completed"
            )
            or (
                prompt.get("outcome") in {"failed_before_content", "cancelled"}
                and prompt.get("first_content_received") is False
            ),
            "expected_token_ids": tokens,
        }
        if "cached_prompt_tokens" in prompt:
            row["cached_prompt_tokens"] = prompt["cached_prompt_tokens"]
        decisions.append(row)
    if not decisions:
        raise ValueError("empty gateway decision join; event lag is unestablished")
    return decisions


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gateway-jsonl", type=Path, required=True)
    parser.add_argument("--prompt-jsonl", type=Path, required=True)
    parser.add_argument("--tokenize-url", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    def rows(path: Path) -> list[dict[str, Any]]:
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]

    result = export_decisions(rows(args.gateway_jsonl), rows(args.prompt_jsonl), args.tokenize_url)
    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
        stream.writelines(json.dumps(row) + "\n" for row in result)
    print(json.dumps({"joined_gateway_decisions": len(result), "raw_tokens_transient": True}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
