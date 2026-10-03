"""Versioned request and outcome records for reproducible experiments."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
from typing import Any

OUTCOME_SCHEMA_VERSION = "request-outcome.v0"
_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,190}$")
_MODEL_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}$")


class Outcome(StrEnum):
    """Terminal request outcomes used by the first benchmark record schema."""

    COMPLETED = "completed"
    REJECTED = "rejected"
    CANCELLED = "cancelled"
    FAILED_BEFORE_CONTENT = "failed_before_content"
    PARTIAL_STREAM = "partial_stream"
    NOT_DISPATCHED = "not_dispatched"


class TokenCountSource(StrEnum):
    """Provenance for token counts carried by an outcome record."""

    RUNTIME_USAGE = "runtime_usage"
    TOKENIZER_ESTIMATE = "tokenizer_estimate"


def canonical_json(value: Mapping[str, Any]) -> str:
    """Return the stable JSON representation used for digests and JSONL records."""

    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def content_digest(value: Mapping[str, Any]) -> str:
    """Address a mapping by the SHA-256 digest of its canonical UTF-8 JSON."""

    return sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _require_non_empty(name: str, value: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")


def _require_identifier(name: str, value: str) -> None:
    if not isinstance(value, str) or not _IDENTIFIER_PATTERN.fullmatch(value):
        raise ValueError(f"{name} must match {_IDENTIFIER_PATTERN.pattern}")


def _require_model(value: str) -> None:
    if not isinstance(value, str) or not _MODEL_PATTERN.fullmatch(value):
        raise ValueError(f"model must match {_MODEL_PATTERN.pattern}")


def _require_offset(name: str, value: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")


def _require_optional_offset(name: str, value: int | None) -> None:
    if value is not None:
        _require_offset(name, value)


def _require_token_count(name: str, value: int | None) -> None:
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer or null")


@dataclass(frozen=True, slots=True)
class OutcomeRecord:
    """One terminal request observation measured by the load-generator process."""

    run_id: str
    request_id: str
    tenant_id: str
    model: str
    policy: str
    planned_arrival_offset_ns: int
    dispatch_offset_ns: int | None
    first_content_offset_ns: int | None
    completion_offset_ns: int | None
    outcome: Outcome
    http_status: int | None
    error_code: str | None
    prompt_tokens: int | None
    completion_tokens: int | None
    token_count_source: TokenCountSource | None
    backend_id: str | None
    configuration_digest: str
    schema_version: str = OUTCOME_SCHEMA_VERSION

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        """Reject records that would make later analysis ambiguous or invalid."""

        if self.schema_version != OUTCOME_SCHEMA_VERSION:
            raise ValueError(f"schema_version must be {OUTCOME_SCHEMA_VERSION!r}")
        for name in ("run_id", "request_id", "tenant_id", "policy"):
            _require_identifier(name, getattr(self, name))
        _require_model(self.model)
        if not isinstance(self.outcome, Outcome):
            raise ValueError("outcome must be an Outcome value")
        if self.token_count_source is not None and not isinstance(
            self.token_count_source, TokenCountSource
        ):
            raise ValueError("token_count_source must be a TokenCountSource value or null")
        if not _DIGEST_PATTERN.fullmatch(self.configuration_digest):
            raise ValueError("configuration_digest must be 64 lowercase hexadecimal characters")

        _require_offset("planned_arrival_offset_ns", self.planned_arrival_offset_ns)
        _require_optional_offset("dispatch_offset_ns", self.dispatch_offset_ns)
        _require_optional_offset("first_content_offset_ns", self.first_content_offset_ns)
        _require_optional_offset("completion_offset_ns", self.completion_offset_ns)

        if self.outcome is Outcome.NOT_DISPATCHED:
            if self.dispatch_offset_ns is not None or self.completion_offset_ns is not None:
                raise ValueError("not_dispatched requires null dispatch and completion offsets")
            if self.first_content_offset_ns is not None or self.backend_id is not None:
                raise ValueError("not_dispatched cannot have first content or backend_id")
            if self.http_status is not None:
                raise ValueError("not_dispatched requires null http_status")
            if self.error_code is None:
                raise ValueError("not_dispatched requires an error_code reason")
            _require_non_empty("error_code", self.error_code)
            if (
                self.prompt_tokens is not None
                or self.completion_tokens is not None
                or self.token_count_source is not None
            ):
                raise ValueError("not_dispatched cannot have token counts or provenance")
            return

        if self.dispatch_offset_ns is None or self.completion_offset_ns is None:
            raise ValueError("dispatched outcomes require dispatch and completion offsets")
        if self.dispatch_offset_ns < self.planned_arrival_offset_ns:
            raise ValueError("dispatch_offset_ns cannot precede planned arrival")
        if self.completion_offset_ns < self.dispatch_offset_ns:
            raise ValueError("completion_offset_ns cannot precede dispatch")
        if (
            self.first_content_offset_ns is not None
            and self.first_content_offset_ns < self.dispatch_offset_ns
        ):
            raise ValueError("first_content_offset_ns cannot precede dispatch")
        if (
            self.first_content_offset_ns is not None
            and self.completion_offset_ns < self.first_content_offset_ns
        ):
            raise ValueError("completion_offset_ns cannot precede first content")

        if self.http_status is not None and (
            isinstance(self.http_status, bool)
            or not isinstance(self.http_status, int)
            or not 100 <= self.http_status <= 599
        ):
            raise ValueError("http_status must be an integer from 100 through 599 or null")
        _require_token_count("prompt_tokens", self.prompt_tokens)
        _require_token_count("completion_tokens", self.completion_tokens)
        has_token_count = self.prompt_tokens is not None or self.completion_tokens is not None
        if has_token_count and self.token_count_source is None:
            raise ValueError("token counts require token_count_source")
        if not has_token_count and self.token_count_source is not None:
            raise ValueError("token_count_source requires at least one token count")
        if self.error_code is not None:
            _require_non_empty("error_code", self.error_code)
        if self.backend_id is not None:
            _require_identifier("backend_id", self.backend_id)

        if self.outcome is Outcome.COMPLETED:
            if self.http_status != 200 or self.error_code is not None:
                raise ValueError("completed outcomes require HTTP 200 and no error_code")
            if self.backend_id is None:
                raise ValueError("completed outcomes require backend_id")
            if (
                self.prompt_tokens is None
                or self.completion_tokens is None
                or self.token_count_source is None
            ):
                raise ValueError(
                    "completed outcomes require prompt/completion counts and token_count_source"
                )
        elif self.outcome is Outcome.REJECTED:
            if self.first_content_offset_ns is not None or self.backend_id is not None:
                raise ValueError("rejected outcomes cannot have first content or backend_id")
            if self.http_status is None or not 400 <= self.http_status <= 499:
                raise ValueError("rejected outcomes require a 4xx HTTP status")
            if self.error_code is None:
                raise ValueError("rejected outcomes require error_code")
            if has_token_count:
                raise ValueError("rejected outcomes cannot have token counts")
        elif self.outcome is Outcome.CANCELLED:
            if self.error_code != "client_cancelled":
                raise ValueError("cancelled outcomes require error_code 'client_cancelled'")
            if self.http_status not in (None, 200):
                raise ValueError("cancelled outcomes allow only null or committed HTTP 200")
        elif self.outcome is Outcome.FAILED_BEFORE_CONTENT:
            if self.first_content_offset_ns is not None:
                raise ValueError("failed_before_content cannot have first content")
            if self.error_code is None:
                raise ValueError("failed_before_content requires error_code")
            if self.http_status is not None and self.http_status < 500:
                raise ValueError("failed_before_content requires a 5xx status or null")
        elif self.outcome is Outcome.PARTIAL_STREAM:
            if self.backend_id is None:
                raise ValueError("partial_stream requires backend_id")
            if self.http_status != 200 or self.error_code is None:
                raise ValueError("partial_stream requires committed HTTP 200 and error_code")

    def ttft_ns(self) -> int | None:
        """Return client-observed TTFT, excluding requests that produced no text."""

        if self.dispatch_offset_ns is None or self.first_content_offset_ns is None:
            return None
        return self.first_content_offset_ns - self.dispatch_offset_ns

    def to_dict(self) -> dict[str, Any]:
        """Return the strict JSON-compatible record mapping."""

        return {
            "backend_id": self.backend_id,
            "completion_offset_ns": self.completion_offset_ns,
            "completion_tokens": self.completion_tokens,
            "configuration_digest": self.configuration_digest,
            "dispatch_offset_ns": self.dispatch_offset_ns,
            "error_code": self.error_code,
            "first_content_offset_ns": self.first_content_offset_ns,
            "http_status": self.http_status,
            "model": self.model,
            "outcome": self.outcome.value,
            "planned_arrival_offset_ns": self.planned_arrival_offset_ns,
            "policy": self.policy,
            "prompt_tokens": self.prompt_tokens,
            "request_id": self.request_id,
            "run_id": self.run_id,
            "schema_version": self.schema_version,
            "tenant_id": self.tenant_id,
            "token_count_source": (
                self.token_count_source.value if self.token_count_source is not None else None
            ),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> OutcomeRecord:
        """Parse a strict mapping, rejecting unknown or missing fields."""

        expected = set(cls.__dataclass_fields__)
        actual = set(value)
        if actual != expected:
            raise ValueError(
                f"outcome record fields differ: missing={sorted(expected - actual)}, "
                f"unknown={sorted(actual - expected)}"
            )
        parsed = dict(value)
        try:
            parsed["outcome"] = Outcome(parsed["outcome"])
        except (TypeError, ValueError) as error:
            raise ValueError(f"unknown outcome: {parsed['outcome']!r}") from error
        try:
            if parsed["token_count_source"] is not None:
                parsed["token_count_source"] = TokenCountSource(parsed["token_count_source"])
        except (TypeError, ValueError) as error:
            raise ValueError(
                f"unknown token_count_source: {parsed['token_count_source']!r}"
            ) from error
        return cls(**parsed)
