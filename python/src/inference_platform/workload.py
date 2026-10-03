"""Seeded workload generation for matched routing-policy experiments."""

from __future__ import annotations

import argparse
import json
import random
import re
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

from inference_platform.records import canonical_json, content_digest

CONFIG_SCHEMA_VERSION = "workload-config.v0"
REQUEST_SCHEMA_VERSION = "workload-request.v0"
_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,190}$")
_RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,183}$")
_MODEL_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}$")
_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def _require_identifier(name: str, value: str) -> None:
    if not isinstance(value, str) or not _IDENTIFIER_PATTERN.fullmatch(value):
        raise ValueError(f"{name} must match {_IDENTIFIER_PATTERN.pattern}")


def _require_model(value: str) -> None:
    if not isinstance(value, str) or not _MODEL_PATTERN.fullmatch(value):
        raise ValueError(f"model must match {_MODEL_PATTERN.pattern}")


def _require_run_id(value: str) -> None:
    if not isinstance(value, str) or not _RUN_ID_PATTERN.fullmatch(value):
        raise ValueError(f"run_id must match {_RUN_ID_PATTERN.pattern}")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON member: {key!r}")
        value[key] = item
    return value


@dataclass(frozen=True, slots=True)
class WorkloadConfig:
    """Inputs that fully determine a generated request trace."""

    run_id: str
    seed: int
    request_count: int
    arrival_rate_rps: float
    tenant_ids: tuple[str, ...]
    model: str
    prefixes: tuple[str, ...]
    max_tokens: int
    schema_version: str = CONFIG_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != CONFIG_SCHEMA_VERSION:
            raise ValueError(f"schema_version must be {CONFIG_SCHEMA_VERSION!r}")
        _require_run_id(self.run_id)
        _require_model(self.model)
        if isinstance(self.seed, bool) or not isinstance(self.seed, int):
            raise ValueError("seed must be an integer")
        if (
            isinstance(self.request_count, bool)
            or not isinstance(self.request_count, int)
            or self.request_count <= 0
        ):
            raise ValueError("request_count must be a positive integer")
        if (
            isinstance(self.arrival_rate_rps, bool)
            or not isinstance(self.arrival_rate_rps, (int, float))
            or not 0 < self.arrival_rate_rps < float("inf")
        ):
            raise ValueError("arrival_rate_rps must be a positive finite number")
        if isinstance(self.max_tokens, bool) or not isinstance(self.max_tokens, int):
            raise ValueError("max_tokens must be a positive integer")
        if self.max_tokens <= 0:
            raise ValueError("max_tokens must be a positive integer")
        if not self.tenant_ids:
            raise ValueError("tenant_ids must not be empty")
        for tenant_id in self.tenant_ids:
            _require_identifier("tenant_id", tenant_id)
        if len(set(self.tenant_ids)) != len(self.tenant_ids):
            raise ValueError("tenant_ids must be unique")
        if not self.prefixes or any(
            not isinstance(prefix, str) or not prefix for prefix in self.prefixes
        ):
            raise ValueError("prefixes must contain non-empty strings")
        if len(set(self.prefixes)) != len(self.prefixes):
            raise ValueError("prefixes must be unique")

    def to_dict(self) -> dict[str, Any]:
        return {
            "arrival_rate_rps": self.arrival_rate_rps,
            "max_tokens": self.max_tokens,
            "model": self.model,
            "prefixes": list(self.prefixes),
            "request_count": self.request_count,
            "run_id": self.run_id,
            "schema_version": self.schema_version,
            "seed": self.seed,
            "tenant_ids": list(self.tenant_ids),
        }

    def digest(self) -> str:
        return content_digest(self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> WorkloadConfig:
        expected = set(cls.__dataclass_fields__)
        actual = set(value)
        if actual != expected:
            raise ValueError(
                f"workload config fields differ: missing={sorted(expected - actual)}, "
                f"unknown={sorted(actual - expected)}"
            )
        parsed = dict(value)
        tenant_ids = parsed.get("tenant_ids")
        prefixes = parsed.get("prefixes")
        if not isinstance(tenant_ids, list) or not isinstance(prefixes, list):
            raise ValueError("tenant_ids and prefixes must be JSON arrays")
        parsed["tenant_ids"] = tuple(tenant_ids)
        parsed["prefixes"] = tuple(prefixes)
        return cls(**parsed)


@dataclass(frozen=True, slots=True)
class WorkloadRequest:
    """One deterministic, planned request in a workload trace."""

    run_id: str
    request_id: str
    ordinal: int
    tenant_id: str
    model: str
    prefix_id: str
    messages: tuple[dict[str, str], ...]
    max_tokens: int
    planned_arrival_offset_ns: int
    configuration_digest: str
    schema_version: str = REQUEST_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != REQUEST_SCHEMA_VERSION:
            raise ValueError(f"schema_version must be {REQUEST_SCHEMA_VERSION!r}")
        for name in ("run_id", "request_id", "tenant_id", "prefix_id"):
            _require_identifier(name, getattr(self, name))
        _require_model(self.model)
        if isinstance(self.ordinal, bool) or not isinstance(self.ordinal, int) or self.ordinal < 0:
            raise ValueError("ordinal must be a non-negative integer")
        if isinstance(self.max_tokens, bool) or not isinstance(self.max_tokens, int):
            raise ValueError("max_tokens must be a positive integer")
        if self.max_tokens <= 0:
            raise ValueError("max_tokens must be a positive integer")
        if (
            isinstance(self.planned_arrival_offset_ns, bool)
            or not isinstance(self.planned_arrival_offset_ns, int)
            or self.planned_arrival_offset_ns < 0
        ):
            raise ValueError("planned_arrival_offset_ns must be a non-negative integer")
        if not _DIGEST_PATTERN.fullmatch(self.configuration_digest):
            raise ValueError("configuration_digest must be 64 lowercase hexadecimal characters")
        if not self.messages:
            raise ValueError("messages must not be empty")
        for message in self.messages:
            if not isinstance(message, dict) or set(message) != {"role", "content"}:
                raise ValueError("each message must contain only role and content")
            if message["role"] not in {"system", "user", "assistant"}:
                raise ValueError("message role is unsupported")
            if not isinstance(message["content"], str) or not message["content"]:
                raise ValueError("message content must be a non-empty string")

    def to_dict(self) -> dict[str, Any]:
        return {
            "configuration_digest": self.configuration_digest,
            "max_tokens": self.max_tokens,
            "messages": list(self.messages),
            "model": self.model,
            "ordinal": self.ordinal,
            "planned_arrival_offset_ns": self.planned_arrival_offset_ns,
            "prefix_id": self.prefix_id,
            "request_id": self.request_id,
            "run_id": self.run_id,
            "schema_version": self.schema_version,
            "tenant_id": self.tenant_id,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> WorkloadRequest:
        expected = set(cls.__dataclass_fields__)
        actual = set(value)
        if actual != expected:
            raise ValueError(
                f"workload request fields differ: missing={sorted(expected - actual)}, "
                f"unknown={sorted(actual - expected)}"
            )
        parsed = dict(value)
        messages = parsed.get("messages")
        if not isinstance(messages, list):
            raise ValueError("messages must be a JSON array")
        parsed["messages"] = tuple(messages)
        return cls(**parsed)


def load_config(path: Path) -> WorkloadConfig:
    """Load a strict workload configuration from UTF-8 JSON."""

    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_strict_object)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        raise ValueError(f"cannot load workload config {path}: {error}") from error
    if not isinstance(value, dict):
        raise ValueError("workload config must be a JSON object")
    return WorkloadConfig.from_dict(value)


def generate_workload(config: WorkloadConfig) -> tuple[WorkloadRequest, ...]:
    """Generate the byte-stable request trace for a validated configuration."""

    generator = random.Random(config.seed)
    configuration_digest = config.digest()
    elapsed_seconds = 0.0
    records: list[WorkloadRequest] = []

    for ordinal in range(config.request_count):
        if ordinal:
            elapsed_seconds += generator.expovariate(config.arrival_rate_rps)
        tenant_id = config.tenant_ids[generator.randrange(len(config.tenant_ids))]
        prefix_index = generator.randrange(len(config.prefixes))
        prefix_digest = sha256(config.prefixes[prefix_index].encode("utf-8")).hexdigest()[:16]
        prompt = f"{config.prefixes[prefix_index]}\n\nSynthetic request {ordinal:06d}."
        records.append(
            WorkloadRequest(
                run_id=config.run_id,
                request_id=f"{config.run_id}-{ordinal:06d}",
                ordinal=ordinal,
                tenant_id=tenant_id,
                model=config.model,
                prefix_id=f"prefix-{prefix_digest}",
                messages=({"role": "user", "content": prompt},),
                max_tokens=config.max_tokens,
                planned_arrival_offset_ns=round(elapsed_seconds * 1_000_000_000),
                configuration_digest=configuration_digest,
            )
        )
    return tuple(records)


def trace_jsonl(records: Sequence[WorkloadRequest]) -> str:
    """Serialize records as canonical UTF-8 JSON Lines with a final newline."""

    return "".join(f"{canonical_json(record.to_dict())}\n" for record in records)


def trace_digest(records: Sequence[WorkloadRequest]) -> str:
    return sha256(trace_jsonl(records).encode("utf-8")).hexdigest()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path, help="workload configuration JSON")
    parser.add_argument("--output", type=Path, help="destination JSONL; stdout when omitted")
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="generate and summarize without writing the trace",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
        records = generate_workload(config)
        rendered = trace_jsonl(records)
    except ValueError as error:
        parser.error(str(error))

    if args.validate_only:
        summary = {
            "configuration_digest": config.digest(),
            "records": len(records),
            "trace_digest": trace_digest(records),
        }
        print(canonical_json(summary))
    elif args.output is None:
        sys.stdout.write(rendered)
    else:
        args.output.write_text(rendered, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
